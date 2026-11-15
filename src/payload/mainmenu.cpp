// Нативный пункт «GitBar» — отдельное подменю верхнего меню Конфигуратора
// (между «Сервис» и «Окна»).
//
// Платформа не даёт публичного API для добавления пунктов в главное меню, но
// рисует его из внутренних «панелей» (bands): панель — CommandID {GUID группы,
// номер}, содержимое — вектор пунктов по 0x70 байт (CommandID + вес double,
// порядок по весу). Верхнее меню — панель {MM_FRAME}/1 («Сервис» = вес 18.0,
// «Окна» = 19.0, наш пункт = 18.5); содержимое popup — наша панель
// {наши}/1. Модули платформы дополняют меню точно так же, как нужно нам:
// создают CommandInterface (createByClsid), кладут в него панели (addBand)
// и отдают менеджеру панелей (addSource + перестройка). Полный реверс и
// раскладка — проект v8snack (tools/MAINMENU.md, engine/mainmenu.as,
// v8api/process.v); эта реализация — перевод того рецепта на C++ payloads
// v8inject (RE live 2342: docs/plan_mainmenu_re.md).
//
// Объект процесса и сервис берутся чтением служебного реестра SCOM_Process
// (RE 2026-11-15, docs/plan_mainmenu_re.md Ф1-Ф2): current_process@core — это
// TlsGetValue(индекс из core83), а getService (vtable слот 14) ищет в хеш-мапе
// по 16-байтовому ключу; для ICommandService ключ — сам IID {8F885821-…}.
// Экземпляры находятся сканом кучи по vtable (core83 rva 0x3EAB68), запись —
// обходом списка от сентинела [proc+0x58]; только чтение памяти, никаких
// вызовов vtable — путь безопасен и не зависит от момента вызова обёртки.
// ( getService на young-экземпляре возвращал null: сервисы регистрируются
// постепенно — live: 29/76/377 записей на трёх экземплярах, ICommandService
// есть только в полном. ) Хуки обёрток 1cv8/config остаются как диагностика
// и fallback-захват объекта, старые шаги QI/getService сохранены как запасной
// путь.
//
// Ветки раскладки v8snack: 8.3.27 и 8.5 совпадают (entry 0x68, SSO-текст).
// Наши тексты («GitBar», «Настройки») короче 10 символов и целиком помещаются
// в SSO-описание команды — ICommandState.setText не требуется.

#include "v8inject/diag.h"
#include "v8inject/hook.h"
#include "v8inject/memscan.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/v8i_export.h"

#include <windows.h>
#include <commctrl.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace v8i {

// Из src/payload/gitbar.cpp (namespace v8i).
void V8iGitBarMenuAction(unsigned num);
void V8iGitBarSetNativeMenu();
void V8iGitBarShowActionMenu();

// --- константы рецепта (v8snack mainmenu.as:10-30, MAINMENU.md §2-§6) ------

const wchar_t kMMGroupStr[] = L"{8B4A6E2F-7D31-4A9C-B5F4-2C6E9D1A47B3}";  // группа наших команд
const wchar_t kMMCatPopupStr[] = L"{79FC5DE1-99D4-45EE-A887-22970F440CE6}";  // категория «Подменю» платформы
const wchar_t kMMCatOwnStr[] = L"{8B4A6E2F-7D31-4A9C-B5F4-2C6E9D1A47B4}";    // категория наших (платформе не регистрируется)
const wchar_t kMMFrameStr[] = L"{B78F2E80-EC68-11D4-9DCF-0050BAE2BC79}";     // группа команд главного окна
const wchar_t kMMClsidCIStr[] = L"{F459D5F0-E7C0-11D4-9DCD-0050BAE2BC79}";   // CommandInterface
const wchar_t kMMIidCIStr[] = L"{7DF15090-7A63-11D4-84A1-008048DA06DF}";
const wchar_t kMMIidSvcStr[] = L"{8F885821-D353-11D3-8A57-008048DA06DF}";   // IID ICommandService
const unsigned kMMPopupNum = 1;       // popup «GitBar» (верхний пункт)
const unsigned kMMActionsNum = 10;    // «Действия…» — открывает popup оверлея
const unsigned kMMSettingsNum = 2;    // «Настройки…»
const unsigned kMMTopBandNum = 1;        // панель верхнего меню ({MM_FRAME}/1)
const uint64_t kMMWeightTop = 0x4032800000000000ULL;    // 18.5 — верхнее меню:
                                          // «Сервис» = 18.0, «Окна» = 19.0 (live 2342)
const uint64_t kMMWeightItem = 0x3FF0000000000000ULL;   // 1.0 — пункт внутри popup

constexpr uintptr_t kMMManagerOff = 0xD0;   // [ICommandService + 0xD0] — менеджер панелей

// Служебный реестр сервисов SCOM_Process (RE: disasm impl getService, rva
// 0x127470 core83, live 8.3.27.2342 x64). Хеш-мапа внутри объекта процесса:
// сентинел списка [proc+0x58], число записей [proc+0x60], бакеты [proc+0x68]
// (по 16 байт: начало цепочки + стоп-узел), маска [proc+0x80] (2^n − 1).
// Узел: next +0x00, prev +0x08, ключ 16 байт +0x10/+0x18 (сравнение двух
// qword getService'ом), связанный GUID +0x20/+0x28, указатель +0x30, сервис
// +0x38. Ключ записи ICommandService — сам IID {8F885821-…} (дамп реестра
// live: запись 52 из 377). vtable SCOM_Process — core83 rva 0x3EAB68.
constexpr uintptr_t kMMProcVtableRva = 0x3EAB68;
constexpr uintptr_t kMMRegSentinel = 0x58;
constexpr uintptr_t kMMRegNodeKey = 0x10;
constexpr uintptr_t kMMRegNodeSvc = 0x38;
constexpr uint64_t kMMIidSvcQ0 = 0x11D3D3538F885821ULL;  // {8F885821-…} младшие 8 байт
constexpr uint64_t kMMIidSvcQ1 = 0xDF06DA488000578AULL;  // …-008048DA06DF старшие

// Менеджер панелей (RE live 2342 x64, 2026-11-15): [ICommandService+0xD0] —
// экземпляр менеджера с ПУСТЫМИ источниками и картой (главное меню платформы
// живёт в другом экземпляре того же класса; слот 27 ICommandService возвращает
// тот же пустой объект). Правильный менеджер выбираем по содержимому: скан
// объектов класса (vtable frame.dll rva 0xB097F0) и поиск в карте (std::map,
// сентинел [mgr+0xD0], корень [sent+8]) панели рамки {MM_FRAME}/52.
// Узел карты: _Left+0, _Parent+8, _Right+0x10, _Isnil байт +0x19, ключ
// CommandID 32 байта +0x20 (GUID, dword номера на +0x30), панель +0x38.
constexpr uintptr_t kMMMngrVtableRva = 0xB097F0;
constexpr uint64_t kMMFrameQ0 = 0x11D4EC68B78F2E80ULL;   // {B78F2E80-EC68-11D4-…}
constexpr uint64_t kMMFrameQ1 = 0x79BCE2BA5000CF9DULL;   // …-9DCF-0050BAE2BC79}
constexpr uintptr_t kMMNodeIsnil = 0x19;
constexpr uintptr_t kMMNodeRight = 0x10;                 // std::map: _Left+0/_Right+0x10
constexpr uintptr_t kMMNodeKey = 0x20;                   // CommandID 32 байта +0x20
constexpr uintptr_t kMMNodeNum = 0x30;                   // dword номера в CommandID
constexpr uintptr_t kMMNodeBand = 0x38;                  // панель в узле карты
constexpr int kMMSlotRegisterCommands = 11; // ICommandService
constexpr int kMMSlotCommandDescription = 3; // ICommandService, после IUnknown
constexpr int kMMSlotBandById = 3;          // менеджер: панель по CommandID
constexpr int kMMSlotAddSource = 10;        // менеджер: подключить источник
constexpr int kMMSlotRebuild = 13;          // менеджер: перестроить панели
constexpr int kMMSlotAddBand = 4;           // источник: addBand(CommandID*, vector*, bool)
constexpr int kMMSlotFinish = 13;           // источник: завершить
constexpr int kMMSlotProcCreate = 5;        // SCOM_Process.createByClsid (v8snack, live)
constexpr int kMMSlotProcGetService = 14;   // SCOM_Process.getService — обёртка
                                            // 1cv8.exe зовёт [rax+0x70] (2342)
constexpr int kMMSlotStateId = 3;           // ICommandState.id()
constexpr int kMMSlotStateEnable = 6;       // ICommandState.enable(bool)
constexpr size_t kMMItemSize = 0x70;
constexpr size_t kMMEntrySize = 0x68;
constexpr size_t kMMEStr = 0x40, kMMEInt1 = 0x58, kMMEInt2 = 0x5C, kMMEByte = 0x60;

// Обёртка getService внутри 1cv8.exe (8.3.27.2342 x64, rva 0xBFCB0):
// test rcx / mov rax,[rcx] / lea rdx,[IID_ICommandService] / call [rax+0x70].
// Смещение привязано к сборке — перекалибровка по билду (дорожная карта Ф2.1);
// на прочих версиях пункт не добавляется и работает fallback-оверлей.
constexpr uintptr_t kMMWrapperRva = 0xBFCB0;

// --- состояние --------------------------------------------------------------

struct MMState {
    GUID group{};
    uintptr_t groupBytes = 0;       // 32 байта: GUID + номер (для mmIsOurs)
    uintptr_t svc = 0, manager = 0, src = 0, proc = 0;
    void* core = nullptr;           // объекты цепочки рамки (для QueryInterface)
    void* frameObj = nullptr;
    int trapTx = 3, trapUpd = 4, trapHas = 5;   // слоты приёмника (8.3)
    volatile LONG procTaken = 0;
    GUID lastObservedIid{};
    GUID getServiceIid{};    // обёртка getService: объект захвачен
    bool stepRan = false;           // шаг был выполнен (маршал готов)
    bool built = false;             // registerCommands/addBand/addSource прошли
    bool failed = false;            // непоправимый шаг, повторять бессмысленно
    bool stepFailed = false;        // шаг просит повтор (меню ещё не построено)
    bool registered = false;        // команды зарегистрированы (повтор нельзя)
    bool sourceAdded = false;       // источник панелей подключён (повтор нельзя)
    bool trapsSet = false;          // перехваты приёмника поставлены
    bool confirmed = false;         // платформа запросила updateState нашего popup
    const char* stage = "?";        // текущий шаг — логируется при падении
    char err[160] = {};
    // перехваты на приёмнике главного окна
    uintptr_t* recvVt = nullptr;
    void* recv = nullptr;
    uintptr_t origUpdate = 0, origHas = 0, origTransmit = 0;
};

MMState g_mm;

// Наблюдатель хука обёртки: 1С сама передаёт сюда SCOM_Process. Захват один
// раз; POD-правила соблюдены (Interlocked + присвоение).
void MMObsTakeProc(uintptr_t a0, uintptr_t a1, uintptr_t, uintptr_t) {
    if (!a0 || !a1) return;
    // Лог запрашиваемого IID: обёртка generic — платформа просит разные
    // сервисы; захват процесса имеет смысл только для нашего IID.
    GUID iid = *(const GUID*)a1;
    LogLine("mainmenu: wrapper: proc=0x%llX iid={%08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X}",
            (unsigned long long)a0, iid.Data1, iid.Data2, iid.Data3,
            iid.Data4[0], iid.Data4[1], iid.Data4[2], iid.Data4[3],
            iid.Data4[4], iid.Data4[5], iid.Data4[6], iid.Data4[7]);
    g_mm.lastObservedIid = iid;
    if (iid.Data1 == 0x8F885821 && iid.Data2 == 0xD353) {   // ICommandService
        if (InterlockedCompareExchange((volatile LONG*)&g_mm.procTaken, 1, 0) == 0) {
            g_mm.proc = a0;
            LogLine("mainmenu: объект процесса захвачен: 0x%llX",
                    (unsigned long long)a0);
        }
    }
}

// --- сырые вызовы слотов ----------------------------------------------------

// Методы платформы — thiscall. Вызов через member-указатель на фиктивном
// объекте: на x86 это даёт правильную очистку стека, на x64 соглашение одно.
struct MMDummy {};
typedef uintptr_t (__thiscall MMDummy::*MMFn0)();
typedef uintptr_t (__thiscall MMDummy::*MMFn1)(uintptr_t);
typedef uintptr_t (__thiscall MMDummy::*MMFn2)(uintptr_t, uintptr_t);
typedef uintptr_t (__thiscall MMDummy::*MMFn3)(uintptr_t, uintptr_t, uintptr_t);

uintptr_t MMCall0(uintptr_t fn, uintptr_t self) {
    union { uintptr_t a; MMFn0 f; } u{fn};
    return (((MMDummy*)self)->*u.f)();
}
uintptr_t MMCall1(uintptr_t fn, uintptr_t self, uintptr_t a1) {
    union { uintptr_t a; MMFn1 f; } u{fn};
    return (((MMDummy*)self)->*u.f)(a1);
}
uintptr_t MMCall2(uintptr_t fn, uintptr_t self, uintptr_t a1, uintptr_t a2) {
    union { uintptr_t a; MMFn2 f; } u{fn};
    return (((MMDummy*)self)->*u.f)(a1, a2);
}
uintptr_t MMCall3(uintptr_t fn, uintptr_t self, uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    union { uintptr_t a; MMFn3 f; } u{fn};
    return (((MMDummy*)self)->*u.f)(a1, a2, a3);
}

// Память под структуры меню: платформа ссылается на них постоянно, поэтому
// выделяется один раз и не освобождается никогда (сотни байт).
uintptr_t MMAlloc(size_t size) {
    void* p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 16);
    return (uintptr_t)p;
}

GUID MMGuid(const wchar_t* s) {   // «{8-4-4-4-12}» в раскладке Windows GUID
    // Стандартный формат несёт тире и внутри Data4 («…-9DCF-0050BAE2BC79»):
    // чтение фиксированными окнами по 2 символа съезжает на тире (live
    // 2342: gq1 = 0xC72BAE0B0500CF9D вместо 0x79BCE2BA5000CF9D) — все
    // getService/QI/bandById с такими GUID возвращали null. Читаем ровно
    // 32 hex-цифры подряд, тире пропускаем.
    GUID g{};
    auto hx = [](wchar_t c) -> int {
        if (c >= L'0' && c <= L'9') return c - L'0';
        if (c >= L'a' && c <= L'f') return c - L'a' + 10;
        if (c >= L'A' && c <= L'F') return c - L'A' + 10;
        return -1;
    };
    int d[32];
    int nd = 0;
    for (const wchar_t* p = s; *p && nd < 32; ++p) {
        const int v = hx(*p);
        if (v >= 0) d[nd++] = v;
    }
    if (nd < 32) return g;   // не GUID-строка — оставляем нулевой
    g.Data1 = ((unsigned)d[0] << 28) | ((unsigned)d[1] << 24) | ((unsigned)d[2] << 20) |
              ((unsigned)d[3] << 16) | ((unsigned)d[4] << 12) | ((unsigned)d[5] << 8) |
              ((unsigned)d[6] << 4) | (unsigned)d[7];
    g.Data2 = (unsigned short)(((unsigned)d[8] << 12) | ((unsigned)d[9] << 8) |
                               ((unsigned)d[10] << 4) | (unsigned)d[11]);
    g.Data3 = (unsigned short)(((unsigned)d[12] << 12) | ((unsigned)d[13] << 8) |
                               ((unsigned)d[14] << 4) | (unsigned)d[15]);
    for (int i = 0; i < 8; ++i)
        g.Data4[i] = (unsigned char)(((unsigned)d[16 + 2 * i] << 4) | (unsigned)d[17 + 2 * i]);
    return g;
}

uintptr_t MMPutGuid(uintptr_t dst, const GUID& g) {
    memcpy((void*)dst, &g, 16);
    return dst;
}

uintptr_t MMNewCid(const GUID& group, unsigned num) {
    uintptr_t p = MMAlloc(32);
    MMPutGuid(p, group);
    *(unsigned*)(p + 16) = num;
    return p;
}

uintptr_t MMNewAnsi(const char* s) {
    size_t n = strlen(s);
    uintptr_t p = MMAlloc(n + 2);
    memcpy((void*)p, s, n + 1);
    return p;
}

// Короткая (до 10 символов) строка v8string прямо в SSO-хранилище:
// 24 байта, слово на +0x16 — «11 - длина».
void MMSetShort(uintptr_t dst, const wchar_t* s) {
    size_t n = wcslen(s);
    if (n > 10) n = 10;
    memset((void*)dst, 0, 24);
    memcpy((void*)dst, s, n * 2);
    *(unsigned short*)(dst + 0x16) = (unsigned short)(11 - n);
}

bool MMIsOurs(uintptr_t cid) {
    if (!cid || !g_mm.groupBytes) return false;
    return *(uintptr_t*)cid == *(uintptr_t*)g_mm.groupBytes &&
           *(uintptr_t*)(cid + 8) == *(uintptr_t*)(g_mm.groupBytes + 8);
}

uintptr_t MMBand(uintptr_t manager, uintptr_t cid) {
    uintptr_t vt = *(uintptr_t*)manager;
    uintptr_t outp = MMAlloc(16);
    MMCall2(*(uintptr_t*)(vt + kMMSlotBandById * 8), manager, outp, cid);
    return *(uintptr_t*)outp;
}

// Прямой поиск панели в карте менеджера (std::map) без вызова bandById:
// live 2342 vtable-слот 3 возвращает 0 даже для существующих панелей, а
// чтение дерева детерминированно (RE 2026-11-15). Полный обход всех вершин
// (стек, лимит 256), возвращает указатель панели из узла (+0x38), без
// AddRef — использование короткое, на UI-потоке.
uintptr_t MMBandDirect(uintptr_t manager, const GUID& group, unsigned num) {
    if (!IsReadable((void*)(manager + kMMManagerOff + 8), 8)) return 0;
    const uintptr_t sent = *(uintptr_t*)(manager + kMMManagerOff);
    if (!sent || !IsReadable((void*)(sent + 16), 1)) return 0;
    const uintptr_t root = *(uintptr_t*)(sent + 8);   // _Parent
    if (!root || root == sent) return 0;
    uintptr_t stack[96];
    int sp = 0;
    stack[sp++] = root;
    int visited = 0;
    int guidMatch = 0, numMatch = 0;
    const uint64_t gq0 = *(const uint64_t*)&group;
    const uint64_t gq1 = *((const uint64_t*)&group + 1);
    while (sp > 0 && visited < 256) {
        const uintptr_t node = stack[--sp];
        if (!node || node == sent) continue;
        if (!IsReadable((void*)node, 0x40)) continue;
        if (*(const uint8_t*)(node + kMMNodeIsnil)) continue;
        ++visited;
        const uintptr_t key = node + kMMNodeKey;
        const uint64_t k0 = *(const uint64_t*)key;
        const uint64_t k1 = *(const uint64_t*)(key + 8);
        const unsigned kNum = *(const unsigned*)(node + kMMNodeNum);
        if (k0 == gq0 && k1 == gq1) ++guidMatch;
        if (kNum == num) ++numMatch;
        if (k0 == gq0 && k1 == gq1 && kNum == num)
            return *(uintptr_t*)(node + kMMNodeBand);
        if (sp + 2 < 96) {
            stack[sp++] = *(uintptr_t*)(node + kMMNodeRight);
            stack[sp++] = *(uintptr_t*)node;              // _Left
        }
    }
    static LONG dbgTick = 0;
    // Аномалия выбора (_GUID узлов совпал, а номер нет — либо наоборот)
    // означает рассинхрон раскладки узла карты с калибровкой сборки.
    if ((InterlockedIncrement(&dbgTick) % 8) == 1 &&
        ((guidMatch > 0 && numMatch == 0) || (guidMatch == 0 && numMatch > 0)))
        LogLine("mainmenu: MMBandDirect: mgr=0x%llX visited=%d guidMatch=%d "
                "numMatch=%d ищем gq0=0x%llX gq1=0x%llX num=%u",
                (unsigned long long)manager, visited, guidMatch, numMatch,
                (unsigned long long)gq0, (unsigned long long)gq1, num);
    return 0;
}

// Первый пункт панели как образец (копируется целиком, потом правятся id и вес)
uintptr_t MMTemplate(uintptr_t manager, const GUID& group, unsigned num) {
    uintptr_t band = MMBand(manager, MMNewCid(group, num));
    if (!band) band = MMBandDirect(manager, group, num);   // bandById вернул 0
    if (!band) return 0;
    uintptr_t beg = *(uintptr_t*)(band + 0x30);
    uintptr_t end = *(uintptr_t*)(band + 0x38);
    if (!beg || end <= beg) return 0;
    return *(uintptr_t*)beg;
}

uintptr_t MMItem(uintptr_t tmpl, const GUID& group, unsigned num, uint64_t weight) {
    uintptr_t it = MMAlloc(kMMItemSize);
    memcpy((void*)it, (void*)tmpl, kMMItemSize);
    MMPutGuid(it, group);
    *(unsigned*)(it + 16) = num;
    for (uintptr_t off = 0x14; off < 0x30; off += 4)
        *(unsigned*)(it + off) = 0;
    *(uint64_t*)(it + 0x30) = weight;
    *(unsigned*)(it + 0x38) = 0;
    *(unsigned*)(it + 0x3C) = 0;
    return it;
}

uintptr_t MMVector(uintptr_t items, size_t count) {
    uintptr_t v = MMAlloc(32);
    *(uintptr_t*)v = items;
    *(uintptr_t*)(v + 8) = items + count * kMMItemSize;
    *(uintptr_t*)(v + 16) = items + count * kMMItemSize;
    return v;
}

uintptr_t MMCmdEntry(const GUID& group, unsigned num, const GUID& category,
                     const char* idName, uintptr_t bundle) {
    uintptr_t e = MMAlloc(kMMEntrySize);
    MMPutGuid(e, group);
    *(unsigned*)(e + 16) = num;
    MMPutGuid(e + 0x14, category);
    *(uintptr_t*)(e + 0x28) = bundle;
    *(uintptr_t*)(e + 0x30) = MMNewAnsi(idName);
    *(unsigned short*)(e + kMMEStr + 0x16) = 11;   // пустая SSO-строка
    *(unsigned*)(e + kMMEInt1) = 0xFFFFFFFF;
    *(unsigned*)(e + kMMEInt2) = 1;
    *(unsigned char*)(e + kMMEByte) = 1;
    return e;
}

// Короткий текст в описание команды (платформа читает его до первого
// updateState); б = описание - 0x70, флаг «строки разрешены» на b+0x68.
void MMSetCommandText(uintptr_t svc, const GUID& group, unsigned num, const wchar_t* text) {
    uintptr_t svt = *(uintptr_t*)svc;
    uintptr_t descr = 0;
    uintptr_t cid = MMNewCid(group, num);
    MMCall2(*(uintptr_t*)(svt + kMMSlotCommandDescription * 8), svc, (uintptr_t)&descr, cid);
    if (!descr) {
        // на 8.5 commandDescription для наших команд возвращает null — норма
        // (v8snack docs/ISSUES.md P0-3); на 8.3.27 заполнено.
        return;
    }
    uintptr_t b = descr - 0x70;
    *(uintptr_t*)(b + 0x68) = 1;
    MMSetShort(b + 0x08, text);
    MMSetShort(b + 0x20, text);
    MMSetShort(b + 0x38, text);
    MMSetShort(b + 0x50, text);
}

// --- перехваты на приёмнике -------------------------------------------------

bool MMPatchSlot(uintptr_t* vt, int slot, void* hookFn, uintptr_t* origOut) {
    uintptr_t* slotPtr = vt + slot;
    void* orig = (void*)*slotPtr;
    DWORD old = 0;
    if (!VirtualProtect(slotPtr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old))
        return false;
    *slotPtr = (uintptr_t)hookFn;
    FlushInstructionCache(GetCurrentProcess(), slotPtr, sizeof(void*));
    VirtualProtect(slotPtr, sizeof(void*), old, &old);
    *origOut = (uintptr_t)orig;
    return true;
}

// Записываемые копии текстов команд: setText платформы может писать в
// переданную строку — литералы лежат в .rdata (read-only) и запись в них
// роняла 1С (0xC0000005, live 2342). Заполняется в MMStepRegister до
// установки перехватов (один поток — без гонок).
//
// (Блок убран: длинные тексты в state-поле не рендерятся — рендерер читает
// поле как SSO; полный список действий показывает owner-drawn popup
// оверлея, см. MMTransmitOnCommand → V8iGitBarShowActionMenu.)

size_t __fastcall MMUpdateTrap(size_t self, size_t state) {
    size_t r = MMCall1(g_mm.origUpdate, self, state);
    if (state) {
        // Наши дополнения под SEH: любой сбой здесь не должен убивать 1С —
        // платформа продолжит с состоянием, которое выставила сама.
        __try {
            uintptr_t vt = *(uintptr_t*)state;
            uintptr_t cid = MMCall0(*(uintptr_t*)(vt + kMMSlotStateId * 8), state);
            if (MMIsOurs(cid)) {
                unsigned num = *(unsigned*)(cid + 16);
                if (num == kMMPopupNum && !g_mm.confirmed) {
                    g_mm.confirmed = true;
                    LogLine("mainmenu: пункт отрисован платформой");
                }
                MMCall1(*(uintptr_t*)(vt + kMMSlotStateEnable * 8), state, 1);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LogLine("mainmenu: updateState-дополнения упали (0x%08X) — состояние не тронуто",
                    GetExceptionCode());
        }
    }
    return r;
}

size_t __fastcall MMHasTrap(size_t self, size_t cid) {
    if (MMIsOurs(cid)) return 1;   // обработчик есть — платформа включает пункт
    return MMCall1(g_mm.origHas, self, cid);
}

// Команда нашей группы: выполняем локально, на платформу не отдаём.
bool MMTransmitOnCommand(void* self, const void* cmd, DWORD deact) {
    (void)self;
    (void)deact;
    if (!cmd || !g_mm.built) return false;
    if (!MMIsOurs((uintptr_t)cmd)) return false;
    unsigned num = *(const unsigned*)((uintptr_t)cmd + 16);
    LogLine("mainmenu: команда %u", num);
    if (num == kMMActionsNum) {
        // «Действия…»: owner-drawn popup оверлея под курсором — полный
        // список действий с подсказками (нативный рендерер читает тексты
        // пунктов как SSO, длинные названия в подменю невозможны).
        V8iGitBarShowActionMenu();
        return true;
    }
    if (num == kMMSettingsNum) {
        V8iGitBarMenuAction(kMMSettingsNum);
        return true;
    }
    return false;
}

#if defined(_WIN64)
void MMTransmitTrap(void* self, const void* cmd, BOOL deact) {
    if (MMTransmitOnCommand(self, cmd, deact ? 1 : 0)) return;
    using Fn = void (*)(void*, const void*, BOOL);
    ((Fn)g_mm.origTransmit)(self, cmd, deact);
}
#else
static bool __cdecl MMTransmitFilter(void* self, const void* cmd, DWORD deact) {
    return MMTransmitOnCommand(self, cmd, deact);
}
// thiscall(this в ECX, cmd/deact на стеке, callee чистит 8): сначала фильтр
// наших команд, затем оригинал либо выход.
__declspec(naked) static void MMTransmitTrapX86() {
    __asm {
        push edx
        push ecx
        mov edx, [esp + 12]     // cmd (после двух push: ret на +8)
        mov ecx, [esp + 8]      // this
        push [esp + 16]         // deactivate
        push edx
        push ecx
        call MMTransmitFilter
        add esp, 12
        test al, al
        jnz ours
        pop ecx
        pop edx
        jmp [g_mm.origTransmit]
    ours:
        pop ecx
        pop edx
        ret 8
    }
}
#define MMTransmitTrap MMTransmitTrapX86
#endif

// --- шаги построения (на UI-потоке через общий cmd-маршал) ------------------

// QueryInterface за ICommandService на объектах цепочки рамки (UI-поток).
// Стандартный COM-вызов: безопасен при любом ответе (E_NOINTERFACE просто
// отказ). Слоты SCOM_Process::getService не использованы вовсе — их
// документальной раскладки нет, а перебор вызовами деструктивен (live:
// падение 1С).
void MMStepQI(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    GUID iid = MMGuid(kMMIidSvcStr);
    // Захваченный из обёртки объект — первый кандидат: это тот самый объект,
    // с которым 1С сама получает сервисы.
    uintptr_t tryObj[] = { (uintptr_t)m->proc, (uintptr_t)m->recv,
                           (uintptr_t)m->core, (uintptr_t)m->frameObj };
    for (uintptr_t obj : tryObj) {
        if (!obj) continue;
        uintptr_t vt = *(uintptr_t*)obj;
        if (!IsReadable((void*)vt, 3 * sizeof(void*))) continue;
        uintptr_t out = 0;
        MMCall2(*(uintptr_t*)vt, obj, (uintptr_t)&iid, (uintptr_t)&out);   // QI
        uintptr_t manager = 0;
        if (out) {
            uintptr_t svcVt = *(uintptr_t*)out;
            if (IsReadable((void*)svcVt, 20 * sizeof(void*))) {
                manager = *(uintptr_t*)(out + kMMManagerOff);
                if (manager) {
                    uintptr_t mgrVt = *(uintptr_t*)manager;
                    if (!IsReadable((void*)mgrVt, 14 * sizeof(void*))) manager = 0;
                }
            }
        }
        LogLine("mainmenu: QI 0x%llX -> svc=0x%llX менеджер=0x%llX",
                (unsigned long long)obj, (unsigned long long)out, (unsigned long long)manager);
        if (out && manager) {
            m->svc = out;
            m->manager = manager;
            LogLine("mainmenu: ICommandService получен через QueryInterface");
            return;
        }
    }
}

// getService на захваченном объекте, слот 14 (обёртка 1cv8.exe зовёт
// [rax+0x70]) — fallback, если QI не дал сервис.
void MMStepGetService(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    GUID iidSvc = m->getServiceIid;
    uintptr_t svc = MMCall1(*(uintptr_t*)(*(uintptr_t*)m->proc + kMMSlotProcGetService * 8),
                            m->proc, (uintptr_t)&iidSvc);
    uintptr_t manager = 0;
    if (svc) {
        uintptr_t svcVt = *(uintptr_t*)svc;
        if (IsReadable((void*)svcVt, 20 * sizeof(void*))) {
            manager = *(uintptr_t*)(svc + kMMManagerOff);
            if (manager) {
                uintptr_t mgrVt = *(uintptr_t*)manager;
                if (!IsReadable((void*)mgrVt, 14 * sizeof(void*))) manager = 0;
            }
        }
    }
    // Значения пишутся всегда: они и есть диагностика слота и момента.
    LogLine("mainmenu: getService слот %d -> svc=0x%llX менеджер=0x%llX",
            kMMSlotProcGetService, (unsigned long long)svc, (unsigned long long)manager);
    if (!svc || !manager) return;
    m->svc = svc;
    m->manager = manager;
}

void MMStepTemplates(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    m->stage = "образцы пунктов";
    GUID frameGroup = MMGuid(kMMFrameStr);
    uintptr_t tmplPopup = MMTemplate(m->manager, frameGroup, 1);
    if (!tmplPopup) {
        // Меню ещё не построено (шаг идёт рано; v8snack работает на первом
        // idle) — повтор через расписание цикла, а не отказ.
        strcpy_s(m->err, "не найдены образцы пунктов");
        m->stepFailed = true;
        return;
    }
    m->stepFailed = false;
    LogLine("mainmenu: образец пункта получен (0x%llX)",
            (unsigned long long)tmplPopup);
}

void MMStepRegister(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    if (m->registered) return;   // повторная регистрация дублирует команды
    m->stage = "registerCommands";
    GUID group = MMGuid(kMMGroupStr);
    GUID catPopup = MMGuid(kMMCatPopupStr);
    GUID catOwn = MMGuid(kMMCatOwnStr);
    uintptr_t bundle = MMNewAnsi("frame");
    // Верхний пункт «GitBar» (popup) + два листовых пункта dropdown'а.
    // Названия нативных пунктов ограничены 10 символами (SSO в описании
    // команды, live 2342) — полный список действий открывает «Действия…»
    // как owner-drawn popup оверлея (полные тексты + подсказки).
    const size_t count = 3;
    uintptr_t entries = MMAlloc(kMMEntrySize * count);
    memcpy((void*)entries,
           (void*)MMCmdEntry(group, kMMPopupNum, catPopup, "GitBarPopup", bundle),
           kMMEntrySize);
    memcpy((void*)(entries + kMMEntrySize),
           (void*)MMCmdEntry(group, kMMActionsNum, catOwn, "GitBarActions", bundle),
           kMMEntrySize);
    memcpy((void*)(entries + 2 * kMMEntrySize),
           (void*)MMCmdEntry(group, kMMSettingsNum, catOwn, "GitBarSettings", bundle),
           kMMEntrySize);
    uintptr_t svt = *(uintptr_t*)m->svc;
    MMCall3(*(uintptr_t*)(svt + kMMSlotRegisterCommands * 8),
            m->svc, bundle, entries, count);
    m->registered = true;
    m->stage = "тексты пунктов";
    MMSetCommandText(m->svc, group, kMMPopupNum, L"GitBar");
    MMSetCommandText(m->svc, group, kMMActionsNum, L"Действия…");
    MMSetCommandText(m->svc, group, kMMSettingsNum, L"Настройки…");
    LogLine("mainmenu: команды группы зарегистрированы (%u шт.)", (unsigned)count);
}

void MMStepSource(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    if (m->sourceAdded) return;   // источник уже подключён
    m->stage = "источник панелей";
    GUID frameGroup = MMGuid(kMMFrameStr);
    GUID group = MMGuid(kMMGroupStr);
    // образцы заново: между register и source платформа могла перестроиться
    uintptr_t tmplPopup = MMTemplate(m->manager, frameGroup, 1);
    uintptr_t tmplLeaf = MMTemplate(m->manager, frameGroup, 52);
    if (!tmplPopup || !tmplLeaf) {
        strcpy_s(m->err, "не найдены образцы пунктов (источник)");
        m->stepFailed = true;
        return;
    }

    uintptr_t clsid = MMAlloc(16), iid = MMAlloc(16), outp = MMAlloc(16);
    MMPutGuid(clsid, MMGuid(kMMClsidCIStr));
    MMPutGuid(iid, MMGuid(kMMIidCIStr));
    MMCall3(*(uintptr_t*)(*(uintptr_t*)m->proc + kMMSlotProcCreate * 8),
            m->proc, clsid, iid, outp);
    m->src = *(uintptr_t*)outp;
    if (!m->src) {
        strcpy_s(m->err, "не создан источник панелей");
        m->stepFailed = true;
        return;
    }

    // Пункт верхнего меню «GitBar» (отдельное подменю между «Сервис» и
    // «Окна»): панель {MM_FRAME}/1, вес 18.5 (live 2342: «Сервис» = 18.0,
    // «Окна» = 19.0). Содержимое popup — панель {наши}/1: «Действия…»
    // (открывает owner-drawn popup оверлея с полными текстами и
    // подсказками) и «Настройки…».
    uintptr_t topItems = MMAlloc(kMMItemSize);
    memcpy((void*)topItems,
           (void*)MMItem(tmplPopup, group, kMMPopupNum, kMMWeightTop), kMMItemSize);
    uintptr_t popItems = MMAlloc(kMMItemSize * 2);
    memcpy((void*)popItems,
           (void*)MMItem(tmplLeaf, group, kMMActionsNum, kMMWeightItem), kMMItemSize);
    memcpy((void*)(popItems + kMMItemSize),
           (void*)MMItem(tmplLeaf, group, kMMSettingsNum, kMMWeightItem), kMMItemSize);

    uintptr_t sv = *(uintptr_t*)m->src;
    MMCall3(*(uintptr_t*)(sv + kMMSlotAddBand * 8), m->src,
            MMNewCid(frameGroup, kMMTopBandNum), MMVector(topItems, 1), 0);
    MMCall3(*(uintptr_t*)(sv + kMMSlotAddBand * 8), m->src,
            MMNewCid(group, kMMPopupNum), MMVector(popItems, 2), 0);
    MMCall0(*(uintptr_t*)(sv + kMMSlotFinish * 8), m->src);
    // 4. подключаем источник к менеджеру и сразу перестраиваем (MM_REBUILD=1,
    //    v8snack mainmenu.as шаг 4): без addSource менеджер не знает об
    //    источнике — панели в его карте не появляются (live 2342).
    MMCall2(*(uintptr_t*)(*(uintptr_t*)m->manager + kMMSlotAddSource * 8),
            m->manager, m->src, 1);
    m->sourceAdded = true;
    LogLine("mainmenu: панели подключены, источник отдан менеджеру "
            "(пункт в верхнем меню, вес 18.5)");
}

void MMStepTraps(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    if (m->trapsSet) { m->built = true; return; }   // повторный патч поймал бы свой хук
    m->stage = "перехваты приёмника";
    if (m->recv && m->recvVt &&
        MMPatchSlot(m->recvVt, m->trapUpd, (void*)&MMUpdateTrap, &m->origUpdate) &&
        MMPatchSlot(m->recvVt, m->trapHas, (void*)&MMHasTrap, &m->origHas) &&
        MMPatchSlot(m->recvVt, m->trapTx, (void*)&MMTransmitTrap, &m->origTransmit)) {
        m->groupBytes = MMAlloc(32);
        MMPutGuid(m->groupBytes, MMGuid(kMMGroupStr));
        m->trapsSet = true;
        LogLine("mainmenu: перехваты установлены на приёмник 0x%llX",
                (unsigned long long)(uintptr_t)m->recv);
    } else {
        LogLine("mainmenu: приёмник для перехватов не получен — пункты останутся неактивными");
    }
    m->built = true;
    LogLine("mainmenu: пункт «GitBar» добавлен в верхнее меню");
}

void MMRebuildStep(void* arg) {
    MMState* m = (MMState*)arg;
    if (!m->manager) return;
    uintptr_t vt = *(uintptr_t*)m->manager;
    MMCall0(*(uintptr_t*)(vt + kMMSlotRebuild * 8), m->manager);
}

// --- поддержка версий и запуск ---------------------------------------------

// Ветки v8snack: 8.3.27 и 8.5 — одна раскладка (entry 0x68, SSO); прочие — отказ.
// Семья платформы определяется по пути модуля (…\1cv8\8.3.27.2342\bin\…):
// профильные API KERNELBASE (GetPrivateProfileStringW, GetFileVersionInfoSizeW)
// роняли поток на канонизации пути (GetFinalPathNameByHandleA+0x20, live
// 8.3.27.2342) и здесь не используются вовсе.
bool MMSupported(bool* is85) {
    ModuleRange m;
    if (FindModule(L"core85.dll", m)) { *is85 = true; return true; }
    *is85 = false;
    if (!FindModule(L"core83.dll", m)) return false;
    bool family27 = m.path.find(L"\\8.3.27.") != std::wstring::npos;
    LogLine("mainmenu: core83 — семья 8.3.27 по пути %ls: %s", m.path.c_str(),
            family27 ? "да" : "нет");
    return family27;
}

// Ключ [git] nativemenu=0 читается вручную (CreateFileW/ReadFile): профильные
// API KERNELBASE (GetPrivateProfileStringW) роняли поток на канонизации пути
// (GetFinalPathNameByHandleA+0x20, live 8.3.27.2342) и здесь не используются.
bool MMNativeMenuEnabled() {
    wchar_t path[MAX_PATH] = {};
    ExpandEnvironmentStringsW(L"%APPDATA%\\v8inject\\gitbar.ini", path, MAX_PATH);
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return true;   // нет файла — включён по умолчанию
    char buf[4096] = {};
    DWORD got = 0;
    ReadFile(f, buf, sizeof(buf) - 1, &got, nullptr);
    CloseHandle(f);
    buf[got < sizeof(buf) - 1 ? got : sizeof(buf) - 1] = 0;
    const char* p = strstr(buf, "nativemenu");
    while (p) {
        const char* eq = strchr(p, '=');
        const char* eol = strchr(p, '\n');
        if (eq && (!eol || eq < eol)) {
            ++eq;
            while (*eq == ' ' || *eq == '\t' || *eq == '\r') ++eq;
            return _strnicmp(eq, "0", 1) != 0;
        }
        p = eol ? eol + 1 : nullptr;
    }
    return true;
}

// --- R2: экземпляры SCOM_Process и чтение реестра getService -----------------

// Скан всей доступной памяти по выровненным qword (шаг 8 байт): адреса объектов,
// чьё первое поле равно vtable SCOM_Process. Чтение через ReadProcessMemory
// самого себя — на отказ региона пропускается окно, а не весь скан.
int MMFindInstances(uintptr_t vtVal, uintptr_t* out, int maxOut) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;
    const size_t kChunk = 1u << 20;
    std::vector<unsigned char> buf(kChunk);
    int n = 0;
    while (addr < maxAddr && n < maxOut) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;
        const uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd <= addr) break;    // защита от отсутствия прогресса
        bool usable = mbi.State == MEM_COMMIT;
        if (usable) {
            const DWORD prot = mbi.Protect & 0xFF;
            usable = prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                     prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            if (mbi.Protect & PAGE_GUARD) usable = false;
        }
        if (!usable) { addr = regionEnd; continue; }
        uintptr_t cur = addr;
        while (cur < regionEnd && n < maxOut) {
            const size_t want = (size_t)(regionEnd - cur < kChunk ? regionEnd - cur : kChunk);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(),
                                   want, &got) || got < 8) {
                cur += kChunk;
                continue;
            }
            for (size_t off = 0; off + 8 <= got && n < maxOut; off += 8) {
                if (*(const uint64_t*)(buf.data() + off) == (uint64_t)vtVal)
                    out[n++] = cur + off;
            }
            if (got < want) break;
            cur += kChunk;
        }
        addr = regionEnd;
    }
    return n;
}

// Обход списка записей реестра от сентинела: поиск ключа ICommandService
// (точное сравнение двух qword — как в impl getService), возврат сервиса.
// Только чтение памяти; битые узлы прерывают обход кандидата.
bool MMRegistryFindSvc(uintptr_t proc, uintptr_t* svcOut) {
    if (!IsReadable((void*)(proc + kMMRegSentinel), 8)) return false;
    const uintptr_t sentinel = *(uintptr_t*)(proc + kMMRegSentinel);
    if (!sentinel || !IsReadable((void*)sentinel, 16)) return false;
    uintptr_t node = *(uintptr_t*)sentinel;
    for (int i = 0; node && node != sentinel && i < 4096; ++i) {
        if (!IsReadable((void*)node, 0x40)) return false;
        if (*(const uint64_t*)(node + kMMRegNodeKey) == kMMIidSvcQ0 &&
            *(const uint64_t*)(node + kMMRegNodeKey + 8) == kMMIidSvcQ1) {
            const uintptr_t svc = *(uintptr_t*)(node + kMMRegNodeSvc);
            if (svc && IsReadable((void*)svc, kMMManagerOff + 8)) {
                *svcOut = svc;
                return true;
            }
            return false;
        }
        node = *(uintptr_t*)node;
    }
    return false;
}

// Рекурсивный поиск панели {MM_FRAME}/52 в std::map-дереве менеджера панелей.
// Битая вершина или превышение глубины завершают ветку (карта сбалансирована,
// глубина живого меню — единицы).
constexpr unsigned kMMFrameBand52 = 52;   // панель «Сервис» — маркер главного менеджера

bool MMTreeHasFrameBand(uintptr_t node, int depth) {
    if (!node || depth > 24) return false;
    if (!IsReadable((void*)node, 0x40)) return false;
    if (*(const uint8_t*)(node + kMMNodeIsnil)) return false;   // сентинел
    if (*(const uint64_t*)(node + kMMNodeKey) == kMMFrameQ0 &&
        *(const uint64_t*)(node + kMMNodeKey + 8) == kMMFrameQ1 &&
        *(const unsigned*)(node + kMMNodeNum) == kMMFrameBand52)
        return true;
    return MMTreeHasFrameBand(*(const uintptr_t*)node, depth + 1) ||
           MMTreeHasFrameBand(*(const uintptr_t*)(node + kMMNodeRight), depth + 1);
}

// Выбор менеджера панелей по содержимому: среди объектов класса менеджера
// (vtable frame.dll+0xB097F0) берём тот, чья карта уже содержит панель рамки.
bool MMFindMenuManager(uintptr_t mgrVtVal, uintptr_t* mgrOut) {
    // Лимит велик: значение vtable встречается и в стековых слотах/коде, и
    // лимит 32 заполнялся ложными попаданиями раньше кучи (live 2342).
    uintptr_t cands[4096] = {};
    const int n = MMFindInstances(mgrVtVal, cands, 4096);
    // Диагностика выбора: счётчик кандидатов и состояние первых — в журнал
    // (печатается не на каждом опросе, чтобы не заливать лог).
    static LONG diagTick = 0;
    const bool diag = (InterlockedIncrement(&diagTick) % 5) == 1;
    if (diag) LogLine("mainmenu: менеджер-скан: кандидатов %d", n);
    for (int i = 0; i < n; ++i) {
        const uintptr_t mgr = cands[i];
        if (!IsReadable((void*)(mgr + kMMManagerOff + 8), 8)) continue;
        const uintptr_t sent = *(uintptr_t*)(mgr + kMMManagerOff);
        if (!sent || !IsReadable((void*)(sent + 16), 1)) continue;
        const uintptr_t root = *(uintptr_t*)(sent + 8);   // std::map _Parent
        if (root && root != sent && MMTreeHasFrameBand(root, 0)) {
            *mgrOut = mgr;
            return true;
        }
    }
    return false;
}

// Один опрос: скан экземпляров SCOM_Process, из реестра первого с записью
// ICommandService берём сервис (registerCommands); менеджер панелей ищем
// сканом по содержимому карты. Сервисы и меню регистрируются по мере
// инициализации платформы, поэтому опрос повторяется снаружи.
bool MMScanRegistry(MMState* m) {
    ModuleRange core;
    if (!FindModule(L"core83.dll", core)) return false;
    if (!m->svc) {
        uintptr_t inst[64] = {};   // значение vtable также лежит в стековых слотах
        const int n = MMFindInstances(core.base + kMMProcVtableRva, inst, 64);
        for (int i = 0; i < n; ++i) {
            uintptr_t svc = 0;
            if (!MMRegistryFindSvc(inst[i], &svc)) continue;
            if (!IsReadable((void*)svc, 0x40)) continue;
            m->proc = inst[i];
            m->svc = svc;
            LogLine("mainmenu: экземпляр 0x%llX — ICommandService svc=0x%llX",
                    (unsigned long long)inst[i], (unsigned long long)svc);
            break;
        }
        if (!m->svc) return false;
    }
    // Менеджер: сначала по содержимому карты (главное меню), затем fallback —
    // менеджер сервиса (v8snack-путь), если у него есть источники.
    ModuleRange frame;
    if (FindModule(L"frame.dll", frame)) {
        uintptr_t menuMgr = 0;
        if (MMFindMenuManager(frame.base + kMMMngrVtableRva, &menuMgr)) {
            m->manager = menuMgr;
            LogLine("mainmenu: менеджер панелей найден сканом: 0x%llX "
                    "(карта содержит {MM_FRAME}/52)", (unsigned long long)menuMgr);
            return true;
        }
    }
    uintptr_t svcMgr = *(uintptr_t*)(m->svc + kMMManagerOff);
    if (svcMgr && IsReadable((void*)(svcMgr + 0xB8 + 8), 8)) {
        const uintptr_t srcs = *(uintptr_t*)(svcMgr + 0xB8);
        if (srcs && IsReadable((void*)srcs, 8) && *(uintptr_t*)srcs != srcs) {
            m->manager = svcMgr;
            LogLine("mainmenu: менеджер из [svc+0xD0]=0x%llX (источники не пусты)",
                    (unsigned long long)svcMgr);
            return true;
        }
    }
    return false;
}

// SEH-обёртки одной попытки: сами функции без C++-объектов, поэтому __try
// здесь допустим (в MMWorkerInner unwind запрещает его — C2712).
bool MMDiscoverReceiverGuarded(void** recvOut, uintptr_t** recvVtOut,
                               int* transmitSlot, int* updateSlot, int* hasSlot,
                               void** coreOut, void** frameObjOut) {
    __try {
        return V8iGetCommandReceiver(recvOut, recvVtOut, transmitSlot, updateSlot,
                                     hasSlot, coreOut, frameObjOut);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void MMScanRegistryGuarded(MMState* m) {
    __try {
        MMScanRegistry(m);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogLine("mainmenu: скан реестра упал (0x%08X)", GetExceptionCode());
    }
}

// Тело рабочего потока. Вызывается из SEH-обёртки: любое исключение в нашем
// потоке не должно убивать 1С (payload-правило «каждый поток под SEH»).
// SEH-обёртки отдельных попыток вынесены в функции без C++-объектов: __try
// запрещён там, где компилятор строит unwind (C2712).
void MMWorkerInner() {
    LogLine("mainmenu: поток запущен, ждём устояния платформы");
    // Хуки обёрток ставятся как можно раньше (1С вызывает getService при
    // загрузке базы; поздняя установка пропускает эти вызовы).
    ModuleRange exeM;
    if (FindModule(L"1cv8.exe", exeM)) {
        std::string hookErr;
        uint32_t hookId = HookInstallObserved(exeM.base + kMMWrapperRva,
                "getServiceWrapper", MMObsTakeProc, hookErr);
        LogLine("mainmenu: хук обёртки getService (1cv8+0xBFCB0): %s",
                hookId ? "установлен" : hookErr.c_str());
    }

    Sleep(3000);
    if (!MMNativeMenuEnabled()) {
        LogLine("mainmenu: отключён ([git] nativemenu=0)");
        return;
    }
    bool is85 = false;
    if (!MMSupported(&is85)) {
        LogLine("mainmenu: версия платформы не поддержана — пункт не добавлен");
        return;
    }
    if (is85) {
        LogLine("mainmenu: 8.5 — приёмник для перехватов ещё не подключён, пункт не добавлен");
        return;
    }

    // 0. приёмник и объекты цепочки рамки (рабочий поток, безопасно):
    //    та же дискавери+проба, что у cmd-цепочки. Проба звает слоты чужих
    //    vtable — падение одной попытки не должно убивать весь воркер.
    void* recv = nullptr;
    uintptr_t* recvVt = nullptr;
    int txSlot = 3, updSlot = 4, hasSlot = 5;
    void* core = nullptr;
    void* frameObj = nullptr;
    bool receiverOk = false;
    for (int i = 0; i < 30 && !receiverOk; ++i) {
        receiverOk = MMDiscoverReceiverGuarded(&recv, &recvVt, &txSlot, &updSlot,
                                               &hasSlot, &core, &frameObj);
        if (!receiverOk) Sleep(3000);
    }
    if (!receiverOk) {
        LogLine("mainmenu: приёмник не захвачен за отведённое время — пункт не добавлен");
        return;
    }
    MMState* m = &g_mm;
    m->recv = recv;
    m->recvVt = recvVt;
    m->core = core;
    m->frameObj = frameObj;
    m->trapTx = txSlot;
    m->trapUpd = updSlot;
    m->trapHas = hasSlot;
    LogLine("mainmenu: приёмник 0x%llX (core 0x%llX, рамка 0x%llX), слоты tx/upd/has %d/%d/%d",
            (unsigned long long)(uintptr_t)recv, (unsigned long long)(uintptr_t)core,
            (unsigned long long)(uintptr_t)frameObj, txSlot, updSlot, hasSlot);

    // хук на обёртку config.dll (загружена к этому моменту)
    ModuleRange cfgM;
    if (FindModule(L"config.dll", cfgM)) {
        std::string hookErr;
        constexpr uintptr_t kMMCfgWrapperRva = 0xCF320;   // 8.3.27.2342 x64
        uint32_t hookId = HookInstallObserved(cfgM.base + kMMCfgWrapperRva,
                "getServiceWrapperCfg", MMObsTakeProc, hookErr);
        LogLine("mainmenu: хук обёртки getService (config+0xCF320): %s",
                hookId ? "установлен" : hookErr.c_str());
    }

    // 1. R2-путь: скан экземпляров SCOM_Process по vtable и чтение реестра
    //    getService. Сервисы регистрируются по мере инициализации — опрашиваем
    //    до 5 минут (журнал каждые 30 с). Только чтение памяти: безопасно на
    //    рабочем потоке, без маршала и без вызовов vtable.
    bool scanRan = false;
    for (int i = 0; i < 30 && !(m->svc && m->manager); ++i) {
        if ((i % 3) == 2)
            LogLine("mainmenu: скан реестра сервисов (%d с)", (i + 1) * 10);
        scanRan = true;
        MMScanRegistryGuarded(m);
        if (m->svc && m->manager) break;
        Sleep(10000);
    }
    if (m->svc && m->manager) {
        LogLine("mainmenu: ICommandService получен чтением реестра getService");
    } else {
        // 2. Fallback: прежний путь — захват объекта хуком обёртки getService
        //    (до 5 минут; журнал каждые 15 с), затем QI и getService (слот 14)
        //    на UI-потоке. Обёртка вызывается платформой при работе с командами.
        for (int i = 0; i < 100 && !m->proc; ++i) {
            if ((i % 5) == 4)
                LogLine("mainmenu: ожидание захвата объекта через хук (%d с)", (i + 1) * 3);
            Sleep(3000);
        }
        if (!m->proc) {
            LogLine("mainmenu: %s — пункт не добавлен",
                    scanRan ? "реестр сервисов не дал ICommandService и обёртка не вызвана"
                            : "скан реестра не выполнялся, обёртка не вызвана");
            return;
        }
        LogLine("mainmenu: объект процесса 0x%llX — QI за ICommandService",
                (unsigned long long)m->proc);

        m->stage = "QueryInterface";
        m->svc = 0;
        m->manager = 0;
        v8i::V8iRunOnUi(MMStepQI, m);
        if (!(m->svc && m->manager)) {
            LogLine("mainmenu: QI не дал ICommandService — пробуем getService (слот 14)");
            m->stage = "getService слот 14";
            m->svc = 0;
            m->manager = 0;
            if (!v8i::V8iRunOnUi(MMStepGetService, m) || !(m->svc && m->manager)) {
                LogLine("mainmenu: getService на захваченном объекте не подтвердился "
                        "— пункт не добавлен");
                return;
            }
        }
    }

    // 3. цепочка построения: образцы, registerCommands, источник, перехваты.
    // Шаг с m->stepFailed (например, меню ещё не построено) повторяется по
    // расписанию; шаги с побочным эффектом (регистрация, источник, перехваты)
    // атомарны — повтор не дублирует их.
    struct MMStepDef { const char* name; void (*fn)(void*); };
    const MMStepDef steps[] = {
        {"образцы пунктов",  MMStepTemplates},
        {"registerCommands", MMStepRegister},
        {"источник панелей", MMStepSource},
        {"перехваты",        MMStepTraps},
    };
    bool built = false;
    for (int attempt = 1; attempt <= 20 && !built; ++attempt) {
        bool ok = true;
        for (const MMStepDef& s : steps) {
            m->stage = s.name;
            m->stepFailed = false;
            if (!v8i::V8iRunOnUi(s.fn, m)) {
                LogLine("mainmenu: цепочка прервана на шаге «%s» (попытка %d)",
                        s.name, attempt);
                ok = false;
                break;
            }
            if (m->stepFailed) {
                LogLine("mainmenu: шаг «%s» повторится (попытка %d)",
                        s.name, attempt);
                ok = false;
                break;
            }
        }
        if (ok) { built = true; break; }
        Sleep(2500);
    }
    if (!built) {
        LogLine("mainmenu: %s", m->err[0] ? m->err : "цепочка построения не прошла");
        return;
    }

    // Платформа отбрасывает перестройку, пока достраивает меню (загрузка
    // конфигурации, восстановление окон), сигнала готовности нет — запрос
    // updateState нашего popup приходит только от нарисованного пункта.
    // Ретраи по расписанию v8snack: 3 с, далее 2 с (до 40), далее 10 с, до 60.
    for (int i = 0; i < 60 && !m->confirmed; ++i) {
        Sleep(i == 0 ? 3000 : (i < 40 ? 2000 : 10000));
        v8i::V8iRunOnUi(MMRebuildStep, m);
    }
    if (m->confirmed) {
        LogLine("mainmenu: пункт «GitBar» в главном меню работает");
        V8iGitBarSetNativeMenu();
    } else {
        LogLine("mainmenu: updateState пункта не пришёл за отведённые перестройки");
    }
}

DWORD WINAPI MMWorkerThread(LPVOID) {
    // Один строитель на процесс: несколько копий payload в одном 1С каждая
    // поднимают свой воркер, и двойное registerCommands/addSource роняет
    // перестройку меню (live 2342: 0xC00000FD в rebuild). Мьютекс держится до
    // конца потока — освобождается в любом исходе, включая исключение.
    HANDLE buildMutex = CreateMutexW(nullptr, FALSE, L"Local\\v8inject.mainmenu.build");
    bool mine = !buildMutex || WaitForSingleObject(buildMutex, 15000) == WAIT_OBJECT_0;
    __try {
        if (mine) MMWorkerInner();
        else LogLine("mainmenu: построение уже идёт в другом воркере — выходим");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogLine("mainmenu: поток упал (0x%08X) на шаге «%s», пункт не добавлен — 1С не тронута",
                GetExceptionCode(), g_mm.stage ? g_mm.stage : "?");
    }
    if (mine && buildMutex) ReleaseMutex(buildMutex);
    if (buildMutex) CloseHandle(buildMutex);
    return 0;
}

void V8iStartNativeMenu() {
    HANDLE t = CreateThread(nullptr, 0, MMWorkerThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

}  // namespace v8i