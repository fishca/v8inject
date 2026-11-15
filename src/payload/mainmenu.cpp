// Нативный пункт «GitBar» в главном меню Конфигуратора.
//
// Платформа не даёт публичного API для добавления пунктов в главное меню, но
// рисует его из внутренних «панелей» (bands): панель — CommandID {GUID группы,
// номер}, содержимое — вектор пунктов по 0x70 байт (CommandID + вес double,
// порядок по весу). Модули платформы дополняют меню точно так же, как нужно
// нам: создают CommandInterface (createByClsid), кладут в него панели
// (addBand) и отдают менеджеру панелей (addSource + перестройка). Полный
// реверс и раскладка — проект v8snack (tools/MAINMENU.md,
// engine/mainmenu.as, v8api/process.v); эта реализация — перевод того рецепта
// на C++ payloads v8inject.
//
// Объект процесса берётся не из ?current_process@core (тот возвращает объект,
// у которого getService отвечает null на live 8.3.27.2342), а перехватом
// обёртки getService в 1cv8.exe (rva 0xBFCB0, калибровка 2342 x64): 1С сама
// передаёт в неё настоящий SCOM_Process — наблюдатель хука его захватывает.
// Слоты getService = 14 подтверждены той же обёрткой (call [rax+0x70]).
//
// Ветки раскладки v8snack: 8.3.27 и 8.5 совпадают (entry 0x68, SSO-текст).
// Наши тексты («GitBar», «Настройки») короче 10 символов и целиком помещаются
// в SSO-описание команды — ICommandState.setText не требуется.

#include "v8inject/diag.h"
#include "v8inject/hook.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/v8i_export.h"

#include <windows.h>
#include <commctrl.h>
#include <cstdint>
#include <cstring>
#include <cwchar>

namespace v8i {

// Из src/payload/gitbar.cpp (namespace v8i).
void V8iGitBarMenuAction(unsigned num);
void V8iGitBarSetNativeMenu();

// --- константы рецепта (v8snack mainmenu.as:10-30, MAINMENU.md §2-§6) ------

const wchar_t kMMGroupStr[] = L"{8B4A6E2F-7D31-4A9C-B5F4-2C6E9D1A47B3}";  // группа наших команд
const wchar_t kMMCatPopupStr[] = L"{79FC5DE1-99D4-45EE-A887-22970F440CE6}";  // категория «Подменю» платформы
const wchar_t kMMCatOwnStr[] = L"{8B4A6E2F-7D31-4A9C-B5F4-2C6E9D1A47B4}";    // категория наших (платформе не регистрируется)
const wchar_t kMMFrameStr[] = L"{B78F2E80-EC68-11D4-9DCF-0050BAE2BC79}";     // группа команд главного окна
const wchar_t kMMClsidCIStr[] = L"{F459D5F0-E7C0-11D4-9DCD-0050BAE2BC79}";   // CommandInterface
const wchar_t kMMIidCIStr[] = L"{7DF15090-7A63-11D4-84A1-008048DA06DF}";
const wchar_t kMMIidSvcStr[] = L"{8F885821-D353-11D3-8A57-008048DA06DF}";   // IID ICommandService
const unsigned kMMPopupNum = 1;       // popup «GitBar»
const unsigned kMMSettingsNum = 2;    // «Настройки»
const unsigned kMMServiceBandNum = 52;   // панель меню «Сервис» ({MM_FRAME}/52)
const uint64_t kMMWeightPopup = 0x4059000000000000ULL;  // 100.0 — конец «Сервиса»
const uint64_t kMMWeightSep = 0x4058C00000000000ULL;    // 99.0 — разделитель перед пунктом
const uint64_t kMMWeightItem = 0x3FF0000000000000ULL;   // 1.0 — пункт внутри popup

// Разделитель «Сервиса»: {9D0A2E40-B978-11D4-84B6-008048DA06DF}/0
constexpr uint64_t kMMSepGuidA = 0x11d4b9789d0a2e40ULL;
constexpr uint64_t kMMSepGuidB = 0xdf06da488000b684ULL;

constexpr uintptr_t kMMManagerOff = 0xD0;   // [ICommandService + 0xD0] — менеджер панелей
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

GUID MMGuid(const wchar_t* s) {   // «{XXXXXXXX-XXXX-…}» в раскладке Windows GUID
    GUID g{};
    auto hex = [](const wchar_t* p, int n) {
        unsigned v = 0;
        for (int i = 0; i < n; ++i) {
            wchar_t c = p[i];
            v <<= 4;
            if (c >= L'0' && c <= L'9') v |= (unsigned)(c - L'0');
            else if (c >= L'a' && c <= L'f') v |= (unsigned)(c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') v |= (unsigned)(c - L'A' + 10);
        }
        return v;
    };
    g.Data1 = hex(s + 1, 8);
    g.Data2 = (unsigned short)hex(s + 10, 4);
    g.Data3 = (unsigned short)hex(s + 15, 4);
    for (int i = 0; i < 8; ++i) g.Data4[i] = (unsigned char)hex(s + 20 + i * 2, 2);
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

// Первый пункт панели как образец (копируется целиком, потом правятся id и вес)
uintptr_t MMTemplate(uintptr_t manager, const GUID& group, unsigned num) {
    uintptr_t band = MMBand(manager, MMNewCid(group, num));
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

size_t __fastcall MMUpdateTrap(size_t self, size_t state) {
    size_t r = MMCall1(g_mm.origUpdate, self, state);
    if (state) {
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
    if (num == kMMSettingsNum) {
        V8iGitBarMenuAction(kMMSettingsNum);
        return true;
    }
    if (num == 3) {   // показать/скрыть панель
        V8iGitBarMenuAction(3);
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
    uintptr_t tmplLeaf = MMTemplate(m->manager, frameGroup, kMMServiceBandNum);
    if (!tmplPopup || !tmplLeaf) { strcpy_s(m->err, "не найдены образцы пунктов"); return; }
    LogLine("mainmenu: образцы пунктов получены (popup=0x%llX leaf=0x%llX)",
            (unsigned long long)tmplPopup, (unsigned long long)tmplLeaf);
}

void MMStepRegister(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    m->stage = "registerCommands";
    GUID group = MMGuid(kMMGroupStr);
    GUID catPopup = MMGuid(kMMCatPopupStr);
    GUID catOwn = MMGuid(kMMCatOwnStr);
    uintptr_t bundle = MMNewAnsi("frame");
    uintptr_t entries = MMAlloc(kMMEntrySize * 2);
    memcpy((void*)entries,
           (void*)MMCmdEntry(group, kMMPopupNum, catPopup, "GitBarPopup", bundle),
           kMMEntrySize);
    memcpy((void*)(entries + kMMEntrySize),
           (void*)MMCmdEntry(group, kMMSettingsNum, catOwn, "GitBarSettings", bundle),
           kMMEntrySize);
    uintptr_t svt = *(uintptr_t*)m->svc;
    MMCall3(*(uintptr_t*)(svt + kMMSlotRegisterCommands * 8),
            m->svc, bundle, entries, 2);
    m->stage = "тексты пунктов";
    MMSetCommandText(m->svc, group, kMMPopupNum, L"GitBar");
    MMSetCommandText(m->svc, group, kMMSettingsNum, L"Настройки");
    LogLine("mainmenu: команды группы зарегистрированы");
}

void MMStepSource(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    m->stage = "источник панелей";
    GUID frameGroup = MMGuid(kMMFrameStr);
    GUID group = MMGuid(kMMGroupStr);
    // образцы заново: между register и source платформа могла перестроиться
    uintptr_t tmplPopup = MMTemplate(m->manager, frameGroup, 1);
    uintptr_t tmplLeaf = MMTemplate(m->manager, frameGroup, kMMServiceBandNum);
    if (!tmplPopup || !tmplLeaf) { strcpy_s(m->err, "не найдены образцы пунктов"); return; }

    uintptr_t clsid = MMAlloc(16), iid = MMAlloc(16), outp = MMAlloc(16);
    MMPutGuid(clsid, MMGuid(kMMClsidCIStr));
    MMPutGuid(iid, MMGuid(kMMIidCIStr));
    MMCall3(*(uintptr_t*)(*(uintptr_t*)m->proc + kMMSlotProcCreate * 8),
            m->proc, clsid, iid, outp);
    m->src = *(uintptr_t*)outp;
    if (!m->src) { strcpy_s(m->err, "не создан источник панелей"); return; }

    // разделитель перед пунктом: образец — разделитель панели «Сервис»
    uintptr_t sepTmpl = 0;
    uintptr_t bandSvc = MMBand(m->manager, MMNewCid(frameGroup, kMMServiceBandNum));
    if (bandSvc) {
        uintptr_t b0 = *(uintptr_t*)(bandSvc + 0x30);
        uintptr_t e0 = *(uintptr_t*)(bandSvc + 0x38);
        for (uintptr_t p = b0; p + kMMItemSize <= e0; p += 8) {
            uintptr_t it = *(uintptr_t*)p;
            if (it && *(uintptr_t*)it == kMMSepGuidA && *(uintptr_t*)(it + 8) == kMMSepGuidB) {
                sepTmpl = it;
                break;
            }
        }
    }

    uintptr_t mainItems = MMAlloc(kMMItemSize * 2);
    size_t mainCount = 0;
    if (sepTmpl) {
        memcpy((void*)mainItems, (void*)sepTmpl, kMMItemSize);
        *(uint64_t*)(mainItems + 0x30) = kMMWeightSep;
        mainCount = 1;
    }
    memcpy((void*)(mainItems + mainCount * kMMItemSize),
           (void*)MMItem(tmplPopup, group, kMMPopupNum, kMMWeightPopup), kMMItemSize);
    mainCount++;
    uintptr_t popItems = MMAlloc(kMMItemSize);
    memcpy((void*)popItems,
           (void*)MMItem(tmplLeaf, group, kMMSettingsNum, kMMWeightItem), kMMItemSize);

    uintptr_t sv = *(uintptr_t*)m->src;
    MMCall3(*(uintptr_t*)(sv + kMMSlotAddBand * 8), m->src,
            MMNewCid(frameGroup, kMMServiceBandNum), MMVector(mainItems, mainCount), 0);
    MMCall3(*(uintptr_t*)(sv + kMMSlotAddBand * 8), m->src,
            MMNewCid(group, kMMPopupNum), MMVector(popItems, 1), 0);
    MMCall0(*(uintptr_t*)(sv + kMMSlotFinish * 8), m->src);
    LogLine("mainmenu: панели подключены (разделитель %s)",
            sepTmpl ? "найден" : "нет образца");
}

void MMStepTraps(void* arg) {
    MMState* m = (MMState*)arg;
    m->stepRan = true;
    m->stage = "перехваты приёмника";
    if (m->recv && m->recvVt &&
        MMPatchSlot(m->recvVt, m->trapUpd, (void*)&MMUpdateTrap, &m->origUpdate) &&
        MMPatchSlot(m->recvVt, m->trapHas, (void*)&MMHasTrap, &m->origHas) &&
        MMPatchSlot(m->recvVt, m->trapTx, (void*)&MMTransmitTrap, &m->origTransmit)) {
        m->groupBytes = MMAlloc(32);
        MMPutGuid(m->groupBytes, MMGuid(kMMGroupStr));
        LogLine("mainmenu: перехваты установлены на приёмник 0x%llX",
                (unsigned long long)(uintptr_t)m->recv);
    } else {
        LogLine("mainmenu: приёмник для перехватов не получен — пункты останутся неактивными");
    }
    m->built = true;
    LogLine("mainmenu: пункт «GitBar» добавлен в меню «Сервис»");
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

// Тело рабочего потока. Вызывается из SEH-обёртки: любое исключение в нашем
// потоке не должно убивать 1С (payload-правило «каждый поток под SEH»).
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
    //    та же дискавери+проба, что у cmd-цепочки.
    void* recv = nullptr;
    uintptr_t* recvVt = nullptr;
    int txSlot = 3, updSlot = 4, hasSlot = 5;
    void* core = nullptr;
    void* frameObj = nullptr;
    bool receiverOk = false;
    for (int i = 0; i < 30 && !receiverOk; ++i) {
        receiverOk = V8iGetCommandReceiver(&recv, &recvVt, &txSlot, &updSlot,
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

    // 1. ожидание захвата объекта через хуки обёрток (до 5 минут; журнал
    //    каждые 15 с). Обёртка getService вызывается платформой при работе
    //    с командами — провоцируется отправкой команд дизайнера.
    for (int i = 0; i < 100 && !m->proc; ++i) {
        if ((i % 5) == 4)
            LogLine("mainmenu: ожидание захвата объекта через хук (%d с)", (i + 1) * 3);
        Sleep(3000);
    }
    if (!m->proc) {
        LogLine("mainmenu: обёртка не вызвана платформой — пункт не добавлен");
        return;
    }
    LogLine("mainmenu: объект процесса 0x%llX — QI за ICommandService",
            (unsigned long long)m->proc);

    // 2. QueryInterface за ICommandService (UI-поток): захваченный объект —
    //    первый кандидат, затем приёмник/core/рамка.
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

    // 3. цепочка построения: образцы, registerCommands, источник, перехваты.
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
            if (!v8i::V8iRunOnUi(s.fn, m)) {
                LogLine("mainmenu: цепочка прервана на шаге «%s» (попытка %d)",
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
    __try {
        MMWorkerInner();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogLine("mainmenu: поток упал (0x%08X) на шаге «%s», пункт не добавлен — 1С не тронута",
                GetExceptionCode(), g_mm.stage ? g_mm.stage : "?");
    }
    return 0;
}

void V8iStartNativeMenu() {
    HANDLE t = CreateThread(nullptr, 0, MMWorkerThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

}  // namespace v8i