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
// Точка входа в сервисы — именованный экспорт ядра
// ?current_process@core@@… (process.v:43), getService — слот 14 SCOM_Process.
// Наши команды живут в отдельной группе и перехватываются на приёмнике
// главного окна: vtable-патч updateState/hasHandler/transmitCommand, команды
// нашей группы на платформу не уходят.
//
// Ветки раскладки v8snack: 8.3.27 и 8.5 совпадают (запись 0x68, SSO-текст).
// Здесь подключена 8.3.27; на прочих версиях пункт не добавляется.
// Наши тексты («GitBar», «Настройки») короче 10 символов и целиком помещаются
// в SSO-описание команды — ICommandState.setText не требуется.

#include "v8inject/diag.h"
#include "v8inject/ini.h"
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
const wchar_t* V8iGitBarIniPath();
void V8iGitBarSetNativeMenu();
void V8iGitBarMenuAction(unsigned num);

namespace {

// --- константы рецепта (v8snack mainmenu.as:10-30, MAINMENU.md §2-§6) ------

const wchar_t kMMGroupStr[] = L"{8B4A6E2F-7D31-4A9C-B5F4-2C6E9D1A47B3}";  // группа наших команд
const wchar_t kMMCatPopupStr[] = L"{79FC5DE1-99D4-45EE-A887-22970F440CE6}";  // категория «Подменю» платформы
const wchar_t kMMCatOwnStr[] = L"{8B4A6E2F-7D31-4A9C-B5F4-2C6E9D1A47B4}";    // категория наших (платформе не регистрируется)
const wchar_t kMMFrameStr[] = L"{B78F2E80-EC68-11D4-9DCF-0050BAE2BC79}";     // группа команд главного окна
const wchar_t kMMClsidCIStr[] = L"{F459D5F0-E7C0-11D4-9DCD-0050BAE2BC79}";   // CommandInterface
const wchar_t kMMIidCIStr[] = L"{7DF15090-7A63-11D4-84A1-008048DA06DF}";
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
constexpr int kMMSlotProcCreate = 5;        // SCOM_Process.createByClsid
constexpr int kMMSlotProcGetService = 14;   // SCOM_Process.getService (process.v)
constexpr int kMMSlotStateId = 3;           // ICommandState.id()
constexpr int kMMSlotStateEnable = 6;       // ICommandState.enable(bool)
constexpr size_t kMMItemSize = 0x70;
constexpr size_t kMMEntrySize = 0x68;
constexpr size_t kMMEStr = 0x40, kMMEInt1 = 0x58, kMMEInt2 = 0x5C, kMMEByte = 0x60;

const char kMMExportX64[] = "?current_process@core@@YAPEAVSCOM_Process@1@XZ";
const char kMMExportX86[] = "?current_process@core@@YAPAVSCOM_Process@1@XZ";
const wchar_t kMMIidSvcStr[] = L"{8F885821-D353-11D3-8A57-008048DA06DF}";   // IID ICommandService

// --- состояние --------------------------------------------------------------

struct MMState {
    GUID group{};
    uintptr_t groupBytes = 0;       // 32 байта: GUID + номер (для mmIsOurs)
    uintptr_t svc = 0, manager = 0, src = 0, proc = 0;
    bool built = false;             // registerCommands/addBand/addSource прошли
    bool failed = false;            // непоправимый шаг, повторять бессмысленно
    bool confirmed = false;         // платформа запросила updateState нашего popup
    char err[160] = {};
    // перехваты на приёмнике главного окна
    uintptr_t* recvVt = nullptr;
    void* recv = nullptr;
    uintptr_t origUpdate = 0, origHas = 0, origTransmit = 0;
};
MMState g_mm;

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

// --- сервисы ----------------------------------------------------------------

// SCOM_Process* current_process() — именованный экспорт ядра (process.v:43).
uintptr_t MMCurrentProcess() {
    const wchar_t* mods[] = { L"core83.dll", L"core85.dll", L"core.dll" };
#if defined(_WIN64)
    const char* exportName = kMMExportX64;
#else
    const char* exportName = kMMExportX86;
#endif
    for (const wchar_t* mod : mods) {
        ModuleRange m;
        if (!FindModule(mod, m)) continue;
        PeImage img = ParsePe(m.base);
        if (!img.valid) continue;
        for (const PeExport& e : img.exports) {
            if (e.forwarded || e.name != exportName) continue;
            typedef uintptr_t (*FnCurrentProcess)();
            return ((FnCurrentProcess)(m.base + e.rva))();
        }
    }
    return 0;
}

// --- маршал на UI-поток -----------------------------------------------------

// Отдельный subclass рамки (id 2) со своим сообщением: не пересекается с
// маршалом cmd (id 1, WM_APP+0x2F11) ни сообщением, ни структурой.
struct MMPending {
    void (*fn)(void*);
    void* arg;
    volatile LONG done;
    int rc;
};
MMPending g_mmPending = {};
HWND g_mmHwnd = nullptr;
const UINT kMMCmdMsg = WM_APP + 0x2F13;

LRESULT CALLBACK MMSubclassProc(HWND h, UINT m, WPARAM w, LPARAM l,
                                UINT_PTR id, DWORD_PTR data) {
    (void)id;
    if (m == kMMCmdMsg) {
        MMPending* p = (MMPending*)data;
        __try {
            p->fn(p->arg);
            p->rc = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            p->rc = -1;
        }
        InterlockedExchange(&p->done, 1);
        return 0;
    }
    return DefSubclassProc(h, m, w, l);
}

HWND MMFindFrame() {
    DWORD pid = GetCurrentProcessId();
    HWND found = nullptr;
    struct Ctx { DWORD pid; HWND* out; } ctx = { pid, &found };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD wp = 0;
        GetWindowThreadProcessId(h, &wp);
        if (wp != c->pid) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(h, cls, 64);
        if (_wcsicmp(cls, L"V8TopLevelFrame") == 0 ||
            wcsncmp(cls, L"V8Window0", 9) == 0) {
            *c->out = h;
            return FALSE;
        }
        return TRUE;
    }, (LPARAM)&ctx);
    return found;
}

bool MMEnsureMarshal(HWND* out) {
    if (g_mmHwnd && IsWindow(g_mmHwnd)) { *out = g_mmHwnd; return true; }
    HWND frame = MMFindFrame();
    if (!frame) return false;
    HMODULE ctl = GetModuleHandleW(L"comctl32.dll");
    typedef BOOL(WINAPI* MMSetSubFn)(HWND, SUBCLASSPROC, UINT_PTR, DWORD_PTR);
    MMSetSubFn setFn = ctl ? (MMSetSubFn)GetProcAddress(ctl, "SetWindowSubclass") : nullptr;
    if (!setFn || !setFn(frame, MMSubclassProc, 2, (DWORD_PTR)&g_mmPending)) return false;
    g_mmHwnd = frame;
    *out = frame;
    return true;
}

// Один шаг построения/перестройки — строго на UI-потоке платформы.
bool MMRunOnUi(void (*fn)(void*), void* arg) {
    HWND h = nullptr;
    if (!MMEnsureMarshal(&h)) return false;
    g_mmPending.fn = fn;
    g_mmPending.arg = arg;
    g_mmPending.rc = -2;
    InterlockedExchange(&g_mmPending.done, 0);
    DWORD_PTR res = 0;
    if (!SendMessageTimeoutW(h, kMMCmdMsg, 0, 0,
                             SMTO_ABORTIFHUNG | SMTO_BLOCK, 15000, &res))
        return false;
    return g_mmPending.done && g_mmPending.rc == 0;
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

// --- построение (на UI-потоке через маршал) ---------------------------------

void MMBuildStep(void* arg) {
    MMState* m = (MMState*)arg;
    m->proc = MMCurrentProcess();
    if (!m->proc) { m->failed = true; strcpy_s(m->err, "current_process() не найден"); return; }

    GUID iidSvc = MMGuid(kMMIidSvcStr);
    m->svc = MMCall1(*(uintptr_t*)(*(uintptr_t*)m->proc + kMMSlotProcGetService * 8),
                     m->proc, (uintptr_t)&iidSvc);
    if (!m->svc) { m->failed = true; strcpy_s(m->err, "нет ICommandService"); return; }
    uintptr_t svcVt = *(uintptr_t*)m->svc;
    if (!IsReadable((void*)svcVt, 16 * sizeof(void*))) {
        m->failed = true; strcpy_s(m->err, "vtable ICommandService нечитаем"); return;
    }

    m->manager = *(uintptr_t*)(m->svc + kMMManagerOff);
    if (!m->manager) { m->failed = true; strcpy_s(m->err, "нет менеджера панелей"); return; }
    uintptr_t mgrVt = *(uintptr_t*)m->manager;
    if (!IsReadable((void*)mgrVt, 14 * sizeof(void*))) {
        m->failed = true; strcpy_s(m->err, "vtable менеджера нечитаем"); return;
    }

    // образцы пунктов — у живых панелей платформы
    GUID frameGroup = MMGuid(kMMFrameStr);
    uintptr_t tmplPopup = MMTemplate(m->manager, frameGroup, 1);
    uintptr_t tmplLeaf = MMTemplate(m->manager, frameGroup, kMMServiceBandNum);
    if (!tmplPopup || !tmplLeaf) {
        m->failed = true;
        strcpy_s(m->err, "не найдены образцы пунктов");
        return;
    }

    // 1. команды нашей группы
    uintptr_t bundle = MMNewAnsi("frame");
    uintptr_t entries = MMAlloc(kMMEntrySize * 2);
    GUID group = MMGuid(kMMGroupStr);
    GUID catPopup = MMGuid(kMMCatPopupStr);
    GUID catOwn = MMGuid(kMMCatOwnStr);
    memcpy((void*)entries,
           (void*)MMCmdEntry(group, kMMPopupNum, catPopup, "GitBarPopup", bundle),
           kMMEntrySize);
    memcpy((void*)(entries + kMMEntrySize),
           (void*)MMCmdEntry(group, kMMSettingsNum, catOwn, "GitBarSettings", bundle),
           kMMEntrySize);
    uintptr_t svt = *(uintptr_t*)m->svc;
    MMCall3(*(uintptr_t*)(svt + kMMSlotRegisterCommands * 8),
            m->svc, bundle, entries, 2);
    MMSetCommandText(m->svc, group, kMMPopupNum, L"GitBar");
    MMSetCommandText(m->svc, group, kMMSettingsNum, L"Настройки");

    // 2. источник панелей: пункт в «Сервисе» и содержимое popup
    uintptr_t clsid = MMAlloc(16), iid = MMAlloc(16), outp = MMAlloc(16);
    MMPutGuid(clsid, MMGuid(kMMClsidCIStr));
    MMPutGuid(iid, MMGuid(kMMIidCIStr));
    MMCall3(*(uintptr_t*)(*(uintptr_t*)m->proc + kMMSlotProcCreate * 8),
            m->proc, clsid, iid, outp);
    m->src = *(uintptr_t*)outp;
    if (!m->src) { m->failed = true; strcpy_s(m->err, "не создан источник панелей"); return; }

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

    // 3. перехваты на приёмнике главного окна
    int txSlot = 0, updSlot = 0, hasSlot = 0;
    void* recv = nullptr;
    uintptr_t* recvVt = nullptr;
    if (V8iGetCommandReceiver(&recv, &recvVt, &txSlot, &updSlot, &hasSlot) &&
        MMPatchSlot(recvVt, updSlot, (void*)&MMUpdateTrap, &m->origUpdate) &&
        MMPatchSlot(recvVt, hasSlot, (void*)&MMHasTrap, &m->origHas) &&
        MMPatchSlot(recvVt, txSlot, (void*)&MMTransmitTrap, &m->origTransmit)) {
        m->recv = recv;
        m->recvVt = recvVt;
        m->groupBytes = MMAlloc(32);
        MMPutGuid(m->groupBytes, group);
        LogLine("mainmenu: перехваты установлены на приёмник 0x%llX",
                (unsigned long long)(uintptr_t)recv);
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
// Первая версия потока работала без обёртки — исключение на первом шаге
// роняло конфигуратор (live 8.3.27.2342, AV через 1 мс после старта).
void MMWorkerInner() {
    LogLine("mainmenu: поток запущен, ждём устояния платформы");
    Sleep(3000);
    if (!MMNativeMenuEnabled()) {
        LogLine("mainmenu: отключён ([git] nativemenu=0)");
        return;
    }
    bool is85 = false;
    if (!MMSupported(&is85)) return;
    if (is85) {
        LogLine("mainmenu: 8.5 — приёмник для перехватов ещё не подключён, пункт не добавлен");
        return;
    }
    for (int attempt = 0; attempt < 40 && !g_mm.built && !g_mm.failed; ++attempt) {
        LogLine("mainmenu: попытка построения %d", attempt + 1);
        MMRunOnUi(MMBuildStep, &g_mm);
        if (g_mm.built || g_mm.failed) break;
        Sleep(2500);   // рамка/маршал ещё не готовы
    }
    if (!g_mm.built) {
        LogLine("mainmenu: %s", g_mm.failed ? g_mm.err : "построение не удалось за отведённые попытки");
        return;
    }
    if (g_mm.failed) {
        LogLine("mainmenu: %s", g_mm.err);
        return;
    }
    // Платформа отбрасывает перестройку, пока достраивает меню (загрузка
    // конфигурации, восстановление окон), сигнала готовности нет — запрос
    // updateState нашего popup приходит только от нарисованного пункта.
    // Ретраи по расписанию v8snack: 3 с, далее 2 с (до 40), далее 10 с, до 60.
    for (int i = 0; i < 60 && !g_mm.confirmed; ++i) {
        Sleep(i == 0 ? 3000 : (i < 40 ? 2000 : 10000));
        MMRunOnUi(MMRebuildStep, &g_mm);
    }
    if (g_mm.confirmed) {
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
        LogLine("mainmenu: поток упал (0x%08X), пункт не добавлен — 1С не тронута",
                GetExceptionCode());
    }
    return 0;
}

}  // namespace

void V8iStartNativeMenu() {
    HANDLE t = CreateThread(nullptr, 0, MMWorkerThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

}  // namespace v8i
