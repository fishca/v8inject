#include <windows.h>
#include <string>
#include <vector>

// Menu enumeration and invocation for the configurator's own menus. The menu
// bar of 1C's designer is an MFC custom control: GetMenu() on the frame from
// OUTSIDE the process returns null, so these commands exist inside the payload
// where the handles are live. This is also the primitive Variant B (custom menu
// items) will grow from.
//
//   menu [filter]            -- windows of this process and their menu items
//   menucmd <hwnd> <id>      -- PostMessage(WM_COMMAND, id) to that window

namespace v8i {

namespace {

std::string Narrow(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out.push_back(c < 0x80 ? (char)c : '?');
    return out;
}

std::string TrimNarrow(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) --b;
    return s.substr(a, b - a);
}

std::string WideToUtf8(const wchar_t* s) {
    std::string out;
    if (!s || !*s) return out;
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return out;
    out.resize(n - 1);
    WideCharToMultiByte(CP_UTF8, 0, s, -1, &out[0], n, nullptr, nullptr);
    return out;
}

// One menu item, flattened text without ampersands.
std::string ItemText(HMENU menu, int i) {
    wchar_t buf[512] = {};
    GetMenuStringW(menu, i, buf, 512, MF_BYPOSITION);
    std::string t = WideToUtf8(buf);
    std::string out;
    for (char c : t) if (c != '&') out.push_back(c);
    return TrimNarrow(out);
}

void AppendItem(std::string& j, HMENU menu, int i, int depth) {
    UINT state = GetMenuState(menu, i, MF_BYPOSITION);
    UINT id = GetMenuItemID(menu, i);
    bool separator = (state & MF_SEPARATOR) != 0;
    bool grayed = (state & (MF_GRAYED | MF_DISABLED)) != 0;

    if (separator) return;

    char buf[64];
    if (id == (UINT)-1 || id == 0) {
        // Popup submenu.
        HMENU sub = GetSubMenu(menu, i);
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"kind\":\"submenu\",\"depth\":%d,\"text\":\"%s\",\"items\":[",
                    depth, ItemText(menu, i).c_str());
        j += buf;
        if (sub) {
            int n = GetMenuItemCount(sub);
            for (int k = 0; k < n; ++k) {
                if (k) j += ",";
                AppendItem(j, sub, k, depth + 1);
            }
        }
        j += "]}";
    } else {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"kind\":\"cmd\",\"depth\":%d,\"id\":%u,\"text\":\"%s\",\"enabled\":%s}",
                    depth, id, ItemText(menu, i).c_str(), grayed ? "false" : "true");
        j += buf;
    }
}

void AppendWindow(std::string& j, HWND hwnd, const std::string& filter) {
    wchar_t title[256] = {};
    GetWindowTextW(hwnd, title, 256);
    wchar_t cls[128] = {};
    GetClassNameW(hwnd, cls, 128);

    std::string t = WideToUtf8(title);
    std::string c = WideToUtf8(cls);
    if (!filter.empty() && t.find(filter) == std::string::npos &&
        c.find(filter) == std::string::npos) {
        return;
    }

    char buf[256];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"hwnd\":\"0x%llX\",\"class\":\"%s\",\"title\":\"%s\",\"menu\":",
                (unsigned long long)(uintptr_t)hwnd, c.c_str(), t.c_str());
    j += buf;

    HMENU menu = GetMenu(hwnd);
    if (!menu) {
        j += "null}";
        return;
    }
    j += "[";
    int n = GetMenuItemCount(menu);
    for (int i = 0; i < n; ++i) {
        if (i) j += ",";
        AppendItem(j, menu, i, 0);
    }
    j += "]}";
}

}  // namespace

std::string MenuCommandToJson(const std::wstring& args) {
    std::string filter = Narrow(args);
    // First window with a non-empty title is the main frame; include children
    // too, because the menu may live on a client window of the frame.
    struct Win { HWND h; std::string cls; std::string title; };
    std::vector<Win> wins;
    HWND frame = nullptr;

    struct Ctx { std::vector<Win>* wins; DWORD pid; } ctx = { &wins, GetCurrentProcessId() };
    // Manual walk: EnumWindows with a lambda-capturing context.
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid != c->pid) return TRUE;
        wchar_t title[256] = {};
        GetWindowTextW(h, title, 256);
        wchar_t cls[128] = {};
        GetClassNameW(h, cls, 128);
        c->wins->push_back({h, WideToUtf8(cls), WideToUtf8(title)});
        return TRUE;
    }, (LPARAM)&ctx);

    for (const Win& w : wins)
        if (!w.title.empty()) { frame = w.h; break; }

    std::string j = "{\"status\":\"ok\",\"windows\":[";
    bool first = true;
    for (const Win& w : wins) {
        // Only frames and their immediate children; skip tiny tool windows.
        BOOL isChild = GetParent(w.h) == frame || w.h == frame;
        if (!isChild) continue;
        if (!first) j += ",";
        first = false;
        AppendWindow(j, w.h, filter);
    }
    j += "]}";
    return j;
}

std::string MenuCmdToJson(const std::wstring& args) {
    std::wstring rest = args;
    while (!rest.empty() && rest.front() == L' ') rest.erase(rest.begin());

    uintptr_t hwnd = 0;
    unsigned id = 0;
    {
        size_t sp = rest.find(L' ');
        std::wstring a = sp == std::wstring::npos ? rest : rest.substr(0, sp);
        std::wstring b = sp == std::wstring::npos ? L"" : rest.substr(sp + 1);
        hwnd = (uintptr_t)_wcstoui64(a.c_str(), nullptr, 0);
        id = (unsigned)_wtoi(b.c_str());
    }
    if (!hwnd || !id) {
        return "{\"status\":\"error\",\"message\":\"usage: menucmd <hwnd> <menu-id>\"}";
    }

    BOOL ok = PostMessageW((HWND)hwnd, WM_COMMAND, (WPARAM)id, 0);
    char buf[128];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"ok\",\"posted\":%s,\"hwnd\":\"0x%llX\",\"id\":%u}",
                ok ? "true" : "false", (unsigned long long)hwnd, id);
    return buf;
}

}  // namespace v8i