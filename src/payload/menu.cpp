#include <windows.h>
#include <string>
#include <vector>

#include "v8inject/text.h"

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

// One menu item, flattened text without ampersands, escaped for a JSON string.
std::string ItemTextJson(HMENU menu, int i) {
    wchar_t buf[512] = {};
    GetMenuStringW(menu, i, buf, 512, MF_BYPOSITION);
    const std::string t = WideToUtf8(buf);
    std::string flat;
    for (char c : t) if (c != '&') flat.push_back(c);
    return JsonEscape(TrimNarrow(flat));
}

// All items of a menu, joined by commas. Declared first: a submenu item needs
// it, and the two call each other.
std::string ItemsOf(HMENU menu, int depth);

// One menu item as a complete JSON value, or an empty string for a separator.
//
// A47: the whole fragment (a 45-byte prefix and the text) used to be formatted
// into a char[64], so any item with a few characters of text was cut inside a
// JSON string, the text went in through %s without escaping (a file-base path
// with a backslash broke the document), and the caller wrote a comma before
// asking for an item that a separator then returned empty: the reply of every
// real designer menu was ",," and dangling commas. Now one item is one
// std::string, and the caller joins the non-empty ones.
std::string ItemJson(HMENU menu, int i, int depth) {
    const UINT state = GetMenuState(menu, i, MF_BYPOSITION);
    if (state & MF_SEPARATOR) return std::string();

    const UINT id = GetMenuItemID(menu, i);
    const bool grayed = (state & (MF_GRAYED | MF_DISABLED)) != 0;
    const std::string text = ItemTextJson(menu, i);

    if (id == (UINT)-1 || id == 0) {
        // Popup submenu.
        HMENU sub = GetSubMenu(menu, i);
        return "{\"kind\":\"submenu\",\"depth\":" + std::to_string(depth) +
               ",\"text\":\"" + text + "\",\"items\":[" +
               (sub ? ItemsOf(sub, depth + 1) : std::string()) + "]}";
    }
    return "{\"kind\":\"cmd\",\"depth\":" + std::to_string(depth) + ",\"id\":" +
           std::to_string(id) + ",\"text\":\"" + text + "\",\"enabled\":" +
           (grayed ? "false" : "true") + "}";
}

std::string ItemsOf(HMENU menu, int depth) {
    std::string out;
    const int n = GetMenuItemCount(menu);
    for (int i = 0; i < n; ++i) {
        const std::string one = ItemJson(menu, i, depth);
        if (one.empty()) continue;
        if (!out.empty()) out += ",";
        out += one;
    }
    return out;
}

// One window as a complete JSON value, or an empty string when the filter
// rejects it: the caller used to append the comma before the call, so a
// filtered-out window left the comma behind (A47).
std::string WindowJson(HWND hwnd, const std::string& filter) {
    wchar_t title[256] = {};
    GetWindowTextW(hwnd, title, 256);
    wchar_t cls[128] = {};
    GetClassNameW(hwnd, cls, 128);

    const std::string t = WideToUtf8(title);
    const std::string c = WideToUtf8(cls);
    if (!filter.empty() && t.find(filter) == std::string::npos &&
        c.find(filter) == std::string::npos) {
        return std::string();
    }

    char num[48];
    _snprintf_s(num, sizeof(num), _TRUNCATE, "\"hwnd\":\"0x%llX\",",
                (unsigned long long)(uintptr_t)hwnd);
    std::string j = "{" + std::string(num) + "\"class\":\"" + JsonEscape(c) + "\",\"title\":\"" +
                    JsonEscape(t) + "\",\"menu\":";

    HMENU menu = GetMenu(hwnd);
    if (!menu) return j + "null}";
    return j + "[" + ItemsOf(menu, 0) + "]}";
}

}  // namespace

std::string MenuCommandToJson(const std::wstring& args) {
    // A47: the filter is UTF-8, not ASCII: a Cyrillic window title has to be
    // selectable by its own text.
    const std::string filter = WideToUtf8(args.c_str());

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
        const BOOL isChild = GetParent(w.h) == frame || w.h == frame;
        if (!isChild) continue;
        // A47: the comma belongs to a window that is really in the reply, not
        // to one the filter drops.
        std::string one = WindowJson(w.h, filter);
        if (one.empty()) continue;
        if (!first) j += ",";
        first = false;
        j += one;
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

    // A93: the payload acts on ITS process. Posting WM_COMMAND into a window of
    // another process would run a window procedure this payload knows nothing
    // about, and a handle of a dead window can be reused.
    DWORD owner = 0;
    GetWindowThreadProcessId((HWND)hwnd, &owner);
    if (!owner || !IsWindow((HWND)hwnd)) {
        return "{\"status\":\"error\",\"message\":\"no window with that handle\"}";
    }
    if (owner != GetCurrentProcessId()) {
        return "{\"status\":\"error\",\"message\":\"the window belongs to another process\"}";
    }

    BOOL ok = PostMessageW((HWND)hwnd, WM_COMMAND, (WPARAM)id, 0);
    char buf[128];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"ok\",\"posted\":%s,\"hwnd\":\"0x%llX\",\"id\":%u}",
                ok ? "true" : "false", (unsigned long long)hwnd, id);
    return buf;
}

}  // namespace v8i