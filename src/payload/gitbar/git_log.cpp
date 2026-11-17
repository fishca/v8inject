#include "git_log.h"

#include "git_service.h"
#include "git_ui.h"

#include <windows.h>
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace v8i {
namespace gitbar {

// ---------------------------------------------------------------------------
// Git history viewer in the configurator: the lane graph, ref badges and diff
// pane borrowed from v8GitView, dressed in the classic 1C skin — cream chrome,
// white rows, rust captions, light-blue selection and a light diff pane.
// ---------------------------------------------------------------------------

namespace {

struct GraphEdge { int fromLane; int toLane; int color; };
struct RefBadge { std::wstring label; COLORREF color; };

struct LogRow {
    std::wstring oid;
    std::wstring hash;
    std::wstring author;
    std::wstring date;
    std::wstring subject;
    std::vector<RefBadge> badges;
    int lane = 0;
    int color = 0;
    bool incoming = false;
    std::vector<GraphEdge> edges;
};

// One line of "git show": file headers, hunks and changed lines are kept apart
// so the pane can draw gutters, colours and the sign column without re-parsing
// the patch on every paint.
struct DiffLine {
    enum Kind { Context, Add, Del, Hunk, FileHead, Meta, Stat, Note };
    Kind kind = Context;
    int oldNo = 0;
    int newNo = 0;
    std::wstring text;     // prefix character already stripped for +, -, ' '
    // Changed word ranges: paired -/+ lines emphasise only the fragments that
    // differ, the way GitExtensions colours the edited words.
    std::vector<std::pair<int, int>> hl;
};

struct LogCtx {
    HWND hwnd = nullptr;
    std::vector<LogRow> rows;
    int maxLanes = 1;
    int top = 0;           // first visible row index
    int sel = -1;          // selected row
    int visible = 1;
    std::wstring dir;
    std::vector<DiffLine> diff;
    int diffTop = 0;       // first visible diff line
    int diffLines = 0;     // total diff lines (for the scroll hint)
    HFONT mono = nullptr;
    HFONT ui = nullptr;
    HFONT uiSemi = nullptr;    // bold for subjects / file headers
    HFONT title = nullptr;
    HFONT badge = nullptr;
    RECT rcClose{};
    bool hoverClose = false;
    int hover = -1;            // row under the cursor
    int drag = 0;              // 0 none, 1 list scrollbar, 2 patch scrollbar
    int dragY = 0;
    int dragTop = 0;
    RECT rcListSb{};
    RECT rcPatchSb{};
};

const int kLogRowH = 28;      // commit row height
const int kDiffRowH = 16;     // patch rows stay compact
const int kLogListTop = 42;   // first commit row, below title + column headers
const int kLaneStep = 16;
const int kGraphPadL = 10;
const int kGraphPadR = 8;
const int kSbW = 10;          // thin overlay scrollbar width
// Light palette in the shared 1C skin (kDlg* above): cream chrome, white rows,
// rust column captions, light-blue selection and a white diff field.
const COLORREF kLogBg = kDlgBg;                     // FCFAEB window chrome
const COLORREF kLogPanel = RGB(245, 243, 229);      // F5F3E5 header band
const COLORREF kLogBase = kDlgFieldBg;              // white list rows
const COLORREF kLogAlt = RGB(248, 246, 236);        // subtle cream alternation
const COLORREF kLogSel = kDlgSel;                   // 9ED8EB light-blue selection
const COLORREF kLogBorder = kDlgBorder;             // B3AC86 frames
const COLORREF kLogText = kDlgText;                 // 333333
const COLORREF kLogGray = RGB(128, 121, 98);        // warm dim text
const COLORREF kLogAddBg = RGB(232, 244, 232);
const COLORREF kLogAddTx = RGB(45, 110, 58);
const COLORREF kLogAddHl = RGB(172, 222, 180);
const COLORREF kLogDelBg = RGB(250, 235, 236);
const COLORREF kLogDelTx = RGB(155, 48, 56);
const COLORREF kLogDelHl = RGB(238, 180, 184);
const COLORREF kLogHunkBg = RGB(240, 238, 226);
const COLORREF kLogHunkTx = kLogGray;
const COLORREF kLogHeadBg = kDlgBtnFace;            // D7D3BD "diff --git" band
const COLORREF kLogPatchBg = kDlgFieldBg;           // white code pane
const COLORREF kLogLineNo = RGB(158, 152, 126);
const COLORREF kLogGutter = RGB(244, 242, 230);

// Scale the HSV value down, keep the hue: badge labels and other accents that
// would glow on a dark face become darker inks on cream / white rows.
COLORREF Darker(COLORREF c, int pct) {
    int r = GetRValue(c) * pct / 100, g = GetGValue(c) * pct / 100,
        b = GetBValue(c) * pct / 100;
    return RGB(r, g, b);
}

// Lane palette tuned for the light face: saturated mid-tones stay readable on
// white rows, the cream chrome and the light-blue selection.
const COLORREF kLaneColors[] = {
    RGB(0x2E, 0x6F, 0xD2), RGB(0xD3, 0x74, 0x0F), RGB(0x39, 0x8B, 0x3B), RGB(0xC6, 0x39, 0x40),
    RGB(0x92, 0x4F, 0x8C), RGB(0x1F, 0x84, 0x8C), RGB(0xB0, 0x7D, 0x0B), RGB(0xC2, 0x53, 0x6F),
    RGB(0x7D, 0x54, 0x33), RGB(0x60, 0x60, 0x60), RGB(0x2B, 0x5F, 0x9E), RGB(0x1F, 0x87, 0x55),
    RGB(0x4E, 0x5A, 0x72), RGB(0x9C, 0x78, 0x00), RGB(0x59, 0x3E, 0x9B), RGB(0x0F, 0x7E, 0xA5),
};
const int kLaneCount = (int)(sizeof(kLaneColors) / sizeof(kLaneColors[0]));
COLORREF LaneColor(int lane) { return kLaneColors[((lane % kLaneCount) + kLaneCount) % kLaneCount]; }

COLORREF RefColor(const std::wstring& ref) {
    if (ref.rfind(L"refs/remotes/", 0) == 0) return RGB(0xCC, 0x78, 0x32);
    if (ref.rfind(L"refs/tags/", 0) == 0) return RGB(0x98, 0x76, 0xAA);
    if (ref.rfind(L"refs/heads/", 0) == 0) return RGB(0x3D, 0x7F, 0x3D);
    return RGB(0x4B, 0x6E, 0xAF);
}

// " (HEAD -> refs/heads/main, refs/tags/v1)" -> badges. HEAD symrefs only
// duplicate the real branch badge, so they are skipped (as in v8GitView).
void ParseBadges(const std::wstring& refs, std::vector<RefBadge>& out) {
    std::wstring s = TrimWs(refs);
    if (s.size() >= 2 && s.front() == L'(' && s.back() == L')')
        s = s.substr(1, s.size() - 2);
    size_t p = 0;
    while (p < s.size()) {
        size_t e = s.find(L", ", p);
        if (e == std::wstring::npos) e = s.size();
        std::wstring ref = TrimWs(s.substr(p, e - p));
        p = e + 2;
        if (ref.empty() || ref == L"HEAD") continue;
        // git prints the checked-out branch once, as "HEAD -> refs/heads/x",
        // and tags with a "tag: " prefix in full decorate mode.
        if (ref.rfind(L"HEAD -> ", 0) == 0) ref = ref.substr(8);
        if (ref.rfind(L"tag: ", 0) == 0) ref = ref.substr(5);
        if (ref.rfind(L"refs/remotes/", 0) == 0 && ref.size() >= 5 &&
            ref.compare(ref.size() - 5, 5, L"/HEAD") == 0) continue;
        std::wstring label = ref;
        if (ref.rfind(L"refs/heads/", 0) == 0) label = ref.substr(11);
        else if (ref.rfind(L"refs/remotes/", 0) == 0) label = ref.substr(13);
        else if (ref.rfind(L"refs/tags/", 0) == 0) label = ref.substr(10);
        out.push_back({ label, RefColor(ref) });
    }
}

// Lane layout over the parent list, ported from v8GitView GraphLayout: each
// lane waits for one commit; the first parent keeps the commit's column,
// extra parents open new lanes on the right.
struct GraphLayout {
    struct Wait { std::wstring oid; int color; };
    std::vector<Wait> lanes;
    int nextColor = 0;

    int Find(const std::wstring& oid) const {
        for (size_t i = 0; i < lanes.size(); ++i)
            if (lanes[i].oid == oid) return (int)i;
        return -1;
    }

    void Next(LogRow& r, const std::vector<std::wstring>& parents) {
        int commitLane = Find(r.oid);
        r.incoming = commitLane >= 0;
        if (commitLane < 0) {
            lanes.push_back({ r.oid, nextColor++ % kLaneCount });
            commitLane = (int)lanes.size() - 1;
        }
        std::vector<Wait> top = lanes;
        int commitColor = top[commitLane].color;
        r.lane = commitLane;
        r.color = commitColor;
        lanes.erase(lanes.begin() + commitLane);
        for (size_t i = 0; i < parents.size(); ++i) {
            int target = Find(parents[i]);
            if (target >= 0) {
                r.edges.push_back({ commitLane, target, lanes[target].color });
                continue;
            }
            int insertAt, color;
            if (i == 0) {
                insertAt = commitLane < (int)lanes.size() ? commitLane : (int)lanes.size();
                color = commitColor;
            } else {
                insertAt = (int)lanes.size();
                color = nextColor++ % kLaneCount;
            }
            lanes.insert(lanes.begin() + insertAt, { parents[i], color });
            r.edges.push_back({ commitLane, insertAt, color });
        }
        for (size_t k = 0; k < top.size(); ++k) {
            if ((int)k == commitLane) continue;
            int to = Find(top[k].oid);
            if (to >= 0) r.edges.push_back({ (int)k, to, top[k].color });
        }
    }
};

int LogListBottom(const RECT& rc) {
    int h = rc.bottom - kLogListTop;
    return kLogListTop + (h > 0 ? h * 48 / 100 : 0);
}

int LogDetailTop(const RECT& rc) { return LogListBottom(rc) + 24; }
int LogPatchTop(const RECT& rc) { return LogDetailTop(rc) + 52; }

bool LoadLog(const std::wstring& dir, std::vector<LogRow>& rows, int* maxLanes) {
    // 0x1F (unit separator) between fields: subjects may contain anything.
    // Full decorate gives refs/heads|remotes|tags prefixes for badge colours;
    // %H/%P feed the parent-based lane layout instead of git's ASCII graph.
    std::wstring out = RunGit({ L"-C", dir, L"log", L"--decorate=full",
                                L"-n", L"300", L"--date=short",
                                L"--pretty=format:%x1f%H%x1f%h%x1f%an <%ae>%x1f%ad%x1f%d%x1f%s%x1f%P" });
    if (out.empty()) return false;
    GraphLayout layout;
    *maxLanes = 1;
    size_t p = 0;
    while (p < out.size()) {
        size_t e = out.find_first_of(L"\r\n", p);
        if (e == std::wstring::npos) e = out.size();
        std::wstring line = out.substr(p, e - p);
        p = e;
        while (p < out.size() && (out[p] == L'\r' || out[p] == L'\n')) ++p;
        if (line.empty() || line[0] != L'\x1f') continue;
        std::vector<std::wstring> f;
        size_t q = 1;
        while (true) {
            size_t d = line.find(L'\x1f', q);
            if (d == std::wstring::npos) { f.push_back(line.substr(q)); break; }
            f.push_back(line.substr(q, d - q));
            q = d + 1;
        }
        if (f.size() < 7) continue;
        LogRow r;
        r.oid = TrimWs(f[0]);
        r.hash = TrimWs(f[1]);
        r.author = f[2];
        r.date = f[3];
        r.subject = f[5];
        ParseBadges(f[4], r.badges);
        std::vector<std::wstring> parents;
        size_t a = 0;
        while (a < f[6].size()) {
            size_t b = f[6].find(L' ', a);
            if (b == std::wstring::npos) b = f[6].size();
            if (b > a) parents.push_back(f[6].substr(a, b - a));
            a = b + 1;
        }
        layout.Next(r, parents);
        *maxLanes = std::max(*maxLanes, r.lane + 1);
        for (const GraphEdge& ed : r.edges)
            *maxLanes = std::max(*maxLanes, std::max(ed.fromLane, ed.toLane) + 1);
        rows.push_back(std::move(r));
    }
    return !rows.empty();
}

HFONT LogFont(int points, const wchar_t* face, int weight, DWORD pitch) {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(points, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    // Tahoma 8 pt matches the platform dialog font; Consolas 9 pt keeps
    // hashes and code readable.
    return CreateFontW(h, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       pitch, face);
}

// "@@ -a,b +c,d @@" -- the counts are optional, so four format variants cover
// every hunk git prints.
void ParseHunkHeader(const std::wstring& line, int* oldNo, int* newNo) {
    int a = 0, b = 0, c = 0, d = 0;
    *oldNo = 0;
    *newNo = 0;
    if (swscanf_s(line.c_str(), L"@@ -%d,%d +%d,%d @@", &a, &b, &c, &d) == 4 ||
        swscanf_s(line.c_str(), L"@@ -%d,%d +%d @@", &a, &b, &c) == 3 ||
        swscanf_s(line.c_str(), L"@@ -%d +%d,%d @@", &a, &c, &d) == 3 ||
        swscanf_s(line.c_str(), L"@@ -%d +%d @@", &a, &c) == 2) {
        *oldNo = a - 1;   // the first line of the hunk increments these
        *newNo = c - 1;
    }
}

// Word-level diff of one deleted/added line pair. Tokens are runs of letters,
// digits and non-ASCII (Cyrillic paths and messages stay whole), single other
// characters and whitespace runs. The LCS keeps identical fragments plain and
// marks the rest, so a one-character edit lights up one character and not the
// whole line.
struct WordTok {
    int start;
    int end;
};

bool IsWordChar(wchar_t c) {
    return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') ||
           (c >= L'a' && c <= L'z') || c == L'_' || c >= 0x80;
}

void TokenizeWords(const std::wstring& s, std::vector<WordTok>& t) {
    t.clear();
    for (size_t i = 0; i < s.size();) {
        size_t j = i;
        if (IsWordChar(s[i])) {
            while (j < s.size() && IsWordChar(s[j])) ++j;
        } else if (s[i] == L' ' || s[i] == L'\t') {
            while (j < s.size() && (s[j] == L' ' || s[j] == L'\t')) ++j;
        } else {
            ++j;
        }
        t.push_back({ (int)i, (int)j });
        i = j;
    }
}

bool SameTok(const std::wstring& a, const WordTok& x, const std::wstring& b, const WordTok& y) {
    int la = x.end - x.start, lb = y.end - y.start;
    return la == lb && a.compare((size_t)x.start, (size_t)la, b, (size_t)y.start,
                                 (size_t)lb) == 0;
}

void MarkUnmatched(const std::vector<WordTok>& t, const std::vector<char>& matched,
                   std::vector<std::pair<int, int>>& out) {
    int start = -1;
    for (size_t i = 0; i < t.size(); ++i) {
        if (!matched[i]) {
            if (start < 0) start = t[i].start;
        } else if (start >= 0) {
            out.push_back({ start, t[i - 1].end });
            start = -1;
        }
    }
    if (start >= 0) out.push_back({ start, t.back().end });
}

void PairHighlight(DiffLine& del, DiffLine& add) {
    std::vector<WordTok> a, b;
    TokenizeWords(del.text, a);
    TokenizeWords(add.text, b);
    if (a.empty() || b.empty()) return;
    size_t n = a.size(), m = b.size();
    if (n * m > 400000) return;   // pathological line: keep the plain line tint
    std::vector<int> dp((n + 1) * (m + 1), 0);
    for (size_t i = 1; i <= n; ++i)
        for (size_t j = 1; j <= m; ++j)
            dp[i * (m + 1) + j] = SameTok(del.text, a[i - 1], add.text, b[j - 1])
                ? dp[(i - 1) * (m + 1) + (j - 1)] + 1
                : std::max(dp[(i - 1) * (m + 1) + j], dp[i * (m + 1) + (j - 1)]);
    std::vector<char> ma(n, 0), mb(m, 0);
    size_t i = n, j = m;
    while (i > 0 && j > 0) {
        if (SameTok(del.text, a[i - 1], add.text, b[j - 1]) &&
            dp[i * (m + 1) + j] == dp[(i - 1) * (m + 1) + (j - 1)] + 1) {
            ma[i - 1] = mb[j - 1] = 1;
            --i;
            --j;
        } else if (dp[(i - 1) * (m + 1) + j] >= dp[i * (m + 1) + (j - 1)]) {
            --i;
        } else {
            --j;
        }
    }
    MarkUnmatched(a, ma, del.hl);
    MarkUnmatched(b, mb, add.hl);
}

void ParseDiff(const std::wstring& patch, std::vector<DiffLine>& out) {
    int oldNo = 0, newNo = 0;
    bool inHunk = false;
    size_t pos = 0;
    while (pos < patch.size()) {
        size_t e = patch.find_first_of(L"\r\n", pos);
        if (e == std::wstring::npos) e = patch.size();
        std::wstring line = patch.substr(pos, e - pos);
        pos = e;
        while (pos < patch.size() && (patch[pos] == L'\r' || patch[pos] == L'\n')) ++pos;

        DiffLine dl;
        if (line.rfind(L"diff --git ", 0) == 0) {
            inHunk = false;
            std::wstring path = line.substr(11);
            size_t b = path.rfind(L" b/");
            if (b != std::wstring::npos) path = path.substr(b + 3);
            dl.kind = DiffLine::FileHead;
            dl.text = path;
            out.push_back(dl);
            continue;
        }
        if (line.rfind(L"@@", 0) == 0) {
            inHunk = true;
            ParseHunkHeader(line, &oldNo, &newNo);
            dl.kind = DiffLine::Hunk;
            dl.text = line;
            out.push_back(dl);
            continue;
        }
        if (inHunk) {
            if (line.empty()) { inHunk = false; continue; }
            wchar_t ch = line[0];
            if (ch == L'+') {
                dl.kind = DiffLine::Add;
                dl.newNo = ++newNo;
                dl.text = line.substr(1);
            } else if (ch == L'-') {
                dl.kind = DiffLine::Del;
                dl.oldNo = ++oldNo;
                dl.text = line.substr(1);
            } else if (ch == L' ') {
                dl.kind = DiffLine::Context;
                dl.oldNo = ++oldNo;
                dl.newNo = ++newNo;
                dl.text = line.substr(1);
            } else if (ch == L'\\') {
                dl.kind = DiffLine::Note;
                dl.text = line;
            } else {
                dl.kind = DiffLine::Context;
                dl.text = line;
            }
            out.push_back(dl);
            continue;
        }

        // Outside a hunk: index/---/+++/mode lines belong to the file header,
        // the --stat block and its "N files changed" summary are stat lines.
        if (line.empty()) continue;
        if (line.rfind(L"index ", 0) == 0 || line.rfind(L"--- ", 0) == 0 ||
            line.rfind(L"+++ ", 0) == 0 || line.rfind(L"new file mode", 0) == 0 ||
            line.rfind(L"deleted file mode", 0) == 0 ||
            line.rfind(L"old mode", 0) == 0 || line.rfind(L"new mode", 0) == 0 ||
            line.rfind(L"similarity index", 0) == 0 ||
            line.rfind(L"rename from", 0) == 0 || line.rfind(L"rename to", 0) == 0 ||
            line.rfind(L"Binary files", 0) == 0) {
            dl.kind = DiffLine::Meta;
        } else {
            dl.kind = DiffLine::Stat;
        }
        dl.text = line;
        out.push_back(dl);
    }

    // git prints each hunk's removals before its additions; pair them line by
    // line so PairHighlight can mark the changed words.
    for (size_t i = 0; i < out.size();) {
        if (out[i].kind != DiffLine::Del) { ++i; continue; }
        size_t d0 = i;
        while (i < out.size() && out[i].kind == DiffLine::Del) ++i;
        size_t a0 = i;
        while (i < out.size() && out[i].kind == DiffLine::Add) ++i;
        size_t pairs = std::min(i - a0, a0 - d0);
        for (size_t k = 0; k < pairs; ++k) PairHighlight(out[d0 + k], out[a0 + k]);
    }
}

// Commit node: a filled dot with a soft halo on the row face.
static void DrawNode(HDC dc, int cx, int cy, COLORREF color, COLORREF bg) {
    HPEN np = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
    HBRUSH hb = CreateSolidBrush(Blend(color, bg, 70));
    HBRUSH ob = (HBRUSH)SelectObject(dc, hb);
    Ellipse(dc, cx - 7, cy - 7, cx + 8, cy + 8);
    SelectObject(dc, ob);
    DeleteObject(hb);
    HBRUSH db = CreateSolidBrush(color);
    ob = (HBRUSH)SelectObject(dc, db);
    Ellipse(dc, cx - 4, cy - 4, cx + 5, cy + 5);
    SelectObject(dc, ob);
    SelectObject(dc, np);
    DeleteObject(db);
}

// Rounded branch/tag pills: tinted fill, stronger border, darker bold label.
// Advances x past the drawn badges; overflow collapses into a "+N" pill.
static void DrawBadges(HDC dc, HFONT font, const std::vector<RefBadge>& badges,
                       int& x, int y, int rowH, int rightLimit, COLORREF bg) {
    if (badges.empty() || x >= rightLimit) return;
    HFONT of = (HFONT)SelectObject(dc, font);
    int top = y + (rowH - 18) / 2;
    size_t drawn = 0;
    for (size_t i = 0; i < badges.size(); ++i) {
        const RefBadge& b = badges[i];
        SIZE sz{};
        GetTextExtentPoint32W(dc, b.label.c_str(), (int)b.label.size(), &sz);
        int w = sz.cx + 12;
        int reserve = (i + 1 == badges.size()) ? 0 : 34;
        if (x + w + reserve > rightLimit) break;
        HBRUSH fb = CreateSolidBrush(Blend(b.color, bg, 45));
        HPEN bp = CreatePen(PS_SOLID, 1, Blend(b.color, bg, 150));
        HBRUSH ob = (HBRUSH)SelectObject(dc, fb);
        HPEN op = (HPEN)SelectObject(dc, bp);
        RoundRect(dc, x, top, x + w + 1, top + 19, 8, 8);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        DeleteObject(fb);
        DeleteObject(bp);
        SetTextColor(dc, Darker(b.color, 76));
        RECT br{ x, top, x + w, top + 18 };
        DrawTextW(dc, b.label.c_str(), (int)b.label.size(), &br,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        x += w + 4;
        ++drawn;
    }
    if (drawn < badges.size()) {
        wchar_t lab[16] = {};
        _snwprintf_s(lab, _TRUNCATE, L"+%d", (int)(badges.size() - drawn));
        SIZE sz{};
        GetTextExtentPoint32W(dc, lab, (int)wcslen(lab), &sz);
        int w = sz.cx + 12;
        if (x + w <= rightLimit) {
            HBRUSH fb = CreateSolidBrush(kDlgBtnFace);
            HPEN bp = CreatePen(PS_SOLID, 1, kLogBorder);
            HBRUSH ob = (HBRUSH)SelectObject(dc, fb);
            HPEN op = (HPEN)SelectObject(dc, bp);
            RoundRect(dc, x, top, x + w + 1, top + 19, 8, 8);
            SelectObject(dc, ob);
            SelectObject(dc, op);
            DeleteObject(fb);
            DeleteObject(bp);
            SetTextColor(dc, kLogGray);
            RECT br{ x, top, x + w, top + 18 };
            DrawTextW(dc, lab, -1, &br,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            x += w + 4;
        }
    }
    SelectObject(dc, of);
}

static int PatchRowsFit(const RECT& rc) {
    int r = (rc.bottom - 6 - LogPatchTop(rc)) / kDiffRowH;
    return r < 1 ? 1 : r;
}

// Thin overlay scrollbar: track height, thumb height (0 = everything fits) and
// thumb top. Shared by paint and the drag / click handlers so they agree.
static void SbGeom(int trackTop, int trackBottom, int total, int fit, int top,
                   int* thumbH, int* thumbY) {
    int trackH = trackBottom - trackTop;
    *thumbH = 0;
    *thumbY = trackTop;
    if (total <= fit || trackH <= 0) return;
    int th = trackH * fit / total;
    if (th < 24) th = 24;
    if (th > trackH) th = trackH;
    int maxTop = total - fit;
    int range = trackH - th;
    *thumbH = th;
    *thumbY = trackTop + (maxTop > 0 && range > 0 ? range * top / maxTop : 0);
}

static void DrawScrollbar(HDC dc, const RECT& track, int thumbH, int thumbY, bool active) {
    if (thumbH <= 0) return;
    HBRUSH tb = CreateSolidBrush(kLogBg);
    FillRect(dc, &track, tb);
    DeleteObject(tb);
    RECT th{ track.left + 1, thumbY, track.right - 1, thumbY + thumbH };
    HBRUSH hb = CreateSolidBrush(active ? kDlgFieldBorder : kLogBorder);
    FillRect(dc, &th, hb);
    DeleteObject(hb);
}

void LogPaint(LogCtx* c) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(c->hwnd, &ps);
    RECT rc{};
    GetClientRect(c->hwnd, &rc);
    HBRUSH bg = CreateSolidBrush(kLogBg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    DrawCaption(dc, c->hwnd, c->title, c->hoverClose);
    // The body keeps its own coordinate space below the painted caption.
    SetWindowOrgEx(dc, 0, -kCapH, nullptr);
    rc.bottom -= kCapH;
    SetBkMode(dc, TRANSPARENT);

    const int contentRight = rc.right - kSbW - 4;
    const int kDateW = 110;
    const int kAuthorW = 176;
    int graphW = kGraphPadL + c->maxLanes * kLaneStep + kGraphPadR;
    if (graphW > 240) graphW = 240;
    const int listLeft = 4;
    const int subjLeft = listLeft + graphW;
    const int dateLeft = contentRight - kDateW;
    const int authorLeft = dateLeft - kAuthorW;
    const int subjRight = authorLeft;
    auto LaneX = [&](int lane) { return listLeft + kGraphPadL + lane * kLaneStep; };
    auto RowBg = [&](int idx) -> COLORREF {
        if (idx == c->sel) return kLogSel;
        COLORREF base = (idx & 1) ? kLogAlt : kLogBase;
        return idx == c->hover ? Blend(kDlgHover, base, 140) : base;
    };

    // Header band: repo path on the cream face under the caption.
    RECT hdr{ 0, 0, rc.right, 24 };
    HBRUSH hbr = CreateSolidBrush(kLogPanel);
    FillRect(dc, &hdr, hbr);
    DeleteObject(hbr);
    SelectObject(dc, c->title);
    SetTextColor(dc, kLogText);
    RECT dr{ 12, 0, rc.right - 12, 24 };
    DrawTextW(dc, c->dir.c_str(), -1, &dr,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

    HPEN border = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN obp = (HPEN)SelectObject(dc, border);
    MoveToEx(dc, 0, 24, nullptr);
    LineTo(dc, rc.right, 24);
    MoveToEx(dc, 0, kLogListTop - 1, nullptr);
    LineTo(dc, rc.right, kLogListTop - 1);
    SelectObject(dc, obp);
    DeleteObject(border);

    // Column headers: commit | author | date, rust labels like the field
    // captions on a live platform dialog.
    RECT hband{ 0, 24, rc.right, kLogListTop - 1 };
    HBRUSH hbb = CreateSolidBrush(kLogPanel);
    FillRect(dc, &hband, hbb);
    DeleteObject(hbb);
    SelectObject(dc, c->ui);
    SetTextColor(dc, kDlgLabel);
    RECT hG{ 8, 24, subjLeft, kLogListTop - 1 };
    DrawTextW(dc, L"Коммит", -1, &hG, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT hA{ authorLeft + 4, 24, dateLeft, kLogListTop - 1 };
    DrawTextW(dc, L"Автор", -1, &hA, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT hD{ dateLeft, 24, contentRight, kLogListTop - 1 };
    DrawTextW(dc, L"Дата", -1, &hD, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    int listTop = kLogListTop;
    int listBottom = LogListBottom(rc);
    c->visible = (listBottom - listTop) / kLogRowH;
    if (c->visible < 1) c->visible = 1;

    // The commit list: white rows with a subtle cream alternation, light-blue
    // selection, pale-yellow hover.
    RECT listArea{ listLeft, listTop, contentRight, listBottom };
    HBRUSH lbr = CreateSolidBrush(kLogBase);
    FillRect(dc, &listArea, lbr);
    DeleteObject(lbr);

    // One round-cap pen per lane colour; lane changes are cubic elbows.
    HPEN lanePens[kLaneCount];
    for (int k = 0; k < kLaneCount; ++k) {
        LOGBRUSH lb{ BS_SOLID, kLaneColors[k], 0 };
        lanePens[k] = ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_ROUND | PS_JOIN_ROUND,
                                   2, &lb, 0, nullptr);
    }

    // Pass 1: row backgrounds so graph and text sit on top.
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        int yTop = listTop + i * kLogRowH;
        RECT row{ listLeft, yTop, contentRight, yTop + kLogRowH };
        HBRUSH rb = CreateSolidBrush(RowBg(idx));
        FillRect(dc, &row, rb);
        DeleteObject(rb);
    }

    // Pass 2: the graph. Incoming lane from the row above, passing lanes as
    // cubic curves across the row, own edges leaving the dot downwards.
    IntersectClipRect(dc, listLeft, listTop, subjLeft - 2, listBottom);
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        int yTop = listTop + i * kLogRowH;
        int yBot = yTop + kLogRowH;
        int mid = (yTop + yBot) / 2;
        const LogRow& r = c->rows[idx];
        if (r.incoming) {
            HPEN op = (HPEN)SelectObject(dc, lanePens[r.color % kLaneCount]);
            MoveToEx(dc, LaneX(r.lane), yTop, nullptr);
            LineTo(dc, LaneX(r.lane), mid);
            SelectObject(dc, op);
        }
        for (const GraphEdge& e : r.edges) {
            if (e.fromLane == r.lane) continue;
            int x0 = LaneX(e.fromLane), x1 = LaneX(e.toLane);
            HPEN op = (HPEN)SelectObject(dc, lanePens[e.color % kLaneCount]);
            POINT pts[4] = { { x0, yTop }, { x0, mid }, { x1, mid }, { x1, yBot } };
            PolyBezier(dc, pts, 4);
            SelectObject(dc, op);
        }
        for (const GraphEdge& e : r.edges) {
            if (e.fromLane != r.lane) continue;
            int x0 = LaneX(r.lane), x1 = LaneX(e.toLane);
            int ym = (mid + yBot) / 2;
            HPEN op = (HPEN)SelectObject(dc, lanePens[e.color % kLaneCount]);
            POINT pts[4] = { { x0, mid }, { x0, ym }, { x1, ym }, { x1, yBot } };
            PolyBezier(dc, pts, 4);
            SelectObject(dc, op);
        }
        DrawNode(dc, LaneX(r.lane), mid, LaneColor(r.color), RowBg(idx));
    }
    SelectClipRgn(dc, nullptr);

    // Pass 3: dim mono hash, badges, subject, author and date.
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        int yTop = listTop + i * kLogRowH;
        int yBot = yTop + kLogRowH;
        const LogRow& r = c->rows[idx];
        COLORREF rbg = RowBg(idx);
        bool sel = idx == c->sel;
        int x = subjLeft;

        SelectObject(dc, c->mono);
        SetTextColor(dc, Blend(kLogText, rbg, sel ? 190 : 135));
        SIZE hs{};
        GetTextExtentPoint32W(dc, r.hash.c_str(), (int)r.hash.size(), &hs);
        int hashW = hs.cx + 12;
        RECT hr{ x, yTop, x + hashW, yBot };
        DrawTextW(dc, r.hash.c_str(), (int)r.hash.size(), &hr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        x += hashW;

        int subjMin = subjRight - x;
        if (subjMin > 180) subjMin = 180;
        if (subjMin < 60) subjMin = 60;
        DrawBadges(dc, c->badge, r.badges, x, yTop, kLogRowH, subjRight - subjMin, rbg);

        SelectObject(dc, c->ui);
        SetTextColor(dc, kDlgText);
        RECT sr{ x, yTop, subjRight, yBot };
        DrawTextW(dc, r.subject.c_str(), (int)r.subject.size(), &sr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

        std::wstring aname = r.author;
        size_t lt = aname.find(L" <");
        if (lt != std::wstring::npos) aname = aname.substr(0, lt);
        RECT ar{ authorLeft + 4, yTop, dateLeft - 4, yBot };
        DrawTextW(dc, aname.c_str(), (int)aname.size(), &ar,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        RECT dtr{ dateLeft, yTop, contentRight, yBot };
        DrawTextW(dc, r.date.c_str(), (int)r.date.size(), &dtr,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }
    for (int k = 0; k < kLaneCount; ++k)
        if (lanePens[k]) DeleteObject(lanePens[k]);

    // Separator + status line between the list and the details card.
    SelectObject(dc, c->ui);
    HPEN sep = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN osep = (HPEN)SelectObject(dc, sep);
    MoveToEx(dc, 4, listBottom + 1, nullptr);
    LineTo(dc, rc.right - 4, listBottom + 1);
    SelectObject(dc, osep);
    DeleteObject(sep);

    SetTextColor(dc, kLogGray);
    wchar_t st[160] = {};
    int shown = c->visible;
    if (shown > (int)c->rows.size() - c->top) shown = (int)c->rows.size() - c->top;
    _snwprintf_s(st, _TRUNCATE, L"%d коммитов · %d линий · %d–%d",
                 (int)c->rows.size(), c->maxLanes, c->top + 1, c->top + shown);
    RECT sr{ 8, listBottom + 3, rc.right - 360, listBottom + 22 };
    DrawTextW(dc, st, -1, &sr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    {
        wchar_t hint[128] = {};
        if (c->diffLines > 0)
            _snwprintf_s(hint, _TRUNCATE, L"изменений: %d  ·  ↑↓ / колесо · Enter — закрыть",
                         c->diffLines);
        else
            _snwprintf_s(hint, _TRUNCATE, L"↑↓ / колесо — прокрутка · Enter — закрыть");
        RECT hr{ rc.right - 350, listBottom + 3, rc.right - 8, listBottom + 22 };
        DrawTextW(dc, hint, -1, &hr, DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    }

    // Details panel: white field card with subject, badges, author, date, hash.
    int detTop = LogDetailTop(rc);
    {
        RECT card{ 8, detTop, rc.right - 8, detTop + 44 };
        HBRUSH cb = CreateSolidBrush(kLogBase);
        FillRect(dc, &card, cb);
        DeleteObject(cb);
        HPEN cp = CreatePen(PS_SOLID, 1, kDlgFieldBorder);
        HPEN ocp = (HPEN)SelectObject(dc, cp);
        HBRUSH ob2 = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, card.left, card.top, card.right, card.bottom);
        SelectObject(dc, ob2);
        SelectObject(dc, ocp);
        DeleteObject(cp);
        if (c->sel >= 0 && c->sel < (int)c->rows.size()) {
            const LogRow& r = c->rows[c->sel];
            SelectObject(dc, c->badge);
            int bw = 0;
            for (const RefBadge& b : r.badges) {
                SIZE sz{};
                GetTextExtentPoint32W(dc, b.label.c_str(), (int)b.label.size(), &sz);
                bw += sz.cx + 16;
            }
            int bx = card.right - 12 - bw;
            int subjAvail = bx - 10 - (card.left + 12);
            if (subjAvail < 40) subjAvail = 40;
            SelectObject(dc, c->uiSemi);
            SetTextColor(dc, kLogText);
            RECT sjr{ card.left + 12, card.top + 4, card.left + 12 + subjAvail, card.top + 20 };
            DrawTextW(dc, r.subject.c_str(), (int)r.subject.size(), &sjr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            DrawBadges(dc, c->badge, r.badges, bx, card.top + 4, 20, card.right - 12, kLogBase);
            std::wstring aname = r.author;
            size_t lt = aname.find(L" <");
            if (lt != std::wstring::npos) aname = aname.substr(0, lt);
            SelectObject(dc, c->ui);
            SetTextColor(dc, kLogText);
            RECT ar{ card.left + 12, card.top + 24, card.left + 232, card.top + 40 };
            DrawTextW(dc, aname.c_str(), (int)aname.size(), &ar,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            SIZE nw{};
            GetTextExtentPoint32W(dc, aname.c_str(), (int)aname.size(), &nw);
            int dx = card.left + 12 + (nw.cx < 220 ? nw.cx : 220) + 10;
            SetTextColor(dc, kLogGray);
            RECT dtr{ dx, card.top + 24, dx + 120, card.top + 40 };
            DrawTextW(dc, r.date.c_str(), (int)r.date.size(), &dtr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, c->mono);
            SetTextColor(dc, Blend(kLogText, kLogBase, 135));
            RECT hr{ card.right - 100, card.top + 24, card.right - 12, card.top + 40 };
            DrawTextW(dc, r.hash.c_str(), (int)r.hash.size(), &hr,
                      DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, c->ui);
        }
    }

    // Patch pane: white code field, light two-column gutter, coloured sign,
    // green/red row tints and word-level chips; hunk / file headers get bands.
    int patchTop = LogPatchTop(rc);
    int patchBottom = rc.bottom - 6;
    if (patchBottom > patchTop && !c->diff.empty()) {
        int rowsFit = PatchRowsFit(rc);
        int maxTop = c->diffLines - rowsFit;
        if (maxTop < 0) maxTop = 0;
        if (c->diffTop > maxTop) c->diffTop = maxTop;
        if (c->diffTop < 0) c->diffTop = 0;

        const int kNoW = 40;
        const int kSignW = 14;
        int paneLeft = 6;
        int paneRight = rc.right - kSbW - 4;
        int gutterRight = paneLeft + kNoW * 2;
        int codeLeft = gutterRight + kSignW + 6;

        RECT pane{ paneLeft, patchTop, paneRight, patchBottom };
        HBRUSH pb = CreateSolidBrush(kLogPatchBg);
        FillRect(dc, &pane, pb);
        DeleteObject(pb);
        RECT gut{ paneLeft, patchTop, gutterRight, patchBottom };
        HBRUSH gb = CreateSolidBrush(kLogGutter);
        FillRect(dc, &gut, gb);
        DeleteObject(gb);

        for (int i = c->diffTop; i < c->diffTop + rowsFit && i < (int)c->diff.size(); ++i) {
            const DiffLine& d = c->diff[i];
            int y = patchTop + (i - c->diffTop) * kDiffRowH;
            RECT lr{ paneLeft, y, paneRight, y + kDiffRowH };
            bool codeRow = (d.kind == DiffLine::Add || d.kind == DiffLine::Del ||
                            d.kind == DiffLine::Context);
            COLORREF fg = kLogText;
            COLORREF bgc = kLogPatchBg;
            COLORREF sign = kLogGray;
            switch (d.kind) {
            case DiffLine::Add:      bgc = kLogAddBg;  sign = kLogAddTx; break;
            case DiffLine::Del:      bgc = kLogDelBg;  sign = kLogDelTx; break;
            case DiffLine::Hunk:     bgc = kLogHunkBg; fg = kLogHunkTx;  break;
            case DiffLine::FileHead: bgc = kLogHeadBg; break;
            case DiffLine::Meta:
                fg = kLogGray;
                if (d.text.rfind(L"--- ", 0) == 0) fg = kLogDelTx;
                else if (d.text.rfind(L"+++ ", 0) == 0) fg = kLogAddTx;
                break;
            case DiffLine::Stat:
            case DiffLine::Note:     fg = kLogGray; break;
            default: break;
            }
            if (bgc != kLogPatchBg) {
                HBRUSH b = CreateSolidBrush(bgc);
                FillRect(dc, &lr, b);
                DeleteObject(b);
            }
            if (d.kind == DiffLine::FileHead) {
                HPEN fp = CreatePen(PS_SOLID, 1, kLogBorder);
                HPEN ofp = (HPEN)SelectObject(dc, fp);
                MoveToEx(dc, paneLeft, y, nullptr);
                LineTo(dc, paneRight, y);
                SelectObject(dc, ofp);
                DeleteObject(fp);
            }

            if (codeRow) {
                SelectObject(dc, c->mono);
                SetTextColor(dc, kLogLineNo);
                wchar_t nb[16] = {};
                if (d.oldNo) {
                    _snwprintf_s(nb, _TRUNCATE, L"%d", d.oldNo);
                    RECT nr{ paneLeft, y, paneLeft + kNoW - 6, y + kDiffRowH };
                    DrawTextW(dc, nb, -1, &nr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
                if (d.newNo) {
                    _snwprintf_s(nb, _TRUNCATE, L"%d", d.newNo);
                    RECT nr{ paneLeft + kNoW, y, gutterRight - 6, y + kDiffRowH };
                    DrawTextW(dc, nb, -1, &nr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
                if (d.kind == DiffLine::Add || d.kind == DiffLine::Del) {
                    SetTextColor(dc, sign);
                    RECT signr{ gutterRight, y, gutterRight + kSignW, y + kDiffRowH };
                    DrawTextW(dc, d.kind == DiffLine::Add ? L"+" : L"-", 1, &signr,
                              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
                if (!d.hl.empty() && (d.kind == DiffLine::Add || d.kind == DiffLine::Del)) {
                    HBRUSH hb = CreateSolidBrush(d.kind == DiffLine::Add ? kLogAddHl : kLogDelHl);
                    HPEN np = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
                    HBRUSH ob = (HBRUSH)SelectObject(dc, hb);
                    int limit = paneRight - 6;
                    for (const std::pair<int, int>& h : d.hl) {
                        SIZE sz{};
                        int x1 = codeLeft;
                        if (h.first > 0) {
                            GetTextExtentPoint32W(dc, d.text.c_str(), h.first, &sz);
                            x1 += sz.cx;
                        }
                        int x2 = codeLeft;
                        GetTextExtentPoint32W(dc, d.text.c_str(), h.second, &sz);
                        x2 += sz.cx;
                        if (x1 >= limit) break;
                        if (x2 > limit) x2 = limit;
                        Rectangle(dc, x1, y + 2, x2, y + kDiffRowH - 2);
                    }
                    SelectObject(dc, ob);
                    SelectObject(dc, np);
                    DeleteObject(hb);
                }
            }

            SetTextColor(dc, fg);
            if (d.kind == DiffLine::FileHead) SelectObject(dc, c->uiSemi);
            else SelectObject(dc, c->mono);
            int textLeft = codeRow ? codeLeft : paneLeft + 8;
            RECT tr{ textLeft, y, paneRight - 6, y + kDiffRowH };
            DrawTextW(dc, d.text.c_str(), (int)d.text.size(), &tr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
        }
        HPEN gp = CreatePen(PS_SOLID, 1, kLogBorder);
        HPEN ogp = (HPEN)SelectObject(dc, gp);
        MoveToEx(dc, gutterRight, patchTop, nullptr);
        LineTo(dc, gutterRight, patchBottom);
        MoveToEx(dc, paneLeft, patchTop - 1, nullptr);
        LineTo(dc, paneRight, patchTop - 1);
        SelectObject(dc, ogp);
        DeleteObject(gp);
    }

    // Thin overlay scrollbars for the list and the patch.
    {
        int sbL = rc.right - kSbW - 2;
        RECT ltrack{ sbL, listTop, rc.right - 2, listBottom };
        c->rcListSb = ltrack;
        int th = 0, ty = 0;
        SbGeom(listTop, listBottom, (int)c->rows.size(), c->visible, c->top, &th, &ty);
        DrawScrollbar(dc, ltrack, th, ty, c->drag == 1);
        if (!c->diff.empty()) {
            RECT ptrack{ sbL, patchTop, rc.right - 2, patchBottom };
            c->rcPatchSb = ptrack;
            int pth = 0, pty = 0;
            SbGeom(patchTop, patchBottom, c->diffLines, PatchRowsFit(rc), c->diffTop, &pth, &pty);
            DrawScrollbar(dc, ptrack, pth, pty, c->drag == 2);
        } else {
            SetRectEmpty(&c->rcPatchSb);
        }
    }

    SetWindowOrgEx(dc, 0, 0, nullptr);
    HPEN frame = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN ofr = (HPEN)SelectObject(dc, frame);
    HBRUSH obb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    RECT full{};
    GetClientRect(c->hwnd, &full);
    Rectangle(dc, 0, 0, full.right - 1, full.bottom - 1);
    SelectObject(dc, obb);
    SelectObject(dc, ofr);
    DeleteObject(frame);
    EndPaint(c->hwnd, &ps);
}

void LogScrollTo(LogCtx* c, int top) {
    int maxTop = (int)c->rows.size() - c->visible;
    if (maxTop < 0) maxTop = 0;
    if (top < 0) top = 0;
    if (top > maxTop) top = maxTop;
    if (top != c->top) { c->top = top; InvalidateRect(c->hwnd, nullptr, FALSE); }
}

void LogSelect(LogCtx* c, int idx) {
    if (idx < 0) idx = 0;
    if (idx > (int)c->rows.size() - 1) idx = (int)c->rows.size() - 1;
    c->sel = idx;
    if (c->sel < c->top) LogScrollTo(c, c->sel);
    if (c->sel >= c->top + c->visible) LogScrollTo(c, c->sel - c->visible + 1);
    const LogRow& r = c->rows[c->sel];
    c->diff.clear();
    c->diffTop = 0;
    c->diffLines = 0;
    if (!r.hash.empty()) {
        // Patch for the diff pane: stat first (one line per file), then the
        // unified diff itself. ParseDiff turns it into rows with line numbers.
        std::wstring patch = RunGit({ L"-c", L"core.quotepath=false",
                                      L"-C", c->dir, L"show", L"--format=",
                                      L"--stat", L"--patch", L"--no-color", r.hash });
        ParseDiff(patch, c->diff);
        c->diffLines = (int)c->diff.size();
    }
    InvalidateRect(c->hwnd, nullptr, FALSE);
}

LRESULT CALLBACK LogWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    LogCtx* c = (LogCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        if (mmi) {
            mmi->ptMinTrackSize.x = 640;
            mmi->ptMinTrackSize.y = 460 + kCapH;
        }
        return 0;
    }
    case WM_PAINT:
        if (c) LogPaint(c);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        if (c) {
            RECT rc{};
            GetClientRect(h, &rc);
            SetRect(&c->rcClose, rc.right - 26, 3, rc.right - 4, 21);
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_MOUSEWHEEL: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        ScreenToClient(h, &pt);
        pt.y -= kCapH;
        RECT rc{};
        GetClientRect(h, &rc);
        rc.bottom -= kCapH;
        int delta = GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA * 3;
        if (pt.y > LogPatchTop(rc)) {
            // cursor over the patch pane — scroll the diff
            int rowsFit = PatchRowsFit(rc);
            if (rowsFit < 1) rowsFit = 1;
            int maxTop = c->diffLines - rowsFit;
            if (maxTop < 0) maxTop = 0;
            c->diffTop -= delta;
            if (c->diffTop > maxTop) c->diffTop = maxTop;
            if (c->diffTop < 0) c->diffTop = 0;
            InvalidateRect(h, nullptr, FALSE);
        } else {
            LogScrollTo(c, c->top - delta);
        }
        return 0;
    }
    case WM_MOUSEMOVE: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        bool hv = PtInRect(&c->rcClose, pt) != 0;
        if (hv != c->hoverClose) { c->hoverClose = hv; InvalidateRect(h, nullptr, FALSE); }
        pt.y -= kCapH;
        RECT rc{};
        GetClientRect(h, &rc);
        rc.bottom -= kCapH;
        if (c->drag) {
            if (c->drag == 1) {
                int trackH = LogListBottom(rc) - kLogListTop;
                int total = (int)c->rows.size();
                int th = 0;
                if (total > c->visible) {
                    th = trackH * c->visible / total;
                    if (th < 24) th = 24;
                    if (th > trackH) th = trackH;
                }
                int maxTop = total - c->visible;
                if (maxTop < 0) maxTop = 0;
                int range = trackH - th;
                if (range < 1) range = 1;
                LogScrollTo(c, c->dragTop + (pt.y - c->dragY) * maxTop / range);
            } else {
                int patchTop = LogPatchTop(rc);
                int trackH = rc.bottom - 6 - patchTop;
                int fit = PatchRowsFit(rc);
                int th = 0;
                if (c->diffLines > fit) {
                    th = trackH * fit / c->diffLines;
                    if (th < 24) th = 24;
                    if (th > trackH) th = trackH;
                }
                int maxTop = c->diffLines - fit;
                if (maxTop < 0) maxTop = 0;
                int range = trackH - th;
                if (range < 1) range = 1;
                int nt = c->dragTop + (pt.y - c->dragY) * maxTop / range;
                if (nt < 0) nt = 0;
                if (nt > maxTop) nt = maxTop;
                if (nt != c->diffTop) { c->diffTop = nt; InvalidateRect(h, nullptr, FALSE); }
            }
            return 0;
        }
        int nh = -1;
        if (pt.y >= kLogListTop && pt.y < LogListBottom(rc) && pt.x < rc.right - kSbW - 2) {
            int idx = c->top + (pt.y - kLogListTop) / kLogRowH;
            if (idx >= 0 && idx < (int)c->rows.size()) nh = idx;
        }
        if (nh != c->hover) { c->hover = nh; InvalidateRect(h, nullptr, FALSE); }
        TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }
    case WM_MOUSELEAVE:
        if (c && (c->hover != -1 || c->hoverClose)) {
            c->hover = -1;
            c->hoverClose = false;
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        if (PtInRect(&c->rcClose, pt)) { DestroyWindow(h); return 0; }
        pt.y -= kCapH;
        RECT rc{};
        GetClientRect(h, &rc);
        rc.bottom -= kCapH;
        if (PtInRect(&c->rcListSb, pt)) {
            int th = 0, ty = 0;
            SbGeom(kLogListTop, LogListBottom(rc), (int)c->rows.size(), c->visible,
                   c->top, &th, &ty);
            if (th > 0 && pt.y >= ty && pt.y < ty + th) {
                c->drag = 1; c->dragY = pt.y; c->dragTop = c->top;
                SetCapture(h);
            } else {
                LogScrollTo(c, c->top + (pt.y < ty ? -c->visible : c->visible));
            }
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&c->rcPatchSb, pt)) {
            int patchTop = LogPatchTop(rc);
            int fit = PatchRowsFit(rc);
            int th = 0, ty = 0;
            SbGeom(patchTop, rc.bottom - 6, c->diffLines, fit, c->diffTop, &th, &ty);
            if (th > 0 && pt.y >= ty && pt.y < ty + th) {
                c->drag = 2; c->dragY = pt.y; c->dragTop = c->diffTop;
                SetCapture(h);
            } else {
                int nt = c->diffTop + (pt.y < ty ? -fit : fit);
                int maxTop = c->diffLines - fit;
                if (maxTop < 0) maxTop = 0;
                if (nt < 0) nt = 0;
                if (nt > maxTop) nt = maxTop;
                c->diffTop = nt;
            }
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        if (pt.y >= kLogListTop && pt.y < LogListBottom(rc)) {
            int idx = c->top + (pt.y - kLogListTop) / kLogRowH;
            if (idx >= 0 && idx < (int)c->rows.size()) LogSelect(c, idx);
        }
        return 0;
    }
    case WM_LBUTTONUP:
        if (c && c->drag) {
            c->drag = 0;
            ReleaseCapture();
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_NCHITTEST:
        return CapHitTest(h, wp, lp);
    case WM_KEYDOWN:
        if (!c) break;
        if (wp == VK_ESCAPE || wp == VK_RETURN) { DestroyWindow(h); return 0; }
        if (wp == VK_DOWN) LogSelect(c, c->sel + 1);
        if (wp == VK_UP) LogSelect(c, c->sel - 1);
        if (wp == VK_NEXT) LogScrollTo(c, c->top + c->visible);
        if (wp == VK_PRIOR) LogScrollTo(c, c->top - c->visible);
        if (wp == VK_HOME) LogSelect(c, 0);
        if (wp == VK_END) LogSelect(c, (int)c->rows.size() - 1);
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

}  // namespace

void ShowGitLog(HWND owner) {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(owner, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    if (GetFileAttributesW((dir + L"\\.git").c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(owner, (L"В папке выгрузки нет git-репозитория:\n" + dir).c_str(),
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    static bool cls = false;
    if (!cls) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = LogWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"V8iGitLog";
        if (!RegisterClassW(&wc)) return;
        cls = true;
    }
    LogCtx* c = new LogCtx();
    c->dir = dir;
    if (!LoadLog(dir, c->rows, &c->maxLanes)) {
        delete c;
        MessageBoxW(owner, L"Не удалось прочитать историю (git log вернул пусто).",
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    c->mono = LogFont(9, L"Consolas", FW_NORMAL, FIXED_PITCH | FF_MODERN);
    c->ui = LogFont(8, L"Tahoma", FW_NORMAL, DEFAULT_PITCH | FF_SWISS);
    c->uiSemi = LogFont(8, L"Tahoma", FW_BOLD, DEFAULT_PITCH | FF_SWISS);
    c->title = LogFont(8, L"Tahoma", FW_BOLD, DEFAULT_PITCH | FF_SWISS);
    c->badge = LogFont(8, L"Tahoma", FW_BOLD, DEFAULT_PITCH | FF_SWISS);

    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"V8iGitLog",
                             L"История Git — v8inject",
                             WS_POPUP | WS_THICKFRAME | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, 960, 700 + kCapH, owner, nullptr,
                             GetModuleHandleW(nullptr), nullptr);
    if (!h) { delete c; return; }
    CenterOnOwner(h, owner);
    SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)c);
    c->hwnd = h;
    RECT rc{};
    GetClientRect(h, &rc);
    SetRect(&c->rcClose, rc.right - 26, 3, rc.right - 4, 21);
    rc.bottom -= kCapH;
    c->visible = (LogListBottom(rc) - kLogListTop) / kLogRowH;
    if (c->visible < 1) c->visible = 1;
    SetForegroundWindow(h);
    LogSelect(c, 0);

    MSG msg;
    ModalEnter();
    while (IsWindow(h) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == h || IsChild(h, msg.hwnd)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        } else {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (IsWindow(h)) DestroyWindow(h);
    if (c->mono) DeleteObject(c->mono);
    if (c->ui) DeleteObject(c->ui);
    if (c->uiSemi) DeleteObject(c->uiSemi);
    if (c->title) DeleteObject(c->title);
    if (c->badge) DeleteObject(c->badge);
    delete c;
    ModalLeave(false);
}

}  // namespace gitbar
}  // namespace v8i
