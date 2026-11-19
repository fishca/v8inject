#include "v8inject/injector.h"
#include "v8inject/procs.h"
#include "v8inject/diag.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdarg>
#include <cstring>

namespace v8i {

namespace {

// Writes a buffer into the target and keeps the allocation alive.
void* AllocRemote(HANDLE hProc, const void* data, size_t bytes) {
    void* remote = VirtualAllocEx(hProc, nullptr, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return nullptr;
    if (!WriteProcessMemory(hProc, remote, data, bytes, nullptr)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return nullptr;
    }
    return remote;
}

// Fills `*out` with a formatted explanation, when the caller asked for one.
void SetDetail(std::wstring* out, const wchar_t* fmt, ...) {
    if (!out) return;
    wchar_t buf[512] = {};
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    *out = buf;
}

// The two readers behind ImageReadFn. The target's image is read through the
// process handle; the host's own copy is already mapped, so a memcpy is all it
// takes. Neither is allowed to read past the end of its image -- the walker
// below bounds every offset with SizeOfImage, but the target reader checks the
// mapped image as well: a stale or corrupt header must not turn the walk into
// a read of unrelated memory of our own process.
struct TargetImage {
    HANDLE    hProc;
    uintptr_t base;
};

bool ReadTargetImage(void* ctx, uint32_t rva, void* dst, size_t bytes) {
    const TargetImage* t = static_cast<const TargetImage*>(ctx);
    if (!t || !t->hProc) return false;
    SIZE_T got = 0;
    if (!ReadProcessMemory(t->hProc, (const BYTE*)t->base + rva, dst, bytes, &got))
        return false;
    return got == bytes;
}

struct HostImage {
    uintptr_t base;
};

bool ReadHostImage(void* ctx, uint32_t rva, void* dst, size_t bytes) {
    const HostImage* h = static_cast<const HostImage*>(ctx);
    if (!h || !h->base) return false;
    memcpy(dst, (const BYTE*)h->base + rva, bytes);
    return true;
}

constexpr uint32_t kMaxImageSize   = 512u * 1024u * 1024u;
constexpr uint32_t kMaxExportNames = 1u << 16;
constexpr size_t   kMaxExportName  = 64;

bool ReadBounded(const ImageReadFn& image, uint32_t sizeOfImage,
                 uint64_t rva, void* dst, size_t bytes) {
    if (rva + bytes > sizeOfImage) return false;
    return image.read(image.ctx, (uint32_t)rva, dst, bytes);
}

// Reads a NUL-terminated export name within the image and within `cap`.
bool ReadExportName(const ImageReadFn& image, uint32_t sizeOfImage,
                    uint32_t rva, char (&name)[kMaxExportName]) {
    for (size_t i = 0; i < kMaxExportName; ++i) {
        if (!ReadBounded(image, sizeOfImage, (uint64_t)rva + i, &name[i], 1)) return false;
        if (name[i] == 0) return true;
    }
    name[kMaxExportName - 1] = 0;
    return false;   // no terminator within the cap: not a name we want
}

}  // namespace

// The walk itself. Kept pure over the reader so the unit tests can hand it
// synthetic images and the host's own copy goes through the very same code as
// the target's image: what one side accepts, the other accepts too.
PayloadImage FindProbeExport(const ImageReadFn& image) {
    PayloadImage out;
    out.error = "the image could not be read";
    if (!image.read) return out;

    IMAGE_DOS_HEADER dos{};
    if (!image.read(image.ctx, 0, &dos, sizeof(dos))) return out;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        out.error = "the image does not start with MZ";
        return out;
    }
    if (dos.e_lfanew <= 0) {
        out.error = "the DOS header has no NT signature offset";
        return out;
    }

    const uint32_t ntRva = (uint32_t)dos.e_lfanew;
    uint32_t signature = 0;
    if (!image.read(image.ctx, ntRva, &signature, sizeof(signature))) {
        out.error = "the NT signature is unreadable";
        return out;
    }
    if (signature != IMAGE_NT_SIGNATURE) {
        out.error = "the image has no PE signature";
        return out;
    }

    IMAGE_FILE_HEADER file{};
    if (!image.read(image.ctx, ntRva + 4, &file, sizeof(file))) {
        out.error = "the file header is unreadable";
        return out;
    }
    out.timeDateStamp = file.TimeDateStamp;

    const uint32_t optRva = ntRva + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = 0;
    if (!image.read(image.ctx, optRva, &magic, sizeof(magic))) {
        out.error = "the optional header is unreadable";
        return out;
    }
    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        out.error = "the optional header is neither PE32 nor PE32+";
        return out;
    }

    // SizeOfImage sits at the same offset in both optional header flavors; the
    // data directory does not (96 bytes into PE32, 112 into PE32+).
    uint32_t sizeOfImage = 0;
    if (!image.read(image.ctx, optRva + 56, &sizeOfImage, sizeof(sizeOfImage))) {
        out.error = "the image size is unreadable";
        return out;
    }
    if (sizeOfImage < optRva + 64 || sizeOfImage > kMaxImageSize) {
        out.error = "the image size is implausible";
        return out;
    }
    // Reported even when the walk ends in a refusal: "which image did we look
    // at" is what the log needs when the export is missing.
    out.sizeOfImage = sizeOfImage;

    const uint64_t dirRva = (uint64_t)optRva +
                            (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112u : 96u);
    IMAGE_DATA_DIRECTORY exports{};
    if (!ReadBounded(image, sizeOfImage, dirRva, &exports, sizeof(exports))) {
        out.error = "the export directory entry is unreadable";
        return out;
    }
    if (!exports.VirtualAddress || exports.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        out.error = "the image has no export directory";
        return out;
    }

    IMAGE_EXPORT_DIRECTORY dir{};
    if (!ReadBounded(image, sizeOfImage, exports.VirtualAddress, &dir, sizeof(dir))) {
        out.error = "the export directory is unreadable";
        return out;
    }
    if (!dir.NumberOfNames || dir.NumberOfNames > kMaxExportNames ||
        dir.NumberOfFunctions > kMaxExportNames) {
        out.error = "the export table has an implausible number of entries";
        return out;
    }

    for (uint32_t i = 0; i < dir.NumberOfNames; ++i) {
        uint32_t nameRva = 0;
        uint16_t ordinal = 0;
        if (!ReadBounded(image, sizeOfImage, (uint64_t)dir.AddressOfNames + (uint64_t)i * 4,
                         &nameRva, sizeof(nameRva)) ||
            !ReadBounded(image, sizeOfImage, (uint64_t)dir.AddressOfNameOrdinals + (uint64_t)i * 2,
                         &ordinal, sizeof(ordinal))) {
            out.error = "the export name table is unreadable";
            return out;
        }
        char name[kMaxExportName] = {};
        // An unusable name is simply not the one we are looking for; the one we
        // want has to be readable, and it is, or the walk ends in a refusal.
        if (!ReadExportName(image, sizeOfImage, nameRva, name)) continue;
        if (strcmp(name, "v8i_probe") != 0) continue;

        if (ordinal >= dir.NumberOfFunctions) {
            out.error = "the v8i_probe ordinal leaves the function table";
            return out;
        }
        uint32_t probeRva = 0;
        if (!ReadBounded(image, sizeOfImage, (uint64_t)dir.AddressOfFunctions + (uint64_t)ordinal * 4,
                         &probeRva, sizeof(probeRva))) {
            out.error = "the export function table is unreadable";
            return out;
        }
        if (!probeRva || probeRva >= sizeOfImage) {
            out.error = "the v8i_probe export points outside the image";
            return out;
        }
        // Inside the export directory means the entry is a forwarder string
        // ("OTHERDLL.func"), not code in this image.
        if (probeRva >= exports.VirtualAddress &&
            (uint64_t)probeRva < (uint64_t)exports.VirtualAddress + exports.Size) {
            out.error = "the v8i_probe export is forwarded to another module";
            return out;
        }
        out.ok = true;
        out.sizeOfImage = sizeOfImage;
        out.probeRva = probeRva;
        out.error = "";
        return out;
    }
    out.error = "the image does not export v8i_probe";
    return out;
}

bool PayloadBuildMatches(const PayloadImage& target, const PayloadImage& file) {
    if (!target.ok || !file.ok) return false;
    return target.timeDateStamp == file.timeDateStamp &&
           target.sizeOfImage == file.sizeOfImage;
}

namespace {

// LoadLibraryW is resolved locally and rebased into the target, never used by
// its local address. On one Windows boot the system DLLs sit at the same base
// in every process of a bitness, so the delta is usually zero -- but that is
// an assumption, and checking it turns a silent wrong-address call in the
// target into a clean, explained failure.
bool RemoteLoadLibrary(HANDLE hProc, const std::wstring& dllPath, HMODULE* baseOut) {
    void* remote = AllocRemote(hProc, dllPath.c_str(),
                               (dllPath.size() + 1) * sizeof(wchar_t));
    if (!remote) return false;

    HMODULE localK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC localLoadLib = localK32 ? GetProcAddress(localK32, "LoadLibraryW") : nullptr;
    // Свежесозданный процесс (launch) может ещё мапить модули: kernel32 в
    // списке целей появляется через миллисекунды. Ждём до 2 с вместо
    // мгновенного отказа, иначе launch-инъекция в новый процесс нестабильна.
    HMODULE remoteK32 = nullptr;
    for (int i = 0; localLoadLib && i < 40; ++i) {
        remoteK32 = FindModuleInProcess(hProc, L"kernel32.dll");
        if (remoteK32) break;
        Sleep(50);
    }
    LPTHREAD_START_ROUTINE loadLib = nullptr;
    if (localLoadLib && remoteK32) {
        loadLib = (LPTHREAD_START_ROUTINE)((uintptr_t)localLoadLib
                                           - (uintptr_t)localK32
                                           + (uintptr_t)remoteK32);
    }
    LogLine("RemoteLoadLibrary: kernel32 local=%p remote=%p LoadLibraryW local=%p remote=%p",
            (void*)localK32, (void*)remoteK32, (void*)localLoadLib, (void*)loadLib);
    if (!loadLib) {
        LogLine("RemoteLoadLibrary: cannot resolve LoadLibraryW in the target");
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, loadLib, remote, 0, nullptr);
    DWORD wait = WAIT_FAILED;
    DWORD code = 0;
    if (th) {
        wait = WaitForSingleObject(th, 15000);
        if (wait == WAIT_OBJECT_0) GetExitCodeThread(th, &code);
    }

    // On anything but a clean finish, find out whether the load completed
    // anyway: a slow target may have loaded the DLL after the timeout fired.
    bool modulePresent = false;
    if (wait != WAIT_OBJECT_0)
        modulePresent = FindModuleInProcess(hProc, dllPath) != nullptr;

    RemoteLoadDecision d = th
        ? EvaluateRemoteLoad(wait, code, modulePresent)
        : RemoteLoadDecision{ false, true, "no remote thread was created" };
    LogLine("RemoteLoadLibrary(%ls) -> %s (wait=%lu code=%lu): %s%s",
            dllPath.c_str(), d.ok ? "ok" : "FAILED", wait, code, d.reason,
            d.freeBuffer ? "" : "; path buffer left allocated");
    if (th) CloseHandle(th);
    if (d.freeBuffer) VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    if (!d.ok) return false;

    // Resolve the real module base inside the target.
    if (baseOut) {
        HMODULE remoteBase = FindModuleInProcess(hProc, dllPath);
        LogLine("FindModuleInProcess -> %p", (void*)remoteBase);
        if (!remoteBase) return false;
        *baseOut = remoteBase;
    }
    return true;
}

}  // namespace

// The decision table for the remote LoadLibrary thread. Kept pure: the unit
// tests pin it down, so a future edit cannot silently reintroduce a free
// under a still-running remote thread.
RemoteLoadDecision EvaluateRemoteLoad(DWORD wait, DWORD exitCode, bool modulePresent) {
    if (wait == WAIT_OBJECT_0) {
        if (exitCode != 0 && exitCode != STILL_ACTIVE)
            return { true, true, "the remote thread finished and returned a module handle" };
        if (exitCode == 0)
            return { false, true, "LoadLibraryW returned NULL" };
        // A finished thread that reports STILL_ACTIVE is indistinguishable
        // from a handle value of 259: neither is a base address we trust.
        return { false, true, "the remote thread exited with code STILL_ACTIVE" };
    }
    // WAIT_TIMEOUT (and, hypothetically, WAIT_FAILED): the thread's fate is
    // unknown, and the path buffer may still be read by it. Never freed.
    if (modulePresent)
        return { true, false, "timed out, but the module is loaded in the target" };
    return { false, false, "injection hung: the remote thread did not finish" };
}

HMODULE FindModuleInProcess(HANDLE hProc, const std::wstring& dllPath) {
    const wchar_t* want = wcsrchr(dllPath.c_str(), L'\\');
    want = want ? want + 1 : dllPath.c_str();

    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return nullptr;

    // Two copies of the payload under different paths can be resident at once
    // (rebuild + re-inject without restarting the target). Matching by base
    // name alone returns whichever copy the enumeration lists first, and the
    // probe address computed from it executes a foreign module (live
    // 2026-11-15: that killed the target with 0x80000003). Exact path wins;
    // the base-name pass remains for targets that canonicalize the injected
    // path (short names, subst drives).
    DWORD count = needed / sizeof(HMODULE);
    for (int pass = 0; pass < 2; ++pass) {
        for (DWORD i = 0; i < count; ++i) {
            wchar_t path[MAX_PATH] = {};
            if (!GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH)) continue;
            const wchar_t* got = wcsrchr(path, L'\\');
            got = got ? got + 1 : path;
            if (pass == 0 ? _wcsicmp(path, dllPath.c_str()) == 0
                          : _wcsicmp(got, want) == 0) {
                return mods[i];
            }
        }
    }
    return nullptr;
}

DWORD FindProcessByName(const wchar_t* exeName) {
    if (!exeName) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool InjectLibrary(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) return false;
    bool ok = RemoteLoadLibrary(hProc, dllPath, nullptr);
    CloseHandle(hProc);
    return ok;
}

bool StartPayloadThread(DWORD pid,
                        const std::wstring& payloadDll,
                        const wchar_t* sharedName,
                        HANDLE& hProcessOut,
                        HANDLE& hThreadOut,
                        int& stageOut,
                        DWORD& win32ErrorOut,
                        std::wstring* detailOut) {
    hProcessOut = nullptr;
    hThreadOut = nullptr;
    stageOut = kStageOpenProcess;
    win32ErrorOut = 0;
    if (detailOut) detailOut->clear();
    if (!sharedName) { win32ErrorOut = ERROR_INVALID_PARAMETER; return false; }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) { win32ErrorOut = GetLastError(); return false; }

    // The target base comes back as the thread's exit code (HMODULE value).
    stageOut = kStageLoadLibrary;
    HMODULE targetBase = nullptr;
    if (!RemoteLoadLibrary(hProc, payloadDll, &targetBase)) {
        win32ErrorOut = GetLastError();
        CloseHandle(hProc);
        return false;
    }

    // Take the export RVA from the image the target actually holds (A42). The
    // target may have answered with an OLD payload module it loaded earlier:
    // LoadLibraryW keys on the path, so a rebuilt file under the same name is
    // not mapped, and the RVA of v8i_probe in that resident image is not the
    // RVA in the file the host just read. Rebasing a local address by the
    // module delta was exactly that mistake.
    TargetImage targetImage{ hProc, (uintptr_t)targetBase };
    const PayloadImage target = FindProbeExport({ ReadTargetImage, &targetImage });
    LogLine("payload image in the target: base=%p stamp=%08lX size=%lu probeRva=0x%08lX %s",
            (void*)targetBase, (unsigned long)target.timeDateStamp,
            (unsigned long)target.sizeOfImage, (unsigned long)target.probeRva,
            target.ok ? "ok" : target.error);
    if (!target.ok) {
        stageOut = kStageTargetImage;
        SetDetail(detailOut,
                  L"the payload image resident in the target cannot be used: %hs. "
                  L"A payload DLL cannot be replaced in a running process -- if the "
                  L"target still runs an older build of v8inject, restart it",
                  target.error);
        CloseHandle(hProc);
        return false;
    }

    // Load the very same file here: the build on disk is what the target should
    // be running, and its stamp tells whether the resident image is that build.
    stageOut = kStageLocalLoad;
    HMODULE localBase = LoadLibraryW(payloadDll.c_str());
    if (!localBase) {
        win32ErrorOut = GetLastError();
        CloseHandle(hProc);
        return false;
    }
    HostImage hostImage{ (uintptr_t)localBase };
    const PayloadImage file = FindProbeExport({ ReadHostImage, &hostImage });
    LogLine("payload image on disk: base=%p stamp=%08lX size=%lu probeRva=0x%08lX %s",
            (void*)localBase, (unsigned long)file.timeDateStamp,
            (unsigned long)file.sizeOfImage, (unsigned long)file.probeRva,
            file.ok ? "ok" : file.error);
    FreeLibrary(localBase);   // target keeps its own reference

    if (!file.ok) {
        stageOut = kStageGetProcAddress;
        SetDetail(detailOut,
                  L"the payload DLL does not export a usable v8i_probe: %hs",
                  file.error);
        CloseHandle(hProc);
        return false;
    }
    if (!PayloadBuildMatches(target, file)) {
        // Refuse instead of calling into a resident image of another build: the
        // stamp is the build identity, and a different one means the target
        // still holds the previous payload (A42).
        stageOut = kStagePayloadMismatch;
        SetDetail(detailOut,
                  L"the target already runs a payload from another build "
                  L"(resident stamp %08lX, size %lu; the DLL on disk: stamp %08lX, "
                  L"size %lu). A loaded DLL cannot be replaced in place -- restart "
                  L"the target application",
                  (unsigned long)target.timeDateStamp, (unsigned long)target.sizeOfImage,
                  (unsigned long)file.timeDateStamp, (unsigned long)file.sizeOfImage);
        LogLine("refusing to start a payload thread in a target of another build");
        CloseHandle(hProc);
        return false;
    }

    const uintptr_t remoteProbeAddr = (uintptr_t)targetBase + target.probeRva;
    LogLine("targetBase=%p probeRva=%08lX -> remoteProbe=%p",
            (void*)targetBase, target.probeRva, (void*)remoteProbeAddr);

    // Nothing is passed to the payload: it derives the block name from its own
    // PID, so there is no cross-process string to marshal.
    stageOut = kStageCreateThread;
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remoteProbeAddr,
                                   nullptr, 0, nullptr);
    LogLine("CreateRemoteThread -> %p err=%lu", (void*)th, GetLastError());
    if (!th) {
        win32ErrorOut = GetLastError();
        CloseHandle(hProc);
        return false;
    }

    stageOut = kStageOk;
    hProcessOut = hProc;
    hThreadOut = th;

    // Ask the thread what happened: exit code 259 means it is still running,
    // anything else is the value v8i_probe returned (or a crash code).
    DWORD wait = WaitForSingleObject(th, 3000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    LogLine("thread wait=%lu exitCode=%lu (259=STILL_ACTIVE, 0=returned)",
            wait, code);
    return true;
}

}  // namespace v8i
