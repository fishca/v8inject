#include "v8inject/disasm.h"
#include "v8inject/pe_utils.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstring>

namespace v8i {

namespace {

// A handle per bitness, created on first use. Capstone handles are not
// thread-safe to reconfigure, but each command runs on a single thread here.
struct Handles {
    csh h32 = 0;
    csh h64 = 0;
    bool ok32 = false;
    bool ok64 = false;

    csh Get(bool is64) {
        csh& h = is64 ? h64 : h32;
        bool& ok = is64 ? ok64 : ok32;
        if (h) return ok ? h : 0;
        cs_mode mode = is64 ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(CS_ARCH_X86, mode, &h) != CS_ERR_OK) {
            h = 0;
            ok = false;
            return 0;
        }
        cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
        ok = true;
        return h;
    }
};

Handles& GetHandles() {
    static Handles handles;
    return handles;
}

std::string HexOf(const uint8_t* p, size_t n) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0xF]);
    }
    return out;
}

}  // namespace

size_t DecodeOne(uintptr_t address, Insn* out, bool is64) {
    csh h = GetHandles().Get(is64);
    if (!h || !out) return 0;
    if (!IsReadable((const void*)address, 16)) return 0;

    cs_insn* insn = nullptr;
    size_t n = cs_disasm(h, (const uint8_t*)address, 16, (uint64_t)address, 1, &insn);
    if (n == 0 || !insn) return 0;

    out->address = (uintptr_t)insn[0].address;
    out->size = (uint8_t)insn[0].size;
    out->mnemonic = insn[0].mnemonic;
    out->opStr = insn[0].op_str;
    out->bytes = HexOf(insn[0].bytes, insn[0].size);

    size_t size = insn[0].size;
    cs_free(insn, n);
    return size;
}

std::vector<Insn> Disassemble(uintptr_t start, size_t size, size_t maxInsns,
                              uintptr_t* stoppedAt, bool is64) {
    std::vector<Insn> out;
    if (stoppedAt) *stoppedAt = start;
    csh h = GetHandles().Get(is64);
    if (!h) return out;

    uintptr_t cur = start;
    uintptr_t end = start + size;
    while (cur < end && out.size() < maxInsns) {
        // Copy through a scratch buffer: reading the target's code directly into
        // Capstone is fine, but guarding the page first avoids a fault on the
        // last page of a section.
        uint8_t scratch[16] = {};
        size_t want = (size_t)std::min<uintptr_t>(sizeof(scratch), end - cur);
        if (!IsReadable((const void*)cur, 1)) break;
        memcpy(scratch, (const void*)cur, want);

        cs_insn* insn = nullptr;
        size_t n = cs_disasm(h, scratch, want, (uint64_t)cur, 1, &insn);
        if (n == 0 || !insn) break;

        Insn i;
        i.address = cur;
        i.size = (uint8_t)insn[0].size;
        i.mnemonic = insn[0].mnemonic;
        i.opStr = insn[0].op_str;
        i.bytes = HexOf(insn[0].bytes, insn[0].size);
        cs_free(insn, n);

        if (i.size == 0) break;
        out.push_back(std::move(i));
        cur += out.back().size;
        if (stoppedAt) *stoppedAt = cur;
    }
    return out;
}

XrefResult FindXrefsVerbose(uintptr_t start, uintptr_t end, uintptr_t target,
                            bool is64, size_t maxHits) {
    XrefResult r;
    r.scannedTo = start;
    csh h = GetHandles().Get(is64);
    if (!h) return r;

    // Copy each page into a local buffer once instead of per instruction: the
    // sweep touches millions of bytes and a syscall per byte is hopeless.
    static const size_t kChunk = 0x1000;
    std::vector<uint8_t> buf(kChunk + 16);
    uintptr_t chunkBase = 0;
    size_t chunkHave = 0;

    uintptr_t cur = start;
    while (cur < end) {
        if (r.hits.size() >= maxHits) { r.hitLimit = true; break; }

        if (cur < chunkBase || cur >= chunkBase + chunkHave) {
            chunkBase = cur;
            chunkHave = 0;
            size_t want = (size_t)std::min<uintptr_t>(kChunk, end - cur);
            if (!IsReadable((const void*)cur, want)) {
                // Find the next readable region rather than dying here.
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery((LPCVOID)cur, &mbi, sizeof(mbi))) break;
                uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                if (next <= cur) break;
                cur = next;
                continue;
            }
            memcpy(buf.data(), (const void*)cur, want);
            chunkHave = want;
        }

        size_t off = (size_t)(cur - chunkBase);
        size_t avail = std::min<size_t>(chunkHave - off, 15);
        if (avail == 0) { cur += 1; continue; }

        cs_insn* insn = nullptr;
        size_t n = cs_disasm(h, buf.data() + off, avail, (uint64_t)cur, 1, &insn);
        if (n == 0 || !insn) {
            ++cur;
            ++r.badBytes;
            continue;
        }

        bool hit = false;
        std::string how;
        const cs_x86& x = insn[0].detail->x86;
        for (int k = 0; k < x.op_count; ++k) {
            const cs_x86_op& op = x.operands[k];
            if (op.type == X86_OP_IMM && (uintptr_t)op.imm == target) {
                hit = true;
                how = insn[0].mnemonic;
            } else if (op.type == X86_OP_MEM && op.mem.base == X86_REG_INVALID &&
                       op.mem.index == X86_REG_INVALID &&
                       (uintptr_t)op.mem.disp == target) {
                hit = true;
                how = std::string(insn[0].mnemonic) + " [mem]";
            }
        }

        size_t sz = insn[0].size ? insn[0].size : 1;
        cs_free(insn, n);

        if (hit) {
            Xref xr;
            xr.from = cur;
            xr.to = target;
            xr.how = how;
            r.hits.push_back(std::move(xr));
        }
        cur += sz;
        r.bytesSeen += sz;
        r.scannedTo = cur;
    }
    if (r.scannedTo < start) r.scannedTo = start;
    return r;
}

std::vector<Xref> FindXrefs(uintptr_t start, uintptr_t end, uintptr_t target,
                            bool is64, size_t maxHits) {
    return FindXrefsVerbose(start, end, target, is64, maxHits).hits;
}

std::vector<uintptr_t> FindFunctionPrologues(uintptr_t start, uintptr_t end,
                                             bool is64, size_t maxHits) {
    std::vector<uintptr_t> out;

    // Classic MSVC prologues. They are not proof of a function start (a prologue
    // byte pair can appear inside another instruction), so callers should verify
    // by decoding forward from the candidate.
    const uint8_t p32a[] = {0x55, 0x8B, 0xEC};              // push ebp; mov ebp,esp
    const uint8_t p32b[] = {0x55, 0x89, 0xE5};              // push ebp; mov ebp,esp (alternate)
    const uint8_t p64a[] = {0x48, 0x89, 0x5C, 0x24};        // mov [rsp+x],rbx
    const uint8_t p64b[] = {0x40, 0x53};                    // push rbx (REX prefix)
    const uint8_t p64c[] = {0x48, 0x83, 0xEC};              // sub rsp, imm8

    auto matches = [](const uint8_t* p, const uint8_t* pat, size_t n) {
        return memcmp(p, pat, n) == 0;
    };

    for (uintptr_t cur = start; cur + 8 < end && out.size() < maxHits; ++cur) {
        if (!IsReadable((const void*)cur, 8)) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery((LPCVOID)cur, &mbi, sizeof(mbi))) break;
            cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }
        const uint8_t* p = (const uint8_t*)cur;
        bool yes = false;
        if (!is64) {
            yes = matches(p, p32a, sizeof(p32a)) || matches(p, p32b, sizeof(p32b));
        } else {
            yes = matches(p, p64a, sizeof(p64a)) || matches(p, p64b, sizeof(p64b)) ||
                  matches(p, p64c, sizeof(p64c));
        }
        if (yes) out.push_back(cur);
    }
    return out;
}

}  // namespace v8i
