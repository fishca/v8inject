#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

// One decoded instruction.
struct Insn {
    uintptr_t address = 0;
    uint8_t   size = 0;
    std::string mnemonic;          // "call", "mov", "lea", ...
    std::string opStr;             // intel syntax operand text
    std::string bytes;             // hex of the raw instruction
};

// A reference to a function/data address found inside a function body.
struct Xref {
    uintptr_t from = 0;            // address of the referring instruction
    uintptr_t to = 0;              // absolute address referenced
    std::string how;               // "call", "jmp", "lea", "mov-imm", "push-imm"
};

struct FunctionInfo {
    uintptr_t start = 0;
    uintptr_t end = 0;             // exclusive
    bool      prologue = false;    // starts with a standard frame prologue
    bool      endsWithRet = false;
};

// Linear sweep over [start, start+size) inside the current process.
// Returns at most `maxInsns` decoded instructions; `stoppedAt` receives the
// address where decoding stopped (bad byte, unreadable page, or the limit).
std::vector<Insn> Disassemble(uintptr_t start, size_t size, size_t maxInsns,
                              uintptr_t* stoppedAt, bool is64);

// Decodes one instruction; returns its length or 0 when it cannot be decoded.
size_t DecodeOne(uintptr_t address, Insn* out, bool is64);

// Finds call/jmp/lea/mov references to `target` inside [start, end).
// This is the primitive used to locate code that touches a known address,
// such as an IAT slot for CreateWindowExW.
std::vector<Xref> FindXrefs(uintptr_t start, uintptr_t end, uintptr_t target,
                            bool is64, size_t maxHits);

// Diagnostic variant: also reports how far the sweep actually got and how many
// bytes failed to decode, so an empty result can be told apart from a broken scan.
struct XrefResult {
    std::vector<Xref> hits;
    uintptr_t scannedTo = 0;
    size_t    bytesSeen = 0;
    size_t    badBytes = 0;
    bool      hitLimit = false;
    const char* stopReason = "";
    int       csError = 0;         // cs_err when Capstone failed to initialise
};
XrefResult FindXrefsVerbose(uintptr_t start, uintptr_t end, uintptr_t target,
                            bool is64, size_t maxHits);

// Scans for MSVC function prologues (push ebp / mov ebp,esp and the x64
// equivalents) and returns the candidate function starts.
std::vector<uintptr_t> FindFunctionPrologues(uintptr_t start, uintptr_t end,
                                             bool is64, size_t maxHits);

}  // namespace v8i
