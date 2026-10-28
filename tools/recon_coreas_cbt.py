#!/usr/bin/env python
"""recon_coreas_cbt.py — как core_as.dll (движок Снегопата) ставит WH_CBT.

Находка (8.5, core_as.dll из v8snack):

    0x13E040  sub  rsp, 0x28
    0x13E044  mov  r9d, [rip+0x25d169]   ; threadId — глобал (поток 1С)
    0x13E04B  lea  rdx, [rip+0x1e]       ; lpfn = 0x13E070 (хук-процедура)
    0x13E052  xor  r8d, r8d              ; hMod = NULL (код уже в процессе)
    0x13E055  lea  ecx, [r8+3]           ; idHook = 3 = WH_CBT
    0x13E059  call [SetWindowsHookExW]
    0x13E05F  mov  [rip+0x25d142], rax   ; g_hook

Хук-процедура 0x13E070:
    nCode != 0                -> CallNextHookEx
    g_engine == NULL          -> CallNextHookEx
    первый вызов (флаг == 1)  -> CallNextHookEx, затем
                                 [engine->vtable[0]](engine, nCode+1)
                                 — инициализация движка (run()) на заставке,
                                 флаг сбрасывается в 0
    дальше                    -> обход списка окон движка (engine+0x1B8)

То есть Снегопат не подписывается «в хуке» напрямую: он вызывает
инициализацию движка на первом CBT-событии, когда все DLL платформы уже
загружены, а главное окно ещё не создано. Подписка на eventCreateFrame
происходит уже внутри run().

Запуск:
    python tools/recon_coreas_cbt.py            # найти вызовы
    python tools/recon_coreas_cbt.py --disasm   # плюс дизасм хука
"""
import argparse
import os
import struct
import sys

DEFAULT = r"E:\work\repo_github\v8snack\snegopat-client\x64\lib\x64\core_as.dll"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", default=DEFAULT)
    ap.add_argument("--disasm", action="store_true")
    args = ap.parse_args()

    try:
        import pefile
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError as e:
        print(f"нужны pefile и capstone: {e}", file=sys.stderr)
        return 2
    if not os.path.exists(args.dll):
        print(f"нет файла: {args.dll}", file=sys.stderr)
        return 2

    pe = pefile.PE(args.dll, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    base = pe.OPTIONAL_HEADER.ImageBase

    iat = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name and imp.name.decode() in (
                    "SetWindowsHookExW", "CallNextHookEx", "UnhookWindowsHookEx"):
                iat[imp.address - base] = imp.name.decode()

    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    code = text.get_data()
    trva = text.VirtualAddress

    hits = []
    for i in range(len(code) - 6):
        if code[i] == 0xFF and code[i + 1] == 0x15:      # call [rip+disp32]
            disp = struct.unpack_from("<i", code, i + 2)[0]
            tgt = trva + i + 6 + disp
            if tgt in iat:
                hits.append((trva + i, iat[tgt]))

    print(f"обращений к хуковым импортам: {len(hits)}")
    for rva, name in hits:
        print(f"  0x{rva:X}  {name}")

    if not args.disasm:
        return 0

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for rva, name in hits:
        if name != "SetWindowsHookExW":
            continue
        s, e = max(trva, rva - 0x30), rva + 0x30
        print(f"\n=== установка хука (0x{rva:X}) ===")
        for ins in md.disasm(code[s - trva:e - trva], base + s):
            mark = "  <== call" if ins.address - base == rva else ""
            print(f"  0x{ins.address - base:08X}  {ins.mnemonic:8s} {ins.op_str}{mark}")
        # хук-процедура: lea rdx,[rip+disp] рядом с установкой
        hproc = None
        for i in range(max(0, rva - 0x30 - trva), (rva - trva)):
            if code[i] == 0x48 and code[i + 1] == 0x8D and code[i + 2] == 0x15:
                disp = struct.unpack_from("<i", code, i + 3)[0]
                hproc = trva + i + 7 + disp
        if hproc:
            print(f"\n=== хук-процедура 0x{hproc:X} ===")
            s2, e2 = hproc, hproc + 0x180
            for ins in md.disasm(code[s2 - trva:e2 - trva], base + s2):
                print(f"  0x{ins.address - base:08X}  {ins.mnemonic:8s} {ins.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
