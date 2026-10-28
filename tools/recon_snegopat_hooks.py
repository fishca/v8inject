#!/usr/bin/env python
"""recon_snegopat_hooks.py — где и как snegopat.dll ставит хуки окон.

Находка (8.3/8.5, snegopat.dll из v8snack):

- Импорты USER32: SetWindowsHookExW, CallNextHookEx, UnhookWindowsHookEx,
  CreateWindowExW — то есть WH_CBT-хук ставит сам модуль snegopat.dll
  (в core_as.dll хуков окон нет), и модуль же создаёт нативные окна.
- Экспорты snegopat.dll: moduleInit (точка входа модуля, вызывается ядром
  core_as) и вспомогательный parse_simple.
- Вызовы в .text: SetWindowsHookExW @ 0x2399 и 0x7A93; рядом — пара
  CallNextHookEx/UnhookWindowsHookEx (процедуры ~0x1900 и ~0x7700).

Сигнатура SetWindowsHookExW: rcx=idHook (5=WH_CBT), rdx=lpfn,
r8=hmod, r9=threadId.

Запуск:
    python tools/recon_snegopat_hooks.py --rva 0x2399
"""
import argparse
import os
import struct
import sys

DEFAULT = r"E:\work\repo_github\v8snack\snegopat-client\x64\modules\snegopat\lib\x64\snegopat.dll"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", default=DEFAULT)
    ap.add_argument("--rva", type=lambda s: int(s, 16), default=None)
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
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    base = pe.OPTIONAL_HEADER.ImageBase

    print("экспорты:", [(s.name.decode() if s.name else "?",
                         hex(s.address)) for s in getattr(
                             pe, "DIRECTORY_ENTRY_EXPORT", []).symbols])

    iat = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name and imp.name.decode() in (
                    "SetWindowsHookExW", "CallNextHookEx",
                    "UnhookWindowsHookEx", "CreateWindowExW"):
                iat[imp.address - base] = imp.name.decode()

    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    code = text.get_data()
    trva = text.VirtualAddress

    hits = []
    for i in range(len(code) - 6):
        if code[i] == 0xFF and code[i + 1] == 0x15:
            disp = struct.unpack_from("<i", code, i + 2)[0]
            tgt = trva + i + 6 + disp
            if tgt in iat:
                hits.append((trva + i, iat[tgt]))
            elif code[i + 1] == 0x15 and tgt in {0x7FFA}:
                pass  # не наша цель

    print("\nвызовы (RVA -> функция):")
    for rva, name in hits:
        print(f"  0x{rva:X}  {name}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    if args.rva is not None:
        s, e = max(trva, args.rva - 0x50), args.rva + 0x30
        print(f"\n=== контекст 0x{args.rva:X} ===")
        for ins in md.disasm(code[s - trva:e - trva], base + s):
            mark = "  <== call" if ins.address - base == args.rva else ""
            print(f"  0x{ins.address - base:08X}  {ins.mnemonic:8s} {ins.op_str}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())