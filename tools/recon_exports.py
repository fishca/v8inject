#!/usr/bin/env python
"""recon_exports.py — инвентарь экспортов платформы 1С для docs/RECON-85.md.

Читает PE-файлы напрямую (в памяти 8.5 зануляет export directory, поэтому
источник — только диск), собирает экспорты по модулям и строит diff 8.3/8.5.

Использование:
    python tools/recon_exports.py                # 8.5 по умолчанию
    python tools/recon_exports.py --json out.json
    python tools/recon_exports.py --diff         # плюс сравнение с 8.3

Требует: pefile (pip install pefile) — или запускать из venv v8snack.
"""
import argparse
import json
import os
import sys

BIN85 = r"C:\Program Files\1cv8\8.5.1.1529\bin"
BIN83 = r"C:\Program Files (x86)\1cv8\8.3.27.1989\bin"

MODULES85 = ["core85.dll", "frame.dll", "mngcore.dll", "mngui.dll", "config.dll", "wbase85.dll"]
MODULES83 = ["core83.dll", "frame.dll", "mngcore.dll", "mngui.dll", "config.dll", "wbase83.dll"]


def load_exports(path):
    """{name: rva} для всех именованных экспортов модуля."""
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    out = {}
    for sym in getattr(pe, "DIRECTORY_ENTRY_EXPORT", []).symbols:
        if sym.name:
            out[sym.name.decode("utf-8", "replace")] = sym.address
    return out


def dump(bin_dir, modules):
    res = {}
    for m in modules:
        p = os.path.join(bin_dir, m)
        if not os.path.exists(p):
            res[m] = {"error": "not found", "path": p}
            continue
        try:
            ex = load_exports(p)
            res[m] = {
                "path": p,
                "count": len(ex),
                "exports": dict(sorted(ex.items())),
            }
        except Exception as e:  # noqa: BLE001 — диагностика важнее типа
            res[m] = {"error": str(e), "path": p}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="куда сохранить полный дамп")
    ap.add_argument("--diff", action="store_true", help="сравнить с 8.3")
    args = ap.parse_args()

    data85 = dump(BIN85, MODULES85)
    print("== 8.5.1.1529 ==")
    for m, v in data85.items():
        if "error" in v:
            print(f"  {m:16s} ОШИБКА: {v['error']}")
        else:
            print(f"  {m:16s} экспортов: {v['count']}")

    result = {"build": "8.5.1.1529", "bin": BIN85, "modules": data85}

    if args.diff:
        data83 = dump(BIN83, MODULES83)
        print("\n== 8.3.27.1989 ==")
        for m, v in data83.items():
            if "error" in v:
                print(f"  {m:16s} ОШИБКА: {v['error']}")
            else:
                print(f"  {m:16s} экспортов: {v['count']}")
        result["build83"] = "8.3.27.1989"
        result["modules83"] = data83

        print("\n== различия по модулям ==")
        for m85, m83 in zip(MODULES85, MODULES83):
            a = data85.get(m85, {})
            b = data83.get(m83, {})
            if "exports" not in a or "exports" not in b:
                continue
            na, nb = set(a["exports"]), set(b["exports"])
            only83, only85 = nb - na, na - nb
            print(f"  {m85}: 8.3={len(nb)} 8.5={len(na)} "
                  f"только-в-8.3={len(only83)} только-в-8.5={len(only85)}")
            result.setdefault("diff", {})[m85] = {
                "only83": sorted(only83),
                "only85": sorted(only85),
            }

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=1)
        print(f"\nсохранено: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
