#!/usr/bin/env python3
"""Copy the chosen qtv8reader icons into the role-named PNGs used by GitBar.

The source PNGs live in src/payload/icons/qtv8reader/ (16px variants from
qtv8reader's metadata icon set; MIT, see ATTRIBUTION.md and
LICENSE-METADATA-ICONS.txt there). This script only maps source names to the
GitBar roles and copies them to src/payload/icons/<role>.png, so the mapping
lives in one place. After that run `python tools/gen_icons.py` to rebuild
icons.h and icons_png.h.

Run from the repo root:  python tools/select_icons.py
"""

import os
import shutil
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ICON_DIR = os.path.join(ROOT, "src", "payload", "icons")
SRC_DIR = os.path.join(ICON_DIR, "qtv8reader")

# role -> qtv8reader metadata icon (16px file in SRC_DIR)
ROLES = [
    ("dump", "document"),
    ("dumpext", "dataProcessor"),
    ("init", "constant"),
    ("clone", "externalDataSource"),
    ("commit", "accountingFlag"),
    ("push", "exchangePlan"),
    ("pull", "businessProcess"),
    ("fetch", "ws"),
    ("branches", "group"),
    ("stash", "settingsStorage"),
    ("tags", "filterCriteria"),
    ("status", "extDimensionAccountingFlag"),
    ("log", "scheduledJob"),
    ("settings", "sessionParameter"),
    ("gitbar", "subsystem"),
]


def png_size(path):
    """Minimal PNG reader: return (width, height, bit_depth, color_type)."""
    with open(path, "rb") as f:
        head = f.read(33)
    if head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        sys.exit(f"{path}: not a PNG")
    w, h, depth, color = struct.unpack(">IIBB", head[16:26])
    return w, h, depth, color


def main():
    for role, name in ROLES:
        src = os.path.join(SRC_DIR, name + "_16.png")
        if not os.path.exists(src):
            sys.exit(f"missing source icon: {src}")
        w, h, depth, color = png_size(src)
        # GitBar bakes 16x16 RGBA (color type 6) with 8 bits per channel.
        if (w, h, depth, color) != (16, 16, 8, 6):
            sys.exit(f"{src}: expected 16x16 RGBA PNG, got {w}x{h} "
                     f"depth={depth} color={color}")
        dst = os.path.join(ICON_DIR, role + ".png")
        shutil.copyfile(src, dst)
        print(f"{role}.png <- qtv8reader/{name}_16.png")
    print(f"{len(ROLES)} icons selected from qtv8reader")


if __name__ == "__main__":
    main()
