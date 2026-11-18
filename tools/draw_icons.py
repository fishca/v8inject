#!/usr/bin/env python3
"""Draw the GitBar icon set: original 16x16 glyphs in the Configurator style.

The platform-looking glyphs that used to live in src/payload/icons/ were cut
out of 1C's own module resources (core83_root.res, mngcore_root.res, ...).
Shipping those pixels is a licensing problem, so the icons are drawn here from
scratch: same 16x16 grid, same beige/blue/green/gold palette and beveled
"plastic" look as the Configurator itself, but every shape is our own.

The output PNGs feed tools/gen_icons.py, which bakes two generated headers:
  * src/payload/icons.h      - premultiplied BGRA for the GDI toolbar strip;
  * src/payload/icons_png.h  - raw PNG bytes for the native main-menu items.

Run from the repo root:
    python tools/draw_icons.py        # draw the PNGs
    python tools/gen_icons.py         # regenerate the C++ headers

The PNGs are committed, the script is the source of truth. Artwork: project
author, MIT (same as the repository); no 1C resource data is embedded.
"""

import os
import math
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "payload", "icons")

SIZE = 16          # final icon size
S = 8              # supersampling factor used while drawing
W = H = SIZE * S

# --- palette: sampled from the Configurator's own chrome --------------------
INK = (74, 66, 52, 255)          # dark brown-grey outline
INK_SOFT = (116, 106, 88, 255)
PAPER_TOP = (255, 253, 246, 255)
PAPER_BOT = (226, 219, 201, 255)
PAGE_TOP = (252, 250, 241, 255)
PAGE_BOT = (219, 211, 192, 255)
FOLD = (240, 234, 216, 255)
FOLDER_TOP = (246, 209, 124, 255)
FOLDER_BOT = (205, 156, 62, 255)
FOLDER_BACK_TOP = (250, 226, 168, 255)
FOLDER_BACK_BOT = (225, 185, 100, 255)
GREEN = (94, 197, 106, 255)
GREEN_BOT = (42, 138, 60, 255)
GREEN_LINE = (24, 108, 46, 255)
BLUE = (128, 184, 241, 255)
BLUE_BOT = (52, 108, 180, 255)
BLUE_LINE = (30, 76, 136, 255)
GOLD = (247, 207, 90, 255)
GOLD_BOT = (194, 140, 26, 255)
GRAY = (208, 203, 190, 255)
GRAY_BOT = (144, 139, 126, 255)
WHITE = (255, 255, 255, 255)


def p(v):
    return int(round(v * S))


def box(*v):
    return [p(v[0]), p(v[1]), p(v[2]), p(v[3])]


def points(pts):
    return [(p(x), p(y)) for x, y in pts]


def gradient(top, bottom):
    """Vertical gradient image the size of the supersampled canvas."""
    img = Image.new("RGB", (W, H))
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / max(1, H - 1)
        c = tuple(int(round(top[i] + (bottom[i] - top[i]) * t)) for i in range(3))
        d.line([(0, y), (W, y)], fill=c)
    return img


def mask_rr(b, radius):
    m = Image.new("L", (W, H), 0)
    ImageDraw.Draw(m).rounded_rectangle(box(*b), radius=p(radius), fill=255)
    return m


def mask_poly(pts):
    m = Image.new("L", (W, H), 0)
    ImageDraw.Draw(m).polygon(points(pts), fill=255)
    return m


def mask_circle(cx, cy, r):
    return mask_poly([(cx + r * math.cos(a), cy + r * math.sin(a))
                      for a in [i * math.pi / 24 for i in range(48)]])


def mask_sub(a, b):
    """a minus b (a mask minus another mask)."""
    from PIL import ImageChops
    return ImageChops.subtract(a, b)


def fill(img, mask, top, bottom):
    img.paste(gradient(top, bottom), (0, 0), mask)


def stroke(d, pts, color, width=1.0, closed=False):
    q = points(pts)
    if closed:
        q = q + [q[0]]
    d.line(q, fill=color, width=max(1, p(width)), joint="curve")


def outline_rr(d, b, radius, color, width=1.0):
    d.rounded_rectangle(box(*b), radius=p(radius), outline=color,
                        width=max(1, p(width)))


def outline_circle(d, cx, cy, r, color, width=1.0):
    d.ellipse(box(cx - r, cy - r, cx + r, cy + r), outline=color,
              width=max(1, p(width)))


# --- reusable parts ---------------------------------------------------------

def page(d, b, fold=3.0, top=PAGE_TOP, bot=PAGE_BOT, lines=True,
         line_color=(198, 190, 172, 255)):
    """A sheet of paper with a folded top-right corner."""
    x0, y0, x1, y1 = b
    body = [(x0, y0), (x1 - fold, y0), (x1, y0 + fold), (x1, y1), (x0, y1)]
    fill(d._image, mask_poly(body), top, bot)
    stroke(d, body, INK, 1.0, closed=True)
    fold_pts = [(x1 - fold, y0), (x1 - fold, y0 + fold), (x1, y0 + fold)]
    fill(d._image, mask_poly(fold_pts), FOLD, (224, 217, 199, 255))
    stroke(d, fold_pts, INK_SOFT, 0.8, closed=True)
    if lines:
        for i, y in enumerate((y0 + 5.2, y0 + 7.4, y0 + 9.6)):
            stroke(d, [(x0 + 1.4, y), (x1 - 1.6 - 0.8 * i, y)], line_color, 0.9)


def badge_check(d, cx, cy, r, disc=GREEN, disc_bot=GREEN_BOT, mark=WHITE):
    fill(d._image, mask_circle(cx, cy, r), disc, disc_bot)
    outline_circle(d, cx, cy, r, INK, 0.9)
    stroke(d, [(cx - r * 0.48, cy + 0.1), (cx - r * 0.12, cy + r * 0.46),
               (cx + r * 0.52, cy - r * 0.42)], mark, 1.35)


def arrow(d, cx, y_from, y_to, shaft_w, head_w, head_h, up=False,
          top=BLUE, bot=BLUE_BOT):
    """Filled, outlined block arrow; the head tip is at y_to."""
    s = -1 if up else 1
    hx = head_h * s
    body = [(cx - shaft_w / 2, y_from), (cx + shaft_w / 2, y_from),
            (cx + shaft_w / 2, y_to - hx), (cx + head_w / 2, y_to - hx),
            (cx, y_to), (cx - head_w / 2, y_to - hx),
            (cx - shaft_w / 2, y_to - hx)]
    fill(d._image, mask_poly(body), top, bot)
    stroke(d, body, BLUE_LINE if top is BLUE else INK, 1.0, closed=True)


def tray(d, b, top=GRAY, bot=GRAY_BOT):
    fill(d._image, mask_rr(b, 0.9), top, bot)
    outline_rr(d, b, 0.9, INK, 0.9)


def folder(d, b, top=FOLDER_TOP, bot=FOLDER_BOT, tab=0.32):
    x0, y0, x1, y1 = b
    tabw = (x1 - x0) * tab
    shape = [(x0, y0 + 1.1), (x0 + tabw, y0 + 1.1), (x0 + tabw + 1.1, y0),
             (x1, y0), (x1, y1), (x0, y1)]
    fill(d._image, mask_poly(shape), top, bot)
    stroke(d, shape, INK, 1.0, closed=True)
    stroke(d, [(x0 + 1.1, y0 + 2.6), (x1 - 1.1, y0 + 2.6)],
           (255, 255, 255, 90), 0.7)


def gear(d, cx, cy, r_out, r_in, teeth=8, top=GRAY, bot=GRAY_BOT):
    m = mask_circle(cx, cy, r_out)
    for i in range(teeth):
        a = 2 * math.pi * i / teeth
        tw, th = r_out * 0.62, r_out * 0.30
        pts = [(cx + (tw / 2) * math.cos(a) - (th / 2) * math.sin(a),
                cy + (tw / 2) * math.sin(a) + (th / 2) * math.cos(a)),
               (cx + (tw / 2) * math.cos(a) + (th / 2) * math.sin(a),
                cy + (tw / 2) * math.sin(a) - (th / 2) * math.cos(a)),
               (cx + (tw / 2 + th) * math.cos(a) + (th / 2) * math.sin(a),
                cy + (tw / 2 + th) * math.sin(a) - (th / 2) * math.cos(a)),
               (cx + (tw / 2 + th) * math.cos(a) - (th / 2) * math.sin(a),
                cy + (tw / 2 + th) * math.sin(a) + (th / 2) * math.cos(a))]
        m = Image.fromarray(
            __import__("numpy").maximum(
                __import__("numpy").array(m),
                __import__("numpy").array(mask_poly(pts))))
    body = mask_sub(m, mask_circle(cx, cy, r_in))
    fill(d._image, body, top, bot)
    # outline: trace outer contour via a slightly larger mask minus the rest
    out = mask_sub(mask_circle(cx, cy, r_out + 1.0), mask_sub(m, mask_circle(cx, cy, r_in)))
    img = d._image
    img.paste(INK, (0, 0), out)
    outline_circle(d, cx, cy, r_in, INK, 0.9, )
    fill(d._image, mask_circle(cx, cy, r_in - 0.7), (246, 243, 234, 255),
         (214, 209, 196, 255))


# --- icons ------------------------------------------------------------------

def arc_arrow(d, a_start, a_end, color, width=2.1, head=3.2, head_w=4.4,
              cx=8.0, cy=8.0, r=4.8):
    """An arc with an arrow head at its end (angles in PIL screen convention)."""
    d.arc(box(cx - r, cy - r, cx + r, cy + r), a_start, a_end, fill=color,
          width=p(width))
    a = math.radians(a_end)
    px, py = cx + r * math.cos(a), cy + r * math.sin(a)
    # direction of increasing angle (clockwise on screen)
    dx, dy = -math.sin(a), math.cos(a)
    nx, ny = -dy, dx
    tip = (px + dx * head, py + dy * head)
    b1 = (px + nx * head_w / 2, py + ny * head_w / 2)
    b2 = (px - nx * head_w / 2, py - ny * head_w / 2)
    fill(d._image, mask_poly([tip, b1, b2]), color, color)
    stroke(d, [tip, b1, b2], color, 0.6, closed=True)


def icon_dump(d):
    page(d, (1.4, 2.0, 8.6, 12.8), fold=2.6)
    arrow(d, 12.3, 2.6, 15.0, shaft_w=2.6, head_w=6.0, head_h=3.4,
          top=GREEN, bot=GREEN_BOT)


def icon_dumpext(d):
    page(d, (1.2, 1.2, 7.6, 8.6), fold=2.2, lines=False)
    page(d, (4.2, 3.4, 10.6, 11.8), fold=2.4, lines=True)
    arrow(d, 13.0, 5.6, 14.9, shaft_w=2.4, head_w=5.2, head_h=2.9,
          top=GREEN, bot=GREEN_BOT)


def icon_init(d):
    folder(d, (1.4, 5.4, 12.4, 14.2), top=FOLDER_BOT, bot=(176, 130, 44, 255))
    folder(d, (1.4, 4.8, 12.4, 13.4))
    fill(d._image, mask_circle(12.4, 5.4, 3.4), GREEN, GREEN_BOT)
    outline_circle(d, 12.4, 5.4, 3.4, INK, 0.9)
    stroke(d, [(11.0, 5.4), (13.8, 5.4)], WHITE, 1.4)
    stroke(d, [(12.4, 4.0), (12.4, 6.8)], WHITE, 1.4)


def icon_clone(d):
    # two repository cards side by side: the familiar copy symbol
    b1 = mask_rr(box(1.6, 3.4, 9.6, 12.6), 1.2)
    fill(d._image, b1, FOLDER_BACK_TOP, FOLDER_BACK_BOT)
    outline_rr(d, (1.6, 3.4, 9.6, 12.6), 1.2, INK, 0.9)
    b2 = mask_rr(box(6.4, 5.4, 14.4, 14.4), 1.2)
    fill(d._image, b2, PAGE_TOP, PAGE_BOT)
    outline_rr(d, (6.4, 5.4, 14.4, 14.4), 1.2, INK, 0.9)
    for y in (8.2, 10.2, 12.2):
        stroke(d, [(7.8, y), (12.8, y)], (198, 190, 172, 255), 0.8)


def icon_commit(d):
    page(d, (2.2, 2.0, 12.2, 12.6), fold=3.0)
    badge_check(d, 11.6, 11.6, 3.4)


def icon_push(d):
    tray(d, (2.0, 12.0, 14.0, 14.4))
    arrow(d, 8.0, 11.4, 1.6, shaft_w=2.6, head_w=6.4, head_h=3.6, up=True)


def icon_pull(d):
    tray(d, (2.0, 12.0, 14.0, 14.4))
    arrow(d, 8.0, 1.6, 11.4, shaft_w=2.6, head_w=6.4, head_h=3.6)


def icon_fetch(d):
    # two arrows chasing each other: the usual "fetch/refresh" ring
    arc_arrow(d, 205, 320, BLUE_LINE, width=2.3, head=3.3, head_w=4.8)
    arc_arrow(d, 25, 140, GREEN_LINE, width=2.3, head=3.3, head_w=4.8)


def icon_branches(d):
    stroke(d, [(5.0, 13.4), (5.0, 3.0)], INK, 1.2)
    stroke(d, [(5.0, 8.2), (7.4, 7.2), (9.2, 5.6), (11.0, 5.0)], INK, 1.2)
    for (cx, cy, top, bot) in ((5.0, 12.2, GREEN, GREEN_BOT),
                               (5.0, 3.0, BLUE, BLUE_BOT),
                               (11.0, 5.0, GOLD, GOLD_BOT)):
        fill(d._image, mask_circle(cx, cy, 1.9), top, bot)
        outline_circle(d, cx, cy, 1.9, INK, 0.8)


def icon_stash(d):
    # archive box with an arrow going into it
    fill(d._image, mask_rr(box(2.0, 6.4, 14.0, 14.2), 1.0), GOLD, GOLD_BOT)
    outline_rr(d, (2.0, 6.4, 14.0, 14.2), 1.0, INK, 0.9)
    stroke(d, [(2.6, 8.4), (13.4, 8.4)], (255, 255, 255, 100), 0.7)
    fill(d._image, mask_rr(box(1.4, 5.2, 14.6, 7.2), 0.7),
         FOLDER_BACK_TOP, FOLDER_BACK_BOT)
    outline_rr(d, (1.4, 5.2, 14.6, 7.2), 0.7, INK, 0.9)
    stroke(d, [(6.2, 6.2), (9.8, 6.2)], INK_SOFT, 0.7)
    arrow(d, 8.0, 0.6, 5.2, shaft_w=2.2, head_w=5.2, head_h=2.6,
          top=GREEN, bot=GREEN_BOT)


def icon_tags(d):
    shape = [(2.4, 3.6), (10.2, 3.6), (14.0, 8.0), (10.2, 12.4), (2.4, 12.4)]
    fill(d._image, mask_poly(shape), GOLD, GOLD_BOT)
    stroke(d, shape, INK, 1.0, closed=True)
    fill(d._image, mask_circle(5.6, 8.0, 1.35), (252, 250, 242, 255),
         (226, 220, 205, 255))
    outline_circle(d, 5.6, 8.0, 1.35, INK, 0.8)
    stroke(d, [(3.2, 5.2), (3.2, 10.8)], (255, 255, 255, 110), 0.8)


def icon_status(d):
    # clipboard with a check mark: "working copy is fine"
    fill(d._image, mask_rr(box(2.2, 2.6, 13.8, 14.4), 1.0), PAGE_TOP, PAGE_BOT)
    outline_rr(d, (2.2, 2.6, 13.8, 14.4), 1.0, INK, 0.9)
    fill(d._image, mask_rr(box(2.2, 12.6, 13.8, 14.4), 0.9), (226, 219, 201, 255),
         (206, 198, 178, 255))
    fill(d._image, mask_rr(box(5.6, 1.2, 10.4, 4.0), 0.9), GRAY, GRAY_BOT)
    outline_rr(d, (5.6, 1.2, 10.4, 4.0), 0.9, INK, 0.8)
    stroke(d, [(5.0, 8.6), (7.2, 10.9), (11.6, 6.2)], GREEN_LINE, 1.7)


def icon_log(d):
    # clock face: "history"
    fill(d._image, mask_circle(8.0, 8.2, 6.2), (250, 247, 238, 255),
         (226, 220, 205, 255))
    outline_circle(d, 8.0, 8.2, 6.2, GOLD_BOT, 1.1)
    outline_circle(d, 8.0, 8.2, 5.3, (206, 170, 66, 255), 0.5)
    for a in range(0, 360, 45):
        x = 8.0 + 4.3 * math.cos(math.radians(a))
        y = 8.2 + 4.3 * math.sin(math.radians(a))
        fill(d._image, mask_circle(x, y, 0.42), INK, INK)
    stroke(d, [(8.0, 8.2), (8.0, 4.9)], INK, 1.2)
    stroke(d, [(8.0, 8.2), (10.6, 9.4)], INK, 1.2)
    fill(d._image, mask_circle(8.0, 8.2, 0.8), GOLD, GOLD_BOT)
    outline_circle(d, 8.0, 8.2, 0.8, INK, 0.7)


def icon_settings(d):
    gear(d, 8.0, 8.2, 5.6, 2.3, teeth=8)


def icon_gitbar(d):
    # three connected commit nodes - the GitBar mark
    stroke(d, [(5.0, 13.0), (5.0, 4.2)], INK, 1.3)
    stroke(d, [(5.0, 8.4), (8.4, 7.2), (11.6, 5.4)], INK, 1.3)
    fill(d._image, mask_circle(5.0, 12.0, 2.1), GREEN, GREEN_BOT)
    fill(d._image, mask_circle(5.0, 4.0, 2.1), BLUE, BLUE_BOT)
    fill(d._image, mask_circle(11.8, 5.0, 2.1), GOLD, GOLD_BOT)
    for (cx, cy) in ((5.0, 12.0), (5.0, 4.0), (11.8, 5.0)):
        outline_circle(d, cx, cy, 2.1, INK, 0.9)


ICONS = {
    "dump": icon_dump,
    "dumpext": icon_dumpext,
    "init": icon_init,
    "clone": icon_clone,
    "commit": icon_commit,
    "push": icon_push,
    "pull": icon_pull,
    "fetch": icon_fetch,
    "branches": icon_branches,
    "stash": icon_stash,
    "tags": icon_tags,
    "status": icon_status,
    "log": icon_log,
    "settings": icon_settings,
    "gitbar": icon_gitbar,
}


def render(name):
    canvas = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(canvas)
    d._image = canvas  # used by the helpers for gradient pasting
    ICONS[name](d)
    return canvas.resize((SIZE, SIZE), Image.LANCZOS)


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in ICONS:
        im = render(name)
        path = os.path.join(OUT, name + ".png")
        im.save(path)
        print(f"wrote {path}")
    print(f"{len(ICONS)} icons written to {OUT}")


if __name__ == "__main__":
    main()
