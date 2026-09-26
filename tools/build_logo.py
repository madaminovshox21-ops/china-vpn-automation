"""SentryScan logo generatori (PIL).

512x512 PNG, doira ichida yaxshi ko'rinadigan (Telegram avatar) dizayn:
qalqon (himoya) + lupa/skan (tekshiruv). Bir necha rang varianti.

Foydalanish:
    python tools/build_logo.py
Chiqish: assets/logo-<variant>.png
"""
from __future__ import annotations

import math
import os

from PIL import Image, ImageDraw

SS = 2          # supersampling
SZ = 512
S = SZ * SS

VARIANTS = {
    "blue":  ((11, 31, 58), (20, 90, 160)),    # navy -> blue
    "teal":  ((6, 30, 34), (13, 148, 136)),    # dark -> teal
    "violet":((26, 16, 48), (99, 60, 190)),    # dark -> violet
}


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _gradient_circle(c1, c2) -> Image.Image:
    grad = Image.new("RGB", (S, S), c1)
    px = grad.load()
    for y in range(S):
        t = y / (S - 1)
        col = _lerp(c1, c2, t)
        for x in range(S):
            px[x, y] = col
    # doira niqob
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, S - 1, S - 1), fill=255)
    out = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    out.paste(grad, (0, 0), mask)
    return out


def _shield_points(cx, cy, w, h):
    """Yumaloq yelkali qalqon konturi nuqtalari."""
    pts = []
    top = cy - h / 2
    bot = cy + h / 2
    left = cx - w / 2
    right = cx + w / 2
    # yuqori chap -> yuqori o'ng
    pts += [(left, top + h * 0.06), (cx, top), (right, top + h * 0.06)]
    # o'ng yon
    pts += [(right, cy - h * 0.05)]
    # pastga uchburchak uchi
    pts += [(cx + w * 0.30, bot - h * 0.10), (cx, bot), (cx - w * 0.30, bot - h * 0.10)]
    pts += [(left, cy - h * 0.05)]
    return pts


def build(variant: str, out_dir: str) -> str:
    c1, c2 = VARIANTS[variant]
    img = _gradient_circle(c1, c2)
    d = ImageDraw.Draw(img)
    cx = cy = S / 2

    # Qalqon (oq, yarim shaffof to'ldirish + oq kontur)
    sw, sh = S * 0.46, S * 0.54
    pts = _shield_points(cx, cy - S * 0.02, sw, sh)
    d.polygon(pts, fill=(255, 255, 255, 235))
    d.line(pts + [pts[0]], fill=(255, 255, 255, 255), width=int(S * 0.010), joint="curve")

    # Ichki aksent rangi (gradient o'rtasi)
    accent = _lerp(c1, c2, 0.55)

    # Lupa (skan) — qalqon ichida
    mr = S * 0.11                      # linza radiusi
    mcx, mcy = cx - S * 0.02, cy - S * 0.03
    d.ellipse((mcx - mr, mcy - mr, mcx + mr, mcy + mr),
              outline=accent, width=int(S * 0.028))
    # dasta
    hx, hy = mcx + mr * 0.72, mcy + mr * 0.72
    ex, ey = hx + S * 0.085, hy + S * 0.085
    d.line((hx, hy, ex, ey), fill=accent, width=int(S * 0.032))

    # skan chizig'i (linza ichida)
    d.line((mcx - mr * 0.55, mcy, mcx + mr * 0.55, mcy),
           fill=accent, width=int(S * 0.016))

    # pastki kichik "tasdiq" nuqtasi (checkmark)
    ck = S * 0.045
    bx, by = cx, cy + S * 0.135
    d.line((bx - ck, by, bx - ck * 0.2, by + ck), fill=accent, width=int(S * 0.020))
    d.line((bx - ck * 0.2, by + ck, bx + ck * 1.2, by - ck * 0.9),
           fill=accent, width=int(S * 0.020))

    out = img.resize((SZ, SZ), Image.LANCZOS)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"logo-{variant}.png")
    out.save(path)
    return path


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outd = os.path.join(root, "assets")
    for v in VARIANTS:
        print("Yaratildi:", build(v, outd))
