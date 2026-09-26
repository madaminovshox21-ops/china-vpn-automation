"""SentryScan wordmark (matn logo) generatori.

Chiqishlar (assets/):
  wordmark-avatar-mono.png   512x512  monospace, ikki qatorli (Telegram avatar)
  wordmark-avatar-sans.png   512x512  sans, ikki qatorli
  wordmark-banner.png       1200x360  keng (landing/docs/social)
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"

NAVY1 = (11, 26, 48)
NAVY2 = (18, 56, 110)
WHITE = (240, 246, 255)
ACCENT = (59, 160, 255)     # ko'k urg'u
DIM = (120, 140, 170)


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _vgrad(w, h, c1, c2):
    img = Image.new("RGB", (w, h), c1)
    px = img.load()
    for y in range(h):
        col = _lerp(c1, c2, y / (h - 1))
        for x in range(w):
            px[x, y] = col
    return img


def _text_w(draw, text, font):
    b = draw.textbbox((0, 0), text, font=font)
    return b[2] - b[0], b[3] - b[1], b[1]


def build_avatar(font_path: str, tag: str, out_dir: str) -> str:
    SS = 2
    SZ = 512
    S = SZ * SS
    base = _vgrad(S, S, NAVY1, NAVY2).convert("RGBA")
    # doira niqob
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, S - 1, S - 1), fill=255)
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img.paste(base, (0, 0), mask)
    d = ImageDraw.Draw(img)

    f_big = ImageFont.truetype(font_path, int(S * 0.20))
    # SENTRY (oq) yuqorida
    w1, h1, off1 = _text_w(d, "SENTRY", f_big)
    w2, h2, off2 = _text_w(d, "SCAN", f_big)
    gap = int(S * 0.02)
    total_h = h1 + gap + h2
    y0 = (S - total_h) / 2 - S * 0.04
    d.text(((S - w1) / 2, y0 - off1), "SENTRY", font=f_big, fill=WHITE)
    d.text(((S - w2) / 2, y0 + h1 + gap - off2), "SCAN", font=f_big, fill=ACCENT)

    # skan chizig'i + nuqta (SCAN ostida)
    ly = y0 + h1 + gap + h2 + S * 0.05
    lx1, lx2 = S * 0.30, S * 0.70
    d.line((lx1, ly, lx2, ly), fill=ACCENT, width=int(S * 0.012))
    d.ellipse((lx2 - S * 0.012, ly - S * 0.012, lx2 + S * 0.012, ly + S * 0.012), fill=WHITE)

    out = img.resize((SZ, SZ), Image.LANCZOS)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"wordmark-avatar-{tag}.png")
    out.save(path)
    return path


def build_banner(out_dir: str) -> str:
    SS = 2
    W, H = 1200, 360
    S = SS
    img = _vgrad(W * S, H * S, NAVY1, NAVY2).convert("RGBA")
    d = ImageDraw.Draw(img)
    cx, cy = W * S / 2, H * S / 2

    # kichik skan ikonkasi (lupa doira + nuqta) chapda
    r = H * S * 0.18
    ix, iy = W * S * 0.20, cy
    d.ellipse((ix - r, iy - r, ix + r, iy + r), outline=ACCENT, width=int(H * S * 0.03))
    d.line((ix + r * 0.7, iy + r * 0.7, ix + r * 1.5, iy + r * 1.5),
           fill=ACCENT, width=int(H * S * 0.035))
    d.line((ix - r * 0.5, iy, ix + r * 0.5, iy), fill=ACCENT, width=int(H * S * 0.02))

    # wordmark: Sentry (oq) + Scan (urg'u)
    f = ImageFont.truetype(SANS, int(H * S * 0.34))
    tx = ix + r * 1.9
    w_s, h_s, off_s = _text_w(d, "Sentry", f)
    ty = cy - h_s / 2 - off_s
    d.text((tx, ty), "Sentry", font=f, fill=WHITE)
    d.text((tx + w_s, ty), "Scan", font=f, fill=ACCENT)

    # tagline
    f2 = ImageFont.truetype(SANS, int(H * S * 0.10))
    d.text((tx + 2, ty + h_s + H * S * 0.06),
           "Security scanning + cyber toolkit", font=f2, fill=DIM)

    out = img.resize((W, H), Image.LANCZOS)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "wordmark-banner.png")
    out.save(path)
    return path


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outd = os.path.join(root, "assets")
    print("Yaratildi:", build_avatar(MONO, "mono", outd))
    print("Yaratildi:", build_avatar(SANS, "sans", outd))
    print("Yaratildi:", build_banner(outd))
