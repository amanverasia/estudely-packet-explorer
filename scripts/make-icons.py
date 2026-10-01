# Copyright (C) 2026 Estudely and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# Draws the app icons for the web app manifest (public/icons/) from the same
# shapes as public/favicon.svg: four white bars on a teal tile. Run once and
# commit the PNGs; the build does not need Python.
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / 'public' / 'icons'
TEAL = (0x0A, 0x66, 0x70, 255)
WHITE = (255, 255, 255, 255)
# favicon.svg bars on its 32-unit grid: (x, y, width, height)
BARS = [(6, 18, 3, 8), (11, 12, 3, 14), (16, 15, 3, 11), (21, 7, 3, 19)]


def draw(size: int, maskable: bool) -> Image.Image:
    # Supersample, then downscale for smooth edges.
    s = size * 4
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if maskable:
        # Full-bleed background; the bars sit inside the 80% safe zone.
        d.rectangle((0, 0, s, s), fill=TEAL)
        scale, off = s * 0.6 / 32, s * 0.2
    else:
        d.rounded_rectangle((0, 0, s - 1, s - 1), radius=s * 7 / 32, fill=TEAL)
        scale, off = s / 32, 0
    for x, y, w, h in BARS:
        d.rounded_rectangle((off + x * scale, off + y * scale, off + (x + w) * scale, off + (y + h) * scale), radius=scale, fill=WHITE)
    return img.resize((size, size), Image.LANCZOS)


OUT.mkdir(parents=True, exist_ok=True)
draw(192, False).save(OUT / 'icon-192.png', optimize=True)
draw(512, False).save(OUT / 'icon-512.png', optimize=True)
draw(512, True).save(OUT / 'icon-maskable-512.png', optimize=True)
draw(180, True).convert('RGB').save(OUT / 'apple-touch-icon.png', optimize=True)
print(f'icons written to {OUT}')
