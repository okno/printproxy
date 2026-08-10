#!/usr/bin/env python3
"""Generate a representative four-artifact PrintProxy receipt sample."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from printproxy_core import readable_file  # noqa: E402
from receipt_renderer import render_receipt_artifacts  # noqa: E402


def raster_command() -> bytes:
    """Build a 384-dot ESC/POS GS v 0 image resembling the photographed header."""

    from PIL import Image, ImageDraw, ImageFont

    width, height = 576, 120
    image = Image.new("1", (width, height), 1)
    draw = ImageDraw.Draw(image)
    draw.rectangle((2, 2, width - 3, height - 3), outline=0, width=3)
    font = None
    for candidate in (
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "DejaVuSans.ttf",
    ):
        try:
            font = ImageFont.truetype(candidate, 58)
            break
        except OSError:
            pass
    if font is None:
        font = ImageFont.load_default()
    label = "Tavolo: 25-B"
    bounds = draw.textbbox((0, 0), label, font=font)
    text_width = bounds[2] - bounds[0]
    text_height = bounds[3] - bounds[1]
    draw.text(
        ((width - text_width) // 2, (height - text_height) // 2 - bounds[1]),
        label,
        fill=0,
        font=font,
    )
    width_bytes = (width + 7) // 8
    payload = bytearray(width_bytes * height)
    for y in range(height):
        for x in range(width):
            if image.getpixel((x, y)) == 0:
                payload[y * width_bytes + x // 8] |= 0x80 >> (x % 8)
    header = bytes(
        (
            0x1D,
            0x76,
            0x30,
            0,
            width_bytes & 0xFF,
            width_bytes >> 8,
            height & 0xFF,
            height >> 8,
        )
    )
    return header + bytes(payload)


def sample_raw() -> bytes:
    return (
        b"\x1b@\x1bt\x13"
        b"Operatore: 10/08/26  23:45\n\n"
        + raster_command()
        + b"\n\x1bE\x01\x1d!\x11Portata: 1\n"
        b"\x1bE\x00\x1d!\x00--------------------------\n"
        b"\x1d!\x00\x1bE\x00"
        b"1x Acqua friz\n   zante picc\n   ola\n\n"
        b"\x1ba\x01\x1d!\x10\x1bE\x01Coperti: 1\n"
        b"\x1dV\x00\x1bp\x00\x19\xfa\x10\x04\x01"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    arguments = parser.parse_args()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    stem = "2026-08-10T23-45-00.000000Z_sample-receipt"
    raw_path = arguments.output_dir / f"{stem}.raw"
    technical_path = arguments.output_dir / f"{stem}.txt"
    clean_path = arguments.output_dir / f"{stem}.PULITO.txt"
    pdf_path = arguments.output_dir / f"{stem}.pdf"
    metadata_path = arguments.output_dir / f"{stem}.json"
    payload = sample_raw()
    raw_path.write_bytes(payload)
    readable_file(raw_path, technical_path, "cp858", max_bytes=1024 * 1024)
    result = render_receipt_artifacts(
        payload,
        clean_text_path=clean_path,
        pdf_path=pdf_path,
        default_codepage="cp858",
        pdf_width_mm=80,
        best_effort=False,
    )
    metadata = {
        "sample": True,
        "source": "synthetic fixture reconstructed from the supplied receipt transcript/photo",
        "raw_file": raw_path.name,
        "technical_txt_file": technical_path.name,
        "clean_txt_file": clean_path.name,
        "pdf_file": pdf_path.name,
        "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "clean_sha256": hashlib.sha256(clean_path.read_bytes()).hexdigest(),
        "pdf_sha256": hashlib.sha256(pdf_path.read_bytes()).hexdigest(),
        "pdf_width_mm": result.pdf.width_mm if result.pdf else None,
        "pdf_height_mm": result.pdf.height_mm if result.pdf else None,
    }
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for path in (raw_path, technical_path, clean_path, pdf_path, metadata_path):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
