"""Bounded ESC/POS receipt parser and human/PDF renderers.

The functions in this module are sidecar helpers: callers must archive and forward
the authoritative RAW bytes independently.  Parsing or PDF failures are reported
without changing the input and, by default, without raising into the print path.
"""

from __future__ import annotations

import binascii
import contextlib
import io
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import unicodedata
import zlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO, Callable, Literal, TypeAlias


Alignment: TypeAlias = Literal["left", "center", "right"]


@dataclass(frozen=True, slots=True)
class ParseLimits:
    """Resource limits for untrusted printer data."""

    max_input_bytes: int = 16 * 1024 * 1024
    max_nodes: int = 100_000
    max_text_chars: int = 4_000_000
    max_image_pixels: int = 8_000_000
    max_image_payload_bytes: int = 8 * 1024 * 1024
    max_warnings: int = 64

    def __post_init__(self) -> None:
        for name in (
            "max_input_bytes",
            "max_nodes",
            "max_text_chars",
            "max_image_pixels",
            "max_image_payload_bytes",
            "max_warnings",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class TextStyle:
    bold: bool = False
    underline: bool = False
    width: int = 1
    height: int = 1
    alignment: Alignment = "left"
    font: Literal["A", "B"] = "A"
    line_spacing_dots: int | None = None
    char_spacing_dots: int = 0


class ReceiptNode:
    """Marker base class for receipt document nodes."""


class GraphicBlock(ReceiptNode):
    """Marker for visual nodes whose source pixels/commands remain authoritative."""


@dataclass(frozen=True, slots=True)
class TextBlock(ReceiptNode):
    text: str
    style: TextStyle


@dataclass(frozen=True, slots=True)
class SeparatorBlock(ReceiptNode):
    """A textual horizontal separator represented semantically and losslessly."""

    pattern: str
    style: TextStyle


@dataclass(frozen=True, slots=True)
class LineBreak(ReceiptNode):
    pass


@dataclass(frozen=True, slots=True)
class FeedBlock(ReceiptNode):
    lines: int = 0
    dots: int = 0


@dataclass(frozen=True, slots=True)
class ImageBlock(GraphicBlock):
    """One-bit image, row-major and MSB first (one means black)."""

    width: int
    height: int
    packed_bits: bytes
    alignment: Alignment
    source: Literal["ESC *", "GS v 0"]
    mode: int
    dpi_x: int
    dpi_y: int
    scale_x: int = 1
    scale_y: int = 1
    complete: bool = True
    strip_count: int = 1
    strip_feed_dots: tuple[int, ...] = ()

    @property
    def row_stride(self) -> int:
        return (self.width + 7) // 8

    def pixel_is_black(self, x: int, y: int) -> bool:
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise IndexError("pixel outside image")
        byte = self.packed_bits[y * self.row_stride + (x // 8)]
        return bool(byte & (0x80 >> (x % 8)))


@dataclass(frozen=True, slots=True)
class OcrTextResult:
    """Bounded OCR result expressed in source-bitmap coordinates."""

    text: str
    confidence: float
    bounding_box: tuple[int, int, int, int] | None = None


@dataclass(frozen=True, slots=True)
class RasterTextBlock(ReceiptNode):
    """Raster whose semantic text was recovered without replacing its pixels."""

    text: str
    source_bitmap: ImageBlock
    ocr_confidence: float
    bounding_box: tuple[int, int, int, int] | None
    alignment: Alignment
    bold_estimate: bool = False
    font_size_estimate: float | None = None


@dataclass(frozen=True, slots=True)
class BarcodeBlock(GraphicBlock):
    symbology: int
    data: bytes
    alignment: Alignment
    complete: bool = True


@dataclass(frozen=True, slots=True)
class QrCodeBlock(GraphicBlock):
    data: bytes
    alignment: Alignment
    complete: bool = True


@dataclass(frozen=True, slots=True)
class InitializeBlock(ReceiptNode):
    pass


@dataclass(frozen=True, slots=True)
class StateChangeBlock(ReceiptNode):
    command: str
    value: int | str | None
    raw: bytes


@dataclass(frozen=True, slots=True)
class CutBlock(ReceiptNode):
    mode: int | str
    feed: int | None = None


@dataclass(frozen=True, slots=True)
class CashDrawerBlock(ReceiptNode):
    pin: int
    on_time: int
    off_time: int


@dataclass(frozen=True, slots=True)
class RealtimeStatusBlock(ReceiptNode):
    command: int
    parameter: int


@dataclass(frozen=True, slots=True)
class UnknownCommandBlock(ReceiptNode):
    raw: bytes
    reason: str


DocumentNode: TypeAlias = (
    TextBlock
    | SeparatorBlock
    | LineBreak
    | FeedBlock
    | ImageBlock
    | RasterTextBlock
    | BarcodeBlock
    | QrCodeBlock
    | InitializeBlock
    | StateChangeBlock
    | CutBlock
    | CashDrawerBlock
    | RealtimeStatusBlock
    | UnknownCommandBlock
)


@dataclass(frozen=True, slots=True)
class ReceiptDocument:
    nodes: tuple[DocumentNode, ...]
    input_size: int
    parsed_size: int
    truncated: bool
    warnings: tuple[str, ...]
    default_codepage: str


@dataclass(frozen=True, slots=True)
class PdfRenderResult:
    success: bool
    path: Path
    error: str | None = None
    width_mm: float | None = None
    height_mm: float | None = None
    content_truncated: bool = False


@dataclass(frozen=True, slots=True)
class ReceiptArtifactsResult:
    document: ReceiptDocument
    clean_text: str
    clean_text_path: Path | None
    clean_text_error: str | None
    pdf: PdfRenderResult | None

    @property
    def success(self) -> bool:
        return self.clean_text_error is None and (self.pdf is None or self.pdf.success)


CODEPAGE_BY_ESC_T: dict[int, str] = {
    0: "cp437",
    2: "cp850",
    3: "cp860",
    4: "cp863",
    5: "cp865",
    16: "cp1252",
    17: "cp866",
    18: "cp852",
    19: "cp858",
    20: "cp864",
    21: "cp862",
    24: "cp1257",
    28: "cp775",
}


class _EscPosParser:
    def __init__(self, data: bytes, default_codepage: str, limits: ParseLimits):
        self.original_size = len(data)
        self.data = memoryview(data)[: limits.max_input_bytes]
        self.default_codepage = default_codepage
        self.encoding = default_codepage
        self.limits = limits
        self.nodes: list[DocumentNode] = []
        self.warnings: list[str] = []
        self.style = TextStyle()
        self.text = bytearray()
        self.text_chars = 0
        self.index = 0
        self.stopped = False
        self.truncated = self.original_size > len(self.data)
        self.qr_data: bytes | None = None
        self.qr_complete = True
        if self.truncated:
            self.warn(
                f"input limited to {limits.max_input_bytes} of {self.original_size} bytes"
            )

    def warn(self, message: str) -> None:
        if len(self.warnings) < self.limits.max_warnings:
            self.warnings.append(message)

    def add(self, node: DocumentNode) -> bool:
        if len(self.nodes) >= self.limits.max_nodes:
            self.warn(f"node limit reached ({self.limits.max_nodes})")
            self.truncated = True
            self.stopped = True
            return False
        self.nodes.append(node)
        return True

    def flush_text(self) -> None:
        if not self.text or self.stopped:
            self.text.clear()
            return
        try:
            decoded = bytes(self.text).decode(self.encoding, errors="replace")
        except LookupError:
            self.warn(f"unknown codepage {self.encoding!r}; using cp858")
            decoded = bytes(self.text).decode("cp858", errors="replace")
        self.text.clear()
        remaining = self.limits.max_text_chars - self.text_chars
        if remaining <= 0:
            self.warn(f"text limit reached ({self.limits.max_text_chars} characters)")
            self.truncated = True
            self.stopped = True
            return
        if len(decoded) > remaining:
            decoded = decoded[:remaining]
            self.warn(f"text limit reached ({self.limits.max_text_chars} characters)")
            self.truncated = True
            self.stopped = True
        if decoded:
            self.text_chars += len(decoded)
            self.add(TextBlock(decoded, self.style))

    def state_change(
        self, command: str, value: int | str | None, raw: bytes, **changes: object
    ) -> None:
        self.flush_text()
        if self.stopped:
            return
        self.add(StateChangeBlock(command, value, raw))
        if changes:
            self.style = replace(self.style, **changes)

    def unknown(self, raw: bytes, reason: str) -> None:
        self.flush_text()
        self.warn(reason)
        self.add(UnknownCommandBlock(raw[:32], reason))

    def require(self, size: int, command: str) -> bool:
        if self.index + size <= len(self.data):
            return True
        raw = bytes(self.data[self.index :])
        self.unknown(raw, f"truncated {command} at offset {self.index}")
        self.index = len(self.data)
        self.truncated = True
        return False

    def parse(self) -> ReceiptDocument:
        while self.index < len(self.data) and not self.stopped:
            value = self.data[self.index]
            if value == 0x1B:
                self.parse_esc()
            elif value == 0x1D:
                self.parse_gs()
            elif value == 0x10:
                self.parse_dle()
            elif value == 0x0A:
                self.flush_text()
                if not self.stopped:
                    self.add(LineBreak())
                self.index += 1
            elif value == 0x0D:
                self.flush_text()
                if not self.stopped:
                    self.add(StateChangeBlock("CARRIAGE_RETURN", None, b"\r"))
                self.index += 1
            elif value == 0x09:
                self.text.extend(b"    ")
                self.index += 1
            elif value == 0x0C:
                self.flush_text()
                if not self.stopped:
                    self.add(FeedBlock(lines=1))
                self.index += 1
            elif value < 0x20 or value == 0x7F:
                self.unknown(bytes((value,)), f"unhandled control 0x{value:02X}")
                self.index += 1
            else:
                self.text.append(value)
                self.index += 1
        self.flush_text()
        return ReceiptDocument(
            nodes=tuple(self.nodes),
            input_size=self.original_size,
            parsed_size=self.index,
            truncated=self.truncated or self.stopped,
            warnings=tuple(self.warnings),
            default_codepage=self.default_codepage,
        )

    def parse_esc(self) -> None:
        if not self.require(2, "ESC command"):
            return
        start = self.index
        command = self.data[start + 1]
        if command == 0x40:  # ESC @ initialize
            self.flush_text()
            self.add(InitializeBlock())
            self.style = TextStyle()
            self.encoding = self.default_codepage
            self.qr_data = None
            self.qr_complete = True
            self.index += 2
            return
        if command in {0x21, 0x45, 0x61, 0x2D, 0x74, 0x64, 0x4A, 0x33, 0x20, 0x4D}:
            if not self.require(3, "ESC parameter command"):
                return
            parameter = self.data[start + 2]
            raw = bytes(self.data[start : start + 3])
            if command == 0x21:  # print mode
                self.state_change(
                    "PRINT_MODE",
                    parameter,
                    raw,
                    bold=bool(parameter & 0x08),
                    height=2 if parameter & 0x10 else 1,
                    width=2 if parameter & 0x20 else 1,
                    underline=bool(parameter & 0x80),
                    font="B" if parameter & 0x01 else "A",
                )
            elif command == 0x45:
                self.state_change("BOLD", parameter, raw, bold=bool(parameter & 1))
            elif command == 0x61:
                alignment = {0: "left", 48: "left", 1: "center", 49: "center", 2: "right", 50: "right"}.get(parameter)
                if alignment is None:
                    self.state_change("ALIGN", parameter, raw)
                    self.warn(f"unsupported alignment value {parameter}")
                else:
                    self.state_change("ALIGN", parameter, raw, alignment=alignment)
            elif command == 0x2D:
                self.state_change("UNDERLINE", parameter, raw, underline=bool(parameter & 3))
            elif command == 0x74:
                self.flush_text()
                next_encoding = CODEPAGE_BY_ESC_T.get(parameter)
                if next_encoding is None:
                    self.add(StateChangeBlock("CODEPAGE", parameter, raw))
                    self.warn(f"unsupported ESC t codepage {parameter}; retaining {self.encoding}")
                else:
                    self.encoding = next_encoding
                    self.add(StateChangeBlock("CODEPAGE", next_encoding, raw))
            elif command == 0x64:
                self.flush_text()
                self.add(FeedBlock(lines=parameter))
            elif command == 0x4A:
                self.flush_text()
                self.add(FeedBlock(dots=parameter))
            elif command == 0x33:
                self.state_change("LINE_SPACING", parameter, raw, line_spacing_dots=parameter)
            elif command == 0x20:
                self.state_change("CHAR_SPACING", parameter, raw, char_spacing_dots=parameter)
            elif command == 0x4D:
                self.state_change("FONT", parameter, raw, font="B" if parameter & 1 else "A")
            self.index += 3
            return
        if command == 0x32:  # ESC 2 default line spacing
            self.state_change("DEFAULT_LINE_SPACING", None, bytes(self.data[start : start + 2]), line_spacing_dots=None)
            self.index += 2
            return
        if command == 0x70:  # cash drawer pulse
            if not self.require(5, "ESC p cash drawer"):
                return
            raw = bytes(self.data[start : start + 5])
            self.flush_text()
            self.add(CashDrawerBlock(raw[2], raw[3], raw[4]))
            self.index += 5
            return
        if command == 0x2A:  # bit image
            self.parse_esc_bit_image()
            return
        if command in {0x69, 0x6D}:  # legacy full/partial cut
            self.flush_text()
            self.add(CutBlock("ESC i" if command == 0x69 else "ESC m"))
            self.index += 2
            return
        self.unknown(bytes(self.data[start : start + 2]), f"unknown ESC command 0x{command:02X}")
        self.index += 2

    def parse_esc_bit_image(self) -> None:
        start = self.index
        if not self.require(5, "ESC * bit image header"):
            return
        mode = self.data[start + 2]
        width = self.data[start + 3] | (self.data[start + 4] << 8)
        bytes_per_column = 3 if mode in {32, 33} else 1
        height = 24 if bytes_per_column == 3 else 8
        declared = width * bytes_per_column
        payload_start = start + 5
        available = min(declared, len(self.data) - payload_start)
        complete = available == declared
        payload = bytes(self.data[payload_start : payload_start + available])
        self.flush_text()
        if mode not in {0, 1, 32, 33}:
            self.unknown(bytes(self.data[start : payload_start]), f"unsupported ESC * mode {mode}")
        elif width <= 0:
            self.unknown(bytes(self.data[start : payload_start]), "ESC * image has zero width")
        elif (
            declared > self.limits.max_image_payload_bytes
            or width * height > self.limits.max_image_pixels
        ):
            self.unknown(
                bytes(self.data[start : payload_start]),
                f"ESC * image exceeds renderer limits ({width}x{height}, {declared} bytes)",
            )
        else:
            packed = _decode_esc_star(width, height, bytes_per_column, payload)
            # ESC/POS bit-image density is defined by the selected mode.  The
            # horizontal values are 90/180 dpi (not 60/120); the latter made
            # real 24-dot double-density bands 50% too wide in the PDF.
            dpi_x = 90 if mode in {0, 32} else 180
            dpi_y = 60 if mode in {0, 1} else 180
            self.add(
                ImageBlock(
                    width=width,
                    height=height,
                    packed_bits=packed,
                    alignment=self.style.alignment,
                    source="ESC *",
                    mode=mode,
                    dpi_x=dpi_x,
                    dpi_y=dpi_y,
                    complete=complete,
                )
            )
        if not complete:
            self.warn(
                f"truncated ESC * image at offset {start}: expected {declared}, got {available} bytes"
            )
            self.truncated = True
        self.index = payload_start + available

    def parse_gs(self) -> None:
        if not self.require(2, "GS command"):
            return
        start = self.index
        command = self.data[start + 1]
        if command == 0x21:  # character size
            if not self.require(3, "GS ! character size"):
                return
            parameter = self.data[start + 2]
            width = min(8, ((parameter >> 4) & 0x07) + 1)
            height = min(8, (parameter & 0x07) + 1)
            self.state_change(
                "CHAR_SIZE",
                parameter,
                bytes(self.data[start : start + 3]),
                width=width,
                height=height,
            )
            self.index += 3
            return
        if command == 0x56:  # cut
            if not self.require(3, "GS V cut"):
                return
            mode = self.data[start + 2]
            length = 4 if mode in {65, 66, 97, 98} else 3
            if not self.require(length, "GS V cut with feed"):
                return
            self.flush_text()
            feed = self.data[start + 3] if length == 4 else None
            self.add(CutBlock(mode, feed))
            self.index += length
            return
        if command == 0x76 and start + 2 < len(self.data) and self.data[start + 2] == 0x30:
            self.parse_raster_image()
            return
        if command == 0x6B:
            self.parse_barcode()
            return
        if command == 0x28:
            self.parse_gs_parenthesized()
            return
        if command in {0x48, 0x68, 0x77, 0x66, 0x62}:
            if not self.require(3, "GS parameter command"):
                return
            names = {
                0x48: "BARCODE_HRI_POSITION",
                0x68: "BARCODE_HEIGHT",
                0x77: "BARCODE_WIDTH",
                0x66: "BARCODE_FONT",
                0x62: "SMOOTHING",
            }
            parameter = self.data[start + 2]
            self.state_change(names[command], parameter, bytes(self.data[start : start + 3]))
            self.index += 3
            return
        self.unknown(bytes(self.data[start : start + 2]), f"unknown GS command 0x{command:02X}")
        self.index += 2

    def parse_raster_image(self) -> None:
        start = self.index
        if not self.require(8, "GS v 0 raster header"):
            return
        mode = self.data[start + 3]
        width_bytes = self.data[start + 4] | (self.data[start + 5] << 8)
        height = self.data[start + 6] | (self.data[start + 7] << 8)
        width = width_bytes * 8
        declared = width_bytes * height
        payload_start = start + 8
        available = min(declared, len(self.data) - payload_start)
        complete = available == declared
        payload = bytes(self.data[payload_start : payload_start + available])
        self.flush_text()
        if mode not in {0, 1, 2, 3, 48, 49, 50, 51}:
            self.unknown(bytes(self.data[start : payload_start]), f"unsupported GS v 0 mode {mode}")
        elif width <= 0 or height <= 0:
            self.unknown(
                bytes(self.data[start : payload_start]),
                f"GS v 0 image has invalid dimensions {width}x{height}",
            )
        elif (
            declared > self.limits.max_image_payload_bytes
            or width * height > self.limits.max_image_pixels
        ):
            self.unknown(
                bytes(self.data[start : payload_start]),
                f"GS v 0 image exceeds renderer limits ({width}x{height}, {declared} bytes)",
            )
        else:
            base_mode = mode - 48 if mode >= 48 else mode
            padded = payload + b"\x00" * (declared - available)
            self.add(
                ImageBlock(
                    width=width,
                    height=height,
                    packed_bits=padded,
                    alignment=self.style.alignment,
                    source="GS v 0",
                    mode=mode,
                    dpi_x=203,
                    dpi_y=203,
                    scale_x=2 if base_mode in {1, 3} else 1,
                    scale_y=2 if base_mode in {2, 3} else 1,
                    complete=complete,
                )
            )
        if not complete:
            self.warn(
                f"truncated GS v 0 image at offset {start}: expected {declared}, got {available} bytes"
            )
            self.truncated = True
        self.index = payload_start + available

    def parse_barcode(self) -> None:
        start = self.index
        if not self.require(3, "GS k barcode header"):
            return
        mode = self.data[start + 2]
        complete = True
        if mode >= 65:
            if not self.require(4, "GS k barcode length"):
                return
            declared = self.data[start + 3]
            payload_start = start + 4
            available = min(declared, len(self.data) - payload_start)
            payload = bytes(self.data[payload_start : payload_start + available])
            complete = available == declared
            end = payload_start + available
        else:
            payload_start = start + 3
            terminator = bytes(self.data[payload_start:]).find(b"\x00")
            if terminator < 0:
                payload = bytes(self.data[payload_start:])
                end = len(self.data)
                complete = False
            else:
                payload = bytes(self.data[payload_start : payload_start + terminator])
                end = payload_start + terminator + 1
        self.flush_text()
        if len(payload) > self.limits.max_image_payload_bytes:
            self.unknown(bytes(self.data[start:payload_start]), "barcode payload exceeds renderer limit")
        else:
            self.add(BarcodeBlock(mode, payload, self.style.alignment, complete))
        if not complete:
            self.warn(f"truncated GS k barcode at offset {start}")
            self.truncated = True
        self.index = end

    def parse_gs_parenthesized(self) -> None:
        start = self.index
        if not self.require(5, "GS ( command header"):
            return
        function_group = self.data[start + 2]
        declared = self.data[start + 3] | (self.data[start + 4] << 8)
        payload_start = start + 5
        available = min(declared, len(self.data) - payload_start)
        payload = bytes(self.data[payload_start : payload_start + available])
        complete = available == declared
        raw_header = bytes(self.data[start:payload_start])
        self.flush_text()
        if function_group == 0x6B and len(payload) >= 2:  # GS ( k: 2-D symbols
            cn, fn = payload[0], payload[1]
            body = payload[2:]
            if cn == 49 and fn == 80:  # QR store data; first byte is mode
                self.qr_data = body[1:] if body else b""
                self.qr_complete = complete
                self.add(StateChangeBlock("QR_STORE", len(self.qr_data), raw_header))
            elif cn == 49 and fn == 81:  # QR print stored symbol
                if self.qr_data is None:
                    self.add(QrCodeBlock(b"", self.style.alignment, False))
                    self.warn("QR print command without preceding complete store command")
                else:
                    self.add(QrCodeBlock(self.qr_data, self.style.alignment, self.qr_complete and complete))
            else:
                self.add(StateChangeBlock(f"GS_(k_{cn}_{fn}", len(body), raw_header))
        else:
            self.add(StateChangeBlock(f"GS_({chr(function_group) if 32 <= function_group < 127 else hex(function_group)}", available, raw_header))
        if not complete:
            self.warn(
                f"truncated GS ( command at offset {start}: expected {declared}, got {available} bytes"
            )
            self.truncated = True
        self.index = payload_start + available

    def parse_dle(self) -> None:
        start = self.index
        if not self.require(2, "DLE command"):
            return
        command = self.data[start + 1]
        if command in {0x04, 0x05}:
            if not self.require(3, "DLE realtime command"):
                return
            self.flush_text()
            self.add(RealtimeStatusBlock(command, self.data[start + 2]))
            self.index += 3
            return
        self.unknown(bytes(self.data[start : start + 2]), f"unknown DLE command 0x{command:02X}")
        self.index += 2


def _decode_esc_star(
    width: int, height: int, bytes_per_column: int, payload: bytes
) -> bytes:
    stride = (width + 7) // 8
    packed = bytearray(stride * height)
    complete_columns = min(width, len(payload) // bytes_per_column)
    for x in range(complete_columns):
        for band in range(bytes_per_column):
            value = payload[x * bytes_per_column + band]
            for bit in range(8):
                y = band * 8 + bit
                if y < height and value & (0x80 >> bit):
                    packed[y * stride + (x // 8)] |= 0x80 >> (x % 8)
    return bytes(packed)


def _same_esc_star_strip(left: ImageBlock, right: ImageBlock) -> bool:
    return (
        left.source == right.source == "ESC *"
        and left.width == right.width
        and left.height == right.height
        and left.mode == right.mode
        and left.dpi_x == right.dpi_x
        and left.dpi_y == right.dpi_y
        and left.scale_x == right.scale_x
        and left.scale_y == right.scale_y
        and left.alignment == right.alignment
        and left.complete
        and right.complete
    )


def _is_strip_positioning_feed(feed: FeedBlock, strip: ImageBlock) -> bool:
    """Recognize the bounded ESC * + ESC J strip-driver pattern.

    ESC * loads a band into the current print line; it does not itself advance
    the paper.  Drivers commonly follow a 24-dot band with ESC J 24 or ESC J 48
    before emitting the next equal band.  Treating both the bitmap height and
    that positioning command as independent PDF flow consumed the distance
    twice and split a single raster into visible horizontal slices.
    """

    return (
        feed.lines == 0
        and feed.dots in {strip.height, strip.height * 2}
        and strip.source == "ESC *"
    )


def _combine_esc_star_strips(
    strips: list[ImageBlock], feeds: list[FeedBlock]
) -> ImageBlock:
    first = strips[0]
    return replace(
        first,
        height=sum(strip.height for strip in strips),
        packed_bits=b"".join(strip.packed_bits for strip in strips),
        complete=all(strip.complete for strip in strips),
        strip_count=sum(strip.strip_count for strip in strips),
        strip_feed_dots=(
            *(dot for strip in strips for dot in strip.strip_feed_dots),
            *(feed.dots for feed in feeds),
        ),
    )


def _reconstruct_esc_star_strips(
    document: ReceiptDocument, *, max_image_pixels: int
) -> ReceiptDocument:
    """Coalesce equal ESC * bands separated only by their positioning feed."""

    source = document.nodes
    rebuilt: list[DocumentNode] = []
    index = 0
    while index < len(source):
        first = source[index]
        if not isinstance(first, ImageBlock) or first.source != "ESC *":
            rebuilt.append(first)
            index += 1
            continue

        strips = [first]
        feeds: list[FeedBlock] = []
        combined_height = first.height
        cursor = index
        while cursor + 2 < len(source):
            feed = source[cursor + 1]
            candidate = source[cursor + 2]
            if not (
                isinstance(feed, FeedBlock)
                and isinstance(candidate, ImageBlock)
                and _is_strip_positioning_feed(feed, strips[-1])
                and _same_esc_star_strip(strips[-1], candidate)
            ):
                break
            prospective_height = combined_height + candidate.height
            if first.width * prospective_height > max_image_pixels:
                break
            feeds.append(feed)
            strips.append(candidate)
            combined_height = prospective_height
            cursor += 2

        if len(strips) == 1:
            rebuilt.append(first)
            index += 1
            continue
        rebuilt.append(_combine_esc_star_strips(strips, feeds))
        index = cursor + 1

    if tuple(rebuilt) == source:
        return document
    return replace(document, nodes=tuple(rebuilt))


def parse_escpos(
    data: bytes | bytearray | memoryview,
    default_codepage: str = "cp858",
    limits: ParseLimits | None = None,
) -> ReceiptDocument:
    """Parse an immutable copy of ESC/POS data into the shared document model."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    raw = bytes(data)
    active_limits = limits or ParseLimits()
    document = _EscPosParser(raw, default_codepage, active_limits).parse()
    return _reconstruct_esc_star_strips(
        document, max_image_pixels=active_limits.max_image_pixels
    )


@dataclass(slots=True)
class _CleanLine:
    text: str
    physical_cells: int
    alignment: Alignment = "left"
    placeholder: bool = False
    continuation_prefix: int | None = None


_ITEM_PREFIX = re.compile(r"^\s*(?:\d+\s*[xX]\s+|[-*]\s+)")
_SEPARATOR = re.compile(r"^\s*[-_=]{3,}\s*$")
_ITALIAN_WORD_BOUNDARY = re.compile(
    r"(?:^|\s)(?:a|ai|al|alla|alle|allo|agli|con|da|dal|dalla|dalle|dei|del|della|"
    r"delle|di|e|in|per|su)$",
    re.IGNORECASE,
)


def _clean_lines(document: ReceiptDocument) -> list[_CleanLine]:
    lines: list[_CleanLine] = []
    fragments: list[str] = []
    physical_cells = 0
    alignment: Alignment = "left"
    have_style = False
    image_sequence = False

    def finish(force: bool = False) -> None:
        nonlocal fragments, physical_cells, alignment, have_style
        if fragments or force:
            text = "".join(fragments)
            match = _ITEM_PREFIX.match(text)
            lines.append(
                _CleanLine(
                    text=text,
                    physical_cells=physical_cells,
                    alignment=alignment,
                    continuation_prefix=len(match.group(0)) if match else None,
                )
            )
        fragments = []
        physical_cells = 0
        alignment = "left"
        have_style = False

    for node in document.nodes:
        if isinstance(node, TextBlock):
            if image_sequence:
                lines.append(_CleanLine("", 0))
                image_sequence = False
            if not have_style:
                alignment = node.style.alignment
                have_style = True
            fragments.append(node.text)
            physical_cells += len(node.text.expandtabs(4)) * node.style.width
        elif isinstance(node, SeparatorBlock):
            finish()
            image_sequence = False
            lines.append(
                _CleanLine(
                    node.pattern,
                    len(node.pattern) * node.style.width,
                    node.style.alignment,
                )
            )
        elif isinstance(node, LineBreak):
            if image_sequence:
                continue
            finish(force=True)
        elif isinstance(node, FeedBlock):
            if image_sequence:
                continue
            finish()
            blanks = node.lines
            if node.dots:
                blanks += max(1, round(node.dots / 24))
            for _ in range(min(blanks, 8)):
                lines.append(_CleanLine("", 0))
        elif isinstance(node, RasterTextBlock):
            finish()
            image_sequence = False
            semantic_lines = [line.strip() for line in node.text.splitlines() if line.strip()]
            for text in semantic_lines:
                lines.append(
                    _CleanLine(
                        text,
                        len(text),
                        node.alignment,
                        placeholder=False,
                    )
                )
        elif isinstance(node, ImageBlock):
            finish()
            if not image_sequence:
                lines.append(_CleanLine("[IMMAGINE]", len("[IMMAGINE]"), "center", True))
            image_sequence = True
        elif isinstance(node, QrCodeBlock):
            finish()
            image_sequence = False
            label = "[QR CODE]"
            lines.append(_CleanLine(label, len(label), node.alignment, True))
        elif isinstance(node, BarcodeBlock):
            finish()
            image_sequence = False
            label = "[CODICE A BARRE]"
            lines.append(_CleanLine(label, len(label), node.alignment, True))
        elif isinstance(node, (CutBlock, CashDrawerBlock, RealtimeStatusBlock)):
            finish()
            image_sequence = False
    finish()
    return lines


def _unwrap_lines(lines: list[_CleanLine]) -> list[_CleanLine]:
    """Join only strongly signalled, printer-width item continuations.

    A continuation must be indented to an item prefix (for example ``"1x "``),
    start with a lower-case letter, and follow alphabetic item text.  Requiring
    the explicit item prefix keeps unrelated indented receipt lines untouched,
    while still handling printers that wrap at different active character sizes.
    """

    result: list[_CleanLine] = []
    active_prefix: int | None = None
    for line in lines:
        stripped = line.text.lstrip(" ")
        indent = len(line.text) - len(stripped)
        previous = result[-1] if result else None
        can_join = (
            previous is not None
            and active_prefix is not None
            and indent == active_prefix
            and stripped[:1].islower()
            and previous.text[-1:].isalpha()
            and not previous.placeholder
            and not _SEPARATOR.match(previous.text)
        )
        if can_join:
            separator = " " if _ITALIAN_WORD_BOUNDARY.search(previous.text) else ""
            previous.text += separator + stripped
            previous.physical_cells += len(separator) + line.physical_cells - indent
            continue
        result.append(line)
        active_prefix = line.continuation_prefix
        if not line.text.strip():
            active_prefix = None
    return result


def render_clean_text(
    document: ReceiptDocument,
    *,
    paper_columns: int = 42,
    unwrap: bool = True,
    max_output_chars: int = 1_000_000,
) -> str:
    """Render a human-readable receipt without technical ESC/POS markers."""

    if paper_columns <= 0:
        raise ValueError("paper_columns must be positive")
    if max_output_chars <= 0:
        raise ValueError("max_output_chars must be positive")
    lines = _clean_lines(document)
    if unwrap:
        lines = _unwrap_lines(lines)
    output: list[str] = []
    used = 0
    truncated = False
    for line in lines:
        text = line.text.rstrip()
        if line.alignment != "left" and text:
            occupied = min(paper_columns, line.physical_cells)
            available = max(0, paper_columns - occupied)
            padding = available // 2 if line.alignment == "center" else available
            text = " " * padding + text.lstrip(" ")
        addition = text + "\n"
        if used + len(addition) > max_output_chars:
            remaining = max_output_chars - used
            if remaining > 0:
                output.append(addition[:remaining])
            truncated = True
            break
        output.append(addition)
        used += len(addition)
    while len(output) > 1 and output[-1] == "\n":
        output.pop()
    if truncated:
        marker = "\n[CONTENUTO TRONCATO]\n"
        joined = "".join(output)
        joined = joined[: max(0, max_output_chars - len(marker))] + marker
        return joined[:max_output_chars]
    rendered = "".join(output)
    return rendered.rstrip("\n") + "\n" if rendered else ""


@dataclass(frozen=True, slots=True)
class _PdfRun:
    text: str
    style: TextStyle


@dataclass(frozen=True, slots=True)
class _PdfLine:
    runs: tuple[_PdfRun, ...]
    height: float
    width: float
    alignment: Alignment


@dataclass(frozen=True, slots=True)
class _PdfSpacer:
    height: float


@dataclass(frozen=True, slots=True)
class _PdfImage:
    image: ImageBlock
    width: float
    height: float


@dataclass(frozen=True, slots=True)
class _PdfPlaceholder:
    label: str
    detail: str
    alignment: Alignment
    width: float
    height: float


_PdfOperation: TypeAlias = _PdfLine | _PdfSpacer | _PdfImage | _PdfPlaceholder


def _safe_pdf_text(text: str) -> str:
    # Built-in ReportLab fonts use WinAnsi.  Preserve Italian accents and euro;
    # replace glyphs they cannot represent instead of letting a sidecar fail.
    return text.encode("cp1252", errors="replace").decode("cp1252")


def _pdf_character_spacing_width(style: TextStyle) -> float:
    # PDF Tz scales Tc as well as glyph displacement.  Keep layout metrics in
    # the same user-space coordinates as the emitted text object so GS ! width
    # cannot make a line wider than the splitter predicts.
    horizontal_scale = style.width / style.height
    return style.char_spacing_dots * 72 / 203 * horizontal_scale


def _run_metrics(run: _PdfRun, pdfmetrics: object, base_size: float) -> tuple[float, float]:
    font = "Courier-Bold" if run.style.bold else "Courier"
    font_size = base_size * run.style.height
    text = _safe_pdf_text(run.text)
    width = pdfmetrics.stringWidth(text, font, font_size)  # type: ignore[attr-defined]
    width *= run.style.width / run.style.height
    if len(text) > 1 and run.style.char_spacing_dots:
        width += (len(text) - 1) * _pdf_character_spacing_width(run.style)
    return width, font_size


def _split_pdf_runs(
    runs: list[_PdfRun], printable_width: float, pdfmetrics: object, base_size: float
) -> list[list[_PdfRun]]:
    if not runs:
        return [[]]
    result: list[list[_PdfRun]] = []
    current: list[_PdfRun] = []
    current_width = 0.0
    for run in runs:
        for character in run.text:
            unit = _PdfRun(character, run.style)
            char_width, _ = _run_metrics(unit, pdfmetrics, base_size)
            # ESC SP is rendered as PDF character spacing inside each
            # homogeneous text run.  A one-character metric contains no such
            # gap, so include the gap that will be introduced when this
            # character is appended to the preceding run.  Otherwise the
            # splitter can accept a line that later grows past the printable
            # width when _run_metrics() measures the merged run.
            joins_previous_run = bool(current and current[-1].style == run.style)
            inter_character_width = (
                _pdf_character_spacing_width(run.style) if joins_previous_run else 0.0
            )
            if (
                current
                and current_width + inter_character_width + char_width
                > printable_width
            ):
                result.append(current)
                current = []
                current_width = 0.0
                inter_character_width = 0.0
            if current and current[-1].style == run.style:
                current[-1] = _PdfRun(current[-1].text + character, run.style)
            else:
                current.append(unit)
            current_width += inter_character_width + char_width
    result.append(current)
    return result


def _pdf_operations(
    document: ReceiptDocument,
    printable_width: float,
    pdfmetrics: object,
    base_size: float,
) -> list[_PdfOperation]:
    operations: list[_PdfOperation] = []
    pending: list[_PdfRun] = []

    def finish(force: bool = False) -> None:
        nonlocal pending
        if not pending and not force:
            return
        for split in _split_pdf_runs(pending, printable_width, pdfmetrics, base_size):
            if split:
                widths_and_sizes = [_run_metrics(run, pdfmetrics, base_size) for run in split]
                width = sum(item[0] for item in widths_and_sizes)
                font_height = max(item[1] for item in widths_and_sizes)
                style = split[0].style
                explicit_spacing = max(
                    (run.style.line_spacing_dots or 0) * 72 / 203 for run in split
                )
                height = max(font_height * 1.25, explicit_spacing)
                operations.append(_PdfLine(tuple(split), height, width, style.alignment))
            else:
                operations.append(_PdfLine((), base_size * 1.25, 0.0, "left"))
        pending = []

    for node in document.nodes:
        if isinstance(node, TextBlock):
            pending.append(_PdfRun(node.text, node.style))
        elif isinstance(node, SeparatorBlock):
            finish()
            pending.append(_PdfRun(node.pattern, node.style))
        elif isinstance(node, LineBreak):
            finish(force=True)
        elif isinstance(node, FeedBlock):
            finish()
            gap = node.lines * base_size * 1.25 + node.dots * 72 / 203
            if gap > 0:
                operations.append(_PdfSpacer(min(gap, 200 * 72 / 25.4)))
        elif isinstance(node, RasterTextBlock):
            finish()
            image = node.source_bitmap
            width = image.width * 72 / max(1, image.dpi_x) * image.scale_x
            height = image.height * 72 / max(1, image.dpi_y) * image.scale_y
            if width > printable_width:
                ratio = printable_width / width
                width *= ratio
                height *= ratio
            operations.append(_PdfImage(image, max(width, 1), max(height, 1)))
        elif isinstance(node, ImageBlock):
            finish()
            width = node.width * 72 / max(1, node.dpi_x) * node.scale_x
            height = node.height * 72 / max(1, node.dpi_y) * node.scale_y
            if width > printable_width:
                ratio = printable_width / width
                width *= ratio
                height *= ratio
            operations.append(_PdfImage(node, max(width, 1), max(height, 1)))
        elif isinstance(node, QrCodeBlock):
            finish()
            size = min(printable_width, 22 * 72 / 25.4)
            detail = _safe_payload_detail(node.data)
            operations.append(_PdfPlaceholder("QR CODE", detail, node.alignment, size, size))
        elif isinstance(node, BarcodeBlock):
            finish()
            detail = _safe_payload_detail(node.data)
            operations.append(
                _PdfPlaceholder(
                    "CODICE A BARRE", detail, node.alignment, printable_width, 18 * 72 / 25.4
                )
            )
        elif isinstance(node, (CutBlock, CashDrawerBlock, RealtimeStatusBlock)):
            finish()
    finish()
    return operations


def _safe_payload_detail(payload: bytes, limit: int = 48) -> str:
    if not payload:
        return ""
    decoded = payload.decode("cp858", errors="replace")
    if any(ord(character) < 32 for character in decoded):
        decoded = payload.hex()
    decoded = decoded.replace("\r", " ").replace("\n", " ")
    return decoded[:limit] + ("..." if len(decoded) > limit else "")


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _bitmap_png(image: ImageBlock) -> bytes:
    stride = image.row_stride
    rows = bytearray()
    for y in range(image.height):
        # PNG grayscale depth 1 uses zero for black and one for white.  The AST
        # uses one for black, so invert each packed row.  Padding becomes white.
        row = image.packed_bits[y * stride : (y + 1) * stride]
        rows.append(0)  # PNG filter: None
        rows.extend(byte ^ 0xFF for byte in row)
    header = struct.pack(">IIBBBBB", image.width, image.height, 1, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + _png_chunk(b"IEND", b"")
    )


OcrEngine: TypeAlias = Callable[[ImageBlock], OcrTextResult | None]


def _raster_ink_metrics(
    image: ImageBlock,
) -> tuple[int, tuple[int, int, int, int] | None, int]:
    black = 0
    left = image.width
    top = image.height
    right = -1
    bottom = -1
    tall_columns = 0
    for x in range(image.width):
        column_ink = 0
        for y in range(image.height):
            if not image.pixel_is_black(x, y):
                continue
            black += 1
            column_ink += 1
            left = min(left, x)
            top = min(top, y)
            right = max(right, x)
            bottom = max(bottom, y)
        if column_ink >= image.height * 0.70:
            tall_columns += 1
    bounding_box = None if right < left else (left, top, right + 1, bottom + 1)
    return black, bounding_box, tall_columns


def _is_potential_raster_text(image: ImageBlock) -> bool:
    pixels = image.width * image.height
    if (
        not image.complete
        or image.width < 16
        or image.height < 8
        or pixels > 1_000_000
    ):
        return False
    black, bounding_box, tall_columns = _raster_ink_metrics(image)
    if bounding_box is None:
        return False
    density = black / pixels
    if not 0.002 <= density <= 0.55:
        return False
    aspect = image.width / image.height
    likely_qr = 0.75 <= aspect <= 1.33 and density >= 0.16
    likely_barcode = (
        aspect >= 1.5
        and tall_columns >= max(8, image.width // 12)
        and density >= 0.12
    )
    return not (likely_qr or likely_barcode)


def _bitmap_pgm_for_ocr(image: ImageBlock) -> tuple[bytes, int, int]:
    """Return a bounded, nearest-neighbour upscaled PGM plus scale/padding."""

    source_pixels = image.width * image.height
    scale = min(4, max(1, int(math.sqrt(4_000_000 / max(1, source_pixels)))))
    padding = 4
    output_width = (image.width + padding * 2) * scale
    rows = bytearray()
    white_row = b"\xff" * output_width
    for _ in range(padding * scale):
        rows.extend(white_row)
    side = b"\xff" * (padding * scale)
    for y in range(image.height):
        row = bytearray(side)
        for x in range(image.width):
            value = b"\x00" if image.pixel_is_black(x, y) else b"\xff"
            row.extend(value * scale)
        row.extend(side)
        for _ in range(scale):
            rows.extend(row)
    for _ in range(padding * scale):
        rows.extend(white_row)
    output_height = (image.height + padding * 2) * scale
    header = f"P5\n{output_width} {output_height}\n255\n".encode("ascii")
    return header + bytes(rows), scale, padding


def _normalize_ocr_word(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = "".join(character for character in value if character.isprintable())
    return " ".join(value.split())[:256]


def _parse_tesseract_tsv(
    payload: bytes, *, scale: int, padding: int
) -> OcrTextResult | None:
    if len(payload) > 1_000_000:
        return None
    try:
        text = payload.decode("utf-8", errors="replace")
    except UnicodeError:
        return None
    grouped: dict[tuple[int, int, int, int], list[str]] = {}
    confidences: list[tuple[float, int]] = []
    boxes: list[tuple[int, int, int, int]] = []
    for row in text.splitlines()[1:]:
        fields = row.split("\t", 11)
        if len(fields) != 12:
            continue
        try:
            level = int(fields[0])
            line_key = tuple(int(fields[index]) for index in (1, 2, 3, 4))
            left, top, width, height = (int(fields[index]) for index in (6, 7, 8, 9))
            confidence = float(fields[10])
        except (TypeError, ValueError):
            continue
        word = _normalize_ocr_word(fields[11])
        if level != 5 or not word or confidence < 0 or not math.isfinite(confidence):
            continue
        grouped.setdefault(line_key, []).append(word)
        confidences.append((min(100.0, confidence), max(1, len(word))))
        boxes.append((left, top, left + max(0, width), top + max(0, height)))
    lines = [" ".join(words).strip(" |[]{}") for words in grouped.values()]
    lines = [line for line in lines if line and any(character.isalnum() for character in line)]
    if not lines or not confidences:
        return None
    normalized = "\n".join(lines)[:2048]
    weight = sum(item[1] for item in confidences)
    confidence = sum(score * size for score, size in confidences) / max(1, weight)
    bounding_box: tuple[int, int, int, int] | None = None
    if boxes:
        raw_left = min(box[0] for box in boxes)
        raw_top = min(box[1] for box in boxes)
        raw_right = max(box[2] for box in boxes)
        raw_bottom = max(box[3] for box in boxes)
        bounding_box = (
            max(0, math.floor(raw_left / scale) - padding),
            max(0, math.floor(raw_top / scale) - padding),
            max(0, math.ceil(raw_right / scale) - padding),
            max(0, math.ceil(raw_bottom / scale) - padding),
        )
    return OcrTextResult(normalized, confidence, bounding_box)


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _run_bounded_process(
    command: list[str],
    input_data: bytes,
    *,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    creationflags: int = 0,
) -> _BoundedProcessResult | None:
    """Run without a shell while bounding both output pipes during execution.

    A temporary input file avoids a third pipe and its associated deadlock
    surface.  Dedicated readers drain stdout and stderr concurrently, retain at
    most their configured caps, and kill the child immediately on overflow.
    ``None`` is the deliberately non-fatal result for timeout, output overflow,
    reader failure, or incomplete cleanup.
    """

    if timeout <= 0 or stdout_limit <= 0 or stderr_limit <= 0:
        raise ValueError("process timeout and output limits must be positive")

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    output_limited = threading.Event()
    reader_failed = threading.Event()
    timed_out = False

    with tempfile.TemporaryFile() as input_file:
        input_file.write(input_data)
        input_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=input_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=creationflags,
        )
        assert process.stdout is not None
        assert process.stderr is not None

        def kill_child() -> None:
            with contextlib.suppress(OSError):
                process.kill()

        def read_bounded(stream: BinaryIO, target: bytearray, limit: int) -> None:
            try:
                # Popen exposes buffered readers. ``read(size)`` may wait for
                # the entire requested size, delaying overflow detection until
                # the global timeout; ``read1`` performs one underlying pipe
                # read and returns as soon as bytes are available.
                read_chunk = getattr(stream, "read1", stream.read)
                while True:
                    chunk = read_chunk(64 * 1024)
                    if not chunk:
                        return
                    remaining = max(0, limit - len(target))
                    target.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        output_limited.set()
                        kill_child()
                        return
            except (OSError, ValueError):
                reader_failed.set()
                kill_child()

        readers = (
            threading.Thread(
                target=read_bounded,
                args=(process.stdout, stdout_buffer, stdout_limit),
                name="printproxy-ocr-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=read_bounded,
                args=(process.stderr, stderr_buffer, stderr_limit),
                name="printproxy-ocr-stderr",
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_child()
            try:
                returncode = process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                reader_failed.set()
                returncode = -1
        finally:
            if process.poll() is None:
                kill_child()
                with contextlib.suppress(OSError, subprocess.SubprocessError):
                    process.wait(timeout=1.0)
            for reader in readers:
                reader.join(timeout=1.0)
            process.stdout.close()
            process.stderr.close()
            for reader in readers:
                if reader.is_alive():
                    reader.join(timeout=1.0)

    if timed_out or output_limited.is_set() or reader_failed.is_set():
        return None
    if any(reader.is_alive() for reader in readers):
        return None
    return _BoundedProcessResult(returncode, bytes(stdout_buffer), bytes(stderr_buffer))


def _run_tesseract_ocr(image: ImageBlock) -> OcrTextResult | None:
    executable = shutil.which("tesseract")
    if executable is None:
        return None
    language = os.environ.get("PRINTPROXY_OCR_LANG", "ita+eng")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", language):
        language = "ita+eng"
    pgm, scale, padding = _bitmap_pgm_for_ocr(image)
    command = [
        executable,
        "stdin",
        "stdout",
        "--dpi",
        str(max(image.dpi_x, image.dpi_y, 72) * scale),
        "--psm",
        "6",
        "-l",
        language,
        "tsv",
    ]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = _run_bounded_process(
            command,
            pgm,
            timeout=5.0,
            stdout_limit=1_000_000,
            stderr_limit=64 * 1024,
            creationflags=creation_flags,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed is None or completed.returncode != 0:
        return None
    return _parse_tesseract_tsv(completed.stdout, scale=scale, padding=padding)


def recognize_raster_text(
    document: ReceiptDocument,
    *,
    ocr_engine: OcrEngine | None = None,
    minimum_confidence: float = 70.0,
    max_images: int = 4,
    max_total_pixels: int = 4_000_000,
) -> ReceiptDocument:
    """Replace only high-confidence textual rasters with semantic AST nodes.

    The original :class:`ImageBlock` is retained inside every
    :class:`RasterTextBlock`; PDF rendering therefore remains pixel-faithful.
    Missing OCR support, low confidence, timeouts, and backend failures all
    degrade safely to the original image node.
    """

    if not 0 <= minimum_confidence <= 100:
        raise ValueError("minimum_confidence must be between 0 and 100")
    if max_images < 0:
        raise ValueError("max_images must be non-negative")
    if max_total_pixels < 0:
        raise ValueError("max_total_pixels must be non-negative")
    engine = ocr_engine or _run_tesseract_ocr
    nodes: list[DocumentNode] = []
    warnings = list(document.warnings)
    attempted_images = 0
    attempted_pixels = 0
    for node in document.nodes:
        if not isinstance(node, ImageBlock) or not _is_potential_raster_text(node):
            nodes.append(node)
            continue
        pixels = node.width * node.height
        if attempted_images >= max_images or attempted_pixels + pixels > max_total_pixels:
            nodes.append(node)
            continue
        attempted_images += 1
        attempted_pixels += pixels
        try:
            result = engine(node)
        except Exception as error:
            if len(warnings) < 64:
                warnings.append(f"raster OCR failed safely: {_safe_error(error, 160)}")
            nodes.append(node)
            continue
        if (
            result is None
            or not isinstance(result, OcrTextResult)
            or not math.isfinite(result.confidence)
            or result.confidence < minimum_confidence
        ):
            nodes.append(node)
            continue
        normalized = "\n".join(
            line.strip()
            for line in unicodedata.normalize("NFKC", result.text).splitlines()
            if line.strip()
        )[:2048]
        if not normalized or not any(character.isalnum() for character in normalized):
            nodes.append(node)
            continue
        bbox = result.bounding_box
        if bbox is not None:
            left, top, right, bottom = bbox
            bbox = (
                max(0, min(node.width, left)),
                max(0, min(node.height, top)),
                max(0, min(node.width, right)),
                max(0, min(node.height, bottom)),
            )
            if bbox[2] <= bbox[0] or bbox[3] <= bbox[1]:
                bbox = None
        line_count = max(1, normalized.count("\n") + 1)
        font_size = None if bbox is None else (bbox[3] - bbox[1]) / line_count
        nodes.append(
            RasterTextBlock(
                text=normalized,
                source_bitmap=node,
                ocr_confidence=result.confidence,
                bounding_box=bbox,
                alignment=node.alignment,
                bold_estimate=False,
                font_size_estimate=font_size,
            )
        )
    return replace(document, nodes=tuple(nodes), warnings=tuple(warnings))


def _safe_error(error: BaseException, limit: int = 500) -> str:
    value = f"{type(error).__name__}: {error}".replace("\r", " ").replace("\n", " ")
    return value[:limit]


def _fsync_file(path: Path) -> None:
    """Make a completed temporary artifact durable before publishing it."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_parent_directory(path: Path) -> None:
    """Persist an atomic replacement's directory entry on POSIX filesystems."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def render_pdf(
    document: ReceiptDocument,
    destination: str | os.PathLike[str],
    *,
    width_mm: float = 80.0,
    base_font_size: float = 8.5,
    margin_mm: float = 4.0,
    max_height_mm: float = 2000.0,
    best_effort: bool = True,
) -> PdfRenderResult:
    """Render one variable-height 80 mm-style receipt page atomically.

    The default ``best_effort=True`` returns a failed :class:`PdfRenderResult`
    instead of raising, so PDF generation cannot fail a successful print job.
    """

    path = Path(destination)
    temporary: Path | None = None
    try:
        if not (30 <= width_mm <= 120):
            raise ValueError("width_mm must be between 30 and 120")
        if not (1 <= base_font_size <= 36):
            raise ValueError("base_font_size must be between 1 and 36")
        if not (0 <= margin_mm < width_mm / 2):
            raise ValueError("margin_mm must be non-negative and leave printable width")
        if not (20 <= max_height_mm <= 5000):
            raise ValueError("max_height_mm must be between 20 and 5000")
        try:
            from reportlab.lib.utils import ImageReader
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfgen import canvas
        except ImportError as error:
            raise RuntimeError("ReportLab is required for PDF receipt rendering") from error

        mm = 72.0 / 25.4
        width_points = width_mm * mm
        margin = margin_mm * mm
        printable_width = width_points - 2 * margin
        operations = _pdf_operations(document, printable_width, pdfmetrics, base_font_size)
        content_height = sum(operation.height for operation in operations)
        minimum_height = 30 * mm
        maximum_height = max_height_mm * mm
        page_height = max(minimum_height, min(maximum_height, content_height + 2 * margin))
        content_truncated = content_height + 2 * margin > maximum_height

        selected: list[_PdfOperation] = []
        available_height = page_height - 2 * margin
        used_height = 0.0
        marker_height = base_font_size * 1.5
        for operation in operations:
            reserve = marker_height if content_truncated else 0.0
            # The page height is derived from this same sum; tolerate sub-point
            # floating error so an exact-fit final operation is not replaced by
            # a false truncation marker.
            if used_height + operation.height > max(
                0.0, available_height - reserve
            ) + 1e-7:
                content_truncated = True
                break
            selected.append(operation)
            used_height += operation.height
        if content_truncated:
            marker_style = TextStyle(bold=True)
            marker = _PdfRun("[CONTENUTO TRONCATO]", marker_style)
            marker_width, _ = _run_metrics(marker, pdfmetrics, base_font_size)
            selected.append(_PdfLine((marker,), marker_height, marker_width, "center"))

        path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        )
        temporary = Path(handle.name)
        handle.close()
        receipt = canvas.Canvas(str(temporary), pagesize=(width_points, page_height), pageCompression=1)
        receipt.setTitle("Ricevuta PrintProxy")
        receipt.setAuthor("PrintProxy")
        y = page_height - margin
        for operation in selected:
            if isinstance(operation, _PdfSpacer):
                y -= operation.height
                continue
            if isinstance(operation, _PdfLine):
                top = y
                y -= operation.height
                if not operation.runs:
                    continue
                if operation.alignment == "center":
                    x = margin + max(0.0, (printable_width - operation.width) / 2)
                elif operation.alignment == "right":
                    x = margin + max(0.0, printable_width - operation.width)
                else:
                    x = margin
                largest_size = max(base_font_size * run.style.height for run in operation.runs)
                baseline = top - largest_size
                for run in operation.runs:
                    font = "Courier-Bold" if run.style.bold else "Courier"
                    font_size = base_font_size * run.style.height
                    horizontal_scale = 100 * run.style.width / run.style.height
                    text = _safe_pdf_text(run.text)
                    text_object = receipt.beginText(x, baseline)
                    text_object.setFont(font, font_size)
                    text_object.setHorizScale(horizontal_scale)
                    if run.style.char_spacing_dots:
                        text_object.setCharSpace(run.style.char_spacing_dots * 72 / 203)
                    text_object.textOut(text)
                    receipt.drawText(text_object)
                    run_width, _ = _run_metrics(run, pdfmetrics, base_font_size)
                    if run.style.underline and text:
                        receipt.setLineWidth(max(0.35, font_size / 18))
                        receipt.line(x, baseline - 1.2, x + run_width, baseline - 1.2)
                    x += run_width
                continue
            if isinstance(operation, _PdfImage):
                y -= operation.height
                if operation.image.alignment == "center":
                    x = margin + (printable_width - operation.width) / 2
                elif operation.image.alignment == "right":
                    x = margin + printable_width - operation.width
                else:
                    x = margin
                image_reader = ImageReader(io.BytesIO(_bitmap_png(operation.image)))
                receipt.drawImage(
                    image_reader,
                    x,
                    y,
                    width=operation.width,
                    height=operation.height,
                    preserveAspectRatio=True,
                    mask="auto",
                )
                continue
            if isinstance(operation, _PdfPlaceholder):
                y -= operation.height
                if operation.alignment == "center":
                    x = margin + (printable_width - operation.width) / 2
                elif operation.alignment == "right":
                    x = margin + printable_width - operation.width
                else:
                    x = margin
                receipt.setLineWidth(0.5)
                receipt.rect(x, y, operation.width, operation.height, stroke=1, fill=0)
                receipt.setFont("Courier-Bold", 7)
                receipt.drawCentredString(x + operation.width / 2, y + operation.height / 2, operation.label)
                if operation.detail:
                    receipt.setFont("Courier", 5.5)
                    receipt.drawCentredString(
                        x + operation.width / 2,
                        y + 3,
                        _safe_pdf_text(operation.detail)[:64],
                    )
        receipt.showPage()
        receipt.save()
        if os.name != "nt":
            os.chmod(temporary, 0o640)
        _fsync_file(temporary)
        os.replace(temporary, path)
        _fsync_parent_directory(path)
        temporary = None
        return PdfRenderResult(
            True,
            path,
            width_mm=width_mm,
            height_mm=page_height / mm,
            content_truncated=content_truncated,
        )
    except BaseException as error:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink()
        if not best_effort:
            raise
        return PdfRenderResult(False, path, error=_safe_error(error))


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(value.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        _fsync_parent_directory(path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def render_receipt_artifacts(
    data: bytes | bytearray | memoryview,
    *,
    clean_text_path: str | os.PathLike[str] | None = None,
    pdf_path: str | os.PathLike[str] | None = None,
    default_codepage: str = "cp858",
    limits: ParseLimits | None = None,
    pdf_width_mm: float = 80.0,
    ocr_enabled: bool = True,
    ocr_engine: OcrEngine | None = None,
    ocr_minimum_confidence: float = 70.0,
    ocr_max_images: int = 4,
    ocr_max_total_pixels: int = 4_000_000,
    best_effort: bool = True,
) -> ReceiptArtifactsResult:
    """Parse once and render clean text/PDF from the same document model.

    This is the integration API intended for a post-forwarding sidecar worker.  It
    does not create or modify the authoritative RAW or technical TXT artifacts.
    """

    document = parse_escpos(data, default_codepage, limits)
    if ocr_enabled:
        document = recognize_raster_text(
            document,
            ocr_engine=ocr_engine,
            minimum_confidence=ocr_minimum_confidence,
            max_images=ocr_max_images,
            max_total_pixels=ocr_max_total_pixels,
        )
    clean_text = render_clean_text(document)
    clean_destination = Path(clean_text_path) if clean_text_path is not None else None
    clean_error: str | None = None
    if clean_destination is not None:
        try:
            _atomic_write_text(clean_destination, clean_text)
        except BaseException as error:
            if not best_effort:
                raise
            clean_error = _safe_error(error)
    pdf_result = (
        render_pdf(document, pdf_path, width_mm=pdf_width_mm, best_effort=best_effort)
        if pdf_path is not None
        else None
    )
    return ReceiptArtifactsResult(
        document=document,
        clean_text=clean_text,
        clean_text_path=clean_destination,
        clean_text_error=clean_error,
        pdf=pdf_result,
    )


__all__ = [
    "BarcodeBlock",
    "CashDrawerBlock",
    "CutBlock",
    "FeedBlock",
    "GraphicBlock",
    "ImageBlock",
    "InitializeBlock",
    "LineBreak",
    "OcrTextResult",
    "ParseLimits",
    "PdfRenderResult",
    "QrCodeBlock",
    "RasterTextBlock",
    "RealtimeStatusBlock",
    "SeparatorBlock",
    "ReceiptArtifactsResult",
    "ReceiptDocument",
    "StateChangeBlock",
    "TextBlock",
    "TextStyle",
    "UnknownCommandBlock",
    "parse_escpos",
    "recognize_raster_text",
    "render_clean_text",
    "render_pdf",
    "render_receipt_artifacts",
]
