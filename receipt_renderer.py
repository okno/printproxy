"""Bounded ESC/POS receipt parser and human/PDF renderers.

The functions in this module are sidecar helpers: callers must archive and forward
the authoritative RAW bytes independently.  Parsing or PDF failures are reported
without changing the input and, by default, without raising into the print path.
"""

from __future__ import annotations

import binascii
import contextlib
import io
import os
import re
import struct
import tempfile
import zlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, TypeAlias


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


@dataclass(frozen=True, slots=True)
class TextBlock(ReceiptNode):
    text: str
    style: TextStyle


@dataclass(frozen=True, slots=True)
class LineBreak(ReceiptNode):
    pass


@dataclass(frozen=True, slots=True)
class FeedBlock(ReceiptNode):
    lines: int = 0
    dots: int = 0


@dataclass(frozen=True, slots=True)
class ImageBlock(ReceiptNode):
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

    @property
    def row_stride(self) -> int:
        return (self.width + 7) // 8

    def pixel_is_black(self, x: int, y: int) -> bool:
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise IndexError("pixel outside image")
        byte = self.packed_bits[y * self.row_stride + (x // 8)]
        return bool(byte & (0x80 >> (x % 8)))


@dataclass(frozen=True, slots=True)
class BarcodeBlock(ReceiptNode):
    symbology: int
    data: bytes
    alignment: Alignment
    complete: bool = True


@dataclass(frozen=True, slots=True)
class QrCodeBlock(ReceiptNode):
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
    | LineBreak
    | FeedBlock
    | ImageBlock
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
            dpi_x = 60 if mode in {0, 32} else 120
            dpi_y = 72 if mode in {0, 1} else 180
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


def parse_escpos(
    data: bytes | bytearray | memoryview,
    default_codepage: str = "cp858",
    limits: ParseLimits | None = None,
) -> ReceiptDocument:
    """Parse an immutable copy of ESC/POS data into the shared document model."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    raw = bytes(data)
    return _EscPosParser(raw, default_codepage, limits or ParseLimits()).parse()


@dataclass(slots=True)
class _CleanLine:
    text: str
    physical_cells: int
    alignment: Alignment = "left"
    placeholder: bool = False
    continuation_prefix: int | None = None


_ITEM_PREFIX = re.compile(r"^\s*(?:\d+\s*[xX]\s+|[-*]\s+)")
_SEPARATOR = re.compile(r"^\s*[-_=]{3,}\s*$")


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
            previous.text += stripped
            previous.physical_cells += line.physical_cells - indent
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


def _run_metrics(run: _PdfRun, pdfmetrics: object, base_size: float) -> tuple[float, float]:
    font = "Courier-Bold" if run.style.bold else "Courier"
    font_size = base_size * run.style.height
    text = _safe_pdf_text(run.text)
    width = pdfmetrics.stringWidth(text, font, font_size)  # type: ignore[attr-defined]
    width *= run.style.width / run.style.height
    if len(text) > 1 and run.style.char_spacing_dots:
        width += (len(text) - 1) * run.style.char_spacing_dots * 72 / 203
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
            if current and current_width + char_width > printable_width:
                result.append(current)
                current = []
                current_width = 0.0
            if current and current[-1].style == run.style:
                current[-1] = _PdfRun(current[-1].text + character, run.style)
            else:
                current.append(unit)
            current_width += char_width
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
        elif isinstance(node, LineBreak):
            finish(force=True)
        elif isinstance(node, FeedBlock):
            finish()
            gap = node.lines * base_size * 1.25 + node.dots * 72 / 203
            if gap > 0:
                operations.append(_PdfSpacer(min(gap, 200 * 72 / 25.4)))
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
            if used_height + operation.height > max(0.0, available_height - reserve):
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
    best_effort: bool = True,
) -> ReceiptArtifactsResult:
    """Parse once and render clean text/PDF from the same document model.

    This is the integration API intended for a post-forwarding sidecar worker.  It
    does not create or modify the authoritative RAW or technical TXT artifacts.
    """

    document = parse_escpos(data, default_codepage, limits)
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
    "ImageBlock",
    "InitializeBlock",
    "LineBreak",
    "ParseLimits",
    "PdfRenderResult",
    "QrCodeBlock",
    "RealtimeStatusBlock",
    "ReceiptArtifactsResult",
    "ReceiptDocument",
    "StateChangeBlock",
    "TextBlock",
    "TextStyle",
    "UnknownCommandBlock",
    "parse_escpos",
    "render_clean_text",
    "render_pdf",
    "render_receipt_artifacts",
]
