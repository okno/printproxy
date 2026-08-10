from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from receipt_renderer import (  # noqa: E402
    BarcodeBlock,
    CashDrawerBlock,
    CutBlock,
    FeedBlock,
    ImageBlock,
    InitializeBlock,
    ParseLimits,
    QrCodeBlock,
    RealtimeStatusBlock,
    StateChangeBlock,
    TextBlock,
    UnknownCommandBlock,
    parse_escpos,
    render_clean_text,
    render_pdf,
    render_receipt_artifacts,
)


class ReceiptParserTests(unittest.TestCase):
    def test_styles_alignment_and_initialization_reach_text_ast(self) -> None:
        raw = (
            b"\x1b@"
            b"\x1ba\x01"
            b"\x1bE\x01"
            b"\x1d!\x11"
            b"TITOLO\n"
            b"\x1b-\x01sottolineato\n"
        )
        original = bytes(raw)

        document = parse_escpos(raw)

        self.assertEqual(raw, original)
        self.assertIsInstance(document.nodes[0], InitializeBlock)
        title = next(
            node for node in document.nodes if isinstance(node, TextBlock) and "TITOLO" in node.text
        )
        self.assertTrue(title.style.bold)
        self.assertEqual(title.style.alignment, "center")
        self.assertEqual((title.style.width, title.style.height), (2, 2))
        underlined = next(
            node
            for node in document.nodes
            if isinstance(node, TextBlock) and "sottolineato" in node.text
        )
        self.assertTrue(underlined.style.underline)
        commands = [
            node.command for node in document.nodes if isinstance(node, StateChangeBlock)
        ]
        self.assertIn("BOLD", commands)
        self.assertIn("CHAR_SIZE", commands)

    def test_cp858_and_explicit_codepage_decode_accents_and_euro(self) -> None:
        raw = b"Caff\x8a, pi\x97, euro \xd5\n\x1bt\x13Prezzo \xd5\n"
        document = parse_escpos(raw, "cp858")
        text = "".join(node.text for node in document.nodes if isinstance(node, TextBlock))
        self.assertIn("Caff\u00e8", text)
        self.assertIn("pi\u00f9", text)
        self.assertIn("euro \u20ac", text)
        self.assertIn("Prezzo \u20ac", text)

    def test_feed_cut_drawer_realtime_and_unknown_are_typed(self) -> None:
        raw = (
            b"A\x1bd\x02"
            b"\x1bJ\x18"
            b"\x1bp\x00\x19\xfa"
            b"\x10\x04\x01"
            b"\x1dV\x42\x03"
            b"\x1bX"
        )
        document = parse_escpos(raw)
        feeds = [node for node in document.nodes if isinstance(node, FeedBlock)]
        self.assertEqual([(node.lines, node.dots) for node in feeds], [(2, 0), (0, 24)])
        self.assertEqual(
            [node for node in document.nodes if isinstance(node, CashDrawerBlock)],
            [CashDrawerBlock(0, 25, 250)],
        )
        self.assertEqual(
            [node for node in document.nodes if isinstance(node, RealtimeStatusBlock)],
            [RealtimeStatusBlock(4, 1)],
        )
        cut = next(node for node in document.nodes if isinstance(node, CutBlock))
        self.assertEqual((cut.mode, cut.feed), (0x42, 3))
        unknown = next(node for node in document.nodes if isinstance(node, UnknownCommandBlock))
        self.assertEqual(unknown.raw, b"\x1bX")

    def test_esc_star_bitmap_is_decoded_column_major(self) -> None:
        # Two 8-dot columns: black at (0, 0) and (1, 1).
        raw = b"\x1b*\x00\x02\x00\x80\x40"
        document = parse_escpos(raw)
        image = next(node for node in document.nodes if isinstance(node, ImageBlock))
        self.assertEqual((image.width, image.height, image.source), (2, 8, "ESC *"))
        self.assertTrue(image.complete)
        self.assertTrue(image.pixel_is_black(0, 0))
        self.assertTrue(image.pixel_is_black(1, 1))
        self.assertFalse(image.pixel_is_black(1, 0))

    def test_24_dot_esc_star_and_raster_bitmap_are_decoded(self) -> None:
        star = b"\x1b*\x21\x01\x00\x80\x00\x01"
        raster = b"\x1dv0\x00\x01\x00\x02\x00\x80\x01"
        document = parse_escpos(star + raster)
        images = [node for node in document.nodes if isinstance(node, ImageBlock)]
        self.assertEqual(len(images), 2)
        self.assertEqual((images[0].width, images[0].height), (1, 24))
        self.assertTrue(images[0].pixel_is_black(0, 0))
        self.assertTrue(images[0].pixel_is_black(0, 23))
        self.assertEqual((images[1].width, images[1].height), (8, 2))
        self.assertTrue(images[1].pixel_is_black(0, 0))
        self.assertTrue(images[1].pixel_is_black(7, 1))

    def test_qr_store_print_and_length_barcode_are_conservative_nodes(self) -> None:
        qr_store_payload = b"\x31\x50\x30HELLO"
        qr_store = b"\x1d(k" + bytes((len(qr_store_payload), 0)) + qr_store_payload
        qr_print_payload = b"\x31\x51\x30"
        qr_print = b"\x1d(k" + bytes((len(qr_print_payload), 0)) + qr_print_payload
        barcode = b"\x1dk\x49\x04ABCD"
        document = parse_escpos(qr_store + qr_print + barcode)

        qr = next(node for node in document.nodes if isinstance(node, QrCodeBlock))
        self.assertEqual(qr.data, b"HELLO")
        self.assertTrue(qr.complete)
        bar = next(node for node in document.nodes if isinstance(node, BarcodeBlock))
        self.assertEqual((bar.symbology, bar.data), (73, b"ABCD"))

    def test_malformed_and_bounded_inputs_do_not_crash(self) -> None:
        limits = ParseLimits(
            max_input_bytes=32,
            max_nodes=8,
            max_text_chars=12,
            max_image_pixels=16,
            max_image_payload_bytes=16,
            max_warnings=8,
        )
        malformed = b"12345678901234567890\x1dv0\x00\xff\xff\xff\xff" + b"X" * 64
        first = parse_escpos(malformed, limits=limits)
        second = parse_escpos(malformed, limits=limits)
        self.assertTrue(first.truncated)
        self.assertLessEqual(first.parsed_size, 32)
        self.assertEqual(first, second)
        self.assertTrue(first.warnings)

    def test_fuzz_prefixes_terminate_deterministically(self) -> None:
        for length in range(256):
            raw = bytes((index * 97 + length * 13) % 256 for index in range(length))
            self.assertEqual(parse_escpos(raw), parse_escpos(raw))


class CleanReceiptRendererTests(unittest.TestCase):
    def test_clean_output_has_no_technical_markers_and_collapses_image_slices(self) -> None:
        image = b"\x1b*\x00\x01\x00\x80"
        raw = (
            b"\x1b@Operatore: 10/08/26  23:45\n"
            + image
            + b"\x1bJ\x30"
            + image
            + b"\x1bJ\x30"
            + b"\x1d!\x11"
            + b"1x Acqua friz\n   zante picc\n   ola\n"
            + b"\x10\x04\x01\x1bp\x00\x01\x01\x1dV\x00"
        )
        clean = render_clean_text(parse_escpos(raw))
        self.assertIn("Operatore: 10/08/26  23:45", clean)
        self.assertEqual(clean.count("[IMMAGINE]"), 1)
        self.assertIn("1x Acqua frizzante piccola", clean)
        self.assertNotIn("ESC/POS", clean)
        self.assertNotIn("REALTIME", clean)
        self.assertNotIn("CASH", clean)

    def test_unwrap_is_conservative_for_ambiguous_indented_lines(self) -> None:
        raw = b"Titolo molto lungo del documento\nNota\n   separata\n"
        clean = render_clean_text(parse_escpos(raw))
        self.assertIn("Nota\n   separata", clean)
        self.assertNotIn("Notaseparata", clean)

    def test_alignment_and_output_limit_are_bounded(self) -> None:
        document = parse_escpos(b"\x1ba\x01CENTRO\n" + b"A" * 200)
        clean = render_clean_text(document, paper_columns=42, max_output_chars=40)
        self.assertTrue(clean.splitlines()[0].startswith(" "))
        self.assertLessEqual(len(clean), 40)
        self.assertIn("TRONCATO", clean)
        self.assertLessEqual(len(render_clean_text(document, max_output_chars=8)), 8)


@unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab not installed")
class PdfReceiptRendererTests(unittest.TestCase):
    def test_pdf_is_80mm_variable_height_and_contains_real_bitmap(self) -> None:
        raw = (
            b"\x1b@\x1ba\x01\x1bE\x01HOTEL\n"
            b"\x1ba\x00Riga accentata: caff\x8a \xd5\n"
            b"\x1b*\x00\x08\x00\xff\x81\x81\x81\x81\x81\x81\xff"
            b"\x1dV\x00"
        )
        document = parse_escpos(raw)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "ricevuta.pdf"
            result = render_pdf(document, destination)
            self.assertTrue(result.success, result.error)
            self.assertEqual(result.width_mm, 80.0)
            self.assertIsNotNone(result.height_mm)
            self.assertGreaterEqual(result.height_mm or 0, 30.0)
            self.assertEqual(destination.read_bytes()[:5], b"%PDF-")
            self.assertGreater(destination.stat().st_size, 500)

    def test_integration_api_parses_once_and_writes_clean_and_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean_path = root / "job.PULITO.txt"
            pdf_path = root / "job.pdf"
            with mock.patch("receipt_renderer._fsync_parent_directory") as fsync_parent:
                result = render_receipt_artifacts(
                    b"\x1b@Conto \xd5 12,00\n\x1dV\x00",
                    clean_text_path=clean_path,
                    pdf_path=pdf_path,
                )
            self.assertTrue(result.success, result.pdf.error if result.pdf else None)
            self.assertIn("Conto \u20ac 12,00", clean_path.read_text(encoding="utf-8"))
            self.assertTrue(pdf_path.is_file())
            self.assertTrue(any(isinstance(node, CutBlock) for node in result.document.nodes))
            self.assertEqual(
                fsync_parent.call_args_list,
                [mock.call(clean_path), mock.call(pdf_path)],
            )

    def test_pdf_failure_is_returned_in_best_effort_mode(self) -> None:
        document = parse_escpos(b"test\n")
        with tempfile.TemporaryDirectory() as directory:
            destination_is_directory = Path(directory) / "already-a-directory.pdf"
            destination_is_directory.mkdir()
            result = render_pdf(document, destination_is_directory)
            self.assertFalse(result.success)
            self.assertIsNotNone(result.error)
            self.assertTrue(destination_is_directory.is_dir())


if __name__ == "__main__":
    unittest.main()
