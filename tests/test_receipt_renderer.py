from __future__ import annotations

import base64
import importlib.util
import shutil
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from receipt_renderer import (  # noqa: E402
    _PdfLine,
    _pdf_operations,
    _run_bounded_process,
    BarcodeBlock,
    CashDrawerBlock,
    CutBlock,
    FeedBlock,
    GraphicBlock,
    ImageBlock,
    InitializeBlock,
    LineBreak,
    OcrTextResult,
    ParseLimits,
    QrCodeBlock,
    RasterTextBlock,
    ReceiptDocument,
    RealtimeStatusBlock,
    SeparatorBlock,
    StateChangeBlock,
    TextBlock,
    TextStyle,
    UnknownCommandBlock,
    parse_escpos,
    recognize_raster_text,
    render_clean_text,
    render_pdf,
    render_receipt_artifacts,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fixture_payload(name: str, *, compressed: bool = False) -> bytes:
    lines = (FIXTURES / name).read_text(encoding="ascii").splitlines()
    encoded = "".join(line.strip() for line in lines if not line.startswith("#"))
    decoded = base64.b64decode(encoded, validate=True)
    return zlib.decompress(decoded) if compressed else decoded


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

    def test_document_model_distinguishes_separator_and_graphics(self) -> None:
        parsed = parse_escpos(
            b"\x1b*\x00\x02\x00\x80\x40\x1dk\x49\x04ABCD"
        )
        separator = SeparatorBlock("--------------------------", TextStyle())
        document = ReceiptDocument(
            nodes=(separator, LineBreak(), *parsed.nodes),
            input_size=parsed.input_size,
            parsed_size=parsed.parsed_size,
            truncated=parsed.truncated,
            warnings=parsed.warnings,
            default_codepage=parsed.default_codepage,
        )

        self.assertEqual(separator.pattern, "--------------------------")
        graphics = [node for node in document.nodes if isinstance(node, GraphicBlock)]
        self.assertEqual(len(graphics), 2)
        self.assertIn("--------------------------", render_clean_text(document))

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

    def test_unrelated_images_are_not_coalesced_without_strip_positioning_feed(self) -> None:
        image = b"\x1b*\x21\x01\x00\x80\x00\x00"
        document = parse_escpos(image + b"\x1bJ\x31" + image)
        images = [node for node in document.nodes if isinstance(node, ImageBlock)]
        self.assertEqual(len(images), 2)

    def test_many_positioned_strips_are_reconstructed_in_linear_pass(self) -> None:
        strip = b"\x1b*\x00\x01\x00\x80"
        raw = (strip + b"\x1bJ\x08") * 10_000

        document = parse_escpos(raw)

        images = [node for node in document.nodes if isinstance(node, ImageBlock)]
        self.assertEqual(len(images), 1)
        self.assertEqual((images[0].width, images[0].height), (1, 80_000))
        self.assertEqual(images[0].strip_count, 10_000)

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
            b"\x1b@Demo: 01/01/00  00:00\n"
            + image
            + b"\x1bJ\x30"
            + image
            + b"\x1bJ\x30"
            + b"\x1d!\x11"
            + b"1x Articolo d\n   imostrativ\n   o\n"
            + b"\x10\x04\x01\x1bp\x00\x01\x01\x1dV\x00"
        )
        clean = render_clean_text(parse_escpos(raw))
        self.assertIn("Demo: 01/01/00  00:00", clean)
        self.assertEqual(clean.count("[IMMAGINE]"), 1)
        self.assertIn("1x Articolo dimostrativo", clean)
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

    def test_high_confidence_raster_text_replaces_placeholder_semantically(self) -> None:
        raw = _fixture_payload(
            "synthetic_tavolo_25_5.escpos.zlib.b64", compressed=True
        )
        parsed = parse_escpos(raw)
        bitmap = next(node for node in parsed.nodes if isinstance(node, ImageBlock))
        self.assertEqual((bitmap.width, bitmap.height, bitmap.strip_count), (312, 96, 4))

        def ocr_engine(image: ImageBlock) -> OcrTextResult:
            self.assertIs(image, bitmap)
            return OcrTextResult("Tavolo: 25-5", 96.5, (46, 30, 266, 66))

        document = recognize_raster_text(parsed, ocr_engine=ocr_engine)
        raster_text = next(
            node for node in document.nodes if isinstance(node, RasterTextBlock)
        )
        self.assertIs(raster_text.source_bitmap, bitmap)
        self.assertEqual(raster_text.text, "Tavolo: 25-5")
        self.assertEqual(raster_text.ocr_confidence, 96.5)
        clean = render_clean_text(document)
        expected = (FIXTURES / "synthetic_tavolo_25_5.expected.PULITO.txt").read_text(
            encoding="utf-8"
        )
        self.assertEqual(clean, expected)
        self.assertIn("Tavolo: 25-5", clean)
        self.assertIn("1x Articolo dimostrativo", clean)
        self.assertNotIn("[IMMAGINE]", clean)

    def test_low_confidence_and_ocr_failure_keep_original_image(self) -> None:
        raw = _fixture_payload(
            "synthetic_tavolo_25_5.escpos.zlib.b64", compressed=True
        )
        parsed = parse_escpos(raw)
        low = recognize_raster_text(
            parsed,
            ocr_engine=lambda _image: OcrTextResult("Tavolo: 25-5", 42.0),
        )
        self.assertIn("[IMMAGINE]", render_clean_text(low))
        self.assertFalse(any(isinstance(node, RasterTextBlock) for node in low.nodes))

        def failing_engine(_image: ImageBlock) -> OcrTextResult:
            raise RuntimeError("backend unavailable\nunsafe detail")

        failed = recognize_raster_text(parsed, ocr_engine=failing_engine)
        self.assertIn("[IMMAGINE]", render_clean_text(failed))
        self.assertTrue(any("failed safely" in warning for warning in failed.warnings))

    def test_optional_tesseract_backend_is_bounded_and_uses_confidence(self) -> None:
        raw = _fixture_payload(
            "synthetic_tavolo_25_5.escpos.zlib.b64", compressed=True
        )
        parsed = parse_escpos(raw)
        tsv = (
            b"level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\t"
            b"width\theight\tconf\ttext\n"
            b"5\t1\t1\t1\t1\t1\t184\t120\t240\t144\t95.0\tTavolo:\n"
            b"5\t1\t1\t1\t1\t2\t440\t120\t160\t144\t93.0\t25-5\n"
        )
        completed = mock.Mock(returncode=0, stdout=tsv, stderr=b"")
        with (
            mock.patch("receipt_renderer.shutil.which", return_value="/usr/bin/tesseract"),
            mock.patch(
                "receipt_renderer._run_bounded_process", return_value=completed
            ) as run,
        ):
            document = recognize_raster_text(parsed)
        self.assertIn("Tavolo: 25-5", render_clean_text(document))
        command = run.call_args.args[0]
        self.assertIn("ita+eng", command)
        self.assertTrue(run.call_args.args[1].startswith(b"P5\n"))
        self.assertEqual(run.call_args.kwargs["timeout"], 5.0)
        self.assertEqual(run.call_args.kwargs["stdout_limit"], 1_000_000)
        self.assertEqual(run.call_args.kwargs["stderr_limit"], 64 * 1024)

    def test_ocr_process_capture_kills_stdout_stderr_overflow_and_timeout(self) -> None:
        cases = (
            (
                "stdout",
                "import sys,time; sys.stdout.buffer.write(b'x'*4096); "
                "sys.stdout.buffer.flush(); time.sleep(30)",
                5.0,
            ),
            (
                "stderr",
                "import sys,time; sys.stderr.buffer.write(b'x'*4096); "
                "sys.stderr.buffer.flush(); time.sleep(30)",
                5.0,
            ),
            ("timeout", "import time; time.sleep(30)", 0.1),
        )
        for name, script, timeout in cases:
            with self.subTest(name=name):
                started = time.monotonic()
                result = _run_bounded_process(
                    [sys.executable, "-c", script],
                    b"",
                    timeout=timeout,
                    stdout_limit=128,
                    stderr_limit=128,
                )
                self.assertIsNone(result)
                self.assertLess(time.monotonic() - started, 3.0)

    @unittest.skipUnless(shutil.which("tesseract"), "Tesseract runtime not installed")
    def test_real_tesseract_recognizes_synthetic_four_strip_fixture(self) -> None:
        raw = _fixture_payload(
            "synthetic_tavolo_25_5.escpos.zlib.b64", compressed=True
        )
        expected = (FIXTURES / "synthetic_tavolo_25_5.expected.PULITO.txt").read_text(
            encoding="utf-8"
        )

        clean = render_clean_text(recognize_raster_text(parse_escpos(raw)))

        self.assertEqual(clean, expected)
        self.assertIn("Tavolo: 25-5", clean)
        self.assertNotIn("[IMMAGINE]", clean)


@unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab not installed")
class PdfReceiptRendererTests(unittest.TestCase):
    def test_pdf_wrap_accounts_for_esc_sp_character_spacing(self) -> None:
        from reportlab.pdfbase import pdfmetrics

        document = parse_escpos(b"\x1b \x14ABCDEFGH\n")
        printable_width = 35.0

        operations = _pdf_operations(document, printable_width, pdfmetrics, 8.5)
        lines = [operation for operation in operations if isinstance(operation, _PdfLine)]

        self.assertGreater(len(lines), 1)
        self.assertEqual(
            "".join(run.text for line in lines for run in line.runs),
            "ABCDEFGH",
        )
        self.assertTrue(
            all(line.width <= printable_width + 1e-7 for line in lines),
            [line.width for line in lines],
        )

    def test_pdf_wrap_scales_esc_sp_with_double_width_tz(self) -> None:
        from reportlab.pdfbase import pdfmetrics

        document = parse_escpos(b"\x1b \x08\x1d!\x10ABCD\n")
        printable_width = 38.0

        operations = _pdf_operations(document, printable_width, pdfmetrics, 8.5)
        lines = [operation for operation in operations if isinstance(operation, _PdfLine)]
        text_lines = ["".join(run.text for run in line.runs) for line in lines]

        self.assertEqual(text_lines, ["AB", "CD"])
        self.assertTrue(
            all(line.width <= printable_width + 1e-7 for line in lines),
            [line.width for line in lines],
        )

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

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "pypdf not installed")
    def test_four_strip_regression_pdf_has_one_complete_in_page_bitmap(self) -> None:
        from pypdf import PdfReader

        raw = _fixture_payload(
            "synthetic_tavolo_25_5.escpos.zlib.b64", compressed=True
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tavolo-25-5.pdf"
            result = render_receipt_artifacts(
                raw,
                pdf_path=destination,
                ocr_engine=lambda _image: OcrTextResult(
                    "Tavolo: 25-5", 96.5, (46, 30, 266, 66)
                ),
            )
            self.assertTrue(result.success, result.pdf.error if result.pdf else None)
            self.assertIn("Tavolo: 25-5", result.clean_text)
            self.assertNotIn("[IMMAGINE]", result.clean_text)
            raster = next(
                node.source_bitmap
                for node in result.document.nodes
                if isinstance(node, RasterTextBlock)
            )
            # The synthetic artwork deliberately leaves a one-pixel white
            # margin around a continuous rectangle.  Assert the complete
            # inner border, rather than inventing ink on the outer margin.
            self.assertTrue(
                all(
                    raster.pixel_is_black(x, 1)
                    for x in range(1, raster.width - 1)
                )
            )
            self.assertTrue(
                all(
                    raster.pixel_is_black(x, raster.height - 2)
                    for x in range(1, raster.width - 1)
                )
            )
            self.assertTrue(
                all(
                    raster.pixel_is_black(1, y)
                    for y in range(1, raster.height - 1)
                )
            )
            self.assertTrue(
                all(
                    raster.pixel_is_black(raster.width - 2, y)
                    for y in range(1, raster.height - 1)
                )
            )

            page = PdfReader(destination).pages[0]
            images = page.images
            self.assertEqual(len(images), 1)
            self.assertEqual(images[0].image.size, (312, 96))
            content = page.get_contents().get_data().decode("latin1")
            self.assertEqual(content.count(" Do"), 1)
            matrix_line = next(
                line for line in content.splitlines() if line.endswith(" cm") and not line.startswith("1 0")
            )
            width, _, _, height, x, y, _operator = matrix_line.split()
            media_width = float(page.mediabox.width)
            media_height = float(page.mediabox.height)
            self.assertGreaterEqual(float(x), 0)
            self.assertGreaterEqual(float(y), 0)
            self.assertLessEqual(float(x) + float(width), media_width + 0.01)
            self.assertLessEqual(float(y) + float(height), media_height + 0.01)

    def test_integration_ocr_backend_failure_is_non_fatal(self) -> None:
        raw = _fixture_payload(
            "synthetic_tavolo_25_5.escpos.zlib.b64", compressed=True
        )

        def failing_engine(_image: ImageBlock) -> OcrTextResult:
            raise TimeoutError("OCR timed out")

        result = render_receipt_artifacts(raw, ocr_engine=failing_engine)
        self.assertTrue(result.success)
        self.assertIn("[IMMAGINE]", result.clean_text)

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
