from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from printproxy_core import escpos_to_text, find_escpos_cut  # noqa: E402


class EscPosParserTests(unittest.TestCase):
    def test_common_commands_and_cut(self) -> None:
        raw = b"\x1b@\x1ba\x01HOTEL\nTOTALE 10.00\n\x1dV\x00"
        rendered = escpos_to_text(raw)
        self.assertIn("[ESC/POS INIT]", rendered)
        self.assertIn("[ESC/POS ALIGN 1]", rendered)
        self.assertIn("HOTEL", rendered)
        self.assertIn("[ESC/POS CUT]", rendered)
        self.assertEqual(raw, b"\x1b@\x1ba\x01HOTEL\nTOTALE 10.00\n\x1dV\x00")

    def test_codepages_and_unhandled_byte_are_visible(self) -> None:
        rendered = escpos_to_text(b"\x1bt\x13Prezzo \xd5\n\x00", "cp858")
        self.assertIn("CODEPAGE 19 cp858", rendered)
        self.assertIn("€", rendered)
        self.assertIn("[BYTE 0x00]", rendered)

    def test_raster_payload_is_not_parsed_as_cut(self) -> None:
        payload = b"\x1dV\x00X"
        raw = b"\x1dv0\x00\x04\x00\x01\x00" + payload
        rendered = escpos_to_text(raw)
        self.assertIn("RASTER_IMAGE bytes=4", rendered)
        self.assertNotIn("[ESC/POS CUT]", rendered)

    def test_cut_detection_variants_and_truncation(self) -> None:
        self.assertEqual(find_escpos_cut(b"abc\x1dV\x00tail"), (3, 6))
        self.assertEqual(find_escpos_cut(b"abc\x1dVA\x03tail"), (3, 7))
        self.assertIsNone(find_escpos_cut(b"abc\x1dV"))
        self.assertIn("ESC/POS ESC", escpos_to_text(b"\x1bX"))

    def test_fuzz_inputs_terminate_and_are_deterministic(self) -> None:
        for length in range(256):
            raw = bytes((index * 73 + length) % 256 for index in range(length))
            first = escpos_to_text(raw)
            second = escpos_to_text(raw)
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
