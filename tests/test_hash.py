from __future__ import annotations

import hashlib
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from printproxy_core import (  # noqa: E402
    IntegrityError,
    IntegrityLedger,
    StateStore,
    atomic_write_bytes,
    atomic_write_json,
    ensure_runtime_directories,
    load_hmac_key,
    load_settings,
    metadata_document_from_state,
    sha256_file,
)
from support import TestEnvironment  # noqa: E402


class HashAndLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = TestEnvironment()
        self.settings = load_settings(self.environment.config)
        ensure_runtime_directories(self.settings)

    def tearDown(self) -> None:
        self.environment.close()

    def test_sha256_known_vector(self) -> None:
        path = self.settings.data_dir / "vector.raw"
        atomic_write_bytes(path, b"abc")
        digest, size = sha256_file(path)
        self.assertEqual(digest, hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(size, 3)

    def test_v1_metadata_schema_stays_byte_compatible_after_duplex_upgrade(self) -> None:
        legacy = {
            "schema_version": 1,
            "job_id": "00000000-0000-4000-8000-000000000099",
            "state": "SENT_UNCONFIRMED",
            "raw_filename": "legacy.raw",
            "readable_filename": "legacy.txt",
            "raw_sha256": "a" * 64,
            # These v2-only values must never be injected into a v1 document;
            # doing so would invalidate historical metadata HMACs on upgrade.
            "bytes_printer_to_client": 1,
            "clean_filename": "legacy.PULITO.txt",
            "pdf_filename": "legacy.pdf",
        }
        document = metadata_document_from_state(legacy)
        self.assertEqual(document["schema_version"], 1)
        self.assertNotIn("bytes_printer_to_client", document)
        self.assertNotIn("clean_filename", document)
        self.assertNotIn("pdf_filename", document)

        current = dict(legacy, schema_version=2)
        current_document = metadata_document_from_state(current)
        self.assertEqual(current_document["bytes_printer_to_client"], 1)
        self.assertEqual(current_document["clean_filename"], "legacy.PULITO.txt")
        self.assertEqual(current_document["pdf_filename"], "legacy.pdf")

    def test_chain_hmac_and_file_tamper_detection(self) -> None:
        key = load_hmac_key(self.settings, cli=True)
        ledger = IntegrityLedger(self.settings, key)
        raw = self.settings.data_dir / "job.raw"
        metadata = self.settings.data_dir / "job.json"
        atomic_write_bytes(raw, b"unchanged bytes")
        raw_hash, size = sha256_file(raw)
        state = {
            "schema_version": 1,
            "job_id": "00000000-0000-4000-8000-000000000001",
            "state": "SEALED",
            "raw_filename": raw.name,
            "metadata_filename": metadata.name,
            "raw_sha256": raw_hash,
            "bytes_received": size,
            "bytes_archived": size,
            "bytes_forwarded": 0,
            "attempts": 0,
            "queue_order": "00000000000000000001-job",
            "last_committed_event": "ARCHIVED",
        }
        atomic_write_json(metadata, metadata_document_from_state(state))
        metadata_hash, _ = sha256_file(metadata)
        ledger.append(
            {
                "event": "ARCHIVED",
                "job_id": "00000000-0000-4000-8000-000000000001",
                "status": "SEALED",
                "raw_filename": raw.name,
                "raw_sha256": raw_hash,
                "raw_size": size,
                "metadata_filename": metadata.name,
                "metadata_sha256": metadata_hash,
                "source": "127.0.0.1:1",
                "destination": "127.0.0.1:9100",
            }
        )
        state["metadata_sha256"] = metadata_hash
        StateStore(self.settings).write(state)
        self.assertTrue(ledger.verify(check_files=True).ok)
        raw.write_bytes(b"changed bytes")
        report = ledger.verify(check_files=True)
        self.assertFalse(report.ok)
        self.assertTrue(any("SHA-256 mismatch" in error for error in report.errors))

    def test_manifest_reorder_is_detected(self) -> None:
        ledger = IntegrityLedger(self.settings, load_hmac_key(self.settings, cli=True))
        for index in range(2):
            ledger.append(
                {
                    "event": "TEST",
                    "job_id": f"00000000-0000-4000-8000-{index:012d}",
                    "status": "TEST",
                    "raw_filename": f"missing-{index}.raw",
                    "raw_sha256": "0" * 64,
                    "raw_size": 0,
                    "metadata_filename": f"missing-{index}.json",
                    "metadata_sha256": "0" * 64,
                }
            )
        lines = self.settings.manifest_path.read_bytes().splitlines(keepends=True)
        self.settings.manifest_path.write_bytes(lines[1] + lines[0])
        report = ledger.verify(check_files=False)
        self.assertFalse(report.ok)
        self.assertTrue(any("sequence" in error or "previous hash" in error for error in report.errors))

    def test_route_scoped_ledger_rejects_clone_and_mixed_destination_append(self) -> None:
        updates = {
            "LISTEN_IP": "127.0.0.21,127.0.0.22",
            "LISTEN_PORT": "19101,19102",
            "PRINTER_IP": "127.0.0.11,127.0.0.12",
            "PRINTER_PORT": "19201,19202",
        }
        rewritten: list[str] = []
        for line in self.environment.config.read_text(encoding="utf-8").splitlines():
            key = line.split("=", 1)[0]
            rewritten.append(f"{key}={updates.pop(key)}" if key in updates else line)
        self.environment.config.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        master = load_settings(self.environment.config)
        ensure_runtime_directories(master)
        source = master.for_proxy(master.proxy_configs[0])
        target = master.for_proxy(master.proxy_configs[1])
        key = load_hmac_key(master, cli=True)
        ledger = IntegrityLedger(source, key)

        record = ledger.append(
            {
                "event": "RETENTION_DELETED",
                "job_id": "00000000-0000-4000-8000-000000000777",
            }
        )
        self.assertEqual(record["destination"], "127.0.0.11:19201")
        with self.assertRaisesRegex(IntegrityError, "destination.*physical printer scope"):
            ledger.append(
                {
                    "event": "RETENTION_DELETED",
                    "job_id": "00000000-0000-4000-8000-000000000778",
                    "destination": "127.0.0.12:19202",
                }
            )

        shutil.copy2(source.manifest_path, target.manifest_path)
        shutil.copy2(source.manifest_head_path, target.manifest_head_path)
        with self.assertRaisesRegex(IntegrityError, "route binding"):
            IntegrityLedger(target, key, repair_head=False)

    def test_flat_legacy_ledger_remains_unbound_and_byte_compatible(self) -> None:
        ledger = IntegrityLedger(self.settings, load_hmac_key(self.settings, cli=True))
        record = ledger.append(
            {
                "event": "LEGACY_TEST",
                "job_id": "00000000-0000-4000-8000-000000000779",
            }
        )
        self.assertNotIn("destination", record)
        self.assertTrue(ledger.verify(check_files=False).ok)

    def test_read_only_offline_verification_never_creates_manifest_lock(self) -> None:
        key = load_hmac_key(self.settings, cli=True)
        ledger = IntegrityLedger(self.settings, key)
        ledger.append(
            {
                "event": "TEST",
                "job_id": "00000000-0000-4000-8000-000000000780",
            }
        )
        lock_path = self.settings.locks_dir / "manifest.lock"
        lock_path.unlink()

        read_only = IntegrityLedger(
            self.settings,
            key,
            repair_head=False,
            read_only=True,
        )
        self.assertTrue(read_only.verify(check_files=False).ok)
        self.assertFalse(lock_path.exists())
        with self.assertRaisesRegex(ValueError, "read-only ledger"):
            read_only.verify(check_files=False, repair_head=True)
        self.assertFalse(lock_path.exists())
        with self.assertRaisesRegex(IntegrityError, "read-only ledger"):
            read_only.append(
                {
                    "event": "TEST",
                    "job_id": "00000000-0000-4000-8000-000000000781",
                }
            )


if __name__ == "__main__":
    unittest.main()
