from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from printproxy import PrintProxyService  # noqa: E402
from printproxy_core import (  # noqa: E402
    IntegrityError,
    IntegrityLedger,
    StateStore,
    atomic_write_bytes,
    atomic_write_json,
    ensure_runtime_directories,
    load_hmac_key,
    load_settings,
    sha256_file,
)
from support import TestEnvironment  # noqa: E402


class IntegrityFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = TestEnvironment()
        self.settings = load_settings(self.environment.config)
        ensure_runtime_directories(self.settings)
        self.key = load_hmac_key(self.settings, cli=True)

    def tearDown(self) -> None:
        self.environment.close()

    def _append_archived(self, ledger: IntegrityLedger) -> tuple[Path, Path]:
        raw = self.settings.data_dir / "2026-01-01T00-00-00.000000Z_00000000-0000-4000-8000-000000000123.raw"
        metadata = raw.with_suffix(".json")
        atomic_write_bytes(raw, b"original")
        atomic_write_bytes(metadata, b"{}\n")
        raw_hash, size = sha256_file(raw)
        meta_hash, _ = sha256_file(metadata)
        ledger.append(
            {
                "event": "ARCHIVED",
                "job_id": "00000000-0000-4000-8000-000000000123",
                "status": "SEALED",
                "raw_filename": raw.name,
                "raw_sha256": raw_hash,
                "raw_size": size,
                "metadata_filename": metadata.name,
                "metadata_sha256": meta_hash,
            }
        )
        return raw, metadata

    def test_missing_metadata_is_an_integrity_error(self) -> None:
        ledger = IntegrityLedger(self.settings, self.key)
        _, metadata = self._append_archived(ledger)
        metadata.unlink()
        report = ledger.verify(check_files=True)
        self.assertFalse(report.ok)
        self.assertTrue(any("metadata unavailable" in error for error in report.errors))

    def test_missing_head_never_auto_reanchors_nonempty_manifest(self) -> None:
        ledger = IntegrityLedger(self.settings, self.key)
        self._append_archived(ledger)
        self.settings.manifest_head_path.unlink()
        with self.assertRaises(IntegrityError):
            IntegrityLedger(self.settings, self.key)

    def test_malformed_chain_hash_reports_failure_not_exception(self) -> None:
        ledger = IntegrityLedger(self.settings, self.key)
        ledger.append({"event": "TEST", "job_id": "00000000-0000-4000-8000-000000000124"})
        record = json.loads(self.settings.manifest_path.read_text(encoding="utf-8"))
        record["chain_hash"] = "g" * 64
        self.settings.manifest_path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        report = ledger.verify(check_files=False)
        self.assertFalse(report.ok)
        self.assertTrue(any("malformed chain hash" in error for error in report.errors))

    def test_live_manifest_tamper_blocks_append(self) -> None:
        ledger = IntegrityLedger(self.settings, self.key)
        ledger.append({"event": "ONE", "job_id": "00000000-0000-4000-8000-000000000125"})
        content = self.settings.manifest_path.read_bytes()
        self.settings.manifest_path.write_bytes(content.replace(b'"ONE"', b'"BAD"'))
        with self.assertRaises(IntegrityError):
            ledger.append({"event": "TWO", "job_id": "00000000-0000-4000-8000-000000000126"})

    def test_binary_hmac_key_is_not_stripped(self) -> None:
        key = b"\n" + b"K" * 30 + b" "
        self.environment.key.write_bytes(key)
        self.assertEqual(load_hmac_key(self.settings, cli=True), key)

    def test_isolated_production_entrypoint_imports_core(self) -> None:
        script = Path(__file__).resolve().parents[1] / "printproxy.py"
        result = subprocess.run(
            [sys.executable, "-I", str(script), "--config", str(self.environment.config), "--check-config"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_object_state_is_quarantined_by_listing(self) -> None:
        bad_id = "00000000-0000-4000-8000-000000000127"
        path = self.settings.states_dir / f"{bad_id}.json"
        path.write_text("[]\n", encoding="utf-8")
        states = StateStore(self.settings).list()
        self.assertEqual(states[0]["state"], "QUARANTINED")


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.environment = TestEnvironment()
        self.settings = load_settings(self.environment.config)
        ensure_runtime_directories(self.settings)

    async def asyncTearDown(self) -> None:
        self.environment.close()

    async def test_sealed_complete_job_is_archived_and_queued_after_crash(self) -> None:
        service = PrintProxyService(self.settings)
        state, temporary = service._new_receiving_state(
            "session", "127.0.0.1", 1234, 1.0
        )
        payload = b"sealed-before-crash"
        atomic_write_bytes(temporary, payload)
        state.update(
            {
                "state": "SEALED",
                "bytes_received": len(payload),
                "bytes_archived": len(payload),
                "timestamp_last_byte": state["timestamp_start"],
                "complete_by_policy": True,
                "boundary_reason": "connection_close",
                "idle_timeout_triggered": False,
            }
        )
        service.store.write(state)
        await service.recover()
        recovered = service.store.load(state["job_id"])
        self.assertEqual(recovered["state"], "QUEUED")
        self.assertEqual(service._raw_path(recovered).read_bytes(), payload)
        self.assertEqual(recovered["last_committed_event"], "QUEUED")

    async def test_pending_queue_outbox_is_reconciled_before_scheduling(self) -> None:
        service = PrintProxyService(self.settings)
        state, temporary = service._new_receiving_state(
            "session", "127.0.0.1", 1234, 1.0
        )
        payload = b"outbox"
        atomic_write_bytes(temporary, payload)
        state.update(
            {
                "state": "SEALED",
                "bytes_received": len(payload),
                "bytes_archived": len(payload),
                "complete_by_policy": True,
                "boundary_reason": "connection_close",
            }
        )
        service.store.write(state)
        await service._recover_sealed(state)
        queued = service.store.load(state["job_id"])

        # Roll back just the QUEUED ledger record/head/state to simulate the
        # exact outbox window deterministically, then let recovery append it.
        lines = self.settings.manifest_path.read_bytes().splitlines(keepends=True)
        archived_record = json.loads(lines[-2])
        self.settings.manifest_path.write_bytes(b"".join(lines[:-1]))
        atomic_write_json(
            self.settings.manifest_head_path,
            {
                "schema_version": 1,
                "record_count": archived_record["sequence"],
                "last_chain_hash": archived_record["chain_hash"],
                "hmac_sha256": service.ledger._head_hmac(
                    archived_record["sequence"], archived_record["chain_hash"]
                ),
            },
        )
        pending_document = service._metadata_document(queued)
        pending_payload = service._event_payload(
            queued, "QUEUED", "00000000-0000-4000-8000-000000000128"
        )
        queued["pending_ledger_event"] = pending_payload
        queued["pending_metadata_document"] = pending_document
        queued["pending_outbox_auth"] = service._outbox_auth(
            pending_payload, pending_document
        )
        queued["last_committed_event"] = "ARCHIVED"
        service.store.write(queued)

        restarted = PrintProxyService(self.settings)
        await restarted.recover()
        recovered = restarted.store.load(queued["job_id"])
        self.assertNotIn("pending_ledger_event", recovered)
        self.assertEqual(recovered["last_committed_event"], "QUEUED")
        self.assertEqual(
            restarted.ledger.latest_job_record(queued["job_id"])["event"], "QUEUED"
        )

    async def test_authenticated_sent_event_overrides_rolled_back_state(self) -> None:
        service = PrintProxyService(self.settings)
        state, temporary = service._new_receiving_state(
            "session", "127.0.0.1", 1234, 1.0
        )
        payload = b"never-print-rollback"
        atomic_write_bytes(temporary, payload)
        state.update(
            {
                "state": "SEALED",
                "bytes_received": len(payload),
                "bytes_archived": len(payload),
                "complete_by_policy": True,
                "boundary_reason": "connection_close",
            }
        )
        service.store.write(state)
        await service._recover_sealed(state)
        queued = service.store.load(state["job_id"])
        queued["state"] = "SEND_ARMED"
        service._persist_state_event(queued, "SEND_ARMED")
        queued["state"] = "SENDING"
        service._persist_state_event(queued, "SENDING")
        queued["state"] = "SENT_UNCONFIRMED"
        service._persist_state_event(queued, "SENT_UNCONFIRMED")
        rolled_back = service.store.load(state["job_id"])
        rolled_back["state"] = "FAILED_BEFORE_SEND"
        rolled_back["last_committed_event"] = "FAILED_BEFORE_SEND"
        service.store.write(rolled_back)

        restarted = PrintProxyService(self.settings)
        with self.assertRaises(IntegrityError):
            await restarted.recover()
        recovered = restarted.store.load(state["job_id"])
        self.assertEqual(recovered["state"], "FAILED_BEFORE_SEND")

    async def test_unknown_operational_state_is_never_scheduled(self) -> None:
        service = PrintProxyService(self.settings)
        state, temporary = service._new_receiving_state(
            "session", "127.0.0.1", 1234, 1.0
        )
        payload = b"never-print-unknown-state"
        atomic_write_bytes(temporary, payload)
        state.update(
            {
                "state": "SEALED",
                "bytes_received": len(payload),
                "bytes_archived": len(payload),
                "complete_by_policy": True,
                "boundary_reason": "connection_close",
            }
        )
        service.store.write(state)
        await service._recover_sealed(state)
        corrupted = service.store.load(state["job_id"])
        corrupted["state"] = "TYPO"
        service.store.write(corrupted)

        restarted = PrintProxyService(self.settings)
        restarted.scheduler.put = mock.AsyncMock()
        with self.assertRaises(IntegrityError):
            await restarted.recover()
        recovered = restarted.store.load(state["job_id"])
        self.assertEqual(recovered["state"], "TYPO")
        restarted.scheduler.put.assert_not_awaited()

    async def test_unreadable_state_aborts_recovery(self) -> None:
        bad_id = "00000000-0000-4000-8000-000000000129"
        (self.settings.states_dir / f"{bad_id}.json").write_text("[]\n", encoding="utf-8")
        service = PrintProxyService(self.settings)
        with self.assertRaises(IntegrityError):
            await service.recover()

    async def test_max_duration_is_not_misclassified_as_idle_completion(self) -> None:
        settings = replace(
            self.settings,
            job_end_mode="hybrid",
            idle_timeout=1.0,
            max_job_duration=0.05,
        )
        service = PrintProxyService(settings)
        reader = asyncio.StreamReader()
        reader.feed_data(b"partial")
        result = await service._receive_one(
            reader,
            bytearray(),
            "session",
            "127.0.0.1",
            1234,
            1.0,
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertFalse(result.complete)
        self.assertFalse(result.idle_timeout_triggered)
        self.assertEqual(result.boundary_reason, "max_job_duration_exceeded")


class ProjectCompletenessTests(unittest.TestCase):
    def test_required_install_payload_exists(self) -> None:
        root = Path(__file__).resolve().parents[1]
        required = [
            "README.md",
            "install.sh",
            "uninstall.sh",
            "printproxy.py",
            "printproxy_core.py",
            "printproxyctl.py",
            "receipt_renderer.py",
            "docs/ARCHITECTURE.md",
            "docs/CONFIGURATION.md",
            "docs/ESCPOS_PROTOCOL.md",
            "docs/INSTALLATION.md",
            "docs/MULTI_PRINTER.md",
            "docs/RECEIPT_RENDERING.md",
            "docs/TROUBLESHOOTING.md",
            "docs/SECURITY.md",
            "docs/RECOVERY.md",
            "docs/TCP_PROXY.md",
            "docs/TEST_REPORT.md",
            "examples/generate_sample_receipt.py",
            "systemd/printproxy.service",
            "tests/fake_escpos_printer.py",
            "tests/test_duplex_proxy.py",
            "tests/test_receipt_renderer.py",
        ]
        missing = [name for name in required if not (root / name).is_file()]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
