from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from printproxy import PrintProxyService  # noqa: E402
from printproxy_core import (  # noqa: E402
    ConfigError,
    IntegrityError,
    IntegrityLedger,
    atomic_write_bytes,
    atomic_write_json,
    ensure_runtime_directories,
    load_settings,
    utc_now,
)
from support import TestEnvironment  # noqa: E402


class AdversarialFailureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.environment = TestEnvironment()
        self.settings = load_settings(self.environment.config)
        ensure_runtime_directories(self.settings)
        self.service = PrintProxyService(self.settings)

    async def asyncTearDown(self) -> None:
        self.environment.close()

    async def _queued_job(self, payload: bytes = b"adversarial-job") -> dict[str, object]:
        state, temporary = self.service._new_receiving_state(
            "session", "127.0.0.1", 1234, 1.0
        )
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
        self.service.store.write(state)
        await self.service._recover_sealed(state)
        return self.service.store.load(state["job_id"])

    async def test_metadata_tamper_before_forward_never_connects_or_rewrites_evidence(
        self,
    ) -> None:
        queued = await self._queued_job()
        metadata_path = self.service._metadata_path(queued)
        tampered = b'{"tampered":true}\n'
        metadata_path.write_bytes(tampered)

        connect = mock.AsyncMock()
        with mock.patch("printproxy.asyncio.open_connection", connect):
            await self.service._forward_job(str(queued["job_id"]))

        connect.assert_not_awaited()
        self.assertIsNotNone(self.service.fatal_exception)
        self.assertEqual(metadata_path.read_bytes(), tampered)
        self.assertEqual(
            self.service.ledger.latest_job_record(str(queued["job_id"]))["event"],
            "QUEUED",
        )
        self.assertFalse(self.service.ledger.verify(check_files=True).ok)

    async def test_split_on_escpos_cut_is_explicitly_rejected(self) -> None:
        config_text = self.environment.config.read_text(encoding="utf-8")
        self.assertIn("SPLIT_ON_ESCPOS_CUT=no", config_text)
        self.environment.config.write_text(
            config_text.replace(
                "SPLIT_ON_ESCPOS_CUT=no", "SPLIT_ON_ESCPOS_CUT=yes", 1
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ConfigError, r"SPLIT_ON_ESCPOS_CUT=yes.*unsafe"
        ):
            load_settings(self.environment.config)

    async def test_full_offline_verify_detects_same_length_prefix_tamper(self) -> None:
        self.service.ledger.append(
            {
                "event": "PREFIX_A",
                "job_id": "00000000-0000-4000-8000-000000000201",
            }
        )
        self.service.ledger.append(
            {
                "event": "UNCHANGED_TAIL",
                "job_id": "00000000-0000-4000-8000-000000000202",
            }
        )
        original_manifest = self.settings.manifest_path.read_bytes()
        original_lines = original_manifest.splitlines(keepends=True)
        original_head = self.settings.manifest_head_path.read_bytes()
        self.assertGreaterEqual(len(original_lines), 2)

        tampered_first = original_lines[0].replace(
            b'"PREFIX_A"', b'"PREFIX_B"', 1
        )
        self.assertNotEqual(tampered_first, original_lines[0])
        self.assertEqual(len(tampered_first), len(original_lines[0]))
        tampered_manifest = b"".join([tampered_first, *original_lines[1:]])
        self.assertEqual(len(tampered_manifest), len(original_manifest))
        self.settings.manifest_path.write_bytes(tampered_manifest)

        tampered_lines = self.settings.manifest_path.read_bytes().splitlines(
            keepends=True
        )
        self.assertEqual(tampered_lines[-1], original_lines[-1])
        self.assertEqual(self.settings.manifest_head_path.read_bytes(), original_head)
        report = self.service.ledger.verify(check_files=False, repair_head=False)
        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "chain hash mismatch" in error or "HMAC mismatch" in error
                for error in report.errors
            )
        )
        with self.assertRaises(IntegrityError):
            IntegrityLedger(self.settings, self.service.key, repair_head=False)

    async def test_verify_reports_metadata_directory_without_raising(self) -> None:
        queued = await self._queued_job()
        metadata_path = self.service._metadata_path(queued)
        metadata_path.unlink()
        metadata_path.mkdir()

        report = self.service.ledger.verify(check_files=True)

        self.assertFalse(report.ok)
        self.assertTrue(any("metadata" in error.lower() for error in report.errors))

    async def test_verify_reports_metadata_symlink_without_raising(self) -> None:
        queued = await self._queued_job()
        metadata_path = self.service._metadata_path(queued)
        target = self.environment.root / "metadata-symlink-target.json"
        target.write_bytes(metadata_path.read_bytes())
        metadata_path.unlink()
        try:
            metadata_path.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable on this platform: {exc}")

        report = self.service.ledger.verify(check_files=True)

        self.assertFalse(report.ok)
        self.assertTrue(any("metadata" in error.lower() for error in report.errors))

    async def test_verify_reports_non_object_operational_state(self) -> None:
        queued = await self._queued_job()
        self.service.store.path_for(str(queued["job_id"])).write_text(
            "[]\n", encoding="utf-8"
        )

        report = self.service.ledger.verify(check_files=True)

        self.assertFalse(report.ok)
        self.assertTrue(any("state" in error.lower() for error in report.errors))

    async def test_tampered_outbox_auth_is_rejected_on_recovery(self) -> None:
        queued = await self._queued_job()
        queued["state"] = "SEND_ARMED"
        queued["forward_status"] = "connecting_no_bytes_sent"
        queued["attempts"] = 1

        with mock.patch.object(
            self.service.ledger,
            "append",
            side_effect=OSError("injected append failure"),
        ):
            with self.assertRaises(OSError):
                self.service._persist_state_event(queued, "SEND_ARMED")

        pending = self.service.store.load(str(queued["job_id"]))
        pending["pending_outbox_auth"]["digest"] = "0" * 64
        self.service.store.write(pending)

        restarted = PrintProxyService(self.settings)
        with self.assertRaises(IntegrityError):
            await restarted.recover()
        self.assertEqual(
            restarted.ledger.latest_job_record(str(queued["job_id"]))["event"],
            "QUEUED",
        )

    async def test_forged_retention_deleted_state_cannot_unlink_artifacts(self) -> None:
        queued = await self._queued_job(b"must-survive-forged-retention")
        queued["state"] = "SEND_ARMED"
        queued["forward_status"] = "connecting_no_bytes_sent"
        queued["attempts"] = 1
        self.service._persist_state_event(queued, "SEND_ARMED")
        queued["state"] = "SENDING"
        queued["forward_status"] = "sending_unconfirmed"
        self.service._persist_state_event(queued, "SENDING")
        queued["state"] = "SENT_UNCONFIRMED"
        queued["forward_status"] = "tcp_stream_forwarded_physical_unconfirmed"
        queued["bytes_forwarded"] = queued["bytes_archived"]
        queued["physical_print_confirmed"] = False
        self.service._persist_state_event(queued, "SENT_UNCONFIRMED")

        tampered = self.service.store.load(str(queued["job_id"]))
        raw_path = self.service._raw_path(tampered)
        metadata_path = self.service._metadata_path(tampered)
        state_path = self.service.store.path_for(str(tampered["job_id"]))
        original_raw = raw_path.read_bytes()
        original_metadata = metadata_path.read_bytes()
        tampered["state"] = "RETENTION_DELETED"
        self.service.store.write(tampered)
        original_state = state_path.read_bytes()

        with self.assertRaises(IntegrityError):
            await self.service._complete_retention(tampered)

        self.assertEqual(raw_path.read_bytes(), original_raw)
        self.assertEqual(metadata_path.read_bytes(), original_metadata)
        self.assertEqual(state_path.read_bytes(), original_state)
        self.assertEqual(
            self.service.ledger.latest_job_record(str(tampered["job_id"]))["event"],
            "SENT_UNCONFIRMED",
        )

    async def test_retry_ledger_failure_keeps_durable_request(self) -> None:
        queued = await self._queued_job()
        request_path = self.service.store.create_request(
            {
                "schema_version": 1,
                "action": "retry",
                "job_id": queued["job_id"],
                "confirm_unknown": False,
                "requested_at": utc_now(),
                "requested_uid": 0,
                "reason": "injected ledger failure",
            }
        )
        original_append = self.service.ledger.append

        def fail_manual_retry(event: dict[str, object]) -> dict[str, object]:
            if event.get("event") == "MANUAL_RETRY_QUEUED":
                raise OSError("injected retry ledger failure")
            return original_append(event)

        with mock.patch.object(
            self.service.ledger, "append", side_effect=fail_manual_retry
        ):
            await self.service._process_retry_request(request_path)

        self.assertTrue(request_path.is_file())
        self.assertIsNotNone(self.service.fatal_exception)
        pending = self.service.store.load(str(queued["job_id"]))
        self.assertEqual(
            pending.get("pending_ledger_event", {}).get("event"),
            "MANUAL_RETRY_QUEUED",
        )

    async def test_replayed_retry_request_is_idempotent(self) -> None:
        queued = await self._queued_job()
        request_path = self.service.store.create_request(
            {
                "schema_version": 1,
                "action": "retry",
                "job_id": queued["job_id"],
                "confirm_unknown": False,
                "requested_at": utc_now(),
                "requested_uid": 0,
                "reason": "idempotency test",
            }
        )
        request_document = json.loads(request_path.read_text(encoding="utf-8"))
        self.service.scheduler.put = mock.AsyncMock()

        await self.service._process_retry_request(request_path)
        self.assertFalse(request_path.exists())
        atomic_write_json(request_path, request_document)
        await self.service._process_retry_request(request_path)

        self.assertFalse(request_path.exists())
        self.service.scheduler.put.assert_awaited_once()
        records = [
            json.loads(line)
            for line in self.settings.manifest_path.read_text(encoding="utf-8").splitlines()
        ]
        retry_events = [
            record
            for record in records
            if record.get("job_id") == queued["job_id"]
            and record.get("event") == "MANUAL_RETRY_QUEUED"
        ]
        self.assertEqual(len(retry_events), 1)


if __name__ == "__main__":
    unittest.main()
