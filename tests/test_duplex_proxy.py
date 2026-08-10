from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import socket
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_escpos_printer import FakeEscPosPrinter  # noqa: E402
from printproxy import PrintProxyService, ReceiveResult  # noqa: E402
from printproxy_core import (  # noqa: E402
    StateStore,
    StorageError,
    ensure_runtime_directories,
    load_settings,
)
from support import TestEnvironment  # noqa: E402


def enable_duplex(environment: TestEnvironment, **values: str) -> None:
    additions = {
        "DELIVERY_MODE": "transparent_duplex",
        "PRINTER_RESPONSE_TIMEOUT": "0.75",
        "MAX_SESSION_DURATION": "5",
        **values,
    }
    lines = environment.config.read_text(encoding="utf-8").splitlines()
    remaining = dict(additions)
    rewritten: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else None
        if key in remaining:
            rewritten.append(f"{key}={remaining.pop(key)}")
        else:
            rewritten.append(line)
    rewritten.extend(f"{key}={value}" for key, value in remaining.items())
    environment.config.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


class DuplexProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fake = FakeEscPosPrinter()
        self.printer_server: asyncio.AbstractServer | None = None
        self.environment: TestEnvironment | None = None
        self.service: PrintProxyService | None = None
        self.service_task: asyncio.Task[None] | None = None

    async def start(self, fake: FakeEscPosPrinter, **config_values: str) -> None:
        self.fake = fake
        self.printer_server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        printer_port = int(self.printer_server.sockets[0].getsockname()[1])
        self.environment = TestEnvironment(printer_port=printer_port, mode="hybrid")
        enable_duplex(self.environment, **config_values)
        settings = load_settings(self.environment.config)
        ensure_runtime_directories(settings)
        self.service = PrintProxyService(settings)
        self.service_task = asyncio.create_task(self.service.run())
        for _ in range(200):
            if self.service.server is not None:
                return
            if self.service_task.done():
                await self.service_task
            await asyncio.sleep(0.01)
        self.fail("duplex proxy did not start")

    async def asyncTearDown(self) -> None:
        if self.service is not None:
            self.service.request_shutdown()
        if self.service_task is not None:
            await asyncio.wait_for(self.service_task, timeout=8)
        if self.printer_server is not None:
            self.printer_server.close()
            await self.printer_server.wait_closed()
        if self.environment is not None:
            self.environment.close()

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        assert self.service is not None
        return await asyncio.open_connection("127.0.0.1", self.service.settings.listen_port)

    async def test_dle_eot_and_binary_status_are_forwarded_byte_exact_live(self) -> None:
        payload = bytes((0, 10, 13, 27, 16, 4, 1, 29, 255)) + os.urandom(8192)
        response = b"\x12\x00\xff\x10\x04"
        await self.start(
            FakeEscPosPrinter(response=response, respond_after_bytes=len(payload))
        )
        reader, writer = await self.connect()
        writer.write(payload)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(response)), 2), response)
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.fake.received, [payload])
        assert self.service is not None
        for _ in range(200):
            states = StateStore(self.service.settings).list()
            if states and states[0].get("state") != "DUPLEX_ACTIVE":
                break
            await asyncio.sleep(0.01)
        self.assertEqual(len(states), 1)
        self.assertEqual(states[0]["state"], "SENT_UNCONFIRMED")
        self.assertEqual(states[0]["bytes_printer_received"], len(response))
        self.assertEqual(states[0]["bytes_printer_to_client"], len(response))
        self.assertEqual(states[0]["printer_response_sha256"], hashlib.sha256(response).hexdigest())
        self.assertEqual(states[0]["printer_response_hex"], response.hex())
        self.assertEqual(states[0]["realtime_status_queries"], 1)
        self.assertFalse(states[0]["retry_allowed"])

    async def test_delayed_fragmented_response_survives_client_half_close(self) -> None:
        fragments = (b"\x12", b"\x00\xff", b"\x10")
        await self.start(
            FakeEscPosPrinter(
                response_delay=0.2,
                response_fragments=fragments,
                fragment_delay=0.05,
            )
        )
        reader, writer = await self.connect()
        payload = b"receipt\x10\x04\x01"
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        expected = b"".join(fragments)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(expected)), 2), expected)
        await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.fake.received, [payload])

    async def test_slow_client_does_not_truncate_printer_response_tail(self) -> None:
        response = b"R" * (4 * 1024 * 1024 + 31)
        await self.start(
            FakeEscPosPrinter(response=response),
            PRINTER_RESPONSE_TIMEOUT="0.1",
            # The deliberately tiny receive window can take well over ten
            # seconds on virtualized Linux/DrvFS. Keep the production total
            # deadline semantics, but give this portability test enough time
            # to prove that response-idle never cancels a pending drain.
            FORWARD_TIMEOUT="60",
            MAX_SESSION_DURATION="90",
            ENABLE_READABLE_DUMP="no",
            ENABLE_HEX_DUMP="no",
            SAVE_CLEAN_TXT="no",
            SAVE_PDF="no",
        )
        assert self.service is not None
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.service.settings.listen_port, limit=1024
        )
        raw_socket = writer.get_extra_info("socket")
        if raw_socket is not None:
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        writer.write(b"response-tail")
        await writer.drain()
        writer.write_eof()
        await asyncio.sleep(0.3)
        received = bytearray()
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), 12)
            if not chunk:
                break
            received.extend(chunk)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(bytes(received), response)

        for _ in range(400):
            states = StateStore(self.service.settings).list()
            if states and states[0].get("state") != "DUPLEX_ACTIVE":
                break
            await asyncio.sleep(0.01)
        self.assertEqual(states[0]["state"], "SENT_UNCONFIRMED")
        self.assertEqual(states[0]["bytes_printer_received"], len(response))
        self.assertEqual(states[0]["bytes_submitted_to_client"], len(response))
        self.assertEqual(states[0]["bytes_printer_to_client"], len(response))

    async def test_clean_response_idle_closes_without_false_unknown(self) -> None:
        await self.start(
            FakeEscPosPrinter(hold_open_after_eof=0.5),
            PRINTER_RESPONSE_TIMEOUT="0.1",
        )
        reader, writer = await self.connect()
        writer.write(b"complete-no-status")
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()
        assert self.service is not None
        for _ in range(300):
            states = StateStore(self.service.settings).list()
            if states and states[0].get("state") != "DUPLEX_ACTIVE":
                break
            await asyncio.sleep(0.01)
        self.assertEqual(states[0]["state"], "SENT_UNCONFIRMED")
        self.assertIsNone(states[0]["last_error"])

    async def test_late_response_before_next_segment_is_audited_on_previous_job(self) -> None:
        first = b"first-segment\x10\x04\x01"
        second = b"second-segment"
        await self.start(
            FakeEscPosPrinter(
                response=b"\x12",
                response_delay=0.2,
                respond_after_bytes=len(first),
            )
        )
        reader, writer = await self.connect()
        writer.write(first)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 2), b"\x12")
        writer.write(second)
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()

        assert self.service is not None
        states: list[dict[str, object]] = []
        for _ in range(400):
            states = StateStore(self.service.settings).list()
            if len(states) == 2 and all(item.get("state") == "SENT_UNCONFIRMED" for item in states):
                break
            await asyncio.sleep(0.01)
        by_raw = {
            (self.service.settings.data_dir / str(item["raw_filename"])).read_bytes(): item
            for item in states
        }
        self.assertEqual(by_raw[first]["bytes_printer_to_client"], 1)
        self.assertEqual(by_raw[first]["printer_response_hex"], "12")
        self.assertEqual(by_raw[second]["bytes_printer_to_client"], 0)

    async def test_completed_job_has_four_receipt_artifacts_and_authenticated_hashes(self) -> None:
        await self.start(FakeEscPosPrinter())
        reader, writer = await self.connect()
        payload = (
            b"\x1b@Operatore: 10/08/26  23:45\n"
            b"\x1bE\x01Portata: 1\n\x1bE\x00"
            b"1x Acqua friz\n   zante picc\n   ola\n"
            b"Coperti: 1\n\x10\x04\x01"
        )
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()

        assert self.service is not None
        state: dict[str, object] | None = None
        for _ in range(300):
            states = StateStore(self.service.settings).list()
            if states and states[0].get("state") == "SENT_UNCONFIRMED":
                state = states[0]
                break
            await asyncio.sleep(0.01)
        self.assertIsNotNone(state)
        assert state is not None
        raw_path = self.service.settings.data_dir / str(state["raw_filename"])
        technical_path = raw_path.with_suffix(".txt")
        clean_path = raw_path.with_suffix(".PULITO.txt")
        pdf_path = raw_path.with_suffix(".pdf")
        self.assertEqual(raw_path.read_bytes(), payload)
        self.assertIn("[ESC/POS INIT]", technical_path.read_text(encoding="utf-8"))
        clean = clean_path.read_text(encoding="utf-8")
        self.assertIn("1x Acqua frizzante piccola", clean)
        self.assertNotIn("[ESC/POS", clean)
        self.assertEqual(pdf_path.read_bytes()[:5], b"%PDF-")
        self.assertEqual(state["clean_sha256"], hashlib.sha256(clean_path.read_bytes()).hexdigest())
        self.assertEqual(state["pdf_sha256"], hashlib.sha256(pdf_path.read_bytes()).hexdigest())
        self.assertEqual(state["render_status"], "complete")
        report = self.service.ledger.verify(check_files=True)
        self.assertTrue(report.ok, report.errors)
        clean_path.write_text(clean + "altered\n", encoding="utf-8")
        tampered = self.service.ledger.verify(check_files=True)
        self.assertFalse(tampered.ok)
        self.assertTrue(any("clean receipt SHA-256 mismatch" in item for item in tampered.errors))

    async def test_server_first_bytes_reach_client_before_client_payload(self) -> None:
        greeting = b"\xaa\x00\x55"
        await self.start(FakeEscPosPrinter(server_first=greeting))
        reader, writer = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(greeting)), 2), greeting)
        writer.write(b"after-greeting")
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.fake.received, [b"after-greeting"])

    async def test_large_fragmented_request_remains_byte_exact(self) -> None:
        payload = os.urandom(2 * 1024 * 1024 + 137)
        await self.start(
            FakeEscPosPrinter(response=b"\x12", respond_after_bytes=len(payload)),
            MAX_SESSION_DURATION="30",
            CHUNK_SIZE="65536",
            FSYNC_INTERVAL_BYTES="262144",
            ENABLE_READABLE_DUMP="no",
            ENABLE_HEX_DUMP="no",
            SAVE_CLEAN_TXT="no",
            SAVE_PDF="no",
        )
        reader, writer = await self.connect()
        for offset in range(0, len(payload), 7919):
            writer.write(payload[offset : offset + 7919])
            await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 5), b"\x12")
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 5)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.fake.received, [payload])

    async def test_printer_reset_after_send_is_unknown_and_not_retryable(self) -> None:
        payload = b"printed-before-reset"
        await self.start(FakeEscPosPrinter(reset_after_bytes=len(payload)))
        reader, writer = await self.connect()
        writer.write(payload)
        await writer.drain()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await asyncio.wait_for(reader.read(), 2)
        writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await writer.wait_closed()
        assert self.service is not None
        state: dict[str, object] | None = None
        for _ in range(300):
            states = StateStore(self.service.settings).list()
            if states and states[0].get("state") != "DUPLEX_ACTIVE":
                state = states[0]
                break
            await asyncio.sleep(0.01)
        self.assertIsNotNone(state)
        assert state is not None
        # Windows can normalize an abortive close that follows all accepted
        # bytes to EOF; both terminal classifications remain non-replayable.
        self.assertIn(state["state"], {"UNKNOWN_PRINT_STATE", "SENT_UNCONFIRMED"})
        self.assertFalse(state["retry_allowed"])
        self.assertEqual(self.service.scheduler._versions, {})

    async def test_max_session_duration_resets_live_session_and_marks_unknown(self) -> None:
        await self.start(
            FakeEscPosPrinter(), MAX_SESSION_DURATION="1", IDLE_TIMEOUT="2"
        )
        reader, writer = await self.connect()
        writer.write(b"session-timeout")
        await writer.drain()
        await asyncio.sleep(1.2)
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await asyncio.wait_for(reader.read(), 2)
        writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await writer.wait_closed()
        assert self.service is not None
        for _ in range(300):
            states = StateStore(self.service.settings).list()
            if states and states[0].get("state") != "DUPLEX_ACTIVE":
                break
            await asyncio.sleep(0.01)
        self.assertEqual(states[0]["state"], "UNKNOWN_PRINT_STATE")
        self.assertEqual(states[0]["boundary_reason"], "max_session_duration_exceeded")

    async def test_second_live_client_is_rejected_while_printer_session_busy(self) -> None:
        await self.start(FakeEscPosPrinter())
        first_reader, first_writer = await self.connect()
        await asyncio.wait_for(self.fake.accepted.wait(), 2)
        second_reader, second_writer = await self.connect()
        second_writer.write(b"must-not-print")
        with self.assertRaises((ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError)):
            await asyncio.wait_for(second_reader.readexactly(1), 2)
        second_writer.close()
        try:
            await second_writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        self.assertEqual(self.fake.connections, 1)
        first_writer.write(b"first-only")
        await first_writer.drain()
        first_writer.write_eof()
        await asyncio.wait_for(first_reader.read(), 2)
        first_writer.close()
        await first_writer.wait_closed()
        self.assertEqual(self.fake.received, [b"first-only"])


class DuplexRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplex_startup_refuses_replayable_store_forward_backlog(self) -> None:
        environment = TestEnvironment(mode="connection_close")
        initial_settings = load_settings(environment.config)
        ensure_runtime_directories(initial_settings)
        legacy = PrintProxyService(initial_settings)
        try:
            state, temporary = legacy._new_receiving_state(
                "legacy-session", "127.0.0.1", 12345, time.monotonic()
            )
            payload = b"legacy-queued-job"
            fd = legacy._open_receiving_file(temporary)
            try:
                legacy._write_receiving(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            state["bytes_received"] = len(payload)
            state["bytes_archived"] = len(payload)
            legacy.store.write(state)
            await legacy._seal_result(
                ReceiveResult(
                    state=state,
                    temp_path=temporary,
                    complete=True,
                    boundary_reason="connection_close",
                    idle_timeout_triggered=False,
                    connection_closed=True,
                )
            )
            self.assertEqual(legacy.store.load(state["job_id"])["state"], "QUEUED")

            enable_duplex(environment)
            duplex = PrintProxyService(load_settings(environment.config))
            with self.assertRaisesRegex(StorageError, "legacy backlog"):
                await duplex.recover()
            self.assertIsNone(duplex.server)
        finally:
            environment.close()

    async def test_read_failure_race_preserves_bytes_already_removed_from_reader(self) -> None:
        environment = TestEnvironment(mode="hybrid")
        enable_duplex(environment)
        settings = load_settings(environment.config)
        ensure_runtime_directories(settings)
        service = PrintProxyService(settings)
        reader = asyncio.StreamReader()
        reader.feed_data(b"must-remain-in-raw")

        class FailedRelay:
            failure_event = asyncio.Event()
            stream_error = ConnectionResetError("printer reset")

        relay = FailedRelay()
        relay.failure_event.set()
        try:
            data = await service._read_with_timeout(reader, 1, relay)  # type: ignore[arg-type]
            self.assertEqual(data, b"must-remain-in-raw")
        finally:
            environment.close()

    async def test_authenticated_active_crash_recovers_unknown_without_replay(self) -> None:
        environment = TestEnvironment(mode="hybrid")
        enable_duplex(environment)
        settings = load_settings(environment.config)
        ensure_runtime_directories(settings)
        service = PrintProxyService(settings)
        try:
            state, temporary = service._new_receiving_state(
                "crash-session", "127.0.0.1", 12345, time.monotonic()
            )
            payload = b"may-have-printed\x10\x04\x01"
            fd = service._open_receiving_file(temporary)
            try:
                service._write_receiving(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            state["bytes_received"] = len(payload)
            state["bytes_archived"] = len(payload)
            state["bytes_forwarded"] = len(payload)
            state["bytes_submitted_to_socket"] = len(payload)
            state["bytes_client_to_printer"] = len(payload)
            state["attempt_id"] = "00000000-0000-0000-0000-000000000001"
            state["attempts"] = 1
            state["state"] = "DUPLEX_ACTIVE"
            state["forward_status"] = "live_send_armed_unconfirmed"
            service._persist_state_event(state, "DUPLEX_ACTIVE")

            recovered = PrintProxyService(settings)
            await recovered.recover()
            final = StateStore(settings).load(state["job_id"])
            self.assertEqual(final["state"], "UNKNOWN_PRINT_STATE")
            self.assertFalse(final["retry_allowed"])
            self.assertEqual(list(settings.data_dir.glob("*.raw"))[0].read_bytes(), payload)
            self.assertEqual(recovered.scheduler._versions, {})

            enable_duplex(environment, BLOCK_QUEUE_ON_UNKNOWN="yes")
            blocked = PrintProxyService(load_settings(environment.config))
            with self.assertRaisesRegex(StorageError, "legacy backlog"):
                await blocked.recover()
        finally:
            environment.close()


if __name__ == "__main__":
    unittest.main()
