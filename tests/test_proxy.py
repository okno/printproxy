from __future__ import annotations

import asyncio
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from printproxy import PrintProxyService  # noqa: E402
from printproxy_core import StateStore, ensure_runtime_directories, load_settings  # noqa: E402
from support import TestEnvironment, free_tcp_port  # noqa: E402


class FakePrinter:
    def __init__(self) -> None:
        self.jobs: list[bytes] = []
        self.event = asyncio.Event()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = bytearray()
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            data.extend(chunk)
        self.jobs.append(bytes(data))
        self.event.set()
        writer.close()
        await writer.wait_closed()


class ProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fake = FakePrinter()
        self.printer_server = await asyncio.start_server(self.fake.handle, "127.0.0.1", 0)
        printer_port = int(self.printer_server.sockets[0].getsockname()[1])
        self.environment = TestEnvironment(printer_port=printer_port)
        self.settings = load_settings(self.environment.config)
        ensure_runtime_directories(self.settings)
        self.service = PrintProxyService(self.settings)
        self.service_task = asyncio.create_task(self.service.run())
        for _ in range(100):
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", self.settings.listen_port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.01)
        else:
            self.fail("proxy did not start")

    async def asyncTearDown(self) -> None:
        self.service.request_shutdown()
        await asyncio.wait_for(self.service_task, timeout=5)
        self.printer_server.close()
        await self.printer_server.wait_closed()
        self.environment.close()

    async def _submit(self, payload: bytes) -> None:
        _, writer = await asyncio.open_connection("127.0.0.1", self.settings.listen_port)
        writer.write(payload)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _submit_fragmented(self, payload: bytes) -> None:
        _, writer = await asyncio.open_connection("127.0.0.1", self.settings.listen_port)
        for byte in payload:
            writer.write(bytes((byte,)))
            await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _wait_for_jobs(self, count: int) -> None:
        for _ in range(300):
            if len(self.fake.jobs) >= count:
                return
            await asyncio.sleep(0.01)
        self.fail(f"expected {count} printer jobs, got {len(self.fake.jobs)}")

    async def test_raw_is_archived_and_forwarded_byte_exact(self) -> None:
        payload = bytes(range(256)) * 17 + b"\x1dV\x00"
        await self._submit(payload)
        await self._wait_for_jobs(1)
        self.assertEqual(self.fake.jobs[0], payload)
        raws = list(self.settings.data_dir.glob("*.raw"))
        self.assertEqual(len(raws), 1)
        self.assertEqual(raws[0].read_bytes(), payload)
        state = StateStore(self.settings).list()[0]
        self.assertEqual(state["raw_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(state["state"], "SENT_UNCONFIRMED")
        self.assertFalse(state["physical_print_confirmed"])

    async def test_concurrent_clients_are_never_interleaved(self) -> None:
        payloads = [b"A" * 20000, b"B" * 17000]
        await asyncio.gather(*(self._submit(payload) for payload in payloads))
        await self._wait_for_jobs(2)
        self.assertCountEqual(self.fake.jobs, payloads)
        self.assertTrue(all(set(job) in ({65}, {66}) for job in self.fake.jobs))

    async def test_tcp_fragmentation_does_not_change_raw(self) -> None:
        payload = b"fragmented-" + bytes(range(256))
        await self._submit_fragmented(payload)
        await self._wait_for_jobs(1)
        self.assertEqual(self.fake.jobs[0], payload)
        self.assertEqual(list(self.settings.data_dir.glob("*.raw"))[0].read_bytes(), payload)

    async def test_post_send_ledger_failure_never_becomes_retry_safe(self) -> None:
        original_append = self.service.ledger.append
        failed_once = False

        def fail_sent_once(event):
            nonlocal failed_once
            if event.get("event") == "SENT_UNCONFIRMED" and not failed_once:
                failed_once = True
                raise OSError("injected audit write failure after send")
            return original_append(event)

        self.service.ledger.append = fail_sent_once
        await self._submit(b"single physical delivery")
        await self._wait_for_jobs(1)
        for _ in range(200):
            states = StateStore(self.settings).list()
            if states and states[0].get("state") == "SENT_UNCONFIRMED":
                break
            await asyncio.sleep(0.01)
        self.assertTrue(failed_once)
        self.assertEqual(states[0]["state"], "SENT_UNCONFIRMED")
        self.assertNotEqual(states[0]["state"], "FAILED_BEFORE_SEND")
        self.assertEqual(len(self.fake.jobs), 1)


class PersistentHybridTests(unittest.IsolatedAsyncioTestCase):
    async def test_idle_boundary_creates_two_non_interleaved_jobs_on_one_session(self) -> None:
        fake = FakePrinter()
        printer_server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        printer_port = int(printer_server.sockets[0].getsockname()[1])
        environment = TestEnvironment(printer_port=printer_port, mode="hybrid")
        settings = load_settings(environment.config)
        ensure_runtime_directories(settings)
        service = PrintProxyService(settings)
        task = asyncio.create_task(service.run())
        try:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", settings.listen_port)
                    break
                except OSError:
                    await asyncio.sleep(0.01)
            writer.write(b"FIRST")
            await writer.drain()
            await asyncio.sleep(0.25)
            writer.write(b"SECOND")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            for _ in range(400):
                if len(fake.jobs) >= 2:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(fake.jobs, [b"FIRST", b"SECOND"])
            raws = [path.read_bytes() for path in sorted(settings.data_dir.glob("*.raw"))]
            self.assertEqual(raws, [b"FIRST", b"SECOND"])
        finally:
            service.request_shutdown()
            await asyncio.wait_for(task, timeout=5)
            printer_server.close()
            await printer_server.wait_closed()
            environment.close()


class OfflinePrinterTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_job_remains_durable_and_safe_retry(self) -> None:
        environment = TestEnvironment(printer_port=free_tcp_port())
        settings = load_settings(environment.config)
        ensure_runtime_directories(settings)
        service = PrintProxyService(settings)
        task = asyncio.create_task(service.run())
        try:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", settings.listen_port)
                    writer.write(b"offline payload")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.01)
            for _ in range(200):
                states = StateStore(settings).list()
                if states and states[0].get("state") == "FAILED_BEFORE_SEND":
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(states[0]["state"], "FAILED_BEFORE_SEND")
            self.assertEqual(list(settings.data_dir.glob("*.raw"))[0].read_bytes(), b"offline payload")
        finally:
            service.request_shutdown()
            await asyncio.wait_for(task, timeout=5)
            environment.close()


if __name__ == "__main__":
    unittest.main()
