from __future__ import annotations

import asyncio
import contextlib
import errno
import importlib.util
import json
import shutil
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_escpos_printer import FakeEscPosPrinter  # noqa: E402
from printproxy import MultiProxyService, PrintProxyService  # noqa: E402
from printproxy_core import (  # noqa: E402
    IntegrityError,
    StateStore,
    StorageError,
    load_settings,
    metadata_document_from_state,
)
from receipt_renderer import (  # noqa: E402
    ImageBlock,
    PdfRenderResult,
    RasterTextBlock,
    ReceiptArtifactsResult,
    ReceiptDocument,
)
from support import TestEnvironment  # noqa: E402


LISTEN_IPS = ("127.0.0.21", "127.0.0.22", "127.0.0.23")
PRINTER_IPS = ("127.0.0.11", "127.0.0.12", "127.0.0.13")


def free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind((host, 0))
        return int(candidate.getsockname()[1])


def rewrite_config(path: Path, **updates: str) -> None:
    remaining = dict(updates)
    rewritten: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0] if "=" in line else None
        if key in remaining:
            rewritten.append(f"{key}={remaining.pop(key)}")
        else:
            rewritten.append(line)
    rewritten.extend(f"{key}={value}" for key, value in remaining.items())
    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


class MultiProxyRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.environment = TestEnvironment(mode="hybrid")
        self.printer_servers: list[asyncio.AbstractServer] = []
        self.runtime: MultiProxyService | None = None
        self.runtime_task: asyncio.Task[None] | None = None

    async def asyncTearDown(self) -> None:
        if self.runtime is not None:
            self.runtime.request_shutdown()
        if self.runtime_task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.runtime_task, timeout=8)
        for server in self.printer_servers:
            server.close()
        await asyncio.gather(
            *(server.wait_closed() for server in self.printer_servers),
            return_exceptions=True,
        )
        self.environment.close()

    async def add_fake_printer(self, host: str, fake: FakeEscPosPrinter) -> int:
        server = await asyncio.start_server(fake.handle, host, 0)
        self.printer_servers.append(server)
        return int(server.sockets[0].getsockname()[1])

    def configure(self, printer_ports: tuple[int, int, int]) -> None:
        listen_ports = tuple(free_port(host) for host in LISTEN_IPS)
        rewrite_config(
            self.environment.config,
            LISTEN_IP=",".join(LISTEN_IPS),
            LISTEN_PORT=",".join(str(port) for port in listen_ports),
            PRINTER_IP=",".join(PRINTER_IPS),
            PRINTER_PORT=",".join(str(port) for port in printer_ports),
            DELIVERY_MODE="transparent_duplex",
            PRINTER_RESPONSE_TIMEOUT="0.25",
            MAX_SESSION_DURATION="5",
            FORWARD_TIMEOUT="3",
            SAVE_CLEAN_TXT="no",
            SAVE_PDF="no",
        )

    async def start_runtime(self) -> list[str]:
        settings = load_settings(self.environment.config)
        self.runtime = MultiProxyService(settings)
        with self.assertLogs("printproxy", level="INFO") as captured:
            self.runtime_task = asyncio.create_task(self.runtime.run())
            for _ in range(300):
                if self.runtime.started:
                    break
                if self.runtime_task.done():
                    await self.runtime_task
                await asyncio.sleep(0.01)
            else:
                self.fail("multi-proxy runtime did not start")
        return captured.output

    async def exchange(self, index: int, payload: bytes, reply: bytes) -> None:
        assert self.runtime is not None
        proxy = self.runtime.services[index].proxy_config
        reader, writer = await asyncio.open_connection(*proxy.listen_endpoint)
        writer.write(payload)
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        self.assertEqual(
            await asyncio.wait_for(reader.readexactly(len(reply)), timeout=3),
            reply,
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    async def wait_for_archives(self) -> None:
        assert self.runtime is not None
        for _ in range(300):
            states = [
                StateStore(service.settings).list() for service in self.runtime.services
            ]
            if all(
                len(route_states) == 1
                and route_states[0].get("state") == "SENT_UNCONFIRMED"
                for route_states in states
            ):
                return
            await asyncio.sleep(0.01)
        self.fail("route archives were not finalized")

    async def test_three_routes_are_concurrent_duplex_and_cross_route_safe(
        self,
    ) -> None:
        payloads = (
            b"kitchen-1\x00\x10\x04\x01",
            b"bar-2\xff\x10\x04\x02",
            b"terrace-3\x1b@\x10\x04\x03",
        )
        replies = (b"\x11\x00", b"\x12\xff", b"\x13\x7f")
        fakes = tuple(
            FakeEscPosPrinter(response=reply, respond_after_bytes=len(payload))
            for payload, reply in zip(payloads, replies, strict=True)
        )
        ports = tuple(
            [
                await self.add_fake_printer(host, fake)
                for host, fake in zip(PRINTER_IPS, fakes, strict=True)
            ]
        )
        self.configure(ports)
        startup_logs = await self.start_runtime()

        with self.assertLogs("printproxy", level="INFO") as job_logs:
            await asyncio.gather(
                *(
                    self.exchange(index, payloads[index], replies[index])
                    for index in range(3)
                )
            )
            await self.wait_for_archives()

        self.assertEqual(
            [fake.received for fake in fakes], [[value] for value in payloads]
        )
        assert self.runtime is not None
        self.assertEqual(len(self.runtime.servers), 3)
        self.assertEqual(
            len(
                {id(service.printer_session_lock) for service in self.runtime.services}
            ),
            3,
        )
        self.assertEqual(
            len({id(service.ledger) for service in self.runtime.services}), 3
        )
        self.assertEqual(
            len({id(service.store) for service in self.runtime.services}), 3
        )

        route_job_ids: list[str] = []
        for index, service in enumerate(self.runtime.services):
            expected_dir = self.environment.data / PRINTER_IPS[index]
            self.assertEqual(service.settings.data_dir, expected_dir)
            self.assertEqual(
                service.settings.spool_dir,
                self.environment.spool / PRINTER_IPS[index],
            )
            self.assertEqual(
                [path.read_bytes() for path in expected_dir.glob("*.raw")],
                [payloads[index]],
            )
            state = StateStore(service.settings).list()[0]
            route_job_ids.append(str(state["job_id"]))
            self.assertEqual(state["proxy_ip"], LISTEN_IPS[index])
            self.assertEqual(state["printer_ip"], PRINTER_IPS[index])
            self.assertEqual(state["bytes_printer_to_client"], len(replies[index]))
            self.assertEqual(state["realtime_status_queries"], 1)
            joined_logs = "\n".join(startup_logs + job_logs.output)
            self.assertIn(f"PROXY_ID=proxy-{index + 1:03d}", joined_logs)
            self.assertIn(
                f"LISTEN={LISTEN_IPS[index]}:{service.settings.listen_port}",
                joined_logs,
            )
            self.assertIn(f"PRINTER={PRINTER_IPS[index]}:{ports[index]}", joined_logs)
            self.assertIn(f"LISTEN_IP={LISTEN_IPS[index]}", joined_logs)
            self.assertIn(f"PRINTER_IP={PRINTER_IPS[index]}", joined_logs)
            self.assertTrue(
                any(
                    "LIVE_JOB_FINALIZED" in line
                    and f"PROXY_ID=proxy-{index + 1:03d}" in line
                    for line in job_logs.output
                )
            )

        for index, service in enumerate(self.runtime.services):
            manifest = service.settings.manifest_path.read_text(encoding="utf-8")
            self.assertIn(route_job_ids[index], manifest)
            for other_index, other_job_id in enumerate(route_job_ids):
                if other_index != index:
                    self.assertNotIn(other_job_id, manifest)

        # A multi-route deployment must never append to the old shared root.
        self.assertEqual(list(self.environment.data.glob("*.raw")), [])
        self.assertFalse((self.environment.data / "manifest.jsonl").exists())

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab not installed")
    async def test_three_routes_keep_all_receipt_sidecars_in_printer_directories(
        self,
    ) -> None:
        payloads = tuple(
            f"\x1b@Route {index}\nItem {index}\n\x10\x04\x01".encode("ascii")
            for index in range(1, 4)
        )
        replies = (b"\x41", b"\x42", b"\x43")
        fakes = tuple(
            FakeEscPosPrinter(response=reply, respond_after_bytes=len(payload))
            for payload, reply in zip(payloads, replies, strict=True)
        )
        ports = tuple(
            [
                await self.add_fake_printer(host, fake)
                for host, fake in zip(PRINTER_IPS, fakes, strict=True)
            ]
        )
        self.configure(ports)
        rewrite_config(
            self.environment.config,
            ENABLE_READABLE_DUMP="yes",
            ENABLE_HEX_DUMP="yes",
            SAVE_CLEAN_TXT="yes",
            SAVE_PDF="yes",
        )
        await self.start_runtime()

        await asyncio.gather(
            *(
                self.exchange(index, payloads[index], replies[index])
                for index in range(3)
            )
        )
        await self.wait_for_archives()

        assert self.runtime is not None
        self.assertEqual([fake.received for fake in fakes], [[value] for value in payloads])
        for index, service in enumerate(self.runtime.services):
            route_states = StateStore(service.settings).list()
            self.assertEqual(len(route_states), 1)
            state = route_states[0]
            route_dir = self.environment.data / PRINTER_IPS[index]
            raw_path = route_dir / str(state["raw_filename"])
            technical_path = raw_path.with_suffix(".txt")
            clean_path = raw_path.with_suffix(".PULITO.txt")
            pdf_path = raw_path.with_suffix(".pdf")
            metadata_path = raw_path.with_suffix(".json")

            self.assertEqual(raw_path.read_bytes(), payloads[index])
            self.assertIn(f"Route {index + 1}", technical_path.read_text(encoding="utf-8"))
            self.assertIn(f"Route {index + 1}", clean_path.read_text(encoding="utf-8"))
            self.assertEqual(pdf_path.read_bytes()[:5], b"%PDF-")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["printer_ip"], PRINTER_IPS[index])
            self.assertEqual(metadata["printer_port"], ports[index])
            self.assertEqual(state["render_status"], "complete")
            self.assertEqual(state["sidecar_errors"], [])
            self.assertTrue(service.ledger.verify(check_files=True).ok)

            for other_index in range(3):
                if other_index != index:
                    self.assertNotIn(
                        f"Route {other_index + 1}",
                        clean_path.read_text(encoding="utf-8"),
                    )

    async def test_single_mapping_runtime_keeps_legacy_flat_layout(self) -> None:
        payload = b"legacy-single-route\x10\x04\x01"
        reply = b"\x41"
        fake = FakeEscPosPrinter(response=reply, respond_after_bytes=len(payload))
        printer_port = await self.add_fake_printer("127.0.0.2", fake)
        rewrite_config(
            self.environment.config,
            PRINTER_PORT=str(printer_port),
            DELIVERY_MODE="transparent_duplex",
            PRINTER_RESPONSE_TIMEOUT="0.25",
            MAX_SESSION_DURATION="5",
            SAVE_CLEAN_TXT="no",
            SAVE_PDF="no",
        )
        await self.start_runtime()
        await self.exchange(0, payload, reply)
        await self.wait_for_archives()

        assert self.runtime is not None
        self.assertEqual(len(self.runtime.services), 1)
        service = self.runtime.services[0]
        self.assertEqual(service.settings.data_dir, self.environment.data)
        self.assertEqual(service.settings.spool_dir, self.environment.spool)
        self.assertEqual(
            [path.read_bytes() for path in self.environment.data.glob("*.raw")],
            [payload],
        )
        self.assertEqual(fake.received, [payload])

    async def test_authenticated_ledger_clone_cannot_cross_physical_printer_route(self) -> None:
        printer_ports = tuple(free_port(host) for host in PRINTER_IPS)
        self.configure(printer_ports)
        rewrite_config(
            self.environment.config,
            DELIVERY_MODE="store_forward",
            ENABLE_READABLE_DUMP="no",
            ENABLE_HEX_DUMP="no",
        )
        master = load_settings(self.environment.config)
        source_proxy, target_proxy = master.proxy_configs[:2]
        source = PrintProxyService(master.for_proxy(source_proxy), source_proxy)

        payload = b"route-one-only"
        state, temporary = source._new_receiving_state(
            "cross-route-session", "127.0.0.1", 12345, 1.0
        )
        temporary.write_bytes(payload)
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
        source.store.write(state)
        await source._recover_sealed(state)
        queued = source.store.load(str(state["job_id"]))
        self.assertEqual(queued["state"], "QUEUED")
        self.assertEqual(queued["printer_ip"], source_proxy.printer_ip)
        self.assertTrue(source.ledger.verify(check_files=True).ok)

        # Simulate an operator copying the complete, valid route-1 evidence
        # (state, RAW, metadata, and HMAC ledger) into route 2. The shared key
        # makes the copied chain cryptographically valid in isolation.
        target_settings = master.for_proxy(target_proxy)
        shutil.copytree(
            source.settings.data_dir,
            target_settings.data_dir,
            dirs_exist_ok=True,
        )
        shutil.copytree(
            source.settings.spool_dir,
            target_settings.spool_dir,
            dirs_exist_ok=True,
        )
        with self.assertRaisesRegex(IntegrityError, r"route binding"):
            PrintProxyService(target_settings, target_proxy)

    async def test_offline_printer_does_not_stop_other_routes(self) -> None:
        good_payloads = (b"route-one\x10\x04\x01", b"route-three\x10\x04\x03")
        good_replies = (b"\x21", b"\x23")
        first = FakeEscPosPrinter(
            response=good_replies[0], respond_after_bytes=len(good_payloads[0])
        )
        third = FakeEscPosPrinter(
            response=good_replies[1], respond_after_bytes=len(good_payloads[1])
        )
        ports = (
            await self.add_fake_printer(PRINTER_IPS[0], first),
            free_port(PRINTER_IPS[1]),
            await self.add_fake_printer(PRINTER_IPS[2], third),
        )
        self.configure(ports)
        await self.start_runtime()
        assert self.runtime is not None

        # Route 2 accepts at the proxy but resets because only its own physical
        # printer is unavailable.  This is a session error, not a service fatal.
        reader, writer = await asyncio.open_connection(
            *self.runtime.services[1].proxy_config.listen_endpoint
        )
        with contextlib.suppress(ConnectionResetError, BrokenPipeError, OSError):
            writer.write(b"offline")
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=2)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

        await asyncio.gather(
            self.exchange(0, good_payloads[0], good_replies[0]),
            self.exchange(2, good_payloads[1], good_replies[1]),
        )
        self.assertEqual(first.received, [good_payloads[0]])
        self.assertEqual(third.received, [good_payloads[1]])
        self.assertTrue(self.runtime.services[1].server.is_serving())
        assert self.runtime_task is not None
        self.assertFalse(self.runtime_task.done())

    async def test_route_fatal_is_isolated_from_healthy_siblings(self) -> None:
        payloads = (b"healthy-one", b"unused", b"healthy-three")
        replies = (b"\x31", b"", b"\x33")
        fakes = tuple(
            FakeEscPosPrinter(response=reply, respond_after_bytes=len(payload))
            for payload, reply in zip(payloads, replies, strict=True)
        )
        ports = tuple(
            [
                await self.add_fake_printer(host, fake)
                for host, fake in zip(PRINTER_IPS, fakes, strict=True)
            ]
        )
        self.configure(ports)
        await self.start_runtime()
        assert self.runtime is not None

        failed = self.runtime.services[1]
        failed.request_fatal_shutdown(
            StorageError("simulated route-local disk failure")
        )
        for _ in range(200):
            if failed.stopped:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(failed.stopped)
        self.assertFalse(failed.server.is_serving())

        await asyncio.gather(
            self.exchange(0, payloads[0], replies[0]),
            self.exchange(2, payloads[2], replies[2]),
        )
        self.assertEqual(fakes[0].received, [payloads[0]])
        self.assertEqual(fakes[2].received, [payloads[2]])
        assert self.runtime_task is not None
        self.assertFalse(self.runtime_task.done())

    async def test_listener_bind_failure_rolls_back_all_prior_listeners(self) -> None:
        listen_ports = tuple(free_port(host) for host in LISTEN_IPS)

        async def discard(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        blocker = await asyncio.start_server(discard, LISTEN_IPS[1], listen_ports[1])
        try:
            printer_ports = tuple(free_port(host) for host in PRINTER_IPS)
            rewrite_config(
                self.environment.config,
                LISTEN_IP=",".join(LISTEN_IPS),
                LISTEN_PORT=",".join(str(port) for port in listen_ports),
                PRINTER_IP=",".join(PRINTER_IPS),
                PRINTER_PORT=",".join(str(port) for port in printer_ports),
                DELIVERY_MODE="transparent_duplex",
                SAVE_CLEAN_TXT="no",
                SAVE_PDF="no",
            )
            self.runtime = MultiProxyService(load_settings(self.environment.config))
            with self.assertRaisesRegex(
                OSError, r"proxy-002: cannot bind listener .*already in use"
            ):
                await self.runtime.run()

            self.assertFalse(self.runtime.started)
            self.assertTrue(
                all(
                    service.server is None or not service.server.is_serving()
                    for service in self.runtime.services
                )
            )
            # The endpoint successfully bound for proxy-001 must already be
            # reusable when run() reports proxy-002's failure.
            probe = await asyncio.start_server(discard, LISTEN_IPS[0], listen_ports[0])
            probe.close()
            await probe.wait_closed()
        finally:
            blocker.close()
            await blocker.wait_closed()

    def test_unconfigured_listener_address_has_an_explicit_reason(self) -> None:
        failure = OSError(errno.EADDRNOTAVAIL, "cannot assign requested address")
        self.assertEqual(
            PrintProxyService._bind_failure_reason(failure, "10.1.2.222"),
            "IP address 10.1.2.222 is not configured on this host",
        )

    async def test_successful_ocr_is_audited_without_becoming_a_sidecar_error(
        self,
    ) -> None:
        rewrite_config(
            self.environment.config,
            SAVE_CLEAN_TXT="yes",
            SAVE_PDF="no",
        )
        service = PrintProxyService(load_settings(self.environment.config))
        state, _ = service._new_receiving_state("ocr-session", "127.0.0.1", 12345, 1.0)
        raw_path = service.settings.data_dir / str(state["raw_filename"])
        raw_path.write_bytes(b"synthetic raster receipt")
        source_bitmap = ImageBlock(
            width=8,
            height=1,
            packed_bits=b"\xff",
            alignment="center",
            source="ESC *",
            mode=0,
            dpi_x=203,
            dpi_y=203,
        )
        document = ReceiptDocument(
            nodes=(
                RasterTextBlock(
                    text="sensitive receipt text",
                    source_bitmap=source_bitmap,
                    ocr_confidence=91.25,
                    bounding_box=(1, 2, 7, 8),
                    alignment="center",
                ),
            ),
            input_size=24,
            parsed_size=24,
            truncated=False,
            warnings=(),
            default_codepage="cp858",
        )

        def fake_render(_data: bytes, **kwargs: object) -> ReceiptArtifactsResult:
            clean_path = Path(str(kwargs["clean_text_path"]))
            clean_path.write_text("sensitive receipt text\n", encoding="utf-8")
            return ReceiptArtifactsResult(
                document=document,
                clean_text="sensitive receipt text\n",
                clean_text_path=clean_path,
                clean_text_error=None,
                pdf=None,
            )

        sidecar_notes = state["sidecar_errors"]
        self.assertIsInstance(sidecar_notes, list)
        with patch("printproxy.render_receipt_artifacts", side_effect=fake_render):
            with self.assertLogs("printproxy", level="INFO") as captured:
                await service._render_receipt_sidecars(state, raw_path, sidecar_notes)

        log_output = "\n".join(captured.output)
        self.assertIn("OCR_RASTER_TEXT", log_output)
        self.assertIn("BLOCKS=1", log_output)
        self.assertIn("CONFIDENCES=91.25", log_output)
        self.assertIn("BBOXES=[[1,2,7,8]]", log_output)
        self.assertIn("PROVENANCE=receipt_renderer:raster_ocr", log_output)
        self.assertIn('BITMAP_SOURCES=["ESC *"]', log_output)
        self.assertIn("PROXY_ID=proxy-001", log_output)
        self.assertNotIn("sensitive receipt text", log_output)
        self.assertEqual(sidecar_notes, [])
        metadata = metadata_document_from_state(state)
        self.assertEqual(metadata["sidecar_errors"], [])

    async def test_truncated_pdf_is_persisted_as_partial_render_warning(self) -> None:
        rewrite_config(
            self.environment.config,
            SAVE_CLEAN_TXT="no",
            SAVE_PDF="yes",
        )
        service = PrintProxyService(load_settings(self.environment.config))
        state, _ = service._new_receiving_state(
            "truncated-pdf-session", "127.0.0.1", 12345, 1.0
        )
        raw_path = service.settings.data_dir / str(state["raw_filename"])
        raw_path.write_bytes(b"synthetic long receipt")
        document = ReceiptDocument(
            nodes=(),
            input_size=22,
            parsed_size=22,
            truncated=False,
            warnings=(),
            default_codepage="cp858",
        )

        def fake_render(_data: bytes, **kwargs: object) -> ReceiptArtifactsResult:
            pdf_path = Path(str(kwargs["pdf_path"]))
            pdf_path.write_bytes(b"%PDF-synthetic")
            return ReceiptArtifactsResult(
                document=document,
                clean_text="",
                clean_text_path=None,
                clean_text_error=None,
                pdf=PdfRenderResult(
                    success=True,
                    path=pdf_path,
                    content_truncated=True,
                ),
            )

        sidecar_notes = state["sidecar_errors"]
        self.assertIsInstance(sidecar_notes, list)
        with patch("printproxy.render_receipt_artifacts", side_effect=fake_render):
            await service._render_receipt_sidecars(state, raw_path, sidecar_notes)

        self.assertEqual(state["render_status"], "partial")
        self.assertIsNotNone(state["pdf_sha256"])
        self.assertEqual(len(sidecar_notes), 1)
        self.assertIn("content truncated", sidecar_notes[0])
        state["sidecar_errors"] = sidecar_notes
        metadata = metadata_document_from_state(state)
        self.assertEqual(metadata["render_status"], "partial")
        self.assertEqual(metadata["sidecar_errors"], sidecar_notes)


if __name__ == "__main__":
    unittest.main()
