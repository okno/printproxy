#!/usr/bin/env python3
"""Durable, serialized RAW TCP print proxy for Debian."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import errno
import hashlib
import hmac
import heapq
import json
import logging
import logging.handlers
import os
import random
import signal
import socket
import struct
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Python isolated mode intentionally omits the script directory. The installed
# directory is root-owned, so adding this exact path is deterministic and safe.
_SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if _SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, _SCRIPT_DIRECTORY)

from printproxy_core import (  # noqa: E402
    ConfigError,
    IntegrityError,
    IntegrityLedger,
    SAFE_RETRY_STATES,
    STATE_SCHEMA_VERSION,
    STATE_LATEST_EVENTS,
    StateStore,
    StorageError,
    Settings,
    atomic_write_json,
    canonical_json,
    create_emergency_reserve,
    disk_free_mb,
    durable_move,
    ensure_runtime_directories,
    filename_timestamp,
    find_escpos_cut,
    fsync_directory,
    hexdump_file,
    load_hmac_key,
    load_settings,
    metadata_hash,
    metadata_document_from_state,
    readable_file,
    read_regular_file_bytes,
    read_regular_file_prefix,
    release_emergency_reserve,
    retention_eligible,
    safe_error,
    service_instance_lock,
    sha256_file,
    utc_now,
)
from receipt_renderer import (  # noqa: E402
    ParseLimits,
    RealtimeStatusBlock,
    render_receipt_artifacts,
)


LOG = logging.getLogger("printproxy")


def log_event(level: int, event: str, **fields: Any) -> None:
    safe_fields = []
    for key, value in fields.items():
        text = str(value).replace("\r", " ").replace("\n", " ")[:500]
        safe_fields.append(f"{key.upper()}={text}")
    LOG.log(level, "%s %s", event, " ".join(safe_fields))


def configure_logging(settings: Settings) -> None:
    LOG.setLevel(logging.INFO)
    LOG.handlers.clear()
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S")
    formatter.converter = time.gmtime
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(formatter)
    LOG.addHandler(stderr)
    if settings.enable_file_log:
        file_handler = logging.handlers.WatchedFileHandler(
            settings.log_dir / "printproxy.log", encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        LOG.addHandler(file_handler)


async def durable_to_thread(function: Any, *args: Any) -> Any:
    """Finish an in-flight fd operation before propagating cancellation."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.gather(task, return_exceptions=True)
        raise


@dataclass
class ReceiveResult:
    state: dict[str, Any]
    temp_path: Path
    complete: bool
    boundary_reason: str
    idle_timeout_triggered: bool
    connection_closed: bool
    cancelled: bool = False


class LiveRelayError(OSError):
    """A live printer stream failed after delivery may have started."""


class LivePrinterRelay:
    """One byte-transparent printer connection for one accepted client session."""

    def __init__(
        self,
        service: "PrintProxyService",
        client_writer: asyncio.StreamWriter,
        session_id: str,
        source: str,
    ) -> None:
        self.service = service
        self.settings = service.settings
        self.client_writer = client_writer
        self.session_id = session_id
        self.source = source
        self.destination = f"{self.settings.printer_ip}:{self.settings.printer_port}"
        self.printer_reader: asyncio.StreamReader | None = None
        self.printer_writer: asyncio.StreamWriter | None = None
        self.response_task: asyncio.Task[None] | None = None
        self.lock_acquired = False
        self.closed = False
        self.printer_write_eof_sent = False
        self.connect_attempted = False
        self.connect_error: BaseException | None = None
        self.stream_error: BaseException | None = None
        self.printer_fin_received = False
        self.printer_reset_received = False
        self.printer_close_kind: str | None = None
        self.client_response_closed = False
        self.client_drain_pending = False
        self.bytes_client_to_printer = 0
        self.bytes_submitted_to_socket = 0
        self.bytes_printer_to_client = 0
        self._response_activity = asyncio.Event()
        self.failure_event = asyncio.Event()
        self._job_id: str | None = None
        self._job_state: dict[str, Any] | None = None
        self._job_response_bytes = 0
        self._job_bytes_rx_from_printer = 0
        self._job_bytes_submitted_to_client = 0
        self._job_response_capture = bytearray()
        self._job_response_truncated = False
        self._job_response_rx_digest = hashlib.sha256()
        self._job_response_delivered_digest = hashlib.sha256()
        self._job_realtime_queries = 0
        self._job_query_tail = b""

    def begin_job(self, state: dict[str, Any]) -> None:
        if self._job_state is not None:
            # Responses can arrive after an idle archive boundary while the
            # same TCP session waits for its next request. Snapshot that tail
            # into the preceding job immediately before counters are reset.
            self.snapshot_job(self._job_state)
            self._job_response_bytes = 0
            self._job_bytes_rx_from_printer = 0
            self._job_bytes_submitted_to_client = 0
            self._job_response_capture.clear()
            self._job_response_truncated = False
            self._job_response_rx_digest = hashlib.sha256()
            self._job_response_delivered_digest = hashlib.sha256()
            self._job_realtime_queries = 0
            self._job_query_tail = b""
        self._job_id = str(state["job_id"])
        self._job_state = state
        state.update(
            {
                "bytes_client_to_printer": 0,
                "bytes_printer_to_client": 0,
                "bytes_printer_received": 0,
                "bytes_submitted_to_client": 0,
                "printer_response_hex": "",
                "printer_response_truncated": False,
                "printer_response_sha256": hashlib.sha256(b"").hexdigest(),
                "printer_response_delivered_sha256": hashlib.sha256(b"").hexdigest(),
                "realtime_status_queries": 0,
                "client_fin_received": False,
                "printer_fin_received": self.printer_fin_received,
                "client_close_kind": None,
                "printer_close_kind": self.printer_close_kind,
                "full_duplex": True,
                "retry_allowed": False,
            }
        )
        # If the printer emitted server-first/ASB bytes after upstream connect,
        # the first job adopts those already-relayed bytes instead of losing
        # them from counters and digests.
        self.snapshot_job(state)

    def end_job(self, job_id: str) -> None:
        if self._job_id == job_id:
            if self._job_state is not None:
                self.snapshot_job(self._job_state)
            self._job_id = None
            self._job_state = None
            self._job_response_capture.clear()
            self._job_query_tail = b""

    def _record_realtime_queries(self, data: bytes) -> None:
        combined = self._job_query_tail + data
        # DLE EOT n is a three-byte request. Keeping two bytes handles a
        # request split at either TCP packet boundary without touching data.
        for index in range(max(0, len(combined) - 2)):
            if (
                combined[index : index + 2] == b"\x10\x04"
                and combined[index + 2] in {1, 2, 3, 4}
            ):
                self._job_realtime_queries += 1
        self._job_query_tail = combined[-2:]

    def snapshot_job(self, state: dict[str, Any]) -> None:
        state["bytes_client_to_printer"] = int(state.get("bytes_forwarded", 0))
        state["bytes_printer_to_client"] = self._job_response_bytes
        state["bytes_printer_received"] = self._job_bytes_rx_from_printer
        state["bytes_submitted_to_client"] = self._job_bytes_submitted_to_client
        state["printer_response_hex"] = bytes(self._job_response_capture).hex()
        state["printer_response_truncated"] = self._job_response_truncated
        state["printer_response_sha256"] = self._job_response_rx_digest.hexdigest()
        state["printer_response_delivered_sha256"] = (
            self._job_response_delivered_digest.hexdigest()
        )
        state["realtime_status_queries"] = self._job_realtime_queries
        state["printer_fin_received"] = self.printer_fin_received
        state["printer_close_kind"] = self.printer_close_kind
        if self.stream_error is not None:
            state["last_error"] = safe_error(self.stream_error)

    def _log_payload(self, direction: str, data: bytes) -> None:
        fields: dict[str, Any] = {
            "timestamp": utc_now(),
            "session_id": self.session_id,
            "direction": direction,
            "source": self.source if direction == "CLIENT_TO_PRINTER" else self.destination,
            "destination": self.destination if direction == "CLIENT_TO_PRINTER" else self.source,
            "bytes": len(data),
        }
        if self.settings.debug_hexdump:
            limit = self.settings.debug_hexdump_max_bytes
            fields["hex"] = data[:limit].hex()
            fields["hex_truncated"] = len(data) > limit
            log_event(logging.INFO, "TCP_PAYLOAD", **fields)
        else:
            log_event(logging.DEBUG, "TCP_PAYLOAD", **fields)

    async def _connect(self) -> bool:
        if self.printer_writer is not None:
            return True
        if self.connect_attempted:
            return False
        self.connect_attempted = True
        if self.service.printer_session_lock.locked():
            self.connect_error = ConnectionRefusedError("printer session is busy")
            log_event(
                logging.WARNING,
                "DUPLEX_REJECTED_BUSY",
                timestamp=utc_now(),
                session_id=self.session_id,
                source=self.source,
                destination=self.destination,
            )
            return False
        await self.service.printer_session_lock.acquire()
        self.lock_acquired = True
        try:
            self.printer_reader, self.printer_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.settings.printer_ip,
                    self.settings.printer_port,
                    limit=self.settings.chunk_size,
                ),
                timeout=self.settings.connect_timeout,
            )
        except asyncio.CancelledError:
            self._release_lock()
            raise
        except Exception as exc:
            self.connect_error = exc
            self._release_lock()
            log_event(
                logging.ERROR,
                "PRINTER_CONNECT_FAILED",
                timestamp=utc_now(),
                session_id=self.session_id,
                source=self.source,
                destination=self.destination,
                error=safe_error(exc),
            )
            return False
        log_event(
            logging.INFO,
            "PRINTER_SESSION_OPEN",
            timestamp=utc_now(),
            session_id=self.session_id,
            source=self.source,
            destination=self.destination,
        )
        self.response_task = asyncio.create_task(
            self._relay_printer_responses(), name=f"printer-to-client-{self.session_id}"
        )
        return True

    async def open(self) -> bool:
        """Open upstream before consuming client bytes (server-first safe)."""
        return await self._connect()

    def _arm_send(self, state: dict[str, Any]) -> None:
        if state.get("attempt_id") is not None:
            return
        state["state"] = "DUPLEX_ACTIVE"
        state["attempts"] = int(state.get("attempts", 0)) + 1
        state["attempt_id"] = str(uuid.uuid4())
        state["forward_status"] = "live_send_armed_unconfirmed"
        state["bytes_submitted_to_socket"] = 0
        state["bytes_forwarded"] = 0
        state["next_retry_at"] = None
        state["next_retry_epoch"] = None
        state["last_error"] = None
        state["retry_allowed"] = False
        # This HMAC-authenticated ledger marker precedes the first
        # writer.write(). Recovery treats it as UNKNOWN even if the process
        # dies in the tiny marker/write window; false uncertainty is safer
        # than a duplicate.
        self.service._persist_state_event(state, "DUPLEX_ACTIVE")

    async def send(self, state: dict[str, Any], data: bytes) -> bool:
        if not data:
            return True
        if self.stream_error is not None:
            raise LiveRelayError(safe_error(self.stream_error)) from self.stream_error
        if not await self._connect():
            state["last_error"] = safe_error(self.connect_error or RuntimeError("printer unavailable"))
            state["forward_status"] = "live_failed_before_send_no_auto_retry"
            return False
        assert self.printer_writer is not None
        self._arm_send(state)
        self._record_realtime_queries(data)
        # From this point onward the kernel may have accepted any prefix. Never
        # classify a later failure as retry-safe.
        state["bytes_submitted_to_socket"] = int(state.get("bytes_submitted_to_socket", 0)) + len(data)
        self.bytes_submitted_to_socket += len(data)
        try:
            self.printer_writer.write(data)
            await asyncio.wait_for(
                self.printer_writer.drain(), timeout=self.settings.forward_timeout
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.stream_error = exc
            state["last_error"] = safe_error(exc)
            state["forward_status"] = "live_send_unknown"
            raise LiveRelayError(safe_error(exc)) from exc
        state["bytes_forwarded"] = int(state.get("bytes_forwarded", 0)) + len(data)
        self.bytes_client_to_printer += len(data)
        self._log_payload("CLIENT_TO_PRINTER", data)
        return True

    async def _relay_printer_responses(self) -> None:
        assert self.printer_reader is not None
        try:
            while True:
                try:
                    data = await self.printer_reader.read(self.settings.chunk_size)
                except asyncio.CancelledError:
                    raise
                except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                    self.stream_error = exc
                    self.printer_reset_received = isinstance(exc, ConnectionResetError)
                    self.printer_close_kind = "rst" if self.printer_reset_received else "error"
                    log_event(
                        logging.WARNING,
                        "TCP_RST" if self.printer_reset_received else "TCP_STREAM_ERROR",
                        timestamp=utc_now(),
                        session_id=self.session_id,
                        direction="PRINTER_TO_CLIENT",
                        source=self.destination,
                        destination=self.source,
                        error=safe_error(exc),
                    )
                    self.failure_event.set()
                    self.service._force_reset(self.client_writer)
                    self.client_writer.close()
                    return
                if not data:
                    self.printer_fin_received = True
                    self.printer_close_kind = "fin"
                    log_event(
                        logging.INFO,
                        "TCP_FIN",
                        timestamp=utc_now(),
                        session_id=self.session_id,
                        direction="PRINTER_TO_CLIENT",
                        source=self.destination,
                        destination=self.source,
                    )
                    if self.client_writer.can_write_eof():
                        with contextlib.suppress(OSError, RuntimeError):
                            self.client_writer.write_eof()
                    return
                self.bytes_printer_to_client += len(data)
                self._job_bytes_rx_from_printer += len(data)
                self._job_response_rx_digest.update(data)
                remaining = (
                    self.settings.max_printer_response_capture_bytes
                    - len(self._job_response_capture)
                )
                if remaining > 0:
                    self._job_response_capture.extend(data[:remaining])
                if len(data) > remaining:
                    self._job_response_truncated = True
                self._job_bytes_submitted_to_client += len(data)
                try:
                    self.client_drain_pending = True
                    self.client_writer.write(data)
                    await asyncio.wait_for(
                        self.client_writer.drain(), timeout=self.settings.forward_timeout
                    )
                except asyncio.CancelledError:
                    raise
                except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                    self.stream_error = exc
                    self.client_response_closed = True
                    log_event(
                        logging.WARNING,
                        "TCP_RST" if isinstance(exc, ConnectionResetError) else "TCP_STREAM_ERROR",
                        timestamp=utc_now(),
                        session_id=self.session_id,
                        direction="PRINTER_TO_CLIENT",
                        source=self.destination,
                        destination=self.source,
                        failed_endpoint="client",
                        error=safe_error(exc),
                    )
                    self.failure_event.set()
                    self.service._force_reset(self.client_writer)
                    self.client_writer.close()
                    return
                finally:
                    self.client_drain_pending = False
                    self._response_activity.set()
                self._job_response_bytes += len(data)
                self._job_response_delivered_digest.update(data)
                self._log_payload("PRINTER_TO_CLIENT", data)
        except asyncio.CancelledError:
            raise
        finally:
            self._response_activity.set()

    async def _wait_for_response_tail(self) -> bool:
        """Return true when a pending reader may be cancelled after clean idle."""

        task = self.response_task
        if task is None or task.done():
            if task is not None:
                with contextlib.suppress(Exception):
                    await task
            return True
        total_deadline = time.monotonic() + self.settings.forward_timeout
        while not task.done():
            remaining = total_deadline - time.monotonic()
            if remaining <= 0:
                if self.stream_error is None:
                    self.stream_error = TimeoutError(
                        "printer response relay exceeded total close deadline"
                    )
                self.failure_event.set()
                log_event(
                    logging.WARNING,
                    "TCP_TIMEOUT",
                    timestamp=utc_now(),
                    session_id=self.session_id,
                    direction="PRINTER_TO_CLIENT",
                    timeout=f"{self.settings.forward_timeout}s",
                    reason="total_response_deadline",
                )
                return False
            self._response_activity.clear()
            try:
                await asyncio.wait_for(
                    self._response_activity.wait(),
                    timeout=min(self.settings.printer_response_timeout, remaining),
                )
            except asyncio.TimeoutError:
                if self.client_drain_pending:
                    # Data is actively being back-pressured to the client; it
                    # is not an idle reverse stream and must not be truncated.
                    continue
                log_event(
                    logging.INFO,
                    "TCP_TIMEOUT",
                    timestamp=utc_now(),
                    session_id=self.session_id,
                    direction="PRINTER_TO_CLIENT",
                    timeout=f"{self.settings.printer_response_timeout}s",
                    reason="response_idle",
                )
                return True
        with contextlib.suppress(Exception):
            await task
        return True

    async def half_close_printer(self, reason: str) -> None:
        if self.printer_writer is None or self.printer_write_eof_sent:
            return
        if not self.printer_writer.can_write_eof():
            return
        self.printer_write_eof_sent = True
        try:
            self.printer_writer.write_eof()
            await asyncio.wait_for(
                self.printer_writer.drain(), timeout=self.settings.forward_timeout
            )
            log_event(
                logging.INFO,
                "TCP_FIN",
                timestamp=utc_now(),
                session_id=self.session_id,
                direction="CLIENT_TO_PRINTER",
                source=self.source,
                destination=self.destination,
                reason=reason,
            )
        except asyncio.CancelledError:
            raise
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            if self.bytes_submitted_to_socket:
                self.stream_error = exc
            raise LiveRelayError(safe_error(exc)) from exc

    async def close(self, reason: str) -> None:
        if self.closed:
            return
        self.closed = True
        clean_response_idle = False
        try:
            if self.printer_writer is not None:
                with contextlib.suppress(LiveRelayError):
                    await self.half_close_printer(reason)
                clean_response_idle = await self._wait_for_response_tail()
                self.printer_writer.close()
                with contextlib.suppress(Exception):
                    await self.printer_writer.wait_closed()
                if self.printer_close_kind is None:
                    self.printer_close_kind = "local_close"
            if self.response_task is not None and not self.response_task.done():
                if not clean_response_idle and self.stream_error is None:
                    self.stream_error = TimeoutError(
                        "printer response relay was cancelled before completion"
                    )
                if not clean_response_idle:
                    self.failure_event.set()
                self.response_task.cancel()
                await asyncio.gather(self.response_task, return_exceptions=True)
            if (
                self._job_bytes_submitted_to_client != self._job_response_bytes
                and self.stream_error is None
            ):
                self.stream_error = LiveRelayError(
                    "printer response bytes were not fully drained to the client"
                )
                self.failure_event.set()
        finally:
            self._release_lock()
            log_event(
                logging.INFO,
                "PRINTER_SESSION_CLOSED",
                timestamp=utc_now(),
                session_id=self.session_id,
                reason=reason,
                bytes_client_to_printer=self.bytes_client_to_printer,
                bytes_printer_to_client=self.bytes_printer_to_client,
                printer_fin=self.printer_fin_received,
                printer_rst=self.printer_reset_received,
                error=safe_error(self.stream_error) if self.stream_error else "none",
            )

    def _release_lock(self) -> None:
        if self.lock_acquired:
            self.lock_acquired = False
            self.service.printer_session_lock.release()


class DurableScheduler:
    """A de-duplicating scheduler whose items are backed by state files."""

    def __init__(self, preserve_order: bool):
        self.preserve_order = preserve_order
        self._condition = asyncio.Condition()
        self._heap: list[tuple[Any, ...]] = []
        self._versions: dict[str, int] = {}

    async def put(self, job_id: str, queue_order: str, not_before: float = 0.0) -> None:
        async with self._condition:
            version = self._versions.get(job_id, 0) + 1
            self._versions[job_id] = version
            if self.preserve_order:
                item = (queue_order, not_before, version, job_id)
            else:
                item = (not_before, queue_order, version, job_id)
            heapq.heappush(self._heap, item)
            self._condition.notify_all()

    async def remove(self, job_id: str) -> None:
        async with self._condition:
            self._versions.pop(job_id, None)
            self._condition.notify_all()

    async def get(self) -> str:
        while True:
            async with self._condition:
                while not self._heap:
                    await self._condition.wait()
                item = self._heap[0]
                if self.preserve_order:
                    _, not_before, version, job_id = item
                else:
                    not_before, _, version, job_id = item
                if self._versions.get(job_id) != version:
                    heapq.heappop(self._heap)
                    continue
                delay = not_before - time.time()
                if delay > 0:
                    try:
                        await asyncio.wait_for(self._condition.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass
                    continue
                heapq.heappop(self._heap)
                self._versions.pop(job_id, None)
                return job_id


class PrintProxyService:
    def __init__(self, settings: Settings):
        self.settings = settings
        ensure_runtime_directories(settings)
        # Ledger construction may repair the one-record durable tail window.
        # Free the reserve before that first possible write, not only in run().
        with contextlib.suppress(OSError):
            release_emergency_reserve(settings)
        self.key = load_hmac_key(settings)
        self.store = StateStore(settings)
        self.ledger = IntegrityLedger(settings, self.key)
        self.scheduler = DurableScheduler(settings.preserve_queue_order)
        # A RAW printer stream is a session, not a datagram. Holding one lock
        # for the whole accepted client session prevents cross-client byte
        # interleaving and ambiguous reverse-channel routing.
        self.printer_session_lock = asyncio.Lock()
        self.shutdown_event = asyncio.Event()
        self.sidecar_semaphore = asyncio.Semaphore(settings.max_concurrent_sidecars)
        self.active_client_slots = 0
        self.client_tasks: set[asyncio.Task[Any]] = set()
        self.background_tasks: list[asyncio.Task[Any]] = []
        self.server: asyncio.AbstractServer | None = None
        self._random = random.SystemRandom()
        self.fatal_exception: BaseException | None = None

    def request_fatal_shutdown(self, exc: BaseException) -> None:
        current: BaseException | None = exc
        while current is not None:
            if isinstance(current, OSError) and current.errno in {errno.ENOSPC, errno.EDQUOT}:
                with contextlib.suppress(OSError):
                    release_emergency_reserve(self.settings)
                break
            current = current.__cause__
        if self.fatal_exception is None:
            self.fatal_exception = exc
            log_event(logging.CRITICAL, "SERVICE_FATAL", error=safe_error(exc))
        self.request_shutdown()

    def _raw_path(self, state: dict[str, Any]) -> Path:
        filename = str(state["raw_filename"])
        job_id = str(state["job_id"])
        if Path(filename).name != filename or not filename.endswith(f"_{job_id}.raw"):
            raise StorageError("unsafe raw filename in state")
        return self.settings.data_dir / filename

    def _metadata_path(self, state: dict[str, Any]) -> Path:
        self._raw_path(state)
        filename = str(state["metadata_filename"])
        expected = Path(str(state["raw_filename"])).with_suffix(".json").name
        if Path(filename).name != filename or filename != expected:
            raise StorageError("unsafe metadata filename in state")
        return self.settings.data_dir / filename

    def _sidecar_path(self, state: dict[str, Any], key: str, suffix: str) -> Path:
        self._raw_path(state)
        filename = state.get(key)
        expected = Path(str(state["raw_filename"])).with_suffix(suffix).name
        if not isinstance(filename, str) or Path(filename).name != filename or filename != expected:
            raise StorageError(f"unsafe {key} in state")
        return self.settings.data_dir / filename

    def _metadata_document(self, state: dict[str, Any]) -> dict[str, Any]:
        return metadata_document_from_state(state)

    def _event_payload(
        self, state: dict[str, Any], event: str, event_id: str
    ) -> dict[str, Any]:
        return {
            "event_id": event_id,
            "event": event,
            "job_id": state["job_id"],
            "status": state["state"],
            "raw_filename": state["raw_filename"],
            "raw_sha256": state.get("raw_sha256"),
            "raw_size": state.get("bytes_archived", 0),
            "metadata_filename": state["metadata_filename"],
            "metadata_sha256": state["metadata_sha256"],
            "source": f"{state.get('source_ip')}:{state.get('source_port')}",
            "destination": f"{self.settings.printer_ip}:{self.settings.printer_port}",
            "attempt_id": state.get("attempt_id"),
            "error": state.get("last_error"),
            "operator_action": state.get("operator_action"),
            "state_schema_version": state.get("schema_version"),
            "delivery_mode": self.settings.delivery_mode,
            "clean_filename": state.get("clean_filename"),
            "clean_sha256": state.get("clean_sha256"),
            "pdf_filename": state.get("pdf_filename"),
            "pdf_sha256": state.get("pdf_sha256"),
            "render_status": state.get("render_status"),
            "bytes_client_to_printer": state.get("bytes_client_to_printer"),
            "bytes_printer_received": state.get("bytes_printer_received"),
            "bytes_printer_to_client": state.get("bytes_printer_to_client"),
            "realtime_status_queries": state.get("realtime_status_queries"),
            "parsed_realtime_status_queries": state.get(
                "parsed_realtime_status_queries"
            ),
            "printer_response_sha256": state.get("printer_response_sha256"),
            "printer_response_delivered_sha256": state.get(
                "printer_response_delivered_sha256"
            ),
            "retry_allowed": state.get("retry_allowed"),
        }

    def _outbox_auth(
        self, payload: dict[str, Any], metadata_document: dict[str, Any]
    ) -> dict[str, str]:
        encoded = canonical_json(
            {"schema_version": 1, "payload": payload, "metadata_document": metadata_document}
        )
        if self.key is None:
            return {"algorithm": "sha256", "digest": hashlib.sha256(encoded).hexdigest()}
        return {
            "algorithm": "hmac-sha256",
            "digest": hmac.new(
                self.key, b"printproxy-outbox-v1\0" + encoded, hashlib.sha256
            ).hexdigest(),
        }

    @staticmethod
    def _validate_event_transition(
        event: str, status: str, previous_event: str | None
    ) -> None:
        event_status = {
            "ARCHIVED": "SEALED",
            "DUPLEX_ACTIVE": "DUPLEX_ACTIVE",
            "DUPLEX_ABORTED": "DUPLEX_ABORTED",
            "QUEUED": "QUEUED",
            "PARTIAL_ARCHIVED": "PARTIAL",
            "SEND_ARMED": "SEND_ARMED",
            "SENDING": "SENDING",
            "SENT_UNCONFIRMED": "SENT_UNCONFIRMED",
            "FAILED_BEFORE_SEND": "FAILED_BEFORE_SEND",
            "FAILED_BEFORE_SEND_RECOVERY": "FAILED_BEFORE_SEND",
            "UNKNOWN_PRINT_STATE": "UNKNOWN_PRINT_STATE",
            "UNKNOWN_PRINT_STATE_RECOVERY": "UNKNOWN_PRINT_STATE",
            "MANUAL_RETRY_QUEUED": "QUEUED",
            "RETENTION_DELETE_STARTED": "RETENTION_DELETING",
            "RETENTION_DELETED": "RETENTION_DELETED",
            "QUARANTINED": "QUARANTINED",
        }
        if event not in event_status or event_status[event] != status:
            raise IntegrityError(f"invalid ledger transition event/status: {event}/{status}")
        predecessors: dict[str, set[str | None]] = {
            "ARCHIVED": {None, "DUPLEX_ACTIVE"},
            "DUPLEX_ACTIVE": {None},
            "DUPLEX_ABORTED": {"ARCHIVED"},
            "QUEUED": {"ARCHIVED"},
            "PARTIAL_ARCHIVED": {"ARCHIVED"},
            "SEND_ARMED": {
                "QUEUED",
                "MANUAL_RETRY_QUEUED",
                "FAILED_BEFORE_SEND",
                "FAILED_BEFORE_SEND_RECOVERY",
            },
            "SENDING": {"SEND_ARMED"},
            "SENT_UNCONFIRMED": {"SENDING", "ARCHIVED"},
            "FAILED_BEFORE_SEND": {"SEND_ARMED", "ARCHIVED"},
            "FAILED_BEFORE_SEND_RECOVERY": {"SEND_ARMED"},
            "UNKNOWN_PRINT_STATE": {"SENDING", "ARCHIVED", "SENT_UNCONFIRMED"},
            "UNKNOWN_PRINT_STATE_RECOVERY": {"SENDING", "ARCHIVED"},
            "MANUAL_RETRY_QUEUED": {
                "QUEUED",
                "MANUAL_RETRY_QUEUED",
                "FAILED_BEFORE_SEND",
                "FAILED_BEFORE_SEND_RECOVERY",
                "UNKNOWN_PRINT_STATE",
                "UNKNOWN_PRINT_STATE_RECOVERY",
            },
            "RETENTION_DELETE_STARTED": {"SENT_UNCONFIRMED"},
            "RETENTION_DELETED": {"RETENTION_DELETE_STARTED"},
        }
        if event == "QUARANTINED":
            if previous_event == "RETENTION_DELETED":
                raise IntegrityError("a retained/deleted job cannot be quarantined")
            return
        if previous_event not in predecessors[event]:
            raise IntegrityError(
                f"invalid ledger predecessor: {previous_event!r} -> {event}"
            )

    def _validate_latest_metadata_file(
        self, state: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        latest = self.ledger.latest_job_record(state["job_id"])
        if latest is None:
            return None, None
        if latest.get("metadata_filename") != state.get("metadata_filename"):
            raise IntegrityError("mutable metadata filename differs from authenticated ledger")
        metadata_path = self._metadata_path(state)
        try:
            metadata_bytes = read_regular_file_bytes(metadata_path)
            actual_hash = hashlib.sha256(metadata_bytes).hexdigest()
            document = json.loads(metadata_bytes)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StorageError) as exc:
            raise IntegrityError(f"authenticated metadata is unavailable: {safe_error(exc)}") from exc
        if actual_hash != latest.get("metadata_sha256"):
            raise IntegrityError("metadata hash differs from authenticated latest event")
        if not isinstance(document, dict):
            raise IntegrityError("metadata document is not a JSON object")
        return latest, document

    def _persist_state_event(self, state: dict[str, Any], event: str) -> dict[str, Any]:
        if state.get("pending_ledger_event") is not None:
            raise IntegrityError("cannot create a second event while an outbox event is pending")
        latest, _ = self._validate_latest_metadata_file(state)
        self._validate_event_transition(
            event,
            str(state.get("state")),
            str(latest.get("event")) if latest is not None else None,
        )
        state["timestamp_state_updated"] = utc_now()
        metadata_document = self._metadata_document(state)
        metadata_bytes = canonical_json(metadata_document) + b"\n"
        state["metadata_sha256"] = hashlib.sha256(metadata_bytes).hexdigest()
        event_id = str(uuid.uuid4())
        payload = self._event_payload(state, event, event_id)
        state["pending_ledger_event"] = payload
        state["pending_metadata_document"] = metadata_document
        state["pending_outbox_auth"] = self._outbox_auth(payload, metadata_document)
        # Write-ahead order: the authenticated recovery context is durable
        # before the mutable metadata is replaced. Every later crash window is
        # therefore idempotently recoverable.
        self.store.write(state)
        metadata_path = self._metadata_path(state)
        atomic_write_json(metadata_path, metadata_document)
        record = self.ledger.append(payload)
        state["last_ledger_sequence"] = record["sequence"]
        state["last_committed_event"] = event
        state.pop("pending_ledger_event", None)
        state.pop("pending_metadata_document", None)
        state.pop("pending_outbox_auth", None)
        self.store.write(state)
        return record

    def _reconcile_pending_event(self, state: dict[str, Any]) -> dict[str, Any]:
        pending = state.get("pending_ledger_event")
        if pending is None:
            return state
        metadata_document = state.get("pending_metadata_document")
        outbox_auth = state.get("pending_outbox_auth")
        if (
            not isinstance(pending, dict)
            or not isinstance(pending.get("event_id"), str)
            or not isinstance(metadata_document, dict)
            or not isinstance(outbox_auth, dict)
        ):
            raise IntegrityError("malformed durable ledger outbox")
        event_id = pending["event_id"]
        try:
            uuid.UUID(event_id)
        except ValueError as exc:
            raise IntegrityError("malformed durable ledger outbox event id") from exc
        expected_document = self._metadata_document(state)
        if metadata_document != expected_document:
            raise IntegrityError("outbox metadata document differs from operational state")
        expected_payload = self._event_payload(state, str(pending.get("event")), event_id)
        if pending != expected_payload:
            raise IntegrityError("outbox payload differs from operational state")
        expected_auth = self._outbox_auth(pending, metadata_document)
        if (
            outbox_auth.get("algorithm") != expected_auth["algorithm"]
            or not isinstance(outbox_auth.get("digest"), str)
            or not hmac.compare_digest(outbox_auth["digest"], expected_auth["digest"])
        ):
            raise IntegrityError("durable ledger outbox authentication failed")
        metadata_path = self._metadata_path(state)
        record = self.ledger.find_event(event_id)
        if record is None:
            latest = self.ledger.latest_job_record(state["job_id"])
            self._validate_event_transition(
                str(pending.get("event")),
                str(pending.get("status")),
                str(latest.get("event")) if latest is not None else None,
            )
            if metadata_path.exists():
                actual_hash = metadata_hash(metadata_path)
                allowed_hashes = {pending.get("metadata_sha256")}
                if latest is not None:
                    allowed_hashes.add(latest.get("metadata_sha256"))
                if actual_hash not in allowed_hashes:
                    raise IntegrityError("metadata differs from both committed and pending versions")
            atomic_write_json(metadata_path, metadata_document)
            if metadata_hash(metadata_path) != pending.get("metadata_sha256"):
                raise IntegrityError("pending event metadata hash mismatch after recovery write")
            record = self.ledger.append(pending)
        else:
            for key, value in pending.items():
                if record.get(key) != value:
                    raise IntegrityError("ledger event_id collision or outbox payload mismatch")
            latest = self.ledger.latest_job_record(state["job_id"])
            if latest is None or latest.get("event_id") != event_id:
                raise IntegrityError("pending event is not the authenticated latest job event")
            if not metadata_path.exists() or metadata_hash(metadata_path) != pending.get(
                "metadata_sha256"
            ):
                atomic_write_json(metadata_path, metadata_document)
        state["last_ledger_sequence"] = record["sequence"]
        state["last_committed_event"] = pending.get("event")
        state.pop("pending_ledger_event", None)
        state.pop("pending_metadata_document", None)
        state.pop("pending_outbox_auth", None)
        self.store.write(state)
        return state

    def _new_receiving_state(
        self, session_id: str, source_ip: str, source_port: int, monotonic_start: float
    ) -> tuple[dict[str, Any], Path]:
        job_id = str(uuid.uuid4())
        timestamp_start = utc_now()
        base = f"{filename_timestamp(timestamp_start)}_{job_id}"
        raw_filename = f"{base}.raw"
        state: dict[str, Any] = {
            "schema_version": STATE_SCHEMA_VERSION,
            "job_id": job_id,
            "session_id": session_id,
            "state": "RECEIVING",
            "timestamp_start": timestamp_start,
            "timestamp_last_byte": None,
            "timestamp_forward_complete": None,
            "timestamp_archive_complete": None,
            "timestamp_state_updated": timestamp_start,
            "source_ip": source_ip,
            "source_port": source_port,
            "proxy_ip": self.settings.listen_ip,
            "proxy_port": self.settings.listen_port,
            "printer_ip": self.settings.printer_ip,
            "printer_port": self.settings.printer_port,
            "bytes_received": 0,
            "bytes_archived": 0,
            "bytes_forwarded": 0,
            "bytes_submitted_to_socket": 0,
            "raw_filename": raw_filename,
            "metadata_filename": f"{base}.json",
            "readable_filename": f"{base}.txt" if self.settings.enable_readable_dump else None,
            "hex_filename": f"{base}.hex" if self.settings.enable_hex_dump else None,
            "raw_sha256": None,
            "boundary_reason": None,
            "complete_by_policy": False,
            "idle_timeout_triggered": False,
            "forward_status": "not_attempted",
            "physical_print_confirmed": False,
            "connection_duration_ms": 0,
            "forward_duration_ms": None,
            "attempts": 0,
            "attempt_id": None,
            "last_error": None,
            "next_retry_at": None,
            "queue_order": f"{timestamp_start}_{job_id}",
            "queue_sequence": None,
            "recovered_after_crash": False,
            "manual_retry_requested": False,
            "sidecar_errors": [],
            "monotonic_start_hint": monotonic_start,
        }
        state.update(
            {
                "bytes_client_to_printer": 0,
                "bytes_printer_to_client": 0,
                "bytes_printer_received": 0,
                "bytes_submitted_to_client": 0,
                "printer_response_hex": "",
                "printer_response_truncated": False,
                "printer_response_sha256": hashlib.sha256(b"").hexdigest(),
                "printer_response_delivered_sha256": hashlib.sha256(b"").hexdigest(),
                "realtime_status_queries": 0,
                "parsed_realtime_status_queries": 0,
                "client_fin_received": False,
                "printer_fin_received": False,
                "client_close_kind": None,
                "printer_close_kind": None,
                "full_duplex": self.settings.full_duplex,
                "retry_allowed": not self.settings.full_duplex,
                "clean_filename": (
                    f"{base}.PULITO.txt" if self.settings.save_clean_text else None
                ),
                "pdf_filename": f"{base}.pdf" if self.settings.save_pdf else None,
                "clean_sha256": None,
                "pdf_sha256": None,
                "render_status": (
                    "pending"
                    if self.settings.save_clean_text or self.settings.save_pdf
                    else "disabled"
                ),
                "render_completed_at": None,
            }
        )
        temporary = self.settings.receiving_dir / f"{job_id}.raw.tmp"
        state["receiving_filename"] = temporary.name
        return state, temporary

    def _open_receiving_file(self, path: Path) -> int:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        fd = os.open(path, flags, 0o640)
        try:
            # The temp name itself must survive power loss. The file contents
            # are fsynced incrementally and again at the receive boundary.
            fsync_directory(path.parent)
        except BaseException:
            os.close(fd)
            with contextlib.suppress(OSError):
                path.unlink()
            with contextlib.suppress(OSError):
                fsync_directory(path.parent)
            raise
        return fd

    @staticmethod
    def _write_receiving(fd: int, data: bytes) -> int:
        view = memoryview(data)
        total = 0
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "zero-length disk write")
            total += written
            view = view[written:]
        return total

    async def _read_with_timeout(
        self,
        reader: asyncio.StreamReader,
        timeout: float,
        relay: LivePrinterRelay | None = None,
    ) -> bytes:
        if relay is None:
            return await asyncio.wait_for(reader.read(self.settings.chunk_size), timeout=timeout)
        read_task = asyncio.create_task(reader.read(self.settings.chunk_size))
        failure_task = asyncio.create_task(relay.failure_event.wait())
        try:
            done, _ = await asyncio.wait(
                {read_task, failure_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise asyncio.TimeoutError
            if read_task in done:
                data = read_task.result()
                if data:
                    # Preserve bytes already removed from StreamReader even if
                    # reverse failure won the same event-loop turn. The caller
                    # archives them; relay.send then fails without forwarding.
                    return data
            if failure_task in done and relay.failure_event.is_set():
                raise LiveRelayError(
                    safe_error(relay.stream_error or RuntimeError("reverse relay failed"))
                )
            return read_task.result()
        finally:
            for task in (read_task, failure_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(read_task, failure_task, return_exceptions=True)

    async def _receive_one(
        self,
        reader: asyncio.StreamReader,
        pending: bytearray,
        session_id: str,
        source_ip: str,
        source_port: int,
        first_byte_timeout: float,
        relay: LivePrinterRelay | None = None,
        session_deadline: float | None = None,
    ) -> ReceiveResult | None:
        try:
            spool_free = disk_free_mb(self.settings.spool_dir)
            data_free = disk_free_mb(self.settings.data_dir)
        except OSError as exc:
            raise StorageError(f"cannot inspect archive free space: {safe_error(exc)}") from exc
        if min(spool_free, data_free) < self.settings.min_free_disk_mb:
            log_event(
                logging.ERROR,
                "DISK_SPACE_LOW",
                spool_free_mb=spool_free,
                data_free_mb=data_free,
            )
            raise StorageError("free disk space is below MIN_FREE_DISK_MB")

        if pending:
            first = bytes(pending)
            pending.clear()
        else:
            try:
                first = await self._read_with_timeout(reader, first_byte_timeout, relay)
            except asyncio.TimeoutError:
                return None
        if not first:
            return None

        monotonic_start = time.monotonic()
        state, temporary = self._new_receiving_state(
            session_id, source_ip, source_port, monotonic_start
        )
        if relay is not None:
            relay.begin_job(state)
        try:
            fd = self._open_receiving_file(temporary)
        except OSError as exc:
            raise StorageError(f"cannot create durable receiving file: {safe_error(exc)}") from exc
        try:
            self.store.write(state)
        except BaseException as exc:
            os.close(fd)
            with contextlib.suppress(OSError):
                temporary.unlink()
            with contextlib.suppress(OSError):
                fsync_directory(self.settings.receiving_dir)
            if isinstance(exc, OSError):
                raise StorageError(f"cannot persist initial receive state: {safe_error(exc)}") from exc
            raise
        bytes_since_sync = 0
        scan_buffer = bytearray()
        complete = False
        boundary_reason = "unknown"
        idle_triggered = False
        connection_closed = False
        cancelled = False
        current = first
        storage_failed = False

        async def commit_bytes(data: bytes) -> None:
            nonlocal bytes_since_sync
            if not data:
                return
            state["bytes_received"] += len(data)
            state["timestamp_last_byte"] = utc_now()
            written = await durable_to_thread(self._write_receiving, fd, data)
            state["bytes_archived"] += written
            bytes_since_sync += written
            if bytes_since_sync >= self.settings.fsync_interval_bytes:
                await durable_to_thread(os.fsync, fd)
                bytes_since_sync = 0

        try:
            while True:
                if self.settings.split_on_escpos_cut:
                    scan_buffer.extend(current)
                    match = find_escpos_cut(bytes(scan_buffer))
                    if match is not None:
                        _, end = match
                        await commit_bytes(bytes(scan_buffer[:end]))
                        pending.extend(scan_buffer[end:])
                        scan_buffer.clear()
                        complete = True
                        boundary_reason = "escpos_cut_configured"
                        break
                    flush_length = max(0, len(scan_buffer) - 3)
                    if flush_length:
                        await commit_bytes(bytes(scan_buffer[:flush_length]))
                        del scan_buffer[:flush_length]
                else:
                    await commit_bytes(current)

                if relay is not None:
                    # Every byte is on stable storage before it can enter the
                    # printer kernel send buffer. Offloading fsync keeps the
                    # reverse relay schedulable while storage is slow.
                    if bytes_since_sync:
                        await durable_to_thread(os.fsync, fd)
                        bytes_since_sync = 0
                    if not await relay.send(state, current):
                        raise LiveRelayError("printer connection failed before send")

                if state["bytes_received"] > self.settings.max_job_bytes:
                    boundary_reason = "max_job_bytes_exceeded"
                    break
                elapsed = time.monotonic() - monotonic_start
                if elapsed >= self.settings.max_job_duration:
                    boundary_reason = "max_job_duration_exceeded"
                    break
                remaining = self.settings.max_job_duration - elapsed
                timeout = remaining
                timeout_reason = "max_job_duration"
                if session_deadline is not None:
                    session_remaining = session_deadline - time.monotonic()
                    if session_remaining <= 0:
                        boundary_reason = "max_session_duration_exceeded"
                        break
                    if session_remaining < timeout:
                        timeout = session_remaining
                        timeout_reason = "max_session_duration"
                if self.settings.job_end_mode in {"idle_timeout", "hybrid"}:
                    # Keep the winning deadline explicit. Inferring it from the
                    # numeric timeout misclassifies MAX_JOB_DURATION as a clean
                    # idle boundary whenever remaining < IDLE_TIMEOUT.
                    if self.settings.idle_timeout < timeout:
                        timeout = self.settings.idle_timeout
                        timeout_reason = "idle"
                try:
                    current = await self._read_with_timeout(reader, timeout, relay)
                except asyncio.TimeoutError:
                    if timeout_reason == "idle":
                        if scan_buffer:
                            await commit_bytes(bytes(scan_buffer))
                            scan_buffer.clear()
                        complete = True
                        idle_triggered = True
                        boundary_reason = "idle_timeout"
                    else:
                        boundary_reason = (
                            "max_session_duration_exceeded"
                            if timeout_reason == "max_session_duration"
                            else "max_job_duration_exceeded"
                        )
                    break
                if not current:
                    if scan_buffer:
                        await commit_bytes(bytes(scan_buffer))
                        scan_buffer.clear()
                    complete = True
                    connection_closed = True
                    state["client_fin_received"] = True
                    state["client_close_kind"] = "fin"
                    boundary_reason = "connection_close"
                    log_event(
                        logging.INFO,
                        "TCP_FIN",
                        timestamp=utc_now(),
                        session_id=session_id,
                        direction="CLIENT_TO_PRINTER",
                        source=f"{source_ip}:{source_port}",
                        destination=f"{self.settings.printer_ip}:{self.settings.printer_port}",
                    )
                    if relay is not None:
                        await relay.half_close_printer("client_fin")
                    break
        except LiveRelayError as exc:
            if scan_buffer:
                with contextlib.suppress(OSError):
                    await commit_bytes(bytes(scan_buffer))
            boundary_reason = (
                "printer_connect_error"
                if relay is not None and relay.connect_error is not None and state.get("attempt_id") is None
                else "printer_stream_error"
            )
            state["last_error"] = safe_error(exc)
            state["forward_status"] = "live_send_unknown"
        except (ConnectionResetError, BrokenPipeError) as exc:
            if scan_buffer:
                with contextlib.suppress(OSError):
                    await commit_bytes(bytes(scan_buffer))
            boundary_reason = "client_reset"
            state["last_error"] = safe_error(exc)
            state["client_close_kind"] = "rst"
            log_event(
                logging.WARNING,
                "TCP_RST",
                timestamp=utc_now(),
                session_id=session_id,
                direction="CLIENT_TO_PRINTER",
                source=f"{source_ip}:{source_port}",
                destination=f"{self.settings.printer_ip}:{self.settings.printer_port}",
                error=safe_error(exc),
            )
        except asyncio.CancelledError:
            if scan_buffer:
                with contextlib.suppress(OSError):
                    await commit_bytes(bytes(scan_buffer))
            boundary_reason = "service_shutdown"
            cancelled = True
            state["client_close_kind"] = "service_shutdown"
        except OSError as exc:
            storage_failed = True
            boundary_reason = "storage_error"
            state["last_error"] = safe_error(exc)
            if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                release_emergency_reserve(self.settings)
                log_event(logging.CRITICAL, "DISK_SPACE_LOW", job_id=state["job_id"], error=safe_error(exc))
        finally:
            try:
                await durable_to_thread(os.fsync, fd)
            except OSError as exc:
                storage_failed = True
                complete = False
                boundary_reason = "storage_fsync_error"
                state["last_error"] = safe_error(exc)
                if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                    release_emergency_reserve(self.settings)
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)

        if storage_failed:
            complete = False
        state["connection_duration_ms"] = max(0, int((time.monotonic() - monotonic_start) * 1000))
        state["boundary_reason"] = boundary_reason
        state["complete_by_policy"] = complete
        state["idle_timeout_triggered"] = idle_triggered
        if relay is not None:
            relay.snapshot_job(state)
            if state.get("attempt_id") is not None:
                # Keep the authenticated DUPLEX_ACTIVE state durable until
                # ARCHIVED replaces it. Persisting a mutable SEALED snapshot
                # here would create a crash window inconsistent with the
                # latest HMAC ledger event.
                state["state"] = "DUPLEX_ACTIVE"
                state["forward_status"] = (
                    "live_sealed_send_unconfirmed"
                    if state.get("last_error") is None
                    else "live_sealed_send_unknown"
                )
            else:
                state["state"] = "SEALED"
                state["forward_status"] = "live_sealed_failed_before_send_no_auto_retry"
        else:
            state["state"] = "SEALED"
            state["forward_status"] = "sealed_not_yet_archived"
        if state["state"] != "DUPLEX_ACTIVE":
            try:
                self.store.write(state)
            except OSError as exc:
                raise StorageError(f"cannot persist sealed receive state: {safe_error(exc)}") from exc
        return ReceiveResult(
            state=state,
            temp_path=temporary,
            complete=complete,
            boundary_reason=boundary_reason,
            idle_timeout_triggered=idle_triggered,
            connection_closed=connection_closed,
            cancelled=cancelled,
        )

    async def _seal_result(self, result: ReceiveResult) -> dict[str, Any]:
        state = result.state
        live_job = (
            state.get("schema_version") == STATE_SCHEMA_VERSION
            and state.get("full_duplex") is True
        )
        raw_path = self._raw_path(state)
        if result.temp_path.exists():
            durable_move(result.temp_path, raw_path)
        elif not raw_path.exists():
            state["state"] = "QUARANTINED"
            state["last_error"] = "receiving and final RAW are both missing"
            self._persist_state_event(state, "QUARANTINED")
            raise StorageError(state["last_error"])
        raw_fd = os.open(
            raw_path,
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
        )
        try:
            os.fsync(raw_fd)
        finally:
            os.close(raw_fd)
        fsync_directory(self.settings.data_dir)
        raw_sha256, raw_size = sha256_file(raw_path)
        state["raw_sha256"] = raw_sha256
        state["bytes_archived"] = raw_size
        if state.get("recovered_after_crash") and int(state.get("bytes_received", 0)) < raw_size:
            state["bytes_received"] = raw_size
            state["bytes_received_reconstructed"] = True
        state["boundary_reason"] = result.boundary_reason
        state["complete_by_policy"] = result.complete
        state["idle_timeout_triggered"] = result.idle_timeout_triggered
        state["timestamp_archive_complete"] = utc_now()
        state["state"] = "SEALED"
        if not live_job:
            state["forward_status"] = "sealed_archived"
        sidecar_errors: list[str] = []
        if self.settings.enable_readable_dump and state.get("readable_filename"):
            try:
                async with self.sidecar_semaphore:
                    await asyncio.to_thread(
                        readable_file,
                        raw_path,
                        self._sidecar_path(state, "readable_filename", ".txt"),
                        self.settings.default_codepage,
                        self.settings.max_readable_dump_bytes,
                    )
            except Exception as exc:
                sidecar_errors.append("readable: " + safe_error(exc))
        if self.settings.enable_hex_dump and state.get("hex_filename"):
            try:
                async with self.sidecar_semaphore:
                    await asyncio.to_thread(
                        hexdump_file,
                        raw_path,
                        self._sidecar_path(state, "hex_filename", ".hex"),
                    )
            except Exception as exc:
                sidecar_errors.append("hex: " + safe_error(exc))
        if state.get("schema_version") == STATE_SCHEMA_VERSION:
            await self._render_receipt_sidecars(state, raw_path, sidecar_errors)
        state["sidecar_errors"] = sidecar_errors
        if state.get("last_committed_event") != "ARCHIVED":
            archive_event = self._persist_state_event(state, "ARCHIVED")
        else:
            archive_event = self.ledger.archive_record(state["job_id"])
            if archive_event is None:
                raise IntegrityError("SEALED job lacks its authenticated ARCHIVED record")
        archive_sequence = archive_event.get("sequence")
        if (
            isinstance(archive_sequence, bool)
            or not isinstance(archive_sequence, int)
            or archive_sequence < 1
        ):
            raise IntegrityError("ARCHIVED record lacks a valid queue sequence")
        state["queue_sequence"] = archive_sequence
        if live_job:
            possible_send = state.get("attempt_id") is not None
            sent_exact = (
                int(state.get("bytes_forwarded", 0)) == raw_size
                and int(state.get("bytes_submitted_to_socket", 0)) >= raw_size
            )
            crashed = result.boundary_reason.startswith("crash_") or (
                state.get("recovered_after_crash") is True and possible_send
            )
            if possible_send and result.complete and sent_exact and not crashed and state.get("last_error") is None:
                state["state"] = "SENT_UNCONFIRMED"
                state["forward_status"] = "tcp_full_duplex_forwarded_physical_unconfirmed"
                state["physical_print_confirmed"] = False
                state["timestamp_forward_complete"] = utc_now()
                state["forward_duration_ms"] = state.get("connection_duration_ms")
                self._persist_state_event(state, "SENT_UNCONFIRMED")
                level = logging.INFO
            elif possible_send:
                state["state"] = "UNKNOWN_PRINT_STATE"
                state["forward_status"] = "live_send_unknown_no_auto_retry"
                state["physical_print_confirmed"] = False
                state["next_retry_at"] = None
                state["next_retry_epoch"] = None
                if state.get("last_error") is None:
                    state["last_error"] = (
                        "service restart after live send"
                        if crashed
                        else f"live delivery incomplete: {result.boundary_reason}"
                    )
                self._persist_state_event(
                    state,
                    "UNKNOWN_PRINT_STATE_RECOVERY" if crashed else "UNKNOWN_PRINT_STATE",
                )
                level = logging.CRITICAL
            else:
                # A live client may retry as soon as it observes failure. Raw
                # ESC/POS with DLE queries is not a replayable one-way job, so
                # pre-send failures use a terminal duplex-specific state.
                state["state"] = "DUPLEX_ABORTED"
                state["forward_status"] = "duplex_aborted_before_send_no_retry"
                state["physical_print_confirmed"] = False
                state["retry_allowed"] = False
                state["next_retry_at"] = None
                state["next_retry_epoch"] = None
                if state.get("last_error") is None:
                    state["last_error"] = "printer connection unavailable"
                self._persist_state_event(state, "DUPLEX_ABORTED")
                level = logging.ERROR
            log_event(
                level,
                "LIVE_JOB_FINALIZED",
                timestamp=utc_now(),
                job_id=state["job_id"],
                session_id=state["session_id"],
                source=f"{state['source_ip']}:{state['source_port']}",
                destination=f"{self.settings.printer_ip}:{self.settings.printer_port}",
                status=state["state"],
                boundary=result.boundary_reason,
                bytes_client_to_printer=state.get("bytes_client_to_printer", 0),
                bytes_printer_to_client=state.get("bytes_printer_to_client", 0),
                realtime_status_queries=state.get("realtime_status_queries", 0),
                duration=f"{state['connection_duration_ms']}ms",
            )
        elif result.complete:
            state["state"] = "QUEUED"
            state["forward_status"] = "queued"
            self._persist_state_event(state, "QUEUED")
            await self.scheduler.put(
                state["job_id"], self._authenticated_queue_order(state)
            )
            log_event(
                logging.INFO,
                "JOB_ARCHIVED",
                job_id=state["job_id"],
                source=f"{state['source_ip']}:{state['source_port']}",
                destination=f"{self.settings.printer_ip}:{self.settings.printer_port}",
                bytes=raw_size,
                sha256=raw_sha256,
                status="QUEUED",
                duration=f"{state['connection_duration_ms']}ms",
            )
        else:
            state["state"] = "PARTIAL"
            state["forward_status"] = "not_forwarded_partial"
            self._persist_state_event(state, "PARTIAL_ARCHIVED")
            log_event(
                logging.WARNING,
                "PARTIAL_JOB",
                job_id=state["job_id"],
                bytes=raw_size,
                reason=result.boundary_reason,
                sha256=raw_sha256,
            )
        return state

    async def _render_receipt_sidecars(
        self, state: dict[str, Any], raw_path: Path, sidecar_errors: list[str]
    ) -> None:
        """Render bounded human/PDF copies after the live TCP session is done.

        RAW is already durable and authoritative.  Rendering runs in a bounded
        worker thread and failures are recorded without changing delivery state.
        """

        clean_path = (
            self._sidecar_path(state, "clean_filename", ".PULITO.txt")
            if self.settings.save_clean_text and state.get("clean_filename")
            else None
        )
        pdf_path = (
            self._sidecar_path(state, "pdf_filename", ".pdf")
            if self.settings.save_pdf and state.get("pdf_filename")
            else None
        )
        if clean_path is None and pdf_path is None:
            state["render_status"] = "disabled"
            state["render_completed_at"] = utc_now()
            return

        try:
            prefix, truncated = await asyncio.to_thread(
                read_regular_file_prefix,
                raw_path,
                max_bytes=self.settings.max_readable_dump_bytes,
            )
            # One sentinel beyond the parser limit records that the source was
            # larger without altering any parsed input byte.
            render_input = prefix + (b"\x00" if truncated else b"")
            limits = ParseLimits(max_input_bytes=self.settings.max_readable_dump_bytes)
            async with self.sidecar_semaphore:
                rendered = await asyncio.to_thread(
                    render_receipt_artifacts,
                    render_input,
                    clean_text_path=clean_path,
                    pdf_path=pdf_path,
                    default_codepage=self.settings.default_codepage,
                    limits=limits,
                    pdf_width_mm=self.settings.pdf_width_mm,
                    best_effort=True,
                )
            succeeded = 0
            expected = int(clean_path is not None) + int(pdf_path is not None)
            if clean_path is not None:
                if rendered.clean_text_error is None and clean_path.is_file():
                    state["clean_sha256"] = (await asyncio.to_thread(sha256_file, clean_path))[0]
                    succeeded += 1
                else:
                    sidecar_errors.append(
                        "clean receipt: "
                        + (rendered.clean_text_error or "artifact was not created")
                    )
            if pdf_path is not None:
                if rendered.pdf is not None and rendered.pdf.success and pdf_path.is_file():
                    state["pdf_sha256"] = (await asyncio.to_thread(sha256_file, pdf_path))[0]
                    succeeded += 1
                else:
                    sidecar_errors.append(
                        "receipt PDF: "
                        + (
                            rendered.pdf.error
                            if rendered.pdf is not None and rendered.pdf.error
                            else "artifact was not created"
                        )
                    )
            state["render_status"] = (
                "complete" if succeeded == expected else "partial" if succeeded else "failed"
            )
            state["parsed_realtime_status_queries"] = sum(
                isinstance(node, RealtimeStatusBlock) for node in rendered.document.nodes
            )
            if rendered.document.truncated:
                sidecar_errors.append(
                    "receipt rendering input was bounded; authoritative RAW is complete"
                )
        except Exception as exc:
            state["render_status"] = "failed"
            sidecar_errors.append("receipt rendering: " + safe_error(exc))
        finally:
            state["render_completed_at"] = utc_now()

    def _mark_finalized_live_job_unknown(
        self, job_id: str, error: BaseException
    ) -> None:
        with self.store.locked(job_id):
            state = self.store.load(job_id)
            if state.get("state") == "UNKNOWN_PRINT_STATE":
                return
            if state.get("state") != "SENT_UNCONFIRMED" or state.get("full_duplex") is not True:
                return
            self._validate_operational_state(state)
            state["state"] = "UNKNOWN_PRINT_STATE"
            state["forward_status"] = "live_reverse_channel_failed_no_retry"
            state["last_error"] = safe_error(error)
            state["retry_allowed"] = False
            state["next_retry_at"] = None
            state["next_retry_epoch"] = None
            self._persist_state_event(state, "UNKNOWN_PRINT_STATE")
        log_event(
            logging.CRITICAL,
            "LIVE_JOB_BECAME_UNKNOWN",
            timestamp=utc_now(),
            job_id=job_id,
            error=safe_error(error),
        )

    def _force_reset(self, writer: asyncio.StreamWriter) -> None:
        raw_socket = writer.get_extra_info("socket")
        if raw_socket is not None:
            with contextlib.suppress(OSError):
                raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self.settings.full_duplex:
            await self._handle_store_forward_client(reader, writer)
            return
        task = asyncio.current_task()
        if task is not None:
            self.client_tasks.add(task)
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        source_ip, source_port = str(peer[0]), int(peer[1])
        source = f"{source_ip}:{source_port}"
        session_id = str(uuid.uuid4())
        pending = bytearray()
        results: list[ReceiveResult] = []
        relay: LivePrinterRelay | None = None
        slot_acquired = False
        session_started = time.monotonic()
        reset_client = False
        try:
            if not self.settings.client_allowed(source_ip):
                log_event(logging.WARNING, "CLIENT_REJECTED", source=source_ip, reason="ACL")
                self._force_reset(writer)
                return
            if self.active_client_slots >= self.settings.max_concurrent_clients:
                log_event(logging.WARNING, "CLIENT_REJECTED", source=source_ip, reason="CONCURRENCY_LIMIT")
                self._force_reset(writer)
                return
            self.active_client_slots += 1
            slot_acquired = True
            relay = LivePrinterRelay(self, writer, session_id, source)
            # Transparent TCP semantics include server-first bytes: upstream is
            # connected before consuming anything from the client.
            if not await relay.open():
                self._force_reset(writer)
                reset_client = True
                return
            log_event(logging.INFO, "DUPLEX_SESSION_ACCEPTED", session_id=session_id, source=source)
            segment_count = 0
            while not self.shutdown_event.is_set():
                remaining_session = self.settings.max_session_duration - (
                    time.monotonic() - session_started
                )
                if remaining_session <= 0:
                    reset_client = True
                    log_event(
                        logging.WARNING,
                        "TCP_TIMEOUT",
                        session_id=session_id,
                        direction="CLIENT_TO_PRINTER",
                        reason="max_session_duration",
                    )
                    break
                first_timeout = (
                    self.settings.initial_data_timeout
                    if segment_count == 0
                    else self.settings.session_idle_timeout
                )
                result = await self._receive_one(
                    reader,
                    pending,
                    session_id,
                    source_ip,
                    source_port,
                    min(first_timeout, remaining_session),
                    relay,
                    session_started + self.settings.max_session_duration,
                )
                if result is None:
                    break
                results.append(result)
                segment_count += 1
                if not result.complete or result.connection_closed or result.cancelled:
                    reset_client = not result.complete
                    break
                # An idle boundary seals only the archive segment. The same
                # upstream socket remains live for the next segment.
        except asyncio.CancelledError:
            raise
        except (StorageError, IntegrityError) as exc:
            reset_client = True
            log_event(logging.CRITICAL, "JOB_FAILED", session_id=session_id, error=safe_error(exc))
            self.request_fatal_shutdown(exc)
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            reset_client = True
            log_event(logging.WARNING, "CLIENT_CONNECTION_ERROR", session_id=session_id, error=safe_error(exc))
        finally:
            if relay is not None:
                with contextlib.suppress(Exception):
                    await relay.close("client_session_end")
                if results:
                    relay.snapshot_job(results[-1].state)
                for result in results:
                    result.state["printer_fin_received"] = relay.printer_fin_received
                    result.state["printer_close_kind"] = relay.printer_close_kind
                    if relay.stream_error is not None and result.state.get("attempt_id") is not None:
                        result.state["last_error"] = safe_error(relay.stream_error)
                    try:
                        await self._seal_result(result)
                    except Exception as exc:
                        reset_client = True
                        log_event(
                            logging.CRITICAL,
                            "JOB_FAILED",
                            job_id=result.state.get("job_id"),
                            error=safe_error(exc),
                        )
                        self.request_fatal_shutdown(exc)
                        break
            if slot_acquired:
                self.active_client_slots -= 1
            if reset_client:
                self._force_reset(writer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if task is not None:
                self.client_tasks.discard(task)

    async def _handle_store_forward_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.client_tasks.add(task)
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        source_ip, source_port = str(peer[0]), int(peer[1])
        session_id = str(uuid.uuid4())
        pending = bytearray()
        partial_seen = False
        segment_count = 0
        try:
            if not self.settings.client_allowed(source_ip):
                log_event(logging.WARNING, "CLIENT_REJECTED", source=source_ip, reason="ACL")
                self._force_reset(writer)
                return
            if self.active_client_slots >= self.settings.max_concurrent_clients:
                log_event(logging.WARNING, "CLIENT_REJECTED", source=source_ip, reason="CONCURRENCY_LIMIT")
                self._force_reset(writer)
                return
            self.active_client_slots += 1
            try:
                log_event(logging.INFO, "JOB_RECEIVED", session_id=session_id, source=f"{source_ip}:{source_port}")
                while not self.shutdown_event.is_set():
                    try:
                        result = await self._receive_one(
                            reader,
                            pending,
                            session_id,
                            source_ip,
                            source_port,
                            self.settings.initial_data_timeout
                            if segment_count == 0
                            else self.settings.session_idle_timeout,
                        )
                    except StorageError as exc:
                        log_event(logging.CRITICAL, "JOB_FAILED", session_id=session_id, error=safe_error(exc))
                        self._force_reset(writer)
                        self.request_fatal_shutdown(exc)
                        break
                    if result is None:
                        break
                    segment_count += 1
                    try:
                        await self._seal_result(result)
                    except Exception as exc:
                        log_event(
                            logging.CRITICAL,
                            "JOB_FAILED",
                            job_id=result.state.get("job_id"),
                            error=safe_error(exc),
                        )
                        self._force_reset(writer)
                        self.request_fatal_shutdown(exc)
                        break
                    if not result.complete:
                        partial_seen = True
                        self._force_reset(writer)
                        break
                    if result.connection_closed or (
                        self.settings.job_end_mode == "connection_close"
                        and not self.settings.split_on_escpos_cut
                    ):
                        break
                    if result.cancelled:
                        break
            finally:
                self.active_client_slots -= 1
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            log_event(logging.WARNING, "CLIENT_CONNECTION_ERROR", session_id=session_id, error=safe_error(exc))
        finally:
            if partial_seen:
                self._force_reset(writer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if task is not None:
                self.client_tasks.discard(task)

    def _open_validated_raw(self, state: dict[str, Any]) -> int:
        archive = self.ledger.archive_record(state["job_id"])
        if archive is None:
            raise IntegrityError("no authenticated ARCHIVED event exists for job")
        if (
            archive.get("raw_filename") != state.get("raw_filename")
            or archive.get("raw_sha256") != state.get("raw_sha256")
            or archive.get("raw_size") != state.get("bytes_archived")
        ):
            raise IntegrityError("mutable state differs from authenticated ARCHIVED event")
        raw_path = self._raw_path(state)
        fd = os.open(
            raw_path,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
        )
        digest = hashlib.sha256()
        size = 0
        try:
            import stat

            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise IntegrityError("authenticated RAW path is not a regular file")
            while True:
                chunk = os.read(fd, self.settings.chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
            if digest.hexdigest() != archive.get("raw_sha256") or size != archive.get("raw_size"):
                raise IntegrityError("RAW hash/size differs from authenticated archive record")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _validate_raw(self, state: dict[str, Any]) -> None:
        fd = self._open_validated_raw(state)
        os.close(fd)

    def _validate_operational_state(self, state: dict[str, Any]) -> None:
        latest, metadata_document = self._validate_latest_metadata_file(state)
        if latest is None:
            raise IntegrityError("job has no authenticated operational event")
        current = state.get("state")
        if not isinstance(current, str) or current not in STATE_LATEST_EVENTS:
            raise IntegrityError(f"unknown operational state: {current!r}")
        allowed = STATE_LATEST_EVENTS[current]
        if latest.get("event") not in allowed:
            raise IntegrityError(
                f"state rollback/tamper: state={current} latest_event={latest.get('event')}"
            )
        if state.get("last_committed_event") != latest.get("event"):
            raise IntegrityError("operational state lacks the authenticated latest event marker")
        if metadata_document != self._metadata_document(state):
            raise IntegrityError("operational state differs from authenticated metadata document")
        if current in {
            "QUEUED",
            "FAILED_BEFORE_SEND",
            "SEND_ARMED",
            "SENDING",
            "SENT_UNCONFIRMED",
            "UNKNOWN_PRINT_STATE",
            "RETENTION_DELETING",
        }:
            queue_sequence = state.get("queue_sequence")
            if (
                isinstance(queue_sequence, bool)
                or not isinstance(queue_sequence, int)
                or queue_sequence < 1
            ):
                raise IntegrityError("operational state has no valid authenticated queue sequence")

    def _authenticated_queue_order(self, state: dict[str, Any]) -> str:
        sequence = state.get("queue_sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise IntegrityError("job lacks its immutable authenticated queue sequence")
        return f"{sequence:020d}_{state['job_id']}"

    @staticmethod
    def _authenticated_not_before(state: dict[str, Any]) -> float:
        value = state.get("next_retry_at")
        if value is None:
            return 0.0
        if not isinstance(value, str):
            raise IntegrityError("invalid authenticated retry timestamp")
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError as exc:
            raise IntegrityError("invalid authenticated retry timestamp") from exc

    def _validate_recovery_state(self, state: dict[str, Any]) -> None:
        current = state.get("state")
        latest = self.ledger.latest_job_record(state["job_id"])
        if current == "RECEIVING":
            if latest is not None:
                raise IntegrityError("RECEIVING state has an impossible prior ledger event")
            return
        if current == "SEALED":
            if latest is not None:
                self._validate_operational_state(state)
            return
        if current == "RETENTION_DELETED":
            if latest is None or latest.get("event") != "RETENTION_DELETED":
                raise IntegrityError("retention cleanup state lacks its authenticated tombstone")
            if state.get("last_committed_event") != "RETENTION_DELETED":
                raise IntegrityError("retention cleanup state lacks its committed marker")
            return
        self._validate_operational_state(state)

    def _transition_error(self, job_id: str, previous: dict[str, Any], exc: BaseException) -> None:
        with self.store.locked(job_id):
            state = self.store.load(job_id)
            if state.get("pending_ledger_event") is not None:
                # Never overwrite a post-send outbox record with a retry-safe
                # transition. Reconcile first; if storage is still failing the
                # pending state remains fail-closed for the next recovery.
                state = self._reconcile_pending_event(state)
            if state.get("state") == "SENT_UNCONFIRMED":
                log_event(
                    logging.ERROR,
                    "POST_SEND_AUDIT_RECOVERED",
                    job_id=job_id,
                    error=safe_error(exc),
                )
                return
            self._validate_operational_state(state)
            state["bytes_forwarded"] = max(
                int(state.get("bytes_forwarded", 0)), int(previous.get("bytes_forwarded", 0))
            )
            state["bytes_submitted_to_socket"] = max(
                int(state.get("bytes_submitted_to_socket", 0)),
                int(previous.get("bytes_submitted_to_socket", 0)),
            )
            state["last_error"] = safe_error(exc)
            if state.get("state") != "SEND_ARMED":
                state["state"] = "UNKNOWN_PRINT_STATE"
                state["forward_status"] = "unknown_may_have_printed"
                state["next_retry_at"] = None
                event = "UNKNOWN_PRINT_STATE"
                level = logging.CRITICAL
            else:
                state["state"] = "FAILED_BEFORE_SEND"
                state["forward_status"] = "failed_before_send"
                attempts = int(state.get("attempts", 1))
                exponent = min(max(0, attempts - 1), 32)
                base = min(
                    self.settings.retry_max_seconds,
                    self.settings.retry_initial_seconds * (2**exponent),
                )
                jitter = base * self.settings.retry_jitter_percent / 100.0
                delay = max(0.1, base + self._random.uniform(-jitter, jitter))
                retry_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
                state["next_retry_at"] = retry_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
                state["next_retry_epoch"] = retry_at.timestamp()
                event = "FAILED_BEFORE_SEND"
                level = logging.ERROR
            self._persist_state_event(state, event)
        log_event(
            level,
            "JOB_FAILED",
            job_id=job_id,
            status=state["state"],
            bytes=state.get("bytes_forwarded", 0),
            error=state["last_error"],
        )
        if state["state"] == "FAILED_BEFORE_SEND" and self.settings.auto_retry_before_send:
            asyncio.create_task(
                self.scheduler.put(
                    job_id,
                    self._authenticated_queue_order(state),
                    self._authenticated_not_before(state),
                )
            )

    def _quarantine_job(self, job_id: str, exc: BaseException) -> None:
        with self.store.locked(job_id):
            state = self.store.load(job_id)
            if state.get("pending_ledger_event") is not None:
                state = self._reconcile_pending_event(state)
            self._validate_operational_state(state)
            state["state"] = "QUARANTINED"
            state["forward_status"] = "blocked_integrity_or_storage_failure"
            state["last_error"] = safe_error(exc)
            state["next_retry_at"] = None
            state["next_retry_epoch"] = None
            self._persist_state_event(state, "QUARANTINED")
        log_event(logging.CRITICAL, "JOB_QUARANTINED", job_id=job_id, error=safe_error(exc))

    async def _forward_job(self, job_id: str) -> None:
        writer: asyncio.StreamWriter | None = None
        raw_fd: int | None = None
        attempt_armed = False
        forward_started = time.monotonic()
        state: dict[str, Any]
        await self.printer_session_lock.acquire()
        try:
            with self.store.locked(job_id):
                state = self.store.load(job_id)
                if state.get("retry_allowed") is False:
                    self._validate_operational_state(state)
                    log_event(
                        logging.ERROR,
                        "RETRY_BLOCKED",
                        job_id=job_id,
                        reason="duplex_job_not_replayable",
                    )
                    return
                if state.get("state") not in SAFE_RETRY_STATES:
                    self._validate_operational_state(state)
                    return
                self._validate_operational_state(state)
                raw_fd = self._open_validated_raw(state)
                state["state"] = "SEND_ARMED"
                state["forward_status"] = "connecting_no_bytes_sent"
                state["attempts"] = int(state.get("attempts", 0)) + 1
                state["attempt_id"] = str(uuid.uuid4())
                state["bytes_forwarded"] = 0
                state["bytes_submitted_to_socket"] = 0
                state["next_retry_at"] = None
                state["next_retry_epoch"] = None
                state["last_error"] = None
                self._persist_state_event(state, "SEND_ARMED")
                attempt_armed = True

            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.settings.printer_ip,
                        self.settings.printer_port,
                        limit=self.settings.chunk_size,
                    ),
                    timeout=self.settings.connect_timeout,
                )
            except BaseException as exc:
                if isinstance(exc, asyncio.CancelledError):
                    self._transition_error(job_id, state, RuntimeError("service stopped before printer connect"))
                    raise
                self._transition_error(job_id, state, exc)
                log_event(
                    logging.ERROR,
                    "PRINTER_UNREACHABLE",
                    job_id=job_id,
                    destination=f"{self.settings.printer_ip}:{self.settings.printer_port}",
                    error=safe_error(exc),
                )
                return

            with self.store.locked(job_id):
                state = self.store.load(job_id)
                self._validate_operational_state(state)
                if state.get("state") != "SEND_ARMED":
                    raise StorageError("job lost SEND_ARMED reservation")
                # This durable marker is committed before the first writer.write().
                state["state"] = "SENDING"
                state["forward_status"] = "sending_unconfirmed"
                self._persist_state_event(state, "SENDING")

            sent = 0
            submitted = 0
            send_digest = hashlib.sha256()
            async with asyncio.timeout(self.settings.forward_timeout):
                while True:
                    chunk = os.read(raw_fd, self.settings.chunk_size)
                    if not chunk:
                        break
                    writer.write(chunk)
                    submitted += len(chunk)
                    state["bytes_submitted_to_socket"] = submitted
                    await writer.drain()
                    sent += len(chunk)
                    send_digest.update(chunk)
                    state["bytes_forwarded"] = sent
                if sent != state.get("bytes_archived") or send_digest.hexdigest() != state.get("raw_sha256"):
                    raise IntegrityError("RAW changed or truncated while being forwarded")
                writer.close()
                await writer.wait_closed()
                writer = None

            with self.store.locked(job_id):
                state = self.store.load(job_id)
                self._validate_operational_state(state)
                if state.get("state") != "SENDING":
                    raise StorageError("job lost SENDING reservation")
                state["state"] = "SENT_UNCONFIRMED"
                state["forward_status"] = "tcp_stream_forwarded_physical_unconfirmed"
                state["physical_print_confirmed"] = False
                state["bytes_forwarded"] = sent
                state["timestamp_forward_complete"] = utc_now()
                state["forward_duration_ms"] = max(0, int((time.monotonic() - forward_started) * 1000))
                self._persist_state_event(state, "SENT_UNCONFIRMED")
            log_event(
                logging.INFO,
                "JOB_FORWARDED",
                job_id=job_id,
                source=f"{state['source_ip']}:{state['source_port']}",
                destination=f"{self.settings.printer_ip}:{self.settings.printer_port}",
                bytes=sent,
                sha256=state["raw_sha256"],
                status="SENT_UNCONFIRMED",
                duration=f"{state['forward_duration_ms']}ms",
            )
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                current = self.store.load(job_id)
                if current.get("state") == "SENDING":
                    self._transition_error(job_id, current, RuntimeError("service stopped during send"))
            raise
        except BaseException as exc:
            try:
                if attempt_armed:
                    self._transition_error(job_id, state, exc)
                else:
                    self._quarantine_job(job_id, exc)
            except Exception as fatal:
                self.request_fatal_shutdown(fatal)
        finally:
            if raw_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(raw_fd)
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            self.printer_session_lock.release()

    def _unknown_jobs_exist(self) -> bool:
        return any(state.get("state") == "UNKNOWN_PRINT_STATE" for state in self.store.list())

    async def _forward_worker(self) -> None:
        while not self.shutdown_event.is_set():
            job_id = await self.scheduler.get()
            if self.shutdown_event.is_set():
                state = self.store.load(job_id)
                self._validate_operational_state(state)
                await self.scheduler.put(job_id, self._authenticated_queue_order(state))
                return
            if self.settings.block_queue_on_unknown and self._unknown_jobs_exist():
                state = self.store.load(job_id)
                self._validate_operational_state(state)
                await self.scheduler.put(
                    job_id, self._authenticated_queue_order(state), time.time() + 5
                )
                await asyncio.sleep(1)
                continue
            await self._forward_job(job_id)

    async def _process_retry_request(self, path: Path) -> None:
        consume_request = False
        try:
            request = json.loads(read_regular_file_bytes(path, max_bytes=65536))
            if request.get("schema_version") != 1 or request.get("action") != "retry":
                raise StorageError("unsupported retry request schema/action")
            request_id = request.get("request_id")
            if request_id != path.stem:
                raise StorageError("retry request id does not match its durable filename")
            uuid.UUID(str(request_id))
            job_id = str(request["job_id"])
            uuid.UUID(job_id)
            consumed = self.ledger.consumed_request_record(str(request_id))
            if consumed is not None:
                if consumed.get("job_id") != job_id:
                    raise IntegrityError("retry request id was authenticated for another job")
                consume_request = True
                return
            confirmed_unknown = request.get("confirm_unknown") is True
            reason = request.get("reason")
            requested_at = request.get("requested_at")
            requested_uid = request.get("requested_uid")
            if not isinstance(reason, str) or not 1 <= len(reason) <= 500:
                raise StorageError("retry reason must be a 1..500 character string")
            if not isinstance(requested_at, str) or not isinstance(requested_uid, (int, type(None))):
                raise StorageError("malformed retry audit identity/timestamp")
            with self.store.locked(job_id):
                state = self.store.load(job_id)
                prior_action = state.get("operator_action")
                if isinstance(prior_action, dict) and prior_action.get("request_id") == request_id:
                    # The ledger/state transition already consumed this exact
                    # request. Never apply a stale UNKNOWN confirmation twice.
                    consume_request = True
                    return
                previous = state.get("state")
                if state.get("retry_allowed") is False:
                    raise StorageError("duplex jobs are not replayable")
                if previous == "UNKNOWN_PRINT_STATE" and not confirmed_unknown:
                    raise StorageError("unknown print state retry lacks explicit confirmation")
                if previous not in {"FAILED_BEFORE_SEND", "QUEUED", "UNKNOWN_PRINT_STATE"}:
                    raise StorageError(f"state {previous} is not retryable")
                self._validate_operational_state(state)
                self._validate_raw(state)
                state["state"] = "QUEUED"
                state["forward_status"] = "queued_manual_retry"
                state["manual_retry_requested"] = True
                state["manual_retry_previous_state"] = previous
                state["operator_action"] = {
                    "action": "manual_retry",
                    "reason": reason,
                    "requested_at": requested_at,
                    "requested_uid": requested_uid,
                    "confirmed_unknown_duplicate_risk": confirmed_unknown,
                    "request_id": request_id,
                }
                state["next_retry_at"] = None
                state["next_retry_epoch"] = None
                self._persist_state_event(state, "MANUAL_RETRY_QUEUED")
            await self.scheduler.put(job_id, self._authenticated_queue_order(state))
            consume_request = True
            log_event(
                logging.WARNING if previous == "UNKNOWN_PRINT_STATE" else logging.INFO,
                "MANUAL_RETRY_QUEUED",
                job_id=job_id,
                previous_state=previous,
                duplicate_risk=previous == "UNKNOWN_PRINT_STATE",
            )
        except Exception as exc:
            log_event(logging.ERROR, "RETRY_REQUEST_REJECTED", request=path.name, error=safe_error(exc))
            if isinstance(exc, (IntegrityError, OSError)):
                self.request_fatal_shutdown(exc)
            else:
                # Malformed/unauthorized requests are rejected permanently;
                # durable storage failures stay for an idempotent restart.
                consume_request = True
        finally:
            if consume_request:
                try:
                    path.unlink()
                    fsync_directory(self.settings.requests_dir)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    log_event(
                        logging.CRITICAL,
                        "RETRY_REQUEST_DELETE_FAILED",
                        request=path.name,
                        error=safe_error(exc),
                    )
                    self.request_fatal_shutdown(exc)

    async def _request_worker(self) -> None:
        while not self.shutdown_event.is_set():
            for path in sorted(self.settings.requests_dir.glob("*.json")):
                await self._process_retry_request(path)
            try:
                await asyncio.wait_for(
                    self.shutdown_event.wait(), timeout=self.settings.request_poll_seconds
                )
            except asyncio.TimeoutError:
                pass

    async def _retention_worker(self) -> None:
        while not self.shutdown_event.is_set():
            cutoff = time.time() - self.settings.retention_days * 86400
            for candidate in self.store.list():
                if candidate.get("state") in {"RETENTION_DELETING", "RETENTION_DELETED"}:
                    try:
                        if candidate.get("state") == "RETENTION_DELETING":
                            self._validate_operational_state(candidate)
                        await self._complete_retention(candidate)
                    except Exception as exc:
                        log_event(
                            logging.ERROR,
                            "RETENTION_FAILED",
                            job_id=candidate.get("job_id"),
                            error=safe_error(exc),
                        )
                        if isinstance(exc, IntegrityError):
                            self.request_fatal_shutdown(exc)
                            return
                    continue
                if not retention_eligible(candidate, cutoff):
                    continue
                job_id = candidate["job_id"]
                try:
                    with self.store.locked(job_id):
                        state = self.store.load(job_id)
                        if not retention_eligible(state, cutoff):
                            continue
                        self._validate_operational_state(state)
                        validated_fd = self._open_validated_raw(state)
                        os.close(validated_fd)
                        state["state"] = "RETENTION_DELETING"
                        state["last_error"] = None
                        self._persist_state_event(state, "RETENTION_DELETE_STARTED")
                    await self._complete_retention(state)
                    log_event(logging.INFO, "RETENTION_DELETED", job_id=job_id)
                except Exception as exc:
                    log_event(logging.ERROR, "RETENTION_FAILED", job_id=job_id, error=safe_error(exc))
                    if isinstance(exc, IntegrityError):
                        self.request_fatal_shutdown(exc)
                        return
            try:
                await asyncio.wait_for(
                    self.shutdown_event.wait(), timeout=self.settings.retention_check_seconds
                )
            except asyncio.TimeoutError:
                pass

    def _retention_paths(
        self, state: dict[str, Any]
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        archive = self.ledger.archive_record(state["job_id"])
        if archive is None or (
            archive.get("raw_filename") != state.get("raw_filename")
            or archive.get("raw_sha256") != state.get("raw_sha256")
            or archive.get("raw_size") != state.get("bytes_archived")
        ):
            raise IntegrityError("retention state differs from authenticated archive")
        raw_path = self._raw_path(state)
        return (
            raw_path,
            raw_path.with_suffix(".txt"),
            raw_path.with_suffix(".hex"),
            raw_path.with_suffix(".PULITO.txt"),
            raw_path.with_suffix(".pdf"),
            self._metadata_path(state),
        )

    async def _complete_retention(self, state: dict[str, Any]) -> None:
        job_id = state["job_id"]
        # Authorization must precede the first unlink. In particular, a mutable
        # state bit-flipped to RETENTION_DELETED is not a tombstone.
        self._validate_recovery_state(state)
        raw_path, text_path, hex_path, clean_path, pdf_path, metadata_path = (
            self._retention_paths(state)
        )
        for artifact_path in (raw_path, text_path, hex_path, clean_path, pdf_path):
            with contextlib.suppress(FileNotFoundError):
                artifact_path.unlink()
        fsync_directory(self.settings.data_dir)
        with self.store.locked(job_id):
            state = self.store.load(job_id)
            if state.get("state") != "RETENTION_DELETED":
                self._validate_operational_state(state)
                state["state"] = "RETENTION_DELETED"
                self._persist_state_event(state, "RETENTION_DELETED")
            with contextlib.suppress(FileNotFoundError):
                metadata_path.unlink()
            with contextlib.suppress(FileNotFoundError):
                self.store.path_for(job_id).unlink()
            fsync_directory(self.settings.data_dir)
            fsync_directory(self.settings.states_dir)

    async def _recover_receiving(self, state: dict[str, Any]) -> None:
        job_id = state["job_id"]
        temp_name = state.get("receiving_filename", f"{job_id}.raw.tmp")
        if temp_name != f"{job_id}.raw.tmp":
            raise StorageError("receiving filename does not match job id")
        temporary = self.settings.receiving_dir / temp_name
        raw_path = self._raw_path(state)
        if not temporary.exists() and not raw_path.exists():
            if state.get("state") == "DUPLEX_ACTIVE":
                raise IntegrityError(
                    "authenticated DUPLEX_ACTIVE job has no recoverable RAW evidence"
                )
            state["state"] = "QUARANTINED"
            state["last_error"] = "crash recovery found no RAW"
            self._persist_state_event(state, "QUARANTINED")
            return
        state["recovered_after_crash"] = True
        result = ReceiveResult(
            state=state,
            temp_path=temporary,
            complete=False,
            boundary_reason="crash_during_receive",
            idle_timeout_triggered=False,
            connection_closed=False,
        )
        await self._seal_result(result)

    async def _recover_sealed(self, state: dict[str, Any]) -> None:
        job_id = state["job_id"]
        temp_name = state.get("receiving_filename", f"{job_id}.raw.tmp")
        if temp_name != f"{job_id}.raw.tmp":
            raise StorageError("receiving filename does not match job id")
        temporary = self.settings.receiving_dir / temp_name
        state["recovered_after_crash"] = True
        result = ReceiveResult(
            state=state,
            temp_path=temporary,
            complete=state.get("complete_by_policy") is True,
            boundary_reason=str(state.get("boundary_reason") or "sealed_recovery"),
            idle_timeout_triggered=state.get("idle_timeout_triggered") is True,
            connection_closed=state.get("boundary_reason") == "connection_close",
        )
        await self._seal_result(result)

    async def _recover_orphan_temps(self, known_ids: set[str]) -> None:
        for path in self.settings.receiving_dir.glob("*.raw.tmp"):
            job_text = path.name.removesuffix(".raw.tmp")
            if job_text in known_ids:
                continue
            try:
                uuid.UUID(job_text)
            except ValueError:
                log_event(logging.ERROR, "ORPHAN_UNSAFE_FILENAME", filename=path.name)
                continue
            timestamp = utc_now()
            base = f"{filename_timestamp(timestamp)}_{job_text}"
            state = {
                "schema_version": 1,
                "job_id": job_text,
                "session_id": "crash-recovery",
                "state": "RECEIVING",
                "timestamp_start": timestamp,
                "timestamp_last_byte": timestamp,
                "timestamp_forward_complete": None,
                "timestamp_archive_complete": None,
                "source_ip": "unknown",
                "source_port": 0,
                "proxy_ip": self.settings.listen_ip,
                "proxy_port": self.settings.listen_port,
                "printer_ip": self.settings.printer_ip,
                "printer_port": self.settings.printer_port,
                "bytes_received": path.stat().st_size,
                "bytes_archived": path.stat().st_size,
                "bytes_forwarded": 0,
                "raw_filename": f"{base}.raw",
                "metadata_filename": f"{base}.json",
                "readable_filename": f"{base}.txt" if self.settings.enable_readable_dump else None,
                "hex_filename": f"{base}.hex" if self.settings.enable_hex_dump else None,
                "raw_sha256": None,
                "boundary_reason": "orphan_temp_after_crash",
                "complete_by_policy": False,
                "idle_timeout_triggered": False,
                "forward_status": "not_forwarded_partial",
                "physical_print_confirmed": False,
                "connection_duration_ms": 0,
                "forward_duration_ms": None,
                "attempts": 0,
                "attempt_id": None,
                "last_error": "orphan receiving file recovered",
                "next_retry_at": None,
                "queue_order": f"{timestamp}_{job_text}",
                "recovered_after_crash": True,
                "manual_retry_requested": False,
                "sidecar_errors": [],
                "receiving_filename": path.name,
            }
            self.store.write(state)
            await self._recover_receiving(state)

    async def recover(self) -> None:
        states = self.store.list()
        known_ids = {state.get("job_id") for state in states if "job_id" in state}
        for ledger_job_id, latest in self.ledger.latest_job_records().items():
            if latest.get("event") != "RETENTION_DELETED" and ledger_job_id not in known_ids:
                raise IntegrityError(
                    f"authenticated job {ledger_job_id} has no operational state file"
                )
        for state in states:
            job_id = state.get("job_id")
            if state.get("state_error") is not None:
                raise IntegrityError(f"unreadable operational state file for job {job_id}")
            try:
                uuid.UUID(str(job_id))
            except ValueError:
                raise IntegrityError(f"invalid operational state filename/job id: {job_id!r}")
            current = state.get("state")
            try:
                with self.store.locked(job_id):
                    state = self.store.load(job_id)
                    state = self._reconcile_pending_event(state)
                current = state.get("state")
                self._validate_recovery_state(state)
                if current == "RECEIVING":
                    await self._recover_receiving(state)
                elif current == "DUPLEX_ACTIVE":
                    await self._recover_receiving(state)
                elif current == "SEALED":
                    await self._recover_sealed(state)
                elif current in {"RETENTION_DELETING", "RETENTION_DELETED"}:
                    await self._complete_retention(state)
                elif current == "SENDING":
                    with self.store.locked(job_id):
                        state = self.store.load(job_id)
                        state["state"] = "UNKNOWN_PRINT_STATE"
                        state["forward_status"] = "unknown_after_service_restart"
                        state["last_error"] = "service restarted while send was armed"
                        self._persist_state_event(state, "UNKNOWN_PRINT_STATE_RECOVERY")
                elif current == "SEND_ARMED":
                    with self.store.locked(job_id):
                        state = self.store.load(job_id)
                        state["state"] = "FAILED_BEFORE_SEND"
                        state["forward_status"] = "safe_retry_after_connect_phase_restart"
                        state["last_error"] = "service restarted before durable SENDING marker"
                        self._persist_state_event(state, "FAILED_BEFORE_SEND_RECOVERY")
                    if self.settings.auto_retry_before_send:
                        await self.scheduler.put(
                            job_id, self._authenticated_queue_order(state)
                        )
                elif current in {"QUEUED", "FAILED_BEFORE_SEND"}:
                    expected = "QUEUED" if current == "QUEUED" else None
                    if expected and state.get("last_committed_event") not in {
                        "QUEUED",
                        "MANUAL_RETRY_QUEUED",
                    }:
                        raise IntegrityError("queue state lacks its committed ledger event")
                    self._validate_operational_state(state)
                    self._validate_raw(state)
                    if current == "QUEUED" or self.settings.auto_retry_before_send:
                        await self.scheduler.put(
                            job_id,
                            self._authenticated_queue_order(state),
                            self._authenticated_not_before(state),
                        )
            except Exception as exc:
                log_event(logging.CRITICAL, "RECOVERY_FAILED", job_id=job_id, error=safe_error(exc))
                # Never turn an untrusted/tampered state document into a newly
                # HMAC-authenticated QUARANTINED record. Preserve the evidence
                # and fail startup for operator-led recovery.
                if isinstance(exc, IntegrityError):
                    raise
                if current in {"RECEIVING", "SEALED", "DUPLEX_ACTIVE"}:
                    raise
                if isinstance(state, dict) and state.get("pending_ledger_event") is not None:
                    raise
                state["state"] = "QUARANTINED"
                state["last_error"] = "recovery: " + safe_error(exc)
                self._persist_state_event(state, "QUARANTINED")
        await self._recover_orphan_temps({str(value) for value in known_ids})
        if self.settings.full_duplex:
            backlog = [
                state
                for state in self.store.list()
                if (
                    state.get("state")
                    in {"QUEUED", "FAILED_BEFORE_SEND", "SEND_ARMED", "SENDING"}
                    and state.get("retry_allowed") is not False
                )
                or (
                    self.settings.block_queue_on_unknown
                    and state.get("state") == "UNKNOWN_PRINT_STATE"
                )
            ]
            if backlog:
                summary = ", ".join(
                    f"{state.get('job_id')}:{state.get('state')}" for state in backlog[:10]
                )
                raise StorageError(
                    "transparent_duplex cannot start with blocked legacy backlog or "
                    "UNKNOWN print state; drain replayable jobs temporarily with "
                    "DELIVERY_MODE=store_forward, or resolve the UNKNOWN policy: "
                    + summary
                )

    def request_shutdown(self) -> None:
        if not self.shutdown_event.is_set():
            log_event(logging.INFO, "SERVICE_STOP", reason="signal")
            self.shutdown_event.set()
            if self.server is not None:
                self.server.close()

    def _supervise_background(self, task: asyncio.Task[Any]) -> None:
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            self.request_fatal_shutdown(exception)

    async def run(self) -> None:
        # Recovery gets first use of reserved blocks. Recreating the reserve
        # before reconciling a pending manifest/head write can deadlock ENOSPC
        # recovery across every systemd restart.
        with contextlib.suppress(OSError):
            release_emergency_reserve(self.settings)
        await self.recover()
        reserve_needed = self.settings.emergency_reserve_mb
        if reserve_needed > 0:
            free_mb = min(
                disk_free_mb(self.settings.spool_dir), disk_free_mb(self.settings.data_dir)
            )
            if free_mb >= self.settings.min_free_disk_mb + reserve_needed:
                try:
                    create_emergency_reserve(self.settings)
                except OSError as exc:
                    log_event(
                        logging.ERROR,
                        "EMERGENCY_RESERVE_UNAVAILABLE",
                        error=safe_error(exc),
                    )
            else:
                log_event(
                    logging.ERROR,
                    "EMERGENCY_RESERVE_SKIPPED",
                    free_mb=free_mb,
                    required_mb=self.settings.min_free_disk_mb + reserve_needed,
                )
        self.server = await asyncio.start_server(
            self._handle_client,
            host=self.settings.listen_ip,
            port=self.settings.listen_port,
            limit=self.settings.chunk_size,
            start_serving=True,
        )
        sockets = self.server.sockets or []
        for bound in sockets:
            log_event(logging.INFO, "SERVICE_START", listener=bound.getsockname(), pid=os.getpid())
        self.background_tasks = [
            asyncio.create_task(self._request_worker(), name="request-worker"),
        ]
        if not self.settings.full_duplex:
            self.background_tasks.append(
                asyncio.create_task(self._forward_worker(), name="printer-forwarder")
            )
        if self.settings.enable_retention:
            self.background_tasks.append(
                asyncio.create_task(self._retention_worker(), name="retention-worker")
            )
        for task in self.background_tasks:
            task.add_done_callback(self._supervise_background)
        await self.shutdown_event.wait()
        self.server.close()
        await self.server.wait_closed()
        if self.client_tasks:
            done, pending = await asyncio.wait(
                set(self.client_tasks), timeout=self.settings.shutdown_grace_seconds
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        for task in self.background_tasks:
            task.cancel()
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        if self.fatal_exception is not None:
            raise IntegrityError(safe_error(self.fatal_exception))


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/printproxy/printproxy.conf")
    parser.add_argument("--check-config", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        settings = load_settings(arguments.config)
        if arguments.check_config:
            print(f"configuration valid: {settings.config_path}")
            return 0
        ensure_runtime_directories(settings)
        configure_logging(settings)
        key = load_hmac_key(settings)
        del key
        with service_instance_lock(settings):
            service = PrintProxyService(settings)

            async def runner() -> None:
                loop = asyncio.get_running_loop()
                for signum in (signal.SIGTERM, signal.SIGINT):
                    with contextlib.suppress(NotImplementedError):
                        loop.add_signal_handler(signum, service.request_shutdown)
                await service.run()

            asyncio.run(runner())
        return 0
    except (ConfigError, StorageError, IntegrityError, OSError) as exc:
        print(f"printproxy: fatal: {safe_error(exc)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
