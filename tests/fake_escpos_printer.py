from __future__ import annotations

import asyncio
import contextlib
import socket
import struct


class FakeEscPosPrinter:
    """Configurable byte-oriented TCP printer used by duplex integration tests."""

    def __init__(
        self,
        *,
        response: bytes = b"",
        response_delay: float = 0.0,
        response_fragments: tuple[bytes, ...] | None = None,
        fragment_delay: float = 0.0,
        respond_after_bytes: int | None = None,
        server_first: bytes = b"",
        close_after_response: bool = False,
        reset_after_receive: bool = False,
        reset_after_bytes: int | None = None,
        hold_open_after_eof: float = 0.0,
    ) -> None:
        self.response = response
        self.response_delay = response_delay
        self.response_fragments = response_fragments
        self.fragment_delay = fragment_delay
        self.respond_after_bytes = respond_after_bytes
        self.server_first = server_first
        self.close_after_response = close_after_response
        self.reset_after_receive = reset_after_receive
        self.reset_after_bytes = reset_after_bytes
        self.hold_open_after_eof = hold_open_after_eof
        self.connections = 0
        self.received: list[bytes] = []
        self.accepted = asyncio.Event()
        self.received_event = asyncio.Event()

    async def _send_response(self, writer: asyncio.StreamWriter) -> None:
        if self.response_delay:
            await asyncio.sleep(self.response_delay)
        fragments = self.response_fragments or ((self.response,) if self.response else ())
        for index, fragment in enumerate(fragments):
            writer.write(fragment)
            await writer.drain()
            if self.fragment_delay and index + 1 < len(fragments):
                await asyncio.sleep(self.fragment_delay)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self.accepted.set()
        data = bytearray()
        response_sent = False
        try:
            if self.server_first:
                writer.write(self.server_first)
                await writer.drain()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                data.extend(chunk)
                if self.reset_after_bytes is not None and len(data) >= self.reset_after_bytes:
                    self.received.append(bytes(data))
                    self.received_event.set()
                    raw_socket = writer.get_extra_info("socket")
                    if raw_socket is not None:
                        raw_socket.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                        )
                    writer.transport.abort()
                    return
                if (
                    not response_sent
                    and self.respond_after_bytes is not None
                    and len(data) >= self.respond_after_bytes
                ):
                    await self._send_response(writer)
                    response_sent = True
                    if self.close_after_response:
                        break
            self.received.append(bytes(data))
            self.received_event.set()
            if self.reset_after_receive:
                raw_socket = writer.get_extra_info("socket")
                if raw_socket is not None:
                    raw_socket.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                    )
                return
            if not response_sent:
                await self._send_response(writer)
            if self.hold_open_after_eof:
                await asyncio.sleep(self.hold_open_after_eof)
            if not self.close_after_response:
                await reader.read()
        except (ConnectionResetError, BrokenPipeError, OSError):
            if bytes(data) not in self.received:
                self.received.append(bytes(data))
                self.received_event.set()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
