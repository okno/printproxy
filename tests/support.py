from __future__ import annotations

import socket
import tempfile
from pathlib import Path


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class TestEnvironment:
    def __init__(self, *, printer_port: int | None = None, mode: str = "connection_close"):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data = self.root / "jobs"
        self.spool = self.root / "spool"
        self.logs = self.root / "logs"
        self.key = self.root / "integrity.key"
        self.key.write_bytes(b"test-integrity-key-32-bytes-minimum!!")
        self.listen_port = free_tcp_port()
        self.printer_port = printer_port or free_tcp_port()
        self.config = self.root / "printproxy.conf"
        self.config.write_text(
            "\n".join(
                (
                    "PROXY_PROTOCOL=raw",
                    "LISTEN_IP=127.0.0.1",
                    f"LISTEN_PORT={self.listen_port}",
                    "PRINTER_IP=127.0.0.1",
                    f"PRINTER_PORT={self.printer_port}",
                    f"DATA_DIR={self.data}",
                    f"SPOOL_DIR={self.spool}",
                    f"LOG_DIR={self.logs}",
                    f"JOB_END_MODE={mode}",
                    "IDLE_TIMEOUT=0.1",
                    "INITIAL_DATA_TIMEOUT=1",
                    "SESSION_IDLE_TIMEOUT=2",
                    "MAX_JOB_DURATION=5",
                    # Keep loopback timing assertions independent of slow/debug fsync
                    # on Windows; production defaults are exercised separately.
                    "CONNECT_TIMEOUT=1",
                    "FORWARD_TIMEOUT=3",
                    "CHUNK_SIZE=4096",
                    "MAX_JOB_BYTES=10485760",
                    "MAX_CONCURRENT_CLIENTS=8",
                    "MAX_CONCURRENT_SIDECARS=2",
                    "FSYNC_INTERVAL_BYTES=4096",
                    "ENABLE_READABLE_DUMP=yes",
                    "MAX_READABLE_DUMP_BYTES=1048576",
                    "ENABLE_HEX_DUMP=yes",
                    "DEFAULT_CODEPAGE=cp858",
                    "HASH_ALGORITHM=sha256",
                    "ENABLE_HASH_CHAIN=yes",
                    "ENABLE_HMAC=yes",
                    f"HMAC_KEY_FILE={self.key}",
                    "HMAC_CREDENTIAL_NAME=integrity.key",
                    "MIN_FREE_DISK_MB=1",
                    "EMERGENCY_RESERVE_MB=0",
                    "ALLOWED_NETWORKS=127.0.0.0/8",
                    "ALLOWED_CLIENTS=",
                    "AUTO_RETRY_BEFORE_SEND=yes",
                    "RETRY_INITIAL_SECONDS=0.1",
                    "RETRY_MAX_SECONDS=0.2",
                    "RETRY_JITTER_PERCENT=0",
                    "PRESERVE_QUEUE_ORDER=yes",
                    "BLOCK_QUEUE_ON_UNKNOWN=no",
                    "REQUEST_POLL_SECONDS=0.1",
                    "ENABLE_RETENTION=no",
                    "RETENTION_DAYS=365",
                    "RETENTION_CHECK_SECONDS=60",
                    "ENABLE_FILE_LOG=no",
                    "SPLIT_ON_ESCPOS_CUT=no",
                    "SHUTDOWN_GRACE_SECONDS=2",
                    "NETWORK_INTERFACE=auto",
                    "VIRTUAL_PREFIX=8",
                    "ENABLE_FIREWALL=no",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def close(self) -> None:
        self.temporary.cleanup()
