#!/usr/bin/env python3
"""Core primitives for the durable TCP print proxy.

Only the Python standard library is used.  This module deliberately contains no
network listener: it is shared by the daemon, the administrative CLI and tests.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import stat
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping


SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 2
ZERO_HASH = "0" * 64
TERMINAL_STATES = {
    "PARTIAL",
    "SENT_UNCONFIRMED",
    "UNKNOWN_PRINT_STATE",
    "DUPLEX_ABORTED",
    "QUARANTINED",
    "RETENTION_DELETED",
}
SAFE_RETRY_STATES = {"QUEUED", "FAILED_BEFORE_SEND"}
UNCERTAIN_STATES = {"SENDING", "DUPLEX_ACTIVE", "UNKNOWN_PRINT_STATE"}
STATE_LATEST_EVENTS = {
    "SEALED": {"ARCHIVED"},
    "QUEUED": {"QUEUED", "MANUAL_RETRY_QUEUED"},
    "FAILED_BEFORE_SEND": {"FAILED_BEFORE_SEND", "FAILED_BEFORE_SEND_RECOVERY"},
    "SEND_ARMED": {"SEND_ARMED"},
    "SENDING": {"SENDING"},
    "DUPLEX_ACTIVE": {"DUPLEX_ACTIVE"},
    "DUPLEX_ABORTED": {"DUPLEX_ABORTED"},
    "SENT_UNCONFIRMED": {"SENT_UNCONFIRMED"},
    "UNKNOWN_PRINT_STATE": {"UNKNOWN_PRINT_STATE", "UNKNOWN_PRINT_STATE_RECOVERY"},
    "PARTIAL": {"PARTIAL_ARCHIVED"},
    "QUARANTINED": {"QUARANTINED"},
    "RETENTION_DELETING": {"RETENTION_DELETE_STARTED"},
    "RETENTION_DELETED": {"RETENTION_DELETED"},
}

# Version 1 is immutable: existing metadata documents and their ledger HMACs
# must remain byte-for-byte verifiable after an upgrade.
METADATA_STATE_FIELDS_V1 = (
    "job_id",
    "session_id",
    "state",
    "timestamp_start",
    "timestamp_last_byte",
    "timestamp_forward_complete",
    "timestamp_archive_complete",
    "timestamp_state_updated",
    "source_ip",
    "source_port",
    "proxy_ip",
    "proxy_port",
    "printer_ip",
    "printer_port",
    "bytes_received",
    "bytes_archived",
    "bytes_forwarded",
    "bytes_submitted_to_socket",
    "raw_filename",
    "readable_filename",
    "hex_filename",
    "raw_sha256",
    "boundary_reason",
    "complete_by_policy",
    "idle_timeout_triggered",
    "forward_status",
    "physical_print_confirmed",
    "connection_duration_ms",
    "forward_duration_ms",
    "attempts",
    "attempt_id",
    "last_error",
    "next_retry_at",
    "next_retry_epoch",
    "queue_order",
    "queue_sequence",
    "recovered_after_crash",
    "bytes_received_reconstructed",
    "manual_retry_requested",
    "manual_retry_previous_state",
    "sidecar_errors",
    "receiving_filename",
    "operator_action",
)

METADATA_STATE_FIELDS_V2 = METADATA_STATE_FIELDS_V1 + (
    "bytes_client_to_printer",
    "bytes_printer_received",
    "bytes_submitted_to_client",
    "bytes_printer_to_client",
    "printer_response_hex",
    "printer_response_truncated",
    "printer_response_sha256",
    "printer_response_delivered_sha256",
    "realtime_status_queries",
    "parsed_realtime_status_queries",
    "client_fin_received",
    "printer_fin_received",
    "client_close_kind",
    "printer_close_kind",
    "retry_allowed",
    "full_duplex",
    "clean_filename",
    "pdf_filename",
    "clean_sha256",
    "pdf_sha256",
    "render_status",
    "render_completed_at",
)

# New code may import the current field set, but serialization always selects a
# set from the state schema below.
METADATA_STATE_FIELDS = METADATA_STATE_FIELDS_V2


class ConfigError(ValueError):
    """Configuration is missing, malformed or unsafe."""


class IntegrityError(RuntimeError):
    """The append-only integrity ledger cannot be trusted."""


class StorageError(RuntimeError):
    """Durable storage operation failed."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def filename_timestamp(timestamp: str) -> str:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%fZ")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def metadata_document_from_state(state: Mapping[str, Any]) -> dict[str, Any]:
    version = state.get("schema_version", SCHEMA_VERSION)
    if version == 1:
        fields = METADATA_STATE_FIELDS_V1
    elif version == STATE_SCHEMA_VERSION:
        fields = METADATA_STATE_FIELDS_V2
    else:
        raise IntegrityError(f"unsupported operational state schema: {version!r}")
    document: dict[str, Any] = {"schema_version": version}
    document.update({field: state.get(field) for field in fields})
    return document


def parse_bool(value: str, key: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"yes", "true", "1", "on"}:
        return True
    if normalized in {"no", "false", "0", "off"}:
        return False
    raise ConfigError(f"{key}: expected yes/no, got {value!r}")


def parse_int(value: str, key: str, minimum: int, maximum: int) -> int:
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise ConfigError(f"{key}: expected integer, got {value!r}") from exc
    if not minimum <= result <= maximum:
        raise ConfigError(f"{key}: expected {minimum}..{maximum}, got {result}")
    return result


def parse_float(value: str, key: str, minimum: float, maximum: float) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise ConfigError(f"{key}: expected number, got {value!r}") from exc
    if not minimum <= result <= maximum:
        raise ConfigError(f"{key}: expected {minimum}..{maximum}, got {result}")
    return result


def _safe_absolute_path(value: str, key: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ConfigError(f"{key}: path must be absolute")
    normalized = Path(os.path.abspath(os.fspath(path)))
    if normalized == Path(normalized.anchor):
        raise ConfigError(f"{key}: filesystem root is not allowed")
    return normalized


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class ProxyConfig:
    """One immutable listener-to-printer route.

    Addresses are canonical IPv4 strings.  That invariant is also what makes
    ``printer_directory_name`` safe to append to the configured archive root:
    it can contain only decimal digits and dots, never path separators.
    """

    proxy_id: str
    listen_ip: str
    listen_port: int
    printer_ip: str
    printer_port: int

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.proxy_id)
            or self.proxy_id in {".", ".."}
        ):
            raise ConfigError(f"unsafe proxy identifier: {self.proxy_id!r}")
        try:
            listen = ipaddress.IPv4Address(self.listen_ip)
            printer = ipaddress.IPv4Address(self.printer_ip)
        except ipaddress.AddressValueError as exc:
            raise ConfigError(f"invalid IPv4 proxy route: {exc}") from exc
        for key, value in (
            ("listen_port", self.listen_port),
            ("printer_port", self.printer_port),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise ConfigError(f"{key}: expected 1..65535, got {value!r}")
        object.__setattr__(self, "listen_ip", str(listen))
        object.__setattr__(self, "printer_ip", str(printer))

    @property
    def printer_directory_name(self) -> str:
        """Return the validated physical-printer IP used as archive dirname."""

        return self.printer_ip

    @property
    def listen_endpoint(self) -> tuple[str, int]:
        return self.listen_ip, self.listen_port

    @property
    def printer_endpoint(self) -> tuple[str, int]:
        return self.printer_ip, self.printer_port


@dataclass(frozen=True)
class Settings:
    config_path: Path
    proxy_protocol: str
    proxy_configs: tuple[ProxyConfig, ...]
    data_dir: Path
    spool_dir: Path
    log_dir: Path
    delivery_mode: str
    job_end_mode: str
    idle_timeout: float
    initial_data_timeout: float
    session_idle_timeout: float
    max_job_duration: float
    connect_timeout: float
    forward_timeout: float
    chunk_size: int
    max_job_bytes: int
    max_concurrent_clients: int
    max_concurrent_sidecars: int
    fsync_interval_bytes: int
    full_duplex: bool
    max_session_duration: float
    printer_response_timeout: float
    max_printer_response_capture_bytes: int
    debug_hexdump: bool
    debug_hexdump_max_bytes: int
    enable_readable_dump: bool
    max_readable_dump_bytes: int
    save_clean_text: bool
    save_pdf: bool
    pdf_width_mm: float
    enable_hex_dump: bool
    default_codepage: str
    enable_hash_chain: bool
    enable_hmac: bool
    hmac_key_file: Path
    hmac_credential_name: str
    min_free_disk_mb: int
    emergency_reserve_mb: int
    allowed_networks: tuple[ipaddress._BaseNetwork, ...]
    allowed_clients: tuple[ipaddress._BaseAddress, ...]
    auto_retry_before_send: bool
    retry_initial_seconds: float
    retry_max_seconds: float
    retry_jitter_percent: int
    preserve_queue_order: bool
    block_queue_on_unknown: bool
    request_poll_seconds: float
    enable_retention: bool
    retention_days: int
    retention_check_seconds: int
    enable_file_log: bool
    split_on_escpos_cut: bool
    shutdown_grace_seconds: float
    network_interface: str
    virtual_prefix: int
    enable_firewall: bool
    route_scoped: bool

    @property
    def primary_proxy(self) -> ProxyConfig:
        """Return the first route for source compatibility with v2 callers."""

        return self.proxy_configs[0]

    @property
    def listen_ip(self) -> str:
        return self.primary_proxy.listen_ip

    @property
    def listen_port(self) -> int:
        return self.primary_proxy.listen_port

    @property
    def printer_ip(self) -> str:
        return self.primary_proxy.printer_ip

    @property
    def printer_port(self) -> int:
        return self.primary_proxy.printer_port

    def for_proxy(self, proxy: ProxyConfig) -> Settings:
        """Return settings scoped to exactly one immutable proxy route.

        A one-route deployment keeps the historic flat DATA_DIR/SPOOL_DIR
        layout so existing manifests, HMAC chains and crash-recovery states
        remain visible after an upgrade.  In a multi-route deployment each
        physical printer gets its own archive/HMAC chain and operational
        spool.  Both use the validated printer IP as a stable identity, so
        reordering positional CSV mappings cannot attach old state to another
        destination.  Duplicate printer IPs are rejected by the parser.
        Existing flat history remains untouched at the configured roots.
        """

        if proxy not in self.proxy_configs:
            raise ConfigError(f"proxy route is not part of these settings: {proxy.proxy_id}")
        if len(self.proxy_configs) == 1:
            return self
        return replace(
            self,
            proxy_configs=(proxy,),
            data_dir=self.data_dir / proxy.printer_directory_name,
            spool_dir=self.spool_dir / proxy.printer_directory_name,
            route_scoped=True,
        )

    @property
    def states_dir(self) -> Path:
        return self.spool_dir / "states"

    @property
    def receiving_dir(self) -> Path:
        return self.spool_dir / "receiving"

    @property
    def requests_dir(self) -> Path:
        return self.spool_dir / "requests"

    @property
    def locks_dir(self) -> Path:
        return self.spool_dir / "locks"

    @property
    def manifest_path(self) -> Path:
        return self.data_dir / "manifest.jsonl"

    @property
    def manifest_head_path(self) -> Path:
        return self.data_dir / "manifest.head.json"

    @property
    def reserve_path(self) -> Path:
        return self.spool_dir / ".emergency-reserve"

    def client_allowed(self, address: str) -> bool:
        candidate = ipaddress.ip_address(address)
        if self.allowed_clients and candidate in self.allowed_clients:
            return True
        return any(candidate in network for network in self.allowed_networks)


DEFAULTS: dict[str, str] = {
    "PROXY_PROTOCOL": "raw",
    "LISTEN_IP": "10.1.2.220",
    "LISTEN_PORT": "9100",
    "PRINTER_IP": "10.1.2.200",
    "PRINTER_PORT": "9100",
    "DATA_DIR": "/var/lib/printproxy/jobs",
    "SPOOL_DIR": "/var/lib/printproxy/spool",
    "LOG_DIR": "/var/log/printproxy",
    "JOB_END_MODE": "hybrid",
    "IDLE_TIMEOUT": "3",
    "INITIAL_DATA_TIMEOUT": "15",
    "SESSION_IDLE_TIMEOUT": "300",
    "MAX_JOB_DURATION": "300",
    "CONNECT_TIMEOUT": "5",
    "FORWARD_TIMEOUT": "30",
    "CHUNK_SIZE": "65536",
    "MAX_JOB_BYTES": "67108864",
    "MAX_CONCURRENT_CLIENTS": "32",
    "MAX_CONCURRENT_SIDECARS": "2",
    "FSYNC_INTERVAL_BYTES": "262144",
    # Compatibility-safe default for an existing configuration that predates
    # DELIVERY_MODE. New installations ship an explicit transparent_duplex
    # value in config/printproxy.conf.
    "DELIVERY_MODE": "store_forward",
    "MAX_SESSION_DURATION": "900",
    "PRINTER_RESPONSE_TIMEOUT": "5",
    "MAX_PRINTER_RESPONSE_CAPTURE_BYTES": "65536",
    "DEBUG_HEXDUMP": "no",
    "DEBUG_HEXDUMP_MAX_BYTES": "256",
    "ENABLE_READABLE_DUMP": "yes",
    "MAX_READABLE_DUMP_BYTES": "1048576",
    "SAVE_CLEAN_TXT": "yes",
    "SAVE_PDF": "yes",
    "PDF_WIDTH_MM": "80",
    "ENABLE_HEX_DUMP": "no",
    "DEFAULT_CODEPAGE": "cp858",
    "HASH_ALGORITHM": "sha256",
    "ENABLE_HASH_CHAIN": "yes",
    "ENABLE_HMAC": "yes",
    "HMAC_KEY_FILE": "/etc/printproxy/integrity.key",
    "HMAC_CREDENTIAL_NAME": "integrity.key",
    "MIN_FREE_DISK_MB": "1024",
    "EMERGENCY_RESERVE_MB": "16",
    "ALLOWED_NETWORKS": "10.1.2.0/24",
    "ALLOWED_CLIENTS": "",
    "AUTO_RETRY_BEFORE_SEND": "yes",
    "RETRY_INITIAL_SECONDS": "5",
    "RETRY_MAX_SECONDS": "300",
    "RETRY_JITTER_PERCENT": "20",
    "PRESERVE_QUEUE_ORDER": "yes",
    "BLOCK_QUEUE_ON_UNKNOWN": "no",
    "REQUEST_POLL_SECONDS": "2",
    "ENABLE_RETENTION": "no",
    "RETENTION_DAYS": "365",
    "RETENTION_CHECK_SECONDS": "86400",
    "ENABLE_FILE_LOG": "yes",
    "SPLIT_ON_ESCPOS_CUT": "no",
    "SHUTDOWN_GRACE_SECONDS": "20",
    "NETWORK_INTERFACE": "auto",
    "VIRTUAL_PREFIX": "24",
    "ENABLE_FIREWALL": "no",
}


def read_config_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {path}: {exc}") from exc
    key_re = re.compile(r"^[A-Z][A-Z0-9_]*$")
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"{path}:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key_re.fullmatch(key):
            raise ConfigError(f"{path}:{line_number}: invalid key {key!r}")
        if key in values:
            raise ConfigError(f"{path}:{line_number}: duplicate key {key}")
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise ConfigError(f"{path}:{line_number}: unterminated quoted value")
            value = value[1:-1]
        if any(ord(character) < 32 and character != "\t" for character in value):
            raise ConfigError(f"{path}:{line_number}: control character in value")
        values[key] = value
    unknown = sorted(set(values) - set(DEFAULTS))
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(unknown)}")
    return values


_PROXY_ARRAY_KEYS = ("LISTEN_IP", "LISTEN_PORT", "PRINTER_IP", "PRINTER_PORT")


def _required_proxy_csv(value: str, key: str) -> tuple[str, ...]:
    """Split a required proxy array without silently discarding empty slots."""

    entries = tuple(item.strip() for item in value.split(","))
    for index, entry in enumerate(entries, 1):
        if not entry:
            raise ConfigError(
                f"{key}: entry {index} is empty; proxy arrays must not contain empty entries"
            )
    return entries


def _proxy_ipv4(value: str, key: str, index: int) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{key}[{index}]: invalid IP address {value!r}: {exc}") from exc
    if address.version != 4:
        raise ConfigError(f"{key}[{index}]: this release supports only IPv4 addresses")
    return str(address)


def parse_proxy_configs(raw: Mapping[str, str]) -> tuple[ProxyConfig, ...]:
    """Parse and validate positional CSV proxy arrays.

    The public configuration format intentionally remains the four historical
    keys.  A scalar value is therefore just a one-element array, while commas
    opt into N independent routes correlated strictly by index.
    """

    arrays = {key: _required_proxy_csv(raw[key], key) for key in _PROXY_ARRAY_KEYS}
    counts = {key: len(entries) for key, entries in arrays.items()}
    if len(set(counts.values())) != 1:
        detail = "; ".join(f"{key} contains {counts[key]} entries" for key in _PROXY_ARRAY_KEYS)
        raise ConfigError(
            f"proxy configuration array length mismatch: {detail}. "
            "All proxy configuration arrays must have the same number of entries."
        )

    proxies: list[ProxyConfig] = []
    listen_endpoints: dict[tuple[str, int], str] = {}
    listen_ips: dict[str, list[str]] = {}
    printer_ips: dict[str, str] = {}
    for offset in range(counts["LISTEN_IP"]):
        display_index = offset + 1
        listen_ip = _proxy_ipv4(arrays["LISTEN_IP"][offset], "LISTEN_IP", display_index)
        printer_ip = _proxy_ipv4(arrays["PRINTER_IP"][offset], "PRINTER_IP", display_index)
        listen_port = parse_int(
            arrays["LISTEN_PORT"][offset], f"LISTEN_PORT[{display_index}]", 1, 65535
        )
        printer_port = parse_int(
            arrays["PRINTER_PORT"][offset], f"PRINTER_PORT[{display_index}]", 1, 65535
        )
        proxy_id = f"proxy-{display_index:03d}"
        if listen_ip == "0.0.0.0":
            raise ConfigError(
                f"LISTEN_IP[{display_index}]=0.0.0.0 is forbidden; bind a dedicated address"
            )
        if (listen_ip, listen_port) == (printer_ip, printer_port):
            raise ConfigError(
                f"{proxy_id}: listener and printer destination must not be identical"
            )
        listen_endpoint = (listen_ip, listen_port)
        if previous := listen_endpoints.get(listen_endpoint):
            raise ConfigError(
                f"duplicate listener endpoint {listen_ip}:{listen_port} "
                f"in {previous} and {proxy_id}"
            )
        if previous := printer_ips.get(printer_ip):
            raise ConfigError(
                f"duplicate PRINTER_IP {printer_ip} in {previous} and {proxy_id}; "
                "jobs are partitioned by physical-printer IP"
            )
        listen_endpoints[listen_endpoint] = proxy_id
        listen_ips.setdefault(listen_ip, []).append(proxy_id)
        printer_ips[printer_ip] = proxy_id
        proxies.append(
            ProxyConfig(
                proxy_id=proxy_id,
                listen_ip=listen_ip,
                listen_port=listen_port,
                printer_ip=printer_ip,
                printer_port=printer_port,
            )
        )

    overlapping_ips = sorted(set(listen_ips) & set(printer_ips))
    if overlapping_ips:
        overlap = overlapping_ips[0]
        listener_routes = ", ".join(listen_ips[overlap])
        raise ConfigError(
            f"unsafe proxy route graph: PRINTER_IP {overlap} in {printer_ips[overlap]} "
            f"is also configured as LISTEN_IP in {listener_routes}; "
            "a physical-printer destination must not target any configured listener IP"
        )
    return tuple(proxies)


def load_settings(path: str | os.PathLike[str]) -> Settings:
    config_path = Path(path)
    raw = dict(DEFAULTS)
    raw.update(read_config_file(config_path))

    proxy_configs = parse_proxy_configs(raw)
    if raw["HASH_ALGORITHM"].lower() != "sha256":
        raise ConfigError("only HASH_ALGORITHM=sha256 is supported")
    if not parse_bool(raw["ENABLE_HASH_CHAIN"], "ENABLE_HASH_CHAIN"):
        raise ConfigError("ENABLE_HASH_CHAIN=no is unsupported; the audit ledger is mandatory")
    if raw["PROXY_PROTOCOL"].lower() != "raw":
        raise ConfigError("this release safely supports only PROXY_PROTOCOL=raw")
    delivery_mode = raw["DELIVERY_MODE"].lower()
    if delivery_mode not in {"store_forward", "transparent_duplex"}:
        raise ConfigError(
            "DELIVERY_MODE must be store_forward or transparent_duplex"
        )

    mode = raw["JOB_END_MODE"].lower()
    if mode not in {"connection_close", "idle_timeout", "hybrid"}:
        raise ConfigError("JOB_END_MODE must be connection_close, idle_timeout or hybrid")
    split_on_cut = parse_bool(raw["SPLIT_ON_ESCPOS_CUT"], "SPLIT_ON_ESCPOS_CUT")
    if split_on_cut:
        raise ConfigError(
            "SPLIT_ON_ESCPOS_CUT=yes is unsafe with binary raster/barcode payloads; use idle/close framing"
        )
    try:
        networks = tuple(ipaddress.ip_network(item, strict=False) for item in _split_csv(raw["ALLOWED_NETWORKS"]))
        clients = tuple(ipaddress.ip_address(item) for item in _split_csv(raw["ALLOWED_CLIENTS"]))
    except ValueError as exc:
        raise ConfigError(f"invalid ALLOWED_NETWORKS/ALLOWED_CLIENTS: {exc}") from exc
    if not networks and not clients:
        raise ConfigError("at least one ALLOWED_NETWORKS or ALLOWED_CLIENTS entry is required")
    if any(network.version != 4 for network in networks) or any(client.version != 4 for client in clients):
        raise ConfigError("client ACL entries must be IPv4")
    if raw["NETWORK_INTERFACE"] != "auto" and not re.fullmatch(
        r"[A-Za-z0-9_.:@-]{1,64}", raw["NETWORK_INTERFACE"]
    ):
        raise ConfigError("NETWORK_INTERFACE contains unsafe characters")

    data_dir = _safe_absolute_path(raw["DATA_DIR"], "DATA_DIR")
    spool_dir = _safe_absolute_path(raw["SPOOL_DIR"], "SPOOL_DIR")
    log_dir = _safe_absolute_path(raw["LOG_DIR"], "LOG_DIR")
    if len({data_dir, spool_dir, log_dir}) != 3:
        raise ConfigError("DATA_DIR, SPOOL_DIR and LOG_DIR must be distinct")

    try:
        "".encode(raw["DEFAULT_CODEPAGE"])
    except LookupError as exc:
        raise ConfigError(f"unknown DEFAULT_CODEPAGE: {raw['DEFAULT_CODEPAGE']}") from exc

    return Settings(
        config_path=config_path,
        proxy_protocol="raw",
        proxy_configs=proxy_configs,
        data_dir=data_dir,
        spool_dir=spool_dir,
        log_dir=log_dir,
        delivery_mode=delivery_mode,
        job_end_mode=mode,
        idle_timeout=parse_float(raw["IDLE_TIMEOUT"], "IDLE_TIMEOUT", 0.1, 3600),
        initial_data_timeout=parse_float(raw["INITIAL_DATA_TIMEOUT"], "INITIAL_DATA_TIMEOUT", 0.1, 3600),
        session_idle_timeout=parse_float(raw["SESSION_IDLE_TIMEOUT"], "SESSION_IDLE_TIMEOUT", 0.1, 86400),
        max_job_duration=parse_float(raw["MAX_JOB_DURATION"], "MAX_JOB_DURATION", 1, 86400),
        connect_timeout=parse_float(raw["CONNECT_TIMEOUT"], "CONNECT_TIMEOUT", 0.1, 300),
        forward_timeout=parse_float(raw["FORWARD_TIMEOUT"], "FORWARD_TIMEOUT", 0.1, 86400),
        chunk_size=parse_int(raw["CHUNK_SIZE"], "CHUNK_SIZE", 1024, 1048576),
        max_job_bytes=parse_int(raw["MAX_JOB_BYTES"], "MAX_JOB_BYTES", 1024, 10737418240),
        max_concurrent_clients=parse_int(raw["MAX_CONCURRENT_CLIENTS"], "MAX_CONCURRENT_CLIENTS", 1, 1024),
        max_concurrent_sidecars=parse_int(
            raw["MAX_CONCURRENT_SIDECARS"], "MAX_CONCURRENT_SIDECARS", 1, 16
        ),
        fsync_interval_bytes=parse_int(raw["FSYNC_INTERVAL_BYTES"], "FSYNC_INTERVAL_BYTES", 1, 1073741824),
        full_duplex=delivery_mode == "transparent_duplex",
        max_session_duration=parse_float(
            raw["MAX_SESSION_DURATION"], "MAX_SESSION_DURATION", 1, 86400
        ),
        printer_response_timeout=parse_float(
            raw["PRINTER_RESPONSE_TIMEOUT"], "PRINTER_RESPONSE_TIMEOUT", 0.1, 300
        ),
        max_printer_response_capture_bytes=parse_int(
            raw["MAX_PRINTER_RESPONSE_CAPTURE_BYTES"],
            "MAX_PRINTER_RESPONSE_CAPTURE_BYTES",
            0,
            16777216,
        ),
        debug_hexdump=parse_bool(raw["DEBUG_HEXDUMP"], "DEBUG_HEXDUMP"),
        debug_hexdump_max_bytes=parse_int(
            raw["DEBUG_HEXDUMP_MAX_BYTES"], "DEBUG_HEXDUMP_MAX_BYTES", 16, 65536
        ),
        enable_readable_dump=parse_bool(raw["ENABLE_READABLE_DUMP"], "ENABLE_READABLE_DUMP"),
        max_readable_dump_bytes=parse_int(
            raw["MAX_READABLE_DUMP_BYTES"], "MAX_READABLE_DUMP_BYTES", 1024, 1048576
        ),
        save_clean_text=parse_bool(raw["SAVE_CLEAN_TXT"], "SAVE_CLEAN_TXT"),
        save_pdf=parse_bool(raw["SAVE_PDF"], "SAVE_PDF"),
        pdf_width_mm=parse_float(raw["PDF_WIDTH_MM"], "PDF_WIDTH_MM", 48, 120),
        enable_hex_dump=parse_bool(raw["ENABLE_HEX_DUMP"], "ENABLE_HEX_DUMP"),
        default_codepage=raw["DEFAULT_CODEPAGE"],
        enable_hash_chain=parse_bool(raw["ENABLE_HASH_CHAIN"], "ENABLE_HASH_CHAIN"),
        enable_hmac=parse_bool(raw["ENABLE_HMAC"], "ENABLE_HMAC"),
        hmac_key_file=_safe_absolute_path(raw["HMAC_KEY_FILE"], "HMAC_KEY_FILE"),
        hmac_credential_name=raw["HMAC_CREDENTIAL_NAME"],
        min_free_disk_mb=parse_int(raw["MIN_FREE_DISK_MB"], "MIN_FREE_DISK_MB", 1, 1048576),
        emergency_reserve_mb=parse_int(raw["EMERGENCY_RESERVE_MB"], "EMERGENCY_RESERVE_MB", 0, 1024),
        allowed_networks=networks,
        allowed_clients=clients,
        auto_retry_before_send=parse_bool(raw["AUTO_RETRY_BEFORE_SEND"], "AUTO_RETRY_BEFORE_SEND"),
        retry_initial_seconds=parse_float(raw["RETRY_INITIAL_SECONDS"], "RETRY_INITIAL_SECONDS", 0.1, 86400),
        retry_max_seconds=parse_float(raw["RETRY_MAX_SECONDS"], "RETRY_MAX_SECONDS", 0.1, 604800),
        retry_jitter_percent=parse_int(raw["RETRY_JITTER_PERCENT"], "RETRY_JITTER_PERCENT", 0, 100),
        preserve_queue_order=parse_bool(raw["PRESERVE_QUEUE_ORDER"], "PRESERVE_QUEUE_ORDER"),
        block_queue_on_unknown=parse_bool(raw["BLOCK_QUEUE_ON_UNKNOWN"], "BLOCK_QUEUE_ON_UNKNOWN"),
        request_poll_seconds=parse_float(raw["REQUEST_POLL_SECONDS"], "REQUEST_POLL_SECONDS", 0.1, 60),
        enable_retention=parse_bool(raw["ENABLE_RETENTION"], "ENABLE_RETENTION"),
        retention_days=parse_int(raw["RETENTION_DAYS"], "RETENTION_DAYS", 1, 36500),
        retention_check_seconds=parse_int(raw["RETENTION_CHECK_SECONDS"], "RETENTION_CHECK_SECONDS", 60, 604800),
        enable_file_log=parse_bool(raw["ENABLE_FILE_LOG"], "ENABLE_FILE_LOG"),
        split_on_escpos_cut=split_on_cut,
        shutdown_grace_seconds=parse_float(raw["SHUTDOWN_GRACE_SECONDS"], "SHUTDOWN_GRACE_SECONDS", 1, 300),
        network_interface=raw["NETWORK_INTERFACE"],
        virtual_prefix=parse_int(raw["VIRTUAL_PREFIX"], "VIRTUAL_PREFIX", 1, 32),
        enable_firewall=parse_bool(raw["ENABLE_FIREWALL"], "ENABLE_FIREWALL"),
        route_scoped=False,
    )


def validate_directory(path: Path, *, create: bool = False, mode: int = 0o750) -> None:
    if create:
        path.mkdir(mode=mode, parents=True, exist_ok=True)
    try:
        info = path.lstat()
    except OSError as exc:
        raise StorageError(f"directory unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StorageError(f"expected real directory, not symlink: {path}")


_INSTALLER_SPOOL_DIRECTORIES = ("states", "receiving", "requests", "locks")


def _installer_directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if os.name != "posix" or any(not hasattr(os, name) for name in required):
        raise StorageError("secure installer directory operations require POSIX O_NOFOLLOW")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _installer_open_directory_at(parent_fd: int, name: str, *, mode: int) -> int:
    created = False
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    except OSError as exc:
        raise StorageError(f"cannot create installer directory component {name!r}: {exc}") from exc
    try:
        descriptor = os.open(name, _installer_directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise StorageError(
            f"unsafe installer directory component {name!r}; expected a real directory: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (linked.st_dev, linked.st_ino):
            raise StorageError(f"installer directory component changed during validation: {name!r}")
        if created:
            os.fchmod(descriptor, mode)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _installer_open_absolute_directory(path: Path, *, uid: int, gid: int) -> int:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or absolute == Path(absolute.anchor):
        raise StorageError(f"unsafe installer directory path: {path}")
    components = absolute.parts[1:]
    descriptor = os.open(absolute.anchor, _installer_directory_flags())
    try:
        for index, component in enumerate(components):
            is_target = index == len(components) - 1
            child = _installer_open_directory_at(
                descriptor,
                component,
                mode=0o750 if is_target else 0o755,
            )
            os.close(descriptor)
            descriptor = child
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o750)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _installer_reopen_absolute_directory(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, _installer_directory_flags())
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                _installer_directory_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def secure_prepare_service_directories(
    data_dir: Path,
    spool_dir: Path,
    log_dir: Path,
    *,
    uid: int,
    gid: int,
) -> None:
    """Create/chown installer-managed directories without following symlinks.

    The daemon owns the configured roots, so a compromised pre-upgrade process
    can replace their children.  Keep descriptors open throughout preparation,
    mutate only opened directory inodes, and verify that every pathname still
    resolves to the same inode before returning.
    """

    if uid <= 0 or gid <= 0:
        raise StorageError("printproxy installer requires non-root uid and gid")
    roots: dict[Path, int] = {}
    children: dict[str, int] = {}
    try:
        for path in (Path(data_dir), Path(spool_dir), Path(log_dir)):
            roots[path] = _installer_open_absolute_directory(path, uid=uid, gid=gid)
        spool_fd = roots[Path(spool_dir)]
        for name in _INSTALLER_SPOOL_DIRECTORIES:
            descriptor = _installer_open_directory_at(spool_fd, name, mode=0o750)
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, 0o750)
            children[name] = descriptor

        for name, descriptor in children.items():
            linked = os.stat(name, dir_fd=spool_fd, follow_symlinks=False)
            opened = os.fstat(descriptor)
            if (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino):
                raise StorageError(f"spool directory changed during preparation: {name!r}")
        for path, descriptor in roots.items():
            try:
                reopened = _installer_reopen_absolute_directory(path)
            except OSError as exc:
                raise StorageError(
                    f"service directory changed during preparation: {path}: {exc}"
                ) from exc
            try:
                expected = os.fstat(descriptor)
                actual = os.fstat(reopened)
                if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
                    raise StorageError(f"service directory changed during preparation: {path}")
            finally:
                os.close(reopened)
    finally:
        for descriptor in children.values():
            os.close(descriptor)
        for descriptor in roots.values():
            os.close(descriptor)


def ensure_runtime_directories(settings: Settings) -> None:
    if len(settings.proxy_configs) > 1:
        # Keep the configured roots available for pre-multi-printer history,
        # but never append new jobs to the shared root.  Every scoped Settings
        # object below has independent ledger and crash-recovery directories.
        for directory in (
            settings.data_dir,
            settings.spool_dir,
            settings.log_dir,
            settings.locks_dir,
        ):
            validate_directory(directory, create=True)
        scoped_settings = tuple(settings.for_proxy(proxy) for proxy in settings.proxy_configs)
    else:
        scoped_settings = (settings,)

    for scoped in scoped_settings:
        for directory in (
            scoped.data_dir,
            scoped.spool_dir,
            scoped.log_dir,
            scoped.states_dir,
            scoped.receiving_dir,
            scoped.requests_dir,
            scoped.locks_dir,
        ):
            validate_directory(directory, create=True)


def _open_flags(base: int) -> int:
    return (
        base
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise StorageError("short write returned zero bytes")
        view = view[written:]


def _open_regular_for_read(path: Path) -> int:
    """Open one regular, non-symlink inode; O_NOFOLLOW closes the Unix race."""
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise StorageError(f"not a regular non-symlink file: {path}")
    fd = os.open(path, _open_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)))
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode):
            raise StorageError(f"not a regular file: {path}")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise StorageError(f"file changed while opening: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular_file_bytes(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    fd = _open_regular_for_read(path)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StorageError(f"not a regular file: {path}")
        if info.st_size > max_bytes:
            raise StorageError(f"file exceeds safe read limit: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise StorageError(f"file exceeds safe read limit: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


_INSTALLER_ROUTE_LIST_KEYS = (
    "LISTEN_PORT_LIST",
    "PRINTER_IP_LIST",
    "PRINTER_PORT_LIST",
)
_INSTALLER_STORAGE_PATH_KEYS = ("DATA_DIR", "SPOOL_DIR")
_INSTALLER_STATE_MAX_BYTES = 64 * 1024
_INSTALLER_HISTORY_STATE_MAX_BYTES = 4 * 1024 * 1024
_INSTALLER_HISTORY_MAX_ENTRIES = 100_000
_INSTALLER_HISTORY_MAX_STATES = 10_000
_INSTALLER_HISTORY_MAX_STATE_BYTES = 128 * 1024 * 1024


def _read_installer_state(path: Path) -> dict[str, str]:
    """Read the root-owned installer state without following a symlink."""

    try:
        text = read_regular_file_bytes(path, max_bytes=_INSTALLER_STATE_MAX_BYTES).decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise ConfigError(f"installer state is not UTF-8: {path}") from exc
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"installer state line {line_number} is malformed")
        key, value = (item.strip() for item in line.split("=", 1))
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ConfigError(f"installer state line {line_number} has an unsafe key")
        if key in values:
            raise ConfigError(f"installer state contains duplicate key {key}")
        values[key] = value
    return values


def read_installed_storage_paths(path: Path) -> tuple[Path, Path]:
    """Read the last deployed DATA/SPOOL roots from the owned systemd drop-in.

    Installer states before schema 4 did not persist storage identity.  The
    previous installer-generated ``ReadWritePaths`` line is the only deployed
    record of those roots, so legacy upgrades must recover it or fail closed.
    """

    try:
        text = read_regular_file_bytes(path, max_bytes=65536).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"installed systemd path drop-in is not UTF-8: {path}") from exc
    populated: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("ReadWritePaths="):
            value = line.split("=", 1)[1].strip()
            if value:
                populated.append(value)
    if len(populated) != 1:
        raise ConfigError(
            "legacy installer state has no storage identity and the deployed "
            f"ReadWritePaths record is missing or ambiguous: {path}"
        )
    paths = populated[0].split()
    if len(paths) != 3:
        raise ConfigError(
            f"installed ReadWritePaths must contain DATA_DIR, SPOOL_DIR and LOG_DIR: {path}"
        )
    return (
        _safe_absolute_path(paths[0], "installed DATA_DIR"),
        _safe_absolute_path(paths[1], "installed SPOOL_DIR"),
    )


def _validate_installer_storage_lifecycle(
    settings: Settings,
    state: Mapping[str, str],
    legacy_storage_paths: tuple[Path, Path] | None,
) -> None:
    present = [key in state for key in _INSTALLER_STORAGE_PATH_KEYS]
    if any(present):
        missing = [key for key in _INSTALLER_STORAGE_PATH_KEYS if not state.get(key)]
        if missing or not all(present):
            raise ConfigError(
                "installer storage state is incomplete: "
                + ", ".join(missing or _INSTALLER_STORAGE_PATH_KEYS)
            )
        previous_data = _safe_absolute_path(state["DATA_DIR"], "installed DATA_DIR")
        previous_spool = _safe_absolute_path(state["SPOOL_DIR"], "installed SPOOL_DIR")
    else:
        if legacy_storage_paths is None:
            raise ConfigError(
                "legacy installer state has no DATA_DIR/SPOOL_DIR identity; recover the "
                "previous installer-owned systemd paths or perform an explicit migration"
            )
        previous_data, previous_spool = (
            _safe_absolute_path(str(legacy_storage_paths[0]), "installed DATA_DIR"),
            _safe_absolute_path(str(legacy_storage_paths[1]), "installed SPOOL_DIR"),
        )

    changed: list[str] = []
    if settings.data_dir != previous_data:
        changed.append(f"DATA_DIR {previous_data} -> {settings.data_dir}")
    if settings.spool_dir != previous_spool:
        changed.append(f"SPOOL_DIR {previous_spool} -> {settings.spool_dir}")
    if changed:
        raise ConfigError(
            "installed storage path change is forbidden because it would strand audit/spool "
            "history: "
            + "; ".join(changed)
            + ". Restore the installed paths or perform an explicit verified migration."
        )


def _route_signature(proxy: ProxyConfig) -> tuple[str, int, str, int]:
    return proxy.listen_ip, proxy.listen_port, proxy.printer_ip, proxy.printer_port


def _format_route_signature(route: tuple[str, int, str, int]) -> str:
    listen_ip, listen_port, printer_ip, printer_port = route
    return f"{listen_ip}:{listen_port}->{printer_ip}:{printer_port}"


def _require_installed_routes_preserved(
    current: tuple[ProxyConfig, ...], previous: tuple[ProxyConfig, ...]
) -> None:
    current_routes = {_route_signature(proxy) for proxy in current}
    missing = [
        _route_signature(proxy)
        for proxy in previous
        if _route_signature(proxy) not in current_routes
    ]
    if missing:
        detail = ", ".join(_format_route_signature(route) for route in missing)
        raise ConfigError(
            "installed proxy route removal/replacement is forbidden: "
            f"{detail}. Reordering and additive routes are allowed; otherwise "
            "stop the service, verify the archive, and use explicit uninstall/migration."
        )


class _InstallerHistoryBudget:
    """Bound one legacy discovery pass against directory/file amplification."""

    def __init__(self) -> None:
        self.entries_remaining = _INSTALLER_HISTORY_MAX_ENTRIES
        self.states_remaining = _INSTALLER_HISTORY_MAX_STATES
        self.state_bytes_remaining = _INSTALLER_HISTORY_MAX_STATE_BYTES

    def entries(self, count: int, path: Path) -> None:
        self.entries_remaining -= count
        if self.entries_remaining < 0:
            raise ConfigError(
                "legacy route discovery exceeded its bounded entry limit at "
                f"{path}; verify and migrate the archive explicitly"
            )

    def state(self, size: int, path: Path) -> None:
        self.states_remaining -= 1
        self.state_bytes_remaining -= size
        if self.states_remaining < 0 or self.state_bytes_remaining < 0:
            raise ConfigError(
                "legacy route discovery exceeded its bounded state/byte limit at "
                f"{path}; verify and migrate the archive explicitly"
            )


def _installer_directory_entries(
    path: Path, budget: _InstallerHistoryBudget
) -> tuple[Path, ...]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise ConfigError(f"legacy history directory is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ConfigError(f"legacy history path is not a real directory: {path}")
    entries: list[Path] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                budget.entries(1, path)
                entries.append(Path(entry.path))
    except OSError as exc:
        raise ConfigError(f"cannot scan legacy history directory {path}: {exc}") from exc
    return tuple(sorted(entries, key=lambda item: item.name))


def _installer_regular_info(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConfigError(f"legacy history entry is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"legacy history entry is not a regular non-symlink file: {path}")
    return info


def _state_route_signature(
    path: Path, budget: _InstallerHistoryBudget
) -> tuple[str, int, str, int]:
    info = _installer_regular_info(path)
    budget.state(info.st_size, path)
    try:
        value = json.loads(
            read_regular_file_bytes(path, max_bytes=_INSTALLER_HISTORY_STATE_MAX_BYTES)
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError, StorageError) as exc:
        raise ConfigError(f"legacy state cannot be read safely: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"legacy state is not a JSON object: {path}")
    listen_ip = value.get("proxy_ip")
    listen_port = value.get("proxy_port")
    printer_ip = value.get("printer_ip")
    printer_port = value.get("printer_port")
    if not isinstance(listen_ip, str) or not isinstance(printer_ip, str):
        raise ConfigError(f"legacy state has no inferable listener/printer IPv4 tuple: {path}")
    if (
        isinstance(listen_port, bool)
        or not isinstance(listen_port, int)
        or not 1 <= listen_port <= 65535
        or isinstance(printer_port, bool)
        or not isinstance(printer_port, int)
        or not 1 <= printer_port <= 65535
    ):
        raise ConfigError(f"legacy state has no inferable listener/printer port tuple: {path}")
    try:
        canonical_listen = str(ipaddress.IPv4Address(listen_ip))
        canonical_printer = str(ipaddress.IPv4Address(printer_ip))
    except ipaddress.AddressValueError as exc:
        raise ConfigError(f"legacy state has an invalid IPv4 endpoint: {path}: {exc}") from exc
    return canonical_listen, listen_port, canonical_printer, printer_port


def _manifest_head_has_history(path: Path) -> bool:
    _installer_regular_info(path)
    try:
        value = json.loads(read_regular_file_bytes(path, max_bytes=65536))
    except (OSError, ValueError, TypeError, json.JSONDecodeError, StorageError) as exc:
        raise ConfigError(f"legacy manifest head cannot be read safely: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"legacy manifest head is not a JSON object: {path}")
    count = value.get("record_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ConfigError(f"legacy manifest head has an invalid record count: {path}")
    return count > 0


def _installer_data_history_present(
    path: Path, budget: _InstallerHistoryBudget, *, allow_scopes: bool
) -> tuple[bool, set[str]]:
    history = False
    scope_names: set[str] = set()
    for entry in _installer_directory_entries(path, budget):
        try:
            info = entry.lstat()
        except OSError as exc:
            raise ConfigError(f"legacy archive entry is unavailable: {entry}: {exc}") from exc
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            try:
                scope_name = str(ipaddress.IPv4Address(entry.name))
            except ipaddress.AddressValueError:
                scope_name = ""
            if allow_scopes and scope_name == entry.name:
                scope_names.add(scope_name)
                continue
            raise ConfigError(f"unexpected legacy archive directory: {entry}")
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"unsafe legacy archive entry: {entry}")
        if entry.name == "manifest.head.json":
            history = _manifest_head_has_history(entry) or history
        elif entry.name == "manifest.jsonl":
            history = info.st_size > 0 or history
        else:
            history = True
    return history, scope_names


def _installer_spool_history(
    path: Path,
    budget: _InstallerHistoryBudget,
    *,
    allow_scopes: bool,
    printer_hint: str | None,
) -> tuple[bool, set[tuple[str, int, str, int]], set[str]]:
    history = False
    routes: set[tuple[str, int, str, int]] = set()
    scope_names: set[str] = set()
    entries = _installer_directory_entries(path, budget)
    by_name = {entry.name: entry for entry in entries}
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError as exc:
            raise ConfigError(f"legacy spool entry is unavailable: {entry}: {exc}") from exc
        if entry.name in {"states", "receiving", "requests", "locks"}:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ConfigError(f"unsafe legacy spool directory: {entry}")
            continue
        if entry.name == ".emergency-reserve":
            _installer_regular_info(entry)
            continue
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            try:
                scope_name = str(ipaddress.IPv4Address(entry.name))
            except ipaddress.AddressValueError:
                scope_name = ""
            if allow_scopes and scope_name == entry.name:
                scope_names.add(scope_name)
                continue
            raise ConfigError(f"unexpected legacy spool directory: {entry}")
        raise ConfigError(f"unexpected legacy spool entry without route identity: {entry}")

    state_dir = by_name.get("states", path / "states")
    state_entries = _installer_directory_entries(state_dir, budget)
    if state_entries:
        history = True
    for state_path in state_entries:
        if state_path.suffix != ".json":
            raise ConfigError(f"unexpected legacy state entry: {state_path}")
        route = _state_route_signature(state_path, budget)
        if printer_hint is not None and route[2] != printer_hint:
            raise ConfigError(
                f"legacy state {state_path} targets {route[2]}, outside its {printer_hint} scope"
            )
        routes.add(route)

    for directory_name in ("receiving", "requests"):
        pending = _installer_directory_entries(path / directory_name, budget)
        history = bool(pending) or history
    return history, routes, scope_names


def _legacy_installer_routes(
    settings: Settings, legacy_listen_ips: set[str]
) -> tuple[ProxyConfig, ...]:
    budget = _InstallerHistoryBudget()
    flat_data_history, data_scopes = _installer_data_history_present(
        settings.data_dir, budget, allow_scopes=True
    )
    flat_spool_history, flat_routes, spool_scopes = _installer_spool_history(
        settings.spool_dir, budget, allow_scopes=True, printer_hint=None
    )
    if (flat_data_history or flat_spool_history) and not flat_routes:
        raise ConfigError(
            "legacy flat archive/spool is non-empty but no complete route can be inferred "
            "from bounded operational state JSON; stop, verify, and migrate it explicitly"
        )

    routes = set(flat_routes)
    for scope_name in sorted(data_scopes | spool_scopes):
        scoped_data_history, nested_data_scopes = _installer_data_history_present(
            settings.data_dir / scope_name, budget, allow_scopes=False
        )
        if nested_data_scopes:
            raise ConfigError(f"nested legacy archive scopes are forbidden: {scope_name}")
        scoped_spool_history, scoped_routes, nested_spool_scopes = _installer_spool_history(
            settings.spool_dir / scope_name,
            budget,
            allow_scopes=False,
            printer_hint=scope_name,
        )
        if nested_spool_scopes:
            raise ConfigError(f"nested legacy spool scopes are forbidden: {scope_name}")
        if (scoped_data_history or scoped_spool_history) and not scoped_routes:
            raise ConfigError(
                f"legacy {scope_name} archive/spool is non-empty but its route cannot be "
                "inferred from bounded operational state JSON; migrate it explicitly"
            )
        routes.update(scoped_routes)

    for route in routes:
        if route[0] not in legacy_listen_ips:
            raise ConfigError(
                "legacy state route is inconsistent with installer-owned listener IPs: "
                f"{_format_route_signature(route)}"
            )
    return tuple(
        ProxyConfig(
            proxy_id=f"legacy-{index:03d}",
            listen_ip=route[0],
            listen_port=route[1],
            printer_ip=route[2],
            printer_port=route[3],
        )
        for index, route in enumerate(sorted(routes), 1)
    )


def _installed_routes_from_state(
    settings: Settings, install_state_path: Path
) -> tuple[ProxyConfig, ...]:
    state = _read_installer_state(install_state_path)
    mapping_fields_present = [key in state for key in _INSTALLER_ROUTE_LIST_KEYS]
    if any(mapping_fields_present):
        required = ("VIP_LIST", *_INSTALLER_ROUTE_LIST_KEYS)
        missing = [key for key in required if not state.get(key)]
        if missing or not all(mapping_fields_present):
            detail = ", ".join(missing or _INSTALLER_ROUTE_LIST_KEYS)
            raise ConfigError(f"installer mapping state is incomplete: {detail}")
        return parse_proxy_configs(
            {
                "LISTEN_IP": state["VIP_LIST"],
                "LISTEN_PORT": state["LISTEN_PORT_LIST"],
                "PRINTER_IP": state["PRINTER_IP_LIST"],
                "PRINTER_PORT": state["PRINTER_PORT_LIST"],
            }
        )

    legacy_listen_csv = state.get("VIP_LIST") or state.get("VIP")
    if not legacy_listen_csv:
        raise ConfigError("legacy installer state has no listener IP identity")
    legacy_listen_ips: set[str] = set()
    for index, value in enumerate(_required_proxy_csv(legacy_listen_csv, "VIP_LIST"), 1):
        canonical = _proxy_ipv4(value, "VIP_LIST", index)
        if canonical in legacy_listen_ips:
            raise ConfigError(f"legacy installer state contains duplicate listener IP {canonical}")
        legacy_listen_ips.add(canonical)
    return _legacy_installer_routes(settings, legacy_listen_ips)


def validate_installer_route_lifecycle(
    settings: Settings,
    install_state_path: Path,
    *,
    legacy_storage_paths: tuple[Path, Path] | None = None,
) -> None:
    """Forbid silently orphaning or rebinding an installed printer route.

    Mapping-aware installer states are authoritative.  Older states did not
    persist ports/printers, so their historical endpoints are inferred only
    from bounded, regular operational-state JSON files.  A non-empty history
    without a complete endpoint is deliberately not guessed.
    """

    state = _read_installer_state(install_state_path)
    previous = _installed_routes_from_state(settings, install_state_path)
    _require_installed_routes_preserved(settings.proxy_configs, previous)
    _validate_installer_storage_lifecycle(settings, state, legacy_storage_paths)


def read_regular_file_prefix(path: Path, *, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes`` from one verified regular inode.

    One extra byte is consumed only to report truncation.  This keeps optional
    receipt rendering bounded without turning a large, otherwise valid RAW job
    into a print-path failure.
    """

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    fd = _open_regular_for_read(path)
    try:
        chunks: list[bytes] = []
        total = 0
        target = max_bytes + 1
        while total < target:
            chunk = os.read(fd, min(65536, target - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        value = b"".join(chunks)
        return value[:max_bytes], len(value) > max_bytes
    finally:
        os.close(fd)


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # Windows has no portable directory fsync. Production target is Debian;
        # this branch exists so the platform-independent unit tests can run.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _same_open_directory(path: Path, descriptor: int) -> bool:
    try:
        reopened = _installer_reopen_absolute_directory(path)
    except OSError:
        return False
    try:
        expected = os.fstat(descriptor)
        actual = os.fstat(reopened)
        return (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
    finally:
        os.close(reopened)


def _atomic_write_as_parent_owner(path: Path, data: bytes, mode: int) -> None:
    """Publish one daemon-readable file through a held, no-follow directory FD."""

    if os.name != "posix":
        raise StorageError("parent-owned atomic writes require POSIX dirfd support")
    parent = Path(path.parent)
    try:
        parent_fd = _installer_reopen_absolute_directory(parent)
    except OSError as exc:
        raise StorageError(f"request directory is unavailable or unsafe: {parent}: {exc}") from exc
    temporary_name = f".{path.name}.{uuid.uuid4().hex}.tmp"
    temporary_fd: int | None = None
    renamed = False
    try:
        parent_info = os.fstat(parent_fd)
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        if not stat.S_ISDIR(parent_info.st_mode) or not _same_open_directory(parent, parent_fd):
            raise StorageError(f"request directory changed during validation: {parent}")
        if parent_info.st_uid <= 0 or parent_info.st_gid <= 0:
            raise StorageError(
                f"request directory must be owned by the non-root daemon account: {parent}"
            )
        if parent_mode & 0o022 or parent_mode & 0o700 != 0o700:
            raise StorageError(f"request directory has unsafe permissions {parent_mode:04o}: {parent}")
        effective_uid = os.geteuid()
        if effective_uid not in {0, parent_info.st_uid}:
            raise StorageError(
                "request creation requires root or the account owning the request directory"
            )

        temporary_fd = os.open(
            temporary_name,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            mode,
            dir_fd=parent_fd,
        )
        write_all(temporary_fd, data)
        os.fchown(temporary_fd, parent_info.st_uid, parent_info.st_gid)
        os.fchmod(temporary_fd, mode)
        os.fsync(temporary_fd)
        linked = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(temporary_fd)
        if (
            not stat.S_ISREG(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino)
            or not _same_open_directory(parent, parent_fd)
        ):
            raise StorageError("request directory or temporary file changed before publish")
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        renamed = True
        published = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (published.st_dev, published.st_ino) != (opened.st_dev, opened.st_ino)
            or not _same_open_directory(parent, parent_fd)
        ):
            raise StorageError("request directory or file changed during publish")
        os.fsync(parent_fd)
    except BaseException:
        cleanup_name = path.name if renamed else temporary_name
        with contextlib.suppress(OSError):
            os.unlink(cleanup_name, dir_fd=parent_fd)
        raise
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        os.close(parent_fd)


def atomic_write_bytes(
    path: Path,
    data: bytes,
    mode: int = 0o640,
    *,
    inherit_parent_owner: bool = False,
) -> None:
    if inherit_parent_owner and os.name == "posix":
        _atomic_write_as_parent_owner(path, data, mode)
        return
    validate_directory(path.parent)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL), mode)
    try:
        write_all(fd, data)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    else:
        os.close(fd)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def atomic_write_json(
    path: Path,
    value: Mapping[str, Any],
    mode: int = 0o640,
    *,
    inherit_parent_owner: bool = False,
) -> None:
    atomic_write_bytes(
        path,
        canonical_json(value) + b"\n",
        mode=mode,
        inherit_parent_owner=inherit_parent_owner,
    )


def durable_move(source: Path, destination: Path) -> None:
    """Move a sealed file durably, including an EXDEV-safe copy path."""
    validate_directory(source.parent)
    validate_directory(destination.parent)
    try:
        os.replace(source, destination)
        destination_fd = os.open(destination, _open_flags(os.O_RDWR))
        try:
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        fsync_directory(destination.parent)
        if source.parent != destination.parent:
            fsync_directory(source.parent)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    source_fd = os.open(source, _open_flags(os.O_RDONLY))
    try:
        destination_fd = os.open(
            temporary, _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL), 0o640
        )
    except BaseException:
        os.close(source_fd)
        raise
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            write_all(destination_fd, chunk)
        os.fsync(destination_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    os.replace(temporary, destination)
    fsync_directory(destination.parent)
    source.unlink()
    fsync_directory(source.parent)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    fd = _open_regular_for_read(path)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise StorageError(f"not a regular file: {path}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), size


def disk_free_mb(path: Path) -> int:
    if hasattr(os, "statvfs"):
        stats = os.statvfs(path)
        return (stats.f_bavail * stats.f_frsize) // (1024 * 1024)
    return shutil.disk_usage(path).free // (1024 * 1024)


def load_hmac_key(settings: Settings, *, cli: bool = False) -> bytes | None:
    if not settings.enable_hmac:
        return None
    candidates: list[Path] = []
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credential_dir and not cli:
        candidates.append(Path(credential_dir) / settings.hmac_credential_name)
    candidates.append(settings.hmac_key_file)
    for path in candidates:
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ConfigError(f"HMAC key must be a regular non-symlink file: {path}")
            if (
                os.name == "posix"
                and path == settings.hmac_key_file
                and path.parent == Path("/etc/printproxy")
                and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600)
            ):
                raise ConfigError(f"HMAC key must be root:root mode 0600: {path}")
            key = read_regular_file_bytes(path, max_bytes=4096)
        except OSError:
            continue
        if len(key) < 32:
            raise ConfigError(f"HMAC key {path} must contain at least 32 bytes")
        return key
    raise ConfigError(
        "ENABLE_HMAC=yes but no key is readable; use systemd LoadCredential or run the CLI as root"
    )


def verify_manifest_head(settings: Settings, key: bytes | None) -> tuple[bool, str]:
    """Perform an O(1) online head/HMAC check without scanning the live ledger."""
    try:
        encoded = read_regular_file_bytes(settings.manifest_head_path, max_bytes=65536)
        head = json.loads(encoded)
        if not isinstance(head, dict) or encoded != canonical_json(head) + b"\n":
            raise IntegrityError("manifest head is not canonical JSON")
        count = head.get("record_count")
        chain_hash = head.get("last_chain_hash")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise IntegrityError("manifest head count is invalid")
        if not isinstance(chain_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", chain_hash):
            raise IntegrityError("manifest head hash is invalid")
        if key is not None:
            expected = hmac.new(
                key,
                canonical_json({"record_count": count, "last_chain_hash": chain_hash}),
                hashlib.sha256,
            ).hexdigest()
            actual = head.get("hmac_sha256")
            if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
                raise IntegrityError("manifest head HMAC mismatch")
        return True, f"authenticated head: {count} records, {chain_hash}"
    except (OSError, ValueError, TypeError, json.JSONDecodeError, StorageError, IntegrityError) as exc:
        return False, safe_error(exc)


@contextlib.contextmanager
def advisory_lock(path: Path, *, exclusive: bool = True) -> Iterator[None]:
    validate_directory(path.parent)
    fd = os.open(path, _open_flags(os.O_RDWR | os.O_CREAT), 0o640)
    try:
        try:
            import fcntl  # type: ignore

            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        except ImportError:
            pass  # Unit tests can run on Windows; production target is Debian.
        yield
    finally:
        try:
            import fcntl  # type: ignore

            fcntl.flock(fd, fcntl.LOCK_UN)
        except ImportError:
            pass
        os.close(fd)


class StateStore:
    def __init__(self, settings: Settings):
        self.settings = settings

    def path_for(self, job_id: str) -> Path:
        uuid.UUID(job_id)
        return self.settings.states_dir / f"{job_id}.json"

    def lock_path_for(self, job_id: str) -> Path:
        parsed = uuid.UUID(job_id)
        # A fixed shard set avoids leaking one inode per retained/deleted job.
        # Collisions only serialize unrelated state transitions; correctness is
        # unchanged and cross-process locking remains stable.
        return self.settings.locks_dir / f"job-{parsed.hex[:2]}.lock"

    @contextlib.contextmanager
    def locked(self, job_id: str) -> Iterator[None]:
        with advisory_lock(self.lock_path_for(job_id), exclusive=True):
            yield

    def write(self, state: Mapping[str, Any]) -> None:
        job_id = str(state["job_id"])
        atomic_write_json(self.path_for(job_id), dict(state))

    def load(self, job_id: str) -> dict[str, Any]:
        path = self.path_for(job_id)
        value = json.loads(read_regular_file_bytes(path, max_bytes=4 * 1024 * 1024))
        if not isinstance(value, dict):
            raise StorageError(f"state file must contain a JSON object: {path}")
        if value.get("job_id") != job_id:
            raise StorageError(f"job id mismatch in {path}")
        return value

    def list(self) -> list[dict[str, Any]]:
        states: list[dict[str, Any]] = []
        for path in sorted(self.settings.states_dir.glob("*.json")):
            try:
                states.append(self.load(path.stem))
            except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError, StorageError):
                states.append({"job_id": path.stem, "state": "QUARANTINED", "state_error": "unreadable"})
        return states

    def create_request(
        self,
        request: Mapping[str, Any],
        *,
        inherit_parent_owner: bool = False,
    ) -> Path:
        request_id = str(uuid.uuid4())
        path = self.settings.requests_dir / f"{request_id}.json"
        payload = dict(request)
        payload["request_id"] = request_id
        atomic_write_json(
            path,
            payload,
            inherit_parent_owner=inherit_parent_owner,
        )
        return path


@dataclass
class VerificationReport:
    ok: bool
    records: int
    jobs: int
    errors: list[str]
    warnings: list[str]
    last_chain_hash: str


class IntegrityLedger:
    """Append-only, hash-chained and optionally HMAC-authenticated JSONL ledger."""

    def __init__(
        self,
        settings: Settings,
        key: bytes | None,
        *,
        repair_head: bool = True,
        read_only: bool = False,
    ):
        if read_only and repair_head:
            raise ValueError("a read-only ledger cannot repair its authenticated head")
        self.settings = settings
        self.key = key
        self._read_only = read_only
        self._thread_lock = threading.RLock()
        self._lock_path = settings.locks_dir / "manifest.lock"
        self._last_hash = ZERO_HASH
        self._record_count = 0
        self._archive_records: dict[str, dict[str, Any]] = {}
        self._latest_job_records: dict[str, dict[str, Any]] = {}
        self._consumed_request_records: dict[str, dict[str, Any]] = {}
        self._manifest_signature_cache: tuple[int, int, int, int, int] | None = None
        self._repair_head = repair_head
        self._load_head_or_manifest()
        self._manifest_signature_cache = self._manifest_signature()
        self._rebuild_archive_index()

    @property
    def _route_destination(self) -> str | None:
        """Return the authenticated storage-scope identity for multi-route ledgers.

        A historical/single-route flat ledger remains deliberately unbound so
        pre-multi-printer records continue to verify byte-for-byte.  Every
        record created below a per-printer route scope is instead bound to the
        immutable physical endpoint already carried by the ledger's
        ``destination`` field.
        """

        if not self.settings.route_scoped:
            return None
        return f"{self.settings.printer_ip}:{self.settings.printer_port}"

    def _manifest_signature(self) -> tuple[int, int, int, int, int] | None:
        try:
            info = self.settings.manifest_path.stat()
        except FileNotFoundError:
            return None
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _line_hmac(self, chain_hash: str) -> str | None:
        if self.key is None:
            return None
        return hmac.new(self.key, bytes.fromhex(chain_hash), hashlib.sha256).hexdigest()

    def _head_hmac(self, count: int, chain_hash: str) -> str | None:
        if self.key is None:
            return None
        payload = canonical_json({"record_count": count, "last_chain_hash": chain_hash})
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def _load_head_or_manifest(self) -> None:
        report = self.verify(check_files=False, repair_head=self._repair_head)
        if not report.ok:
            raise IntegrityError("ledger verification failed: " + "; ".join(report.errors))
        self._last_hash = report.last_chain_hash
        self._record_count = report.records

    def _rebuild_archive_index(self) -> None:
        self._archive_records.clear()
        self._latest_job_records.clear()
        self._consumed_request_records.clear()
        if not self.settings.manifest_path.exists():
            return
        with self.settings.manifest_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                record = json.loads(raw_line)
                if record.get("event") == "ARCHIVED" and isinstance(record.get("job_id"), str):
                    self._archive_records[record["job_id"]] = record
                if isinstance(record.get("job_id"), str):
                    self._latest_job_records[record["job_id"]] = record
                operator_action = record.get("operator_action")
                if record.get("event") == "MANUAL_RETRY_QUEUED" and isinstance(
                    operator_action, dict
                ):
                    request_id = operator_action.get("request_id")
                    if isinstance(request_id, str):
                        self._consumed_request_records[request_id] = record

    def _validate_cached_head(self) -> None:
        if self._manifest_signature() != self._manifest_signature_cache:
            raise IntegrityError("manifest changed outside the authenticated append path")
        try:
            head_bytes = read_regular_file_bytes(
                self.settings.manifest_head_path, max_bytes=65536
            )
            head = json.loads(head_bytes)
            if not isinstance(head, dict) or head_bytes != canonical_json(head) + b"\n":
                raise IntegrityError("authenticated manifest head is not canonical JSON")
        except (OSError, ValueError, TypeError, json.JSONDecodeError, StorageError) as exc:
            raise IntegrityError(f"cannot read authenticated manifest head: {exc}") from exc
        count = head.get("record_count")
        chain_hash = head.get("last_chain_hash")
        if count != self._record_count or chain_hash != self._last_hash:
            raise IntegrityError("manifest head changed outside this ledger instance")
        expected = self._head_hmac(count, chain_hash)
        if self.key is not None and (
            not isinstance(head.get("hmac_sha256"), str)
            or expected is None
            or not hmac.compare_digest(head["hmac_sha256"], expected)
        ):
            raise IntegrityError("manifest head HMAC mismatch")
        if self._record_count == 0:
            if self.settings.manifest_path.exists() and self.settings.manifest_path.stat().st_size:
                raise IntegrityError("non-empty manifest conflicts with empty authenticated head")
            return
        try:
            manifest_fd = os.open(
                self.settings.manifest_path,
                _open_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
            )
            try:
                manifest_info = os.fstat(manifest_fd)
                if not stat.S_ISREG(manifest_info.st_mode):
                    raise IntegrityError("manifest is not a regular file")
                size = manifest_info.st_size
                window = min(size, 1024 * 1024)
                os.lseek(manifest_fd, size - window, os.SEEK_SET)
                tail = bytearray()
                while len(tail) < window:
                    chunk = os.read(manifest_fd, window - len(tail))
                    if not chunk:
                        break
                    tail.extend(chunk)
            finally:
                os.close(manifest_fd)
            tail = bytes(tail)
            if not tail.endswith(b"\n"):
                raise IntegrityError("manifest tail is truncated")
            lines = tail.splitlines()
            if not lines:
                raise IntegrityError("authenticated manifest has no tail record")
            raw_last = lines[-1]
            if size > window and b"\n" not in tail[:-1]:
                raise IntegrityError("manifest tail record exceeds validation window")
            last = json.loads(raw_last)
            if not isinstance(last, dict) or raw_last + b"\n" != canonical_json(last) + b"\n":
                raise IntegrityError("manifest tail is not canonical JSON")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"cannot authenticate manifest tail: {exc}") from exc
        if last.get("sequence") != self._record_count or last.get("chain_hash") != self._last_hash:
            raise IntegrityError("manifest tail differs from authenticated cached head")
        expected_destination = self._route_destination
        if (
            expected_destination is not None
            and last.get("destination") != expected_destination
        ):
            raise IntegrityError(
                "manifest tail route binding does not match this physical printer scope"
            )
        previous_hash = last.get("previous_chain_hash")
        if not isinstance(previous_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", previous_hash):
            raise IntegrityError("manifest tail previous hash is malformed")
        tail_payload = {
            key: value
            for key, value in last.items()
            if key not in {"previous_chain_hash", "chain_hash", "hmac_sha256"}
        }
        tail_encoded = canonical_json(tail_payload)
        tail_digest = hashlib.sha256()
        tail_digest.update(bytes.fromhex(previous_hash))
        tail_digest.update(len(tail_encoded).to_bytes(8, "big"))
        tail_digest.update(tail_encoded)
        if not hmac.compare_digest(tail_digest.hexdigest(), self._last_hash):
            raise IntegrityError("manifest tail payload does not match its authenticated hash")
        actual_mac = last.get("hmac_sha256")
        expected_mac = self._line_hmac(self._last_hash)
        if self.key is not None and (
            not isinstance(actual_mac, str)
            or expected_mac is None
            or not hmac.compare_digest(actual_mac, expected_mac)
        ):
            raise IntegrityError("manifest tail HMAC mismatch")

    def append(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if self._read_only:
            raise IntegrityError("cannot append through a read-only ledger")
        with self._thread_lock, advisory_lock(self._lock_path, exclusive=True):
            self._validate_cached_head()
            supplied = dict(event)
            forbidden = {
                "schema_version",
                "sequence",
                "timestamp",
                "previous_chain_hash",
                "chain_hash",
                "hmac_sha256",
            }
            if forbidden.intersection(supplied):
                raise IntegrityError("event attempts to override reserved ledger fields")
            expected_destination = self._route_destination
            if expected_destination is not None:
                supplied_destination = supplied.get("destination")
                if (
                    supplied_destination is not None
                    and supplied_destination != expected_destination
                ):
                    raise IntegrityError(
                        "ledger event destination does not match this physical printer scope"
                    )
                supplied["destination"] = expected_destination
            event_id = str(supplied.pop("event_id", uuid.uuid4()))
            uuid.UUID(event_id)
            sequence = self._record_count + 1
            previous = self._last_hash
            payload = {
                "schema_version": SCHEMA_VERSION,
                "sequence": sequence,
                "event_id": event_id,
                "timestamp": utc_now(),
                **supplied,
            }
            encoded = canonical_json(payload)
            digest = hashlib.sha256()
            digest.update(bytes.fromhex(previous))
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            chain_hash = digest.hexdigest()
            record = {
                **payload,
                "previous_chain_hash": previous,
                "chain_hash": chain_hash,
                "hmac_sha256": self._line_hmac(chain_hash),
            }
            line = canonical_json(record) + b"\n"
            fd = os.open(
                self.settings.manifest_path,
                _open_flags(os.O_WRONLY | os.O_CREAT | os.O_APPEND),
                0o640,
            )
            try:
                write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            fsync_directory(self.settings.data_dir)
            head = {
                "schema_version": SCHEMA_VERSION,
                "record_count": sequence,
                "last_chain_hash": chain_hash,
                "hmac_sha256": self._head_hmac(sequence, chain_hash),
            }
            atomic_write_json(self.settings.manifest_head_path, head)
            self._last_hash = chain_hash
            self._record_count = sequence
            self._manifest_signature_cache = self._manifest_signature()
            if record.get("event") == "ARCHIVED" and isinstance(record.get("job_id"), str):
                self._archive_records[record["job_id"]] = record
            if isinstance(record.get("job_id"), str):
                self._latest_job_records[record["job_id"]] = record
            operator_action = record.get("operator_action")
            if record.get("event") == "MANUAL_RETRY_QUEUED" and isinstance(
                operator_action, dict
            ):
                request_id = operator_action.get("request_id")
                if isinstance(request_id, str):
                    self._consumed_request_records[request_id] = record
            return record

    def archive_record(self, job_id: str) -> dict[str, Any] | None:
        uuid.UUID(job_id)
        with self._thread_lock:
            record = self._archive_records.get(job_id)
            return dict(record) if record is not None else None

    def latest_job_record(self, job_id: str) -> dict[str, Any] | None:
        uuid.UUID(job_id)
        with self._thread_lock:
            record = self._latest_job_records.get(job_id)
            return dict(record) if record is not None else None

    def latest_job_records(self) -> dict[str, dict[str, Any]]:
        with self._thread_lock:
            return {job_id: dict(record) for job_id, record in self._latest_job_records.items()}

    def consumed_request_record(self, request_id: str) -> dict[str, Any] | None:
        uuid.UUID(request_id)
        with self._thread_lock:
            record = self._consumed_request_records.get(request_id)
            return dict(record) if record is not None else None

    def find_event(self, event_id: str) -> dict[str, Any] | None:
        """Find an outbox event after first validating the complete chain."""
        uuid.UUID(event_id)
        lock_context = (
            contextlib.nullcontext()
            if self._read_only
            else advisory_lock(self._lock_path, exclusive=False)
        )
        with self._thread_lock, lock_context:
            self._validate_cached_head()
            if not self.settings.manifest_path.exists():
                return None
            with self.settings.manifest_path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    record = json.loads(raw_line)
                    if record.get("event_id") == event_id:
                        return record
        return None

    def verify(
        self,
        *,
        check_files: bool = True,
        repair_head: bool = False,
        already_locked: bool = False,
    ) -> VerificationReport:
        if self._read_only and repair_head:
            raise ValueError("a read-only ledger cannot repair its authenticated head")
        errors: list[str] = []
        warnings: list[str] = []
        previous = ZERO_HASH
        count = 0
        jobs: dict[str, dict[str, Any]] = {}
        hashes_by_sequence: dict[int, str] = {0: ZERO_HASH}

        lock_context = (
            contextlib.nullcontext()
            if already_locked or self._read_only
            else advisory_lock(self._lock_path, exclusive=False)
        )
        with lock_context:
            if self.settings.manifest_path.exists():
                try:
                    manifest_info = self.settings.manifest_path.lstat()
                    if stat.S_ISLNK(manifest_info.st_mode) or not stat.S_ISREG(manifest_info.st_mode):
                        raise IntegrityError("manifest is not a regular file")
                    with self.settings.manifest_path.open("rb") as handle:
                        for line_number, raw_line in enumerate(handle, 1):
                            if not raw_line.endswith(b"\n"):
                                errors.append(f"manifest line {line_number} is truncated")
                                break
                            try:
                                record = json.loads(raw_line)
                            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                                errors.append(f"manifest line {line_number} invalid JSON: {exc}")
                                break
                            if not isinstance(record, dict):
                                errors.append(f"manifest line {line_number} must be a JSON object")
                                break
                            try:
                                canonical_line = canonical_json(record) + b"\n"
                            except (TypeError, ValueError) as exc:
                                errors.append(
                                    f"manifest line {line_number}: non-canonical value: {exc}"
                                )
                                break
                            if raw_line != canonical_line:
                                errors.append(
                                    f"manifest line {line_number}: serialization is not canonical"
                                )
                            expected_destination = self._route_destination
                            if (
                                expected_destination is not None
                                and record.get("destination") != expected_destination
                            ):
                                errors.append(
                                    f"manifest line {line_number}: route binding does not match "
                                    "this physical printer scope"
                                )
                            count += 1
                            if record.get("sequence") != count:
                                errors.append(f"manifest line {line_number}: invalid sequence")
                            if record.get("previous_chain_hash") != previous:
                                errors.append(f"manifest line {line_number}: previous hash mismatch")
                            payload = {
                                key: value
                                for key, value in record.items()
                                if key not in {"previous_chain_hash", "chain_hash", "hmac_sha256"}
                            }
                            try:
                                encoded = canonical_json(payload)
                            except (TypeError, ValueError) as exc:
                                errors.append(f"manifest line {line_number}: non-canonical value: {exc}")
                                break
                            digest = hashlib.sha256()
                            try:
                                digest.update(bytes.fromhex(previous))
                            except ValueError:
                                errors.append(f"manifest line {line_number}: malformed previous hash")
                                previous = ZERO_HASH
                                continue
                            digest.update(len(encoded).to_bytes(8, "big"))
                            digest.update(encoded)
                            calculated = digest.hexdigest()
                            actual = str(record.get("chain_hash", ""))
                            if not hmac.compare_digest(actual, calculated):
                                errors.append(f"manifest line {line_number}: chain hash mismatch")
                            try:
                                expected_mac = self._line_hmac(actual) if len(actual) == 64 else None
                            except ValueError:
                                expected_mac = None
                                errors.append(f"manifest line {line_number}: malformed chain hash")
                            actual_mac = record.get("hmac_sha256")
                            if self.key is not None and (
                                not isinstance(actual_mac, str)
                                or expected_mac is None
                                or not hmac.compare_digest(actual_mac, expected_mac)
                            ):
                                errors.append(f"manifest line {line_number}: HMAC mismatch")
                            valid_actual = bool(re.fullmatch(r"[0-9a-f]{64}", actual))
                            previous = actual if valid_actual else ZERO_HASH
                            hashes_by_sequence[count] = previous
                            job_id = record.get("job_id")
                            if isinstance(job_id, str):
                                jobs[job_id] = record
                except OSError as exc:
                    errors.append(f"cannot read manifest: {exc}")

            head: dict[str, Any] | None = None
            if self.settings.manifest_head_path.exists() or self.settings.manifest_head_path.is_symlink():
                try:
                    head_info = self.settings.manifest_head_path.lstat()
                    if stat.S_ISLNK(head_info.st_mode) or not stat.S_ISREG(head_info.st_mode):
                        raise OSError("manifest head is not a regular non-symlink file")
                    head = json.loads(self.settings.manifest_head_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    errors.append(f"invalid manifest head: {exc}")
                if head is not None and not isinstance(head, dict):
                    errors.append("manifest head must be a JSON object")
                    head = None
            if head is not None:
                head_count = head.get("record_count")
                head_hash = head.get("last_chain_hash")
                head_mac = head.get("hmac_sha256")
                valid_head_mac = self._head_hmac(head_count, head_hash) if isinstance(head_count, int) and isinstance(head_hash, str) else None
                head_hmac_valid = self.key is None or (
                    isinstance(head_mac, str)
                    and valid_head_mac is not None
                    and hmac.compare_digest(head_mac, valid_head_mac)
                )
                if not head_hmac_valid:
                    errors.append("manifest head HMAC mismatch")
                if head_count != count or head_hash != previous:
                    prefix_is_authenticated = (
                        isinstance(head_count, int)
                        and 0 <= head_count
                        and count == head_count + 1
                        and hashes_by_sequence.get(head_count) == head_hash
                        and head_hmac_valid
                    )
                    if repair_head and prefix_is_authenticated and not errors:
                        warnings.append("manifest head repaired after a durable append interruption")
                        head = {
                            "schema_version": SCHEMA_VERSION,
                            "record_count": count,
                            "last_chain_hash": previous,
                            "hmac_sha256": self._head_hmac(count, previous),
                        }
                        atomic_write_json(self.settings.manifest_head_path, head)
                    else:
                        errors.append("manifest head does not match manifest tail")
            elif count:
                errors.append("manifest head is missing; automatic reconstruction would hide tail rollback")
            elif repair_head and not self.settings.manifest_head_path.exists():
                atomic_write_json(
                    self.settings.manifest_head_path,
                    {
                        "schema_version": SCHEMA_VERSION,
                        "record_count": 0,
                        "last_chain_hash": ZERO_HASH,
                        "hmac_sha256": self._head_hmac(0, ZERO_HASH),
                    },
                )

            if check_files:
                archived: dict[str, dict[str, Any]] = {}
                deleted: set[str] = set()
                if self.settings.manifest_path.exists() and not errors:
                    with self.settings.manifest_path.open("r", encoding="utf-8") as handle:
                        for raw_line in handle:
                            record = json.loads(raw_line)
                            job_id = record.get("job_id")
                            event = record.get("event")
                            if isinstance(job_id, str) and event == "ARCHIVED":
                                archived[job_id] = record
                            elif isinstance(job_id, str) and event == "RETENTION_DELETED":
                                deleted.add(job_id)
                referenced_raw: set[str] = set()
                metadata_documents: dict[str, dict[str, Any]] = {}
                for job_id, record in archived.items():
                    if job_id in deleted:
                        continue
                    filename = record.get("raw_filename")
                    if not isinstance(filename, str) or Path(filename).name != filename:
                        errors.append(f"job {job_id}: unsafe raw filename")
                        continue
                    referenced_raw.add(filename)
                    path = self.settings.data_dir / filename
                    try:
                        digest, size = sha256_file(path)
                    except (OSError, StorageError) as exc:
                        errors.append(f"job {job_id}: raw unavailable: {exc}")
                        continue
                    if digest != record.get("raw_sha256"):
                        errors.append(f"job {job_id}: SHA-256 mismatch")
                    if size != record.get("raw_size"):
                        errors.append(f"job {job_id}: size mismatch")
                    if record.get("state_schema_version") == STATE_SCHEMA_VERSION:
                        for filename_key, hash_key, suffix, label in (
                            (
                                "clean_filename",
                                "clean_sha256",
                                ".PULITO.txt",
                                "clean receipt",
                            ),
                            ("pdf_filename", "pdf_sha256", ".pdf", "receipt PDF"),
                        ):
                            artifact_filename = record.get(filename_key)
                            artifact_hash = record.get(hash_key)
                            if artifact_filename is None:
                                continue
                            expected_name = Path(filename).with_suffix(suffix).name
                            if (
                                not isinstance(artifact_filename, str)
                                or Path(artifact_filename).name != artifact_filename
                                or artifact_filename != expected_name
                            ):
                                errors.append(f"job {job_id}: unsafe {label} filename")
                                continue
                            artifact_path = self.settings.data_dir / artifact_filename
                            try:
                                actual_artifact_hash, _ = sha256_file(artifact_path)
                            except (OSError, StorageError) as exc:
                                message = f"job {job_id}: {label} unavailable: {exc}"
                                if record.get("render_status") == "complete":
                                    errors.append(message)
                                else:
                                    warnings.append(message)
                                continue
                            if (
                                not isinstance(artifact_hash, str)
                                or not hmac.compare_digest(actual_artifact_hash, artifact_hash)
                            ):
                                errors.append(f"job {job_id}: {label} SHA-256 mismatch")
                    metadata_filename = record.get("metadata_filename")
                    metadata_hash = record.get("metadata_sha256")
                    if isinstance(metadata_filename, str) and Path(metadata_filename).name == metadata_filename:
                        metadata_path = self.settings.data_dir / metadata_filename
                        try:
                            metadata_bytes = read_regular_file_bytes(metadata_path)
                            actual_meta = hashlib.sha256(metadata_bytes).hexdigest()
                            metadata_document = json.loads(metadata_bytes)
                            if not isinstance(metadata_document, dict):
                                raise ValueError("metadata is not a JSON object")
                            metadata_documents[job_id] = metadata_document
                        except (OSError, ValueError, json.JSONDecodeError, StorageError) as exc:
                            errors.append(f"job {job_id}: metadata unavailable: {exc}")
                        else:
                            if not metadata_hash:
                                errors.append(f"job {job_id}: metadata hash missing from manifest")
                            latest = jobs.get(job_id, {})
                            latest_hash = latest.get("metadata_sha256", metadata_hash)
                            if actual_meta != latest_hash:
                                errors.append(f"job {job_id}: metadata SHA-256 mismatch")
                    else:
                        errors.append(f"job {job_id}: unsafe metadata filename")
                for raw_path in self.settings.data_dir.glob("*.raw"):
                    if raw_path.name not in referenced_raw:
                        errors.append(f"orphan RAW not referenced by manifest: {raw_path.name}")
                for job_id, latest in jobs.items():
                    if latest.get("event") == "RETENTION_DELETED":
                        continue
                    if job_id not in metadata_documents:
                        metadata_filename = latest.get("metadata_filename")
                        if (
                            not isinstance(metadata_filename, str)
                            or Path(metadata_filename).name != metadata_filename
                        ):
                            errors.append(f"job {job_id}: unsafe metadata filename")
                        else:
                            metadata_path = self.settings.data_dir / metadata_filename
                            try:
                                metadata_bytes = read_regular_file_bytes(metadata_path)
                                actual_meta = hashlib.sha256(metadata_bytes).hexdigest()
                                metadata_document = json.loads(metadata_bytes)
                                if not isinstance(metadata_document, dict):
                                    raise ValueError("metadata is not a JSON object")
                                metadata_documents[job_id] = metadata_document
                                if actual_meta != latest.get("metadata_sha256"):
                                    errors.append(
                                        f"job {job_id}: metadata SHA-256 mismatch"
                                    )
                            except (OSError, ValueError, json.JSONDecodeError, StorageError) as exc:
                                errors.append(f"job {job_id}: metadata unavailable: {exc}")
                    try:
                        state = StateStore(self.settings).load(job_id)
                    except (OSError, ValueError, TypeError, json.JSONDecodeError, StorageError) as exc:
                        errors.append(f"job {job_id}: operational state file unavailable: {exc}")
                        continue
                    if state.get("schema_version") not in {SCHEMA_VERSION, STATE_SCHEMA_VERSION}:
                        errors.append(f"job {job_id}: invalid operational state schema")
                    if state.get("pending_ledger_event") is not None:
                        errors.append(f"job {job_id}: durable ledger event requires recovery")
                        continue
                    current = state.get("state")
                    allowed = STATE_LATEST_EVENTS.get(current) if isinstance(current, str) else None
                    if allowed is None:
                        errors.append(f"job {job_id}: unknown operational state {current!r}")
                    elif latest.get("event") not in allowed:
                        errors.append(
                            f"job {job_id}: state/latest-event mismatch "
                            f"({current}/{latest.get('event')})"
                        )
                    if state.get("last_committed_event") != latest.get("event"):
                        errors.append(f"job {job_id}: latest event marker mismatch")
                    archive = archived.get(job_id)
                    if archive is not None and (
                        state.get("raw_filename") != archive.get("raw_filename")
                        or state.get("raw_sha256") != archive.get("raw_sha256")
                        or state.get("bytes_archived") != archive.get("raw_size")
                    ):
                        errors.append(f"job {job_id}: state differs from authenticated archive")
                    metadata_document = metadata_documents.get(job_id)
                    if (
                        metadata_document is not None
                        and metadata_document != metadata_document_from_state(state)
                    ):
                        errors.append(f"job {job_id}: state differs from authenticated metadata")
                    if not isinstance(state.get("queue_order"), str):
                        errors.append(f"job {job_id}: invalid queue_order")
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
                            errors.append(f"job {job_id}: invalid queue_sequence")
                    for field in (
                        "bytes_received",
                        "bytes_archived",
                        "bytes_forwarded",
                        "attempts",
                    ):
                        value = state.get(field)
                        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                            errors.append(f"job {job_id}: invalid {field}")

        return VerificationReport(
            ok=not errors,
            records=count,
            jobs=len(jobs),
            errors=errors,
            warnings=warnings,
            last_chain_hash=previous,
        )


_MIGRATION_SAFE_TERMINAL_STATES = {
    "SENT_UNCONFIRMED",
    "PARTIAL",
    "DUPLEX_ABORTED",
    "QUARANTINED",
    "RETENTION_DELETED",
}


def validate_single_to_multi_migration(
    settings: Settings,
    install_state_path: Path,
    key: bytes | None,
) -> None:
    """Verify the legacy flat store before it becomes read-only history.

    This check is intentionally offline and non-repairing.  The complete HMAC
    ledger, referenced RAW/metadata and operational states are authenticated
    before mutable state names are considered for terminality.  Otherwise an
    operator or attacker could relabel a replayable root state as terminal and
    strand it during the switch to per-printer scopes.
    """

    previous = _installed_routes_from_state(settings, install_state_path)
    _require_installed_routes_preserved(settings.proxy_configs, previous)
    if len(settings.proxy_configs) <= 1 or len(previous) != 1:
        raise ConfigError(
            "single-to-multi integrity validation requires exactly one installed route "
            "and more than one configured route"
        )
    if settings.enable_hmac and key is None:
        raise IntegrityError("single-to-multi migration requires the configured HMAC key")

    previous_proxy = previous[0]
    legacy = replace(
        settings,
        proxy_configs=(previous_proxy,),
        route_scoped=False,
    )
    ledger = IntegrityLedger(legacy, key, repair_head=False, read_only=True)
    report = ledger.verify(check_files=True, repair_head=False)
    if not report.ok:
        raise IntegrityError(
            "legacy flat ledger/archive/state verification failed: " + "; ".join(report.errors)
        )

    budget = _InstallerHistoryBudget()
    problems: list[str] = []
    latest_records = ledger.latest_job_records()
    for path in _installer_directory_entries(legacy.states_dir, budget):
        if path.suffix != ".json":
            problems.append(f"states/{path.name}: unexpected entry")
            continue
        try:
            info = _installer_regular_info(path)
            budget.state(info.st_size, path)
            state = json.loads(
                read_regular_file_bytes(path, max_bytes=_INSTALLER_HISTORY_STATE_MAX_BYTES)
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError, StorageError) as exc:
            problems.append(f"states/{path.name}: unreadable/corrupt ({type(exc).__name__})")
            continue
        if not isinstance(state, dict):
            problems.append(f"states/{path.name}: state is not a JSON object")
            continue
        job_id = state.get("job_id")
        valid_job_id = isinstance(job_id, str)
        if valid_job_id:
            try:
                uuid.UUID(job_id)
            except ValueError:
                valid_job_id = False
        if not valid_job_id or path.name != f"{job_id}.json":
            problems.append(f"states/{path.name}: job identity mismatch")
            continue
        if job_id not in latest_records:
            problems.append(f"states/{path.name}: no authenticated ledger event")
        if (
            state.get("proxy_ip") != previous_proxy.listen_ip
            or state.get("proxy_port") != previous_proxy.listen_port
            or state.get("printer_ip") != previous_proxy.printer_ip
            or state.get("printer_port") != previous_proxy.printer_port
        ):
            problems.append(f"states/{path.name}: endpoint differs from installed route")
        status = state.get("state")
        if status not in _MIGRATION_SAFE_TERMINAL_STATES:
            problems.append(f"states/{path.name}: unresolved state {status!r}")

    for directory in (legacy.receiving_dir, legacy.requests_dir):
        for path in _installer_directory_entries(directory, budget):
            problems.append(f"{path.relative_to(legacy.spool_dir)}: pending")

    if problems:
        detail = "; ".join(problems[:50])
        if len(problems) > 50:
            detail += f"; ... and {len(problems) - 50} more"
        raise IntegrityError(f"legacy root spool is not migration-safe: {detail}")


CODEPAGE_BY_ESC_T = {
    0: "cp437",
    2: "cp850",
    16: "cp1252",
    19: "cp858",
}


def _decode_text(data: bytes, encoding: str, *, allow_utf8_detection: bool = True) -> str:
    if not data:
        return ""
    if allow_utf8_detection and any(byte >= 0x80 for byte in data):
        try:
            candidate = data.decode("utf-8", errors="strict")
            if any(ord(character) > 127 for character in candidate):
                return candidate
        except UnicodeDecodeError:
            pass
    try:
        return data.decode(encoding, errors="backslashreplace")
    except LookupError:
        return "".join(chr(byte) if 32 <= byte < 127 else f"\\x{byte:02x}" for byte in data)


def escpos_to_text(
    data: bytes, default_codepage: str = "cp858", max_output_chars: int = 4_000_000
) -> str:
    """Best-effort, bounded ESC/POS rendering; the input is never modified."""
    output: list[str] = []
    text = bytearray()
    encoding = default_codepage
    allow_utf8_detection = True
    index = 0
    output_chars = 0
    truncated = False

    def emit(value: str) -> None:
        nonlocal output_chars, truncated
        remaining = max_output_chars - output_chars
        if remaining <= 0:
            truncated = True
            return
        if len(value) > remaining:
            output.append(value[:remaining])
            output_chars += remaining
            truncated = True
        else:
            output.append(value)
            output_chars += len(value)

    def flush() -> None:
        if text:
            emit(
                _decode_text(
                    bytes(text), encoding, allow_utf8_detection=allow_utf8_detection
                )
            )
            text.clear()

    def tag(value: str) -> None:
        flush()
        emit(f"[{value}]")

    while index < len(data) and not truncated:
        byte = data[index]
        if byte == 0x0A:
            flush()
            emit("\n")
            index += 1
        elif byte == 0x0D:
            flush()
            index += 1
        elif byte == 0x09:
            text.extend(b"    ")
            index += 1
        elif byte == 0x1B and index + 1 < len(data):
            command = data[index + 1]
            if command == 0x40:
                tag("ESC/POS INIT")
                index += 2
            elif command == 0x74 and index + 2 < len(data):
                code = data[index + 2]
                flush()
                encoding = CODEPAGE_BY_ESC_T.get(code, encoding)
                allow_utf8_detection = False
                emit(f"[ESC/POS CODEPAGE {code} {encoding}]")
                index += 3
            elif command in {0x21, 0x45, 0x61, 0x64, 0x4A, 0x33, 0x20} and index + 2 < len(data):
                names = {0x21: "STYLE", 0x45: "BOLD", 0x61: "ALIGN", 0x64: "FEED_LINES", 0x4A: "FEED_DOTS", 0x33: "LINE_SPACING", 0x20: "CHAR_SPACING"}
                tag(f"ESC/POS {names[command]} {data[index + 2]}")
                index += 3
            elif command == 0x70 and index + 4 < len(data):
                tag("ESC/POS CASH_DRAWER")
                index += 5
            elif command == 0x2A and index + 4 < len(data):
                width = data[index + 3] + (data[index + 4] << 8)
                density = data[index + 2]
                multiplier = 3 if density in {32, 33} else 1
                payload_length = width * multiplier
                available = min(payload_length, max(0, len(data) - (index + 5)))
                tag(f"ESC/POS BIT_IMAGE bytes={available}")
                index += 5 + available
            else:
                tag(f"ESC/POS ESC 0x{command:02X}")
                index += 2
        elif byte == 0x1D and index + 1 < len(data):
            command = data[index + 1]
            if command == 0x56 and index + 2 < len(data):
                mode = data[index + 2]
                length = 4 if mode in {65, 66} and index + 3 < len(data) else 3
                tag("ESC/POS CUT")
                index += length
            elif command == 0x21 and index + 2 < len(data):
                tag(f"ESC/POS CHAR_SIZE {data[index + 2]}")
                index += 3
            elif command == 0x76 and index + 7 < len(data) and data[index + 2] == 0x30:
                width_bytes = data[index + 4] + (data[index + 5] << 8)
                height = data[index + 6] + (data[index + 7] << 8)
                payload_length = width_bytes * height
                available = min(payload_length, max(0, len(data) - (index + 8)))
                tag(f"ESC/POS RASTER_IMAGE bytes={available}")
                index += 8 + available
            elif command == 0x6B and index + 2 < len(data):
                mode = data[index + 2]
                if mode >= 65 and index + 3 < len(data):
                    declared = data[index + 3]
                    available = min(declared, max(0, len(data) - (index + 4)))
                    tag(f"ESC/POS BARCODE bytes={available}")
                    index += 4 + available
                else:
                    end = data.find(b"\x00", index + 3)
                    end = len(data) if end < 0 else end + 1
                    tag(f"ESC/POS BARCODE bytes={max(0, end - index - 3)}")
                    index = end
            elif command == 0x28 and index + 4 < len(data):
                declared = data[index + 3] + (data[index + 4] << 8)
                available = min(declared, max(0, len(data) - (index + 5)))
                tag(f"ESC/POS GS_PAREN bytes={available}")
                index += 5 + available
            else:
                tag(f"ESC/POS GS 0x{command:02X}")
                index += 2
        elif byte == 0x10 and index + 2 < len(data):
            tag(f"ESC/POS REALTIME 0x{data[index + 1]:02X} {data[index + 2]}")
            index += 3
        elif byte < 0x20 or byte == 0x7F:
            tag(f"BYTE 0x{byte:02X}")
            index += 1
        else:
            text.append(byte)
            index += 1
    flush()
    if truncated:
        output.append("\n[READABLE OUTPUT TRUNCATED; AUTHORITATIVE RAW IS COMPLETE]\n")
    rendered = "".join(output)
    return rendered.rstrip("\n") + "\n"


def find_escpos_cut(data: bytes) -> tuple[int, int] | None:
    """Return (start, end) for a cut command; use only when explicitly enabled."""
    index = 0
    while True:
        index = data.find(b"\x1d\x56", index)
        if index < 0 or index + 2 >= len(data):
            return None
        mode = data[index + 2]
        if mode in {0, 1, 48, 49}:
            return index, index + 3
        if mode in {65, 66} and index + 3 < len(data):
            return index, index + 4
        index += 2


def hexdump_file(source: Path, destination: Path) -> None:
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    source_fd = os.open(source, _open_flags(os.O_RDONLY))
    try:
        output_fd = os.open(
            temporary, _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL), 0o640
        )
    except BaseException:
        os.close(source_fd)
        raise
    offset = 0
    try:
        while True:
            chunk = os.read(source_fd, 16)
            if not chunk:
                break
            hexadecimal = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            line = f"{offset:08x}  {hexadecimal:<47}  |{ascii_part}|\n".encode("ascii")
            write_all(output_fd, line)
            offset += len(chunk)
        os.fsync(output_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    finally:
        os.close(source_fd)
        os.close(output_fd)
    os.replace(temporary, destination)
    fsync_directory(destination.parent)


def readable_file(
    source: Path, destination: Path, default_codepage: str, max_bytes: int = 16 * 1024 * 1024
) -> None:
    # Receipt jobs are bounded by MAX_JOB_BYTES.  The parser is a sidecar only;
    # failure here must never affect the sealed RAW or forwarding eligibility.
    fd = os.open(source, _open_flags(os.O_RDONLY))
    try:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        while True:
            remaining = max_bytes - total
            if remaining <= 0:
                truncated = bool(os.read(fd, 1))
                break
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        rendered = escpos_to_text(b"".join(chunks), default_codepage)
        if truncated:
            rendered += (
                f"[READABLE DUMP TRUNCATED AFTER {max_bytes} BYTES; "
                "AUTHORITATIVE RAW IS COMPLETE]\n"
            )
    finally:
        os.close(fd)
    atomic_write_bytes(destination, rendered.encode("utf-8"))


def metadata_hash(path: Path) -> str:
    return sha256_file(path)[0]


def safe_error(exc: BaseException, limit: int = 500) -> str:
    text = f"{type(exc).__name__}: {exc}".replace("\r", " ").replace("\n", " ")
    return text[:limit]


def service_instance_lock(settings: Settings) -> contextlib.AbstractContextManager[None]:
    return advisory_lock(settings.locks_dir / "service.lock", exclusive=True)


def create_emergency_reserve(settings: Settings) -> None:
    if settings.emergency_reserve_mb <= 0 or settings.reserve_path.exists():
        return
    fd = os.open(
        settings.reserve_path,
        _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
        0o600,
    )
    try:
        size = settings.emergency_reserve_mb * 1024 * 1024
        if hasattr(os, "posix_fallocate"):
            os.posix_fallocate(fd, 0, size)
        else:
            os.ftruncate(fd, size)
        os.fsync(fd)
    except BaseException:
        with contextlib.suppress(OSError):
            settings.reserve_path.unlink()
        with contextlib.suppress(OSError):
            fsync_directory(settings.spool_dir)
        raise
    finally:
        os.close(fd)
    fsync_directory(settings.spool_dir)


def release_emergency_reserve(settings: Settings) -> bool:
    try:
        settings.reserve_path.unlink()
        fsync_directory(settings.spool_dir)
        return True
    except FileNotFoundError:
        return False


def retention_eligible(state: Mapping[str, Any], cutoff_epoch: float) -> bool:
    if state.get("state") != "SENT_UNCONFIRMED":
        return False
    timestamp = state.get("timestamp_archive_complete") or state.get("timestamp_start")
    if not isinstance(timestamp, str):
        return False
    try:
        epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False
    return epoch < cutoff_epoch
