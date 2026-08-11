#!/usr/bin/env python3
"""Administrative and diagnostic CLI for printproxy."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

_SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if _SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, _SCRIPT_DIRECTORY)

from printproxy_core import (  # noqa: E402
    ConfigError,
    IntegrityError,
    IntegrityLedger,
    ProxyConfig,
    Settings,
    StateStore,
    StorageError,
    atomic_write_bytes,
    disk_free_mb,
    load_hmac_key,
    load_settings,
    safe_error,
    sha256_file,
    utc_now,
    verify_manifest_head,
)


def run_command(arguments: list[str], timeout: float = 10) -> tuple[int, str]:
    try:
        process = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (process.stdout or process.stderr).strip()
        return process.returncode, output
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, safe_error(exc)


def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str, float]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000
            return True, "reachable", elapsed
    except OSError as exc:
        elapsed = (time.monotonic() - started) * 1000
        return False, safe_error(exc), elapsed


def proc_tcp_listener(
    host: str, port: int, proc_path: Path = Path("/proc/net/tcp")
) -> tuple[bool | None, str]:
    """Inspect one exact IPv4 LISTEN socket without traversing the firewall.

    ``None`` means the Linux proc view is unavailable and callers may use a TCP
    fallback.  A readable proc table returning ``False`` is authoritative.
    """

    try:
        address = socket.inet_aton(host)[::-1].hex().upper()
    except OSError as exc:
        return False, safe_error(exc)
    expected = f"{address}:{port:04X}"
    try:
        with proc_path.open("r", encoding="ascii", errors="strict") as handle:
            for index, line in enumerate(handle):
                if index > 1_000_000:
                    return False, "proc socket table exceeds safety limit"
                fields = line.split()
                if len(fields) >= 4 and fields[1].upper() == expected and fields[3] == "0A":
                    return True, "exact LISTEN socket present in /proc/net/tcp"
    except (OSError, UnicodeError) as exc:
        return None, f"proc socket table unavailable: {safe_error(exc)}"
    return False, "exact LISTEN socket absent from /proc/net/tcp"


def ntp_status() -> tuple[bool, str]:
    if shutil.which("timedatectl") is None:
        return False, "timedatectl unavailable"
    code, output = run_command(
        ["timedatectl", "show", "--property=NTPSynchronized", "--value"], timeout=5
    )
    if code != 0:
        return False, output
    synchronized = output.strip().lower() == "yes"
    return synchronized, "synchronized" if synchronized else "NOT synchronized"


def service_status() -> tuple[str, str]:
    if shutil.which("systemctl") is None:
        return "unavailable", "systemctl unavailable"
    code, output = run_command(["systemctl", "is-active", "printproxy.service"], timeout=5)
    return ("active" if code == 0 else "inactive"), output


def format_state_line(state: dict[str, Any]) -> str:
    route = state.get("proxy_id")
    prefix = f"[{route}] " if route else ""
    return (
        f"{prefix}{state.get('job_id', '?')}  {state.get('state', '?'):<24} "
        f"bytes={state.get('bytes_archived', 0):>8} attempts={state.get('attempts', 0):>3} "
        f"start={state.get('timestamp_start', '?')}"
    )


def _proxy_settings(settings: Settings) -> tuple[tuple[ProxyConfig, Settings], ...]:
    return tuple((proxy, settings.for_proxy(proxy)) for proxy in settings.proxy_configs)


def _legacy_flat_storage_present(settings: Settings) -> bool:
    """Detect pre-multi-printer root data without treating empty roots as history."""

    if len(settings.proxy_configs) == 1:
        return False
    durable_files = (
        settings.manifest_path,
        settings.manifest_head_path,
        settings.reserve_path,
    )
    if any(path.exists() or path.is_symlink() for path in durable_files):
        return True
    for directory, patterns in (
        (settings.data_dir, ("*.raw", "*.json", "*.txt", "*.pdf")),
        (settings.states_dir, ("*.json",)),
        (settings.receiving_dir, ("*",)),
        (settings.requests_dir, ("*.json",)),
    ):
        if directory.exists() and any(
            path for pattern in patterns for path in directory.glob(pattern)
        ):
            return True
    return False


def _archive_scopes(
    settings: Settings, *, include_legacy: bool
) -> tuple[tuple[str, Settings], ...]:
    scopes = [(proxy.proxy_id, scoped) for proxy, scoped in _proxy_settings(settings)]
    if include_legacy and _legacy_flat_storage_present(settings):
        scopes.append(("legacy-flat", settings))
    return tuple(scopes)


def _route_states(proxy: ProxyConfig, scoped: Settings) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for original in StateStore(scoped).list():
        state = dict(original)
        route_error = _physical_route_error(proxy, state)
        if route_error is not None:
            state["route_integrity_error"] = route_error
        recorded_proxy_id = state.get("proxy_id")
        if recorded_proxy_id not in {None, proxy.proxy_id}:
            state["recorded_proxy_id"] = recorded_proxy_id
        # The directory selected by the current validated mapping is
        # authoritative for administration.  Keep a historical positional id
        # separately after CSV reordering instead of mislabelling the route.
        state["proxy_id"] = proxy.proxy_id
        state["storage_scope"] = proxy.printer_directory_name
        state["read_only"] = False
        state.setdefault("proxy_ip", proxy.listen_ip)
        state.setdefault("proxy_port", proxy.listen_port)
        state.setdefault("printer_ip", proxy.printer_ip)
        state.setdefault("printer_port", proxy.printer_port)
        states.append(state)
    return states


def _physical_route_error(
    proxy: ProxyConfig, state: dict[str, Any]
) -> str | None:
    printer_ip = state.get("printer_ip")
    printer_port = state.get("printer_port")
    if (
        not isinstance(printer_ip, str)
        or isinstance(printer_port, bool)
        or not isinstance(printer_port, int)
        or printer_ip != proxy.printer_ip
        or printer_port != proxy.printer_port
    ):
        return (
            "authenticated/operational printer endpoint does not match configured "
            f"physical route: recorded={printer_ip!r}:{printer_port!r} "
            f"configured={proxy.printer_ip}:{proxy.printer_port}"
        )
    return None


def _legacy_states(settings: Settings) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    if not _legacy_flat_storage_present(settings):
        return states
    for original in StateStore(settings).list():
        state = dict(original)
        state["proxy_id"] = "legacy-flat"
        state["storage_scope"] = "legacy-flat"
        state["read_only"] = True
        states.append(state)
    return states


def _integrity_summary(
    scoped: Settings, key: bytes | None, *, service_active: bool
) -> tuple[bool, str]:
    try:
        if service_active:
            ok, detail = verify_manifest_head(scoped, key)
            return ok, (
                f"{'HEAD OK' if ok else 'FAILED'} "
                f"({detail}; full verify requires stopped service)"
            )
        report = IntegrityLedger(
            scoped,
            key,
            repair_head=False,
            read_only=True,
        ).verify(check_files=True)
        return report.ok, (
            f"{'OK' if report.ok else 'FAILED'} "
            f"({report.records} records, head {report.last_chain_hash})"
        )
    except (ConfigError, IntegrityError, StorageError, OSError, ValueError) as exc:
        return False, f"FAILED ({safe_error(exc)})"


def command_status(settings: Settings, _arguments: argparse.Namespace) -> int:
    active, active_detail = service_status()
    ntp_ok, ntp_detail = ntp_status()
    key = load_hmac_key(settings, cli=True)

    print(f"Service:              {active} ({active_detail})")
    print(f"Delivery mode:        {settings.delivery_mode}")
    print(f"Configured proxies:   {len(settings.proxy_configs)}")
    print(f"NTP:                  {'OK' if ntp_ok else 'WARNING'} ({ntp_detail})")
    integrity_results: list[bool] = []
    listener_results: list[bool] = []
    for proxy, scoped in _proxy_settings(settings):
        states = _route_states(proxy, scoped)
        route_errors = [
            state["route_integrity_error"]
            for state in states
            if "route_integrity_error" in state
        ]
        counts = Counter(state.get("state", "UNKNOWN") for state in states)
        successful = sorted(
            (state for state in states if state.get("state") == "SENT_UNCONFIRMED"),
            key=lambda state: state.get("timestamp_forward_complete") or "",
        )
        failed = sorted(
            (
                state
                for state in states
                if state.get("state")
                in {
                    "FAILED_BEFORE_SEND",
                    "UNKNOWN_PRINT_STATE",
                    "PARTIAL",
                    "QUARANTINED",
                }
            ),
            key=lambda state: state.get("timestamp_state_updated") or "",
        )
        listener_ok, listener_detail = _listener_check(scoped)
        listener_results.append(listener_ok)
        printer_ok, printer_detail, printer_ms = tcp_probe(
            proxy.printer_ip, proxy.printer_port, scoped.connect_timeout
        )
        integrity_ok, integrity = _integrity_summary(
            scoped, key, service_active=active == "active"
        )
        integrity_results.append(integrity_ok and not route_errors)
        raw_count = sum(1 for _ in scoped.data_dir.glob("*.raw"))
        queued = sum(
            counts[name] for name in ("QUEUED", "FAILED_BEFORE_SEND", "SEND_ARMED")
        )

        print(f"\n[{proxy.proxy_id}]")
        print(f"Listener:             {proxy.listen_ip}:{proxy.listen_port}")
        print(f"Listener state:       {'UP' if listener_ok else 'DOWN'} ({listener_detail})")
        print(
            f"Printer:              {'reachable' if printer_ok else 'UNREACHABLE'} "
            f"{proxy.printer_ip}:{proxy.printer_port} ({printer_ms:.1f} ms; {printer_detail})"
        )
        print(f"Jobs:                 {scoped.data_dir}")
        print(f"Disk free:            {disk_free_mb(scoped.data_dir)} MiB")
        print(f"Archived RAW:         {raw_count}")
        print(f"Queued/safe retry:    {queued}")
        print(f"Unknown print state:  {counts['UNKNOWN_PRINT_STATE']}")
        print(f"Integrity:            {integrity}")
        for route_error in route_errors:
            print(f"ROUTE ERROR:          {route_error}")
        print(
            "Last successful job:  "
            + (format_state_line(successful[-1]) if successful else "none")
        )
        print(
            "Last failed job:      " + (format_state_line(failed[-1]) if failed else "none")
        )

    if _legacy_flat_storage_present(settings):
        legacy_states = _legacy_states(settings)
        legacy_counts = Counter(state.get("state", "UNKNOWN") for state in legacy_states)
        legacy_attention_states = {
            "RECEIVING",
            "SEALED",
            "QUEUED",
            "FAILED_BEFORE_SEND",
            "SEND_ARMED",
            "SENDING",
            "DUPLEX_ACTIVE",
            "UNKNOWN_PRINT_STATE",
        }
        legacy_attention = sum(
            state.get("state") in legacy_attention_states for state in legacy_states
        )
        legacy_ok, legacy_integrity = _integrity_summary(
            settings, key, service_active=False
        )
        integrity_results.append(legacy_ok and legacy_attention == 0)
        print("\n[legacy-flat]")
        print(f"Jobs:                 {settings.data_dir}")
        print("Mode:                 read-only pre-multi-printer history")
        print(f"Operational states:   {legacy_attention} require migration review")
        print(
            "Replayable stranded:  "
            f"{sum(legacy_counts[name] for name in ('QUEUED', 'FAILED_BEFORE_SEND', 'SEND_ARMED'))}"
        )
        print(f"Unknown print state:  {legacy_counts['UNKNOWN_PRINT_STATE']}")
        print(f"Integrity:            {legacy_integrity}")
    return (
        0
        if active == "active" and all(listener_results) and all(integrity_results)
        else 1
    )


def command_test_printer(settings: Settings, _arguments: argparse.Namespace) -> int:
    results: list[bool] = []
    for proxy, scoped in _proxy_settings(settings):
        ok, detail, elapsed = tcp_probe(
            proxy.printer_ip, proxy.printer_port, scoped.connect_timeout
        )
        results.append(ok)
        print(
            f"[{proxy.proxy_id}] listen={proxy.listen_ip}:{proxy.listen_port} "
            f"printer={proxy.printer_ip}:{proxy.printer_port}: "
            f"{'reachable' if ok else 'unreachable'} ({elapsed:.1f} ms; {detail})"
        )
    print("No print bytes were sent.")
    return 0 if all(results) else 1


def command_verify(settings: Settings, arguments: argparse.Namespace) -> int:
    active, _ = service_status()
    if active == "active":
        print(
            "REFUSED: full verification requires a stable snapshot. Stop "
            "printproxy.service gracefully, run verify, then start it again.",
            file=sys.stderr,
        )
        return 2
    key = load_hmac_key(settings, cli=True)
    results: list[bool] = []
    for label, scoped in _archive_scopes(settings, include_legacy=True):
        print(f"[{label}]")
        try:
            report = IntegrityLedger(
                scoped,
                key,
                repair_head=False,
                read_only=True,
            ).verify(
                check_files=not arguments.ledger_only
            )
        except (ConfigError, IntegrityError, StorageError, OSError, ValueError) as exc:
            results.append(False)
            print("Integrity verification: FAILED")
            print(f"ERROR: {safe_error(exc)}")
            continue
        proxy = next(
            (candidate for candidate in settings.proxy_configs if candidate.proxy_id == label),
            None,
        )
        route_errors = (
            [
                state["route_integrity_error"]
                for state in _route_states(proxy, scoped)
                if "route_integrity_error" in state
            ]
            if proxy is not None
            else []
        )
        scope_ok = report.ok and not route_errors
        results.append(scope_ok)
        print(f"Integrity verification: {'OK' if scope_ok else 'FAILED'}")
        print(f"Records: {report.records}; jobs: {report.jobs}; head: {report.last_chain_hash}")
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        for error in report.errors:
            print(f"ERROR: {error}")
        for error in route_errors:
            print(f"ERROR: {error}")
    return 0 if all(results) else 1


def command_queue(settings: Settings, arguments: argparse.Namespace) -> int:
    states = [
        state
        for proxy, scoped in _proxy_settings(settings)
        for state in _route_states(proxy, scoped)
    ]
    states.extend(_legacy_states(settings))
    selected = [
        state
        for state in states
        if arguments.all
        or state.get("state")
        in {
            "QUEUED",
            "FAILED_BEFORE_SEND",
            "SEND_ARMED",
            "SENDING",
            "UNKNOWN_PRINT_STATE",
            "PARTIAL",
            "QUARANTINED",
        }
    ]
    selected.sort(key=lambda state: state.get("queue_order") or state.get("timestamp_start") or "")
    if arguments.json:
        print(json.dumps(selected, indent=2, ensure_ascii=False, sort_keys=True))
    elif selected:
        for state in selected:
            print(format_state_line(state))
            if state.get("last_error"):
                print(f"  error: {state['last_error']}")
    else:
        print("Queue is empty.")
    return 1 if any("route_integrity_error" in state for state in selected) else 0


def command_retry(settings: Settings, arguments: argparse.Namespace) -> int:
    stores = [
        (proxy, StateStore(scoped)) for proxy, scoped in _proxy_settings(settings)
    ]
    targets: list[tuple[ProxyConfig, StateStore, dict[str, Any]]] = []
    if arguments.all_safe:
        targets = [
            (proxy, store, state)
            for proxy, store in stores
            for state in store.list()
            if state.get("state") in {"QUEUED", "FAILED_BEFORE_SEND"}
            and state.get("retry_allowed") is not False
        ]
    elif arguments.job_id:
        matches: list[tuple[ProxyConfig, StateStore, dict[str, Any]]] = []
        load_errors: list[str] = []
        for proxy, store in stores:
            try:
                matches.append((proxy, store, store.load(arguments.job_id)))
            except FileNotFoundError:
                continue
            except (OSError, ValueError, StorageError) as exc:
                load_errors.append(f"{proxy.proxy_id}: {safe_error(exc)}")
        legacy_match: dict[str, Any] | None = None
        if _legacy_flat_storage_present(settings):
            try:
                legacy_match = StateStore(settings).load(arguments.job_id)
            except FileNotFoundError:
                pass
            except (OSError, ValueError, StorageError) as exc:
                load_errors.append(f"legacy-flat: {safe_error(exc)}")
        if load_errors:
            print(f"retry: {'; '.join(load_errors)}", file=sys.stderr)
            return 1
        if legacy_match is not None:
            if matches:
                locations = ", ".join(
                    [*(proxy.proxy_id for proxy, _, _ in matches), "legacy-flat"]
                )
                print(
                    f"retry: ambiguous job id {arguments.job_id}; found in {locations}",
                    file=sys.stderr,
                )
                return 1
            print(
                f"REFUSED [legacy-flat] {arguments.job_id}: legacy root spool is read-only "
                "in multi-proxy mode; migrate or drain it in single-route mode",
                file=sys.stderr,
            )
            return 1
        if not matches:
            print(f"retry: job not found: {arguments.job_id}", file=sys.stderr)
            return 1
        if len(matches) != 1:
            locations = ", ".join(proxy.proxy_id for proxy, _, _ in matches)
            print(
                f"retry: ambiguous job id {arguments.job_id}; found in {locations}",
                file=sys.stderr,
            )
            return 1
        targets = matches
    else:
        print("retry requires JOB_ID or --all-safe", file=sys.stderr)
        return 2

    created = 0
    for proxy, store, state in targets:
        current = state.get("state")
        route_error = _physical_route_error(proxy, state)
        if route_error is not None:
            print(
                f"REFUSED [{proxy.proxy_id}] {state.get('job_id')}: {route_error}",
                file=sys.stderr,
            )
            continue
        if state.get("retry_allowed") is False:
            print(
                f"REFUSED [{proxy.proxy_id}] {state['job_id']}: "
                "transparent-duplex transcripts are not "
                "safe one-way replay jobs; start a new session from the gestionale",
                file=sys.stderr,
            )
            continue
        if current == "UNKNOWN_PRINT_STATE" and not arguments.confirm_unknown:
            print(
                f"REFUSED [{proxy.proxy_id}] {state['job_id']}: physical outcome is unknown; "
                "repeat with --confirm-unknown only after accepting duplicate-print risk",
                file=sys.stderr,
            )
            continue
        if current not in {"QUEUED", "FAILED_BEFORE_SEND", "UNKNOWN_PRINT_STATE"}:
            print(
                f"REFUSED [{proxy.proxy_id}] {state['job_id']}: "
                f"state {current} is not retryable",
                file=sys.stderr,
            )
            continue
        store.create_request(
            {
                "schema_version": 1,
                "action": "retry",
                "job_id": state["job_id"],
                "confirm_unknown": bool(arguments.confirm_unknown),
                "requested_at": utc_now(),
                "requested_uid": os.geteuid() if hasattr(os, "geteuid") else None,
                "reason": arguments.reason,
                "proxy_id": proxy.proxy_id,
            },
            inherit_parent_owner=True,
        )
        created += 1
        print(
            f"Retry request queued: [{proxy.proxy_id}] {state['job_id']} "
            f"(previous state {current})"
        )
    if created:
        print("The daemon will consume the durable request; no CLI process sends to the printer.")
        return 0
    return 1


def _listener_check(settings: Settings) -> tuple[bool, str]:
    status, _ = service_status()
    if status == "active":
        present, detail = proc_tcp_listener(settings.listen_ip, settings.listen_port)
        if present is not None:
            return present, detail
        ok, detail, elapsed = tcp_probe(
            settings.listen_ip, settings.listen_port, settings.connect_timeout
        )
        return ok, f"TCP connect {elapsed:.1f} ms; {detail}"
    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        candidate.bind((settings.listen_ip, settings.listen_port))
        return True, "bind succeeded while service inactive"
    except OSError as exc:
        return False, safe_error(exc)
    finally:
        candidate.close()


def command_self_test(settings: Settings, _arguments: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("configuration", True, str(settings.config_path)))
    ntp_ok, ntp_detail = ntp_status()
    checks.append(("NTP", ntp_ok, ntp_detail))
    active, _ = service_status()
    try:
        key = load_hmac_key(settings, cli=True)
    except Exception as exc:
        key = None
        checks.append(("HMAC key", False, safe_error(exc)))

    for proxy, scoped in _proxy_settings(settings):
        prefix = f"[{proxy.proxy_id}] "
        listener_ok, listener_detail = _listener_check(scoped)
        checks.append((prefix + "listener/bind", listener_ok, listener_detail))
        printer_ok, printer_detail, _ = tcp_probe(
            proxy.printer_ip, proxy.printer_port, scoped.connect_timeout
        )
        checks.append((prefix + "printer TCP", printer_ok, printer_detail))
        free = disk_free_mb(scoped.data_dir)
        checks.append(
            (
                prefix + "disk space",
                free >= scoped.min_free_disk_mb,
                f"{free} MiB free at {scoped.data_dir}",
            )
        )

        probe_path = scoped.spool_dir / f".self-test-{uuid.uuid4().hex}"
        try:
            payload = os.urandom(256)
            atomic_write_bytes(probe_path, payload, mode=0o600)
            digest, size = sha256_file(probe_path)
            expected = hashlib.sha256(payload).hexdigest()
            checks.append((prefix + "filesystem write/fsync", size == len(payload), f"{size} bytes"))
            checks.append((prefix + "SHA-256", digest == expected, digest))
        except OSError as exc:
            checks.append((prefix + "filesystem write/fsync", False, safe_error(exc)))
        finally:
            with contextlib.suppress(OSError):
                probe_path.unlink()

        if not any(name == "HMAC key" and not ok for name, ok, _ in checks):
            integrity_ok, integrity_detail = _integrity_summary(
                scoped, key, service_active=active == "active"
            )
            checks.append((prefix + "manifest/hash-chain/HMAC", integrity_ok, integrity_detail))

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<28} {detail}")
    print("No print bytes were sent. Use test-print explicitly for a physical test.")
    return 0 if all(ok for _, ok, _ in checks) else 1


def command_test_print(settings: Settings, arguments: argparse.Namespace) -> int:
    if not arguments.confirm:
        print(
            "REFUSED: this command produces a physical print. Repeat with --confirm.",
            file=sys.stderr,
        )
        return 2
    proxy_id = arguments.proxy_id
    if len(settings.proxy_configs) > 1 and not proxy_id:
        choices = ", ".join(proxy.proxy_id for proxy in settings.proxy_configs)
        print(
            f"REFUSED: --proxy-id is required with multiple mappings; choose one of: {choices}",
            file=sys.stderr,
        )
        return 2
    selected = next(
        (
            proxy
            for proxy in settings.proxy_configs
            if proxy.proxy_id == (proxy_id or settings.primary_proxy.proxy_id)
        ),
        None,
    )
    if selected is None:
        choices = ", ".join(proxy.proxy_id for proxy in settings.proxy_configs)
        print(
            f"REFUSED: unknown --proxy-id {proxy_id!r}; choose one of: {choices}",
            file=sys.stderr,
        )
        return 2
    scoped = settings.for_proxy(selected)
    text = arguments.text or "PRINTPROXY TEST - NON FISCALE"
    payload = (
        b"\x1b@"
        + b"================================\n"
        + text.encode("utf-8", errors="backslashreplace")
        + b"\n"
        + utc_now().encode("ascii")
        + b"\n================================\n\n\n"
        + b"\x1dV\x00"
    )
    try:
        with socket.create_connection(
            (selected.listen_ip, selected.listen_port), timeout=scoped.connect_timeout
        ) as connection:
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
        print(
            f"Submitted {len(payload)} bytes to [{selected.proxy_id}] "
            f"{selected.listen_ip}:{selected.listen_port}. "
            "Check queue/status and physical output."
        )
        return 0
    except OSError as exc:
        print(f"test-print failed: {safe_error(exc)}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/printproxy/printproxy.conf")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="service, storage, printer, NTP and integrity status")
    subparsers.add_parser("test-printer", help="TCP connect test; sends no print data")

    verify = subparsers.add_parser("verify", help="verify SHA-256, manifest, chain and HMAC")
    verify.add_argument("--ledger-only", action="store_true", help="skip archived file hashes")

    queue = subparsers.add_parser("queue", help="show queued/problem jobs")
    queue.add_argument("--all", action="store_true", help="include terminal successful jobs")
    queue.add_argument("--json", action="store_true")

    retry = subparsers.add_parser("retry", help="create a durable retry request")
    retry.add_argument("job_id", nargs="?")
    retry.add_argument("--all-safe", action="store_true", help="retry only pre-send failures")
    retry.add_argument("--confirm-unknown", action="store_true", help="accept duplicate-print risk")
    retry.add_argument("--reason", default="operator request")

    subparsers.add_parser("self-test", help="non-destructive checks; never prints")
    test_print = subparsers.add_parser("test-print", help="explicit physical test through proxy")
    test_print.add_argument("--confirm", action="store_true", required=True)
    test_print.add_argument("--proxy-id")
    test_print.add_argument("--text")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        settings = load_settings(arguments.config)
        commands = {
            "status": command_status,
            "test-printer": command_test_printer,
            "verify": command_verify,
            "queue": command_queue,
            "retry": command_retry,
            "self-test": command_self_test,
            "test-print": command_test_print,
        }
        return commands[arguments.command](settings, arguments)
    except (ConfigError, IntegrityError, StorageError, OSError) as exc:
        print(f"printproxyctl: {safe_error(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
