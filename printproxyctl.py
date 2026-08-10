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

from printproxy_core import (
    ConfigError,
    IntegrityError,
    IntegrityLedger,
    SAFE_RETRY_STATES,
    StateStore,
    StorageError,
    atomic_write_bytes,
    disk_free_mb,
    ensure_runtime_directories,
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
    return (
        f"{state.get('job_id', '?')}  {state.get('state', '?'):<24} "
        f"bytes={state.get('bytes_archived', 0):>8} attempts={state.get('attempts', 0):>3} "
        f"start={state.get('timestamp_start', '?')}"
    )


def command_status(settings: Any, _arguments: argparse.Namespace) -> int:
    store = StateStore(settings)
    states = store.list()
    counts = Counter(state.get("state", "UNKNOWN") for state in states)
    active, active_detail = service_status()
    printer_ok, printer_detail, printer_ms = tcp_probe(
        settings.printer_ip, settings.printer_port, settings.connect_timeout
    )
    ntp_ok, ntp_detail = ntp_status()
    successful = sorted(
        (state for state in states if state.get("state") == "SENT_UNCONFIRMED"),
        key=lambda state: state.get("timestamp_forward_complete") or "",
    )
    failed = sorted(
        (
            state
            for state in states
            if state.get("state")
            in {"FAILED_BEFORE_SEND", "UNKNOWN_PRINT_STATE", "PARTIAL", "QUARANTINED"}
        ),
        key=lambda state: state.get("timestamp_state_updated") or "",
    )
    raw_count = sum(1 for _ in settings.data_dir.glob("*.raw"))
    queued = sum(counts[name] for name in ("QUEUED", "FAILED_BEFORE_SEND", "SEND_ARMED"))
    key = load_hmac_key(settings, cli=True)
    if active == "active":
        integrity_ok, integrity_detail = verify_manifest_head(settings, key)
        integrity_summary = (
            f"{'HEAD OK' if integrity_ok else 'FAILED'} "
            f"({integrity_detail}; full verify requires stopped service)"
        )
    else:
        report = IntegrityLedger(settings, key, repair_head=False).verify(check_files=True)
        integrity_ok = report.ok
        integrity_summary = (
            f"{'OK' if report.ok else 'FAILED'} "
            f"({report.records} records, head {report.last_chain_hash})"
        )

    print(f"Service:              {active} ({active_detail})")
    print(f"Listener:             {settings.listen_ip}:{settings.listen_port}")
    print(
        f"Printer:              {'reachable' if printer_ok else 'UNREACHABLE'} "
        f"{settings.printer_ip}:{settings.printer_port} ({printer_ms:.1f} ms; {printer_detail})"
    )
    print(f"Disk free:            {disk_free_mb(settings.data_dir)} MiB")
    print(f"Archived RAW:         {raw_count}")
    print(f"Queued/safe retry:    {queued}")
    print(f"Unknown print state:  {counts['UNKNOWN_PRINT_STATE']}")
    print(f"NTP:                  {'OK' if ntp_ok else 'WARNING'} ({ntp_detail})")
    print(f"Integrity:            {integrity_summary}")
    print(f"Last successful job:  {format_state_line(successful[-1]) if successful else 'none'}")
    print(f"Last failed job:      {format_state_line(failed[-1]) if failed else 'none'}")
    return 0 if active == "active" and integrity_ok else 1


def command_test_printer(settings: Any, _arguments: argparse.Namespace) -> int:
    ok, detail, elapsed = tcp_probe(
        settings.printer_ip, settings.printer_port, settings.connect_timeout
    )
    print(
        f"{settings.printer_ip}:{settings.printer_port}: "
        f"{'reachable' if ok else 'unreachable'} ({elapsed:.1f} ms; {detail})"
    )
    print("No print bytes were sent.")
    return 0 if ok else 1


def command_verify(settings: Any, arguments: argparse.Namespace) -> int:
    active, _ = service_status()
    if active == "active":
        print(
            "REFUSED: full verification requires a stable snapshot. Stop "
            "printproxy.service gracefully, run verify, then start it again.",
            file=sys.stderr,
        )
        return 2
    key = load_hmac_key(settings, cli=True)
    report = IntegrityLedger(settings, key, repair_head=False).verify(
        check_files=not arguments.ledger_only
    )
    print(f"Integrity verification: {'OK' if report.ok else 'FAILED'}")
    print(f"Records: {report.records}; jobs: {report.jobs}; head: {report.last_chain_hash}")
    for warning in report.warnings:
        print(f"WARNING: {warning}")
    for error in report.errors:
        print(f"ERROR: {error}")
    return 0 if report.ok else 1


def command_queue(settings: Any, arguments: argparse.Namespace) -> int:
    states = StateStore(settings).list()
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
    return 0


def command_retry(settings: Any, arguments: argparse.Namespace) -> int:
    store = StateStore(settings)
    targets: list[dict[str, Any]] = []
    if arguments.all_safe:
        targets = [
            state
            for state in store.list()
            if state.get("state") in {"QUEUED", "FAILED_BEFORE_SEND"}
        ]
    elif arguments.job_id:
        try:
            targets = [store.load(arguments.job_id)]
        except (OSError, ValueError, StorageError) as exc:
            print(f"retry: {safe_error(exc)}", file=sys.stderr)
            return 1
    else:
        print("retry requires JOB_ID or --all-safe", file=sys.stderr)
        return 2

    created = 0
    for state in targets:
        current = state.get("state")
        if current == "UNKNOWN_PRINT_STATE" and not arguments.confirm_unknown:
            print(
                f"REFUSED {state['job_id']}: physical outcome is unknown; "
                "repeat with --confirm-unknown only after accepting duplicate-print risk",
                file=sys.stderr,
            )
            continue
        if current not in {"QUEUED", "FAILED_BEFORE_SEND", "UNKNOWN_PRINT_STATE"}:
            print(f"REFUSED {state['job_id']}: state {current} is not retryable", file=sys.stderr)
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
            }
        )
        created += 1
        print(f"Retry request queued: {state['job_id']} (previous state {current})")
    if created:
        print("The daemon will consume the durable request; no CLI process sends to the printer.")
        return 0
    return 1


def _listener_check(settings: Any) -> tuple[bool, str]:
    status, _ = service_status()
    if status == "active":
        return True, "service active; destructive bind test skipped"
    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        candidate.bind((settings.listen_ip, settings.listen_port))
        return True, "bind succeeded while service inactive"
    except OSError as exc:
        return False, safe_error(exc)
    finally:
        candidate.close()


def command_self_test(settings: Any, _arguments: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("configuration", True, str(settings.config_path)))
    listener_ok, listener_detail = _listener_check(settings)
    checks.append(("listener/bind", listener_ok, listener_detail))
    printer_ok, printer_detail, _ = tcp_probe(
        settings.printer_ip, settings.printer_port, settings.connect_timeout
    )
    checks.append(("printer TCP", printer_ok, printer_detail))
    free = disk_free_mb(settings.data_dir)
    checks.append(("disk space", free >= settings.min_free_disk_mb, f"{free} MiB free"))
    ntp_ok, ntp_detail = ntp_status()
    checks.append(("NTP", ntp_ok, ntp_detail))

    probe_path = settings.spool_dir / f".self-test-{uuid.uuid4().hex}"
    try:
        payload = os.urandom(256)
        atomic_write_bytes(probe_path, payload, mode=0o600)
        digest, size = sha256_file(probe_path)
        expected = hashlib.sha256(payload).hexdigest()
        checks.append(("filesystem write/fsync", size == len(payload), f"{size} bytes"))
        checks.append(("SHA-256", digest == expected, digest))
    except OSError as exc:
        checks.append(("filesystem write/fsync", False, safe_error(exc)))
    finally:
        with contextlib.suppress(OSError):
            probe_path.unlink()

    try:
        key = load_hmac_key(settings, cli=True)
        active, _ = service_status()
        if active == "active":
            head_ok, head_detail = verify_manifest_head(settings, key)
            checks.append(
                (
                    "manifest head/HMAC",
                    head_ok,
                    head_detail + "; full verify requires stopped service",
                )
            )
        else:
            report = IntegrityLedger(settings, key, repair_head=False).verify(check_files=True)
            checks.append(
                (
                    "manifest/hash-chain/HMAC",
                    report.ok,
                    "; ".join(report.errors) or f"{report.records} records",
                )
            )
    except Exception as exc:
        checks.append(("manifest/hash-chain/HMAC", False, safe_error(exc)))

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<28} {detail}")
    print("No print bytes were sent. Use test-print explicitly for a physical test.")
    return 0 if all(ok for _, ok, _ in checks) else 1


def command_test_print(settings: Any, arguments: argparse.Namespace) -> int:
    if not arguments.confirm:
        print(
            "REFUSED: this command produces a physical print. Repeat with --confirm.",
            file=sys.stderr,
        )
        return 2
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
            (settings.listen_ip, settings.listen_port), timeout=settings.connect_timeout
        ) as connection:
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
        print(f"Submitted {len(payload)} bytes to the proxy. Check queue/status and physical output.")
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
    test_print.add_argument("--text")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        settings = load_settings(arguments.config)
        ensure_runtime_directories(settings)
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
