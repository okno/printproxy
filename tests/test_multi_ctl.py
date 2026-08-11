from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import printproxyctl
import printproxy_core
from printproxy_core import (
    StateStore,
    StorageError,
    ensure_runtime_directories,
    load_settings,
)


class MultiProxyControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "printproxy.conf"
        self.config.write_text(
            "\n".join(
                (
                    "LISTEN_IP=127.0.0.1,127.0.0.2,127.0.0.3",
                    "LISTEN_PORT=19101,19102,19103",
                    "PRINTER_IP=127.0.0.11,127.0.0.12,127.0.0.13",
                    "PRINTER_PORT=9100,9100,9100",
                    f"DATA_DIR={self.root / 'jobs'}",
                    f"SPOOL_DIR={self.root / 'spool'}",
                    f"LOG_DIR={self.root / 'logs'}",
                    f"HMAC_KEY_FILE={self.root / 'integrity.key'}",
                    "ENABLE_HMAC=no",
                    "MIN_FREE_DISK_MB=1",
                    "ALLOWED_NETWORKS=127.0.0.0/8",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.settings = load_settings(self.config)
        ensure_runtime_directories(self.settings)
        if os.name == "posix" and os.geteuid() == 0:
            import pwd

            account = pwd.getpwnam("nobody")
            for proxy in self.settings.proxy_configs:
                requests = self.settings.for_proxy(proxy).requests_dir
                os.chown(requests, account.pw_uid, account.pw_gid)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _arguments(**overrides):
        values = {
            "all": False,
            "json": False,
            "all_safe": False,
            "job_id": None,
            "confirm_unknown": False,
            "reason": "test",
            "ledger_only": False,
            "confirm": True,
            "proxy_id": None,
            "text": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _write_state(
        self,
        route_index: int,
        *,
        job_id: str | None = None,
        state: str = "QUEUED",
        retry_allowed: bool = True,
        marker: str = "",
    ) -> str:
        proxy = self.settings.proxy_configs[route_index]
        scoped = self.settings.for_proxy(proxy)
        identifier = job_id or str(uuid.uuid4())
        StateStore(scoped).write(
            {
                "job_id": identifier,
                "state": state,
                "retry_allowed": retry_allowed,
                "printer_ip": proxy.printer_ip,
                "printer_port": proxy.printer_port,
                "bytes_archived": route_index + 1,
                "attempts": 0,
                "timestamp_start": f"2026-08-11T00:00:0{route_index}Z",
                "marker": marker,
            }
        )
        return identifier

    def test_status_reports_every_route_and_endpoint(self) -> None:
        stdout = io.StringIO()
        with (
            patch("printproxyctl.service_status", return_value=("active", "active")),
            patch("printproxyctl.ntp_status", return_value=(True, "synchronized")),
            patch(
                "printproxyctl.proc_tcp_listener",
                return_value=(True, "exact LISTEN socket present"),
            ),
            patch("printproxyctl.tcp_probe", return_value=(True, "reachable", 1.5)),
            patch("printproxyctl.verify_manifest_head", return_value=(True, "head ok")),
            patch("printproxyctl.disk_free_mb", return_value=4096),
            contextlib.redirect_stdout(stdout),
        ):
            result = printproxyctl.command_status(self.settings, self._arguments())

        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Configured proxies:   3", output)
        for index in range(3):
            proxy = self.settings.proxy_configs[index]
            self.assertIn(f"[{proxy.proxy_id}]", output)
            self.assertIn(f"{proxy.listen_ip}:{proxy.listen_port}", output)
            self.assertIn(f"{proxy.printer_ip}:{proxy.printer_port}", output)
            self.assertIn(str(self.settings.for_proxy(proxy).data_dir), output)

    def test_cli_main_does_not_create_missing_service_directories_as_root(self) -> None:
        for directory in (
            self.settings.data_dir,
            self.settings.spool_dir,
            self.settings.log_dir,
        ):
            shutil.rmtree(directory)
        with patch("printproxyctl.command_status", return_value=0):
            result = printproxyctl.main(["--config", str(self.config), "status"])

        self.assertEqual(result, 0)
        self.assertFalse(self.settings.data_dir.exists())
        self.assertFalse(self.settings.spool_dir.exists())
        self.assertFalse(self.settings.log_dir.exists())

    def test_status_is_unhealthy_when_one_listener_is_down(self) -> None:
        stdout = io.StringIO()
        listener_results = iter(
            ((True, "up"), (False, "route stopped"), (True, "up"))
        )
        with (
            patch("printproxyctl.service_status", return_value=("active", "active")),
            patch("printproxyctl.ntp_status", return_value=(True, "synchronized")),
            patch("printproxyctl._listener_check", side_effect=lambda _settings: next(listener_results)),
            patch("printproxyctl.tcp_probe", return_value=(True, "reachable", 1.5)),
            patch("printproxyctl.verify_manifest_head", return_value=(True, "head ok")),
            patch("printproxyctl.disk_free_mb", return_value=4096),
            contextlib.redirect_stdout(stdout),
        ):
            result = printproxyctl.command_status(self.settings, self._arguments())

        self.assertEqual(result, 1)
        self.assertIn("Listener state:       DOWN (route stopped)", stdout.getvalue())

    def test_proc_listener_check_is_exact_and_does_not_send_packets(self) -> None:
        proc_table = self.root / "proc-net-tcp"
        proc_table.write_text(
            "  sl  local_address rem_address   st\n"
            "   0: 0100007F:4A9D 00000000:0000 0A\n"
            "   1: 0200007F:4A9E 00000000:0000 01\n",
            encoding="ascii",
        )

        self.assertEqual(
            printproxyctl.proc_tcp_listener("127.0.0.1", 19101, proc_table),
            (True, "exact LISTEN socket present in /proc/net/tcp"),
        )
        present, detail = printproxyctl.proc_tcp_listener(
            "127.0.0.2", 19102, proc_table
        )
        self.assertFalse(present)
        self.assertIn("absent", detail)

    def test_test_printer_checks_all_routes_and_aggregates_failure(self) -> None:
        def probe(host: str, _port: int, _timeout: float):
            return host != "127.0.0.12", "probe", 2.0

        stdout = io.StringIO()
        with patch("printproxyctl.tcp_probe", side_effect=probe), contextlib.redirect_stdout(stdout):
            result = printproxyctl.command_test_printer(self.settings, self._arguments())

        self.assertEqual(result, 1)
        output = stdout.getvalue()
        self.assertEqual(output.count("listen="), 3)
        self.assertIn("[proxy-002]", output)
        self.assertIn("unreachable", output)

    def test_queue_json_aggregates_routes_without_losing_identity(self) -> None:
        expected_ids = [
            self._write_state(index, marker=f"route-{index + 1}") for index in range(3)
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = printproxyctl.command_queue(
                self.settings, self._arguments(all=True, json=True)
            )

        self.assertEqual(result, 0)
        records = json.loads(stdout.getvalue())
        self.assertEqual({record["job_id"] for record in records}, set(expected_ids))
        self.assertEqual(
            {record["proxy_id"] for record in records},
            {"proxy-001", "proxy-002", "proxy-003"},
        )
        for record in records:
            index = int(record["proxy_id"].removeprefix("proxy-")) - 1
            self.assertEqual(record["marker"], f"route-{index + 1}")

    def test_queue_uses_current_route_id_after_positional_reordering(self) -> None:
        proxy = self.settings.proxy_configs[1]
        scoped = self.settings.for_proxy(proxy)
        job_id = str(uuid.uuid4())
        StateStore(scoped).write(
            {
                "job_id": job_id,
                "state": "QUEUED",
                "proxy_id": "proxy-001",
            }
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            printproxyctl.command_queue(
                self.settings, self._arguments(all=True, json=True)
            )

        record = next(item for item in json.loads(stdout.getvalue()) if item["job_id"] == job_id)
        self.assertEqual(record["proxy_id"], "proxy-002")
        self.assertEqual(record["recorded_proxy_id"], "proxy-001")
        self.assertEqual(record["storage_scope"], proxy.printer_ip)

    def test_cross_route_state_fails_queue_verify_and_retry(self) -> None:
        target_proxy = self.settings.proxy_configs[1]
        target_settings = self.settings.for_proxy(target_proxy)
        job_id = str(uuid.uuid4())
        StateStore(target_settings).write(
            {
                "job_id": job_id,
                "state": "QUEUED",
                "retry_allowed": True,
                "printer_ip": self.settings.proxy_configs[0].printer_ip,
                "printer_port": self.settings.proxy_configs[0].printer_port,
            }
        )

        queue_output = io.StringIO()
        with contextlib.redirect_stdout(queue_output):
            queue_result = printproxyctl.command_queue(
                self.settings, self._arguments(all=True, json=True)
            )
        self.assertEqual(queue_result, 1)
        records = json.loads(queue_output.getvalue())
        copied = next(record for record in records if record["job_id"] == job_id)
        self.assertIn("configured physical route", copied["route_integrity_error"])

        verify_output = io.StringIO()
        with (
            patch("printproxyctl.service_status", return_value=("inactive", "stopped")),
            contextlib.redirect_stdout(verify_output),
        ):
            verify_result = printproxyctl.command_verify(
                self.settings, self._arguments(ledger_only=False)
            )
        self.assertEqual(verify_result, 1)
        self.assertIn("configured physical route", verify_output.getvalue())

        retry_error = io.StringIO()
        with contextlib.redirect_stderr(retry_error):
            retry_result = printproxyctl.command_retry(
                self.settings,
                self._arguments(
                    job_id=job_id,
                    all_safe=False,
                    confirm_unknown=False,
                ),
            )
        self.assertEqual(retry_result, 1)
        self.assertIn("configured physical route", retry_error.getvalue())
        self.assertEqual(list(target_settings.requests_dir.glob("*.json")), [])

    def test_retry_finds_unique_job_and_writes_only_its_route_request(self) -> None:
        job_id = self._write_state(1, state="FAILED_BEFORE_SEND")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = printproxyctl.command_retry(
                self.settings, self._arguments(job_id=job_id)
            )

        self.assertEqual(result, 0)
        self.assertIn("[proxy-002]", stdout.getvalue())
        request_counts = []
        for proxy in self.settings.proxy_configs:
            scoped = self.settings.for_proxy(proxy)
            request_counts.append(len(list(scoped.requests_dir.glob("*.json"))))
        self.assertEqual(request_counts, [0, 1, 0])
        request_path = next(self.settings.for_proxy(self.settings.proxy_configs[1]).requests_dir.glob("*.json"))
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual(request["proxy_id"], "proxy-002")

    @unittest.skipUnless(os.name == "posix", "requires POSIX ownership and setuid")
    def test_root_retry_request_is_owned_and_readable_by_daemon_uid(self) -> None:
        job_id = self._write_state(1, state="FAILED_BEFORE_SEND")
        scoped = self.settings.for_proxy(self.settings.proxy_configs[1])
        if os.geteuid() == 0:
            import pwd

            account = pwd.getpwnam("nobody")
            daemon_uid, daemon_gid = account.pw_uid, account.pw_gid
            self.root.chmod(0o755)
            self.settings.spool_dir.chmod(0o755)
            scoped.spool_dir.chmod(0o755)
        else:
            daemon_uid, daemon_gid = os.geteuid(), os.getegid()
        os.chown(scoped.requests_dir, daemon_uid, daemon_gid)
        scoped.requests_dir.chmod(0o750)

        with contextlib.redirect_stdout(io.StringIO()):
            result = printproxyctl.command_retry(
                self.settings,
                self._arguments(job_id=job_id),
            )

        self.assertEqual(result, 0)
        request_path = next(scoped.requests_dir.glob("*.json"))
        info = request_path.stat()
        self.assertEqual((info.st_uid, info.st_gid), (daemon_uid, daemon_gid))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
        if os.geteuid() == daemon_uid:
            json.loads(request_path.read_text(encoding="utf-8"))
        else:
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(daemon_gid)
                    os.setuid(daemon_uid)
                    json.loads(request_path.read_text(encoding="utf-8"))
                except BaseException:
                    os._exit(1)
                os._exit(0)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    @unittest.skipUnless(os.name == "posix", "requires POSIX dirfd operations")
    def test_retry_request_parent_swap_fails_without_cross_directory_publish(self) -> None:
        job_id = self._write_state(1, state="FAILED_BEFORE_SEND")
        scoped = self.settings.for_proxy(self.settings.proxy_configs[1])
        requests = scoped.requests_dir
        displaced = requests.with_name("requests-displaced")
        if os.geteuid() == 0:
            import pwd

            account = pwd.getpwnam("nobody")
            self.root.chmod(0o755)
            self.settings.spool_dir.chmod(0o755)
            scoped.spool_dir.chmod(0o755)
            os.chown(requests, account.pw_uid, account.pw_gid)
        original_write = printproxy_core.write_all
        swapped = False

        def write_then_swap(descriptor: int, data: bytes) -> None:
            nonlocal swapped
            original_write(descriptor, data)
            if not swapped:
                requests.rename(displaced)
                requests.mkdir(mode=0o750)
                swapped = True

        try:
            with (
                patch("printproxy_core.write_all", side_effect=write_then_swap),
                self.assertRaisesRegex(StorageError, "directory.*changed"),
            ):
                printproxyctl.command_retry(
                    self.settings,
                    self._arguments(job_id=job_id),
                )
            self.assertEqual(list(requests.iterdir()), [])
            self.assertEqual(list(displaced.iterdir()), [])
        finally:
            if displaced.exists():
                shutil.rmtree(requests)
                displaced.rename(requests)

    def test_retry_rejects_ambiguous_job_id_across_stores(self) -> None:
        job_id = str(uuid.uuid4())
        self._write_state(0, job_id=job_id, state="FAILED_BEFORE_SEND")
        self._write_state(2, job_id=job_id, state="FAILED_BEFORE_SEND")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = printproxyctl.command_retry(
                self.settings, self._arguments(job_id=job_id)
            )

        self.assertEqual(result, 1)
        self.assertIn("ambiguous job id", stderr.getvalue())
        self.assertIn("proxy-001", stderr.getvalue())
        self.assertIn("proxy-003", stderr.getvalue())

    def test_retry_still_refuses_duplex_transcript(self) -> None:
        job_id = self._write_state(
            0,
            state="UNKNOWN_PRINT_STATE",
            retry_allowed=False,
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = printproxyctl.command_retry(
                self.settings,
                self._arguments(job_id=job_id, confirm_unknown=True),
            )

        self.assertEqual(result, 1)
        self.assertIn("transparent-duplex transcripts", stderr.getvalue())
        self.assertFalse(
            list(self.settings.for_proxy(self.settings.proxy_configs[0]).requests_dir.glob("*.json"))
        )

    def test_retry_explains_that_legacy_root_state_is_read_only(self) -> None:
        self.settings.states_dir.mkdir(parents=True)
        job_id = str(uuid.uuid4())
        StateStore(self.settings).write(
            {
                "job_id": job_id,
                "state": "FAILED_BEFORE_SEND",
                "retry_allowed": True,
            }
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = printproxyctl.command_retry(
                self.settings, self._arguments(job_id=job_id)
            )

        self.assertEqual(result, 1)
        self.assertIn("[legacy-flat]", stderr.getvalue())
        self.assertIn("read-only", stderr.getvalue())

    def test_test_print_requires_and_honors_proxy_id(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            refused = printproxyctl.command_test_print(
                self.settings, self._arguments(proxy_id=None)
            )
        self.assertEqual(refused, 2)
        self.assertIn("--proxy-id is required", stderr.getvalue())

        connection = MagicMock()
        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        stdout = io.StringIO()
        with (
            patch("printproxyctl.socket.create_connection", return_value=context_manager) as connect,
            contextlib.redirect_stdout(stdout),
        ):
            accepted = printproxyctl.command_test_print(
                self.settings,
                self._arguments(proxy_id="proxy-003", text="ROUTE THREE"),
            )

        self.assertEqual(accepted, 0)
        connect.assert_called_once_with(("127.0.0.3", 19103), timeout=self.settings.connect_timeout)
        self.assertIn("[proxy-003]", stdout.getvalue())
        self.assertIn(b"ROUTE THREE", connection.sendall.call_args.args[0])

    def test_verify_includes_read_only_legacy_flat_ledger(self) -> None:
        self.settings.manifest_path.write_bytes(b"")
        stdout = io.StringIO()
        with (
            patch("printproxyctl.service_status", return_value=("inactive", "inactive")),
            contextlib.redirect_stdout(stdout),
        ):
            result = printproxyctl.command_verify(
                self.settings, self._arguments(ledger_only=True)
            )

        self.assertEqual(result, 0)
        output = stdout.getvalue()
        for label in ("proxy-001", "proxy-002", "proxy-003", "legacy-flat"):
            self.assertIn(f"[{label}]", output)

    def test_queue_all_includes_legacy_states_as_read_only(self) -> None:
        self.settings.states_dir.mkdir(parents=True)
        legacy_job = str(uuid.uuid4())
        StateStore(self.settings).write(
            {
                "job_id": legacy_job,
                "state": "SENT_UNCONFIRMED",
                "bytes_archived": 42,
            }
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = printproxyctl.command_queue(
                self.settings, self._arguments(all=True, json=True)
            )

        self.assertEqual(result, 0)
        records = json.loads(stdout.getvalue())
        legacy = next(record for record in records if record["job_id"] == legacy_job)
        self.assertEqual(legacy["proxy_id"], "legacy-flat")
        self.assertEqual(legacy["storage_scope"], "legacy-flat")
        self.assertIs(legacy["read_only"], True)

    def test_status_identifies_legacy_flat_history(self) -> None:
        self.settings.manifest_path.write_bytes(b"")
        stdout = io.StringIO()
        with (
            patch("printproxyctl.service_status", return_value=("active", "active")),
            patch("printproxyctl.ntp_status", return_value=(True, "synchronized")),
            patch("printproxyctl._listener_check", return_value=(True, "up")),
            patch("printproxyctl.tcp_probe", return_value=(True, "reachable", 1.0)),
            patch("printproxyctl.verify_manifest_head", return_value=(True, "head ok")),
            patch("printproxyctl.disk_free_mb", return_value=4096),
            contextlib.redirect_stdout(stdout),
        ):
            result = printproxyctl.command_status(self.settings, self._arguments())

        self.assertEqual(result, 0)
        self.assertIn("[legacy-flat]", stdout.getvalue())
        self.assertIn("read-only pre-multi-printer history", stdout.getvalue())

    def test_status_fails_closed_for_stranded_legacy_queue_state(self) -> None:
        self.settings.states_dir.mkdir(parents=True)
        StateStore(self.settings).write(
            {
                "job_id": str(uuid.uuid4()),
                "state": "FAILED_BEFORE_SEND",
            }
        )
        stdout = io.StringIO()
        with (
            patch("printproxyctl.service_status", return_value=("active", "active")),
            patch("printproxyctl.ntp_status", return_value=(True, "synchronized")),
            patch("printproxyctl._listener_check", return_value=(True, "up")),
            patch("printproxyctl.tcp_probe", return_value=(True, "reachable", 1.0)),
            patch("printproxyctl.verify_manifest_head", return_value=(True, "head ok")),
            patch("printproxyctl.disk_free_mb", return_value=4096),
            contextlib.redirect_stdout(stdout),
        ):
            result = printproxyctl.command_status(self.settings, self._arguments())

        self.assertEqual(result, 1)
        self.assertIn("Operational states:   1 require migration review", stdout.getvalue())
        self.assertIn("Replayable stranded:  1", stdout.getvalue())

    def test_self_test_runs_route_scoped_checks_for_every_mapping(self) -> None:
        stdout = io.StringIO()
        with (
            patch("printproxyctl.service_status", return_value=("inactive", "inactive")),
            patch("printproxyctl.ntp_status", return_value=(True, "synchronized")),
            patch("printproxyctl._listener_check", return_value=(True, "bind ok")),
            patch("printproxyctl.tcp_probe", return_value=(True, "reachable", 1.0)),
            patch("printproxyctl.disk_free_mb", return_value=4096),
            contextlib.redirect_stdout(stdout),
        ):
            result = printproxyctl.command_self_test(self.settings, self._arguments())

        self.assertEqual(result, 0)
        output = stdout.getvalue()
        for proxy_id in ("proxy-001", "proxy-002", "proxy-003"):
            self.assertIn(f"[{proxy_id}] listener/bind", output)
            self.assertIn(f"[{proxy_id}] printer TCP", output)
            self.assertIn(f"[{proxy_id}] manifest/hash-chain/HMAC", output)


if __name__ == "__main__":
    unittest.main()
