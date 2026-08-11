from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from printproxy_core import (
    ConfigError,
    IntegrityError,
    IntegrityLedger,
    StorageError,
    StateStore,
    atomic_write_bytes,
    atomic_write_json,
    ensure_runtime_directories,
    load_hmac_key,
    load_settings,
    metadata_document_from_state,
    read_installed_storage_paths,
    secure_prepare_service_directories,
    sha256_file,
    validate_installer_route_lifecycle,
    validate_single_to_multi_migration,
)


class InstallerRouteLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "printproxy.conf"
        self.install_state = self.root / "install-state"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _settings(
        self,
        routes: list[tuple[str, int, str, int]],
        *,
        data_dir: Path | None = None,
        spool_dir: Path | None = None,
    ):
        values = {
            "LISTEN_IP": ",".join(route[0] for route in routes),
            "LISTEN_PORT": ",".join(str(route[1]) for route in routes),
            "PRINTER_IP": ",".join(route[2] for route in routes),
            "PRINTER_PORT": ",".join(str(route[3]) for route in routes),
            "DATA_DIR": str(data_dir or self.root / "jobs"),
            "SPOOL_DIR": str(spool_dir or self.root / "spool"),
            "LOG_DIR": str(self.root / "logs"),
            "HMAC_KEY_FILE": str(self.root / "integrity.key"),
        }
        self.config.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()),
            encoding="utf-8",
        )
        return load_settings(self.config)

    def _mapping_state(self, routes: list[tuple[str, int, str, int]]) -> None:
        self.install_state.write_text(
            "".join(
                (
                    "SCHEMA_VERSION=4\n",
                    "VIP_LIST=" + ",".join(route[0] for route in routes) + "\n",
                    "LISTEN_PORT_LIST="
                    + ",".join(str(route[1]) for route in routes)
                    + "\n",
                    "PRINTER_IP_LIST=" + ",".join(route[2] for route in routes) + "\n",
                    "PRINTER_PORT_LIST="
                    + ",".join(str(route[3]) for route in routes)
                    + "\n",
                    f"DATA_DIR={self.root / 'jobs'}\n",
                    f"SPOOL_DIR={self.root / 'spool'}\n",
                )
            ),
            encoding="utf-8",
        )

    def _validate(self, settings) -> None:
        validate_installer_route_lifecycle(
            settings,
            self.install_state,
            legacy_storage_paths=(self.root / "jobs", self.root / "spool"),
        )

    def _legacy_state(self, *listen_ips: str) -> None:
        self.install_state.write_text(
            "SCHEMA_VERSION=2\nVIP_LIST=" + ",".join(listen_ips) + "\n",
            encoding="utf-8",
        )

    def _operational_state(
        self,
        route: tuple[str, int, str, int],
        *,
        scope: str | None = None,
        filename: str = "00000000-0000-4000-8000-000000000001.json",
    ) -> None:
        spool = self.root / "spool"
        if scope is not None:
            spool /= scope
        states = spool / "states"
        states.mkdir(parents=True, exist_ok=True)
        states.joinpath(filename).write_text(
            json.dumps(
                {
                    "job_id": Path(filename).stem,
                    "proxy_ip": route[0],
                    "proxy_port": route[1],
                    "printer_ip": route[2],
                    "printer_port": route[3],
                    "state": "SENT_UNCONFIRMED",
                }
            ),
            encoding="utf-8",
        )

    def test_mapping_state_allows_reordering_and_addition(self) -> None:
        first = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        second = ("10.1.2.221", 9101, "10.1.2.201", 9100)
        added = ("10.1.2.222", 9102, "10.1.2.202", 9100)
        self._mapping_state([first, second])
        settings = self._settings([second, added, first])

        self._validate(settings)

    def test_mapping_state_rejects_removal_or_endpoint_substitution(self) -> None:
        first = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        second = ("10.1.2.221", 9101, "10.1.2.201", 9100)
        self._mapping_state([first, second])

        for current in (
            [first],
            [first, ("10.1.2.221", 9101, "10.1.2.202", 9100)],
            [("10.1.2.220", 9200, "10.1.2.200", 9100), second],
        ):
            with self.subTest(current=current), self.assertRaisesRegex(
                ConfigError, "route removal/replacement is forbidden"
            ):
                self._validate(self._settings(current))

    def test_incomplete_mapping_state_fails_closed(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self.install_state.write_text(
            "SCHEMA_VERSION=3\nVIP_LIST=10.1.2.220\nLISTEN_PORT_LIST=9100\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ConfigError, "mapping state is incomplete"):
            self._validate(self._settings([route]))

    def test_legacy_flat_state_infers_and_preserves_exact_endpoint(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._legacy_state(route[0])
        self._operational_state(route)

        self._validate(self._settings([route]))

        changed = ("10.1.2.220", 9100, "10.1.2.201", 9100)
        with self.assertRaisesRegex(ConfigError, "route removal/replacement is forbidden"):
            self._validate(self._settings([changed]))

    def test_legacy_scoped_state_is_bound_to_physical_printer_directory(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._legacy_state(route[0])
        self._operational_state(route, scope=route[2])
        (self.root / "jobs" / route[2]).mkdir(parents=True)
        (self.root / "jobs" / route[2] / "receipt.raw").write_bytes(b"job")

        self._validate(self._settings([route]))

    def test_nonempty_legacy_history_without_inferable_state_is_rejected(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._legacy_state(route[0])
        (self.root / "jobs").mkdir()
        (self.root / "jobs" / "orphan.raw").write_bytes(b"orphan")

        with self.assertRaisesRegex(ConfigError, "non-empty.*no complete route"):
            self._validate(self._settings([route]))

    def test_empty_authenticated_head_is_not_treated_as_job_history(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._legacy_state(route[0])
        (self.root / "jobs").mkdir()
        (self.root / "jobs" / "manifest.head.json").write_text(
            json.dumps({"record_count": 0, "last_chain_hash": "0" * 64}),
            encoding="utf-8",
        )

        self._validate(self._settings([route]))

    def test_legacy_directory_scan_stops_at_the_entry_budget(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._legacy_state(route[0])
        (self.root / "jobs").mkdir()
        (self.root / "jobs" / "one.raw").write_bytes(b"one")
        (self.root / "jobs" / "two.raw").write_bytes(b"two")

        with mock.patch("printproxy_core._INSTALLER_HISTORY_MAX_ENTRIES", 1):
            with self.assertRaisesRegex(ConfigError, "bounded entry limit"):
                self._validate(self._settings([route]))

    def test_mapping_state_rejects_data_or_spool_path_drift(self) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._mapping_state([route])
        for key, settings in (
            ("DATA_DIR", self._settings([route], data_dir=self.root / "new-jobs")),
            ("SPOOL_DIR", self._settings([route], spool_dir=self.root / "new-spool")),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(
                ConfigError, rf"storage path change.*{key}"
            ):
                self._validate(settings)

    def test_legacy_state_without_storage_identity_requires_deployed_path_fallback(
        self,
    ) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        self._legacy_state(route[0])
        self._operational_state(route)
        settings = self._settings([route])

        with self.assertRaisesRegex(ConfigError, "no DATA_DIR/SPOOL_DIR identity"):
            validate_installer_route_lifecycle(settings, self.install_state)
        self._validate(settings)

    def test_legacy_storage_identity_is_read_from_deployed_systemd_dropin(self) -> None:
        dropin = self.root / "paths.conf"
        dropin.write_text(
            "[Service]\nReadWritePaths=\n"
            f"ReadWritePaths={self.root / 'jobs'} {self.root / 'spool'} "
            f"{self.root / 'logs'}\n",
            encoding="utf-8",
        )

        self.assertEqual(
            read_installed_storage_paths(dropin),
            (self.root / "jobs", self.root / "spool"),
        )

    def test_single_to_multi_rejects_terminal_state_tampered_past_authenticated_ledger(
        self,
    ) -> None:
        route = ("10.1.2.220", 9100, "10.1.2.200", 9100)
        added = ("10.1.2.221", 9100, "10.1.2.201", 9100)
        self.root.joinpath("integrity.key").write_bytes(
            b"installer-migration-test-key-32-bytes-minimum"
        )
        legacy = self._settings([route])
        ensure_runtime_directories(legacy)
        key = load_hmac_key(legacy, cli=True)
        ledger = IntegrityLedger(legacy, key)
        job_id = "00000000-0000-4000-8000-000000000901"
        raw_path = legacy.data_dir / f"{job_id}.raw"
        metadata_path = legacy.data_dir / f"{job_id}.json"
        atomic_write_bytes(raw_path, b"queued-before-migration")
        raw_hash, raw_size = sha256_file(raw_path)
        state = {
            "schema_version": 1,
            "job_id": job_id,
            "state": "QUEUED",
            "proxy_ip": route[0],
            "proxy_port": route[1],
            "printer_ip": route[2],
            "printer_port": route[3],
            "raw_filename": raw_path.name,
            "metadata_filename": metadata_path.name,
            "raw_sha256": raw_hash,
            "bytes_received": raw_size,
            "bytes_archived": raw_size,
            "bytes_forwarded": 0,
            "attempts": 0,
            "queue_order": "00000000000000000001-migration",
            "queue_sequence": 1,
            "last_committed_event": "QUEUED",
        }
        atomic_write_json(metadata_path, metadata_document_from_state(state))
        metadata_hash, _ = sha256_file(metadata_path)
        state["metadata_sha256"] = metadata_hash
        StateStore(legacy).write(state)
        common = {
            "job_id": job_id,
            "raw_filename": raw_path.name,
            "raw_sha256": raw_hash,
            "raw_size": raw_size,
            "metadata_filename": metadata_path.name,
            "metadata_sha256": metadata_hash,
            "destination": f"{route[2]}:{route[3]}",
        }
        ledger.append({"event": "ARCHIVED", "status": "SEALED", **common})
        ledger.append({"event": "QUEUED", "status": "QUEUED", **common})
        self.assertTrue(ledger.verify(check_files=True).ok)

        self._mapping_state([route])
        current = self._settings([route, added])
        tampered = dict(state, state="SENT_UNCONFIRMED")
        StateStore(legacy).write(tampered)
        lock_path = legacy.locks_dir / "manifest.lock"
        lock_path.unlink()

        with self.assertRaisesRegex(IntegrityError, "verification failed"):
            validate_single_to_multi_migration(current, self.install_state, key)
        self.assertFalse(lock_path.exists())

    def test_installer_persists_route_lists_and_requires_exact_prefix(self) -> None:
        project = Path(__file__).resolve().parents[1]
        script = (project / "install.sh").read_text(encoding="utf-8")
        for key in (
            "VIP_LIST",
            "LISTEN_PORT_LIST",
            "PRINTER_IP_LIST",
            "PRINTER_PORT_LIST",
            "DATA_DIR",
            "SPOOL_DIR",
        ):
            self.assertIn(f"printf '{key}=%s\\n'", script)
        self.assertIn("SCHEMA_VERSION=4", script)
        self.assertIn("network.prefixlen == configured_prefix", script)
        self.assertIn("validate_single_to_multi_migration", script)
        self.assertIn("key = load_hmac_key(settings, cli=True)", script)
        stop_message = script.index("Stopping printproxy.service")
        service_stop = script.index("systemctl stop printproxy.service", stop_message)
        directory_prepare = script.index("secure_prepare_service_directories(")
        self.assertLess(service_stop, directory_prepare)
        self.assertNotIn('"$SPOOL_DIR/states"', script)

        uninstall = (project / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('conf_get PRINTER_IP_LIST "$STATE_FILE"', uninstall)
        self.assertIn('conf_get PRINTER_PORT_LIST "$STATE_FILE"', uninstall)
        self.assertIn('conf_get DATA_DIR "$STATE_FILE"', uninstall)
        self.assertIn('conf_get SPOOL_DIR "$STATE_FILE"', uninstall)
        self.assertIn("legacy installer state has no authoritative DATA_DIR/SPOOL_DIR", uninstall)

        vip_helper = (project / "network" / "printproxy-vip").read_text(
            encoding="utf-8"
        )
        down_branch = vip_helper.index("    down)")
        config_read = vip_helper.index('[ -r "$CONF" ]')
        self.assertLess(down_branch, config_read)
        self.assertIn('VIP_LIST=$(get_value VIP_LIST "$STATE")', vip_helper)
        self.assertIn('[ -n "$VIP_LIST" ] || VIP_LIST=$(get_value VIP "$STATE")', vip_helper)

        firewall_helper = (project / "network" / "printproxy-firewall").read_text(
            encoding="utf-8"
        )
        firewall_down = firewall_helper.index('if [ "${1:-}" = down ]')
        firewall_config_read = firewall_helper.index('[ -r "$CONF" ]')
        self.assertLess(firewall_down, firewall_config_read)
        self.assertIn('OWNED=$(get_value FIREWALL_OWNED "$STATE")', firewall_helper)

    @unittest.skipUnless(os.name == "posix", "requires POSIX dirfd/O_NOFOLLOW")
    def test_secure_directory_preparation_rejects_spool_child_symlink(self) -> None:
        data = self.root / "jobs"
        spool = self.root / "spool"
        logs = self.root / "logs"
        external = self.root / "external"
        data.mkdir()
        spool.mkdir()
        logs.mkdir()
        external.mkdir(mode=0o711)
        try:
            (spool / "states").symlink_to(external, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        before = external.stat()

        with self.assertRaisesRegex(StorageError, "unsafe installer"):
            secure_prepare_service_directories(
                data,
                spool,
                logs,
                uid=os.getuid() or 65534,
                gid=os.getgid() or 65534,
            )

        after = external.stat()
        self.assertEqual(stat.S_IMODE(before.st_mode), stat.S_IMODE(after.st_mode))
        self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))


if __name__ == "__main__":
    unittest.main()
