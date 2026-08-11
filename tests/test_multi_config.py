from __future__ import annotations

import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from printproxy_core import (
    ConfigError,
    ProxyConfig,
    StateStore,
    ensure_runtime_directories,
    load_settings,
)


class MultiProxyConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _load(self, **overrides: str):
        values = {
            "DATA_DIR": str(self.root / "jobs"),
            "SPOOL_DIR": str(self.root / "spool"),
            "LOG_DIR": str(self.root / "logs"),
            "HMAC_KEY_FILE": str(self.root / "integrity.key"),
        }
        values.update(overrides)
        config = self.root / "printproxy.conf"
        config.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()),
            encoding="utf-8",
        )
        return load_settings(config)

    def test_single_scalar_mapping_keeps_legacy_properties_and_flat_storage(self) -> None:
        settings = self._load(
            LISTEN_IP="10.1.2.220",
            LISTEN_PORT="9100",
            PRINTER_IP="10.1.2.200",
            PRINTER_PORT="9100",
        )

        self.assertEqual(len(settings.proxy_configs), 1)
        proxy = settings.proxy_configs[0]
        self.assertEqual(proxy.proxy_id, "proxy-001")
        self.assertEqual(proxy.listen_endpoint, ("10.1.2.220", 9100))
        self.assertEqual(proxy.printer_endpoint, ("10.1.2.200", 9100))
        self.assertEqual(proxy.printer_directory_name, "10.1.2.200")
        self.assertEqual(settings.listen_ip, proxy.listen_ip)
        self.assertEqual(settings.listen_port, proxy.listen_port)
        self.assertEqual(settings.printer_ip, proxy.printer_ip)
        self.assertEqual(settings.printer_port, proxy.printer_port)
        self.assertIs(settings.for_proxy(proxy), settings)
        self.assertEqual(settings.data_dir, self.root / "jobs")
        self.assertEqual(settings.spool_dir, self.root / "spool")

    def test_three_mappings_are_trimmed_correlated_and_immutable(self) -> None:
        settings = self._load(
            LISTEN_IP="10.1.2.220, 10.1.2.221 ,10.1.2.222",
            LISTEN_PORT="9100, 9101,9102",
            PRINTER_IP="10.1.2.200, 10.1.2.201,10.1.2.202",
            PRINTER_PORT="9200, 9201,9202",
        )

        self.assertEqual(
            [proxy.proxy_id for proxy in settings.proxy_configs],
            ["proxy-001", "proxy-002", "proxy-003"],
        )
        self.assertEqual(
            [
                (proxy.listen_ip, proxy.listen_port, proxy.printer_ip, proxy.printer_port)
                for proxy in settings.proxy_configs
            ],
            [
                ("10.1.2.220", 9100, "10.1.2.200", 9200),
                ("10.1.2.221", 9101, "10.1.2.201", 9201),
                ("10.1.2.222", 9102, "10.1.2.202", 9202),
            ],
        )
        with self.assertRaises(FrozenInstanceError):
            settings.proxy_configs[0].printer_ip = "10.9.9.9"  # type: ignore[misc]

    def test_multi_mapping_scopes_archive_spool_and_manifest(self) -> None:
        settings = self._load(
            LISTEN_IP="10.1.2.220,10.1.2.221,10.1.2.222",
            LISTEN_PORT="9100,9100,9100",
            PRINTER_IP="10.1.2.200,10.1.2.201,10.1.2.202",
            PRINTER_PORT="9100,9100,9100",
        )
        legacy_manifest = settings.data_dir / "manifest.jsonl"
        settings.data_dir.mkdir(parents=True)
        legacy_manifest.write_bytes(b"legacy-chain-remains-at-root\n")

        scoped = [settings.for_proxy(proxy) for proxy in settings.proxy_configs]
        self.assertEqual(
            [item.data_dir for item in scoped],
            [self.root / "jobs" / f"10.1.2.{suffix}" for suffix in (200, 201, 202)],
        )
        self.assertEqual(
            [item.spool_dir for item in scoped],
            [self.root / "spool" / f"10.1.2.{suffix}" for suffix in (200, 201, 202)],
        )
        self.assertEqual(len({item.manifest_path for item in scoped}), 3)
        self.assertTrue(all(len(item.proxy_configs) == 1 for item in scoped))

        ensure_runtime_directories(settings)

        self.assertEqual(legacy_manifest.read_bytes(), b"legacy-chain-remains-at-root\n")
        self.assertTrue(settings.locks_dir.is_dir())
        for item in scoped:
            self.assertTrue(item.data_dir.is_dir())
            self.assertTrue(item.states_dir.is_dir())
            self.assertTrue(item.receiving_dir.is_dir())
            self.assertTrue(item.requests_dir.is_dir())
            self.assertTrue(item.locks_dir.is_dir())

    def test_csv_reordering_keeps_spool_bound_to_physical_printer(self) -> None:
        original = self._load(
            LISTEN_IP="10.1.2.220,10.1.2.221,10.1.2.222",
            LISTEN_PORT="9100,9100,9100",
            PRINTER_IP="10.1.2.200,10.1.2.201,10.1.2.202",
            PRINTER_PORT="9100,9100,9100",
        )
        ensure_runtime_directories(original)
        printer_200 = next(
            proxy for proxy in original.proxy_configs if proxy.printer_ip == "10.1.2.200"
        )
        state = {
            "job_id": "00000000-0000-4000-8000-000000000200",
            "state": "FAILED_BEFORE_SEND",
            "printer_ip": "10.1.2.200",
        }
        StateStore(original.for_proxy(printer_200)).write(state)

        reordered = self._load(
            LISTEN_IP="10.1.2.222,10.1.2.220,10.1.2.221",
            LISTEN_PORT="9100,9100,9100",
            PRINTER_IP="10.1.2.202,10.1.2.200,10.1.2.201",
            PRINTER_PORT="9100,9100,9100",
        )
        ensure_runtime_directories(reordered)
        scoped_by_printer = {
            proxy.printer_ip: reordered.for_proxy(proxy)
            for proxy in reordered.proxy_configs
        }

        self.assertEqual(
            scoped_by_printer["10.1.2.200"].spool_dir,
            self.root / "spool" / "10.1.2.200",
        )
        self.assertEqual(
            StateStore(scoped_by_printer["10.1.2.200"]).load(state["job_id"])["printer_ip"],
            "10.1.2.200",
        )
        self.assertEqual(StateStore(scoped_by_printer["10.1.2.201"]).list(), [])
        self.assertEqual(StateStore(scoped_by_printer["10.1.2.202"]).list(), [])

    def test_mismatched_array_lengths_report_every_count(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self._load(
                LISTEN_IP="10.1.2.220,10.1.2.221",
                LISTEN_PORT="9100,9100",
                PRINTER_IP="10.1.2.200",
                PRINTER_PORT="9100,9100",
            )
        message = str(raised.exception)
        self.assertIn("LISTEN_IP contains 2 entries", message)
        self.assertIn("LISTEN_PORT contains 2 entries", message)
        self.assertIn("PRINTER_IP contains 1 entries", message)
        self.assertIn("PRINTER_PORT contains 2 entries", message)
        self.assertIn("same number of entries", message)

    def test_empty_proxy_array_entries_are_never_discarded(self) -> None:
        for key, value in (
            ("LISTEN_IP", "10.1.2.220,,10.1.2.222"),
            ("LISTEN_PORT", "9100, ,9100"),
            ("PRINTER_IP", "10.1.2.200,10.1.2.201,"),
            ("PRINTER_PORT", ",9100,9100"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(
                ConfigError, rf"{key}: entry [123] is empty"
            ):
                self._load(**{key: value})

    def test_invalid_or_non_ipv4_addresses_fail_with_indexed_error(self) -> None:
        for key, value in (
            ("LISTEN_IP", "not-an-ip"),
            ("PRINTER_IP", "300.1.2.3"),
            ("LISTEN_IP", "2001:db8::1"),
            ("PRINTER_IP", "2001:db8::2"),
        ):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                ConfigError, rf"{key}\[1\]"
            ):
                self._load(**{key: value})

    def test_invalid_ports_fail_with_indexed_error(self) -> None:
        for key, value in (
            ("LISTEN_PORT", "0"),
            ("LISTEN_PORT", "65536"),
            ("PRINTER_PORT", "not-a-port"),
        ):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                ConfigError, rf"{key}\[1\]"
            ):
                self._load(**{key: value})

    def test_duplicate_listener_endpoint_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "duplicate listener endpoint 10.1.2.220:9100"):
            self._load(
                LISTEN_IP="10.1.2.220,10.1.2.220",
                LISTEN_PORT="9100,9100",
                PRINTER_IP="10.1.2.200,10.1.2.201",
                PRINTER_PORT="9100,9100",
            )

    def test_duplicate_printer_ip_is_rejected_even_on_different_ports(self) -> None:
        with self.assertRaisesRegex(ConfigError, "duplicate PRINTER_IP 10.1.2.200"):
            self._load(
                LISTEN_IP="10.1.2.220,10.1.2.221",
                LISTEN_PORT="9100,9100",
                PRINTER_IP="10.1.2.200,10.1.2.200",
                PRINTER_PORT="9100,9200",
            )

    def test_swapped_cross_route_listener_cycle_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unsafe proxy route graph"):
            self._load(
                LISTEN_IP="10.1.2.220,10.1.2.221",
                LISTEN_PORT="9100,9200",
                PRINTER_IP="10.1.2.221,10.1.2.220",
                PRINTER_PORT="9200,9100",
            )

    def test_one_way_cross_route_listener_ip_is_rejected_even_on_other_port(self) -> None:
        with self.assertRaisesRegex(
            ConfigError,
            "PRINTER_IP 10.1.2.220 .* also configured as LISTEN_IP",
        ):
            self._load(
                LISTEN_IP="10.1.2.220,10.1.2.221",
                LISTEN_PORT="9100,9200",
                PRINTER_IP="10.1.2.200,10.1.2.220",
                PRINTER_PORT="9100,9300",
            )

    def test_proxy_route_constructor_enforces_safe_identifiers_and_ipv4(self) -> None:
        for unsafe in ("../printer", ".", "proxy/one", "proxy one"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ConfigError):
                ProxyConfig(unsafe, "10.1.2.220", 9100, "10.1.2.200", 9100)
        with self.assertRaises(ConfigError):
            ProxyConfig("proxy-001", "10.1.2.220", 9100, "2001:db8::1", 9100)

    def test_for_proxy_rejects_a_route_from_another_settings_object(self) -> None:
        settings = self._load(
            LISTEN_IP="10.1.2.220,10.1.2.221",
            LISTEN_PORT="9100,9100",
            PRINTER_IP="10.1.2.200,10.1.2.201",
            PRINTER_PORT="9100,9100",
        )
        foreign = ProxyConfig("proxy-999", "10.1.2.250", 9100, "10.1.2.251", 9100)
        with self.assertRaisesRegex(ConfigError, "not part of these settings"):
            settings.for_proxy(foreign)


if __name__ == "__main__":
    unittest.main()
