from __future__ import annotations

import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from printproxy_core import (  # noqa: E402
    StateStore,
    atomic_write_bytes,
    durable_move,
    ensure_runtime_directories,
    load_settings,
    retention_eligible,
    sha256_file,
)
from support import TestEnvironment  # noqa: E402


class SpoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = TestEnvironment()
        self.settings = load_settings(self.environment.config)
        ensure_runtime_directories(self.settings)
        self.store = StateStore(self.settings)

    def tearDown(self) -> None:
        self.environment.close()

    def test_atomic_state_replacement(self) -> None:
        job_id = str(uuid.uuid4())
        state = {"job_id": job_id, "state": "RECEIVING", "counter": 1}
        self.store.write(state)
        state["state"] = "QUEUED"
        state["counter"] = 2
        self.store.write(state)
        self.assertEqual(self.store.load(job_id), state)
        self.assertFalse(any(self.settings.states_dir.glob("*.tmp")))

    def test_durable_move_preserves_exact_bytes(self) -> None:
        payload = os.urandom(131071)
        source = self.settings.receiving_dir / "source.tmp"
        destination = self.settings.data_dir / "destination.raw"
        atomic_write_bytes(source, payload)
        durable_move(source, destination)
        self.assertFalse(source.exists())
        self.assertEqual(destination.read_bytes(), payload)
        digest, size = sha256_file(destination)
        self.assertEqual(size, len(payload))
        self.assertEqual(len(digest), 64)

    def test_retention_only_allows_successful_terminal_jobs(self) -> None:
        old = "2000-01-01T00:00:00.000000Z"
        self.assertTrue(
            retention_eligible(
                {"state": "SENT_UNCONFIRMED", "timestamp_archive_complete": old},
                1_700_000_000,
            )
        )
        for state in ("QUEUED", "PARTIAL", "UNKNOWN_PRINT_STATE", "FAILED_BEFORE_SEND"):
            self.assertFalse(
                retention_eligible(
                    {"state": state, "timestamp_archive_complete": old}, 1_700_000_000
                )
            )

    def test_state_path_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            self.store.path_for("../../outside")


if __name__ == "__main__":
    unittest.main()
