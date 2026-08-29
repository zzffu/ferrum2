from __future__ import annotations

import copy
import pathlib
import tempfile
import unittest

from tests.performance_udp_workers._fixture import valid_record
from tools.performance_udp_workers.contract import UdpWorkerControlError
from tools.performance_udp_workers.evidence import summarize, validate_trial
from tools.performance_udp_workers.pairing import build_trials


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.directory.name)
        self.runner = root / "m4-qualification"
        self.client = root / "ferrum2-client"
        self.server = root / "ferrum2-server"
        for path, content in (
            (self.runner, b"runner"),
            (self.client, b"client"),
            (self.server, b"server"),
        ):
            path.write_bytes(content)
        self.sha = "a" * 40
        self.contract = {
            "producer_source_sha256": "1" * 64,
            "controller_source_sha256": "2" * 64,
            "semantic_recipe_sha256": "3" * 64,
            "evidence_bundle_sha256": "4" * 64,
        }

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_closed_trial_recomputes_all_structural_deltas(self) -> None:
        trial = build_trials()[0]
        record = valid_record(
            trial,
            candidate_sha=self.sha,
            contract=self.contract,
            runner=self.runner,
            client=self.client,
            server=self.server,
        )
        validate_trial(
            record,
            trial,
            candidate_sha=self.sha,
            contract=self.contract,
            runner=self.runner,
            client=self.client,
            server=self.server,
        )

    def test_overflow_and_missing_counter_fail_closed(self) -> None:
        trial = build_trials()[0]
        record = valid_record(
            trial,
            candidate_sha=self.sha,
            contract=self.contract,
            runner=self.runner,
            client=self.client,
            server=self.server,
        )
        overflow = copy.deepcopy(record)
        overflow["structural"]["server_after"]["overflowed"] = True
        with self.assertRaisesRegex(UdpWorkerControlError, "overflow"):
            validate_trial(
                overflow,
                trial,
                candidate_sha=self.sha,
                contract=self.contract,
                runner=self.runner,
                client=self.client,
                server=self.server,
            )
        missing = copy.deepcopy(record)
        del missing["structural"]["server_delta"]["admission_lock_wait_nanoseconds"]
        with self.assertRaisesRegex(UdpWorkerControlError, "not closed"):
            validate_trial(
                missing,
                trial,
                candidate_sha=self.sha,
                contract=self.contract,
                runner=self.runner,
                client=self.client,
                server=self.server,
            )

    def test_summary_is_always_deferred_and_keeps_default_one(self) -> None:
        records = []
        for trial in build_trials():
            throughput = 100_000
            if trial.phase == "comparison" and trial.member == "variant":
                throughput += trial.server_receive_workers * 10_000
            records.append(
                valid_record(
                    trial,
                    candidate_sha=self.sha,
                    contract=self.contract,
                    runner=self.runner,
                    client=self.client,
                    server=self.server,
                    throughput=throughput,
                )
            )
        summary = summarize(records, self.sha)
        self.assertEqual(summary["decision"], "DEFERRED")
        self.assertEqual(summary["default_receive_workers"], 1)
        self.assertFalse(summary["default_changed"])
        self.assertFalse(summary["authority"]["performance_authoritative"])


if __name__ == "__main__":
    unittest.main()
