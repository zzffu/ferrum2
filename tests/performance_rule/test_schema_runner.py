import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.performance_rule._fixture import SCENARIO_SUITES, report
from tools.performance_rule.json_contract import closed_json_bytes
from tools.performance_rule.runner_report import require_same_scenarios, validate_report
from tools.performance_rule.schema import (
    RUNNER_PRIORITY_HIGH,
    RUNNER_PRIORITY_NORMAL,
    ControlError,
    runner_creation_flags,
    validate_pairs,
)


class SchemaAndRunnerTests(unittest.TestCase):
    def test_requires_exactly_six_pairs(self):
        with self.assertRaisesRegex(ControlError, "pairs"):
            validate_pairs(5)
        validate_pairs(6)
        with self.assertRaisesRegex(ControlError, "pairs"):
            validate_pairs(8)

    def test_high_priority_is_windows_only_and_never_realtime(self):
        self.assertEqual(runner_creation_flags(RUNNER_PRIORITY_NORMAL), 0)
        with mock.patch("tools.performance_rule.schema.sys.platform", "not-windows"):
            with self.assertRaisesRegex(ControlError, "only on Windows"):
                runner_creation_flags(RUNNER_PRIORITY_HIGH)
        if sys.platform == "win32":
            import subprocess

            flags = runner_creation_flags(RUNNER_PRIORITY_HIGH)
            self.assertEqual(flags, subprocess.HIGH_PRIORITY_CLASS)
            self.assertNotEqual(flags, subprocess.REALTIME_PRIORITY_CLASS)

    def test_runner_sha_and_measurement_shape_are_validated(self):
        self.assertEqual(validate_report(report("abc"), "abc"), SCENARIO_SUITES)
        with self.assertRaisesRegex(ControlError, "SHA-256"):
            validate_report(report("wrong"), "abc")
        malformed = report("abc")
        malformed["measurements"][0]["samples_ns_per_op"] = [1] * 4
        with self.assertRaisesRegex(ControlError, "sample count"):
            validate_report(malformed, "abc")
        extra = report("abc")
        extra["measurements"][0]["invented"] = True
        with self.assertRaisesRegex(ControlError, "fields"):
            validate_report(extra, "abc")
        nonfinite = report("abc")
        nonfinite["measurements"][0]["p50_ns_per_op"] = float("nan")
        with self.assertRaisesRegex(ControlError, "p50"):
            validate_report(nonfinite, "abc")

    def test_profile_size_matrix_is_exact_and_100k_is_append_only(self):
        malformed = report("abc")
        malformed["configuration"]["match_sizes"] = [64, 65, 100]
        with self.assertRaisesRegex(ControlError, "profile size"):
            validate_report(malformed, "abc")

        qualification = report("abc")
        qualification["configuration"]["includes_100k"] = True
        qualification["configuration"]["match_sizes"].append(100_000)
        self.assertEqual(validate_report(qualification, "abc"), SCENARIO_SUITES)

    def test_candidate_identity_is_closed_sorted_and_non_adopting(self):
        enabled = report("abc")
        enabled["candidate"]["enabled_features"] = [
            "candidate-atomic-snapshot",
            "candidate-cidr-radix",
            "candidate-domain-suffix-trie",
        ]
        self.assertEqual(validate_report(enabled, "abc"), SCENARIO_SUITES)

        for candidate, message in (
            ({"enabled_features": []}, "fields"),
            ({"adoption_claim": True, "enabled_features": []}, "adoption"),
            (
                {
                    "adoption_claim": False,
                    "enabled_features": [
                        "candidate-domain-suffix-trie",
                        "candidate-cidr-radix",
                    ],
                },
                "identity",
            ),
            (
                {
                    "adoption_claim": False,
                    "enabled_features": [
                        "candidate-cidr-radix",
                        "candidate-cidr-radix",
                    ],
                },
                "identity",
            ),
            (
                {"adoption_claim": False, "enabled_features": ["candidate-unknown"]},
                "identity",
            ),
        ):
            malformed = report("abc")
            malformed["candidate"] = candidate
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(ControlError, message):
                    validate_report(malformed, "abc")

    def test_snapshot_lifecycle_and_required_contention_rows_fail_closed(self):
        lifecycle = report("abc")
        lifecycle["snapshot_lifecycle"][
            "old_snapshot_released_after_reader_release"
        ] = False
        with self.assertRaisesRegex(ControlError, "snapshot lifecycle"):
            validate_report(lifecycle, "abc")

        missing = report("abc")
        missing["measurements"] = [
            row
            for row in missing["measurements"]
            if row["id"] != "snapshot_registry/registry_publish/publish_under_readers"
        ]
        missing["scenario_count"] = len(missing["measurements"])
        with self.assertRaisesRegex(ControlError, "snapshot measurement"):
            validate_report(missing, "abc")

        inconsistent = report("abc")
        inconsistent["snapshot_lifecycle"]["fresh_action"] = 1
        with self.assertRaisesRegex(ControlError, "generations"):
            validate_report(inconsistent, "abc")

    def test_closed_json_rejects_duplicate_nonfinite_and_oversize_input(self):
        for payload, message in (
            (b'{"value":1,"value":2}', "duplicate"),
            (b'{"value":NaN}', "non-finite"),
            (b'{"value":1e999}', "non-finite"),
            (b'{"value":' + b"1" * 5_000 + b"}", "integer"),
            (b"[" * 2_000 + b"]" * 2_000, "nesting"),
            (b"{}", "byte bound"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ControlError, message):
                    closed_json_bytes(
                        payload,
                        label="synthetic runner stdout",
                        maximum_bytes=1 if message == "byte bound" else 10_000,
                    )

    def test_parent_and_candidate_must_have_identical_scenarios(self):
        with self.assertRaisesRegex(ControlError, "catalog changed"):
            require_same_scenarios(
                {"match_set/one": "match_set"},
                {"match_set/one": "route_program"},
            )
