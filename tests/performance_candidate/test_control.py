#!/usr/bin/env python3
"""Behavior tests for the manual performance candidate control plane."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import ROUND_CEILING, Decimal

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "performance_candidate.py"
POLICY_PATH = ROOT / "tools" / "performance_candidate_policy.json"
SCALE_POLICY_PATH = ROOT / "tools" / "performance_candidate_scale_safety_policy.json"
WINDOWS_TUN_POLICY_PATH = ROOT / "tools" / "windows_tun_performance_policy.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "performance-candidate.yml"
SPEC = importlib.util.spec_from_file_location("performance_candidate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)

FINAL_CALIBRATION_POLICY_ID = (
    "github-hosted-ubuntu-24.04-profiling-v1-"
    "calibrated-final-harness-20260818"
)
FINAL_CALIBRATION_ENVIRONMENT = {
    **CONTROL.MEASUREMENT_ENVIRONMENT,
    "warmup_seconds": 3,
    "active_seconds": 30,
}
TCP_CALIBRATION_SOURCE = (
    "artifact:github-actions/zzffu/ferrum2/runs/32126651170/artifacts/"
    "9321742851/paired-profile-qualification-tcp-frame-capacity-"
    "32126651170-1@sha256:"
    "ee1f51842a9e07126ca80b61905d452a8298e74923044d9e3ed795d1587edb97"
)
UDP_CALIBRATION_SOURCE = (
    "artifact:github-actions/zzffu/ferrum2/runs/32126655215/artifacts/"
    "9321908225/paired-profile-qualification-udp-payload-matrix-"
    "32126655215-1@sha256:"
    "fbd1356c631398fd087b9370d7498b1ed1fed31576535b9224aaf3fc0cc5379d"
)
UDP_DIRECT_CALIBRATION_SOURCE = (
    "artifact:github-actions/zzffu/ferrum2/runs/32126658578/artifacts/"
    "9321242153/paired-profile-qualification-udp-direct-payload-bounds-"
    "32126658578-1@sha256:"
    "29830b3b677a35ed8de55886defbd985c81396ca30ddb0945d8084005195c5dd"
)
FINAL_CALIBRATION_THRESHOLDS = {
    "tcp-stream-64k": (
        Decimal("2.290"),
        Decimal("-2.291"),
        TCP_CALIBRATION_SOURCE,
    ),
    "tcp-bulk": (
        Decimal("0.912"),
        Decimal("-0.913"),
        TCP_CALIBRATION_SOURCE,
    ),
    "tcp-request-1k": (
        Decimal("0.771"),
        Decimal("-2.001"),
        TCP_CALIBRATION_SOURCE,
    ),
    "tcp-request-4k": (
        Decimal("0.809"),
        Decimal("-2.001"),
        TCP_CALIBRATION_SOURCE,
    ),
    "tcp-request-16k": (
        Decimal("0.572"),
        Decimal("-2.001"),
        TCP_CALIBRATION_SOURCE,
    ),
    "udp-small-high": (
        Decimal("0.436"),
        Decimal("-0.437"),
        UDP_CALIBRATION_SOURCE,
    ),
    "udp-mtu-1200": (
        Decimal("0.692"),
        Decimal("-0.693"),
        UDP_CALIBRATION_SOURCE,
    ),
    "udp-payload-1472": (
        Decimal("0.343"),
        Decimal("-0.344"),
        UDP_CALIBRATION_SOURCE,
    ),
    "udp-payload-1500": (
        Decimal("0.394"),
        Decimal("-0.395"),
        UDP_CALIBRATION_SOURCE,
    ),
    "udp-payload-8192": (
        Decimal("0.919"),
        Decimal("-0.920"),
        UDP_CALIBRATION_SOURCE,
    ),
    "udp-max-wire-65507": (
        Decimal("1.206"),
        Decimal("-1.207"),
        UDP_CALIBRATION_SOURCE,
    ),
    "udp-direct-small-128": (
        Decimal("2.789"),
        Decimal("-2.790"),
        UDP_DIRECT_CALIBRATION_SOURCE,
    ),
    "udp-direct-max-65497": (
        Decimal("0.518"),
        Decimal("-0.519"),
        UDP_DIRECT_CALIBRATION_SOURCE,
    ),
}
FINAL_AA_RAW_EVIDENCE = {
    "tcp-stream-64k": (
        "higher_is_better",
        (
            (239_451_067, 237_685_964),
            (247_105_672, 241_443_362),
            (248_093_081, 242_413_294),
            (245_366_784, 238_909_303),
            (246_633_813, 242_946_321),
        ),
    ),
    "tcp-bulk": (
        "higher_is_better",
        (
            (282_252_629, 283_331_788),
            (285_116_552, 287_716_147),
            (284_843_485, 279_742_600),
            (282_447_052, 283_709_713),
            (285_393_988, 282_355_302),
        ),
    ),
    "tcp-request-1k": (
        "lower_is_better",
        (
            (182_890, 179_805),
            (183_100, 181_689),
            (180_447, 179_725),
            (179_304, 182_880),
            (180_797, 180_256),
        ),
    ),
    "tcp-request-4k": (
        "lower_is_better",
        (
            (199_244, 197_081),
            (199_374, 198_693),
            (201_839, 197_893),
            (199_354, 197_742),
            (198_273, 199_215),
        ),
    ),
    "tcp-request-16k": (
        "lower_is_better",
        (
            (259_253, 257_771),
            (256_349, 257_501),
            (257_991, 255_468),
            (255_648, 260_785),
            (257_620, 258_702),
        ),
    ),
    "udp-small-high": (
        "higher_is_better",
        (
            (14_772, 14_704),
            (14_979, 14_949),
            (14_940, 14_875),
            (14_900, 14_802),
            (15_019, 14_972),
        ),
    ),
    "udp-mtu-1200": (
        "higher_is_better",
        (
            (14_343, 14_390),
            (14_489, 14_375),
            (14_460, 14_360),
            (14_463, 14_384),
            (14_468, 14_339),
        ),
    ),
    "udp-payload-1472": (
        "higher_is_better",
        (
            (14_305, 14_256),
            (14_279, 14_270),
            (14_318, 14_226),
            (14_284, 14_239),
            (14_239, 14_170),
        ),
    ),
    "udp-payload-1500": (
        "higher_is_better",
        (
            (14_228, 14_188),
            (14_245, 14_189),
            (14_288, 14_228),
            (14_313, 14_268),
            (14_324, 14_203),
        ),
    ),
    "udp-payload-8192": (
        "higher_is_better",
        (
            (11_505, 11_399),
            (11_558, 11_429),
            (11_546, 11_440),
            (11_476, 11_455),
            (11_460, 11_431),
        ),
    ),
    "udp-max-wire-65507": (
        "higher_is_better",
        (
            (5_560, 5_493),
            (5_450, 5_507),
            (5_635, 5_501),
            (5_532, 5_494),
            (5_464, 5_593),
        ),
    ),
    "udp-direct-small-128": (
        "higher_is_better",
        (
            (36_976, 37_779),
            (37_077, 38_111),
            (37_489, 36_110),
            (35_633, 35_579),
            (36_188, 37_904),
        ),
    ),
    "udp-direct-max-65497": (
        "higher_is_better",
        (
            (20_582, 20_725),
            (20_880, 20_772),
            (20_969, 20_747),
            (20_605, 20_653),
            (20_704, 20_776),
        ),
    ),
}
FINAL_AA_RAW_EVIDENCE_SHA256 = (
    "bf6bc4e00d69e9e906c899b9188de5b7da806bb6591e4ff503fc869f7fc555c3"
)


def synthetic_policy(
    *,
    calibrated_scenarios: set[str] | None = None,
    noise: float = 2.0,
    regression: float = -5.0,
    adoption: float = 5.0,
    minimum_pairs: int = 3,
    minimum_wins: int = 2,
    minimum_losses: int = 2,
    warmup_seconds: int = 3,
    active_seconds: int = 30,
) -> dict[str, object]:
    policy = copy.deepcopy(CONTROL.UNCALIBRATED_POLICY)
    policy["policy_id"] = "synthetic-test-calibration"
    calibrated_scenarios = calibrated_scenarios or set(CONTROL.SCENARIO_CATALOG)
    environment = {
        **CONTROL.MEASUREMENT_ENVIRONMENT,
        "warmup_seconds": warmup_seconds,
        "active_seconds": active_seconds,
    }
    for scenario in calibrated_scenarios:
        policy["scenarios"][scenario].update(
            {
                "noise_band_percent": noise,
                "regression_threshold_percent": regression,
                "adoption_threshold_percent": adoption,
                "minimum_pairs": minimum_pairs,
                "minimum_wins": minimum_wins,
                "minimum_losses": minimum_losses,
                "calibration_source": "artifact:synthetic-test-only",
                "calibration_environment": dict(environment),
            }
        )
    CONTROL.validate_decision_policy(policy)
    return policy


def synthetic_scale_sample(
    *, active: int, client_smaps: int, server_smaps: int, harness: int = 100
) -> dict[str, int]:
    return {
        "client_active": active,
        "server_active": active,
        "client_fds": 20 if active else 10,
        "server_fds": 20 if active else 10,
        "client_tasks": 8 if active else 4,
        "server_tasks": 8 if active else 4,
        "client_rss_kib": client_smaps,
        "server_rss_kib": server_smaps,
        "client_smaps_rss_kib": client_smaps,
        "server_smaps_rss_kib": server_smaps,
        "client_anonymous_kib": client_smaps,
        "server_anonymous_kib": server_smaps,
        "client_anon_huge_pages_kib": 0,
        "server_anon_huge_pages_kib": 0,
        "harness_rss_kib": harness,
    }


def synthetic_scale_row(
    *,
    pair: int,
    member: str,
    full_completions: int = 100,
    starve_first: bool = False,
    client_touch_extra_kib: int = 0,
    server_touch_extra_kib: int = 0,
) -> dict[str, object]:
    payload = CONTROL.SCALE_RECIPE["payload_bytes"]
    completions = [full_completions] * 10_000
    if starve_first:
        completions[0] = 0
    full_bytes = [value * payload for value in completions]
    partial_bytes = [payload] * 1_000
    full_checked = sum(full_bytes)
    full_completion_sum = sum(completions)
    elapsed = 30_000_000_000
    fairness_derived = CONTROL._recompute_scale_fairness(full_bytes)
    fairness = {
        field: fairness_derived[field] for field in CONTROL.SCALE_FAIRNESS_FIELDS
    }
    established = synthetic_scale_sample(
        active=10_000, client_smaps=2_000, server_smaps=3_000
    )
    touched = synthetic_scale_sample(
        active=10_000,
        client_smaps=3_000 + client_touch_extra_kib,
        server_smaps=4_000 + server_touch_extra_kib,
    )
    quiet = synthetic_scale_sample(active=0, client_smaps=1_000, server_smaps=1_500)
    client_increment = CONTROL._truncating_division(
        (1_000 + client_touch_extra_kib) * 1_024, 10_000
    )
    server_increment = CONTROL._truncating_division(
        (1_000 + server_touch_extra_kib) * 1_024, 10_000
    )
    partial_completions = 1_000
    touch_completions = 20_000
    scale = {
        "schema_version": 1,
        "recipe": dict(CONTROL.SCALE_RECIPE),
        "correctness": {
            "target_accepted": 10_000,
            "client_active": 10_000,
            "server_active": 10_000,
            "touch_completed_flows": 10_000,
            "touch_completed_round_trips": touch_completions,
            "touch_checked_bytes": touch_completions * payload,
            "payload_checks": touch_completions
            + partial_completions
            + full_completion_sum,
            "partial_nonzero_flows": 1_000,
            "full_nonzero_flows": sum(value != 0 for value in full_bytes),
            "application_tasks_joined": 10_000,
            "target_tasks_joined": 10_000,
            "drain": "PASS",
            "rebind": "PASS",
            "cleanup": "PASS",
        },
        "traffic": {
            "partial_checked_bytes": sum(partial_bytes),
            "partial_io_completions": partial_completions,
            "partial_discarded_tail_completions": 0,
            "partial_flow_bytes": partial_bytes,
            "full_checked_bytes": full_checked,
            "full_io_completions": full_completion_sum,
            "full_discarded_tail_completions": 0,
            "full_elapsed_nanoseconds": elapsed,
            "full_flow_bytes": full_bytes,
            "full_flow_completions": completions,
            "aggregate_bytes_per_second": full_checked * 1_000_000_000 // elapsed,
        },
        "fairness": fairness,
        "resource": {
            "pre_load": [dict(quiet)],
            "established": [dict(established) for _ in range(5)],
            "touched": [dict(touched) for _ in range(5)],
            "partial_active": [dict(touched) for _ in range(5)],
            "full_active": [dict(touched) for _ in range(5)],
            "post_full": [dict(touched) for _ in range(5)],
            "drained": [dict(quiet)],
            "client_touched_increment_bytes_per_connection": client_increment,
            "server_touched_increment_bytes_per_connection": server_increment,
            "combined_touched_increment_bytes_per_connection": client_increment
            + server_increment,
            "harness_peak_rss_kib": 100,
            "memory_available_kib": 16_000_000,
            "nofile_soft": 65_536,
        },
    }
    parent = "1" * 40
    candidate = "2" * 40
    is_parent = member == "parent"
    return {
        "schema_version": CONTROL.PROFILE_TRIAL_SCHEMA_VERSION,
        "kind": "m18_profile_trial",
        "parent_sha": parent,
        "candidate_sha": candidate,
        "member": member,
        "pair": pair,
        "order": 1 if (pair % 2 == 1) == is_parent else 2,
        "build_profile": "current",
        "scenario": CONTROL.SCALE_SCENARIO,
        "warmup_seconds": 10,
        "active_seconds": 30,
        "topology": "shadowsocks",
        "application_payload_bytes": payload,
        "socks_datagram_bytes": None,
        "upstream_wire_bytes": None,
        "sha": parent if is_parent else candidate,
        "tree": ("3" if is_parent else "4") * 40,
        "runner_sha256": "a" * 64,
        "client_sha256": ("b" if is_parent else "c") * 64,
        "server_sha256": ("d" if is_parent else "e") * 64,
        "rustc": "rustc 1.97.1 test",
        "kernel": "test-kernel",
        "cpu_model": "test-cpu",
        "cpu_count": 8,
        "memory_kib": 32_000_000,
        "metric": "bytes_per_second",
        "value": scale["traffic"]["aggregate_bytes_per_second"],
        "checked_units": full_checked,
        "p99_nanoseconds": None,
        "io_completions": full_completion_sum * 2,
        "scale": scale,
        "correctness": "PASS",
        "status": "PASS",
    }


def rewrite_scale_full_completions(
    row: dict[str, object], completions: list[int]
) -> None:
    if len(completions) != CONTROL.SCALE_RECIPE["sessions"]:
        raise AssertionError("scale completion fixture must cover all sessions")
    scale = row["scale"]
    traffic = scale["traffic"]
    correctness = scale["correctness"]
    payload = CONTROL.SCALE_RECIPE["payload_bytes"]
    full_bytes = [value * payload for value in completions]
    full_checked = sum(full_bytes)
    full_completion_sum = sum(completions)
    traffic["full_flow_bytes"] = full_bytes
    traffic["full_flow_completions"] = list(completions)
    traffic["full_checked_bytes"] = full_checked
    traffic["full_io_completions"] = full_completion_sum
    traffic["aggregate_bytes_per_second"] = (
        full_checked * 1_000_000_000 // traffic["full_elapsed_nanoseconds"]
    )
    fairness = CONTROL._recompute_scale_fairness(full_bytes)
    scale["fairness"] = {
        field: fairness[field] for field in CONTROL.SCALE_FAIRNESS_FIELDS
    }
    correctness["full_nonzero_flows"] = sum(value != 0 for value in full_bytes)
    correctness["payload_checks"] = (
        correctness["touch_completed_round_trips"]
        + traffic["partial_io_completions"]
        + traffic["partial_discarded_tail_completions"]
        + full_completion_sum
        + traffic["full_discarded_tail_completions"]
    )
    row["value"] = traffic["aggregate_bytes_per_second"]
    row["checked_units"] = full_checked
    row["io_completions"] = full_completion_sum * 2


def rewrite_scale_resource_increments(row: dict[str, object]) -> None:
    resource = row["scale"]["resource"]
    sessions = CONTROL.SCALE_RECIPE["sessions"]
    increments = {}
    for side in ("client", "server"):
        field = f"{side}_smaps_rss_kib"
        established = CONTROL._scale_stage_median(resource["established"], field)
        touched = CONTROL._scale_stage_median(resource["touched"], field)
        increments[side] = CONTROL._truncating_division(
            (touched - established) * 1_024, sessions
        )
        resource[f"{side}_touched_increment_bytes_per_connection"] = increments[
            side
        ]
    resource["combined_touched_increment_bytes_per_connection"] = (
        increments["client"] + increments["server"]
    )


def synthetic_scale_lineage() -> dict[str, object]:
    return {
        "schema_version": 1,
        "head_sha": "0" * 40,
        "head_tree": "4" * 40,
        "parent_sha": "1" * 40,
        "parent_tree": "3" * 40,
        "candidate_sha": "2" * 40,
        "candidate_tree": "4" * 40,
        "counterfactual_patch_sha256": "f" * 64,
        "runner_sha256": "a" * 64,
        "parent_client_sha256": "b" * 64,
        "parent_server_sha256": "d" * 64,
        "candidate_client_sha256": "c" * 64,
        "candidate_server_sha256": "e" * 64,
    }


class MeasurementInputTests(unittest.TestCase):
    def test_every_workflow_choice_is_valid(self) -> None:
        for warmup in ("1", "3", "5", "10"):
            for active in ("15", "30", "60"):
                for pairs in ("3", "5"):
                    self.assertEqual(
                        CONTROL.validate_measurement_inputs(warmup, active, pairs),
                        (int(warmup), int(active), int(pairs)),
                    )

    def test_each_measurement_input_rejects_invalid_values_independently(self) -> None:
        cases = (
            ("2", "15", "3", "warmup_seconds"),
            ("1", "45", "3", "active_seconds"),
            ("1", "15", "4", "pairs"),
            ("01", "15", "3", "warmup_seconds"),
            ("one", "15", "3", "warmup_seconds"),
        )
        for warmup, active, pairs, field in cases:
            with self.subTest(field=field, value=(warmup, active, pairs)):
                with self.assertRaisesRegex(CONTROL.CandidateControlError, field):
                    CONTROL.validate_measurement_inputs(warmup, active, pairs)


class ScenarioPlanTests(unittest.TestCase):
    def plan(self, mode: str, scenario: str) -> dict[str, object]:
        return CONTROL.create_plan(
            mode=mode,
            selection=scenario,
            warmup_seconds="3",
            active_seconds="30",
            pairs="3",
            decision_policy=copy.deepcopy(CONTROL.UNCALIBRATED_POLICY),
        )

    def entries(self, mode: str, scenario: str) -> list[tuple[str, str]]:
        return [
            (entry["scenario"], entry["role"])
            for entry in self.plan(mode, scenario)["scenarios"]
        ]

    def test_diagnostic_plan_contains_only_the_selected_scenario(self) -> None:
        for scenario in CONTROL.SCENARIO_CATALOG:
            with self.subTest(scenario=scenario):
                plan = self.plan("diagnostic", scenario)
                self.assertEqual(plan["schema_version"], CONTROL.PLAN_SCHEMA_VERSION)
                self.assertEqual(
                    self.entries("diagnostic", scenario),
                    [(scenario, "diagnostic")],
                )
                self.assertFalse(plan["adoption_eligible"])
                self.assertIsNone(
                    plan["decision_policy"]["scenarios"][scenario]["noise_band_percent"]
                )

    def test_tcp_throughput_qualification_adds_the_other_guard(self) -> None:
        self.assertEqual(
            self.entries("qualification", "tcp-stream-64k"),
            [("tcp-stream-64k", "primary"), ("tcp-bulk", "guard")],
        )
        self.assertEqual(
            self.entries("qualification", "tcp-bulk"),
            [("tcp-bulk", "primary"), ("tcp-stream-64k", "guard")],
        )

    def test_tcp_request_qualification_runs_all_requests_and_bulk_guard(self) -> None:
        entries = self.entries("qualification", "tcp-request-4k")
        self.assertEqual(entries[0], ("tcp-request-4k", "primary"))
        self.assertEqual(
            set(entries[1:]),
            {
                ("tcp-request-1k", "guard"),
                ("tcp-request-16k", "guard"),
                ("tcp-bulk", "guard"),
            },
        )

    def test_udp_qualification_runs_both_udp_scenarios(self) -> None:
        self.assertEqual(
            self.entries("qualification", "udp-small-high"),
            [("udp-small-high", "primary"), ("udp-mtu-1200", "guard")],
        )

    def test_udp_payload_matrix_records_exact_shadowsocks_bounds(self) -> None:
        plan = self.plan("qualification", "udp-payload-matrix")
        self.assertEqual(plan["scenario_group"], "udp-payload-matrix")
        self.assertIsNone(plan["selected_scenario"])
        self.assertEqual(
            [
                (
                    entry["scenario"],
                    entry["role"],
                    entry["topology"],
                    entry["application_payload_bytes"],
                    entry["socks_datagram_bytes"],
                    entry["upstream_wire_bytes"],
                )
                for entry in plan["scenarios"]
            ],
            [
                ("udp-small-high", "primary", "shadowsocks", 128, 138, 186),
                ("udp-mtu-1200", "guard", "shadowsocks", 1_200, 1_210, 1_258),
                ("udp-payload-1472", "guard", "shadowsocks", 1_472, 1_482, 1_530),
                ("udp-payload-1500", "guard", "shadowsocks", 1_500, 1_510, 1_558),
                ("udp-payload-8192", "guard", "shadowsocks", 8_192, 8_202, 8_250),
                ("udp-max-wire-65507", "guard", "shadowsocks", 65_449, 65_459, 65_507),
            ],
        )

    def test_udp_direct_group_proves_socks_ipv4_application_bound(self) -> None:
        plan = self.plan("qualification", "udp-direct-payload-bounds")
        self.assertEqual(plan["scenario_group"], "udp-direct-payload-bounds")
        self.assertIsNone(plan["selected_scenario"])
        self.assertEqual(
            [
                (
                    entry["scenario"],
                    entry["role"],
                    entry["topology"],
                    entry["application_payload_bytes"],
                    entry["socks_datagram_bytes"],
                    entry["upstream_wire_bytes"],
                )
                for entry in plan["scenarios"]
            ],
            [
                ("udp-direct-small-128", "primary", "direct", 128, 138, 128),
                ("udp-direct-max-65497", "guard", "direct", 65_497, 65_507, 65_497),
            ],
        )

    def test_tcp_frame_capacity_group_has_two_primaries_and_three_latency_guards(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-frame-capacity")
        self.assertEqual(plan["scenario_group"], "tcp-frame-capacity")
        self.assertIsNone(plan["selected_scenario"])
        self.assertEqual(
            [
                (entry["scenario"], entry["role"], entry["direction"])
                for entry in plan["scenarios"]
            ],
            [
                ("tcp-stream-64k", "primary", "higher_is_better"),
                ("tcp-bulk", "primary", "higher_is_better"),
                ("tcp-request-1k", "guard", "lower_is_better"),
                ("tcp-request-4k", "guard", "lower_is_better"),
                ("tcp-request-16k", "guard", "lower_is_better"),
            ],
        )
        self.assertTrue(all(entry["mandatory"] for entry in plan["scenarios"]))

    def test_invalid_mode_or_selection_and_diagnostic_group_are_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "mode"):
            self.plan("adopt", "tcp-bulk")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "selection"):
            self.plan("qualification", "tcp-unknown")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "diagnostic"):
            self.plan("diagnostic", "tcp-frame-capacity")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "diagnostic"):
            self.plan("diagnostic", "udp-payload-matrix")

    def test_only_named_windows_tun_lifecycle_profiles_are_qualification_only(
        self,
    ) -> None:
        for selection in (
            "windows-tun-network-reset-10",
            "windows-tun-network-reset-100",
            "windows-tun-network-reset-1000",
            "windows-tun-scheduler-ring-full",
        ):
            with self.subTest(selection=selection):
                with self.assertRaisesRegex(
                    CONTROL.CandidateControlError,
                    "lifecycle selection is qualification-only",
                ):
                    self.plan("qualification", selection)
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "selection"):
            self.plan("qualification", "windows-tun-route-detect")
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "dedicated windows-tun-plan"
        ):
            self.plan("qualification", CONTROL.WINDOWS_TUN_SELECTION)
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "selection"):
            self.plan("qualification", "windows-tun-unregistered")

    def test_workflow_exposes_only_controller_plannable_selections(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^      selection:\n.*?^        options:\n"
            r"(?P<options>(?:^          - [^\n]+\n)+)",
            workflow,
        )
        self.assertIsNotNone(match)
        assert match is not None
        choices = {
            line.removeprefix("          - ")
            for line in match.group("options").splitlines()
        }
        self.assertEqual(
            choices,
            set(CONTROL.SCENARIO_CATALOG)
            | set(CONTROL.QUALIFICATION_GROUPS)
            | {CONTROL.SCALE_SCENARIO},
        )


class WindowsTunPerformanceTests(unittest.TestCase):
    AA_SHA = "1" * 40
    PARENT_SHA = "2" * 40
    CANDIDATE_SHA = "3" * 40

    def policy(self, *, calibrated: bool = False) -> dict[str, object]:
        policy = CONTROL.load_windows_tun_policy(WINDOWS_TUN_POLICY_PATH)
        if not calibrated:
            return policy
        environment = {
            **CONTROL.WINDOWS_TUN_GUEST,
            "recipe_sha256": CONTROL.windows_tun_recipe_sha256(),
            "guest_build": "19045.6216",
            "cpu_model": "Synthetic CPU",
            "cpu_count": 8,
            "memory_bytes": 17_179_869_184,
            "power_plan_guid": "381b4222-f694-41f0-9685-ff5bb260df2e",
        }
        digest = "4" * 64
        for scenario in policy["scenarios"].values():
            for entry in scenario["metrics"].values():
                entry.update(
                    {
                        "noise_band_percent": 2.0,
                        "regression_threshold_percent": -5.0,
                        "adoption_threshold_percent": 5.0,
                        "minimum_pairs": 5,
                        "minimum_wins": 4,
                        "minimum_losses": 3,
                        "calibration_source": f"artifact:test-aa@sha256:{digest}",
                        "calibration_artifact_sha256": digest,
                        "calibration_environment": copy.deepcopy(environment),
                    }
                )
        CONTROL.validate_windows_tun_policy(policy)
        return policy

    def environment(self) -> dict[str, object]:
        return {
            **CONTROL.WINDOWS_TUN_GUEST,
            "guest_build": "19045.6216",
            "cpu_model": "Synthetic CPU",
            "cpu_count": 8,
            "memory_bytes": 17_179_869_184,
            "power_plan_guid": "381b4222-f694-41f0-9685-ff5bb260df2e",
        }

    @staticmethod
    def network_lifecycle_metrics(
        *, generation: int, reset_cycles: int, rebuild_cycles: int
    ) -> dict[str, int]:
        return {
            "network_generation": generation,
            "session_generation": generation,
            "network_reset_total": reset_cycles * 2,
            "network_reset_started": reset_cycles,
            "network_reset_succeeded": reset_cycles,
            "network_reset_failed": 0,
            "full_rebuild_total": rebuild_cycles * 2,
            "full_rebuild_started": rebuild_cycles,
            "full_rebuild_succeeded": rebuild_cycles,
            "full_rebuild_failed": 0,
        }

    def network_model_observation(
        self, *, row: dict[str, object]
    ) -> dict[str, object]:
        model = CONTROL.WINDOWS_TUN_NETWORK_MODEL
        resources = {
            "process_handles": 120,
            "process_threads": 12,
            "udp_associations_active": 0,
            "managed_adapters_active": 1,
        }
        cycles = []
        identity = "a" * 64
        for sequence in range(1, model.RESET_CYCLES + model.FULL_REBUILD_CYCLES + 1):
            reset = sequence <= model.RESET_CYCLES
            completed_resets = min(sequence - 1, model.RESET_CYCLES)
            completed_rebuilds = max(0, sequence - model.RESET_CYCLES - 1)
            metrics_before = self.network_lifecycle_metrics(
                generation=sequence,
                reset_cycles=completed_resets,
                rebuild_cycles=completed_rebuilds,
            )
            if reset:
                reason = (
                    "interface_change"
                    if sequence == model.INTERFACE_SWITCH_SEQUENCE
                    else "route_change"
                )
                operation = "reset_network"
                identity_after = identity
                elapsed = sequence * 1_000
                completed_resets += 1
            else:
                operation = "full_rebuild"
                reason = model.FULL_REBUILD_DAMAGE_REASON
                rebuild = sequence - model.RESET_CYCLES
                identity_after = f"{rebuild:064x}"
                elapsed = (10 + rebuild) * 1_000_000
                completed_rebuilds += 1
            metrics_after = self.network_lifecycle_metrics(
                generation=sequence + 1,
                reset_cycles=completed_resets,
                rebuild_cycles=completed_rebuilds,
            )
            udp_before = sequence % 16 + 1
            tcp_before = sequence % 8
            cycles.append(
                {
                    "sequence": sequence,
                    "operation": operation,
                    "reason": reason,
                    "elapsed_nanoseconds": elapsed,
                    "lifecycle_metrics_before": metrics_before,
                    "lifecycle_metrics_after": metrics_after,
                    "managed_identity_before": identity,
                    "managed_identity_after": identity_after,
                    "tcp_flows_before": tcp_before,
                    "udp_associations_before": udp_before,
                    "tcp_flows_closed": tcp_before,
                    "udp_associations_closed": udp_before,
                    "tcp_probe_succeeded": True,
                    "udp_probe_succeeded": True,
                    "resources_after": dict(resources),
                }
            )
            identity = identity_after
        reference = row["network_model_evidence"]
        environment = row["environment"]
        return {
            "schema_version": model.SCHEMA_VERSION,
            "workload": model.LIFECYCLE_WORKLOAD,
            "identity": {
                "run_kind": row["run_kind"],
                "member": row["member"],
                "pair": row["pair"],
                "trial_sequence": row["sequence"],
                "client_pid": 1234,
                "server_pid": 1235,
                "vm_name": environment["vm_name"],
                "vm_id": environment["vm_id"],
                "checkpoint_name": environment["checkpoint_name"],
                "checkpoint_id": environment["checkpoint_id"],
                "sha": row["sha"],
                "tree": row["tree"],
                "client_sha256": row["client_sha256"],
                "server_sha256": row["server_sha256"],
                "harness_sha256": row["harness_sha256"],
                "collector_sha256": reference["collector_sha256"],
                "recipe_sha256": row["recipe_sha256"],
                "model_controller_sha256": reference["controller_sha256"],
                "model_plan_sha256": reference["plan_sha256"],
            },
            "baseline_resources": dict(resources),
            "cycles": cycles,
            "interface_resolver": {
                "probes": model.INTERFACE_RESOLVER_PROBES,
                "resolutions": model.INTERFACE_RESOLVER_PROBES * 2,
                "cache_hits": model.INTERFACE_RESOLVER_PROBES * 2 - 2,
            },
        }

    def route_once_observation(self, *, row: dict[str, object]) -> dict[str, object]:
        model = CONTROL.WINDOWS_TUN_NETWORK_MODEL
        reference = row["network_model_evidence"]
        environment = row["environment"]
        generations = []
        for ordinal in range(1, model.ROUTE_GENERATIONS + 1):
            associations = []
            for source_slot in range(model.ROUTE_SOURCE_SLOTS):
                datagrams = model.ROUTE_TARGET_SLOTS * model.ROUTE_DATAGRAMS_PER_TARGET
                associations.append(
                    {
                        "source_slot": source_slot,
                        "target_slots": list(range(model.ROUTE_TARGET_SLOTS)),
                        "first_target_slot": 0 if source_slot % 2 == 0 else 1,
                        "datagrams_sent": datagrams,
                        "replies_received": datagrams,
                    }
                )
            path_datagrams = model.ROUTE_SOURCE_SLOTS // 2 * datagrams
            generations.append(
                {
                    "ordinal": ordinal,
                    "network_generation": 10 + ordinal,
                    "session_generation": 10 + ordinal,
                    "direct_datagrams_observed": path_datagrams,
                    "direct_replies_observed": path_datagrams,
                    "proxy_datagrams_observed": path_datagrams,
                    "proxy_replies_observed": path_datagrams,
                    "associations": associations,
                }
            )
        associations_created = model.ROUTE_GENERATIONS * model.ROUTE_SOURCE_SLOTS
        return {
            "schema_version": model.SCHEMA_VERSION,
            "workload": model.ROUTE_ONCE_WORKLOAD,
            "identity": {
                "run_kind": row["run_kind"],
                "member": row["member"],
                "pair": row["pair"],
                "trial_sequence": row["sequence"],
                "client_pid": 1234,
                "server_pid": 1235,
                "vm_name": environment["vm_name"],
                "vm_id": environment["vm_id"],
                "checkpoint_name": environment["checkpoint_name"],
                "checkpoint_id": environment["checkpoint_id"],
                "sha": row["sha"],
                "tree": row["tree"],
                "client_sha256": row["client_sha256"],
                "server_sha256": row["server_sha256"],
                "harness_sha256": row["harness_sha256"],
                "collector_sha256": reference["collector_sha256"],
                "recipe_sha256": row["recipe_sha256"],
                "model_controller_sha256": reference["controller_sha256"],
                "model_plan_sha256": reference["plan_sha256"],
            },
            "elapsed_nanoseconds": 1_000_000_000,
            "association_creation_elapsed_nanoseconds": 500_000_000,
            "association_creations_observed": associations_created,
            "router_invocations_observed": associations_created,
            "generations": generations,
        }

    def row(
        self,
        *,
        plan: dict[str, object],
        scenario: str,
        pair: int,
        member: str,
        parent_sha: str,
        candidate_sha: str,
        regression: bool = False,
    ) -> dict[str, object]:
        contract = CONTROL.WINDOWS_TUN_SCENARIOS[scenario]
        planned = [
            trial
            for trial in plan["trials"]
            if trial["scenario"] == scenario
            and trial["pair"] == pair
            and trial["member"] == member
        ]
        self.assertEqual(len(planned), 1)
        order = planned[0]["order"]
        sequence = planned[0]["sequence"]
        started = datetime(2026, 8, 22, tzinfo=timezone.utc) + timedelta(
            seconds=sequence * 2
        )
        finished = started + timedelta(seconds=1)
        canonical_utc = lambda value: value.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        measurements = {}
        for metric, metric_contract in contract["metrics"].items():
            value = 1_000
            if regression and member == "candidate":
                value = (
                    900
                    if metric_contract["direction"] == "higher_is_better"
                    else 1_100
                )
            measurements[metric] = {
                "unit": metric_contract["unit"],
                "value": value,
            }
        member_sha = parent_sha if member == "parent" else candidate_sha
        aa = parent_sha == candidate_sha
        identity_digit = "5" if aa or member == "parent" else "6"
        row = {
            "schema_version": CONTROL.WINDOWS_TUN_TRIAL_SCHEMA_VERSION,
            "kind": "windows_tun_performance_trial",
            "selection": CONTROL.WINDOWS_TUN_SELECTION,
            "run_kind": plan["run_kind"],
            "scenario": scenario,
            "member": member,
            "pair": pair,
            "order": order,
            "sequence": sequence,
            "started_utc": canonical_utc(started),
            "finished_utc": canonical_utc(finished),
            "parent_sha": parent_sha,
            "candidate_sha": candidate_sha,
            "sha": member_sha,
            "tree": identity_digit * 40,
            "client_sha256": identity_digit * 64,
            "server_sha256": identity_digit * 64,
            "harness_sha256": "7" * 64,
            "recipe_sha256": plan["recipe_sha256"],
            "environment": self.environment(),
            "measurements": measurements,
            "correctness": {
                "status": "PASS",
                "checked_unit": contract["checked_unit"],
                "checked_units": contract["minimum_checked_units"],
                "checks": {
                    check: True for check in contract["correctness_checks"]
                },
            },
            "diagnostics": None,
            "network_model_evidence": None,
            "status": "PASS",
        }
        if scenario == "fragment-reassembly-throughput":
            active_unique = row["correctness"]["checked_units"]
            warmup_unique = 8
            retransmissions = 1
            total_unique = warmup_unique + active_unique
            total_request_attempts = total_unique + retransmissions
            expected_fragment_packets = total_request_attempts * 2
            background_family_disabled = 2
            background_invalid_destination = 1
            background_packets = (
                background_family_disabled + background_invalid_destination
            )
            row["diagnostics"] = {
                "schema_version": 2,
                "kind": "fragment_ack_accounting",
                "batch_datagrams": 8,
                "ack_window_milliseconds": 500,
                "max_missing_per_batch": 1,
                "max_retransmissions_per_sequence": 1,
                "retry_budget_unique_datagrams": 1_000_000,
                "minimum_retry_budget": 1,
                "retry_scope": "missing-sequence-only",
                "accounting": {
                    "warmup_unique_datagrams": warmup_unique,
                    "warmup_request_attempts": warmup_unique,
                    "active_unique_datagrams": active_unique,
                    "active_request_attempts": active_unique + retransmissions,
                    "total_unique_datagrams": total_unique,
                    "total_request_attempts": total_request_attempts,
                    "retransmissions": retransmissions,
                    "ack_window_expirations": retransmissions,
                    "duplicate_or_stale_acks": 0,
                    "retry_budget": 1,
                },
                "packet_counter_deltas": {
                    "accepted_packets": expected_fragment_packets,
                    "ingress_packets": expected_fragment_packets
                    + background_packets,
                    "background_family_disabled": background_family_disabled,
                    "background_invalid_destination": (
                        background_invalid_destination
                    ),
                    "background_packets": background_packets,
                },
                "adapter_counter_deltas": {
                    "ReceivedUnicastPackets": total_request_attempts,
                    "ReceivedDiscardedPackets": 0,
                    "ReceivedPacketErrors": 0,
                    "SentUnicastPackets": expected_fragment_packets
                    + background_packets,
                    "OutboundDiscardedPackets": 0,
                    "OutboundPacketErrors": 0,
                },
            }
        if scenario in {"udp-route-once", "network-lifecycle"}:
            row["network_model_evidence"] = {
                "schema_version": 1,
                "controller_sha256": CONTROL.WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256,
                "collector_sha256": "8" * 64,
                "plan_sha256": CONTROL.WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256,
                "observation_file": (
                    f"{sequence:03d}-{scenario}-{member}-pair-{pair}.network-model.json"
                ),
                "observation_sha256": "9" * 64,
            }
            if scenario == "udp-route-once":
                summary = CONTROL.WINDOWS_TUN_NETWORK_MODEL.summarize_route_once_observation(
                    self.route_once_observation(row=row)
                )
                values = CONTROL._route_once_trial_values(summary)
                row["correctness"]["checked_units"] = summary["datagrams_sent"]
                row["correctness"]["checks"] = {
                    "every_reply_accounted": True,
                    "payload_exact": True,
                    "direct_and_proxy_sources": True,
                    "association_creation_counter_exact": True,
                    "router_invocation_counter_exact": True,
                    "post_reset_reroute_verified": True,
                    "network_model_evidence_bound": True,
                    "tun_path_observed": True,
                    "clean_drain": True,
                }
            else:
                summary = CONTROL.WINDOWS_TUN_NETWORK_MODEL.summarize_lifecycle_observation(
                    self.network_model_observation(row=row)
                )
                values = CONTROL._network_model_trial_values(summary)
            for metric, value in values.items():
                row["measurements"][metric]["value"] = value
            if scenario == "network-lifecycle":
                row["correctness"]["checks"] = {
                    "same_process_all_cycles": True,
                    "generation_advanced_once_per_cycle": True,
                    "managed_identity_preserved_across_resets": True,
                    "damage_only_full_rebuild": True,
                    "reset_and_full_rebuild_metrics_are_exact": True,
                    "resource_growth_zero_after_1000_resets": True,
                    "tcp_and_udp_recovered_after_interface_switch": True,
                    "interface_resolver_cache_hit_observed": True,
                    "network_model_evidence_bound": True,
                    "tun_path_observed": True,
                    "clean_drain": True,
                }
        return row

    def evidence(
        self,
        root: pathlib.Path,
        *,
        plan: dict[str, object],
        parent_sha: str,
        candidate_sha: str,
        regression: bool = False,
    ) -> None:
        model_root = root / "network-model"
        model_root.mkdir()
        for trial in plan["trials"]:
            row = self.row(
                plan=plan,
                scenario=trial["scenario"],
                pair=trial["pair"],
                member=trial["member"],
                parent_sha=parent_sha,
                candidate_sha=candidate_sha,
                regression=regression,
            )
            if row["scenario"] in {"udp-route-once", "network-lifecycle"}:
                observation = (
                    self.route_once_observation(row=row)
                    if row["scenario"] == "udp-route-once"
                    else self.network_model_observation(row=row)
                )
                encoded = json.dumps(observation, sort_keys=True).encode("utf-8")
                reference = row["network_model_evidence"]
                reference["observation_sha256"] = hashlib.sha256(encoded).hexdigest()
                (model_root / reference["observation_file"]).write_bytes(encoded)
            path = root / (
                f"{trial['scenario']}-{trial['pair']}-{trial['member']}.json"
            )
            path.write_text(json.dumps(row), encoding="utf-8")

    def test_repository_policy_and_plan_are_closed_and_uncalibrated(self) -> None:
        policy = self.policy()
        self.assertFalse(CONTROL.windows_tun_policy_is_calibrated(policy))
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=policy
        )
        self.assertEqual(CONTROL.WINDOWS_TUN_TRIAL_SCHEMA_VERSION, 3)
        self.assertEqual(set(plan["scenarios"]), set(CONTROL.WINDOWS_TUN_SCENARIOS))
        self.assertEqual(len(plan["scenarios"]), 9)
        self.assertEqual(
            sum(len(contract["metrics"]) for contract in plan["scenarios"].values()),
            22,
        )
        self.assertEqual(len(plan["trials"]), 90)
        self.assertFalse(plan["calibration_complete"])
        self.assertFalse(plan["adoption_eligible"])
        self.assertEqual(
            {
                scenario: contract["recipe"]["topology"]
                for scenario, contract in plan["scenarios"].items()
            },
            {
                "tcp-single-flow": "tun-shadowsocks-external-echo",
                "tcp-256-flow-fairness": "tun-shadowsocks-external-echo",
                "udp-packets-per-second": "tun-direct-external-echo",
                "udp-8192-association-lookup-expiry": "tun-direct-external-echo",
                "fragment-reassembly-throughput": (
                    "tun-direct-external-fragment-ack"
                ),
                "idle-cpu-wakeup": "tun-idle-no-traffic",
                "wintun-ring-full-drop-rate": "tun-direct-external-echo",
                "udp-route-once": "tun-mixed-direct-shadowsocks-external-echo",
                "network-lifecycle": "tun-mixed-direct-shadowsocks-external-echo",
            },
        )
        udp_packet_recipe = plan["scenarios"]["udp-packets-per-second"]["recipe"]
        self.assertEqual(
            (
                udp_packet_recipe["batch_datagrams"],
                udp_packet_recipe["tun_udp_datagram_queue_packets"],
                udp_packet_recipe[
                    "tun_udp_response_queue_packets_per_association"
                ],
            ),
            (8, 8, 8),
        )
        fragment_recipe = plan["scenarios"]["fragment-reassembly-throughput"][
            "recipe"
        ]
        self.assertEqual(
            (
                fragment_recipe["tun_mtu_bytes"],
                fragment_recipe["support_underlay_minimum_ipv4_packet_bytes"],
                fragment_recipe["fragments_per_datagram"],
                fragment_recipe["batch_datagrams"],
                fragment_recipe["payload_bytes"],
                fragment_recipe["tun_ring_capacity_bytes"],
                fragment_recipe["tun_tcp_buffer_bytes"],
                fragment_recipe["client_runtime_idle_timeout_milliseconds"],
            ),
            (1_420, 1_468, 2, 8, 1_440, 8_388_608, 32_768, 60_000),
        )
        self.assertEqual(
            fragment_recipe["runner_source_sha256"],
            hashlib.sha256(CONTROL.WINDOWS_TUN_RUNNER_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            fragment_recipe["preflight_probe"],
            {
                "tcp_payload_bytes": 1_024,
                "udp_payload_bytes": 1_024,
                "udp_target_slots": 4,
                "fragment_payload_bytes": 1_440,
                "fragment_datagrams": 1,
                "fragment_ack_bytes": 24,
            },
        )
        self.assertEqual(
            {
                field: fragment_recipe[field]
                for field in (
                    "batch_datagrams",
                    "ack_window_milliseconds",
                    "max_missing_per_batch",
                    "max_retransmissions_per_sequence",
                    "retry_budget_unique_datagrams",
                    "minimum_retry_budget",
                    "retry_scope",
                )
            },
            {
                "batch_datagrams": 8,
                "ack_window_milliseconds": 500,
                "max_missing_per_batch": 1,
                "max_retransmissions_per_sequence": 1,
                "retry_budget_unique_datagrams": 1_000_000,
                "minimum_retry_budget": 1,
                "retry_scope": "missing-sequence-only",
            },
        )
        self.assertTrue(
            {
                "no_gso",
                "all_sequences_acknowledged",
                "bounded_retransmissions",
                "no_adapter_packet_loss",
            }.issubset(
                plan["scenarios"]["fragment-reassembly-throughput"][
                    "correctness_checks"
                ]
            )
        )
        association_recipe = plan["scenarios"][
            "udp-8192-association-lookup-expiry"
        ]["recipe"]
        self.assertEqual(
            (
                association_recipe["associations"],
                association_recipe["bootstrap_batch_associations"],
                association_recipe["batch_associations"],
                association_recipe["lookup_rounds"],
                association_recipe["payload_bytes"],
                association_recipe["tun_max_udp_mappings"],
                association_recipe["tun_udp_datagram_queue_packets"],
                association_recipe[
                    "tun_udp_response_queue_packets_per_association"
                ],
            ),
            (8_192, 1, 8, 64, 32, 8_192, 8, 8),
        )
        fairness = plan["scenarios"]["tcp-256-flow-fairness"]
        self.assertEqual(
            (
                fairness["recipe"]["connection_readiness"],
                fairness["recipe"]["readiness_payload_bytes"],
                fairness["recipe"]["support_tcp_idle_timeout_milliseconds"],
            ),
            ("sequential_exact_round_trip", 1_024, 120_000),
        )
        self.assertIn(
            "all_256_flows_ready", fairness["correctness_checks"]
        )
        self.assertEqual(
            plan["scenarios"]["wintun-ring-full-drop-rate"]["recipe"]
            ["payload_bytes"],
            1_200,
        )
        route_once = plan["scenarios"]["udp-route-once"]
        self.assertEqual(
            set(route_once["metrics"]),
            {
                "multi_target_packet_rate",
                "association_creation_rate",
                "router_invocations_avoided",
            },
        )
        self.assertEqual(
            (
                route_once["recipe"]["generations"],
                route_once["recipe"]["source_slots"],
                route_once["recipe"]["target_slots"],
                route_once["recipe"]["datagrams_per_target"],
            ),
            (2, 64, 4, 32),
        )
        self.assertEqual(
            plan["scenarios"]["wintun-ring-full-drop-rate"]["metrics"]
            ["pending_response_peak"],
            {"unit": "pending_udp_responses", "direction": "lower_is_better"},
        )
        for scenario, contract in plan["scenarios"].items():
            with self.subTest(scenario=scenario):
                for field, value in CONTROL.WINDOWS_TUN_RUNTIME_RECIPE.items():
                    self.assertEqual(contract["recipe"][field], value)
                if scenario != "idle-cpu-wakeup":
                    self.assertIn(
                        "tun_path_observed", contract["correctness_checks"]
                    )
        for sequence, trial in enumerate(plan["trials"], start=1):
            self.assertEqual(trial["sequence"], sequence)
            expected = 1 if (
                (trial["member"] == "parent") == (trial["pair"] % 2 == 1)
            ) else 2
            self.assertEqual(trial["order"], expected)
        scheduled_scenarios = [
            plan["trials"][index * CONTROL.WINDOWS_TUN_PAIR_COUNT * 2]["scenario"]
            for index in range(len(CONTROL.WINDOWS_TUN_SCENARIOS))
        ]
        self.assertEqual(
            scheduled_scenarios,
            list(CONTROL.WINDOWS_TUN_SCENARIOS),
            "canonical JSON key sorting must not reorder trial execution",
        )
        self.assertEqual(
            [
                (
                    trial["sequence"],
                    trial["member"],
                    trial["pair"],
                    trial["order"],
                )
                for trial in plan["trials"]
                if trial["scenario"] == "fragment-reassembly-throughput"
            ][:2],
            [(41, "parent", 1, 1), (42, "candidate", 1, 2)],
        )

    def test_serialized_windows_tun_plan_preserves_the_trial_schedule(self) -> None:
        policy = self.policy()
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=policy
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "plan.json"
            path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
            loaded = CONTROL.load_windows_tun_plan(path, decision_policy=policy)
            for sequence in (True, 1.0, "1"):
                with self.subTest(sequence=sequence):
                    tampered = copy.deepcopy(plan)
                    tampered["trials"][0]["sequence"] = sequence
                    path.write_text(
                        json.dumps(tampered, sort_keys=True), encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        CONTROL.CandidateControlError, "canonical recipe"
                    ):
                        CONTROL.load_windows_tun_plan(
                            path, decision_policy=policy
                        )
        self.assertEqual(loaded["trials"], plan["trials"])
        self.assertEqual(loaded["trials"][40]["sequence"], 41)
        self.assertEqual(
            loaded["trials"][40]["scenario"],
            "fragment-reassembly-throughput",
        )

    def test_policy_rejects_partial_or_unbound_calibration(self) -> None:
        policy = self.policy()
        first_scenario = next(iter(policy["scenarios"].values()))
        first_metric = next(iter(first_scenario["metrics"].values()))
        first_metric["noise_band_percent"] = 2.0
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "complete or entirely null"
        ):
            CONTROL.validate_windows_tun_policy(policy)
        calibrated = self.policy(calibrated=True)
        first_scenario = next(iter(calibrated["scenarios"].values()))
        first_metric = next(iter(first_scenario["metrics"].values()))
        first_metric["calibration_artifact_sha256"] = "8" * 64
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "bind one SHA-256"
        ):
            CONTROL.validate_windows_tun_policy(calibrated)

    def test_aa_evidence_produces_separate_non_adoptable_calibration_artifact(
        self,
    ) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="calibration-aa", decision_policy=self.policy()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.AA_SHA,
                candidate_sha=self.AA_SHA,
            )
            summary = CONTROL.summarize_windows_tun_evidence(
                plan=plan,
                evidence_root=root,
                parent_sha=self.AA_SHA,
                candidate_sha=self.AA_SHA,
            )
        self.assertEqual(summary["status"], "CALIBRATION_EVIDENCE")
        self.assertFalse(summary["adoption_eligible"])
        artifact = CONTROL.windows_tun_calibration_artifact(summary)
        self.assertFalse(artifact["adoption_eligible"])
        self.assertFalse(artifact["thresholds_reviewed"])
        self.assertRegex(artifact["content_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(artifact["observations"]), set(CONTROL.WINDOWS_TUN_SCENARIOS))
        self.assertEqual(len(artifact["evidence_files"]), 110)
        self.assertEqual(
            artifact["network_model"]["raw_observations"],
            CONTROL.WINDOWS_TUN_PAIR_COUNT * 2 * 2,
        )

    def test_uncalibrated_comparison_is_fail_closed(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            summary = CONTROL.summarize_windows_tun_evidence(
                plan=plan,
                evidence_root=root,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(summary["adoption_eligible"])
        self.assertTrue(summary["correctness_complete"])

    def test_uncalibrated_comparison_cli_returns_non_success(self) -> None:
        policy = self.policy()
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=policy
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            self.evidence(
                evidence,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            plan_path = root / "plan.json"
            output = root / "summary.json"
            markdown = root / "summary.md"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            status = CONTROL.main(
                [
                    "windows-tun-summarize",
                    "--plan",
                    str(plan_path),
                    "--evidence-root",
                    str(evidence),
                    "--parent-sha",
                    self.PARENT_SHA,
                    "--candidate-sha",
                    self.CANDIDATE_SHA,
                    "--policy",
                    str(WINDOWS_TUN_POLICY_PATH),
                    "--output",
                    str(output),
                    "--markdown",
                    str(markdown),
                ]
            )
            summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 4)
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(summary["adoption_eligible"])

    def test_evidence_rejects_claimed_order_when_trials_overlap(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            second = root / "tcp-single-flow-1-candidate.json"
            row = json.loads(second.read_text(encoding="utf-8"))
            row["started_utc"] = "2026-08-22T00:00:02.5000000Z"
            second.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(
                CONTROL.CandidateControlError, "overlap.*planned order"
            ):
                CONTROL.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )

    def test_lifecycle_sidecar_is_hash_bound_and_reduced_from_raw_cycles(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            trial_path = root / "network-lifecycle-1-parent.json"
            row = json.loads(trial_path.read_text(encoding="utf-8"))
            observation_path = (
                root
                / "network-model"
                / row["network_model_evidence"]["observation_file"]
            )
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            observation["cycles"][499]["elapsed_nanoseconds"] += 1
            encoded = json.dumps(observation, sort_keys=True).encode("utf-8")
            observation_path.write_bytes(encoded)
            row["network_model_evidence"]["observation_sha256"] = hashlib.sha256(
                encoded
            ).hexdigest()
            trial_path.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(
                CONTROL.CandidateControlError, "not recomputed from raw evidence"
            ):
                CONTROL.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )

    def test_route_once_sidecar_is_hash_bound_and_reduced_from_raw_counters(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            trial_path = root / "udp-route-once-1-parent.json"
            row = json.loads(trial_path.read_text(encoding="utf-8"))
            observation_path = (
                root
                / "network-model"
                / row["network_model_evidence"]["observation_file"]
            )
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            observation["elapsed_nanoseconds"] += 1
            encoded = json.dumps(observation, sort_keys=True).encode("utf-8")
            observation_path.write_bytes(encoded)
            row["network_model_evidence"]["observation_sha256"] = hashlib.sha256(
                encoded
            ).hexdigest()
            trial_path.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(
                CONTROL.CandidateControlError, "route-once measurements were not recomputed"
            ):
                CONTROL.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )

    def test_calibrated_comparison_detects_clear_and_regression(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(calibrated=True)
        )
        self.assertTrue(plan["calibration_complete"])
        self.assertFalse(plan["adoption_eligible"])
        for regression, expected, eligible in (
            (False, "NO_REGRESSION", True),
            (True, "REGRESSION", False),
        ):
            with self.subTest(regression=regression), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                self.evidence(
                    root,
                    plan=plan,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                    regression=regression,
                )
                summary = CONTROL.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )
                self.assertEqual(summary["status"], expected)
                self.assertEqual(summary["adoption_eligible"], eligible)

    def test_trial_rejects_unit_correctness_and_order_tampering(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        cases = []
        wrong_unit = copy.deepcopy(row)
        wrong_unit["measurements"]["throughput"]["unit"] = "bits_per_second"
        cases.append((wrong_unit, "unit mismatch"))
        wrong_check = copy.deepcopy(row)
        wrong_check["correctness"]["checks"]["payload_exact"] = False
        cases.append((wrong_check, "correctness check failed"))
        wrong_order = copy.deepcopy(row)
        wrong_order["order"] = 2
        cases.append((wrong_order, "alternating"))
        wrong_sequence = copy.deepcopy(row)
        wrong_sequence["sequence"] = 2
        cases.append((wrong_sequence, "planned sequence"))
        for candidate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CONTROL.CandidateControlError, message):
                    CONTROL.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_trial_sequence_is_strictly_typed_and_uniquely_plan_bound(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        for value in (True, 1.0, "1", 0, 91):
            with self.subTest(sequence=value):
                candidate = copy.deepcopy(row)
                candidate["sequence"] = value
                with self.assertRaisesRegex(
                    CONTROL.CandidateControlError, "sequence"
                ):
                    CONTROL.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

        for name, mutate in (
            (
                "scenario",
                lambda value: value.update(scenario="tcp-256-flow-fairness"),
            ),
            (
                "pair-member-order",
                lambda value: value.update(pair=2, member="candidate", order=1),
            ),
        ):
            with self.subTest(identity=name):
                candidate = copy.deepcopy(row)
                mutate(candidate)
                with self.assertRaisesRegex(
                    CONTROL.CandidateControlError, "planned sequence"
                ):
                    CONTROL.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

        for name, index, replacement in (
            ("duplicate", 1, 1),
            ("missing", 0, 90),
        ):
            with self.subTest(plan_sequence=name):
                tampered_plan = copy.deepcopy(plan)
                tampered_plan["trials"][index]["sequence"] = replacement
                with self.assertRaisesRegex(
                    CONTROL.CandidateControlError,
                    "sequence does not uniquely match the plan",
                ):
                    CONTROL.validate_windows_tun_trial(
                        row,
                        plan=tampered_plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

        for field, value in (("pair", True), ("order", 1.0)):
            with self.subTest(plan_identity=field):
                tampered_plan = copy.deepcopy(plan)
                tampered_plan["trials"][0][field] = value
                with self.assertRaisesRegex(
                    CONTROL.CandidateControlError,
                    "planned trial identity is invalid",
                ):
                    CONTROL.validate_windows_tun_trial(
                        row,
                        plan=tampered_plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_fragment_diagnostics_are_required_and_scenario_scoped(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        fragment = self.row(
            plan=plan,
            scenario="fragment-reassembly-throughput",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        CONTROL.validate_windows_tun_trial(
            fragment,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        missing = copy.deepcopy(fragment)
        missing["diagnostics"] = None
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "diagnostics must be an object"
        ):
            CONTROL.validate_windows_tun_trial(
                missing,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

        non_fragment = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        non_fragment["diagnostics"] = copy.deepcopy(fragment["diagnostics"])
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "non-fragment.*must be null"
        ):
            CONTROL.validate_windows_tun_trial(
                non_fragment,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

    def test_fragment_diagnostics_reject_closed_schema_and_accounting_tampering(
        self,
    ) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        row = self.row(
            plan=plan,
            scenario="fragment-reassembly-throughput",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        cases = []

        extra_field = copy.deepcopy(row)
        extra_field["diagnostics"]["unexpected"] = 0
        cases.append((extra_field, "fragment diagnostics schema mismatch"))

        packet_container_missing = copy.deepcopy(row)
        packet_container_missing["diagnostics"].pop("packet_counter_deltas")
        cases.append(
            (packet_container_missing, "fragment diagnostics schema mismatch")
        )

        wrong_schema = copy.deepcopy(row)
        wrong_schema["diagnostics"]["schema_version"] = 1
        cases.append((wrong_schema, "schema_version is unsupported"))

        wrong_kind = copy.deepcopy(row)
        wrong_kind["diagnostics"]["kind"] = "fragment_ack_summary"
        cases.append((wrong_kind, "diagnostics kind is invalid"))

        accounting_extra = copy.deepcopy(row)
        accounting_extra["diagnostics"]["accounting"]["unexpected"] = 0
        cases.append((accounting_extra, "diagnostics accounting schema mismatch"))

        packet_missing = copy.deepcopy(row)
        packet_missing["diagnostics"]["packet_counter_deltas"].pop(
            "background_invalid_destination"
        )
        cases.append((packet_missing, "packet counter deltas schema mismatch"))

        packet_extra = copy.deepcopy(row)
        packet_extra["diagnostics"]["packet_counter_deltas"]["unexpected"] = 0
        cases.append((packet_extra, "packet counter deltas schema mismatch"))

        packet_not_object = copy.deepcopy(row)
        packet_not_object["diagnostics"]["packet_counter_deltas"] = []
        cases.append((packet_not_object, "packet counter deltas must be an object"))

        packet_boolean = copy.deepcopy(row)
        packet_boolean["diagnostics"]["packet_counter_deltas"][
            "background_packets"
        ] = False
        cases.append((packet_boolean, "non-negative u64"))

        adapter_missing = copy.deepcopy(row)
        adapter_missing["diagnostics"]["adapter_counter_deltas"].pop(
            "OutboundPacketErrors"
        )
        cases.append((adapter_missing, "adapter counter deltas schema mismatch"))

        wrong_recipe = copy.deepcopy(row)
        wrong_recipe["diagnostics"]["ack_window_milliseconds"] = 501
        cases.append((wrong_recipe, "does not match the recipe"))

        wrong_batch = copy.deepcopy(row)
        wrong_batch["diagnostics"]["batch_datagrams"] = 7
        cases.append((wrong_batch, "does not match the recipe"))

        negative = copy.deepcopy(row)
        negative["diagnostics"]["accounting"]["retransmissions"] = -1
        cases.append((negative, "non-negative u64"))

        boolean = copy.deepcopy(row)
        boolean["diagnostics"]["accounting"]["duplicate_or_stale_acks"] = False
        cases.append((boolean, "non-negative u64"))

        zero_warmup = copy.deepcopy(row)
        zero_accounting = zero_warmup["diagnostics"]["accounting"]
        zero_accounting["warmup_unique_datagrams"] = 0
        zero_accounting["warmup_request_attempts"] = 0
        zero_accounting["total_unique_datagrams"] = zero_accounting[
            "active_unique_datagrams"
        ]
        zero_accounting["total_request_attempts"] = zero_accounting[
            "active_request_attempts"
        ]
        cases.append((zero_warmup, "warmup_unique_datagrams must be positive"))

        misaligned = copy.deepcopy(row)
        misaligned_accounting = misaligned["diagnostics"]["accounting"]
        misaligned_accounting["warmup_unique_datagrams"] += 1
        misaligned_accounting["warmup_request_attempts"] += 1
        misaligned_accounting["total_unique_datagrams"] += 1
        misaligned_accounting["total_request_attempts"] += 1
        cases.append((misaligned, "warmup_unique_datagrams is not batch-aligned"))

        active_mismatch = copy.deepcopy(row)
        active_mismatch["diagnostics"]["accounting"][
            "active_unique_datagrams"
        ] += 8
        cases.append((active_mismatch, "active unique count"))

        phase_attempts = copy.deepcopy(row)
        phase_attempts["diagnostics"]["accounting"][
            "active_request_attempts"
        ] = 0
        cases.append((phase_attempts, "active attempts are below"))

        total_unique = copy.deepcopy(row)
        total_unique["diagnostics"]["accounting"]["total_unique_datagrams"] += 8
        cases.append((total_unique, "total unique count"))

        total_attempts = copy.deepcopy(row)
        total_attempts["diagnostics"]["accounting"][
            "total_request_attempts"
        ] += 1
        cases.append((total_attempts, "total attempt count"))

        retransmissions = copy.deepcopy(row)
        retransmissions["diagnostics"]["accounting"]["retransmissions"] = 0
        cases.append((retransmissions, "retransmission count"))

        expirations = copy.deepcopy(row)
        expirations["diagnostics"]["accounting"]["ack_window_expirations"] = 0
        cases.append((expirations, "ACK-window expiration count"))

        duplicate_acks = copy.deepcopy(row)
        duplicate_acks["diagnostics"]["accounting"][
            "duplicate_or_stale_acks"
        ] = 2
        cases.append((duplicate_acks, "duplicate/stale ACK count"))

        wrong_budget = copy.deepcopy(row)
        wrong_budget["diagnostics"]["accounting"]["retry_budget"] = 2
        cases.append((wrong_budget, "retry budget is inconsistent"))

        exceeded_budget = copy.deepcopy(row)
        exceeded_accounting = exceeded_budget["diagnostics"]["accounting"]
        exceeded_accounting["active_request_attempts"] += 1
        exceeded_accounting["total_request_attempts"] += 1
        exceeded_accounting["retransmissions"] += 1
        exceeded_accounting["ack_window_expirations"] += 1
        cases.append((exceeded_budget, "exceeded the retry budget"))

        background_sum = copy.deepcopy(row)
        background_sum["diagnostics"]["packet_counter_deltas"][
            "background_packets"
        ] += 1
        cases.append((background_sum, "background packet accounting"))

        accepted_packets = copy.deepcopy(row)
        accepted_packets["diagnostics"]["packet_counter_deltas"][
            "accepted_packets"
        ] -= 1
        cases.append((accepted_packets, "accepted-packet accounting"))

        ingress_packets = copy.deepcopy(row)
        ingress_packets["diagnostics"]["packet_counter_deltas"][
            "ingress_packets"
        ] -= 1
        cases.append((ingress_packets, "ingress/background accounting"))

        adapter_loss = copy.deepcopy(row)
        adapter_loss["diagnostics"]["adapter_counter_deltas"][
            "ReceivedDiscardedPackets"
        ] = 1
        cases.append((adapter_loss, "recorded packet loss"))

        adapter_sent = copy.deepcopy(row)
        adapter_sent["diagnostics"]["adapter_counter_deltas"][
            "SentUnicastPackets"
        ] -= 1
        cases.append((adapter_sent, "adapter sent-packet accounting"))

        adapter_received = copy.deepcopy(row)
        adapter_received["diagnostics"]["adapter_counter_deltas"][
            "ReceivedUnicastPackets"
        ] = 0
        cases.append((adapter_received, "adapter received-packet accounting"))

        for candidate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CONTROL.CandidateControlError, message):
                    CONTROL.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_fragment_diagnostics_retry_budget_uses_unique_datagram_ceiling(
        self,
    ) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        row = self.row(
            plan=plan,
            scenario="fragment-reassembly-throughput",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        accounting = row["diagnostics"]["accounting"]
        accounting["warmup_unique_datagrams"] = 1_000_000
        accounting["warmup_request_attempts"] = 1_000_000
        accounting["total_unique_datagrams"] = (
            accounting["warmup_unique_datagrams"]
            + accounting["active_unique_datagrams"]
        )
        accounting["total_request_attempts"] = (
            accounting["warmup_request_attempts"]
            + accounting["active_request_attempts"]
        )
        accounting["retry_budget"] = 2
        packet_counters = row["diagnostics"]["packet_counter_deltas"]
        expected_fragment_packets = accounting["total_request_attempts"] * 2
        packet_counters["accepted_packets"] = expected_fragment_packets
        packet_counters["ingress_packets"] = (
            expected_fragment_packets + packet_counters["background_packets"]
        )
        adapter = row["diagnostics"]["adapter_counter_deltas"]
        adapter["ReceivedUnicastPackets"] = accounting["total_request_attempts"]
        adapter["SentUnicastPackets"] = packet_counters["ingress_packets"]
        CONTROL.validate_windows_tun_trial(
            row,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        accounting["retry_budget"] = 1
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "retry budget is inconsistent"
        ):
            CONTROL.validate_windows_tun_trial(
                row,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

    def test_single_trial_cli_validates_collector_output(self) -> None:
        plan = CONTROL.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy()
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan_path = root / "plan.json"
            trial_path = root / "trial.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            trial_path.write_text(json.dumps(row), encoding="utf-8")
            status = CONTROL.main(
                [
                    "windows-tun-validate-trial",
                    "--plan",
                    str(plan_path),
                    "--trial",
                    str(trial_path),
                    "--parent-sha",
                    self.PARENT_SHA,
                    "--candidate-sha",
                    self.CANDIDATE_SHA,
                    "--policy",
                    str(WINDOWS_TUN_POLICY_PATH),
                ]
            )
        self.assertEqual(status, 0)


class DecisionPolicyTests(unittest.TestCase):
    def test_repository_policy_is_the_exact_final_harness_calibration(self) -> None:
        policy = CONTROL.load_decision_policy(POLICY_PATH)
        self.assertRegex(policy["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(policy["policy_id"], FINAL_CALIBRATION_POLICY_ID)
        self.assertEqual(
            set(policy["scenarios"]), set(FINAL_CALIBRATION_THRESHOLDS)
        )
        self.assertEqual(set(policy["scenarios"]), set(CONTROL.SCENARIO_CATALOG))
        for scenario, entry in policy["scenarios"].items():
            with self.subTest(scenario=scenario):
                noise, regression, source = FINAL_CALIBRATION_THRESHOLDS[scenario]
                metric, direction, _family = CONTROL.SCENARIO_CATALOG[scenario]
                self.assertEqual(entry["metric"], metric)
                self.assertEqual(entry["direction"], direction)
                self.assertEqual(
                    Decimal(str(entry["noise_band_percent"])), noise
                )
                self.assertEqual(
                    Decimal(str(entry["regression_threshold_percent"])),
                    regression,
                )
                self.assertEqual(
                    Decimal(str(entry["adoption_threshold_percent"])),
                    Decimal("5.001"),
                )
                self.assertEqual(
                    (
                        entry["minimum_pairs"],
                        entry["minimum_wins"],
                        entry["minimum_losses"],
                    ),
                    (5, 4, 3),
                )
                self.assertEqual(entry["calibration_source"], source)
                self.assertEqual(
                    entry["calibration_environment"],
                    FINAL_CALIBRATION_ENVIRONMENT,
                )

    def test_repository_thresholds_are_derived_from_all_65_raw_aa_pairs(
        self,
    ) -> None:
        serialized = json.dumps(
            FINAL_AA_RAW_EVIDENCE,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.assertEqual(
            hashlib.sha256(serialized).hexdigest(),
            FINAL_AA_RAW_EVIDENCE_SHA256,
        )
        self.assertEqual(len(FINAL_AA_RAW_EVIDENCE), 13)
        self.assertEqual(
            sum(len(pairs) for _direction, pairs in FINAL_AA_RAW_EVIDENCE.values()),
            65,
        )

        policy = CONTROL.load_decision_policy(POLICY_PATH)
        quantum = Decimal("0.001")
        for scenario, (frozen_direction, pairs) in FINAL_AA_RAW_EVIDENCE.items():
            with self.subTest(scenario=scenario):
                metric, catalog_direction, _family = CONTROL.SCENARIO_CATALOG[
                    scenario
                ]
                self.assertEqual(catalog_direction, frozen_direction)
                self.assertEqual(len(pairs), 5)
                deltas = []
                for parent, candidate in pairs:
                    self.assertIs(type(parent), int)
                    self.assertIs(type(candidate), int)
                    self.assertGreater(parent, 0)
                    self.assertGreater(candidate, 0)
                    difference = (
                        candidate - parent
                        if frozen_direction == "higher_is_better"
                        else parent - candidate
                    )
                    expected_delta = (
                        Decimal(difference) * Decimal(100) / Decimal(parent)
                    )
                    observed_delta = CONTROL._improvement(
                        parent, candidate, frozen_direction
                    )
                    self.assertEqual(observed_delta, expected_delta)
                    deltas.append(observed_delta)

                median_absolute_delta = sorted(abs(delta) for delta in deltas)[2]
                self.assertEqual(
                    CONTROL._median([abs(delta) for delta in deltas]),
                    median_absolute_delta,
                )
                noise = median_absolute_delta.quantize(
                    quantum, rounding=ROUND_CEILING
                )
                adoption = max(Decimal(5), noise) + quantum
                regression_floor = (
                    Decimal(2) if metric == "p99_nanoseconds" else Decimal(0)
                )
                regression = -(max(regression_floor, noise) + quantum)
                entry = policy["scenarios"][scenario]
                self.assertEqual(
                    Decimal(str(entry["noise_band_percent"])), noise
                )
                self.assertEqual(
                    Decimal(str(entry["adoption_threshold_percent"])), adoption
                )
                self.assertEqual(
                    Decimal(str(entry["regression_threshold_percent"])),
                    regression,
                )

    def test_repository_calibration_eligibility_requires_five_matching_pairs(
        self,
    ) -> None:
        policy = CONTROL.load_decision_policy(POLICY_PATH)
        for selection in (
            "tcp-frame-capacity",
            "udp-payload-matrix",
            "udp-direct-payload-bounds",
        ):
            with self.subTest(selection=selection, case="matched"):
                matched = CONTROL.create_plan(
                    mode="qualification",
                    selection=selection,
                    warmup_seconds="3",
                    active_seconds="30",
                    pairs="5",
                    decision_policy=policy,
                )
                self.assertTrue(matched["adoption_eligible"])
            with self.subTest(selection=selection, case="three-pair"):
                three_pair = CONTROL.create_plan(
                    mode="qualification",
                    selection=selection,
                    warmup_seconds="3",
                    active_seconds="30",
                    pairs="3",
                    decision_policy=policy,
                )
                self.assertFalse(three_pair["adoption_eligible"])
            with self.subTest(selection=selection, case="recipe-mismatch"):
                mismatched = CONTROL.create_plan(
                    mode="qualification",
                    selection=selection,
                    warmup_seconds="5",
                    active_seconds="30",
                    pairs="5",
                    decision_policy=policy,
                )
                self.assertFalse(mismatched["adoption_eligible"])

    def test_policy_schema_rejects_shape_identity_and_partial_calibration_errors(
        self,
    ) -> None:
        mutations = {
            "missing scenario": lambda policy: policy["scenarios"].pop("tcp-bulk"),
            "wrong metric": lambda policy: policy["scenarios"]["tcp-bulk"].update(
                metric="p99_nanoseconds"
            ),
            "partial calibration": lambda policy: policy["scenarios"][
                "tcp-bulk"
            ].update(calibration_source=None),
            "threshold inside noise": lambda policy: policy["scenarios"][
                "tcp-bulk"
            ].update(regression_threshold_percent=-1.0),
            "boolean count": lambda policy: policy["scenarios"]["tcp-bulk"].update(
                minimum_wins=True
            ),
            "boolean recipe": lambda policy: policy["scenarios"]["tcp-bulk"][
                "calibration_environment"
            ].update(warmup_seconds=True),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                policy = synthetic_policy()
                mutation(policy)
                with self.assertRaises(CONTROL.CandidateControlError):
                    CONTROL.validate_decision_policy(policy)

    def test_policy_loader_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-policy-json-") as directory:
            root = pathlib.Path(directory)
            for name, text in (
                ("duplicate", '{"schema_version":1,"schema_version":1}'),
                (
                    "non-finite",
                    '{"schema_version":1,"policy_id":"x","scenarios":NaN}',
                ),
            ):
                with self.subTest(name=name):
                    path = root / f"{name}.json"
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(CONTROL.CandidateControlError):
                        CONTROL.load_decision_policy(path)

    def test_canonical_plan_rejects_policy_digest_or_threshold_tampering(self) -> None:
        policy = CONTROL.load_decision_policy(POLICY_PATH)
        plan = CONTROL.create_plan(
            mode="qualification",
            selection="tcp-stream-64k",
            warmup_seconds="3",
            active_seconds="30",
            pairs="3",
            decision_policy=policy,
        )
        with tempfile.TemporaryDirectory(prefix="ferrum2-policy-plan-") as directory:
            path = pathlib.Path(directory) / "plan.json"
            for name, mutate in (
                (
                    "schema version",
                    lambda value: value.update(schema_version=3),
                ),
                (
                    "digest",
                    lambda value: value["decision_policy"].update(
                        policy_sha256="0" * 64
                    ),
                ),
                (
                    "threshold",
                    lambda value: value["decision_policy"]["scenarios"][
                        "tcp-bulk"
                    ].update(noise_band_percent=2.0),
                ),
            ):
                with self.subTest(name=name):
                    tampered = copy.deepcopy(plan)
                    mutate(tampered)
                    CONTROL.write_plan(path, tampered)
                    with self.assertRaises(CONTROL.CandidateControlError):
                        CONTROL.load_plan(path, decision_policy=policy)


class EvidenceSummaryTests(unittest.TestCase):
    PARENT_SHA = "1" * 40
    CANDIDATE_SHA = "2" * 40

    def setUp(self) -> None:
        self.owners: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for owner in reversed(self.owners):
            owner.cleanup()

    def plan(
        self,
        mode: str,
        scenario: str,
        *,
        decision_policy: dict[str, object] | None = None,
        warmup_seconds: int = 3,
        active_seconds: int = 30,
        pairs: int = 3,
    ) -> dict[str, object]:
        return CONTROL.create_plan(
            mode=mode,
            selection=scenario,
            warmup_seconds=str(warmup_seconds),
            active_seconds=str(active_seconds),
            pairs=str(pairs),
            decision_policy=(
                copy.deepcopy(CONTROL.UNCALIBRATED_POLICY)
                if decision_policy is None
                else decision_policy
            ),
        )

    def roots(self) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        owner = tempfile.TemporaryDirectory(prefix="ferrum2-performance-evidence-")
        self.owners.append(owner)
        root = pathlib.Path(owner.name)
        parent = root / "parent"
        candidate = root / "candidate"
        parent.mkdir()
        candidate.mkdir()
        return root, parent, candidate

    def row(
        self,
        plan: dict[str, object],
        scenario: str,
        pair: int,
        member: str,
        *,
        value: object | None = None,
    ) -> dict[str, object]:
        metric, direction, _family = CONTROL.SCENARIO_CATALOG[scenario]
        topology, payload_bytes, socks_bytes, upstream_bytes = (
            CONTROL.SCENARIO_EVIDENCE[scenario]
        )
        if value is None:
            if member == "parent":
                value = 100
            else:
                value = 110 if direction == "higher_is_better" else 90
        order = 1 if (pair % 2 == 1) == (member == "parent") else 2
        sha = self.PARENT_SHA if member == "parent" else self.CANDIDATE_SHA
        member_digit = "a" if member == "parent" else "b"
        return {
            "schema_version": CONTROL.PROFILE_TRIAL_SCHEMA_VERSION,
            "kind": "m18_profile_trial",
            "parent_sha": self.PARENT_SHA,
            "candidate_sha": self.CANDIDATE_SHA,
            "member": member,
            "pair": pair,
            "order": order,
            "build_profile": "current",
            "scenario": scenario,
            "warmup_seconds": plan["warmup_seconds"],
            "active_seconds": plan["active_seconds"],
            "topology": topology,
            "application_payload_bytes": payload_bytes,
            "socks_datagram_bytes": socks_bytes,
            "upstream_wire_bytes": upstream_bytes,
            "sha": sha,
            "tree": ("3" if member == "parent" else "4") * 40,
            "runner_sha256": member_digit * 64,
            "client_sha256": ("c" if member == "parent" else "d") * 64,
            "server_sha256": ("e" if member == "parent" else "f") * 64,
            "rustc": "rustc 1.97.1 test",
            "kernel": "test-kernel",
            "cpu_model": "test-cpu",
            "cpu_count": 8,
            "memory_kib": 16_777_216,
            "metric": metric,
            "value": value,
            "checked_units": 1_000,
            "p99_nanoseconds": value if metric == "p99_nanoseconds" else None,
            "io_completions": 2_000,
            "scale": None,
            "correctness": "PASS",
            "status": "PASS",
        }

    def populate(
        self,
        plan: dict[str, object],
        parent_root: pathlib.Path,
        candidate_root: pathlib.Path,
        values: dict[tuple[str, int, str], object] | None = None,
    ) -> None:
        values = values or {}
        for scenario in plan["scenarios"]:
            name = scenario["scenario"]
            for pair in range(1, plan["pairs"] + 1):
                for member, root in (
                    ("parent", parent_root),
                    ("candidate", candidate_root),
                ):
                    value = values.get((name, pair, member))
                    row = self.row(plan, name, pair, member, value=value)
                    (root / f"{name}-{member}-{pair}.jsonl").write_text(
                        json.dumps(row, sort_keys=True, allow_nan=True) + "\n",
                        encoding="utf-8",
                    )

    def summarize(
        self,
        plan: dict[str, object],
        parent_root: pathlib.Path,
        candidate_root: pathlib.Path,
    ) -> dict[str, object]:
        return CONTROL.summarize_evidence(
            plan=plan,
            parent_root=parent_root,
            candidate_root=candidate_root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

    @staticmethod
    def rewrite(path: pathlib.Path, change) -> None:
        row = json.loads(path.read_text(encoding="utf-8"))
        change(row)
        path.write_text(
            json.dumps(row, sort_keys=True, allow_nan=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def materialize_policy(
        root: pathlib.Path, policy: dict[str, object]
    ) -> tuple[pathlib.Path, dict[str, object]]:
        path = root / "decision-policy.json"
        document = {
            "schema_version": policy["schema_version"],
            "policy_id": policy["policy_id"],
            "scenarios": policy["scenarios"],
        }
        path.write_text(
            json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        return path, CONTROL.load_decision_policy(path)

    def fresh_diagnostic(self) -> tuple[dict[str, object], pathlib.Path, pathlib.Path]:
        plan = self.plan("diagnostic", "tcp-bulk")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        return plan, parent, candidate

    def test_diagnostic_dry_run_is_measured_without_adoption_claim(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "MEASURED")
        self.assertFalse(summary["adoption_claim"])
        self.assertEqual(summary["scenarios"][0]["median_improvement_percent"], 10.0)

    def test_diagnostic_regression_is_reported_as_measurement_not_adoption_decision(
        self,
    ) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair in range(1, plan["pairs"] + 1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row: row.update(value=10),
            )
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "MEASURED")
        self.assertEqual(summary["scenarios"][0]["losses"], 3)
        self.assertFalse(summary["adoption_claim"])

    def test_parent_then_candidate_and_candidate_then_parent_are_paired_by_member(
        self,
    ) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        pairs = self.summarize(plan, parent, candidate)["scenarios"][0]["pairs"]
        self.assertEqual(
            (pairs[0]["parent_order"], pairs[0]["candidate_order"]), (1, 2)
        )
        self.assertEqual(
            (pairs[1]["parent_order"], pairs[1]["candidate_order"]), (2, 1)
        )
        self.assertTrue(all(pair["improvement_percent"] == 10.0 for pair in pairs))

    def test_higher_and_lower_is_better_metrics_use_positive_for_improvement(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-request-1k")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summaries = {
            item["scenario"]: item
            for item in self.summarize(plan, parent, candidate)["scenarios"]
        }
        self.assertEqual(summaries["tcp-bulk"]["median_improvement_percent"], 10.0)
        self.assertEqual(
            summaries["tcp-request-1k"]["median_improvement_percent"], 10.0
        )

    def test_odd_pair_median_is_calculated_after_each_pair_delta(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair, value in enumerate((110, 130, 120), start=1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row, value=value: row.update(value=value),
            )
        scenario = self.summarize(plan, parent, candidate)["scenarios"][0]
        self.assertEqual(scenario["median_improvement_percent"], 20.0)
        self.assertEqual(scenario["minimum_improvement_percent"], 10.0)
        self.assertEqual(scenario["maximum_improvement_percent"], 30.0)

    def test_wins_losses_and_ties_use_unrounded_pair_deltas(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair, value in enumerate((110, 90, 100), start=1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row, value=value: row.update(value=value),
            )
        scenario = self.summarize(plan, parent, candidate)["scenarios"][0]
        self.assertEqual(
            (scenario["wins"], scenario["losses"], scenario["ties"]),
            (1, 1, 1),
        )
        self.assertEqual(scenario["median_improvement_percent"], 0.0)

    def test_observed_direction_spread_and_outlier_warnings_are_descriptive(
        self,
    ) -> None:
        cases = (
            ((110, 120, 130), "positive", set()),
            ((90, 80, 70), "negative", set()),
            ((90, 100, 110), "mixed", {"MIXED_DIRECTION"}),
            (
                (4, 101, 102),
                "mixed",
                {"MIXED_DIRECTION", "EXTREME_NEGATIVE_PAIR", "HIGH_VARIANCE"},
            ),
            (
                (99, 101, 196),
                "mixed",
                {"MIXED_DIRECTION", "EXTREME_POSITIVE_PAIR", "HIGH_VARIANCE"},
            ),
            ((100, 100, 100), "neutral", set()),
        )
        for candidates, direction, expected_warnings in cases:
            with self.subTest(candidates=candidates):
                plan = self.plan("qualification", "tcp-bulk")
                _root, parent, candidate = self.roots()
                values = {
                    ("tcp-bulk", pair, "candidate"): value
                    for pair, value in enumerate(candidates, start=1)
                }
                self.populate(plan, parent, candidate, values)
                summary = self.summarize(plan, parent, candidate)
                primary = next(
                    item for item in summary["scenarios"] if item["role"] == "primary"
                )
                self.assertEqual(summary["status"], "INCONCLUSIVE")
                self.assertEqual(primary["observed_direction"], direction)
                self.assertEqual(set(primary["warnings"]), expected_warnings)
                self.assertEqual(
                    primary["spread_percent"],
                    primary["maximum_improvement_percent"]
                    - primary["minimum_improvement_percent"],
                )

    def test_warning_never_overrides_a_calibrated_candidate_decision(self) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(),
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-stream-64k", pair, "candidate"): value
            for pair, value in enumerate((4, 110, 110), start=1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        primary = next(
            item for item in summary["scenarios"] if item["role"] == "primary"
        )
        self.assertEqual(summary["status"], "CANDIDATE_WIN")
        self.assertIn("EXTREME_NEGATIVE_PAIR", primary["warnings"])
        self.assertIsNone(summary["workflow_failure_reason"])

    def test_even_median_averages_the_two_middle_deltas(self) -> None:
        self.assertEqual(
            CONTROL._median(
                [Decimal("-10"), Decimal("40"), Decimal("20"), Decimal("30")]
            ),
            Decimal("25"),
        )

    def test_clear_guard_decline_is_inconclusive_without_calibration(self) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): 4 for pair in range(1, plan["pairs"] + 1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        scenarios = {item["scenario"]: item for item in summary["scenarios"]}
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        self.assertEqual(scenarios["tcp-stream-64k"]["wins"], 3)
        self.assertEqual(scenarios["tcp-bulk"]["losses"], 3)
        self.assertEqual(scenarios["tcp-bulk"]["median_improvement_percent"], -96.0)

    def test_negative_guard_median_is_inconclusive_even_with_one_positive_pair(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", 1, "candidate"): 4,
            ("tcp-bulk", 2, "candidate"): 4,
            ("tcp-bulk", 3, "candidate"): 101,
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        guard = next(
            item for item in summary["scenarios"] if item["scenario"] == "tcp-bulk"
        )
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        self.assertEqual(guard["median_improvement_percent"], -96.0)

    def test_tiny_negative_and_positive_medians_are_inconclusive_without_thresholds(
        self,
    ) -> None:
        for candidates, observed in (
            ((99_950, 99_900, 100_040), "mixed"),
            ((100_050, 100_100, 99_960), "mixed"),
        ):
            with self.subTest(candidates=candidates):
                plan = self.plan("qualification", "tcp-stream-64k")
                _root, parent, candidate = self.roots()
                values = {}
                for scenario in plan["scenarios"]:
                    for pair, value in enumerate(candidates, start=1):
                        values[(scenario["scenario"], pair, "parent")] = 100_000
                        values[(scenario["scenario"], pair, "candidate")] = value
                self.populate(plan, parent, candidate, values)
                summary = self.summarize(plan, parent, candidate)
                self.assertEqual(summary["status"], "INCONCLUSIVE")
                self.assertFalse(summary["decision_enabled"])
                self.assertFalse(summary["adoption_claim"])
                self.assertTrue(
                    all(
                        item["observed_direction"] == observed
                        for item in summary["scenarios"]
                    )
                )

    def test_multi_scenario_qualification_dry_run_is_measured_without_threshold(
        self,
    ) -> None:
        plan = self.plan("qualification", "udp-small-high")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        self.assertFalse(summary["adoption_claim"])

    def test_tcp_frame_capacity_dry_run_requires_every_primary_and_guard(self) -> None:
        plan = self.plan("qualification", "tcp-frame-capacity")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["scenario_group"], "tcp-frame-capacity")
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        self.assertEqual(len(summary["primary_results"]), 2)
        self.assertEqual(len(summary["guard_results"]), 3)

        for entry in plan["scenarios"]:
            with self.subTest(missing=entry["scenario"]):
                _root, missing_parent, missing_candidate = self.roots()
                self.populate(plan, missing_parent, missing_candidate)
                for evidence_root in (missing_parent, missing_candidate):
                    for path in evidence_root.glob(f"{entry['scenario']}-*.jsonl"):
                        path.unlink()
                with self.assertRaises(CONTROL.CandidateControlError) as captured:
                    self.summarize(plan, missing_parent, missing_candidate)
                self.assertEqual(
                    captured.exception.missing_scenarios, [entry["scenario"]]
                )

    def test_udp_bound_summary_distinguishes_application_socks_and_upstream_wire(
        self,
    ) -> None:
        for selection, expected in (
            (
                "udp-payload-matrix",
                "65,449 application bytes and fills the AES-2022 response wire",
            ),
            (
                "udp-direct-payload-bounds",
                "65,497 application bytes plus the 10-byte",
            ),
        ):
            with self.subTest(selection=selection):
                plan = self.plan("qualification", selection)
                _root, parent, candidate = self.roots()
                self.populate(plan, parent, candidate)
                summary = self.summarize(plan, parent, candidate)
                markdown = CONTROL.summary_markdown(summary)
                self.assertIn(expected, markdown)
                self.assertIn("Application payload B", markdown)
                self.assertIn("SOCKS datagram B", markdown)
                self.assertIn("Upstream wire B", markdown)

    def test_calibrated_tcp_frame_capacity_group_can_win_or_confirm_guard_regression(
        self,
    ) -> None:
        for expected_status, request_1k_value in (
            ("CANDIDATE_WIN", 90),
            ("REGRESSION", 110),
        ):
            with self.subTest(status=expected_status):
                plan = self.plan(
                    "qualification",
                    "tcp-frame-capacity",
                    decision_policy=synthetic_policy(),
                )
                _root, parent, candidate = self.roots()
                values = {
                    ("tcp-request-1k", pair, "candidate"): request_1k_value
                    for pair in range(1, plan["pairs"] + 1)
                }
                self.populate(plan, parent, candidate, values)
                summary = self.summarize(plan, parent, candidate)
                self.assertEqual(summary["status"], expected_status)

    def test_calibrated_noise_band_is_inconclusive(self) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(),
        )
        _root, parent, candidate = self.roots()
        values = {
            (entry["scenario"], pair, "candidate"): 101
            for entry in plan["scenarios"]
            for pair in range(1, plan["pairs"] + 1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        primary = next(
            item for item in summary["scenarios"] if item["role"] == "primary"
        )
        self.assertEqual(primary["threshold_decision"], "WITHIN_NOISE")

    def test_calibrated_primary_improvement_and_clear_guard_is_candidate_win(
        self,
    ) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(),
        )
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "CANDIDATE_WIN")
        self.assertTrue(summary["adoption_claim"])
        self.assertEqual(summary["threshold_availability"], "complete")

    def test_calibrated_guard_regression_overrides_primary_improvement(self) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(),
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): 90 for pair in range(1, plan["pairs"] + 1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "REGRESSION")
        guard = next(item for item in summary["scenarios"] if item["role"] == "guard")
        self.assertEqual(guard["threshold_decision"], "CONFIRMED_REGRESSION")

    def test_repository_policy_enforces_five_pair_adoption_boundaries(self) -> None:
        policy = CONTROL.load_decision_policy(POLICY_PATH)
        cases = (
            (
                "within-noise",
                (101, 101, 101, 101, 101),
                "INCONCLUSIVE",
                "WITHIN_NOISE",
            ),
            (
                "four-wins",
                (110, 110, 110, 110, 90),
                "CANDIDATE_WIN",
                "CANDIDATE_IMPROVEMENT",
            ),
            (
                "three-wins",
                (110, 110, 110, 90, 90),
                "INCONCLUSIVE",
                "INSUFFICIENT_WINS",
            ),
        )
        for name, candidates, expected_status, expected_decision in cases:
            with self.subTest(case=name):
                plan = self.plan(
                    "qualification",
                    "tcp-stream-64k",
                    decision_policy=policy,
                    pairs=5,
                )
                self.assertTrue(plan["adoption_eligible"])
                _root, parent, candidate = self.roots()
                values = {
                    ("tcp-stream-64k", pair, "candidate"): value
                    for pair, value in enumerate(candidates, start=1)
                }
                self.populate(plan, parent, candidate, values)
                summary = self.summarize(plan, parent, candidate)
                primary = next(
                    item
                    for item in summary["scenarios"]
                    if item["scenario"] == "tcp-stream-64k"
                )
                self.assertEqual(summary["status"], expected_status)
                self.assertEqual(
                    primary["threshold_decision"], expected_decision
                )
                self.assertEqual(
                    primary["wins"], sum(value > 100 for value in candidates)
                )

    def test_repository_policy_requires_three_losses_for_regression(self) -> None:
        policy = CONTROL.load_decision_policy(POLICY_PATH)
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=policy,
            pairs=5,
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): value
            for pair, value in enumerate((90, 90, 90, 110, 110), start=1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        guard = next(
            item
            for item in summary["scenarios"]
            if item["scenario"] == "tcp-bulk"
        )
        self.assertEqual(summary["status"], "REGRESSION")
        self.assertEqual(guard["losses"], 3)
        self.assertEqual(guard["threshold_decision"], "CONFIRMED_REGRESSION")

        scenario_plan = next(
            item for item in plan["scenarios"] if item["scenario"] == "tcp-bulk"
        )
        # With five pairs, a negative median necessarily has at least three losses,
        # so exercise the minimum-loss branch directly at its decision boundary.
        insufficient = CONTROL._scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=3,
            losses=2,
            median_improvement=Decimal("-10"),
        )
        confirmed = CONTROL._scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=2,
            losses=3,
            median_improvement=Decimal("-10"),
        )
        self.assertEqual(
            insufficient["threshold_decision"], "INSUFFICIENT_LOSSES"
        )
        self.assertEqual(insufficient["status"], "INCONCLUSIVE")
        self.assertFalse(insufficient["guard_passed"])
        self.assertEqual(confirmed["threshold_decision"], "CONFIRMED_REGRESSION")

    def test_adoption_threshold_without_minimum_wins_is_inconclusive(self) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(minimum_wins=3),
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-stream-64k", pair, "candidate"): value
            for pair, value in enumerate((110, 90, 110), start=1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        primary = next(
            item for item in summary["scenarios"] if item["role"] == "primary"
        )
        self.assertEqual(primary["threshold_decision"], "INSUFFICIENT_WINS")

    def test_partial_or_recipe_mismatched_calibration_cannot_claim_a_win(self) -> None:
        cases = (
            synthetic_policy(calibrated_scenarios={"tcp-stream-64k"}),
            synthetic_policy(warmup_seconds=5),
        )
        for policy in cases:
            with self.subTest(policy=policy["policy_id"]):
                plan = self.plan(
                    "qualification",
                    "tcp-stream-64k",
                    decision_policy=policy,
                )
                _root, parent, candidate = self.roots()
                self.populate(plan, parent, candidate)
                summary = self.summarize(plan, parent, candidate)
                self.assertEqual(summary["status"], "INCONCLUSIVE")
                self.assertFalse(summary["adoption_claim"])

    def test_regression_threshold_without_minimum_losses_is_inconclusive(self) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(minimum_losses=3),
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): value
            for pair, value in enumerate((90, 90, 120), start=1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        guard = next(item for item in summary["scenarios"] if item["role"] == "guard")
        self.assertEqual(guard["threshold_decision"], "INSUFFICIENT_LOSSES")

    def test_missing_mandatory_guard_is_invalid(self) -> None:
        plan = self.plan("qualification", "udp-small-high")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        for root in (parent, candidate):
            for path in root.glob("udp-mtu-1200-*.jsonl"):
                path.unlink()
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "incomplete"):
            self.summarize(plan, parent, candidate)

    def test_missing_duplicate_mismatched_and_failed_rows_are_invalid(self) -> None:
        mutations = {
            "legacy raw without schema version": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.pop("schema_version"),
            ),
            "unsupported raw schema version": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(schema_version=1),
            ),
            "missing candidate": lambda _plan, _parent, candidate: (
                candidate / "tcp-bulk-candidate-1.jsonl"
            ).unlink(),
            "duplicate row": lambda _plan, parent, _candidate: (
                parent / "duplicate.jsonl"
            ).write_text(
                (parent / "tcp-bulk-parent-1.jsonl").read_text(encoding="utf-8"),
                encoding="utf-8",
            ),
            "wrong scenario": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(scenario="udp-small-high"),
            ),
            "wrong topology": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(topology="direct"),
            ),
            "wrong payload bound": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(application_payload_bytes=65_507),
            ),
            "unexpected UDP wire bound": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(upstream_wire_bytes=65_507),
            ),
            "wrong pair": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-2.jsonl",
                lambda row: row.update(pair=1),
            ),
            "correctness failure": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(correctness="FAIL"),
            ),
            "status failure": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(status="FAIL"),
            ),
            "same order": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(order=1),
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                plan, parent, candidate = self.fresh_diagnostic()
                mutate(plan, parent, candidate)
                with self.assertRaises(CONTROL.CandidateControlError):
                    self.summarize(plan, parent, candidate)

    def test_zero_non_numeric_negative_and_non_finite_baselines_are_invalid(
        self,
    ) -> None:
        for value in (
            0,
            "100",
            True,
            -1,
            100.0,
            float("nan"),
            float("inf"),
            float("-inf"),
        ):
            with self.subTest(value=repr(value)):
                plan, parent, candidate = self.fresh_diagnostic()
                self.rewrite(
                    parent / "tcp-bulk-parent-1.jsonl",
                    lambda row, value=value: row.update(value=value),
                )
                with self.assertRaises(CONTROL.CandidateControlError):
                    self.summarize(plan, parent, candidate)

    def test_wrong_metric_and_request_p99_are_invalid(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        self.rewrite(
            candidate / "tcp-bulk-candidate-1.jsonl",
            lambda row: row.update(metric="p99_nanoseconds"),
        )
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "metric"):
            self.summarize(plan, parent, candidate)

        plan = self.plan("diagnostic", "tcp-request-1k")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        self.rewrite(
            candidate / "tcp-request-1k-candidate-1.jsonl",
            lambda row: row.update(p99_nanoseconds=91),
        )
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "p99"):
            self.summarize(plan, parent, candidate)

    def test_duplicate_json_keys_are_invalid(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        path = candidate / "tcp-bulk-candidate-1.jsonl"
        text = path.read_text(encoding="utf-8").strip()
        path.write_text(text[:-1] + ', "status": "PASS"}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "duplicate JSON key"
        ):
            self.summarize(plan, parent, candidate)

    def test_summary_command_writes_outputs_before_invalid_evidence_failure(
        self,
    ) -> None:
        root, parent, candidate = self.roots()
        policy_path, policy = self.materialize_policy(
            root, copy.deepcopy(CONTROL.UNCALIBRATED_POLICY)
        )
        plan = self.plan(
            "qualification", "tcp-stream-64k", decision_policy=policy
        )
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent,
                "candidate_root": candidate,
                "parent_sha": self.PARENT_SHA,
                "candidate_sha": self.CANDIDATE_SHA,
                "policy": policy_path,
                "output": output,
                "markdown": markdown,
            },
        )()
        self.assertEqual(CONTROL.run_summary_command(arguments), 2)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["schema_version"], CONTROL.SUMMARY_SCHEMA_VERSION)
        self.assertEqual(summary["status"], "INVALID_EVIDENCE")
        self.assertEqual(summary["mode"], "qualification")
        self.assertEqual(summary["scenario_group"], "tcp-throughput")
        self.assertEqual(
            set(summary["missing_scenarios"]), set(summary["mandatory_scenarios"])
        )
        rendered = markdown.read_text(encoding="utf-8")
        self.assertIn("INVALID_EVIDENCE", rendered)
        self.assertIn("tcp-throughput", rendered)
        self.assertIn("Missing scenarios", rendered)

    def test_summary_command_writes_valid_machine_and_markdown_results(self) -> None:
        root, parent, candidate = self.roots()
        policy_path, policy = self.materialize_policy(
            root, copy.deepcopy(CONTROL.UNCALIBRATED_POLICY)
        )
        plan = self.plan("diagnostic", "tcp-bulk", decision_policy=policy)
        self.populate(plan, parent, candidate)
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent,
                "candidate_root": candidate,
                "parent_sha": self.PARENT_SHA,
                "candidate_sha": self.CANDIDATE_SHA,
                "policy": policy_path,
                "output": output,
                "markdown": markdown,
            },
        )()
        self.assertEqual(CONTROL.run_summary_command(arguments), 0)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["schema_version"], CONTROL.SUMMARY_SCHEMA_VERSION)
        self.assertEqual(summary["status"], "MEASURED")
        self.assertEqual(
            summary["build_identities"],
            {
                "parent": {
                    "sha": self.PARENT_SHA,
                    "tree": "3" * 40,
                    "runner_sha256": "a" * 64,
                    "client_sha256": "c" * 64,
                    "server_sha256": "e" * 64,
                },
                "candidate": {
                    "sha": self.CANDIDATE_SHA,
                    "tree": "4" * 40,
                    "runner_sha256": "b" * 64,
                    "client_sha256": "d" * 64,
                    "server_sha256": "f" * 64,
                },
            },
        )
        rendered = markdown.read_text(encoding="utf-8")
        self.assertIn("| parent |", rendered)
        self.assertIn("| candidate |", rendered)
        self.assertIn("| tcp-bulk |", rendered)

    def test_summary_command_keeps_uncalibrated_decline_non_failing(self) -> None:
        root, parent, candidate = self.roots()
        policy_path, policy = self.materialize_policy(
            root, copy.deepcopy(CONTROL.UNCALIBRATED_POLICY)
        )
        plan = self.plan(
            "qualification", "tcp-stream-64k", decision_policy=policy
        )
        values = {
            ("tcp-bulk", pair, "candidate"): 4 for pair in range(1, plan["pairs"] + 1)
        }
        self.populate(plan, parent, candidate, values)
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent,
                "candidate_root": candidate,
                "parent_sha": self.PARENT_SHA,
                "candidate_sha": self.CANDIDATE_SHA,
                "policy": policy_path,
                "output": output,
                "markdown": markdown,
            },
        )()
        self.assertEqual(CONTROL.run_summary_command(arguments), 0)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "INCONCLUSIVE",
        )

    def test_summary_command_exit_codes_follow_calibrated_decisions(self) -> None:
        for expected_status, guard_value, expected_exit in (
            ("CANDIDATE_WIN", 110, 0),
            ("REGRESSION", 90, 3),
        ):
            with self.subTest(status=expected_status):
                root, parent, candidate = self.roots()
                policy_path, policy = self.materialize_policy(root, synthetic_policy())
                plan = self.plan(
                    "qualification",
                    "tcp-stream-64k",
                    decision_policy=policy,
                )
                values = {
                    ("tcp-bulk", pair, "candidate"): guard_value
                    for pair in range(1, plan["pairs"] + 1)
                }
                self.populate(plan, parent, candidate, values)
                plan_path = root / "plan.json"
                output = root / "performance-summary.json"
                markdown = root / "performance-summary.md"
                CONTROL.write_plan(plan_path, plan)
                arguments = type(
                    "Arguments",
                    (),
                    {
                        "plan": plan_path,
                        "parent_root": parent,
                        "candidate_root": candidate,
                        "parent_sha": self.PARENT_SHA,
                        "candidate_sha": self.CANDIDATE_SHA,
                        "policy": policy_path,
                        "output": output,
                        "markdown": markdown,
                    },
                )()
                self.assertEqual(CONTROL.run_summary_command(arguments), expected_exit)
                self.assertEqual(
                    json.loads(output.read_text(encoding="utf-8"))["status"],
                    expected_status,
                )


class ScaleControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = CONTROL.load_scale_safety_policy(SCALE_POLICY_PATH)
        self.plan = CONTROL.create_plan(
            mode="qualification",
            selection=CONTROL.SCALE_SCENARIO,
            warmup_seconds="10",
            active_seconds="30",
            pairs="5",
            decision_policy=CONTROL.load_decision_policy(POLICY_PATH),
            scale_safety_policy=self.policy,
            scale_lineage=synthetic_scale_lineage(),
        )

    def summarize_rows(
        self,
        candidates: list[dict[str, object]],
        parents: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        parents = parents or [
            synthetic_scale_row(pair=pair, member="parent")
            for pair in range(1, 6)
        ]
        rows = {
            (CONTROL.SCALE_SCENARIO, row["pair"], row["member"]): row
            for row in [*parents, *candidates]
        }
        identity_fields = (
            "sha",
            "tree",
            "runner_sha256",
            "client_sha256",
            "server_sha256",
        )
        member_identity = {
            "parent": tuple(parents[0][field] for field in identity_fields),
            "candidate": tuple(candidates[0][field] for field in identity_fields),
        }
        return CONTROL._summarize_scale_evidence(
            plan=self.plan,
            rows=rows,
            parent_sha="1" * 40,
            candidate_sha="2" * 40,
            member_identity=member_identity,
            identity_fields=identity_fields,
            evidence_files=[],
        )

    def trial_failures(self, row: dict[str, object]) -> set[str]:
        _observation, failures = CONTROL._scale_trial_observation(row, self.policy)
        return set(failures)

    def test_scale_plan_is_qualification_only_and_requires_exact_recipe(self) -> None:
        self.assertEqual(self.plan["scenario_group"], CONTROL.SCALE_SCENARIO)
        self.assertFalse(self.plan["adoption_eligible"])
        self.assertEqual(self.plan["scale_safety_policy"], self.policy)
        for mode, warmup, active, pairs in (
            ("diagnostic", "10", "30", "5"),
            ("qualification", "5", "30", "5"),
            ("qualification", "10", "15", "5"),
            ("qualification", "10", "30", "3"),
        ):
            with self.subTest(values=(mode, warmup, active, pairs)):
                with self.assertRaises(CONTROL.CandidateControlError):
                    CONTROL.create_plan(
                        mode=mode,
                        selection=CONTROL.SCALE_SCENARIO,
                        warmup_seconds=warmup,
                        active_seconds=active,
                        pairs=pairs,
                        decision_policy=CONTROL.load_decision_policy(POLICY_PATH),
                        scale_safety_policy=self.policy,
                        scale_lineage=synthetic_scale_lineage(),
                    )

    def test_scale_vectors_fairness_quantiles_and_signed_rss_recompute(self) -> None:
        row = synthetic_scale_row(pair=1, member="parent")
        derived = CONTROL._validate_scale_evidence(row)
        self.assertEqual(
            row["scale"]["recipe"]["quiescent_sample_interval_milliseconds"],
            1_000,
        )
        self.assertEqual(
            row["scale"]["recipe"]["active_sample_slot_denominator"], 6
        )
        self.assertNotIn(
            "resource_sample_interval_milliseconds", row["scale"]["recipe"]
        )
        self.assertEqual(derived["fairness"]["jain_fraction"], 1)
        self.assertEqual(
            row["scale"]["resource"][
                "client_touched_increment_bytes_per_connection"
            ],
            102,
        )
        ratio_vector = [16_384] * 100 + [32_768] * 9_900
        ratio = CONTROL._recompute_scale_fairness(ratio_vector)
        self.assertEqual(ratio["p01_bytes"], 16_384)
        self.assertEqual(ratio["median_bytes"], 32_768)
        self.assertEqual(ratio["p01_median_fraction"], CONTROL.Fraction(1, 2))
        jain_boundary = CONTROL._recompute_scale_fairness(
            [0] * 1_000 + [32_768] * 9_000
        )
        self.assertEqual(jain_boundary["jain_fraction"], CONTROL.Fraction(9, 10))

    def test_scale_safety_requires_four_throughput_wins_without_adoption(self) -> None:
        candidates = [
            synthetic_scale_row(
                pair=pair,
                member="candidate",
                full_completions=101 if pair <= 4 else 100,
            )
            for pair in range(1, 6)
        ]
        passed = self.summarize_rows(candidates)
        self.assertEqual(passed["status"], "SCALE_SAFETY_PASS")
        self.assertFalse(passed["adoption_claim"])
        self.assertEqual(passed["scale_safety"]["throughput_wins"], 4)

        failed = self.summarize_rows(
            [
                synthetic_scale_row(
                    pair=pair,
                    member="candidate",
                    full_completions=101 if pair <= 3 else 100,
                )
                for pair in range(1, 6)
            ]
        )
        self.assertEqual(failed["status"], "SCALE_SAFETY_FAIL")
        self.assertIn("THROUGHPUT_WINS", failed["scale_safety"]["failures"])

    def test_zero_flow_is_valid_evidence_but_a_hard_scale_failure(self) -> None:
        candidates = [
            synthetic_scale_row(
                pair=pair,
                member="candidate",
                full_completions=101,
                starve_first=pair == 1,
            )
            for pair in range(1, 6)
        ]
        summary = self.summarize_rows(candidates)
        self.assertEqual(summary["status"], "SCALE_SAFETY_FAIL")
        self.assertTrue(
            any("FULL_ALL_FLOWS_NONZERO" in failure for failure in summary["scale_safety"]["failures"])
        )

    def test_host_owner_tuple_and_zero_touched_rss_are_scale_failures(self) -> None:
        mutations = {}

        def low_cpu(row):
            row["cpu_count"] = 3

        mutations["HOST_CPU_COUNT"] = low_cpu

        def low_memory(row):
            row["memory_kib"] = 14_999_999

        mutations["HOST_MEMORY_TOTAL"] = low_memory

        def owner_drift(row):
            row["scale"]["resource"]["touched"][2]["client_fds"] += 1

        mutations["RESOURCE_TOUCHED_OWNER_TUPLE"] = owner_drift

        def zero_touched(row):
            resource = row["scale"]["resource"]
            for stage in ("touched", "post_full"):
                for sample in resource[stage]:
                    sample["client_smaps_rss_kib"] = 0
            resource["client_touched_increment_bytes_per_connection"] = -204
            resource["combined_touched_increment_bytes_per_connection"] = -102

        mutations["CLIENT_TOUCHED_RSS_ZERO"] = zero_touched

        for expected, mutation in mutations.items():
            with self.subTest(expected=expected):
                candidates = [
                    synthetic_scale_row(
                        pair=pair, member="candidate", full_completions=101
                    )
                    for pair in range(1, 6)
                ]
                mutation(candidates[0])
                summary = self.summarize_rows(candidates)
                self.assertEqual(summary["status"], "SCALE_SAFETY_FAIL")
                self.assertTrue(
                    any(
                        expected in failure
                        for failure in summary["scale_safety"]["failures"]
                    )
                )

    def test_scale_host_and_owner_tuple_boundaries_are_exhaustive(self) -> None:
        for member in ("parent", "candidate"):
            with self.subTest(member=member, boundary="host"):
                boundary = synthetic_scale_row(pair=1, member=member)
                boundary["cpu_count"] = 4
                boundary["memory_kib"] = 15_000_000
                failures = self.trial_failures(boundary)
                self.assertNotIn("HOST_CPU_COUNT", failures)
                self.assertNotIn("HOST_MEMORY_TOTAL", failures)
            for field, value, expected in (
                ("cpu_count", 3, "HOST_CPU_COUNT"),
                ("memory_kib", 14_999_999, "HOST_MEMORY_TOTAL"),
            ):
                with self.subTest(member=member, field=field):
                    row = synthetic_scale_row(pair=1, member=member)
                    row[field] = value
                    self.assertIn(expected, self.trial_failures(row))

        for member in ("parent", "candidate"):
            for stage in (
                "established",
                "touched",
                "partial_active",
                "full_active",
                "post_full",
            ):
                for side in ("client", "server"):
                    for counter in ("active", "fds", "tasks"):
                        with self.subTest(
                            member=member,
                            stage=stage,
                            side=side,
                            counter=counter,
                        ):
                            row = synthetic_scale_row(pair=1, member=member)
                            row["scale"]["resource"][stage][4][
                                f"{side}_{counter}"
                            ] += 1
                            self.assertIn(
                                f"RESOURCE_{stage.upper()}_OWNER_TUPLE",
                                self.trial_failures(row),
                            )

    def test_scale_trial_fairness_and_rss_boundaries_are_exact(self) -> None:
        for member in ("parent", "candidate"):
            for side, touched, at_limit, above_limit in (
                ("client", 3_000, 3_150, 3_151),
                ("server", 4_000, 4_200, 4_201),
            ):
                for post, should_fail in ((at_limit, False), (above_limit, True)):
                    with self.subTest(
                        member=member, side=side, post=post, gate="post_full"
                    ):
                        row = synthetic_scale_row(pair=1, member=member)
                        for sample in row["scale"]["resource"]["touched"]:
                            self.assertEqual(sample[f"{side}_smaps_rss_kib"], touched)
                        for sample in row["scale"]["resource"]["post_full"]:
                            sample[f"{side}_smaps_rss_kib"] = post
                        failure = f"{side.upper()}_POST_FULL_RSS"
                        self.assertEqual(
                            failure in self.trial_failures(row), should_fail
                        )
                with self.subTest(member=member, side=side, gate="zero_touched"):
                    row = synthetic_scale_row(pair=1, member=member)
                    for stage in ("touched", "post_full"):
                        for sample in row["scale"]["resource"][stage]:
                            sample[f"{side}_smaps_rss_kib"] = 0
                    rewrite_scale_resource_increments(row)
                    self.assertIn(
                        f"{side.upper()}_TOUCHED_RSS_ZERO",
                        self.trial_failures(row),
                    )

            jain_boundary = synthetic_scale_row(pair=1, member=member)
            rewrite_scale_full_completions(
                jain_boundary, [0] * 1_000 + [1] * 9_000
            )
            self.assertNotIn("TRIAL_JAIN", self.trial_failures(jain_boundary))
            jain_below = synthetic_scale_row(pair=1, member=member)
            rewrite_scale_full_completions(
                jain_below, [0] * 1_001 + [1] * 8_999
            )
            self.assertIn("TRIAL_JAIN", self.trial_failures(jain_below))

            ratio_boundary = synthetic_scale_row(pair=1, member=member)
            rewrite_scale_full_completions(
                ratio_boundary, [1] * 100 + [2] * 9_900
            )
            self.assertNotIn(
                "TRIAL_P01_MEDIAN_RATIO", self.trial_failures(ratio_boundary)
            )
            ratio_below = synthetic_scale_row(pair=1, member=member)
            rewrite_scale_full_completions(
                ratio_below, [1] * 100 + [3] * 9_900
            )
            self.assertIn(
                "TRIAL_P01_MEDIAN_RATIO", self.trial_failures(ratio_below)
            )

    def test_page_touch_growth_of_growth_boundary_is_signed_and_exact(self) -> None:
        cases = (
            ("client", 640_000, 0, "PAIR_1_CLIENT_PAGE_TOUCH_GOG"),
            ("server", 0, 640_000, "PAIR_1_SERVER_PAGE_TOUCH_GOG"),
            ("combined", 640_000, 640_000, "PAIR_1_COMBINED_PAGE_TOUCH_GOG"),
        )
        for name, client_limit, server_limit, expected in cases:
            with self.subTest(side=name, boundary="equal"):
                at_limit = self.summarize_rows(
                    [
                        synthetic_scale_row(
                            pair=pair,
                            member="candidate",
                            full_completions=101,
                            client_touch_extra_kib=client_limit,
                            server_touch_extra_kib=server_limit,
                        )
                        for pair in range(1, 6)
                    ]
                )
                self.assertEqual(at_limit["status"], "SCALE_SAFETY_PASS")
            with self.subTest(side=name, boundary="above"):
                above = self.summarize_rows(
                    [
                        synthetic_scale_row(
                            pair=pair,
                            member="candidate",
                            full_completions=101,
                            client_touch_extra_kib=client_limit
                            + (1 if pair == 1 and name != "server" else 0),
                            server_touch_extra_kib=server_limit
                            + (1 if pair == 1 and name == "server" else 0),
                        )
                        for pair in range(1, 6)
                    ]
                )
                self.assertEqual(above["status"], "SCALE_SAFETY_FAIL")
                self.assertIn(expected, above["scale_safety"]["failures"])
        negative = self.summarize_rows(
            [
                synthetic_scale_row(
                    pair=pair,
                    member="candidate",
                    full_completions=101,
                    client_touch_extra_kib=-500,
                )
                for pair in range(1, 6)
            ]
        )
        self.assertEqual(negative["status"], "SCALE_SAFETY_PASS")

    def test_scale_pair_and_median_threshold_boundaries_are_exact(self) -> None:
        def candidates(counts: list[int]) -> list[dict[str, object]]:
            return [
                synthetic_scale_row(
                    pair=pair,
                    member="candidate",
                    full_completions=count,
                )
                for pair, count in enumerate(counts, 1)
            ]

        pair_floor = self.summarize_rows(candidates([90, 101, 101, 101, 101]))
        self.assertEqual(pair_floor["status"], "SCALE_SAFETY_PASS")
        below_pair_floor = self.summarize_rows(
            candidates([89, 101, 101, 101, 101])
        )
        self.assertIn(
            "PAIR_1_THROUGHPUT_FLOOR",
            below_pair_floor["scale_safety"]["failures"],
        )

        median_equal = self.summarize_rows(candidates([99, 99, 100, 101, 101]))
        self.assertNotIn(
            "MEDIAN_THROUGHPUT", median_equal["scale_safety"]["failures"]
        )
        median_below = self.summarize_rows(candidates([99, 99, 99, 101, 101]))
        self.assertIn(
            "MEDIAN_THROUGHPUT", median_below["scale_safety"]["failures"]
        )

        def fairness_candidates(
            low: int, high: int, low_count: int
        ) -> list[dict[str, object]]:
            rows = candidates([101] * 5)
            for row in rows:
                rewrite_scale_full_completions(
                    row, [low] * low_count + [high] * (10_000 - low_count)
                )
            return rows

        jain_equal = self.summarize_rows(fairness_candidates(0, 1, 100))
        self.assertNotIn(
            "MEDIAN_JAIN_DELTA", jain_equal["scale_safety"]["failures"]
        )
        jain_below = self.summarize_rows(fairness_candidates(0, 1, 101))
        self.assertIn(
            "MEDIAN_JAIN_DELTA", jain_below["scale_safety"]["failures"]
        )
        ratio_equal = self.summarize_rows(fairness_candidates(19, 20, 100))
        self.assertNotIn(
            "MEDIAN_P01_MEDIAN_RATIO_DELTA",
            ratio_equal["scale_safety"]["failures"],
        )
        ratio_below = self.summarize_rows(fairness_candidates(18, 20, 100))
        self.assertIn(
            "MEDIAN_P01_MEDIAN_RATIO_DELTA",
            ratio_below["scale_safety"]["failures"],
        )

    def test_scale_schema_rejects_vector_mutation_and_bounds_input_before_decode(self) -> None:
        row = synthetic_scale_row(pair=1, member="candidate")
        malformed = copy.deepcopy(row)
        malformed["scale"]["traffic"]["full_flow_bytes"].pop()
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "exactly 10000"):
            CONTROL._validate_scale_evidence(malformed)
        with tempfile.TemporaryDirectory(prefix="ferrum2-scale-reader-") as directory:
            root = pathlib.Path(directory)
            path = root / "scale.jsonl"
            maximum = copy.deepcopy(row)
            maximum["scale"]["traffic"]["partial_flow_bytes"] = [
                CONTROL.U64_MAX
            ] * 1_000
            maximum["scale"]["traffic"]["full_flow_bytes"] = [
                CONTROL.U64_MAX
            ] * 10_000
            maximum["scale"]["traffic"]["full_flow_completions"] = [
                CONTROL.U64_MAX
            ] * 10_000
            compact = json.dumps(maximum, separators=(",", ":"))
            self.assertLessEqual(len(compact.encode()), CONTROL.SCALE_TRIAL_MAX_BYTES)
            self.assertGreater(len(compact.encode()), CONTROL.REGULAR_TRIAL_MAX_BYTES)
            path.write_text(compact + "\n", encoding="utf-8")
            self.assertEqual(CONTROL._read_trial(path)["scenario"], CONTROL.SCALE_SCENARIO)
            path.write_bytes(b" " * (CONTROL.SCALE_TRIAL_MAX_BYTES + 2))
            with self.assertRaisesRegex(CONTROL.CandidateControlError, "byte bound"):
                CONTROL._read_trial(path)
            path.write_text("[" * 2_000 + "]" * 2_000 + "\n", encoding="utf-8")
            with self.assertRaises(CONTROL.CandidateControlError):
                CONTROL._read_trial(path)
            path.write_text('{"value":' + "9" * 100 + "}\n", encoding="utf-8")
            with self.assertRaises(CONTROL.CandidateControlError):
                CONTROL._read_trial(path)


class GitRelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ferrum2-performance-git-")
        self.repository = pathlib.Path(self.temporary.name)
        self._git("init", "--quiet", "--initial-branch=main")
        self._git("config", "user.name", "Performance Test")
        self._git("config", "user.email", "performance@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        self.base = self._commit("base")
        self.direct = self._commit("direct")
        self.multiple = self._commit("multiple")
        self._git("switch", "--quiet", "--orphan", "unrelated")
        self.unrelated = self._commit("unrelated")
        self._git("switch", "--quiet", "main")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            }
        )
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def _commit(self, message: str) -> str:
        self._git("commit", "--quiet", "--allow-empty", "-m", message)
        return self._git("rev-parse", "HEAD")

    def test_direct_and_multi_commit_candidates_are_accepted(self) -> None:
        self.assertEqual(
            CONTROL.validate_git_relation(self.repository, self.base, self.direct),
            (self.base, self.direct),
        )
        self.assertEqual(
            CONTROL.validate_git_relation(self.repository, self.base, self.multiple),
            (self.base, self.multiple),
        )
        self.assertEqual(
            CONTROL.validate_git_relation(
                self.repository, self.base.upper(), self.multiple.upper()
            ),
            (self.base, self.multiple),
        )

    def test_same_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "different"):
            CONTROL.validate_git_relation(self.repository, self.base, self.base)

    def test_unrelated_history_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "not an ancestor"):
            CONTROL.validate_git_relation(self.repository, self.base, self.unrelated)

    def test_reverse_ancestry_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "not an ancestor"):
            CONTROL.validate_git_relation(self.repository, self.multiple, self.base)

    def test_missing_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "available commit"):
            CONTROL.validate_git_relation(self.repository, "f" * 40, self.multiple)

    def test_annotated_tag_object_is_not_accepted_as_a_commit_sha(self) -> None:
        self._git("tag", "--annotate", "candidate-tag", "--message", "candidate")
        tag_object = self._git("rev-parse", "candidate-tag")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "available commit"):
            CONTROL.validate_git_relation(self.repository, self.base, tag_object)

    def test_shallow_history_without_parent_is_rejected(self) -> None:
        shallow_owner = tempfile.TemporaryDirectory(
            prefix="ferrum2-performance-shallow-"
        )
        self.addCleanup(shallow_owner.cleanup)
        shallow = pathlib.Path(shallow_owner.name) / "checkout"
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--depth=1",
                "--branch=main",
                self.repository.as_uri(),
                str(shallow),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "complete history"):
            CONTROL.validate_git_relation(shallow, self.base, self.multiple)


class ScaleLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ferrum2-scale-lineage-")
        self.repository = pathlib.Path(self.temporary.name) / "repository"
        self.repository.mkdir()
        self._git("init", "--quiet", "--initial-branch=main")
        self._git("config", "user.name", "Scale Test")
        self._git("config", "user.email", "scale@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        for path, replacements in CONTROL.SCALE_COUNTERFACTUAL_REPLACEMENTS.items():
            destination = self.repository / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            literals = b"\n".join(old for old, _new in replacements)
            destination.write_bytes(b"prefix\n" + literals + b"\nsuffix\n")
        (self.repository / "extra.txt").write_text("unchanged\n", encoding="utf-8")
        self._git("add", ".")
        self.head = self._commit("H final tree")
        self._apply_counterfactual()
        self.parent = self._commit("P16 exact counterfactual")
        self._git("checkout", "--quiet", self.head, "--", ".")
        self.candidate = self._commit("C32 restore final tree")
        binary_root = pathlib.Path(self.temporary.name) / "binaries"
        binary_root.mkdir()
        self.paths = {}
        for name in (
            "runner",
            "parent-client",
            "parent-server",
            "candidate-client",
            "candidate-server",
        ):
            path = binary_root / name
            path.write_bytes(name.encode())
            self.paths[name] = path

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            }
        )
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def _commit(self, message: str) -> str:
        self._git("commit", "--quiet", "-am", message)
        return self._git("rev-parse", "HEAD")

    def _apply_counterfactual(self) -> None:
        for path, replacements in CONTROL.SCALE_COUNTERFACTUAL_REPLACEMENTS.items():
            destination = self.repository / path
            value = destination.read_bytes()
            for old, new in replacements:
                self.assertEqual(value.count(old), 1)
                value = value.replace(old, new, 1)
            destination.write_bytes(value)

    def build(self, parent: str | None = None, candidate: str | None = None):
        return CONTROL.build_scale_lineage(
            repository=self.repository,
            head_sha=self.head,
            parent_sha=parent or self.parent,
            candidate_sha=candidate or self.candidate,
            runner=self.paths["runner"],
            parent_client=self.paths["parent-client"],
            parent_server=self.paths["parent-server"],
            candidate_client=self.paths["candidate-client"],
            candidate_server=self.paths["candidate-server"],
        )

    def test_exact_h_p16_c32_lineage_binds_trees_patch_and_binaries(self) -> None:
        source = CONTROL.validate_scale_source_lineage(
            self.repository, self.head, self.parent, self.candidate
        )
        self.assertEqual(source["head_tree"], source["candidate_tree"])
        self.assertEqual(
            CONTROL.main(
                [
                    "scale-source-lineage",
                    "--repository",
                    str(self.repository),
                    "--head-sha",
                    self.head,
                    "--parent-sha",
                    self.parent,
                    "--candidate-sha",
                    self.candidate,
                ]
            ),
            0,
        )
        lineage = self.build()
        self.assertEqual(lineage["head_tree"], lineage["candidate_tree"])
        self.assertNotEqual(lineage["head_tree"], lineage["parent_tree"])
        self.assertRegex(lineage["counterfactual_patch_sha256"], r"^[0-9a-f]{64}$")
        CONTROL.validate_scale_lineage_repository(self.repository, lineage)

    def test_lineage_rejects_patch_digest_parent_chain_and_extra_path(self) -> None:
        lineage = self.build()
        tampered = copy.deepcopy(lineage)
        tampered["counterfactual_patch_sha256"] = "0" * 64
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "patch digest"):
            CONTROL.validate_scale_lineage_repository(self.repository, tampered)
        tampered = copy.deepcopy(lineage)
        tampered["candidate_sha"] = self.head
        with self.assertRaises(CONTROL.CandidateControlError):
            CONTROL.validate_scale_lineage_repository(self.repository, tampered)

        self._git("checkout", "--quiet", "--detach", self.head)
        self._apply_counterfactual()
        (self.repository / "extra.txt").write_text("mutated\n", encoding="utf-8")
        extra_parent = self._commit("P16 with extra path")
        self._git("checkout", "--quiet", self.head, "--", ".")
        extra_candidate = self._commit("C32 restore after extra path")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "unexpected path"):
            self.build(extra_parent, extra_candidate)

    def test_scale_summary_command_revalidates_real_lineage_and_writes_all_outcomes(
        self,
    ) -> None:
        lineage = self.build()
        scale_policy = CONTROL.load_scale_safety_policy(SCALE_POLICY_PATH)
        plan = CONTROL.create_plan(
            mode="qualification",
            selection=CONTROL.SCALE_SCENARIO,
            warmup_seconds="10",
            active_seconds="30",
            pairs="5",
            decision_policy=CONTROL.load_decision_policy(POLICY_PATH),
            scale_safety_policy=scale_policy,
            scale_lineage=lineage,
        )
        evidence_root = pathlib.Path(self.temporary.name) / "evidence"
        parent_root = evidence_root / "parent"
        candidate_root = evidence_root / "candidate"
        parent_root.mkdir(parents=True)
        candidate_root.mkdir(parents=True)

        def bind(row: dict[str, object]) -> None:
            member = row["member"]
            row["parent_sha"] = self.parent
            row["candidate_sha"] = self.candidate
            row["sha"] = lineage[f"{member}_sha"]
            row["tree"] = lineage[f"{member}_tree"]
            row["runner_sha256"] = lineage["runner_sha256"]
            row["client_sha256"] = lineage[f"{member}_client_sha256"]
            row["server_sha256"] = lineage[f"{member}_server_sha256"]

        rows: dict[tuple[str, int], dict[str, object]] = {}
        for pair in range(1, 6):
            for member in ("parent", "candidate"):
                row = synthetic_scale_row(
                    pair=pair,
                    member=member,
                    full_completions=(
                        101 if member == "candidate" and pair <= 4 else 100
                    ),
                )
                bind(row)
                rows[(member, pair)] = row

        def write_rows() -> None:
            for (member, pair), row in rows.items():
                root = parent_root if member == "parent" else candidate_root
                (root / f"scale-{member}-{pair}.jsonl").write_text(
                    json.dumps(row, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )

        write_rows()
        plan_path = evidence_root / "plan.json"
        output = evidence_root / "summary.json"
        markdown = evidence_root / "summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent_root,
                "candidate_root": candidate_root,
                "parent_sha": self.parent,
                "candidate_sha": self.candidate,
                "policy": POLICY_PATH,
                "scale_policy": SCALE_POLICY_PATH,
                "repository": self.repository,
                "output": output,
                "markdown": markdown,
            },
        )()

        self.assertEqual(CONTROL.run_summary_command(arguments), 0)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "SCALE_SAFETY_PASS",
        )
        self.assertIn(
            "SCALE_SAFETY_PASS", markdown.read_text(encoding="utf-8")
        )

        safety = rows[("candidate", 1)]
        completions = list(safety["scale"]["traffic"]["full_flow_completions"])
        completions[0] = 0
        rewrite_scale_full_completions(safety, completions)
        write_rows()
        self.assertEqual(CONTROL.run_summary_command(arguments), 3)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "SCALE_SAFETY_FAIL",
        )
        self.assertIn(
            "SCALE_SAFETY_FAIL", markdown.read_text(encoding="utf-8")
        )

        safety["scale"]["traffic"]["full_checked_bytes"] += 1
        write_rows()
        self.assertEqual(CONTROL.run_summary_command(arguments), 2)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "INVALID_EVIDENCE",
        )
        self.assertIn("INVALID_EVIDENCE", markdown.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
