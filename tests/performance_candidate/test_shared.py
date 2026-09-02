import copy
import pathlib
import re
import tempfile
import unittest

from tests.performance_candidate._shared_fixture import WORKFLOW_PATH
from tools.performance_candidate import json_contract
from tools.performance_candidate import status as performance_status
from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy
from tools.performance_candidate.linux import scale as linux_scale
from tools.performance_candidate.windows_tun import recipe as windows_recipe


class SummaryExitCodeTests(unittest.TestCase):
    def test_diagnostic_measurement_success_does_not_weaken_qualification(self) -> None:
        self.assertEqual(
            performance_status.summary_exit_code(
                mode="diagnostic", status=performance_status.INCONCLUSIVE
            ),
            0,
        )
        self.assertEqual(
            performance_status.summary_exit_code(
                mode="qualification", status=performance_status.INCONCLUSIVE
            ),
            4,
        )
        self.assertEqual(
            performance_status.summary_exit_code(
                mode="diagnostic", status=performance_status.INVALID
            ),
            2,
        )
        self.assertEqual(
            performance_status.summary_exit_code(
                mode="diagnostic", status=performance_status.CANDIDATE_WIN
            ),
            4,
        )


class MeasurementInputTests(unittest.TestCase):
    def test_every_workflow_choice_is_valid(self) -> None:
        for warmup in ("1", "3", "5", "10"):
            for active in ("15", "30", "60"):
                for pairs in ("6",):
                    self.assertEqual(
                        linux_plan.validate_measurement_inputs(warmup, active, pairs),
                        (int(warmup), int(active), int(pairs)),
                    )

    def test_each_measurement_input_rejects_invalid_values_independently(self) -> None:
        cases = (
            ("2", "15", "6", "warmup_seconds"),
            ("1", "45", "6", "active_seconds"),
            ("1", "15", "4", "pairs"),
            ("01", "15", "6", "warmup_seconds"),
            ("one", "15", "6", "warmup_seconds"),
        )
        for warmup, active, pairs, field in cases:
            with self.subTest(field=field, value=(warmup, active, pairs)):
                with self.assertRaisesRegex(json_contract.CandidateControlError, field):
                    linux_plan.validate_measurement_inputs(warmup, active, pairs)


class ClosedJsonInputTests(unittest.TestCase):
    def test_reader_rejects_oversized_input_before_schema_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "oversized.json"
            path.write_bytes(b" " * 17)
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "16-byte bound"
            ):
                json_contract.read_bounded_closed_json(
                    path, maximum_bytes=16, source="synthetic plan"
                )

    def test_reader_rejects_exponent_overflow_as_nonfinite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "overflow.json"
            path.write_text('{"threshold":1e999}', encoding="utf-8")
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "finite number envelope"
            ):
                json_contract.read_bounded_closed_json(
                    path, maximum_bytes=1024, source="synthetic policy"
                )


class ScenarioPlanTests(unittest.TestCase):
    def plan(self, mode: str, scenario: str) -> dict[str, object]:
        return linux_plan.create_plan(
            mode=mode,
            selection=scenario,
            warmup_seconds="3",
            active_seconds="30",
            pairs="6",
            decision_policy=copy.deepcopy(linux_policy.UNCALIBRATED_POLICY),
        )

    def entries(self, mode: str, scenario: str) -> list[tuple[str, str]]:
        return [
            (entry["scenario"], entry["role"])
            for entry in self.plan(mode, scenario)["scenarios"]
        ]

    def test_diagnostic_plan_contains_only_the_selected_scenario(self) -> None:
        for scenario in linux_catalog.SCENARIO_CATALOG:
            with self.subTest(scenario=scenario):
                plan = self.plan("diagnostic", scenario)
                self.assertEqual(plan["schema_version"], linux_plan.PLAN_SCHEMA_VERSION)
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
    def test_dns_concurrency_qualification_has_exact_direct_contract(self) -> None:
        plan = self.plan("qualification", "dns-udp-concurrency")
        self.assertEqual(plan["scenario_group"], "dns")
        self.assertEqual(plan["selected_scenario"], "dns-udp-concurrency")
        self.assertEqual(len(plan["scenarios"]), 1)
        scenario = plan["scenarios"][0]
        self.assertEqual(
            (
                scenario["role"],
                scenario["topology"],
                scenario["application_payload_bytes"],
                scenario["socks_datagram_bytes"],
                scenario["upstream_wire_bytes"],
                scenario["evidence_contract"]["unit"],
            ),
            ("primary", "dns-direct", 46, None, None, "queries_per_second"),
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
        with self.assertRaisesRegex(json_contract.CandidateControlError, "mode"):
            self.plan("adopt", "tcp-bulk")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "selection"):
            self.plan("qualification", "tcp-unknown")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "diagnostic"):
            self.plan("diagnostic", "tcp-frame-capacity")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "diagnostic"):
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
                    json_contract.CandidateControlError,
                    "lifecycle selection is qualification-only",
                ):
                    self.plan("qualification", selection)
        with self.assertRaisesRegex(json_contract.CandidateControlError, "selection"):
            self.plan("qualification", "windows-tun-route-detect")
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "dedicated windows-tun-plan"
        ):
            self.plan("qualification", windows_recipe.WINDOWS_TUN_SELECTION)
        with self.assertRaisesRegex(json_contract.CandidateControlError, "selection"):
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
            set(linux_catalog.SCENARIO_CATALOG)
            | set(linux_catalog.QUALIFICATION_GROUPS)
            | {linux_catalog.FULL_NON_TUN_SELECTION, linux_scale.SCALE_SCENARIO},
        )

    def test_workflow_binds_product_commits_independently_from_controller(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("REQUESTED_CANDIDATE_SHA: ${{ inputs.candidate_sha }}", workflow)
        self.assertIn('CANDIDATE_DIR="$RUNNER_TEMP/ferrum2-candidate"', workflow)
        self.assertNotIn('CANDIDATE_DIR="$GITHUB_WORKSPACE"', workflow)
        self.assertIn(
            'git worktree add --detach "$CANDIDATE_DIR" "$CANDIDATE_SHA"',
            workflow,
        )
        self.assertIn(
            '--repository "$CONTROLLER_DIR" \\\n'
            '              --parent-sha "$PARENT_SHA" \\\n'
            '              --candidate-sha "$CANDIDATE_SHA"',
            workflow,
        )

    def test_workflow_runs_calibrated_matrix_and_preserves_ordinary_modes(
        self,
    ) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("          - calibrated-qualification", workflow)
        self.assertIn("          - qualification", workflow)
        self.assertIn("          - diagnostic", workflow)
        self.assertIn(
            '["tcp-frame-capacity","udp-payload-matrix",'
            '"udp-direct-payload-bounds","dns-udp-concurrency"]',
            workflow,
        )
        self.assertIn("-m tools.performance_candidate schedule", workflow)
        self.assertIn("-m tools.performance_candidate calibrate", workflow)
        self.assertIn("aggregate-full-non-tun:", workflow)
        self.assertIn(
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            workflow,
        )
