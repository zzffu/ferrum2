import copy
import json
from decimal import Decimal

from tests.performance_candidate._linux_summary_support import LinuxSummaryFixture
from tests.performance_candidate._shared_fixture import synthetic_policy
from tools.performance_candidate import json_contract
from tools.performance_candidate import pairing as paired_stats
from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import decision as linux_decision
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy

class LinuxSummaryTests(LinuxSummaryFixture):
    def test_diagnostic_result_is_inconclusive_without_adoption_claim(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        self.assertFalse(summary["adoption_claim"])
        self.assertIsNone(summary["workflow_failure_reason"])
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
        self.assertEqual(summary["status"], "INCONCLUSIVE")
        self.assertEqual(summary["scenarios"][0]["losses"], 6)
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

    def test_six_pair_median_is_calculated_after_each_pair_delta(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair, value in enumerate((110, 130, 120, 120, 130, 110), start=1):
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
        for pair, value in enumerate((110, 90, 100, 110, 90, 100), start=1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row, value=value: row.update(value=value),
            )
        scenario = self.summarize(plan, parent, candidate)["scenarios"][0]
        self.assertEqual(
            (scenario["wins"], scenario["losses"], scenario["ties"]),
            (2, 2, 2),
        )
        self.assertEqual(scenario["median_improvement_percent"], 0.0)

    def test_observed_direction_spread_and_outlier_warnings_are_descriptive(
        self,
    ) -> None:
        cases = (
            ((110, 120, 130, 110, 120, 130), "positive", set()),
            ((90, 80, 70, 90, 80, 70), "negative", set()),
            ((90, 100, 110, 90, 100, 110), "mixed", {"MIXED_DIRECTION"}),
            (
                (4, 101, 102, 4, 101, 102),
                "mixed",
                {"MIXED_DIRECTION", "EXTREME_NEGATIVE_PAIR", "HIGH_VARIANCE"},
            ),
            (
                (99, 101, 196, 99, 101, 196),
                "mixed",
                {"MIXED_DIRECTION", "EXTREME_POSITIVE_PAIR", "HIGH_VARIANCE"},
            ),
            ((100, 100, 100, 100, 100, 100), "neutral", set()),
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
                self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
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
            for pair, value in enumerate((4, 110, 110, 4, 110, 110), start=1)
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
            paired_stats._median(
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
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertEqual(scenarios["tcp-stream-64k"]["wins"], 6)
        self.assertEqual(scenarios["tcp-bulk"]["losses"], 6)
        self.assertEqual(scenarios["tcp-bulk"]["median_improvement_percent"], -96.0)

    def test_negative_guard_median_is_inconclusive_even_with_one_positive_pair(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", 1, "candidate"): 4,
            ("tcp-bulk", 2, "candidate"): 4,
            ("tcp-bulk", 3, "candidate"): 4,
            ("tcp-bulk", 4, "candidate"): 4,
            ("tcp-bulk", 5, "candidate"): 4,
            ("tcp-bulk", 6, "candidate"): 101,
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        guard = next(
            item for item in summary["scenarios"] if item["scenario"] == "tcp-bulk"
        )
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertEqual(guard["median_improvement_percent"], -96.0)

    def test_tiny_negative_and_positive_medians_are_inconclusive_without_thresholds(
        self,
    ) -> None:
        for candidates, observed in (
            ((99_950, 99_900, 100_040, 99_950, 99_900, 100_040), "mixed"),
            ((100_050, 100_100, 99_960, 100_050, 100_100, 99_960), "mixed"),
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
                self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
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
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(summary["adoption_claim"])

    def test_tcp_frame_capacity_dry_run_requires_every_primary_and_guard(self) -> None:
        plan = self.plan("qualification", "tcp-frame-capacity")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["scenario_group"], "tcp-frame-capacity")
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertEqual(len(summary["primary_results"]), 2)
        self.assertEqual(len(summary["guard_results"]), 3)

        for entry in plan["scenarios"]:
            with self.subTest(missing=entry["scenario"]):
                _root, missing_parent, missing_candidate = self.roots()
                self.populate(plan, missing_parent, missing_candidate)
                for evidence_root in (missing_parent, missing_candidate):
                    for path in evidence_root.glob(f"{entry['scenario']}-*.jsonl"):
                        path.unlink()
                with self.assertRaises(json_contract.CandidateControlError) as captured:
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
                markdown = linux_decision.summary_markdown(summary)
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

    def test_calibrated_noise_band_is_accepted(self) -> None:
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
        self.assertEqual(summary["status"], "WITHIN_CALIBRATED_BAND")
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

    def test_six_pair_policy_enforces_adoption_boundaries(self) -> None:
        policy = synthetic_policy()
        cases = (
            (
                "within-noise",
                (101, 101, 101, 101, 101, 101),
                "WITHIN_CALIBRATED_BAND",
                "WITHIN_NOISE",
            ),
            (
                "four-wins",
                (110, 110, 110, 110, 90, 100),
                "CANDIDATE_WIN",
                "CANDIDATE_IMPROVEMENT",
            ),
            (
                "three-wins",
                (110, 110, 110, 90, 90, 100),
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
                    pairs=6,
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

    def test_six_pair_policy_requires_four_losses_for_regression(self) -> None:
        policy = synthetic_policy()
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=policy,
            pairs=6,
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): value
            for pair, value in enumerate((90, 90, 90, 90, 110, 110), start=1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        guard = next(
            item
            for item in summary["scenarios"]
            if item["scenario"] == "tcp-bulk"
        )
        self.assertEqual(summary["status"], "REGRESSION")
        self.assertEqual(guard["losses"], 4)
        self.assertEqual(guard["threshold_decision"], "CONFIRMED_REGRESSION")

        scenario_plan = next(
            item for item in plan["scenarios"] if item["scenario"] == "tcp-bulk"
        )
        # Exercise the minimum-loss branch directly at its decision boundary.
        insufficient = linux_decision._scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=3,
            losses=3,
            median_improvement=Decimal("-10"),
            observed_environment=self.row(plan, "tcp-bulk", 1, "parent")[
                "environment_identity"
            ],
        )
        confirmed = linux_decision._scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=2,
            losses=4,
            median_improvement=Decimal("-10"),
            observed_environment=self.row(plan, "tcp-bulk", 1, "parent")[
                "environment_identity"
            ],
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
            decision_policy=synthetic_policy(minimum_wins=5),
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-stream-64k", pair, "candidate"): value
            for pair, value in enumerate((110, 90, 110, 110, 100, 100), start=1)
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
                self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
                self.assertFalse(summary["adoption_claim"])

    def test_regression_threshold_without_minimum_losses_is_inconclusive(self) -> None:
        plan = self.plan(
            "qualification",
            "tcp-stream-64k",
            decision_policy=synthetic_policy(minimum_losses=4),
        )
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): value
            for pair, value in enumerate((90, 90, 90, 120, 100, 100), start=1)
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
        with self.assertRaisesRegex(json_contract.CandidateControlError, "incomplete"):
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
                with self.assertRaises(json_contract.CandidateControlError):
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
                with self.assertRaises(json_contract.CandidateControlError):
                    self.summarize(plan, parent, candidate)

    def test_wrong_metric_and_request_p99_are_invalid(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        self.rewrite(
            candidate / "tcp-bulk-candidate-1.jsonl",
            lambda row: row.update(metric="p99_nanoseconds"),
        )
        with self.assertRaisesRegex(json_contract.CandidateControlError, "metric"):
            self.summarize(plan, parent, candidate)

        plan = self.plan("diagnostic", "tcp-request-1k")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        self.rewrite(
            candidate / "tcp-request-1k-candidate-1.jsonl",
            lambda row: row.update(p99_nanoseconds=91),
        )
        with self.assertRaisesRegex(json_contract.CandidateControlError, "p99"):
            self.summarize(plan, parent, candidate)

    def test_duplicate_json_keys_are_invalid(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        path = candidate / "tcp-bulk-candidate-1.jsonl"
        text = path.read_text(encoding="utf-8").strip()
        path.write_text(text[:-1] + ', "status": "PASS"}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "duplicate JSON key"
        ):
            self.summarize(plan, parent, candidate)

    def test_summary_command_writes_outputs_before_invalid_evidence_failure(
        self,
    ) -> None:
        root, parent, candidate = self.roots()
        policy_path, policy = self.materialize_policy(
            root, copy.deepcopy(linux_policy.UNCALIBRATED_POLICY)
        )
        plan = self.plan(
            "qualification", "tcp-stream-64k", decision_policy=policy
        )
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        linux_plan.write_plan(plan_path, plan)
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
        self.assertEqual(linux_decision.run_summary_command(arguments), 2)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["schema_version"], linux_catalog.SUMMARY_SCHEMA_VERSION)
        self.assertEqual(summary["status"], "INVALID")
        self.assertEqual(summary["mode"], "qualification")
        self.assertEqual(summary["scenario_group"], "tcp-throughput")
        self.assertEqual(
            set(summary["missing_scenarios"]), set(summary["mandatory_scenarios"])
        )
        rendered = markdown.read_text(encoding="utf-8")
        self.assertIn("INVALID", rendered)
        self.assertIn("tcp-throughput", rendered)
        self.assertIn("Missing scenarios", rendered)

    def test_summary_command_writes_valid_machine_and_markdown_results(self) -> None:
        root, parent, candidate = self.roots()
        policy_path, policy = self.materialize_policy(
            root, copy.deepcopy(linux_policy.UNCALIBRATED_POLICY)
        )
        plan = self.plan("diagnostic", "tcp-bulk", decision_policy=policy)
        self.populate(plan, parent, candidate)
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        linux_plan.write_plan(plan_path, plan)
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
        self.assertEqual(linux_decision.run_summary_command(arguments), 0)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["schema_version"], linux_catalog.SUMMARY_SCHEMA_VERSION)
        self.assertEqual(summary["status"], "INCONCLUSIVE")
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

    def test_summary_command_fails_closed_when_calibration_is_required(self) -> None:
        root, parent, candidate = self.roots()
        policy_path, policy = self.materialize_policy(
            root, copy.deepcopy(linux_policy.UNCALIBRATED_POLICY)
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
        linux_plan.write_plan(plan_path, plan)
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
        self.assertEqual(linux_decision.run_summary_command(arguments), 4)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "CALIBRATION_REQUIRED",
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
                linux_plan.write_plan(plan_path, plan)
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
                self.assertEqual(linux_decision.run_summary_command(arguments), expected_exit)
                self.assertEqual(
                    json.loads(output.read_text(encoding="utf-8"))["status"],
                    expected_status,
                )
