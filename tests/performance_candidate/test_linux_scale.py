import copy
import json
import pathlib
import tempfile
import unittest
from fractions import Fraction

from tests.performance_candidate._shared_fixture import (
    POLICY_PATH,
    SCALE_POLICY_PATH,
    rewrite_scale_full_completions,
    rewrite_scale_resource_increments,
    synthetic_scale_lineage,
    synthetic_scale_row,
)
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy
from tools.performance_candidate.linux import scale as linux_scale
from tools.performance_candidate.linux import scale_decision, scale_trial
from tools.performance_candidate.linux import trial as linux_trial

class ScaleControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = linux_scale.load_scale_safety_policy(SCALE_POLICY_PATH)
        self.plan = linux_plan.create_plan(
            mode="qualification",
            selection=linux_scale.SCALE_SCENARIO,
            warmup_seconds="10",
            active_seconds="30",
            pairs="6",
            decision_policy=linux_policy.load_decision_policy(POLICY_PATH),
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
            for pair in range(1, 7)
        ]
        rows = {
            (linux_scale.SCALE_SCENARIO, row["pair"], row["member"]): row
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
        return scale_decision._summarize_scale_evidence(
            plan=self.plan,
            rows=rows,
            parent_sha="1" * 40,
            candidate_sha="2" * 40,
            member_identity=member_identity,
            identity_fields=identity_fields,
            evidence_files=[],
        )

    def trial_failures(self, row: dict[str, object]) -> set[str]:
        _observation, failures = scale_decision._scale_trial_observation(row, self.policy)
        return set(failures)

    def test_scale_plan_is_qualification_only_and_requires_exact_recipe(self) -> None:
        self.assertEqual(self.plan["scenario_group"], linux_scale.SCALE_SCENARIO)
        self.assertFalse(self.plan["adoption_eligible"])
        self.assertEqual(self.plan["scale_safety_policy"], self.policy)
        for mode, warmup, active, pairs in (
            ("diagnostic", "10", "30", "6"),
            ("qualification", "5", "30", "6"),
            ("qualification", "10", "15", "6"),
            ("qualification", "10", "30", "5"),
        ):
            with self.subTest(values=(mode, warmup, active, pairs)):
                with self.assertRaises(json_contract.CandidateControlError):
                    linux_plan.create_plan(
                        mode=mode,
                        selection=linux_scale.SCALE_SCENARIO,
                        warmup_seconds=warmup,
                        active_seconds=active,
                        pairs=pairs,
                        decision_policy=linux_policy.load_decision_policy(POLICY_PATH),
                        scale_safety_policy=self.policy,
                        scale_lineage=synthetic_scale_lineage(),
                    )

    def test_scale_vectors_fairness_quantiles_and_signed_rss_recompute(self) -> None:
        row = synthetic_scale_row(pair=1, member="parent")
        derived = scale_trial._validate_scale_evidence(row)
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
        ratio = scale_trial._recompute_scale_fairness(ratio_vector)
        self.assertEqual(ratio["p01_bytes"], 16_384)
        self.assertEqual(ratio["median_bytes"], 32_768)
        self.assertEqual(ratio["p01_median_fraction"], Fraction(1, 2))
        jain_boundary = scale_trial._recompute_scale_fairness(
            [0] * 1_000 + [32_768] * 9_000
        )
        self.assertEqual(jain_boundary["jain_fraction"], Fraction(9, 10))

    def test_scale_safety_requires_four_throughput_wins_without_adoption(self) -> None:
        candidates = [
            synthetic_scale_row(
                pair=pair,
                member="candidate",
                full_completions=101 if pair <= 4 else 100,
            )
            for pair in range(1, 7)
        ]
        passed = self.summarize_rows(candidates)
        self.assertEqual(passed["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(passed["adoption_claim"])
        self.assertEqual(passed["scale_safety"]["throughput_wins"], 4)

        failed = self.summarize_rows(
            [
                synthetic_scale_row(
                    pair=pair,
                    member="candidate",
                    full_completions=101 if pair <= 3 else 100,
                )
                for pair in range(1, 7)
            ]
        )
        self.assertEqual(failed["status"], "REGRESSION")
        self.assertIn("THROUGHPUT_WINS", failed["scale_safety"]["failures"])

    def test_zero_flow_is_valid_evidence_but_a_hard_scale_failure(self) -> None:
        candidates = [
            synthetic_scale_row(
                pair=pair,
                member="candidate",
                full_completions=101,
                starve_first=pair == 1,
            )
            for pair in range(1, 7)
        ]
        summary = self.summarize_rows(candidates)
        self.assertEqual(summary["status"], "REGRESSION")
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
                    for pair in range(1, 7)
                ]
                mutation(candidates[0])
                summary = self.summarize_rows(candidates)
                self.assertEqual(summary["status"], "REGRESSION")
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
                        for pair in range(1, 7)
                    ]
                )
                self.assertEqual(at_limit["status"], "CALIBRATION_REQUIRED")
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
                        for pair in range(1, 7)
                    ]
                )
                self.assertEqual(above["status"], "REGRESSION")
                self.assertIn(expected, above["scale_safety"]["failures"])
        negative = self.summarize_rows(
            [
                synthetic_scale_row(
                    pair=pair,
                    member="candidate",
                    full_completions=101,
                    client_touch_extra_kib=-500,
                )
                for pair in range(1, 7)
            ]
        )
        self.assertEqual(negative["status"], "CALIBRATION_REQUIRED")

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

        pair_floor = self.summarize_rows(candidates([90, 101, 101, 101, 101, 101]))
        self.assertEqual(pair_floor["status"], "CALIBRATION_REQUIRED")
        below_pair_floor = self.summarize_rows(
            candidates([89, 101, 101, 101, 101, 101])
        )
        self.assertIn(
            "PAIR_1_THROUGHPUT_FLOOR",
            below_pair_floor["scale_safety"]["failures"],
        )

        median_equal = self.summarize_rows(candidates([99, 99, 100, 100, 101, 101]))
        self.assertNotIn(
            "MEDIAN_THROUGHPUT", median_equal["scale_safety"]["failures"]
        )
        median_below = self.summarize_rows(candidates([99, 99, 99, 99, 101, 101]))
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
        with self.assertRaisesRegex(json_contract.CandidateControlError, "exactly 10000"):
            scale_trial._validate_scale_evidence(malformed)
        with tempfile.TemporaryDirectory(prefix="ferrum2-scale-reader-") as directory:
            root = pathlib.Path(directory)
            path = root / "scale.jsonl"
            maximum = copy.deepcopy(row)
            maximum["scale"]["traffic"]["partial_flow_bytes"] = [
                json_contract.U64_MAX
            ] * 1_000
            maximum["scale"]["traffic"]["full_flow_bytes"] = [
                json_contract.U64_MAX
            ] * 10_000
            maximum["scale"]["traffic"]["full_flow_completions"] = [
                json_contract.U64_MAX
            ] * 10_000
            compact = json.dumps(maximum, separators=(",", ":"))
            self.assertLessEqual(len(compact.encode()), linux_scale.SCALE_TRIAL_MAX_BYTES)
            self.assertGreater(len(compact.encode()), linux_trial.REGULAR_TRIAL_MAX_BYTES)
            path.write_text(compact + "\n", encoding="utf-8")
            self.assertEqual(linux_trial._read_trial(path)["scenario"], linux_scale.SCALE_SCENARIO)
            path.write_bytes(b" " * (linux_scale.SCALE_TRIAL_MAX_BYTES + 2))
            with self.assertRaisesRegex(json_contract.CandidateControlError, "byte bound"):
                linux_trial._read_trial(path)
            path.write_text("[" * 2_000 + "]" * 2_000 + "\n", encoding="utf-8")
            with self.assertRaises(json_contract.CandidateControlError):
                linux_trial._read_trial(path)
            path.write_text('{"value":' + "9" * 100 + "}\n", encoding="utf-8")
            with self.assertRaises(json_contract.CandidateControlError):
                linux_trial._read_trial(path)
