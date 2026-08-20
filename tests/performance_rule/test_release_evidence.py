import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "tests" / "performance_rule" / "release-qualification.json"
AA_REPORT = ROOT / "tests" / "performance_rule" / "release-aa.json"
AB_REPORT = ROOT / "tests" / "performance_rule" / "release-ab.json"
LEGACY_AA_REPORT = (
    ROOT / "tests" / "performance_rule" / "release-aa-v2-p99-diagnostic.json"
)
V3_AA_REPORT = (
    ROOT / "tests" / "performance_rule" / "release-aa-v3-all-suite-median.json"
)
V3_AB_REPORT = (
    ROOT
    / "tests"
    / "performance_rule"
    / "release-ab-v3-all-suite-median-diagnostic.json"
)
RUNNER_SCHEMA = "ferrum2.rule-qualification.v1"
LEGACY_CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v2"
V3_CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v3"
CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v4"
LEGACY_THRESHOLD_POLICY_VERSION = "outer-median-and-p99-gates.v1"
V3_THRESHOLD_POLICY_VERSION = "outer-median-gates.v2"
THRESHOLD_POLICY_VERSION = "section-5.7-match-set-median-gates.v3"
PINNED_V2_AA_SHA256 = (
    "2b8f08988112c2142294a4266a24c8d7672d89f2387a91f4b460b52daaf7d4e9"
)
PINNED_V3_AA_SHA256 = (
    "8e795edfc61c2328cb1f84fe0fd65f8ec0236d210078fb23c11e221cba87d394"
)
PINNED_V3_AB_SHA256 = (
    "679a85722049e5dc0ea9fa601807623defc267be064d9bb4694aae0bf59719f3"
)
PINNED_V3_AB_RAW_SHA256 = (
    "f1df276c3c9723190e70caa0129c61ddceb27a89143d0d2f2dc7a532cf372283"
)
PINNED_PARENT_SHA256 = (
    "3193b2ade54c634d5b96c11f448d90d9f7c843ed89c30e1da56acbbf617112c9"
)
EXPECTED_RUNNER_ARGUMENTS = [
    "--profile",
    "smoke",
    "--samples",
    "501",
    "--workspace-root",
    ".",
]
SCALES = (100, 1_000, 10_000, 100_000)
CASES = {
    "exact": ("hit", "miss"),
    "suffix": ("hit", "miss"),
    "keyword": ("hit", "miss"),
    "cidr_ipv4": ("hit", "miss"),
    "cidr_ipv6": ("hit", "miss"),
    "mixed": ("domain_hit", "ip_hit", "domain_miss", "ip_miss"),
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_sha256(value):
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def assert_alternating_controller_evidence(test, report, mode):
    test.assertEqual(report["schema"], CONTROL_SCHEMA)
    test.assertEqual(report["mode"], mode)
    test.assertEqual(report["pairs"], 6)
    test.assertGreaterEqual(report["pairs"], 5)
    test.assertEqual(report["runner_arguments"], EXPECTED_RUNNER_ARGUMENTS)
    test.assertEqual(report["parent_runner_sha256"], PINNED_PARENT_SHA256)
    test.assertRegex(report["candidate_runner_sha256"], r"^[0-9a-f]{64}$")
    test.assertTrue(report["scenario_ids"])
    test.assertEqual(len(report["scenario_ids"]), len(set(report["scenario_ids"])))
    test.assertEqual(sorted(report["scenario_suites"]), report["scenario_ids"])
    test.assertEqual(
        report["execution_policy"],
        {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": "high",
        },
    )
    test.assertTrue(report["threshold_policy"]["enforced"])
    test.assertEqual(
        report["threshold_policy"]["version"], THRESHOLD_POLICY_VERSION
    )
    test.assertEqual(
        report["threshold_policy"]["gate_metric"],
        "cross_process_median_p50_match_set_only",
    )
    test.assertEqual(
        report["threshold_policy"]["suite_policy"],
        {
            "match_set": {
                "scope_authority": "plan.section_5_7",
                "median_classification": "hard_gate",
            },
            "route_program": {
                "scope_authority": "plan.section_17_2",
                "median_classification": "observed_cross_process",
            },
            "dns_policy": {
                "scope_authority": "plan.section_17_3",
                "median_classification": "observed_cross_process",
            },
        },
    )
    test.assertEqual(report["threshold_policy"]["hard_gate_suites"], ["match_set"])
    test.assertEqual(
        report["threshold_policy"]["observed_suites"],
        ["route_program", "dns_policy"],
    )
    test.assertEqual(report["threshold_policy"]["local_target_percent"], 5.0)
    test.assertEqual(report["threshold_policy"]["noisy_gate_ceiling_percent"], 10.0)
    test.assertEqual(report["threshold_policy"]["p99_parity_target_percent"], 15.0)
    test.assertEqual(
        report["threshold_policy"]["p99_classification"],
        "observed_cross_process",
    )
    test.assertFalse(report["threshold_policy"]["p99_gate_applicable"])
    test.assertEqual(
        report["threshold_policy"]["p99_gate_owner"],
        "final_candidate_in_process_paired_parity",
    )
    test.assertTrue(report["threshold_policy"]["gate_passed"])
    test.assertEqual(report["threshold_policy"]["decision"], "passed")
    test.assertTrue(report["comparisons"])
    by_suite = {
        suite: [row for row in report["comparisons"] if row["suite"] == suite]
        for suite in ("match_set", "route_program", "dns_policy")
    }
    test.assertEqual({suite: len(rows) for suite, rows in by_suite.items()}, {
        "match_set": 44,
        "route_program": 36,
        "dns_policy": 11,
    })
    test.assertEqual(report["threshold_policy"]["hard_gate_comparison_count"], 44)
    test.assertEqual(report["threshold_policy"]["observed_comparison_count"], 47)
    for comparison in report["comparisons"]:
        suite = comparison["suite"]
        test.assertEqual(report["scenario_suites"][comparison["id"]], suite)
        test.assertEqual(comparison["p99_reference_percent"], 15.0)
        test.assertEqual(
            comparison["p99_classification"], "observed_cross_process"
        )
        test.assertFalse(comparison["p99_gate_applicable"])
        test.assertEqual(comparison["p99_decision"], "observed")
        if suite == "match_set":
            test.assertTrue(comparison["median_gate_applicable"])
            test.assertEqual(comparison["median_classification"], "hard_gate")
            test.assertEqual(comparison["median_decision"], "passed")
            test.assertEqual(comparison["decision"], "passed")
        else:
            test.assertFalse(comparison["median_gate_applicable"])
            test.assertEqual(
                comparison["median_classification"], "observed_cross_process"
            )
            test.assertIsNone(comparison["median_limit_percent"])
            test.assertEqual(comparison["median_decision"], "observed")
            test.assertEqual(comparison["decision"], "observed")
    observed_summary = report["threshold_policy"]["observed_suite_summary"]
    for suite in ("route_program", "dns_policy"):
        rows = by_suite[suite]
        test.assertEqual(observed_summary[suite]["comparison_count"], len(rows))
        test.assertEqual(
            observed_summary[suite]["max_absolute_median_p50_delta_percent"],
            max(abs(row["median_p50_delta_percent"]) for row in rows),
        )
        test.assertEqual(
            observed_summary[suite]["max_absolute_median_p99_delta_percent"],
            max(abs(row["median_p99_delta_percent"]) for row in rows),
        )

    expected_trace = []
    for pair_index in range(report["pairs"]):
        roles = (
            ("parent", "candidate")
            if pair_index % 2 == 0
            else ("candidate", "parent")
        )
        for order_index, role in enumerate(roles, 1):
            expected_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index,
                    "role": role,
                    "runner_sha256": (
                        report["parent_runner_sha256"]
                        if role == "parent"
                        else report["candidate_runner_sha256"]
                    ),
                }
            )
    test.assertEqual(report["execution_trace"], expected_trace)
    test.assertEqual(len(report["raw_pairs"]), report["pairs"])
    expected_ids = set(report["scenario_ids"])
    for pair in report["raw_pairs"]:
        test.assertEqual(set(pair), {"parent", "candidate"})
        for role in ("parent", "candidate"):
            raw = pair[role]
            expected_sha = (
                report["parent_runner_sha256"]
                if role == "parent"
                else report["candidate_runner_sha256"]
            )
            test.assertEqual(raw["schema"], RUNNER_SCHEMA)
            test.assertEqual(raw["runner"]["sha256"], expected_sha)
            test.assertEqual(raw["configuration"]["samples"], 501)
            test.assertTrue(raw["correctness_passed"])
            test.assertTrue(raw["allocation_gate_passed"])
            test.assertTrue(raw["parity_gate_passed"])
            test.assertTrue(raw["thresholds_passed"])
            test.assertEqual(
                raw["measurement_policy"]["p99_parity_target_percent"], 15.0
            )
            test.assertEqual(
                {measurement["id"] for measurement in raw["measurements"]},
                expected_ids,
            )
            test.assertEqual(
                {
                    measurement["id"]: measurement["suite"]
                    for measurement in raw["measurements"]
                },
                report["scenario_suites"],
            )
            test.assertTrue(
                all(
                    len(measurement["samples_ns_per_op"]) == 501
                    for measurement in raw["measurements"]
                )
            )


def assert_qualification_source_binding(test, qualification, ab):
    test.assertEqual(qualification["schema"], RUNNER_SCHEMA)
    test.assertEqual(qualification["profile"], "qualification")
    test.assertEqual(ab["schema"], CONTROL_SCHEMA)
    test.assertEqual(ab["mode"], "parent_candidate")

    runner = qualification["runner"]
    test.assertRegex(runner["sha256"], r"^[0-9a-f]{64}$")
    test.assertGreater(runner["bytes"], 0)
    test.assertEqual(runner["sha256"], ab["candidate_runner_sha256"])

    repository = qualification["repository"]
    test.assertRegex(repository["git_head"], r"^[0-9a-f]{40}$")
    test.assertRegex(repository["git_tree"], r"^[0-9a-f]{40}$")
    test.assertIn(repository["tree_state"], ("clean", "dirty"))
    test.assertIs(type(repository["changed_entries"]), int)
    test.assertGreaterEqual(repository["changed_entries"], 0)
    test.assertRegex(repository["status_sha256"], r"^[0-9a-f]{64}$")
    if repository["tree_state"] == "clean":
        test.assertEqual(repository["changed_entries"], 0)
    else:
        test.assertGreater(repository["changed_entries"], 0)

    environment = qualification["environment"]
    for field in ("os", "architecture", "family", "timer", "build_profile"):
        test.assertIsInstance(environment[field], str)
        test.assertTrue(environment[field].strip())
    test.assertIs(type(environment["logical_cpus"]), int)
    test.assertGreater(environment["logical_cpus"], 0)
    test.assertIsInstance(environment["rustc_version"], str)
    test.assertRegex(environment["rustc_version"], r"^rustc 1\.97\.1\b")
    test.assertEqual(environment["timer"], "std::time::Instant")
    test.assertEqual(environment["build_profile"], "release")

    policy = qualification["measurement_policy"]
    test.assertTrue(policy["retained_samples"])
    test.assertTrue(policy["thresholds_enforced_by_runner"])
    test.assertGreaterEqual(policy["minimum_reported_batch_nanoseconds"], 100_000)
    test.assertEqual(policy["p99_parity_target_percent"], 15.0)


def assert_final_candidate_p99_parity_gate(test, qualification, ab):
    test.assertEqual(
        qualification["runner"]["sha256"], ab["candidate_runner_sha256"]
    )
    test.assertTrue(qualification["parity_gate_passed"])
    test.assertTrue(qualification["thresholds_passed"])
    applicable = [
        row
        for row in qualification["parity_observations"]
        if row["performance_gate_applicable"] is True
    ]
    test.assertTrue(applicable)
    for row in applicable:
        test.assertEqual(row["suite"], "match_set")
        test.assertEqual(row["median_limit_percent"], 5.0)
        test.assertLessEqual(abs(row["median_delta_percent"]), 5.0)
        test.assertEqual(row["p99_limit_percent"], 15.0)
        test.assertLessEqual(abs(row["p99_delta_percent"]), 15.0)
        test.assertEqual(row["decision"], "passed")
    observed = [
        row
        for row in qualification["parity_observations"]
        if row["performance_gate_applicable"] is False
    ]
    test.assertTrue(observed)
    for row in observed:
        test.assertIn(row["suite"], ("route_program", "dns_policy"))
        test.assertEqual(row["decision"], "observed")


class ReleaseEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_generated_binary_srs_matrix_has_complete_gated_evidence(self):
        self.assertEqual(self.report["profile"], "qualification")
        self.assertTrue(self.report["configuration"]["includes_100k"])
        fixtures = {fixture["name"]: fixture for fixture in self.report["fixtures"]}
        measurements = {row["id"]: row for row in self.report["measurements"]}
        parity = {
            row["baseline_id"]: row for row in self.report["parity_observations"]
        }

        for scale in SCALES:
            for kind, cases in CASES.items():
                fixture_name = f"generated-{kind}-{scale}.srs"
                fixture = fixtures[fixture_name]
                self.assertEqual(
                    fixture["provenance"],
                    "deterministic_runner_generated_canonical_srs_v2",
                )
                self.assertEqual(fixture["srs_version"], 2)
                self.assertGreater(fixture["bytes"], 0)
                self.assertRegex(fixture["sha256"], re.compile(r"^[0-9a-f]{64}$"))
                statistics = fixture["statistics"]
                self.assertEqual(statistics["rules"], 1)
                self.assertEqual(
                    statistics["exact_domains"]
                    + statistics["domain_suffixes"]
                    + statistics["domain_keywords"]
                    + statistics["ip_cidrs"],
                    scale,
                )

                for case in cases:
                    scenario = f"{kind}/{case}"
                    baseline_id = (
                        f"match_set/synthetic_srs/{fixture_name}/{scenario}"
                    )
                    candidate_id = f"match_set/binary_srs/{fixture_name}/{scenario}"
                    baseline = measurements[baseline_id]
                    candidate = measurements[candidate_id]
                    for row in (baseline, candidate):
                        self.assertEqual(row["fixture"], fixture_name)
                        self.assertEqual(row["compiled_entries"], scale)
                        self.assertGreater(row["build_nanoseconds"], 0)
                        self.assertGreater(row["compiled_memory_bytes"], 0)
                        self.assertTrue(row["allocation_gate_applicable"])
                        self.assertTrue(row["allocation_gate_passed"])
                        self.assertEqual(row["allocations_per_op"], 0.0)
                        self.assertEqual(row["reallocations_per_op"], 0.0)
                    self.assertEqual(
                        baseline["timing_pair_id"], candidate["timing_pair_id"]
                    )
                    self.assertEqual(
                        baseline["actual_iterations_per_sample"],
                        candidate["actual_iterations_per_sample"],
                    )
                    observation = parity[baseline_id]
                    self.assertEqual(observation["candidate_id"], candidate_id)
                    self.assertTrue(observation["performance_gate_applicable"])
                    self.assertEqual(observation["decision"], "passed")

    def test_pinned_real_srs_fixtures_remain_in_the_report(self):
        fixtures = {fixture["name"]: fixture for fixture in self.report["fixtures"]}
        for name in ("ads.srs", "ai.srs", "cn.srs", "cnip.srs"):
            self.assertEqual(fixtures[name]["provenance"], "pinned_repository_fixture")

    def test_full_qualification_owns_p99_gate_and_is_bound_to_final_ab_candidate(self):
        self.assertTrue(AB_REPORT.is_file(), "release A/B evidence is missing")
        ab = json.loads(AB_REPORT.read_text(encoding="utf-8"))
        assert_qualification_source_binding(self, self.report, ab)
        assert_final_candidate_p99_parity_gate(self, self.report, ab)


class EvidenceContractFixtureTests(unittest.TestCase):
    def test_qualification_binding_and_workspace_fingerprint_contract(self):
        candidate_sha = "a" * 64
        qualification = {
            "schema": RUNNER_SCHEMA,
            "profile": "qualification",
            "runner": {"sha256": candidate_sha, "bytes": 1},
            "repository": {
                "git_head": "b" * 40,
                "git_tree": "c" * 40,
                "tree_state": "dirty",
                "changed_entries": 1,
                "status_sha256": "d" * 64,
            },
            "environment": {
                "os": "windows",
                "architecture": "x86_64",
                "family": "windows",
                "logical_cpus": 1,
                "cpu_model": "fixture",
                "rustc_version": "rustc 1.97.1 (fixture)",
                "timer": "std::time::Instant",
                "build_profile": "release",
            },
            "measurement_policy": {
                "retained_samples": True,
                "thresholds_enforced_by_runner": True,
                "minimum_reported_batch_nanoseconds": 100_000,
                "p99_parity_target_percent": 15.0,
            },
        }
        ab = {
            "schema": CONTROL_SCHEMA,
            "mode": "parent_candidate",
            "candidate_runner_sha256": candidate_sha,
        }
        assert_qualification_source_binding(self, qualification, ab)

    def test_final_candidate_p99_gate_contract_is_fail_closed(self):
        candidate_sha = "a" * 64
        qualification = {
            "runner": {"sha256": candidate_sha},
            "parity_gate_passed": True,
            "thresholds_passed": True,
            "parity_observations": [
                {
                    "performance_gate_applicable": True,
                    "suite": "match_set",
                    "median_limit_percent": 5.0,
                    "median_delta_percent": 5.0,
                    "p99_limit_percent": 15.0,
                    "p99_delta_percent": -15.0,
                    "decision": "passed",
                },
                {
                    "performance_gate_applicable": False,
                    "suite": "route_program",
                    "p99_limit_percent": 15.0,
                    "p99_delta_percent": 200.0,
                    "decision": "observed",
                },
            ],
        }
        ab = {"candidate_runner_sha256": candidate_sha}
        assert_final_candidate_p99_parity_gate(self, qualification, ab)

        qualification["parity_observations"][0]["p99_delta_percent"] = 15.01
        with self.assertRaises(AssertionError):
            assert_final_candidate_p99_parity_gate(self, qualification, ab)


class AlternatingReleaseEvidenceTests(unittest.TestCase):
    def test_v4_aa_reclassifies_preserved_v3_scope_without_changing_raw_pairs(self):
        self.assertTrue(AA_REPORT.is_file(), "release A/A evidence is missing")
        self.assertTrue(
            V3_AA_REPORT.is_file(), "archived v3 A/A evidence is missing"
        )
        self.assertEqual(sha256_file(V3_AA_REPORT), PINNED_V3_AA_SHA256)
        aa = json.loads(AA_REPORT.read_text(encoding="utf-8"))
        assert_alternating_controller_evidence(self, aa, "aa")
        self.assertEqual(aa["candidate_runner_sha256"], PINNED_PARENT_SHA256)
        self.assertEqual(
            aa["threshold_policy"]["calibration_source"],
            "reclassified_v3_aa_raw_pairs",
        )
        self.assertEqual(
            aa["threshold_policy"]["calibrated_median_limit_percent"], 5.0
        )
        self.assertIsNone(aa["threshold_policy"]["calibration_sha256"])
        provenance = aa["provenance"]
        self.assertEqual(provenance["derivation"], "offline_scope_reclassification")
        self.assertEqual(
            provenance["source_report_artifact"], V3_AA_REPORT.name
        )
        self.assertEqual(provenance["source_report_sha256"], PINNED_V3_AA_SHA256)
        self.assertEqual(provenance["source_schema"], V3_CONTROL_SCHEMA)
        self.assertEqual(
            provenance["source_threshold_policy_version"],
            V3_THRESHOLD_POLICY_VERSION,
        )
        self.assertTrue(provenance["source_gate_passed"])
        self.assertEqual(provenance["source_decision"], "passed")
        self.assertEqual(provenance["source_failed_comparison_count"], 0)
        self.assertEqual(provenance["source_failed_comparison_ids"], [])
        self.assertEqual(provenance["raw_pairs_transform"], "none")
        raw_pairs_sha256 = canonical_json_sha256(aa["raw_pairs"])
        self.assertEqual(provenance["source_raw_pairs_sha256"], raw_pairs_sha256)
        self.assertEqual(
            provenance["reclassified_raw_pairs_sha256"], raw_pairs_sha256
        )
        self.assertEqual(
            provenance["source_comparisons_sha256"],
            canonical_json_sha256(provenance["source_comparisons"]),
        )
        with V3_AA_REPORT.open(encoding="utf-8") as source:
            v3 = json.load(source)
        self.assertEqual(v3["raw_pairs"], aa["raw_pairs"])
        self.assertEqual(
            v3["comparisons"], provenance["source_comparisons"]
        )
        self.assertEqual(
            v3["threshold_policy"], provenance["source_threshold_policy"]
        )
        self.assertEqual(v3["provenance"], provenance["source_provenance"])

    def test_archived_v3_aa_remains_bound_to_original_failed_v2(self):
        self.assertTrue(V3_AA_REPORT.is_file(), "archived v3 A/A is missing")
        self.assertTrue(LEGACY_AA_REPORT.is_file(), "failed v2 A/A is missing")
        self.assertEqual(sha256_file(V3_AA_REPORT), PINNED_V3_AA_SHA256)
        self.assertEqual(sha256_file(LEGACY_AA_REPORT), PINNED_V2_AA_SHA256)
        with V3_AA_REPORT.open(encoding="utf-8") as source:
            v3 = json.load(source)
        provenance = v3["provenance"]
        self.assertEqual(v3["schema"], V3_CONTROL_SCHEMA)
        self.assertEqual(provenance["source_report_artifact"], LEGACY_AA_REPORT.name)
        self.assertEqual(provenance["source_report_sha256"], PINNED_V2_AA_SHA256)
        self.assertEqual(provenance["source_schema"], LEGACY_CONTROL_SCHEMA)
        self.assertEqual(
            provenance["source_threshold_policy_version"],
            LEGACY_THRESHOLD_POLICY_VERSION,
        )
        self.assertFalse(provenance["source_gate_passed"])
        self.assertEqual(provenance["source_decision"], "failed")
        with LEGACY_AA_REPORT.open(encoding="utf-8") as source:
            v2 = json.load(source)
        self.assertEqual(v2["raw_pairs"], v3["raw_pairs"])
        self.assertEqual(v2["comparisons"], provenance["source_comparisons"])
        self.assertEqual(v2["threshold_policy"], provenance["source_threshold_policy"])

    def test_v4_ab_retains_all_19_v3_failures_and_binds_both_calibrations(self):
        self.assertTrue(AB_REPORT.is_file(), "release A/B evidence is missing")
        self.assertTrue(AA_REPORT.is_file(), "release A/A calibration is missing")
        self.assertTrue(V3_AB_REPORT.is_file(), "failed v3 A/B evidence is missing")
        self.assertTrue(V3_AA_REPORT.is_file(), "archived v3 A/A is missing")
        self.assertEqual(sha256_file(V3_AB_REPORT), PINNED_V3_AB_SHA256)
        ab = json.loads(AB_REPORT.read_text(encoding="utf-8"))
        assert_alternating_controller_evidence(self, ab, "parent_candidate")
        self.assertNotEqual(ab["candidate_runner_sha256"], PINNED_PARENT_SHA256)
        self.assertEqual(
            ab["threshold_policy"]["calibration_sha256"], sha256_file(AA_REPORT)
        )
        self.assertEqual(
            Path(ab["threshold_policy"]["calibration_source"]).resolve(),
            AA_REPORT.resolve(),
        )
        provenance = ab["provenance"]
        self.assertEqual(provenance["source_report_artifact"], V3_AB_REPORT.name)
        self.assertEqual(provenance["source_report_sha256"], PINNED_V3_AB_SHA256)
        self.assertEqual(provenance["source_schema"], V3_CONTROL_SCHEMA)
        self.assertFalse(provenance["source_gate_passed"])
        self.assertEqual(provenance["source_decision"], "failed")
        self.assertEqual(provenance["source_failed_comparison_count"], 19)
        self.assertEqual(len(provenance["source_failed_comparison_ids"]), 19)
        self.assertEqual(
            provenance["source_failed_comparison_ids"],
            sorted(
                row["id"]
                for row in provenance["source_comparisons"]
                if row["decision"] == "failed"
            ),
        )
        self.assertEqual(
            provenance["source_raw_pairs_sha256"], PINNED_V3_AB_RAW_SHA256
        )
        self.assertEqual(
            provenance["reclassified_raw_pairs_sha256"],
            PINNED_V3_AB_RAW_SHA256,
        )
        self.assertEqual(
            provenance["source_calibration_artifact"], V3_AA_REPORT.name
        )
        self.assertEqual(
            provenance["source_calibration_sha256"], PINNED_V3_AA_SHA256
        )
        with V3_AB_REPORT.open(encoding="utf-8") as source:
            v3 = json.load(source)
        self.assertEqual(v3["raw_pairs"], ab["raw_pairs"])
        self.assertEqual(v3["comparisons"], provenance["source_comparisons"])
        self.assertEqual(v3["threshold_policy"], provenance["source_threshold_policy"])
        self.assertEqual(
            canonical_json_sha256(v3["raw_pairs"]), PINNED_V3_AB_RAW_SHA256
        )

if __name__ == "__main__":
    unittest.main()
