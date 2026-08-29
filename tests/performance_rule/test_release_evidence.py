import json
import re
import tempfile
import unittest
from pathlib import Path

from tests.performance_rule.archive_verifier import validate_archived_controller
from tools.performance_rule.evidence import validate_control_document
from tools.performance_rule.runner_report import validate_report

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "performance_rule" / "fixtures"
CONTRACT_FIXTURE = FIXTURE_ROOT / "release-evidence-contract-v1.json"
EXTERNAL_MANIFEST = FIXTURE_ROOT / "external-evidence-manifest-v1.json"
RUNNER_SCHEMA = "ferrum2.rule-qualification.v3"
CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v7"
THRESHOLD_POLICY_VERSION = "section-5.7-and-rule-04-conditional-median-gates.v6"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def decode_closed_json(payload):
    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    return json.loads(payload, object_pairs_hook=reject_duplicate_keys)


def load_closed_json(path):
    return decode_closed_json(path.read_text(encoding="utf-8"))


class CompactReleaseEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = load_closed_json(CONTRACT_FIXTURE)
        cls.qualification = cls.fixture["qualification"]
        cls.ab = cls.fixture["ab"]

    def test_fixture_is_explicitly_synthetic_and_current_schema_only(self):
        self.assertEqual(
            set(self.fixture),
            {"ab", "kind", "qualification", "schema_version", "synthetic"},
        )
        self.assertEqual(self.fixture["schema_version"], 1)
        self.assertTrue(self.fixture["synthetic"])
        self.assertEqual(self.qualification["schema"], RUNNER_SCHEMA)
        self.assertEqual(self.ab["schema"], CONTROL_SCHEMA)
        validate_report(self.qualification, self.qualification["runner"]["sha256"])
        validate_control_document(self.ab)

    def test_representative_generated_and_pinned_fixtures_are_bound(self):
        fixtures = {row["name"]: row for row in self.qualification["fixtures"]}
        generated = fixtures["generated-exact-100.srs"]
        self.assertEqual(
            generated["provenance"],
            "deterministic_runner_generated_canonical_srs_v2",
        )
        self.assertEqual(generated["srs_version"], 2)
        self.assertRegex(generated["sha256"], SHA256)
        statistics = generated["statistics"]
        self.assertEqual(statistics["rules"], 1)
        self.assertEqual(
            statistics["exact_domains"]
            + statistics["domain_suffixes"]
            + statistics["domain_keywords"]
            + statistics["ip_cidrs"],
            100,
        )
        self.assertEqual(fixtures["ads.srs"]["provenance"], "pinned_repository_fixture")

    def test_representative_pair_retains_allocation_and_parity_contracts(self):
        measurements = self.qualification["measurements"]
        self.assertEqual(len(measurements), 4)
        self.assertEqual(
            {row["suite"] for row in measurements},
            {"match_set", "snapshot_registry"},
        )
        match_measurements = [
            row for row in measurements if row["suite"] == "match_set"
        ]
        self.assertEqual(
            {row["timing_pair_id"] for row in match_measurements},
            {"match_set/generated-exact-100/exact-hit"},
        )
        for row in match_measurements:
            self.assertTrue(row["allocation_gate_applicable"])
            self.assertTrue(row["allocation_gate_passed"])
            self.assertEqual(row["allocations_per_op"], 0.0)
            self.assertEqual(row["reallocations_per_op"], 0.0)
            self.assertGreater(row["compiled_memory_bytes"], 0)

        parity = self.qualification["parity_observations"]
        self.assertEqual(len(parity), 1)
        observation = parity[0]
        self.assertTrue(observation["performance_gate_applicable"])
        self.assertEqual(observation["median_limit_percent"], 5.0)
        self.assertEqual(observation["p99_limit_percent"], 15.0)
        self.assertEqual(observation["decision"], "passed")

        snapshot = [row for row in measurements if row["suite"] == "snapshot_registry"]
        self.assertEqual(
            {row["scenario"] for row in snapshot},
            {"read_under_publish", "publish_under_readers"},
        )
        self.assertTrue(
            all(
                row["scale"] == 4
                and row["allocation_gate_applicable"] is False
                and row["allocation_gate_passed"] is None
                for row in snapshot
            )
        )

    def test_snapshot_lifecycle_contract_is_explicit_and_non_adopting(self):
        lifecycle = self.qualification["snapshot_lifecycle"]
        self.assertTrue(self.qualification["snapshot_lifecycle_passed"])
        self.assertEqual(lifecycle["reader_threads"], 4)
        self.assertEqual(lifecycle["reader_generation"], 1)
        self.assertEqual(lifecycle["published_generation"], 2)
        self.assertTrue(lifecycle["old_snapshot_alive_before_reader_release"])
        self.assertTrue(lifecycle["old_snapshot_released_after_reader_release"])
        self.assertTrue(lifecycle["generation_action_consistent"])
        self.assertTrue(lifecycle["publish_monotonic"])
        self.assertTrue(lifecycle["watch_no_missed_publication"])
        self.assertFalse(self.qualification["candidate"]["adoption_claim"])

    def test_qualification_identity_is_bound_to_current_ab_candidate(self):
        runner = self.qualification["runner"]
        self.assertRegex(runner["sha256"], SHA256)
        self.assertGreater(runner["bytes"], 0)
        self.assertEqual(runner["sha256"], self.ab["candidate_runner_sha256"])
        self.assertEqual(self.ab["mode"], "parent_candidate")
        self.assertEqual(self.ab["pairs"], 6)
        self.assertEqual(
            self.ab["execution_policy"],
            {
                "pair_order": "alternating_parent_candidate",
                "raw_reports_retained": True,
                "runner_process_priority": "high",
            },
        )
        policy = self.ab["threshold_policy"]
        self.assertFalse(policy["enforced"])
        self.assertFalse(policy["reviewed"])
        self.assertFalse(policy["gate_passed"])
        self.assertEqual(policy["status"], "CALIBRATION_REQUIRED")
        self.assertEqual(policy["version"], THRESHOLD_POLICY_VERSION)
        self.assertEqual(policy["version"], THRESHOLD_POLICY_VERSION)

    def test_environment_and_repository_identity_contracts_are_closed(self):
        environment = self.qualification["environment"]
        self.assertEqual(environment["build_profile"], "release")
        self.assertEqual(environment["timer"], "std::time::Instant")
        self.assertRegex(environment["rustc_version"], r"^rustc 1\.97\.1\b")
        self.assertGreater(environment["logical_cpus"], 0)

        repository = self.qualification["repository"]
        self.assertRegex(repository["git_head"], r"^[0-9a-f]{40}$")
        self.assertRegex(repository["git_tree"], r"^[0-9a-f]{40}$")
        self.assertRegex(repository["status_sha256"], SHA256)
        self.assertEqual(repository["tree_state"], "clean")
        self.assertEqual(repository["changed_entries"], 0)


class ExternalEvidenceManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_closed_json(EXTERNAL_MANIFEST)

    def test_manifest_is_closed_complete_and_content_addressed(self):
        self.assertEqual(
            set(self.manifest),
            {"artifacts", "kind", "schema_version", "storage", "total_bytes"},
        )
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(self.manifest["storage"], "external_immutable_artifact")
        artifacts = self.manifest["artifacts"]
        self.assertEqual(len(artifacts), 7)
        self.assertEqual(
            self.manifest["total_bytes"], sum(row["bytes"] for row in artifacts)
        )
        self.assertEqual(len({row["file"] for row in artifacts}), len(artifacts))
        self.assertEqual(len({row["role"] for row in artifacts}), len(artifacts))
        for row in artifacts:
            self.assertEqual(set(row), {"bytes", "file", "role", "sha256"})
            self.assertEqual(Path(row["file"]).name, row["file"])
            self.assertGreater(row["bytes"], 0)
            self.assertRegex(row["sha256"], SHA256)

    def test_manifest_retains_the_archived_provenance_chain(self):
        by_role = {row["role"]: row for row in self.manifest["artifacts"]}
        self.assertEqual(
            by_role["archived_v2_aa_diagnostic"]["sha256"],
            "2b8f08988112c2142294a4266a24c8d7672d89f2387a91f4b460b52daaf7d4e9",
        )
        self.assertEqual(
            by_role["archived_v3_aa_calibration"]["sha256"],
            "8e795edfc61c2328cb1f84fe0fd65f8ec0236d210078fb23c11e221cba87d394",
        )
        self.assertEqual(
            by_role["archived_v3_ab_diagnostic"]["sha256"],
            "679a85722049e5dc0ea9fa601807623defc267be064d9bb4694aae0bf59719f3",
        )
        self.assertEqual(
            by_role["archived_v4_aa_calibration"]["sha256"],
            "a69f361ec981e7c923f889db9e6e0dd5714883df4a66902729c40fb53c2ae8b0",
        )
        self.assertEqual(
            by_role["archived_v4_ab_comparison"]["sha256"],
            "e870c59b4d9e33cd667dbf8881af3d74dae9c5a649d726de57ae47206e66f200",
        )

    def test_closed_json_loader_rejects_duplicate_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            decode_closed_json('{"schema_version":1,"schema_version":2}')

    def test_archived_v2_policy_requires_its_original_unversioned_shape(self):
        report = {
            "schema": "ferrum2.rule-qualification-control.v2",
            "mode": "aa",
            "pairs": 5,
            "raw_pairs": [{"parent": {}, "candidate": {}} for _ in range(5)],
            "execution_policy": {
                "pair_order": "alternating_parent_candidate",
                "raw_reports_retained": True,
            },
            "threshold_policy": {"p99_parity_target_percent": 15.0},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archived-v2.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            validate_archived_controller(path, "archived_v2_aa_diagnostic")
            report["threshold_policy"]["version"] = "invented-version"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "threshold policy changed"):
                validate_archived_controller(path, "archived_v2_aa_diagnostic")


if __name__ == "__main__":
    unittest.main()
