import pathlib
import unittest

from tests.performance_candidate.test_build_experiment import BuildExperimentFixture
from tools.performance_candidate import evidence_matrix
from tools.performance_candidate.json_contract import CandidateControlError


class Phase4EvidenceMatrixTests(BuildExperimentFixture):
    def validation_path(self) -> pathlib.Path:
        scenarios = [
            self.scenario("tcp-request", "tcp-request"),
            self.scenario("udp-small", "udp-small"),
        ]
        for scenario in scenarios:
            scenario["argv"] = ["{artifact}", "--fixture", scenario["name"]]
        return self.workload_path("phase4-validation.json", "validation", scenarios)

    def matrix(self, family: str, **overrides) -> dict[str, object]:
        prerequisite_evidence = []
        for kind in sorted(evidence_matrix.PREREQUISITE_EVIDENCE_KEYS[family]):
            path = self.root / f"{family}-{kind}.evidence"
            path.write_text(f"fixture evidence: {kind}\n", encoding="utf-8")
            prerequisite_evidence.append(f"{kind}={path}")
        arguments = {
            "environment_path": self.environment_path(),
            "validation_workloads_path": self.validation_path(),
            "family": family,
            "target_root": self.root / "phase4-targets" / family,
            "evidence_root": self.root / "phase4-evidence",
            "package": "ferrum2-server",
            "binary_name": "ferrum2-server",
            "artifact_name": "ferrum2-server",
            "acknowledge_prerequisites": True,
            "prerequisite_evidence": prerequisite_evidence,
        }
        arguments.update(overrides)
        return evidence_matrix.create_evidence_matrix(**arguments)

    def test_every_family_requires_explicit_evidence_prerequisite_acknowledgement(
        self,
    ) -> None:
        with self.assertRaisesRegex(CandidateControlError, "acknowledgement"):
            self.matrix(
                "metrics",
                candidate_feature="metrics-per-worker-experiment",
                acknowledge_prerequisites=False,
            )

    def test_metrics_matrix_keeps_candidate_feature_and_runtime_opt_in_explicit(
        self,
    ) -> None:
        matrix = self.matrix(
            "metrics",
            candidate_feature="metrics-per-worker-experiment",
            candidate_environment=["FERRUM2_METRICS_EXPERIMENT=per-worker"],
        )

        self.assertEqual(matrix["build_commands"][0]["feature_opt_in"], None)
        self.assertEqual(
            matrix["build_commands"][1]["feature_opt_in"],
            "metrics-per-worker-experiment",
        )
        self.assertFalse(matrix["variants"][0]["candidate_opt_in"])
        self.assertTrue(matrix["variants"][1]["candidate_opt_in"])
        self.assertEqual(
            matrix["variants"][1]["run_environment_overrides"],
            {"FERRUM2_METRICS_EXPERIMENT": "per-worker"},
        )
        self.assertIn("counter_contention", matrix["collection_fields"])
        self.assertIn("perf_c2c", matrix["collection_fields"])

    def test_runtime_matrix_has_default_physical_and_lower_worker_variants(
        self,
    ) -> None:
        matrix = self.matrix("runtime", physical_workers=16, reduced_workers=8)

        self.assertEqual(len(matrix["build_commands"]), 1)
        self.assertEqual(
            [variant["name"] for variant in matrix["variants"]],
            ["default", "physical-cores", "reduced"],
        )
        self.assertEqual(matrix["variants"][0]["run_environment_overrides"], {})
        self.assertEqual(
            matrix["variants"][1]["run_environment_overrides"],
            {"TOKIO_WORKER_THREADS": "16"},
        )
        self.assertEqual(
            matrix["variants"][2]["run_environment_overrides"],
            {"TOKIO_WORKER_THREADS": "8"},
        )
        self.assertIn("context_switches", matrix["collection_fields"])
        self.assertIn("cpu_utilization", matrix["collection_fields"])

    def test_allocator_matrix_requires_named_candidate_and_long_run_evidence(
        self,
    ) -> None:
        with self.assertRaisesRegex(CandidateControlError, "candidate_allocator"):
            self.matrix("allocator", candidate_feature="allocator-experiment")

        matrix = self.matrix(
            "allocator",
            candidate_feature="allocator-experiment",
            candidate_allocator="mimalloc-candidate",
        )

        self.assertEqual(matrix["candidate"]["allocator"], "mimalloc-candidate")
        self.assertEqual(matrix["candidate"]["cargo_feature"], "allocator-experiment")
        for field in (
            "allocator_cpu_time",
            "allocator_lock_contention",
            "rss",
            "fragmentation",
            "long_run_growth",
        ):
            self.assertIn(field, matrix["collection_fields"])

    def test_run_rows_bind_environment_build_workload_variant_and_result_identity(
        self,
    ) -> None:
        matrix = self.matrix("runtime", physical_workers=12, reduced_workers=6)
        identities = [row["result_identity_seed"] for row in matrix["run_commands"]]

        self.assertEqual(len(identities), 6)
        self.assertEqual(len(set(identities)), 6)
        self.assertTrue(
            all(
                row["argv"][0].endswith("ferrum2-server")
                for row in matrix["run_commands"]
            )
        )
        self.assertEqual(
            matrix["environment"]["environment_id"],
            self.environment()["environment_id"],
        )
        self.assertRegex(matrix["validation_workloads"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn(
            "artifact_sha256",
            matrix["result_identity_contract"]["required_fields"],
        )

    def test_matrix_records_no_threshold_or_adoption_claim(self) -> None:
        matrix = self.matrix(
            "metrics", candidate_feature="metrics-per-worker-experiment"
        )

        self.assertIsNone(matrix["decision_contract"]["performance_thresholds"])
        self.assertFalse(matrix["decision_contract"]["adoption_claim"])
        self.assertFalse(matrix["decision_contract"]["candidate_enabled_by_default"])
        self.assertTrue(matrix["decision_contract"]["results_are_observations_only"])

    def test_gate_hash_binds_each_required_prerequisite_evidence_file(self) -> None:
        matrix = self.matrix(
            "metrics", candidate_feature="metrics-per-worker-experiment"
        )

        self.assertEqual(
            set(matrix["evidence_gate"]["evidence"]),
            {"counter-contention", "perf-c2c"},
        )
        self.assertTrue(
            all(
                row["size_bytes"] > 0 and len(row["sha256"]) == 64
                for row in matrix["evidence_gate"]["evidence"].values()
            )
        )


if __name__ == "__main__":
    unittest.main()
