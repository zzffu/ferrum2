import pathlib
import tempfile
import unittest
from unittest import mock

import yaml

from tools.ci import performance_build_workflow
from tools.performance_candidate.json_contract import CandidateControlError


class PerformanceBuildWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def cpuinfo(self, vendor: str = "AuthenticAMD") -> pathlib.Path:
        path = self.root / f"cpu-{vendor}.txt"
        path.write_text(
            f"vendor_id\t: {vendor}\nmodel name\t: Fixture CPU\n",
            encoding="utf-8",
        )
        return path

    def test_host_capture_requires_amd_and_binds_stable_identity(self):
        host = performance_build_workflow.capture_amd_host(
            cpuinfo_path=self.cpuinfo(), runner_image="ubuntu-24.04"
        )
        self.assertEqual(host["cpu_vendor"], "AuthenticAMD")
        self.assertEqual(host["scope"] if "scope" in host else None, None)
        self.assertRegex(host["host_id"], r"^[0-9a-f]{64}$")

        with self.assertRaisesRegex(CandidateControlError, "AuthenticAMD"):
            performance_build_workflow.capture_amd_host(
                cpuinfo_path=self.cpuinfo("GenuineIntel"),
                runner_image="ubuntu-24.04",
            )

    def test_prepare_uses_one_fresh_root_and_one_experiment_kind(self):
        github_env = self.root / "github.env"
        values = performance_build_workflow.prepare_paths(
            root=self.root / "experiment",
            experiment_kind="pgo",
            github_env=github_env,
        )
        self.assertEqual(values["EXPERIMENT_KIND"], "pgo")
        self.assertTrue(
            pathlib.Path(values["BUILD_TARGET_ROOT"]).is_relative_to(self.root)
        )
        self.assertIn("EXPERIMENT_KIND=pgo", github_env.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(CandidateControlError, "fresh"):
            performance_build_workflow.prepare_paths(
                root=self.root / "experiment",
                experiment_kind="thin-lto-cgu1",
                github_env=github_env,
            )

    def test_plan_items_never_mix_training_validation_or_phase_rows(self):
        plan = {
            "phases": [
                {"name": "baseline", "phase_type": "build"},
                {"name": "pgo-generate", "phase_type": "build"},
            ],
            "pgo": {
                "training_commands": [
                    {"build_phase": "pgo-generate", "command_id": "a" * 64}
                ],
                "validation_commands": [
                    {"build_phase": "baseline", "command_id": "b" * 64}
                ],
            },
        }
        with mock.patch.object(
            performance_build_workflow.build_experiment,
            "_load_plan",
            return_value=(plan, "c" * 64),
        ):
            self.assertEqual(
                performance_build_workflow.plan_items(self.root / "plan", "training"),
                [("a" * 64, "pgo-generate")],
            )
            self.assertEqual(
                performance_build_workflow.plan_items(self.root / "plan", "validation"),
                [("b" * 64, "baseline")],
            )

    def test_phase_artifact_directory_comes_from_plan_and_fails_on_drift(self):
        target = self.root / "targets" / "thin-lto-cgu1"
        artifact_dir = target / "performance-thin-lto"
        artifact_dir.mkdir(parents=True)
        artifacts = ["ferrum2-client", "ferrum2-server"]
        for name in artifacts:
            (artifact_dir / name).write_bytes(name.encode("ascii"))
        plan = {
            "phases": [
                {
                    "name": "thin-lto-cgu1",
                    "phase_type": "build",
                    "target_dir": str(target),
                    "artifacts": [f"performance-thin-lto/{name}" for name in artifacts],
                }
            ]
        }
        with mock.patch.object(
            performance_build_workflow.build_experiment,
            "_load_plan",
            return_value=(plan, "c" * 64),
        ):
            self.assertEqual(
                performance_build_workflow.phase_artifact_directory(
                    self.root / "plan.json", "thin-lto-cgu1"
                ),
                artifact_dir,
            )
            plan["phases"][0]["artifacts"][1] = "other/ferrum2-server"
            other = target / "other"
            other.mkdir()
            (other / "ferrum2-server").write_bytes(b"server")
            with self.assertRaisesRegex(CandidateControlError, "share one directory"):
                performance_build_workflow.phase_artifact_directory(
                    self.root / "plan.json", "thin-lto-cgu1"
                )

    def test_build_workflow_does_not_hardcode_candidate_profile_directory(self):
        workflow_path = (
            pathlib.Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "performance-build.yml"
        )
        document = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        steps = next(iter(document["jobs"].values()))["steps"]
        resolver = next(
            step
            for step in steps
            if step.get("name") == "Resolve baseline and candidate artifact directories"
        )["run"]
        self.assertEqual(resolver.count("phase-artifact-directory"), 2)
        self.assertNotIn("$BUILD_TARGET_ROOT/$candidate_phase/profiling", resolver)

        self.assertEqual(
            document["env"]["BUILD_TARGET_TRIPLE"], "x86_64-unknown-linux-gnu"
        )
        plan_step = next(
            step
            for step in steps
            if step.get("name") == "Create exactly one artifact-level build plan"
        )["run"]
        self.assertIn('--target-triple "$BUILD_TARGET_TRIPLE"', plan_step)
        install_step = next(
            step
            for step in steps
            if step.get("name") == "Install pinned Rust and LLVM profile tools"
        )["run"]
        self.assertIn('target add "$BUILD_TARGET_TRIPLE"', install_step)

    def test_artifact_manifest_is_closed_and_never_authoritative(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "qualification.json").write_text("{}\n", encoding="utf-8")
        manifest = performance_build_workflow.artifact_manifest(
            evidence_root=evidence,
            repository="owner/repo",
            run_id="123",
            run_attempt="2",
            source_sha="a" * 40,
        )
        self.assertFalse(manifest["performance_authoritative"])
        self.assertFalse(manifest["bare_metal_gate_satisfied"])
        self.assertFalse(manifest["durable_evidence_gate_satisfied"])
        self.assertEqual(len(manifest["files"]), 1)

    def test_profile_artifacts_are_materialized_at_the_exact_m4_seam(self):
        repository = self.root / "repository"
        repository.mkdir()
        first = self.root / "first"
        second = self.root / "second"
        first.mkdir()
        second.mkdir()
        for name in performance_build_workflow.PROFILE_ARTIFACTS:
            (first / name).write_bytes(f"first-{name}".encode("ascii"))
            (second / name).write_bytes(f"second-{name}".encode("ascii"))

        destination = performance_build_workflow.materialize_profile_artifacts(
            source_dir=first, repository=repository
        )
        self.assertEqual(destination, repository / "target" / "profiling")
        self.assertEqual(
            (destination / "m4-qualification").read_bytes(),
            b"first-m4-qualification",
        )

        performance_build_workflow.materialize_profile_artifacts(
            source_dir=second, repository=repository
        )
        self.assertEqual(
            (destination / "m4-qualification").read_bytes(),
            b"second-m4-qualification",
        )
        (second / "ferrum2-client").unlink()
        with self.assertRaisesRegex(CandidateControlError, "unavailable"):
            performance_build_workflow.materialize_profile_artifacts(
                source_dir=second, repository=repository
            )
        with self.assertRaisesRegex(CandidateControlError, "paths are invalid"):
            performance_build_workflow.materialize_profile_artifacts(
                source_dir=destination, repository=repository
            )


if __name__ == "__main__":
    unittest.main()
