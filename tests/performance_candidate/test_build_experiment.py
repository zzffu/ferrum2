import hashlib
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import CandidateControlError

PARENT_SHA = "1" * 40
CANDIDATE_SHA = "2" * 40
PARENT_TREE = "3" * 40
CANDIDATE_TREE = "4" * 40


class BuildExperimentFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / "Cargo.toml").write_text(
            "[workspace]\nmembers = []\n", encoding="utf-8"
        )
        (self.repository / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (self.repository / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.97.1"\n', encoding="utf-8"
        )

    @staticmethod
    def machine() -> dict[str, object]:
        return {
            "architecture": "x86_64",
            "cpu_model": {
                "source": "/proc/cpuinfo",
                "status": "captured",
                "value": "Fixture CPU",
            },
            "frequency_governor": {
                "source": "/sys/devices/system/cpu",
                "status": "captured",
                "values": ["performance"],
            },
            "kernel": "fixture-kernel",
            "microcode": {
                "source": "/proc/cpuinfo",
                "status": "captured",
                "value": "0x123",
            },
            "numa": {
                "online_nodes": [0, 1],
                "source": "/sys/devices/system/node/online",
                "status": "captured",
            },
            "operating_system": "Linux",
            "operating_system_version": "fixture-version",
        }

    @staticmethod
    def background() -> dict[str, object]:
        return {
            "distinct_names": 2,
            "snapshot_sha256": "5" * 64,
            "source": "/proc/*/comm",
            "status": "captured",
            "top": [
                {"instances": 2, "name": "worker"},
                {"instances": 1, "name": "init"},
            ],
            "total_processes": 3,
            "truncated": False,
        }

    def command_result(self, argv, *, cwd=None):
        command = tuple(argv)
        if command == ("git", "rev-parse", "--show-toplevel"):
            return 0, str(self.repository)
        if command == ("git", "rev-parse", "HEAD"):
            return 0, CANDIDATE_SHA
        if command == (
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ):
            return 0, ""
        if command == ("git", "rev-parse", f"{PARENT_SHA}^{{tree}}"):
            return 0, PARENT_TREE
        if command == ("git", "rev-parse", f"{CANDIDATE_SHA}^{{tree}}"):
            return 0, CANDIDATE_TREE
        if command == ("rustc", "-vV"):
            return 0, "rustc 1.97.1\nrelease: 1.97.1\nhost: fixture"
        if command == ("cargo", "-V"):
            return 0, "cargo 1.97.1 (fixture)"
        self.fail(f"unexpected identity command: {command}, cwd={cwd}")

    def environment(self) -> dict[str, object]:
        with (
            mock.patch.object(
                build_experiment,
                "validate_git_relation",
                return_value=(PARENT_SHA, CANDIDATE_SHA),
            ),
            mock.patch.object(
                build_experiment, "_bounded_command", side_effect=self.command_result
            ),
            mock.patch.object(
                build_experiment,
                "_capture_machine_identity",
                return_value=(self.machine(), self.background()),
            ),
            mock.patch.object(
                build_experiment, "_utc_now", return_value="2026-08-28T00:00:00Z"
            ),
        ):
            return build_experiment.capture_environment(
                repository=self.repository,
                parent_sha=PARENT_SHA,
                candidate_sha=CANDIDATE_SHA,
                run_kind="comparison",
                environment_kind="stable-bare-metal",
                runner_image="bare-metal-fixture-v1",
            )

    def write_json(self, name: str, value: object) -> pathlib.Path:
        path = self.root / name
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return path

    def environment_path(self) -> pathlib.Path:
        return self.write_json("environment.json", self.environment())

    @staticmethod
    def scenario(
        name: str,
        category: str,
        *,
        role: str = "validation",
        coverage: str = "representative",
        weight: int | None = None,
    ) -> dict[str, object]:
        return {
            "argv": ["fixture-runner", "--scenario", name],
            "category": category,
            "coverage": "steady-state" if role == "training" else coverage,
            "name": name,
            "platforms": ["linux-x86_64"],
            "weight_basis_points": weight if role == "training" else None,
            "working_directory": ".",
        }

    def pgo_scenario(
        self,
        name: str,
        category: str,
        *,
        role: str = "validation",
        coverage: str = "representative",
        weight: int | None = None,
    ) -> dict[str, object]:
        scenario = self.scenario(
            name,
            category,
            role=role,
            coverage=coverage,
            weight=weight,
        )
        scenario["argv"] = ["{artifact:ferrum2-client}", "--fixture", name]
        return scenario

    def workload_path(
        self, name: str, role: str, scenarios: list[dict[str, object]]
    ) -> pathlib.Path:
        return self.write_json(
            name,
            {
                "role": role,
                "scenarios": scenarios,
                "schema_version": build_experiment.WORKLOAD_SCHEMA_VERSION,
            },
        )

    def tcp_udp_validation_path(self) -> pathlib.Path:
        return self.workload_path(
            "validation.json",
            "validation",
            [
                self.scenario("validate-tcp", "tcp-request"),
                self.scenario("validate-udp", "udp-small"),
            ],
        )

    def create_plan(self, kind: str, **overrides) -> dict[str, object]:
        arguments = {
            "environment_path": self.environment_path(),
            "validation_workloads_path": self.tcp_udp_validation_path(),
            "kind": kind,
            "target_root": self.root / "targets" / kind,
            "artifact_names": ["ferrum2-client", "ferrum2-server"],
        }
        arguments.update(overrides)
        return build_experiment.create_experiment_plan(**arguments)


class EnvironmentCaptureTests(BuildExperimentFixture):
    def test_capture_binds_source_toolchain_machine_and_background_snapshot(
        self,
    ) -> None:
        report = self.environment()

        self.assertEqual(
            report["schema_version"], build_experiment.ENVIRONMENT_SCHEMA_VERSION
        )
        self.assertEqual(report["source_identity"]["candidate_tree"], CANDIDATE_TREE)
        self.assertEqual(report["build_identity"]["rust_release"], "1.97.1")
        self.assertTrue(report["build_identity"]["locked_dependencies"])
        self.assertEqual(
            report["machine_identity"]["frequency_governor"]["values"],
            ["performance"],
        )
        self.assertEqual(report["background_process_snapshot"]["total_processes"], 3)
        self.assertRegex(report["environment_id"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["build_identity_id"], r"^[0-9a-f]{64}$")

    def test_dirty_worktree_is_rejected_instead_of_getting_a_false_tree_identity(
        self,
    ) -> None:
        def dirty_command(argv, *, cwd=None):
            if tuple(argv) == (
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ):
                return 0, " M Cargo.toml"
            return self.command_result(argv, cwd=cwd)

        with (
            mock.patch.object(
                build_experiment,
                "validate_git_relation",
                return_value=(PARENT_SHA, CANDIDATE_SHA),
            ),
            mock.patch.object(
                build_experiment, "_bounded_command", side_effect=dirty_command
            ),
        ):
            with self.assertRaisesRegex(CandidateControlError, "clean worktree"):
                build_experiment.capture_environment(
                    repository=self.repository,
                    parent_sha=PARENT_SHA,
                    candidate_sha=CANDIDATE_SHA,
                    run_kind="comparison",
                    environment_kind="github-hosted",
                    runner_image="ubuntu-24.04",
                )

    def test_environment_id_excludes_transient_background_process_counts(self) -> None:
        first = self.environment()
        changed = dict(first)
        changed["background_process_snapshot"] = {
            **first["background_process_snapshot"],
            "total_processes": 99,
        }
        path = self.write_json("changed-environment.json", changed)

        loaded, _ = build_experiment._load_environment(path)

        self.assertEqual(loaded["environment_id"], first["environment_id"])


class BuildPlanTests(BuildExperimentFixture):
    def test_thin_lto_plan_has_separate_locked_baseline_and_candidate(self) -> None:
        plan = self.create_plan("thin-lto-cgu1")

        self.assertEqual(
            [phase["name"] for phase in plan["phases"]],
            ["baseline", "thin-lto-cgu1"],
        )
        self.assertEqual(plan["phases"][0]["profile"], "profiling")
        self.assertEqual(plan["phases"][1]["profile"], "performance-thin-lto")
        self.assertIn("--locked", plan["phases"][0]["argv"])
        self.assertFalse(plan["evidence_contract"]["performance_conclusions_recorded"])
        self.assertTrue(plan["evidence_contract"]["single_scenario_adoption_forbidden"])

    def test_target_cpu_is_named_and_requires_fixed_deployment_opt_in(self) -> None:
        with self.assertRaisesRegex(CandidateControlError, "nonportable"):
            self.create_plan("target-cpu", target_cpu="x86-64-v3")
        with self.assertRaisesRegex(CandidateControlError, "native"):
            self.create_plan(
                "target-cpu",
                target_cpu="native",
                deployment_id="host-fleet-a",
                acknowledge_nonportable=True,
            )

        plan = self.create_plan(
            "target-cpu",
            target_cpu="x86-64-v3",
            deployment_id="host-fleet-a",
            acknowledge_nonportable=True,
        )

        self.assertEqual(plan["portability"]["target_cpu"], "x86-64-v3")
        self.assertTrue(plan["portability"]["nonportable_opt_in"])
        self.assertTrue(plan["portability"]["general_distribution_baseline_unchanged"])
        self.assertEqual(
            plan["phases"][1]["environment_overrides"]["CARGO_ENCODED_RUSTFLAGS"],
            "-Ctarget-cpu=x86-64-v3",
        )

    def test_pgo_plan_separates_mixed_training_and_independent_validation(self) -> None:
        training_categories = [
            "tcp-request",
            "tcp-bulk",
            "udp-small",
            "udp-mtu",
            "dns",
            "rule",
        ]
        training = self.workload_path(
            "training.json",
            "training",
            [
                self.pgo_scenario(
                    f"train-{category}",
                    category,
                    role="training",
                    weight=1_667 if index < 5 else 1_665,
                )
                for index, category in enumerate(training_categories)
            ],
        )
        validation = self.workload_path(
            "pgo-validation.json",
            "validation",
            [
                self.pgo_scenario(
                    f"validate-{coverage}",
                    "tcp-request" if index % 2 == 0 else "udp-small",
                    coverage=coverage,
                )
                for index, coverage in enumerate(
                    ("representative", "cold-path", "error-path", "different-cpu")
                )
            ],
        )
        llvm_profdata = self.root / "llvm-profdata"
        llvm_profdata.write_bytes(b"fixture llvm-profdata")

        plan = self.create_plan(
            "pgo",
            training_workloads_path=training,
            validation_workloads_path=validation,
            llvm_profdata=llvm_profdata,
        )

        self.assertEqual(
            [phase["name"] for phase in plan["phases"]],
            ["baseline", "pgo-generate", "pgo-merge", "pgo-use"],
        )
        self.assertEqual(
            plan["pgo"]["execution_order"],
            [
                "baseline",
                "pgo-generate",
                "external-training-workloads",
                "pgo-merge",
                "pgo-use",
                "external-validation-workloads",
            ],
        )
        self.assertNotEqual(
            plan["pgo"]["training_workloads"]["sha256"],
            plan["validation_workloads"]["sha256"],
        )
        self.assertIn(
            "-Cprofile-generate=",
            plan["phases"][1]["environment_overrides"]["CARGO_ENCODED_RUSTFLAGS"],
        )
        self.assertIn(
            "-Cprofile-use=",
            plan["phases"][3]["environment_overrides"]["CARGO_ENCODED_RUSTFLAGS"],
        )
        self.assertEqual(len(plan["pgo"]["training_commands"]), 6)
        self.assertEqual(len(plan["pgo"]["validation_commands"]), 8)
        self.assertTrue(
            all(
                "{artifact:" not in argument
                for command in plan["pgo"]["training_commands"]
                for argument in command["argv"]
            )
        )

    def test_pgo_rejects_training_scenario_reused_for_validation(self) -> None:
        training_categories = sorted(build_experiment.PGO_TRAINING_CATEGORIES)
        training = self.workload_path(
            "training-overlap.json",
            "training",
            [
                self.pgo_scenario(
                    "shared-name" if index == 0 else f"train-{category}",
                    category,
                    role="training",
                    weight=1_667 if index < 5 else 1_665,
                )
                for index, category in enumerate(training_categories)
            ],
        )
        validation = self.workload_path(
            "validation-overlap.json",
            "validation",
            [
                self.pgo_scenario(
                    "shared-name" if index == 0 else f"validate-{coverage}",
                    "tcp-request",
                    coverage=coverage,
                )
                for index, coverage in enumerate(
                    sorted(build_experiment.VALIDATION_COVERAGE)
                )
            ],
        )
        llvm_profdata = self.root / "llvm-profdata"
        llvm_profdata.write_bytes(b"fixture")

        with self.assertRaisesRegex(CandidateControlError, "disjoint"):
            self.create_plan(
                "pgo",
                training_workloads_path=training,
                validation_workloads_path=validation,
                llvm_profdata=llvm_profdata,
            )

    def test_panic_abort_strip_is_scoped_to_size_startup_and_operations_review(
        self,
    ) -> None:
        validation = self.workload_path(
            "startup-validation.json",
            "validation",
            [self.scenario("validate-startup", "startup")],
        )

        plan = self.create_plan(
            "panic-abort-strip", validation_workloads_path=validation
        )

        self.assertEqual(plan["phases"][1]["profile"], "performance-panic-abort-strip")
        self.assertTrue(plan["operational_review"]["size_and_startup_are_primary"])
        self.assertTrue(
            plan["operational_review"][
                "panic_backtrace_and_crash_diagnostics_review_required"
            ]
        )

    def test_named_profiles_do_not_modify_default_release(self) -> None:
        cargo = (pathlib.Path(__file__).resolve().parents[2] / "Cargo.toml").read_text(
            encoding="utf-8"
        )

        self.assertIn("[profile.performance-thin-lto]", cargo)
        self.assertIn("[profile.performance-panic-abort-strip]", cargo)
        self.assertNotIn("[profile.release]", cargo)


class BuildRunTests(BuildExperimentFixture):
    def test_pgo_inputs_require_fresh_raw_data_and_bind_profile_hashes(self) -> None:
        raw = self.root / "pgo-data" / "raw"
        merged = self.root / "pgo-data" / "merged.profdata"
        plan = {
            "pgo": {
                "raw_profile_directory": str(raw),
                "merged_profile": str(merged),
            }
        }

        self.assertEqual(build_experiment._phase_inputs(plan, "pgo-generate"), [])
        (raw / "first.profraw").write_bytes(b"profile one")
        (raw / "second.profraw").write_bytes(b"profile two")
        merge_inputs = build_experiment._phase_inputs(plan, "pgo-merge")
        self.assertEqual(merge_inputs[0]["file_count"], 2)
        self.assertEqual(
            merge_inputs[0]["total_size_bytes"],
            len(b"profile one") + len(b"profile two"),
        )
        merged.write_bytes(b"merged profile")
        use_inputs = build_experiment._phase_inputs(plan, "pgo-use")
        self.assertEqual(
            use_inputs[0]["sha256"], hashlib.sha256(b"merged profile").hexdigest()
        )
        with self.assertRaisesRegex(CandidateControlError, "already exists"):
            build_experiment._phase_inputs(plan, "pgo-merge")
        with self.assertRaisesRegex(CandidateControlError, "empty raw"):
            build_experiment._phase_inputs(plan, "pgo-generate")

    def test_success_record_contains_time_size_hash_and_controlled_environment(
        self,
    ) -> None:
        plan = self.create_plan("thin-lto-cgu1")
        plan_path = self.write_json("plan.json", plan)
        phase = plan["phases"][0]
        expected_bytes = b"fixture executable"
        log_path = self.root / "logs" / "baseline.log"

        def executor(argv, cwd, environment, log):
            self.assertEqual(cwd, self.repository)
            self.assertNotIn("RUSTFLAGS", environment)
            self.assertNotIn("CARGO_PROFILE_RELEASE_LTO", environment)
            self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
            artifact = pathlib.Path(phase["target_dir"]) / phase["artifacts"][0]
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(expected_bytes)
            second = pathlib.Path(phase["target_dir"]) / phase["artifacts"][1]
            second.write_bytes(b"server")
            log.parent.mkdir(parents=True)
            log.write_bytes(b"build log")
            return 0

        with (
            mock.patch.dict(
                os.environ,
                {
                    "RUSTFLAGS": "-Ctarget-cpu=native",
                    "CARGO_PROFILE_RELEASE_LTO": "fat",
                },
                clear=False,
            ),
            mock.patch.object(
                build_experiment,
                "capture_environment",
                return_value=self.environment(),
            ),
        ):
            ticks = iter((100, 160))
            record, returncode = build_experiment.run_experiment_phase(
                plan_path=plan_path,
                phase_name="baseline",
                log_path=log_path,
                executor=executor,
                clock=lambda: next(ticks),
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(record["status"], "succeeded")
        self.assertEqual(record["elapsed_nanoseconds"], 60)
        self.assertEqual(record["artifacts"][0]["size_bytes"], len(expected_bytes))
        self.assertEqual(
            record["artifacts"][0]["sha256"],
            hashlib.sha256(expected_bytes).hexdigest(),
        )
        self.assertEqual(record["log"]["size_bytes"], len(b"build log"))

    def test_failed_build_is_recorded_without_claiming_artifacts(self) -> None:
        plan = self.create_plan("thin-lto-cgu1")
        plan_path = self.write_json("failed-plan.json", plan)
        log_path = self.root / "logs" / "failed.log"

        def executor(argv, cwd, environment, log):
            log.parent.mkdir(parents=True)
            log.write_bytes(b"compiler error")
            return 7

        with mock.patch.object(
            build_experiment,
            "capture_environment",
            return_value=self.environment(),
        ):
            ticks = iter((10, 25))
            record, returncode = build_experiment.run_experiment_phase(
                plan_path=plan_path,
                phase_name="baseline",
                log_path=log_path,
                executor=executor,
                clock=lambda: next(ticks),
            )

        self.assertEqual(returncode, 7)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["exit_code"], 7)
        self.assertEqual(record["artifacts"], [])
        self.assertEqual(record["log"]["size_bytes"], len(b"compiler error"))


if __name__ == "__main__":
    unittest.main()
