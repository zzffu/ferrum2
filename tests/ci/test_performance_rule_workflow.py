from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import shutil
import tempfile
import unittest

from tests.performance_rule._fixture import (
    SCENARIO_SUITES,
    aa_source_report,
    report as runner_report,
    write_json,
)
from tools.ci import performance_rule_evidence as evidence
from tools.ci import performance_rule_workflow as workflow
from tools.performance_rule.evidence import review_calibration_source
from tools.performance_rule.pairing import summarize
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.schema import ControlError

SOURCE_SHA = "b" * 40
SOURCE_TREE = "c" * 40
REPOSITORY = "owner/ferrum2"
REVIEWED_BY = "reviewer"
REVIEWED_UTC = "2026-08-29T00:00:00Z"


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PerformanceRuleWorkflowControllerTests(unittest.TestCase):
    def test_registered_workload_arguments_are_exact(self) -> None:
        self.assertEqual(
            evidence.CONTROL_SCHEMA,
            "ferrum2.rule-qualification-control.v7",
        )
        self.assertEqual(
            evidence.WORKFLOW_ARGUMENTS,
            (
                "--profile",
                "qualification",
                "--samples",
                "101",
                "--workspace-root",
                ".",
            ),
        )

    @staticmethod
    def command_probe(command: tuple[str, ...], cwd: pathlib.Path) -> str:
        del cwd
        if command == ("git", "rev-parse", "HEAD"):
            return SOURCE_SHA
        if command == ("git", "rev-parse", "HEAD^{tree}"):
            return SOURCE_TREE
        if command == ("uname", "-srvmo"):
            return "Linux 6.17.0 #1 SMP x86_64 GNU/Linux"
        raise AssertionError(f"unexpected command probe: {command}")

    @staticmethod
    def host_environment() -> dict[str, str]:
        return {
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "ImageOS": "ubuntu24",
            "ImageVersion": "20260824.1.0",
        }

    def write_host(self, path: pathlib.Path, vendor: str = "AuthenticAMD") -> None:
        files = {
            "/proc/cpuinfo": (
                f"processor : 0\nvendor_id : {vendor}\n"
                "model name : AMD EPYC 7763 64-Core Processor\n"
            ),
            "/proc/meminfo": "MemTotal:       16384000 kB\n",
        }

        def read_text(source: pathlib.Path, maximum: int) -> str:
            value = files[source.as_posix()]
            self.assertLessEqual(len(value.encode()), maximum)
            return value

        workflow.capture_host_identity(
            path,
            environ=self.host_environment(),
            read_text=read_text,
            command_probe=self.command_probe,
            cpu_count=lambda: 4,
        )

    @staticmethod
    def expected_repository() -> dict[str, object]:
        return {
            "git_head": SOURCE_SHA,
            "git_tree": SOURCE_TREE,
            "tree_state": "clean",
            "changed_entries": 0,
            "status_sha256": hashlib.sha256(b"").hexdigest(),
        }

    @staticmethod
    def bind_workflow_samples(runner: dict[str, object]) -> None:
        configuration = runner["configuration"]
        configuration["samples"] = evidence.WORKFLOW_SAMPLES
        configuration["base_iterations_per_sample"] = evidence.WORKFLOW_BASE_ITERATIONS
        for row in runner["measurements"]:
            row["samples_ns_per_op"] = [row["samples_ns_per_op"][0]] * (
                evidence.WORKFLOW_SAMPLES
            )
            row["actual_iterations_per_sample"] = [
                row["actual_iterations_per_sample"][0]
            ] * evidence.WORKFLOW_SAMPLES
            row["sample_batch_nanoseconds"] = [
                row["sample_batch_nanoseconds"][0]
            ] * evidence.WORKFLOW_SAMPLES

    def write_aa(self, path: pathlib.Path, parent: pathlib.Path) -> dict[str, object]:
        value = aa_source_report()
        parent_sha256 = file_sha256(parent)
        parent_bytes = parent.stat().st_size
        value["parent_runner_sha256"] = parent_sha256
        value["candidate_runner_sha256"] = parent_sha256
        value["runner_arguments"] = list(evidence.WORKFLOW_ARGUMENTS)
        value["execution_policy"]["runner_process_priority"] = "normal"
        for entry in value["execution_trace"]:
            entry["runner_sha256"] = parent_sha256
        for pair in value["raw_pairs"]:
            for role in ("parent", "candidate"):
                runner = pair[role]
                runner["repository"] = self.expected_repository()
                runner["runner"] = {
                    "sha256": parent_sha256,
                    "bytes": parent_bytes,
                }
                runner["candidate"] = {
                    "adoption_claim": False,
                    "enabled_features": [],
                }
                runner["profile"] = "qualification"
                self.bind_workflow_samples(runner)
                runner["configuration"]["includes_100k"] = False
        write_json(path, value)
        return value

    def calibration_bundle(self, root: pathlib.Path) -> dict[str, pathlib.Path]:
        evidence_dir = root / "calibration"
        (evidence_dir / "parent").mkdir(parents=True)
        parent = evidence_dir / "parent" / "ferrum2-rule-qualification"
        parent.write_bytes(b"feature-free-parent")
        aa_report = evidence_dir / "release-aa-v7.json"
        self.write_aa(aa_report, parent)
        host = evidence_dir / "host-identity.json"
        self.write_host(host)
        (evidence_dir / "controller-exit-code.txt").write_bytes(b"4\n")
        manifest = evidence_dir / "calibration-manifest.json"
        evidence.build_calibration_manifest(
            evidence.CalibrationManifestInputs(
                evidence=evidence_dir,
                parent=parent,
                aa_report=aa_report,
                host_identity=host,
                workspace=root,
                expected_sha=SOURCE_SHA,
                repository=REPOSITORY,
                run_id=101,
                run_attempt=2,
                output=manifest,
            ),
            command_probe=self.command_probe,
        )
        return {
            "evidence": evidence_dir,
            "parent": parent,
            "aa": aa_report,
            "host": host,
            "manifest": manifest,
        }

    def comparison_bundle(
        self, root: pathlib.Path
    ) -> evidence.ComparisonValidationInputs:
        calibration = self.calibration_bundle(root)
        evidence_dir = root / "comparison"
        (evidence_dir / "parent").mkdir(parents=True)
        (evidence_dir / "candidate").mkdir()
        parent = evidence_dir / "parent" / "ferrum2-rule-qualification"
        candidate = evidence_dir / "candidate" / "ferrum2-rule-qualification"
        shutil.copyfile(calibration["parent"], parent)
        candidate.write_bytes(b"domain-suffix-trie-candidate")
        source = evidence_dir / "release-aa-v7.json"
        shutil.copyfile(calibration["aa"], source)
        shutil.copyfile(
            calibration["manifest"], evidence_dir / "calibration-manifest.json"
        )
        shutil.copyfile(
            calibration["host"], evidence_dir / "calibration-host-identity.json"
        )
        shutil.copyfile(calibration["host"], evidence_dir / "host-identity.json")

        reviewed = review_calibration_source(
            source,
            reviewed_by=REVIEWED_BY,
            reviewed_utc=REVIEWED_UTC,
        )
        reviewed_path = evidence_dir / "reviewed-aa-v3.json"
        write_json(reviewed_path, reviewed)

        parent_sha256 = file_sha256(parent)
        candidate_sha256 = file_sha256(candidate)
        parent_bytes = parent.stat().st_size
        candidate_bytes = candidate.stat().st_size
        ab = copy.deepcopy(json.loads(source.read_text(encoding="utf-8")))
        ab["mode"] = "parent_candidate"
        ab["parent_runner_sha256"] = parent_sha256
        ab["candidate_runner_sha256"] = candidate_sha256
        pairs = []
        for source_pair in ab["raw_pairs"]:
            parent_report = copy.deepcopy(source_pair["parent"])
            candidate_report = copy.deepcopy(parent_report)
            parent_report["runner"] = {
                "sha256": parent_sha256,
                "bytes": parent_bytes,
            }
            candidate_report["runner"] = {
                "sha256": candidate_sha256,
                "bytes": candidate_bytes,
            }
            candidate_report["candidate"] = {
                "adoption_claim": False,
                "enabled_features": ["candidate-domain-suffix-trie"],
            }
            pairs.append({"parent": parent_report, "candidate": candidate_report})
        ab["raw_pairs"] = pairs
        trace = []
        for pair_index in range(6):
            roles = (
                ("parent", "candidate")
                if pair_index % 2 == 0
                else ("candidate", "parent")
            )
            for order_index, role in enumerate(roles, 1):
                trace.append(
                    {
                        "pair": pair_index + 1,
                        "order": order_index,
                        "role": role,
                        "runner_sha256": (
                            parent_sha256 if role == "parent" else candidate_sha256
                        ),
                    }
                )
        ab["execution_trace"] = trace
        limits = dict(reviewed["effective_median_limits_percent"])
        comparisons = summarize(SCENARIO_SUITES, pairs, False, limits)
        policy = threshold_policy(
            comparisons,
            limits,
            str(reviewed_path.resolve()),
            file_sha256(reviewed_path),
            reviewed=True,
        )
        ab["comparisons"] = comparisons
        ab["threshold_policy"] = policy
        ab["status"] = policy["status"]
        ab["decision_reason"] = (
            "reviewed match_set and conditional snapshot_registry median gates evaluated"
        )
        ab_path = evidence_dir / "release-ab-v7.json"
        write_json(ab_path, ab)
        (evidence_dir / "ab-exit-code.txt").write_bytes(b"0\n")

        qualification = runner_report(candidate_sha256)
        qualification["repository"] = self.expected_repository()
        qualification["runner"]["bytes"] = candidate_bytes
        qualification["candidate"] = {
            "adoption_claim": False,
            "enabled_features": ["candidate-domain-suffix-trie"],
        }
        qualification["profile"] = "qualification"
        qualification["configuration"]["match_sizes"] = [
            8,
            32,
            64,
            65,
            100,
            128,
            1_000,
            10_000,
            100_000,
        ]
        qualification["configuration"]["route_sizes"] = [
            1,
            8,
            32,
            64,
            128,
            1_000,
            10_000,
        ]
        self.bind_workflow_samples(qualification)
        qualification["configuration"]["includes_100k"] = True
        qualification_path = evidence_dir / "candidate-qualification.json"
        write_json(qualification_path, qualification)
        (evidence_dir / "qualification-exit-code.txt").write_bytes(b"0\n")
        return evidence.ComparisonValidationInputs(
            evidence=evidence_dir,
            workspace=root,
            parent=parent,
            candidate=candidate,
            calibration=reviewed_path,
            ab_report=ab_path,
            qualification_report=qualification_path,
            reviewed_by=REVIEWED_BY,
            reviewed_utc=REVIEWED_UTC,
            feature="domain",
            repository=REPOSITORY,
            expected_sha=SOURCE_SHA,
            comparison_run_id=202,
            comparison_run_attempt=1,
            calibration_run_id=101,
            output=evidence_dir / "comparison-manifest.json",
        )

    def test_host_capture_is_closed_atomic_and_amd_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host = root / "host.json"
            self.write_host(host)
            value = evidence.read_strict_json(
                host, evidence.MAX_HOST_BYTES, "test host"
            )
            self.assertEqual(set(value), evidence.HOST_FIELDS)
            self.assertEqual(value["cpu_vendor"], "AuthenticAMD")
            self.assertEqual(list(root.glob(".host.json.*.tmp")), [])

            rejected = root / "intel.json"
            with self.assertRaisesRegex(evidence.WorkflowContractError, "AuthenticAMD"):
                self.write_host(rejected, vendor="GenuineIntel")
            self.assertTrue(rejected.is_file(), "failed preflight must retain evidence")

    def test_prepare_comparison_exports_one_typed_feature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            github_env = root / "github-env"
            github_env.write_text("", encoding="utf-8")
            workflow.prepare_comparison(
                root / "work",
                github_env,
                run_id=101,
                current_run_id=202,
                reviewed_by=REVIEWED_BY,
                reviewed_utc=REVIEWED_UTC,
                feature="all",
            )
            exported = github_env.read_text(encoding="utf-8")
            self.assertIn(
                "CANDIDATE_FEATURES=candidate-atomic-snapshot,"
                "candidate-cidr-radix,candidate-domain-suffix-trie\n",
                exported,
            )
            self.assertIn(
                'EXPECTED_FEATURES_JSON=["candidate-atomic-snapshot",'
                '"candidate-cidr-radix","candidate-domain-suffix-trie"]\n',
                exported,
            )
            with self.assertRaisesRegex(
                evidence.WorkflowContractError, "own workflow run"
            ):
                workflow.prepare_comparison(
                    root / "other",
                    github_env,
                    run_id=202,
                    current_run_id=202,
                    reviewed_by=REVIEWED_BY,
                    reviewed_utc=REVIEWED_UTC,
                    feature="domain",
                )

    def test_calibration_manifest_and_verifier_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle = self.calibration_bundle(root)
            comparison_host = root / "comparison-host.json"
            shutil.copyfile(bundle["host"], comparison_host)
            manifest = evidence.verify_calibration_artifact(
                evidence.CalibrationVerificationInputs(
                    artifact=bundle["evidence"],
                    comparison_host=comparison_host,
                    workspace=root,
                    expected_sha=SOURCE_SHA,
                    repository=REPOSITORY,
                    run_id=101,
                    run_attempt=2,
                ),
                command_probe=self.command_probe,
            )
            self.assertEqual(manifest["schema"], evidence.CALIBRATION_BUNDLE_SCHEMA)
            self.assertEqual(manifest["source_tree"], SOURCE_TREE)
            self.assertRegex(manifest["parent_binary"]["sha256"], r"^[0-9a-f]{64}$")

    def test_calibration_verifier_rejects_duplicate_path_size_hash_and_extra(
        self,
    ) -> None:
        mutations = ("duplicate", "path", "size", "hash", "extra")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for index, mutation in enumerate(mutations):
                with self.subTest(mutation=mutation):
                    case = root / str(index)
                    bundle = self.calibration_bundle(case)
                    comparison_host = case / "comparison-host.json"
                    shutil.copyfile(bundle["host"], comparison_host)
                    manifest_path = bundle["manifest"]
                    if mutation == "duplicate":
                        contents = manifest_path.read_text(encoding="utf-8")
                        contents = contents.replace(
                            "{\n",
                            '{\n  "schema": "duplicate",\n',
                            1,
                        )
                        manifest_path.write_text(contents, encoding="utf-8")
                    elif mutation == "extra":
                        (bundle["evidence"] / "unexpected.txt").write_text(
                            "extra", encoding="utf-8"
                        )
                    else:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        if mutation == "path":
                            manifest["parent_binary"]["path"] = "../parent"
                        elif mutation == "size":
                            manifest["host_identity"]["bytes"] = (
                                evidence.MAX_HOST_BYTES + 1
                            )
                        elif mutation == "hash":
                            manifest["parent_binary"]["sha256"] = "0" * 64
                        write_json(manifest_path, manifest)
                    with self.assertRaises(
                        (evidence.WorkflowContractError, ControlError)
                    ):
                        evidence.verify_calibration_artifact(
                            evidence.CalibrationVerificationInputs(
                                artifact=bundle["evidence"],
                                comparison_host=comparison_host,
                                workspace=case,
                                expected_sha=SOURCE_SHA,
                                repository=REPOSITORY,
                                run_id=101,
                                run_attempt=2,
                            ),
                            command_probe=self.command_probe,
                        )

    def test_resolve_calibration_uses_injected_api_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            github_env = root / "github-env"
            github_env.write_text("", encoding="utf-8")
            calls = []

            def fetch(url: str, token: str) -> dict[str, object]:
                calls.append((url, token))
                return {
                    "id": 101,
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": SOURCE_SHA,
                    "path": ".github/workflows/performance-candidate.yml",
                    "run_attempt": 2,
                    "repository": {"full_name": REPOSITORY},
                }

            attempt, artifact = workflow.resolve_calibration_run(
                run_id=101,
                current_run_id=202,
                repository=REPOSITORY,
                expected_sha=SOURCE_SHA,
                api_url="https://api.github.test",
                token="token",
                github_env=github_env,
                api_fetch=fetch,
            )
            self.assertEqual(
                (attempt, artifact), (2, "performance-rule-calibration-101-2")
            )
            self.assertEqual(
                calls,
                [
                    (
                        "https://api.github.test/repos/owner/ferrum2/actions/runs/101",
                        "token",
                    )
                ],
            )
            self.assertIn("CALIBRATION_RUN_ATTEMPT=2\n", github_env.read_text())

            def rejected(url: str, token: str) -> dict[str, object]:
                value = fetch(url, token)
                value["head_sha"] = "0" * 40
                return value

            with self.assertRaisesRegex(evidence.WorkflowContractError, "not approved"):
                workflow.resolve_calibration_run(
                    run_id=101,
                    current_run_id=202,
                    repository=REPOSITORY,
                    expected_sha=SOURCE_SHA,
                    api_url="https://api.github.test",
                    token="token",
                    github_env=github_env,
                    api_fetch=rejected,
                )

            def wrong_workflow(url: str, token: str) -> dict[str, object]:
                value = fetch(url, token)
                value["path"] = ".github/workflows/ordinary.yml"
                return value

            with self.assertRaisesRegex(evidence.WorkflowContractError, "not approved"):
                workflow.resolve_calibration_run(
                    run_id=101,
                    current_run_id=202,
                    repository=REPOSITORY,
                    expected_sha=SOURCE_SHA,
                    api_url="https://api.github.test",
                    token="token",
                    github_env=github_env,
                    api_fetch=wrong_workflow,
                )

    def test_comparison_validation_writes_non_adopting_hashed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inputs = self.comparison_bundle(root)
            manifest = evidence.validate_comparison(
                inputs, command_probe=self.command_probe
            )
            self.assertEqual(manifest["schema"], evidence.COMPARISON_BUNDLE_SCHEMA)
            self.assertFalse(manifest["adoption_claim"])
            self.assertEqual(
                manifest["enabled_features"], ["candidate-domain-suffix-trie"]
            )
            self.assertEqual(
                [entry["path"] for entry in manifest["artifacts"]],
                list(evidence.COMPARISON_FILES),
            )
            self.assertTrue(inputs.output.is_file())

    def test_comparison_validation_rejects_derived_matrix_and_file_drift(self) -> None:
        mutations = (
            "source",
            "feature",
            "exit",
            "raw_result",
            "comparisons",
            "policy",
            "matrix",
            "extra",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for index, mutation in enumerate(mutations):
                with self.subTest(mutation=mutation):
                    inputs = self.comparison_bundle(root / str(index))
                    if mutation == "source":
                        inputs = evidence.ComparisonValidationInputs(
                            **{**inputs.__dict__, "expected_sha": "0" * 40}
                        )
                    elif mutation == "feature":
                        inputs = evidence.ComparisonValidationInputs(
                            **{**inputs.__dict__, "feature": "cidr"}
                        )
                    elif mutation == "exit":
                        (inputs.evidence / "ab-exit-code.txt").write_bytes(b"3\n")
                    elif mutation == "raw_result":
                        report = json.loads(
                            inputs.ab_report.read_text(encoding="utf-8")
                        )
                        for pair in report["raw_pairs"]:
                            for row in pair["candidate"]["measurements"]:
                                if row["suite"] == "match_set":
                                    row["p50_ns_per_op"] = 200
                        write_json(inputs.ab_report, report)
                    elif mutation == "comparisons":
                        report = json.loads(
                            inputs.ab_report.read_text(encoding="utf-8")
                        )
                        report["comparisons"] = []
                        write_json(inputs.ab_report, report)
                    elif mutation == "policy":
                        report = json.loads(
                            inputs.ab_report.read_text(encoding="utf-8")
                        )
                        report["threshold_policy"]["hard_gate_suites"] = []
                        write_json(inputs.ab_report, report)
                    elif mutation == "matrix":
                        report = json.loads(
                            inputs.qualification_report.read_text(encoding="utf-8")
                        )
                        report["configuration"]["route_sizes"] = [1, 32, 64]
                        write_json(inputs.qualification_report, report)
                    else:
                        (inputs.evidence / "unexpected.txt").write_text(
                            "extra", encoding="utf-8"
                        )
                    with self.assertRaises(
                        (evidence.WorkflowContractError, ControlError)
                    ):
                        evidence.validate_comparison(
                            inputs, command_probe=self.command_probe
                        )


if __name__ == "__main__":
    unittest.main()
