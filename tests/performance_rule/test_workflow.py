from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "performance-rule.yml"


class PerformanceRuleWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def job(self, name: str, following: str | None = None) -> str:
        start = self.workflow.index(f"  {name}:\n")
        if following is None:
            return self.workflow[start:]
        end = self.workflow.index(f"  {following}:\n", start + 1)
        return self.workflow[start:end]

    @staticmethod
    def step(job: str, name: str, following: str | None = None) -> str:
        marker = f"      - name: {name}\n"
        start = job.index(marker)
        if following is None:
            return job[start:]
        end = job.index(f"      - name: {following}\n", start + 1)
        return job[start:end]

    def test_dispatch_and_permissions_are_closed(self) -> None:
        workflow = self.workflow
        self.assertIn("name: performance-rule\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        for value in (
            "stage:",
            "calibration_run_id:",
            "reviewed_by:",
            "reviewed_utc:",
            "candidate_feature:",
            "- calibration-aa",
            "- comparison",
            "- domain",
            "- cidr",
            "- atomic",
            "- all",
        ):
            self.assertIn(value, workflow)
        permissions = workflow.split("permissions:\n", 1)[1].split("\nenv:\n", 1)[0]
        self.assertEqual(permissions, "  actions: read\n  contents: read\n")
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:\n", workflow)

    def test_every_action_uses_the_repository_pinned_sha(self) -> None:
        uses = re.findall(r"^\s*uses:\s*([^\s]+)$", self.workflow, re.MULTILINE)
        self.assertEqual(
            uses,
            [
                "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
                "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
                "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            ],
        )
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", use) for use in uses))

    def test_calibration_preflights_amd_before_rust_build_or_workload(self) -> None:
        job = self.job("calibration-aa", "comparison")
        checkout = job.index("- name: Checkout exact calibration source")
        preflight = job.index("- name: Require exact clean source and AMD host identity")
        rust = job.index("- name: Install pinned Rust toolchain")
        build = job.index("- name: Build feature-free calibrated parent")
        workload = job.index("- name: Collect controller v6 six-pair A/A smoke evidence")
        self.assertLess(checkout, preflight)
        self.assertLess(preflight, rust)
        self.assertLess(preflight, build)
        self.assertLess(preflight, workload)
        preflight_block = self.step(
            job,
            "Require exact clean source and AMD host identity",
            "Install pinned Rust toolchain",
        )
        for contract in (
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
            "/proc/cpuinfo",
            'identity["cpu_vendor"] != "AuthenticAMD"',
            '"cpu_model"',
            '"logical_cpus"',
            '"memory_kib"',
            '"kernel"',
            '"runner_environment"',
            '"image_os"',
            '"image_version"',
            "before Rust install/build/workload",
        ):
            self.assertIn(contract, preflight_block)
        self.assertNotIn("rustup", preflight_block)
        self.assertNotIn("cargo ", preflight_block)

    def test_calibration_uses_one_feature_free_binary_and_controller_v6(self) -> None:
        job = self.job("calibration-aa", "comparison")
        build = self.step(
            job,
            "Build feature-free calibrated parent",
            "Collect controller v6 six-pair A/A smoke evidence",
        )
        self.assertIn("--no-default-features", build)
        self.assertNotIn("--features", build)
        workload = self.step(
            job,
            "Collect controller v6 six-pair A/A smoke evidence",
            "Validate and bind calibration evidence identities",
        )
        for value in (
            "python3 -B -m tools.performance_rule run",
            '--parent "$PARENT_BINARY"',
            "--pairs 6",
            "--profile smoke --samples 501 --workspace-root .",
            'test "$controller_status" -eq 4',
            'cmp "$aa_stdout" "$AA_REPORT"',
        ):
            self.assertIn(value, workload)
        manifest = self.step(
            job,
            "Validate and bind calibration evidence identities",
            "Upload calibration evidence and exact parent",
        )
        for value in (
            '"ferrum2.rule-qualification-control.v6"',
            'aa_report["status"] != "CALIBRATION_REQUIRED"',
            '"source_sha": source_sha',
            '"source_tree": source_tree',
            '"controller_exit": artifact(',
            '"parent_binary": artifact(',
            '"aa_report": artifact(',
            '"host_identity": artifact(',
            '"adoption_claim": False',
        ):
            self.assertIn(value, manifest)

    def test_calibration_always_uploads_immutable_90_day_hashed_evidence(self) -> None:
        job = self.job("calibration-aa", "comparison")
        upload = self.step(job, "Upload calibration evidence and exact parent")
        for value in (
            "if: ${{ always() }}",
            "performance-rule-calibration-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ runner.temp }}/performance-rule/calibration",
            "if-no-files-found: warn",
            "retention-days: 90",
        ):
            self.assertIn(value, upload)
        self.assertNotIn("overwrite:", upload)

    def test_comparison_downloads_one_exact_successful_calibration_run(self) -> None:
        job = self.job("comparison")
        resolve = self.step(
            job,
            "Resolve one successful calibration workflow attempt",
            "Download exact calibration run artifact",
        )
        for value in (
            'source_run.get("event") != "workflow_dispatch"',
            'source_run.get("conclusion") != "success"',
            'source_run.get("head_sha") != local_sha',
            'source_run.get("path") != ".github/workflows/performance-rule.yml"',
            "CALIBRATION_RUN_ATTEMPT=",
            "CALIBRATION_ARTIFACT_NAME=performance-rule-calibration-",
        ):
            self.assertIn(value, resolve)
        download = self.step(
            job,
            "Download exact calibration run artifact",
            "Verify calibration run source host and artifact closure",
        )
        for value in (
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            "name: ${{ env.CALIBRATION_ARTIFACT_NAME }}",
            "github-token: ${{ github.token }}",
            "repository: ${{ github.repository }}",
            "run-id: ${{ inputs.calibration_run_id }}",
        ):
            self.assertIn(value, download)
        verify = self.step(
            job,
            "Verify calibration run source host and artifact closure",
            "Create explicitly reviewed source-bound calibration",
        )
        for value in (
            'manifest["source_tree"] != local_tree',
            "observed_files != expected_files",
            'if record["path"] != expected_path',
            'sha256_file(path) != record["sha256"]',
        ):
            self.assertIn(value, verify)

    def test_comparison_requires_exact_amd_cpu_and_runner_identity(self) -> None:
        job = self.job("comparison")
        amd = job.index("- name: Require exact AMD comparison host identity")
        download = job.index("- name: Download exact calibration run artifact")
        rust = job.index("- name: Install pinned Rust toolchain")
        build = job.index("- name: Build independent candidate feature binary")
        ab = job.index("- name: Collect reviewed six-pair A/B smoke evidence")
        self.assertLess(amd, download)
        self.assertLess(amd, rust)
        self.assertLess(amd, build)
        self.assertLess(amd, ab)
        verify = self.step(
            job,
            "Verify calibration run source host and artifact closure",
            "Create explicitly reviewed source-bound calibration",
        )
        self.assertIn("calibration_host != comparison_host", verify)
        self.assertIn('calibration_host.get("cpu_vendor") != "AuthenticAMD"', verify)
        self.assertIn("exact runner identity differs from calibration", verify)

    def test_comparison_review_build_and_evidence_are_separate(self) -> None:
        job = self.job("comparison")
        review = self.step(
            job,
            "Create explicitly reviewed source-bound calibration",
            "Install pinned Rust toolchain",
        )
        for value in (
            "python3 -B -m tools.performance_rule review-calibration",
            '--reviewed-by "$REVIEWED_BY"',
            '--reviewed-utc "$REVIEWED_UTC"',
            '--output "$REVIEWED_CALIBRATION"',
        ):
            self.assertIn(value, review)
        build = self.step(
            job,
            "Build independent candidate feature binary",
            "Collect reviewed six-pair A/B smoke evidence",
        )
        self.assertIn('--features "$CANDIDATE_FEATURES"', build)
        for feature in (
            "candidate-domain-suffix-trie",
            "candidate-cidr-radix",
            "candidate-atomic-snapshot",
        ):
            self.assertIn(feature, job)
        ab = self.step(
            job,
            "Collect reviewed six-pair A/B smoke evidence",
            "Collect candidate qualification including 100k",
        )
        for value in (
            '--parent "$CALIBRATED_PARENT"',
            '--candidate "$CANDIDATE_BINARY"',
            '--calibration "$REVIEWED_CALIBRATION"',
            "--pairs 6",
            "--profile smoke --samples 501 --workspace-root .",
        ):
            self.assertIn(value, ab)
        qualification = self.step(
            job,
            "Collect candidate qualification including 100k",
            "Validate comparison raw evidence and write hashes",
        )
        self.assertIn("--profile qualification", qualification)
        self.assertIn("--include-100k", qualification)

    def test_comparison_never_claims_adoption_and_uploads_before_failing_gate(self) -> None:
        job = self.job("comparison")
        validate = self.step(
            job,
            "Validate comparison raw evidence and write hashes",
            "Upload comparison raw evidence",
        )
        self.assertIn('"adoption_claim": False', validate)
        self.assertIn('qualification["configuration"]["includes_100k"] is not True', validate)
        self.assertIn('"REGRESSION": 3', validate)
        upload_index = job.index("- name: Upload comparison raw evidence")
        enforce_index = job.index(
            "- name: Enforce reviewed comparison decision after evidence upload"
        )
        self.assertLess(upload_index, enforce_index)
        upload = self.step(
            job,
            "Upload comparison raw evidence",
            "Enforce reviewed comparison decision after evidence upload",
        )
        for value in (
            "if: ${{ always() }}",
            "if-no-files-found: warn",
            "retention-days: 90",
        ):
            self.assertIn(value, upload)


if __name__ == "__main__":
    unittest.main()
