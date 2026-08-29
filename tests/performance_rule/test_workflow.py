from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "performance-rule.yml"


class PerformanceRuleWorkflowOrchestrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def job(self, name: str, following: str | None = None) -> str:
        start = self.workflow.index(f"  {name}:\n")
        if following is None:
            return self.workflow[start:]
        return self.workflow[
            start : self.workflow.index(f"  {following}:\n", start + 1)
        ]

    @staticmethod
    def ordered(text: str, names: tuple[str, ...]) -> None:
        offsets = [text.index(f"- name: {name}") for name in names]
        if offsets != sorted(offsets):
            raise AssertionError(f"workflow step order changed: {names}")

    def test_dispatch_permissions_and_workflow_size_are_closed(self) -> None:
        workflow = self.workflow
        for value in (
            "workflow_call:",
            "workflow_dispatch:",
            "candidate_sha:",
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
        self.assertLess(len(workflow.splitlines()), 450)
        self.assertNotIn("python3 -B - <<", workflow)
        self.assertNotIn("urllib", workflow)
        self.assertNotIn("import ", workflow)
        for current_name in (
            "release-aa-v7.json",
            "release-ab-v7.stdout.json",
            "reviewed-aa-v3.stdout.json",
        ):
            self.assertIn(current_name, workflow)
        self.assertNotIn("release-aa-v6", workflow)
        self.assertNotIn("release-ab-v6", workflow)
        self.assertNotIn("reviewed-aa-v2", workflow)

    def test_reusable_invocation_is_exactly_candidate_sha_bound(self) -> None:
        workflow = self.workflow
        reusable = workflow.split("  workflow_call:\n", 1)[1].split(
            "  workflow_dispatch:\n", 1
        )[0]
        for name, type_name in (
            ("stage", "string"),
            ("candidate_sha", "string"),
            ("calibration_run_id", "number"),
            ("reviewed_by", "string"),
            ("reviewed_utc", "string"),
            ("candidate_feature", "string"),
        ):
            match = re.search(
                rf"^      {name}:\n(?P<body>(?:        .*\n)+)",
                reusable,
                re.MULTILINE,
            )
            self.assertIsNotNone(match)
            self.assertIn(f"type: {type_name}", match.group("body"))
        invocation = self.job("invocation", "calibration-aa")
        self.assertIn('[[ "$CANDIDATE_SHA" =~ ^[0-9a-f]{40}$ ]]', invocation)
        self.assertIn("*) exit 2 ;;", invocation)
        self.assertEqual(
            workflow.count("ref: ${{ inputs.candidate_sha }}"),
            2,
        )
        self.assertEqual(
            workflow.count('test "$(git rev-parse HEAD)" = "$CANDIDATE_SHA"'),
            2,
        )
        self.assertNotIn("$GITHUB_SHA", workflow)

    def test_every_action_uses_the_reviewed_repository_pin(self) -> None:
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

    def test_calibration_preflights_before_build_and_workload(self) -> None:
        job = self.job("calibration-aa", "comparison")
        self.ordered(
            job,
            (
                "Checkout exact calibration source",
                "Initialize calibration evidence paths",
                "Require exact clean source and AMD host identity",
                "Install pinned Rust toolchain",
                "Build feature-free calibrated parent",
                "Collect controller v7 six-pair A/A qualification evidence",
                "Validate and bind calibration evidence identities",
                "Upload calibration evidence and exact parent",
            ),
        )
        self.assertIn("CALIBRATION_EVIDENCE=%s", job)
        self.assertIn("tools.ci.performance_rule_workflow capture-host", job)
        self.assertIn("tools.ci.performance_rule_workflow calibration-manifest", job)
        self.assertIn('test "$(git rev-parse HEAD)" = "$CANDIDATE_SHA"', job)
        self.assertIn('--expected-sha "$CANDIDATE_SHA"', job)
        self.assertIn("--no-default-features", job)
        self.assertNotIn('--features "$CANDIDATE_FEATURES"', job)
        self.assertEqual(job.count("--pairs 6"), 1)
        self.assertIn(
            "--profile qualification --samples 101 \\\n"
            "            --iterations-per-sample 1 --workspace-root .",
            job,
        )
        self.assertEqual(job.count("--iterations-per-sample 1"), 1)
        self.assertNotIn("--timeout-seconds", job)
        self.assertIn('test "$controller_status" -eq 4', job)

    def test_comparison_sequence_preserves_review_and_independent_candidate(
        self,
    ) -> None:
        job = self.job("comparison")
        self.ordered(
            job,
            (
                "Checkout exact comparison source",
                "Validate comparison inputs and initialize paths",
                "Require exact AMD comparison host identity",
                "Resolve one successful calibration workflow attempt",
                "Download exact calibration run artifact",
                "Verify calibration run source host and artifact closure",
                "Create explicitly reviewed source-bound calibration",
                "Install pinned Rust toolchain",
                "Build independent candidate feature binary",
                "Collect reviewed six-pair A/B qualification evidence",
                "Collect candidate qualification including 100k",
                "Validate comparison raw evidence and write hashes",
                "Upload comparison raw evidence",
                "Enforce reviewed comparison decision after evidence upload",
            ),
        )
        for command in (
            "prepare-comparison",
            "capture-host",
            "resolve-calibration",
            "verify-calibration",
            "validate-comparison",
        ):
            self.assertIn(f"tools.ci.performance_rule_workflow {command}", job)
        self.assertIn("tools.performance_rule review-calibration", job)
        self.assertIn('--features "$CANDIDATE_FEATURES"', job)
        self.assertIn('--parent "$CALIBRATED_PARENT"', job)
        self.assertIn('--candidate "$CANDIDATE_BINARY"', job)
        self.assertIn('--calibration "$REVIEWED_CALIBRATION"', job)
        self.assertEqual(job.count("--pairs 6"), 1)
        self.assertEqual(
            job.count(
                "--profile qualification --samples 101 \\\n"
                "            --iterations-per-sample 1 --workspace-root ."
            ),
            1,
        )
        self.assertEqual(job.count("--iterations-per-sample 1"), 2)
        self.assertNotIn("--timeout-seconds", job)
        self.assertIn("--profile qualification", job)
        self.assertIn("--include-100k", job)
        qualification_step = job.split(
            "- name: Collect candidate qualification including 100k", 1
        )[1].split("- name: Validate comparison raw evidence and write hashes", 1)[0]
        self.assertEqual(qualification_step.count("--iterations-per-sample 1"), 1)
        self.assertNotIn("--iterations-per-sample 8192", qualification_step)
        self.assertEqual(job.count('--expected-sha "$CANDIDATE_SHA"'), 3)

    def test_cross_run_download_and_always_uploads_remain_explicit(self) -> None:
        workflow = self.workflow
        for value in (
            "name: ${{ env.CALIBRATION_ARTIFACT_NAME }}",
            "github-token: ${{ github.token }}",
            "repository: ${{ github.repository }}",
            "run-id: ${{ inputs.calibration_run_id }}",
            "performance-rule-calibration-${{ github.run_id }}-${{ github.run_attempt }}",
            "performance-rule-comparison-${{ github.run_id }}-${{ github.run_attempt }}",
        ):
            self.assertIn(value, workflow)
        self.assertEqual(workflow.count("if: ${{ always() }}"), 3)
        self.assertEqual(workflow.count("retention-days: 90"), 2)
        self.assertEqual(workflow.count("if-no-files-found: warn"), 2)


if __name__ == "__main__":
    unittest.main()
