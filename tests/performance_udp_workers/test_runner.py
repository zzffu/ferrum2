from __future__ import annotations

import pathlib
import unittest

from tools.performance_udp_workers.contract import evidence_contract
from tools.performance_udp_workers.pairing import build_trials
from tools.performance_udp_workers.runner import trial_command


class RunnerTests(unittest.TestCase):
    def test_workflow_materializes_isolated_build_at_the_exact_m4_seam(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/performance-udp-workers.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "UDP_WORKER_TARGET: ${{ github.workspace }}/target/udp-worker", workflow
        )
        self.assertIn(
            "UDP_WORKER_BINARIES: ${{ github.workspace }}/target/profiling",
            workflow,
        )
        self.assertIn("-p ferrum2-rule-qualification", workflow)
        self.assertIn("materialize-profile-artifacts", workflow)
        self.assertIn('--source-dir "$UDP_WORKER_TARGET/profiling"', workflow)
        self.assertIn('--repository "$GITHUB_WORKSPACE"', workflow)
        self.assertIn('test "$profile_bin_dir" = "$UDP_WORKER_BINARIES"', workflow)

    def test_command_binds_exact_axis_and_source_contract(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        binary_dir = root / "target/profiling"
        trial = next(
            trial
            for trial in build_trials()
            if trial.phase == "comparison"
            and trial.session_topology == "multi-session"
            and trial.comparison_receive_workers == 8
            and trial.member == "variant"
        )
        command = trial_command(
            trial,
            root=root,
            binary_dir=binary_dir,
            candidate_sha="a" * 40,
            contract=evidence_contract(root),
        )
        joined = "\n".join(command)
        self.assertIn("--server-receive-workers\n8", joined)
        self.assertIn("--session-topology\nmulti-session", joined)
        self.assertIn("--candidate-sha\n" + "a" * 40, joined)
        self.assertNotIn("parent-sha", joined)


if __name__ == "__main__":
    unittest.main()
