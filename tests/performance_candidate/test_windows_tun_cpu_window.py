"""Offline CPU/work decisions through both host summary interfaces."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_windows_tun_host_evidence import (
    BASELINE, CANDIDATE, POLICY, ROOT, plan_for, scale_trial_work, summary_for,
    validate_windows_tun_host_evidence, write_common, write_json, write_trials,
)


class WindowsTunCpuWindowTests(unittest.TestCase):
    def check_summaries(self, *, powershell: bool) -> None:
        for topology, guarded_role in (
            ("ClientDirect", "client"), ("EndToEnd", "client"),
            ("EndToEnd", "server"),
        ):
            for increased_cost in (False, True):
                with self.subTest(topology=topology, role=guarded_role,
                                  increased_cost=increased_cost), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    plan = plan_for("Quick", topology)
                    write_common(root, "Quick", topology, plan)
                    trials = write_trials(root, plan)
                    baseline_work = {(row["scenario"], row["pair"]): row["checked_units"] for row in trials if row["member"] == "baseline"}
                    for trial in trials:
                        candidate = trial["member"] == "candidate"
                        # Both windows satisfy the actual active-time evidence contract.
                        window = (20.0 if candidate else 10.0) if increased_cost else (
                            10.0 if candidate else 20.0
                        )
                        elapsed = trial["workload_measurements"].get(
                            "active_elapsed_nanoseconds", trial["active_seconds"] * 1_000_000_000
                        ) / 1_000_000_000
                        window = max(window, elapsed + 0.01)
                        trial["cpu_sample_seconds"] = window
                        # Preserve each scenario's actual work and adjust CPU seconds
                        # by its work ratio; the regression case adds 50% CPU/work.
                        if candidate:
                            scale_trial_work(trial, 2)
                        for role in ("client", "server"):
                            if trial[f"{role}_cpu_percent"] is not None:
                                work_ratio = trial["checked_units"] / baseline_work[(trial["scenario"], trial["pair"])]
                                seconds = 2.0 * work_ratio
                                if candidate and increased_cost and role == guarded_role:
                                    seconds *= 1.5
                                trial[f"{role}_cpu_percent"] = seconds / window * 100.0
                        write_json(root / "trials" / f"{trial['sequence']:03d}" / "trial.json", trial)
                    expected = summary_for(plan, trials)
                    for scenario in expected["scenarios"]:
                        scenario["qualification_status"] = (
                            "regression" if increased_cost else "candidate-win"
                        )
                    if powershell:
                        write_json(root / "input.json", {"plan": plan, "trials": trials})
                        script = root / "summary.ps1"
                        script.write_text(
                            "param($Owner, $InputPath)\n$ErrorActionPreference = 'Stop'\n"
                            ". $Owner\n$data = Get-Content -Raw -LiteralPath $InputPath | ConvertFrom-Json\n"
                            "New-Ferrum2HostSummary -Context $data.plan -Plan $data.plan "
                            "-Trials $data.trials | ConvertTo-Json -Depth 30\n",
                            encoding="utf-8",
                        )
                        result = subprocess.run(
                            ["pwsh", "-NoProfile", "-File", str(script),
                             str(ROOT / "tools/powershell/Ferrum2.Performance/HostProfiles.ps1"),
                             str(root / "input.json")],
                            capture_output=True, text=True, timeout=30, check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        actual = json.loads(result.stdout)
                        self.assertEqual(actual, expected)
                    else:
                        actual = expected
                    write_json(root / "summary.json", actual)
                    report = validate_windows_tun_host_evidence(
                        evidence_root=root, baseline_sha=BASELINE, candidate_sha=CANDIDATE,
                        mode="Quick", topology=topology, policy_path=POLICY,
                    )
                    self.assertEqual(report["status"], "REGRESSION" if increased_cost else "CANDIDATE_WIN")
                    self.assertIn("lower_is_better", {row["direction"] for row in actual["scenarios"]})

    def test_python_evidence_uses_cpu_seconds_per_checked_work(self) -> None:
        self.check_summaries(powershell=False)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required for host reducer")
    def test_powershell_summary_uses_cpu_seconds_per_checked_work(self) -> None:
        self.check_summaries(powershell=True)
