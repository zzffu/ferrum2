import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import unittest

from tools.performance_candidate.windows_tun.recipe import (
    WINDOWS_TUN_PERFORMANCE_SOURCE_PATHS,
)

ROOT = Path(__file__).resolve().parents[2]
RUNNER = (
    ROOT
    / "tools"
    / "windows-tun"
    / "performance"
    / "run_windows_tun_performance_host.ps1"
)
MODULE_ROOT = ROOT / "tools" / "powershell" / "Ferrum2.Performance"
MODULE_MANIFEST = MODULE_ROOT / "Ferrum2.Performance.psd1"
PROCESS_OWNER = MODULE_ROOT / "PerformanceProcessOwner.cs"
OWNERSHIP = MODULE_ROOT / "HostOwnership.ps1"
PERFORMANCE_BUNDLE = MODULE_ROOT / "bundle.json"
M4_PACKAGE_ROOT = ROOT / "tools" / "ferrum2-m4-qualification"
M4_BUNDLE = (
    M4_PACKAGE_ROOT / "src" / "m4_support" / "windows_tun" / "bundle.json"
)


class WindowsTunHostRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.process_owner = PROCESS_OWNER.read_text(encoding="utf-8")
        cls.ownership = OWNERSHIP.read_text(encoding="utf-8")
        cls.performance_bundle = json.loads(
            PERFORMANCE_BUNDLE.read_text(encoding="utf-8")
        )

    def test_public_interface_is_host_only_and_small(self) -> None:
        for name in (
            "PlanOnly",
            "Mode",
            "BaselineSha",
            "CandidateSha",
            "EvidenceDirectory",
            "AcknowledgeHostNetworkMutation",
            "RecoveryOnly",
        ):
            self.assertIn(f"${name}", self.runner)
        for obsolete in (
            "SafetyCheck",
            "VmName",
            "Checkpoint",
            "TopologyManifest",
            "CredentialPath",
            "WintunZip",
            "SupportPid",
        ):
            self.assertNotIn(f"${obsolete}", self.runner)

    def test_runner_has_no_hyperv_or_sing_box_control_surface(self) -> None:
        lowered = self.runner.lower()
        for forbidden in (
            "restore-vmsnapshot",
            "start-vm",
            "invoke-command -vm",
            "set-dnsclientserveraddress",
            "disable-netadapter",
            "enable-netadapter",
            "sing-box.exe",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_source_bundle_is_exact_and_content_addressed(self) -> None:
        manifest = self.performance_bundle
        self.assertEqual(
            set(manifest),
            {"schema_version", "kind", "entrypoint", "files"},
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(
            manifest["kind"],
            "ferrum2.windows-tun-performance-source-bundle.v2",
        )
        self.assertEqual(
            manifest["entrypoint"],
            "tools/windows-tun/performance/run_windows_tun_performance_host.ps1",
        )
        rows = {row["path"]: row for row in manifest["files"]}
        self.assertEqual(set(rows), set(WINDOWS_TUN_PERFORMANCE_SOURCE_PATHS))
        for relative, row in rows.items():
            payload = (ROOT / relative).read_bytes()
            self.assertEqual(row["bytes"], len(payload))
            self.assertEqual(row["sha256"], hashlib.sha256(payload).hexdigest())
        for obsolete in (
            "run_windows_tun_performance_hyperv.ps1",
            "GuestTransaction.ps1",
            "HostVmTransaction.ps1",
            "RuntimeStaging.ps1",
            "windows_tun_hyperv_support_topology_plan.json",
        ):
            self.assertNotIn(obsolete, PERFORMANCE_BUNDLE.read_text(encoding="utf-8"))

    def test_workload_source_bundle_covers_complete_harness_source(self) -> None:
        manifest = json.loads(M4_BUNDLE.read_text(encoding="utf-8"))
        self.assertEqual(
            (manifest["kind"], manifest["entrypoint"]),
            ("ferrum2.m4-windows-tun-source-bundle.v2", "src/main.rs"),
        )
        rows = {row["path"]: row for row in manifest["files"]}
        actual = {"Cargo.toml"}
        actual.update(
            path.relative_to(M4_PACKAGE_ROOT).as_posix()
            for path in (M4_PACKAGE_ROOT / "src").rglob("*.rs")
        )
        self.assertEqual(set(rows), actual)
        for relative, row in rows.items():
            payload = (M4_PACKAGE_ROOT / relative).read_bytes()
            self.assertEqual(row["bytes"], len(payload))
            self.assertEqual(row["sha256"], hashlib.sha256(payload).hexdigest())

    def test_process_owner_contains_descendants_in_kill_on_close_job(self) -> None:
        self.assertIn("AssignProcessToJobObject", self.process_owner)
        self.assertIn("JobObjectLimitKillOnJobClose", self.process_owner)
        self.assertIn("CreateSuspended", self.process_owner)
        self.assertIn("ResumeThread", self.process_owner)
        self.assertIn("CloseGroup", self.process_owner)

    def test_cleanup_uses_ledger_identities_not_global_name_sweeps(self) -> None:
        self.assertIn("Remove-Ferrum2LedgerResources", self.ownership)
        self.assertIn("process identity mismatch", self.ownership)
        self.assertIn("owned adapter GUID identity mismatch", self.ownership)
        self.assertIn("/remove-device $pnpId", self.ownership)
        self.assertIn('expected_interface_description = "Ferrum2 Tunnel"', self.ownership)
        for forbidden in (
            "Get-NetAdapter | Remove",
            "Stop-Process -Name",
            "0.0.0.0/0",
            "::/0",
            "Set-DnsClientServerAddress",
            "Disable-NetAdapter",
            "Enable-NetAdapter",
        ):
            self.assertNotIn(forbidden, self.ownership)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
    def test_process_owner_rejects_a_second_module_load(self) -> None:
        manifest = str(MODULE_MANIFEST).replace("'", "''")
        completed = subprocess.run(
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-Command",
                f"Import-Module '{manifest}' -ErrorAction Stop; "
                f"Import-Module '{manifest}' -Force -ErrorAction Stop",
            ],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("process owner is already loaded", completed.stderr)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
    def test_plan_only_is_unprivileged_and_excludes_long_soak(self) -> None:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        completed = subprocess.run(
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-File",
                str(RUNNER),
                "-PlanOnly",
                "-Mode",
                "Quick",
                "-BaselineSha",
                sha,
                "-CandidateSha",
                sha,
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["execution"], "explicit-authorized-windows-host")
        self.assertEqual(plan["pair_count"], 3)
        self.assertEqual(plan["trial_count"], 12)
        self.assertEqual(plan["qualification"]["product_lifecycle_cycles"], 0)
        self.assertEqual(plan["qualification"]["long_durability_soak"], "excluded")
        self.assertFalse(plan["qualification"]["vm_start"])
        self.assertFalse(plan["qualification"]["checkpoint_restore"])
        self.assertFalse(plan["qualification"]["guest_staging"])
        lifecycle_command = completed.args.copy()
        lifecycle_command[lifecycle_command.index("Quick")] = "Lifecycle"
        lifecycle_plan = json.loads(
            subprocess.run(
                lifecycle_command,
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            ).stdout
        )
        self.assertIsInstance(lifecycle_plan["trials"], list)
        self.assertEqual(len(lifecycle_plan["trials"]), 1)


if __name__ == "__main__":
    unittest.main()
