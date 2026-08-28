from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = (
    ROOT
    / "tools"
    / "windows-tun"
    / "performance"
    / "run_windows_tun_performance_hyperv.ps1"
)
BOOTSTRAP = (
    ROOT
    / "tools"
    / "powershell"
    / "Ferrum2.WindowsTun.Lab"
    / "BundleBootstrap.ps1"
)
HOST_VM_TRANSACTION = (
    ROOT
    / "tools"
    / "powershell"
    / "Ferrum2.Performance"
    / "HostVmTransaction.ps1"
)
GUEST_TRANSACTION = (
    ROOT
    / "tools"
    / "powershell"
    / "Ferrum2.Performance"
    / "GuestTransaction.ps1"
)
COLLECTOR = (
    ROOT
    / "tools"
    / "windows-tun"
    / "performance"
    / "collect_windows_tun_performance_trial.ps1"
)
UDP_COLLECTOR = (
    ROOT
    / "tools"
    / "windows-tun"
    / "performance"
    / "collect_windows_tun_udp_boundary_diagnostic.ps1"
)


class WindowsTunSourceCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RUNNER.read_text(encoding="utf-8")
        cls.bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        cls.host_vm_transaction = HOST_VM_TRANSACTION.read_text(encoding="utf-8")
        cls.guest_transaction = GUEST_TRANSACTION.read_text(encoding="utf-8")
        cls.collectors = (
            COLLECTOR.read_text(encoding="utf-8"),
            UDP_COLLECTOR.read_text(encoding="utf-8"),
        )

    def test_verified_sources_are_captured_before_any_module_or_owner_load(self) -> None:
        source = self.source
        closure_capture = source.index(
            "$verifiedPerformanceSource = Read-Ferrum2BootstrapFlatSourceClosure"
        )
        stage_creation = source.index(
            "$capturedSourceStage = Open-Ferrum2BootstrapLockedStage"
        )
        first_module_load = source.index("Import-Module $labModulePath")
        first_owner_load = source.index(". $hostContractPath")

        self.assertLess(closure_capture, stage_creation)
        self.assertLess(stage_creation, first_module_load)
        self.assertLess(first_module_load, first_owner_load)
        self.assertEqual(
            source.count("[IO.File]::ReadAllBytes($performanceSourceBundlePath)"),
            1,
        )
        self.assertIn("-ManifestBytes $performanceSourceBundleBytes", source)

    def test_bootstrap_executes_the_bytes_compared_with_its_manifest_entry(self) -> None:
        source = self.source

        self.assertIn(
            "$bundleBootstrapBytes = [IO.File]::ReadAllBytes($bundleBootstrapPath)",
            source,
        )
        self.assertIn(
            "[Security.Cryptography.SHA256]::HashData($bundleBootstrapBytes)",
            source,
        )
        self.assertIn(
            ". ([scriptblock]::Create($utf8Strict.GetString($bundleBootstrapBytes)))",
            source,
        )
        self.assertNotIn(". $bundleBootstrapPath", source)

    def test_all_late_powershell_loads_and_guest_maps_use_the_locked_stage(self) -> None:
        source = self.source

        self.assertIn("[IO.FileShare]::Read", self.bootstrap)
        self.assertIn(
            "-RepositoryRoot $capturedRepositoryRoot)",
            source,
        )
        self.assertIn(
            "$performanceModuleRoot = Join-Path $capturedRepositoryRoot",
            source,
        )
        self.assertIn(
            "$topologyRuntimePath = Join-Path $capturedLabRoot",
            source,
        )
        self.assertIn(
            "finally {\n    Close-Ferrum2BootstrapLockedStage -Stage "
            "$capturedSourceStage\n}",
            source,
        )

    def test_capture_helpers_bind_the_canonical_required_root(self) -> None:
        source = self.source
        self.assertIn(
            "-RepositoryRoot $repositoryRoot -RequiredRoot $repositoryRoot",
            source,
        )
        self.assertIn(
            "-RequiredRoot $RequiredRoot -RelativePath $RelativePath",
            self.bootstrap,
        )

    def test_runner_uses_the_canonical_lab_capture_api_without_local_helpers(self) -> None:
        source = self.source

        for helper in (
            "Read-Ferrum2CapturedFile",
            "Get-Ferrum2CapturedSha256",
            "Get-Ferrum2CapturedSourceClosure",
            "Add-Ferrum2CapturedDependency",
            "New-Ferrum2CapturedSourceStage",
            "Remove-Ferrum2CapturedSourceStage",
        ):
            self.assertNotIn(f"function {helper}", source)
        for canonical in (
            "Read-Ferrum2BootstrapFlatSourceClosure",
            "Add-Ferrum2BootstrapSourceDependency",
            "Open-Ferrum2BootstrapLockedStage",
            "Close-Ferrum2BootstrapLockedStage",
        ):
            self.assertIn(f"function {canonical}", self.bootstrap)

    def test_guest_bundle_manifest_stays_within_its_controller_root(self) -> None:
        self.assertIn(
            'Join-Path $performanceControllerBundleRoot "controller-bundle.json"',
            self.host_vm_transaction,
        )
        self.assertIn(
            'Join-Path $controllerBundleRoot "controller-bundle.json"',
            self.guest_transaction,
        )
        self.assertNotIn(
            'Join-Path $InputRoot "controller-bundle.json"',
            self.guest_transaction,
        )
        for collector in self.collectors:
            self.assertIn(
                'Join-Path $PSScriptRoot "controller-bundle.json"',
                collector,
            )
            self.assertNotIn(
                "Split-Path -Parent $PSScriptRoot",
                collector,
            )

    def test_guest_transaction_returns_only_its_closed_result(self) -> None:
        self.assertIn(
            "[void](Add-Type -Path $processOwnerSource)",
            self.guest_transaction,
        )
        self.assertTrue(self.guest_transaction.rstrip().endswith("$guestControllerResult"))

    def test_udp_diagnostic_exits_before_formal_evidence_reduction(self) -> None:
        result = self.source.index(". $hostUdpResultPath")
        diagnostic_exit = self.source.index(
            "if ($instrumentedDiagnosticMode) {\n    exit 0\n}",
            result,
        )
        formal_evidence = self.source.index("$rawEvidence =", result)

        self.assertLess(result, diagnostic_exit)
        self.assertLess(diagnostic_exit, formal_evidence)

    def test_script_validation_selects_bounded_pairs_and_skips_reduction(self) -> None:
        source = self.source
        raw_evidence = source.index('$rawEvidence =')
        validation = source.index('if ($scriptValidationMode) {', raw_evidence)
        reducer = source.index('$summaryArguments =', validation)

        self.assertLess(raw_evidence, validation)
        self.assertLess(validation, reducer)
        self.assertIn("qualification = $false", source[validation:reducer])
        self.assertIn("formal_plan_trials = @($plan.trials).Count", source)
        self.assertIn(
            "[int]$_.pair -le $scriptValidationPairCount",
            self.host_vm_transaction,
        )
        self.assertIn(
            "[int]$_.pair -le $ValidationPairCountValue",
            self.guest_transaction,
        )
        self.assertIn(
            "$executionTrials.Count -ne (18 * $scriptValidationPairCount)",
            self.host_vm_transaction,
        )
        self.assertIn(
            "$executionTrials.Count -ne (18 * $ValidationPairCountValue)",
            self.guest_transaction,
        )


if __name__ == "__main__":
    unittest.main()
