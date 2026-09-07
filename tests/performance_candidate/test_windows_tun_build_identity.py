"""Build evidence binds the executed shared harness, not unused candidate harness code."""
import copy
import json
import hashlib
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.windows_tun.summary import validate_windows_tun_host_evidence
from test_windows_tun_host_evidence import (
    BASELINE, CANDIDATE, POLICY, plan_for, summary_for, write_common, write_json, write_trials,
)


class WindowsTunBuildIdentityTests(unittest.TestCase):
    def test_distinct_product_bundles_keep_one_exact_executed_harness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = plan_for("Quick", "EndToEnd")
            write_common(root, "Quick", "EndToEnd", plan)
            trials = write_trials(root, plan)
            write_json(root / "summary.json", summary_for(plan, trials))
            builds = json.loads((root / "builds.json").read_text(encoding="utf-8"))
            builds["candidate"]["product_m4_source_bundle_sha256"] = "e" * 64
            write_json(root / "builds.json", builds)
            self.validate(root)
            mutations = [
                ("shared_harness_sha256", "f" * 64),
                ("shared_harness_source_bundle_sha256", "e" * 64),
                ("shared_harness_commit_sha", CANDIDATE),
                ("schema_version", 1),
                ("schema_version", True),
            ]
            for field, value in mutations:
                with self.subTest(field=field, value=value):
                    invalid = copy.deepcopy(builds)
                    invalid[field] = value
                    write_json(root / "builds.json", invalid)
                    with self.assertRaises(CandidateControlError):
                        self.validate(root)
            for label in ("baseline", "candidate"):
                for field, value in (
                    ("harness_sha256", "f" * 64),
                    ("harness", "C:/different/m4-qualification.exe"),
                    ("product_m4_source_bundle_sha256", "unverified"),
                    ("commit_sha", "3" * 40),
                ):
                    with self.subTest(label=label, field=field):
                        invalid = copy.deepcopy(builds)
                        invalid[label][field] = value
                        write_json(root / "builds.json", invalid)
                        with self.assertRaises(CandidateControlError):
                            self.validate(root)
            invalid = copy.deepcopy(builds)
            invalid["candidate"]["source_bundle_sha256"] = invalid["candidate"].pop(
                "product_m4_source_bundle_sha256"
            )
            write_json(root / "builds.json", invalid)
            with self.assertRaises(CandidateControlError):
                self.validate(root)

    @staticmethod
    def validate(root: Path) -> object:
        return validate_windows_tun_host_evidence(
            evidence_root=root, baseline_sha=BASELINE, candidate_sha=CANDIDATE,
            mode="Quick", topology="EndToEnd", policy_path=POLICY,
        )


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class WindowsTunBuildProducerTests(unittest.TestCase):
    owner = Path(__file__).resolve().parents[2] / "tools/powershell/Ferrum2.Performance/HostExecution.ps1"

    def run_script(self, root: Path, script: str) -> subprocess.CompletedProcess[str]:
        path = root / "contract.ps1"
        path.write_text(script, encoding="utf-8")
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(path), str(self.owner), str(root)],
            capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_producer_executes_only_baseline_harness_for_distinct_source_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_common(root, "Quick", "EndToEnd", plan_for("Quick", "EndToEnd"))
            fixture = json.loads((root / "builds.json").read_text(encoding="utf-8"))
            fixture["candidate"]["product_m4_source_bundle_sha256"] = "e" * 64
            fixture["candidate"]["harness"] = None
            fixture["candidate"]["harness_sha256"] = None
            write_json(root / "input.json", fixture)
            self.run_script(root, r'''
param([string]$Owner, [string]$Root)
$ErrorActionPreference = "Stop"
. $Owner
$script:fixture = Get-Content (Join-Path $Root "input.json") -Raw | ConvertFrom-Json
$script:admitted = [Collections.Generic.List[string]]::new()
function Resolve-Ferrum2CommitSha { param($RepositoryRoot, $Sha) return $Sha }
function Resolve-Ferrum2WintunArchive { return "fixture.zip" }
function Expand-Ferrum2WintunDll { param($Archive, $Destination) return $script:fixture.wintun_dll_sha256 }
function Build-Ferrum2HostMember {
    param($Context, $Label, $Sha, $WintunDll, [switch]$IncludeHarness)
    $script:admitted.Add("${Label}:$($IncludeHarness.IsPresent)")
    return $script:fixture.$Label
}
function Write-AtomicJsonFile {
    param($Path, $Document)
    $Document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
}
$context = [pscustomobject]@{
    repository_root = $Root; run_root = (Join-Path $Root "owned")
    run_id = $script:fixture.run_id; evidence_directory = $Root
    performance_source_bundle_sha256 = $script:fixture.performance_source_bundle_sha256
}
$result = Initialize-Ferrum2HostBuilds -Context $context `
    -BaselineSha $script:fixture.baseline.commit_sha -CandidateSha $script:fixture.candidate.commit_sha
if (($script:admitted -join ",") -cne "baseline:True,candidate:False") { throw "unexpected harness build" }
if ($result.harness -cne $script:fixture.baseline.harness) { throw "wrong executed harness" }
''')
            actual = json.loads((root / "builds.json").read_text(encoding="utf-8-sig"))
            self.assertEqual(actual["schema_version"], 2)
            self.assertEqual(actual["candidate"]["product_m4_source_bundle_sha256"], "e" * 64)
            self.assertEqual(actual["candidate"]["harness"], actual["baseline"]["harness"])
            self.assertEqual(actual["candidate"]["harness_sha256"], actual["shared_harness_sha256"])
            self.assertEqual(actual["baseline"]["product_m4_source_bundle_sha256"], actual["shared_harness_source_bundle_sha256"])

    def test_each_source_bundle_still_rejects_changed_or_unlisted_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "tools/ferrum2-m4-qualification"
            manifest = package / "src/m4_support/windows_tun/bundle.json"
            manifest.parent.mkdir(parents=True)
            files = []
            for name, data in (("Cargo.toml", b"fixture"), ("src/main.rs", b"fn main() {}")):
                path = package / name
                path.write_bytes(data)
                files.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            write_json(manifest, {
                "schema_version": 1, "kind": "ferrum2.m4-windows-tun-source-bundle.v3",
                "entrypoint": "src/main.rs", "files": files,
            })
            self.run_script(root, r'''
param([string]$Owner, [string]$Root)
$ErrorActionPreference = "Stop"
. $Owner
$identity = Get-Ferrum2M4SourceBundleIdentity -SourceRoot $Root
if ($identity -cnotmatch '^[0-9a-f]{64}$') { throw "missing source identity" }
$main = Join-Path $Root "tools/ferrum2-m4-qualification/src/main.rs"
[IO.File]::WriteAllText($main, "fn main() { panic!(); }")
$rejected = $false
try { Get-Ferrum2M4SourceBundleIdentity -SourceRoot $Root | Out-Null } catch { $rejected = $true }
if (-not $rejected) { throw "changed source accepted" }
[IO.File]::WriteAllText($main, "fn main() {}")
[IO.File]::WriteAllText((Join-Path (Split-Path $main) "unlisted.rs"), "")
$rejected = $false
try { Get-Ferrum2M4SourceBundleIdentity -SourceRoot $Root | Out-Null } catch { $rejected = $true }
if (-not $rejected) { throw "unlisted source accepted" }
''')
