"""Pure PowerShell readback and run-owned file export; no host runner is loaded."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required for offline readback")
class WindowsTunCleanupReadbackTests(unittest.TestCase):
    def test_retired_identities_and_recovery_diagnostics_remain_verifiable(self) -> None:
        root = Path(__file__).resolve().parents[2]
        supervisor = Path(tempfile.gettempdir()) / (
            "ferrum2-host-qualification-supervisor-" + uuid.uuid4().hex
        )
        supervisor.mkdir()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-File",
                     str(root / "tests/platform/test_windows_tun_cleanup_readback.ps1"),
                     "-ScratchDirectory", temporary, "-SupervisorDirectory", str(supervisor)],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("offline_cleanup_readback_and_supervisor_evidence=PASS", result.stdout)
        finally:
            shutil.rmtree(supervisor)
