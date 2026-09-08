"""Offline family admission, readback, and owned file export; no host runner is loaded."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required for offline readback")
class WindowsTunCleanupReadbackTests(unittest.TestCase):
    def test_family_ownership_residue_and_recovery_diagnostics(self) -> None:
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
                    capture_output=True, timeout=30, check=False,
                )
                diagnostics = (result.stdout + result.stderr).decode("utf-8", errors="backslashreplace")
                self.assertEqual(result.returncode, 0, diagnostics)
        finally:
            shutil.rmtree(supervisor)
