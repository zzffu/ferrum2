"""Cross-platform test support for offline CI-controller behavior tests."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


class TemporaryRepository:
    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.email", "ci-tests@example.invalid")
        self.git("config", "user.name", "CI tests")

    def close(self) -> None:
        self._temporary.cleanup()

    def git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def commit_file(self, relative: str, content: str) -> str:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.git("add", "--", relative)
        self.git("commit", "--quiet", "-m", f"update {relative}")
        return self.git("rev-parse", "HEAD")
