import os
import pathlib
import subprocess
import tempfile
import unittest

from tools.performance_candidate import identity as git_identity
from tools.performance_candidate import json_contract

class GitRelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ferrum2-performance-git-")
        self.repository = pathlib.Path(self.temporary.name)
        self._git("init", "--quiet", "--initial-branch=main")
        self._git("config", "user.name", "Performance Test")
        self._git("config", "user.email", "performance@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        self.base = self._commit("base")
        self.direct = self._commit("direct")
        self.multiple = self._commit("multiple")
        self._git("switch", "--quiet", "--orphan", "unrelated")
        self.unrelated = self._commit("unrelated")
        self._git("switch", "--quiet", "main")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            }
        )
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def _commit(self, message: str) -> str:
        self._git("commit", "--quiet", "--allow-empty", "-m", message)
        return self._git("rev-parse", "HEAD")

    def test_direct_and_multi_commit_candidates_are_accepted(self) -> None:
        self.assertEqual(
            git_identity.validate_git_relation(self.repository, self.base, self.direct),
            (self.base, self.direct),
        )
        self.assertEqual(
            git_identity.validate_git_relation(self.repository, self.base, self.multiple),
            (self.base, self.multiple),
        )
        self.assertEqual(
            git_identity.validate_git_relation(
                self.repository, self.base.upper(), self.multiple.upper()
            ),
            (self.base, self.multiple),
        )

    def test_same_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(json_contract.CandidateControlError, "different"):
            git_identity.validate_git_relation(self.repository, self.base, self.base)

    def test_calibration_requires_and_accepts_exactly_one_same_commit(self) -> None:
        self.assertEqual(
            git_identity.validate_git_relation(
                self.repository,
                self.base,
                self.base,
                run_kind="calibration-aa",
            ),
            (self.base, self.base),
        )
        with self.assertRaisesRegex(json_contract.CandidateControlError, "identical"):
            git_identity.validate_git_relation(
                self.repository,
                self.base,
                self.direct,
                run_kind="calibration-aa",
            )

    def test_unrelated_history_is_rejected(self) -> None:
        with self.assertRaisesRegex(json_contract.CandidateControlError, "not an ancestor"):
            git_identity.validate_git_relation(self.repository, self.base, self.unrelated)

    def test_reverse_ancestry_is_rejected(self) -> None:
        with self.assertRaisesRegex(json_contract.CandidateControlError, "not an ancestor"):
            git_identity.validate_git_relation(self.repository, self.multiple, self.base)

    def test_missing_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(json_contract.CandidateControlError, "available commit"):
            git_identity.validate_git_relation(self.repository, "f" * 40, self.multiple)

    def test_annotated_tag_object_is_not_accepted_as_a_commit_sha(self) -> None:
        self._git("tag", "--annotate", "candidate-tag", "--message", "candidate")
        tag_object = self._git("rev-parse", "candidate-tag")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "available commit"):
            git_identity.validate_git_relation(self.repository, self.base, tag_object)

    def test_shallow_history_without_parent_is_rejected(self) -> None:
        shallow_owner = tempfile.TemporaryDirectory(
            prefix="ferrum2-performance-shallow-"
        )
        self.addCleanup(shallow_owner.cleanup)
        shallow = pathlib.Path(shallow_owner.name) / "checkout"
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--depth=1",
                "--branch=main",
                self.repository.as_uri(),
                str(shallow),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with self.assertRaisesRegex(json_contract.CandidateControlError, "complete history"):
            git_identity.validate_git_relation(shallow, self.base, self.multiple)
