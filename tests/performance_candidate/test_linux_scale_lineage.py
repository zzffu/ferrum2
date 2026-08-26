import copy
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from tests.performance_candidate._shared_fixture import (
    POLICY_PATH,
    SCALE_POLICY_PATH,
    rewrite_scale_full_completions,
    synthetic_scale_row,
)
from tools.performance_candidate import cli as controller_cli
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import decision as linux_decision
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy
from tools.performance_candidate.linux import scale as linux_scale
from tools.performance_candidate.linux import scale_lineage

class ScaleLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ferrum2-scale-lineage-")
        self.repository = pathlib.Path(self.temporary.name) / "repository"
        self.repository.mkdir()
        self._git("init", "--quiet", "--initial-branch=main")
        self._git("config", "user.name", "Scale Test")
        self._git("config", "user.email", "scale@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        for path, replacements in linux_scale.SCALE_COUNTERFACTUAL_REPLACEMENTS.items():
            destination = self.repository / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            literals = b"\n".join(old for old, _new in replacements)
            destination.write_bytes(b"prefix\n" + literals + b"\nsuffix\n")
        (self.repository / "extra.txt").write_text("unchanged\n", encoding="utf-8")
        self._git("add", ".")
        self.head = self._commit("H final tree")
        self._apply_counterfactual()
        self.parent = self._commit("P16 exact counterfactual")
        self._git("checkout", "--quiet", self.head, "--", ".")
        self.candidate = self._commit("C32 restore final tree")
        binary_root = pathlib.Path(self.temporary.name) / "binaries"
        binary_root.mkdir()
        self.paths = {}
        for name in (
            "runner",
            "parent-client",
            "parent-server",
            "candidate-client",
            "candidate-server",
        ):
            path = binary_root / name
            path.write_bytes(name.encode())
            self.paths[name] = path

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
        self._git("commit", "--quiet", "-am", message)
        return self._git("rev-parse", "HEAD")

    def _apply_counterfactual(self) -> None:
        for path, replacements in linux_scale.SCALE_COUNTERFACTUAL_REPLACEMENTS.items():
            destination = self.repository / path
            value = destination.read_bytes()
            for old, new in replacements:
                self.assertEqual(value.count(old), 1)
                value = value.replace(old, new, 1)
            destination.write_bytes(value)

    def build(self, parent: str | None = None, candidate: str | None = None):
        return scale_lineage.build_scale_lineage(
            repository=self.repository,
            head_sha=self.head,
            parent_sha=parent or self.parent,
            candidate_sha=candidate or self.candidate,
            runner=self.paths["runner"],
            parent_client=self.paths["parent-client"],
            parent_server=self.paths["parent-server"],
            candidate_client=self.paths["candidate-client"],
            candidate_server=self.paths["candidate-server"],
        )

    def test_exact_h_p16_c32_lineage_binds_trees_patch_and_binaries(self) -> None:
        source = scale_lineage.validate_scale_source_lineage(
            self.repository, self.head, self.parent, self.candidate
        )
        self.assertEqual(source["head_tree"], source["candidate_tree"])
        self.assertEqual(
            controller_cli.main(
                [
                    "scale-source-lineage",
                    "--repository",
                    str(self.repository),
                    "--head-sha",
                    self.head,
                    "--parent-sha",
                    self.parent,
                    "--candidate-sha",
                    self.candidate,
                ]
            ),
            0,
        )
        lineage = self.build()
        self.assertEqual(lineage["head_tree"], lineage["candidate_tree"])
        self.assertNotEqual(lineage["head_tree"], lineage["parent_tree"])
        self.assertRegex(lineage["counterfactual_patch_sha256"], r"^[0-9a-f]{64}$")
        scale_lineage.validate_scale_lineage_repository(self.repository, lineage)

    def test_lineage_rejects_patch_digest_parent_chain_and_extra_path(self) -> None:
        lineage = self.build()
        tampered = copy.deepcopy(lineage)
        tampered["counterfactual_patch_sha256"] = "0" * 64
        with self.assertRaisesRegex(json_contract.CandidateControlError, "patch digest"):
            scale_lineage.validate_scale_lineage_repository(self.repository, tampered)
        tampered = copy.deepcopy(lineage)
        tampered["candidate_sha"] = self.head
        with self.assertRaises(json_contract.CandidateControlError):
            scale_lineage.validate_scale_lineage_repository(self.repository, tampered)

        self._git("checkout", "--quiet", "--detach", self.head)
        self._apply_counterfactual()
        (self.repository / "extra.txt").write_text("mutated\n", encoding="utf-8")
        extra_parent = self._commit("P16 with extra path")
        self._git("checkout", "--quiet", self.head, "--", ".")
        extra_candidate = self._commit("C32 restore after extra path")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "unexpected path"):
            self.build(extra_parent, extra_candidate)

    def test_scale_summary_command_revalidates_real_lineage_and_writes_all_outcomes(
        self,
    ) -> None:
        lineage = self.build()
        scale_policy = linux_scale.load_scale_safety_policy(SCALE_POLICY_PATH)
        plan = linux_plan.create_plan(
            mode="qualification",
            selection=linux_scale.SCALE_SCENARIO,
            warmup_seconds="10",
            active_seconds="30",
            pairs="6",
            decision_policy=linux_policy.load_decision_policy(POLICY_PATH),
            scale_safety_policy=scale_policy,
            scale_lineage=lineage,
        )
        evidence_root = pathlib.Path(self.temporary.name) / "evidence"
        parent_root = evidence_root / "parent"
        candidate_root = evidence_root / "candidate"
        parent_root.mkdir(parents=True)
        candidate_root.mkdir(parents=True)

        def bind(row: dict[str, object]) -> None:
            member = row["member"]
            row["parent_sha"] = self.parent
            row["candidate_sha"] = self.candidate
            row["sha"] = lineage[f"{member}_sha"]
            row["tree"] = lineage[f"{member}_tree"]
            row["runner_sha256"] = lineage["runner_sha256"]
            row["client_sha256"] = lineage[f"{member}_client_sha256"]
            row["server_sha256"] = lineage[f"{member}_server_sha256"]

        rows: dict[tuple[str, int], dict[str, object]] = {}
        for pair in range(1, 7):
            for member in ("parent", "candidate"):
                row = synthetic_scale_row(
                    pair=pair,
                    member=member,
                    full_completions=(
                        101 if member == "candidate" and pair <= 4 else 100
                    ),
                )
                bind(row)
                rows[(member, pair)] = row

        def write_rows() -> None:
            for (member, pair), row in rows.items():
                root = parent_root if member == "parent" else candidate_root
                (root / f"scale-{member}-{pair}.jsonl").write_text(
                    json.dumps(row, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )

        write_rows()
        plan_path = evidence_root / "plan.json"
        output = evidence_root / "summary.json"
        markdown = evidence_root / "summary.md"
        linux_plan.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent_root,
                "candidate_root": candidate_root,
                "parent_sha": self.parent,
                "candidate_sha": self.candidate,
                "policy": POLICY_PATH,
                "scale_policy": SCALE_POLICY_PATH,
                "repository": self.repository,
                "output": output,
                "markdown": markdown,
            },
        )()

        self.assertEqual(linux_decision.run_summary_command(arguments), 4)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "CALIBRATION_REQUIRED",
        )
        self.assertIn(
            "CALIBRATION_REQUIRED", markdown.read_text(encoding="utf-8")
        )

        safety = rows[("candidate", 1)]
        completions = list(safety["scale"]["traffic"]["full_flow_completions"])
        completions[0] = 0
        rewrite_scale_full_completions(safety, completions)
        write_rows()
        self.assertEqual(linux_decision.run_summary_command(arguments), 3)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "REGRESSION",
        )
        self.assertIn(
            "REGRESSION", markdown.read_text(encoding="utf-8")
        )

        safety["scale"]["traffic"]["full_checked_bytes"] += 1
        write_rows()
        self.assertEqual(linux_decision.run_summary_command(arguments), 2)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "INVALID",
        )
        self.assertIn("INVALID", markdown.read_text(encoding="utf-8"))
