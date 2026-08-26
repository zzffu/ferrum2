import copy
import json
import pathlib
import tempfile
import unittest

from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import decision as linux_decision
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy
from tools.performance_candidate.linux import trial as linux_trial

class LinuxSummaryFixture(unittest.TestCase):
    PARENT_SHA = "1" * 40
    CANDIDATE_SHA = "2" * 40

    def setUp(self) -> None:
        self.owners: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for owner in reversed(self.owners):
            owner.cleanup()

    def plan(
        self,
        mode: str,
        scenario: str,
        *,
        decision_policy: dict[str, object] | None = None,
        warmup_seconds: int = 3,
        active_seconds: int = 30,
        pairs: int = 6,
    ) -> dict[str, object]:
        return linux_plan.create_plan(
            mode=mode,
            selection=scenario,
            warmup_seconds=str(warmup_seconds),
            active_seconds=str(active_seconds),
            pairs=str(pairs),
            decision_policy=(
                copy.deepcopy(linux_policy.UNCALIBRATED_POLICY)
                if decision_policy is None
                else decision_policy
            ),
        )

    def roots(self) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        owner = tempfile.TemporaryDirectory(prefix="ferrum2-performance-evidence-")
        self.owners.append(owner)
        root = pathlib.Path(owner.name)
        parent = root / "parent"
        candidate = root / "candidate"
        parent.mkdir()
        candidate.mkdir()
        return root, parent, candidate

    def row(
        self,
        plan: dict[str, object],
        scenario: str,
        pair: int,
        member: str,
        *,
        value: object | None = None,
    ) -> dict[str, object]:
        metric, direction, _family = linux_catalog.SCENARIO_CATALOG[scenario]
        topology, payload_bytes, socks_bytes, upstream_bytes = (
            linux_catalog.SCENARIO_EVIDENCE[scenario]
        )
        if value is None:
            if member == "parent":
                value = 100
            else:
                value = 110 if direction == "higher_is_better" else 90
        order = 1 if (pair % 2 == 1) == (member == "parent") else 2
        sha = self.PARENT_SHA if member == "parent" else self.CANDIDATE_SHA
        member_digit = "a" if member == "parent" else "b"
        contract = next(
            entry["evidence_contract"]
            for entry in plan["scenarios"]
            if entry["scenario"] == scenario
        )
        return {
            "schema_version": linux_trial.PROFILE_TRIAL_SCHEMA_VERSION,
            "kind": "m18_profile_trial",
            "parent_sha": self.PARENT_SHA,
            "candidate_sha": self.CANDIDATE_SHA,
            "member": member,
            "pair": pair,
            "order": order,
            "build_profile": "current",
            "scenario": scenario,
            "warmup_seconds": plan["warmup_seconds"],
            "active_seconds": plan["active_seconds"],
            "topology": topology,
            "application_payload_bytes": payload_bytes,
            "socks_datagram_bytes": socks_bytes,
            "upstream_wire_bytes": upstream_bytes,
            "sha": sha,
            "tree": ("3" if member == "parent" else "4") * 40,
            "runner_sha256": member_digit * 64,
            "client_sha256": ("c" if member == "parent" else "d") * 64,
            "server_sha256": ("e" if member == "parent" else "f") * 64,
            "rustc": "rustc 1.97.1 test",
            "kernel": "test-kernel",
            "cpu_model": "test-cpu",
            "cpu_count": 8,
            "memory_kib": 16_777_216,
            "metric": metric,
            "unit": contract["unit"],
            "value": value,
            "checked_units": 1_000,
            "p99_nanoseconds": value if metric == "p99_nanoseconds" else None,
            "io_completions": 2_000,
            "scale": None,
            "producer_source_sha256": contract["producer_source_sha256"],
            "controller_source_sha256": contract["controller_source_sha256"],
            "semantic_recipe_sha256": contract["semantic_recipe_sha256"],
            "evidence_bundle_sha256": contract["evidence_bundle_sha256"],
            "environment_identity": {
                "runner_image": contract["runner_image"],
                "rustc": "rustc 1.97.1 test",
                "kernel": "test-kernel",
                "cpu_model": "test-cpu",
                "cpu_count": 8,
                "memory_kib": 16_777_216,
                "build_profile": "current",
            },
            "cleanup": copy.deepcopy(contract["cleanup_contract"]),
            "correctness": "PASS",
            "status": "PASS",
        }

    def populate(
        self,
        plan: dict[str, object],
        parent_root: pathlib.Path,
        candidate_root: pathlib.Path,
        values: dict[tuple[str, int, str], object] | None = None,
    ) -> None:
        values = values or {}
        for scenario in plan["scenarios"]:
            name = scenario["scenario"]
            for pair in range(1, plan["pairs"] + 1):
                for member, root in (
                    ("parent", parent_root),
                    ("candidate", candidate_root),
                ):
                    value = values.get((name, pair, member))
                    row = self.row(plan, name, pair, member, value=value)
                    (root / f"{name}-{member}-{pair}.jsonl").write_text(
                        json.dumps(row, sort_keys=True, allow_nan=True) + "\n",
                        encoding="utf-8",
                    )

    def summarize(
        self,
        plan: dict[str, object],
        parent_root: pathlib.Path,
        candidate_root: pathlib.Path,
    ) -> dict[str, object]:
        return linux_decision.summarize_evidence(
            plan=plan,
            parent_root=parent_root,
            candidate_root=candidate_root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

    @staticmethod
    def rewrite(path: pathlib.Path, change) -> None:
        row = json.loads(path.read_text(encoding="utf-8"))
        change(row)
        path.write_text(
            json.dumps(row, sort_keys=True, allow_nan=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def materialize_policy(
        root: pathlib.Path, policy: dict[str, object]
    ) -> tuple[pathlib.Path, dict[str, object]]:
        path = root / "decision-policy.json"
        document = {
            "schema_version": policy["schema_version"],
            "policy_id": policy["policy_id"],
            "scenarios": policy["scenarios"],
        }
        path.write_text(
            json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        return path, linux_policy.load_decision_policy(path)

    def fresh_diagnostic(self) -> tuple[dict[str, object], pathlib.Path, pathlib.Path]:
        plan = self.plan("diagnostic", "tcp-bulk")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        return plan, parent, candidate
