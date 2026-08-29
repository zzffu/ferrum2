import copy
import json
import pathlib
import unittest
from unittest import mock

from tests.performance_candidate._linux_summary_support import structural_metrics
from tests.performance_candidate.test_build_experiment import (
    SOURCE_SHA,
    SOURCE_TREE,
    BuildExperimentFixture,
)
from tools.performance_candidate import build_experiment, build_qualification
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux import catalog, trial
from tools.performance_candidate.linux.evidence_contract import (
    catalog_evidence_contract,
)


class BuildQualificationTests(BuildExperimentFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy = (
            pathlib.Path(__file__).resolve().parents[2]
            / "tools"
            / "performance_build_policy.json"
        )

    def plan_and_records(self):
        environment_path = self.environment_path("github-hosted")
        plan = build_experiment.create_experiment_plan(
            environment_path=environment_path,
            validation_workloads_path=self.tcp_udp_validation_path(),
            kind="thin-lto-cgu1",
            target_root=self.root / "targets" / "qualification",
            artifact_names=sorted(build_qualification.REQUIRED_ARTIFACTS),
        )
        plan_path = self.write_json("qualification-plan.json", plan)
        environment = self.environment("github-hosted")
        record_paths = []
        for phase in plan["phases"]:
            log_path = self.root / "logs" / f"{phase['name']}.log"

            def executor(argv, cwd, env, log, *, selected=phase):
                for index, relative in enumerate(selected["artifacts"]):
                    path = pathlib.Path(selected["target_dir"]) / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(f"{selected['name']}-{index}".encode("ascii"))
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_bytes(b"fixture build")
                return 0

            with mock.patch.object(
                build_experiment, "capture_environment", return_value=environment
            ):
                record, status = build_experiment.run_experiment_phase(
                    plan_path=plan_path,
                    phase_name=phase["name"],
                    log_path=log_path,
                    executor=executor,
                    clock=iter((10, 20)).__next__,
                )
            self.assertEqual(status, 0)
            record_paths.append(self.write_json(f"{phase['name']}-record.json", record))
        return environment_path, plan_path, plan, record_paths

    @staticmethod
    def row(
        scenario: str,
        member: str,
        pair: int,
        variant: dict[str, object],
        *,
        value: int,
    ) -> dict[str, object]:
        metric, _direction, _family = catalog.SCENARIO_CATALOG[scenario]
        topology, payload, socks_bytes, upstream_bytes = catalog.SCENARIO_EVIDENCE[
            scenario
        ]
        order = 1 if (pair % 2 == 1) == (member == "parent") else 2
        artifacts = variant["artifacts"]
        evidence_contract = catalog_evidence_contract(
            scenario,
            warmup_seconds=1,
            active_seconds=15,
            pair_schedule="abba-six-pairs",
        )
        environment = {
            "runner_image": "ubuntu-24.04",
            "rustc": "rustc 1.97.1 fixture",
            "kernel": "Linux fixture",
            "cpu_model": "AMD EPYC fixture",
            "cpu_count": 4,
            "memory_kib": 16_000_000,
            "build_profile": "current",
        }
        return {
            "schema_version": trial.PROFILE_TRIAL_SCHEMA_VERSION,
            "kind": "m18_profile_trial",
            "parent_sha": SOURCE_SHA,
            "candidate_sha": SOURCE_SHA,
            "member": member,
            "pair": pair,
            "order": order,
            "build_profile": "current",
            "scenario": scenario,
            "warmup_seconds": 1,
            "active_seconds": 15,
            "topology": topology,
            "application_payload_bytes": payload,
            "workload_scale": catalog.SCENARIO_WORKLOAD_SCALE.get(scenario),
            "socks_datagram_bytes": socks_bytes,
            "upstream_wire_bytes": upstream_bytes,
            "sha": SOURCE_SHA,
            "tree": SOURCE_TREE,
            "runner_sha256": artifacts["m4-qualification"]["sha256"],
            "client_sha256": artifacts["ferrum2-client"]["sha256"],
            "server_sha256": artifacts["ferrum2-server"]["sha256"],
            "rustc": environment["rustc"],
            "kernel": environment["kernel"],
            "cpu_model": environment["cpu_model"],
            "cpu_count": environment["cpu_count"],
            "memory_kib": environment["memory_kib"],
            "metric": metric,
            "unit": "nanoseconds" if metric == "p99_nanoseconds" else metric,
            "value": value,
            "checked_units": 1_000,
            "p99_nanoseconds": value if metric == "p99_nanoseconds" else None,
            "io_completions": (0 if metric == "operations_per_second" else 2_000),
            "scale": None,
            "structural_metrics": structural_metrics(scenario),
            "producer_source_sha256": evidence_contract["producer_source_sha256"],
            "controller_source_sha256": evidence_contract["controller_source_sha256"],
            "semantic_recipe_sha256": evidence_contract["semantic_recipe_sha256"],
            "evidence_bundle_sha256": evidence_contract["evidence_bundle_sha256"],
            "environment_identity": environment,
            "cleanup": {
                "active_processes": 0,
                "active_workers": 0,
                "ready_file_removed": True,
                "status": "PASS",
            },
            "correctness": "PASS",
            "status": "PASS",
        }

    def evidence_root(
        self,
        name: str,
        variants: dict[str, dict[str, object]],
        member_variants: dict[str, str],
    ) -> pathlib.Path:
        root = self.root / name
        policy, _ = build_qualification._load_policy(self.policy)
        for member in ("parent", "candidate"):
            member_root = root / member
            member_root.mkdir(parents=True)
            variant = variants[member_variants[member]]
            for scenario in policy["scenarios"]:
                for pair in range(1, 7):
                    value = 100 if member == "parent" else 105
                    row = self.row(scenario["name"], member, pair, variant, value=value)
                    (member_root / f"{scenario['name']}-{pair}.jsonl").write_text(
                        json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
                    )
        return root

    def prepared(self, suffix: str = ""):
        environment, plan_path, plan, records = self.plan_and_records()
        loaded_plan, plan_sha = build_experiment._load_plan(plan_path)
        loaded_records = build_qualification._phase_records(
            loaded_plan, plan_sha, records
        )
        phases = {row["name"]: row for row in loaded_plan["phases"]}
        source = self.environment("github-hosted")["source_identity"]
        variants = {}
        for name, phase_name in (
            ("baseline", "baseline"),
            ("candidate", "thin-lto-cgu1"),
        ):
            record, digest = loaded_records[phase_name]
            variants[name] = build_qualification._variant(
                name=name,
                source_identity=source,
                plan=loaded_plan,
                phase=phases[phase_name],
                phase_record=record,
                phase_record_sha256=digest,
            )
        aa1 = self.evidence_root(
            f"aa1{suffix}", variants, {"parent": "baseline", "candidate": "baseline"}
        )
        aa2 = self.evidence_root(
            f"aa2{suffix}", variants, {"parent": "baseline", "candidate": "baseline"}
        )
        comparison = self.evidence_root(
            f"comparison{suffix}",
            variants,
            {"parent": "baseline", "candidate": "candidate"},
        )
        return environment, plan_path, records, aa1, aa2, comparison

    def test_same_source_variants_bind_phase_records_and_close_hosted_adoption(self):
        environment, plan, records, aa1, aa2, comparison = self.prepared()

        record = build_qualification.create_qualification_record(
            environment_path=environment,
            plan_path=plan,
            phase_record_paths=records,
            a_a_roots=[aa1, aa2],
            comparison_root=comparison,
            policy_path=self.policy,
        )

        self.assertEqual(record["status"], "PASS")
        self.assertEqual(
            record["adoption_decision"],
            "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        )
        self.assertFalse(record["performance_authoritative"])
        self.assertFalse(record["bare_metal_gate_satisfied"])
        self.assertFalse(record["durable_evidence_gate_satisfied"])
        self.assertFalse(
            record["provisional_threshold_observation"]["used_for_adoption"]
        )
        self.assertIn("candidate_total_artifact_bytes", record["build_cost"])
        self.assertIn("candidate_peak_rss_upper_bound_kib", record["build_cost"])
        self.assertEqual(len(record["a_a_rounds"]), 2)
        self.assertNotEqual(
            record["variants"]["baseline"]["variant_id"],
            record["variants"]["candidate"]["variant_id"],
        )
        self.assertEqual(
            record["variants"]["baseline"]["source_sha"],
            record["variants"]["candidate"]["source_sha"],
        )

    def test_missing_pair_and_non_amd_evidence_fail_closed(self):
        environment, plan, records, aa1, aa2, comparison = self.prepared()
        next((aa1 / "parent").glob("*.jsonl")).unlink()
        with self.assertRaisesRegex(CandidateControlError, "incomplete"):
            build_qualification.create_qualification_record(
                environment_path=environment,
                plan_path=plan,
                phase_record_paths=records,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                policy_path=self.policy,
            )

        # Restore a complete fixture, then make its host identity non-AMD.
        _, _, _, aa1, aa2, comparison = self.prepared("-non-amd")
        for root in (aa1, aa2, comparison):
            for member in ("parent", "candidate"):
                for path in (root / member).glob("*.jsonl"):
                    row = json.loads(path.read_text(encoding="utf-8"))
                    row["cpu_model"] = "Intel fixture"
                    row["environment_identity"]["cpu_model"] = "Intel fixture"
                    path.write_text(
                        json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
                    )
        with self.assertRaisesRegex(CandidateControlError, "AMD"):
            build_qualification.create_qualification_record(
                environment_path=environment,
                plan_path=plan,
                phase_record_paths=records,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                policy_path=self.policy,
            )

    def test_phase_record_and_artifact_mutations_fail_closed(self):
        environment, plan, records, aa1, aa2, comparison = self.prepared("-artifact")
        phase_record = json.loads(records[0].read_text(encoding="utf-8"))
        pathlib.Path(phase_record["artifacts"][0]["path"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(CandidateControlError, "artifact identity"):
            build_qualification.create_qualification_record(
                environment_path=environment,
                plan_path=plan,
                phase_record_paths=records,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                policy_path=self.policy,
            )

        environment, plan, records, aa1, aa2, comparison = self.prepared("-command")
        phase_record = json.loads(records[0].read_text(encoding="utf-8"))
        phase_record["command"]["argv"].append("--unexpected")
        material = dict(phase_record)
        material.pop("record_id")
        phase_record["record_id"] = build_experiment._json_sha256(material)
        records[0].write_text(
            json.dumps(phase_record, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(CandidateControlError, "differs from its plan"):
            build_qualification.create_qualification_record(
                environment_path=environment,
                plan_path=plan,
                phase_record_paths=records,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                policy_path=self.policy,
            )

    def test_trial_source_contract_and_abba_mutations_fail_closed(self):
        environment, plan, records, aa1, aa2, comparison = self.prepared("-contract")
        path = next((comparison / "parent").glob("*.jsonl"))
        row = json.loads(path.read_text(encoding="utf-8"))
        row["producer_source_sha256"] = "f" * 64
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(CandidateControlError, "source contract"):
            build_qualification.create_qualification_record(
                environment_path=environment,
                plan_path=plan,
                phase_record_paths=records,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                policy_path=self.policy,
            )

        environment, plan, records, aa1, aa2, comparison = self.prepared("-order")
        path = next((comparison / "parent").glob("*.jsonl"))
        row = json.loads(path.read_text(encoding="utf-8"))
        row["order"] = 2 if row["order"] == 1 else 1
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(CandidateControlError, "ABBA"):
            build_qualification.create_qualification_record(
                environment_path=environment,
                plan_path=plan,
                phase_record_paths=records,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                policy_path=self.policy,
            )


if __name__ == "__main__":
    unittest.main()
