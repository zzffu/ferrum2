from __future__ import annotations

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
from tests.performance_udp_workers._fixture import valid_record
from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux.trial import PROFILE_TRIAL_SCHEMA_VERSION
from tools.performance_udp_headroom import build, contract, evidence
from tools.performance_udp_workers.contract import BUILD_PROFILE


class UdpHeadroomQualificationTests(BuildExperimentFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy = (
            contract.repository_root() / "tools/performance_udp_headroom/policy.json"
        )

    def github_environment(self) -> dict[str, object]:
        machine = self.machine()
        machine["cpu_model"] = {
            "source": "/proc/cpuinfo",
            "status": "captured",
            "value": "AMD EPYC fixture",
        }
        with (
            mock.patch.object(
                build_experiment, "_bounded_command", side_effect=self.command_result
            ),
            mock.patch.object(
                build_experiment,
                "_capture_machine_identity",
                return_value=(machine, self.background()),
            ),
            mock.patch.object(
                build_experiment, "_utc_now", return_value="2026-08-29T00:00:00Z"
            ),
        ):
            return build_experiment.capture_environment(
                repository=self.repository,
                source_sha=SOURCE_SHA,
                environment_kind="github-hosted",
                runner_image="ubuntu-24.04",
            )

    def plan(self) -> tuple[pathlib.Path, dict[str, object], dict[str, object]]:
        environment = self.github_environment()
        environment_path = self.write_json("udp-headroom-environment.json", environment)
        row = build.create_plan(
            environment_path=environment_path,
            policy_path=self.policy,
            target_root=self.root / "udp-headroom-targets",
        )
        return self.write_json("udp-headroom-plan.json", row), row, environment

    def build_record(
        self,
        plan_path: pathlib.Path,
        plan: dict[str, object],
        environment: dict[str, object],
        variant_name: str,
    ) -> pathlib.Path:
        selected = next(row for row in plan["variants"] if row["name"] == variant_name)

        def executor(argv, cwd, env, log):
            self.assertEqual(argv, selected["argv"])
            self.assertEqual(pathlib.Path(cwd), self.repository)
            for name, path_value in selected["artifact_paths"].items():
                path = pathlib.Path(path_value)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"{variant_name}-{name}".encode("ascii"))
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_bytes(b"closed UDP headroom fixture build")
            return 0

        with mock.patch.object(
            build_experiment, "capture_environment", return_value=environment
        ):
            record, status = build.run_build(
                plan_path=plan_path,
                variant_name=variant_name,
                log_path=self.root / "logs" / f"{variant_name}.log",
                executor=executor,
                clock=iter((10, 20)).__next__,
            )
        self.assertEqual(status, 0)
        return self.write_json(f"udp-headroom-build-{variant_name}.json", record)

    @staticmethod
    def timed_environment() -> dict[str, object]:
        return {
            "runner_image": "ubuntu-24.04",
            "rustc": "rustc 1.97.1 (fixture)",
            "kernel": "Linux fixture",
            "cpu_model": "AMD EPYC fixture",
            "cpu_count": 8,
            "memory_kib": 32_000_000,
            "build_profile": "current",
        }

    def trial_row(
        self,
        *,
        plan: dict[str, object],
        scenario_name: str,
        member: str,
        pair: int,
        build_record: dict[str, object],
    ) -> dict[str, object]:
        scenario = next(
            row for row in plan["scenarios"] if row["name"] == scenario_name
        )
        evidence_contract = scenario["evidence_contract"]
        artifacts = {row["name"]: row for row in build_record["artifacts"]}
        value = 100 if member == "parent" else 105
        return {
            "schema_version": PROFILE_TRIAL_SCHEMA_VERSION,
            "kind": "m18_profile_trial",
            "parent_sha": SOURCE_SHA,
            "candidate_sha": SOURCE_SHA,
            "member": member,
            "pair": pair,
            "order": 1 if (pair % 2 == 1) == (member == "parent") else 2,
            "build_profile": "current",
            "scenario": scenario_name,
            "warmup_seconds": scenario["warmup_seconds"],
            "active_seconds": scenario["active_seconds"],
            "topology": scenario["topology"],
            "application_payload_bytes": scenario["application_payload_bytes"],
            "workload_scale": scenario["workload_scale"],
            "socks_datagram_bytes": scenario["socks_datagram_bytes"],
            "upstream_wire_bytes": scenario["upstream_wire_bytes"],
            "sha": SOURCE_SHA,
            "tree": SOURCE_TREE,
            "runner_sha256": artifacts["m4-qualification"]["sha256"],
            "client_sha256": artifacts["ferrum2-client"]["sha256"],
            "server_sha256": artifacts["ferrum2-server"]["sha256"],
            "rustc": self.timed_environment()["rustc"],
            "kernel": self.timed_environment()["kernel"],
            "cpu_model": self.timed_environment()["cpu_model"],
            "cpu_count": self.timed_environment()["cpu_count"],
            "memory_kib": self.timed_environment()["memory_kib"],
            "metric": scenario["metric"],
            "unit": evidence_contract["unit"],
            "value": value,
            "checked_units": 1_000,
            "p99_nanoseconds": None,
            "io_completions": 4_000,
            "scale": None,
            "structural_metrics": structural_metrics(scenario_name),
            "producer_source_sha256": evidence_contract["producer_source_sha256"],
            "controller_source_sha256": evidence_contract["controller_source_sha256"],
            "semantic_recipe_sha256": evidence_contract["semantic_recipe_sha256"],
            "evidence_bundle_sha256": evidence_contract["evidence_bundle_sha256"],
            "environment_identity": self.timed_environment(),
            "cleanup": copy.deepcopy(evidence_contract["cleanup_contract"]),
            "correctness": "PASS",
            "status": "PASS",
        }

    def evidence_root(
        self,
        *,
        relative: str,
        plan: dict[str, object],
        parent_build: dict[str, object],
        candidate_build: dict[str, object],
    ) -> pathlib.Path:
        root = self.repository / relative
        for member, record in (
            ("parent", parent_build),
            ("candidate", candidate_build),
        ):
            member_root = root / member
            member_root.mkdir(parents=True)
            for scenario in plan["scenarios"]:
                for pair in range(1, 7):
                    row = self.trial_row(
                        plan=plan,
                        scenario_name=scenario["name"],
                        member=member,
                        pair=pair,
                        build_record=record,
                    )
                    (member_root / f"{scenario['name']}-{pair}.jsonl").write_text(
                        json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
                    )
        return root

    def diagnostic_record(
        self,
        plan: dict[str, object],
        build_record: dict[str, object],
        diagnostic_variant: str,
    ) -> pathlib.Path:
        artifacts = {
            row["name"]: pathlib.Path(row["path"]) for row in build_record["artifacts"]
        }
        row = valid_record(
            evidence.diagnostic_trial(diagnostic_variant),
            candidate_sha=SOURCE_SHA,
            contract=plan["diagnostic_contract"],
            runner=artifacts["m4-qualification"],
            client=artifacts["ferrum2-client"],
            server=artifacts["ferrum2-server"],
        )
        row["identity"]["tree"] = SOURCE_TREE
        row["identity"]["environment"].update(
            {
                key: value
                for key, value in self.timed_environment().items()
                if key != "build_profile"
            }
        )
        row["identity"]["environment"]["build_profile"] = BUILD_PROFILE
        structural = row["structural"]
        copy_counter = "udp_payload_to_wire_copy_bytes"
        if diagnostic_variant == "diagnostic-candidate":
            for endpoint in ("client", "server"):
                structural[f"{endpoint}_after"]["values"][copy_counter] = structural[
                    f"{endpoint}_before"
                ]["values"][copy_counter]
                structural[f"{endpoint}_delta"][copy_counter] = 0
            structural["merged_delta"][copy_counter] = 0
        path = self.repository / evidence.DIAGNOSTIC_OUTPUTS[diagnostic_variant]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def prepared(self):
        plan_path, plan, environment = self.plan()
        paths = {
            name: self.build_record(plan_path, plan, environment, name)
            for name in contract.VARIANT_NAMES
        }
        records = {
            name: json.loads(path.read_text(encoding="utf-8"))
            for name, path in paths.items()
        }
        aa1 = self.evidence_root(
            relative="profiles/udp-headroom/timed/aa-1",
            plan=plan,
            parent_build=records["candidate"],
            candidate_build=records["candidate"],
        )
        aa2 = self.evidence_root(
            relative="profiles/udp-headroom/timed/aa-2",
            plan=plan,
            parent_build=records["candidate"],
            candidate_build=records["candidate"],
        )
        comparison = self.evidence_root(
            relative="profiles/udp-headroom/timed/comparison",
            plan=plan,
            parent_build=records["default"],
            candidate_build=records["candidate"],
        )
        diagnostics = {
            name: self.diagnostic_record(plan, records[name], name)
            for name in ("diagnostic-default", "diagnostic-candidate")
        }
        return plan_path, plan, paths, records, aa1, aa2, comparison, diagnostics

    def test_plan_separates_uninstrumented_timed_builds_from_diagnostic(self) -> None:
        plan_path, plan, _environment = self.plan()
        loaded, _ = build.load_plan(plan_path)
        self.assertEqual(
            [row["name"] for row in loaded["variants"]], list(contract.VARIANT_NAMES)
        )
        default, candidate, diagnostic_default, diagnostic_candidate = loaded[
            "variants"
        ]
        self.assertTrue(default["timed"])
        self.assertTrue(candidate["timed"])
        self.assertFalse(diagnostic_default["timed"])
        self.assertFalse(diagnostic_candidate["timed"])
        self.assertEqual(default["features"], [])
        self.assertNotIn("structural", ",".join(candidate["features"]))
        self.assertIn("structural-diagnostic", ",".join(diagnostic_default["features"]))
        self.assertNotIn(
            "candidate-udp-owned-headroom", ",".join(diagnostic_default["features"])
        )
        self.assertIn(
            "structural-diagnostic", ",".join(diagnostic_candidate["features"])
        )
        self.assertIn(
            "candidate-udp-owned-headroom",
            ",".join(diagnostic_candidate["features"]),
        )
        self.assertIn("candidate-udp-owned-headroom", ",".join(candidate["features"]))

        mutated = copy.deepcopy(plan)
        mutated["variants"][1]["features"].append("ferrum2-client/structural-metrics")
        material = dict(mutated)
        material.pop("plan_id")
        material.pop("generated_at_utc")
        mutated["plan_id"] = build_experiment._json_sha256(material)
        with self.assertRaisesRegex(CandidateControlError, "variants changed"):
            build.load_plan(self.write_json("mutated-headroom-plan.json", mutated))

        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["authority"]["default_enabled"] = True
        with self.assertRaisesRegex(CandidateControlError, "policy contract changed"):
            contract.load_policy(
                self.write_json("mutated-headroom-policy.json", policy)
            )

    def test_materialize_binds_timed_and_diagnostic_to_exact_m4_directory(
        self,
    ) -> None:
        plan_path, plan, environment = self.plan()
        candidate_path = self.build_record(plan_path, plan, environment, "candidate")
        diagnostic_path = self.build_record(
            plan_path, plan, environment, "diagnostic-candidate"
        )
        staged = build.materialize(
            plan_path=plan_path,
            build_path=candidate_path,
            variant_name="candidate",
            destination=self.repository / "target/profiling",
        )
        self.assertEqual(
            staged["destination"], str(self.repository / "target/profiling")
        )
        self.assertEqual(len(staged["artifacts"]), 3)
        diagnostic_staged = build.materialize(
            plan_path=plan_path,
            build_path=diagnostic_path,
            variant_name="diagnostic-candidate",
            destination=self.repository / "target/profiling",
        )
        self.assertEqual(
            diagnostic_staged["destination"],
            str(self.repository / "target/profiling"),
        )
        self.assertEqual(
            [
                pathlib.Path(row["path"]).read_bytes()
                for row in diagnostic_staged["artifacts"]
            ],
            [
                f"diagnostic-candidate-{name}".encode("ascii")
                for name in contract.ARTIFACT_NAMES
            ],
        )
        with self.assertRaisesRegex(CandidateControlError, "destination is invalid"):
            build.materialize(
                plan_path=plan_path,
                build_path=diagnostic_path,
                variant_name="diagnostic-candidate",
                destination=self.repository / "target/udp-worker/profiling",
            )

    def test_materialize_rejects_artifact_mutation(self) -> None:
        plan_path, plan, environment = self.plan()
        candidate_path = self.build_record(plan_path, plan, environment, "candidate")
        record = json.loads(candidate_path.read_text(encoding="utf-8"))
        pathlib.Path(record["artifacts"][0]["path"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(CandidateControlError, "changed after build"):
            build.materialize(
                plan_path=plan_path,
                build_path=candidate_path,
                variant_name="candidate",
                destination=self.repository / "target/profiling",
            )

    def test_two_aa_abba_and_zero_copy_diagnostic_remain_provisional_default_off(
        self,
    ) -> None:
        plan_path, _plan, paths, _records, aa1, aa2, comparison, diagnostics = (
            self.prepared()
        )
        result = evidence.create_qualification(
            plan_path=plan_path,
            default_build_path=paths["default"],
            candidate_build_path=paths["candidate"],
            diagnostic_default_build_path=paths["diagnostic-default"],
            diagnostic_candidate_build_path=paths["diagnostic-candidate"],
            a_a_roots=[aa1, aa2],
            comparison_root=comparison,
            diagnostic_default_path=diagnostics["diagnostic-default"],
            diagnostic_candidate_path=diagnostics["diagnostic-candidate"],
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["a_a_rounds"]), 2)
        self.assertEqual(len(result["comparison"]["observations"]), 5)
        self.assertFalse(result["timed_binaries_structural_metrics"])
        self.assertEqual(result["diagnostic"]["counter_count"], 49)
        self.assertTrue(result["diagnostic"]["same_host_same_workload"])
        for endpoint in ("client", "server"):
            default = result["diagnostic"]["default"]["assertions"][endpoint]
            candidate = result["diagnostic"]["candidate"]["assertions"][endpoint]
            self.assertGreater(default["udp_payload_to_wire_copy_bytes"], 0)
            self.assertEqual(candidate["udp_payload_to_wire_copy_bytes"], 0)
            self.assertGreater(candidate["udp_owned_fast_path_hits"], 0)
        self.assertEqual(result["authority"], contract.AUTHORITY)
        self.assertFalse(result["authority"]["default_enabled"])
        self.assertFalse(result["authority"]["gate03_stable_host_satisfied"])
        self.assertFalse(result["authority"]["gate07_durable_evidence_satisfied"])

    def test_structural_copy_hit_counter_and_timed_identity_mutations_fail_closed(
        self,
    ) -> None:
        plan_path, _plan, paths, _records, aa1, aa2, comparison, diagnostics = (
            self.prepared()
        )
        originals = {
            name: json.loads(path.read_text(encoding="utf-8"))
            for name, path in diagnostics.items()
        }

        def qualify() -> dict[str, object]:
            return evidence.create_qualification(
                plan_path=plan_path,
                default_build_path=paths["default"],
                candidate_build_path=paths["candidate"],
                diagnostic_default_build_path=paths["diagnostic-default"],
                diagnostic_candidate_build_path=paths["diagnostic-candidate"],
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
                diagnostic_default_path=diagnostics["diagnostic-default"],
                diagnostic_candidate_path=diagnostics["diagnostic-candidate"],
            )

        default_path = diagnostics["diagnostic-default"]
        candidate_path = diagnostics["diagnostic-candidate"]
        row = copy.deepcopy(originals["diagnostic-default"])
        before = row["structural"]["client_before"]["values"]
        row["structural"]["client_after"]["values"][
            "udp_payload_to_wire_copy_bytes"
        ] = before["udp_payload_to_wire_copy_bytes"]
        row["structural"]["client_delta"]["udp_payload_to_wire_copy_bytes"] = 0
        row["structural"]["merged_delta"]["udp_payload_to_wire_copy_bytes"] = 1
        default_path.write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            CandidateControlError, "default client did not prove"
        ):
            qualify()
        default_path.write_text(
            json.dumps(originals["diagnostic-default"], sort_keys=True) + "\n",
            encoding="utf-8",
        )

        row = copy.deepcopy(originals["diagnostic-candidate"])
        row["structural"]["client_after"]["values"][
            "udp_payload_to_wire_copy_bytes"
        ] += 1
        row["structural"]["client_delta"]["udp_payload_to_wire_copy_bytes"] = 1
        row["structural"]["merged_delta"]["udp_payload_to_wire_copy_bytes"] = 1
        candidate_path.write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            CandidateControlError, "candidate client did not prove"
        ):
            qualify()

        row = copy.deepcopy(originals["diagnostic-candidate"])
        before = row["structural"]["client_before"]["values"]
        row["structural"]["client_after"]["values"]["udp_owned_fast_path_hits"] = (
            before["udp_owned_fast_path_hits"]
        )
        row["structural"]["client_delta"]["udp_owned_fast_path_hits"] = 0
        row["structural"]["merged_delta"]["udp_owned_fast_path_hits"] = 1
        candidate_path.write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            CandidateControlError, "candidate client did not prove"
        ):
            qualify()

        row = copy.deepcopy(originals["diagnostic-candidate"])
        removed = "tcp_decrypt_prepare_copy_bytes"
        row["structural"]["counter_count"] = 48
        row["structural"]["counter_schema"].pop(removed)
        for field in (
            "client_before",
            "client_after",
            "server_before",
            "server_after",
        ):
            row["structural"][field]["values"].pop(removed)
        for field in ("client_delta", "server_delta", "merged_delta"):
            row["structural"][field].pop(removed)
        candidate_path.write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(CandidateControlError, "structural schema changed"):
            qualify()

        candidate_path.write_text(
            json.dumps(originals["diagnostic-candidate"], sort_keys=True) + "\n",
            encoding="utf-8",
        )

        unexpected = comparison / "unexpected.json"
        unexpected.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(CandidateControlError, "path set changed"):
            qualify()
        unexpected.unlink()

        timed = next((comparison / "candidate").glob("udp-small-high-*.jsonl"))
        timed_row = json.loads(timed.read_text(encoding="utf-8"))
        timed_row["runner_sha256"] = "0" * 64
        timed.write_text(json.dumps(timed_row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(CandidateControlError, "trial identity"):
            qualify()


if __name__ == "__main__":
    unittest.main()
