import copy
from contextlib import redirect_stdout
import hashlib
import json
import io
from pathlib import Path
import tempfile
import unittest

from tools.performance_candidate import cli as controller_cli
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.windows_tun.plan import validate_windows_tun_plan
from tools.performance_candidate.windows_tun.policy import load_windows_tun_policy
from tools.performance_candidate.windows_tun.recipe import (
    WINDOWS_TUN_PROFILES,
    WINDOWS_TUN_WORKLOAD_CHECKS,
)
from tools.performance_candidate.windows_tun.summary import (
    validate_windows_tun_host_evidence,
)
from tools.performance_candidate.windows_tun.trial import validate_windows_tun_trial


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "tools" / "windows_tun_performance_policy.json"
BASELINE = "1" * 40
CANDIDATE = "2" * 40
RUN_ID = "abc123def456"
LOOPBACK_INDEX = 42
LOOPBACK_ALIAS = "Renamed loopback interface"
DIGEST = hashlib.sha256(
    (ROOT / "tools" / "powershell" / "Ferrum2.Performance" / "bundle.json").read_bytes()
).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def plan_for(mode: str) -> dict[str, object]:
    profile = WINDOWS_TUN_PROFILES[mode]
    scenarios = [
        {"name": name, "metric": metric, "unit": unit}
        for name, metric, unit in profile["scenarios"]
    ]
    trials = []
    if mode == "Lifecycle":
        trials.append(
            {
                "sequence": 1,
                "scenario": "product-lifecycle",
                "member": "candidate",
                "commit_sha": CANDIDATE,
                "lifecycle_cycles": 20,
                "action": "product-start-probe-stop",
            }
        )
    else:
        sequence = 0
        for scenario in scenarios:
            for pair in range(1, profile["pair_count"] + 1):
                order = "baseline-candidate" if pair % 2 else "candidate-baseline"
                members = ("baseline", "candidate") if pair % 2 else ("candidate", "baseline")
                for member in members:
                    sequence += 1
                    trials.append(
                        {
                            "sequence": sequence,
                            "pair": pair,
                            "order": order,
                            "scenario": scenario["name"],
                            "metric": scenario["metric"],
                            "unit": scenario["unit"],
                            "member": member,
                            "commit_sha": BASELINE if member == "baseline" else CANDIDATE,
                            "warmup_seconds": profile["warmup_seconds"],
                            "active_seconds": profile["active_seconds"],
                            "initial_product_state": "fresh-processes-and-adapter",
                        }
                    )
    return {
        "schema_version": 1,
        "kind": "ferrum2.windows-tun.host-performance-plan",
        "run_id": RUN_ID,
        "execution": "explicit-authorized-windows-host",
        "mode": mode,
        "baseline_sha": BASELINE,
        "candidate_sha": CANDIDATE,
        "performance_source_bundle_sha256": DIGEST,
        "pair_count": profile["pair_count"],
        "warmup_seconds": profile["warmup_seconds"],
        "active_seconds": profile["active_seconds"],
        "lifecycle_cycles": profile["lifecycle_cycles"],
        "scenario_count": len(scenarios),
        "trial_count": len(trials),
        "scenarios": scenarios,
        "trials": trials,
        "safety": {
            "requires_elevation": True,
            "requires_explicit_acknowledgement": True,
            "automatic_elevation": False,
            "address_family": "RFC2544 198.18.0.0/15",
            "route_scope": "run-owned /32 only",
            "mutations": [
                "one run-owned Wintun adapter",
                "run-owned RFC2544 loopback support address",
                "run-owned narrow routes",
            ],
            "forbidden_mutations": [
                "default route",
                "system DNS",
                "physical adapters",
                "WLAN",
                "firewall",
                "WFP",
                "sing-box",
            ],
            "cleanup": "exact RunId ledger identities in try/finally",
            "recovery": "%PROGRAMDATA%/Ferrum2HostPerformance-v2/<RunId>/recovery.json",
        },
        "qualification": {
            "product_lifecycle_cycles": profile["lifecycle_cycles"],
            "long_durability_soak": "excluded",
            "vm_start": False,
            "checkpoint_restore": False,
            "guest_staging": False,
        },
    }


def route_proofs(planned: dict[str, object]) -> list[dict[str, object]]:
    value = int(RUN_ID[:4], 16)
    third = (value >> 8) & 0xFF
    block = (value & 0xFF) % 63 * 4
    tun_address = f"198.18.{third}.{block + 2}"
    support_address = f"198.19.{third}.{block + 1}"
    adapter_alias = f"Ferrum2Perf-{RUN_ID}-{planned['sequence']:03d}"
    return [
        {
            "purpose": "benchmark-application-to-test-tun",
            "remote_address": support_address,
            "local_address": tun_address,
            "interface_index": 73,
            "interface_alias": adapter_alias,
            "destination_prefix": f"{support_address}/32",
            "next_hop": "0.0.0.0",
        },
        {
            "purpose": "server-to-support-without-test-tun",
            "remote_address": support_address,
            "local_address": support_address,
            "interface_index": LOOPBACK_INDEX,
            "interface_alias": LOOPBACK_ALIAS,
            "destination_prefix": f"{support_address}/32",
            "next_hop": "0.0.0.0",
        },
        {
            "purpose": "product-underlay-control",
            "remote_address": "127.0.0.1",
            "local_address": "127.0.0.1",
            "interface_index": LOOPBACK_INDEX,
            "interface_alias": LOOPBACK_ALIAS,
            "destination_prefix": "127.0.0.1/32",
            "next_hop": "0.0.0.0",
        },
        {
            "purpose": "sing-box-proxy-excluded",
            "remote_address": "127.0.0.1",
            "local_address": "127.0.0.1",
            "interface_index": LOOPBACK_INDEX,
            "interface_alias": LOOPBACK_ALIAS,
            "destination_prefix": "127.0.0.1/32",
            "next_hop": "0.0.0.0",
        },
    ]


def trial_for(planned: dict[str, object], value: float) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "ferrum2.windows-tun.host-performance-trial",
        "run_id": RUN_ID,
        "performance_source_bundle_sha256": DIGEST,
        "sequence": planned["sequence"],
        "pair": planned["pair"],
        "order": planned["order"],
        "scenario": planned["scenario"],
        "member": planned["member"],
        "commit_sha": planned["commit_sha"],
        "metric": planned["metric"],
        "unit": planned["unit"],
        "value": value,
        "warmup_seconds": planned["warmup_seconds"],
        "active_seconds": planned["active_seconds"],
        "client_cpu_percent": 20.0 if planned["member"] == "baseline" else 18.0,
        "server_cpu_percent": 10.0 if planned["member"] == "baseline" else 9.0,
        "client_failure_counter_delta": 0.0,
        "server_failure_counter_delta": 0.0,
        "checked_units": 1000.0,
        "loopback_interface_index": LOOPBACK_INDEX,
        "loopback_interface_alias": LOOPBACK_ALIAS,
        "route_proofs": route_proofs(planned),
        "workload_checks": {
            check: True
            for check in WINDOWS_TUN_WORKLOAD_CHECKS[str(planned["scenario"])]
        },
        "status": "PASS",
    }


def write_common(root: Path, mode: str, plan: dict[str, object]) -> None:
    write_json(root / "plan.json", plan)
    member_fields = {
        "root": "C:/fixture",
        "client": "C:/fixture/ferrum2-client.exe",
        "server": "C:/fixture/ferrum2-server.exe",
        "harness": "C:/fixture/m4-qualification.exe",
        "client_sha256": DIGEST,
        "server_sha256": DIGEST,
        "harness_sha256": DIGEST,
        "source_bundle_sha256": DIGEST,
        "wintun_dll_sha256": DIGEST,
    }
    write_json(
        root / "builds.json",
        {
            "schema_version": 1,
            "kind": "ferrum2.windows-tun.host-build-manifest",
            "run_id": RUN_ID,
            "performance_source_bundle_sha256": DIGEST,
            "baseline": {"label": "baseline", "commit_sha": BASELINE, **member_fields},
            "candidate": {"label": "candidate", "commit_sha": CANDIDATE, **member_fields},
            "shared_harness_sha256": DIGEST,
            "shared_harness_commit_sha": CANDIDATE,
            "shared_source_bundle_sha256": DIGEST,
            "wintun_archive_sha256": DIGEST,
            "wintun_dll_sha256": DIGEST,
        },
    )
    write_json(
        root / "cleanup.json",
        {
            "schema_version": 1,
            "kind": "ferrum2.windows-tun.host-performance-cleanup",
            "run_id": RUN_ID,
            "performance_source_bundle_sha256": DIGEST,
            "status": "PASS",
            "benchmark_succeeded": True,
            "adapter_remaining": 0,
            "routes_remaining": 0,
            "addresses_remaining": 0,
            "processes_remaining": 0,
            "ports_remaining": 0,
            "completed_utc": "2026-09-03T00:00:00Z",
        },
    )
    write_json(
        root / "runtime.json",
        {
            "schema_version": 1,
            "kind": "ferrum2.windows-tun.host-performance-runtime",
            "run_id": RUN_ID,
            "performance_source_bundle_sha256": DIGEST,
            "mode": mode,
            "build_seconds": 1.0,
            "execution_seconds": 2.0,
            "cleanup_seconds": 0.1,
            "elapsed_seconds": 3.1,
            "cleanup_status": "PASS",
        },
    )


class WindowsTunHostEvidenceTests(unittest.TestCase):
    def test_policy_and_plans_split_feedback_from_soak(self) -> None:
        policy = load_windows_tun_policy(POLICY)
        self.assertFalse(policy["soak"]["enabled_by_default"])
        self.assertFalse(policy["soak"]["candidate_decision_input"])
        self.assertEqual(policy["soak"]["cycles"], 1000)
        for mode in ("Quick", "Confirm", "Lifecycle"):
            validate_windows_tun_plan(
                plan_for(mode), baseline_sha=BASELINE, candidate_sha=CANDIDATE, mode=mode
            )

    def test_plan_rejects_unreviewed_performance_bundle_digest(self) -> None:
        plan = plan_for("Quick")
        plan["performance_source_bundle_sha256"] = "f" * 64
        with self.assertRaisesRegex(CandidateControlError, "reviewed performance source bundle"):
            validate_windows_tun_plan(
                plan, baseline_sha=BASELINE, candidate_sha=CANDIDATE, mode="Quick"
            )

    def test_plan_rejects_guest_fallback_and_default_soak(self) -> None:
        plan = plan_for("Quick")
        plan["qualification"]["vm_start"] = True
        with self.assertRaisesRegex(CandidateControlError, "isolation"):
            validate_windows_tun_plan(
                plan, baseline_sha=BASELINE, candidate_sha=CANDIDATE, mode="Quick"
            )
        plan = plan_for("Quick")
        plan["qualification"]["long_durability_soak"] = "included"
        with self.assertRaisesRegex(CandidateControlError, "isolation"):
            validate_windows_tun_plan(
                plan, baseline_sha=BASELINE, candidate_sha=CANDIDATE, mode="Quick"
            )
        plan = plan_for("Quick")
        plan["run_id"] = "fixture-run"
        with self.assertRaisesRegex(CandidateControlError, "transaction identity"):
            validate_windows_tun_plan(
                plan, baseline_sha=BASELINE, candidate_sha=CANDIDATE, mode="Quick"
            )

    def test_trial_rejects_failure_counters_and_recursive_route(self) -> None:
        planned = plan_for("Quick")["trials"][0]
        trial = trial_for(planned, 1000.0)
        identity = {
            "planned_trial": planned,
            "run_id": RUN_ID,
            "performance_source_bundle_sha256": DIGEST,
        }
        validate_windows_tun_trial(trial, **identity)
        failed = copy.deepcopy(trial)
        failed["client_failure_counter_delta"] = 1.0
        with self.assertRaisesRegex(CandidateControlError, "failure counter"):
            validate_windows_tun_trial(failed, **identity)
        recursive = copy.deepcopy(trial)
        recursive["route_proofs"][2]["interface_index"] = 73
        with self.assertRaisesRegex(CandidateControlError, "loopback exclusion"):
            validate_windows_tun_trial(recursive, **identity)
        stale = copy.deepcopy(trial)
        stale["performance_source_bundle_sha256"] = "f" * 64
        with self.assertRaisesRegex(CandidateControlError, "identity"):
            validate_windows_tun_trial(stale, **identity)
        spliced_route = copy.deepcopy(trial)
        spliced_route["route_proofs"][0]["interface_alias"] = (
            f"Ferrum2Perf-{'f' * 12}-001"
        )
        with self.assertRaisesRegex(CandidateControlError, "run-owned TUN path"):
            validate_windows_tun_trial(spliced_route, **identity)
        truncated_checks = copy.deepcopy(trial)
        truncated_checks["workload_checks"] = {"payload_exact": True}
        with self.assertRaisesRegex(CandidateControlError, "check closure"):
            validate_windows_tun_trial(truncated_checks, **identity)

    def test_complete_paired_evidence_is_reduced_from_raw_trials(self) -> None:
        plan = plan_for("Quick")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_common(root, "Quick", plan)
            ratios = (1.03, 1.04, 0.99)
            trial_rows = []
            for planned in plan["trials"]:
                value = 1000.0 if planned["member"] == "baseline" else 1000.0 * ratios[planned["pair"] - 1]
                trial = trial_for(planned, value)
                trial_rows.append(trial)
                write_json(root / "trials" / f"{planned['sequence']:03d}" / "trial.json", trial)
            summaries = []
            for scenario in plan["scenarios"]:
                rows = [row for row in trial_rows if row["scenario"] == scenario["name"]]
                pairs = []
                for pair, ratio in enumerate(ratios, 1):
                    baseline = next(row for row in rows if row["pair"] == pair and row["member"] == "baseline")
                    candidate = next(row for row in rows if row["pair"] == pair and row["member"] == "candidate")
                    pairs.append(
                        {
                            "pair": pair,
                            "order": baseline["order"],
                            "baseline": baseline["value"],
                            "candidate": candidate["value"],
                            "ratio": ratio,
                        }
                    )
                summaries.append(
                    {
                        "scenario": scenario["name"],
                        "metric": scenario["metric"],
                        "unit": scenario["unit"],
                        "pairs": pairs,
                        "median_pair_ratio": 1.03,
                        "median_pair_improvement_percent": 3.0,
                        "minimum_pair_ratio": 0.99,
                        "maximum_pair_ratio": 1.04,
                        "median_absolute_deviation": 0.01,
                        "outlier_pairs": [3],
                        "pairs_improved": 2,
                        "baseline_client_cpu_percent_median": 20.0,
                        "candidate_client_cpu_percent_median": 18.0,
                        "baseline_server_cpu_percent_median": 10.0,
                        "candidate_server_cpu_percent_median": 9.0,
                        "client_failure_counter_delta": 0,
                        "server_failure_counter_delta": 0,
                        "qualification_status": "candidate-win",
                    }
                )
            write_json(
                root / "summary.json",
                {
                    "schema_version": 1,
                    "kind": "ferrum2.windows-tun.host-performance-summary",
                    "run_id": RUN_ID,
                    "performance_source_bundle_sha256": DIGEST,
                    "mode": "Quick",
                    "baseline_sha": BASELINE,
                    "candidate_sha": CANDIDATE,
                    "pair_count": 3,
                    "scenarios": summaries,
                    "threshold_percent": 2.0,
                    "status": "PASS",
                },
            )
            report = validate_windows_tun_host_evidence(
                evidence_root=root,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Quick",
                policy_path=POLICY,
            )
            self.assertEqual(report["status"], "CANDIDATE_WIN")
            self.assertEqual(
                [row["qualification_status"] for row in report["scenario_decisions"]],
                ["candidate-win", "candidate-win"],
            )
            cleanup = json.loads((root / "cleanup.json").read_text(encoding="utf-8"))
            runtime = json.loads((root / "runtime.json").read_text(encoding="utf-8"))
            spliced_cleanup = copy.deepcopy(cleanup)
            spliced_runtime = copy.deepcopy(runtime)
            spliced_cleanup["run_id"] = "fedcba654321"
            spliced_runtime["run_id"] = "fedcba654321"
            write_json(root / "cleanup.json", spliced_cleanup)
            write_json(root / "runtime.json", spliced_runtime)
            with self.assertRaisesRegex(CandidateControlError, "cleanup evidence"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    policy_path=POLICY,
                )
            write_json(root / "cleanup.json", cleanup)
            write_json(root / "runtime.json", runtime)
            builds = json.loads((root / "builds.json").read_text(encoding="utf-8"))
            inconsistent = copy.deepcopy(builds)
            inconsistent["candidate"]["harness_sha256"] = "b" * 64
            write_json(root / "builds.json", inconsistent)
            with self.assertRaisesRegex(CandidateControlError, "shared harness"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    policy_path=POLICY,
                )
            unexpected = copy.deepcopy(builds)
            unexpected["baseline"]["unexpected"] = True
            write_json(root / "builds.json", unexpected)
            with self.assertRaisesRegex(CandidateControlError, "schema mismatch"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    policy_path=POLICY,
                )
            write_json(root / "builds.json", builds)
            baseline_cpu = (100.0, 101.0, 1.0)
            candidate_cpu = (106.0, 1.0, 2.1)
            for planned in plan["trials"]:
                trial_path = root / "trials" / f"{planned['sequence']:03d}" / "trial.json"
                trial = json.loads(trial_path.read_text(encoding="utf-8"))
                values = baseline_cpu if planned["member"] == "baseline" else candidate_cpu
                trial["client_cpu_percent"] = values[planned["pair"] - 1]
                write_json(trial_path, trial)
            summary_document = json.loads(
                (root / "summary.json").read_text(encoding="utf-8")
            )
            for scenario in summary_document["scenarios"]:
                scenario["baseline_client_cpu_percent_median"] = 100.0
                scenario["candidate_client_cpu_percent_median"] = 2.1
            write_json(root / "summary.json", summary_document)
            with self.assertRaisesRegex(CandidateControlError, "scenario decision"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    policy_path=POLICY,
                )
            for scenario in summary_document["scenarios"]:
                scenario["qualification_status"] = "regression"
            write_json(root / "summary.json", summary_document)
            report = validate_windows_tun_host_evidence(
                evidence_root=root,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Quick",
                policy_path=POLICY,
            )
            self.assertEqual(
                [row["qualification_status"] for row in report["scenario_decisions"]],
                ["regression", "regression"],
            )
            self.assertEqual(report["status"], "REGRESSION")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    controller_cli.main(
                        [
                            "windows-tun-validate-host-evidence",
                            "--evidence-root",
                            str(root),
                            "--baseline-sha",
                            BASELINE,
                            "--candidate-sha",
                            CANDIDATE,
                            "--mode",
                            "Quick",
                            "--policy",
                            str(POLICY),
                        ]
                    ),
                    3,
                )
            dirty = json.loads((root / "cleanup.json").read_text(encoding="utf-8"))
            dirty["routes_remaining"] = 1
            write_json(root / "cleanup.json", dirty)
            with self.assertRaisesRegex(CandidateControlError, "not clean"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    policy_path=POLICY,
                )

    def test_lifecycle_evidence_is_short_and_never_mutates_physical_network(self) -> None:
        plan = plan_for("Lifecycle")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_common(root, "Lifecycle", plan)
            write_json(
                root / "summary.json",
                {
                    "schema_version": 1,
                    "kind": "ferrum2.windows-tun.host-lifecycle-summary",
                    "run_id": RUN_ID,
                    "performance_source_bundle_sha256": DIGEST,
                    "mode": "Lifecycle",
                    "candidate_sha": CANDIDATE,
                    "lifecycle_cycles": 20,
                    "lifecycle_action": "product-start-probe-stop",
                    "cycle_latencies_ms": [float(value) for value in range(1, 21)],
                    "cycle_latency_median_ms": 10.5,
                    "cycle_latency_p95_ms": 19.0,
                    "cycle_latency_minimum_ms": 1.0,
                    "cycle_latency_maximum_ms": 20.0,
                    "probe_failures": 0,
                    "between_cycle_adapter_remaining": 0,
                    "between_cycle_routes_remaining": 0,
                    "between_cycle_product_processes_remaining": 0,
                    "between_cycle_product_ports_remaining": 0,
                    "physical_adapter_mutations": 0,
                    "wlan_mutations": 0,
                    "dns_mutations": 0,
                    "long_durability_soak": "not-run",
                    "status": "PASS",
                },
            )
            report = validate_windows_tun_host_evidence(
                evidence_root=root,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Lifecycle",
                policy_path=POLICY,
            )
            self.assertEqual(report["scenario_decisions"], [])
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["between_cycle_adapter_remaining"] = 1
            write_json(root / "summary.json", summary)
            with self.assertRaisesRegex(CandidateControlError, "contract is invalid"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Lifecycle",
                    policy_path=POLICY,
                )


if __name__ == "__main__":
    unittest.main()
