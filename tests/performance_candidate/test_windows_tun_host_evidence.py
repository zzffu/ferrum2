import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import statistics
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


def plan_for(mode: str, topology: str = "EndToEnd") -> dict[str, object]:
    profile = WINDOWS_TUN_PROFILES[mode]
    scenarios = [
        {"name": name, "metric": metric, "unit": unit, "direction": direction}
        for name, metric, unit, direction in profile["scenarios"]
    ]
    trials = []
    if mode == "Lifecycle":
        trials.append(
            {
                "sequence": 1,
                "scenario": "product-lifecycle",
                "topology": topology,
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
                members = (
                    ("baseline", "candidate")
                    if pair % 2
                    else ("candidate", "baseline")
                )
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
                            "topology": topology,
                            "direction": scenario["direction"],
                            "member": member,
                            "commit_sha": (
                                BASELINE if member == "baseline" else CANDIDATE
                            ),
                            "warmup_seconds": profile["warmup_seconds"],
                            "active_seconds": profile["active_seconds"],
                            "initial_product_state": "fresh-processes-and-adapter",
                        }
                    )
    return {
        "schema_version": 2,
        "kind": "ferrum2.windows-tun.host-performance-plan",
        "run_id": RUN_ID,
        "execution": "explicit-authorized-windows-host",
        "mode": mode,
        "topology": topology,
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
    }


def route_proofs(planned: dict[str, object]) -> list[dict[str, object]]:
    value = int(RUN_ID[:4], 16)
    third = (value >> 8) & 0xFF
    block = (value & 0xFF) % 63 * 4
    tun_address = f"198.18.{third}.{block + 2}"
    support_address = f"198.19.{third}.{block + 1}"
    adapter_alias = f"Ferrum2Perf-{RUN_ID}-{planned['sequence']:03d}"
    direct = planned["topology"] == "ClientDirect"
    proofs = [
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
            "purpose": (
                "client-direct-to-support-without-test-tun"
                if direct
                else "server-to-support-without-test-tun"
            ),
            "remote_address": support_address,
            "local_address": support_address,
            "interface_index": LOOPBACK_INDEX,
            "interface_alias": LOOPBACK_ALIAS,
            "destination_prefix": f"{support_address}/32",
            "next_hop": "0.0.0.0",
        },
    ]
    if not direct:
        proofs.append(
            {
                "purpose": "product-underlay-control",
                "remote_address": "127.0.0.1",
                "local_address": "127.0.0.1",
                "interface_index": LOOPBACK_INDEX,
                "interface_alias": LOOPBACK_ALIAS,
                "destination_prefix": "127.0.0.1/32",
                "next_hop": "0.0.0.0",
            }
        )
    proofs.append(
        {
            "purpose": "sing-box-proxy-excluded",
            "remote_address": "127.0.0.1",
            "local_address": "127.0.0.1",
            "interface_index": LOOPBACK_INDEX,
            "interface_alias": LOOPBACK_ALIAS,
            "destination_prefix": "127.0.0.1/32",
            "next_hop": "0.0.0.0",
        }
    )
    return proofs


def workload_measurements(planned: dict[str, object], value: int) -> tuple[dict[str, int], int]:
    scenario = planned["scenario"]
    active = int(planned["active_seconds"])
    if scenario == "tcp-single-flow":
        checked = max(64 * 1024 * 1024, (value * active + 65535) // 65536 * 65536)
        elapsed = checked * 1_000_000_000 // value
        return {
            "throughput": value,
            "cpu_payload_bytes": checked + 65536,
            "io_completions": checked // 65536 * 2,
            "active_elapsed_nanoseconds": elapsed,
            "tail_checked_units": 65536 if elapsed > active * 1_000_000_000 else 0,
        }, checked
    elapsed = active * 1_000_000_000
    tail = 0
    if scenario == "tcp-request-1k-p99":
        checked = 4096
        measurements = {
            "p50_nanoseconds": value // 2, "p95_nanoseconds": value * 9 // 10,
            "p99_nanoseconds": value, "latency_samples": checked,
            "io_completions": checked * 2,
        }
    elif scenario == "tcp-256-flow-fairness":
        checked = 256 * 16384 * 100
        measurements = {
            "fairness": value, "aggregate_throughput": checked // active,
            "io_completions": checked // 16384 * 2,
        }
    elif scenario == "udp-packets-per-second":
        checked = value * active
        measurements = {
            "packet_rate": value, "p50_nanoseconds": 20_000,
            "p95_nanoseconds": 40_000, "p99_nanoseconds": 50_000,
            "latency_samples": min(checked, 2_000_000), "io_completions": checked * 2,
        }
    elif scenario == "fragment-reassembly-throughput":
        checked = max(4096, (value * active + 5759) // 5760 * 4)
        elapsed = checked * 1440 * 1_000_000_000 // value
        tail = 4 if elapsed > active * 1_000_000_000 else 0
        measurements = {"reassembly_rate": value, "io_completions": checked * 2}
    else:
        raise AssertionError(f"unhandled test scenario: {scenario}")
    measurements.update(active_elapsed_nanoseconds=elapsed, tail_checked_units=tail)
    return measurements, checked


def scale_trial_work(trial: dict[str, object], factor: int) -> None:
    """Keep the synthetic observation consistent when varying CPU/work."""
    trial["checked_units"] *= factor
    measurements = trial["workload_measurements"]
    measurements["io_completions"] *= factor
    trial["io_completions"] = measurements["io_completions"]
    if "latency_samples" in measurements:
        measurements["latency_samples"] = min(trial["checked_units"], 2_000_000)
    if trial["scenario"] == "tcp-single-flow":
        measurements["cpu_payload_bytes"] *= factor
    for field, payload in (("throughput", 1), ("packet_rate", 1), ("aggregate_throughput", 1), ("reassembly_rate", 1440)):
        if field in measurements:
            measurements[field] = max(1, trial["checked_units"] * payload * 1_000_000_000 // measurements["active_elapsed_nanoseconds"])
    trial["value"] = float(measurements[trial["metric"]])


def trial_for(planned: dict[str, object], value: int) -> dict[str, object]:
    measurements, checked = workload_measurements(planned, value)
    server_present = planned["topology"] == "EndToEnd"
    baseline = planned["member"] == "baseline"
    return {
        "schema_version": 4,
        "kind": "ferrum2.windows-tun.host-performance-trial",
        "run_id": RUN_ID,
        "performance_source_bundle_sha256": DIGEST,
        "sequence": planned["sequence"],
        "pair": planned["pair"],
        "order": planned["order"],
        "topology": planned["topology"],
        "scenario": planned["scenario"],
        "member": planned["member"],
        "commit_sha": planned["commit_sha"],
        "metric": planned["metric"],
        "unit": planned["unit"],
        "direction": planned["direction"],
        "value": float(value),
        "warmup_seconds": planned["warmup_seconds"],
        "active_seconds": planned["active_seconds"],
        "cpu_sample_seconds": float(planned["active_seconds"]) + 0.01,
        "io_completions": measurements["io_completions"],
        "p99_nanoseconds": measurements.get("p99_nanoseconds"),
        "client_cpu_percent": 20.0 if baseline else 18.0,
        "server_present": server_present,
        "server_cpu_percent": (10.0 if baseline else 9.0) if server_present else None,
        "client_peak_working_set_bytes": 64 * 1024 * 1024,
        "server_peak_working_set_bytes": (
            32 * 1024 * 1024 if server_present else None
        ),
        "client_failure_counter_delta": 0.0,
        "server_failure_counter_delta": 0.0 if server_present else None,
        "checked_units": checked,
        "loopback_interface_index": LOOPBACK_INDEX,
        "loopback_interface_alias": LOOPBACK_ALIAS,
        "route_proofs": route_proofs(planned),
        "workload_measurements": measurements,
        "workload_checks": {
            check: True
            for check in WINDOWS_TUN_WORKLOAD_CHECKS[str(planned["scenario"])]
        },
        "status": "PASS",
    }


def write_common(root: Path, mode: str, topology: str, plan: dict[str, object]) -> None:
    write_json(root / "plan.json", plan)
    member_fields = {
        "root": "C:/fixture",
        "client": "C:/fixture/ferrum2-client.exe",
        "server": "C:/fixture/ferrum2-server.exe",
        "harness": "C:/fixture/m4-qualification.exe",
        "client_sha256": DIGEST,
        "server_sha256": DIGEST,
        "harness_sha256": DIGEST,
        "product_m4_source_bundle_sha256": DIGEST,
        "wintun_dll_sha256": DIGEST,
    }
    write_json(
        root / "builds.json",
        {
            "schema_version": 2,
            "kind": "ferrum2.windows-tun.host-build-manifest",
            "run_id": RUN_ID,
            "performance_source_bundle_sha256": DIGEST,
            "baseline": {"label": "baseline", "commit_sha": BASELINE, **member_fields},
            "candidate": {
                "label": "candidate",
                "commit_sha": CANDIDATE,
                **member_fields,
            },
            "shared_harness_sha256": DIGEST,
            "shared_harness_commit_sha": BASELINE,
            "shared_harness_source_bundle_sha256": DIGEST,
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
            "schema_version": 2,
            "kind": "ferrum2.windows-tun.host-performance-runtime",
            "run_id": RUN_ID,
            "performance_source_bundle_sha256": DIGEST,
            "mode": mode,
            "topology": topology,
            "build_seconds": 1.0,
            "execution_seconds": 2.0,
            "cleanup_seconds": 0.1,
            "elapsed_seconds": 3.1,
            "cleanup_status": "PASS",
        },
    )


def write_trials(root: Path, plan: dict[str, object]) -> list[dict[str, object]]:
    pair_ratios = (1.03, 1.04, 0.99)
    rows = []
    for planned in plan["trials"]:
        baseline_value = {"tcp-single-flow": 10_000_000, "fragment-reassembly-throughput": 10_000_000, "tcp-256-flow-fairness": 900_000_000}.get(planned["scenario"], 100_000)
        ratio = pair_ratios[int(planned["pair"]) - 1]
        candidate_value = (
            round(baseline_value * ratio)
            if planned["direction"] == "higher_is_better"
            else round(baseline_value / ratio)
        )
        value = baseline_value if planned["member"] == "baseline" else candidate_value
        trial = trial_for(planned, value)
        rows.append(trial)
        write_json(
            root / "trials" / f"{planned['sequence']:03d}" / "trial.json", trial
        )
    return rows


def median_or_none(rows: list[dict[str, object]], field: str) -> float | None:
    values = [row[field] for row in rows]
    if any(value is None for value in values):
        return None
    return statistics.median(values)


def summary_for(plan: dict[str, object], trials: list[dict[str, object]]) -> dict[str, object]:
    server_present = plan["topology"] == "EndToEnd"
    scenarios = []
    for planned_scenario in plan["scenarios"]:
        rows = [row for row in trials if row["scenario"] == planned_scenario["name"]]
        pairs = []
        ratios = []
        for pair_number in range(1, int(plan["pair_count"]) + 1):
            baseline = next(
                row
                for row in rows
                if row["pair"] == pair_number and row["member"] == "baseline"
            )
            candidate = next(
                row
                for row in rows
                if row["pair"] == pair_number and row["member"] == "candidate"
            )
            ratio = (
                candidate["value"] / baseline["value"]
                if planned_scenario["direction"] == "higher_is_better"
                else baseline["value"] / candidate["value"]
            )
            ratios.append(ratio)
            pairs.append(
                {
                    "pair": pair_number,
                    "order": baseline["order"],
                    "baseline": baseline["value"],
                    "candidate": candidate["value"],
                    "baseline_checked_units": baseline["checked_units"],
                    "candidate_checked_units": candidate["checked_units"],
                    "improvement_ratio": ratio,
                }
            )
        median_ratio = statistics.median(ratios)
        mad = statistics.median(abs(value - median_ratio) for value in ratios)
        outliers = (
            []
            if mad == 0
            else [
                number
                for number, ratio in enumerate(ratios, 1)
                if abs(ratio - median_ratio) > 3.0 * mad
            ]
        )
        baseline_rows = [row for row in rows if row["member"] == "baseline"]
        candidate_rows = [row for row in rows if row["member"] == "candidate"]
        scenarios.append(
            {
                "scenario": planned_scenario["name"],
                "topology": plan["topology"],
                "metric": planned_scenario["metric"],
                "unit": planned_scenario["unit"],
                "direction": planned_scenario["direction"],
                "pairs": pairs,
                "median_pair_improvement_ratio": median_ratio,
                "median_pair_improvement_percent": (median_ratio - 1.0) * 100.0,
                "minimum_pair_improvement_ratio": min(ratios),
                "maximum_pair_improvement_ratio": max(ratios),
                "median_absolute_deviation": mad,
                "outlier_pairs": outliers,
                "pairs_improved": sum(value > 1.0 for value in ratios),
                "baseline_checked_units_median": statistics.median(
                    row["checked_units"] for row in baseline_rows
                ),
                "candidate_checked_units_median": statistics.median(
                    row["checked_units"] for row in candidate_rows
                ),
                "baseline_io_completions_median": statistics.median(
                    row["io_completions"] for row in baseline_rows
                ),
                "candidate_io_completions_median": statistics.median(
                    row["io_completions"] for row in candidate_rows
                ),
                "baseline_p99_nanoseconds_median": median_or_none(
                    baseline_rows, "p99_nanoseconds"
                ),
                "candidate_p99_nanoseconds_median": median_or_none(
                    candidate_rows, "p99_nanoseconds"
                ),
                "baseline_client_cpu_percent_median": statistics.median(
                    row["client_cpu_percent"] for row in baseline_rows
                ),
                "candidate_client_cpu_percent_median": statistics.median(
                    row["client_cpu_percent"] for row in candidate_rows
                ),
                "baseline_server_cpu_percent_median": (
                    statistics.median(
                        row["server_cpu_percent"] for row in baseline_rows
                    )
                    if server_present
                    else None
                ),
                "candidate_server_cpu_percent_median": (
                    statistics.median(
                        row["server_cpu_percent"] for row in candidate_rows
                    )
                    if server_present
                    else None
                ),
                "baseline_client_peak_working_set_bytes_median": statistics.median(
                    row["client_peak_working_set_bytes"] for row in baseline_rows
                ),
                "candidate_client_peak_working_set_bytes_median": statistics.median(
                    row["client_peak_working_set_bytes"] for row in candidate_rows
                ),
                "baseline_server_peak_working_set_bytes_median": (
                    statistics.median(
                        row["server_peak_working_set_bytes"] for row in baseline_rows
                    )
                    if server_present
                    else None
                ),
                "candidate_server_peak_working_set_bytes_median": (
                    statistics.median(
                        row["server_peak_working_set_bytes"] for row in candidate_rows
                    )
                    if server_present
                    else None
                ),
                "client_failure_counter_delta": 0,
                "server_failure_counter_delta": 0 if server_present else None,
                "qualification_status": "candidate-win",
            }
        )
    return {
        "schema_version": 2,
        "kind": "ferrum2.windows-tun.host-performance-summary",
        "run_id": RUN_ID,
        "performance_source_bundle_sha256": DIGEST,
        "mode": plan["mode"],
        "topology": plan["topology"],
        "baseline_sha": BASELINE,
        "candidate_sha": CANDIDATE,
        "pair_count": plan["pair_count"],
        "scenarios": scenarios,
        "threshold_percent": 2.0,
        "maximum_non_target_cpu_regression_percent": 2.0,
        "status": "PASS",
    }


def lifecycle_summary(plan: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 2,
        "kind": "ferrum2.windows-tun.host-lifecycle-summary",
        "run_id": RUN_ID,
        "performance_source_bundle_sha256": DIGEST,
        "mode": "Lifecycle",
        "topology": plan["topology"],
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
        "status": "PASS",
    }


class WindowsTunHostEvidenceTests(unittest.TestCase):
    def test_policy_and_plans_close_both_topologies_and_profiles(self) -> None:
        policy = load_windows_tun_policy(POLICY)
        self.assertEqual(policy["topologies"], ["ClientDirect", "EndToEnd"])
        self.assertEqual(len(WINDOWS_TUN_PROFILES["Quick"]["scenarios"]), 4)
        self.assertEqual(len(WINDOWS_TUN_PROFILES["Confirm"]["scenarios"]), 5)
        for topology in ("ClientDirect", "EndToEnd"):
            for mode in ("Quick", "Confirm", "Lifecycle"):
                validate_windows_tun_plan(
                    plan_for(mode, topology),
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode=mode,
                    topology=topology,
                )

    def test_plan_rejects_unreviewed_or_open_contract(self) -> None:
        plan = plan_for("Quick")
        plan["performance_source_bundle_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            CandidateControlError, "reviewed performance source bundle"
        ):
            validate_windows_tun_plan(
                plan,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Quick",
                topology="EndToEnd",
            )
        plan = plan_for("Quick")
        plan["qualification"] = {"vm_start": True}
        with self.assertRaisesRegex(CandidateControlError, "schema mismatch"):
            validate_windows_tun_plan(
                plan,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Quick",
                topology="EndToEnd",
            )
        plan = plan_for("Quick")
        plan["run_id"] = "fixture-run"
        with self.assertRaisesRegex(CandidateControlError, "transaction identity"):
            validate_windows_tun_plan(
                plan,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Quick",
                topology="EndToEnd",
            )

    def test_trials_close_server_presence_routes_and_workload_measurements(self) -> None:
        for topology, proof_count in (("ClientDirect", 3), ("EndToEnd", 4)):
            planned = plan_for("Quick", topology)["trials"][0]
            trial = trial_for(planned, 10_000_000)
            identity = {
                "planned_trial": planned,
                "run_id": RUN_ID,
                "performance_source_bundle_sha256": DIGEST,
            }
            validate_windows_tun_trial(trial, **identity)
            self.assertEqual(len(trial["route_proofs"]), proof_count)
            self.assertEqual(trial["server_present"], topology == "EndToEnd")
            wrong_server = copy.deepcopy(trial)
            wrong_server["server_present"] = not wrong_server["server_present"]
            with self.assertRaisesRegex(CandidateControlError, "server presence"):
                validate_windows_tun_trial(wrong_server, **identity)
            mismatched = copy.deepcopy(trial)
            mismatched["workload_measurements"][planned["metric"]] += 1
            with self.assertRaisesRegex(CandidateControlError, "primary metric"):
                validate_windows_tun_trial(mismatched, **identity)
            failed = copy.deepcopy(trial)
            failed["client_failure_counter_delta"] = 1.0
            with self.assertRaisesRegex(CandidateControlError, "failure counter"):
                validate_windows_tun_trial(failed, **identity)
            recursive = copy.deepcopy(trial)
            recursive["route_proofs"][1]["interface_index"] = 73
            with self.assertRaisesRegex(CandidateControlError, "loopback exclusion"):
                validate_windows_tun_trial(recursive, **identity)

    def test_latency_percentiles_and_samples_are_bound_to_checked_work(self) -> None:
        for scenario in ("tcp-request-1k-p99", "udp-packets-per-second"):
            planned = next(
                row for row in plan_for("Quick", "EndToEnd")["trials"]
                if row["scenario"] == scenario
            )
            trial = trial_for(planned, 100_000)
            identity = {
                "planned_trial": planned,
                "run_id": RUN_ID,
                "performance_source_bundle_sha256": DIGEST,
            }
            validate_windows_tun_trial(trial, **identity)
            for field, value in (
                ("p50_nanoseconds", 200_000),
                ("p95_nanoseconds", 200_000),
                ("latency_samples", 999),
            ):
                with self.subTest(scenario=scenario, field=field):
                    invalid = copy.deepcopy(trial)
                    invalid["workload_measurements"][field] = value
                    with self.assertRaises(CandidateControlError):
                        validate_windows_tun_trial(invalid, **identity)
            incomplete = copy.deepcopy(trial)
            del incomplete["workload_measurements"]["p95_nanoseconds"]
            with self.assertRaisesRegex(CandidateControlError, "measurement closure"):
                validate_windows_tun_trial(incomplete, **identity)
            retired = copy.deepcopy(trial)
            retired["schema_version"] = 2
            with self.assertRaisesRegex(CandidateControlError, "identity"):
                validate_windows_tun_trial(retired, **identity)

    def test_paired_evidence_validates_direct_and_end_to_end_metrics(self) -> None:
        for topology in ("ClientDirect", "EndToEnd"):
            with self.subTest(topology=topology), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan = plan_for("Quick", topology)
                write_common(root, "Quick", topology, plan)
                trials = write_trials(root, plan)
                summary = summary_for(plan, trials)
                write_json(root / "summary.json", summary)
                report = validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    topology=topology,
                    policy_path=POLICY,
                )
                self.assertEqual(report["status"], "CANDIDATE_WIN")
                self.assertEqual(report["topology"], topology)
                self.assertEqual(len(report["scenario_decisions"]), 4)
                request = next(
                    row
                    for row in summary["scenarios"]
                    if row["scenario"] == "tcp-request-1k-p99"
                )
                self.assertGreater(request["median_pair_improvement_ratio"], 1.0)
                request_trials = [
                    row
                    for row in trials
                    if row["scenario"] == "tcp-request-1k-p99"
                ]
                baseline_request = next(
                    row for row in request_trials if row["member"] == "baseline"
                )
                candidate_request = next(
                    row for row in request_trials if row["member"] == "candidate"
                )
                self.assertLess(
                    candidate_request["p99_nanoseconds"],
                    baseline_request["p99_nanoseconds"],
                )

    def test_cpu_cost_uses_checked_work_not_latency_improvement_ratio(self) -> None:
        topology = "ClientDirect"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = plan_for("Quick", topology)
            write_common(root, "Quick", topology, plan)
            trials = write_trials(root, plan)
            for trial in trials:
                if trial["member"] == "candidate":
                    scale_trial_work(trial, 2)
                    trial["client_cpu_percent"] = 30.0
                    write_json(
                        root / "trials" / f"{trial['sequence']:03d}" / "trial.json",
                        trial,
                    )
            write_json(root / "summary.json", summary_for(plan, trials))
            report = validate_windows_tun_host_evidence(
                evidence_root=root,
                baseline_sha=BASELINE,
                candidate_sha=CANDIDATE,
                mode="Quick",
                topology=topology,
                policy_path=POLICY,
            )
            self.assertEqual(report["status"], "CANDIDATE_WIN")

    def test_evidence_rejects_spliced_builds_cleanup_and_decisions(self) -> None:
        topology = "EndToEnd"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = plan_for("Quick", topology)
            write_common(root, "Quick", topology, plan)
            trials = write_trials(root, plan)
            summary = summary_for(plan, trials)
            write_json(root / "summary.json", summary)
            builds = json.loads((root / "builds.json").read_text(encoding="utf-8"))
            builds["candidate"]["harness_sha256"] = "b" * 64
            write_json(root / "builds.json", builds)
            with self.assertRaisesRegex(CandidateControlError, "shared harness"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    topology=topology,
                    policy_path=POLICY,
                )
            write_common(root, "Quick", topology, plan)
            dirty = json.loads((root / "cleanup.json").read_text(encoding="utf-8"))
            dirty["routes_remaining"] = 1
            write_json(root / "cleanup.json", dirty)
            with self.assertRaisesRegex(CandidateControlError, "not clean"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    topology=topology,
                    policy_path=POLICY,
                )
            write_common(root, "Quick", topology, plan)
            summary["scenarios"][0]["qualification_status"] = "regression"
            write_json(root / "summary.json", summary)
            with self.assertRaisesRegex(CandidateControlError, "scenario decision"):
                validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Quick",
                    topology=topology,
                    policy_path=POLICY,
                )

    def test_cli_returns_regression_exit_code(self) -> None:
        topology = "EndToEnd"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = plan_for("Quick", topology)
            write_common(root, "Quick", topology, plan)
            trials = write_trials(root, plan)
            for trial in trials:
                if trial["member"] == "candidate":
                    trial["client_cpu_percent"] = 30.0
                    trial["server_cpu_percent"] = 20.0
                    write_json(
                        root / "trials" / f"{trial['sequence']:03d}" / "trial.json",
                        trial,
                    )
            summary = summary_for(plan, trials)
            for scenario in summary["scenarios"]:
                scenario["candidate_client_cpu_percent_median"] = 30.0
                scenario["candidate_server_cpu_percent_median"] = 20.0
                scenario["qualification_status"] = "regression"
            write_json(root / "summary.json", summary)
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
                            "--topology",
                            topology,
                            "--policy",
                            str(POLICY),
                        ]
                    ),
                    3,
                )

    def test_lifecycle_evidence_runs_under_selected_topology(self) -> None:
        for topology in ("ClientDirect", "EndToEnd"):
            with self.subTest(topology=topology), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan = plan_for("Lifecycle", topology)
                write_common(root, "Lifecycle", topology, plan)
                write_json(root / "summary.json", lifecycle_summary(plan))
                report = validate_windows_tun_host_evidence(
                    evidence_root=root,
                    baseline_sha=BASELINE,
                    candidate_sha=CANDIDATE,
                    mode="Lifecycle",
                    topology=topology,
                    policy_path=POLICY,
                )
                self.assertEqual(report["scenario_decisions"], [])
                summary = lifecycle_summary(plan)
                summary["between_cycle_adapter_remaining"] = 1
                write_json(root / "summary.json", summary)
                with self.assertRaisesRegex(CandidateControlError, "contract is invalid"):
                    validate_windows_tun_host_evidence(
                        evidence_root=root,
                        baseline_sha=BASELINE,
                        candidate_sha=CANDIDATE,
                        mode="Lifecycle",
                        topology=topology,
                        policy_path=POLICY,
                    )


if __name__ == "__main__":
    unittest.main()
