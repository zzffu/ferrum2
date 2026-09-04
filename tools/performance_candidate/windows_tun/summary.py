"""Closed validation and reduction of Windows-host TUN performance evidence."""

from __future__ import annotations

import math
import pathlib
import statistics

from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.windows_tun.plan import load_windows_tun_plan
from tools.performance_candidate.windows_tun.policy import load_windows_tun_policy
from tools.performance_candidate.windows_tun.trial import (
    WINDOWS_TUN_TRIAL_MAX_BYTES,
    validate_windows_tun_trial,
)

_DOCUMENT_MAX_BYTES = 1024 * 1024
_SUMMARY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "mode",
        "baseline_sha",
        "candidate_sha",
        "pair_count",
        "scenarios",
        "threshold_percent",
        "status",
    }
)
_SCENARIO_FIELDS = frozenset(
    {
        "scenario",
        "metric",
        "unit",
        "pairs",
        "median_pair_ratio",
        "median_pair_improvement_percent",
        "minimum_pair_ratio",
        "maximum_pair_ratio",
        "median_absolute_deviation",
        "outlier_pairs",
        "pairs_improved",
        "baseline_client_cpu_percent_median",
        "candidate_client_cpu_percent_median",
        "baseline_server_cpu_percent_median",
        "candidate_server_cpu_percent_median",
        "client_failure_counter_delta",
        "server_failure_counter_delta",
        "qualification_status",
    }
)
_PAIR_FIELDS = frozenset({"pair", "order", "baseline", "candidate", "ratio"})


def _read_object(path: pathlib.Path, source: str) -> dict[str, object]:
    value = read_bounded_closed_json(
        path, maximum_bytes=_DOCUMENT_MAX_BYTES, source=source
    ).value
    if type(value) is not dict:
        raise CandidateControlError(f"{source} must be a JSON object")
    return value


def _finite(value: object, field: str, *, minimum: float | None = None) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise CandidateControlError(f"{field} must be a finite number")
    number = float(value)
    if minimum is not None and number < minimum:
        raise CandidateControlError(f"{field} is below its minimum")
    return number


def _same_number(actual: object, expected: float, field: str) -> None:
    if not math.isclose(_finite(actual, field), expected, rel_tol=1e-10, abs_tol=1e-10):
        raise CandidateControlError(f"{field} does not match the raw paired evidence")


def _cpu_cost_regressed(
    baseline_cpu: float,
    candidate_cpu: float,
    *,
    work_ratio: float,
    maximum_regression_percent: float,
) -> bool:
    if baseline_cpu == 0:
        return candidate_cpu > 0
    cpu_cost_ratio = (candidate_cpu / baseline_cpu) / work_ratio
    return (cpu_cost_ratio - 1.0) * 100.0 > maximum_regression_percent


def _validate_cleanup(root: pathlib.Path, *, expected_mode: str) -> dict[str, object]:
    cleanup = _read_object(root / "cleanup.json", "Windows TUN cleanup evidence")
    _exact_fields(
        cleanup,
        frozenset(
            {
                "schema_version",
                "kind",
                "run_id",
                "status",
                "benchmark_succeeded",
                "adapter_remaining",
                "routes_remaining",
                "addresses_remaining",
                "processes_remaining",
                "ports_remaining",
                "completed_utc",
            }
        ),
        "Windows TUN cleanup evidence",
    )
    if (
        cleanup["schema_version"] != 1
        or cleanup["kind"] != "ferrum2.windows-tun.host-performance-cleanup"
        or cleanup["status"] != "PASS"
        or cleanup["benchmark_succeeded"] is not True
        or any(
            cleanup[field] != 0
            for field in (
                "adapter_remaining",
                "routes_remaining",
                "addresses_remaining",
                "processes_remaining",
                "ports_remaining",
            )
        )
    ):
        raise CandidateControlError("Windows TUN cleanup evidence is not clean")
    runtime = _read_object(root / "runtime.json", "Windows TUN runtime evidence")
    _exact_fields(
        runtime,
        frozenset(
            {
                "schema_version",
                "kind",
                "run_id",
                "mode",
                "build_seconds",
                "execution_seconds",
                "cleanup_seconds",
                "elapsed_seconds",
                "cleanup_status",
            }
        ),
        "Windows TUN runtime evidence",
    )
    if (
        runtime["schema_version"] != 1
        or runtime["kind"] != "ferrum2.windows-tun.host-performance-runtime"
        or runtime["run_id"] != cleanup["run_id"]
        or runtime["mode"] != expected_mode
        or runtime["cleanup_status"] != "PASS"
    ):
        raise CandidateControlError("Windows TUN runtime identity is invalid")
    for field in ("build_seconds", "execution_seconds", "cleanup_seconds", "elapsed_seconds"):
        _finite(runtime[field], field, minimum=0.0)
    return runtime


def _validate_builds(
    root: pathlib.Path, *, baseline_sha: str, candidate_sha: str
) -> dict[str, object]:
    builds = _read_object(root / "builds.json", "Windows TUN build evidence")
    _exact_fields(
        builds,
        frozenset(
            {
                "schema_version",
                "kind",
                "baseline",
                "candidate",
                "shared_harness_sha256",
                "shared_harness_commit_sha",
                "shared_source_bundle_sha256",
                "wintun_archive_sha256",
                "wintun_dll_sha256",
            }
        ),
        "Windows TUN build evidence",
    )
    if (
        builds["schema_version"] != 1
        or builds["kind"] != "ferrum2.windows-tun.host-build-manifest"
        or builds["shared_harness_commit_sha"] != candidate_sha
    ):
        raise CandidateControlError("Windows TUN build evidence identity is invalid")
    for field in (
        "shared_harness_sha256",
        "shared_source_bundle_sha256",
        "wintun_archive_sha256",
        "wintun_dll_sha256",
    ):
        if type(builds[field]) is not str or SHA256.fullmatch(builds[field]) is None:
            raise CandidateControlError(f"Windows TUN build {field} is invalid")
    for label, sha in (("baseline", baseline_sha), ("candidate", candidate_sha)):
        member = builds[label]
        if type(member) is not dict or member.get("label") != label or member.get("commit_sha") != sha:
            raise CandidateControlError(f"Windows TUN {label} build identity is invalid")
        for field in (
            "client_sha256",
            "server_sha256",
            "harness_sha256",
            "source_bundle_sha256",
            "wintun_dll_sha256",
        ):
            if type(member.get(field)) is not str or SHA256.fullmatch(member[field]) is None:
                raise CandidateControlError(f"Windows TUN {label} build {field} is invalid")
        if member["source_bundle_sha256"] != builds["shared_source_bundle_sha256"]:
            raise CandidateControlError("baseline and candidate workload source contracts differ")
    return builds


def _load_trials(root: pathlib.Path, plan: dict[str, object]) -> list[dict[str, object]]:
    trials = []
    for planned in plan["trials"]:
        path = root / "trials" / f"{planned['sequence']:03d}" / "trial.json"
        document = read_bounded_closed_json(
            path,
            maximum_bytes=WINDOWS_TUN_TRIAL_MAX_BYTES,
            source=f"Windows TUN trial {planned['sequence']}",
        )
        trials.append(validate_windows_tun_trial(document.value, planned_trial=planned))
    actual_paths = sorted((root / "trials").glob("*/trial.json"))
    if len(actual_paths) != len(trials):
        raise CandidateControlError("Windows TUN trial evidence closure is not exact")
    return trials


def _validate_paired_summary(
    root: pathlib.Path,
    *,
    plan: dict[str, object],
    policy: dict[str, object],
) -> dict[str, object]:
    trials = _load_trials(root, plan)
    summary = _read_object(root / "summary.json", "Windows TUN paired summary")
    _exact_fields(summary, _SUMMARY_FIELDS, "Windows TUN paired summary")
    if (
        summary["schema_version"] != 1
        or summary["kind"] != "ferrum2.windows-tun.host-performance-summary"
        or summary["mode"] != plan["mode"]
        or summary["baseline_sha"] != plan["baseline_sha"]
        or summary["candidate_sha"] != plan["candidate_sha"]
        or summary["pair_count"] != plan["pair_count"]
        or summary["threshold_percent"] != policy["threshold_percent"]
        or summary["status"] != "PASS"
    ):
        raise CandidateControlError("Windows TUN paired summary identity is invalid")
    if type(summary["scenarios"]) is not list or len(summary["scenarios"]) != len(plan["scenarios"]):
        raise CandidateControlError("Windows TUN paired scenario closure is invalid")
    for planned_scenario, scenario in zip(plan["scenarios"], summary["scenarios"], strict=True):
        if type(scenario) is not dict:
            raise CandidateControlError("Windows TUN scenario summary must be an object")
        _exact_fields(scenario, _SCENARIO_FIELDS, "Windows TUN scenario summary")
        for field, planned_field in (
            ("scenario", "name"),
            ("metric", "metric"),
            ("unit", "unit"),
        ):
            if scenario[field] != planned_scenario[planned_field]:
                raise CandidateControlError(f"Windows TUN scenario {field} changed")
        rows = [row for row in trials if row["scenario"] == scenario["scenario"]]
        expected_pairs = []
        ratios = []
        for pair_number in range(1, plan["pair_count"] + 1):
            baseline = [row for row in rows if row["pair"] == pair_number and row["member"] == "baseline"]
            candidate = [row for row in rows if row["pair"] == pair_number and row["member"] == "candidate"]
            if len(baseline) != 1 or len(candidate) != 1:
                raise CandidateControlError("Windows TUN raw paired evidence is incomplete")
            ratio = candidate[0]["value"] / baseline[0]["value"]
            ratios.append(ratio)
            expected_pairs.append((pair_number, baseline[0], candidate[0], ratio))
        pairs = scenario["pairs"]
        if type(pairs) is not list or len(pairs) != plan["pair_count"]:
            raise CandidateControlError("Windows TUN pair summary count is invalid")
        for row, (number, baseline, candidate, ratio) in zip(pairs, expected_pairs, strict=True):
            if type(row) is not dict:
                raise CandidateControlError("Windows TUN pair summary must be an object")
            _exact_fields(row, _PAIR_FIELDS, "Windows TUN pair summary")
            if row["pair"] != number or row["order"] != baseline["order"]:
                raise CandidateControlError("Windows TUN pair identity changed")
            _same_number(row["baseline"], baseline["value"], "pair.baseline")
            _same_number(row["candidate"], candidate["value"], "pair.candidate")
            _same_number(row["ratio"], ratio, "pair.ratio")
        median_ratio = statistics.median(ratios)
        deviations = [abs(value - median_ratio) for value in ratios]
        mad = statistics.median(deviations)
        outliers = [] if mad == 0 else [
            number
            for number, ratio in enumerate(ratios, 1)
            if abs(ratio - median_ratio) > 3.0 * mad
        ]
        pairs_improved = sum(value > 1.0 for value in ratios)
        majority = pairs_improved > plan["pair_count"] // 2
        baseline_client_cpu = statistics.median(
            row["client_cpu_percent"] for row in rows if row["member"] == "baseline"
        )
        candidate_client_cpu = statistics.median(
            row["client_cpu_percent"] for row in rows if row["member"] == "candidate"
        )
        baseline_server_cpu = statistics.median(
            row["server_cpu_percent"] for row in rows if row["member"] == "baseline"
        )
        candidate_server_cpu = statistics.median(
            row["server_cpu_percent"] for row in rows if row["member"] == "candidate"
        )
        maximum_cpu_regression = policy["maximum_non_target_regression_percent"]
        cpu_cost_regressed = _cpu_cost_regressed(
            baseline_client_cpu,
            candidate_client_cpu,
            work_ratio=median_ratio,
            maximum_regression_percent=maximum_cpu_regression,
        ) or _cpu_cost_regressed(
            baseline_server_cpu,
            candidate_server_cpu,
            work_ratio=median_ratio,
            maximum_regression_percent=maximum_cpu_regression,
        )
        status = (
            "regression"
            if cpu_cost_regressed
            or (
                median_ratio <= 0.98
                and sum(value < 1.0 for value in ratios) > plan["pair_count"] // 2
            )
            else "candidate-win"
            if median_ratio >= 1.02 and majority
            else "within-noise-band"
        )
        for field, expected in (
            ("median_pair_ratio", median_ratio),
            ("median_pair_improvement_percent", (median_ratio - 1.0) * 100.0),
            ("minimum_pair_ratio", min(ratios)),
            ("maximum_pair_ratio", max(ratios)),
            ("median_absolute_deviation", mad),
            ("baseline_client_cpu_percent_median", baseline_client_cpu),
            ("candidate_client_cpu_percent_median", candidate_client_cpu),
            ("baseline_server_cpu_percent_median", baseline_server_cpu),
            ("candidate_server_cpu_percent_median", candidate_server_cpu),
        ):
            _same_number(scenario[field], expected, field)
        if (
            scenario["outlier_pairs"] != outliers
            or scenario["pairs_improved"] != pairs_improved
            or scenario["client_failure_counter_delta"] != 0
            or scenario["server_failure_counter_delta"] != 0
            or scenario["qualification_status"] != status
        ):
            raise CandidateControlError("Windows TUN scenario decision does not match raw evidence")
    return summary


def _validate_lifecycle_summary(root: pathlib.Path, plan: dict[str, object]) -> dict[str, object]:
    summary = _read_object(root / "summary.json", "Windows TUN lifecycle summary")
    expected_fields = frozenset(
        {
            "schema_version",
            "kind",
            "mode",
            "candidate_sha",
            "lifecycle_cycles",
            "lifecycle_action",
            "cycle_latencies_ms",
            "cycle_latency_median_ms",
            "cycle_latency_p95_ms",
            "cycle_latency_minimum_ms",
            "cycle_latency_maximum_ms",
            "probe_failures",
            "between_cycle_adapter_remaining",
            "between_cycle_routes_remaining",
            "between_cycle_product_processes_remaining",
            "between_cycle_product_ports_remaining",
            "physical_adapter_mutations",
            "wlan_mutations",
            "dns_mutations",
            "long_durability_soak",
            "status",
        }
    )
    _exact_fields(summary, expected_fields, "Windows TUN lifecycle summary")
    if (
        summary["schema_version"] != 1
        or summary["kind"] != "ferrum2.windows-tun.host-lifecycle-summary"
        or summary["mode"] != "Lifecycle"
        or summary["candidate_sha"] != plan["candidate_sha"]
        or summary["lifecycle_cycles"] != 20
        or summary["lifecycle_action"] != "product-start-probe-stop"
        or summary["probe_failures"] != 0
        or summary["between_cycle_adapter_remaining"] != 0
        or summary["between_cycle_routes_remaining"] != 0
        or summary["between_cycle_product_processes_remaining"] != 0
        or summary["between_cycle_product_ports_remaining"] != 0
        or summary["physical_adapter_mutations"] != 0
        or summary["wlan_mutations"] != 0
        or summary["dns_mutations"] != 0
        or summary["long_durability_soak"] != "not-run"
        or summary["status"] != "PASS"
    ):
        raise CandidateControlError("Windows TUN lifecycle summary contract is invalid")
    latencies = summary["cycle_latencies_ms"]
    if type(latencies) is not list or len(latencies) != 20:
        raise CandidateControlError("Windows TUN lifecycle cycle latencies are invalid")
    values = [
        _finite(value, f"cycle_latencies_ms[{index}]", minimum=0.0)
        for index, value in enumerate(latencies)
    ]
    ordered = sorted(values)
    for field, expected in (
        ("cycle_latency_median_ms", statistics.median(values)),
        ("cycle_latency_p95_ms", ordered[math.ceil(len(ordered) * 0.95) - 1]),
        ("cycle_latency_minimum_ms", ordered[0]),
        ("cycle_latency_maximum_ms", ordered[-1]),
    ):
        _same_number(summary[field], expected, field)
    return summary


def validate_windows_tun_host_evidence(
    *,
    evidence_root: pathlib.Path,
    baseline_sha: str,
    candidate_sha: str,
    mode: str,
    policy_path: pathlib.Path,
) -> dict[str, object]:
    policy = load_windows_tun_policy(policy_path)
    plan = load_windows_tun_plan(
        evidence_root / "plan.json",
        baseline_sha=baseline_sha,
        candidate_sha=candidate_sha,
        mode=mode,
    )
    _validate_builds(
        evidence_root, baseline_sha=baseline_sha, candidate_sha=candidate_sha
    )
    summary = (
        _validate_lifecycle_summary(evidence_root, plan)
        if mode == "Lifecycle"
        else _validate_paired_summary(evidence_root, plan=plan, policy=policy)
    )
    runtime = _validate_cleanup(evidence_root, expected_mode=mode)
    return {
        "schema_version": 1,
        "kind": "ferrum2.windows-tun.host-evidence-validation",
        "mode": mode,
        "baseline_sha": baseline_sha,
        "candidate_sha": candidate_sha,
        "run_id": runtime["run_id"],
        "scenario_decisions": []
        if mode == "Lifecycle"
        else [
            {
                "scenario": row["scenario"],
                "qualification_status": row["qualification_status"],
                "median_pair_improvement_percent": row["median_pair_improvement_percent"],
            }
            for row in summary["scenarios"]
        ],
        "status": "PASS",
    }
