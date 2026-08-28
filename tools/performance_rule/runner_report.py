"""Current qualification-runner report validation and bounded execution."""

from __future__ import annotations

import math
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from tools.performance_rule.json_contract import closed_json_bytes, exact_fields
from tools.performance_rule.schema import (
    ControlError,
    P99_TARGET_PERCENT,
    RUNNER_SCHEMA,
    SUITE_POLICY,
)

RUNNER_STDOUT_MAX_BYTES = 64 * 1024 * 1024
RUNNER_STDERR_MAX_BYTES = 64 * 1024
RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS = 5
REPORT_FIELDS = frozenset(
    {
        "schema", "generated_unix_millis", "profile", "environment", "repository",
        "runner", "candidate", "configuration", "measurement_policy", "fixtures", "measurements",
        "parity_observations", "scenario_count", "correctness_passed",
        "allocation_gate_passed", "parity_gate_passed", "thresholds_passed",
    }
)
ENVIRONMENT_FIELDS = frozenset(
    {"os", "architecture", "family", "logical_cpus", "cpu_model", "rustc_version", "timer", "build_profile"}
)
REPOSITORY_FIELDS = frozenset(
    {"git_head", "git_tree", "tree_state", "changed_entries", "status_sha256"}
)
RUNNER_FIELDS = frozenset({"sha256", "bytes"})
CANDIDATE_FIELDS = frozenset({"adoption_claim", "enabled_features"})
CANDIDATE_FEATURES = frozenset(
    {
        "candidate-atomic-snapshot",
        "candidate-cidr-radix",
        "candidate-domain-suffix-trie",
    }
)
CONFIGURATION_FIELDS = frozenset(
    {"match_sizes", "route_sizes", "dns_rule_sizes", "samples", "base_iterations_per_sample", "includes_100k"}
)
MEASUREMENT_POLICY_FIELDS = frozenset(
    {
        "latency_source", "minimum_reported_batch_nanoseconds", "calibration",
        "warmup_batches", "paired_order", "retained_samples", "allocation_measurement",
        "compiled_memory_measurement", "local_parity_target_percent",
        "noisy_gate_ceiling_percent", "p99_parity_target_percent",
        "thresholds_enforced_by_runner", "parity_gate_scope", "paired_observation_scope",
        "allocation_gate_scope", "note",
    }
)
FIXTURE_FIELDS = frozenset(
    {"name", "provenance", "bytes", "sha256", "srs_version", "statistics", "capabilities"}
)
STATISTICS_FIELDS = frozenset(
    {"rules", "exact_domains", "domain_suffixes", "domain_keywords", "ip_cidrs"}
)
CAPABILITIES_FIELDS = frozenset(
    {"exact_domain", "domain_suffix", "domain_keyword", "ip_cidr"}
)
MEASUREMENT_FIELDS = frozenset(
    {
        "id", "suite", "source", "scenario", "scale", "fixture", "rule_program_mode",
        "query_candidate_visits", "requested_min_iterations_per_sample",
        "actual_iterations_per_sample", "sample_batch_nanoseconds", "timing_pair_id",
        "paired_sample_order", "samples_ns_per_op", "p50_ns_per_op", "p99_ns_per_op",
        "queries_per_second_from_p50", "build_nanoseconds", "compiled_allocations",
        "compiled_reallocations", "compiled_entries", "compiled_bytes_per_entry",
        "allocation_samples", "allocations_per_op", "reallocations_per_op",
        "bytes_allocated_per_op", "bytes_deallocated_per_op", "compiled_memory_bytes",
        "allocation_status", "compiled_memory_status", "allocation_gate_applicable",
        "allocation_gate_passed", "correctness", "outcome_checksum",
    }
)
ALLOCATION_SAMPLE_FIELDS = frozenset(
    {"iterations", "allocations", "deallocations", "reallocations", "bytes_allocated", "bytes_deallocated"}
)
PARITY_FIELDS = frozenset(
    {
        "suite", "scenario", "scale", "baseline_id", "candidate_id",
        "median_delta_percent", "p99_delta_percent", "median_limit_percent",
        "p99_limit_percent", "performance_gate_applicable", "decision",
    }
)


def _finite_number(value: Any, *, positive: bool) -> bool:
    return (
        type(value) in (int, float)
        and math.isfinite(value)
        and (value > 0 if positive else value >= 0)
    )


def _validate_closed_report_shape(report: Any) -> dict[str, Any]:
    report = exact_fields(report, REPORT_FIELDS, label="runner report")
    exact_fields(report["environment"], ENVIRONMENT_FIELDS, label="runner environment")
    exact_fields(report["repository"], REPOSITORY_FIELDS, label="runner repository")
    exact_fields(report["runner"], RUNNER_FIELDS, label="runner identity")
    exact_fields(report["candidate"], CANDIDATE_FIELDS, label="runner candidate evidence")
    exact_fields(report["configuration"], CONFIGURATION_FIELDS, label="runner configuration")
    exact_fields(
        report["measurement_policy"],
        MEASUREMENT_POLICY_FIELDS,
        label="runner measurement policy",
    )
    fixtures = report["fixtures"]
    if not isinstance(fixtures, list):
        raise ControlError("runner fixtures are not a list")
    for fixture in fixtures:
        exact_fields(fixture, FIXTURE_FIELDS, label="runner fixture")
        exact_fields(fixture["statistics"], STATISTICS_FIELDS, label="runner fixture statistics")
        exact_fields(fixture["capabilities"], CAPABILITIES_FIELDS, label="runner fixture capabilities")
    rows = report["measurements"]
    if not isinstance(rows, list):
        raise ControlError("runner measurements are not a list")
    for row in rows:
        exact_fields(row, MEASUREMENT_FIELDS, label="runner measurement")
        samples = row["allocation_samples"]
        if not isinstance(samples, list):
            raise ControlError("runner allocation samples are not a list")
        for sample in samples:
            exact_fields(sample, ALLOCATION_SAMPLE_FIELDS, label="runner allocation sample")
    parity = report["parity_observations"]
    if not isinstance(parity, list):
        raise ControlError("runner parity observations are not a list")
    for observation in parity:
        exact_fields(observation, PARITY_FIELDS, label="runner parity observation")
    return report


def validate_report(report: Any, expected_sha256: str) -> dict[str, str]:
    report = _validate_closed_report_shape(report)
    if report.get("schema") != RUNNER_SCHEMA:
        raise ControlError("runner emitted an unsupported JSON schema")
    candidate = report["candidate"]
    if candidate["adoption_claim"] is not False:
        raise ControlError("runner candidate evidence must not claim adoption")
    enabled_features = candidate["enabled_features"]
    if (
        not isinstance(enabled_features, list)
        or any(not isinstance(feature, str) for feature in enabled_features)
        or enabled_features != sorted(set(enabled_features))
        or not set(enabled_features).issubset(CANDIDATE_FEATURES)
    ):
        raise ControlError("runner candidate feature identity is invalid")
    runner = report.get("runner")
    if not isinstance(runner, dict) or runner.get("sha256") != expected_sha256:
        raise ControlError("runner-reported SHA-256 does not match the executed binary")
    if report.get("correctness_passed") is not True:
        raise ControlError("runner did not report successful correctness checks")
    if report.get("allocation_gate_passed") is not True:
        raise ControlError("runner did not pass the allocation-free hot-path gate")
    if report.get("parity_gate_passed") is not True:
        raise ControlError("runner did not pass the local ordinary/RuleSet parity gate")
    if report.get("thresholds_passed") is not True:
        raise ControlError("runner did not pass its applicable performance thresholds")
    policy = report.get("measurement_policy")
    if not isinstance(policy, dict):
        raise ControlError("runner report has no measurement policy")
    minimum_batch_ns = policy.get("minimum_reported_batch_nanoseconds")
    if type(minimum_batch_ns) is not int or minimum_batch_ns < 100_000:
        raise ControlError("runner sample window is below 100 microseconds")
    if policy.get("thresholds_enforced_by_runner") is not True:
        raise ControlError("runner does not enforce its local parity threshold")
    p99_target = policy.get("p99_parity_target_percent")
    if p99_target != P99_TARGET_PERCENT:
        raise ControlError("runner p99 parity target is not 15 percent")
    rows = report.get("measurements")
    if not isinstance(rows, list) or not rows:
        raise ControlError("runner report has no measurements")
    scenario_suites: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ControlError("runner measurement is not an object")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ControlError("runner measurement id is invalid")
        if identifier in scenario_suites:
            raise ControlError("runner measurement ids are not unique")
        suite = row.get("suite")
        if suite not in SUITE_POLICY:
            raise ControlError(
                f"runner measurement {identifier} has an unsupported suite"
            )
        if not identifier.startswith(f"{suite}/"):
            raise ControlError(
                f"runner measurement {identifier} does not match its suite"
            )
        scenario_suites[identifier] = suite
        for metric in ("p50_ns_per_op", "p99_ns_per_op"):
            if not _finite_number(row.get(metric), positive=True):
                raise ControlError(f"runner measurement {identifier} has invalid {metric}")
        samples = row.get("samples_ns_per_op")
        if not isinstance(samples, list) or len(samples) < 5:
            raise ControlError(f"runner measurement {identifier} has too few raw samples")
        if any(not _finite_number(value, positive=True) for value in samples):
            raise ControlError(f"runner measurement {identifier} has invalid raw samples")
        requested_iterations = row.get("requested_min_iterations_per_sample")
        if type(requested_iterations) is not int or requested_iterations <= 0:
            raise ControlError(
                f"runner measurement {identifier} has invalid requested iterations"
            )
        actual_iterations = row.get("actual_iterations_per_sample")
        batch_nanoseconds = row.get("sample_batch_nanoseconds")
        if not isinstance(actual_iterations, list) or len(actual_iterations) != len(
            samples
        ):
            raise ControlError(
                f"runner measurement {identifier} has invalid actual iterations"
            )
        if not isinstance(batch_nanoseconds, list) or len(batch_nanoseconds) != len(
            samples
        ):
            raise ControlError(
                f"runner measurement {identifier} has invalid batch durations"
            )
        if any(type(value) is not int or value <= 0 for value in actual_iterations):
            raise ControlError(
                f"runner measurement {identifier} has non-positive actual iterations"
            )
        if any(
            type(value) is not int or value < minimum_batch_ns
            for value in batch_nanoseconds
        ):
            raise ControlError(
                f"runner measurement {identifier} retained a sub-window timing batch"
            )
        pair_id = row.get("timing_pair_id")
        pair_order = row.get("paired_sample_order")
        if pair_id is None:
            if pair_order is not None:
                raise ControlError(
                    f"runner measurement {identifier} has order without a timing pair"
                )
        elif (
            not isinstance(pair_id, str)
            or not pair_id
            or not isinstance(pair_order, list)
            or len(pair_order) != len(samples)
            or any(
                value not in ("baseline_first", "candidate_first")
                for value in pair_order
            )
        ):
            raise ControlError(
                f"runner measurement {identifier} has invalid paired timing evidence"
            )
        for metric in (
            "allocations_per_op",
            "reallocations_per_op",
            "bytes_allocated_per_op",
            "bytes_deallocated_per_op",
        ):
            value = row.get(metric)
            if not _finite_number(value, positive=False):
                raise ControlError(f"runner measurement {identifier} has invalid {metric}")
        if type(row.get("compiled_memory_bytes")) is not int or row[
            "compiled_memory_bytes"
        ] < 0:
            raise ControlError(
                f"runner measurement {identifier} has invalid compiled memory"
            )
        bytes_per_entry = row.get("compiled_bytes_per_entry")
        if bytes_per_entry is not None and not _finite_number(bytes_per_entry, positive=False):
            raise ControlError(
                f"runner measurement {identifier} has invalid memory per entry"
            )
        allocation_samples = row.get("allocation_samples")
        if not allocation_samples:
            raise ControlError(
                f"runner measurement {identifier} has invalid allocation samples"
            )
        for sample in allocation_samples:
            if not isinstance(sample, dict):
                raise ControlError(
                    f"runner measurement {identifier} has a malformed allocation sample"
                )
            for metric in (
                "iterations",
                "allocations",
                "deallocations",
                "reallocations",
                "bytes_allocated",
                "bytes_deallocated",
            ):
                if type(sample.get(metric)) is not int or sample[metric] < 0:
                    raise ControlError(
                        f"runner measurement {identifier} has an invalid allocation sample"
                    )
            if sample["iterations"] != 1:
                raise ControlError(
                    f"runner measurement {identifier} allocation sample is not per-operation"
                )
        if row.get("allocation_gate_applicable") is True and row.get(
            "allocation_gate_passed"
        ) is not True:
            raise ControlError(
                f"runner measurement {identifier} failed its allocation gate"
            )
    if type(report["scenario_count"]) is not int or report["scenario_count"] != len(rows):
        raise ControlError("runner scenario count does not match its measurements")
    return scenario_suites


def require_same_scenarios(
    expected: dict[str, str] | None, observed: dict[str, str]
) -> dict[str, str]:
    if expected is None:
        return observed
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        raise ControlError(
            "runner scenario or suite catalog changed "
            f"(missing={missing[:3]}, extra={extra[:3]})"
        )
    return expected


def run_once(
    role: str,
    executable: Path,
    runner_arguments: list[str],
    timeout_seconds: int,
    expected_sha256: str,
    creation_flags: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    command = [str(executable), *runner_arguments]
    returncode, stdout, stderr = _run_bounded(
        command, timeout_seconds=timeout_seconds, creation_flags=creation_flags
    )
    if returncode != 0:
        stderr = stderr[-2_000:].strip()
        raise ControlError(
            f"{role} runner exited {returncode}: {stderr or '[no stderr]'}"
        )
    report = closed_json_bytes(
        stdout.encode("utf-8"),
        label=f"{role} runner stdout",
        maximum_bytes=RUNNER_STDOUT_MAX_BYTES,
    )
    scenarios = validate_report(report, expected_sha256)
    return report, scenarios


def _run_bounded(
    command: list[str], *, timeout_seconds: int, creation_flags: int
) -> tuple[int, str, str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    )
    assert process.stdout is not None and process.stderr is not None
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    failures: list[str] = []

    def drain(name: str, maximum_bytes: int) -> None:
        stream = process.stdout if name == "stdout" else process.stderr
        assert stream is not None
        try:
            while block := stream.read(64 * 1024):
                target = captured[name]
                if len(target) + len(block) > maximum_bytes:
                    failures.append(f"runner {name} exceeds the {maximum_bytes}-byte bound")
                    process.kill()
                    return
                target.extend(block)
        except OSError as error:
            failures.append(f"unable to capture runner {name}: {error}")
            process.kill()
        finally:
            stream.close()

    readers = [
        threading.Thread(
            target=drain,
            args=("stdout", RUNNER_STDOUT_MAX_BYTES),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=("stderr", RUNNER_STDERR_MAX_BYTES),
            daemon=True,
        ),
    ]

    def join_readers() -> None:
        deadline = time.monotonic() + RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS
        for reader in readers:
            reader.join(max(0.0, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            raise ControlError("runner output capture did not terminate")

    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        join_readers()
        raise subprocess.TimeoutExpired(command, timeout_seconds)
    join_readers()
    if failures:
        raise ControlError(failures[0])
    try:
        stdout = bytes(captured["stdout"]).decode("utf-8")
        stderr = bytes(captured["stderr"]).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ControlError("runner output is not valid UTF-8") from error
    return returncode, stdout, stderr
