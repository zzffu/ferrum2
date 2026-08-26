"""linux trial owner."""

from __future__ import annotations

import pathlib

from tools.performance_candidate.identity import COMMIT_SHA
from tools.performance_candidate.json_contract import CandidateControlError, SHA256, _optional_u64, _require_pattern, _required_string, _required_u64, _strict_json
from tools.performance_candidate.linux.scale import SCALE_SCENARIO, SCALE_TRIAL_MAX_BYTES
from tools.performance_candidate.linux.scale_trial import _validate_scale_evidence
from tools.performance_candidate.linux.evidence_contract import PROFILE_TRIAL_SCHEMA_VERSION

REGULAR_TRIAL_MAX_BYTES = 16 * 1024


PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "parent_sha",
        "candidate_sha",
        "member",
        "pair",
        "order",
        "build_profile",
        "scenario",
        "warmup_seconds",
        "active_seconds",
        "topology",
        "application_payload_bytes",
        "socks_datagram_bytes",
        "upstream_wire_bytes",
        "sha",
        "tree",
        "runner_sha256",
        "client_sha256",
        "server_sha256",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "metric",
        "unit",
        "value",
        "checked_units",
        "p99_nanoseconds",
        "io_completions",
        "scale",
        "producer_source_sha256",
        "controller_source_sha256",
        "semantic_recipe_sha256",
        "evidence_bundle_sha256",
        "environment_identity",
        "cleanup",
        "correctness",
        "status",
    }
)


def _read_trial(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except (OSError, UnicodeError) as error:
        raise CandidateControlError(
            f"unable to read evidence file {path.name}"
        ) from error
    if len(raw) > SCALE_TRIAL_MAX_BYTES + 1:
        raise CandidateControlError(
            f"evidence file {path.name} exceeds the scale byte bound"
        )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise CandidateControlError(
            f"evidence file {path.name} is not UTF-8"
        ) from error
    if len(lines) != 1 or not lines[0]:
        raise CandidateControlError(
            f"evidence file {path.name} must contain exactly one JSON row"
        )
    row = _strict_json(lines[0], source=f"evidence file {path.name}")
    if type(row) is not dict:
        raise CandidateControlError(f"evidence file {path.name} must contain an object")
    if set(row) != PROFILE_FIELDS:
        missing = sorted(PROFILE_FIELDS - set(row))
        unexpected = sorted(set(row) - PROFILE_FIELDS)
        raise CandidateControlError(
            f"evidence schema mismatch in {path.name}: missing={missing}, unexpected={unexpected}"
        )
    line_bytes = len(lines[0].encode("utf-8"))
    limit = (
        SCALE_TRIAL_MAX_BYTES
        if row.get("scenario") == SCALE_SCENARIO
        else REGULAR_TRIAL_MAX_BYTES
    )
    if line_bytes > limit:
        raise CandidateControlError(
            f"evidence file {path.name} exceeds its scenario byte bound"
        )
    return row


def _validate_trial(
    row: dict[str, object],
    *,
    source_member: str,
    plan: dict[str, object],
    planned: dict[str, dict[str, object]],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[str, int, str]:
    if _required_u64(row, "schema_version", positive=True) != PROFILE_TRIAL_SCHEMA_VERSION:
        raise CandidateControlError("evidence schema_version is unsupported")
    _required_string(row, "kind", expected="m18_profile_trial")
    _required_string(row, "parent_sha", expected=parent_sha)
    _required_string(row, "candidate_sha", expected=candidate_sha)
    member = _required_string(row, "member")
    if member not in {"parent", "candidate"} or member != source_member:
        raise CandidateControlError(
            "evidence member does not match its source directory"
        )
    scenario = _required_string(row, "scenario")
    if scenario not in planned:
        raise CandidateControlError(f"unexpected scenario in evidence: {scenario}")
    pair = _required_u64(row, "pair", positive=True)
    if pair > plan["pairs"]:
        raise CandidateControlError("evidence pair is outside the planned range")
    order = _required_u64(row, "order", positive=True)
    if order not in {1, 2}:
        raise CandidateControlError("evidence order must be 1 or 2")
    _required_string(row, "build_profile", expected="current")
    if _required_u64(row, "warmup_seconds", positive=True) != plan["warmup_seconds"]:
        raise CandidateControlError("evidence warmup_seconds does not match the plan")
    if _required_u64(row, "active_seconds", positive=True) != plan["active_seconds"]:
        raise CandidateControlError("evidence active_seconds does not match the plan")
    if _required_string(row, "topology") != planned[scenario]["topology"]:
        raise CandidateControlError("evidence topology does not match the scenario")
    if (
        _required_u64(row, "application_payload_bytes", positive=True)
        != planned[scenario]["application_payload_bytes"]
    ):
        raise CandidateControlError(
            "evidence application_payload_bytes does not match the scenario"
        )
    for field in ("socks_datagram_bytes", "upstream_wire_bytes"):
        if _optional_u64(row, field) != planned[scenario][field]:
            raise CandidateControlError(f"evidence {field} does not match the scenario")
    expected_sha = parent_sha if member == "parent" else candidate_sha
    sha = _required_string(row, "sha", expected=expected_sha)
    tree = _required_string(row, "tree")
    _require_pattern(sha, COMMIT_SHA, field="sha")
    _require_pattern(tree, COMMIT_SHA, field="tree")
    for field in ("runner_sha256", "client_sha256", "server_sha256"):
        _require_pattern(_required_string(row, field), SHA256, field=field)
    contract = planned[scenario]["evidence_contract"]
    for field in (
        "producer_source_sha256",
        "controller_source_sha256",
        "semantic_recipe_sha256",
        "evidence_bundle_sha256",
    ):
        _require_pattern(
            _required_string(row, field, expected=contract[field]), SHA256, field=field
        )
    for field in ("rustc", "kernel", "cpu_model"):
        _required_string(row, field)
    _required_u64(row, "cpu_count", positive=True)
    _required_u64(row, "memory_kib", positive=True)
    metric = _required_string(row, "metric", expected=planned[scenario]["metric"])
    _required_string(row, "unit", expected=contract["unit"])
    value = _required_u64(row, "value")
    is_scale = scenario == SCALE_SCENARIO
    _required_u64(row, "checked_units", positive=not is_scale)
    _required_u64(row, "io_completions", positive=not is_scale)
    p99 = row.get("p99_nanoseconds")
    if metric == "p99_nanoseconds":
        if type(p99) is not int or p99 != value or value == 0:
            raise CandidateControlError(
                "request evidence requires positive matching value and p99_nanoseconds"
            )
    elif p99 is not None:
        raise CandidateControlError(
            "throughput evidence must have null p99_nanoseconds"
        )
    if is_scale:
        _validate_scale_evidence(row)
    elif row["scale"] is not None:
        raise CandidateControlError("ordinary profile evidence must have null scale")
    environment_identity = row["environment_identity"]
    expected_environment_fields = {
        "runner_image",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "build_profile",
    }
    if type(environment_identity) is not dict or set(environment_identity) != expected_environment_fields:
        raise CandidateControlError("evidence environment_identity is invalid")
    expected_environment = {
        "runner_image": contract["runner_image"],
        "rustc": row["rustc"],
        "kernel": row["kernel"],
        "cpu_model": row["cpu_model"],
        "cpu_count": row["cpu_count"],
        "memory_kib": row["memory_kib"],
        "build_profile": row["build_profile"],
    }
    if environment_identity != expected_environment:
        raise CandidateControlError("evidence environment_identity does not match the trial")
    if row["cleanup"] != contract["cleanup_contract"]:
        raise CandidateControlError("evidence cleanup contract is incomplete")
    _required_string(row, "correctness", expected="PASS")
    _required_string(row, "status", expected="PASS")
    return scenario, pair, member
