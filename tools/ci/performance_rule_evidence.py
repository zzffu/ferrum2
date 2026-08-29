"""Strict evidence contracts for the manual AMD Rule performance workflow."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from tools.performance_rule.evidence import (
    load_calibration,
    read_json_report,
    validate_control_raw_evidence,
)
from tools.performance_rule.pairing import summarize
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.runner_report import validate_report
from tools.performance_rule.schema import (
    CONTROL_SCHEMA,
    SNAPSHOT_READER_THREADS,
    WORKFLOW_BASE_ITERATIONS,
    WORKFLOW_SAMPLES,
    expected_profile_sizes,
)

HOST_SCHEMA = "ferrum2.performance-rule-host.v1"
CALIBRATION_BUNDLE_SCHEMA = "ferrum2.performance-rule-calibration-bundle.v2"
COMPARISON_BUNDLE_SCHEMA = "ferrum2.performance-rule-comparison-bundle.v2"
WORKFLOW_PATH = ".github/workflows/performance-rule.yml"
APPROVED_RUN_WORKFLOW_PATHS = frozenset(
    (WORKFLOW_PATH, ".github/workflows/performance-candidate.yml")
)
WORKFLOW_ARGUMENTS = (
    "--profile",
    "qualification",
    "--samples",
    str(WORKFLOW_SAMPLES),
    "--workspace-root",
    ".",
)
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_HOST_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
REVIEWER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:/-]{0,127}\Z")
HOST_FIELDS = frozenset(
    "schema cpu_vendor cpu_model logical_cpus memory_kib kernel runner_os "
    "runner_arch runner_environment image_os image_version".split()
)
CALIBRATION_MANIFEST_FIELDS = frozenset(
    "schema artifact_name repository workflow_path calibration_run_id "
    "calibration_run_attempt source_sha source_tree controller_schema pairs "
    "runner_arguments controller_exit parent_binary aa_report host_identity authority "
    "adoption_claim production_feature_enabled_by_default".split()
)
COMPARISON_MANIFEST_FIELDS = frozenset(
    "schema artifact_name repository workflow_path comparison_run_id "
    "comparison_run_attempt calibration_run_id source_sha source_tree "
    "candidate_feature enabled_features adoption_claim "
    "production_feature_enabled_by_default authority artifacts".split()
)
AUTHORITY_FIELDS = frozenset(
    {
        "scope",
        "performance_authoritative",
        "bare_metal_gate_satisfied",
        "durable_evidence_gate_satisfied",
    }
)
HOSTED_AMD_PROVISIONAL_AUTHORITY = {
    "scope": "github-hosted-amd-provisional",
    "performance_authoritative": False,
    "bare_metal_gate_satisfied": False,
    "durable_evidence_gate_satisfied": False,
}
ARTIFACT_RECORD_FIELDS = frozenset({"path", "bytes", "sha256"})
CALIBRATION_FILES = frozenset(
    "calibration-manifest.json controller-exit-code.txt host-identity.json "
    "parent/ferrum2-rule-qualification release-aa-v7.json".split()
)
CALIBRATION_RECORDS = {
    "controller_exit": ("controller-exit-code.txt", 32),
    "parent_binary": ("parent/ferrum2-rule-qualification", MAX_BINARY_BYTES),
    "aa_report": ("release-aa-v7.json", MAX_REPORT_BYTES),
    "host_identity": ("host-identity.json", MAX_HOST_BYTES),
}
COMPARISON_FILES = tuple(
    "ab-exit-code.txt calibration-host-identity.json calibration-manifest.json "
    "candidate-qualification.json candidate/ferrum2-rule-qualification "
    "host-identity.json parent/ferrum2-rule-qualification "
    "qualification-exit-code.txt release-aa-v7.json release-ab-v7.json "
    "reviewed-aa-v3.json".split()
)
FEATURES = {
    "domain": ("candidate-domain-suffix-trie",),
    "cidr": ("candidate-cidr-radix",),
    "atomic": ("candidate-atomic-snapshot",),
    "all": (
        "candidate-atomic-snapshot",
        "candidate-cidr-radix",
        "candidate-domain-suffix-trie",
    ),
}


class WorkflowContractError(ValueError):
    """The manual workflow input or evidence failed closed validation."""


CommandProbe = Callable[[tuple[str, ...], pathlib.Path], str]


@dataclass(frozen=True)
class SourceIdentity:
    sha: str
    tree: str


@dataclass(frozen=True)
class CalibrationManifestInputs:
    evidence: pathlib.Path
    parent: pathlib.Path
    aa_report: pathlib.Path
    host_identity: pathlib.Path
    workspace: pathlib.Path
    expected_sha: str
    repository: str
    run_id: int
    run_attempt: int
    output: pathlib.Path


@dataclass(frozen=True)
class CalibrationVerificationInputs:
    artifact: pathlib.Path
    comparison_host: pathlib.Path
    workspace: pathlib.Path
    expected_sha: str
    repository: str
    run_id: int
    run_attempt: int


@dataclass(frozen=True)
class ComparisonValidationInputs:
    evidence: pathlib.Path
    workspace: pathlib.Path
    parent: pathlib.Path
    candidate: pathlib.Path
    calibration: pathlib.Path
    ab_report: pathlib.Path
    qualification_report: pathlib.Path
    reviewed_by: str
    reviewed_utc: str
    feature: str
    repository: str
    expected_sha: str
    comparison_run_id: int
    comparison_run_attempt: int
    calibration_run_id: int
    output: pathlib.Path


def fail(message: str) -> NoReturn:
    raise WorkflowContractError(message)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is not permitted: {value}")


def _regular_file(path: pathlib.Path, maximum: int, label: str) -> int:
    if path.is_symlink():
        fail(f"{label} must not be a symbolic link")
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        fail(f"{label} is missing")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular file")
    if not 0 < metadata.st_size <= maximum:
        fail(f"{label} exceeds its bounded size")
    return metadata.st_size


def decode_strict_json(encoded: bytes, maximum: int, label: str) -> dict[str, object]:
    try:
        if not encoded or len(encoded) > maximum:
            fail(f"{label} exceeds its bounded size")
        contents = encoded.decode("utf-8")
        value = json.loads(
            contents,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkflowContractError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def read_strict_json(path: pathlib.Path, maximum: int, label: str) -> dict[str, object]:
    _regular_file(path, maximum, label)
    with path.open("rb") as source:
        encoded = source.read(maximum + 1)
    return decode_strict_json(encoded, maximum, label)


def write_json_atomic(path: pathlib.Path, value: Mapping[str, object]) -> None:
    if path.suffix != ".json":
        fail("JSON output must use a .json extension")
    if not path.parent.is_dir():
        fail("JSON output parent directory does not exist")
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def sha256_file(path: pathlib.Path, maximum: int, label: str) -> tuple[int, str]:
    size = _regular_file(path, maximum, label)
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            observed += len(block)
            if observed > maximum:
                fail(f"{label} exceeds its bounded size")
            digest.update(block)
    if observed != size:
        fail(f"{label} changed while hashing")
    return size, digest.hexdigest()


def artifact_record(
    path: pathlib.Path, relative: str, maximum: int, label: str
) -> dict[str, object]:
    size, digest = sha256_file(path, maximum, label)
    return {"path": relative, "bytes": size, "sha256": digest}


def _exact_fields(
    value: object, expected: frozenset[str], label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields are not closed")
    return value


def _validate_outer_manifest_authority(
    value: object, expected_fields: frozenset[str], schema: str, label: str
) -> dict[str, object]:
    manifest = _exact_fields(value, expected_fields, label)
    authority = _exact_fields(manifest.get("authority"), AUTHORITY_FIELDS, "authority")
    if (
        manifest.get("schema") != schema
        or authority.get("scope") != "github-hosted-amd-provisional"
        or authority.get("performance_authoritative") is not False
        or authority.get("bare_metal_gate_satisfied") is not False
        or authority.get("durable_evidence_gate_satisfied") is not False
        or manifest.get("adoption_claim") is not False
        or manifest.get("production_feature_enabled_by_default") is not False
    ):
        fail(f"{label} broadened GitHub-hosted AMD authority")
    return manifest


def validate_calibration_manifest_authority(value: object) -> dict[str, object]:
    return _validate_outer_manifest_authority(
        value,
        CALIBRATION_MANIFEST_FIELDS,
        CALIBRATION_BUNDLE_SCHEMA,
        "calibration manifest",
    )


def validate_comparison_manifest_authority(value: object) -> dict[str, object]:
    return _validate_outer_manifest_authority(
        value,
        COMPARISON_MANIFEST_FIELDS,
        COMPARISON_BUNDLE_SCHEMA,
        "comparison manifest",
    )


def _read_persisted_manifest(
    path: pathlib.Path,
    *,
    expected: Mapping[str, object],
    expected_fields: frozenset[str],
    schema: str,
    label: str,
) -> dict[str, object]:
    observed = _validate_outer_manifest_authority(
        read_strict_json(path, MAX_MANIFEST_BYTES, label),
        expected_fields,
        schema,
        label,
    )
    if observed != expected:
        fail(f"{label} differs from recomputed raw evidence")
    return observed


def positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def validate_git_sha(value: str, label: str) -> None:
    if not HEX_40.fullmatch(value):
        fail(f"{label} must be a lowercase Git SHA")


def validate_repository(value: str) -> None:
    if not REPOSITORY.fullmatch(value):
        fail("repository must be owner/name")


def validate_review(reviewed_by: str, reviewed_utc: str) -> None:
    if not REVIEWER.fullmatch(reviewed_by):
        fail("reviewed_by is not a bounded reviewer identity")
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        reviewed_utc,
    ):
        fail("reviewed_utc is not canonical UTC")
    import datetime as dt

    try:
        dt.datetime.strptime(reviewed_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise WorkflowContractError("reviewed_utc is not a real UTC time") from error


def default_command_probe(command: tuple[str, ...], cwd: pathlib.Path) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    value = completed.stdout.strip()
    if not value or len(value) > 4096:
        fail(f"command probe returned invalid output: {command[0]}")
    return value


def source_identity(
    workspace: pathlib.Path, command_probe: CommandProbe = default_command_probe
) -> SourceIdentity:
    identity = SourceIdentity(
        command_probe(("git", "rev-parse", "HEAD"), workspace),
        command_probe(("git", "rev-parse", "HEAD^{tree}"), workspace),
    )
    validate_git_sha(identity.sha, "source SHA")
    validate_git_sha(identity.tree, "source tree")
    return identity


def expected_repository(identity: SourceIdentity) -> dict[str, object]:
    return {
        "git_head": identity.sha,
        "git_tree": identity.tree,
        "tree_state": "clean",
        "changed_entries": 0,
        "status_sha256": EMPTY_STATUS_SHA256,
    }


def validate_host_document(value: object) -> dict[str, object]:
    host = _exact_fields(value, HOST_FIELDS, "host identity")
    if host.get("schema") != HOST_SCHEMA or host.get("cpu_vendor") != "AuthenticAMD":
        fail("host identity is not AuthenticAMD")
    for field in (
        "cpu_model",
        "kernel",
        "runner_os",
        "runner_arch",
        "runner_environment",
        "image_os",
        "image_version",
    ):
        if not isinstance(host.get(field), str) or not host[field]:
            fail(f"host identity {field} is invalid")
    for field in ("logical_cpus", "memory_kib"):
        positive_integer(host.get(field), f"host identity {field}")
    if host["runner_os"] != "Linux" or host["runner_arch"] != "X64":
        fail("host identity is not Linux/X64")
    if host["runner_environment"] != "github-hosted":
        fail("host identity is not a GitHub-hosted runner")
    return host


def _observed_files(root: pathlib.Path) -> frozenset[str]:
    if root.is_symlink() or not root.is_dir():
        fail("evidence root must be a direct directory")
    observed: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            fail("evidence contains a symbolic link")
        if path.is_file():
            observed.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            fail("evidence contains a non-file entry")
    return frozenset(observed)


def _validate_runner(
    report: Mapping[str, Any],
    *,
    repository: Mapping[str, object],
    runner_sha256: str,
    runner_bytes: int,
    features: Sequence[str],
    profile: str,
    samples: int,
    includes_100k: bool,
) -> None:
    if (
        report.get("repository") != repository
        or report.get("runner") != {"sha256": runner_sha256, "bytes": runner_bytes}
        or report.get("candidate")
        != {"adoption_claim": False, "enabled_features": list(features)}
        or report.get("profile") != profile
    ):
        fail("raw runner build or source identity is inconsistent")
    configuration = report.get("configuration")
    if not isinstance(configuration, dict):
        fail("raw runner configuration is invalid")
    match_sizes, route_sizes, dns_rule_sizes = expected_profile_sizes(
        profile, includes_100k
    )
    expected_configuration = {
        "match_sizes": match_sizes,
        "route_sizes": route_sizes,
        "dns_rule_sizes": dns_rule_sizes,
        "snapshot_reader_threads": SNAPSHOT_READER_THREADS,
        "samples": samples,
        "base_iterations_per_sample": WORKFLOW_BASE_ITERATIONS,
        "includes_100k": includes_100k,
    }
    if configuration != expected_configuration:
        fail("raw runner qualification matrix or iteration identity changed")


def _validate_aa(
    path: pathlib.Path,
    *,
    identity: SourceIdentity,
    parent_sha256: str,
    parent_bytes: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _, report, _ = read_json_report(path, "workflow A/A evidence")
    _, raw_pairs = validate_control_raw_evidence(report, "aa")
    if (
        report.get("schema") != CONTROL_SCHEMA
        or report.get("status") != "CALIBRATION_REQUIRED"
        or report.get("pairs") != 6
        or report.get("runner_arguments") != list(WORKFLOW_ARGUMENTS)
        or report.get("parent_runner_sha256") != parent_sha256
        or report.get("candidate_runner_sha256") != parent_sha256
    ):
        fail("A/A controller identity is not the registered v7 contract")
    repository = expected_repository(identity)
    environment: object | None = None
    for pair in raw_pairs:
        for role in ("parent", "candidate"):
            runner = pair[role]
            _validate_runner(
                runner,
                repository=repository,
                runner_sha256=parent_sha256,
                runner_bytes=parent_bytes,
                features=(),
                profile="qualification",
                samples=WORKFLOW_SAMPLES,
                includes_100k=False,
            )
            if environment is None:
                environment = runner["environment"]
            elif runner["environment"] != environment:
                fail("A/A runner environment changed within the schedule")
    return report, raw_pairs


def _read_exit(path: pathlib.Path, label: str) -> int:
    _regular_file(path, 32, label)
    with path.open("rb") as source:
        encoded = source.read(33)
    if not re.fullmatch(rb"[0-9]+\n", encoded):
        fail(f"{label} is malformed")
    return int(encoded)


def build_calibration_manifest(
    inputs: CalibrationManifestInputs,
    *,
    command_probe: CommandProbe = default_command_probe,
) -> dict[str, object]:
    positive_integer(inputs.run_id, "calibration run ID")
    positive_integer(inputs.run_attempt, "calibration run attempt")
    validate_repository(inputs.repository)
    validate_git_sha(inputs.expected_sha, "expected SHA")
    identity = source_identity(inputs.workspace, command_probe)
    if identity.sha != inputs.expected_sha:
        fail("calibration source SHA changed")
    parent_bytes, parent_sha256 = sha256_file(
        inputs.parent, MAX_BINARY_BYTES, "calibrated parent"
    )
    validate_host_document(
        read_strict_json(inputs.host_identity, MAX_HOST_BYTES, "host identity")
    )
    _validate_aa(
        inputs.aa_report,
        identity=identity,
        parent_sha256=parent_sha256,
        parent_bytes=parent_bytes,
    )
    if _read_exit(inputs.evidence / "controller-exit-code.txt", "A/A exit") != 4:
        fail("A/A controller exit identity is invalid")
    if _observed_files(inputs.evidence) != CALIBRATION_FILES - {
        "calibration-manifest.json"
    }:
        fail("calibration evidence file closure changed")
    manifest: dict[str, object] = {
        "schema": CALIBRATION_BUNDLE_SCHEMA,
        "artifact_name": (
            f"performance-rule-calibration-{inputs.run_id}-{inputs.run_attempt}"
        ),
        "repository": inputs.repository,
        "workflow_path": WORKFLOW_PATH,
        "calibration_run_id": inputs.run_id,
        "calibration_run_attempt": inputs.run_attempt,
        "source_sha": identity.sha,
        "source_tree": identity.tree,
        "controller_schema": CONTROL_SCHEMA,
        "pairs": 6,
        "runner_arguments": list(WORKFLOW_ARGUMENTS),
        "controller_exit": artifact_record(
            inputs.evidence / "controller-exit-code.txt",
            "controller-exit-code.txt",
            32,
            "controller exit",
        ),
        "parent_binary": artifact_record(
            inputs.parent,
            "parent/ferrum2-rule-qualification",
            MAX_BINARY_BYTES,
            "calibrated parent",
        ),
        "aa_report": artifact_record(
            inputs.aa_report, "release-aa-v7.json", MAX_REPORT_BYTES, "A/A report"
        ),
        "host_identity": artifact_record(
            inputs.host_identity, "host-identity.json", MAX_HOST_BYTES, "host identity"
        ),
        "authority": dict(HOSTED_AMD_PROVISIONAL_AUTHORITY),
        "adoption_claim": False,
        "production_feature_enabled_by_default": False,
    }
    if inputs.output.parent != inputs.evidence or inputs.output.name != (
        "calibration-manifest.json"
    ):
        fail("calibration manifest output path is invalid")
    write_json_atomic(inputs.output, manifest)
    return _read_persisted_manifest(
        inputs.output,
        expected=manifest,
        expected_fields=CALIBRATION_MANIFEST_FIELDS,
        schema=CALIBRATION_BUNDLE_SCHEMA,
        label="calibration manifest",
    )


def _parse_artifact_record(
    root: pathlib.Path,
    value: object,
    *,
    expected_path: str,
    maximum: int,
    label: str,
) -> tuple[pathlib.Path, int, str]:
    record = _exact_fields(value, ARTIFACT_RECORD_FIELDS, label)
    if record.get("path") != expected_path:
        fail(f"{label} manifest path changed")
    size = positive_integer(record.get("bytes"), f"{label} bytes")
    digest = record.get("sha256")
    if size > maximum or not isinstance(digest, str) or not HEX_64.fullmatch(digest):
        fail(f"{label} manifest identity is invalid")
    path = root.joinpath(*pathlib.PurePosixPath(expected_path).parts)
    observed_size, observed_digest = sha256_file(path, maximum, label)
    if (observed_size, observed_digest) != (size, digest):
        fail(f"{label} artifact identity changed")
    return path, size, digest


def verify_calibration_artifact(
    inputs: CalibrationVerificationInputs,
    *,
    command_probe: CommandProbe = default_command_probe,
) -> dict[str, object]:
    positive_integer(inputs.run_id, "calibration run ID")
    positive_integer(inputs.run_attempt, "calibration run attempt")
    validate_repository(inputs.repository)
    validate_git_sha(inputs.expected_sha, "expected SHA")
    if _observed_files(inputs.artifact) != CALIBRATION_FILES:
        fail("calibration artifact file closure changed")
    manifest = validate_calibration_manifest_authority(
        read_strict_json(
            inputs.artifact / "calibration-manifest.json",
            MAX_MANIFEST_BYTES,
            "calibration manifest",
        ),
    )
    identity = source_identity(inputs.workspace, command_probe)
    if (
        manifest.get("schema") != CALIBRATION_BUNDLE_SCHEMA
        or manifest.get("artifact_name")
        != f"performance-rule-calibration-{inputs.run_id}-{inputs.run_attempt}"
        or manifest.get("repository") != inputs.repository
        or manifest.get("workflow_path") != WORKFLOW_PATH
        or manifest.get("calibration_run_id") != inputs.run_id
        or manifest.get("calibration_run_attempt") != inputs.run_attempt
        or manifest.get("source_sha") != identity.sha
        or identity.sha != inputs.expected_sha
        or manifest.get("source_tree") != identity.tree
        or manifest.get("controller_schema") != CONTROL_SCHEMA
        or manifest.get("pairs") != 6
        or manifest.get("runner_arguments") != list(WORKFLOW_ARGUMENTS)
    ):
        fail("calibration manifest does not apply to this checkout")
    records = {
        name: _parse_artifact_record(
            inputs.artifact,
            manifest.get(name),
            expected_path=path,
            maximum=maximum,
            label=name,
        )
        for name, (path, maximum) in CALIBRATION_RECORDS.items()
    }
    calibration_host = validate_host_document(
        read_strict_json(
            records["host_identity"][0], MAX_HOST_BYTES, "calibration host"
        )
    )
    comparison_host = validate_host_document(
        read_strict_json(inputs.comparison_host, MAX_HOST_BYTES, "comparison host")
    )
    if calibration_host != comparison_host:
        fail(
            "comparison AMD CPU model or exact runner identity differs from calibration"
        )
    parent_path, parent_bytes, parent_sha256 = records["parent_binary"]
    _validate_aa(
        records["aa_report"][0],
        identity=identity,
        parent_sha256=parent_sha256,
        parent_bytes=parent_bytes,
    )
    if _read_exit(records["controller_exit"][0], "downloaded A/A exit") != 4:
        fail("downloaded A/A controller exit identity is invalid")
    if parent_path.stat().st_size != parent_bytes:
        fail("downloaded parent identity changed")
    return manifest


def validate_comparison(
    inputs: ComparisonValidationInputs,
    *,
    command_probe: CommandProbe = default_command_probe,
) -> dict[str, object]:
    positive_integer(inputs.comparison_run_id, "comparison run ID")
    positive_integer(inputs.comparison_run_attempt, "comparison run attempt")
    positive_integer(inputs.calibration_run_id, "calibration run ID")
    validate_repository(inputs.repository)
    validate_git_sha(inputs.expected_sha, "expected SHA")
    validate_review(inputs.reviewed_by, inputs.reviewed_utc)
    expected_features = FEATURES.get(inputs.feature)
    if expected_features is None:
        fail("candidate feature is not supported")
    identity = source_identity(inputs.workspace, command_probe)
    if identity.sha != inputs.expected_sha:
        fail("comparison source SHA changed")
    parent_bytes, parent_sha256 = sha256_file(
        inputs.parent, MAX_BINARY_BYTES, "calibrated parent"
    )
    candidate_bytes, candidate_sha256 = sha256_file(
        inputs.candidate, MAX_BINARY_BYTES, "candidate binary"
    )
    if parent_sha256 == candidate_sha256:
        fail("candidate binary is identical to calibrated parent")
    _, ab_report, _ = read_json_report(inputs.ab_report, "workflow A/B evidence")
    _, raw_pairs = validate_control_raw_evidence(ab_report, "parent_candidate")
    calibration_path, calibration, calibration_file_sha256 = read_json_report(
        inputs.calibration, "workflow reviewed calibration"
    )
    _, effective_limits, calibration_sha256 = load_calibration(
        inputs.calibration,
        parent_sha256,
        ab_report["scenario_suites"],
        list(WORKFLOW_ARGUMENTS),
        "normal",
    )
    if calibration_file_sha256 != calibration_sha256:
        fail("reviewed calibration changed while validating")
    if (
        calibration.get("review_status") != "APPROVED"
        or calibration.get("reviewed_by") != inputs.reviewed_by
        or calibration.get("reviewed_utc") != inputs.reviewed_utc
        or calibration.get("source_report") != "release-aa-v7.json"
        or calibration.get("runner_sha256") != parent_sha256
        or calibration.get("runner_arguments") != list(WORKFLOW_ARGUMENTS)
    ):
        fail("reviewed calibration identity is inconsistent")
    if (
        ab_report.get("schema") != CONTROL_SCHEMA
        or ab_report.get("pairs") != 6
        or ab_report.get("runner_arguments") != list(WORKFLOW_ARGUMENTS)
        or ab_report.get("parent_runner_sha256") != parent_sha256
        or ab_report.get("candidate_runner_sha256") != candidate_sha256
        or not isinstance(ab_report.get("threshold_policy"), dict)
        or ab_report["threshold_policy"].get("reviewed") is not True
    ):
        fail("A/B controller identity is inconsistent")
    expected_comparisons = summarize(
        ab_report["scenario_suites"], raw_pairs, False, effective_limits
    )
    expected_policy = threshold_policy(
        expected_comparisons,
        effective_limits,
        str(calibration_path),
        calibration_sha256,
        reviewed=True,
    )
    if (
        ab_report.get("comparisons") != expected_comparisons
        or ab_report.get("threshold_policy") != expected_policy
        or ab_report.get("status") != expected_policy["status"]
        or ab_report.get("decision_reason")
        != "reviewed match_set and conditional snapshot_registry median gates evaluated"
    ):
        fail("A/B comparison or policy derivation is inconsistent")
    repository = expected_repository(identity)
    environment: object | None = None
    for pair in raw_pairs:
        for role, digest, size, features in (
            ("parent", parent_sha256, parent_bytes, ()),
            ("candidate", candidate_sha256, candidate_bytes, expected_features),
        ):
            runner = pair[role]
            _validate_runner(
                runner,
                repository=repository,
                runner_sha256=digest,
                runner_bytes=size,
                features=features,
                profile="qualification",
                samples=WORKFLOW_SAMPLES,
                includes_100k=False,
            )
            if environment is None:
                environment = runner["environment"]
            elif runner["environment"] != environment:
                fail("A/B runner environment changed within the schedule")
    _, qualification, _ = read_json_report(
        inputs.qualification_report, "candidate qualification evidence"
    )
    validate_report(qualification, candidate_sha256)
    _validate_runner(
        qualification,
        repository=repository,
        runner_sha256=candidate_sha256,
        runner_bytes=candidate_bytes,
        features=expected_features,
        profile="qualification",
        samples=WORKFLOW_SAMPLES,
        includes_100k=True,
    )
    expected_ab_exit = {
        "CANDIDATE_WIN": 0,
        "WITHIN_CALIBRATED_BAND": 0,
        "REGRESSION": 3,
        "INCONCLUSIVE": 4,
    }.get(ab_report.get("status"))
    if (
        expected_ab_exit is None
        or _read_exit(inputs.evidence / "ab-exit-code.txt", "A/B exit")
        != expected_ab_exit
    ):
        fail("A/B exit status does not match its evidence")
    if (
        _read_exit(
            inputs.evidence / "qualification-exit-code.txt", "qualification exit"
        )
        != 0
    ):
        fail("candidate qualification did not pass")
    calibration_host = validate_host_document(
        read_strict_json(
            inputs.evidence / "calibration-host-identity.json",
            MAX_HOST_BYTES,
            "calibration host",
        )
    )
    comparison_host = validate_host_document(
        read_strict_json(
            inputs.evidence / "host-identity.json", MAX_HOST_BYTES, "comparison host"
        )
    )
    if calibration_host != comparison_host:
        fail("comparison host identity changed after calibration verification")
    if _observed_files(inputs.evidence) != frozenset(COMPARISON_FILES):
        fail("comparison evidence file closure changed")
    artifacts = []
    for relative in COMPARISON_FILES:
        if relative.endswith("ferrum2-rule-qualification"):
            maximum = MAX_BINARY_BYTES
        elif relative.endswith("exit-code.txt"):
            maximum = 32
        elif relative.endswith("host-identity.json") or relative.endswith(
            "manifest.json"
        ):
            maximum = MAX_MANIFEST_BYTES
        else:
            maximum = MAX_REPORT_BYTES
        artifacts.append(
            artifact_record(
                inputs.evidence.joinpath(*pathlib.PurePosixPath(relative).parts),
                relative,
                maximum,
                relative,
            )
        )
    manifest: dict[str, object] = {
        "schema": COMPARISON_BUNDLE_SCHEMA,
        "artifact_name": (
            f"performance-rule-comparison-{inputs.comparison_run_id}-"
            f"{inputs.comparison_run_attempt}"
        ),
        "repository": inputs.repository,
        "workflow_path": WORKFLOW_PATH,
        "comparison_run_id": inputs.comparison_run_id,
        "comparison_run_attempt": inputs.comparison_run_attempt,
        "calibration_run_id": inputs.calibration_run_id,
        "source_sha": identity.sha,
        "source_tree": identity.tree,
        "candidate_feature": inputs.feature,
        "enabled_features": list(expected_features),
        "adoption_claim": False,
        "production_feature_enabled_by_default": False,
        "authority": dict(HOSTED_AMD_PROVISIONAL_AUTHORITY),
        "artifacts": artifacts,
    }
    if inputs.output.parent != inputs.evidence or inputs.output.name != (
        "comparison-manifest.json"
    ):
        fail("comparison manifest output path is invalid")
    write_json_atomic(inputs.output, manifest)
    return _read_persisted_manifest(
        inputs.output,
        expected=manifest,
        expected_fields=COMPARISON_MANIFEST_FIELDS,
        schema=COMPARISON_BUNDLE_SCHEMA,
        label="comparison manifest",
    )
