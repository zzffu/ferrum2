"""network model identity owner."""

from __future__ import annotations

import re


SCHEMA_VERSION = 6


PAIR_COUNT = 6


TRIAL_COUNT = 108


MAX_LIFECYCLE_METRIC = 10_000_000


IDENTITY = re.compile(r"^[0-9a-f]{64}$")


COMMIT_IDENTITY = re.compile(r"^[0-9a-f]{40}$")


RUN_KINDS = frozenset({"comparison", "calibration-aa"})


MEMBERS = frozenset({"parent", "candidate"})


OBSERVATION_IDENTITY_FIELDS = {
    "run_kind",
    "member",
    "pair",
    "trial_sequence",
    "client_pid",
    "server_pid",
    "vm_name",
    "vm_id",
    "checkpoint_name",
    "checkpoint_id",
    "sha",
    "tree",
    "client_sha256",
    "server_sha256",
    "harness_sha256",
    "collector_sha256",
    "recipe_sha256",
    "model_controller_sha256",
    "model_plan_sha256",
}


class NetworkModelError(ValueError):
    """A deterministic workload observation violates the closed contract."""


def _fail(message: str) -> NoReturn:
    raise NetworkModelError(message)


def _exact_fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} fields mismatch: missing={missing}, extra={extra}")
    return value


def _integer(
    value: object,
    *,
    label: str,
    minimum: int = 0,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _identity(value: object, *, label: str) -> str:
    if type(value) is not str or IDENTITY.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 identity")
    return value


def _observation_identity(value: object) -> dict[str, object]:
    identity = _exact_fields(value, OBSERVATION_IDENTITY_FIELDS, "observation identity")
    if identity["run_kind"] not in RUN_KINDS or identity["member"] not in MEMBERS:
        _fail("observation identity run_kind/member is invalid")
    _integer(
        identity["pair"],
        label="observation identity.pair",
        minimum=1,
        maximum=PAIR_COUNT,
    )
    _integer(
        identity["trial_sequence"],
        label="observation identity.trial_sequence",
        minimum=1,
        maximum=TRIAL_COUNT,
    )
    for field in ("client_pid", "server_pid"):
        _integer(
            identity[field],
            label=f"observation identity.{field}",
            minimum=1,
            maximum=2_147_483_647,
        )
    for field in ("vm_name", "vm_id", "checkpoint_name", "checkpoint_id"):
        if type(identity[field]) is not str or not identity[field].strip():
            _fail(f"observation identity.{field} must be non-empty")
    for field in ("sha", "tree"):
        if type(identity[field]) is not str or COMMIT_IDENTITY.fullmatch(identity[field]) is None:
            _fail(f"observation identity.{field} must be lowercase 40-hex")
    for field in (
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "collector_sha256",
        "recipe_sha256",
        "model_controller_sha256",
        "model_plan_sha256",
    ):
        _identity(identity[field], label=f"observation identity.{field}")
    return identity
