#!/usr/bin/env python3
"""Deterministic helper for the Codex milestone workflow.

Standard-library only. Python 3.11+ is required for tomllib.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import fnmatch
import math
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

MIN_PYTHON = (3, 11)
TICKET_STATUSES = {
    "draft",
    "blocked",
    "ready",
    "in_progress",
    "review",
    "failed",
    "done",
    "deferred",
}
DURABLE_TICKET_STATUSES = {"draft", "blocked", "ready", "done", "deferred"}
LEGACY_TRANSIENT_STATUSES = {"in_progress", "review", "failed"}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
DEPENDENCY_FIELDS = {
    "implementation": "implementation_blocked_by",
    "review": "review_blocked_by",
    "integration": "integration_blocked_by",
    "release": "release_blocked_by",
}
RISK_LEVELS = {"low", "medium", "high", "critical"}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
BLOCKER_CLASSES = {
    "authorization",
    "code",
    "contract",
    "decision",
    "dependency",
    "environment",
    "mechanical",
    "none",
    "remote",
    "repository_state",
    "security",
    "test_evidence",
}
AUTHORIZATION_STATES = {"not_required", "required", "granted", "exhausted"}
REPAIR_CLASSES = {"mechanical", "evidence", "substantive"}
REVIEW_ROUNDS = {"full", "targeted", "superseding"}
REVIEW_VERDICTS = {"pass", "pass_with_notes", "block", "escalate"}
REVIEWERS = {"architect", "qa"}
REVIEW_FINDING_SEVERITIES = {"blocker", "major", "minor", "note"}
BLOCKING_REVIEW_SEVERITIES = {"blocker", "major"}
NEW_REVIEW_BLOCKER_ORIGINS = {"introduced_by_repair", "previously_unobservable"}
TEST_BUDGET_GATES = {"report", "ticket", "milestone"}
TEST_BUDGET_MODES = {"ratchet", "strict", "off"}
TEST_BUDGET_TOOLS = {"auto", "builtin", "rustloc"}
TRANSIENT_PHASES = {"implementation", "review", "repair", "integration", "release"}
ACTIVE_WRITER_PHASES = {"implementation", "repair"}
PHASE_DEPENDENCY_GATE = {
    "implementation": "implementation",
    "review": "review",
    "repair": "review",
    "integration": "integration",
    "release": "release",
}
DEPENDENCY_PHASE_ORDER = {
    phase: index for index, phase in enumerate(DEPENDENCY_FIELDS)
}
LEGACY_STATUS_PHASES = {
    "in_progress": "implementation",
    "review": "review",
    "failed": "repair",
}
RUNTIME_STATE_VERSION = 1
ALLOWED_DURABLE_TRANSITIONS = {
    "draft": {"blocked", "ready", "deferred"},
    "blocked": {"draft", "ready", "deferred"},
    "ready": {"blocked", "done", "deferred"},
    "done": set(),
    "deferred": {"draft", "ready"},
}

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "workflow": {
        "base_branch": "main",
        "worktree_root": ".worktrees",
        "engineer_branch_prefix": "codex/ticket",
        "integration_branch_prefix": "codex/integration",
        "max_parallel_engineers": 3,
        "require_clean_base": True,
        "auto_remove_worktrees": False,
        "checkpoint_policy": "integration",
    },
    "execution": {
        "strategy": "drain",
        "max_waves_per_run": 0,
        "max_repair_attempts_per_ticket": 1,
        "repair_budget": {"low": 1, "medium": 1, "high": 1, "critical": 1},
        "non_counting_repair_classes": ["mechanical"],
        "continue_after_independent_failure": True,
        "auto_close": False,
        "no_progress_limit": 2,
    },
    "planning": {
        "contract_style": "outcome",
        "max_adrs_per_milestone": 4,
        "allow_new_adr_during_execute": False,
        "spec_soft_line_limit": 400,
        "test_plan_soft_line_limit": 300,
        "max_acceptance_criteria_per_ticket": 8,
    },
    "review": {
        "blocking_severities": ["blocker", "major"],
        "max_full_review_rounds": 1,
        "max_targeted_repair_rounds": 1,
        "new_blockers_after_first_review": "introduced_by_repair_only",
        "pass_with_notes_integrates": True,
        "freeze_contract_on_execute": True,
        "write_advisories_to_backlog": True,
    },
    "quality": {
        "test_budget": {
            "enabled": True,
            "tool": "builtin",
            "mode": "ratchet",
            "target_ratio": 1.0,
            "warn_ratio": 0.85,
            "max_regression": 0.0,
            "ratchet_step": 0.05,
            "max_delta_ratio": 1.0,
            "delta_test_allowance": 120,
            "min_code_lines": 200,
            "baseline_path": "codex/test-budget-baseline.json",
            "include_extensions": [".rs"],
            "exclude_globs": [
                ".git/**",
                ".worktrees/**",
                "target/**",
                "**/target/**",
                "**/generated/**",
                "**/fixtures/**",
            ],
        }
    },
    "state": {"path": "codex/milestone-workflow-state.json"},
    "agents": {
        "product_manager": {
            "config": ".codex/agents/product-manager.toml",
            "name": "product_manager",
            "model": "gpt-5.6-sol",
            "reasoning_effort": "max",
        },
        "architect": {
            "config": ".codex/agents/architect.toml",
            "name": "architect",
            "model": "gpt-5.6-sol",
            "reasoning_effort": "max",
        },
        "engineer": {
            "config": ".codex/agents/engineer.toml",
            "name": "engineer",
            "model": "gpt-5.6-sol",
            "reasoning_effort": "high",
        },
        "qa": {
            "config": ".codex/agents/qa.toml",
            "name": "qa",
            "model": "gpt-5.6-sol",
            "reasoning_effort": "high",
        },
    },
    "documents": {
        "vision": "docs/vision.md",
        "gap_analysis": "docs/gap-analysis.md",
        "roadmap": "docs/roadmap.md",
        "ci_status": "docs/ci-status.md",
        "adr_dir": "docs/adr",
        "spec_dir": "docs/specs",
        "test_plan_dir": "docs/test-plans",
        "ticket_dir": "docs/tickets",
        "handoff_dir": "docs/handoffs",
        "review_debt": "docs/review-debt.md",
    },
    "validation": {"workflow": [], "quick": [], "full": []},
}


@dataclass(frozen=True)
class Ticket:
    path: Path
    metadata: dict[str, Any]
    body: str

    @property
    def id(self) -> str:
        return str(self.metadata["id"])

    @property
    def title(self) -> str:
        return str(self.metadata["title"])

    @property
    def milestone(self) -> str:
        return str(self.metadata["milestone"])

    @property
    def status(self) -> str:
        return str(self.metadata["status"])

    @property
    def priority(self) -> str:
        return str(self.metadata.get("priority", "P2")).upper()

    @property
    def blockers(self) -> list[str]:
        """Legacy alias for implementation dependencies."""
        return self.implementation_blockers

    def dependencies(self, phase: str) -> list[str]:
        field = DEPENDENCY_FIELDS[phase]
        if phase == "implementation" and field not in self.metadata:
            raw = self.metadata.get("blocked_by", [])
        else:
            raw = self.metadata.get(field, [])
        return [str(item) for item in raw] if isinstance(raw, list) else []

    def dependencies_through(self, phase: str) -> list[str]:
        result: list[str] = []
        for current in DEPENDENCY_FIELDS:
            for dependency in self.dependencies(current):
                if dependency not in result:
                    result.append(dependency)
            if current == phase:
                break
        return result

    @property
    def implementation_blockers(self) -> list[str]:
        return self.dependencies("implementation")

    @property
    def review_blockers(self) -> list[str]:
        return self.dependencies("review")

    @property
    def integration_blockers(self) -> list[str]:
        return self.dependencies("integration")

    @property
    def release_blockers(self) -> list[str]:
        return self.dependencies("release")

    @property
    def all_blockers(self) -> list[str]:
        result: list[str] = []
        for phase in DEPENDENCY_FIELDS:
            for blocker in self.dependencies(phase):
                if blocker not in result:
                    result.append(blocker)
        return result

    @property
    def risk(self) -> str:
        return str(self.metadata.get("risk", "high")).lower()

    @property
    def required_reviews(self) -> list[str]:
        raw = self.metadata.get("required_reviews")
        if isinstance(raw, list):
            return [str(item) for item in raw]
        if self.risk in {"high", "critical"}:
            return ["architect", "qa"]
        if self.risk == "medium":
            return ["qa"]
        return []

    @property
    def blocker_record(self) -> dict[str, Any]:
        raw = self.metadata.get("blocker", {})
        return dict(raw) if isinstance(raw, dict) else {}

    @property
    def owns(self) -> list[str]:
        return [str(item) for item in self.metadata.get("owns", [])]

    @property
    def spec(self) -> str:
        return str(self.metadata.get("spec", ""))

    @property
    def test_plan(self) -> str:
        return str(self.metadata.get("test_plan", ""))


class WorkflowError(RuntimeError):
    pass


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        list(args),
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture,
        check=False,
    )
    if check and proc.returncode != 0:
        command = " ".join(args)
        detail = (proc.stderr or proc.stdout or "").strip()
        raise WorkflowError(f"Command failed ({proc.returncode}): {command}\n{detail}")
    return proc


def git_root(start: Path | None = None) -> Path:
    start = (start or Path.cwd()).resolve()
    proc = run(["git", "rev-parse", "--show-toplevel"], cwd=start, check=False)
    if proc.returncode != 0:
        raise WorkflowError(f"Not inside a Git worktree: {start}")
    return Path(proc.stdout.strip()).resolve()


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in base.items():
        result[key] = deep_merge(value, {}) if isinstance(value, dict) else value
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(root: Path) -> dict[str, Any]:
    path = root / "workflow.toml"
    if not path.exists():
        return deep_merge(DEFAULT_CONFIG, {})
    try:
        with path.open("rb") as handle:
            user = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise WorkflowError(f"Cannot parse {path}: {exc}") from exc
    cfg = deep_merge(DEFAULT_CONFIG, user)
    if cfg.get("version") != 1:
        raise WorkflowError(f"Unsupported workflow.toml version: {cfg.get('version')!r}")
    return cfg


def git_common_dir(root: Path) -> Path:
    proc = run(["git", "rev-parse", "--git-common-dir"], cwd=root)
    configured = Path(proc.stdout.strip())
    return (configured if configured.is_absolute() else root / configured).resolve()


def runtime_state_path(root: Path, cfg: dict[str, Any]) -> Path:
    raw = str(cfg.get("state", {}).get("path", "")).strip()
    if not raw:
        raise WorkflowError("state.path must not be empty")
    configured = Path(raw)
    common = git_common_dir(root)
    path = configured if configured.is_absolute() else common / configured
    resolved = path.resolve()
    try:
        resolved.relative_to(common)
    except ValueError as exc:
        raise WorkflowError(f"state.path must stay inside the Git common dir: {path}") from exc
    return resolved


def empty_runtime_state() -> dict[str, Any]:
    return {"version": RUNTIME_STATE_VERSION, "revision": 0, "milestones": {}}


def review_record_errors(
    prefix: str,
    round_name: str,
    record: object,
) -> list[str]:
    errors: list[str] = []
    if round_name not in REVIEW_ROUNDS or not isinstance(record, dict):
        return [prefix + " is invalid"]
    if record.get("round") != round_name:
        errors.append(prefix + ".round must match its key")
    if record.get("verdict") not in REVIEW_VERDICTS:
        errors.append(prefix + ".verdict is invalid")
    candidate_sha = record.get("candidate_sha", "")
    if not (
        isinstance(candidate_sha, str)
        and re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", candidate_sha)
    ):
        errors.append(prefix + ".candidate_sha must be exact")
    findings = record.get("findings", [])
    if not isinstance(findings, list):
        errors.append(prefix + ".findings must be an array")
        return errors
    seen_finding_ids: set[str] = set()
    for index, finding in enumerate(findings):
        finding_prefix = f"{prefix}.findings[{index}]"
        if not isinstance(finding, dict):
            errors.append(finding_prefix + " must be an object")
            continue
        finding_id = str(finding.get("id", "")).strip()
        if not finding_id or finding_id in seen_finding_ids:
            errors.append(finding_prefix + ".id must be non-empty and unique")
        seen_finding_ids.add(finding_id)
        if finding.get("severity") not in REVIEW_FINDING_SEVERITIES:
            errors.append(finding_prefix + ".severity is invalid")
        if not str(finding.get("summary", "")).strip():
            errors.append(finding_prefix + ".summary is required")
        if round_name == "targeted" and finding.get("new", False):
            if finding.get("origin") not in NEW_REVIEW_BLOCKER_ORIGINS:
                errors.append(finding_prefix + ".origin is invalid for a new finding")
    resolved = record.get("resolved", [])
    if (
        not isinstance(resolved, list)
        or any(not isinstance(item, str) or not item.strip() for item in resolved)
        or len(resolved) != len(set(resolved))
    ):
        errors.append(prefix + ".resolved must contain unique non-empty IDs")
    return errors


def root_cycle_round_invariant_errors(
    rounds: dict[str, Any],
    blocking_severities: set[str],
) -> list[str]:
    errors: list[str] = []
    full = rounds.get("full")
    if not isinstance(full, dict):
        return errors
    full_blocking = [
        finding
        for finding in full.get("findings", [])
        if isinstance(finding, dict)
        and finding.get("severity") in blocking_severities
    ]
    if full.get("verdict") == "block" and not full_blocking:
        errors.append("blocking full review requires a blocking finding")
    if full.get("verdict") in {"pass", "pass_with_notes"} and full_blocking:
        errors.append("passing full review cannot retain a blocking finding")

    targeted = rounds.get("targeted")
    if not isinstance(targeted, dict):
        return errors
    targeted_findings = [
        finding
        for finding in targeted.get("findings", [])
        if isinstance(finding, dict)
    ]
    targeted_blocking = [
        finding
        for finding in targeted_findings
        if finding.get("severity") in blocking_severities
    ]
    if targeted.get("verdict") == "escalate" and not targeted_blocking:
        errors.append("targeted escalation requires a blocking finding")
    if (
        targeted.get("verdict") in {"pass", "pass_with_notes"}
        and targeted_blocking
    ):
        errors.append("passing targeted review cannot retain a blocking finding")
    resolved = targeted.get("resolved", [])
    finding_ids = {
        str(finding.get("id", ""))
        for finding in targeted_findings
        if str(finding.get("id", "")).strip()
    }
    if isinstance(resolved, list) and finding_ids.intersection(resolved):
        errors.append("targeted findings and resolved IDs cannot overlap")
    return errors


def runtime_state_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    milestones = payload.get("milestones", {})
    if not isinstance(milestones, dict):
        return ["milestones must be an object"]
    for milestone, runtime in milestones.items():
        if not isinstance(runtime, dict):
            errors.append(f"{milestone} must be an object")
            continue
        authorizations = runtime.get("authorizations", {})
        if not isinstance(authorizations, dict):
            errors.append(f"{milestone}.authorizations must be an object")
        else:
            for scope, record in authorizations.items():
                if not isinstance(record, dict):
                    errors.append(f"{milestone}.authorizations.{scope} must be an object")
                    continue
                if record.get("status") not in {"granted", "revoked"}:
                    errors.append(
                        f"{milestone}.authorizations.{scope}.status must be granted or revoked"
                    )
                kind = record.get("kind")
                if kind not in {"local", "remote"}:
                    errors.append(
                        f"{milestone}.authorizations.{scope}.kind must be local or remote"
                    )
                if not isinstance(record.get("actions"), list) or not record.get("actions"):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.actions must be non-empty"
                    )
                if not isinstance(record.get("tickets"), list) or not record.get("tickets"):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.tickets must be non-empty"
                    )
                classes = record.get("blocker_classes")
                if not isinstance(classes, list) or not classes or any(
                    item not in BLOCKER_CLASSES - {"none"} for item in classes
                ):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.blocker_classes must be "
                        "non-empty and valid"
                    )
                if record.get("max_risk") not in RISK_LEVELS:
                    errors.append(
                        f"{milestone}.authorizations.{scope}.max_risk is invalid"
                    )
                if not isinstance(record.get("remote_effects"), bool):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.remote_effects must be boolean"
                    )
                elif (kind == "remote") != bool(record.get("remote_effects")):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.kind and remote_effects "
                        "must agree"
                    )
                uses = record.get("uses", 0)
                max_uses = record.get("max_uses")
                if isinstance(uses, bool) or not isinstance(uses, int) or uses < 0:
                    errors.append(
                        f"{milestone}.authorizations.{scope}.uses must be a "
                        "non-negative integer"
                    )
                if max_uses is not None and (
                    isinstance(max_uses, bool)
                    or not isinstance(max_uses, int)
                    or max_uses < 1
                ):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.max_uses must be "
                        "an integer >= 1 when present"
                    )
                elif (
                    isinstance(uses, int)
                    and isinstance(max_uses, int)
                    and uses > max_uses
                ):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.uses exceeds max_uses"
                    )
                if kind == "remote":
                    if not str(record.get("remote_ref", "")).strip():
                        errors.append(
                            f"{milestone}.authorizations.{scope}.remote_ref is "
                            "required for remote authorization"
                        )
                    commit_sha = record.get("commit_sha")
                    if not (
                        isinstance(commit_sha, str)
                        and re.fullmatch(
                            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
                            commit_sha,
                        )
                    ):
                        errors.append(
                            f"{milestone}.authorizations.{scope}.commit_sha must be "
                            "an exact commit ID for remote authorization"
                        )
                    if max_uses is None:
                        errors.append(
                            f"{milestone}.authorizations.{scope}.max_uses must be "
                            "an integer >= 1 for remote authorization"
                        )
                elif str(record.get("remote_ref", "")).strip() or str(
                    record.get("commit_sha", "")
                ).strip():
                    errors.append(
                        f"{milestone}.authorizations.{scope} local scope must not "
                        "contain remote_ref or commit_sha"
                    )

        blockers = runtime.get("blockers", {})
        if not isinstance(blockers, dict):
            errors.append(f"{milestone}.blockers must be an object")
            blockers = {}
        for blocker_id, record in blockers.items():
            if not isinstance(record, dict):
                errors.append(f"{milestone}.blockers.{blocker_id} must be an object")
                continue
            if record.get("id") != blocker_id:
                errors.append(f"{milestone}.blockers.{blocker_id}.id must match its key")
            if record.get("class") not in BLOCKER_CLASSES - {"none"}:
                errors.append(f"{milestone}.blockers.{blocker_id}.class is invalid")
            if record.get("phase") not in DEPENDENCY_FIELDS:
                errors.append(f"{milestone}.blockers.{blocker_id}.phase is invalid")
            if record.get("risk") not in RISK_LEVELS:
                errors.append(f"{milestone}.blockers.{blocker_id}.risk is invalid")
            if record.get("authorization", "not_required") not in AUTHORIZATION_STATES:
                errors.append(
                    f"{milestone}.blockers.{blocker_id}.authorization is invalid"
                )
            if record.get("status", "open") not in {
                "open",
                "resolved",
                "superseded",
            }:
                errors.append(f"{milestone}.blockers.{blocker_id}.status is invalid")
            if not str(record.get("ticket_id", "")).strip():
                errors.append(f"{milestone}.blockers.{blocker_id}.ticket_id is required")
            if not str(record.get("root_cause", "")).strip():
                errors.append(f"{milestone}.blockers.{blocker_id}.root_cause is required")
            derived_from = record.get("derived_from")
            root_cause_id = record.get("root_cause_id")
            if derived_from:
                root = blockers.get(derived_from)
                if not isinstance(root, dict) or root.get("derived_from"):
                    errors.append(
                        f"{milestone}.blockers.{blocker_id}.derived_from must name a root"
                    )
                if root_cause_id != derived_from:
                    errors.append(
                        f"{milestone}.blockers.{blocker_id}.root_cause_id must equal "
                        "derived_from"
                    )
            elif root_cause_id != blocker_id:
                errors.append(
                    f"{milestone}.blockers.{blocker_id}.root_cause_id must equal its id"
                )

        if isinstance(authorizations, dict):
            for scope, authorization in authorizations.items():
                if not isinstance(authorization, dict):
                    continue
                bound_root = str(
                    authorization.get("root_cause_id", "")
                ).strip()
                bound_reviewer = str(authorization.get("reviewer", "")).strip()
                if bool(bound_root) != bool(bound_reviewer):
                    errors.append(
                        f"{milestone}.authorizations.{scope} root_cause_id and "
                        "reviewer must be provided together"
                    )
                    continue
                if not bound_root:
                    continue
                root = blockers.get(bound_root)
                if (
                    authorization.get("kind") != "local"
                    or authorization.get("actions") != ["review_round_override"]
                    or authorization.get("max_uses") != 1
                ):
                    errors.append(
                        f"{milestone}.authorizations.{scope} bound review scope "
                        "must be local, single-use, and review_round_override-only"
                    )
                if bound_reviewer not in REVIEWERS:
                    errors.append(
                        f"{milestone}.authorizations.{scope}.reviewer is invalid"
                    )
                if (
                    not isinstance(root, dict)
                    or root.get("derived_from")
                    or str(root.get("root_cause_id", "")) != bound_root
                ):
                    errors.append(
                        f"{milestone}.authorizations.{scope}.root_cause_id must "
                        "name a canonical root"
                    )
                    continue
                expected_ticket = str(root.get("ticket_id", "")).upper()
                if authorization.get("tickets") != [expected_ticket]:
                    errors.append(
                        f"{milestone}.authorizations.{scope}.tickets must contain "
                        "only the canonical root ticket"
                    )
                root_class = str(root.get("class", ""))
                root_risk = str(root.get("risk", ""))
                max_risk = str(authorization.get("max_risk", ""))
                if root_class not in authorization.get("blocker_classes", []) or (
                    root_risk in RISK_ORDER
                    and max_risk in RISK_ORDER
                    and RISK_ORDER[max_risk] < RISK_ORDER[root_risk]
                ):
                    errors.append(
                        f"{milestone}.authorizations.{scope} class/risk must "
                        "cover its bound canonical root"
                    )

        repairs = runtime.get("repairs", {})
        if not isinstance(repairs, dict):
            errors.append(f"{milestone}.repairs must be an object")
        else:
            for ticket_id, entries in repairs.items():
                if not isinstance(entries, list):
                    errors.append(f"{milestone}.repairs.{ticket_id} must be an array")
                    continue
                for index, entry in enumerate(entries):
                    if not isinstance(entry, dict) or entry.get("class") not in REPAIR_CLASSES:
                        errors.append(
                            f"{milestone}.repairs.{ticket_id}[{index}] is invalid"
                        )
                        continue
                    if "consumes_budget" in entry and not isinstance(
                        entry.get("consumes_budget"),
                        bool,
                    ):
                        errors.append(
                            f"{milestone}.repairs.{ticket_id}[{index}]."
                            "consumes_budget must be boolean"
                        )
                    root_cause_id = entry.get("root_cause_id")
                    root = blockers.get(root_cause_id)
                    if (
                        not isinstance(root_cause_id, str)
                        or not isinstance(root, dict)
                        or root.get("derived_from")
                    ):
                        errors.append(
                            f"{milestone}.repairs.{ticket_id}[{index}].root_cause_id "
                            "must name a canonical root blocker"
                        )
                        continue
                    if str(root.get("ticket_id", "")).upper() != str(ticket_id).upper():
                        errors.append(
                            f"{milestone}.repairs.{ticket_id}[{index}] must reference "
                            "a root owned by the same ticket"
                        )
                    for field, action in (
                        ("repair_authorization_scope", "local_repair"),
                        (
                            "budget_override_authorization_scope",
                            "repair_budget_override",
                        ),
                    ):
                        scope = str(entry.get(field, "")).strip()
                        if not scope:
                            continue
                        authorization = (
                            authorizations.get(scope)
                            if isinstance(authorizations, dict)
                            else None
                        )
                        if not isinstance(
                            authorization,
                            dict,
                        ) or not authorization_record_covers(
                            authorization,
                            action=action,
                            ticket_id=str(root.get("ticket_id", "")),
                            blocker_class=str(root.get("class", "")),
                            risk=str(root.get("risk", "")),
                            remote_effects=False,
                            require_available=False,
                        ):
                            errors.append(
                                f"{milestone}.repairs.{ticket_id}[{index}].{field} "
                                f"does not cover canonical root {root_cause_id}"
                            )
        repair_overrides = runtime.get("repair_overrides", {})
        if not isinstance(repair_overrides, dict):
            errors.append(f"{milestone}.repair_overrides must be an object")
        else:
            override_scope_counts: collections.Counter[str] = collections.Counter()
            for root_cause_id, entries in repair_overrides.items():
                root = blockers.get(root_cause_id)
                if not isinstance(root, dict) or root.get("derived_from"):
                    errors.append(
                        f"{milestone}.repair_overrides.{root_cause_id} must name "
                        "a canonical root blocker"
                    )
                if not isinstance(entries, list):
                    errors.append(
                        f"{milestone}.repair_overrides.{root_cause_id} must be an array"
                    )
                    continue
                for index, entry in enumerate(entries):
                    if (
                        not isinstance(entry, dict)
                        or not str(entry.get("authorization_scope", "")).strip()
                    ):
                        errors.append(
                            f"{milestone}.repair_overrides.{root_cause_id}[{index}] "
                            "must name an authorization scope"
                        )
                        continue
                    scope = str(entry["authorization_scope"])
                    override_scope_counts[scope] += 1
                    authorization = (
                        authorizations.get(scope)
                        if isinstance(authorizations, dict)
                        else None
                    )
                    if (
                        not isinstance(authorization, dict)
                        or authorization.get("kind") != "local"
                        or "repair_budget_override"
                        not in authorization.get("actions", [])
                    ):
                        errors.append(
                            f"{milestone}.repair_overrides.{root_cause_id}[{index}] "
                            "must reference a local repair_budget_override scope"
                        )
                    elif isinstance(root, dict) and not authorization_record_covers(
                        authorization,
                        action="repair_budget_override",
                        ticket_id=str(root.get("ticket_id", "")),
                        blocker_class=str(root.get("class", "")),
                        risk=str(root.get("risk", "")),
                        remote_effects=False,
                        require_available=False,
                    ):
                        errors.append(
                            f"{milestone}.repair_overrides.{root_cause_id}[{index}] "
                            f"authorization {scope} does not cover that root"
                        )
            for scope, count in override_scope_counts.items():
                authorization = (
                    authorizations.get(scope)
                    if isinstance(authorizations, dict)
                    else None
                )
                uses = (
                    authorization.get("uses", 0)
                    if isinstance(authorization, dict)
                    else 0
                )
                if not isinstance(uses, int) or uses < count:
                    errors.append(
                        f"{milestone}.repair_overrides references {scope} {count} "
                        f"times but authorization uses is {uses!r}"
                    )
        reviews = runtime.get("reviews", {})
        if not isinstance(reviews, dict):
            errors.append(f"{milestone}.reviews must be an object")
        else:
            superseding_scope_counts: collections.Counter[str] = collections.Counter()
            for ticket_id, ticket_reviews in reviews.items():
                if not isinstance(ticket_reviews, dict):
                    errors.append(f"{milestone}.reviews.{ticket_id} must be an object")
                    continue
                reviewers = ticket_reviews.get("reviewers", {})
                if not isinstance(reviewers, dict):
                    errors.append(
                        f"{milestone}.reviews.{ticket_id}.reviewers must be an object"
                    )
                    continue
                for reviewer, rounds in reviewers.items():
                    if reviewer not in REVIEWERS:
                        errors.append(
                            f"{milestone}.reviews.{ticket_id}.{reviewer} is not a valid reviewer"
                        )
                        continue
                    if not isinstance(rounds, dict):
                        errors.append(
                            f"{milestone}.reviews.{ticket_id}.{reviewer} must be an object"
                        )
                        continue
                    for round_name, record in rounds.items():
                        if round_name not in REVIEW_ROUNDS or not isinstance(record, dict):
                            errors.append(
                                f"{milestone}.reviews.{ticket_id}.{reviewer}.{round_name} "
                                "is invalid"
                            )
                            continue
                        if record.get("verdict") not in REVIEW_VERDICTS:
                            errors.append(
                                f"{milestone}.reviews.{ticket_id}.{reviewer}.{round_name}."
                                "verdict is invalid"
                            )
                        candidate_sha = record.get("candidate_sha", "")
                        if not (
                            isinstance(candidate_sha, str)
                            and re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", candidate_sha)
                        ):
                            errors.append(
                                f"{milestone}.reviews.{ticket_id}.{reviewer}.{round_name}."
                                "candidate_sha must be exact"
                            )
                        findings = record.get("findings", [])
                        if not isinstance(findings, list):
                            errors.append(
                                f"{milestone}.reviews.{ticket_id}.{reviewer}.{round_name}."
                                "findings must be an array"
                            )
                            continue
                        seen_finding_ids: set[str] = set()
                        for index, finding in enumerate(findings):
                            prefix = (
                                f"{milestone}.reviews.{ticket_id}.{reviewer}."
                                f"{round_name}.findings[{index}]"
                            )
                            if not isinstance(finding, dict):
                                errors.append(prefix + " must be an object")
                                continue
                            finding_id = str(finding.get("id", "")).strip()
                            if not finding_id or finding_id in seen_finding_ids:
                                errors.append(prefix + ".id must be non-empty and unique")
                            seen_finding_ids.add(finding_id)
                            if finding.get("severity") not in REVIEW_FINDING_SEVERITIES:
                                errors.append(prefix + ".severity is invalid")
                            if not str(finding.get("summary", "")).strip():
                                errors.append(prefix + ".summary is required")
                            origin = finding.get("origin")
                            if round_name == "targeted" and finding.get("new", False):
                                if origin not in NEW_REVIEW_BLOCKER_ORIGINS:
                                    errors.append(prefix + ".origin is invalid for a new finding")
                    superseding = rounds.get("superseding")
                    if not isinstance(superseding, dict):
                        continue
                    authorization_scope = str(
                        superseding.get("authorization_scope", "")
                    ).strip()
                    findings = superseding.get("findings", [])
                    resolved = superseding.get("resolved", [])
                    try:
                        expected_findings, _, _ = validate_superseding_review(
                            runtime=runtime,
                            ticket_id=str(ticket_id),
                            reviewer_rounds=rounds,
                            candidate_sha=str(
                                superseding.get("candidate_sha", "")
                            ).lower(),
                            verdict=str(superseding.get("verdict", "")),
                            findings=findings if isinstance(findings, list) else [],
                            new_findings=[],
                            resolved=resolved if isinstance(resolved, list) else [],
                            root_cause_id=str(
                                superseding.get("root_cause_id", "")
                            ).strip(),
                            authorization_scope=authorization_scope,
                            blocking_severities=BLOCKING_REVIEW_SEVERITIES,
                            supersedes=superseding.get("supersedes"),
                            require_available=False,
                        )
                        if expected_findings != findings:
                            raise WorkflowError(
                                "Superseding findings do not match unresolved targeted IDs"
                            )
                    except WorkflowError as exc:
                        errors.append(
                            f"{milestone}.reviews.{ticket_id}.{reviewer}."
                            f"superseding is invalid: {exc}"
                        )
                    else:
                        superseding_scope_counts[authorization_scope] += 1
                root_cycles = ticket_reviews.get("root_cycles", [])
                if not isinstance(root_cycles, list):
                    errors.append(
                        f"{milestone}.reviews.{ticket_id}.root_cycles must be an array"
                    )
                    continue
                seen_roots: set[str] = set()
                for cycle_index, cycle in enumerate(root_cycles):
                    cycle_prefix = (
                        f"{milestone}.reviews.{ticket_id}.root_cycles[{cycle_index}]"
                    )
                    if not isinstance(cycle, dict):
                        errors.append(cycle_prefix + " must be an object")
                        continue
                    root_cause_id = str(cycle.get("root_cause_id", "")).strip()
                    if not root_cause_id or root_cause_id in seen_roots:
                        errors.append(
                            cycle_prefix
                            + ".root_cause_id must be non-empty and append-only unique"
                        )
                    seen_roots.add(root_cause_id)
                    if str(cycle.get("ticket_id", "")).upper() != str(
                        ticket_id
                    ).upper():
                        errors.append(
                            cycle_prefix + ".ticket_id must match its ticket key"
                        )
                    try:
                        canonical_review_root(
                            runtime,
                            str(ticket_id),
                            root_cause_id,
                            require_open=False,
                        )
                    except WorkflowError as exc:
                        errors.append(cycle_prefix + f" is invalid: {exc}")
                    cycle_reviewers = cycle.get("reviewers", {})
                    if not isinstance(cycle_reviewers, dict):
                        errors.append(cycle_prefix + ".reviewers must be an object")
                        continue
                    for reviewer, rounds in cycle_reviewers.items():
                        reviewer_prefix = cycle_prefix + f".reviewers.{reviewer}"
                        if reviewer not in REVIEWERS:
                            errors.append(reviewer_prefix + " is not a valid reviewer")
                            continue
                        if not isinstance(rounds, dict):
                            errors.append(reviewer_prefix + " must be an object")
                            continue
                        for round_name, record in rounds.items():
                            errors.extend(
                                review_record_errors(
                                    reviewer_prefix + f".{round_name}",
                                    round_name,
                                    record,
                                )
                            )
                            if isinstance(record, dict) and record.get(
                                "reviewer"
                            ) != reviewer:
                                errors.append(
                                    reviewer_prefix
                                    + f".{round_name}.reviewer must match its key"
                                )
                        full = rounds.get("full")
                        targeted = rounds.get("targeted")
                        if not isinstance(full, dict):
                            errors.append(reviewer_prefix + " requires a full review")
                            continue
                        errors.extend(
                            reviewer_prefix + ": " + error
                            for error in root_cycle_round_invariant_errors(
                                rounds,
                                BLOCKING_REVIEW_SEVERITIES,
                            )
                        )
                        if full.get("verdict") not in {
                            "pass",
                            "pass_with_notes",
                            "block",
                        }:
                            errors.append(
                                reviewer_prefix
                                + ".full verdict must be pass, pass_with_notes, or block"
                            )
                        if isinstance(targeted, dict):
                            if full.get("verdict") != "block":
                                errors.append(
                                    reviewer_prefix
                                    + ".targeted requires a blocking full review"
                                )
                            if targeted.get("verdict") not in {
                                "pass",
                                "pass_with_notes",
                                "escalate",
                            }:
                                errors.append(
                                    reviewer_prefix
                                    + ".targeted verdict must be pass, "
                                    "pass_with_notes, or escalate"
                                )
                            if targeted.get("candidate_sha") == full.get(
                                "candidate_sha"
                            ):
                                errors.append(
                                    reviewer_prefix
                                    + ".targeted candidate must differ from full"
                                )
                            full_blocking = {
                                str(item.get("id")): item
                                for item in full.get("findings", [])
                                if isinstance(item, dict)
                                and item.get("severity")
                                in BLOCKING_REVIEW_SEVERITIES
                            }
                            resolved = targeted.get("resolved", [])
                            resolved_ids = (
                                set(resolved) if isinstance(resolved, list) else set()
                            )
                            if not resolved_ids.issubset(full_blocking):
                                errors.append(
                                    reviewer_prefix
                                    + ".targeted resolved IDs must come from full"
                                )
                            targeted_findings = targeted.get("findings", [])
                            targeted_ids: set[str] = set()
                            if isinstance(targeted_findings, list):
                                for finding in targeted_findings:
                                    if not isinstance(finding, dict):
                                        continue
                                    finding_id = str(finding.get("id", ""))
                                    targeted_ids.add(finding_id)
                                    original = full_blocking.get(finding_id)
                                    if finding.get("new", False):
                                        if (
                                            original is not None
                                            or finding.get("origin")
                                            != "introduced_by_repair"
                                        ):
                                            errors.append(
                                                reviewer_prefix
                                                + ".targeted new findings must be "
                                                "introduced_by_repair with a new ID"
                                            )
                                    elif (
                                        not isinstance(original, dict)
                                        or finding.get("severity")
                                        != original.get("severity")
                                        or finding.get("origin")
                                        != original.get("origin")
                                    ):
                                        errors.append(
                                            reviewer_prefix
                                            + ".targeted prior findings must preserve "
                                            "their ID, severity, and provenance"
                                        )
                            expected_retained = set(full_blocking) - resolved_ids
                            if not expected_retained.issubset(targeted_ids):
                                errors.append(
                                    reviewer_prefix
                                    + ".targeted must retain every unresolved "
                                    "full-review blocker"
                                )
                        superseding = rounds.get("superseding")
                        if not isinstance(superseding, dict):
                            continue
                        authorization_scope = str(
                            superseding.get("authorization_scope", "")
                        ).strip()
                        findings = superseding.get("findings", [])
                        resolved = superseding.get("resolved", [])
                        try:
                            expected_findings, _, _ = validate_superseding_review(
                                runtime=runtime,
                                ticket_id=str(ticket_id),
                                reviewer=reviewer,
                                reviewer_rounds=rounds,
                                candidate_sha=str(
                                    superseding.get("candidate_sha", "")
                                ).lower(),
                                verdict=str(superseding.get("verdict", "")),
                                findings=findings if isinstance(findings, list) else [],
                                new_findings=[],
                                resolved=resolved if isinstance(resolved, list) else [],
                                root_cause_id=root_cause_id,
                                authorization_scope=authorization_scope,
                                blocking_severities=BLOCKING_REVIEW_SEVERITIES,
                                supersedes=superseding.get("supersedes"),
                                require_available=False,
                                root_cycle=True,
                            )
                            if expected_findings != findings:
                                raise WorkflowError(
                                    "Superseding findings do not match frozen "
                                    "root-cycle blocking IDs"
                                )
                        except WorkflowError as exc:
                            errors.append(
                                reviewer_prefix + f".superseding is invalid: {exc}"
                            )
                        else:
                            superseding_scope_counts[authorization_scope] += 1
            for scope, count in superseding_scope_counts.items():
                authorization = (
                    authorizations.get(scope)
                    if isinstance(authorizations, dict)
                    else None
                )
                uses = (
                    authorization.get("uses", 0)
                    if isinstance(authorization, dict)
                    else 0
                )
                if not isinstance(uses, int) or uses < count:
                    errors.append(
                        f"{milestone}.reviews superseding records reference {scope} "
                        f"{count} times but authorization uses is {uses!r}"
                    )

        phases = runtime.get("phases", {})
        if not isinstance(phases, dict):
            errors.append(f"{milestone}.phases must be an object")
        else:
            for ticket_id, record in phases.items():
                if not isinstance(record, dict):
                    errors.append(f"{milestone}.phases.{ticket_id} must be an object")
                    continue
                if record.get("phase") not in TRANSIENT_PHASES:
                    errors.append(f"{milestone}.phases.{ticket_id}.phase is invalid")
                if record.get("ticket_id") != ticket_id:
                    errors.append(
                        f"{milestone}.phases.{ticket_id}.ticket_id must match its key"
                    )
                phase = record.get("phase")
                candidate_sha = record.get("candidate_sha", "")
                if phase in {"review", "integration", "release"} and not (
                    isinstance(candidate_sha, str)
                    and re.fullmatch(
                        r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
                        candidate_sha,
                    )
                ):
                    errors.append(
                        f"{milestone}.phases.{ticket_id}.candidate_sha must be an "
                        "exact commit ID for review/integration/release"
                    )
                if record.get("phase") == "repair":
                    root_cause_id = record.get("root_cause_id")
                    root = blockers.get(root_cause_id)
                    if (
                        not isinstance(root_cause_id, str)
                        or not isinstance(root, dict)
                        or root.get("derived_from")
                    ):
                        errors.append(
                            f"{milestone}.phases.{ticket_id}.root_cause_id must name "
                            "a canonical root blocker during repair"
                        )
    return errors


def load_runtime_state(root: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    path = runtime_state_path(root, cfg)
    if not path.exists():
        return empty_runtime_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"Cannot parse runtime state {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != RUNTIME_STATE_VERSION:
        raise WorkflowError(
            f"Unsupported runtime state version in {path}: "
            f"{payload.get('version') if isinstance(payload, dict) else None!r}"
        )
    if not isinstance(payload.get("milestones"), dict):
        raise WorkflowError(f"Runtime state {path} must contain a milestones object")
    if (
        isinstance(payload.get("revision"), bool)
        or not isinstance(payload.get("revision"), int)
        or payload["revision"] < 0
    ):
        raise WorkflowError(f"Runtime state {path} must contain a non-negative revision")
    errors = runtime_state_errors(payload)
    if errors:
        raise WorkflowError(
            f"Invalid runtime state {path}: " + "; ".join(errors)
        )
    return payload


def acquire_runtime_state_lock(lock_path: Path) -> Any:
    """Acquire a process-owned, crash-released lock on a persistent lock file."""

    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise WorkflowError(
            f"Runtime state is locked by another writer: {lock_path}"
        ) from exc

    try:
        metadata = (
            json.dumps(
                {"pid": os.getpid(), "acquired_at": utc_now()},
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        handle.seek(0)
        handle.write(metadata)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
    except Exception:
        release_runtime_state_lock(handle)
        raise
    return handle


def release_runtime_state_lock(handle: Any) -> None:
    """Release a lock acquired by acquire_runtime_state_lock."""

    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def save_runtime_state(root: Path, cfg: dict[str, Any], state: dict[str, Any]) -> Path:
    path = runtime_state_path(root, cfg)
    errors = runtime_state_errors(state)
    if errors:
        raise WorkflowError("Refusing invalid runtime state: " + "; ".join(errors))
    path.parent.mkdir(parents=True, exist_ok=True)
    expected_revision = int(state.get("revision", 0))
    lock_path = path.with_name(path.name + ".lock")
    lock_handle: Any | None = None
    temporary: Path | None = None
    try:
        lock_handle = acquire_runtime_state_lock(lock_path)

        if path.exists():
            try:
                current = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise WorkflowError(f"Cannot parse runtime state {path}: {exc}") from exc
            actual_revision = current.get("revision")
            if actual_revision != expected_revision:
                raise WorkflowError(
                    f"Runtime state revision changed concurrently: expected "
                    f"{expected_revision}, found {actual_revision}"
                )
        elif expected_revision != 0:
            raise WorkflowError(
                f"Runtime state disappeared concurrently at revision "
                f"{expected_revision}"
            )

        next_revision = expected_revision + 1
        serialized = dict(state)
        serialized["revision"] = next_revision
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=path.name + ".",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(serialized, indent=2, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        state["revision"] = next_revision
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                eprint(f"warning: could not remove runtime-state temporary: {exc}")
        if lock_handle is not None:
            try:
                release_runtime_state_lock(lock_handle)
            except OSError as exc:
                eprint(f"warning: could not release runtime-state lock {lock_path}: {exc}")
    return path


def milestone_runtime_state(state: dict[str, Any], milestone: str) -> dict[str, Any]:
    milestones = state.setdefault("milestones", {})
    normalized = milestone.strip().upper()
    current = milestones.setdefault(
        normalized,
        {
            "authorizations": {},
            "blockers": {},
            "repairs": {},
            "repair_overrides": {},
            "reviews": {},
            "phases": {},
            "last_checkpoint": {},
        },
    )
    for key in (
        "authorizations",
        "blockers",
        "repairs",
        "repair_overrides",
        "reviews",
        "phases",
        "last_checkpoint",
    ):
        if key not in current:
            current[key] = {}
        elif not isinstance(current.get(key), dict):
            raise WorkflowError(f"Runtime state {normalized}.{key} must be an object")
    return current


def runtime_blocker_for_ticket(
    runtime: dict[str, Any], ticket_id: str
) -> dict[str, Any]:
    records = runtime.get("blockers", {})
    if not isinstance(records, dict):
        return {}
    matching = [
        record
        for record in records.values()
        if isinstance(record, dict)
        and str(record.get("ticket_id", "")).upper() == ticket_id.upper()
        and record.get("status", "open") == "open"
        and isinstance(
            records.get(str(record.get("derived_from") or record.get("id"))),
            dict,
        )
        and records[
            str(record.get("derived_from") or record.get("id"))
        ].get("status", "open")
        == "open"
    ]
    roots = [record for record in matching if not record.get("derived_from")]
    return dict((roots or matching)[0]) if (roots or matching) else {}


def open_root_blocker_ids_for_ticket(
    runtime: dict[str, Any],
    ticket_id: str,
    through_phase: str | None = None,
) -> list[str]:
    """Return effective open canonical roots relevant to one ticket and gate."""

    records = runtime.get("blockers", {})
    if not isinstance(records, dict):
        return []
    maximum = (
        DEPENDENCY_PHASE_ORDER[through_phase]
        if through_phase is not None
        else max(DEPENDENCY_PHASE_ORDER.values())
    )
    roots: list[str] = []
    for record in records.values():
        if (
            not isinstance(record, dict)
            or str(record.get("ticket_id", "")).upper() != ticket_id.upper()
            or record.get("status", "open") != "open"
        ):
            continue
        phase = str(record.get("phase", ""))
        if phase not in DEPENDENCY_PHASE_ORDER:
            continue
        if DEPENDENCY_PHASE_ORDER[phase] > maximum:
            continue
        root_id = str(record.get("derived_from") or record.get("id", ""))
        root = records.get(root_id)
        if (
            not root_id
            or not isinstance(root, dict)
            or root.get("derived_from")
            or root.get("status", "open") != "open"
        ):
            continue
        if root_id not in roots:
            roots.append(root_id)
    return roots


def open_canonical_root_blocker_ids(runtime: dict[str, Any]) -> list[str]:
    records = runtime.get("blockers", {})
    if not isinstance(records, dict):
        return []
    return sorted(
        blocker_id
        for blocker_id, record in records.items()
        if isinstance(record, dict)
        and not record.get("derived_from")
        and record.get("status", "open") == "open"
    )


def ticket_phase(
    ticket: Ticket, runtime: dict[str, Any] | None
) -> tuple[str, str, dict[str, Any]] | None:
    phases = runtime.get("phases", {}) if isinstance(runtime, dict) else {}
    record = phases.get(ticket.id) if isinstance(phases, dict) else None
    if isinstance(record, dict) and record.get("phase") in TRANSIENT_PHASES:
        return str(record["phase"]), "runtime", dict(record)
    legacy = LEGACY_STATUS_PHASES.get(ticket.status)
    if legacy:
        return legacy, "legacy_ticket_status", {}
    return None


def active_ticket_phases(
    tickets: Sequence[Ticket],
    runtime: dict[str, Any] | None,
    milestone: str | None = None,
) -> list[tuple[Ticket, str, str, dict[str, Any]]]:
    active: list[tuple[Ticket, str, str, dict[str, Any]]] = []
    for ticket in tickets:
        if milestone and ticket.milestone.upper() != milestone.upper():
            continue
        phase = ticket_phase(ticket, runtime)
        if phase:
            active.append((ticket, *phase))
    return active


def authorization_record_covers(
    record: dict[str, Any],
    *,
    action: str,
    ticket_id: str,
    blocker_class: str,
    risk: str,
    remote_effects: bool,
    remote_ref: str = "",
    commit_sha: str = "",
    require_available: bool = True,
) -> bool:
    if require_available and record.get("status") != "granted":
        return False
    expected_kind = "remote" if remote_effects else "local"
    actions = record.get("actions", [])
    tickets = [str(item).upper() for item in record.get("tickets", [])]
    classes = record.get("blocker_classes", [])
    maximum = str(record.get("max_risk", "low"))
    if record.get("kind") != expected_kind:
        return False
    if not isinstance(actions, list) or action not in actions:
        return False
    if not tickets or ticket_id.upper() not in tickets:
        return False
    if not isinstance(classes, list) or blocker_class not in classes:
        return False
    if RISK_ORDER.get(risk, 99) > RISK_ORDER.get(maximum, -1):
        return False
    if bool(record.get("remote_effects", False)) != remote_effects:
        return False
    uses = record.get("uses", 0)
    max_uses = record.get("max_uses")
    if require_available and isinstance(max_uses, int) and (
        isinstance(uses, bool)
        or not isinstance(uses, int)
        or uses >= max_uses
    ):
        return False
    if remote_effects:
        if (
            not remote_ref
            or not commit_sha
            or record.get("remote_ref") != remote_ref
            or str(record.get("commit_sha", "")).lower() != commit_sha.lower()
        ):
            return False
        if require_available and (
            isinstance(uses, bool)
            or not isinstance(uses, int)
            or isinstance(max_uses, bool)
            or not isinstance(max_uses, int)
            or uses >= max_uses
        ):
            return False
    return True


def matching_authorization(
    runtime: dict[str, Any],
    *,
    action: str,
    ticket_id: str,
    blocker_class: str,
    risk: str,
    remote_effects: bool,
    remote_ref: str = "",
    commit_sha: str = "",
) -> tuple[str, dict[str, Any]] | None:
    authorizations = runtime.get("authorizations", {})
    if not isinstance(authorizations, dict):
        return None
    for scope, record in authorizations.items():
        if isinstance(record, dict) and authorization_record_covers(
            record,
            action=action,
            ticket_id=ticket_id,
            blocker_class=blocker_class,
            risk=risk,
            remote_effects=remote_effects,
            remote_ref=remote_ref,
            commit_sha=commit_sha,
        ):
            return str(scope), dict(record)
    return None


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def recorded_at(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def parse_frontmatter(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "+++":
        raise WorkflowError(f"{path} must start with TOML frontmatter delimiter +++")
    closing = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "+++":
            closing = index
            break
    if closing is None:
        raise WorkflowError(f"{path} has no closing TOML frontmatter delimiter +++")
    raw = "".join(lines[1:closing])
    try:
        metadata = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise WorkflowError(f"Invalid TOML frontmatter in {path}: {exc}") from exc
    body = "".join(lines[closing + 1 :])
    return metadata, body


def ticket_dir(root: Path, cfg: dict[str, Any]) -> Path:
    return root / str(cfg["documents"]["ticket_dir"])


def iter_ticket_paths(root: Path, cfg: dict[str, Any]) -> Iterable[Path]:
    directory = ticket_dir(root, cfg)
    if not directory.exists():
        return []
    result: list[Path] = []
    for path in sorted(directory.glob("*.md")):
        lower = path.name.lower()
        if lower == "readme.md" or "template" in lower:
            continue
        result.append(path)
    return result


def load_tickets(root: Path, cfg: dict[str, Any]) -> list[Ticket]:
    tickets: list[Ticket] = []
    for path in iter_ticket_paths(root, cfg):
        metadata, body = parse_frontmatter(path)
        tickets.append(Ticket(path=path, metadata=metadata, body=body))
    return tickets


def find_ticket(tickets: Sequence[Ticket], ticket_id: str) -> Ticket:
    normalized = ticket_id.strip().upper()
    for ticket in tickets:
        if ticket.id.upper() == normalized:
            return ticket
    raise WorkflowError(f"Unknown ticket ID: {ticket_id}")


def static_prefix(pattern: str) -> str:
    normalized = pattern.replace("\\", "/").lstrip("./")
    wildcard_positions = [
        pos for token in ("*", "?", "[") if (pos := normalized.find(token)) >= 0
    ]
    if wildcard_positions:
        normalized = normalized[: min(wildcard_positions)]
    normalized = normalized.rstrip("/")
    if not normalized:
        return ""
    # File-like exact paths still own their parent relationship against broader globs.
    return PurePosixPath(normalized).as_posix()


def ownership_overlaps(a: Sequence[str], b: Sequence[str]) -> bool:
    if not a or not b:
        return True
    for left in a:
        lp = static_prefix(left)
        for right in b:
            rp = static_prefix(right)
            if not lp or not rp:
                return True
            if lp == rp:
                return True
            if lp.startswith(rp + "/") or rp.startswith(lp + "/"):
                return True
    return False


def detect_cycles(
    tickets: Sequence[Ticket],
    through_phase: str = "integration",
) -> list[list[str]]:
    if through_phase not in DEPENDENCY_FIELDS:
        raise WorkflowError(f"Unknown dependency phase: {through_phase}")
    graph = {
        ticket.id: ticket.dependencies_through(through_phase)
        for ticket in tickets
    }
    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        marker = state.get(node, 0)
        if marker == 1:
            try:
                start = stack.index(node)
            except ValueError:
                start = 0
            cycle = stack[start:] + [node]
            if cycle not in cycles:
                cycles.append(cycle)
            return
        if marker == 2:
            return
        state[node] = 1
        stack.append(node)
        for dep in graph.get(node, []):
            if dep in graph:
                visit(dep)
        stack.pop()
        state[node] = 2

    for node in graph:
        visit(node)
    return cycles


def validate_tickets(root: Path, cfg: dict[str, Any]) -> tuple[list[str], list[str], list[Ticket]]:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        tickets = load_tickets(root, cfg)
    except WorkflowError as exc:
        return [str(exc)], warnings, []

    required = {
        "id",
        "title",
        "milestone",
        "status",
        "priority",
        "owns",
        "spec",
        "test_plan",
        "acceptance",
    }
    seen: dict[str, Path] = {}
    by_id: dict[str, Ticket] = {}
    for ticket in tickets:
        missing = sorted(required - set(ticket.metadata))
        if missing:
            errors.append(f"{relative(root, ticket.path)} missing fields: {', '.join(missing)}")
            continue
        if ticket.id in seen:
            errors.append(
                f"Duplicate ticket ID {ticket.id}: {relative(root, seen[ticket.id])} and "
                f"{relative(root, ticket.path)}"
            )
        seen[ticket.id] = ticket.path
        by_id[ticket.id] = ticket
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", ticket.id):
            errors.append(f"{ticket.id}: ID contains unsupported characters")
        if ticket.status not in TICKET_STATUSES:
            errors.append(f"{ticket.id}: invalid status {ticket.status!r}")
        elif ticket.status in LEGACY_TRANSIENT_STATUSES:
            warnings.append(
                f"{ticket.id}: legacy transient status {ticket.status!r}; migrate the "
                "ticket to ready and record its phase in the runtime ledger"
            )
        if ticket.priority not in PRIORITY_ORDER:
            warnings.append(f"{ticket.id}: unusual priority {ticket.priority!r}; expected P0-P3")
        if ticket.risk not in RISK_LEVELS:
            errors.append(
                f"{ticket.id}: risk must be one of {', '.join(sorted(RISK_LEVELS))}"
            )
        raw_reviews = ticket.metadata.get("required_reviews")
        if raw_reviews is not None and (
            not isinstance(raw_reviews, list)
            or any(item not in {"architect", "qa"} for item in raw_reviews)
        ):
            errors.append(
                f"{ticket.id}: required_reviews must contain only architect and qa"
            )
        if ticket.risk in {"high", "critical"} and not {
            "architect",
            "qa",
        }.issubset(ticket.required_reviews):
            errors.append(
                f"{ticket.id}: {ticket.risk}-risk tickets require architect and qa"
            )
        legacy = ticket.metadata.get("blocked_by")
        implementation = ticket.metadata.get("implementation_blocked_by")
        if legacy is not None and not isinstance(legacy, list):
            errors.append(f"{ticket.id}: blocked_by must be an array")
        for phase, field in DEPENDENCY_FIELDS.items():
            value = ticket.metadata.get(field)
            if value is not None and not isinstance(value, list):
                errors.append(f"{ticket.id}: {field} must be an array")
        if legacy is not None and implementation is not None and legacy != implementation:
            errors.append(
                f"{ticket.id}: blocked_by and implementation_blocked_by disagree; "
                "remove the legacy field or make them identical"
            )
        if not ticket.owns:
            errors.append(f"{ticket.id}: owns must contain at least one explicit path")
        if any(not path.strip() for path in ticket.owns):
            errors.append(f"{ticket.id}: owns contains an empty path")
        acceptance = ticket.metadata.get("acceptance")
        if not isinstance(acceptance, list) or not acceptance or any(
            not str(item).strip() for item in acceptance
        ):
            errors.append(f"{ticket.id}: acceptance must be a non-empty array of statements")
        else:
            maximum_acceptance = int(
                cfg.get("planning", {}).get("max_acceptance_criteria_per_ticket", 8)
            )
            if len(acceptance) > maximum_acceptance:
                message = (
                    f"{ticket.id}: {len(acceptance)} acceptance criteria exceed the "
                    f"configured maximum of {maximum_acceptance}; split the ticket or "
                    "consolidate duplicate evidence"
                )
                if ticket.status in {"draft", "blocked", "ready"}:
                    errors.append(message)
                else:
                    warnings.append(message)
        for label, document in (("spec", ticket.spec), ("test_plan", ticket.test_plan)):
            if not document:
                errors.append(f"{ticket.id}: {label} path is empty")
            elif not (root / document).exists():
                errors.append(f"{ticket.id}: {label} does not exist: {document}")
        blocker = ticket.blocker_record
        if blocker:
            blocker_class = str(blocker.get("class", "none"))
            authorization = str(blocker.get("authorization", "not_required"))
            derivatives = blocker.get("derivatives", [])
            if blocker_class not in BLOCKER_CLASSES:
                errors.append(
                    f"{ticket.id}: blocker.class must be one of "
                    f"{', '.join(sorted(BLOCKER_CLASSES))}"
                )
            if authorization not in AUTHORIZATION_STATES:
                errors.append(
                    f"{ticket.id}: blocker.authorization must be one of "
                    f"{', '.join(sorted(AUTHORIZATION_STATES))}"
                )
            if not isinstance(derivatives, list):
                errors.append(f"{ticket.id}: blocker.derivatives must be an array")
            if blocker_class != "none" and not str(blocker.get("root_cause", "")).strip():
                errors.append(
                    f"{ticket.id}: blocker.root_cause is required when blocker.class is not none"
                )
        elif ticket.status in {"blocked", "failed"}:
            warnings.append(
                f"{ticket.id}: {ticket.status} ticket has no structured blocker record"
            )

    for ticket in tickets:
        for blocker in ticket.all_blockers:
            if blocker == ticket.id:
                errors.append(f"{ticket.id}: cannot block itself")
            elif blocker not in by_id:
                errors.append(f"{ticket.id}: unknown blocker {blocker}")

    reported_cycles: set[frozenset[str]] = set()
    for phase in ("implementation", "review", "integration"):
        for cycle in detect_cycles(tickets, phase):
            key = frozenset(cycle[:-1])
            if key in reported_cycles:
                continue
            reported_cycles.add(key)
            errors.append(
                f"Ticket dependency cycle first visible at {phase}: "
                + " -> ".join(cycle)
            )

    active = [t for t in tickets if t.status in {"ready", "in_progress", "review"}]
    for index, left in enumerate(active):
        for right in active[index + 1 :]:
            if left.milestone == right.milestone and ownership_overlaps(left.owns, right.owns):
                warnings.append(
                    f"Potential ownership overlap in {left.milestone}: {left.id} and {right.id}"
                )
    if not tickets:
        warnings.append("No non-template tickets found")
    return errors, warnings, tickets


def unmet_dependencies(
    ticket: Ticket,
    phase: str,
    by_id: dict[str, Ticket],
) -> list[str]:
    return [
        dependency
        for dependency in ticket.dependencies_through(phase)
        if dependency not in by_id or by_id[dependency].status != "done"
    ]


def eligible_tickets(tickets: Sequence[Ticket], milestone: str | None = None) -> list[Ticket]:
    by_id = {ticket.id: ticket for ticket in tickets}
    eligible: list[Ticket] = []
    for ticket in tickets:
        if ticket.status != "ready":
            continue
        if milestone and ticket.milestone.upper() != milestone.upper():
            continue
        if not unmet_dependencies(ticket, "implementation", by_id):
            eligible.append(ticket)
    return sorted(
        eligible,
        key=lambda ticket: (PRIORITY_ORDER.get(ticket.priority, 99), ticket.id),
    )


def select_frontier(
    tickets: Sequence[Ticket],
    milestone: str | None,
    limit: int,
    reserved: Sequence[Ticket] = (),
    runtimes: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[Ticket], list[tuple[Ticket, str]]]:
    selected: list[Ticket] = []
    skipped: list[tuple[Ticket, str]] = []
    reserved_ids = {ticket.id for ticket in reserved}
    for ticket in eligible_tickets(tickets, milestone):
        runtime = (runtimes or {}).get(ticket.milestone.upper(), {})
        open_roots = open_root_blocker_ids_for_ticket(
            runtime,
            ticket.id,
            "implementation",
        )
        if open_roots:
            skipped.append(
                (
                    ticket,
                    "open implementation blockers: " + ", ".join(open_roots),
                )
            )
            continue
        if ticket.id in reserved_ids:
            skipped.append((ticket, "ticket already has an active runtime phase"))
            continue
        reserved_conflict = next(
            (other for other in reserved if ownership_overlaps(ticket.owns, other.owns)),
            None,
        )
        if reserved_conflict:
            skipped.append((ticket, f"ownership overlaps active {reserved_conflict.id}"))
            continue
        if len(selected) >= limit:
            skipped.append((ticket, "parallel limit reached"))
            continue
        conflict = next(
            (other for other in selected if ownership_overlaps(ticket.owns, other.owns)),
            None,
        )
        if conflict:
            skipped.append((ticket, f"ownership overlaps {conflict.id}"))
            continue
        selected.append(ticket)
    return selected, skipped


def milestone_scheduler_state(
    tickets: Sequence[Ticket],
    milestone: str,
    limit: int,
    runtime: dict[str, Any] | None = None,
    continue_after_independent_failure: bool = True,
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the next deterministic orchestration action for one milestone.

    This function does not mutate repository state or spawn agents. It gives the
    primary Codex thread a compact checkpoint for its execute/resume control loop.
    """

    normalized = milestone.strip().upper()
    scoped = [ticket for ticket in tickets if ticket.milestone.upper() == normalized]
    counts = collections.Counter(ticket.status for ticket in scoped)
    runtime = runtime or {}
    active_entries = active_ticket_phases(scoped, runtime, normalized)
    active = [ticket for ticket, _, _, _ in active_entries]
    failed_active = any(phase == "repair" for _, phase, _, _ in active_entries)
    terminal = {"done", "deferred"}

    blocked: list[dict[str, Any]] = []
    by_id = {ticket.id: ticket for ticket in tickets}
    active_details: list[dict[str, Any]] = []
    resumable: list[Ticket] = []
    active_ids = {ticket.id for ticket in active}
    for ticket, phase, source, phase_record in active_entries:
        gate = PHASE_DEPENDENCY_GATE[phase]
        root_blocker: dict[str, Any] = {}
        root_cause_id = (
            str(phase_record.get("root_cause_id", ""))
            if phase == "repair"
            else ""
        )
        if root_cause_id:
            root_blocker = runtime.get("blockers", {}).get(root_cause_id, {})
            if (
                isinstance(root_blocker, dict)
                and root_blocker.get("phase") in DEPENDENCY_FIELDS
            ):
                gate = str(root_blocker["phase"])
        unmet = unmet_dependencies(ticket, gate, by_id)
        open_roots = (
            []
            if phase == "repair"
            else open_root_blocker_ids_for_ticket(runtime, ticket.id, gate)
        )
        detail = {
            "id": ticket.id,
            "status": ticket.status,
            "phase": phase,
            "phase_source": source,
            "phase_record": phase_record,
            "dependency_gate": gate,
            "unmet_dependencies": unmet,
            "open_root_blockers": open_roots,
        }
        repair = None
        repair_root_open = True
        repair_authorized = True
        if phase == "repair":
            repair = repair_summary(
                ticket,
                cfg or deep_merge(DEFAULT_CONFIG, {}),
                runtime,
                root_cause_id or None,
            )
            detail["repair_budget"] = repair
            repair_root_open = bool(
                root_cause_id
                and isinstance(root_blocker, dict)
                and root_blocker.get("status", "open") == "open"
            )
            authorization_required = (
                isinstance(root_blocker, dict)
                and root_blocker.get("authorization", "not_required")
                != "not_required"
            )
            authorization_match = None
            if authorization_required and repair_root_open:
                authorization_match = matching_authorization(
                    runtime,
                    action="local_repair",
                    ticket_id=ticket.id,
                    blocker_class=str(root_blocker.get("class", "code")),
                    risk=str(root_blocker.get("risk", ticket.risk)),
                    remote_effects=False,
                )
                repair_authorized = authorization_match is not None
            detail["repair_root_open"] = repair_root_open
            detail["repair_authorization_required"] = authorization_required
            detail["repair_authorization_scope"] = (
                authorization_match[0] if authorization_match else None
            )
        active_details.append(detail)
        if (
            not unmet
            and not open_roots
            and repair_root_open
            and repair_authorized
            and not (repair and repair["exhausted"])
        ):
            resumable.append(ticket)
        else:
            if unmet:
                blocker_class = "dependency"
                reason = "unmet " + gate + " dependencies: " + ", ".join(unmet)
            elif open_roots:
                blocker_class = "code"
                reason = "open canonical root blockers: " + ", ".join(open_roots)
            elif repair and not repair_root_open:
                blocker_class = "repository_state"
                reason = (
                    f"repair phase references resolved or missing root "
                    f"{root_cause_id}; clear or advance the phase"
                )
            elif repair and repair["exhausted"]:
                blocker_class = "authorization"
                reason = (
                    "repair budget exhausted "
                    f"({repair['consumed']}/{repair['budget']})"
                )
            else:
                blocker_class = "authorization"
                reason = (
                    f"no exact local_repair authorization matches root "
                    f"{root_cause_id}"
                )
            blocked.append(
                {
                    "id": ticket.id,
                    "status": ticket.status,
                    "class": blocker_class,
                    "phase": phase,
                    "reason": reason,
                }
            )

    resumable_ids = {ticket.id for ticket in resumable}
    active_writer_count = sum(
        phase in ACTIVE_WRITER_PHASES and ticket.id in resumable_ids
        for ticket, phase, _, _ in active_entries
    )
    available = max(0, limit - active_writer_count)
    if failed_active and not continue_after_independent_failure:
        available = 0
    selected, skipped = select_frontier(
        tickets,
        normalized,
        available,
        reserved=active,
        runtimes={normalized: runtime},
    )

    for ticket in scoped:
        if ticket.id in active_ids:
            continue
        reason = ""
        blocker_class = ""
        if ticket.status == "draft":
            reason = "contract is still draft"
            blocker_class = "contract"
        elif ticket.status == "blocked":
            reason = "ticket is explicitly blocked"
            blocker_class = "dependency"
        elif ticket.status == "ready":
            unmet = unmet_dependencies(ticket, "implementation", by_id)
            if unmet:
                reason = "unmet implementation dependencies: " + ", ".join(
                    f"{dep}={by_id[dep].status if dep in by_id else 'missing'}"
                    for dep in unmet
                )
                blocker_class = "dependency"
            else:
                open_roots = open_root_blocker_ids_for_ticket(
                    runtime,
                    ticket.id,
                    "implementation",
                )
                if open_roots:
                    reason = "open implementation blockers: " + ", ".join(
                        open_roots
                    )
                    blocker_class = "code"
        if reason:
            runtime_record = runtime_blocker_for_ticket(runtime or {}, ticket.id)
            static_record = ticket.blocker_record
            record = runtime_record or static_record
            blocked.append(
                {
                    "id": ticket.id,
                    "status": ticket.status,
                    "class": str(record.get("class", blocker_class or "none")),
                    "root_cause": str(record.get("root_cause", "")),
                    "derivatives": list(record.get("derivatives", []))
                    if isinstance(record.get("derivatives", []), list)
                    else [],
                    "authorization": str(
                        record.get("authorization", "not_required")
                    ),
                    "reason": reason,
                }
            )

    release_blocked: list[dict[str, Any]] = []
    for ticket in scoped:
        if ticket.status not in terminal:
            continue
        unmet = unmet_dependencies(ticket, "release", by_id)
        if unmet:
            release_blocked.append({"id": ticket.id, "dependencies": unmet})
    open_release_roots = open_canonical_root_blocker_ids(runtime)

    if not scoped:
        action = "no_tickets"
    elif resumable and selected:
        action = "resume_and_execute_frontier"
    elif resumable:
        action = "resume_active"
    elif selected:
        action = "execute_frontier"
    elif (
        all(ticket.status in terminal for ticket in scoped)
        and not release_blocked
        and not open_release_roots
    ):
        action = "ready_to_close"
    else:
        action = "blocked"

    return {
        "milestone": normalized,
        "action": action,
        "counts": dict(sorted(counts.items())),
        "selected": [ticket.id for ticket in selected],
        "available_engineer_slots": available,
        "active": [ticket.id for ticket in active],
        "active_details": active_details,
        "blocked": blocked,
        "release_blocked": release_blocked,
        "open_root_blockers": open_release_roots,
        "skipped": [{"id": ticket.id, "reason": reason} for ticket, reason in skipped],
        "all_terminal": bool(scoped) and all(ticket.status in terminal for ticket in scoped),
    }


def apply_run_limits(
    payload: dict[str, Any],
    cfg: dict[str, Any],
    runtime: dict[str, Any],
) -> dict[str, Any]:
    """Turn persisted wave/no-progress limits into a scheduler stop decision."""

    checkpoint = runtime.get("last_checkpoint", {})
    if not isinstance(checkpoint, dict):
        checkpoint = {}
    strategy = str(cfg["execution"]["strategy"])
    configured_wave_limit = int(cfg["execution"]["max_waves_per_run"])
    effective_wave_limit = 1 if strategy == "wave" else configured_wave_limit
    wave = int(checkpoint.get("wave", 0))
    no_progress = int(checkpoint.get("no_progress_count", 0))
    no_progress_limit = int(cfg["execution"]["no_progress_limit"])
    wave_limit_reached = bool(
        effective_wave_limit and wave >= effective_wave_limit
    )
    no_progress_exhausted = no_progress >= no_progress_limit
    payload["wave"] = wave
    payload["no_progress_count"] = no_progress
    payload["effective_wave_limit"] = effective_wave_limit
    payload["wave_limit_reached"] = wave_limit_reached
    payload["no_progress_exhausted"] = no_progress_exhausted
    if (
        payload.get("action")
        not in {"no_tickets", "ready_to_close", "blocked"}
        and (wave_limit_reached or no_progress_exhausted)
    ):
        prior_action = str(payload["action"])
        prior_selected = list(payload.get("selected", []))
        payload["action_before_run_limit"] = prior_action
        payload["selected_before_run_limit"] = prior_selected
        payload["selected"] = []
        payload["action"] = "run_limit_reached"
        payload["stop_reason"] = (
            f"no-progress limit reached ({no_progress}/{no_progress_limit})"
            if no_progress_exhausted
            else f"wave limit reached ({wave}/{effective_wave_limit})"
        )
    return payload


def current_branch(root: Path) -> str:
    proc = run(["git", "branch", "--show-current"], cwd=root)
    return proc.stdout.strip()


def is_clean(root: Path) -> tuple[bool, list[str]]:
    proc = run(["git", "status", "--porcelain"], cwd=root)
    paths = [line.rstrip() for line in proc.stdout.splitlines() if line.strip()]
    return not paths, paths


def branch_exists(root: Path, branch: str) -> bool:
    proc = run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=root,
        check=False,
    )
    return proc.returncode == 0


def unborn_branch(root: Path) -> str | None:
    """Return the symbolic branch name when a repository has no commits yet."""

    head = run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=root,
        check=False,
    )
    if head.returncode != 0:
        return None
    committed = run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        check=False,
    )
    if committed.returncode == 0:
        return None
    return head.stdout.strip() or None


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-.")
    if not value:
        raise WorkflowError("Cannot derive a safe slug")
    return value


def append_gitignore(root: Path, entry: str) -> bool:
    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = {line.strip() for line in existing.splitlines()}
    if entry in lines:
        return False
    with path.open("a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(entry + "\n")
    return True


def asset_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "assets" / "templates"


def document_template_mapping(cfg: dict[str, Any]) -> dict[str, str]:
    docs = cfg["documents"]
    return {
        str(Path(docs["adr_dir"]) / "ADR-0000-template.md"): "adr.md",
        str(Path(docs["spec_dir"]) / "SPEC-0000-template.md"): "spec.md",
        str(Path(docs["test_plan_dir"]) / "TEST-0000-template.md"): "test-plan.md",
        str(Path(docs["ticket_dir"]) / "TICKET-0000-template.md"): "ticket.md",
        str(Path(docs["handoff_dir"]) / "HANDOFF-0000-template.md"): "handoff.md",
    }


def write_if_missing(destination: Path, source: Path) -> bool:
    if destination.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True



@dataclass(frozen=True)
class SourceCounts:
    code: int
    tests: int
    files: int
    tool: str

    @property
    def ratio(self) -> float:
        if self.code == 0:
            return 0.0 if self.tests == 0 else math.inf
        return self.tests / self.code

    def payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "tests": self.tests,
            "files": self.files,
            "tool": self.tool,
            "ratio": None if math.isinf(self.ratio) else round(self.ratio, 6),
            "ratio_display": "inf" if math.isinf(self.ratio) else f"{self.ratio:.3f}",
        }


def _matches_any_glob(path: str, patterns: Sequence[str]) -> bool:
    normalized = path.replace("\\", "/")
    # Remove an explicit relative-path prefix without stripping a meaningful
    # leading dot from hidden directories such as `.git` or `.worktrees`.
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    return any(
        fnmatch.fnmatch(normalized, pattern)
        or PurePosixPath(normalized).match(pattern)
        for pattern in patterns
    )


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path.replace("\\", "/"))
    parts = {part.lower() for part in pure.parts[:-1]}
    if parts & {"test", "tests", "testing", "spec", "specs", "bench", "benches", "benchmarks"}:
        return True
    stem = pure.stem.lower()
    return (
        stem.startswith("test_")
        or stem.endswith("_test")
        or stem.endswith("_tests")
        or stem == "tests"
    )


def _strip_comments_and_strings_for_braces(
    line: str,
    *,
    block_depth: int,
) -> tuple[str, str, int]:
    """Return visible code, brace-safe code, and updated /* */ depth.

    This is intentionally a conservative source-line classifier, not a language
    parser. It handles ordinary Rust comments and quoted strings well enough to
    distinguish unit-test regions without introducing a parser dependency.
    """

    visible: list[str] = []
    brace_safe: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(line):
        ch = line[index]
        nxt = line[index + 1] if index + 1 < len(line) else ""
        if block_depth:
            if ch == "/" and nxt == "*":
                block_depth += 1
                index += 2
                continue
            if ch == "*" and nxt == "/":
                block_depth -= 1
                index += 2
                continue
            index += 1
            continue
        if quote is not None:
            visible.append(ch)
            brace_safe.append(" ")
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            index += 1
            continue
        if ch == "/" and nxt == "/":
            break
        if ch == "/" and nxt == "*":
            block_depth = 1
            index += 2
            continue
        if ch in {'"', "'"}:
            quote = ch
            visible.append(ch)
            brace_safe.append(" ")
            index += 1
            continue
        visible.append(ch)
        brace_safe.append(ch)
        index += 1
    return "".join(visible).strip(), "".join(brace_safe), block_depth


def _count_source_text(path: str, text: str) -> tuple[int, int]:
    whole_file_test = _is_test_path(path)
    extension = PurePosixPath(path).suffix.lower()
    code = 0
    tests = 0
    block_depth = 0
    brace_depth = 0
    active_test_base: int | None = None
    pending_test_item = False
    test_attribute = re.compile(
        r"#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|(?:tokio::|async_std::)?test(?:\s*\([^]]*\))?)\s*\]"
    )

    for raw_line in text.splitlines():
        visible, brace_safe, block_depth = _strip_comments_and_strings_for_braces(
            raw_line,
            block_depth=block_depth,
        )
        if not visible:
            continue
        if extension != ".rs":
            if whole_file_test:
                tests += 1
            else:
                code += 1
            continue

        has_test_attr = bool(test_attribute.search(visible))
        in_test = whole_file_test or active_test_base is not None or pending_test_item or has_test_attr
        if in_test:
            tests += 1
        else:
            code += 1

        before_depth = brace_depth
        opens = brace_safe.count("{")
        closes = brace_safe.count("}")

        if has_test_attr and active_test_base is None:
            pending_test_item = True
        if pending_test_item and opens:
            active_test_base = before_depth
            pending_test_item = False
        elif pending_test_item and ";" in brace_safe:
            pending_test_item = False

        brace_depth += opens - closes
        if active_test_base is not None and brace_depth <= active_test_base:
            active_test_base = None
    return code, tests


def _test_budget_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    settings = cfg.get("quality", {}).get("test_budget", {})
    if not isinstance(settings, dict):
        raise WorkflowError("quality.test_budget must be a table")
    return settings


def _source_extensions(settings: dict[str, Any]) -> set[str]:
    raw = settings.get("include_extensions", [".rs"])
    if not isinstance(raw, list):
        raise WorkflowError("quality.test_budget.include_extensions must be an array")
    return {str(item).lower() for item in raw}


def _excluded(path: str, settings: dict[str, Any]) -> bool:
    patterns = settings.get("exclude_globs", [])
    if not isinstance(patterns, list):
        raise WorkflowError("quality.test_budget.exclude_globs must be an array")
    return _matches_any_glob(path, [str(item) for item in patterns])


def count_working_tree_builtin(root: Path, settings: dict[str, Any]) -> SourceCounts:
    extensions = _source_extensions(settings)
    code = tests = files = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in extensions:
            continue
        relative_path = path.relative_to(root).as_posix()
        if _excluded(relative_path, settings):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
        file_code, file_tests = _count_source_text(relative_path, text)
        code += file_code
        tests += file_tests
        files += 1
    return SourceCounts(code=code, tests=tests, files=files, tool="builtin")


def count_git_ref_builtin(
    root: Path,
    ref: str,
    settings: dict[str, Any],
) -> SourceCounts:
    extensions = _source_extensions(settings)
    listing = run(
        ["git", "ls-tree", "-r", "--name-only", ref],
        cwd=root,
        check=False,
    )
    if listing.returncode != 0:
        raise WorkflowError(f"Cannot read Git ref for test budget: {ref}")
    code = tests = files = 0
    for relative_path in listing.stdout.splitlines():
        if PurePosixPath(relative_path).suffix.lower() not in extensions:
            continue
        if _excluded(relative_path, settings):
            continue
        blob = run(
            ["git", "show", f"{ref}:{relative_path}"],
            cwd=root,
            check=False,
        )
        if blob.returncode != 0:
            continue
        file_code, file_tests = _count_source_text(relative_path, blob.stdout)
        code += file_code
        tests += file_tests
        files += 1
    return SourceCounts(code=code, tests=tests, files=files, tool="builtin")


def count_rustloc(root: Path) -> SourceCounts:
    executable = shutil.which("rustloc")
    if not executable:
        raise WorkflowError(
            "rustloc is not available; install it or set quality.test_budget.tool = 'builtin'"
        )
    proc = subprocess.run(
        [executable, "--lang", "rust", "-t", "code,tests"],
        cwd=str(root),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise WorkflowError(f"rustloc failed ({proc.returncode}): {detail}")
    output = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
    match = re.search(
        r"Total\s*\([^\n)]*files?\)\s+([0-9][0-9,]*)\s+([0-9][0-9,]*)",
        output,
        flags=re.IGNORECASE,
    )
    if not match:
        raise WorkflowError("Could not parse rustloc Total row")
    code = int(match.group(1).replace(",", ""))
    tests = int(match.group(2).replace(",", ""))
    file_match = re.search(r"Total\s*\(\s*([0-9,]+)\s+files?\)", output, re.I)
    files = int(file_match.group(1).replace(",", "")) if file_match else 0
    return SourceCounts(code=code, tests=tests, files=files, tool="rustloc")


def test_budget_baseline_path(root: Path, settings: dict[str, Any]) -> Path:
    raw = str(settings.get("baseline_path", "")).strip()
    if not raw:
        raise WorkflowError("quality.test_budget.baseline_path must not be empty")
    configured = Path(raw)
    path = configured if configured.is_absolute() else root / configured
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise WorkflowError("test-budget baseline must stay inside the repository") from exc
    return resolved


def load_test_budget_baseline(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"Cannot parse test-budget baseline {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise WorkflowError(f"Unsupported test-budget baseline schema in {path}")
    counts = payload.get("counts")
    if not isinstance(counts, dict):
        raise WorkflowError(f"Invalid test-budget baseline counts in {path}")
    for field in ("code", "tests"):
        value = counts.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WorkflowError(f"Invalid test-budget baseline {field} in {path}")
    if payload.get("tool") not in {"builtin", "rustloc"}:
        raise WorkflowError(f"Invalid test-budget baseline tool in {path}")
    return payload


def write_test_budget_baseline(
    root: Path,
    path: Path,
    counts: SourceCounts,
    settings: dict[str, Any],
) -> None:
    commit = run(["git", "rev-parse", "HEAD"], cwd=root, check=False).stdout.strip()
    payload = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "commit": commit,
        "tool": counts.tool,
        "counts": counts.payload(),
        "policy": {
            key: settings.get(key)
            for key in (
                "mode",
                "target_ratio",
                "warn_ratio",
                "max_regression",
                "ratchet_step",
                "max_delta_ratio",
                "delta_test_allowance",
                "min_code_lines",
            )
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _choose_test_budget_tool(
    requested: str,
    baseline: dict[str, Any] | None,
) -> str:
    if requested not in TEST_BUDGET_TOOLS:
        raise WorkflowError(f"Unsupported test-budget tool: {requested}")
    if requested != "auto":
        return requested
    if baseline and baseline.get("tool") in {"builtin", "rustloc"}:
        chosen = str(baseline["tool"])
        if chosen == "rustloc" and not shutil.which("rustloc"):
            raise WorkflowError(
                "The baseline was created with rustloc, but rustloc is unavailable. "
                "Install rustloc or explicitly migrate the baseline with "
                "--tool builtin --write-baseline."
            )
        return chosen
    return "rustloc" if shutil.which("rustloc") else "builtin"


def _ratio_from_baseline(baseline: dict[str, Any]) -> float:
    counts = baseline["counts"]
    code = int(counts["code"])
    tests = int(counts["tests"])
    if code == 0:
        return 0.0 if tests == 0 else math.inf
    return tests / code


def _merge_base(root: Path, base: str) -> str:
    proc = run(["git", "merge-base", "HEAD", base], cwd=root, check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    proc = run(["git", "rev-parse", base], cwd=root, check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    raise WorkflowError(f"Cannot resolve test-budget base ref: {base}")


def evaluate_test_budget(
    root: Path,
    cfg: dict[str, Any],
    *,
    gate: str,
    base: str,
    requested_tool: str | None,
    write_baseline: bool,
) -> tuple[dict[str, Any], int]:
    if gate not in TEST_BUDGET_GATES:
        raise WorkflowError(f"Unsupported test-budget gate: {gate}")
    settings = _test_budget_settings(cfg)
    enabled = bool(settings.get("enabled", True))
    mode = str(settings.get("mode", "ratchet"))
    baseline_path = test_budget_baseline_path(root, settings)
    baseline = load_test_budget_baseline(baseline_path)
    tool = _choose_test_budget_tool(
        requested_tool or str(settings.get("tool", "auto")),
        baseline,
    )
    builtin_current = count_working_tree_builtin(root, settings)
    current = count_rustloc(root) if tool == "rustloc" else builtin_current
    warnings: list[str] = []
    reasons: list[str] = []
    ratio = current.ratio
    warn_ratio = float(settings.get("warn_ratio", 0.85))
    if ratio > warn_ratio:
        warnings.append(
            f"test/code ratio {ratio:.3f} exceeds warning ratio {warn_ratio:.3f}"
        )

    if write_baseline:
        write_test_budget_baseline(root, baseline_path, current, settings)
        baseline = load_test_budget_baseline(baseline_path)

    delta_payload: dict[str, Any] | None = None
    delta_size = 0
    if gate in {"ticket", "milestone"}:
        merge_base = _merge_base(root, base)
        base_counts = count_git_ref_builtin(root, merge_base, settings)
        delta_code = max(0, builtin_current.code - base_counts.code)
        delta_tests = max(0, builtin_current.tests - base_counts.tests)
        delta_size = delta_code + delta_tests
        allowed_delta_tests = (
            delta_code * float(settings.get("max_delta_ratio", 1.0))
            + int(settings.get("delta_test_allowance", 120))
        )
        delta_payload = {
            "base_ref": base,
            "merge_base": merge_base,
            "code": delta_code,
            "tests": delta_tests,
            "allowed_tests": round(allowed_delta_tests, 3),
            "ratio": None if delta_code == 0 else round(delta_tests / delta_code, 6),
        }
        if gate == "ticket" and delta_tests > allowed_delta_tests:
            reasons.append(
                f"test delta {delta_tests} exceeds allowance {allowed_delta_tests:.1f} "
                f"for code delta {delta_code}"
            )

    baseline_ratio: float | None = None
    required_ratio: float | None = None
    if enabled and mode != "off" and gate != "report":
        target_ratio = float(settings.get("target_ratio", 1.0))
        regression = float(settings.get("max_regression", 0.0))
        if mode == "strict":
            required_ratio = target_ratio + regression
            if ratio > required_ratio:
                reasons.append(
                    f"ratio {ratio:.3f} exceeds strict target {required_ratio:.3f}"
                )
        elif mode == "ratchet":
            if baseline is None:
                # Fresh repositories do not have an inherited debt baseline. Treat
                # the configured target as the initial ceiling so the first ticket
                # can proceed without an impossible empty-project baseline.
                required_ratio = target_ratio + regression
                if ratio > required_ratio:
                    reasons.append(
                        f"ratio {ratio:.3f} exceeds initial target {required_ratio:.3f}; "
                        "write a baseline only when intentionally adopting existing debt"
                    )
            else:
                baseline_ratio = _ratio_from_baseline(baseline)
                allowed_current = baseline_ratio + regression
                if ratio > allowed_current:
                    reasons.append(
                        f"ratio {ratio:.3f} regressed beyond baseline {baseline_ratio:.3f}"
                    )
                if gate == "milestone" and delta_size >= int(
                    settings.get("min_code_lines", 200)
                ):
                    required_ratio = max(
                        target_ratio,
                        baseline_ratio - float(settings.get("ratchet_step", 0.05)),
                    ) + regression
                    if ratio > required_ratio:
                        reasons.append(
                            f"milestone ratio {ratio:.3f} did not reach ratchet target "
                            f"{required_ratio:.3f}"
                        )

    verdict = "pass" if not reasons else "fail"
    payload = {
        "enabled": enabled,
        "mode": mode,
        "gate": gate,
        "verdict": verdict,
        "counts": current.payload(),
        "builtin_counts": builtin_current.payload(),
        "baseline_path": relative(root, baseline_path),
        "baseline": baseline,
        "baseline_ratio": None
        if baseline_ratio is None or math.isinf(baseline_ratio)
        else round(baseline_ratio, 6),
        "required_ratio": None
        if required_ratio is None or math.isinf(required_ratio)
        else round(required_ratio, 6),
        "delta": delta_payload,
        "warnings": warnings,
        "reasons": reasons,
        "baseline_written": write_baseline,
    }
    return payload, 0 if verdict == "pass" or gate == "report" or not enabled or mode == "off" else 1


def cmd_test_budget(args: argparse.Namespace) -> int:
    root = git_root(Path(args.cwd).resolve() if args.cwd else None)
    cfg = load_config(root)
    payload, exit_code = evaluate_test_budget(
        root,
        cfg,
        gate=args.gate,
        base=args.base or str(cfg["workflow"]["base_branch"]),
        requested_tool=args.tool,
        write_baseline=args.write_baseline,
    )
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return exit_code
    counts = payload["counts"]
    print(
        f"Test budget: {payload['verdict'].upper()} "
        f"(code={counts['code']}, tests={counts['tests']}, "
        f"ratio={counts['ratio_display']}, tool={counts['tool']})"
    )
    if payload.get("baseline_written"):
        print(f"  baseline written: {payload['baseline_path']}")
    if payload.get("baseline_ratio") is not None:
        print(f"  baseline ratio: {payload['baseline_ratio']:.3f}")
    if payload.get("required_ratio") is not None:
        print(f"  required ratio: {payload['required_ratio']:.3f}")
    delta = payload.get("delta")
    if isinstance(delta, dict):
        print(
            f"  delta from {delta['base_ref']}: code={delta['code']} "
            f"tests={delta['tests']} allowed_tests={delta['allowed_tests']}"
        )
    for warning in payload.get("warnings", []):
        print(f"  warning: {warning}")
    for reason in payload.get("reasons", []):
        print(f"  failure: {reason}")
    return exit_code


def _parse_review_finding(raw: str, *, new: bool) -> dict[str, Any]:
    parts = raw.split(":", 3 if new else 2)
    expected = 4 if new else 3
    if len(parts) != expected:
        syntax = "ID:severity:origin:summary" if new else "ID:severity:summary"
        raise WorkflowError(f"Review finding must use {syntax}: {raw!r}")
    finding_id = parts[0].strip()
    severity = parts[1].strip().lower()
    origin = parts[2].strip().lower() if new else "initial_review"
    summary = parts[3].strip() if new else parts[2].strip()
    if not finding_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", finding_id):
        raise WorkflowError(f"Invalid review finding ID: {finding_id!r}")
    if severity not in REVIEW_FINDING_SEVERITIES:
        raise WorkflowError(f"Invalid review finding severity: {severity!r}")
    if new and origin not in NEW_REVIEW_BLOCKER_ORIGINS:
        raise WorkflowError(f"Invalid new review finding origin: {origin!r}")
    if not summary:
        raise WorkflowError("Review finding summary must not be empty")
    return {
        "id": finding_id,
        "severity": severity,
        "origin": origin,
        "summary": summary,
        "new": new,
    }


def _review_passes(verdict: str, cfg: dict[str, Any]) -> bool:
    return verdict == "pass" or (
        verdict == "pass_with_notes"
        and bool(cfg.get("review", {}).get("pass_with_notes_integrates", True))
    )


def canonical_review_root(
    runtime: dict[str, Any],
    ticket_id: str,
    root_cause_id: str,
    *,
    require_open: bool,
) -> dict[str, Any]:
    root = runtime.get("blockers", {}).get(root_cause_id)
    if (
        not root_cause_id
        or not isinstance(root, dict)
        or root.get("derived_from")
        or str(root.get("root_cause_id", "")) != root_cause_id
        or str(root.get("ticket_id", "")).upper() != ticket_id.upper()
        or (require_open and root.get("status", "open") != "open")
    ):
        state = "open " if require_open else ""
        raise WorkflowError(
            f"--root-blocker must name {ticket_id}'s {state}canonical root exactly"
        )
    return root


def find_root_review_cycle(
    ticket_reviews: dict[str, Any],
    root_cause_id: str,
) -> dict[str, Any] | None:
    cycles = ticket_reviews.get("root_cycles", [])
    if not isinstance(cycles, list):
        raise WorkflowError("Root-scoped review cycles must be an array")
    matching = [
        cycle
        for cycle in cycles
        if isinstance(cycle, dict)
        and str(cycle.get("root_cause_id", "")) == root_cause_id
    ]
    if len(matching) > 1:
        raise WorkflowError(
            f"Canonical root {root_cause_id} already has multiple review cycles"
        )
    return matching[0] if matching else None


def validate_superseding_review(
    *,
    runtime: dict[str, Any],
    ticket_id: str,
    reviewer: str = "",
    reviewer_rounds: dict[str, Any],
    candidate_sha: str,
    verdict: str,
    findings: Sequence[dict[str, Any]],
    new_findings: Sequence[dict[str, Any]],
    resolved: Sequence[str],
    root_cause_id: str,
    authorization_scope: str,
    blocking_severities: set[str],
    phase: dict[str, Any] | None = None,
    supersedes: object = None,
    require_available: bool = True,
    root_cycle: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, str]]:
    if any(not isinstance(item, dict) for item in findings + new_findings):
        raise WorkflowError("Superseding review findings must be objects")
    if any(not isinstance(item, str) or not item.strip() for item in resolved):
        raise WorkflowError("Superseding resolved IDs must be non-empty strings")
    if verdict not in {"pass", "pass_with_notes", "escalate"}:
        raise WorkflowError(
            "Superseding review verdict must be pass, pass_with_notes, or escalate"
        )
    if new_findings:
        raise WorkflowError("Superseding review does not accept new findings")
    full = reviewer_rounds.get("full")
    targeted = reviewer_rounds.get("targeted")
    if not isinstance(full, dict):
        raise WorkflowError("Superseding review requires the original full review")
    if root_cycle:
        if isinstance(targeted, dict):
            if full.get("verdict") != "block" or targeted.get("verdict") != "escalate":
                raise WorkflowError(
                    "Root-cycle targeted verification requires a blocking full "
                    "review and targeted escalation"
                )
            prior = targeted
        else:
            if full.get("verdict") not in {"pass", "pass_with_notes"}:
                raise WorkflowError(
                    "Root-cycle verification without targeted escalation requires "
                    "a passing baseline review"
                )
            prior = full
    else:
        if full.get("verdict") != "block":
            raise WorkflowError(
                "Superseding review requires the original blocking full review"
            )
        if not isinstance(targeted, dict) or targeted.get("verdict") != "escalate":
            raise WorkflowError(
                "Superseding review requires a prior targeted escalation"
            )
        prior = targeted
    prior_sha = str(prior.get("candidate_sha", "")).lower()
    if candidate_sha == prior_sha:
        raise WorkflowError(
            "Superseding review candidate must differ from the prior root-cycle SHA"
            if root_cycle
            else "Superseding review candidate must differ from the targeted escalation SHA"
        )
    root = canonical_review_root(
        runtime,
        ticket_id,
        root_cause_id,
        require_open=require_available,
    )
    if phase is not None and (
        phase.get("phase") != "repair"
        or phase.get("root_cause_id") != root_cause_id
    ):
        raise WorkflowError(
            f"Superseding review root {root_cause_id} does not match the active repair root"
        )
    if phase is not None:
        phase_sha = str(phase.get("candidate_sha", "")).lower()
        if not phase_sha or phase_sha != candidate_sha:
            raise WorkflowError(
                f"Superseding review candidate {candidate_sha} does not match "
                f"active repair SHA {phase_sha or 'missing'}"
            )
    if not authorization_scope:
        raise WorkflowError("Superseding review requires --authorization-scope")
    authorization = runtime.get("authorizations", {}).get(authorization_scope)
    blocker_class = str(root.get("class", ""))
    risk = str(root.get("risk", ""))
    if not isinstance(authorization, dict):
        raise WorkflowError(
            f"Superseding review authorization scope {authorization_scope} is missing"
        )
    if authorization.get("max_uses") != 1:
        raise WorkflowError(
            "Superseding review requires a single-use review_round_override scope"
        )
    uses = authorization.get("uses", 0)
    if require_available and (isinstance(uses, bool) or uses != 0):
        raise WorkflowError(
            f"Superseding review requires an unused authorization scope; "
            f"{authorization_scope} is exhausted or revoked"
        )
    if not require_available and (
        isinstance(uses, bool)
        or uses != 1
        or authorization.get("status") != "revoked"
    ):
        raise WorkflowError(
            "Superseding runtime record requires its consumed single-use "
            "review_round_override scope"
        )
    if not authorization_record_covers(
        authorization,
        action="review_round_override",
        ticket_id=ticket_id,
        blocker_class=blocker_class,
        risk=risk,
        remote_effects=False,
        require_available=require_available,
    ):
        if require_available and authorization.get("status") != "granted":
            raise WorkflowError(
                f"Superseding review requires an unused authorization scope; "
                f"{authorization_scope} is exhausted or revoked"
            )
        raise WorkflowError(
            f"Superseding review authorization scope {authorization_scope} "
            f"does not cover {ticket_id}/{blocker_class}/{risk}"
        )
    if root_cycle:
        bound_root = str(authorization.get("root_cause_id", "")).strip()
        bound_reviewer = str(authorization.get("reviewer", "")).strip()
        if not bound_root or not bound_reviewer:
            raise WorkflowError(
                "Root-cycle verification requires a review_round_override scope "
                "pre-bound to its canonical root and reviewer"
            )
        if bound_root != root_cause_id:
            raise WorkflowError(
                f"Superseding review authorization scope {authorization_scope} "
                f"is bound to canonical root {bound_root}"
            )
        if bound_reviewer != reviewer:
            raise WorkflowError(
                f"Superseding review authorization scope {authorization_scope} "
                f"is bound to reviewer {bound_reviewer}"
            )
    prior_at = recorded_at(prior.get("recorded_at"))
    repairs = runtime.get("repairs", {}).get(ticket_id, [])
    authorizations = runtime.get("authorizations", {})
    root_overrides = runtime.get("repair_overrides", {}).get(root_cause_id, [])

    def is_authorized_later_repair(item: object) -> bool:
        if not isinstance(item, dict):
            return False
        scope = str(item.get("budget_override_authorization_scope", "")).strip()
        override = authorizations.get(scope) if isinstance(authorizations, dict) else None
        override_uses = override.get("uses", 0) if isinstance(override, dict) else 0
        return bool(
            item.get("root_cause_id") == root_cause_id
            and item.get("consumes_budget", True)
            and (
                root_cycle
                or (
                    prior_at is not None
                    and (
                        recorded_at(item.get("recorded_at"))
                        or dt.datetime.min.replace(tzinfo=dt.timezone.utc)
                    )
                    > prior_at
                )
            )
            and scope
            and isinstance(root_overrides, list)
            and any(
                isinstance(entry, dict)
                and entry.get("authorization_scope") == scope
                for entry in root_overrides
            )
            and isinstance(override, dict)
            and authorization_record_covers(
                override,
                action="repair_budget_override",
                ticket_id=ticket_id,
                blocker_class=blocker_class,
                risk=risk,
                remote_effects=False,
                require_available=False,
            )
            and not isinstance(override_uses, bool)
            and override_uses >= 1
        )

    candidate_repairs = repairs if isinstance(repairs, list) else []
    if root_cycle:
        root_repairs = [
            item
            for item in candidate_repairs
            if isinstance(item, dict)
            and item.get("root_cause_id") == root_cause_id
            and item.get("consumes_budget", True)
        ]
        candidate_repairs = root_repairs[1:]
    later_repair = any(is_authorized_later_repair(item) for item in candidate_repairs)
    if not later_repair:
        raise WorkflowError(
            "Superseding review requires a later budget-consuming repair with a "
            "separately authorized repair_budget_override scope for canonical root "
            f"{root_cause_id}"
        )
    prior_open = {
        str(item.get("id")): item
        for item in prior.get("findings", [])
        if isinstance(item, dict) and item.get("severity") in blocking_severities
    }
    if isinstance(targeted, dict) and not prior_open:
        raise WorkflowError(
            "Targeted escalation must retain at least one blocking finding"
        )
    resolved_ids = set(resolved)
    if len(resolved_ids) != len(resolved) or not resolved_ids.issubset(prior_open):
        raise WorkflowError(
            "--resolved must uniquely name findings in the prior root-cycle review"
            if root_cycle
            else "--resolved must uniquely name findings in the targeted escalation"
        )
    remaining = {
        finding_id: dict(item)
        for finding_id, item in prior_open.items()
        if finding_id not in resolved_ids
    }
    for item in findings:
        finding_id = str(item.get("id", ""))
        if finding_id not in prior_open:
            raise WorkflowError(
                "Superseding --finding must reuse a blocking finding still open "
                f"in the prior root-cycle review: {finding_id}"
                if root_cycle
                else "Superseding --finding must reuse a blocking finding still "
                f"open in the targeted escalation: {finding_id}"
            )
        if finding_id in resolved_ids:
            raise WorkflowError(
                f"Superseding finding {finding_id} cannot be both resolved and open"
            )
        prior_finding = prior_open[finding_id]
        if item.get("severity") != prior_finding.get("severity"):
            raise WorkflowError(
                f"Superseding finding {finding_id} must retain its targeted severity"
            )
        retained = dict(prior_finding)
        retained["summary"] = item["summary"]
        remaining[finding_id] = retained
    if verdict in {"pass", "pass_with_notes"} and remaining:
        raise WorkflowError(
            "Superseding passing verdict leaves unresolved blocking findings: "
            + ", ".join(sorted(remaining))
        )
    if verdict == "escalate" and not remaining:
        raise WorkflowError(
            "Superseding escalation must retain at least one blocking finding"
        )
    expected_supersedes = {
        "round": str(prior.get("round", "")),
        "candidate_sha": prior_sha,
        "verdict": str(prior.get("verdict", "")),
    }
    if (
        (not require_available or supersedes is not None)
        and supersedes != expected_supersedes
    ):
        raise WorkflowError(
            "Superseding record must exactly preserve targeted SHA/verdict"
        )
    return list(remaining.values()), authorization, expected_supersedes


def review_gate_status(
    ticket: Ticket,
    runtime: dict[str, Any],
    cfg: dict[str, Any],
) -> tuple[bool, list[str]]:
    ticket_reviews = runtime.get("reviews", {}).get(ticket.id, {})
    root_cycles = (
        ticket_reviews.get("root_cycles", [])
        if isinstance(ticket_reviews, dict)
        else []
    )
    if isinstance(root_cycles, list) and root_cycles:
        cycle = root_cycles[-1]
        if not isinstance(cycle, dict):
            return False, ["latest root review cycle is invalid"]
        root_cause_id = str(cycle.get("root_cause_id", ""))
        reviewers = cycle.get("reviewers", {})
        failures: list[str] = []
        final_sha = ""
        for reviewer in ticket.required_reviews:
            rounds = reviewers.get(reviewer, {}) if isinstance(reviewers, dict) else {}
            if not isinstance(rounds, dict) or not isinstance(
                rounds.get("full"),
                dict,
            ):
                failures.append(f"{reviewer} root review baseline is missing")
                continue
            invariant_errors = root_cycle_round_invariant_errors(
                rounds,
                set(cfg.get("review", {}).get("blocking_severities", [])),
            )
            if invariant_errors:
                failures.extend(
                    f"{reviewer} root review is invalid: {error}"
                    for error in invariant_errors
                )
                continue
            record = None
            terminal_round = ""
            for round_name in ("superseding", "targeted", "full"):
                if round_name in rounds:
                    record = rounds[round_name]
                    terminal_round = round_name
                    break
            if not isinstance(record, dict):
                failures.append(f"missing {reviewer} final review")
                continue
            record_root = str(record.get("root_cause_id", "")).strip()
            if (
                terminal_round == "superseding"
                and record_root != root_cause_id
            ) or (
                terminal_round != "superseding"
                and record_root
                and record_root != root_cause_id
            ):
                failures.append(
                    f"{reviewer} final review is not bound to {root_cause_id}"
                )
                continue
            verdict = str(record.get("verdict", ""))
            if not _review_passes(verdict, cfg):
                failures.append(
                    f"{reviewer} final review verdict is {verdict or 'missing'}"
                )
                continue
            candidate_sha = str(record.get("candidate_sha", "")).lower()
            if not candidate_sha:
                failures.append(f"{reviewer} final review candidate is missing")
            elif not final_sha:
                final_sha = candidate_sha
            elif candidate_sha != final_sha:
                failures.append(
                    f"{reviewer} final review candidate {candidate_sha or 'missing'} "
                    f"does not match {final_sha}"
                )
        return not failures, failures

    reviewers = ticket_reviews.get("reviewers", {}) if isinstance(ticket_reviews, dict) else {}
    failures: list[str] = []
    for reviewer in ticket.required_reviews:
        rounds = reviewers.get(reviewer, {}) if isinstance(reviewers, dict) else {}
        record = None
        if isinstance(rounds, dict):
            record = (
                rounds.get("superseding")
                or rounds.get("targeted")
                or rounds.get("full")
            )
        if not isinstance(record, dict):
            failures.append(f"missing {reviewer} review")
            continue
        verdict = str(record.get("verdict", ""))
        if not _review_passes(verdict, cfg):
            failures.append(f"{reviewer} review verdict is {verdict or 'missing'}")
    return not failures, failures


def _append_review_debt(
    root: Path,
    cfg: dict[str, Any],
    *,
    ticket_id: str,
    reviewer: str,
    candidate_sha: str,
    notes: Sequence[str],
) -> None:
    if not notes or not bool(cfg.get("review", {}).get("write_advisories_to_backlog", True)):
        return
    raw = str(cfg.get("documents", {}).get("review_debt", "docs/review-debt.md"))
    path = root / raw
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(
            "# Review Debt\n\nNon-blocking findings accepted for integration.\n\n",
            encoding="utf-8",
        )
    existing = path.read_text(encoding="utf-8")
    entries: list[str] = []
    for note in notes:
        fingerprint = hashlib.sha256(
            f"{ticket_id}|{reviewer}|{candidate_sha}|{note}".encode("utf-8")
        ).hexdigest()[:12]
        marker = f"<!-- review-debt:{fingerprint} -->"
        if marker in existing:
            continue
        entries.append(
            f"{marker}\n- `{ticket_id}` `{reviewer}` `{candidate_sha[:12]}`: {note}\n"
        )
    if entries:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write("".join(entries))


def cmd_record_review(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    tickets = load_tickets(root, cfg)
    ticket = find_ticket(tickets, args.ticket_id)
    reviewer = args.reviewer
    round_name = args.round
    verdict = args.verdict
    candidate_sha = args.candidate_sha.lower()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", candidate_sha):
        raise WorkflowError("--candidate-sha must be an exact 40- or 64-hex commit ID")
    if reviewer not in REVIEWERS or round_name not in REVIEW_ROUNDS:
        raise WorkflowError("Invalid review role or round")
    root_cause_id = str(args.root_blocker).strip()
    root_scoped = bool(root_cause_id)
    if round_name != "superseding" and str(args.authorization_scope).strip():
        raise WorkflowError(
            "--authorization-scope is only valid for superseding review"
        )

    findings = [_parse_review_finding(raw, new=False) for raw in args.finding]
    new_findings = [_parse_review_finding(raw, new=True) for raw in args.new_finding]
    all_ids = [str(item["id"]) for item in findings + new_findings]
    if len(all_ids) != len(set(all_ids)):
        raise WorkflowError("Review finding IDs must be unique in one record")
    blocking_severities = set(cfg.get("review", {}).get("blocking_severities", []))
    blocking = [item for item in findings + new_findings if item["severity"] in blocking_severities]
    if round_name != "superseding" and verdict == "block" and not blocking:
        raise WorkflowError("A block verdict requires at least one blocking finding")
    if (
        round_name != "superseding"
        and verdict in {"pass", "pass_with_notes"}
        and blocking
    ):
        raise WorkflowError("A passing verdict cannot contain unresolved blocking findings")
    if verdict == "pass_with_notes" and not any(str(note).strip() for note in args.note):
        raise WorkflowError("pass_with_notes requires at least one --note")
    if root_scoped and round_name == "full" and verdict == "escalate":
        raise WorkflowError(
            "Root-scoped full review verdict must be pass, pass_with_notes, or block"
        )

    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)
    if root_scoped:
        canonical_review_root(
            runtime,
            ticket.id,
            root_cause_id,
            require_open=True,
        )
    phase = runtime.get("phases", {}).get(ticket.id, {})
    if isinstance(phase, dict) and phase.get("phase") == "review":
        phase_sha = str(phase.get("candidate_sha", "")).lower()
        if phase_sha and phase_sha != candidate_sha:
            raise WorkflowError(
                f"Review candidate {candidate_sha} does not match active review SHA {phase_sha}"
            )
    review_cfg = cfg.get("review", {})
    ticket_reviews = runtime["reviews"].setdefault(ticket.id, {"reviewers": {}})
    cycle = find_root_review_cycle(ticket_reviews, root_cause_id) if root_scoped else None
    legacy_reviewer_rounds = ticket_reviews.setdefault("reviewers", {}).setdefault(
        reviewer,
        {},
    )
    root_cycle_scoped = root_scoped and not (
        round_name == "superseding"
        and cycle is None
        and isinstance(legacy_reviewer_rounds.get("full"), dict)
        and isinstance(legacy_reviewer_rounds.get("targeted"), dict)
    )
    if root_cycle_scoped:
        if cycle is None:
            if round_name != "full":
                raise WorkflowError(
                    f"Root-scoped {round_name} review requires an existing full "
                    f"review cycle for {root_cause_id}"
                )
            cycle = {
                "root_cause_id": root_cause_id,
                "ticket_id": ticket.id,
                "reviewers": {},
            }
            ticket_reviews.setdefault("root_cycles", []).append(cycle)
        elif str(cycle.get("ticket_id", "")).upper() != ticket.id.upper():
            raise WorkflowError(
                f"Root review cycle {root_cause_id} belongs to "
                f"{cycle.get('ticket_id')}, not {ticket.id}"
            )
        cycle_reviewers = cycle.setdefault("reviewers", {})
        if not isinstance(cycle_reviewers, dict):
            raise WorkflowError("Root-scoped review cycle reviewers must be an object")
        reviewer_rounds = cycle_reviewers.setdefault(reviewer, {})
    else:
        reviewer_rounds = legacy_reviewer_rounds
    record_extra: dict[str, Any] = {}
    authorization_to_consume: dict[str, Any] | None = None

    if round_name == "full":
        maximum = int(review_cfg.get("max_full_review_rounds", 1))
        if "full" in reviewer_rounds:
            existing = reviewer_rounds["full"]
            same = (
                existing.get("candidate_sha") == candidate_sha
                and existing.get("verdict") == verdict
                and existing.get("findings") == findings
                and existing.get("notes", []) == args.note
            )
            if same:
                print(f"Review already recorded: {ticket.id} {reviewer} full")
                return 0 if _review_passes(verdict, cfg) else 1
            raise WorkflowError(
                f"{ticket.id} {reviewer} already used its full review round; "
                "record a targeted re-review or escalate"
            )
        if maximum < 1:
            raise WorkflowError("Full review rounds are disabled by configuration")
        if new_findings:
            raise WorkflowError("--new-finding is valid only for targeted re-review")
        record_findings = findings
    elif round_name == "targeted":
        maximum = int(review_cfg.get("max_targeted_repair_rounds", 1))
        if "targeted" in reviewer_rounds:
            raise WorkflowError(
                f"{ticket.id} {reviewer} already used its targeted re-review round; escalate"
            )
        if maximum < 1:
            raise WorkflowError("Targeted review rounds are disabled by configuration")
        full = reviewer_rounds.get("full")
        if not isinstance(full, dict) or full.get("verdict") != "block":
            raise WorkflowError("Targeted re-review requires a prior blocking full review")
        if root_scoped and candidate_sha == str(full.get("candidate_sha", "")).lower():
            raise WorkflowError(
                "Root-scoped targeted candidate must differ from the full-review SHA"
            )
        repairs = runtime.get("repairs", {}).get(ticket.id, [])
        qualifying_repairs = (
            [
                item
                for item in repairs
                if isinstance(item, dict)
                and bool(item.get("consumes_budget", True))
                and (
                    not root_cycle_scoped
                    or item.get("root_cause_id") == root_cause_id
                )
            ]
            if isinstance(repairs, list)
            else []
        )
        if not qualifying_repairs:
            raise WorkflowError(
                "Targeted re-review requires one recorded substantive/evidence repair; "
                "a mechanical-only change does not consume the review repair round"
            )
        if verdict == "block":
            raise WorkflowError(
                "A second blocking verdict must be recorded as escalate; automatic repair is exhausted"
            )
        original_blocking = {
            str(item.get("id")): item
            for item in full.get("findings", [])
            if isinstance(item, dict) and item.get("severity") in blocking_severities
        }
        unknown_resolved = sorted(set(args.resolved) - set(original_blocking))
        if root_scoped and len(args.resolved) != len(set(args.resolved)):
            raise WorkflowError(
                "Root-scoped --resolved must contain unique finding IDs"
            )
        if unknown_resolved:
            raise WorkflowError(
                "--resolved contains unknown full-review findings: "
                + ", ".join(unknown_resolved)
            )
        policy = str(
            review_cfg.get("new_blockers_after_first_review", "introduced_by_repair_only")
        )
        allowed_origins: set[str]
        if policy == "none":
            allowed_origins = set()
        elif policy == "introduced_by_repair_only":
            allowed_origins = {"introduced_by_repair"}
        else:
            allowed_origins = set(NEW_REVIEW_BLOCKER_ORIGINS)
        disallowed = [item for item in new_findings if item["origin"] not in allowed_origins]
        if disallowed:
            raise WorkflowError(
                "New targeted-review blockers violate policy: "
                + ", ".join(str(item["id"]) for item in disallowed)
            )
        resolved_ids = set(args.resolved)
        remaining_by_id = {
            finding_id: dict(item)
            for finding_id, item in original_blocking.items()
            if finding_id not in resolved_ids
        }
        for item in findings:
            finding_id = str(item["id"])
            if finding_id not in original_blocking:
                raise WorkflowError(
                    "Targeted --finding must reuse an original full-review ID; "
                    f"use --new-finding for {finding_id}"
                )
            if finding_id in resolved_ids:
                raise WorkflowError(
                    f"Targeted finding {finding_id} cannot be both --resolved and still open"
                )
            if root_scoped and (
                item.get("severity") != original_blocking[finding_id].get("severity")
                or item.get("origin") != original_blocking[finding_id].get("origin")
            ):
                raise WorkflowError(
                    f"Root-scoped targeted finding {finding_id} must preserve "
                    "severity and provenance"
                )
            remaining_by_id[finding_id] = item
        for item in new_findings:
            finding_id = str(item["id"])
            if finding_id in original_blocking or finding_id in remaining_by_id:
                raise WorkflowError(f"New targeted finding ID already exists: {finding_id}")
            remaining_by_id[finding_id] = item
        record_findings = list(remaining_by_id.values())
        remaining_blocking = [
            item for item in record_findings if item.get("severity") in blocking_severities
        ]
        if verdict in {"pass", "pass_with_notes"} and remaining_blocking:
            raise WorkflowError(
                "Targeted passing verdict leaves unresolved blocking findings: "
                + ", ".join(str(item["id"]) for item in remaining_blocking)
            )
        if verdict == "escalate" and not remaining_blocking:
            raise WorkflowError("Escalate verdict requires an unresolved blocking finding")
    else:
        if "superseding" in reviewer_rounds:
            raise WorkflowError(
                f"{ticket.id} {reviewer} already used its superseding review round"
            )
        authorization_scope = str(args.authorization_scope).strip()
        record_findings, authorization_to_consume, supersedes = (
            validate_superseding_review(
                runtime=runtime,
                ticket_id=ticket.id,
                reviewer=reviewer,
                reviewer_rounds=reviewer_rounds,
                candidate_sha=candidate_sha,
                verdict=verdict,
                findings=findings,
                new_findings=new_findings,
                resolved=args.resolved,
                root_cause_id=root_cause_id,
                authorization_scope=authorization_scope,
                blocking_severities=blocking_severities,
                phase=phase if isinstance(phase, dict) else {},
                root_cycle=root_cycle_scoped,
            )
        )
        record_extra = {
            "authorization_scope": authorization_scope,
            "root_cause_id": root_cause_id,
            "supersedes": supersedes,
        }

    record = {
        "round": round_name,
        "reviewer": reviewer,
        "candidate_sha": candidate_sha,
        "verdict": verdict,
        "findings": record_findings,
        "resolved": list(args.resolved),
        "notes": list(args.note),
        "recorded_at": utc_now(),
        **record_extra,
    }
    if authorization_to_consume is not None:
        consume_authorization_record(authorization_to_consume)
    reviewer_rounds[round_name] = record
    path = save_runtime_state(root, cfg, state)
    if verdict == "pass_with_notes":
        _append_review_debt(
            root,
            cfg,
            ticket_id=ticket.id,
            reviewer=reviewer,
            candidate_sha=candidate_sha,
            notes=args.note,
        )
    print(
        f"Recorded {round_name} review: {ticket.id} {reviewer} {verdict} "
        f"({relative(root, path)})"
    )
    return 0 if _review_passes(verdict, cfg) else 1


def cmd_review_state(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    tickets = load_tickets(root, cfg)
    ticket = find_ticket(tickets, args.ticket_id)
    state = load_runtime_state(root, cfg)
    runtime = state.get("milestones", {}).get(ticket.milestone.upper(), {})
    ticket_reviews = runtime.get("reviews", {}).get(ticket.id, {}) if isinstance(runtime, dict) else {}
    passed, failures = review_gate_status(ticket, runtime if isinstance(runtime, dict) else {}, cfg)
    payload = {
        "ticket": ticket.id,
        "milestone": ticket.milestone,
        "required_reviews": ticket.required_reviews,
        "gate_passed": passed,
        "failures": failures,
        "reviews": ticket_reviews,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Review gate for {ticket.id}: {'PASS' if passed else 'BLOCK'}")
        for failure in failures:
            print(f"  - {failure}")
    return 0 if passed else 1

def cmd_bootstrap(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    docs = cfg["documents"]
    created: list[str] = []
    for key in ("adr_dir", "spec_dir", "test_plan_dir", "ticket_dir", "handoff_dir"):
        path = root / str(docs[key])
        if not path.exists():
            path.mkdir(parents=True)
            created.append(relative(root, path) + "/")

    assets = asset_dir()
    mapping = {
        "vision": (str(docs["vision"]), "vision.md"),
        "gap_analysis": (str(docs["gap_analysis"]), "gap-analysis.md"),
        "roadmap": (str(docs["roadmap"]), "roadmap.md"),
        "ci_status": (str(docs["ci_status"]), "ci-status.md"),
        "review_debt": (str(docs["review_debt"]), "review-debt.md"),
    }
    mapping.update(
        {
            f"template:{destination}": (destination, source)
            for destination, source in document_template_mapping(cfg).items()
        }
    )
    for destination, source_name in mapping.values():
        source = assets / source_name
        if source.exists() and write_if_missing(root / destination, source):
            created.append(destination)

    worktree_root = str(cfg["workflow"]["worktree_root"]).rstrip("/") + "/"
    if append_gitignore(root, worktree_root):
        created.append(".gitignore (appended worktree ignore)")

    print("Bootstrap complete.")
    if created:
        for item in created:
            print(f"  created: {item}")
    else:
        print("  no files were missing")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    errors: list[str] = []
    warnings: list[str] = []

    for key in ("vision", "gap_analysis", "roadmap", "ci_status", "review_debt"):
        path = root / str(cfg["documents"][key])
        if not path.exists():
            errors.append(f"Missing document: {relative(root, path)}")
    for key in ("adr_dir", "spec_dir", "test_plan_dir", "ticket_dir", "handoff_dir"):
        path = root / str(cfg["documents"][key])
        if not path.is_dir():
            errors.append(f"Missing document directory: {relative(root, path)}")
    for destination, source_name in document_template_mapping(cfg).items():
        destination_path = root / destination
        source_path = asset_dir() / source_name
        if not destination_path.exists() or not source_path.exists():
            continue
        if destination_path.read_text(encoding="utf-8") != source_path.read_text(
            encoding="utf-8"
        ):
            errors.append(
                f"Document template drift: {destination} must match "
                f"assets/templates/{source_name}"
            )

    planning_limits = cfg.get("planning", {})
    for directory_key, limit_key, label in (
        ("spec_dir", "spec_soft_line_limit", "spec"),
        ("test_plan_dir", "test_plan_soft_line_limit", "test plan"),
    ):
        directory = root / str(cfg["documents"][directory_key])
        limit = int(planning_limits.get(limit_key, 400 if label == "spec" else 300))
        if directory.is_dir():
            for path in sorted(directory.glob("*.md")):
                if path.name.lower() == "readme.md" or "template" in path.name.lower():
                    continue
                line_count = len(path.read_text(encoding="utf-8").splitlines())
                if line_count > limit:
                    warnings.append(
                        f"{relative(root, path)} has {line_count} lines, above the "
                        f"{label} soft limit of {limit}; prefer outcome contracts and "
                        "move supporting detail to references"
                    )

    ticket_errors, ticket_warnings, _ = validate_tickets(root, cfg)
    errors.extend(ticket_errors)
    warnings.extend(ticket_warnings)

    validation = cfg.get("validation", {})
    if not isinstance(validation, dict):
        errors.append("validation must be a table")
        validation = {}
    for scope, commands in validation.items():
        if not isinstance(commands, list):
            errors.append(f"validation.{scope} must be an array of command strings")
        elif any(not isinstance(command, str) or not command.strip() for command in commands):
            errors.append(f"validation.{scope} contains an invalid command")
    for scope in ("quick", "full"):
        if not validation.get(scope):
            warnings.append(f"validation.{scope} is empty; that gate cannot pass")

    execution = cfg.get("execution", {})
    strategy = execution.get("strategy")
    if strategy not in {"drain", "wave"}:
        errors.append("execution.strategy must be 'drain' or 'wave'")
    for key, minimum in (
        ("max_waves_per_run", 0),
        ("max_repair_attempts_per_ticket", 0),
        ("no_progress_limit", 1),
    ):
        value = execution.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            errors.append(f"execution.{key} must be an integer >= {minimum}")
    for key in ("continue_after_independent_failure", "auto_close"):
        if not isinstance(execution.get(key), bool):
            errors.append(f"execution.{key} must be true or false")
    repair_budget = execution.get("repair_budget")
    if not isinstance(repair_budget, dict):
        errors.append("execution.repair_budget must be a table")
    else:
        for risk in sorted(RISK_LEVELS):
            value = repair_budget.get(risk)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(
                    f"execution.repair_budget.{risk} must be an integer >= 0"
                )
    non_counting = execution.get("non_counting_repair_classes")
    if not isinstance(non_counting, list) or any(
        item not in REPAIR_CLASSES for item in non_counting
    ):
        errors.append(
            "execution.non_counting_repair_classes must contain only "
            + ", ".join(sorted(REPAIR_CLASSES))
        )

    planning = cfg.get("planning", {})
    if not isinstance(planning, dict):
        errors.append("planning must be a table")
        planning = {}
    if planning.get("contract_style") not in {"outcome", "prescriptive"}:
        errors.append("planning.contract_style must be outcome or prescriptive")
    for key, minimum in (
        ("max_adrs_per_milestone", 0),
        ("spec_soft_line_limit", 1),
        ("test_plan_soft_line_limit", 1),
        ("max_acceptance_criteria_per_ticket", 1),
    ):
        value = planning.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            errors.append(f"planning.{key} must be an integer >= {minimum}")
    if not isinstance(planning.get("allow_new_adr_during_execute"), bool):
        errors.append("planning.allow_new_adr_during_execute must be true or false")

    review = cfg.get("review", {})
    if not isinstance(review, dict):
        errors.append("review must be a table")
        review = {}
    severities = review.get("blocking_severities")
    if not isinstance(severities, list) or not severities or any(
        item not in REVIEW_FINDING_SEVERITIES for item in severities
    ):
        errors.append(
            "review.blocking_severities must be a non-empty array of valid severities"
        )
    for key in ("max_full_review_rounds", "max_targeted_repair_rounds"):
        value = review.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"review.{key} must be an integer >= 0")
    if review.get("new_blockers_after_first_review") not in {
        "none",
        "introduced_by_repair_only",
        "introduced_by_repair_or_previously_unobservable",
    }:
        errors.append(
            "review.new_blockers_after_first_review has an unsupported policy"
        )
    for key in (
        "pass_with_notes_integrates",
        "freeze_contract_on_execute",
        "write_advisories_to_backlog",
    ):
        if not isinstance(review.get(key), bool):
            errors.append(f"review.{key} must be true or false")

    quality = cfg.get("quality", {})
    if not isinstance(quality, dict):
        errors.append("quality must be a table")
        quality = {}
    test_budget = quality.get("test_budget", {})
    if not isinstance(test_budget, dict):
        errors.append("quality.test_budget must be a table")
        test_budget = {}
    if not isinstance(test_budget.get("enabled"), bool):
        errors.append("quality.test_budget.enabled must be true or false")
    if test_budget.get("tool") not in TEST_BUDGET_TOOLS:
        errors.append("quality.test_budget.tool must be auto, builtin, or rustloc")
    if test_budget.get("mode") not in TEST_BUDGET_MODES:
        errors.append("quality.test_budget.mode must be ratchet, strict, or off")
    for key, minimum in (
        ("target_ratio", 0.0),
        ("warn_ratio", 0.0),
        ("max_regression", 0.0),
        ("ratchet_step", 0.0),
        ("max_delta_ratio", 0.0),
    ):
        value = test_budget.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < minimum:
            errors.append(f"quality.test_budget.{key} must be a number >= {minimum}")
    for key, minimum in (("delta_test_allowance", 0), ("min_code_lines", 0)):
        value = test_budget.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            errors.append(f"quality.test_budget.{key} must be an integer >= {minimum}")
    if not str(test_budget.get("baseline_path", "")).strip():
        errors.append("quality.test_budget.baseline_path must not be empty")
    extensions = test_budget.get("include_extensions")
    if not isinstance(extensions, list) or not extensions or any(
        not isinstance(item, str) or not item.startswith(".") for item in extensions
    ):
        errors.append(
            "quality.test_budget.include_extensions must be a non-empty array of extensions"
        )
    excludes = test_budget.get("exclude_globs")
    if not isinstance(excludes, list) or any(not isinstance(item, str) for item in excludes):
        errors.append("quality.test_budget.exclude_globs must be an array of strings")

    checkpoint_policy = cfg.get("workflow", {}).get("checkpoint_policy")
    if checkpoint_policy not in {"transition", "wave", "integration"}:
        errors.append(
            "workflow.checkpoint_policy must be transition, wave, or integration"
        )
    try:
        runtime_state_path(root, cfg)
        load_runtime_state(root, cfg)
    except WorkflowError as exc:
        errors.append(str(exc))

    agents = cfg.get("agents")
    if not isinstance(agents, dict):
        errors.append("agents must be a table")
    else:
        for role in ("product_manager", "architect", "engineer", "qa"):
            profile = agents.get(role)
            if not isinstance(profile, dict):
                errors.append(f"agents.{role} must be a table")
                continue
            for field in ("config", "name", "model", "reasoning_effort"):
                if not str(profile.get(field, "")).strip():
                    errors.append(f"agents.{role}.{field} must not be empty")

    if warnings:
        print("Warnings:")
        for warning in sorted(set(warnings)):
            print(f"  - {warning}")
    if errors:
        print("Errors:")
        for error in sorted(set(errors)):
            print(f"  - {error}")
        return 1
    print("Workflow validation passed.")
    return 0


def discover_skills(root: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = collections.defaultdict(list)
    roots = [root / ".agents" / "skills", Path.home() / ".agents" / "skills"]
    for skill_root in roots:
        if not skill_root.exists():
            continue
        try:
            paths = list(skill_root.rglob("SKILL.md"))
        except OSError:
            continue
        for path in paths:
            try:
                head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:30])
            except OSError:
                continue
            match = re.search(r"(?m)^name:\s*[\"']?([^\"'\n]+)", head)
            if match:
                found[match.group(1).strip()].append(str(path))
    return dict(found)


def cmd_doctor(args: argparse.Namespace) -> int:
    failures: list[str] = []
    warnings: list[str] = []
    print(f"Python: {sys.version.split()[0]}")
    if sys.version_info < MIN_PYTHON:
        failures.append("Python 3.11+ is required")
    if shutil.which("git") is None:
        failures.append("git is not on PATH")
        root = Path.cwd()
    else:
        try:
            root = git_root()
            print(f"Repository: {root}")
        except WorkflowError as exc:
            failures.append(str(exc))
            root = Path.cwd()
    try:
        cfg = load_config(root)
        print(f"Base branch: {cfg['workflow']['base_branch']}")
        print(f"Worktree root: {cfg['workflow']['worktree_root']}")
        print(f"Execute strategy: {cfg['execution']['strategy']}")
        max_waves = int(cfg['execution']['max_waves_per_run'])
        print(f"Max waves per execute run: {max_waves or 'unlimited'}")
        print(f"Auto close: {cfg['execution']['auto_close']}")
        print(f"Checkpoint policy: {cfg['workflow']['checkpoint_policy']}")
        print(f"Runtime state: {runtime_state_path(root, cfg)}")
    except WorkflowError as exc:
        failures.append(str(exc))
        cfg = deep_merge(DEFAULT_CONFIG, {})

    required_files = [
        root / "AGENTS.md",
        root / "workflow.toml",
        root / ".codex" / "config.toml",
        root / ".agents" / "skills" / "milestone-workflow" / "SKILL.md",
    ]
    profiles = cfg.get("agents", {})
    if not isinstance(profiles, dict):
        profiles = {}
    for profile in profiles.values():
        if isinstance(profile, dict) and str(profile.get("config", "")).strip():
            required_files.append(root / str(profile["config"]))
    for path in required_files:
        if not path.exists():
            failures.append(f"Missing workflow file: {relative(root, path)}")

    agents_doc = root / "AGENTS.md"
    if agents_doc.exists() and "<!-- BEGIN CODEX MILESTONE WORKFLOW -->" not in agents_doc.read_text(encoding="utf-8"):
        warnings.append("AGENTS.md does not contain the milestone workflow section")

    codex_config = root / ".codex" / "config.toml"
    if codex_config.exists():
        try:
            with codex_config.open("rb") as handle:
                parsed_codex = tomllib.load(handle)
            agent_cfg = parsed_codex.get("agents", {})
            if isinstance(agent_cfg, dict) and agent_cfg.get("enabled") is False:
                failures.append(".codex/config.toml disables subagents")
        except (OSError, tomllib.TOMLDecodeError) as exc:
            failures.append(f"Cannot parse .codex/config.toml: {exc}")

    for role, profile in profiles.items():
        if not isinstance(profile, dict):
            failures.append(f"agents.{role} must be a table")
            continue
        role_path = root / str(profile.get("config", ""))
        if not role_path.exists():
            continue
        try:
            with role_path.open("rb") as handle:
                role_cfg = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            failures.append(f"Cannot parse {relative(root, role_path)}: {exc}")
            continue
        for field in ("name", "description", "developer_instructions"):
            if not str(role_cfg.get(field, "")).strip():
                failures.append(f"{relative(root, role_path)} missing required field {field}")
        expected_fields = {
            "name": profile.get("name"),
            "model": profile.get("model"),
            "model_reasoning_effort": profile.get("reasoning_effort"),
        }
        for field, expected in expected_fields.items():
            if role_cfg.get(field) != expected:
                failures.append(
                    f"{relative(root, role_path)} defines {field}="
                    f"{role_cfg.get(field)!r}; expected {expected!r}"
                )
        print(
            f"Agent profile {role}: {role_cfg.get('model')} / "
            f"{role_cfg.get('model_reasoning_effort')}"
        )

    if root.joinpath(".gitignore").exists():
        ignored = {line.strip() for line in root.joinpath(".gitignore").read_text(encoding="utf-8").splitlines()}
        expected_ignore = str(cfg["workflow"]["worktree_root"]).rstrip("/") + "/"
        if expected_ignore not in ignored:
            warnings.append(f".gitignore does not contain {expected_ignore}")

    try:
        configured_base = str(cfg["workflow"]["base_branch"])
        if not branch_exists(root, configured_base):
            pending_branch = unborn_branch(root)
            if pending_branch == configured_base:
                warnings.append(
                    f"Configured base branch {configured_base} is unborn; commit the "
                    "installed workflow before plan/execute creates worktrees"
                )
            else:
                failures.append(f"Configured base branch does not exist: {configured_base}")
    except WorkflowError:
        pass

    if shutil.which("codex") is None:
        warnings.append("codex CLI is not on PATH; desktop/IDE use may still work")

    skills = discover_skills(root)
    optional = {
        "research",
        "prototype",
        "tdd",
        "domain-modeling",
        "codebase-design",
        "code-review",
        "diagnosing-bugs",
        "resolving-merge-conflicts",
    }
    present = sorted(optional & set(skills))
    missing = sorted(optional - set(skills))
    print("Optional Matt-style model-invoked skills found: " + (", ".join(present) or "none"))
    if missing:
        warnings.append("Optional skills not found: " + ", ".join(missing))

    ticket_errors, ticket_warnings, _ = validate_tickets(root, cfg)
    failures.extend(ticket_errors)
    warnings.extend(ticket_warnings)
    for scope in ("quick", "full"):
        commands = cfg.get("validation", {}).get(scope, [])
        if not commands:
            warnings.append(f"workflow.toml validation.{scope} is empty")

    if warnings:
        print("Warnings:")
        for warning in sorted(set(warnings)):
            print(f"  - {warning}")
    if failures:
        print("Failures:")
        for failure in sorted(set(failures)):
            print(f"  - {failure}")
        return 1
    print("Doctor checks passed.")
    return 0


def ticket_to_dict(root: Path, ticket: Ticket) -> dict[str, Any]:
    return {
        "id": ticket.id,
        "title": ticket.title,
        "milestone": ticket.milestone,
        "status": ticket.status,
        "priority": ticket.priority,
        "risk": ticket.risk,
        "required_reviews": ticket.required_reviews,
        "blocked_by": ticket.blockers,
        "implementation_blocked_by": ticket.implementation_blockers,
        "review_blocked_by": ticket.review_blockers,
        "integration_blocked_by": ticket.integration_blockers,
        "release_blocked_by": ticket.release_blockers,
        "blocker": ticket.blocker_record,
        "owns": ticket.owns,
        "spec": ticket.spec,
        "test_plan": ticket.test_plan,
        "path": relative(root, ticket.path),
    }


def cmd_frontier(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    errors, warnings, tickets = validate_tickets(root, cfg)
    if errors:
        raise WorkflowError("Ticket validation failed; run workflow.py validate")
    limit = args.limit or int(cfg["workflow"]["max_parallel_engineers"])
    limit = min(limit, int(cfg["workflow"]["max_parallel_engineers"]))
    state = load_runtime_state(root, cfg)
    if args.milestone:
        runtime = milestone_runtime_state(state, args.milestone)
        active_entries = active_ticket_phases(tickets, runtime, args.milestone)
    else:
        active_entries = []
        for milestone, runtime in state["milestones"].items():
            active_entries.extend(active_ticket_phases(tickets, runtime, milestone))
        recorded = {ticket.id for ticket, _, _, _ in active_entries}
        active_entries.extend(
            entry
            for entry in active_ticket_phases(tickets, None)
            if entry[0].id not in recorded
        )
    active = [ticket for ticket, _, _, _ in active_entries]
    if args.milestone:
        decision = milestone_scheduler_state(
            tickets,
            args.milestone,
            limit,
            milestone_runtime_state(state, args.milestone),
            bool(cfg["execution"]["continue_after_independent_failure"]),
            cfg,
        )
        by_id = {ticket.id: ticket for ticket in tickets}
        selected = [by_id[ticket_id] for ticket_id in decision["selected"]]
        skipped = [
            (by_id[item["id"]], item["reason"])
            for item in decision["skipped"]
            if item["id"] in by_id
        ]
        available = int(decision["available_engineer_slots"])
    else:
        available = max(
            0,
            limit
            - sum(phase in ACTIVE_WRITER_PHASES for _, phase, _, _ in active_entries),
        )
        if any(phase == "repair" for _, phase, _, _ in active_entries) and not bool(
            cfg["execution"]["continue_after_independent_failure"]
        ):
            available = 0
        selected, skipped = select_frontier(
            tickets,
            args.milestone,
            available,
            reserved=active,
            runtimes={
                str(milestone).upper(): runtime
                for milestone, runtime in state["milestones"].items()
                if isinstance(runtime, dict)
            },
        )
    payload = {
        "milestone": args.milestone,
        "limit": limit,
        "available_engineer_slots": available,
        "selected": [ticket_to_dict(root, ticket) for ticket in selected],
        "skipped": [
            {"ticket": ticket_to_dict(root, ticket), "reason": reason}
            for ticket, reason in skipped
        ],
        "warnings": warnings,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        if selected:
            print("Selected frontier:")
            for ticket in selected:
                print(f"  {ticket.id} [{ticket.priority}] {ticket.title}")
        else:
            print("Selected frontier: none")
        if skipped:
            print("Eligible but not selected:")
            for ticket, reason in skipped:
                print(f"  {ticket.id}: {reason}")
    return 0


def cmd_next(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    errors, warnings, tickets = validate_tickets(root, cfg)
    if errors:
        raise WorkflowError("Ticket validation failed; run workflow.py validate")
    limit = args.limit or int(cfg["workflow"]["max_parallel_engineers"])
    limit = min(limit, int(cfg["workflow"]["max_parallel_engineers"]))
    if limit < 1:
        raise WorkflowError("Frontier limit must be at least 1")
    runtime_state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(runtime_state, args.milestone)
    payload = milestone_scheduler_state(
        tickets,
        args.milestone,
        limit,
        runtime,
        bool(cfg["execution"]["continue_after_independent_failure"]),
        cfg,
    )
    payload["strategy"] = str(cfg["execution"]["strategy"])
    payload["max_waves_per_run"] = int(cfg["execution"]["max_waves_per_run"])
    payload["auto_close"] = bool(cfg["execution"]["auto_close"])
    payload["checkpoint_policy"] = str(cfg["workflow"]["checkpoint_policy"])
    payload["runtime_state_path"] = relative(root, runtime_state_path(root, cfg))
    payload["authorizations"] = runtime["authorizations"]
    payload["repairs"] = runtime["repairs"]
    apply_run_limits(payload, cfg, runtime)
    payload["warnings"] = warnings
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Milestone: {payload['milestone']}")
        print(f"Next action: {payload['action']}")
        print(f"Strategy: {payload['strategy']}")
        if payload["selected"]:
            print("Selected frontier: " + ", ".join(payload["selected"]))
        if payload["active"]:
            print("Active recovery: " + ", ".join(payload["active"]))
        if payload["release_blocked"]:
            for item in payload["release_blocked"]:
                print(
                    f"Release blocked: {item['id']} — "
                    + ", ".join(item["dependencies"])
                )
        for item in payload["blocked"]:
            print(f"Blocked: {item['id']} — {item['reason']}")
    return 0


def worktree_records(root: Path) -> list[dict[str, Any]]:
    proc = run(["git", "worktree", "list", "--porcelain"], cwd=root)
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in proc.stdout.splitlines() + [""]:
        if not line.strip():
            if current:
                path = Path(current["worktree"])
                if path.exists():
                    clean, dirty = is_clean(path)
                    current["clean"] = clean
                    current["dirty"] = dirty
                records.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key in {"bare", "detached", "locked", "prunable"} and not value:
            current[key] = True
        else:
            current[key] = value
    return records


def cmd_worktree_list(args: argparse.Namespace) -> int:
    root = git_root()
    records = worktree_records(root)
    if args.json:
        print(json.dumps(records, indent=2, ensure_ascii=False))
        return 0
    for record in records:
        branch = str(record.get("branch", "detached")).removeprefix("refs/heads/")
        state = "clean" if record.get("clean") else "dirty"
        print(f"{record.get('worktree')}  {branch}  {record.get('HEAD', '?')}  {state}")
        for dirty in record.get("dirty", []):
            print(f"    {dirty}")
    return 0


def ensure_base_branch(root: Path, cfg: dict[str, Any]) -> str:
    base = str(cfg["workflow"]["base_branch"])
    if not branch_exists(root, base):
        raise WorkflowError(
            f"Configured base branch {base!r} does not exist. Update workflow.toml."
        )
    return base


def create_worktree(root: Path, path: Path, branch: str, base: str) -> dict[str, Any]:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        proc = run(["git", "branch", "--show-current"], cwd=path, check=False)
        if proc.returncode != 0:
            raise WorkflowError(f"Worktree path exists but is not a Git worktree: {path}")
        actual = proc.stdout.strip()
        if actual != branch:
            raise WorkflowError(
                f"Worktree {path} is on {actual!r}, expected branch {branch!r}"
            )
        return {"path": str(path), "branch": branch, "created": False}
    if branch_exists(root, branch):
        run(["git", "worktree", "add", str(path), branch], cwd=root)
    else:
        run(["git", "worktree", "add", "-b", branch, str(path), base], cwd=root)
    return {"path": str(path), "branch": branch, "created": True}


def cmd_worktree_create(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    tickets = load_tickets(root, cfg)
    ticket = find_ticket(tickets, args.ticket_id)
    base = ensure_base_branch(root, cfg)
    slug = slugify(ticket.id)
    branch = f"{str(cfg['workflow']['engineer_branch_prefix']).rstrip('/')}/{slug}"
    path = root / str(cfg["workflow"]["worktree_root"]) / slug
    record = create_worktree(root, path, branch, base)
    record.update(
        {
            "ticket": ticket.id,
            "ticket_path": relative(root, ticket.path),
            "base": base,
            "spec": ticket.spec,
            "test_plan": ticket.test_plan,
            "owns": ticket.owns,
        }
    )
    print(json.dumps(record, indent=2, ensure_ascii=False))
    return 0


def cmd_integration_create(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    base = ensure_base_branch(root, cfg)
    slug = slugify(args.milestone)
    branch = f"{str(cfg['workflow']['integration_branch_prefix']).rstrip('/')}/{slug}"
    path = root / str(cfg["workflow"]["worktree_root"]) / f"_integration-{slug}"
    record = create_worktree(root, path, branch, base)
    record.update({"milestone": args.milestone, "base": base, "type": "integration"})
    print(json.dumps(record, indent=2, ensure_ascii=False))
    return 0


def cmd_worktree_remove(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    worktree_root = root / str(cfg["workflow"]["worktree_root"])
    if args.integration:
        slug = f"_integration-{slugify(args.identifier)}"
    else:
        slug = slugify(args.identifier)
    path = (worktree_root / slug).resolve()
    if not path.exists():
        raise WorkflowError(f"Worktree does not exist: {path}")
    clean, dirty = is_clean(path)
    if not clean:
        detail = "\n".join(dirty)
        raise WorkflowError(f"Refusing to remove dirty worktree {path}:\n{detail}")
    run(["git", "worktree", "remove", str(path)], cwd=root, capture=False)
    print(f"Removed clean worktree: {path}")
    print("Branch was preserved.")
    return 0


def replace_bytes_atomic(path: Path, content: bytes) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=path.name + ".",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def replace_status(path: Path, new_status: str) -> tuple[str, str]:
    metadata, _ = parse_frontmatter(path)
    old = str(metadata.get("status", ""))
    original = path.read_bytes()
    text = original.decode("utf-8")
    pattern = re.compile(
        r'(?m)^(status[ \t]*=[ \t]*")[^"\r\n]*("[ \t]*)(?=\r?$)'
    )
    updated, count = pattern.subn(
        rf'\g<1>{new_status}\g<2>',
        text,
        count=1,
    )
    if count != 1:
        raise WorkflowError(f"Could not replace status in {path}")
    replace_bytes_atomic(path, updated.encode("utf-8"))
    return old, new_status


def canonical_root_blocker(
    runtime: dict[str, Any],
    blocker_id: str,
    *,
    require_open: bool = True,
) -> tuple[str, dict[str, Any]]:
    blockers = runtime.get("blockers", {})
    record = blockers.get(blocker_id) if isinstance(blockers, dict) else None
    if not isinstance(record, dict):
        raise WorkflowError(f"Unknown blocker: {blocker_id}")
    root_id = str(record.get("derived_from") or blocker_id)
    root = blockers.get(root_id)
    if not isinstance(root, dict) or root.get("derived_from"):
        raise WorkflowError(f"{blocker_id} does not resolve to a canonical root blocker")
    if require_open and root.get("status", "open") != "open":
        raise WorkflowError(f"Canonical root blocker {root_id} is not open")
    return root_id, root


def resolve_blocker_family(
    runtime: dict[str, Any],
    blocker_id: str,
    resolution: str,
    *,
    resolved_at: str | None = None,
) -> tuple[str, list[str], list[str]]:
    """Resolve a canonical root, all direct derivatives, and its repair phases."""

    root_id, _ = canonical_root_blocker(
        runtime,
        blocker_id,
        require_open=False,
    )
    timestamp = resolved_at or utc_now()
    resolved: list[str] = []
    for current_id, record in runtime["blockers"].items():
        if (
            not isinstance(record, dict)
            or str(record.get("root_cause_id", "")) != root_id
        ):
            continue
        record["status"] = "resolved"
        record["resolution"] = resolution
        record["resolved_at"] = timestamp
        resolved.append(current_id)

    cleared_phases: list[str] = []
    for ticket_id, record in list(runtime.get("phases", {}).items()):
        if (
            isinstance(record, dict)
            and record.get("phase") == "repair"
            and record.get("root_cause_id") == root_id
        ):
            del runtime["phases"][ticket_id]
            cleared_phases.append(ticket_id)
    return root_id, sorted(resolved), sorted(cleared_phases)


def phase_record_for(
    ticket: Ticket,
    phase: str,
    *,
    branch: str = "",
    worktree: str = "",
    candidate_sha: str = "",
    root_cause_id: str = "",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ticket_id": ticket.id,
        "phase": phase,
        "recorded_at": utc_now(),
    }
    for key, value in (
        ("branch", branch),
        ("worktree", worktree),
        ("candidate_sha", candidate_sha),
        ("root_cause_id", root_cause_id),
    ):
        if value:
            record[key] = value
    return record


def validate_phase_entry(
    ticket: Ticket,
    phase: str,
    tickets: Sequence[Ticket],
    runtime: dict[str, Any],
    *,
    root_blocker: str = "",
) -> str:
    durable_status = (
        "ready" if ticket.status in LEGACY_TRANSIENT_STATUSES else ticket.status
    )
    allowed_statuses = {"done", "deferred"} if phase == "release" else {"ready"}
    if durable_status not in allowed_statuses:
        raise WorkflowError(
            f"{ticket.id} cannot enter transient phase {phase} from durable status "
            f"{durable_status}"
        )
    root_id = ""
    if phase == "repair":
        if not root_blocker:
            raise WorkflowError("repair phase requires --root-blocker")
        root_id, root = canonical_root_blocker(runtime, root_blocker)
        if str(root.get("ticket_id", "")).upper() != ticket.id.upper():
            raise WorkflowError(
                f"Root blocker {root_id} belongs to "
                f"{root.get('ticket_id')}, not {ticket.id}"
            )
        gate = str(root.get("phase", "review"))
        if gate not in DEPENDENCY_FIELDS:
            raise WorkflowError(
                f"Root blocker {root_id} has invalid dependency gate {gate}"
            )
    else:
        if root_blocker:
            raise WorkflowError("--root-blocker is valid only for the repair phase")
        gate = PHASE_DEPENDENCY_GATE[phase]
        open_roots = open_root_blocker_ids_for_ticket(runtime, ticket.id, gate)
        if open_roots:
            raise WorkflowError(
                f"{ticket.id} cannot enter {phase}; open canonical root blockers "
                "through this gate: "
                + ", ".join(open_roots)
            )
    by_id = {item.id: item for item in tickets}
    unmet = unmet_dependencies(ticket, gate, by_id)
    if unmet:
        raise WorkflowError(
            f"{ticket.id} cannot enter {phase}; unmet {gate} dependencies: "
            + ", ".join(unmet)
        )
    if phase != "repair":
        return ""
    return root_id


def validate_candidate_commit(root: Path, phase: str, candidate_sha: str) -> str:
    if phase in {"review", "integration", "release"} and not candidate_sha:
        raise WorkflowError(f"{phase} phase requires --candidate-sha")
    if not candidate_sha:
        return ""
    if not re.fullmatch(
        r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
        candidate_sha,
    ):
        raise WorkflowError(
            "--candidate-sha must be a full 40- or 64-digit hexadecimal commit ID"
        )
    normalized = candidate_sha.lower()
    probe = run(
        ["git", "cat-file", "-e", f"{normalized}^{{commit}}"],
        cwd=root,
        check=False,
    )
    if probe.returncode != 0:
        raise WorkflowError(
            f"--candidate-sha is not a commit in this repository: {candidate_sha}"
        )
    return normalized


def validate_writer_location(phase: str, branch: str, worktree: str) -> None:
    if phase not in ACTIVE_WRITER_PHASES:
        return
    if not branch.strip() or not worktree.strip():
        raise WorkflowError(
            f"{phase} phase requires exact --branch and --worktree"
        )
    if not Path(worktree).is_absolute():
        raise WorkflowError(f"{phase} --worktree must be an absolute path")


def cmd_set_phase(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    tickets = load_tickets(root, cfg)
    ticket = find_ticket(tickets, args.ticket_id)
    candidate_sha = validate_candidate_commit(
        root, args.phase, args.candidate_sha
    )
    validate_writer_location(args.phase, args.branch, args.worktree)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)
    root_cause_id = validate_phase_entry(
        ticket,
        args.phase,
        tickets,
        runtime,
        root_blocker=args.root_blocker,
    )
    runtime["phases"][ticket.id] = phase_record_for(
        ticket,
        args.phase,
        branch=args.branch,
        worktree=args.worktree,
        candidate_sha=candidate_sha,
        root_cause_id=root_cause_id,
    )
    path = save_runtime_state(root, cfg, state)
    migrated = ""
    if ticket.status in LEGACY_TRANSIENT_STATUSES:
        old, new = replace_status(ticket.path, "ready")
        migrated = f"; migrated tracked status {old} -> {new}"
    print(
        f"{ticket.id}: phase={args.phase} recorded in {relative(root, path)}"
        + migrated
    )
    return 0


def cmd_clear_phase(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    ticket = find_ticket(load_tickets(root, cfg), args.ticket_id)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)
    record = runtime["phases"].get(ticket.id)
    if not isinstance(record, dict):
        if ticket.status in LEGACY_TRANSIENT_STATUSES:
            old, new = replace_status(ticket.path, "ready")
            print(
                f"{ticket.id}: cleared legacy phase by migrating tracked status "
                f"{old} -> {new}"
            )
        else:
            print(f"{ticket.id}: no runtime phase recorded")
        return 0
    if args.expect and record.get("phase") != args.expect:
        raise WorkflowError(
            f"{ticket.id} has phase {record.get('phase')}, expected {args.expect}"
        )
    migrated = ""
    original_bytes = b""
    if ticket.status in LEGACY_TRANSIENT_STATUSES:
        original_bytes = ticket.path.read_bytes()
        old, new = replace_status(ticket.path, "ready")
        migrated = f"; migrated tracked status {old} -> {new}"
    del runtime["phases"][ticket.id]
    try:
        path = save_runtime_state(root, cfg, state)
    except Exception:
        if original_bytes:
            replace_bytes_atomic(ticket.path, original_bytes)
        raise
    print(f"{ticket.id}: phase cleared in {relative(root, path)}" + migrated)
    return 0


def cmd_set_status(args: argparse.Namespace) -> int:
    if args.status not in TICKET_STATUSES:
        raise WorkflowError(f"Invalid ticket status: {args.status}")
    root = git_root()
    cfg = load_config(root)
    tickets = load_tickets(root, cfg)
    ticket = find_ticket(tickets, args.ticket_id)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)

    if args.status in LEGACY_STATUS_PHASES:
        phase = LEGACY_STATUS_PHASES[args.status]
        candidate_sha = validate_candidate_commit(
            root, phase, args.candidate_sha
        )
        validate_writer_location(phase, args.branch, args.worktree)
        open_roots = [
            record
            for record in runtime["blockers"].values()
            if isinstance(record, dict)
            and not record.get("derived_from")
            and record.get("status", "open") == "open"
            and str(record.get("ticket_id", "")).upper() == ticket.id.upper()
        ]
        root_blocker = args.root_blocker
        if phase == "repair" and not root_blocker:
            if len(open_roots) > 1:
                raise WorkflowError(
                    f"{ticket.id} has multiple open canonical roots; "
                    "legacy failed status requires --root-blocker"
                )
            if open_roots:
                root_blocker = str(open_roots[0]["id"])
        root_cause_id = validate_phase_entry(
            ticket,
            phase,
            tickets,
            runtime,
            root_blocker=root_blocker,
        )
        runtime["phases"][ticket.id] = phase_record_for(
            ticket,
            phase,
            branch=args.branch,
            worktree=args.worktree,
            candidate_sha=candidate_sha,
            root_cause_id=root_cause_id,
        )
        path = save_runtime_state(root, cfg, state)
        migrated = ""
        if ticket.status in LEGACY_TRANSIENT_STATUSES:
            old, new = replace_status(ticket.path, "ready")
            migrated = f"; migrated tracked status {old} -> {new}"
        print(
            f"{ticket.id}: legacy status {args.status} mapped to runtime phase {phase} "
            f"in {relative(root, path)}{migrated}"
        )
        return 0

    if args.candidate_sha or args.branch or args.worktree or args.root_blocker:
        raise WorkflowError(
            "--candidate-sha/--branch/--worktree/--root-blocker apply only when "
            "mapping a legacy transient status; use set-phase for new work"
        )
    current = "ready" if ticket.status in LEGACY_TRANSIENT_STATUSES else ticket.status
    phase_record = runtime["phases"].get(ticket.id)
    if (
        current == args.status
        and ticket.status == args.status
        and not isinstance(phase_record, dict)
    ):
        print(f"{ticket.id} already has durable status {args.status}")
        return 0
    if (
        current != args.status
        and not args.force
        and args.status not in ALLOWED_DURABLE_TRANSITIONS.get(current, set())
    ):
        if not (ticket.status in LEGACY_TRANSIENT_STATUSES and args.status == "ready"):
            raise WorkflowError(
                f"Durable transition {current} -> {args.status} is not allowed; use "
                "--force only after reconciling repository evidence"
            )
    if args.status == "done" and not (current == "done" and ticket.status == "done"):
        by_id = {item.id: item for item in tickets}
        unmet = unmet_dependencies(ticket, "integration", by_id)
        if unmet:
            raise WorkflowError(
                f"{ticket.id} cannot become done; unmet integration dependencies: "
                + ", ".join(unmet)
            )
        open_roots = open_root_blocker_ids_for_ticket(
            runtime,
            ticket.id,
            "integration",
        )
        if open_roots:
            raise WorkflowError(
                f"{ticket.id} cannot become done; open canonical root blockers "
                "through integration: "
                + ", ".join(open_roots)
            )
        reviews_clear, review_failures = review_gate_status(ticket, runtime, cfg)
        if not args.force and not reviews_clear:
            raise WorkflowError(
                f"{ticket.id} cannot become done; review gate is incomplete: "
                + "; ".join(review_failures)
            )
        if not args.force and (
            not isinstance(phase_record, dict)
            or phase_record.get("phase") != "integration"
            or not phase_record.get("candidate_sha")
        ):
            raise WorkflowError(
                f"{ticket.id} can become done only from an integration phase bound "
                "to an exact candidate SHA; use --force only for evidence-backed "
                "legacy reconciliation"
            )
    original_bytes = ticket.path.read_bytes()
    if current == args.status and ticket.status == args.status:
        old = new = args.status
    else:
        old, new = replace_status(ticket.path, args.status)
    phase_cleared = runtime["phases"].pop(ticket.id, None) is not None
    if phase_cleared:
        try:
            save_runtime_state(root, cfg, state)
        except Exception:
            replace_bytes_atomic(ticket.path, original_bytes)
            raise
    suffix = "; cleared runtime phase" if phase_cleared else ""
    print(f"{ticket.id}: durable status {old} -> {new}{suffix}")
    return 0


def cmd_gate_check(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    tickets = load_tickets(root, cfg)
    ticket = find_ticket(tickets, args.ticket_id)
    by_id = {item.id: item for item in tickets}
    unmet = unmet_dependencies(ticket, args.phase, by_id)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)
    open_roots = open_root_blocker_ids_for_ticket(
        runtime,
        ticket.id,
        args.phase,
    )
    reviews_clear = True
    review_failures: list[str] = []
    if args.phase in {"integration", "release"}:
        reviews_clear, review_failures = review_gate_status(ticket, runtime, cfg)
    gate_clear = not unmet and not open_roots and reviews_clear
    payload = {
        "ticket": ticket.id,
        "phase": args.phase,
        "dependencies": ticket.dependencies(args.phase),
        "dependencies_through_gate": ticket.dependencies_through(args.phase),
        "unmet": unmet,
        "open_root_blockers": open_roots,
        "review_failures": review_failures,
        "clear": gate_clear,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif not gate_clear:
        reasons = []
        if unmet:
            reasons.append("dependencies=" + ", ".join(unmet))
        if open_roots:
            reasons.append("root blockers=" + ", ".join(open_roots))
        if review_failures:
            reasons.append("reviews=" + "; ".join(review_failures))
        print(f"{ticket.id} {args.phase} gate blocked: " + "; ".join(reasons))
    else:
        print(f"{ticket.id} {args.phase} gate clear")
    return 0 if gate_clear else 1


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def cmd_new_ticket(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    directory = ticket_dir(root, cfg)
    directory.mkdir(parents=True, exist_ok=True)
    ticket_id = args.id.upper()
    existing = load_tickets(root, cfg)
    if any(ticket.id.upper() == ticket_id for ticket in existing):
        raise WorkflowError(f"Ticket ID already exists: {ticket_id}")
    slug = slugify(args.title)
    path = directory / f"{ticket_id}-{slug}.md"
    if path.exists():
        raise WorkflowError(f"Ticket file already exists: {path}")
    implementation_blocked = [
        item.upper()
        for item in (args.implementation_blocked_by + args.blocked_by)
    ]
    dependency_values = {
        "implementation_blocked_by": implementation_blocked,
        "review_blocked_by": [item.upper() for item in args.review_blocked_by],
        "integration_blocked_by": [item.upper() for item in args.integration_blocked_by],
        "release_blocked_by": [item.upper() for item in args.release_blocked_by],
    }
    rendered_dependencies = "\n".join(
        f"{field} = ["
        + ", ".join(toml_string(item) for item in values)
        + "]"
        for field, values in dependency_values.items()
    )
    owns = ", ".join(toml_string(item) for item in args.owns)
    maximum_acceptance = int(
        cfg.get("planning", {}).get("max_acceptance_criteria_per_ticket", 8)
    )
    if len(args.acceptance) > maximum_acceptance:
        raise WorkflowError(
            f"Ticket has {len(args.acceptance)} acceptance criteria; maximum is "
            f"{maximum_acceptance}. Split the ticket or consolidate duplicate evidence."
        )
    acceptance = ",\n  ".join(toml_string(item) for item in args.acceptance)
    reviews = args.required_review or (
        ["architect", "qa"]
        if args.risk in {"high", "critical"}
        else (["qa"] if args.risk == "medium" else [])
    )
    rendered_reviews = ", ".join(toml_string(item) for item in reviews)
    content = f'''+++
id = {toml_string(ticket_id)}
title = {toml_string(args.title)}
milestone = {toml_string(args.milestone.upper())}
status = "draft"
priority = {toml_string(args.priority.upper())}
risk = {toml_string(args.risk.lower())}
{rendered_dependencies}
required_reviews = [{rendered_reviews}]
owns = [{owns}]
spec = {toml_string(args.spec)}
test_plan = {toml_string(args.test_plan)}
acceptance = [
  {acceptance}
]
+++

# {ticket_id}: {args.title}

## Outcome

TODO

## Context

TODO

## In scope

- TODO

## Out of scope

- TODO

## Implementation notes and constraints

- TODO

## Validation commands

```bash
# Add ticket-specific commands.
```

## Risks

- TODO

## Blocker record

Use the Git-common-dir runtime ledger for transient blockers. If a durable contract
blocker must be documented here, include ID, class, gate, root cause, derivatives,
owner, evidence, authorization state, and unblock condition.

Tracked status is durable: use only `draft`, `ready`, `blocked`, `done`, or
`deferred`. Record implementation/review/repair/integration/release with
`workflow.py set-phase`, not by editing this frontmatter.

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Required reviewer role/profile and verdict:
- Exact candidate SHA:
- Integrated commit:
'''
    path.write_text(content, encoding="utf-8")
    print(relative(root, path))
    return 0


def repair_budget_for(
    ticket: Ticket,
    cfg: dict[str, Any],
    risk: str | None = None,
) -> int:
    configured = cfg.get("execution", {}).get("repair_budget", {})
    if isinstance(configured, dict):
        value = configured.get(risk or ticket.risk)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return int(cfg["execution"]["max_repair_attempts_per_ticket"])


def repair_summary(
    ticket: Ticket,
    cfg: dict[str, Any],
    runtime: dict[str, Any],
    root_cause_id: str | None = None,
) -> dict[str, Any]:
    all_entries = runtime.get("repairs", {}).get(ticket.id, [])
    if not isinstance(all_entries, list):
        raise WorkflowError(f"Runtime repairs for {ticket.id} must be an array")
    entries = [
        entry
        for entry in all_entries
        if not root_cause_id
        or (
            isinstance(entry, dict)
            and entry.get("root_cause_id") == root_cause_id
        )
    ]
    non_counting = set(cfg["execution"].get("non_counting_repair_classes", []))
    consumed = sum(
        1
        for entry in entries
        if isinstance(entry, dict)
        and (
            entry["consumes_budget"]
            if isinstance(entry.get("consumes_budget"), bool)
            else str(entry.get("class")) not in non_counting
        )
    )
    root = runtime.get("blockers", {}).get(root_cause_id, {})
    risk = (
        str(root.get("risk"))
        if root_cause_id and isinstance(root, dict) and root.get("risk") in RISK_LEVELS
        else ticket.risk
    )
    base_budget = repair_budget_for(ticket, cfg, risk)
    overrides = runtime.get("repair_overrides", {}).get(root_cause_id, [])
    override_count = len(overrides) if root_cause_id and isinstance(overrides, list) else 0
    budget = base_budget + override_count
    return {
        "root_cause_id": root_cause_id,
        "risk": risk,
        "base_budget": base_budget,
        "override_count": override_count,
        "budget": budget,
        "consumed": consumed,
        "remaining": max(0, budget - consumed),
        "exhausted": consumed >= budget,
        "entries": entries,
    }


def cmd_state(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    state = load_runtime_state(root, cfg)
    payload: dict[str, Any] = {
        "path": relative(root, runtime_state_path(root, cfg)),
        "version": state["version"],
    }
    if args.milestone:
        runtime = milestone_runtime_state(state, args.milestone)
        tickets = [
            ticket
            for ticket in load_tickets(root, cfg)
            if ticket.milestone.upper() == args.milestone.upper()
        ]
        payload["milestone"] = args.milestone.upper()
        payload["runtime"] = runtime
        payload["repair_budgets"] = {
            ticket.id: repair_summary(ticket, cfg, runtime) for ticket in tickets
        }
        payload["repair_budgets_by_root"] = {
            root_id: repair_summary(
                find_ticket(tickets, str(record["ticket_id"])),
                cfg,
                runtime,
                root_id,
            )
            for root_id, record in runtime["blockers"].items()
            if isinstance(record, dict)
            and not record.get("derived_from")
            and any(
                ticket.id.upper() == str(record.get("ticket_id", "")).upper()
                for ticket in tickets
            )
        }
    else:
        payload["milestones"] = state["milestones"]
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_grant_authorization(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, args.milestone)
    if args.scope in runtime["authorizations"]:
        raise WorkflowError(
            f"Authorization scope {args.scope} already exists and is immutable; "
            "revoke it if needed and grant a new scope ID"
        )
    bound_root = str(getattr(args, "root_blocker", "")).strip()
    bound_reviewer = str(getattr(args, "reviewer", "")).strip()
    if bool(bound_root) != bool(bound_reviewer):
        raise WorkflowError(
            "--root-blocker and --reviewer must be provided together"
        )
    bound_root_record: dict[str, Any] | None = None
    if bound_root:
        if args.kind != "local" or list(args.action) != ["review_round_override"]:
            raise WorkflowError(
                "root/reviewer binding is valid only for a local "
                "review_round_override authorization"
            )
        bound_root_record = canonical_review_root(
            runtime,
            str(args.ticket[0]) if len(args.ticket) == 1 else "",
            bound_root,
            require_open=True,
        )
        expected_ticket = str(bound_root_record.get("ticket_id", "")).upper()
        normalized_tickets = [ticket.upper() for ticket in args.ticket]
        if normalized_tickets != [expected_ticket]:
            raise WorkflowError(
                "bound review authorization must name only its canonical root ticket"
            )
        root_class = str(bound_root_record.get("class", ""))
        root_risk = str(bound_root_record.get("risk", ""))
        if root_class not in args.blocker_class or (
            root_risk in RISK_ORDER
            and RISK_ORDER[args.max_risk] < RISK_ORDER[root_risk]
        ):
            raise WorkflowError(
                "bound review authorization class/risk must cover its canonical root"
            )
    if (args.kind == "remote") != bool(args.remote_effects):
        raise WorkflowError(
            "--kind remote requires --remote-effects, and local authorization must "
            "not use --remote-effects"
        )
    if args.kind == "remote":
        if not args.remote_ref or not args.commit_sha:
            raise WorkflowError(
                "remote authorization requires --remote-ref and --commit-sha"
            )
        if not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            args.commit_sha,
        ):
            raise WorkflowError("--commit-sha must be a full exact commit ID")
        probe = run(
            ["git", "cat-file", "-e", f"{args.commit_sha}^{{commit}}"],
            cwd=root,
            check=False,
        )
        if probe.returncode != 0:
            raise WorkflowError(
                f"--commit-sha is not a commit in this repository: {args.commit_sha}"
            )
        max_uses = args.max_uses if args.max_uses is not None else 1
        if max_uses < 1:
            raise WorkflowError("--max-uses must be at least 1")
    else:
        if args.remote_ref or args.commit_sha:
            raise WorkflowError(
                "local authorization must not set --remote-ref or --commit-sha"
            )
        max_uses = 1 if bound_root and args.max_uses is None else args.max_uses
        if max_uses is not None and max_uses < 1:
            raise WorkflowError("--max-uses must be at least 1")
        if bound_root and max_uses != 1:
            raise WorkflowError(
                "bound review_round_override authorization must be single-use"
            )
    record = {
        "kind": args.kind,
        "status": "granted",
        "actions": list(args.action),
        "tickets": [ticket.upper() for ticket in args.ticket],
        "blocker_classes": list(args.blocker_class),
        "max_risk": args.max_risk,
        "remote_effects": bool(args.remote_effects),
        "evidence": args.evidence,
        "uses": 0,
        "recorded_at": utc_now(),
    }
    if max_uses is not None:
        record["max_uses"] = max_uses
    if bound_root_record is not None:
        record.update(
            {
                "root_cause_id": bound_root,
                "reviewer": bound_reviewer,
            }
        )
    if args.kind == "remote":
        record.update(
            {
                "remote_ref": args.remote_ref,
                "commit_sha": args.commit_sha.lower(),
            }
        )
    runtime["authorizations"][args.scope] = record
    path = save_runtime_state(root, cfg, state)
    print(f"Recorded explicit {args.kind} authorization in {relative(root, path)}")
    return 0


def cmd_revoke_authorization(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, args.milestone)
    record = runtime["authorizations"].get(args.scope)
    if not isinstance(record, dict):
        raise WorkflowError(f"Unknown authorization scope: {args.scope}")
    if record.get("status") == "revoked":
        print(f"Authorization scope {args.scope} is already revoked")
        return 0
    record["status"] = "revoked"
    record["revoked_at"] = utc_now()
    record["revocation_reason"] = args.reason
    path = save_runtime_state(root, cfg, state)
    print(f"Revoked authorization {args.scope} in {relative(root, path)}")
    return 0


def cmd_authorization_check(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    if args.remote_effects:
        if not args.remote_ref or not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            args.commit_sha,
        ):
            raise WorkflowError(
                "remote authorization check requires exact --remote-ref and "
                "--commit-sha"
            )
    elif args.remote_ref or args.commit_sha:
        raise WorkflowError(
            "local authorization check must not include remote ref or commit"
        )
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, args.milestone)
    match = matching_authorization(
        runtime,
        action=args.action,
        ticket_id=args.ticket,
        blocker_class=args.blocker_class,
        risk=args.risk,
        remote_effects=args.remote_effects,
        remote_ref=args.remote_ref,
        commit_sha=args.commit_sha,
    )
    payload = {
        "authorized": match is not None,
        "scope": match[0] if match else None,
        "record": match[1] if match else None,
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if match else 1


def consume_authorization_record(record: dict[str, Any]) -> None:
    record["uses"] = int(record.get("uses", 0)) + 1
    record["last_used_at"] = utc_now()
    if isinstance(record.get("max_uses"), int) and record["uses"] >= record["max_uses"]:
        record["status"] = "revoked"
        record["revoked_at"] = utc_now()
        record["revocation_reason"] = "usage limit exhausted"


def cmd_consume_authorization(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    if args.remote_effects:
        if not args.remote_ref or not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            args.commit_sha,
        ):
            raise WorkflowError(
                "remote authorization consumption requires exact --remote-ref and "
                "--commit-sha"
            )
    elif args.remote_ref or args.commit_sha:
        raise WorkflowError(
            "local authorization consumption must not include remote ref or commit"
        )
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, args.milestone)
    match = matching_authorization(
        runtime,
        action=args.action,
        ticket_id=args.ticket,
        blocker_class=args.blocker_class,
        risk=args.risk,
        remote_effects=args.remote_effects,
        remote_ref=args.remote_ref,
        commit_sha=args.commit_sha,
    )
    if not match:
        raise WorkflowError("No unused authorization matches the exact requested scope")
    scope, _ = match
    record = runtime["authorizations"][scope]
    root_cause_id = ""
    if args.action == "repair_budget_override":
        if args.remote_effects:
            raise WorkflowError("repair budget override must be a local authorization")
        if not args.root_blocker:
            raise WorkflowError(
                "repair_budget_override consumption requires --root-blocker"
            )
        root_cause_id, root_blocker = canonical_root_blocker(
            runtime, args.root_blocker
        )
        if str(root_blocker.get("ticket_id", "")).upper() != args.ticket.upper():
            raise WorkflowError(
                f"Root blocker {root_cause_id} belongs to "
                f"{root_blocker.get('ticket_id')}, not {args.ticket}"
            )
        actual_class = str(root_blocker.get("class", ""))
        actual_risk = str(root_blocker.get("risk", ""))
        if args.blocker_class != actual_class or args.risk != actual_risk:
            raise WorkflowError(
                f"Requested class/risk {args.blocker_class}/{args.risk} does not "
                f"match root blocker {root_cause_id} "
                f"{actual_class}/{actual_risk}"
            )
        runtime["repair_overrides"].setdefault(root_cause_id, []).append(
            {
                "authorization_scope": scope,
                "recorded_at": utc_now(),
            }
        )
    elif args.root_blocker:
        raise WorkflowError(
            "--root-blocker is valid only for repair_budget_override consumption"
        )
    consume_authorization_record(record)
    path = save_runtime_state(root, cfg, state)
    print(
        json.dumps(
            {
                "consumed": True,
                "scope": scope,
                "uses": record["uses"],
                "max_uses": record.get("max_uses"),
                "status": record["status"],
                "root_cause_id": root_cause_id or None,
                "path": relative(root, path),
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def cmd_record_blocker(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    ticket = find_ticket(load_tickets(root, cfg), args.ticket_id)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)
    blocker_id = args.blocker_id or (
        f"{ticket.id}-B{len(runtime['blockers']) + 1:03d}"
    )
    if blocker_id in runtime["blockers"]:
        raise WorkflowError(f"Blocker ID already exists: {blocker_id}")
    derived_from = ""
    if args.derived_from:
        derived_from, _ = canonical_root_blocker(runtime, args.derived_from)
    runtime["blockers"][blocker_id] = {
        "id": blocker_id,
        "ticket_id": ticket.id,
        "class": args.blocker_class,
        "phase": args.phase,
        "risk": args.risk or ticket.risk,
        "root_cause": args.root_cause,
        "root_cause_id": derived_from or blocker_id,
        "derived_from": derived_from or None,
        "derivatives": list(args.derivative),
        "owner": args.owner or ticket.id,
        "authorization": args.authorization,
        "evidence": list(args.evidence),
        "unblock_condition": args.unblock_condition,
        "status": "open",
        "recorded_at": utc_now(),
    }
    path = save_runtime_state(root, cfg, state)
    print(f"Recorded blocker {blocker_id} for {ticket.id} in {relative(root, path)}")
    return 0


def cmd_resolve_blocker(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    state = load_runtime_state(root, cfg)
    found: tuple[str, dict[str, Any]] | None = None
    for milestone, runtime in state["milestones"].items():
        record = runtime.get("blockers", {}).get(args.blocker_id)
        if isinstance(record, dict):
            found = (milestone, record)
            break
    if found is None:
        raise WorkflowError(f"No runtime blocker recorded with ID {args.blocker_id}")
    milestone, record = found
    runtime = milestone_runtime_state(state, milestone)
    if not isinstance(record, dict):
        raise WorkflowError(f"Invalid runtime blocker {args.blocker_id}")
    root_id, resolved, cleared_phases = resolve_blocker_family(
        runtime,
        args.blocker_id,
        args.resolution,
    )
    path = save_runtime_state(root, cfg, state)
    print(
        f"Resolved canonical root {root_id} and {len(resolved) - 1} "
        f"derivative(s) in {relative(root, path)}"
    )
    if cleared_phases:
        print("Cleared repair phases: " + ", ".join(cleared_phases))
    return 0


def cmd_record_repair(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    ticket = find_ticket(load_tickets(root, cfg), args.ticket_id)
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, ticket.milestone)
    root_cause_id, root_blocker = canonical_root_blocker(
        runtime, args.root_blocker
    )
    if str(root_blocker.get("ticket_id", "")).upper() != ticket.id.upper():
        raise WorkflowError(
            f"Root blocker {root_cause_id} belongs to "
            f"{root_blocker.get('ticket_id')}, not {ticket.id}"
        )
    phase_record = runtime["phases"].get(ticket.id)
    if (
        not isinstance(phase_record, dict)
        or phase_record.get("phase") != "repair"
        or phase_record.get("root_cause_id") != root_cause_id
    ):
        raise WorkflowError(
            f"{ticket.id} repair record must match its active repair phase and "
            f"canonical root {root_cause_id}"
        )
    entries = runtime["repairs"].setdefault(ticket.id, [])
    if not isinstance(entries, list):
        raise WorkflowError(f"Runtime repairs for {ticket.id} must be an array")
    before = repair_summary(ticket, cfg, runtime, root_cause_id)
    non_counting = set(cfg["execution"].get("non_counting_repair_classes", []))
    consumes_budget = args.repair_class not in non_counting
    authorization_scope = ""
    blocker_class = str(root_blocker.get("class", "code"))
    risk = str(root_blocker.get("risk", ticket.risk))
    if root_blocker.get("authorization", "not_required") != "not_required":
        match = matching_authorization(
            runtime,
            action="local_repair",
            ticket_id=ticket.id,
            blocker_class=blocker_class,
            risk=risk,
            remote_effects=False,
        )
        if not match:
            raise WorkflowError(
                f"{ticket.id} repair requires an exact local_repair authorization "
                f"for blocker class {blocker_class} at risk {risk}"
            )
        authorization_scope = match[0]
        consume_authorization_record(runtime["authorizations"][authorization_scope])
    if args.force and (not consumes_budget or not before["exhausted"]):
        raise WorkflowError(
            "--force is valid only for a budget-consuming repair whose root budget "
            "is exhausted"
        )
    if consumes_budget and before["exhausted"] and not args.force:
        raise WorkflowError(
            f"{ticket.id}/{root_cause_id} repair budget is exhausted "
            f"({before['consumed']}/{before['budget']}); consume an exact "
            "repair_budget_override authorization before another repair"
        )
    if args.force:
        override = matching_authorization(
            runtime,
            action="repair_budget_override",
            ticket_id=ticket.id,
            blocker_class=blocker_class,
            risk=risk,
            remote_effects=False,
        )
        if not override:
            raise WorkflowError(
                f"--force requires an exact repair_budget_override authorization for "
                f"{ticket.id}, blocker class {blocker_class}, risk {risk}"
            )
        override_scope = override[0]
        override_record = runtime["authorizations"][override_scope]
        consume_authorization_record(override_record)
        runtime["repair_overrides"].setdefault(root_cause_id, []).append(
            {
                "authorization_scope": override_scope,
                "recorded_at": utc_now(),
            }
        )
        before = repair_summary(ticket, cfg, runtime, root_cause_id)
    entries.append(
        {
            "class": args.repair_class,
            "root_cause_id": root_cause_id,
            "note": args.note,
            "commit": args.commit,
            "consumes_budget": consumes_budget,
            "repair_authorization_scope": authorization_scope,
            "budget_override_authorization_scope": (
                override_scope if args.force else ""
            ),
            "recorded_at": utc_now(),
        }
    )
    path = save_runtime_state(root, cfg, state)
    after = repair_summary(ticket, cfg, runtime, root_cause_id)
    print(
        f"Recorded {args.repair_class} repair for {ticket.id}/{root_cause_id}; "
        f"budget {after['consumed']}/{after['budget']} in {relative(root, path)}"
    )
    return 0


def scheduler_fingerprint(payload: dict[str, Any]) -> str:
    stable = {
        "action": payload.get("action"),
        "selected": payload.get("selected", []),
        "active_details": payload.get("active_details", []),
        "blocked": payload.get("blocked", []),
        "release_blocked": payload.get("release_blocked", []),
        "open_root_blockers": payload.get("open_root_blockers", []),
    }
    encoded = json.dumps(
        stable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def next_no_progress_count(current: int, progress: str) -> int:
    if progress == "material":
        return 0
    if progress == "none":
        return current + 1
    raise WorkflowError(f"Unknown progress classification: {progress}")


def cmd_checkpoint(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    errors, _, tickets = validate_tickets(root, cfg)
    if errors:
        raise WorkflowError("Ticket validation failed; run workflow.py validate")
    state = load_runtime_state(root, cfg)
    runtime = milestone_runtime_state(state, args.milestone)
    limit = args.limit or int(cfg["workflow"]["max_parallel_engineers"])
    payload = milestone_scheduler_state(
        tickets,
        args.milestone,
        limit,
        runtime,
        bool(cfg["execution"]["continue_after_independent_failure"]),
        cfg,
    )
    fingerprint = scheduler_fingerprint(payload)
    run_state = runtime["last_checkpoint"]
    if args.new_run:
        run_state.clear()
    previous = str(run_state.get("fingerprint", ""))
    no_progress = next_no_progress_count(
        int(run_state.get("no_progress_count", 0)),
        args.progress,
    )
    wave = int(run_state.get("wave", 0)) + (1 if args.wave_complete else 0)
    run_state.update(
        {
            "strategy": str(cfg["execution"]["strategy"]),
            "wave": wave,
            "fingerprint": fingerprint,
            "fingerprint_changed": bool(previous and previous != fingerprint),
            "no_progress_count": no_progress,
            "action": payload["action"],
            "active": payload["active"],
            "selected": payload["selected"],
            "updated_at": utc_now(),
        }
    )
    path = save_runtime_state(root, cfg, state)
    limit_value = int(cfg["execution"]["no_progress_limit"])
    result = {
        "path": str(path),
        "milestone": args.milestone.upper(),
        "checkpoint": run_state,
        "no_progress_limit": limit_value,
        "no_progress_exhausted": no_progress >= limit_value,
        "max_waves_per_run": int(cfg["execution"]["max_waves_per_run"]),
    }
    result["wave_limit_reached"] = bool(
        result["max_waves_per_run"]
        and wave >= result["max_waves_per_run"]
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result["no_progress_exhausted"] else 0


def cmd_status(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    errors, warnings, tickets = validate_tickets(root, cfg)
    counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for ticket in tickets:
        counts[ticket.milestone][ticket.status] += 1
    clean, dirty = is_clean(root)
    max_parallel = int(cfg["workflow"]["max_parallel_engineers"])
    state = load_runtime_state(root, cfg)
    if args.milestone:
        selected_runtime = milestone_runtime_state(state, args.milestone)
        active_entries = active_ticket_phases(
            tickets, selected_runtime, args.milestone
        )
    else:
        active_entries = []
        for milestone, selected_runtime in state["milestones"].items():
            active_entries.extend(
                active_ticket_phases(tickets, selected_runtime, milestone)
            )
        recorded = {ticket.id for ticket, _, _, _ in active_entries}
        active_entries.extend(
            entry
            for entry in active_ticket_phases(tickets, None)
            if entry[0].id not in recorded
        )
    active = [ticket for ticket, _, _, _ in active_entries]
    if args.milestone:
        decision = milestone_scheduler_state(
            tickets,
            args.milestone,
            max_parallel,
            milestone_runtime_state(state, args.milestone),
            bool(cfg["execution"]["continue_after_independent_failure"]),
            cfg,
        )
        by_id = {ticket.id: ticket for ticket in tickets}
        selected = [by_id[ticket_id] for ticket_id in decision["selected"]]
        skipped = [
            (by_id[item["id"]], item["reason"])
            for item in decision["skipped"]
            if item["id"] in by_id
        ]
        available = int(decision["available_engineer_slots"])
    else:
        available = max(
            0,
            max_parallel
            - sum(phase in ACTIVE_WRITER_PHASES for _, phase, _, _ in active_entries),
        )
        if any(phase == "repair" for _, phase, _, _ in active_entries) and not bool(
            cfg["execution"]["continue_after_independent_failure"]
        ):
            available = 0
        selected, skipped = select_frontier(
            tickets,
            args.milestone,
            available,
            reserved=active,
            runtimes={
                str(milestone).upper(): runtime
                for milestone, runtime in state["milestones"].items()
                if isinstance(runtime, dict)
            },
        )
    payload = {
        "repository": str(root),
        "current_branch": current_branch(root),
        "base_branch": cfg["workflow"]["base_branch"],
        "base_worktree_clean": clean,
        "base_worktree_dirty": dirty,
        "milestones": {milestone: dict(counter) for milestone, counter in sorted(counts.items())},
        "frontier": [ticket_to_dict(root, ticket) for ticket in selected],
        "available_engineer_slots": available,
        "active_phases": [
            {
                "id": ticket.id,
                "phase": phase,
                "source": source,
                "record": record,
            }
            for ticket, phase, source, record in active_entries
        ],
        "frontier_skipped": [
            {"id": ticket.id, "reason": reason} for ticket, reason in skipped
        ],
        "runtime_state_path": str(runtime_state_path(root, cfg)),
        "runtime": (
            milestone_runtime_state(state, args.milestone)
            if args.milestone
            else state["milestones"]
        ),
        "errors": errors,
        "warnings": warnings,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 1 if errors else 0
    print(f"Repository: {root}")
    print(f"Branch: {payload['current_branch']} (base: {payload['base_branch']})")
    print(f"Base worktree: {'clean' if clean else 'dirty'}")
    for line in dirty:
        print(f"  {line}")
    if counts:
        print("Milestones:")
        for milestone, counter in sorted(counts.items()):
            details = ", ".join(f"{status}={count}" for status, count in sorted(counter.items()))
            print(f"  {milestone}: {details}")
    else:
        print("Milestones: no tickets")
    if selected:
        print("Ready frontier:")
        for ticket in selected:
            print(f"  {ticket.id} [{ticket.priority}] {ticket.title}")
    else:
        print("Ready frontier: none")
    if errors:
        print("Errors:")
        for error in errors:
            print(f"  - {error}")
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  - {warning}")
    return 1 if errors else 0


def cmd_run_validation(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    commands = cfg.get("validation", {}).get(args.scope, [])
    if not commands:
        raise WorkflowError(
            f"workflow.toml validation.{args.scope} is empty; refusing to claim a gate"
        )
    cwd = Path(args.cwd).resolve() if args.cwd else root
    if not cwd.exists():
        raise WorkflowError(f"Validation cwd does not exist: {cwd}")
    results: list[dict[str, Any]] = []
    for index, command in enumerate(commands, start=1):
        print(f"\n[{index}/{len(commands)}] {command}", flush=True)
        started = dt.datetime.now(dt.timezone.utc)
        proc = subprocess.run(command, cwd=str(cwd), shell=True, text=True, check=False)
        ended = dt.datetime.now(dt.timezone.utc)
        results.append(
            {
                "command": command,
                "exit": proc.returncode,
                "started": started.isoformat(),
                "ended": ended.isoformat(),
            }
        )
        if proc.returncode != 0:
            print(json.dumps({"scope": args.scope, "results": results}, indent=2))
            return proc.returncode or 1
    print(json.dumps({"scope": args.scope, "results": results}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and operate the Codex milestone workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              workflow.py doctor
              workflow.py frontier --milestone M1 --limit 3 --json
              workflow.py next --milestone M1 --limit 3 --json
              workflow.py worktree-create M1-T01
              workflow.py integration-create M1
              workflow.py run-validation quick --cwd .worktrees/m1-t01
              workflow.py test-budget --gate ticket --base main
              workflow.py review-state M1-T01 --json
            """
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("bootstrap", help="Create missing workflow document structure")
    p.set_defaults(func=cmd_bootstrap)

    p = sub.add_parser("doctor", help="Check environment and workflow installation")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("validate", help="Validate config, documents, and ticket graph")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser(
        "test-budget",
        help="Measure and enforce the configured production/test source budget",
    )
    p.add_argument("--gate", choices=sorted(TEST_BUDGET_GATES), default="report")
    p.add_argument("--base", help="Base branch or commit for delta measurement")
    p.add_argument("--tool", choices=sorted(TEST_BUDGET_TOOLS))
    p.add_argument("--write-baseline", action="store_true")
    p.add_argument("--cwd", help="Run against the Git worktree containing this path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_test_budget)

    p = sub.add_parser("status", help="Summarize repository and ticket state")
    p.add_argument("--milestone")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("frontier", help="Select dependency-ready, non-overlapping tickets")
    p.add_argument("--milestone")
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_frontier)

    p = sub.add_parser("next", help="Report the next orchestration action for a milestone")
    p.add_argument("--milestone", required=True)
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_next)

    p = sub.add_parser("new-ticket", help="Create a draft ticket")
    p.add_argument("--id", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--milestone", required=True)
    p.add_argument("--priority", default="P1")
    p.add_argument("--risk", choices=sorted(RISK_LEVELS), default="medium")
    p.add_argument(
        "--required-review",
        action="append",
        choices=("architect", "qa"),
        default=[],
    )
    p.add_argument("--spec", required=True)
    p.add_argument("--test-plan", required=True)
    p.add_argument(
        "--blocked-by",
        action="append",
        default=[],
        help="Legacy alias for --implementation-blocked-by",
    )
    p.add_argument("--implementation-blocked-by", action="append", default=[])
    p.add_argument("--review-blocked-by", action="append", default=[])
    p.add_argument("--integration-blocked-by", action="append", default=[])
    p.add_argument("--release-blocked-by", action="append", default=[])
    p.add_argument("--owns", action="append", required=True)
    p.add_argument("--acceptance", action="append", required=True)
    p.set_defaults(func=cmd_new_ticket)

    p = sub.add_parser("set-status", help="Apply a validated ticket state transition")
    p.add_argument("ticket_id")
    p.add_argument("status", choices=sorted(TICKET_STATUSES))
    p.add_argument("--force", action="store_true")
    p.add_argument("--branch", default="")
    p.add_argument("--worktree", default="")
    p.add_argument("--candidate-sha", default="")
    p.add_argument("--root-blocker", default="")
    p.set_defaults(func=cmd_set_status)

    p = sub.add_parser(
        "set-phase",
        help="Record a transient execution phase outside product Git history",
    )
    p.add_argument("ticket_id")
    p.add_argument("phase", choices=sorted(TRANSIENT_PHASES))
    p.add_argument("--branch", default="")
    p.add_argument("--worktree", default="")
    p.add_argument("--candidate-sha", default="")
    p.add_argument("--root-blocker", default="")
    p.set_defaults(func=cmd_set_phase)

    p = sub.add_parser(
        "clear-phase",
        help="Clear a ticket's transient execution phase",
    )
    p.add_argument("ticket_id")
    p.add_argument("--expect", choices=sorted(TRANSIENT_PHASES))
    p.set_defaults(func=cmd_clear_phase)

    p = sub.add_parser("gate-check", help="Check one ticket dependency gate")
    p.add_argument("ticket_id")
    p.add_argument("phase", choices=tuple(DEPENDENCY_FIELDS))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_gate_check)

    p = sub.add_parser("worktree-create", help="Create or reuse a ticket worktree")
    p.add_argument("ticket_id")
    p.set_defaults(func=cmd_worktree_create)

    p = sub.add_parser("integration-create", help="Create or reuse a milestone integration worktree")
    p.add_argument("milestone")
    p.set_defaults(func=cmd_integration_create)

    p = sub.add_parser("worktree-list", help="List worktrees with clean/dirty state")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_worktree_list)

    p = sub.add_parser("worktree-remove", help="Remove a clean worktree but preserve its branch")
    p.add_argument("identifier", help="Ticket ID, or milestone with --integration")
    p.add_argument("--integration", action="store_true")
    p.set_defaults(func=cmd_worktree_remove)

    p = sub.add_parser("state", help="Show local recoverable workflow state")
    p.add_argument("--milestone")
    p.set_defaults(func=cmd_state)

    p = sub.add_parser(
        "grant-authorization",
        help="Record an authorization that the user explicitly granted",
    )
    p.add_argument("milestone")
    p.add_argument("--scope", required=True)
    p.add_argument("--kind", choices=("local", "remote"), default="local")
    p.add_argument("--action", action="append", required=True)
    p.add_argument("--ticket", action="append", required=True)
    p.add_argument(
        "--blocker-class",
        action="append",
        choices=sorted(BLOCKER_CLASSES - {"none"}),
        required=True,
    )
    p.add_argument("--max-risk", choices=sorted(RISK_LEVELS), default="low")
    p.add_argument("--remote-effects", action="store_true")
    p.add_argument("--remote-ref", default="")
    p.add_argument("--commit-sha", default="")
    p.add_argument("--max-uses", type=int)
    p.add_argument(
        "--root-blocker",
        default="",
        help="Pre-bind one review_round_override to an open canonical root",
    )
    p.add_argument(
        "--reviewer",
        choices=sorted(REVIEWERS),
        default="",
        help="Pre-bind one review_round_override to architect or qa",
    )
    p.add_argument("--evidence", required=True)
    p.set_defaults(func=cmd_grant_authorization)

    p = sub.add_parser(
        "revoke-authorization",
        help="Atomically revoke an existing immutable authorization scope",
    )
    p.add_argument("milestone")
    p.add_argument("--scope", required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_revoke_authorization)

    p = sub.add_parser(
        "authorization-check",
        help="Check an action against exact recorded authorization scope",
    )
    p.add_argument("milestone")
    p.add_argument("--action", required=True)
    p.add_argument("--ticket", required=True)
    p.add_argument(
        "--blocker-class",
        choices=sorted(BLOCKER_CLASSES - {"none"}),
        required=True,
    )
    p.add_argument("--risk", choices=sorted(RISK_LEVELS), required=True)
    p.add_argument("--remote-effects", action="store_true")
    p.add_argument("--remote-ref", default="")
    p.add_argument("--commit-sha", default="")
    p.set_defaults(func=cmd_authorization_check)

    p = sub.add_parser(
        "consume-authorization",
        help="Atomically consume one exact authorization use before an action",
    )
    p.add_argument("milestone")
    p.add_argument("--action", required=True)
    p.add_argument("--ticket", required=True)
    p.add_argument(
        "--blocker-class",
        choices=sorted(BLOCKER_CLASSES - {"none"}),
        required=True,
    )
    p.add_argument("--risk", choices=sorted(RISK_LEVELS), required=True)
    p.add_argument("--remote-effects", action="store_true")
    p.add_argument("--remote-ref", default="")
    p.add_argument("--commit-sha", default="")
    p.add_argument("--root-blocker", default="")
    p.set_defaults(func=cmd_consume_authorization)

    p = sub.add_parser("record-blocker", help="Record one canonical root blocker")
    p.add_argument("ticket_id")
    p.add_argument("--id", dest="blocker_id")
    p.add_argument(
        "--class",
        dest="blocker_class",
        choices=sorted(BLOCKER_CLASSES - {"none"}),
        required=True,
    )
    p.add_argument(
        "--phase",
        choices=("implementation", "review", "integration", "release"),
        required=True,
    )
    p.add_argument("--risk", choices=sorted(RISK_LEVELS))
    p.add_argument("--root-cause", required=True)
    p.add_argument("--derived-from")
    p.add_argument("--derivative", action="append", default=[])
    p.add_argument("--owner")
    p.add_argument(
        "--authorization",
        choices=sorted(AUTHORIZATION_STATES),
        default="not_required",
    )
    p.add_argument("--evidence", action="append", default=[])
    p.add_argument("--unblock-condition", required=True)
    p.set_defaults(func=cmd_record_blocker)

    p = sub.add_parser(
        "record-review",
        help=(
            "Record one bounded full, targeted, or authorized superseding review; "
            "--root-blocker appends a later root-scoped cycle"
        ),
    )
    p.add_argument("ticket_id")
    p.add_argument("--reviewer", choices=sorted(REVIEWERS), required=True)
    p.add_argument("--round", choices=sorted(REVIEW_ROUNDS), required=True)
    p.add_argument("--verdict", choices=sorted(REVIEW_VERDICTS), required=True)
    p.add_argument("--candidate-sha", required=True)
    p.add_argument(
        "--finding",
        action="append",
        default=[],
        help="ID:severity:summary; use for initial or still-open findings",
    )
    p.add_argument(
        "--new-finding",
        action="append",
        default=[],
        help="ID:severity:origin:summary; targeted round only",
    )
    p.add_argument("--resolved", action="append", default=[])
    p.add_argument("--note", action="append", default=[])
    p.add_argument(
        "--root-blocker",
        default="",
        help="Canonical root for a superseding review or append-only later root cycle",
    )
    p.add_argument("--authorization-scope", default="")
    p.set_defaults(func=cmd_record_review)

    p = sub.add_parser("review-state", help="Show the bounded review gate for one ticket")
    p.add_argument("ticket_id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_review_state)

    p = sub.add_parser("resolve-blocker", help="Resolve a recorded root blocker")
    p.add_argument("blocker_id")
    p.add_argument("--resolution", required=True)
    p.set_defaults(func=cmd_resolve_blocker)

    p = sub.add_parser("record-repair", help="Record a risk-aware repair attempt")
    p.add_argument("ticket_id")
    p.add_argument("--root-blocker", required=True)
    p.add_argument("--class", dest="repair_class", choices=sorted(REPAIR_CLASSES), required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--commit", default="")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_record_repair)

    p = sub.add_parser(
        "checkpoint",
        help="Persist a drain/resume scheduler checkpoint outside product history",
    )
    p.add_argument("--milestone", required=True)
    p.add_argument("--limit", type=int)
    p.add_argument("--progress", choices=("material", "none"), required=True)
    p.add_argument("--wave-complete", action="store_true")
    p.add_argument("--new-run", action="store_true")
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("run-validation", help="Run a configured validation command list")
    p.add_argument("scope")
    p.add_argument("--cwd")
    p.set_defaults(func=cmd_run_validation)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info < MIN_PYTHON:
        eprint("Python 3.11+ is required")
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except WorkflowError as exc:
        eprint(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        eprint("interrupted; repository state was preserved")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
