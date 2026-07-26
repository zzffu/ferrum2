#!/usr/bin/env python3
"""Deterministic helper for the Codex milestone workflow.

Standard-library only. Python 3.11+ is required for tomllib.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import tomllib
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
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
ALLOWED_TRANSITIONS = {
    "draft": {"blocked", "ready", "deferred"},
    "blocked": {"draft", "ready", "deferred"},
    "ready": {"in_progress", "blocked", "deferred"},
    "in_progress": {"review", "blocked", "failed"},
    "review": {"in_progress", "blocked", "done", "failed"},
    "failed": {"in_progress", "blocked", "deferred"},
    "done": set(),
    "deferred": {"draft"},
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
    },
    "execution": {
        "strategy": "drain",
        "max_waves_per_run": 0,
        "max_repair_attempts_per_ticket": 2,
        "continue_after_independent_failure": True,
        "auto_close": False,
        "no_progress_limit": 2,
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
    },
    "validation": {"quick": [], "full": []},
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
        return [str(item) for item in self.metadata.get("blocked_by", [])]

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


def detect_cycles(tickets: Sequence[Ticket]) -> list[list[str]]:
    graph = {ticket.id: ticket.blockers for ticket in tickets}
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
        "blocked_by",
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
        if ticket.priority not in PRIORITY_ORDER:
            warnings.append(f"{ticket.id}: unusual priority {ticket.priority!r}; expected P0-P3")
        if not isinstance(ticket.metadata.get("blocked_by"), list):
            errors.append(f"{ticket.id}: blocked_by must be an array")
        if not ticket.owns:
            errors.append(f"{ticket.id}: owns must contain at least one explicit path")
        if any(not path.strip() for path in ticket.owns):
            errors.append(f"{ticket.id}: owns contains an empty path")
        acceptance = ticket.metadata.get("acceptance")
        if not isinstance(acceptance, list) or not acceptance or any(
            not str(item).strip() for item in acceptance
        ):
            errors.append(f"{ticket.id}: acceptance must be a non-empty array of statements")
        for label, document in (("spec", ticket.spec), ("test_plan", ticket.test_plan)):
            if not document:
                errors.append(f"{ticket.id}: {label} path is empty")
            elif not (root / document).exists():
                errors.append(f"{ticket.id}: {label} does not exist: {document}")

    for ticket in tickets:
        for blocker in ticket.blockers:
            if blocker == ticket.id:
                errors.append(f"{ticket.id}: cannot block itself")
            elif blocker not in by_id:
                errors.append(f"{ticket.id}: unknown blocker {blocker}")

    for cycle in detect_cycles(tickets):
        errors.append("Ticket dependency cycle: " + " -> ".join(cycle))

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


def eligible_tickets(tickets: Sequence[Ticket], milestone: str | None = None) -> list[Ticket]:
    by_id = {ticket.id: ticket for ticket in tickets}
    eligible: list[Ticket] = []
    for ticket in tickets:
        if ticket.status != "ready":
            continue
        if milestone and ticket.milestone.upper() != milestone.upper():
            continue
        if all(by_id.get(dep) and by_id[dep].status == "done" for dep in ticket.blockers):
            eligible.append(ticket)
    return sorted(
        eligible,
        key=lambda ticket: (PRIORITY_ORDER.get(ticket.priority, 99), ticket.id),
    )


def select_frontier(
    tickets: Sequence[Ticket], milestone: str | None, limit: int
) -> tuple[list[Ticket], list[tuple[Ticket, str]]]:
    selected: list[Ticket] = []
    skipped: list[tuple[Ticket, str]] = []
    for ticket in eligible_tickets(tickets, milestone):
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
    tickets: Sequence[Ticket], milestone: str, limit: int
) -> dict[str, Any]:
    """Return the next deterministic orchestration action for one milestone.

    This function does not mutate repository state or spawn agents. It gives the
    primary Codex thread a compact checkpoint for its execute/resume control loop.
    """

    normalized = milestone.strip().upper()
    scoped = [ticket for ticket in tickets if ticket.milestone.upper() == normalized]
    counts = collections.Counter(ticket.status for ticket in scoped)
    selected, skipped = select_frontier(tickets, normalized, limit)
    active = [
        ticket
        for ticket in scoped
        if ticket.status in {"in_progress", "review", "failed"}
    ]
    terminal = {"done", "deferred"}

    blocked: list[dict[str, Any]] = []
    by_id = {ticket.id: ticket for ticket in tickets}
    for ticket in scoped:
        reason = ""
        if ticket.status == "draft":
            reason = "contract is still draft"
        elif ticket.status == "blocked":
            reason = "ticket is explicitly blocked"
        elif ticket.status == "ready":
            unmet = [
                f"{dep}={by_id[dep].status if dep in by_id else 'missing'}"
                for dep in ticket.blockers
                if dep not in by_id or by_id[dep].status != "done"
            ]
            if unmet:
                reason = "unmet blockers: " + ", ".join(unmet)
        if reason:
            blocked.append({"id": ticket.id, "status": ticket.status, "reason": reason})

    if not scoped:
        action = "no_tickets"
    elif active:
        action = "resume_active"
    elif selected:
        action = "execute_frontier"
    elif all(ticket.status in terminal for ticket in scoped):
        action = "ready_to_close"
    else:
        action = "blocked"

    return {
        "milestone": normalized,
        "action": action,
        "counts": dict(sorted(counts.items())),
        "selected": [ticket.id for ticket in selected],
        "active": [ticket.id for ticket in active],
        "blocked": blocked,
        "skipped": [{"id": ticket.id, "reason": reason} for ticket, reason in skipped],
        "all_terminal": bool(scoped) and all(ticket.status in terminal for ticket in scoped),
    }


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


def write_if_missing(destination: Path, source: Path) -> bool:
    if destination.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True


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
        "adr": (str(Path(docs["adr_dir"]) / "ADR-0000-template.md"), "adr.md"),
        "spec": (str(Path(docs["spec_dir"]) / "SPEC-0000-template.md"), "spec.md"),
        "test": (
            str(Path(docs["test_plan_dir"]) / "TEST-0000-template.md"),
            "test-plan.md",
        ),
        "ticket": (
            str(Path(docs["ticket_dir"]) / "TICKET-0000-template.md"),
            "ticket.md",
        ),
        "handoff": (
            str(Path(docs["handoff_dir"]) / "HANDOFF-0000-template.md"),
            "handoff.md",
        ),
    }
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

    for key in ("vision", "gap_analysis", "roadmap", "ci_status"):
        path = root / str(cfg["documents"][key])
        if not path.exists():
            errors.append(f"Missing document: {relative(root, path)}")
    for key in ("adr_dir", "spec_dir", "test_plan_dir", "ticket_dir", "handoff_dir"):
        path = root / str(cfg["documents"][key])
        if not path.is_dir():
            errors.append(f"Missing document directory: {relative(root, path)}")

    ticket_errors, ticket_warnings, _ = validate_tickets(root, cfg)
    errors.extend(ticket_errors)
    warnings.extend(ticket_warnings)

    for scope in ("quick", "full"):
        commands = cfg.get("validation", {}).get(scope, [])
        if not isinstance(commands, list):
            errors.append(f"validation.{scope} must be an array of command strings")
        elif not commands:
            warnings.append(f"validation.{scope} is empty; that gate cannot pass")
        elif any(not isinstance(command, str) or not command.strip() for command in commands):
            errors.append(f"validation.{scope} contains an invalid command")

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
    except WorkflowError as exc:
        failures.append(str(exc))
        cfg = deep_merge(DEFAULT_CONFIG, {})

    required_files = [
        root / "AGENTS.md",
        root / "workflow.toml",
        root / ".codex" / "config.toml",
        root / ".agents" / "skills" / "milestone-workflow" / "SKILL.md",
    ]
    role_files = {
        "product-manager.toml": "product_manager",
        "architect.toml": "architect",
        "engineer.toml": "engineer",
        "qa.toml": "qa",
    }
    for filename in role_files:
        required_files.append(root / ".codex" / "agents" / filename)
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

    for filename, expected_name in role_files.items():
        role_path = root / ".codex" / "agents" / filename
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
        if role_cfg.get("name") != expected_name:
            failures.append(
                f"{relative(root, role_path)} defines name={role_cfg.get('name')!r}; "
                f"expected {expected_name!r}"
            )

    if root.joinpath(".gitignore").exists():
        ignored = {line.strip() for line in root.joinpath(".gitignore").read_text(encoding="utf-8").splitlines()}
        expected_ignore = str(cfg["workflow"]["worktree_root"]).rstrip("/") + "/"
        if expected_ignore not in ignored:
            warnings.append(f".gitignore does not contain {expected_ignore}")

    try:
        configured_base = str(cfg["workflow"]["base_branch"])
        if not branch_exists(root, configured_base):
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
        "blocked_by": ticket.blockers,
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
    selected, skipped = select_frontier(tickets, args.milestone, limit)
    payload = {
        "milestone": args.milestone,
        "limit": limit,
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
    payload = milestone_scheduler_state(tickets, args.milestone, limit)
    payload["strategy"] = str(cfg["execution"]["strategy"])
    payload["max_waves_per_run"] = int(cfg["execution"]["max_waves_per_run"])
    payload["auto_close"] = bool(cfg["execution"]["auto_close"])
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


def replace_status(path: Path, new_status: str) -> tuple[str, str]:
    metadata, _ = parse_frontmatter(path)
    old = str(metadata.get("status", ""))
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r'(?m)^status\s*=\s*"[^"]*"\s*$')
    replacement = f'status = "{new_status}"'
    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise WorkflowError(f"Could not replace status in {path}")
    path.write_text(updated, encoding="utf-8")
    return old, new_status


def cmd_set_status(args: argparse.Namespace) -> int:
    if args.status not in TICKET_STATUSES:
        raise WorkflowError(f"Invalid ticket status: {args.status}")
    root = git_root()
    cfg = load_config(root)
    ticket = find_ticket(load_tickets(root, cfg), args.ticket_id)
    if ticket.status == args.status:
        print(f"{ticket.id} already has status {args.status}")
        return 0
    if not args.force and args.status not in ALLOWED_TRANSITIONS.get(ticket.status, set()):
        raise WorkflowError(
            f"Transition {ticket.status} -> {args.status} is not allowed; use --force only "
            "after reconciling repository evidence"
        )
    old, new = replace_status(ticket.path, args.status)
    print(f"{ticket.id}: {old} -> {new}")
    return 0


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
    blocked = ", ".join(toml_string(item.upper()) for item in args.blocked_by)
    owns = ", ".join(toml_string(item) for item in args.owns)
    acceptance = ",\n  ".join(toml_string(item) for item in args.acceptance)
    content = f'''+++
id = {toml_string(ticket_id)}
title = {toml_string(args.title)}
milestone = {toml_string(args.milestone.upper())}
status = "draft"
priority = {toml_string(args.priority.upper())}
blocked_by = [{blocked}]
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

## Completion evidence

- Branch:
- Commit(s):
- Architect verdict:
- QA verdict:
- Integrated commit:
'''
    path.write_text(content, encoding="utf-8")
    print(relative(root, path))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = git_root()
    cfg = load_config(root)
    errors, warnings, tickets = validate_tickets(root, cfg)
    counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for ticket in tickets:
        counts[ticket.milestone][ticket.status] += 1
    clean, dirty = is_clean(root)
    max_parallel = int(cfg["workflow"]["max_parallel_engineers"])
    selected, skipped = select_frontier(tickets, args.milestone, max_parallel)
    payload = {
        "repository": str(root),
        "current_branch": current_branch(root),
        "base_branch": cfg["workflow"]["base_branch"],
        "base_worktree_clean": clean,
        "base_worktree_dirty": dirty,
        "milestones": {milestone: dict(counter) for milestone, counter in sorted(counts.items())},
        "frontier": [ticket_to_dict(root, ticket) for ticket in selected],
        "frontier_skipped": [
            {"id": ticket.id, "reason": reason} for ticket, reason in skipped
        ],
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
    p.add_argument("--spec", required=True)
    p.add_argument("--test-plan", required=True)
    p.add_argument("--blocked-by", action="append", default=[])
    p.add_argument("--owns", action="append", required=True)
    p.add_argument("--acceptance", action="append", required=True)
    p.set_defaults(func=cmd_new_ticket)

    p = sub.add_parser("set-status", help="Apply a validated ticket state transition")
    p.add_argument("ticket_id")
    p.add_argument("status", choices=sorted(TICKET_STATUSES))
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_set_status)

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

    p = sub.add_parser("run-validation", help="Run configured quick or full command list")
    p.add_argument("scope", choices=("quick", "full"))
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
