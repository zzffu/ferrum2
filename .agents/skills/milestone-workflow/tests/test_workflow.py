from __future__ import annotations

import argparse
import copy
import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "workflow.py"
SPEC = importlib.util.spec_from_file_location("milestone_workflow", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
workflow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workflow
SPEC.loader.exec_module(workflow)


def ticket(
    ticket_id: str,
    status: str,
    *,
    owns: tuple[str, ...],
    blocked_by: tuple[str, ...] = (),
    implementation: tuple[str, ...] | None = None,
    review: tuple[str, ...] = (),
    integration: tuple[str, ...] = (),
    release: tuple[str, ...] = (),
    risk: str = "medium",
) -> workflow.Ticket:
    metadata: dict[str, object] = {
        "id": ticket_id,
        "title": ticket_id,
        "milestone": "M0",
        "status": status,
        "priority": "P1",
        "owns": list(owns),
        "spec": "spec.md",
        "test_plan": "test.md",
        "acceptance": ["observable"],
        "risk": risk,
    }
    if implementation is None:
        metadata["blocked_by"] = list(blocked_by)
    else:
        metadata["implementation_blocked_by"] = list(implementation)
    metadata["review_blocked_by"] = list(review)
    metadata["integration_blocked_by"] = list(integration)
    metadata["release_blocked_by"] = list(release)
    return workflow.Ticket(
        path=Path(f"{ticket_id}.md"),
        metadata=metadata,
        body="",
    )


class DependencyTests(unittest.TestCase):
    def test_legacy_blocked_by_remains_implementation_dependency(self) -> None:
        first = ticket("M0-T01", "ready", owns=("a/**",))
        second = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            blocked_by=("M0-T01",),
        )
        self.assertEqual(workflow.eligible_tickets([first, second]), [first])

    def test_integration_dependency_does_not_block_implementation(self) -> None:
        first = ticket("M0-T01", "in_progress", owns=("a/**",))
        second = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            implementation=(),
            integration=("M0-T01",),
        )
        by_id = {item.id: item for item in (first, second)}
        self.assertEqual(
            workflow.unmet_dependencies(second, "implementation", by_id),
            [],
        )
        self.assertEqual(
            workflow.unmet_dependencies(second, "integration", by_id),
            ["M0-T01"],
        )

    def test_gate_dependencies_are_cumulative_and_stably_deduplicated(self) -> None:
        first = ticket("M0-T01", "done", owns=("a/**",))
        second = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            implementation=("M0-T01",),
            review=("M0-T01",),
            integration=("M0-T01",),
        )
        self.assertEqual(
            second.dependencies_through("integration"),
            ["M0-T01"],
        )
        self.assertEqual(
            workflow.unmet_dependencies(
                second,
                "integration",
                {item.id: item for item in (first, second)},
            ),
            [],
        )

    def test_cycle_detection_reports_completion_deadlock(self) -> None:
        first = ticket(
            "M0-T01",
            "ready",
            owns=("a/**",),
            integration=("M0-T02",),
        )
        second = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            review=("M0-T01",),
        )
        self.assertEqual(
            workflow.detect_cycles([first, second]),
            [["M0-T01", "M0-T02", "M0-T01"]],
        )

    def test_release_only_edge_does_not_create_false_completion_cycle(self) -> None:
        first = ticket(
            "M0-T01",
            "ready",
            owns=("a/**",),
            integration=("M0-T02",),
        )
        second = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            release=("M0-T01",),
        )
        self.assertEqual(workflow.detect_cycles([first, second]), [])


class SchedulerTests(unittest.TestCase):
    def test_active_work_and_disjoint_frontier_are_returned_together(self) -> None:
        active = ticket("M0-T07", "in_progress", owns=("listener/**",))
        ready = ticket(
            "M0-T08",
            "ready",
            owns=("workflow/**",),
            implementation=(),
            integration=("M0-T07",),
        )
        state = workflow.milestone_scheduler_state([active, ready], "M0", 8)
        self.assertEqual(state["action"], "resume_and_execute_frontier")
        self.assertEqual(state["active"], ["M0-T07"])
        self.assertEqual(state["selected"], ["M0-T08"])

    def test_runtime_phase_is_active_while_tracked_status_stays_ready(self) -> None:
        active = ticket("M0-T07", "ready", owns=("listener/**",))
        ready = ticket("M0-T08", "ready", owns=("workflow/**",))
        runtime = {
            "phases": {
                active.id: {
                    "ticket_id": active.id,
                    "phase": "implementation",
                    "worktree": ".worktrees/m0-t07",
                }
            }
        }
        state = workflow.milestone_scheduler_state(
            [active, ready], "M0", 8, runtime
        )
        self.assertEqual(state["action"], "resume_and_execute_frontier")
        self.assertEqual(state["active"], ["M0-T07"])
        self.assertEqual(state["selected"], ["M0-T08"])
        self.assertEqual(
            state["active_details"][0]["phase_source"],
            "runtime",
        )

    def test_runtime_phase_overrides_legacy_status_adapter(self) -> None:
        active = ticket("M0-T07", "in_progress", owns=("listener/**",))
        runtime = {
            "phases": {
                active.id: {
                    "ticket_id": active.id,
                    "phase": "review",
                    "candidate_sha": "a" * 40,
                }
            }
        }
        state = workflow.milestone_scheduler_state([active], "M0", 8, runtime)
        self.assertEqual(state["active_details"][0]["phase"], "review")
        self.assertEqual(state["active_details"][0]["phase_source"], "runtime")

    def test_active_ownership_still_excludes_conflicting_frontier(self) -> None:
        active = ticket("M0-T07", "in_progress", owns=("shared/**",))
        ready = ticket(
            "M0-T08",
            "ready",
            owns=("shared/file.rs",),
            implementation=(),
        )
        state = workflow.milestone_scheduler_state([active, ready], "M0", 8)
        self.assertEqual(state["action"], "resume_active")
        self.assertEqual(state["selected"], [])
        self.assertIn("ownership overlaps active M0-T07", state["skipped"][0]["reason"])

    def test_release_dependency_prevents_ready_to_close(self) -> None:
        deferred = ticket("M0-T01", "deferred", owns=("a/**",))
        done = ticket(
            "M0-T02",
            "done",
            owns=("b/**",),
            release=("M0-T01",),
        )
        state = workflow.milestone_scheduler_state([deferred, done], "M0", 8)
        self.assertEqual(state["action"], "blocked")
        self.assertEqual(
            state["release_blocked"],
            [{"id": "M0-T02", "dependencies": ["M0-T01"]}],
        )

    def test_deferred_ticket_release_dependency_is_still_enforced(self) -> None:
        first = ticket(
            "M0-T01",
            "deferred",
            owns=("a/**",),
            release=("M0-T02",),
        )
        second = ticket("M0-T02", "deferred", owns=("b/**",))
        state = workflow.milestone_scheduler_state([first, second], "M0", 8)
        self.assertEqual(state["action"], "blocked")
        self.assertEqual(
            state["release_blocked"],
            [{"id": "M0-T01", "dependencies": ["M0-T02"]}],
        )

    def test_open_root_blocker_prevents_terminal_milestone_close(self) -> None:
        item = ticket("M0-T01", "done", owns=("a/**",))
        runtime = {
            "blockers": {
                "B1": {
                    "id": "B1",
                    "ticket_id": item.id,
                    "class": "code",
                    "phase": "integration",
                    "risk": "high",
                    "root_cause": "unresolved integration defect",
                    "root_cause_id": "B1",
                    "derived_from": None,
                    "status": "open",
                }
            }
        }
        state = workflow.milestone_scheduler_state([item], "M0", 8, runtime)
        self.assertEqual(state["action"], "blocked")
        self.assertEqual(state["open_root_blockers"], ["B1"])

    def test_review_blocker_does_not_block_implementation_frontier(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",))
        runtime = {
            "blockers": {
                "B1": {
                    "id": "B1",
                    "ticket_id": item.id,
                    "class": "test_evidence",
                    "phase": "review",
                    "risk": "medium",
                    "root_cause": "review evidence",
                    "root_cause_id": "B1",
                    "derived_from": None,
                    "status": "open",
                }
            }
        }
        state = workflow.milestone_scheduler_state([item], "M0", 8, runtime)
        self.assertEqual(state["action"], "execute_frontier")
        self.assertEqual(state["selected"], [item.id])

    def test_failed_ticket_only_blocks_independent_frontier_when_configured(self) -> None:
        failed = ticket("M0-T01", "failed", owns=("a/**",))
        ready = ticket("M0-T02", "ready", owns=("b/**",))
        continuing = workflow.milestone_scheduler_state(
            [failed, ready],
            "M0",
            8,
            continue_after_independent_failure=True,
        )
        stopping = workflow.milestone_scheduler_state(
            [failed, ready],
            "M0",
            8,
            continue_after_independent_failure=False,
        )
        self.assertEqual(continuing["selected"], ["M0-T02"])
        self.assertEqual(stopping["selected"], [])

    def test_exhausted_repair_budget_blocks_only_that_active_ticket(self) -> None:
        failed = ticket("M0-T01", "ready", owns=("a/**",), risk="critical")
        ready = ticket("M0-T02", "ready", owns=("b/**",))
        runtime = {
            "phases": {
                failed.id: {
                    "ticket_id": failed.id,
                    "phase": "repair",
                    "root_cause_id": "B1",
                }
            },
            "repairs": {
                failed.id: [
                    {
                        "class": "substantive",
                        "root_cause_id": "B1",
                    }
                ]
            },
            "blockers": {
                "B1": {
                    "id": "B1",
                    "ticket_id": failed.id,
                    "class": "code",
                    "phase": "implementation",
                    "risk": "critical",
                    "root_cause": "defect",
                    "root_cause_id": "B1",
                    "derived_from": None,
                }
            },
        }
        state = workflow.milestone_scheduler_state(
            [failed, ready], "M0", 8, runtime
        )
        self.assertEqual(state["action"], "execute_frontier")
        self.assertEqual(state["selected"], ["M0-T02"])
        self.assertEqual(state["blocked"][0]["class"], "authorization")

    def test_blocked_repair_does_not_consume_only_engineer_slot(self) -> None:
        failed = ticket("M0-T01", "ready", owns=("a/**",), risk="critical")
        ready = ticket("M0-T02", "ready", owns=("b/**",))
        runtime = {
            "phases": {
                failed.id: {
                    "ticket_id": failed.id,
                    "phase": "repair",
                    "root_cause_id": "B1",
                }
            },
            "repairs": {
                failed.id: [
                    {
                        "class": "substantive",
                        "root_cause_id": "B1",
                        "consumes_budget": True,
                    }
                ]
            },
            "repair_overrides": {},
            "blockers": {
                "B1": {
                    "id": "B1",
                    "ticket_id": failed.id,
                    "class": "code",
                    "phase": "implementation",
                    "risk": "critical",
                    "root_cause": "defect",
                    "root_cause_id": "B1",
                    "derived_from": None,
                    "status": "open",
                }
            },
        }
        state = workflow.milestone_scheduler_state(
            [failed, ready],
            "M0",
            1,
            runtime,
        )
        self.assertEqual(state["available_engineer_slots"], 1)
        self.assertEqual(state["selected"], [ready.id])
        self.assertEqual(state["action"], "execute_frontier")

    def test_repair_budget_is_isolated_per_canonical_root(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="critical")
        runtime = {
            "phases": {
                item.id: {
                    "ticket_id": item.id,
                    "phase": "repair",
                    "root_cause_id": "B2",
                }
            },
            "repairs": {
                item.id: [
                    {
                        "class": "substantive",
                        "root_cause_id": "B1",
                    }
                ]
            },
            "repair_overrides": {},
            "blockers": {
                blocker_id: {
                    "id": blocker_id,
                    "ticket_id": item.id,
                    "class": "code",
                    "phase": "implementation",
                    "risk": "critical",
                    "root_cause": blocker_id,
                    "root_cause_id": blocker_id,
                    "derived_from": None,
                }
                for blocker_id in ("B1", "B2")
            },
        }
        state = workflow.milestone_scheduler_state([item], "M0", 8, runtime)
        self.assertEqual(state["action"], "resume_active")
        self.assertEqual(
            state["active_details"][0]["repair_budget"]["consumed"],
            0,
        )

    def test_repair_uses_its_root_blocker_dependency_gate(self) -> None:
        dependency = ticket("M0-T01", "ready", owns=("a/**",))
        item = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            integration=("M0-T01",),
        )
        runtime = {
            "phases": {
                item.id: {
                    "ticket_id": item.id,
                    "phase": "repair",
                    "root_cause_id": "B1",
                }
            },
            "repairs": {},
            "repair_overrides": {},
            "blockers": {
                "B1": {
                    "id": "B1",
                    "ticket_id": item.id,
                    "class": "code",
                    "phase": "integration",
                    "risk": "high",
                    "root_cause": "integration defect",
                    "root_cause_id": "B1",
                    "derived_from": None,
                }
            },
        }
        state = workflow.milestone_scheduler_state(
            [dependency, item], "M0", 8, runtime
        )
        detail = next(
            detail for detail in state["active_details"] if detail["id"] == item.id
        )
        self.assertEqual(detail["dependency_gate"], "integration")
        self.assertEqual(detail["unmet_dependencies"], ["M0-T01"])

    def test_root_bound_override_creates_one_additional_attempt(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="critical")
        runtime = {
            "phases": {
                item.id: {
                    "ticket_id": item.id,
                    "phase": "repair",
                    "root_cause_id": "B1",
                }
            },
            "repairs": {
                item.id: [
                    {
                        "class": "substantive",
                        "root_cause_id": "B1",
                    }
                ]
            },
            "repair_overrides": {
                "B1": [
                    {
                        "authorization_scope": "one-more",
                    }
                ]
            },
            "blockers": {
                "B1": {
                    "id": "B1",
                    "ticket_id": item.id,
                    "class": "code",
                    "phase": "implementation",
                    "risk": "critical",
                    "root_cause": "defect",
                    "root_cause_id": "B1",
                    "derived_from": None,
                }
            },
        }
        allowed = workflow.milestone_scheduler_state([item], "M0", 8, runtime)
        self.assertEqual(allowed["action"], "resume_active")
        runtime["repairs"][item.id].append(
            {
                "class": "substantive",
                "root_cause_id": "B1",
            }
        )
        exhausted = workflow.milestone_scheduler_state([item], "M0", 8, runtime)
        self.assertEqual(exhausted["action"], "blocked")

    def test_scheduler_fingerprint_ignores_unrelated_output_fields(self) -> None:
        payload = {
            "action": "execute_frontier",
            "selected": ["M0-T01"],
            "active_details": [],
            "blocked": [],
            "release_blocked": [],
        }
        other = dict(payload, warnings=["not part of progress"])
        self.assertEqual(
            workflow.scheduler_fingerprint(payload),
            workflow.scheduler_fingerprint(other),
        )

    def test_wave_strategy_suppresses_next_frontier_after_one_wave(self) -> None:
        cfg = workflow.deep_merge(
            workflow.DEFAULT_CONFIG,
            {"execution": {"strategy": "wave"}},
        )
        payload = {
            "action": "execute_frontier",
            "selected": ["M0-T02"],
        }
        runtime = {
            "last_checkpoint": {
                "wave": 1,
                "no_progress_count": 0,
            }
        }
        workflow.apply_run_limits(payload, cfg, runtime)
        self.assertEqual(payload["action"], "run_limit_reached")
        self.assertEqual(payload["selected"], [])
        self.assertEqual(payload["selected_before_run_limit"], ["M0-T02"])

    def test_no_progress_limit_suppresses_resume_decision(self) -> None:
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        payload = {
            "action": "resume_active",
            "selected": [],
        }
        runtime = {
            "last_checkpoint": {
                "wave": 0,
                "no_progress_count": cfg["execution"]["no_progress_limit"],
            }
        }
        workflow.apply_run_limits(payload, cfg, runtime)
        self.assertEqual(payload["action"], "run_limit_reached")
        self.assertTrue(payload["no_progress_exhausted"])

    def test_non_material_checkpoint_never_resets_for_changed_fingerprint(self) -> None:
        self.assertEqual(workflow.next_no_progress_count(1, "none"), 2)
        self.assertEqual(workflow.next_no_progress_count(9, "material"), 0)


class RepairAndStateTests(unittest.TestCase):
    def test_mechanical_repair_does_not_consume_substantive_budget(self) -> None:
        item = ticket("M0-T01", "in_progress", owns=("a/**",), risk="low")
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        runtime = {
            "repairs": {
                item.id: [
                    {"class": "mechanical"},
                    {"class": "substantive"},
                ]
            }
        }
        summary = workflow.repair_summary(item, cfg, runtime)
        self.assertEqual(summary["budget"], 1)
        self.assertEqual(summary["consumed"], 1)
        self.assertEqual(summary["remaining"], 0)

    def test_persisted_budget_decision_survives_config_change(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="low")
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        runtime = {
            "repairs": {
                item.id: [
                    {
                        "class": "mechanical",
                        "consumes_budget": True,
                    },
                    {
                        "class": "substantive",
                        "consumes_budget": False,
                    },
                ]
            }
        }
        summary = workflow.repair_summary(item, cfg, runtime)
        self.assertEqual(summary["consumed"], 1)

    def test_runtime_state_is_shared_in_git_common_dir_and_revision_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(
                ["git", "init", "-q"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            cfg = workflow.deep_merge(
                workflow.DEFAULT_CONFIG,
                {"state": {"path": "codex/test-state.json"}},
            )
            first = workflow.empty_runtime_state()
            workflow.milestone_runtime_state(first, "M0")
            path = workflow.save_runtime_state(root, cfg, first)
            self.assertTrue(path.is_relative_to(workflow.git_common_dir(root)))
            self.assertEqual(first["revision"], 1)

            stale = workflow.load_runtime_state(root, cfg)
            current = workflow.load_runtime_state(root, cfg)
            workflow.milestone_runtime_state(current, "M1")
            workflow.save_runtime_state(root, cfg, current)
            with self.assertRaises(workflow.WorkflowError):
                workflow.save_runtime_state(root, cfg, stale)

    def test_runtime_state_lock_is_process_owned_and_stale_file_is_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(
                ["git", "init", "-q"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            cfg = workflow.deep_merge(
                workflow.DEFAULT_CONFIG,
                {"state": {"path": "codex/test-state.json"}},
            )
            state = workflow.empty_runtime_state()
            path = workflow.runtime_state_path(root, cfg)
            path.parent.mkdir(parents=True, exist_ok=True)
            lock = path.with_name(path.name + ".lock")
            lock.write_text("stale owner metadata\n", encoding="utf-8")
            workflow.save_runtime_state(root, cfg, state)
            self.assertTrue(lock.exists())
            self.assertEqual(state["revision"], 1)

            current = workflow.load_runtime_state(root, cfg)
            held = workflow.acquire_runtime_state_lock(lock)
            try:
                with self.assertRaisesRegex(
                    workflow.WorkflowError,
                    "locked by another writer",
                ):
                    workflow.save_runtime_state(root, cfg, current)
            finally:
                workflow.release_runtime_state_lock(held)
            self.assertEqual(current["revision"], 1)

            workflow.save_runtime_state(root, cfg, current)
            self.assertEqual(current["revision"], 2)

    def test_runtime_state_adds_new_optional_ledgers_on_resume(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        del runtime["repair_overrides"]
        resumed = workflow.milestone_runtime_state(state, "M0")
        self.assertEqual(resumed["repair_overrides"], {})

    def test_authorization_requires_exact_action_scope_risk_and_remote_boundary(self) -> None:
        runtime = {
            "authorizations": {
                "local-t07": {
                    "kind": "local",
                    "status": "granted",
                    "actions": ["local_repair"],
                    "tickets": ["M0-T07"],
                    "blocker_classes": ["mechanical", "code"],
                    "max_risk": "medium",
                    "remote_effects": False,
                }
            }
        }
        self.assertIsNotNone(
            workflow.matching_authorization(
                runtime,
                action="local_repair",
                ticket_id="M0-T07",
                blocker_class="code",
                risk="medium",
                remote_effects=False,
            )
        )
        for changed in (
            {"action": "push"},
            {"ticket_id": "M0-T08"},
            {"blocker_class": "security"},
            {"risk": "high"},
            {"remote_effects": True},
        ):
            request = {
                "action": "local_repair",
                "ticket_id": "M0-T07",
                "blocker_class": "code",
                "risk": "medium",
                "remote_effects": False,
            }
            request.update(changed)
            self.assertIsNone(
                workflow.matching_authorization(runtime, **request),
                changed,
            )

    def test_empty_or_remote_authorization_never_matches_local_scope(self) -> None:
        base = {
            "status": "granted",
            "actions": ["local_repair"],
            "tickets": ["M0-T07"],
            "blocker_classes": ["code"],
            "max_risk": "high",
            "remote_effects": False,
        }
        for changed in (
            {"kind": "local", "tickets": []},
            {"kind": "local", "blocker_classes": []},
            {"kind": "remote"},
        ):
            record = dict(base)
            record.update(changed)
            self.assertIsNone(
                workflow.matching_authorization(
                    {"authorizations": {"scope": record}},
                    action="local_repair",
                    ticket_id="M0-T07",
                    blocker_class="code",
                    risk="high",
                    remote_effects=False,
                )
            )

    def test_remote_authorization_matches_exact_ref_sha_once(self) -> None:
        commit_sha = "a" * 40
        record = {
            "kind": "remote",
            "status": "granted",
            "actions": ["push_integration_sha"],
            "tickets": ["M0-T08"],
            "blocker_classes": ["remote"],
            "max_risk": "high",
            "remote_effects": True,
            "remote_ref": "origin/codex/integration/m0",
            "commit_sha": commit_sha,
            "uses": 0,
            "max_uses": 1,
        }
        runtime = {"authorizations": {"one-push": record}}
        request = {
            "action": "push_integration_sha",
            "ticket_id": "M0-T08",
            "blocker_class": "remote",
            "risk": "high",
            "remote_effects": True,
            "remote_ref": "origin/codex/integration/m0",
            "commit_sha": commit_sha,
        }
        self.assertIsNotNone(workflow.matching_authorization(runtime, **request))
        self.assertIsNone(
            workflow.matching_authorization(
                runtime,
                **dict(request, remote_ref="origin/master"),
            )
        )
        record["uses"] = 1
        self.assertIsNone(workflow.matching_authorization(runtime, **request))

    def test_authorization_consumption_exhausts_one_use_scope(self) -> None:
        record = {
            "status": "granted",
            "uses": 0,
            "max_uses": 1,
        }
        workflow.consume_authorization_record(record)
        self.assertEqual(record["uses"], 1)
        self.assertEqual(record["status"], "revoked")

    def test_grant_cannot_overwrite_consumed_authorization_scope(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["authorizations"]["push-once"] = {
            "kind": "remote",
            "status": "revoked",
            "actions": ["push_integration_sha"],
            "tickets": ["M0-T08"],
            "blocker_classes": ["remote"],
            "max_risk": "high",
            "remote_effects": True,
            "remote_ref": "origin/codex/integration/m0",
            "commit_sha": "a" * 40,
            "uses": 1,
            "max_uses": 1,
        }
        args = argparse.Namespace(milestone="M0", scope="push-once")
        with (
            mock.patch.object(workflow, "git_root", return_value=Path.cwd()),
            mock.patch.object(
                workflow,
                "load_config",
                return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
            ),
            mock.patch.object(workflow, "load_runtime_state", return_value=state),
        ):
            with self.assertRaisesRegex(
                workflow.WorkflowError,
                "already exists and is immutable",
            ):
                workflow.cmd_grant_authorization(args)

    def test_runtime_state_rejects_derivative_without_direct_root(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B2"] = {
            "id": "B2",
            "ticket_id": "M0-T01",
            "class": "dependency",
            "phase": "implementation",
            "risk": "low",
            "root_cause": "derived symptom",
            "root_cause_id": "B1",
            "derived_from": "B1",
        }
        errors = workflow.runtime_state_errors(state)
        self.assertTrue(any("must name a root" in error for error in errors))

    def test_runtime_state_rejects_repair_without_canonical_root(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["repairs"]["M0-T01"] = [
            {"class": "substantive", "root_cause_id": "missing"}
        ]
        errors = workflow.runtime_state_errors(state)
        self.assertTrue(
            any("must name a canonical root blocker" in error for error in errors)
        )

    def test_runtime_state_requires_exact_remote_target_and_usage_limit(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["authorizations"]["push"] = {
            "kind": "remote",
            "status": "granted",
            "actions": ["push_integration_sha"],
            "tickets": ["M0-T08"],
            "blocker_classes": ["remote"],
            "max_risk": "high",
            "remote_effects": True,
            "uses": 0,
        }
        errors = workflow.runtime_state_errors(state)
        self.assertTrue(any("remote_ref is required" in error for error in errors))
        self.assertTrue(any("commit_sha must be" in error for error in errors))
        self.assertTrue(any("max_uses must be" in error for error in errors))

    def test_runtime_state_accepts_consumed_root_bound_override(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["authorizations"]["one-more"] = {
            "kind": "local",
            "status": "revoked",
            "actions": ["repair_budget_override"],
            "tickets": ["M0-T01"],
            "blocker_classes": ["code"],
            "max_risk": "high",
            "remote_effects": False,
            "uses": 1,
            "max_uses": 1,
        }
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": "M0-T01",
            "class": "code",
            "phase": "implementation",
            "risk": "high",
            "root_cause": "defect",
            "root_cause_id": "B1",
            "derived_from": None,
        }
        runtime["repair_overrides"]["B1"] = [
            {
                "authorization_scope": "one-more",
            }
        ]
        self.assertEqual(workflow.runtime_state_errors(state), [])

    def test_runtime_state_rejects_cross_ticket_repair_and_override_scope(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": "M0-T01",
            "class": "code",
            "phase": "implementation",
            "risk": "high",
            "root_cause": "defect",
            "root_cause_id": "B1",
            "derived_from": None,
            "status": "open",
        }
        runtime["authorizations"]["wrong-ticket"] = {
            "kind": "local",
            "status": "revoked",
            "actions": ["repair_budget_override"],
            "tickets": ["M0-T02"],
            "blocker_classes": ["code"],
            "max_risk": "high",
            "remote_effects": False,
            "uses": 1,
            "max_uses": 1,
        }
        runtime["repairs"]["M0-T02"] = [
            {
                "class": "substantive",
                "root_cause_id": "B1",
                "consumes_budget": True,
            }
        ]
        runtime["repair_overrides"]["B1"] = [
            {
                "authorization_scope": "wrong-ticket",
            }
        ]
        errors = workflow.runtime_state_errors(state)
        self.assertTrue(any("same ticket" in error for error in errors))
        self.assertTrue(any("does not cover that root" in error for error in errors))

    def test_resolving_derivative_resolves_root_family_and_repair_phases(self) -> None:
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"] = {
            "B1": {
                "id": "B1",
                "ticket_id": "M0-T01",
                "class": "code",
                "phase": "integration",
                "risk": "high",
                "root_cause": "root",
                "root_cause_id": "B1",
                "derived_from": None,
                "status": "open",
            },
            "B2": {
                "id": "B2",
                "ticket_id": "M0-T02",
                "class": "dependency",
                "phase": "integration",
                "risk": "high",
                "root_cause": "derived",
                "root_cause_id": "B1",
                "derived_from": "B1",
                "status": "open",
            },
        }
        runtime["phases"] = {
            ticket_id: {
                "ticket_id": ticket_id,
                "phase": "repair",
                "root_cause_id": "B1",
            }
            for ticket_id in ("M0-T01", "M0-T02")
        }
        root_id, resolved, cleared = workflow.resolve_blocker_family(
            runtime,
            "B2",
            "fixed",
            resolved_at="2026-07-28T00:00:00Z",
        )
        self.assertEqual(root_id, "B1")
        self.assertEqual(resolved, ["B1", "B2"])
        self.assertEqual(cleared, ["M0-T01", "M0-T02"])
        self.assertTrue(
            all(record["status"] == "resolved" for record in runtime["blockers"].values())
        )
        self.assertEqual(
            workflow.open_root_blocker_ids_for_ticket(
                runtime,
                "M0-T02",
                "release",
            ),
            [],
        )

    def test_repair_with_granted_marker_still_requires_exact_ledger_scope(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="high")
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": item.id,
            "class": "code",
            "phase": "implementation",
            "risk": "high",
            "root_cause": "defect",
            "root_cause_id": "B1",
            "derived_from": None,
            "authorization": "granted",
            "status": "open",
        }
        runtime["phases"][item.id] = {
            "ticket_id": item.id,
            "phase": "repair",
            "root_cause_id": "B1",
        }
        decision = workflow.milestone_scheduler_state([item], "M0", 8, runtime)
        self.assertEqual(decision["action"], "blocked")
        self.assertEqual(decision["blocked"][0]["class"], "authorization")

    def test_record_repair_consumes_limited_local_authorization(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="high")
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": item.id,
            "class": "code",
            "phase": "implementation",
            "risk": "high",
            "root_cause": "defect",
            "root_cause_id": "B1",
            "derived_from": None,
            "authorization": "required",
            "status": "open",
        }
        runtime["phases"][item.id] = {
            "ticket_id": item.id,
            "phase": "repair",
            "root_cause_id": "B1",
        }
        runtime["authorizations"]["one-repair"] = {
            "kind": "local",
            "status": "granted",
            "actions": ["local_repair"],
            "tickets": [item.id],
            "blocker_classes": ["code"],
            "max_risk": "high",
            "remote_effects": False,
            "uses": 0,
            "max_uses": 1,
        }
        args = argparse.Namespace(
            ticket_id=item.id,
            root_blocker="B1",
            repair_class="mechanical",
            note="line ending",
            commit="",
            force=False,
        )
        with (
            mock.patch.object(workflow, "git_root", return_value=Path.cwd()),
            mock.patch.object(
                workflow,
                "load_config",
                return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
            ),
            mock.patch.object(workflow, "load_tickets", return_value=[item]),
            mock.patch.object(workflow, "load_runtime_state", return_value=state),
            mock.patch.object(
                workflow,
                "save_runtime_state",
                return_value=Path.cwd() / "state.json",
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            workflow.cmd_record_repair(args)
        authorization = runtime["authorizations"]["one-repair"]
        self.assertEqual(authorization["uses"], 1)
        self.assertEqual(authorization["status"], "revoked")
        entry = runtime["repairs"][item.id][0]
        self.assertEqual(
            entry["repair_authorization_scope"],
            "one-repair",
        )
        self.assertEqual(entry["budget_override_authorization_scope"], "")

    def test_forced_repair_audits_repair_and_override_scopes_separately(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="critical")
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": item.id,
            "class": "code",
            "phase": "implementation",
            "risk": "critical",
            "root_cause": "defect",
            "root_cause_id": "B1",
            "derived_from": None,
            "authorization": "required",
            "status": "open",
        }
        runtime["phases"][item.id] = {
            "ticket_id": item.id,
            "phase": "repair",
            "root_cause_id": "B1",
        }
        runtime["repairs"][item.id] = [
            {
                "class": "substantive",
                "root_cause_id": "B1",
            }
        ]
        runtime["authorizations"] = {
            "repair-scope": {
                "kind": "local",
                "status": "granted",
                "actions": ["local_repair"],
                "tickets": [item.id],
                "blocker_classes": ["code"],
                "max_risk": "critical",
                "remote_effects": False,
                "uses": 0,
            },
            "override-scope": {
                "kind": "local",
                "status": "granted",
                "actions": ["repair_budget_override"],
                "tickets": [item.id],
                "blocker_classes": ["code"],
                "max_risk": "critical",
                "remote_effects": False,
                "uses": 0,
                "max_uses": 1,
            },
        }
        args = argparse.Namespace(
            ticket_id=item.id,
            root_blocker="B1",
            repair_class="substantive",
            note="one bounded retry",
            commit="",
            force=True,
        )
        with (
            mock.patch.object(workflow, "git_root", return_value=Path.cwd()),
            mock.patch.object(
                workflow,
                "load_config",
                return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
            ),
            mock.patch.object(workflow, "load_tickets", return_value=[item]),
            mock.patch.object(workflow, "load_runtime_state", return_value=state),
            mock.patch.object(
                workflow,
                "save_runtime_state",
                return_value=Path.cwd() / "state.json",
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            workflow.cmd_record_repair(args)
        entry = runtime["repairs"][item.id][-1]
        self.assertEqual(entry["repair_authorization_scope"], "repair-scope")
        self.assertEqual(
            entry["budget_override_authorization_scope"],
            "override-scope",
        )
        self.assertEqual(
            runtime["repair_overrides"]["B1"][0]["authorization_scope"],
            "override-scope",
        )

    def test_record_repair_requires_matching_active_repair_phase(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="high")
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": item.id,
            "class": "code",
            "phase": "implementation",
            "risk": "high",
            "root_cause": "defect",
            "root_cause_id": "B1",
            "derived_from": None,
            "status": "open",
        }
        args = argparse.Namespace(
            ticket_id=item.id,
            root_blocker="B1",
            repair_class="mechanical",
            note="wrong phase",
            commit="",
            force=False,
        )
        with (
            mock.patch.object(workflow, "git_root", return_value=Path.cwd()),
            mock.patch.object(
                workflow,
                "load_config",
                return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
            ),
            mock.patch.object(workflow, "load_tickets", return_value=[item]),
            mock.patch.object(workflow, "load_runtime_state", return_value=state),
        ):
            with self.assertRaisesRegex(
                workflow.WorkflowError,
                "must match its active repair phase",
            ):
                workflow.cmd_record_repair(args)


class PhaseCommandTests(unittest.TestCase):
    def test_legacy_set_status_records_phase_without_transient_ticket_edit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "M0-T01.md"
            path.write_text(
                '+++\nid = "M0-T01"\ntitle = "T"\nmilestone = "M0"\n'
                'status = "ready"\npriority = "P1"\nowns = ["a/**"]\n'
                'spec = "spec.md"\ntest_plan = "test.md"\n'
                'acceptance = ["ok"]\n+++\n',
                encoding="utf-8",
            )
            item = ticket("M0-T01", "ready", owns=("a/**",))
            object.__setattr__(item, "path", path)
            state = workflow.empty_runtime_state()
            args = argparse.Namespace(
                ticket_id=item.id,
                status="in_progress",
                force=False,
                branch="codex/ticket/m0-t01",
                worktree=str(root),
                candidate_sha="",
                root_blocker="",
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(
                    workflow,
                    "load_config",
                    return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
                ),
                mock.patch.object(workflow, "load_tickets", return_value=[item]),
                mock.patch.object(workflow, "load_runtime_state", return_value=state),
                mock.patch.object(
                    workflow,
                    "save_runtime_state",
                    return_value=root / "state.json",
                ),
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    workflow.cmd_set_status(args)
            self.assertIn('status = "ready"', path.read_text(encoding="utf-8"))
            self.assertEqual(
                state["milestones"]["M0"]["phases"][item.id]["phase"],
                "implementation",
            )

    def test_legacy_review_adapter_records_exact_candidate_sha(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "M0-T01.md"
            path.write_text('status = "ready"\n', encoding="utf-8")
            item = ticket("M0-T01", "ready", owns=("a/**",))
            object.__setattr__(item, "path", path)
            state = workflow.empty_runtime_state()
            candidate_sha = "a" * 40
            args = argparse.Namespace(
                ticket_id=item.id,
                status="review",
                force=False,
                branch="codex/ticket/m0-t01",
                worktree=str(root),
                candidate_sha=candidate_sha,
                root_blocker="",
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(
                    workflow,
                    "load_config",
                    return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
                ),
                mock.patch.object(workflow, "load_tickets", return_value=[item]),
                mock.patch.object(workflow, "load_runtime_state", return_value=state),
                mock.patch.object(
                    workflow,
                    "validate_candidate_commit",
                    return_value=candidate_sha,
                ),
                mock.patch.object(
                    workflow,
                    "save_runtime_state",
                    return_value=root / "state.json",
                ),
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    workflow.cmd_set_status(args)
            phase = state["milestones"]["M0"]["phases"][item.id]
            self.assertEqual(phase["phase"], "review")
            self.assertEqual(phase["candidate_sha"], candidate_sha)
            self.assertEqual(workflow.runtime_state_errors(state), [])

    def test_legacy_failed_adapter_requires_root_when_multiple_are_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "M0-T01.md"
            path.write_text('status = "ready"\n', encoding="utf-8")
            item = ticket("M0-T01", "ready", owns=("a/**",))
            object.__setattr__(item, "path", path)
            state = workflow.empty_runtime_state()
            runtime = workflow.milestone_runtime_state(state, "M0")
            runtime["blockers"] = {
                blocker_id: {
                    "id": blocker_id,
                    "ticket_id": item.id,
                    "class": "code",
                    "phase": "implementation",
                    "risk": "high",
                    "root_cause": blocker_id,
                    "root_cause_id": blocker_id,
                    "derived_from": None,
                    "status": "open",
                }
                for blocker_id in ("B1", "B2")
            }
            args = argparse.Namespace(
                ticket_id=item.id,
                status="failed",
                force=False,
                branch="codex/repair/m0-t01",
                worktree=str(root),
                candidate_sha="",
                root_blocker="",
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(
                    workflow,
                    "load_config",
                    return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
                ),
                mock.patch.object(workflow, "load_tickets", return_value=[item]),
                mock.patch.object(workflow, "load_runtime_state", return_value=state),
            ):
                with self.assertRaisesRegex(
                    workflow.WorkflowError,
                    "multiple open canonical roots",
                ):
                    workflow.cmd_set_status(args)

    def test_durable_status_edit_rolls_back_if_ledger_save_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "M0-T01.md"
            path.write_text('status = "ready"\n', encoding="utf-8")
            item = ticket("M0-T01", "ready", owns=("a/**",))
            object.__setattr__(item, "path", path)
            state = workflow.empty_runtime_state()
            runtime = workflow.milestone_runtime_state(state, "M0")
            runtime["phases"][item.id] = {
                "ticket_id": item.id,
                "phase": "implementation",
            }
            args = argparse.Namespace(
                ticket_id=item.id,
                status="blocked",
                force=False,
                branch="",
                worktree="",
                candidate_sha="",
                root_blocker="",
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(
                    workflow,
                    "load_config",
                    return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
                ),
                mock.patch.object(workflow, "load_tickets", return_value=[item]),
                mock.patch.object(workflow, "load_runtime_state", return_value=state),
                mock.patch.object(
                    workflow,
                    "save_runtime_state",
                    side_effect=workflow.WorkflowError("locked"),
                ),
            ):
                with self.assertRaises(workflow.WorkflowError):
                    workflow.cmd_set_status(args)
            self.assertEqual(path.read_text(encoding="utf-8"), 'status = "ready"\n')

    def test_idempotent_done_retry_clears_phase_after_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "M0-T01.md"
            original = b'status = "done"\r\n'
            path.write_bytes(original)
            item = ticket("M0-T01", "done", owns=("a/**",))
            object.__setattr__(item, "path", path)
            state = workflow.empty_runtime_state()
            runtime = workflow.milestone_runtime_state(state, "M0")
            runtime["phases"][item.id] = {
                "ticket_id": item.id,
                "phase": "integration",
                "candidate_sha": "a" * 40,
            }
            args = argparse.Namespace(
                ticket_id=item.id,
                status="done",
                force=False,
                branch="",
                worktree="",
                candidate_sha="",
                root_blocker="",
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(
                    workflow,
                    "load_config",
                    return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
                ),
                mock.patch.object(workflow, "load_tickets", return_value=[item]),
                mock.patch.object(workflow, "load_runtime_state", return_value=state),
                mock.patch.object(
                    workflow,
                    "save_runtime_state",
                    return_value=root / "state.json",
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                workflow.cmd_set_status(args)
            self.assertNotIn(item.id, runtime["phases"])
            self.assertEqual(path.read_bytes(), original)

    def test_status_replacement_preserves_crlf_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ticket.md"
            original = (
                b"+++\r\n"
                b'id = "M0-T01"\r\n'
                b'status = "ready"\r\n'
                b"+++\r\n"
                b"body\r\n"
            )
            path.write_bytes(original)
            workflow.replace_status(path, "blocked")
            updated = path.read_bytes()
            self.assertEqual(updated.count(b"\r\n"), original.count(b"\r\n"))
            self.assertNotIn(b"\n", updated.replace(b"\r\n", b""))
            self.assertIn(b'status = "blocked"\r\n', updated)

    def test_done_transition_rejects_open_integration_root_even_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "M0-T01.md"
            path.write_text('status = "ready"\n', encoding="utf-8")
            item = ticket("M0-T01", "ready", owns=("a/**",))
            object.__setattr__(item, "path", path)
            state = workflow.empty_runtime_state()
            runtime = workflow.milestone_runtime_state(state, "M0")
            runtime["blockers"]["B1"] = {
                "id": "B1",
                "ticket_id": item.id,
                "class": "code",
                "phase": "integration",
                "risk": "high",
                "root_cause": "defect",
                "root_cause_id": "B1",
                "derived_from": None,
                "status": "open",
            }
            runtime["phases"][item.id] = {
                "ticket_id": item.id,
                "phase": "integration",
                "candidate_sha": "a" * 40,
            }
            args = argparse.Namespace(
                ticket_id=item.id,
                status="done",
                force=True,
                branch="",
                worktree="",
                candidate_sha="",
                root_blocker="",
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(
                    workflow,
                    "load_config",
                    return_value=workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
                ),
                mock.patch.object(workflow, "load_tickets", return_value=[item]),
                mock.patch.object(workflow, "load_runtime_state", return_value=state),
            ):
                with self.assertRaisesRegex(
                    workflow.WorkflowError,
                    "open canonical root blockers",
                ):
                    workflow.cmd_set_status(args)


class SerializationTests(unittest.TestCase):
    def test_ticket_json_keeps_legacy_field_and_adds_phases(self) -> None:
        item = ticket(
            "M0-T02",
            "ready",
            owns=("b/**",),
            blocked_by=("M0-T01",),
            review=("M0-T03",),
        )
        payload = workflow.ticket_to_dict(Path.cwd(), item)
        self.assertEqual(payload["blocked_by"], ["M0-T01"])
        self.assertEqual(payload["implementation_blocked_by"], ["M0-T01"])
        self.assertEqual(payload["review_blocked_by"], ["M0-T03"])

    def test_live_document_templates_match_workflow_assets(self) -> None:
        root = MODULE_PATH.parents[4]
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        for destination, source in workflow.document_template_mapping(cfg).items():
            with self.subTest(destination=destination):
                self.assertEqual(
                    (root / destination).read_text(encoding="utf-8"),
                    (workflow.asset_dir() / source).read_text(encoding="utf-8"),
                )

    def test_new_ticket_contains_runtime_blocker_and_exact_sha_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = workflow.deep_merge(
                workflow.DEFAULT_CONFIG,
                {
                    "documents": {
                        "ticket_dir": "docs/tickets",
                    }
                },
            )
            args = argparse.Namespace(
                id="M0-T99",
                title="Generated contract",
                milestone="M0",
                priority="P1",
                risk="high",
                required_review=[],
                spec="docs/specs/SPEC-0001.md",
                test_plan="docs/test-plans/TEST-0001.md",
                blocked_by=[],
                implementation_blocked_by=[],
                review_blocked_by=[],
                integration_blocked_by=[],
                release_blocked_by=[],
                owns=["generated/**"],
                acceptance=["observable"],
            )
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(workflow, "load_config", return_value=cfg),
                mock.patch.object(workflow, "load_tickets", return_value=[]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                workflow.cmd_new_ticket(args)
            generated = next((root / "docs" / "tickets").glob("M0-T99-*.md"))
            text = generated.read_text(encoding="utf-8")
            self.assertIn('risk = "high"', text)
            self.assertIn('required_reviews = ["architect", "qa"]', text)
            self.assertIn("## Blocker record", text)
            self.assertIn("- Required reviewer role/profile and verdict:", text)
            self.assertIn("- Exact candidate SHA:", text)


class RepositoryStateTests(unittest.TestCase):
    def test_unborn_branch_is_reported_until_first_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            self.assertEqual(workflow.unborn_branch(root), "main")
            (root / "README.md").write_text("seed\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "seed",
                ],
                cwd=root,
                check=True,
            )
            self.assertIsNone(workflow.unborn_branch(root))
            self.assertTrue(workflow.branch_exists(root, "main"))


class TestEconomyTests(unittest.TestCase):
    def test_hidden_worktree_and_git_paths_are_excluded(self) -> None:
        settings = workflow.DEFAULT_CONFIG["quality"]["test_budget"]
        self.assertTrue(workflow._excluded(".git/checkouts/demo/src/lib.rs", settings))
        self.assertTrue(workflow._excluded("./.worktrees/ticket/src/lib.rs", settings))
        self.assertTrue(workflow._excluded("target/debug/build/generated.rs", settings))
        self.assertFalse(workflow._excluded("src/lib.rs", settings))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("pub fn live() {}\n", encoding="utf-8")
            (root / ".worktrees" / "ticket" / "src").mkdir(parents=True)
            (root / ".worktrees" / "ticket" / "src" / "lib.rs").write_text(
                "#[test]\nfn duplicate() {}\n", encoding="utf-8"
            )
            (root / ".git" / "checkouts" / "ticket").mkdir(parents=True)
            (root / ".git" / "checkouts" / "ticket" / "cached.rs").write_text(
                "#[test]\nfn cached() {}\n", encoding="utf-8"
            )
            counts = workflow.count_working_tree_builtin(root, settings)
        self.assertEqual((counts.code, counts.tests, counts.files), (1, 0, 1))

    def test_builtin_rust_counter_separates_cfg_test_and_test_paths(self) -> None:
        source = """pub fn answer() -> u32 {\n    42\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn works() {\n        assert_eq!(super::answer(), 42);\n    }\n}\n"""
        code, tests = workflow._count_source_text("src/lib.rs", source)
        self.assertEqual(code, 3)
        self.assertEqual(tests, 7)
        path_code, path_tests = workflow._count_source_text(
            "tests/integration.rs",
            "fn helper() {}\n#[test]\nfn integration() {}\n",
        )
        self.assertEqual(path_code, 0)
        self.assertEqual(path_tests, 3)

    def test_rustloc_parser_accepts_windows_style_total_row(self) -> None:
        output = """                  Name                   Code Tests\n───────────────────────────────────────────────────\nTotal (57 files)                         6254 15092\n"""
        completed = subprocess.CompletedProcess(
            args=["rustloc"], returncode=0, stdout=output, stderr=""
        )
        with (
            mock.patch.object(workflow.shutil, "which", return_value="rustloc"),
            mock.patch.object(workflow.subprocess, "run", return_value=completed),
        ):
            counts = workflow.count_rustloc(Path.cwd())
        self.assertEqual((counts.code, counts.tests, counts.files), (6254, 15092, 57))

    def test_fresh_ratchet_uses_target_and_existing_baseline_prevents_regression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = workflow.deep_merge(
                workflow.DEFAULT_CONFIG,
                {
                    "quality": {
                        "test_budget": {
                            "tool": "builtin",
                            "target_ratio": 1.0,
                            "max_regression": 0.0,
                        }
                    }
                },
            )
            current = workflow.SourceCounts(code=100, tests=80, files=2, tool="builtin")
            with (
                mock.patch.object(workflow, "count_working_tree_builtin", return_value=current),
                mock.patch.object(workflow, "load_test_budget_baseline", return_value=None),
                mock.patch.object(workflow, "_merge_base", return_value="a" * 40),
                mock.patch.object(
                    workflow,
                    "count_git_ref_builtin",
                    return_value=workflow.SourceCounts(100, 80, 2, "builtin"),
                ),
            ):
                payload, code = workflow.evaluate_test_budget(
                    root,
                    cfg,
                    gate="ticket",
                    base="main",
                    requested_tool="builtin",
                    write_baseline=False,
                )
            self.assertEqual(code, 0)
            self.assertEqual(payload["required_ratio"], 1.0)

            regressed = workflow.SourceCounts(code=100, tests=90, files=2, tool="builtin")
            baseline = {
                "schema_version": 1,
                "tool": "builtin",
                "counts": {"code": 100, "tests": 80},
            }
            with (
                mock.patch.object(workflow, "count_working_tree_builtin", return_value=regressed),
                mock.patch.object(workflow, "load_test_budget_baseline", return_value=baseline),
                mock.patch.object(workflow, "_merge_base", return_value="a" * 40),
                mock.patch.object(
                    workflow,
                    "count_git_ref_builtin",
                    return_value=workflow.SourceCounts(100, 80, 2, "builtin"),
                ),
            ):
                payload, code = workflow.evaluate_test_budget(
                    root,
                    cfg,
                    gate="ticket",
                    base="main",
                    requested_tool="builtin",
                    write_baseline=False,
                )
            self.assertEqual(code, 1)
            self.assertTrue(any("regressed beyond baseline" in reason for reason in payload["reasons"]))

    def test_ticket_delta_budget_rejects_large_test_only_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
            baseline = {
                "schema_version": 1,
                "tool": "builtin",
                "counts": {"code": 1000, "tests": 1000},
            }
            current = workflow.SourceCounts(code=1000, tests=1150, files=2, tool="builtin")
            with (
                mock.patch.object(workflow, "count_working_tree_builtin", return_value=current),
                mock.patch.object(workflow, "load_test_budget_baseline", return_value=baseline),
                mock.patch.object(workflow, "_merge_base", return_value="a" * 40),
                mock.patch.object(
                    workflow,
                    "count_git_ref_builtin",
                    return_value=workflow.SourceCounts(1000, 1000, 2, "builtin"),
                ),
            ):
                payload, code = workflow.evaluate_test_budget(
                    root,
                    cfg,
                    gate="ticket",
                    base="main",
                    requested_tool="builtin",
                    write_baseline=False,
                )
            self.assertEqual(code, 1)
            self.assertEqual(payload["delta"]["allowed_tests"], 120.0)
            self.assertTrue(any("test delta 150" in reason for reason in payload["reasons"]))

    def test_milestone_delta_is_reported_without_ticket_allowance_enforcement(self) -> None:
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        baseline = {
            "schema_version": 1,
            "tool": "builtin",
            "counts": {"code": 1000, "tests": 2000},
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                workflow, "load_test_budget_baseline", return_value=baseline
            ),
            mock.patch.object(workflow, "_merge_base", return_value="a" * 40),
            mock.patch.object(
                workflow,
                "count_git_ref_builtin",
                return_value=workflow.SourceCounts(1000, 2000, 2, "builtin"),
            ),
        ):
            for current_tests, expected_code in ((2500, 0), (2550, 1)):
                with self.subTest(current_tests=current_tests), mock.patch.object(
                    workflow,
                    "count_working_tree_builtin",
                    return_value=workflow.SourceCounts(1300, current_tests, 2, "builtin"),
                ):
                    payload, code = workflow.evaluate_test_budget(
                        Path(directory),
                        cfg,
                        gate="milestone",
                        base="main",
                        requested_tool="builtin",
                        write_baseline=False,
                    )
                self.assertEqual(code, expected_code)
                self.assertGreater(
                    payload["delta"]["tests"], payload["delta"]["allowed_tests"]
                )
                self.assertFalse(
                    any("test delta" in reason for reason in payload["reasons"])
                )
                self.assertEqual(
                    any("did not reach ratchet target" in reason for reason in payload["reasons"]),
                    expected_code == 1,
                )


class ReviewConvergenceTests(unittest.TestCase):
    @staticmethod
    def review_args(
        *,
        reviewer: str,
        round_name: str,
        verdict: str,
        finding: list[str] | None = None,
        new_finding: list[str] | None = None,
        resolved: list[str] | None = None,
        note: list[str] | None = None,
        sha: str = "a" * 40,
        root_blocker: str = "",
        authorization_scope: str = "",
    ) -> argparse.Namespace:
        return argparse.Namespace(
            ticket_id="M0-T01",
            reviewer=reviewer,
            round=round_name,
            verdict=verdict,
            candidate_sha=sha,
            finding=finding or [],
            new_finding=new_finding or [],
            resolved=resolved or [],
            note=note or [],
            root_blocker=root_blocker,
            authorization_scope=authorization_scope,
        )

    def _record(self, state: dict[str, object], item: workflow.Ticket, args: argparse.Namespace) -> int:
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        with (
            mock.patch.object(workflow, "git_root", return_value=Path.cwd()),
            mock.patch.object(workflow, "load_config", return_value=cfg),
            mock.patch.object(workflow, "load_tickets", return_value=[item]),
            mock.patch.object(workflow, "load_runtime_state", return_value=state),
            mock.patch.object(workflow, "save_runtime_state", return_value=Path("state.json")),
            mock.patch.object(workflow, "_append_review_debt"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            return workflow.cmd_record_review(args)

    def superseding_fixture(
        self,
        *,
        include_repair_finding: bool = False,
    ) -> tuple[dict[str, object], workflow.Ticket, dict[str, object], argparse.Namespace]:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="critical")
        state = workflow.empty_runtime_state()
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["blockers"]["B1"] = {
            "id": "B1",
            "ticket_id": item.id,
            "class": "security",
            "phase": "review",
            "risk": "critical",
            "root_cause": "security invariant",
            "root_cause_id": "B1",
            "derived_from": None,
            "status": "open",
        }
        self._record(
            state,
            item,
            self.review_args(
                reviewer="architect",
                round_name="full",
                verdict="block",
                finding=["ARCH-001:major:security invariant is violated"],
            ),
        )
        runtime["repairs"][item.id] = [
            {
                "class": "substantive",
                "root_cause_id": "B1",
                "consumes_budget": True,
                "recorded_at": "2026-07-28T00:01:00+00:00",
            }
        ]
        self._record(
            state,
            item,
            self.review_args(
                reviewer="architect",
                round_name="targeted",
                verdict="escalate",
                finding=["ARCH-001:major:security invariant remains violated"],
                new_finding=(
                    [
                        "ARCH-002:major:introduced_by_repair:"
                        "repair creates a cleanup gap"
                    ]
                    if include_repair_finding
                    else []
                ),
                sha="b" * 40,
            ),
        )
        targeted = runtime["reviews"][item.id]["reviewers"]["architect"]["targeted"]
        targeted["recorded_at"] = "2026-07-28T00:02:00+00:00"
        runtime["repairs"][item.id].append(
            {
                "class": "substantive",
                "root_cause_id": "B1",
                "consumes_budget": True,
                "budget_override_authorization_scope": "repair-override",
                "recorded_at": "2026-07-28T00:03:00+00:00",
            }
        )
        self._record(
            state,
            item,
            self.review_args(
                reviewer="qa",
                round_name="full",
                verdict="pass",
            ),
        )
        runtime["phases"][item.id] = {
            "ticket_id": item.id,
            "phase": "repair",
            "branch": "codex/ticket/m0-t01",
            "worktree": str(Path.cwd().resolve()),
            "candidate_sha": "c" * 40,
            "root_cause_id": "B1",
        }
        runtime["authorizations"]["review-override"] = {
            "kind": "local",
            "status": "granted",
            "actions": ["review_round_override"],
            "tickets": [item.id],
            "blocker_classes": ["security"],
            "max_risk": "critical",
            "remote_effects": False,
            "uses": 0,
            "max_uses": 1,
        }
        runtime["authorizations"]["repair-override"] = {
            "kind": "local",
            "status": "revoked",
            "actions": ["repair_budget_override"],
            "tickets": [item.id],
            "blocker_classes": ["security"],
            "max_risk": "critical",
            "remote_effects": False,
            "uses": 1,
            "max_uses": 1,
        }
        runtime["repair_overrides"]["B1"] = [
            {"authorization_scope": "repair-override"}
        ]
        args = self.review_args(
            reviewer="architect",
            round_name="superseding",
            verdict="pass",
            resolved=(
                ["ARCH-001", "ARCH-002"]
                if include_repair_finding
                else ["ARCH-001"]
            ),
            sha="c" * 40,
            root_blocker="B1",
            authorization_scope="review-override",
        )
        return state, item, runtime, args

    def root_cycle_verification_fixture(
        self,
    ) -> tuple[dict[str, object], workflow.Ticket, dict[str, object], argparse.Namespace]:
        state, item, runtime, args = self.superseding_fixture(
            include_repair_finding=True
        )
        legacy_reviewers = runtime["reviews"][item.id]["reviewers"]
        runtime["reviews"][item.id]["root_cycles"] = [
            {
                "root_cause_id": "B1",
                "ticket_id": item.id,
                "reviewers": {
                    "architect": copy.deepcopy(legacy_reviewers["architect"]),
                    "qa": copy.deepcopy(legacy_reviewers["qa"]),
                },
            }
        ]
        return state, item, runtime, args

    def test_superseding_review_preserves_escalation_consumes_scope_and_passes_gate(
        self,
    ) -> None:
        state, item, runtime, args = self.superseding_fixture()
        targeted = dict(runtime["reviews"][item.id]["reviewers"]["architect"]["targeted"])

        self.assertEqual(self._record(state, item, args), 0)

        rounds = runtime["reviews"][item.id]["reviewers"]["architect"]
        self.assertEqual(rounds["targeted"], targeted)
        superseding = rounds["superseding"]
        self.assertEqual(superseding["root_cause_id"], "B1")
        self.assertEqual(superseding["authorization_scope"], "review-override")
        self.assertEqual(
            superseding["supersedes"],
            {
                "round": "targeted",
                "candidate_sha": "b" * 40,
                "verdict": "escalate",
            },
        )
        self.assertEqual(runtime["authorizations"]["review-override"]["uses"], 1)
        self.assertEqual(runtime["authorizations"]["review-override"]["status"], "revoked")
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        self.assertEqual(workflow.review_gate_status(item, runtime, cfg), (True, []))
        self.assertEqual(workflow.runtime_state_errors(state), [])

    def test_superseding_review_resolves_repair_introduced_targeted_blocker(
        self,
    ) -> None:
        state, item, runtime, args = self.superseding_fixture(
            include_repair_finding=True
        )
        targeted = dict(runtime["reviews"][item.id]["reviewers"]["architect"]["targeted"])

        self.assertEqual(self._record(state, item, args), 0)

        rounds = runtime["reviews"][item.id]["reviewers"]["architect"]
        self.assertEqual(rounds["targeted"], targeted)
        self.assertEqual(
            rounds["superseding"]["resolved"],
            ["ARCH-001", "ARCH-002"],
        )
        self.assertEqual(rounds["superseding"]["findings"], [])
        self.assertEqual(runtime["authorizations"]["review-override"]["uses"], 1)
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        self.assertEqual(workflow.review_gate_status(item, runtime, cfg), (True, []))
        self.assertEqual(workflow.runtime_state_errors(state), [])

    def test_hosted_root_cycle_preserves_legacy_history_and_requires_one_final_sha(
        self,
    ) -> None:
        state, item, runtime, legacy_args = self.superseding_fixture()
        self.assertEqual(self._record(state, item, legacy_args), 0)
        legacy = copy.deepcopy(runtime["reviews"][item.id]["reviewers"])
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        self.assertEqual(workflow.review_gate_status(item, runtime, cfg), (True, []))

        root_id = "M2-T05-HOSTED-001"
        base_sha = "a168b89eb8dcd0c7a06df06b95a57d63893f2ab6"
        repair_sha = "c31290eb572aedc236be3613d23136fae17406ff"
        final_sha = "d" * 40
        runtime["blockers"][root_id] = {
            "id": root_id,
            "ticket_id": item.id,
            "class": "test_evidence",
            "phase": "release",
            "risk": "critical",
            "root_cause": "hosted release evidence failed",
            "root_cause_id": root_id,
            "derived_from": None,
            "status": "open",
        }
        self.assertEqual(
            self._record(
                state,
                item,
                self.review_args(
                    reviewer="architect",
                    round_name="full",
                    verdict="block",
                    finding=[
                        "ARCH-M2-T05-HOSTED-001:major:"
                        "hosted causal ordering is invalid"
                    ],
                    sha=base_sha,
                    root_blocker=root_id,
                ),
            ),
            1,
        )
        cycle = runtime["reviews"][item.id]["root_cycles"][-1]
        cycle["reviewers"]["architect"]["full"]["recorded_at"] = (
            "2026-07-29T00:00:00+00:00"
        )
        runtime["repairs"][item.id].append(
            {
                "class": "substantive",
                "root_cause_id": root_id,
                "consumes_budget": True,
                "recorded_at": "2026-07-29T00:01:00+00:00",
            }
        )
        self.assertEqual(
            self._record(
                state,
                item,
                self.review_args(
                    reviewer="architect",
                    round_name="targeted",
                    verdict="escalate",
                    resolved=["ARCH-M2-T05-HOSTED-001"],
                    new_finding=[
                        "ARCH-M2-T05-HOSTED-002:major:introduced_by_repair:"
                        "repair exceeds its test budget"
                    ],
                    sha=repair_sha,
                    root_blocker=root_id,
                ),
            ),
            1,
        )
        self.assertEqual(
            self._record(
                state,
                item,
                self.review_args(
                    reviewer="qa",
                    round_name="full",
                    verdict="pass_with_notes",
                    note=["hosted rerun remains release evidence"],
                    sha=repair_sha,
                    root_blocker=root_id,
                ),
            ),
            0,
        )
        self.assertEqual(runtime["reviews"][item.id]["reviewers"], legacy)
        passed, failures = workflow.review_gate_status(item, runtime, cfg)
        self.assertFalse(passed)
        self.assertIn("missing architect final review", failures)
        self.assertIn("missing qa final review", failures)

        cycle = runtime["reviews"][item.id]["root_cycles"][-1]
        architect_targeted = cycle["reviewers"]["architect"]["targeted"]
        architect_targeted["recorded_at"] = "2026-07-29T00:02:00+00:00"
        qa_full = cycle["reviewers"]["qa"]["full"]
        qa_full["recorded_at"] = "2026-07-29T00:02:00+00:00"
        runtime["repairs"][item.id].append(
            {
                "class": "substantive",
                "root_cause_id": root_id,
                "consumes_budget": True,
                "budget_override_authorization_scope": "hosted-repair-override",
                "recorded_at": "2026-07-29T00:03:00+00:00",
            }
        )
        runtime["repair_overrides"][root_id] = [
            {"authorization_scope": "hosted-repair-override"}
        ]
        runtime["authorizations"]["hosted-repair-override"] = {
            "kind": "local",
            "status": "revoked",
            "actions": ["repair_budget_override"],
            "tickets": [item.id],
            "blocker_classes": ["test_evidence"],
            "max_risk": "critical",
            "remote_effects": False,
            "uses": 1,
            "max_uses": 1,
        }
        for reviewer in ("architect", "qa"):
            runtime["authorizations"][f"hosted-review-{reviewer}"] = {
                "kind": "local",
                "status": "granted",
                "actions": ["review_round_override"],
                "tickets": [item.id],
                "blocker_classes": ["test_evidence"],
                "max_risk": "critical",
                "remote_effects": False,
                "uses": 0,
                "max_uses": 1,
            }
        runtime["phases"][item.id] = {
            "ticket_id": item.id,
            "phase": "repair",
            "branch": "codex/repair/m2-t05-hosted",
            "worktree": str(Path.cwd().resolve()),
            "candidate_sha": final_sha,
            "root_cause_id": root_id,
        }

        self.assertEqual(
            self._record(
                state,
                item,
                self.review_args(
                    reviewer="architect",
                    round_name="superseding",
                    verdict="pass_with_notes",
                    resolved=["ARCH-M2-T05-HOSTED-002"],
                    note=["hosted rerun remains separately authorized release evidence"],
                    sha=final_sha,
                    root_blocker=root_id,
                    authorization_scope="hosted-review-architect",
                ),
            ),
            0,
        )
        passed, failures = workflow.review_gate_status(item, runtime, cfg)
        self.assertFalse(passed)
        self.assertEqual(failures, ["missing qa final review"])
        self.assertEqual(
            self._record(
                state,
                item,
                self.review_args(
                    reviewer="qa",
                    round_name="superseding",
                    verdict="pass",
                    sha=final_sha,
                    root_blocker=root_id,
                    authorization_scope="hosted-review-qa",
                ),
            ),
            0,
        )

        cycle = runtime["reviews"][item.id]["root_cycles"][-1]
        self.assertEqual(cycle["root_cause_id"], root_id)
        self.assertEqual(cycle["ticket_id"], item.id)
        self.assertEqual(runtime["reviews"][item.id]["reviewers"], legacy)
        self.assertEqual(
            cycle["reviewers"]["architect"]["targeted"]["findings"][0]["origin"],
            "introduced_by_repair",
        )
        for reviewer in ("architect", "qa"):
            final = cycle["reviewers"][reviewer]["superseding"]
            self.assertEqual(final["candidate_sha"], final_sha)
            scope = runtime["authorizations"][f"hosted-review-{reviewer}"]
            self.assertEqual(scope["root_cause_id"], root_id)
            self.assertEqual(scope["reviewer"], reviewer)
        self.assertEqual(workflow.review_gate_status(item, runtime, cfg), (True, []))
        self.assertEqual(workflow.runtime_state_errors(state), [])

    def test_hosted_root_cycle_rejects_scope_drift_and_prior_evidence_mutation(
        self,
    ) -> None:
        cases = [
            ("new final finding", "does not accept new findings"),
            ("cross root", "active repair root"),
            ("cross ticket", "canonical root exactly"),
            ("rewrite baseline", "already used its full review"),
        ]
        for name, message in cases:
            with self.subTest(name=name):
                state, item, runtime, args = self.root_cycle_verification_fixture()
                if name == "new final finding":
                    args.new_finding = [
                        "ARCH-003:major:introduced_by_repair:new final finding"
                    ]
                elif name == "cross root":
                    runtime["blockers"]["B2"] = {
                        **runtime["blockers"]["B1"],
                        "id": "B2",
                        "root_cause_id": "B2",
                    }
                    args.root_blocker = "B2"
                elif name == "cross ticket":
                    runtime["blockers"]["B2"] = {
                        **runtime["blockers"]["B1"],
                        "id": "B2",
                        "ticket_id": "M0-T02",
                        "root_cause_id": "B2",
                    }
                    args.root_blocker = "B2"
                else:
                    args.round = "full"
                    args.verdict = "block"
                    args.finding = ["ARCH-999:major:replacement baseline"]
                    args.new_finding = []
                    args.resolved = []
                    args.authorization_scope = ""
                with self.assertRaisesRegex(workflow.WorkflowError, message):
                    self._record(state, item, args)

        state, item, runtime, args = self.root_cycle_verification_fixture()
        self.assertEqual(self._record(state, item, args), 0)
        reused = self.review_args(
            reviewer="qa",
            round_name="superseding",
            verdict="pass",
            sha="c" * 40,
            root_blocker="B1",
            authorization_scope="review-override",
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "unused"):
            self._record(state, item, reused)

        state, item, runtime, args = self.root_cycle_verification_fixture()
        self.assertEqual(self._record(state, item, args), 0)
        runtime["authorizations"]["qa-review-override"] = {
            **runtime["authorizations"]["review-override"],
            "status": "granted",
            "uses": 0,
        }
        runtime["authorizations"]["qa-review-override"].pop("root_cause_id", None)
        runtime["authorizations"]["qa-review-override"].pop("reviewer", None)
        runtime["phases"][item.id]["candidate_sha"] = "d" * 40
        self.assertEqual(
            self._record(
                state,
                item,
                self.review_args(
                    reviewer="qa",
                    round_name="superseding",
                    verdict="pass",
                    sha="d" * 40,
                    root_blocker="B1",
                    authorization_scope="qa-review-override",
                ),
            ),
            0,
        )
        passed, failures = workflow.review_gate_status(
            item,
            runtime,
            workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
        )
        self.assertFalse(passed)
        self.assertTrue(any("does not match" in failure for failure in failures))

        state, item, runtime, _args = self.root_cycle_verification_fixture()
        targeted = runtime["reviews"][item.id]["root_cycles"][0]["reviewers"][
            "architect"
        ]["targeted"]
        targeted["findings"][0]["origin"] = "previously_unobservable"
        errors = workflow.runtime_state_errors(state)
        self.assertTrue(
            any("preserve their ID, severity, and provenance" in error for error in errors)
        )

    def test_superseding_review_rejects_unaudited_or_broadened_dispositions(
        self,
    ) -> None:
        cases = [
            ("missing scope", "requires --authorization-scope"),
            ("wrong scope", "does not cover"),
            ("exhausted scope", "unused"),
            ("wrong candidate", "active repair SHA"),
            ("wrong root", "active repair root"),
            ("second record", "already used"),
            ("new finding", "does not accept new findings"),
            ("unknown targeted finding", "targeted escalation"),
            ("missing later repair", "later budget-consuming repair"),
            ("repair without override", "separately authorized"),
            ("repair with wrong override", "separately authorized"),
            ("unbounded review scope", "single-use"),
            ("multi-use review scope", "single-use"),
            ("target not escalated", "targeted escalation"),
            ("escalation without blocker", "blocking finding"),
            ("second block", "verdict must be"),
            ("passing with open finding", "unresolved"),
        ]
        for name, message in cases:
            with self.subTest(name=name):
                state, item, runtime, args = self.superseding_fixture()
                if name == "missing scope":
                    args.authorization_scope = ""
                elif name == "wrong scope":
                    runtime["authorizations"]["review-override"]["tickets"] = ["M0-T02"]
                elif name == "exhausted scope":
                    runtime["authorizations"]["review-override"].update(
                        status="revoked", uses=1
                    )
                elif name == "wrong candidate":
                    args.candidate_sha = "d" * 40
                elif name == "wrong root":
                    runtime["blockers"]["B2"] = {
                        **runtime["blockers"]["B1"],
                        "id": "B2",
                        "root_cause_id": "B2",
                    }
                    args.root_blocker = "B2"
                elif name == "second record":
                    runtime["reviews"][item.id]["reviewers"]["architect"][
                        "superseding"
                    ] = {}
                elif name == "new finding":
                    args.new_finding = [
                        "ARCH-002:major:introduced_by_repair:new security finding"
                    ]
                elif name == "unknown targeted finding":
                    args.finding = ["ARCH-999:major:not an original finding"]
                elif name == "missing later repair":
                    runtime["repairs"][item.id].pop()
                elif name == "repair without override":
                    runtime["repairs"][item.id][-1][
                        "budget_override_authorization_scope"
                    ] = ""
                elif name == "repair with wrong override":
                    runtime["repairs"][item.id][-1][
                        "budget_override_authorization_scope"
                    ] = "review-override"
                elif name == "unbounded review scope":
                    del runtime["authorizations"]["review-override"]["max_uses"]
                elif name == "multi-use review scope":
                    runtime["authorizations"]["review-override"]["max_uses"] = 2
                elif name == "target not escalated":
                    runtime["reviews"][item.id]["reviewers"]["architect"]["targeted"][
                        "verdict"
                    ] = "pass"
                elif name == "escalation without blocker":
                    runtime["reviews"][item.id]["reviewers"]["architect"]["targeted"][
                        "findings"
                    ] = []
                elif name == "second block":
                    args.verdict = "block"
                    args.resolved = []
                    args.finding = ["ARCH-001:major:still blocked"]
                else:
                    args.resolved = []
                uses_before = runtime["authorizations"]["review-override"]["uses"]
                with self.assertRaisesRegex(workflow.WorkflowError, message):
                    self._record(state, item, args)
                self.assertEqual(
                    runtime["authorizations"]["review-override"]["uses"],
                    uses_before,
                )

        state, item, runtime, args = self.superseding_fixture()
        self._record(state, item, args)
        runtime["reviews"][item.id]["reviewers"]["architect"]["superseding"][
            "authorization_scope"
        ] = "missing"
        errors = workflow.runtime_state_errors(state)
        self.assertTrue(any("authorization scope" in error for error in errors))

        for round_name in ("full", "targeted"):
            with self.subTest(round_name=round_name):
                state, item, _runtime, args = self.superseding_fixture()
                args.round = round_name
                with self.assertRaisesRegex(
                    workflow.WorkflowError,
                    "only valid for superseding",
                ):
                    self._record(state, item, args)

    def test_full_review_is_idempotent_but_cannot_be_reopened(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="high")
        state = workflow.empty_runtime_state()
        args = self.review_args(
            reviewer="architect",
            round_name="full",
            verdict="block",
            finding=["ARCH-001:major:observable contract violation"],
        )
        self.assertEqual(self._record(state, item, args), 1)
        self.assertEqual(self._record(state, item, args), 1)
        changed = self.review_args(
            reviewer="architect",
            round_name="full",
            verdict="block",
            finding=["ARCH-002:major:different finding"],
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "already used its full review"):
            self._record(state, item, changed)

    def test_targeted_review_requires_substantive_repair_and_resolves_stable_ids(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="high")
        state = workflow.empty_runtime_state()
        full = self.review_args(
            reviewer="architect",
            round_name="full",
            verdict="block",
            finding=["ARCH-001:major:contract violation"],
        )
        self._record(state, item, full)
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["repairs"][item.id] = [{"class": "mechanical", "consumes_budget": False}]
        targeted = self.review_args(
            reviewer="architect",
            round_name="targeted",
            verdict="pass",
            resolved=["ARCH-001"],
            sha="b" * 40,
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "substantive/evidence repair"):
            self._record(state, item, targeted)
        runtime["repairs"][item.id].append(
            {"class": "substantive", "consumes_budget": True}
        )
        self.assertEqual(self._record(state, item, targeted), 0)
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        passed, failures = workflow.review_gate_status(item, runtime, cfg)
        self.assertFalse(passed)  # QA is still required for a high-risk ticket.
        self.assertEqual(failures, ["missing qa review"])

    def test_targeted_review_rejects_moving_goalposts_and_second_block(self) -> None:
        item = ticket("M0-T01", "ready", owns=("a/**",), risk="medium")
        state = workflow.empty_runtime_state()
        self._record(
            state,
            item,
            self.review_args(
                reviewer="qa",
                round_name="full",
                verdict="block",
                finding=["QA-001:major:missing primary evidence"],
            ),
        )
        runtime = workflow.milestone_runtime_state(state, "M0")
        runtime["repairs"][item.id] = [{"class": "substantive", "consumes_budget": True}]
        moving = self.review_args(
            reviewer="qa",
            round_name="targeted",
            verdict="escalate",
            new_finding=["QA-002:major:previously_unobservable:new unrelated edge"],
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "violate policy"):
            self._record(state, item, moving)
        second_block = self.review_args(
            reviewer="qa",
            round_name="targeted",
            verdict="block",
            finding=["QA-001:major:still failing"],
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "recorded as escalate"):
            self._record(state, item, second_block)


class PlanningBudgetTests(unittest.TestCase):
    def test_acceptance_cap_is_error_before_execution_and_warning_after_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "spec.md").write_text("spec\n", encoding="utf-8")
            (root / "test.md").write_text("test\n", encoding="utf-8")
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
            ready = ticket("M0-T01", "ready", owns=("a/**",))
            ready.metadata["acceptance"] = [f"criterion {index}" for index in range(9)]
            with mock.patch.object(workflow, "load_tickets", return_value=[ready]):
                errors, warnings, _ = workflow.validate_tickets(root, cfg)
            self.assertTrue(any("acceptance criteria exceed" in error for error in errors))
            self.assertEqual(warnings, [])

            done = ticket("M0-T01", "done", owns=("a/**",))
            done.metadata["acceptance"] = [f"criterion {index}" for index in range(9)]
            with mock.patch.object(workflow, "load_tickets", return_value=[done]):
                errors, warnings, _ = workflow.validate_tickets(root, cfg)
            self.assertEqual(errors, [])
            self.assertTrue(any("acceptance criteria exceed" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
