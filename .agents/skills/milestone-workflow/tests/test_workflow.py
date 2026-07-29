from __future__ import annotations

import argparse
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


class FeatureContextTests(unittest.TestCase):
    @staticmethod
    def _context_text(*, include_planned: bool = True, todo: bool = False) -> str:
        value = "TODO" if todo else "verified"
        planned = (
            f"- Active planned changes: None.\n" if include_planned else ""
        )
        return (
            "# Repository instructions\n\n"
            "## Project-specific context\n\n"
            f"- Product purpose: {value} product purpose.\n"
            f"- Primary languages/frameworks: {value} Rust workspace.\n"
            f"- Architecture entry points: {value} src/lib.rs.\n"
            f"- Critical invariants: {value} compatibility invariant.\n"
            f"- Generated files: {value} target is generated.\n"
            f"- Local development setup: {value} cargo test.\n"
            + planned
            + "- Deployment topology: verified local process.\n\n"
            "## Project validation\n\nUse workflow.toml.\n"
        )

    @staticmethod
    def _roadmap(statuses: list[tuple[str, str]]) -> str:
        body = ["# Roadmap", ""]
        for milestone, status in statuses:
            body.extend(
                [
                    f"## {milestone} — milestone",
                    "",
                    f"- **Status:** `{status}`",
                    "",
                ]
            )
        return "\n".join(body)

    def _repo(
        self,
        root: Path,
        *,
        context_text: str | None = None,
        statuses: list[tuple[str, str]] | None = None,
    ) -> dict[str, object]:
        cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
        (root / "docs/tickets").mkdir(parents=True)
        (root / "docs/context-audits").mkdir(parents=True)
        (root / "docs").mkdir(exist_ok=True)
        (root / "AGENTS.md").write_text(
            context_text or self._context_text(), encoding="utf-8"
        )
        (root / "docs/roadmap.md").write_text(
            self._roadmap(statuses or []), encoding="utf-8"
        )
        subprocess.run(
            ["git", "init", "-b", "main"],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "workflow@example.invalid"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Workflow Tests"],
            cwd=root,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(
            ["git", "commit", "-m", "baseline"],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
        return cfg

    def test_inventory_covers_required_and_project_added_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(root)
            inventory = workflow.project_context_inventory(root, cfg)
            names = [item["name"] for item in inventory["entries"]]
            self.assertIn("Active planned changes", names)
            self.assertIn("Deployment topology", names)
            self.assertEqual(inventory["missing_required"], [])
            self.assertEqual(inventory["extra_entries"], ["Deployment topology"])
            self.assertRegex(inventory["sha256"], r"^[0-9a-f]{64}$")

    def test_inventory_reports_missing_planned_changes_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(
                root,
                context_text=self._context_text(include_planned=False),
            )
            inventory = workflow.project_context_inventory(root, cfg)
            self.assertEqual(
                inventory["missing_required"], ["Active planned changes"]
            )

    def test_next_milestone_is_m5_after_m0_through_m4(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(
                root,
                statuses=[(f"M{index}", "closed") for index in range(5)],
            )
            self.assertEqual(workflow.known_milestones(root, cfg), [f"M{i}" for i in range(5)])
            self.assertEqual(workflow.next_milestone_id(root, cfg), "M5")
            self.assertEqual(workflow.open_prior_milestones(root, cfg, "M5"), [])

    def test_feature_preflight_rejects_open_previous_milestone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(
                root,
                statuses=[("M0", "closed"), ("M1", "proposed")],
            )
            args = argparse.Namespace(
                goal="Add multi-user support",
                milestone=None,
                slug=None,
                write_audit=True,
                force=False,
                allow_open_milestones=False,
                reuse_existing=False,
                json=True,
            )
            output = io.StringIO()
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(workflow, "load_config", return_value=cfg),
                contextlib.redirect_stdout(output),
            ):
                code = workflow.cmd_feature_preflight(args)
            payload = __import__("json").loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertFalse(payload["ready"])
            self.assertEqual(payload["milestone"], "M2")
            self.assertIn("previous milestones are not closed", payload["blockers"])
            self.assertFalse((root / payload["audit_path"]).exists())

    def test_feature_preflight_creates_m5_audit_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(
                root,
                statuses=[(f"M{index}", "closed") for index in range(5)],
            )
            args = argparse.Namespace(
                goal="增加多用户管理",
                milestone=None,
                slug=None,
                write_audit=True,
                force=False,
                allow_open_milestones=False,
                reuse_existing=False,
                json=True,
            )
            payloads: list[dict[str, object]] = []
            output = io.StringIO()
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(workflow, "load_config", return_value=cfg),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(workflow.cmd_feature_preflight(args), 0)
            payloads.append(__import__("json").loads(output.getvalue()))
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "draft context audit"],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            output = io.StringIO()
            with (
                mock.patch.object(workflow, "git_root", return_value=root),
                mock.patch.object(workflow, "load_config", return_value=cfg),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(workflow.cmd_feature_preflight(args), 0)
            payloads.append(__import__("json").loads(output.getvalue()))
            self.assertEqual(payloads[0]["milestone"], "M5")
            self.assertEqual(payloads[1]["milestone"], "M5")
            self.assertEqual(
                payloads[0]["audit_path"], "docs/context-audits/CONTEXT-M5-feature.md"
            )
            self.assertTrue(payloads[0]["audit_created"])
            self.assertFalse(payloads[1]["audit_created"])
            audit = root / str(payloads[0]["audit_path"])
            self.assertTrue(audit.is_file())
            metadata, body = workflow.parse_frontmatter(audit)
            self.assertEqual(metadata["milestone"], "M5")
            self.assertEqual(metadata["status"], "draft")
            self.assertIn("Deployment topology", metadata["entries"])
            self.assertIn("增加多用户管理", body)

    def test_ready_feature_ticket_requires_approved_context_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(
                root,
                statuses=[(f"M{index}", "closed") for index in range(5)],
            )
            inventory = workflow.project_context_inventory(root, cfg)
            audit = root / "docs/context-audits/CONTEXT-M5-feature.md"
            audit.write_text(
                workflow.render_context_audit(
                    milestone="M5",
                    goal="Add feature",
                    baseline_commit=workflow.current_commit(root),
                    inventory=inventory,
                ),
                encoding="utf-8",
            )
            (root / "spec.md").write_text("spec\n", encoding="utf-8")
            (root / "test.md").write_text("test\n", encoding="utf-8")
            item = ticket("M5-T01", "ready", owns=("src/**",))
            item.metadata["milestone"] = "M5"
            with mock.patch.object(workflow, "load_tickets", return_value=[item]):
                errors, _, _ = workflow.validate_tickets(root, cfg)
            self.assertTrue(any("audit is not approved" in error for error in errors))

    def test_approved_context_audit_passes_then_detects_context_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self._repo(
                root,
                statuses=[(f"M{index}", "closed") for index in range(5)],
            )
            inventory = workflow.project_context_inventory(root, cfg)
            baseline = workflow.current_commit(root)
            text = workflow.render_context_audit(
                milestone="M5",
                goal="Add multi-user support",
                baseline_commit=baseline,
                inventory=inventory,
            )
            text = text.replace('status = "draft"', 'status = "approved"')
            text = text.replace(
                'after_context_sha256 = ""',
                f'after_context_sha256 = "{inventory["sha256"]}"',
            )
            text = text.replace(
                "reviewers = []",
                'reviewers = ["product_manager", "architect", "qa"]',
            )
            text = text.replace("TODO", "verified evidence")
            audit = root / "docs/context-audits/CONTEXT-M5-multi-user.md"
            audit.write_text(text, encoding="utf-8")
            self.assertEqual(
                workflow.context_audit_errors(
                    root,
                    cfg,
                    audit,
                    expected_milestone="M5",
                    require_approved=True,
                ),
                [],
            )
            agents = root / "AGENTS.md"
            agents.write_text(
                agents.read_text(encoding="utf-8").replace(
                    "verified product purpose", "changed product purpose"
                ),
                encoding="utf-8",
            )
            errors = workflow.context_audit_errors(
                root,
                cfg,
                audit,
                expected_milestone="M5",
                require_approved=True,
            )
            self.assertTrue(any("after_context_sha256 does not match" in item for item in errors))



class ControlPlaneTests(unittest.TestCase):
    def init_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)

    def write_manifest(self, root: Path, rel: str, content: bytes) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        manifest = root / workflow.INSTALL_METADATA_PATH
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(
            __import__("json").dumps(
                {
                    "schema_version": 1,
                    "package_version": "test",
                    "managed_files": {
                        rel: workflow._logical_hash_bytes(content),
                    },
                    "protected_files": {},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_manifest_detects_semantic_drift_but_ignores_eol_only_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            rel = ".agents/skills/milestone-workflow/SKILL.md"
            self.write_manifest(root, rel, b"line one\nline two\n")
            (root / "workflow.toml").write_text("version = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=root, check=True, capture_output=True)
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})

            clear = workflow.control_plane_report(root, cfg)
            self.assertTrue(clear["clear"], clear)

            (root / rel).write_bytes(b"line one\r\nline two\r\n")
            eol = workflow.control_plane_report(root, cfg)
            self.assertTrue(eol["clear"], eol)
            self.assertEqual(eol["manifest_drift"], [])

            (root / rel).write_text("semantic change\n", encoding="utf-8")
            drift = workflow.control_plane_report(root, cfg)
            self.assertFalse(drift["clear"])
            self.assertEqual(drift["manifest_drift"][0]["path"], rel)


    def test_agents_workflow_section_is_protected_while_context_may_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            rel = ".agents/skills/milestone-workflow/SKILL.md"
            self.write_manifest(root, rel, b"skill\n")
            agents = root / "AGENTS.md"
            agents.write_text(
                "## Project-specific context\n\n"
                "- Product purpose: original\n\n"
                f"{workflow.AGENTS_WORKFLOW_BEGIN}\n"
                "workflow policy\n"
                f"{workflow.AGENTS_WORKFLOW_END}\n",
                encoding="utf-8",
            )
            manifest = root / workflow.INSTALL_METADATA_PATH
            payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
            section = workflow._extract_protected_section(
                root, "AGENTS.md#codex_milestone_workflow"
            )
            self.assertIsNotNone(section)
            payload["protected_sections"] = {
                "AGENTS.md#codex_milestone_workflow": workflow._logical_hash_bytes(section)
            }
            manifest.write_text(
                __import__("json").dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            (root / "workflow.toml").write_text("version = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True
            )
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})

            agents.write_text(
                agents.read_text(encoding="utf-8").replace("original", "updated truth"),
                encoding="utf-8",
            )
            context_only = workflow.control_plane_report(root, cfg)
            self.assertTrue(context_only["clear"], context_only)
            self.assertEqual(context_only["section_drift"], [])

            agents.write_text(
                agents.read_text(encoding="utf-8").replace(
                    "workflow policy", "self-modified workflow policy"
                ),
                encoding="utf-8",
            )
            drift = workflow.control_plane_report(root, cfg)
            self.assertFalse(drift["clear"])
            self.assertEqual(
                drift["section_drift"][0]["path"],
                "AGENTS.md#codex_milestone_workflow",
            )

    def test_candidate_section_change_is_rejected_without_blocking_context_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            rel = ".agents/skills/milestone-workflow/SKILL.md"
            self.write_manifest(root, rel, b"skill\n")
            agents = root / "AGENTS.md"
            agents.write_text(
                "## Project-specific context\n\n"
                "- Product purpose: original\n\n"
                f"{workflow.AGENTS_WORKFLOW_BEGIN}\n"
                "workflow policy\n"
                f"{workflow.AGENTS_WORKFLOW_END}\n",
                encoding="utf-8",
            )
            manifest = root / workflow.INSTALL_METADATA_PATH
            payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
            section = workflow._extract_protected_section(
                root, "AGENTS.md#codex_milestone_workflow"
            )
            assert section is not None
            payload["protected_sections"] = {
                "AGENTS.md#codex_milestone_workflow": workflow._logical_hash_bytes(section)
            }
            manifest.write_text(
                __import__("json").dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            (root / "workflow.toml").write_text("version = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
            ).stdout.strip()

            agents.write_text(
                agents.read_text(encoding="utf-8")
                .replace("original", "valid feature truth")
                .replace("workflow policy", "candidate self modification"),
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "AGENTS.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "candidate"], cwd=root, check=True, capture_output=True
            )
            candidate = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
            ).stdout.strip()
            subprocess.run(["git", "checkout", "--detach", base], cwd=root, check=True, capture_output=True)
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
            report = workflow.control_plane_report(
                root, cfg, base=base, candidate=candidate, include_worktree=False
            )
            self.assertFalse(report["clear"])
            self.assertEqual(report["candidate_paths"], [])
            self.assertEqual(
                report["candidate_section_drift"][0]["path"],
                "AGENTS.md#codex_milestone_workflow",
            )


    def test_gitattributes_control_section_is_protected_but_project_rules_may_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            rel = ".agents/skills/milestone-workflow/SKILL.md"
            self.write_manifest(root, rel, b"skill\n")
            attrs = root / ".gitattributes"
            attrs.write_text(
                "*.rs text eol=lf\n"
                f"{workflow.GITATTRIBUTES_WORKFLOW_BEGIN}\n"
                "/.agents/skills/** text eol=lf\n"
                f"{workflow.GITATTRIBUTES_WORKFLOW_END}\n",
                encoding="utf-8",
            )
            manifest = root / workflow.INSTALL_METADATA_PATH
            payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
            section = workflow._extract_protected_section(
                root, ".gitattributes#codex_milestone_workflow_control_plane"
            )
            assert section is not None
            payload["protected_sections"] = {
                ".gitattributes#codex_milestone_workflow_control_plane":
                    workflow._logical_hash_bytes(section)
            }
            manifest.write_text(
                __import__("json").dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            (root / "workflow.toml").write_text("version = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True
            )
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})

            attrs.write_text(
                attrs.read_text(encoding="utf-8") + "*.bin binary\n", encoding="utf-8"
            )
            project_rule = workflow.control_plane_report(root, cfg)
            self.assertTrue(project_rule["clear"], project_rule)

            attrs.write_text(
                attrs.read_text(encoding="utf-8").replace(
                    "/.agents/skills/** text eol=lf",
                    "/.agents/skills/** -text",
                ),
                encoding="utf-8",
            )
            drift = workflow.control_plane_report(root, cfg)
            self.assertFalse(drift["clear"])
            self.assertEqual(
                drift["section_drift"][0]["path"],
                ".gitattributes#codex_milestone_workflow_control_plane",
            )

    def test_all_repository_skills_are_candidate_protected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            managed = ".agents/skills/milestone-workflow/SKILL.md"
            self.write_manifest(root, managed, b"managed\n")
            third_party = root / ".agents/skills/tdd/SKILL.md"
            third_party.parent.mkdir(parents=True, exist_ok=True)
            third_party.write_text("original\n", encoding="utf-8")
            (root / "workflow.toml").write_text("version = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
            ).stdout.strip()
            third_party.write_text("changed by product task\n", encoding="utf-8")
            subprocess.run(["git", "add", third_party.relative_to(root).as_posix()], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "change skill"], cwd=root, check=True, capture_output=True
            )
            candidate = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
            ).stdout.strip()
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
            report = workflow.control_plane_report(
                root, cfg, base=base, candidate=candidate, include_worktree=False
            )
            self.assertFalse(report["clear"])
            self.assertEqual(report["candidate_paths"], [".agents/skills/tdd/SKILL.md"])

    def test_candidate_diff_rejects_protected_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            rel = ".agents/skills/milestone-workflow/SKILL.md"
            self.write_manifest(root, rel, b"v1\n")
            (root / "workflow.toml").write_text("version = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True)
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
            ).stdout.strip()
            (root / rel).write_text("v2\n", encoding="utf-8")
            subprocess.run(["git", "add", rel], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "self modify"], cwd=root, check=True, capture_output=True)
            candidate = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
            ).stdout.strip()
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
            report = workflow.control_plane_report(
                root, cfg, base=base, candidate=candidate, include_worktree=False
            )
            self.assertFalse(report["clear"])
            self.assertEqual(report["candidate_paths"], [rel])

    def test_workflow_debt_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = workflow.deep_merge(workflow.DEFAULT_CONFIG, {})
            first = workflow._append_workflow_debt(
                root,
                cfg,
                milestone="M2",
                ticket_id="M2-T05",
                summary="review protocol cannot represent a late root",
                evidence=["hosted gate failed after close"],
                proposed_fix="add a separate repair-ticket flow",
            )
            second = workflow._append_workflow_debt(
                root,
                cfg,
                milestone="M2",
                ticket_id="M2-T05",
                summary="review protocol cannot represent a late root",
                evidence=["hosted gate failed after close"],
                proposed_fix="add a separate repair-ticket flow",
            )
            self.assertTrue(first)
            self.assertFalse(second)
            content = (root / "docs/workflow-debt.md").read_text(encoding="utf-8")
            self.assertEqual(content.count("workflow-debt:"), 1)


class LegacyReviewCompatibilityTests(unittest.TestCase):
    def record(self, reviewer: str, verdict: str, sha: str) -> dict[str, object]:
        return {
            "round": "superseding",
            "reviewer": reviewer,
            "candidate_sha": sha,
            "verdict": verdict,
            "findings": [],
            "resolved": [],
            "notes": [],
        }

    def test_legacy_superseding_and_root_cycles_are_read_only_compatible(self) -> None:
        sha = "a" * 40
        state = {
            "version": 1,
            "revision": 1,
            "milestones": {
                "M0": {
                    "authorizations": {},
                    "blockers": {},
                    "repairs": {},
                    "repair_overrides": {},
                    "phases": {},
                    "last_checkpoint": {},
                    "reviews": {
                        "M0-T01": {
                            "reviewers": {
                                "architect": {"superseding": self.record("architect", "pass", sha)},
                                "qa": {"targeted": {**self.record("qa", "pass", sha), "round": "targeted"}},
                            },
                            "root_cycles": [
                                {
                                    "root_cause_id": "M0-LATE-001",
                                    "ticket_id": "M0-T01",
                                    "reviewers": {
                                        "architect": {"superseding": self.record("architect", "pass", sha)},
                                        "qa": {"targeted": {**self.record("qa", "pass_with_notes", sha), "round": "targeted"}},
                                    },
                                }
                            ],
                        }
                    },
                }
            },
        }
        self.assertEqual(workflow.runtime_state_errors(state), [])
        warnings = workflow.runtime_state_legacy_warnings(state)
        self.assertEqual(len(warnings), 2)
        item = ticket("M0-T01", "done", owns=("src/**",), risk="high")
        passed, failures = workflow.review_gate_status(
            item,
            state["milestones"]["M0"],
            workflow.deep_merge(workflow.DEFAULT_CONFIG, {}),
        )
        self.assertTrue(passed, failures)

    def test_cli_cannot_create_superseding_review(self) -> None:
        parser = workflow.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "record-review",
                    "M0-T01",
                    "--reviewer",
                    "qa",
                    "--round",
                    "superseding",
                    "--candidate-sha",
                    "a" * 40,
                    "--verdict",
                    "pass",
                ]
            )


if __name__ == "__main__":
    unittest.main()
