#!/usr/bin/env python3
"""Behavior tests for the deterministic local Hyper-V network-model controller."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("windows_tun_network_model.py")
SPEC = importlib.util.spec_from_file_location("windows_tun_network_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)


def observation_identity(*, trial_sequence: int = 90) -> dict[str, object]:
    return {
        "run_kind": "comparison",
        "member": "candidate",
        "pair": 1,
        "trial_sequence": trial_sequence,
        "client_pid": 1234,
        "server_pid": 1235,
        "vm_name": "Windows 10 MSIX packaging environment",
        "vm_id": "82e20295-1d30-48e7-a751-e21d35d872d4",
        "checkpoint_name": "Ferrum2-WindowsTun-InternalSupport-v1",
        "checkpoint_id": "81000000-0000-4000-8000-000000000001",
        "sha": "1" * 40,
        "tree": "2" * 40,
        "client_sha256": "3" * 64,
        "server_sha256": "4" * 64,
        "harness_sha256": "5" * 64,
        "collector_sha256": "6" * 64,
        "recipe_sha256": "7" * 64,
        "model_controller_sha256": "8" * 64,
        "model_plan_sha256": "9" * 64,
    }


def route_once_observation(*, elapsed_nanoseconds: int = 1_000_000_000) -> dict[str, object]:
    generations = []
    for generation in range(1, MODEL.ROUTE_GENERATIONS + 1):
        associations = []
        for source_slot in range(MODEL.ROUTE_SOURCE_SLOTS):
            associations.append(
                {
                    "source_slot": source_slot,
                    "target_slots": list(range(MODEL.ROUTE_TARGET_SLOTS)),
                    "first_target_slot": 0 if source_slot % 2 == 0 else 1,
                    "datagrams_sent": (
                        MODEL.ROUTE_TARGET_SLOTS * MODEL.ROUTE_DATAGRAMS_PER_TARGET
                    ),
                    "replies_received": (
                        MODEL.ROUTE_TARGET_SLOTS * MODEL.ROUTE_DATAGRAMS_PER_TARGET
                    ),
                }
            )
        path_datagrams = (
            MODEL.ROUTE_SOURCE_SLOTS
            // 2
            * MODEL.ROUTE_TARGET_SLOTS
            * MODEL.ROUTE_DATAGRAMS_PER_TARGET
        )
        generations.append(
            {
                "ordinal": generation,
                "network_generation": 10 + generation,
                "session_generation": 10 + generation,
                "direct_datagrams_observed": path_datagrams,
                "direct_replies_observed": path_datagrams,
                "proxy_datagrams_observed": path_datagrams,
                "proxy_replies_observed": path_datagrams,
                "associations": associations,
            }
        )
    expected_associations = MODEL.ROUTE_GENERATIONS * MODEL.ROUTE_SOURCE_SLOTS
    return {
        "schema_version": MODEL.SCHEMA_VERSION,
        "workload": MODEL.ROUTE_ONCE_WORKLOAD,
        "identity": observation_identity(),
        "elapsed_nanoseconds": elapsed_nanoseconds,
        "association_creation_elapsed_nanoseconds": elapsed_nanoseconds // 2,
        "association_creations_observed": expected_associations,
        "router_invocations_observed": expected_associations,
        "generations": generations,
    }


def lifecycle_metrics(
    *, generation: int, reset_cycles: int, rebuild_cycles: int
) -> dict[str, int]:
    return {
        "network_generation": generation,
        "session_generation": generation,
        "network_reset_total": reset_cycles * 2,
        "network_reset_started": reset_cycles,
        "network_reset_succeeded": reset_cycles,
        "network_reset_failed": 0,
        "full_rebuild_total": rebuild_cycles * 2,
        "full_rebuild_started": rebuild_cycles,
        "full_rebuild_succeeded": rebuild_cycles,
        "full_rebuild_failed": 0,
    }


def lifecycle_observation() -> dict[str, object]:
    cold_start_resources = {
        "process_handles": 115,
        "process_threads": 10,
        "udp_associations_active": 0,
        "managed_adapters_active": 1,
    }
    resources = {
        "process_handles": 120,
        "process_threads": 12,
        "udp_associations_active": 0,
        "managed_adapters_active": 1,
    }
    identity = "a" * 64
    route_metric_baseline = 25
    route_metric_states = (26, 27, route_metric_baseline)
    resource_warmup_cycles = []
    route_metric_before = route_metric_baseline
    for sequence in range(1, MODEL.RESOURCE_WARMUP_RESET_CYCLES + 1):
        metrics_before = lifecycle_metrics(
            generation=sequence,
            reset_cycles=sequence - 1,
            rebuild_cycles=0,
        )
        metrics_after = lifecycle_metrics(
            generation=sequence + 1,
            reset_cycles=sequence,
            rebuild_cycles=0,
        )
        route_metric_after = route_metric_states[(sequence - 1) % len(route_metric_states)]
        tcp_before = sequence % 4
        udp_before = sequence % 8 + 1
        warmup_resources = {
            **resources,
            "process_handles": min(
                resources["process_handles"],
                cold_start_resources["process_handles"] + sequence,
            ),
            "process_threads": min(
                resources["process_threads"],
                cold_start_resources["process_threads"] + sequence,
            ),
        }
        if sequence == MODEL.RESOURCE_WARMUP_RESET_CYCLES:
            warmup_resources["process_handles"] += 1
        resource_warmup_cycles.append(
            {
                "sequence": sequence,
                "operation": "reset_network",
                "reason": "route_change",
                "route_metric_before": route_metric_before,
                "route_metric_after": route_metric_after,
                "lifecycle_metrics_before": metrics_before,
                "lifecycle_metrics_after": metrics_after,
                "managed_identity_before": identity,
                "managed_identity_after": identity,
                "tcp_flows_before": tcp_before,
                "udp_associations_before": udp_before,
                "tcp_flows_closed": tcp_before,
                "udp_associations_closed": udp_before,
                "tcp_probe_succeeded": True,
                "udp_probe_succeeded": True,
                "resources_after": warmup_resources,
            }
        )
        route_metric_before = route_metric_after

    cycles = []
    total_cycles = MODEL.RESET_CYCLES + MODEL.FULL_REBUILD_CYCLES
    for sequence in range(1, total_cycles + 1):
        completed_resets = MODEL.RESOURCE_WARMUP_RESET_CYCLES + min(
            sequence - 1, MODEL.RESET_CYCLES
        )
        completed_rebuilds = max(0, sequence - MODEL.RESET_CYCLES - 1)
        metrics_before = lifecycle_metrics(
            generation=MODEL.RESOURCE_WARMUP_RESET_CYCLES + sequence,
            reset_cycles=completed_resets,
            rebuild_cycles=completed_rebuilds,
        )
        if sequence <= MODEL.RESET_CYCLES:
            operation = "reset_network"
            reason = (
                "interface_change"
                if sequence == MODEL.INTERFACE_SWITCH_SEQUENCE
                else "route_change"
            )
            elapsed = sequence * 1_000
            identity_after = identity
            completed_resets += 1
        else:
            rebuild_index = sequence - MODEL.RESET_CYCLES - 1
            operation = "full_rebuild"
            reason = MODEL.FULL_REBUILD_DAMAGE_REASON
            elapsed = (11 + rebuild_index) * 1_000_000
            identity_after = f"{rebuild_index + 1:064x}"
            completed_rebuilds += 1
        metrics_after = lifecycle_metrics(
            generation=MODEL.RESOURCE_WARMUP_RESET_CYCLES + sequence + 1,
            reset_cycles=completed_resets,
            rebuild_cycles=completed_rebuilds,
        )
        tcp_before = sequence % 8
        udp_before = sequence % 16 + 1
        cycles.append(
            {
                "sequence": sequence,
                "operation": operation,
                "reason": reason,
                "elapsed_nanoseconds": elapsed,
                "lifecycle_metrics_before": metrics_before,
                "lifecycle_metrics_after": metrics_after,
                "managed_identity_before": identity,
                "managed_identity_after": identity_after,
                "tcp_flows_before": tcp_before,
                "udp_associations_before": udp_before,
                "tcp_flows_closed": tcp_before,
                "udp_associations_closed": udp_before,
                "tcp_probe_succeeded": True,
                "udp_probe_succeeded": True,
                "resources_after": dict(resources),
            }
        )
        identity = identity_after
    return {
        "schema_version": MODEL.SCHEMA_VERSION,
        "workload": MODEL.LIFECYCLE_WORKLOAD,
        "identity": observation_identity(trial_sequence=80),
        "resource_warmup": {
            "reset_network_cycles": MODEL.RESOURCE_WARMUP_RESET_CYCLES,
            "route_metric_baseline": route_metric_baseline,
            "quiescence_seconds": MODEL.RESOURCE_QUIESCENCE_SECONDS,
            "cold_start_resources": cold_start_resources,
            "cycles": resource_warmup_cycles,
            "baseline_resource_samples": [dict(resources) for _ in range(3)],
        },
        "baseline_resources": dict(resources),
        "cycles": cycles,
        "interface_resolver": {
            "probes": MODEL.INTERFACE_RESOLVER_PROBES,
            "resolutions": MODEL.INTERFACE_RESOLVER_PROBES * 2,
            "cache_hits": MODEL.INTERFACE_RESOLVER_PROBES * 2 - 2,
            "interface_switch_probe_attempts": 1,
            "interface_switch_resolution_failures": 0,
        },
    }


class LocalHypervPerformancePlanTests(unittest.TestCase):
    def test_plan_is_closed_bounded_and_guest_only(self) -> None:
        plan = MODEL.create_local_hyperv_plan()
        self.assertEqual(plan["schema_version"], 6)
        self.assertEqual(plan["execution"], "local_hyperv_guest")
        self.assertEqual(plan["host_network_mutation"], "forbidden")
        self.assertEqual(
            set(plan["workloads"]),
            {MODEL.ROUTE_ONCE_WORKLOAD, MODEL.LIFECYCLE_WORKLOAD},
        )
        route = plan["workloads"][MODEL.ROUTE_ONCE_WORKLOAD]
        self.assertEqual(
            (
                route["generations"],
                route["source_slots"],
                route["target_slots"],
                route["datagrams_per_target"],
            ),
            (2, 64, 4, 32),
        )
        lifecycle = plan["workloads"][MODEL.LIFECYCLE_WORKLOAD]
        self.assertEqual(lifecycle["resource_warmup_reset_cycles"], 12)
        self.assertEqual(lifecycle["resource_warmup_route_metric_states"], 3)
        self.assertEqual(lifecycle["resource_quiescence_seconds"], 30)
        self.assertEqual(lifecycle["reset_network_cycles"], 1_000)
        self.assertEqual(lifecycle["total_reset_network_cycles"], 1_012)
        self.assertEqual(lifecycle["interface_switch_trial_reset_ordinal"], 512)
        self.assertTrue(lifecycle["terminal_resource_convergence_excluded_from_elapsed"])
        self.assertEqual(
            lifecycle["interface_switch_kind"],
            "approved_underlay_disable_enable",
        )
        self.assertEqual(lifecycle["interface_switch_recovery_timeout_seconds"], 30)
        self.assertEqual(lifecycle["interface_switch_probe_retry_milliseconds"], 250)
        self.assertEqual(
            lifecycle["full_rebuild_cycles"], MODEL.FULL_REBUILD_CYCLES
        )
        self.assertEqual(lifecycle["latency_percentiles"], [50, 95, 99])
        self.assertTrue(
            all(
                growth == 0
                for growth in lifecycle[
                    "maximum_retained_resource_growth"
                ].values()
            )
        )
        self.assertEqual(
            lifecycle["retained_resource_growth_enforced_operations"],
            ["reset_network"],
        )
        self.assertEqual(
            lifecycle["diagnostic_resource_growth_operations"],
            ["full_rebuild"],
        )

    def test_plan_cli_writes_a_local_hyperv_consumable_json_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "plan.json"
            status = MODEL.main(["plan", "--output", str(output)])
            encoded = output.read_bytes()
            plan = json.loads(encoded.decode("utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(plan, MODEL.create_local_hyperv_plan())
        self.assertEqual(
            encoded,
            (
                json.dumps(MODEL.create_local_hyperv_plan(), indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8"),
        )


class RouteOnceWorkloadTests(unittest.TestCase):
    def test_multi_target_sources_route_once_and_reroute_once_after_reset(self) -> None:
        summary = MODEL.summarize_route_once_observation(route_once_observation())
        expected_associations = MODEL.ROUTE_GENERATIONS * MODEL.ROUTE_SOURCE_SLOTS
        expected_datagrams = (
            expected_associations
            * MODEL.ROUTE_TARGET_SLOTS
            * MODEL.ROUTE_DATAGRAMS_PER_TARGET
        )
        self.assertEqual(summary["associations_created"], expected_associations)
        self.assertEqual(summary["datagrams_sent"], expected_datagrams)
        self.assertEqual(summary["packets_per_second"], expected_datagrams)
        self.assertEqual(summary["associations_per_second"], expected_associations * 2)
        self.assertEqual(summary["router_invocations"], expected_associations)
        self.assertTrue(summary["direct_and_proxy_verified"])
        self.assertEqual(
            summary["router_invocations_avoided"],
            expected_associations * (MODEL.ROUTE_TARGET_SLOTS - 1),
        )
        self.assertTrue(summary["route_once_verified"])
        self.assertTrue(summary["post_reset_reroute_verified"])

    def test_route_once_contract_rejects_per_target_or_child_egress_behavior(self) -> None:
        cases = []
        routed_per_target = route_once_observation()
        routed_per_target["router_invocations_observed"] += 1
        cases.append((routed_per_target, "router exactly once"))
        duplicate = route_once_observation()
        duplicate["generations"][0]["associations"][-1] = copy.deepcopy(
            duplicate["generations"][0]["associations"][0]
        )
        cases.append((duplicate, "duplicated"))
        changed_route = route_once_observation()
        changed_route["generations"][0]["proxy_datagrams_observed"] -= 1
        cases.append((changed_route, "proxy traffic split"))
        missing_target = route_once_observation()
        missing_target["generations"][0]["associations"][0]["target_slots"] = [0, 1, 2]
        cases.append((missing_target, "deterministic target set"))
        stale_generation = route_once_observation()
        stale_generation["generations"][1]["network_generation"] += 1
        stale_generation["generations"][1]["session_generation"] += 1
        cases.append((stale_generation, "advance the generation exactly once"))
        for observation, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(MODEL.NetworkModelError, message):
                    MODEL.summarize_route_once_observation(observation)

    def test_summary_cli_recomputes_raw_route_once_measurements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            raw = root / "raw.json"
            output = root / "summary.json"
            raw.write_text(json.dumps(route_once_observation()), encoding="utf-8")
            status = MODEL.main(
                ["summarize", "--input", str(raw), "--output", str(output)]
            )
            summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertTrue(summary["route_once_verified"])


class NetworkLifecycleWorkloadTests(unittest.TestCase):
    def test_reset_and_rebuild_latency_and_resources_are_accounted_separately(
        self,
    ) -> None:
        summary = MODEL.summarize_lifecycle_observation(lifecycle_observation())
        self.assertEqual(
            summary["cycles"],
            {
                "reset_network": 1_000,
                "full_rebuild": MODEL.FULL_REBUILD_CYCLES,
            },
        )
        self.assertEqual(summary["resource_warmup"]["reset_network_cycles"], 12)
        self.assertEqual(
            summary["resource_warmup"]["measured_reset_network_cycles"], 1_000
        )
        self.assertEqual(
            summary["resource_warmup"]["total_reset_network_cycles"], 1_012
        )
        self.assertTrue(summary["resource_warmup"]["route_metric_restored"])
        self.assertEqual(
            summary["resource_warmup"]["initialization_growth"],
            {
                "process_handles": 5,
                "process_threads": 2,
                "udp_associations_active": 0,
                "managed_adapters_active": 0,
            },
        )
        self.assertEqual(
            summary["resource_warmup"]["peak"]["process_handles"], 121
        )
        reset = summary["latency_nanoseconds"]["reset_network"]
        self.assertEqual(
            reset,
            {
                "count": 1_000,
                "minimum": 1_000,
                "p50": 500_000,
                "p95": 950_000,
                "p99": 990_000,
                "maximum": 1_000_000,
            },
        )
        rebuild = summary["latency_nanoseconds"]["full_rebuild"]
        self.assertEqual(
            rebuild,
            {
                "count": 10,
                "minimum": 11_000_000,
                "p50": 15_000_000,
                "p95": 20_000_000,
                "p99": 20_000_000,
                "maximum": 20_000_000,
            },
        )
        self.assertEqual(
            summary["latency_nanoseconds"][
                "full_rebuild_p95_over_reset_p95_basis_points"
            ],
            210_526,
        )
        for operation in ("reset_network", "full_rebuild"):
            with self.subTest(operation=operation):
                resources = summary["resources"][operation]
                self.assertEqual(
                    resources["growth"], {field: 0 for field in MODEL.RESOURCE_FIELDS}
                )
                self.assertEqual(
                    resources["peak_growth"],
                    {field: 0 for field in MODEL.RESOURCE_FIELDS},
                )
                self.assertEqual(
                    resources["retained_growth_enforced"],
                    operation == "reset_network",
                )
        self.assertTrue(summary["managed_identity_preserved_across_resets"])
        self.assertTrue(summary["connections_closed"])
        self.assertTrue(summary["damage_only_full_rebuild"])
        self.assertTrue(summary["reset_and_full_rebuild_metrics_are_exact"])
        self.assertEqual(
            summary["interface_switch_recovery_nanoseconds"],
            MODEL.INTERFACE_SWITCH_SEQUENCE * 1_000,
        )
        self.assertEqual(
            summary["interface_resolver"]["cache_hits_per_million_resolutions"],
            968_750,
        )
        self.assertEqual(summary["interface_resolver"]["interface_switch_probe_attempts"], 1)
        self.assertEqual(
            summary["interface_resolver"]["interface_switch_resolution_failures"], 0
        )

    def test_lifecycle_contract_rejects_metric_identity_leak_and_reason_errors(
        self,
    ) -> None:
        cases = []
        wrong_operation = lifecycle_observation()
        wrong_operation["cycles"][0]["operation"] = "full_rebuild"
        cases.append((wrong_operation, "ordinary ResetNetwork schedule"))
        rebuild_during_reset = lifecycle_observation()
        rebuild_during_reset["cycles"][0]["lifecycle_metrics_after"][
            "full_rebuild_started"
        ] += 1
        rebuild_during_reset["cycles"][0]["lifecycle_metrics_after"][
            "full_rebuild_total"
        ] += 1
        cases.append((rebuild_during_reset, "full_rebuild_started delta must be 0"))
        reset_failure = lifecycle_observation()
        reset_failure["cycles"][0]["lifecycle_metrics_after"][
            "network_reset_failed"
        ] += 1
        reset_failure["cycles"][0]["lifecycle_metrics_after"][
            "network_reset_total"
        ] += 1
        cases.append((reset_failure, "network_reset_failed delta must be 0"))
        generation_mismatch = lifecycle_observation()
        generation_mismatch["cycles"][0]["lifecycle_metrics_after"][
            "session_generation"
        ] += 1
        cases.append((generation_mismatch, "generations must match"))
        discontinuous_metrics = lifecycle_observation()
        discontinuous_metrics["cycles"][1]["lifecycle_metrics_before"][
            "network_reset_total"
        ] += 1
        cases.append((discontinuous_metrics, "do not continue the prior cycle"))
        identity_changed = lifecycle_observation()
        identity_changed["cycles"][0]["managed_identity_after"] = "b" * 64
        cases.append((identity_changed, "changed managed identity"))
        association_leaked = lifecycle_observation()
        association_leaked["cycles"][0]["resources_after"][
            "udp_associations_active"
        ] = 1
        cases.append((association_leaked, "retained a UDP association"))
        connection_open = lifecycle_observation()
        connection_open["cycles"][0]["udp_associations_closed"] -= 1
        cases.append((connection_open, "did not close every UDP association"))
        ordinary_rebuild = lifecycle_observation()
        ordinary_rebuild["cycles"][MODEL.RESET_CYCLES]["reason"] = "route_change"
        cases.append((ordinary_rebuild, "managed-damage rebuild schedule"))
        bad_identity = lifecycle_observation()
        bad_identity["identity"]["recipe_sha256"] = "not-a-digest"
        cases.append((bad_identity, "recipe_sha256"))
        no_cache_hit = lifecycle_observation()
        no_cache_hit["interface_resolver"]["cache_hits"] = 0
        cases.append((no_cache_hit, "cache_hits"))
        inconsistent_probe_attempts = lifecycle_observation()
        inconsistent_probe_attempts["interface_resolver"][
            "interface_switch_probe_attempts"
        ] = 2
        cases.append((inconsistent_probe_attempts, "probe attempt accounting"))
        late_interface_recovery = lifecycle_observation()
        late_interface_recovery["cycles"][MODEL.INTERFACE_SWITCH_SEQUENCE - 1][
            "elapsed_nanoseconds"
        ] = MODEL.INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS * 1_000_000_000 + 1
        cases.append((late_interface_recovery, "bounded timeout"))
        missing_warmup_cycle = lifecycle_observation()
        missing_warmup_cycle["resource_warmup"]["cycles"].pop()
        cases.append((missing_warmup_cycle, "requires exactly 12 cycles"))
        wrong_warmup_operation = lifecycle_observation()
        wrong_warmup_operation["resource_warmup"]["cycles"][0][
            "operation"
        ] = "full_rebuild"
        cases.append((wrong_warmup_operation, "route-change ResetNetwork"))
        wrong_warmup_route = lifecycle_observation()
        wrong_warmup_route["resource_warmup"]["cycles"][1][
            "route_metric_after"
        ] += 1
        cases.append((wrong_warmup_route, "three-state route schedule"))
        warmup_identity_changed = lifecycle_observation()
        warmup_identity_changed["resource_warmup"]["cycles"][0][
            "managed_identity_after"
        ] = "b" * 64
        cases.append((warmup_identity_changed, "changed managed identity"))
        warmup_probe_failed = lifecycle_observation()
        warmup_probe_failed["resource_warmup"]["cycles"][0][
            "udp_probe_succeeded"
        ] = False
        cases.append((warmup_probe_failed, "did not recover both TCP and UDP probes"))
        warmup_baseline_mismatch = lifecycle_observation()
        warmup_baseline_mismatch["resource_warmup"]["baseline_resource_samples"][
            1
        ]["process_handles"] -= 1
        cases.append((warmup_baseline_mismatch, "not stable and exact"))
        warmup_formal_discontinuity = lifecycle_observation()
        warmup_formal_discontinuity["cycles"][0]["lifecycle_metrics_before"][
            "full_rebuild_total"
        ] += 1
        cases.append((warmup_formal_discontinuity, "do not continue the prior cycle"))
        for observation, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(MODEL.NetworkModelError, message):
                    MODEL.summarize_lifecycle_observation(observation)

    def test_nearest_rank_quantiles_do_not_interpolate_latency_samples(self) -> None:
        self.assertEqual(MODEL._nearest_rank(list(range(1, 1_001)), 50), 500)
        self.assertEqual(MODEL._nearest_rank(list(range(1, 1_001)), 95), 950)
        self.assertEqual(MODEL._nearest_rank(list(range(1, 1_001)), 99), 990)
        self.assertEqual(MODEL._nearest_rank(list(range(1, 8)), 95), 7)

    def test_transient_resource_peak_is_reported_without_being_called_a_leak(self) -> None:
        observation = lifecycle_observation()
        observation["cycles"][0]["resources_after"]["process_handles"] += 5
        summary = MODEL.summarize_lifecycle_observation(observation)
        self.assertEqual(
            summary["resources"]["reset_network"]["peak_growth"]["process_handles"],
            5,
        )
        self.assertEqual(
            summary["resources"]["reset_network"]["growth"]["process_handles"],
            0,
        )

    def test_full_rebuild_final_resource_growth_is_diagnostic_and_reported(self) -> None:
        observation = lifecycle_observation()
        final_resources = observation["cycles"][-1]["resources_after"]
        final_resources["process_handles"] += 2
        final_resources["process_threads"] += 1

        summary = MODEL.summarize_lifecycle_observation(observation)
        resources = summary["resources"]["full_rebuild"]
        self.assertFalse(resources["retained_growth_enforced"])
        self.assertEqual(
            resources["final"],
            {
                "process_handles": 122,
                "process_threads": 13,
                "udp_associations_active": 0,
                "managed_adapters_active": 1,
            },
        )
        self.assertEqual(
            resources["growth"],
            {
                "process_handles": 2,
                "process_threads": 1,
                "udp_associations_active": 0,
                "managed_adapters_active": 0,
            },
        )

    def test_reset_final_resource_growth_remains_rejected(self) -> None:
        observation = lifecycle_observation()
        observation["cycles"][MODEL.RESET_CYCLES - 1]["resources_after"][
            "process_handles"
        ] += 1

        with self.assertRaisesRegex(MODEL.NetworkModelError, "retained resource growth"):
            MODEL.summarize_lifecycle_observation(observation)


class ObservationInputTests(unittest.TestCase):
    def test_duplicate_keys_and_oversized_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"workload":"udp-route-once","workload":"network-lifecycle"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODEL.NetworkModelError, "duplicate JSON key"):
                MODEL.load_observation(duplicate)

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MODEL.MAX_ARTIFACT_BYTES + 1))
            with self.assertRaisesRegex(MODEL.NetworkModelError, "exceeds"):
                MODEL.load_observation(oversized)


if __name__ == "__main__":
    unittest.main()
