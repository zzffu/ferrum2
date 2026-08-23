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


def route_once_observation(*, elapsed_nanoseconds: int = 1_000_000_000) -> dict[str, object]:
    associations = []
    for generation in range(1, MODEL.ROUTE_GENERATIONS + 1):
        for source_slot in range(MODEL.ROUTE_SOURCE_SLOTS):
            associations.append(
                {
                    "generation": generation,
                    "source_slot": source_slot,
                    "target_slots": list(range(MODEL.ROUTE_TARGET_SLOTS)),
                    "datagrams_sent": (
                        MODEL.ROUTE_TARGET_SLOTS * MODEL.ROUTE_DATAGRAMS_PER_TARGET
                    ),
                    "router_invocations": 1,
                    "association_commits": 1,
                    "egress_instances": 1,
                    "frozen_outbound": "direct" if source_slot % 2 == 0 else "proxy",
                }
            )
    return {
        "schema_version": MODEL.SCHEMA_VERSION,
        "workload": MODEL.ROUTE_ONCE_WORKLOAD,
        "elapsed_nanoseconds": elapsed_nanoseconds,
        "associations": associations,
    }


def lifecycle_observation() -> dict[str, object]:
    resources = {
        "process_handles": 120,
        "process_threads": 12,
        "udp_associations_active": 0,
        "managed_adapters_active": 1,
    }
    cycles = []
    identity = "a" * 64
    total_cycles = MODEL.RESET_CYCLES + MODEL.FULL_REBUILD_CYCLES
    for sequence in range(1, total_cycles + 1):
        if sequence <= MODEL.RESET_CYCLES:
            operation = "reset_network"
            reason = (
                "interface_change"
                if sequence == MODEL.INTERFACE_SWITCH_SEQUENCE
                else "route_change"
            )
            elapsed = sequence * 1_000
            identity_after = identity
        else:
            rebuild_index = sequence - MODEL.RESET_CYCLES - 1
            operation = "full_rebuild"
            reason = MODEL.FULL_REBUILD_DAMAGE_REASON
            elapsed = (11 + rebuild_index) * 1_000_000
            identity_after = f"{rebuild_index + 1:064x}"
        tcp_before = sequence % 8
        udp_before = sequence % 16 + 1
        cycles.append(
            {
                "sequence": sequence,
                "operation": operation,
                "reason": reason,
                "generation_before": sequence,
                "generation_after": sequence + 1,
                "elapsed_nanoseconds": elapsed,
                "operation_counter_before": sequence - 1,
                "operation_counter_after": sequence,
                "session_restart_started_before": 0,
                "session_restart_started_after": 0,
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
        "identity": {
            "run_kind": "comparison",
            "member": "candidate",
            "pair": 1,
            "trial_sequence": 72,
            "client_pid": 1234,
            "server_pid": 1235,
            "vm_name": "Windows 10 MSIX packaging environment",
            "vm_id": "82e20295-1d30-48e7-a751-e21d35d872d4",
            "checkpoint_name": "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9",
            "checkpoint_id": "1e570209-faf7-4248-8167-aa0687cdb8cf",
            "sha": "1" * 40,
            "tree": "2" * 40,
            "client_sha256": "3" * 64,
            "server_sha256": "4" * 64,
            "harness_sha256": "5" * 64,
            "collector_sha256": "6" * 64,
            "recipe_sha256": "7" * 64,
            "model_controller_sha256": "8" * 64,
            "model_plan_sha256": "9" * 64,
        },
        "baseline_resources": dict(resources),
        "cycles": cycles,
        "interface_resolver": {
            "probes": MODEL.INTERFACE_RESOLVER_PROBES,
            "resolutions": MODEL.INTERFACE_RESOLVER_PROBES * 2,
            "cache_hits": MODEL.INTERFACE_RESOLVER_PROBES * 2 - 2,
        },
    }


class LocalHypervPerformancePlanTests(unittest.TestCase):
    def test_plan_is_closed_bounded_and_guest_only(self) -> None:
        plan = MODEL.create_local_hyperv_plan()
        self.assertEqual(plan["schema_version"], 2)
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
        self.assertEqual(lifecycle["reset_network_cycles"], 1_000)
        self.assertEqual(
            lifecycle["interface_switch_kind"],
            "approved_underlay_disable_enable",
        )
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

    def test_plan_cli_writes_a_local_hyperv_consumable_json_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "plan.json"
            status = MODEL.main(["plan", "--output", str(output)])
            plan = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(plan, MODEL.create_local_hyperv_plan())


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
        self.assertEqual(summary["router_invocations"], expected_associations)
        self.assertEqual(summary["egress_instances"], expected_associations)
        self.assertEqual(
            summary["router_invocations_avoided"],
            expected_associations * (MODEL.ROUTE_TARGET_SLOTS - 1),
        )
        self.assertTrue(summary["route_once_verified"])
        self.assertTrue(summary["post_reset_reroute_verified"])

    def test_route_once_contract_rejects_per_target_or_child_egress_behavior(self) -> None:
        cases = []
        routed_per_target = route_once_observation()
        routed_per_target["associations"][0]["router_invocations"] = (
            MODEL.ROUTE_TARGET_SLOTS
        )
        cases.append((routed_per_target, "router exactly once"))
        child_egress = route_once_observation()
        child_egress["associations"][0]["egress_instances"] = 2
        cases.append((child_egress, "one multi-target egress"))
        duplicate = route_once_observation()
        duplicate["associations"][-1] = copy.deepcopy(duplicate["associations"][0])
        cases.append((duplicate, "duplicated"))
        changed_route = route_once_observation()
        changed_route["associations"][1]["frozen_outbound"] = "direct"
        cases.append((changed_route, "first-route decision"))
        missing_target = route_once_observation()
        missing_target["associations"][0]["target_slots"] = [0, 1, 2]
        cases.append((missing_target, "deterministic target set"))
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
        self.assertTrue(summary["managed_identity_preserved_across_resets"])
        self.assertTrue(summary["connections_closed"])
        self.assertTrue(summary["damage_only_full_rebuild"])
        self.assertEqual(
            summary["interface_switch_recovery_nanoseconds"],
            MODEL.INTERFACE_SWITCH_SEQUENCE * 1_000,
        )
        self.assertEqual(
            summary["interface_resolver"]["cache_hits_per_million_resolutions"],
            968_750,
        )

    def test_lifecycle_contract_rejects_restart_identity_leak_and_reason_errors(
        self,
    ) -> None:
        cases = []
        restart = lifecycle_observation()
        restart["cycles"][0]["operation"] = "restart_session"
        cases.append((restart, "ordinary ResetNetwork schedule"))
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
        resource_growth = lifecycle_observation()
        resource_growth["cycles"][MODEL.RESET_CYCLES - 1]["resources_after"][
            "process_handles"
        ] += 1
        cases.append((resource_growth, "retained resource growth"))
        bad_identity = lifecycle_observation()
        bad_identity["identity"]["recipe_sha256"] = "not-a-digest"
        cases.append((bad_identity, "recipe_sha256"))
        no_cache_hit = lifecycle_observation()
        no_cache_hit["interface_resolver"]["cache_hits"] = 0
        cases.append((no_cache_hit, "cache_hits"))
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
