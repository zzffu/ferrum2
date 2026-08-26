from tests.performance_candidate._windows_tun_base import WindowsTunBase
from tools.performance_candidate.windows_tun import network_model

class WindowsTunNetworkSupport(WindowsTunBase):
    @staticmethod
    def network_lifecycle_metrics(
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

    def network_model_observation(
        self, *, row: dict[str, object]
    ) -> dict[str, object]:
        model = network_model
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
        for sequence in range(1, model.RESOURCE_WARMUP_RESET_CYCLES + 1):
            metrics_before = self.network_lifecycle_metrics(
                generation=sequence,
                reset_cycles=sequence - 1,
                rebuild_cycles=0,
            )
            metrics_after = self.network_lifecycle_metrics(
                generation=sequence + 1,
                reset_cycles=sequence,
                rebuild_cycles=0,
            )
            route_metric_after = route_metric_states[
                (sequence - 1) % len(route_metric_states)
            ]
            udp_before = sequence % 8 + 1
            tcp_before = sequence % 4
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
            if sequence == model.RESOURCE_WARMUP_RESET_CYCLES:
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
        for sequence in range(1, model.RESET_CYCLES + model.FULL_REBUILD_CYCLES + 1):
            reset = sequence <= model.RESET_CYCLES
            completed_resets = model.RESOURCE_WARMUP_RESET_CYCLES + min(
                sequence - 1, model.RESET_CYCLES
            )
            completed_rebuilds = max(0, sequence - model.RESET_CYCLES - 1)
            metrics_before = self.network_lifecycle_metrics(
                generation=model.RESOURCE_WARMUP_RESET_CYCLES + sequence,
                reset_cycles=completed_resets,
                rebuild_cycles=completed_rebuilds,
            )
            if reset:
                reason = (
                    "interface_change"
                    if sequence == model.INTERFACE_SWITCH_SEQUENCE
                    else "route_change"
                )
                operation = "reset_network"
                identity_after = identity
                elapsed = sequence * 1_000
                completed_resets += 1
            else:
                operation = "full_rebuild"
                reason = model.FULL_REBUILD_DAMAGE_REASON
                rebuild = sequence - model.RESET_CYCLES
                identity_after = f"{rebuild:064x}"
                elapsed = (10 + rebuild) * 1_000_000
                completed_rebuilds += 1
            metrics_after = self.network_lifecycle_metrics(
                generation=model.RESOURCE_WARMUP_RESET_CYCLES + sequence + 1,
                reset_cycles=completed_resets,
                rebuild_cycles=completed_rebuilds,
            )
            udp_before = sequence % 16 + 1
            tcp_before = sequence % 8
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
        reference = row["network_model_evidence"]
        environment = row["environment"]
        return {
            "schema_version": model.SCHEMA_VERSION,
            "workload": model.LIFECYCLE_WORKLOAD,
            "identity": {
                "run_kind": row["run_kind"],
                "member": row["member"],
                "pair": row["pair"],
                "trial_sequence": row["sequence"],
                "client_pid": 1234,
                "server_pid": 1235,
                "vm_name": environment["vm_name"],
                "vm_id": environment["vm_id"],
                "checkpoint_name": environment["checkpoint_name"],
                "checkpoint_id": environment["checkpoint_id"],
                "sha": row["sha"],
                "tree": row["tree"],
                "client_sha256": row["client_sha256"],
                "server_sha256": row["server_sha256"],
                "harness_sha256": row["harness_sha256"],
                "collector_sha256": reference["collector_sha256"],
                "recipe_sha256": row["recipe_sha256"],
                "model_controller_sha256": reference["controller_sha256"],
                "model_plan_sha256": reference["plan_sha256"],
            },
            "resource_warmup": {
                "reset_network_cycles": model.RESOURCE_WARMUP_RESET_CYCLES,
                "route_metric_baseline": route_metric_baseline,
                "quiescence_seconds": model.RESOURCE_QUIESCENCE_SECONDS,
                "cold_start_resources": cold_start_resources,
                "cycles": resource_warmup_cycles,
                "baseline_resource_samples": [dict(resources) for _ in range(3)],
            },
            "baseline_resources": dict(resources),
            "cycles": cycles,
            "interface_resolver": {
                "probes": model.INTERFACE_RESOLVER_PROBES,
                "resolutions": model.INTERFACE_RESOLVER_PROBES * 2,
                "cache_hits": model.INTERFACE_RESOLVER_PROBES * 2 - 2,
                "interface_switch_probe_attempts": 1,
                "interface_switch_resolution_failures": 0,
            },
        }

    def route_once_observation(self, *, row: dict[str, object]) -> dict[str, object]:
        model = network_model
        reference = row["network_model_evidence"]
        environment = row["environment"]
        generations = []
        for ordinal in range(1, model.ROUTE_GENERATIONS + 1):
            associations = []
            for source_slot in range(model.ROUTE_SOURCE_SLOTS):
                datagrams = model.ROUTE_TARGET_SLOTS * model.ROUTE_DATAGRAMS_PER_TARGET
                associations.append(
                    {
                        "source_slot": source_slot,
                        "target_slots": list(range(model.ROUTE_TARGET_SLOTS)),
                        "first_target_slot": 0 if source_slot % 2 == 0 else 1,
                        "datagrams_sent": datagrams,
                        "replies_received": datagrams,
                    }
                )
            path_datagrams = model.ROUTE_SOURCE_SLOTS // 2 * datagrams
            generations.append(
                {
                    "ordinal": ordinal,
                    "network_generation": 10 + ordinal,
                    "session_generation": 10 + ordinal,
                    "direct_datagrams_observed": path_datagrams,
                    "direct_replies_observed": path_datagrams,
                    "proxy_datagrams_observed": path_datagrams,
                    "proxy_replies_observed": path_datagrams,
                    "associations": associations,
                }
            )
        associations_created = model.ROUTE_GENERATIONS * model.ROUTE_SOURCE_SLOTS
        return {
            "schema_version": model.SCHEMA_VERSION,
            "workload": model.ROUTE_ONCE_WORKLOAD,
            "identity": {
                "run_kind": row["run_kind"],
                "member": row["member"],
                "pair": row["pair"],
                "trial_sequence": row["sequence"],
                "client_pid": 1234,
                "server_pid": 1235,
                "vm_name": environment["vm_name"],
                "vm_id": environment["vm_id"],
                "checkpoint_name": environment["checkpoint_name"],
                "checkpoint_id": environment["checkpoint_id"],
                "sha": row["sha"],
                "tree": row["tree"],
                "client_sha256": row["client_sha256"],
                "server_sha256": row["server_sha256"],
                "harness_sha256": row["harness_sha256"],
                "collector_sha256": reference["collector_sha256"],
                "recipe_sha256": row["recipe_sha256"],
                "model_controller_sha256": reference["controller_sha256"],
                "model_plan_sha256": reference["plan_sha256"],
            },
            "elapsed_nanoseconds": 1_000_000_000,
            "association_creation_elapsed_nanoseconds": 500_000_000,
            "association_creations_observed": associations_created,
            "router_invocations_observed": associations_created,
            "generations": generations,
        }
