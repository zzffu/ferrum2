import hashlib
import json
import pathlib
from datetime import datetime, timedelta, timezone

from tests.performance_candidate._windows_tun_network_support import WindowsTunNetworkSupport
from tests.performance_candidate._windows_tun_udp_support import WindowsTunUdpSupport
from tools.performance_candidate.windows_tun import network_model_lifecycle, network_model_route
from tools.performance_candidate.windows_tun import recipe as windows_recipe
from tools.performance_candidate.windows_tun import trial as windows_trial

class WindowsTunTrialSupport(WindowsTunUdpSupport, WindowsTunNetworkSupport):
    def row(
        self,
        *,
        plan: dict[str, object],
        scenario: str,
        pair: int,
        member: str,
        parent_sha: str,
        candidate_sha: str,
        regression: bool = False,
    ) -> dict[str, object]:
        contract = windows_recipe.scenario_catalog()[scenario]
        planned = [
            trial
            for trial in plan["trials"]
            if trial["scenario"] == scenario
            and trial["pair"] == pair
            and trial["member"] == member
        ]
        self.assertEqual(len(planned), 1)
        order = planned[0]["order"]
        sequence = planned[0]["sequence"]
        started = datetime(2026, 8, 22, tzinfo=timezone.utc) + timedelta(
            seconds=sequence * 2
        )
        finished = started + timedelta(seconds=1)
        canonical_utc = lambda value: value.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        measurements = {}
        for metric, metric_contract in contract["metrics"].items():
            value = 1_000
            if regression and member == "candidate":
                value = (
                    900
                    if metric_contract["direction"] == "higher_is_better"
                    else 1_100
                )
            measurements[metric] = {
                "unit": metric_contract["unit"],
                "value": value,
            }
        member_sha = parent_sha if member == "parent" else candidate_sha
        aa = parent_sha == candidate_sha
        identity_digit = "5" if aa or member == "parent" else "6"
        row = {
            "schema_version": windows_trial.WINDOWS_TUN_TRIAL_SCHEMA_VERSION,
            "kind": "windows_tun_performance_trial",
            "selection": windows_recipe.WINDOWS_TUN_SELECTION,
            "run_kind": plan["run_kind"],
            "scenario": scenario,
            "member": member,
            "pair": pair,
            "order": order,
            "sequence": sequence,
            "started_utc": canonical_utc(started),
            "finished_utc": canonical_utc(finished),
            "parent_sha": parent_sha,
            "candidate_sha": candidate_sha,
            "sha": member_sha,
            "tree": identity_digit * 40,
            "client_sha256": identity_digit * 64,
            "server_sha256": identity_digit * 64,
            "harness_sha256": "7" * 64,
            "recipe_sha256": plan["recipe_sha256"],
            "controller_bundle_sha256": plan["controller_bundle_sha256"],
            "environment": self.environment(),
            "measurements": measurements,
            "correctness": {
                "status": "PASS",
                "checked_unit": contract["checked_unit"],
                "checked_units": contract["minimum_checked_units"],
                "checks": {
                    check: True for check in contract["correctness_checks"]
                },
            },
            "diagnostics": None,
            "network_model_evidence": None,
            "status": "PASS",
        }
        if scenario == "wintun-ring-full-drop-rate":
            positive_drop = regression and member == "candidate"
            response_attempts = (
                100_000
                if positive_drop
                else contract["minimum_checked_units"]
            )
            ring_full_drops = 110 if positive_drop else 0
            pending_response_peak = 1 if positive_drop else 0
            row["measurements"]["drop_rate"]["value"] = (
                ring_full_drops * 1_000_000 + response_attempts - 1
            ) // response_attempts
            row["measurements"]["pending_response_peak"][
                "value"
            ] = pending_response_peak
            row["correctness"]["checked_units"] = response_attempts
            row["diagnostics"] = {
                "schema_version": 1,
                "kind": "wintun_egress_pressure_accounting",
                "workload_attempted_datagrams": 1_000_000,
                "tun_packets_egress": response_attempts - ring_full_drops,
                "wintun_ring_full_dropped": ring_full_drops,
                "tun_response_attempts": response_attempts,
                "pending_response_before": 0,
                "pending_response_peak": pending_response_peak,
                "pending_response_after": 0,
            }
        if scenario == "udp-8192-association-lookup-expiry":
            row["diagnostics"] = {
                "udp_association_source_preflight": (
                    self.udp_association_source_preflight()
                )
            }
        if scenario == "fragment-reassembly-throughput":
            active_unique = row["correctness"]["checked_units"]
            warmup_unique = 8
            retransmissions = 1
            total_unique = warmup_unique + active_unique
            total_request_attempts = total_unique + retransmissions
            expected_fragment_packets = total_request_attempts * 2
            background_family_disabled = 2
            background_invalid_destination = 1
            background_packets = (
                background_family_disabled + background_invalid_destination
            )
            row["diagnostics"] = {
                "schema_version": 2,
                "kind": "fragment_ack_accounting",
                "batch_datagrams": 8,
                "ack_window_milliseconds": 500,
                "max_missing_per_batch": 1,
                "max_retransmissions_per_sequence": 1,
                "retry_budget_unique_datagrams": 1_000_000,
                "minimum_retry_budget": 1,
                "retry_scope": "missing-sequence-only",
                "accounting": {
                    "warmup_unique_datagrams": warmup_unique,
                    "warmup_request_attempts": warmup_unique,
                    "active_unique_datagrams": active_unique,
                    "active_request_attempts": active_unique + retransmissions,
                    "total_unique_datagrams": total_unique,
                    "total_request_attempts": total_request_attempts,
                    "retransmissions": retransmissions,
                    "ack_window_expirations": retransmissions,
                    "duplicate_or_stale_acks": 0,
                    "retry_budget": 1,
                },
                "packet_counter_deltas": {
                    "accepted_packets": expected_fragment_packets,
                    "ingress_packets": expected_fragment_packets
                    + background_packets,
                    "background_family_disabled": background_family_disabled,
                    "background_invalid_destination": (
                        background_invalid_destination
                    ),
                    "background_packets": background_packets,
                },
                "adapter_counter_deltas": {
                    "ReceivedUnicastPackets": total_request_attempts,
                    "ReceivedDiscardedPackets": 0,
                    "ReceivedPacketErrors": 0,
                    "SentUnicastPackets": expected_fragment_packets
                    + background_packets,
                    "OutboundDiscardedPackets": 0,
                    "OutboundPacketErrors": 0,
                },
            }
        if scenario in {"udp-route-once", "network-lifecycle"}:
            row["network_model_evidence"] = {
                "schema_version": 1,
                "controller_sha256": windows_recipe.source_identities()["network_model_controller_sha256"],
                "collector_sha256": windows_recipe.source_identities()["collector_source_sha256"],
                "plan_sha256": windows_recipe.network_model_plan_sha256(),
                "observation_file": (
                    f"{sequence:03d}-{scenario}-{member}-pair-{pair}.network-model.json"
                ),
                "observation_sha256": "9" * 64,
            }
            if scenario == "udp-route-once":
                summary = network_model_route.summarize_route_once_observation(
                    self.route_once_observation(row=row)
                )
                values = windows_trial._route_once_trial_values(summary)
                row["correctness"]["checked_units"] = summary["datagrams_sent"]
                row["correctness"]["checks"] = {
                    "every_reply_accounted": True,
                    "payload_exact": True,
                    "direct_and_proxy_sources": True,
                    "association_creation_counter_exact": True,
                    "router_invocation_counter_exact": True,
                    "post_reset_reroute_verified": True,
                    "network_model_evidence_bound": True,
                    "tun_path_observed": True,
                    "clean_drain": True,
                }
            else:
                summary = network_model_lifecycle.summarize_lifecycle_observation(
                    self.network_model_observation(row=row)
                )
                values = windows_trial._network_model_trial_values(summary)
            for metric, value in values.items():
                row["measurements"][metric]["value"] = value
            if scenario == "network-lifecycle":
                row["correctness"]["checks"] = {
                    "same_process_all_cycles": True,
                    "resource_warmup_exact": True,
                    "generation_advanced_once_per_cycle": True,
                    "managed_identity_preserved_across_resets": True,
                    "damage_only_full_rebuild": True,
                    "reset_and_full_rebuild_metrics_are_exact": True,
                    "resource_growth_zero_after_1000_resets": True,
                    "tcp_and_udp_recovered_after_interface_switch": True,
                    "interface_resolver_cache_hit_observed": True,
                    "network_model_evidence_bound": True,
                    "tun_path_observed": True,
                    "clean_drain": True,
                }
        return row

    def evidence(
        self,
        root: pathlib.Path,
        *,
        plan: dict[str, object],
        parent_sha: str,
        candidate_sha: str,
        regression: bool = False,
    ) -> None:
        model_root = root / "network-model"
        model_root.mkdir()
        for trial in plan["trials"]:
            row = self.row(
                plan=plan,
                scenario=trial["scenario"],
                pair=trial["pair"],
                member=trial["member"],
                parent_sha=parent_sha,
                candidate_sha=candidate_sha,
                regression=regression,
            )
            if row["scenario"] in {"udp-route-once", "network-lifecycle"}:
                observation = (
                    self.route_once_observation(row=row)
                    if row["scenario"] == "udp-route-once"
                    else self.network_model_observation(row=row)
                )
                encoded = json.dumps(observation, sort_keys=True).encode("utf-8")
                reference = row["network_model_evidence"]
                reference["observation_sha256"] = hashlib.sha256(encoded).hexdigest()
                (model_root / reference["observation_file"]).write_bytes(encoded)
            path = root / (
                f"{trial['scenario']}-{trial['pair']}-{trial['member']}.json"
            )
            path.write_text(json.dumps(row), encoding="utf-8")
