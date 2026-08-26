"""udp schema owner."""

from __future__ import annotations



WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES = 256 * 1024


WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA = (
    "ferrum2.windows-tun.hyperv-udp-diagnostic.v1"
)


WINDOWS_TUN_UDP_FAILURE_SUMMARY_SCHEMA = (
    "ferrum2.windows-tun.hyperv-udp-failure-summary.v1"
)


WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA = (
    "ferrum2.windows-tun.udp-workload-flow-ledger.v3"
)


WINDOWS_TUN_UDP_SUPPORT_LEDGER_SCHEMA = (
    "ferrum2.windows-tun.udp-support-ledger.v2"
)


WINDOWS_TUN_UDP_DIAGNOSTIC_LIMITS = {
    "max_artifacts": 32,
    "max_total_bytes": 256 * 1024 * 1024,
    "max_artifact_bytes": 128 * 1024 * 1024,
    "max_ndjson_line_bytes": 4 * 1024,
    "max_ledger_events": 65_536,
}


WINDOWS_TUN_UDP_ASSOCIATION_DIAGNOSTIC_FIELDS = frozenset(
    {"udp_association_source_preflight"}
)


WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_SCHEMA = (
    "ferrum2.windows-tun.udp-fixed-source-preflight.v1"
)


WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_FIELDS = frozenset(
    {
        "schema",
        "captured_utc",
        "source_contract",
        "adapter",
        "ip_owner",
        "udp_endpoint_conflicts",
        "dynamic_port_udp",
        "dynamic_port_range",
        "dynamic_port_intersects_source",
        "excluded_port_ranges_udp",
        "excluded_port_ranges",
        "excluded_port_intersections",
        "valid",
        "violations",
        "errors",
    }
)


WINDOWS_TUN_UDP_SOURCE_CONTRACT_FIELDS = frozenset(
    {
        "adapter_name",
        "source_ip",
        "source_prefix_length",
        "source_port_first",
        "source_port_last",
        "source_port_count",
    }
)


WINDOWS_TUN_UDP_SOURCE_MATCH_SET_FIELDS = frozenset(
    {"match_count", "retained_count", "matches"}
)


WINDOWS_TUN_UDP_SOURCE_ADAPTER_FIELDS = frozenset(
    {
        "name",
        "interface_description",
        "interface_index",
        "status",
        "mac_address",
    }
)


WINDOWS_TUN_UDP_SOURCE_IP_OWNER_FIELDS = frozenset(
    {
        "ip_address",
        "prefix_length",
        "interface_index",
        "interface_alias",
        "address_state",
        "prefix_origin",
        "suffix_origin",
    }
)


WINDOWS_TUN_UDP_SOURCE_CONFLICT_FIELDS = frozenset(
    {"count", "retained_count", "truncated", "endpoints"}
)


WINDOWS_TUN_UDP_SOURCE_CONFLICT_ENDPOINT_FIELDS = frozenset(
    {"local_address", "local_port", "owning_process"}
)


WINDOWS_TUN_UDP_SOURCE_NETSH_SNAPSHOT_FIELDS = frozenset(
    {"command", "exit_code", "total_lines", "truncated", "lines"}
)


WINDOWS_TUN_UDP_SOURCE_PORT_RANGE_FIELDS = frozenset(
    {"first_port", "last_port", "port_count"}
)


WINDOWS_TUN_UDP_SOURCE_EXCLUDED_RANGE_FIELDS = frozenset(
    {"first_port", "last_port"}
)


WINDOWS_TUN_UDP_DIAGNOSTIC_FIELDS = frozenset(
    "schema qualification profile evidence_status trial_status run_nonce "
    "started_utc finished_utc identity trial environment support topology "
    "bounds artifacts failure_summary cleanup".split()
)


WINDOWS_TUN_UDP_DIAGNOSTIC_IDENTITY_FIELDS = frozenset(
    "parent_sha candidate_sha sha tree client_sha256 server_sha256 harness_sha256 "
    "runner_sha256 recipe_sha256 plan_sha256".split()
)


WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_FIELDS = frozenset(
    "selection run_kind sequence scenario member pair order".split()
)


WINDOWS_TUN_UDP_DIAGNOSTIC_SUPPORT_FIELDS = frozenset(
    "pid owner binary_sha256 listen_endpoints".split()
)


WINDOWS_TUN_UDP_SUPPORT_ENDPOINT_FIELDS = frozenset("protocol ip port".split())


WINDOWS_TUN_UDP_DIAGNOSTIC_TOPOLOGY_FIELDS = frozenset(
    "support_ipv4 guest_ipv4 host_network_path_file host_network_path_sha256 "
    "host_tun_bypassed host_network_mutations".split()
)


WINDOWS_TUN_UDP_DIAGNOSTIC_BOUND_FIELDS = frozenset(
    WINDOWS_TUN_UDP_DIAGNOSTIC_LIMITS
)


WINDOWS_TUN_UDP_DIAGNOSTIC_ARTIFACT_FIELDS = frozenset(
    "role state file sha256 bytes records max_events dropped_events write_failures".split()
)


WINDOWS_TUN_UDP_FAILURE_REFERENCE_FIELDS = frozenset("file sha256".split())


WINDOWS_TUN_UDP_DIAGNOSTIC_ARTIFACT_ROLES = frozenset(
    "workload_ledger support_ledger host_capture host_capture_native "
    "endpoint_snapshot_before endpoint_snapshot_after dynamic_port_snapshot_before "
    "dynamic_port_snapshot_after host_network_path failure_summary runner_log "
    "guest_process_log host_process_log".split()
)


WINDOWS_TUN_UDP_DIAGNOSTIC_CLEANUP_FIELDS = frozenset(
    "status checkpoint_restored final_vm_state capture_stop_status "
    "guest_owned_processes".split()
)


WINDOWS_TUN_UDP_FAILURE_SUMMARY_FIELDS = frozenset(
    "schema qualification run_nonce parent_sha candidate_sha sha tree client_sha256 "
    "server_sha256 harness_sha256 runner_sha256 recipe_sha256 vm_id checkpoint_id "
    "support_pid support_owner support_sha256 trial_sequence scenario member pair order "
    "failure_kind phase association_index round packet_nonce workload_tuple physical_tuple "
    "observation_sources observations last_confirmed_stage first_missing_stage "
    "response_sink_outcome failure_fingerprint cleanup".split()
)


WINDOWS_TUN_UDP_FAILURE_TUPLE_FIELDS = frozenset(
    "source_ip source_port target_ip target_port".split()
)


WINDOWS_TUN_UDP_OBSERVATION_STAGES = tuple(
    "workload_send direct_send guest_request host_request support_rx support_tx "
    "host_reply guest_reply ferrum_receive response_classified response_sink "
    "wintun_injection workload_reply".split()
)


WINDOWS_TUN_UDP_OBSERVATION_SOURCES = frozenset(
    "workload_ledger support_ledger host_capture guest_capture ferrum_boundary".split()
)


WINDOWS_TUN_UDP_OBSERVATION_SOURCE_FIELDS = frozenset(
    "state records dropped_events write_failures covers_packet_nonce".split()
)


WINDOWS_TUN_UDP_LEDGER_COUNTER_FIELDS = frozenset(
    "attempted_events events_written dropped_events write_failures".split()
)


WINDOWS_TUN_UDP_LEDGER_EVENT_COMMON_FIELDS = frozenset(
    "schema record_type event_index timestamp_qpc timestamp_qpc_frequency "
    "ledger_counters".split()
)


WINDOWS_TUN_UDP_WORKLOAD_EVENT_FIELDS = frozenset(
    WINDOWS_TUN_UDP_LEDGER_EVENT_COMMON_FIELDS
    | set(
        "run_nonce trial_sequence phase association_index round packet_nonce "
        "workload_local_ip workload_local_port target_ip target_port send_result "
        "send_bytes reply_result reply_source_ip reply_source_port payload_match "
        "error_kind".split()
    )
)


WINDOWS_TUN_UDP_SUPPORT_EVENT_FIELDS = frozenset(
    WINDOWS_TUN_UDP_LEDGER_EVENT_COMMON_FIELDS
    | set(
        "stage listen_ip listen_port remote_ip remote_port payload_run_nonce "
        "payload_run_nonce_match trial_sequence phase association_index round "
        "packet_nonce recv_bytes send_attempted send_result send_bytes error_kind".split()
    )
)


WINDOWS_TUN_UDP_CAPTURE_MANIFEST_FIELDS = frozenset(
    "schema state filters started_utc stop_status expected_files files failures".split()
)


WINDOWS_TUN_UDP_CAPTURE_FILE_FIELDS = frozenset("file bytes sha256".split())


WINDOWS_TUN_UDP_CAPTURE_FILTER_FIELDS = frozenset(
    "name support_ipv4 protocol port command_exit_code".split()
)


WINDOWS_TUN_UDP_CAPTURE_FILES = (
    "PktMon.etl",
    "PktMon.txt",
    "PktMon.pcapng",
    "pktmon-counters.json",
    "pktmon-stop.txt",
)
