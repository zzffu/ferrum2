use std::collections::BTreeSet;

const APPROVED_HYPER_V_GUEST: &str = "Windows 10 MSIX packaging environment";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Feature {
    InProcessRestart,
    FragmentReassembly,
    DualStackDns,
    UdpEimAdfEifRouting,
    SchedulerRingFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModeSpec {
    id: &'static str,
    feature: Feature,
    restart_cycles: Option<usize>,
    workflow_only: bool,
    approved_guest: &'static str,
    witnesses: &'static [&'static str],
    counters: &'static [&'static str],
}

const RESTART_WITNESSES: &[&str] = &[
    "same_process_for_every_restart",
    "generation_advances_once_per_restart",
    "adapter_route_dns_and_handler_baselines_restore",
];

const UDP_INTEROPERABILITY_WITNESSES: &[&str] = &[
    "one_eim_association_for_multiple_targets",
    "adf_allows_authorized_ip_any_port",
    "adf_rejects_unauthorized_ip",
    "eif_allows_valid_same_family_peer",
    "rejected_target_never_authorizes_peer",
    "per_target_route_and_outbound_decision",
    "mixed_ipv4_ipv6_target_children",
    "directed_broadcast_never_allocates_association",
    "udp_firewall_scope_is_journaled_and_removed",
    "dns_udp_payload_round_trips",
    "quic_v1_initial_envelope_round_trips",
    "stun_binding_requests_reach_multiple_servers",
    "webrtc_ice_candidate_check_round_trips",
    "game_style_binary_datagrams_reach_multiple_peers",
    "one_eim_association_mixes_direct_and_shadowsocks_targets",
    "association_capacity_drops_new_without_evicting_live",
    "udp_queue_pressure_is_bounded_and_control_remains_live",
    "restart_clears_udp_stale_generation_state",
];

const MODES: &[ModeSpec] = &[
    ModeSpec {
        id: "restart-stress-10",
        feature: Feature::InProcessRestart,
        restart_cycles: Some(10),
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: RESTART_WITNESSES,
        counters: &[
            "ferrum2_tun_session_restart_started_total",
            "ferrum2_tun_session_restart_succeeded_total",
            "ferrum2_tun_session_generation",
        ],
    },
    ModeSpec {
        id: "restart-stress-100",
        feature: Feature::InProcessRestart,
        restart_cycles: Some(100),
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: RESTART_WITNESSES,
        counters: &[
            "ferrum2_tun_session_restart_started_total",
            "ferrum2_tun_session_restart_succeeded_total",
            "ferrum2_tun_session_generation",
        ],
    },
    ModeSpec {
        id: "restart-stress-1000",
        feature: Feature::InProcessRestart,
        restart_cycles: Some(1000),
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: RESTART_WITNESSES,
        counters: &[
            "ferrum2_tun_session_restart_started_total",
            "ferrum2_tun_session_restart_succeeded_total",
            "ferrum2_tun_session_generation",
        ],
    },
    ModeSpec {
        id: "fragments",
        feature: Feature::FragmentReassembly,
        restart_cycles: None,
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: &[
            "ipv4_udp_out_of_order",
            "ipv4_tcp_out_of_order",
            "ipv6_extension_and_fragment",
            "fragmented_synthetic_dns",
            "overlap_drops_entry",
            "timeout_drops_entry",
        ],
        counters: &[
            "ferrum2_tun_reassembly_entries_active",
            "ferrum2_tun_packets_rejected_total",
        ],
    },
    ModeSpec {
        id: "dual-stack-dns",
        feature: Feature::DualStackDns,
        restart_cycles: None,
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: &[
            "ipv4_udp_dns",
            "ipv4_tcp_dns",
            "ipv6_udp_dns",
            "ipv6_tcp_dns",
            "dual_dns_readback_and_restore",
        ],
        counters: &[
            "ferrum2_tun_packets_ingress_total",
            "ferrum2_tun_packets_egress_total",
        ],
    },
    ModeSpec {
        id: "udp-policy",
        feature: Feature::UdpEimAdfEifRouting,
        restart_cycles: None,
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: UDP_INTEROPERABILITY_WITNESSES,
        counters: &[
            "ferrum2_tun_udp_associations_active",
            "ferrum2_tun_udp_candidates_active",
            "ferrum2_tun_udp_association_rejected_limit_total",
            "ferrum2_tun_udp_datagram_queue_full_total",
            "ferrum2_tun_udp_response_queue_full_total",
            "ferrum2_tun_udp_stale_generation_total",
        ],
    },
    ModeSpec {
        id: "scheduler-ring-full",
        feature: Feature::SchedulerRingFull,
        restart_cycles: None,
        workflow_only: true,
        approved_guest: APPROVED_HYPER_V_GUEST,
        witnesses: &[
            "rx_bursts_8_16_64_have_no_structural_drop",
            "udp_response_backpressure_is_lossless",
            "work_stages_rotate_fairly",
            "ring_full_drops_one_complete_packet",
            "ring_full_is_not_retried",
            "ring_full_does_not_restart_session",
            "wintun_error_kinds_have_exact_owner_dispositions",
            "live_egress_pressure_has_closed_accounting",
        ],
        counters: &[
            "ferrum2_tun_internal_egress_backpressured_total",
            "ferrum2_tun_wintun_ring_full_dropped_total",
            "ferrum2_tun_packets_egress_total",
        ],
    },
];

#[test]
fn privileged_mode_contract_is_closed_guest_only_and_feature_complete() {
    let ids = MODES.iter().map(|mode| mode.id).collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), MODES.len(), "duplicate privileged mode id");
    assert!(MODES.iter().all(|mode| {
        mode.workflow_only
            && mode.approved_guest == APPROVED_HYPER_V_GUEST
            && !mode.witnesses.is_empty()
            && !mode.counters.is_empty()
    }));

    let actual_features = MODES
        .iter()
        .map(|mode| mode.feature)
        .collect::<BTreeSet<_>>();
    let expected_features = BTreeSet::from([
        Feature::InProcessRestart,
        Feature::FragmentReassembly,
        Feature::DualStackDns,
        Feature::UdpEimAdfEifRouting,
        Feature::SchedulerRingFull,
    ]);
    assert_eq!(actual_features, expected_features);

    let restart_cycles = MODES
        .iter()
        .filter_map(|mode| mode.restart_cycles)
        .collect::<BTreeSet<_>>();
    assert_eq!(restart_cycles, BTreeSet::from([10, 100, 1000]));
    assert!(MODES.iter().all(|mode| {
        (mode.feature == Feature::InProcessRestart) == mode.restart_cycles.is_some()
    }));
}

#[test]
fn fixed_counter_names_are_low_cardinality() {
    let counters = MODES
        .iter()
        .flat_map(|mode| mode.counters.iter().copied())
        .collect::<BTreeSet<_>>();
    assert!(counters.iter().all(|name| {
        name.starts_with("ferrum2_tun_")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }));
}

#[test]
fn udp_policy_contract_covers_the_complete_interoperability_matrix() {
    let udp = MODES
        .iter()
        .find(|mode| mode.id == "udp-policy")
        .expect("UDP policy mode");
    let actual = udp.witnesses.iter().copied().collect::<BTreeSet<_>>();
    let required = BTreeSet::from([
        "dns_udp_payload_round_trips",
        "quic_v1_initial_envelope_round_trips",
        "stun_binding_requests_reach_multiple_servers",
        "webrtc_ice_candidate_check_round_trips",
        "game_style_binary_datagrams_reach_multiple_peers",
        "adf_allows_authorized_ip_any_port",
        "eif_allows_valid_same_family_peer",
        "one_eim_association_mixes_direct_and_shadowsocks_targets",
        "mixed_ipv4_ipv6_target_children",
        "association_capacity_drops_new_without_evicting_live",
        "udp_queue_pressure_is_bounded_and_control_remains_live",
        "restart_clears_udp_stale_generation_state",
    ]);
    assert!(required.is_subset(&actual));
    assert_eq!(actual.len(), UDP_INTEROPERABILITY_WITNESSES.len());
}
