use std::collections::BTreeSet;

use ferrum2_observability::{Metrics, TunPacketRejectReason, TunUdpResponseDropReason};

const PACKET_REJECT_REASONS: &[(TunPacketRejectReason, &str)] = &[
    (
        TunPacketRejectReason::InvalidIpVersion,
        "invalid_ip_version",
    ),
    (TunPacketRejectReason::FamilyDisabled, "family_disabled"),
    (TunPacketRejectReason::InvalidIpLength, "invalid_ip_length"),
    (
        TunPacketRejectReason::InvalidIpChecksum,
        "invalid_ip_checksum",
    ),
    (
        TunPacketRejectReason::InvalidExtensionHeader,
        "invalid_extension_header",
    ),
    (
        TunPacketRejectReason::UnsupportedIpProtocol,
        "unsupported_ip_protocol",
    ),
    (
        TunPacketRejectReason::IcmpEchoUnsupported,
        "icmp_echo_unsupported",
    ),
    (
        TunPacketRejectReason::FragmentMalformed,
        "fragment_malformed",
    ),
    (TunPacketRejectReason::FragmentOverlap, "fragment_overlap"),
    (TunPacketRejectReason::FragmentTimeout, "fragment_timeout"),
    (TunPacketRejectReason::FragmentLimit, "fragment_limit"),
    (
        TunPacketRejectReason::InvalidTransportLength,
        "invalid_transport_length",
    ),
    (
        TunPacketRejectReason::InvalidTransportChecksum,
        "invalid_transport_checksum",
    ),
    (TunPacketRejectReason::InvalidSource, "invalid_source"),
    (
        TunPacketRejectReason::InvalidDestination,
        "invalid_destination",
    ),
    (TunPacketRejectReason::IngressFull, "ingress_full"),
    (TunPacketRejectReason::TcpFlowLimit, "tcp_flow_limit"),
    (
        TunPacketRejectReason::UdpAssociationLimit,
        "udp_association_limit",
    ),
    (
        TunPacketRejectReason::UdpCandidateTimeout,
        "udp_candidate_timeout",
    ),
    (TunPacketRejectReason::UdpQueueFull, "udp_queue_full"),
    (
        TunPacketRejectReason::UdpResponseFiltered,
        "udp_response_filtered",
    ),
    (
        TunPacketRejectReason::UdpResponseClosed,
        "udp_response_closed",
    ),
    (TunPacketRejectReason::StaleGeneration, "stale_generation"),
    (TunPacketRejectReason::WintunRingFull, "wintun_ring_full"),
];

const UDP_RESPONSE_DROP_REASONS: &[(TunUdpResponseDropReason, &str)] = &[
    (
        TunUdpResponseDropReason::StaleGeneration,
        "stale_generation",
    ),
    (
        TunUdpResponseDropReason::AssociationClosed,
        "association_closed",
    ),
    (TunUdpResponseDropReason::QueueFull, "queue_full"),
    (
        TunUdpResponseDropReason::MalformedResponse,
        "malformed_response",
    ),
    (TunUdpResponseDropReason::Filtered, "filtered"),
    (
        TunUdpResponseDropReason::InjectionRejected,
        "injection_rejected",
    ),
    (TunUdpResponseDropReason::SessionReset, "session_reset"),
    (TunUdpResponseDropReason::Shutdown, "shutdown"),
    (TunUdpResponseDropReason::OwnerFatal, "owner_fatal"),
];

fn series(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.rsplit_once(' ')
                .expect("sample and value")
                .0
                .to_owned()
        })
        .collect()
}

fn record_one_of_every_tun_event(metrics: &Metrics) {
    metrics.tun_session_started();
    metrics.tun_session_restart_started();
    metrics.tun_session_restart_succeeded();
    metrics.tun_session_restart_failed();
    metrics.set_tun_session_generation(7);
    metrics.set_tun_session_active(true);
    metrics.tun_session_active_inc();
    metrics.tun_session_active_dec();

    metrics.tun_packet_ingress();
    metrics.tun_packet_egress();
    for (reason, _) in PACKET_REJECT_REASONS {
        metrics.tun_packet_rejected(*reason);
    }
    metrics.tun_internal_egress_backpressured();
    metrics.set_tun_pending_udp_responses(1);
    for (reason, _) in UDP_RESPONSE_DROP_REASONS {
        metrics.tun_udp_response_dropped(*reason);
    }
    metrics.tun_wintun_ring_full_dropped();

    metrics.set_tun_tcp_flows_active(11);
    metrics.tun_tcp_flows_active_inc();
    metrics.tun_tcp_flows_active_dec();
    metrics.tun_tcp_flow_rejected_limit();
    metrics.tun_tcp_flow_reset_restart();
    metrics.tun_tcp_bridge_blocked();

    metrics.set_tun_udp_associations_active(13);
    metrics.tun_udp_associations_active_inc();
    metrics.tun_udp_associations_active_dec();
    metrics.set_tun_udp_candidates_active(17);
    metrics.tun_udp_candidates_active_inc();
    metrics.tun_udp_candidates_active_dec();
    metrics.tun_udp_association_created();
    metrics.tun_udp_association_rejected_limit();
    metrics.tun_udp_datagram_queue_full();
    metrics.tun_udp_response_queue_full();
    metrics.tun_udp_response_filtered();
    metrics.tun_udp_stale_generation();

    metrics.set_tun_reassembly_entries_active(19);
    metrics.tun_reassembly_entries_active_inc();
    metrics.tun_reassembly_entries_active_dec();
    metrics.tun_reassembly_started();
    metrics.tun_reassembly_completed();
    metrics.tun_reassembly_dropped_overlap();
    metrics.tun_reassembly_dropped_timeout();
    metrics.tun_reassembly_dropped_limit();
    metrics.tun_reassembly_dropped_malformed();

    metrics.tun_network_change();
    metrics.tun_underlay_bind_stale();
}

#[test]
fn tun_metric_names_types_and_help_are_an_exact_contract() {
    let metrics = Metrics::new();
    record_one_of_every_tun_event(&metrics);
    let output = metrics.encode_text().expect("TUN metrics");

    let legacy = [
        "ferrum2_tun_packets_accepted",
        "ferrum2_tun_packets_foundation_dropped",
    ];
    let help = output
        .lines()
        .filter_map(|line| line.strip_prefix("# HELP "))
        .filter(|line| line.starts_with("ferrum2_tun_"))
        .filter(|line| !legacy.iter().any(|name| line.starts_with(name)))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        help,
        BTreeSet::from([
            "ferrum2_tun_internal_egress_backpressured TUN internal egress backpressure observations; packets are retained for retry.",
            "ferrum2_tun_network_change Semantic network changes observed by the TUN session.",
            "ferrum2_tun_pending_udp_responses TUN UDP responses retained for owner-thread injection.",
            "ferrum2_tun_packets_egress Packets sent successfully to Wintun by the TUN owner.",
            "ferrum2_tun_packets_ingress Packets received from Wintun by the TUN owner.",
            "ferrum2_tun_packets_rejected TUN packets rejected by a closed low-cardinality reason.",
            "ferrum2_tun_reassembly_completed TUN fragment reassemblies completed.",
            "ferrum2_tun_reassembly_dropped_limit TUN fragment reassemblies dropped by a bounded limit.",
            "ferrum2_tun_reassembly_dropped_malformed Malformed TUN fragment reassemblies dropped.",
            "ferrum2_tun_reassembly_dropped_overlap TUN fragment reassemblies dropped for overlap.",
            "ferrum2_tun_reassembly_dropped_timeout TUN fragment reassemblies dropped after timeout.",
            "ferrum2_tun_reassembly_entries_active Active bounded TUN fragment reassembly entries.",
            "ferrum2_tun_reassembly_started TUN fragment reassemblies started.",
            "ferrum2_tun_session_active Whether a TUN session is active.",
            "ferrum2_tun_session_generation Current TUN session generation.",
            "ferrum2_tun_session_restart_failed TUN session restart attempts that failed.",
            "ferrum2_tun_session_restart_started TUN session restart attempts started.",
            "ferrum2_tun_session_restart_succeeded TUN session restart attempts completed successfully.",
            "ferrum2_tun_session_started TUN sessions that reached their initial start.",
            "ferrum2_tun_tcp_bridge_blocked TUN TCP bridge operations that observed bounded backpressure.",
            "ferrum2_tun_tcp_flows_active Active TUN TCP flows.",
            "ferrum2_tun_tcp_flows_rejected_limit TUN TCP flows rejected by the configured flow limit.",
            "ferrum2_tun_tcp_flows_reset_restart TUN TCP flows reset during session restart.",
            "ferrum2_tun_udp_association_created TUN UDP associations created.",
            "ferrum2_tun_udp_association_rejected_limit TUN UDP associations rejected by the configured limit.",
            "ferrum2_tun_udp_associations_active Active TUN UDP associations.",
            "ferrum2_tun_udp_candidates_active Active uncommitted TUN UDP association candidates.",
            "ferrum2_tun_udp_datagram_queue_full TUN UDP datagrams dropped because an association queue was full.",
            "ferrum2_tun_udp_response_filtered TUN UDP responses rejected by endpoint filtering.",
            "ferrum2_tun_udp_response_dropped Terminal TUN UDP response drops by a closed low-cardinality reason.",
            "ferrum2_tun_udp_response_queue_full TUN UDP responses dropped because the response queue was full.",
            "ferrum2_tun_udp_stale_generation TUN UDP work rejected after its session generation became stale.",
            "ferrum2_tun_underlay_bind_stale TUN underlay binds rejected because their generation was stale.",
            "ferrum2_tun_wintun_ring_full_dropped TUN packets dropped because the Wintun send ring was full.",
        ])
    );

    let types = output
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter(|line| line.starts_with("ferrum2_tun_"))
        .filter(|line| !legacy.iter().any(|name| line.starts_with(name)))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        types,
        BTreeSet::from([
            "ferrum2_tun_internal_egress_backpressured counter",
            "ferrum2_tun_network_change counter",
            "ferrum2_tun_pending_udp_responses gauge",
            "ferrum2_tun_packets_egress counter",
            "ferrum2_tun_packets_ingress counter",
            "ferrum2_tun_packets_rejected counter",
            "ferrum2_tun_reassembly_completed counter",
            "ferrum2_tun_reassembly_dropped_limit counter",
            "ferrum2_tun_reassembly_dropped_malformed counter",
            "ferrum2_tun_reassembly_dropped_overlap counter",
            "ferrum2_tun_reassembly_dropped_timeout counter",
            "ferrum2_tun_reassembly_entries_active gauge",
            "ferrum2_tun_reassembly_started counter",
            "ferrum2_tun_session_active gauge",
            "ferrum2_tun_session_generation gauge",
            "ferrum2_tun_session_restart_failed counter",
            "ferrum2_tun_session_restart_started counter",
            "ferrum2_tun_session_restart_succeeded counter",
            "ferrum2_tun_session_started counter",
            "ferrum2_tun_tcp_bridge_blocked counter",
            "ferrum2_tun_tcp_flows_active gauge",
            "ferrum2_tun_tcp_flows_rejected_limit counter",
            "ferrum2_tun_tcp_flows_reset_restart counter",
            "ferrum2_tun_udp_association_created counter",
            "ferrum2_tun_udp_association_rejected_limit counter",
            "ferrum2_tun_udp_associations_active gauge",
            "ferrum2_tun_udp_candidates_active gauge",
            "ferrum2_tun_udp_datagram_queue_full counter",
            "ferrum2_tun_udp_response_filtered counter",
            "ferrum2_tun_udp_response_dropped counter",
            "ferrum2_tun_udp_response_queue_full counter",
            "ferrum2_tun_udp_stale_generation counter",
            "ferrum2_tun_underlay_bind_stale counter",
            "ferrum2_tun_wintun_ring_full_dropped counter",
        ])
    );

    for expected in [
        "ferrum2_tun_session_generation 7",
        "ferrum2_tun_session_active 1",
        "ferrum2_tun_pending_udp_responses 1",
        "ferrum2_tun_tcp_flows_active 11",
        "ferrum2_tun_udp_associations_active 13",
        "ferrum2_tun_udp_candidates_active 17",
        "ferrum2_tun_reassembly_entries_active 19",
    ] {
        assert!(output.contains(expected), "missing sample {expected}");
    }
}

#[test]
fn tun_reason_series_are_closed_and_identity_free() {
    let metrics = Metrics::new();
    record_one_of_every_tun_event(&metrics);
    metrics.set_udp_buffered_bytes(ferrum2_observability::Role::Client, 4_096);
    let output = metrics.encode_text().expect("TUN metrics");
    let samples = series(&output);

    let rejected = samples
        .iter()
        .filter(|sample| sample.starts_with("ferrum2_tun_packets_rejected_total{"))
        .collect::<BTreeSet<_>>();
    assert_eq!(rejected.len(), PACKET_REJECT_REASONS.len());
    for (reason, encoded) in PACKET_REJECT_REASONS {
        assert_eq!(reason.to_string(), *encoded);
        assert!(rejected.contains(&format!(
            "ferrum2_tun_packets_rejected_total{{reason=\"{encoded}\"}}"
        )));
    }

    let response_drops = samples
        .iter()
        .filter(|sample| sample.starts_with("ferrum2_tun_udp_response_dropped_total{"))
        .collect::<BTreeSet<_>>();
    assert_eq!(response_drops.len(), UDP_RESPONSE_DROP_REASONS.len());
    for (reason, encoded) in UDP_RESPONSE_DROP_REASONS {
        assert_eq!(reason.to_string(), *encoded);
        assert!(response_drops.contains(&format!(
            "ferrum2_tun_udp_response_dropped_total{{reason=\"{encoded}\"}}"
        )));
    }

    for sample in samples
        .iter()
        .filter(|sample| sample.starts_with("ferrum2_tun_") && sample.contains('{'))
    {
        assert!(sample.contains("{reason=\""));
        assert_eq!(sample.matches('=').count(), 1);
    }
    for forbidden_label in ["ip=", "port=", "adapter=", "prefix="] {
        assert!(!output.contains(forbidden_label));
    }
    for sentinel in [
        "192.0.2.99",
        "[2001:db8::99]:443",
        "TUN_ADAPTER_SENTINEL",
        "10.0.0.0/8",
    ] {
        assert!(!output.contains(sentinel));
    }

    assert!(output.contains("# HELP ferrum2_udp_buffered_bytes "));
    assert!(output.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 4096"));
    assert!(!output.contains("ferrum2_tun_buffered_bytes"));
    assert!(!output.contains("ferrum2_tun_owned_bytes"));
    assert!(!output.contains("ferrum2_tun_route_detect"));
    assert!(!output.contains("ferrum2_tun_route_conflict"));
}
