use super::*;

#[test]
fn every_tun_event_maps_to_one_exact_metric_or_closed_diagnostic() {
    use ferrum2_tun::{
        TunDiagnosticReason, TunEvent, TunIpFamily, TunNetworkFullRebuildReason,
        TunNetworkResetReason, TunRejectReason, UdpResponseDropReason,
    };

    let metrics = ferrum2_observability::Metrics::new();
    let events = [
        TunEvent::PacketAccepted,
        TunEvent::PacketFoundationDropped,
        TunEvent::SessionStarted,
        TunEvent::StrictRouteFilterInstalled,
        TunEvent::StrictRouteFilterInstallFailed,
        TunEvent::NetworkResetStarted(TunNetworkResetReason::NetworkChange),
        TunEvent::NetworkResetSucceeded(TunNetworkResetReason::NetworkChange),
        TunEvent::NetworkResetFailed(TunNetworkResetReason::NetworkChange),
        TunEvent::NetworkResetStarted(TunNetworkResetReason::Retry),
        TunEvent::NetworkResetSucceeded(TunNetworkResetReason::Retry),
        TunEvent::NetworkResetFailed(TunNetworkResetReason::Retry),
        TunEvent::NetworkFullRebuildStarted {
            reason: TunNetworkFullRebuildReason::RouteDamage,
            generation: 7,
            tcp_associations: 5,
            udp_associations: 6,
        },
        TunEvent::NetworkFullRebuildSucceeded {
            reason: TunNetworkFullRebuildReason::RouteDamage,
            generation: 7,
            tcp_associations: 5,
            udp_associations: 6,
        },
        TunEvent::NetworkFullRebuildFailed {
            reason: TunNetworkFullRebuildReason::RouteDamage,
            generation: 7,
            tcp_associations: 5,
            udp_associations: 6,
        },
        TunEvent::SessionGeneration(7),
        TunEvent::SessionActive(true),
        TunEvent::PacketIngress,
        TunEvent::PacketEgress,
        TunEvent::InternalEgressBackpressured,
        TunEvent::WintunRingFullDropped,
        TunEvent::TcpFlowsActive(11),
        TunEvent::TcpFlowRejectedLimit,
        TunEvent::TcpFlowResetRestart,
        TunEvent::TcpBridgeBlocked,
        TunEvent::UdpAssociationsActive(13),
        TunEvent::UdpCandidatesActive(17),
        TunEvent::UdpAssociationCreated,
        TunEvent::UdpAssociationRejectedLimit,
        TunEvent::UdpDatagramQueueFull,
        TunEvent::UdpResponseQueueFull,
        TunEvent::UdpResponseFiltered,
        TunEvent::UdpResponseDropped(UdpResponseDropReason::OwnerFatal),
        TunEvent::UdpPendingResponses(1),
        TunEvent::UdpStaleGeneration,
        TunEvent::ReassemblyEntriesActive(19),
        TunEvent::ReassemblyStarted,
        TunEvent::ReassemblyCompleted,
        TunEvent::ReassemblyDroppedOverlap,
        TunEvent::ReassemblyDroppedTimeout,
        TunEvent::ReassemblyDroppedLimit,
        TunEvent::ReassemblyDroppedMalformed,
        TunEvent::NetworkChange,
        TunEvent::UnderlayBindStale,
        TunEvent::Diagnostic {
            reason: TunDiagnosticReason::WintunRingFull,
            family: TunIpFamily::Ipv4,
        },
    ];
    for event in events {
        record_tun_event(&metrics, event);
    }
    let reject_reasons = [
        TunRejectReason::InvalidIpVersion,
        TunRejectReason::FamilyDisabled,
        TunRejectReason::InvalidIpLength,
        TunRejectReason::InvalidIpChecksum,
        TunRejectReason::InvalidExtensionHeader,
        TunRejectReason::UnsupportedIpProtocol,
        TunRejectReason::IcmpEchoUnsupported,
        TunRejectReason::FragmentMalformed,
        TunRejectReason::FragmentOverlap,
        TunRejectReason::FragmentTimeout,
        TunRejectReason::FragmentLimit,
        TunRejectReason::InvalidTransportLength,
        TunRejectReason::InvalidTransportChecksum,
        TunRejectReason::InvalidSource,
        TunRejectReason::InvalidDestination,
        TunRejectReason::IngressFull,
        TunRejectReason::TcpFlowLimit,
        TunRejectReason::UdpAssociationLimit,
        TunRejectReason::UdpCandidateTimeout,
        TunRejectReason::UdpQueueFull,
        TunRejectReason::UdpResponseFiltered,
        TunRejectReason::UdpResponseClosed,
        TunRejectReason::StaleGeneration,
        TunRejectReason::WintunRingFull,
    ];
    for reason in reject_reasons {
        record_tun_event(&metrics, TunEvent::PacketRejected(reason));
    }

    let output = metrics.encode_text().expect("TUN metrics");
    for sample in [
        "ferrum2_tun_packets_accepted_total 1",
        "ferrum2_tun_packets_foundation_dropped_total 1",
        "ferrum2_tun_session_started_total 1",
        "ferrum2_network_reset_total{reason=\"network_change\",result=\"started\"} 1",
        "ferrum2_network_reset_total{reason=\"network_change\",result=\"succeeded\"} 1",
        "ferrum2_network_reset_total{reason=\"network_change\",result=\"failed\"} 1",
        "ferrum2_network_reset_total{reason=\"retry\",result=\"started\"} 1",
        "ferrum2_network_reset_total{reason=\"retry\",result=\"succeeded\"} 1",
        "ferrum2_network_reset_total{reason=\"retry\",result=\"failed\"} 1",
        "ferrum2_network_full_rebuild_total{reason=\"route_damage\",result=\"started\"} 1",
        "ferrum2_network_full_rebuild_total{reason=\"route_damage\",result=\"succeeded\"} 1",
        "ferrum2_network_full_rebuild_total{reason=\"route_damage\",result=\"failed\"} 1",
        "ferrum2_network_associations_reset_total{operation=\"full_rebuild\",transport=\"tcp\"} 5",
        "ferrum2_network_associations_reset_total{operation=\"full_rebuild\",transport=\"udp\"} 6",
        "ferrum2_tun_session_generation 7",
        "ferrum2_tun_session_active 1",
        "ferrum2_tun_packets_ingress_total 1",
        "ferrum2_tun_packets_egress_total 1",
        "ferrum2_tun_internal_egress_backpressured_total 1",
        "ferrum2_tun_wintun_ring_full_dropped_total 1",
        "ferrum2_tun_tcp_flows_active 11",
        "ferrum2_tun_tcp_flows_rejected_limit_total 1",
        "ferrum2_tun_tcp_flows_reset_restart_total 1",
        "ferrum2_tun_tcp_bridge_blocked_total 1",
        "ferrum2_tun_udp_associations_active 13",
        "ferrum2_tun_udp_candidates_active 17",
        "ferrum2_tun_udp_association_created_total 1",
        "ferrum2_tun_udp_association_rejected_limit_total 1",
        "ferrum2_tun_udp_datagram_queue_full_total 1",
        "ferrum2_tun_pending_udp_responses 1",
        "ferrum2_tun_udp_response_queue_full_total 1",
        "ferrum2_tun_udp_response_filtered_total 1",
        "ferrum2_tun_udp_response_dropped_total{reason=\"owner_fatal\"} 1",
        "ferrum2_tun_udp_stale_generation_total 1",
        "ferrum2_tun_reassembly_entries_active 19",
        "ferrum2_tun_reassembly_started_total 1",
        "ferrum2_tun_reassembly_completed_total 1",
        "ferrum2_tun_reassembly_dropped_overlap_total 1",
        "ferrum2_tun_reassembly_dropped_timeout_total 1",
        "ferrum2_tun_reassembly_dropped_limit_total 1",
        "ferrum2_tun_reassembly_dropped_malformed_total 1",
        "ferrum2_tun_network_change_total 1",
        "ferrum2_tun_underlay_bind_stale_total 1",
    ] {
        assert!(
            output.lines().any(|line| line == sample),
            "missing {sample}"
        );
    }
    assert!(!output.contains("ferrum2_tun_route_detect"));
    assert!(!output.contains("ferrum2_tun_route_conflict"));
    assert_eq!(
        output
            .lines()
            .filter(
                |line| line.starts_with("ferrum2_tun_packets_rejected_total{")
                    && line.ends_with(" 1")
            )
            .count(),
        reject_reasons.len()
    );
}

#[test]
fn deferred_then_injected_udp_response_keeps_rejected_metrics_at_zero() {
    let metrics = ferrum2_observability::Metrics::new();
    record_tun_event(&metrics, ferrum2_tun::TunEvent::InternalEgressBackpressured);
    record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(1));
    record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(0));

    let output = metrics.encode_text().expect("deferred TUN UDP metrics");
    assert!(
        output
            .lines()
            .any(|line| line == "ferrum2_tun_internal_egress_backpressured_total 1")
    );
    assert!(
        output
            .lines()
            .any(|line| line == "ferrum2_tun_pending_udp_responses 0")
    );
    let rejected = output
        .lines()
        .filter(|line| line.starts_with("ferrum2_tun_packets_rejected_total{"))
        .collect::<Vec<_>>();
    assert!(
        rejected.iter().all(|line| line.ends_with(" 0")),
        "a delayed response that is later injected is not rejected: {rejected:?}"
    );
}

#[test]
fn deferred_then_dropped_udp_response_counts_each_terminal_metric_once() {
    let metrics = ferrum2_observability::Metrics::new();
    record_tun_event(&metrics, ferrum2_tun::TunEvent::InternalEgressBackpressured);
    record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(1));
    record_tun_event(
        &metrics,
        ferrum2_tun::TunEvent::UdpResponseDropped(
            ferrum2_tun::UdpResponseDropReason::InjectionRejected,
        ),
    );
    record_tun_event(
        &metrics,
        ferrum2_tun::TunEvent::PacketRejected(ferrum2_tun::TunRejectReason::InvalidIpChecksum),
    );
    record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(0));

    let output = metrics.encode_text().expect("terminal TUN UDP metrics");
    assert!(output.lines().any(|line| {
        line == "ferrum2_tun_udp_response_dropped_total{reason=\"injection_rejected\"} 1"
    }));
    assert!(output.lines().any(|line| {
        line == "ferrum2_tun_packets_rejected_total{reason=\"invalid_ip_checksum\"} 1"
    }));
    assert_eq!(
        output
            .lines()
            .filter(|line| {
                line.starts_with("ferrum2_tun_udp_response_dropped_total{") && line.ends_with(" 1")
            })
            .count(),
        1
    );
    assert_eq!(
        output
            .lines()
            .filter(|line| {
                line.starts_with("ferrum2_tun_packets_rejected_total{") && line.ends_with(" 1")
            })
            .count(),
        1
    );
    assert!(
        output
            .lines()
            .any(|line| line == "ferrum2_tun_pending_udp_responses 0")
    );
}

pub(in crate::run) struct NeverPrepared;

impl PreparedProcessRoot<RunError> for NeverPrepared {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        _cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}
