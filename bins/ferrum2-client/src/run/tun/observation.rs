use ferrum2_observability::{
    Metrics, NetworkFullRebuildReason, NetworkLifecycleOperation, NetworkLifecycleResult,
    NetworkResetReason, Role, StrictRouteDiagnosticStatus, StrictRouteFilterInstallResult,
    Transport, TunDiagnosticReason, TunIpFamily, TunPacketRejectReason, TunUdpResponseDropReason,
    emit_network_full_rebuild_diagnostic, emit_strict_route_diagnostic, emit_tun_diagnostic,
};
use ferrum2_runtime::ManagedNetworkDamage;

pub(super) fn record_tun_event(metrics: &Metrics, event: ferrum2_tun::TunEvent) {
    use ferrum2_tun::TunEvent;

    match event {
        TunEvent::PacketAccepted => metrics.tun_packet_accepted(),
        TunEvent::PacketFoundationDropped => metrics.tun_packet_foundation_dropped(),
        TunEvent::SessionStarted => metrics.tun_session_started(),
        TunEvent::StrictRouteFilterInstalled => {
            metrics.tun_strict_route_filter_install(StrictRouteFilterInstallResult::Success);
            emit_strict_route_diagnostic(Role::Client, StrictRouteDiagnosticStatus::Installed);
        }
        TunEvent::StrictRouteFilterInstallFailed => {
            metrics.tun_strict_route_filter_install(StrictRouteFilterInstallResult::Failure);
            emit_strict_route_diagnostic(Role::Client, StrictRouteDiagnosticStatus::InstallFailed);
        }
        TunEvent::NetworkResetStarted(reason) => metrics.network_reset(
            map_network_reset_reason(reason),
            NetworkLifecycleResult::Started,
        ),
        TunEvent::NetworkResetSucceeded(reason) => metrics.network_reset(
            map_network_reset_reason(reason),
            NetworkLifecycleResult::Succeeded,
        ),
        TunEvent::NetworkResetFailed(reason) => metrics.network_reset(
            map_network_reset_reason(reason),
            NetworkLifecycleResult::Failed,
        ),
        TunEvent::NetworkFullRebuildStarted {
            reason,
            generation,
            tcp_associations,
            udp_associations,
        } => record_network_full_rebuild_event(
            metrics,
            reason,
            NetworkLifecycleResult::Started,
            generation,
            tcp_associations,
            udp_associations,
        ),
        TunEvent::NetworkFullRebuildSucceeded {
            reason,
            generation,
            tcp_associations,
            udp_associations,
        } => record_network_full_rebuild_event(
            metrics,
            reason,
            NetworkLifecycleResult::Succeeded,
            generation,
            tcp_associations,
            udp_associations,
        ),
        TunEvent::NetworkFullRebuildFailed {
            reason,
            generation,
            tcp_associations,
            udp_associations,
        } => record_network_full_rebuild_event(
            metrics,
            reason,
            NetworkLifecycleResult::Failed,
            generation,
            tcp_associations,
            udp_associations,
        ),
        TunEvent::SessionGeneration(generation) => {
            metrics.set_tun_session_generation(generation);
        }
        TunEvent::SessionActive(active) => metrics.set_tun_session_active(active),
        TunEvent::PacketIngress => metrics.tun_packet_ingress(),
        TunEvent::PacketEgress => metrics.tun_packet_egress(),
        TunEvent::PacketRejected(reason) => metrics.tun_packet_rejected(match reason {
            ferrum2_tun::TunRejectReason::InvalidIpVersion => {
                TunPacketRejectReason::InvalidIpVersion
            }
            ferrum2_tun::TunRejectReason::FamilyDisabled => TunPacketRejectReason::FamilyDisabled,
            ferrum2_tun::TunRejectReason::InvalidIpLength => TunPacketRejectReason::InvalidIpLength,
            ferrum2_tun::TunRejectReason::InvalidIpChecksum => {
                TunPacketRejectReason::InvalidIpChecksum
            }
            ferrum2_tun::TunRejectReason::InvalidExtensionHeader => {
                TunPacketRejectReason::InvalidExtensionHeader
            }
            ferrum2_tun::TunRejectReason::UnsupportedIpProtocol => {
                TunPacketRejectReason::UnsupportedIpProtocol
            }
            ferrum2_tun::TunRejectReason::IcmpEchoUnsupported => {
                TunPacketRejectReason::IcmpEchoUnsupported
            }
            ferrum2_tun::TunRejectReason::FragmentMalformed => {
                TunPacketRejectReason::FragmentMalformed
            }
            ferrum2_tun::TunRejectReason::FragmentOverlap => TunPacketRejectReason::FragmentOverlap,
            ferrum2_tun::TunRejectReason::FragmentTimeout => TunPacketRejectReason::FragmentTimeout,
            ferrum2_tun::TunRejectReason::FragmentLimit => TunPacketRejectReason::FragmentLimit,
            ferrum2_tun::TunRejectReason::InvalidTransportLength => {
                TunPacketRejectReason::InvalidTransportLength
            }
            ferrum2_tun::TunRejectReason::InvalidTransportChecksum => {
                TunPacketRejectReason::InvalidTransportChecksum
            }
            ferrum2_tun::TunRejectReason::InvalidSource => TunPacketRejectReason::InvalidSource,
            ferrum2_tun::TunRejectReason::InvalidDestination => {
                TunPacketRejectReason::InvalidDestination
            }
            ferrum2_tun::TunRejectReason::IngressFull => TunPacketRejectReason::IngressFull,
            ferrum2_tun::TunRejectReason::TcpFlowLimit => TunPacketRejectReason::TcpFlowLimit,
            ferrum2_tun::TunRejectReason::UdpAssociationLimit => {
                TunPacketRejectReason::UdpAssociationLimit
            }
            ferrum2_tun::TunRejectReason::UdpCandidateTimeout => {
                TunPacketRejectReason::UdpCandidateTimeout
            }
            ferrum2_tun::TunRejectReason::UdpQueueFull => TunPacketRejectReason::UdpQueueFull,
            ferrum2_tun::TunRejectReason::UdpResponseFiltered => {
                TunPacketRejectReason::UdpResponseFiltered
            }
            ferrum2_tun::TunRejectReason::UdpResponseClosed => {
                TunPacketRejectReason::UdpResponseClosed
            }
            ferrum2_tun::TunRejectReason::StaleGeneration => TunPacketRejectReason::StaleGeneration,
            ferrum2_tun::TunRejectReason::WintunRingFull => TunPacketRejectReason::WintunRingFull,
        }),
        TunEvent::InternalEgressBackpressured => metrics.tun_internal_egress_backpressured(),
        TunEvent::WintunRingFullDropped => metrics.tun_wintun_ring_full_dropped(),
        TunEvent::TcpFlowsActive(flows) => metrics.set_tun_tcp_flows_active(flows),
        TunEvent::TcpFlowRejectedLimit => metrics.tun_tcp_flow_rejected_limit(),
        TunEvent::TcpFlowResetRestart => metrics.tun_tcp_flow_reset_restart(),
        TunEvent::TcpBridgeBlocked => metrics.tun_tcp_bridge_blocked(),
        TunEvent::UdpAssociationsActive(associations) => {
            metrics.set_tun_udp_associations_active(associations);
        }
        TunEvent::UdpCandidatesActive(candidates) => {
            metrics.set_tun_udp_candidates_active(candidates);
        }
        TunEvent::UdpAssociationCreated => metrics.tun_udp_association_created(),
        TunEvent::UdpAssociationRejectedLimit => metrics.tun_udp_association_rejected_limit(),
        TunEvent::UdpDatagramQueueFull => metrics.tun_udp_datagram_queue_full(),
        TunEvent::UdpResponseQueueFull => metrics.tun_udp_response_queue_full(),
        TunEvent::UdpResponseFiltered => metrics.tun_udp_response_filtered(),
        TunEvent::UdpResponseDropped(reason) => metrics.tun_udp_response_dropped(match reason {
            ferrum2_tun::UdpResponseDropReason::StaleGeneration => {
                TunUdpResponseDropReason::StaleGeneration
            }
            ferrum2_tun::UdpResponseDropReason::AssociationClosed => {
                TunUdpResponseDropReason::AssociationClosed
            }
            ferrum2_tun::UdpResponseDropReason::QueueFull => TunUdpResponseDropReason::QueueFull,
            ferrum2_tun::UdpResponseDropReason::MalformedResponse => {
                TunUdpResponseDropReason::MalformedResponse
            }
            ferrum2_tun::UdpResponseDropReason::Filtered => TunUdpResponseDropReason::Filtered,
            ferrum2_tun::UdpResponseDropReason::InjectionRejected => {
                TunUdpResponseDropReason::InjectionRejected
            }
            ferrum2_tun::UdpResponseDropReason::SessionReset => {
                TunUdpResponseDropReason::SessionReset
            }
            ferrum2_tun::UdpResponseDropReason::Shutdown => TunUdpResponseDropReason::Shutdown,
            ferrum2_tun::UdpResponseDropReason::OwnerFatal => TunUdpResponseDropReason::OwnerFatal,
        }),
        TunEvent::UdpPendingResponses(responses) => {
            metrics.set_tun_pending_udp_responses(responses);
        }
        TunEvent::UdpStaleGeneration => metrics.tun_udp_stale_generation(),
        TunEvent::ReassemblyEntriesActive(entries) => {
            metrics.set_tun_reassembly_entries_active(entries);
        }
        TunEvent::ReassemblyStarted => metrics.tun_reassembly_started(),
        TunEvent::ReassemblyCompleted => metrics.tun_reassembly_completed(),
        TunEvent::ReassemblyDroppedOverlap => metrics.tun_reassembly_dropped_overlap(),
        TunEvent::ReassemblyDroppedTimeout => metrics.tun_reassembly_dropped_timeout(),
        TunEvent::ReassemblyDroppedLimit => metrics.tun_reassembly_dropped_limit(),
        TunEvent::ReassemblyDroppedMalformed => metrics.tun_reassembly_dropped_malformed(),
        TunEvent::NetworkChange => metrics.tun_network_change(),
        TunEvent::UnderlayBindStale => metrics.tun_underlay_bind_stale(),
        TunEvent::Diagnostic { reason, family } => emit_tun_diagnostic(
            Role::Client,
            match reason {
                ferrum2_tun::TunDiagnosticReason::WintunRingFull => {
                    TunDiagnosticReason::WintunRingFull
                }
            },
            match family {
                ferrum2_tun::TunIpFamily::Ipv4 => TunIpFamily::Ipv4,
                ferrum2_tun::TunIpFamily::Ipv6 => TunIpFamily::Ipv6,
            },
        ),
    }
}

pub(super) fn record_network_full_rebuild_event(
    metrics: &Metrics,
    reason: ferrum2_tun::TunNetworkFullRebuildReason,
    result: NetworkLifecycleResult,
    generation: u64,
    tcp_associations: usize,
    udp_associations: usize,
) {
    let reason = map_observability_full_rebuild_reason(reason);
    metrics.network_full_rebuild(reason, result);
    if result == NetworkLifecycleResult::Succeeded {
        metrics.network_associations_reset(
            NetworkLifecycleOperation::FullRebuild,
            Transport::Tcp,
            tcp_associations,
        );
        metrics.network_associations_reset(
            NetworkLifecycleOperation::FullRebuild,
            Transport::Udp,
            udp_associations,
        );
    }
    emit_network_full_rebuild_diagnostic(
        Role::Client,
        reason,
        result,
        generation,
        tcp_associations,
        udp_associations,
    );
}

const fn map_network_reset_reason(
    reason: ferrum2_tun::TunNetworkResetReason,
) -> NetworkResetReason {
    match reason {
        ferrum2_tun::TunNetworkResetReason::NetworkChange => NetworkResetReason::NetworkChange,
        ferrum2_tun::TunNetworkResetReason::Retry => NetworkResetReason::Retry,
    }
}

pub(super) const fn map_runtime_full_rebuild_reason(
    reason: ferrum2_tun::TunNetworkFullRebuildReason,
) -> ManagedNetworkDamage {
    match reason {
        ferrum2_tun::TunNetworkFullRebuildReason::AdapterDamage => {
            ManagedNetworkDamage::AdapterInvalid
        }
        ferrum2_tun::TunNetworkFullRebuildReason::SessionDamage => {
            ManagedNetworkDamage::DeviceSessionFatal
        }
        ferrum2_tun::TunNetworkFullRebuildReason::AddressDamage => {
            ManagedNetworkDamage::ManagedAddressDamaged
        }
        ferrum2_tun::TunNetworkFullRebuildReason::RouteDamage => {
            ManagedNetworkDamage::ManagedRouteDamaged
        }
        ferrum2_tun::TunNetworkFullRebuildReason::DnsDamage => {
            ManagedNetworkDamage::ManagedDnsDamaged
        }
        ferrum2_tun::TunNetworkFullRebuildReason::StrictRouteDamage => {
            ManagedNetworkDamage::StrictRouteDamaged
        }
        ferrum2_tun::TunNetworkFullRebuildReason::OwnershipLedgerDamage => {
            ManagedNetworkDamage::OwnershipLedgerUntrusted
        }
    }
}

const fn map_observability_full_rebuild_reason(
    reason: ferrum2_tun::TunNetworkFullRebuildReason,
) -> NetworkFullRebuildReason {
    match reason {
        ferrum2_tun::TunNetworkFullRebuildReason::AdapterDamage => {
            NetworkFullRebuildReason::AdapterDamage
        }
        ferrum2_tun::TunNetworkFullRebuildReason::SessionDamage => {
            NetworkFullRebuildReason::SessionDamage
        }
        ferrum2_tun::TunNetworkFullRebuildReason::AddressDamage => {
            NetworkFullRebuildReason::AddressDamage
        }
        ferrum2_tun::TunNetworkFullRebuildReason::RouteDamage => {
            NetworkFullRebuildReason::RouteDamage
        }
        ferrum2_tun::TunNetworkFullRebuildReason::DnsDamage => NetworkFullRebuildReason::DnsDamage,
        ferrum2_tun::TunNetworkFullRebuildReason::StrictRouteDamage => {
            NetworkFullRebuildReason::StrictRouteDamage
        }
        ferrum2_tun::TunNetworkFullRebuildReason::OwnershipLedgerDamage => {
            NetworkFullRebuildReason::OwnershipLedgerDamage
        }
    }
}
