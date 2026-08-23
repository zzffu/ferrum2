use std::collections::BTreeSet;

use ferrum2_observability::{
    InterfaceResolutionResult, InterfaceResolutionSource, Metrics, NetworkFullRebuildReason,
    NetworkLifecycleOperation, NetworkLifecycleResult, NetworkResetReason,
    StrictRouteFilterInstallResult, Transport, TunUdpAssociationRouteResult,
};

const LIFECYCLE_RESULTS: &[(NetworkLifecycleResult, &str)] = &[
    (NetworkLifecycleResult::Started, "started"),
    (NetworkLifecycleResult::Succeeded, "succeeded"),
    (NetworkLifecycleResult::Failed, "failed"),
];
const RESET_REASONS: &[(NetworkResetReason, &str)] = &[
    (NetworkResetReason::NetworkChange, "network_change"),
    (NetworkResetReason::Retry, "retry"),
];
const REBUILD_REASONS: &[(NetworkFullRebuildReason, &str)] = &[
    (NetworkFullRebuildReason::AdapterDamage, "adapter_damage"),
    (NetworkFullRebuildReason::SessionDamage, "session_damage"),
    (NetworkFullRebuildReason::AddressDamage, "address_damage"),
    (NetworkFullRebuildReason::RouteDamage, "route_damage"),
    (NetworkFullRebuildReason::DnsDamage, "dns_damage"),
    (
        NetworkFullRebuildReason::StrictRouteDamage,
        "strict_route_damage",
    ),
    (
        NetworkFullRebuildReason::OwnershipLedgerDamage,
        "ownership_ledger_damage",
    ),
];
const OPERATIONS: &[(NetworkLifecycleOperation, &str)] = &[
    (NetworkLifecycleOperation::ResetNetwork, "reset_network"),
    (NetworkLifecycleOperation::FullRebuild, "full_rebuild"),
];
const TRANSPORTS: &[(Transport, &str)] = &[(Transport::Tcp, "tcp"), (Transport::Udp, "udp")];
const INTERFACE_SOURCES: &[(InterfaceResolutionSource, &str)] = &[
    (
        InterfaceResolutionSource::OutboundExplicit,
        "outbound_explicit",
    ),
    (InterfaceResolutionSource::AutoDetected, "auto_detected"),
    (InterfaceResolutionSource::RouteDefault, "route_default"),
    (
        InterfaceResolutionSource::SystemBestRoute,
        "system_best_route",
    ),
];
const INTERFACE_RESULTS: &[(InterfaceResolutionResult, &str)] = &[
    (InterfaceResolutionResult::Success, "success"),
    (InterfaceResolutionResult::Failure, "failure"),
];
const ROUTE_RESULTS: &[(TunUdpAssociationRouteResult, &str)] = &[
    (TunUdpAssociationRouteResult::Success, "success"),
    (TunUdpAssociationRouteResult::Rejected, "rejected"),
    (TunUdpAssociationRouteResult::Failure, "failure"),
    (
        TunUdpAssociationRouteResult::StaleGeneration,
        "stale_generation",
    ),
];

fn samples(output: &str, prefix: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter(|line| line.starts_with(prefix))
        .map(|line| {
            line.rsplit_once(' ')
                .expect("sample and value")
                .0
                .to_owned()
        })
        .collect()
}

fn is_network_contract_family(line: &str) -> bool {
    line.starts_with("ferrum2_network_")
        || line.starts_with("ferrum2_tun_strict_route_")
        || line.starts_with("ferrum2_outbound_interface_resolution")
        || line.starts_with("ferrum2_tun_udp_association_route")
}

#[test]
fn network_lifecycle_families_have_exact_closed_low_cardinality_series() {
    let metrics = Metrics::new();
    for (reason, _) in RESET_REASONS {
        for (result, _) in LIFECYCLE_RESULTS {
            metrics.network_reset(*reason, *result);
        }
    }
    for (reason, _) in REBUILD_REASONS {
        for (result, _) in LIFECYCLE_RESULTS {
            metrics.network_full_rebuild(*reason, *result);
        }
    }
    for (operation, _) in OPERATIONS {
        for (transport, _) in TRANSPORTS {
            metrics.network_associations_reset(*operation, *transport, 3);
        }
    }
    metrics.set_network_generation(41);

    let output = metrics.encode_text().expect("network lifecycle metrics");
    let resets = samples(&output, "ferrum2_network_reset_total{");
    assert_eq!(resets.len(), RESET_REASONS.len() * LIFECYCLE_RESULTS.len());
    for (reason, encoded_reason) in RESET_REASONS {
        assert_eq!(reason.to_string(), *encoded_reason);
        for (result, encoded_result) in LIFECYCLE_RESULTS {
            assert_eq!(result.to_string(), *encoded_result);
            assert!(resets.contains(&format!(
                "ferrum2_network_reset_total{{reason=\"{encoded_reason}\",result=\"{encoded_result}\"}}"
            )));
        }
    }

    let rebuilds = samples(&output, "ferrum2_network_full_rebuild_total{");
    assert_eq!(
        rebuilds.len(),
        REBUILD_REASONS.len() * LIFECYCLE_RESULTS.len()
    );
    for (reason, encoded_reason) in REBUILD_REASONS {
        assert_eq!(reason.to_string(), *encoded_reason);
        for (_, encoded_result) in LIFECYCLE_RESULTS {
            assert!(rebuilds.contains(&format!(
                "ferrum2_network_full_rebuild_total{{reason=\"{encoded_reason}\",result=\"{encoded_result}\"}}"
            )));
        }
    }

    let reset_associations = samples(&output, "ferrum2_network_associations_reset_total{");
    assert_eq!(
        reset_associations.len(),
        OPERATIONS.len() * TRANSPORTS.len()
    );
    for (operation, encoded_operation) in OPERATIONS {
        assert_eq!(operation.to_string(), *encoded_operation);
        for (_, encoded_transport) in TRANSPORTS {
            assert!(reset_associations.contains(&format!(
                "ferrum2_network_associations_reset_total{{operation=\"{encoded_operation}\",transport=\"{encoded_transport}\"}}"
            )));
        }
    }

    assert!(output.contains("ferrum2_network_generation 41"));
    for line in output
        .lines()
        .filter(|line| line.starts_with("ferrum2_network_associations_reset_total{"))
    {
        assert!(line.ends_with(" 3"));
    }
}

#[test]
fn strict_route_interface_and_route_once_metrics_are_closed() {
    let metrics = Metrics::new();
    metrics.set_tun_strict_route_requested(true);
    metrics.set_tun_strict_route_effective(false);
    for result in [
        StrictRouteFilterInstallResult::Success,
        StrictRouteFilterInstallResult::Failure,
    ] {
        metrics.tun_strict_route_filter_install(result);
    }
    for (source, _) in INTERFACE_SOURCES {
        for (result, _) in INTERFACE_RESULTS {
            metrics.outbound_interface_resolution(*source, *result);
        }
    }
    metrics.outbound_interface_resolution_cache_hit();
    for (result, _) in ROUTE_RESULTS {
        metrics.tun_udp_association_route(*result);
    }

    let output = metrics.encode_text().expect("network policy metrics");
    for expected in [
        "ferrum2_tun_strict_route_requested 1",
        "ferrum2_tun_strict_route_effective 0",
        "ferrum2_tun_strict_route_filter_install_total{result=\"success\"} 1",
        "ferrum2_tun_strict_route_filter_install_total{result=\"failure\"} 1",
        "ferrum2_outbound_interface_resolution_cache_hit_total 1",
    ] {
        assert!(output.contains(expected), "missing `{expected}`\n{output}");
    }

    let resolutions = samples(&output, "ferrum2_outbound_interface_resolution_total{");
    assert_eq!(
        resolutions.len(),
        INTERFACE_SOURCES.len() * INTERFACE_RESULTS.len()
    );
    for (source, encoded_source) in INTERFACE_SOURCES {
        assert_eq!(source.to_string(), *encoded_source);
        for (result, encoded_result) in INTERFACE_RESULTS {
            assert_eq!(result.to_string(), *encoded_result);
            assert!(resolutions.contains(&format!(
                "ferrum2_outbound_interface_resolution_total{{source=\"{encoded_source}\",result=\"{encoded_result}\"}}"
            )));
        }
    }

    let routes = samples(&output, "ferrum2_tun_udp_association_route_total{");
    assert_eq!(routes.len(), ROUTE_RESULTS.len());
    for (result, encoded_result) in ROUTE_RESULTS {
        assert_eq!(result.to_string(), *encoded_result);
        assert!(routes.contains(&format!(
            "ferrum2_tun_udp_association_route_total{{result=\"{encoded_result}\"}}"
        )));
    }
}

#[test]
fn network_metric_contract_exposes_no_identity_or_external_conflict_surface() {
    let metrics = Metrics::new();
    metrics.network_reset(
        NetworkResetReason::NetworkChange,
        NetworkLifecycleResult::Started,
    );
    metrics.network_full_rebuild(
        NetworkFullRebuildReason::StrictRouteDamage,
        NetworkLifecycleResult::Failed,
    );
    metrics.outbound_interface_resolution(
        InterfaceResolutionSource::OutboundExplicit,
        InterfaceResolutionResult::Failure,
    );
    let output = metrics.encode_text().expect("redacted network metrics");

    for forbidden_label in [
        "interface=",
        "interface_name=",
        "destination=",
        "address=",
        "adapter=",
        "prefix=",
        "filter_id=",
    ] {
        assert!(!output.contains(forbidden_label));
    }
    for sentinel in [
        "ETHERNET_IDENTITY_SENTINEL",
        "192.0.2.99:443",
        "10.0.0.0/8",
        "WFP_FILTER_ID_SENTINEL",
        "C:\\private\\ferrum2.exe",
    ] {
        assert!(!output.contains(sentinel));
    }
    for forbidden_family in [
        "route_conflict",
        "route_detect",
        "external_route",
        "more_specific_route",
        "equal_prefix_preferred",
    ] {
        assert!(!output.contains(forbidden_family));
    }
}

#[test]
fn network_family_names_types_and_help_are_an_exact_contract() {
    let metrics = Metrics::new();
    metrics.network_reset(
        NetworkResetReason::NetworkChange,
        NetworkLifecycleResult::Started,
    );
    metrics.network_full_rebuild(
        NetworkFullRebuildReason::AdapterDamage,
        NetworkLifecycleResult::Started,
    );
    metrics.network_associations_reset(NetworkLifecycleOperation::ResetNetwork, Transport::Tcp, 0);
    metrics.tun_strict_route_filter_install(StrictRouteFilterInstallResult::Success);
    metrics.outbound_interface_resolution(
        InterfaceResolutionSource::AutoDetected,
        InterfaceResolutionResult::Success,
    );
    metrics.tun_udp_association_route(TunUdpAssociationRouteResult::Success);

    let output = metrics.encode_text().expect("network metric metadata");
    let help = output
        .lines()
        .filter_map(|line| line.strip_prefix("# HELP "))
        .filter(|line| is_network_contract_family(line))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        help,
        BTreeSet::from([
            "ferrum2_network_associations_reset TCP and UDP associations closed by a network lifecycle operation.",
            "ferrum2_network_full_rebuild Managed network-plane full rebuild attempts by closed damage reason and result.",
            "ferrum2_network_generation Current fully published network runtime generation.",
            "ferrum2_network_reset Lightweight ResetNetwork attempts by closed initiating reason and result.",
            "ferrum2_outbound_interface_resolution Outbound interface resolutions by closed selection source and result.",
            "ferrum2_outbound_interface_resolution_cache_hit Outbound interface resolver cache hits.",
            "ferrum2_tun_strict_route_effective Whether strict route is effective under the auto-route gate.",
            "ferrum2_tun_strict_route_filter_install Windows strict-route filter installation outcomes.",
            "ferrum2_tun_strict_route_requested Whether strict route was requested by validated configuration.",
            "ferrum2_tun_udp_association_route Single route evaluations for TUN UDP associations by closed result.",
        ])
    );

    let types = output
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter(|line| is_network_contract_family(line))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        types,
        BTreeSet::from([
            "ferrum2_network_associations_reset counter",
            "ferrum2_network_full_rebuild counter",
            "ferrum2_network_generation gauge",
            "ferrum2_network_reset counter",
            "ferrum2_outbound_interface_resolution counter",
            "ferrum2_outbound_interface_resolution_cache_hit counter",
            "ferrum2_tun_strict_route_effective gauge",
            "ferrum2_tun_strict_route_filter_install counter",
            "ferrum2_tun_strict_route_requested gauge",
            "ferrum2_tun_udp_association_route counter",
        ])
    );
}
