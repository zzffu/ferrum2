use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use ferrum2_net::*;

#[derive(Default)]
struct Catalog {
    interfaces: Vec<NetworkInterfaceObservation>,
    system: Option<SystemBestRoute>,
    system_destinations: Mutex<Vec<SocketAddr>>,
}

impl NetworkInterfaceCatalog for Catalog {
    fn read_routes(
        &self,
    ) -> Result<Vec<ferrum2_net::NetworkRouteObservation>, ferrum2_net::NetworkInterfaceCatalogError>
    {
        Ok(Vec::new())
    }
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        Ok(self.interfaces.clone())
    }

    fn system_best_route(
        &self,
        destination: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        self.system_destinations.lock().unwrap().push(destination);
        self.system.ok_or(NetworkInterfaceCatalogError)
    }
}

fn binding(name: &str, id: u64, index: u32, addresses: &[IpAddr]) -> InterfaceBinding {
    InterfaceBinding::new(name, id, index, Arc::<[IpAddr]>::from(addresses)).unwrap()
}

fn v4(name: &str, id: u64, index: u32, octet: u8) -> InterfaceBinding {
    binding(
        name,
        id,
        index,
        &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet))],
    )
}

fn v6(name: &str, id: u64, index: u32, suffix: u16) -> InterfaceBinding {
    binding(
        name,
        id,
        index,
        &[IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, suffix,
        ))],
    )
}

fn observation(
    binding: InterfaceBinding,
    family: NetworkFamily,
    operational: InterfaceOperationalState,
    connected: InterfaceLinkState,
    kind: NetworkInterfaceKind,
    interface_metric: u32,
    default_route_metric: Option<u32>,
) -> NetworkInterfaceObservation {
    NetworkInterfaceObservation::new(
        binding,
        family,
        operational,
        connected,
        kind,
        interface_metric,
        default_route_metric,
    )
    .unwrap()
}

fn available(binding: InterfaceBinding, family: NetworkFamily) -> NetworkInterfaceObservation {
    observation(
        binding,
        family,
        InterfaceOperationalState::Operational,
        InterfaceLinkState::Connected,
        NetworkInterfaceKind::Underlay,
        10,
        None,
    )
}

#[test]
fn four_tier_priority_is_exact_and_system_fallback_is_target_aware() {
    let explicit = v4("explicit", 1, 11, 11);
    let automatic = v4("automatic", 2, 12, 12);
    let route_default = v4("route-default", 3, 13, 13);
    let system = v4("system", 4, 14, 14);
    let interfaces = vec![
        available(explicit.clone(), NetworkFamily::Ipv4),
        observation(
            automatic.clone(),
            NetworkFamily::Ipv4,
            InterfaceOperationalState::Operational,
            InterfaceLinkState::Connected,
            NetworkInterfaceKind::Underlay,
            5,
            Some(5),
        ),
        available(route_default.clone(), NetworkFamily::Ipv4),
        available(system.clone(), NetworkFamily::Ipv4),
    ];
    let catalog = Catalog {
        interfaces: interfaces.clone(),
        system: Some(SystemBestRoute::new(system.stable_id(), system.index()).unwrap()),
        system_destinations: Mutex::default(),
    };
    let snapshot = NetworkSnapshot::capture(7, &catalog).unwrap();
    let no_auto = NetworkSnapshot::from_interfaces(
        8,
        [
            explicit.clone(),
            automatic.clone(),
            route_default.clone(),
            system.clone(),
        ]
        .map(|binding| {
            observation(
                binding,
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                0,
                None,
            )
        })
        .into(),
    )
    .unwrap();
    let resolver = NetworkInterfaceResolver::new(catalog);
    let target = SocketAddr::from(([203, 0, 113, 9], 443));

    let selected = resolver
        .resolve(
            &DialOptions::new(Some("explicit"), None, None),
            &RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                Some("route-default"),
            ),
            target,
            &snapshot,
        )
        .unwrap();
    assert_eq!(selected.binding(), &explicit);
    assert_eq!(
        selected.selection_source(),
        InterfaceSelectionSource::OutboundExplicit
    );

    let selected = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                Some("route-default"),
            ),
            target,
            &snapshot,
        )
        .unwrap();
    assert_eq!(selected.binding(), &automatic);
    assert_eq!(
        selected.selection_source(),
        InterfaceSelectionSource::AutoDetected
    );

    let selected = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                Some("route-default"),
            ),
            target,
            &no_auto,
        )
        .unwrap();
    assert_eq!(selected.binding(), &route_default);
    assert_eq!(
        selected.selection_source(),
        InterfaceSelectionSource::RouteDefault
    );

    let selected = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Disabled,
                Some("missing"),
            ),
            target,
            &no_auto,
        )
        .unwrap();
    assert_eq!(selected.binding(), &system);
    assert_eq!(
        selected.selection_source(),
        InterfaceSelectionSource::SystemBestRoute
    );
    assert_eq!(
        resolver
            .catalog()
            .system_destinations
            .lock()
            .unwrap()
            .as_slice(),
        [target]
    );
}

#[test]
fn explicit_lookup_failure_never_falls_back() {
    for (interfaces, expected) in [
        (
            vec![],
            InterfaceResolutionErrorKind::ExplicitInterfaceMissing,
        ),
        (
            vec![
                available(v4("explicit", 1, 11, 11), NetworkFamily::Ipv4),
                available(v4("explicit", 2, 12, 12), NetworkFamily::Ipv4),
            ],
            InterfaceResolutionErrorKind::ExplicitInterfaceAmbiguous,
        ),
        (
            vec![observation(
                v4("explicit", 1, 11, 11),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Unavailable,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                1,
                None,
            )],
            InterfaceResolutionErrorKind::ExplicitInterfaceUnavailable,
        ),
        (
            vec![available(v6("explicit", 1, 11, 11), NetworkFamily::Ipv6)],
            InterfaceResolutionErrorKind::ExplicitInterfaceWrongFamily,
        ),
    ] {
        let resolver = NetworkInterfaceResolver::new(Catalog {
            interfaces: interfaces.clone(),
            system: Some(SystemBestRoute::new(4, 14).unwrap()),
            system_destinations: Mutex::default(),
        });
        let error = resolver
            .resolve(
                &DialOptions::new(Some("explicit"), None, None),
                &RouteNetworkOptions::new(
                    ferrum2_net::AutomaticInterfaceSelection::Enabled,
                    Some("fallback"),
                ),
                SocketAddr::from(([203, 0, 113, 9], 443)),
                &NetworkSnapshot::from_interfaces(1, interfaces).unwrap(),
            )
            .unwrap_err();
        assert_eq!(error.kind(), expected);
        assert_eq!(
            error.attempted_source(),
            InterfaceSelectionSource::OutboundExplicit
        );
        assert!(
            resolver
                .catalog()
                .system_destinations
                .lock()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn family_defaults_and_source_addresses_are_independent() {
    let ipv4 = v4("v4", 4, 14, 14);
    let ipv6 = v6("v6", 6, 16, 16);
    let snapshot = NetworkSnapshot::new(22, Some(ipv4.clone()), Some(ipv6.clone())).unwrap();
    let resolver = NetworkInterfaceResolver::new(Catalog::default());
    let options = DialOptions::new(
        None::<&str>,
        Some(Ipv4Addr::new(192, 0, 2, 14)),
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 16)),
    );

    let selected_v4 = resolver
        .resolve(
            &options,
            &RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                None::<&str>,
            ),
            SocketAddr::from(([203, 0, 113, 9], 443)),
            &snapshot,
        )
        .unwrap();
    assert_eq!(selected_v4.binding(), &ipv4);
    assert_eq!(
        selected_v4.source_address(),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14)))
    );
    assert_eq!(selected_v4.snapshot_generation(), 22);

    let selected_v6 = resolver
        .resolve(
            &options,
            &RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                None::<&str>,
            ),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 9)),
                443,
            ),
            &snapshot,
        )
        .unwrap();
    assert_eq!(selected_v6.binding(), &ipv6);
    assert_eq!(
        selected_v6.source_address(),
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 16)))
    );
}

#[test]
fn mismatched_source_retains_each_selected_tier_and_family_is_rejected() {
    assert_eq!(
        NetworkSnapshot::new(1, Some(v6("wrong", 1, 1, 1)), None).unwrap_err(),
        NetworkSnapshotError
    );

    let snapshot = NetworkSnapshot::new(1, Some(v4("v4", 1, 1, 1)), None).unwrap();
    let resolver = NetworkInterfaceResolver::new(Catalog {
        interfaces: Vec::new(),
        system: Some(SystemBestRoute::new(1, 1).unwrap()),
        system_destinations: Mutex::default(),
    });
    let source = Some(Ipv4Addr::new(192, 0, 2, 99));
    for (outbound, route, expected_source) in [
        (
            DialOptions::new(Some("v4"), source, None),
            RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                None::<&str>,
            ),
            InterfaceSelectionSource::OutboundExplicit,
        ),
        (
            DialOptions::new(None::<&str>, source, None),
            RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Enabled,
                None::<&str>,
            ),
            InterfaceSelectionSource::AutoDetected,
        ),
        (
            DialOptions::new(None::<&str>, source, None),
            RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Disabled,
                Some("v4"),
            ),
            InterfaceSelectionSource::RouteDefault,
        ),
        (
            DialOptions::new(None::<&str>, source, None),
            RouteNetworkOptions::new(
                ferrum2_net::AutomaticInterfaceSelection::Disabled,
                None::<&str>,
            ),
            InterfaceSelectionSource::SystemBestRoute,
        ),
    ] {
        let error = resolver
            .resolve(
                &outbound,
                &route,
                SocketAddr::from(([203, 0, 113, 9], 443)),
                &snapshot,
            )
            .unwrap_err();
        assert_eq!(
            error.kind(),
            InterfaceResolutionErrorKind::SourceAddressUnavailable
        );
        assert_eq!(error.attempted_source(), expected_source);
    }
}

#[test]
fn automatic_defaults_are_family_aware_filtered_and_metric_ranked() {
    let ipv4_winner = v4("v4-winner", 20, 20, 20);
    let ipv6_winner = v6("v6-winner", 60, 60, 60);
    let catalog = Catalog {
        interfaces: vec![
            observation(
                v4("managed-tun", 1, 1, 1),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::ManagedTun,
                1,
                Some(1),
            ),
            observation(
                v4("loopback", 2, 2, 2),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Loopback,
                1,
                Some(1),
            ),
            observation(
                v4("down", 3, 3, 3),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Unavailable,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                1,
                Some(1),
            ),
            observation(
                v4("disconnected", 4, 4, 4),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Disconnected,
                NetworkInterfaceKind::Underlay,
                1,
                Some(1),
            ),
            observation(
                v4("no-default-route", 5, 5, 5),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                1,
                None,
            ),
            observation(
                ipv4_winner.clone(),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                4,
                Some(6),
            ),
            observation(
                v4("v4-tied-later", 30, 30, 30),
                NetworkFamily::Ipv4,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                5,
                Some(5),
            ),
            observation(
                ipv6_winner.clone(),
                NetworkFamily::Ipv6,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                2,
                Some(3),
            ),
            observation(
                v6("v6-higher-metric", 61, 61, 61),
                NetworkFamily::Ipv6,
                InterfaceOperationalState::Operational,
                InterfaceLinkState::Connected,
                NetworkInterfaceKind::Underlay,
                3,
                Some(3),
            ),
        ],
        system: None,
        system_destinations: Mutex::default(),
    };

    let snapshot = NetworkSnapshot::capture(41, &catalog).unwrap();
    assert_eq!(
        snapshot.auto_interface(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Some(&ipv4_winner)
    );
    assert_eq!(
        snapshot.auto_interface(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        Some(&ipv6_winner)
    );
    assert_eq!(snapshot.interfaces().len(), 9);
}

#[test]
fn system_route_identity_must_exist_in_the_same_family_snapshot() {
    let only_ipv4 = v4("system", 7, 17, 7);
    let snapshot =
        NetworkSnapshot::from_interfaces(4, vec![available(only_ipv4, NetworkFamily::Ipv4)])
            .unwrap();
    let resolver = NetworkInterfaceResolver::new(Catalog {
        interfaces: vec![],
        system: Some(SystemBestRoute::new(7, 17).unwrap()),
        system_destinations: Mutex::default(),
    });

    let error = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            &snapshot,
        )
        .unwrap_err();
    assert_eq!(
        error.kind(),
        InterfaceResolutionErrorKind::SystemBestRouteUnavailable
    );
    assert_eq!(
        error.attempted_source(),
        InterfaceSelectionSource::SystemBestRoute
    );
}

#[test]
fn semantic_observation_tracks_existing_family_routes_sources_and_both_defaults() {
    let base_row = observation(
        v6("underlay", 1, 1, 1),
        NetworkFamily::Ipv6,
        InterfaceOperationalState::Operational,
        InterfaceLinkState::Connected,
        NetworkInterfaceKind::Underlay,
        10,
        Some(10),
    );
    let route = |metric, next_hop| {
        NetworkRouteObservation::new(1, 1, "2001:db8::99".parse().unwrap(), 128, next_hop, metric)
    };
    let hop = "2001:db8::fe".parse().unwrap();
    let orphan = NetworkRouteObservation::new(
        2,
        2,
        "224.0.0.0".parse().unwrap(),
        4,
        "0.0.0.0".parse().unwrap(),
        256,
    );
    let initial = NetworkSnapshot::from_interfaces_and_routes(
        1,
        vec![base_row.clone()],
        vec![route(10, hop), orphan.clone()],
    )
    .unwrap();
    let added = available(
        binding("unrelated", 2, 2, &["10.20.30.40".parse().unwrap()]),
        NetworkFamily::Ipv4,
    );
    let additive = NetworkSnapshot::from_interfaces_and_routes(
        1,
        vec![base_row.clone(), added.clone()],
        vec![
            route(10, hop),
            orphan.clone(),
            NetworkRouteObservation::new(
                2,
                2,
                "10.20.0.0".parse().unwrap(),
                16,
                "0.0.0.0".parse().unwrap(),
                256,
            ),
        ],
    )
    .unwrap();
    assert!(additive.preserves_work_from(&initial));
    assert!(matches!(
        additive.resolve_named("unrelated", NetworkFamily::Ipv4),
        NamedInterfaceResolution::Available(_)
    ));
    for changed_route in [route(11, hop), route(10, "2001:db8::fd".parse().unwrap())] {
        let changed = NetworkSnapshot::from_interfaces_and_routes(
            2,
            vec![base_row.clone()],
            vec![changed_route, orphan.clone()],
        )
        .unwrap();
        assert!(!changed.preserves_work_from(&initial));
    }
    let changed_source = observation(
        v6("underlay", 1, 1, 2),
        NetworkFamily::Ipv6,
        InterfaceOperationalState::Operational,
        InterfaceLinkState::Connected,
        NetworkInterfaceKind::Underlay,
        10,
        Some(10),
    );
    let changed = NetworkSnapshot::from_interfaces_and_routes(
        2,
        vec![changed_source],
        vec![route(10, hop), orphan.clone()],
    )
    .unwrap();
    assert!(!changed.preserves_work_from(&initial));
    let ipv4_default = observation(
        added.binding().clone(),
        NetworkFamily::Ipv4,
        InterfaceOperationalState::Operational,
        InterfaceLinkState::Connected,
        NetworkInterfaceKind::Underlay,
        10,
        Some(10),
    );
    let changed = NetworkSnapshot::from_interfaces_and_routes(
        2,
        vec![base_row.clone(), ipv4_default],
        vec![route(10, hop), orphan.clone()],
    )
    .unwrap();
    assert!(!changed.preserves_work_from(&initial));
    let orphan_changed = NetworkSnapshot::from_interfaces_and_routes(
        2,
        vec![base_row.clone()],
        vec![
            route(10, hop),
            NetworkRouteObservation::new(
                2,
                2,
                orphan.destination(),
                orphan.prefix_length(),
                orphan.next_hop(),
                257,
            ),
        ],
    )
    .unwrap();
    assert!(!orphan_changed.preserves_work_from(&initial));
    let missing_routes = NetworkSnapshot::from_interfaces(2, vec![base_row]).unwrap();
    assert!(!missing_routes.preserves_work_from(&initial));
}

#[test]
fn route_query_failure_cannot_produce_an_unchanged_snapshot() {
    struct FailedRoutes;
    impl NetworkInterfaceCatalog for FailedRoutes {
        fn read_interfaces(
            &self,
        ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
            Ok(Vec::new())
        }
        fn read_routes(
            &self,
        ) -> Result<Vec<NetworkRouteObservation>, NetworkInterfaceCatalogError> {
            Err(NetworkInterfaceCatalogError)
        }
        fn system_best_route(
            &self,
            _: SocketAddr,
        ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
            Err(NetworkInterfaceCatalogError)
        }
    }
    assert_eq!(
        NetworkSnapshot::capture(1, &FailedRoutes),
        Err(NetworkSnapshotCaptureError::CatalogUnavailable)
    );
}
