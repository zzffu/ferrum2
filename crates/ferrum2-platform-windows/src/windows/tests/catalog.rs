use super::support::{
    CatalogFamilyRow, CatalogInterfaceRow, DefaultRouteCandidate, DialOptions, Error, ErrorKind,
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, InterfaceBinding, InterfaceCandidate,
    InterfaceIdentity, NetworkFamily, NetworkInterfaceCatalog, NetworkInterfaceCatalogError,
    NetworkInterfaceKind, NetworkInterfaceObservation, NetworkInterfaceResolver, NetworkSnapshot,
    ResolvedSocketBindingOperations, RouteNetworkOptions, SystemBestRoute,
    WindowsNetworkInterfaceCatalog, bind_resolved_socket_with,
    build_network_interface_observations, catalog_default_route, fallback_interface_identity,
    interface_socket_option, ipv4_interface_index_option_value, ipv6_interface_index_option_value,
    sockaddr_port, sockaddr_scope_id, socket_addr_sockaddr,
};

#[test]
fn underlay_interface_options_use_family_specific_byte_order() {
    let index = 0x0102_0304;
    assert_eq!(
        ipv4_interface_index_option_value(index).to_ne_bytes(),
        [1, 2, 3, 4]
    );
    assert_ne!(ipv4_interface_index_option_value(index), index);
    assert_eq!(ipv6_interface_index_option_value(index), index);
    assert_eq!(
        interface_socket_option("192.0.2.1".parse().unwrap(), index),
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    );
    assert_eq!(
        interface_socket_option("2001:db8::1".parse().unwrap(), index),
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    );

    let ipv4 = socket_addr_sockaddr("192.0.2.1:443".parse().unwrap());
    assert_eq!(sockaddr_port(&ipv4).unwrap(), 443);
    let ipv6 = socket_addr_sockaddr("[fe80::1%19]:853".parse().unwrap());
    assert_eq!(sockaddr_port(&ipv6).unwrap(), 853);
    assert_eq!(sockaddr_scope_id(&ipv6).unwrap(), 19);
}

#[test]
fn windows_catalog_is_family_aware_and_marks_the_exact_managed_tun() {
    let physical_v4 = InterfaceIdentity {
        luid: 10,
        index: 20,
    };
    let physical_v6 = InterfaceIdentity {
        luid: 11,
        index: 21,
    };
    let managed = InterfaceIdentity {
        luid: 12,
        index: 22,
    };
    let unavailable = InterfaceIdentity {
        luid: 13,
        index: 23,
    };
    let interfaces = vec![
        CatalogInterfaceRow {
            identity: physical_v4,
            name: "physical-v4".into(),
            operational: true,
            connected: true,
            kind: NetworkInterfaceKind::Underlay,
        },
        CatalogInterfaceRow {
            identity: physical_v6,
            name: "physical-v6".into(),
            operational: true,
            connected: true,
            kind: NetworkInterfaceKind::Underlay,
        },
        CatalogInterfaceRow {
            identity: managed,
            name: "managed-tun-sentinel".into(),
            operational: true,
            connected: true,
            kind: NetworkInterfaceKind::Underlay,
        },
        CatalogInterfaceRow {
            identity: unavailable,
            name: "down".into(),
            operational: false,
            connected: true,
            kind: NetworkInterfaceKind::Underlay,
        },
    ];
    let families = vec![
        CatalogFamilyRow {
            identity: physical_v4,
            family: NetworkFamily::Ipv4,
            addresses: vec!["192.0.2.10".parse().unwrap()],
            connected: true,
            interface_metric: 20,
            default_route_metric: Some(10),
        },
        CatalogFamilyRow {
            identity: physical_v6,
            family: NetworkFamily::Ipv6,
            addresses: vec!["2001:db8::10".parse().unwrap()],
            connected: true,
            interface_metric: 30,
            default_route_metric: Some(5),
        },
        CatalogFamilyRow {
            identity: managed,
            family: NetworkFamily::Ipv4,
            addresses: vec!["198.18.0.2".parse().unwrap()],
            connected: true,
            interface_metric: 0,
            default_route_metric: Some(0),
        },
        CatalogFamilyRow {
            identity: unavailable,
            family: NetworkFamily::Ipv4,
            addresses: vec!["192.0.2.23".parse().unwrap()],
            connected: true,
            interface_metric: 0,
            default_route_metric: Some(0),
        },
    ];

    let observations =
        build_network_interface_observations(&interfaces, &families, Some(managed)).unwrap();
    assert_eq!(observations.len(), 4);
    assert_eq!(
        observations
            .iter()
            .find(|row| row.binding().stable_id() == managed.luid)
            .unwrap()
            .kind(),
        NetworkInterfaceKind::ManagedTun
    );
    let snapshot = NetworkSnapshot::from_interfaces(41, observations).unwrap();
    assert_eq!(
        snapshot
            .auto_interface("0.0.0.0".parse().unwrap())
            .unwrap()
            .stable_id(),
        physical_v4.luid
    );
    assert_eq!(
        snapshot
            .auto_interface("::".parse().unwrap())
            .unwrap()
            .stable_id(),
        physical_v6.luid
    );

    let catalog =
        WindowsNetworkInterfaceCatalog::excluding_managed_tun(managed.luid, managed.index).unwrap();
    let debug = format!("{catalog:?}");
    assert!(debug.contains("managed_tun: true"));
    assert!(!debug.contains(&managed.luid.to_string()));
    assert!(!debug.contains(&managed.index.to_string()));
    assert!(WindowsNetworkInterfaceCatalog::excluding_managed_tun(0, 1).is_err());
    let shared_catalog = catalog.clone();
    catalog.clear_managed_tun(managed).unwrap();
    assert_eq!(shared_catalog.managed_tun().unwrap(), None);
    shared_catalog.set_managed_tun(managed).unwrap();
    assert_eq!(catalog.managed_tun().unwrap(), Some(managed));

    let virtual_identity = InterfaceIdentity {
        luid: 91,
        index: 92,
    };
    let virtual_underlay = InterfaceCandidate {
        identity: virtual_identity,
        loopback: false,
        operational: true,
        admin_enabled: true,
        connected: true,
        hardware_interface: false,
    };
    assert_eq!(
        fallback_interface_identity(virtual_underlay, None),
        Some(virtual_identity),
        "target-aware fallback may use a connected virtual underlay"
    );
    assert_eq!(
        fallback_interface_identity(virtual_underlay, Some(virtual_identity)),
        None,
        "the exact managed TUN is never a fallback"
    );
}

#[test]
fn catalog_default_route_requires_an_unspecified_zero_prefix() {
    let identity = InterfaceIdentity {
        luid: 44,
        index: 54,
    };
    let mut row = DefaultRouteCandidate {
        identity,
        destination: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        prefix_length: 0,
        metric: 17,
    };
    let route = catalog_default_route(row).unwrap();
    assert_eq!(route.identity, identity);
    assert_eq!(route.family, NetworkFamily::Ipv4);
    assert_eq!(route.metric, 17);

    row.prefix_length = 1;
    assert!(catalog_default_route(row).is_none());
    row.prefix_length = 0;
    row.destination = "192.0.2.0".parse().unwrap();
    assert!(catalog_default_route(row).is_none());
}

#[derive(Debug, Eq, PartialEq)]
enum ResolvedBindCall {
    Interface(std::net::IpAddr, u32),
    Source(std::net::SocketAddr),
}

#[derive(Default)]
struct InjectedResolvedBinder {
    calls: Vec<ResolvedBindCall>,
}

impl ResolvedSocketBindingOperations for InjectedResolvedBinder {
    fn bind_interface(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<(), Error> {
        self.calls
            .push(ResolvedBindCall::Interface(family, interface_index));
        Ok(())
    }

    fn bind_source(&mut self, source: std::net::SocketAddr) -> Result<(), Error> {
        self.calls.push(ResolvedBindCall::Source(source));
        Ok(())
    }
}

#[derive(Default)]
struct NoRouteCatalog;

impl NetworkInterfaceCatalog for NoRouteCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        _: std::net::SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}

#[test]
fn resolved_socket_binding_applies_interface_then_family_source() {
    let source = "192.0.2.44".parse().unwrap();
    let destination = "203.0.113.9:443".parse().unwrap();
    let binding =
        InterfaceBinding::new("Ethernet", 64, 74, vec![std::net::IpAddr::V4(source)]).unwrap();
    let snapshot = NetworkSnapshot::new(7, Some(binding), None).unwrap();
    let resolved = NetworkInterfaceResolver::new(NoRouteCatalog)
        .resolve(
            &DialOptions::new(None::<&str>, Some(source), None),
            &RouteNetworkOptions::new(true, None::<&str>),
            destination,
            &snapshot,
        )
        .unwrap();
    let mut binder = InjectedResolvedBinder::default();
    bind_resolved_socket_with(destination, &resolved, &mut binder).unwrap();
    assert_eq!(
        binder.calls,
        [
            ResolvedBindCall::Interface(destination.ip(), 74),
            ResolvedBindCall::Source("192.0.2.44:0".parse().unwrap()),
        ]
    );

    let mut wrong_family = InjectedResolvedBinder::default();
    let error = bind_resolved_socket_with(
        "[2001:db8::9]:443".parse().unwrap(),
        &resolved,
        &mut wrong_family,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(wrong_family.calls.is_empty());
}

#[test]
fn resolved_link_local_source_carries_the_selected_ipv6_scope() {
    let source = "fe80::44".parse().unwrap();
    let destination = "[2001:db8::9]:443".parse().unwrap();
    let binding =
        InterfaceBinding::new("Ethernet v6", 65, 75, vec![std::net::IpAddr::V6(source)]).unwrap();
    let snapshot = NetworkSnapshot::new(8, None, Some(binding)).unwrap();
    let resolved = NetworkInterfaceResolver::new(NoRouteCatalog)
        .resolve(
            &DialOptions::new(None::<&str>, None, Some(source)),
            &RouteNetworkOptions::new(true, None::<&str>),
            destination,
            &snapshot,
        )
        .unwrap();
    let mut binder = InjectedResolvedBinder::default();
    bind_resolved_socket_with(destination, &resolved, &mut binder).unwrap();
    assert_eq!(
        binder.calls,
        [
            ResolvedBindCall::Interface(destination.ip(), 75),
            ResolvedBindCall::Source("[fe80::44%75]:0".parse().unwrap()),
        ]
    );
}
