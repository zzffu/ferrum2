use super::*;
use crate::run::egress::io_error_from_network_service;
use crate::run::egress::network::{
    connect_error_from_network_service, interface_resolution_result, record_interface_resolution,
};
use crate::run::runtime_route_network;
use ferrum2_net::InterfaceSelectionSource;
use ferrum2_observability::InterfaceResolutionResult;
use ferrum2_runtime::{
    NetworkRuntimeResourceAdmissionError, NetworkSocketServiceError, SystemNetworkSocketError,
};

#[test]
fn shared_network_reset_hub_resets_all_live_engines_and_drops_registration_exactly() {
    let hub = ClientNetworkResetHub::default();
    let first = Arc::new(ClientEgressNetworkResetState::new(None));
    let second = Arc::new(ClientEgressNetworkResetState::new(None));
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let first_action: Arc<ClientDnsResetAction> = {
        let calls = Arc::clone(&first_calls);
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            2
        })
    };
    let second_action: Arc<ClientDnsResetAction> = {
        let calls = Arc::clone(&second_calls);
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            3
        })
    };
    first.register_dns_action(&first_action).unwrap();
    second.register_dns_action(&second_action).unwrap();
    let _first_registration = hub.register(&first).unwrap();
    let second_registration = hub.register(&second).unwrap();

    assert_eq!(hub.reset(), 5);
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);

    drop(second_registration);
    assert_eq!(hub.reset(), 2);
    assert_eq!(first_calls.load(Ordering::SeqCst), 2);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn validated_network_policies_are_retained_per_outbound_and_route() {
    let explicit = ferrum2_config::OutboundDialOptions {
        bind_interface: Some("policy-interface".into()),
        inet4_bind_address: Some("192.0.2.44".parse().unwrap()),
        inet6_bind_address: Some("2001:db8::44".parse().unwrap()),
    };
    let expected = DialOptions::new(
        Some("policy-interface"),
        Some("192.0.2.44".parse().unwrap()),
        Some("2001:db8::44".parse().unwrap()),
    );
    let outbounds = prepare_client_outbounds(vec![
        ferrum2_config::ClientOutboundConfig::Direct {
            domain_resolver: ferrum2_config::DirectDomainResolver::System,
            dial_options: explicit.clone(),
        },
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "198.51.100.44:443".parse().unwrap(),
            psk: Arc::new(ferrum2_crypto::MethodPsk::aes128([0x44; 16])),
            dial_options: explicit,
        },
    ])
    .unwrap();
    assert_eq!(outbounds[0].dial_options(), &expected);
    assert_eq!(outbounds[1].dial_options(), &expected);

    let route = ferrum2_config::RouteNetworkConfig {
        auto_detect_interface: true,
        default_interface: Some("route-interface".into()),
    };
    assert_eq!(
        runtime_route_network(&route),
        RouteNetworkOptions::new(true, Some("route-interface"))
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PhysicalPolicyAttempt {
    target: TargetAddr,
    dial_options: DialOptions,
    route_network: RouteNetworkOptions,
}

#[derive(Default)]
struct PhysicalPolicyTrace {
    tcp: Mutex<Vec<PhysicalPolicyAttempt>>,
    udp: Mutex<Vec<(DialOptions, RouteNetworkOptions)>>,
    udp_socket: Arc<udp::InjectedUdpSocketTrace>,
}

struct RecordingPhysicalConnector {
    trace: Arc<PhysicalPolicyTrace>,
}

impl ClientPhysicalConnector for RecordingPhysicalConnector {
    type Stream = TokioTransport<ScriptedIo>;

    async fn connect_physical(
        &self,
        target: &TargetAddr,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
    ) -> Result<Self::Stream, ConnectError> {
        self.trace
            .tcp
            .lock()
            .expect("physical TCP attempts")
            .push(PhysicalPolicyAttempt {
                target: target.clone(),
                dial_options: dial_options.clone(),
                route_network: route_network.clone(),
            });
        Err(ConnectError::new(ConnectErrorKind::ConnectionRefused))
    }

    fn udp_socket_factory(
        &self,
        _expected_generation: Option<u64>,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
    ) -> udp::ClientUdpSocketFactory {
        self.trace
            .udp
            .lock()
            .expect("physical UDP policies")
            .push((dial_options.clone(), route_network.clone()));
        udp::ClientUdpSocketFactory::injected(Arc::clone(&self.trace.udp_socket))
    }
}

#[tokio::test]
async fn physical_connector_receives_selected_policy_and_first_concrete_target() {
    let direct_dial = DialOptions::new(
        Some("direct-interface"),
        Some("192.0.2.10".parse().unwrap()),
        None,
    );
    let proxy_dial = DialOptions::new(
        Some("proxy-interface"),
        Some("192.0.2.20".parse().unwrap()),
        None,
    );
    let route_network = RouteNetworkOptions::new(true, Some("route-interface"));
    let proxy_server: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let trace = Arc::new(PhysicalPolicyTrace::default());
    let engine = ClientEgressEngine::new(
        vec![
            ClientOutboundContext::direct(direct_dial.clone()),
            ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                tcp_server: TargetAddr::ip(proxy_server).unwrap(),
                udp_server: proxy_server,
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                    ferrum2_crypto::MethodPsk::aes128([0x20; 16]),
                )),
                dial_options: proxy_dial.clone(),
            }),
        ]
        .into(),
        RecordingPhysicalConnector {
            trace: Arc::clone(&trace),
        },
        SystemClock::new(),
        SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), OwnerRegistry::new()),
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        None,
    )
    .with_route_network(route_network.clone());
    let direct_plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
    let proxy_plan = ferrum2_core::route::EgressPlanHandle::direct(1).snapshot_owned();
    let direct_target = TargetAddr::ip("203.0.113.10:8443".parse().unwrap()).unwrap();
    let application_target = TargetAddr::ip("203.0.113.30:5353".parse().unwrap()).unwrap();

    assert!(matches!(
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(direct_plan.clone()),
                &direct_target,
                None,
                None,
            )
            .await,
        Err(ClientOpenFailure::Connect(
            ConnectErrorKind::ConnectionRefused
        ))
    ));
    assert!(matches!(
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(proxy_plan.clone()),
                &application_target,
                None,
                None,
            )
            .await,
        Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
            ConnectErrorKind::ConnectionRefused
        )))
    ));

    let mut direct_udp = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(direct_plan),
            Some(&direct_target),
        )
        .await
        .unwrap();
    let wire_length = match direct_udp.prepare_application_request(
        &engine,
        &engine.outbounds,
        direct_target.clone(),
        b"first",
        Instant::now(),
    ) {
        Ok(length) => length,
        Err(_) => panic!("direct UDP request should encode"),
    };
    assert!(matches!(
        direct_udp.send_encoded_request(wire_length).await,
        Ok(length) if length == wire_length
    ));
    let _proxy_udp = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(proxy_plan),
            Some(&application_target),
        )
        .await
        .unwrap();

    assert_eq!(
        trace.tcp.lock().unwrap().as_slice(),
        &[
            PhysicalPolicyAttempt {
                target: direct_target.clone(),
                dial_options: direct_dial.clone(),
                route_network: route_network.clone(),
            },
            PhysicalPolicyAttempt {
                target: TargetAddr::ip(proxy_server).unwrap(),
                dial_options: proxy_dial.clone(),
                route_network: route_network.clone(),
            },
        ]
    );
    assert_eq!(
        trace.udp.lock().unwrap().as_slice(),
        &[
            (direct_dial, route_network.clone()),
            (proxy_dial, route_network),
        ]
    );
    assert_eq!(
        trace.udp_socket.opened(),
        vec![direct_target.as_socket_addr().unwrap(), proxy_server]
    );
    assert_eq!(
        trace.udp_socket.sent(),
        vec![direct_target.as_socket_addr().unwrap()]
    );
}

pub(in crate::run) struct EmptyNetworkCatalog;

impl ferrum2_net::NetworkInterfaceCatalog for EmptyNetworkCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<
        Vec<ferrum2_net::NetworkInterfaceObservation>,
        ferrum2_net::NetworkInterfaceCatalogError,
    > {
        Ok(Vec::new())
    }

    fn system_best_route(
        &self,
        _destination: SocketAddr,
    ) -> Result<ferrum2_net::SystemBestRoute, ferrum2_net::NetworkInterfaceCatalogError> {
        Err(ferrum2_net::NetworkInterfaceCatalogError)
    }
}

#[test]
fn generation_bound_socket_errors_and_interface_metrics_keep_closed_categories() {
    let refused = NetworkSocketServiceError::Connection {
        attempted_source: InterfaceSelectionSource::SystemBestRoute,
        error: SystemNetworkSocketError::<()>::Socket(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        )),
    };
    assert_eq!(
        interface_resolution_result(&refused),
        InterfaceResolutionResult::Success
    );
    assert_eq!(
        connect_error_from_network_service(refused).kind(),
        ConnectErrorKind::ConnectionRefused
    );

    let denied = explicit_interface_error();
    assert_eq!(
        interface_resolution_result(&denied),
        InterfaceResolutionResult::Failure
    );
    assert_eq!(
        connect_error_from_network_service(denied).kind(),
        ConnectErrorKind::PolicyDenied
    );
    assert_eq!(
        io_error_from_network_service(explicit_interface_error()).kind(),
        io::ErrorKind::PermissionDenied
    );

    let stale = NetworkSocketServiceError::Admission(NetworkRuntimeResourceAdmissionError::<
        SystemNetworkSocketError<()>,
    >::NetworkGenerationChanged {
        attempted_source: InterfaceSelectionSource::AutoDetected,
    });
    assert_eq!(
        interface_resolution_result(&stale),
        InterfaceResolutionResult::Failure
    );
    assert_eq!(
        connect_error_from_network_service(stale).kind(),
        ConnectErrorKind::NetworkUnreachable
    );

    let metrics = Metrics::new();
    record_interface_resolution(
        &metrics,
        InterfaceSelectionSource::OutboundExplicit,
        InterfaceResolutionResult::Success,
    );
    record_interface_resolution(
        &metrics,
        InterfaceSelectionSource::SystemBestRoute,
        InterfaceResolutionResult::Failure,
    );
    let encoded = metrics.encode_text().unwrap();
    assert!(encoded.contains(
        "ferrum2_outbound_interface_resolution_total{source=\"outbound_explicit\",result=\"success\"} 1"
    ));
    assert!(encoded.contains(
        "ferrum2_outbound_interface_resolution_total{source=\"system_best_route\",result=\"failure\"} 1"
    ));
}

#[derive(Clone, Copy)]
pub(in crate::run) struct ApplicationRoute {
    pub(in crate::run) ingress: usize,
    pub(in crate::run) network: ferrum2_core::route::Network,
    pub(in crate::run) endpoint: SocketAddr,
}

pub(in crate::run) struct RoutedApplicationBackend {
    pub(in crate::run) routes: Vec<ApplicationRoute>,
    pub(in crate::run) observed: Mutex<Vec<(usize, ferrum2_core::route::Network)>>,
}

impl ferrum2_dns::ApplicationResolveBackend for RoutedApplicationBackend {
    fn resolve<'a>(
        &'a self,
        request: ferrum2_dns::ApplicationResolveRequest<'a>,
    ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
        let context = request.context();
        self.observed
            .lock()
            .expect("application observations")
            .push((context.ingress(), context.network()));
        let endpoint = self
            .routes
            .iter()
            .find(|route| route.ingress == context.ingress() && route.network == context.network())
            .map(|route| route.endpoint);
        Box::pin(async move {
            endpoint
                .map(|endpoint| vec![endpoint])
                .ok_or(ferrum2_dns::DnsError::Timeout)
        })
    }
}
