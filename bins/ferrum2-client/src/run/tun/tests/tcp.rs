use super::*;

#[tokio::test]
async fn tun_auto_dns_tcp_answer_failure_closes_flow_before_ordinary_route() {
    let fallback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fallback listener");
    let fallback_address = match fallback.local_addr().expect("fallback address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 fallback"),
    };
    let dns_upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("DNS upstream");
    let dns_address = dns_upstream.local_addr().expect("DNS upstream address");
    let dns_inbound = reserve_address();
    let (path, _) = client_test_config(reserve_address(), fallback_address);
    std::fs::write(
        &path,
        format!(
            r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "fallback"
type = "shadowsocks"
server = "{fallback_address}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[route]
final = "fallback"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "{dns_inbound}"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "{dns_address}"
[dns.route]
final = "resolver"
"#
        ),
    )
    .expect("TUN DNS failure config");
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare TUN DNS config");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish TUN DNS config");
    std::fs::remove_file(&path).expect("remove TUN DNS config");
    let runtime = config.runtime;
    let selector = config.selector_control();
    let outbounds = prepare_client_outbounds(config.outbounds).expect("test outbounds");
    let routing = Arc::new(ClientRouting {
        program: config.route,
        outbounds: Arc::clone(&outbounds),
        selector,
    });
    let (resolver, mut resolver_owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(dns_address).expect("numeric DNS target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("one DNS query"),
    )
    .expect("test resolver");
    resolver_owner.ready().await.expect("resolver ready");
    let dns_snapshot = ferrum2_rule::RuleEngineSnapshotBuilder::new(1)
        .build()
        .expect("empty DNS rule snapshot");
    let dns_policy = Arc::new(
        ferrum2_dns::DnsPolicyProgram::try_new(
            Vec::new(),
            ferrum2_dns::DnsPolicyRoute::new(
                ferrum2_dns::DnsServerId::new(0),
                ferrum2_dns::DnsStrategy::PreferIpv4,
            ),
            &dns_snapshot,
        )
        .expect("final-only DNS policy"),
    );
    let proxy = Arc::new(DnsProxy::new(
        Arc::new(resolver),
        dns_policy,
        Arc::new(ferrum2_rule::RuleEngineRegistry::new(dns_snapshot)),
        1,
        1,
    ));
    let dns = Arc::new(std::sync::OnceLock::new());
    assert!(dns.set(proxy).is_ok(), "one DNS proxy");
    let registry = OwnerRegistry::new();
    let context = Arc::new(ClientContext {
        inbound: Socks5Inbound::new(),
        egress: Arc::new(ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                crate::run::egress::system_application_resolver(),
                runtime.connect_timeout,
            )),
            SystemClock::new(),
            SystemRandom,
            (runtime.connect_timeout, runtime.handshake_timeout),
            None,
            None,
        )),
        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk())),
        runtime,
        public_udp_slots: None,
        registry: registry.clone(),
        metrics: Arc::new(Metrics::new()),
        #[cfg(feature = "structural-metrics")]
        structural: ferrum2_structural::StructuralHub::new().local(),
        dns: Some(dns),
    });

    let (cancellation_sender, cancellation_receiver) = tokio::sync::oneshot::channel();
    let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
        cancellation_sender
            .send(cancellation.clone())
            .expect("one cancellation view");
        cancellation.cancelled().await;
        Ok::<Option<NeverPrepared>, RunError>(None)
    });
    let cancellation_registry = OwnerRegistry::new();
    let supervisor = ProcessSupervisor::new(
        vec![root],
        Duration::from_secs(1),
        cancellation_registry.clone(),
    )
    .expect("cancellation root");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let supervisor = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_receiver.await;
    }));
    let cancellation = cancellation_receiver.await.expect("active cancellation");

    let target: SocketAddr = "192.0.2.53:53".parse().expect("DNS target");
    let (flow, mut peer) = tokio::io::duplex(64);
    peer.write_all(&[0, 1, 0])
        .await
        .expect("malformed DNS frame");
    peer.shutdown().await.expect("DNS request half-close");
    run_tcp(
        target,
        flow,
        cancellation.clone(),
        Arc::clone(&context),
        routing,
        0,
        SyntheticDns {
            ipv4: Some(Ipv4Addr::new(192, 0, 2, 53)),
            ipv6: None,
        },
        None,
    )
    .await;
    assert_eq!(peer.read(&mut [0; 1]).await.expect("terminal close"), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), fallback.accept())
            .await
            .is_err(),
        "DNS failure evaluated the final route or fallback egress"
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let direct_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("direct TUN TCP target");
    let direct_target = direct_listener.local_addr().expect("direct TUN target");
    let direct_registry = OwnerRegistry::new();
    let direct_outbounds =
        prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct {
            domain_resolver: ferrum2_config::DirectDomainResolver::System,
            dial_options: Default::default(),
        }])
        .expect("direct TUN outbound");
    let route_path = write_client_test_source(&format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"tun\"\nlisten = \"{}\"\noutbound = \"direct\"\n[[outbounds]]\ntag = \"direct\"\ntype = \"direct\"\n",
        reserve_address()
    ));
    let prepared = ferrum2_config::prepare_client(&route_path).expect("prepare direct TUN route");
    let route_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish direct TUN route");
    std::fs::remove_file(route_path).expect("remove direct TUN route config");
    let direct_selector = route_config.selector_control();
    let direct_routing = Arc::new(ClientRouting {
        program: route_config.route,
        outbounds: Arc::clone(&direct_outbounds),
        selector: direct_selector,
    });
    let direct_context = Arc::new(ClientContext {
        inbound: Socks5Inbound::new(),
        egress: Arc::new(ClientEgressEngine::new(
            direct_outbounds,
            TokioConnector::new(TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                crate::run::egress::system_application_resolver(),
                context.runtime.connect_timeout,
            )),
            SystemClock::new(),
            SystemRandom,
            (
                context.runtime.connect_timeout,
                context.runtime.handshake_timeout,
            ),
            None,
            None,
        )),
        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk())),
        runtime: context.runtime,
        public_udp_slots: None,
        registry: direct_registry.clone(),
        metrics: Arc::new(Metrics::new()),
        #[cfg(feature = "structural-metrics")]
        structural: ferrum2_structural::StructuralHub::new().local(),
        dns: None,
    });
    let target = tokio::spawn(async move {
        let (mut stream, _) = direct_listener.accept().await.expect("direct TUN accept");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .await
            .expect("direct TUN target read");
        stream
            .write_all(b"tun-reply")
            .await
            .expect("direct TUN target reply");
        stream
            .shutdown()
            .await
            .expect("direct TUN target half close");
        request
    });
    let (flow, mut peer) = tokio::io::duplex(64);
    let direct = tokio::spawn(run_tcp(
        direct_target,
        flow,
        cancellation.clone(),
        direct_context,
        direct_routing,
        0,
        SyntheticDns::default(),
        None,
    ));
    peer.write_all(b"tun-direct")
        .await
        .expect("direct TUN write");
    peer.shutdown().await.expect("direct TUN half close");
    let mut response = Vec::new();
    peer.read_to_end(&mut response)
        .await
        .expect("direct TUN response");
    assert_eq!(response, b"tun-reply");
    assert_eq!(
        target.await.expect("direct TUN target owner"),
        b"tun-direct"
    );
    direct.await.expect("direct TUN relay owner");
    assert_eq!(active(direct_registry.snapshot()), OwnerSnapshot::default());

    shutdown_sender.send(()).expect("stop cancellation root");
    assert_eq!(
        report_result(supervisor.await.expect("cancellation supervisor")),
        Ok(())
    );
    drop(context);
    resolver_owner.shutdown().await.expect("resolver shutdown");
    assert_eq!(
        active(cancellation_registry.snapshot()),
        OwnerSnapshot::default()
    );
}
