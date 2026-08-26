use super::*;

#[test]
fn fixed_endpoints_share_the_final_empty_or_ruleset_registry_generation() {
    assert_eq!(initial_resolver_generation(false).get(), 0);
    assert_eq!(
        initial_resolver_generation(true).get(),
        INITIAL_RULESET_GENERATION
    );
}

#[tokio::test]
async fn minimal_v2_materializes_without_network_or_background_owner() {
    let address = reserve_address();
    let file = TestConfig::new(|_| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#
        )
    });
    let prepared = ferrum2_config::prepare_client(&file.path).expect("prepare minimal config");
    let downloader = Arc::new(RecordingDownloader::failure());
    let materializer =
        ClientV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());

    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("materialize minimal config");
    assert!(downloader.seen().is_empty());
    let config = materialized
        .validate_only()
        .expect("validation-only cleanup");
    assert!(config.route.rule_registry().is_none());
}

#[tokio::test]
async fn numeric_bootstrap_materializes_domain_dns_upstream_in_dependency_order() {
    let listen = reserve_address();
    let dns_listen = reserve_address();
    let resolved_upstream = reserve_address();
    let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("numeric bootstrap DNS");
    let bootstrap_address = bootstrap.local_addr().expect("bootstrap DNS address");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let worker_observed = Arc::clone(&observed);
    let (stop, mut stopped) = oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        loop {
            let received = tokio::select! {
                _ = &mut stopped => break,
                received = bootstrap.recv_from(&mut wire) => received,
            };
            let (length, peer) = received.expect("bootstrap DNS receive");
            let request = Message::from_vec(&wire[..length]).expect("bootstrap DNS decode");
            let [query] = request.queries.as_slice() else {
                panic!("one bootstrap DNS question");
            };
            worker_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((query.name().to_ascii(), query.query_type()));
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            bootstrap
                .send_to(&response.to_vec().expect("bootstrap DNS encode"), peer)
                .await
                .expect("bootstrap DNS response");
        }
    });
    let file = TestConfig::new(|_| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[[dns.servers]]
tag = "resolved"
transport = "udp"
address = "upstream.test:{}"
domain_resolver = "bootstrap"
domain_strategy = "ipv4_only"

[dns.route]
final = "resolved"
"#,
            resolved_upstream.port()
        )
    });
    let prepared = ferrum2_config::prepare_client(&file.path).expect("prepare domain DNS upstream");
    let order = prepared.materialization_order();
    let bootstrap_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(0))
        .expect("bootstrap dependency node");
    let resolved_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(1))
        .expect("resolved dependency node");
    assert!(bootstrap_position < resolved_position);

    let metrics = Arc::new(Metrics::new());
    let materializer = ClientV2Materializer::new(Arc::clone(&metrics));
    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("materialize domain DNS upstream through numeric bootstrap");
    let dns = materialized
        .config()
        .dns
        .as_ref()
        .expect("materialized DNS");
    assert_eq!(
        dns.servers[0].target.as_socket_addr(),
        Some(bootstrap_address)
    );
    assert_eq!(
        dns.servers[1].target.canonical_domain().unwrap().as_str(),
        "upstream.test"
    );
    assert_eq!(
        dns.servers[1].resolved_targets.as_ref(),
        &[SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            resolved_upstream.port()
        )]
    );
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [("upstream.test.".to_owned(), RecordType::A)],
        "materialization issued anything other than the single bootstrap query"
    );
    let encoded = metrics.encode_text().expect("bootstrap DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"fixed_endpoint\",result=\"success\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    assert!(
        !encoded.contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"fixed_endpoint\"}")
    );
    materialized
        .validate_only()
        .expect("domain DNS upstream validation-only cleanup");
    let rebound = TcpListener::bind(listen).expect("client inbound remained unbound");
    drop(rebound);
    let _ = stop.send(());
    worker.await.expect("bootstrap DNS worker");
}

#[tokio::test]
async fn production_ruleset_transport_uses_tagged_dns_and_reaps_failed_tls_path() {
    let listen = reserve_address();
    let dns_listen = reserve_address();
    let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("RuleSet tagged DNS");
    let bootstrap_address = bootstrap.local_addr().expect("RuleSet DNS address");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let worker_observed = Arc::clone(&observed);
    let (stop, mut stopped) = oneshot::channel();
    let dns_worker = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        loop {
            let received = tokio::select! {
                _ = &mut stopped => break,
                received = bootstrap.recv_from(&mut wire) => received,
            };
            let (length, peer) = received.expect("RuleSet DNS receive");
            let request = Message::from_vec(&wire[..length]).expect("RuleSet DNS decode");
            let [query] = request.queries.as_slice() else {
                panic!("one RuleSet DNS question");
            };
            worker_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((query.name().to_ascii(), query.query_type()));
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            bootstrap
                .send_to(&response.to_vec().expect("RuleSet DNS encode"), peer)
                .await
                .expect("RuleSet DNS response");
        }
    });
    let tls_listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("controlled RuleSet TLS endpoint");
    let tls_address = tls_listener.local_addr().expect("RuleSet TLS address");
    let tls_worker = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), tls_listener.accept())
            .await
            .expect("RuleSet TCP connect timeout")
            .expect("RuleSet TCP connect");
        let mut client_hello = [0_u8; 4096];
        let received = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut client_hello))
            .await
            .expect("RuleSet TLS ClientHello timeout")
            .expect("RuleSet TLS ClientHello read");
        assert!(
            received > 0,
            "production downloader sent no TLS ClientHello"
        );
        stream
            .write_all(&[0, 0, 0, 0, 0])
            .await
            .expect("write controlled invalid TLS record");
        let mut drain = [0_u8; 256];
        loop {
            let length = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut drain))
                .await
                .expect("production RuleSet bridge did not close")
                .expect("read RuleSet bridge shutdown");
            if length == 0 {
                break;
            }
        }
        received
    });
    let file = TestConfig::new(|cache| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "private-rule-tag"
type = "remote"
url = "https://rules.test:{}/ads.srs"
download_resolver = "bootstrap"

[[route.rules]]
rule_set = "private-rule-tag"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 2000
max_redirects = 0

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[dns.route]
final = "bootstrap"
"#,
            tls_address.port()
        )
    });
    let prepared =
        ferrum2_config::prepare_client(&file.path).expect("prepare production tagged RuleSet V2");
    let order = prepared.materialization_order();
    let resolver_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(0))
        .expect("RuleSet resolver dependency node");
    let rule_set_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::RuleSet(0))
        .expect("RuleSet dependency node");
    assert!(resolver_position < rule_set_position);
    let metrics = Arc::new(Metrics::new());
    let materializer = ClientV2Materializer::new(Arc::clone(&metrics));
    let error = match materializer.materialize(prepared).await {
        Ok(_) => panic!("controlled TLS endpoint unexpectedly materialized"),
        Err(error) => error,
    };
    assert_eq!(error, RunError::RuleSetDownload);
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("private-rule-tag"));
        assert!(!rendered.contains("rules.test"));
    }
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [("rules.test.".to_owned(), RecordType::A)],
        "RuleSet resolution escaped its selected tagged resolver"
    );
    let tls_bytes = tls_worker.await.expect("controlled RuleSet TLS worker");
    assert!(tls_bytes > 0);
    let rebound = TcpListener::bind(listen).expect("client inbound remained unbound");
    drop(rebound);
    let encoded = metrics
        .encode_text()
        .expect("production RuleSet DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"ruleset_download\",result=\"success\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    assert!(
        !encoded
            .contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"ruleset_download\"}")
    );
    let _ = stop.send(());
    dns_worker.await.expect("RuleSet DNS worker");
    let rebound = UdpSocket::bind(bootstrap_address)
        .await
        .expect("test DNS endpoint fully reaped");
    drop(rebound);
}

#[tokio::test]
async fn fixed_endpoint_and_tcp_udp_application_share_generation_zero_cache() {
    let listen = reserve_address();
    let dns_listen = reserve_address();
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("tagged DNS upstream");
    let upstream_address = upstream.local_addr().expect("tagged DNS address");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let worker_observed = Arc::clone(&observed);
    let (stop, mut stopped) = oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        loop {
            let received = tokio::select! {
                _ = &mut stopped => break,
                received = upstream.recv_from(&mut wire) => received,
            };
            let (length, peer) = received.expect("tagged DNS receive");
            let request = Message::from_vec(&wire[..length]).expect("tagged DNS decode");
            let [query] = request.queries.as_slice() else {
                panic!("one tagged DNS question");
            };
            worker_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((query.name().to_ascii(), query.query_type()));
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 19))),
            ));
            upstream
                .send_to(&response.to_vec().expect("tagged DNS encode"), peer)
                .await
                .expect("tagged DNS response");
        }
    });
    let file = TestConfig::new(|_| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"
type = "direct"

[[outbounds]]
tag = "fixed-domain"
type = "shadowsocks"
server = "shared-cache.test:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
domain_resolver = "local"
domain_strategy = "ipv4_only"

[route]
final = "direct"

[[route.rules]]
domain_keyword = "fixed-only"
action = "route"
outbound = "fixed-domain"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 16

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "{upstream_address}"

[dns.route]
final = "local"
"#
        )
    });
    let prepared =
        ferrum2_config::prepare_client(&file.path).expect("prepare fixed endpoint cache");
    assert!(prepared.rule_sets().is_empty());
    let metrics = Arc::new(Metrics::new());
    let materializer = ClientV2Materializer::new(Arc::clone(&metrics));
    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("materialize fixed domain endpoint");
    assert_eq!(
        materialized.config().outbounds[1].server(),
        Some("203.0.113.19:8388".parse().expect("resolved endpoint"))
    );
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [("shared-cache.test.".to_owned(), RecordType::A)]
    );

    let MaterializedRunParts {
        mut config,
        materialization_root: root,
        cache,
    } = materialized
        .into_run_parts()
        .await
        .expect("materialized cache handoff");
    assert!(root.is_none(), "no RuleSet refresh root");
    let cache = cache.expect("materialization cache");
    assert!(config.route.rule_registry().is_none());
    let dns = config.dns.take().expect("materialized DNS graph");
    let runtime = crate::run::ClientDnsProxyRuntime::try_new(
        config
            .dns_route
            .as_mut()
            .expect("materialized client DNS policy"),
        dns.runtime,
        Some(cache),
        &metrics,
    )
    .expect("application DNS runtime");
    let (generation, listener_count, ordinary_count, _) = runtime.contract_snapshot();
    assert_eq!((generation, listener_count, ordinary_count), (0, 1, 1));
    let (resolver, mut owner) = TaggedResolver::new(
        crate::run::dns_egress::dns_runtime_specs(&dns.servers),
        dns.timeout,
        dns.max_inflight,
        Arc::new(ferrum2_dns::SystemDnsEgress),
    )
    .expect("application tagged resolver");
    owner.ready().await.expect("application DNS ready");
    let proxy = Arc::new(runtime.bind(Arc::new(resolver)));
    let proxy_slot = Arc::new(OnceLock::new());
    assert!(proxy_slot.set(proxy).is_ok());
    let application = ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::configured(Arc::new(
            crate::run::dns_egress::ClientConfiguredApplicationBackend::new(proxy_slot),
        ))),
        0,
        DnsStrategy::Ipv4Only,
    );
    assert_eq!(
        application.mode(),
        ferrum2_dns::ApplicationResolverMode::Configured
    );

    assert_eq!(
        ferrum2_net::TcpResolver::resolve(&application, "shared-cache.test", 443)
            .await
            .expect("TCP application cache hit"),
        ["203.0.113.19:443".parse().expect("TCP candidate")]
    );
    assert_eq!(
        ferrum2_net::UdpResolver::resolve(&application, "shared-cache.test", 53)
            .await
            .expect("UDP application cache hit"),
        ["203.0.113.19:53".parse().expect("UDP candidate")]
    );
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [("shared-cache.test.".to_owned(), RecordType::A)],
        "application lookup missed the generation-zero materialization cache"
    );
    let encoded = metrics.encode_text().expect("cache metrics");
    for expected in [
        "ferrum2_dns_cache_miss_total{qtype=\"a\"} 1",
        "ferrum2_dns_cache_hit_total{qtype=\"a\"} 2",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }

    owner.shutdown().await.expect("application DNS shutdown");
    let _ = stop.send(());
    worker.await.expect("tagged DNS worker");
}
