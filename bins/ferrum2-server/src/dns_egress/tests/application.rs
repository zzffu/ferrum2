use super::*;

#[tokio::test]
async fn application_observer_separates_system_and_configured_without_fallback() {
    let system_metrics = Arc::new(Metrics::new());
    let system = ServerDnsResolver::new_observed(None, Arc::clone(&system_metrics));
    assert!(
        !TcpResolver::resolve(&system, "localhost", 443)
            .await
            .expect("explicit system localhost")
            .is_empty()
    );
    let encoded = system_metrics.encode_text().expect("system metrics");
    assert!(encoded.contains(
            "ferrum2_dns_resolve_total{resolver=\"system\",purpose=\"application\",result=\"success\"} 1"
        ));
    assert!(
        encoded.contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1")
    );
    assert!(encoded.contains("ferrum2_dns_implicit_system_fallback_total 0"));

    let listen = reserve_address();
    let upstream = reserve_address();
    let source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "app"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[dns]
strategy = "ipv4_only"

[[dns.servers]]
tag = "configured"
transport = "udp"
address = "{upstream}"

[dns.route]
final = "configured"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
    );
    let (path, mut config) = materialized_server_test_config_source("dns-observer", &source);
    let dns = config.dns.take().expect("configured DNS");
    let state = Arc::new(
        ServerDnsState::try_new(
            config.dns_route.take().expect("compiled DNS policy"),
            dns.runtime,
        )
        .expect("configured state"),
    );
    let configured_metrics = Arc::new(Metrics::new());
    let configured = ServerDnsResolver::new_observed(Some(state), Arc::clone(&configured_metrics));
    assert!(
        TcpResolver::resolve(&configured, "failure.example", 443)
            .await
            .is_err()
    );
    let encoded = configured_metrics
        .encode_text()
        .expect("configured metrics");
    assert!(encoded.contains(
            "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"application\",result=\"failure\"} 1"
        ));
    assert!(
        !encoded.contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1")
    );
    assert!(encoded.contains("ferrum2_dns_implicit_system_fallback_total 0"));
    std::fs::remove_file(path).expect("remove observer config");
}

#[tokio::test]
async fn caller_owned_cache_is_used_with_compiled_final_policy() {
    let listen = reserve_address();
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cache test upstream");
    let source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "app"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[dns]
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 8

[[dns.servers]]
tag = "configured"
transport = "udp"
address = "{}"

[dns.route]
final = "configured"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        upstream.local_addr().expect("upstream address")
    );
    let (path, mut config) = materialized_server_test_config_source("dns-shared-cache", &source);
    let dns = config.dns.take().expect("configured DNS");
    let specs = dns_runtime_specs(&dns.servers);
    let cache = DnsCache::try_new(std::num::NonZeroUsize::new(8).unwrap()).expect("caller cache");
    let domain = ferrum2_core::CanonicalDomain::new("cached.example").expect("cache domain");
    cache
        .insert_positive(
            DnsCacheKey::new(
                DnsServerId::new(0),
                domain,
                DnsCacheQtype::A,
                ResolverGeneration::new(0),
            ),
            DnsAddressRecords::A(Arc::from([Ipv4Addr::new(203, 0, 113, 44)])),
            Duration::from_secs(60),
            Instant::now(),
        )
        .expect("seed shared cache");
    let state = Arc::new(
        ServerDnsState::try_new_with_cache(
            config.dns_route.take().expect("compiled DNS policy"),
            dns.runtime,
            Some(cache),
        )
        .expect("state with caller cache"),
    );
    let (tagged, mut owner) = TaggedResolver::new(
        specs,
        dns.timeout,
        dns.max_inflight,
        Arc::new(ServerDnsEgress::test(config.outbounds.len())),
    )
    .expect("tagged resolver");
    owner.ready().await.expect("tagged ready");
    state.install(Arc::new(tagged)).expect("install resolver");
    let resolver = ServerDnsResolver::new(Some(Arc::clone(&state)));
    assert_eq!(
        TcpResolver::resolve(&resolver, "cached.example", 443)
            .await
            .expect("cached application lookup"),
        [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 44), 443))]
    );
    assert_pending(
        upstream.recv_from(&mut [0_u8; 1]),
        "caller cache was not shared with final application resolver",
    )
    .await;
    drop(resolver);
    drop(state.take());
    owner.shutdown().await.expect("tagged shutdown");
    std::fs::remove_file(path).expect("remove shared cache config");
}
