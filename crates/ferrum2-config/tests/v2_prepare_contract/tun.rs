use super::support::*;

#[test]
fn finished_tun_tracks_every_dual_stack_dns_candidate_and_rechecks_listener_aliases() {
    let source = r#"
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
outbound = "direct"

[[outbounds]]
tag = "direct"
type = "direct"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "bootstrap.example.test:5353"
domain_resolver = "system"
domain_strategy = "prefer_ipv4"

[dns.route]
final = "bootstrap"
"#;
    let file = TempConfig::new(source);
    let candidates = vec![
        "192.0.2.10:5353".parse().unwrap(),
        "192.0.2.11:5353".parse().unwrap(),
        "[2001:db8::53]:5353".parse().unwrap(),
    ]
    .into_boxed_slice();
    let prepared = prepare_client(&file.0).expect("prepare candidate TUN");
    let finished = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::from_candidates(0, candidates)],
            Vec::new(),
            None,
        ),
    )
    .expect("finish candidate TUN");
    assert_eq!(
        finished.tun.unwrap().physical_endpoints,
        [
            "192.0.2.10:5353".parse().unwrap(),
            "192.0.2.11:5353".parse().unwrap(),
            "[2001:db8::53]:5353".parse().unwrap(),
        ]
    );

    let prepared = prepare_client(&file.0).expect("prepare alias candidate TUN");
    let error = match finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::from_candidates(
                0,
                Box::new(["127.0.0.1:5353".parse().unwrap()]),
            )],
            Vec::new(),
            None,
        ),
    ) {
        Ok(_) => panic!("resolved DNS candidate aliases its listener"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::DnsServersAddress);

    let mut overflow_source = String::from(
        r#"
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
outbound = "direct"

[[outbounds]]
tag = "direct"
type = "direct"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:6000"
"#,
    );
    for server in 0..17 {
        overflow_source.push_str(&format!(
            r#"
[[dns.servers]]
tag = "s{server}"
transport = "udp"
address = "s{server}.example.test:5353"
domain_resolver = "system"
domain_strategy = "ipv4_only"
"#,
        ));
    }
    overflow_source.push_str("\n[dns.route]\nfinal = \"s0\"\n");
    for server in 1..17 {
        overflow_source.push_str(&format!(
            r#"
[[dns.route.rules]]
domain_keyword = "probe-{server}"
action = "route"
server = "s{server}"
"#,
        ));
    }
    let overflow_file = TempConfig::new(&overflow_source);
    let prepared = prepare_client(&overflow_file.0).expect("prepare physical endpoint overflow");
    let resources = (0_u32..17)
        .map(|server| {
            let candidates = (1_u8..=16)
                .map(|candidate| format!("192.0.{server}.{candidate}:5353").parse().unwrap())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            ResolvedDnsEndpoint::from_candidates(server, candidates)
        })
        .collect();
    let error = match finish_client_v2(
        prepared,
        ClientV2Resources::new(resources, Vec::new(), None),
    ) {
        Ok(_) => panic!("physical endpoint overflow must fail during config finish"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::TunAutoRoute);
}

#[test]
fn bootstrap_descriptors_follow_dependency_order_without_exposing_values_in_debug() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client(&file.0).expect("prepare bootstrap descriptors");

    assert_eq!(prepared.dns_server_count(), 2);
    let doh = prepared.dns_server(1).expect("DoH descriptor");
    assert_eq!(doh.index(), 1);
    assert_eq!(doh.transport(), ferrum2_config::DnsTransport::Doh);
    assert_eq!(doh.server_name(), Some("dns.example.test"));
    assert_eq!(doh.path(), Some("/dns-query"));
    assert_eq!(doh.detour().unwrap().snapshot().hops(), &[0]);
    assert!(doh.endpoint().is_domain());
    let debug = format!("{doh:?}");
    assert!(!debug.contains("dns.example.test"));
    assert!(!debug.contains("dns-query"));

    assert_eq!(prepared.outbound_count(), 2);
    let direct = prepared.outbound(0).expect("direct descriptor");
    assert_eq!(direct.kind(), PreparedClientOutboundKind::Direct);
    assert!(direct.method().is_none());
    assert!(direct.psk().is_none());
    assert!(direct.endpoint().is_none());
    assert_eq!(direct.domain_resolver(), Some(DirectDomainResolver::System));
    let shadowsocks = prepared.outbound(1).expect("Shadowsocks descriptor");
    assert_eq!(shadowsocks.kind(), PreparedClientOutboundKind::Shadowsocks);
    assert!(shadowsocks.method().is_some());
    let shared_psk = shadowsocks.psk().expect("shared Shadowsocks PSK");
    let staged_psk = Arc::clone(shared_psk);
    assert!(Arc::ptr_eq(shared_psk, &staged_psk));
    assert_eq!(format!("{shared_psk:?}"), "MethodPsk([REDACTED])");
    assert!(shadowsocks.endpoint().is_some_and(DialEndpoint::is_domain));
    let debug = format!("{shadowsocks:?}");
    assert!(!debug.contains("AAECAwQFBgcICQoLDA0ODw=="));

    let declarations = prepared
        .materialization_order()
        .iter()
        .filter_map(|node| {
            prepared
                .fixed_endpoint_for_node(*node)
                .map(|descriptor| (*node, descriptor.target()))
        })
        .collect::<Vec<_>>();
    assert_eq!(declarations.len(), 3);
    for (node, target) in declarations {
        match (node, target) {
            (
                PreparedDependencyNode::DnsServer(index),
                PreparedFixedEndpointTarget::DnsServer(target_index),
            ) => assert_eq!(index, target_index),
            (
                PreparedDependencyNode::Outbound(index),
                PreparedFixedEndpointTarget::Outbound(target_index),
            ) => assert_eq!(index, target_index),
            other => panic!("dependency endpoint identity mismatch: {other:?}"),
        }
    }
    assert!(
        prepared
            .fixed_endpoint_for_node(PreparedDependencyNode::Outbound(0))
            .is_none()
    );
    assert_eq!(prepared.runtime().max_connections.get(), 4_096);
    assert!(prepared.udp().is_none());
}
