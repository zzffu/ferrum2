use super::*;

#[test]
fn synthetic_dns_matches_each_configured_family_exactly() {
    let dns = SyntheticDns {
        ipv4: Some("198.18.0.1".parse().unwrap()),
        ipv6: Some("fd00::1".parse().unwrap()),
    };
    for (target, expected) in [
        ("198.18.0.1:53", true),
        ("[fd00::1]:53", true),
        ("198.18.0.1:54", false),
        ("[fd00::1]:54", false),
        ("198.18.0.2:53", false),
        ("[fd00::2]:53", false),
    ] {
        assert_eq!(dns.matches(target.parse().unwrap()), expected, "{target}");
    }
    assert!(!SyntheticDns::default().matches("198.18.0.1:53".parse().unwrap()));
    assert!(!SyntheticDns::default().matches("[fd00::1]:53".parse().unwrap()));
}

#[test]
fn synthetic_dns_precedes_one_frozen_ordinary_udp_route() {
    let (path, _) = client_test_config(reserve_address(), reserve_address());
    std::fs::write(
        &path,
        r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "fallback"
server = "192.0.2.10:8388"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "fallback"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.53"
port = 53
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.54"
port = 53
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.60"
action = "route"
outbound = "direct"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:5300"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:5301"
[dns.route]
final = "resolver"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
    )
    .expect("TUN UDP modes config");
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare TUN UDP modes config");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish TUN UDP modes config");
    std::fs::remove_file(path).expect("remove TUN UDP modes config");
    let inbound = config.inbounds.len();
    let selector = config.selector_control();
    let outbounds = prepare_client_outbounds(config.outbounds).expect("outbound contexts");
    let routing = ClientRouting {
        program: config.route,
        outbounds,
        selector,
    };
    let metrics = ferrum2_observability::Metrics::new();
    let synthetic_v4 = Ipv4Addr::new(198, 18, 0, 1);
    let synthetic_target = TargetAddr::ip("198.18.0.1:53".parse().expect("synthetic DNS target"))
        .expect("synthetic DNS target");
    let synthetic = select_udp_target(
        &routing,
        inbound,
        Some(synthetic_v4),
        None,
        &synthetic_target,
        b"query",
        1_392,
        &metrics,
    )
    .expect("synthetic DNS plan");
    assert!(matches!(synthetic, TunUdpPlan::SyntheticDns));

    let direct_target = TargetAddr::ip("192.0.2.60:443".parse().unwrap()).unwrap();
    let proxy_target = TargetAddr::ip("192.0.2.61:443".parse().unwrap()).unwrap();
    let first = select_udp_target(
        &routing,
        inbound,
        Some(synthetic_v4),
        None,
        &direct_target,
        b"direct-a",
        1_392,
        &metrics,
    )
    .expect("first ordinary plan");
    let TunUdpPlan::Route {
        snapshot: frozen,
        request_payload_bound: frozen_bound,
        ..
    } = first
    else {
        panic!("first ordinary target must select Direct");
    };
    assert_eq!(frozen.hops(), &[1]);

    let encoded = metrics.encode_text().expect("route-once metrics");
    assert!(
        encoded.lines().any(|line| {
            line.starts_with("ferrum2_rule_program_candidate_count_count{program=\"route\"}")
                && line.ends_with(" 1")
        }),
        "synthetic DNS plus the first ordinary target must invoke the router once\n{encoded}"
    );

    let verification_metrics = ferrum2_observability::Metrics::new();
    let independently_selected_second = select_udp_target(
        &routing,
        inbound,
        Some(synthetic_v4),
        None,
        &proxy_target,
        b"proxy-b",
        1_392,
        &verification_metrics,
    )
    .expect("independent target-B policy witness");
    let TunUdpPlan::Route {
        snapshot: independently_selected_second,
        request_payload_bound: proxy_bound,
        ..
    } = independently_selected_second
    else {
        panic!("target B proxy route");
    };
    assert_eq!(independently_selected_second.hops(), &[0]);
    assert_eq!(frozen.hops(), &[1]);
    assert!(
        frozen_bound > proxy_bound,
        "Direct and proxy should retain distinct plan limits"
    );
    assert!(target_payload_within_bound(proxy_bound + 1, frozen_bound));
}
