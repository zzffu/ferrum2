use super::support::*;

#[test]
fn schema_v2_dns_rejects_role_mixing_closed_values_and_bounds() {
    let client = |rule: &str, version: u32| {
        let rule = if rule.contains("[[dns.route.rules]]") && !rule.contains("action =") {
            rule.replace("server =", "action = \"route\"\nserver =")
        } else {
            rule.to_owned()
        };
        with_dns(
            tagged_client(1, 1).replacen(
                "schema_version = 2",
                &format!("schema_version = {version}"),
                1,
            ),
            &format!(
                "[dns]\n[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"s0\"\n{rule}"
            ),
        )
    };
    let server = |rule: &str| {
        let rule = if rule.contains("[[dns.route.rules]]") && !rule.contains("action =") {
            rule.replace("server =", "action = \"route\"\nserver =")
        } else {
            rule.to_owned()
        };
        with_dns(
            tagged_server(1, 1),
            &format!(
                "[dns]\n[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"s0\"\n{rule}"
            ),
        )
    };
    let values = (0..65)
        .map(|index| format!("\"q{index}.example\""))
        .collect::<Vec<_>>()
        .join(", ");
    validated_client(
        TempConfig::text(&client(
            &format!("[[dns.route.rules]]\nqname = [{values}]\nserver = \"s0\""),
            2,
        ))
        .path(),
    )
    .expect("more than 64 DNS matcher values");
    #[rustfmt::skip]
    let cases = vec![
        ("client rejects server domain", ConfigRole::Client, client("[[dns.route.rules]]\ndomain = \"example.test\"\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesDomain),
        ("client rejects server port", ConfigRole::Client, client("[[dns.route.rules]]\nport = 53\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesPort),
        ("server rejects client qname", ConfigRole::Server, server("[[dns.route.rules]]\nqname = \"example.test\"\nserver = \"s0\""), ConfigField::DnsRouteRulesQname),
        ("server exposes no qtype", ConfigRole::Server, server("[[dns.route.rules]]\nqtype = \"A\"\nserver = \"s0\""), ConfigField::DnsRouteRulesQtype),
        ("unknown qtype", ConfigRole::Client, client("[[dns.route.rules]]\nqtype = \"AXFR\"\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesQtype),
        ("empty qtype", ConfigRole::Client, client("[[dns.route.rules]]\nqtype = []\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesQtype),
        ("case-insensitive duplicate qtype", ConfigRole::Client, client("[[dns.route.rules]]\nqtype = [\"a\", \"A\"]\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesQtype),
        ("duplicate normalized qname suffix", ConfigRole::Client, client("[[dns.route.rules]]\nqname_suffix = [\"Example.COM.\", \"example.com\"]\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesQnameSuffix),
        ("normalized empty qname", ConfigRole::Client, client("[[dns.route.rules]]\nqname = \".\"\nserver = \"s0\"", 2), ConfigField::DnsRouteRulesQname),
        ("server reversed port range", ConfigRole::Server, server("[[dns.route.rules]]\nport_range = \"54:53\"\nserver = \"s0\""), ConfigField::DnsRouteRulesPortRange),
    ];
    for (index, (name, role, source, field)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            150 + index,
        );
    }
}

#[test]
fn dns_graph_rejects_each_closed_shape_reference_and_loop_field_redacted() {
    let base_dns = r#"[dns]
[[dns.inbounds]]
tag = "d0"
listen = "127.0.0.1:5353"
[[dns.servers]]
tag = "s0"
transport = "udp"
address = "192.0.2.53:53"
[dns.route]
final = "s0""#;
    let client = || with_dns(CLIENT_BASE.to_owned(), base_dns);
    let two_servers = base_dns.replacen(
        "[dns.route]",
        "[[dns.servers]]\ntag = \"s1\"\ntransport = \"tcp\"\naddress = \"192.0.2.54:53\"\n[dns.route]",
        1,
    );
    let many_inbounds = (0..65)
        .map(|index| {
            format!(
                "[[dns.inbounds]]\ntag = \"d{index}\"\nlisten = \"127.0.0.1:{}\"\n",
                40_000 + index
            )
        })
        .collect::<String>();
    let many_servers = (0..65)
        .map(|index| format!("[[dns.servers]]\ntag = \"s{index}\"\ntransport = \"udp\"\naddress = \"192.0.2.53:{}\"\n", 1_000 + index))
        .collect::<String>();
    let many_rules =
        "[[dns.route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\nserver = \"s0\"\n".repeat(65);
    validated_client(
        TempConfig::text(
            &client().replace("final = \"s0\"", &format!("final = \"s0\"\n{many_rules}")),
        )
        .path(),
    )
    .expect("more than 64 DNS rules");
    let doh_client = |server_name: &str, path: &str| {
        client()
            .replace("transport = \"udp\"", "transport = \"doh\"")
            .replace(
                "address = \"192.0.2.53:53\"",
                &format!(
                    "address = \"192.0.2.53:53\"\nserver_name = \"{server_name}\"\npath = \"{path}\""
                ),
            )
    };
    let tagged_detour = |detour: &str| {
        with_dns(
            tagged_client(1, 1),
            &base_dns.replacen(
                "address = \"192.0.2.53:53\"",
                &format!("address = \"192.0.2.53:53\"\ndetour = \"{detour}\""),
                1,
            ),
        )
    };
    #[rustfmt::skip]
    let cases = [
        ("missing client inbounds", client().replace("[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n", ""), ConfigField::DnsInbounds, ConfigRole::Client),
        ("empty client inbounds", with_dns(CLIENT_BASE.to_owned(), "[dns]\ninbounds = []\n[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"s0\""), ConfigField::DnsInbounds, ConfigRole::Client),
        ("65 client inbounds", with_dns(CLIENT_BASE.to_owned(), &format!("[dns]\n{many_inbounds}[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"s0\"")), ConfigField::DnsInbounds, ConfigRole::Client),
        ("missing servers", client().replace("[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n", ""), ConfigField::DnsRouteFinal, ConfigRole::Client),
        ("zero servers", with_dns(CLIENT_BASE.to_owned(), "[dns]\nservers = []\n[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n[dns.route]\nfinal = \"s0\""), ConfigField::DnsRouteFinal, ConfigRole::Client),
        ("65 servers", with_dns(CLIENT_BASE.to_owned(), &format!("[dns]\n[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n{many_servers}[dns.route]\nfinal = \"s0\"")), ConfigField::DnsServers, ConfigRole::Client),
        ("duplicate DNS inbound", client().replacen("[[dns.servers]]", "[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5354\"\n[[dns.servers]]", 1), ConfigField::DnsInboundsTag, ConfigRole::Client),
        ("timeout low", client().replacen("[dns]", "[dns]\ntimeout_ms = 99", 1), ConfigField::DnsTimeout, ConfigRole::Client),
        ("timeout high", client().replacen("[dns]", "[dns]\ntimeout_ms = 30001", 1), ConfigField::DnsTimeout, ConfigRole::Client),
        ("inflight zero", client().replacen("[dns]", "[dns]\nmax_inflight = 0", 1), ConfigField::DnsMaxInflight, ConfigRole::Client),
        ("inflight high", client().replacen("[dns]", "[dns]\nmax_inflight = 4097", 1), ConfigField::DnsMaxInflight, ConfigRole::Client),
        ("inbound global collision", with_dns(tagged_client(1, 1), &base_dns.replace("tag = \"d0\"", "tag = \"i0\"")), ConfigField::DnsInboundsTag, ConfigRole::Client),
        ("inbound socket collision", client().replace("127.0.0.1:5353", "127.0.0.1:1080"), ConfigField::DnsInboundsListen, ConfigRole::Client),
        ("duplicate server", with_dns(CLIENT_BASE.to_owned(), &two_servers.replace("tag = \"s1\"", "tag = \"s0\"")), ConfigField::DnsServersTag, ConfigRole::Client),
        ("unknown transport", client().replace("transport = \"udp\"", "transport = \"quic\""), ConfigField::DnsServersTransport, ConfigRole::Client),
        ("zero bootstrap port", client().replace("192.0.2.53:53", "192.0.2.53:0"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("direct exact loop", client().replace("192.0.2.53:53", "127.0.0.1:5353"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("direct wildcard loop", client().replace("127.0.0.1:5353", "0.0.0.0:5353").replace("192.0.2.53:53", "127.0.0.1:5353"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("plain TLS name", client().replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\nserver_name = \"resolver.example\""), ConfigField::DnsServersServerName, ConfigRole::Client),
        ("DoT missing TLS name", client().replace("transport = \"udp\"", "transport = \"dot\""), ConfigField::DnsServersServerName, ConfigRole::Client),
        ("DoT path", client().replace("transport = \"udp\"", "transport = \"dot\"").replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\nserver_name = \"resolver.example\"\npath = \"/dns-query\""), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH relative path", client().replace("transport = \"udp\"", "transport = \"doh\"").replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\nserver_name = \"resolver.example\"\npath = \"dns-query\""), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH long path", doh_client("resolver.example", &format!("/{}", "a".repeat(1_024))), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH authority path", doh_client("resolver.example", "//resolver.example/dns-query"), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH query path", doh_client("resolver.example", "/dns-query?name=sentinel"), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH fragment path", doh_client("resolver.example", "/dns-query#sentinel"), ConfigField::DnsServersPath, ConfigRole::Client),
        ("malformed TLS identity", doh_client("-invalid.example", "/dns-query"), ConfigField::DnsServersServerName, ConfigRole::Client),
        ("missing route", client().replace("[dns.route]\nfinal = \"s0\"", ""), ConfigField::DnsRoute, ConfigRole::Client),
        ("unknown final", client().replace("final = \"s0\"", "final = \"missing\""), ConfigField::DnsRouteFinal, ConfigRole::Client),
        ("unreachable server", with_dns(CLIENT_BASE.to_owned(), &two_servers), ConfigField::DnsRouteRulesServer, ConfigRole::Client),
        ("unknown route inbound", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\ninbound = \"missing\"\naction = \"route\"\nserver = \"s0\""), ConfigField::DnsRouteRulesInbound, ConfigRole::Client),
        ("unknown route network", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\nnetwork = \"quic\"\naction = \"route\"\nserver = \"s0\""), ConfigField::DnsRouteRulesNetwork, ConfigRole::Client),
        ("unknown rule server", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\nserver = \"missing\""), ConfigField::DnsRouteRulesServer, ConfigRole::Client),
        ("DNS outbound action", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"s0\""), ConfigField::DnsRouteRulesServer, ConfigRole::Client),
        ("unknown detour tag", with_dns(CLIENT_BASE.to_owned(), &base_dns.replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\ndetour = \"unsupported\"")), ConfigField::DnsServersDetour, ConfigRole::Client),
        ("unknown detour", tagged_detour("missing"), ConfigField::DnsServersDetour, ConfigRole::Client),
        ("inbound detour", tagged_detour("i0"), ConfigField::DnsServersDetour, ConfigRole::Client),
        ("DNS server detour", tagged_detour("s0"), ConfigField::DnsServersDetour, ConfigRole::Client),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            250 + index,
        );
    }

    let selector_detour = base_dns.replace(
        "address = \"192.0.2.53:53\"",
        "address = \"192.0.2.53:53\"\ndetour = \"manual\"",
    );
    let invalid_route_with_valid_detour = with_dns(
        with_selectors(
            routed(
                tagged_client(1, 2),
                "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"missing\"",
            ),
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"",
        ),
        &selector_detour,
    );
    assert_tagged_error(
        "ordinary route error wins with valid DNS selector detour",
        ConfigRole::Client,
        invalid_route_with_valid_detour,
        (ConfigErrorKind::Semantic, ConfigField::RouteRulesOutbound),
        289,
    );

    let ordinary_server_action = routed(
        tagged_client(1, 1),
        "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"o0\"\nserver = \"dns\"",
    );
    assert_tagged_error(
        "ordinary server action",
        ConfigRole::Client,
        ordinary_server_action,
        (ConfigErrorKind::Semantic, ConfigField::RouteRulesOutbound),
        290,
    );

    let hop_collision = with_dns(
        tagged_client(1, 1),
        &base_dns.replace("127.0.0.1:5353", "127.0.0.1:20000"),
    );
    assert_tagged_error(
        "DNS listener concrete-hop collision",
        ConfigRole::Client,
        hop_collision,
        (ConfigErrorKind::Semantic, ConfigField::DnsInboundsListen),
        291,
    );
    let server_selector = with_dns(
        with_selectors(
            tagged_server(1, 2)
                .replace("outbound = \"o0\"", "outbound = \"manual\"")
                .replace("outbound = \"o1\"", "outbound = \"manual\""),
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"",
        ),
        &base_dns
            .replace(
                "[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n",
                "",
            )
            .replace(
                "address = \"192.0.2.53:53\"",
                "address = \"192.0.2.53:53\"\ndetour = \"manual\"",
            ),
    );
    let server_selector = validated_server(TempConfig::text(&server_selector).path())
        .expect("server DNS selector detour");
    assert_eq!(
        server_selector.dns.as_ref().unwrap().servers[0]
            .detour
            .as_ref()
            .unwrap()
            .snapshot()
            .hops(),
        &[0]
    );
    server_selector
        .selector_control()
        .switch("manual", "o1")
        .unwrap();
    assert_eq!(
        server_selector.dns.as_ref().unwrap().servers[0]
            .detour
            .as_ref()
            .unwrap()
            .snapshot()
            .hops(),
        &[1]
    );

    let inbounds_64 = (0..64)
        .map(|index| {
            format!(
                "[[dns.inbounds]]\ntag = \"d{index}\"\nlisten = \"127.0.0.1:{}\"\n",
                40_000 + index
            )
        })
        .collect::<String>();
    let servers_64 = (0..64)
        .map(|index| format!("[[dns.servers]]\ntag = \"s{index}\"\ntransport = \"udp\"\naddress = \"192.0.2.53:{}\"\n", 1_000 + index))
        .collect::<String>();
    let rules_64 = (0..63)
        .map(|index| {
            format!("[[dns.route.rules]]\nqname = \"s{index}.example.\"\naction = \"route\"\nserver = \"s{index}\"\n")
        })
        .collect::<String>();
    let maximum = with_dns(
        CLIENT_BASE.to_owned(),
        &format!("[dns]\n{inbounds_64}{servers_64}[dns.route]\nfinal = \"s63\"\n{rules_64}"),
    );
    let maximum = validated_client(TempConfig::text(&maximum).path()).expect("64 DNS identities");
    let maximum = maximum.dns.expect("DNS maximum");
    assert_eq!((maximum.inbounds.len(), maximum.servers.len()), (64, 64));
}

#[test]
fn routed_graph_rejects_mixing_bounds_matchers_and_references_redacted() {
    let base = tagged_client(1, 2);
    #[rustfmt::skip]
    let cases = [
        ("static mixing", format!("{}[route]\nfinal = \"o0\"\n", base), ConfigField::Route),
        ("partial static binding", base.replacen("outbound = \"o0\"\n", "", 1), ConfigField::InboundsOutbound),
        ("missing final", routed(base.clone(), "[route]"), ConfigField::RouteFinal),
        ("dangling final", routed(base.clone(), "[route]\nfinal = \"missing\""), ConfigField::RouteFinal),
        ("wrong final namespace", routed(base.clone(), "[route]\nfinal = \"i0\""), ConfigField::RouteFinal),
        ("empty predicate", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\naction = \"route\"\noutbound = \"o1\""), ConfigField::RouteRules),
        ("unknown network", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"quic\"\naction = \"route\"\noutbound = \"o1\""), ConfigField::RouteRulesNetwork),
        ("dangling inbound", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"missing\"\naction = \"route\"\noutbound = \"o1\""), ConfigField::RouteRulesInbound),
        ("wrong inbound namespace", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"o0\"\naction = \"route\"\noutbound = \"o1\""), ConfigField::RouteRulesInbound),
        ("missing action", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"missing\""), ConfigField::RouteRulesAction),
        ("missing outbound", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\""), ConfigField::RouteRulesOutbound),
        ("wrong outbound namespace", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"i0\""), ConfigField::RouteRulesOutbound),
        ("unreferenced outbound", routed(base.clone(), "[route]\nfinal = \"o0\""), ConfigField::RouteRulesOutbound),
    ];
    for (index, (name, source, field)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            ConfigRole::Client,
            source,
            (ConfigErrorKind::Semantic, field),
            60 + index,
        );
    }

    let too_many =
        "[[route.rules]]\ninbound = \"i0\"\naction = \"route\"\noutbound = \"o1\"\n".repeat(65);
    validated_client(
        TempConfig::text(&routed(
            base,
            &format!("[route]\nfinal = \"o0\"\n{too_many}"),
        ))
        .path(),
    )
    .expect("more than 64 client route rules");
    let server_base = tagged_server(1, 2);
    let server_routed = |route| routed(server_base.clone(), route);
    #[rustfmt::skip]
    let server_cases = [
        ("server static mixing", format!("{server_base}[route]\nfinal = \"o0\"\n"), ConfigField::Route),
        ("server partial static binding", server_base.replacen("outbound = \"o0\"\n", "", 1), ConfigField::InboundsOutbound),
        ("server wrong inbound namespace", server_routed("[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"o0\"\naction = \"route\"\noutbound = \"o1\""), ConfigField::RouteRulesInbound),
        ("server wrong outbound namespace", server_routed("[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"i0\""), ConfigField::RouteRulesOutbound),
        ("server wrong final namespace", server_routed("[route]\nfinal = \"i0\""), ConfigField::RouteFinal),
        ("server unreferenced outbound", server_routed("[route]\nfinal = \"o0\""), ConfigField::RouteRulesOutbound),
    ];
    validated_server(
        TempConfig::text(&server_routed(&format!(
            "[route]\nfinal = \"o0\"\n{}",
            "[[route.rules]]\ninbound = \"i0\"\naction = \"route\"\noutbound = \"o1\"\n".repeat(65)
        )))
        .path(),
    )
    .expect("more than 64 server route rules");
    for (index, (name, source, field)) in server_cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            ConfigRole::Server,
            source,
            (ConfigErrorKind::Semantic, field),
            90 + index,
        );
    }
    let fields = [
        ConfigField::Route,
        ConfigField::RouteRules,
        ConfigField::RouteRulesInbound,
        ConfigField::RouteRulesNetwork,
        ConfigField::RouteRulesOutbound,
        ConfigField::RouteFinal,
    ];
    assert_eq!(
        fields.map(ConfigField::as_str),
        [
            "route",
            "route.rules",
            "route.rules.inbound",
            "route.rules.network",
            "route.rules.outbound",
            "route.final"
        ]
    );
}

#[test]
fn tagged_graph_rejects_invalid_counts_tags_references_and_collisions_redacted() {
    let valid = tagged_client(2, 2);
    let server = tagged_server(2, 2);
    let server_three = tagged_server(3, 3);
    let cases = vec![
        ("empty inbounds", tagged_client(0, 1), ConfigField::Inbounds, ConfigRole::Client),
        ("empty outbounds", tagged_client(1, 0), ConfigField::Outbounds, ConfigRole::Client),
        ("65 inbounds", tagged_client(65, 1), ConfigField::Inbounds, ConfigRole::Client),
        ("65 outbounds", tagged_client(1, 65), ConfigField::Outbounds, ConfigRole::Client),
        ("empty tag", valid.replacen("tag = \"i0\"", "tag = \"\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("long tag", valid.replacen("tag = \"i0\"", &format!("tag = \"{}\"", "a".repeat(65)), 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("non ASCII tag", valid.replacen("tag = \"i0\"", "tag = \"é\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("whitespace tag", valid.replacen("tag = \"i0\"", "tag = \"bad tag\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("invalid tag", valid.replacen("tag = \"i0\"", "tag = \"bad/tag\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("invalid outbound tag", valid.replacen("tag = \"o0\"", "tag = \"bad/tag\"", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("duplicate inbound", valid.replacen("tag = \"i1\"", "tag = \"i0\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("duplicate outbound", valid.replacen("tag = \"o1\"", "tag = \"o0\"", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("global collision", valid.replacen("tag = \"o0\"", "tag = \"i0\"", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("invalid reference", valid.replacen("outbound = \"o0\"", "outbound = \"bad ref\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("dangling reference", valid.replacen("outbound = \"o0\"", "outbound = \"missing\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("wrong namespace", valid.replacen("outbound = \"o0\"", "outbound = \"i0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("case sensitive", valid.replacen("outbound = \"o0\"", "outbound = \"O0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("unreferenced", tagged_client(1, 2), ConfigField::OutboundsTag, ConfigRole::Client),
        ("duplicate listen", valid.replacen("127.0.0.1:10001", "127.0.0.1:10000", 1), ConfigField::InboundsListen, ConfigRole::Client),
        ("client server collision", valid.replacen("127.0.0.1:20000", "127.0.0.1:10000", 1), ConfigField::OutboundsServer, ConfigRole::Client),
        ("client metrics collision", format!("{valid}[metrics]\nlisten = \"127.0.0.1:10001\"\n"), ConfigField::MetricsListen, ConfigRole::Client),
        ("server metrics collision", format!("{server}[metrics]\nlisten = \"127.0.0.1:10001\"\n"), ConfigField::MetricsListen, ConfigRole::Server),
        ("server empty inbounds", tagged_server(0, 1), ConfigField::Inbounds, ConfigRole::Server),
        ("server empty outbounds", tagged_server(1, 0), ConfigField::Outbounds, ConfigRole::Server),
        ("server 65 inbounds", tagged_server(65, 1), ConfigField::Inbounds, ConfigRole::Server),
        ("server 65 outbounds", tagged_server(1, 65), ConfigField::Outbounds, ConfigRole::Server),
        ("server invalid inbound tag", server.replacen("tag = \"i0\"", "tag = \"bad/tag\"", 1), ConfigField::InboundsTag, ConfigRole::Server),
        ("server invalid outbound tag", server.replacen("tag = \"o0\"", "tag = \"bad/tag\"", 1), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server duplicate inbound", server.replacen("tag = \"i1\"", "tag = \"i0\"", 1), ConfigField::InboundsTag, ConfigRole::Server),
        ("server duplicate outbound", server.replacen("tag = \"o1\"", "tag = \"o0\"", 1), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server global collision", server.replacen("tag = \"o0\"", "tag = \"i0\"", 1), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server dangling", server.replacen("outbound = \"o0\"", "outbound = \"missing\"", 1), ConfigField::InboundsOutbound, ConfigRole::Server),
        ("server wrong namespace", server.replacen("outbound = \"o0\"", "outbound = \"i0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Server),
        ("server case sensitive", server.replacen("outbound = \"o0\"", "outbound = \"O0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Server),
        ("server unreferenced", tagged_server(1, 2), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server duplicate listen", server.replacen("127.0.0.1:10001", "127.0.0.1:10000", 1), ConfigField::InboundsListen, ConfigRole::Server),
        ("server first last duplicate", server_three.replacen("127.0.0.1:10002", "127.0.0.1:10000", 1), ConfigField::InboundsListen, ConfigRole::Server),
        ("server metrics first", format!("{server_three}[metrics]\nlisten = \"127.0.0.1:10000\"\n"), ConfigField::MetricsListen, ConfigRole::Server),
        ("server metrics last", format!("{server_three}[metrics]\nlisten = \"127.0.0.1:10002\"\n"), ConfigField::MetricsListen, ConfigRole::Server),
        ("client server last collision", tagged_client(3, 3).replacen("127.0.0.1:20000", "127.0.0.1:10002", 1), ConfigField::OutboundsServer, ConfigRole::Client),
        ("missing inbounds", "schema_version = 2\n[[outbounds]]\ntag = \"o0\"\ntype = \"direct\"\n".to_owned(), ConfigField::Inbounds, ConfigRole::Client),
        ("missing outbounds", "schema_version = 2\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"o0\"\n".to_owned(), ConfigField::Outbounds, ConfigRole::Client),
        ("server missing inbounds", "schema_version = 2\n[[outbounds]]\ntag = \"o0\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Inbounds, ConfigRole::Server),
        ("server missing outbounds", "schema_version = 2\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"o0\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Outbounds, ConfigRole::Server),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            index,
        );
    }

    assert_tagged_error(
        "client removed root rejected",
        ConfigRole::Client,
        format!(
            "{CLIENT_BASE}[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n"
        ),
        (ConfigErrorKind::Syntax, ConfigField::Config),
        48,
    );
    assert_tagged_error(
        "server removed root rejected",
        ConfigRole::Server,
        format!("{SERVER_BASE}[server]\nlisten = \"127.0.0.1:8388\"\n"),
        (ConfigErrorKind::Syntax, ConfigField::Config),
        49,
    );

    let client_unknown = valid.replacen(
        "server = \"127.0.0.1:20000\"",
        "server = \"127.0.0.1:20000\"\nunexpected = true",
        1,
    );
    assert_tagged_error(
        "client nested unknown",
        ConfigRole::Client,
        client_unknown,
        (ConfigErrorKind::Syntax, ConfigField::Config),
        50,
    );
    let server_unknown = server.replacen("tag = \"o0\"", "tag = \"o0\"\nunexpected = true", 1);
    assert_tagged_error(
        "server nested unknown",
        ConfigRole::Server,
        server_unknown,
        (ConfigErrorKind::Syntax, ConfigField::Config),
        51,
    );

    let fields = [
        ConfigField::Inbounds,
        ConfigField::Outbounds,
        ConfigField::InboundsTag,
        ConfigField::InboundsListen,
        ConfigField::InboundsOutbound,
        ConfigField::OutboundsTag,
        ConfigField::OutboundsServer,
    ];
    assert_eq!(
        fields.map(ConfigField::as_str),
        [
            "inbounds",
            "outbounds",
            "inbounds.tag",
            "inbounds.listen",
            "inbounds.outbound",
            "outbounds.tag",
            "outbounds.server"
        ]
    );
}
