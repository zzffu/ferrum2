use super::support::*;

#[test]
fn route_network_defaults_and_combinations_are_role_neutral() {
    let client =
        validated_client(TempConfig::text(CLIENT_BASE).path()).expect("client route defaults");
    assert!(!client.route_network.auto_detect_interface);
    assert_eq!(client.route_network.default_interface(), None);
    let server =
        validated_server(TempConfig::text(SERVER_BASE).path()).expect("server route defaults");
    assert!(!server.route_network.auto_detect_interface);
    assert_eq!(server.route_network.default_interface(), None);

    for (name, settings, auto_detect, default_interface) in [
        (
            "explicit defaults",
            "auto_detect_interface = false\n",
            false,
            None,
        ),
        (
            "automatic only",
            "auto_detect_interface = true\n",
            true,
            None,
        ),
        (
            "fallback only",
            "default_interface = \"Ethernet 2\"\n",
            false,
            Some("Ethernet 2"),
        ),
        (
            "automatic with fallback",
            "auto_detect_interface = true\ndefault_interface = \"Wi-Fi Ω\"\n",
            true,
            Some("Wi-Fi Ω"),
        ),
    ] {
        let route = format!("[route]\n{settings}final = \"o0\"");
        for role in [ConfigRole::Client, ConfigRole::Server] {
            let source = match role {
                ConfigRole::Client => routed(tagged_client(1, 1), &route),
                ConfigRole::Server => routed(tagged_server(1, 1), &route),
            };
            let actual = match role {
                ConfigRole::Client => {
                    let config = validated_client(TempConfig::text(&source).path())
                        .unwrap_or_else(|error| panic!("{name} client: {error}"));
                    (
                        config.route_network.auto_detect_interface,
                        config.route_network.default_interface,
                    )
                }
                ConfigRole::Server => {
                    let config = validated_server(TempConfig::text(&source).path())
                        .unwrap_or_else(|error| panic!("{name} server: {error}"));
                    (
                        config.route_network.auto_detect_interface,
                        config.route_network.default_interface,
                    )
                }
            };
            assert_eq!(actual.0, auto_detect, "{name}");
            assert_eq!(actual.1.as_deref(), default_interface, "{name}");
        }
    }
}

#[test]
fn outbound_dial_options_default_and_apply_to_socket_owning_outbounds() {
    let client =
        validated_client(TempConfig::text(CLIENT_BASE).path()).expect("client dial defaults");
    assert_eq!(
        client.outbounds[0].dial_options(),
        &ferrum2_config::OutboundDialOptions::default()
    );
    let server =
        validated_server(TempConfig::text(SERVER_BASE).path()).expect("server dial defaults");
    assert_eq!(
        server.outbounds[0].dial_options(),
        &ferrum2_config::OutboundDialOptions::default()
    );

    let fields = concat!(
        "bind_interface = \"Ethernet 2\"\n",
        "inet4_bind_address = \"192.0.2.10\"\n",
        "inet6_bind_address = \"2001:db8::10\"\n",
    );
    let client_proxy = CLIENT_BASE.replace(
        "server = \"127.0.0.1:8388\"\n",
        &format!("server = \"127.0.0.1:8388\"\n{fields}"),
    );
    let client_proxy = validated_client(TempConfig::text(&client_proxy).path())
        .expect("client proxy dial options");
    let options = client_proxy.outbounds[0].dial_options();
    assert_eq!(options.bind_interface(), Some("Ethernet 2"));
    assert_eq!(
        options.inet4_bind_address(),
        Some("192.0.2.10".parse().unwrap())
    );
    assert_eq!(
        options.inet6_bind_address(),
        Some("2001:db8::10".parse().unwrap())
    );
    let debug = format!("{options:?}");
    for sensitive in ["Ethernet 2", "192.0.2.10", "2001:db8::10"] {
        assert!(!debug.contains(sensitive));
    }

    let client_direct = CLIENT_BASE.replace(
        "type = \"shadowsocks\"\nserver = \"127.0.0.1:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
        &format!("type = \"direct\"\n{fields}"),
    );
    let client_direct = validated_client(TempConfig::text(&client_direct).path())
        .expect("client Direct dial options");
    assert_eq!(
        client_direct.outbounds[0].dial_options(),
        client_proxy.outbounds[0].dial_options()
    );

    let server_direct =
        SERVER_BASE.replace("tag = \"direct\"\n", &format!("tag = \"direct\"\n{fields}"));
    let server_direct = validated_server(TempConfig::text(&server_direct).path())
        .expect("server Direct dial options");
    assert_eq!(
        server_direct.outbounds[0].dial_options(),
        client_proxy.outbounds[0].dial_options()
    );
}

#[test]
fn outbound_dial_fields_validate_family_interface_and_owner_precisely() {
    for (name, setting, field) in [
        (
            "IPv6 in IPv4 field",
            "inet4_bind_address = \"2001:db8::1\"\n",
            ConfigField::OutboundsInet4BindAddress,
        ),
        (
            "malformed IPv4",
            "inet4_bind_address = \"sensitive-v4-address\"\n",
            ConfigField::OutboundsInet4BindAddress,
        ),
        (
            "IPv4 in IPv6 field",
            "inet6_bind_address = \"192.0.2.1\"\n",
            ConfigField::OutboundsInet6BindAddress,
        ),
        (
            "malformed IPv6",
            "inet6_bind_address = \"sensitive-v6-address\"\n",
            ConfigField::OutboundsInet6BindAddress,
        ),
        (
            "empty interface",
            "bind_interface = \"\"\n",
            ConfigField::OutboundsBindInterface,
        ),
    ] {
        for (role, base, anchor) in [
            (
                ConfigRole::Client,
                CLIENT_BASE,
                "server = \"127.0.0.1:8388\"\n",
            ),
            (ConfigRole::Server, SERVER_BASE, "tag = \"direct\"\n"),
        ] {
            let source = base.replace(anchor, &format!("{anchor}{setting}"));
            let file = TempConfig::text(&source);
            let error = match role {
                ConfigRole::Client => validated_client(file.path()).err(),
                ConfigRole::Server => validated_server(file.path()).err(),
            }
            .unwrap_or_else(|| panic!("{name} passed"));
            assert_eq!(
                (error.kind(), error.field()),
                (ConfigErrorKind::Semantic, field),
                "{name}"
            );
            let rendered = format!("{error}\n{error:?}");
            assert!(!rendered.contains("sensitive-"), "{name}");
        }
    }

    for interface in [
        "x".repeat(257),
        "🛜".repeat(129),
        "private\tinterface".to_owned(),
    ] {
        let source = CLIENT_BASE.replace(
            "server = \"127.0.0.1:8388\"\n",
            &format!("server = \"127.0.0.1:8388\"\nbind_interface = {interface:?}\n"),
        );
        let error = validated_client(TempConfig::text(&source).path())
            .err()
            .expect("invalid outbound interface");
        assert_eq!(error.field(), ConfigField::OutboundsBindInterface);
        assert!(!format!("{error}\n{error:?}").contains(&interface));
    }

    let accepted = "🛜".repeat(128);
    let source = CLIENT_BASE.replace(
        "server = \"127.0.0.1:8388\"\n",
        &format!("server = \"127.0.0.1:8388\"\nbind_interface = {accepted:?}\n"),
    );
    let config =
        validated_client(TempConfig::text(&source).path()).expect("256-unit interface name");
    assert_eq!(
        config.outbounds[0].dial_options().bind_interface(),
        Some(accepted.as_str())
    );

    for (owner, declaration) in [
        (
            "selector",
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"proxy-out\"]\ndefault = \"proxy-out\"\nbind_interface = \"Ethernet\"\n",
        ),
        (
            "chain",
            "[[chains]]\ntag = \"chain\"\nhops = [\"proxy-out\"]\nbind_interface = \"Ethernet\"\n",
        ),
    ] {
        let source =
            CLIENT_BASE.replacen("# graph-anchor", &format!("{declaration}# graph-anchor"), 1);
        let error = validated_client(TempConfig::text(&source).path())
            .err()
            .unwrap_or_else(|| panic!("{owner} accepted outbound dial fields"));
        assert_eq!(
            (error.kind(), error.field()),
            (ConfigErrorKind::Syntax, ConfigField::Config)
        );
    }
}

#[test]
fn route_default_interface_is_bounded_preserved_and_redacted_on_failure() {
    let accepted = ["E".to_owned(), "x".repeat(256), "🛜".repeat(128)];
    for interface in accepted {
        let route = format!("[route]\ndefault_interface = \"{interface}\"\nfinal = \"o0\"");
        let source = routed(tagged_client(1, 1), &route);
        let config = validated_client(TempConfig::text(&source).path())
            .expect("bounded route default interface");
        assert_eq!(
            config.route_network.default_interface(),
            Some(interface.as_str())
        );
    }

    for (name, interface) in [
        ("empty", String::new()),
        ("257 UTF-16 units", "x".repeat(257)),
        ("258 UTF-16 units", "🛜".repeat(129)),
        ("control character", "sensitive-interface\tname".to_owned()),
    ] {
        let route = format!("[route]\ndefault_interface = \"{interface}\"\nfinal = \"o0\"");
        let source = routed(tagged_client(1, 1), &route);
        let error = validated_client(TempConfig::text(&source).path())
            .err()
            .unwrap_or_else(|| panic!("{name} passed"));
        assert_eq!(
            (error.kind(), error.field()),
            (
                ConfigErrorKind::Semantic,
                ConfigField::RouteDefaultInterface
            ),
            "{name}"
        );
        let rendered = format!("{error}\n{error:?}");
        if !interface.is_empty() {
            assert!(!rendered.contains(&interface), "{name}");
        }
    }

    let route = "[route]\nauto_detect_interface = \"enabled\"\nfinal = \"o0\"";
    let source = routed(tagged_client(1, 1), route);
    let error = validated_client(TempConfig::text(&source).path())
        .err()
        .expect("non-boolean automatic interface detection must fail");
    assert_eq!(
        (error.kind(), error.field()),
        (ConfigErrorKind::Syntax, ConfigField::Config)
    );
    assert!(!format!("{error}\n{error:?}").contains("enabled"));
}

#[test]
fn schema_v2_route_rejections_cover_versions_shapes_bounds_and_capabilities() {
    let client = |rules: &str| {
        routed(
            tagged_client(1, 1),
            &format!("[route]\nfinal = \"o0\"\n{rules}"),
        )
    };
    let server = |rules: &str| {
        routed(
            tagged_server(1, 1),
            &format!("[route]\nfinal = \"o0\"\n{rules}"),
        )
    };
    #[rustfmt::skip]
    let cases = vec![
        ("v2 dangling final", ConfigRole::Client, client("").replacen("final = \"o0\"", "final = \"missing\"", 1), ConfigField::RouteFinal),
        ("v2 dangling rule action", ConfigRole::Client, client("[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"missing\""), ConfigField::RouteRulesOutbound),
        ("empty matcher list", ConfigRole::Server, server("[[route.rules]]\nip = []\naction = \"reject\""), ConfigField::RouteRulesIp),
        ("duplicate normalized domain", ConfigRole::Server, server("[[route.rules]]\ndomain = [\"Example.COM.\", \"example.com\"]\naction = \"reject\""), ConfigField::RouteRulesDomain),
        ("normalized empty domain", ConfigRole::Server, server("[[route.rules]]\ndomain = \".\"\naction = \"reject\""), ConfigField::RouteRulesDomain),
        ("duplicate network", ConfigRole::Server, server("[[route.rules]]\nnetwork = [\"tcp\", \"tcp\"]\naction = \"reject\""), ConfigField::RouteRulesNetwork),
        ("duplicate parsed CIDR", ConfigRole::Server, server("[[route.rules]]\nip_cidr = [\"2001:db8::/32\", \"2001:0db8::/32\"]\naction = \"reject\""), ConfigField::RouteRulesIpCidr),
        ("noncanonical CIDR", ConfigRole::Server, server("[[route.rules]]\nip_cidr = \"192.0.2.1/24\"\naction = \"reject\""), ConfigField::RouteRulesIpCidr),
        ("zero port range", ConfigRole::Server, server("[[route.rules]]\nport_range = \"0:53\"\naction = \"reject\""), ConfigField::RouteRulesPortRange),
        ("reversed port range", ConfigRole::Server, server("[[route.rules]]\nport_range = \"54:53\"\naction = \"reject\""), ConfigField::RouteRulesPortRange),
        ("overflow port range", ConfigRole::Server, server("[[route.rules]]\nport_range = \"1:65536\"\naction = \"reject\""), ConfigField::RouteRulesPortRange),
        ("route requires outbound", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\""), ConfigField::RouteRulesOutbound),
        ("route forbids sniffers", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"o0\"\nsniffers = \"tls\""), ConfigField::RouteRulesSniffers),
        ("sniff forbids outbound", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\noutbound = \"o0\""), ConfigField::RouteRulesOutbound),
        ("reject forbids sniffers", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\naction = \"reject\"\nsniffers = \"tls\""), ConfigField::RouteRulesSniffers),
        ("absent action is rejected", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\""), ConfigField::RouteRulesAction),
        ("unconditional terminal is unreachable", ConfigRole::Server, server("[[route.rules]]\naction = \"reject\""), ConfigField::RouteRules),
        ("unknown sniffer", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"quic\""), ConfigField::RouteRulesSniffers),
        ("sniff timeout below range", ConfigRole::Server, server("").replacen("[[route.rules]]", "[route.sniff]\ntimeout_ms = 9\n[[route.rules]]", 1).replacen("[shadowsocks]", "[route.sniff]\ntimeout_ms = 9\n[shadowsocks]", 1), ConfigField::RouteSniffTimeout),
        ("sniff bytes above range", ConfigRole::Server, server("").replacen("[shadowsocks]", "[route.sniff]\nmax_bytes = 16385\n[shadowsocks]", 1), ConfigField::RouteSniffMaxBytes),
        ("client TCP sniff", ConfigRole::Client, client("[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"dns\""), ConfigField::RouteRulesAction),
        ("client UDP TLS sniff", ConfigRole::Client, client("[[route.rules]]\nnetwork = \"udp\"\naction = \"sniff\"\nsniffers = \"tls\""), ConfigField::RouteRulesSniffers),
        ("client UDP HTTP sniff", ConfigRole::Client, client("[[route.rules]]\nnetwork = \"udp\"\naction = \"sniff\"\nsniffers = \"http\""), ConfigField::RouteRulesSniffers),
        ("server UDP TLS sniff", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"udp\"\naction = \"sniff\"\nsniffers = \"tls\""), ConfigField::RouteRulesSniffers),
        ("server UDP HTTP sniff", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"udp\"\naction = \"sniff\"\nsniffers = \"http\""), ConfigField::RouteRulesSniffers),
        ("server DNS hijack", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\naction = \"hijack-dns\""), ConfigField::RouteRulesAction),
        ("client hijack without DNS", ConfigRole::Client, client("[[route.rules]]\nnetwork = \"udp\"\naction = \"hijack-dns\""), ConfigField::RouteRulesAction),
        ("protocol without sniff", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"tls\"\naction = \"reject\""), ConfigField::RouteRulesProtocol),
        ("port-narrow sniff cannot cover", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\nport = 443\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"tls\"\naction = \"reject\""), ConfigField::RouteRulesProtocol),
        ("IP-narrow sniff cannot cover", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\nip = \"192.0.2.1\"\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"tls\"\naction = \"reject\""), ConfigField::RouteRulesProtocol),
        ("domain-gated sniff cannot prove metadata", ConfigRole::Server, server("[[route.rules]]\nnetwork = \"tcp\"\ndomain = \"example.test\"\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"tls\"\ndomain = \"example.test\"\naction = \"reject\""), ConfigField::RouteRulesProtocol),
        ("inbound-narrow sniff cannot cover", ConfigRole::Server, routed(tagged_server(2, 1), "[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"i0\"\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"tls\"\naction = \"reject\""), ConfigField::RouteRulesProtocol),
    ];
    for (index, (name, role, source, field)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            100 + index,
        );
    }
}

#[test]
fn removed_composite_target_is_unknown_for_route_and_dns_roles() {
    let client_dns = with_dns(
        tagged_client(1, 1),
        "[dns]\n\
         [[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n\
         [[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n\
         [dns.route]\nfinal = \"s0\"\n\
         [[dns.route.rules]]\ntarget = { host = \"old-client.example\", port = 53 }\nserver = \"s0\"",
    );
    let server_dns = with_dns(
        tagged_server(1, 1),
        "[dns]\n\
         [[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n\
         [dns.route]\nfinal = \"s0\"\n\
         [[dns.route.rules]]\ntarget = { host = \"old-server.example\", port = 443 }\nserver = \"s0\"",
    );
    let cases = [
        (
            "client ordinary route composite target",
            ConfigRole::Client,
            routed(
                tagged_client(1, 1),
                "[route]\nfinal = \"o0\"\n\
                 [[route.rules]]\ntarget = { host = \"old-route.example\", port = 443 }\naction = \"reject\"",
            ),
        ),
        (
            "server ordinary route target subtable",
            ConfigRole::Server,
            routed(
                tagged_server(1, 1),
                "[route]\nfinal = \"o0\"\n\
                 [[route.rules]]\naction = \"reject\"\n\
                 [route.rules.target]\nhost = \"old-subtable.example\"\nport = 443",
            ),
        ),
        (
            "client DNS composite target",
            ConfigRole::Client,
            client_dns,
        ),
        (
            "server DNS composite target",
            ConfigRole::Server,
            server_dns,
        ),
    ];
    for (index, (name, role, source)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Syntax, ConfigField::Config),
            330 + index,
        );
    }
}

#[test]
fn schema_v2_protocol_coverage_uses_the_first_overlapping_sniff() {
    let server = |rules: &str| {
        routed(
            tagged_server(1, 1),
            &format!("[route]\nfinal = \"o0\"\n{rules}"),
        )
    };
    #[rustfmt::skip]
    let cases = [
        (
            "broad DNS sniff blocks later TLS sniff",
            "[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"dns\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"tls\"\naction = \"reject\"",
            Some((ConfigErrorKind::Semantic, ConfigField::RouteRulesProtocol)),
        ),
        (
            "broad TLS sniff blocks later DNS sniff",
            "[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"dns\"\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = \"dns\"\naction = \"reject\"",
            Some((ConfigErrorKind::Semantic, ConfigField::RouteRulesProtocol)),
        ),
        (
            "same-port DNS sniff blocks later TLS sniff",
            "[[route.rules]]\nnetwork = \"tcp\"\nport = 443\naction = \"sniff\"\nsniffers = \"dns\"\n[[route.rules]]\nnetwork = \"tcp\"\nport = 443\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nport = 443\nprotocol = \"tls\"\naction = \"reject\"",
            Some((ConfigErrorKind::Semantic, ConfigField::RouteRulesProtocol)),
        ),
        (
            "disjoint-port DNS sniff does not block TLS sniff",
            "[[route.rules]]\nnetwork = \"tcp\"\nport = 53\naction = \"sniff\"\nsniffers = \"dns\"\n[[route.rules]]\nnetwork = \"tcp\"\nport = 443\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\nnetwork = \"tcp\"\nport = 443\nprotocol = \"tls\"\naction = \"reject\"",
            None,
        ),
        (
            "first sniff may cover a protocol union",
            "[[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = [\"dns\", \"tls\"]\n[[route.rules]]\nnetwork = \"tcp\"\nprotocol = [\"dns\", \"tls\"]\naction = \"reject\"",
            None,
        ),
    ];

    let actual = cases
        .iter()
        .map(|(name, rules, _)| {
            let error = validated_server(TempConfig::text(&server(rules)).path()).err();
            (*name, error.map(|error| (error.kind(), error.field())))
        })
        .collect::<Vec<_>>();
    let expected = cases
        .iter()
        .map(|(name, _, expected)| (*name, *expected))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}
