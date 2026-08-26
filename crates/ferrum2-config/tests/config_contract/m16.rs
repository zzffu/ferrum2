use super::support::*;

#[test]
fn m16_direct_only_client_omits_global_credentials_and_compiles_static_plan() {
    let source = "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"exit\"\n[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n";
    let config = validated_client(TempConfig::text(source).path()).expect("direct-only client");

    assert_eq!(config.outbounds.len(), 1);
    assert_eq!(final_plan(&config.route).hops(), &[0]);
    let error = validated_client(
        TempConfig::text(&format!(
            "{source}[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
        ))
        .path(),
    )
    .err()
    .expect("client root credentials are rejected");
    assert_eq!(error.field(), ConfigField::Config);
}

#[test]
fn m16_client_outbound_shape_and_direct_plan_roots_are_closed() {
    let credentials = "method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";
    let missing_type = format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\nserver = \"[::1]:8388\"\n{credentials}"
    );
    assert_eq!(
        validated_client(TempConfig::text(&missing_type).path())
            .err()
            .expect("outbound type is mandatory")
            .field(),
        ConfigField::OutboundsType
    );
    let source = missing_type.replace(
        "tag = \"proxy\"\nserver",
        "tag = \"proxy\"\ntype = \"shadowsocks\"\nserver",
    );
    let config = validated_client(TempConfig::text(&source).path()).expect("proxy shape");
    assert_eq!(
        config.outbounds[0].server(),
        Some("[::1]:8388".parse().unwrap())
    );
    assert_eq!(
        config.outbounds[0].method(),
        Some(MethodProfile::Blake3Aes128Gcm2022)
    );

    for (name, extra, field) in [
        (
            "server",
            "server = \"127.0.0.1:8388\"\n",
            ConfigField::OutboundsServer,
        ),
        (
            "method",
            "method = \"2022-blake3-aes-128-gcm\"\n",
            ConfigField::OutboundsMethod,
        ),
        (
            "psk",
            "psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
            ConfigField::OutboundsPsk,
        ),
        (
            "all direct fields",
            "server = \"127.0.0.1:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
            ConfigField::OutboundsServer,
        ),
        ("unknown", "type = \"DIRECT\"\n", ConfigField::OutboundsType),
    ] {
        let type_line = if name == "unknown" {
            ""
        } else {
            "type = \"direct\"\n"
        };
        let source = format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"exit\"\n[[outbounds]]\ntag = \"exit\"\n{type_line}{extra}"
        );
        let error = validated_client(TempConfig::text(&source).path())
            .err()
            .expect(name);
        assert_eq!(
            (error.kind(), error.field()),
            (ConfigErrorKind::Semantic, field),
            "{name}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "error[config.semantic] {}: configuration value is invalid",
                field.as_str()
            )
        );
    }

    let missing_server = format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\n{credentials}"
    );
    let error = validated_client(TempConfig::text(&missing_server).path())
        .err()
        .expect("missing server");
    assert_eq!(error.field(), ConfigField::OutboundsServer);

    let explicit_without_global = "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"127.0.0.1:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";
    validated_client(TempConfig::text(explicit_without_global).path())
        .expect("explicit outbound credentials are self-contained");

    for hops in [["exit", "proxy"], ["proxy", "exit"]] {
        let source = format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"chain\"\n[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"127.0.0.1:8388\"\n{credentials}[[chains]]\ntag = \"chain\"\nhops = [\"{}\", \"{}\"]\n",
            hops[0], hops[1]
        );
        let error = validated_client(TempConfig::text(&source).path())
            .err()
            .expect("direct chain hop");
        assert_eq!(error.field(), ConfigField::ChainsHops);
    }

    #[rustfmt::skip]
    let source = format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"static\"\nlisten = \"127.0.0.1:1080\"\n[[inbounds]]\ntag = \"routed\"\nlisten = \"127.0.0.1:1081\"\n[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"127.0.0.1:8388\"\n{credentials}[[selectors]]\ntag = \"manual\"\noutbounds = [\"exit\", \"proxy\"]\ndefault = \"exit\"\n[route]\nfinal = \"manual\"\n[[route.rules]]\ninbound = \"routed\"\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"exit\"\n[dns]\n[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"dns-up\"\ntransport = \"udp\"\naddress = \"1.1.1.1:53\"\ndetour = \"exit\"\n[dns.route]\nfinal = \"dns-up\"\n"
    );
    let config = validated_client(TempConfig::text(&source).path()).expect("all direct roots");
    let target = TargetAddr::domain("direct.test", 443).unwrap();
    assert_eq!(
        selected_plan(&config.route, 1, Network::Tcp, &target).hops(),
        &[0]
    );
    assert_eq!(final_plan(&config.route).hops(), &[0]);
    assert_eq!(
        config.dns.as_ref().unwrap().servers[0]
            .detour
            .as_ref()
            .unwrap()
            .snapshot()
            .hops(),
        &[0]
    );
    config.selector_control().switch("manual", "proxy").unwrap();
    assert_eq!(
        selected_plan(&config.route, 0, Network::Udp, &target).hops(),
        &[1]
    );
}

#[test]
fn m16_managed_tun_compiles_bounded_canonical_capture_and_dns_plan() {
    let base = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\noutbound = \"proxy\"";
    let unmanaged =
        validated_client(TempConfig::text(&tun_client(base)).path()).expect("unmanaged");
    let tun = unmanaged.tun.unwrap();
    assert!(!tun.auto_route);
    assert!(!tun.auto_dns);
    assert!(tun.capture_routes.is_empty());
    assert!(tun.ipv4_dns_address.is_none());
    assert!(tun.physical_endpoints.is_empty());

    let managed = tun_client(&base.replace("outbound =", "auto_route = true\noutbound ="));
    let tun = validated_client(TempConfig::text(&managed).path())
        .expect("managed defaults")
        .tun
        .unwrap();
    assert_eq!(
        tun.capture_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
    );
    assert_eq!(tun.physical_endpoints, ["192.0.2.10:8388".parse().unwrap()]);

    let ordered = base.replace(
        "outbound =",
        "auto_route = true\nroute_address = [\"192.168.0.0/16\", \"10.0.0.0/8\"]\nroute_exclude_address = [\"10.0.0.0/9\", \"203.0.113.0/24\"]\noutbound =",
    );
    let reversed = ordered
        .replace(
            "[\"192.168.0.0/16\", \"10.0.0.0/8\"]",
            "[\"10.0.0.0/8\", \"192.168.0.0/16\"]",
        )
        .replace(
            "[\"10.0.0.0/9\", \"203.0.113.0/24\"]",
            "[\"203.0.113.0/24\", \"10.0.0.0/9\"]",
        );
    for source in [ordered, reversed] {
        let tun = validated_client(TempConfig::text(&tun_client(&source)).path())
            .expect("canonical plan")
            .tun
            .unwrap();
        assert_eq!(
            tun.capture_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.128.0.0/9", "192.168.0.0/16"]
        );
    }

    let dns = "[dns]\n[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"resolver\"\ntransport = \"udp\"\naddress = \"1.1.1.1:53\"\n[dns.route]\nfinal = \"resolver\"";
    let auto_dns = tun_client(&base.replace(
        "outbound =",
        &format!(
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.0.1\"\noutbound = \"proxy\"\n{dns}\n#"
        ),
    ));
    let tun = validated_client(TempConfig::text(&auto_dns).path())
        .expect("auto DNS")
        .tun
        .unwrap();
    assert!(tun.auto_dns);
    assert_eq!(tun.ipv4_dns_address, Some("198.18.0.1".parse().unwrap()));
}

#[test]
fn m16_managed_tun_omits_loopback_physical_first_hops() {
    let base = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\noutbound = \"proxy\"";
    for server in ["127.0.0.1:8388", "[::1]:8388", "[::ffff:127.0.0.1]:8388"] {
        let source = tun_client(base).replace("192.0.2.10:8388", server);
        let tun = validated_client(TempConfig::text(&source).path())
            .unwrap_or_else(|error| panic!("loopback first hop {server} failed: {error}"))
            .tun
            .expect("managed TUN");
        assert!(
            tun.physical_endpoints.is_empty(),
            "loopback first hop {server} entered the physical underlay plan"
        );
    }
    let mapped_non_loopback = "[::ffff:192.0.2.10]:8388";
    let source = tun_client(base).replace("192.0.2.10:8388", mapped_non_loopback);
    let tun = validated_client(TempConfig::text(&source).path())
        .expect("mapped non-loopback first hop")
        .tun
        .expect("managed TUN");
    assert_eq!(
        tun.physical_endpoints,
        vec![mapped_non_loopback.parse().expect("mapped endpoint")]
    );
}

#[test]
fn m16_managed_tun_relations_bounds_and_physical_endpoints_fail_closed() {
    let base = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\noutbound = \"proxy\"";
    let managed =
        |fields: &str| tun_client(&base.replace("outbound =", &format!("{fields}\noutbound =")));
    for (name, fields, expected) in [
        (
            "route while disabled",
            "route_address = [\"0.0.0.0/0\"]",
            ConfigField::TunRouteAddress,
        ),
        (
            "exclude while disabled",
            "route_exclude_address = []",
            ConfigField::TunRouteExcludeAddress,
        ),
        (
            "empty include",
            "auto_route = true\nroute_address = []",
            ConfigField::TunRouteAddress,
        ),
        (
            "IPv6 include",
            "auto_route = true\nroute_address = [\"::/0\"]",
            ConfigField::TunRouteAddress,
        ),
        (
            "IPv6 exclude",
            "auto_route = true\nroute_exclude_address = [\"::1/128\"]",
            ConfigField::TunRouteExcludeAddress,
        ),
        (
            "empty result",
            "auto_route = true\nroute_address = [\"10.0.0.0/8\"]\nroute_exclude_address = [\"10.0.0.0/8\"]",
            ConfigField::TunRouteAddress,
        ),
        (
            "DNS without route",
            "auto_dns = true\nipv4_dns_address = \"198.18.0.1\"",
            ConfigField::TunAutoDns,
        ),
        (
            "DNS missing address",
            "auto_route = true\nauto_dns = true",
            ConfigField::TunAutoDns,
        ),
        (
            "DNS graph missing",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.0.1\"",
            ConfigField::TunAutoDns,
        ),
        (
            "address while DNS disabled",
            "auto_route = true\nipv4_dns_address = \"198.18.0.1\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "IPv6 DNS",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.0.1\"\nipv6_dns_address = \"fd00::1\"",
            ConfigField::TunIpv6DnsAddress,
        ),
        (
            "DNS local",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.0.2\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "DNS unspecified",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"0.0.0.0\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "DNS loopback",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"127.0.0.1\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "DNS multicast",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"224.0.0.1\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "DNS network",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.0.0\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "DNS broadcast",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.0.3\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "DNS outside",
            "auto_route = true\nauto_dns = true\nipv4_dns_address = \"198.18.1.1\"",
            ConfigField::TunIpv4DnsAddress,
        ),
    ] {
        let error = validated_client(TempConfig::text(&managed(fields)).path())
            .err()
            .unwrap_or_else(|| panic!("{name} passed"));
        assert_eq!(error.field(), expected, "{name}");
        assert!(!format!("{error:?}").contains("198.18"), "{name}");
    }

    let tun = validated_client(
        TempConfig::text(&managed(
            "auto_route = true\nroute_address = [\"10.1.0.0/8\"]",
        ))
        .path(),
    )
    .expect("noncanonical include is normalized")
    .tun
    .unwrap();
    assert_eq!(
        tun.capture_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.0.0.0/8"]
    );

    let includes = (0..65)
        .map(|index| format!("\"10.{index}.0.0/16\""))
        .collect::<Vec<_>>()
        .join(", ");
    let error = validated_client(
        TempConfig::text(&managed(&format!(
            "auto_route = true\nroute_address = [{includes}]"
        )))
        .path(),
    )
    .err()
    .expect("65 includes");
    assert_eq!(error.field(), ConfigField::TunRouteAddress);

    for count in [1, 64] {
        let includes = (0..count)
            .map(|index| format!("\"10.{index}.0.0/16\""))
            .collect::<Vec<_>>()
            .join(", ");
        let tun = validated_client(
            TempConfig::text(&managed(&format!(
                "auto_route = true\nroute_address = [{includes}]"
            )))
            .path(),
        )
        .unwrap_or_else(|error| panic!("{count} includes failed: {error}"))
        .tun
        .unwrap();
        assert_eq!(
            tun.capture_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [if count == 1 {
                "10.0.0.0/16"
            } else {
                "10.0.0.0/10"
            }],
            "{count} includes"
        );
    }

    let exact_output = |extra: &str| {
        let mut excludes = (0..10)
            .map(|index| format!("\"{index}.0.0.1/32\""))
            .collect::<Vec<_>>();
        excludes.push(format!("\"{extra}\""));
        managed(&format!(
            "auto_route = true\nroute_exclude_address = [{}]",
            excludes.join(", ")
        ))
    };
    let tun = validated_client(TempConfig::text(&exact_output("10.0.0.0/18")).path())
        .expect("exactly 256 compiled rows")
        .tun
        .unwrap();
    assert_eq!(tun.capture_routes.len(), 256);
    let error = validated_client(TempConfig::text(&exact_output("10.0.0.0/19")).path())
        .err()
        .expect("257 compiled rows");
    assert_eq!(error.field(), ConfigField::TunRouteAddress);

    for count in [0, 1, 64] {
        let excludes = (0..count)
            .map(|index| format!("\"192.0.2.{index}/32\""))
            .collect::<Vec<_>>()
            .join(", ");
        let tun = validated_client(
            TempConfig::text(&managed(&format!(
                "auto_route = true\nroute_address = [\"10.0.0.0/8\"]\nroute_exclude_address = [{excludes}]"
            )))
            .path(),
        )
        .unwrap_or_else(|error| panic!("{count} excludes failed: {error}"))
        .tun
        .unwrap();
        assert_eq!(
            tun.capture_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.0/8"],
            "{count} excludes"
        );
    }

    let excludes = (0..65)
        .map(|index| format!("\"192.0.2.{index}/32\""))
        .collect::<Vec<_>>()
        .join(", ");
    let error = validated_client(
        TempConfig::text(&managed(&format!(
            "auto_route = true\nroute_exclude_address = [{excludes}]"
        )))
        .path(),
    )
    .err()
    .expect("65 excludes");
    assert_eq!(error.field(), ConfigField::TunRouteExcludeAddress);

    let ipv6_proxy = tun_client(base).replace("192.0.2.10:8388", "[2001:db8::10]:8388");
    let config = validated_client(TempConfig::text(&ipv6_proxy).path()).expect("manual IPv6 proxy");
    assert!(config.tun.unwrap().physical_endpoints.is_empty());
    let tun = validated_client(
        TempConfig::text(&ipv6_proxy.replace("outbound =", "auto_route = true\noutbound =")).path(),
    )
    .expect("managed IPv6 proxy")
    .tun
    .unwrap();
    assert_eq!(
        tun.physical_endpoints,
        ["[2001:db8::10]:8388".parse().unwrap()]
    );

    let dns = "[dns]\n[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"resolver\"\ntransport = \"udp\"\naddress = \"[2001:db8::53]:53\"\n[dns.route]\nfinal = \"resolver\"";
    let manual_dns = tun_client(&format!("{base}\n{dns}"));
    validated_client(TempConfig::text(&manual_dns).path()).expect("manual IPv6 DNS");
    let managed_dns = manual_dns.replace("outbound =", "auto_route = true\noutbound =");
    let tun = validated_client(TempConfig::text(&managed_dns).path())
        .expect("managed direct IPv6 DNS")
        .tun
        .unwrap();
    assert_eq!(
        tun.physical_endpoints,
        [
            "192.0.2.10:8388".parse().unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        ]
    );

    let detoured = managed_dns.replace(
        "address = \"[2001:db8::53]:53\"",
        "address = \"[2001:db8::53]:53\"\ndetour = \"proxy\"",
    );
    let tun = validated_client(TempConfig::text(&detoured).path())
        .expect("logical IPv6 DNS behind IPv4 proxy")
        .tun
        .unwrap();
    assert_eq!(tun.physical_endpoints, ["192.0.2.10:8388".parse().unwrap()]);

    let selector_detoured = detoured.replace(
        "detour = \"proxy\"\n[dns.route]",
        "detour = \"manual\"\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"proxy\"]\ndefault = \"proxy\"\n[dns.route]",
    );
    let tun = validated_client(TempConfig::text(&selector_detoured).path())
        .expect("logical IPv6 DNS behind IPv4 proxy selector")
        .tun
        .unwrap();
    assert_eq!(tun.physical_endpoints, ["192.0.2.10:8388".parse().unwrap()]);

    let selector_ipv6 = "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\noutbound = \"manual\"\n[[outbounds]]\ntag = \"v4\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.10:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[[outbounds]]\ntag = \"v6\"\ntype = \"shadowsocks\"\nserver = \"[2001:db8::10]:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"v4\", \"v6\"]\ndefault = \"v4\"\n";
    let tun = validated_client(TempConfig::text(selector_ipv6).path())
        .expect("selector IPv6 physical first hop")
        .tun
        .unwrap();
    assert_eq!(
        tun.physical_endpoints,
        [
            "192.0.2.10:8388".parse().unwrap(),
            "[2001:db8::10]:8388".parse().unwrap()
        ]
    );

    let chained = "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\noutbound = \"chain\"\n[[outbounds]]\ntag = \"outer\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.10:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[[outbounds]]\ntag = \"inner\"\ntype = \"shadowsocks\"\nserver = \"[2001:db8::10]:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[[chains]]\ntag = \"chain\"\nhops = [\"outer\", \"inner\"]\n";
    let tun = validated_client(TempConfig::text(chained).path())
        .expect("logical IPv6 inner hop behind IPv4 first hop")
        .tun
        .unwrap();
    assert_eq!(tun.physical_endpoints, ["192.0.2.10:8388".parse().unwrap()]);
}
