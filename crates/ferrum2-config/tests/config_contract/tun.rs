use super::support::*;

#[test]
fn tun_only_static_config_appends_one_validated_ordinary_inbound() {
    let file = TempConfig::text(&tun_client(
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\noutbound = \"proxy\"",
    ));
    let config = validated_client(file.path()).expect("TUN-only config");
    let tun = config.tun.expect("validated TUN");

    assert!(config.inbounds.is_empty(), "TUN is not a SOCKS listener");
    assert_eq!(
        selected(&config.route, 0),
        0,
        "TUN-only ordinary ID is zero"
    );
    assert_eq!(tun.adapter_name.as_ref(), "Ferrum2");
    assert_eq!(
        tun.ipv4_address.expect("IPv4 address").to_string(),
        "198.18.0.2/30"
    );
    assert_eq!(
        tun.ipv6_address.expect("IPv6 address").to_string(),
        "fd00::2/126"
    );
}

#[test]
fn tun_udp_filtering_defaults_to_eif_and_preserves_explicit_choices() {
    assert_eq!(UdpFiltering::default(), UdpFiltering::EndpointIndependent);

    for (name, setting, expected) in [
        ("omitted", "", UdpFiltering::EndpointIndependent),
        (
            "explicit address-dependent",
            "udp_filtering = \"address_dependent\"\n",
            UdpFiltering::AddressDependent,
        ),
        (
            "explicit endpoint-independent",
            "udp_filtering = \"endpoint_independent\"\n",
            UdpFiltering::EndpointIndependent,
        ),
    ] {
        let source = format!(
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\n{setting}outbound = \"proxy\""
        );
        let tun = validated_client(TempConfig::text(&tun_client(&source)).path())
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .tun
            .expect(name);
        assert_eq!(tun.udp_filtering, expected, "{name}");
    }
}

#[test]
fn tun_strict_route_retains_the_request_and_is_effective_only_with_auto_route() {
    for (name, settings, auto_route, requested, effective) in [
        ("omitted defaults", "", false, false, false),
        (
            "both explicitly disabled",
            "auto_route = false\nstrict_route = false\n",
            false,
            false,
            false,
        ),
        (
            "requested without automatic routing",
            "auto_route = false\nstrict_route = true\n",
            false,
            true,
            false,
        ),
        (
            "automatic routing without strict routing",
            "auto_route = true\nstrict_route = false\n",
            true,
            false,
            false,
        ),
        (
            "strict routing effective",
            "auto_route = true\nstrict_route = true\n",
            true,
            true,
            true,
        ),
    ] {
        let source = format!(
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\n{settings}outbound = \"proxy\""
        );
        let tun = validated_client(TempConfig::text(&tun_client(&source)).path())
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .tun
            .expect(name);
        assert_eq!(tun.auto_route, auto_route, "{name}");
        assert_eq!(tun.strict_route, requested, "{name}");
        assert_eq!(tun.strict_route_requested(), requested, "{name}");
        assert_eq!(tun.strict_route_effective(), effective, "{name}");
    }
}

#[test]
fn tun_strict_route_rejects_non_boolean_values() {
    for value in ["\"definitely-not-a-bool\"", "1", "[]"] {
        let source = format!(
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nstrict_route = {value}\noutbound = \"proxy\""
        );
        let error = validated_client(TempConfig::text(&tun_client(&source)).path())
            .err()
            .expect("non-boolean strict_route must fail");
        assert_eq!(error.kind(), ConfigErrorKind::Syntax);
        assert_eq!(error.field(), ConfigField::Config);
        assert!(!format!("{error}\n{error:?}").contains("definitely-not-a-bool"));
    }
}

#[test]
fn tun_optional_families_routes_and_filtering_are_family_exact() {
    let v4 = tun_client(
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nauto_route = true\nudp_filtering = \"address_dependent\"\noutbound = \"proxy\"",
    );
    let tun = validated_client(TempConfig::text(&v4).path())
        .expect("IPv4-only TUN")
        .tun
        .unwrap();
    assert!(tun.ipv4_address.is_some());
    assert!(tun.ipv6_address.is_none());
    assert_eq!(tun.udp_filtering, UdpFiltering::AddressDependent);
    assert_eq!(
        tun.capture_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["0.0.0.0/1", "128.0.0.0/1"]
    );

    let v6_default = tun_client(
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\noutbound = \"proxy\"",
    );
    let tun = validated_client(TempConfig::text(&v6_default).path())
        .expect("IPv6-only default routes")
        .tun
        .unwrap();
    assert!(tun.ipv4_address.is_none());
    assert!(tun.ipv6_address.is_some());
    assert_eq!(
        tun.capture_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["::/1", "8000::/1"]
    );

    let v6_subtracted = tun_client(
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\nroute_address = [\"2001:db8:1::1/48\"]\nroute_exclude_address = [\"2001:db8:1:8000::1/49\"]\noutbound = \"proxy\"",
    );
    let tun = validated_client(TempConfig::text(&v6_subtracted).path())
        .expect("IPv6-only normalized route subtraction")
        .tun
        .unwrap();
    assert!(tun.ipv4_address.is_none());
    assert!(tun.ipv6_address.is_some());
    assert_eq!(
        tun.capture_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["2001:db8:1::/49"]
    );

    let dual = tun_client(
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\nudp_filtering = \"endpoint_independent\"\noutbound = \"proxy\"",
    );
    let tun = validated_client(TempConfig::text(&dual).path())
        .expect("dual-stack EIF TUN")
        .tun
        .unwrap();
    assert_eq!(tun.udp_filtering, UdpFiltering::EndpointIndependent);
    assert_eq!(
        tun.capture_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
    );

    for (name, tun, field) in [
        (
            "neither family",
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\noutbound = \"proxy\"",
            ConfigField::Tun,
        ),
        (
            "IPv6 route in IPv4-only TUN",
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nauto_route = true\nroute_address = [\"::/0\"]\noutbound = \"proxy\"",
            ConfigField::TunRouteAddress,
        ),
        (
            "IPv4 exclude in IPv6-only TUN",
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\nroute_exclude_address = [\"10.0.0.0/8\"]\noutbound = \"proxy\"",
            ConfigField::TunRouteExcludeAddress,
        ),
        (
            "unknown UDP filtering",
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nudp_filtering = \"port_dependent\"\noutbound = \"proxy\"",
            ConfigField::TunUdpFiltering,
        ),
        (
            "IPv6 network interface address",
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv6_address = \"fd00::/126\"\noutbound = \"proxy\"",
            ConfigField::TunIpv6Address,
        ),
    ] {
        let error = validated_client(TempConfig::text(&tun_client(tun)).path())
            .err()
            .unwrap_or_else(|| panic!("{name} passed"));
        assert_eq!(error.field(), field, "{name}");
    }

    for field in [
        "route_guard",
        "on_network_change",
        "dns_mode",
        "udp_mapping",
    ] {
        let source = format!(
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\n{field} = \"disabled\"\noutbound = \"proxy\""
        );
        let error = validated_client(TempConfig::text(&tun_client(&source)).path())
            .err()
            .unwrap_or_else(|| panic!("forbidden {field} passed"));
        assert_eq!(
            (error.kind(), error.field()),
            (ConfigErrorKind::Syntax, ConfigField::Config),
            "{field}"
        );
    }

    let ipv6_endpoint_inside_tun = tun_client(
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\noutbound = \"proxy\"",
    )
    .replace("192.0.2.10:8388", "[fd00::1]:8388");
    let error = validated_client(TempConfig::text(&ipv6_endpoint_inside_tun).path())
        .err()
        .expect("managed IPv6 endpoint inside TUN subnet");
    assert_eq!(error.field(), ConfigField::TunIpv6Address);
}

#[test]
fn tun_synthetic_dns_supports_each_enabled_family_and_rejects_mismatches() {
    let dns = "[dns]\n[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"resolver\"\ntransport = \"udp\"\naddress = \"1.1.1.1:53\"\n[dns.route]\nfinal = \"resolver\"";
    let valid = [
        (
            "IPv4-only DNS",
            "ipv4_address = \"198.18.0.2/30\"",
            "ipv4_dns_address = \"198.18.0.1\"",
            Some("198.18.0.1"),
            None,
        ),
        (
            "IPv6-only DNS",
            "ipv6_address = \"fd00::2/126\"",
            "ipv6_dns_address = \"fd00::1\"",
            None,
            Some("fd00::1"),
        ),
        (
            "dual DNS",
            "ipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"",
            "ipv4_dns_address = \"198.18.0.1\"\nipv6_dns_address = \"fd00::1\"",
            Some("198.18.0.1"),
            Some("fd00::1"),
        ),
    ];
    for (name, addresses, dns_addresses, expected_v4, expected_v6) in valid {
        let source = format!(
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\n{addresses}\nauto_route = true\nauto_dns = true\n{dns_addresses}\noutbound = \"proxy\"\n{dns}"
        );
        let tun = validated_client(TempConfig::text(&tun_client(&source)).path())
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .tun
            .unwrap();
        assert_eq!(
            tun.ipv4_dns_address.map(|address| address.to_string()),
            expected_v4.map(str::to_owned),
            "{name}"
        );
        assert_eq!(
            tun.ipv6_dns_address.map(|address| address.to_string()),
            expected_v6.map(str::to_owned),
            "{name}"
        );
    }

    for (name, addresses, dns_fields, field) in [
        (
            "IPv6 DNS on IPv4-only TUN",
            "ipv4_address = \"198.18.0.2/30\"",
            "ipv6_dns_address = \"fd00::1\"",
            ConfigField::TunIpv6DnsAddress,
        ),
        (
            "IPv4 DNS on IPv6-only TUN",
            "ipv6_address = \"fd00::2/126\"",
            "ipv4_dns_address = \"198.18.0.1\"",
            ConfigField::TunIpv4DnsAddress,
        ),
        (
            "no synthetic DNS",
            "ipv6_address = \"fd00::2/126\"",
            "",
            ConfigField::TunAutoDns,
        ),
        (
            "IPv6 DNS is interface address",
            "ipv6_address = \"fd00::2/126\"",
            "ipv6_dns_address = \"fd00::2\"",
            ConfigField::TunIpv6DnsAddress,
        ),
        (
            "IPv6 DNS is network address",
            "ipv6_address = \"fd00::2/126\"",
            "ipv6_dns_address = \"fd00::\"",
            ConfigField::TunIpv6DnsAddress,
        ),
        (
            "IPv6 DNS is outside subnet",
            "ipv6_address = \"fd00::2/126\"",
            "ipv6_dns_address = \"fd00::5\"",
            ConfigField::TunIpv6DnsAddress,
        ),
    ] {
        let source = format!(
            "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\n{addresses}\nauto_route = true\nauto_dns = true\n{dns_fields}\noutbound = \"proxy\"\n{dns}"
        );
        let error = validated_client(TempConfig::text(&tun_client(&source)).path())
            .err()
            .unwrap_or_else(|| panic!("{name} passed"));
        assert_eq!(error.field(), field, "{name}");
    }
}

#[test]
fn tun_resource_and_shape_failures_are_redacted_and_field_specific() {
    let base = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\noutbound = \"proxy\"";
    let cases = [
        (
            "mtu below",
            base.replace("outbound =", "mtu = 1279\noutbound ="),
            ConfigField::TunMtu,
        ),
        (
            "ring not power of two",
            base.replace("outbound =", "ring_capacity = 131073\noutbound ="),
            ConfigField::TunRingCapacity,
        ),
        (
            "TCP flow zero",
            base.replace("outbound =", "max_tcp_flows = 0\noutbound ="),
            ConfigField::TunMaxTcpFlows,
        ),
        (
            "IPv4 network address",
            base.replace("198.18.0.2/30", "198.18.0.0/30"),
            ConfigField::TunIpv4Address,
        ),
        (
            "IPv6 multicast",
            base.replace("fd00::2/126", "ff02::1/126"),
            ConfigField::TunIpv6Address,
        ),
        (
            "adapter control",
            base.replace("Ferrum2", "Ferrum2\\u0001"),
            ConfigField::TunAdapterName,
        ),
    ];
    for (name, tun, field) in cases {
        let file = TempConfig::text(&tun_client(&tun));
        let error = validated_client(file.path()).err().expect(name);
        assert_eq!(
            (error.kind(), error.field()),
            (ConfigErrorKind::Semantic, field),
            "{name}"
        );
        assert!(!format!("{error:?}").contains("198.18"), "{name}");
    }

    let server = TempConfig::text(&format!(
        "schema_version = 2\n{base}\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"127.0.0.1:8388\"\noutbound = \"direct\"\n[[outbounds]]\ntag = \"direct\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
    ));
    assert_eq!(
        validated_server(server.path())
            .err()
            .expect("server TUN")
            .field(),
        ConfigField::Tun
    );
    let unsupported =
        TempConfig::text(&tun_client(base).replacen("schema_version = 2", "schema_version = 1", 1));
    assert_eq!(
        validated_client(unsupported.path())
            .err()
            .expect("unsupported schema")
            .field(),
        ConfigField::SchemaVersion
    );
}

#[test]
fn removed_tun_udp_memory_field_is_always_unknown() {
    let base = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\noutbound = \"proxy\"";
    for value in ["0", "65536", "134217728", "18446744073709551615"] {
        let source = base.replace(
            "outbound =",
            &format!("max_udp_buffered_bytes = {value}\noutbound ="),
        );
        let error = validated_client(TempConfig::text(&tun_client(&source)).path())
            .err()
            .expect("removed TUN UDP memory field must fail");
        assert_eq!(
            (error.kind(), error.field()),
            (ConfigErrorKind::Syntax, ConfigField::Config)
        );
        let rendered = format!("{error}\n{error:?}");
        assert!(!rendered.contains(value));
    }
}

#[test]
fn tun_every_resource_edge_unknown_field_and_prefix_overlap_fail_closed() {
    let base = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\noutbound = \"proxy\"";
    let minimums = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nmtu = 1280\nring_capacity = 131072\nready_timeout_ms = 1000\nmax_tcp_flows = 1\ntcp_buffer_bytes = 4096\nmax_udp_mappings = 1\noutbound = \"proxy\"";
    let accepted = [
        ("all minima", minimums.to_owned()),
        ("mtu maximum", minimums.replace("mtu = 1280", "mtu = 1500")),
        (
            "ring maximum",
            minimums.replace("ring_capacity = 131072", "ring_capacity = 67108864"),
        ),
        (
            "ready maximum",
            minimums.replace("ready_timeout_ms = 1000", "ready_timeout_ms = 60000"),
        ),
        (
            "flow maximum",
            minimums.replace("max_tcp_flows = 1", "max_tcp_flows = 4096"),
        ),
        (
            "TCP bytes maximum",
            minimums.replace("tcp_buffer_bytes = 4096", "tcp_buffer_bytes = 262144"),
        ),
        (
            "mapping maximum",
            minimums.replace("max_udp_mappings = 1", "max_udp_mappings = 8192"),
        ),
    ];
    for (name, source) in accepted {
        let file = TempConfig::text(&tun_client(&source));
        validated_client(file.path()).unwrap_or_else(|error| panic!("{name}: {error}"));
    }

    let mutations = [
        ("mtu low", "mtu = 1279", ConfigField::TunMtu),
        ("mtu high", "mtu = 1501", ConfigField::TunMtu),
        (
            "ring minimum minus one",
            "ring_capacity = 131071",
            ConfigField::TunRingCapacity,
        ),
        (
            "ring minimum plus one",
            "ring_capacity = 131073",
            ConfigField::TunRingCapacity,
        ),
        (
            "ring maximum minus one",
            "ring_capacity = 67108863",
            ConfigField::TunRingCapacity,
        ),
        (
            "ring maximum plus one",
            "ring_capacity = 67108865",
            ConfigField::TunRingCapacity,
        ),
        (
            "ready low",
            "ready_timeout_ms = 999",
            ConfigField::TunReadyTimeout,
        ),
        (
            "ready high",
            "ready_timeout_ms = 60001",
            ConfigField::TunReadyTimeout,
        ),
        (
            "flows low",
            "max_tcp_flows = 0",
            ConfigField::TunMaxTcpFlows,
        ),
        (
            "flows high",
            "max_tcp_flows = 4097",
            ConfigField::TunMaxTcpFlows,
        ),
        (
            "TCP bytes low",
            "tcp_buffer_bytes = 4095",
            ConfigField::TunTcpBufferBytes,
        ),
        (
            "TCP bytes high",
            "tcp_buffer_bytes = 262145",
            ConfigField::TunTcpBufferBytes,
        ),
        (
            "mappings low",
            "max_udp_mappings = 0",
            ConfigField::TunMaxUdpMappings,
        ),
        (
            "mappings high",
            "max_udp_mappings = 8193",
            ConfigField::TunMaxUdpMappings,
        ),
    ];
    for (name, mutation, field) in mutations {
        let source = base.replace("outbound =", &format!("{mutation}\noutbound ="));
        let file = TempConfig::text(&tun_client(&source));
        assert_eq!(
            validated_client(file.path()).err().expect(name).field(),
            field,
            "{name}"
        );
    }

    validated_client(
        TempConfig::text(&tun_client(
            &base.replace("outbound =", "auto_route = true\noutbound ="),
        ))
        .path(),
    )
    .expect("managed auto-route is recognized");
    let inside = tun_client(base).replace("192.0.2.10:8388", "198.18.0.1:8388");
    validated_client(TempConfig::text(&inside).path()).expect("manual route preserves M15 overlap");
    let managed_inside = inside.replace("outbound =", "auto_route = true\noutbound =");
    assert_eq!(
        validated_client(TempConfig::text(&managed_inside).path())
            .err()
            .expect("managed proxy inside prefix")
            .field(),
        ConfigField::TunIpv4Address
    );

    let chain_collision = tun_client(&base.replace("outbound = \"proxy\"", "outbound = \"tun-in\""))
        .replacen(
            "# graph-anchor",
            "[[outbounds]]\ntag = \"other\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.11:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[[chains]]\ntag = \"tun-in\"\nhops = [\"proxy\", \"other\"]\n# graph-anchor",
            1,
        );
    let selector_collision = tun_client(&base.replace("outbound = \"proxy\"", "outbound = \"tun-in\""))
        .replacen(
            "# graph-anchor",
            "[[outbounds]]\ntag = \"other\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.11:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[[selectors]]\ntag = \"tun-in\"\noutbounds = [\"proxy\", \"other\"]\ndefault = \"proxy\"\n# graph-anchor",
            1,
        );
    let dns_collision = tun_client(base).replacen(
        "# graph-anchor",
        "[dns]\n[[dns.inbounds]]\ntag = \"tun-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"resolver\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"resolver\"\n# graph-anchor",
        1,
    );
    for (name, source) in [
        (
            "ordinary inbound collision",
            tun_client(&format!(
                "[[inbounds]]\ntag = \"tun-in\"\nlisten = \"127.0.0.1:1080\"\n{base}"
            )),
        ),
        (
            "outbound collision",
            tun_client(&base.replace("tag = \"tun-in\"", "tag = \"proxy\"")),
        ),
        ("chain collision", chain_collision),
        ("selector collision", selector_collision),
        ("DNS inbound collision", dns_collision),
    ] {
        let file = TempConfig::text(&source);
        let error = validated_client(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Semantic, "{name}");
        assert!(!format!("{error:?}").contains("198.18"), "{name}");
    }
}

#[test]
fn tun_tcp_sniff_is_narrowly_capable_only_for_the_tun_inbound() {
    let routed = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\n[route]\nfinal = \"proxy\"\n[[route.rules]]\ninbound = \"tun-in\"\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"tls\"\n[[route.rules]]\ninbound = \"tun-in\"\nnetwork = \"tcp\"\nprotocol = \"tls\"\naction = \"reject\"";
    let file = TempConfig::text(&tun_client(routed));
    validated_client(file.path()).expect("TUN-only TCP sniff");

    let tun_only_wildcard = routed.replacen("inbound = \"tun-in\"\nnetwork", "network", 1);
    let file = TempConfig::text(&tun_client(&tun_only_wildcard));
    validated_client(file.path()).expect("TUN-only wildcard TCP sniff");

    for (name, mutation) in [
        (
            "coexistence wildcard",
            routed
                .replacen(
                    "[tun]",
                    "[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\n[tun]",
                    1,
                )
                .replacen("inbound = \"tun-in\"\nnetwork", "network", 1),
        ),
        (
            "mixed SOCKS and TUN",
            routed
                .replacen(
                    "[tun]",
                    "[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\n[tun]",
                    1,
                )
                .replacen(
                    "inbound = \"tun-in\"",
                    "inbound = [\"socks\", \"tun-in\"]",
                    1,
                ),
        ),
    ] {
        let file = TempConfig::text(&tun_client(&mutation));
        assert_eq!(
            validated_client(file.path()).err().expect(name).field(),
            ConfigField::RouteRulesAction,
            "{name}"
        );
    }
}
