use super::support::*;

#[test]
fn tagged_graph_normalizes_complete_resolved_collections() {
    for (method, psk) in [
        ("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="),
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
        ),
    ] {
        let source = tagged_client(2, 2)
            .replacen("2022-blake3-aes-128-gcm", method, 1)
            .replacen("AAECAwQFBgcICQoLDA0ODw==", psk, 1);
        let config = validated_client(TempConfig::text(&source).path()).expect(method);
        assert_eq!(config.inbounds.len(), 2, "{method}");
        assert_eq!(config.outbounds.len(), 2, "{method}");
        let [
            ClientOutboundConfig::Shadowsocks { psk: first, .. },
            ClientOutboundConfig::Shadowsocks { psk: second, .. },
        ] = config.outbounds.as_slice()
        else {
            panic!("global credentials did not produce two Shadowsocks outbounds");
        };
        assert!(!Arc::ptr_eq(first, second), "{method}");
        assert_eq!(selected(&config.route, 1), 1, "{method}");
        let source = tagged_server(2, 2)
            .replacen("2022-blake3-aes-128-gcm", method, 1)
            .replacen("AAECAwQFBgcICQoLDA0ODw==", psk, 1);
        let config = validated_server(TempConfig::text(&source).path()).expect(method);
        assert_eq!(selected(&config.route, 1), 1, "{method}");
    }

    let shared = tagged_client(2, 1);
    let config = validated_client(TempConfig::text(&shared).path()).expect("shared outbound");
    assert_eq!(selected(&config.route, 0), selected(&config.route, 1));
    let exact_case = tagged_client(1, 1)
        .replacen("outbound = \"o0\"", "outbound = \"O0\"", 1)
        .replacen("tag = \"o0\"", "tag = \"O0\"", 1);
    validated_client(TempConfig::text(&exact_case).path()).expect("exact case-sensitive match");
    let shared_server =
        validated_server(TempConfig::text(&tagged_server(2, 1)).path()).expect("shared direct");
    assert_eq!(selected(&shared_server.route, 0), 0);
    assert_eq!(selected(&shared_server.route, 1), 0);

    let client =
        validated_client(TempConfig::text(&tagged_client(64, 64)).path()).expect("64 client");
    assert_eq!((client.inbounds.len(), client.outbounds.len()), (64, 64));
    let server =
        validated_server(TempConfig::text(&tagged_server(64, 64)).path()).expect("64 server");
    assert_eq!((server.inbounds.len(), server.outbounds.len()), (64, 64));
    assert_eq!(selected(&server.route, 63), 63);
}

#[test]
fn client_credentials_and_fixed_plans_compile_in_order_with_redacted_secret_owners() {
    #[rustfmt::skip]
    let source = tagged_client(1, 3)
        .replacen("outbound = \"o0\"", "outbound = \"three-hop\"", 1)
        .replacen("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"", "method = \"2022-blake3-aes-256-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"", 1)
        .replacen("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"", "method = \"2022-blake3-chacha20-poly1305\"\npsk = \"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\"", 1)
        .replacen("# graph-anchor", "[[chains]]\ntag = \"three-hop\"\nhops = [\"o0\", \"o1\", \"o2\"]\n# graph-anchor", 1);
    let config = validated_client(TempConfig::text(&source).path()).expect("mixed credentials");
    #[rustfmt::skip]
    assert_eq!(config.outbounds.iter().map(|outbound| outbound.method().unwrap()).collect::<Vec<_>>(), [MethodProfile::Blake3Aes256Gcm2022, MethodProfile::Blake3ChaCha20Poly13052022, MethodProfile::Blake3Aes128Gcm2022]);
    let target = TargetAddr::domain("chain.test", 443).expect("target");
    #[rustfmt::skip]
    assert_eq!((selected_plan(&config.route, 0, Network::Tcp, &target).hops(), final_plan(&config.route).hops(), config.outbounds[0].server()), (&[0, 1, 2][..], &[0, 1, 2][..], Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_000)))));
    assert!(
        config
            .outbounds
            .iter()
            .all(|outbound| format!("{outbound:?}")
                == "ClientOutboundConfig::Shadowsocks([redacted])")
    );
}

#[test]
fn selector_graphs_compile_for_both_roles_and_share_live_route_state() {
    let selectors = "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o1\", \"o0\"]\ndefault = \"o0\"\n[[selectors]]\ntag = \"nested\"\noutbounds = [\"manual\"]\ndefault = \"manual\"";
    let static_source = |source: String| {
        with_selectors(
            source
                .replacen("outbound = \"o0\"", "outbound = \"manual\"", 1)
                .replacen("outbound = \"o1\"", "outbound = \"nested\"", 1),
            selectors,
        )
    };
    let client = validated_client(TempConfig::text(&static_source(tagged_client(2, 2))).path())
        .expect("client static");
    let snapshot = client.outbounds[selected(&client.route, 0)].server();
    client.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&client.route, 0), selected(&client.route, 1)),
        (1, 1)
    );
    assert_eq!(snapshot, Some("127.0.0.1:20000".parse().unwrap()));
    assert_eq!(
        client.outbounds[selected(&client.route, 0)].server(),
        Some("127.0.0.1:20001".parse().unwrap())
    );
    let server = validated_server(TempConfig::text(&static_source(tagged_server(2, 2))).path())
        .expect("server static");
    server.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&server.route, 0), selected(&server.route, 1)),
        (1, 1)
    );

    let route = "[route]\nfinal = \"nested\"\n[[route.rules]]\ninbound = \"i0\"\nnetwork = \"tcp\"\naction = \"route\"\noutbound = \"manual\"";
    let routed_source = |source| with_selectors(routed(source, route), selectors);
    let client = validated_client(TempConfig::text(&routed_source(tagged_client(2, 2))).path())
        .expect("client route");
    let configured_default = Some(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        20_000,
    )));
    assert_eq!(client.selector_control().selected("manual"), Ok("o0"));
    #[rustfmt::skip]
    assert_eq!((selected(&client.route, 0), selected(&client.route, 1), final_plan(&client.route).hops()[0]), (0, 0, 0));
    assert_eq!(
        client.outbounds[final_plan(&client.route).hops()[0]].server(),
        configured_default
    );
    client.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&client.route, 0), selected(&client.route, 1)),
        (1, 1)
    );
    assert_eq!(final_plan(&client.route).hops()[0], 1);
    assert_eq!(
        client.outbounds[final_plan(&client.route).hops()[0]].server(),
        Some("127.0.0.1:20001".parse().unwrap())
    );
    let server = validated_server(TempConfig::text(&routed_source(tagged_server(2, 2))).path())
        .expect("server route");
    server.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&server.route, 0), selected(&server.route, 1)),
        (1, 1)
    );
}

#[test]
fn client_selector_generation_advances_only_for_successful_member_changes() {
    let selectors =
        "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"";
    let source = with_selectors(
        tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"manual\"", 1),
        selectors,
    );
    let config = validated_client(TempConfig::text(&source).path()).expect("client selector");
    let control = config.selector_control();
    let observer = config.route.selector_control();
    let initial = observer.generation();

    control.switch("manual", "o0").expect("same member");
    assert_eq!(
        observer.generation(),
        initial,
        "no-op switch changed generation"
    );
    assert!(control.switch("manual", "missing").is_err());
    assert_eq!(
        observer.generation(),
        initial,
        "rejected switch changed generation"
    );

    control.switch("manual", "o1").expect("switch to o1");
    let second = observer.generation();
    assert_ne!(second, initial);
    assert_eq!(observer.selected("manual"), Ok("o1"));
    control.switch("manual", "o1").expect("same o1 member");
    assert_eq!(observer.generation(), second);

    control.switch("manual", "o0").expect("switch back to o0");
    assert_ne!(
        observer.generation(),
        second,
        "switch-back reused generation"
    );
}

#[test]
fn selector_graph_rejects_bounds_members_defaults_cycles_and_inert_nodes_redacted() {
    let base = || tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"manual\"", 1);
    let graph = |selectors: &str| with_selectors(base(), selectors);
    let valid = "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"";
    let selector_65 = (0..65)
        .map(|index| {
            format!("[[selectors]]\ntag = \"s{index}\"\noutbounds = [\"o0\"]\ndefault = \"o0\"\n")
        })
        .collect::<String>();
    let members_65 = (0..65)
        .map(|index| format!("\"m{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let empty = base().replacen(
        "schema_version = 2",
        "schema_version = 2\nselectors = []",
        1,
    );
    let partial = "schema_version = 2\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"manual\"\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\"]\ndefault = \"o0\"\n".to_owned();
    #[rustfmt::skip]
    let cases = [
        ("partial tagged selector", partial, ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("empty selectors", empty, ConfigField::Selectors, ConfigRole::Client),
        ("65 selectors", graph(&selector_65).replacen("outbound = \"manual\"", "outbound = \"s0\"", 1), ConfigField::Selectors, ConfigRole::Client),
        ("empty members", graph("[[selectors]]\ntag = \"manual\"\noutbounds = []\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("65 members", graph(&format!("[[selectors]]\ntag = \"manual\"\noutbounds = [{members_65}]\ndefault = \"m0\"")), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("invalid selector tag", graph("[[selectors]]\ntag = \"bad/tag\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\""), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("duplicate selector tag", graph(&format!("{valid}\n{valid}")), ConfigField::SelectorsTag, ConfigRole::Client),
        ("global selector collision", graph("[[selectors]]\ntag = \"i0\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\""), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("duplicate member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o0\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("dangling member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"missing\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("case mismatched member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"O1\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("inbound member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"i0\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("missing default", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]"), ConfigField::SelectorsDefault, ConfigRole::Client),
        ("dangling default", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"missing\""), ConfigField::SelectorsDefault, ConfigRole::Client),
        ("nonmember default", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\"]\ndefault = \"o1\""), ConfigField::SelectorsDefault, ConfigRole::Client),
        ("unreachable selector", graph(&format!("{valid}\n[[selectors]]\ntag = \"unused\"\noutbounds = [\"o0\"]\ndefault = \"o0\"")), ConfigField::SelectorsTag, ConfigRole::Client),
        ("unreachable concrete", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\"]\ndefault = \"o0\""), ConfigField::OutboundsTag, ConfigRole::Client),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            110 + index,
        );
    }

    #[rustfmt::skip]
    assert_eq!([ConfigField::Selectors, ConfigField::SelectorsTag, ConfigField::SelectorsOutbounds, ConfigField::SelectorsDefault].map(ConfigField::as_str), ["selectors", "selectors.tag", "selectors.outbounds", "selectors.default"]);
}

#[test]
fn outbound_credential_pairs_reject_partial_method_encoding_and_width_redacted() {
    let with_fields = |fields: &str| {
        tagged_client(1, 1).replacen(
            "method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"",
            fields,
            1,
        )
    };
    #[rustfmt::skip]
    let cases = [
        ("method only", with_fields("method = \"2022-blake3-aes-128-gcm\""), ConfigField::OutboundsPsk),
        ("psk only", with_fields("psk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsMethod),
        ("unknown method", with_fields("method = \"future-method\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsMethod),
        ("unpadded", with_fields("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw\""), ConfigField::OutboundsPsk),
        ("noncanonical", with_fields("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODx==\""), ConfigField::OutboundsPsk),
        ("aes128 wide", with_fields("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\""), ConfigField::OutboundsPsk),
        ("aes256 short", with_fields("method = \"2022-blake3-aes-256-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsPsk),
        ("chacha short", with_fields("method = \"2022-blake3-chacha20-poly1305\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsPsk),
    ];
    for (index, (name, source, field)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            ConfigRole::Client,
            source,
            (ConfigErrorKind::Semantic, field),
            150 + index,
        );
    }

    assert_tagged_error(
        "server outbound credentials",
        ConfigRole::Server,
        tagged_server(1, 1).replacen(
            "tag = \"o0\"",
            "tag = \"o0\"\nmethod = \"2022-blake3-aes-128-gcm\"",
            1,
        ),
        (ConfigErrorKind::Syntax, ConfigField::Config),
        159,
    );
}

#[test]
fn chains_reject_all_bounds_namespaces_references_and_inert_nodes_redacted() {
    let chain = |tag: &str, hops: &str| {
        tagged_client(1, 2)
            .replacen("outbound = \"o0\"", &format!("outbound = \"{tag}\""), 1)
            .replacen(
                "# graph-anchor",
                &format!("[[chains]]\ntag = \"{tag}\"\nhops = [{hops}]\n# graph-anchor"),
                1,
            )
    };
    let many = (0..65)
        .map(|index| format!("[[chains]]\ntag = \"c{index}\"\nhops = [\"o0\", \"o1\"]\n"))
        .collect::<String>();
    let selector_hop = chain("c", "\"manual\", \"o1\"").replacen(
        "# graph-anchor",
        "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n# graph-anchor",
        1,
    );
    #[rustfmt::skip]
    let cases = [
        ("empty collection", tagged_client(1, 1).replacen("schema_version = 2", "schema_version = 2\nchains = []", 1), ConfigField::Chains, ConfigRole::Client),
        ("chains missing inbounds", "schema_version = 2\n[[outbounds]]\ntag = \"o0\"\ntype = \"direct\"\n[[outbounds]]\ntag = \"o1\"\ntype = \"direct\"\n[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n".to_owned(), ConfigField::Inbounds, ConfigRole::Client),
        ("chains missing outbounds", "schema_version = 2\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"c\"\n[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n".to_owned(), ConfigField::ChainsHops, ConfigRole::Client),
        ("65 chains", tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"c0\"", 1).replacen("# graph-anchor", &format!("{many}# graph-anchor"), 1), ConfigField::Chains, ConfigRole::Client),
        ("missing tag", tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("# graph-anchor", "[[chains]]\nhops = [\"o0\", \"o1\"]\n# graph-anchor", 1), ConfigField::Chains, ConfigRole::Client),
        ("missing hops", tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("# graph-anchor", "[[chains]]\ntag = \"c\"\n# graph-anchor", 1), ConfigField::ChainsHops, ConfigRole::Client),
        ("empty hops", chain("c", ""), ConfigField::ChainsHops, ConfigRole::Client),
        ("one hop", chain("c", "\"o0\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("nine hops", tagged_client(1, 9).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("# graph-anchor", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\", \"o2\", \"o3\", \"o4\", \"o5\", \"o6\", \"o7\", \"o8\"]\n# graph-anchor", 1), ConfigField::ChainsHops, ConfigRole::Client),
        ("duplicate hop", chain("c", "\"o0\", \"o0\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("unknown hop", chain("c", "\"o0\", \"missing\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("case hop", chain("c", "\"o0\", \"O1\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("inbound hop", chain("c", "\"o0\", \"i0\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("selector hop", selector_hop, ConfigField::ChainsHops, ConfigRole::Client),
        ("chain hop", chain("c0", "\"o0\", \"o1\"").replacen("# graph-anchor", "[[chains]]\ntag = \"c1\"\nhops = [\"c0\", \"o1\"]\n# graph-anchor", 1), ConfigField::ChainsHops, ConfigRole::Client),
        ("invalid chain tag", chain("bad/tag", "\"o0\", \"o1\""), ConfigField::ChainsTag, ConfigRole::Client),
        ("inbound collision", chain("i0", "\"o0\", \"o1\""), ConfigField::ChainsTag, ConfigRole::Client),
        ("outbound collision", chain("o1", "\"o0\", \"o1\""), ConfigField::ChainsTag, ConfigRole::Client),
        ("duplicate chain", chain("c", "\"o0\", \"o1\"").replacen("# graph-anchor", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n# graph-anchor", 1), ConfigField::ChainsTag, ConfigRole::Client),
        ("selector collision", chain("manual", "\"o0\", \"o1\"").replacen("# graph-anchor", "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n# graph-anchor", 1), ConfigField::ChainsTag, ConfigRole::Client),
        ("unreachable chain", tagged_client(1, 2).replacen("# graph-anchor", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n# graph-anchor", 1), ConfigField::ChainsTag, ConfigRole::Client),
        ("unreachable concrete", tagged_client(1, 3).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("# graph-anchor", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n# graph-anchor", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("server chain", tagged_server(1, 1).replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::Chains, ConfigRole::Server),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            170 + index,
        );
    }
    assert_eq!(
        [
            ConfigField::Chains,
            ConfigField::ChainsTag,
            ConfigField::ChainsHops
        ]
        .map(ConfigField::as_str),
        ["chains", "chains.tag", "chains.hops"]
    );
}
