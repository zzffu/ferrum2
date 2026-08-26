#[path = "config_cli_support/mod.rs"]
mod support;

use support::*;

#[test]
fn schema_v2_check_succeeds_and_occupied_runtime_endpoints_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client_listener, client_address) = reserve_loopback();
    let (server_listener, server_udp, server_address) = reserve_server_tcp_udp();
    let cases = [
        (
            "ferrum2-client",
            CLIENT_BASE
                .replace("127.0.0.1:1080", &client_address.to_string())
                .replace("127.0.0.1:8388", &server_address.to_string()),
        ),
        (
            "ferrum2-server",
            SERVER_BASE.replace("127.0.0.1:8388", &server_address.to_string()),
        ),
    ];
    for (binary, source) in cases {
        let path = directory.path().join(format!("{binary}-v2.toml"));
        std::fs::write(&path, source).expect("schema v2 config");
        let checked = run_binary(
            binary,
            &[
                "--config",
                path.to_str().expect("UTF-8 path"),
                "--check-config",
            ],
        );
        assert_eq!(checked.status.code(), Some(0), "{binary}");
        assert_eq!(checked.stdout, b"configuration valid\n", "{binary}");
        assert!(checked.stderr.is_empty(), "{binary}");

        let run = run_binary(binary, &["--config", path.to_str().expect("UTF-8 path")]);
        let _ = assert_startup_bind_failure(&run, binary, &path, binary);
    }

    for listener in [client_listener, server_listener] {
        let address = listener.local_addr().expect("listener address");
        assert!(
            TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1)).is_ok(),
            "pre-existing listener was disturbed"
        );
    }
    assert_eq!(
        server_udp.local_addr().expect("UDP address"),
        std::net::SocketAddr::V4(server_address)
    );
}

#[test]
fn invalid_matrix_is_redacted_and_uses_exit_two() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let sentinel = "M0_PROCESS_SECRET_SENTINEL";
    let cases = [
        (
            "client missing schema",
            "ferrum2-client",
            CLIENT_BASE.replacen("schema_version = 2\n", "", 1),
            Some("schema_version"),
        ),
        (
            "client unknown field",
            "ferrum2-client",
            CLIENT_BASE.replacen(
                "server = \"127.0.0.1:8388\"\n",
                "server = \"127.0.0.1:8388\"\nunexpected = 1\n",
                1,
            ),
            None,
        ),
        (
            "client runtime range",
            "ferrum2-client",
            format!("{CLIENT_BASE}[runtime]\nmax_connections = 0\n"),
            Some("runtime.max_connections"),
        ),
        (
            "client endpoint collision",
            "ferrum2-client",
            CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:8388", 1),
            Some("outbounds.server"),
        ),
        (
            "client unknown method",
            "ferrum2-client",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "future-method", 1),
            Some("outbounds.method"),
        ),
        (
            "client AES256 short PSK",
            "ferrum2-client",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", 1),
            Some("outbounds.psk"),
        ),
        (
            "client secret",
            "ferrum2-client",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", sentinel, 1),
            Some("outbounds.psk"),
        ),
        (
            "client metrics non-loopback",
            "ferrum2-client",
            format!("{CLIENT_BASE}[metrics]\nlisten = \"192.0.2.1:9090\"\n"),
            Some("metrics.listen"),
        ),
        (
            "client UDP session range",
            "ferrum2-client",
            format!("{CLIENT_BASE}[udp]\nmax_sessions = 0\n"),
            Some("udp.max_sessions"),
        ),
        (
            "client DNS timeout range",
            "ferrum2-client",
            format!(
                "{CLIENT_BASE}[dns]\ntimeout_ms = 99\n[[dns.inbounds]]\ntag = \"local-dns\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"direct\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"direct\"\n"
            ),
            Some("dns.timeout_ms"),
        ),
        (
            "server wrong role",
            "ferrum2-server",
            SERVER_BASE.replacen(
                "[[inbounds]]",
                "[server]\nlisten = \"127.0.0.1:8388\"\n[[inbounds]]",
                1,
            ),
            None,
        ),
        (
            "server replay range",
            "ferrum2-server",
            format!("{SERVER_BASE}[replay]\ncapacity = 1023\n"),
            Some("replay.capacity"),
        ),
        (
            "server metrics collision",
            "ferrum2-server",
            format!("{SERVER_BASE}[metrics]\nlisten = \"127.0.0.1:8388\"\n"),
            Some("metrics.listen"),
        ),
        (
            "server UDP session range",
            "ferrum2-server",
            format!("{SERVER_BASE}[udp]\nmax_sessions = 0\n"),
            Some("udp.max_sessions"),
        ),
        (
            "server UDP buffer range",
            "ferrum2-server",
            format!("{SERVER_BASE}[udp]\nmax_buffered_bytes = 1048575\n"),
            Some("udp.max_buffered_bytes"),
        ),
        (
            "server UDP idle range",
            "ferrum2-server",
            format!("{SERVER_BASE}[udp]\nidle_timeout_ms = 59999\n"),
            Some("udp.idle_timeout_ms"),
        ),
    ];

    for (label, binary, source, semantic_field) in cases {
        let path = directory
            .path()
            .join(format!("{}.toml", label.replace(' ', "-")));
        std::fs::write(&path, source).expect("invalid config");
        let expected = semantic_field.map_or_else(
            || "error[config.syntax] config: configuration is not valid TOML\n".to_owned(),
            |field| format!("error[config.semantic] {field}: configuration value is invalid\n"),
        );
        assert_invalid(binary, &path, &expected, sentinel);
    }

    let syntax_path = directory.path().join("invalid-utf8.toml");
    std::fs::write(&syntax_path, [0xff, 0xfe, 0xfd]).expect("invalid UTF-8 config");
    assert_invalid(
        "ferrum2-client",
        &syntax_path,
        "error[config.syntax] config: configuration is not valid TOML\n",
        sentinel,
    );

    let too_large_path = directory.path().join("too-large.toml");
    std::fs::write(&too_large_path, vec![b'#'; 1_048_577]).expect("oversized config");
    assert_invalid(
        "ferrum2-server",
        &too_large_path,
        "error[config.too_large] config: configuration exceeds 1048576 bytes\n",
        sentinel,
    );

    let missing_path = directory.path().join("missing.toml");
    assert_invalid(
        "ferrum2-client",
        &missing_path,
        "error[config.io] config: unable to read configuration\n",
        sentinel,
    );
}

#[test]
fn tagged_check_is_offline_and_multi_run_uses_transition_startup_errors() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client_a, client_address_a) = reserve_loopback();
    let (client_b, client_address_b) = reserve_loopback();
    let (server_a, server_udp_a, server_address_a) = reserve_server_tcp_udp();
    let (server_b, server_udp_b, server_address_b) = reserve_server_tcp_udp();
    let client_path = directory.path().join("client-tagged.toml");
    let server_path = directory.path().join("server-tagged.toml");
    let client_route_path = directory.path().join("client-route.toml");
    let client_chain_path = directory.path().join("client-chain.toml");
    let server_route_path = directory.path().join("server-route.toml");
    let client_selector_path = directory.path().join("client-selector.toml");
    let server_selector_path = directory.path().join("server-selector.toml");
    std::fs::write(
        &client_path,
        tagged_client(
            &[client_address_a, client_address_b],
            &[server_address_a, server_address_b],
        ),
    )
    .expect("client tagged config");
    std::fs::write(
        &server_path,
        tagged_server(&[server_address_a, server_address_b]),
    )
    .expect("server tagged config");
    std::fs::write(
        &client_route_path,
        routed_tagged(tagged_client(
            &[client_address_a, client_address_b],
            &[server_address_a, server_address_b],
        )),
    )
    .expect("client routed config");
    let chain = format!(
        "{}[[chains]]\ntag = \"two-hop\"\nhops = [\"o0\", \"o1\"]\n",
        tagged_client(&[client_address_a], &[server_address_a, server_address_b]).replacen(
            "outbound = \"o0\"",
            "outbound = \"two-hop\"",
            1
        )
    );
    std::fs::write(&client_chain_path, chain).expect("client chain config");
    std::fs::write(
        &server_route_path,
        routed_tagged(tagged_server(&[server_address_a, server_address_b])),
    )
    .expect("server routed config");
    let selectors =
        "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n";
    let selector = |source: String| {
        format!(
            "{}{selectors}",
            source
                .replace("outbound = \"o0\"", "outbound = \"manual\"")
                .replace("outbound = \"o1\"", "outbound = \"manual\"")
        )
    };
    std::fs::write(
        &client_selector_path,
        selector(tagged_client(
            &[client_address_a, client_address_b],
            &[server_address_a, server_address_b],
        )),
    )
    .expect("selector config");
    std::fs::write(
        &server_selector_path,
        selector(tagged_server(&[server_address_a, server_address_b])),
    )
    .expect("selector config");

    for (binary, path) in [
        ("ferrum2-client", &client_path),
        ("ferrum2-client", &client_chain_path),
        ("ferrum2-server", &server_path),
    ] {
        let checked = run_binary(
            binary,
            &[
                "--config",
                path.to_str().expect("UTF-8 path"),
                "--check-config",
            ],
        );
        assert_eq!(checked.status.code(), Some(0), "{binary}");
        assert_eq!(checked.stdout, b"configuration valid\n", "{binary}");
        assert!(checked.stderr.is_empty(), "{binary}");

        let run = run_binary(binary, &["--config", path.to_str().expect("UTF-8 path")]);
        let _ = assert_startup_bind_failure(&run, binary, path, binary);
    }

    for (binary, path) in [
        ("ferrum2-client", &client_route_path),
        ("ferrum2-server", &server_route_path),
        ("ferrum2-client", &client_selector_path),
        ("ferrum2-server", &server_selector_path),
    ] {
        let checked = run_binary(
            binary,
            &[
                "--config",
                path.to_str().expect("UTF-8 path"),
                "--check-config",
            ],
        );
        assert_eq!(checked.status.code(), Some(0), "{binary}");
        assert_eq!(checked.stdout, b"configuration valid\n", "{binary}");
        assert!(checked.stderr.is_empty(), "{binary}");

        let run = run_binary(binary, &["--config", path.to_str().expect("UTF-8 path")]);
        let _ = assert_startup_bind_failure(&run, binary, path, binary);
    }

    let invalid = directory.path().join("client-tagged-invalid.toml");
    std::fs::write(
        &invalid,
        tagged_client(&[client_address_a], &[server_address_a]).replacen(
            "outbound = \"o0\"",
            "outbound = \"dangling\"",
            1,
        ),
    )
    .expect("invalid tagged config");
    assert_invalid(
        "ferrum2-client",
        &invalid,
        "error[config.semantic] inbounds.outbound: configuration value is invalid\n",
        "dangling",
    );
    let server_sentinel = "server_cli_tag_sentinel";
    let invalid = directory.path().join("server-tagged-invalid.toml");
    std::fs::write(
        &invalid,
        format!(
            "{}# {server_sentinel}\n",
            tagged_server(&[server_address_a]).replacen(
                "outbound = \"o0\"",
                &format!("outbound = \"{server_sentinel}\""),
                1,
            )
        ),
    )
    .expect("invalid server tagged config");
    assert_invalid(
        "ferrum2-server",
        &invalid,
        "error[config.semantic] inbounds.outbound: configuration value is invalid\n",
        server_sentinel,
    );
    let route_sentinel = "route_cli_tag_sentinel";
    let invalid = directory.path().join("client-route-invalid.toml");
    std::fs::write(
        &invalid,
        routed_tagged(tagged_client(
            &[client_address_a, client_address_b],
            &[server_address_a, server_address_b],
        ))
        .replacen(
            "outbound = \"o1\"",
            &format!("outbound = \"{route_sentinel}\""),
            1,
        ),
    )
    .expect("invalid routed config");
    assert_invalid(
        "ferrum2-client",
        &invalid,
        "error[config.semantic] route.rules.outbound: configuration value is invalid\n",
        route_sentinel,
    );
    let cycle_sentinel = "selector_cli_cycle_sentinel";
    let invalid = directory.path().join("client-selector-cycle.toml");
    let source = std::fs::read_to_string(&client_selector_path)
        .expect("selector source")
        .replace(
            "outbounds = [\"o0\", \"o1\"]",
            &format!("outbounds = [\"manual\", \"o0\", \"o1\"]\n# {cycle_sentinel}"),
        );
    std::fs::write(&invalid, source).expect("cycle config");
    assert_invalid(
        "ferrum2-client",
        &invalid,
        "error[config.dependency_cycle] config.dependency_cycle: the configuration dependency graph contains a cycle: selector[0] -> selector[0]\n",
        cycle_sentinel,
    );
    for (name, source, field) in
        [
            (
                "partial-outbound-credential",
                tagged_client(&[client_address_a], &[server_address_a]).replacen(
                    "psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
                    "",
                    1,
                ),
                "outbounds.psk",
            ),
            (
                "invalid-chain-hop",
                format!(
                    "{}[[chains]]\ntag = \"two-hop\"\nhops = [\"o0\", \"missing-hop\"]\n",
                    tagged_client(&[client_address_a], &[server_address_a, server_address_b])
                        .replacen("outbound = \"o0\"", "outbound = \"two-hop\"", 1)
                ),
                "chains.hops",
            ),
        ]
    {
        let path = directory.path().join(format!("{name}.toml"));
        std::fs::write(&path, source).expect(name);
        assert_invalid(
            "ferrum2-client",
            &path,
            &format!("error[config.semantic] {field}: configuration value is invalid\n"),
            if name.starts_with("invalid") {
                "missing-hop"
            } else {
                "2022-blake3-aes-128-gcm"
            },
        );
    }

    for listener in [client_a, client_b, server_a, server_b] {
        let address = listener.local_addr().expect("listener address");
        assert!(
            TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1)).is_ok(),
            "pre-existing listener was disturbed: {address}"
        );
    }
    assert_eq!(
        server_udp_a.local_addr().expect("UDP A"),
        server_address_a.into()
    );
    assert_eq!(
        server_udp_b.local_addr().expect("UDP B"),
        server_address_b.into()
    );
}

#[test]
fn one_entry_tagged_run_matches_stable_startup_behavior() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (_client_listener, client_address) = reserve_loopback();
    let (_server_listener, _server_udp, server_address) = reserve_server_tcp_udp();
    let cases = [
        (
            "ferrum2-client",
            CLIENT_BASE
                .replace("127.0.0.1:1080", &client_address.to_string())
                .replace("127.0.0.1:8388", &server_address.to_string()),
            tagged_client(&[client_address], &[server_address]),
        ),
        (
            "ferrum2-server",
            SERVER_BASE.replace("127.0.0.1:8388", &server_address.to_string()),
            tagged_server(&[server_address]),
        ),
    ];
    for (binary, baseline, tagged) in cases {
        let baseline_path = directory.path().join(format!("{binary}-baseline.toml"));
        let tagged_path = directory.path().join(format!("{binary}-tagged.toml"));
        std::fs::write(&baseline_path, baseline).expect("baseline config");
        std::fs::write(&tagged_path, tagged).expect("tagged config");
        let baseline = run_binary(
            binary,
            &["--config", baseline_path.to_str().expect("UTF-8 path")],
        );
        let tagged = run_binary(
            binary,
            &["--config", tagged_path.to_str().expect("UTF-8 path")],
        );
        assert_eq!(tagged.status.code(), baseline.status.code(), "{binary}");
        assert_eq!(tagged.stdout, baseline.stdout, "{binary}");
        let baseline_report =
            assert_startup_bind_failure(&baseline, binary, &baseline_path, binary);
        let tagged_report = assert_startup_bind_failure(&tagged, binary, &tagged_path, binary);
        match (baseline_report, tagged_report) {
            (Some(baseline), Some(tagged)) => assert_eq!(
                stable_client_startup_bind_semantics(&tagged),
                stable_client_startup_bind_semantics(&baseline),
                "{binary} stable startup semantics"
            ),
            (None, None) => assert_eq!(tagged.stderr, baseline.stderr, "{binary}"),
            _ => panic!("{binary} startup report shape changed between configurations"),
        }
    }
}
