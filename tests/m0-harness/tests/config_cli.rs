#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io;
use std::net::{SocketAddrV4, TcpListener, TcpStream, UdpSocket};

use local_support::{
    TCP_METHOD_CONFIGS, reserve_loopback, rewrite_config_method, run_binary, unused_loopback,
    write_client_config, write_server_config, write_udp_client_config,
};

const CLIENT_BASE: &str = "schema_version = 1\n[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

const SERVER_BASE: &str = "schema_version = 1\n[server]\nlisten = \"127.0.0.1:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

const PAIRED_PORT_ATTEMPTS: usize = 256;

fn tagged_client(inbounds: &[SocketAddrV4], servers: &[SocketAddrV4]) -> String {
    let mut source = "schema_version = 1\n".to_owned();
    for (index, listen) in inbounds.iter().enumerate() {
        source.push_str(&format!(
            "[[inbounds]]\ntag = \"i{index}\"\nlisten = \"{listen}\"\noutbound = \"o{index}\"\n"
        ));
    }
    for (index, server) in servers.iter().enumerate() {
        source.push_str(&format!(
            "[[outbounds]]\ntag = \"o{index}\"\nserver = \"{server}\"\n"
        ));
    }
    source.push_str(
        "[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
    );
    source
}

fn tagged_server(inbounds: &[SocketAddrV4]) -> String {
    tagged_client(inbounds, inbounds)
        .lines()
        .filter(|line| !line.starts_with("server = "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn routed_tagged(source: String) -> String {
    source
        .lines()
        .filter(|line| !line.starts_with("outbound = "))
        .collect::<Vec<_>>()
        .join("\n")
        .replacen(
            "[shadowsocks]",
            "[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"i0\"\nnetwork = \"tcp\"\ntarget = { host = \"example.test\", port = 443 }\noutbound = \"o1\"\n[shadowsocks]",
            1,
        )
        + "\n"
}

fn reserve_server_tcp_udp() -> (TcpListener, UdpSocket, SocketAddrV4) {
    let mut last_retry = None;
    for _ in 0..PAIRED_PORT_ATTEMPTS {
        let (tcp, address) = reserve_loopback();
        match UdpSocket::bind(address) {
            Ok(udp) => return (tcp, udp, address),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
                ) =>
            {
                last_retry = Some(error);
            }
            Err(error) => panic!("reserve server UDP port {address} failed: {error}"),
        }
    }
    panic!(
        "no paired TCP/UDP loopback port after {PAIRED_PORT_ATTEMPTS} attempts: {}",
        last_retry.expect("at least one retry")
    );
}

#[test]
fn valid_client_and_server_configs_have_exact_offline_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    for method in TCP_METHOD_CONFIGS {
        let client =
            write_client_config(directory.path(), unused_loopback(), unused_loopback(), None)
                .expect("client config");
        let server =
            write_server_config(directory.path(), unused_loopback(), None).expect("server config");
        rewrite_config_method(&client, method).expect("client method");
        rewrite_config_method(&server, method).expect("server method");

        for (binary, config) in [("ferrum2-client", client), ("ferrum2-server", server)] {
            let output = run_binary(
                binary,
                &[
                    "--config",
                    config.to_str().expect("UTF-8 path"),
                    "--check-config",
                ],
            );
            assert_eq!(output.status.code(), Some(0), "{binary}: {}", method.0);
            assert_eq!(
                output.stdout, b"configuration valid\n",
                "{binary}: {}",
                method.0
            );
            assert!(output.stderr.is_empty(), "{binary}: {}", method.0);
        }
    }
}

#[test]
fn no_side_effects_even_when_all_configured_ports_are_occupied() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client_listener, client_address) = reserve_loopback();
    let (server_listener, server_udp, server_address) = reserve_server_tcp_udp();
    let (client_metrics, client_metrics_address) = reserve_loopback();
    let (server_metrics, server_metrics_address) = reserve_loopback();
    let (dns_listener, dns_udp, dns_address) = reserve_server_tcp_udp();
    let client = write_udp_client_config(
        directory.path(),
        client_address,
        server_address,
        Some(client_metrics_address),
    )
    .expect("client config");
    let client_source = std::fs::read_to_string(&client).expect("client source");
    std::fs::write(
        &client,
        format!(
            "{client_source}\n[dns]\n[[dns.inbounds]]\ntag = \"local-dns\"\nlisten = \"{dns_address}\"\n[[dns.servers]]\ntag = \"direct\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"direct\"\n"
        ),
    )
    .expect("client DNS config");
    let server = write_server_config(
        directory.path(),
        server_address,
        Some(server_metrics_address),
    )
    .expect("server config");

    for (binary, config) in [("ferrum2-client", client), ("ferrum2-server", server)] {
        let output = run_binary(
            binary,
            &[
                "--config",
                config.to_str().expect("UTF-8 path"),
                "--check-config",
            ],
        );
        assert_eq!(output.status.code(), Some(0), "{binary}");
        assert_eq!(output.stdout, b"configuration valid\n", "{binary}");
        assert!(output.stderr.is_empty(), "{binary}");
    }

    for listener in [
        client_listener,
        server_listener,
        client_metrics,
        server_metrics,
        dns_listener,
    ] {
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
    assert_eq!(
        dns_udp.local_addr().expect("DNS UDP address"),
        std::net::SocketAddr::V4(dns_address)
    );
}

#[test]
fn schema_v2_check_succeeds_while_client_latch_and_server_runtime_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client_listener, client_address) = reserve_loopback();
    let (server_listener, server_udp, server_address) = reserve_server_tcp_udp();
    let cases = [
        (
            "ferrum2-client",
            CLIENT_BASE
                .replacen("schema_version = 1", "schema_version = 2", 1)
                .replace("127.0.0.1:1080", &client_address.to_string())
                .replace("127.0.0.1:8388", &server_address.to_string()),
            b"error[startup.protocol] process: unable to prepare protocol resources\n".as_slice(),
        ),
        (
            "ferrum2-server",
            SERVER_BASE
                .replacen("schema_version = 1", "schema_version = 2", 1)
                .replace("127.0.0.1:8388", &server_address.to_string()),
            b"error[startup.bind] process: unable to prepare required endpoint\n".as_slice(),
        ),
    ];
    for (binary, source, expected_stderr) in cases {
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
        assert_eq!(run.status.code(), Some(1), "{binary}");
        assert!(run.stdout.is_empty(), "{binary}");
        assert_eq!(run.stderr, expected_stderr, "{binary}");
    }

    let migration_path = directory.path().join("client-v1-routed-udp.toml");
    let migration = routed_tagged(tagged_client(
        &[client_address],
        &[server_address, unused_loopback()],
    )) + "[udp]\nenabled = true\n";
    std::fs::write(&migration_path, migration).expect("migration config");
    for arguments in [
        vec![
            "--config",
            migration_path.to_str().expect("UTF-8 path"),
            "--check-config",
        ],
        vec!["--config", migration_path.to_str().expect("UTF-8 path")],
    ] {
        let output = run_binary("ferrum2-client", &arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"error[config.semantic] schema_version: configuration value is invalid\n"
        );
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
            CLIENT_BASE.replacen("schema_version = 1\n", "", 1),
            None,
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
            Some("client.server"),
        ),
        (
            "client unknown method",
            "ferrum2-client",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "future-method", 1),
            Some("shadowsocks.method"),
        ),
        (
            "client AES256 short PSK",
            "ferrum2-client",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", 1),
            Some("shadowsocks.psk"),
        ),
        (
            "client secret",
            "ferrum2-client",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", sentinel, 1),
            Some("shadowsocks.psk"),
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
            SERVER_BASE.replacen("[server]", "[client]", 1),
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
    #[rustfmt::skip]
    let chain = tagged_client(&[client_address_a], &[server_address_a, server_address_b])
        .replacen("outbound = \"o0\"", "outbound = \"two-hop\"", 1)
        .replacen(&format!("server = \"{server_address_b}\""), &format!("server = \"{server_address_b}\"\nmethod = \"2022-blake3-aes-256-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\""), 1)
        .replacen("[shadowsocks]", "[[chains]]\ntag = \"two-hop\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1);
    std::fs::write(&client_chain_path, chain).expect("client chain config");
    std::fs::write(
        &server_route_path,
        routed_tagged(tagged_server(&[server_address_a, server_address_b])),
    )
    .expect("server routed config");
    let selectors =
        "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n";
    let selector = |source: String| {
        source
            .replace("outbound = \"o0\"", "outbound = \"manual\"")
            .replace("outbound = \"o1\"", "outbound = \"manual\"")
            .replacen("[shadowsocks]", &format!("{selectors}[shadowsocks]"), 1)
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
        assert_eq!(run.status.code(), Some(1), "{binary}");
        assert!(run.stdout.is_empty(), "{binary}");
        assert_eq!(
            run.stderr, b"error[startup.bind] process: unable to prepare required endpoint\n",
            "{binary}"
        );
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
        assert_eq!(run.status.code(), Some(1), "{binary}");
        assert!(run.stdout.is_empty(), "{binary}");
        assert_eq!(
            run.stderr, b"error[startup.bind] process: unable to prepare required endpoint\n",
            "{binary}"
        );
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
        "error[config.semantic] selectors.outbounds: configuration value is invalid\n",
        cycle_sentinel,
    );
    for (name, source, field) in [
        (
            "partial-outbound-credential",
            tagged_client(&[client_address_a], &[server_address_a]).replacen(
                &format!("server = \"{server_address_a}\""),
                &format!("server = \"{server_address_a}\"\nmethod = \"2022-blake3-aes-128-gcm\""),
                1,
            ),
            "outbounds.psk",
        ),
        (
            "invalid-chain-hop",
            tagged_client(&[client_address_a], &[server_address_a, server_address_b])
                .replacen("outbound = \"o0\"", "outbound = \"two-hop\"", 1)
                .replacen("[shadowsocks]", "[[chains]]\ntag = \"two-hop\"\nhops = [\"o0\", \"missing-hop\"]\n[shadowsocks]", 1),
            "chains.hops",
        ),
    ] {
        let path = directory.path().join(format!("{name}.toml"));
        std::fs::write(&path, source).expect(name);
        assert_invalid(
            "ferrum2-client",
            &path,
            &format!("error[config.semantic] {field}: configuration value is invalid\n"),
            if name.starts_with("invalid") { "missing-hop" } else { "2022-blake3-aes-128-gcm" },
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
fn one_entry_tagged_run_matches_legacy_startup_behavior() {
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
    for (binary, legacy, tagged) in cases {
        let legacy_path = directory.path().join(format!("{binary}-legacy.toml"));
        let tagged_path = directory.path().join(format!("{binary}-tagged.toml"));
        std::fs::write(&legacy_path, legacy).expect("legacy config");
        std::fs::write(&tagged_path, tagged).expect("tagged config");
        let legacy = run_binary(
            binary,
            &["--config", legacy_path.to_str().expect("UTF-8 path")],
        );
        let tagged = run_binary(
            binary,
            &["--config", tagged_path.to_str().expect("UTF-8 path")],
        );
        assert_eq!(tagged.status.code(), legacy.status.code(), "{binary}");
        assert_eq!(tagged.stdout, legacy.stdout, "{binary}");
        assert_eq!(tagged.stderr, legacy.stderr, "{binary}");
        assert_eq!(
            tagged.stderr,
            b"error[startup.bind] process: unable to prepare required endpoint\n"
        );
    }
}

fn assert_invalid(binary: &str, path: &std::path::Path, expected_stderr: &str, sentinel: &str) {
    let output = run_binary(
        binary,
        &[
            "--config",
            path.to_str().expect("UTF-8 path"),
            "--check-config",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "{binary}: {}",
        path.display()
    );
    assert!(output.stdout.is_empty(), "{binary}: {}", path.display());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert_eq!(stderr, expected_stderr, "{binary}: {}", path.display());
    assert!(!stderr.contains(sentinel));
    assert!(!stderr.contains("AAECAwQFBgcICQoLDA0ODw=="));
}
