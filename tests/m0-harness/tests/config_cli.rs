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
    let client = write_udp_client_config(
        directory.path(),
        client_address,
        server_address,
        Some(client_metrics_address),
    )
    .expect("client config");
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
}

#[test]
fn invalid_matrix_is_redacted_and_uses_exit_two() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let sentinel = "M0_PROCESS_SECRET_SENTINEL";
    #[rustfmt::skip]
    let cases = [
        ("client missing schema", "ferrum2-client", CLIENT_BASE.replacen("schema_version = 1\n", "", 1), None),
        ("client unknown field", "ferrum2-client", CLIENT_BASE.replacen("server = \"127.0.0.1:8388\"\n", "server = \"127.0.0.1:8388\"\nunexpected = 1\n", 1), None),
        ("client runtime range", "ferrum2-client", format!("{CLIENT_BASE}[runtime]\nmax_connections = 0\n"), Some("runtime.max_connections")),
        ("client endpoint collision", "ferrum2-client", CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:8388", 1), Some("client.server")),
        ("client unknown method", "ferrum2-client", CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "future-method", 1), Some("shadowsocks.method")),
        ("client AES256 short PSK", "ferrum2-client", CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", 1), Some("shadowsocks.psk")),
        ("client secret", "ferrum2-client", CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", sentinel, 1), Some("shadowsocks.psk")),
        ("client metrics non-loopback", "ferrum2-client", format!("{CLIENT_BASE}[metrics]\nlisten = \"192.0.2.1:9090\"\n"), Some("metrics.listen")),
        ("client UDP session range", "ferrum2-client", format!("{CLIENT_BASE}[udp]\nmax_sessions = 0\n"), Some("udp.max_sessions")),
        ("server wrong role", "ferrum2-server", SERVER_BASE.replacen("[server]", "[client]", 1), None),
        ("server replay range", "ferrum2-server", format!("{SERVER_BASE}[replay]\ncapacity = 1023\n"), Some("replay.capacity")),
        ("server metrics collision", "ferrum2-server", format!("{SERVER_BASE}[metrics]\nlisten = \"127.0.0.1:8388\"\n"), Some("metrics.listen")),
        ("server UDP session range", "ferrum2-server", format!("{SERVER_BASE}[udp]\nmax_sessions = 0\n"), Some("udp.max_sessions")),
        ("server UDP buffer range", "ferrum2-server", format!("{SERVER_BASE}[udp]\nmax_buffered_bytes = 1048575\n"), Some("udp.max_buffered_bytes")),
        ("server UDP idle range", "ferrum2-server", format!("{SERVER_BASE}[udp]\nidle_timeout_ms = 59999\n"), Some("udp.idle_timeout_ms")),
    ];

    for (label, binary, source, semantic_field) in cases {
        let path = directory
            .path()
            .join(format!("{}.toml", label.replace(' ', "-")));
        std::fs::write(&path, source).expect("invalid config");
        let expected = semantic_field.map_or_else(
            || {
                "error[config.syntax] config: configuration is not valid schema version 1 TOML\n"
                    .to_owned()
            },
            |field| format!("error[config.semantic] {field}: configuration value is invalid\n"),
        );
        assert_invalid(binary, &path, &expected, sentinel);
    }

    let syntax_path = directory.path().join("invalid-utf8.toml");
    std::fs::write(&syntax_path, [0xff, 0xfe, 0xfd]).expect("invalid UTF-8 config");
    assert_invalid(
        "ferrum2-client",
        &syntax_path,
        "error[config.syntax] config: configuration is not valid schema version 1 TOML\n",
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
