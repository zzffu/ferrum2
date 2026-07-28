#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::net::TcpStream;

use local_support::{
    TCP_METHOD_CONFIGS, reserve_loopback, rewrite_config_method, run_binary, unused_loopback,
    write_client_config, write_server_config,
};

const CLIENT_BASE: &str = "schema_version = 1\n\
    [client]\n\
    listen = \"127.0.0.1:1080\"\n\
    server = \"127.0.0.1:8388\"\n\
    [shadowsocks]\n\
    method = \"2022-blake3-aes-128-gcm\"\n\
    psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

const SERVER_BASE: &str = "schema_version = 1\n\
    [server]\n\
    listen = \"127.0.0.1:8388\"\n\
    [shadowsocks]\n\
    method = \"2022-blake3-aes-128-gcm\"\n\
    psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

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
    let (server_listener, server_address) = reserve_loopback();
    let (client_metrics, client_metrics_address) = reserve_loopback();
    let (server_metrics, server_metrics_address) = reserve_loopback();
    let client = write_client_config(
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
}

#[test]
fn invalid_matrix_is_redacted_and_uses_exit_two() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let sentinel = "M0_PROCESS_SECRET_SENTINEL";
    let cases = [
        (
            "client-missing-schema",
            "ferrum2-client",
            CLIENT_BASE.replacen("schema_version = 1\n", "", 1),
            "error[config.syntax] config: configuration is not valid schema version 1 TOML\n",
        ),
        (
            "client-unknown-field",
            "ferrum2-client",
            CLIENT_BASE.replacen(
                "server = \"127.0.0.1:8388\"\n",
                "server = \"127.0.0.1:8388\"\nunexpected = 1\n",
                1,
            ),
            "error[config.syntax] config: configuration is not valid schema version 1 TOML\n",
        ),
        (
            "client-runtime-range",
            "ferrum2-client",
            format!("{CLIENT_BASE}[runtime]\nmax_connections = 0\n"),
            "error[config.semantic] runtime.max_connections: configuration value is invalid\n",
        ),
        (
            "client-endpoint-collision",
            "ferrum2-client",
            CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:8388", 1),
            "error[config.semantic] client.server: configuration value is invalid\n",
        ),
        (
            "client-unknown-method",
            "ferrum2-client",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "future-method", 1),
            "error[config.semantic] shadowsocks.method: configuration value is invalid\n",
        ),
        (
            "client-aes256-short-psk",
            "ferrum2-client",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", 1),
            "error[config.semantic] shadowsocks.psk: configuration value is invalid\n",
        ),
        (
            "client-secret",
            "ferrum2-client",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", sentinel, 1),
            "error[config.semantic] shadowsocks.psk: configuration value is invalid\n",
        ),
        (
            "client-metrics-non-loopback",
            "ferrum2-client",
            format!("{CLIENT_BASE}[metrics]\nlisten = \"192.0.2.1:9090\"\n"),
            "error[config.semantic] metrics.listen: configuration value is invalid\n",
        ),
        (
            "server-wrong-role",
            "ferrum2-server",
            SERVER_BASE.replacen("[server]", "[client]", 1),
            "error[config.syntax] config: configuration is not valid schema version 1 TOML\n",
        ),
        (
            "server-replay-range",
            "ferrum2-server",
            format!("{SERVER_BASE}[replay]\ncapacity = 1023\n"),
            "error[config.semantic] replay.capacity: configuration value is invalid\n",
        ),
        (
            "server-metrics-collision",
            "ferrum2-server",
            format!("{SERVER_BASE}[metrics]\nlisten = \"127.0.0.1:8388\"\n"),
            "error[config.semantic] metrics.listen: configuration value is invalid\n",
        ),
    ];

    for (name, binary, source, expected_stderr) in cases {
        let path = directory.path().join(format!("{name}.toml"));
        std::fs::write(&path, source).expect("invalid config");
        assert_invalid(binary, &path, expected_stderr, sentinel);
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
