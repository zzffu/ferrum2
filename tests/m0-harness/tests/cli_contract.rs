#[path = "../src/local_support/mod.rs"]
mod local_support;

use local_support::{run_binary, unused_loopback, write_client_config, write_server_config};

const STARTUP_BIND_DIAGNOSTIC: &[u8] =
    b"error[startup.bind] process: unable to prepare required endpoint\n";

#[test]
fn help_and_version_use_the_shared_cli_surface() {
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let help = run_binary(binary, &["--help"]);
        assert_eq!(help.status.code(), Some(0), "{binary} --help");
        assert!(help.stderr.is_empty(), "{binary} --help stderr");
        let stdout = String::from_utf8(help.stdout).expect("UTF-8 help");
        assert!(stdout.contains("--config <PATH>"), "{binary}");
        assert!(stdout.contains("--check-config"), "{binary}");

        let version = run_binary(binary, &["--version"]);
        assert_eq!(version.status.code(), Some(0), "{binary} --version");
        assert!(version.stderr.is_empty(), "{binary} --version stderr");
        assert_eq!(
            String::from_utf8(version.stdout).expect("UTF-8 version"),
            format!("{binary} {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn usage_errors_exit_two_without_starting_run_mode() {
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let output = run_binary(binary, &[]);
        assert_eq!(output.status.code(), Some(2), "{binary}");
        assert!(output.stdout.is_empty(), "{binary}");
        assert!(
            String::from_utf8(output.stderr)
                .expect("UTF-8 stderr")
                .starts_with("error:"),
            "{binary}"
        );
    }
}

#[test]
fn valid_run_mode_bind_failure_exits_one() {
    let directory = tempfile::tempdir().expect("temporary directory");
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let occupied =
            std::net::TcpListener::bind(unused_loopback()).expect("occupy proxy listener");
        let listen = match occupied.local_addr().expect("occupied address") {
            std::net::SocketAddr::V4(address) => address,
            std::net::SocketAddr::V6(_) => unreachable!("IPv4 bind"),
        };
        let config = match binary {
            "ferrum2-client" => {
                write_client_config(directory.path(), listen, unused_loopback(), None)
            }
            "ferrum2-server" => write_server_config(directory.path(), listen, None),
            _ => unreachable!("closed binary table"),
        }
        .expect("config");
        let output = run_binary(binary, &["--config", config.to_str().expect("UTF-8 path")]);
        assert_eq!(output.status.code(), Some(1), "{binary}");
        assert!(output.stdout.is_empty(), "{binary}");
        assert_eq!(output.stderr, STARTUP_BIND_DIAGNOSTIC, "{binary}");
    }
}

#[test]
fn later_metrics_bind_failure_rolls_back_the_prepared_proxy() {
    let directory = tempfile::tempdir().expect("temporary directory");
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let proxy = unused_loopback();
        let occupied_metrics =
            std::net::TcpListener::bind(unused_loopback()).expect("occupy metrics listener");
        let metrics = match occupied_metrics.local_addr().expect("metrics address") {
            std::net::SocketAddr::V4(address) => address,
            std::net::SocketAddr::V6(_) => unreachable!("IPv4 bind"),
        };
        let config = match binary {
            "ferrum2-client" => {
                write_client_config(directory.path(), proxy, unused_loopback(), Some(metrics))
            }
            "ferrum2-server" => write_server_config(directory.path(), proxy, Some(metrics)),
            _ => unreachable!("closed binary table"),
        }
        .expect("config");

        let output = run_binary(binary, &["--config", config.to_str().expect("UTF-8 path")]);
        assert_eq!(output.status.code(), Some(1), "{binary}");
        assert!(output.stdout.is_empty(), "{binary}");
        assert_eq!(output.stderr, STARTUP_BIND_DIAGNOSTIC, "{binary}");
        let rebound = std::net::TcpListener::bind(proxy).expect("prepared proxy rolled back");
        drop(rebound);
    }
}
