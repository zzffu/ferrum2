#[path = "../src/local_support/mod.rs"]
mod local_support;

use local_support::{
    SYNTHETIC_PSK, reserve_loopback, run_binary, unused_loopback, write_client_config,
    write_server_config,
};

const STARTUP_BIND_DIAGNOSTIC: &str =
    "error[startup.bind] process: unable to prepare required endpoint\n";
const REPORT_FIELDS: [&str; 17] = [
    "actual_grace_deadline_elapsed_ns",
    "actual_grace_deadline_source",
    "cleanup_failure",
    "event",
    "forced_root_count",
    "owner_baseline",
    "owner_delta",
    "owner_stopped",
    "process_states",
    "process_transitions",
    "role",
    "root",
    "root_error_category",
    "root_exit_category",
    "root_exit_events",
    "shutdown_grace_ns",
    "termination_cause",
];
const OWNER_COUNTER_FIELDS: [&str; 25] = [
    "active_supervisor_children",
    "active_tun_handler_tasks",
    "active_tun_tcp_flows",
    "active_process_roots",
    "connection_tasks",
    "forced_shutdowns",
    "listeners",
    "network_reset_drivers",
    "network_reset_hooks",
    "network_runtime_owners",
    "owned_buffers",
    "owned_permits",
    "prepared_process_roots",
    "process_forced_roots",
    "process_root_reaps",
    "process_root_rollbacks",
    "process_supervisors",
    "sniff_buffered_bytes",
    "udp_buffered_bytes",
    "udp_forced_shutdowns",
    "udp_queued_datagrams",
    "udp_scratch_buffers",
    "udp_sessions",
    "udp_sockets",
    "udp_tasks",
];

fn assert_closed_fields(value: &serde_json::Value, expected: &[&str], context: &str) {
    let actual = value
        .as_object()
        .unwrap_or_else(|| panic!("{context} object"))
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected, "{context} fields");
}

fn assert_client_bind_failure_report(
    stderr: &str,
    expected_root_name: &str,
    expected_root_id: u64,
    expected_rollbacks: i64,
) {
    assert!(
        stderr.ends_with('\n'),
        "client stderr is newline terminated"
    );
    let mut lines = stderr.lines();
    let report_line = lines.next().expect("client shutdown report line");
    assert_eq!(
        lines.next(),
        Some(STARTUP_BIND_DIAGNOSTIC.trim_end()),
        "client startup error line"
    );
    assert_eq!(lines.next(), None, "client stderr contains only two lines");

    let report: serde_json::Value =
        serde_json::from_str(report_line).expect("closed client shutdown report JSON");
    assert_closed_fields(&report, &REPORT_FIELDS, "client shutdown report");
    assert_eq!(report["event"], "process_shutdown_report");
    assert_eq!(report["role"], "client");
    let expected_states = ["Validated", "Preparing", "Rollback", "Stopped"];
    assert_eq!(report["process_states"], serde_json::json!(expected_states));
    let transitions = report["process_transitions"]
        .as_array()
        .expect("process transition array");
    assert_eq!(transitions.len(), expected_states.len());
    let mut previous_elapsed_ns = 0;
    for (index, (transition, expected_state)) in transitions.iter().zip(expected_states).enumerate()
    {
        assert_closed_fields(transition, &["elapsed_ns", "state"], "process transition");
        assert_eq!(
            transition["state"].as_str(),
            Some(expected_state),
            "transition {index} state"
        );
        let elapsed_ns = transition["elapsed_ns"]
            .as_u64()
            .expect("transition elapsed nanoseconds");
        assert!(
            elapsed_ns >= previous_elapsed_ns,
            "transition {index} is monotonic"
        );
        previous_elapsed_ns = elapsed_ns;
    }
    assert_eq!(report["root_exit_events"], serde_json::json!([]));
    assert!(
        report["shutdown_grace_ns"]
            .as_u64()
            .is_some_and(|nanoseconds| nanoseconds > 0)
    );
    assert!(report["actual_grace_deadline_elapsed_ns"].is_null());
    assert!(report["actual_grace_deadline_source"].is_null());
    assert_eq!(report["termination_cause"], "PreparationFailed");
    assert_eq!(
        report["root"],
        serde_json::json!({"name": expected_root_name, "id": expected_root_id})
    );
    assert!(report["root_exit_category"].is_null());
    assert_eq!(report["root_error_category"], "startup.bind");
    assert_eq!(report["forced_root_count"], 0);
    for field in ["owner_baseline", "owner_stopped", "owner_delta"] {
        assert_closed_fields(&report[field], &OWNER_COUNTER_FIELDS, field);
    }
    for field in OWNER_COUNTER_FIELDS {
        let expected = if field == "process_root_rollbacks" {
            expected_rollbacks
        } else {
            0
        };
        assert_eq!(
            report["owner_delta"][field].as_i64(),
            Some(expected),
            "{field} owner delta"
        );
        assert!(
            report["owner_baseline"][field].as_u64().is_some(),
            "{field} owner baseline"
        );
        assert!(
            report["owner_stopped"][field].as_u64().is_some(),
            "{field} stopped owner count"
        );
    }
    assert!(report["cleanup_failure"].is_null());
}

fn assert_bind_failure_stderr(
    binary: &str,
    stderr: &[u8],
    config: &std::path::Path,
    client_root: (&str, u64),
    expected_rollbacks: i64,
    configured_endpoints: &[String],
) {
    let stderr = std::str::from_utf8(stderr).expect("UTF-8 bind failure stderr");
    assert!(!stderr.contains(SYNTHETIC_PSK), "{binary} disclosed PSK");
    let config_path = config.to_str().expect("UTF-8 config path");
    assert!(
        !stderr.contains(config_path) && !stderr.contains(&config_path.replace('\\', "\\\\")),
        "{binary} disclosed config path"
    );
    for endpoint in configured_endpoints {
        assert!(
            !stderr.contains(endpoint),
            "{binary} disclosed configured endpoint"
        );
    }
    if binary == "ferrum2-client" {
        assert_client_bind_failure_report(stderr, client_root.0, client_root.1, expected_rollbacks);
    } else {
        assert_eq!(stderr, STARTUP_BIND_DIAGNOSTIC, "{binary}");
    }
}

#[test]
fn help_and_version_use_the_shared_cli_surface() {
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let help = run_binary(binary, &["--help"]);
        assert_eq!(help.status.code(), Some(0), "{binary} --help");
        assert!(help.stderr.is_empty(), "{binary} --help stderr");
        let stdout = String::from_utf8(help.stdout).expect("UTF-8 help");
        assert!(stdout.contains("--config <PATH>"), "{binary}");
        assert!(stdout.contains("--check-config"), "{binary}");
        if binary == "ferrum2-client" {
            assert!(stdout.contains("--materialize"), "{binary}");
        }

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

    let standalone_materialize = run_binary(
        "ferrum2-client",
        &["--config", "unused.toml", "--materialize"],
    );
    assert_eq!(standalone_materialize.status.code(), Some(2));
    assert!(standalone_materialize.stdout.is_empty());
    let stderr = String::from_utf8(standalone_materialize.stderr).expect("UTF-8 usage error");
    assert!(stderr.contains("--check-config"), "{stderr}");
}

#[test]
fn valid_run_mode_bind_failure_exits_one() {
    let directory = tempfile::tempdir().expect("temporary directory");
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let network_root_offset = u64::from(binary == "ferrum2-client" && cfg!(windows));
        let (_occupied, listen) = reserve_loopback();
        let (config, configured_endpoints) = match binary {
            "ferrum2-client" => {
                let server = unused_loopback();
                (
                    write_client_config(directory.path(), listen, server, None),
                    vec![listen.to_string(), server.to_string()],
                )
            }
            "ferrum2-server" => (
                write_server_config(directory.path(), listen, None),
                vec![listen.to_string()],
            ),
            _ => unreachable!("closed binary table"),
        };
        let config = config.expect("config");
        let output = run_binary(binary, &["--config", config.to_str().expect("UTF-8 path")]);
        assert_eq!(output.status.code(), Some(1), "{binary}");
        assert!(output.stdout.is_empty(), "{binary}");
        assert_bind_failure_stderr(
            binary,
            &output.stderr,
            &config,
            ("socks", network_root_offset),
            network_root_offset as i64,
            &configured_endpoints,
        );
    }
    for binary in ["ferrum2-client", "ferrum2-server"] {
        let network_root_offset = u64::from(binary == "ferrum2-client" && cfg!(windows));
        let proxy = unused_loopback();
        let (_occupied_metrics, metrics) = reserve_loopback();
        let (config, configured_endpoints) = if binary == "ferrum2-client" {
            let server = unused_loopback();
            (
                write_client_config(directory.path(), proxy, server, Some(metrics)),
                vec![proxy.to_string(), server.to_string(), metrics.to_string()],
            )
        } else {
            (
                write_server_config(directory.path(), proxy, Some(metrics)),
                vec![proxy.to_string(), metrics.to_string()],
            )
        };
        let config = config.expect("transactional config");
        let output = run_binary(binary, &["--config", config.to_str().expect("UTF-8 path")]);
        assert_eq!(output.status.code(), Some(1), "{binary}");
        assert!(output.stdout.is_empty(), "{binary}");
        assert_bind_failure_stderr(
            binary,
            &output.stderr,
            &config,
            ("metrics", network_root_offset + 1),
            network_root_offset as i64 + 1,
            &configured_endpoints,
        );
        std::net::TcpListener::bind(proxy).expect("prepared proxy rolled back");
    }
}
