#![allow(dead_code, unused_imports)]

#[path = "../../src/local_support/mod.rs"]
pub(super) mod local_support;

pub(super) use std::io;
pub(super) use std::net::{SocketAddrV4, TcpListener, TcpStream, UdpSocket};
pub(super) use std::process::Output;

pub(super) use local_support::{
    SYNTHETIC_PSK, TCP_METHOD_CONFIGS, reserve_loopback, rewrite_config_method, run_binary,
    unused_loopback, write_client_config, write_server_config, write_udp_client_config,
};

pub(super) const CLIENT_BASE: &str = "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy-out\"\n[[outbounds]]\ntag = \"proxy-out\"\ntype = \"shadowsocks\"\nserver = \"127.0.0.1:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

pub(super) const SERVER_BASE: &str = "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"127.0.0.1:8388\"\noutbound = \"direct\"\n[[outbounds]]\ntag = \"direct\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

pub(super) const PAIRED_PORT_ATTEMPTS: usize = 256;
pub(super) const STARTUP_BIND_DIAGNOSTIC: &str =
    "error[startup.bind] process: unable to prepare required endpoint";
pub(super) const STARTUP_BIND_STDERR: &[u8] =
    b"error[startup.bind] process: unable to prepare required endpoint\n";
pub(super) const CLIENT_SHUTDOWN_REPORT_FIELDS: [&str; 17] = [
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
pub(super) const OWNER_COUNTER_FIELDS: [&str; 25] = [
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
pub(super) const ACTIVE_OWNER_COUNTER_FIELDS: [&str; 20] = [
    "active_supervisor_children",
    "active_tun_handler_tasks",
    "active_tun_tcp_flows",
    "active_process_roots",
    "connection_tasks",
    "listeners",
    "network_reset_drivers",
    "network_reset_hooks",
    "network_runtime_owners",
    "owned_buffers",
    "owned_permits",
    "prepared_process_roots",
    "process_supervisors",
    "sniff_buffered_bytes",
    "udp_buffered_bytes",
    "udp_queued_datagrams",
    "udp_scratch_buffers",
    "udp_sessions",
    "udp_sockets",
    "udp_tasks",
];

pub(super) fn assert_closed_fields(value: &serde_json::Value, expected: &[&str], context: &str) {
    let actual = value
        .as_object()
        .unwrap_or_else(|| panic!("{context} is not an object"))
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected, "{context} fields");
}

pub(super) fn assert_sensitive_config_values_absent(config: &str, stderr: &str, context: &str) {
    for line in config.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !matches!(name, "listen" | "server" | "psk") {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or_else(|| panic!("{context} has a non-string {name} assignment"));
        assert!(
            !value.is_empty(),
            "{context} has an empty {name} assignment"
        );
        assert!(
            !stderr.contains(value),
            "{context} disclosed configured {name} value"
        );
    }
}

pub(super) fn parse_client_startup_bind_report(
    stderr: &[u8],
    config_path: &std::path::Path,
    context: &str,
) -> serde_json::Value {
    let stderr = std::str::from_utf8(stderr).expect("UTF-8 client startup stderr");
    let config_path = config_path.to_str().expect("UTF-8 config path");
    let config =
        std::fs::read_to_string(config_path).expect("read client config for redaction assertion");
    assert!(
        !stderr.contains(config_path),
        "{context} disclosed the configuration path"
    );
    assert_sensitive_config_values_absent(&config, stderr, context);

    assert!(
        stderr.ends_with('\n'),
        "{context} stderr is newline terminated"
    );
    let mut lines = stderr.lines();
    let report_line = lines.next().expect("client shutdown report line");
    assert_eq!(
        lines.next(),
        Some(STARTUP_BIND_DIAGNOSTIC),
        "{context} canonical startup error; stderr={stderr:?}"
    );
    assert_eq!(
        lines.next(),
        None,
        "{context} stderr contains only two lines"
    );

    let report: serde_json::Value =
        serde_json::from_str(report_line).expect("closed client shutdown report JSON");
    assert_closed_fields(
        &report,
        &CLIENT_SHUTDOWN_REPORT_FIELDS,
        "client shutdown report",
    );
    assert_eq!(report["event"], "process_shutdown_report", "{context}");
    assert_eq!(report["role"], "client", "{context}");
    assert_eq!(
        report["process_states"],
        serde_json::json!(["Validated", "Preparing", "Rollback", "Stopped"]),
        "{context} process states"
    );
    let transitions = report["process_transitions"]
        .as_array()
        .expect("client process transition array");
    assert_eq!(transitions.len(), 4, "{context} process transition count");
    let mut previous_elapsed_ns = 0;
    for (transition, expected_state) in
        transitions
            .iter()
            .zip(["Validated", "Preparing", "Rollback", "Stopped"])
    {
        assert_closed_fields(transition, &["elapsed_ns", "state"], "process transition");
        assert_eq!(transition["state"], expected_state, "{context}");
        let elapsed_ns = transition["elapsed_ns"]
            .as_u64()
            .expect("transition elapsed nanoseconds");
        assert!(
            elapsed_ns >= previous_elapsed_ns,
            "{context} process transition clock is not monotonic"
        );
        previous_elapsed_ns = elapsed_ns;
    }
    assert_eq!(
        report["root_exit_events"],
        serde_json::json!([]),
        "{context}"
    );
    assert!(
        report["shutdown_grace_ns"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "{context} shutdown grace"
    );
    assert!(report["actual_grace_deadline_elapsed_ns"].is_null());
    assert!(report["actual_grace_deadline_source"].is_null());
    assert_eq!(
        report["termination_cause"], "PreparationFailed",
        "{context}"
    );
    assert_eq!(
        report["root"],
        serde_json::json!({
            "name": "socks",
            "id": u64::from(cfg!(windows)),
        }),
        "{context} failed root"
    );
    assert!(report["root_exit_category"].is_null(), "{context}");
    assert_eq!(report["root_error_category"], "startup.bind", "{context}");
    assert_eq!(report["forced_root_count"], 0, "{context}");
    assert!(report["cleanup_failure"].is_null(), "{context}");
    for field in ["owner_baseline", "owner_stopped", "owner_delta"] {
        assert_closed_fields(&report[field], &OWNER_COUNTER_FIELDS, field);
    }
    for field in OWNER_COUNTER_FIELDS {
        assert!(
            report["owner_baseline"][field].as_u64().is_some(),
            "{context} owner_baseline.{field}"
        );
        assert!(
            report["owner_stopped"][field].as_u64().is_some(),
            "{context} owner_stopped.{field}"
        );
        assert!(
            report["owner_delta"][field].as_i64().is_some(),
            "{context} owner_delta.{field}"
        );
    }
    for field in ACTIVE_OWNER_COUNTER_FIELDS {
        assert_eq!(
            report["owner_stopped"][field].as_u64(),
            Some(0),
            "{context} owner_stopped.{field}"
        );
    }

    report
}

pub(super) fn stable_client_startup_bind_semantics(
    report: &serde_json::Value,
) -> serde_json::Value {
    let mut stable = report.clone();
    for transition in stable["process_transitions"]
        .as_array_mut()
        .expect("client process transition array")
    {
        transition
            .as_object_mut()
            .expect("client process transition object")
            .remove("elapsed_ns");
    }
    for event in stable["root_exit_events"]
        .as_array_mut()
        .expect("client root exit event array")
    {
        event
            .as_object_mut()
            .expect("client root exit event object")
            .remove("elapsed_ns");
    }
    stable
}

pub(super) fn assert_startup_bind_failure(
    output: &Output,
    binary: &str,
    config_path: &std::path::Path,
    context: &str,
) -> Option<serde_json::Value> {
    assert_eq!(output.status.code(), Some(1), "{context}");
    assert!(output.stdout.is_empty(), "{context}");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(SYNTHETIC_PSK),
        "{context} leaked the configured PSK"
    );
    match binary {
        "ferrum2-client" => Some(parse_client_startup_bind_report(
            &output.stderr,
            config_path,
            context,
        )),
        "ferrum2-server" => {
            let stderr = std::str::from_utf8(&output.stderr).expect("UTF-8 server startup stderr");
            let config_path = config_path.to_str().expect("UTF-8 config path");
            let config = std::fs::read_to_string(config_path)
                .expect("read server config for redaction assertion");
            assert!(
                !stderr.contains(config_path),
                "{context} disclosed the configuration path"
            );
            assert_sensitive_config_values_absent(&config, stderr, context);
            assert!(
                output.stderr == STARTUP_BIND_STDERR,
                "{context} server canonical startup error"
            );
            None
        }
        _ => panic!("unexpected binary {binary}"),
    }
}

pub(super) fn tun_only_client() -> String {
    "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.10:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".into()
}

pub(super) fn tun_client(fields: &str) -> String {
    format!(
        "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\n{fields}\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.10:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
    )
}

pub(super) const TUN_DNS_RUNTIME: &str = "[dns]\n[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"resolver\"\ntransport = \"udp\"\naddress = \"1.1.1.1:53\"\n[dns.route]\nfinal = \"resolver\"\n";

pub(super) fn assert_tun_check_is_offline_valid(label: &str, source: &str) {
    let directory = tempfile::tempdir().expect("temporary TUN config directory");
    let path = directory.path().join(format!("{label}.toml"));
    std::fs::write(&path, source).expect("TUN config fixture");
    let output = run_binary(
        "ferrum2-client",
        &[
            "--config",
            path.to_str().expect("UTF-8 TUN config path"),
            "--check-config",
        ],
    );
    if cfg!(all(windows, target_arch = "x86_64")) {
        assert_eq!(output.status.code(), Some(0), "{label}");
        assert_eq!(output.stdout, b"configuration valid\n", "{label}");
        assert!(output.stderr.is_empty(), "{label}");
    } else {
        assert_eq!(output.status.code(), Some(2), "{label}");
        assert!(output.stdout.is_empty(), "{label}");
        assert_eq!(
            output.stderr, b"error[config.semantic] tun: configuration value is invalid\n",
            "{label}"
        );
    }
}

pub(super) fn tagged_client(inbounds: &[SocketAddrV4], servers: &[SocketAddrV4]) -> String {
    let mut source = "schema_version = 2\n".to_owned();
    for (index, listen) in inbounds.iter().enumerate() {
        source.push_str(&format!(
            "[[inbounds]]\ntag = \"i{index}\"\nlisten = \"{listen}\"\noutbound = \"o{index}\"\n"
        ));
    }
    for (index, server) in servers.iter().enumerate() {
        source.push_str(&format!(
            "[[outbounds]]\ntag = \"o{index}\"\ntype = \"shadowsocks\"\nserver = \"{server}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
        ));
    }
    source
}

pub(super) fn tagged_server(inbounds: &[SocketAddrV4]) -> String {
    let mut source = "schema_version = 2\n".to_owned();
    for (index, listen) in inbounds.iter().enumerate() {
        source.push_str(&format!(
            "[[inbounds]]\ntag = \"i{index}\"\nlisten = \"{listen}\"\noutbound = \"o{index}\"\n"
        ));
        source.push_str(&format!("[[outbounds]]\ntag = \"o{index}\"\n"));
    }
    source.push_str(
        "[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
    );
    source
}

pub(super) fn routed_tagged(source: String) -> String {
    let source = source
        .lines()
        .filter(|line| !line.starts_with("outbound = "))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{source}\n[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"i0\"\nnetwork = \"tcp\"\ndomain = \"example.test\"\nport = 443\naction = \"route\"\noutbound = \"o1\"\n"
    )
}

pub(super) fn reserve_server_tcp_udp() -> (TcpListener, UdpSocket, SocketAddrV4) {
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

pub(super) fn assert_materialized_check_failure(
    binary: &str,
    path: &std::path::Path,
    cache_root: &std::path::Path,
    expected_exit: i32,
    expected_stderr: &[u8],
) {
    let path = path.to_str().expect("UTF-8 materialized config path");
    let static_check = run_binary(binary, &["--config", path, "--check-config"]);
    assert_eq!(static_check.status.code(), Some(0), "{binary} static check");
    assert_eq!(
        static_check.stdout, b"configuration valid\n",
        "{binary} static check"
    );
    assert!(static_check.stderr.is_empty(), "{binary} static check");
    assert!(
        !cache_root.exists(),
        "{binary} static check created its RuleSet cache"
    );

    // Repetition is the black-box cleanup witness: each invocation must finish
    // with the same closed result and leave no listener or temporary owner that
    // can perturb the next materialization pass.
    for attempt in 1..=2 {
        let materialized = run_binary(
            binary,
            &["--config", path, "--check-config", "--materialize"],
        );
        assert_eq!(
            materialized.status.code(),
            Some(expected_exit),
            "{binary} materialized attempt {attempt}"
        );
        assert!(
            materialized.stdout.is_empty(),
            "{binary} materialized attempt {attempt}"
        );
        assert_eq!(
            materialized.stderr, expected_stderr,
            "{binary} materialized attempt {attempt}"
        );
        assert!(
            !String::from_utf8_lossy(&materialized.stderr).contains(path),
            "{binary} materialized attempt {attempt} disclosed its config path"
        );
    }
}

pub(super) fn assert_materialized_check_success(binary: &str, path: &std::path::Path) {
    let path = path.to_str().expect("UTF-8 materialized config path");
    for attempt in 1..=2 {
        let materialized = run_binary(
            binary,
            &["--config", path, "--check-config", "--materialize"],
        );
        assert_eq!(
            materialized.status.code(),
            Some(0),
            "{binary} materialized attempt {attempt}"
        );
        assert_eq!(
            materialized.stdout, b"configuration valid\n",
            "{binary} materialized attempt {attempt}"
        );
        assert!(
            materialized.stderr.is_empty(),
            "{binary} materialized attempt {attempt}"
        );
    }
}

pub(super) fn assert_listener_is_undisturbed(listener: &TcpListener, context: &str) {
    let probe = TcpStream::connect_timeout(
        &listener.local_addr().expect("occupied listener"),
        std::time::Duration::from_secs(1),
    )
    .unwrap_or_else(|error| panic!("{context} disturbed the occupied listener: {error}"));
    let (accepted, _) = listener
        .accept()
        .unwrap_or_else(|error| panic!("{context} could not drain its listener probe: {error}"));
    drop(accepted);
    drop(probe);
}

pub(super) fn assert_invalid(
    binary: &str,
    path: &std::path::Path,
    expected_stderr: &str,
    sentinel: &str,
) {
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
