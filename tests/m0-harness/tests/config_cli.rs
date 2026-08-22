#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io;
use std::net::{SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::process::Output;

use local_support::{
    SYNTHETIC_PSK, TCP_METHOD_CONFIGS, reserve_loopback, rewrite_config_method, run_binary,
    unused_loopback, write_client_config, write_server_config, write_udp_client_config,
};

const CLIENT_BASE: &str = "schema_version = 1\n[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

const SERVER_BASE: &str = "schema_version = 1\n[server]\nlisten = \"127.0.0.1:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

const PAIRED_PORT_ATTEMPTS: usize = 256;
const STARTUP_BIND_DIAGNOSTIC: &str =
    "error[startup.bind] process: unable to prepare required endpoint";
const STARTUP_BIND_STDERR: &[u8] =
    b"error[startup.bind] process: unable to prepare required endpoint\n";
const CLIENT_SHUTDOWN_REPORT_FIELDS: [&str; 17] = [
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
const OWNER_COUNTER_FIELDS: [&str; 22] = [
    "active_supervisor_children",
    "active_tun_handler_tasks",
    "active_tun_tcp_flows",
    "active_process_roots",
    "connection_tasks",
    "forced_shutdowns",
    "listeners",
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
const ACTIVE_OWNER_COUNTER_FIELDS: [&str; 17] = [
    "active_supervisor_children",
    "active_tun_handler_tasks",
    "active_tun_tcp_flows",
    "active_process_roots",
    "connection_tasks",
    "listeners",
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

fn assert_closed_fields(value: &serde_json::Value, expected: &[&str], context: &str) {
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

fn assert_sensitive_config_values_absent(config: &str, stderr: &str, context: &str) {
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

fn parse_client_startup_bind_report(
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
        serde_json::json!({"name": "socks", "id": 0}),
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

fn stable_client_startup_bind_semantics(report: &serde_json::Value) -> serde_json::Value {
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

fn assert_startup_bind_failure(
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

fn tun_only_client() -> String {
    "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\nserver = \"192.0.2.10:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".into()
}

fn tun_client(fields: &str) -> String {
    format!(
        "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\n{fields}\noutbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\nserver = \"192.0.2.10:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
    )
}

const TUN_DNS_RUNTIME: &str = "[dns]\n[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:5353\"\n[[dns.servers]]\ntag = \"resolver\"\ntransport = \"udp\"\naddress = \"1.1.1.1:53\"\n[dns.route]\nfinal = \"resolver\"\n";

fn assert_tun_check_is_offline_valid(label: &str, source: &str) {
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
fn tun_check_config_is_offline_and_has_a_pure_target_gate() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = directory.path().join("tun-client.toml");
    std::fs::write(&config, tun_only_client()).expect("TUN config");
    let output = run_binary(
        "ferrum2-client",
        &[
            "--config",
            config.to_str().expect("UTF-8 path"),
            "--check-config",
        ],
    );
    if cfg!(all(windows, target_arch = "x86_64")) {
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"configuration valid\n");
        assert!(output.stderr.is_empty());
    } else {
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"error[config.semantic] tun: configuration value is invalid\n"
        );
    }
}

#[test]
fn tun_optional_families_routes_dns_and_filtering_are_offline_qualified() {
    let cases = [
        (
            "ipv4-only",
            "ipv4_address = \"198.18.0.2/30\"\nauto_route = true\nroute_address = [\"0.0.0.0/0\"]\nroute_exclude_address = [\"10.0.0.0/8\", \"192.168.0.0/16\"]\nauto_dns = true\nipv4_dns_address = \"198.18.0.1\"\nudp_filtering = \"address_dependent\"",
            true,
        ),
        (
            "ipv6-only",
            "ipv6_address = \"fd00::2/126\"\nauto_route = true\nroute_address = [\"::/0\"]\nroute_exclude_address = [\"2001:db8:ffff::/48\"]\nauto_dns = true\nipv6_dns_address = \"fd00::1\"\nudp_filtering = \"address_dependent\"",
            true,
        ),
        (
            "dual-stack",
            "ipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\nroute_exclude_address = [\"10.0.0.0/8\", \"2001:db8:ffff::/48\"]\nauto_dns = true\nipv4_dns_address = \"198.18.0.1\"\nipv6_dns_address = \"fd00::1\"\nudp_filtering = \"endpoint_independent\"",
            true,
        ),
        (
            "compiled-prefix-difference",
            "ipv4_address = \"198.18.0.2/30\"\nipv6_address = \"fd00::2/126\"\nauto_route = true\nroute_address = [\"10.0.0.1/8\", \"2001:db8:1::1/48\"]\nroute_exclude_address = [\"10.128.0.1/9\", \"2001:db8:1:8000::1/49\"]",
            false,
        ),
    ];
    for (label, fields, dns) in cases {
        let mut source = tun_client(fields);
        if dns {
            source.push_str(TUN_DNS_RUNTIME);
        }
        assert_tun_check_is_offline_valid(label, &source);
    }
}

#[test]
fn tun_compiled_capture_plan_is_bounded_after_excludes() {
    let directory = tempfile::tempdir().expect("temporary compiled-route directory");
    let compiled_plan = |last_exclude: &str| {
        let mut excludes = (0..10)
            .map(|index| format!("\"{index}.0.0.1/32\""))
            .collect::<Vec<_>>();
        excludes.push(format!("\"{last_exclude}\""));
        tun_client(&format!(
            "ipv4_address = \"198.18.0.2/30\"\nauto_route = true\nroute_exclude_address = [{}]",
            excludes.join(", ")
        ))
    };

    assert_tun_check_is_offline_valid("compiled-route-limit", &compiled_plan("10.0.0.0/18"));

    for (label, source) in [
        ("compiled-route-over-limit", compiled_plan("10.0.0.0/19")),
        (
            "compiled-route-empty",
            tun_client(
                "ipv4_address = \"198.18.0.2/30\"\nauto_route = true\nroute_address = [\"10.0.0.1/8\"]\nroute_exclude_address = [\"10.128.0.1/9\", \"10.0.0.1/9\"]",
            ),
        ),
    ] {
        let path = directory.path().join(format!("{label}.toml"));
        std::fs::write(&path, source).expect("compiled-route fixture");
        assert_invalid(
            "ferrum2-client",
            &path,
            "error[config.semantic] tun.route_address: configuration value is invalid\n",
            label,
        );
    }
}

#[test]
fn legacy_tun_udp_buffer_field_is_parse_only_and_not_range_checked() {
    for (label, value) in [
        ("legacy-zero", "0"),
        ("legacy-former-minimum-minus-one", "65535"),
        ("legacy-former-maximum-plus-one", "134217729"),
        ("legacy-maximum-integer", "18446744073709551615"),
    ] {
        let fields = format!("ipv4_address = \"198.18.0.2/30\"\nmax_udp_buffered_bytes = {value}");
        assert_tun_check_is_offline_valid(label, &tun_client(&fields));
    }
}

#[test]
fn tun_family_mismatches_and_unknown_filter_fail_before_platform_gating() {
    let directory = tempfile::tempdir().expect("temporary TUN invalid directory");
    let cases = [
        (
            "missing-family",
            "udp_filtering = \"address_dependent\"",
            "tun",
        ),
        (
            "ipv4-with-ipv6-route",
            "ipv4_address = \"198.18.0.2/30\"\nauto_route = true\nroute_address = [\"::/0\"]",
            "tun.route_address",
        ),
        (
            "ipv6-with-ipv4-exclude",
            "ipv6_address = \"fd00::2/126\"\nauto_route = true\nroute_exclude_address = [\"10.0.0.0/8\"]",
            "tun.route_exclude_address",
        ),
        (
            "ipv4-with-ipv6-dns",
            "ipv4_address = \"198.18.0.2/30\"\nauto_route = true\nauto_dns = true\nipv6_dns_address = \"fd00::1\"",
            "tun.ipv6_dns_address",
        ),
        (
            "unknown-filter",
            "ipv4_address = \"198.18.0.2/30\"\nudp_filtering = \"port_dependent\"",
            "tun.udp_filtering",
        ),
    ];
    for (label, fields, field) in cases {
        let path = directory.path().join(format!("{label}.toml"));
        std::fs::write(&path, tun_client(fields)).expect("invalid TUN fixture");
        assert_invalid(
            "ferrum2-client",
            &path,
            &format!("error[config.semantic] {field}: configuration value is invalid\n"),
            label,
        );
    }
}

#[test]
fn direct_check_config_is_offline_and_runtime_reaches_bind() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (listener, listen) = reserve_loopback();
    let direct = directory.path().join("direct-client.toml");
    std::fs::write(
        &direct,
        format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"{listen}\"\noutbound = \"exit\"\n[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n"
        ),
    )
    .expect("direct config");

    let checked = run_binary(
        "ferrum2-client",
        &["--config", direct.to_str().unwrap(), "--check-config"],
    );
    assert_eq!(checked.status.code(), Some(0));
    assert_eq!(checked.stdout, b"configuration valid\n");
    assert!(checked.stderr.is_empty());

    let run = run_binary("ferrum2-client", &["--config", direct.to_str().unwrap()]);
    let _ = assert_startup_bind_failure(&run, "ferrum2-client", &direct, "direct client runtime");
    assert!(
        TcpStream::connect_timeout(
            &listener.local_addr().expect("occupied listener"),
            std::time::Duration::from_secs(1)
        )
        .is_ok(),
        "direct runtime bind failure disturbed the occupied endpoint"
    );

    for (name, binary, source, expected) in [
        (
            "schema-v1-direct",
            "ferrum2-client",
            std::fs::read_to_string(&direct)
                .unwrap()
                .replacen("schema_version = 2", "schema_version = 1", 1),
            b"error[config.semantic] outbounds.type: configuration value is invalid\n".as_slice(),
        ),
        (
            "server-direct",
            "ferrum2-server",
            "schema_version = 2\n[[inbounds]]\ntag = \"in\"\nlisten = \"127.0.0.1:8388\"\n[[outbounds]]\ntag = \"out\"\ntype = \"direct\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(),
            b"error[config.syntax] config: configuration is not valid TOML\n".as_slice(),
        ),
    ] {
        let path = directory.path().join(format!("{name}.toml"));
        std::fs::write(&path, source).expect(name);
        let output = run_binary(
            binary,
            &["--config", path.to_str().unwrap(), "--check-config"],
        );
        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert_eq!(output.stderr, expected, "{name}");
    }
}

#[test]
fn client_materialized_check_is_opt_in_and_never_prepares_listener() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (occupied, listen) = reserve_loopback();
    let cache = directory
        .path()
        .join("ruleset-cache")
        .to_string_lossy()
        .replace('\\', "/");
    let path = directory.path().join("materialized-client.toml");
    let source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://localhost:9/ads.srs"
download_resolver = "system"

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 250
max_redirects = 0
"#
    );
    std::fs::write(&path, &source).expect("materialized check config");
    let path_text = path.to_str().expect("UTF-8 config path");

    let static_check = run_binary("ferrum2-client", &["--config", path_text, "--check-config"]);
    assert_eq!(static_check.status.code(), Some(0));
    assert_eq!(static_check.stdout, b"configuration valid\n");
    assert!(static_check.stderr.is_empty());
    assert!(!directory.path().join("ruleset-cache").exists());

    let materialized_check = run_binary(
        "ferrum2-client",
        &["--config", path_text, "--check-config", "--materialize"],
    );
    assert_eq!(materialized_check.status.code(), Some(1));
    assert!(materialized_check.stdout.is_empty());
    assert_eq!(
        materialized_check.stderr,
        b"error[ruleset.download] materialization: RuleSet download failed\n"
    );
    assert!(!String::from_utf8_lossy(&materialized_check.stderr).contains(path_text));
    assert!(
        TcpStream::connect_timeout(
            &occupied.local_addr().expect("occupied listener"),
            std::time::Duration::from_secs(1),
        )
        .is_ok(),
        "materialized validation disturbed the occupied listener"
    );

    let local = directory.path().join("local-materialized-client.toml");
    std::fs::write(
        &local,
        format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{listen}\"\n[[outbounds]]\ntag = \"direct\"\ntype = \"direct\"\n[route]\nfinal = \"direct\"\n"
        ),
    )
    .expect("local materialized config");
    let successful = run_binary(
        "ferrum2-client",
        &[
            "--config",
            local.to_str().expect("UTF-8 local path"),
            "--check-config",
            "--materialize",
        ],
    );
    assert_eq!(successful.status.code(), Some(0));
    assert_eq!(successful.stdout, b"configuration valid\n");
    assert!(successful.stderr.is_empty());

    let v1 = write_client_config(directory.path(), listen, unused_loopback(), None)
        .expect("V1 materialized-check config");
    let v1_successful = run_binary(
        "ferrum2-client",
        &[
            "--config",
            v1.to_str().expect("UTF-8 V1 path"),
            "--check-config",
            "--materialize",
        ],
    );
    assert_eq!(v1_successful.status.code(), Some(0));
    assert_eq!(v1_successful.stdout, b"configuration valid\n");
    assert!(v1_successful.stderr.is_empty());
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
fn schema_v2_check_succeeds_and_occupied_runtime_endpoints_fail_closed() {
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
        ),
        (
            "ferrum2-server",
            SERVER_BASE
                .replacen("schema_version = 1", "schema_version = 2", 1)
                .replace("127.0.0.1:8388", &server_address.to_string()),
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
        let legacy_report = assert_startup_bind_failure(&legacy, binary, &legacy_path, binary);
        let tagged_report = assert_startup_bind_failure(&tagged, binary, &tagged_path, binary);
        match (legacy_report, tagged_report) {
            (Some(legacy), Some(tagged)) => assert_eq!(
                stable_client_startup_bind_semantics(&tagged),
                stable_client_startup_bind_semantics(&legacy),
                "{binary} stable startup semantics"
            ),
            (None, None) => assert_eq!(tagged.stderr, legacy.stderr, "{binary}"),
            _ => panic!("{binary} startup report shape changed between configurations"),
        }
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
