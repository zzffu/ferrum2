#[path = "config_cli_support/mod.rs"]
mod support;

use support::*;

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
    let path = config.to_str().expect("UTF-8 path");
    for (mode, arguments) in [
        ("offline", vec!["--config", path, "--check-config"]),
        (
            "materialized-1",
            vec!["--config", path, "--check-config", "--materialize"],
        ),
        (
            "materialized-2",
            vec!["--config", path, "--check-config", "--materialize"],
        ),
    ] {
        let output = run_binary("ferrum2-client", &arguments);
        if cfg!(all(windows, target_arch = "x86_64")) {
            assert_eq!(output.status.code(), Some(0), "{mode}");
            assert_eq!(output.stdout, b"configuration valid\n", "{mode}");
            assert!(output.stderr.is_empty(), "{mode}");
        } else {
            assert_eq!(output.status.code(), Some(2), "{mode}");
            assert!(output.stdout.is_empty(), "{mode}");
            assert_eq!(
                output.stderr, b"error[config.semantic] tun: configuration value is invalid\n",
                "{mode}"
            );
        }
    }
    // Both validation modes return synchronously. No TUN root exists in this
    // black-box process, and a second materialized pass above would otherwise
    // collide with adapter or managed-network ownership left by the first.
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
fn removed_tun_udp_memory_field_fails_offline_cli_validation() {
    let directory = tempfile::tempdir().expect("temporary removed TUN field directory");
    for (label, value) in [
        ("removed-zero", "0"),
        ("removed-former-minimum", "65536"),
        ("removed-former-maximum", "134217728"),
        ("removed-maximum-integer", "18446744073709551615"),
    ] {
        let fields = format!("ipv4_address = \"198.18.0.2/30\"\nmax_udp_buffered_bytes = {value}");
        let path = directory.path().join(format!("{label}.toml"));
        std::fs::write(&path, tun_client(&fields)).expect("removed TUN field fixture");
        assert_invalid(
            "ferrum2-client",
            &path,
            "error[config.syntax] config: configuration is not valid TOML\n",
            value,
        );
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
            b"error[config.semantic] schema_version: configuration value is invalid\n".as_slice(),
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
