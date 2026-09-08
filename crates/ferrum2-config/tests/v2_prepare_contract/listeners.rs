use super::support::*;

#[test]
fn wildcard_listeners_conflict_in_either_declaration_order() {
    for (source, port, first_tag, addresses) in [
        (
            CLIENT_V2_MINIMAL,
            1080,
            "proxy",
            [("0.0.0.0", "127.0.0.1"), ("127.0.0.1", "0.0.0.0")],
        ),
        (
            SERVER_V2,
            8388,
            "ss-in",
            [("0.0.0.0", "127.0.0.1"), ("127.0.0.1", "0.0.0.0")],
        ),
        (
            SERVER_V2,
            8388,
            "ss-in",
            [("[::]", "[::1]"), ("[::1]", "[::]")],
        ),
        (
            SERVER_V2,
            8388,
            "ss-in",
            [("[::1]", "[0:0:0:0:0:0:0:1]"), ("[::]", "[::]")],
        ),
    ] {
        for (first, second) in addresses {
            let source = source.replace(
                &format!("listen = \"127.0.0.1:{port}\""),
                &format!(
                    "listen = \"{first}:{port}\"\n\n[[inbounds]]\ntag = \"{first_tag}-second\"\nlisten = \"{second}:{port}\""
                ),
            );
            let file = TempConfig::new(&source);
            let error = if port == 1080 {
                prepare_client(&file.0).expect_err("overlapping client listeners")
            } else {
                prepare_server(&file.0).expect_err("overlapping server listeners")
            };
            assert_eq!(
                (error.kind(), error.field()),
                (ConfigErrorKind::Semantic, ConfigField::InboundsListen)
            );
        }
    }
}

#[test]
fn wildcard_proxy_and_dns_listeners_conflict_with_loopback_metrics() {
    for (base, old, new, metrics, port) in [
        (
            CLIENT_V2_MINIMAL,
            "127.0.0.1:1080",
            "0.0.0.0:1080",
            "127.0.0.1",
            1080,
        ),
        (
            CLIENT_V2,
            "127.0.0.1:5353",
            "0.0.0.0:5353",
            "127.0.0.1",
            5353,
        ),
        (
            SERVER_V2,
            "127.0.0.1:8388",
            "0.0.0.0:8388",
            "127.0.0.1",
            8388,
        ),
        (CLIENT_V2, "127.0.0.1:5353", "[::]:5353", "[::1]", 5353),
        (CLIENT_V2, "127.0.0.1:5353", "[::1]:5353", "[::1]", 5353),
        (SERVER_V2, "127.0.0.1:8388", "[::]:8388", "[::1]", 8388),
        (SERVER_V2, "127.0.0.1:8388", "[::1]:8388", "[::1]", 8388),
    ] {
        let source = format!(
            "{}\n[metrics]\nlisten = \"{metrics}:{port}\"\n",
            base.replace(old, new)
        );
        let file = TempConfig::new(&source);
        let error = if port == 8388 {
            prepare_server(&file.0).expect_err("metrics overlap")
        } else {
            prepare_client(&file.0).expect_err("metrics overlap")
        };
        assert_eq!(
            (error.kind(), error.field()),
            (ConfigErrorKind::Semantic, ConfigField::MetricsListen)
        );
    }
}

#[test]
fn distinct_local_addresses_may_share_a_listener_port() {
    let source = CLIENT_V2_MINIMAL.replace(
        "[[outbounds]]",
        "[[inbounds]]\ntag = \"second\"\nlisten = \"127.0.0.2:1080\"\n\n[[outbounds]]",
    );
    let source = format!("{source}\n[metrics]\nlisten = \"127.0.0.3:1080\"\n");
    let file = TempConfig::new(&source);
    let prepared = prepare_client(&file.0).expect("disjoint addresses");
    let config = finish_client_v2(prepared, ClientV2Resources::default()).expect("finish");
    assert_eq!(config.inbounds.len(), 2);
}

#[test]
fn ipv6_server_and_loopback_metrics_accept_disjoint_listener_addresses() {
    let source = SERVER_V2.replace("127.0.0.1:8388", "[::1]:8388");
    let file = TempConfig::new(&format!("{source}\n[metrics]\nlisten = \"[::1]:9090\"\n"));
    prepare_server(&file.0).expect("IPv6 server and loopback metrics");

    let source = SERVER_V2.replace("127.0.0.1:8388", "[::]:8388");
    let file = TempConfig::new(&format!(
        "{source}\n[metrics]\nlisten = \"127.0.0.1:8388\"\n"
    ));
    prepare_server(&file.0).expect("IPv6-only wildcard does not alias IPv4 metrics");

    let file = TempConfig::new(&format!(
        "{CLIENT_V2_MINIMAL}\n[metrics]\nlisten = \"[::1]:1080\"\n"
    ));
    let prepared = prepare_client(&file.0).expect("IPv6 metrics do not alias IPv4 SOCKS");
    finish_client_v2(prepared, ClientV2Resources::default()).expect("finish client");
}

#[test]
fn ipv6_metrics_reject_nonloopback_addresses_and_zero_ports() {
    for endpoint in ["[::]:9090", "[2001:db8::1]:9090", "[::1]:0"] {
        for (source, server) in [(CLIENT_V2_MINIMAL, false), (SERVER_V2, true)] {
            let file = TempConfig::new(&format!("{source}\n[metrics]\nlisten = \"{endpoint}\"\n"));
            let error = if server {
                prepare_server(&file.0).expect_err("invalid IPv6 metrics")
            } else {
                prepare_client(&file.0).expect_err("invalid IPv6 metrics")
            };
            assert_eq!(
                (error.kind(), error.field()),
                (ConfigErrorKind::Semantic, ConfigField::MetricsListen)
            );
        }
    }
}

#[test]
fn ipv6_server_requires_a_nonzero_port_and_client_socks_remains_ipv4_only() {
    let file = TempConfig::new(&SERVER_V2.replace("127.0.0.1:8388", "[::1]:0"));
    let error = prepare_server(&file.0).expect_err("zero server port");
    assert_eq!(
        (error.kind(), error.field()),
        (ConfigErrorKind::Semantic, ConfigField::InboundsListen)
    );

    let file = TempConfig::new(&CLIENT_V2_MINIMAL.replace("127.0.0.1:1080", "[::1]:1080"));
    let error = prepare_client(&file.0).expect_err("IPv6 SOCKS remains unsupported");
    assert_eq!(
        (error.kind(), error.field()),
        (ConfigErrorKind::Semantic, ConfigField::InboundsListen)
    );
}
