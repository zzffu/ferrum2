use super::support::*;

#[test]
fn wildcard_listeners_conflict_in_either_declaration_order() {
    for (source, port, first_tag) in [
        (CLIENT_V2_MINIMAL, 1080, "proxy"),
        (SERVER_V2, 8388, "ss-in"),
    ] {
        for (first, second) in [("0.0.0.0", "127.0.0.1"), ("127.0.0.1", "0.0.0.0")] {
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
            assert_eq!(
                error.to_string(),
                "error[config.semantic] inbounds.listen: configuration value is invalid"
            );
        }
    }
}

#[test]
fn wildcard_proxy_and_dns_listeners_conflict_with_loopback_metrics() {
    for (base, old, new, port) in [
        (CLIENT_V2_MINIMAL, "127.0.0.1:1080", "0.0.0.0:1080", 1080),
        (CLIENT_V2, "127.0.0.1:5353", "0.0.0.0:5353", 5353),
        (SERVER_V2, "127.0.0.1:8388", "0.0.0.0:8388", 8388),
    ] {
        let source = format!(
            "{}\n[metrics]\nlisten = \"127.0.0.1:{port}\"\n",
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
