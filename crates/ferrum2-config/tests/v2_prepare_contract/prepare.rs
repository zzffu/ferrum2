use super::support::*;

#[test]
fn unified_prepare_returns_schema_v2_prepared_types() {
    let client_v2 = TempConfig::new(CLIENT_V2_MINIMAL);
    let client = prepare_client(&client_v2.0).expect("prepare client V2");
    assert!(!client.has_tun());

    let server_v2 = TempConfig::new(SERVER_V2);
    let server = prepare_server(&server_v2.0).expect("prepare server V2");
    assert_eq!(server.outbound_count(), 1);
}

fn assert_schema_version_error<T>(result: Result<T, ConfigError>) {
    let error = match result {
        Ok(_) => panic!("unsupported schema produced a configuration"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(error.field(), ConfigField::SchemaVersion);
}

#[test]
fn load_and_prepare_reject_missing_and_unsupported_schema_versions() {
    let client_sources = [
        CLIENT_V2_MINIMAL.replacen("schema_version = 2", "schema_version = 1", 1),
        CLIENT_V2_MINIMAL.replacen("schema_version = 2", "schema_version = 0", 1),
        CLIENT_V2_MINIMAL.replacen("schema_version = 2", "schema_version = 3", 1),
        CLIENT_V2_MINIMAL.replacen("schema_version = 2", "", 1),
    ];
    for source in client_sources {
        let file = TempConfig::new(&source);
        assert_schema_version_error(prepare_client(&file.0));
        assert_schema_version_error(prepare_client(&file.0));
    }

    let server_sources = [
        SERVER_V2.replacen("schema_version = 2", "schema_version = 1", 1),
        SERVER_V2.replacen("schema_version = 2", "schema_version = 0", 1),
        SERVER_V2.replacen("schema_version = 2", "schema_version = 3", 1),
        SERVER_V2.replacen("schema_version = 2", "", 1),
    ];
    for source in server_sources {
        let file = TempConfig::new(&source);
        assert_schema_version_error(prepare_server(&file.0));
        assert_schema_version_error(prepare_server(&file.0));
    }
}

#[test]
fn prepared_and_finished_client_preserve_strict_route_request_and_effective_state() {
    let without_tun = TempConfig::new(CLIENT_V2_MINIMAL);
    let without_tun = prepare_client(&without_tun.0).expect("prepare client without TUN");
    assert!(!without_tun.has_tun());
    assert!(!without_tun.tun_auto_route());
    assert!(!without_tun.tun_strict_route_requested());
    assert!(!without_tun.tun_strict_route_effective());

    for (auto_route, strict_route, effective) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let source = format!(
            r#"
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = {auto_route}
strict_route = {strict_route}
outbound = "direct"

[[outbounds]]
tag = "direct"
type = "direct"
"#,
        );
        let file = TempConfig::new(&source);
        let prepared = prepare_client(&file.0).expect("prepare strict-route combination");
        assert!(prepared.has_tun());
        assert_eq!(prepared.tun_auto_route(), auto_route);
        assert_eq!(prepared.tun_strict_route_requested(), strict_route);
        assert_eq!(prepared.tun_strict_route_effective(), effective);

        let finished = finish_client_v2(prepared, ClientV2Resources::default())
            .expect("finish strict-route combination");
        let tun = finished.tun.expect("finished TUN");
        assert_eq!(tun.auto_route, auto_route);
        assert_eq!(tun.strict_route_requested(), strict_route);
        assert_eq!(tun.strict_route_effective(), effective);
    }
}

#[test]
fn route_network_values_survive_client_and_server_prepare_finish() {
    let client_source = CLIENT_V2_MINIMAL.replacen(
        "[route]\n",
        "[route]\nauto_detect_interface = true\ndefault_interface = \"Client Ethernet\"\n",
        1,
    );
    let client_file = TempConfig::new(&client_source);
    let client = prepare_client(&client_file.0).expect("prepare client route network");
    assert!(client.route_network().auto_detect_interface);
    assert_eq!(
        client.route_network().default_interface(),
        Some("Client Ethernet")
    );
    let client = finish_client_v2(client, ClientV2Resources::default())
        .expect("finish client route network");
    assert!(client.route_network.auto_detect_interface);
    assert_eq!(
        client.route_network.default_interface(),
        Some("Client Ethernet")
    );

    let server_source = r#"
schema_version = 2

[[inbounds]]
tag = "server"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"

[route]
auto_detect_interface = true
default_interface = "Server Ethernet"
final = "direct"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let server_file = TempConfig::new(server_source);
    let server = prepare_server(&server_file.0).expect("prepare server route network");
    assert!(server.route_network().auto_detect_interface);
    assert_eq!(
        server.route_network().default_interface(),
        Some("Server Ethernet")
    );
    let server = finish_server_v2(server, ServerV2Resources::default())
        .expect("finish server route network");
    assert!(server.route_network.auto_detect_interface);
    assert_eq!(
        server.route_network.default_interface(),
        Some("Server Ethernet")
    );
}

#[test]
fn outbound_dial_options_survive_client_and_server_prepare_finish() {
    let client_source = r#"
schema_version = 2

[[inbounds]]
tag = "client"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct"
type = "direct"
bind_interface = "Client Ethernet"
inet4_bind_address = "192.0.2.10"
inet6_bind_address = "2001:db8::10"

[route]
final = "direct"
"#;
    let client_file = TempConfig::new(client_source);
    let client = prepare_client(&client_file.0).expect("prepare client dial options");
    let descriptor = client.outbound(0).expect("client outbound descriptor");
    assert_eq!(
        descriptor.dial_options().bind_interface(),
        Some("Client Ethernet")
    );
    assert_eq!(
        descriptor.dial_options().inet4_bind_address(),
        Some("192.0.2.10".parse().unwrap())
    );
    assert_eq!(
        descriptor.dial_options().inet6_bind_address(),
        Some("2001:db8::10".parse().unwrap())
    );
    let debug = format!("{descriptor:?}");
    assert!(!debug.contains("Client Ethernet"));
    assert!(!debug.contains("192.0.2.10"));
    let client =
        finish_client_v2(client, ClientV2Resources::default()).expect("finish client dial options");
    assert_eq!(
        client.outbounds[0].dial_options().bind_interface(),
        Some("Client Ethernet")
    );

    let server_source = r#"
schema_version = 2

[[inbounds]]
tag = "server"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"
bind_interface = "Server Ethernet"
inet4_bind_address = "198.51.100.10"
inet6_bind_address = "2001:db8::20"

[route]
final = "direct"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let server_file = TempConfig::new(server_source);
    let server = prepare_server(&server_file.0).expect("prepare server dial options");
    let descriptor = server.outbound(0).expect("server outbound descriptor");
    assert_eq!(
        descriptor.dial_options().bind_interface(),
        Some("Server Ethernet")
    );
    assert_eq!(
        descriptor.dial_options().inet4_bind_address(),
        Some("198.51.100.10".parse().unwrap())
    );
    let server =
        finish_server_v2(server, ServerV2Resources::default()).expect("finish server dial options");
    assert_eq!(
        server.outbounds[0].dial_options().bind_interface(),
        Some("Server Ethernet")
    );
}
