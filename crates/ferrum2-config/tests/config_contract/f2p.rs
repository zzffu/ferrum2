use super::support::*;
use ferrum2_config::{PreparedClientOutboundKind, ServerInboundProtocol};
use ferrum2_f2p::Profile;

const CLIENT: &str = r#"
schema_version = 2
[[inbounds]]
tag = "socks"
listen = "127.0.0.1:1080"
outbound = "proxy"
[[outbounds]]
tag = "proxy"
type = "f2p"
server = "192.0.2.10:8443"
[outbounds.auth]
token_file = "missing-secrets/client.token"
[outbounds.tls]
server_name = "edge.example.test"
ca_file = "missing-secrets/ca.pem"
"#;

const SERVER: &str = r#"
schema_version = 2
[[inbounds]]
tag = "proxy"
type = "f2p"
listen = "127.0.0.1:8443"
outbound = "direct"
[inbounds.auth]
token_file = "missing-secrets/server.token"
[inbounds.tls]
certificate_file = "missing-secrets/cert.pem"
private_key_file = "missing-secrets/key.pem"
[[outbounds]]
tag = "direct"
"#;

#[test]
fn f2p_domain_materialization_retains_credentials_profile_and_dial_policy() {
    let source = CLIENT.replace(
        "server = \"192.0.2.10:8443\"",
        "server = \"edge.example.test:8443\"\ndomain_resolver = \"system\"\ndomain_strategy = \"ipv4_only\"\nprofile = \"realtime\"\nbind_interface = \"Ethernet\"\ninet4_bind_address = \"192.0.2.4\"",
    );
    let file = TempConfig::text(&source);
    let prepared = prepare_client(file.path()).expect("offline prepare without credential files");
    let outbound = prepared.outbound(0).unwrap();
    assert_eq!(outbound.kind(), PreparedClientOutboundKind::F2p);
    assert!(matches!(
        outbound.endpoint(),
        Some(DialEndpoint::Domain { .. })
    ));
    let expected = outbound.f2p().unwrap().clone();
    let resources = client_resources(&prepared);
    let config = finish_client_v2(prepared, resources).expect("resolved F2P config");
    let ClientOutboundConfig::F2p(actual) = &config.outbounds[0] else {
        panic!("F2P outbound")
    };
    assert_eq!(actual.server, "192.0.2.200:8443".parse().unwrap());
    assert_eq!(actual.profile, Profile::Realtime);
    assert_eq!(actual.token_file, expected.token_file);
    assert_eq!(actual.server_name, expected.server_name);
    assert_eq!(actual.ca_file, expected.ca_file);
    assert_eq!(actual.dial_options, expected.dial_options);
    assert_eq!(
        selected_plan(
            &config.route,
            0,
            Network::Udp,
            &TargetAddr::domain("game.test", 443).unwrap()
        )
        .hops(),
        &[0]
    );
}

#[test]
fn f2p_only_server_needs_no_shadowsocks_secret_and_mixed_server_does() {
    let config = validated_server(TempConfig::text(SERVER).path()).expect("offline F2P server");
    assert!(config.psk.is_none());
    assert!(config.method().is_none());
    let ServerInboundProtocol::F2p(protocol) = &config.inbounds[0].protocol else {
        panic!("F2P listener")
    };
    assert_eq!(
        protocol.token_file,
        Path::new("missing-secrets/server.token")
    );
    assert_eq!(
        protocol.certificate_file,
        Path::new("missing-secrets/cert.pem")
    );
    assert_eq!(
        protocol.private_key_file,
        Path::new("missing-secrets/key.pem")
    );
    let mixed = format!(
        "{SERVER}\n[[inbounds]]\ntag = \"ss\"\nlisten = \"127.0.0.1:8388\"\noutbound = \"direct\"\n"
    );
    assert_eq!(
        prepare_server(TempConfig::text(&mixed).path())
            .err()
            .unwrap()
            .field(),
        ConfigField::ShadowsocksMethod
    );
    let mixed = format!(
        "{mixed}\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
    );
    let config = validated_server(TempConfig::text(&mixed).path()).expect("mixed protocols");
    assert!(config.psk.is_some());
    assert!(matches!(
        config.inbounds[1].protocol,
        ServerInboundProtocol::Shadowsocks
    ));
}

#[test]
fn f2p_selector_supports_tcp_udp_and_default_profile() {
    let source = CLIENT.replace("outbound = \"proxy\"", "outbound = \"select\"")
        + r#"
[[outbounds]]
tag = "direct"
type = "direct"
[[selectors]]
tag = "select"
outbounds = ["proxy", "direct"]
default = "proxy"
[udp]
enabled = true
max_sessions = 7
max_buffered_bytes = 1048576
"#;
    let config = validated_client(TempConfig::text(&source).path()).expect("F2P selector");
    let ClientOutboundConfig::F2p(protocol) = &config.outbounds[0] else {
        panic!("F2P outbound")
    };
    assert_eq!(protocol.profile, Profile::Balanced);
    let target = TargetAddr::domain("game.test", 443).unwrap();
    for network in [Network::Tcp, Network::Udp] {
        assert_eq!(
            selected_plan(&config.route, 0, network, &target).hops(),
            &[0]
        );
    }
    assert_eq!(config.udp.unwrap().max_sessions, 7);
}

#[test]
fn f2p_rejects_nested_chains_and_inapplicable_fields() {
    for hops in ["\"proxy\", \"ss\"", "\"ss\", \"proxy\""] {
        let source = CLIENT.replace("outbound = \"proxy\"", "outbound = \"chain\"")
            + &format!(
                r#"
[[outbounds]]
tag = "ss"
type = "shadowsocks"
server = "192.0.2.11:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[chains]]
tag = "chain"
hops = [{hops}]
"#
            );
        assert_eq!(
            prepare_client(TempConfig::text(&source).path())
                .err()
                .unwrap()
                .field(),
            ConfigField::ChainsHops
        );
    }
    for (extra, field) in [
        ("profile = \"fast\"", ConfigField::OutboundsProfile),
        (
            "method = \"2022-blake3-aes-128-gcm\"",
            ConfigField::OutboundsMethod,
        ),
        (
            "psk = \"AAECAwQFBgcICQoLDA0ODw==\"",
            ConfigField::OutboundsPsk,
        ),
    ] {
        let source = CLIENT.replace("type = \"f2p\"", &format!("type = \"f2p\"\n{extra}"));
        assert_eq!(
            prepare_client(TempConfig::text(&source).path())
                .err()
                .unwrap()
                .field(),
            field
        );
    }
    for extra in ["transport = \"tcp\"", "udp = true", "udp_enabled = true"] {
        let source = CLIENT.replace("type = \"f2p\"", &format!("type = \"f2p\"\n{extra}"));
        assert_eq!(
            prepare_client(TempConfig::text(&source).path())
                .err()
                .unwrap()
                .kind(),
            ConfigErrorKind::Syntax
        );
    }
    for (source, field) in [
        (
            CLIENT.replace("missing-secrets/client.token", ""),
            ConfigField::OutboundsAuth,
        ),
        (
            CLIENT.replace("edge.example.test", "bad name"),
            ConfigField::OutboundsTls,
        ),
        (
            CLIENT.replace("missing-secrets/ca.pem", ""),
            ConfigField::OutboundsTls,
        ),
        (
            CLIENT.replace("type = \"f2p\"", "type = \"direct\""),
            ConfigField::OutboundsAuth,
        ),
    ] {
        assert_eq!(
            prepare_client(TempConfig::text(&source).path())
                .err()
                .unwrap()
                .field(),
            field
        );
    }
    for (source, field) in [
        (
            SERVER.replace("missing-secrets/server.token", ""),
            ConfigField::InboundsAuth,
        ),
        (
            SERVER.replace("missing-secrets/key.pem", ""),
            ConfigField::InboundsTls,
        ),
        (
            SERVER.replace("type = \"f2p\"", "type = \"shadowsocks\""),
            ConfigField::InboundsAuth,
        ),
    ] {
        assert_eq!(
            prepare_server(TempConfig::text(&source).path())
                .err()
                .unwrap()
                .field(),
            field
        );
    }
}

#[test]
fn f2p_is_a_dns_and_rule_set_detour_and_tun_physical_endpoint() {
    let source = CLIENT.replace(
        "[[inbounds]]\ntag = \"socks\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy\"",
        "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\nauto_route = true",
    ) + r#"
[route]
final = "proxy"
[[route.rule_set]]
tag = "remote"
type = "remote"
format = "binary"
url = "https://rules.example.test/rules.srs"
download_resolver = "system"
download_detour = "proxy"
[[route.rules]]
rule_set = "remote"
action = "reject"
[dns]
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:1053"
[[dns.servers]]
tag = "remote-dns"
transport = "udp"
address = "192.0.2.53:53"
detour = "proxy"
[dns.route]
final = "remote-dns"
[udp]
enabled = true
"#;
    let file = TempConfig::text(&source);
    let prepared = prepare_client(file.path()).expect("F2P resource consumer preparation");
    assert!(prepared.rule_sets()[0].download_detour().is_some());
    let resources = client_resources(&prepared);
    let config = finish_client_v2(prepared, resources).expect("F2P resource consumer finish");
    assert_eq!(
        config.tun.unwrap().physical_endpoints,
        vec!["192.0.2.10:8443".parse::<SocketAddr>().unwrap()]
    );
    assert!(config.dns.unwrap().servers[0].detour.is_some());
}
