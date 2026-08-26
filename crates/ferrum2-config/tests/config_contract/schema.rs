use super::support::*;

#[test]
fn schema_v2_fixture_cohort_normalizes_defaults_boundaries_and_choices() {
    let cases = [
        CohortCase {
            name: "client defaults",
            fixture: "client-valid.toml",
            role: ConfigRole::Client,
            method: MethodProfile::Blake3Aes128Gcm2022,
            runtime: [4_096, 1_024, 5_000, 10_000, 300_000, 30_000],
            replay_capacity: None,
            udp: None,
            logging: LoggingLevel::Info,
            metrics_port: None,
        },
        CohortCase {
            name: "client minimum boundaries",
            fixture: "client-preserved-minimum.toml",
            role: ConfigRole::Client,
            method: MethodProfile::Blake3Aes256Gcm2022,
            runtime: [1, 1, 100, 100, 1_000, 0],
            replay_capacity: None,
            udp: None,
            logging: LoggingLevel::Error,
            metrics_port: Some(9_090),
        },
        CohortCase {
            name: "server defaults",
            fixture: "server-valid.toml",
            role: ConfigRole::Server,
            method: MethodProfile::Blake3Aes128Gcm2022,
            runtime: [4_096, 1_024, 5_000, 10_000, 300_000, 30_000],
            replay_capacity: Some(65_536),
            udp: Some((true, 4_096, 16_777_216, 300_000)),
            logging: LoggingLevel::Info,
            metrics_port: None,
        },
        CohortCase {
            name: "server minimum boundaries",
            fixture: "server-preserved-minimum.toml",
            role: ConfigRole::Server,
            method: MethodProfile::Blake3Aes256Gcm2022,
            runtime: [1, 1, 100, 100, 1_000, 0],
            replay_capacity: Some(1_024),
            udp: Some((false, 1, 1_048_576, 60_000)),
            logging: LoggingLevel::Warn,
            metrics_port: None,
        },
        CohortCase {
            name: "server maximum boundaries",
            fixture: "server-preserved-maximum.toml",
            role: ConfigRole::Server,
            method: MethodProfile::Blake3ChaCha20Poly13052022,
            runtime: [65_535, 65_535, 60_000, 120_000, 86_400_000, 300_000],
            replay_capacity: Some(1_048_576),
            udp: Some((true, 65_535, 268_435_456, 86_400_000)),
            logging: LoggingLevel::Trace,
            metrics_port: Some(9_091),
        },
    ];

    for case in cases {
        let path = fixture(case.fixture);
        let source_before = fs::read(&path).expect(case.name);
        match case.role {
            ConfigRole::Client => {
                let config = validated_client(&path).expect(case.name);
                let outbound = &config.outbounds[0];
                let actual = (
                    config.inbounds[0].listen,
                    outbound.server(),
                    outbound.method(),
                    format!("{outbound:?}"),
                    config.logging.level,
                    config.metrics.map(|metrics| metrics.listen.port()),
                );
                let expected = (
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1_080),
                    Some(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::LOCALHOST,
                        8_388,
                    ))),
                    Some(case.method),
                    "ClientOutboundConfig::Shadowsocks([redacted])".to_owned(),
                    case.logging,
                    case.metrics_port,
                );
                assert_eq!(actual, expected, "{}", case.name);
                assert_runtime(config.runtime, case.runtime, case.name);
                assert!(case.replay_capacity.is_none());
                assert!(case.udp.is_none());
                assert!(config.dns.is_none(), "{}", case.name);
                assert_eq!(config.inbounds.len(), 1, "{}", case.name);
                assert_eq!(config.outbounds.len(), 1, "{}", case.name);
                assert_eq!(
                    config.inbounds[0].listen, config.inbounds[0].listen,
                    "{}",
                    case.name
                );
                assert_eq!(
                    config.outbounds[selected(&config.route, 0)].server(),
                    outbound.server()
                );
            }
            ConfigRole::Server => {
                let config = validated_server(&path).expect(case.name);
                let expected_udp = case.udp.expect("server UDP expectation");
                let actual = (
                    config.inbounds[0].listen,
                    config.method(),
                    format!("{:?}", config.psk),
                    Some(config.replay.capacity),
                    config.udp.enabled,
                    config.udp.max_sessions,
                    config.udp.max_buffered_bytes,
                    config.udp.idle_timeout.as_millis() as u64,
                    config.logging.level,
                    config.metrics.map(|metrics| metrics.listen.port()),
                );
                let expected = (
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_388),
                    case.method,
                    "MethodPsk([REDACTED])".to_owned(),
                    case.replay_capacity,
                    expected_udp.0,
                    expected_udp.1,
                    expected_udp.2,
                    expected_udp.3,
                    case.logging,
                    case.metrics_port,
                );
                assert_eq!(actual, expected, "{}", case.name);
                assert_runtime(config.runtime, case.runtime, case.name);
                assert!(config.dns.is_none(), "{}", case.name);
                assert_eq!(config.inbounds.len(), 1, "{}", case.name);
                assert_eq!(config.outbounds.len(), 1, "{}", case.name);
                assert_eq!(
                    config.inbounds[0].listen, config.inbounds[0].listen,
                    "{}",
                    case.name
                );
            }
        }
        assert_eq!(
            fs::read(&path).expect(case.name),
            source_before,
            "{}",
            case.name
        );
    }

    let mut exact_limit = format!("{CLIENT_BASE}\n#").into_bytes();
    exact_limit.resize(MAX_CONFIG_BYTES - 1, b'a');
    exact_limit.push(b'\n');
    let file = TempConfig::bytes(&exact_limit);
    validated_client(file.path()).expect("the documented maximum size remains accepted");
}
