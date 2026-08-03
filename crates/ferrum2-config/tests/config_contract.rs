use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferrum2_config::{
    ConfigErrorKind, ConfigField, LoggingLevel, MAX_CONFIG_BYTES, RuntimeConfig, load_client,
    load_server,
};
use ferrum2_crypto::TcpMethodProfile;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/config")
        .join(name)
}

const CLIENT_BASE: &str = "schema_version = 1\n[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

const SERVER_BASE: &str = "schema_version = 1\n[server]\nlisten = \"127.0.0.1:8388\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

fn tagged_client(inbound_count: usize, outbound_count: usize) -> String {
    let mut source = "schema_version = 1\n".to_owned();
    for index in 0..inbound_count {
        source.push_str(&format!(
            "[[inbounds]]\ntag = \"i{index}\"\nlisten = \"127.0.0.1:{}\"\noutbound = \"o{}\"\n",
            10_000 + index,
            index.min(outbound_count.saturating_sub(1))
        ));
    }
    for index in 0..outbound_count {
        source.push_str(&format!(
            "[[outbounds]]\ntag = \"o{index}\"\nserver = \"127.0.0.1:{}\"\n",
            20_000 + index
        ));
    }
    source.push_str(
        "[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
    );
    source
}

fn tagged_server(inbound_count: usize, outbound_count: usize) -> String {
    tagged_client(inbound_count, outbound_count)
        .lines()
        .filter(|line| !line.starts_with("server = "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn assert_tagged_error(
    name: &str,
    role: ConfigRole,
    mut source: String,
    expected: (ConfigErrorKind, ConfigField),
    index: usize,
) {
    let raw = format!("raw_sentinel_{index}");
    if !source.contains("[metrics]") {
        source.push_str(&format!(
            "[metrics]\nlisten = \"127.0.0.1:{}\"\n",
            30_003 + index * 4
        ));
    }
    source = source
        .replace("i0", &format!("r{index}i"))
        .replace("o0", &format!("r{index}o"));
    let endpoints = [30_000 + index * 4, 30_001 + index * 4, 30_002 + index * 4];
    source = source
        .replace("127.0.0.1:10000", &format!("127.0.0.1:{}", endpoints[0]))
        .replace("127.0.0.1:10001", &format!("127.0.0.1:{}", endpoints[1]))
        .replace("127.0.0.1:20000", &format!("127.0.0.1:{}", endpoints[2]));
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let psk = format!("{}AECAwQFBgcICQoLDA0ODw==", char::from(alphabet[index]));
    source = source.replace("AAECAwQFBgcICQoLDA0ODw==", &psk);
    source.push_str(&format!("# {raw}\n"));

    let file = TempConfig::text(&source);
    let error = match role {
        ConfigRole::Client => load_client(file.path()).err(),
        ConfigRole::Server => load_server(file.path()).err(),
    }
    .expect(name);
    assert_eq!((error.kind(), error.field()), expected, "{name}");
    let rendered = format!("{error}\n{error:?}");
    let values = source.lines().filter_map(|line| {
        let (field, value) = line.split_once(" = ")?;
        matches!(field, "tag" | "outbound" | "listen" | "server" | "psk")
            .then(|| value.strip_prefix('"')?.strip_suffix('"'))?
            .filter(|value| !value.is_empty())
    });
    for sentinel in std::iter::once(raw.as_str()).chain(values) {
        assert!(!rendered.contains(sentinel), "{name}: {sentinel}");
    }
}

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

struct TempConfig(PathBuf);

impl TempConfig {
    fn text(contents: &str) -> Self {
        Self::bytes(contents.as_bytes())
    }

    fn bytes(contents: &[u8]) -> Self {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-m0-t04-{}-{sequence}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write temporary config");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Clone, Copy)]
enum ConfigRole {
    Client,
    Server,
}

struct CohortCase {
    name: &'static str,
    fixture: &'static str,
    role: ConfigRole,
    method: TcpMethodProfile,
    runtime: [u64; 6],
    replay_capacity: Option<usize>,
    udp: Option<(bool, usize, usize, u64)>,
    logging: LoggingLevel,
    metrics_port: Option<u16>,
}

struct SchemaV1CompatibilityPolicy {
    all_v0_releases: bool,
    successor_minimum_months: u8,
    successor_minimum_stable_minors: u8,
    prior_stable_release_notice: bool,
    elapsed_time_proven_at_m3_close: bool,
}

const SCHEMA_V1_COMPATIBILITY_POLICY: SchemaV1CompatibilityPolicy = SchemaV1CompatibilityPolicy {
    all_v0_releases: true,
    successor_minimum_months: 12,
    successor_minimum_stable_minors: 2,
    prior_stable_release_notice: true,
    elapsed_time_proven_at_m3_close: false,
};

fn assert_runtime(actual: RuntimeConfig, expected: [u64; 6], name: &str) {
    let actual = (
        u64::from(actual.max_connections.get()),
        u64::from(actual.listen_backlog.get()),
        actual.handshake_timeout,
        actual.connect_timeout,
        actual.idle_timeout,
        actual.shutdown_grace,
    );
    let expected = (
        expected[0],
        expected[1],
        Duration::from_millis(expected[2]),
        Duration::from_millis(expected[3]),
        Duration::from_millis(expected[4]),
        Duration::from_millis(expected[5]),
    );
    assert_eq!(actual, expected, "{name}");
}

#[test]
fn preserved_schema_v1_cohort_normalizes_defaults_boundaries_and_choices() {
    let cases = [
        CohortCase {
            name: "client defaults",
            fixture: "client-valid.toml",
            role: ConfigRole::Client,
            method: TcpMethodProfile::Blake3Aes128Gcm2022,
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
            method: TcpMethodProfile::Blake3Aes256Gcm2022,
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
            method: TcpMethodProfile::Blake3Aes128Gcm2022,
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
            method: TcpMethodProfile::Blake3Aes256Gcm2022,
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
            method: TcpMethodProfile::Blake3ChaCha20Poly13052022,
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
                let config = load_client(&path).expect(case.name);
                let actual = (
                    config.listen,
                    config.server,
                    config.method(),
                    format!("{:?}", config.psk),
                    config.logging.level,
                    config.metrics.map(|metrics| metrics.listen.port()),
                );
                let expected = (
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1_080),
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_388),
                    case.method,
                    "MethodPsk([REDACTED])".to_owned(),
                    case.logging,
                    case.metrics_port,
                );
                assert_eq!(actual, expected, "{}", case.name);
                assert_runtime(config.runtime, case.runtime, case.name);
                assert!(case.replay_capacity.is_none());
                assert!(case.udp.is_none());
                assert_eq!(config.inbounds.len(), 1, "{}", case.name);
                assert_eq!(config.outbounds.len(), 1, "{}", case.name);
                assert_eq!(config.inbounds[0].listen, config.listen, "{}", case.name);
                assert_eq!(
                    config.inbounds[0].outbound.server, config.server,
                    "{}",
                    case.name
                );
            }
            ConfigRole::Server => {
                let config = load_server(&path).expect(case.name);
                let expected_udp = case.udp.expect("server UDP expectation");
                let actual = (
                    config.listen,
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
                assert_eq!(config.inbounds.len(), 1, "{}", case.name);
                assert_eq!(config.outbounds.len(), 1, "{}", case.name);
                assert_eq!(config.inbounds[0].listen, config.listen, "{}", case.name);
            }
        }
        assert_eq!(
            fs::read(&path).expect(case.name),
            source_before,
            "{}",
            case.name
        );
    }

    let policy = SCHEMA_V1_COMPATIBILITY_POLICY;
    let policy = (
        policy.all_v0_releases,
        policy.successor_minimum_months,
        policy.successor_minimum_stable_minors,
        policy.prior_stable_release_notice,
        policy.elapsed_time_proven_at_m3_close,
    );
    assert_eq!(policy, (true, 12, 2, true, false));

    let mut exact_limit = format!("{CLIENT_BASE}\n#").into_bytes();
    exact_limit.resize(MAX_CONFIG_BYTES - 1, b'a');
    exact_limit.push(b'\n');
    let file = TempConfig::bytes(&exact_limit);
    load_client(file.path()).expect("the documented maximum size remains accepted");
}

#[test]
fn tagged_graph_normalizes_complete_resolved_collections() {
    for (method, psk) in [
        ("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="),
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
        ),
    ] {
        let source = tagged_client(2, 2)
            .replacen("2022-blake3-aes-128-gcm", method, 1)
            .replacen("AAECAwQFBgcICQoLDA0ODw==", psk, 1);
        let config = load_client(TempConfig::text(&source).path()).expect(method);
        assert_eq!(config.inbounds.len(), 2, "{method}");
        assert_eq!(config.outbounds.len(), 2, "{method}");
        assert_eq!(config.inbounds[1].outbound, config.outbounds[1], "{method}");
        let source = tagged_server(2, 2)
            .replacen("2022-blake3-aes-128-gcm", method, 1)
            .replacen("AAECAwQFBgcICQoLDA0ODw==", psk, 1);
        let config = load_server(TempConfig::text(&source).path()).expect(method);
        assert_eq!(config.inbounds[1].outbound, 1, "{method}");
    }

    let shared = tagged_client(2, 1);
    let config = load_client(TempConfig::text(&shared).path()).expect("shared outbound");
    assert_eq!(config.inbounds[0].outbound, config.inbounds[1].outbound);
    let exact_case = tagged_client(1, 1)
        .replacen("outbound = \"o0\"", "outbound = \"O0\"", 1)
        .replacen("tag = \"o0\"", "tag = \"O0\"", 1);
    load_client(TempConfig::text(&exact_case).path()).expect("exact case-sensitive match");
    let shared_server =
        load_server(TempConfig::text(&tagged_server(2, 1)).path()).expect("shared direct");
    assert_eq!(shared_server.inbounds[0].outbound, 0);
    assert_eq!(shared_server.inbounds[1].outbound, 0);

    let client = load_client(TempConfig::text(&tagged_client(64, 64)).path()).expect("64 client");
    assert_eq!((client.inbounds.len(), client.outbounds.len()), (64, 64));
    let server = load_server(TempConfig::text(&tagged_server(64, 64)).path()).expect("64 server");
    assert_eq!((server.inbounds.len(), server.outbounds.len()), (64, 64));
    assert_eq!(server.inbounds[63].outbound, 63);
}

#[test]
fn tagged_graph_rejects_invalid_counts_tags_references_and_collisions_redacted() {
    let valid = tagged_client(2, 2);
    let server = tagged_server(2, 2);
    let server_three = tagged_server(3, 3);
    let mut cases = vec![
        ("empty inbounds", tagged_client(0, 1), ConfigField::Inbounds, ConfigRole::Client),
        ("empty outbounds", tagged_client(1, 0), ConfigField::Outbounds, ConfigRole::Client),
        ("65 inbounds", tagged_client(65, 1), ConfigField::Inbounds, ConfigRole::Client),
        ("65 outbounds", tagged_client(1, 65), ConfigField::Outbounds, ConfigRole::Client),
        ("empty tag", valid.replacen("tag = \"i0\"", "tag = \"\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("long tag", valid.replacen("tag = \"i0\"", &format!("tag = \"{}\"", "a".repeat(65)), 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("non ASCII tag", valid.replacen("tag = \"i0\"", "tag = \"é\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("whitespace tag", valid.replacen("tag = \"i0\"", "tag = \"bad tag\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("invalid tag", valid.replacen("tag = \"i0\"", "tag = \"bad/tag\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("invalid outbound tag", valid.replacen("tag = \"o0\"", "tag = \"bad/tag\"", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("duplicate inbound", valid.replacen("tag = \"i1\"", "tag = \"i0\"", 1), ConfigField::InboundsTag, ConfigRole::Client),
        ("duplicate outbound", valid.replacen("tag = \"o1\"", "tag = \"o0\"", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("global collision", valid.replacen("tag = \"o0\"", "tag = \"i0\"", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("invalid reference", valid.replacen("outbound = \"o0\"", "outbound = \"bad ref\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("dangling reference", valid.replacen("outbound = \"o0\"", "outbound = \"missing\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("wrong namespace", valid.replacen("outbound = \"o0\"", "outbound = \"i0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("case sensitive", valid.replacen("outbound = \"o0\"", "outbound = \"O0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Client),
        ("unreferenced", tagged_client(1, 2), ConfigField::OutboundsTag, ConfigRole::Client),
        ("duplicate listen", valid.replacen("127.0.0.1:10001", "127.0.0.1:10000", 1), ConfigField::InboundsListen, ConfigRole::Client),
        ("client server collision", valid.replacen("127.0.0.1:20000", "127.0.0.1:10000", 1), ConfigField::OutboundsServer, ConfigRole::Client),
        ("client metrics collision", format!("{valid}[metrics]\nlisten = \"127.0.0.1:10001\"\n"), ConfigField::MetricsListen, ConfigRole::Client),
        ("server metrics collision", format!("{server}[metrics]\nlisten = \"127.0.0.1:10001\"\n"), ConfigField::MetricsListen, ConfigRole::Server),
        ("server empty inbounds", tagged_server(0, 1), ConfigField::Inbounds, ConfigRole::Server),
        ("server empty outbounds", tagged_server(1, 0), ConfigField::Outbounds, ConfigRole::Server),
        ("server 65 inbounds", tagged_server(65, 1), ConfigField::Inbounds, ConfigRole::Server),
        ("server 65 outbounds", tagged_server(1, 65), ConfigField::Outbounds, ConfigRole::Server),
        ("server invalid inbound tag", server.replacen("tag = \"i0\"", "tag = \"bad/tag\"", 1), ConfigField::InboundsTag, ConfigRole::Server),
        ("server invalid outbound tag", server.replacen("tag = \"o0\"", "tag = \"bad/tag\"", 1), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server duplicate inbound", server.replacen("tag = \"i1\"", "tag = \"i0\"", 1), ConfigField::InboundsTag, ConfigRole::Server),
        ("server duplicate outbound", server.replacen("tag = \"o1\"", "tag = \"o0\"", 1), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server global collision", server.replacen("tag = \"o0\"", "tag = \"i0\"", 1), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server dangling", server.replacen("outbound = \"o0\"", "outbound = \"missing\"", 1), ConfigField::InboundsOutbound, ConfigRole::Server),
        ("server wrong namespace", server.replacen("outbound = \"o0\"", "outbound = \"i0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Server),
        ("server case sensitive", server.replacen("outbound = \"o0\"", "outbound = \"O0\"", 1), ConfigField::InboundsOutbound, ConfigRole::Server),
        ("server unreferenced", tagged_server(1, 2), ConfigField::OutboundsTag, ConfigRole::Server),
        ("server duplicate listen", server.replacen("127.0.0.1:10001", "127.0.0.1:10000", 1), ConfigField::InboundsListen, ConfigRole::Server),
        ("server first last duplicate", server_three.replacen("127.0.0.1:10002", "127.0.0.1:10000", 1), ConfigField::InboundsListen, ConfigRole::Server),
        ("server metrics first", format!("{server_three}[metrics]\nlisten = \"127.0.0.1:10000\"\n"), ConfigField::MetricsListen, ConfigRole::Server),
        ("server metrics last", format!("{server_three}[metrics]\nlisten = \"127.0.0.1:10002\"\n"), ConfigField::MetricsListen, ConfigRole::Server),
        ("client server last collision", tagged_client(3, 3).replacen("127.0.0.1:20000", "127.0.0.1:10002", 1), ConfigField::OutboundsServer, ConfigRole::Client),
        ("missing inbounds", "schema_version = 1\n[[outbounds]]\ntag = \"o0\"\nserver = \"127.0.0.1:20000\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Inbounds, ConfigRole::Client),
        ("missing outbounds", "schema_version = 1\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"o0\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Outbounds, ConfigRole::Client),
        ("server missing inbounds", "schema_version = 1\n[[outbounds]]\ntag = \"o0\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Inbounds, ConfigRole::Server),
        ("server missing outbounds", "schema_version = 1\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"o0\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Outbounds, ConfigRole::Server),
    ];
    cases.push((
        "legacy tagged mixing",
        format!("{CLIENT_BASE}[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"o0\"\n[[outbounds]]\ntag = \"o0\"\nserver = \"127.0.0.1:20000\"\n"),
        ConfigField::Inbounds,
        ConfigRole::Client,
    ));
    cases.push((
        "server legacy tagged mixing",
        format!("{SERVER_BASE}[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"o0\"\n[[outbounds]]\ntag = \"o0\"\n"),
        ConfigField::Inbounds,
        ConfigRole::Server,
    ));

    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            index,
        );
    }

    let client_unknown = valid.replacen(
        "server = \"127.0.0.1:20000\"",
        "server = \"127.0.0.1:20000\"\nunexpected = true",
        1,
    );
    assert_tagged_error(
        "client nested unknown",
        ConfigRole::Client,
        client_unknown,
        (ConfigErrorKind::Syntax, ConfigField::Config),
        50,
    );
    let server_unknown = server.replacen("tag = \"o0\"", "tag = \"o0\"\nunexpected = true", 1);
    assert_tagged_error(
        "server nested unknown",
        ConfigRole::Server,
        server_unknown,
        (ConfigErrorKind::Syntax, ConfigField::Config),
        51,
    );

    let fields = [
        ConfigField::Inbounds,
        ConfigField::Outbounds,
        ConfigField::InboundsTag,
        ConfigField::InboundsListen,
        ConfigField::InboundsOutbound,
        ConfigField::OutboundsTag,
        ConfigField::OutboundsServer,
    ];
    assert_eq!(
        fields.map(ConfigField::as_str),
        [
            "inbounds",
            "outbounds",
            "inbounds.tag",
            "inbounds.listen",
            "inbounds.outbound",
            "outbounds.tag",
            "outbounds.server"
        ]
    );
}

#[test]
fn client_udp_is_explicit_and_reuses_server_defaults_boundaries_and_errors() {
    let cases = [
        ("empty", "", (true, 4_096, 16_777_216, 300_000)),
        (
            "enabled",
            "enabled = true\n",
            (true, 4_096, 16_777_216, 300_000),
        ),
        (
            "disabled",
            "enabled = false\n",
            (false, 4_096, 16_777_216, 300_000),
        ),
        (
            "minimum",
            "max_sessions = 1\nmax_buffered_bytes = 1048576\nidle_timeout_ms = 60000\n",
            (true, 1, 1_048_576, 60_000),
        ),
        (
            "maximum",
            "max_sessions = 65535\nmax_buffered_bytes = 268435456\nidle_timeout_ms = 86400000\n",
            (true, 65_535, 268_435_456, 86_400_000),
        ),
    ];
    for (name, section, expected) in cases {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[udp]\n{section}"));
        let udp = load_client(file.path()).expect(name).udp.expect(name);
        let actual = (
            udp.enabled,
            udp.max_sessions,
            udp.max_buffered_bytes,
            udp.idle_timeout.as_millis() as u64,
        );
        assert_eq!(actual, expected, "{name}");
    }

    let invalid = [
        ("sessions", "max_sessions", 0, ConfigField::UdpMaxSessions),
        (
            "buffer",
            "max_buffered_bytes",
            1_048_575,
            ConfigField::UdpMaxBufferedBytes,
        ),
        (
            "idle",
            "idle_timeout_ms",
            59_999,
            ConfigField::UdpIdleTimeout,
        ),
    ];
    for (name, field, value, expected) in invalid {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[udp]\n{field} = {value}\n"));
        let error = load_client(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Semantic, "{name}");
        assert_eq!(error.field(), expected, "{name}");
    }
}

#[test]
fn endpoint_method_key_and_cross_field_rules_are_enforced() {
    let cases = [
        (
            "client endpoints equal",
            CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:8388", 1),
            ConfigField::ClientServer,
        ),
        (
            "unknown method",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "future-method", 1),
            ConfigField::ShadowsocksMethod,
        ),
        (
            "reduced-round method",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-chacha8-poly1305", 1),
            ConfigField::ShadowsocksMethod,
        ),
        (
            "unpadded base64",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoLDA0ODw", 1),
            ConfigField::ShadowsocksPsk,
        ),
        (
            "whitespace base64",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoL DA0ODw==", 1),
            ConfigField::ShadowsocksPsk,
        ),
        (
            "url safe base64",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "_____________________w==", 1),
            ConfigField::ShadowsocksPsk,
        ),
    ];
    for (name, source, expected_field) in cases {
        let file = TempConfig::text(&source);
        let error = load_client(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Semantic, "{name}");
        assert_eq!(error.field(), expected_field, "{name}");
    }

    for level in ["fatal", "INFO", "client=debug"] {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[logging]\nlevel = \"{level}\"\n"));
        let actual = load_client(file.path())
            .err()
            .expect("logging level")
            .field();
        assert_eq!(actual, ConfigField::LoggingLevel);
    }
    for level in ["error", "warn", "info", "debug", "trace"] {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[logging]\nlevel = \"{level}\"\n"));
        load_client(file.path()).expect("approved logging level");
    }

    let metrics_cases = [
        ("non-loopback", "192.0.2.1:9090"),
        ("proxy collision", "127.0.0.1:1080"),
        ("zero port", "127.0.0.1:0"),
    ];
    for (name, endpoint) in metrics_cases {
        let file = TempConfig::text(&format!(
            "{CLIENT_BASE}\n[metrics]\nlisten = \"{endpoint}\"\n"
        ));
        let error = load_client(file.path()).err().expect(name);
        assert_eq!(error.field(), ConfigField::MetricsListen, "{name}");
    }

    let missing_metrics_listen = TempConfig::text(&format!("{CLIENT_BASE}\n[metrics]\n"));
    let actual = load_client(missing_metrics_listen.path())
        .err()
        .expect("metrics listen required")
        .kind();
    assert_eq!(actual, ConfigErrorKind::Syntax);

    let server_metrics_collision = TempConfig::text(&format!(
        "{SERVER_BASE}\n[metrics]\nlisten = \"127.0.0.1:8388\"\n"
    ));
    let actual = load_server(server_metrics_collision.path())
        .err()
        .expect("server metrics collision")
        .field();
    assert_eq!(actual, ConfigField::MetricsListen);
}

#[test]
fn invalid_cohort_rows_keep_stable_redacted_categories_and_fields() {
    const SOURCE_SENTINEL: &str = "M3_RAW_CONFIG_SOURCE_SENTINEL";
    let mut oversized = CLIENT_BASE.as_bytes().to_vec();
    oversized.resize(MAX_CONFIG_BYTES + 1, b' ');
    let cases = [
        (
            "missing required section",
            ConfigRole::Client,
            CLIENT_BASE
                .replace(
                    "[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n",
                    "",
                )
                .into_bytes(),
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        ),
        (
            "current reader rejects a later optional field",
            ConfigRole::Client,
            fs::read(fixture("client-invalid-unknown-field.toml")).expect("unknown fixture"),
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        ),
        (
            "oversized",
            ConfigRole::Client,
            oversized,
            ConfigErrorKind::TooLarge,
            ConfigField::Config,
        ),
        (
            "malformed",
            ConfigRole::Client,
            format!("schema_version = [\n# {SOURCE_SENTINEL}").into_bytes(),
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        ),
        (
            "wrong declared version",
            ConfigRole::Client,
            CLIENT_BASE
                .replacen("schema_version = 1", "schema_version = 2", 1)
                .into_bytes(),
            ConfigErrorKind::Semantic,
            ConfigField::SchemaVersion,
        ),
        (
            "zero-port endpoint",
            ConfigRole::Client,
            CLIENT_BASE
                .replacen("127.0.0.1:1080", "127.0.0.1:0", 1)
                .into_bytes(),
            ConfigErrorKind::Semantic,
            ConfigField::ClientListen,
        ),
        (
            "invalid range",
            ConfigRole::Client,
            format!("{CLIENT_BASE}\n[runtime]\nmax_connections = 0\n").into_bytes(),
            ConfigErrorKind::Semantic,
            ConfigField::RuntimeMaxConnections,
        ),
        (
            "noncanonical psk",
            ConfigRole::Client,
            CLIENT_BASE
                .replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoLDA0ODx==", 1)
                .into_bytes(),
            ConfigErrorKind::Semantic,
            ConfigField::ShadowsocksPsk,
        ),
        (
            "client wrong-length psk fixture",
            ConfigRole::Client,
            fs::read(fixture("client-invalid-key-length.toml")).expect("client key fixture"),
            ConfigErrorKind::Semantic,
            ConfigField::ShadowsocksPsk,
        ),
        (
            "server wrong-length psk fixture",
            ConfigRole::Server,
            fs::read(fixture("server-invalid-key-length.toml")).expect("server key fixture"),
            ConfigErrorKind::Semantic,
            ConfigField::ShadowsocksPsk,
        ),
    ];

    for (name, role, source, expected_kind, expected_field) in cases {
        let file = TempConfig::bytes(&source);
        let error = match role {
            ConfigRole::Client => load_client(file.path()).err(),
            ConfigRole::Server => load_server(file.path()).err(),
        }
        .expect(name);
        assert_eq!(error.kind(), expected_kind, "{name}");
        assert_eq!(error.field(), expected_field, "{name}");
        assert_eq!(error.code(), expected_kind.code(), "{name}");
        assert_eq!(fs::read(file.path()).expect(name), source, "{name}");
        let rendered = format!("{error}\n{error:?}");
        assert!(!rendered.contains(SOURCE_SENTINEL), "{name}");
        let source_text = String::from_utf8_lossy(&source);
        if let Some(secret) = source_text.lines().find_map(|line| {
            line.strip_prefix("psk = \"")
                .and_then(|value| value.strip_suffix('"'))
        }) {
            assert!(!rendered.contains(secret), "{name}");
        }
    }

    let missing = fixture("does-not-exist.toml");
    let io_error = load_client(missing).err().expect("I/O failure");
    assert_eq!(io_error.kind(), ConfigErrorKind::Io);
    assert!(Error::source(&io_error).is_none());
}
