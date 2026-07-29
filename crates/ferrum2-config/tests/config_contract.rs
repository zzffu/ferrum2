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

const CLIENT_BASE: &str = r#"schema_version = 1
[client]
listen = "127.0.0.1:1080"
server = "127.0.0.1:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;

const SERVER_BASE: &str = r#"schema_version = 1
[server]
listen = "127.0.0.1:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;

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
    assert_eq!(
        u64::from(actual.max_connections.get()),
        expected[0],
        "{name}"
    );
    assert_eq!(
        u64::from(actual.listen_backlog.get()),
        expected[1],
        "{name}"
    );
    assert_eq!(
        actual.handshake_timeout,
        Duration::from_millis(expected[2]),
        "{name}"
    );
    assert_eq!(
        actual.connect_timeout,
        Duration::from_millis(expected[3]),
        "{name}"
    );
    assert_eq!(
        actual.idle_timeout,
        Duration::from_millis(expected[4]),
        "{name}"
    );
    assert_eq!(
        actual.shutdown_grace,
        Duration::from_millis(expected[5]),
        "{name}"
    );
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
                assert_eq!(
                    config.listen,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1_080),
                    "{}",
                    case.name
                );
                assert_eq!(
                    config.server,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_388),
                    "{}",
                    case.name
                );
                assert_eq!(config.method(), case.method, "{}", case.name);
                assert_eq!(format!("{:?}", config.psk), "MethodPsk([REDACTED])");
                assert_runtime(config.runtime, case.runtime, case.name);
                assert_eq!(config.logging.level, case.logging, "{}", case.name);
                assert_eq!(
                    config.metrics.map(|metrics| metrics.listen.port()),
                    case.metrics_port,
                    "{}",
                    case.name
                );
                assert!(case.replay_capacity.is_none());
                assert!(case.udp.is_none());
            }
            ConfigRole::Server => {
                let config = load_server(&path).expect(case.name);
                assert_eq!(
                    config.listen,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_388),
                    "{}",
                    case.name
                );
                assert_eq!(config.method(), case.method, "{}", case.name);
                assert_eq!(format!("{:?}", config.psk), "MethodPsk([REDACTED])");
                assert_runtime(config.runtime, case.runtime, case.name);
                assert_eq!(
                    Some(config.replay.capacity),
                    case.replay_capacity,
                    "{}",
                    case.name
                );
                let expected_udp = case.udp.expect("server UDP expectation");
                assert_eq!(
                    (
                        config.udp.enabled,
                        config.udp.max_sessions,
                        config.udp.max_buffered_bytes,
                        config.udp.idle_timeout.as_millis() as u64,
                    ),
                    expected_udp,
                    "{}",
                    case.name
                );
                assert_eq!(config.logging.level, case.logging, "{}", case.name);
                assert_eq!(
                    config.metrics.map(|metrics| metrics.listen.port()),
                    case.metrics_port,
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

    let policy = SCHEMA_V1_COMPATIBILITY_POLICY;
    assert!(policy.all_v0_releases);
    assert_eq!(policy.successor_minimum_months, 12);
    assert_eq!(policy.successor_minimum_stable_minors, 2);
    assert!(policy.prior_stable_release_notice);
    assert!(!policy.elapsed_time_proven_at_m3_close);

    let mut exact_limit = format!("{CLIENT_BASE}\n#").into_bytes();
    exact_limit.resize(MAX_CONFIG_BYTES - 1, b'a');
    exact_limit.push(b'\n');
    let file = TempConfig::bytes(&exact_limit);
    load_client(file.path()).expect("the documented maximum size remains accepted");
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
        assert_eq!(
            load_client(file.path())
                .err()
                .expect("logging level")
                .field(),
            ConfigField::LoggingLevel
        );
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
    assert_eq!(
        load_client(missing_metrics_listen.path())
            .err()
            .expect("metrics listen required")
            .kind(),
        ConfigErrorKind::Syntax
    );

    let server_metrics_collision = TempConfig::text(&format!(
        "{SERVER_BASE}\n[metrics]\nlisten = \"127.0.0.1:8388\"\n"
    ));
    assert_eq!(
        load_server(server_metrics_collision.path())
            .err()
            .expect("server metrics collision")
            .field(),
        ConfigField::MetricsListen
    );
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
