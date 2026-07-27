use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferrum2_config::{
    ConfigErrorKind, ConfigField, LoggingLevel, MAX_CONFIG_BYTES, load_client, load_server,
};
use ferrum2_crypto::TcpMethod;

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

#[test]
fn role_specific_valid_configs_apply_all_defaults() {
    let client = load_client(fixture("client-valid.toml")).expect("valid client fixture");
    assert_eq!(client.listen, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080));
    assert_eq!(client.server, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388));
    assert_eq!(client.method, TcpMethod::Blake3Aes128Gcm2022);
    assert_eq!(format!("{:?}", client.psk), "Aes128Psk([REDACTED])");
    assert_eq!(
        client.runtime.max_connections,
        NonZeroU16::new(4096).expect("non-zero")
    );
    assert_eq!(
        client.runtime.listen_backlog,
        NonZeroU16::new(1024).expect("non-zero")
    );
    assert_eq!(
        client.runtime.handshake_timeout,
        Duration::from_millis(5_000)
    );
    assert_eq!(
        client.runtime.connect_timeout,
        Duration::from_millis(10_000)
    );
    assert_eq!(client.runtime.idle_timeout, Duration::from_millis(300_000));
    assert_eq!(client.runtime.shutdown_grace, Duration::from_millis(30_000));
    assert_eq!(client.logging.level, LoggingLevel::Info);
    assert!(client.metrics.is_none());

    let server = load_server(fixture("server-valid.toml")).expect("valid server fixture");
    assert_eq!(server.listen, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388));
    assert_eq!(server.method, TcpMethod::Blake3Aes128Gcm2022);
    assert_eq!(server.replay.capacity, 65_536);
    assert_eq!(server.logging.level, LoggingLevel::Info);
    assert!(server.metrics.is_none());
}

#[test]
fn explicit_boundary_values_are_accepted_and_typed() {
    let client = TempConfig::text(&format!(
        "{CLIENT_BASE}\n[runtime]\n\
         max_connections = 1\nlisten_backlog = 1\n\
         handshake_timeout_ms = 100\nconnect_timeout_ms = 100\n\
         idle_timeout_ms = 1000\nshutdown_grace_ms = 0\n\
         [logging]\nlevel = \"error\"\n\
         [metrics]\nlisten = \"127.0.0.1:9090\"\n"
    ));
    let validated = load_client(client.path()).expect("minimum boundaries");
    assert_eq!(validated.runtime.max_connections.get(), 1);
    assert_eq!(validated.runtime.listen_backlog.get(), 1);
    assert_eq!(
        validated.runtime.handshake_timeout,
        Duration::from_millis(100)
    );
    assert_eq!(
        validated.runtime.connect_timeout,
        Duration::from_millis(100)
    );
    assert_eq!(validated.runtime.idle_timeout, Duration::from_millis(1_000));
    assert_eq!(validated.runtime.shutdown_grace, Duration::ZERO);
    assert_eq!(validated.logging.level, LoggingLevel::Error);
    assert_eq!(
        validated.metrics.expect("enabled").listen,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090)
    );

    let server = TempConfig::text(&format!(
        "{SERVER_BASE}\n[runtime]\n\
         max_connections = 65535\nlisten_backlog = 65535\n\
         handshake_timeout_ms = 60000\nconnect_timeout_ms = 120000\n\
         idle_timeout_ms = 86400000\nshutdown_grace_ms = 300000\n\
         [replay]\ncapacity = 1048576\n\
         [logging]\nlevel = \"trace\"\n"
    ));
    let validated = load_server(server.path()).expect("maximum boundaries");
    assert_eq!(validated.runtime.max_connections.get(), 65_535);
    assert_eq!(validated.runtime.listen_backlog.get(), 65_535);
    assert_eq!(validated.replay.capacity, 1_048_576);
    assert_eq!(validated.logging.level, LoggingLevel::Trace);
}

#[test]
fn missing_unknown_and_wrong_role_fields_are_rejected() {
    let client_cases = [
        ("missing schema", CLIENT_BASE.replacen("schema_version = 1\n", "", 1)),
        (
            "missing client",
            CLIENT_BASE.replace(
                "[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n",
                "",
            ),
        ),
        (
            "missing client listen",
            CLIENT_BASE.replacen("listen = \"127.0.0.1:1080\"\n", "", 1),
        ),
        (
            "missing client server",
            CLIENT_BASE.replacen("server = \"127.0.0.1:8388\"\n", "", 1),
        ),
        (
            "missing shadowsocks",
            CLIENT_BASE.replace(
                "[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
                "",
            ),
        ),
        (
            "missing method",
            CLIENT_BASE.replacen("method = \"2022-blake3-aes-128-gcm\"\n", "", 1),
        ),
        (
            "missing psk",
            CLIENT_BASE.replacen("psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n", "", 1),
        ),
        (
            "unknown root",
            CLIENT_BASE.replacen(
                "schema_version = 1\n",
                "schema_version = 1\nunexpected = 1\n",
                1,
            ),
        ),
        (
            "unknown client",
            CLIENT_BASE.replacen(
                "server = \"127.0.0.1:8388\"\n",
                "server = \"127.0.0.1:8388\"\nunexpected = 1\n",
                1,
            ),
        ),
        (
            "unknown shadowsocks",
            CLIENT_BASE.replacen(
                "psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
                "psk = \"AAECAwQFBgcICQoLDA0ODw==\"\nunexpected = 1\n",
                1,
            ),
        ),
        (
            "unknown runtime",
            format!("{CLIENT_BASE}\n[runtime]\nunexpected = 1\n"),
        ),
        (
            "unknown logging",
            format!("{CLIENT_BASE}\n[logging]\nunexpected = 1\n"),
        ),
        (
            "unknown metrics",
            format!(
                "{CLIENT_BASE}\n[metrics]\nlisten = \"127.0.0.1:9090\"\nunexpected = 1\n"
            ),
        ),
        (
            "server role in client",
            format!("{CLIENT_BASE}\n[server]\nlisten = \"127.0.0.1:9000\"\n"),
        ),
        (
            "replay role in client",
            format!("{CLIENT_BASE}\n[replay]\ncapacity = 65536\n"),
        ),
    ];
    for (name, source) in client_cases {
        let file = TempConfig::text(&source);
        let error = load_client(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Syntax, "{name}");
    }

    let server_cases = [
        (
            "missing server listen",
            SERVER_BASE.replacen("listen = \"127.0.0.1:8388\"\n", "", 1),
        ),
        (
            "unknown server",
            SERVER_BASE.replacen(
                "listen = \"127.0.0.1:8388\"\n",
                "listen = \"127.0.0.1:8388\"\nunexpected = 1\n",
                1,
            ),
        ),
        (
            "client role in server",
            format!(
                "{SERVER_BASE}\n[client]\nlisten = \"127.0.0.1:1080\"\nserver = \"127.0.0.1:8388\"\n"
            ),
        ),
        (
            "unknown replay",
            format!("{SERVER_BASE}\n[replay]\nunexpected = 1\n"),
        ),
    ];
    for (name, source) in server_cases {
        let file = TempConfig::text(&source);
        let error = load_server(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Syntax, "{name}");
    }
}

#[test]
fn every_numeric_range_rejects_values_immediately_outside_it() {
    let runtime_cases = [
        ("max_connections", 0_u64),
        ("max_connections", 65_536),
        ("listen_backlog", 0),
        ("listen_backlog", 65_536),
        ("handshake_timeout_ms", 99),
        ("handshake_timeout_ms", 60_001),
        ("connect_timeout_ms", 99),
        ("connect_timeout_ms", 120_001),
        ("idle_timeout_ms", 999),
        ("idle_timeout_ms", 86_400_001),
        ("shutdown_grace_ms", 300_001),
    ];
    for (field, value) in runtime_cases {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[runtime]\n{field} = {value}\n"));
        let error = load_client(file.path()).err().expect(field);
        assert_eq!(error.kind(), ConfigErrorKind::Semantic, "{field}={value}");
    }

    for capacity in [1_023, 1_048_577] {
        let file = TempConfig::text(&format!("{SERVER_BASE}\n[replay]\ncapacity = {capacity}\n"));
        let error = load_server(file.path()).err().expect("replay range");
        assert_eq!(error.field(), ConfigField::ReplayCapacity);
    }
}

#[test]
fn endpoint_method_key_and_cross_field_rules_are_enforced() {
    let cases = [
        (
            "schema version",
            CLIENT_BASE.replacen("schema_version = 1", "schema_version = 2", 1),
            ConfigField::SchemaVersion,
        ),
        (
            "hostname",
            CLIENT_BASE.replacen("127.0.0.1:1080", "localhost:1080", 1),
            ConfigField::ClientListen,
        ),
        (
            "ipv6",
            CLIENT_BASE.replacen("127.0.0.1:1080", "[::1]:1080", 1),
            ConfigField::ClientListen,
        ),
        (
            "zero port",
            CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:0", 1),
            ConfigField::ClientListen,
        ),
        (
            "client endpoints equal",
            CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:8388", 1),
            ConfigField::ClientServer,
        ),
        (
            "method",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", 1),
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
        (
            "wrong key length",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoLDA0O", 1),
            ConfigField::ShadowsocksPsk,
        ),
        (
            "non-canonical trailing bits",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoLDA0ODx==", 1),
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

    let replay_minimum = TempConfig::text(&format!("{SERVER_BASE}\n[replay]\ncapacity = 1024\n"));
    assert_eq!(
        load_server(replay_minimum.path())
            .expect("replay lower boundary")
            .replay
            .capacity,
        1024
    );

    let malformed = TempConfig::text("schema_version = [\nM0_SOURCE_SENTINEL");
    assert_eq!(
        load_client(malformed.path())
            .err()
            .expect("malformed TOML")
            .kind(),
        ConfigErrorKind::Syntax
    );
}

#[test]
fn bounded_utf8_reader_accepts_exact_limit_and_rejects_one_byte_more() {
    let prefix = format!("{CLIENT_BASE}\n#");
    let mut exact = prefix.into_bytes();
    exact.resize(MAX_CONFIG_BYTES - 1, b'a');
    exact.push(b'\n');
    assert_eq!(exact.len(), MAX_CONFIG_BYTES);
    let file = TempConfig::bytes(&exact);
    load_client(file.path()).expect("exactly one MiB is accepted");

    exact.push(b'\n');
    let file = TempConfig::bytes(&exact);
    assert_eq!(
        load_client(file.path())
            .err()
            .expect("one byte too large")
            .kind(),
        ConfigErrorKind::TooLarge
    );

    let file = TempConfig::bytes(&[0xff, 0xfe, 0xfd]);
    assert_eq!(
        load_client(file.path())
            .err()
            .expect("invalid UTF-8")
            .kind(),
        ConfigErrorKind::Syntax
    );
}

#[test]
fn errors_never_retain_or_render_secret_or_source_text() {
    const SECRET: &str = "M0_CONFIG_SECRET_SENTINEL";
    const SOURCE: &str = "M0_RAW_CONFIG_SOURCE_SENTINEL";
    let file = TempConfig::text(&format!(
        "{CLIENT_BASE}\n[logging]\nlevel = \"{SOURCE}\"\n# {SECRET}\n"
    ));
    let error = load_client(file.path()).err().expect("invalid config");
    let rendered = format!("{error}\n{error:?}");
    assert!(!rendered.contains(SECRET));
    assert!(!rendered.contains(SOURCE));
    assert!(!rendered.contains("AAECAwQFBgcICQoLDA0ODw=="));
    assert!(rendered.contains("config.semantic"));

    let missing = fixture("does-not-exist.toml");
    let io_error = load_client(missing).err().expect("I/O failure");
    assert_eq!(io_error.kind(), ConfigErrorKind::Io);
    assert!(Error::source(&io_error).is_none());
}
