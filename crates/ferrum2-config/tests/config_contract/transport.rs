use super::support::*;

#[test]
fn network_generation_mode_defaults_dynamic_and_static_is_explicitly_non_tun() {
    let client_default = validated_client(TempConfig::text(CLIENT_BASE).path()).unwrap();
    let server_default = validated_server(TempConfig::text(SERVER_BASE).path()).unwrap();
    assert_eq!(
        client_default.runtime.network_generation,
        NetworkGenerationMode::Dynamic
    );
    assert_eq!(
        server_default.runtime.network_generation,
        NetworkGenerationMode::Dynamic
    );

    let client_static = validated_client(
        TempConfig::text(&format!(
            "{CLIENT_BASE}\n[runtime]\nnetwork_generation = \"static\"\n"
        ))
        .path(),
    )
    .unwrap();
    let server_static = validated_server(
        TempConfig::text(&format!(
            "{SERVER_BASE}\n[runtime]\nnetwork_generation = \"static\"\n"
        ))
        .path(),
    )
    .unwrap();
    assert_eq!(
        client_static.runtime.network_generation,
        NetworkGenerationMode::Static
    );
    assert_eq!(
        server_static.runtime.network_generation,
        NetworkGenerationMode::Static
    );

    let invalid = validated_client(
        TempConfig::text(&format!(
            "{CLIENT_BASE}\n[runtime]\nnetwork_generation = \"adaptive\"\n"
        ))
        .path(),
    )
    .err()
    .expect("unknown network generation mode");
    assert_eq!(invalid.kind(), ConfigErrorKind::Semantic);
    assert_eq!(invalid.field(), ConfigField::RuntimeNetworkGeneration);

    let tun = "[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\nipv4_address = \"198.18.0.2/30\"\noutbound = \"proxy\"";
    let static_tun = format!(
        "{}\n[runtime]\nnetwork_generation = \"static\"\n",
        tun_client(tun)
    );
    let error = validated_client(TempConfig::text(&static_tun).path())
        .err()
        .expect("static generation mode rejects TUN");
    assert_eq!(error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(error.field(), ConfigField::RuntimeNetworkGeneration);
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
        let udp = validated_client(file.path()).expect(name).udp.expect(name);
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
        let error = validated_client(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Semantic, "{name}");
        assert_eq!(error.field(), expected, "{name}");
    }
}

#[test]
fn udp_receive_workers_are_bounded_server_only_and_default_to_one() {
    let client =
        validated_client(TempConfig::text(&format!("{CLIENT_BASE}\n[udp]\n")).path()).unwrap();
    let server = validated_server(TempConfig::text(SERVER_BASE).path()).unwrap();
    assert_eq!(client.udp.expect("client UDP").receive_workers, 1);
    assert_eq!(server.udp.receive_workers, 1);

    let server_workers = validated_server(
        TempConfig::text(&format!(
            "{SERVER_BASE}\n[udp]\nreceive_workers = {}\n",
            MAX_UDP_RECEIVE_WORKERS
        ))
        .path(),
    )
    .unwrap();
    assert_eq!(server_workers.udp.receive_workers, MAX_UDP_RECEIVE_WORKERS);

    for value in [0, MAX_UDP_RECEIVE_WORKERS + 1] {
        let error = validated_server(
            TempConfig::text(&format!(
                "{SERVER_BASE}\n[udp]\nreceive_workers = {value}\n"
            ))
            .path(),
        )
        .err()
        .expect("out-of-range worker count");
        assert_eq!(error.kind(), ConfigErrorKind::Semantic);
        assert_eq!(error.field(), ConfigField::UdpReceiveWorkers);
    }

    let client_error = validated_client(
        TempConfig::text(&format!("{CLIENT_BASE}\n[udp]\nreceive_workers = 2\n")).path(),
    )
    .err()
    .expect("client cannot configure server receive workers");
    assert_eq!(client_error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(client_error.field(), ConfigField::UdpReceiveWorkers);
}

#[test]
fn endpoint_method_key_and_cross_field_rules_are_enforced() {
    let cases = [
        (
            "client endpoints equal",
            CLIENT_BASE.replacen("127.0.0.1:1080", "127.0.0.1:8388", 1),
            ConfigField::OutboundsServer,
        ),
        (
            "unknown method",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "future-method", 1),
            ConfigField::OutboundsMethod,
        ),
        (
            "reduced-round method",
            CLIENT_BASE.replacen("2022-blake3-aes-128-gcm", "2022-blake3-chacha8-poly1305", 1),
            ConfigField::OutboundsMethod,
        ),
        (
            "unpadded base64",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoLDA0ODw", 1),
            ConfigField::OutboundsPsk,
        ),
        (
            "whitespace base64",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoL DA0ODw==", 1),
            ConfigField::OutboundsPsk,
        ),
        (
            "url safe base64",
            CLIENT_BASE.replacen("AAECAwQFBgcICQoLDA0ODw==", "_____________________w==", 1),
            ConfigField::OutboundsPsk,
        ),
    ];
    for (name, source, expected_field) in cases {
        let file = TempConfig::text(&source);
        let error = validated_client(file.path()).err().expect(name);
        assert_eq!(error.kind(), ConfigErrorKind::Semantic, "{name}");
        assert_eq!(error.field(), expected_field, "{name}");
    }

    for level in ["fatal", "INFO", "client=debug"] {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[logging]\nlevel = \"{level}\"\n"));
        let actual = validated_client(file.path())
            .err()
            .expect("logging level")
            .field();
        assert_eq!(actual, ConfigField::LoggingLevel);
    }
    for level in ["error", "warn", "info", "debug", "trace"] {
        let file = TempConfig::text(&format!("{CLIENT_BASE}\n[logging]\nlevel = \"{level}\"\n"));
        validated_client(file.path()).expect("approved logging level");
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
        let error = validated_client(file.path()).err().expect(name);
        assert_eq!(error.field(), ConfigField::MetricsListen, "{name}");
    }

    let missing_metrics_listen = TempConfig::text(&format!("{CLIENT_BASE}\n[metrics]\n"));
    let actual = validated_client(missing_metrics_listen.path())
        .err()
        .expect("metrics listen required")
        .kind();
    assert_eq!(actual, ConfigErrorKind::Syntax);

    let server_metrics_collision = TempConfig::text(&format!(
        "{SERVER_BASE}\n[metrics]\nlisten = \"127.0.0.1:8388\"\n"
    ));
    let actual = validated_server(server_metrics_collision.path())
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
                    "[[inbounds]]\ntag = \"proxy\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy-out\"\n",
                    "",
                )
                .into_bytes(),
            ConfigErrorKind::Semantic,
            ConfigField::Inbounds,
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
                .replacen("schema_version = 2", "schema_version = 3", 1)
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
            ConfigField::InboundsListen,
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
            ConfigField::OutboundsPsk,
        ),
        (
            "client wrong-length psk fixture",
            ConfigRole::Client,
            fs::read(fixture("client-invalid-key-length.toml")).expect("client key fixture"),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsPsk,
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
            ConfigRole::Client => validated_client(file.path()).err(),
            ConfigRole::Server => validated_server(file.path()).err(),
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
    let io_error = validated_client(missing).err().expect("I/O failure");
    assert_eq!(io_error.kind(), ConfigErrorKind::Io);
    assert!(Error::source(&io_error).is_none());
}
