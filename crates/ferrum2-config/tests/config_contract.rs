use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferrum2_config::{
    ConfigErrorKind, ConfigField, DnsTransport, LoggingLevel, MAX_CONFIG_BYTES, RuntimeConfig,
    load_client, load_server,
};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{Network, RouteTable};
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/config")
        .join(name)
}

fn selected(route: &RouteTable, inbound: usize) -> usize {
    route.select(
        inbound,
        Network::Tcp,
        &TargetAddr::domain("selection.test", 443).expect("test target"),
    )
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

fn routed(source: String, route: &str) -> String {
    source
        .lines()
        .filter(|line| !line.starts_with("outbound = "))
        .collect::<Vec<_>>()
        .join("\n")
        .replacen("[shadowsocks]", &format!("{route}\n[shadowsocks]"), 1)
        + "\n"
}

fn with_selectors(source: String, selectors: &str) -> String {
    source.replacen("[shadowsocks]", &format!("{selectors}\n[shadowsocks]"), 1)
}

fn with_dns(source: String, dns: &str) -> String {
    source.replacen("[shadowsocks]", &format!("{dns}\n[shadowsocks]"), 1)
}

fn assert_tagged_error(
    name: &str,
    role: ConfigRole,
    mut source: String,
    expected: (ConfigErrorKind, ConfigField),
    index: usize,
) {
    let raw = format!("raw_sentinel_{index}");
    let target_host = format!("route_target_sentinel_{index}.test");
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
    let target_host = source.contains("host = \"example.test\"").then(|| {
        source = source.replace(
            "host = \"example.test\"",
            &format!("host = \"{target_host}\""),
        );
        target_host
    });
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let psk = format!(
        "{}AECAwQFBgcICQoLDA0ODw==",
        char::from(alphabet[index % alphabet.len()])
    );
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
    let values = source
        .lines()
        .flat_map(|line| line.split('"').skip(1).step_by(2))
        .filter(|value| value.len() >= 2);
    for sentinel in std::iter::once(raw.as_str())
        .chain(target_host.as_deref())
        .chain(values)
    {
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
                assert!(config.dns.is_none(), "{}", case.name);
                assert_eq!(config.inbounds.len(), 1, "{}", case.name);
                assert_eq!(config.outbounds.len(), 1, "{}", case.name);
                assert_eq!(config.inbounds[0].listen, config.listen, "{}", case.name);
                assert_eq!(
                    config.outbounds[selected(&config.route, 0)].server,
                    config.server
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
                assert!(config.dns.is_none(), "{}", case.name);
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
        assert_eq!(selected(&config.route, 1), 1, "{method}");
        let source = tagged_server(2, 2)
            .replacen("2022-blake3-aes-128-gcm", method, 1)
            .replacen("AAECAwQFBgcICQoLDA0ODw==", psk, 1);
        let config = load_server(TempConfig::text(&source).path()).expect(method);
        assert_eq!(selected(&config.route, 1), 1, "{method}");
    }

    let shared = tagged_client(2, 1);
    let config = load_client(TempConfig::text(&shared).path()).expect("shared outbound");
    assert_eq!(selected(&config.route, 0), selected(&config.route, 1));
    let exact_case = tagged_client(1, 1)
        .replacen("outbound = \"o0\"", "outbound = \"O0\"", 1)
        .replacen("tag = \"o0\"", "tag = \"O0\"", 1);
    load_client(TempConfig::text(&exact_case).path()).expect("exact case-sensitive match");
    let shared_server =
        load_server(TempConfig::text(&tagged_server(2, 1)).path()).expect("shared direct");
    assert_eq!(selected(&shared_server.route, 0), 0);
    assert_eq!(selected(&shared_server.route, 1), 0);

    let client = load_client(TempConfig::text(&tagged_client(64, 64)).path()).expect("64 client");
    assert_eq!((client.inbounds.len(), client.outbounds.len()), (64, 64));
    let server = load_server(TempConfig::text(&tagged_server(64, 64)).path()).expect("64 server");
    assert_eq!((server.inbounds.len(), server.outbounds.len()), (64, 64));
    assert_eq!(selected(&server.route, 63), 63);
}

#[test]
fn client_credentials_and_fixed_plans_compile_in_order_with_redacted_secret_owners() {
    #[rustfmt::skip]
    let source = tagged_client(1, 3)
        .replacen("outbound = \"o0\"", "outbound = \"three-hop\"", 1)
        .replacen("server = \"127.0.0.1:20001\"", "server = \"127.0.0.1:20001\"\nmethod = \"2022-blake3-aes-256-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"", 1)
        .replacen("server = \"127.0.0.1:20002\"", "server = \"127.0.0.1:20002\"\nmethod = \"2022-blake3-chacha20-poly1305\"\npsk = \"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\"", 1)
        .replacen("[shadowsocks]", "[[chains]]\ntag = \"three-hop\"\nhops = [\"o0\", \"o1\", \"o2\"]\n[shadowsocks]", 1);
    let config = load_client(TempConfig::text(&source).path()).expect("mixed credentials");
    #[rustfmt::skip]
    assert_eq!(config.outbound_psks.iter().map(MethodPsk::profile).collect::<Vec<_>>(), [TcpMethodProfile::Blake3Aes128Gcm2022, TcpMethodProfile::Blake3Aes256Gcm2022, TcpMethodProfile::Blake3ChaCha20Poly13052022]);
    let target = TargetAddr::domain("chain.test", 443).expect("target");
    #[rustfmt::skip]
    assert_eq!((config.route.select_plan(0, Network::Tcp, &target).hops(), config.route.final_plan().hops(), config.server), (&[0, 1, 2][..], &[0, 1, 2][..], SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_000)));
    assert!(
        config
            .outbound_psks
            .iter()
            .all(|psk| format!("{psk:?}") == "MethodPsk([REDACTED])")
    );
}

#[test]
fn chain_bounds_and_static_rule_final_selector_actions_are_complete() {
    #[rustfmt::skip]
    let routed_source = routed(
        tagged_client(1, 3), "[route]\nfinal = \"b-c\"\n[[route.rules]]\ninbound = \"i0\"\nnetwork = \"tcp\"\noutbound = \"a-b\"",
    ).replacen("[shadowsocks]", "[[chains]]\ntag = \"a-b\"\nhops = [\"o0\", \"o1\"]\n[[chains]]\ntag = \"b-c\"\nhops = [\"o1\", \"o2\"]\n[shadowsocks]", 1);
    let routed =
        load_client(TempConfig::text(&routed_source).path()).expect("rule and final plans");
    let target = TargetAddr::domain("chain-actions.test", 443).expect("target");
    #[rustfmt::skip]
    assert_eq!((routed.route.select_plan(0, Network::Tcp, &target).hops(), routed.route.select_plan(0, Network::Udp, &target).hops()), (&[0, 1][..], &[1, 2][..]));

    let hops = (0..8)
        .map(|index| format!("\"o{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    #[rustfmt::skip]
    let eight = tagged_client(1, 8).replacen("outbound = \"o0\"", "outbound = \"eight\"", 1).replacen("[shadowsocks]", &format!("[[chains]]\ntag = \"eight\"\nhops = [{hops}]\n[shadowsocks]"), 1);
    let eight = load_client(TempConfig::text(&eight).path()).expect("eight hops");
    assert_eq!(eight.route.final_plan().hops(), &(0..8).collect::<Vec<_>>());

    let tags = (0..64)
        .map(|index| format!("\"c{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let chains = (0..64)
        .map(|index| format!("[[chains]]\ntag = \"c{index}\"\nhops = [\"o0\", \"o1\"]\n"))
        .collect::<String>();
    #[rustfmt::skip]
    let sixty_four = tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"manual\"", 1).replacen("[shadowsocks]", &format!("{chains}[[selectors]]\ntag = \"manual\"\noutbounds = [{tags}]\ndefault = \"c0\"\n[shadowsocks]"), 1);
    let config = load_client(TempConfig::text(&sixty_four).path()).expect("64 reachable chains");
    let snapshot = config.route.final_plan();
    config.selector_control().switch("manual", "c63").unwrap();
    assert_eq!(
        (
            snapshot.hops(),
            config.route.select_plan(0, Network::Tcp, &target).hops()
        ),
        (&[0, 1][..], &[0, 1][..])
    );
}

#[test]
fn selector_graphs_compile_for_both_roles_and_share_live_route_state() {
    let selectors = "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o1\", \"o0\"]\ndefault = \"o0\"\n[[selectors]]\ntag = \"nested\"\noutbounds = [\"manual\"]\ndefault = \"manual\"";
    let static_source = |source: String| {
        with_selectors(
            source
                .replacen("outbound = \"o0\"", "outbound = \"manual\"", 1)
                .replacen("outbound = \"o1\"", "outbound = \"nested\"", 1),
            selectors,
        )
    };
    let client = load_client(TempConfig::text(&static_source(tagged_client(2, 2))).path())
        .expect("client static");
    let snapshot = client.server;
    client.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&client.route, 0), selected(&client.route, 1)),
        (1, 1)
    );
    assert_eq!(client.server, snapshot);
    let server = load_server(TempConfig::text(&static_source(tagged_server(2, 2))).path())
        .expect("server static");
    server.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&server.route, 0), selected(&server.route, 1)),
        (1, 1)
    );

    let route = "[route]\nfinal = \"nested\"\n[[route.rules]]\ninbound = \"i0\"\nnetwork = \"tcp\"\noutbound = \"manual\"";
    let routed_source = |source| with_selectors(routed(source, route), selectors);
    let client = load_client(TempConfig::text(&routed_source(tagged_client(2, 2))).path())
        .expect("client route");
    let configured_default = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_000);
    assert_eq!(client.selector_control().selected("manual"), Ok("o0"));
    #[rustfmt::skip]
    assert_eq!((selected(&client.route, 0), selected(&client.route, 1), client.route.final_outbound()), (0, 0, 0));
    assert_eq!(client.server, configured_default);
    client.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&client.route, 0), selected(&client.route, 1)),
        (1, 1)
    );
    assert_eq!(client.route.final_outbound(), 0);
    assert_eq!(client.server, configured_default);
    let server = load_server(TempConfig::text(&routed_source(tagged_server(2, 2))).path())
        .expect("server route");
    server.selector_control().switch("manual", "o1").unwrap();
    assert_eq!(
        (selected(&server.route, 0), selected(&server.route, 1)),
        (1, 1)
    );
}

#[test]
fn selector_graph_rejects_bounds_members_defaults_cycles_and_inert_nodes_redacted() {
    let base = || tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"manual\"", 1);
    let graph = |selectors: &str| with_selectors(base(), selectors);
    let valid = "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"";
    let selector_65 = (0..65)
        .map(|index| {
            format!("[[selectors]]\ntag = \"s{index}\"\noutbounds = [\"o0\"]\ndefault = \"o0\"\n")
        })
        .collect::<String>();
    let members_65 = (0..65)
        .map(|index| format!("\"m{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let empty = base().replacen(
        "schema_version = 1",
        "schema_version = 1\nselectors = []",
        1,
    );
    let partial = "schema_version = 1\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"manual\"\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\"]\ndefault = \"o0\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned();
    #[rustfmt::skip]
    let cases = [
        ("legacy mixing", with_selectors(CLIENT_BASE.to_owned(), valid), ConfigField::Selectors, ConfigRole::Client),
        ("partial tagged selector", partial, ConfigField::Selectors, ConfigRole::Client),
        ("empty selectors", empty, ConfigField::Selectors, ConfigRole::Client),
        ("65 selectors", graph(&selector_65).replacen("outbound = \"manual\"", "outbound = \"s0\"", 1), ConfigField::Selectors, ConfigRole::Client),
        ("empty members", graph("[[selectors]]\ntag = \"manual\"\noutbounds = []\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("65 members", graph(&format!("[[selectors]]\ntag = \"manual\"\noutbounds = [{members_65}]\ndefault = \"m0\"")), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("invalid selector tag", graph("[[selectors]]\ntag = \"bad/tag\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\""), ConfigField::SelectorsTag, ConfigRole::Client),
        ("duplicate selector tag", graph(&format!("{valid}\n{valid}")), ConfigField::SelectorsTag, ConfigRole::Client),
        ("global selector collision", graph("[[selectors]]\ntag = \"i0\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\""), ConfigField::SelectorsTag, ConfigRole::Client),
        ("duplicate member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o0\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("dangling member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"missing\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("case mismatched member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"O1\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("inbound member", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"i0\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("missing default", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]"), ConfigField::SelectorsDefault, ConfigRole::Client),
        ("dangling default", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"missing\""), ConfigField::SelectorsDefault, ConfigRole::Client),
        ("nonmember default", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\"]\ndefault = \"o1\""), ConfigField::SelectorsDefault, ConfigRole::Client),
        ("unreachable selector", graph(&format!("{valid}\n[[selectors]]\ntag = \"unused\"\noutbounds = [\"o0\"]\ndefault = \"o0\"")), ConfigField::SelectorsTag, ConfigRole::Client),
        ("unreachable concrete", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\"]\ndefault = \"o0\""), ConfigField::OutboundsTag, ConfigRole::Client),
        ("self cycle", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"manual\", \"o0\", \"o1\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("two node cycle", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"other\", \"o0\", \"o1\"]\ndefault = \"o0\"\n[[selectors]]\ntag = \"other\"\noutbounds = [\"manual\"]\ndefault = \"manual\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("latent longer cycle", graph("[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\", \"a\"]\ndefault = \"o0\"\n[[selectors]]\ntag = \"a\"\noutbounds = [\"o0\", \"b\"]\ndefault = \"o0\"\n[[selectors]]\ntag = \"b\"\noutbounds = [\"o0\", \"a\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Client),
        ("server cycle", with_selectors(tagged_server(1, 1).replacen("outbound = \"o0\"", "outbound = \"manual\"", 1), "[[selectors]]\ntag = \"manual\"\noutbounds = [\"manual\", \"o0\"]\ndefault = \"o0\""), ConfigField::SelectorsOutbounds, ConfigRole::Server),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            110 + index,
        );
    }

    #[rustfmt::skip]
    assert_eq!([ConfigField::Selectors, ConfigField::SelectorsTag, ConfigField::SelectorsOutbounds, ConfigField::SelectorsDefault].map(ConfigField::as_str), ["selectors", "selectors.tag", "selectors.outbounds", "selectors.default"]);
}

#[test]
fn outbound_credential_pairs_reject_partial_method_encoding_and_width_redacted() {
    let with_fields = |fields: &str| {
        tagged_client(1, 1).replacen(
            "server = \"127.0.0.1:20000\"",
            &format!("server = \"127.0.0.1:20000\"\n{fields}"),
            1,
        )
    };
    #[rustfmt::skip]
    let cases = [
        ("method only", with_fields("method = \"2022-blake3-aes-128-gcm\""), ConfigField::OutboundsPsk),
        ("psk only", with_fields("psk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsMethod),
        ("unknown method", with_fields("method = \"future-method\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsMethod),
        ("unpadded", with_fields("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw\""), ConfigField::OutboundsPsk),
        ("noncanonical", with_fields("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODx==\""), ConfigField::OutboundsPsk),
        ("aes128 wide", with_fields("method = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\""), ConfigField::OutboundsPsk),
        ("aes256 short", with_fields("method = \"2022-blake3-aes-256-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsPsk),
        ("chacha short", with_fields("method = \"2022-blake3-chacha20-poly1305\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\""), ConfigField::OutboundsPsk),
    ];
    for (index, (name, source, field)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            ConfigRole::Client,
            source,
            (ConfigErrorKind::Semantic, field),
            150 + index,
        );
    }

    assert_tagged_error(
        "server outbound credentials",
        ConfigRole::Server,
        tagged_server(1, 1).replacen(
            "tag = \"o0\"",
            "tag = \"o0\"\nmethod = \"2022-blake3-aes-128-gcm\"",
            1,
        ),
        (ConfigErrorKind::Syntax, ConfigField::Config),
        159,
    );
}

#[test]
fn chains_reject_all_bounds_namespaces_references_and_inert_nodes_redacted() {
    let chain = |tag: &str, hops: &str| {
        tagged_client(1, 2)
            .replacen("outbound = \"o0\"", &format!("outbound = \"{tag}\""), 1)
            .replacen(
                "[shadowsocks]",
                &format!("[[chains]]\ntag = \"{tag}\"\nhops = [{hops}]\n[shadowsocks]"),
                1,
            )
    };
    let many = (0..65)
        .map(|index| format!("[[chains]]\ntag = \"c{index}\"\nhops = [\"o0\", \"o1\"]\n"))
        .collect::<String>();
    let selector_hop = chain("c", "\"manual\", \"o1\"").replacen(
        "[shadowsocks]",
        "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n[shadowsocks]",
        1,
    );
    #[rustfmt::skip]
    let cases = [
        ("empty collection", tagged_client(1, 1).replacen("schema_version = 1", "schema_version = 1\nchains = []", 1), ConfigField::Chains, ConfigRole::Client),
        ("chains missing inbounds", "schema_version = 1\n[[outbounds]]\ntag = \"o0\"\nserver = \"127.0.0.1:20000\"\n[[outbounds]]\ntag = \"o1\"\nserver = \"127.0.0.1:20001\"\n[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Chains, ConfigRole::Client),
        ("chains missing outbounds", "schema_version = 1\n[[inbounds]]\ntag = \"i0\"\nlisten = \"127.0.0.1:10000\"\noutbound = \"c\"\n[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n".to_owned(), ConfigField::Chains, ConfigRole::Client),
        ("65 chains", tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"c0\"", 1).replacen("[shadowsocks]", &format!("{many}[shadowsocks]"), 1), ConfigField::Chains, ConfigRole::Client),
        ("missing tag", tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("[shadowsocks]", "[[chains]]\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::Chains, ConfigRole::Client),
        ("missing hops", tagged_client(1, 2).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\n[shadowsocks]", 1), ConfigField::Chains, ConfigRole::Client),
        ("empty hops", chain("c", ""), ConfigField::ChainsHops, ConfigRole::Client),
        ("one hop", chain("c", "\"o0\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("nine hops", tagged_client(1, 9).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\", \"o2\", \"o3\", \"o4\", \"o5\", \"o6\", \"o7\", \"o8\"]\n[shadowsocks]", 1), ConfigField::ChainsHops, ConfigRole::Client),
        ("duplicate hop", chain("c", "\"o0\", \"o0\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("unknown hop", chain("c", "\"o0\", \"missing\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("case hop", chain("c", "\"o0\", \"O1\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("inbound hop", chain("c", "\"o0\", \"i0\""), ConfigField::ChainsHops, ConfigRole::Client),
        ("selector hop", selector_hop, ConfigField::ChainsHops, ConfigRole::Client),
        ("chain hop", chain("c0", "\"o0\", \"o1\"").replacen("[shadowsocks]", "[[chains]]\ntag = \"c1\"\nhops = [\"c0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::ChainsHops, ConfigRole::Client),
        ("invalid chain tag", chain("bad/tag", "\"o0\", \"o1\""), ConfigField::ChainsTag, ConfigRole::Client),
        ("inbound collision", chain("i0", "\"o0\", \"o1\""), ConfigField::ChainsTag, ConfigRole::Client),
        ("outbound collision", chain("o1", "\"o0\", \"o1\""), ConfigField::ChainsTag, ConfigRole::Client),
        ("duplicate chain", chain("c", "\"o0\", \"o1\"").replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::ChainsTag, ConfigRole::Client),
        ("selector collision", chain("manual", "\"o0\", \"o1\"").replacen("[shadowsocks]", "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n[shadowsocks]", 1), ConfigField::ChainsTag, ConfigRole::Client),
        ("unreachable chain", tagged_client(1, 2).replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::ChainsTag, ConfigRole::Client),
        ("unreachable concrete", tagged_client(1, 3).replacen("outbound = \"o0\"", "outbound = \"c\"", 1).replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::OutboundsTag, ConfigRole::Client),
        ("legacy chain", CLIENT_BASE.replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::Chains, ConfigRole::Client),
        ("server chain", tagged_server(1, 1).replacen("[shadowsocks]", "[[chains]]\ntag = \"c\"\nhops = [\"o0\", \"o1\"]\n[shadowsocks]", 1), ConfigField::Chains, ConfigRole::Server),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            170 + index,
        );
    }
    assert_eq!(
        [
            ConfigField::Chains,
            ConfigField::ChainsTag,
            ConfigField::ChainsHops
        ]
        .map(ConfigField::as_str),
        ["chains", "chains.tag", "chains.hops"]
    );
}

#[test]
fn routed_graph_compiles_resolved_first_match_tables_for_both_roles() {
    let client = load_client(fixture("client-route-valid.toml")).expect("routed client");
    let domain = TargetAddr::domain("EXAMPLE.TEST", 443).expect("domain");
    let ipv4 = TargetAddr::ip("192.0.2.1:53".parse().expect("IPv4")).expect("target");
    let other_port = TargetAddr::domain("example.test", 80).expect("other port");
    #[rustfmt::skip]
    let client_actual = (client.route.is_routed(), client.route.select(0, Network::Tcp, &domain), client.route.select(1, Network::Tcp, &domain), client.route.select(0, Network::Udp, &ipv4), client.route.select(0, Network::Tcp, &other_port));
    assert_eq!(client_actual, (true, 1, 0, 2, 0));
    let server = load_server(fixture("server-route-valid.toml")).expect("routed server");
    let ipv6 = TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target");
    assert_eq!(
        (
            server.route.is_routed(),
            server.route.select(1, Network::Tcp, &domain),
            server.route.select(0, Network::Udp, &ipv6)
        ),
        (true, 1, 2)
    );
    for count in [0, 64] {
        let rules = "[[route.rules]]\ninbound = \"i0\"\noutbound = \"o0\"\n".repeat(count);
        let source = routed(
            tagged_client(1, 1),
            &format!("[route]\nfinal = \"o0\"\n{rules}"),
        );
        load_client(TempConfig::text(&source).path()).expect("bounded routed rules");
    }
}

#[test]
fn dns_graph_compiles_independent_server_actions_and_detour_plan_roots() {
    let graph = "[[chains]]\ntag = \"two-hop\"\nhops = [\"o1\", \"o2\"]\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"o1\", \"o2\"]\ndefault = \"o1\"";
    let dns = r#"[dns]
timeout_ms = 100
max_inflight = 4096
[[dns.inbounds]]
tag = "local-dns"
listen = "127.0.0.1:5353"
[[dns.servers]]
tag = "plain"
transport = "udp"
address = "[2001:db8::53]:53"
[[dns.servers]]
tag = "tcp-v6"
transport = "tcp"
address = "127.0.0.1:5353"
detour = "o0"
[[dns.servers]]
tag = "tls"
transport = "dot"
address = "192.0.2.54:853"
server_name = "resolver.example"
detour = "two-hop"
[[dns.servers]]
tag = "https"
transport = "doh"
address = "192.0.2.55:443"
server_name = "resolver.example"
path = "/resolve"
detour = "manual"
[dns.route]
final = "https"
[[dns.route.rules]]
inbound = "local-dns"
network = "udp"
target = { host = "plain.example.", port = 53 }
server = "plain"
[[dns.route.rules]]
network = "tcp"
target = { host = "tcp.example.", port = 53 }
server = "tcp-v6"
[[dns.route.rules]]
target = { host = "tls.example.", port = 53 }
server = "tls""#;
    let source =
        with_dns(with_selectors(tagged_client(1, 3), graph), dns) + "\n[udp]\nenabled = false\n";
    let config = load_client(TempConfig::text(&source).path()).expect("client DNS graph");
    let dns = config.dns.as_ref().expect("validated DNS");
    assert_eq!(
        (
            dns.timeout,
            dns.max_inflight.get(),
            dns.inbounds[0].listen,
            dns.servers
                .iter()
                .map(|server| server.transport)
                .collect::<Vec<_>>(),
            dns.servers[3].path.as_deref(),
            config.udp.expect("public UDP setting").enabled,
        ),
        (
            Duration::from_millis(100),
            4096,
            "127.0.0.1:5353".parse().unwrap(),
            vec![
                DnsTransport::Udp,
                DnsTransport::Tcp,
                DnsTransport::Dot,
                DnsTransport::Doh
            ],
            Some("/resolve"),
            false,
        )
    );
    let select_dns = |name: &str, network| {
        dns.route.select(
            0,
            network,
            &TargetAddr::domain(name, 53).expect("DNS target"),
        )
    };
    assert_eq!(
        (
            select_dns("PLAIN.EXAMPLE.", Network::Udp),
            select_dns("tcp.example.", Network::Tcp),
            select_dns("tls.example.", Network::Udp),
            select_dns("other.example.", Network::Udp),
        ),
        (0, 1, 2, 3)
    );
    assert_eq!(
        dns.servers[1].detour.as_ref().unwrap().snapshot().hops(),
        &[0]
    );
    assert_eq!(
        dns.servers[2].detour.as_ref().unwrap().snapshot().hops(),
        &[1, 2]
    );
    assert_eq!(
        dns.servers[3].detour.as_ref().unwrap().snapshot().hops(),
        &[1]
    );
    config.selector_control().switch("manual", "o2").unwrap();
    assert_eq!(
        dns.servers[3].detour.as_ref().unwrap().snapshot().hops(),
        &[2]
    );

    let server_dns = r#"[dns]
[[dns.servers]]
tag = "direct"
transport = "doh"
address = "192.0.2.53:443"
server_name = "resolver.example"
[[dns.servers]]
tag = "detoured"
transport = "udp"
address = "192.0.2.54:53"
detour = "o1"
[dns.route]
final = "direct"
[[dns.route.rules]]
inbound = "i0"
network = "tcp"
server = "detoured""#;
    let server = load_server(TempConfig::text(&with_dns(tagged_server(1, 2), server_dns)).path())
        .expect("server DNS graph");
    let dns = server.dns.expect("server DNS");
    assert_eq!(dns.servers[0].path.as_deref(), Some("/dns-query"));
    assert_eq!(
        dns.servers[1].detour.as_ref().unwrap().snapshot().hops(),
        &[1]
    );
    assert_eq!(
        dns.route.select(
            0,
            Network::Tcp,
            &TargetAddr::domain("application.example", 443).unwrap()
        ),
        1
    );
}

#[test]
fn dns_graph_rejects_each_closed_shape_reference_and_loop_field_redacted() {
    let base_dns = r#"[dns]
[[dns.inbounds]]
tag = "d0"
listen = "127.0.0.1:5353"
[[dns.servers]]
tag = "s0"
transport = "udp"
address = "192.0.2.53:53"
[dns.route]
final = "s0""#;
    let client = || with_dns(CLIENT_BASE.to_owned(), base_dns);
    let two_servers = base_dns.replacen(
        "[dns.route]",
        "[[dns.servers]]\ntag = \"s1\"\ntransport = \"tcp\"\naddress = \"192.0.2.54:53\"\n[dns.route]",
        1,
    );
    let many_inbounds = (0..65)
        .map(|index| {
            format!(
                "[[dns.inbounds]]\ntag = \"d{index}\"\nlisten = \"127.0.0.1:{}\"\n",
                40_000 + index
            )
        })
        .collect::<String>();
    let many_servers = (0..65)
        .map(|index| format!("[[dns.servers]]\ntag = \"s{index}\"\ntransport = \"udp\"\naddress = \"192.0.2.53:{}\"\n", 1_000 + index))
        .collect::<String>();
    let many_rules = "[[dns.route.rules]]\nnetwork = \"tcp\"\nserver = \"s0\"\n".repeat(65);
    let doh_client = |server_name: &str, path: &str| {
        client()
            .replace("transport = \"udp\"", "transport = \"doh\"")
            .replace(
                "address = \"192.0.2.53:53\"",
                &format!(
                    "address = \"192.0.2.53:53\"\nserver_name = \"{server_name}\"\npath = \"{path}\""
                ),
            )
    };
    let tagged_detour = |detour: &str| {
        with_dns(
            tagged_client(1, 1),
            &base_dns.replacen(
                "address = \"192.0.2.53:53\"",
                &format!("address = \"192.0.2.53:53\"\ndetour = \"{detour}\""),
                1,
            ),
        )
    };
    #[rustfmt::skip]
    let cases = [
        ("missing client inbounds", client().replace("[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n", ""), ConfigField::DnsInbounds, ConfigRole::Client),
        ("empty client inbounds", with_dns(CLIENT_BASE.to_owned(), "[dns]\ninbounds = []\n[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"s0\""), ConfigField::DnsInbounds, ConfigRole::Client),
        ("65 client inbounds", with_dns(CLIENT_BASE.to_owned(), &format!("[dns]\n{many_inbounds}[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"s0\"")), ConfigField::DnsInbounds, ConfigRole::Client),
        ("server inbounds", with_dns(SERVER_BASE.to_owned(), base_dns), ConfigField::DnsInbounds, ConfigRole::Server),
        ("missing servers", client().replace("[[dns.servers]]\ntag = \"s0\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n", ""), ConfigField::DnsServers, ConfigRole::Client),
        ("zero servers", with_dns(CLIENT_BASE.to_owned(), "[dns]\nservers = []\n[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n[dns.route]\nfinal = \"s0\""), ConfigField::DnsServers, ConfigRole::Client),
        ("65 servers", with_dns(CLIENT_BASE.to_owned(), &format!("[dns]\n[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n{many_servers}[dns.route]\nfinal = \"s0\"")), ConfigField::DnsServers, ConfigRole::Client),
        ("duplicate DNS inbound", client().replacen("[[dns.servers]]", "[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5354\"\n[[dns.servers]]", 1), ConfigField::DnsInboundsTag, ConfigRole::Client),
        ("timeout low", client().replacen("[dns]", "[dns]\ntimeout_ms = 99", 1), ConfigField::DnsTimeout, ConfigRole::Client),
        ("timeout high", client().replacen("[dns]", "[dns]\ntimeout_ms = 30001", 1), ConfigField::DnsTimeout, ConfigRole::Client),
        ("inflight zero", client().replacen("[dns]", "[dns]\nmax_inflight = 0", 1), ConfigField::DnsMaxInflight, ConfigRole::Client),
        ("inflight high", client().replacen("[dns]", "[dns]\nmax_inflight = 4097", 1), ConfigField::DnsMaxInflight, ConfigRole::Client),
        ("inbound global collision", with_dns(tagged_client(1, 1), &base_dns.replace("tag = \"d0\"", "tag = \"i0\"")), ConfigField::DnsInboundsTag, ConfigRole::Client),
        ("inbound socket collision", client().replace("127.0.0.1:5353", "127.0.0.1:1080"), ConfigField::DnsInboundsListen, ConfigRole::Client),
        ("duplicate server", with_dns(CLIENT_BASE.to_owned(), &two_servers.replace("tag = \"s1\"", "tag = \"s0\"")), ConfigField::DnsServersTag, ConfigRole::Client),
        ("unknown transport", client().replace("transport = \"udp\"", "transport = \"quic\""), ConfigField::DnsServersTransport, ConfigRole::Client),
        ("hostname bootstrap", client().replace("192.0.2.53:53", "resolver.example:53"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("zero bootstrap port", client().replace("192.0.2.53:53", "192.0.2.53:0"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("direct exact loop", client().replace("192.0.2.53:53", "127.0.0.1:5353"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("direct wildcard loop", client().replace("127.0.0.1:5353", "0.0.0.0:5353").replace("192.0.2.53:53", "127.0.0.1:5353"), ConfigField::DnsServersAddress, ConfigRole::Client),
        ("plain TLS name", client().replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\nserver_name = \"resolver.example\""), ConfigField::DnsServersServerName, ConfigRole::Client),
        ("DoT missing TLS name", client().replace("transport = \"udp\"", "transport = \"dot\""), ConfigField::DnsServersServerName, ConfigRole::Client),
        ("DoT path", client().replace("transport = \"udp\"", "transport = \"dot\"").replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\nserver_name = \"resolver.example\"\npath = \"/dns-query\""), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH relative path", client().replace("transport = \"udp\"", "transport = \"doh\"").replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\nserver_name = \"resolver.example\"\npath = \"dns-query\""), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH long path", doh_client("resolver.example", &format!("/{}", "a".repeat(1_024))), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH authority path", doh_client("resolver.example", "//resolver.example/dns-query"), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH query path", doh_client("resolver.example", "/dns-query?name=sentinel"), ConfigField::DnsServersPath, ConfigRole::Client),
        ("DoH fragment path", doh_client("resolver.example", "/dns-query#sentinel"), ConfigField::DnsServersPath, ConfigRole::Client),
        ("malformed TLS identity", doh_client("-invalid.example", "/dns-query"), ConfigField::DnsServersServerName, ConfigRole::Client),
        ("missing route", client().replace("[dns.route]\nfinal = \"s0\"", ""), ConfigField::DnsRoute, ConfigRole::Client),
        ("65 DNS rules", client().replace("final = \"s0\"", &format!("final = \"s0\"\n{many_rules}")), ConfigField::DnsRouteRules, ConfigRole::Client),
        ("unknown final", client().replace("final = \"s0\"", "final = \"missing\""), ConfigField::DnsRouteFinal, ConfigRole::Client),
        ("unreachable server", with_dns(CLIENT_BASE.to_owned(), &two_servers), ConfigField::DnsRouteRulesServer, ConfigRole::Client),
        ("unknown route inbound", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\ninbound = \"missing\"\nserver = \"s0\""), ConfigField::DnsRouteRulesInbound, ConfigRole::Client),
        ("unknown route network", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\nnetwork = \"quic\"\nserver = \"s0\""), ConfigField::DnsRouteRulesNetwork, ConfigRole::Client),
        ("invalid route target", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\ntarget = { host = \"example.test\", port = 0 }\nserver = \"s0\""), ConfigField::DnsRouteRulesTarget, ConfigRole::Client),
        ("unknown rule server", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\nnetwork = \"tcp\"\nserver = \"missing\""), ConfigField::DnsRouteRulesServer, ConfigRole::Client),
        ("DNS outbound action", client().replace("final = \"s0\"", "final = \"s0\"\n[[dns.route.rules]]\nnetwork = \"tcp\"\noutbound = \"s0\""), ConfigField::DnsRouteRulesServer, ConfigRole::Client),
        ("legacy detour", with_dns(CLIENT_BASE.to_owned(), &base_dns.replace("address = \"192.0.2.53:53\"", "address = \"192.0.2.53:53\"\ndetour = \"legacy\"")), ConfigField::DnsServersDetour, ConfigRole::Client),
        ("unknown detour", tagged_detour("missing"), ConfigField::DnsServersDetour, ConfigRole::Client),
        ("inbound detour", tagged_detour("i0"), ConfigField::DnsServersDetour, ConfigRole::Client),
        ("DNS server detour", tagged_detour("s0"), ConfigField::DnsServersDetour, ConfigRole::Client),
    ];
    for (index, (name, source, field, role)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            role,
            source,
            (ConfigErrorKind::Semantic, field),
            250 + index,
        );
    }

    let selector_detour = base_dns.replace(
        "address = \"192.0.2.53:53\"",
        "address = \"192.0.2.53:53\"\ndetour = \"manual\"",
    );
    let invalid_route_with_valid_detour = with_dns(
        with_selectors(
            routed(
                tagged_client(1, 2),
                "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"missing\"",
            ),
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"",
        ),
        &selector_detour,
    );
    assert_tagged_error(
        "ordinary route error wins with valid DNS selector detour",
        ConfigRole::Client,
        invalid_route_with_valid_detour,
        (ConfigErrorKind::Semantic, ConfigField::RouteRulesOutbound),
        289,
    );

    let ordinary_server_action = routed(
        tagged_client(1, 1),
        "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"o0\"\nserver = \"dns\"",
    );
    assert_tagged_error(
        "ordinary server action",
        ConfigRole::Client,
        ordinary_server_action,
        (ConfigErrorKind::Semantic, ConfigField::RouteRulesOutbound),
        290,
    );

    let hop_collision = with_dns(
        tagged_client(1, 1),
        &base_dns.replace("127.0.0.1:5353", "127.0.0.1:20000"),
    );
    assert_tagged_error(
        "DNS listener concrete-hop collision",
        ConfigRole::Client,
        hop_collision,
        (ConfigErrorKind::Semantic, ConfigField::DnsInboundsListen),
        291,
    );
    let server_selector = with_dns(
        with_selectors(
            tagged_server(1, 2)
                .replace("outbound = \"o0\"", "outbound = \"manual\"")
                .replace("outbound = \"o1\"", "outbound = \"manual\""),
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"",
        ),
        &base_dns
            .replace(
                "[[dns.inbounds]]\ntag = \"d0\"\nlisten = \"127.0.0.1:5353\"\n",
                "",
            )
            .replace(
                "address = \"192.0.2.53:53\"",
                "address = \"192.0.2.53:53\"\ndetour = \"manual\"",
            ),
    );
    assert_tagged_error(
        "server selector detour",
        ConfigRole::Server,
        server_selector,
        (ConfigErrorKind::Semantic, ConfigField::DnsServersDetour),
        292,
    );

    let inbounds_64 = (0..64)
        .map(|index| {
            format!(
                "[[dns.inbounds]]\ntag = \"d{index}\"\nlisten = \"127.0.0.1:{}\"\n",
                40_000 + index
            )
        })
        .collect::<String>();
    let servers_64 = (0..64)
        .map(|index| format!("[[dns.servers]]\ntag = \"s{index}\"\ntransport = \"udp\"\naddress = \"192.0.2.53:{}\"\n", 1_000 + index))
        .collect::<String>();
    let rules_64 = (0..63)
        .map(|index| format!("[[dns.route.rules]]\ntarget = {{ host = \"s{index}.example.\", port = 53 }}\nserver = \"s{index}\"\n"))
        .collect::<String>();
    let maximum = with_dns(
        CLIENT_BASE.to_owned(),
        &format!("[dns]\n{inbounds_64}{servers_64}[dns.route]\nfinal = \"s63\"\n{rules_64}"),
    );
    let maximum = load_client(TempConfig::text(&maximum).path()).expect("64 DNS identities");
    let maximum = maximum.dns.expect("DNS maximum");
    assert_eq!((maximum.inbounds.len(), maximum.servers.len()), (64, 64));
}

#[test]
fn routed_graph_rejects_mixing_bounds_matchers_and_references_redacted() {
    let base = tagged_client(1, 2);
    #[rustfmt::skip]
    let cases = [
        ("static mixing", format!("{}[route]\nfinal = \"o0\"\n", base), ConfigField::Route),
        ("legacy mixing", format!("{CLIENT_BASE}[route]\nfinal = \"o0\"\n"), ConfigField::Route),
        ("partial static binding", base.replacen("outbound = \"o0\"\n", "", 1), ConfigField::InboundsOutbound),
        ("missing final", routed(base.clone(), "[route]"), ConfigField::RouteFinal),
        ("dangling final", routed(base.clone(), "[route]\nfinal = \"missing\""), ConfigField::RouteFinal),
        ("wrong final namespace", routed(base.clone(), "[route]\nfinal = \"i0\""), ConfigField::RouteFinal),
        ("empty predicate", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\noutbound = \"o1\""), ConfigField::RouteRules),
        ("unknown network", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"quic\"\noutbound = \"o1\""), ConfigField::RouteRulesNetwork),
        ("dangling inbound", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"missing\"\noutbound = \"o1\""), ConfigField::RouteRulesInbound),
        ("wrong inbound namespace", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"o0\"\noutbound = \"o1\""), ConfigField::RouteRulesInbound),
        ("dangling outbound", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"missing\""), ConfigField::RouteRulesOutbound),
        ("missing outbound", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\""), ConfigField::RouteRulesOutbound),
        ("wrong outbound namespace", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"i0\""), ConfigField::RouteRulesOutbound),
        ("unreferenced outbound", routed(base.clone(), "[route]\nfinal = \"o0\""), ConfigField::RouteRulesOutbound),
        ("ordinary target subtable", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\noutbound = \"o1\"\n[route.rules.target]\nhost = \"example.test\"\nport = 53"), ConfigField::RouteRulesTarget),
        ("missing target host", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { port = 53 }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("missing target port", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { host = \"example.test\" }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("empty target", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { host = \"\", port = 53 }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("non ASCII target", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { host = \"é.test\", port = 53 }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("zero target port", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { host = \"example.test\", port = 0 }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("high target port", routed(base.clone(), "[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { host = \"example.test\", port = 65536 }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("long target", routed(base.clone(), &format!("[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = {{ host = \"{}\", port = 53 }}\noutbound = \"o1\"", "a".repeat(256))), ConfigField::RouteRulesTarget),
    ];
    for (index, (name, source, field)) in cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            ConfigRole::Client,
            source,
            (ConfigErrorKind::Semantic, field),
            60 + index,
        );
    }

    let too_many = "[[route.rules]]\ninbound = \"i0\"\noutbound = \"o1\"\n".repeat(65);
    assert_tagged_error(
        "65 rules",
        ConfigRole::Client,
        routed(base, &format!("[route]\nfinal = \"o0\"\n{too_many}")),
        (ConfigErrorKind::Semantic, ConfigField::RouteRules),
        80,
    );
    let server_base = tagged_server(1, 2);
    let server_routed = |route| routed(server_base.clone(), route);
    #[rustfmt::skip]
    let server_cases = [
        ("server static mixing", format!("{server_base}[route]\nfinal = \"o0\"\n"), ConfigField::Route),
        ("server legacy mixing", format!("{SERVER_BASE}[route]\nfinal = \"o0\"\n"), ConfigField::Route),
        ("server partial static binding", server_base.replacen("outbound = \"o0\"\n", "", 1), ConfigField::InboundsOutbound),
        ("server 65 rules", server_routed(&format!("[route]\nfinal = \"o0\"\n{}", "[[route.rules]]\ninbound = \"i0\"\noutbound = \"o1\"\n".repeat(65))), ConfigField::RouteRules),
        ("server wrong inbound namespace", server_routed("[route]\nfinal = \"o0\"\n[[route.rules]]\ninbound = \"o0\"\noutbound = \"o1\""), ConfigField::RouteRulesInbound),
        ("server wrong outbound namespace", server_routed("[route]\nfinal = \"o0\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"i0\""), ConfigField::RouteRulesOutbound),
        ("server wrong final namespace", server_routed("[route]\nfinal = \"i0\""), ConfigField::RouteFinal),
        ("server invalid target", server_routed("[route]\nfinal = \"o0\"\n[[route.rules]]\ntarget = { host = \"example.test\", port = 0 }\noutbound = \"o1\""), ConfigField::RouteRulesTarget),
        ("server unreferenced outbound", server_routed("[route]\nfinal = \"o0\""), ConfigField::RouteRulesOutbound),
    ];
    for (index, (name, source, field)) in server_cases.into_iter().enumerate() {
        assert_tagged_error(
            name,
            ConfigRole::Server,
            source,
            (ConfigErrorKind::Semantic, field),
            90 + index,
        );
    }
    let fields = [
        ConfigField::Route,
        ConfigField::RouteRules,
        ConfigField::RouteRulesInbound,
        ConfigField::RouteRulesNetwork,
        ConfigField::RouteRulesTarget,
        ConfigField::RouteRulesOutbound,
        ConfigField::RouteFinal,
    ];
    assert_eq!(
        fields.map(ConfigField::as_str),
        [
            "route",
            "route.rules",
            "route.rules.inbound",
            "route.rules.network",
            "route.rules.target",
            "route.rules.outbound",
            "route.final"
        ]
    );
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
