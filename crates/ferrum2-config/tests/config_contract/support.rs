pub(super) use std::error::Error;
pub(super) use std::fs;
pub(super) use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
pub(super) use std::path::{Path, PathBuf};
pub(super) use std::sync::Arc;
pub(super) use std::sync::atomic::{AtomicU64, Ordering};
pub(super) use std::time::Duration;

pub(super) use ferrum2_config::{
    ClientOutboundConfig, ClientV2Resources, CompiledRoute, CompiledRuleSetResource, ConfigError,
    ConfigErrorKind, ConfigField, DialEndpoint, DnsStrategy, LoggingLevel, MAX_CONFIG_BYTES,
    PreparedClientV2, PreparedFixedEndpointTarget, PreparedServerV2, ResolvedDnsEndpoint,
    ResolvedOutboundEndpoint, RouteAction, RuntimeConfig, ServerV2Resources, UdpFiltering,
    finish_client_v2, finish_server_v2, prepare_client, prepare_server,
};
pub(super) use ferrum2_core::TargetAddr;
pub(super) use ferrum2_core::route::{EgressPlanSnapshot, Network};
pub(super) use ferrum2_crypto::MethodProfile;
pub(super) use ferrum2_rule::{
    MatchSetBuilder, RouteMetadata, RouteProgramAction, RuleEngineRegistry,
    RuleEngineSnapshotBuilder,
};

pub(super) fn selected_endpoint(endpoint: &DialEndpoint) -> SocketAddr {
    let DialEndpoint::Domain { port, strategy, .. } = endpoint else {
        panic!("only domain endpoints require a resource")
    };
    match strategy {
        DnsStrategy::Ipv6Only => format!("[2001:db8::200]:{}", port.get()).parse().unwrap(),
        DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 | DnsStrategy::Ipv4Only => {
            format!("192.0.2.200:{}", port.get()).parse().unwrap()
        }
    }
}

pub(super) fn compiled_rule_sets(
    rule_sets: &[ferrum2_config::PreparedRuleSet],
) -> Option<CompiledRuleSetResource> {
    if rule_sets.is_empty() {
        return None;
    }
    let mut registry = RuleEngineSnapshotBuilder::new(1);
    let mut ids = Vec::with_capacity(rule_sets.len());
    for rule_set in rule_sets {
        let mut matches = MatchSetBuilder::new();
        matches.add_exact_domain("materialized.invalid").unwrap();
        matches.add_ip("192.0.2.200".parse().unwrap()).unwrap();
        let matches = registry.add_match_set(matches.build().unwrap()).unwrap();
        ids.push(registry.add_rule_set(rule_set.tag(), matches).unwrap());
    }
    Some(CompiledRuleSetResource::new(
        Arc::new(RuleEngineRegistry::new(registry.build().unwrap())),
        ids.into_boxed_slice(),
    ))
}

pub(super) fn client_resources(prepared: &PreparedClientV2) -> ClientV2Resources {
    let mut dns = Vec::new();
    let mut outbounds = Vec::new();
    for &node in prepared.materialization_order() {
        let Some(descriptor) = prepared.fixed_endpoint_for_node(node) else {
            continue;
        };
        if !matches!(descriptor.endpoint(), DialEndpoint::Domain { .. }) {
            continue;
        }
        let address = selected_endpoint(descriptor.endpoint());
        match descriptor.target() {
            PreparedFixedEndpointTarget::DnsServer(server) => dns.push(
                ResolvedDnsEndpoint::from_candidates(server, Box::new([address])),
            ),
            PreparedFixedEndpointTarget::Outbound(outbound) => {
                outbounds.push(ResolvedOutboundEndpoint::new(outbound, address));
            }
        }
    }
    ClientV2Resources::new(dns, outbounds, compiled_rule_sets(prepared.rule_sets()))
}

pub(super) fn server_resources(prepared: &PreparedServerV2) -> ServerV2Resources {
    let mut dns = Vec::new();
    for &node in prepared.materialization_order() {
        let Some(descriptor) = prepared.fixed_endpoint_for_node(node) else {
            continue;
        };
        if !matches!(descriptor.endpoint(), DialEndpoint::Domain { .. }) {
            continue;
        }
        let PreparedFixedEndpointTarget::DnsServer(server) = descriptor.target() else {
            unreachable!("server has no materialized outbound endpoints")
        };
        dns.push(ResolvedDnsEndpoint::from_candidates(
            server,
            Box::new([selected_endpoint(descriptor.endpoint())]),
        ));
    }
    ServerV2Resources::new(dns, compiled_rule_sets(prepared.rule_sets()))
}

pub(super) fn validated_client(
    path: impl AsRef<Path>,
) -> Result<ferrum2_config::ValidatedClientConfig, ConfigError> {
    let prepared = prepare_client(path)?;
    let resources = client_resources(&prepared);
    finish_client_v2(prepared, resources)
}

pub(super) fn validated_server(
    path: impl AsRef<Path>,
) -> Result<ferrum2_config::ValidatedServerConfig, ConfigError> {
    let prepared = prepare_server(path)?;
    let resources = server_resources(&prepared);
    finish_server_v2(prepared, resources)
}

pub(super) fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/config")
        .join(name)
}

pub(super) fn selected_plan(
    route: &CompiledRoute,
    inbound: usize,
    network: Network,
    target: &TargetAddr,
) -> EgressPlanSnapshot {
    let mut scratch = route.evaluation_scratch().expect("route scratch");
    let mut evaluation = route.evaluate_with_scratch(inbound, network, target, &mut scratch);
    loop {
        match evaluation.next(RouteMetadata::new(None, None)) {
            Some(RouteProgramAction::Continue(_)) => {}
            Some(RouteProgramAction::Terminal(RouteAction::Route(handle)))
            | Some(RouteProgramAction::Final(RouteAction::Route(handle))) => {
                return handle.snapshot_owned();
            }
            other => panic!("unexpected route action: {other:?}"),
        }
    }
}

pub(super) fn selected(route: &CompiledRoute, inbound: usize) -> usize {
    let plan = selected_plan(
        route,
        inbound,
        Network::Tcp,
        &TargetAddr::domain("selection.test", 443).expect("test target"),
    );
    assert_eq!(plan.hops().len(), 1);
    plan.hops()[0]
}

pub(super) fn final_plan(route: &CompiledRoute) -> EgressPlanSnapshot {
    selected_plan(
        route,
        usize::MAX,
        Network::Udp,
        &TargetAddr::domain("final.test", 1).expect("test target"),
    )
}

pub(super) const CLIENT_BASE: &str = "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"127.0.0.1:1080\"\noutbound = \"proxy-out\"\n[[outbounds]]\ntag = \"proxy-out\"\ntype = \"shadowsocks\"\nserver = \"127.0.0.1:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n# graph-anchor\n";

pub(super) const SERVER_BASE: &str = "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"127.0.0.1:8388\"\noutbound = \"direct\"\n[[outbounds]]\ntag = \"direct\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n";

pub(super) fn tagged_client(inbound_count: usize, outbound_count: usize) -> String {
    let mut source = "schema_version = 2\n".to_owned();
    for index in 0..inbound_count {
        source.push_str(&format!(
            "[[inbounds]]\ntag = \"i{index}\"\nlisten = \"127.0.0.1:{}\"\noutbound = \"o{}\"\n",
            10_000 + index,
            index.min(outbound_count.saturating_sub(1))
        ));
    }
    for index in 0..outbound_count {
        source.push_str(&format!(
            "[[outbounds]]\ntag = \"o{index}\"\ntype = \"shadowsocks\"\nserver = \"127.0.0.1:{}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
            20_000 + index
        ));
    }
    source.push_str("# graph-anchor\n");
    source
}

pub(super) fn tagged_server(inbound_count: usize, outbound_count: usize) -> String {
    tagged_client(inbound_count, outbound_count)
        .lines()
        .filter(|line| {
            !line.starts_with("type = ")
                && !line.starts_with("server = ")
                && !line.starts_with("method = ")
                && !line.starts_with("psk = ")
                && *line != "# graph-anchor"
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n# graph-anchor\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
}

pub(super) fn routed(source: String, route: &str) -> String {
    source
        .lines()
        .filter(|line| !line.starts_with("outbound = "))
        .collect::<Vec<_>>()
        .join("\n")
        .replacen("# graph-anchor", &format!("{route}\n# graph-anchor"), 1)
        + "\n"
}

pub(super) fn with_selectors(source: String, selectors: &str) -> String {
    source.replacen("# graph-anchor", &format!("{selectors}\n# graph-anchor"), 1)
}

pub(super) fn with_dns(source: String, dns: &str) -> String {
    source.replacen("# graph-anchor", &format!("{dns}\n# graph-anchor"), 1)
}

pub(super) fn assert_tagged_error(
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
        ConfigRole::Client => validated_client(file.path()).err(),
        ConfigRole::Server => validated_server(file.path()).err(),
    }
    .expect(name);
    assert_eq!((error.kind(), error.field()), expected, "{name}");
    let rendered = format!("{error}\n{error:?}");
    let values = source
        .lines()
        .flat_map(|line| line.split('"').skip(1).step_by(2))
        .filter(|value| value.len() >= 2 && !expected.1.as_str().contains(value));
    for sentinel in std::iter::once(raw.as_str())
        .chain(target_host.as_deref())
        .chain(values)
    {
        assert!(!rendered.contains(sentinel), "{name}: {sentinel}");
    }
}

pub(super) static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

pub(super) struct TempConfig(PathBuf);

impl TempConfig {
    pub(super) fn text(contents: &str) -> Self {
        Self::bytes(contents.as_bytes())
    }

    pub(super) fn bytes(contents: &[u8]) -> Self {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-m0-t04-{}-{sequence}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write temporary config");
        Self(path)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Clone, Copy)]
pub(super) enum ConfigRole {
    Client,
    Server,
}

pub(super) struct CohortCase {
    pub(super) name: &'static str,
    pub(super) fixture: &'static str,
    pub(super) role: ConfigRole,
    pub(super) method: MethodProfile,
    pub(super) runtime: [u64; 6],
    pub(super) replay_capacity: Option<usize>,
    pub(super) udp: Option<(bool, usize, usize, u64)>,
    pub(super) logging: LoggingLevel,
    pub(super) metrics_port: Option<u16>,
}

pub(super) fn tun_client(tun: &str) -> String {
    format!(
        "schema_version = 2\n{tun}\n[[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"192.0.2.10:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n# graph-anchor\n"
    )
}

pub(super) fn assert_runtime(actual: RuntimeConfig, expected: [u64; 6], name: &str) {
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
