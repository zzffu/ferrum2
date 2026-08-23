use std::fs;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use ferrum2_config::{
    ClientV2MaterializeContext, ClientV2MaterializeFuture, ClientV2Resources,
    CompiledRuleSetResource, ConfigError, ConfigErrorKind, ConfigField, DialEndpoint,
    DirectDomainResolver, DnsEndpointMode, DnsIngressId, DnsQueryType, DnsStrategy,
    PreparedClientOutboundKind, PreparedDependencyNode, PreparedDnsAction, PreparedDnsEndpointMode,
    PreparedEgressRef, PreparedFixedEndpointTarget, PreparedRuleSetDownloadMode,
    ResolvedDnsEndpoint, ResolvedOutboundEndpoint, ResolverRef, RouteAction, SchemaVersion,
    ServerV2MaterializeContext, ServerV2MaterializeFuture, ServerV2Resources, finish_client_v2,
    finish_server_v2, load_client, materialize_client_v2, materialize_server_v2, prepare_client,
    prepare_client_v2, prepare_server, prepare_server_v2,
};
use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr};
use ferrum2_rule::{
    CompiledMatchSet, DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, MatchSetBuilder,
    Network, RouteMetadata, RouteProgramAction,
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TempConfig(PathBuf);

impl TempConfig {
    fn new(contents: &str) -> Self {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-v2-prepare-{}-{id}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write temporary config");
        Self(path)
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = TaskContext::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct CountingMaterializer {
    calls: AtomicU64,
    fail: bool,
}

impl CountingMaterializer {
    const fn new(fail: bool) -> Self {
        Self {
            calls: AtomicU64::new(0),
            fail,
        }
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl ClientV2MaterializeContext for CountingMaterializer {
    fn materialize_client<'a>(
        &'a self,
        _prepared: &'a ferrum2_config::PreparedClientV2,
    ) -> ClientV2MaterializeFuture<'a> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(ConfigError::resource_materialization())
            } else {
                Ok(ClientV2Resources::default())
            }
        })
    }
}

impl ServerV2MaterializeContext for CountingMaterializer {
    fn materialize_server<'a>(
        &'a self,
        _prepared: &'a ferrum2_config::PreparedServerV2,
    ) -> ServerV2MaterializeFuture<'a> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(ConfigError::resource_materialization())
            } else {
                Ok(ServerV2Resources::default())
            }
        })
    }
}

const CLIENT_V2: &str = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct-out"
type = "direct"

[[outbounds]]
tag = "ss-out"
type = "shadowsocks"
server = "edge.example.test:8388"
domain_resolver = "local"
domain_strategy = "ipv4_only"

[[selectors]]
tag = "main"
outbounds = ["direct-out", "ss-out"]
default = "direct-out"

[route]
final = "main"

[[route.rule_set]]
tag = "ads"
type = "remote"
format = "binary"
url = "https://rules.example.test/ads.srs"
download_resolver = "local"
download_detour = "main"
update_interval_seconds = 86400

[[route.rules]]
domain_keyword = "internal"
action = "route"
outbound = "direct-out"

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "./cache"
download_timeout_ms = 15000
max_redirects = 5

[dns]
strategy = "prefer_ipv6"

[dns.cache]
enabled = true
max_entries = 8192

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[[dns.servers]]
tag = "bootstrap"
transport = "doh"
address = "dns.example.test:443"
domain_resolver = "system"
domain_strategy = "ipv6_only"
server_name = "dns.example.test"
path = "/dns-query"
detour = "main"

[dns.route]
final = "local"

[[dns.route.rules]]
domain_keyword = "special"
action = "route"
server = "bootstrap"
strategy = "ipv6_only"

[[dns.route.rules]]
rule_set = "ads"
action = "reject"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;

const SERVER_V2: &str = r#"
schema_version = 2

[[inbounds]]
tag = "ss-in"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct-out"

[[selectors]]
tag = "main"
outbounds = ["direct-out"]
default = "direct-out"

[route]
final = "main"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.test/ads.srs"
download_resolver = "system"
download_detour = "main"

[[route.rules]]
rule_set = "ads"
action = "reject"

[dns]
strategy = "ipv4_only"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"
detour = "main"

[dns.route]
final = "local"

[[dns.route.rules]]
rule_set = "ads"
action = "reject"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;

const CLIENT_V2_MINIMAL: &str = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#;

fn exact_match_set(value: &str) -> Arc<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder.add_exact_domain(value).unwrap();
    Arc::new(builder.build().unwrap())
}

fn suffix_match_set(value: &str) -> Arc<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder.add_domain_suffix(value).unwrap();
    Arc::new(builder.build().unwrap())
}

fn ip_match_set(address: IpAddr) -> Arc<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder.add_ip(address).unwrap();
    Arc::new(builder.build().unwrap())
}

fn valid_client_resources() -> ClientV2Resources {
    ClientV2Resources::new(
        vec![ResolvedDnsEndpoint::from_candidates(
            1,
            vec![
                "[2001:db8::53]:443".parse().unwrap(),
                "[2001:db8::54]:443".parse().unwrap(),
            ]
            .into_boxed_slice(),
        )],
        vec![ResolvedOutboundEndpoint::new(
            1,
            "198.51.100.10:8388".parse().unwrap(),
        )],
        vec![CompiledRuleSetResource::new(
            0,
            exact_match_set("blocked.example"),
            7,
        )],
    )
}

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

fn assert_config_syntax_error<T>(result: Result<T, ConfigError>) {
    let error = match result {
        Ok(_) => panic!("legacy root shape produced a configuration"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ConfigErrorKind::Syntax);
    assert_eq!(error.field(), ConfigField::Config);
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
        assert_schema_version_error(load_client(&file.0));
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
        assert_schema_version_error(ferrum2_config::load_server(&file.0));
        assert_schema_version_error(prepare_server(&file.0));
    }
}

#[test]
fn prepared_client_reports_only_validated_tun_auto_route() {
    let without_tun = TempConfig::new(CLIENT_V2_MINIMAL);
    let without_tun = prepare_client_v2(&without_tun.0).expect("prepare client without TUN");
    assert!(!without_tun.has_tun());
    assert!(!without_tun.tun_auto_route());

    let with_tun = TempConfig::new(
        r#"
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
outbound = "direct"

[[outbounds]]
tag = "direct"
type = "direct"
"#,
    );
    let with_tun = prepare_client_v2(&with_tun.0).expect("prepare auto-route TUN");
    assert!(with_tun.has_tun());
    assert!(with_tun.tun_auto_route());
}

#[test]
fn finished_tun_tracks_every_dual_stack_dns_candidate_and_rechecks_listener_aliases() {
    let source = r#"
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
outbound = "direct"

[[outbounds]]
tag = "direct"
type = "direct"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "bootstrap.example.test:5353"
domain_resolver = "system"
domain_strategy = "prefer_ipv4"

[dns.route]
final = "bootstrap"
"#;
    let file = TempConfig::new(source);
    let candidates = vec![
        "192.0.2.10:5353".parse().unwrap(),
        "192.0.2.11:5353".parse().unwrap(),
        "[2001:db8::53]:5353".parse().unwrap(),
    ]
    .into_boxed_slice();
    let prepared = prepare_client_v2(&file.0).expect("prepare candidate TUN");
    let finished = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::from_candidates(0, candidates)],
            Vec::new(),
            Vec::new(),
        ),
    )
    .expect("finish candidate TUN");
    assert_eq!(
        finished.tun.unwrap().physical_endpoints,
        [
            "192.0.2.10:5353".parse().unwrap(),
            "192.0.2.11:5353".parse().unwrap(),
            "[2001:db8::53]:5353".parse().unwrap(),
        ]
    );

    let prepared = prepare_client_v2(&file.0).expect("prepare alias candidate TUN");
    let error = match finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::new(
                0,
                "127.0.0.1:5353".parse().unwrap(),
            )],
            Vec::new(),
            Vec::new(),
        ),
    ) {
        Ok(_) => panic!("resolved DNS candidate aliases its listener"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::DnsServersAddress);

    let mut overflow_source = String::from(
        r#"
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
outbound = "direct"

[[outbounds]]
tag = "direct"
type = "direct"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:6000"
"#,
    );
    for server in 0..17 {
        overflow_source.push_str(&format!(
            r#"
[[dns.servers]]
tag = "s{server}"
transport = "udp"
address = "s{server}.example.test:5353"
domain_resolver = "system"
domain_strategy = "ipv4_only"
"#,
        ));
    }
    overflow_source.push_str("\n[dns.route]\nfinal = \"s0\"\n");
    for server in 1..17 {
        overflow_source.push_str(&format!(
            r#"
[[dns.route.rules]]
domain_keyword = "probe-{server}"
action = "route"
server = "s{server}"
"#,
        ));
    }
    let overflow_file = TempConfig::new(&overflow_source);
    let prepared = prepare_client_v2(&overflow_file.0).expect("prepare physical endpoint overflow");
    let resources = (0_u32..17)
        .map(|server| {
            let candidates = (1_u8..=16)
                .map(|candidate| format!("192.0.{server}.{candidate}:5353").parse().unwrap())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            ResolvedDnsEndpoint::from_candidates(server, candidates)
        })
        .collect();
    let error = match finish_client_v2(
        prepared,
        ClientV2Resources::new(resources, Vec::new(), Vec::new()),
    ) {
        Ok(_) => panic!("physical endpoint overflow must fail during config finish"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::TunAutoRoute);
}

#[test]
fn async_materialize_facade_calls_context_once_and_short_circuits_failure() {
    let client_file = TempConfig::new(CLIENT_V2_MINIMAL);
    let prepared = prepare_client(&client_file.0).expect("prepare client");
    let success = CountingMaterializer::new(false);
    assert_eq!(
        success.calls(),
        0,
        "static preparation invoked materializer"
    );
    let config = block_on(materialize_client_v2(prepared, &success)).expect("materialize client");
    assert_eq!(success.calls(), 1);
    assert_eq!(config.schema_version, SchemaVersion::V2);

    let server_file = TempConfig::new(SERVER_V2);
    let prepared = prepare_server(&server_file.0).expect("prepare server");
    let failure = CountingMaterializer::new(true);
    assert_eq!(
        failure.calls(),
        0,
        "static preparation invoked materializer"
    );
    let error = match block_on(materialize_server_v2(prepared, &failure)) {
        Ok(_) => panic!("failed materializer reached finish"),
        Err(error) => error,
    };
    assert_eq!(failure.calls(), 1);
    assert_eq!(error, ConfigError::resource_materialization());
    assert_eq!(error.field(), ConfigField::ResourceMaterialization);
}

#[test]
fn bootstrap_descriptors_follow_dependency_order_without_exposing_values_in_debug() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client_v2(&file.0).expect("prepare bootstrap descriptors");

    assert_eq!(prepared.dns_server_count(), 2);
    let doh = prepared.dns_server(1).expect("DoH descriptor");
    assert_eq!(doh.index(), 1);
    assert_eq!(doh.transport(), ferrum2_config::DnsTransport::Doh);
    assert_eq!(doh.server_name(), Some("dns.example.test"));
    assert_eq!(doh.path(), Some("/dns-query"));
    assert_eq!(doh.detour().unwrap().snapshot().hops(), &[0]);
    assert!(doh.endpoint().is_domain());
    let debug = format!("{doh:?}");
    assert!(!debug.contains("dns.example.test"));
    assert!(!debug.contains("dns-query"));

    assert_eq!(prepared.outbound_count(), 2);
    let direct = prepared.outbound(0).expect("direct descriptor");
    assert_eq!(direct.kind(), PreparedClientOutboundKind::Direct);
    assert!(direct.method().is_none());
    assert!(direct.psk().is_none());
    assert!(direct.endpoint().is_none());
    assert_eq!(direct.domain_resolver(), Some(DirectDomainResolver::System));
    let shadowsocks = prepared.outbound(1).expect("Shadowsocks descriptor");
    assert_eq!(shadowsocks.kind(), PreparedClientOutboundKind::Shadowsocks);
    assert!(shadowsocks.method().is_some());
    let shared_psk = shadowsocks.psk().expect("shared Shadowsocks PSK");
    let staged_psk = Arc::clone(shared_psk);
    assert!(Arc::ptr_eq(shared_psk, &staged_psk));
    assert_eq!(format!("{shared_psk:?}"), "MethodPsk([REDACTED])");
    assert!(shadowsocks.endpoint().is_some_and(DialEndpoint::is_domain));
    let debug = format!("{shadowsocks:?}");
    assert!(!debug.contains("AAECAwQFBgcICQoLDA0ODw=="));

    let declarations = prepared
        .materialization_order()
        .iter()
        .filter_map(|node| {
            prepared
                .fixed_endpoint_for_node(*node)
                .map(|descriptor| (*node, descriptor.target()))
        })
        .collect::<Vec<_>>();
    assert_eq!(declarations.len(), 3);
    for (node, target) in declarations {
        match (node, target) {
            (
                PreparedDependencyNode::DnsServer(index),
                PreparedFixedEndpointTarget::DnsServer(target_index),
            ) => assert_eq!(index, target_index),
            (
                PreparedDependencyNode::Outbound(index),
                PreparedFixedEndpointTarget::Outbound(target_index),
            ) => assert_eq!(index, target_index),
            other => panic!("dependency endpoint identity mismatch: {other:?}"),
        }
    }
    assert!(
        prepared
            .fixed_endpoint_for_node(PreparedDependencyNode::Outbound(0))
            .is_none()
    );
    assert_eq!(prepared.runtime().max_connections.get(), 4_096);
    assert!(prepared.udp().is_none());
}

#[test]
fn client_prepare_retains_closed_resources_without_materializing() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client_v2(&file.0).expect("prepare client V2");

    assert_eq!(
        prepared.rule_set_loader().cache_dir,
        PathBuf::from("./cache")
    );
    assert_eq!(
        prepared.rule_set_loader().download_timeout,
        Duration::from_secs(15)
    );
    assert_eq!(prepared.dns_strategy(), Some(DnsStrategy::PreferIpv6));
    assert_eq!(prepared.dns_cache().unwrap().max_entries, 8192);
    let dns_runtime = prepared.dns_runtime().expect("prepared DNS runtime");
    assert_eq!(dns_runtime.strategy(), DnsStrategy::PreferIpv6);
    assert_eq!(dns_runtime.cache(), prepared.dns_cache().unwrap());
    assert_eq!(prepared.dns_timeout(), Some(Duration::from_secs(5)));
    assert_eq!(prepared.dns_max_inflight().unwrap().get(), 256);
    assert_eq!(prepared.rule_sets().len(), 1);
    assert_eq!(
        prepared.rule_sets()[0].download_mode(),
        PreparedRuleSetDownloadMode::ClientResolved {
            resolver: ResolverRef::DnsServer(0),
        }
    );
    assert_eq!(
        prepared.rule_sets()[0].download_resolver(),
        Some(ResolverRef::DnsServer(0))
    );
    assert_eq!(
        prepared.rule_sets()[0].download_detour(),
        Some(PreparedEgressRef::Selector(0))
    );
    assert_eq!(prepared.route_rule_sets()[0].rule_sets, [0]);
    assert_eq!(prepared.dns_rules()[0].rule_sets, []);
    assert_eq!(
        prepared.dns_rules()[0].action,
        PreparedDnsAction::Route { server: 1 }
    );
    assert_eq!(prepared.dns_rules()[0].strategy, DnsStrategy::Ipv6Only);
    assert_eq!(prepared.dns_rules()[1].rule_sets, [0]);
    assert_eq!(prepared.dns_rules()[1].action, PreparedDnsAction::Reject);
    assert!(prepared.outbound_endpoints()[0].is_none());
    assert!(matches!(
        prepared.outbound_endpoints()[1],
        Some(DialEndpoint::Domain {
            resolver: ResolverRef::DnsServer(0),
            strategy: DnsStrategy::Ipv4Only,
            ..
        })
    ));
    assert_eq!(
        prepared.dns_endpoints()[0].mode(),
        PreparedDnsEndpointMode::Numeric
    );
    assert_eq!(
        prepared.dns_endpoints()[1].mode(),
        PreparedDnsEndpointMode::ClientResolved {
            resolver: ResolverRef::System,
            strategy: DnsStrategy::Ipv6Only,
        }
    );
    assert_eq!(prepared.dependency_node_count(), 7);
    assert_eq!(
        prepared
            .download_detour_plan(0)
            .expect("RuleSet detour plan")
            .snapshot()
            .hops(),
        &[0]
    );
    assert_eq!(prepared.download_detour_is_direct(0), Some(true));
    assert!(prepared.download_detour_plan(1).is_none());
    assert_eq!(prepared.download_detour_is_direct(1), None);
    let order = prepared.materialization_order();
    let position = |node| {
        order
            .iter()
            .position(|candidate| *candidate == node)
            .unwrap()
    };
    assert!(
        position(PreparedDependencyNode::SystemResolver)
            < position(PreparedDependencyNode::DnsServer(1))
    );
    assert!(
        position(PreparedDependencyNode::DnsServer(0))
            < position(PreparedDependencyNode::Outbound(1))
    );
    assert!(
        position(PreparedDependencyNode::Outbound(1))
            < position(PreparedDependencyNode::Selector(0))
    );
    assert!(
        position(PreparedDependencyNode::Selector(0))
            < position(PreparedDependencyNode::RuleSet(0))
    );
}

#[test]
fn server_prepare_accepts_shared_rulesets_and_selector_detours() {
    let file = TempConfig::new(SERVER_V2);
    let prepared = prepare_server_v2(&file.0).expect("prepare server V2");
    assert_eq!(
        prepared.outbound(0).unwrap().domain_resolver(),
        DirectDomainResolver::System
    );
    assert_eq!(prepared.dns_timeout(), Some(Duration::from_secs(5)));
    assert_eq!(prepared.dns_max_inflight().unwrap().get(), 256);
    assert_eq!(prepared.rule_sets().len(), 1);
    assert_eq!(
        prepared.rule_sets()[0].download_detour(),
        Some(PreparedEgressRef::Selector(0))
    );
    assert_eq!(
        prepared
            .download_detour_plan(0)
            .expect("server RuleSet detour plan")
            .snapshot()
            .hops(),
        &[0]
    );
    assert_eq!(prepared.download_detour_is_direct(0), Some(true));
    assert_eq!(prepared.route_rule_sets()[0].rule_sets, [0]);
    assert_eq!(prepared.dns_rules()[0].action, PreparedDnsAction::Reject);
}

#[test]
fn direct_resolver_metadata_is_preserved_for_client_and_server() {
    let client_source = CLIENT_V2.replacen(
        "type = \"direct\"\n",
        concat!(
            "type = \"direct\"\n",
            "domain_resolver = \"local\"\n",
            "domain_strategy = \"ipv4_only\"\n",
        ),
        1,
    );
    let client_file = TempConfig::new(&client_source);
    let client = prepare_client_v2(&client_file.0).expect("explicit client Direct resolver");
    assert_eq!(
        client.outbound(0).unwrap().domain_resolver(),
        Some(DirectDomainResolver::DnsServer {
            server: 0,
            strategy: DnsStrategy::Ipv4Only,
        })
    );
    assert_eq!(
        client.accepts_domain_target(PreparedEgressRef::Outbound(0)),
        Some(true)
    );
    let order = client.materialization_order();
    assert!(
        order
            .iter()
            .position(|node| *node == PreparedDependencyNode::DnsServer(0))
            < order
                .iter()
                .position(|node| *node == PreparedDependencyNode::Outbound(0))
    );

    let server_source = r#"
schema_version = 2

[[inbounds]]
tag = "ss-in"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"
domain_resolver = "local"
domain_strategy = "prefer_ipv6"

[route]
final = "direct"

[dns]
strategy = "ipv4_only"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[dns.route]
final = "local"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let server_file = TempConfig::new(server_source);
    let server = prepare_server_v2(&server_file.0).expect("explicit server Direct resolver");
    assert_eq!(server.outbound_count(), 1);
    assert_eq!(
        server.outbound(0).unwrap().domain_resolver(),
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: DnsStrategy::PreferIpv6,
        }
    );
    assert_eq!(
        server.accepts_domain_target(PreparedEgressRef::Outbound(0)),
        Some(true)
    );
    let finished = finish_server_v2(server, ServerV2Resources::default())
        .expect("finish server Direct resolver");
    assert_eq!(
        finished.outbounds[0].domain_resolver,
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: DnsStrategy::PreferIpv6,
        }
    );
}

#[test]
fn deferred_dns_and_ruleset_modes_keep_domains_and_need_no_resolver_resources() {
    let source = CLIENT_V2
        .replace(
            concat!(
                "domain_resolver = \"system\"\n",
                "domain_strategy = \"ipv6_only\"\n",
            ),
            "",
        )
        .replace("download_resolver = \"local\"\n", "");
    let file = TempConfig::new(&source);
    let prepared = prepare_client_v2(&file.0).expect("deferred domain targets");
    assert_eq!(
        prepared.dns_endpoints()[1].mode(),
        PreparedDnsEndpointMode::DeferredToDetour
    );
    assert_eq!(
        prepared.dns_endpoints()[1]
            .target()
            .canonical_domain()
            .unwrap()
            .as_str(),
        "dns.example.test"
    );
    assert!(
        prepared
            .fixed_endpoint_for_node(PreparedDependencyNode::DnsServer(1))
            .is_none()
    );
    assert_eq!(
        prepared.rule_sets()[0].download_mode(),
        PreparedRuleSetDownloadMode::DeferredToDetour
    );
    assert_eq!(prepared.rule_sets()[0].download_resolver(), None);
    let finished = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            vec![CompiledRuleSetResource::new(
                0,
                exact_match_set("blocked.example"),
                7,
            )],
        ),
    )
    .expect("finish deferred domain targets");
    let server = &finished.dns.as_ref().unwrap().servers[1];
    assert_eq!(server.endpoint_mode, DnsEndpointMode::DeferredToDetour);
    assert_eq!(
        server.target.canonical_domain().unwrap().as_str(),
        "dns.example.test"
    );
}

#[test]
fn direct_resolver_cycles_use_the_unified_dependency_cycle_code() {
    let source = CLIENT_V2
        .replacen(
            "type = \"direct\"\n",
            "type = \"direct\"\ndomain_resolver = \"local\"\n",
            1,
        )
        .replacen(
            "address = \"192.0.2.53:53\"\n",
            "address = \"192.0.2.53:53\"\ndetour = \"direct-out\"\n",
            1,
        );
    let file = TempConfig::new(&source);
    let error = prepare_client_v2(&file.0).expect_err("Direct resolver cycle");
    assert_eq!(error.kind(), ConfigErrorKind::DnsDependencyCycle);
    assert_eq!(error.code(), "config.dependency_cycle");
    assert_eq!(
        error.to_string(),
        concat!(
            "error[config.dependency_cycle] config.dependency_cycle: ",
            "the configuration dependency graph contains a cycle: ",
            "dns-server[0] -> outbound[0] -> dns-server[0]"
        )
    );
}

#[test]
fn nested_selectors_aggregate_domain_capability_and_cycles_fail_closed() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct-a"
type = "direct"

[[outbounds]]
tag = "direct-b"
type = "direct"

[[selectors]]
tag = "inner"
outbounds = ["direct-a", "direct-b"]
default = "direct-a"

[[selectors]]
tag = "outer"
outbounds = ["inner"]
default = "inner"

[route]
final = "outer"
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_client_v2(&file.0).expect("nested selectors");
    assert_eq!(
        prepared.accepts_domain_target(PreparedEgressRef::Selector(0)),
        Some(true)
    );
    assert_eq!(
        prepared.accepts_domain_target(PreparedEgressRef::Selector(1)),
        Some(true)
    );

    let cycle = source
        .replace(
            "outbounds = [\"direct-a\", \"direct-b\"]",
            "outbounds = [\"outer\"]",
        )
        .replace("default = \"direct-a\"", "default = \"outer\"");
    let file = TempConfig::new(&cycle);
    let error = prepare_client_v2(&file.0).expect_err("nested selector cycle");
    assert_eq!(error.code(), "config.dependency_cycle");
    assert_eq!(
        error.to_string(),
        concat!(
            "error[config.dependency_cycle] config.dependency_cycle: ",
            "the configuration dependency graph contains a cycle: ",
            "selector[0] -> selector[1] -> selector[0]"
        )
    );
}

#[test]
fn selector_chain_cycle_reports_the_complete_closed_path() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct"
type = "direct"

[[chains]]
tag = "loop-chain"
hops = ["direct", "loop-selector"]

[[selectors]]
tag = "loop-selector"
outbounds = ["loop-chain"]
default = "loop-chain"

[route]
final = "loop-selector"
"#;
    let file = TempConfig::new(source);
    let error = prepare_client_v2(&file.0).expect_err("selector/chain cycle");

    assert_eq!(error.code(), "config.dependency_cycle");
    assert_eq!(
        error.to_string(),
        concat!(
            "error[config.dependency_cycle] config.dependency_cycle: ",
            "the configuration dependency graph contains a cycle: ",
            "selector[0] -> chain[0] -> selector[0]"
        )
    );
}

#[test]
fn endpoint_and_ruleset_failures_are_field_specific_and_redacted() {
    let cases = [
        (
            CLIENT_V2.replacen("domain_resolver = \"local\"\n", "", 1),
            ConfigErrorKind::DnsResolverRequired,
            ConfigField::OutboundsDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "server = \"edge.example.test:8388\"",
                "server = \"192.0.2.80:8388\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                concat!(
                    "domain_resolver = \"system\"\n",
                    "domain_strategy = \"ipv6_only\"\n",
                    "server_name = \"dns.example.test\"\n",
                    "path = \"/dns-query\"\n",
                    "detour = \"main\"\n",
                ),
                concat!(
                    "server_name = \"dns.example.test\"\n",
                    "path = \"/dns-query\"\n",
                ),
            ),
            ConfigErrorKind::DnsResolverRequired,
            ConfigField::DnsServersDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "address = \"192.0.2.53:53\"",
                "address = \"192.0.2.53:53\"\ndomain_resolver = \"system\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::DnsServersDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "type = \"direct\"",
                "type = \"direct\"\ndomain_resolver = \"system\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "type = \"direct\"",
                "type = \"direct\"\ndomain_strategy = \"ipv4_only\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsDomainStrategy,
        ),
        (
            CLIENT_V2.replace(
                "download_resolver = \"local\"\ndownload_detour = \"main\"\n",
                "",
            ),
            ConfigErrorKind::DnsResolverRequired,
            ConfigField::RouteRuleSetDownloadResolver,
        ),
        (
            CLIENT_V2.replacen(
                "[[route.rule_set]]\ntag = \"ads\"\n",
                "[[route.rule_set]]\n",
                1,
            ),
            ConfigErrorKind::Semantic,
            ConfigField::RouteRuleSetTag,
        ),
        (
            CLIENT_V2.replace("https://rules.example.test", "http://secret.invalid"),
            ConfigErrorKind::Semantic,
            ConfigField::RouteRuleSetUrl,
        ),
        (
            CLIENT_V2.replace("rule_set = \"ads\"", "rule_set = \"missing-secret\""),
            ConfigErrorKind::Semantic,
            ConfigField::RouteRulesRuleSet,
        ),
    ];
    for (index, (source, expected_kind, expected_field)) in cases.into_iter().enumerate() {
        let file = TempConfig::new(&source);
        let error = prepare_client_v2(&file.0).expect_err("invalid prepared config");
        assert_eq!(error.kind(), expected_kind, "case {index}");
        assert_eq!(error.field(), expected_field, "case {index}");
        let display = error.to_string();
        assert!(!display.contains("secret"), "case {index}");
        assert!(!display.contains("example.test"), "case {index}");
    }
}

#[test]
fn duplicate_ruleset_tags_fail_closed() {
    let duplicate = r#"
[[route.rule_set]]
tag = "ads"
type = "remote"
format = "binary"
url = "https://duplicate.invalid/secret.srs"
download_resolver = "local"
download_detour = "main"
"#;
    let source = CLIENT_V2.replacen(
        "[[route.rules]]",
        &format!("{duplicate}\n[[route.rules]]"),
        1,
    );
    let file = TempConfig::new(&source);
    let error = prepare_client_v2(&file.0).expect_err("duplicate RuleSet tag");
    assert_eq!(error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(error.field(), ConfigField::RouteRuleSetTag);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("duplicate.invalid"));
    assert!(!rendered.contains("secret"));
}

#[test]
fn system_is_reserved_and_dependency_cycles_fail_before_materialization() {
    let reserved = CLIENT_V2.replace("tag = \"local\"", "tag = \"system\"");
    let file = TempConfig::new(&reserved);
    let error = prepare_client_v2(&file.0).unwrap_err();
    assert_eq!(error.kind(), ConfigErrorKind::DnsReservedResolverName);
    assert_eq!(error.field(), ConfigField::DnsServersTag);

    let self_cycle = CLIENT_V2.replace(
        "domain_resolver = \"system\"",
        "domain_resolver = \"bootstrap\"",
    );
    let file = TempConfig::new(&self_cycle);
    let error = prepare_client_v2(&file.0).unwrap_err();
    assert_eq!(error.kind(), ConfigErrorKind::DnsDependencyCycle);
    assert_eq!(error.field(), ConfigField::DnsDependencyCycle);

    let selector_cycle = CLIENT_V2.replace(
        "address = \"192.0.2.53:53\"",
        "address = \"192.0.2.53:53\"\ndetour = \"main\"",
    );
    let file = TempConfig::new(&selector_cycle);
    let error = prepare_client_v2(&file.0).unwrap_err();
    assert_eq!(error.kind(), ConfigErrorKind::DnsDependencyCycle);
    assert_eq!(error.field(), ConfigField::DnsDependencyCycle);
}

#[test]
fn schema_v1_is_rejected_before_legacy_root_fields_are_parsed() {
    let source = r#"
schema_version = 1
[client]
listen = "127.0.0.1:1080"
server = "127.0.0.1:8388"
[rule_set_loader]
cache_dir = "./cache"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let error = match ferrum2_config::load_client(&file.0) {
        Ok(_) => panic!("schema V1 produced a configuration"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(error.field(), ConfigField::SchemaVersion);
}

#[test]
fn schema_v2_rejects_legacy_client_and_server_root_shapes() {
    let client = TempConfig::new(
        r#"
schema_version = 2
[client]
listen = "127.0.0.1:1080"
server = "127.0.0.1:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
    );
    assert_config_syntax_error(load_client(&client.0));
    assert_config_syntax_error(prepare_client(&client.0));

    let server = TempConfig::new(
        r#"
schema_version = 2
[server]
listen = "127.0.0.1:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
    );
    assert_config_syntax_error(ferrum2_config::load_server(&server.0));
    assert_config_syntax_error(prepare_server(&server.0));
}

#[test]
fn inline_domain_keyword_compiles_for_ordinary_and_dns_routes() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "fallback"
type = "direct"

[[outbounds]]
tag = "keyword"
type = "direct"

[route]
final = "fallback"

[[route.rules]]
domain_keyword = "needle"
action = "route"
outbound = "keyword"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "fallback-dns"
transport = "udp"
address = "192.0.2.1:53"

[[dns.servers]]
tag = "keyword-dns"
transport = "udp"
address = "192.0.2.2:53"

[dns.route]
final = "fallback-dns"

[[dns.route.rules]]
domain_keyword = "needle"
action = "route"
server = "keyword-dns"

[[dns.route.rules]]
qname = "exact.example"
action = "route"
server = "keyword-dns"
"#;
    let file = TempConfig::new(source);
    let config = ferrum2_config::load_client(&file.0).expect("load inline keyword V2");
    assert!(
        config
            .dns_route
            .as_ref()
            .expect("DNS route")
            .has_compatibility_program()
    );
    let target = TargetAddr::domain("has-needle.example", 443).expect("target");
    let mut route = config
        .route_program
        .as_ref()
        .expect("compiled route")
        .evaluate(0, Network::Tcp, &target);
    match route.next(RouteMetadata::new(None, None)) {
        Some(RouteProgramAction::Terminal(RouteAction::Route(plan))) => {
            assert_eq!(plan.snapshot().hops(), [1]);
        }
        _ => panic!("domain keyword did not select its route"),
    }
    assert_eq!(
        config.dns_route.as_ref().expect("DNS route").select(
            DnsIngressId::Listener(0),
            Network::Udp,
            &target,
            Some(DnsQueryType::A),
        ),
        Some(1)
    );

    let prepared = prepare_client_v2(&file.0).expect("prepare inline keyword V2");
    let finished =
        finish_client_v2(prepared, ClientV2Resources::default()).expect("finish inline keyword V2");
    let binding = finished
        .dns_route
        .as_ref()
        .and_then(|route| route.policy_blueprint())
        .expect("inline-only policy blueprint");
    assert!(
        !finished
            .dns_route
            .as_ref()
            .expect("materialized DNS route")
            .has_compatibility_program()
    );
    assert_eq!(binding.registry().generation(), 0);
    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 2);
    assert_eq!(blueprint.response_rule_count(), 0);
    for (rule, domain) in blueprint
        .rules()
        .iter()
        .zip(["has-needle.example", "exact.example"])
    {
        assert!(
            rule.matcher().query_fields()[0]
                .matches_domain(&CanonicalDomain::new(domain).expect("canonical policy probe"))
        );
        assert_eq!(
            rule.action(),
            DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
                1,
                DnsPolicyAddressStrategy::PreferIpv4,
            ))
        );
    }
}

#[test]
fn finish_client_replaces_domain_endpoints_and_captures_one_registry() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client_v2(&file.0).expect("prepare client V2");
    let config = finish_client_v2(prepared, valid_client_resources()).expect("finish client V2");

    assert_eq!(
        config.outbounds[1].server(),
        Some("198.51.100.10:8388".parse().unwrap())
    );
    let resolved_server = &config.dns.as_ref().unwrap().servers[1];
    assert_eq!(
        resolved_server.target.canonical_domain().unwrap().as_str(),
        "dns.example.test"
    );
    assert_eq!(
        resolved_server.resolved_targets.as_ref(),
        &[
            "[2001:db8::53]:443".parse().unwrap(),
            "[2001:db8::54]:443".parse().unwrap(),
        ]
    );
    assert_eq!(
        config.dns.as_ref().unwrap().servers[0].endpoint_mode,
        DnsEndpointMode::Numeric
    );
    assert_eq!(
        config.dns.as_ref().unwrap().servers[1].endpoint_mode,
        DnsEndpointMode::ClientResolved {
            resolver: ResolverRef::System,
            strategy: DnsStrategy::Ipv6Only,
        }
    );
    let dns_runtime = config.dns.as_ref().unwrap().runtime;
    assert_eq!(dns_runtime.strategy(), DnsStrategy::PreferIpv6);
    assert_eq!(dns_runtime.cache().max_entries, 8_192);
    let route = config.route_program.as_ref().expect("compiled route");
    let registry = route.rule_registry().expect("RuleSet registry");
    assert_eq!(registry.generation(), 7);
    assert_eq!(registry.snapshot().rule_set_count(), 1);

    let dns_route = config.dns_route.as_ref().expect("compiled DNS route");
    assert!(!dns_route.has_compatibility_program());
    let binding = dns_route
        .policy_blueprint()
        .expect("materialized DNS policy blueprint");
    let dns_registry = binding.registry();
    assert!(Arc::ptr_eq(&registry, &dns_registry));
    assert_eq!(binding.listener_count(), 1);
    assert_eq!(binding.ordinary_count(), 1);
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(0)), Some(0));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Ordinary(0)), Some(1));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(1)), None);

    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 2);
    let special = &blueprint.rules()[0];
    assert_eq!(
        special.action(),
        DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
            1,
            DnsPolicyAddressStrategy::Ipv6Only,
        ))
    );
    assert!(
        special.matcher().query_fields()[0]
            .matches_domain(&CanonicalDomain::new("very-special.example").expect("special probe"))
    );
    let ads = &blueprint.rules()[1];
    assert_eq!(ads.action(), DnsPolicyActionDescriptor::Reject);
    assert_eq!(
        ads.matcher().rule_sets(),
        [ferrum2_rule::RuleSetId::from_raw(0)]
    );

    let target = TargetAddr::domain("blocked.example", 443).unwrap();
    let mut evaluation = route.evaluate(0, Network::Tcp, &target);
    assert_eq!(evaluation.snapshot_generation(), Some(7));
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(RouteAction::Reject))
    ));
}

#[test]
fn materialized_v2_dns_runtime_uses_compatible_defaults() {
    let source = CLIENT_V2
        .replace("strategy = \"prefer_ipv6\"\n", "")
        .replace("\n[dns.cache]\nenabled = true\nmax_entries = 8192\n", "");
    assert!(!source.contains("[dns.cache]"));
    let file = TempConfig::new(&source);
    let prepared = prepare_client_v2(&file.0).expect("prepare default DNS runtime");
    let prepared_runtime = prepared.dns_runtime().expect("prepared default runtime");
    assert_eq!(prepared_runtime.strategy(), DnsStrategy::PreferIpv4);
    assert_eq!(
        prepared_runtime.cache(),
        ferrum2_config::DnsCacheConfig {
            enabled: true,
            max_entries: 8_192,
        }
    );

    let config = finish_client_v2(prepared, valid_client_resources()).expect("finish defaults");
    let runtime = config.dns.as_ref().unwrap().runtime;
    assert_eq!(runtime, prepared_runtime);
}

#[test]
fn finish_server_rulesets_are_ored_anded_and_match_a_sniffed_domain() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "ss-in"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "first"
type = "remote"
url = "https://rules.example.test/first.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "second"
type = "remote"
url = "https://rules.example.test/second.srs"
download_resolver = "system"

[[route.rules]]
network = "tcp"
action = "sniff"
sniffers = "tls"

[[route.rules]]
network = "tcp"
rule_set = ["first", "second"]
action = "reject"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_server_v2(&file.0).expect("prepare server RuleSets");
    let config = finish_server_v2(
        prepared,
        ServerV2Resources::new(
            vec![],
            vec![
                CompiledRuleSetResource::new(0, exact_match_set("first.example"), 9),
                CompiledRuleSetResource::new(1, exact_match_set("sniffed.example"), 9),
            ],
        ),
    )
    .expect("finish server RuleSets");
    let route = config.route_program.as_ref().unwrap();
    let original = TargetAddr::ip("192.0.2.10:443".parse().unwrap()).unwrap();
    let sniffed = DomainName::new("SNIFFED.EXAMPLE.").unwrap();
    let mut evaluation = route.evaluate(0, Network::Tcp, &original);
    assert_eq!(evaluation.snapshot_generation(), Some(9));
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(RouteAction::Sniff(_)))
    ));
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, Some(&sniffed))),
        Some(RouteProgramAction::Terminal(RouteAction::Reject))
    ));

    let target = TargetAddr::domain("sniffed.example", 443).unwrap();
    let mut wrong_network = route.evaluate(0, Network::Udp, &target);
    assert!(matches!(
        wrong_network.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(RouteAction::Route(_)))
    ));
}

#[test]
fn server_dns_policy_uses_ruleset_or_external_and_application_namespace() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "app"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "first"
type = "remote"
url = "https://rules.example.test/first.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "second"
type = "remote"
url = "https://rules.example.test/second.srs"
download_resolver = "system"

[dns]

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[[dns.servers]]
tag = "fallback"
transport = "udp"
address = "192.0.2.54:53"

[dns.route]
final = "fallback"

[[dns.route.rules]]
inbound = "app"
network = "tcp"
domain_keyword = "service"
rule_set = ["first", "second"]
port = 443
port_range = "400:500"
action = "route"
server = "local"
strategy = "ipv6_only"

[[dns.route.rules]]
domain = "exact.invalid"
port = 8443
action = "route"
server = "local"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_server_v2(&file.0).expect("prepare server DNS policy");
    let config = finish_server_v2(
        prepared,
        ServerV2Resources::new(
            vec![],
            vec![
                CompiledRuleSetResource::new(0, exact_match_set("first.invalid"), 11),
                CompiledRuleSetResource::new(1, suffix_match_set("allowed.invalid"), 11),
            ],
        ),
    )
    .expect("finish server DNS policy");
    let route_registry = config
        .route_program
        .as_ref()
        .and_then(|route| route.rule_registry())
        .expect("ordinary route registry");
    let dns_route = config.dns_route.as_ref().expect("server DNS route");
    assert!(!dns_route.has_compatibility_program());
    let binding = dns_route
        .policy_blueprint()
        .expect("server DNS policy blueprint");
    let registry = binding.registry();
    assert!(Arc::ptr_eq(&route_registry, &registry));
    assert_eq!(registry.generation(), 11);
    assert_eq!(binding.listener_count(), 0);
    assert_eq!(binding.ordinary_count(), 1);
    assert_eq!(binding.resolve_ingress(DnsIngressId::Ordinary(0)), Some(0));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(0)), None);

    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 2);
    let matching = &blueprint.rules()[0];
    assert_eq!(matching.matcher().inbounds(), [0]);
    assert_eq!(matching.matcher().networks(), [Network::Tcp]);
    assert_eq!(matching.matcher().ports()[0].get(), 443);
    assert_eq!(matching.matcher().port_ranges()[0].first().get(), 400);
    assert_eq!(matching.matcher().port_ranges()[0].last().get(), 500);
    assert_eq!(matching.matcher().rule_sets().len(), 2);
    assert!(
        matching.matcher().query_fields()[0].matches_domain(
            &CanonicalDomain::new("service.allowed.invalid").expect("keyword probe")
        )
    );
    assert_eq!(
        matching.action(),
        DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
            0,
            DnsPolicyAddressStrategy::Ipv6Only,
        ))
    );
    let target = &blueprint.rules()[1];
    assert!(
        target.matcher().query_fields()[0]
            .matches_domain(&CanonicalDomain::new("exact.invalid").expect("target probe"))
    );
    assert_eq!(target.matcher().ports()[0].get(), 8443);
    assert_eq!(
        blueprint.final_route(),
        ferrum2_rule::DnsPolicyRouteDescriptor::new(1, DnsPolicyAddressStrategy::PreferIpv4,)
    );
}

#[test]
fn finish_rejects_missing_extra_mistyped_and_misidentified_resources_redacted() {
    let file = TempConfig::new(CLIENT_V2);
    let invalid = [
        ClientV2Resources::default(),
        ClientV2Resources::new(
            vec![
                ResolvedDnsEndpoint::new(1, "[2001:db8::53]:443".parse().unwrap()),
                ResolvedDnsEndpoint::new(0, "192.0.2.53:53".parse().unwrap()),
            ],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            vec![CompiledRuleSetResource::new(
                0,
                exact_match_set("blocked.example"),
                7,
            )],
        ),
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::new(
                1,
                "[2001:db8::53]:443".parse().unwrap(),
            )],
            vec![ResolvedOutboundEndpoint::new(
                0,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            vec![CompiledRuleSetResource::new(
                0,
                exact_match_set("blocked.example"),
                7,
            )],
        ),
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::new(
                1,
                "[2001:db8::53]:443".parse().unwrap(),
            )],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.10:9999".parse().unwrap(),
            )],
            vec![CompiledRuleSetResource::new(
                0,
                exact_match_set("blocked.example"),
                7,
            )],
        ),
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::new(
                1,
                "[2001:db8::53]:443".parse().unwrap(),
            )],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "[2001:db8::10]:8388".parse().unwrap(),
            )],
            vec![CompiledRuleSetResource::new(
                1,
                exact_match_set("blocked.example"),
                7,
            )],
        ),
    ];
    for (index, resources) in invalid.into_iter().enumerate() {
        let prepared = prepare_client_v2(&file.0).expect("prepare invalid resource case");
        let error = finish_client_v2(prepared, resources)
            .err()
            .expect("resource mismatch must fail");
        assert_eq!(error.field(), ConfigField::ResourceMaterialization);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("example"), "case {index}");
        assert!(!rendered.contains("198.51"), "case {index}");
        assert!(!rendered.contains("2001:db8"), "case {index}");
    }
}

#[test]
fn finish_rejects_mixed_ruleset_generations() {
    let second = r#"
[[route.rule_set]]
tag = "second"
type = "remote"
format = "binary"
url = "https://rules.example.test/second.srs"
download_resolver = "local"
download_detour = "main"
"#;
    let source = CLIENT_V2.replacen("[[route.rules]]", &format!("{second}\n[[route.rules]]"), 1);
    let file = TempConfig::new(&source);
    let prepared = prepare_client_v2(&file.0).expect("prepare two RuleSets");
    assert!(std::ptr::eq(
        prepared.download_detour_plan(0).unwrap(),
        prepared.download_detour_plan(1).unwrap()
    ));
    assert_eq!(prepared.download_detour_is_direct(0), Some(true));
    assert_eq!(prepared.download_detour_is_direct(1), Some(true));
    let resources = ClientV2Resources::new(
        vec![ResolvedDnsEndpoint::new(
            1,
            "[2001:db8::53]:443".parse().unwrap(),
        )],
        vec![ResolvedOutboundEndpoint::new(
            1,
            "198.51.100.10:8388".parse().unwrap(),
        )],
        vec![
            CompiledRuleSetResource::new(0, exact_match_set("first.example"), 7),
            CompiledRuleSetResource::new(1, exact_match_set("second.example"), 8),
        ],
    );
    assert_eq!(
        finish_client_v2(prepared, resources)
            .err()
            .expect("mixed generation")
            .field(),
        ConfigField::ResourceMaterialization
    );
}

#[test]
fn ruleset_tags_reject_cache_path_components() {
    for tag in [".", ".."] {
        let source = CLIENT_V2.replacen("tag = \"ads\"", &format!("tag = \"{tag}\""), 1);
        let file = TempConfig::new(&source);
        assert_eq!(
            prepare_client_v2(&file.0).unwrap_err().field(),
            ConfigField::RouteRuleSetTag
        );
    }
}

#[test]
fn dependency_only_ruleset_detours_and_resolvers_are_reachability_roots() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "fallback"
type = "direct"

[[outbounds]]
tag = "download-hop"
type = "shadowsocks"
server = "edge.example.test:8388"
domain_resolver = "bootstrap"

[[outbounds]]
tag = "download-exit"
type = "shadowsocks"
server = "192.0.2.99:8388"

[[chains]]
tag = "download-chain"
hops = ["download-hop", "download-exit"]

[route]
final = "fallback"

[[route.rule_set]]
tag = "download-only"
type = "remote"
url = "https://rules.example.test/download-only.srs"
download_resolver = "bootstrap"
download_detour = "download-chain"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "final-dns"
transport = "udp"
address = "192.0.2.1:53"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "192.0.2.2:53"

[dns.route]
final = "final-dns"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_client_v2(&file.0).expect("dependency-only roots prepare");
    assert_eq!(
        prepared.accepts_domain_target(PreparedEgressRef::Chain(0)),
        Some(true)
    );
    assert_eq!(
        prepared
            .download_detour_plan(0)
            .expect("dependency-only RuleSet detour")
            .snapshot()
            .hops(),
        &[1, 2]
    );
    assert_eq!(prepared.download_detour_is_direct(0), Some(false));
    let config = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.20:8388".parse().unwrap(),
            )],
            vec![CompiledRuleSetResource::new(
                0,
                exact_match_set("download-only.example"),
                1,
            )],
        ),
    )
    .expect("dependency-only roots finish");
    assert_eq!(
        config.outbounds[1].server(),
        Some("198.51.100.20:8388".parse().unwrap())
    );

    let cycle_source = source.replace(
        "address = \"192.0.2.2:53\"",
        concat!(
            "address = \"bootstrap.example.test:53\"\n",
            "domain_resolver = \"system\"\n",
            "detour = \"download-chain\"",
        ),
    );
    let file = TempConfig::new(&cycle_source);
    let materializer = CountingMaterializer::new(false);
    let error = match prepare_client(&file.0) {
        Ok(prepared) => match block_on(materialize_client_v2(prepared, &materializer)) {
            Ok(_) => panic!("dependency cycle reached materialization"),
            Err(error) => error,
        },
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::DnsDependencyCycle);
    assert_eq!(materializer.calls(), 0);
}

#[test]
fn old_v2_finishes_without_a_registry_or_resources() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_client_v2(&file.0).expect("prepare old V2");
    let config = finish_client_v2(prepared, ClientV2Resources::default()).expect("finish old V2");
    assert!(
        config
            .route_program
            .as_ref()
            .unwrap()
            .rule_registry()
            .is_none()
    );
    let target = TargetAddr::domain("ordinary.example", 443).unwrap();
    let mut evaluation = config
        .route_program
        .as_ref()
        .unwrap()
        .evaluate(0, Network::Tcp, &target);
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(RouteAction::Route(_)))
    ));
}

#[test]
fn tracked_dns_ruleset_example_prepares_closed_query_and_response_blueprint() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/client-v2-dns-rulesets.toml");
    let prepared = prepare_client_v2(&example).expect("prepare tracked DNS RuleSet example");
    let config = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![],
            vec![ResolvedOutboundEndpoint::new(
                2,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            vec![
                CompiledRuleSetResource::new(0, suffix_match_set("ads.invalid"), 23),
                CompiledRuleSetResource::new(1, suffix_match_set("ai.invalid"), 23),
                CompiledRuleSetResource::new(2, suffix_match_set("cn.invalid"), 23),
                CompiledRuleSetResource::new(
                    3,
                    ip_match_set(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
                    23,
                ),
            ],
        ),
    )
    .expect("finish tracked DNS RuleSet example");
    let binding = config
        .dns_route
        .as_ref()
        .and_then(|route| route.policy_blueprint())
        .expect("tracked example policy");
    let registry = binding.registry();
    assert_eq!(registry.generation(), 23);
    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 5);
    assert_eq!(blueprint.response_rule_count(), 1);
    assert_eq!(
        blueprint.rules()[0].action(),
        DnsPolicyActionDescriptor::Reject
    );
    assert_eq!(blueprint.rules()[0].matcher().rule_sets()[0].raw(), 0);
    for (index, server) in [(2, 1), (3, 0), (4, 0)] {
        assert_eq!(
            blueprint.rules()[index].action(),
            DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
                server,
                DnsPolicyAddressStrategy::Ipv4Only,
            ))
        );
    }
    assert_eq!(blueprint.rules()[4].matcher().rule_sets()[0].raw(), 3);
    assert!(
        registry
            .snapshot()
            .rule_set(ferrum2_rule::RuleSetId::from_raw(3))
            .expect("CNIP descriptor")
            .capabilities()
            .ip_cidr
    );
    assert_eq!(
        blueprint.final_route(),
        ferrum2_rule::DnsPolicyRouteDescriptor::new(1, DnsPolicyAddressStrategy::Ipv4Only,)
    );
}

#[test]
fn response_dependent_ruleset_reject_is_closed_and_field_specific() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client_v2(&file.0).expect("prepare response reject case");
    let resources = ClientV2Resources::new(
        vec![ResolvedDnsEndpoint::new(
            1,
            "[2001:db8::53]:443".parse().unwrap(),
        )],
        vec![ResolvedOutboundEndpoint::new(
            1,
            "198.51.100.10:8388".parse().unwrap(),
        )],
        vec![CompiledRuleSetResource::new(
            0,
            ip_match_set(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            7,
        )],
    );
    let error = match finish_client_v2(prepared, resources) {
        Ok(_) => panic!("IP RuleSet reject was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::DnsRouteRulesAction);
    assert!(!format!("{error:?} {error}").contains("blocked"));
}
