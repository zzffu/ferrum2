pub(super) use std::fs;
pub(super) use std::net::{IpAddr, Ipv4Addr};
pub(super) use std::path::PathBuf;
pub(super) use std::sync::Arc;
pub(super) use std::sync::atomic::{AtomicU64, Ordering};
pub(super) use std::time::Duration;

pub(super) use ferrum2_config::{
    ClientV2Resources, CompiledRuleSetResource, ConfigError, ConfigErrorKind, ConfigField,
    DialEndpoint, DirectDomainResolver, DnsEndpointMode, DnsIngressId, DnsStrategy,
    PreparedClientOutboundKind, PreparedDependencyNode, PreparedDnsAction, PreparedDnsEndpointMode,
    PreparedEgressRef, PreparedFixedEndpointTarget, PreparedRuleSetDownloadMode,
    ResolvedDnsEndpoint, ResolvedOutboundEndpoint, ResolverRef, RouteAction, ServerV2Resources,
    finish_client_v2, finish_server_v2, prepare_client, prepare_server,
};
pub(super) use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr};
pub(super) use ferrum2_rule::{
    CompiledMatchSet, DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, MatchSetBuilder,
    Network, RouteMetadata, RouteProgramAction, RuleEngineRegistry, RuleEngineSnapshotBuilder,
};

pub(super) static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

pub(super) struct TempConfig(pub(super) PathBuf);

impl TempConfig {
    pub(super) fn new(contents: &str) -> Self {
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

pub(super) const CLIENT_V2: &str = r#"
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
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
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

"#;

pub(super) const SERVER_V2: &str = r#"
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

pub(super) const CLIENT_V2_MINIMAL: &str = r#"
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

pub(super) fn exact_match_set(value: &str) -> Arc<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder.add_exact_domain(value).unwrap();
    Arc::new(builder.build().unwrap())
}

pub(super) fn suffix_match_set(value: &str) -> Arc<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder.add_domain_suffix(value).unwrap();
    Arc::new(builder.build().unwrap())
}

pub(super) fn ip_match_set(address: IpAddr) -> Arc<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder.add_ip(address).unwrap();
    Arc::new(builder.build().unwrap())
}

pub(super) fn compiled_rule_sets(
    generation: u64,
    entries: &[(&str, Arc<CompiledMatchSet>)],
) -> CompiledRuleSetResource {
    let mut builder = RuleEngineSnapshotBuilder::new(generation);
    let mut rule_set_ids = Vec::with_capacity(entries.len());
    for (tag, match_set) in entries {
        let match_set = builder
            .add_shared_match_set(Arc::clone(match_set))
            .expect("add test match set");
        rule_set_ids.push(
            builder
                .add_rule_set(tag, match_set)
                .expect("add test RuleSet"),
        );
    }
    CompiledRuleSetResource::new(
        Arc::new(RuleEngineRegistry::new(
            builder.build().expect("build test RuleSet registry"),
        )),
        rule_set_ids.into_boxed_slice(),
    )
}

pub(super) fn valid_client_resources() -> ClientV2Resources {
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
        Some(compiled_rule_sets(
            7,
            &[("ads", exact_match_set("blocked.example"))],
        )),
    )
}

pub(super) fn assert_config_syntax_error<T>(result: Result<T, ConfigError>) {
    let error = match result {
        Ok(_) => panic!("removed root shape produced a configuration"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ConfigErrorKind::Syntax);
    assert_eq!(error.field(), ConfigField::Config);
}
