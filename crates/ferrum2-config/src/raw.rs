use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;
use serde::de::{Deserializer, Visitor};
use zeroize::Zeroizing;

use crate::{
    DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_DNS_MAX_INFLIGHT, DEFAULT_DNS_TIMEOUT_MS,
    DEFAULT_HANDSHAKE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_LISTEN_BACKLOG,
    DEFAULT_MAX_CONNECTIONS, DEFAULT_REPLAY_CAPACITY, DEFAULT_ROUTE_SNIFF_MAX_BYTES,
    DEFAULT_ROUTE_SNIFF_TIMEOUT_MS, DEFAULT_SHUTDOWN_GRACE_MS, DEFAULT_TUN_MAX_TCP_FLOWS,
    DEFAULT_TUN_MAX_UDP_MAPPINGS, DEFAULT_TUN_MTU, DEFAULT_TUN_READY_TIMEOUT_MS,
    DEFAULT_TUN_RING_CAPACITY, DEFAULT_TUN_TCP_BUFFER_BYTES, DEFAULT_UDP_IDLE_TIMEOUT_MS,
    DEFAULT_UDP_MAX_BUFFERED_BYTES, DEFAULT_UDP_MAX_SESSIONS,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawClientRoot {
    pub(super) schema_version: u32,
    pub(super) inbounds: Option<Vec<RawClientInbound>>,
    pub(super) outbounds: Option<Vec<RawClientOutbound>>,
    pub(super) chains: Option<Vec<RawChain>>,
    pub(super) selectors: Option<Vec<RawSelector>>,
    pub(super) route: Option<RawRoute>,
    pub(super) dns: Option<RawDns>,
    pub(super) rule_set_loader: Option<RawRuleSetLoader>,
    pub(super) tun: Option<RawTun>,
    pub(super) shadowsocks: Option<RawShadowsocks>,
    #[serde(default)]
    pub(super) runtime: RawRuntime,
    pub(super) udp: Option<RawUdp>,
    #[serde(default)]
    pub(super) logging: RawLogging,
    pub(super) metrics: Option<RawMetrics>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawServerRoot {
    pub(super) schema_version: u32,
    pub(super) inbounds: Option<Vec<RawServerInbound>>,
    pub(super) outbounds: Option<Vec<RawServerOutbound>>,
    pub(super) chains: Option<Vec<RawChain>>,
    pub(super) selectors: Option<Vec<RawSelector>>,
    pub(super) route: Option<RawRoute>,
    pub(super) dns: Option<RawDns>,
    pub(super) rule_set_loader: Option<RawRuleSetLoader>,
    pub(super) tun: Option<RawTun>,
    pub(super) shadowsocks: RawShadowsocks,
    #[serde(default)]
    pub(super) runtime: RawRuntime,
    #[serde(default)]
    pub(super) replay: RawReplay,
    #[serde(default)]
    pub(super) udp: RawUdp,
    #[serde(default)]
    pub(super) logging: RawLogging,
    pub(super) metrics: Option<RawMetrics>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTun {
    pub(super) tag: String,
    pub(super) adapter_name: String,
    pub(super) ipv4_address: Option<String>,
    pub(super) ipv6_address: Option<String>,
    pub(super) outbound: Option<String>,
    #[serde(default)]
    pub(super) auto_route: bool,
    #[serde(default)]
    pub(super) strict_route: bool,
    pub(super) route_address: Option<Vec<String>>,
    pub(super) route_exclude_address: Option<Vec<String>>,
    #[serde(default)]
    pub(super) auto_dns: bool,
    pub(super) ipv4_dns_address: Option<String>,
    pub(super) ipv6_dns_address: Option<String>,
    #[serde(default = "default_tun_mtu")]
    pub(super) mtu: u64,
    #[serde(default = "default_tun_ring_capacity")]
    pub(super) ring_capacity: u64,
    #[serde(default = "default_tun_ready_timeout_ms")]
    pub(super) ready_timeout_ms: u64,
    #[serde(default = "default_tun_max_tcp_flows")]
    pub(super) max_tcp_flows: u64,
    #[serde(default = "default_tun_tcp_buffer_bytes")]
    pub(super) tcp_buffer_bytes: u64,
    #[serde(default = "default_tun_max_udp_mappings")]
    pub(super) max_udp_mappings: u64,
    #[serde(default = "default_tun_udp_filtering")]
    pub(super) udp_filtering: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawUdp {
    #[serde(default = "default_udp_enabled")]
    pub(super) enabled: bool,
    #[serde(default = "default_udp_max_sessions")]
    pub(super) max_sessions: usize,
    #[serde(default = "default_udp_max_buffered_bytes")]
    pub(super) max_buffered_bytes: usize,
    #[serde(default = "default_udp_idle_timeout_ms")]
    pub(super) idle_timeout_ms: u64,
}

impl Default for RawUdp {
    fn default() -> Self {
        Self {
            enabled: default_udp_enabled(),
            max_sessions: default_udp_max_sessions(),
            max_buffered_bytes: default_udp_max_buffered_bytes(),
            idle_timeout_ms: default_udp_idle_timeout_ms(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawClientInbound {
    pub(super) tag: String,
    pub(super) listen: String,
    pub(super) outbound: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawClientOutbound {
    pub(super) tag: String,
    #[serde(rename = "type")]
    pub(super) outbound_type: Option<String>,
    pub(super) server: Option<String>,
    pub(super) method: Option<String>,
    pub(super) psk: Option<SecretString>,
    pub(super) domain_resolver: Option<String>,
    pub(super) domain_strategy: Option<String>,
    pub(super) bind_interface: Option<String>,
    pub(super) inet4_bind_address: Option<String>,
    pub(super) inet6_bind_address: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawChain {
    pub(super) tag: Option<String>,
    pub(super) hops: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawServerInbound {
    pub(super) tag: String,
    pub(super) listen: String,
    pub(super) outbound: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawServerOutbound {
    pub(super) tag: String,
    pub(super) domain_resolver: Option<String>,
    pub(super) domain_strategy: Option<String>,
    pub(super) bind_interface: Option<String>,
    pub(super) inet4_bind_address: Option<String>,
    pub(super) inet6_bind_address: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSelector {
    pub(super) tag: String,
    #[serde(default)]
    pub(super) outbounds: Vec<String>,
    pub(super) default: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRoute {
    #[serde(default)]
    pub(super) auto_detect_interface: bool,
    pub(super) default_interface: Option<String>,
    #[serde(rename = "final")]
    pub(super) final_outbound: Option<String>,
    pub(super) sniff: Option<RawRouteSniff>,
    #[serde(default)]
    pub(super) rules: Vec<RawRouteRule>,
    #[serde(default)]
    pub(super) rule_set: Vec<RawRuleSet>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRuleSet {
    pub(super) tag: Option<String>,
    #[serde(rename = "type")]
    pub(super) rule_set_type: Option<String>,
    pub(super) format: Option<String>,
    pub(super) url: Option<String>,
    pub(super) download_resolver: Option<String>,
    pub(super) download_detour: Option<String>,
    pub(super) update_interval_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRuleSetLoader {
    pub(super) cache_dir: Option<PathBuf>,
    pub(super) download_timeout_ms: Option<u64>,
    pub(super) max_redirects: Option<u8>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRouteRule {
    pub(super) inbound: Option<ScalarOrList<String>>,
    pub(super) network: Option<ScalarOrList<String>>,
    pub(super) protocol: Option<ScalarOrList<String>>,
    pub(super) domain: Option<ScalarOrList<String>>,
    pub(super) domain_suffix: Option<ScalarOrList<String>>,
    pub(super) domain_keyword: Option<ScalarOrList<String>>,
    pub(super) rule_set: Option<ScalarOrList<String>>,
    pub(super) ip: Option<ScalarOrList<String>>,
    pub(super) ip_cidr: Option<ScalarOrList<String>>,
    pub(super) port: Option<ScalarOrList<i64>>,
    pub(super) port_range: Option<ScalarOrList<String>>,
    pub(super) action: Option<String>,
    pub(super) sniffers: Option<ScalarOrList<String>>,
    pub(super) outbound: Option<String>,
    pub(super) server: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRouteSniff {
    #[serde(default = "default_route_sniff_timeout_ms")]
    pub(super) timeout_ms: u64,
    #[serde(default = "default_route_sniff_max_bytes")]
    pub(super) max_bytes: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDns {
    #[serde(default = "default_dns_timeout_ms")]
    pub(super) timeout_ms: u64,
    #[serde(default = "default_dns_max_inflight")]
    pub(super) max_inflight: u32,
    pub(super) strategy: Option<String>,
    pub(super) cache: Option<RawDnsCache>,
    pub(super) inbounds: Option<Vec<RawDnsInbound>>,
    pub(super) servers: Option<Vec<RawDnsServer>>,
    pub(super) route: Option<RawDnsRoute>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDnsCache {
    #[serde(default = "default_dns_cache_enabled")]
    pub(super) enabled: bool,
    #[serde(default = "default_dns_cache_max_entries")]
    pub(super) max_entries: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDnsInbound {
    pub(super) tag: String,
    pub(super) listen: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDnsServer {
    pub(super) tag: String,
    pub(super) transport: String,
    pub(super) address: String,
    pub(super) server_name: Option<String>,
    pub(super) path: Option<String>,
    pub(super) detour: Option<String>,
    pub(super) domain_resolver: Option<String>,
    pub(super) domain_strategy: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDnsRoute {
    #[serde(rename = "final")]
    pub(super) final_server: Option<String>,
    #[serde(default)]
    pub(super) rules: Vec<RawDnsRouteRule>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDnsRouteRule {
    pub(super) inbound: Option<ScalarOrList<String>>,
    pub(super) network: Option<ScalarOrList<String>>,
    pub(super) qname: Option<ScalarOrList<String>>,
    pub(super) qname_suffix: Option<ScalarOrList<String>>,
    pub(super) qtype: Option<ScalarOrList<String>>,
    pub(super) domain: Option<ScalarOrList<String>>,
    pub(super) domain_suffix: Option<ScalarOrList<String>>,
    pub(super) domain_keyword: Option<ScalarOrList<String>>,
    pub(super) rule_set: Option<ScalarOrList<String>>,
    pub(super) port: Option<ScalarOrList<i64>>,
    pub(super) port_range: Option<ScalarOrList<String>>,
    pub(super) server: Option<String>,
    pub(super) outbound: Option<String>,
    pub(super) action: Option<String>,
    pub(super) strategy: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum ScalarOrList<T> {
    Scalar(T),
    List(Vec<T>),
}

impl<T> ScalarOrList<T> {
    pub fn len(&self) -> usize {
        match self {
            Self::Scalar(_) => 1,
            Self::List(values) => values.len(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        match self {
            Self::Scalar(value) => std::slice::from_ref(value).iter(),
            Self::List(values) => values.iter(),
        }
    }

    pub fn scalar(&self) -> Option<&T> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::List(_) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawShadowsocks {
    pub(super) method: String,
    pub(super) psk: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRuntime {
    #[serde(default = "default_max_connections")]
    pub(super) max_connections: u32,
    #[serde(default = "default_listen_backlog")]
    pub(super) listen_backlog: u32,
    #[serde(default = "default_handshake_timeout_ms")]
    pub(super) handshake_timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub(super) connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub(super) idle_timeout_ms: u64,
    #[serde(default = "default_shutdown_grace_ms")]
    pub(super) shutdown_grace_ms: u64,
}

impl Default for RawRuntime {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            listen_backlog: default_listen_backlog(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            connect_timeout_ms: default_connect_timeout_ms(),
            idle_timeout_ms: default_idle_timeout_ms(),
            shutdown_grace_ms: default_shutdown_grace_ms(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawReplay {
    #[serde(default = "default_replay_capacity")]
    pub(super) capacity: usize,
}

impl Default for RawReplay {
    fn default() -> Self {
        Self {
            capacity: default_replay_capacity(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawLogging {
    #[serde(default = "default_logging_level")]
    pub(super) level: String,
}

impl Default for RawLogging {
    fn default() -> Self {
        Self {
            level: default_logging_level(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMetrics {
    pub(super) listen: String,
}

pub(super) struct SecretString(pub(super) Zeroizing<String>);

impl SecretString {
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretVisitor;

        impl Visitor<'_> for SecretVisitor {
            type Value = SecretString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64 secret string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretString(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretString(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

const fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

const fn default_listen_backlog() -> u32 {
    DEFAULT_LISTEN_BACKLOG
}

const fn default_handshake_timeout_ms() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_MS
}

const fn default_connect_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}

const fn default_idle_timeout_ms() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

const fn default_shutdown_grace_ms() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_MS
}

const fn default_replay_capacity() -> usize {
    DEFAULT_REPLAY_CAPACITY
}

const fn default_udp_enabled() -> bool {
    true
}

const fn default_udp_max_sessions() -> usize {
    DEFAULT_UDP_MAX_SESSIONS
}

const fn default_udp_max_buffered_bytes() -> usize {
    DEFAULT_UDP_MAX_BUFFERED_BYTES
}

const fn default_udp_idle_timeout_ms() -> u64 {
    DEFAULT_UDP_IDLE_TIMEOUT_MS
}

const fn default_dns_timeout_ms() -> u64 {
    DEFAULT_DNS_TIMEOUT_MS
}

const fn default_dns_max_inflight() -> u32 {
    DEFAULT_DNS_MAX_INFLIGHT
}

const fn default_dns_cache_enabled() -> bool {
    true
}

const fn default_dns_cache_max_entries() -> usize {
    8_192
}

const fn default_route_sniff_timeout_ms() -> u64 {
    DEFAULT_ROUTE_SNIFF_TIMEOUT_MS
}

const fn default_route_sniff_max_bytes() -> usize {
    DEFAULT_ROUTE_SNIFF_MAX_BYTES
}

const fn default_tun_mtu() -> u64 {
    DEFAULT_TUN_MTU
}

const fn default_tun_ring_capacity() -> u64 {
    DEFAULT_TUN_RING_CAPACITY
}

const fn default_tun_ready_timeout_ms() -> u64 {
    DEFAULT_TUN_READY_TIMEOUT_MS
}

const fn default_tun_max_tcp_flows() -> u64 {
    DEFAULT_TUN_MAX_TCP_FLOWS
}

const fn default_tun_tcp_buffer_bytes() -> u64 {
    DEFAULT_TUN_TCP_BUFFER_BYTES
}

const fn default_tun_max_udp_mappings() -> u64 {
    DEFAULT_TUN_MAX_UDP_MAPPINGS
}

fn default_tun_udp_filtering() -> String {
    "endpoint_independent".to_owned()
}

fn default_logging_level() -> String {
    "info".to_owned()
}
