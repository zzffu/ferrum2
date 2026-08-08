use std::sync::Arc;

#[cfg(test)]
use std::net::SocketAddrV4;

use ferrum2_config::RuntimeConfig;
use ferrum2_dns::DnsProxy;
use ferrum2_observability::Metrics;
use ferrum2_runtime::OwnerRegistry;
use ferrum2_socks5::Socks5Inbound;

#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;

use super::egress::{ClientEgressEngine, ClientOutboundContext};

pub(super) struct ClientRouting {
    pub(super) legacy: ferrum2_core::route::RouteTable,
    pub(super) program: Option<ferrum2_config::CompiledRoute>,
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
}

pub(super) struct ClientContext {
    pub(super) inbound: Socks5Inbound,
    pub(super) egress: Arc<ClientEgressEngine>,
    #[cfg(test)]
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
    pub(super) runtime: RuntimeConfig,
    pub(super) udp_associate_enabled: bool,
    pub(super) registry: OwnerRegistry,
    pub(super) metrics: Arc<Metrics>,
    pub(super) dns: Option<Arc<std::sync::OnceLock<Arc<DnsProxy>>>>,
    #[cfg(test)]
    pub(super) test_udp_server: SocketAddrV4,
}
