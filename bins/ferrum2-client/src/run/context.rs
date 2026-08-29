use std::sync::Arc;

use ferrum2_config::RuntimeConfig;
use ferrum2_dns::DnsProxy;
use ferrum2_observability::Metrics;
use ferrum2_runtime::OwnerRegistry;
use ferrum2_socks5::Socks5Inbound;
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::StructuralLocal;

#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;

use super::egress::{ClientEgressEngine, ClientOutboundContext};

pub(super) struct ClientRouting {
    pub(super) program: ferrum2_config::CompiledRoute,
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
    pub(super) selector: ferrum2_rule::SelectorControl,
}

pub(super) struct ClientContext {
    pub(super) inbound: Socks5Inbound,
    pub(super) egress: Arc<ClientEgressEngine>,
    #[cfg(test)]
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
    pub(super) runtime: RuntimeConfig,
    pub(super) public_udp_slots: Option<Arc<tokio::sync::Semaphore>>,
    pub(super) registry: OwnerRegistry,
    pub(super) metrics: Arc<Metrics>,
    #[cfg(feature = "structural-metrics")]
    pub(super) structural: StructuralLocal,
    pub(super) dns: Option<Arc<std::sync::OnceLock<Arc<DnsProxy>>>>,
}
