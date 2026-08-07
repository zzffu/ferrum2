use super::*;

pub(super) struct ClientRouting {
    pub(super) route: ferrum2_core::route::RouteTable,
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
    #[cfg(test)]
    pub(super) test_udp_server: SocketAddrV4,
}
