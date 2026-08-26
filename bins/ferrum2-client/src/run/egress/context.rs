use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_crypto::MethodSinglePskProvider;
use ferrum2_net::{DialOptions, RouteNetworkOptions};
use ferrum2_shadowsocks::MethodKeyAdapter;

use crate::run::RunError;

pub(in crate::run) enum ClientOutboundContext {
    Shadowsocks(ClientShadowsocksContext),
    Direct { dial_options: DialOptions },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run) enum ClientRequestOrigin {
    Socks,
    Tun,
    Dns,
    RuleSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelectedEgress {
    Direct {
        outbound: Option<usize>,
    },
    Shadowsocks {
        first_outbound: usize,
        first_server: SocketAddr,
    },
}

pub(in crate::run) struct ClientShadowsocksContext {
    pub(in crate::run) tcp_server: TargetAddr,
    pub(in crate::run) udp_server: SocketAddr,
    pub(in crate::run) keys: MethodKeyAdapter<MethodSinglePskProvider>,
    pub(in crate::run) dial_options: DialOptions,
}

impl ClientOutboundContext {
    pub(in crate::run) fn direct(dial_options: DialOptions) -> Self {
        Self::Direct { dial_options }
    }

    pub(in crate::run) fn shadowsocks(&self) -> Option<&ClientShadowsocksContext> {
        match self {
            Self::Shadowsocks(outbound) => Some(outbound),
            Self::Direct { .. } => None,
        }
    }

    pub(in crate::run) fn dial_options(&self) -> &DialOptions {
        match self {
            Self::Shadowsocks(outbound) => &outbound.dial_options,
            Self::Direct { dial_options } => dial_options,
        }
    }
}

pub(in crate::run) fn runtime_dial_options(
    options: &ferrum2_config::OutboundDialOptions,
) -> DialOptions {
    DialOptions::new(
        options.bind_interface(),
        options.inet4_bind_address(),
        options.inet6_bind_address(),
    )
}

pub(in crate::run) fn runtime_route_network(
    route: &ferrum2_config::RouteNetworkConfig,
) -> RouteNetworkOptions {
    RouteNetworkOptions::new(route.auto_detect_interface, route.default_interface())
}

pub(in crate::run) fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
) -> Result<Arc<[ClientOutboundContext]>, RunError> {
    if outbounds.is_empty() {
        return Err(RunError::StartupProtocol);
    }
    outbounds
        .into_iter()
        .map(|outbound| {
            Ok(match outbound {
                ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server,
                    psk,
                    dial_options,
                } => ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                    tcp_server: TargetAddr::ip(server).map_err(|_| RunError::StartupProtocol)?,
                    udp_server: server,
                    keys: MethodKeyAdapter::new(MethodSinglePskProvider::from_shared(psk)),
                    dial_options: runtime_dial_options(&dial_options),
                }),
                ferrum2_config::ClientOutboundConfig::Direct { dial_options, .. } => {
                    ClientOutboundContext::direct(runtime_dial_options(&dial_options))
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Arc::from)
}
