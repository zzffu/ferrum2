mod tcp;
mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, MethodSinglePskProvider, SecureRandom};
use ferrum2_shadowsocks::{BoxedClientFlow, MethodKeyAdapter, ShadowsocksError, TransportIo};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};

use super::RunError;
use super::tokio_io::TokioConnector;

pub(super) use udp::{
    ClientUdpAssociation, ClientUdpContext, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
#[cfg(test)]
pub(super) use udp::{
    IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, UdpIoOperation,
    composed_udp_request_limit, composed_udp_response_limit,
};

pub(super) struct ClientOutboundContext {
    pub(super) tcp_server: TargetAddr,
    pub(super) udp_server: SocketAddr,
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
}

pub(super) fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
) -> Result<Arc<[ClientOutboundContext]>, RunError> {
    if outbounds.is_empty() {
        return Err(RunError::StartupProtocol);
    }
    if outbounds
        .iter()
        .any(|outbound| matches!(outbound, ferrum2_config::ClientOutboundConfig::Direct))
    {
        return Err(RunError::StartupDirectUnsupported);
    }
    outbounds
        .into_iter()
        .map(|outbound| {
            let ferrum2_config::ClientOutboundConfig::Shadowsocks { server, psk } = outbound else {
                unreachable!("direct outbounds were rejected before protocol preparation")
            };
            Ok(ClientOutboundContext {
                tcp_server: TargetAddr::ip(server).map_err(|_| RunError::StartupProtocol)?,
                udp_server: server,
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk)),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Arc::from)
}

pub(super) struct ClientEgressEngine<
    C = TokioConnector<ferrum2_runtime::TcpConnector>,
    T = ferrum2_crypto::SystemClock,
    R = ferrum2_crypto::SystemRandom,
> {
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
    connector: C,
    pub(super) clock: T,
    pub(super) random: R,
    phase_deadlines: (Duration, Duration),
    pub(super) udp: Option<ClientUdpContext>,
    #[cfg(test)]
    pub(super) udp_id_random: Option<Arc<dyn SecureRandom>>,
}

impl<C, T, R> ClientEgressEngine<C, T, R> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        Self {
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            #[cfg(test)]
            udp_id_random,
        }
    }

    pub(super) async fn open_tcp<'a>(
        &'a self,
        plan: EgressPlanSnapshot,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<BoxedClientFlow<'a>, ClientOpenFailure>
    where
        C: Connector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        let deadlines = timeout_limit.map_or(self.phase_deadlines, |limit| {
            (
                limit.min(self.phase_deadlines.0),
                limit.min(self.phase_deadlines.1),
            )
        });
        tcp::open(
            &self.outbounds,
            plan.hops(),
            &self.connector,
            &self.clock,
            &self.random,
            application_target,
            deadlines,
            #[cfg(test)]
            observers,
        )
        .await
    }
}

impl ClientEgressEngine {
    pub(super) async fn prepare_udp<A, F, Fut>(
        &self,
        plan: EgressPlanSnapshot,
        first_server: A,
        bind: F,
    ) -> Result<ClientUdpAssociation, ()>
    where
        A: Into<SocketAddr>,
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        udp::prepare(self, plan, first_server.into(), bind).await
    }
}

#[derive(Debug)]
pub(super) enum ClientOpenFailure {
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}

#[cfg(test)]
mod m16_tests {
    use super::*;

    fn proxy() -> ferrum2_config::ClientOutboundConfig {
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "127.0.0.1:8388".parse().unwrap(),
            psk: ferrum2_crypto::MethodPsk::aes128([0; 16]),
        }
    }

    #[test]
    fn m16_direct_pre_socket_rejects_empty_mixed_and_multi_direct_plans() {
        assert_eq!(
            prepare_client_outbounds(Vec::new()).err().unwrap(),
            RunError::StartupProtocol
        );
        for outbounds in [
            vec![ferrum2_config::ClientOutboundConfig::Direct],
            vec![proxy(), ferrum2_config::ClientOutboundConfig::Direct],
            vec![
                ferrum2_config::ClientOutboundConfig::Direct,
                ferrum2_config::ClientOutboundConfig::Direct,
            ],
        ] {
            let error = prepare_client_outbounds(outbounds).err().unwrap();
            assert_eq!(error, RunError::StartupDirectUnsupported);
            assert_eq!(
                error.to_string(),
                "error[startup.direct_unsupported] process: direct execution is not available"
            );
        }
    }
}
