mod tcp;
mod udp;

use std::net::SocketAddrV4;
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
    pub(super) udp_server: SocketAddrV4,
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
}

pub(super) fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
    psks: Vec<ferrum2_crypto::MethodPsk>,
) -> Result<Arc<[ClientOutboundContext]>, RunError> {
    if outbounds.len() != psks.len() {
        return Err(RunError::StartupProtocol);
    }
    outbounds
        .into_iter()
        .zip(psks)
        .map(|(outbound, psk)| {
            Ok(ClientOutboundContext {
                tcp_server: TargetAddr::ipv4(outbound.server)
                    .map_err(|_| RunError::StartupProtocol)?,
                udp_server: outbound.server,
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
    pub(super) async fn prepare_udp<F, Fut>(
        &self,
        local_ip: std::net::Ipv4Addr,
        static_plan: Option<(EgressPlanSnapshot, SocketAddrV4)>,
        bind: F,
    ) -> Result<ClientUdpAssociation, ()>
    where
        F: FnMut(SocketAddrV4) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        udp::prepare(self, local_ip, static_plan, bind).await
    }
}

#[derive(Debug)]
pub(super) enum ClientOpenFailure {
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}
