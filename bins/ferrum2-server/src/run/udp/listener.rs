use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use ferrum2_crypto::SystemClock;
#[cfg(feature = "candidate-udp-owned-headroom")]
use ferrum2_crypto::SystemRandom;
use ferrum2_observability::{Direction, Metrics, Outcome, Reason, Role, Stage};
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpRuntime, UdpSessionHandle,
};
#[cfg(feature = "candidate-udp-owned-headroom")]
use ferrum2_runtime::{UdpHeadroomLease, UdpHeadroomPacket};
use ferrum2_shadowsocks::UdpServer;
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::StructuralLocal;
use tokio::net::UdpSocket;

use crate::run::dns_egress;
use crate::run::observation::{
    record_udp_failure, record_udp_protocol_failure, record_udp_runtime_failure,
};

use super::identity::UdpMappings;
use super::response_codec::{ResponseCodecPool, ResponseEncodeError};

#[derive(Clone, Copy)]
pub(super) struct UdpAdapterError;

pub(super) const UDP_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);
pub(super) const MAX_UDP_LISTENER_READINESS_DRAIN: usize = 32;

pub(in crate::run) trait ServerUdpListener: Send + Sync + 'static {
    fn recv_buf_from(
        &self,
        destination: &mut BytesMut,
    ) -> impl std::future::Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    fn try_recv_buf_from(&self, _destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    fn send_to(
        &self,
        source: &[u8],
        peer: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

impl ServerUdpListener for UdpSocket {
    async fn recv_buf_from(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_buf_from(self, destination).await
    }

    fn try_recv_buf_from(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::try_recv_buf_from(self, destination)
    }

    async fn send_to(&self, source: &[u8], peer: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, source, peer).await
    }
}

pub(super) struct ServerUdpResponseHandler<L> {
    pub(super) listener: Arc<L>,
    pub(super) protocol: Arc<UdpServer>,
    pub(super) mappings: Arc<UdpMappings>,
    pub(super) clock: Arc<SystemClock>,
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    pub(super) codec: Arc<ResponseCodecPool>,
    #[cfg(feature = "candidate-udp-owned-headroom")]
    pub(super) codec: Option<Arc<ResponseCodecPool>>,
    pub(super) metrics: Arc<Metrics>,
    #[cfg(feature = "structural-metrics")]
    pub(super) structural: StructuralLocal,
}

impl<L> DirectUdpPacketHandler for ServerUdpResponseHandler<L>
where
    L: ServerUdpListener,
{
    type Error = UdpAdapterError;

    #[cfg(feature = "candidate-udp-owned-headroom")]
    const SUPPORTS_UDP_HEADROOM: bool = true;

    async fn handle_target_response(
        &self,
        session: UdpSessionHandle,
        response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        let capability = self
            .mappings
            .capability(session)
            .await
            .ok_or(UdpAdapterError)?;
        #[cfg(feature = "candidate-udp-owned-headroom")]
        let codec = self.codec.as_ref().ok_or(UdpAdapterError)?;
        #[cfg(not(feature = "candidate-udp-owned-headroom"))]
        let codec = &self.codec;
        #[cfg(feature = "structural-metrics")]
        let encoded = codec.encode_structural(
            &self.protocol,
            capability,
            self.clock.as_ref(),
            response.datagram(),
            &self.structural,
        );
        #[cfg(not(feature = "structural-metrics"))]
        let encoded = codec.encode(
            &self.protocol,
            capability,
            self.clock.as_ref(),
            response.datagram(),
        );
        let encoded = match encoded.await {
            Ok(encoded) => encoded,
            Err(ResponseEncodeError::Protocol(error)) => {
                self.mappings.invalidate_handle(session);
                record_udp_protocol_failure(&self.metrics, error);
                return Err(UdpAdapterError);
            }
            Err(ResponseEncodeError::Runtime(error)) => {
                record_udp_runtime_failure(&self.metrics, error);
                return Err(UdpAdapterError);
            }
        };
        drop(response);
        let wire_len = encoded.wire_len;
        self.listener
            .send_to(encoded.wire.wire(wire_len), encoded.peer)
            .await
            .map_err(|_| {
                record_udp_failure(&self.metrics, Stage::Direct, Reason::Send, Outcome::Failed);
                UdpAdapterError
            })?;
        self.metrics
            .udp_datagram(Role::Server, Direction::TargetToClient, Outcome::Completed);
        self.metrics
            .add_udp_bytes(Role::Server, Direction::TargetToClient, wire_len as u64);
        Ok(())
    }

    #[cfg(feature = "candidate-udp-owned-headroom")]
    async fn handle_target_response_headroom(
        &self,
        session: UdpSessionHandle,
        mut response: UdpHeadroomPacket,
    ) -> Result<UdpHeadroomLease, Self::Error> {
        let capability = self
            .mappings
            .capability(session)
            .await
            .ok_or(UdpAdapterError)?;
        #[cfg(feature = "structural-metrics")]
        let encoded = self.protocol.encode_response_owned_headroom_structural(
            capability,
            self.clock.as_ref(),
            &SystemRandom,
            response.datagram_mut().map_err(|error| {
                record_udp_runtime_failure(&self.metrics, error);
                UdpAdapterError
            })?,
            0,
            &self.structural,
        );
        #[cfg(not(feature = "structural-metrics"))]
        let encoded = self.protocol.encode_response_owned_headroom(
            capability,
            self.clock.as_ref(),
            &SystemRandom,
            response.datagram_mut().map_err(|error| {
                record_udp_runtime_failure(&self.metrics, error);
                UdpAdapterError
            })?,
            0,
        );
        let encoded = match encoded {
            Ok(encoded) => encoded,
            Err(error) => {
                self.mappings.invalidate_handle(session);
                record_udp_protocol_failure(&self.metrics, error);
                return Err(UdpAdapterError);
            }
        };
        let wire_range = encoded.wire_range();
        let wire_len = wire_range.len();
        let wire = response.wire(wire_range).map_err(|error| {
            record_udp_runtime_failure(&self.metrics, error);
            UdpAdapterError
        })?;
        self.listener
            .send_to(wire, encoded.peer())
            .await
            .map_err(|_| {
                record_udp_failure(&self.metrics, Stage::Direct, Reason::Send, Outcome::Failed);
                UdpAdapterError
            })?;
        self.metrics
            .udp_datagram(Role::Server, Direction::TargetToClient, Outcome::Completed);
        self.metrics
            .add_udp_bytes(Role::Server, Direction::TargetToClient, wire_len as u64);
        response.recycle().map_err(|error| {
            record_udp_runtime_failure(&self.metrics, error);
            UdpAdapterError
        })
    }
}

pub(super) type ServerUdpRuntime<L, F> =
    DirectUdpRuntime<dns_egress::ServerDnsResolver, F, ServerUdpResponseHandler<L>>;
