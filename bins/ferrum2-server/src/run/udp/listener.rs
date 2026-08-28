use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use ferrum2_crypto::SystemClock;
use ferrum2_observability::{Direction, Metrics, Outcome, Reason, Role, Stage};
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpRuntime, UdpSessionHandle,
};
use ferrum2_shadowsocks::UdpServer;
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
    pub(super) codec: Arc<ResponseCodecPool>,
    pub(super) metrics: Arc<Metrics>,
}

impl<L> DirectUdpPacketHandler for ServerUdpResponseHandler<L>
where
    L: ServerUdpListener,
{
    type Error = UdpAdapterError;

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
        let encoded = match self
            .codec
            .encode(
                &self.protocol,
                capability,
                self.clock.as_ref(),
                response.datagram(),
            )
            .await
        {
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
}

pub(super) type ServerUdpRuntime<L, F> =
    DirectUdpRuntime<dns_egress::ServerDnsResolver, F, ServerUdpResponseHandler<L>>;
