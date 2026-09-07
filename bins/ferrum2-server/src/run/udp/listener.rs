use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use ferrum2_crypto::SystemClock;
use ferrum2_observability::{Direction, Metrics, Outcome, Role};
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpRuntime, UdpSessionHandle,
};
use ferrum2_shadowsocks::UdpServer;
use tokio::net::UdpSocket;

use crate::run::dns_egress;

use super::identity::UdpMappings;
use super::response_codec::{ResponseCodecPool, ResponseEncodeError};

#[derive(Clone, Copy)]
pub(super) enum UdpAdapterError {
    Mapping,
    Protocol(ferrum2_shadowsocks::UdpPacketError),
    Runtime(ferrum2_runtime::UdpRuntimeError),
    Send,
}

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
            .ok_or(UdpAdapterError::Mapping)?;
        let encoded = loop {
            let returned = self.codec.returned.notified();
            match self.codec.try_encode(
                &self.protocol,
                capability,
                self.clock.as_ref(),
                &ferrum2_crypto::SystemRandom,
                response.datagram(),
            ) {
                Ok(Some(encoded)) => break encoded,
                Ok(None) => returned.await,
                Err(ResponseEncodeError::Protocol(error)) => {
                    return Err(UdpAdapterError::Protocol(error));
                }
                Err(ResponseEncodeError::Runtime(error)) => {
                    return Err(UdpAdapterError::Runtime(error));
                }
            }
        };
        drop(response);
        self.codec.notify_capacity_change();
        let wire_len = encoded.wire_len;
        self.listener
            .send_to(encoded.wire.wire(wire_len), encoded.peer)
            .await
            .map_err(|_| UdpAdapterError::Send)?;
        self.metrics
            .udp_datagram(Role::Server, Direction::TargetToClient, Outcome::Completed);
        self.metrics
            .add_udp_bytes(Role::Server, Direction::TargetToClient, wire_len as u64);
        Ok(())
    }
}

pub(super) type ServerUdpRuntime<L, F> =
    DirectUdpRuntime<dns_egress::ServerDnsResolver, F, ServerUdpResponseHandler<L>>;
