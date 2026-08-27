use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_net::{DialOptions, RouteNetworkOptions};
use ferrum2_observability::Metrics;
use ferrum2_runtime::DirectUdpSocketFactory;
#[cfg(any(windows, test))]
use ferrum2_runtime::GenerationBoundUdpSocket;
#[cfg(any(not(windows), test))]
use ferrum2_runtime::{SystemDirectUdpSocket, SystemDirectUdpSocketFactory};
#[cfg(any(windows, test))]
use tokio::net::UdpSocket;

use crate::run::network::ServerNetworkSocketService;
#[cfg(any(windows, test))]
use crate::run::network::{
    interface_resolution_result, interface_resolution_source, record_interface_resolution_success,
};
#[derive(Clone)]
pub(in crate::run) struct ServerUdpNetworkPolicy {
    pub(super) outbound: DialOptions,
    pub(super) route: Arc<RouteNetworkOptions>,
}

#[derive(Clone)]
pub(in crate::run) struct ServerNetworkUdpSocketFactory {
    pub(super) sockets: Arc<ServerNetworkSocketService>,
    pub(super) metrics: Arc<Metrics>,
}

#[cfg(any(windows, test))]
pub(super) type ServerPhysicalUdpSocket = GenerationBoundUdpSocket<UdpSocket>;
#[cfg(all(not(windows), not(test)))]
pub(super) type ServerPhysicalUdpSocket = SystemDirectUdpSocket;

impl DirectUdpSocketFactory for ServerNetworkUdpSocketFactory {
    type Socket = ServerPhysicalUdpSocket;
    type OpenContext = Option<ServerUdpNetworkPolicy>;

    async fn open(
        &self,
        policy: Self::OpenContext,
        selection_destination: SocketAddr,
    ) -> io::Result<Self::Socket> {
        let policy = policy.ok_or_else(closed_udp_socket_error)?;
        #[cfg(all(not(windows), not(test)))]
        {
            let _ = (
                &self.sockets,
                &self.metrics,
                &policy.outbound,
                &policy.route,
            );
            SystemDirectUdpSocketFactory
                .open((), selection_destination)
                .await
        }

        #[cfg(any(windows, test))]
        {
            let result = self.sockets.open_udp(
                &policy.outbound,
                policy.route.as_ref(),
                selection_destination,
            );
            match result {
                Ok(socket) => {
                    record_interface_resolution_success(&self.metrics, socket.resolved_interface());
                    Ok(socket)
                }
                Err(error) => {
                    self.metrics.outbound_interface_resolution(
                        interface_resolution_source(error.attempted_source()),
                        interface_resolution_result(&error),
                    );
                    Err(closed_udp_socket_error())
                }
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ServerSystemUdpSocketFactory;

#[cfg(test)]
impl DirectUdpSocketFactory for ServerSystemUdpSocketFactory {
    type Socket = SystemDirectUdpSocket;
    type OpenContext = Option<ServerUdpNetworkPolicy>;

    async fn open(
        &self,
        policy: Self::OpenContext,
        selection_destination: SocketAddr,
    ) -> io::Result<Self::Socket> {
        if policy.is_some() {
            return Err(closed_udp_socket_error());
        }
        SystemDirectUdpSocketFactory
            .open((), selection_destination)
            .await
    }
}

pub(super) fn closed_udp_socket_error() -> io::Error {
    io::Error::other("generation-bound UDP socket unavailable")
}
