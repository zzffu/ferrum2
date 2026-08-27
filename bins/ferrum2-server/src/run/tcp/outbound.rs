use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::RuntimeConfig;
use ferrum2_core::{ConnectError, ConnectErrorKind, TargetAddr, TargetHostRef};
use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_net::{DialOptions, RouteNetworkOptions, TcpResolver as _};
use ferrum2_observability::Metrics;
#[cfg(all(not(windows), not(test)))]
use ferrum2_runtime::RuntimeTcpStream;
use ferrum2_runtime::{MAX_RESOLVED_CANDIDATES, OwnerRegistry};
use ferrum2_shadowsocks::{MethodKeyAdapter, TcpReplayStore};
use tokio::io::AsyncWrite;

use super::prefix::{PrefixFailure, forward_initial_payload};
use crate::run::dns_egress;
#[cfg(all(not(windows), not(test)))]
use crate::run::network::connect_error_kind_from_io;
use crate::run::network::{ServerNetworkSocketService, ServerPhysicalTcpStream};
#[cfg(any(windows, test))]
use crate::run::network::{
    connect_error_from_network_service, interface_resolution_result, interface_resolution_source,
    record_interface_resolution_success,
};
use crate::run::routing::ServerRouting;

#[derive(Debug)]
pub(super) enum DirectFlowError<E> {
    CancelledBeforeOpen,
    Open(E),
    Prefix(PrefixFailure),
}

pub(super) async fn open_and_prefix<O, C>(
    direct: &O,
    target: &TargetAddr,
    initial_payload: &[u8],
    idle_timeout: std::time::Duration,
    cancellation: C,
) -> Result<(O::Stream, u64), DirectFlowError<O::Error>>
where
    O: ferrum2_core::Outbound,
    O::Stream: AsyncWrite + Unpin,
    C: std::future::Future,
{
    tokio::pin!(cancellation);
    let mut stream = tokio::select! {
        _ = cancellation.as_mut() => return Err(DirectFlowError::CancelledBeforeOpen),
        result = direct.open(target) => result.map_err(DirectFlowError::Open)?,
    };
    let bytes = forward_initial_payload(
        &mut stream,
        initial_payload,
        idle_timeout,
        cancellation.as_mut(),
    )
    .await
    .map_err(DirectFlowError::Prefix)?;
    Ok((stream, bytes))
}

pub(in crate::run) struct ServerContext {
    pub(in crate::run) inbound: usize,
    pub(in crate::run) routing: Arc<ServerRouting>,
    pub(in crate::run) keys: Arc<MethodKeyAdapter<MethodSinglePskProvider>>,
    pub(in crate::run) clock: Arc<SystemClock>,
    pub(in crate::run) random: SystemRandom,
    pub(in crate::run) replay: Arc<TcpReplayStore>,
    pub(in crate::run) runtime: RuntimeConfig,
    pub(in crate::run) direct_resolvers: Arc<[dns_egress::ServerDnsResolver]>,
    pub(in crate::run) outbound_dial_options: Arc<[DialOptions]>,
    pub(in crate::run) route_network: Arc<RouteNetworkOptions>,
    pub(in crate::run) network_sockets: Arc<ServerNetworkSocketService>,
    pub(in crate::run) registry: OwnerRegistry,
    pub(in crate::run) metrics: Arc<Metrics>,
}

pub(super) struct ServerNetworkTcpOutbound {
    pub(super) sockets: Arc<ServerNetworkSocketService>,
    pub(super) resolver: dns_egress::ServerDnsResolver,
    pub(super) outbound: DialOptions,
    pub(super) route: Arc<RouteNetworkOptions>,
    pub(super) connect_timeout: Duration,
    pub(super) metrics: Arc<Metrics>,
}

impl ferrum2_core::Outbound for ServerNetworkTcpOutbound {
    type Stream = ServerPhysicalTcpStream;
    type Error = ConnectError;

    async fn open(&self, target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        if let Some(address) = target.as_socket_addr() {
            return self.connect_candidate(address, deadline).await;
        }

        let TargetHostRef::Domain(host) = target.host() else {
            return Err(ConnectError::new(ConnectErrorKind::Other));
        };
        let candidates = match tokio::time::timeout_at(
            deadline,
            self.resolver.resolve(host, target.port().get()),
        )
        .await
        {
            Ok(Ok(candidates)) => candidates,
            Ok(Err(_)) => {
                return Err(ConnectError::new(ConnectErrorKind::HostUnreachable));
            }
            Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
        };

        let mut attempted = false;
        let mut last_error = ConnectError::new(ConnectErrorKind::HostUnreachable);
        for address in candidates.into_iter().take(MAX_RESOLVED_CANDIDATES) {
            if tokio::time::Instant::now() >= deadline {
                return Err(ConnectError::new(ConnectErrorKind::Timeout));
            }
            attempted = true;
            match self.connect_candidate(address, deadline).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = error,
            }
        }
        if attempted {
            Err(last_error)
        } else {
            Err(ConnectError::new(ConnectErrorKind::HostUnreachable))
        }
    }
}

impl ServerNetworkTcpOutbound {
    async fn connect_candidate(
        &self,
        address: std::net::SocketAddr,
        deadline: tokio::time::Instant,
    ) -> Result<ServerPhysicalTcpStream, ConnectError> {
        #[cfg(all(not(windows), not(test)))]
        {
            let _ = (&self.sockets, &self.outbound, &self.route, &self.metrics);
            let stream =
                match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address))
                    .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        return Err(ConnectError::new(connect_error_kind_from_io(&error)));
                    }
                    Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
                };
            RuntimeTcpStream::from_connected(stream)
                .map_err(|error| ConnectError::new(connect_error_kind_from_io(&error)))
        }

        #[cfg(any(windows, test))]
        {
            let result = match tokio::time::timeout_at(
                deadline,
                self.sockets
                    .connect_tcp(&self.outbound, self.route.as_ref(), address),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
            };
            match result {
                Ok(stream) => {
                    record_interface_resolution_success(&self.metrics, stream.resolved_interface());
                    Ok(stream)
                }
                Err(error) => {
                    self.metrics.outbound_interface_resolution(
                        interface_resolution_source(error.attempted_source()),
                        interface_resolution_result(&error),
                    );
                    Err(connect_error_from_network_service(error))
                }
            }
        }
    }
}
