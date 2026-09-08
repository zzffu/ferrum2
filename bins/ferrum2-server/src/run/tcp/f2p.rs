use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use ferrum2_core::{ConnectErrorKind, LocalEndpoint, TargetAddr, TargetHostRef};
use ferrum2_f2p::{Accepted, Limits, UdpBackend, UdpSocket};
use ferrum2_net::UdpResolver;
use ferrum2_observability::{Direction, Inbound, Outcome, Reason, Role, Stage};
use ferrum2_runtime::{
    CancellationToken, DirectUdpSocket, DirectUdpSocketFactory, RuntimeTcpStream, relay_lifecycle,
};
use tokio::io::{AsyncRead, ReadBuf};

use super::outbound::{
    DirectFlowError, ServerContext, ServerNetworkTcpOutbound, ServerProtocol, open_and_prefix,
};
use super::selection::select_tcp_route;
use crate::run::observation::record_failure;
use crate::run::routing::ServerTerminalRoute;
use crate::run::udp::physical::{
    ServerNetworkUdpSocketFactory, ServerPhysicalUdpSocket, ServerUdpNetworkPolicy,
};
use crate::run::udp::route::select_udp_route;

struct ActiveConnection<'a>(&'a ferrum2_observability::Metrics);
impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        self.0.active_connections_dec(Role::Server, Inbound::F2p);
    }
}

pub(in crate::run) struct UdpBudget {
    enabled: bool,
    sessions: ferrum2_runtime::UdpSessionManager,
}

impl UdpBudget {
    pub(in crate::run) fn new(enabled: bool, sessions: ferrum2_runtime::UdpSessionManager) -> Self {
        Self { enabled, sessions }
    }

    fn reserve(&self) -> io::Result<(Limits, Vec<ferrum2_runtime::UdpBufferReservation>)> {
        if !self.enabled {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let configured = self.sessions.limits();
        // A tunnel borrows from the same aggregate budget as native Shadowsocks,
        // without dividing validated session/byte minima into invalid sublimits.
        let bytes = (configured.max_buffered_bytes() / 4).min(1_048_576);
        let budget = self.sessions.buffer_budget();
        let mut reservations = Vec::new();
        let mut remaining = bytes;
        while remaining != 0 {
            let part = remaining.min(ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES);
            reservations.push(
                budget
                    .reserve(part)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?,
            );
            remaining -= part;
        }
        Ok((
            Limits {
                max_sessions: configured.max_sessions().min(64),
                max_buffered_bytes: bytes,
                idle_timeout: configured.idle_timeout(),
            },
            reservations,
        ))
    }
}

pub(super) async fn connection(
    stream: RuntimeTcpStream,
    cancellation: CancellationToken,
    context: Arc<ServerContext>,
) {
    #[cfg(any(windows, test))]
    {
        let coordinator = context.network_sockets.coordinator();
        let generation = coordinator.status().published_generation();
        let Ok(mut owner) = coordinator.register_runtime_owner(
            generation,
            ferrum2_runtime::NetworkRuntimeOwnerKind::TcpConnection,
        ) else {
            return;
        };
        tokio::select! {
            _ = owner.cancelled() => {},
            () = connection_inner(stream, cancellation, context) => {},
        }
    }
    #[cfg(all(not(windows), not(test)))]
    connection_inner(stream, cancellation, context).await;
}

async fn connection_inner(
    stream: RuntimeTcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ServerContext>,
) {
    let ServerProtocol::F2p(config) = &context.protocol else {
        return;
    };
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(context.runtime.handshake_timeout, ferrum2_f2p::accept(stream, config)) => result,
    };
    let accepted = match accepted {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(_)) => {
            record_failure(&context, Stage::F2p, Reason::RelayIo, Outcome::Failed);
            return;
        }
        Err(_) => {
            record_failure(
                &context,
                Stage::F2p,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            return;
        }
    };
    context
        .metrics
        .connection(Role::Server, Inbound::F2p, Outcome::Accepted);
    context
        .metrics
        .active_connections_inc(Role::Server, Inbound::F2p);
    let _active = ActiveConnection(&context.metrics);
    let result = match accepted {
        Accepted::Tcp {
            mut stream, target, ..
        } => tcp(&mut stream, target, &mut cancellation, &context).await,
        Accepted::Udp { stream, profile } => match context.f2p_udp.reserve() {
            Ok((limits, bytes)) => {
                tokio::select! {
                    _ = cancellation.cancelled() => Err(io::ErrorKind::Interrupted.into()),
                    result = ferrum2_f2p::serve_udp(stream, profile, limits, Backend { context: Arc::clone(&context) }, bytes) => result,
                }
            }
            Err(error) => Err(error),
        },
    };
    match result {
        Ok(()) => context
            .metrics
            .connection(Role::Server, Inbound::F2p, Outcome::Completed),
        Err(_) => record_failure(&context, Stage::F2p, Reason::RelayIo, Outcome::Failed),
    }
}

async fn reply(
    stream: &mut ferrum2_f2p::ServerStream<RuntimeTcpStream>,
    result: Result<SocketAddr, ConnectErrorKind>,
    context: &ServerContext,
    cancellation: &mut CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(io::ErrorKind::Interrupted.into()),
        result = tokio::time::timeout(context.runtime.handshake_timeout, ferrum2_f2p::respond_tcp(stream, result)) => result.map_err(|_| io::ErrorKind::TimedOut)?,
    }
}

async fn tcp(
    stream: &mut ferrum2_f2p::ServerStream<RuntimeTcpStream>,
    target: TargetAddr,
    cancellation: &mut CancellationToken,
    context: &ServerContext,
) -> io::Result<()> {
    let selection = select_tcp_route(
        context,
        &target,
        |cx, destination| {
            let mut buffer = ReadBuf::new(destination);
            Pin::new(&mut *stream)
                .poll_read(cx, &mut buffer)
                .map_ok(|()| buffer.filled().len())
        },
        &[][..],
        cancellation.cancelled(),
    )
    .await
    .map_err(|_| io::Error::other("route selection failed"))?;
    let ServerTerminalRoute::Direct(outbound) = selection.terminal else {
        reply(
            stream,
            Err(ConnectErrorKind::PolicyDenied),
            context,
            cancellation,
        )
        .await?;
        return Err(io::ErrorKind::PermissionDenied.into());
    };
    let resolver = context
        .direct_resolvers
        .get(outbound)
        .ok_or(io::ErrorKind::PermissionDenied)?;
    let dial = context
        .outbound_dial_options
        .get(outbound)
        .ok_or(io::ErrorKind::PermissionDenied)?;
    let direct = ServerNetworkTcpOutbound {
        sockets: Arc::clone(&context.network_sockets),
        resolver: resolver.for_inbound(context.inbound),
        outbound: dial.clone(),
        route: Arc::clone(&context.route_network),
        connect_timeout: context.runtime.connect_timeout,
        metrics: Arc::clone(&context.metrics),
    };
    let opened = open_and_prefix(
        &direct,
        &target,
        selection.prefix.as_ref(),
        context.runtime.idle_timeout,
        cancellation.cancelled(),
    )
    .await;
    let (mut destination, prefix_bytes) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            let kind = match error {
                DirectFlowError::Open(error) => error.kind(),
                _ => ConnectErrorKind::Other,
            };
            reply(stream, Err(kind), context, cancellation).await?;
            return Err(io::Error::other("destination connection failed"));
        }
    };
    drop(selection);
    reply(
        stream,
        Ok(destination.local_socket_addr()),
        context,
        cancellation,
    )
    .await?;
    let result = relay_lifecycle(
        stream,
        &mut destination,
        context.runtime.idle_timeout,
        &context.registry,
        cancellation.cancelled(),
    )
    .await;
    let stats = match &result {
        Ok(stats) => stats,
        Err(failure) => &failure.stats,
    };
    context.metrics.add_bytes(
        Role::Server,
        Direction::InboundToOutbound,
        prefix_bytes + stats.inbound_to_outbound,
    );
    context.metrics.add_bytes(
        Role::Server,
        Direction::OutboundToInbound,
        stats.outbound_to_inbound,
    );
    result
        .map(|_| ())
        .map_err(|_| io::Error::other("relay terminated"))
}

struct Backend {
    context: Arc<ServerContext>,
}
struct Socket {
    socket: ServerPhysicalUdpSocket,
    peer: SocketAddr,
    metrics: Arc<ferrum2_observability::Metrics>,
    session: SessionLease,
}

struct SessionLease {
    manager: ferrum2_runtime::UdpSessionManager,
    handle: ferrum2_runtime::UdpSessionHandle,
}

impl SessionLease {
    fn activity(
        &self,
        direction: ferrum2_runtime::UdpDirection,
    ) -> io::Result<ferrum2_runtime::PendingUdpDatagram> {
        // Payload ownership is already charged to the tunnel's aggregate reservation.
        self.manager
            .reserve_datagram(self.handle, direction, 0)
            .map_err(|_| io::ErrorKind::Interrupted.into())
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        self.manager.remove(self.handle);
    }
}

impl UdpBackend for Backend {
    type Socket = Socket;
    type Reservation = ferrum2_runtime::PendingUdpSession;

    fn reserve_session(&self) -> io::Result<Self::Reservation> {
        self.context
            .f2p_udp
            .sessions
            .reserve_session(tokio::time::Instant::now())
            .map_err(|_| io::ErrorKind::OutOfMemory.into())
    }

    async fn connect(
        &self,
        pending: Self::Reservation,
        target: &TargetAddr,
        first_payload: &[u8],
    ) -> io::Result<Socket> {
        let context = &self.context;
        let mut scratch = context
            .routing
            .route_scratch()
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let selected = select_udp_route(
            &context.routing,
            context.inbound,
            target,
            first_payload,
            &context.metrics,
            &mut scratch,
        )
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
        let ServerTerminalRoute::Direct(outbound) = selected else {
            return Err(io::ErrorKind::PermissionDenied.into());
        };
        let resolver = context
            .direct_resolvers
            .get(outbound)
            .ok_or(io::ErrorKind::PermissionDenied)?
            .for_inbound(context.inbound);
        let dial = context
            .outbound_dial_options
            .get(outbound)
            .ok_or(io::ErrorKind::PermissionDenied)?
            .clone();
        tokio::time::timeout(context.runtime.connect_timeout, async {
            let peer = if let Some(peer) = target.as_socket_addr() {
                peer
            } else {
                let TargetHostRef::Domain(host) = target.host() else {
                    return Err(io::ErrorKind::InvalidInput.into());
                };
                UdpResolver::resolve(&resolver, host, target.port().get())
                    .await?
                    .into_iter()
                    .next()
                    .ok_or(io::ErrorKind::NotFound)?
            };
            let factory = ServerNetworkUdpSocketFactory {
                sockets: Arc::clone(&context.network_sockets),
                metrics: Arc::clone(&context.metrics),
            };
            let socket = factory
                .open(
                    Some(ServerUdpNetworkPolicy {
                        outbound: dial,
                        route: Arc::clone(&context.route_network),
                    }),
                    peer,
                )
                .await?;
            socket.connect_peer(peer).await?;
            let activity = pending
                .reserve_datagram(ferrum2_runtime::UdpDirection::ToTarget, 0)
                .map_err(|_| io::ErrorKind::Interrupted)?;
            let handle = pending
                .commit_activity(activity, tokio::time::Instant::now())
                .map_err(|_| io::ErrorKind::Interrupted)?;
            Ok(Socket {
                socket,
                peer,
                metrics: Arc::clone(&context.metrics),
                session: SessionLease {
                    manager: context.f2p_udp.sessions.clone(),
                    handle,
                },
            })
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }
}

impl UdpSocket for Socket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        let activity = self
            .session
            .activity(ferrum2_runtime::UdpDirection::ToTarget)?;
        let mut cancellation = self
            .session
            .manager
            .cancellation(self.session.handle)
            .map_err(|_| io::ErrorKind::Interrupted)?;
        let sent = tokio::select! {
            _ = cancellation.wait_for(|closed| *closed) => return Err(io::ErrorKind::Interrupted.into()),
            sent = self.socket.send_to(payload, self.peer) => sent?,
        };
        if sent != payload.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        activity
            .commit_activity(tokio::time::Instant::now())
            .map_err(|_| io::ErrorKind::Interrupted)?;
        self.metrics
            .add_bytes(Role::Server, Direction::InboundToOutbound, sent as u64);
        Ok(())
    }
    async fn readable(&self) -> io::Result<()> {
        let mut cancellation = self
            .session
            .manager
            .cancellation(self.session.handle)
            .map_err(|_| io::ErrorKind::Interrupted)?;
        tokio::select! {
            _ = cancellation.wait_for(|closed| *closed) => Err(io::ErrorKind::Interrupted.into()),
            ready = self.socket.readable() => ready,
        }
    }
    fn try_receive(&self, destination: &mut [u8]) -> io::Result<usize> {
        let activity = self
            .session
            .activity(ferrum2_runtime::UdpDirection::ToClient)?;
        let received = self.socket.try_receive_connected(destination)?;
        activity
            .commit_activity(tokio::time::Instant::now())
            .map_err(|_| io::ErrorKind::Interrupted)?;
        self.metrics
            .add_bytes(Role::Server, Direction::OutboundToInbound, received as u64);
        Ok(received)
    }
}
