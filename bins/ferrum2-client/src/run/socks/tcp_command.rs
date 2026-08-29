use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::route::Network;
use ferrum2_core::{ConnectErrorKind, LocalEndpoint, SessionReply as _};
use ferrum2_observability::{
    Event, Inbound, LogLevel, Outcome, Reason, Role, Stage, TraceRecord, emit,
};
#[cfg(feature = "structural-metrics")]
use ferrum2_runtime::RELAY_BUFFER_BYTES;
use ferrum2_runtime::{
    CancellationToken, RelayDirection, relay_lifecycle, relay_lifecycle_with_engine,
};
use ferrum2_shadowsocks::ShadowsocksError;
use ferrum2_shadowsocks::tokio::{FusedRelayDirection, TokioFramed, relay_client_flow};
use ferrum2_socks5::SocksCommand;
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{FtbrFallbackReason, StructuralCounter};
use tokio::net::UdpSocket;

use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::{
    ClientOpenFailure, ClientPlanFailure, ClientRequestOrigin, ClientTcpFlow,
};
use crate::run::observation::{finish_relay, observation_for_error, record_failure};
use crate::run::routing::{ClientTerminalRoute, relay_hijacked_tcp};

use super::association::run_udp_association;

pub(super) async fn client_connection(
    stream: tokio::net::TcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ClientContext>,
    inbound: usize,
    routing: Arc<ClientRouting>,
) {
    let peer_ip = stream.peer_addr().ok().map(|peer| peer.ip());
    let local_addr = stream.local_addr().ok();
    let local_ip = match local_addr {
        Some(SocketAddr::V4(local)) if !local.ip().is_unspecified() => Some(*local.ip()),
        Some(SocketAddr::V4(_)) | Some(SocketAddr::V6(_)) | None => None,
    };
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            context.runtime.handshake_timeout,
            context.inbound.accept_command(stream),
        ) => result,
    };
    let command = match accepted {
        Ok(Ok(command)) => command,
        Ok(Err(_)) => {
            record_failure(
                &context,
                Stage::Socks5,
                Reason::SocksProtocol,
                Outcome::Rejected,
            );
            return;
        }
        Err(_) => {
            record_failure(
                &context,
                Stage::Socks5,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            return;
        }
    };
    let connect = match command {
        SocksCommand::Connect(connect) => connect,
        SocksCommand::UdpAssociate(association) => {
            let Some(public_udp_slots) = context.public_udp_slots.as_ref() else {
                let _ = association.reject_command_not_supported().await;
                return;
            };
            let Ok(public_udp_slot) = Arc::clone(public_udp_slots).try_acquire_owned() else {
                let _ = association.reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            let (Some(peer_ip), Some(local_ip)) = (peer_ip, local_ip) else {
                let _ = association.reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            run_udp_association(
                association,
                peer_ip,
                local_ip,
                &mut cancellation,
                Arc::clone(&context),
                (inbound, &routing),
                UdpSocket::bind,
            )
            .await;
            drop(public_udp_slot);
            return;
        }
    };
    let (target, reply) = connect.into_parts();
    let Ok(mut route_scratch) = routing.route_scratch() else {
        let _ = reply.failed(ConnectErrorKind::Other).await;
        return;
    };
    let Ok(terminal) = routing.select_terminal_with_scratch(
        inbound,
        Network::Tcp,
        &target,
        None,
        &context.metrics,
        &mut route_scratch,
    ) else {
        let _ = reply.failed(ConnectErrorKind::Other).await;
        return;
    };
    let plan = match terminal {
        ClientTerminalRoute::Route(plan) => plan,
        ClientTerminalRoute::Reject => {
            let _ = reply.failed(ConnectErrorKind::PolicyDenied).await;
            return;
        }
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                let _ = reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            let Some(bound) = local_addr else {
                let _ = reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            let mut stream = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = reply.succeeded_socket(bound) => match result {
                    Ok(stream) => stream,
                    Err(_) => return,
                },
            };
            relay_hijacked_tcp(
                &mut stream,
                inbound,
                &proxy,
                context.runtime.idle_timeout,
                cancellation.cancelled(),
            )
            .await;
            return;
        }
    };
    let opened = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = context.egress.open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            inbound,
            Some(plan),
            &target,
            None,
            #[cfg(test)]
            None,
        ) => result,
    };
    let flow = match opened {
        Ok(flow) => flow,
        Err(ClientOpenFailure::Plan(failure)) => {
            let kind = match failure {
                ClientPlanFailure::Invalid => ConnectErrorKind::Other,
            };
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::Connect(kind)) => {
            record_failure(&context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::Protocol(error)) => {
            let (stage, outcome, reason) = observation_for_error(error);
            record_failure(&context, stage, reason, outcome);
            let kind = match error {
                ShadowsocksError::Connect(kind) => kind,
                ShadowsocksError::Detection(_)
                | ShadowsocksError::Protocol(_)
                | ShadowsocksError::Transport(_) => ConnectErrorKind::Other,
            };
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::HandshakeTimeout) => {
            record_failure(
                &context,
                Stage::Shadowsocks,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let bound = flow.local_socket_addr();
    let mut stream = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = reply.succeeded_socket(bound) => match result {
            Ok(stream) => stream,
            Err(_) => {
                record_failure(&context, Stage::Socks5, Reason::RelayIo, Outcome::Failed);
                return;
            }
        },
    };

    context
        .metrics
        .connection(Role::Client, Inbound::Socks5, Outcome::Accepted);
    context
        .metrics
        .active_connections_inc(Role::Client, Inbound::Socks5);
    emit(TraceRecord::new(
        LogLevel::Info,
        Event::Connection,
        Role::Client,
        Stage::Socks5,
        Outcome::Accepted,
    ));
    #[cfg(feature = "structural-metrics")]
    match &flow {
        ClientTcpFlow::SingleProxy(_) => {
            context
                .structural
                .add(StructuralCounter::FtbrFastPathConnections, 1);
            context.structural.add(
                StructuralCounter::FtbrRelayBufferCapacityRemovedBytes,
                2 * RELAY_BUFFER_BYTES as u64,
            );
        }
        ClientTcpFlow::Direct(_) => context
            .structural
            .add(FtbrFallbackReason::Direct.counter(), 1),
        ClientTcpFlow::Proxy(_) => context
            .structural
            .add(FtbrFallbackReason::MultiHop.counter(), 1),
    }
    let flow = match flow {
        ClientTcpFlow::SingleProxy(mut flow) => {
            let relay = relay_lifecycle_with_engine(
                context.runtime.idle_timeout,
                cancellation.cancelled(),
                |progress| {
                    relay_client_flow(
                        &mut stream,
                        &mut flow,
                        move |direction, bytes| {
                            progress.record(
                                match direction {
                                    FusedRelayDirection::PlainToTunnel => {
                                        RelayDirection::InboundToOutbound
                                    }
                                    FusedRelayDirection::TunnelToPlain => {
                                        RelayDirection::OutboundToInbound
                                    }
                                },
                                bytes,
                            );
                        },
                        #[cfg(feature = "structural-metrics")]
                        &context.structural,
                    )
                },
            )
            .await;
            let framed = TokioFramed::new(flow);
            context
                .metrics
                .active_connections_dec(Role::Client, Inbound::Socks5);
            finish_relay(&context, &framed, relay);
            return;
        }
        flow => flow,
    };

    let mut framed = TokioFramed::new(flow);
    let relay = relay_lifecycle(
        &mut stream,
        &mut framed,
        context.runtime.idle_timeout,
        &context.registry,
        cancellation.cancelled(),
    )
    .await;
    context
        .metrics
        .active_connections_dec(Role::Client, Inbound::Socks5);
    finish_relay(&context, &framed, relay);
}
