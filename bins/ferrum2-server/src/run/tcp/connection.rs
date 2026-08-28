use std::sync::Arc;

use ferrum2_core::{ConnectErrorKind, Inbound as _, LocalEndpoint, SessionReply as _};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Outcome, Reason, Role, Stage, TraceRecord, emit,
};
use ferrum2_runtime::{
    CancellationToken, RelayDirection, RelayRunError, RuntimeTcpStream, relay_lifecycle_with_engine,
};
use ferrum2_shadowsocks::ShadowsocksTcpInbound;
use ferrum2_shadowsocks::tokio::{
    FusedRelayDirection, TokioFramed, TokioTransport, relay_server_flow,
};

use super::ServerContext;
use super::outbound::{DirectFlowError, ServerNetworkTcpOutbound, open_and_prefix};
use super::selection::{TcpRouteFailure, select_tcp_route};
use crate::run::observation::{
    finish_relay, observation_for_direct_connect, observation_for_error, record_failure,
    update_replay_metric,
};
use crate::run::routing::ServerTerminalRoute;
use crate::run::run_error_for_rule_compile;

pub(super) async fn server_connection(
    stream: tokio::net::TcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ServerContext>,
) {
    let stream = match RuntimeTcpStream::from_connected(stream) {
        Ok(stream) => stream,
        Err(_) => {
            record_failure(&context, Stage::Listen, Reason::RelayIo, Outcome::Failed);
            return;
        }
    };
    let inbound = ShadowsocksTcpInbound::new(
        context.keys.as_ref(),
        context.clock.as_ref(),
        &context.random,
        context.replay.as_ref(),
    );
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            context.runtime.handshake_timeout,
            inbound.accept(TokioTransport::new(stream)),
        ) => result,
    };
    let session = match accepted {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            let (stage, outcome, reason) = observation_for_error(error);
            record_failure(&context, stage, reason, outcome);
            update_replay_metric(&context);
            return;
        }
        Err(_) => {
            record_failure(
                &context,
                Stage::Shadowsocks,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            return;
        }
    };
    update_replay_metric(&context);
    context
        .metrics
        .connection(Role::Server, Inbound::Shadowsocks, Outcome::Accepted);
    context
        .metrics
        .active_connections_inc(Role::Server, Inbound::Shadowsocks);
    emit(TraceRecord::new(
        LogLevel::Info,
        Event::Connection,
        Role::Server,
        Stage::Shadowsocks,
        Outcome::Accepted,
    ));

    let ferrum2_core::Session {
        target,
        mut stream,
        initial_payload,
        reply,
    } = session;
    let selection = select_tcp_route(
        &context,
        &target,
        &mut stream,
        initial_payload,
        cancellation.cancelled(),
    )
    .await;
    let selection = match selection {
        Ok(selection) => selection,
        Err(TcpRouteFailure::Cancelled) => {
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(TcpRouteFailure::Read) => {
            record_failure(&context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(TcpRouteFailure::Rule(error)) => {
            let _category = run_error_for_rule_compile(error);
            record_failure(
                &context,
                Stage::Config,
                Reason::ConfigSemantic,
                Outcome::Failed,
            );
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
    };
    let ServerTerminalRoute::Direct(outbound) = selection.terminal else {
        context
            .metrics
            .active_connections_dec(Role::Server, Inbound::Shadowsocks);
        return;
    };
    let (Some(resolver), Some(dial_options)) = (
        context.direct_resolvers.get(outbound).cloned(),
        context.outbound_dial_options.get(outbound).cloned(),
    ) else {
        record_failure(
            &context,
            Stage::Config,
            Reason::ConfigSemantic,
            Outcome::Failed,
        );
        let _ = reply.failed(ConnectErrorKind::PolicyDenied).await;
        context
            .metrics
            .active_connections_dec(Role::Server, Inbound::Shadowsocks);
        return;
    };
    let prefix = selection.prefix;
    let direct = ServerNetworkTcpOutbound {
        sockets: Arc::clone(&context.network_sockets),
        resolver: resolver.for_inbound(context.inbound),
        outbound: dial_options,
        route: Arc::clone(&context.route_network),
        connect_timeout: context.runtime.connect_timeout,
        metrics: Arc::clone(&context.metrics),
    };
    let opened = open_and_prefix(
        &direct,
        &target,
        prefix.as_ref(),
        context.runtime.idle_timeout,
        cancellation.cancelled(),
    )
    .await;
    drop(prefix);
    let (mut target_stream, initial_payload_bytes) = match opened {
        Ok(opened) => opened,
        Err(DirectFlowError::CancelledBeforeOpen) => {
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(DirectFlowError::Open(error)) => {
            let kind = error.kind();
            let (stage, outcome, reason) = observation_for_direct_connect(kind);
            record_failure(&context, stage, reason, outcome);
            let _ = reply.failed(kind).await;
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(DirectFlowError::Prefix(failure)) => {
            context
                .metrics
                .add_bytes(Role::Server, Direction::InboundToOutbound, failure.bytes);
            let (reason, outcome) = match failure.kind {
                RelayRunError::Io => (Reason::RelayIo, Outcome::Failed),
                RelayRunError::IdleTimeout => (Reason::IdleTimeout, Outcome::Timeout),
                RelayRunError::Cancelled => (Reason::Cancelled, Outcome::Cancelled),
            };
            record_failure(&context, Stage::Direct, reason, outcome);
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
    };
    let _ = reply
        .succeeded_socket(target_stream.local_socket_addr())
        .await;
    let relay = relay_lifecycle_with_engine(
        context.runtime.idle_timeout,
        cancellation.cancelled(),
        |progress| {
            relay_server_flow(&mut target_stream, &mut stream, move |direction, bytes| {
                progress.record(
                    match direction {
                        FusedRelayDirection::PlainToTunnel => RelayDirection::OutboundToInbound,
                        FusedRelayDirection::TunnelToPlain => RelayDirection::InboundToOutbound,
                    },
                    bytes,
                );
            })
        },
    )
    .await;
    let framed = TokioFramed::new(stream);
    context
        .metrics
        .active_connections_dec(Role::Server, Inbound::Shadowsocks);
    finish_relay(&context, &framed, initial_payload_bytes, relay);
}
