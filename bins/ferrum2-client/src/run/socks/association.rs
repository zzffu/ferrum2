use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ferrum2_core::route::Network;
use ferrum2_core::{ConnectErrorKind, SessionReply as _};
use ferrum2_observability::{Direction, Outcome, Reason, Role, Stage};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::{SocksStream, SocksUdpAssociate};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::{
    ClientRequestOrigin, ClientUdpAssociation, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
use crate::run::observation::{
    UdpPacketPhase, record_udp_drop, record_udp_packet_error, record_udp_runtime_error,
    record_udp_terminal,
};
use crate::run::routing::ClientTerminalRoute;

use super::dns_hijack::relay_hijacked_udp;
use super::endpoint::{SocksUdpEndpoint, SocksUdpOwnedPacket, SocksUdpPacket};

pub(super) async fn run_udp_association<IO, F, Fut>(
    association: SocksUdpAssociate<IO>,
    peer_ip: IpAddr,
    local_ip: Ipv4Addr,
    cancellation: &mut CancellationToken,
    context: Arc<ClientContext>,
    route: (usize, &ClientRouting),
    mut bind: F,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let requested_port = association.source_port();
    let SocksUdpAssociate {
        mut control, reply, ..
    } = association;
    let (inbound, routing) = route;
    #[cfg(feature = "candidate-udp-owned-headroom")]
    let Some(receive_budget) = context
        .egress
        .udp
        .as_ref()
        .map(|udp| udp.manager.buffer_budget())
    else {
        let _ = reply.failed(ConnectErrorKind::Other).await;
        return;
    };
    let endpoint = tokio::select! {
        _ = cancellation.cancelled() => return,
        endpoint = SocksUdpEndpoint::bind(
            local_ip,
            peer_ip,
            requested_port,
            #[cfg(feature = "candidate-udp-owned-headroom")]
            receive_budget,
            &mut bind,
        ) => endpoint,
    };
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    #[cfg(feature = "structural-metrics")]
    let endpoint = endpoint.with_structural(context.structural.clone());
    let bound = match endpoint.local_addr() {
        Ok(bound) => bound,
        Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    if reply.succeeded_socket(SocketAddr::V4(bound)).await.is_err() {
        return;
    }
    classify_udp_association(
        endpoint,
        &mut control,
        cancellation,
        &context,
        inbound,
        routing,
    )
    .await;
}

pub(super) async fn relay_udp_association<IO>(
    endpoint: &mut SocksUdpEndpoint,
    prepared: &mut ClientUdpAssociation,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    routing: &ClientRouting,
    first: Option<SocksUdpOwnedPacket>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut session_cancellation = match prepared.cancellation() {
        Ok(cancellation) => cancellation,
        Err(_) => return,
    };
    let mut first = match first {
        Some(first) => first,
        None => {
            let mut control_byte = [0; 1];
            loop {
                let idle_deadline = match prepared.idle_deadline() {
                    Ok(deadline) => deadline,
                    Err(_) => return,
                };
                let received = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    changed = session_cancellation.changed() => {
                        let _ = changed;
                        return;
                    }
                    _ = tokio::time::sleep_until(idle_deadline) => {
                        if prepared.idle_expired(idle_deadline) {
                            return;
                        }
                        continue;
                    }
                    read = control.read(&mut control_byte) => {
                        if !matches!(read, Ok(1)) {
                            return;
                        }
                        continue;
                    }
                    received = endpoint.receive() => received,
                };
                let packet = match received {
                    Ok(SocksUdpPacket::Valid(packet)) => packet,
                    Ok(SocksUdpPacket::WrongSource) => {
                        record_udp_drop(
                            context,
                            Direction::ClientToTarget,
                            Stage::Socks5,
                            Reason::Address,
                        );
                        continue;
                    }
                    Ok(SocksUdpPacket::InvalidWire) => {
                        record_udp_drop(
                            context,
                            Direction::ClientToTarget,
                            Stage::Socks5,
                            Reason::Bounds,
                        );
                        continue;
                    }
                    Err(_) => {
                        record_udp_terminal(
                            context,
                            Stage::Relay,
                            Reason::Receive,
                            Outcome::Failed,
                        );
                        return;
                    }
                };
                let encoded_target_len = packet.encoded_target_len();
                if packet.payload().len()
                    > prepared.payload_limit(&routing.outbounds, false, encoded_target_len)
                {
                    record_udp_drop(
                        context,
                        Direction::ClientToTarget,
                        Stage::Shadowsocks,
                        Reason::Bounds,
                    );
                    endpoint.recycle_failure(packet);
                    continue;
                }
                endpoint.accept(packet.source_port());
                break packet;
            }
        }
    };
    if prepared.activate(&context.egress).is_err() {
        endpoint.recycle_failure(first);
        record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
        return;
    }
    let forwarded = forward_udp_request(
        prepared,
        cancellation,
        &mut session_cancellation,
        context,
        routing,
        &mut first,
    )
    .await;
    if forwarded {
        endpoint.recycle(first);
    } else {
        endpoint.recycle_failure(first);
    }
    if !forwarded {
        return;
    }
    let mut control_byte = [0_u8; 1];
    loop {
        let idle_deadline = match prepared.idle_deadline() {
            Ok(deadline) => deadline,
            Err(_) => return,
        };
        tokio::select! {
            _ = cancellation.cancelled() => return,
            changed = session_cancellation.changed() => {
                let _ = changed;
                return;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                if prepared.idle_expired(idle_deadline) {
                    return;
                }
            }
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
            }
            received = async {
                endpoint.receive().await
            } => {
                let mut packet = match received {
                    Ok(SocksUdpPacket::Valid(packet)) => packet,
                    Ok(SocksUdpPacket::WrongSource) => {
                        record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Address);
                        continue;
                    }
                    Ok(SocksUdpPacket::InvalidWire) => {
                        record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Bounds);
                        continue;
                    }
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                let encoded_target_len = packet.encoded_target_len();
                if packet.payload().len()
                    > prepared.payload_limit(&routing.outbounds, false, encoded_target_len)
                {
                    record_udp_drop(
                        context,
                        Direction::ClientToTarget,
                        Stage::Shadowsocks,
                        Reason::Bounds,
                    );
                    endpoint.recycle_failure(packet);
                    continue;
                }
                endpoint.accept(packet.source_port());
                let forwarded = forward_udp_request(
                    prepared,
                    cancellation,
                    &mut session_cancellation,
                    context,
                    routing,
                    &mut packet,
                ).await;
                if forwarded {
                    endpoint.recycle(packet);
                } else {
                    endpoint.recycle_failure(packet);
                }
                if !forwarded {
                    return;
                }
            }
            received = async {
                prepared.receive_response_wire().await
            } => {
                let length = match received {
                    Ok(received) => received,
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                let response = match prepared.prepare_application_response(
                    &context.egress,
                    &routing.outbounds,
                    length,
                ) {
                    Ok(response) => response,
                    Err(UdpPlanResponseError::Packet(error)) => {
                        if record_udp_packet_error(
                            context,
                            Direction::TargetToClient,
                            UdpPacketPhase::ResponsePrepare,
                            error,
                        ) {
                            continue;
                        }
                        return;
                    }
                    Err(UdpPlanResponseError::Runtime(error)) => {
                        if record_udp_runtime_error(context, Direction::TargetToClient, error) {
                            continue;
                        }
                        return;
                    }
                };
                let target = response.datagram().target();
                let payload = response.datagram().payload();
                let Ok(send_deadline) = prepared.idle_deadline() else { return };
                match send_with_lifecycle(
                        endpoint.send(target, payload),
                        cancellation,
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(_) => {}
                    Err(UdpSendError::Io) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                        return;
                    }
                    Err(UdpSendError::Cancelled) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
                        return;
                    }
                    Err(UdpSendError::Idle) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
                        return;
                    }
                }
                context.metrics.udp_datagram(Role::Client, Direction::TargetToClient, Outcome::Accepted);
                context.metrics.add_udp_bytes(Role::Client, Direction::TargetToClient, payload.len() as u64);
                prepared.recycle_application_response(response);
            }
        }
    }
}

pub(super) async fn classify_udp_association<IO>(
    mut endpoint: SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    routing: &ClientRouting,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut control_byte = [0; 1];
    let Ok(mut route_scratch) = routing.route_scratch() else {
        return;
    };
    let (packet, terminal) = loop {
        let idle_deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let received = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep_until(idle_deadline) => return,
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
                continue;
            }
            received = endpoint.receive() => received,
        };
        let packet = match received {
            Ok(SocksUdpPacket::Valid(packet)) => packet,
            Ok(SocksUdpPacket::WrongSource) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Address,
                );
                continue;
            }
            Ok(SocksUdpPacket::InvalidWire) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Bounds,
                );
                continue;
            }
            Err(_) => {
                record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                return;
            }
        };
        let Ok(terminal) = routing.select_terminal_with_scratch(
            inbound,
            Network::Udp,
            packet.target(),
            Some(packet.payload()),
            &context.metrics,
            &mut route_scratch,
        ) else {
            endpoint.recycle_failure(packet);
            return;
        };
        if matches!(terminal, ClientTerminalRoute::Reject) {
            endpoint.recycle_failure(packet);
            return;
        }
        let encoded_target_len = packet.encoded_target_len();
        if let ClientTerminalRoute::Route(plan) = &terminal
            && packet.payload().len()
                > composed_udp_plan_limit(
                    &routing.outbounds,
                    plan.hops(),
                    false,
                    encoded_target_len,
                )
        {
            record_udp_drop(
                context,
                Direction::ClientToTarget,
                Stage::Shadowsocks,
                Reason::Bounds,
            );
            endpoint.recycle_failure(packet);
            continue;
        }
        endpoint.accept(packet.source_port());
        break (packet, terminal);
    };

    match terminal {
        ClientTerminalRoute::Route(plan) => {
            let target = packet.target().clone();
            let prepared = tokio::select! {
                _ = cancellation.cancelled() => None,
                prepared = context.egress.prepare_udp_for_ingress(
                    ClientRequestOrigin::Socks,
                    inbound,
                    Some(plan),
                    Some(&target),
                ) => Some(prepared),
            };
            let Some(prepared) = prepared else {
                endpoint.recycle_failure(packet);
                return;
            };
            let Ok(mut prepared) = prepared else {
                endpoint.recycle_failure(packet);
                record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
                return;
            };
            relay_udp_association(
                &mut endpoint,
                &mut prepared,
                control,
                cancellation,
                context,
                routing,
                Some(packet),
            )
            .await;
        }
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                endpoint.recycle_failure(packet);
                return;
            };
            relay_hijacked_udp(
                &mut endpoint,
                control,
                cancellation,
                context,
                inbound,
                &proxy,
                Some(packet),
            )
            .await;
        }
        ClientTerminalRoute::Reject => unreachable!("reject terminates during classification"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_udp_request(
    prepared: &mut ClientUdpAssociation,
    cancellation: &mut CancellationToken,
    session_cancellation: &mut tokio::sync::watch::Receiver<bool>,
    context: &ClientContext,
    routing: &ClientRouting,
    packet: &mut SocksUdpOwnedPacket,
) -> bool {
    #[cfg(feature = "candidate-udp-owned-headroom")]
    if prepared.supports_owned_headroom_request() {
        return forward_owned_headroom_request(
            prepared,
            cancellation,
            session_cancellation,
            context,
            routing,
            packet,
        )
        .await;
    }
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    let target = packet.target().clone();
    let payload_len = packet.payload().len();
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    let wire_len = match prepared.prepare_owned_application_request(
        &context.egress,
        &routing.outbounds,
        target,
        packet.payload_mut(),
        Instant::now(),
    ) {
        Ok(length) => length,
        Err(UdpPlanResponseError::Packet(error)) => {
            return record_udp_packet_error(
                context,
                Direction::ClientToTarget,
                UdpPacketPhase::RequestEncode,
                error,
            );
        }
        Err(UdpPlanResponseError::Runtime(error)) => {
            return record_udp_runtime_error(context, Direction::ClientToTarget, error);
        }
    };
    #[cfg(feature = "candidate-udp-owned-headroom")]
    let wire_len = match prepared.prepare_headroom_fallback_application_request(
        &context.egress,
        &routing.outbounds,
        packet.headroom_mut(),
        Instant::now(),
    ) {
        Ok(length) => length,
        Err(UdpPlanResponseError::Packet(error)) => {
            return record_udp_packet_error(
                context,
                Direction::ClientToTarget,
                UdpPacketPhase::RequestEncode,
                error,
            );
        }
        Err(UdpPlanResponseError::Runtime(error)) => {
            return record_udp_runtime_error(context, Direction::ClientToTarget, error);
        }
    };
    let Ok(send_deadline) = prepared.idle_deadline() else {
        return false;
    };
    match send_with_lifecycle(
        prepared.send_encoded_request(wire_len),
        cancellation,
        session_cancellation,
        send_deadline,
    )
    .await
    {
        Ok(sent) if sent == wire_len => {}
        Ok(_) | Err(UdpSendError::Io) => {
            record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
            return false;
        }
        Err(UdpSendError::Cancelled) => {
            record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
            return false;
        }
        Err(UdpSendError::Idle) => {
            record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
            return false;
        }
    }
    context
        .metrics
        .udp_datagram(Role::Client, Direction::ClientToTarget, Outcome::Accepted);
    context
        .metrics
        .add_udp_bytes(Role::Client, Direction::ClientToTarget, payload_len as u64);
    true
}

#[cfg(feature = "candidate-udp-owned-headroom")]
#[allow(clippy::too_many_arguments)]
async fn forward_owned_headroom_request(
    prepared: &mut ClientUdpAssociation,
    cancellation: &mut CancellationToken,
    session_cancellation: &mut tokio::sync::watch::Receiver<bool>,
    context: &ClientContext,
    routing: &ClientRouting,
    packet: &mut SocksUdpOwnedPacket,
) -> bool {
    let payload_len = packet.payload().len();
    let wire_range = match prepared.prepare_owned_headroom_application_request(
        &context.egress,
        &routing.outbounds,
        packet.headroom_mut(),
        Instant::now(),
    ) {
        Ok(wire_range) => wire_range,
        Err(UdpPlanResponseError::Packet(error)) => {
            return record_udp_packet_error(
                context,
                Direction::ClientToTarget,
                UdpPacketPhase::RequestEncode,
                error,
            );
        }
        Err(UdpPlanResponseError::Runtime(error)) => {
            return record_udp_runtime_error(context, Direction::ClientToTarget, error);
        }
    };
    let wire = match packet
        .headroom_mut()
        .as_ref()
        .expect("successful owned encode restores its packet")
        .wire(wire_range.clone())
    {
        Ok(wire) => wire,
        Err(error) => {
            return record_udp_runtime_error(context, Direction::ClientToTarget, error);
        }
    };
    let Ok(send_deadline) = prepared.idle_deadline() else {
        return false;
    };
    match send_with_lifecycle(
        prepared.send_owned_encoded_request(wire),
        cancellation,
        session_cancellation,
        send_deadline,
    )
    .await
    {
        Ok(sent) if sent == wire_range.len() => {}
        Ok(_) | Err(UdpSendError::Io) => {
            record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
            return false;
        }
        Err(UdpSendError::Cancelled) => {
            record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
            return false;
        }
        Err(UdpSendError::Idle) => {
            record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
            return false;
        }
    }
    context
        .metrics
        .udp_datagram(Role::Client, Direction::ClientToTarget, Outcome::Accepted);
    context
        .metrics
        .add_udp_bytes(Role::Client, Direction::ClientToTarget, payload_len as u64);
    true
}
