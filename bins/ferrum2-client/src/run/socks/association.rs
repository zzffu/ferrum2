use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ferrum2_core::route::Network;
use ferrum2_core::{ConnectErrorKind, SessionReply as _, TargetAddr};
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
use super::endpoint::{SocksUdpEndpoint, SocksUdpPacket};

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
    let endpoint = tokio::select! {
        _ = cancellation.cancelled() => return,
        endpoint = SocksUdpEndpoint::bind(local_ip, peer_ip, requested_port, &mut bind) => endpoint,
    };
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
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
    first: Option<(TargetAddr, Vec<u8>)>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut session_cancellation = match prepared.cancellation() {
        Ok(cancellation) => cancellation,
        Err(_) => return,
    };
    let first = match first {
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
                let (decoded, source_port) = match received {
                    Ok(SocksUdpPacket::Valid {
                        datagram,
                        source_port,
                    }) => (datagram, source_port),
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
                let encoded_target_len = decoded.encoded_target_len();
                if decoded.payload().len()
                    > prepared.payload_limit(&routing.outbounds, false, encoded_target_len)
                {
                    record_udp_drop(
                        context,
                        Direction::ClientToTarget,
                        Stage::Shadowsocks,
                        Reason::Bounds,
                    );
                    continue;
                }
                let target = decoded.to_target_addr();
                let payload = decoded.payload().to_vec();
                endpoint.accept(source_port);
                break (target, payload);
            }
        }
    };
    if prepared.activate(&context.egress).is_err() {
        record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
        return;
    }
    if !forward_udp_request(
        prepared,
        cancellation,
        &mut session_cancellation,
        context,
        routing,
        first.0,
        first.1,
    )
    .await
    {
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
                let (decoded, source_port) = match received {
                    Ok(SocksUdpPacket::Valid { datagram, source_port }) => {
                        (datagram, source_port)
                    }
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
                let encoded_target_len = decoded.encoded_target_len();
                if decoded.payload().len()
                    > prepared.payload_limit(&routing.outbounds, false, encoded_target_len)
                {
                    record_udp_drop(
                        context,
                        Direction::ClientToTarget,
                        Stage::Shadowsocks,
                        Reason::Bounds,
                    );
                    continue;
                }
                let target = decoded.to_target_addr();
                let payload = decoded.payload().to_vec();
                endpoint.accept(source_port);
                if !forward_udp_request(
                    prepared,
                    cancellation,
                    &mut session_cancellation,
                    context,
                    routing,
                    target,
                    payload,
                ).await {
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
    let (target, payload, terminal) = loop {
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
        let (decoded, source_port) = match received {
            Ok(SocksUdpPacket::Valid {
                datagram,
                source_port,
            }) => (datagram, source_port),
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
        let target = decoded.to_target_addr();
        let Ok(terminal) = routing.select_terminal_with_scratch(
            inbound,
            Network::Udp,
            &target,
            Some(decoded.payload()),
            &context.metrics,
            &mut route_scratch,
        ) else {
            return;
        };
        if matches!(terminal, ClientTerminalRoute::Reject) {
            return;
        }
        let encoded_target_len = decoded.encoded_target_len();
        if let ClientTerminalRoute::Route(plan) = &terminal
            && decoded.payload().len()
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
            continue;
        }
        let payload = decoded.payload().to_vec();
        endpoint.accept(source_port);
        break (target, payload, terminal);
    };

    match terminal {
        ClientTerminalRoute::Route(plan) => {
            let prepared = tokio::select! {
                _ = cancellation.cancelled() => return,
                prepared = context.egress.prepare_udp_for_ingress(
                    ClientRequestOrigin::Socks,
                    inbound,
                    Some(plan),
                    Some(&target),
                ) => prepared,
            };
            let Ok(mut prepared) = prepared else {
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
                Some((target, payload)),
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
                return;
            };
            relay_hijacked_udp(
                &mut endpoint,
                control,
                cancellation,
                context,
                inbound,
                &proxy,
                Some((target, payload)),
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
    target: TargetAddr,
    payload: Vec<u8>,
) -> bool {
    let payload_len = payload.len();
    let wire_len = match prepared.prepare_owned_application_request(
        &context.egress,
        &routing.outbounds,
        target,
        bytes::Bytes::from(payload).into(),
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
    let sent = if cancellation.is_cancelled()
        || session_cancellation.has_changed().is_err()
        || *session_cancellation.borrow()
    {
        Err(UdpSendError::Cancelled)
    } else if Instant::now() >= send_deadline {
        Err(UdpSendError::Idle)
    } else {
        match prepared.try_send_encoded_request(wire_len) {
            Ok(sent) => Ok(sent),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                send_with_lifecycle(
                    prepared.send_encoded_request(wire_len),
                    cancellation,
                    session_cancellation,
                    send_deadline,
                )
                .await
            }
            Err(_) => Err(UdpSendError::Io),
        }
    };
    match sent {
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
