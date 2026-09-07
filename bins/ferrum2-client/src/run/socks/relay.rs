use super::admission::{
    AdmittedRequest, RequestDisposition, SocksUdpEndpoint, admit_request, receive_candidate,
};
use super::send::{SocksSendError, send_with_control};
use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::{ClientUdpAssociation, UdpPlanResponseError};
use crate::run::observation::{
    UdpPacketPhase, record_udp_packet_error, record_udp_runtime_error, record_udp_terminal,
};
use ferrum2_observability::{Direction, Outcome, Reason, Role, Stage};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::SocksStream;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::time::Instant;

pub(super) async fn relay_admitted<IO: AsyncRead + AsyncWrite + Unpin>(
    endpoint: &mut SocksUdpEndpoint,
    prepared: &mut ClientUdpAssociation,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    routing: &ClientRouting,
    first: AdmittedRequest,
) {
    let Ok(mut session_cancellation) = prepared.cancellation() else {
        return;
    };
    if !send_admitted_request(
        prepared,
        cancellation,
        &mut session_cancellation,
        context,
        first,
        control,
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
            received = receive_candidate(endpoint, context) => {
                let candidate = match received {
                    Ok(Some(candidate)) => candidate,
                    Ok(None) => continue,
                    Err(_) => { record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed); return; }
                };
                match admit_request(endpoint, prepared, context, routing, candidate) {
                    RequestDisposition::Admitted(admitted) => {
                        if !send_admitted_request(prepared, cancellation, &mut session_cancellation, context, admitted, control).await { return; }
                    }
                    RequestDisposition::Dropped => continue,
                    RequestDisposition::Terminated => return,
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
                match send_with_control(
                        endpoint.send(target, payload),
                        control,
                        cancellation.cancelled(),
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(_) => {}
                    Err(SocksSendError::ControlClosed) => return,
                    Err(SocksSendError::Io) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                        return;
                    }
                    Err(SocksSendError::Cancelled) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
                        return;
                    }
                    Err(SocksSendError::Idle) => {
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
async fn send_admitted_request<IO: AsyncRead + Unpin>(
    prepared: &mut ClientUdpAssociation,
    cancellation: &mut CancellationToken,
    session_cancellation: &mut tokio::sync::watch::Receiver<bool>,
    context: &ClientContext,
    admitted: AdmittedRequest,
    control: &mut IO,
) -> bool {
    let AdmittedRequest {
        wire_len,
        payload_len,
    } = admitted;
    let Ok(send_deadline) = prepared.idle_deadline() else {
        return false;
    };
    let sent = if cancellation.is_cancelled()
        || session_cancellation.has_changed().is_err()
        || *session_cancellation.borrow()
    {
        Err(SocksSendError::Cancelled)
    } else if Instant::now() >= send_deadline {
        Err(SocksSendError::Idle)
    } else {
        match prepared.try_send_encoded_request(wire_len) {
            Ok(sent) => Ok(sent),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                send_with_control(
                    prepared.send_encoded_request(wire_len),
                    control,
                    cancellation.cancelled(),
                    session_cancellation,
                    send_deadline,
                )
                .await
            }
            Err(_) => Err(SocksSendError::Io),
        }
    };
    match sent {
        Err(SocksSendError::ControlClosed) => return false,
        Ok(sent) if sent == wire_len => {}
        Ok(_) | Err(SocksSendError::Io) => {
            record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
            return false;
        }
        Err(SocksSendError::Cancelled) => {
            record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
            return false;
        }
        Err(SocksSendError::Idle) => {
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

#[cfg(test)]
pub(super) async fn relay_udp_association<IO: AsyncRead + AsyncWrite + Unpin>(
    endpoint: &mut SocksUdpEndpoint,
    prepared: &mut ClientUdpAssociation,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    routing: &ClientRouting,
) {
    let mut byte = [0];
    let Ok(mut session_cancellation) = prepared.cancellation() else {
        return;
    };
    loop {
        let Ok(deadline) = prepared.idle_deadline() else {
            return;
        };
        let candidate = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = session_cancellation.changed() => return,
            _ = tokio::time::sleep_until(deadline) => return,
            read = control.read(&mut byte) => { if !matches!(read, Ok(1)) { return; } continue; }
            received = receive_candidate(endpoint, context) => match received { Ok(Some(candidate)) => candidate, Ok(None) => continue, Err(_) => return },
        };
        match admit_request(endpoint, prepared, context, routing, candidate) {
            RequestDisposition::Admitted(first) => {
                relay_admitted(
                    endpoint,
                    prepared,
                    control,
                    cancellation,
                    context,
                    routing,
                    first,
                )
                .await;
                return;
            }
            RequestDisposition::Dropped => continue,
            RequestDisposition::Terminated => return,
        }
    }
}
