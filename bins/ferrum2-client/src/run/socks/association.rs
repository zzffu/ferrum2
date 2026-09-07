use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ferrum2_core::route::Network;
use ferrum2_core::{ConnectErrorKind, SessionReply as _};
use ferrum2_observability::{Outcome, Reason, Stage};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::{SocksStream, SocksUdpAssociate};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::net::UdpSocket;

use super::admission::{RequestDisposition, SocksUdpEndpoint, admit_request, receive_candidate};
use super::dns_hijack::{DnsDisposition, answer_hijacked_udp, relay_hijacked_udp};
use super::relay::relay_admitted;
use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::ClientRequestOrigin;
use crate::run::observation::record_udp_terminal;
use crate::run::routing::ClientTerminalRoute;

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

pub(super) async fn classify_udp_association<IO: AsyncRead + AsyncWrite + Unpin>(
    mut endpoint: SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    routing: &ClientRouting,
) {
    let mut control_byte = [0];
    let Ok(mut route_scratch) = routing.route_scratch() else {
        return;
    };
    loop {
        let idle_deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let candidate = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep_until(idle_deadline) => return,
            read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return; } continue; }
            received = receive_candidate(&mut endpoint, context) => match received {
                Ok(Some(candidate)) => candidate, Ok(None) => continue,
                Err(_) => { record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed); return; }
            },
        };
        let Ok(terminal) = routing.select_terminal_with_scratch(
            inbound,
            Network::Udp,
            &candidate.target,
            Some(&candidate.payload),
            &context.metrics,
            &mut route_scratch,
        ) else {
            return;
        };
        match terminal {
            ClientTerminalRoute::Reject => return,
            ClientTerminalRoute::Route(plan) => {
                let prepared = {
                    let preparing = context.egress.prepare_udp_for_ingress(
                        ClientRequestOrigin::Socks,
                        inbound,
                        Some(plan),
                        Some(&candidate.target),
                    );
                    tokio::pin!(preparing);
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => return,
                            _ = tokio::time::sleep_until(idle_deadline) => return,
                            read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return; } }
                            prepared = &mut preparing => break prepared,
                        }
                    }
                };
                let Ok(mut prepared) = prepared else {
                    record_udp_terminal(
                        context,
                        Stage::Shadowsocks,
                        Reason::Random,
                        Outcome::Failed,
                    );
                    return;
                };
                match admit_request(&mut endpoint, &mut prepared, context, routing, candidate) {
                    RequestDisposition::Admitted(first) => {
                        relay_admitted(
                            &mut endpoint,
                            &mut prepared,
                            control,
                            cancellation,
                            context,
                            routing,
                            first,
                        )
                        .await;
                        return;
                    }
                    // Drop the entire provisional path and its frozen route before
                    // receiving the next source candidate and selecting its route.
                    RequestDisposition::Dropped => continue,
                    RequestDisposition::Terminated => return,
                }
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
                match answer_hijacked_udp(
                    &mut endpoint,
                    control,
                    cancellation,
                    inbound,
                    &proxy,
                    candidate,
                    context.runtime.idle_timeout,
                )
                .await
                {
                    DnsDisposition::Admitted => {
                        relay_hijacked_udp(
                            &mut endpoint,
                            control,
                            cancellation,
                            context,
                            inbound,
                            &proxy,
                        )
                        .await;
                        return;
                    }
                    DnsDisposition::Dropped => continue,
                    DnsDisposition::Terminated => return,
                }
            }
        }
    }
}
