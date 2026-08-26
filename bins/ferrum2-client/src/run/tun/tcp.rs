use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_runtime::{ProcessCancellation, relay_lifecycle};
use ferrum2_shadowsocks::tokio::TokioFramed;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::ClientRequestOrigin;
use crate::run::routing::{ClientTerminalRoute, ReplayIo, relay_hijacked_tcp};

use super::udp::{SyntheticDns, wait_for_session_cancellation};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_tcp<IO>(
    target: SocketAddr,
    mut flow: IO,
    mut cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: Option<ferrum2_tun::SessionCancellation>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if synthetic_dns.matches(target) {
        let Some(proxy) = context
            .dns
            .as_ref()
            .and_then(|proxy| proxy.get())
            .map(Arc::clone)
        else {
            return;
        };
        let mut process_cancelled = cancellation.clone();
        relay_hijacked_tcp(
            &mut flow,
            inbound,
            &proxy,
            context.runtime.idle_timeout,
            async {
                tokio::select! {
                    () = process_cancelled.forced() => {},
                    () = wait_for_session_cancellation(&session_cancellation) => {},
                }
            },
        )
        .await;
        return;
    }
    let Ok(target) = TargetAddr::ip(target) else {
        return;
    };
    let mut process_cancelled = cancellation.clone();
    let Ok(Some(selection)) = routing
        .select_tcp(
            inbound,
            &target,
            &mut flow,
            async {
                tokio::select! {
                    () = process_cancelled.forced() => {},
                    () = wait_for_session_cancellation(&session_cancellation) => {},
                }
            },
            &context.registry,
            &context.metrics,
        )
        .await
    else {
        return;
    };
    let mut flow = ReplayIo::new(flow, selection.prefix);
    match selection.terminal {
        ClientTerminalRoute::Reject => {}
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                return;
            };
            let mut process_cancelled = cancellation.clone();
            relay_hijacked_tcp(
                &mut flow,
                inbound,
                &proxy,
                context.runtime.idle_timeout,
                async {
                    tokio::select! {
                        () = process_cancelled.forced() => {},
                        () = wait_for_session_cancellation(&session_cancellation) => {},
                    }
                },
            )
            .await;
        }
        ClientTerminalRoute::Route(plan) => {
            let opened = tokio::select! {
                _ = cancellation.forced() => return,
                () = wait_for_session_cancellation(&session_cancellation) => return,
                opened = context.egress.open_tcp_for_ingress(
                    ClientRequestOrigin::Tun,
                    inbound,
                    Some(plan),
                    &target,
                    None,
                    #[cfg(test)]
                    None,
                ) => opened,
            };
            let Ok(opened) = opened else {
                return;
            };
            let mut opened = TokioFramed::new(opened);
            let mut process_cancelled = cancellation.clone();
            let _ = relay_lifecycle(
                &mut flow,
                &mut opened,
                context.runtime.idle_timeout,
                &context.registry,
                async {
                    tokio::select! {
                        () = process_cancelled.forced() => {},
                        () = wait_for_session_cancellation(&session_cancellation) => {},
                    }
                },
            )
            .await;
        }
    }
}

pub(super) fn is_synthetic_dns_target(target: &TargetAddr, synthetic_dns: SyntheticDns) -> bool {
    target
        .as_socket_addr()
        .is_some_and(|target| synthetic_dns.matches(target))
}
