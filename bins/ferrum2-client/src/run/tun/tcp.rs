use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_runtime::ProcessCancellation;
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
    let observed_target = TargetAddr::ip(target).ok();
    let observation = context.observe("tcp", "tun", None, observed_target.as_ref());
    if synthetic_dns.matches(target) {
        if let Some(observation) = &observation {
            observation.set_tun_dns_route();
        }
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
            observation.as_ref(),
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
                    () = crate::run::context::observation_cancelled(observation.as_ref()) => {},
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
        ClientTerminalRoute::Reject => {
            if let Some(observation) = &observation {
                observation.set_terminal_route(selection.rule_index, "拒绝");
                observation.finish("rejected");
            }
        }
        ClientTerminalRoute::HijackDns => {
            if let Some(observation) = &observation {
                observation.set_terminal_route(selection.rule_index, "DNS 接管");
            }
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
                observation.as_ref(),
            )
            .await;
        }
        ClientTerminalRoute::Route(plan) => {
            crate::run::context::observe_route(observation.as_ref(), &plan, selection.rule_index);
            let opened = tokio::select! {
                () = crate::run::context::observation_cancelled(observation.as_ref()) => {
                    if let Some(observation) = &observation { observation.finish("cancelled"); }
                    return;
                },
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
                if let Some(observation) = &observation {
                    observation.finish("connect_error");
                }
                return;
            };
            let mut opened = TokioFramed::new(opened);
            let mut process_cancelled = cancellation.clone();
            let _ = context
                .relay_tcp(
                    &mut flow,
                    &mut opened,
                    // TcpFlow exposes only the original destination, not the application source.
                    None,
                    &target,
                    async {
                        tokio::select! {
                            () = process_cancelled.forced() => {},
                            () = wait_for_session_cancellation(&session_cancellation) => {},
                        }
                    },
                    observation.as_ref(),
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
