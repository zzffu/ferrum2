use std::pin::Pin;
use std::time::Instant;

use ferrum2_config::RouteAction;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;
use ferrum2_observability::Transport as ObservationTransport;
use ferrum2_rule::{RouteMetadata, RouteProgramAction, RuleCompileError};
use ferrum2_runtime::{PrefixDecision, SniffPrefix, SniffPrefixOutcome, collect_sniff_prefix};
use ferrum2_shadowsocks::PlainDuplex;
use ferrum2_sniff::{Progress as SniffProgress, Transport};

use super::outbound::ServerContext;
use crate::run::observation::record_sniff;
use crate::run::routing::{
    RouteProgramObservation, ServerTerminalRoute, route_metadata, sniff_order,
};

#[derive(Debug)]
pub(super) enum TcpRouteFailure {
    Cancelled,
    Read,
    Rule(RuleCompileError),
}

pub(super) struct TcpRouteSelection<P> {
    pub(super) terminal: ServerTerminalRoute,
    pub(super) prefix: TcpRoutePrefix<P>,
}

pub(super) enum TcpRoutePrefix<P> {
    Initial(P),
    Collected(SniffPrefix<P>),
}

impl<P: AsRef<[u8]>> AsRef<[u8]> for TcpRoutePrefix<P> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Initial(prefix) => prefix.as_ref(),
            Self::Collected(prefix) => prefix.as_ref(),
        }
    }
}

pub(super) async fn select_tcp_route<F, C, P>(
    context: &ServerContext,
    target: &TargetAddr,
    stream: &mut F,
    initial_payload: P,
    cancellation: C,
) -> Result<TcpRouteSelection<P>, TcpRouteFailure>
where
    F: PlainDuplex + Unpin,
    C: std::future::Future,
    P: AsRef<[u8]>,
{
    let mut prefix = TcpRoutePrefix::Initial(initial_payload);
    let program = context.routing.program();
    let mut scratch = match program.evaluation_scratch() {
        Ok(scratch) => scratch,
        Err(error) => {
            let _ = stream.mark_abortive_plain();
            return Err(TcpRouteFailure::Rule(error));
        }
    };
    let mut evaluation =
        program.evaluate_with_scratch(context.inbound, Network::Tcp, target, &mut scratch);
    evaluation.enable_match_observation();
    let mut protocol = None;
    let mut domain = None;
    let mut sniffed = false;
    let mut observation = RouteProgramObservation::new(&context.metrics);
    tokio::pin!(cancellation);

    loop {
        let started = Instant::now();
        let action = evaluation
            .next(RouteMetadata::new(protocol, domain.as_ref()))
            .expect("validated route program has one terminal action");
        observation.record_step(evaluation.candidate_visits(), started.elapsed());
        observation.record_matches(evaluation.last_match_observation());
        match action {
            RouteProgramAction::Continue(RouteAction::Sniff(sniffers)) if !sniffed => {
                sniffed = true;
                let order = sniff_order(sniffers, Network::Tcp);
                let max_bytes = program.sniff.max_bytes;
                let classification_horizon = max_bytes
                    .checked_add(1)
                    .expect("validated sniff maximum has one-byte horizon");
                let mut progress = if prefix.as_ref().len() > max_bytes {
                    SniffProgress::NeedMore
                } else {
                    ferrum2_sniff::sniff(
                        prefix.as_ref(),
                        classification_horizon,
                        Transport::Tcp,
                        target.port().get(),
                        &order,
                    )
                };
                let mut collector = None;
                if progress == SniffProgress::NeedMore {
                    let initial = match prefix {
                        TcpRoutePrefix::Initial(initial) => initial,
                        TcpRoutePrefix::Collected(_) => {
                            unreachable!("validated route program sniffs at most once")
                        }
                    };
                    let collected = collect_sniff_prefix(
                        initial,
                        max_bytes,
                        program.sniff.max_aggregate_bytes,
                        &context.registry,
                        program.sniff.timeout,
                        cancellation.as_mut(),
                        |context, destination| {
                            Pin::new(&mut *stream).poll_read_plain(context, destination)
                        },
                        |bytes| {
                            if ferrum2_sniff::sniff(
                                bytes,
                                classification_horizon,
                                Transport::Tcp,
                                target.port().get(),
                                &order,
                            ) == SniffProgress::NeedMore
                            {
                                PrefixDecision::ReadMore
                            } else {
                                PrefixDecision::Complete
                            }
                        },
                    )
                    .await;
                    let outcome = collected.outcome();
                    match outcome {
                        SniffPrefixOutcome::Complete => {
                            progress = ferrum2_sniff::sniff(
                                collected.as_ref(),
                                max_bytes,
                                Transport::Tcp,
                                target.port().get(),
                                &order,
                            );
                        }
                        SniffPrefixOutcome::Timeout
                        | SniffPrefixOutcome::Limit
                        | SniffPrefixOutcome::Unavailable => {
                            progress = SniffProgress::NoMatch;
                        }
                        SniffPrefixOutcome::Cancelled | SniffPrefixOutcome::ReadError => {
                            record_sniff(
                                &context.metrics,
                                ObservationTransport::Tcp,
                                progress,
                                Some(outcome),
                            );
                            let _ = stream.mark_abortive_plain();
                            return Err(match outcome {
                                SniffPrefixOutcome::Cancelled => TcpRouteFailure::Cancelled,
                                SniffPrefixOutcome::ReadError => TcpRouteFailure::Read,
                                _ => unreachable!("closed terminal prefix outcome"),
                            });
                        }
                    }
                    collector = Some(outcome);
                    prefix = TcpRoutePrefix::Collected(collected);
                }
                record_sniff(
                    &context.metrics,
                    ObservationTransport::Tcp,
                    progress.clone(),
                    collector,
                );
                (protocol, domain) = route_metadata(progress);
            }
            RouteProgramAction::Continue(RouteAction::Sniff(_)) => {}
            RouteProgramAction::Continue(_) => {
                let _ = stream.mark_abortive_plain();
                return Ok(TcpRouteSelection {
                    terminal: ServerTerminalRoute::Reject,
                    prefix,
                });
            }
            RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                let terminal = context.routing.terminal(action);
                if terminal == ServerTerminalRoute::Reject {
                    let _ = stream.mark_abortive_plain();
                }
                return Ok(TcpRouteSelection { terminal, prefix });
            }
        }
    }
}
