use ferrum2_config::RouteAction;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;
use ferrum2_observability::{Metrics, Transport as ObservationTransport};
use ferrum2_rule::{RouteMetadata, RouteProgramAction, RuleCompileError, RuleEvaluationScratch};
use ferrum2_runtime::SniffPrefixOutcome;
use ferrum2_sniff::{Progress as SniffProgress, Transport as SniffTransport};
use tokio::time::Instant;

use crate::run::observation::record_sniff;
use crate::run::routing::{
    RouteProgramObservation, ServerRouting, ServerTerminalRoute, route_metadata, sniff_order,
};

pub(super) fn select_udp_route(
    routing: &ServerRouting,
    inbound: usize,
    target: &TargetAddr,
    payload: &[u8],
    metrics: &Metrics,
    scratch: &mut RuleEvaluationScratch,
) -> Result<ServerTerminalRoute, RuleCompileError> {
    let program = routing.program();
    let mut evaluation = program.evaluate_with_scratch(inbound, Network::Udp, target, scratch);
    evaluation.enable_match_observation();
    let mut protocol = None;
    let mut domain = None;
    let mut sniffed = false;
    let mut observation = RouteProgramObservation::new(metrics);
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
                let order = sniff_order(sniffers, Network::Udp);
                let (progress, collector) = if payload.len() > program.sniff.max_bytes {
                    (SniffProgress::NoMatch, Some(SniffPrefixOutcome::Limit))
                } else {
                    (
                        ferrum2_sniff::sniff(
                            payload,
                            program.sniff.max_bytes,
                            SniffTransport::Udp,
                            target.port().get(),
                            &order,
                        ),
                        None,
                    )
                };
                record_sniff(
                    metrics,
                    ObservationTransport::Udp,
                    progress.clone(),
                    collector,
                );
                (protocol, domain) = route_metadata(progress);
            }
            RouteProgramAction::Continue(RouteAction::Sniff(_)) => {}
            RouteProgramAction::Continue(_) => return Ok(ServerTerminalRoute::Reject),
            RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                return Ok(routing.terminal(action));
            }
        }
    }
}
