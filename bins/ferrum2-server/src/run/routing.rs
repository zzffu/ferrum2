use std::time::Duration;

use ferrum2_config::{CompiledRoute, RouteAction, RouteProtocol, Sniffers};
use ferrum2_core::DomainName;
use ferrum2_core::route::Network;
use ferrum2_observability::{Metrics, RuleMatchResult, RuleMatchType, RuleProgram, RuleSource};
use ferrum2_rule::{
    RouteMatchObservation as EngineMatchObservation, RouteMatchSource as EngineMatchSource,
    RouteMatchType as EngineMatchType, RuleCompileError, RuleEvaluationScratch,
};
use ferrum2_sniff::{Metadata as SniffMetadata, Progress as SniffProgress, Protocol};

pub(super) struct ServerRouting {
    pub(super) program: CompiledRoute,
    pub(super) outbound_count: usize,
}

pub(super) struct RouteProgramObservation<'a> {
    metrics: &'a Metrics,
    candidates: usize,
    match_ns: u64,
}

impl<'a> RouteProgramObservation<'a> {
    pub(super) const fn new(metrics: &'a Metrics) -> Self {
        Self {
            metrics,
            candidates: 0,
            match_ns: 0,
        }
    }

    pub(super) fn record_step(&mut self, candidates: usize, elapsed: Duration) {
        self.candidates = self.candidates.saturating_add(candidates);
        self.match_ns = self
            .match_ns
            .saturating_add(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
    }

    pub(super) fn record_matches(&self, observation: EngineMatchObservation) {
        for source in EngineMatchSource::ALL {
            for r#type in EngineMatchType::ALL {
                if !observation.evaluated(source, r#type) {
                    continue;
                }
                let result = if observation.matched(source, r#type) {
                    RuleMatchResult::Matched
                } else {
                    RuleMatchResult::Missed
                };
                let source = match source {
                    EngineMatchSource::Inline => RuleSource::Inline,
                    EngineMatchSource::RuleSet => RuleSource::RuleSet,
                };
                let r#type = match r#type {
                    EngineMatchType::Domain => RuleMatchType::Domain,
                    EngineMatchType::DomainSuffix => RuleMatchType::DomainSuffix,
                    EngineMatchType::DomainKeyword => RuleMatchType::DomainKeyword,
                    EngineMatchType::IpCidr => RuleMatchType::IpCidr,
                    EngineMatchType::Scalar => RuleMatchType::Scalar,
                };
                self.metrics.route_match(source, r#type, result);
            }
        }
    }
}

impl Drop for RouteProgramObservation<'_> {
    fn drop(&mut self) {
        self.metrics
            .observe_rule_program_candidate_count(RuleProgram::Route, self.candidates);
        self.metrics
            .observe_rule_program_match_ns(RuleProgram::Route, self.match_ns);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerTerminalRoute {
    Direct(usize),
    Reject,
}

impl ServerRouting {
    pub(super) const fn program(&self) -> &CompiledRoute {
        &self.program
    }

    pub(super) fn route_scratch(&self) -> Result<RuleEvaluationScratch, RuleCompileError> {
        self.program.evaluation_scratch()
    }

    pub(super) fn terminal(&self, action: &RouteAction) -> ServerTerminalRoute {
        match action {
            RouteAction::Route(handle) => match handle.snapshot().hops() {
                [outbound] if *outbound < self.outbound_count => {
                    ServerTerminalRoute::Direct(*outbound)
                }
                _ => ServerTerminalRoute::Reject,
            },
            RouteAction::Sniff(_) | RouteAction::HijackDns | RouteAction::Reject => {
                ServerTerminalRoute::Reject
            }
        }
    }
}

pub(super) fn sniff_order(sniffers: &Sniffers, network: Network) -> Vec<Protocol> {
    match sniffers {
        Sniffers::Default => match network {
            Network::Tcp => vec![Protocol::Dns, Protocol::Tls, Protocol::Http],
            Network::Udp => vec![Protocol::Dns],
        },
        Sniffers::Explicit(protocols) => protocols
            .iter()
            .copied()
            .map(|protocol| match protocol {
                RouteProtocol::Dns => Protocol::Dns,
                RouteProtocol::Tls => Protocol::Tls,
                RouteProtocol::Http => Protocol::Http,
            })
            .collect(),
    }
}

pub(super) fn route_metadata(
    progress: SniffProgress,
) -> (Option<RouteProtocol>, Option<DomainName>) {
    let (protocol, domain) = match progress {
        SniffProgress::Matched(SniffMetadata::Dns { domain }) => (RouteProtocol::Dns, Some(domain)),
        SniffProgress::Matched(SniffMetadata::Tls { domain }) => (RouteProtocol::Tls, domain),
        SniffProgress::Matched(SniffMetadata::Http { domain }) => (RouteProtocol::Http, domain),
        SniffProgress::NeedMore | SniffProgress::NoMatch | SniffProgress::Invalid => {
            return (None, None);
        }
    };
    match domain.map(|domain| DomainName::new(&domain)).transpose() {
        Ok(domain) => (Some(protocol), domain),
        Err(_) => (None, None),
    }
}
