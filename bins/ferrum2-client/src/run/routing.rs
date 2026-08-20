use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ferrum2_config::{RouteAction, RouteProtocol, Sniffers};
use ferrum2_core::route::{EgressPlanSnapshot, Network};
use ferrum2_core::{DomainName, TargetAddr};
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_observability::{Metrics, RuleMatchResult, RuleMatchType, RuleProgram, RuleSource};
use ferrum2_rule::{
    RouteMatchObservation, RouteMatchSource as EngineMatchSource, RouteMatchType as EngineMatchType,
};
use ferrum2_rule::{RouteMetadata, RouteProgramAction, RuleCompileError, RuleEvaluationScratch};
use ferrum2_runtime::{PrefixDecision, SniffPrefix, SniffPrefixOutcome, collect_sniff_prefix};
use ferrum2_sniff::{Metadata as SniffMetadata, Progress as SniffProgress, Protocol, Transport};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use super::context::ClientRouting;
use super::observation::record_sniff;

pub(super) enum ClientTerminalRoute {
    Route(EgressPlanSnapshot),
    HijackDns,
    Reject,
}

pub(super) struct TcpRouteSelection {
    pub(super) terminal: ClientTerminalRoute,
    pub(super) prefix: TcpRoutePrefix,
}

pub(super) enum TcpRoutePrefix {
    Empty,
    Collected(SniffPrefix<&'static [u8]>),
}

impl AsRef<[u8]> for TcpRoutePrefix {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Collected(prefix) => prefix.as_ref(),
        }
    }
}

impl ClientRouting {
    pub(super) fn route_scratch(&self) -> Result<Option<RuleEvaluationScratch>, RuleCompileError> {
        self.program
            .as_ref()
            .map(ferrum2_config::CompiledRoute::evaluation_scratch)
            .transpose()
    }

    pub(super) fn select_terminal_with_scratch(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
        payload: Option<&[u8]>,
        metrics: &Metrics,
        scratch: Option<&mut RuleEvaluationScratch>,
    ) -> Result<ClientTerminalRoute, RuleCompileError> {
        let Some(program) = self.program.as_ref() else {
            return Ok(ClientTerminalRoute::Route(
                self.legacy.select_plan_snapshot(inbound, network, target),
            ));
        };
        let Some(scratch) = scratch else {
            return Err(RuleCompileError::Internal);
        };
        let mut evaluation = program.evaluate_with_scratch(inbound, network, target, scratch);
        evaluation.enable_match_observation();
        let mut observation = RouteProgramObservation::new(metrics);
        let mut protocol = None;
        let mut domain = None;
        let mut sniffed = false;
        loop {
            let started = Instant::now();
            let action = evaluation
                .next(RouteMetadata::new(protocol, domain.as_ref()))
                .expect("validated client route program has one terminal action");
            observation.record_step(evaluation.candidate_visits(), started.elapsed());
            observation.record_matches(evaluation.last_match_observation());
            match action {
                RouteProgramAction::Continue(RouteAction::Sniff(_)) if !sniffed => {
                    sniffed = true;
                    let Some(payload) = payload else {
                        continue;
                    };
                    let (progress, limited) = if payload.len() > program.sniff.max_bytes {
                        (SniffProgress::NoMatch, true)
                    } else {
                        (
                            ferrum2_sniff::sniff(
                                payload,
                                program.sniff.max_bytes,
                                Transport::Udp,
                                target.port().get(),
                                &[Protocol::Dns],
                            ),
                            false,
                        )
                    };
                    record_sniff(metrics, progress.clone(), limited);
                    (protocol, domain) = route_metadata(progress);
                }
                RouteProgramAction::Continue(RouteAction::Sniff(_)) => {}
                RouteProgramAction::Continue(_) => return Ok(ClientTerminalRoute::Reject),
                RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                    return Ok(terminal(action));
                }
            }
        }
    }

    pub(super) async fn select_tcp<IO, C>(
        &self,
        inbound: usize,
        target: &TargetAddr,
        stream: &mut IO,
        cancellation: C,
        registry: &ferrum2_runtime::OwnerRegistry,
        metrics: &Metrics,
    ) -> Result<Option<TcpRouteSelection>, RuleCompileError>
    where
        IO: AsyncRead + Unpin,
        C: Future,
    {
        let Some(program) = self.program.as_ref() else {
            return Ok(Some(TcpRouteSelection {
                terminal: ClientTerminalRoute::Route(self.legacy.select_plan_snapshot(
                    inbound,
                    Network::Tcp,
                    target,
                )),
                prefix: TcpRoutePrefix::Empty,
            }));
        };
        let mut scratch = program.evaluation_scratch()?;
        let mut evaluation =
            program.evaluate_with_scratch(inbound, Network::Tcp, target, &mut scratch);
        evaluation.enable_match_observation();
        let mut observation = RouteProgramObservation::new(metrics);
        let mut protocol = None;
        let mut domain = None;
        let mut prefix = TcpRoutePrefix::Empty;
        let mut sniffed = false;
        tokio::pin!(cancellation);
        loop {
            let started = Instant::now();
            let action = evaluation
                .next(RouteMetadata::new(protocol, domain.as_ref()))
                .expect("validated client route program has one terminal action");
            observation.record_step(evaluation.candidate_visits(), started.elapsed());
            observation.record_matches(evaluation.last_match_observation());
            match action {
                RouteProgramAction::Continue(RouteAction::Sniff(sniffers)) if !sniffed => {
                    sniffed = true;
                    let order = sniff_order(sniffers);
                    let horizon = program.sniff.max_bytes + 1;
                    let collected = collect_sniff_prefix(
                        &[][..],
                        program.sniff.max_bytes,
                        program.sniff.max_aggregate_bytes,
                        registry,
                        program.sniff.timeout,
                        cancellation.as_mut(),
                        |context, destination| {
                            let mut destination = ReadBuf::new(destination);
                            match Pin::new(&mut *stream).poll_read(context, &mut destination) {
                                Poll::Ready(Ok(())) => {
                                    Poll::Ready(Ok::<_, io::Error>(destination.filled().len()))
                                }
                                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                                Poll::Pending => Poll::Pending,
                            }
                        },
                        |bytes| {
                            if ferrum2_sniff::sniff(
                                bytes,
                                horizon,
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
                    let progress = match outcome {
                        SniffPrefixOutcome::Complete => ferrum2_sniff::sniff(
                            collected.as_ref(),
                            program.sniff.max_bytes,
                            Transport::Tcp,
                            target.port().get(),
                            &order,
                        ),
                        SniffPrefixOutcome::Timeout
                        | SniffPrefixOutcome::Limit
                        | SniffPrefixOutcome::Unavailable => SniffProgress::NoMatch,
                        SniffPrefixOutcome::Cancelled | SniffPrefixOutcome::ReadError => {
                            record_sniff(metrics, SniffProgress::NoMatch, false);
                            return Ok(None);
                        }
                    };
                    record_sniff(
                        metrics,
                        progress.clone(),
                        outcome == SniffPrefixOutcome::Limit,
                    );
                    (protocol, domain) = route_metadata(progress);
                    prefix = TcpRoutePrefix::Collected(collected);
                }
                RouteProgramAction::Continue(RouteAction::Sniff(_)) => {}
                RouteProgramAction::Continue(_) => {
                    return Ok(Some(TcpRouteSelection {
                        terminal: ClientTerminalRoute::Reject,
                        prefix,
                    }));
                }
                RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                    return Ok(Some(TcpRouteSelection {
                        terminal: terminal(action),
                        prefix,
                    }));
                }
            }
        }
    }
}

struct RouteProgramObservation<'a> {
    metrics: &'a Metrics,
    candidates: usize,
    match_ns: u64,
}

impl<'a> RouteProgramObservation<'a> {
    const fn new(metrics: &'a Metrics) -> Self {
        Self {
            metrics,
            candidates: 0,
            match_ns: 0,
        }
    }

    fn record_step(&mut self, candidates: usize, elapsed: Duration) {
        self.candidates = self.candidates.saturating_add(candidates);
        self.match_ns = self
            .match_ns
            .saturating_add(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
    }

    fn record_matches(&self, observation: RouteMatchObservation) {
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

fn terminal(action: &RouteAction) -> ClientTerminalRoute {
    match action {
        RouteAction::Route(handle) => ClientTerminalRoute::Route(handle.snapshot_owned()),
        RouteAction::HijackDns => ClientTerminalRoute::HijackDns,
        RouteAction::Reject | RouteAction::Sniff(_) => ClientTerminalRoute::Reject,
    }
}

fn sniff_order(sniffers: &Sniffers) -> Vec<Protocol> {
    match sniffers {
        Sniffers::Default => vec![Protocol::Dns, Protocol::Tls, Protocol::Http],
        Sniffers::Explicit(protocols) => protocols
            .iter()
            .map(|protocol| match protocol {
                RouteProtocol::Dns => Protocol::Dns,
                RouteProtocol::Tls => Protocol::Tls,
                RouteProtocol::Http => Protocol::Http,
            })
            .collect(),
    }
}

fn route_metadata(progress: SniffProgress) -> (Option<RouteProtocol>, Option<DomainName>) {
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

pub(super) struct ReplayIo<IO> {
    io: IO,
    prefix: TcpRoutePrefix,
    offset: usize,
}

impl<IO> ReplayIo<IO> {
    pub(super) const fn new(io: IO, prefix: TcpRoutePrefix) -> Self {
        Self {
            io,
            prefix,
            offset: 0,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for ReplayIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let prefix = self.prefix.as_ref();
        if self.offset < prefix.len() {
            let count = destination.remaining().min(prefix.len() - self.offset);
            destination.put_slice(&prefix[self.offset..self.offset + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(context, destination)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ReplayIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, source)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}

pub(super) async fn relay_hijacked_tcp<IO, C>(
    stream: &mut IO,
    inbound: usize,
    proxy: &DnsProxy,
    idle_timeout: std::time::Duration,
    cancellation: C,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Future,
{
    tokio::pin!(cancellation);
    loop {
        let exchange = async {
            let length = stream.read_u16().await?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "empty DNS frame",
                ));
            }
            let mut request = vec![0; usize::from(length)];
            stream.read_exact(&mut request).await?;
            let response = proxy
                .answer(
                    ProxyIngress::Ordinary(inbound),
                    ProxyTransport::Tcp,
                    &request,
                )
                .await
                .ok_or_else(|| io::Error::other("DNS answer unavailable"))?;
            let length = u16::try_from(response.len())
                .map_err(|_| io::Error::other("DNS answer exceeds TCP frame"))?;
            stream.write_u16(length).await?;
            stream.write_all(&response).await
        };
        let result = tokio::select! {
            _ = cancellation.as_mut() => return,
            result = tokio::time::timeout(idle_timeout, exchange) => result,
        };
        if !matches!(result, Ok(Ok(()))) {
            return;
        }
    }
}

#[cfg(test)]
mod match_observation_tests {
    use ferrum2_rule::{
        MatchSetBuilder, OrderedRouteProgram, OrderedRouteRule, RouteMatchField, RouteMatcher,
        RouteRuleAction,
    };

    use super::*;

    #[test]
    fn selected_composite_exports_exact_match_and_closed_category_misses() {
        let mut builder = MatchSetBuilder::new();
        builder
            .add_exact_domain("www.example.test")
            .expect("exact")
            .add_domain_suffix("other.invalid")
            .expect("suffix")
            .add_domain_keyword("missing-token")
            .expect("keyword");
        let matcher = RouteMatcher::<()>::try_new(vec![RouteMatchField::MatchSet(
            builder.build().expect("match set"),
        )])
        .expect("matcher");
        let program = OrderedRouteProgram::try_new(
            vec![OrderedRouteRule::new(
                matcher,
                RouteRuleAction::Terminal(()),
            )],
            (),
        )
        .expect("program");
        let mut scratch = program.evaluation_scratch().expect("scratch");
        let target = TargetAddr::domain("www.example.test", 443).expect("target");
        let mut evaluation = program.evaluate_with_scratch(0, Network::Tcp, &target, &mut scratch);
        evaluation.enable_match_observation();
        assert!(matches!(
            evaluation.next(RouteMetadata::new(None, None)),
            Some(RouteProgramAction::Terminal(_))
        ));

        let metrics = Metrics::new();
        RouteProgramObservation::new(&metrics).record_matches(evaluation.last_match_observation());
        let encoded = metrics.encode_text().expect("metrics");
        for expected in [
            "ferrum2_route_match_total{source=\"inline\",type=\"domain\",result=\"matched\"} 1",
            "ferrum2_route_match_total{source=\"inline\",type=\"domain_suffix\",result=\"missed\"} 1",
            "ferrum2_route_match_total{source=\"inline\",type=\"domain_keyword\",result=\"missed\"} 1",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
    }
}
