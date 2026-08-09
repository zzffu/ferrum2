use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use ferrum2_config::{RouteAction, RouteProtocol, Sniffers};
use ferrum2_core::route::{EgressPlanSnapshot, Network, RouteMetadata, RouteProgramAction};
use ferrum2_core::{DomainName, TargetAddr};
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
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
    pub(super) fn select_terminal(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
        payload: Option<&[u8]>,
        metrics: &ferrum2_observability::Metrics,
    ) -> ClientTerminalRoute {
        let Some(program) = self.program.as_ref() else {
            return ClientTerminalRoute::Route(
                self.legacy.select_plan_snapshot(inbound, network, target),
            );
        };
        let mut evaluation = program.evaluate(inbound, network, target);
        let mut protocol = None;
        let mut domain = None;
        let mut sniffed = false;
        loop {
            match evaluation
                .next(RouteMetadata::new(protocol, domain.as_ref()))
                .expect("validated client route program has one terminal action")
            {
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
                RouteProgramAction::Continue(_) => return ClientTerminalRoute::Reject,
                RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                    return terminal(action);
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
        metrics: &ferrum2_observability::Metrics,
    ) -> Option<TcpRouteSelection>
    where
        IO: AsyncRead + Unpin,
        C: Future,
    {
        let Some(program) = self.program.as_ref() else {
            return Some(TcpRouteSelection {
                terminal: ClientTerminalRoute::Route(self.legacy.select_plan_snapshot(
                    inbound,
                    Network::Tcp,
                    target,
                )),
                prefix: TcpRoutePrefix::Empty,
            });
        };
        let mut evaluation = program.evaluate(inbound, Network::Tcp, target);
        let mut protocol = None;
        let mut domain = None;
        let mut prefix = TcpRoutePrefix::Empty;
        let mut sniffed = false;
        tokio::pin!(cancellation);
        loop {
            match evaluation
                .next(RouteMetadata::new(protocol, domain.as_ref()))
                .expect("validated client route program has one terminal action")
            {
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
                            return None;
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
                    return Some(TcpRouteSelection {
                        terminal: ClientTerminalRoute::Reject,
                        prefix,
                    });
                }
                RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                    return Some(TcpRouteSelection {
                        terminal: terminal(action),
                        prefix,
                    });
                }
            }
        }
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
