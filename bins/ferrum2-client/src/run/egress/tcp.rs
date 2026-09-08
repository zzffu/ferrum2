use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_core::{ConnectErrorKind, Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, SecureRandom};
use ferrum2_shadowsocks::{
    BoxedClientFlow, ClientTcpOutbound, FlowTerminal, PlainDuplex, ShadowsocksError, TransportIo,
    TransportPhase,
};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};

use super::context::ClientOutboundContext;
use super::engine::ClientOpenFailure;

pub(in crate::run) enum ClientTcpFlow<'a, S> {
    Direct(S),
    Proxy(BoxedClientFlow<'a>),
    F2p(Box<ferrum2_f2p::ClientStream<super::f2p::SuppliedIo<S>>>),
}

impl<S> LocalEndpoint for ClientTcpFlow<'_, S>
where
    S: LocalEndpoint,
{
    fn local_socket_addr(&self) -> std::net::SocketAddr {
        match self {
            Self::Direct(stream) => stream.local_socket_addr(),
            Self::Proxy(flow) => flow.local_socket_addr(),
            Self::F2p(stream) => stream.local_socket_addr(),
        }
    }
}

impl<S> PlainDuplex for ClientTcpFlow<'_, S>
where
    S: TransportIo + LocalEndpoint,
{
    fn poll_read_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_read(context, destination)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Read)),
            Self::Proxy(flow) => Pin::new(flow).poll_read_plain(context, destination),
            Self::F2p(stream) => {
                let mut buffer = tokio::io::ReadBuf::new(destination);
                match tokio::io::AsyncRead::poll_read(Pin::new(stream), context, &mut buffer) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
                    Poll::Ready(Err(_)) => {
                        Poll::Ready(Err(ShadowsocksError::Transport(TransportPhase::Read)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_write_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_write(context, source)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Write)),
            Self::Proxy(flow) => Pin::new(flow).poll_write_plain(context, source),
            Self::F2p(stream) => {
                tokio::io::AsyncWrite::poll_write(Pin::new(stream), context, source)
                    .map_err(|_| ShadowsocksError::Transport(TransportPhase::Write))
            }
        }
    }

    fn poll_flush_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_flush(context)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Flush)),
            Self::Proxy(flow) => Pin::new(flow).poll_flush_plain(context),
            Self::F2p(stream) => tokio::io::AsyncWrite::poll_flush(Pin::new(stream), context)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Flush)),
        }
    }

    fn poll_shutdown_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_shutdown(context)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown)),
            Self::Proxy(flow) => Pin::new(flow).poll_shutdown_plain(context),
            Self::F2p(stream) => tokio::io::AsyncWrite::poll_shutdown(Pin::new(stream), context)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown)),
        }
    }

    fn mark_abortive_plain(&mut self) -> Result<(), ShadowsocksError> {
        match self {
            Self::Direct(stream) => stream
                .mark_abortive()
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown)),
            Self::Proxy(flow) => flow.mark_abortive_plain(),
            Self::F2p(stream) => ferrum2_core::AbortiveClose::mark_abortive(stream.as_mut())
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown)),
        }
    }

    fn terminal(&self) -> Option<FlowTerminal> {
        match self {
            Self::Direct(_) | Self::F2p(_) => None,
            Self::Proxy(flow) => flow.terminal(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn open<'a, C, T, R>(
    outbounds: &'a [ClientOutboundContext],
    plan: &[usize],
    connector: &'a C,
    clock: &'a T,
    random: &'a R,
    application_target: &TargetAddr,
    deadlines: (Duration, Duration),
    #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
) -> Result<BoxedClientFlow<'a>, ClientOpenFailure>
where
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint + 'a,
    T: Clock + Sync,
    R: SecureRandom,
{
    let first = outbounds[plan[0]]
        .shadowsocks()
        .expect("classified Shadowsocks plan");
    let outbound = ClientTcpOutbound::new(
        first.tcp_server.clone(),
        &first.keys,
        connector,
        clock,
        random,
    );
    #[cfg(test)]
    let outbound = match observers {
        Some((buffer, flow)) => outbound.with_observers(buffer, flow),
        None => outbound,
    };
    let connected = tokio::time::timeout(deadlines.0, outbound.connect_server())
        .await
        .map_err(|_| {
            ClientOpenFailure::Protocol(ShadowsocksError::Connect(ConnectErrorKind::Timeout))
        })?
        .map_err(ClientOpenFailure::Protocol)?;
    tokio::time::timeout(deadlines.1, async {
        let first_target = plan.get(1).map_or(application_target, |next| {
            &outbounds[*next]
                .shadowsocks()
                .expect("classified Shadowsocks plan")
                .tcp_server
        });
        let mut flow = connected.write_request(first_target).await?.into_boxed();
        for (position, index) in plan.iter().copied().enumerate().skip(1) {
            let hop = outbounds[index]
                .shadowsocks()
                .expect("classified Shadowsocks plan");
            let next_target = plan.get(position + 1).map_or(application_target, |next| {
                &outbounds[*next]
                    .shadowsocks()
                    .expect("classified Shadowsocks plan")
                    .tcp_server
            });
            let outbound =
                ClientTcpOutbound::new(hop.tcp_server.clone(), &hop.keys, connector, clock, random);
            #[cfg(test)]
            let outbound = match observers {
                Some((buffer, flow)) => outbound.with_observers(buffer, flow),
                None => outbound,
            };
            flow = outbound
                .write_request_on(flow, next_target)
                .await?
                .into_boxed();
        }
        if plan.len() > 1 {
            std::future::poll_fn(|cx| Pin::new(&mut flow).poll_flush_plain(cx)).await?;
        }
        Ok(flow)
    })
    .await
    .map_err(|_| ClientOpenFailure::HandshakeTimeout)?
    .map_err(ClientOpenFailure::Protocol)
}

#[cfg(test)]
mod tests;
