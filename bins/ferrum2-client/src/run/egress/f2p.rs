use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_core::{AbortiveClose, LocalEndpoint, TargetAddr};
use ferrum2_f2p::{ClientConfig, ClientTunnel, Profile};
use ferrum2_net::{DialOptions, RouteNetworkOptions};
use ferrum2_runtime::{MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget};
use ferrum2_shadowsocks::TransportIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::network::ClientPhysicalConnector;
use crate::run::RunError;

// This adapter belongs at the binary boundary: the physical socket service still
// owns every dial, while the protocol receives only the supplied byte stream.
pub(in crate::run) struct SuppliedIo<S>(pub(super) S);
impl<S: LocalEndpoint> LocalEndpoint for SuppliedIo<S> {
    fn local_socket_addr(&self) -> SocketAddr {
        self.0.local_socket_addr()
    }
}
impl<S: AbortiveClose> AbortiveClose for SuppliedIo<S> {
    type Error = S::Error;
    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.0.mark_abortive()
    }
}
impl<S: TransportIo> AsyncRead for SuppliedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.0).poll_read(cx, buf.initialize_unfilled()) {
            Poll::Ready(Ok(length)) => {
                buf.advance(length);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(io::Error::other("physical stream read failed")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl<S: TransportIo> AsyncWrite for SuppliedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0)
            .poll_write(cx, bytes)
            .map_err(|_| io::Error::other("physical stream write failed"))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(|_| io::Error::other("physical stream flush failed"))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0)
            .poll_shutdown(cx)
            .map_err(|_| io::Error::other("physical stream shutdown failed"))
    }
}

pub(in crate::run) struct ClientF2pContext {
    pub(super) server: TargetAddr,
    pub(super) config: Arc<ClientConfig>,
    pub(super) profile: Profile,
    pub(super) dial_options: DialOptions,
    pool: Mutex<PoolState>,
    dialing: tokio::sync::Mutex<()>,
    runtime: tokio::runtime::Handle,
}
#[derive(Default)]
struct PoolState {
    epoch: u64,
    fenced: bool,
    tunnel: Option<Arc<ClientTunnel>>,
}
impl ClientF2pContext {
    pub(in crate::run) fn new(
        server: SocketAddr,
        config: Arc<ClientConfig>,
        profile: Profile,
        dial_options: DialOptions,
    ) -> Result<Self, RunError> {
        Ok(Self {
            server: TargetAddr::ip(server).map_err(|_| RunError::StartupProtocol)?,
            config,
            profile,
            dial_options,
            pool: Mutex::new(PoolState::default()),
            dialing: tokio::sync::Mutex::new(()),
            runtime: tokio::runtime::Handle::try_current().map_err(|_| RunError::StartupRuntime)?,
        })
    }
    fn retire(&self) -> Option<Arc<ClientTunnel>> {
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pool.fenced = true;
        pool.epoch = pool.epoch.wrapping_add(1);
        pool.tunnel.take()
    }
    pub(super) fn fence(&self) {
        if let Some(tunnel) = self.retire() {
            tunnel.close();
        }
    }

    pub(in crate::run) async fn shutdown(&self) -> Result<(), RunError> {
        if let Some(tunnel) = self.retire() {
            tunnel
                .shutdown()
                .await
                .map_err(|_| RunError::ShutdownCleanup)?;
        }
        Ok(())
    }
    pub(super) fn reopen(&self) {
        self.pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fenced = false;
    }
    pub(super) async fn tunnel<C: ClientPhysicalConnector>(
        &self,
        connector: &Arc<C>,
        route: &RouteNetworkOptions,
        budget: &UdpBufferBudget,
        deadlines: (Duration, Duration),
        runtime_limits: ferrum2_runtime::UdpRuntimeLimits,
    ) -> io::Result<Arc<ClientTunnel>> {
        let _dial = self.dialing.lock().await;
        let epoch = {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| io::Error::other("F2P pool unavailable"))?;
            if pool.fenced {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if let Some(tunnel) = &pool.tunnel
                && !tunnel.is_closed()
            {
                return Ok(Arc::clone(tunnel));
            }
            pool.tunnel = None;
            pool.epoch
        };
        // One lazy tunnel per outbound identity. Reserve a partition of the
        // existing aggregate budget, never an additional independent budget.
        let blocks = match self.profile {
            Profile::Balanced => 4,
            Profile::Realtime => 2,
        };
        let bytes =
            (blocks * MAX_UDP_WIRE_DATAGRAM_BYTES).min(runtime_limits.max_buffered_bytes() / 4);
        let mut capacity = Vec::new();
        let mut remaining = bytes;
        while remaining != 0 {
            let part = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
            capacity.push(
                budget
                    .reserve(part)
                    .map_err(|_| io::Error::other("F2P UDP budget exhausted"))?,
            );
            remaining -= part;
        }
        let generation = connector.network_generation();
        let physical = Arc::clone(connector);
        let server = self.server.clone();
        let dial_options = self.dial_options.clone();
        let route = route.clone();
        let config = Arc::clone(&self.config);
        let profile = self.profile;
        // A pooled socket must outlive the SOCKS connection shard that first uses it.
        // Register its socket, TLS and driver on the process reactor. The JoinSet
        // also cancels an unfinished dial when association admission is cancelled.
        let mut opening = tokio::task::JoinSet::new();
        opening.spawn_on(
            async move {
                let io = tokio::time::timeout(
                    deadlines.0,
                    physical.connect_physical(&server, &dial_options, &route),
                )
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                .map_err(|_| io::Error::other("F2P physical connect failed"))?;
                let stream = tokio::time::timeout(
                    deadlines.1,
                    ferrum2_f2p::connect_udp(SuppliedIo(io), &config, profile),
                )
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                Ok::<_, io::Error>(Arc::new(ClientTunnel::start(
                    stream,
                    profile,
                    ferrum2_f2p::Limits {
                        max_sessions: runtime_limits.max_sessions().min(256),
                        max_buffered_bytes: bytes,
                        idle_timeout: runtime_limits.idle_timeout(),
                    },
                    capacity,
                )?))
            },
            &self.runtime,
        );
        let tunnel = opening
            .join_next()
            .await
            .ok_or_else(|| io::Error::other("F2P dial owner missing"))?
            .map_err(|_| io::Error::other("F2P dial owner stopped"))??;
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| io::Error::other("F2P pool unavailable"))?;
        if pool.fenced
            || pool.epoch != epoch
            || !connector.network_generation_is_admissible(generation)
        {
            tunnel.close();
            return Err(io::ErrorKind::Interrupted.into());
        }
        pool.tunnel = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }
}
impl Drop for ClientF2pContext {
    fn drop(&mut self) {
        self.fence();
    }
}
