use std::io;
#[cfg(test)]
use std::net::Ipv4Addr;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::net::SocketAddrV4;
use std::num::NonZeroUsize;
#[cfg(test)]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
#[cfg(test)]
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveFuture, ApplicationResolveRequest, DnsError,
    DnsProxy,
};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, ChannelDnsDatagram, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsIoFuture, DnsTaskRegistrar, DnsUpstreamSpec, DnsUpstreamTransport,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
#[cfg(test)]
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::egress::{ClientEgressEngine, ClientRequestOrigin, ClientUdpAssociation};
use ferrum2_shadowsocks::tokio::TokioFramed;

type Packet = Vec<u8>;
type DnsUdpPool = Arc<DnsUdpPoolState<IdleDnsUdp>>;

struct DnsUdpPoolState<T> {
    inner: Mutex<DnsUdpPoolInner<T>>,
}

struct DnsUdpPoolInner<T> {
    generation: u64,
    accepts_reuse: bool,
    idle: Vec<T>,
}

impl<T> Default for DnsUdpPoolState<T> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(DnsUdpPoolInner {
                generation: 0,
                accepts_reuse: true,
                idle: Vec::new(),
            }),
        }
    }
}

impl<T> DnsUdpPoolState<T> {
    fn reset(&self) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.generation.checked_add(1) {
            Some(generation) => inner.generation = generation,
            None => inner.accepts_reuse = false,
        }
        let count = inner.idle.len();
        inner.idle.clear();
        count
    }

    fn put(&self, generation: u64, value: T) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.accepts_reuse && inner.generation == generation {
            inner.idle.push(value);
        }
    }
}

/// Configured application resolver backend bound to the one prepared client
/// DNS proxy graph. Absence or shutdown is terminal and never reaches system
/// DNS.
#[cfg(test)]
pub(super) struct ClientConfiguredApplicationBackend {
    proxy: Arc<OnceLock<Arc<DnsProxy>>>,
}

#[cfg(test)]
impl ClientConfiguredApplicationBackend {
    pub(super) fn new(proxy: Arc<OnceLock<Arc<DnsProxy>>>) -> Self {
        Self { proxy }
    }
}

#[cfg(test)]
impl ApplicationResolveBackend for ClientConfiguredApplicationBackend {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            let proxy = self.proxy.get().ok_or(DnsError::Runtime)?;
            proxy.resolve_application(request).await
        })
    }
}

pub(super) fn dns_runtime_specs(servers: &[DnsServerConfig]) -> Vec<DnsUpstreamSpec> {
    servers
        .iter()
        .map(|server| {
            let transport = match server.transport {
                DnsTransport::Udp => DnsUpstreamTransport::Udp,
                DnsTransport::Tcp => DnsUpstreamTransport::Tcp,
                DnsTransport::Dot => DnsUpstreamTransport::Dot {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoT server name"),
                },
                DnsTransport::Doh => DnsUpstreamTransport::Doh {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoH server name"),
                    path: server.path.clone().expect("validated DoH path"),
                },
            };
            DnsUpstreamSpec {
                transport,
                target: server.target.clone(),
                resolved_targets: server.resolved_targets.clone(),
                detour: server.detour.clone(),
            }
        })
        .collect()
}

pub(super) struct ClientDnsEgress {
    engine: Arc<ClientEgressEngine>,
    udp_pool: DnsUdpPool,
    _network_reset_action: Arc<super::egress::ClientDnsResetAction>,
}

impl ClientDnsEgress {
    pub(super) fn new(engine: Arc<ClientEgressEngine>) -> Result<Self, ()> {
        let udp_pool = Arc::new(DnsUdpPoolState::default());
        let weak_pool = Arc::downgrade(&udp_pool);
        let network_reset_action: Arc<super::egress::ClientDnsResetAction> =
            Arc::new(move || weak_pool.upgrade().map_or(0, |pool| pool.reset()));
        engine.register_dns_reset_action(&network_reset_action)?;
        Ok(Self {
            engine,
            udp_pool,
            _network_reset_action: network_reset_action,
        })
    }
}

#[derive(Eq, PartialEq)]
struct DnsUdpPoolKey {
    plan: Option<EgressPlanSnapshot>,
    target: TargetAddr,
}

struct IdleDnsUdp {
    key: DnsUdpPoolKey,
    association: ClientUdpAssociation,
}

struct PooledDnsUdp {
    idle: Option<IdleDnsUdp>,
    pool: DnsUdpPool,
    pool_generation: u64,
    reusable: bool,
}

impl PooledDnsUdp {
    fn begin_request(&mut self) {
        self.reusable = false;
    }

    async fn relay_request(
        &mut self,
        engine: &ClientEgressEngine,
        plan: Option<&EgressPlanSnapshot>,
        destination: TargetAddr,
        packet: Vec<u8>,
        responses: &mpsc::Sender<Packet>,
    ) -> io::Result<bool> {
        self.begin_request();
        let idle = self.idle.as_mut().expect("pooled DNS UDP owner");
        if idle.key.target != destination {
            return Err(invalid_target());
        }
        let (response, fully_reusable) = idle
            .association
            .relay(engine, plan, destination, packet)
            .await?;
        responses
            .send(response)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DNS UDP response closed"))?;
        self.reusable = fully_reusable;
        Ok(fully_reusable)
    }
}

impl Drop for PooledDnsUdp {
    fn drop(&mut self) {
        if !self.reusable {
            return;
        }
        let Some(idle) = self.idle.take() else {
            return;
        };
        self.pool.put(self.pool_generation, idle);
    }
}

fn take_dns_udp(
    pool: &DnsUdpPool,
    key: &DnsUdpPoolKey,
) -> io::Result<(Option<IdleDnsUdp>, Option<IdleDnsUdp>, u64)> {
    let mut pool = pool.inner.lock().map_err(|_| invalid_target())?;
    let generation = pool.generation;
    let (matching, stale) = match pool.idle.iter().position(|idle| idle.key == *key) {
        Some(index) => (Some(pool.idle.swap_remove(index)), None),
        None => (None, pool.idle.pop()),
    };
    Ok((matching, stale, generation))
}

impl DnsEgress for ClientDnsEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        let engine = Arc::clone(&self.engine);
        Box::pin(async move {
            let queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            let (client, mut bridge_front) = tokio::io::duplex(2_048);
            let (mut bridge_back, mut session_io) = tokio::io::duplex(2_048);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_queue, _buffer) = (queue, buffer);
                let _ = tokio::io::copy_bidirectional(&mut bridge_front, &mut bridge_back).await;
            });
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                let Ok(flow) = engine
                    .open_tcp_for_ingress(
                        ClientRequestOrigin::Dns,
                        0,
                        plan,
                        &target,
                        Some(timeout),
                        #[cfg(test)]
                        None,
                    )
                    .await
                else {
                    return;
                };
                let mut upstream = TokioFramed::new(flow);
                let _ = tokio::io::copy_bidirectional(&mut session_io, &mut upstream).await;
            });
            Ok(Box::new(client) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let engine = Arc::clone(&self.engine);
        let pool = Arc::clone(&self.udp_pool);
        Box::pin(async move {
            let key = DnsUdpPoolKey {
                plan: plan.clone(),
                target: target.clone(),
            };
            let (idle, stale, pool_generation) = take_dns_udp(&pool, &key)?;
            let reusable = idle.is_some();
            drop(stale);
            let idle = match idle {
                Some(idle) => idle,
                None => IdleDnsUdp {
                    key,
                    association: engine
                        .prepare_udp_for_ingress(
                            ClientRequestOrigin::Dns,
                            0,
                            plan.clone(),
                            Some(&target),
                        )
                        .await
                        .map_err(|_| io::Error::other("DNS UDP egress unavailable"))?,
                },
            };
            let mut prepared = PooledDnsUdp {
                idle: Some(idle),
                pool,
                pool_generation,
                reusable,
            };

            let (io, mut outbound, inbound) = ChannelDnsDatagram::bounded(
                NonZeroUsize::new(MAX_UDP_WIRE_LEN).expect("non-zero DNS UDP wire limit"),
            )
            .into_parts();
            let (session_requests, mut requests) = mpsc::channel::<Packet>(1);
            let (session_responses, mut responses) = mpsc::channel::<Packet>(1);
            let outbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let inbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let request_queue = tasks.own(DnsEgressResourceKind::Queue);
            let response_queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_outbound_queue, _inbound_queue, _request_queue, _response_queue, _buffer) = (
                    outbound_queue,
                    inbound_queue,
                    request_queue,
                    response_queue,
                    buffer,
                );
                while let Some(packet) = outbound.recv().await {
                    if session_requests.send(packet).await.is_err() {
                        break;
                    }
                    let Some(response) = responses.recv().await else {
                        break;
                    };
                    if inbound.send(response).await.is_err() {
                        break;
                    }
                }
            });
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                while let Some(packet) = requests.recv().await {
                    let reusable = prepared
                        .relay_request(
                            &engine,
                            plan.as_ref(),
                            target.clone(),
                            packet,
                            &session_responses,
                        )
                        .await;
                    let Ok(fully_reusable) = reusable else {
                        break;
                    };
                    if !fully_reusable {
                        break;
                    }
                }
            });
            Ok(io)
        })
    }
}

fn invalid_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS egress target")
}

#[cfg(test)]
#[path = "dns_egress/tests/mod.rs"]
mod tests;
