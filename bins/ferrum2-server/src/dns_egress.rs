#![forbid(unsafe_code)]

//! Server adapters for the shared tagged DNS resolver.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::{ActionTable, Network};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsIoFuture, DnsTaskRegistrar, PlanSnapshot,
    SystemDnsEgress, TaggedResolver,
};
use ferrum2_runtime::{
    MAX_RESOLVED_CANDIDATES, SystemTcpResolver, SystemUdpResolver, TcpResolver, UdpResolver,
};

pub(super) struct ServerDnsState {
    route: ActionTable<usize>,
    resolver: Mutex<Option<Arc<TaggedResolver>>>,
}

impl ServerDnsState {
    pub(super) fn new(route: ActionTable<usize>) -> Self {
        Self {
            route,
            resolver: Mutex::new(None),
        }
    }

    pub(super) fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> usize {
        self.route.select(inbound, network, target)
    }

    pub(super) fn install(&self, resolver: Arc<TaggedResolver>) -> Result<(), ()> {
        let mut current = self.resolver.lock().map_err(|_| ())?;
        if current.is_some() {
            return Err(());
        }
        *current = Some(resolver);
        Ok(())
    }

    pub(super) fn take(&self) -> Option<Arc<TaggedResolver>> {
        self.resolver.lock().ok()?.take()
    }

    fn resolver(&self) -> io::Result<Arc<TaggedResolver>> {
        self.resolver
            .lock()
            .map_err(|_| io::Error::other("DNS resolver state unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::other("DNS resolver is not active"))
    }
}

#[derive(Clone)]
pub(super) struct ServerDnsResolver {
    state: Option<Arc<ServerDnsState>>,
    inbound: usize,
    network: Network,
}

impl ServerDnsResolver {
    pub(super) fn new(
        state: Option<Arc<ServerDnsState>>,
        inbound: usize,
        network: Network,
    ) -> Self {
        Self {
            state,
            inbound,
            network,
        }
    }

    async fn resolve_candidates(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let Some(state) = &self.state else {
            return match self.network {
                Network::Tcp => SystemTcpResolver.resolve(host, port).await,
                Network::Udp => SystemUdpResolver.resolve(host, port).await,
            };
        };
        let target = TargetAddr::domain(host, port)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS target"))?;
        let selected = state.select(self.inbound, self.network, &target);
        let resolver = state.resolver()?;
        let mut candidates = Vec::with_capacity(MAX_RESOLVED_CANDIDATES);
        for record_type in ["A", "AAAA"] {
            match resolver
                .lookup(
                    selected,
                    host.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name")
                    })?,
                    record_type.parse().expect("fixed DNS record type"),
                )
                .await
            {
                Ok(lookup) => candidates.extend(
                    lookup
                        .answers()
                        .iter()
                        .filter_map(|record| record.data.ip_addr())
                        .map(|ip| SocketAddr::new(ip, port))
                        .take(MAX_RESOLVED_CANDIDATES - candidates.len()),
                ),
                Err(ferrum2_dns::DnsError::NoData) => {}
                Err(_) => return Err(io::Error::other("DNS resolution failed")),
            }
        }
        Ok(candidates)
    }
}

impl TcpResolver for ServerDnsResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve_candidates(host, port).await
    }
}

impl UdpResolver for ServerDnsResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve_candidates(host, port).await
    }
}

pub(super) struct ServerDnsEgress {
    outbound_count: usize,
}

impl ServerDnsEgress {
    pub(super) fn new(outbound_count: usize) -> Self {
        Self { outbound_count }
    }

    fn validate(&self, plan: &Option<PlanSnapshot>) -> io::Result<()> {
        match plan {
            None => Ok(()),
            Some(plan) if matches!(plan.hops(), [outbound] if *outbound < self.outbound_count) => {
                Ok(())
            }
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid server DNS detour",
            )),
        }
    }
}

impl DnsEgress for ServerDnsEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        if let Err(error) = self.validate(&plan) {
            return Box::pin(async move { Err(error) });
        }
        SystemDnsEgress.connect_tcp(target, None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        if let Err(error) = self.validate(&plan) {
            return Box::pin(async move { Err(error) });
        }
        SystemDnsEgress.bind_udp(target, None, tasks)
    }
}
