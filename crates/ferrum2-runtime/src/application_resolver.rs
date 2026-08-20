use std::fmt;
use std::future::Future;
use std::io;
use std::num::NonZeroU16;
use std::sync::Arc;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::Network;
use ferrum2_dns::{
    ApplicationResolveContext, ApplicationResolveRequest, ApplicationResolver,
    ApplicationResolverMode, DnsError, DnsStrategy,
};

use crate::connector::TcpResolver;
use crate::udp::UdpResolver;

tokio::task_local! {
    static APPLICATION_RESOLVE_INGRESS: usize;
}

/// Cloneable TCP/UDP adapter over one shared application resolver graph.
///
/// Clones preserve the exact resolver/backend/cache ownership. Changing the
/// ingress creates only another routing view and never changes resolver mode.
#[derive(Clone)]
pub struct ApplicationResolverAdapter {
    resolver: Arc<ApplicationResolver>,
    ingress: usize,
    strategy: DnsStrategy,
}

impl ApplicationResolverAdapter {
    /// Creates one application resolver view for an ordinary ingress.
    pub const fn new(
        resolver: Arc<ApplicationResolver>,
        ingress: usize,
        strategy: DnsStrategy,
    ) -> Self {
        Self {
            resolver,
            ingress,
            strategy,
        }
    }

    /// Returns another ingress view backed by the same resolver and cache.
    pub fn for_ingress(&self, ingress: usize) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            ingress,
            strategy: self.strategy,
        }
    }

    /// Returns the immutable resolver mode selected during materialization.
    pub fn mode(&self) -> ApplicationResolverMode {
        self.resolver.mode()
    }

    /// Returns the selected address-family strategy.
    pub const fn strategy(&self) -> DnsStrategy {
        self.strategy
    }

    /// Reports whether two views share the exact resolver/backend/cache graph.
    pub fn shares_resolver_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.resolver, &other.resolver)
    }

    /// Runs one TCP connection attempt with an authenticated ingress view.
    ///
    /// This is task-local rather than process-global, so concurrent client
    /// inbounds can share one connector without racing or rewriting resolver
    /// state. UDP associations should retain an explicit [`Self::for_ingress`]
    /// clone because their lookups can outlive the preparation call.
    pub async fn scope_ingress<F>(&self, ingress: usize, future: F) -> F::Output
    where
        F: Future,
    {
        APPLICATION_RESOLVE_INGRESS.scope(ingress, future).await
    }

    async fn resolve_network(
        &self,
        network: Network,
        host: &str,
        port: u16,
    ) -> io::Result<Vec<std::net::SocketAddr>> {
        let domain = CanonicalDomain::new(host).map_err(|_| invalid_target())?;
        let port = NonZeroU16::new(port).ok_or_else(invalid_target)?;
        let ingress = APPLICATION_RESOLVE_INGRESS
            .try_with(|ingress| *ingress)
            .unwrap_or(self.ingress);
        let request = ApplicationResolveRequest::new(
            ApplicationResolveContext::new(ingress, network),
            &domain,
            port,
            self.strategy,
        );
        self.resolver
            .resolve(request)
            .await
            .map_err(application_error)
    }
}

impl fmt::Debug for ApplicationResolverAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationResolverAdapter")
            .field("mode", &self.mode())
            .field("ingress", &self.ingress)
            .field("strategy", &self.strategy)
            .field("resolver", &"[redacted]")
            .finish()
    }
}

impl TcpResolver for ApplicationResolverAdapter {
    type Candidates = Vec<std::net::SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve_network(Network::Tcp, host, port).await
    }
}

impl UdpResolver for ApplicationResolverAdapter {
    type Candidates = Vec<std::net::SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve_network(Network::Udp, host, port).await
    }
}

fn invalid_target() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid application DNS target",
    )
}

fn application_error(error: DnsError) -> io::Error {
    let kind = match error {
        DnsError::Timeout => io::ErrorKind::TimedOut,
        DnsError::NxDomain | DnsError::NoData => io::ErrorKind::NotFound,
        DnsError::Busy
        | DnsError::Transport
        | DnsError::Protocol
        | DnsError::Shutdown
        | DnsError::InvalidServer
        | DnsError::Runtime => io::ErrorKind::Other,
    };
    io::Error::new(kind, "application DNS resolution failed")
}
