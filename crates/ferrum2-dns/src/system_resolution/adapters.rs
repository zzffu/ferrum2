use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::time::Instant;

use super::{SystemResolutionError, SystemResolver};
use crate::{
    ApplicationResolveBackend, ApplicationResolveFuture, ApplicationResolveRequest, DnsError,
};

impl From<SystemResolutionError> for DnsError {
    fn from(error: SystemResolutionError) -> Self {
        match error {
            SystemResolutionError::InvalidLimits | SystemResolutionError::WorkerFailed => {
                Self::Runtime
            }
            SystemResolutionError::Busy => Self::Busy,
            SystemResolutionError::Timeout => Self::Timeout,
            SystemResolutionError::Shutdown => Self::Shutdown,
            SystemResolutionError::Resolution => Self::Transport,
        }
    }
}

impl From<SystemResolutionError> for io::Error {
    fn from(error: SystemResolutionError) -> Self {
        Self::from(match error {
            SystemResolutionError::InvalidLimits => io::ErrorKind::InvalidInput,
            SystemResolutionError::WorkerFailed | SystemResolutionError::Resolution => {
                io::ErrorKind::Other
            }
            SystemResolutionError::Busy => io::ErrorKind::WouldBlock,
            SystemResolutionError::Timeout => io::ErrorKind::TimedOut,
            SystemResolutionError::Shutdown => io::ErrorKind::Interrupted,
        })
    }
}

impl ferrum2_net::TcpResolver for SystemResolver {
    type Candidates = Vec<SocketAddr>;
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve(host, port, Instant::now() + self.shared.timeout)
            .await
            .map_err(Into::into)
    }
}
impl ferrum2_net::UdpResolver for SystemResolver {
    type Candidates = Vec<SocketAddr>;
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve(host, port, Instant::now() + self.shared.timeout)
            .await
            .map_err(Into::into)
    }
}
impl ApplicationResolveBackend for SystemResolver {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            let addresses = self
                .resolve_addresses(
                    request.domain().as_str(),
                    Instant::now() + self.shared.timeout,
                )
                .await?;
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for address in addresses {
                match address {
                    IpAddr::V4(address) => ipv4.push(address),
                    IpAddr::V6(address) => ipv6.push(address),
                }
            }
            let mut candidates = request
                .strategy()
                .socket_candidates(request.port(), &ipv4, &ipv6);
            candidates.truncate(crate::MAX_APPLICATION_RESOLVED_CANDIDATES);
            if candidates.is_empty() {
                Err(DnsError::NoData)
            } else {
                Ok(candidates)
            }
        })
    }
}
