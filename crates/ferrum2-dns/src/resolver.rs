use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError;
use tokio::time::Instant;

use crate::error::DnsError;
use crate::runtime_provider::{FerrumRuntimeProvider, PlanSnapshot};

pub(crate) struct SelectedServer {
    config: DnsServerConfig,
    #[cfg(test)]
    tls: Option<rustls::ClientConfig>,
}

impl SelectedServer {
    pub(crate) fn from_config(config: DnsServerConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            tls: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_tls(mut self, tls: rustls::ClientConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub(crate) fn plan_snapshot(&self) -> Option<PlanSnapshot> {
        self.config
            .detour
            .as_ref()
            .map(|detour| PlanSnapshot::new(detour.snapshot().hops()))
    }
}

pub(crate) async fn lookup(
    server: &SelectedServer,
    name: Name,
    record_type: RecordType,
    deadline: Instant,
    provider: FerrumRuntimeProvider,
) -> Result<Lookup, DnsError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DnsError::Timeout);
    }

    let mut name_server = match server.config.transport {
        DnsTransport::Udp => NameServerConfig::udp_and_tcp(server.config.address.ip()),
        DnsTransport::Tcp => NameServerConfig::tcp(server.config.address.ip()),
        DnsTransport::Dot => NameServerConfig::tls(
            server.config.address.ip(),
            server
                .config
                .server_name
                .as_deref()
                .map(Arc::from)
                .ok_or(DnsError::Protocol)?,
        ),
        DnsTransport::Doh => NameServerConfig::https(
            server.config.address.ip(),
            server
                .config
                .server_name
                .as_deref()
                .map(Arc::from)
                .ok_or(DnsError::Protocol)?,
            server.config.path.as_deref().map(Arc::from),
        ),
    };
    for connection in &mut name_server.connections {
        connection.port = server.config.address.port();
    }

    let options = exact_options(remaining);
    let builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), vec![name_server]),
        provider,
    )
    .with_options(options);
    #[cfg(test)]
    let builder = match server.tls.clone() {
        Some(tls) => builder.with_tls_config(tls),
        None => builder,
    };
    let resolver = builder.build().map_err(|_| DnsError::Protocol)?;

    tokio::time::timeout_at(deadline, resolver.lookup(name, record_type))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(map_error)
}

fn map_error(error: NetError) -> DnsError {
    if error.is_nx_domain() {
        DnsError::NxDomain
    } else if error.is_no_records_found() {
        DnsError::NoData
    } else {
        match error {
            NetError::Busy => DnsError::Busy,
            NetError::Timeout => DnsError::Timeout,
            NetError::Io(_) => DnsError::Transport,
            _ => DnsError::Protocol,
        }
    }
}

fn exact_options(timeout: Duration) -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.timeout = timeout;
    options.attempts = 0;
    options.cache_size = 0;
    options.use_hosts_file = ResolveHosts::Never;
    options.num_concurrent_reqs = 1;
    options.max_active_requests = 1;
    options.try_tcp_on_error = false;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    options.os_port_selection = true;
    options.case_randomization = false;
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_options_disable_cache_retry_races_and_host_lookup() {
        let options = exact_options(Duration::from_secs(3));
        assert_eq!(options.timeout, Duration::from_secs(3));
        assert_eq!(options.attempts, 0);
        assert_eq!(options.cache_size, 0);
        assert_eq!(options.use_hosts_file, ResolveHosts::Never);
        assert_eq!(options.num_concurrent_reqs, 1);
        assert_eq!(options.max_active_requests, 1);
        assert!(!options.try_tcp_on_error);
        assert_eq!(
            options.server_ordering_strategy,
            ServerOrderingStrategy::UserProvidedOrder
        );
        assert!(options.os_port_selection);
        assert!(!options.case_randomization);
    }
}
