use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::{EgressPlanHandle, EgressPlanSnapshot};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{
    NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer, Protocol};
use hickory_resolver::{ConnectionProvider, PoolContext, Resolver, TlsConfig};
use tokio::time::Instant;

use crate::error::DnsError;
use crate::runtime_provider::FerrumRuntimeProvider;

/// Closed transport values for one validated DNS upstream.
#[derive(Clone, Eq, PartialEq)]
pub enum DnsUpstreamTransport {
    /// DNS over UDP with same-server TCP upgrade on truncation.
    Udp,
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS with an authenticated server name.
    Dot { server_name: Box<str> },
    /// DNS over HTTPS with an authenticated server name and validated path.
    Doh {
        server_name: Box<str>,
        path: Box<str>,
    },
}

/// Validated runtime values for one DNS upstream.
pub struct DnsUpstreamSpec {
    pub transport: DnsUpstreamTransport,
    pub address: SocketAddr,
    pub detour: Option<EgressPlanHandle>,
}

pub(crate) struct SelectedServer {
    spec: DnsUpstreamSpec,
    #[cfg(test)]
    tls: Option<rustls::ClientConfig>,
}

impl SelectedServer {
    pub(crate) fn from_spec(spec: DnsUpstreamSpec) -> Self {
        Self {
            spec,
            #[cfg(test)]
            tls: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_tls(mut self, tls: rustls::ClientConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub(crate) fn plan_snapshot(&self) -> Option<EgressPlanSnapshot> {
        self.spec
            .detour
            .as_ref()
            .map(EgressPlanHandle::snapshot_owned)
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

    let name_server = name_server_config(server)?;

    let options = exact_options(remaining);
    let builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), vec![name_server]),
        provider,
    )
    .with_options(options);
    #[cfg(feature = "__interop-test-root")]
    let builder = builder.with_tls_config(interop_test_tls()?);
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

pub(crate) async fn lookup_ips(
    server: &SelectedServer,
    name: Name,
    deadline: Instant,
    provider: FerrumRuntimeProvider,
) -> Result<Vec<IpAddr>, DnsError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DnsError::Timeout);
    }

    let name_server = name_server_config(server)?;
    let builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), vec![name_server]),
        provider,
    )
    .with_options(exact_options(remaining));
    #[cfg(feature = "__interop-test-root")]
    let builder = builder.with_tls_config(interop_test_tls()?);
    #[cfg(test)]
    let builder = match server.tls.clone() {
        Some(tls) => builder.with_tls_config(tls),
        None => builder,
    };
    let resolver = builder.build().map_err(|_| DnsError::Protocol)?;
    let mut addresses = Vec::new();
    for record_type in [RecordType::A, RecordType::AAAA] {
        match tokio::time::timeout_at(deadline, resolver.lookup(name.clone(), record_type))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(map_error)
        {
            Ok(lookup) => addresses.extend(
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| record.data.ip_addr()),
            ),
            Err(DnsError::NoData) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(addresses)
}

pub(crate) async fn query(
    server: &SelectedServer,
    request: Message,
    deadline: Instant,
    provider: FerrumRuntimeProvider,
) -> Result<Message, DnsError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DnsError::Timeout);
    }

    let name_server = name_server_config(server)?;
    #[cfg(not(feature = "__interop-test-root"))]
    let tls = TlsConfig::new().map_err(map_error)?;
    #[cfg(feature = "__interop-test-root")]
    let tls = TlsConfig {
        config: interop_test_tls()?,
    };
    #[cfg(test)]
    let tls = match server.tls.clone() {
        Some(config) => TlsConfig { config },
        None => tls,
    };
    let context = PoolContext::new(exact_options(remaining), tls);
    let connection = name_server
        .connections
        .first()
        .ok_or(DnsError::InvalidServer)?;
    let response = send_query(
        &provider,
        name_server.ip,
        connection,
        &context,
        request.clone(),
        deadline,
    )
    .await?;
    if response.metadata.truncation && connection.protocol.to_protocol() == Protocol::Udp {
        let tcp = name_server
            .connections
            .iter()
            .find(|connection| connection.protocol.to_protocol() == Protocol::Tcp)
            .ok_or(DnsError::Protocol)?;
        return send_query(&provider, name_server.ip, tcp, &context, request, deadline).await;
    }
    Ok(response)
}

#[cfg(feature = "__interop-test-root")]
fn interop_test_tls() -> Result<rustls::ClientConfig, DnsError> {
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;

    const ROOT: &[u8] = include_bytes!("../tests/fixtures/m12-test-ca.der");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ROOT.to_vec()))
        .map_err(|_| DnsError::Protocol)?;
    rustls::ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    )
    .with_safe_default_protocol_versions()
    .map_err(|_| DnsError::Protocol)
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

async fn send_query(
    provider: &FerrumRuntimeProvider,
    ip: std::net::IpAddr,
    connection: &hickory_resolver::config::ConnectionConfig,
    context: &PoolContext,
    request: Message,
    deadline: Instant,
) -> Result<Message, DnsError> {
    let handle = provider
        .new_connection(ip, connection, context)
        .map_err(map_error)?
        .await
        .map_err(map_error)?;
    tokio::time::timeout_at(
        deadline,
        handle
            .send(DnsRequest::new(request, DnsRequestOptions::default()))
            .first_answer(),
    )
    .await
    .map_err(|_| DnsError::Timeout)?
    .map_err(map_error)
    .map(|response| response.into_message())
}

fn name_server_config(server: &SelectedServer) -> Result<NameServerConfig, DnsError> {
    let mut name_server = match &server.spec.transport {
        DnsUpstreamTransport::Udp => NameServerConfig::udp_and_tcp(server.spec.address.ip()),
        DnsUpstreamTransport::Tcp => NameServerConfig::tcp(server.spec.address.ip()),
        DnsUpstreamTransport::Dot { server_name } => {
            NameServerConfig::tls(server.spec.address.ip(), Arc::from(server_name.as_ref()))
        }
        DnsUpstreamTransport::Doh { server_name, path } => NameServerConfig::https(
            server.spec.address.ip(),
            Arc::from(server_name.as_ref()),
            Some(Arc::from(path.as_ref())),
        ),
    };
    for connection in &mut name_server.connections {
        connection.port = server.spec.address.port();
    }
    Ok(name_server)
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
