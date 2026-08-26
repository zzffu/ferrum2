use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::Duration;

use ferrum2_core::CanonicalDomain;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::lookup::Lookup;
use tokio::runtime::Builder;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::Instant;

use crate::error::DnsError;
use crate::resolver::{DnsUpstreamSpec, SelectedServer};
use crate::runtime_provider::{
    DNS_QUERY_SCOPE, DnsEgress, DnsQueryContext, RuntimeCounters, SystemDnsEgress,
};
use crate::{DnsAddressRecords, DnsCacheQtype, FixedEndpointLookup};

use command_loop::{run_commands, runtime_stats};

/// Current bounded DNS owner counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStats {
    /// Independent query chains admitted and not yet terminal.
    pub queries: usize,
    /// Hickory background tasks registered through its runtime handle.
    pub tasks: usize,
    /// Selected upstream TCP streams currently owned.
    pub tcp_streams: usize,
    /// Selected upstream UDP sockets currently owned.
    pub udp_sockets: usize,
    /// Detour I/O bridges currently owned by admitted queries.
    pub bridge_tasks: usize,
    /// Concrete detour sessions currently owned by admitted queries.
    pub sessions: usize,
    /// Bounded detour queues currently registered to admitted queries.
    pub queues: usize,
    /// Fixed-capacity detour buffers currently registered to admitted queries.
    pub buffers: usize,
}

/// Successful exclusive-runtime shutdown evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Tokio tasks remaining immediately before the exclusive runtime is dropped.
    pub runtime_tasks: usize,
    /// All ferrum-owned DNS resources after cancellation and joining.
    pub stats: RuntimeStats,
}

pub(super) enum Command {
    Lookup {
        server: usize,
        name: Name,
        record_type: RecordType,
        deadline: Instant,
        reply: oneshot::Sender<Result<Lookup, DnsError>>,
        context: DnsQueryContext,
    },
    LookupIps {
        server: usize,
        name: Name,
        deadline: Instant,
        reply: oneshot::Sender<Result<Vec<IpAddr>, DnsError>>,
        context: DnsQueryContext,
    },
    Query {
        server: usize,
        request: Message,
        deadline: Instant,
        reply: oneshot::Sender<Result<Message, DnsError>>,
        context: DnsQueryContext,
    },
}

struct ShutdownSignal(Mutex<Option<oneshot::Sender<()>>>);

impl ShutdownSignal {
    fn request(&self) {
        if let Some(shutdown) = self.0.lock().expect("DNS shutdown lock poisoned").take() {
            let _ = shutdown.send(());
        }
    }
}

/// Bounded tagged resolver handle backed by one separately awaited runtime owner.
pub struct TaggedResolver {
    sender: Option<mpsc::Sender<Command>>,
    shutdown: Arc<ShutdownSignal>,
    admission: Arc<Semaphore>,
    server_count: usize,
    timeout: Duration,
    counters: Arc<RuntimeCounters>,
}

/// Unique join owner for one tagged resolver's exclusive runtime thread.
#[must_use = "await shutdown() after dropping the TaggedResolver handle"]
pub struct TaggedResolverOwner {
    shutdown: Arc<ShutdownSignal>,
    ready: Option<oneshot::Receiver<Result<(), DnsError>>>,
    ready_result: Option<Result<(), DnsError>>,
    thread: Option<ThreadJoinHandle<Result<ShutdownReport, DnsError>>>,
    join: Option<tokio::task::JoinHandle<Result<ShutdownReport, DnsError>>>,
    report: Option<Result<ShutdownReport, DnsError>>,
}

impl TaggedResolver {
    /// Starts a lazy resolver graph using direct numeric Tokio sockets.
    pub fn direct(
        servers: Vec<DnsUpstreamSpec>,
        timeout: Duration,
        max_inflight: NonZeroU16,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        Self::new(servers, timeout, max_inflight, Arc::new(SystemDnsEgress))
    }

    /// Starts a lazy resolver graph over the supplied direct/detour adapter.
    pub fn new(
        servers: Vec<DnsUpstreamSpec>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        Self::start(
            servers
                .into_iter()
                .map(SelectedServer::from_spec)
                .collect::<Result<Vec<_>, _>>()?,
            timeout,
            max_inflight,
            egress,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_test_tls(
        servers: Vec<(DnsUpstreamSpec, rustls::ClientConfig)>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        Self::start(
            servers
                .into_iter()
                .map(|(server, tls)| {
                    SelectedServer::from_spec(server).map(|server| server.with_tls(tls))
                })
                .collect::<Result<Vec<_>, _>>()?,
            timeout,
            max_inflight,
            egress,
        )
    }

    fn start(
        servers: Vec<SelectedServer>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        if servers.is_empty() {
            return Err(DnsError::InvalidServer);
        }
        let server_count = servers.len();
        let capacity = usize::from(max_inflight.get());
        let admission = Arc::new(Semaphore::new(capacity));
        let counters = Arc::new(RuntimeCounters::default());
        let (sender, receiver) = mpsc::channel(capacity);
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let shutdown = Arc::new(ShutdownSignal(Mutex::new(Some(shutdown_sender))));
        let (ready_sender, ready_receiver) = oneshot::channel();
        let thread_counters = Arc::clone(&counters);
        let thread = std::thread::Builder::new()
            .name("ferrum2-dns".to_owned())
            .spawn(move || {
                let runtime = match Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = ready_sender.send(Err(DnsError::Runtime));
                        return Err(DnsError::Runtime);
                    }
                };
                let handle = runtime.handle().clone();
                let servers = Arc::new(servers);
                let _ = ready_sender.send(Ok(()));
                runtime.block_on(run_commands(
                    receiver,
                    shutdown_receiver,
                    servers,
                    egress,
                    thread_counters,
                    handle,
                ))
            })
            .map_err(|_| DnsError::Runtime)?;
        Ok((
            Self {
                sender: Some(sender),
                shutdown: Arc::clone(&shutdown),
                admission,
                server_count,
                timeout,
                counters,
            },
            TaggedResolverOwner {
                shutdown,
                ready: Some(ready_receiver),
                ready_result: None,
                thread: Some(thread),
                join: None,
                report: None,
            },
        ))
    }

    /// Queries one already-selected tagged server under the shared admission and deadline.
    pub fn lookup(
        &self,
        server: usize,
        name: Name,
        record_type: RecordType,
    ) -> impl std::future::Future<Output = Result<Lookup, DnsError>> + Send + 'static {
        let server_count = self.server_count;
        let timeout = self.timeout;
        let admission = Arc::clone(&self.admission);
        let counters = Arc::clone(&self.counters);
        let sender = self.sender.clone();
        async move {
            if server >= server_count {
                return Err(DnsError::InvalidServer);
            }
            let deadline = Instant::now() + timeout;
            let permit = admission.try_acquire_owned().map_err(|_| DnsError::Busy)?;
            let context = DnsQueryContext::root(permit, counters, deadline);
            let (reply, response) = oneshot::channel();
            let command = Command::Lookup {
                server,
                name,
                record_type,
                deadline,
                reply,
                context,
            };
            tokio::time::timeout_at(deadline, sender.ok_or(DnsError::Shutdown)?.send(command))
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?;
            response.await.map_err(|_| DnsError::Shutdown)?
        }
    }

    pub(crate) fn lookup_dependency(
        &self,
        server: usize,
        name: Name,
        record_type: RecordType,
    ) -> impl std::future::Future<Output = Result<Lookup, DnsError>> + Send + 'static {
        let server_count = self.server_count;
        let timeout = self.timeout;
        let inherited = DNS_QUERY_SCOPE
            .try_with(Clone::clone)
            .ok()
            .filter(|scope| scope.belongs_to(&self.counters));
        let admission = Arc::clone(&self.admission);
        let counters = Arc::clone(&self.counters);
        let sender = self.sender.clone();
        async move {
            if server >= server_count {
                return Err(DnsError::InvalidServer);
            }
            let context = match inherited {
                Some(scope) => scope.child(server_count).ok_or(DnsError::InvalidServer)?,
                None => {
                    let deadline = Instant::now() + timeout;
                    let permit = admission.try_acquire_owned().map_err(|_| DnsError::Busy)?;
                    DnsQueryContext::root(permit, counters, deadline)
                }
            };
            let deadline = context.deadline();
            let (reply, response) = oneshot::channel();
            let command = Command::Lookup {
                server,
                name,
                record_type,
                deadline,
                reply,
                context,
            };
            tokio::time::timeout_at(deadline, sender.ok_or(DnsError::Shutdown)?.send(command))
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?;
            response.await.map_err(|_| DnsError::Shutdown)?
        }
    }

    /// Resolves A then AAAA through one selected server, admission and deadline.
    pub fn lookup_ips(
        &self,
        server: usize,
        name: Name,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + 'static {
        let server_count = self.server_count;
        let timeout = self.timeout;
        let admission = Arc::clone(&self.admission);
        let counters = Arc::clone(&self.counters);
        let sender = self.sender.clone();
        async move {
            if server >= server_count {
                return Err(DnsError::InvalidServer);
            }
            let deadline = Instant::now() + timeout;
            let permit = admission.try_acquire_owned().map_err(|_| DnsError::Busy)?;
            let context = DnsQueryContext::root(permit, counters, deadline);
            let (reply, response) = oneshot::channel();
            let command = Command::LookupIps {
                server,
                name,
                deadline,
                reply,
                context,
            };
            tokio::time::timeout_at(deadline, sender.ok_or(DnsError::Shutdown)?.send(command))
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?;
            response.await.map_err(|_| DnsError::Shutdown)?
        }
    }

    pub(crate) fn lookup_ips_dependency(
        &self,
        server: usize,
        name: Name,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + 'static {
        let server_count = self.server_count;
        let timeout = self.timeout;
        let inherited = DNS_QUERY_SCOPE
            .try_with(Clone::clone)
            .ok()
            .filter(|scope| scope.belongs_to(&self.counters));
        let admission = Arc::clone(&self.admission);
        let counters = Arc::clone(&self.counters);
        let sender = self.sender.clone();
        async move {
            if server >= server_count {
                return Err(DnsError::InvalidServer);
            }
            let context = match inherited {
                Some(scope) => scope.child(server_count).ok_or(DnsError::InvalidServer)?,
                None => {
                    let deadline = Instant::now() + timeout;
                    let permit = admission.try_acquire_owned().map_err(|_| DnsError::Busy)?;
                    DnsQueryContext::root(permit, counters, deadline)
                }
            };
            let deadline = context.deadline();
            let (reply, response) = oneshot::channel();
            let command = Command::LookupIps {
                server,
                name,
                deadline,
                reply,
                context,
            };
            tokio::time::timeout_at(deadline, sender.ok_or(DnsError::Shutdown)?.send(command))
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?;
            response.await.map_err(|_| DnsError::Shutdown)?
        }
    }

    /// Resolves one canonical application or bootstrap domain through the
    /// selected tagged server without exposing Hickory name construction to
    /// composition crates.
    pub fn lookup_canonical_ips(
        &self,
        server: usize,
        domain: CanonicalDomain,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + 'static {
        let parsed: Result<Name, DnsError> = domain
            .as_str()
            .parse()
            .map_err(|_| DnsError::Protocol)
            .map(|mut name: Name| {
                name.set_fqdn(true);
                name
            });
        let lookup = parsed.map(|name| self.lookup_ips(server, name));
        async move {
            match lookup {
                Ok(lookup) => lookup.await,
                Err(error) => Err(error),
            }
        }
    }

    /// Resolves one fixed-endpoint family and preserves the upstream TTL for
    /// the shared materialization cache.
    pub fn lookup_fixed_endpoint(
        &self,
        server: usize,
        domain: CanonicalDomain,
        qtype: DnsCacheQtype,
    ) -> impl std::future::Future<Output = Result<FixedEndpointLookup, DnsError>> + Send + 'static
    {
        let parsed: Result<Name, DnsError> = domain
            .as_str()
            .parse()
            .map_err(|_| DnsError::Protocol)
            .map(|mut name: Name| {
                name.set_fqdn(true);
                name
            });
        let lookup = parsed.map(|name| {
            self.lookup(
                server,
                name,
                match qtype {
                    DnsCacheQtype::A => RecordType::A,
                    DnsCacheQtype::Aaaa => RecordType::AAAA,
                },
            )
        });
        async move {
            let lookup = match lookup {
                Ok(lookup) => match lookup.await {
                    Ok(lookup) => lookup,
                    Err(DnsError::NxDomain | DnsError::NoData) => {
                        return Ok(FixedEndpointLookup::negative(Duration::ZERO));
                    }
                    Err(error) => return Err(error),
                },
                Err(error) => return Err(error),
            };
            let ttl = lookup
                .valid_until()
                .saturating_duration_since(std::time::Instant::now());
            match qtype {
                DnsCacheQtype::A => {
                    let mut addresses = Vec::new();
                    for address in lookup
                        .answers()
                        .iter()
                        .filter_map(|record| record.data.ip_addr())
                        .filter_map(|address| match address {
                            IpAddr::V4(address) => Some(address),
                            IpAddr::V6(_) => None,
                        })
                    {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                            if addresses.len() == crate::MAX_APPLICATION_RESOLVED_CANDIDATES {
                                break;
                            }
                        }
                    }
                    if addresses.is_empty() {
                        Ok(FixedEndpointLookup::negative(Duration::ZERO))
                    } else {
                        Ok(FixedEndpointLookup::positive(
                            DnsAddressRecords::A(addresses.into()),
                            ttl,
                        ))
                    }
                }
                DnsCacheQtype::Aaaa => {
                    let mut addresses = Vec::new();
                    for address in lookup
                        .answers()
                        .iter()
                        .filter_map(|record| record.data.ip_addr())
                        .filter_map(|address| match address {
                            IpAddr::V4(_) => None,
                            IpAddr::V6(address) => Some(address),
                        })
                    {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                            if addresses.len() == crate::MAX_APPLICATION_RESOLVED_CANDIDATES {
                                break;
                            }
                        }
                    }
                    if addresses.is_empty() {
                        Ok(FixedEndpointLookup::negative(Duration::ZERO))
                    } else {
                        Ok(FixedEndpointLookup::positive(
                            DnsAddressRecords::Aaaa(addresses.into()),
                            ttl,
                        ))
                    }
                }
            }
        }
    }

    /// Sends one already-validated single-question message without discarding response sections.
    pub fn query(
        &self,
        server: usize,
        request: Message,
    ) -> impl std::future::Future<Output = Result<Message, DnsError>> + Send + 'static {
        let server_count = self.server_count;
        let timeout = self.timeout;
        let admission = Arc::clone(&self.admission);
        let counters = Arc::clone(&self.counters);
        let sender = self.sender.clone();
        async move {
            if server >= server_count {
                return Err(DnsError::InvalidServer);
            }
            let deadline = Instant::now() + timeout;
            let permit = admission.try_acquire_owned().map_err(|_| DnsError::Busy)?;
            let context = DnsQueryContext::root(permit, counters, deadline);
            let (reply, response) = oneshot::channel();
            let command = Command::Query {
                server,
                request,
                deadline,
                reply,
                context,
            };
            tokio::time::timeout_at(deadline, sender.ok_or(DnsError::Shutdown)?.send(command))
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?;
            response.await.map_err(|_| DnsError::Shutdown)?
        }
    }

    /// Returns stable, low-cardinality owner counts.
    pub fn stats(&self) -> RuntimeStats {
        runtime_stats(&self.counters)
    }

    fn request_shutdown(&mut self) {
        self.sender.take();
        self.shutdown.request();
    }
}

impl Drop for TaggedResolver {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

impl TaggedResolverOwner {
    /// Awaits exclusive-runtime initialization without blocking the calling Tokio worker.
    pub async fn ready(&mut self) -> Result<(), DnsError> {
        if let Some(result) = self.ready_result {
            return result;
        }
        let result = match self.ready.as_mut() {
            Some(ready) => ready.await.map_err(|_| DnsError::Runtime)?,
            None => Err(DnsError::Runtime),
        };
        self.ready.take();
        self.ready_result = Some(result);
        result
    }

    /// Signals shutdown and retryably awaits the unique OS-thread join off-worker.
    pub async fn shutdown(&mut self) -> Result<ShutdownReport, DnsError> {
        if let Some(result) = self.report {
            return result;
        }
        self.shutdown.request();
        if self.join.is_none() {
            let thread = self.thread.take().ok_or(DnsError::Shutdown)?;
            self.join = Some(tokio::task::spawn_blocking(move || {
                thread
                    .join()
                    .map_err(|_| DnsError::Runtime)
                    .and_then(|result| result)
            }));
        }
        let result = self
            .join
            .as_mut()
            .expect("DNS join owner present")
            .await
            .map_err(|_| DnsError::Runtime)?;
        self.join.take();
        self.report = Some(result);
        result
    }
}

impl Drop for TaggedResolverOwner {
    fn drop(&mut self) {
        self.shutdown.request();
    }
}

mod command_loop;

#[cfg(test)]
mod tests;
