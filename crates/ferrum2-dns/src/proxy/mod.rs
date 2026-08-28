mod loops;
mod policy_cache;

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::Network;
use ferrum2_rule::RuleEngineRegistry;

use crate::{
    ApplicationResolveRequest, DnsCache, DnsCacheAnswer, DnsCacheKey, DnsError, DnsPolicyObserver,
    DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute, DnsPolicyStep, DnsServerId, DnsStrategy,
    MAX_APPLICATION_RESOLVED_CANDIDATES, ResolverGeneration, TaggedResolver,
};

use loops::{UdpRequestPool, bind_tcp, encode_response, tcp_loop, udp_loop};
use policy_cache::{
    append_application_records, bind_response, cache_application_response, cache_qtype,
    cached_application_negative_response, cached_application_response, error_response,
    memo_position,
};

/// Network on which a client proxy question was received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyTransport {
    /// One DNS UDP datagram.
    Udp,
    /// One DNS message on a TCP connection.
    Tcp,
}

/// Collision-free source identity for one client proxy query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyIngress {
    /// A configured dedicated DNS listener.
    Listener(usize),
    /// An ordinary inbound serving a hijacked DNS query.
    Ordinary(usize),
}

/// Closed, identity-free UDP listener lifecycle events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsUdpEvent {
    /// One datagram acquired a bounded request slot.
    Acquired,
    /// One acquired request released its slot after completion or cancellation.
    Completed,
    /// One datagram was dropped because every request slot was occupied.
    PoolDrop,
    /// One response could not be encoded within the advertised wire bound.
    EncodeFailure,
}

/// Low-cardinality observer for DNS UDP listener structural work.
pub trait DnsUdpObserver: Send + Sync + 'static {
    /// Records one closed listener lifecycle event.
    fn record(&self, event: DnsUdpEvent);
}

impl<F> DnsUdpObserver for F
where
    F: Fn(DnsUdpEvent) + Send + Sync + 'static,
{
    fn record(&self, event: DnsUdpEvent) {
        self(event);
    }
}

/// Hickory-backed DNS proxy request seam.
pub struct DnsProxy {
    resolver: Arc<TaggedResolver>,
    policy: ProxyPolicy,
    policy_observer: Option<Arc<dyn DnsPolicyObserver>>,
    udp_observer: Option<Arc<dyn DnsUdpObserver>>,
    pub(super) cache: Option<ProxyCache>,
}

pub(super) struct ProxyPolicy {
    pub(super) program: Arc<DnsPolicyProgram>,
    pub(super) registry: Arc<RuleEngineRegistry>,
    pub(super) listener_count: usize,
    pub(super) ordinary_count: usize,
}

pub(super) struct ProxyCache {
    pub(super) cache: DnsCache,
}

#[derive(Clone, Copy)]
pub(super) struct ApplicationQueryContext<'a> {
    domain: &'a CanonicalDomain,
    port: NonZeroU16,
    pub(super) generation: Option<ResolverGeneration>,
}

pub(super) struct MemoizedPolicyResponse {
    server: DnsServerId,
    qname: Name,
    qtype: RecordType,
    response: Message,
}

pub(super) enum PolicyQueryOutcome {
    Rejected,
    Response {
        route: DnsPolicyRoute,
        response: Message,
    },
}

/// Prepared paired UDP/TCP listeners for every configured DNS inbound.
pub struct DnsProxyListeners {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    proxy: Arc<DnsProxy>,
    connections: Arc<Semaphore>,
    udp_requests: UdpRequestPool,
    idle_timeout: Duration,
}

/// Paired sockets prepared before the resolver owner starts.
pub struct DnsProxySockets {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    connections: Arc<Semaphore>,
    udp_requests: UdpRequestPool,
    idle_timeout: Duration,
}

impl DnsProxyListeners {
    /// Atomically binds one UDP and one bounded-backlog TCP listener per address.
    ///
    /// `max_connections` independently bounds aggregate TCP connections and
    /// aggregate in-flight UDP requests. UDP datagrams received while that
    /// request limit is saturated are dropped.
    pub async fn bind(
        inbounds: Vec<SocketAddr>,
        backlog: u32,
        max_connections: NonZeroU16,
        idle_timeout: Duration,
        proxy: Arc<DnsProxy>,
    ) -> io::Result<Self> {
        Ok(
            DnsProxySockets::bind(inbounds, backlog, max_connections, idle_timeout)
                .await?
                .with_proxy(proxy),
        )
    }

    /// Runs the fixed listener set until shutdown or a required listener fails.
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> io::Result<()> {
        let mut listeners = JoinSet::new();
        let (cancel, cancel_rx) = watch::channel(false);
        for (inbound, socket) in self.udp.into_iter().enumerate() {
            let proxy = Arc::clone(&self.proxy);
            listeners.spawn(udp_loop(
                socket,
                inbound,
                proxy,
                self.udp_requests.clone(),
                cancel_rx.clone(),
            ));
        }
        for (inbound, listener) in self.tcp.into_iter().enumerate() {
            let proxy = Arc::clone(&self.proxy);
            let connections = Arc::clone(&self.connections);
            listeners.spawn(tcp_loop(
                listener,
                inbound,
                proxy,
                connections,
                self.idle_timeout,
                cancel_rx.clone(),
            ));
        }
        tokio::pin!(shutdown);
        let result = tokio::select! {
            biased;
            () = &mut shutdown => Ok(()),
            result = listeners.join_next() => match result {
                Some(Ok(result)) => result,
                Some(Err(_)) | None => Err(io::Error::other("DNS listener stopped")),
            },
        };
        let _ = cancel.send(true);
        while listeners.join_next().await.is_some() {}
        result
    }
}

impl DnsProxySockets {
    /// Binds all paired sockets without starting a resolver or service task.
    ///
    /// `max_connections` independently bounds aggregate TCP connections and
    /// aggregate in-flight UDP requests.
    pub async fn bind(
        inbounds: Vec<SocketAddr>,
        backlog: u32,
        max_connections: NonZeroU16,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        let mut udp = Vec::with_capacity(inbounds.len());
        let mut tcp = Vec::with_capacity(inbounds.len());
        for address in inbounds {
            udp.push(UdpSocket::bind(address).await?);
            tcp.push(bind_tcp(address, backlog)?);
        }
        Ok(Self {
            udp,
            tcp,
            connections: Arc::new(Semaphore::new(usize::from(max_connections.get()))),
            udp_requests: UdpRequestPool::new(usize::from(max_connections.get())),
            idle_timeout,
        })
    }

    /// Completes the prepared root with its ready resolver-backed proxy.
    pub fn with_proxy(self, proxy: Arc<DnsProxy>) -> DnsProxyListeners {
        DnsProxyListeners {
            udp: self.udp,
            tcp: self.tcp,
            proxy,
            connections: self.connections,
            udp_requests: self.udp_requests,
            idle_timeout: self.idle_timeout,
        }
    }
}

impl DnsProxy {
    /// Binds one compiled DNS policy to one tagged resolver graph.
    ///
    /// Listener identities precede ordinary identities in the same
    /// collision-free order used by the compiled policy.
    pub fn new(
        resolver: Arc<TaggedResolver>,
        program: Arc<DnsPolicyProgram>,
        registry: Arc<RuleEngineRegistry>,
        listener_count: usize,
        ordinary_count: usize,
    ) -> Self {
        Self {
            resolver,
            policy: ProxyPolicy {
                program,
                registry,
                listener_count,
                ordinary_count,
            },
            policy_observer: None,
            udp_observer: None,
            cache: None,
        }
    }

    /// Adds one identity-free observer called once per complete policy continuation.
    pub fn with_policy_observer(mut self, observer: Arc<dyn DnsPolicyObserver>) -> Self {
        self.policy_observer = Some(observer);
        self
    }

    /// Adds one identity-free observer for bounded UDP listener work.
    pub fn with_udp_observer(mut self, observer: Arc<dyn DnsUdpObserver>) -> Self {
        self.udp_observer = Some(observer);
        self
    }

    pub(super) fn observe_udp(&self, event: DnsUdpEvent) {
        if let Some(observer) = &self.udp_observer {
            observer.record(event);
        }
    }

    pub(super) fn udp_observer(&self) -> Option<Arc<dyn DnsUdpObserver>> {
        self.udp_observer.as_ref().map(Arc::clone)
    }

    /// Enables one shared, generation-scoped cache for application A/AAAA lookups.
    ///
    /// Wire proxy responses remain complete upstream messages and do not enter
    /// this typed address cache.
    pub fn with_cache(mut self, cache: DnsCache) -> Self {
        self.cache = Some(ProxyCache { cache });
        self
    }

    /// Resolves one ordinary application domain through only this proxy's
    /// configured selection policy and tagged resolver graph.
    ///
    /// A and AAAA are selected independently so query-type DNS rules remain
    /// authoritative. No operating-system resolver is reachable from this
    /// path.
    pub async fn resolve_application(
        &self,
        request: ApplicationResolveRequest<'_>,
    ) -> Result<Vec<SocketAddr>, DnsError> {
        let context = request.context();
        let ingress = ProxyIngress::Ordinary(context.ingress());
        let transport = match context.network() {
            Network::Tcp => ProxyTransport::Tcp,
            Network::Udp => ProxyTransport::Udp,
        };
        let mut name: Name = request
            .domain()
            .as_str()
            .parse()
            .map_err(|_| DnsError::Protocol)?;
        // CanonicalDomain deliberately omits the root dot. DNS messages decode
        // owners as absolute names, so retain that identity before comparing
        // response owners and following CNAME chains.
        name.set_fqdn(true);
        let application = ApplicationQueryContext {
            domain: request.domain(),
            port: request.port(),
            generation: None,
        };
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let requested_strategy = request.strategy();
        let first_qtype = match requested_strategy {
            DnsStrategy::PreferIpv6 | DnsStrategy::Ipv6Only => RecordType::AAAA,
            DnsStrategy::PreferIpv4 | DnsStrategy::Ipv4Only => RecordType::A,
        };
        let effective_strategy = self
            .lookup_application_family(
                ingress,
                transport,
                &name,
                first_qtype,
                application,
                &mut ipv4,
                &mut ipv6,
            )
            .await?;
        // The first selected policy row supplies the per-rule override. The
        // other family, when required, uses the same final ordering/filter.
        let second_qtype = match (first_qtype, effective_strategy) {
            (RecordType::A, DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6)
            | (RecordType::A, DnsStrategy::Ipv6Only) => Some(RecordType::AAAA),
            (RecordType::AAAA, DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6)
            | (RecordType::AAAA, DnsStrategy::Ipv4Only) => Some(RecordType::A),
            _ => None,
        };
        if let Some(second_qtype) = second_qtype {
            self.lookup_application_family(
                ingress,
                transport,
                &name,
                second_qtype,
                application,
                &mut ipv4,
                &mut ipv6,
            )
            .await?;
        }
        let mut candidates = effective_strategy.socket_candidates(request.port(), &ipv4, &ipv6);
        candidates.truncate(MAX_APPLICATION_RESOLVED_CANDIDATES);
        if candidates.is_empty() {
            Err(DnsError::NoData)
        } else {
            Ok(candidates)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn lookup_application_family(
        &self,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        name: &Name,
        record_type: RecordType,
        application: ApplicationQueryContext<'_>,
        ipv4: &mut Vec<std::net::Ipv4Addr>,
        ipv6: &mut Vec<std::net::Ipv6Addr>,
    ) -> Result<DnsStrategy, DnsError> {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        let question = Query::query(name.clone(), record_type);
        request.add_query(question.clone());
        let PolicyQueryOutcome::Response { route, response } = self
            .evaluate_policy_query(
                &self.policy,
                ingress,
                transport,
                &request,
                &question,
                Some(application),
            )
            .await?
        else {
            return Err(DnsError::Protocol);
        };
        match response.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Err(DnsError::NxDomain),
            _ => return Err(DnsError::Protocol),
        }
        append_application_records(name, record_type, &response, ipv4, ipv6);
        Ok(route.strategy())
    }

    /// Parses, selects, resolves and encodes one DNS message through Hickory.
    ///
    /// `None` means the supplied bytes could not be parsed or the safe response could not be encoded.
    pub async fn answer(
        &self,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        wire: &[u8],
    ) -> Option<Vec<u8>> {
        let request = Message::from_vec(wire).ok()?;
        let capacity = match transport {
            ProxyTransport::Udp => usize::from(request.max_payload()).min(4096),
            ProxyTransport::Tcp => 512,
        };
        let advertised = request.max_payload();
        let response = self.response(ingress, transport, &request).await;
        let mut wire = Vec::with_capacity(capacity);
        encode_response(&response, transport, advertised, &mut wire)?;
        Some(wire)
    }

    pub(super) async fn answer_message_into(
        &self,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        request: Message,
        wire: &mut Vec<u8>,
    ) -> Option<()> {
        let advertised = request.max_payload();
        let response = self.response(ingress, transport, &request).await;
        encode_response(&response, transport, advertised, wire)
    }

    async fn response(
        &self,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        request: &Message,
    ) -> Message {
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return error_response(request, ResponseCode::NotImp);
        }
        let [query] = request.queries.as_slice() else {
            return error_response(request, ResponseCode::FormErr);
        };
        if query.query_class() != DNSClass::IN {
            return error_response(request, ResponseCode::Refused);
        }
        self.policy_response(&self.policy, ingress, transport, request, query)
            .await
    }

    async fn policy_response(
        &self,
        policy: &ProxyPolicy,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        request: &Message,
        question: &Query,
    ) -> Message {
        match self
            .evaluate_policy_query(policy, ingress, transport, request, question, None)
            .await
        {
            Ok(PolicyQueryOutcome::Rejected) => error_response(request, ResponseCode::Refused),
            Ok(PolicyQueryOutcome::Response { response, .. }) => {
                bind_response(response, request, question)
            }
            Err(_) => error_response(request, ResponseCode::ServFail),
        }
    }

    async fn evaluate_policy_query(
        &self,
        policy: &ProxyPolicy,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        request: &Message,
        question: &Query,
        application: Option<ApplicationQueryContext<'_>>,
    ) -> Result<PolicyQueryOutcome, DnsError> {
        let Some(inbound) = policy.inbound(ingress) else {
            return Err(DnsError::InvalidServer);
        };
        let network = match transport {
            ProxyTransport::Udp => Network::Udp,
            ProxyTransport::Tcp => Network::Tcp,
        };
        let qname = question.name().clone();
        let qtype = question.query_type();
        let query = match application {
            Some(application) => DnsPolicyQuery::new_application(
                inbound,
                network,
                qname.clone(),
                qtype,
                application.port,
            ),
            None => DnsPolicyQuery::new(inbound, network, qname.clone(), qtype),
        };
        // Request-local scratch is retained across the complete async
        // continuation. It contains no heap storage and never serializes
        // concurrent proxy evaluations behind a shared lock.
        let mut scratch = policy.program.evaluation_scratch();
        let mut evaluation = policy.program.evaluate_with_registry_and_scratch(
            query,
            &policy.registry,
            &mut scratch,
        );
        let application = application.map(|mut application| {
            application.generation =
                Some(ResolverGeneration::new(evaluation.snapshot_generation()));
            application
        });
        let result = async {
            let Ok(Some(mut step)) = evaluation.next_step() else {
                return Err(DnsError::Protocol);
            };
            let mut memo = Vec::<MemoizedPolicyResponse>::new();
            loop {
                match step {
                    DnsPolicyStep::Reject => return Ok(PolicyQueryOutcome::Rejected),
                    DnsPolicyStep::RouteImmediately { server, strategy }
                    | DnsPolicyStep::Final { server, strategy } => {
                        let response = self
                            .policy_server_response(
                                server,
                                &qname,
                                qtype,
                                request,
                                application,
                                &mut memo,
                            )
                            .await?;
                        return Ok(PolicyQueryOutcome::Response {
                            route: DnsPolicyRoute::new(server, strategy),
                            response,
                        });
                    }
                    DnsPolicyStep::EvaluateResponse { server, .. } => {
                        let position = self
                            .memoized_policy_response(
                                server,
                                &qname,
                                qtype,
                                request,
                                application,
                                &mut memo,
                            )
                            .await?;
                        step = evaluation
                            .evaluate_response(&memo[position].response)
                            .map_err(|_| DnsError::Protocol)?;
                    }
                    DnsPolicyStep::AcceptResponse { server, strategy } => {
                        let Some(position) = memo_position(&memo, server, &qname, qtype) else {
                            return Err(DnsError::Protocol);
                        };
                        let response = memo.swap_remove(position).response;
                        return Ok(PolicyQueryOutcome::Response {
                            route: DnsPolicyRoute::new(server, strategy),
                            response,
                        });
                    }
                }
            }
        }
        .await;
        if let Some(observer) = &self.policy_observer {
            observer.observe(evaluation.observation());
        }
        result
    }

    async fn memoized_policy_response(
        &self,
        server: DnsServerId,
        qname: &Name,
        qtype: RecordType,
        request: &Message,
        application: Option<ApplicationQueryContext<'_>>,
        memo: &mut Vec<MemoizedPolicyResponse>,
    ) -> Result<usize, DnsError> {
        if let Some(position) = memo_position(memo, server, qname, qtype) {
            return Ok(position);
        }
        let response = match application {
            Some(application) => {
                self.application_server_response(
                    server,
                    qname,
                    qtype,
                    request,
                    application.domain,
                    application.generation,
                )
                .await?
            }
            None => {
                self.resolver
                    .query(server.get() as usize, request.clone())
                    .await?
            }
        };
        memo.push(MemoizedPolicyResponse {
            server,
            qname: qname.clone(),
            qtype,
            response,
        });
        Ok(memo.len() - 1)
    }

    async fn policy_server_response(
        &self,
        server: DnsServerId,
        qname: &Name,
        qtype: RecordType,
        request: &Message,
        application: Option<ApplicationQueryContext<'_>>,
        memo: &mut Vec<MemoizedPolicyResponse>,
    ) -> Result<Message, DnsError> {
        if let Some(position) = memo_position(memo, server, qname, qtype) {
            return Ok(memo.swap_remove(position).response);
        }
        match application {
            Some(application) => {
                self.application_server_response(
                    server,
                    qname,
                    qtype,
                    request,
                    application.domain,
                    application.generation,
                )
                .await
            }
            None => {
                self.resolver
                    .query(server.get() as usize, request.clone())
                    .await
            }
        }
    }

    async fn application_server_response(
        &self,
        server: DnsServerId,
        qname: &Name,
        qtype: RecordType,
        request: &Message,
        domain: &CanonicalDomain,
        captured_generation: Option<ResolverGeneration>,
    ) -> Result<Message, DnsError> {
        let Some(cache) = &self.cache else {
            return self
                .resolver
                .query(server.get() as usize, request.clone())
                .await;
        };
        let cache_qtype = cache_qtype(qtype).ok_or(DnsError::Protocol)?;
        let key = DnsCacheKey::new(
            server,
            domain.clone(),
            cache_qtype,
            captured_generation.ok_or(DnsError::Protocol)?,
        );
        match cache
            .cache
            .get(&key, Instant::now())
            .map_err(|_| DnsError::Runtime)?
        {
            Some(DnsCacheAnswer::Positive(records)) => {
                return Ok(cached_application_response(request, &records));
            }
            Some(DnsCacheAnswer::Negative) => {
                return Ok(cached_application_negative_response(request));
            }
            None => {}
        }

        let response = self
            .resolver
            .query(server.get() as usize, request.clone())
            .await?;
        cache_application_response(cache, key, qname, qtype, &response)?;
        Ok(response)
    }
}
