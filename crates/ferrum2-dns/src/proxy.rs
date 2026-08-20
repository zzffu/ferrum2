use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use hickory_proto::op::SerialMessage;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::tcp::TcpStream as HickoryTcpStream;
use hickory_resolver::net::xfer::DnsStreamHandle;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::Network;
use ferrum2_rule::RuleEngineRegistry;

use crate::{
    ApplicationResolveRequest, DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheKey,
    DnsCacheQtype, DnsError, DnsPolicyObserver, DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute,
    DnsPolicyStep, DnsServerId, DnsStrategy, MAX_APPLICATION_RESOLVED_CANDIDATES,
    ResolverGeneration, TaggedResolver,
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

type SelectServer = dyn Fn(ProxyIngress, ProxyTransport, &Name, u16) -> Option<usize> + Send + Sync;

/// Hickory-backed DNS proxy request seam.
pub struct DnsProxy {
    resolver: Arc<TaggedResolver>,
    select: Arc<SelectServer>,
    policy: Option<ProxyPolicy>,
    policy_observer: Option<Arc<dyn DnsPolicyObserver>>,
    cache: Option<ProxyCache>,
}

struct ProxyPolicy {
    program: Arc<DnsPolicyProgram>,
    registry: Arc<RuleEngineRegistry>,
    listener_count: usize,
    ordinary_count: usize,
}

struct ProxyCache {
    cache: DnsCache,
    generation: ResolverGeneration,
}

#[derive(Clone, Copy)]
struct ApplicationQueryContext<'a> {
    domain: &'a CanonicalDomain,
    port: NonZeroU16,
    generation: Option<ResolverGeneration>,
}

struct MemoizedPolicyResponse {
    server: DnsServerId,
    qname: Name,
    qtype: RecordType,
    response: Message,
}

enum PolicyQueryOutcome {
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
    idle_timeout: Duration,
}

/// Paired sockets prepared before the resolver owner starts.
pub struct DnsProxySockets {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
}

impl DnsProxyListeners {
    /// Atomically binds one UDP and one bounded-backlog TCP listener per address.
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
            listeners.spawn(udp_loop(socket, inbound, proxy, cancel_rx.clone()));
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
            idle_timeout: self.idle_timeout,
        }
    }
}

impl DnsProxy {
    /// Binds one validated first-match selector to one tagged resolver graph.
    pub fn new(
        resolver: Arc<TaggedResolver>,
        select: impl Fn(ProxyIngress, ProxyTransport, &Name, u16) -> Option<usize>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            resolver,
            select: Arc::new(select),
            policy: None,
            policy_observer: None,
            cache: None,
        }
    }

    /// Enables the two-stage compiled DNS policy for wire and application queries.
    ///
    /// Listener identities precede ordinary identities in the same
    /// collision-free order used by the compiled policy. Without this binding,
    /// both paths retain the selector supplied to [`Self::new`].
    pub fn with_policy(
        mut self,
        program: Arc<DnsPolicyProgram>,
        registry: Arc<RuleEngineRegistry>,
        listener_count: usize,
        ordinary_count: usize,
    ) -> Self {
        self.policy = Some(ProxyPolicy {
            program,
            registry,
            listener_count,
            ordinary_count,
        });
        self
    }

    /// Adds one identity-free observer called once per complete policy continuation.
    pub fn with_policy_observer(mut self, observer: Arc<dyn DnsPolicyObserver>) -> Self {
        self.policy_observer = Some(observer);
        self
    }

    /// Enables one shared, generation-scoped cache for application A/AAAA lookups.
    ///
    /// Wire proxy responses remain complete upstream messages and do not enter
    /// this typed address cache.
    pub fn with_cache(mut self, cache: DnsCache, generation: ResolverGeneration) -> Self {
        self.cache = Some(ProxyCache { cache, generation });
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
        let first_qtype = match (self.policy.is_none(), requested_strategy) {
            // Preserve the established selector path's stable A-then-AAAA
            // request order. Policy-bound resolution may start with the
            // preferred family because the first selected row can override
            // the strategy used for the continuation.
            (true, DnsStrategy::PreferIpv6) => RecordType::A,
            (_, DnsStrategy::PreferIpv6 | DnsStrategy::Ipv6Only) => RecordType::AAAA,
            (_, DnsStrategy::PreferIpv4 | DnsStrategy::Ipv4Only) => RecordType::A,
        };
        let policy_strategy = self
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
        let effective_strategy = policy_strategy.unwrap_or(requested_strategy);
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
    ) -> Result<Option<DnsStrategy>, DnsError> {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        let question = Query::query(name.clone(), record_type);
        request.add_query(question.clone());
        if let Some(policy) = &self.policy {
            let PolicyQueryOutcome::Response { route, response } = self
                .evaluate_policy_query(
                    policy,
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
            return Ok(Some(route.strategy()));
        }
        let server = (self.select)(ingress, transport, name, u16::from(record_type))
            .ok_or(DnsError::InvalidServer)?;
        let server = u32::try_from(server)
            .map(DnsServerId::new)
            .map_err(|_| DnsError::InvalidServer)?;
        let response = self
            .application_server_response(
                server,
                name,
                record_type,
                &request,
                application.domain,
                application.generation,
            )
            .await?;
        match response.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Err(DnsError::NxDomain),
            _ => return Err(DnsError::Protocol),
        }
        append_application_records(name, record_type, &response, ipv4, ipv6);
        Ok(None)
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
        let response = self.response(ingress, transport, &request).await;
        encode_response(response, transport, request.max_payload())
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
        if let Some(policy) = &self.policy {
            return self
                .policy_response(policy, ingress, transport, request, query)
                .await;
        }
        let Some(server) = (self.select)(
            ingress,
            transport,
            query.name(),
            u16::from(query.query_type()),
        ) else {
            return error_response(request, ResponseCode::ServFail);
        };
        match self.resolver.query(server, request.clone()).await {
            Ok(mut response) => {
                response.metadata.id = request.metadata.id;
                response.queries.clear();
                response.add_query(query.clone());
                response
            }
            Err(_) => error_response(request, ResponseCode::ServFail),
        }
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
            captured_generation.unwrap_or(cache.generation),
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

impl ProxyPolicy {
    fn inbound(&self, ingress: ProxyIngress) -> Option<usize> {
        match ingress {
            ProxyIngress::Listener(index) if index < self.listener_count => Some(index),
            ProxyIngress::Ordinary(index) if index < self.ordinary_count => {
                self.listener_count.checked_add(index)
            }
            ProxyIngress::Listener(_) | ProxyIngress::Ordinary(_) => None,
        }
    }
}

fn memo_position(
    memo: &[MemoizedPolicyResponse],
    server: DnsServerId,
    qname: &Name,
    qtype: RecordType,
) -> Option<usize> {
    memo.iter()
        .position(|entry| entry.server == server && entry.qname == *qname && entry.qtype == qtype)
}

fn append_application_records(
    qname: &Name,
    qtype: RecordType,
    response: &Message,
    ipv4: &mut Vec<std::net::Ipv4Addr>,
    ipv6: &mut Vec<std::net::Ipv6Addr>,
) {
    let Some((records, _)) = application_records_with_ttl(qname, qtype, response) else {
        return;
    };
    match records {
        DnsAddressRecords::A(records) => {
            for address in records.iter().copied() {
                if ipv4.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
                    break;
                }
                if !ipv4.contains(&address) {
                    ipv4.push(address);
                }
            }
        }
        DnsAddressRecords::Aaaa(records) => {
            for address in records.iter().copied() {
                if ipv6.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
                    break;
                }
                if !ipv6.contains(&address) {
                    ipv6.push(address);
                }
            }
        }
    }
}

fn cache_qtype(qtype: RecordType) -> Option<DnsCacheQtype> {
    match qtype {
        RecordType::A => Some(DnsCacheQtype::A),
        RecordType::AAAA => Some(DnsCacheQtype::Aaaa),
        _ => None,
    }
}

fn cache_application_response(
    cache: &ProxyCache,
    key: DnsCacheKey,
    qname: &Name,
    qtype: RecordType,
    response: &Message,
) -> Result<(), DnsError> {
    let now = Instant::now();
    match response.metadata.response_code {
        ResponseCode::NoError => {
            if let Some((records, ttl)) = application_records_with_ttl(qname, qtype, response) {
                cache
                    .cache
                    .insert_positive(key, records, ttl, now)
                    .map_err(|_| DnsError::Runtime)?;
            } else if let Some(ttl) = negative_ttl(response) {
                cache
                    .cache
                    .insert_negative(key, ttl, now)
                    .map_err(|_| DnsError::Runtime)?;
            }
        }
        ResponseCode::NXDomain => {
            if let Some(ttl) = negative_ttl(response) {
                cache
                    .cache
                    .insert_negative(key, ttl, now)
                    .map_err(|_| DnsError::Runtime)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn application_records_with_ttl(
    qname: &Name,
    qtype: RecordType,
    response: &Message,
) -> Option<(DnsAddressRecords, Duration)> {
    let (owner, mut ttl) = final_answer_owner(qname, &response.answers)?;
    match qtype {
        RecordType::A => {
            let mut addresses = Vec::new();
            for record in &response.answers {
                if &record.name != owner {
                    continue;
                }
                let RData::A(address) = &record.data else {
                    continue;
                };
                ttl = minimum_ttl(ttl, record.ttl);
                if addresses.len() < MAX_APPLICATION_RESOLVED_CANDIDATES
                    && !addresses.contains(&address.0)
                {
                    addresses.push(address.0);
                }
            }
            (!addresses.is_empty()).then(|| {
                (
                    DnsAddressRecords::A(Arc::from(addresses)),
                    Duration::from_secs(u64::from(ttl.unwrap_or(0))),
                )
            })
        }
        RecordType::AAAA => {
            let mut addresses = Vec::new();
            for record in &response.answers {
                if &record.name != owner {
                    continue;
                }
                let RData::AAAA(address) = &record.data else {
                    continue;
                };
                ttl = minimum_ttl(ttl, record.ttl);
                if addresses.len() < MAX_APPLICATION_RESOLVED_CANDIDATES
                    && !addresses.contains(&address.0)
                {
                    addresses.push(address.0);
                }
            }
            (!addresses.is_empty()).then(|| {
                (
                    DnsAddressRecords::Aaaa(Arc::from(addresses)),
                    Duration::from_secs(u64::from(ttl.unwrap_or(0))),
                )
            })
        }
        _ => None,
    }
}

fn final_answer_owner<'a>(
    qname: &'a Name,
    answers: &'a [Record],
) -> Option<(&'a Name, Option<u32>)> {
    let mut owner = qname;
    let mut ttl = None;
    for _ in 0..=answers.len() {
        let Some(record) = answers
            .iter()
            .find(|record| &record.name == owner && matches!(record.data, RData::CNAME(_)))
        else {
            return Some((owner, ttl));
        };
        let RData::CNAME(cname) = &record.data else {
            unreachable!("the selected record is a CNAME")
        };
        ttl = minimum_ttl(ttl, record.ttl);
        owner = &cname.0;
    }
    None
}

fn minimum_ttl(current: Option<u32>, candidate: u32) -> Option<u32> {
    Some(current.map_or(candidate, |current| current.min(candidate)))
}

fn negative_ttl(response: &Message) -> Option<Duration> {
    response
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
        .map(|ttl| Duration::from_secs(u64::from(ttl)))
}

fn cached_application_response(request: &Message, records: &DnsAddressRecords) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    let Some(question) = request.queries.first() else {
        return response;
    };
    response.add_query(question.clone());
    match records {
        DnsAddressRecords::A(records) => {
            for address in records.iter().copied() {
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    0,
                    RData::A(address.into()),
                ));
            }
        }
        DnsAddressRecords::Aaaa(records) => {
            for address in records.iter().copied() {
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    0,
                    RData::AAAA(address.into()),
                ));
            }
        }
    }
    response
}

fn cached_application_negative_response(request: &Message) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_queries(request.queries.iter().cloned());
    response
}

fn bind_response(mut response: Message, request: &Message, question: &Query) -> Message {
    response.metadata.id = request.metadata.id;
    response.queries.clear();
    response.add_query(question.clone());
    response
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.add_queries(request.queries.iter().cloned());
    response
}

fn encode_response(
    mut response: Message,
    transport: ProxyTransport,
    advertised: u16,
) -> Option<Vec<u8>> {
    let wire = response.to_vec().ok()?;
    let limit = usize::from(advertised).min(4096);
    if transport == ProxyTransport::Udp && wire.len() > limit {
        response = response.truncate();
        response.to_vec().ok()
    } else {
        Some(wire)
    }
}

fn bind_tcp(address: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = match address.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

async fn udp_loop(
    socket: UdpSocket,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut request = [0_u8; 4096];
    loop {
        let (length, peer) = tokio::select! {
            result = socket.recv_from(&mut request) => result?,
            _ = cancelled(&mut cancel) => return Ok(()),
        };
        let response = tokio::select! {
            response = proxy.answer(ProxyIngress::Listener(inbound), ProxyTransport::Udp, &request[..length]) => response,
            _ = cancelled(&mut cancel) => return Ok(()),
        };
        if let Some(response) = response {
            let sent = socket.send_to(&response, peer).await?;
            if sent != response.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short DNS datagram",
                ));
            }
        }
    }
}

async fn tcp_loop(
    listener: TcpListener,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut children = JoinSet::new();
    loop {
        let (stream, _) = tokio::select! {
            result = listener.accept() => result?,
            _ = children.join_next(), if !children.is_empty() => continue,
            _ = cancelled(&mut cancel) => break,
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let proxy = Arc::clone(&proxy);
        children.spawn(async move {
            let _permit = permit;
            tcp_connection(stream, inbound, proxy, idle_timeout).await;
        });
    }
    children.abort_all();
    while children.join_next().await.is_some() {}
    Ok(())
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    if *cancel.borrow() {
        return;
    }
    let _ = cancel.changed().await;
}

async fn tcp_connection(
    stream: TcpStream,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    idle_timeout: Duration,
) {
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(_) => return,
    };
    let (mut stream, mut responses) =
        HickoryTcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);
    loop {
        let Ok(Some(Ok(request))) = tokio::time::timeout(idle_timeout, stream.next()).await else {
            return;
        };
        let Some(response) = proxy
            .answer(
                ProxyIngress::Listener(inbound),
                ProxyTransport::Tcp,
                request.bytes(),
            )
            .await
        else {
            return;
        };
        if responses.send(SerialMessage::new(response, peer)).is_err() {
            return;
        }
    }
}
