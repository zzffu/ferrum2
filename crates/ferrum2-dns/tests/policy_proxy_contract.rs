use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrum2_core::route::Network;
use ferrum2_core::{CanonicalDomain, TargetAddr};
use ferrum2_dns::{
    ApplicationResolveContext, ApplicationResolveRequest, DnsCache, DnsCacheAnswer, DnsCacheKey,
    DnsCacheQtype, DnsError, DnsPolicyAction, DnsPolicyMatcher, DnsPolicyObservation,
    DnsPolicyProgram, DnsPolicyRoute, DnsPolicyRule, DnsPortRange, DnsProxy, DnsServerId,
    DnsStrategy, DnsUpstreamSpec, DnsUpstreamTransport, ProxyIngress, ProxyTransport,
    ResolverGeneration, TaggedResolver,
};
use ferrum2_rule::{
    CompiledMatchSet, MatchSetBuilder, RuleEngineRegistry, RuleEngineSnapshot,
    RuleEngineSnapshotBuilder, RuleSetId,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

static TEST_NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const LOCAL: DnsPolicyRoute = DnsPolicyRoute::new(DnsServerId::new(0), DnsStrategy::Ipv4Only);
const REMOTE: DnsPolicyRoute = DnsPolicyRoute::new(DnsServerId::new(1), DnsStrategy::PreferIpv4);

fn suffix_set(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_domain_suffix(value).expect("domain suffix");
    builder.build().expect("suffix set")
}

fn exact_set(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_exact_domain(value).expect("exact domain");
    builder.build().expect("exact set")
}

fn ip_set(address: IpAddr) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_ip(address).expect("IP matcher");
    builder.build().expect("IP set")
}

fn snapshot(sets: Vec<(&str, CompiledMatchSet)>) -> (RuleEngineSnapshot, Vec<RuleSetId>) {
    let mut builder = RuleEngineSnapshotBuilder::new(1);
    let mut ids = Vec::with_capacity(sets.len());
    for (tag, set) in sets {
        let match_set = builder.add_match_set(set).expect("snapshot match set");
        ids.push(
            builder
                .add_rule_set(tag, match_set)
                .expect("snapshot RuleSet"),
        );
    }
    (builder.build().expect("snapshot"), ids)
}

fn matcher(rule_sets: Vec<RuleSetId>) -> DnsPolicyMatcher {
    DnsPolicyMatcher::try_new(Vec::new(), rule_sets, Vec::new(), Vec::new(), Vec::new())
        .expect("RuleSet matcher")
}

fn policy(
    snapshot: &RuleEngineSnapshot,
    rules: Vec<DnsPolicyRule>,
    final_route: DnsPolicyRoute,
) -> Arc<DnsPolicyProgram> {
    Arc::new(DnsPolicyProgram::try_new(rules, final_route, snapshot).expect("DNS policy"))
}

fn final_proxy(
    resolver: Arc<TaggedResolver>,
    generation: u64,
    final_route: DnsPolicyRoute,
    listener_count: usize,
    ordinary_count: usize,
) -> DnsProxy {
    let snapshot = RuleEngineSnapshotBuilder::new(generation)
        .build()
        .expect("empty rule snapshot");
    let program = policy(&snapshot, Vec::new(), final_route);
    DnsProxy::new(
        resolver,
        program,
        Arc::new(RuleEngineRegistry::new(snapshot)),
        listener_count,
        ordinary_count,
    )
}

fn udp_server(socket: &UdpSocket) -> DnsUpstreamSpec {
    DnsUpstreamSpec {
        transport: DnsUpstreamTransport::Udp,
        target: TargetAddr::ip(socket.local_addr().expect("upstream address"))
            .expect("non-zero upstream target"),
        resolved_targets: Box::new([]),
        detour: None,
    }
}

fn wire_query(id: u16, name: &str, record_type: RecordType) -> Message {
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        record_type,
    ));
    request
}

fn address_response(request: &Message, address: IpAddr) -> Message {
    address_response_with_ttl(request, address, 30)
}

fn address_response_with_ttl(request: &Message, address: IpAddr, ttl: u32) -> Message {
    let question = request.queries.first().expect("one question").clone();
    let data = match address {
        IpAddr::V4(address) => RData::A(A(address)),
        IpAddr::V6(address) => RData::AAAA(AAAA(address)),
    };
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response
        .add_query(question.clone())
        .add_answer(Record::from_rdata(question.name().clone(), ttl, data));
    response
}

fn negative_response(request: &Message, soa_ttl: Option<(u32, u32)>) -> Message {
    let question = request.queries.first().expect("one question").clone();
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::NXDomain;
    response.add_query(question);
    if let Some((record_ttl, minimum)) = soa_ttl {
        response.add_authority(Record::from_rdata(
            Name::from_ascii("policy.invalid.").expect("negative zone"),
            record_ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.policy.invalid.").expect("negative primary"),
                Name::from_ascii("hostmaster.policy.invalid.").expect("negative mailbox"),
                1,
                60,
                60,
                300,
                minimum,
            )),
        ));
    }
    response
}

async fn receive_request(socket: &UdpSocket) -> (Message, SocketAddr) {
    let mut wire = [0_u8; 4096];
    let (length, peer) =
        tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut wire))
            .await
            .expect("upstream query timeout")
            .expect("upstream query");
    (
        Message::from_vec(&wire[..length]).expect("typed upstream query"),
        peer,
    )
}

async fn send_response(socket: &UdpSocket, peer: SocketAddr, response: Message) {
    socket
        .send_to(&response.to_vec().expect("upstream response encode"), peer)
        .await
        .expect("upstream response send");
}

#[tokio::test]
async fn reject_is_refused_for_wire_and_terminal_for_application_without_upstream() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("reject upstream");
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![udp_server(&upstream)],
        Duration::from_millis(50),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("reject resolver");
    owner.ready().await.expect("reject resolver ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![("ads", suffix_set("ads.invalid"))]);
    let program = policy(
        &snapshot,
        vec![DnsPolicyRule::new(matcher(ids), DnsPolicyAction::Reject)],
        LOCAL,
    );
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let observations = Arc::new(Mutex::new(Vec::<DnsPolicyObservation>::new()));
    let observation_sink = Arc::clone(&observations);
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, registry, 1, 1).with_policy_observer(
        Arc::new(move |observation| {
            observation_sink
                .lock()
                .expect("policy observation lock")
                .push(observation);
        }),
    );

    let request = wire_query(0x6101, "tracker.ads.invalid.", RecordType::A);
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("reject request"),
        )
        .await
        .expect("reject response");
    let response = Message::from_vec(&response).expect("typed reject response");
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert_eq!(response.metadata.id, request.metadata.id);
    assert_eq!(response.queries, request.queries);

    let domain = CanonicalDomain::new("tracker.ads.invalid").expect("application domain");
    let application = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(0, Network::Tcp),
        &domain,
        NonZeroU16::new(443).expect("application port"),
        DnsStrategy::Ipv4Only,
    );
    assert_eq!(
        proxy
            .resolve_application(application)
            .await
            .expect_err("application reject is terminal"),
        DnsError::Protocol
    );
    let mut wire = [0_u8; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), upstream.recv_from(&mut wire))
            .await
            .is_err(),
        "reject reached the upstream"
    );
    {
        let observations = observations.lock().expect("policy observations");
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|observation| {
            observation.query_evaluated()
                && !observation.response_evaluated()
                && observation.query_candidates() == 1
        }));
    }

    drop((proxy, resolver, upstream));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("reject resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn response_is_reused_across_same_server_continuation_and_rebound_to_request() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("memo upstream");
    let server = udp_server(&upstream);
    let upstream_task = tokio::spawn(async move {
        let (request, peer) = receive_request(&upstream).await;
        send_response(
            &upstream,
            peer,
            address_response(&request, Ipv4Addr::new(10, 0, 0, 2).into()),
        )
        .await;
        let mut wire = [0_u8; 4096];
        tokio::time::timeout(Duration::from_millis(50), upstream.recv_from(&mut wire))
            .await
            .is_err()
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("memo resolver");
    owner.ready().await.expect("memo resolver ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![
        ("first", ip_set(Ipv4Addr::new(10, 0, 0, 1).into())),
        ("second", ip_set(Ipv4Addr::new(10, 0, 0, 2).into())),
    ]);
    let rules = ids
        .into_iter()
        .map(|id| DnsPolicyRule::new(matcher(vec![id]), DnsPolicyAction::Route(LOCAL)))
        .collect();
    let program = policy(&snapshot, rules, LOCAL);
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, registry, 1, 0);

    let request = wire_query(0x6102, "memo.policy.invalid.", RecordType::A);
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("memo request"),
        )
        .await
        .expect("memo response");
    let response = Message::from_vec(&response).expect("typed memo response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.metadata.id, request.metadata.id);
    assert_eq!(response.queries, request.queries);
    assert_eq!(
        response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(10, 0, 0, 2))))
    );
    assert!(upstream_task.await.expect("memo upstream join"));

    drop((proxy, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("memo resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn response_miss_continues_to_the_final_server_once() {
    let _network = TEST_NETWORK.lock().await;
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("local upstream");
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("remote upstream");
    let servers = vec![udp_server(&local), udp_server(&remote)];
    let local_task = tokio::spawn(async move {
        let (request, peer) = receive_request(&local).await;
        send_response(
            &local,
            peer,
            address_response(&request, Ipv4Addr::new(203, 0, 113, 10).into()),
        )
        .await;
    });
    let remote_task = tokio::spawn(async move {
        let (request, peer) = receive_request(&remote).await;
        send_response(
            &remote,
            peer,
            address_response(&request, Ipv4Addr::new(198, 51, 100, 44).into()),
        )
        .await;
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        servers,
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("continuation resolver");
    owner.ready().await.expect("continuation resolver ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![("cnip", ip_set(Ipv4Addr::new(10, 0, 0, 0).into()))]);
    let program = policy(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(ids),
            DnsPolicyAction::Route(LOCAL),
        )],
        REMOTE,
    );
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, registry, 1, 0);

    let request = wire_query(0x6103, "continuation.policy.invalid.", RecordType::A);
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("continuation request"),
        )
        .await
        .expect("continuation response");
    let response = Message::from_vec(&response).expect("typed continuation response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 44))))
    );
    local_task.await.expect("local upstream join");
    remote_task.await.expect("remote upstream join");

    drop((proxy, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("continuation resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn application_policy_route_overrides_requested_strategy() {
    let _network = TEST_NETWORK.lock().await;
    let unused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("unused upstream");
    let selected = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("selected upstream");
    let servers = vec![udp_server(&unused), udp_server(&selected)];
    let selected_task = tokio::spawn(async move {
        for (record_type, address) in [
            (RecordType::A, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 81))),
            (
                RecordType::AAAA,
                IpAddr::V6("2001:db8::81".parse().expect("policy IPv6")),
            ),
        ] {
            let (request, peer) = receive_request(&selected).await;
            assert_eq!(request.queries[0].query_type(), record_type);
            send_response(&selected, peer, address_response(&request, address)).await;
        }
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        servers,
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("application policy resolver");
    owner.ready().await.expect("application policy ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![(
        "application",
        exact_set("application.policy.invalid"),
    )]);
    let override_route = DnsPolicyRoute::new(DnsServerId::new(1), DnsStrategy::Ipv6Only);
    let application_matcher = DnsPolicyMatcher::try_new_with_application_constraints(
        Vec::new(),
        ids,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![NonZeroU16::new(443).expect("policy port")],
        vec![DnsPortRange::try_new(400, 500).expect("policy port range")],
    )
    .expect("application matcher");
    let program = policy(
        &snapshot,
        vec![DnsPolicyRule::new(
            application_matcher,
            DnsPolicyAction::Route(override_route),
        )],
        LOCAL,
    );
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, registry, 0, 1);
    let domain =
        CanonicalDomain::new("Application.Policy.Invalid.").expect("canonical policy domain");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(0, Network::Tcp),
        &domain,
        NonZeroU16::new(443).expect("application port"),
        DnsStrategy::PreferIpv4,
    );

    assert_eq!(
        proxy
            .resolve_application(request)
            .await
            .expect("application policy resolution"),
        [SocketAddr::new(
            Ipv6Addr::from([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81,
            ])
            .into(),
            443,
        )]
    );
    selected_task.await.expect("selected upstream join");
    let mut wire = [0_u8; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), unused.recv_from(&mut wire))
            .await
            .is_err(),
        "application query reached the final server"
    );

    drop((proxy, resolver, unused));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("application policy shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn application_selected_server_failure_is_terminal_without_final_fallback() {
    let _network = TEST_NETWORK.lock().await;
    let selected = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("selected failure upstream");
    let fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("forbidden fallback upstream");
    let servers = vec![udp_server(&selected), udp_server(&fallback)];
    let (resolver, mut owner) = TaggedResolver::direct(
        servers,
        Duration::from_millis(50),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("failure resolver");
    owner.ready().await.expect("failure resolver ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![("cnip", ip_set(Ipv4Addr::new(10, 0, 0, 1).into()))]);
    let program = policy(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(ids),
            DnsPolicyAction::Route(LOCAL),
        )],
        REMOTE,
    );
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, registry, 0, 1);
    let domain = CanonicalDomain::new("failure.policy.invalid").expect("failure domain");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(0, Network::Udp),
        &domain,
        NonZeroU16::new(53).expect("application port"),
        DnsStrategy::Ipv4Only,
    );

    let resolve = proxy.resolve_application(request);
    let receive = receive_request(&selected);
    let (result, (upstream_request, _)) = tokio::join!(resolve, receive);
    assert_eq!(upstream_request.queries[0].query_type(), RecordType::A);
    assert_eq!(
        result.expect_err("selected failure must be terminal"),
        DnsError::Timeout
    );
    let mut wire = [0_u8; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), fallback.recv_from(&mut wire))
            .await
            .is_err(),
        "selected failure reached the final server"
    );

    drop((proxy, resolver, selected, fallback));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("failure resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn application_cache_uses_minimum_positive_ttl_and_is_shared_by_transport_and_generation() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("positive cache upstream");
    let server = udp_server(&upstream);
    let upstream_task = tokio::spawn(async move {
        for index in 0..3 {
            let (request, peer) = receive_request(&upstream).await;
            let response = match index {
                0 => {
                    let question = request.queries[0].clone();
                    let final_owner =
                        Name::from_ascii("final.positive.policy.invalid.").expect("final owner");
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response
                        .add_query(question.clone())
                        .add_answer(Record::from_rdata(
                            question.name().clone(),
                            0,
                            RData::CNAME(CNAME(final_owner.clone())),
                        ))
                        .add_answer(Record::from_rdata(
                            final_owner,
                            30,
                            RData::A(A(Ipv4Addr::new(192, 0, 2, 91))),
                        ));
                    response
                }
                1 => address_response_with_ttl(&request, Ipv4Addr::new(192, 0, 2, 92).into(), 30),
                2 => address_response_with_ttl(&request, Ipv4Addr::new(192, 0, 2, 93).into(), 30),
                _ => unreachable!("bounded positive-cache requests"),
            };
            send_response(&upstream, peer, response).await;
        }
        let mut wire = [0_u8; 4096];
        tokio::time::timeout(Duration::from_millis(50), upstream.recv_from(&mut wire))
            .await
            .is_err()
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("positive cache resolver");
    owner.ready().await.expect("positive cache resolver ready");
    let resolver = Arc::new(resolver);
    let cache =
        DnsCache::try_new(NonZeroUsize::new(8).expect("cache capacity")).expect("positive cache");
    let generation_one =
        final_proxy(Arc::clone(&resolver), 1, LOCAL, 0, 1).with_cache(cache.clone());
    let generation_two = final_proxy(Arc::clone(&resolver), 2, LOCAL, 0, 1).with_cache(cache);
    let domain = CanonicalDomain::new("positive.policy.invalid").expect("positive cache domain");
    let request = |network| {
        ApplicationResolveRequest::new(
            ApplicationResolveContext::new(0, network),
            &domain,
            NonZeroU16::new(443).expect("positive cache port"),
            DnsStrategy::Ipv4Only,
        )
    };
    let expected = |octet| SocketAddr::new(Ipv4Addr::new(192, 0, 2, octet).into(), 443);

    assert_eq!(
        generation_one
            .resolve_application(request(Network::Tcp))
            .await
            .expect("zero minimum TTL response"),
        [expected(91)]
    );
    assert_eq!(
        generation_one
            .resolve_application(request(Network::Udp))
            .await
            .expect("positive cache fill"),
        [expected(92)]
    );
    assert_eq!(
        generation_one
            .resolve_application(request(Network::Tcp))
            .await
            .expect("cross-transport positive cache hit"),
        [expected(92)]
    );
    assert_eq!(
        generation_two
            .resolve_application(request(Network::Udp))
            .await
            .expect("generation cache miss"),
        [expected(93)]
    );
    assert!(upstream_task.await.expect("positive cache upstream join"));

    drop((generation_one, generation_two, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("positive cache shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn live_policy_refresh_uses_the_evaluation_generation_for_cache_isolation() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("generation upstream");
    let server = udp_server(&upstream);
    let upstream_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (request, peer) = receive_request(&upstream).await;
            send_response(
                &upstream,
                peer,
                address_response(&request, Ipv4Addr::new(192, 0, 2, 77).into()),
            )
            .await;
        }
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_millis(200),
        NonZeroU16::new(2).expect("two in-flight queries"),
    )
    .expect("generation resolver");
    owner.ready().await.expect("generation resolver ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![("domain", suffix_set("generation.invalid"))]);
    let program = policy(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(ids),
            DnsPolicyAction::Route(LOCAL),
        )],
        LOCAL,
    );
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let cache =
        DnsCache::try_new(NonZeroUsize::new(8).expect("cache capacity")).expect("generation cache");
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, Arc::clone(&registry), 0, 1)
        .with_cache(cache);
    let domain = CanonicalDomain::new("host.generation.invalid").expect("generation domain");
    let request = || {
        ApplicationResolveRequest::new(
            ApplicationResolveContext::new(0, Network::Tcp),
            &domain,
            NonZeroU16::new(443).expect("application port"),
            DnsStrategy::Ipv4Only,
        )
    };

    assert_eq!(
        proxy.resolve_application(request()).await,
        Ok(vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 77), 443))])
    );
    let current = registry.snapshot();
    let next = current
        .builder_for_generation(2)
        .expect("next generation builder")
        .build()
        .expect("next generation snapshot");
    registry.publish(next).expect("publish next generation");
    assert_eq!(
        proxy.resolve_application(request()).await,
        Ok(vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 77), 443))])
    );
    upstream_task.await.expect("two generation queries");

    drop((proxy, registry, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("generation resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn application_negative_cache_requires_soa_ttl() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("negative cache upstream");
    let server = udp_server(&upstream);
    let upstream_task = tokio::spawn(async move {
        let (first, first_peer) = receive_request(&upstream).await;
        send_response(&upstream, first_peer, negative_response(&first, None)).await;
        let (second, second_peer) = receive_request(&upstream).await;
        send_response(
            &upstream,
            second_peer,
            negative_response(&second, Some((30, 10))),
        )
        .await;
        let mut wire = [0_u8; 4096];
        tokio::time::timeout(Duration::from_millis(50), upstream.recv_from(&mut wire))
            .await
            .is_err()
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("negative cache resolver");
    owner.ready().await.expect("negative cache resolver ready");
    let resolver = Arc::new(resolver);
    let cache =
        DnsCache::try_new(NonZeroUsize::new(4).expect("cache capacity")).expect("negative cache");
    let proxy = final_proxy(Arc::clone(&resolver), 7, LOCAL, 0, 1).with_cache(cache.clone());
    let domain = CanonicalDomain::new("negative.policy.invalid").expect("negative cache domain");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(0, Network::Tcp),
        &domain,
        NonZeroU16::new(443).expect("negative cache port"),
        DnsStrategy::Ipv4Only,
    );

    assert_eq!(
        proxy
            .resolve_application(request)
            .await
            .expect_err("unverified negative response"),
        DnsError::NxDomain
    );
    assert_eq!(
        proxy
            .resolve_application(request)
            .await
            .expect_err("SOA-backed negative response"),
        DnsError::NxDomain
    );
    let key = DnsCacheKey::new(
        DnsServerId::new(0),
        domain.clone(),
        DnsCacheQtype::A,
        ResolverGeneration::new(7),
    );
    assert_eq!(
        cache
            .get(&key, Instant::now())
            .expect("negative cache read"),
        Some(DnsCacheAnswer::Negative)
    );
    assert_eq!(
        proxy
            .resolve_application(request)
            .await
            .expect_err("cached negative response"),
        DnsError::NoData
    );
    assert!(upstream_task.await.expect("negative cache upstream join"));

    drop((proxy, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("negative cache shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn policy_response_continuation_reuses_server_scoped_cache_across_transports() {
    let _network = TEST_NETWORK.lock().await;
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cached policy local");
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cached policy remote");
    let servers = vec![udp_server(&local), udp_server(&remote)];
    let local_task = tokio::spawn(async move {
        let (request, peer) = receive_request(&local).await;
        send_response(
            &local,
            peer,
            address_response(&request, Ipv4Addr::new(203, 0, 113, 20).into()),
        )
        .await;
        let mut wire = [0_u8; 4096];
        tokio::time::timeout(Duration::from_millis(50), local.recv_from(&mut wire))
            .await
            .is_err()
    });
    let remote_task = tokio::spawn(async move {
        let (request, peer) = receive_request(&remote).await;
        send_response(
            &remote,
            peer,
            address_response(&request, Ipv4Addr::new(198, 51, 100, 120).into()),
        )
        .await;
        let mut wire = [0_u8; 4096];
        tokio::time::timeout(Duration::from_millis(50), remote.recv_from(&mut wire))
            .await
            .is_err()
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        servers,
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one in-flight query"),
    )
    .expect("cached policy resolver");
    owner.ready().await.expect("cached policy resolver ready");
    let resolver = Arc::new(resolver);
    let (snapshot, ids) = snapshot(vec![("cnip", ip_set(Ipv4Addr::new(10, 0, 0, 1).into()))]);
    let program = policy(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(ids),
            DnsPolicyAction::Route(LOCAL),
        )],
        DnsPolicyRoute::new(DnsServerId::new(1), DnsStrategy::Ipv4Only),
    );
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let cache = DnsCache::try_new(NonZeroUsize::new(8).expect("cache capacity"))
        .expect("cached policy cache");
    let proxy = DnsProxy::new(Arc::clone(&resolver), program, registry, 0, 1).with_cache(cache);
    let domain =
        CanonicalDomain::new("continuation.cache.invalid").expect("cached continuation domain");
    let request = |network| {
        ApplicationResolveRequest::new(
            ApplicationResolveContext::new(0, network),
            &domain,
            NonZeroU16::new(443).expect("cached continuation port"),
            DnsStrategy::Ipv4Only,
        )
    };
    let expected = [SocketAddr::new(
        Ipv4Addr::new(198, 51, 100, 120).into(),
        443,
    )];

    assert_eq!(
        proxy
            .resolve_application(request(Network::Tcp))
            .await
            .expect("cold cached continuation"),
        expected
    );
    assert_eq!(
        proxy
            .resolve_application(request(Network::Udp))
            .await
            .expect("warm cached continuation"),
        expected
    );
    assert!(local_task.await.expect("cached local join"));
    assert!(remote_task.await.expect("cached remote join"));

    drop((proxy, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("cached policy shutdown")
            .runtime_tasks,
        0
    );
}
