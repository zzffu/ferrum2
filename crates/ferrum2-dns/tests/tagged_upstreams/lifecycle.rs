use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_dependency_lookup_obeys_aggregate_admission() {
    let _network = TEST_NETWORK.lock().await;
    let fixture = PlainFixture::start().await;
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("silent upstream bind");
    let silent_address = silent.local_addr().expect("silent upstream address");
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            configured_server(silent_address, DnsUpstreamTransport::Udp, false),
            configured_server(fixture.address, DnsUpstreamTransport::Udp, false),
        ],
        Duration::from_millis(600),
        NonZeroU16::new(1).expect("one aggregate admission permit"),
        egress.clone(),
    )
    .expect("nested resolver");
    owner.ready().await.expect("nested resolver ready");
    let resolver = Arc::new(resolver);
    let root_resolver = Arc::clone(&resolver);
    let root = tokio::spawn(async move {
        root_resolver
            .lookup(
                0,
                Name::from_ascii("blocked.resolver.test.").expect("blocked root name"),
                RecordType::A,
            )
            .await
    });
    tokio::time::timeout(Duration::from_millis(100), async {
        while egress.calls().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("root query reached its silent upstream");

    let slot = Arc::new(OnceLock::new());
    slot.set(Arc::downgrade(&resolver))
        .map_err(|_| ())
        .expect("initialize nested resolver slot");
    let backend = TaggedServerApplicationResolveBackend::new(slot, 1);
    let domain = CanonicalDomain::new("answer.resolver.test").expect("nested domain");
    assert_eq!(
        backend
            .resolve(ApplicationResolveRequest::new(
                ApplicationResolveContext::new(1, Network::Tcp),
                &domain,
                NonZeroU16::new(443).expect("nested target port"),
                DnsStrategy::Ipv4Only,
            ))
            .await,
        Err(DnsError::Busy)
    );
    assert_eq!(root.await.expect("root query join"), Err(DnsError::Timeout));

    drop(backend);
    drop(resolver);
    owner.shutdown().await.expect("nested resolver shutdown");
    fixture.shutdown().await;
}

struct CrossResolverEgress {
    resolver: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
    observed: Arc<Mutex<Option<DnsError>>>,
}

impl DnsEgress for CrossResolverEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        _plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        SystemDnsEgress.connect_tcp(target, None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        _target: TargetAddr,
        _plan: Option<EgressPlanSnapshot>,
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let resolver = Arc::clone(&self.resolver);
        let observed = Arc::clone(&self.observed);
        Box::pin(async move {
            let backend = TaggedServerApplicationResolveBackend::new(resolver, 0);
            let domain =
                CanonicalDomain::new("answer.resolver.test").expect("cross-owner resolver domain");
            let error = backend
                .resolve(ApplicationResolveRequest::new(
                    ApplicationResolveContext::new(3, Network::Udp),
                    &domain,
                    NonZeroU16::new(53).expect("cross-owner resolver port"),
                    DnsStrategy::Ipv4Only,
                ))
                .await
                .expect_err("saturated foreign resolver must reject the dependency");
            *observed.lock().expect("cross-owner observation") = Some(error);
            Err(std::io::Error::other(
                "cross-owner dependency remained independently saturated",
            ))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dependency_scope_never_bypasses_another_resolver_admission() {
    let _network = TEST_NETWORK.lock().await;
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("foreign silent upstream bind");
    let silent_address = silent.local_addr().expect("foreign silent address");
    let foreign_egress = Arc::new(RecordingEgress::default());
    let (foreign, mut foreign_owner) = TaggedResolver::new(
        vec![configured_server(
            silent_address,
            DnsUpstreamTransport::Udp,
            false,
        )],
        Duration::from_millis(500),
        NonZeroU16::new(1).expect("foreign aggregate admission"),
        foreign_egress.clone(),
    )
    .expect("foreign resolver");
    foreign_owner.ready().await.expect("foreign resolver ready");
    let foreign = Arc::new(foreign);
    let blocked_foreign = Arc::clone(&foreign);
    let blocked = tokio::spawn(async move {
        blocked_foreign
            .lookup(
                0,
                Name::from_ascii("blocked.resolver.test.").expect("blocked foreign name"),
                RecordType::A,
            )
            .await
    });
    tokio::time::timeout(Duration::from_millis(100), async {
        while foreign_egress.calls().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("foreign resolver admission occupied");
    assert_eq!(foreign.stats().queries, 1);

    let foreign_slot = Arc::new(OnceLock::new());
    foreign_slot
        .set(Arc::downgrade(&foreign))
        .map_err(|_| ())
        .expect("install foreign resolver");
    let observed = Arc::new(Mutex::new(None));
    let egress = Arc::new(CrossResolverEgress {
        resolver: foreign_slot,
        observed: Arc::clone(&observed),
    });
    let (resolver, mut owner) = TaggedResolver::new(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::domain("cross-owner.resolver.test", silent_address.port())
                .expect("cross-owner target"),
            resolved_targets: Box::new([]),
            detour: Some(EgressPlanHandle::direct(0)),
        }],
        Duration::from_millis(300),
        NonZeroU16::new(1).expect("local aggregate admission"),
        egress,
    )
    .expect("local resolver");
    owner.ready().await.expect("local resolver ready");

    assert_eq!(
        resolver
            .lookup(
                0,
                Name::from_ascii("answer.resolver.test.").expect("local query name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::Protocol)
    );
    assert_eq!(
        *observed.lock().expect("cross-owner observation"),
        Some(DnsError::Busy)
    );
    assert_eq!(foreign.stats().queries, 1);
    assert_eq!(
        blocked.await.expect("foreign query join"),
        Err(DnsError::Timeout)
    );

    drop(resolver);
    owner.shutdown().await.expect("local resolver shutdown");
    drop(foreign);
    foreign_owner
        .shutdown()
        .await
        .expect("foreign resolver shutdown");
}

struct NestedResolverEgress {
    resolver: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
    fixture: SocketAddr,
    max_query_chains: Arc<AtomicUsize>,
    binds: Arc<AtomicUsize>,
}

impl DnsEgress for NestedResolverEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        _plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        SystemDnsEgress.connect_tcp(target, None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: TargetAddr,
        _plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let resolver = Arc::clone(&self.resolver);
        let fixture = self.fixture;
        let max_query_chains = Arc::clone(&self.max_query_chains);
        let binds = Arc::clone(&self.binds);
        Box::pin(async move {
            binds.fetch_add(1, Ordering::AcqRel);
            if let Some(active) = resolver
                .get()
                .and_then(std::sync::Weak::upgrade)
                .map(|resolver| resolver.stats().queries)
            {
                max_query_chains.fetch_max(active, Ordering::AcqRel);
            }
            let nested_server = match target.canonical_domain().map(|domain| domain.as_str()) {
                Some("outer-0.resolver.test") => Some(1),
                Some("outer-1.resolver.test") => Some(2),
                _ => None,
            };
            let dial_target = if let Some(nested_server) = nested_server {
                let backend = TaggedServerApplicationResolveBackend::new(resolver, nested_server);
                let domain =
                    CanonicalDomain::new("answer.resolver.test").expect("nested resolver domain");
                backend
                    .resolve(ApplicationResolveRequest::new(
                        ApplicationResolveContext::new(1, Network::Udp),
                        &domain,
                        NonZeroU16::new(53).expect("nested resolver port"),
                        DnsStrategy::Ipv4Only,
                    ))
                    .await
                    .map_err(|_| std::io::Error::other("nested DNS resolution failed"))?;
                TargetAddr::ip(fixture).expect("fixture target")
            } else {
                target
            };
            SystemDnsEgress.bind_udp(dial_target, None, tasks).await
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_dependency_chain_shares_one_aggregate_admission() {
    let _network = TEST_NETWORK.lock().await;
    let fixture = PlainFixture::start().await;
    let slot = Arc::new(OnceLock::new());
    let max_query_chains = Arc::new(AtomicUsize::new(0));
    let binds = Arc::new(AtomicUsize::new(0));
    let egress = Arc::new(NestedResolverEgress {
        resolver: Arc::clone(&slot),
        fixture: fixture.address,
        max_query_chains: Arc::clone(&max_query_chains),
        binds: Arc::clone(&binds),
    });
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            DnsUpstreamSpec {
                transport: DnsUpstreamTransport::Udp,
                target: TargetAddr::domain("outer-0.resolver.test", fixture.address.port())
                    .expect("first outer domain target"),
                resolved_targets: Box::new([]),
                detour: Some(EgressPlanHandle::direct(0)),
            },
            DnsUpstreamSpec {
                transport: DnsUpstreamTransport::Udp,
                target: TargetAddr::domain("outer-1.resolver.test", fixture.address.port())
                    .expect("second outer domain target"),
                resolved_targets: Box::new([]),
                detour: Some(EgressPlanHandle::direct(1)),
            },
            configured_server(fixture.address, DnsUpstreamTransport::Udp, false),
        ],
        Duration::from_millis(700),
        NonZeroU16::new(1).expect("one aggregate admission permit"),
        egress,
    )
    .expect("nested dependency resolver");
    owner
        .ready()
        .await
        .expect("nested dependency resolver ready");
    let resolver = Arc::new(resolver);
    slot.set(Arc::downgrade(&resolver))
        .map_err(|_| ())
        .expect("install nested resolver");

    let lookup = resolver
        .lookup(
            0,
            Name::from_ascii("answer.resolver.test.").expect("outer query"),
            RecordType::A,
        )
        .await
        .expect("nested dependency chain completes with one admission");
    assert!(
        lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 41))))
    );
    assert_eq!(max_query_chains.load(Ordering::Acquire), 1);
    assert_eq!(binds.load(Ordering::Acquire), 3);
    assert_eq!(resolver.stats().queries, 0);

    drop(resolver);
    owner.shutdown().await.expect("nested resolver shutdown");
    fixture.shutdown().await;
}
