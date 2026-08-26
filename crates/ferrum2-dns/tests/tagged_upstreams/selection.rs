use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_resolved_upstream_tries_all_candidates_under_one_deadline() {
    let _network = TEST_NETWORK.lock().await;
    let fixture = PlainFixture::start().await;
    let unreachable = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), fixture.address.port()));
    let logical = TargetAddr::domain("bootstrap.resolver.test", fixture.address.port())
        .expect("logical upstream target");
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: logical,
            resolved_targets: vec![unreachable, fixture.address].into_boxed_slice(),
            detour: None,
        }],
        Duration::from_millis(600),
        NonZeroU16::new(1).expect("one root query"),
        egress.clone(),
    )
    .expect("candidate resolver");
    owner.ready().await.expect("candidate resolver ready");

    let lookup = resolver
        .lookup(
            0,
            Name::from_ascii("answer.resolver.test.").expect("candidate query"),
            RecordType::A,
        )
        .await
        .expect("second candidate succeeds");
    assert!(
        lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 41))))
    );
    assert_eq!(
        egress
            .calls()
            .into_iter()
            .map(|call| call.target)
            .collect::<Vec<_>>(),
        vec![numeric_target(unreachable), numeric_target(fixture.address)]
    );

    drop(resolver);
    owner.shutdown().await.expect("candidate resolver shutdown");
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tagged_application_backend_queries_only_its_explicit_server_and_family() {
    let _network = TEST_NETWORK.lock().await;
    let fixture = PlainFixture::start().await;
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![configured_server(
            fixture.address,
            DnsUpstreamTransport::Udp,
            false,
        )],
        Duration::from_secs(1),
        NonZeroU16::new(2).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start application resolver");
    owner.ready().await.expect("application resolver ready");
    let resolver = Arc::new(resolver);
    let slot = Arc::new(OnceLock::new());
    slot.set(Arc::downgrade(&resolver))
        .map_err(|_| ())
        .expect("initialize tagged resolver slot");
    let backend = TaggedServerApplicationResolveBackend::new(Arc::clone(&slot), 0);
    let domain = CanonicalDomain::new("answer.resolver.test").expect("application domain");

    assert_eq!(
        backend
            .resolve(ApplicationResolveRequest::new(
                ApplicationResolveContext::new(7, Network::Tcp),
                &domain,
                NonZeroU16::new(443).expect("application port"),
                DnsStrategy::Ipv6Only,
            ))
            .await,
        Ok(vec![SocketAddr::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41).into(),
            443,
        )])
    );
    assert_eq!(
        egress.calls(),
        vec![EgressCall {
            network: "udp",
            target: numeric_target(fixture.address),
            plan: None,
        }]
    );

    drop(backend);
    drop(slot);
    drop(resolver);
    owner
        .shutdown()
        .await
        .expect("application resolver shutdown");
    fixture.shutdown().await;
}

#[tokio::test]
async fn tagged_application_backend_has_no_uninitialized_fallback() {
    let backend = TaggedServerApplicationResolveBackend::new(Arc::new(OnceLock::new()), 0);
    let domain = CanonicalDomain::new("no-fallback.resolver.test").expect("application domain");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(1, Network::Udp),
        &domain,
        NonZeroU16::new(53).expect("application port"),
        DnsStrategy::PreferIpv4,
    );

    assert_eq!(backend.resolve(request).await, Err(DnsError::Runtime));
}
