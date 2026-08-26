use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_tcp_exact_server_plan_and_negative_semantics() {
    let _network = TEST_NETWORK.lock().await;
    let fixture = PlainFixture::start().await;
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            configured_server(fixture.address, DnsUpstreamTransport::Udp, true),
            configured_server(fixture.address, DnsUpstreamTransport::Tcp, false),
        ],
        Duration::from_secs(1),
        NonZeroU16::new(8).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start resolver");
    owner.ready().await.expect("resolver ready");

    for server in [0, 1] {
        assert_eq!(
            resolver
                .lookup_ips(
                    server,
                    Name::from_ascii("answer.resolver.test.").expect("address query"),
                )
                .await
                .expect("ordered address lookup"),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41)),
            ]
        );
        let a = resolver
            .lookup(
                server,
                Name::from_ascii("answer.resolver.test.").expect("A query"),
                RecordType::A,
            )
            .await
            .expect("A lookup");
        assert!(
            a.answers()
                .iter()
                .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 41))))
        );

        let aaaa = resolver
            .lookup(
                server,
                Name::from_ascii("v6.resolver.test.").expect("AAAA query"),
                RecordType::AAAA,
            )
            .await
            .expect("AAAA lookup");
        assert!(
            aaaa.answers()
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );

        let cname = resolver
            .lookup(
                server,
                Name::from_ascii("alias.resolver.test.").expect("CNAME query"),
                RecordType::A,
            )
            .await
            .expect("CNAME lookup");
        assert!(
            cname
                .answers()
                .iter()
                .any(|record| matches!(record.data, RData::CNAME(_)))
        );

        assert_eq!(
            resolver
                .lookup(
                    server,
                    Name::from_ascii("missing.resolver.test.").expect("NX query"),
                    RecordType::A,
                )
                .await,
            Err(DnsError::NxDomain)
        );
        assert_eq!(
            resolver
                .lookup(
                    server,
                    Name::from_ascii("a-only.resolver.test.").expect("NODATA query"),
                    RecordType::AAAA,
                )
                .await,
            Err(DnsError::NoData)
        );
    }

    let calls = egress.calls();
    assert!(calls.iter().any(|call| {
        call.network == "udp"
            && call.target == numeric_target(fixture.address)
            && call.plan.as_deref() == Some(&[0][..])
    }));
    assert!(calls.iter().any(|call| {
        call.network == "tcp"
            && call.target == numeric_target(fixture.address)
            && call.plan.is_none()
    }));
    assert!(
        calls
            .iter()
            .all(|call| call.target == numeric_target(fixture.address))
    );

    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("resolver shutdown")
            .runtime_tasks,
        0
    );
    let address = fixture.address;
    fixture.shutdown().await;
    assert!(UdpSocket::bind(address).await.is_ok());
    assert!(TcpListener::bind(address).await.is_ok());
}
