use super::*;

#[tokio::test]
async fn direct_tcp_socks_uses_the_numeric_target_and_raw_half_close() {
    let aborts = Arc::new(AtomicUsize::new(0));
    let (stream, mut peer) = tokio::io::duplex(1_024);
    let target = TargetAddr::ip("192.0.2.44:443".parse().expect("numeric target")).expect("target");
    let engine = ClientEgressEngine::new(
        vec![ClientOutboundContext::direct(
            ferrum2_net::DialOptions::default(),
        )]
        .into(),
        DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::clone(&aborts),
            )))),
        },
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        None,
        None,
    );
    let opened = engine
        .open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            &target,
            None,
            None,
        )
        .await
        .expect("direct open");
    let mut opened = TokioFramed::new(opened);
    opened.write_all(b"raw-direct").await.expect("raw write");
    opened.shutdown().await.expect("raw half-close");
    let mut raw = Vec::new();
    peer.read_to_end(&mut raw).await.expect("raw EOF");
    assert_eq!(raw, b"raw-direct");
    assert_eq!(
        engine.connector.targets.lock().expect("targets").as_slice(),
        &[target]
    );
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}
