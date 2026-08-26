use super::*;

#[test]
fn dns_udp_pool_reset_synchronously_drops_every_idle_owner() {
    struct DropCounter(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pool = DnsUdpPoolState::default();
    pool.inner.lock().unwrap().idle.extend([
        DropCounter(Arc::clone(&drops)),
        DropCounter(Arc::clone(&drops)),
    ]);

    assert_eq!(pool.reset(), 2);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(pool.reset(), 0, "a repeated reset is idempotent");

    pool.put(0, DropCounter(Arc::clone(&drops)));
    assert_eq!(
        drops.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "an owner acquired before reset cannot return to the new pool generation"
    );
}

#[tokio::test]
async fn dns_udp_pool_reuses_only_exact_success_and_discards_failed_or_partial_state() {
    let (selector, mut roots) = compile_egress_plans_with_roots(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("a", 0),
            TaggedOutbound::new("b", 1),
            TaggedOutbound::new("c", 2),
        ],
        &[
            TaggedPlan::new("a-b", vec![0, 1]),
            TaggedPlan::new("b-a", vec![1, 0]),
        ],
        &[SelectorDefinition::new(
            "manual",
            vec!["a-b", "b-a", "c"],
            Some("a-b"),
        )],
        &["manual"],
    )
    .expect("DNS UDP pool plans");
    let target = TargetAddr::domain("pool.test", 53).expect("pool target");
    let route = roots.remove(0);
    let selected = route.snapshot_owned();
    selector.switch("manual", "b-a").expect("reverse plan");
    let reversed = route.snapshot_owned();
    selector.switch("manual", "c").expect("later plan");
    let later = route.snapshot_owned();
    let key_cases = [
        (
            "equal snapshot",
            DnsUdpPoolKey {
                plan: Some(selected.clone()),
                target: target.clone(),
            },
            true,
        ),
        (
            "absent plan",
            DnsUdpPoolKey {
                plan: None,
                target: target.clone(),
            },
            false,
        ),
        (
            "different hop order",
            DnsUdpPoolKey {
                plan: Some(reversed),
                target: target.clone(),
            },
            false,
        ),
        (
            "selector switched plan",
            DnsUdpPoolKey {
                plan: Some(later),
                target: target.clone(),
            },
            false,
        ),
        (
            "different logical target",
            DnsUdpPoolKey {
                plan: Some(selected.clone()),
                target: TargetAddr::domain("other-pool.test", 53).expect("different pool target"),
            },
            false,
        ),
    ];

    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("association mutation server");
    let first_server = match server.local_addr().expect("mutation server address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 mutation server"),
    };
    let registry = ferrum2_runtime::OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (path, mut context) = udp_test_context_for_server(registry.clone(), first_server);
    let outbounds = prepare_client_outbounds(
        (0..3)
            .map(|_| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: first_server.into(),
                psk: Arc::new(default_test_psk()),
                dial_options: Default::default(),
            })
            .collect(),
    )
    .expect("pool outbounds");
    Arc::get_mut(
        &mut Arc::get_mut(&mut context)
            .expect("unique pool context")
            .egress,
    )
    .expect("unique pool egress")
    .outbounds = outbounds;
    let plan = EgressPlanHandle::direct(0).snapshot_owned();
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("mutation DNS upstream");
    let destination = upstream.local_addr().expect("mutation upstream address");
    let numeric_target = TargetAddr::ip(destination).expect("numeric DNS target");
    let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
    let protocol_server = UdpServer::new(&keys).expect("mutation protocol server");
    let clock = SystemClock::new();
    let random = SystemRandom;
    let mut scratch = UdpPacketScratch::new();
    for (case, candidate, reusable) in key_cases {
        let association = context
            .egress
            .prepare_udp_with(selected.clone(), UdpSocket::bind)
            .await
            .expect("key association");
        let pool = Arc::new(DnsUdpPoolState::default());
        pool.put(
            0,
            IdleDnsUdp {
                key: DnsUdpPoolKey {
                    plan: Some(selected.clone()),
                    target: target.clone(),
                },
                association,
            },
        );
        let (matched, stale, _) = take_dns_udp(&pool, &candidate).expect("key lookup");
        assert_eq!(matched.is_some(), reusable, "{case}");
        assert_eq!(stale.is_some(), !reusable, "{case}");
        drop((matched, stale));
        assert_eq!(registry.snapshot(), baseline, "{case}");
    }
    for case in [
        "partial",
        "send-io",
        "receive-io",
        "authentication",
        "binding",
        "cancel",
        "saturation",
    ] {
        let sessions_before_failure = protocol_server
            .session_count()
            .expect("mutation session baseline");
        let mut association = context
            .egress
            .prepare_udp_with(plan.clone(), UdpSocket::bind)
            .await
            .expect("mutation association");
        association
            .activate(&context.egress)
            .expect("mutation activation");
        let pool = Arc::new(DnsUdpPoolState::default());
        let (session_responses, mut responses) = mpsc::channel(1);
        let mut pooled = PooledDnsUdp {
            idle: Some(IdleDnsUdp {
                key: DnsUdpPoolKey {
                    plan: Some(plan.clone()),
                    target: numeric_target.clone(),
                },
                association,
            }),
            pool: Arc::clone(&pool),
            pool_generation: 0,
            reusable: false,
        };
        let mutation_handle = pooled
            .idle
            .as_ref()
            .expect("healthy mutation owner")
            .association
            .handle();
        let payload = vec![0x10];
        let echo = async {
            let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
            let (length, peer) = upstream
                .recv_from(&mut wire)
                .await
                .expect("healthy mutation upstream query");
            upstream
                .send_to(&wire[..length], peer)
                .await
                .expect("healthy mutation upstream response");
        };
        let (reusable, (), ()) = tokio::join!(
            pooled.relay_request(
                &context.egress,
                Some(&plan),
                numeric_target.clone(),
                payload.clone(),
                &session_responses,
            ),
            relay_dns_udp_hop_once(
                &server,
                &protocol_server,
                DnsUdpHopTarget {
                    logical: numeric_target.clone(),
                    upstream: destination,
                },
                &clock,
                &random,
                &mut scratch,
                DnsUdpResponsePrefix::None,
            ),
            echo,
        );
        let fully_reusable = reusable.expect("healthy mutation relay");
        let response = responses.try_recv().expect("healthy mutation response");
        assert_eq!(response, payload, "{case}");
        assert!(fully_reusable, "{case} healthy mutation tainted");
        drop(pooled);
        assert_eq!(
            pool.inner.lock().expect("healthy mutation pool").idle.len(),
            1
        );
        assert_eq!(
            protocol_server
                .session_count()
                .expect("healthy mutation session"),
            sessions_before_failure + 1,
            "{case} healthy mutation session"
        );
        let key = DnsUdpPoolKey {
            plan: Some(plan.clone()),
            target: numeric_target.clone(),
        };
        let (matched, stale, pool_generation) =
            take_dns_udp(&pool, &key).expect("mutation exact reuse");
        assert!(stale.is_none(), "{case} healthy exact key was discarded");
        let idle = matched.expect("mutation exact-key association");
        assert_eq!(idle.association.handle(), mutation_handle, "{case}");
        let mut pooled = PooledDnsUdp {
            idle: Some(idle),
            pool: Arc::clone(&pool),
            pool_generation,
            reusable: true,
        };
        match case {
            "partial" => pooled.begin_request(),
            "send-io" | "receive-io" => {
                let operation = if case == "send-io" {
                    UdpIoOperation::UpstreamSend
                } else {
                    UdpIoOperation::UpstreamRecv
                };
                pooled
                    .idle
                    .as_mut()
                    .expect("mutation owner")
                    .association
                    .set_io_fault(Some(Arc::new(UdpIoFaultPlan::new(operation, 1))));
                assert!(
                    pooled
                        .relay_request(
                            &context.egress,
                            Some(&plan),
                            numeric_target.clone(),
                            vec![0x21],
                            &session_responses,
                        )
                        .await
                        .is_err(),
                    "{case}"
                );
                if case == "receive-io" {
                    let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                    tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut wire))
                        .await
                        .expect("receive-io request timeout")
                        .expect("receive-io request");
                }
            }
            "authentication" | "binding" => {
                let echo = async {
                    let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                    let (length, peer) = upstream
                        .recv_from(&mut wire)
                        .await
                        .expect("authentication upstream query");
                    upstream
                        .send_to(&wire[..length], peer)
                        .await
                        .expect("authentication upstream response");
                };
                let payload = vec![0x22];
                let prefix = if case == "authentication" {
                    DnsUdpResponsePrefix::Unauthenticated
                } else {
                    DnsUdpResponsePrefix::AuthenticatedTarget(
                        TargetAddr::ip(SocketAddr::from(([192, 0, 2, 99], destination.port())))
                            .expect("wrong numeric response target"),
                    )
                };
                let (result, (), ()) = tokio::join!(
                    pooled.relay_request(
                        &context.egress,
                        Some(&plan),
                        numeric_target.clone(),
                        payload.clone(),
                        &session_responses,
                    ),
                    relay_dns_udp_hop_once(
                        &server,
                        &protocol_server,
                        DnsUdpHopTarget {
                            logical: numeric_target.clone(),
                            upstream: destination,
                        },
                        &clock,
                        &random,
                        &mut scratch,
                        prefix,
                    ),
                    echo,
                );
                let fully_reusable = result.expect("valid response after authentication discard");
                let response = responses
                    .try_recv()
                    .expect("valid response after authentication discard");
                assert_eq!(response, payload);
                assert!(!fully_reusable, "{case} discard left association reusable");
            }
            "cancel" => {
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(20),
                        pooled.relay_request(
                            &context.egress,
                            Some(&plan),
                            numeric_target.clone(),
                            vec![0x23],
                            &session_responses,
                        ),
                    )
                    .await
                    .is_err(),
                    "cancel"
                );
                let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut wire))
                    .await
                    .expect("cancel request timeout")
                    .expect("cancel request");
            }
            "saturation" => {
                pooled.begin_request();
                assert!(
                    context
                        .egress
                        .prepare_udp_with(plan.clone(), UdpSocket::bind)
                        .await
                        .is_err(),
                    "saturation admitted a second association"
                );
            }
            _ => unreachable!("closed mutation table"),
        }
        assert!(
            !pooled.reusable,
            "{case} request start retained reusable state"
        );
        drop(pooled);
        assert!(
            pool.inner.lock().expect("mutation pool").idle.is_empty(),
            "{case}"
        );

        let sessions_before = protocol_server
            .session_count()
            .expect("healthy session baseline");
        let association = context
            .egress
            .prepare_udp_with(plan.clone(), UdpSocket::bind)
            .await
            .expect("following valid association");
        let mut initial = Some(IdleDnsUdp {
            key: DnsUdpPoolKey {
                plan: Some(plan.clone()),
                target: numeric_target.clone(),
            },
            association,
        });
        for valid in 0..2_u8 {
            let (idle, reusable, pool_generation) = match initial.take() {
                Some(idle) => (idle, false, 0),
                None => {
                    let key = DnsUdpPoolKey {
                        plan: Some(plan.clone()),
                        target: numeric_target.clone(),
                    };
                    let (matched, stale, pool_generation) =
                        take_dns_udp(&pool, &key).expect("healthy reuse");
                    assert!(stale.is_none(), "healthy exact key was discarded");
                    (
                        matched.expect("healthy exact-key association"),
                        true,
                        pool_generation,
                    )
                }
            };
            let mut healthy = PooledDnsUdp {
                idle: Some(idle),
                pool: Arc::clone(&pool),
                pool_generation,
                reusable,
            };
            let payload = vec![0x30 + valid];
            let echo = async {
                let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                let (length, peer) = upstream
                    .recv_from(&mut wire)
                    .await
                    .expect("following valid upstream query");
                upstream
                    .send_to(&wire[..length], peer)
                    .await
                    .expect("following valid upstream response");
            };
            let (reusable, (), ()) = tokio::join!(
                healthy.relay_request(
                    &context.egress,
                    Some(&plan),
                    numeric_target.clone(),
                    payload.clone(),
                    &session_responses,
                ),
                relay_dns_udp_hop_once(
                    &server,
                    &protocol_server,
                    DnsUdpHopTarget {
                        logical: numeric_target.clone(),
                        upstream: destination,
                    },
                    &clock,
                    &random,
                    &mut scratch,
                    DnsUdpResponsePrefix::None,
                ),
                echo,
            );
            let fully_reusable = reusable.expect("following valid relay");
            let response = responses.try_recv().expect("following valid response");
            assert_eq!(response, payload, "{case}");
            assert!(fully_reusable, "{case} healthy association tainted");
            drop(healthy);
            assert_eq!(
                pool.inner.lock().expect("healthy pool").idle.len(),
                1,
                "{case}"
            );
        }
        assert_eq!(
            protocol_server
                .session_count()
                .expect("healthy session count"),
            sessions_before + 1,
            "{case} exact-key reuse created another SIP022 session"
        );
        drop(pool.inner.lock().expect("healthy pool").idle.pop());
        assert_eq!(registry.snapshot(), baseline, "{case}");
    }
    drop((context, protocol_server, keys));
    assert_eq!(registry.snapshot(), baseline);
    drop(server);
    drop(upstream);
    drop(
        UdpSocket::bind(first_server)
            .await
            .expect("mutation server rebind"),
    );
    drop(
        UdpSocket::bind(destination)
            .await
            .expect("mutation upstream rebind"),
    );
    std::fs::remove_file(path).expect("remove mutation config");
}
