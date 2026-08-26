use super::*;

#[tokio::test]
async fn initial_ruleset_failure_returns_before_listener_bind() {
    let address = reserve_address();
    let file = TestConfig::new(|cache| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0
"#
        )
    });
    let prepared = ferrum2_config::prepare_client(&file.path).expect("prepare remote config");
    let downloader = Arc::new(RecordingDownloader::failure());
    let materializer =
        ClientV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());

    assert!(matches!(
        materializer.materialize(prepared).await,
        Err(RunError::RuleSetDownload)
    ));
    assert_eq!(downloader.seen().len(), 1);
    let rebound = TcpListener::bind(address).expect("materialization never bound inbound");
    drop(rebound);
}

#[tokio::test]
async fn refresh_uses_live_detour_snapshot_and_is_explicitly_cleaned() {
    let address = reserve_address();
    let file = TestConfig::new(|cache| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "first"
type = "direct"

[[outbounds]]
tag = "second"
type = "direct"

[[selectors]]
tag = "download"
outbounds = ["first", "second"]
default = "first"

[route]
final = "download"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"
download_detour = "download"
update_interval_seconds = 60

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0
"#
        )
    });
    let prepared = ferrum2_config::prepare_client(&file.path).expect("prepare refresh config");
    let downloader = Arc::new(RecordingDownloader::success());
    let materializer =
        ClientV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());
    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("strict initial snapshot");
    assert_eq!(
        downloader.seen(),
        [SeenDownload {
            mode: RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
            detour: Some(vec![0]),
        }]
    );
    materialized
        .config()
        .selector_control()
        .switch("download", "second")
        .expect("switch download selector");

    let MaterializedRunParts {
        config,
        materialization_root: root,
        cache: _cache,
    } = materialized
        .into_run_parts()
        .await
        .expect("transfer refresh ownership");
    let mut root = root.expect("refresh root");
    let outcome = root.refresh_once(0).await;
    assert!(matches!(outcome, RuleSetRefreshOutcome::Updated { .. }));
    assert_eq!(
        downloader.seen(),
        [
            SeenDownload {
                mode: RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
                detour: Some(vec![0]),
            },
            SeenDownload {
                mode: RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
                detour: Some(vec![1]),
            },
        ]
    );
    let registry = config.route.rule_registry().expect("route registry");
    assert_eq!(registry.generation(), 2);
    root.cleanup().await.expect("refresh owner cleanup");
    root.cleanup().await.expect("idempotent cleaned root");
    assert!(root.is_cleaned());
}

#[tokio::test]
async fn four_real_srs_load_finish_into_one_materialized_route_and_dns_snapshot() {
    let address = reserve_address();
    let file = TestConfig::new(|cache| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "direct"
type = "direct"

[[outbounds]]
tag = "ai"
type = "direct"

[dns]
timeout_ms = 1000
max_inflight = 16

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[[dns.servers]]
tag = "google"
transport = "udp"
address = "198.51.100.53:53"

[dns.route]
final = "google"

[[dns.route.rules]]
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
rule_set = "ai"
action = "route"
server = "google"

[[dns.route.rules]]
rule_set = "cn"
action = "route"
server = "local"

[[dns.route.rules]]
rule_set = "cnip"
action = "route"
server = "local"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "ai"
type = "remote"
url = "https://rules.example.invalid/ai.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "cn"
type = "remote"
url = "https://rules.example.invalid/cn.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "cnip"
type = "remote"
url = "https://rules.example.invalid/cnip.srs"
download_resolver = "system"

[[route.rules]]
rule_set = "ads"
action = "reject"

[[route.rules]]
rule_set = "ai"
action = "route"
outbound = "ai"

[[route.rules]]
rule_set = "cn"
action = "route"
outbound = "direct"

[[route.rules]]
rule_set = "cnip"
action = "route"
outbound = "direct"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0
"#
        )
    });
    let prepared = ferrum2_config::prepare_client(&file.path).expect("prepare four real RuleSets");
    let downloader = Arc::new(RecordingDownloader::fixture_set());
    let materializer =
        ClientV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());
    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("one strict four-RuleSet snapshot");
    assert_eq!(downloader.seen().len(), 4);
    assert!(downloader.seen().iter().all(|request| {
        request.mode == RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System)
    }));
    let registry = materialized
        .config()
        .route
        .rule_registry()
        .expect("shared route registry");
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.generation(), INITIAL_RULESET_GENERATION);
    assert_eq!(snapshot.rule_set_count(), 4);
    let match_set = |tag| {
        let id = snapshot.rule_set_id(tag).expect("RuleSet tag");
        let descriptor = snapshot.rule_set(id).expect("RuleSet descriptor");
        snapshot
            .match_set(descriptor.match_set())
            .expect("compiled MatchSet")
    };
    assert!(
        match_set("ads").matches_domain(
            &ferrum2_core::CanonicalDomain::new("x.0.myikas.com").expect("ads probe")
        )
    );
    assert!(match_set("ai").matches_domain(
        &ferrum2_core::CanonicalDomain::new("api.openai.example").expect("ai probe")
    ));
    assert!(
        match_set("cn")
            .matches_domain(&ferrum2_core::CanonicalDomain::new("x.0.zone").expect("cn probe"))
    );
    assert!(match_set("cnip").matches_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))));
    assert!(!match_set("cnip").matches_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

    let config = materialized.config();
    let route = &config.route;
    let terminal_hops = |target: &TargetAddr| {
        let mut scratch = route.evaluation_scratch().expect("route scratch");
        let mut evaluation = route.evaluate_with_scratch(0, Network::Tcp, target, &mut scratch);
        match evaluation.next(RouteMetadata::new(None, None)) {
            Some(RouteProgramAction::Terminal(RouteAction::Route(plan))) => {
                Some(plan.snapshot_owned().hops().to_vec())
            }
            Some(RouteProgramAction::Terminal(RouteAction::Reject)) => None,
            _ => panic!("unexpected ordinary route action"),
        }
    };
    let ads_target = TargetAddr::domain("x.0.myikas.com", 443).expect("ads target");
    let mut ads_scratch = route.evaluation_scratch().expect("ads route scratch");
    let mut ads_route = route.evaluate_with_scratch(0, Network::Tcp, &ads_target, &mut ads_scratch);
    assert!(matches!(
        ads_route.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(RouteAction::Reject))
    ));
    assert_eq!(
        terminal_hops(&TargetAddr::domain("api.openai.example", 443).expect("AI target")),
        Some(vec![1])
    );
    assert_eq!(
        terminal_hops(&TargetAddr::domain("x.0.zone", 443).expect("CN target")),
        Some(vec![0])
    );
    assert_eq!(
        terminal_hops(
            &TargetAddr::ip("1.1.8.8:443".parse().expect("CN IP address")).expect("CN IP target")
        ),
        Some(vec![0])
    );

    let binding = config
        .dns_route
        .as_ref()
        .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
        .expect("DNS policy blueprint");
    let dns_registry = binding.registry();
    assert!(Arc::ptr_eq(&registry, &dns_registry));
    assert_eq!(
        binding.resolve_ingress(ferrum2_config::DnsIngressId::Listener(0)),
        Some(0)
    );
    let policy = ferrum2_dns::DnsPolicyProgram::try_from_blueprint(
        binding.blueprint().clone(),
        &dns_registry.snapshot(),
    )
    .expect("compile DNS execution program from blueprint");
    let query = |name: &str| {
        DnsPolicyQuery::new(
            0,
            Network::Udp,
            Name::from_str(name).expect("DNS query name"),
            RecordType::A,
        )
    };
    let mut ads_dns = policy.evaluate(query("x.0.myikas.com."), &dns_registry);
    assert_eq!(
        ads_dns.next_step().expect("ads DNS rule"),
        Some(DnsPolicyStep::Reject)
    );
    let mut ai_dns = policy.evaluate(query("api.openai.example."), &dns_registry);
    assert!(matches!(
        ai_dns.next_step().expect("AI DNS rule"),
        Some(DnsPolicyStep::RouteImmediately { server, .. }) if server.get() == 1
    ));
    let mut cn_dns = policy.evaluate(query("x.0.zone."), &dns_registry);
    assert!(matches!(
        cn_dns.next_step().expect("CN DNS rule"),
        Some(DnsPolicyStep::RouteImmediately { server, .. }) if server.get() == 0
    ));
    let response_name = "response-only.invalid.";
    let mut cnip_dns = policy.evaluate(query(response_name), &dns_registry);
    assert!(matches!(
        cnip_dns.next_step().expect("CNIP response rule"),
        Some(DnsPolicyStep::EvaluateResponse { server, .. }) if server.get() == 0
    ));
    let mut response = Message::new(9, MessageType::Response, OpCode::Query);
    response.add_answer(Record::from_rdata(
        Name::from_str(response_name).expect("DNS response name"),
        60,
        RData::A(A(Ipv4Addr::new(1, 1, 8, 8))),
    ));
    assert!(matches!(
        cnip_dns.evaluate_response(&response).expect("CNIP response hit"),
        DnsPolicyStep::AcceptResponse { server, .. } if server.get() == 0
    ));

    let mut cnip_miss = policy.evaluate(query(response_name), &dns_registry);
    assert!(matches!(
        cnip_miss.next_step().expect("CNIP response rule"),
        Some(DnsPolicyStep::EvaluateResponse { server, .. }) if server.get() == 0
    ));
    let mut response = Message::new(10, MessageType::Response, OpCode::Query);
    response.add_answer(Record::from_rdata(
        Name::from_str(response_name).expect("DNS response name"),
        60,
        RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
    ));
    assert!(matches!(
        cnip_miss
            .evaluate_response(&response)
            .expect("CNIP response miss"),
        DnsPolicyStep::Final { server, .. } if server.get() == 1
    ));
    materialized.validate_only().expect("four-RuleSet cleanup");
}

#[test]
fn ruleset_host_observer_records_closed_resolver_outcomes_without_fallback() {
    let metrics = Arc::new(Metrics::new());
    let observer = rule_set_host_resolve_observer(&metrics);
    observer.record(
        RuleSetHostResolverKind::System,
        RuleSetHostResolveOutcome::Success,
    );
    observer.record(
        RuleSetHostResolverKind::Configured,
        RuleSetHostResolveOutcome::Failure,
    );

    let encoded = metrics.encode_text().expect("encode RuleSet DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"system\",purpose=\"ruleset_download\",result=\"success\"} 1",
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"ruleset_download\",result=\"failure\"} 1",
        "ferrum2_dns_explicit_system_resolve_total{purpose=\"ruleset_download\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
}

#[test]
fn degraded_initial_and_retained_refresh_emit_failure_metrics() {
    let metrics = Metrics::new();
    metrics.ruleset_load(initial_rule_set_result(
        RuleSetLoadDisposition::OfflineCache,
        Some(RuleSetLoadErrorKind::Download(
            RuleSetDownloadErrorKind::Resolution,
        )),
    ));
    metrics.ruleset_refresh(refresh_rule_set_result(
        RuleSetRefreshOutcome::RetainedCache(RuleSetLoadDisposition::StaleCache),
    ));

    let encoded = metrics.encode_text().expect("encode RuleSet metrics");
    for expected in [
        "ferrum2_ruleset_load_total{result=\"failure\"} 1",
        "ferrum2_ruleset_refresh_total{result=\"failure\"} 1",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    assert_eq!(
        refresh_rule_set_result(RuleSetRefreshOutcome::NotModified),
        RuleSetResult::Unchanged
    );
}

#[test]
fn materialization_failures_keep_closed_operator_categories() {
    let cases = [
        (
            RuleSetLoadErrorKind::Allocation,
            RunError::RuleAllocation,
            "error[rule.allocation]",
        ),
        (
            RuleSetLoadErrorKind::Download(RuleSetDownloadErrorKind::Connect),
            RunError::RuleSetDownload,
            "error[ruleset.download]",
        ),
        (
            RuleSetLoadErrorKind::CacheDigest,
            RunError::RuleSetCache,
            "error[ruleset.cache]",
        ),
        (
            RuleSetLoadErrorKind::Decode(ferrum2_rule::srs::SrsErrorKind::InvalidMagic),
            RunError::RuleSetFormat,
            "error[ruleset.format]",
        ),
        (
            RuleSetLoadErrorKind::Decode(ferrum2_rule::srs::SrsErrorKind::UnsupportedMatcher),
            RunError::RuleSetUnsupportedMatcher,
            "error[ruleset.unsupported_matcher]",
        ),
        (
            RuleSetLoadErrorKind::RegistryCompile,
            RunError::RuleSetCompile,
            "error[ruleset.compile]",
        ),
    ];
    for (kind, expected, code) in cases {
        let classified = classify_rule_set_load_error_kind(kind);
        assert_eq!(classified, expected);
        let rendered = classified.to_string();
        assert!(rendered.starts_with(code));
        assert!(!rendered.contains("secret.invalid"));
    }
    assert_eq!(
        classify_fixed_endpoint_error(FixedEndpointMaterializeError::Resolve(DnsError::NoData)),
        RunError::DnsResolve
    );
}

#[tokio::test]
async fn bridge_shutdown_aborts_and_joins_every_spawned_task() {
    struct RunningGuard(Arc<AtomicBool>);

    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let bridges = RuleSetBridgeTasks::default();
    let running = Arc::new(AtomicBool::new(false));
    let task_running = Arc::clone(&running);
    let _abort = bridges
        .spawn(async move {
            task_running.store(true, Ordering::Release);
            let _guard = RunningGuard(Arc::clone(&task_running));
            std::future::pending::<()>().await;
        })
        .expect("bridge task accepted");
    while !running.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    bridges.shutdown().await;
    assert!(!running.load(Ordering::Acquire));
    assert!(bridges.spawn(async {}).is_err());
    assert!(
        bridges
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
}

#[tokio::test]
async fn cancelled_ruleset_attempt_aborts_its_bridge_immediately() {
    struct RunningGuard(Arc<AtomicBool>);

    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let bridges = RuleSetBridgeTasks::default();
    let running = Arc::new(AtomicBool::new(false));
    let task_running = Arc::clone(&running);
    let abort = bridges
        .spawn(async move {
            task_running.store(true, Ordering::Release);
            let _guard = RunningGuard(Arc::clone(&task_running));
            std::future::pending::<()>().await;
        })
        .expect("attempt bridge accepted");
    while !running.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    drop(AbortRuleSetBridge::new(abort));
    tokio::time::timeout(Duration::from_millis(100), async {
        while running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled attempt bridge stopped");
    bridges.shutdown().await;
}

#[tokio::test]
async fn dropping_open_ruleset_stream_aborts_its_bridge_immediately() {
    struct RunningGuard(Arc<AtomicBool>);

    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let bridges = RuleSetBridgeTasks::default();
    let running = Arc::new(AtomicBool::new(false));
    let task_running = Arc::clone(&running);
    let abort = bridges
        .spawn(async move {
            task_running.store(true, Ordering::Release);
            let _guard = RunningGuard(Arc::clone(&task_running));
            std::future::pending::<()>().await;
        })
        .expect("open bridge accepted");
    while !running.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    let (inner, _peer) = tokio::io::duplex(64);
    drop(RuleSetBridgeIo {
        inner,
        bridge: abort,
    });
    tokio::time::timeout(Duration::from_millis(100), async {
        while running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped open stream stopped its bridge");
    bridges.shutdown().await;
}
