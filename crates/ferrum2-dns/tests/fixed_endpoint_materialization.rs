use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrum2_core::CanonicalDomain;
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheQtype, DnsError, DnsServerId, DnsStrategy,
    FixedEndpointKind, FixedEndpointLookup, FixedEndpointMaterializeError, FixedEndpointPlanEntry,
    FixedEndpointResolveBackend, FixedEndpointResolveFuture, FixedEndpointResolveRequest,
    FixedEndpointSpec, ResolverGeneration, ResolverRef, materialize_fixed_endpoints,
    materialize_fixed_endpoints_with_clock, validate_fixed_endpoint_order,
};

fn domain(value: &str) -> CanonicalDomain {
    CanonicalDomain::new(value).expect("canonical fixed endpoint domain")
}

fn port(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("non-zero fixed endpoint port")
}

fn domain_entry(
    kind: FixedEndpointKind,
    name: &str,
    resolver: ResolverRef,
    strategy: DnsStrategy,
) -> FixedEndpointPlanEntry {
    FixedEndpointPlanEntry::new(
        kind,
        FixedEndpointSpec::domain(domain(name), port(443), resolver, strategy),
    )
}

fn ip_entry(kind: FixedEndpointKind, address: &str) -> FixedEndpointPlanEntry {
    FixedEndpointPlanEntry::new(
        kind,
        FixedEndpointSpec::ip(address.parse().expect("numeric fixed endpoint"))
            .expect("non-zero numeric endpoint"),
    )
}

#[derive(Default)]
struct CountingBackend {
    system_calls: AtomicUsize,
    tagged_calls: AtomicUsize,
}

impl FixedEndpointResolveBackend for CountingBackend {
    fn resolve_system<'a>(
        &'a self,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            self.system_calls.fetch_add(1, Ordering::SeqCst);
            Ok(positive_for(request.qtype()))
        })
    }

    fn resolve_dns_server<'a>(
        &'a self,
        _resolver: DnsServerId,
        _resolver_endpoint: &'a ferrum2_dns::MaterializedFixedEndpoint,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            self.tagged_calls.fetch_add(1, Ordering::SeqCst);
            Ok(positive_for(request.qtype()))
        })
    }
}

fn positive_for(qtype: DnsCacheQtype) -> FixedEndpointLookup {
    match qtype {
        DnsCacheQtype::A => FixedEndpointLookup::positive(
            DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 10)])),
            Duration::from_secs(60),
        ),
        DnsCacheQtype::Aaaa => FixedEndpointLookup::positive(
            DnsAddressRecords::Aaaa(Arc::from([Ipv6Addr::LOCALHOST])),
            Duration::from_secs(60),
        ),
    }
}

#[tokio::test]
async fn missing_and_cyclic_dependencies_fail_before_any_query() {
    let backend = CountingBackend::default();
    let missing = [domain_entry(
        FixedEndpointKind::Shadowsocks,
        "missing.example",
        ResolverRef::DnsServer(DnsServerId::new(9)),
        DnsStrategy::Ipv4Only,
    )];
    assert_eq!(
        validate_fixed_endpoint_order(&missing),
        Err(FixedEndpointMaterializeError::MissingResolver)
    );
    assert_eq!(
        materialize_fixed_endpoints(&missing, &backend, None, ResolverGeneration::new(1))
            .await
            .unwrap_err(),
        FixedEndpointMaterializeError::MissingResolver
    );

    let first = DnsServerId::new(1);
    let second = DnsServerId::new(2);
    let cycle = [
        domain_entry(
            FixedEndpointKind::DnsServer(first),
            "first.example",
            ResolverRef::DnsServer(second),
            DnsStrategy::Ipv4Only,
        ),
        domain_entry(
            FixedEndpointKind::DnsServer(second),
            "second.example",
            ResolverRef::DnsServer(first),
            DnsStrategy::Ipv4Only,
        ),
    ];
    assert_eq!(
        validate_fixed_endpoint_order(&cycle),
        Err(FixedEndpointMaterializeError::InvalidDependencyOrder)
    );
    assert_eq!(
        materialize_fixed_endpoints(&cycle, &backend, None, ResolverGeneration::new(1))
            .await
            .unwrap_err(),
        FixedEndpointMaterializeError::InvalidDependencyOrder
    );
    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.tagged_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn numeric_dns_shadowsocks_and_ruleset_endpoints_bypass_all_resolution() {
    let backend = CountingBackend::default();
    let plan = [
        ip_entry(
            FixedEndpointKind::DnsServer(DnsServerId::new(1)),
            "192.0.2.53:53",
        ),
        ip_entry(FixedEndpointKind::Shadowsocks, "198.51.100.9:8388"),
        ip_entry(FixedEndpointKind::RuleSet, "203.0.113.10:443"),
    ];

    let materialized =
        materialize_fixed_endpoints(&plan, &backend, None, ResolverGeneration::new(1))
            .await
            .expect("numeric materialization");

    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.tagged_calls.load(Ordering::SeqCst), 0);
    for (entry, output) in plan.iter().zip(&materialized) {
        assert_eq!(output.kind(), entry.kind());
        assert_eq!(output.spec().domain_name(), None);
        assert_eq!(output.candidates(), &[entry.spec().socket_addr().unwrap()]);
    }
}

#[derive(Default)]
struct StrategyBackend {
    qtypes: Mutex<Vec<DnsCacheQtype>>,
}

impl FixedEndpointResolveBackend for StrategyBackend {
    fn resolve_system<'a>(
        &'a self,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            self.qtypes.lock().unwrap().push(request.qtype());
            Ok(positive_for(request.qtype()))
        })
    }

    fn resolve_dns_server<'a>(
        &'a self,
        _resolver: DnsServerId,
        _resolver_endpoint: &'a ferrum2_dns::MaterializedFixedEndpoint,
        _request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async { panic!("strategy test must use only explicit system resolution") })
    }
}

#[tokio::test]
async fn all_four_strategies_filter_order_and_retain_the_logical_domain() {
    let backend = StrategyBackend::default();
    let plan = [
        domain_entry(
            FixedEndpointKind::Shadowsocks,
            "Preserved.Example.",
            ResolverRef::System,
            DnsStrategy::PreferIpv4,
        ),
        domain_entry(
            FixedEndpointKind::Shadowsocks,
            "Preserved.Example.",
            ResolverRef::System,
            DnsStrategy::PreferIpv6,
        ),
        domain_entry(
            FixedEndpointKind::Shadowsocks,
            "Preserved.Example.",
            ResolverRef::System,
            DnsStrategy::Ipv4Only,
        ),
        domain_entry(
            FixedEndpointKind::RuleSet,
            "Preserved.Example.",
            ResolverRef::System,
            DnsStrategy::Ipv6Only,
        ),
    ];

    let output = materialize_fixed_endpoints(&plan, &backend, None, ResolverGeneration::new(1))
        .await
        .expect("strategy materialization");
    let ipv4 = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 443);
    let ipv6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);

    assert_eq!(output[0].candidates(), &[ipv4, ipv6]);
    assert_eq!(output[1].candidates(), &[ipv6, ipv4]);
    assert_eq!(output[2].candidates(), &[ipv4]);
    assert_eq!(output[3].candidates(), &[ipv6]);
    assert!(output.iter().all(|endpoint| {
        endpoint
            .spec()
            .domain_name()
            .is_some_and(|name| name.as_str() == "preserved.example")
    }));
    assert_eq!(
        *backend.qtypes.lock().unwrap(),
        [
            DnsCacheQtype::A,
            DnsCacheQtype::Aaaa,
            DnsCacheQtype::Aaaa,
            DnsCacheQtype::A,
            DnsCacheQtype::A,
            DnsCacheQtype::Aaaa,
        ]
    );
}

struct FailingTaggedBackend {
    system_calls: AtomicUsize,
    tagged_calls: AtomicUsize,
}

impl FixedEndpointResolveBackend for FailingTaggedBackend {
    fn resolve_system<'a>(
        &'a self,
        _request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            self.system_calls.fetch_add(1, Ordering::SeqCst);
            Ok(positive_for(DnsCacheQtype::A))
        })
    }

    fn resolve_dns_server<'a>(
        &'a self,
        resolver: DnsServerId,
        resolver_endpoint: &'a ferrum2_dns::MaterializedFixedEndpoint,
        _request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            self.tagged_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                resolver_endpoint.kind(),
                FixedEndpointKind::DnsServer(resolver)
            );
            Err(DnsError::Timeout)
        })
    }
}

#[tokio::test]
async fn tagged_failure_is_terminal_and_never_calls_the_system_backend() {
    let resolver = DnsServerId::new(7);
    let plan = [
        ip_entry(FixedEndpointKind::DnsServer(resolver), "192.0.2.53:53"),
        domain_entry(
            FixedEndpointKind::Shadowsocks,
            "terminal.example",
            ResolverRef::DnsServer(resolver),
            DnsStrategy::PreferIpv4,
        ),
    ];
    let backend = FailingTaggedBackend {
        system_calls: AtomicUsize::new(0),
        tagged_calls: AtomicUsize::new(0),
    };

    assert_eq!(
        materialize_fixed_endpoints(&plan, &backend, None, ResolverGeneration::new(1))
            .await
            .unwrap_err(),
        FixedEndpointMaterializeError::Resolve(DnsError::Timeout)
    );
    assert_eq!(backend.tagged_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct TopologyBackend {
    tagged_queries: Mutex<Vec<(DnsServerId, String, DnsCacheQtype)>>,
    observed: Mutex<Vec<FixedEndpointKind>>,
}

impl FixedEndpointResolveBackend for TopologyBackend {
    fn resolve_system<'a>(
        &'a self,
        _request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async { panic!("numeric root DNS server needs no system query") })
    }

    fn resolve_dns_server<'a>(
        &'a self,
        resolver: DnsServerId,
        resolver_endpoint: &'a ferrum2_dns::MaterializedFixedEndpoint,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            assert!(
                self.observed
                    .lock()
                    .unwrap()
                    .contains(&FixedEndpointKind::DnsServer(resolver)),
                "resolver endpoint must be published before its dependant query"
            );
            assert_eq!(
                resolver_endpoint.kind(),
                FixedEndpointKind::DnsServer(resolver)
            );
            self.tagged_queries.lock().unwrap().push((
                resolver,
                request.domain().as_str().to_owned(),
                request.qtype(),
            ));
            match (resolver.get(), request.domain().as_str(), request.qtype()) {
                (1, "second.resolver", DnsCacheQtype::A) => Ok(FixedEndpointLookup::positive(
                    DnsAddressRecords::A(Arc::from([Ipv4Addr::new(198, 51, 100, 53)])),
                    Duration::from_secs(60),
                )),
                (2, "shared.target", DnsCacheQtype::A) => Ok(FixedEndpointLookup::positive(
                    DnsAddressRecords::A(Arc::from([Ipv4Addr::new(203, 0, 113, 9)])),
                    Duration::from_secs(60),
                )),
                (2, "shared.target", DnsCacheQtype::Aaaa) => {
                    Ok(FixedEndpointLookup::negative(Duration::from_secs(30)))
                }
                _ => Err(DnsError::Protocol),
            }
        })
    }

    fn endpoint_materialized(
        &self,
        endpoint: &ferrum2_dns::MaterializedFixedEndpoint,
    ) -> Result<(), FixedEndpointMaterializeError> {
        self.observed.lock().unwrap().push(endpoint.kind());
        Ok(())
    }
}

#[tokio::test]
async fn topological_chain_shares_positive_and_negative_ttl_cache_by_generation() {
    let first = DnsServerId::new(1);
    let second = DnsServerId::new(2);
    let plan = [
        ip_entry(FixedEndpointKind::DnsServer(first), "192.0.2.53:53"),
        domain_entry(
            FixedEndpointKind::DnsServer(second),
            "second.resolver",
            ResolverRef::DnsServer(first),
            DnsStrategy::Ipv4Only,
        ),
        domain_entry(
            FixedEndpointKind::Shadowsocks,
            "shared.target",
            ResolverRef::DnsServer(second),
            DnsStrategy::PreferIpv4,
        ),
        domain_entry(
            FixedEndpointKind::RuleSet,
            "shared.target",
            ResolverRef::DnsServer(second),
            DnsStrategy::PreferIpv4,
        ),
    ];
    let backend = TopologyBackend::default();
    let cache = DnsCache::try_new(NonZeroUsize::new(16).unwrap()).expect("fixed endpoint cache");
    let started = Instant::now();

    let first_output = materialize_fixed_endpoints_with_clock(
        &plan,
        &backend,
        Some(&cache),
        ResolverGeneration::new(4),
        || started,
    )
    .await
    .expect("initial topological materialization");
    assert_eq!(
        first_output[1].candidates(),
        &["198.51.100.53:443".parse().unwrap()]
    );
    assert_eq!(
        first_output[2].candidates(),
        &["203.0.113.9:443".parse().unwrap()]
    );
    assert_eq!(first_output[3].candidates(), first_output[2].candidates());
    assert_eq!(backend.tagged_queries.lock().unwrap().len(), 3);
    assert_eq!(
        *backend.observed.lock().unwrap(),
        [
            FixedEndpointKind::DnsServer(first),
            FixedEndpointKind::DnsServer(second),
            FixedEndpointKind::Shadowsocks,
            FixedEndpointKind::RuleSet,
        ]
    );

    backend.observed.lock().unwrap().clear();
    materialize_fixed_endpoints_with_clock(
        &plan,
        &backend,
        Some(&cache),
        ResolverGeneration::new(4),
        || started + Duration::from_secs(10),
    )
    .await
    .expect("same generation cache hit");
    assert_eq!(backend.tagged_queries.lock().unwrap().len(), 3);

    materialize_fixed_endpoints_with_clock(
        &plan,
        &backend,
        Some(&cache),
        ResolverGeneration::new(5),
        || started + Duration::from_secs(10),
    )
    .await
    .expect("new generation cache miss");
    assert_eq!(backend.tagged_queries.lock().unwrap().len(), 6);

    materialize_fixed_endpoints_with_clock(
        &plan,
        &backend,
        Some(&cache),
        ResolverGeneration::new(4),
        || started + Duration::from_secs(61),
    )
    .await
    .expect("expired generation reload");
    assert_eq!(backend.tagged_queries.lock().unwrap().len(), 9);
    assert_eq!(
        cache.entry_count(started).expect("cache count"),
        5,
        "the shorter negative TTL was purged independently"
    );
}
