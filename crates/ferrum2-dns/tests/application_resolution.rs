use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ferrum2_core::route::Network;
use ferrum2_core::{CanonicalDomain, DomainName};
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveContext, ApplicationResolveFuture,
    ApplicationResolveOutcome, ApplicationResolveRequest, ApplicationResolver,
    ApplicationResolverMode, DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheError,
    DnsCacheKey, DnsCacheLookup, DnsCacheQtype, DnsError, DnsServerId, DnsStrategy,
    ResolverGeneration,
};

fn canonical_domain(value: &str) -> CanonicalDomain {
    CanonicalDomain::new(value).expect("canonical domain")
}

fn key(name: &str, qtype: DnsCacheQtype, generation: ResolverGeneration) -> DnsCacheKey {
    DnsCacheKey::new(
        DnsServerId::new(7),
        canonical_domain(name),
        qtype,
        generation,
    )
}

#[test]
fn strategies_order_and_filter_address_families() {
    let port = NonZeroU16::new(443).expect("non-zero port");
    let ipv4 = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
    let ipv6 = [Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED];
    let v4 = |address: Ipv4Addr| SocketAddr::new(address.into(), 443);
    let v6 = |address: Ipv6Addr| SocketAddr::new(address.into(), 443);

    assert_eq!(
        DnsStrategy::PreferIpv4.socket_candidates(port, &ipv4, &ipv6),
        [v4(ipv4[0]), v4(ipv4[1]), v6(ipv6[0]), v6(ipv6[1])]
    );
    assert_eq!(
        DnsStrategy::PreferIpv6.socket_candidates(port, &ipv4, &ipv6),
        [v6(ipv6[0]), v6(ipv6[1]), v4(ipv4[0]), v4(ipv4[1])]
    );
    assert_eq!(
        DnsStrategy::Ipv4Only.socket_candidates(port, &ipv4, &ipv6),
        [v4(ipv4[0]), v4(ipv4[1])]
    );
    assert_eq!(
        DnsStrategy::Ipv6Only.socket_candidates(port, &ipv4, &ipv6),
        [v6(ipv6[0]), v6(ipv6[1])]
    );

    for (spelling, expected) in [
        ("prefer_ipv4", DnsStrategy::PreferIpv4),
        ("prefer_ipv6", DnsStrategy::PreferIpv6),
        ("ipv4_only", DnsStrategy::Ipv4Only),
        ("ipv6_only", DnsStrategy::Ipv6Only),
    ] {
        assert_eq!(spelling.parse::<DnsStrategy>(), Ok(expected));
        assert_eq!(expected.as_str(), spelling);
    }
    assert!("system".parse::<DnsStrategy>().is_err());
}

#[test]
fn tcp_and_udp_views_share_one_cache_handle() {
    let cache =
        DnsCache::try_new(NonZeroUsize::new(4).expect("positive capacity")).expect("bounded cache");
    let tcp_cache = cache.clone();
    let udp_cache = cache;
    let now = Instant::now();
    let key = key(
        "shared.example.",
        DnsCacheQtype::A,
        ResolverGeneration::new(1),
    );
    let addresses = Arc::<[Ipv4Addr]>::from([Ipv4Addr::new(192, 0, 2, 9)]);

    tcp_cache
        .insert_positive(
            key.clone(),
            DnsAddressRecords::A(addresses.clone()),
            Duration::from_secs(30),
            now,
        )
        .expect("TCP insert");

    assert_eq!(
        udp_cache.get(&key, now).expect("UDP lookup"),
        Some(DnsCacheAnswer::Positive(DnsAddressRecords::A(addresses)))
    );
}

#[test]
fn cache_honors_canonical_name_qtype_generation_and_ttls() {
    let cache =
        DnsCache::try_new(NonZeroUsize::new(8).expect("positive capacity")).expect("bounded cache");
    let now = Instant::now();
    let generation_one = ResolverGeneration::new(1);
    let a_key = key("MiXeD.Example.", DnsCacheQtype::A, generation_one);
    let canonical_a_key = key("mixed.example", DnsCacheQtype::A, generation_one);
    let aaaa_key = key("mixed.example", DnsCacheQtype::Aaaa, generation_one);
    let next_generation = key(
        "mixed.example",
        DnsCacheQtype::A,
        generation_one.checked_next().expect("next generation"),
    );
    let address = Ipv4Addr::new(198, 51, 100, 4);

    cache
        .insert_positive(
            a_key,
            DnsAddressRecords::A(Arc::from([address])),
            Duration::from_secs(5),
            now,
        )
        .expect("positive insert");
    assert_eq!(
        cache.get(&canonical_a_key, now).expect("canonical hit"),
        Some(DnsCacheAnswer::Positive(DnsAddressRecords::A(Arc::from([
            address
        ]))))
    );
    assert_eq!(cache.get(&aaaa_key, now).expect("AAAA miss"), None);
    assert_eq!(
        cache.get(&next_generation, now).expect("generation miss"),
        None
    );
    assert_eq!(
        cache
            .get(&canonical_a_key, now + Duration::from_secs(5))
            .expect("expired positive"),
        None
    );

    cache
        .insert_negative(aaaa_key.clone(), Duration::from_secs(2), now)
        .expect("negative insert");
    assert_eq!(
        cache.get(&aaaa_key, now).expect("negative hit"),
        Some(DnsCacheAnswer::Negative)
    );
    assert_eq!(
        cache
            .get(&aaaa_key, now + Duration::from_secs(2))
            .expect("expired negative"),
        None
    );

    assert_eq!(
        cache.insert_positive(
            aaaa_key,
            DnsAddressRecords::Aaaa(Arc::from([Ipv6Addr::LOCALHOST])),
            Duration::ZERO,
            now,
        ),
        Ok(())
    );
    assert_eq!(cache.entry_count(now).expect("zero TTL purge"), 0);
    assert_eq!(
        cache.insert_positive(
            canonical_a_key,
            DnsAddressRecords::Aaaa(Arc::from([Ipv6Addr::LOCALHOST])),
            Duration::from_secs(1),
            now,
        ),
        Err(DnsCacheError::AddressFamily)
    );

    let root = DomainName::new(".").expect("protocol root name");
    assert!(
        DnsCacheKey::from_domain(DnsServerId::new(7), &root, DnsCacheQtype::A, generation_one,)
            .is_none()
    );
}

#[test]
fn cache_capacity_is_bounded_and_evicts_the_oldest_live_key() {
    let cache =
        DnsCache::try_new(NonZeroUsize::new(2).expect("positive capacity")).expect("bounded cache");
    let now = Instant::now();
    let generation = ResolverGeneration::new(1);
    let first = key("first.example", DnsCacheQtype::A, generation);
    let second = key("second.example", DnsCacheQtype::A, generation);
    let third = key("third.example", DnsCacheQtype::A, generation);

    for (key, octet) in [(&first, 1), (&second, 2), (&third, 3)] {
        cache
            .insert_positive(
                key.clone(),
                DnsAddressRecords::A(Arc::from([Ipv4Addr::new(203, 0, 113, octet)])),
                Duration::from_secs(60),
                now,
            )
            .expect("cache insert");
    }

    assert_eq!(cache.entry_count(now).expect("entry count"), 2);
    assert_eq!(cache.get(&first, now).expect("oldest lookup"), None);
    assert!(cache.get(&second, now).expect("second lookup").is_some());
    assert!(cache.get(&third, now).expect("third lookup").is_some());
}

#[test]
fn cache_observer_is_shared_identity_free_and_counts_expiry_as_a_miss() {
    let hits = Arc::new(AtomicUsize::new(0));
    let misses = Arc::new(AtomicUsize::new(0));
    let observed_hits = Arc::clone(&hits);
    let observed_misses = Arc::clone(&misses);
    let cache = DnsCache::try_new(NonZeroUsize::new(2).expect("positive capacity"))
        .expect("bounded cache")
        .try_with_observer(Arc::new(move |qtype, outcome| {
            assert_eq!(qtype, DnsCacheQtype::A);
            match outcome {
                DnsCacheLookup::Hit => observed_hits.fetch_add(1, Ordering::SeqCst),
                DnsCacheLookup::Miss => observed_misses.fetch_add(1, Ordering::SeqCst),
            };
        }))
        .expect("cache observer");
    let shared = cache.clone();
    let now = Instant::now();
    let cache_key = key(
        "observed.example",
        DnsCacheQtype::A,
        ResolverGeneration::new(1),
    );

    assert_eq!(cache.get(&cache_key, now).expect("initial miss"), None);
    cache
        .insert_positive(
            cache_key.clone(),
            DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 40)])),
            Duration::from_secs(1),
            now,
        )
        .expect("insert observed answer");
    assert!(shared.get(&cache_key, now).expect("shared hit").is_some());
    assert_eq!(
        shared
            .get(&cache_key, now + Duration::from_secs(1))
            .expect("expired miss"),
        None
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(misses.load(Ordering::SeqCst), 2);
}

struct FailingBackend {
    calls: AtomicUsize,
}

impl ApplicationResolveBackend for FailingBackend {
    fn resolve<'a>(
        &'a self,
        _request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(DnsError::Timeout)
        })
    }
}

struct SuccessfulBackend;

impl ApplicationResolveBackend for SuccessfulBackend {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            Ok(request.strategy().socket_candidates(
                request.port(),
                &[Ipv4Addr::new(192, 0, 2, 10)],
                &[Ipv6Addr::LOCALHOST],
            ))
        })
    }
}

#[tokio::test]
async fn system_mode_accepts_an_injected_backend() {
    let observations = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&observations);
    let resolver = ApplicationResolver::system(Arc::new(SuccessfulBackend)).with_observer(
        Arc::new(move |mode, outcome| {
            assert_eq!(mode, ApplicationResolverMode::System);
            assert_eq!(outcome, ApplicationResolveOutcome::Success);
            observed.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let target = canonical_domain("injected-system.example");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(3, Network::Tcp),
        &target,
        NonZeroU16::new(80).expect("non-zero port"),
        DnsStrategy::Ipv6Only,
    );

    assert_eq!(resolver.mode(), ApplicationResolverMode::System);
    assert_eq!(
        resolver.resolve(request).await,
        Ok(vec![SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 80)])
    );
    assert_eq!(observations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn configured_failure_is_terminal_without_system_fallback() {
    let backend = Arc::new(FailingBackend {
        calls: AtomicUsize::new(0),
    });
    let observations = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&observations);
    let resolver = ApplicationResolver::configured(backend.clone()).with_observer(Arc::new(
        move |mode, outcome| {
            assert_eq!(mode, ApplicationResolverMode::Configured);
            assert_eq!(outcome, ApplicationResolveOutcome::Failure);
            observed.fetch_add(1, Ordering::SeqCst);
        },
    ));
    let target = canonical_domain("does-not-fallback.example");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(7, Network::Udp),
        &target,
        NonZeroU16::new(443).expect("non-zero port"),
        DnsStrategy::PreferIpv4,
    );

    assert_eq!(resolver.mode(), ApplicationResolverMode::Configured);
    assert_eq!(resolver.resolve(request).await, Err(DnsError::Timeout));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(observations.load(Ordering::SeqCst), 1);
}
