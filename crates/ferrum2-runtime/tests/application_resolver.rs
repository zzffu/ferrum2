use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrum2_core::route::Network;
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveFuture, ApplicationResolveRequest,
    ApplicationResolver, ApplicationResolverMode, DnsAddressRecords, DnsCache, DnsCacheAnswer,
    DnsCacheKey, DnsCacheQtype, DnsError, DnsServerId, DnsStrategy, ResolverGeneration,
};
use ferrum2_runtime::{ApplicationResolverAdapter, TcpResolver, UdpResolver};

struct CacheBackedBackend {
    cache: DnsCache,
    upstream_queries: AtomicUsize,
    contexts: Mutex<Vec<(usize, Network)>>,
}

impl CacheBackedBackend {
    fn ipv4(&self, request: ApplicationResolveRequest<'_>, now: Instant) -> Vec<Ipv4Addr> {
        let key = DnsCacheKey::new(
            DnsServerId::new(4),
            request.domain().clone(),
            DnsCacheQtype::A,
            ResolverGeneration::new(8),
        );
        if let Some(DnsCacheAnswer::Positive(DnsAddressRecords::A(records))) =
            self.cache.get(&key, now).expect("cache lookup")
        {
            return records.to_vec();
        }
        self.upstream_queries.fetch_add(1, Ordering::SeqCst);
        let records = Arc::<[Ipv4Addr]>::from([Ipv4Addr::new(192, 0, 2, 41)]);
        self.cache
            .insert_positive(
                key,
                DnsAddressRecords::A(Arc::clone(&records)),
                Duration::from_secs(60),
                now,
            )
            .expect("cache IPv4");
        records.to_vec()
    }

    fn ipv6(&self, request: ApplicationResolveRequest<'_>, now: Instant) -> Vec<Ipv6Addr> {
        let key = DnsCacheKey::new(
            DnsServerId::new(4),
            request.domain().clone(),
            DnsCacheQtype::Aaaa,
            ResolverGeneration::new(8),
        );
        if let Some(DnsCacheAnswer::Positive(DnsAddressRecords::Aaaa(records))) =
            self.cache.get(&key, now).expect("cache lookup")
        {
            return records.to_vec();
        }
        self.upstream_queries.fetch_add(1, Ordering::SeqCst);
        let records = Arc::<[Ipv6Addr]>::from([Ipv6Addr::LOCALHOST]);
        self.cache
            .insert_positive(
                key,
                DnsAddressRecords::Aaaa(Arc::clone(&records)),
                Duration::from_secs(60),
                now,
            )
            .expect("cache IPv6");
        records.to_vec()
    }
}

impl ApplicationResolveBackend for CacheBackedBackend {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            let context = request.context();
            self.contexts
                .lock()
                .expect("context log")
                .push((context.ingress(), context.network()));
            let now = Instant::now();
            let ipv4 = self.ipv4(request, now);
            let ipv6 = self.ipv6(request, now);
            Ok(request
                .strategy()
                .socket_candidates(request.port(), &ipv4, &ipv6))
        })
    }
}

#[tokio::test]
async fn tcp_and_udp_share_one_application_resolver_cache_and_strategy() {
    let backend = Arc::new(CacheBackedBackend {
        cache: DnsCache::try_new(NonZeroUsize::new(8).expect("positive capacity"))
            .expect("bounded cache"),
        upstream_queries: AtomicUsize::new(0),
        contexts: Mutex::new(Vec::new()),
    });
    let resolver = Arc::new(ApplicationResolver::configured(backend.clone()));
    let adapter = ApplicationResolverAdapter::new(resolver, 9, DnsStrategy::PreferIpv6);
    let other_ingress = adapter.for_ingress(10);

    assert_eq!(adapter.mode(), ApplicationResolverMode::Configured);
    assert!(adapter.shares_resolver_with(&other_ingress));
    let tcp = TcpResolver::resolve(&adapter, "Shared.Example.", 443)
        .await
        .expect("TCP resolution");
    let udp = UdpResolver::resolve(&adapter, "shared.example", 443)
        .await
        .expect("UDP resolution");
    let expected = vec![
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 41).into(), 443),
    ];

    assert_eq!(tcp, expected);
    assert_eq!(udp, expected);
    assert_eq!(backend.upstream_queries.load(Ordering::SeqCst), 2);
    assert_eq!(
        *backend.contexts.lock().expect("context log"),
        [(9, Network::Tcp), (9, Network::Udp)]
    );
}

#[tokio::test]
async fn task_local_ingress_views_are_concurrent_and_restore_the_default() {
    let backend = Arc::new(CacheBackedBackend {
        cache: DnsCache::try_new(NonZeroUsize::new(16).expect("positive capacity"))
            .expect("bounded cache"),
        upstream_queries: AtomicUsize::new(0),
        contexts: Mutex::new(Vec::new()),
    });
    let adapter = ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::configured(backend.clone())),
        11,
        DnsStrategy::Ipv4Only,
    );

    let (first, second) = tokio::join!(
        adapter.scope_ingress(3, TcpResolver::resolve(&adapter, "first.example", 443)),
        adapter.scope_ingress(7, TcpResolver::resolve(&adapter, "second.example", 443)),
    );
    first.expect("first scoped resolution");
    second.expect("second scoped resolution");
    TcpResolver::resolve(&adapter, "default.example", 443)
        .await
        .expect("default resolution after scopes");

    let mut contexts = backend.contexts.lock().expect("context log").clone();
    contexts.sort_unstable();
    assert_eq!(
        contexts,
        [(3, Network::Tcp), (7, Network::Tcp), (11, Network::Tcp),]
    );
}

struct FailingConfiguredBackend {
    calls: AtomicUsize,
}

impl ApplicationResolveBackend for FailingConfiguredBackend {
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

#[tokio::test]
async fn configured_adapter_failure_is_terminal_without_system_fallback() {
    let backend = Arc::new(FailingConfiguredBackend {
        calls: AtomicUsize::new(0),
    });
    let resolver = Arc::new(ApplicationResolver::configured(backend.clone()));
    let adapter = ApplicationResolverAdapter::new(resolver, 0, DnsStrategy::Ipv4Only);

    let error = TcpResolver::resolve(&adapter, "no-fallback.invalid", 443)
        .await
        .expect_err("configured failure");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}
