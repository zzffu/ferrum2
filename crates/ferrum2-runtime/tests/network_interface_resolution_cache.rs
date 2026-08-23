use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use ferrum2_runtime::{
    DialOptions, InterfaceBinding, InterfaceSelectionSource,
    NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY, NetworkInterfaceCatalog,
    NetworkInterfaceCatalogError, NetworkInterfaceObservation, NetworkInterfaceResolver,
    NetworkSnapshot, RouteNetworkOptions, SystemBestRoute,
};

#[derive(Clone)]
struct CountingCatalog {
    state: Arc<CountingCatalogState>,
}

struct CountingCatalogState {
    calls: Mutex<Vec<SocketAddr>>,
    first_failure: AtomicBool,
    concurrent_miss_barrier: Option<Arc<Barrier>>,
}

impl CountingCatalog {
    fn new(first_failure: bool, concurrent_miss_barrier: Option<Arc<Barrier>>) -> Self {
        Self {
            state: Arc::new(CountingCatalogState {
                calls: Mutex::new(Vec::new()),
                first_failure: AtomicBool::new(first_failure),
                concurrent_miss_barrier,
            }),
        }
    }

    fn calls(&self) -> Vec<SocketAddr> {
        self.state.calls.lock().unwrap().clone()
    }
}

impl NetworkInterfaceCatalog for CountingCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        destination: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        self.state.calls.lock().unwrap().push(destination);
        if let Some(barrier) = &self.state.concurrent_miss_barrier {
            barrier.wait();
        }
        if self.state.first_failure.swap(false, Ordering::SeqCst) {
            return Err(NetworkInterfaceCatalogError);
        }
        SystemBestRoute::new(1, 1).map_err(|_| NetworkInterfaceCatalogError)
    }
}

fn snapshot(generation: u64) -> Arc<NetworkSnapshot> {
    let binding =
        InterfaceBinding::new("underlay", 1, 1, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
            .unwrap();
    Arc::new(NetworkSnapshot::new(generation, Some(binding), None).unwrap())
}

fn destination(port: u16) -> SocketAddr {
    SocketAddr::from(([203, 0, 113, 10], port))
}

#[test]
fn successful_result_is_a_hit_only_after_real_reuse() {
    let catalog = CountingCatalog::new(false, None);
    let resolver = NetworkInterfaceResolver::new(catalog.clone());
    let snapshot = snapshot(7);
    let target = destination(443);

    let first = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            target,
            &snapshot,
        )
        .unwrap();
    let second = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            target,
            &snapshot,
        )
        .unwrap();

    assert!(!first.cache_hit());
    assert!(second.cache_hit());
    assert_eq!(catalog.calls(), [target]);
}

#[test]
fn destination_and_every_policy_input_are_isolated() {
    let catalog = CountingCatalog::new(false, None);
    let resolver = NetworkInterfaceResolver::new(catalog.clone());
    let snapshot = snapshot(8);
    let first_target = destination(443);
    let second_target = destination(8443);

    let system = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            first_target,
            &snapshot,
        )
        .unwrap();
    let other_target = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            second_target,
            &snapshot,
        )
        .unwrap();
    let route_default = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::new(false, Some("underlay")),
            first_target,
            &snapshot,
        )
        .unwrap();
    let explicit = resolver
        .resolve(
            &DialOptions::new(Some("underlay"), None, None),
            &RouteNetworkOptions::default(),
            first_target,
            &snapshot,
        )
        .unwrap();
    let explicit_hit = resolver
        .resolve(
            &DialOptions::new(Some("underlay"), None, None),
            &RouteNetworkOptions::default(),
            first_target,
            &snapshot,
        )
        .unwrap();

    assert!(!system.cache_hit());
    assert!(!other_target.cache_hit());
    assert!(!route_default.cache_hit());
    assert!(!explicit.cache_hit());
    assert!(explicit_hit.cache_hit());
    assert_eq!(
        system.selection_source(),
        InterfaceSelectionSource::SystemBestRoute
    );
    assert_eq!(
        route_default.selection_source(),
        InterfaceSelectionSource::RouteDefault
    );
    assert_eq!(
        explicit.selection_source(),
        InterfaceSelectionSource::OutboundExplicit
    );
    assert_eq!(catalog.calls(), [first_target, second_target]);
}

#[test]
fn a_new_generation_invalidates_all_old_results_without_allowing_regression() {
    let catalog = CountingCatalog::new(false, None);
    let resolver = NetworkInterfaceResolver::new(catalog.clone());
    let first = snapshot(11);
    let second = snapshot(12);
    let target = destination(53);

    assert!(
        !resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                target,
                &first,
            )
            .unwrap()
            .cache_hit()
    );
    assert!(
        resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                target,
                &first,
            )
            .unwrap()
            .cache_hit()
    );
    assert!(
        !resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                target,
                &second,
            )
            .unwrap()
            .cache_hit()
    );
    assert!(
        resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                target,
                &second,
            )
            .unwrap()
            .cache_hit()
    );

    let stale = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            target,
            &first,
        )
        .unwrap();
    let current = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            target,
            &second,
        )
        .unwrap();
    assert!(!stale.cache_hit());
    assert!(current.cache_hit());
    assert_eq!(catalog.calls().len(), 3);
}

#[test]
fn capacity_is_bounded_and_fifo_eviction_is_deterministic() {
    let catalog = CountingCatalog::new(false, None);
    let resolver = NetworkInterfaceResolver::new(catalog.clone());
    let snapshot = snapshot(20);

    for offset in 0..NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY {
        let port = u16::try_from(1_000 + offset).unwrap();
        let resolved = resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                destination(port),
                &snapshot,
            )
            .unwrap();
        assert!(!resolved.cache_hit());
    }
    assert_eq!(
        catalog.calls().len(),
        NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY
    );

    let newest_port = u16::try_from(999 + NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY).unwrap();
    assert!(
        resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                destination(newest_port),
                &snapshot,
            )
            .unwrap()
            .cache_hit()
    );
    assert!(
        !resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                destination(40_000),
                &snapshot,
            )
            .unwrap()
            .cache_hit()
    );
    assert!(
        !resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                destination(1_000),
                &snapshot,
            )
            .unwrap()
            .cache_hit()
    );
    assert_eq!(
        catalog.calls().len(),
        NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY + 2
    );
}

#[test]
fn failed_resolutions_are_never_cached() {
    let catalog = CountingCatalog::new(true, None);
    let resolver = NetworkInterfaceResolver::new(catalog.clone());
    let snapshot = snapshot(30);
    let target = destination(443);

    assert!(
        resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                target,
                &snapshot,
            )
            .is_err()
    );
    let recovered = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            target,
            &snapshot,
        )
        .unwrap();
    let cached = resolver
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::default(),
            target,
            &snapshot,
        )
        .unwrap();

    assert!(!recovered.cache_hit());
    assert!(cached.cache_hit());
    assert_eq!(catalog.calls().len(), 2);
}

#[test]
fn concurrent_misses_are_not_relabelled_as_cache_hits() {
    let barrier = Arc::new(Barrier::new(2));
    let catalog = CountingCatalog::new(false, Some(barrier));
    let resolver = Arc::new(NetworkInterfaceResolver::new(catalog.clone()));
    let snapshot = snapshot(40);
    let target = destination(443);

    let workers = (0..2)
        .map(|_| {
            let resolver = Arc::clone(&resolver);
            let snapshot = Arc::clone(&snapshot);
            std::thread::spawn(move || {
                resolver
                    .resolve(
                        &DialOptions::default(),
                        &RouteNetworkOptions::default(),
                        target,
                        &snapshot,
                    )
                    .unwrap()
                    .cache_hit()
            })
        })
        .collect::<Vec<_>>();
    let hits = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(hits, [false, false]);
    assert_eq!(catalog.calls().len(), 2);
    assert!(
        resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::default(),
                target,
                &snapshot,
            )
            .unwrap()
            .cache_hit()
    );
}
