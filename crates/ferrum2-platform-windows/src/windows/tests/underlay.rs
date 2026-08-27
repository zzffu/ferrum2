use super::managed_routes::InjectedRouteCleanup;
use super::support::{
    Error, ErrorKind, InjectedUnderlay, InterfaceCandidate, InterfaceIdentity,
    ManagedNetworkValidation, ManagedNetworkValidationOutcome, ManagedRouteRead,
    ManagedStateDamage, RouteFingerprint, SocketBindingOperations, UnderlayOperations,
    bind_fixed_with, bind_target_with, classify_underlay_refresh, eligible_interface_identity,
    refresh_underlay_with, revalidate_managed_network, snapshot_underlay_at,
    snapshot_underlay_with, underlay_matches_with, underlay_snapshot_matches,
};

#[test]
fn network_change_revalidates_underlay_and_owned_routes_before_shutdown() {
    let physical = InterfaceIdentity { luid: 7, index: 17 };
    let wintun = InterfaceIdentity { luid: 9, index: 19 };
    let route = RouteFingerprint {
        interface_luid: physical.luid,
        interface_index: physical.index,
        destination: "0.0.0.0".parse().unwrap(),
        prefix_length: 0,
        next_hop: "192.0.2.1".parse().unwrap(),
        metric: 4,
        source: Some("192.0.2.2".parse().unwrap()),
    };
    let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], true, None, None).unwrap();
    let underlay = InjectedUnderlay {
        interfaces: vec![physical],
        routes: vec![(endpoint.ip(), route)],
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();

    let mut generation = [1, 1].into_iter();
    let mut validated_generation = 0;
    let mut owned_routes = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        revalidate_managed_network(
            ManagedNetworkValidation {
                policy: &policy,
                owned: wintun,
                routes: &[1],
                validated_generation: &mut validated_generation,
            },
            false,
            || generation.next().unwrap(),
            &mut underlay.clone(),
            &mut owned_routes,
            || Ok(true),
            || Ok(true),
        )
        .unwrap(),
        ManagedNetworkValidationOutcome::Unchanged
    );
    assert_eq!(validated_generation, 1);
    assert_eq!(owned_routes.calls, ["get"]);

    for (name, changed_underlay, route_readback, expected) in [
        (
            "underlay",
            true,
            ManagedRouteRead::Present(1),
            ManagedNetworkValidationOutcome::UnderlayChanged,
        ),
        (
            "owned route",
            false,
            ManagedRouteRead::Present(2),
            ManagedNetworkValidationOutcome::ManagedStateDamaged(ManagedStateDamage::Route),
        ),
        (
            "replacement query",
            false,
            ManagedRouteRead::Failed,
            ManagedNetworkValidationOutcome::ManagedStateDamaged(ManagedStateDamage::Route),
        ),
    ] {
        let mut changed = underlay.clone();
        if changed_underlay {
            changed.routes[0].1.metric += 1;
        }
        let mut owned_routes = InjectedRouteCleanup {
            reads: [route_readback].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        let mut observed = 1;
        let mut generation = [2, 2].into_iter();
        assert_eq!(
            revalidate_managed_network(
                ManagedNetworkValidation {
                    policy: &policy,
                    owned: wintun,
                    routes: &[1],
                    validated_generation: &mut observed,
                },
                false,
                || generation.next().unwrap(),
                &mut changed,
                &mut owned_routes,
                || Ok(true),
                || Ok(true),
            )
            .unwrap(),
            expected,
            "{name}"
        );
        assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
        assert!(bind_fixed_with(&policy, endpoint, &mut InjectedBinder::default()).is_err());
    }

    let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();
    let mut generation = [2, 3, 3].into_iter();
    let mut observed = 1;
    let mut owned_routes = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1), ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        revalidate_managed_network(
            ManagedNetworkValidation {
                policy: &policy,
                owned: wintun,
                routes: &[1],
                validated_generation: &mut observed,
            },
            false,
            || generation.next().unwrap(),
            &mut underlay.clone(),
            &mut owned_routes,
            || Ok(true),
            || Ok(true),
        )
        .unwrap(),
        ManagedNetworkValidationOutcome::Unchanged,
        "one repeated/coalesced signal gets one bounded retry"
    );
    assert_eq!(observed, 3);

    let mut generation = [4, 5, 6].into_iter();
    let mut owned_routes = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1), ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        revalidate_managed_network(
            ManagedNetworkValidation {
                policy: &policy,
                owned: wintun,
                routes: &[1],
                validated_generation: &mut observed,
            },
            false,
            || generation.next().unwrap(),
            &mut underlay.clone(),
            &mut owned_routes,
            || Ok(true),
            || Ok(true),
        )
        .unwrap(),
        ManagedNetworkValidationOutcome::UnderlayChanged,
        "repeated changes exhaust the bounded retry"
    );
    assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
    assert!(
        bind_target_with(
            &policy,
            endpoint,
            &mut underlay.clone(),
            &mut InjectedBinder::default(),
        )
        .is_err()
    );

    let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();
    let mut observed = 0;
    let mut owned_routes = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    let mut additional_checks = 0;
    assert_eq!(
        revalidate_managed_network(
            ManagedNetworkValidation {
                policy: &policy,
                owned: wintun,
                routes: &[1],
                validated_generation: &mut observed,
            },
            true,
            || 0,
            &mut underlay.clone(),
            &mut owned_routes,
            || {
                additional_checks += 1;
                Ok(false)
            },
            || Ok(true),
        )
        .unwrap(),
        ManagedNetworkValidationOutcome::ManagedStateDamaged(ManagedStateDamage::Dns),
        "a forced runtime audit rejects a mutated DNS lease even without a generation bump"
    );
    assert_eq!(additional_checks, 1);
    assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
}

impl UnderlayOperations for InjectedUnderlay {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error> {
        if self.fail_at == Some("eligible") {
            return Err(Error);
        }
        Ok(self
            .interfaces
            .iter()
            .copied()
            .filter(|identity| Some(*identity) != excluded)
            .collect())
    }

    fn best_interface(&mut self, destination: std::net::SocketAddr) -> Result<u32, Error> {
        self.best_calls += 1;
        if self.fail_at == Some("best") {
            Err(Error)
        } else {
            self.routes
                .iter()
                .find_map(|(candidate, route)| {
                    (*candidate == destination.ip()).then_some(route.interface_index)
                })
                .ok_or(Error)
        }
    }

    fn interface_metric(
        &mut self,
        _family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<u32, Error> {
        Ok(self
            .interface_metrics
            .iter()
            .find_map(|(index, metric)| (*index == interface_index).then_some(*metric))
            .unwrap_or(0))
    }

    fn constrained_route(
        &mut self,
        destination: std::net::SocketAddr,
        interface_index: u32,
        _require_source: bool,
    ) -> Result<RouteFingerprint, Error> {
        if self.fail_at == Some("route") {
            return Err(Error);
        }
        if let Some(generation) = &self.change_generation {
            generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        self.routes
            .iter()
            .find_map(|(candidate, route)| {
                (*candidate == destination.ip() && route.interface_index == interface_index)
                    .then_some(*route)
            })
            .or_else(|| {
                self.routes.iter().find_map(|(candidate, route)| {
                    (*candidate == destination.ip()).then_some(*route)
                })
            })
            .ok_or(Error)
    }
}

#[derive(Default)]
struct InjectedBinder {
    calls: Vec<(std::net::IpAddr, u32)>,
    change_generation: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    fail: bool,
}

impl SocketBindingOperations for InjectedBinder {
    fn bind(&mut self, family: std::net::IpAddr, interface_index: u32) -> Result<(), Error> {
        self.calls.push((family, interface_index));
        if let Some(generation) = &self.change_generation {
            generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        if self.fail { Err(Error) } else { Ok(()) }
    }
}

fn injected_fingerprint(identity: InterfaceIdentity, family: std::net::IpAddr) -> RouteFingerprint {
    match family {
        std::net::IpAddr::V4(_) => RouteFingerprint {
            interface_luid: identity.luid,
            interface_index: identity.index,
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            next_hop: "192.0.2.1".parse().unwrap(),
            metric: 4,
            source: Some("192.0.2.2".parse().unwrap()),
        },
        std::net::IpAddr::V6(_) => RouteFingerprint {
            interface_luid: identity.luid,
            interface_index: identity.index,
            destination: "::".parse().unwrap(),
            prefix_length: 0,
            next_hop: "2001:db8:ffff::1".parse().unwrap(),
            metric: 4,
            source: Some("2001:db8:ffff::2".parse().unwrap()),
        },
    }
}

#[test]
fn dual_stack_target_binding_selects_actual_target_and_rejects_tun() {
    let physical_v4 = InterfaceIdentity { luid: 7, index: 17 };
    let physical_v6 = InterfaceIdentity { luid: 8, index: 18 };
    let wintun = InterfaceIdentity { luid: 9, index: 19 };
    let fixed_v4: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
    let fixed_v6: std::net::SocketAddr = "[2001:db8::8]:443".parse().unwrap();
    let target_v4_a: std::net::SocketAddr = "203.0.113.8:80".parse().unwrap();
    let target_v4_b: std::net::SocketAddr = "192.0.2.200:80".parse().unwrap();
    let target_v6: std::net::SocketAddr = "[2001:db8:1::8]:80".parse().unwrap();
    let tun_target: std::net::SocketAddr = "203.0.113.19:80".parse().unwrap();
    let routes = vec![
        (
            fixed_v4.ip(),
            injected_fingerprint(physical_v4, fixed_v4.ip()),
        ),
        (
            fixed_v6.ip(),
            injected_fingerprint(physical_v6, fixed_v6.ip()),
        ),
        (
            target_v4_a.ip(),
            injected_fingerprint(physical_v4, target_v4_a.ip()),
        ),
        (
            target_v4_b.ip(),
            injected_fingerprint(physical_v6, target_v4_b.ip()),
        ),
        (
            target_v6.ip(),
            injected_fingerprint(physical_v6, target_v6.ip()),
        ),
        (
            tun_target.ip(),
            injected_fingerprint(wintun, tun_target.ip()),
        ),
    ];
    let mut operations = InjectedUnderlay {
        interfaces: vec![physical_v4, physical_v6, wintun],
        routes,
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(41));
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![fixed_v4, fixed_v6], true, None, None)
            .unwrap();
    let policy = snapshot_underlay_at(&config, generation, 41, &mut operations).unwrap();
    policy.set_owned_identity(wintun).unwrap();

    let mut binder = InjectedBinder::default();
    bind_fixed_with(&policy, fixed_v4, &mut binder).unwrap();
    bind_fixed_with(&policy, fixed_v6, &mut binder).unwrap();
    bind_target_with(&policy, target_v4_a, &mut operations, &mut binder).unwrap();
    bind_target_with(&policy, target_v4_b, &mut operations, &mut binder).unwrap();
    bind_target_with(&policy, target_v6, &mut operations, &mut binder).unwrap();
    assert_eq!(operations.best_calls, 2, "target binds remain constrained");
    assert_eq!(
        binder.calls,
        [
            (fixed_v4.ip(), physical_v4.index),
            (fixed_v6.ip(), physical_v6.index),
            (target_v4_a.ip(), physical_v4.index),
            (target_v4_b.ip(), physical_v6.index),
            (target_v6.ip(), physical_v6.index),
        ],
        "multiple default routes are selected per actual target and family"
    );
    assert!(bind_target_with(&policy, tun_target, &mut operations, &mut binder).is_err());
    assert_eq!(
        operations.best_calls, 2,
        "target binds never use global best route"
    );
    assert_eq!(
        binder.calls.len(),
        5,
        "the managed interface is never bound"
    );

    let fixed_only =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![fixed_v4], false, None, None).unwrap();
    let fixed_only = snapshot_underlay_with(&fixed_only, &mut operations).unwrap();
    fixed_only.set_owned_identity(wintun).unwrap();
    assert!(bind_target_with(&fixed_only, target_v4_a, &mut operations, &mut binder).is_err());
}

#[test]
fn target_binding_excludes_tun_and_orders_prefix_then_effective_metric() {
    let physical_a = InterfaceIdentity { luid: 7, index: 17 };
    let physical_b = InterfaceIdentity { luid: 8, index: 18 };
    let physical_c = InterfaceIdentity { luid: 9, index: 20 };
    let wintun = InterfaceIdentity {
        luid: 10,
        index: 19,
    };
    let target: std::net::SocketAddr = "203.0.113.8:443".parse().unwrap();
    let mut route_a = injected_fingerprint(physical_a, target.ip());
    route_a.prefix_length = 8;
    route_a.metric = 1;
    let mut route_b = injected_fingerprint(physical_b, target.ip());
    route_b.prefix_length = 24;
    route_b.metric = 100;
    let mut route_c = injected_fingerprint(physical_c, target.ip());
    route_c.prefix_length = 24;
    route_c.metric = 50;
    let mut tun_route = injected_fingerprint(wintun, target.ip());
    tun_route.prefix_length = 32;
    tun_route.metric = 0;
    let mut operations = InjectedUnderlay {
        interfaces: vec![physical_a, physical_b, physical_c, wintun],
        routes: vec![
            (target.ip(), route_a),
            (target.ip(), route_b),
            (target.ip(), route_c),
            (target.ip(), tun_route),
        ],
        interface_metrics: vec![(physical_b.index, 100), (physical_c.index, 10)],
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), Vec::new(), true, None, None).unwrap();
    let policy = snapshot_underlay_with(&config, &mut operations).unwrap();
    policy.set_owned_identity(wintun).unwrap();
    let mut binder = InjectedBinder::default();

    bind_target_with(&policy, target, &mut operations, &mut binder).unwrap();

    assert_eq!(binder.calls, [(target.ip(), physical_c.index)]);
    assert_eq!(operations.best_calls, 0);
}

#[test]
fn underlay_binding_fails_closed_across_every_generation_race() {
    let physical = InterfaceIdentity { luid: 7, index: 17 };
    let wintun = InterfaceIdentity { luid: 9, index: 19 };
    let target: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), Vec::new(), true, None, None).unwrap();
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(7));
    let make_operations = || InjectedUnderlay {
        interfaces: vec![physical, wintun],
        routes: vec![(target.ip(), injected_fingerprint(physical, target.ip()))],
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let mut operations = make_operations();
    let policy = snapshot_underlay_at(&config, generation.clone(), 7, &mut operations).unwrap();
    policy.set_owned_identity(wintun).unwrap();

    generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let mut binder = InjectedBinder::default();
    assert!(bind_target_with(&policy, target, &mut operations, &mut binder).is_err());
    assert!(
        binder.calls.is_empty(),
        "a stale policy does not touch the socket"
    );

    policy.accept_generation(8);
    let mut changes_during_route = make_operations();
    changes_during_route.change_generation = Some(generation.clone());
    assert!(bind_target_with(&policy, target, &mut changes_during_route, &mut binder,).is_err());
    assert!(
        binder.calls.is_empty(),
        "a route-selection race is caught before setsockopt"
    );

    policy.accept_generation(9);
    let mut changes_during_bind = InjectedBinder {
        change_generation: Some(generation.clone()),
        ..InjectedBinder::default()
    };
    assert!(
        bind_target_with(
            &policy,
            target,
            &mut make_operations(),
            &mut changes_during_bind,
        )
        .is_err()
    );
    assert_eq!(changes_during_bind.calls.len(), 1);

    let mut validated_generation = 9;
    let mut no_routes = InjectedRouteCleanup {
        reads: std::collections::VecDeque::new(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        revalidate_managed_network(
            ManagedNetworkValidation {
                policy: &policy,
                owned: wintun,
                routes: &[],
                validated_generation: &mut validated_generation,
            },
            false,
            || generation.load(std::sync::atomic::Ordering::Acquire),
            &mut make_operations(),
            &mut no_routes,
            || Ok(true),
            || Ok(true),
        )
        .unwrap(),
        ManagedNetworkValidationOutcome::Unchanged
    );
    assert_eq!(validated_generation, 10);
    bind_target_with(
        &policy,
        target,
        &mut make_operations(),
        &mut InjectedBinder::default(),
    )
    .unwrap();

    let fixed =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![target], false, None, None).unwrap();
    let mut snapshot_race = make_operations();
    snapshot_race.change_generation = Some(generation.clone());
    assert!(snapshot_underlay_at(&fixed, generation, 10, &mut snapshot_race).is_err());
}

#[test]
fn underlay_refresh_is_transactional_and_temporary_capture_failure_is_recoverable() {
    let physical_a = InterfaceIdentity { luid: 7, index: 17 };
    let physical_b = InterfaceIdentity { luid: 8, index: 18 };
    let wintun = InterfaceIdentity { luid: 9, index: 19 };
    let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], false, None, None).unwrap();
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    let mut initial_operations = InjectedUnderlay {
        interfaces: vec![physical_a, wintun],
        routes: vec![(
            endpoint.ip(),
            injected_fingerprint(physical_a, endpoint.ip()),
        )],
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let current = snapshot_underlay_at(
        &config,
        std::sync::Arc::clone(&generation),
        1,
        &mut initial_operations,
    )
    .unwrap();
    current.set_owned_identity(wintun).unwrap();

    generation.store(2, std::sync::atomic::Ordering::Release);
    let mut refreshed_operations = InjectedUnderlay {
        interfaces: vec![physical_b, wintun],
        routes: vec![(
            endpoint.ip(),
            injected_fingerprint(physical_b, endpoint.ip()),
        )],
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let mut validated_generation = 1;
    let refreshed = refresh_underlay_with(
        &config,
        &current,
        wintun,
        &mut validated_generation,
        std::sync::Arc::clone(&generation),
        &mut refreshed_operations,
    )
    .unwrap();

    assert_eq!(validated_generation, 2);
    assert!(!current.valid.load(std::sync::atomic::Ordering::Acquire));
    assert!(refreshed.generation_is_current());
    let mut binder = InjectedBinder::default();
    bind_fixed_with(&refreshed, endpoint, &mut binder).unwrap();
    assert_eq!(binder.calls, [(endpoint.ip(), physical_b.index)]);

    generation.store(3, std::sync::atomic::Ordering::Release);
    let mut failed_operations = InjectedUnderlay {
        fail_at: Some("route"),
        ..refreshed_operations
    };
    let result = classify_underlay_refresh(refresh_underlay_with(
        &config,
        &refreshed,
        wintun,
        &mut validated_generation,
        generation,
        &mut failed_operations,
    ));
    let error = match result {
        Ok(_) => panic!("temporary route capture failure must fail the refresh"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ErrorKind::RecoverableSession);
    assert!(refreshed.valid.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(validated_generation, 2);
}

#[test]
fn managed_generation_and_underlay_post_capture_use_frozen_physical_route() {
    let physical = InterfaceIdentity { luid: 7, index: 17 };
    let wintun = InterfaceIdentity { luid: 9, index: 19 };
    let route = RouteFingerprint {
        interface_luid: physical.luid,
        interface_index: physical.index,
        destination: "0.0.0.0".parse().unwrap(),
        prefix_length: 0,
        next_hop: "192.0.2.1".parse().unwrap(),
        metric: 4,
        source: Some("192.0.2.2".parse().unwrap()),
    };
    let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], true, None, None).unwrap();
    let mut operations = InjectedUnderlay {
        interfaces: vec![physical],
        routes: vec![(endpoint.ip(), route)],
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };
    let policy = snapshot_underlay_with(&config, &mut operations).unwrap();
    assert_eq!(
        operations.best_calls, 1,
        "unrestricted lookup is pre-capture"
    );

    operations.interfaces.push(wintun);
    assert!(underlay_matches_with(&policy, wintun, &mut operations).unwrap());
    assert_eq!(
        operations.best_calls, 1,
        "post-capture cannot re-run best-interface"
    );

    for changed in [
        RouteFingerprint {
            interface_luid: physical.luid + 1,
            ..route
        },
        RouteFingerprint {
            interface_index: physical.index + 1,
            ..route
        },
        RouteFingerprint {
            source: Some("192.0.2.3".parse().unwrap()),
            ..route
        },
        RouteFingerprint {
            next_hop: "192.0.2.9".parse().unwrap(),
            ..route
        },
        RouteFingerprint { metric: 5, ..route },
    ] {
        let mut changed_operations = operations.clone();
        changed_operations.routes[0].1 = changed;
        assert!(!underlay_matches_with(&policy, wintun, &mut changed_operations).unwrap());
    }

    let mut changed_identity = operations.clone();
    changed_identity.interfaces[0].luid += 1;
    assert!(!underlay_matches_with(&policy, wintun, &mut changed_identity).unwrap());

    let mut stable = [4_u64, 4].into_iter();
    assert!(
        underlay_snapshot_matches(
            &policy,
            wintun,
            4,
            || stable.next().unwrap(),
            &mut operations.clone(),
        )
        .unwrap()
    );
    let mut changed_before = [5_u64].into_iter();
    assert!(
        !underlay_snapshot_matches(
            &policy,
            wintun,
            4,
            || changed_before.next().unwrap(),
            &mut operations.clone(),
        )
        .unwrap()
    );
    let mut changed_during = [4_u64, 5].into_iter();
    assert!(
        !underlay_snapshot_matches(
            &policy,
            wintun,
            4,
            || changed_during.next().unwrap(),
            &mut operations,
        )
        .unwrap()
    );
}

#[test]
fn underlay_eligibility_and_query_failures_are_closed() {
    let physical = InterfaceIdentity { luid: 7, index: 17 };
    let route = RouteFingerprint {
        interface_luid: physical.luid,
        interface_index: physical.index,
        destination: "0.0.0.0".parse().unwrap(),
        prefix_length: 0,
        next_hop: "192.0.2.1".parse().unwrap(),
        metric: 4,
        source: Some("192.0.2.2".parse().unwrap()),
    };
    let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
    let config =
        crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], true, None, None).unwrap();
    let operations = InjectedUnderlay {
        interfaces: vec![physical],
        routes: vec![(endpoint.ip(), route)],
        interface_metrics: Vec::new(),
        best_calls: 0,
        fail_at: None,
        change_generation: None,
    };

    for failure in ["eligible", "best", "route"] {
        let mut failed = operations.clone();
        failed.fail_at = Some(failure);
        assert!(snapshot_underlay_with(&config, &mut failed).is_err());
    }
    let mut none = operations.clone();
    none.interfaces.clear();
    assert!(snapshot_underlay_with(&config, &mut none).is_err());
    let mut missing_best = operations.clone();
    missing_best.routes[0].1.interface_index += 1;
    assert!(snapshot_underlay_with(&config, &mut missing_best).is_err());

    let raw = InterfaceCandidate {
        identity: physical,
        loopback: false,
        operational: true,
        admin_enabled: true,
        connected: true,
        hardware_interface: true,
    };
    assert!(eligible_interface_identity(raw, None) == Some(physical));
    assert!(eligible_interface_identity(raw, Some(physical)).is_none());
    for ineligible in [
        {
            let mut row = raw;
            row.identity.index = 0;
            row
        },
        {
            let mut row = raw;
            row.loopback = true;
            row
        },
        {
            let mut row = raw;
            row.operational = false;
            row
        },
        {
            let mut row = raw;
            row.admin_enabled = false;
            row
        },
        {
            let mut row = raw;
            row.connected = false;
            row
        },
        {
            let mut row = raw;
            row.hardware_interface = false;
            row
        },
    ] {
        assert!(eligible_interface_identity(ineligible, None).is_none());
    }
}
