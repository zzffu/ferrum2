use super::support::{
    ABI_EXPORTS, AdapterCreateFailure, CleanupOperations, DLL_BYTES, DLL_SHA256, DadProgress,
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF,
    ERROR_NO_MORE_ITEMS, Error, ErrorKind, IpDadStateDeprecated, IpDadStateDuplicate,
    IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative, IpPrefix, Ipv4Prefix, Ipv6Prefix,
    LoaderOperations, MIB_IPFORWARD_ROW2, SendOutcome, SessionJournal, SetupOperations,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WaitOutcome, capture_route_row,
    classify_adapter_create_failure, classify_receive_null, classify_send_allocation_failure,
    classify_wait_result, cleanup_transaction, dad_snapshot, finish_setup_transaction,
    increment_route_interface_luid, load_transaction, require_exports, route_destination,
    route_matches, route_next_hop, set_route_destination, set_route_next_hop, setup_transaction,
    validate_artifact,
};

struct InjectedSetup {
    ipv4: bool,
    ipv6: bool,
    fail_at: Option<usize>,
    cleanup_fail_at: Option<usize>,
    idle: bool,
    calls: Vec<&'static str>,
    resources: Vec<&'static str>,
    notifications: bool,
    strict_route: bool,
    routes: Vec<&'static str>,
    dns: Vec<&'static str>,
    cleanup_calls: Vec<&'static str>,
}

impl InjectedSetup {
    fn step(&mut self, name: &'static str, resource: Option<&'static str>) -> Result<(), Error> {
        let position = self.calls.len();
        self.calls.push(name);
        if self.fail_at == Some(position) {
            Err(Error)
        } else {
            if let Some(resource) = resource {
                self.resources.push(resource);
            }
            Ok(())
        }
    }

    fn cleanup_step(&mut self, resource: &'static str, name: &'static str) -> Option<bool> {
        if self.resources.last() != Some(&resource) {
            return None;
        }
        self.resources.pop();
        let position = self.cleanup_calls.len();
        self.cleanup_calls.push(name);
        Some(self.cleanup_fail_at == Some(position))
    }
}

impl SetupOperations for InjectedSetup {
    fn check_cancelled(&mut self) -> Result<(), Error> {
        self.step("cancel", None)
    }

    fn check_deadline(&mut self) -> Result<(), Error> {
        self.step("deadline", None)
    }

    fn create_adapter(&mut self) -> Result<(), Error> {
        self.step("create", Some("adapter"))
    }

    fn check_driver(&mut self) -> Result<(), Error> {
        self.step("driver", None)
    }

    fn identify_adapter(&mut self) -> Result<(), Error> {
        self.step("identity", None)
    }

    fn ipv4_enabled(&self) -> bool {
        self.ipv4
    }

    fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    fn set_ipv4_mtu(&mut self) -> Result<(), Error> {
        self.step("ipv4-mtu", Some("ipv4-mtu"))
    }

    fn set_ipv6_mtu(&mut self) -> Result<(), Error> {
        self.step("ipv6-mtu", Some("ipv6-mtu"))
    }

    fn add_ipv4_address(&mut self) -> Result<(), Error> {
        self.step("ipv4-address", Some("ipv4-address"))
    }

    fn add_ipv6_address(&mut self) -> Result<(), Error> {
        self.step("ipv6-address", Some("ipv6-address"))
    }

    fn start_session(&mut self) -> Result<(), Error> {
        self.step("start-session", Some("session"))
    }

    fn wait_for_dad(&mut self) -> Result<(), Error> {
        assert!(self.resources.contains(&"session"));
        self.step("dad", None)
    }
}

impl CleanupOperations for InjectedSetup {
    fn session_is_idle(&mut self) -> bool {
        self.idle
    }

    fn cancel_notifications(&mut self) -> Option<bool> {
        if !std::mem::take(&mut self.notifications) {
            return None;
        }
        let position = self.cleanup_calls.len();
        self.cleanup_calls.push("notifications");
        Some(self.cleanup_fail_at == Some(position))
    }

    fn close_strict_route(&mut self) -> Option<bool> {
        if !std::mem::take(&mut self.strict_route) {
            return None;
        }
        let position = self.cleanup_calls.len();
        self.cleanup_calls.push("strict-route");
        Some(self.cleanup_fail_at == Some(position))
    }

    fn delete_last_route(&mut self) -> Option<bool> {
        let route = self.routes.pop()?;
        let position = self.cleanup_calls.len();
        self.cleanup_calls.push(route);
        Some(self.cleanup_fail_at == Some(position))
    }

    fn restore_last_dns(&mut self) -> Option<bool> {
        let dns = self.dns.pop()?;
        let position = self.cleanup_calls.len();
        self.cleanup_calls.push(dns);
        Some(self.cleanup_fail_at == Some(position))
    }

    fn end_session(&mut self) -> Option<bool> {
        self.cleanup_step("session", "end-session")
    }

    fn delete_last_address(&mut self) -> Option<bool> {
        for (resource, name) in [
            ("ipv6-address", "ipv6-address"),
            ("ipv4-address", "ipv4-address"),
        ] {
            if let Some(result) = self.cleanup_step(resource, name) {
                return Some(result);
            }
        }
        None
    }

    fn restore_ipv6_mtu(&mut self) -> Option<bool> {
        self.cleanup_step("ipv6-mtu", "ipv6-mtu")
    }

    fn restore_ipv4_mtu(&mut self) -> Option<bool> {
        self.cleanup_step("ipv4-mtu", "ipv4-mtu")
    }

    fn close_adapter(&mut self) -> Option<bool> {
        self.cleanup_step("adapter", "adapter")
    }
}

struct InjectedLoader {
    fail_at: Option<usize>,
    calls: Vec<&'static str>,
}

impl InjectedLoader {
    fn step(&mut self, name: &'static str) -> Result<(), Error> {
        let position = self.calls.len();
        self.calls.push(name);
        if self.fail_at == Some(position) {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

impl LoaderOperations for InjectedLoader {
    fn discover_executable(&mut self) -> Result<(), Error> {
        self.step("executable")
    }

    fn reject_network_and_reparse_directories(&mut self) -> Result<(), Error> {
        self.step("held-directories")
    }

    fn open_sibling_dll(&mut self) -> Result<(), Error> {
        self.step("sibling-dll")
    }

    fn verify_dll_identity(&mut self) -> Result<(), Error> {
        self.step("file-identity")
    }

    fn verify_artifact(&mut self) -> Result<(), Error> {
        self.step("size/hash")
    }

    fn load_system32_scoped_library(&mut self) -> Result<(), Error> {
        self.step("system32-load")
    }

    fn resolve_exact_abi(&mut self) -> Result<(), Error> {
        self.step("eleven-exports")
    }

    fn pin_loaded_library(&mut self) -> Result<(), Error> {
        self.step("process-lifetime-pin")
    }
}

#[test]
fn loader_and_every_abi_position_fail_closed() {
    let order = [
        "executable",
        "held-directories",
        "sibling-dll",
        "file-identity",
        "size/hash",
        "system32-load",
        "eleven-exports",
        "process-lifetime-pin",
    ];
    for failed in 0..order.len() {
        let mut loader = InjectedLoader {
            fail_at: Some(failed),
            calls: Vec::new(),
        };
        assert!(load_transaction(&mut loader).is_err(), "loader {failed}");
        assert_eq!(loader.calls, order[..=failed], "loader {failed}");
    }
    let mut loader = InjectedLoader {
        fail_at: None,
        calls: Vec::new(),
    };
    load_transaction(&mut loader).expect("complete loader");
    assert_eq!(loader.calls, order);

    assert!(validate_artifact(DLL_BYTES, DLL_SHA256).is_ok());
    assert!(validate_artifact(DLL_BYTES - 1, DLL_SHA256).is_err());
    assert!(validate_artifact(DLL_BYTES + 1, DLL_SHA256).is_err());
    let mut wrong_hash = DLL_SHA256;
    wrong_hash[0] ^= 1;
    assert!(validate_artifact(DLL_BYTES, wrong_hash).is_err());

    for missing in 0..ABI_EXPORTS.len() {
        let mut visited = Vec::new();
        let result = require_exports(|name| {
            visited.push(name.to_vec());
            name != ABI_EXPORTS[missing]
        });
        assert!(result.is_err(), "missing export {missing}");
        assert_eq!(
            visited,
            ABI_EXPORTS[..=missing]
                .iter()
                .map(|name| name.to_vec())
                .collect::<Vec<_>>(),
            "missing export {missing}"
        );
    }
    let mut visited = Vec::new();
    require_exports(|name| {
        visited.push(name.to_vec());
        true
    })
    .expect("all exact exports");
    assert_eq!(
        visited,
        ABI_EXPORTS
            .iter()
            .map(|name| name.to_vec())
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_enabled_family_setup_stage_fails_closed_and_rolls_back() {
    let cases: [(bool, bool, &[&str]); 3] = [
        (
            true,
            false,
            &[
                "cancel",
                "deadline",
                "create",
                "driver",
                "start-session",
                "identity",
                "ipv4-mtu",
                "ipv4-address",
                "dad",
            ],
        ),
        (
            false,
            true,
            &[
                "cancel",
                "deadline",
                "create",
                "driver",
                "start-session",
                "identity",
                "ipv6-mtu",
                "ipv6-address",
                "dad",
            ],
        ),
        (
            true,
            true,
            &[
                "cancel",
                "deadline",
                "create",
                "driver",
                "start-session",
                "identity",
                "ipv4-mtu",
                "ipv6-mtu",
                "ipv4-address",
                "ipv6-address",
                "dad",
            ],
        ),
    ];
    for (ipv4, ipv6, order) in cases {
        for failed in 0..order.len() {
            let mut setup = InjectedSetup {
                ipv4,
                ipv6,
                fail_at: Some(failed),
                cleanup_fail_at: None,
                idle: true,
                calls: Vec::new(),
                resources: Vec::new(),
                notifications: false,
                strict_route: false,
                routes: Vec::new(),
                dns: Vec::new(),
                cleanup_calls: Vec::new(),
            };
            assert!(
                setup_transaction(&mut setup).is_err(),
                "families {ipv4}/{ipv6}, step {failed}"
            );
            assert_eq!(setup.calls, order[..=failed]);
            let expected_cleanup = [
                ("ipv6-address", "ipv6-address"),
                ("ipv4-address", "ipv4-address"),
                ("ipv6-mtu", "ipv6-mtu"),
                ("ipv4-mtu", "ipv4-mtu"),
                ("session", "end-session"),
                ("adapter", "adapter"),
            ]
            .into_iter()
            .filter_map(|(resource, cleanup)| {
                setup.resources.contains(&resource).then_some(cleanup)
            })
            .collect::<Vec<_>>();
            assert!(!cleanup_transaction(&mut setup));
            assert_eq!(setup.cleanup_calls, expected_cleanup);
            assert!(setup.resources.is_empty());
        }

        let mut setup = InjectedSetup {
            ipv4,
            ipv6,
            fail_at: None,
            cleanup_fail_at: None,
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            strict_route: false,
            routes: Vec::new(),
            dns: Vec::new(),
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut setup).expect("complete setup");
        assert_eq!(setup.calls, order);
        assert!(
            setup.calls.iter().position(|step| *step == "start-session")
                < setup.calls.iter().position(|step| *step == "identity")
        );
        assert!(
            setup
                .calls
                .iter()
                .position(|step| *step == "identity")
                .unwrap()
                < setup
                    .calls
                    .iter()
                    .position(|step| matches!(*step, "ipv4-mtu" | "ipv6-mtu"))
                    .unwrap()
        );
    }
}

#[test]
fn only_post_session_enabled_family_natural_preferred_dad_is_ready() {
    assert!(dad_snapshot(true, &[], false).is_err());
    assert_eq!(
        dad_snapshot(true, &[IpDadStatePreferred], false),
        Ok(DadProgress::Ready)
    );
    assert_eq!(
        dad_snapshot(true, &[IpDadStateTentative], false),
        Ok(DadProgress::Waiting)
    );
    assert!(dad_snapshot(true, &[IpDadStateTentative], true).is_err());
    assert!(dad_snapshot(false, &[IpDadStatePreferred, IpDadStatePreferred], false).is_err());
    assert_eq!(
        dad_snapshot(true, &[IpDadStatePreferred, IpDadStatePreferred], false),
        Ok(DadProgress::Ready)
    );
    for states in [
        [IpDadStateTentative, IpDadStatePreferred],
        [IpDadStatePreferred, IpDadStateTentative],
        [IpDadStateTentative, IpDadStateTentative],
    ] {
        assert_eq!(dad_snapshot(true, &states, false), Ok(DadProgress::Waiting));
        assert!(dad_snapshot(true, &states, true).is_err());
    }
    for family in 0..2 {
        for state in [IpDadStateDuplicate, IpDadStateInvalid, IpDadStateDeprecated] {
            let mut states = [IpDadStatePreferred, IpDadStatePreferred];
            states[family] = state;
            assert!(dad_snapshot(true, &states, false).is_err());
        }
    }
}

#[test]
fn adapter_create_null_causes_are_closed_and_redacted() {
    assert_eq!(
        classify_adapter_create_failure(ERROR_ACCESS_DENIED),
        AdapterCreateFailure::NoAdmin
    );
    assert_eq!(
        classify_adapter_create_failure(ERROR_ALREADY_EXISTS),
        AdapterCreateFailure::NameCollision
    );
    assert_eq!(
        classify_adapter_create_failure(0xdead_beef),
        AdapterCreateFailure::Other
    );
}

#[test]
fn send_allocation_failure_distinguishes_ring_full_from_fatal_errors() {
    assert_eq!(
        classify_send_allocation_failure(ERROR_BUFFER_OVERFLOW),
        Ok(SendOutcome::DroppedRingFull)
    );
    assert_eq!(
        classify_send_allocation_failure(ERROR_ACCESS_DENIED)
            .expect_err("non-ring failure")
            .kind(),
        ErrorKind::UnrecoverableCorruption
    );
}

#[test]
fn receive_null_distinguishes_empty_recoverable_eof_and_corruption() {
    assert_eq!(classify_receive_null(ERROR_NO_MORE_ITEMS), Ok(()));
    assert_eq!(
        classify_receive_null(ERROR_HANDLE_EOF)
            .expect_err("ended session")
            .kind(),
        ErrorKind::RecoverableSession
    );
    assert_eq!(
        classify_receive_null(ERROR_ACCESS_DENIED)
            .expect_err("unexpected driver failure")
            .kind(),
        ErrorKind::UnrecoverableCorruption
    );
}

#[test]
fn wait_result_distinguishes_each_installed_handle_and_timeout() {
    for (result, expected) in [
        (WAIT_OBJECT_0, WaitOutcome::Stop),
        (WAIT_OBJECT_0 + 1, WaitOutcome::Work),
        (WAIT_OBJECT_0 + 2, WaitOutcome::NetworkChanged),
        (WAIT_OBJECT_0 + 3, WaitOutcome::Readable),
        (WAIT_TIMEOUT, WaitOutcome::Timeout),
    ] {
        assert_eq!(classify_wait_result(result), Ok(expected));
    }
    assert_eq!(
        classify_wait_result(WAIT_FAILED)
            .expect_err("failed wait")
            .kind(),
        ErrorKind::UnrecoverableCorruption
    );
    assert_eq!(
        classify_wait_result(WAIT_OBJECT_0 + 4)
            .expect_err("unexpected wait index")
            .kind(),
        ErrorKind::UnrecoverableCorruption
    );
}

#[test]
fn work_and_stop_wait_slots_remain_distinct() {
    assert_eq!(classify_wait_result(WAIT_OBJECT_0), Ok(WaitOutcome::Stop));
    assert_eq!(
        classify_wait_result(WAIT_OBJECT_0 + 1),
        Ok(WaitOutcome::Work)
    );
    assert_eq!(classify_wait_result(WAIT_TIMEOUT), Ok(WaitOutcome::Timeout));
}

#[test]
fn dad_failure_rolls_back_in_reverse_and_cleanup_conflicts_do_not_short_circuit() {
    let order = [
        "ipv6-address",
        "ipv4-address",
        "ipv6-mtu",
        "ipv4-mtu",
        "end-session",
        "adapter",
    ];
    for failed in 0..order.len() {
        let mut cleanup = InjectedSetup {
            ipv4: true,
            ipv6: true,
            fail_at: None,
            cleanup_fail_at: Some(failed),
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            strict_route: false,
            routes: Vec::new(),
            dns: Vec::new(),
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut cleanup).expect("complete setup");
        assert!(cleanup_transaction(&mut cleanup), "cleanup step {failed}");
        assert_eq!(cleanup.cleanup_calls, order, "cleanup step {failed}");
        assert!(cleanup.resources.is_empty(), "cleanup step {failed}");
    }

    let mut cleanup = InjectedSetup {
        ipv4: true,
        ipv6: true,
        fail_at: None,
        cleanup_fail_at: None,
        idle: true,
        calls: Vec::new(),
        resources: Vec::new(),
        notifications: false,
        strict_route: false,
        routes: Vec::new(),
        dns: Vec::new(),
        cleanup_calls: Vec::new(),
    };
    setup_transaction(&mut cleanup).expect("complete setup");
    assert!(!cleanup_transaction(&mut cleanup));
    assert_eq!(cleanup.cleanup_calls, order);

    let journal = SessionJournal::default();
    let wait = journal.begin_wait().expect("first wait");
    assert!(
        journal.begin_wait().is_err(),
        "overlapping waits fail closed"
    );
    let mut overlap = InjectedSetup {
        ipv4: true,
        ipv6: true,
        fail_at: None,
        idle: journal.cleanup_is_safe(),
        calls: Vec::new(),
        cleanup_fail_at: None,
        resources: Vec::new(),
        notifications: false,
        strict_route: false,
        routes: Vec::new(),
        dns: Vec::new(),
        cleanup_calls: Vec::new(),
    };
    setup_transaction(&mut overlap).expect("complete setup");
    assert!(cleanup_transaction(&mut overlap));
    assert!(
        overlap.cleanup_calls.is_empty(),
        "EndSession cannot overlap an active wait"
    );
    drop(wait);
    assert!(journal.cleanup_is_safe());
    overlap.idle = true;
    assert!(!cleanup_transaction(&mut overlap));
    assert_eq!(overlap.cleanup_calls, order);

    let clean = finish_setup_transaction(Err(Error), false, || false).expect_err("DAD failure");
    assert!(!clean.is_cleanup_failure());
    let conflict =
        finish_setup_transaction(Err(Error), false, || true).expect_err("cleanup conflict");
    assert!(conflict.is_cleanup_failure());
    let mut cleanup_called = false;
    finish_setup_transaction(Ok(()), false, || {
        cleanup_called = true;
        false
    })
    .expect("successful setup");
    assert!(!cleanup_called, "successful setup retains the journal");

    let strict = finish_setup_transaction(Err(Error), true, || false)
        .expect_err("strict-route install failure");
    assert!(strict.is_strict_route_install_failure());
    assert!(!strict.is_cleanup_failure());
    let strict_cleanup = finish_setup_transaction(Err(Error), true, || true)
        .expect_err("strict-route install cleanup conflict");
    assert!(strict_cleanup.is_strict_route_install_failure());
    assert!(strict_cleanup.is_cleanup_failure());
}

#[test]
fn managed_route_initializer_and_exact_ownership_are_closed() {
    let low = Ipv4Prefix::new("0.0.0.0".parse().unwrap(), 1).unwrap();
    let high = Ipv4Prefix::new("128.0.0.0".parse().unwrap(), 1).unwrap();
    let luid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: 7 };
    let low = capture_route_row(luid, 11, IpPrefix::V4(low));
    let high = capture_route_row(luid, 11, IpPrefix::V4(high));
    assert!(route_matches(&low, &low));
    assert!(route_matches(&high, &high));
    assert_ne!(
        route_destination(&low).unwrap(),
        route_destination(&high).unwrap()
    );
    let mut mutations = Vec::new();
    for mutate in [
        increment_route_interface_luid,
        |row: &mut MIB_IPFORWARD_ROW2| row.InterfaceIndex += 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.DestinationPrefix.PrefixLength += 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.SitePrefixLength += 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.ValidLifetime -= 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.PreferredLifetime -= 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.Metric += 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.Protocol += 1,
        |row: &mut MIB_IPFORWARD_ROW2| row.Loopback = true,
        |row: &mut MIB_IPFORWARD_ROW2| row.AutoconfigureAddress = true,
        |row: &mut MIB_IPFORWARD_ROW2| row.Publish = true,
        |row: &mut MIB_IPFORWARD_ROW2| row.Immortal = true,
        |row: &mut MIB_IPFORWARD_ROW2| row.Origin += 1,
    ] {
        let mut changed = low;
        mutate(&mut changed);
        mutations.push(changed);
    }
    let mut changed_destination = low;
    set_route_destination(&mut changed_destination, "1.0.0.0".parse().unwrap());
    mutations.push(changed_destination);
    let mut changed_next_hop = low;
    set_route_next_hop(&mut changed_next_hop, "1.0.0.0".parse().unwrap());
    mutations.push(changed_next_hop);
    assert!(
        mutations
            .iter()
            .all(|changed| !route_matches(&low, changed)),
        "every initialized ownership field is mutation-sensitive"
    );

    let ipv6 = capture_route_row(
        luid,
        11,
        IpPrefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32).unwrap()),
    );
    assert!(route_matches(&ipv6, &ipv6));
    assert_eq!(
        route_destination(&ipv6).unwrap(),
        "2001:db8::".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        route_next_hop(&ipv6).unwrap(),
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    );
    let mut changed_ipv6_destination = ipv6;
    set_route_destination(
        &mut changed_ipv6_destination,
        "2001:db8::1".parse().unwrap(),
    );
    let mut changed_ipv6_next_hop = ipv6;
    set_route_next_hop(&mut changed_ipv6_next_hop, "::1".parse().unwrap());
    assert!(!route_matches(&ipv6, &changed_ipv6_destination));
    assert!(!route_matches(&ipv6, &changed_ipv6_next_hop));

    let mut cleanup = InjectedSetup {
        ipv4: true,
        ipv6: true,
        fail_at: None,
        cleanup_fail_at: Some(3),
        idle: true,
        calls: Vec::new(),
        resources: Vec::new(),
        notifications: false,
        strict_route: false,
        routes: Vec::new(),
        dns: Vec::new(),
        cleanup_calls: Vec::new(),
    };
    setup_transaction(&mut cleanup).expect("complete adapter setup");
    cleanup.notifications = true;
    cleanup.strict_route = true;
    cleanup.routes.extend(["low-route", "high-route"]);
    cleanup.dns.extend(["ipv4-dns", "ipv6-dns"]);
    assert!(
        cleanup_transaction(&mut cleanup),
        "cleanup conflicts are surfaced"
    );
    assert_eq!(
        cleanup.cleanup_calls,
        [
            "notifications",
            "strict-route",
            "ipv6-dns",
            "ipv4-dns",
            "high-route",
            "low-route",
            "ipv6-address",
            "ipv4-address",
            "ipv6-mtu",
            "ipv4-mtu",
            "end-session",
            "adapter",
        ],
        "managed cleanup cannot short-circuit reverse ownership order"
    );
    assert!(cleanup.resources.is_empty());
    assert_eq!(low.Metric, 1);
    assert_eq!(low.DestinationPrefix.PrefixLength, 1);
    assert_eq!(
        route_next_hop(&low).unwrap(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    );
}
