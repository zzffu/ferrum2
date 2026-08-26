use super::managed_routes::InjectedRouteCleanup;
use super::support::{
    ERROR_SUCCESS, Error, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_E_FILTER_NOT_FOUND,
    FWP_E_SESSION_ABORTED, FWP_UINT64, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, InterfaceIdentity, IpPrefix,
    ManagedOwnershipLedgerView, ManagedRouteRead, ManagedStateDamage, ManagedTunHealth,
    STRICT_ROUTE_BLOCK_WEIGHT, StrictRouteAction, StrictRouteCondition, StrictRouteLayer,
    StrictRouteOperations, StrictRouteRule, StrictRouteRuleKind, StrictRouteSession, guid_matches,
    managed_device_health, managed_ownership_ledger_exact, managed_state_health,
    strict_route_rules, strict_route_state_matches, wfp_readback_present,
};

#[test]
fn managed_state_health_reports_owned_route_dns_and_strict_route_damage() {
    for readback in [
        ManagedRouteRead::Absent,
        ManagedRouteRead::Present(2),
        ManagedRouteRead::Failed,
    ] {
        let mut routes = InjectedRouteCleanup {
            reads: [readback].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            managed_state_health(&[1], &mut routes, || Ok(true), || Ok(true)).unwrap(),
            ManagedTunHealth::Damaged(ManagedStateDamage::Route)
        );
    }

    let mut healthy_route = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        managed_state_health(&[1], &mut healthy_route, || Ok(false), || Ok(true)).unwrap(),
        ManagedTunHealth::Damaged(ManagedStateDamage::Dns)
    );

    let mut healthy_route = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        managed_state_health(&[1], &mut healthy_route, || Ok(true), || Ok(false)).unwrap(),
        ManagedTunHealth::Damaged(ManagedStateDamage::StrictRoute)
    );

    let mut healthy_route = InjectedRouteCleanup {
        reads: [ManagedRouteRead::Present(1)].into(),
        delete_error: false,
        calls: Vec::new(),
    };
    assert_eq!(
        managed_state_health(&[1], &mut healthy_route, || Ok(true), || Ok(true)).unwrap(),
        ManagedTunHealth::Healthy
    );
}

#[derive(Default)]
struct InjectedStrictRouteState {
    calls: Vec<String>,
    installed: Vec<(u64, StrictRouteRule)>,
    sublayer_present: bool,
    damaged_filter: Option<u64>,
    fail_at: Option<String>,
    close_calls: usize,
}

struct InjectedStrictRoute {
    state: std::rc::Rc<std::cell::RefCell<InjectedStrictRouteState>>,
}

impl InjectedStrictRoute {
    fn step(&self, name: String) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        state.calls.push(name.clone());
        if state.fail_at.as_deref() == Some(name.as_str()) {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

impl StrictRouteOperations for InjectedStrictRoute {
    type Session = u64;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error> {
        self.step("open".into())?;
        Ok(7)
    }

    fn app_id(&mut self) -> Result<Box<[u8]>, Error> {
        self.step("app-id".into())?;
        Ok(Box::from(&b"ferrum2-app"[..]))
    }

    fn begin_transaction(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
        self.step("begin".into())
    }

    fn add_sublayer(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
        self.step("sublayer".into())?;
        self.state.borrow_mut().sublayer_present = true;
        Ok(())
    }

    fn add_filter(
        &mut self,
        _session: &mut Self::Session,
        rule: &StrictRouteRule,
    ) -> Result<u64, Error> {
        let index = self.state.borrow().installed.len();
        self.step(format!("filter-{index}"))?;
        let id = 100 + u64::try_from(index).unwrap();
        self.state.borrow_mut().installed.push((id, rule.clone()));
        Ok(id)
    }

    fn commit_transaction(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
        self.step("commit".into())
    }

    fn abort_transaction(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
        self.step("abort".into())?;
        let mut state = self.state.borrow_mut();
        state.sublayer_present = false;
        state.installed.clear();
        Ok(())
    }

    fn sublayer_matches(&self, _session: &Self::Session) -> Result<bool, Error> {
        self.step("health-sublayer".into())?;
        Ok(self.state.borrow().sublayer_present)
    }

    fn filter_matches(
        &self,
        _session: &Self::Session,
        id: u64,
        rule: &StrictRouteRule,
    ) -> Result<bool, Error> {
        self.step(format!("health-filter-{id}"))?;
        let state = self.state.borrow();
        Ok(state.damaged_filter != Some(id)
            && state
                .installed
                .iter()
                .any(|(current_id, current)| *current_id == id && current == rule))
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        {
            let mut state = self.state.borrow_mut();
            state.close_calls += 1;
        }
        self.step("close".into())?;
        let mut state = self.state.borrow_mut();
        state.sublayer_present = false;
        state.installed.clear();
        *session = 0;
        Ok(())
    }
}

fn injected_strict_route(
    fail_at: Option<&str>,
) -> (
    InjectedStrictRoute,
    std::rc::Rc<std::cell::RefCell<InjectedStrictRouteState>>,
) {
    let state = std::rc::Rc::new(std::cell::RefCell::new(InjectedStrictRouteState {
        fail_at: fail_at.map(str::to_owned),
        ..InjectedStrictRouteState::default()
    }));
    (
        InjectedStrictRoute {
            state: state.clone(),
        },
        state,
    )
}

#[test]
fn strict_route_rule_plan_is_family_and_managed_dns_bounded() {
    let app_id = b"opaque-app-id";
    let luid = 0x1122_3344_5566_7788;
    assert!(guid_matches(
        &StrictRouteLayer::V4.key(),
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    ));
    assert!(guid_matches(
        &StrictRouteLayer::V6.key(),
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ));
    assert_eq!(StrictRouteAction::Permit.raw(), FWP_ACTION_PERMIT);
    assert_eq!(StrictRouteAction::Block.raw(), FWP_ACTION_BLOCK);
    let dual = strict_route_rules(true, true, false, app_id, luid).unwrap();
    assert_eq!(dual.len(), 4);
    assert!(dual.iter().all(|rule| {
        rule.action == StrictRouteAction::Permit && rule.weight > STRICT_ROUTE_BLOCK_WEIGHT
    }));
    assert_eq!(
        dual.iter()
            .filter(|rule| rule.layer == StrictRouteLayer::V4)
            .count(),
        2
    );
    assert_eq!(
        dual.iter()
            .filter(|rule| rule.layer == StrictRouteLayer::V6)
            .count(),
        2
    );
    assert!(dual.iter().any(|rule| {
        rule.kind == StrictRouteRuleKind::TunPermitV4
            && rule.conditions.as_ref() == [StrictRouteCondition::LocalInterfaceLuid(luid)]
    }));
    let luid_condition = StrictRouteCondition::LocalInterfaceLuid(luid);
    assert_eq!(luid_condition.data_type(), FWP_UINT64);
    assert!(guid_matches(
        &luid_condition.field_key(),
        &FWPM_CONDITION_IP_LOCAL_INTERFACE,
    ));
    assert!(dual.iter().any(|rule| {
        rule.kind == StrictRouteRuleKind::AppPermitV6
            && rule.conditions.as_ref() == [StrictRouteCondition::AppId(Box::from(&app_id[..]))]
    }));

    let ipv4_only = strict_route_rules(true, false, false, app_id, luid).unwrap();
    assert_eq!(ipv4_only.len(), 5);
    assert!(ipv4_only.iter().any(|rule| {
        rule.kind == StrictRouteRuleKind::FamilyBlockV6
            && rule.layer == StrictRouteLayer::V6
            && rule.action == StrictRouteAction::Block
            && rule.conditions.is_empty()
    }));
    let ipv6_only = strict_route_rules(false, true, false, app_id, luid).unwrap();
    assert_eq!(ipv6_only.len(), 5);
    assert!(ipv6_only.iter().any(|rule| {
        rule.kind == StrictRouteRuleKind::FamilyBlockV4
            && rule.layer == StrictRouteLayer::V4
            && rule.action == StrictRouteAction::Block
            && rule.conditions.is_empty()
    }));

    let dual_with_dns = strict_route_rules(true, true, true, app_id, luid).unwrap();
    assert_eq!(dual_with_dns.len(), 8);
    let dns = dual_with_dns
        .iter()
        .filter(|rule| {
            matches!(
                rule.kind,
                StrictRouteRuleKind::DnsTcpBlockV4
                    | StrictRouteRuleKind::DnsUdpBlockV4
                    | StrictRouteRuleKind::DnsTcpBlockV6
                    | StrictRouteRuleKind::DnsUdpBlockV6
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(dns.len(), 4);
    assert!(dns.iter().all(|rule| {
        rule.action == StrictRouteAction::Block
            && rule.weight == STRICT_ROUTE_BLOCK_WEIGHT
            && rule
                .conditions
                .contains(&StrictRouteCondition::RemotePort(53))
            && rule
                .conditions
                .iter()
                .any(|condition| matches!(condition, StrictRouteCondition::IpProtocol(6 | 17)))
    }));
    for (kind, layer, protocol) in [
        (StrictRouteRuleKind::DnsTcpBlockV4, StrictRouteLayer::V4, 6),
        (StrictRouteRuleKind::DnsUdpBlockV4, StrictRouteLayer::V4, 17),
        (StrictRouteRuleKind::DnsTcpBlockV6, StrictRouteLayer::V6, 6),
        (StrictRouteRuleKind::DnsUdpBlockV6, StrictRouteLayer::V6, 17),
    ] {
        assert!(dns.iter().any(|rule| {
            rule.kind == kind
                && rule.layer == layer
                && rule.conditions.as_ref()
                    == [
                        StrictRouteCondition::IpProtocol(protocol),
                        StrictRouteCondition::RemotePort(53),
                    ]
        }));
    }
    assert_eq!(
        strict_route_rules(true, false, true, app_id, luid)
            .unwrap()
            .len(),
        9
    );
    assert!(strict_route_rules(false, false, false, app_id, luid).is_err());
    assert!(strict_route_rules(true, false, false, &[], luid).is_err());
    assert!(strict_route_rules(true, false, false, app_id, 0).is_err());
}

#[test]
fn strict_route_transaction_is_atomic_and_raii_closes_the_dynamic_session() {
    assert!(strict_route_state_matches::<InjectedStrictRoute>(false, None).unwrap());
    assert!(!strict_route_state_matches::<InjectedStrictRoute>(true, None).unwrap());
    let (operations, state) = injected_strict_route(None);
    {
        let mut session = StrictRouteSession::open(operations).unwrap();
        session
            .install(true, false, true, 0x1122_3344_5566_7788)
            .unwrap();
        assert!(session.health().unwrap());
        assert!(strict_route_state_matches(true, Some(&session)).unwrap());
        assert!(!strict_route_state_matches(false, Some(&session)).unwrap());
        assert_eq!(state.borrow().installed.len(), 9);
        assert_eq!(state.borrow().close_calls, 0);
    }
    let state = state.borrow();
    assert_eq!(state.close_calls, 1);
    assert_eq!(state.calls.last().map(String::as_str), Some("close"));
    assert!(
        state
            .calls
            .iter()
            .position(|call| call == "commit")
            .unwrap()
            < state
                .calls
                .iter()
                .position(|call| call == "health-sublayer")
                .unwrap()
    );
}

#[test]
fn strict_route_install_failure_aborts_then_dynamic_close_removes_partial_state() {
    for failure in ["sublayer", "filter-3", "commit"] {
        let (operations, state) = injected_strict_route(Some(failure));
        {
            let mut session = StrictRouteSession::open(operations).unwrap();
            assert!(session.install(true, false, true, 7).is_err(), "{failure}");
        }
        let state = state.borrow();
        let failure_position = state.calls.iter().position(|call| call == failure).unwrap();
        let abort_position = state.calls.iter().position(|call| call == "abort").unwrap();
        let close_position = state.calls.iter().position(|call| call == "close").unwrap();
        assert!(failure_position < abort_position && abort_position < close_position);
        assert_eq!(state.close_calls, 1);
        assert!(state.installed.is_empty());
    }
}

#[test]
fn strict_route_failed_explicit_close_is_retained_for_raii_retry() {
    let (operations, state) = injected_strict_route(Some("close"));
    let mut session = StrictRouteSession::open(operations).unwrap();
    session.install(true, true, false, 7).unwrap();
    assert!(session.close().is_err());
    state.borrow_mut().fail_at = None;
    drop(session);
    assert_eq!(state.borrow().close_calls, 2);
    assert!(state.borrow().installed.is_empty());
    assert_eq!(
        state
            .borrow()
            .calls
            .iter()
            .filter(|call| call.as_str() == "close")
            .count(),
        2
    );
}

#[test]
fn strict_route_health_reads_every_exact_filter_id_and_rejects_damage() {
    let (operations, state) = injected_strict_route(None);
    let mut session = StrictRouteSession::open(operations).unwrap();
    session.install(true, true, false, 7).unwrap();
    assert!(session.health().unwrap());
    let expected_ids = state
        .borrow()
        .installed
        .iter()
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    for id in &expected_ids {
        assert!(
            state
                .borrow()
                .calls
                .contains(&format!("health-filter-{id}"))
        );
    }
    state.borrow_mut().damaged_filter = expected_ids.get(2).copied();
    assert!(!session.health().unwrap());
    {
        let mut state = state.borrow_mut();
        state.damaged_filter = None;
        state.installed[2].1.weight = STRICT_ROUTE_BLOCK_WEIGHT;
    }
    assert!(!session.health().unwrap());
}

#[test]
fn strict_route_readback_classifies_missing_and_aborted_sessions_as_damage() {
    assert!(wfp_readback_present(ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND).unwrap());
    assert!(!wfp_readback_present(FWP_E_FILTER_NOT_FOUND as u32, FWP_E_FILTER_NOT_FOUND,).unwrap());
    assert!(!wfp_readback_present(FWP_E_SESSION_ABORTED as u32, FWP_E_FILTER_NOT_FOUND,).unwrap());
    assert!(wfp_readback_present(0xdead_beef, FWP_E_FILTER_NOT_FOUND).is_err());
}

#[test]
fn managed_device_health_is_closed_and_checks_owned_state_in_order() {
    use std::cell::Cell;

    for (name, adapter, session, address_ledger, identity, addresses, expected) in [
        (
            "adapter handle",
            false,
            true,
            true,
            true,
            true,
            ManagedStateDamage::Adapter,
        ),
        (
            "interface identity",
            true,
            true,
            true,
            false,
            true,
            ManagedStateDamage::Adapter,
        ),
        (
            "device session",
            true,
            false,
            true,
            true,
            true,
            ManagedStateDamage::Session,
        ),
        (
            "address ledger",
            true,
            true,
            false,
            true,
            true,
            ManagedStateDamage::OwnershipLedger,
        ),
        (
            "address readback",
            true,
            true,
            true,
            true,
            false,
            ManagedStateDamage::Address,
        ),
    ] {
        assert_eq!(
            managed_device_health(adapter, session, address_ledger, || identity, || addresses,),
            ManagedTunHealth::Damaged(expected),
            "{name}"
        );
    }

    assert_eq!(
        managed_device_health(true, true, true, || true, || true),
        ManagedTunHealth::Healthy
    );

    let identity_calls = Cell::new(0);
    let address_calls = Cell::new(0);
    assert_eq!(
        managed_device_health(
            false,
            true,
            true,
            || {
                identity_calls.set(identity_calls.get() + 1);
                true
            },
            || {
                address_calls.set(address_calls.get() + 1);
                true
            },
        ),
        ManagedTunHealth::Damaged(ManagedStateDamage::Adapter)
    );
    assert_eq!(identity_calls.get(), 0);
    assert_eq!(address_calls.get(), 0);
}

#[test]
fn ownership_ledger_damage_is_constructible_from_every_managed_owner_family() {
    let capture = [IpPrefix::V4(
        crate::Ipv4Prefix::new("198.18.0.0".parse().unwrap(), 30).unwrap(),
    )];
    let other_capture = [IpPrefix::V4(
        crate::Ipv4Prefix::new("198.18.1.0".parse().unwrap(), 30).unwrap(),
    )];
    let dns = "198.18.0.1".parse().unwrap();
    let config =
        crate::ManagedNetworkConfig::new(capture.to_vec(), Vec::new(), false, Some(dns), None)
            .unwrap()
            .with_strict_route(true);
    let owned = InterfaceIdentity { luid: 7, index: 17 };
    let healthy = ManagedOwnershipLedgerView {
        capture_routes: &capture,
        pending_route: false,
        route_count: 1,
        ipv4_dns_address: Some(dns),
        ipv6_dns_address: None,
        dns_interface: true,
        ipv4_dns_lease: true,
        ipv6_dns_lease: false,
        strict_route_intent: true,
        strict_route_session: true,
    };
    let exact = |state| {
        managed_ownership_ledger_exact(Some(&config), state, false, 1, 1, Some(owned), owned)
    };
    assert!(exact(Some(healthy)));
    assert!(
        !exact(None),
        "configured managed state cannot lose its journal"
    );
    assert!(!managed_ownership_ledger_exact(
        None,
        Some(healthy),
        false,
        1,
        1,
        Some(owned),
        owned,
    ));
    assert!(!managed_ownership_ledger_exact(
        Some(&config),
        Some(healthy),
        true,
        1,
        1,
        Some(owned),
        owned,
    ));
    assert!(!managed_ownership_ledger_exact(
        Some(&config),
        Some(healthy),
        false,
        0,
        1,
        Some(owned),
        owned,
    ));
    assert!(!managed_ownership_ledger_exact(
        Some(&config),
        Some(healthy),
        false,
        1,
        1,
        None,
        owned,
    ));

    for damaged in [
        ManagedOwnershipLedgerView {
            capture_routes: &other_capture,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            pending_route: true,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            route_count: 0,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            ipv4_dns_address: None,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            dns_interface: false,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            ipv4_dns_lease: false,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            strict_route_intent: false,
            ..healthy
        },
        ManagedOwnershipLedgerView {
            strict_route_session: false,
            ..healthy
        },
    ] {
        assert!(!exact(Some(damaged)));
    }
}
