use std::cell::RefCell;
use std::rc::Rc;

use super::support::{
    Error, ErrorKind, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWP_UINT64, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, Ipv4Prefix, Ipv6Prefix, TCP_INGRESS_FILTER_WEIGHT,
    TCP_PROTOCOL, TcpIngressCondition, TcpIngressEndpoint, TcpIngressLayer, TcpIngressOperations,
    TcpIngressRule, TcpIngressSession, guid_matches, tcp_ingress_rules,
    validate_tcp_ingress_addresses,
};

#[derive(Default)]
struct InjectedState {
    calls: Vec<String>,
    installed: Vec<(u64, TcpIngressRule)>,
    sublayer_present: bool,
    damaged_identity: Option<u64>,
    fail_at: Option<String>,
    abort_fails: bool,
    close_calls: usize,
}

struct InjectedOperations(Rc<RefCell<InjectedState>>);

impl InjectedOperations {
    fn step(&self, name: String) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        state.calls.push(name.clone());
        if state.fail_at.as_deref() == Some(name.as_str()) {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

impl TcpIngressOperations for InjectedOperations {
    type Session = u64;
    type FilterIdentity = u64;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error> {
        self.step("open".into())?;
        Ok(7)
    }

    fn app_id(&mut self) -> Result<Box<[u8]>, Error> {
        self.step("app-id".into())?;
        Ok(Box::from(&b"ferrum2-app"[..]))
    }

    fn begin_transaction(&mut self, _: &mut Self::Session) -> Result<(), Error> {
        self.step("begin".into())
    }

    fn add_sublayer(&mut self, _: &mut Self::Session) -> Result<(), Error> {
        self.step("sublayer".into())?;
        self.0.borrow_mut().sublayer_present = true;
        Ok(())
    }

    fn add_filter(
        &mut self,
        _: &mut Self::Session,
        rule: &TcpIngressRule,
    ) -> Result<Self::FilterIdentity, Error> {
        let index = self.0.borrow().installed.len();
        self.step(format!("filter-{index}"))?;
        let identity = 100 + u64::try_from(index).unwrap();
        self.0.borrow_mut().installed.push((identity, rule.clone()));
        Ok(identity)
    }

    fn commit_transaction(&mut self, _: &mut Self::Session) -> Result<(), Error> {
        self.step("commit".into())
    }
    fn abort_transaction(&mut self, _: &mut Self::Session) -> Result<(), Error> {
        self.step("abort".into())?;
        if self.0.borrow().abort_fails {
            return Err(Error);
        }
        let mut state = self.0.borrow_mut();
        state.sublayer_present = false;
        state.installed.clear();
        Ok(())
    }

    fn sublayer_matches(&self, _: &Self::Session) -> Result<bool, Error> {
        self.step("verify-sublayer".into())?;
        Ok(self.0.borrow().sublayer_present)
    }

    fn filter_matches(
        &self,
        _: &Self::Session,
        identity: &Self::FilterIdentity,
        rule: &TcpIngressRule,
    ) -> Result<bool, Error> {
        self.step(format!("verify-filter-{identity}"))?;
        let state = self.0.borrow();
        Ok(state.damaged_identity != Some(*identity)
            && state
                .installed
                .iter()
                .any(|(current_identity, current)| current_identity == identity && current == rule))
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        self.0.borrow_mut().close_calls += 1;
        self.step("close".into())?;
        let mut state = self.0.borrow_mut();
        state.sublayer_present = false;
        state.installed.clear();
        *session = 0;
        Ok(())
    }
}

fn endpoints() -> [TcpIngressEndpoint; 2] {
    [
        TcpIngressEndpoint::new(
            "198.18.0.2:41001".parse().unwrap(),
            "198.18.0.1".parse().unwrap(),
        )
        .unwrap(),
        TcpIngressEndpoint::new(
            "[fd00::2]:41002".parse().unwrap(),
            "fd00::1".parse().unwrap(),
        )
        .unwrap(),
    ]
}

fn injected(fail_at: Option<&str>) -> (InjectedOperations, Rc<RefCell<InjectedState>>) {
    let state = Rc::new(RefCell::new(InjectedState {
        fail_at: fail_at.map(str::to_owned),
        ..InjectedState::default()
    }));
    (InjectedOperations(state.clone()), state)
}

#[test]
fn tcp_ingress_rule_plan_is_exact_family_bounded_and_tcp_only() {
    let endpoints = endpoints();
    let app_id = b"opaque-app-id";
    let luid = 0x1122_3344_5566_7788;
    assert!(guid_matches(
        &TcpIngressLayer::V4.key(),
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    ));
    assert!(guid_matches(
        &TcpIngressLayer::V6.key(),
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ));
    for (condition, field, data_type) in [
        (
            TcpIngressCondition::AppId(Box::from(&app_id[..])),
            FWPM_CONDITION_ALE_APP_ID,
            FWP_BYTE_BLOB_TYPE,
        ),
        (
            TcpIngressCondition::LocalInterfaceLuid(luid),
            FWPM_CONDITION_IP_LOCAL_INTERFACE,
            FWP_UINT64,
        ),
        (
            TcpIngressCondition::IpProtocol(TCP_PROTOCOL),
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_UINT8,
        ),
        (
            TcpIngressCondition::LocalAddress(endpoints[0].local().ip()),
            FWPM_CONDITION_IP_LOCAL_ADDRESS,
            FWP_UINT32,
        ),
        (
            TcpIngressCondition::LocalPort(endpoints[0].local().port()),
            FWPM_CONDITION_IP_LOCAL_PORT,
            FWP_UINT16,
        ),
        (
            TcpIngressCondition::RemoteAddress(endpoints[0].peer()),
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_UINT32,
        ),
        (
            TcpIngressCondition::RemoteAddress(endpoints[1].peer()),
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_BYTE_ARRAY16_TYPE,
        ),
    ] {
        assert!(guid_matches(&condition.field_key(), &field));
        assert_eq!(condition.data_type(), data_type);
    }
    let rules = tcp_ingress_rules(&endpoints, app_id, luid).unwrap();
    assert_eq!(rules.len(), 2);
    for ((rule, endpoint), layer) in rules
        .iter()
        .zip(endpoints)
        .zip([TcpIngressLayer::V4, TcpIngressLayer::V6])
    {
        assert_eq!(rule.layer, layer);
        assert_eq!(rule.weight, TCP_INGRESS_FILTER_WEIGHT);
        assert_eq!(
            rule.conditions.as_ref(),
            [
                TcpIngressCondition::AppId(Box::from(&app_id[..])),
                TcpIngressCondition::LocalInterfaceLuid(luid),
                TcpIngressCondition::IpProtocol(TCP_PROTOCOL),
                TcpIngressCondition::LocalAddress(endpoint.local().ip()),
                TcpIngressCondition::LocalPort(endpoint.local().port()),
                TcpIngressCondition::RemoteAddress(endpoint.peer()),
            ]
        );
    }

    assert!(tcp_ingress_rules(&[], app_id, luid).is_err());
    assert!(tcp_ingress_rules(&endpoints, &[], luid).is_err());
    assert!(tcp_ingress_rules(&endpoints, app_id, 0).is_err());
    assert!(tcp_ingress_rules(&[endpoints[0], endpoints[0]], app_id, luid).is_err());
    assert!(
        TcpIngressEndpoint::new("0.0.0.0:1".parse().unwrap(), "198.18.0.1".parse().unwrap())
            .is_err()
    );
    assert!(
        TcpIngressEndpoint::new(
            "198.18.0.2:0".parse().unwrap(),
            "198.18.0.1".parse().unwrap()
        )
        .is_err()
    );
    assert!(
        TcpIngressEndpoint::new("198.18.0.2:1".parse().unwrap(), "fd00::1".parse().unwrap())
            .is_err()
    );
}

#[test]
fn tcp_ingress_addresses_are_exactly_bound_to_owned_prefixes() {
    let endpoints = endpoints();
    let ipv4 = Ipv4Prefix::new("198.18.0.2".parse().unwrap(), 30).unwrap();
    let ipv6 = Ipv6Prefix::new("fd00::2".parse().unwrap(), 126).unwrap();
    assert!(validate_tcp_ingress_addresses(&endpoints, Some(ipv4), Some(ipv6)).is_ok());
    assert!(validate_tcp_ingress_addresses(&endpoints[..1], Some(ipv4), None).is_ok());
    assert!(validate_tcp_ingress_addresses(&endpoints[..1], Some(ipv4), Some(ipv6)).is_err());

    for (local, peer) in [
        ("198.18.0.3:41001", "198.18.0.1"),
        ("198.18.0.2:41001", "198.18.0.2"),
        ("198.18.0.2:41001", "198.18.0.0"),
        ("198.18.0.2:41001", "198.18.0.3"),
        ("198.18.0.2:41001", "198.18.0.5"),
    ] {
        let endpoint = TcpIngressEndpoint::new(local.parse().unwrap(), peer.parse().unwrap())
            .expect("individually well-formed endpoint");
        assert!(
            validate_tcp_ingress_addresses(&[endpoint], Some(ipv4), None).is_err(),
            "{local} {peer}"
        );
    }
    for (local, peer) in [
        ("[fd00::3]:41002", "fd00::1"),
        ("[fd00::2]:41002", "fd00::2"),
        ("[fd00::2]:41002", "fd00::"),
        ("[fd00::2]:41002", "fd00::5"),
    ] {
        let endpoint = TcpIngressEndpoint::new(local.parse().unwrap(), peer.parse().unwrap())
            .expect("individually well-formed endpoint");
        assert!(
            validate_tcp_ingress_addresses(&[endpoint], None, Some(ipv6)).is_err(),
            "{local} {peer}"
        );
    }
}

#[test]
fn tcp_ingress_install_aborts_every_partial_transaction_then_closes_session() {
    for failure in ["sublayer", "filter-1", "commit"] {
        let (operations, state) = injected(Some(failure));
        {
            let mut session = TcpIngressSession::open(operations).unwrap();
            assert!(session.install(&endpoints(), 7).is_err(), "{failure}");
        }
        let state = state.borrow();
        let failed = state.calls.iter().position(|call| call == failure).unwrap();
        let abort = state.calls.iter().position(|call| call == "abort").unwrap();
        let close = state.calls.iter().position(|call| call == "close").unwrap();
        assert!(failed < abort && abort < close, "{failure}");
        assert!(state.installed.is_empty(), "{failure}");
        assert_eq!(state.close_calls, 1, "{failure}");
    }
}

#[test]
fn tcp_ingress_install_and_health_require_exact_identity_and_conditions() {
    let (operations, state) = injected(None);
    let mut session = TcpIngressSession::open(operations).unwrap();
    session.install(&endpoints(), 7).unwrap();
    assert!(session.health().unwrap());
    assert_eq!(state.borrow().installed.len(), 2);

    state.borrow_mut().damaged_identity = Some(100);
    assert!(!session.health().unwrap());
    state.borrow_mut().damaged_identity = None;
    state.borrow_mut().installed[0].1.conditions[4] = TcpIngressCondition::LocalPort(9);
    assert!(!session.health().unwrap());
}

#[test]
fn tcp_ingress_abort_failure_is_cleanup_integrity_failure_and_close_retries() {
    let (operations, state) = injected(Some("filter-1"));
    state.borrow_mut().abort_fails = true;
    {
        let mut session = TcpIngressSession::open(operations).unwrap();
        assert_eq!(
            session.install(&endpoints(), 7).unwrap_err().kind(),
            ErrorKind::Cleanup
        );
    }
    assert_eq!(state.borrow().close_calls, 1);
    assert!(state.borrow().installed.is_empty());
}

#[test]
fn tcp_ingress_failed_explicit_close_retains_owner_for_raii_retry() {
    let (operations, state) = injected(None);
    let mut session = TcpIngressSession::open(operations).unwrap();
    session.install(&endpoints(), 7).unwrap();
    state.borrow_mut().fail_at = Some("close".into());
    assert!(session.close().is_err());
    state.borrow_mut().fail_at = None;
    drop(session);
    assert_eq!(state.borrow().close_calls, 2);
    assert!(state.borrow().installed.is_empty());
}
