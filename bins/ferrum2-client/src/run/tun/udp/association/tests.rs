use super::{DatagramAction, OrdinaryTerminal, SyntheticDns, datagram_action};

fn synthetic_dns() -> SyntheticDns {
    SyntheticDns {
        ipv4: Some("198.18.0.1".parse().unwrap()),
        ipv6: Some("fd00::1".parse().unwrap()),
    }
}

#[test]
fn frozen_reject_answers_only_exact_synthetic_queries_in_both_families() {
    let terminal = OrdinaryTerminal::Reject;
    let observed = [
        "192.0.2.1:443",
        "198.18.0.1:53",
        "198.18.0.1:54",
        "198.18.0.2:53",
        "[2001:db8::1]:443",
        "[fd00::1]:53",
        "[fd00::1]:54",
        "[fd00::2]:53",
        "192.0.2.1:443",
    ]
    .map(|target| datagram_action(synthetic_dns(), target.parse().unwrap(), Some(&terminal)));
    assert_eq!(
        observed,
        [
            DatagramAction::Reject,
            DatagramAction::Dns,
            DatagramAction::Reject,
            DatagramAction::Reject,
            DatagramAction::Reject,
            DatagramAction::Dns,
            DatagramAction::Reject,
            DatagramAction::Reject,
            DatagramAction::Reject,
        ]
    );
    assert!(matches!(terminal, OrdinaryTerminal::Reject));
}

#[test]
fn synthetic_first_keeps_ordinary_unselected_then_reject_stays_frozen() {
    let dns = synthetic_dns();
    for target in ["198.18.0.1:53", "[fd00::1]:53"] {
        assert_eq!(
            datagram_action(dns, target.parse().unwrap(), None),
            DatagramAction::Dns
        );
    }
    assert_eq!(
        datagram_action(dns, "192.0.2.1:443".parse().unwrap(), None),
        DatagramAction::SelectOrdinary
    );
    let frozen = OrdinaryTerminal::Reject;
    for target in ["198.18.0.1:53", "[fd00::1]:53"] {
        assert_eq!(
            datagram_action(dns, target.parse().unwrap(), Some(&frozen)),
            DatagramAction::Dns
        );
    }
    assert_eq!(
        datagram_action(dns, "192.0.2.2:53".parse().unwrap(), Some(&frozen)),
        DatagramAction::Reject
    );
    assert!(matches!(frozen, OrdinaryTerminal::Reject));
}

#[test]
fn frozen_hijack_and_missing_synthetic_family_do_not_reselect_ordinary_policy() {
    let terminal = OrdinaryTerminal::HijackDns;
    for target in ["192.0.2.1:443", "198.18.0.1:53", "[fd00::1]:53"] {
        assert_eq!(
            datagram_action(synthetic_dns(), target.parse().unwrap(), Some(&terminal)),
            DatagramAction::Dns
        );
    }
    let ipv4_only = SyntheticDns {
        ipv6: None,
        ..synthetic_dns()
    };
    assert_eq!(
        datagram_action(ipv4_only, "[fd00::1]:53".parse().unwrap(), None),
        DatagramAction::SelectOrdinary
    );
    assert_eq!(
        datagram_action(
            ipv4_only,
            "[fd00::1]:53".parse().unwrap(),
            Some(&OrdinaryTerminal::Reject)
        ),
        DatagramAction::Reject
    );
}
