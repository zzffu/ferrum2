use ferrum2_core::route::{
    Network, OrderedRouteProgram, OrderedRouteRule, PortRange, RouteMatchField, RouteMatcher,
    RouteMetadata, RouteProgramAction, RouteRuleAction,
};
use ferrum2_core::{DomainName, TargetAddr};
use ipnet::IpNet;
use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;

#[test]
fn matched_non_terminal_resumes_at_later_rule_then_terminal_stops() {
    let program = OrderedRouteProgram::new(
        vec![
            OrderedRouteRule::new(
                RouteMatcher::new(Vec::new()).expect("unconditional matcher"),
                RouteRuleAction::Continue("inspect"),
            ),
            OrderedRouteRule::new(
                RouteMatcher::new(vec![RouteMatchField::Protocol(vec!["recognized"])])
                    .expect("protocol matcher"),
                RouteRuleAction::Terminal("selected"),
            ),
            OrderedRouteRule::new(
                RouteMatcher::new(Vec::new()).expect("unconditional matcher"),
                RouteRuleAction::Terminal("late"),
            ),
        ],
        "final",
    )
    .expect("bounded program");
    let target = TargetAddr::domain("original.test", 443).expect("target");
    let mut evaluation = program.evaluate(7, Network::Tcp, &target);

    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(&"inspect"))
    );
    assert_eq!(
        evaluation.next(RouteMetadata::new(Some("recognized"), None)),
        Some(RouteProgramAction::Terminal(&"selected"))
    );
    assert_eq!(evaluation.next(RouteMetadata::new(None, None)), None);

    let continuation = OrderedRouteProgram::new(
        vec![OrderedRouteRule::new(
            RouteMatcher::new(Vec::new()).unwrap(),
            RouteRuleAction::Continue("inspect"),
        )],
        "mandatory final",
    )
    .unwrap();
    for outcome in ["unknown", "invalid", "timeout", "limit"] {
        let mut evaluation = continuation.evaluate(7, Network::Tcp, &target);
        assert!(matches!(
            evaluation.next(RouteMetadata::new(None::<&str>, None)),
            Some(RouteProgramAction::Continue(action)) if *action == "inspect"
        ));
        assert!(
            matches!(
                evaluation.next(RouteMetadata::new(None, None)),
                Some(RouteProgramAction::Final(action)) if *action == "mandatory final"
            ),
            "{outcome} metadata must continue to final"
        );
    }

    for terminal in ["route", "reject", "hijack"] {
        let program = OrderedRouteProgram::new(
            vec![OrderedRouteRule::new(
                RouteMatcher::new(Vec::new()).unwrap(),
                RouteRuleAction::Terminal(terminal),
            )],
            "unreachable final",
        )
        .unwrap();
        let mut evaluation = program.evaluate(7, Network::Tcp, &target);
        assert!(matches!(
            evaluation.next(RouteMetadata::new(None::<&str>, None)),
            Some(RouteProgramAction::Terminal(actual)) if *actual == terminal
        ));
        assert!(evaluation.next(RouteMetadata::new(None, None)).is_none());
    }
}

#[test]
fn domain_matchers_normalize_and_prefer_sniffed_metadata_without_replacing_original() {
    let cases = [
        (
            "exact original ignores ASCII case and one terminal dot",
            RouteMatchField::Domain(vec![DomainName::new("example.test").unwrap()]),
            TargetAddr::domain("EXAMPLE.TEST.", 443).unwrap(),
            None,
            true,
        ),
        (
            "suffix honors a label boundary",
            RouteMatchField::DomainSuffix(vec![DomainName::new("example.test.").unwrap()]),
            TargetAddr::domain("www.Example.Test", 443).unwrap(),
            None,
            true,
        ),
        (
            "suffix rejects a partial label",
            RouteMatchField::DomainSuffix(vec![DomainName::new("example.test").unwrap()]),
            TargetAddr::domain("notexample.test", 443).unwrap(),
            None,
            false,
        ),
        (
            "sniffed domain takes precedence",
            RouteMatchField::Domain(vec![DomainName::new("original.test").unwrap()]),
            TargetAddr::domain("original.test", 443).unwrap(),
            Some(DomainName::new("detected.test").unwrap()),
            false,
        ),
        (
            "sniffed domain can satisfy a matcher",
            RouteMatchField::Domain(vec![DomainName::new("detected.test.").unwrap()]),
            TargetAddr::domain("original.test", 443).unwrap(),
            Some(DomainName::new("DETECTED.TEST").unwrap()),
            true,
        ),
        (
            "sniffed domain can satisfy a matcher for an original IP target",
            RouteMatchField::Domain(vec![DomainName::new("detected.test").unwrap()]),
            TargetAddr::ip("192.0.2.9:443".parse::<SocketAddr>().unwrap()).unwrap(),
            Some(DomainName::new("DETECTED.TEST.").unwrap()),
            true,
        ),
    ];

    for (name, field, target, sniffed, expected) in cases {
        let program = OrderedRouteProgram::new(
            vec![OrderedRouteRule::new(
                RouteMatcher::new(vec![field]).unwrap(),
                RouteRuleAction::Terminal(true),
            )],
            false,
        )
        .unwrap();
        let mut evaluation = program.evaluate(0, Network::Tcp, &target);
        let actual = matches!(
            evaluation.next(RouteMetadata::new(None::<&str>, sniffed.as_ref())),
            Some(RouteProgramAction::Terminal(true))
        );
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn address_port_legacy_and_conjunctive_matchers_use_only_the_original_target() {
    let cases = [
        (
            "IPv4 exact",
            RouteMatchField::Ip(vec!["192.0.2.9".parse::<IpAddr>().unwrap()]),
            TargetAddr::ip("192.0.2.9:443".parse::<SocketAddr>().unwrap()).unwrap(),
            None,
            true,
        ),
        (
            "IPv6 exact",
            RouteMatchField::Ip(vec!["2001:db8::9".parse::<IpAddr>().unwrap()]),
            TargetAddr::ip("[2001:db8::9]:443".parse::<SocketAddr>().unwrap()).unwrap(),
            None,
            true,
        ),
        (
            "IPv4 CIDR includes its network boundary",
            RouteMatchField::Cidr(vec!["192.0.2.0/24".parse::<IpNet>().unwrap()]),
            TargetAddr::ip("192.0.2.0:443".parse::<SocketAddr>().unwrap()).unwrap(),
            None,
            true,
        ),
        (
            "IPv6 CIDR upper boundary",
            RouteMatchField::Cidr(vec!["2001:db8::/126".parse::<IpNet>().unwrap()]),
            TargetAddr::ip("[2001:db8::3]:443".parse::<SocketAddr>().unwrap()).unwrap(),
            None,
            true,
        ),
        (
            "IPv4 outside CIDR",
            RouteMatchField::Cidr(vec!["192.0.2.0/24".parse::<IpNet>().unwrap()]),
            TargetAddr::ip("192.0.3.0:443".parse::<SocketAddr>().unwrap()).unwrap(),
            None,
            false,
        ),
        (
            "domain never matches an IP field",
            RouteMatchField::Ip(vec!["192.0.2.9".parse::<IpAddr>().unwrap()]),
            TargetAddr::domain("192.0.2.9", 443).unwrap(),
            Some(DomainName::new("192.0.2.9").unwrap()),
            false,
        ),
        (
            "exact port",
            RouteMatchField::Port(vec![NonZeroU16::new(443).unwrap()]),
            TargetAddr::domain("port.test", 443).unwrap(),
            None,
            true,
        ),
        (
            "inclusive port-range boundary",
            RouteMatchField::PortRange(vec![PortRange::new(1000, 2000).unwrap()]),
            TargetAddr::domain("port.test", 2000).unwrap(),
            None,
            true,
        ),
        (
            "inclusive port-range lower boundary",
            RouteMatchField::PortRange(vec![PortRange::new(1000, 2000).unwrap()]),
            TargetAddr::domain("port.test", 1000).unwrap(),
            None,
            true,
        ),
        (
            "legacy target ignores sniffed metadata",
            RouteMatchField::Target(vec![TargetAddr::domain("ORIGINAL.TEST", 443).unwrap()]),
            TargetAddr::domain("original.test", 443).unwrap(),
            Some(DomainName::new("detected.test").unwrap()),
            true,
        ),
        (
            "legacy target preserves terminal-dot identity",
            RouteMatchField::Target(vec![TargetAddr::domain("original.test.", 443).unwrap()]),
            TargetAddr::domain("original.test", 443).unwrap(),
            None,
            false,
        ),
    ];

    for (name, field, target, sniffed, expected) in cases {
        let program = OrderedRouteProgram::new(
            vec![OrderedRouteRule::new(
                RouteMatcher::new(vec![field]).unwrap(),
                RouteRuleAction::Terminal(true),
            )],
            false,
        )
        .unwrap();
        let mut evaluation = program.evaluate(0, Network::Tcp, &target);
        let actual = matches!(
            evaluation.next(RouteMetadata::new(None::<&str>, sniffed.as_ref())),
            Some(RouteProgramAction::Terminal(true))
        );
        assert_eq!(actual, expected, "{name}");
    }

    for (name, inbound, network, target, expected) in [
        (
            "all fields and second values match",
            7,
            Network::Udp,
            TargetAddr::domain("api.example.test", 5353).unwrap(),
            true,
        ),
        (
            "different fields are ANDed",
            7,
            Network::Tcp,
            TargetAddr::domain("api.example.test", 5353).unwrap(),
            false,
        ),
        (
            "values within a field are ORed",
            1,
            Network::Udp,
            TargetAddr::domain("example.test", 53).unwrap(),
            true,
        ),
        (
            "one failed field rejects",
            1,
            Network::Udp,
            TargetAddr::domain("example.test", 54).unwrap(),
            false,
        ),
    ] {
        let matcher = RouteMatcher::new(vec![
            RouteMatchField::Inbound(vec![1, 7]),
            RouteMatchField::Network(vec![Network::Udp]),
            RouteMatchField::DomainSuffix(vec![DomainName::new("example.test").unwrap()]),
            RouteMatchField::Port(vec![
                NonZeroU16::new(53).unwrap(),
                NonZeroU16::new(5353).unwrap(),
            ]),
        ])
        .unwrap();
        let program = OrderedRouteProgram::new(
            vec![OrderedRouteRule::new(
                matcher,
                RouteRuleAction::Terminal(true),
            )],
            false,
        )
        .unwrap();
        let mut evaluation = program.evaluate(inbound, network, &target);
        let actual = matches!(
            evaluation.next(RouteMetadata::new(None::<&str>, None)),
            Some(RouteProgramAction::Terminal(true))
        );
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn public_bounds_limit_rules_values_and_monotonic_visits() {
    struct Probe<'a> {
        value: u8,
        visits: &'a Cell<usize>,
    }

    impl PartialEq for Probe<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.visits.set(self.visits.get() + 1);
            self.value == other.value
        }
    }
    impl Eq for Probe<'_> {}

    let visits = Cell::new(0);
    let rules = (0..64)
        .map(|value| {
            OrderedRouteRule::new(
                RouteMatcher::new(vec![RouteMatchField::Protocol(vec![Probe {
                    value,
                    visits: &visits,
                }])])
                .unwrap(),
                RouteRuleAction::Terminal(String::from("unexpected")),
            )
        })
        .collect();
    let program = OrderedRouteProgram::new(rules, String::from("mandatory final")).unwrap();
    let target = TargetAddr::domain("bounded.test", 443).unwrap();
    let mut evaluation = program.evaluate(0, Network::Tcp, &target);
    assert!(matches!(
        evaluation.next(RouteMetadata::new(
            Some(Probe {
                value: 255,
                visits: &visits,
            }),
            None,
        )),
        Some(RouteProgramAction::Final(action)) if action == "mandatory final"
    ));
    assert_eq!(visits.get(), 64);
    assert_eq!(evaluation.next(RouteMetadata::new(None, None)), None);
    assert_eq!(visits.get(), 64, "finished evaluation restarted");

    let oversized_rules = (0..65)
        .map(|_| {
            OrderedRouteRule::new(
                RouteMatcher::<()>::new(Vec::new()).unwrap(),
                RouteRuleAction::Terminal(()),
            )
        })
        .collect();
    assert!(OrderedRouteProgram::new(oversized_rules, ()).is_none());
    assert!(
        RouteMatcher::<()>::new(vec![
            RouteMatchField::Inbound((0..63).collect()),
            RouteMatchField::Network(vec![Network::Tcp]),
        ])
        .is_some()
    );
    assert!(
        RouteMatcher::<()>::new(vec![
            RouteMatchField::Inbound((0..64).collect()),
            RouteMatchField::Network(vec![Network::Tcp]),
        ])
        .is_none()
    );
    assert!(RouteMatcher::<()>::new(vec![RouteMatchField::Inbound(Vec::new())]).is_none());
    assert!(
        RouteMatcher::<()>::new(vec![
            RouteMatchField::Inbound(vec![1]),
            RouteMatchField::Inbound(vec![2]),
        ])
        .is_none()
    );
    assert!(RouteMatcher::<()>::new(vec![RouteMatchField::Inbound(vec![1, 1])]).is_none());
    assert!(
        RouteMatcher::<()>::new(vec![RouteMatchField::Domain(vec![
            DomainName::new("Example.Test").unwrap(),
            DomainName::new("example.test.").unwrap(),
        ])])
        .is_none()
    );
    assert!(
        RouteMatcher::<()>::new(vec![RouteMatchField::Target(vec![
            TargetAddr::domain("Example.Test", 443).unwrap(),
            TargetAddr::domain("example.test", 443).unwrap(),
        ])])
        .is_none()
    );
    assert!(
        RouteMatcher::<()>::new(vec![
            RouteMatchField::Target(vec![TargetAddr::domain("legacy.test", 443).unwrap()]),
            RouteMatchField::Port(vec![NonZeroU16::new(443).unwrap()]),
        ])
        .is_none()
    );
    assert!(
        RouteMatcher::<()>::new(vec![RouteMatchField::Cidr(vec![
            "192.0.2.1/24".parse::<IpNet>().unwrap(),
        ])])
        .is_none()
    );
    assert!(PortRange::new(0, 1).is_none());
    assert!(PortRange::new(2, 1).is_none());
}
