use std::sync::{Arc, Barrier};
use std::thread;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::{
    ActionRule, ActionTable, Network, compile_selector_plans, compile_selector_route,
};
use ferrum2_core::selector::{
    SelectorControl, SelectorDefinition, SelectorError, TaggedInbound, TaggedOutbound, TaggedPlan,
    TaggedRoute, TaggedRouteRule, TaggedStaticBinding,
};

fn nested_route() -> (ferrum2_core::route::RouteTable, SelectorControl) {
    compile_selector_route(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("leaf-a", 7),
            TaggedOutbound::new("leaf-b", 8),
        ],
        &[
            SelectorDefinition::new("inner", vec!["leaf-a", "leaf-b"], Some("leaf-a")),
            SelectorDefinition::new("outer", vec!["leaf-b", "inner"], Some("inner")),
        ],
        TaggedRoute::Routed {
            rules: vec![],
            final_outbound: Some("outer"),
        },
    )
    .expect("valid nested selector graph")
}

fn select(route: &ferrum2_core::route::RouteTable) -> usize {
    route.select(
        0,
        Network::Tcp,
        &TargetAddr::domain("selector.test", 443).expect("target"),
    )
}

#[test]
fn public_control_resolves_nested_members_and_keeps_closed_failures_atomic() {
    let (route, control) = nested_route();
    assert_eq!(control.selected("outer"), Ok("inner"));
    assert_eq!(control.selected("inner"), Ok("leaf-a"));
    assert_eq!((select(&route), route.final_outbound()), (7, 7));

    for selector in ["missing-selector", "leaf-a"] {
        let error = control.selected(selector).unwrap_err();
        assert_eq!(error, SelectorError::UnknownSelector);
        assert!(!format!("{error}\n{error:?}").contains(selector));
    }
    for member in ["missing-member", "Leaf-B", "outer", "leaf-a"] {
        let error = control.switch("outer", member).unwrap_err();
        assert_eq!(error, SelectorError::UnknownMember);
        assert!(!format!("{error}\n{error:?}").contains(member));
        assert_eq!(control.selected("outer"), Ok("inner"));
    }

    control.switch("outer", "leaf-b").expect("valid switch");
    control.switch("outer", "leaf-b").expect("no-op switch");
    assert_eq!((select(&route), route.final_outbound()), (8, 7));
    control.switch("outer", "inner").expect("nested switch");
    control.switch("inner", "leaf-b").expect("inner switch");
    assert_eq!(control.selected("outer"), Ok("inner"));
    assert_eq!(select(&route), 8);
    assert_eq!(format!("{control:?}"), "SelectorControl([redacted])");
}

#[test]
fn concurrent_queries_and_switches_observe_only_complete_members_and_leaves() {
    let shared = Arc::new(nested_route());
    let barrier = Arc::new(Barrier::new(5));
    let mut tasks = Vec::new();
    for task in 0..4 {
        let (shared, barrier) = (Arc::clone(&shared), Arc::clone(&barrier));
        tasks.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1_000 {
                if task < 2 {
                    assert!(["leaf-a", "leaf-b"].contains(&shared.1.selected("inner").unwrap()));
                    assert!([7, 8].contains(&select(&shared.0)));
                } else {
                    shared
                        .1
                        .switch("inner", if task == 2 { "leaf-a" } else { "leaf-b" })
                        .unwrap();
                }
            }
        }));
    }
    barrier.wait();
    tasks.into_iter().for_each(|task| task.join().unwrap());
    shared.1.switch("inner", "leaf-b").unwrap();
    assert_eq!(shared.1.selected("inner"), Ok("leaf-b"));
    assert_eq!(select(&shared.0), 8);
}

#[test]
fn public_route_selection_snapshots_complete_static_rule_final_and_selector_plans() {
    let inbounds = [TaggedInbound::new("entry", 0)];
    #[rustfmt::skip]
    let outbounds = [TaggedOutbound::new("a", 7), TaggedOutbound::new("b", 8), TaggedOutbound::new("c", 9)];
    #[rustfmt::skip]
    let plans = [TaggedPlan::new("a-b", vec![7, 8]), TaggedPlan::new("b-c", vec![8, 9])];
    let selectors = [SelectorDefinition::new(
        "manual",
        vec!["a-b", "c"],
        Some("a-b"),
    )];
    #[rustfmt::skip]
    let (route, control) = compile_selector_plans(
        &inbounds, &outbounds, &plans, &selectors,
        TaggedRoute::Routed { rules: vec![TaggedRouteRule::new(Some("entry"), Some(Network::Tcp), None, Some("manual"))], final_outbound: Some("b-c") },
    ).expect("valid routed plans");
    let target = TargetAddr::domain("plans.test", 443).expect("target");
    let snapshot = route.select_plan(0, Network::Tcp, &target);
    #[rustfmt::skip]
    assert_eq!((snapshot.hops(), route.select_plan(0, Network::Udp, &target).hops(), route.final_plan().hops()), (&[7, 8][..], &[8, 9][..], &[8, 9][..]));
    control.switch("manual", "c").expect("whole-plan switch");
    #[rustfmt::skip]
    assert_eq!((snapshot.hops(), route.select_plan(0, Network::Tcp, &target).hops(), route.final_plan().hops()), (&[7, 8][..], &[9][..], &[8, 9][..]));

    #[rustfmt::skip]
    let (static_route, _) = compile_selector_plans(
        &inbounds, &outbounds[..2], &plans[..1], &[], TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "a-b")]),
    ).expect("valid static plan");
    assert_eq!(
        static_route.select_plan(0, Network::Tcp, &target).hops(),
        &[7, 8]
    );
    assert!(
        std::panic::catch_unwind(|| static_route.select(0, Network::Tcp, &target)).is_err(),
        "the direct-only accessor must not truncate a multi-hop plan"
    );
}

#[test]
fn one_action_table_preserves_exact_first_match_semantics_for_two_action_domains() {
    fn table<A: Copy>(actions: [A; 4]) -> ActionTable<A> {
        ActionTable::new(
            vec![
                ActionRule::new(
                    Some(2),
                    Some(Network::Tcp),
                    Some(TargetAddr::domain("Example.test.", 53).unwrap()),
                    actions[0],
                ),
                ActionRule::new(
                    None,
                    Some(Network::Udp),
                    Some(TargetAddr::ip("192.0.2.1:53".parse().unwrap()).unwrap()),
                    actions[1],
                ),
                ActionRule::new(None, None, None, actions[2]),
            ],
            actions[3],
        )
        .unwrap()
    }

    let contexts = [
        (2, Network::Tcp, "EXAMPLE.TEST.:53", 0),
        (7, Network::Udp, "192.0.2.1:53", 1),
        (2, Network::Tcp, "example.test:53", 2),
        (2, Network::Tcp, "example.test.:54", 2),
        (7, Network::Udp, "192.0.2.2:53", 2),
    ];
    let outbound = table([10, 20, 30, 40]);
    let dns = table(["primary", "lan", "shadow", "final"]);
    for (inbound, network, target, expected) in contexts {
        let target = target
            .parse()
            .ok()
            .and_then(|socket| TargetAddr::ip(socket).ok())
            .unwrap_or_else(|| {
                let (host, port) = target.rsplit_once(':').unwrap();
                TargetAddr::domain(host, port.parse().unwrap()).unwrap()
            });
        assert_eq!(
            outbound.select(inbound, network, &target),
            [10, 20, 30][expected]
        );
        assert_eq!(
            dns.select(inbound, network, &target),
            ["primary", "lan", "shadow"][expected]
        );
    }
    let final_only = ActionTable::new(Vec::new(), "final").unwrap();
    assert_eq!(
        final_only.select(
            0,
            Network::Tcp,
            &TargetAddr::domain("unused.test", 443).unwrap()
        ),
        "final"
    );
}
