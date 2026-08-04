use std::sync::{Arc, Barrier};
use std::thread;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::{Network, compile_selector_route};
use ferrum2_core::selector::{
    SelectorControl, SelectorDefinition, SelectorError, TaggedInbound, TaggedOutbound, TaggedRoute,
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
