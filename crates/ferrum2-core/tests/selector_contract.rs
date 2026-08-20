use std::sync::{Arc, Barrier};
use std::thread;

use ferrum2_core::route::{EgressPlanHandle, compile_egress_plans_with_roots};
use ferrum2_core::selector::{
    SelectorCompileError, SelectorDefinition, SelectorError, TaggedInbound, TaggedOutbound,
    TaggedPlan,
};

fn nested_graph() -> (ferrum2_core::selector::SelectorControl, EgressPlanHandle) {
    let (control, mut roots) = compile_egress_plans_with_roots(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("leaf-a", 7),
            TaggedOutbound::new("leaf-b", 8),
        ],
        &[],
        &[
            SelectorDefinition::new("inner", vec!["leaf-a", "leaf-b"], Some("leaf-a")),
            SelectorDefinition::new("outer", vec!["leaf-b", "inner"], Some("inner")),
        ],
        &["outer"],
    )
    .expect("valid nested selector graph");
    (control, roots.remove(0))
}

#[test]
fn public_control_resolves_nested_members_and_switches_whole_plans() {
    let (control, root) = nested_graph();
    assert_eq!(control.selected("outer"), Ok("inner"));
    assert_eq!(control.selected("inner"), Ok("leaf-a"));
    assert_eq!(root.snapshot().hops(), &[7]);

    assert_eq!(
        control.switch("missing", "leaf-a"),
        Err(SelectorError::UnknownSelector)
    );
    assert_eq!(
        control.switch("outer", "missing"),
        Err(SelectorError::UnknownMember)
    );
    control.switch("inner", "leaf-b").expect("valid switch");
    assert_eq!(root.snapshot_owned().hops(), &[8]);
}

#[test]
fn selector_reads_and_switches_are_atomic() {
    let shared = Arc::new(nested_graph());
    let barrier = Arc::new(Barrier::new(5));
    let mut tasks = Vec::new();
    for task in 0..4 {
        let shared = Arc::clone(&shared);
        let barrier = Arc::clone(&barrier);
        tasks.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1_000 {
                if task < 2 {
                    assert!([7, 8].contains(&shared.1.snapshot().hops()[0]));
                } else {
                    shared
                        .0
                        .switch("inner", if task == 2 { "leaf-a" } else { "leaf-b" })
                        .expect("member");
                }
            }
        }));
    }
    barrier.wait();
    for task in tasks {
        task.join().expect("worker");
    }
}

#[test]
fn plans_and_reachability_keep_existing_resource_bounds() {
    let error = compile_egress_plans_with_roots(
        &[TaggedInbound::new("entry", 0)],
        &[TaggedOutbound::new("out", 7)],
        &[TaggedPlan::new("empty", Vec::new())],
        &[],
        &["out"],
    )
    .unwrap_err();
    assert_eq!(error, SelectorCompileError::PlanHops);

    let error = compile_egress_plans_with_roots(
        &[TaggedInbound::new("entry", 0)],
        &[TaggedOutbound::new("out", 7)],
        &[],
        &[],
        &["missing"],
    )
    .unwrap_err();
    assert_eq!(error, SelectorCompileError::ExtraRoot);
}
