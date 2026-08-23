use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use ferrum2_core::GenerationChange;
use ferrum2_core::route::{EgressPlanHandle, compile_egress_plans_with_roots};
use ferrum2_core::selector::{
    SelectorCompileError, SelectorControl, SelectorDefinition, SelectorError, TaggedInbound,
    TaggedOutbound, TaggedPlan,
};

struct SelectorWake {
    control: SelectorControl,
    count: AtomicUsize,
    observed_generation: AtomicU64,
}

impl Wake for SelectorWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.observed_generation
            .store(self.control.generation(), Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll_change(change: &mut GenerationChange, waker: &Waker) -> Poll<u64> {
    Future::poll(Pin::new(change), &mut Context::from_waker(waker))
}

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
    let initial_generation = control.generation();
    assert_eq!(control.selected("outer"), Ok("inner"));
    assert_eq!(control.selected("inner"), Ok("leaf-a"));
    assert_eq!(root.snapshot().hops(), &[7]);

    assert_eq!(
        control.switch("missing", "leaf-a"),
        Err(SelectorError::UnknownSelector)
    );
    assert_eq!(control.generation(), initial_generation);
    assert_eq!(
        control.switch("outer", "missing"),
        Err(SelectorError::UnknownMember)
    );
    assert_eq!(control.generation(), initial_generation);
    control.switch("inner", "leaf-a").expect("no-op switch");
    assert_eq!(control.generation(), initial_generation);

    let observer = control.clone();
    control.switch("inner", "leaf-b").expect("valid switch");
    assert_ne!(observer.generation(), initial_generation);
    assert_eq!(root.snapshot_owned().hops(), &[8]);
}

#[test]
fn selector_change_subscription_only_reports_completed_effective_switches() {
    let (control, _) = nested_graph();
    let initial_generation = control.generation();
    let wake = Arc::new(SelectorWake {
        control: control.clone(),
        count: AtomicUsize::new(0),
        observed_generation: AtomicU64::new(u64::MAX),
    });
    let waker = Waker::from(Arc::clone(&wake));
    let mut change = control.watch_generation();
    assert_eq!(change.baseline(), initial_generation);
    assert_eq!(poll_change(&mut change, &waker), Poll::Pending);

    assert_eq!(
        control.switch("missing", "leaf-a"),
        Err(SelectorError::UnknownSelector)
    );
    control.switch("inner", "leaf-a").expect("no-op switch");
    assert_eq!(wake.count.load(Ordering::SeqCst), 0);
    assert_eq!(poll_change(&mut change, &waker), Poll::Pending);

    control.switch("inner", "leaf-b").expect("effective switch");
    let completed_generation = control.generation();
    assert_eq!(completed_generation & 1, 0);
    assert_ne!(completed_generation, initial_generation);
    assert_eq!(wake.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        wake.observed_generation.load(Ordering::SeqCst),
        completed_generation,
        "generation publication must complete before subscribers are woken"
    );
    assert_eq!(
        poll_change(&mut change, &waker),
        Poll::Ready(completed_generation)
    );
}

#[test]
fn selector_change_before_post_selection_subscription_is_observed() {
    let (control, _) = nested_graph();
    let selected_generation = control.generation();
    control.switch("inner", "leaf-b").expect("effective switch");
    let mut change = control.watch_generation_from(selected_generation);
    let wake = Arc::new(SelectorWake {
        control: control.clone(),
        count: AtomicUsize::new(0),
        observed_generation: AtomicU64::new(u64::MAX),
    });
    let waker = Waker::from(Arc::clone(&wake));

    assert_eq!(
        poll_change(&mut change, &waker),
        Poll::Ready(control.generation())
    );
    assert_eq!(wake.count.load(Ordering::SeqCst), 0);
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
