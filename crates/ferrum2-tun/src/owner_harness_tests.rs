use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_runtime::OwnerRegistry;
use tokio::sync::mpsc;

use crate::packet::test_support::{ipv4_tcp_with_options, ipv4_udp, repair_ipv4_header};
use crate::scheduler::{BudgetOutcome, FairScheduler, StepOutcome, WorkStage};
use crate::supervisor::{NETWORK_DEBOUNCE, NetworkDebounce};
use crate::udp::ResponseProcessOutcome;
use crate::{
    OutputFlushOutcome, OutputSendOutcome, OwnerWake, Stack, TcpFlow, TunEvent, TunEventSink,
    TunRejectReason, UdpCandidate, UdpFiltering, UdpInjectOutcome, UdpResponseDropReason,
    UdpResponseSendOutcome, bounded_network_wait, owner_wait_after_budget,
};

const TEST_WORK_BUDGET: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeWaitOutcome {
    Stop,
    Work,
    Readable,
    Timeout,
    NetworkChanged,
}

#[derive(Debug)]
enum FakeReceiveOutcome {
    Packet(Vec<u8>),
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeSendOutcome {
    Sent,
    RingFull,
    Fatal,
}

#[derive(Debug, Default)]
struct FakeAdapter {
    receives: VecDeque<FakeReceiveOutcome>,
    waits: VecDeque<FakeWaitOutcome>,
    sends: VecDeque<FakeSendOutcome>,
    semantic_changes: VecDeque<bool>,
    send_attempts: Vec<Vec<u8>>,
    sent_packets: Vec<Vec<u8>>,
    wait_durations: Vec<Duration>,
    receive_calls: usize,
    semantic_checks: usize,
}

impl FakeAdapter {
    fn receive(&mut self) -> Result<Option<Vec<u8>>, ()> {
        self.receive_calls += 1;
        match self.receives.pop_front() {
            Some(FakeReceiveOutcome::Packet(packet)) => Ok(Some(packet)),
            Some(FakeReceiveOutcome::Fatal) => Err(()),
            None => Ok(None),
        }
    }

    fn send(&mut self, packet: &[u8]) -> FakeSendOutcome {
        self.send_attempts.push(packet.to_vec());
        let outcome = self.sends.pop_front().unwrap_or(FakeSendOutcome::Sent);
        if outcome == FakeSendOutcome::Sent {
            self.sent_packets.push(packet.to_vec());
        }
        outcome
    }

    fn wait(&mut self, timeout: Duration) -> FakeWaitOutcome {
        self.wait_durations.push(timeout);
        self.waits.pop_front().unwrap_or(FakeWaitOutcome::Timeout)
    }

    fn semantic_network_changed(&mut self) -> bool {
        self.semantic_checks += 1;
        self.semantic_changes.pop_front().unwrap_or(true)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FakeClock {
    now_millis: i64,
}

impl FakeClock {
    fn advance(&mut self, millis: i64) {
        self.now_millis = self.now_millis.saturating_add(millis);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessExit {
    Stop,
    NetworkChanged,
    Fatal,
}

struct OwnerSessionHarness {
    stack: Stack,
    flows: mpsc::Receiver<TcpFlow>,
    candidates: mpsc::Receiver<UdpCandidate>,
    flow_count: Arc<AtomicUsize>,
    adapter: FakeAdapter,
    scheduler: FairScheduler,
    clock: FakeClock,
    debounce: NetworkDebounce,
    raw_network_generation: u64,
    audit_deadline: Option<i64>,
    admitting: bool,
    exit: Option<HarnessExit>,
    stage_visits: [usize; FairScheduler::STAGE_COUNT],
    stage_log: Vec<WorkStage>,
    events: Arc<Mutex<Vec<TunEvent>>>,
    last_wait: Option<Duration>,
}

impl OwnerSessionHarness {
    fn new() -> Self {
        Self::with_udp_capacity(8)
    }

    fn with_udp_capacity(max_udp_associations: usize) -> Self {
        let flow_count = Arc::new(AtomicUsize::new(0));
        let (mut stack, flows, candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1_420,
            8,
            4_096,
            Duration::from_secs(60),
            Arc::clone(&flow_count),
            OwnerRegistry::new(),
            max_udp_associations,
            Duration::from_secs(60),
            UdpFiltering::EndpointIndependent,
            1,
            OwnerWake::default(),
        )
        .expect("deterministic owner stack");
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        stack.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("owner harness events").push(event);
        }));
        Self {
            stack,
            flows,
            candidates,
            flow_count,
            adapter: FakeAdapter::default(),
            scheduler: FairScheduler::default(),
            clock: FakeClock::default(),
            debounce: NetworkDebounce::default(),
            raw_network_generation: 0,
            audit_deadline: None,
            admitting: true,
            exit: None,
            stage_visits: [0; FairScheduler::STAGE_COUNT],
            stage_log: Vec::new(),
            events,
            last_wait: None,
        }
    }

    fn events(&self) -> Vec<TunEvent> {
        self.events.lock().expect("owner harness events").clone()
    }

    fn terminate(&mut self, exit: HarnessExit) {
        if self.exit.is_some() {
            return;
        }
        self.admitting = false;
        let response_drop_reason = match exit {
            HarnessExit::Stop => UdpResponseDropReason::Shutdown,
            HarnessExit::NetworkChanged => UdpResponseDropReason::SessionReset,
            HarnessExit::Fatal => UdpResponseDropReason::OwnerFatal,
        };
        self.stack.quiesce(2, response_drop_reason);
        self.exit = Some(exit);
    }

    fn run_work_budget(&mut self, budget: usize) -> BudgetOutcome {
        if self.exit.is_some() {
            return BudgetOutcome::default();
        }
        let now_millis = self.clock.now_millis;
        let admitting = self.admitting;
        let scheduler = &mut self.scheduler;
        let stack = &mut self.stack;
        let adapter = &mut self.adapter;
        let events = &self.events;
        let stage_visits = &mut self.stage_visits;
        let stage_log = &mut self.stage_log;
        let outcome = scheduler.run_budget(budget, |stage| {
            stage_visits[stage_index(stage)] += 1;
            stage_log.push(stage);
            match stage {
                WorkStage::Control => {
                    StepOutcome::from_work(stack.process_one_udp_control(now_millis, admitting))
                }
                WorkStage::FlushOutput => {
                    match stack.flush_output(|packet| match adapter.send(packet) {
                        FakeSendOutcome::Sent => {
                            emit(events, TunEvent::PacketEgress);
                            OutputSendOutcome::Sent
                        }
                        FakeSendOutcome::RingFull => {
                            emit(events, TunEvent::WintunRingFullDropped);
                            emit(
                                events,
                                TunEvent::PacketRejected(TunRejectReason::WintunRingFull),
                            );
                            OutputSendOutcome::DroppedRingFull
                        }
                        FakeSendOutcome::Fatal => OutputSendOutcome::Fatal,
                    }) {
                        OutputFlushOutcome::Empty => StepOutcome::Idle,
                        OutputFlushOutcome::Sent | OutputFlushOutcome::DroppedRingFull => {
                            StepOutcome::Worked
                        }
                        OutputFlushOutcome::Fatal => StepOutcome::Fatal,
                    }
                }
                WorkStage::Stack => {
                    let outcome =
                        stack.poll_stack_once(smoltcp::time::Instant::from_millis(now_millis));
                    for _ in 0..outcome.foundation_dropped {
                        emit(events, TunEvent::PacketFoundationDropped);
                    }
                    StepOutcome::from_work(outcome.worked)
                }
                WorkStage::Receive if stack.ingress_available() != 0 => match adapter.receive() {
                    Ok(Some(packet)) => {
                        emit(events, TunEvent::PacketIngress);
                        if stack.enqueue_at(&packet, admitting, now_millis) {
                            emit(events, TunEvent::PacketAccepted);
                        }
                        StepOutcome::Worked
                    }
                    Ok(None) => StepOutcome::Idle,
                    Err(()) => StepOutcome::Fatal,
                },
                WorkStage::Receive => StepOutcome::Idle,
                WorkStage::UdpResponse => match stack.process_one_udp_response(now_millis) {
                    ResponseProcessOutcome::Idle => StepOutcome::Idle,
                    ResponseProcessOutcome::Deferred => {
                        emit(events, TunEvent::InternalEgressBackpressured);
                        StepOutcome::Worked
                    }
                    ResponseProcessOutcome::Injected | ResponseProcessOutcome::Dropped(_) => {
                        StepOutcome::Worked
                    }
                },
                WorkStage::Expire => StepOutcome::from_work(stack.expire_deadlines(now_millis)),
            }
        });
        if outcome.fatal {
            self.terminate(HarnessExit::Fatal);
        }
        outcome
    }

    fn run_cycle(&mut self) {
        if self.exit.is_some() {
            return;
        }
        let now_millis = self.clock.now_millis;
        if self.debounce.take_ready(now_millis).is_some() && self.adapter.semantic_network_changed()
        {
            self.terminate(HarnessExit::NetworkChanged);
            return;
        }
        let budget = self.run_work_budget(TEST_WORK_BUDGET);
        if budget.fatal || self.exit.is_some() {
            return;
        }
        let debounce_deadline = self.debounce.deadline_millis();
        let audit_deadline = self.audit_deadline.filter(|_| debounce_deadline.is_none());
        let wait = owner_wait_after_budget(
            budget,
            bounded_network_wait(
                self.stack.next_wait_duration(now_millis),
                now_millis,
                debounce_deadline,
                audit_deadline,
            ),
        );
        self.last_wait = Some(wait);
        match self.adapter.wait(wait) {
            FakeWaitOutcome::Stop => self.terminate(HarnessExit::Stop),
            FakeWaitOutcome::NetworkChanged => {
                self.raw_network_generation = self.raw_network_generation.wrapping_add(1).max(1);
                self.debounce
                    .observe(self.raw_network_generation, self.clock.now_millis);
            }
            FakeWaitOutcome::Work | FakeWaitOutcome::Readable | FakeWaitOutcome::Timeout => {}
        }
    }

    fn run_single_stage(&mut self, stage: WorkStage) -> BudgetOutcome {
        self.scheduler = FairScheduler::default();
        for _ in 0..stage_index(stage) {
            let _ = self.scheduler.next_stage();
        }
        self.run_work_budget(1)
    }
}

fn stage_index(stage: WorkStage) -> usize {
    match stage {
        WorkStage::Control => 0,
        WorkStage::FlushOutput => 1,
        WorkStage::Stack => 2,
        WorkStage::Receive => 3,
        WorkStage::UdpResponse => 4,
        WorkStage::Expire => 5,
    }
}

fn emit(events: &Arc<Mutex<Vec<TunEvent>>>, event: TunEvent) {
    events.lock().expect("owner harness events").push(event);
}

fn first_ipv4_fragment() -> Vec<u8> {
    let packet = ipv4_udp(b"fragmented-payload", &[]);
    let mut fragment = packet[..20].to_vec();
    fragment.extend_from_slice(&packet[20..36]);
    let fragment_len = u16::try_from(fragment.len()).unwrap();
    fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
    fragment[4..6].copy_from_slice(&77_u16.to_be_bytes());
    fragment[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    repair_ipv4_header(&mut fragment);
    fragment
}

fn ipv4_udp_from_source_port(source_port: u16) -> Vec<u8> {
    let mut packet = ipv4_udp(b"control-backlog", &[]);
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[header_len..header_len + 2].copy_from_slice(&source_port.to_be_bytes());
    // IPv4 permits a zero UDP checksum, which keeps this fixture mutation
    // focused on making each source-keyed candidate distinct.
    packet[header_len + 6..header_len + 8].fill(0);
    packet
}

#[test]
fn owner_wait_uses_the_earliest_protocol_debounce_and_audit_deadline() {
    let base = Duration::from_secs(10);
    for (now, debounce, audit, expected) in [
        (100, None, None, Duration::from_secs(10)),
        (100, Some(2_000), None, Duration::from_millis(1_900)),
        (100, None, Some(500), Duration::from_millis(400)),
        (100, Some(2_000), Some(500), Duration::from_millis(400)),
        (500, Some(400), Some(900), Duration::ZERO),
    ] {
        assert_eq!(
            bounded_network_wait(base, now, debounce, audit),
            expected,
            "deadline ordering changed for debounce={debounce:?} audit={audit:?}"
        );
    }

    let mut harness = OwnerSessionHarness::new();
    assert!(
        harness
            .stack
            .enqueue_at(&ipv4_udp(b"candidate", &[]), true, 0)
    );
    assert!(harness.stack.enqueue_at(&first_ipv4_fragment(), true, 0));
    assert_eq!(
        harness.stack.next_wait_duration(0),
        Duration::from_secs(5),
        "candidate deadline precedes the reassembly deadline"
    );

    harness.audit_deadline = Some(100);
    harness.adapter.waits.push_back(FakeWaitOutcome::Timeout);
    harness.run_cycle();
    assert_eq!(harness.last_wait, Some(Duration::from_millis(100)));

    harness.debounce.observe(1, 0);
    harness.adapter.waits.push_back(FakeWaitOutcome::Timeout);
    harness.run_cycle();
    assert_eq!(
        harness.last_wait,
        Some(NETWORK_DEBOUNCE),
        "the owner suppresses its periodic audit while debounce is pending"
    );

    harness.audit_deadline = None;
    harness.adapter.semantic_changes.push_back(false);
    harness.clock.advance(5_000);
    harness.run_cycle();
    assert_eq!(harness.adapter.semantic_checks, 1);
    assert_eq!(harness.stack.live_udp_associations(), 0);
    assert!(harness.events().contains(&TunEvent::PacketRejected(
        TunRejectReason::UdpCandidateTimeout
    )));
    assert_eq!(
        harness.stack.next_wait_duration(5_000),
        Duration::from_secs(25),
        "after candidate expiry only the fragment deadline remains"
    );
}

#[test]
fn coalesced_udp_control_backlog_gets_an_immediate_budget_retry() {
    const NOTICE_COUNT: usize = 16;

    let mut harness = OwnerSessionHarness::with_udp_capacity(NOTICE_COUNT);
    let mut candidates = Vec::with_capacity(NOTICE_COUNT);
    for ordinal in 0..NOTICE_COUNT {
        let source_port = 10_000_u16 + u16::try_from(ordinal).unwrap();
        assert!(
            harness.stack.enqueue_at(
                &ipv4_udp_from_source_port(source_port),
                harness.admitting,
                harness.clock.now_millis,
            ),
            "candidate {ordinal} was rejected"
        );
        candidates.push(
            harness
                .candidates
                .try_recv()
                .expect("one distinct UDP candidate"),
        );
    }
    drop(candidates);

    harness.adapter.waits.push_back(FakeWaitOutcome::Timeout);
    harness.run_cycle();
    assert_eq!(harness.last_wait, Some(Duration::ZERO));
    assert!(
        harness.stack.udp.provisional_candidates() != 0,
        "the first budget must leave enough real control work to exercise a coalesced wake"
    );

    harness.adapter.waits.push_back(FakeWaitOutcome::Timeout);
    harness.run_cycle();
    assert_eq!(harness.stack.udp.provisional_candidates(), 0);
    assert_ne!(
        harness.last_wait,
        Some(Duration::ZERO),
        "an idle rotation restores blocking instead of spinning"
    );
}

#[test]
fn fake_wait_classes_are_distinct_and_terminal_events_quiesce_admission() {
    for outcome in [
        FakeWaitOutcome::Work,
        FakeWaitOutcome::Readable,
        FakeWaitOutcome::Timeout,
    ] {
        let mut harness = OwnerSessionHarness::new();
        harness.adapter.waits.push_back(outcome);
        harness.run_cycle();
        assert_eq!(harness.exit, None, "{outcome:?} is non-terminal");
        assert!(harness.admitting);
    }

    let mut stopped = OwnerSessionHarness::new();
    assert!(stopped.stack.enqueue_at(
        &ipv4_tcp_with_options(&[]),
        stopped.admitting,
        stopped.clock.now_millis,
    ));
    assert_eq!(stopped.flow_count.load(Ordering::Acquire), 1);
    stopped.adapter.waits.push_back(FakeWaitOutcome::Stop);
    stopped.run_cycle();
    assert_eq!(stopped.exit, Some(HarnessExit::Stop));
    assert!(!stopped.admitting);
    assert_eq!(stopped.flow_count.load(Ordering::Acquire), 0);
    assert!(!stopped.stack.enqueue_at(
        &ipv4_tcp_with_options(&[]),
        stopped.admitting,
        stopped.clock.now_millis,
    ));
    assert!(
        stopped
            .events()
            .contains(&TunEvent::PacketRejected(TunRejectReason::StaleGeneration))
    );

    let mut changed = OwnerSessionHarness::new();
    changed
        .adapter
        .waits
        .push_back(FakeWaitOutcome::NetworkChanged);
    changed.adapter.semantic_changes.push_back(true);
    changed.run_cycle();
    assert_eq!(changed.exit, None, "raw notifications are only debounced");
    assert_eq!(changed.adapter.semantic_checks, 0);
    changed
        .clock
        .advance(i64::try_from(NETWORK_DEBOUNCE.as_millis()).unwrap());
    changed.run_cycle();
    assert_eq!(changed.adapter.semantic_checks, 1);
    assert_eq!(changed.exit, Some(HarnessExit::NetworkChanged));
    assert!(!changed.admitting);
}

#[test]
fn burst_rx_rotates_all_work_stages_without_structural_loss() {
    let mut harness = OwnerSessionHarness::new();
    let packet = ipv4_tcp_with_options(&[]);
    for _ in 0..64 {
        harness
            .adapter
            .receives
            .push_back(FakeReceiveOutcome::Packet(packet.clone()));
    }

    let mut cycles = 0;
    while !harness.adapter.receives.is_empty() || harness.stack.pending() != 0 {
        harness.run_cycle();
        cycles += 1;
        assert!(cycles < 128, "bounded fake owner made no burst progress");
    }

    let events = harness.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == TunEvent::PacketIngress)
            .count(),
        64
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == TunEvent::PacketAccepted)
            .count(),
        64
    );
    assert!(!events.contains(&TunEvent::PacketRejected(TunRejectReason::IngressFull)));
    assert!(
        harness.adapter.receive_calls >= 64,
        "the fake adapter may be probed once after the burst is empty"
    );
    assert!(harness.stage_visits.iter().all(|visits| *visits != 0));
    let minimum = *harness.stage_visits.iter().min().unwrap();
    let maximum = *harness.stage_visits.iter().max().unwrap();
    assert!(
        maximum - minimum <= 1,
        "fair stage rotation drifted: {:?}",
        harness.stage_visits
    );
    assert!(
        harness.adapter.wait_durations.iter().any(Duration::is_zero),
        "queued owner work must not wait for a polling tick"
    );
    let _ = harness.flows.try_recv();
}

#[tokio::test]
async fn occupied_output_preserves_udp_response_order_and_ring_full_is_nonfatal() {
    let mut harness = OwnerSessionHarness::new();
    assert!(
        harness
            .stack
            .enqueue_at(&ipv4_udp(b"request", &[]), true, 0)
    );
    let candidate = harness
        .candidates
        .try_recv()
        .expect("one deterministic UDP candidate");
    let commit = tokio::spawn(async move { candidate.commit_association().await });
    tokio::task::yield_now().await;
    assert_eq!(harness.run_single_stage(WorkStage::Control).work_units, 1);
    let association = commit
        .await
        .expect("commit task")
        .expect("owner accepted commit");
    let remote: SocketAddr = "192.0.2.1:53".parse().unwrap();
    assert_eq!(
        association.send_response(remote, b"first"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        association.send_response(remote, b"second"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        harness
            .events()
            .iter()
            .filter(|event| matches!(event, TunEvent::PacketRejected(_)))
            .count(),
        0
    );

    assert_eq!(
        harness.run_single_stage(WorkStage::UdpResponse).work_units,
        1
    );
    assert!(harness.stack.has_output());
    assert_eq!(
        harness.run_single_stage(WorkStage::UdpResponse).work_units,
        1,
        "the current response is retained when the single output slot is occupied"
    );
    assert_eq!(
        harness
            .events()
            .iter()
            .filter(|event| **event == TunEvent::InternalEgressBackpressured)
            .count(),
        1
    );

    harness.adapter.sends.push_back(FakeSendOutcome::Sent);
    assert_eq!(
        harness.run_single_stage(WorkStage::FlushOutput).work_units,
        1
    );
    assert_eq!(
        harness.run_single_stage(WorkStage::UdpResponse).work_units,
        1
    );
    let delayed_then_success = harness.events();
    assert_eq!(
        delayed_then_success
            .iter()
            .filter(|event| matches!(event, TunEvent::PacketRejected(_)))
            .count(),
        0,
        "a response retained and later injected is never rejected"
    );
    assert_eq!(
        delayed_then_success
            .iter()
            .filter_map(|event| match event {
                TunEvent::UdpPendingResponses(pending) => Some(*pending),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [1, 0],
        "the pending-response gauge follows the deferred response lifecycle"
    );
    harness.adapter.sends.push_back(FakeSendOutcome::RingFull);
    assert_eq!(
        harness.run_single_stage(WorkStage::FlushOutput).work_units,
        1
    );

    assert_eq!(harness.adapter.send_attempts.len(), 2);
    assert!(harness.adapter.send_attempts[0].ends_with(b"first"));
    assert!(harness.adapter.send_attempts[1].ends_with(b"second"));
    assert_eq!(harness.adapter.sent_packets.len(), 1);
    assert!(!harness.stack.has_output());
    assert_eq!(harness.exit, None, "ring-full is not a restart boundary");
    assert!(harness.events().contains(&TunEvent::WintunRingFullDropped));
    assert!(
        harness
            .events()
            .contains(&TunEvent::PacketRejected(TunRejectReason::WintunRingFull))
    );
}

#[test]
fn fatal_receive_stops_before_later_stages_and_quiesces_once() {
    let mut harness = OwnerSessionHarness::new();
    harness
        .adapter
        .receives
        .push_back(FakeReceiveOutcome::Fatal);

    let outcome = harness.run_work_budget(TEST_WORK_BUDGET);
    assert!(outcome.fatal);
    assert_eq!(harness.exit, Some(HarnessExit::Fatal));
    assert!(!harness.admitting);
    assert_eq!(
        harness.stage_log,
        [
            WorkStage::Control,
            WorkStage::FlushOutput,
            WorkStage::Stack,
            WorkStage::Receive,
        ],
        "no UDP response, expiry, or second stack mutation follows fatal receive"
    );
    let event_count = harness.events().len();
    assert_eq!(harness.run_work_budget(TEST_WORK_BUDGET).work_units, 0);
    assert_eq!(
        harness.events().len(),
        event_count,
        "terminal quiesce runs once"
    );
}

#[test]
fn fatal_send_is_classified_separately_from_ring_full() {
    let mut harness = OwnerSessionHarness::new();
    assert_eq!(
        harness.stack.device.inject_udp_response(
            crate::UdpTuple::new(
                "198.18.0.1:10000".parse().unwrap(),
                "192.0.2.1:53".parse().unwrap(),
            ),
            b"fatal",
        ),
        UdpInjectOutcome::Injected
    );
    harness.adapter.sends.push_back(FakeSendOutcome::Fatal);
    let outcome = harness.run_single_stage(WorkStage::FlushOutput);
    assert!(outcome.fatal);
    assert_eq!(harness.exit, Some(HarnessExit::Fatal));
    assert!(!harness.events().contains(&TunEvent::WintunRingFullDropped));
}

#[tokio::test]
async fn owner_fatal_counts_one_pending_udp_response_drop_and_reject() {
    let mut harness = OwnerSessionHarness::new();
    assert!(
        harness
            .stack
            .enqueue_at(&ipv4_udp(b"request", &[]), true, 0)
    );
    let candidate = harness
        .candidates
        .try_recv()
        .expect("one deterministic UDP candidate");
    let commit = tokio::spawn(async move { candidate.commit_association().await });
    tokio::task::yield_now().await;
    assert_eq!(harness.run_single_stage(WorkStage::Control).work_units, 1);
    let association = commit
        .await
        .expect("commit task")
        .expect("owner accepted commit");
    let remote: SocketAddr = "192.0.2.1:53".parse().unwrap();
    assert_eq!(
        association.send_response(remote, b"occupies-output"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        harness.run_single_stage(WorkStage::UdpResponse).work_units,
        1
    );
    assert_eq!(
        association.send_response(remote, b"pending"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        harness.run_single_stage(WorkStage::UdpResponse).work_units,
        1
    );

    harness.adapter.sends.push_back(FakeSendOutcome::Fatal);
    assert!(harness.run_single_stage(WorkStage::FlushOutput).fatal);
    assert_eq!(harness.exit, Some(HarnessExit::Fatal));
    let events = harness.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                **event == TunEvent::UdpResponseDropped(UdpResponseDropReason::OwnerFatal)
            })
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                **event == TunEvent::PacketRejected(TunRejectReason::UdpResponseClosed)
            })
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event {
                TunEvent::UdpPendingResponses(pending) => Some(*pending),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [1, 0]
    );
}
