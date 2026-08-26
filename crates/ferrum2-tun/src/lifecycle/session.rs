use std::sync::atomic::Ordering;
use std::time::Duration;

use smoltcp::time::Instant;

use super::prepare::forward_session_item;
use super::rebuild::adapter_underlay_is_current;
use super::reset::{
    MANAGED_DNS_AUDIT_MILLIS, NetworkChangeTransition, bounded_network_wait,
    owner_wait_after_budget, packet_ip_family, semantic_network_change_transition,
};
use crate::scheduler::{FairScheduler, StepOutcome, WorkStage};
use crate::stack::{OutputFlushOutcome, OutputSendOutcome, Stack};
use crate::supervisor::NetworkDebounce;
use crate::{
    AdapterErrorDisposition, OWNER_WORK_BUDGET, OwnerControl, OwnerExit, SessionCancellation,
    SessionItem, TcpFlow, TunDiagnosticReason, TunEvent, TunEventSink, TunNetworkFullRebuildReason,
    TunNetworkResetReason, TunRejectReason, UdpCandidate, classify_adapter_error,
};

pub(crate) struct ActiveSession<'a> {
    pub(crate) adapter: &'a mut ferrum2_platform_windows::Adapter,
    pub(crate) stack: &'a mut Stack,
    pub(crate) flows: &'a mut tokio::sync::mpsc::Receiver<TcpFlow>,
    pub(crate) datagrams: &'a mut tokio::sync::mpsc::Receiver<UdpCandidate>,
    pub(crate) pending_flow: &'a mut Option<TcpFlow>,
    pub(crate) pending_datagram: &'a mut Option<UdpCandidate>,
    pub(crate) control: &'a OwnerControl,
    pub(crate) flow_output: &'a tokio::sync::mpsc::Sender<SessionItem<TcpFlow>>,
    pub(crate) datagram_output: &'a tokio::sync::mpsc::Sender<SessionItem<UdpCandidate>>,
    pub(crate) cancellation: &'a SessionCancellation,
    pub(crate) events: &'a TunEventSink,
    pub(crate) supervisor_origin: std::time::Instant,
    pub(crate) debounce: &'a mut NetworkDebounce,
    pub(crate) audit_managed_dns: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionExit {
    Stopped,
    ResetNetwork { settle_underlay: bool },
    FullRebuild(TunNetworkFullRebuildReason),
    Terminal(OwnerExit),
}

pub(crate) fn run_active_session(session: &mut ActiveSession<'_>) -> SessionExit {
    let mut scheduler = FairScheduler::default();
    let clock_origin = std::time::Instant::now();
    let mut next_dns_audit = session.audit_managed_dns.then(|| {
        i64::try_from(session.supervisor_origin.elapsed().as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(MANAGED_DNS_AUDIT_MILLIS)
    });
    let mut raw_notification_generation = 0_u64;

    while !session.control.stop.load(Ordering::Acquire) {
        let supervisor_now =
            i64::try_from(session.supervisor_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
        let underlay_stale = !adapter_underlay_is_current(session.adapter);
        let debounced = session.debounce.take_ready(supervisor_now).is_some();
        let periodic_audit = !underlay_stale
            && !debounced
            && session.debounce.deadline_millis().is_none()
            && next_dns_audit.is_some_and(|deadline| supervisor_now >= deadline);
        if underlay_stale || debounced || periodic_audit {
            if session.audit_managed_dns {
                next_dns_audit = Some(supervisor_now.saturating_add(MANAGED_DNS_AUDIT_MILLIS));
            }
            match semantic_network_change_transition(session.adapter, session.events) {
                Ok(NetworkChangeTransition::Unchanged) => {}
                Ok(NetworkChangeTransition::ResetNetwork { settle_underlay }) => {
                    session.events.emit(TunEvent::NetworkResetStarted(
                        TunNetworkResetReason::NetworkChange,
                    ));
                    return SessionExit::ResetNetwork { settle_underlay };
                }
                Ok(NetworkChangeTransition::FullRebuild(damage))
                | Err(AdapterErrorDisposition::FullRebuild(damage)) => {
                    return SessionExit::FullRebuild(damage);
                }
                Err(AdapterErrorDisposition::RuntimeFailed) => {
                    return SessionExit::Terminal(OwnerExit::RuntimeFailed);
                }
                Err(AdapterErrorDisposition::CleanupFailed) => {
                    return SessionExit::Terminal(OwnerExit::CleanupFailed);
                }
            }
        }
        if !session.control.active.load(Ordering::Acquire) {
            let debounce_deadline = session.debounce.deadline_millis();
            let audit_deadline = next_dns_audit.filter(|_| debounce_deadline.is_none());
            let wait = bounded_network_wait(
                Duration::from_millis(u64::from(u32::MAX - 1)),
                supervisor_now,
                debounce_deadline,
                audit_deadline,
            );
            match session.adapter.wait(wait) {
                Ok(
                    ferrum2_platform_windows::WaitOutcome::Stop
                    | ferrum2_platform_windows::WaitOutcome::Work
                    | ferrum2_platform_windows::WaitOutcome::Readable
                    | ferrum2_platform_windows::WaitOutcome::Timeout,
                ) => {}
                Ok(ferrum2_platform_windows::WaitOutcome::NetworkChanged) => {
                    observe_network_change(session, &mut raw_notification_generation);
                }
                Err(error) => return exit_for_adapter_error(error),
            }
            continue;
        }

        let elapsed = i64::try_from(clock_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
        let admitting = session.control.admitting.load(Ordering::Acquire);
        let mut adapter_failure = None;
        let budget = scheduler.run_budget(OWNER_WORK_BUDGET, |stage| match stage {
            WorkStage::Control => {
                let forwarded_flow = forward_session_item(
                    session.flows,
                    session.pending_flow,
                    session.flow_output,
                    session.cancellation,
                );
                let forwarded_datagram = forward_session_item(
                    session.datagrams,
                    session.pending_datagram,
                    session.datagram_output,
                    session.cancellation,
                );
                StepOutcome::from_work(session.stack.process_owner_control_stage(
                    elapsed,
                    admitting,
                    forwarded_flow || forwarded_datagram,
                ))
            }
            WorkStage::FlushOutput => {
                match session
                    .stack
                    .flush_output(|packet| match session.adapter.send(packet) {
                        Ok(ferrum2_platform_windows::SendOutcome::Sent) => {
                            session.events.emit(TunEvent::PacketEgress);
                            OutputSendOutcome::Sent
                        }
                        Ok(ferrum2_platform_windows::SendOutcome::DroppedRingFull) => {
                            session.events.emit(TunEvent::WintunRingFullDropped);
                            session
                                .events
                                .emit(TunEvent::PacketRejected(TunRejectReason::WintunRingFull));
                            if let Some(family) = packet_ip_family(packet) {
                                session.events.emit(TunEvent::Diagnostic {
                                    reason: TunDiagnosticReason::WintunRingFull,
                                    family,
                                });
                            }
                            OutputSendOutcome::DroppedRingFull
                        }
                        Err(error) => {
                            adapter_failure = Some(classify_adapter_error(error));
                            OutputSendOutcome::Fatal
                        }
                    }) {
                    OutputFlushOutcome::Empty => StepOutcome::Idle,
                    OutputFlushOutcome::Sent | OutputFlushOutcome::DroppedRingFull => {
                        StepOutcome::Worked
                    }
                    OutputFlushOutcome::Fatal => StepOutcome::Fatal,
                }
            }
            WorkStage::Stack => {
                let outcome = session.stack.poll_stack_once(Instant::from_millis(elapsed));
                for _ in 0..outcome.foundation_dropped {
                    session.events.emit(TunEvent::PacketFoundationDropped);
                }
                StepOutcome::from_work(outcome.worked)
            }
            WorkStage::Receive if session.stack.ingress_available() != 0 => {
                let received = match session.adapter.receive() {
                    Ok(Some(packet)) => packet,
                    Ok(None) => return StepOutcome::Idle,
                    Err(error) => {
                        adapter_failure = Some(classify_adapter_error(error));
                        return StepOutcome::Fatal;
                    }
                };
                session.events.emit(TunEvent::PacketIngress);
                if session.stack.enqueue_at(&received, admitting, elapsed) {
                    session.events.emit(TunEvent::PacketAccepted);
                }
                StepOutcome::Worked
            }
            WorkStage::Receive => StepOutcome::Idle,
            WorkStage::UdpResponse => match session.stack.process_one_udp_response(elapsed) {
                crate::udp::ResponseProcessOutcome::Idle => StepOutcome::Idle,
                crate::udp::ResponseProcessOutcome::Deferred => {
                    session.events.emit(TunEvent::InternalEgressBackpressured);
                    StepOutcome::Worked
                }
                crate::udp::ResponseProcessOutcome::Injected
                | crate::udp::ResponseProcessOutcome::Dropped(_) => StepOutcome::Worked,
            },
            WorkStage::Expire => StepOutcome::from_work(session.stack.expire_deadlines(elapsed)),
        });
        if budget.fatal {
            return match adapter_failure.unwrap_or(AdapterErrorDisposition::RuntimeFailed) {
                AdapterErrorDisposition::FullRebuild(damage) => SessionExit::FullRebuild(damage),
                AdapterErrorDisposition::RuntimeFailed => {
                    SessionExit::Terminal(OwnerExit::RuntimeFailed)
                }
                AdapterErrorDisposition::CleanupFailed => {
                    SessionExit::Terminal(OwnerExit::CleanupFailed)
                }
            };
        }
        session
            .control
            .association_count
            .store(session.stack.live_udp_associations(), Ordering::Release);
        let debounce_deadline = session.debounce.deadline_millis();
        let audit_deadline = next_dns_audit.filter(|_| debounce_deadline.is_none());
        let wait = owner_wait_after_budget(
            budget,
            bounded_network_wait(
                session.stack.next_wait_duration(elapsed),
                supervisor_now,
                debounce_deadline,
                audit_deadline,
            ),
        );
        match session.adapter.wait(wait) {
            Ok(
                ferrum2_platform_windows::WaitOutcome::Stop
                | ferrum2_platform_windows::WaitOutcome::Readable
                | ferrum2_platform_windows::WaitOutcome::Work
                | ferrum2_platform_windows::WaitOutcome::Timeout,
            ) => {}
            Ok(ferrum2_platform_windows::WaitOutcome::NetworkChanged) => {
                observe_network_change(session, &mut raw_notification_generation);
            }
            Err(error) => return exit_for_adapter_error(error),
        }
    }
    SessionExit::Stopped
}

fn observe_network_change(session: &mut ActiveSession<'_>, raw_generation: &mut u64) {
    *raw_generation = raw_generation.wrapping_add(1).max(1);
    let observed_at =
        i64::try_from(session.supervisor_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
    session.debounce.observe(*raw_generation, observed_at);
}

fn exit_for_adapter_error(error: ferrum2_platform_windows::Error) -> SessionExit {
    match classify_adapter_error(error) {
        AdapterErrorDisposition::FullRebuild(damage) => SessionExit::FullRebuild(damage),
        AdapterErrorDisposition::RuntimeFailed => SessionExit::Terminal(OwnerExit::RuntimeFailed),
        AdapterErrorDisposition::CleanupFailed => SessionExit::Terminal(OwnerExit::CleanupFailed),
    }
}
