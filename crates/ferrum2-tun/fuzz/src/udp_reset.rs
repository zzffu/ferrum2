use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::runtime::Builder;

use crate::udp::{
    Admission, InjectOutcome, ResponseProcessOutcome, UdpAssociation, UdpCommitError,
    UdpDatagramEndpoints, UdpFiltering, UdpResponseSendOutcome, UdpTable,
};
use crate::{OwnerWake, TunRejectReason, UdpResponseDropReason};

/// Hard input bound for the UDP reset state-sequence target.
pub const MAX_UDP_RESET_FUZZ_INPUT_BYTES: usize = 4 * 1024;

const MAX_STEPS: usize = 256;
const MAX_CAPACITY: usize = 8;
const MAX_RETAINED_STALE_SINKS: usize = 16;

/// Exercises the production source-keyed UDP table across bounded reset interleavings.
///
/// This target is entirely in memory. It never creates a TUN adapter, socket, route, WFP object,
/// or background thread. Input bytes select admissions, provisional commits, response injection,
/// expiry, association closes, and network-generation changes.
pub fn fuzz_udp_reset_races(input: &[u8]) {
    if input.len() > MAX_UDP_RESET_FUZZ_INPUT_BYTES {
        return;
    }
    let runtime = Builder::new_current_thread()
        .build()
        .expect("bounded current-thread runtime");
    runtime.block_on(exercise(input));
}

async fn exercise(input: &[u8]) {
    let selector = input.first().copied().unwrap_or_default();
    let capacity = usize::from(selector % MAX_CAPACITY as u8) + 1;
    let filtering = if selector & 0x80 == 0 {
        UdpFiltering::EndpointIndependent
    } else {
        UdpFiltering::AddressDependent
    };
    let wake_count = Arc::new(AtomicUsize::new(0));
    let observed_wakes = Arc::clone(&wake_count);
    let wake = OwnerWake::new(move || {
        observed_wakes.fetch_add(1, Ordering::Relaxed);
    });
    let mut generation = 1_u64;
    let (mut table, mut candidates) = UdpTable::with_options(
        capacity,
        Duration::from_millis(1_000),
        filtering,
        generation,
        wake,
    );
    let mut associations = Vec::<UdpAssociation>::with_capacity(capacity);
    let mut stale_sinks = VecDeque::with_capacity(MAX_RETAINED_STALE_SINKS);
    let mut now_millis = 0_i64;

    for (ordinal, frame) in input.chunks(4).take(MAX_STEPS).enumerate() {
        let operation = frame.first().copied().unwrap_or_default();
        let source_selector = frame.get(1).copied().unwrap_or(operation);
        let target_selector = frame.get(2).copied().unwrap_or(source_selector);
        let policy = frame.get(3).copied().unwrap_or(target_selector);
        now_millis = now_millis.saturating_add(i64::from(policy & 0x0f));

        match operation % 8 {
            0 => {
                let endpoints = endpoints(source_selector, target_selector);
                let payload = frame;
                let payload_bound = payload.len().saturating_add(usize::from(policy & 0x1f));
                let _ = table.admit(endpoints, payload, payload_bound, now_millis, true);
            }
            1 => {
                if let Ok(candidate) = candidates.try_recv() {
                    let source = candidate.source();
                    let first_target = candidate.first_target();
                    let packet_bound = candidate.packet_payload_bound();
                    let selected_bound = if policy & 0x40 == 0 {
                        packet_bound
                    } else {
                        packet_bound.saturating_add(1)
                    };
                    let commit = tokio::spawn(async move {
                        candidate
                            .commit_association_with_payload_bound(selected_bound)
                            .await
                    });
                    tokio::task::yield_now().await;

                    if policy & 0x80 != 0 {
                        reset_table(
                            &mut table,
                            &mut generation,
                            &mut associations,
                            &mut stale_sinks,
                        );
                    }
                    for _ in 0..capacity.saturating_add(2) {
                        let _ = table.process_one_control(now_millis, true);
                        tokio::task::yield_now().await;
                        if commit.is_finished() {
                            break;
                        }
                    }
                    if !commit.is_finished() {
                        reset_table(
                            &mut table,
                            &mut generation,
                            &mut associations,
                            &mut stale_sinks,
                        );
                    }
                    match commit.await.expect("commit task must not panic") {
                        Ok(mut association) => {
                            assert_eq!(association.source(), source);
                            assert_eq!(association.first_target(), first_target);
                            let first = association
                                .receive()
                                .await
                                .expect("committed candidate retains its first datagram");
                            assert_eq!(first.source(), source);
                            assert_eq!(first.target(), first_target);
                            retain_stale_sink(&mut stale_sinks, association.response_sink());
                            associations.push(association);
                            assert!(associations.len() <= capacity);
                        }
                        Err(UdpCommitError::Rejected | UdpCommitError::Unavailable) => {}
                    }
                }
            }
            2 => {
                if let Some(association) =
                    associations.get(usize::from(source_selector) % associations.len().max(1))
                {
                    let response_source = target(source_selector, target_selector);
                    let payload = frame;
                    let _ = association.send_response(response_source, payload);
                    let injection = policy % 3;
                    let _ = table.process_one_response(now_millis, |endpoints, bytes| {
                        assert!(endpoints.source().port() != 0);
                        assert!(endpoints.target().port() != 0);
                        assert!(!bytes.is_empty() && bytes.len() <= 4);
                        match injection {
                            0 => InjectOutcome::Injected,
                            1 => InjectOutcome::Backpressured,
                            _ => InjectOutcome::Rejected(TunRejectReason::InvalidDestination),
                        }
                    });
                }
            }
            3 => reset_table(
                &mut table,
                &mut generation,
                &mut associations,
                &mut stale_sinks,
            ),
            4 => {
                let association_index = usize::from(source_selector) % associations.len().max(1);
                if let Some(association) = associations.get_mut(association_index) {
                    let first_target = association.first_target();
                    let endpoints = UdpDatagramEndpoints::new(
                        association.source(),
                        target(source_selector, target_selector),
                    );
                    let admission = table.admit(endpoints, frame, frame.len(), now_millis, true);
                    if matches!(admission, Admission::Mapped | Admission::CandidateQueued) {
                        let datagram = association
                            .receive()
                            .await
                            .expect("accepted mapped datagram remains queued");
                        assert_eq!(datagram.source(), association.source());
                        assert_ne!(datagram.target().port(), 0);
                        assert_eq!(association.first_target(), first_target);
                    }
                }
            }
            5 => {
                if !associations.is_empty() {
                    let index = usize::from(source_selector) % associations.len();
                    let association = associations.swap_remove(index);
                    retain_stale_sink(&mut stale_sinks, association.response_sink());
                    drop(association);
                    let _ = table.process_one_control(now_millis, true);
                }
            }
            6 => {
                for _ in 0..=capacity {
                    if table
                        .process_one_control(now_millis, policy & 0x80 == 0)
                        .is_none()
                    {
                        break;
                    }
                }
                let outcome = table.process_one_response(now_millis, |_, _| {
                    if policy & 1 == 0 {
                        InjectOutcome::Injected
                    } else {
                        InjectOutcome::Backpressured
                    }
                });
                assert!(matches!(
                    outcome,
                    ResponseProcessOutcome::Idle
                        | ResponseProcessOutcome::Injected
                        | ResponseProcessOutcome::Deferred
                        | ResponseProcessOutcome::Dropped(_)
                ));
            }
            _ => {
                now_millis = now_millis.saturating_add(i64::from(policy).saturating_mul(1_000));
                let _ = table.expire(now_millis);
                let _ = table.next_deadline_millis();
            }
        }

        assert!(table.active_associations() <= capacity);
        assert!(associations.len() <= capacity);
        assert!(ordinal < MAX_STEPS);
        assert!(
            wake_count.load(Ordering::Relaxed) <= (ordinal + 1).saturating_mul(8).saturating_add(8)
        );
    }

    reset_table(
        &mut table,
        &mut generation,
        &mut associations,
        &mut stale_sinks,
    );
    drain_stale_candidates(&mut table, &mut candidates).await;
    assert_reclaimed(&mut table);

    for slot in 0..capacity {
        let source_selector = u8::try_from(slot).unwrap_or_default();
        assert_eq!(
            table.admit(
                endpoints(source_selector, source_selector),
                b"fresh",
                5,
                now_millis,
                true,
            ),
            Admission::Provisional,
            "reset must restore every admission slot"
        );
    }
    generation = next_generation(generation);
    table.invalidate_session(generation, UdpResponseDropReason::SessionReset);
    drain_stale_candidates(&mut table, &mut candidates).await;
    assert_reclaimed(&mut table);

    for sink in stale_sinks {
        assert!(matches!(
            sink.send(target(0, 0), b"late"),
            UdpResponseSendOutcome::StaleGeneration | UdpResponseSendOutcome::Closed
        ));
    }
}

fn reset_table(
    table: &mut UdpTable,
    generation: &mut u64,
    associations: &mut Vec<UdpAssociation>,
    stale_sinks: &mut VecDeque<crate::udp::UdpResponseSink>,
) {
    for association in associations.iter() {
        retain_stale_sink(stale_sinks, association.response_sink());
    }
    *generation = next_generation(*generation);
    table.invalidate_session(*generation, UdpResponseDropReason::SessionReset);
    associations.clear();
    assert_reclaimed(table);
}

async fn drain_stale_candidates(
    table: &mut UdpTable,
    candidates: &mut tokio::sync::mpsc::Receiver<crate::udp::UdpCandidate>,
) {
    while let Ok(candidate) = candidates.try_recv() {
        assert!(matches!(
            candidate.commit_association().await,
            Err(UdpCommitError::Rejected | UdpCommitError::Unavailable)
        ));
    }
    while table.process_one_control(0, true).is_some() {}
}

fn assert_reclaimed(table: &mut UdpTable) {
    assert_eq!(table.active_associations(), 0);
    assert!(!table.has_pending_response());
    assert_eq!(table.next_deadline_millis(), None);
}

fn retain_stale_sink(
    stale_sinks: &mut VecDeque<crate::udp::UdpResponseSink>,
    sink: crate::udp::UdpResponseSink,
) {
    if stale_sinks.len() == MAX_RETAINED_STALE_SINKS {
        stale_sinks.pop_front();
    }
    stale_sinks.push_back(sink);
}

fn next_generation(generation: u64) -> u64 {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

fn endpoints(source_selector: u8, target_selector: u8) -> UdpDatagramEndpoints {
    UdpDatagramEndpoints::new(
        source(source_selector),
        target(source_selector, target_selector),
    )
}

fn source(selector: u8) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(10, 0, selector / 254, selector % 254 + 1),
        10_000 + u16::from(selector),
    ))
}

fn target(source_selector: u8, target_selector: u8) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(198, 51, 100, target_selector % 254 + 1),
        20_000 + u16::from(source_selector ^ target_selector),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_sequences_cover_reset_before_and_after_commit() {
        for input in [
            &b"\x01\x00\x00\x00\x00\x01\x01\x00\x01\x00\x00\x80"[..],
            &b"\x82\x00\x00\x00\x01\x00\x00\x80\x03\x00\x00\x00"[..],
            &b"\x04\x01\x02\x00\x01\x01\x02\x00\x02\x01\x02\x00\x03\x00\x00\x00"[..],
        ] {
            fuzz_udp_reset_races(input);
        }
    }

    #[test]
    fn oversized_input_is_rejected_without_allocating_runtime_state() {
        fuzz_udp_reset_races(&vec![0; MAX_UDP_RESET_FUZZ_INPUT_BYTES + 1]);
    }
}
