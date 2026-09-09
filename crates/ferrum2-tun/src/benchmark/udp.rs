//! Independent detail recipe `udp-table-v1` (not part of the v2 primary).
//! Quick: 8 active/8 slots/64-byte payloads/128 windows. Confirm:
//! 32 active/64 slots/1360-byte payloads/64 windows. Each fresh window has
//! 128 ordered payloads per association. Payload byte j is (association*17 +
//! sequence*31 + j) modulo 256, with the first 16 bytes encoding both indices.
//! Accepted recipes run 16 rounds of eight datagrams per association in each
//! direction. Congestion recipes run 256 rejected attempts per association,
//! with queues filled before timing. All setup, content/outcome checks, expiry,
//! and release checks are untimed. Captures are preallocated; production payload
//! allocation and response capture copying remain included in measured cost.

use super::recipe::endpoints;
use crate::udp::{
    Admission, InjectOutcome, ResponseProcessOutcome, UdpDatagramEndpoints, UdpTable,
};
use crate::{OwnerWake, UdpAssociation, UdpDatagram, UdpFiltering, UdpResponseSendOutcome};
use ferrum2_runtime::{OwnerRegistry, UdpBufferBudget};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const IDLE: i64 = 30_000;
const ROUNDS: usize = 16;
const BURST: usize = 8;

pub(super) fn trial(scenario: &str, mode: &str) -> Result<String, &'static str> {
    if !matches!(
        scenario,
        "udp-deadline-same"
            | "udp-deadline-advance"
            | "udp-ingress-full"
            | "udp-response-full"
            | "udp-consumer-lag"
    ) {
        return Err("unknown scenario");
    }
    let (active, capacity, bytes, windows) = match mode {
        "Quick" => (8, 8, 64, 128),
        "Confirm" => (32, 64, 1360, 64),
        _ => return Err("unknown mode"),
    };
    let diagnostic = run(scenario, active, capacity, bytes, false);
    let mut elapsed = 0;
    for _ in 0..windows {
        let result = run(scenario, active, capacity, bytes, true);
        assert_eq!(result.1, diagnostic.1);
        assert_eq!(result.2, diagnostic.2);
        elapsed += result.0;
    }
    let checked = diagnostic.1 * windows;
    let rejected = diagnostic.2 * windows;
    let accepted = checked - rejected;
    let deferred = if scenario == "udp-consumer-lag" {
        ROUNDS * 4 * windows
    } else {
        0
    };
    Ok(format!(
        "{{\"schema_version\":1,\"kind\":\"ferrum2.tun-detail.trial\",\"scenario\":\"{scenario}\",\"mode\":\"{mode}\",\"checked_units\":{checked},\"elapsed_nanoseconds\":{elapsed},\"unit\":\"datagram_attempt\",\"recipe_id\":\"udp-table-v1/{scenario}/{mode}\",\"observation\":{{\"active_associations\":{active},\"table_capacity\":{capacity},\"payload_bytes\":{bytes},\"timed_windows\":{windows},\"accepted_units\":{accepted},\"rejected_units\":{rejected},\"deferred_response_attempts\":{deferred}}}}}"
    ))
}

struct Fixture {
    table: UdpTable,
    associations: Vec<UdpAssociation>,
    endpoints: Vec<UdpDatagramEndpoints>,
    payloads: Vec<Vec<Vec<u8>>>,
    budget: UdpBufferBudget,
}

impl Fixture {
    fn new(active: usize, capacity: usize, bytes: usize) -> Self {
        let budget = UdpBufferBudget::new_tun(32 * 1024 * 1024, OwnerRegistry::new());
        let (mut table, mut candidates) = UdpTable::with_options(
            capacity,
            Duration::from_millis(IDLE as u64),
            UdpFiltering::EndpointIndependent,
            1,
            OwnerWake::default(),
        );
        table.set_buffer_budget(budget.clone());
        let endpoints: Vec<_> = (0..active)
            .map(|index| {
                let (source, target) = endpoints(false, index);
                UdpDatagramEndpoints::new(source, target)
            })
            .collect();
        let payloads: Vec<Vec<Vec<u8>>> = (0..active)
            .map(|association| {
                (0..ROUNDS * BURST)
                    .map(|sequence| {
                        let mut payload: Vec<u8> = (0..bytes)
                            .map(|j| (association * 17 + sequence * 31 + j) as u8)
                            .collect();
                        payload[..8].copy_from_slice(&(association as u64).to_le_bytes());
                        payload[8..16].copy_from_slice(&(sequence as u64).to_le_bytes());
                        payload
                    })
                    .collect()
            })
            .collect();
        let mut associations = Vec::with_capacity(active);
        for index in 0..active {
            assert_eq!(
                table.admit(endpoints[index], &payloads[index][0], bytes, 0, true),
                Admission::Provisional
            );
            let candidate = candidates.try_recv().expect("candidate publication");
            assert_eq!(candidate.source(), endpoints[index].source());
            assert_eq!(candidate.first_target(), endpoints[index].target());
            assert_eq!(candidate.first_payload(), payloads[index][0]);
            let mut future = pin!(candidate.commit_association());
            let mut context = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut context).is_pending());
            assert_eq!(table.process_one_control(0, true), Some(true));
            let Poll::Ready(Ok(mut association)) = future.as_mut().poll(&mut context) else {
                panic!("commit must resolve");
            };
            check_datagram(
                &receive(&mut association),
                endpoints[index],
                &payloads[index][0],
            );
            associations.push(association);
        }
        assert_eq!(table.active_associations(), active);
        assert_eq!(budget.reserved_bytes(), 0);
        Self {
            table,
            associations,
            endpoints,
            payloads,
            budget,
        }
    }

    fn finish(mut self, last_refresh: i64) {
        let active = self.associations.len();
        assert!(!self.table.has_pending_response());
        assert_eq!(self.table.next_deadline_millis(), Some(last_refresh + IDLE));
        assert_eq!(self.table.expire(last_refresh + IDLE - 1).associations, 0);
        assert_eq!(self.table.active_associations(), active);
        let expired = self.table.expire(last_refresh + IDLE);
        assert_eq!(expired.candidates, 0);
        assert_eq!(expired.associations, active);
        assert_eq!(self.table.active_associations(), 0);
        assert_eq!(self.table.next_deadline_millis(), None);
        for association in &mut self.associations {
            let mut future = pin!(association.receive());
            assert!(matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(None)
            ));
        }
        self.associations.clear();
        while let Some(committed) = self.table.process_one_control(last_refresh + IDLE, true) {
            assert!(!committed);
        }
        drop(self.table);
        assert_eq!(self.budget.reserved_bytes(), 0);
    }
}

fn receive(association: &mut UdpAssociation) -> UdpDatagram {
    let mut future = pin!(association.receive());
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Some(datagram)) => datagram,
        _ => panic!("queued datagram must be available"),
    }
}

fn check_datagram(datagram: &UdpDatagram, endpoints: UdpDatagramEndpoints, payload: &[u8]) {
    assert_eq!(datagram.source(), endpoints.source());
    assert_eq!(datagram.target(), endpoints.target());
    assert_eq!(datagram.payload(), payload);
}

struct Capture {
    endpoints: UdpDatagramEndpoints,
    payload: Vec<u8>,
}

fn inject(table: &mut UdpTable, now: i64, capture: &mut Capture) -> ResponseProcessOutcome {
    table.process_one_response(now, |endpoints, payload| {
        capture.endpoints = endpoints;
        capture.payload.extend_from_slice(payload);
        InjectOutcome::Injected
    })
}

fn run(
    scenario: &str,
    active: usize,
    capacity: usize,
    bytes: usize,
    measuring: bool,
) -> (u128, usize, usize) {
    let mut fixture = Fixture::new(active, capacity, bytes);
    let full_ingress = scenario == "udp-ingress-full";
    let full_response = scenario == "udp-response-full";
    let lag = scenario == "udp-consumer-lag";
    let full = full_ingress || full_response;
    let delivered = if full_ingress {
        active * BURST
    } else if full_response {
        capacity * BURST
    } else {
        active * ROUNDS * BURST
    };
    let mut ingress = Vec::with_capacity(delivered);
    let mut responses: Vec<_> = (0..delivered)
        .map(|_| Capture {
            endpoints: fixture.endpoints[0],
            payload: Vec::with_capacity(bytes),
        })
        .collect();
    let mut admissions = Vec::with_capacity(if full {
        active * 256
    } else {
        delivered + ROUNDS * active * 2
    });
    let mut sends = Vec::with_capacity(if full { active * 256 } else { delivered });
    let mut processed = Vec::with_capacity(delivered + ROUNDS * 4);
    if full {
        for index in 0..delivered {
            let association = index % active;
            let sequence = index / active;
            if full_ingress {
                assert_eq!(
                    fixture.table.admit(
                        fixture.endpoints[association],
                        &fixture.payloads[association][sequence],
                        bytes,
                        0,
                        true
                    ),
                    Admission::Mapped
                );
            } else {
                assert_eq!(
                    fixture.associations[association].send_response(
                        fixture.endpoints[association].target(),
                        &fixture.payloads[association][sequence]
                    ),
                    UdpResponseSendOutcome::Queued
                );
            }
        }
    }
    let start = measuring.then(Instant::now);
    if full {
        for sequence in 0..256 {
            for association in 0..active {
                if full_ingress {
                    admissions.push(fixture.table.admit(
                        fixture.endpoints[association],
                        &fixture.payloads[association][sequence % 128],
                        bytes,
                        1,
                        true,
                    ));
                } else {
                    sends.push(fixture.associations[association].send_response(
                        fixture.endpoints[association].target(),
                        &fixture.payloads[association][sequence % 128],
                    ));
                }
            }
        }
    } else {
        let mut captured = 0;
        for round in 0..ROUNDS {
            for offset in 0..BURST {
                let sequence = round * BURST + offset;
                let now = if scenario == "udp-deadline-advance" {
                    sequence as i64 + 1
                } else {
                    1
                };
                for association in 0..active {
                    admissions.push(fixture.table.admit(
                        fixture.endpoints[association],
                        &fixture.payloads[association][sequence],
                        bytes,
                        now,
                        true,
                    ));
                    sends.push(fixture.associations[association].send_response(
                        fixture.endpoints[association].target(),
                        &fixture.payloads[association][sequence],
                    ));
                    if !lag {
                        ingress.push(receive(&mut fixture.associations[association]));
                        processed.push(inject(&mut fixture.table, now, &mut responses[captured]));
                        captured += 1;
                    }
                }
            }
            if lag {
                for _ in 0..2 {
                    for association in 0..active {
                        admissions.push(fixture.table.admit(
                            fixture.endpoints[association],
                            &fixture.payloads[association][0],
                            bytes,
                            1,
                            true,
                        ));
                    }
                }
                for _ in 0..4 {
                    processed.push(
                        fixture
                            .table
                            .process_one_response(1, |_, _| InjectOutcome::Backpressured),
                    );
                }
                for _ in 0..BURST {
                    for association in 0..active {
                        ingress.push(receive(&mut fixture.associations[association]));
                        processed.push(inject(&mut fixture.table, 1, &mut responses[captured]));
                        captured += 1;
                    }
                }
            }
        }
    }
    let elapsed = start.map_or(0, |start| start.elapsed().as_nanos());
    let checked = admissions.len() + sends.len();
    let rejected = if full {
        active * 256
    } else if lag {
        ROUNDS * active * 2
    } else {
        0
    };
    if full {
        assert!(
            admissions
                .iter()
                .all(|outcome| *outcome == Admission::Dropped)
        );
        assert!(
            sends
                .iter()
                .all(|outcome| *outcome == UdpResponseSendOutcome::QueueFull)
        );
        for (index, response) in responses.iter_mut().enumerate() {
            if full_ingress {
                ingress.push(receive(&mut fixture.associations[index % active]));
            } else {
                assert_eq!(
                    inject(&mut fixture.table, 0, response),
                    ResponseProcessOutcome::Injected
                );
            }
        }
    } else {
        for (index, outcome) in admissions.iter().enumerate() {
            let rejected = lag && index % (active * 10) >= active * BURST;
            assert_eq!(
                *outcome,
                if rejected {
                    Admission::Dropped
                } else {
                    Admission::Mapped
                }
            );
        }
        assert!(
            sends
                .iter()
                .all(|outcome| *outcome == UdpResponseSendOutcome::Queued)
        );
        for (index, outcome) in processed.iter().enumerate() {
            let deferred = lag && index % (active * BURST + 4) < 4;
            assert_eq!(
                *outcome,
                if deferred {
                    ResponseProcessOutcome::Deferred
                } else {
                    ResponseProcessOutcome::Injected
                }
            );
        }
    }
    for index in 0..delivered {
        let association = index % active;
        let sequence = index / active;
        let endpoints = fixture.endpoints[association];
        let payload = &fixture.payloads[association][sequence];
        if !full_response {
            check_datagram(&ingress[index], endpoints, payload);
        }
        if !full_ingress {
            assert_eq!(responses[index].endpoints, endpoints);
            assert_eq!(&responses[index].payload, payload);
        }
    }
    assert_eq!(
        fixture
            .table
            .process_one_response(1, |_, _| panic!("unexpected response")),
        ResponseProcessOutcome::Idle
    );
    for association in &mut fixture.associations {
        let mut future = pin!(association.receive());
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    drop(ingress);
    assert_eq!(fixture.budget.reserved_bytes(), 0);
    let last_refresh = if full {
        0
    } else if scenario == "udp-deadline-advance" {
        (ROUNDS * BURST) as i64
    } else {
        1
    };
    fixture.finish(last_refresh);
    (elapsed, checked, rejected)
}
