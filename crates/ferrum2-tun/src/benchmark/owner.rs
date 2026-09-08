use super::recipe::MTU;
use crate::packet::{Families, PacketParser, ParsedPacket, TransportMetadata};
use crate::scheduler::{FairScheduler, StepOutcome, WorkStage};
use crate::stack::{OutputFlushOutcome, OutputSendOutcome, Stack};
use crate::system_tcp::PortQuarantine;
use crate::{OwnerWake, UdpAssociation, UdpCandidate, UdpFiltering};
use ferrum2_runtime::{OwnerRegistry, UdpBufferBudget};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

pub(super) struct Owner {
    pub stack: Stack,
    pub candidates: tokio::sync::mpsc::Receiver<UdpCandidate>,
    pub flows: tokio::sync::mpsc::Receiver<crate::TcpFlow>,
    budget: UdpBufferBudget,
    scheduler: FairScheduler,
    pub now: i64,
    pub input: usize,
    pub output: usize,
    pub rejected: usize,
    pub peak: usize,
    pub deferred: Arc<AtomicUsize>,
    pub measuring: bool,
    capture_enabled: bool,
    capture_bytes: usize,
    pub capture: Vec<Vec<u8>>,
    pub received: Vec<crate::UdpDatagram>,
    pub stage_visits: [usize; 6],
}

impl Owner {
    pub fn new(states: usize) -> Self {
        let registry = OwnerRegistry::new();
        let budget = UdpBufferBudget::new_tun(states * MTU * 32, registry.clone());
        let (mut stack, flows, candidates) = Stack::new_with_udp(
            (
                Some(("198.18.0.1".parse().expect("fixture"), 30)),
                Some(("2001:db8:ffff::1".parse().expect("fixture"), 126)),
            ),
            MTU,
            states,
            Duration::from_secs(30),
            Arc::new(AtomicUsize::new(0)),
            registry,
            states,
            Duration::from_secs(30),
            UdpFiltering::EndpointIndependent,
            0,
            OwnerWake::default(),
            Arc::new(Mutex::new(PortQuarantine::default())),
        )
        .expect("bounded stack");
        #[cfg(not(test))]
        stack.configure_packet_bindings();
        stack.set_udp_buffer_budget(budget.clone());
        let deferred = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&deferred);
        stack.set_event_sink(crate::TunEventSink::new(move |event| {
            if event == crate::TunEvent::InternalEgressBackpressured {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
        let mut owner = Self {
            stack,
            candidates,
            flows,
            budget,
            scheduler: FairScheduler::default(),
            now: 0,
            input: 0,
            output: 0,
            rejected: 0,
            peak: 0,
            deferred,
            measuring: false,
            capture_enabled: false,
            capture_bytes: 0,
            capture: Vec::new(),
            received: Vec::new(),
            stage_visits: [0; 6],
        };
        owner.sample();
        owner
    }

    pub fn begin_capture(&mut self, outputs: usize, inputs: usize, measuring: bool) {
        self.capture = (0..outputs).map(|_| Vec::with_capacity(MTU)).collect();
        self.capture_bytes = self.capture.iter().map(Vec::capacity).sum();
        self.received = Vec::with_capacity(inputs);
        self.capture_enabled = true;
        self.sample();
        self.measuring = measuring;
    }

    pub fn sample(&mut self) {
        if self.measuring {
            return;
        }
        self.peak = self.peak.max(
            self.stack.device.owned_packet_bytes()
                + self.stack.reassembly.owned_packet_bytes()
                + self.budget.reserved_bytes()
                + self.capture_bytes,
        );
    }

    pub fn enqueue(&mut self, packet: &[u8]) {
        self.input += 1;
        if !self.stack.enqueue_at(packet, true, self.now) {
            self.rejected += 1;
        }
        self.sample();
    }

    pub fn commit(&mut self) -> UdpAssociation {
        let candidate = self.candidates.try_recv().expect("candidate publication");
        let mut future = pin!(candidate.commit_association());
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert!(
            self.stack
                .process_owner_control_stage(self.now, true, false)
        );
        let Poll::Ready(Ok(association)) = future.as_mut().poll(&mut context) else {
            panic!("owner commit must resolve");
        };
        self.sample();
        association
    }

    pub fn receive(
        &mut self,
        association: &mut UdpAssociation,
        target: SocketAddr,
        payload: &[u8],
    ) {
        let mut future = pin!(association.receive());
        let Poll::Ready(Some(datagram)) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("admitted datagram must be published");
        };
        if !self.measuring {
            assert_eq!(datagram.target(), target);
            assert_eq!(datagram.payload(), payload);
        }
        if self.capture_enabled {
            self.received.push(datagram);
        }
    }

    /// A bounded packet sink drains only when the owner is granted a consumer turn.
    /// Withheld turns retain the actual MemoryDevice output slot and force real
    /// ingress/UDP-response backpressure; no always-ready echo is substituted.
    pub fn turn(&mut self, drain: bool, verify: &mut impl FnMut(&[u8])) -> usize {
        let mut scheduler = std::mem::take(&mut self.scheduler);
        let outcome = scheduler.run_budget(64, |stage| {
            if !self.measuring {
                let index = match stage {
                    WorkStage::Control => 0,
                    WorkStage::FlushOutput => 1,
                    WorkStage::Stack => 2,
                    WorkStage::Receive => 3,
                    WorkStage::UdpResponse => 4,
                    WorkStage::Expire => 5,
                };
                self.stage_visits[index] += 1;
            }
            let step = match stage {
                WorkStage::Receive => StepOutcome::Idle,
                WorkStage::FlushOutput if drain => match self.stack.flush_output(|packet| {
                    if !self.measuring {
                        verify(packet);
                    }
                    if self.capture_enabled {
                        let Some(slot) = self.capture.get_mut(self.output) else {
                            return OutputSendOutcome::DroppedRingFull;
                        };
                        if packet.len() > slot.capacity() {
                            return OutputSendOutcome::Fatal;
                        }
                        slot.extend_from_slice(packet);
                    }
                    OutputSendOutcome::Sent
                }) {
                    OutputFlushOutcome::Empty => StepOutcome::Idle,
                    OutputFlushOutcome::Sent => {
                        self.output += 1;
                        StepOutcome::Worked
                    }
                    OutputFlushOutcome::DroppedRingFull => {
                        self.rejected += 1;
                        StepOutcome::Fatal
                    }
                    OutputFlushOutcome::Fatal => StepOutcome::Fatal,
                },
                WorkStage::FlushOutput => StepOutcome::Idle,
                _ => self
                    .stack
                    .owner_internal_step(stage, self.now, true)
                    .expect("internal stage"),
            };
            self.sample();
            step
        });
        self.scheduler = scheduler;
        assert!(!outcome.fatal);
        outcome.work_units
    }

    pub fn drain(&mut self, verify: &mut impl FnMut(&[u8])) {
        for _ in 0..64 {
            if self.turn(true, verify) == 0 {
                // Model the owner's idle decision without invoking an OS wait.
                std::hint::black_box(self.stack.next_wait_duration(self.now));
                return;
            }
        }
        panic!("bounded owner failed to make progress");
    }

    pub fn clear_observations(&mut self) {
        self.input = 0;
        self.output = 0;
        self.rejected = 0;
    }
}

pub(super) fn validate(packet: &[u8], source: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let parsed = parse(packet);
    let (source_port, target_port, header) = match parsed.transport {
        TransportMetadata::Tcp(tcp) => (tcp.source_port, tcp.destination_port, 20),
        TransportMetadata::Udp(udp) => (udp.source_port, udp.destination_port, 8),
    };
    assert_eq!(SocketAddr::new(parsed.source, source_port), source);
    assert_eq!(SocketAddr::new(parsed.destination, target_port), target);
    assert_eq!(&packet[parsed.transport_offset + header..], payload);
}
pub(super) fn parse(packet: &[u8]) -> crate::packet::ParsedIpPacket {
    let Ok(ParsedPacket::Complete(parsed)) = PacketParser::new(Families {
        ipv4: true,
        ipv6: true,
    })
    .parse(packet) else {
        panic!("output must satisfy canonical checksums and lengths");
    };
    parsed
}
