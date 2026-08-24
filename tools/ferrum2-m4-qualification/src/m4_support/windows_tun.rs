use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const TCP_SINGLE_WARMUP: Duration = Duration::from_secs(10);
const TCP_SINGLE_ACTIVE: Duration = Duration::from_secs(60);
const TCP_SINGLE_PAYLOAD: usize = 65_536;
const TCP_SINGLE_MINIMUM_BYTES: u64 = 64 * 1024 * 1024;
const TCP_FAIRNESS_WARMUP: Duration = Duration::from_secs(10);
const TCP_FAIRNESS_ACTIVE: Duration = Duration::from_secs(30);
const TCP_FAIRNESS_FLOWS: usize = 256;
const TCP_FAIRNESS_PAYLOAD: usize = 16_384;
const TCP_FAIRNESS_READINESS_PAYLOAD: usize = 1_024;
const UDP_WARMUP: Duration = Duration::from_secs(5);
const UDP_ACTIVE: Duration = Duration::from_secs(30);
const UDP_PAYLOAD: usize = 1_200;
const UDP_BATCH: usize = 8;
const UDP_MINIMUM_DATAGRAMS: u64 = 4_096;
const ASSOCIATIONS: usize = 8_192;
const ASSOCIATION_BOOTSTRAP_BATCH: usize = 1;
const ASSOCIATION_BOOTSTRAP_PACING_ASSOCIATIONS: usize = 8;
const ASSOCIATION_BOOTSTRAP_PACING_DELAY: Duration = Duration::from_millis(25);
const ASSOCIATION_LOOKUP_BATCH: usize = 8;
const ASSOCIATION_LOOKUP_ROUNDS: usize = 64;
const ASSOCIATION_WARMUP: Duration = Duration::from_secs(5);
const FRAGMENT_WARMUP: Duration = Duration::from_secs(5);
const FRAGMENT_ACTIVE: Duration = Duration::from_secs(30);
const FRAGMENT_PAYLOAD: usize = 1_440;
const FRAGMENT_BATCH: usize = 8;
const FRAGMENT_MINIMUM_DATAGRAMS: u64 = 4_096;
const FRAGMENT_ACK_WINDOW: Duration = Duration::from_millis(500);
const FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS: u64 = 1_000_000;
const FRAGMENT_REQUEST_TAG: [u8; 8] = *b"F2FRQ001";
const FRAGMENT_ACK_TAG: [u8; 8] = *b"F2FAK001";
const FRAGMENT_ACK_LEN: usize = 24;
const FRAGMENT_REPLY_BUFFER: usize = FRAGMENT_ACK_LEN + 1;
const PERFORMANCE_TUN_MTU: usize = 1_420;
const SUPPORT_UNDERLAY_IPV4_MTU: usize = 1_500;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const FRAGMENT_IPV4_RESPONSE_BOUND: usize = PERFORMANCE_TUN_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;
const RING_BURST_ATTEMPTS: u64 = 1_000_000;
const ROUTE_SOURCE_SLOTS: usize = 64;
const ROUTE_TARGET_SLOTS: usize = 4;
const ROUTE_DATAGRAMS_PER_TARGET: usize = 32;
const ROUTE_PAYLOAD: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const SUPPORT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const SUPPORT_MAX_TCP_CONNECTIONS: usize = 1_024;
const UDP_DIAGNOSTIC_PAYLOAD_LEN: usize = 32;
const UDP_DIAGNOSTIC_MAGIC: [u8; 4] = *b"F2U1";
const UDP_DIAGNOSTIC_VERSION: u8 = 1;
const UDP_DIAGNOSTIC_MAX_EVENTS: usize = 65_536;
const UDP_DIAGNOSTIC_MAX_EVENT_BYTES: usize = 4 * 1024;
const UDP_DIAGNOSTIC_SCOPE: &str = "bootstrap";
const UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE: u16 = 31;
const UDP_DIAGNOSTIC_SOURCE_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const UDP_DIAGNOSTIC_SOURCE_PORT_FIRST: u16 = 20_000;
const UDP_DIAGNOSTIC_SOURCE_PORT_LAST: u16 = 28_191;
const UDP_WORKLOAD_DIAGNOSTIC_CLOSURE: &str = "workload_process_exit";
const UDP_SUPPORT_DIAGNOSTIC_CLOSURE: &str = "host_four_port_barrier_after_vm_off";
const UDP_WORKLOAD_LEDGER_SCHEMA: &str = "ferrum2.windows-tun.udp-workload-flow-ledger.v3";
const UDP_SUPPORT_LEDGER_SCHEMA: &str = "ferrum2.windows-tun.udp-support-ledger.v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum UdpDiagnosticPhase {
    Bootstrap = 1,
    Warmup = 2,
    Lookup = 3,
    Refresh = 4,
    Finalize = 5,
}

impl UdpDiagnosticPhase {
    fn parse(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Bootstrap),
            2 => Some(Self::Warmup),
            3 => Some(Self::Lookup),
            4 => Some(Self::Refresh),
            5 => Some(Self::Finalize),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Warmup => "warmup",
            Self::Lookup => "lookup",
            Self::Refresh => "refresh",
            Self::Finalize => "finalize",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpDiagnosticPayload {
    phase: UdpDiagnosticPhase,
    trial_sequence: u16,
    association_index: u32,
    round: u32,
    run_nonce: u64,
    packet_nonce: u64,
}

impl UdpDiagnosticPayload {
    fn encode(self) -> [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN] {
        let mut payload = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
        payload[..4].copy_from_slice(&UDP_DIAGNOSTIC_MAGIC);
        payload[4] = UDP_DIAGNOSTIC_VERSION;
        payload[5] = self.phase as u8;
        payload[6..8].copy_from_slice(&self.trial_sequence.to_be_bytes());
        payload[8..12].copy_from_slice(&self.association_index.to_be_bytes());
        payload[12..16].copy_from_slice(&self.round.to_be_bytes());
        payload[16..24].copy_from_slice(&self.run_nonce.to_be_bytes());
        payload[24..32].copy_from_slice(&self.packet_nonce.to_be_bytes());
        payload
    }

    fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() != UDP_DIAGNOSTIC_PAYLOAD_LEN
            || !payload.starts_with(&UDP_DIAGNOSTIC_MAGIC)
            || payload[4] != UDP_DIAGNOSTIC_VERSION
        {
            return None;
        }
        let parsed = Self {
            phase: UdpDiagnosticPhase::parse(payload[5])?,
            trial_sequence: u16::from_be_bytes(payload[6..8].try_into().ok()?),
            association_index: u32::from_be_bytes(payload[8..12].try_into().ok()?),
            round: u32::from_be_bytes(payload[12..16].try_into().ok()?),
            run_nonce: u64::from_be_bytes(payload[16..24].try_into().ok()?),
            packet_nonce: u64::from_be_bytes(payload[24..32].try_into().ok()?),
        };
        (parsed.trial_sequence != 0 && parsed.run_nonce != 0).then_some(parsed)
    }
}

fn udp_diagnostic_finalize_marker(run_nonce: u64) -> UdpDiagnosticPayload {
    UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Finalize,
        trial_sequence: UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE,
        association_index: u32::MAX,
        round: u32::MAX,
        run_nonce,
        packet_nonce: u64::MAX,
    }
}

fn is_udp_diagnostic_finalize_marker(identity: UdpDiagnosticPayload, run_nonce: u64) -> bool {
    identity == udp_diagnostic_finalize_marker(run_nonce)
}

#[derive(Clone, Debug)]
struct UdpDiagnosticLedgerArgs {
    path: PathBuf,
    run_nonce: u64,
    max_events: usize,
}

#[derive(Clone, Debug)]
struct UdpWorkloadDiagnosticArgs {
    ledger: UdpDiagnosticLedgerArgs,
    trial_sequence: u16,
    source_ip: IpAddr,
    source_port_first: u16,
    source_port_last: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpDiagnosticFinalizeArgs {
    target_ip: IpAddr,
    udp_port: u16,
    run_nonce: u64,
}

struct BoundedUdpDiagnosticLedger {
    schema: &'static str,
    run_nonce: u64,
    state: Mutex<UdpDiagnosticLedgerState>,
    started: Instant,
    max_events: usize,
    reported_limit: AtomicBool,
    reported_write_failure: AtomicBool,
    report_degradation: bool,
}

struct UdpDiagnosticLedgerState {
    writer: File,
    attempted_events: usize,
    events_written: usize,
    dropped_events: usize,
    write_failures: usize,
    truncation_written: bool,
    writer_failed: bool,
    closed: bool,
}

impl BoundedUdpDiagnosticLedger {
    fn create(
        arguments: &UdpDiagnosticLedgerArgs,
        schema: &'static str,
        metadata: Value,
    ) -> Result<Self, String> {
        Self::create_with_reporting(arguments, schema, metadata, true)
    }

    fn create_with_reporting(
        arguments: &UdpDiagnosticLedgerArgs,
        schema: &'static str,
        metadata: Value,
        report_degradation: bool,
    ) -> Result<Self, String> {
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&arguments.path)
            .map_err(|error| format!("create Windows TUN UDP diagnostic ledger failed: {error}"))?;
        let mut header = json!({
            "schema": schema,
            "record_type": "header",
            "run_nonce": arguments.run_nonce.to_string(),
            "max_events": arguments.max_events,
            "timestamp_clock": "std_instant_normalized_nanoseconds"
        });
        let header_object = header
            .as_object_mut()
            .expect("diagnostic ledger header is an object");
        let metadata = metadata
            .as_object()
            .ok_or_else(|| "Windows TUN UDP ledger metadata must be an object".to_owned())?;
        for (key, value) in metadata {
            if header_object.insert(key.clone(), value.clone()).is_some() {
                return Err(
                    "Windows TUN UDP ledger metadata key conflicts with the header".to_owned(),
                );
            }
        }
        let mut encoded = serde_json::to_vec(&header)
            .map_err(|error| format!("serialize Windows TUN UDP ledger header failed: {error}"))?;
        encoded.push(b'\n');
        writer
            .write_all(&encoded)
            .and_then(|()| writer.flush())
            .map_err(|error| format!("write Windows TUN UDP ledger header failed: {error}"))?;
        Ok(Self {
            schema,
            run_nonce: arguments.run_nonce,
            state: Mutex::new(UdpDiagnosticLedgerState {
                writer,
                attempted_events: 0,
                events_written: 0,
                dropped_events: 0,
                write_failures: 0,
                truncation_written: false,
                writer_failed: false,
                closed: false,
            }),
            started: Instant::now(),
            max_events: arguments.max_events,
            reported_limit: AtomicBool::new(false),
            reported_write_failure: AtomicBool::new(false),
            report_degradation,
        })
    }

    fn record(&self, mut event: Value) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return;
        }
        let event_index = state.attempted_events;
        state.attempted_events = state.attempted_events.saturating_add(1);
        if event_index >= self.max_events {
            state.dropped_events = state.dropped_events.saturating_add(1);
            let mut truncation_write_failed = false;
            if !state.truncation_written && !state.writer_failed {
                state.truncation_written = true;
                let truncation = json!({
                    "schema": self.schema,
                    "record_type": "truncation",
                    "run_nonce": self.run_nonce.to_string(),
                    "attempted_events": state.attempted_events,
                    "events_written": state.events_written,
                    "dropped_events_at_least": state.dropped_events,
                    "write_failures": state.write_failures
                });
                let write_result = serde_json::to_vec(&truncation)
                    .map(|mut encoded| {
                        encoded.push(b'\n');
                        encoded
                    })
                    .map_err(std::io::Error::other)
                    .and_then(|encoded| state.writer.write_all(&encoded))
                    .and_then(|()| state.writer.flush());
                if write_result.is_err() {
                    state.write_failures = state.write_failures.saturating_add(1);
                    state.writer_failed = true;
                    truncation_write_failed = true;
                }
            }
            drop(state);
            if truncation_write_failed {
                self.report_write_failure("truncation_write");
            }
            if self.report_degradation && !self.reported_limit.swap(true, Ordering::AcqRel) {
                eprintln!("windows_tun_udp_diagnostic_ledger status=TRUNCATED reason=max_events");
            }
            return;
        }
        if state.writer_failed {
            state.dropped_events = state.dropped_events.saturating_add(1);
            return;
        }
        let Some(object) = event.as_object_mut() else {
            state.write_failures = state.write_failures.saturating_add(1);
            drop(state);
            self.report_write_failure("invalid_event");
            return;
        };
        object.insert("schema".to_owned(), json!(self.schema));
        object.insert("record_type".to_owned(), json!("event"));
        object.insert("event_index".to_owned(), json!(event_index));
        let timestamp_qpc = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        object.insert("timestamp_qpc".to_owned(), json!(timestamp_qpc));
        object.insert(
            "timestamp_qpc_frequency".to_owned(),
            json!(1_000_000_000_u64),
        );
        object.insert(
            "ledger_counters".to_owned(),
            json!({
                "attempted_events": state.attempted_events,
                "events_written": state.events_written.saturating_add(1),
                "dropped_events": state.dropped_events,
                "write_failures": state.write_failures
            }),
        );
        let mut encoded = match serde_json::to_vec(&event) {
            Ok(encoded) if encoded.len() <= UDP_DIAGNOSTIC_MAX_EVENT_BYTES => encoded,
            Ok(_) => {
                state.write_failures = state.write_failures.saturating_add(1);
                drop(state);
                self.report_write_failure("event_too_large");
                return;
            }
            Err(_) => {
                state.write_failures = state.write_failures.saturating_add(1);
                drop(state);
                self.report_write_failure("serialize");
                return;
            }
        };
        encoded.push(b'\n');
        if state
            .writer
            .write_all(&encoded)
            .and_then(|()| state.writer.flush())
            .is_ok()
        {
            state.events_written = state.events_written.saturating_add(1);
        } else {
            state.write_failures = state.write_failures.saturating_add(1);
            state.writer_failed = true;
            drop(state);
            self.report_write_failure("write");
        }
    }

    fn report_write_failure(&self, reason: &'static str) {
        if self.report_degradation && !self.reported_write_failure.swap(true, Ordering::AcqRel) {
            eprintln!("windows_tun_udp_diagnostic_ledger status=DEGRADED reason={reason}");
        }
    }

    fn counters(&self) -> (usize, usize, usize, usize) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            state.attempted_events,
            state.events_written,
            state.dropped_events,
            state.write_failures,
        )
    }

    fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(reason) = Self::write_footer(self.schema, self.run_nonce, &mut state) {
            drop(state);
            self.report_write_failure(reason);
        }
    }

    fn write_footer(
        schema: &'static str,
        run_nonce: u64,
        state: &mut UdpDiagnosticLedgerState,
    ) -> Result<(), &'static str> {
        if state.closed {
            return Ok(());
        }
        state.closed = true;
        if state.writer_failed {
            return Err("footer_after_write_failure");
        }
        let footer = json!({
            "schema": schema,
            "record_type": "footer",
            "run_nonce": run_nonce.to_string(),
            "attempted_events": state.attempted_events,
            "events_written": state.events_written,
            "dropped_events": state.dropped_events,
            "write_failures": state.write_failures,
            "closed": true
        });
        serde_json::to_vec(&footer)
            .map(|mut encoded| {
                encoded.push(b'\n');
                encoded
            })
            .map_err(|_| "footer_serialize")
            .and_then(|encoded| {
                state
                    .writer
                    .write_all(&encoded)
                    .and_then(|()| state.writer.flush())
                    .map_err(|_| "footer_write")
            })
    }
}

struct SupportUdpDiagnostic {
    ledger: BoundedUdpDiagnosticLedger,
    finalize_slots: Mutex<[bool; ROUTE_TARGET_SLOTS]>,
}

impl SupportUdpDiagnostic {
    fn new(ledger: BoundedUdpDiagnosticLedger) -> Self {
        Self {
            ledger,
            finalize_slots: Mutex::new([false; ROUTE_TARGET_SLOTS]),
        }
    }

    fn observe_finalize_marker(
        &self,
        slot: usize,
        listen: SocketAddr,
        peer: SocketAddr,
        request: &[u8],
    ) {
        if slot >= ROUTE_TARGET_SLOTS || peer.ip() != listen.ip() {
            return;
        }
        let Some(identity) = UdpDiagnosticPayload::parse(request) else {
            return;
        };
        if !is_udp_diagnostic_finalize_marker(identity, self.ledger.run_nonce) {
            return;
        }
        let mut finalize_slots = self
            .finalize_slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        finalize_slots[slot] = true;
        if finalize_slots.iter().all(|observed| *observed) {
            self.ledger.close();
        }
    }
}

impl Drop for BoundedUdpDiagnosticLedger {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if Self::write_footer(self.schema, self.run_nonce, state).is_err()
            && self.report_degradation
            && !self.reported_write_failure.swap(true, Ordering::AcqRel)
        {
            eprintln!("windows_tun_udp_diagnostic_ledger status=DEGRADED reason=footer_write");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FragmentPhase {
    Warmup,
    Active,
}

#[derive(Debug)]
struct FragmentAckBatch {
    first_sequence: u64,
    end_sequence: u64,
    seen: Vec<bool>,
}

impl FragmentAckBatch {
    fn new(first_sequence: u64, batch: usize) -> Result<Self, String> {
        if batch == 0 {
            return Err("fragment ACK batch cannot be empty".to_owned());
        }
        let end_sequence = first_sequence
            .checked_add(batch as u64)
            .ok_or_else(|| "fragment ACK batch sequence overflow".to_owned())?;
        Ok(Self {
            first_sequence,
            end_sequence,
            seen: vec![false; batch],
        })
    }

    fn observe(
        &mut self,
        sequence: u64,
        retried_sequences: &HashSet<u64>,
        duplicate_sequences: &mut HashSet<u64>,
    ) -> Result<bool, String> {
        if sequence >= self.end_sequence {
            return Err("fragment ACK sequence is in the future".to_owned());
        }
        if sequence < self.first_sequence {
            if retried_sequences.contains(&sequence) && duplicate_sequences.insert(sequence) {
                return Ok(false);
            }
            return Err("fragment ACK sequence is stale or duplicated without a retry".to_owned());
        }
        let offset = usize::try_from(sequence - self.first_sequence)
            .map_err(|_| "fragment ACK sequence offset overflow".to_owned())?;
        if !std::mem::replace(&mut self.seen[offset], true) {
            return Ok(true);
        }
        if retried_sequences.contains(&sequence) && duplicate_sequences.insert(sequence) {
            return Ok(false);
        }
        Err("fragment ACK sequence was duplicated more than allowed".to_owned())
    }

    fn complete(&self) -> bool {
        self.seen.iter().all(|seen| *seen)
    }

    fn missing_sequences(&self) -> Vec<u64> {
        self.seen
            .iter()
            .enumerate()
            .filter(|(_, seen)| !**seen)
            .map(|(offset, _)| self.first_sequence + offset as u64)
            .collect()
    }

    fn sole_missing_sequence(&self) -> Result<u64, String> {
        let missing = self.missing_sequences();
        if missing.len() != 1 {
            return Err("fragment ACK window must leave exactly one missing sequence".to_owned());
        }
        Ok(missing[0])
    }

    fn seen_bitmap(&self) -> String {
        self.seen
            .iter()
            .map(|seen| if *seen { '1' } else { '0' })
            .collect()
    }
}

#[derive(Debug, Default)]
struct FragmentWorkloadAccounting {
    warmup_unique_datagrams: u64,
    warmup_request_attempts: u64,
    active_unique_datagrams: u64,
    active_request_attempts: u64,
    retransmissions: u64,
    ack_window_expirations: u64,
    duplicate_or_stale_acks: u64,
    retried_sequences: HashSet<u64>,
    duplicate_sequences: HashSet<u64>,
}

impl FragmentWorkloadAccounting {
    fn total_unique_datagrams(&self) -> Result<u64, String> {
        self.warmup_unique_datagrams
            .checked_add(self.active_unique_datagrams)
            .ok_or_else(|| "fragment total unique datagram count overflow".to_owned())
    }

    fn total_request_attempts(&self) -> Result<u64, String> {
        self.warmup_request_attempts
            .checked_add(self.active_request_attempts)
            .ok_or_else(|| "fragment total request attempt count overflow".to_owned())
    }

    fn record_initial_attempts(
        &mut self,
        phase: FragmentPhase,
        attempts: u64,
    ) -> Result<(), String> {
        let target = match phase {
            FragmentPhase::Warmup => &mut self.warmup_request_attempts,
            FragmentPhase::Active => &mut self.active_request_attempts,
        };
        *target = target
            .checked_add(attempts)
            .ok_or_else(|| "fragment phase request attempt count overflow".to_owned())?;
        Ok(())
    }

    fn record_unique_datagrams(
        &mut self,
        phase: FragmentPhase,
        datagrams: u64,
    ) -> Result<(), String> {
        let target = match phase {
            FragmentPhase::Warmup => &mut self.warmup_unique_datagrams,
            FragmentPhase::Active => &mut self.active_unique_datagrams,
        };
        *target = target
            .checked_add(datagrams)
            .ok_or_else(|| "fragment phase unique datagram count overflow".to_owned())?;
        Ok(())
    }

    fn record_ack_window_expiration(&mut self) -> Result<(), String> {
        self.ack_window_expirations = self
            .ack_window_expirations
            .checked_add(1)
            .ok_or_else(|| "fragment ACK window expiration count overflow".to_owned())?;
        Ok(())
    }

    fn record_retransmission(
        &mut self,
        phase: FragmentPhase,
        sequence: u64,
        retry_budget: u64,
    ) -> Result<(), String> {
        let retransmissions = self
            .retransmissions
            .checked_add(1)
            .ok_or_else(|| "fragment retransmission count overflow".to_owned())?;
        if retransmissions > retry_budget {
            return Err("fragment retransmission budget exhausted".to_owned());
        }
        if self.retried_sequences.contains(&sequence) {
            return Err("fragment sequence was already retransmitted".to_owned());
        }
        self.record_initial_attempts(phase, 1)?;
        self.retried_sequences.insert(sequence);
        self.retransmissions = retransmissions;
        Ok(())
    }

    fn record_duplicate_or_stale_ack(&mut self) -> Result<(), String> {
        self.duplicate_or_stale_acks = self
            .duplicate_or_stale_acks
            .checked_add(1)
            .ok_or_else(|| "fragment duplicate/stale ACK count overflow".to_owned())?;
        Ok(())
    }

    fn observe_ack(&mut self, batch: &mut FragmentAckBatch, sequence: u64) -> Result<(), String> {
        let is_unique = batch.observe(
            sequence,
            &self.retried_sequences,
            &mut self.duplicate_sequences,
        )?;
        if !is_unique {
            self.record_duplicate_or_stale_ack()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    TcpSingle,
    TcpFairness,
    UdpPackets,
    UdpAssociations,
    UdpRouteOnce,
    Fragments,
    RingFull,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "tcp-single-flow" => Ok(Self::TcpSingle),
            "tcp-256-flow-fairness" => Ok(Self::TcpFairness),
            "udp-packets-per-second" => Ok(Self::UdpPackets),
            "udp-8192-association-lookup-expiry" => Ok(Self::UdpAssociations),
            "udp-route-once" => Ok(Self::UdpRouteOnce),
            "fragment-reassembly-throughput" => Ok(Self::Fragments),
            "wintun-ring-full-drop-rate" => Ok(Self::RingFull),
            _ => Err("unsupported Windows TUN workload scenario".to_owned()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::TcpSingle => "tcp-single-flow",
            Self::TcpFairness => "tcp-256-flow-fairness",
            Self::UdpPackets => "udp-packets-per-second",
            Self::UdpAssociations => "udp-8192-association-lookup-expiry",
            Self::UdpRouteOnce => "udp-route-once",
            Self::Fragments => "fragment-reassembly-throughput",
            Self::RingFull => "wintun-ring-full-drop-rate",
        }
    }
}

struct WorkloadArgs {
    scenario: Scenario,
    target_ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
    output: PathBuf,
    diagnostic: Option<UdpWorkloadDiagnosticArgs>,
}

struct ProbeArgs {
    target_ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
}

struct SupportArgs {
    listen_ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
    diagnostic: Option<UdpDiagnosticLedgerArgs>,
}

fn parse_pairs(arguments: &[OsString]) -> Result<Vec<(String, String)>, String> {
    let mut chunks = arguments.chunks_exact(2);
    let mut pairs = Vec::new();
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "Windows TUN option name is not UTF-8".to_owned())?;
        let value = pair[1]
            .to_str()
            .ok_or_else(|| format!("Windows TUN option {flag} is not UTF-8"))?;
        pairs.push((flag.to_owned(), value.to_owned()));
    }
    if !chunks.remainder().is_empty() {
        return Err("every Windows TUN option requires one value".to_owned());
    }
    Ok(pairs)
}

fn take_unique(slot: &mut Option<String>, value: String, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate Windows TUN option: {flag}"));
    }
    Ok(())
}

fn parse_port(value: Option<String>, flag: &str) -> Result<u16, String> {
    let value = value.ok_or_else(|| format!("missing Windows TUN option: {flag}"))?;
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("{flag} must be a decimal TCP/UDP port"))?;
    if port == 0 || port.to_string() != value {
        return Err(format!("{flag} must be a canonical nonzero port"));
    }
    Ok(port)
}

fn parse_canonical_nonzero_u64(value: String, flag: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a canonical nonzero decimal integer"))?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(format!(
            "{flag} must be a canonical nonzero decimal integer"
        ));
    }
    Ok(parsed)
}

fn parse_diagnostic_max_events(value: String) -> Result<usize, String> {
    let parsed = parse_canonical_nonzero_u64(value, "--diagnostic-max-events")?;
    let parsed = usize::try_from(parsed)
        .map_err(|_| "--diagnostic-max-events is outside the supported range".to_owned())?;
    if parsed > UDP_DIAGNOSTIC_MAX_EVENTS {
        return Err(format!(
            "--diagnostic-max-events cannot exceed {UDP_DIAGNOSTIC_MAX_EVENTS}"
        ));
    }
    Ok(parsed)
}

fn parse_diagnostic_trial_sequence(value: String) -> Result<u16, String> {
    let parsed = parse_canonical_nonzero_u64(value, "--diagnostic-trial-sequence")?;
    u16::try_from(parsed)
        .map_err(|_| "--diagnostic-trial-sequence is outside the supported range".to_owned())
}

fn parse_diagnostic_source_ip(value: String) -> Result<IpAddr, String> {
    let expected = UDP_DIAGNOSTIC_SOURCE_IPV4.to_string();
    if value != expected {
        return Err(format!("--diagnostic-source-ip must be exactly {expected}"));
    }
    Ok(IpAddr::V4(UDP_DIAGNOSTIC_SOURCE_IPV4))
}

fn parse_diagnostic_source_port(value: String, flag: &str, expected: u16) -> Result<u16, String> {
    let parsed = parse_port(Some(value), flag)?;
    if parsed != expected {
        return Err(format!("{flag} must be exactly {expected}"));
    }
    Ok(parsed)
}

fn validate_diagnostic_ledger_path(value: String) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .extension()
            .is_none_or(|extension| extension != "ndjson")
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(
            "--diagnostic-ledger must be an absolute normalized .ndjson file path".to_owned(),
        );
    }
    if path.exists() {
        return Err("Windows TUN UDP diagnostic ledger baseline must be absent".to_owned());
    }
    if path.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err("Windows TUN UDP diagnostic ledger parent must exist".to_owned());
    }
    Ok(path)
}

fn parse_diagnostic_ledger_args(
    ledger: Option<String>,
    run_nonce: Option<String>,
    max_events: Option<String>,
) -> Result<Option<UdpDiagnosticLedgerArgs>, String> {
    let supplied = [ledger.is_some(), run_nonce.is_some(), max_events.is_some()];
    if supplied.iter().all(|supplied| !supplied) {
        return Ok(None);
    }
    if !supplied.iter().all(|supplied| *supplied) {
        return Err(
            "--diagnostic-ledger, --diagnostic-run-nonce, and --diagnostic-max-events must be supplied together"
                .to_owned(),
        );
    }
    Ok(Some(UdpDiagnosticLedgerArgs {
        path: validate_diagnostic_ledger_path(ledger.expect("checked diagnostic ledger"))?,
        run_nonce: parse_canonical_nonzero_u64(
            run_nonce.expect("checked diagnostic run nonce"),
            "--diagnostic-run-nonce",
        )?,
        max_events: parse_diagnostic_max_events(
            max_events.expect("checked diagnostic max events"),
        )?,
    }))
}

fn parse_workload(arguments: &[OsString]) -> Result<WorkloadArgs, String> {
    let mut scenario = None;
    let mut target_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut output = None;
    let mut diagnostic_ledger = None;
    let mut diagnostic_run_nonce = None;
    let mut diagnostic_max_events = None;
    let mut diagnostic_trial_sequence = None;
    let mut diagnostic_source_ip = None;
    let mut diagnostic_source_port_first = None;
    let mut diagnostic_source_port_last = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--scenario" => take_unique(&mut scenario, value, &flag)?,
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--output" => take_unique(&mut output, value, &flag)?,
            "--diagnostic-ledger" => take_unique(&mut diagnostic_ledger, value, &flag)?,
            "--diagnostic-run-nonce" => take_unique(&mut diagnostic_run_nonce, value, &flag)?,
            "--diagnostic-max-events" => take_unique(&mut diagnostic_max_events, value, &flag)?,
            "--diagnostic-trial-sequence" => {
                take_unique(&mut diagnostic_trial_sequence, value, &flag)?
            }
            "--diagnostic-source-ip" => take_unique(&mut diagnostic_source_ip, value, &flag)?,
            "--diagnostic-source-port-first" => {
                take_unique(&mut diagnostic_source_port_first, value, &flag)?
            }
            "--diagnostic-source-port-last" => {
                take_unique(&mut diagnostic_source_port_last, value, &flag)?
            }
            _ => return Err(format!("unsupported Windows TUN option: {flag}")),
        }
    }
    let scenario = Scenario::parse(
        &scenario.ok_or_else(|| "missing Windows TUN option: --scenario".to_owned())?,
    )?;
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    let output =
        PathBuf::from(output.ok_or_else(|| "missing Windows TUN option: --output".to_owned())?);
    if output.as_os_str().is_empty() || output.exists() {
        return Err("Windows TUN workload output baseline must be absent".to_owned());
    }
    if output.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err("Windows TUN workload output parent must exist".to_owned());
    }
    let diagnostic_ledger = parse_diagnostic_ledger_args(
        diagnostic_ledger,
        diagnostic_run_nonce,
        diagnostic_max_events,
    )?;
    let diagnostic = match (
        diagnostic_ledger,
        diagnostic_trial_sequence,
        diagnostic_source_ip,
        diagnostic_source_port_first,
        diagnostic_source_port_last,
    ) {
        (None, None, None, None, None) => None,
        (
            Some(ledger),
            Some(trial_sequence),
            Some(source_ip),
            Some(source_port_first),
            Some(source_port_last),
        ) => {
            let trial_sequence = parse_diagnostic_trial_sequence(trial_sequence)?;
            if trial_sequence != UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE {
                return Err(format!(
                    "--diagnostic-trial-sequence must be exactly {UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE}"
                ));
            }
            Some(UdpWorkloadDiagnosticArgs {
                ledger,
                trial_sequence,
                source_ip: parse_diagnostic_source_ip(source_ip)?,
                source_port_first: parse_diagnostic_source_port(
                    source_port_first,
                    "--diagnostic-source-port-first",
                    UDP_DIAGNOSTIC_SOURCE_PORT_FIRST,
                )?,
                source_port_last: parse_diagnostic_source_port(
                    source_port_last,
                    "--diagnostic-source-port-last",
                    UDP_DIAGNOSTIC_SOURCE_PORT_LAST,
                )?,
            })
        }
        _ => {
            return Err(
                "workload UDP diagnostics require all ledger, trial-sequence, and fixed source endpoint options"
                    .to_owned(),
            );
        }
    };
    if diagnostic.is_some() && scenario != Scenario::UdpAssociations {
        return Err(
            "workload UDP diagnostics are only supported for udp-8192-association-lookup-expiry"
                .to_owned(),
        );
    }
    if diagnostic.is_some() && !target_ip.is_ipv4() {
        return Err("workload UDP diagnostics require an IPv4 target".to_owned());
    }
    if diagnostic
        .as_ref()
        .is_some_and(|diagnostic| diagnostic.ledger.path == output)
    {
        return Err("workload observation and diagnostic ledger paths must differ".to_owned());
    }
    Ok(WorkloadArgs {
        scenario,
        target_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
        output,
        diagnostic,
    })
}

fn parse_probe(arguments: &[OsString]) -> Result<ProbeArgs, String> {
    let mut target_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN probe option: {flag}")),
        }
    }
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    Ok(ProbeArgs {
        target_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
    })
}

fn parse_support(arguments: &[OsString]) -> Result<SupportArgs, String> {
    let mut listen_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut diagnostic_ledger = None;
    let mut diagnostic_run_nonce = None;
    let mut diagnostic_max_events = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--listen-ip" => take_unique(&mut listen_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--diagnostic-ledger" => take_unique(&mut diagnostic_ledger, value, &flag)?,
            "--diagnostic-run-nonce" => take_unique(&mut diagnostic_run_nonce, value, &flag)?,
            "--diagnostic-max-events" => take_unique(&mut diagnostic_max_events, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN support option: {flag}")),
        }
    }
    let listen_ip = listen_ip
        .ok_or_else(|| "missing Windows TUN option: --listen-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--listen-ip must be an IP literal".to_owned())?;
    if listen_ip.is_multicast() {
        return Err("--listen-ip cannot be multicast".to_owned());
    }
    Ok(SupportArgs {
        listen_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
        diagnostic: parse_diagnostic_ledger_args(
            diagnostic_ledger,
            diagnostic_run_nonce,
            diagnostic_max_events,
        )?,
    })
}

fn parse_udp_diagnostic_finalize(
    arguments: &[OsString],
) -> Result<UdpDiagnosticFinalizeArgs, String> {
    let mut target_ip = None;
    let mut udp_port = None;
    let mut diagnostic_run_nonce = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--diagnostic-run-nonce" => take_unique(&mut diagnostic_run_nonce, value, &flag)?,
            _ => {
                return Err(format!(
                    "unsupported Windows TUN UDP diagnostic finalize option: {flag}"
                ));
            }
        }
    }
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    let udp_port = parse_port(udp_port, "--udp-port")?;
    udp_port
        .checked_add((ROUTE_TARGET_SLOTS - 1) as u16)
        .ok_or_else(|| "--udp-port cannot address four contiguous UDP listeners".to_owned())?;
    Ok(UdpDiagnosticFinalizeArgs {
        target_ip,
        udp_port,
        run_nonce: parse_canonical_nonzero_u64(
            diagnostic_run_nonce
                .ok_or_else(|| "missing Windows TUN option: --diagnostic-run-nonce".to_owned())?,
            "--diagnostic-run-nonce",
        )?,
    })
}

fn checked_payload_byte(index: usize, seed: u64) -> u8 {
    ((index as u64).wrapping_mul(131).wrapping_add(seed) & 0xff) as u8
}

fn checked_payload(length: usize, seed: u64) -> Vec<u8> {
    (0..length)
        .map(|index| checked_payload_byte(index, seed))
        .collect()
}

fn configure_tcp_with_read_timeout(
    stream: &TcpStream,
    read_timeout: Duration,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("set TCP_NODELAY failed: {error}"))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| format!("set TCP read timeout failed: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set TCP write timeout failed: {error}"))?;
    Ok(())
}

fn configure_tcp(stream: &TcpStream) -> Result<(), String> {
    configure_tcp_with_read_timeout(stream, IO_TIMEOUT)
}

fn configure_support_tcp(stream: &TcpStream) -> Result<(), String> {
    configure_tcp_with_read_timeout(stream, SUPPORT_TCP_IDLE_TIMEOUT)
}

fn tcp_round_trip(stream: &mut TcpStream, payload: &[u8], reply: &mut [u8]) -> Result<(), String> {
    stream
        .write_all(payload)
        .map_err(|error| format!("TCP workload write failed: {error}"))?;
    stream
        .read_exact(reply)
        .map_err(|error| format!("TCP workload read failed: {error}"))?;
    if reply != payload {
        return Err("TCP workload payload mismatch".to_owned());
    }
    Ok(())
}

fn elapsed_rate(units: u64, elapsed: Duration, name: &str) -> Result<u64, String> {
    let nanos = elapsed.as_nanos();
    if units == 0 || nanos == 0 {
        return Err(format!("{name} has no measured work"));
    }
    let rate = u128::from(units)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| format!("{name} rate numerator overflow"))?
        / nanos;
    u64::try_from(rate.max(1)).map_err(|_| format!("{name} rate overflow"))
}

fn tcp_single(address: SocketAddr) -> Result<Value, String> {
    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .map_err(|error| format!("TCP single-flow connect failed: {error}"))?;
    configure_tcp(&stream)?;
    let payload = checked_payload(TCP_SINGLE_PAYLOAD, 1);
    let mut reply = vec![0; payload.len()];
    let warmup_deadline = Instant::now() + TCP_SINGLE_WARMUP;
    let mut warmup_bytes = 0_u64;
    while Instant::now() < warmup_deadline {
        tcp_round_trip(&mut stream, &payload, &mut reply)?;
        warmup_bytes = warmup_bytes
            .checked_add(payload.len() as u64)
            .ok_or_else(|| "TCP single-flow warmup byte count overflow".to_owned())?;
    }
    let start = Instant::now();
    let deadline = start + TCP_SINGLE_ACTIVE;
    let mut checked_bytes = 0_u64;
    while Instant::now() < deadline {
        tcp_round_trip(&mut stream, &payload, &mut reply)?;
        checked_bytes = checked_bytes
            .checked_add(payload.len() as u64)
            .ok_or_else(|| "TCP single-flow byte count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    if checked_bytes < TCP_SINGLE_MINIMUM_BYTES {
        return Err("TCP single-flow correctness coverage is below 64 MiB".to_owned());
    }
    let cpu_payload_bytes = warmup_bytes
        .checked_add(checked_bytes)
        .ok_or_else(|| "TCP single-flow total byte count overflow".to_owned())?;
    Ok(json!({
        "measurements": {
            "throughput": elapsed_rate(checked_bytes, elapsed, "TCP throughput")?,
            "cpu_payload_bytes": cpu_payload_bytes
        },
        "checked_units": checked_bytes,
        "checks": {
            "single_flow_only": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

fn tcp_fairness(address: SocketAddr) -> Result<Value, String> {
    let start = Arc::new(OnceLock::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let mut streams = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    for flow in 0..TCP_FAIRNESS_FLOWS {
        let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
            .map_err(|error| format!("fairness connect failed: {error}"))?;
        configure_tcp(&stream)?;
        let readiness = checked_payload(TCP_FAIRNESS_READINESS_PAYLOAD, flow as u64);
        let mut reply = vec![0; readiness.len()];
        tcp_round_trip(&mut stream, &readiness, &mut reply)
            .map_err(|error| format!("fairness readiness flow {flow} failed: {error}"))?;
        streams.push(stream);
    }
    let mut workers = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    for (flow, mut stream) in streams.into_iter().enumerate() {
        let worker_start = Arc::clone(&start);
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new()
            .name(format!("tun-fairness-{flow:03}"))
            .spawn(move || -> Result<u64, String> {
                let payload = checked_payload(TCP_FAIRNESS_PAYLOAD, flow as u64);
                let mut reply = vec![0; payload.len()];
                let common_start = loop {
                    if let Some(start) = worker_start.get() {
                        break *start;
                    }
                    if worker_cancel.load(Ordering::Acquire) {
                        return Err("fairness start was cancelled".to_owned());
                    }
                    thread::sleep(Duration::from_millis(1));
                };
                let warmup_deadline = common_start + TCP_FAIRNESS_WARMUP;
                while Instant::now() < warmup_deadline {
                    tcp_round_trip(&mut stream, &payload, &mut reply)?;
                }
                let deadline = warmup_deadline + TCP_FAIRNESS_ACTIVE;
                let mut bytes = 0_u64;
                while Instant::now() < deadline {
                    tcp_round_trip(&mut stream, &payload, &mut reply)?;
                    bytes = bytes
                        .checked_add(payload.len() as u64)
                        .ok_or_else(|| "fairness byte count overflow".to_owned())?;
                }
                Ok(bytes)
            });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                cancel.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(format!("spawn fairness worker failed: {error}"));
            }
        }
    }
    start
        .set(Instant::now() + Duration::from_millis(100))
        .map_err(|_| "fairness start was already set".to_owned())?;
    let mut values = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    let mut first_failure = None;
    for worker in workers {
        match worker.join() {
            Ok(Ok(value)) => values.push(value),
            Ok(Err(error)) => {
                first_failure.get_or_insert(error);
            }
            Err(_) => {
                first_failure.get_or_insert("fairness worker panicked".to_owned());
            }
        }
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    if values.contains(&0) {
        return Err("fairness workload starved at least one flow".to_owned());
    }
    let sum = values.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(u128::from(*value))
            .ok_or_else(|| "fairness sum overflow".to_owned())
    })?;
    let squares = values.iter().try_fold(0_u128, |sum, value| {
        let value = u128::from(*value);
        sum.checked_add(
            value
                .checked_mul(value)
                .ok_or_else(|| "fairness square overflow".to_owned())?,
        )
        .ok_or_else(|| "fairness square sum overflow".to_owned())
    })?;
    let numerator = sum
        .checked_mul(sum)
        .and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or_else(|| "fairness numerator overflow".to_owned())?;
    let denominator = (TCP_FAIRNESS_FLOWS as u128)
        .checked_mul(squares)
        .ok_or_else(|| "fairness denominator overflow".to_owned())?;
    let jain_ppb =
        u64::try_from(numerator / denominator).map_err(|_| "fairness index overflow".to_owned())?;
    Ok(json!({
        "measurements": {"fairness": jain_ppb},
        "checked_units": TCP_FAIRNESS_FLOWS,
        "checks": {
            "all_256_flows_ready": true,
            "all_256_flows_nonzero": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

fn connected_udp(address: SocketAddr) -> Result<UdpSocket, String> {
    let bind = match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => "[::]:0"
            .parse::<SocketAddr>()
            .map_err(|_| "internal IPv6 wildcard is invalid".to_owned())?,
    };
    let socket =
        UdpSocket::bind(bind).map_err(|error| format!("UDP workload bind failed: {error}"))?;
    socket
        .connect(address)
        .map_err(|error| format!("UDP workload connect failed: {error}"))?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set UDP read timeout failed: {error}"))?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set UDP write timeout failed: {error}"))?;
    Ok(socket)
}

fn udp_diagnostic_source_endpoint(
    arguments: &UdpWorkloadDiagnosticArgs,
    association_index: usize,
) -> Result<SocketAddr, String> {
    if association_index >= ASSOCIATIONS {
        return Err(format!(
            "diagnostic UDP association index is outside the source range: index={association_index}"
        ));
    }
    let offset = u16::try_from(association_index).map_err(|_| {
        format!("diagnostic UDP association source offset overflow: index={association_index}")
    })?;
    let port = arguments
        .source_port_first
        .checked_add(offset)
        .ok_or_else(|| {
            format!("diagnostic UDP association source port overflow: index={association_index}")
        })?;
    let endpoint = SocketAddr::new(arguments.source_ip, port);
    if port > arguments.source_port_last {
        return Err(format!(
            "diagnostic UDP association source endpoint is outside the fixed range: index={association_index} endpoint={endpoint}"
        ));
    }
    Ok(endpoint)
}

fn connected_diagnostic_udp(
    address: SocketAddr,
    arguments: &UdpWorkloadDiagnosticArgs,
    association_index: usize,
) -> Result<UdpSocket, String> {
    let endpoint = udp_diagnostic_source_endpoint(arguments, association_index)?;
    let socket = UdpSocket::bind(endpoint).map_err(|error| {
        format!(
            "diagnostic UDP association bind failed: index={association_index} endpoint={endpoint} error={error}"
        )
    })?;
    socket.connect(address).map_err(|error| {
        format!(
            "diagnostic UDP association connect failed: index={association_index} endpoint={endpoint} target={address} error={error}"
        )
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            format!(
                "set diagnostic UDP association read timeout failed: index={association_index} endpoint={endpoint} error={error}"
            )
        })?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            format!(
                "set diagnostic UDP association write timeout failed: index={association_index} endpoint={endpoint} error={error}"
            )
        })?;
    let local = socket.local_addr().map_err(|error| {
        format!(
            "read diagnostic UDP association local address failed: index={association_index} endpoint={endpoint} error={error}"
        )
    })?;
    if local != endpoint {
        return Err(format!(
            "diagnostic UDP association local address mismatch: index={association_index} endpoint={endpoint} actual={local}"
        ));
    }
    Ok(socket)
}

fn unconnected_udp(address: IpAddr) -> Result<UdpSocket, String> {
    let bind = match address {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => "[::]:0"
            .parse::<SocketAddr>()
            .map_err(|_| "internal IPv6 wildcard is invalid".to_owned())?,
    };
    let socket = UdpSocket::bind(bind)
        .map_err(|error| format!("multi-target UDP workload bind failed: {error}"))?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set multi-target UDP read timeout failed: {error}"))?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set multi-target UDP write timeout failed: {error}"))?;
    Ok(socket)
}

fn udp_round_trip(socket: &UdpSocket, payload: &[u8], reply: &mut [u8]) -> Result<(), String> {
    let sent = socket
        .send(payload)
        .map_err(|error| format!("UDP workload send failed: {error}"))?;
    if sent != payload.len() {
        return Err("UDP workload sent a partial datagram".to_owned());
    }
    let received = socket
        .recv(reply)
        .map_err(|error| format!("UDP workload receive failed: {error}"))?;
    if received != payload.len() || &reply[..received] != payload {
        return Err("UDP workload payload mismatch".to_owned());
    }
    Ok(())
}

fn sequenced_payload(length: usize, sequence: u64) -> Result<Vec<u8>, String> {
    if length < std::mem::size_of::<u64>() {
        return Err("sequenced UDP payload is too short".to_owned());
    }
    let mut payload = checked_payload(length, sequence);
    payload[..8].copy_from_slice(&sequence.to_be_bytes());
    Ok(payload)
}

fn fragment_request(sequence: u64) -> Vec<u8> {
    let mut payload = checked_payload(FRAGMENT_PAYLOAD, sequence);
    payload[..8].copy_from_slice(&FRAGMENT_REQUEST_TAG);
    payload[8..16].copy_from_slice(&sequence.to_be_bytes());
    payload
}

fn fragment_request_sequence(payload: &[u8]) -> Result<u64, String> {
    if payload.len() != FRAGMENT_PAYLOAD {
        return Err("fragment request payload length mismatch".to_owned());
    }
    if !payload.starts_with(&FRAGMENT_REQUEST_TAG) {
        return Err("fragment request protocol tag mismatch".to_owned());
    }
    let mut encoded_sequence = [0_u8; 8];
    encoded_sequence.copy_from_slice(&payload[8..16]);
    let sequence = u64::from_be_bytes(encoded_sequence);
    if payload[16..]
        .iter()
        .enumerate()
        .any(|(offset, byte)| *byte != checked_payload_byte(offset + 16, sequence))
    {
        return Err("fragment request payload mismatch".to_owned());
    }
    Ok(sequence)
}

fn fragment_ack(sequence: u64) -> [u8; FRAGMENT_ACK_LEN] {
    let mut ack = [0_u8; FRAGMENT_ACK_LEN];
    ack[..8].copy_from_slice(&FRAGMENT_ACK_TAG);
    ack[8..16].copy_from_slice(&sequence.to_be_bytes());
    ack[16..24].copy_from_slice(&(FRAGMENT_PAYLOAD as u64).to_be_bytes());
    ack
}

fn fragment_ack_sequence(payload: &[u8]) -> Result<u64, String> {
    if payload.len() != FRAGMENT_ACK_LEN {
        return Err("fragment ACK payload length mismatch".to_owned());
    }
    if !payload.starts_with(&FRAGMENT_ACK_TAG) {
        return Err("fragment ACK protocol tag mismatch".to_owned());
    }
    let mut encoded_sequence = [0_u8; 8];
    encoded_sequence.copy_from_slice(&payload[8..16]);
    let mut encoded_request_len = [0_u8; 8];
    encoded_request_len.copy_from_slice(&payload[16..24]);
    if u64::from_be_bytes(encoded_request_len) != FRAGMENT_PAYLOAD as u64 {
        return Err("fragment ACK request length mismatch".to_owned());
    }
    Ok(u64::from_be_bytes(encoded_sequence))
}

fn fragment_ack_for_request(payload: &[u8]) -> Result<Option<[u8; FRAGMENT_ACK_LEN]>, String> {
    if !payload.starts_with(&FRAGMENT_REQUEST_TAG) {
        return Ok(None);
    }
    let sequence = fragment_request_sequence(payload)?;
    Ok(Some(fragment_ack(sequence)))
}

fn udp_batch_round_trip(
    socket: &UdpSocket,
    payload_len: usize,
    batch: usize,
    first_sequence: u64,
    reply: &mut [u8],
) -> Result<u64, String> {
    if batch == 0 || reply.len() < payload_len {
        return Err("UDP batch bounds are invalid".to_owned());
    }
    let end_sequence = first_sequence
        .checked_add(batch as u64)
        .ok_or_else(|| "UDP batch sequence overflow".to_owned())?;
    for sequence in first_sequence..end_sequence {
        let payload = sequenced_payload(payload_len, sequence)?;
        if socket
            .send(&payload)
            .map_err(|error| format!("UDP batch send failed: {error}"))?
            != payload.len()
        {
            return Err("UDP batch sent a partial datagram".to_owned());
        }
    }
    let mut seen = vec![false; batch];
    for _ in 0..batch {
        let received = socket
            .recv(reply)
            .map_err(|error| format!("UDP batch receive failed: {error}"))?;
        if received != payload_len {
            return Err("UDP batch payload length mismatch".to_owned());
        }
        let mut encoded_sequence = [0_u8; 8];
        encoded_sequence.copy_from_slice(&reply[..8]);
        let sequence = u64::from_be_bytes(encoded_sequence);
        if !(first_sequence..end_sequence).contains(&sequence) {
            return Err("UDP batch reply sequence is outside the request set".to_owned());
        }
        let offset = (sequence - first_sequence) as usize;
        if std::mem::replace(&mut seen[offset], true) {
            return Err("UDP batch contained a duplicate reply".to_owned());
        }
        if reply[..received] != sequenced_payload(payload_len, sequence)? {
            return Err("UDP batch payload mismatch".to_owned());
        }
    }
    Ok(end_sequence)
}

fn fragment_batch_round_trip(
    socket: &UdpSocket,
    batch: usize,
    first_sequence: u64,
    reply: &mut [u8],
) -> Result<u64, String> {
    if batch == 0 || reply.len() < FRAGMENT_REPLY_BUFFER {
        return Err("fragment batch bounds are invalid".to_owned());
    }
    let end_sequence = first_sequence
        .checked_add(batch as u64)
        .ok_or_else(|| "fragment batch sequence overflow".to_owned())?;
    for sequence in first_sequence..end_sequence {
        let payload = fragment_request(sequence);
        if socket
            .send(&payload)
            .map_err(|error| format!("fragment batch send failed: {error}"))?
            != payload.len()
        {
            return Err("fragment batch sent a partial datagram".to_owned());
        }
    }
    let mut seen = vec![false; batch];
    for _ in 0..batch {
        let received = socket
            .recv(reply)
            .map_err(|error| format!("fragment ACK receive failed: {error}"))?;
        let sequence = fragment_ack_sequence(&reply[..received])?;
        if !(first_sequence..end_sequence).contains(&sequence) {
            return Err("fragment ACK sequence is outside the request set".to_owned());
        }
        let offset = (sequence - first_sequence) as usize;
        if std::mem::replace(&mut seen[offset], true) {
            return Err("fragment batch contained a duplicate ACK".to_owned());
        }
    }
    Ok(end_sequence)
}

fn fragment_retry_budget(unique_datagrams: u64) -> u64 {
    unique_datagrams
        .div_ceil(FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS)
        .max(1)
}

fn fragment_batch_failure(error: &str, batch: &FragmentAckBatch, retry_budget: u64) -> String {
    let missing_sequences = batch.missing_sequences();
    format!(
        "{error}; first={} end={} seen={} missing={} missing_sequences={missing_sequences:?} budget={retry_budget}",
        batch.first_sequence,
        batch.end_sequence,
        batch.seen_bitmap(),
        missing_sequences.len(),
    )
}

fn send_fragment_request(socket: &UdpSocket, sequence: u64) -> Result<(), String> {
    let payload = fragment_request(sequence);
    if socket
        .send(&payload)
        .map_err(|error| format!("fragment request send failed: {error}"))?
        != payload.len()
    {
        return Err("fragment request send was partial".to_owned());
    }
    Ok(())
}

fn receive_fragment_ack_window(
    socket: &UdpSocket,
    reply: &mut [u8],
    batch: &mut FragmentAckBatch,
    accounting: &mut FragmentWorkloadAccounting,
    retry_budget: u64,
) -> Result<bool, String> {
    let deadline = Instant::now() + FRAGMENT_ACK_WINDOW;
    while !batch.complete() {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        socket
            .set_read_timeout(Some(deadline.duration_since(now)))
            .map_err(|error| {
                fragment_batch_failure(
                    &format!("set fragment ACK window failed: {error}"),
                    batch,
                    retry_budget,
                )
            })?;
        let received = match socket.recv(reply) {
            Ok(received) => received,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(false);
            }
            Err(error) => {
                return Err(fragment_batch_failure(
                    &format!("fragment ACK receive failed: {error}"),
                    batch,
                    retry_budget,
                ));
            }
        };
        let sequence = fragment_ack_sequence(&reply[..received])
            .map_err(|error| fragment_batch_failure(&error, batch, retry_budget))?;
        accounting
            .observe_ack(batch, sequence)
            .map_err(|error| fragment_batch_failure(&error, batch, retry_budget))?;
    }
    Ok(true)
}

fn fragment_workload_batch_round_trip(
    socket: &UdpSocket,
    phase: FragmentPhase,
    first_sequence: u64,
    reply: &mut [u8],
    accounting: &mut FragmentWorkloadAccounting,
) -> Result<u64, String> {
    if reply.len() < FRAGMENT_REPLY_BUFFER {
        return Err(format!(
            "fragment workload reply buffer is invalid; first={first_sequence} end={first_sequence} seen=<none> missing={FRAGMENT_BATCH} budget=1"
        ));
    }
    let mut batch = FragmentAckBatch::new(first_sequence, FRAGMENT_BATCH).map_err(|error| {
        format!(
            "{error}; first={first_sequence} end=<overflow> seen=<none> missing={FRAGMENT_BATCH} budget=1"
        )
    })?;
    let prospective_unique = accounting
        .total_unique_datagrams()
        .and_then(|value| {
            value
                .checked_add(FRAGMENT_BATCH as u64)
                .ok_or_else(|| "fragment prospective unique count overflow".to_owned())
        })
        .map_err(|error| fragment_batch_failure(&error, &batch, 1))?;
    let retry_budget = fragment_retry_budget(prospective_unique);
    accounting
        .record_initial_attempts(phase, FRAGMENT_BATCH as u64)
        .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
    for sequence in batch.first_sequence..batch.end_sequence {
        send_fragment_request(socket, sequence)
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
    }
    if !receive_fragment_ack_window(socket, reply, &mut batch, accounting, retry_budget)? {
        accounting
            .record_ack_window_expiration()
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        let missing_sequence = batch
            .sole_missing_sequence()
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        accounting
            .record_retransmission(phase, missing_sequence, retry_budget)
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        send_fragment_request(socket, missing_sequence)
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        if !receive_fragment_ack_window(socket, reply, &mut batch, accounting, retry_budget)? {
            accounting
                .record_ack_window_expiration()
                .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
            return Err(fragment_batch_failure(
                "fragment ACK remained missing after its only retransmission",
                &batch,
                retry_budget,
            ));
        }
    }
    accounting
        .record_unique_datagrams(phase, FRAGMENT_BATCH as u64)
        .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
    Ok(batch.end_sequence)
}

fn udp_packets(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let mut reply = vec![0; UDP_PAYLOAD];
    let mut sequence = 0_u64;
    let warmup_deadline = Instant::now() + UDP_WARMUP;
    while Instant::now() < warmup_deadline {
        sequence = udp_batch_round_trip(&socket, UDP_PAYLOAD, UDP_BATCH, sequence, &mut reply)?;
    }
    let start = Instant::now();
    let deadline = start + UDP_ACTIVE;
    let mut datagrams = 0_u64;
    while Instant::now() < deadline {
        sequence = udp_batch_round_trip(&socket, UDP_PAYLOAD, UDP_BATCH, sequence, &mut reply)?;
        datagrams = datagrams
            .checked_add(UDP_BATCH as u64)
            .ok_or_else(|| "UDP datagram count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    if datagrams < UDP_MINIMUM_DATAGRAMS {
        return Err("UDP packet-rate correctness coverage is below 4096 echoes".to_owned());
    }
    Ok(json!({
        "measurements": {
            "packet_rate": elapsed_rate(datagrams, elapsed, "UDP packet rate")?
        },
        "checked_units": datagrams,
        "checks": {
            "every_reply_accounted": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

fn association_round(
    sockets: &[UdpSocket],
    seed_prefix: u64,
    reply: &mut [u8; 32],
    batch_associations: usize,
    phase: &str,
    pacing: Option<(usize, Duration)>,
) -> Result<(), String> {
    if batch_associations == 0 || !sockets.len().is_multiple_of(batch_associations) {
        return Err("association batch bounds are invalid".to_owned());
    }
    if let Some((pacing_associations, _)) = pacing
        && (pacing_associations == 0
            || !pacing_associations.is_multiple_of(batch_associations)
            || !sockets.len().is_multiple_of(pacing_associations))
    {
        return Err("association pacing bounds are invalid".to_owned());
    }
    for (batch_index, batch) in sockets.chunks(batch_associations).enumerate() {
        let base = batch_index * batch_associations;
        for (offset, socket) in batch.iter().enumerate() {
            let seed = seed_prefix
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((base + offset) as u64);
            let payload = checked_payload(32, seed);
            if socket
                .send(&payload)
                .map_err(|error| {
                    format!(
                        "association batch send failed: phase={phase} association_index={} error={error}",
                        base + offset
                    )
                })?
                != payload.len()
            {
                return Err(format!(
                    "association batch sent a partial datagram: phase={phase} association_index={}",
                    base + offset
                ));
            }
        }
        for (offset, socket) in batch.iter().enumerate() {
            let seed = seed_prefix
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((base + offset) as u64);
            let payload = checked_payload(32, seed);
            let received = socket
                .recv(reply)
                .map_err(|error| {
                    format!(
                        "association batch receive failed: phase={phase} association_index={} error={error}",
                        base + offset
                    )
                })?;
            if received != payload.len() || reply[..received] != payload {
                return Err(format!(
                    "association batch payload mismatch: phase={phase} association_index={}",
                    base + offset
                ));
            }
        }
        let completed = base + batch.len();
        if let Some((pacing_associations, delay)) = pacing
            && completed < sockets.len()
            && completed.is_multiple_of(pacing_associations)
        {
            thread::sleep(delay);
        }
    }
    Ok(())
}

struct UdpWorkloadDiagnosticSession {
    arguments: UdpWorkloadDiagnosticArgs,
    ledger: BoundedUdpDiagnosticLedger,
    next_packet_nonce: u64,
}

struct UdpWorkloadFlowOutcome<'a> {
    send_result: &'a str,
    send_bytes: Option<usize>,
    reply_result: &'a str,
    reply_source: Option<SocketAddr>,
    payload_match: bool,
    error_kind: Option<&'a str>,
}

struct UdpWorkloadDiagnosticRequest {
    identity: UdpDiagnosticPayload,
    payload: [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN],
    local: Option<SocketAddr>,
    target: Option<SocketAddr>,
    sent: usize,
}

impl UdpWorkloadDiagnosticSession {
    fn create(arguments: &UdpWorkloadDiagnosticArgs) -> Result<Self, String> {
        Ok(Self {
            ledger: BoundedUdpDiagnosticLedger::create(
                &arguments.ledger,
                UDP_WORKLOAD_LEDGER_SCHEMA,
                json!({
                    "trial_sequence": arguments.trial_sequence,
                    "scope": UDP_DIAGNOSTIC_SCOPE,
                    "closure": UDP_WORKLOAD_DIAGNOSTIC_CLOSURE,
                    "source_ip": arguments.source_ip.to_string(),
                    "source_port_first": arguments.source_port_first,
                    "source_port_last": arguments.source_port_last
                }),
            )?,
            arguments: arguments.clone(),
            next_packet_nonce: 0,
        })
    }

    fn payload(
        &mut self,
        phase: UdpDiagnosticPhase,
        association_index: usize,
        round: u32,
    ) -> Result<UdpDiagnosticPayload, String> {
        let association_index = u32::try_from(association_index)
            .map_err(|_| "diagnostic association index overflow".to_owned())?;
        let packet_nonce = self.next_packet_nonce;
        self.next_packet_nonce = self
            .next_packet_nonce
            .checked_add(1)
            .ok_or_else(|| "diagnostic packet nonce overflow".to_owned())?;
        Ok(UdpDiagnosticPayload {
            phase,
            trial_sequence: self.arguments.trial_sequence,
            association_index,
            round,
            run_nonce: self.arguments.ledger.run_nonce,
            packet_nonce,
        })
    }

    fn record_flow(
        &self,
        identity: UdpDiagnosticPayload,
        local: Option<SocketAddr>,
        target: Option<SocketAddr>,
        outcome: UdpWorkloadFlowOutcome<'_>,
    ) {
        if identity.phase != UdpDiagnosticPhase::Bootstrap {
            return;
        }
        self.ledger.record(json!({
            "run_nonce": identity.run_nonce.to_string(),
            "trial_sequence": identity.trial_sequence,
            "phase": identity.phase.label(),
            "association_index": identity.association_index,
            "round": identity.round,
            "packet_nonce": identity.packet_nonce.to_string(),
            "workload_local_ip": local.map(|address| address.ip().to_string()),
            "workload_local_port": local.map(|address| address.port()),
            "target_ip": target.map(|address| address.ip().to_string()),
            "target_port": target.map(|address| address.port()),
            "send_result": outcome.send_result,
            "send_bytes": outcome.send_bytes,
            "reply_result": outcome.reply_result,
            "reply_source_ip": outcome.reply_source.map(|address| address.ip().to_string()),
            "reply_source_port": outcome.reply_source.map(|address| address.port()),
            "payload_match": outcome.payload_match,
            "error_kind": outcome.error_kind
        }));
    }

    fn record_not_observed(&self, request: &UdpWorkloadDiagnosticRequest) {
        self.record_flow(
            request.identity,
            request.local,
            request.target,
            UdpWorkloadFlowOutcome {
                send_result: "success",
                send_bytes: Some(request.sent),
                reply_result: "not_observed",
                reply_source: None,
                payload_match: false,
                error_kind: Some("prior_batch_failure"),
            },
        );
    }
}

fn bounded_io_error_kind(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::TimedOut => "timeout",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "address_in_use",
        ErrorKind::AddrNotAvailable => "address_not_available",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::Interrupted => "interrupted",
        _ => "other",
    }
}

fn diagnostic_association_round(
    sockets: &[UdpSocket],
    reply: &mut [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN],
    batch_associations: usize,
    phase: UdpDiagnosticPhase,
    round: u32,
    pacing: Option<(usize, Duration)>,
    diagnostic: &mut UdpWorkloadDiagnosticSession,
) -> Result<(), String> {
    if batch_associations == 0 || !sockets.len().is_multiple_of(batch_associations) {
        return Err("diagnostic association batch bounds are invalid".to_owned());
    }
    if let Some((pacing_associations, _)) = pacing
        && (pacing_associations == 0
            || !pacing_associations.is_multiple_of(batch_associations)
            || !sockets.len().is_multiple_of(pacing_associations))
    {
        return Err("diagnostic association pacing bounds are invalid".to_owned());
    }
    for (batch_index, batch) in sockets.chunks(batch_associations).enumerate() {
        let base = batch_index * batch_associations;
        let mut requests = Vec::with_capacity(batch.len());
        for (offset, socket) in batch.iter().enumerate() {
            let association_index = base + offset;
            let identity = diagnostic.payload(phase, association_index, round)?;
            let payload = identity.encode();
            let local = socket.local_addr().ok();
            let target = socket.peer_addr().ok();
            let sent = match socket.send(&payload) {
                Ok(sent) => sent,
                Err(error) => {
                    for request in &requests {
                        diagnostic.record_not_observed(request);
                    }
                    diagnostic.record_flow(
                        identity,
                        local,
                        target,
                        UdpWorkloadFlowOutcome {
                            send_result: "error",
                            send_bytes: None,
                            reply_result: "not_attempted",
                            reply_source: None,
                            payload_match: false,
                            error_kind: Some(bounded_io_error_kind(error.kind())),
                        },
                    );
                    return Err(format!(
                        "association batch send failed: phase={} association_index={association_index} error={error}",
                        phase.label()
                    ));
                }
            };
            if sent != payload.len() {
                for request in &requests {
                    diagnostic.record_not_observed(request);
                }
                diagnostic.record_flow(
                    identity,
                    local,
                    target,
                    UdpWorkloadFlowOutcome {
                        send_result: "partial",
                        send_bytes: Some(sent),
                        reply_result: "not_attempted",
                        reply_source: None,
                        payload_match: false,
                        error_kind: Some("partial"),
                    },
                );
                return Err(format!(
                    "association batch sent a partial datagram: phase={} association_index={association_index}",
                    phase.label()
                ));
            }
            requests.push(UdpWorkloadDiagnosticRequest {
                identity,
                payload,
                local,
                target,
                sent,
            });
        }
        for (offset, (socket, request)) in batch.iter().zip(&requests).enumerate() {
            let (received, reply_source) = match socket.recv_from(reply) {
                Ok(received) => received,
                Err(error) => {
                    diagnostic.record_flow(
                        request.identity,
                        request.local,
                        request.target,
                        UdpWorkloadFlowOutcome {
                            send_result: "success",
                            send_bytes: Some(request.sent),
                            reply_result: if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) {
                                "timeout"
                            } else {
                                "error"
                            },
                            reply_source: None,
                            payload_match: false,
                            error_kind: Some(bounded_io_error_kind(error.kind())),
                        },
                    );
                    for pending in &requests[(offset + 1)..] {
                        diagnostic.record_not_observed(pending);
                    }
                    return Err(format!(
                        "association batch receive failed: phase={} association_index={} error={error}",
                        phase.label(),
                        base + offset
                    ));
                }
            };
            let payload_match =
                received == request.payload.len() && reply[..received] == request.payload;
            diagnostic.record_flow(
                request.identity,
                request.local,
                request.target,
                UdpWorkloadFlowOutcome {
                    send_result: "success",
                    send_bytes: Some(request.sent),
                    reply_result: if payload_match {
                        "success"
                    } else {
                        "payload_mismatch"
                    },
                    reply_source: Some(reply_source),
                    payload_match,
                    error_kind: (!payload_match).then_some("payload_mismatch"),
                },
            );
            if !payload_match {
                for pending in &requests[(offset + 1)..] {
                    diagnostic.record_not_observed(pending);
                }
                return Err(format!(
                    "association batch payload mismatch: phase={} association_index={}",
                    phase.label(),
                    base + offset
                ));
            }
        }
        let completed = base + batch.len();
        if let Some((pacing_associations, delay)) = pacing
            && completed < sockets.len()
            && completed.is_multiple_of(pacing_associations)
        {
            thread::sleep(delay);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AssociationRoundSpec<'a> {
    seed_prefix: u64,
    batch_associations: usize,
    phase_label: &'a str,
    phase: UdpDiagnosticPhase,
    round: u32,
    pacing: Option<(usize, Duration)>,
}

fn association_round_selected(
    sockets: &[UdpSocket],
    reply: &mut [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN],
    spec: AssociationRoundSpec<'_>,
    diagnostic: &mut Option<UdpWorkloadDiagnosticSession>,
) -> Result<(), String> {
    if let Some(diagnostic) = diagnostic.as_mut() {
        diagnostic_association_round(
            sockets,
            reply,
            spec.batch_associations,
            spec.phase,
            spec.round,
            spec.pacing,
            diagnostic,
        )
    } else {
        association_round(
            sockets,
            spec.seed_prefix,
            reply,
            spec.batch_associations,
            spec.phase_label,
            spec.pacing,
        )
    }
}

fn udp_associations(
    address: SocketAddr,
    diagnostic_arguments: Option<&UdpWorkloadDiagnosticArgs>,
) -> Result<Value, String> {
    let mut diagnostic = diagnostic_arguments
        .map(UdpWorkloadDiagnosticSession::create)
        .transpose()?;
    let mut sockets = Vec::with_capacity(ASSOCIATIONS);
    let mut reply = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
    for association_index in 0..ASSOCIATIONS {
        sockets.push(if let Some(arguments) = diagnostic_arguments {
            connected_diagnostic_udp(address, arguments, association_index)?
        } else {
            connected_udp(address)?
        });
    }
    association_round_selected(
        &sockets,
        &mut reply,
        AssociationRoundSpec {
            seed_prefix: 0,
            batch_associations: ASSOCIATION_BOOTSTRAP_BATCH,
            phase_label: "bootstrap",
            phase: UdpDiagnosticPhase::Bootstrap,
            round: 0,
            pacing: Some((
                ASSOCIATION_BOOTSTRAP_PACING_ASSOCIATIONS,
                ASSOCIATION_BOOTSTRAP_PACING_DELAY,
            )),
        },
        &mut diagnostic,
    )?;
    let warmup_deadline = Instant::now() + ASSOCIATION_WARMUP;
    let mut warmup_round = 1_u64;
    while Instant::now() < warmup_deadline || warmup_round == 1 {
        let diagnostic_round = u32::try_from(warmup_round)
            .map_err(|_| "association diagnostic warmup round overflow".to_owned())?;
        association_round_selected(
            &sockets,
            &mut reply,
            AssociationRoundSpec {
                seed_prefix: warmup_round,
                batch_associations: ASSOCIATION_LOOKUP_BATCH,
                phase_label: "warmup",
                phase: UdpDiagnosticPhase::Warmup,
                round: diagnostic_round,
                pacing: None,
            },
            &mut diagnostic,
        )?;
        warmup_round = warmup_round
            .checked_add(1)
            .ok_or_else(|| "association warmup round overflow".to_owned())?;
    }
    let start = Instant::now();
    let mut lookups = 0_u64;
    for round in 0..ASSOCIATION_LOOKUP_ROUNDS {
        let round_number = warmup_round
            .checked_add(round as u64)
            .ok_or_else(|| "association lookup round overflow".to_owned())?;
        let diagnostic_round = u32::try_from(round_number)
            .map_err(|_| "association diagnostic lookup round overflow".to_owned())?;
        association_round_selected(
            &sockets,
            &mut reply,
            AssociationRoundSpec {
                seed_prefix: round_number,
                batch_associations: ASSOCIATION_LOOKUP_BATCH,
                phase_label: "lookup",
                phase: UdpDiagnosticPhase::Lookup,
                round: diagnostic_round,
                pacing: None,
            },
            &mut diagnostic,
        )?;
        lookups = lookups
            .checked_add(ASSOCIATIONS as u64)
            .ok_or_else(|| "association lookup count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    let expected = (ASSOCIATIONS * ASSOCIATION_LOOKUP_ROUNDS) as u64;
    if lookups != expected {
        return Err("association workload lookup count mismatch".to_owned());
    }
    // Refresh the whole key set in one complete round so the collector can
    // observe the exact 8192-entry peak before the fixed idle timeout expires it.
    association_round_selected(
        &sockets,
        &mut reply,
        AssociationRoundSpec {
            seed_prefix: u32::MAX as u64,
            batch_associations: ASSOCIATION_LOOKUP_BATCH,
            phase_label: "refresh",
            phase: UdpDiagnosticPhase::Refresh,
            round: u32::MAX,
            pacing: None,
        },
        &mut diagnostic,
    )?;
    drop(sockets);
    Ok(json!({
        "measurements": {
            "lookup_rate": elapsed_rate(lookups, elapsed, "association lookup")?
        },
        "checked_units": lookups,
        "checks": {
            "exactly_8192_associations": true,
            "all_lookups_hit": true,
            "no_gso": true
        }
    }))
}

fn route_target_addresses(target_ip: IpAddr, base_port: u16) -> Result<Vec<SocketAddr>, String> {
    let last_port = base_port
        .checked_add((ROUTE_TARGET_SLOTS - 1) as u16)
        .ok_or_else(|| "UDP route-once target port range overflows".to_owned())?;
    if last_port == 0 {
        return Err("UDP route-once target port range is invalid".to_owned());
    }
    Ok((0..ROUTE_TARGET_SLOTS)
        .map(|slot| SocketAddr::new(target_ip, base_port + slot as u16))
        .collect())
}

const fn route_target_order(source_slot: usize) -> [usize; ROUTE_TARGET_SLOTS] {
    if source_slot.is_multiple_of(2) {
        [0, 1, 2, 3]
    } else {
        [1, 0, 2, 3]
    }
}

fn send_route_targets(
    socket: &UdpSocket,
    source_slot: usize,
    round: usize,
    targets: &[SocketAddr],
    target_slots: &[usize],
) -> Result<(), String> {
    for &target_slot in target_slots {
        let sequence = ((source_slot as u64) << 32) | ((round as u64) << 16) | target_slot as u64;
        let payload = sequenced_payload(ROUTE_PAYLOAD, sequence)?;
        let sent = socket
            .send_to(&payload, targets[target_slot])
            .map_err(|error| format!("multi-target UDP send failed: {error}"))?;
        if sent != payload.len() {
            return Err("multi-target UDP sent a partial datagram".to_owned());
        }
    }
    Ok(())
}

fn receive_route_targets(
    socket: &UdpSocket,
    source_slot: usize,
    round: usize,
    targets: &[SocketAddr],
    expected_target_slots: &[usize],
) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(expected_target_slots.len());
    let mut reply = [0_u8; ROUTE_PAYLOAD];
    for _ in expected_target_slots {
        let (received, response_source) = socket
            .recv_from(&mut reply)
            .map_err(|error| format!("multi-target UDP receive failed: {error}"))?;
        if received != ROUTE_PAYLOAD {
            return Err("multi-target UDP payload length mismatch".to_owned());
        }
        let target_slot = targets
            .iter()
            .position(|target| *target == response_source)
            .ok_or_else(|| {
                "multi-target UDP response source is outside the target set".to_owned()
            })?;
        if !expected_target_slots.contains(&target_slot) || !seen.insert(target_slot) {
            return Err(
                "multi-target UDP received an unexpected or duplicate target response".to_owned(),
            );
        }
        let sequence = ((source_slot as u64) << 32) | ((round as u64) << 16) | target_slot as u64;
        if reply != sequenced_payload(ROUTE_PAYLOAD, sequence)?[..] {
            return Err("multi-target UDP payload mismatch".to_owned());
        }
    }
    Ok(())
}

fn udp_route_once(target_ip: IpAddr, base_port: u16) -> Result<Value, String> {
    let targets = route_target_addresses(target_ip, base_port)?;
    let sockets = (0..ROUTE_SOURCE_SLOTS)
        .map(|_| unconnected_udp(target_ip))
        .collect::<Result<Vec<_>, _>>()?;
    let start = Instant::now();
    for (source_slot, socket) in sockets.iter().enumerate() {
        send_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[..1],
        )?;
    }
    for (source_slot, socket) in sockets.iter().enumerate() {
        receive_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[..1],
        )?;
    }
    let association_creation_elapsed = start.elapsed();
    for (source_slot, socket) in sockets.iter().enumerate() {
        send_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[1..],
        )?;
    }
    for (source_slot, socket) in sockets.iter().enumerate() {
        receive_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[1..],
        )?;
    }
    for round in 1..ROUTE_DATAGRAMS_PER_TARGET {
        for (source_slot, socket) in sockets.iter().enumerate() {
            send_route_targets(
                socket,
                source_slot,
                round,
                &targets,
                &route_target_order(source_slot),
            )?;
        }
        for (source_slot, socket) in sockets.iter().enumerate() {
            receive_route_targets(
                socket,
                source_slot,
                round,
                &targets,
                &route_target_order(source_slot),
            )?;
        }
    }
    let elapsed = start.elapsed();
    let datagrams = (ROUTE_SOURCE_SLOTS * ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET) as u64;
    let associations = (0..ROUTE_SOURCE_SLOTS)
        .map(|source_slot| {
            json!({
                "source_slot": source_slot,
                "target_slots": (0..ROUTE_TARGET_SLOTS).collect::<Vec<_>>(),
                "first_target_slot": if source_slot % 2 == 0 { 0 } else { 1 },
                "datagrams_sent": ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET,
                "replies_received": ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "measurements": {
            "elapsed_nanoseconds": u64::try_from(elapsed.as_nanos())
                .map_err(|_| "multi-target UDP elapsed time overflow".to_owned())?,
            "association_creation_elapsed_nanoseconds": u64::try_from(
                association_creation_elapsed.as_nanos()
            ).map_err(|_| "multi-target UDP association time overflow".to_owned())?,
            "packet_rate": elapsed_rate(datagrams, elapsed, "multi-target UDP packet rate")?,
        },
        "checked_units": datagrams,
        "associations": associations,
        "checks": {
            "every_reply_accounted": true,
            "payload_exact": true,
            "multi_target_sources": true,
            "no_gso": true,
        }
    }))
}

fn fragments(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let mut reply = [0_u8; FRAGMENT_REPLY_BUFFER];
    let mut sequence = 0_u64;
    let mut accounting = FragmentWorkloadAccounting::default();
    let warmup_deadline = Instant::now() + FRAGMENT_WARMUP;
    while Instant::now() < warmup_deadline {
        sequence = fragment_workload_batch_round_trip(
            &socket,
            FragmentPhase::Warmup,
            sequence,
            &mut reply,
            &mut accounting,
        )?;
    }
    let start = Instant::now();
    let deadline = start + FRAGMENT_ACTIVE;
    while Instant::now() < deadline
        || accounting.active_unique_datagrams < FRAGMENT_MINIMUM_DATAGRAMS
    {
        sequence = fragment_workload_batch_round_trip(
            &socket,
            FragmentPhase::Active,
            sequence,
            &mut reply,
            &mut accounting,
        )?;
    }
    let elapsed = start.elapsed();
    let bytes = accounting
        .active_unique_datagrams
        .checked_mul(FRAGMENT_PAYLOAD as u64)
        .ok_or_else(|| "fragment byte count overflow".to_owned())?;
    let total_unique_datagrams = accounting.total_unique_datagrams()?;
    let total_request_attempts = accounting.total_request_attempts()?;
    let retry_budget = fragment_retry_budget(total_unique_datagrams);
    let expected_request_attempts = total_unique_datagrams
        .checked_add(accounting.retransmissions)
        .ok_or_else(|| "fragment request accounting overflow".to_owned())?;
    if sequence != total_unique_datagrams
        || total_request_attempts != expected_request_attempts
        || accounting.retransmissions > retry_budget
        || accounting.ack_window_expirations != accounting.retransmissions
        || accounting.duplicate_or_stale_acks > accounting.retransmissions
    {
        return Err("fragment workload accounting invariants failed".to_owned());
    }
    Ok(json!({
        "measurements": {
            "reassembly_rate": elapsed_rate(bytes, elapsed, "fragment reassembly")?
        },
        "checked_units": accounting.active_unique_datagrams,
        "accounting": {
            "warmup_unique_datagrams": accounting.warmup_unique_datagrams,
            "warmup_request_attempts": accounting.warmup_request_attempts,
            "active_unique_datagrams": accounting.active_unique_datagrams,
            "active_request_attempts": accounting.active_request_attempts,
            "total_unique_datagrams": total_unique_datagrams,
            "total_request_attempts": total_request_attempts,
            "retransmissions": accounting.retransmissions,
            "ack_window_expirations": accounting.ack_window_expirations,
            "duplicate_or_stale_acks": accounting.duplicate_or_stale_acks,
            "retry_budget": retry_budget,
        },
        "checks": {
            "payload_exact": true,
            "no_gso": true,
            "all_sequences_acknowledged": true,
            "bounded_retransmissions": true,
        }
    }))
}

fn ring_full(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let payload = checked_payload(UDP_PAYLOAD, 4);
    let start = Instant::now();
    let mut attempts = 0_u64;
    while attempts < RING_BURST_ATTEMPTS {
        let sent = socket
            .send(&payload)
            .map_err(|error| format!("ring-full burst send failed: {error}"))?;
        if sent != payload.len() {
            return Err("ring-full burst sent a partial datagram".to_owned());
        }
        attempts += 1;
    }
    Ok(json!({
        "measurements": {
            "attempted_datagrams": attempts,
            "send_rate": elapsed_rate(attempts, start.elapsed(), "ring burst")?
        },
        "checked_units": attempts,
        "checks": {"no_gso": true}
    }))
}

fn write_observation(path: &Path, scenario: Scenario, observation: Value) -> Result<(), String> {
    let document = json!({
        "schema_version": 1,
        "kind": "windows_tun_guest_workload",
        "scenario": scenario.label(),
        "observation": observation,
        "status": "PASS"
    });
    let encoded = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("serialize Windows TUN workload failed: {error}"))?;
    if encoded.len() > 64 * 1024 {
        return Err("Windows TUN workload observation exceeds 64 KiB".to_owned());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create Windows TUN workload output failed: {error}"))?;
    let result = output
        .write_all(&encoded)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("write Windows TUN workload output failed: {error}"));
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(path);
    }
    result
}

pub(super) fn run_workload(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_workload(arguments)?;
    let address = SocketAddr::new(
        arguments.target_ip,
        match arguments.scenario {
            Scenario::TcpSingle | Scenario::TcpFairness => arguments.tcp_port,
            _ => arguments.udp_port,
        },
    );
    let observation = match arguments.scenario {
        Scenario::TcpSingle => tcp_single(address)?,
        Scenario::TcpFairness => tcp_fairness(address)?,
        Scenario::UdpPackets => udp_packets(address)?,
        Scenario::UdpAssociations => udp_associations(address, arguments.diagnostic.as_ref())?,
        Scenario::UdpRouteOnce => udp_route_once(arguments.target_ip, arguments.udp_port)?,
        Scenario::Fragments => fragments(address)?,
        Scenario::RingFull => ring_full(address)?,
    };
    write_observation(&arguments.output, arguments.scenario, observation)?;
    Ok(format!(
        "windows_tun_workload status=PASS scenario={}",
        arguments.scenario.label()
    ))
}

fn probe(arguments: &ProbeArgs) -> Result<(), String> {
    let tcp_address = SocketAddr::new(arguments.target_ip, arguments.tcp_port);
    let mut stream = TcpStream::connect_timeout(&tcp_address, IO_TIMEOUT)
        .map_err(|error| format!("Windows TUN TCP probe connect failed: {error}"))?;
    configure_tcp(&stream)?;
    let payload = checked_payload(1_024, 5);
    let mut reply = vec![0; payload.len()];
    tcp_round_trip(&mut stream, &payload, &mut reply)?;
    for udp_address in route_target_addresses(arguments.target_ip, arguments.udp_port)? {
        let socket = connected_udp(udp_address)?;
        let mut udp_reply = vec![0; payload.len()];
        udp_round_trip(&socket, &payload, &mut udp_reply)?;
    }
    let fragment_socket = connected_udp(SocketAddr::new(arguments.target_ip, arguments.udp_port))?;
    let mut fragment_reply = [0_u8; FRAGMENT_REPLY_BUFFER];
    if fragment_batch_round_trip(&fragment_socket, 1, 0, &mut fragment_reply)? != 1 {
        return Err("Windows TUN fragment path probe sequence mismatch".to_owned());
    }
    Ok(())
}

pub(super) fn run_probe(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_probe(arguments)?;
    probe(&arguments)?;
    Ok("windows_tun_probe status=PASS protocols=tcp,udp".to_owned())
}

fn finalize_udp_diagnostic(arguments: UdpDiagnosticFinalizeArgs) -> Result<(), String> {
    let targets = route_target_addresses(arguments.target_ip, arguments.udp_port)?;
    let socket = UdpSocket::bind(SocketAddr::new(arguments.target_ip, 0)).map_err(|error| {
        format!("bind Windows TUN UDP diagnostic finalize socket failed: {error}")
    })?;
    socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|error| {
        format!("set Windows TUN UDP diagnostic finalize read timeout failed: {error}")
    })?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            format!("set Windows TUN UDP diagnostic finalize write timeout failed: {error}")
        })?;
    let local = socket.local_addr().map_err(|error| {
        format!("read Windows TUN UDP diagnostic finalize local address failed: {error}")
    })?;
    if local.ip() != arguments.target_ip {
        return Err("Windows TUN UDP diagnostic finalize socket IP mismatch".to_owned());
    }
    let marker = udp_diagnostic_finalize_marker(arguments.run_nonce).encode();
    let mut reply = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
    for target in targets {
        let sent = socket.send_to(&marker, target).map_err(|error| {
            format!("send Windows TUN UDP diagnostic finalize marker failed: {error}")
        })?;
        if sent != marker.len() {
            return Err("Windows TUN UDP diagnostic finalize marker send was partial".to_owned());
        }
        let (received, peer) = socket.recv_from(&mut reply).map_err(|error| {
            format!("receive Windows TUN UDP diagnostic finalize echo failed: {error}")
        })?;
        if peer != target || received != marker.len() || reply[..received] != marker {
            return Err("Windows TUN UDP diagnostic finalize echo mismatch".to_owned());
        }
    }
    Ok(())
}

pub(super) fn run_udp_diagnostic_finalize(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_udp_diagnostic_finalize(arguments)?;
    finalize_udp_diagnostic(arguments)?;
    let last_port = arguments
        .udp_port
        .checked_add((ROUTE_TARGET_SLOTS - 1) as u16)
        .expect("validated Windows TUN UDP diagnostic finalize port range");
    Ok(format!(
        "windows_tun_udp_diagnostic_finalize status=PASS target={} udp_ports={}..{}",
        arguments.target_ip, arguments.udp_port, last_port
    ))
}

fn serve_tcp(mut stream: TcpStream) -> Result<(), String> {
    configure_support_tcp(&stream)?;
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("support TCP read failed: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        stream
            .write_all(&buffer[..read])
            .map_err(|error| format!("support TCP write failed: {error}"))?;
    }
}

fn bind_support_tcp(address: SocketAddr) -> Result<TcpListener, String> {
    let backlog =
        i32::try_from(SUPPORT_MAX_TCP_CONNECTIONS).expect("Windows TUN support backlog fits i32");
    // Winsock uses a negative backlog as SOMAXCONN_HINT(n); a positive value
    // above its ordinary provider limit is silently capped below this burst.
    #[cfg(windows)]
    let backlog = -backlog;
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(|error| format!("create Windows TUN support TCP socket failed: {error}"))?;
    socket
        .bind(&address.into())
        .map_err(|error| format!("bind Windows TUN support TCP failed: {error}"))?;
    socket
        .listen(backlog)
        .map_err(|error| format!("listen Windows TUN support TCP failed: {error}"))?;
    Ok(socket.into())
}

fn self_check_support_backlog() -> Result<(), String> {
    let listener = bind_support_tcp(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("read Windows TUN self-check TCP address failed: {error}"))?;
    if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
        return Err("Windows TUN support listener did not preserve its bind address".to_owned());
    }
    let clients = (0..TCP_FAIRNESS_FLOWS)
        .map(|index| {
            TcpStream::connect_timeout(&address, IO_TIMEOUT).map_err(|error| {
                format!("queue Windows TUN support TCP burst {index} failed: {error}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    listener.set_nonblocking(true).map_err(|error| {
        format!("set Windows TUN self-check listener nonblocking failed: {error}")
    })?;
    for index in 0..clients.len() {
        let (stream, _) = listener
            .accept()
            .map_err(|error| format!("accept Windows TUN support TCP burst failed: {error}"))?;
        if index == 0 {
            configure_support_tcp(&stream)?;
            let read_timeout = stream
                .read_timeout()
                .map_err(|error| format!("read support TCP read timeout failed: {error}"))?;
            let write_timeout = stream
                .write_timeout()
                .map_err(|error| format!("read support TCP write timeout failed: {error}"))?;
            if read_timeout != Some(SUPPORT_TCP_IDLE_TIMEOUT) || write_timeout != Some(IO_TIMEOUT) {
                return Err("Windows TUN support TCP timeouts are invalid".to_owned());
            }
        }
    }
    Ok(())
}

struct SupportUdpLedgerEvent<'a> {
    stage: &'a str,
    listen: SocketAddr,
    peer: SocketAddr,
    request: &'a [u8],
    send_attempted: Option<bool>,
    send_result: &'a str,
    sent: Option<usize>,
    error_kind: Option<&'a str>,
}

fn record_support_udp_event(
    diagnostic: Option<&SupportUdpDiagnostic>,
    event: SupportUdpLedgerEvent<'_>,
) {
    let Some(diagnostic) = diagnostic else {
        return;
    };
    let Some(identity) = UdpDiagnosticPayload::parse(event.request) else {
        return;
    };
    if identity.run_nonce != diagnostic.ledger.run_nonce
        || identity.phase != UdpDiagnosticPhase::Bootstrap
    {
        return;
    }
    diagnostic.ledger.record(json!({
        "stage": event.stage,
        "listen_ip": event.listen.ip().to_string(),
        "listen_port": event.listen.port(),
        "remote_ip": event.peer.ip().to_string(),
        "remote_port": event.peer.port(),
        "payload_run_nonce": identity.run_nonce.to_string(),
        "payload_run_nonce_match": true,
        "trial_sequence": identity.trial_sequence,
        "phase": identity.phase.label(),
        "association_index": identity.association_index,
        "round": identity.round,
        "packet_nonce": identity.packet_nonce.to_string(),
        "recv_bytes": event.request.len(),
        "send_attempted": event.send_attempted,
        "send_result": event.send_result,
        "send_bytes": event.sent,
        "error_kind": event.error_kind
    }));
}

pub(super) fn run_support(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_support(arguments)?;
    let tcp_address = SocketAddr::new(arguments.listen_ip, arguments.tcp_port);
    let udp_addresses = route_target_addresses(arguments.listen_ip, arguments.udp_port)?;
    let tcp = bind_support_tcp(tcp_address)?;
    let udp_sockets = udp_addresses
        .iter()
        .map(|address| {
            UdpSocket::bind(address)
                .map_err(|error| format!("bind Windows TUN support UDP failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let diagnostic = arguments
        .diagnostic
        .as_ref()
        .map(|arguments| {
            BoundedUdpDiagnosticLedger::create(
                arguments,
                UDP_SUPPORT_LEDGER_SCHEMA,
                json!({
                    "pid": std::process::id(),
                    "listen_ip": tcp_address.ip().to_string(),
                    "tcp_port": tcp_address.port(),
                    "udp_ports": udp_addresses.iter().map(|address| address.port()).collect::<Vec<_>>(),
                    "scope": UDP_DIAGNOSTIC_SCOPE,
                    "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
                }),
            )
            .map(SupportUdpDiagnostic::new)
            .map(Arc::new)
        })
        .transpose()?;
    let active = Arc::new(AtomicUsize::new(0));
    let udp_workers = udp_sockets
        .into_iter()
        .enumerate()
        .map(|(slot, udp)| {
            let listen = udp
                .local_addr()
                .map_err(|error| format!("read Windows TUN support UDP address failed: {error}"))?;
            let diagnostic = diagnostic.clone();
            thread::Builder::new()
                .name(format!("tun-support-udp-{slot}"))
                .spawn(move || -> Result<(), String> {
                    let mut buffer = vec![0_u8; 65_507];
                    loop {
                        let (read, peer) = udp
                            .recv_from(&mut buffer)
                            .map_err(|error| format!("support UDP receive failed: {error}"))?;
                        let request = &buffer[..read];
                        if let Some(diagnostic) = diagnostic.as_deref() {
                            diagnostic.observe_finalize_marker(slot, listen, peer, request);
                        }
                        record_support_udp_event(
                            diagnostic.as_deref(),
                            SupportUdpLedgerEvent {
                                stage: "rx",
                                listen,
                                peer,
                                request,
                                send_attempted: None,
                                send_result: "pending",
                                sent: None,
                                error_kind: None,
                            },
                        );
                        let ack;
                        let response = match fragment_ack_for_request(request) {
                            Ok(Some(value)) => {
                                ack = value;
                                &ack[..]
                            }
                            Ok(None) => request,
                            Err(_) => {
                                record_support_udp_event(
                                    diagnostic.as_deref(),
                                    SupportUdpLedgerEvent {
                                        stage: "tx",
                                        listen,
                                        peer,
                                        request,
                                        send_attempted: Some(false),
                                        send_result: "not_attempted",
                                        sent: None,
                                        error_kind: Some("invalid_fragment_request"),
                                    },
                                );
                                continue;
                            }
                        };
                        let response_len = response.len();
                        let sent = match udp.send_to(response, peer) {
                            Ok(sent) => sent,
                            Err(error) => {
                                record_support_udp_event(
                                    diagnostic.as_deref(),
                                    SupportUdpLedgerEvent {
                                        stage: "tx",
                                        listen,
                                        peer,
                                        request,
                                        send_attempted: Some(true),
                                        send_result: "error",
                                        sent: None,
                                        error_kind: Some(bounded_io_error_kind(error.kind())),
                                    },
                                );
                                return Err(format!("support UDP send failed: {error}"));
                            }
                        };
                        record_support_udp_event(
                            diagnostic.as_deref(),
                            SupportUdpLedgerEvent {
                                stage: "tx",
                                listen,
                                peer,
                                request,
                                send_attempted: Some(true),
                                send_result: if sent == response_len {
                                    "success"
                                } else {
                                    "partial"
                                },
                                sent: Some(sent),
                                error_kind: (sent != response_len).then_some("partial"),
                            },
                        );
                        if sent != response_len {
                            return Err("support UDP sent a partial datagram".to_owned());
                        }
                    }
                })
                .map_err(|error| format!("spawn support UDP worker failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "windows_tun_support status=READY tcp={} udp={}..={}",
        tcp.local_addr()
            .map_err(|error| format!("read support TCP address failed: {error}"))?,
        udp_addresses[0],
        udp_addresses[ROUTE_TARGET_SLOTS - 1],
    );
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flush support readiness failed: {error}"))?;
    for accepted in tcp.incoming() {
        let stream = accepted.map_err(|error| format!("support TCP accept failed: {error}"))?;
        if active.fetch_add(1, Ordering::AcqRel) >= SUPPORT_MAX_TCP_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            drop(stream);
            continue;
        }
        let active = Arc::clone(&active);
        thread::Builder::new()
            .name("tun-support-tcp".to_owned())
            .spawn(move || {
                let result = serve_tcp(stream);
                active.fetch_sub(1, Ordering::AcqRel);
                result
            })
            .map_err(|error| format!("spawn support TCP worker failed: {error}"))?;
    }
    for worker in udp_workers {
        let _ = worker.join();
    }
    Err("Windows TUN support listener stopped unexpectedly".to_owned())
}

pub(super) fn self_check() -> Result<(), String> {
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create Windows TUN self-check directory failed: {error}"))?;
    let output = directory.path().join("observation.json");
    let arguments: Vec<OsString> = [
        "--scenario".to_owned(),
        "tcp-single-flow".to_owned(),
        "--target-ip".to_owned(),
        "192.0.2.10".to_owned(),
        "--tcp-port".to_owned(),
        "443".to_owned(),
        "--udp-port".to_owned(),
        "53".to_owned(),
        "--output".to_owned(),
        output.to_string_lossy().into_owned(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let parsed = parse_workload(&arguments)?;
    if parsed.scenario != Scenario::TcpSingle
        || parsed.target_ip != "192.0.2.10".parse::<IpAddr>().expect("literal")
        || parsed.tcp_port != 443
        || parsed.udp_port != 53
        || parsed.output != output
        || parsed.diagnostic.is_some()
    {
        return Err("Windows TUN workload arguments were not preserved".to_owned());
    }
    let mut duplicate = arguments.clone();
    duplicate.extend([
        OsString::from("--scenario"),
        OsString::from("udp-packets-per-second"),
    ]);
    if parse_workload(&duplicate).is_ok() {
        return Err("Windows TUN duplicate option was accepted".to_owned());
    }
    let mut loopback = arguments.clone();
    loopback[3] = OsString::from("127.0.0.1");
    if parse_workload(&loopback).is_ok() {
        return Err("Windows TUN loopback target was accepted".to_owned());
    }
    let workload_ledger_path = directory.path().join("workload-flow.ndjson");
    let mut diagnostic_arguments = arguments.clone();
    diagnostic_arguments[1] = OsString::from("udp-8192-association-lookup-expiry");
    diagnostic_arguments.extend([
        OsString::from("--diagnostic-ledger"),
        workload_ledger_path.as_os_str().to_owned(),
        OsString::from("--diagnostic-run-nonce"),
        OsString::from("72623859790382856"),
        OsString::from("--diagnostic-max-events"),
        OsString::from("16384"),
        OsString::from("--diagnostic-trial-sequence"),
        OsString::from("31"),
        OsString::from("--diagnostic-source-ip"),
        OsString::from("198.18.0.2"),
        OsString::from("--diagnostic-source-port-first"),
        OsString::from("20000"),
        OsString::from("--diagnostic-source-port-last"),
        OsString::from("28191"),
    ]);
    let diagnostic_parsed = parse_workload(&diagnostic_arguments)?;
    let diagnostic = diagnostic_parsed
        .diagnostic
        .as_ref()
        .ok_or_else(|| "Windows TUN workload diagnostic options were discarded".to_owned())?;
    if diagnostic_parsed.scenario != Scenario::UdpAssociations
        || diagnostic.ledger.path != workload_ledger_path
        || diagnostic.ledger.run_nonce != 0x0102_0304_0506_0708
        || diagnostic.ledger.max_events != 16_384
        || diagnostic.trial_sequence != 31
        || diagnostic.source_ip != IpAddr::V4(UDP_DIAGNOSTIC_SOURCE_IPV4)
        || diagnostic.source_port_first != UDP_DIAGNOSTIC_SOURCE_PORT_FIRST
        || diagnostic.source_port_last != UDP_DIAGNOSTIC_SOURCE_PORT_LAST
    {
        return Err("Windows TUN workload diagnostic arguments were not preserved".to_owned());
    }
    let mut partial_diagnostic = diagnostic_arguments.clone();
    partial_diagnostic.truncate(partial_diagnostic.len() - 2);
    if parse_workload(&partial_diagnostic).is_ok() {
        return Err("incomplete Windows TUN workload diagnostic options were accepted".to_owned());
    }
    let mut wrong_scenario_diagnostic = diagnostic_arguments.clone();
    wrong_scenario_diagnostic[1] = OsString::from("udp-packets-per-second");
    if parse_workload(&wrong_scenario_diagnostic).is_ok() {
        return Err("Windows TUN diagnostics were accepted for a canonical workload".to_owned());
    }
    let mut zero_nonce_diagnostic = diagnostic_arguments.clone();
    zero_nonce_diagnostic[13] = OsString::from("0");
    let mut noncanonical_nonce_diagnostic = diagnostic_arguments.clone();
    noncanonical_nonce_diagnostic[13] = OsString::from("01");
    let mut oversized_events_diagnostic = diagnostic_arguments.clone();
    oversized_events_diagnostic[15] = OsString::from((UDP_DIAGNOSTIC_MAX_EVENTS + 1).to_string());
    let mut zero_trial_diagnostic = diagnostic_arguments.clone();
    zero_trial_diagnostic[17] = OsString::from("0");
    let mut wrong_trial_diagnostic = diagnostic_arguments.clone();
    wrong_trial_diagnostic[17] = OsString::from("30");
    let mut wrong_source_ip_diagnostic = diagnostic_arguments.clone();
    wrong_source_ip_diagnostic[19] = OsString::from("198.18.0.3");
    let mut wrong_source_port_first_diagnostic = diagnostic_arguments.clone();
    wrong_source_port_first_diagnostic[21] = OsString::from("20001");
    let mut wrong_source_port_last_diagnostic = diagnostic_arguments.clone();
    wrong_source_port_last_diagnostic[23] = OsString::from("28190");
    if parse_workload(&zero_nonce_diagnostic).is_ok()
        || parse_workload(&noncanonical_nonce_diagnostic).is_ok()
        || parse_workload(&oversized_events_diagnostic).is_ok()
        || parse_workload(&zero_trial_diagnostic).is_ok()
        || parse_workload(&wrong_trial_diagnostic).is_ok()
        || parse_workload(&wrong_source_ip_diagnostic).is_ok()
        || parse_workload(&wrong_source_port_first_diagnostic).is_ok()
        || parse_workload(&wrong_source_port_last_diagnostic).is_ok()
    {
        return Err("invalid Windows TUN workload diagnostic bounds were accepted".to_owned());
    }
    for option_index in [18_usize, 20, 22] {
        let mut missing_source_option = diagnostic_arguments.clone();
        missing_source_option.drain(option_index..(option_index + 2));
        if parse_workload(&missing_source_option).is_ok() {
            return Err(
                "incomplete Windows TUN workload diagnostic source options were accepted"
                    .to_owned(),
            );
        }
    }
    let mut canonical_with_diagnostic_source = arguments.clone();
    canonical_with_diagnostic_source.extend([
        OsString::from("--diagnostic-source-ip"),
        OsString::from("198.18.0.2"),
        OsString::from("--diagnostic-source-port-first"),
        OsString::from("20000"),
        OsString::from("--diagnostic-source-port-last"),
        OsString::from("28191"),
    ]);
    if parse_workload(&canonical_with_diagnostic_source).is_ok() {
        return Err("canonical Windows TUN workload accepted diagnostic source options".to_owned());
    }
    if usize::from(UDP_DIAGNOSTIC_SOURCE_PORT_LAST - UDP_DIAGNOSTIC_SOURCE_PORT_FIRST + 1)
        != ASSOCIATIONS
        || udp_diagnostic_source_endpoint(diagnostic, 0)?
            != "198.18.0.2:20000".parse().expect("literal")
        || udp_diagnostic_source_endpoint(diagnostic, 85)?
            != "198.18.0.2:20085".parse().expect("literal")
        || udp_diagnostic_source_endpoint(diagnostic, ASSOCIATIONS - 1)?
            != "198.18.0.2:28191".parse().expect("literal")
        || udp_diagnostic_source_endpoint(diagnostic, ASSOCIATIONS).is_ok()
    {
        return Err("Windows TUN UDP diagnostic source endpoint mapping is invalid".to_owned());
    }
    let mut relative_ledger_diagnostic = diagnostic_arguments.clone();
    relative_ledger_diagnostic[11] = OsString::from("workload-flow.ndjson");
    let mut wrong_extension_diagnostic = diagnostic_arguments.clone();
    wrong_extension_diagnostic[11] = directory.path().join("workload-flow.json").into_os_string();
    if parse_workload(&relative_ledger_diagnostic).is_ok()
        || parse_workload(&wrong_extension_diagnostic).is_ok()
    {
        return Err("unsafe Windows TUN workload diagnostic ledger path was accepted".to_owned());
    }
    let existing_ledger_path = directory.path().join("existing.ndjson");
    File::create(&existing_ledger_path)
        .map_err(|error| format!("create self-check existing ledger failed: {error}"))?;
    let mut existing_ledger_diagnostic = diagnostic_arguments.clone();
    existing_ledger_diagnostic[11] = existing_ledger_path.into_os_string();
    if parse_workload(&existing_ledger_diagnostic).is_ok() {
        return Err("existing Windows TUN workload diagnostic ledger was accepted".to_owned());
    }
    let support_ledger_path = directory.path().join("support.ndjson");
    let support_arguments: Vec<OsString> = [
        OsString::from("--listen-ip"),
        OsString::from("192.0.2.10"),
        OsString::from("--tcp-port"),
        OsString::from("443"),
        OsString::from("--udp-port"),
        OsString::from("53"),
        OsString::from("--diagnostic-ledger"),
        support_ledger_path.as_os_str().to_owned(),
        OsString::from("--diagnostic-run-nonce"),
        OsString::from("72623859790382856"),
        OsString::from("--diagnostic-max-events"),
        OsString::from("16384"),
    ]
    .into_iter()
    .collect();
    let support_parsed = parse_support(&support_arguments)?;
    let support_diagnostic = support_parsed
        .diagnostic
        .as_ref()
        .ok_or_else(|| "Windows TUN support diagnostic options were discarded".to_owned())?;
    if support_parsed.listen_ip != "192.0.2.10".parse::<IpAddr>().expect("literal")
        || support_parsed.tcp_port != 443
        || support_parsed.udp_port != 53
        || support_diagnostic.path != support_ledger_path
        || support_diagnostic.run_nonce != 0x0102_0304_0506_0708
        || support_diagnostic.max_events != 16_384
    {
        return Err("Windows TUN support diagnostic arguments were not preserved".to_owned());
    }
    let mut partial_support_diagnostic = support_arguments.clone();
    partial_support_diagnostic.truncate(partial_support_diagnostic.len() - 2);
    if parse_support(&partial_support_diagnostic).is_ok() {
        return Err("incomplete Windows TUN support diagnostic options were accepted".to_owned());
    }
    let finalize_arguments: Vec<OsString> = [
        "--target-ip",
        "192.0.2.10",
        "--udp-port",
        "53",
        "--diagnostic-run-nonce",
        "72623859790382856",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let finalize_parsed = parse_udp_diagnostic_finalize(&finalize_arguments)?;
    if finalize_parsed
        != (UdpDiagnosticFinalizeArgs {
            target_ip: "192.0.2.10".parse().expect("literal"),
            udp_port: 53,
            run_nonce: 0x0102_0304_0506_0708,
        })
    {
        return Err("Windows TUN UDP diagnostic finalize arguments were not preserved".to_owned());
    }
    let mut partial_finalize = finalize_arguments.clone();
    partial_finalize.truncate(partial_finalize.len() - 2);
    let mut duplicate_finalize = finalize_arguments.clone();
    duplicate_finalize.extend([OsString::from("--udp-port"), OsString::from("54")]);
    let mut extra_finalize = finalize_arguments.clone();
    extra_finalize.extend([OsString::from("--tcp-port"), OsString::from("443")]);
    let mut zero_nonce_finalize = finalize_arguments.clone();
    zero_nonce_finalize[5] = OsString::from("0");
    let mut noncanonical_nonce_finalize = finalize_arguments.clone();
    noncanonical_nonce_finalize[5] = OsString::from("01");
    let mut overflowing_port_finalize = finalize_arguments.clone();
    overflowing_port_finalize[3] = OsString::from("65535");
    if parse_udp_diagnostic_finalize(&partial_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&duplicate_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&extra_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&zero_nonce_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&noncanonical_nonce_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&overflowing_port_finalize).is_ok()
    {
        return Err("Windows TUN UDP diagnostic finalize argument boundary is open".to_owned());
    }
    if elapsed_rate(10, Duration::from_secs(2), "self-check")? != 5 {
        return Err("Windows TUN integer rate calculation is invalid".to_owned());
    }
    let payload = sequenced_payload(32, 0x0102_0304_0506_0708)?;
    if payload[..8] != 0x0102_0304_0506_0708_u64.to_be_bytes()
        || payload == sequenced_payload(32, 0x0102_0304_0506_0709)?
    {
        return Err("Windows TUN sequenced UDP payload is invalid".to_owned());
    }
    let diagnostic_identity = UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Bootstrap,
        trial_sequence: 31,
        association_index: 85,
        round: 0,
        run_nonce: 0x0102_0304_0506_0708,
        packet_nonce: 0x1112_1314_1516_1718,
    };
    let diagnostic_payload = diagnostic_identity.encode();
    if UdpDiagnosticPayload::parse(&diagnostic_payload) != Some(diagnostic_identity)
        || fragment_ack_for_request(&diagnostic_payload)?.is_some()
    {
        return Err("Windows TUN tagged UDP diagnostic payload did not round-trip".to_owned());
    }
    let finalize_identity = udp_diagnostic_finalize_marker(diagnostic_identity.run_nonce);
    let finalize_payload = finalize_identity.encode();
    if finalize_identity.phase != UdpDiagnosticPhase::Finalize
        || finalize_identity.trial_sequence != UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE
        || finalize_identity.association_index != u32::MAX
        || finalize_identity.round != u32::MAX
        || finalize_identity.packet_nonce != u64::MAX
        || UdpDiagnosticPayload::parse(&finalize_payload) != Some(finalize_identity)
        || !is_udp_diagnostic_finalize_marker(finalize_identity, diagnostic_identity.run_nonce)
        || is_udp_diagnostic_finalize_marker(
            finalize_identity,
            diagnostic_identity.run_nonce.wrapping_add(1),
        )
    {
        return Err("Windows TUN UDP diagnostic finalize marker identity is invalid".to_owned());
    }
    let mut invalid_magic = diagnostic_payload;
    invalid_magic[0] ^= 1;
    let mut invalid_version = diagnostic_payload;
    invalid_version[4] = UDP_DIAGNOSTIC_VERSION + 1;
    let mut invalid_phase = diagnostic_payload;
    invalid_phase[5] = 0;
    let mut zero_trial = diagnostic_payload;
    zero_trial[6..8].fill(0);
    let mut zero_run_nonce = diagnostic_payload;
    zero_run_nonce[16..24].fill(0);
    let mut extended_diagnostic_payload = diagnostic_payload.to_vec();
    extended_diagnostic_payload.push(0);
    if UdpDiagnosticPayload::parse(&invalid_magic).is_some()
        || UdpDiagnosticPayload::parse(&invalid_version).is_some()
        || UdpDiagnosticPayload::parse(&invalid_phase).is_some()
        || UdpDiagnosticPayload::parse(&zero_trial).is_some()
        || UdpDiagnosticPayload::parse(&zero_run_nonce).is_some()
        || UdpDiagnosticPayload::parse(&diagnostic_payload[..UDP_DIAGNOSTIC_PAYLOAD_LEN - 1])
            .is_some()
        || UdpDiagnosticPayload::parse(&extended_diagnostic_payload).is_some()
    {
        return Err("malformed Windows TUN tagged UDP diagnostic payload was accepted".to_owned());
    }
    let bounded_ledger_path = directory.path().join("bounded.ndjson");
    let bounded_ledger_arguments = UdpDiagnosticLedgerArgs {
        path: bounded_ledger_path.clone(),
        run_nonce: diagnostic_identity.run_nonce,
        max_events: 2,
    };
    let bounded_ledger = BoundedUdpDiagnosticLedger::create_with_reporting(
        &bounded_ledger_arguments,
        UDP_SUPPORT_LEDGER_SCHEMA,
        json!({
            "pid": 123,
            "listen_ip": "192.0.2.10",
            "tcp_port": 443,
            "udp_ports": [53, 54, 55, 56],
            "scope": UDP_DIAGNOSTIC_SCOPE,
            "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        }),
        false,
    )?;
    bounded_ledger.record(json!({"stage": "rx"}));
    bounded_ledger.record(json!({"stage": "tx"}));
    bounded_ledger.record(json!({"stage": "rx"}));
    if bounded_ledger.is_closed() {
        return Err(
            "Windows TUN UDP diagnostic ledger closed without an explicit boundary".to_owned(),
        );
    }
    bounded_ledger.close();
    bounded_ledger.record(json!({"stage": "after_close"}));
    if !bounded_ledger.is_closed() || bounded_ledger.counters() != (3, 2, 1, 0) {
        return Err("Windows TUN UDP diagnostic ledger event bound is invalid".to_owned());
    }
    drop(bounded_ledger);
    let bounded_records = fs::read_to_string(&bounded_ledger_path)
        .map_err(|error| format!("read bounded UDP diagnostic ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse bounded UDP diagnostic ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if bounded_records.len() != 5
        || bounded_records[0]["schema"] != UDP_SUPPORT_LEDGER_SCHEMA
        || bounded_records[0]["record_type"] != "header"
        || bounded_records[0]["pid"] != 123
        || bounded_records[0]["scope"] != UDP_DIAGNOSTIC_SCOPE
        || bounded_records[0]["closure"] != UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        || bounded_records[1]["stage"] != "rx"
        || bounded_records[1]["ledger_counters"]["attempted_events"] != 1
        || bounded_records[2]["stage"] != "tx"
        || bounded_records[3]["record_type"] != "truncation"
        || bounded_records[3]["attempted_events"] != 3
        || bounded_records[3]["events_written"] != 2
        || bounded_records[3]["dropped_events_at_least"] != 1
        || bounded_records[3]["write_failures"] != 0
        || bounded_records[4]["record_type"] != "footer"
        || bounded_records[4]["attempted_events"] != 3
        || bounded_records[4]["events_written"] != 2
        || bounded_records[4]["dropped_events"] != 1
        || bounded_records[4]["write_failures"] != 0
    {
        return Err("Windows TUN UDP diagnostic ledger records are invalid".to_owned());
    }
    let barrier_ledger_path = directory.path().join("barrier.ndjson");
    let barrier_ledger = BoundedUdpDiagnosticLedger::create_with_reporting(
        &UdpDiagnosticLedgerArgs {
            path: barrier_ledger_path.clone(),
            run_nonce: diagnostic_identity.run_nonce,
            max_events: 4,
        },
        UDP_SUPPORT_LEDGER_SCHEMA,
        json!({
            "pid": 123,
            "listen_ip": "192.0.2.10",
            "tcp_port": 443,
            "udp_ports": [53, 54, 55, 56],
            "scope": UDP_DIAGNOSTIC_SCOPE,
            "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        }),
        false,
    )?;
    let barrier_diagnostic = SupportUdpDiagnostic::new(barrier_ledger);
    let barrier_listen: SocketAddr = "192.0.2.10:53".parse().expect("literal");
    let barrier_peer: SocketAddr = "192.0.2.10:54321".parse().expect("literal");
    record_support_udp_event(
        Some(&barrier_diagnostic),
        SupportUdpLedgerEvent {
            stage: "rx",
            listen: barrier_listen,
            peer: barrier_peer,
            request: &diagnostic_payload,
            send_attempted: None,
            send_result: "pending",
            sent: None,
            error_kind: None,
        },
    );
    record_support_udp_event(
        Some(&barrier_diagnostic),
        SupportUdpLedgerEvent {
            stage: "tx",
            listen: barrier_listen,
            peer: barrier_peer,
            request: &diagnostic_payload,
            send_attempted: Some(true),
            send_result: "success",
            sent: Some(diagnostic_payload.len()),
            error_kind: None,
        },
    );
    let warmup_payload = UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Warmup,
        ..diagnostic_identity
    }
    .encode();
    let foreign_payload = UdpDiagnosticPayload {
        run_nonce: diagnostic_identity.run_nonce.wrapping_add(1),
        ..diagnostic_identity
    }
    .encode();
    for request in [
        &warmup_payload[..],
        &foreign_payload[..],
        b"ordinary UDP payload",
    ] {
        record_support_udp_event(
            Some(&barrier_diagnostic),
            SupportUdpLedgerEvent {
                stage: "rx",
                listen: barrier_listen,
                peer: barrier_peer,
                request,
                send_attempted: None,
                send_result: "pending",
                sent: None,
                error_kind: None,
            },
        );
    }
    barrier_diagnostic.observe_finalize_marker(
        0,
        barrier_listen,
        "198.51.100.10:54321".parse().expect("literal"),
        &finalize_payload,
    );
    for slot in 0..(ROUTE_TARGET_SLOTS - 1) {
        let listen = SocketAddr::new(
            barrier_listen.ip(),
            barrier_listen.port() + u16::try_from(slot).expect("slot fits u16"),
        );
        barrier_diagnostic.observe_finalize_marker(slot, listen, barrier_peer, &finalize_payload);
    }
    barrier_diagnostic.observe_finalize_marker(0, barrier_listen, barrier_peer, &finalize_payload);
    if barrier_diagnostic.ledger.is_closed() || barrier_diagnostic.ledger.counters() != (2, 2, 0, 0)
    {
        return Err(
            "Windows TUN UDP diagnostic finalize barrier closed before all slots".to_owned(),
        );
    }
    let final_slot = ROUTE_TARGET_SLOTS - 1;
    let final_listen = SocketAddr::new(
        barrier_listen.ip(),
        barrier_listen.port() + u16::try_from(final_slot).expect("slot fits u16"),
    );
    barrier_diagnostic.observe_finalize_marker(
        final_slot,
        final_listen,
        barrier_peer,
        &finalize_payload,
    );
    barrier_diagnostic.observe_finalize_marker(
        final_slot,
        final_listen,
        barrier_peer,
        &finalize_payload,
    );
    barrier_diagnostic
        .ledger
        .record(json!({"stage": "after_close"}));
    if !barrier_diagnostic.ledger.is_closed()
        || barrier_diagnostic.ledger.counters() != (2, 2, 0, 0)
    {
        return Err("Windows TUN UDP diagnostic finalize barrier is not idempotent".to_owned());
    }
    drop(barrier_diagnostic);
    let barrier_records = fs::read_to_string(&barrier_ledger_path)
        .map_err(|error| format!("read finalized UDP diagnostic ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse finalized UDP diagnostic ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if barrier_records.len() != 4
        || barrier_records[0]["closure"] != UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        || barrier_records[1]["stage"] != "rx"
        || barrier_records[2]["stage"] != "tx"
        || barrier_records[3]["record_type"] != "footer"
        || barrier_records[3]["attempted_events"] != 2
        || barrier_records[3]["events_written"] != 2
    {
        return Err("Windows TUN UDP diagnostic finalize barrier ledger is invalid".to_owned());
    }
    let degraded_ledger_path = directory.path().join("degraded.ndjson");
    let degraded_ledger_arguments = UdpDiagnosticLedgerArgs {
        path: degraded_ledger_path.clone(),
        run_nonce: diagnostic_identity.run_nonce,
        max_events: 2,
    };
    let degraded_ledger = BoundedUdpDiagnosticLedger::create_with_reporting(
        &degraded_ledger_arguments,
        UDP_SUPPORT_LEDGER_SCHEMA,
        json!({
            "scope": UDP_DIAGNOSTIC_SCOPE,
            "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        }),
        false,
    )?;
    degraded_ledger.record(json!({
        "oversized": "x".repeat(UDP_DIAGNOSTIC_MAX_EVENT_BYTES + 1)
    }));
    degraded_ledger.record(json!({"stage": "rx"}));
    if degraded_ledger.counters() != (2, 1, 0, 1) {
        return Err("Windows TUN UDP diagnostic write-failure accounting is invalid".to_owned());
    }
    drop(degraded_ledger);
    let degraded_records = fs::read_to_string(&degraded_ledger_path)
        .map_err(|error| format!("read degraded UDP diagnostic ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse degraded UDP diagnostic ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if degraded_records.len() != 3
        || degraded_records[1]["stage"] != "rx"
        || degraded_records[1]["event_index"] != 1
        || degraded_records[2]["attempted_events"] != 2
        || degraded_records[2]["events_written"] != 1
        || degraded_records[2]["write_failures"] != 1
    {
        return Err(
            "Windows TUN UDP diagnostic logging failure altered later recording".to_owned(),
        );
    }
    let failed_flow_path = directory.path().join("failed-flow.ndjson");
    let failed_flow_arguments = UdpWorkloadDiagnosticArgs {
        ledger: UdpDiagnosticLedgerArgs {
            path: failed_flow_path.clone(),
            run_nonce: diagnostic_identity.run_nonce,
            max_events: 3,
        },
        trial_sequence: diagnostic_identity.trial_sequence,
        source_ip: IpAddr::V4(UDP_DIAGNOSTIC_SOURCE_IPV4),
        source_port_first: UDP_DIAGNOSTIC_SOURCE_PORT_FIRST,
        source_port_last: UDP_DIAGNOSTIC_SOURCE_PORT_LAST,
    };
    let failed_flow = UdpWorkloadDiagnosticSession::create(&failed_flow_arguments)?;
    failed_flow.record_flow(
        UdpDiagnosticPayload {
            phase: UdpDiagnosticPhase::Warmup,
            ..diagnostic_identity
        },
        Some("198.18.0.2:54320".parse().expect("literal")),
        Some("192.0.2.10:53".parse().expect("literal")),
        UdpWorkloadFlowOutcome {
            send_result: "success",
            send_bytes: Some(UDP_DIAGNOSTIC_PAYLOAD_LEN),
            reply_result: "success",
            reply_source: Some("192.0.2.10:53".parse().expect("literal")),
            payload_match: true,
            error_kind: None,
        },
    );
    failed_flow.record_flow(
        diagnostic_identity,
        Some("198.18.0.2:20085".parse().expect("literal")),
        Some("192.0.2.10:53".parse().expect("literal")),
        UdpWorkloadFlowOutcome {
            send_result: "success",
            send_bytes: Some(UDP_DIAGNOSTIC_PAYLOAD_LEN),
            reply_result: "timeout",
            reply_source: None,
            payload_match: false,
            error_kind: Some("timeout"),
        },
    );
    let unobserved_identity = UdpDiagnosticPayload {
        association_index: diagnostic_identity.association_index + 1,
        packet_nonce: diagnostic_identity.packet_nonce + 1,
        ..diagnostic_identity
    };
    failed_flow.record_not_observed(&UdpWorkloadDiagnosticRequest {
        identity: unobserved_identity,
        payload: unobserved_identity.encode(),
        local: Some("198.18.0.2:20086".parse().expect("literal")),
        target: Some("192.0.2.10:53".parse().expect("literal")),
        sent: UDP_DIAGNOSTIC_PAYLOAD_LEN,
    });
    drop(failed_flow);
    let failed_flow_records = fs::read_to_string(&failed_flow_path)
        .map_err(|error| format!("read failed UDP flow ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse failed UDP flow ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unobserved_packet_nonce = unobserved_identity.packet_nonce.to_string();
    if failed_flow_records.len() != 4
        || failed_flow_records[0]["schema"] != UDP_WORKLOAD_LEDGER_SCHEMA
        || failed_flow_records[0]["scope"] != UDP_DIAGNOSTIC_SCOPE
        || failed_flow_records[0]["closure"] != UDP_WORKLOAD_DIAGNOSTIC_CLOSURE
        || failed_flow_records[0]["source_ip"] != UDP_DIAGNOSTIC_SOURCE_IPV4.to_string()
        || failed_flow_records[0]["source_port_first"] != UDP_DIAGNOSTIC_SOURCE_PORT_FIRST
        || failed_flow_records[0]["source_port_last"] != UDP_DIAGNOSTIC_SOURCE_PORT_LAST
        || failed_flow_records[1]["phase"] != "bootstrap"
        || failed_flow_records[1]["association_index"] != 85
        || failed_flow_records[1]["workload_local_port"] != 20085
        || failed_flow_records[1]["reply_result"] != "timeout"
        || failed_flow_records[1]["payload_match"] != false
        || failed_flow_records[2]["packet_nonce"].as_str() != Some(unobserved_packet_nonce.as_str())
        || failed_flow_records[2]["association_index"] != 86
        || failed_flow_records[2]["workload_local_port"] != 20086
        || failed_flow_records[2]["send_result"] != "success"
        || failed_flow_records[2]["reply_result"] != "not_observed"
        || failed_flow_records[2]["reply_source_ip"] != Value::Null
        || failed_flow_records[2]["payload_match"] != false
        || failed_flow_records[2]["error_kind"] != "prior_batch_failure"
        || failed_flow_records[3]["record_type"] != "footer"
    {
        return Err("Windows TUN UDP failed-flow diagnostic record is invalid".to_owned());
    }
    let batch_failure_ledger_path = directory.path().join("batch-failure.ndjson");
    let batch_failure_arguments = UdpWorkloadDiagnosticArgs {
        ledger: UdpDiagnosticLedgerArgs {
            path: batch_failure_ledger_path.clone(),
            run_nonce: diagnostic_identity.run_nonce,
            max_events: 2,
        },
        trial_sequence: diagnostic_identity.trial_sequence,
        source_ip: IpAddr::V4(UDP_DIAGNOSTIC_SOURCE_IPV4),
        source_port_first: UDP_DIAGNOSTIC_SOURCE_PORT_FIRST,
        source_port_last: UDP_DIAGNOSTIC_SOURCE_PORT_LAST,
    };
    let server_a = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind first diagnostic batch server failed: {error}"))?;
    let server_b = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind second diagnostic batch server failed: {error}"))?;
    let client_a = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind first diagnostic batch client failed: {error}"))?;
    let client_b = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind second diagnostic batch client failed: {error}"))?;
    client_a
        .connect(
            server_a
                .local_addr()
                .map_err(|error| format!("read first diagnostic server address failed: {error}"))?,
        )
        .map_err(|error| format!("connect first diagnostic batch client failed: {error}"))?;
    client_b
        .connect(
            server_b.local_addr().map_err(|error| {
                format!("read second diagnostic server address failed: {error}")
            })?,
        )
        .map_err(|error| format!("connect second diagnostic batch client failed: {error}"))?;
    client_a
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|error| format!("set diagnostic batch receive timeout failed: {error}"))?;
    let mut batch_failure_session = UdpWorkloadDiagnosticSession::create(&batch_failure_arguments)?;
    let mut batch_failure_reply = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
    let batch_failure = diagnostic_association_round(
        &[client_a, client_b],
        &mut batch_failure_reply,
        2,
        UdpDiagnosticPhase::Bootstrap,
        1,
        None,
        &mut batch_failure_session,
    )
    .expect_err("first diagnostic batch receive must time out");
    if !batch_failure.contains("phase=bootstrap association_index=0") {
        return Err("Windows TUN UDP batch failure identity is invalid".to_owned());
    }
    drop(batch_failure_session);
    let batch_failure_records = fs::read_to_string(&batch_failure_ledger_path)
        .map_err(|error| format!("read batch-failure UDP ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse batch-failure UDP ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if batch_failure_records.len() != 4
        || batch_failure_records[1]["association_index"] != 0
        || batch_failure_records[1]["send_result"] != "success"
        || batch_failure_records[1]["reply_result"] != "timeout"
        || batch_failure_records[2]["association_index"] != 1
        || batch_failure_records[2]["send_result"] != "success"
        || batch_failure_records[2]["reply_result"] != "not_observed"
        || batch_failure_records[2]["error_kind"] != "prior_batch_failure"
        || batch_failure_records[3]["record_type"] != "footer"
    {
        return Err("Windows TUN UDP batch-failure ledger is incomplete".to_owned());
    }
    if UDP_BATCH != 8 {
        return Err("Windows TUN UDP packet-rate batch recipe is invalid".to_owned());
    }
    if ASSOCIATIONS != 8_192
        || ASSOCIATION_BOOTSTRAP_BATCH != 1
        || ASSOCIATION_BOOTSTRAP_PACING_ASSOCIATIONS != 8
        || ASSOCIATION_BOOTSTRAP_PACING_DELAY != Duration::from_millis(25)
        || ASSOCIATION_LOOKUP_BATCH != 8
        || !ASSOCIATIONS.is_multiple_of(ASSOCIATION_BOOTSTRAP_BATCH)
        || !ASSOCIATIONS.is_multiple_of(ASSOCIATION_BOOTSTRAP_PACING_ASSOCIATIONS)
        || !ASSOCIATION_BOOTSTRAP_PACING_ASSOCIATIONS.is_multiple_of(ASSOCIATION_BOOTSTRAP_BATCH)
        || !ASSOCIATIONS.is_multiple_of(ASSOCIATION_LOOKUP_BATCH)
        || ASSOCIATION_LOOKUP_ROUNDS != 64
    {
        return Err("Windows TUN UDP association recipe is invalid".to_owned());
    }
    let fragment_sequence = 0x1112_1314_1516_1718_u64;
    let fragment_request = fragment_request(fragment_sequence);
    let expected_ack = fragment_ack(fragment_sequence);
    let support_ack = fragment_ack_for_request(&fragment_request)?
        .ok_or_else(|| "fragment request was classified as an ordinary echo".to_owned())?;
    if fragment_request.len() != FRAGMENT_PAYLOAD
        || fragment_request_sequence(&fragment_request)? != fragment_sequence
        || support_ack != expected_ack
        || fragment_ack_sequence(&support_ack)? != fragment_sequence
    {
        return Err("Windows TUN fragment request/ACK round trip is invalid".to_owned());
    }
    if fragment_ack_for_request(&payload)?.is_some() {
        return Err("ordinary UDP echo payload was classified as a fragment request".to_owned());
    }
    if FRAGMENT_ACK_LEN != 24
        || FRAGMENT_REPLY_BUFFER != FRAGMENT_ACK_LEN + 1
        || FRAGMENT_ACK_LEN > FRAGMENT_IPV4_RESPONSE_BOUND
    {
        return Err("Windows TUN fragment ACK bound is invalid".to_owned());
    }
    let fragment_data_capacity = ((PERFORMANCE_TUN_MTU - IPV4_HEADER_LEN) / 8) * 8;
    let fragment_count = (FRAGMENT_PAYLOAD + UDP_HEADER_LEN).div_ceil(fragment_data_capacity);
    let fragment_ipv4_len = FRAGMENT_PAYLOAD + UDP_HEADER_LEN + IPV4_HEADER_LEN;
    if fragment_count != 2
        || fragment_ipv4_len <= PERFORMANCE_TUN_MTU
        || fragment_ipv4_len > SUPPORT_UNDERLAY_IPV4_MTU
    {
        return Err(
            "Windows TUN fragment request must split at the TUN MTU without fragmenting the support underlay"
                .to_owned(),
        );
    }
    if fragment_ack_for_request(&fragment_request[..FRAGMENT_PAYLOAD - 1]).is_ok() {
        return Err("truncated fragment request was accepted".to_owned());
    }
    let mut extended_request = fragment_request.clone();
    extended_request.push(0);
    if fragment_ack_for_request(&extended_request).is_ok() {
        return Err("extended fragment request was accepted".to_owned());
    }
    let mut corrupted_request = fragment_request.clone();
    corrupted_request[FRAGMENT_PAYLOAD - 1] ^= 1;
    if fragment_ack_for_request(&corrupted_request).is_ok() {
        return Err("corrupted fragment request was accepted".to_owned());
    }
    if fragment_ack_sequence(&expected_ack[..FRAGMENT_ACK_LEN - 1]).is_ok() {
        return Err("truncated fragment ACK was accepted".to_owned());
    }
    let mut extended_ack = expected_ack.to_vec();
    extended_ack.push(0);
    if fragment_ack_sequence(&extended_ack).is_ok() {
        return Err("extended fragment ACK was accepted".to_owned());
    }
    let mut invalid_ack_tag = expected_ack;
    invalid_ack_tag[0] ^= 1;
    if fragment_ack_sequence(&invalid_ack_tag).is_ok() {
        return Err("fragment ACK with an invalid tag was accepted".to_owned());
    }
    let mut invalid_ack_request_len = expected_ack;
    invalid_ack_request_len[16..24].copy_from_slice(&((FRAGMENT_PAYLOAD - 1) as u64).to_be_bytes());
    if fragment_ack_sequence(&invalid_ack_request_len).is_ok() {
        return Err("fragment ACK with an invalid request length was accepted".to_owned());
    }
    if FRAGMENT_BATCH != 8
        || FRAGMENT_ACK_WINDOW != Duration::from_millis(500)
        || fragment_retry_budget(0) != 1
        || fragment_retry_budget(1) != 1
        || fragment_retry_budget(FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS) != 1
        || fragment_retry_budget(FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS + 1) != 2
    {
        return Err("Windows TUN fragment retry recipe is invalid".to_owned());
    }
    let mut ordered_batch = FragmentAckBatch::new(100, FRAGMENT_BATCH)?;
    let mut ordered_accounting = FragmentWorkloadAccounting::default();
    for sequence in [107, 100, 106, 101, 105, 102, 104, 103] {
        ordered_accounting.observe_ack(&mut ordered_batch, sequence)?;
    }
    if !ordered_batch.complete()
        || ordered_batch.sole_missing_sequence().is_ok()
        || ordered_accounting.duplicate_or_stale_acks != 0
    {
        return Err("Windows TUN out-of-order fragment ACK accounting is invalid".to_owned());
    }
    let mut multiple_missing_batch = FragmentAckBatch::new(150, FRAGMENT_BATCH)?;
    let mut multiple_missing_accounting = FragmentWorkloadAccounting::default();
    for sequence in 150..156 {
        multiple_missing_accounting.observe_ack(&mut multiple_missing_batch, sequence)?;
    }
    if multiple_missing_batch.sole_missing_sequence().is_ok() {
        return Err("Windows TUN multiple missing fragment ACKs were recoverable".to_owned());
    }
    let mut retry_batch = FragmentAckBatch::new(200, FRAGMENT_BATCH)?;
    let mut retry_accounting = FragmentWorkloadAccounting::default();
    retry_accounting.record_initial_attempts(FragmentPhase::Warmup, FRAGMENT_BATCH as u64)?;
    for sequence in 200..208 {
        if sequence != 203 {
            retry_accounting.observe_ack(&mut retry_batch, sequence)?;
        }
    }
    let retry_diagnostic = fragment_batch_failure("self-check", &retry_batch, 1);
    if retry_batch.complete()
        || retry_batch.sole_missing_sequence()? != 203
        || !retry_diagnostic.contains("first=200")
        || !retry_diagnostic.contains("end=208")
        || !retry_diagnostic.contains("seen=")
        || !retry_diagnostic.contains("missing=1")
        || !retry_diagnostic.contains("missing_sequences=[203]")
        || !retry_diagnostic.contains("budget=1")
        || retry_accounting.observe_ack(&mut retry_batch, 200).is_ok()
        || retry_accounting.observe_ack(&mut retry_batch, 208).is_ok()
    {
        return Err("Windows TUN missing/future fragment ACK mutation was accepted".to_owned());
    }
    retry_accounting.record_ack_window_expiration()?;
    retry_accounting.record_retransmission(FragmentPhase::Warmup, 203, 1)?;
    retry_accounting.observe_ack(&mut retry_batch, 203)?;
    retry_accounting.observe_ack(&mut retry_batch, 203)?;
    if !retry_batch.complete()
        || retry_accounting.observe_ack(&mut retry_batch, 203).is_ok()
        || retry_accounting
            .record_retransmission(FragmentPhase::Warmup, 204, 1)
            .is_ok()
        || retry_accounting.warmup_request_attempts != 9
        || retry_accounting.retransmissions != 1
        || retry_accounting.ack_window_expirations != 1
        || retry_accounting.duplicate_or_stale_acks != 1
    {
        return Err("Windows TUN bounded fragment retransmission accounting is invalid".to_owned());
    }
    let mut stale_batch = FragmentAckBatch::new(300, FRAGMENT_BATCH)?;
    let mut stale_accounting = FragmentWorkloadAccounting::default();
    stale_accounting.record_retransmission(FragmentPhase::Warmup, 299, 1)?;
    stale_accounting.observe_ack(&mut stale_batch, 299)?;
    if stale_accounting.observe_ack(&mut stale_batch, 299).is_ok()
        || stale_accounting.duplicate_or_stale_acks != 1
    {
        return Err("Windows TUN stale fragment ACK bound is invalid".to_owned());
    }
    let labels = [
        "tcp-single-flow",
        "tcp-256-flow-fairness",
        "udp-packets-per-second",
        "udp-8192-association-lookup-expiry",
        "udp-route-once",
        "fragment-reassembly-throughput",
        "wintun-ring-full-drop-rate",
    ];
    for label in labels {
        if Scenario::parse(label)?.label() != label {
            return Err("Windows TUN scenario label did not round-trip".to_owned());
        }
    }
    self_check_support_backlog()?;
    Ok(())
}
