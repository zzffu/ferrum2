use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) const TCP_SINGLE_WARMUP: Duration = Duration::from_secs(10);
pub(crate) const TCP_SINGLE_ACTIVE: Duration = Duration::from_secs(60);
pub(crate) const TCP_SINGLE_PAYLOAD: usize = 65_536;
pub(crate) const TCP_SINGLE_MINIMUM_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const TCP_FAIRNESS_WARMUP: Duration = Duration::from_secs(10);
pub(crate) const TCP_FAIRNESS_ACTIVE: Duration = Duration::from_secs(30);
pub(crate) const TCP_FAIRNESS_FLOWS: usize = 256;
pub(crate) const TCP_FAIRNESS_PAYLOAD: usize = 16_384;
pub(crate) const TCP_FAIRNESS_READINESS_PAYLOAD: usize = 1_024;
pub(crate) const UDP_WARMUP: Duration = Duration::from_secs(5);
pub(crate) const UDP_ACTIVE: Duration = Duration::from_secs(30);
pub(crate) const UDP_PAYLOAD: usize = 1_200;
pub(crate) const UDP_BATCH: usize = 8;
pub(crate) const UDP_MINIMUM_DATAGRAMS: u64 = 4_096;
pub(crate) const ASSOCIATIONS: usize = 8_192;
pub(crate) const ASSOCIATION_BOOTSTRAP_BATCH: usize = 1;
pub(crate) const ASSOCIATION_LOOKUP_BATCH: usize = 8;
pub(crate) const ASSOCIATION_LOOKUP_ROUNDS: usize = 64;
pub(crate) const ASSOCIATION_WARMUP: Duration = Duration::from_secs(5);
pub(crate) const FRAGMENT_WARMUP: Duration = Duration::from_secs(5);
pub(crate) const FRAGMENT_ACTIVE: Duration = Duration::from_secs(30);
pub(crate) const FRAGMENT_PAYLOAD: usize = 1_440;
pub(crate) const FRAGMENT_BATCH: usize = 8;
pub(crate) const FRAGMENT_MINIMUM_DATAGRAMS: u64 = 4_096;
pub(crate) const FRAGMENT_ACK_WINDOW: Duration = Duration::from_millis(500);
pub(crate) const FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS: u64 = 1_000_000;
pub(crate) const FRAGMENT_REQUEST_TAG: [u8; 8] = *b"F2FRQ001";
pub(crate) const FRAGMENT_ACK_TAG: [u8; 8] = *b"F2FAK001";
pub(crate) const FRAGMENT_ACK_LEN: usize = 24;
pub(crate) const FRAGMENT_REPLY_BUFFER: usize = FRAGMENT_ACK_LEN + 1;
pub(crate) const PERFORMANCE_TUN_MTU: usize = 1_420;
pub(crate) const SUPPORT_UNDERLAY_IPV4_MTU: usize = 1_500;
pub(crate) const IPV4_HEADER_LEN: usize = 20;
pub(crate) const UDP_HEADER_LEN: usize = 8;
pub(crate) const FRAGMENT_IPV4_RESPONSE_BOUND: usize =
    PERFORMANCE_TUN_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;
pub(crate) const RING_BURST_ATTEMPTS: u64 = 1_000_000;
pub(crate) const ROUTE_SOURCE_SLOTS: usize = 64;
pub(crate) const ROUTE_TARGET_SLOTS: usize = 4;
pub(crate) const ROUTE_DATAGRAMS_PER_TARGET: usize = 32;
pub(crate) const ROUTE_PAYLOAD: usize = 32;
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const SUPPORT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const SUPPORT_MAX_TCP_CONNECTIONS: usize = 1_024;
pub(crate) const UDP_DIAGNOSTIC_PAYLOAD_LEN: usize = 32;
pub(crate) const UDP_DIAGNOSTIC_MAGIC: [u8; 4] = *b"F2U1";
pub(crate) const UDP_DIAGNOSTIC_VERSION: u8 = 1;
pub(crate) const UDP_DIAGNOSTIC_MAX_EVENTS: usize = 65_536;
pub(crate) const UDP_DIAGNOSTIC_MAX_EVENT_BYTES: usize = 4 * 1024;
pub(crate) const UDP_DIAGNOSTIC_SCOPE: &str = "bootstrap";
pub(crate) const UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE: u16 = 37;
pub(crate) const UDP_ASSOCIATION_SOURCE_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub(crate) const UDP_ASSOCIATION_SOURCE_PORT_FIRST: u16 = 20_000;
pub(crate) const UDP_ASSOCIATION_SOURCE_PORT_LAST: u16 = 28_191;
pub(crate) const UDP_WORKLOAD_DIAGNOSTIC_CLOSURE: &str = "workload_process_exit";
pub(crate) const UDP_SUPPORT_DIAGNOSTIC_CLOSURE: &str = "host_four_port_barrier_after_vm_off";
pub(crate) const UDP_WORKLOAD_LEDGER_SCHEMA: &str =
    "ferrum2.windows-tun.udp-workload-flow-ledger.v3";
pub(crate) const UDP_SUPPORT_LEDGER_SCHEMA: &str = "ferrum2.windows-tun.udp-support-ledger.v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum UdpDiagnosticPhase {
    Bootstrap = 1,
    Warmup = 2,
    Lookup = 3,
    Refresh = 4,
    Finalize = 5,
}

impl UdpDiagnosticPhase {
    pub(crate) fn parse(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Bootstrap),
            2 => Some(Self::Warmup),
            3 => Some(Self::Lookup),
            4 => Some(Self::Refresh),
            5 => Some(Self::Finalize),
            _ => None,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
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
pub(crate) struct UdpDiagnosticPayload {
    pub(crate) phase: UdpDiagnosticPhase,
    pub(crate) trial_sequence: u16,
    pub(crate) association_index: u32,
    pub(crate) round: u32,
    pub(crate) run_nonce: u64,
    pub(crate) packet_nonce: u64,
}

impl UdpDiagnosticPayload {
    pub(crate) fn encode(self) -> [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN] {
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

    pub(crate) fn parse(payload: &[u8]) -> Option<Self> {
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

pub(crate) fn udp_diagnostic_finalize_marker(run_nonce: u64) -> UdpDiagnosticPayload {
    UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Finalize,
        trial_sequence: UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE,
        association_index: u32::MAX,
        round: u32::MAX,
        run_nonce,
        packet_nonce: u64::MAX,
    }
}

pub(crate) fn is_udp_diagnostic_finalize_marker(
    identity: UdpDiagnosticPayload,
    run_nonce: u64,
) -> bool {
    identity == udp_diagnostic_finalize_marker(run_nonce)
}

#[derive(Clone, Debug)]
pub(crate) struct UdpDiagnosticLedgerArgs {
    pub(crate) path: PathBuf,
    pub(crate) run_nonce: u64,
    pub(crate) max_events: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct UdpWorkloadDiagnosticArgs {
    pub(crate) ledger: UdpDiagnosticLedgerArgs,
    pub(crate) trial_sequence: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UdpAssociationSourceArgs {
    pub(crate) source_ip: IpAddr,
    pub(crate) source_port_first: u16,
    pub(crate) source_port_last: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UdpDiagnosticFinalizeArgs {
    pub(crate) target_ip: IpAddr,
    pub(crate) udp_port: u16,
    pub(crate) run_nonce: u64,
}

pub(crate) struct BoundedUdpDiagnosticLedger {
    pub(crate) schema: &'static str,
    pub(crate) run_nonce: u64,
    pub(crate) state: Mutex<UdpDiagnosticLedgerState>,
    pub(crate) started: Instant,
    pub(crate) max_events: usize,
    pub(crate) reported_limit: AtomicBool,
    pub(crate) reported_write_failure: AtomicBool,
    pub(crate) report_degradation: bool,
}

pub(crate) struct UdpDiagnosticLedgerState {
    pub(crate) writer: File,
    pub(crate) attempted_events: usize,
    pub(crate) events_written: usize,
    pub(crate) dropped_events: usize,
    pub(crate) write_failures: usize,
    pub(crate) truncation_written: bool,
    pub(crate) writer_failed: bool,
    pub(crate) closed: bool,
}

impl BoundedUdpDiagnosticLedger {
    pub(crate) fn create(
        arguments: &UdpDiagnosticLedgerArgs,
        schema: &'static str,
        metadata: Value,
    ) -> Result<Self, String> {
        Self::create_with_reporting(arguments, schema, metadata, true)
    }

    pub(crate) fn create_with_reporting(
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

    pub(crate) fn record(&self, mut event: Value) {
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

    pub(crate) fn report_write_failure(&self, reason: &'static str) {
        if self.report_degradation && !self.reported_write_failure.swap(true, Ordering::AcqRel) {
            eprintln!("windows_tun_udp_diagnostic_ledger status=DEGRADED reason={reason}");
        }
    }

    pub(crate) fn counters(&self) -> (usize, usize, usize, usize) {
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

    pub(crate) fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }

    pub(crate) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(reason) = Self::write_footer(self.schema, self.run_nonce, &mut state) {
            drop(state);
            self.report_write_failure(reason);
        }
    }

    pub(crate) fn write_footer(
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

pub(crate) struct SupportUdpDiagnostic {
    pub(crate) ledger: BoundedUdpDiagnosticLedger,
    pub(crate) finalize_slots: Mutex<[bool; ROUTE_TARGET_SLOTS]>,
}

impl SupportUdpDiagnostic {
    pub(crate) fn new(ledger: BoundedUdpDiagnosticLedger) -> Self {
        Self {
            ledger,
            finalize_slots: Mutex::new([false; ROUTE_TARGET_SLOTS]),
        }
    }

    pub(crate) fn observe_finalize_marker(
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
pub(crate) enum FragmentPhase {
    Warmup,
    Active,
}

#[derive(Debug)]
pub(crate) struct FragmentAckBatch {
    pub(crate) first_sequence: u64,
    pub(crate) end_sequence: u64,
    pub(crate) seen: Vec<bool>,
}

impl FragmentAckBatch {
    pub(crate) fn new(first_sequence: u64, batch: usize) -> Result<Self, String> {
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

    pub(crate) fn observe(
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

    pub(crate) fn complete(&self) -> bool {
        self.seen.iter().all(|seen| *seen)
    }

    pub(crate) fn missing_sequences(&self) -> Vec<u64> {
        self.seen
            .iter()
            .enumerate()
            .filter(|(_, seen)| !**seen)
            .map(|(offset, _)| self.first_sequence + offset as u64)
            .collect()
    }

    pub(crate) fn sole_missing_sequence(&self) -> Result<u64, String> {
        let missing = self.missing_sequences();
        if missing.len() != 1 {
            return Err("fragment ACK window must leave exactly one missing sequence".to_owned());
        }
        Ok(missing[0])
    }

    pub(crate) fn seen_bitmap(&self) -> String {
        self.seen
            .iter()
            .map(|seen| if *seen { '1' } else { '0' })
            .collect()
    }
}

#[derive(Debug, Default)]
pub(crate) struct FragmentWorkloadAccounting {
    pub(crate) warmup_unique_datagrams: u64,
    pub(crate) warmup_request_attempts: u64,
    pub(crate) active_unique_datagrams: u64,
    pub(crate) active_request_attempts: u64,
    pub(crate) retransmissions: u64,
    pub(crate) ack_window_expirations: u64,
    pub(crate) duplicate_or_stale_acks: u64,
    pub(crate) retried_sequences: HashSet<u64>,
    pub(crate) duplicate_sequences: HashSet<u64>,
}

impl FragmentWorkloadAccounting {
    pub(crate) fn total_unique_datagrams(&self) -> Result<u64, String> {
        self.warmup_unique_datagrams
            .checked_add(self.active_unique_datagrams)
            .ok_or_else(|| "fragment total unique datagram count overflow".to_owned())
    }

    pub(crate) fn total_request_attempts(&self) -> Result<u64, String> {
        self.warmup_request_attempts
            .checked_add(self.active_request_attempts)
            .ok_or_else(|| "fragment total request attempt count overflow".to_owned())
    }

    pub(crate) fn record_initial_attempts(
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

    pub(crate) fn record_unique_datagrams(
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

    pub(crate) fn record_ack_window_expiration(&mut self) -> Result<(), String> {
        self.ack_window_expirations = self
            .ack_window_expirations
            .checked_add(1)
            .ok_or_else(|| "fragment ACK window expiration count overflow".to_owned())?;
        Ok(())
    }

    pub(crate) fn record_retransmission(
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

    pub(crate) fn record_duplicate_or_stale_ack(&mut self) -> Result<(), String> {
        self.duplicate_or_stale_acks = self
            .duplicate_or_stale_acks
            .checked_add(1)
            .ok_or_else(|| "fragment duplicate/stale ACK count overflow".to_owned())?;
        Ok(())
    }

    pub(crate) fn observe_ack(
        &mut self,
        batch: &mut FragmentAckBatch,
        sequence: u64,
    ) -> Result<(), String> {
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
