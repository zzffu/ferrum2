use super::diagnostic::{
    ASSOCIATION_BOOTSTRAP_BATCH, ASSOCIATION_LOOKUP_BATCH, ASSOCIATION_LOOKUP_ROUNDS,
    ASSOCIATION_WARMUP, ASSOCIATIONS, BoundedUdpDiagnosticLedger, UDP_DIAGNOSTIC_PAYLOAD_LEN,
    UDP_DIAGNOSTIC_SCOPE, UDP_WORKLOAD_DIAGNOSTIC_CLOSURE, UDP_WORKLOAD_LEDGER_SCHEMA,
    UdpAssociationSourceArgs, UdpDiagnosticPayload, UdpDiagnosticPhase, UdpWorkloadDiagnosticArgs,
};
use super::workload::{association_round, connected_udp_association, elapsed_rate};
use serde_json::{Value, json};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

pub(crate) struct UdpWorkloadDiagnosticSession {
    pub(crate) arguments: UdpWorkloadDiagnosticArgs,
    pub(crate) ledger: BoundedUdpDiagnosticLedger,
    pub(crate) next_packet_nonce: u64,
}

pub(crate) struct UdpWorkloadFlowOutcome<'a> {
    pub(crate) send_result: &'a str,
    pub(crate) send_bytes: Option<usize>,
    pub(crate) reply_result: &'a str,
    pub(crate) reply_source: Option<SocketAddr>,
    pub(crate) payload_match: bool,
    pub(crate) error_kind: Option<&'a str>,
}

pub(crate) struct UdpWorkloadDiagnosticRequest {
    pub(crate) identity: UdpDiagnosticPayload,
    pub(crate) payload: [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN],
    pub(crate) local: Option<SocketAddr>,
    pub(crate) target: Option<SocketAddr>,
    pub(crate) sent: usize,
}

impl UdpWorkloadDiagnosticSession {
    pub(crate) fn create(
        arguments: &UdpWorkloadDiagnosticArgs,
        source: &UdpAssociationSourceArgs,
    ) -> Result<Self, String> {
        Ok(Self {
            ledger: BoundedUdpDiagnosticLedger::create(
                &arguments.ledger,
                UDP_WORKLOAD_LEDGER_SCHEMA,
                json!({
                    "trial_sequence": arguments.trial_sequence,
                    "scope": UDP_DIAGNOSTIC_SCOPE,
                    "closure": UDP_WORKLOAD_DIAGNOSTIC_CLOSURE,
                    "source_ip": source.source_ip.to_string(),
                    "source_port_first": source.source_port_first,
                    "source_port_last": source.source_port_last
                }),
            )?,
            arguments: arguments.clone(),
            next_packet_nonce: 0,
        })
    }

    pub(crate) fn payload(
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

    pub(crate) fn record_flow(
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

    pub(crate) fn record_not_observed(&self, request: &UdpWorkloadDiagnosticRequest) {
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

pub(crate) fn bounded_io_error_kind(kind: ErrorKind) -> &'static str {
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

pub(crate) fn diagnostic_association_round(
    sockets: &[UdpSocket],
    reply: &mut [u8; UDP_DIAGNOSTIC_PAYLOAD_LEN],
    batch_associations: usize,
    phase: UdpDiagnosticPhase,
    round: u32,
    diagnostic: &mut UdpWorkloadDiagnosticSession,
) -> Result<(), String> {
    if batch_associations == 0 || !sockets.len().is_multiple_of(batch_associations) {
        return Err("diagnostic association batch bounds are invalid".to_owned());
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
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct AssociationRoundSpec<'a> {
    pub(crate) seed_prefix: u64,
    pub(crate) batch_associations: usize,
    pub(crate) phase_label: &'a str,
    pub(crate) phase: UdpDiagnosticPhase,
    pub(crate) round: u32,
}

pub(crate) fn association_round_selected(
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
            diagnostic,
        )
    } else {
        association_round(
            sockets,
            spec.seed_prefix,
            reply,
            spec.batch_associations,
            spec.phase_label,
        )
    }
}

pub(crate) fn udp_associations(
    address: SocketAddr,
    source_arguments: &UdpAssociationSourceArgs,
    diagnostic_arguments: Option<&UdpWorkloadDiagnosticArgs>,
) -> Result<Value, String> {
    let mut diagnostic = diagnostic_arguments
        .map(|arguments| UdpWorkloadDiagnosticSession::create(arguments, source_arguments))
        .transpose()?;
    let mut sockets = Vec::with_capacity(ASSOCIATIONS);
    let mut reply = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
    for association_index in 0..ASSOCIATIONS {
        sockets.push(connected_udp_association(
            address,
            source_arguments,
            association_index,
        )?);
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
