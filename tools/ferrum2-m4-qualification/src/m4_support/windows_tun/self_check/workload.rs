use std::time::Duration;

use super::super::contract::Scenario;
use super::super::diagnostic::{
    ASSOCIATION_BOOTSTRAP_BATCH, ASSOCIATION_LOOKUP_BATCH, ASSOCIATION_LOOKUP_ROUNDS, ASSOCIATIONS,
    FRAGMENT_ACK_LEN, FRAGMENT_ACK_WINDOW, FRAGMENT_BATCH, FRAGMENT_IPV4_RESPONSE_BOUND,
    FRAGMENT_PAYLOAD, FRAGMENT_REPLY_BUFFER, FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS,
    FragmentAckBatch, FragmentPhase, FragmentWorkloadAccounting, IPV4_HEADER_LEN,
    PERFORMANCE_TUN_MTU, SUPPORT_UNDERLAY_IPV4_MTU, UDP_BATCH, UDP_HEADER_LEN, UDP_PACKET_TIMEOUT,
    UDP_RECEIVE_ATTEMPTS,
};
use super::super::workload::{
    elapsed_rate, fragment_ack, fragment_ack_for_request, fragment_ack_sequence,
    fragment_batch_failure, fragment_request, fragment_request_sequence, fragment_retry_budget,
    sequenced_payload,
};

pub(super) fn check_basics() -> Result<Vec<u8>, String> {
    if elapsed_rate(10, Duration::from_secs(2), "self-check")? != 5 {
        return Err("Windows TUN integer rate calculation is invalid".to_owned());
    }
    let payload = sequenced_payload(32, 0x0102_0304_0506_0708)?;
    if payload[..8] != 0x0102_0304_0506_0708_u64.to_be_bytes()
        || payload == sequenced_payload(32, 0x0102_0304_0506_0709)?
    {
        return Err("Windows TUN sequenced UDP payload is invalid".to_owned());
    }
    Ok(payload)
}

pub(super) fn check_recipe(payload: &[u8]) -> Result<(), String> {
    if UDP_BATCH != 1
        || UDP_RECEIVE_ATTEMPTS != 3
        || UDP_PACKET_TIMEOUT != Duration::from_millis(10)
    {
        return Err("Windows TUN UDP packet-rate batch recipe is invalid".to_owned());
    }
    if ASSOCIATIONS != 8_192
        || ASSOCIATION_BOOTSTRAP_BATCH != 1
        || ASSOCIATION_LOOKUP_BATCH != 8
        || !ASSOCIATIONS.is_multiple_of(ASSOCIATION_BOOTSTRAP_BATCH)
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
    if fragment_ack_for_request(payload)?.is_some() {
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
    if FRAGMENT_BATCH != 4
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
    for sequence in [103, 100, 102, 101] {
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
    for sequence in 150..152 {
        multiple_missing_accounting.observe_ack(&mut multiple_missing_batch, sequence)?;
    }
    if multiple_missing_batch.sole_missing_sequence().is_ok() {
        return Err("Windows TUN multiple missing fragment ACKs were recoverable".to_owned());
    }
    let mut retry_batch = FragmentAckBatch::new(200, FRAGMENT_BATCH)?;
    let mut retry_accounting = FragmentWorkloadAccounting::default();
    retry_accounting.record_initial_attempts(FragmentPhase::Warmup, FRAGMENT_BATCH as u64)?;
    for sequence in 200..204 {
        if sequence != 203 {
            retry_accounting.observe_ack(&mut retry_batch, sequence)?;
        }
    }
    let retry_diagnostic = fragment_batch_failure("self-check", &retry_batch, 1);
    if retry_batch.complete()
        || retry_batch.sole_missing_sequence()? != 203
        || !retry_diagnostic.contains("first=200")
        || !retry_diagnostic.contains("end=204")
        || !retry_diagnostic.contains("seen=")
        || !retry_diagnostic.contains("missing=1")
        || !retry_diagnostic.contains("missing_sequences=[203]")
        || !retry_diagnostic.contains("budget=1")
        || retry_accounting.observe_ack(&mut retry_batch, 200).is_ok()
        || retry_accounting.observe_ack(&mut retry_batch, 204).is_ok()
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
        || retry_accounting.warmup_request_attempts != 5
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
    Ok(())
}
