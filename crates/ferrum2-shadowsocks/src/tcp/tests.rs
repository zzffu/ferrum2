use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, TargetAddr};
use ferrum2_crypto::{
    MethodProfile, MethodPsk, MethodSinglePskProvider, MethodTcpSalt, MonotonicInstant, TcpSealer,
};

use super::error::{
    OneShotCipherFault, frame_from_open_aead, frame_from_seal_aead, terminate_detection,
};
use super::flow::{Lifecycle, protocol_cipher_boundary};
use super::observe::{NOOP_OBSERVER, fixed_scratch};
use super::replay::{MIN_REPLAY_CAPACITY, ReplayInsertError};
use super::wire::{
    ENCRYPTED_LENGTH_LEN, encode_request_state_into, encode_response_state_into,
    open_data_frame_into, opener_for, seal_data_chunk_into, sealer_for,
};
use super::*;
#[derive(Default)]
struct CountingFlowObserver {
    terminals: AtomicUsize,
    abortive: AtomicUsize,
}

impl FlowObserver for CountingFlowObserver {
    fn terminal_installed(&self, _terminal: FlowTerminal) {
        self.terminals.fetch_add(1, Ordering::SeqCst);
    }
}

impl AbortiveClose for CountingFlowObserver {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.abortive.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct SequenceFlowObserver(Arc<Mutex<Vec<&'static str>>>);

impl FlowObserver for SequenceFlowObserver {
    fn terminal_installed(&self, _terminal: FlowTerminal) {
        self.0.lock().expect("sequence").push("terminal");
    }
}

struct FailingAbortive {
    calls: usize,
    sequence: Arc<Mutex<Vec<&'static str>>>,
}

impl AbortiveClose for FailingAbortive {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.calls += 1;
        self.sequence.lock().expect("sequence").push("abortive");
        Err(())
    }
}

fn provider() -> MethodKeyAdapter<MethodSinglePskProvider> {
    MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes128([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ])))
}

fn salt(last: u8) -> MethodTcpSalt {
    let mut bytes = [0_u8; TCP_SALT_LEN];
    bytes[TCP_SALT_LEN - 1] = last;
    MethodTcpSalt::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &bytes).expect("AES-128 salt")
}

fn assert_scratch_unchanged(scratch: &BytesMut, identity: usize, capacity: usize) {
    assert_eq!(scratch.as_ptr() as usize, identity);
    assert_eq!(scratch.capacity(), capacity);
}

fn encrypted_frame(sealer: &mut TcpSealer, payload: &[u8]) -> (BytesMut, BytesMut) {
    let mut length = BytesMut::from(
        &u16::try_from(payload.len())
            .expect("test payload fits")
            .to_be_bytes()[..],
    );
    let mut payload = BytesMut::from(payload);
    sealer.seal_in_place(&mut length).expect("seal length");
    sealer.seal_in_place(&mut payload).expect("seal payload");
    (length, payload)
}

#[test]
fn client_seal_nonce_flow_internal_contract() {
    let observer = CountingFlowObserver::default();
    let mut lifecycle = Lifecycle::default();
    let mut fault = OneShotCipherFault::default();

    let error = protocol_cipher_boundary(&mut lifecycle, &observer, || {
        fault.seal().map_err(frame_from_seal_aead)
    })
    .expect_err("nonce exhaustion");

    assert_eq!(
        error,
        ShadowsocksError::Protocol(ProtocolReason::NonceExhausted)
    );
    assert_eq!(
        lifecycle.terminal,
        Some(FlowTerminal::Protocol(ProtocolReason::NonceExhausted))
    );
    assert_eq!(fault.calls(), 1);
    assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
    assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);

    let repeated = protocol_cipher_boundary(&mut lifecycle, &observer, || {
        fault.seal().map_err(frame_from_seal_aead)
    });
    assert_eq!(repeated, Err(error));
    assert_eq!(fault.calls(), 1, "terminal freezes the one-shot boundary");
    assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
    assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);
}

#[test]
fn server_open_nonce_flow_internal_contract() {
    let observer = CountingFlowObserver::default();
    let mut lifecycle = Lifecycle::default();
    let mut fault = OneShotCipherFault::default();

    let error = protocol_cipher_boundary(&mut lifecycle, &observer, || {
        fault.open().map_err(frame_from_open_aead)
    })
    .expect_err("nonce exhaustion");

    assert_eq!(
        error,
        ShadowsocksError::Protocol(ProtocolReason::NonceExhausted)
    );
    assert_eq!(
        lifecycle.terminal,
        Some(FlowTerminal::Protocol(ProtocolReason::NonceExhausted))
    );
    assert_eq!(fault.calls(), 1);
    assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
    assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);

    let repeated = protocol_cipher_boundary(&mut lifecycle, &observer, || {
        fault.open().map_err(frame_from_open_aead)
    });
    assert_eq!(repeated, Err(error));
    assert_eq!(fault.calls(), 1, "terminal freezes the one-shot boundary");
    assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
    assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);
}

#[test]
fn encrypt_scratch_capacity_flow_internal_contract() {
    let keys = provider();
    let mut sealer = sealer_for(&keys, &salt(1)).expect("sealer");
    let mut reference = sealer_for(&keys, &salt(1)).expect("reference sealer");
    let mut scratch = fixed_scratch(BufferRole::Encrypt, MAX_ENCRYPT_WIRE_LEN, &NOOP_OBSERVER);
    let identity = scratch.as_ptr() as usize;
    let capacity = scratch.capacity();

    for payload in [Vec::new(), vec![0x5a; MAX_ENCODE_PAYLOAD_LEN]]
        .into_iter()
        .chain((0_u8..32).map(|value| vec![value]))
    {
        seal_data_chunk_into(&mut sealer, &payload, &mut scratch).expect("seal frame");
        let (encrypted_length, encrypted_payload) = encrypted_frame(&mut reference, &payload);
        let mut expected =
            BytesMut::with_capacity(encrypted_length.len() + encrypted_payload.len());
        expected.extend_from_slice(&encrypted_length);
        expected.extend_from_slice(&encrypted_payload);
        assert_eq!(scratch, expected, "append-only wire remains byte-exact");
        assert_scratch_unchanged(&scratch, identity, capacity);
    }
}

#[test]
fn encrypt_scratch_capacity_failure_precedes_nonce_commit() {
    let keys = provider();
    let frame_len = ENCRYPTED_LENGTH_LEN + 1 + TAG_LEN;
    let mut sealer = sealer_for(&keys, &salt(4)).expect("sealer");
    let mut undersized = BytesMut::with_capacity(frame_len - 1);
    undersized.extend_from_slice(b"sentinel");
    let original = undersized.clone();

    assert_eq!(
        seal_data_chunk_into(&mut sealer, b"x", &mut undersized),
        Err(FrameError::Bounds)
    );
    assert_eq!(undersized, original);

    let mut scratch = BytesMut::with_capacity(frame_len);
    seal_data_chunk_into(&mut sealer, b"x", &mut scratch)
        .expect("capacity failure did not consume nonce");
    let mut reference = sealer_for(&keys, &salt(4)).expect("reference sealer");
    let (length, payload) = encrypted_frame(&mut reference, b"x");
    assert_eq!(&scratch[..ENCRYPTED_LENGTH_LEN], length);
    assert_eq!(&scratch[ENCRYPTED_LENGTH_LEN..], payload);
}

#[test]
fn first_write_append_only_layout_preserves_storage_identity() {
    let keys = provider();
    let request_salt = salt(5);
    let response_salt = salt(6);
    let target =
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)).expect("valid target");
    let mut scratch = fixed_scratch(BufferRole::Encrypt, MAX_ENCRYPT_WIRE_LEN, &NOOP_OBSERVER);
    let identity = scratch.as_ptr() as usize;
    let capacity = scratch.capacity();

    let expected_request =
        encode_request_first_write(&keys, &request_salt, 7, &target, &[0xa1], b"request")
            .expect("request fixture");
    encode_request_state_into(
        &keys,
        &request_salt,
        7,
        &target,
        &[0xa1],
        b"request",
        &mut scratch,
    )
    .expect("request state");
    assert_eq!(scratch, expected_request);
    assert_scratch_unchanged(&scratch, identity, capacity);

    let expected_response =
        encode_response_first_write(&keys, &response_salt, 8, &request_salt, b"response")
            .expect("response fixture");
    encode_response_state_into(
        &keys,
        &response_salt,
        8,
        &request_salt,
        b"response",
        &mut scratch,
    )
    .expect("response state");
    assert_eq!(scratch, expected_response);
    assert_scratch_unchanged(&scratch, identity, capacity);
}

#[test]
fn first_write_capacity_failure_preserves_existing_scratch() {
    let keys = provider();
    let request_salt = salt(7);
    let response_salt = salt(8);
    let target =
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)).expect("valid target");
    let mut scratch = BytesMut::with_capacity(1);
    scratch.extend_from_slice(&[0xa5]);
    let original = scratch.clone();

    assert!(matches!(
        encode_request_state_into(&keys, &request_salt, 9, &target, &[0xa1], &[], &mut scratch,),
        Err(FrameError::Bounds)
    ));
    assert_eq!(scratch, original);

    assert!(matches!(
        encode_response_state_into(
            &keys,
            &response_salt,
            10,
            &request_salt,
            b"response",
            &mut scratch,
        ),
        Err(FrameError::Bounds)
    ));
    assert_eq!(scratch, original);
}

#[test]
fn decrypt_scratch_capacity_flow_internal_contract() {
    let keys = provider();
    let salt = salt(2);
    let mut sealer = sealer_for(&keys, &salt).expect("sealer");
    let mut opener = opener_for(&keys, &salt).expect("opener");
    let mut scratch = fixed_scratch(BufferRole::Decrypt, MAX_DECRYPT_WIRE_LEN, &NOOP_OBSERVER);
    let identity = scratch.as_ptr() as usize;
    let capacity = scratch.capacity();
    assert_eq!(scratch.len(), MAX_DECRYPT_WIRE_LEN);

    for payload in [Vec::new(), vec![0xa5; MAX_PAYLOAD_LEN]]
        .into_iter()
        .chain((0_u8..32).map(|value| vec![value]))
    {
        let (length, encrypted_payload) = encrypted_frame(&mut sealer, &payload);
        let plaintext_len =
            open_data_frame_into(&mut opener, &length, &encrypted_payload, &mut scratch)
                .expect("open frame");
        assert_eq!(&scratch[..plaintext_len], payload);
        assert_eq!(scratch.len(), MAX_DECRYPT_WIRE_LEN);
        assert_scratch_unchanged(&scratch, identity, capacity);
    }
}

#[test]
fn replay_unavailable_detection_reason_contract() {
    let replay = TcpReplayStore::new(MIN_REPLAY_CAPACITY).expect("capacity");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = replay.state.lock().expect("replay lock");
        panic!("poison replay state for the private failure-path contract");
    }));
    assert_eq!(
        replay.check_and_insert(&salt(3), MonotonicInstant::from_duration(Duration::ZERO),),
        Err(ReplayInsertError::Unavailable)
    );

    let sequence = Arc::new(Mutex::new(Vec::new()));
    let observer = SequenceFlowObserver(sequence.clone());
    let mut io = FailingAbortive {
        calls: 0,
        sequence: sequence.clone(),
    };
    let error = terminate_detection(&mut io, &observer, DetectionReason::ReplayUnavailable);

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ReplayUnavailable)
    );
    assert_eq!(io.calls, 1);
    assert_eq!(
        *sequence.lock().expect("sequence"),
        vec!["terminal", "abortive"]
    );
}
