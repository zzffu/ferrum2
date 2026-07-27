mod common;

use bytes::BytesMut;
use ferrum2_crypto::{KeyProvider, KeySelector, TcpMethod, TcpOpener, TcpSealer};
use ferrum2_shadowsocks::{
    ClientTcpOutbound, FrameError, MAX_DECRYPT_WIRE_LEN, MAX_ENCODE_PAYLOAD_LEN,
    REQUEST_FIRST_READ_LEN, TcpReplayStore, accept_server_request, encode_request_first_write,
    open_data_frame,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes, provider,
    salt_from_u64, target,
};

#[tokio::test]
async fn maximum_peer_chunk_uses_the_single_fixed_decrypt_cap() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_from_u64(300);
    let initial_payload = vec![0x5a; u16::MAX as usize - 9];
    let wire = encode_request_first_write(&keys, &salt, NOW, &target(), &[], &initial_payload)
        .expect("maximum legal variable chunk");
    let (io, observation) = RecordingIo::request(&wire);

    let accepted = accept_server_request(io, &keys, &clock, &replay)
        .await
        .expect("maximum legal request");

    assert_eq!(accepted.initial_payload().len(), initial_payload.len());
    let observed = observation.lock().expect("observation");
    assert_eq!(
        observed.read_lengths,
        vec![REQUEST_FIRST_READ_LEN, MAX_DECRYPT_WIRE_LEN]
    );
    assert!(
        observed
            .read_lengths
            .iter()
            .all(|length| *length <= MAX_DECRYPT_WIRE_LEN)
    );
}

#[tokio::test]
async fn ferrum_encoder_caps_application_chunks_at_16_kib() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_from_u64(301);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let (io, _) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(&keys, &connector, &clock, &random);
    let mut opened = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");

    assert!(
        opened
            .seal_request_chunk(&vec![0x11; MAX_ENCODE_PAYLOAD_LEN])
            .is_ok()
    );
    assert_eq!(
        opened
            .seal_request_chunk(&vec![0x22; MAX_ENCODE_PAYLOAD_LEN + 1])
            .err(),
        Some(FrameError::Bounds)
    );
}

#[test]
fn decoder_accepts_the_full_65535_byte_peer_payload_range() {
    let keys = provider();
    let salt = salt_from_u64(302);
    let mut sealer = keys
        .with_key(KeySelector::Default, |key| {
            TcpSealer::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, &salt))
        })
        .expect("default key");
    let mut opener = keys
        .with_key(KeySelector::Default, |key| {
            TcpOpener::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, &salt))
        })
        .expect("default key");
    let mut length = BytesMut::from(&u16::MAX.to_be_bytes()[..]);
    let mut payload = BytesMut::from(&vec![0x33; u16::MAX as usize][..]);
    sealer.seal_in_place(&mut length).expect("length seal");
    sealer.seal_in_place(&mut payload).expect("payload seal");

    let opened = open_data_frame(&mut opener, &length, &payload).expect("maximum peer payload");

    assert_eq!(opened.len(), u16::MAX as usize);
    assert!(opened.iter().all(|byte| *byte == 0x33));
}
