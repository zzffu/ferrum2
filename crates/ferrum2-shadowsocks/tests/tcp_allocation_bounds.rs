mod common;

use bytes::BytesMut;
use ferrum2_crypto::{KeyProvider, KeySelector, TcpMethod, TcpOpener, TcpSealer};
use ferrum2_shadowsocks::{
    BufferRole, ClientTcpOutbound, MAX_DECRYPT_WIRE_LEN, MAX_ENCODE_PAYLOAD_LEN,
    MAX_ENCRYPT_WIRE_LEN, ShadowsocksTcpInbound, TcpReplayStore, encode_request_first_write,
    open_data_frame,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, RecordingObservers, ScriptedRandom,
    client_random_bytes, provider, salt_from_u64, server_target, target, write_plain,
};

#[tokio::test]
async fn maximum_request_uses_one_fixed_scratch_per_role_and_independent_payload_owner() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_from_u64(300);
    let initial_payload = vec![0x5a; u16::MAX as usize - 9];
    let wire = encode_request_first_write(&keys, &salt, NOW, &target(), &[], &initial_payload)
        .expect("maximum legal variable chunk");
    let (io, _) = RecordingIo::request(&wire);
    let observers = RecordingObservers::default();
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
        .with_observers(&observers, &observers);

    let session = inbound
        .accept_stream(io)
        .await
        .expect("maximum legal request");

    assert_eq!(session.initial_payload.as_ref(), initial_payload);
    let buffers = observers.buffers.lock().expect("buffers");
    assert_eq!(buffers.len(), 2);
    assert_eq!(buffers[0].0, BufferRole::Decrypt);
    assert_eq!(buffers[0].1, MAX_DECRYPT_WIRE_LEN);
    assert_ne!(buffers[0].2, session.initial_payload.as_ptr() as usize);
    assert_eq!(buffers[1].0, BufferRole::Encrypt);
    assert_eq!(buffers[1].1, MAX_ENCRYPT_WIRE_LEN);
    assert_ne!(buffers[0].2, buffers[1].2);
    let inspections = observers.inspections.lock().expect("inspections");
    assert!(inspections.iter().all(|(role, identity)| {
        let allocated = buffers
            .iter()
            .find(|entry| entry.0 == *role)
            .expect("role allocated");
        *identity == allocated.2
    }));
}

#[tokio::test]
async fn client_flow_allocates_once_then_admits_0_1_16384_16385_with_fixed_cap() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_from_u64(301);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let (io, _) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let observers = RecordingObservers::default();
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random)
        .with_observers(&observers, &observers);
    let mut flow = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");

    assert_eq!(write_plain(&mut flow, &[]).await, Ok(0));
    assert_eq!(write_plain(&mut flow, &[1]).await, Ok(1));
    assert_eq!(
        write_plain(&mut flow, &vec![2; MAX_ENCODE_PAYLOAD_LEN]).await,
        Ok(MAX_ENCODE_PAYLOAD_LEN)
    );
    assert_eq!(
        write_plain(&mut flow, &vec![3; MAX_ENCODE_PAYLOAD_LEN + 1]).await,
        Ok(MAX_ENCODE_PAYLOAD_LEN)
    );

    let buffers = observers.buffers.lock().expect("buffers");
    assert_eq!(buffers.len(), 2);
    assert_eq!(
        buffers.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![BufferRole::Encrypt, BufferRole::Decrypt]
    );
    assert_eq!(buffers[0].1, MAX_ENCRYPT_WIRE_LEN);
    assert_eq!(buffers[1].1, MAX_DECRYPT_WIRE_LEN);
    let inspections = observers.inspections.lock().expect("inspections");
    assert!(inspections.len() >= 8);
    assert!(inspections.iter().all(|(role, identity)| {
        let allocated = buffers
            .iter()
            .find(|entry| entry.0 == *role)
            .expect("role allocated");
        *identity == allocated.2
    }));
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
