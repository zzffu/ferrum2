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
    client_random_bytes, flush_plain, provider, read_plain, response_wire_and_frames,
    salt_from_u64, server_target, target, valid_request_wire, write_plain,
};

fn assert_fixed_storage_never_grows(observers: &RecordingObservers) {
    let buffers = observers.buffers.lock().expect("buffers");
    assert_eq!(buffers.len(), 2);
    let capacities = observers.capacities.lock().expect("capacities");
    for (role, usable_limit, identity) in buffers.iter().copied() {
        let samples = capacities
            .iter()
            .filter(|sample| sample.0 == role)
            .collect::<Vec<_>>();
        assert!(!samples.is_empty(), "{role:?}: capacity was never observed");
        assert!(
            samples
                .iter()
                .all(|sample| sample.1 == identity && sample.2 == usable_limit),
            "{role:?}: storage identity or capacity changed"
        );
    }
}

#[tokio::test]
async fn minimum_request_uses_fixed_scratch_and_empty_independent_payload_owner() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_from_u64(299);
    let wire =
        encode_request_first_write(&keys, &salt, NOW, &target(), &[0xa1], &[]).expect("minimum");
    let (io, _) = RecordingIo::request(&wire);
    let observers = RecordingObservers::default();
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
        .with_observers(&observers, &observers);

    let session = inbound.accept_stream(io).await.expect("minimum request");

    assert!(session.initial_payload.is_empty());
    assert_fixed_storage_never_grows(&observers);
}

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
    drop(inspections);
    drop(buffers);
    assert_fixed_storage_never_grows(&observers);
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
    drop(inspections);
    drop(buffers);
    assert_fixed_storage_never_grows(&observers);
}

#[tokio::test]
async fn client_rx_and_server_tx_reuse_storage_across_32_subsequent_frames() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(303);
    let response_salt = salt_from_u64(304);
    let payloads = (0_u8..32).map(|value| vec![value]).collect::<Vec<_>>();
    let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
    let (response, frames) =
        response_wire_and_frames(&request_salt, &response_salt, b"first", &payload_refs);
    let mut reads = vec![response[..59].to_vec(), response[59..].to_vec()];
    reads.extend(frames);
    let (client_io, _) = RecordingIo::new(reads);
    let connector = RecordingConnector::succeeds(client_io);
    let client_random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let client_observers = RecordingObservers::default();
    let outbound =
        ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &client_random)
            .with_observers(&client_observers, &client_observers);
    let mut client = outbound.open_stream(&target()).await.expect("client");
    let mut destination = [0_u8; 16];

    let first = read_plain(&mut client, &mut destination)
        .await
        .expect("first payload");
    assert_eq!(&destination[..first], b"first");
    for expected in 0_u8..32 {
        let read = read_plain(&mut client, &mut destination)
            .await
            .expect("subsequent client RX frame");
        assert_eq!(&destination[..read], &[expected]);
    }
    assert_fixed_storage_never_grows(&client_observers);

    let replay = TcpReplayStore::new(1024).expect("capacity");
    let request = valid_request_wire(NOW, &request_salt);
    let (server_io, _) = RecordingIo::request(&request);
    let server_random = ScriptedRandom::new(response_salt.as_bytes().iter().copied());
    let server_observers = RecordingObservers::default();
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay)
        .with_observers(&server_observers, &server_observers);
    let mut server = inbound
        .accept_stream(server_io)
        .await
        .expect("server")
        .stream;

    assert_eq!(write_plain(&mut server, b"first").await, Ok(5));
    flush_plain(&mut server).await.expect("first response");
    for value in 0_u8..32 {
        assert_eq!(write_plain(&mut server, &[value]).await, Ok(1));
        flush_plain(&mut server)
            .await
            .expect("subsequent server TX frame");
    }
    assert_fixed_storage_never_grows(&server_observers);
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
