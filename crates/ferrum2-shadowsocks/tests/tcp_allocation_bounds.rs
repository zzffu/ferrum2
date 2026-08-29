mod common;

use bytes::BytesMut;
use ferrum2_crypto::MethodProfile;
use ferrum2_shadowsocks::{
    BufferRole, ClientTcpOutbound, INITIAL_ENCODE_PAYLOAD_LEN, INITIAL_ENCRYPT_WIRE_LEN,
    MAX_DECRYPT_WIRE_LEN, ShadowsocksTcpInbound, TAG_LEN, TcpKeyProvider, TcpReplayStore,
    encode_request_first_write, open_data_frame,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, RecordingObservers, ScriptedRandom,
    client_random_bytes, flush_plain, method_provider, method_salt_from_u64, provider, read_plain,
    response_wire_and_frames, salt_from_u64, server_target, target, valid_request_wire,
    write_plain,
};

fn assert_fixed_storage_identity(observers: &RecordingObservers) {
    let buffers = observers.buffers.lock().expect("buffers");
    assert_eq!(buffers.len(), 2);
    for (role, usable_limit, identity) in buffers.iter().copied() {
        assert!(matches!(
            (role, usable_limit),
            (BufferRole::Encrypt, INITIAL_ENCRYPT_WIRE_LEN)
                | (BufferRole::Decrypt, MAX_DECRYPT_WIRE_LEN)
        ));
        let samples = observers
            .inspections
            .lock()
            .expect("inspections")
            .iter()
            .filter(|sample| sample.0 == role)
            .copied()
            .collect::<Vec<_>>();
        assert!(!samples.is_empty(), "{role:?}: identity was never observed");
        assert!(
            samples.iter().all(|sample| sample.1 == identity),
            "{role:?}: storage identity changed"
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
    assert_fixed_storage_identity(&observers);
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
    assert_eq!(buffers[1].1, INITIAL_ENCRYPT_WIRE_LEN);
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
    assert_fixed_storage_identity(&observers);
}

#[tokio::test]
async fn client_flow_allocates_once_then_admits_0_1_max_and_max_plus_one() {
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
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("request first-write");

    assert_eq!(write_plain(&mut flow, &[]).await, Ok(0));
    assert_eq!(write_plain(&mut flow, &[1]).await, Ok(1));
    assert_eq!(
        write_plain(&mut flow, &vec![2; INITIAL_ENCODE_PAYLOAD_LEN]).await,
        Ok(INITIAL_ENCODE_PAYLOAD_LEN)
    );
    assert_eq!(
        write_plain(&mut flow, &vec![3; INITIAL_ENCODE_PAYLOAD_LEN + 1]).await,
        Ok(INITIAL_ENCODE_PAYLOAD_LEN)
    );

    let buffers = observers.buffers.lock().expect("buffers");
    assert_eq!(buffers.len(), 2);
    assert_eq!(
        buffers.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![BufferRole::Encrypt, BufferRole::Decrypt]
    );
    assert_eq!(buffers[0].1, INITIAL_ENCRYPT_WIRE_LEN);
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
    assert_fixed_storage_identity(&observers);
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
    let mut client = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("client");
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
    assert_fixed_storage_identity(&client_observers);

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
    assert_fixed_storage_identity(&server_observers);
}

#[tokio::test]
async fn steady_frame_capacity_preserves_wire_and_reduces_records() {
    const CONTINUOUS_BYTES: usize = 262_144;

    assert!(matches!(
        INITIAL_ENCODE_PAYLOAD_LEN,
        16_384 | 32_768 | 65_535
    ));
    let clock = FakeClock::new(NOW, 0);
    let plaintext = (0..CONTINUOUS_BYTES)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    for (case, profile) in [
        MethodProfile::Blake3Aes128Gcm2022,
        MethodProfile::Blake3Aes256Gcm2022,
        MethodProfile::Blake3ChaCha20Poly13052022,
    ]
    .into_iter()
    .enumerate()
    {
        let keys = method_provider(profile);
        let request_salt = method_salt_from_u64(profile, 400 + case as u64);
        let client_random = ScriptedRandom::new(client_random_bytes(&request_salt));
        let (client_io, client_observation) = RecordingIo::new([]);
        let connector = RecordingConnector::succeeds(client_io);
        let client_observers = RecordingObservers::default();
        let outbound =
            ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &client_random)
                .with_observers(&client_observers, &client_observers);
        let mut client = outbound
            .connect_server()
            .await
            .expect("server connection")
            .write_request(&target())
            .await
            .expect("client");
        let mut offset = 0;
        while offset < plaintext.len() {
            let written = write_plain(&mut client, &plaintext[offset..])
                .await
                .expect("steady frame");
            assert_eq!(
                written,
                INITIAL_ENCODE_PAYLOAD_LEN.min(plaintext.len() - offset)
            );
            offset += written;
        }
        flush_plain(&mut client).await.expect("flush steady frames");
        assert_fixed_storage_identity(&client_observers);

        let writes = client_observation
            .lock()
            .expect("client writes")
            .writes
            .clone();
        let (request, frames) = writes.split_first().expect("request first-write");
        let frame_plaintext_lengths = plaintext
            .chunks(INITIAL_ENCODE_PAYLOAD_LEN)
            .map(<[u8]>::len)
            .collect::<Vec<_>>();
        assert_eq!(frames.len(), frame_plaintext_lengths.len());
        assert!(
            frames
                .iter()
                .zip(&frame_plaintext_lengths)
                .all(|(frame, payload_len)| frame.len() == 2 + TAG_LEN + payload_len + TAG_LEN)
        );

        let first_read_len = profile.initial_request_read_bytes();
        let reads = [
            request[..first_read_len].to_vec(),
            request[first_read_len..].to_vec(),
        ]
        .into_iter()
        .chain(frames.iter().cloned());
        let (server_io, server_observation) = RecordingIo::new(reads);
        let replay = TcpReplayStore::new(1024).expect("capacity");
        let server_random = ScriptedRandom::new([]);
        let server_observers = RecordingObservers::default();
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay)
            .with_observers(&server_observers, &server_observers);
        let mut server = inbound
            .accept_stream(server_io)
            .await
            .expect("server")
            .stream;
        let mut opened = Vec::with_capacity(CONTINUOUS_BYTES);
        let mut destination = vec![0_u8; INITIAL_ENCODE_PAYLOAD_LEN];
        for expected in &frame_plaintext_lengths {
            let read = read_plain(&mut server, &mut destination)
                .await
                .expect("open steady frame");
            assert_eq!(read, *expected);
            opened.extend_from_slice(&destination[..read]);
        }
        assert_eq!(opened, plaintext);
        assert_fixed_storage_identity(&server_observers);

        let mut expected_read_lengths = vec![
            profile.initial_request_read_bytes(),
            request.len() - profile.initial_request_read_bytes(),
        ];
        for payload_len in frame_plaintext_lengths {
            expected_read_lengths.extend([2 + TAG_LEN, payload_len + TAG_LEN]);
        }
        assert_eq!(
            server_observation
                .lock()
                .expect("server observation")
                .read_lengths,
            expected_read_lengths,
            "continuous frames expose only encrypted length and current payload ranges"
        );
    }
}

#[cfg(all(
    feature = "__frame-size-adaptive",
    not(feature = "__frame-size-16k"),
    not(feature = "__frame-size-65535")
))]
#[tokio::test]
async fn adaptive_flow_grows_after_512_kib_without_batching_the_triggering_read() {
    use ferrum2_shadowsocks::{ADAPTIVE_FRAME_GROW_BYTES, MAX_ENCODE_PAYLOAD_LEN};

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(601);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("request first-write");

    let initial_frames =
        usize::try_from(ADAPTIVE_FRAME_GROW_BYTES / INITIAL_ENCODE_PAYLOAD_LEN as u64)
            .expect("threshold frame count");
    assert_eq!(initial_frames, 16);
    for _ in 0..initial_frames {
        assert_eq!(
            write_plain(&mut flow, &vec![0x41; INITIAL_ENCODE_PAYLOAD_LEN]).await,
            Ok(INITIAL_ENCODE_PAYLOAD_LEN)
        );
    }
    flush_plain(&mut flow).await.expect("initial frame drain");
    assert_eq!(
        write_plain(&mut flow, &vec![0x42; MAX_ENCODE_PAYLOAD_LEN + 1]).await,
        Ok(MAX_ENCODE_PAYLOAD_LEN)
    );
    flush_plain(&mut flow).await.expect("grown frame drain");

    let writes = &observation.lock().expect("wire writes").writes;
    let frames = &writes[1..];
    assert_eq!(frames.len(), initial_frames + 1);
    assert!(
        frames[..initial_frames]
            .iter()
            .all(|wire| { wire.len() == 2 + TAG_LEN + INITIAL_ENCODE_PAYLOAD_LEN + TAG_LEN })
    );
    assert_eq!(
        frames.last().expect("grown wire").len(),
        2 + TAG_LEN + MAX_ENCODE_PAYLOAD_LEN + TAG_LEN
    );
}

#[test]
fn decoder_accepts_the_full_65535_byte_peer_payload_range() {
    let keys = provider();
    let salt = salt_from_u64(302);
    let mut sealer = keys.tcp_sealer(&salt).expect("default key");
    let mut opener = keys.tcp_opener(&salt).expect("default key");
    let mut length = BytesMut::from(&u16::MAX.to_be_bytes()[..]);
    let mut payload = BytesMut::from(&vec![0x33; u16::MAX as usize][..]);
    sealer.seal_in_place(&mut length).expect("length seal");
    sealer.seal_in_place(&mut payload).expect("payload seal");

    let opened = open_data_frame(&mut opener, &length, &payload).expect("maximum peer payload");

    assert_eq!(opened.len(), u16::MAX as usize);
    assert!(opened.iter().all(|byte| *byte == 0x33));
}
