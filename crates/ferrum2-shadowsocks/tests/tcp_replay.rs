mod common;

use std::sync::Arc;

use ferrum2_shadowsocks::{
    DetectionReason, ShadowsocksError, ShadowsocksTcpInbound, TcpReplayStore,
};
use tokio::sync::Barrier;

use common::{
    FakeClock, NOW, RecordingIo, ScriptedRandom, provider, salt_from_u64, valid_request_wire,
};

#[tokio::test]
async fn timestamp_boundaries_are_inclusive() {
    for (index, (peer_timestamp, accepted)) in [
        (NOW - 31, false),
        (NOW - 30, true),
        (NOW, true),
        (NOW + 30, true),
        (NOW + 31, false),
    ]
    .into_iter()
    .enumerate()
    {
        let keys = provider();
        let clock = FakeClock::new(NOW, 0);
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let random = ScriptedRandom::new([]);
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let salt = salt_from_u64(index as u64);
        let wire = valid_request_wire(peer_timestamp, &salt);
        let (io, observation) = RecordingIo::request(&wire);
        let result = inbound.accept_stream(io).await;
        if accepted {
            assert!(result.is_ok(), "timestamp {peer_timestamp} should pass");
            assert_eq!(replay.entry_count().expect("snapshot"), 1);
            assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
        } else {
            assert_eq!(
                result.err(),
                Some(ShadowsocksError::Detection(DetectionReason::TimestampSkew))
            );
            assert_eq!(replay.entry_count().expect("snapshot"), 0);
            assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
        }
    }
}

#[tokio::test]
async fn exact_invalid_does_not_poison_then_duplicate_is_rejected() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let salt = salt_from_u64(100);
    let mut invalid_wire = valid_request_wire(NOW, &salt);
    invalid_wire[30] ^= 1;
    let (invalid_io, _) = RecordingIo::request(&invalid_wire);
    assert!(matches!(
        inbound.accept_stream(invalid_io).await,
        Err(ShadowsocksError::Detection(_))
    ));
    assert_eq!(replay.entry_count().expect("snapshot"), 0);

    let wire = valid_request_wire(NOW, &salt);
    let (first_io, _) = RecordingIo::request(&wire);
    assert!(inbound.accept_stream(first_io).await.is_ok());
    let (duplicate_io, observation) = RecordingIo::request(&wire);
    assert!(matches!(
        inbound.accept_stream(duplicate_io).await,
        Err(ShadowsocksError::Detection(DetectionReason::Replay))
    ));
    assert_eq!(replay.entry_count().expect("snapshot"), 1);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_64_way_duplicate_has_exactly_one_success() {
    for round in 0..20_u64 {
        let keys = Arc::new(provider());
        let clock = Arc::new(FakeClock::new(NOW, 0));
        let replay = Arc::new(TcpReplayStore::new(1024).expect("approved capacity"));
        let random = Arc::new(ScriptedRandom::new([]));
        let salt = salt_from_u64(1_000 + round);
        let wire = Arc::new(valid_request_wire(NOW, &salt));
        let barrier = Arc::new(Barrier::new(64));
        let mut tasks = Vec::with_capacity(64);
        for _ in 0..64 {
            let keys = Arc::clone(&keys);
            let clock = Arc::clone(&clock);
            let replay = Arc::clone(&replay);
            let random = Arc::clone(&random);
            let wire = Arc::clone(&wire);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let (io, _) = RecordingIo::request(&wire);
                barrier.wait().await;
                let inbound = ShadowsocksTcpInbound::new(
                    keys.as_ref(),
                    clock.as_ref(),
                    random.as_ref(),
                    replay.as_ref(),
                );
                inbound.accept_stream(io).await.map(|_| ())
            }));
        }
        let mut accepted = 0;
        let mut replayed = 0;
        for task in tasks {
            match task.await.expect("task completed") {
                Ok(_) => accepted += 1,
                Err(ShadowsocksError::Detection(DetectionReason::Replay)) => replayed += 1,
                Err(other) => panic!("unexpected closed result: {other:?}"),
            }
        }
        assert_eq!((accepted, replayed), (1, 63), "round {round}");
    }
}

#[tokio::test]
async fn retention_uses_monotonic_59999_and_60000_boundaries_despite_wall_rollback() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let salt = salt_from_u64(200);
    let wire = valid_request_wire(NOW, &salt);
    let (first_io, _) = RecordingIo::request(&wire);
    assert!(inbound.accept_stream(first_io).await.is_ok());

    clock.set_wall(NOW - 10);
    clock.set_monotonic_millis(59_999);
    let (still_live_io, _) = RecordingIo::request(&wire);
    assert!(matches!(
        inbound.accept_stream(still_live_io).await,
        Err(ShadowsocksError::Detection(DetectionReason::Replay))
    ));

    clock.set_monotonic_millis(60_000);
    let (expired_io, _) = RecordingIo::request(&wire);
    assert!(inbound.accept_stream(expired_io).await.is_ok());
    assert_eq!(replay.entry_count().expect("snapshot"), 1);
}

#[tokio::test]
async fn capacity_full_fails_closed_without_live_eviction() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved minimum capacity");
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    for value in 0..1024_u64 {
        let wire = valid_request_wire(NOW, &salt_from_u64(value));
        let (io, _) = RecordingIo::request(&wire);
        assert!(inbound.accept_stream(io).await.is_ok(), "entry {value}");
    }
    assert_eq!(replay.entry_count().expect("snapshot"), 1024);

    let new_wire = valid_request_wire(NOW, &salt_from_u64(2_000));
    let (new_io, _) = RecordingIo::request(&new_wire);
    assert!(matches!(
        inbound.accept_stream(new_io).await,
        Err(ShadowsocksError::Detection(DetectionReason::ReplayCapacity))
    ));

    let old_wire = valid_request_wire(NOW, &salt_from_u64(0));
    let (old_io, _) = RecordingIo::request(&old_wire);
    assert!(matches!(
        inbound.accept_stream(old_io).await,
        Err(ShadowsocksError::Detection(DetectionReason::Replay))
    ));
    assert_eq!(replay.entry_count().expect("snapshot"), 1024);
}
