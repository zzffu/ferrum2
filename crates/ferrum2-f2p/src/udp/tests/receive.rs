use super::super::receive::Scratch;
use super::*;

#[tokio::test]
async fn one_mib_retains_forty_live_responders_after_false_readiness() {
    for profile in [Profile::Balanced, Profile::Realtime] {
        let settings = Limits {
            max_sessions: 64,
            ..limits()
        };
        let (client, server) = tokio::io::duplex(128 * 1024);
        let alive = Arc::new(AtomicUsize::new(0));
        let slots = Arc::new(tokio::sync::Semaphore::new(64));
        let mut jobs = JoinSet::new();
        jobs.spawn(serve_udp(
            server,
            profile,
            settings,
            EchoBackend {
                alive: alive.clone(),
                first: Arc::new(Mutex::new(Vec::new())),
                slots: slots.clone(),
            },
            (),
        ));
        let tunnel = ClientTunnel::start(client, profile, settings, ()).unwrap();
        let idle = tunnel.open(target(1003)).await.unwrap();
        idle.send(b"false-ready").await.unwrap();
        let mut sessions = Vec::new();
        let mut response = [0; 2];
        for port in 2000_u16..2040 {
            let mut session = tunnel.open(target(port)).await.unwrap();
            let payload = port.to_be_bytes();
            session.send(&payload).await.unwrap();
            let (length, peer) = timeout(Duration::from_secs(1), session.receive(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!((length, peer.port(), response), (2, port, payload));
            sessions.push(session);
        }
        assert_eq!(alive.load(Ordering::Acquire), 41);
        // Recheck the original sessions: admission must not have evicted them.
        for (index, session) in sessions.iter_mut().enumerate() {
            let payload = (index as u16).to_be_bytes();
            session.send(&payload).await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(1), session.receive(&mut response))
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
                2
            );
            assert_eq!(response, payload);
        }
        // Cancellation of an idle false-ready worker must release its slot too.
        tunnel.shutdown().await.unwrap();
        while jobs.join_next().await.is_some() {}
        assert_eq!(alive.load(Ordering::Acquire), 0);
        assert_eq!(slots.available_permits(), 64);
    }
}

#[tokio::test]
async fn receive_preserves_maximum_and_empty_but_rejects_oversize() {
    for profile in [Profile::Balanced, Profile::Realtime] {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let mut jobs = JoinSet::new();
        jobs.spawn(serve_udp(
            server,
            profile,
            limits(),
            EchoBackend {
                alive: Arc::new(AtomicUsize::new(0)),
                first: Arc::new(Mutex::new(Vec::new())),
                slots: Arc::new(tokio::sync::Semaphore::new(8)),
            },
            (),
        ));
        let tunnel = ClientTunnel::start(client, profile, limits(), ()).unwrap();
        let mut session = tunnel.open(target(1001)).await.unwrap();
        let payload: Vec<u8> = (0..MAX_DATA).map(|index| (index % 251) as u8).collect();
        let mut response = vec![0; MAX_DATA + 1];
        session.send(&payload).await.unwrap();
        let (length, _) = timeout(Duration::from_secs(1), session.receive(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(length, MAX_DATA);
        assert_eq!(&response[..length], payload);
        session.send(&[]).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), session.receive(&mut response))
                .await
                .unwrap()
                .unwrap()
                .0,
            0
        );
        let mut oversized = tunnel.open(target(1004)).await.unwrap();
        oversized.send(b"oversize").await.unwrap();
        assert!(
            timeout(Duration::from_secs(1), oversized.receive(&mut response))
                .await
                .unwrap()
                .is_err()
        );
        // Rejection is session-local, not a tunnel failure.
        session.send(b"still-live").await.unwrap();
        let (length, _) = timeout(Duration::from_secs(1), session.receive(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..length], b"still-live");
        tunnel.shutdown().await.unwrap();
        while jobs.join_next().await.is_some() {}
    }
}

#[test]
fn scratch_retains_partition_until_allocation_and_charge_are_destroyed() {
    struct Resources {
        budget: Arc<Mutex<Option<Arc<Budget>>>>,
        released: Arc<AtomicBool>,
    }
    impl Drop for Resources {
        fn drop(&mut self) {
            assert_eq!(
                lock(&self.budget)
                    .as_ref()
                    .unwrap()
                    .used
                    .load(Ordering::Acquire),
                0
            );
            self.released.store(true, Ordering::Release);
        }
    }
    let budget = Arc::new(Mutex::new(None));
    let released = Arc::new(AtomicBool::new(false));
    let shared = Shared::new(
        Profile::Balanced,
        limits(),
        Resources {
            budget: budget.clone(),
            released: released.clone(),
        },
    )
    .unwrap();
    *lock(&budget) = Some(shared.budget.clone());
    let scratch = Arc::new(Scratch::new(shared.clone()).unwrap());
    shared.stop();
    drop(shared);
    assert!(!released.load(Ordering::Acquire));
    assert_eq!(
        lock(&budget).as_ref().unwrap().used.load(Ordering::Acquire),
        BASE_OVERHEAD + MAX_DATA + 1 + PACKET_OVERHEAD
    );
    let worker = scratch.clone();
    drop(scratch);
    assert!(!released.load(Ordering::Acquire));
    drop(worker);
    assert!(released.load(Ordering::Acquire));
}

#[test]
fn scratch_admission_failure_releases_its_partition() {
    let shared = Shared::new(
        Profile::Balanced,
        Limits {
            max_buffered_bytes: BASE_OVERHEAD + MAX_DATA + PACKET_OVERHEAD,
            ..limits()
        },
        (),
    )
    .unwrap();
    assert!(
        matches!(Scratch::new(shared.clone()), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert_eq!(shared.budget.used.load(Ordering::Acquire), BASE_OVERHEAD);
}
