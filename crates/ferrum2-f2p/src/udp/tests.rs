use super::*;
use tokio::{io::DuplexStream, sync::mpsc};

mod receive;
mod server;

fn limits() -> Limits {
    Limits {
        max_sessions: 16,
        max_buffered_bytes: 1024 * 1024,
        idle_timeout: Duration::from_secs(5),
    }
}
fn target(port: u16) -> TargetAddr {
    TargetAddr::ip(SocketAddr::from(([127, 0, 0, 1], port))).unwrap()
}
fn frame(kind: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, 0];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
async fn raw_frame(io: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 8];
    io.read_exact(&mut header).await.unwrap();
    let mut body = vec![0; usize::from(u16::from_be_bytes([header[2], header[3]]))];
    io.read_exact(&mut body).await.unwrap();
    (
        header[0],
        u32::from_be_bytes(header[4..8].try_into().unwrap()),
        body,
    )
}
struct EchoBackend {
    alive: Arc<AtomicUsize>,
    first: Arc<Mutex<Vec<Vec<u8>>>>,
    slots: Arc<tokio::sync::Semaphore>,
}
struct EchoSocket {
    peer: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    ready: Notify,
    false_ready: AtomicBool,
    alive: Arc<AtomicUsize>,
    _slot: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for EchoSocket {
    fn drop(&mut self) {
        self.alive.fetch_sub(1, Ordering::AcqRel);
    }
}
impl UdpBackend for EchoBackend {
    type Socket = EchoSocket;
    type Reservation = tokio::sync::OwnedSemaphorePermit;
    fn reserve_session(&self) -> io::Result<Self::Reservation> {
        self.slots.clone().try_acquire_owned().map_err(|_| full())
    }
    async fn connect(
        &self,
        slot: Self::Reservation,
        target: &TargetAddr,
        first_payload: &[u8],
    ) -> io::Result<EchoSocket> {
        if target.port().get() == 9 {
            return std::future::pending().await;
        }
        if target.port().get() == 10 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test policy rejection",
            ));
        }
        lock(&self.first).push(first_payload.to_vec());
        let (tx, rx) = mpsc::channel(8);
        self.alive.fetch_add(1, Ordering::AcqRel);
        Ok(EchoSocket {
            peer: target.as_socket_addr().unwrap(),
            tx,
            rx: Mutex::new(rx),
            ready: Notify::new(),
            false_ready: AtomicBool::new(target.port().get() == 1003),
            alive: self.alive.clone(),
            _slot: slot,
        })
    }
}
impl UdpSocket for EchoSocket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        // This destination emits one false readiness notification, then stays idle.
        if self.peer.port() == 1003 {
            return Ok(());
        }
        let payload = if self.peer.port() == 1004 {
            vec![0; MAX_DATA + 1]
        } else {
            payload.to_vec()
        };
        self.tx.send(payload).await.map_err(|_| closed())?;
        self.ready.notify_one();
        Ok(())
    }
    async fn readable(&self) -> io::Result<()> {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.false_ready.load(Ordering::Acquire) || !lock(&self.rx).is_empty() {
                return Ok(());
            }
            notified.await;
        }
    }
    fn try_receive(&self, destination: &mut [u8]) -> io::Result<usize> {
        if self.false_ready.swap(false, Ordering::AcqRel) {
            return Err(full());
        }
        let payload = lock(&self.rx).try_recv().map_err(|error| match error {
            mpsc::error::TryRecvError::Empty => full(),
            mpsc::error::TryRecvError::Disconnected => closed(),
        })?;
        let count = destination.len().min(payload.len());
        destination[..count].copy_from_slice(&payload[..count]);
        Ok(count)
    }
}

#[tokio::test]
async fn stalled_open_does_not_block_other_sessions_empty_payloads_or_rejection() {
    for profile in [Profile::Balanced, Profile::Realtime] {
        let (client, server) = tokio::io::duplex(4096);
        let alive = Arc::new(AtomicUsize::new(0));
        let first = Arc::new(Mutex::new(Vec::new()));
        let backend = EchoBackend {
            alive: alive.clone(),
            first: first.clone(),
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
        };
        let mut jobs = JoinSet::new();
        jobs.spawn(serve_udp(server, profile, limits(), backend, ()));
        let tunnel = ClientTunnel::start(client, profile, limits(), ()).unwrap();
        let stalled = tunnel.open(target(9)).await.unwrap();
        stalled.send(b"stalled").await.unwrap();
        let mut rejected = tunnel.open(target(10)).await.unwrap();
        rejected.send(b"rejected").await.unwrap();
        let mut one = tunnel.open(target(1001)).await.unwrap();
        let mut two = tunnel.open(target(1002)).await.unwrap();
        one.send(&[]).await.unwrap();
        two.send(b"second").await.unwrap();
        let mut destination = [0; 64];
        let (count, peer) = timeout(Duration::from_secs(2), one.receive(&mut destination))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((count, peer.port()), (0, 1001));
        let (count, peer) = timeout(Duration::from_secs(2), two.receive(&mut destination))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (&destination[..count], peer.port()),
            (b"second".as_slice(), 1002)
        );
        assert!(
            timeout(Duration::from_secs(2), rejected.receive(&mut destination))
                .await
                .unwrap()
                .is_err()
        );
        assert!(!tunnel.is_closed());
        {
            let observed = lock(&first);
            assert!(observed.iter().any(Vec::is_empty));
            assert!(observed.iter().any(|p| p == b"second"));
        }
        drop(jobs);
        timeout(Duration::from_secs(2), async {
            while alive.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        timeout(Duration::from_secs(2), async {
            while !tunnel.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(two.send(b"not replayed").await.is_err());
    }
}

#[tokio::test]
async fn cancelled_receive_preserves_fragmented_parser_and_empty_datagram() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let tunnel = ClientTunnel::start(client, Profile::Balanced, limits(), ()).unwrap();
    let mut session = tunnel.open(target(1001)).await.unwrap();
    session.send(b"first").await.unwrap();
    assert_eq!(raw_frame(&mut peer).await.0, OPEN);
    assert_eq!(raw_frame(&mut peer).await.2, b"first");
    let mut reply = vec![0];
    wire::encode_endpoint(SocketAddr::from(([127, 0, 0, 1], 1001)), &mut reply);
    let encoded = frame(OPEN_RESULT, 1, &reply);
    peer.write_all(&encoded[..7]).await.unwrap();
    let mut destination = [0; 10];
    assert!(
        timeout(Duration::from_millis(5), session.receive(&mut destination))
            .await
            .is_err()
    );
    for byte in &encoded[7..] {
        peer.write_all(&[*byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
    peer.write_all(&frame(DATA, 1, &[])).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), session.receive(&mut destination))
            .await
            .unwrap()
            .unwrap()
            .0,
        0
    );
    // A malformed header invalidates every session, not just the addressed one.
    peer.write_all(&[DATA, 1, 0, 0, 0, 0, 0, 1]).await.unwrap();
    assert!(
        timeout(Duration::from_secs(1), session.receive(&mut destination))
            .await
            .unwrap()
            .is_err()
    );
    assert!(tunnel.is_closed());
}

#[tokio::test]
async fn partial_write_is_completed_before_the_next_frame() {
    let (client, mut peer) = tokio::io::duplex(1);
    let tunnel = ClientTunnel::start(client, Profile::Realtime, limits(), ()).unwrap();
    let session = tunnel.open(target(1001)).await.unwrap();
    session.send(b"committed").await.unwrap();
    let opened = raw_frame(&mut peer).await;
    assert_eq!(opened.0, OPEN);
    let mut byte = [0];
    peer.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte[0], DATA);
    // DATA is now committed, so queue expiration cannot discard its remaining bytes.
    tokio::time::sleep(Duration::from_millis(40)).await;
    let mut rest = [0; 7];
    peer.read_exact(&mut rest).await.unwrap();
    let mut body = [0; 9];
    peer.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"committed");
    session.send(&[]).await.unwrap();
    assert_eq!(raw_frame(&mut peer).await, (DATA, 1, vec![]));
    drop(tunnel);
    assert!(session.is_closed());
    let mut eof = [0; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut eof))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn bounded_empty_packets_and_session_ids_are_not_reused() {
    let (client, mut peer) = tokio::io::duplex(1);
    let mut small = limits();
    small.max_buffered_bytes = BASE_OVERHEAD + SESSION_OVERHEAD + 4096;
    let tunnel = ClientTunnel::start(client, Profile::Balanced, small, ()).unwrap();
    let session = tunnel.open(target(1001)).await.unwrap();
    let mut accepted = 0;
    while session.send(&[]).await.is_ok() {
        accepted += 1;
        assert!(accepted <= 16);
    }
    assert!(accepted > 0);
    assert!(tunnel.shared.budget.used.load(Ordering::Acquire) <= small.max_buffered_bytes);
    drop(session);
    let next = tunnel.open(target(1002)).await.unwrap();
    assert_eq!(next.session.id, 2);
    // Drain through CLOSE and any already committed old OPEN to the new OPEN.
    loop {
        let (kind, id, _) = raw_frame(&mut peer).await;
        if kind == OPEN && id == 2 {
            break;
        }
    }
    next.send(&[]).await.unwrap();
    assert_eq!(raw_frame(&mut peer).await, (DATA, 2, vec![]));
    let (stream, _) = tokio::io::duplex(1);
    small.max_buffered_bytes = BASE_OVERHEAD - 1;
    assert!(ClientTunnel::start(stream, Profile::Balanced, small, ()).is_err());
}

#[tokio::test]
async fn profiles_expire_uncommitted_data_and_writer_round_robins_ready_sessions() {
    for profile in [Profile::Balanced, Profile::Realtime] {
        let shared = Shared::new(profile, limits(), ()).unwrap();
        let (one, two) = {
            let mut state = lock(&shared.state);
            (
                shared.insert(&mut state, 1).unwrap(),
                shared.insert(&mut state, 2).unwrap(),
            )
        };
        let mut stale = shared.packet(Some(&one), DATA, 1, b"old").unwrap();
        stale.created = Instant::now() - Duration::from_millis(100);
        shared.enqueue(&one, stale, true).unwrap();
        shared
            .enqueue(
                &one,
                shared.packet(Some(&one), DATA, 1, b"one").unwrap(),
                true,
            )
            .unwrap();
        shared
            .enqueue(
                &two,
                shared.packet(Some(&two), DATA, 2, b"two").unwrap(),
                true,
            )
            .unwrap();
        let (writer, mut reader) = tokio::io::duplex(4096);
        let mut jobs = JoinSet::new();
        jobs.spawn(write_loop(writer, shared));
        let a = raw_frame(&mut reader).await;
        let b = raw_frame(&mut reader).await;
        assert_eq!((a.1, b.1), (1, 2));
        assert_eq!(b.2, b"two");
        if profile == Profile::Balanced {
            assert_eq!(a.2, b"old");
            assert_eq!(raw_frame(&mut reader).await.2, b"one");
        } else {
            assert_eq!(a.2, b"one");
        }
    }
}

#[tokio::test]
async fn idle_expiry_closes_pending_sessions() {
    let (client, _peer) = tokio::io::duplex(4096);
    let mut short = limits();
    short.idle_timeout = Duration::from_millis(10);
    let tunnel = ClientTunnel::start(client, Profile::Balanced, short, ()).unwrap();
    let mut session = tunnel.open(target(1001)).await.unwrap();
    let mut byte = [0];
    assert!(
        timeout(Duration::from_secs(1), session.receive(&mut byte))
            .await
            .unwrap()
            .is_err()
    );
    assert!(!tunnel.is_closed());
}

#[tokio::test]
async fn pending_opens_share_capacity_across_tunnels_and_release_on_close() {
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let alive = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(Mutex::new(Vec::new()));
    let mut jobs = JoinSet::new();
    let mut peers = Vec::new();
    for _ in 0..2 {
        let (peer, server) = tokio::io::duplex(4096);
        peers.push(peer);
        jobs.spawn(serve_udp(
            server,
            Profile::Balanced,
            limits(),
            EchoBackend {
                alive: alive.clone(),
                first: first.clone(),
                slots: slots.clone(),
            },
            (),
        ));
    }
    let mut address = Vec::new();
    wire::encode_target(&target(1001), &mut address);
    peers[0].write_all(&frame(OPEN, 1, &address)).await.unwrap();
    peers[0].write_all(&frame(PING, 0, &[])).await.unwrap();
    assert_eq!(raw_frame(&mut peers[0]).await, (PONG, 0, Vec::new()));
    // No first DATA exists yet, but this OPEN must already consume the shared slot.
    peers[1].write_all(&frame(OPEN, 1, &address)).await.unwrap();
    let refused = timeout(Duration::from_secs(1), raw_frame(&mut peers[1]))
        .await
        .unwrap();
    assert_eq!((refused.0, refused.1), (OPEN_RESULT, 1));
    assert_ne!(refused.2, [0]);
    peers[0].write_all(&frame(CLOSE, 1, &[])).await.unwrap();
    // The injected capacity owner observes actual release, not just a CLOSE queued on wire.
    drop(
        timeout(Duration::from_secs(1), slots.acquire())
            .await
            .unwrap()
            .unwrap(),
    );
    peers[1].write_all(&frame(OPEN, 2, &address)).await.unwrap();
    peers[1]
        .write_all(&frame(DATA, 2, b"new-session"))
        .await
        .unwrap();
    let accepted = raw_frame(&mut peers[1]).await;
    assert_eq!((accepted.0, accepted.1, accepted.2[0]), (OPEN_RESULT, 2, 0));
    assert_eq!(
        raw_frame(&mut peers[1]).await,
        (DATA, 2, b"new-session".to_vec())
    );
    drop(jobs);
}

#[tokio::test]
async fn cancelled_tunnel_retains_aggregate_reservation_until_socket_drop() {
    struct ReservationProbe {
        alive: Arc<AtomicUsize>,
        observed: Arc<AtomicUsize>,
    }
    impl Drop for ReservationProbe {
        fn drop(&mut self) {
            self.observed
                .store(self.alive.load(Ordering::Acquire), Ordering::Release);
        }
    }
    let alive = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(AtomicUsize::new(usize::MAX));
    let (client, server) = tokio::io::duplex(4096);
    let mut jobs = JoinSet::new();
    jobs.spawn(serve_udp(
        server,
        Profile::Balanced,
        limits(),
        EchoBackend {
            alive: alive.clone(),
            first: Arc::new(Mutex::new(Vec::new())),
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
        },
        ReservationProbe {
            alive: alive.clone(),
            observed: observed.clone(),
        },
    ));
    let tunnel = ClientTunnel::start(client, Profile::Balanced, limits(), ()).unwrap();
    let mut session = tunnel.open(target(1001)).await.unwrap();
    session.send(b"active").await.unwrap();
    let mut response = [0_u8; 6];
    assert_eq!(session.receive(&mut response).await.unwrap().0, 6);
    assert_eq!(&response, b"active");
    assert_eq!(alive.load(Ordering::Acquire), 1);
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    timeout(Duration::from_secs(1), async {
        while observed.load(Ordering::Acquire) == usize::MAX {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(observed.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn concurrent_shutdowns_join_the_driver_before_returning() {
    let (client, mut peer) = tokio::io::duplex(64);
    let tunnel = ClientTunnel::start(client, Profile::Balanced, limits(), ()).unwrap();
    let (first, second) = tokio::join!(tunnel.shutdown(), tunnel.shutdown());
    first.unwrap();
    second.unwrap();
    let mut destination = [0_u8; 1];
    let mut buffer = tokio::io::ReadBuf::new(&mut destination);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        std::pin::Pin::new(&mut peer).poll_read(&mut context, &mut buffer),
        Poll::Ready(Ok(()))
    ));
    assert!(
        buffer.filled().is_empty(),
        "the joined driver must close its stream"
    );
    tunnel.shutdown().await.unwrap();
}
