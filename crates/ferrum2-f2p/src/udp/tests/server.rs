use super::*;

struct DelayedBackend {
    connect_delay: Duration,
    send_delay: Duration,
    echo: EchoBackend,
}

impl DelayedBackend {
    fn new(connect_delay: Duration, send_delay: Duration) -> Self {
        Self {
            connect_delay,
            send_delay,
            echo: EchoBackend {
                alive: Arc::new(AtomicUsize::new(0)),
                first: Arc::new(Mutex::new(Vec::new())),
                slots: Arc::new(tokio::sync::Semaphore::new(8)),
            },
        }
    }
}

struct DelayedSocket {
    send_delay: Duration,
    echo: EchoSocket,
}

impl UdpBackend for DelayedBackend {
    type Socket = DelayedSocket;
    type Reservation = tokio::sync::OwnedSemaphorePermit;

    fn reserve_session(&self) -> io::Result<Self::Reservation> {
        self.echo.reserve_session()
    }

    async fn connect(
        &self,
        reservation: Self::Reservation,
        target: &TargetAddr,
        first_payload: &[u8],
    ) -> io::Result<Self::Socket> {
        tokio::time::sleep(self.connect_delay).await;
        Ok(DelayedSocket {
            send_delay: self.send_delay,
            echo: self
                .echo
                .connect(reservation, target, first_payload)
                .await?,
        })
    }
}

impl UdpSocket for DelayedSocket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.echo.peer_addr()
    }

    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        tokio::time::sleep(self.send_delay).await;
        self.echo.send(payload).await
    }

    async fn readable(&self) -> io::Result<()> {
        self.echo.readable().await
    }

    fn try_receive(&self, destination: &mut [u8]) -> io::Result<usize> {
        self.echo.try_receive(destination)
    }
}

#[tokio::test(start_paused = true)]
async fn opening_work_preserves_first_datagram_but_not_expired_queued_data() {
    let (client, server) = tokio::io::duplex(4096);
    let backend = DelayedBackend::new(Duration::from_millis(40), Duration::ZERO);
    let mut jobs = JoinSet::new();
    jobs.spawn(serve_udp(server, Profile::Realtime, limits(), backend, ()));
    let tunnel = ClientTunnel::start(client, Profile::Realtime, limits(), ()).unwrap();
    let mut session = tunnel.open(target(1001)).await.unwrap();
    session.send(b"first").await.unwrap();
    session.send(b"expires while opening").await.unwrap();

    let mut destination = [0; 64];
    let (length, peer) = timeout(Duration::from_secs(1), session.receive(&mut destination))
        .await
        .expect("admitted first datagram survives destination preparation")
        .unwrap();
    assert_eq!(
        (&destination[..length], peer),
        (b"first".as_slice(), target(1001).as_socket_addr().unwrap())
    );
    assert!(
        timeout(Duration::from_millis(1), session.receive(&mut destination))
            .await
            .is_err()
    );

    session.send(b"after opening").await.unwrap();
    let (length, peer) = timeout(Duration::from_secs(1), session.receive(&mut destination))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (&destination[..length], peer),
        (
            b"after opening".as_slice(),
            target(1001).as_socket_addr().unwrap()
        )
    );
    tunnel.shutdown().await.unwrap();
    jobs.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn destination_preparation_and_first_send_share_one_stall_deadline() {
    let (client, server) = tokio::io::duplex(4096);
    let backend = DelayedBackend::new(
        STALL - Duration::from_millis(100),
        Duration::from_millis(200),
    );
    let limits = Limits {
        idle_timeout: STALL * 3,
        ..limits()
    };
    let mut jobs = JoinSet::new();
    jobs.spawn(serve_udp(server, Profile::Realtime, limits, backend, ()));
    let tunnel = ClientTunnel::start(client, Profile::Realtime, limits, ()).unwrap();
    let mut session = tunnel.open(target(1001)).await.unwrap();
    session
        .send(b"cannot complete before the shared deadline")
        .await
        .unwrap();
    let mut destination = [0; 64];
    assert!(
        timeout(
            STALL + Duration::from_millis(50),
            session.receive(&mut destination)
        )
        .await
        .expect("destination stall closes the session before another full send timeout")
        .is_err()
    );
    assert!(!tunnel.is_closed());
    tunnel.shutdown().await.unwrap();
    jobs.shutdown().await;
}
