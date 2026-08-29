use super::*;

use bytes::BufMut;

#[test]
fn dns_connected_response_binding_is_exact_or_a_port_preserving_remote_resolution() {
    let numeric = TargetAddr::ip("192.0.2.53:53".parse().unwrap()).unwrap();
    assert!(dns_response_target_matches(&numeric, &numeric));
    assert!(!dns_response_target_matches(
        &numeric,
        &TargetAddr::ip("192.0.2.54:53".parse().unwrap()).unwrap()
    ));
    assert!(!dns_response_target_matches(
        &numeric,
        &TargetAddr::ip("192.0.2.53:5353".parse().unwrap()).unwrap()
    ));
    assert!(!dns_response_target_matches(
        &numeric,
        &TargetAddr::domain("dns.example.test", 53).unwrap()
    ));

    let deferred = TargetAddr::domain("dns.example.test", 53).unwrap();
    assert!(dns_response_target_matches(
        &deferred,
        &TargetAddr::domain("DNS.EXAMPLE.TEST", 53).unwrap()
    ));
    assert!(dns_response_target_matches(
        &deferred,
        &TargetAddr::ip("198.51.100.53:53".parse().unwrap()).unwrap()
    ));
    assert!(!dns_response_target_matches(
        &deferred,
        &TargetAddr::ip("198.51.100.53:5353".parse().unwrap()).unwrap()
    ));
    assert!(!dns_response_target_matches(
        &deferred,
        &TargetAddr::domain("other.example.test", 53).unwrap()
    ));
}

pub(in crate::run) struct DirectTestResolver {
    pub(in crate::run) candidates: Option<Vec<SocketAddr>>,
    pub(in crate::run) calls: AtomicUsize,
}

impl UdpResolver for DirectTestResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.candidates
            .clone()
            .ok_or_else(|| io::Error::other("injected resolver failure"))
    }
}

pub(in crate::run) struct DirectTestSocket {
    pub(in crate::run) attempts: Mutex<Vec<SocketAddr>>,
    pub(in crate::run) succeed_at: Option<usize>,
}

impl DirectUdpSocket for DirectTestSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        let mut attempts = self.attempts.lock().expect("direct send attempts");
        attempts.push(target);
        if self.succeed_at == Some(attempts.len()) {
            Ok(payload.len())
        } else {
            Err(io::Error::other("injected direct send failure"))
        }
    }

    async fn readable(&self) -> io::Result<()> {
        Ok(())
    }

    async fn recv_buf_from<B: BufMut + Send>(
        &self,
        _payload: &mut B,
    ) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::other("receive is unused"))
    }

    fn try_recv_buf_from<B: BufMut>(&self, _payload: &mut B) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::other("receive is unused"))
    }
}

pub(in crate::run) struct SequencedDirectTestResolver {
    pub(in crate::run) answers: Mutex<VecDeque<Result<Vec<SocketAddr>, io::ErrorKind>>>,
    pub(in crate::run) calls: AtomicUsize,
}

impl UdpResolver for SequencedDirectTestResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self
            .answers
            .lock()
            .expect("sequenced resolver answers")
            .pop_front()
            .ok_or_else(|| io::Error::other("injected resolver exhaustion"))?
        {
            Ok(candidates) => Ok(candidates),
            Err(kind) => Err(io::Error::from(kind)),
        }
    }
}

pub(in crate::run) struct SelectiveDirectTestSocket {
    pub(in crate::run) attempts: Mutex<Vec<SocketAddr>>,
    pub(in crate::run) successful: Mutex<HashSet<SocketAddr>>,
}

impl SelectiveDirectTestSocket {
    pub(in crate::run) fn set_successful(&self, candidates: impl IntoIterator<Item = SocketAddr>) {
        *self.successful.lock().expect("successful candidates") = candidates.into_iter().collect();
    }

    pub(in crate::run) fn take_attempts(&self) -> Vec<SocketAddr> {
        std::mem::take(&mut *self.attempts.lock().expect("selective attempts"))
    }
}

impl DirectUdpSocket for SelectiveDirectTestSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.attempts
            .lock()
            .expect("selective attempts")
            .push(target);
        if self
            .successful
            .lock()
            .expect("successful candidates")
            .contains(&target)
        {
            Ok(payload.len())
        } else {
            Err(io::Error::other("injected direct send failure"))
        }
    }

    async fn readable(&self) -> io::Result<()> {
        Ok(())
    }

    async fn recv_buf_from<B: BufMut + Send>(
        &self,
        _payload: &mut B,
    ) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::other("receive is unused"))
    }

    fn try_recv_buf_from<B: BufMut>(&self, _payload: &mut B) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::other("receive is unused"))
    }
}

struct ScriptedDirectUdpSocket {
    awaited: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    ready: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    awaited_calls: AtomicUsize,
    try_calls: AtomicUsize,
}

impl ScriptedDirectUdpSocket {
    fn receive<B: BufMut>(
        queue: &Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        payload: &mut B,
    ) -> io::Result<(usize, SocketAddr)> {
        let (packet, source) = queue
            .lock()
            .expect("scripted receive queue")
            .pop_front()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let length = packet.len();
        payload.put_slice(&packet);
        Ok((length, source))
    }
}

impl DirectUdpSocket for ScriptedDirectUdpSocket {
    async fn send_to(&self, payload: &[u8], _target: SocketAddr) -> io::Result<usize> {
        Ok(payload.len())
    }

    async fn readable(&self) -> io::Result<()> {
        Ok(())
    }

    async fn recv_buf_from<B: BufMut + Send>(
        &self,
        payload: &mut B,
    ) -> io::Result<(usize, SocketAddr)> {
        self.awaited_calls.fetch_add(1, Ordering::SeqCst);
        Self::receive(&self.awaited, payload)
    }

    fn try_recv_buf_from<B: BufMut>(&self, payload: &mut B) -> io::Result<(usize, SocketAddr)> {
        self.try_calls.fetch_add(1, Ordering::SeqCst);
        Self::receive(&self.ready, payload)
    }
}

#[test]
fn direct_response_policies_separate_tun_family_from_exact_outstanding_peer() {
    let expected: SocketAddr = "192.0.2.8:53".parse().unwrap();
    let alternate_port: SocketAddr = "192.0.2.8:5353".parse().unwrap();
    let ipv6: SocketAddr = "[2001:db8::8]:53".parse().unwrap();
    let peers = VecDeque::from([expected]);

    assert_eq!(
        DirectUdpResponsePolicy::OutstandingPeers.classify(&peers, expected),
        Some(DirectUdpResponseMatch::OutstandingPeer(0))
    );
    assert_eq!(
        DirectUdpResponsePolicy::OutstandingPeers.classify(&peers, alternate_port),
        None,
        "SOCKS and DNS remain bound to an exact outstanding endpoint"
    );
    assert_eq!(
        DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv4)
            .classify(&VecDeque::new(), alternate_port),
        Some(DirectUdpResponseMatch::TunSink),
        "TUN defers same-family source admission to its ADF/EIF sink"
    );
    assert_eq!(
        DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv4).classify(&peers, ipv6),
        None
    );
    assert_eq!(
        DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv6).classify(&peers, expected),
        None
    );
}

#[tokio::test]
async fn direct_response_readiness_drain_is_bounded_and_yields() {
    let invalid: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let expected: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let socket = ScriptedDirectUdpSocket {
        awaited: Mutex::new(VecDeque::from([
            (b"first-spoof".to_vec(), invalid),
            (b"accepted".to_vec(), expected),
        ])),
        ready: Mutex::new(
            (1..MAX_DIRECT_UDP_READINESS_DRAIN)
                .map(|_| (b"ready-spoof".to_vec(), invalid))
                .collect(),
        ),
        awaited_calls: AtomicUsize::new(0),
        try_calls: AtomicUsize::new(0),
    };
    let scheduler_ran = Arc::new(AtomicBool::new(false));
    let scheduler_probe = Arc::clone(&scheduler_ran);
    let probe = tokio::spawn(async move {
        scheduler_probe.store(true, Ordering::SeqCst);
    });
    let mut payload = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
    let peers = VecDeque::from([expected]);

    let (length, source, response_match) = receive_direct_response(
        &socket,
        &peers,
        DirectUdpResponsePolicy::OutstandingPeers,
        &mut payload,
    )
    .await
    .expect("bounded drain response");

    assert!(scheduler_ran.load(Ordering::SeqCst));
    probe.await.expect("scheduler probe");
    assert_eq!(socket.awaited_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        socket.try_calls.load(Ordering::SeqCst),
        MAX_DIRECT_UDP_READINESS_DRAIN - 1
    );
    assert_eq!((length, source), (8, expected));
    assert_eq!(response_match, DirectUdpResponseMatch::OutstandingPeer(0));
    assert_eq!(&payload[..], b"accepted");
}

#[tokio::test]
async fn direct_response_would_block_retains_receive_scratch_storage() {
    let socket = ScriptedDirectUdpSocket {
        awaited: Mutex::new(VecDeque::new()),
        ready: Mutex::new(VecDeque::new()),
        awaited_calls: AtomicUsize::new(0),
        try_calls: AtomicUsize::new(0),
    };
    let mut scratch = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
    scratch.extend_from_slice(b"previous packet");
    let identity = scratch.as_ptr();

    let error = receive_direct_response(
        &socket,
        &VecDeque::new(),
        DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv4),
        &mut scratch,
    )
    .await
    .expect_err("empty socket would block");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(scratch.as_ptr(), identity);
    assert_eq!(scratch.capacity(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    assert!(scratch.is_empty());
}
