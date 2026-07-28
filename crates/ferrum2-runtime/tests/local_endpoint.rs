use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::future::{Future, pending, ready};
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::{
    ConnectError, ConnectErrorKind, Connector, LocalEndpoint, Outbound, TargetAddr,
};
use ferrum2_runtime::{
    DEFAULT_CONNECT_TIMEOUT, DirectOutbound, MAX_RESOLVED_CANDIDATES, RuntimeTcpStream,
    SocketInspector, SystemSocketInspector, TcpConnector, TcpDialer, TcpResolver,
};
use tokio::net::{TcpListener, TcpStream};

struct ScriptedInspector {
    calls: Arc<AtomicUsize>,
    result: io::Result<SocketAddr>,
}

impl ScriptedInspector {
    fn returning(result: io::Result<SocketAddr>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            result,
        }
    }
}

impl SocketInspector for ScriptedInspector {
    fn local_addr(&self, _stream: &TcpStream) -> io::Result<SocketAddr> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.result {
            Ok(address) => Ok(*address),
            Err(error) => Err(io::Error::new(error.kind(), "scripted lookup failure")),
        }
    }
}

async fn connected_stream() -> TcpStream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let connect = TcpStream::connect(address);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    drop(accepted.expect("accept stream").0);
    client.expect("connect stream")
}

#[tokio::test]
async fn stores_an_ipv4_endpoint_after_exactly_one_lookup() {
    let stream = connected_stream().await;
    let expected = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152);
    let inspector = ScriptedInspector::returning(Ok(SocketAddr::V4(expected)));

    let stream =
        RuntimeTcpStream::from_connected_with_inspector(stream, &inspector).expect("IPv4 endpoint");

    assert_eq!(stream.local_socket_addr(), SocketAddr::V4(expected));
    assert_eq!(stream.local_socket_addr(), SocketAddr::V4(expected));
    assert_eq!(inspector.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lookup_failure_returns_no_stream() {
    let stream = connected_stream().await;
    let inspector = ScriptedInspector::returning(Err(io::Error::other("scripted lookup failure")));

    let result = RuntimeTcpStream::from_connected_with_inspector(stream, &inspector);

    assert!(result.is_err());
    assert_eq!(inspector.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ipv6_lookup_is_stored_without_family_conversion() {
    let stream = connected_stream().await;
    let ipv6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 49152, 0, 0);
    let inspector = ScriptedInspector::returning(Ok(SocketAddr::V6(ipv6)));

    let result =
        RuntimeTcpStream::from_connected_with_inspector(stream, &inspector).expect("IPv6 endpoint");

    assert_eq!(result.local_socket_addr(), SocketAddr::V6(ipv6));
    assert_eq!(inspector.calls.load(Ordering::SeqCst), 1);
}

#[derive(Clone, Copy)]
struct StoredEndpoint(SocketAddrV4);

impl LocalEndpoint for StoredEndpoint {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.0
    }
}

struct RecordingConnector {
    calls: Arc<AtomicUsize>,
}

impl Connector for RecordingConnector {
    type Stream = StoredEndpoint;

    fn connect(
        &self,
        _target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ready(Ok(StoredEndpoint(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            49152,
        ))))
    }
}

#[tokio::test]
async fn direct_outbound_forwards_every_normalized_target_to_the_connector() {
    let calls = Arc::new(AtomicUsize::new(0));
    let outbound = DirectOutbound::new(RecordingConnector {
        calls: Arc::clone(&calls),
    });
    let ipv4 = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("IPv4 target");
    let domain = TargetAddr::domain("example.test", 80).expect("bounded domain");

    assert!(outbound.open(&domain).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(outbound.open(&ipv4).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn tcp_connector_returns_the_actual_ipv4_local_endpoint() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let address = match listener.local_addr().expect("listener address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("IPv4 bind returned IPv6"),
    };
    let target = TargetAddr::ipv4(address).expect("IPv4 target");
    let connector = TcpConnector::new(DEFAULT_CONNECT_TIMEOUT);

    let (opened, accepted) = tokio::join!(connector.connect(&target), listener.accept());
    let stream = match opened {
        Ok(stream) => stream,
        Err(error) => panic!("connect failed: {error}"),
    };
    let (accepted, _) = accepted.expect("accept connection");
    let peer = match accepted.peer_addr().expect("accepted peer address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("IPv4 peer returned IPv6"),
    };

    assert_eq!(stream.local_socket_addr(), SocketAddr::V4(peer));
}

struct PendingDialer {
    calls: Arc<AtomicUsize>,
}

impl TcpDialer for PendingDialer {
    fn connect(&self, _address: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        pending()
    }
}

#[tokio::test(start_paused = true)]
async fn tcp_connector_timeout_uses_the_injected_dialer_deadline() {
    let calls = Arc::new(AtomicUsize::new(0));
    let connector = TcpConnector::with_adapters(
        SystemSocketInspector,
        PendingDialer {
            calls: Arc::clone(&calls),
        },
        DEFAULT_CONNECT_TIMEOUT,
    );
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("IPv4 target");
    let connect = tokio::spawn(async move { connector.connect(&target).await });
    tokio::task::yield_now().await;

    assert_eq!(DEFAULT_CONNECT_TIMEOUT, Duration::from_secs(10));
    tokio::time::advance(DEFAULT_CONNECT_TIMEOUT).await;

    let error = match connect.await.expect("connector task") {
        Ok(_) => panic!("pending dialer unexpectedly connected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ConnectErrorKind::Timeout);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

async fn connect_with_scripted_inspector(
    result: io::Result<SocketAddr>,
) -> (Result<SocketAddr, ConnectErrorKind>, usize) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let address = match listener.local_addr().expect("listener address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("IPv4 bind returned IPv6"),
    };
    let target = TargetAddr::ipv4(address).expect("IPv4 target");
    let inspector = ScriptedInspector::returning(result);
    let calls = Arc::clone(&inspector.calls);
    let connector = TcpConnector::with_inspector(inspector, DEFAULT_CONNECT_TIMEOUT);

    let (opened, accepted) = tokio::join!(connector.connect(&target), listener.accept());
    drop(accepted.expect("accept connection").0);
    let endpoint = opened
        .map(|stream| stream.local_socket_addr())
        .map_err(|error| error.kind());
    (endpoint, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn tcp_connector_queries_once_and_returns_no_stream_for_lookup_failure() {
    let (lookup_failure, lookup_calls) =
        connect_with_scripted_inspector(Err(io::Error::other("scripted lookup failure"))).await;
    assert_eq!(lookup_failure, Err(ConnectErrorKind::Other));
    assert_eq!(lookup_calls, 1);
}

struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
    candidates: Vec<SocketAddr>,
    delay: Duration,
}

impl TcpResolver for ScriptedResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.candidates.clone())
    }
}

struct ScriptedDialer {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<SocketAddr>>>,
    failures: Mutex<VecDeque<io::ErrorKind>>,
    delay: Duration,
}

impl TcpDialer for ScriptedDialer {
    async fn connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("seen lock").push(address);
        tokio::time::sleep(self.delay).await;
        let kind = self
            .failures
            .lock()
            .expect("failure lock")
            .pop_front()
            .unwrap_or(io::ErrorKind::ConnectionRefused);
        Err(io::Error::new(kind, "scripted dial failure"))
    }
}

#[tokio::test(start_paused = true)]
async fn domain_resolution_and_ordered_candidates_share_one_absolute_deadline() {
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let dial_calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let candidates: Vec<_> = (1..=20)
        .map(|last| SocketAddr::from(([192, 0, 2, last], 443)))
        .collect();
    let connector = TcpConnector::with_resolution_adapters(
        SystemSocketInspector,
        ScriptedDialer {
            calls: Arc::clone(&dial_calls),
            seen: Arc::clone(&seen),
            failures: Mutex::new(VecDeque::new()),
            delay: Duration::from_secs(1),
        },
        ScriptedResolver {
            calls: Arc::clone(&resolver_calls),
            candidates: candidates.clone(),
            delay: Duration::from_secs(3),
        },
        DEFAULT_CONNECT_TIMEOUT,
    );
    let target = TargetAddr::domain("example.test", 443).expect("domain target");

    let error = match connector.connect(&target).await {
        Ok(_) => panic!("deadline must stop sequential attempts"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), ConnectErrorKind::Timeout);
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
    assert!(dial_calls.load(Ordering::SeqCst) < MAX_RESOLVED_CANDIDATES);
    assert_eq!(
        &*seen.lock().expect("seen lock"),
        &candidates[..dial_calls.load(Ordering::SeqCst)]
    );
}

#[tokio::test(start_paused = true)]
async fn domain_candidate_bound_and_last_concrete_failure_are_deterministic() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let candidates: Vec<_> = (1..=20)
        .map(|last| SocketAddr::from(([198, 51, 100, last], 80)))
        .collect();
    let mut failures = VecDeque::from(vec![
        io::ErrorKind::NetworkUnreachable;
        MAX_RESOLVED_CANDIDATES
    ]);
    *failures.back_mut().expect("last failure") = io::ErrorKind::ConnectionRefused;
    let connector = TcpConnector::with_resolution_adapters(
        SystemSocketInspector,
        ScriptedDialer {
            calls: Arc::clone(&calls),
            seen: Arc::clone(&seen),
            failures: Mutex::new(failures),
            delay: Duration::ZERO,
        },
        ScriptedResolver {
            calls: Arc::new(AtomicUsize::new(0)),
            candidates: candidates.clone(),
            delay: Duration::ZERO,
        },
        DEFAULT_CONNECT_TIMEOUT,
    );
    let target = TargetAddr::domain("example.test", 80).expect("domain target");

    let error = match connector.connect(&target).await {
        Ok(_) => panic!("all candidates must fail"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), ConnectErrorKind::ConnectionRefused);
    assert_eq!(calls.load(Ordering::SeqCst), MAX_RESOLVED_CANDIDATES);
    assert_eq!(
        &*seen.lock().expect("seen lock"),
        &candidates[..MAX_RESOLVED_CANDIDATES]
    );
}
