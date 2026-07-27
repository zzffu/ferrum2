use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};

use std::future::{Future, pending, ready};
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::{
    ConnectError, ConnectErrorKind, Connector, LocalEndpoint, Outbound, TargetAddr,
};
use ferrum2_runtime::{
    DEFAULT_CONNECT_TIMEOUT, DirectOutbound, RuntimeTcpStream, SocketInspector,
    SystemSocketInspector, TcpConnector, TcpDialer,
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

    assert_eq!(stream.local_endpoint(), expected);
    assert_eq!(stream.local_endpoint(), expected);
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
async fn ipv6_lookup_returns_no_stream() {
    let stream = connected_stream().await;
    let ipv6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 49152, 0, 0);
    let inspector = ScriptedInspector::returning(Ok(SocketAddr::V6(ipv6)));

    let result = RuntimeTcpStream::from_connected_with_inspector(stream, &inspector);

    assert!(result.is_err());
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
async fn direct_outbound_invokes_connector_only_for_ipv4_targets() {
    let calls = Arc::new(AtomicUsize::new(0));
    let outbound = DirectOutbound::new(RecordingConnector {
        calls: Arc::clone(&calls),
    });
    let ipv4 = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("IPv4 target");
    let domain = TargetAddr::domain("example.test", 80).expect("bounded domain");

    assert!(outbound.open(&domain).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(outbound.open(&ipv4).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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

    assert_eq!(stream.local_endpoint(), peer);
}

struct PendingDialer {
    calls: Arc<AtomicUsize>,
}

impl TcpDialer for PendingDialer {
    fn connect(
        &self,
        _address: SocketAddrV4,
    ) -> impl Future<Output = io::Result<TcpStream>> + Send {
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
) -> (Result<SocketAddrV4, ConnectErrorKind>, usize) {
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
        .map(|stream| stream.local_endpoint())
        .map_err(|error| error.kind());
    (endpoint, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn tcp_connector_queries_once_and_returns_no_stream_for_invalid_endpoint_results() {
    let (lookup_failure, lookup_calls) =
        connect_with_scripted_inspector(Err(io::Error::other("scripted lookup failure"))).await;
    assert_eq!(lookup_failure, Err(ConnectErrorKind::Other));
    assert_eq!(lookup_calls, 1);

    let ipv6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 49152, 0, 0);
    let (ipv6_failure, ipv6_calls) =
        connect_with_scripted_inspector(Ok(SocketAddr::V6(ipv6))).await;
    assert_eq!(ipv6_failure, Err(ConnectErrorKind::Other));
    assert_eq!(ipv6_calls, 1);
}
