use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};

use std::future::{Future, ready};
use std::sync::Arc;

use ferrum2_core::{ConnectError, Connector, LocalEndpoint, Outbound, TargetAddr};
use ferrum2_runtime::{DirectOutbound, RuntimeTcpStream, SocketInspector};
use tokio::net::{TcpListener, TcpStream};

struct ScriptedInspector {
    calls: AtomicUsize,
    result: io::Result<SocketAddr>,
}

impl ScriptedInspector {
    fn returning(result: io::Result<SocketAddr>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
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
