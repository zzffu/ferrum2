use std::net::Ipv4Addr;
use std::time::Duration;

use ferrum2_core::AbortiveClose;
use ferrum2_runtime::RuntimeTcpStream;
use socket2::SockRef;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

async fn connected_stream() -> RuntimeTcpStream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let connect = TcpStream::connect(address);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    drop(accepted.expect("accept stream").0);
    RuntimeTcpStream::from_connected(client.expect("connect stream")).expect("IPv4 endpoint")
}

#[tokio::test]
async fn mark_abortive_alone_sets_zero_linger() {
    let mut stream = connected_stream().await;
    assert_eq!(SockRef::from(stream.as_ref()).linger().unwrap(), None);

    stream.mark_abortive().expect("set zero linger");

    assert_eq!(
        SockRef::from(stream.as_ref()).linger().unwrap(),
        Some(Duration::ZERO)
    );
}

#[tokio::test]
async fn ordinary_shutdown_does_not_set_linger() {
    let mut stream = connected_stream().await;

    stream.shutdown().await.expect("normal write shutdown");

    assert_eq!(SockRef::from(stream.as_ref()).linger().unwrap(), None);
}
