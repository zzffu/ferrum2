use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use hickory_proto::op::{Message, SerialMessage};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::tcp::TcpStream as HickoryTcpStream;
use hickory_resolver::net::xfer::DnsStreamHandle;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::{DnsProxy, ProxyIngress, ProxyTransport};

pub(super) fn encode_response(
    mut response: Message,
    transport: ProxyTransport,
    advertised: u16,
) -> Option<Vec<u8>> {
    let wire = response.to_vec().ok()?;
    let limit = usize::from(advertised).min(4096);
    if transport == ProxyTransport::Udp && wire.len() > limit {
        response = response.truncate();
        response.to_vec().ok()
    } else {
        Some(wire)
    }
}

pub(super) fn bind_tcp(address: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = match address.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

pub(super) async fn udp_loop(
    socket: UdpSocket,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut children = JoinSet::new();
    let mut request = [0_u8; 4096];
    let result = loop {
        tokio::select! {
            _ = cancelled(&mut cancel) => break Ok(()),
            completed = children.join_next(), if !children.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(_)) | None => {
                        break Err(io::Error::other("DNS UDP request task stopped"));
                    }
                }
            }
            received = socket.recv_from(&mut request), if children.len() < proxy.udp_concurrency => {
                let (length, peer) = match received {
                    Ok(received) => received,
                    Err(error) => break Err(error),
                };
                let request = request[..length].to_vec();
                let socket = Arc::clone(&socket);
                let proxy = Arc::clone(&proxy);
                children.spawn(async move {
                    if let Some(response) = proxy
                        .answer(
                            ProxyIngress::Listener(inbound),
                            ProxyTransport::Udp,
                            &request,
                        )
                        .await
                    {
                        let sent = socket.send_to(&response, peer).await?;
                        if sent != response.len() {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "short DNS datagram",
                            ));
                        }
                    }
                    Ok(())
                });
            }
        }
    };
    children.abort_all();
    while children.join_next().await.is_some() {}
    result
}

pub(super) async fn tcp_loop(
    listener: TcpListener,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut children = JoinSet::new();
    loop {
        let (stream, _) = tokio::select! {
            result = listener.accept() => result?,
            _ = children.join_next(), if !children.is_empty() => continue,
            _ = cancelled(&mut cancel) => break,
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let proxy = Arc::clone(&proxy);
        children.spawn(async move {
            let _permit = permit;
            tcp_connection(stream, inbound, proxy, idle_timeout).await;
        });
    }
    children.abort_all();
    while children.join_next().await.is_some() {}
    Ok(())
}

pub(super) async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    if *cancel.borrow() {
        return;
    }
    let _ = cancel.changed().await;
}

pub(super) async fn tcp_connection(
    stream: TcpStream,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    idle_timeout: Duration,
) {
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(_) => return,
    };
    let (mut stream, mut responses) =
        HickoryTcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);
    loop {
        let Ok(Some(Ok(request))) = tokio::time::timeout(idle_timeout, stream.next()).await else {
            return;
        };
        let Some(response) = proxy
            .answer(
                ProxyIngress::Listener(inbound),
                ProxyTransport::Tcp,
                request.bytes(),
            )
            .await
        else {
            return;
        };
        if responses.send(SerialMessage::new(response, peer)).is_err() {
            return;
        }
    }
}
