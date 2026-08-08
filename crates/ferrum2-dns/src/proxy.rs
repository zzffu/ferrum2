use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use hickory_proto::op::SerialMessage;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::tcp::TcpStream as HickoryTcpStream;
use hickory_resolver::net::xfer::DnsStreamHandle;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::TaggedResolver;

/// Network on which a client proxy question was received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyTransport {
    /// One DNS UDP datagram.
    Udp,
    /// One DNS message on a TCP connection.
    Tcp,
}

/// Collision-free source identity for one client proxy query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyIngress {
    /// A configured dedicated DNS listener.
    Listener(usize),
    /// An ordinary inbound serving a hijacked DNS query.
    Ordinary(usize),
}

type SelectServer = dyn Fn(ProxyIngress, ProxyTransport, &Name, u16) -> Option<usize> + Send + Sync;

/// Hickory-backed DNS proxy request seam.
pub struct DnsProxy {
    resolver: Arc<TaggedResolver>,
    select: Arc<SelectServer>,
}

/// Prepared paired UDP/TCP listeners for every configured DNS inbound.
pub struct DnsProxyListeners {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    proxy: Arc<DnsProxy>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
}

/// Paired sockets prepared before the resolver owner starts.
pub struct DnsProxySockets {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
}

impl DnsProxyListeners {
    /// Atomically binds one UDP and one bounded-backlog TCP listener per address.
    pub async fn bind(
        inbounds: Vec<SocketAddr>,
        backlog: u32,
        max_connections: NonZeroU16,
        idle_timeout: Duration,
        proxy: Arc<DnsProxy>,
    ) -> io::Result<Self> {
        Ok(
            DnsProxySockets::bind(inbounds, backlog, max_connections, idle_timeout)
                .await?
                .with_proxy(proxy),
        )
    }

    /// Runs the fixed listener set until shutdown or a required listener fails.
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> io::Result<()> {
        let mut listeners = JoinSet::new();
        let (cancel, cancel_rx) = watch::channel(false);
        for (inbound, socket) in self.udp.into_iter().enumerate() {
            let proxy = Arc::clone(&self.proxy);
            listeners.spawn(udp_loop(socket, inbound, proxy, cancel_rx.clone()));
        }
        for (inbound, listener) in self.tcp.into_iter().enumerate() {
            let proxy = Arc::clone(&self.proxy);
            let connections = Arc::clone(&self.connections);
            listeners.spawn(tcp_loop(
                listener,
                inbound,
                proxy,
                connections,
                self.idle_timeout,
                cancel_rx.clone(),
            ));
        }
        tokio::pin!(shutdown);
        let result = tokio::select! {
            biased;
            () = &mut shutdown => Ok(()),
            result = listeners.join_next() => match result {
                Some(Ok(result)) => result,
                Some(Err(_)) | None => Err(io::Error::other("DNS listener stopped")),
            },
        };
        let _ = cancel.send(true);
        while listeners.join_next().await.is_some() {}
        result
    }
}

impl DnsProxySockets {
    /// Binds all paired sockets without starting a resolver or service task.
    pub async fn bind(
        inbounds: Vec<SocketAddr>,
        backlog: u32,
        max_connections: NonZeroU16,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        let mut udp = Vec::with_capacity(inbounds.len());
        let mut tcp = Vec::with_capacity(inbounds.len());
        for address in inbounds {
            udp.push(UdpSocket::bind(address).await?);
            tcp.push(bind_tcp(address, backlog)?);
        }
        Ok(Self {
            udp,
            tcp,
            connections: Arc::new(Semaphore::new(usize::from(max_connections.get()))),
            idle_timeout,
        })
    }

    /// Completes the prepared root with its ready resolver-backed proxy.
    pub fn with_proxy(self, proxy: Arc<DnsProxy>) -> DnsProxyListeners {
        DnsProxyListeners {
            udp: self.udp,
            tcp: self.tcp,
            proxy,
            connections: self.connections,
            idle_timeout: self.idle_timeout,
        }
    }
}

impl DnsProxy {
    /// Binds one validated first-match selector to one tagged resolver graph.
    pub fn new(
        resolver: Arc<TaggedResolver>,
        select: impl Fn(ProxyIngress, ProxyTransport, &Name, u16) -> Option<usize>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            resolver,
            select: Arc::new(select),
        }
    }

    /// Parses, selects, resolves and encodes one DNS message through Hickory.
    ///
    /// `None` means the supplied bytes could not be parsed as a DNS message.
    pub async fn answer(
        &self,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        wire: &[u8],
    ) -> Option<Vec<u8>> {
        let request = Message::from_vec(wire).ok()?;
        let response = self.response(ingress, transport, &request).await;
        encode_response(response, transport, request.max_payload())
    }

    async fn response(
        &self,
        ingress: ProxyIngress,
        transport: ProxyTransport,
        request: &Message,
    ) -> Message {
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return error_response(request, ResponseCode::NotImp);
        }
        let [query] = request.queries.as_slice() else {
            return error_response(request, ResponseCode::FormErr);
        };
        if query.query_class() != DNSClass::IN {
            return error_response(request, ResponseCode::Refused);
        }
        let Some(server) = (self.select)(
            ingress,
            transport,
            query.name(),
            u16::from(query.query_type()),
        ) else {
            return error_response(request, ResponseCode::ServFail);
        };
        match self.resolver.query(server, request.clone()).await {
            Ok(mut response) => {
                response.metadata.id = request.metadata.id;
                response.queries.clear();
                response.add_query(query.clone());
                response
            }
            Err(_) => error_response(request, ResponseCode::ServFail),
        }
    }
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.add_queries(request.queries.iter().cloned());
    response
}

fn encode_response(
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

fn bind_tcp(address: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = match address.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

async fn udp_loop(
    socket: UdpSocket,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut request = [0_u8; 4096];
    loop {
        let (length, peer) = tokio::select! {
            result = socket.recv_from(&mut request) => result?,
            _ = cancelled(&mut cancel) => return Ok(()),
        };
        let response = tokio::select! {
            response = proxy.answer(ProxyIngress::Listener(inbound), ProxyTransport::Udp, &request[..length]) => response,
            _ = cancelled(&mut cancel) => return Ok(()),
        };
        if let Some(response) = response {
            let sent = socket.send_to(&response, peer).await?;
            if sent != response.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short DNS datagram",
                ));
            }
        }
    }
}

async fn tcp_loop(
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

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    if *cancel.borrow() {
        return;
    }
    let _ = cancel.changed().await;
}

async fn tcp_connection(
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
