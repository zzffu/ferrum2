use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::{DnsError, TaggedResolver};

/// Network on which a client proxy question was received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyTransport {
    /// One DNS UDP datagram.
    Udp,
    /// One DNS message on a TCP connection.
    Tcp,
}

type SelectServer = dyn Fn(usize, ProxyTransport, &Name) -> usize + Send + Sync;

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

impl DnsProxyListeners {
    /// Atomically binds one UDP and one bounded-backlog TCP listener per address.
    pub async fn bind(
        inbounds: Vec<SocketAddr>,
        backlog: u32,
        max_connections: NonZeroU16,
        idle_timeout: Duration,
        proxy: Arc<DnsProxy>,
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
            proxy,
            connections: Arc::new(Semaphore::new(usize::from(max_connections.get()))),
            idle_timeout,
        })
    }

    /// Runs the fixed listener set until shutdown or a required listener fails.
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> io::Result<()> {
        let mut listeners = JoinSet::new();
        for (inbound, socket) in self.udp.into_iter().enumerate() {
            let proxy = Arc::clone(&self.proxy);
            listeners.spawn(udp_loop(socket, inbound, proxy));
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
        listeners.abort_all();
        while listeners.join_next().await.is_some() {}
        result
    }
}

impl DnsProxy {
    /// Binds one validated first-match selector to one tagged resolver graph.
    pub fn new(
        resolver: Arc<TaggedResolver>,
        select: impl Fn(usize, ProxyTransport, &Name) -> usize + Send + Sync + 'static,
    ) -> Self {
        Self {
            resolver,
            select: Arc::new(select),
        }
    }

    /// Parses, selects, resolves and encodes one DNS message through Hickory.
    ///
    /// `None` means no client identity could safely be recovered.
    pub async fn answer(
        &self,
        inbound: usize,
        transport: ProxyTransport,
        wire: &[u8],
    ) -> Option<Vec<u8>> {
        let request = Message::from_vec(wire).ok()?;
        let response = self.response(inbound, transport, &request).await;
        encode_response(response, transport, request.max_payload())
    }

    async fn response(
        &self,
        inbound: usize,
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
        let server = (self.select)(inbound, transport, query.name());
        match self
            .resolver
            .lookup(server, query.name().clone(), query.query_type())
            .await
        {
            Ok(lookup) => {
                let mut response = lookup.message().clone();
                response.metadata.id = request.metadata.id;
                response.queries.clear();
                response.add_query(query.clone());
                response
            }
            Err(DnsError::NxDomain) => error_response(request, ResponseCode::NXDomain),
            Err(DnsError::NoData) => error_response(request, ResponseCode::NoError),
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

async fn udp_loop(socket: UdpSocket, inbound: usize, proxy: Arc<DnsProxy>) -> io::Result<()> {
    let mut request = [0_u8; 4096];
    loop {
        let (length, peer) = socket.recv_from(&mut request).await?;
        if let Some(response) = proxy
            .answer(inbound, ProxyTransport::Udp, &request[..length])
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
    }
}

async fn tcp_loop(
    listener: TcpListener,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut children = JoinSet::new();
    loop {
        while children.try_join_next().is_some() {}
        let (stream, _) = listener.accept().await?;
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
}

async fn tcp_connection(
    mut stream: TcpStream,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    idle_timeout: Duration,
) {
    loop {
        let Ok(Ok(length)) = tokio::time::timeout(idle_timeout, stream.read_u16()).await else {
            return;
        };
        if length == 0 {
            return;
        }
        let mut request = vec![0_u8; usize::from(length)];
        if !matches!(
            tokio::time::timeout(idle_timeout, stream.read_exact(&mut request)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let Some(response) = proxy.answer(inbound, ProxyTransport::Tcp, &request).await else {
            return;
        };
        let Ok(length) = u16::try_from(response.len()) else {
            return;
        };
        let write = async {
            stream.write_u16(length).await?;
            stream.write_all(&response).await?;
            stream.flush().await
        };
        if !matches!(tokio::time::timeout(idle_timeout, write).await, Ok(Ok(()))) {
            return;
        }
    }
}
