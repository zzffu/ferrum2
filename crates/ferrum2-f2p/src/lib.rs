//! Authenticated TLS 1.3 TCP proxy streams and bounded UDP tunnels.
use ferrum2_core::{AbortiveClose, ConnectError, ConnectErrorKind, LocalEndpoint, TargetAddr};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;
mod tls;
mod udp;
mod wire;
pub use tls::{ClientConfig, ServerConfig};
pub use udp::{ClientSession, ClientTunnel, Limits, UdpBackend, UdpSocket, serve_udp};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAGIC: &[u8; 4] = b"F2P\x01";
const TCP: u8 = 1;
const UDP: u8 = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Profile {
    #[default]
    Balanced,
    Realtime,
}
impl Profile {
    fn encode(self) -> u8 {
        match self {
            Self::Balanced => 0,
            Self::Realtime => 1,
        }
    }
    fn decode(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Balanced),
            1 => Ok(Self::Realtime),
            _ => Err(wire::invalid()),
        }
    }
}

pub struct ClientStream<S> {
    inner: tokio_rustls::client::TlsStream<S>,
    reply: Option<ReplyReader>,
    failed: bool,
}
struct ReplyReader {
    bytes: [u8; 21],
    filled: usize,
    needed: usize,
    deadline: Pin<Box<tokio::time::Sleep>>,
}
pub struct ServerStream<S> {
    inner: tokio_rustls::server::TlsStream<S>,
    ready: bool,
    reply_started: bool,
}
pub enum Accepted<S> {
    Tcp {
        stream: ServerStream<S>,
        target: TargetAddr,
        profile: Profile,
    },
    Udp {
        stream: ServerStream<S>,
        profile: Profile,
    },
}

macro_rules! stream_traits {
    ($name:ident) => {
        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for $name<S> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.get_mut().poll_relay_read(cx, buf)
            }
        }
        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for $name<S> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                if !this.relay_ready() {
                    return Poll::Ready(Err(wire::invalid()));
                }
                Pin::new(&mut this.inner)
                    .poll_write(cx, buf)
                    .map_err(tls::closed)
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if !this.relay_ready() {
                    return Poll::Ready(Err(wire::invalid()));
                }
                Pin::new(&mut this.inner)
                    .poll_flush(cx)
                    .map_err(tls::closed)
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if !this.relay_ready() {
                    return Poll::Ready(Err(wire::invalid()));
                }
                // Tokio-rustls flushes close_notify and shuts down only the write half.
                Pin::new(&mut this.inner)
                    .poll_shutdown(cx)
                    .map_err(tls::closed)
            }
        }
        impl<S: LocalEndpoint> LocalEndpoint for $name<S> {
            fn local_socket_addr(&self) -> SocketAddr {
                self.inner.get_ref().0.local_socket_addr()
            }
        }
        impl<S: AbortiveClose> AbortiveClose for $name<S> {
            type Error = S::Error;
            fn mark_abortive(&mut self) -> Result<(), Self::Error> {
                self.inner.get_mut().0.mark_abortive()
            }
        }
    };
}
impl<S> ClientStream<S> {
    fn relay_ready(&self) -> bool {
        !self.failed
    }
}
impl<S> ServerStream<S> {
    fn relay_ready(&self) -> bool {
        self.ready
    }
}
stream_traits!(ClientStream);
stream_traits!(ServerStream);

impl<S: AsyncRead + AsyncWrite + Unpin> ServerStream<S> {
    fn poll_relay_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.reply_started && !self.ready {
            return Poll::Ready(Err(wire::invalid()));
        }
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(tls::closed)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> ClientStream<S> {
    fn poll_relay_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(wire::invalid()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(reply) = &mut self.reply {
            loop {
                while reply.filled < reply.needed {
                    let mut part = ReadBuf::new(&mut reply.bytes[reply.filled..reply.needed]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut part) {
                        Poll::Pending => {
                            if reply.deadline.as_mut().poll(cx).is_ready() {
                                self.failed = true;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "F2P reply timed out",
                                )));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            self.failed = true;
                            return Poll::Ready(Err(tls::closed(error)));
                        }
                        Poll::Ready(Ok(())) if part.filled().is_empty() => {
                            self.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "F2P reply ended",
                            )));
                        }
                        Poll::Ready(Ok(())) => reply.filled += part.filled().len(),
                    }
                }
                if reply.needed == 1 {
                    if reply.bytes[0] != 0 {
                        self.failed = true;
                        return Poll::Ready(Err(remote_error(reply.bytes[0])));
                    }
                    reply.needed = 2;
                } else if reply.needed == 2 {
                    if !matches!(reply.bytes[1], 7 | 19) {
                        self.failed = true;
                        return Poll::Ready(Err(wire::invalid()));
                    }
                    reply.needed += usize::from(reply.bytes[1]);
                } else {
                    if let Err(error) = wire::decode_endpoint(&reply.bytes[2..reply.needed]) {
                        self.failed = true;
                        return Poll::Ready(Err(error));
                    }
                    break;
                }
            }
            self.reply = None;
        }
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(tls::closed)
    }
}
fn remote_error(code: u8) -> io::Error {
    let kind = match wire::decode_error(code) {
        Ok(kind) => kind,
        Err(error) => return error,
    };
    let io_kind = match kind {
        ConnectErrorKind::PolicyDenied => io::ErrorKind::PermissionDenied,
        ConnectErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        ConnectErrorKind::Timeout => io::ErrorKind::TimedOut,
        ConnectErrorKind::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
        ConnectErrorKind::HostUnreachable => io::ErrorKind::HostUnreachable,
        ConnectErrorKind::Other => io::ErrorKind::Other,
    };
    io::Error::new(io_kind, ConnectError::new(kind))
}

async fn deadline<T>(future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "F2P startup timed out"))?
        .map_err(tls::closed)
}

async fn startup<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    config: &ClientConfig,
    profile: Profile,
    target: Option<&TargetAddr>,
) -> io::Result<ClientStream<S>> {
    let mut stream = tokio_rustls::TlsConnector::from(config.tls.clone())
        .connect(config.name.clone(), io)
        .await
        .map_err(tls::closed)?;
    if stream.get_ref().1.alpn_protocol() != Some(tls::ALPN) {
        return Err(wire::invalid());
    }
    let mut header = Zeroizing::new(Vec::with_capacity(40 + wire::MAX_TARGET_LEN));
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[if target.is_some() { TCP } else { UDP }, profile.encode()]);
    header.extend_from_slice(&config.token[..]);
    if let Some(target) = target {
        let begin = header.len();
        header.extend_from_slice(&[0, 0]);
        wire::encode_target(target, &mut header);
        let len = (header.len() - begin - 2) as u16;
        header[begin..begin + 2].copy_from_slice(&len.to_be_bytes());
    }
    stream.write_all(&header).await?;
    stream.flush().await?;
    let status = stream.read_u8().await?;
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "F2P authentication failed",
        ));
    }
    Ok(ClientStream {
        inner: stream,
        reply: target.map(|_| ReplyReader {
            bytes: [0; 21],
            filled: 0,
            needed: 1,
            deadline: Box::pin(tokio::time::sleep(HANDSHAKE_TIMEOUT)),
        }),
        failed: false,
    })
}

pub async fn connect_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    config: &ClientConfig,
    profile: Profile,
    target: &TargetAddr,
) -> io::Result<ClientStream<S>> {
    deadline(startup(io, config, profile, Some(target))).await
}
pub async fn connect_udp<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    config: &ClientConfig,
    profile: Profile,
) -> io::Result<ClientStream<S>> {
    deadline(startup(io, config, profile, None)).await
}

pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    config: &ServerConfig,
) -> io::Result<Accepted<S>> {
    deadline(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config.tls.clone())
            .accept(io)
            .await
            .map_err(tls::closed)?;
        if stream.get_ref().1.alpn_protocol() != Some(tls::ALPN) {
            return Err(wire::invalid());
        }
        let mut header = Zeroizing::new([0u8; 38]);
        stream.read_exact(&mut header[..]).await?;
        if &header[..4] != MAGIC || !matches!(header[4], TCP | UDP) {
            return Err(wire::invalid());
        }
        let profile = Profile::decode(header[5])?;
        let presented: &[u8; 32] = header[6..].try_into().map_err(|_| wire::invalid())?;
        if !constant_time_eq::constant_time_eq_32(presented, &config.token) {
            stream.write_all(&[1]).await?;
            stream.flush().await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "F2P authentication failed",
            ));
        }
        let target = if header[4] == TCP {
            let len = usize::from(stream.read_u16().await?);
            if !(1..=wire::MAX_TARGET_LEN).contains(&len) {
                return Err(wire::invalid());
            }
            let mut bytes = [0u8; wire::MAX_TARGET_LEN];
            stream.read_exact(&mut bytes[..len]).await?;
            Some(wire::decode_target(&bytes[..len])?)
        } else {
            None
        };
        stream.write_all(&[0]).await?;
        stream.flush().await?;
        Ok(match target {
            Some(target) => Accepted::Tcp {
                stream: ServerStream {
                    inner: stream,
                    ready: false,
                    reply_started: false,
                },
                target,
                profile,
            },
            None => Accepted::Udp {
                stream: ServerStream {
                    inner: stream,
                    ready: true,
                    reply_started: true,
                },
                profile,
            },
        })
    })
    .await
}

pub async fn respond_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut ServerStream<S>,
    result: Result<SocketAddr, ConnectErrorKind>,
) -> io::Result<()> {
    // A cancelled or failed reply cannot be retried or expose a partially framed relay.
    if stream.reply_started {
        return Err(wire::invalid());
    }
    stream.reply_started = true;
    let mut reply = Vec::with_capacity(21);
    match result {
        Ok(endpoint) => {
            if endpoint.port() == 0 {
                return Err(wire::invalid());
            }
            reply.extend_from_slice(&[0, 0]);
            wire::encode_endpoint(endpoint, &mut reply);
            reply[1] = (reply.len() - 2) as u8;
        }
        Err(kind) => reply.push(wire::encode_error(kind)),
    }
    deadline(async {
        stream.inner.write_all(&reply).await?;
        stream.inner.flush().await
    })
    .await?;
    stream.ready = result.is_ok();
    Ok(())
}

#[cfg(test)]
mod reply_tests;
#[cfg(test)]
mod tests;
