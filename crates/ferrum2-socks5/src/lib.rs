#![forbid(unsafe_code)]

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use ferrum2_core::{ConnectErrorKind, Inbound, Session, SessionReply, TargetAddr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTHENTICATION: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const ADDRESS_TYPE_IPV4: u8 = 0x01;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const MAX_METHODS: usize = u8::MAX as usize;

/// The M0 SOCKS5 no-authentication IPv4 `CONNECT` inbound.
#[derive(Clone, Copy, Debug, Default)]
pub struct Socks5Inbound;

impl Socks5Inbound {
    /// Constructs the stateless inbound.
    pub const fn new() -> Self {
        Self
    }
}

/// A closed SOCKS5 handshake or reply failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SocksError {
    /// The peer closed or violated the bounded SOCKS5 wire contract.
    #[error("malformed SOCKS5 input")]
    Malformed,
    /// The greeting offered no supported authentication method.
    #[error("no acceptable SOCKS5 authentication method")]
    NoAcceptableMethod,
    /// The request used a command outside the M0 `CONNECT` scope.
    #[error("SOCKS5 command is not supported")]
    CommandNotSupported,
    /// The request used an address family outside the M0 IPv4 scope.
    #[error("SOCKS5 address type is not supported")]
    AddressTypeNotSupported,
    /// The request did not contain a valid non-zero IPv4 target.
    #[error("invalid SOCKS5 target")]
    InvalidTarget,
    /// Transport I/O failed without retaining the source error.
    #[error("SOCKS5 transport I/O failed")]
    Io,
}

/// The application stream retained after the SOCKS5 request is accepted.
pub struct SocksStream<IO> {
    io: Arc<Mutex<IO>>,
}

/// The one-shot pending SOCKS5 request reply.
///
/// The core [`SessionReply`] methods consume this owner, preventing a second
/// success or failure reply.
pub struct SocksReplyPending<IO> {
    io: Arc<Mutex<IO>>,
}

impl<IO> Inbound<IO> for Socks5Inbound
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Stream = SocksStream<IO>;
    type Reply = SocksReplyPending<IO>;
    type Error = SocksError;

    async fn accept(&self, mut io: IO) -> Result<Session<Self::Stream, Self::Reply>, Self::Error> {
        let mut greeting_header = [0_u8; 2];
        read_exact(&mut io, &mut greeting_header).await?;
        if greeting_header[0] != SOCKS_VERSION || greeting_header[1] == 0 {
            return Err(SocksError::Malformed);
        }

        let method_count = usize::from(greeting_header[1]);
        let mut methods = [0_u8; MAX_METHODS];
        read_exact(&mut io, &mut methods[..method_count]).await?;
        if !methods[..method_count].contains(&NO_AUTHENTICATION) {
            write_exact(&mut io, &[SOCKS_VERSION, NO_ACCEPTABLE_METHODS]).await?;
            return Err(SocksError::NoAcceptableMethod);
        }
        write_exact(&mut io, &[SOCKS_VERSION, NO_AUTHENTICATION]).await?;

        let mut request_header = [0_u8; 4];
        read_exact(&mut io, &mut request_header).await?;
        if request_header[0] != SOCKS_VERSION || request_header[2] != 0 {
            return Err(SocksError::Malformed);
        }
        if request_header[1] != COMMAND_CONNECT {
            write_failure(&mut io, REPLY_COMMAND_NOT_SUPPORTED).await?;
            return Err(SocksError::CommandNotSupported);
        }
        if request_header[3] != ADDRESS_TYPE_IPV4 {
            write_failure(&mut io, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(SocksError::AddressTypeNotSupported);
        }

        let mut address_and_port = [0_u8; 6];
        read_exact(&mut io, &mut address_and_port).await?;
        let address = Ipv4Addr::new(
            address_and_port[0],
            address_and_port[1],
            address_and_port[2],
            address_and_port[3],
        );
        let port = u16::from_be_bytes([address_and_port[4], address_and_port[5]]);
        let target = match TargetAddr::ipv4(SocketAddrV4::new(address, port)) {
            Ok(target) => target,
            Err(_) => {
                write_failure(&mut io, REPLY_GENERAL_FAILURE).await?;
                return Err(SocksError::InvalidTarget);
            }
        };

        let io = Arc::new(Mutex::new(io));
        Ok(Session {
            target,
            stream: SocksStream {
                io: Arc::clone(&io),
            },
            initial_payload: Bytes::new(),
            reply: SocksReplyPending { io },
        })
    }
}

impl<IO> SessionReply for SocksReplyPending<IO>
where
    IO: AsyncWrite + Unpin + Send,
{
    type Error = SocksError;

    async fn succeeded(self, bound: SocketAddrV4) -> Result<(), Self::Error> {
        let address = bound.ip().octets();
        let port = bound.port().to_be_bytes();
        let reply = [
            SOCKS_VERSION,
            0x00,
            0x00,
            ADDRESS_TYPE_IPV4,
            address[0],
            address[1],
            address[2],
            address[3],
            port[0],
            port[1],
        ];
        let mut stream = SocksStream { io: self.io };
        write_exact(&mut stream, &reply).await
    }

    async fn failed(self, kind: ConnectErrorKind) -> Result<(), Self::Error> {
        let reply = match kind {
            ConnectErrorKind::NetworkUnreachable => REPLY_NETWORK_UNREACHABLE,
            ConnectErrorKind::HostUnreachable => REPLY_HOST_UNREACHABLE,
            ConnectErrorKind::ConnectionRefused => REPLY_CONNECTION_REFUSED,
            ConnectErrorKind::Timeout | ConnectErrorKind::Other => REPLY_GENERAL_FAILURE,
        };
        let mut stream = SocksStream { io: self.io };
        write_failure(&mut stream, reply).await
    }
}

impl<IO> AsyncRead for SocksStream<IO>
where
    IO: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.io.lock() {
            Ok(mut io) => Pin::new(&mut *io).poll_read(context, buffer),
            Err(_) => Poll::Ready(Err(poisoned_transport())),
        }
    }
}

impl<IO> AsyncWrite for SocksStream<IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.io.lock() {
            Ok(mut io) => Pin::new(&mut *io).poll_write(context, buffer),
            Err(_) => Poll::Ready(Err(poisoned_transport())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.io.lock() {
            Ok(mut io) => Pin::new(&mut *io).poll_flush(context),
            Err(_) => Poll::Ready(Err(poisoned_transport())),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.io.lock() {
            Ok(mut io) => Pin::new(&mut *io).poll_shutdown(context),
            Err(_) => Poll::Ready(Err(poisoned_transport())),
        }
    }
}

async fn read_exact<IO>(io: &mut IO, buffer: &mut [u8]) -> Result<(), SocksError>
where
    IO: AsyncRead + Unpin,
{
    io.read_exact(buffer)
        .await
        .map(|_| ())
        .map_err(|_| SocksError::Malformed)
}

async fn write_exact<IO>(io: &mut IO, buffer: &[u8]) -> Result<(), SocksError>
where
    IO: AsyncWrite + Unpin,
{
    io.write_all(buffer).await.map_err(|_| SocksError::Io)
}

async fn write_failure<IO>(io: &mut IO, reply: u8) -> Result<(), SocksError>
where
    IO: AsyncWrite + Unpin,
{
    write_exact(
        io,
        &[
            SOCKS_VERSION,
            reply,
            0x00,
            ADDRESS_TYPE_IPV4,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ],
    )
    .await
}

fn poisoned_transport() -> io::Error {
    io::Error::other("SOCKS5 transport unavailable")
}
