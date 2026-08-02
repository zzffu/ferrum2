#![forbid(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use ferrum2_core::{ConnectErrorKind, Inbound, Session, SessionReply, TargetAddr, TargetHostRef};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTHENTICATION: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_DOMAIN: u8 = 0x03;
const ADDRESS_TYPE_IPV6: u8 = 0x04;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const MAX_METHODS: usize = u8::MAX as usize;

/// Largest complete SOCKS5 UDP datagram accepted on the wire.
pub const MAX_SOCKS_UDP_DATAGRAM_BYTES: usize = 65_507;

/// The SOCKS5 no-authentication TCP `CONNECT` inbound.
#[derive(Clone, Copy, Debug, Default)]
pub struct Socks5Inbound;

impl Socks5Inbound {
    /// Constructs the stateless inbound.
    pub const fn new() -> Self {
        Self
    }

    /// Accepts one no-authentication SOCKS5 command, including `UDP ASSOCIATE`.
    ///
    /// The returned UDP command retains the control stream and its one-shot
    /// reply so composition can finish setup before committing success.
    pub async fn accept_command<IO>(&self, io: IO) -> Result<SocksCommand<IO>, SocksError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (io, command) = accept_command(io, true).await?;
        Ok(match command {
            ParsedCommand::Connect(target) => SocksCommand::Connect(connect_session(io, target)),
            ParsedCommand::UdpAssociate(source_port) => {
                let io = Arc::new(Mutex::new(io));
                SocksCommand::UdpAssociate(SocksUdpAssociate {
                    source_port,
                    control: SocksStream {
                        io: Arc::clone(&io),
                    },
                    reply: SocksReplyPending { io },
                })
            }
        })
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
    /// The request used an unsupported address family.
    #[error("SOCKS5 address type is not supported")]
    AddressTypeNotSupported,
    /// The request did not contain a valid non-zero target.
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

/// A validated SOCKS5 command with its retained transport ownership.
pub enum SocksCommand<IO> {
    /// The existing TCP `CONNECT` session.
    Connect(Session<SocksStream<IO>, SocksReplyPending<IO>>),
    /// A reply-pending UDP association request.
    UdpAssociate(SocksUdpAssociate<IO>),
}

/// A validated UDP association request awaiting socket setup and one reply.
pub struct SocksUdpAssociate<IO> {
    source_port: u16,
    /// The TCP stream whose lifetime owns the association.
    pub control: SocksStream<IO>,
    /// The one-shot request reply, retained until setup finishes.
    pub reply: SocksReplyPending<IO>,
}

impl<IO> SocksUdpAssociate<IO> {
    /// Returns the requested source port, or zero when the first valid datagram pins it.
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }
}

/// A validated borrowed SOCKS5 UDP datagram.
pub struct SocksUdpDatagram<'a> {
    host: TargetHostRef<'a>,
    port: NonZeroU16,
    payload: &'a [u8],
}

impl SocksUdpDatagram<'_> {
    /// Materializes the validated target after the caller reserves capacity.
    pub fn to_target_addr(&self) -> TargetAddr {
        match self.host {
            TargetHostRef::Ip(address) => TargetAddr::ip(SocketAddr::new(address, self.port.get())),
            TargetHostRef::Domain(host) => TargetAddr::domain(host, self.port.get()),
        }
        .expect("borrowed SOCKS5 target was already validated")
    }

    /// Returns the exact application payload borrowed from the received datagram.
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// A closed SOCKS5 UDP decode or encode failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SocksUdpError {
    /// The datagram violates the bounded SOCKS5 UDP header contract.
    #[error("invalid SOCKS5 UDP datagram")]
    Invalid,
    /// RFC 1928 fragmentation is intentionally unsupported.
    #[error("SOCKS5 UDP fragmentation is unsupported")]
    Fragmented,
    /// The complete datagram or supplied output exceeds the fixed wire bound.
    #[error("SOCKS5 UDP datagram exceeds bounds")]
    Bounds,
}

impl<IO> Inbound<IO> for Socks5Inbound
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Stream = SocksStream<IO>;
    type Reply = SocksReplyPending<IO>;
    type Error = SocksError;

    async fn accept(&self, io: IO) -> Result<Session<Self::Stream, Self::Reply>, Self::Error> {
        let (io, command) = accept_command(io, false).await?;
        match command {
            ParsedCommand::Connect(target) => Ok(connect_session(io, target)),
            ParsedCommand::UdpAssociate(_) => Err(SocksError::CommandNotSupported),
        }
    }
}

/// Decodes one complete SOCKS5 UDP datagram without allocating.
pub fn decode_udp_datagram(input: &[u8]) -> Result<SocksUdpDatagram<'_>, SocksUdpError> {
    if input.len() > MAX_SOCKS_UDP_DATAGRAM_BYTES {
        return Err(SocksUdpError::Bounds);
    }
    if input.len() < 4 || input[..2] != [0, 0] {
        return Err(SocksUdpError::Invalid);
    }
    if input[2] != 0 {
        return Err(SocksUdpError::Fragmented);
    }

    let (host, port_offset) = match input[3] {
        ADDRESS_TYPE_IPV4 => {
            let address = input.get(4..8).ok_or(SocksUdpError::Invalid)?;
            let address =
                Ipv4Addr::from(<[u8; 4]>::try_from(address).expect("checked IPv4 address region"));
            (TargetHostRef::Ip(IpAddr::V4(address)), 8)
        }
        ADDRESS_TYPE_IPV6 => {
            let address = input.get(4..20).ok_or(SocksUdpError::Invalid)?;
            let address =
                Ipv6Addr::from(<[u8; 16]>::try_from(address).expect("checked IPv6 address region"));
            (TargetHostRef::Ip(IpAddr::V6(address)), 20)
        }
        ADDRESS_TYPE_DOMAIN => {
            let length = usize::from(*input.get(4).ok_or(SocksUdpError::Invalid)?);
            if length == 0 {
                return Err(SocksUdpError::Invalid);
            }
            let end = 5_usize.checked_add(length).ok_or(SocksUdpError::Invalid)?;
            let host = std::str::from_utf8(input.get(5..end).ok_or(SocksUdpError::Invalid)?)
                .map_err(|_| SocksUdpError::Invalid)?;
            if !host.is_ascii() {
                return Err(SocksUdpError::Invalid);
            }
            (TargetHostRef::Domain(host), end)
        }
        _ => return Err(SocksUdpError::Invalid),
    };
    let port_end = port_offset.checked_add(2).ok_or(SocksUdpError::Invalid)?;
    let port = input
        .get(port_offset..port_end)
        .ok_or(SocksUdpError::Invalid)?;
    let port =
        NonZeroU16::new(u16::from_be_bytes([port[0], port[1]])).ok_or(SocksUdpError::Invalid)?;
    Ok(SocksUdpDatagram {
        host,
        port,
        payload: &input[port_end..],
    })
}

/// Encodes one complete SOCKS5 UDP datagram into caller-owned bounded storage.
pub fn encode_udp_datagram(
    target: &TargetAddr,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, SocksUdpError> {
    let header_len = match target.host() {
        TargetHostRef::Ip(IpAddr::V4(_)) => 10,
        TargetHostRef::Ip(IpAddr::V6(_)) => 22,
        TargetHostRef::Domain(host) => 7 + host.len(),
    };
    let complete_len = header_len
        .checked_add(payload.len())
        .ok_or(SocksUdpError::Bounds)?;
    if complete_len > MAX_SOCKS_UDP_DATAGRAM_BYTES || output.len() < complete_len {
        return Err(SocksUdpError::Bounds);
    }

    output[..3].fill(0);
    match target.host() {
        TargetHostRef::Ip(IpAddr::V4(address)) => {
            output[3] = ADDRESS_TYPE_IPV4;
            output[4..8].copy_from_slice(&address.octets());
            output[8..10].copy_from_slice(&target.port().get().to_be_bytes());
        }
        TargetHostRef::Ip(IpAddr::V6(address)) => {
            output[3] = ADDRESS_TYPE_IPV6;
            output[4..20].copy_from_slice(&address.octets());
            output[20..22].copy_from_slice(&target.port().get().to_be_bytes());
        }
        TargetHostRef::Domain(host) => {
            output[3] = ADDRESS_TYPE_DOMAIN;
            output[4] = u8::try_from(host.len()).expect("validated domain length");
            output[5..5 + host.len()].copy_from_slice(host.as_bytes());
            output[5 + host.len()..header_len].copy_from_slice(&target.port().get().to_be_bytes());
        }
    }
    output[header_len..complete_len].copy_from_slice(payload);
    Ok(complete_len)
}

impl<IO> SessionReply for SocksReplyPending<IO>
where
    IO: AsyncWrite + Unpin + Send,
{
    type Error = SocksError;

    async fn succeeded(self, bound: std::net::SocketAddrV4) -> Result<(), Self::Error> {
        self.succeeded_socket(SocketAddr::V4(bound)).await
    }

    async fn succeeded_socket(self, bound: SocketAddr) -> Result<(), Self::Error> {
        let mut reply = [0_u8; 22];
        reply[..3].copy_from_slice(&[SOCKS_VERSION, 0x00, 0x00]);
        let reply_len = match bound {
            SocketAddr::V4(bound) => {
                reply[3] = ADDRESS_TYPE_IPV4;
                reply[4..8].copy_from_slice(&bound.ip().octets());
                reply[8..10].copy_from_slice(&bound.port().to_be_bytes());
                10
            }
            SocketAddr::V6(bound) => {
                reply[3] = ADDRESS_TYPE_IPV6;
                reply[4..20].copy_from_slice(&bound.ip().octets());
                reply[20..22].copy_from_slice(&bound.port().to_be_bytes());
                22
            }
        };
        let mut stream = SocksStream { io: self.io };
        write_exact(&mut stream, &reply[..reply_len]).await
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

enum ParsedCommand {
    Connect(TargetAddr),
    UdpAssociate(u16),
}

async fn accept_command<IO>(
    mut io: IO,
    udp_enabled: bool,
) -> Result<(IO, ParsedCommand), SocksError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
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
    if request_header[1] != COMMAND_CONNECT
        && (request_header[1] != COMMAND_UDP_ASSOCIATE || !udp_enabled)
    {
        write_failure(&mut io, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(SocksError::CommandNotSupported);
    }

    let command = match request_header[1] {
        COMMAND_CONNECT => match read_target(&mut io, request_header[3]).await {
            Ok(target) => ParsedCommand::Connect(target),
            Err(error) => return reject_request(&mut io, error).await,
        },
        COMMAND_UDP_ASSOCIATE => match read_udp_source_port(&mut io, request_header[3]).await {
            Ok(source_port) => ParsedCommand::UdpAssociate(source_port),
            Err(error) => return reject_request(&mut io, error).await,
        },
        _ => unreachable!("unsupported command was rejected"),
    };
    Ok((io, command))
}

async fn reject_request<IO, T>(io: &mut IO, error: SocksError) -> Result<T, SocksError>
where
    IO: AsyncWrite + Unpin,
{
    match error {
        SocksError::AddressTypeNotSupported => {
            write_failure(io, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            Err(SocksError::AddressTypeNotSupported)
        }
        SocksError::InvalidTarget => {
            write_failure(io, REPLY_GENERAL_FAILURE).await?;
            Err(SocksError::InvalidTarget)
        }
        error => Err(error),
    }
}

fn connect_session<IO>(
    io: IO,
    target: TargetAddr,
) -> Session<SocksStream<IO>, SocksReplyPending<IO>> {
    let io = Arc::new(Mutex::new(io));
    Session {
        target,
        stream: SocksStream {
            io: Arc::clone(&io),
        },
        initial_payload: Bytes::new(),
        reply: SocksReplyPending { io },
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

async fn read_target<IO>(io: &mut IO, address_type: u8) -> Result<TargetAddr, SocksError>
where
    IO: AsyncRead + Unpin,
{
    match address_type {
        ADDRESS_TYPE_IPV4 => {
            let mut address_and_port = [0_u8; 6];
            read_exact(io, &mut address_and_port).await?;
            let address = Ipv4Addr::new(
                address_and_port[0],
                address_and_port[1],
                address_and_port[2],
                address_and_port[3],
            );
            let port = u16::from_be_bytes([address_and_port[4], address_and_port[5]]);
            TargetAddr::ip(SocketAddr::new(address.into(), port))
                .map_err(|_| SocksError::InvalidTarget)
        }
        ADDRESS_TYPE_IPV6 => {
            let mut address_and_port = [0_u8; 18];
            read_exact(io, &mut address_and_port).await?;
            let address = Ipv6Addr::from(
                <[u8; 16]>::try_from(&address_and_port[..16]).expect("fixed IPv6 address region"),
            );
            let port = u16::from_be_bytes([address_and_port[16], address_and_port[17]]);
            TargetAddr::ip(SocketAddr::new(address.into(), port))
                .map_err(|_| SocksError::InvalidTarget)
        }
        ADDRESS_TYPE_DOMAIN => {
            let mut length = [0_u8; 1];
            read_exact(io, &mut length).await?;
            let length = usize::from(length[0]);
            let mut host = [0_u8; u8::MAX as usize];
            read_exact(io, &mut host[..length]).await?;
            let mut port = [0_u8; 2];
            read_exact(io, &mut port).await?;
            let host =
                std::str::from_utf8(&host[..length]).map_err(|_| SocksError::InvalidTarget)?;
            TargetAddr::domain(host, u16::from_be_bytes(port))
                .map_err(|_| SocksError::InvalidTarget)
        }
        _ => Err(SocksError::AddressTypeNotSupported),
    }
}

async fn read_udp_source_port<IO>(io: &mut IO, address_type: u8) -> Result<u16, SocksError>
where
    IO: AsyncRead + Unpin,
{
    match address_type {
        ADDRESS_TYPE_IPV4 => {
            let mut address_and_port = [0_u8; 6];
            read_exact(io, &mut address_and_port).await?;
            Ok(u16::from_be_bytes([
                address_and_port[4],
                address_and_port[5],
            ]))
        }
        ADDRESS_TYPE_IPV6 => {
            let mut address_and_port = [0_u8; 18];
            read_exact(io, &mut address_and_port).await?;
            Ok(u16::from_be_bytes([
                address_and_port[16],
                address_and_port[17],
            ]))
        }
        ADDRESS_TYPE_DOMAIN => {
            let mut length = [0_u8; 1];
            read_exact(io, &mut length).await?;
            let length = usize::from(length[0]);
            let mut host = [0_u8; u8::MAX as usize];
            read_exact(io, &mut host[..length]).await?;
            let mut port = [0_u8; 2];
            read_exact(io, &mut port).await?;
            if length == 0 || !host[..length].is_ascii() {
                return Err(SocksError::InvalidTarget);
            }
            Ok(u16::from_be_bytes(port))
        }
        _ => Err(SocksError::AddressTypeNotSupported),
    }
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
