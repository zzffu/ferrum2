#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;

use bytes::Bytes;

const MAX_DOMAIN_NAME_BYTES: usize = 255;

/// A domain name whose storage is bounded before allocation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Validates and stores a domain name.
    pub fn new(value: &str) -> Result<Self, DomainNameError> {
        match value.len() {
            0 => Err(DomainNameError::Empty),
            1..=MAX_DOMAIN_NAME_BYTES if value.is_ascii() => Ok(Self(value.into())),
            1..=MAX_DOMAIN_NAME_BYTES => Err(DomainNameError::NonAscii),
            _ => Err(DomainNameError::TooLong),
        }
    }

    /// Returns the validated domain name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DomainName([redacted])")
    }
}

/// Failure to construct a bounded domain name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainNameError {
    /// An empty domain is not a target.
    Empty,
    /// The encoded domain exceeds the protocol's 255-byte bound.
    TooLong,
    /// M1 preserves only ASCII domain bytes and does not perform IDNA.
    NonAscii,
}

impl fmt::Display for DomainNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("domain name is empty"),
            Self::TooLong => formatter.write_str("domain name exceeds 255 bytes"),
            Self::NonAscii => formatter.write_str("domain name is not ASCII"),
        }
    }
}

impl Error for DomainNameError {}

#[derive(Clone, Eq, Hash, PartialEq)]
enum TargetHost {
    Ip(IpAddr),
    Domain(DomainName),
}

/// A validated IP or bounded-domain target.
///
/// The type intentionally has no `Display` implementation so target values are
/// not accidentally included in operator-facing diagnostics.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TargetAddr {
    host: TargetHost,
    port: NonZeroU16,
}

impl TargetAddr {
    /// Constructs an IP target and rejects port zero.
    pub fn ip(address: SocketAddr) -> Result<Self, TargetAddrError> {
        let port = NonZeroU16::new(address.port()).ok_or(TargetAddrError::PortZero)?;
        Ok(Self {
            host: TargetHost::Ip(address.ip()),
            port,
        })
    }

    /// Constructs an IPv4 target and rejects port zero.
    pub fn ipv4(address: SocketAddrV4) -> Result<Self, TargetAddrError> {
        Self::ip(SocketAddr::V4(address))
    }

    /// Constructs a bounded-domain target and rejects port zero.
    pub fn domain(host: &str, port: u16) -> Result<Self, TargetAddrError> {
        let host = DomainName::new(host).map_err(TargetAddrError::Domain)?;
        let port = NonZeroU16::new(port).ok_or(TargetAddrError::PortZero)?;
        Ok(Self {
            host: TargetHost::Domain(host),
            port,
        })
    }

    /// Returns a non-secret view of the target host for protocol adapters.
    pub fn host(&self) -> TargetHostRef<'_> {
        match &self.host {
            TargetHost::Ip(address) => TargetHostRef::Ip(*address),
            TargetHost::Domain(domain) => TargetHostRef::Domain(domain.as_str()),
        }
    }

    /// Returns the validated non-zero target port.
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// Returns a socket address when the target is already an IP literal.
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self.host {
            TargetHost::Ip(address) => Some(SocketAddr::new(address, self.port.get())),
            TargetHost::Domain(_) => None,
        }
    }
}

impl fmt::Debug for TargetAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetAddr([redacted])")
    }
}

/// A borrowed view of a target host.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TargetHostRef<'a> {
    /// An IP-literal target.
    Ip(IpAddr),
    /// A bounded domain target.
    Domain(&'a str),
}

impl fmt::Debug for TargetHostRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetHostRef([redacted])")
    }
}

/// Failure to construct a normalized target address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetAddrError {
    /// Domain validation failed.
    Domain(DomainNameError),
    /// Port zero is never a connect target.
    PortZero,
}

impl fmt::Display for TargetAddrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => error.fmt(formatter),
            Self::PortZero => formatter.write_str("target port is zero"),
        }
    }
}

impl Error for TargetAddrError {}

/// A normalized accepted session passed from an inbound to an outbound.
pub struct Session<S, R> {
    /// The validated destination.
    pub target: TargetAddr,
    /// The application-facing stream.
    pub stream: S,
    /// Bytes accepted with the session before relay starts.
    pub initial_payload: Bytes,
    /// The one-shot reply capability owned by this session.
    pub reply: R,
}

/// Application-facing traffic that produces normalized sessions.
pub trait Inbound<IO>: Send + Sync {
    /// Stream type yielded to the runtime.
    type Stream;
    /// One-shot session response.
    type Reply: SessionReply;
    /// Closed inbound error.
    type Error;

    /// Accepts one application-facing flow.
    fn accept(
        &self,
        io: IO,
    ) -> impl Future<Output = Result<Session<Self::Stream, Self::Reply>, Self::Error>> + Send;
}

/// A destination-facing session opener.
pub trait Outbound: Send + Sync {
    /// Opened stream with an already stored local socket endpoint.
    type Stream: LocalEndpoint;
    /// Closed outbound error.
    type Error;

    /// Opens a stream for a validated target.
    fn open(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;
}

/// Establishes a protocol-neutral stream for a validated target.
pub trait Connector: Send + Sync {
    /// Connected stream with an already stored local socket endpoint.
    type Stream: LocalEndpoint;

    /// Connects or returns a closed connect error.
    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send;
}

/// Access to a local endpoint captured before a stream is returned.
pub trait LocalEndpoint {
    /// Returns the stored endpoint infallibly without a socket query.
    fn local_endpoint(&self) -> SocketAddr;
}

/// A one-shot response to an accepted application session.
pub trait SessionReply: Sized {
    /// Closed response error.
    type Error;

    /// Consumes the reply owner and reports success using the opened stream's endpoint.
    fn succeeded(self, bound: SocketAddr) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Consumes the reply owner and reports a pre-success connect failure.
    fn failed(self, kind: ConnectErrorKind)
    -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Protocol-neutral capability for marking an owned transport abortive on drop.
pub trait AbortiveClose {
    /// Socket-adapter error.
    type Error;

    /// Marks the transport for abortive close.
    fn mark_abortive(&mut self) -> Result<(), Self::Error>;
}

/// Stable pre-success connection failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectErrorKind {
    /// No route exists to the destination network.
    NetworkUnreachable,
    /// The destination host cannot be reached.
    HostUnreachable,
    /// The destination refused the connection.
    ConnectionRefused,
    /// The connection attempt exceeded its deadline.
    Timeout,
    /// A closed implementation error that does not expose its source.
    Other,
}

/// A closed connection error that never retains or displays a raw source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectError {
    kind: ConnectErrorKind,
}

impl ConnectError {
    /// Constructs a closed connection error.
    pub const fn new(kind: ConnectErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable category used by a one-shot session reply.
    pub const fn kind(&self) -> ConnectErrorKind {
        self.kind
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ConnectErrorKind::NetworkUnreachable => "network unreachable",
            ConnectErrorKind::HostUnreachable => "host unreachable",
            ConnectErrorKind::ConnectionRefused => "connection refused",
            ConnectErrorKind::Timeout => "connection timed out",
            ConnectErrorKind::Other => "connection failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ConnectError {}

#[cfg(test)]
mod tests {
    use std::future::ready;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn domain_names_are_bounded_before_storage() {
        assert_eq!(DomainName::new("").unwrap_err(), DomainNameError::Empty);
        assert!(DomainName::new(&"a".repeat(255)).is_ok());
        assert_eq!(
            DomainName::new("é.example").unwrap_err(),
            DomainNameError::NonAscii
        );
        assert_eq!(
            DomainName::new(&"a".repeat(256)).unwrap_err(),
            DomainNameError::TooLong
        );
    }

    #[test]
    fn target_debug_does_not_disclose_the_address() {
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 443))
            .expect("non-zero port");

        let rendered = format!("{target:?}");
        assert!(!rendered.contains("192.0.2.9"));
        assert!(!rendered.contains("443"));
    }

    struct StoredEndpoint(SocketAddr);

    impl LocalEndpoint for StoredEndpoint {
        fn local_endpoint(&self) -> SocketAddr {
            self.0
        }
    }

    struct PendingReply;

    impl SessionReply for PendingReply {
        type Error = ();

        fn succeeded(
            self,
            _bound: SocketAddr,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Ok(()))
        }

        fn failed(
            self,
            _kind: ConnectErrorKind,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Ok(()))
        }
    }

    struct TestConnector;

    impl Connector for TestConnector {
        type Stream = StoredEndpoint;

        fn connect(
            &self,
            _target: &TargetAddr,
        ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
            let endpoint = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 49152, 0, 0));
            ready(Ok(StoredEndpoint(endpoint)))
        }
    }

    fn assert_send_future<T: Send>(_future: T) {}

    #[test]
    fn connector_stream_carries_an_infallible_stored_socket_endpoint() {
        let target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("non-zero port");
        let connector = TestConnector;
        assert_send_future(connector.connect(&target));
    }

    #[test]
    fn reply_contract_requires_the_opened_stream_endpoint() {
        let bound = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 49152, 0, 0));
        let stream = StoredEndpoint(bound);
        let reply = PendingReply;
        assert_send_future(reply.succeeded(stream.local_endpoint()));
    }
}
