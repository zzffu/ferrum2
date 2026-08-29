#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::ops::Range;

use bytes::{Bytes, BytesMut};

mod generation;

pub use generation::{GenerationChange, GenerationNotification, GenerationSignal};

const MAX_DOMAIN_NAME_BYTES: usize = 255;

/// A canonical ASCII domain used by allocation-free policy matchers.
///
/// Canonicalization folds ASCII case and removes at most one trailing dot.
/// The original [`DomainName`] remains available to protocol adapters.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalDomain(Box<str>);

impl CanonicalDomain {
    /// Validates and canonicalizes one non-empty ASCII domain.
    pub fn new(value: &str) -> Result<Self, DomainNameError> {
        match value.len() {
            0 => return Err(DomainNameError::Empty),
            1..=MAX_DOMAIN_NAME_BYTES if value.is_ascii() => {}
            1..=MAX_DOMAIN_NAME_BYTES => return Err(DomainNameError::NonAscii),
            _ => return Err(DomainNameError::TooLong),
        }
        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty() {
            Err(DomainNameError::Empty)
        } else {
            Ok(Self(value.to_ascii_lowercase().into_boxed_str()))
        }
    }

    /// Returns the canonical lowercase domain without a trailing dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalDomain([redacted])")
    }
}

/// A domain name whose original and canonical storage is bounded before use.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DomainName {
    original: Box<str>,
    canonical: Option<CanonicalDomain>,
}

impl DomainName {
    /// Validates and stores a domain name.
    pub fn new(value: &str) -> Result<Self, DomainNameError> {
        match value.len() {
            0 => Err(DomainNameError::Empty),
            1..=MAX_DOMAIN_NAME_BYTES if value.is_ascii() => Ok(Self {
                original: value.into(),
                // A root-only name remains a valid protocol target but cannot
                // participate in canonical policy matching.
                canonical: CanonicalDomain::new(value).ok(),
            }),
            1..=MAX_DOMAIN_NAME_BYTES => Err(DomainNameError::NonAscii),
            _ => Err(DomainNameError::TooLong),
        }
    }

    /// Returns the validated domain name.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns the canonical policy view when the name is not root-only.
    pub fn canonical(&self) -> Option<&CanonicalDomain> {
        self.canonical.as_ref()
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
        let port = NonZeroU16::new(port).ok_or(TargetAddrError::PortZero)?;
        let host = DomainName::new(host).map_err(TargetAddrError::Domain)?;
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

    /// Returns the allocation-free canonical policy view for a domain target.
    pub fn canonical_domain(&self) -> Option<&CanonicalDomain> {
        match &self.host {
            TargetHost::Domain(domain) => domain.canonical(),
            TargetHost::Ip(_) => None,
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

/// Runtime-neutral manual outbound selector state and public control.
pub mod selector;

/// Runtime-neutral, total first-match routing.
pub mod route;

/// A runtime-neutral datagram with a validated target and owned payload.
///
/// Construction applies the caller's complete payload bound before the value
/// can cross a protocol/runtime seam. Buffer-capacity accounting remains a
/// runtime concern and is intentionally not represented here.
pub struct Datagram {
    target: TargetAddr,
    backing: BytesMut,
    payload_range: Range<usize>,
    allocated_capacity: usize,
}

impl Datagram {
    /// Constructs an owned datagram whose payload does not exceed `max_payload_bytes`.
    pub fn new(
        target: TargetAddr,
        payload: BytesMut,
        max_payload_bytes: usize,
    ) -> Result<Self, DatagramError> {
        if payload.len() > max_payload_bytes {
            return Err(DatagramError::Bounds);
        }
        let allocated_capacity = payload.capacity();
        let payload_range = 0..payload.len();
        Ok(Self {
            target,
            backing: payload,
            payload_range,
            allocated_capacity,
        })
    }

    /// Constructs a datagram whose payload occupies one validated range in an
    /// exclusively owned backing allocation.
    ///
    /// Bytes before and after the payload remain owned by the datagram. A
    /// protocol adapter can therefore receive directly into its future payload
    /// position, then consume the datagram with [`Self::into_backing_parts`] to
    /// fill framing headroom and rearroom without moving the payload.
    pub fn from_payload_range(
        target: TargetAddr,
        backing: BytesMut,
        payload_range: Range<usize>,
        max_payload_bytes: usize,
    ) -> Result<Self, DatagramError> {
        if payload_range.start > payload_range.end
            || payload_range.end > backing.len()
            || payload_range.len() > max_payload_bytes
        {
            return Err(DatagramError::Bounds);
        }
        let allocated_capacity = backing.capacity();
        Ok(Self {
            target,
            backing,
            payload_range,
            allocated_capacity,
        })
    }

    /// Returns the normalized target without exposing it through formatting.
    pub fn target(&self) -> &TargetAddr {
        &self.target
    }

    /// Returns the owned payload.
    pub fn payload(&self) -> &[u8] {
        &self.backing[self.payload_range.clone()]
    }

    /// Returns the owned backing capacity captured before the payload was frozen.
    pub const fn allocated_capacity(&self) -> usize {
        self.allocated_capacity
    }

    /// Consumes the datagram into its normalized target and owned payload.
    pub fn into_parts(self) -> (TargetAddr, Bytes) {
        let payload = self.backing.freeze().slice(self.payload_range);
        (self.target, payload)
    }

    /// Consumes the datagram into its target, complete backing allocation, and
    /// exact payload range.
    ///
    /// The returned backing is uniquely owned. Its pointer and capacity are the
    /// same values captured at construction, so a protocol adapter can mutate
    /// reserved framing bytes without reallocating while an I/O operation owns
    /// the buffer.
    pub fn into_backing_parts(self) -> (TargetAddr, BytesMut, Range<usize>) {
        (self.target, self.backing, self.payload_range)
    }

    /// Borrows the target, complete backing, and exact payload range.
    pub fn backing_parts(&self) -> (&TargetAddr, &BytesMut, Range<usize>) {
        (&self.target, &self.backing, self.payload_range.clone())
    }

    /// Borrows the target, complete backing, and payload range for an owned
    /// protocol adapter that frames this datagram in place.
    ///
    /// The adapter must preserve the backing allocation: reserving, resizing
    /// beyond its existing capacity, or replacing it would violate any pending
    /// I/O operation's stable-address contract. The returned payload range is
    /// always valid for the current logical length.
    pub fn backing_parts_mut(&mut self) -> (&TargetAddr, &mut BytesMut, Range<usize>) {
        (&self.target, &mut self.backing, self.payload_range.clone())
    }
}

impl fmt::Debug for Datagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Datagram")
            .field("target", &"[redacted]")
            .field("payload_len", &self.payload().len())
            .finish()
    }
}

/// Failure to construct a caller-bounded datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramError {
    /// The owned payload exceeds the caller's complete payload bound.
    Bounds,
}

impl fmt::Display for DatagramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounds")
    }
}

impl Error for DatagramError {}

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
    /// Returns the complete stored endpoint without a socket query.
    fn local_socket_addr(&self) -> SocketAddr;
}

/// A one-shot response to an accepted application session.
pub trait SessionReply: Sized {
    /// Closed response error.
    type Error;

    /// Consumes the reply owner and reports success for either socket family.
    fn succeeded_socket(
        self,
        bound: SocketAddr,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

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
    /// Local policy denied the connection before opening an outbound.
    PolicyDenied,
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
            ConnectErrorKind::PolicyDenied => "connection failed",
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
        assert_eq!(
            TargetAddr::domain("example.test", 0).unwrap_err(),
            TargetAddrError::PortZero
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

    #[test]
    fn canonical_domains_fold_ascii_case_and_one_trailing_dot() {
        let domain = DomainName::new("ExAmPlE.Test.").expect("domain");
        assert_eq!(domain.as_str(), "ExAmPlE.Test.");
        assert_eq!(
            domain.canonical().expect("canonical").as_str(),
            "example.test"
        );
        assert!(DomainName::new(".").expect("root").canonical().is_none());
        let target = TargetAddr::domain("EXAMPLE.TEST.", 443).expect("target");
        assert_eq!(
            target.canonical_domain().expect("canonical").as_str(),
            "example.test"
        );
    }

    #[test]
    fn public_direct_egress_handle_never_yields_an_empty_plan() {
        let handle = route::EgressPlanHandle::direct(7);
        assert_eq!(handle.snapshot().hops(), &[7]);
        assert_eq!(handle.snapshot_owned().hops(), &[7]);
    }

    #[test]
    fn datagram_owns_a_caller_bounded_payload_without_disclosing_values() {
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 443))
            .expect("non-zero port");
        let datagram =
            Datagram::new(target, BytesMut::from(&b"owned payload"[..]), 13).expect("at bound");

        assert_eq!(datagram.payload(), b"owned payload");
        assert_eq!(datagram.allocated_capacity(), 13);
        assert_eq!(datagram.target().port().get(), 443);
        assert_eq!(
            Datagram::new(
                TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("non-zero port"),
                BytesMut::from(&b"too large"[..]),
                8,
            )
            .unwrap_err(),
            DatagramError::Bounds
        );
        let rendered = format!("{datagram:?}");
        assert!(!rendered.contains("192.0.2.9"));
        assert!(!rendered.contains("owned payload"));
    }

    #[test]
    fn ranged_datagram_retains_complete_unique_backing() {
        let target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)).expect("non-zero port");
        let mut backing = BytesMut::with_capacity(128);
        backing.resize(24, 0xa5);
        backing.extend_from_slice(b"payload");
        let pointer = backing.as_ptr();
        let capacity = backing.capacity();
        let datagram = Datagram::from_payload_range(target, backing, 24..31, 7)
            .expect("bounded ranged datagram");

        assert_eq!(datagram.payload(), b"payload");
        assert_eq!(datagram.allocated_capacity(), capacity);
        let (_, backing, payload_range) = datagram.into_backing_parts();
        assert_eq!(backing.as_ptr(), pointer);
        assert_eq!(backing.capacity(), capacity);
        assert_eq!(payload_range, 24..31);
        assert_eq!(&backing[payload_range], b"payload");
    }

    #[test]
    fn ranged_datagram_rejects_invalid_ranges_and_payload_bounds() {
        let target =
            || TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)).expect("non-zero port");

        let reversed_start = 6;
        let reversed_end = 5;
        assert_eq!(
            Datagram::from_payload_range(
                target(),
                BytesMut::from(&b"payload"[..]),
                reversed_start..reversed_end,
                7,
            )
            .unwrap_err(),
            DatagramError::Bounds
        );
        assert_eq!(
            Datagram::from_payload_range(target(), BytesMut::from(&b"payload"[..]), 0..8, 8)
                .unwrap_err(),
            DatagramError::Bounds
        );
        assert_eq!(
            Datagram::from_payload_range(target(), BytesMut::from(&b"payload"[..]), 0..7, 6)
                .unwrap_err(),
            DatagramError::Bounds
        );
    }

    struct StoredEndpoint(SocketAddr);

    impl LocalEndpoint for StoredEndpoint {
        fn local_socket_addr(&self) -> SocketAddr {
            self.0
        }
    }

    struct PendingReply;

    impl SessionReply for PendingReply {
        type Error = ();

        fn succeeded_socket(
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
            let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152);
            ready(Ok(StoredEndpoint(SocketAddr::V4(endpoint))))
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
        struct Ipv6Endpoint(SocketAddr);
        impl LocalEndpoint for Ipv6Endpoint {
            fn local_socket_addr(&self) -> SocketAddr {
                self.0
            }
        }
        let stream = Ipv6Endpoint(bound);
        let reply = PendingReply;
        assert_send_future(reply.succeeded_socket(stream.local_socket_addr()));
    }
}
