#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;

use bytes::{Bytes, BytesMut};

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
    payload: Bytes,
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
        Ok(Self {
            target,
            payload: payload.freeze(),
            allocated_capacity,
        })
    }

    /// Returns the normalized target without exposing it through formatting.
    pub fn target(&self) -> &TargetAddr {
        &self.target
    }

    /// Returns the owned payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the owned backing capacity captured before the payload was frozen.
    pub const fn allocated_capacity(&self) -> usize {
        self.allocated_capacity
    }

    /// Consumes the datagram into its normalized target and owned payload.
    pub fn into_parts(self) -> (TargetAddr, Bytes) {
        (self.target, self.payload)
    }
}

impl fmt::Debug for Datagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Datagram")
            .field("target", &"[redacted]")
            .field("payload_len", &self.payload.len())
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
    /// Returns the stored legacy IPv4 endpoint without a socket query.
    fn local_endpoint(&self) -> SocketAddrV4;

    /// Returns the complete stored endpoint without a socket query.
    fn local_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.local_endpoint())
    }
}

/// A one-shot response to an accepted application session.
pub trait SessionReply: Sized {
    /// Closed response error.
    type Error;

    /// Consumes the reply owner and reports success using the opened stream's endpoint.
    fn succeeded(self, bound: SocketAddrV4)
    -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Consumes the reply owner and reports success for either socket family.
    ///
    /// Legacy reply owners retain their IPv4 behavior and fail closed for IPv6.
    fn succeeded_socket(
        self,
        bound: SocketAddr,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self: Send,
    {
        async move {
            match bound {
                SocketAddr::V4(bound) => self.succeeded(bound).await,
                SocketAddr::V6(_) => self.failed(ConnectErrorKind::Other).await,
            }
        }
    }

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
    fn route_table_is_ordered_conjunctive_exact_and_total() {
        use route::{MAX_ROUTE_RULES, Network, RouteRule, RouteTable};

        let domain = TargetAddr::domain("example.test", 443).expect("domain");
        let ipv4 =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 443)).expect("IPv4");
        let different_ipv4 =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443)).expect("IPv4");
        let ipv6 = TargetAddr::ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        )))
        .expect("IPv6");
        let route = RouteTable::routed(
            vec![
                RouteRule::new(Some(0), Some(Network::Tcp), Some(domain.clone()), 1),
                RouteRule::new(Some(0), None, None, 2),
                RouteRule::new(None, Some(Network::Udp), None, 3),
                RouteRule::new(None, None, Some(ipv4.clone()), 4),
                RouteRule::new(None, None, Some(ipv6.clone()), 5),
            ],
            6,
        )
        .expect("bounded route");
        #[rustfmt::skip]
        let cases = [
            (0, Network::Tcp, domain.clone(), 1),
            (0, Network::Tcp, TargetAddr::domain("EXAMPLE.TEST", 443).expect("case"), 1),
            (0, Network::Udp, domain.clone(), 2),
            (1, Network::Udp, domain.clone(), 3),
            (1, Network::Tcp, ipv4, 4),
            (1, Network::Tcp, different_ipv4, 6),
            (1, Network::Tcp, ipv6, 5),
            (1, Network::Tcp, TargetAddr::domain("example.test.", 443).expect("dot"), 6),
            (1, Network::Tcp, TargetAddr::domain("example.test", 80).expect("port"), 6),
        ];
        assert!(route.is_routed());
        for (inbound, network, target, expected) in cases {
            assert_eq!(route.select(inbound, network, &target), expected);
        }
        let static_route = RouteTable::static_bindings(vec![7, 8]).expect("static route");
        assert!(!static_route.is_routed());
        assert_eq!(static_route.select(1, Network::Udp, &domain), 8);
        assert_eq!(format!("{route:?}"), "RouteTable([redacted])");
        #[rustfmt::skip]
        let oversized = (0..=MAX_ROUTE_RULES).map(|_| RouteRule::new(Some(0), None, None, 0)).collect();
        assert!(RouteTable::routed(oversized, 0).is_none());
    }

    #[test]
    fn public_route_constructors_never_yield_empty_plans() {
        use route::{EgressPlanHandle, RouteTable, compile_selector_plans};
        use selector::{TaggedInbound, TaggedOutbound, TaggedPlan, TaggedRoute};

        assert_eq!(EgressPlanHandle::direct(7).snapshot_owned().hops(), &[7]);
        assert!(RouteTable::static_bindings(Vec::new()).is_none());
        assert_eq!(
            RouteTable::routed(Vec::new(), 8)
                .expect("mandatory final")
                .final_plan_snapshot()
                .hops(),
            &[8]
        );
        let Err(error) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &[TaggedOutbound::new("out", 7)],
            &[TaggedPlan::new("empty", Vec::new())],
            &[],
            TaggedRoute::Routed {
                rules: Vec::new(),
                final_outbound: Some("out"),
            },
        ) else {
            panic!("empty plan was accepted")
        };
        assert_eq!(error, selector::SelectorCompileError::PlanHops);
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

    struct StoredEndpoint(SocketAddrV4);

    impl LocalEndpoint for StoredEndpoint {
        fn local_endpoint(&self) -> SocketAddrV4 {
            self.0
        }
    }

    struct PendingReply;

    impl SessionReply for PendingReply {
        type Error = ();

        fn succeeded(
            self,
            _bound: SocketAddrV4,
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
        struct Ipv6Endpoint(SocketAddr);
        impl LocalEndpoint for Ipv6Endpoint {
            fn local_endpoint(&self) -> SocketAddrV4 {
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.0.port())
            }

            fn local_socket_addr(&self) -> SocketAddr {
                self.0
            }
        }
        let stream = Ipv6Endpoint(bound);
        let reply = PendingReply;
        assert_send_future(reply.succeeded_socket(stream.local_socket_addr()));
    }
}
