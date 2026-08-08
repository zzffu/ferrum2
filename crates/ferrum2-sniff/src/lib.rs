/// A closed sniffer selector. Slice order is evaluation order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Dns,
    Tls,
    Http,
}

/// The framing already owned by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

use std::{fmt, io::Cursor, net::IpAddr};

use hickory_proto::{
    op::{Message, MessageType, OpCode},
    rr::{DNSClass, Name},
    serialize::binary::{BinDecodable, BinDecoder},
};
use rustls::server::Acceptor;

/// Closed metadata whose `Debug` representation never includes the detected name.
#[derive(Clone, Eq, PartialEq)]
pub enum Metadata {
    Dns { domain: String },
    Tls { domain: Option<String> },
    Http { domain: Option<String> },
}

impl fmt::Debug for Metadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns { .. } => formatter.write_str("Dns { domain: <redacted> }"),
            Self::Tls { domain } => formatter
                .debug_struct("Tls")
                .field("domain_present", &domain.is_some())
                .finish(),
            Self::Http { domain } => formatter
                .debug_struct("Http")
                .field("domain_present", &domain.is_some())
                .finish(),
        }
    }
}

/// A closed parser result. `NeedMore` is returned only below the caller's limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Progress {
    Matched(Metadata),
    NeedMore,
    NoMatch,
    Invalid,
}

/// Inspects only `bytes`, honoring configured order and the caller's absolute byte limit.
///
/// `destination_port` affects only incomplete DNS/TCP arbitration; complete DNS is port-neutral.
pub fn sniff(
    bytes: &[u8],
    max_bytes: usize,
    transport: Transport,
    destination_port: u16,
    order: &[Protocol],
) -> Progress {
    if bytes.len() > max_bytes {
        return Progress::Invalid;
    }

    let mut invalid = false;
    for protocol in order {
        let progress = match protocol {
            Protocol::Dns => sniff_dns(bytes, max_bytes, transport, destination_port),
            Protocol::Tls => sniff_tls(bytes, max_bytes, transport),
            Protocol::Http => sniff_http(bytes, max_bytes, transport),
        };
        match progress {
            Progress::Matched(_) | Progress::NeedMore => return progress,
            Progress::Invalid => invalid = true,
            Progress::NoMatch => {}
        }
    }
    if invalid {
        Progress::Invalid
    } else {
        Progress::NoMatch
    }
}

fn sniff_dns(
    bytes: &[u8],
    max_bytes: usize,
    transport: Transport,
    destination_port: u16,
) -> Progress {
    let message = match transport {
        Transport::Udp => decode_dns(bytes),
        Transport::Tcp => {
            let Some(length) = bytes
                .get(..2)
                .map(|length| usize::from(u16::from_be_bytes([length[0], length[1]])))
            else {
                return dns_incomplete(bytes.len(), max_bytes, destination_port);
            };
            if length == 0 || length > max_bytes.saturating_sub(2) {
                return Progress::Invalid;
            }
            let end = length + 2;
            let Some(frame) = bytes.get(2..end) else {
                return dns_incomplete(bytes.len(), max_bytes, destination_port);
            };
            decode_dns(frame)
        }
    };

    let Ok(message) = message else {
        return Progress::Invalid;
    };
    if message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Query
        || message.queries.len() != 1
        || message.queries[0].query_class() != DNSClass::IN
    {
        return Progress::Invalid;
    }
    Progress::Matched(Metadata::Dns {
        domain: message.queries[0].name().to_ascii(),
    })
}

fn decode_dns(bytes: &[u8]) -> Result<Message, ()> {
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(|_| ())?;
    decoder.is_empty().then_some(message).ok_or(())
}

fn dns_incomplete(length: usize, max_bytes: usize, destination_port: u16) -> Progress {
    if destination_port != 53 {
        Progress::NoMatch
    } else if length < max_bytes {
        Progress::NeedMore
    } else {
        Progress::Invalid
    }
}

fn sniff_tls(bytes: &[u8], max_bytes: usize, transport: Transport) -> Progress {
    if transport != Transport::Tcp || !plausible_tls_prefix(bytes) {
        return Progress::NoMatch;
    }

    let mut acceptor = Acceptor::default();
    let mut input = Cursor::new(bytes);
    loop {
        let read = match acceptor.read_tls(&mut input) {
            Ok(read) => read,
            Err(_) => return Progress::Invalid,
        };
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                return Progress::Matched(Metadata::Tls {
                    domain: accepted.client_hello().server_name().map(str::to_owned),
                });
            }
            Ok(None) => {}
            Err(_) => return Progress::Invalid,
        }
        if read == 0 {
            return bounded_partial(bytes.len(), max_bytes);
        }
    }
}

fn plausible_tls_prefix(bytes: &[u8]) -> bool {
    bytes
        .first()
        .is_none_or(|first| *first == 0x16 && bytes.get(1).is_none_or(|major| *major == 0x03))
}

fn bounded_partial(length: usize, max_bytes: usize) -> Progress {
    if length < max_bytes {
        Progress::NeedMore
    } else {
        Progress::Invalid
    }
}

fn sniff_http(bytes: &[u8], max_bytes: usize, transport: Transport) -> Progress {
    if transport != Transport::Tcp {
        return Progress::NoMatch;
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(_body_offset)) => {
            let domain = if request.method == Some("CONNECT") {
                request.path.and_then(domain_from_authority)
            } else {
                let mut hosts = request
                    .headers
                    .iter()
                    .filter(|header| header.name.eq_ignore_ascii_case("host"));
                match (hosts.next(), hosts.next()) {
                    (Some(host), None) => std::str::from_utf8(host.value)
                        .ok()
                        .and_then(domain_from_authority),
                    _ => None,
                }
            };
            Progress::Matched(Metadata::Http { domain })
        }
        Ok(httparse::Status::Partial) if plausible_http_prefix(bytes) => {
            bounded_partial(bytes.len(), max_bytes)
        }
        Ok(httparse::Status::Partial) => Progress::NoMatch,
        Err(_) if plausible_http_prefix(bytes) => Progress::Invalid,
        Err(_) => Progress::NoMatch,
    }
}

fn plausible_http_prefix(bytes: &[u8]) -> bool {
    bytes.first().is_none_or(u8::is_ascii_uppercase)
}

fn domain_from_authority(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() || authority.starts_with('[') {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().ok()?;
            if port == 0 || host.contains(':') {
                return None;
            }
            host
        }
        None => authority,
    };
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let name = Name::from_ascii(host).ok()?;
    (!name.is_root()).then(|| name.to_ascii())
}
