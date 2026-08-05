use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name};

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
