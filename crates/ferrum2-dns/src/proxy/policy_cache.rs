use std::time::Instant;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::{MemoizedPolicyResponse, ProxyCache, ProxyIngress, ProxyPolicy};
use crate::response::ResponseSemantics;
use crate::{
    DnsAddressRecords, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsError, DnsServerId,
    MAX_APPLICATION_RESOLVED_CANDIDATES,
};

impl ProxyPolicy {
    pub(super) fn inbound(&self, ingress: ProxyIngress) -> Option<usize> {
        match ingress {
            ProxyIngress::Listener(index) if index < self.listener_count => Some(index),
            ProxyIngress::Ordinary(index) if index < self.ordinary_count => {
                self.listener_count.checked_add(index)
            }
            ProxyIngress::Listener(_) | ProxyIngress::Ordinary(_) => None,
        }
    }
}

pub(super) fn memo_position(
    memo: &[MemoizedPolicyResponse],
    server: DnsServerId,
    qname: &Name,
    qtype: RecordType,
) -> Option<usize> {
    memo.iter()
        .position(|entry| entry.server == server && entry.qname == *qname && entry.qtype == qtype)
}

pub(super) fn append_application_records(
    qname: &Name,
    qtype: RecordType,
    response: &Message,
    ipv4: &mut Vec<std::net::Ipv4Addr>,
    ipv6: &mut Vec<std::net::Ipv6Addr>,
) {
    for (address, _) in ResponseSemantics::new(qname, qtype, response).addresses() {
        match (qtype, address) {
            (RecordType::A, std::net::IpAddr::V4(address))
                if ipv4.len() < MAX_APPLICATION_RESOLVED_CANDIDATES && !ipv4.contains(&address) =>
            {
                ipv4.push(address);
            }
            (RecordType::AAAA, std::net::IpAddr::V6(address))
                if ipv6.len() < MAX_APPLICATION_RESOLVED_CANDIDATES && !ipv6.contains(&address) =>
            {
                ipv6.push(address);
            }
            _ => {}
        }
    }
}

pub(super) fn cache_qtype(qtype: RecordType) -> Option<DnsCacheQtype> {
    match qtype {
        RecordType::A => Some(DnsCacheQtype::A),
        RecordType::AAAA => Some(DnsCacheQtype::Aaaa),
        _ => None,
    }
}

pub(super) fn cache_application_response(
    cache: &ProxyCache,
    key: DnsCacheKey,
    qname: &Name,
    qtype: RecordType,
    response: &Message,
) -> Result<(), DnsError> {
    let Some((answer, ttl)) = ResponseSemantics::new(qname, qtype, response).cache_answer() else {
        return Ok(());
    };
    let now = Instant::now();
    match answer {
        DnsCacheAnswer::Positive(records) => cache.cache.insert_positive(key, records, ttl, now),
        DnsCacheAnswer::Negative => cache.cache.insert_negative(key, ttl, now),
    }
    .map_err(|_| DnsError::Runtime)?;
    Ok(())
}

pub(super) fn cached_application_response(
    request: &Message,
    records: &DnsAddressRecords,
) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    let Some(question) = request.queries.first() else {
        return response;
    };
    response.add_query(question.clone());
    match records {
        DnsAddressRecords::A(records) => {
            for address in records.iter().copied() {
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    0,
                    RData::A(address.into()),
                ));
            }
        }
        DnsAddressRecords::Aaaa(records) => {
            for address in records.iter().copied() {
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    0,
                    RData::AAAA(address.into()),
                ));
            }
        }
    }
    response
}

pub(super) fn cached_application_negative_response(request: &Message) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_queries(request.queries.iter().cloned());
    response
}

pub(super) fn bind_response(mut response: Message, request: &Message, question: &Query) -> Message {
    response.metadata.id = request.metadata.id;
    response.queries.clear();
    response.add_query(question.clone());
    response
}

pub(super) fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.add_queries(request.queries.iter().cloned());
    response
}
