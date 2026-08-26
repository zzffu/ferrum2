use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::{MemoizedPolicyResponse, ProxyCache, ProxyIngress, ProxyPolicy};
use crate::{
    DnsAddressRecords, DnsCacheKey, DnsCacheQtype, DnsError, DnsServerId,
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
    let Some((records, _)) = application_records_with_ttl(qname, qtype, response) else {
        return;
    };
    match records {
        DnsAddressRecords::A(records) => {
            for address in records.iter().copied() {
                if ipv4.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
                    break;
                }
                if !ipv4.contains(&address) {
                    ipv4.push(address);
                }
            }
        }
        DnsAddressRecords::Aaaa(records) => {
            for address in records.iter().copied() {
                if ipv6.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
                    break;
                }
                if !ipv6.contains(&address) {
                    ipv6.push(address);
                }
            }
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
    let now = Instant::now();
    match response.metadata.response_code {
        ResponseCode::NoError => {
            if let Some((records, ttl)) = application_records_with_ttl(qname, qtype, response) {
                cache
                    .cache
                    .insert_positive(key, records, ttl, now)
                    .map_err(|_| DnsError::Runtime)?;
            } else if let Some(ttl) = negative_ttl(response) {
                cache
                    .cache
                    .insert_negative(key, ttl, now)
                    .map_err(|_| DnsError::Runtime)?;
            }
        }
        ResponseCode::NXDomain => {
            if let Some(ttl) = negative_ttl(response) {
                cache
                    .cache
                    .insert_negative(key, ttl, now)
                    .map_err(|_| DnsError::Runtime)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn application_records_with_ttl(
    qname: &Name,
    qtype: RecordType,
    response: &Message,
) -> Option<(DnsAddressRecords, Duration)> {
    let (owner, mut ttl) = final_answer_owner(qname, &response.answers)?;
    match qtype {
        RecordType::A => {
            let mut addresses = Vec::new();
            for record in &response.answers {
                if &record.name != owner {
                    continue;
                }
                let RData::A(address) = &record.data else {
                    continue;
                };
                ttl = minimum_ttl(ttl, record.ttl);
                if addresses.len() < MAX_APPLICATION_RESOLVED_CANDIDATES
                    && !addresses.contains(&address.0)
                {
                    addresses.push(address.0);
                }
            }
            (!addresses.is_empty()).then(|| {
                (
                    DnsAddressRecords::A(Arc::from(addresses)),
                    Duration::from_secs(u64::from(ttl.unwrap_or(0))),
                )
            })
        }
        RecordType::AAAA => {
            let mut addresses = Vec::new();
            for record in &response.answers {
                if &record.name != owner {
                    continue;
                }
                let RData::AAAA(address) = &record.data else {
                    continue;
                };
                ttl = minimum_ttl(ttl, record.ttl);
                if addresses.len() < MAX_APPLICATION_RESOLVED_CANDIDATES
                    && !addresses.contains(&address.0)
                {
                    addresses.push(address.0);
                }
            }
            (!addresses.is_empty()).then(|| {
                (
                    DnsAddressRecords::Aaaa(Arc::from(addresses)),
                    Duration::from_secs(u64::from(ttl.unwrap_or(0))),
                )
            })
        }
        _ => None,
    }
}

pub(super) fn final_answer_owner<'a>(
    qname: &'a Name,
    answers: &'a [Record],
) -> Option<(&'a Name, Option<u32>)> {
    let mut owner = qname;
    let mut ttl = None;
    for _ in 0..=answers.len() {
        let Some(record) = answers
            .iter()
            .find(|record| &record.name == owner && matches!(record.data, RData::CNAME(_)))
        else {
            return Some((owner, ttl));
        };
        let RData::CNAME(cname) = &record.data else {
            unreachable!("the selected record is a CNAME")
        };
        ttl = minimum_ttl(ttl, record.ttl);
        owner = &cname.0;
    }
    None
}

pub(super) fn minimum_ttl(current: Option<u32>, candidate: u32) -> Option<u32> {
    Some(current.map_or(candidate, |current| current.min(candidate)))
}

pub(super) fn negative_ttl(response: &Message) -> Option<Duration> {
    response
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
        .map(|ttl| Duration::from_secs(u64::from(ttl)))
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
