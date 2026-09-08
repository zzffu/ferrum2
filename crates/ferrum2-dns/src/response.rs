use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

use crate::{DnsAddressRecords, DnsCacheAnswer, MAX_APPLICATION_RESOLVED_CANDIDATES};

/// Borrowed DNS answer semantics shared by policy, application extraction and caching.
/// Invalid or ambiguous alias chains have no usable terminal owner.
pub(crate) struct ResponseSemantics<'a> {
    response: &'a Message,
    qtype: RecordType,
    terminal: Option<(&'a Name, Option<u32>)>,
}

impl<'a> ResponseSemantics<'a> {
    pub(crate) fn new(qname: &'a Name, qtype: RecordType, response: &'a Message) -> Self {
        Self {
            response,
            qtype,
            terminal: final_owner(qname, response),
        }
    }

    /// Policy deliberately sees both address families, without the application bound.
    pub(crate) fn addresses(&self) -> impl Iterator<Item = (IpAddr, u32)> + '_ {
        self.response.answers.iter().filter_map(|record| {
            let (owner, _) = self.terminal?;
            if !matches!(self.qtype, RecordType::A | RecordType::AAAA) || &record.name != owner {
                return None;
            }
            let address = match &record.data {
                RData::A(address) => IpAddr::V4(address.0),
                RData::AAAA(address) => IpAddr::V6(address.0),
                _ => return None,
            };
            Some((address, record.ttl))
        })
    }

    /// Only retain answers whose complete policy address set can be reconstructed.
    /// Oversized, mixed-family, truncated and invalid answers bypass this bounded cache.
    pub(crate) fn cache_answer(&self) -> Option<(DnsCacheAnswer, Duration)> {
        let (_, mut ttl) = self.terminal?;
        if self.response.metadata.truncation
            || !matches!(self.qtype, RecordType::A | RecordType::AAAA)
            || !matches!(
                self.response.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return None;
        }
        let mut addresses =
            [IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED); MAX_APPLICATION_RESOLVED_CANDIDATES];
        let mut count = 0;
        for (address, record_ttl) in self.addresses() {
            if self.response.metadata.response_code != ResponseCode::NoError
                || !matches!(
                    (self.qtype, address),
                    (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
                )
            {
                return None;
            }
            ttl = Some(ttl.map_or(record_ttl, |ttl| ttl.min(record_ttl)));
            if !addresses[..count].contains(&address) {
                if count == addresses.len() {
                    return None;
                }
                addresses[count] = address;
                count += 1;
            }
        }
        if ttl == Some(0) {
            return None;
        }
        let answer = if count == 0 {
            let soa_ttl = self
                .response
                .authorities
                .iter()
                .filter_map(|record| match &record.data {
                    RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
                    _ => None,
                })
                .min()?;
            ttl = Some(ttl.map_or(soa_ttl, |ttl| ttl.min(soa_ttl)));
            DnsCacheAnswer::Negative
        } else {
            let records = match self.qtype {
                RecordType::A => DnsAddressRecords::A(Arc::from(
                    addresses[..count]
                        .iter()
                        .filter_map(|address| match address {
                            IpAddr::V4(address) => Some(*address),
                            IpAddr::V6(_) => None,
                        })
                        .collect::<Vec<_>>(),
                )),
                RecordType::AAAA => DnsAddressRecords::Aaaa(Arc::from(
                    addresses[..count]
                        .iter()
                        .filter_map(|address| match address {
                            IpAddr::V6(address) => Some(*address),
                            IpAddr::V4(_) => None,
                        })
                        .collect::<Vec<_>>(),
                )),
                _ => return None,
            };
            DnsCacheAnswer::Positive(records)
        };
        let ttl = ttl.filter(|ttl| *ttl != 0)?;
        Some((answer, Duration::from_secs(u64::from(ttl))))
    }
}

fn final_owner<'a>(qname: &'a Name, response: &'a Message) -> Option<(&'a Name, Option<u32>)> {
    let mut owner = qname;
    let mut ttl: Option<u32> = None;
    // A longer walk necessarily revisits a name; no allocation is needed to reject cycles.
    for _ in 0..=response.answers.len() {
        let mut next = None;
        let mut has_address = false;
        for record in response
            .answers
            .iter()
            .filter(|record| &record.name == owner)
        {
            match &record.data {
                RData::CNAME(cname) => {
                    if next.is_some_and(|next| next != &cname.0) {
                        return None;
                    }
                    next = Some(&cname.0);
                    ttl = Some(ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
                }
                RData::A(_) | RData::AAAA(_) => has_address = true,
                _ => {}
            }
        }
        match next {
            None => return Some((owner, ttl)),
            Some(_) if has_address => return None,
            Some(next) => owner = next,
        }
    }
    None
}
