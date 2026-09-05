//! Exact client-facing responses from the two reviewed M4 DNS fixtures.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

pub(super) enum DnsResponseFixture {
    Profile,
    Resource,
}

pub(super) struct ExpectedDnsResponse(Message);

impl ExpectedDnsResponse {
    pub(super) fn new(name: Name, fixture: DnsResponseFixture) -> Self {
        let ttl = match fixture {
            DnsResponseFixture::Profile => 0,
            DnsResponseFixture::Resource => 30,
        };
        let mut response = Message::new(0, MessageType::Response, OpCode::Query);
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.authoritative = false;
        response.metadata.truncation = false;
        response.metadata.recursion_desired = false;
        response.metadata.recursion_available = true;
        response.metadata.authentic_data = false;
        response.metadata.checking_disabled = false;
        response.add_query(Query::query(name.clone(), RecordType::A));
        let mut answer = Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::LOCALHOST)));
        answer.dns_class = DNSClass::IN;
        response.add_answer(answer);
        Self(response)
    }

    pub(super) fn validate_wire(&self, request_id: u16, wire: &[u8]) -> Result<(), String> {
        if wire.len() < 12 || wire[3] & 0x40 != 0 {
            return Err("DNS fixture response header is invalid".to_owned());
        }
        let mut decoder = BinDecoder::new(wire);
        let actual = Message::read(&mut decoder)
            .map_err(|_| "DNS fixture response is malformed".to_owned())?;
        if !decoder.is_empty() {
            return Err("DNS fixture response has trailing bytes".to_owned());
        }
        let mut expected = self.0.clone();
        expected.metadata.id = request_id;
        // Hickory Record equality deliberately ignores TTL (RFC 2136). This
        // fixture contract includes it, in addition to every Message field.
        if actual != expected
            || actual
                .answers
                .iter()
                .map(|record| record.ttl)
                .ne(expected.answers.iter().map(|record| record.ttl))
        {
            return Err(
                "DNS fixture response does not match the complete expected message".to_owned(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod dns_contract_tests {
    use super::*;

    fn response(ttl: u32) -> Message {
        let name = Name::from_ascii("fixture.test.").unwrap();
        let mut response = Message::new(73, MessageType::Response, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(Query::query(name.clone(), RecordType::A));
        response.add_answer(Record::from_rdata(
            name,
            ttl,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        response
    }

    #[test]
    fn complete_fixture_responses_and_each_semantic_mutation_are_checked() {
        for (fixture, ttl) in [
            (DnsResponseFixture::Profile, 0),
            (DnsResponseFixture::Resource, 30),
        ] {
            let expected =
                ExpectedDnsResponse::new(Name::from_ascii("fixture.test.").unwrap(), fixture);
            let valid = response(ttl);
            assert_eq!(expected.validate_wire(73, &valid.to_vec().unwrap()), Ok(()));
            let mutations: Vec<fn(&mut Message)> = vec![
                |value| value.metadata.id += 1,
                |value| value.metadata.message_type = MessageType::Query,
                |value| value.metadata.op_code = OpCode::Status,
                |value| value.metadata.response_code = ResponseCode::ServFail,
                |value| value.metadata.authoritative = true,
                |value| value.metadata.truncation = true,
                |value| value.metadata.recursion_desired = true,
                |value| value.metadata.recursion_available = false,
                |value| value.metadata.authentic_data = true,
                |value| value.metadata.checking_disabled = true,
                |value| {
                    value.queries[0].set_name(Name::from_ascii("other.test.").unwrap());
                },
                |value| {
                    value.queries[0].set_query_type(RecordType::AAAA);
                },
                |value| {
                    value.queries[0].set_query_class(DNSClass::CH);
                },
                |value| value.queries.push(value.queries[0].clone()),
                |value| value.answers[0].name = Name::from_ascii("other.test.").unwrap(),
                |value| value.answers[0].dns_class = DNSClass::CH,
                |value| value.answers[0].ttl += 1,
                |value| value.answers[0].data = RData::A(A(Ipv4Addr::UNSPECIFIED)),
                |value| value.answers.clear(),
                |value| value.answers.push(value.answers[0].clone()),
                |value| value.authorities.push(value.answers[0].clone()),
                |value| value.additionals.push(value.answers[0].clone()),
                |value| value.edns = Some(Default::default()),
            ];
            for (index, mutate) in mutations.into_iter().enumerate() {
                let mut invalid = valid.clone();
                mutate(&mut invalid);
                assert!(
                    expected
                        .validate_wire(73, &invalid.to_vec().unwrap())
                        .is_err(),
                    "mutation {index}"
                );
            }
            let mut trailing = valid.to_vec().unwrap();
            trailing.push(0);
            assert!(expected.validate_wire(73, &trailing).is_err());
            let mut reserved = valid.to_vec().unwrap();
            reserved[3] |= 0x40;
            assert!(expected.validate_wire(73, &reserved).is_err());
        }
    }
}
