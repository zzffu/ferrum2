use super::*;

use ferrum2_config::{
    CompiledRuleSetResource, DnsEndpointMode, ServerV2Resources, finish_server_v2, prepare_server,
};
use ferrum2_core::route::EgressPlanHandle;
use ferrum2_dns::{DnsAddressRecords, DnsCacheKey, DnsCacheQtype, DnsServerId, ResolverGeneration};
use ferrum2_rule::{MatchSetBuilder, RuleEngineSnapshotBuilder};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::run::test_support::{
    Ipv4Addr, UdpSocket, assert_pending, recv_udp, reserve_address, server_test_config_source,
};

use direct::answer_a;
use policy::materialized_server_test_config_source;

mod application;
mod direct;
mod policy;
mod specs;
