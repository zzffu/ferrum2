use super::*;

use ferrum2_config::DnsEndpointMode;
use ferrum2_core::route::EgressPlanHandle;
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::run::test_support::{Ipv4Addr, UdpSocket, recv_udp};

mod application;
mod direct;
mod specs;
