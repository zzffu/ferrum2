use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_dns::{DnsUpstreamSpec, DnsUpstreamTransport, TaggedResolver};
use ferrum2_runtime::{
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot,
    ProcessSupervisor,
};
use tokio::sync::Notify;

use super::super::test_support::*;
use super::super::{RunError, report_result};
use super::network_lifecycle::{
    ClientNetworkResetHook, ClientNetworkResetRuntime, network_reset_coordinator,
};
use super::observation::record_tun_event;
use super::tcp::run_tcp;
use super::udp::{
    SyntheticDns, TunUdpPlan, TunUdpRouteRequest, authorize_dns_peer_after_answer,
    commit_peer_after_success, select_udp_target, select_udp_target_generation_stable,
    target_payload_within_bound, udp_route_generation_is_current,
};

mod network_lifecycle;
mod observation;
mod tcp;
mod udp_association;
mod udp_dns;
mod udp_route;

pub(in crate::run) use observation::NeverPrepared;
