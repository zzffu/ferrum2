use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

mod association;
mod direct;
mod request;
mod response;

pub(in crate::run) use response::{
    DirectTestResolver, DirectTestSocket, SelectiveDirectTestSocket, SequencedDirectTestResolver,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_crypto::{
    KeySelector, MethodKeyProvider, MethodPsk, MethodSecretKeyRef, MethodSinglePskProvider,
    SecureRandom,
};
use ferrum2_net::UdpResolver;
use ferrum2_runtime::{
    DirectUdpSocket, MAX_UDP_WIRE_DATAGRAM_BYTES, OwnerRegistry, UDP_SESSION_QUEUE_DEPTH,
    UdpBufferReservation, UdpRuntimeError, UdpRuntimeLimits, UdpSessionManager,
};
use ferrum2_shadowsocks::{
    MAX_UDP_WIRE_LEN, MethodKeyAdapter, UdpPacketError, UdpPacketScratch, UdpServer,
};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::direct::{
    DIRECT_UDP_CANDIDATE_HINT_CAPACITY, DirectUdpCandidateHints, DirectUdpFamily,
    DirectUdpResponseMatch, DirectUdpResponsePolicy, MAX_DIRECT_UDP_READINESS_DRAIN,
    receive_direct_response,
};
use super::request::register_udp_session;
use super::response::dns_response_target_matches;
use super::*;
use crate::run::egress::context::ClientRequestOrigin;
use crate::run::test_support::*;

fn exhaust_budget(
    budget: &ferrum2_runtime::UdpBufferBudget,
    limit: usize,
) -> Vec<UdpBufferReservation> {
    let mut remaining = limit
        .checked_sub(budget.reserved_bytes())
        .expect("test budget is not overcommitted");
    let mut held = Vec::new();
    while remaining != 0 {
        let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
        held.push(budget.reserve(capacity).expect("fill test budget"));
        remaining -= capacity;
    }
    held
}

struct FailingConfiguredApplicationBackend {
    calls: AtomicUsize,
}

impl ferrum2_dns::ApplicationResolveBackend for FailingConfiguredApplicationBackend {
    fn resolve<'a>(
        &'a self,
        _request: ferrum2_dns::ApplicationResolveRequest<'a>,
    ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ferrum2_dns::DnsError::Timeout)
        })
    }
}

async fn assert_registration_failure_rolls_back_setup<K: MethodKeyProvider>(
    keys: MethodKeyAdapter<K>,
    random: &impl SecureRandom,
) {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
    let session = manager
        .reserve_session(Instant::now())
        .expect("setup session");
    let budget = manager.buffer_budget();
    let fixed = (0..3)
        .map(|_| budget.reserve(MAX_UDP_WIRE_LEN).expect("fixed capacity"))
        .collect::<Vec<_>>();
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application socket");
    let upstream = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("upstream socket");
    upstream
        .connect((Ipv4Addr::LOCALHOST, 9))
        .await
        .expect("upstream connect");
    let application_address = application.local_addr().expect("application address");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let live_ids = Mutex::new(HashSet::new());
    assert!(register_udp_session(&keys, random, &live_ids).is_err());
    assert!(live_ids.lock().expect("live IDs").is_empty());
    assert_eq!(manager.session_count(), 1);
    assert_eq!(budget.reserved_bytes(), 3 * MAX_UDP_WIRE_LEN);

    drop((application, upstream, fixed, session));
    assert_eq!(manager.session_count(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot(), baseline);
    drop(
        UdpSocket::bind(application_address)
            .await
            .expect("application rebind"),
    );
    drop(
        UdpSocket::bind(upstream_address)
            .await
            .expect("upstream rebind"),
    );
}
