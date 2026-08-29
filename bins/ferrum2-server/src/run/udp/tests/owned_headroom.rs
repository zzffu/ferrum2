use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_crypto::{MonotonicInstant, SystemClock, SystemRandom};
use ferrum2_observability::Metrics;
use ferrum2_runtime::{
    DirectUdpPacketHandler, MAX_UDP_WIRE_DATAGRAM_BYTES, OwnerRegistry, UdpHeadroomLayout,
    UdpHeadroomLease, UdpRuntimeLimits, UdpSessionManager,
};
use ferrum2_shadowsocks::{
    UdpClientSession, UdpPacketScratch, UdpServer, udp_response_owned_headroom,
};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralCounter, StructuralHub};
use tokio::sync::{Notify, Semaphore};

use super::super::identity::UdpMappings;
use super::super::listener::ServerUdpResponseHandler;
use super::{ConcurrentSendListener, commit_lifecycle_generation};
use crate::run::test_support::aes_keys;

#[tokio::test]
async fn target_response_seals_and_sends_from_the_received_backing() {
    let keys = aes_keys();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client session");
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
    let mappings = Arc::new(UdpMappings::new(8));
    let clock = Arc::new(SystemClock::new());
    let mut scratch = UdpPacketScratch::new();
    let target = "127.0.0.1:5353".parse().expect("target");
    let peer = "127.0.0.1:49152".parse().expect("peer");
    let (_, handle) = commit_lifecycle_generation(
        &mut client,
        &protocol,
        &manager,
        &mappings,
        &clock,
        target,
        peer,
        b"request",
        MonotonicInstant::ZERO,
        &mut scratch,
    );

    let sent = Arc::new(Mutex::new(Vec::new()));
    let listener = Arc::new(ConcurrentSendListener {
        entered: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        entry_changed: Arc::new(Notify::new()),
        send_gate: Arc::new(Semaphore::new(1)),
        sent: Arc::clone(&sent),
    });
    #[cfg(feature = "structural-metrics")]
    let structural = StructuralHub::new();
    let handler = ServerUdpResponseHandler {
        listener,
        protocol: Arc::clone(&protocol),
        mappings,
        clock: Arc::clone(&clock),
        codec: None,
        metrics: Arc::new(Metrics::new()),
        #[cfg(feature = "structural-metrics")]
        structural: structural.local(),
    };
    let headroom = udp_response_owned_headroom();
    let layout = UdpHeadroomLayout::for_receive_bound(
        MAX_UDP_WIRE_DATAGRAM_BYTES,
        headroom.front(),
        headroom.rear(),
    )
    .expect("response layout");
    let mut lease =
        UdpHeadroomLease::reserve(&manager.buffer_budget(), layout).expect("response lease");
    let backing = lease.prepare_receive().expect("prepare target receive");
    let allocation = backing.as_ptr() as usize;
    let payload = vec![0x5a; 8_192];
    backing.extend_from_slice(&payload);
    let response = lease
        .finish_receive(
            ferrum2_core::TargetAddr::ip(target).expect("response target"),
            payload.len(),
        )
        .expect("received response");

    let mut returned = match handler
        .handle_target_response_headroom(handle, response)
        .await
    {
        Ok(returned) => returned,
        Err(_) => panic!("encode and send response"),
    };
    assert_eq!(
        returned
            .prepare_receive()
            .expect("recycled receive")
            .as_ptr() as usize,
        allocation
    );
    let sent = sent.lock().expect("captured send");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, peer);
    let pending = client
        .prepare_response_owned(clock.as_ref(), BytesMut::from(sent[0].1.as_slice()))
        .expect("client opens response");
    assert_eq!(pending.datagram().payload(), payload);
    let (_, commit) = pending.into_parts();
    client
        .commit_response(commit, MonotonicInstant::ZERO)
        .expect("response commits");
    drop(sent);

    #[cfg(feature = "structural-metrics")]
    {
        let snapshot = structural.snapshot();
        assert_eq!(
            snapshot.get(StructuralCounter::UdpPayloadToWireCopyBytes),
            0
        );
        assert_eq!(snapshot.get(StructuralCounter::UdpOwnedFastPathHits), 1);
        assert_eq!(snapshot.get(StructuralCounter::ResponseCodecLockSamples), 0);
    }

    drop(returned);
    drop(handler);
    assert!(manager.remove(handle));
    assert_eq!(manager.buffer_budget().reserved_bytes(), 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
}
