use std::time::Duration;

use ferrum2_runtime::{
    DirectUdpRuntime, MIN_UDP_IDLE_TIMEOUT, OwnerRegistry, UdpDirection, UdpSessionManager,
};
use tokio::time::Instant;

mod udp_support;
use udp_support::{
    RecordingHandler, committed_session, empty_resolver, ip_datagram, limits, scripted_factory,
    selection_destination, socket_fixture, wait_for_zero_udp_owners,
};

#[derive(Clone, Copy)]
enum CommitKind {
    Queued,
    Immediate,
}

#[tokio::test(start_paused = true)]
async fn commits_in_capture_reverse_order_do_not_shorten_the_idle_deadline() {
    for kind in [CommitKind::Queued, CommitKind::Immediate] {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let manager = UdpSessionManager::new(limits(1), registry.clone());
        let captured_first = Instant::now();
        let handle = committed_session(&manager, captured_first, b"x");
        tokio::time::advance(Duration::from_secs(20)).await;
        let captured_last = Instant::now();
        // Two callers can capture time before contending for the commit lock.
        // The later observation may commit first.
        for captured in [captured_last, captured_first] {
            let reservation = manager
                .reserve_datagram(handle, UdpDirection::ToTarget, 1)
                .expect("reserved request");
            match kind {
                CommitKind::Queued => reservation
                    .commit(ip_datagram(b"x"), captured)
                    .expect("queued commit"),
                CommitKind::Immediate => {
                    drop(
                        reservation
                            .commit_immediate(ip_datagram(b"x"), captured)
                            .expect("immediate commit"),
                    );
                }
            }
        }
        let observed_deadline = manager.idle_deadline(handle);
        assert!(manager.remove(handle));
        drop(manager);
        assert_eq!(registry.snapshot(), baseline);
        assert_eq!(observed_deadline, Ok(captured_last + MIN_UDP_IDLE_TIMEOUT));
    }
}

#[tokio::test(start_paused = true)]
async fn activity_after_timer_registration_expires_at_the_refreshed_deadline() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(1),
        empty_resolver(),
        scripted_factory(socket),
        RecordingHandler::default(),
        registry.clone(),
    );
    let started = Instant::now();
    let admission = runtime
        .reserve_session(started, 1, (), selection_destination())
        .await
        .expect("admission");
    let handle = runtime
        .commit_session(admission, ip_datagram(b"x"), started)
        .expect("initial request");
    tokio::task::yield_now().await;
    tokio::time::advance(MIN_UDP_IDLE_TIMEOUT - Duration::from_secs(1)).await;
    let refreshed = Instant::now();
    runtime
        .reserve_datagram(handle, 1)
        .expect("request reservation")
        .commit(ip_datagram(b"y"), refreshed)
        .expect("refresh activity");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(runtime.sessions().session_count(), 1);
    tokio::time::advance(MIN_UDP_IDLE_TIMEOUT - Duration::from_secs(2)).await;
    wait_for_zero_udp_owners(&registry).await;
    assert_eq!(runtime.shutdown(Duration::ZERO).await, 0);
    assert_eq!(registry.snapshot(), baseline);
}
