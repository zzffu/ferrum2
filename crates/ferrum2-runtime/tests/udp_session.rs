#![allow(dead_code, unused_imports)]

use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_net::UdpResolver;
use ferrum2_runtime::{
    AccountedDatagram, DEFAULT_UDP_IDLE_TIMEOUT, DEFAULT_UDP_MAX_BUFFERED_BYTES,
    DEFAULT_UDP_MAX_SESSIONS, DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSocket,
    DirectUdpSocketFactory, MAX_UDP_IDLE_TIMEOUT, MAX_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_SESSIONS,
    MAX_UDP_WIRE_DATAGRAM_BYTES, MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES,
    MIN_UDP_MAX_SESSIONS, OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture,
    ProcessRoot, ProcessSupervisor, UDP_SESSION_QUEUE_DEPTH, UdpCommitError, UdpDirection,
    UdpLimitError, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager,
};
use tokio::sync::Notify;
use tokio::time::Instant;

mod udp_support;
use udp_support::*;

#[tokio::test(start_paused = true)]
async fn reservation_queue_and_generation_table_is_single_charge_and_fail_closed() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let now = Instant::now();
    let handle = committed_session(&manager, now, b"one");
    let mut cancellation = manager.cancellation(handle).expect("live cancellation");
    assert_eq!(
        manager.idle_deadline(handle),
        Ok(now + MIN_UDP_IDLE_TIMEOUT)
    );
    assert!(!*cancellation.borrow());

    let rejected = manager
        .reserve_datagram(handle, UdpDirection::ToTarget, 16)
        .expect("capacity precedes protocol commit");
    let result = rejected.commit_with(ip_datagram_with_capacity(b"rejected", 16), now, || {
        assert_eq!(registry.snapshot().udp_buffered_bytes, 3 + 16);
        Err("protocol rejection")
    });
    assert!(matches!(result, Err(UdpCommitError::Protocol(_))));
    assert_eq!(registry.snapshot().udp_queued_datagrams, 1);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 3);

    for payload in [b"two".as_slice(), b"three", b"four"] {
        let reservation = manager
            .reserve_datagram(handle, UdpDirection::ToTarget, 16)
            .expect("queue capacity");
        let mut owned = BytesMut::with_capacity(16);
        owned.extend_from_slice(payload);
        reservation
            .commit(
                Datagram::new(
                    TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("target"),
                    owned,
                    16,
                )
                .expect("bounded"),
                now,
            )
            .expect("post-validation commit");
    }
    assert_eq!(
        manager
            .reserve_datagram(handle, UdpDirection::ToTarget, 16)
            .unwrap_err(),
        UdpRuntimeError::QueueFull
    );
    assert_eq!(
        registry.snapshot().udp_queued_datagrams,
        UDP_SESSION_QUEUE_DEPTH
    );
    assert_eq!(registry.snapshot().udp_buffered_bytes, 3 + 16 * 3);

    let moved = manager
        .pop(handle, UdpDirection::ToTarget)
        .expect("live generation")
        .expect("queued datagram");
    assert_eq!(moved.allocated_capacity(), 3);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 3 + 16 * 3);
    drop(moved);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 16 * 3);

    for _ in 0..UDP_SESSION_QUEUE_DEPTH {
        manager
            .reserve_datagram(handle, UdpDirection::ToClient, 4)
            .expect("independent response queue")
            .commit(ip_datagram_with_capacity(b"r", 4), now)
            .expect("response queue commit");
    }
    assert!(matches!(
        manager.reserve_datagram(handle, UdpDirection::ToClient, 4),
        Err(UdpRuntimeError::QueueFull)
    ));
    assert_eq!(registry.snapshot().udp_queued_datagrams, 7);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 16 * 3 + 4 * 4);

    assert!(manager.remove(handle));
    cancellation.changed().await.expect("generation wake");
    assert!(*cancellation.borrow());
    assert_eq!(
        manager.idle_deadline(handle),
        Err(UdpRuntimeError::Cancelled)
    );
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);

    let recreated = committed_session(&manager, now, b"new");
    assert!(matches!(
        manager.reserve_datagram(handle, UdpDirection::ToTarget, 1),
        Err(UdpRuntimeError::Cancelled)
    ));
    manager.remove(recreated);
}

#[tokio::test]
async fn global_byte_permits_use_exact_capacity_and_release_after_moves() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(2), registry.clone());
    let (first_socket, _) = socket_fixture(Duration::ZERO, []);
    let (second_socket, _) = socket_fixture(Duration::ZERO, []);
    let first = shared_runtime(manager.clone(), &registry, first_socket);
    let mut second = shared_runtime(manager, &registry, second_socket);
    let budget = first.sessions().buffer_budget();
    let mut reservations = Vec::new();
    for _ in 0..16 {
        reservations.push(budget.reserve(65_507).expect("within one MiB budget"));
    }
    assert_eq!(budget.reserved_bytes(), 1_048_112);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 1_048_112);
    let before_failure = registry.snapshot();
    assert_eq!(
        second
            .reserve_session(Instant::now(), 465, (), selection_destination())
            .await
            .unwrap_err(),
        UdpRuntimeError::BufferLimit
    );
    assert_eq!(registry.snapshot(), before_failure);

    let moved = reservations.pop().expect("reservation");
    assert_eq!(budget.reserved_bytes(), 1_048_112);
    drop(moved);
    assert_eq!(budget.reserved_bytes(), 982_605);
    drop(
        second
            .reserve_session(Instant::now(), 465, (), selection_destination())
            .await
            .expect("shared bytes returned"),
    );
    drop(reservations);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    first.shutdown(Duration::ZERO).await;
    second.shutdown(Duration::ZERO).await;
}

#[tokio::test(start_paused = true)]
async fn full_admission_purges_only_the_deterministic_oldest_expired_session() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(2), registry.clone());
    let start = Instant::now();
    let oldest = committed_session(&manager, start, b"oldest");
    tokio::time::advance(Duration::from_secs(1)).await;
    let newer = committed_session(&manager, Instant::now(), b"newer");

    tokio::time::advance(Duration::from_secs(58)).await;
    assert_eq!(
        manager.reserve_session(Instant::now()).unwrap_err(),
        UdpRuntimeError::SessionLimit
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let replacement = manager
        .reserve_session(Instant::now())
        .expect("oldest is exactly idle-expired");
    assert!(matches!(
        manager.reserve_datagram(oldest, UdpDirection::ToTarget, 0),
        Err(UdpRuntimeError::Cancelled)
    ));
    assert!(
        manager
            .reserve_datagram(newer, UdpDirection::ToTarget, 0)
            .is_ok()
    );
    drop(replacement);
    manager.remove(newer);
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
}

#[test]
fn concurrent_capacity_one_admission_has_exactly_one_owner() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let barrier = Arc::new(Barrier::new(17));
    let now = Instant::now();
    let mut threads = Vec::new();
    for _ in 0..16 {
        let manager = manager.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            manager.reserve_session(now)
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("admission thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UdpRuntimeError::SessionLimit)))
            .count(),
        15
    );
    drop(results);
    assert_eq!(registry.snapshot().udp_sessions, 0);
}
