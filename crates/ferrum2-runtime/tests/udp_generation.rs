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

#[test]
fn batch_liveness_filter_is_read_only_and_capacity_independent() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(5), registry.clone());
    let now = Instant::now();

    let full = committed_session(&manager, now, b"f");
    for _ in 1..UDP_SESSION_QUEUE_DEPTH {
        manager
            .reserve_datagram(full, UdpDirection::ToTarget, 4)
            .expect("queue capacity")
            .commit(ip_datagram_with_capacity(b"full", 4), now)
            .expect("fill queue");
    }
    assert_eq!(
        manager
            .reserve_datagram(full, UdpDirection::ToTarget, 0)
            .unwrap_err(),
        UdpRuntimeError::QueueFull
    );

    let pending = committed_session(&manager, now, b"pending");
    let held_pending = manager
        .reserve_datagram(pending, UdpDirection::ToTarget, 11)
        .expect("pending capacity");
    let provisional = manager.reserve_session(now).expect("provisional capacity");
    let provisional_handle = provisional.handle();

    let stale = committed_session(&manager, now, b"stale");
    assert!(manager.remove(stale));
    let replacement = committed_session(&manager, now, b"replacement");
    let missing = committed_session(&manager, now, b"missing");
    assert!(manager.remove(missing));

    let full_cancellation = manager.cancellation(full).expect("live cancellation");
    let provisional_cancellation = manager
        .cancellation(provisional_handle)
        .expect("provisional cancellation");
    let before_snapshot = registry.snapshot();
    let before_budget = manager.buffer_budget().reserved_bytes();
    let mut candidates = vec![
        missing,
        full,
        provisional_handle,
        stale,
        pending,
        replacement,
    ];

    manager.retain_live_sessions(&mut candidates);

    assert_eq!(candidates, [full, pending, replacement]);
    assert_eq!(registry.snapshot(), before_snapshot);
    assert_eq!(manager.buffer_budget().reserved_bytes(), before_budget);
    assert!(!full_cancellation.has_changed().expect("live cancellation"));
    assert!(
        !provisional_cancellation
            .has_changed()
            .expect("provisional cancellation")
    );

    let second_pending = manager
        .reserve_datagram(pending, UdpDirection::ToTarget, 0)
        .expect("second pending slot");
    let third_pending = manager
        .reserve_datagram(pending, UdpDirection::ToTarget, 0)
        .expect("third pending slot");
    assert_eq!(
        manager
            .reserve_datagram(pending, UdpDirection::ToTarget, 0)
            .unwrap_err(),
        UdpRuntimeError::QueueFull,
        "the liveness query must not release the held pending slot"
    );

    drop(third_pending);
    drop(second_pending);
    drop(held_pending);
    drop(provisional);
    assert!(manager.remove(full));
    assert!(manager.remove(pending));
    assert!(manager.remove(replacement));
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(manager.buffer_budget().reserved_bytes(), 0);
}

#[tokio::test]
async fn batch_liveness_filter_rejects_shutdown_without_side_effects() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let handle = committed_session(&manager, Instant::now(), b"shutdown");
    let mut cancellation = manager.cancellation(handle).expect("live cancellation");
    manager.signal_all();
    cancellation.changed().await.expect("shutdown signal");

    let before_snapshot = registry.snapshot();
    let before_budget = manager.buffer_budget().reserved_bytes();
    let mut candidates = vec![handle];
    manager.retain_live_sessions(&mut candidates);

    assert!(candidates.is_empty());
    assert_eq!(registry.snapshot(), before_snapshot);
    assert_eq!(manager.buffer_budget().reserved_bytes(), before_budget);
    assert!(!cancellation.has_changed().expect("shutdown cancellation"));

    manager.cancel_all();
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(manager.buffer_budget().reserved_bytes(), 0);
}

#[tokio::test]
async fn network_reset_cancels_existing_sessions_without_closing_admission() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let mut removals = manager.subscribe_removals();
    let first = committed_session(&manager, Instant::now(), b"first");
    let mut cancellation = manager.cancellation(first).expect("live cancellation");

    assert_eq!(manager.reset_all(), 1);
    cancellation.changed().await.expect("network reset signal");
    assert!(*cancellation.borrow());
    assert_eq!(removals.try_recv().expect("network reset removal"), first);
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(manager.buffer_budget().reserved_bytes(), 0);

    let replacement = committed_session(&manager, Instant::now(), b"replacement");
    assert_ne!(replacement, first);

    manager.cancel_all();
    assert_eq!(manager.reset_all(), 0, "reset must not reopen shutdown");
    assert_eq!(
        manager.reserve_session(Instant::now()).unwrap_err(),
        UdpRuntimeError::Cancelled
    );
}

#[test]
fn removal_subscription_reports_each_exact_generation() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(2), registry.clone());
    let mut removals = manager.subscribe_removals();
    let first = committed_session(&manager, Instant::now(), b"first");
    let second = committed_session(&manager, Instant::now(), b"second");

    assert!(manager.remove(first));
    assert_eq!(removals.try_recv().expect("first removal"), first);
    manager.cancel_all();
    assert_eq!(removals.try_recv().expect("shutdown removal"), second);
    assert!(matches!(
        removals.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[test]
fn lagged_removal_subscription_recovers_with_one_batch_liveness_pass() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let mut removals = manager.subscribe_removals();
    let first = committed_session(&manager, Instant::now(), b"first");
    assert!(manager.remove(first));
    let second = committed_session(&manager, Instant::now(), b"second");
    assert!(manager.remove(second));

    assert!(matches!(
        removals.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(1))
    ));
    let live = committed_session(&manager, Instant::now(), b"live");
    let mut indexed = vec![first, second, live];
    manager.retain_live_sessions(&mut indexed);
    assert_eq!(indexed, [live]);

    assert!(manager.remove(live));
    assert_eq!(registry.snapshot().udp_sessions, 0);
}
