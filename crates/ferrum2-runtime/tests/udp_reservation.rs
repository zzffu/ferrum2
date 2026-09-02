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
fn immediate_commit_preserves_budget_and_skips_queue_ownership() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let now = Instant::now();
    let session = manager.reserve_session(now).expect("session capacity");
    let reservation = session
        .reserve_datagram(UdpDirection::ToTarget, 7)
        .expect("datagram capacity");

    let (handle, datagram) = session
        .commit_immediate(reservation, ip_datagram(b"request"), now)
        .expect("immediate commit");

    let active = registry.snapshot();
    assert_eq!(active.udp_sessions, 1);
    assert_eq!(active.udp_queued_datagrams, 0);
    assert_eq!(active.udp_buffered_bytes, 7);
    assert!(
        manager
            .pop(handle, UdpDirection::ToTarget)
            .expect("live generation")
            .is_none()
    );
    assert_eq!(datagram.datagram().payload(), b"request");

    drop(datagram);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    assert!(manager.remove(handle));
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[test]
fn borrowed_immediate_commit_advances_activity_without_buffer_ownership() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let now = Instant::now();
    let session = manager.reserve_session(now).expect("session capacity");
    let reservation = session
        .reserve_datagram(UdpDirection::ToTarget, 0)
        .expect("borrowed datagram admission");
    let handle = session
        .commit_borrowed_immediate(reservation, now)
        .expect("borrowed first datagram");

    assert_eq!(registry.snapshot().udp_sessions, 1);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    assert!(
        manager
            .pop(handle, UdpDirection::ToTarget)
            .expect("live generation")
            .is_none()
    );

    let later = now + Duration::from_secs(1);
    manager
        .reserve_datagram(handle, UdpDirection::ToTarget, 0)
        .expect("established borrowed admission")
        .commit_borrowed_immediate(later)
        .expect("established borrowed commit");
    assert_eq!(
        manager.idle_deadline(handle),
        Ok(later + MIN_UDP_IDLE_TIMEOUT)
    );
    assert!(manager.remove(handle));

    let rejected = manager
        .reserve_session(now)
        .expect("replacement session capacity");
    let owned_reservation = rejected
        .reserve_datagram(UdpDirection::ToTarget, 1)
        .expect("owned capacity");
    assert_eq!(
        rejected.commit_borrowed_immediate(owned_reservation, now),
        Err(UdpRuntimeError::Bounds)
    );
    assert_eq!(manager.session_count(), 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
}

#[test]
fn immediate_protocol_rejection_rolls_back_every_provisional_owner() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let now = Instant::now();
    let session = manager.reserve_session(now).expect("session capacity");
    let reservation = session
        .reserve_datagram(UdpDirection::ToTarget, 7)
        .expect("datagram capacity");

    let result = session.commit_immediate_with(reservation, ip_datagram(b"request"), now, || {
        Err("protocol rejection")
    });

    assert!(matches!(result, Err(UdpCommitError::Protocol(_))));
    assert_eq!(manager.session_count(), 0);
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
}

#[test]
fn pending_session_rejects_same_handle_reservation_from_another_manager() {
    let registry = OwnerRegistry::new();
    let first = UdpSessionManager::new(limits(1), registry.clone());
    let second = UdpSessionManager::new(limits(1), registry.clone());
    let now = Instant::now();

    let first_session = first.reserve_session(now).expect("first session");
    let second_session = second.reserve_session(now).expect("second session");
    assert_eq!(first_session.handle(), second_session.handle());
    let foreign = second_session
        .reserve_datagram(UdpDirection::ToTarget, 7)
        .expect("foreign reservation");
    assert!(matches!(
        first_session.commit_immediate(foreign, ip_datagram(b"foreign"), now),
        Err(UdpRuntimeError::Cancelled)
    ));
    assert_eq!(first.session_count(), 0);
    assert_eq!(second.session_count(), 1);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    drop(second_session);

    let first_session = first.reserve_session(now).expect("next first session");
    let second_session = second.reserve_session(now).expect("next second session");
    assert_eq!(first_session.handle(), second_session.handle());
    let foreign = second_session
        .reserve_datagram(UdpDirection::ToTarget, 7)
        .expect("next foreign reservation");
    assert!(matches!(
        first_session.commit(foreign, ip_datagram(b"foreign"), now),
        Err(UdpRuntimeError::Cancelled)
    ));
    assert_eq!(first.session_count(), 0);
    assert_eq!(second.session_count(), 1);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    drop(second_session);

    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[test]
fn validated_limits_freeze_defaults_and_inclusive_ranges() {
    let defaults = UdpRuntimeLimits::default();
    let actual = (
        defaults.max_sessions(),
        defaults.max_buffered_bytes(),
        defaults.idle_timeout(),
    );
    let expected = (
        DEFAULT_UDP_MAX_SESSIONS,
        DEFAULT_UDP_MAX_BUFFERED_BYTES,
        DEFAULT_UDP_IDLE_TIMEOUT,
    );
    assert_eq!(actual, expected);

    let valid = [
        (
            MIN_UDP_MAX_SESSIONS,
            MIN_UDP_MAX_BUFFERED_BYTES,
            MIN_UDP_IDLE_TIMEOUT,
        ),
        (
            MAX_UDP_MAX_SESSIONS,
            MAX_UDP_MAX_BUFFERED_BYTES,
            MAX_UDP_IDLE_TIMEOUT,
        ),
    ];
    for (sessions, bytes, idle) in valid {
        assert!(UdpRuntimeLimits::new(sessions, bytes, idle).is_ok());
    }
    let invalid = [
        (
            "sessions",
            0,
            MIN_UDP_MAX_BUFFERED_BYTES,
            MIN_UDP_IDLE_TIMEOUT,
            UdpLimitError::Sessions,
        ),
        (
            "bytes",
            MIN_UDP_MAX_SESSIONS,
            MIN_UDP_MAX_BUFFERED_BYTES - 1,
            MIN_UDP_IDLE_TIMEOUT,
            UdpLimitError::BufferedBytes,
        ),
        (
            "idle",
            MIN_UDP_MAX_SESSIONS,
            MIN_UDP_MAX_BUFFERED_BYTES,
            MIN_UDP_IDLE_TIMEOUT - Duration::from_millis(1),
            UdpLimitError::IdleTimeout,
        ),
    ];
    for (label, sessions, bytes, idle, expected) in invalid {
        let actual = UdpRuntimeLimits::new(sessions, bytes, idle);
        assert_eq!(actual, Err(expected), "{label}");
    }
}
