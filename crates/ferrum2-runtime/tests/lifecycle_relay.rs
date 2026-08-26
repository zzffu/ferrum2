#![allow(dead_code, unused_imports)]

use std::collections::VecDeque;
use std::future::{pending, ready};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, DEFAULT_HANDSHAKE_TIMEOUT, DeadlineError, OwnerRegistry,
    PreparedProcessRoot, ProcessCause, ProcessCleanupFailure, ProcessExitKind, ProcessFuture,
    ProcessRoot, ProcessRootEventPhase, ProcessRootExit, ProcessRootExitCategory, ProcessState,
    ProcessSupervisor, RelayFailure, RelayRunError, RelayStats, SupervisorError,
    relay_bidirectional_with_idle_timeout, relay_lifecycle, with_deadline,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

const REQUIRED_ROOT_COUNT: usize = 3;

mod lifecycle_support;
use lifecycle_support::*;

#[tokio::test(start_paused = true)]
async fn handshake_timeout_uses_the_five_second_monotonic_deadline() {
    assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(5));
    let task = tokio::spawn(with_deadline(
        DEFAULT_HANDSHAKE_TIMEOUT,
        pending::<Result<(), io::Error>>(),
    ));
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(5)).await;

    assert!(matches!(
        task.await.expect("deadline task"),
        Err(DeadlineError::Timeout)
    ));
}

#[tokio::test(start_paused = true)]
async fn idle_relay_times_out_without_forwarded_bytes() {
    let (_application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, _target) = tokio::io::duplex(64);
    let relay = tokio::spawn(async move {
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(5)).await;

    assert_eq!(
        relay.await.expect("relay task"),
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            stats: RelayStats {
                inbound_to_outbound: 0,
                outbound_to_inbound: 0,
            },
        })
    );
}

#[tokio::test]
async fn partial_write_then_error_retains_the_exact_completed_prefix() {
    let mut inbound = Endpoint {
        reader: BytesReader::new(b"completed-prefix-and-unwritten-suffix"),
        writer: SinkWriter,
    };
    let mut outbound = Endpoint {
        reader: PendingReader,
        writer: PartialThenErrorWriter {
            remaining_before_error: 9,
        },
    };

    let failure =
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(60))
            .await
            .expect_err("second write fails");

    assert_eq!(
        failure,
        RelayFailure {
            kind: RelayRunError::Io,
            stats: RelayStats {
                inbound_to_outbound: 9,
                outbound_to_inbound: 0,
            },
        }
    );
    assert!(!format!("{failure:?}").contains("scripted write failure"));
    assert!(std::error::Error::source(&failure).is_none());
}

#[tokio::test]
async fn asymmetric_bidirectional_failure_keeps_direction_mapping() {
    let gate = Arc::new(WriteGate::new());
    let mut inbound = Endpoint {
        reader: BytesReader::new(b"abc"),
        writer: GatedPartialThenErrorWriter {
            gate: Arc::clone(&gate),
            remaining_before_error: 5,
        },
    };
    let mut outbound = Endpoint {
        reader: BytesReader::new(b"reverse-data"),
        writer: GateOpeningWriter { gate },
    };

    let failure =
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(60))
            .await
            .expect_err("reverse direction fails after both directions progress");

    assert_eq!(
        failure,
        RelayFailure {
            kind: RelayRunError::Io,
            stats: RelayStats {
                inbound_to_outbound: 3,
                outbound_to_inbound: 5,
            },
        }
    );
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_after_progress_retains_completed_stats() {
    let (mut application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, mut target) = tokio::io::duplex(64);
    let relay = tokio::spawn(async move {
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });
    tokio::task::yield_now().await;

    application
        .write_all(b"abc")
        .await
        .expect("write application bytes");
    let mut forwarded = [0_u8; 3];
    target
        .read_exact(&mut forwarded)
        .await
        .expect("read forwarded bytes");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;

    assert_eq!(
        relay.await.expect("relay task"),
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            stats: RelayStats {
                inbound_to_outbound: 3,
                outbound_to_inbound: 0,
            },
        })
    );
}

#[tokio::test(start_paused = true)]
async fn read_ahead_into_a_pending_writer_counts_zero_and_does_not_reset_idle() {
    let observed = Arc::new(AtomicUsize::new(0));
    let observed_by_reader = Arc::clone(&observed);
    let read_gate = Arc::new(WriteGate::new());
    let read_gate_for_relay = Arc::clone(&read_gate);
    let relay = tokio::spawn(async move {
        let mut inbound = Endpoint {
            reader: CountingBytesReader {
                bytes: b"read-but-not-written",
                offset: 0,
                observed: observed_by_reader,
                gate: read_gate_for_relay,
            },
            writer: SinkWriter,
        };
        let mut outbound = Endpoint {
            reader: PendingReader,
            writer: PendingWriter,
        };
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(observed.load(Ordering::SeqCst), 0);
    assert!(!relay.is_finished(), "idle interval has one second left");

    read_gate.open();
    for _ in 0..100 {
        if observed.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        observed.load(Ordering::SeqCst),
        b"read-but-not-written".len()
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        relay.is_finished(),
        "successful reads must not reset the armed idle deadline"
    );

    assert_eq!(
        relay.await.expect("relay task"),
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            stats: RelayStats {
                inbound_to_outbound: 0,
                outbound_to_inbound: 0,
            },
        })
    );
}

#[tokio::test]
async fn write_zero_is_io_failure_with_zero_completed_stats() {
    let mut inbound = Endpoint {
        reader: BytesReader::new(b"not-accepted"),
        writer: SinkWriter,
    };
    let mut outbound = Endpoint {
        reader: PendingReader,
        writer: WriteZeroWriter,
    };

    let failure =
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(60))
            .await
            .expect_err("write zero is an I/O failure");

    assert_eq!(
        failure,
        RelayFailure {
            kind: RelayRunError::Io,
            stats: RelayStats {
                inbound_to_outbound: 0,
                outbound_to_inbound: 0,
            },
        }
    );
}

#[tokio::test(start_paused = true)]
async fn relay_lifecycle_cancel_retains_asymmetric_stats_and_returns_buffers() {
    let (mut application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, mut target) = tokio::io::duplex(64);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let registry_for_relay = registry.clone();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(async move {
        relay_lifecycle(
            &mut inbound,
            &mut outbound,
            Duration::from_secs(5),
            &registry_for_relay,
            async move {
                let _ = cancel_rx.await;
            },
        )
        .await
    });
    tokio::task::yield_now().await;
    assert_eq!(registry.snapshot().owned_buffers, 2);

    tokio::time::advance(Duration::from_secs(4)).await;
    application.write_all(b"x").await.expect("write one byte");
    let mut forwarded = [0_u8; 1];
    target
        .read_exact(&mut forwarded)
        .await
        .expect("byte is forwarded");
    assert_eq!(forwarded, *b"x");
    target.write_all(b"yz").await.expect("write reverse bytes");
    let mut reverse = [0_u8; 2];
    application
        .read_exact(&mut reverse)
        .await
        .expect("reverse bytes are forwarded");
    assert_eq!(reverse, *b"yz");

    tokio::time::advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(
        !relay.is_finished(),
        "forwarded byte reset the idle deadline"
    );

    cancel_tx
        .send(())
        .expect("request cooperative cancellation");
    assert_eq!(
        relay.await.expect("relay owner"),
        Err(RelayFailure {
            kind: RelayRunError::Cancelled,
            stats: RelayStats {
                inbound_to_outbound: 1,
                outbound_to_inbound: 2,
            },
        })
    );
    assert_eq!(registry.snapshot(), baseline);
}
