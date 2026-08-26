use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ferrum2_core::{ConnectError, ConnectErrorKind, LocalEndpoint, Outbound};
use ferrum2_runtime::RelayRunError;
use tokio::io::AsyncWrite;
use tokio::sync::Notify;

use super::*;
use crate::run::test_support::*;

struct RecordingStream {
    bytes: Arc<Mutex<Vec<u8>>>,
    write_calls: Arc<AtomicUsize>,
    max_write: usize,
    fail_after: Option<usize>,
    stall_after: Option<usize>,
    endpoint: SocketAddrV4,
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let call = self.write_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_after == Some(call) {
            return Poll::Ready(Err(io::Error::other("sentinel write failure")));
        }
        if self.stall_after.is_some_and(|after| call >= after) {
            return Poll::Pending;
        }
        let written = source.len().min(self.max_write);
        self.bytes
            .lock()
            .expect("recording bytes")
            .extend_from_slice(&source[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl LocalEndpoint for RecordingStream {
    fn local_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.endpoint)
    }
}

struct ControlledOutbound {
    gate: Arc<Notify>,
    stream: Mutex<Option<RecordingStream>>,
    failure: Option<ConnectErrorKind>,
    calls: Arc<AtomicUsize>,
}

impl Outbound for ControlledOutbound {
    type Stream = RecordingStream;
    type Error = ConnectError;

    async fn open(&self, _target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.gate.notified().await;
        match self.failure {
            Some(kind) => Err(ConnectError::new(kind)),
            None => Ok(self
                .stream
                .lock()
                .expect("recording stream")
                .take()
                .expect("one open")),
        }
    }
}

type ControlledParts = (
    Arc<ControlledOutbound>,
    Arc<Notify>,
    Arc<Mutex<Vec<u8>>>,
    Arc<AtomicUsize>,
);

fn controlled_outbound(
    max_write: usize,
    fail_after: Option<usize>,
    stall_after: Option<usize>,
    failure: Option<ConnectErrorKind>,
) -> ControlledParts {
    let gate = Arc::new(Notify::new());
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let write_calls = Arc::new(AtomicUsize::new(0));
    let outbound = Arc::new(ControlledOutbound {
        gate: Arc::clone(&gate),
        stream: Mutex::new(Some(RecordingStream {
            bytes: Arc::clone(&bytes),
            write_calls: Arc::clone(&write_calls),
            max_write,
            fail_after,
            stall_after,
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003),
        })),
        failure,
        calls: Arc::new(AtomicUsize::new(0)),
    });
    (outbound, gate, bytes, write_calls)
}

#[tokio::test]
async fn adapter_contract_connect_failure_never_reports_opened_stream() {
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
    let (outbound, gate, bytes, write_calls) =
        controlled_outbound(2, None, None, Some(ConnectErrorKind::ConnectionRefused));
    let task_outbound = Arc::clone(&outbound);
    let task_target = target.clone();
    let task = tokio::spawn(async move {
        open_and_prefix(
            task_outbound.as_ref(),
            &task_target,
            b"never",
            Duration::from_secs(5),
            std::future::pending::<()>(),
        )
        .await
    });
    tokio::task::yield_now().await;
    assert!(bytes.lock().expect("recording bytes").is_empty());
    gate.notify_one();
    assert!(matches!(
        task.await.expect("connect task"),
        Err(DirectFlowError::Open(error))
            if error.kind() == ConnectErrorKind::ConnectionRefused
    ));
    assert_eq!(write_calls.load(Ordering::SeqCst), 0);
}

struct GatedPrefixWriter {
    ready: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    waker: Arc<Mutex<Option<Waker>>>,
    max_write: usize,
    fail_after: Option<usize>,
    zero_after: Option<usize>,
}

impl AsyncWrite for GatedPrefixWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_after == Some(call) {
            return Poll::Ready(Err(io::Error::other("prefix sentinel")));
        }
        if self.zero_after == Some(call) {
            return Poll::Ready(Ok(0));
        }
        if !self.ready.swap(false, Ordering::SeqCst) {
            *self.waker.lock().expect("prefix waker") = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(source.len().min(self.max_write)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn server_deadline_test_config(idle_timeout_ms: Option<u64>) -> (PathBuf, ValidatedServerConfig) {
    let mut runtime = String::from("[runtime]\n");
    if let Some(value) = idle_timeout_ms {
        runtime.push_str(&format!("idle_timeout_ms = {value}\n"));
    }
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"proxy\"\n\
         listen = \"127.0.0.1:42001\"\n\
         outbound = \"direct\"\n\
         [[outbounds]]\n\
         tag = \"direct\"\n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         {runtime}"
    );
    server_test_config_source("deadline", &source)
}

async fn assert_prefix_pending<F>(future: &mut Pin<Box<F>>)
where
    F: std::future::Future,
{
    tokio::select! {
        biased;
        _ = future.as_mut() => panic!("prefix completed before its controlled deadline"),
        _ = tokio::task::yield_now() => {}
    }
}

fn release_prefix_writer(ready: &AtomicBool, waker: &Mutex<Option<Waker>>) {
    ready.store(true, Ordering::SeqCst);
    if let Some(waker) = waker.lock().expect("prefix waker").take() {
        waker.wake();
    }
}

#[tokio::test(start_paused = true)]
async fn lifecycle_composition_contract_default_prefix_idle_timeout_is_exact() {
    let (path, config) = server_deadline_test_config(None);
    assert_eq!(config.runtime.idle_timeout, Duration::from_secs(300));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut writer = GatedPrefixWriter {
        ready: Arc::new(AtomicBool::new(false)),
        calls: Arc::clone(&calls),
        waker: Arc::new(Mutex::new(None)),
        max_write: 2,
        fail_after: None,
        zero_after: None,
    };
    let mut prefix = Box::pin(forward_initial_payload(
        &mut writer,
        b"four",
        config.runtime.idle_timeout,
        std::future::pending::<()>(),
    ));

    assert_prefix_pending(&mut prefix).await;
    tokio::time::advance(Duration::from_millis(299_999)).await;
    assert_prefix_pending(&mut prefix).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        prefix.await,
        Err(PrefixFailure {
            kind: RelayRunError::IdleTimeout,
            bytes: 0,
        })
    );
    assert!(calls.load(Ordering::SeqCst) >= 1);
    std::fs::remove_file(path).expect("remove server deadline config");
}

#[tokio::test(start_paused = true)]
async fn lifecycle_composition_contract_non_default_prefix_progress_resets_fresh_deadline() {
    let (path, config) = server_deadline_test_config(Some(3_700));
    assert_eq!(config.runtime.idle_timeout, Duration::from_millis(3_700));
    let ready = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let waker = Arc::new(Mutex::new(None));
    let mut writer = GatedPrefixWriter {
        ready: Arc::clone(&ready),
        calls: Arc::clone(&calls),
        waker: Arc::clone(&waker),
        max_write: 2,
        fail_after: None,
        zero_after: None,
    };
    let mut prefix = Box::pin(forward_initial_payload(
        &mut writer,
        b"four",
        config.runtime.idle_timeout,
        std::future::pending::<()>(),
    ));

    assert_prefix_pending(&mut prefix).await;
    tokio::time::advance(Duration::from_millis(2_300)).await;
    assert_prefix_pending(&mut prefix).await;
    release_prefix_writer(&ready, &waker);
    assert_prefix_pending(&mut prefix).await;
    assert!(calls.load(Ordering::SeqCst) >= 2);
    tokio::time::advance(Duration::from_millis(3_699)).await;
    assert_prefix_pending(&mut prefix).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        prefix.await,
        Err(PrefixFailure {
            kind: RelayRunError::IdleTimeout,
            bytes: 2,
        })
    );
    std::fs::remove_file(path).expect("remove server deadline config");
}

#[tokio::test]
async fn lifecycle_composition_contract_prefix_cancel_retains_partial_count() {
    let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
    let (outbound, _gate, bytes, writes) = controlled_outbound(2, None, None, None);
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
    let mut prefix = Box::pin(open_and_prefix(
        outbound.as_ref(),
        &target,
        b"four",
        std::time::Duration::from_secs(5),
        cancelled,
    ));
    tokio::select! {
        biased;
        _ = &mut prefix => panic!("prefix ended before cancellation"),
        _ = tokio::task::yield_now() => {}
    }
    assert_eq!(outbound.calls.load(Ordering::SeqCst), 1);
    cancel.send(()).expect("cancel prefix");
    assert!(matches!(
        prefix.await,
        Err(DirectFlowError::CancelledBeforeOpen)
    ));
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert!(bytes.lock().expect("recorded prefix").is_empty());

    let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
    let (outbound, gate, bytes, _) = controlled_outbound(2, None, Some(1), None);
    gate.notify_one();
    let mut prefix = Box::pin(open_and_prefix(
        outbound.as_ref(),
        &target,
        b"four",
        std::time::Duration::from_secs(5),
        cancelled,
    ));
    tokio::select! {
        biased;
        _ = &mut prefix => panic!("prefix ended before cancellation"),
        _ = tokio::task::yield_now() => {}
    }
    cancel.send(()).expect("cancel prefix");
    assert!(matches!(
        prefix.await,
        Err(DirectFlowError::Prefix(PrefixFailure {
            kind: RelayRunError::Cancelled,
            bytes: 2,
        }))
    ));
    assert_eq!(bytes.lock().expect("recorded prefix").as_slice(), b"fo");
}

#[tokio::test]
async fn lifecycle_composition_contract_prefix_write_zero_and_error_retain_counts() {
    for (fail_after, zero_after) in [(Some(1), None), (None, Some(1))] {
        let mut writer = GatedPrefixWriter {
            ready: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            waker: Arc::new(Mutex::new(None)),
            max_write: 2,
            fail_after,
            zero_after,
        };
        let result = forward_initial_payload(
            &mut writer,
            b"four",
            std::time::Duration::from_secs(5),
            std::future::pending::<()>(),
        )
        .await;
        assert_eq!(
            result,
            Err(PrefixFailure {
                kind: RelayRunError::Io,
                bytes: 2,
            })
        );
    }
}

#[tokio::test]
async fn lifecycle_composition_contract_empty_prefix_performs_no_write() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut writer = GatedPrefixWriter {
        ready: Arc::new(AtomicBool::new(false)),
        calls: Arc::clone(&calls),
        waker: Arc::new(Mutex::new(None)),
        max_write: 1,
        fail_after: None,
        zero_after: None,
    };
    assert_eq!(
        forward_initial_payload(
            &mut writer,
            b"",
            std::time::Duration::from_secs(5),
            std::future::pending::<()>(),
        )
        .await,
        Ok(0)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
