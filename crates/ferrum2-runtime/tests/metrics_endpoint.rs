use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, METRICS_CONNECTION_LIMIT, METRICS_HEADER_BYTES, METRICS_HEADER_TIMEOUT,
    MetricsEndpoint, OwnerRegistry, serve_metrics_connection,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

async fn exchange(request: &[u8]) -> String {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let renderer_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&renderer_calls);
    let request_owner = tokio::spawn(async move {
        let renderer = move || {
            calls.fetch_add(1, Ordering::SeqCst);
            "metric_name 1\n".to_owned()
        };
        serve_metrics_connection(&mut server, &renderer).await
    });
    client.write_all(request).await.expect("write request");
    client.shutdown().await.expect("finish request");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");
    request_owner
        .await
        .expect("request owner")
        .expect("bounded response");
    response
}

#[tokio::test]
async fn get_metrics_renders_composition_owned_text() {
    let response = exchange(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("metric_name 1\n"));
}

#[tokio::test]
async fn rejects_other_methods_and_oversized_headers() {
    let method = exchange(b"POST /metrics HTTP/1.1\r\n\r\n").await;
    assert!(method.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

    let oversized = vec![b'a'; METRICS_HEADER_BYTES];
    let response = exchange(&oversized).await;
    assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
}

#[tokio::test(start_paused = true)]
async fn incomplete_header_times_out_after_two_seconds() {
    assert_eq!(METRICS_HEADER_TIMEOUT, Duration::from_secs(2));
    let (mut client, mut server) = tokio::io::duplex(4096);
    let request_owner = tokio::spawn(async move {
        serve_metrics_connection(&mut server, &|| "unused".to_owned()).await
    });
    client
        .write_all(b"GET /metrics HTTP/1.1\r\n")
        .await
        .expect("write partial header");
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(2)).await;

    request_owner
        .await
        .expect("request owner")
        .expect("bounded timeout response");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read timeout response");
    assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
}

struct PendingIo;

impl AsyncRead for PendingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct MetricsListener {
    streams: Mutex<VecDeque<PendingIo>>,
    accepts: Arc<AtomicUsize>,
}

impl AcceptListener for MetricsListener {
    type Stream = PendingIo;

    async fn accept(&self) -> io::Result<Self::Stream> {
        self.accepts.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .streams
            .lock()
            .expect("stream lock")
            .pop_front()
            .expect("test provides enough streams"))
    }
}

#[tokio::test]
async fn endpoint_stops_accepting_at_sixteen_owned_requests() {
    assert_eq!(METRICS_CONNECTION_LIMIT, 16);
    let accepts = Arc::new(AtomicUsize::new(0));
    let listener = MetricsListener {
        streams: Mutex::new(
            (0..METRICS_CONNECTION_LIMIT + 1)
                .map(|_| PendingIo)
                .collect(),
        ),
        accepts: Arc::clone(&accepts),
    };
    let registry = OwnerRegistry::new();
    let endpoint = MetricsEndpoint::new(listener, || "unused".to_owned(), registry.clone());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(endpoint.run_until(async move {
        let _ = shutdown_rx.await;
    }));

    for _ in 0..200 {
        if registry.snapshot().connection_tasks == METRICS_CONNECTION_LIMIT {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(accepts.load(Ordering::SeqCst), METRICS_CONNECTION_LIMIT);
    assert_eq!(registry.snapshot().owned_permits, METRICS_CONNECTION_LIMIT);

    shutdown_tx.send(()).expect("request shutdown");
    run.await
        .expect("endpoint task")
        .expect("bounded endpoint shutdown");
    assert_eq!(registry.snapshot().connection_tasks, 0);
    assert_eq!(registry.snapshot().owned_permits, 0);
}
