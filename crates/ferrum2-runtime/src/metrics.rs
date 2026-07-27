use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{AcceptListener, BoundedSupervisor, OwnerRegistry, SupervisorError};

/// Maximum concurrent metrics requests.
pub const METRICS_CONNECTION_LIMIT: usize = 16;
/// Maximum complete metrics request header.
pub const METRICS_HEADER_BYTES: usize = 1024;
/// Deadline for receiving a complete metrics request header.
pub const METRICS_HEADER_TIMEOUT: Duration = Duration::from_secs(2);

const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const REQUEST_TIMEOUT: &[u8] =
    b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const METHOD_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\nAllow: GET\r\n\r\n";
const HEADER_TOO_LARGE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Process-level failure of the supervisor-owned metrics listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricsEndpointError {
    /// The metrics listener failed.
    ListenerFailure,
    /// A metrics request owner task failed.
    ChildFailure,
}

impl std::fmt::Display for MetricsEndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListenerFailure => formatter.write_str("metrics listener failed"),
            Self::ChildFailure => formatter.write_str("metrics request owner failed"),
        }
    }
}

impl std::error::Error for MetricsEndpointError {}

/// Generic bounded metrics listener that has no observability-crate dependency.
#[derive(Debug)]
pub struct MetricsEndpoint<L, R> {
    listener: L,
    renderer: R,
    registry: OwnerRegistry,
}

impl<L, R> MetricsEndpoint<L, R> {
    /// Creates an endpoint from a listener and a composition-owned text renderer.
    pub fn new(listener: L, renderer: R, registry: OwnerRegistry) -> Self {
        Self {
            listener,
            renderer,
            registry,
        }
    }
}

impl<L, R> MetricsEndpoint<L, R>
where
    L: AcceptListener,
    L::Stream: AsyncRead + AsyncWrite + Unpin,
    R: Fn() -> String + Send + Sync + 'static,
{
    /// Serves bounded requests until the supervisor shutdown future resolves.
    pub async fn run_until<S>(self, shutdown: S) -> Result<(), MetricsEndpointError>
    where
        S: Future<Output = ()> + Send,
    {
        let renderer = Arc::new(self.renderer);
        let Ok(supervisor) = BoundedSupervisor::new(
            self.listener,
            METRICS_CONNECTION_LIMIT,
            Duration::ZERO,
            self.registry,
        ) else {
            return Err(MetricsEndpointError::ChildFailure);
        };
        supervisor
            .run_until(
                move |mut stream, _cancellation| {
                    let renderer = Arc::clone(&renderer);
                    async move {
                        let _ = serve_metrics_connection(&mut stream, &*renderer).await;
                    }
                },
                shutdown,
            )
            .await
            .map_err(|error| match error {
                SupervisorError::ListenerFailure => MetricsEndpointError::ListenerFailure,
                SupervisorError::ChildFailure => MetricsEndpointError::ChildFailure,
            })
    }
}

/// Serves one fixed-bound HTTP metrics request and closes the stream.
pub async fn serve_metrics_connection<S, R>(stream: &mut S, renderer: &R) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Fn() -> String + ?Sized,
{
    let mut header = [0_u8; METRICS_HEADER_BYTES];
    let header_length = match tokio::time::timeout(
        METRICS_HEADER_TIMEOUT,
        read_header(stream, &mut header),
    )
    .await
    {
        Err(_) => {
            stream.write_all(REQUEST_TIMEOUT).await?;
            return stream.shutdown().await;
        }
        Ok(Err(error)) => return Err(error),
        Ok(Ok(HeaderRead::Closed)) => {
            stream.write_all(BAD_REQUEST).await?;
            return stream.shutdown().await;
        }
        Ok(Ok(HeaderRead::TooLarge)) => {
            stream.write_all(HEADER_TOO_LARGE).await?;
            return stream.shutdown().await;
        }
        Ok(Ok(HeaderRead::Complete(length))) => length,
    };

    let first_line_end = header[..header_length]
        .windows(2)
        .position(|window| window == b"\r\n");
    let Some(first_line_end) = first_line_end else {
        stream.write_all(BAD_REQUEST).await?;
        return stream.shutdown().await;
    };
    let mut parts = header[..first_line_end].split(|byte| *byte == b' ');
    let method = parts.next();
    let path = parts.next();
    let version = parts.next();
    if parts.next().is_some() || version != Some(b"HTTP/1.1".as_slice()) {
        stream.write_all(BAD_REQUEST).await?;
        return stream.shutdown().await;
    }
    if method != Some(b"GET".as_slice()) {
        stream.write_all(METHOD_NOT_ALLOWED).await?;
        return stream.shutdown().await;
    }
    if path != Some(b"/metrics".as_slice()) {
        stream.write_all(NOT_FOUND).await?;
        return stream.shutdown().await;
    }

    let body = renderer();
    let response_header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response_header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

enum HeaderRead {
    Complete(usize),
    Closed,
    TooLarge,
}

async fn read_header<S>(
    stream: &mut S,
    header: &mut [u8; METRICS_HEADER_BYTES],
) -> io::Result<HeaderRead>
where
    S: AsyncRead + Unpin,
{
    let mut used = 0;
    loop {
        if used == header.len() {
            return Ok(HeaderRead::TooLarge);
        }
        let read = stream.read(&mut header[used..]).await?;
        if read == 0 {
            return Ok(HeaderRead::Closed);
        }
        used += read;
        if header[..used]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            return Ok(HeaderRead::Complete(used));
        }
    }
}
