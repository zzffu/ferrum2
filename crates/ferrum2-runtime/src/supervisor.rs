use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::{OwnerRegistry, ProcessCancellation};

/// Listener boundary used by the bounded supervisor and deterministic tests.
pub trait AcceptListener: Send + Sync + 'static {
    /// Accepted stream type.
    type Stream: Send + 'static;

    /// Accepts one stream.
    fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

impl AcceptListener for TcpListener {
    type Stream = TcpStream;

    async fn accept(&self) -> io::Result<Self::Stream> {
        let (stream, _peer) = TcpListener::accept(self).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

/// Per-flow cancellation view owned by one supervisor child.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    receiver: watch::Receiver<bool>,
}

impl CancellationToken {
    /// Returns whether cancellation has already been requested.
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Waits until cancellation is requested.
    pub async fn cancelled(&mut self) {
        while !*self.receiver.borrow_and_update() {
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Debug)]
struct CancellationSource {
    sender: watch::Sender<bool>,
}

impl CancellationSource {
    fn new() -> (Self, CancellationToken) {
        let (sender, receiver) = watch::channel(false);
        (Self { sender }, CancellationToken { receiver })
    }

    fn cancel(&self) {
        self.sender.send_replace(true);
    }
}

/// Invalid supervisor construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorConfigError {
    /// At least one connection permit is required.
    ZeroConnectionLimit,
}

impl std::fmt::Display for SupervisorConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("connection limit is zero")
    }
}

impl std::error::Error for SupervisorConfigError {}

/// Closed process-level supervisor failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// A non-transient listener failure stopped acceptance.
    ListenerFailure,
    /// A child owner task failed to join normally.
    ChildFailure,
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListenerFailure => formatter.write_str("listener failed"),
            Self::ChildFailure => formatter.write_str("supervisor child failed"),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// Owns one listener, its connection permits, and every spawned flow.
#[derive(Debug)]
pub struct BoundedSupervisor<L> {
    listener: L,
    max_connections: usize,
    shutdown_grace: Duration,
    registry: OwnerRegistry,
}

impl<L> BoundedSupervisor<L>
where
    L: AcceptListener,
{
    /// Creates a supervisor with a validated non-zero connection bound.
    pub fn new(
        listener: L,
        max_connections: usize,
        shutdown_grace: Duration,
        registry: OwnerRegistry,
    ) -> Result<Self, SupervisorConfigError> {
        if max_connections == 0 {
            return Err(SupervisorConfigError::ZeroConnectionLimit);
        }
        Ok(Self {
            listener,
            max_connections,
            shutdown_grace,
            registry,
        })
    }

    /// Accepts bounded flows until shutdown or a process-fatal listener/child failure.
    pub async fn run_until<F, Fut, S>(self, handler: F, shutdown: S) -> Result<(), SupervisorError>
    where
        F: Fn(L::Stream, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        S: Future<Output = ()> + Send,
    {
        let shutdown_grace = self.shutdown_grace;
        self.run_with_shutdown(handler, shutdown, DrainMode::Relative(shutdown_grace))
            .await
    }

    /// Accepts until the process lineage quiesces, then drains until that same
    /// lineage forces shutdown without starting another grace interval.
    pub async fn run_with_cancellation<F, Fut>(
        self,
        handler: F,
        mut cancellation: ProcessCancellation,
    ) -> Result<(), SupervisorError>
    where
        F: Fn(L::Stream, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let drain_cancellation = cancellation.clone();
        self.run_with_shutdown(
            handler,
            async move { cancellation.cancelled().await },
            DrainMode::Process(drain_cancellation),
        )
        .await
    }

    async fn run_with_shutdown<F, Fut, S>(
        self,
        handler: F,
        shutdown: S,
        drain_mode: DrainMode,
    ) -> Result<(), SupervisorError>
    where
        F: Fn(L::Stream, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        S: Future<Output = ()> + Send,
    {
        let Self {
            listener,
            max_connections,
            shutdown_grace: _,
            registry,
        } = self;
        let semaphore = Arc::new(Semaphore::new(max_connections));
        let (cancellation_source, cancellation_token) = CancellationSource::new();
        let handler = Arc::new(handler);
        let mut children = JoinSet::new();
        let listener = listener;
        let listener_guard = registry.track_listener();
        tokio::pin!(shutdown);

        enum Stop {
            Operator,
            Fatal(SupervisorError),
        }

        let stop = 'accepting: loop {
            while let Some(result) = children.try_join_next() {
                if result.is_err() {
                    break 'accepting Stop::Fatal(SupervisorError::ChildFailure);
                }
            }

            let permit = tokio::select! {
                biased;
                _ = &mut shutdown => break 'accepting Stop::Operator,
                result = children.join_next(), if !children.is_empty() => {
                    if result.is_some_and(|result| result.is_err()) {
                        break 'accepting Stop::Fatal(SupervisorError::ChildFailure);
                    }
                    continue;
                }
                permit = Arc::clone(&semaphore).acquire_owned() => {
                    match permit {
                        Ok(permit) => permit,
                        Err(_) => break 'accepting Stop::Fatal(SupervisorError::ChildFailure),
                    }
                }
            };
            let permit_guard = registry.track_permit();
            if future_is_ready(shutdown.as_mut()).await {
                break Stop::Operator;
            }

            let accepted = loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown => break 'accepting Stop::Operator,
                    result = children.join_next(), if !children.is_empty() => {
                        if result.is_some_and(|result| result.is_err()) {
                            break 'accepting Stop::Fatal(SupervisorError::ChildFailure);
                        }
                    }
                    result = listener.accept() => break result,
                }
            };
            if future_is_ready(shutdown.as_mut()).await {
                break Stop::Operator;
            }

            let stream = match accepted {
                Ok(stream) => stream,
                Err(error) if is_transient_accept_error(&error) => {
                    drop(permit_guard);
                    drop(permit);
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(_) => break Stop::Fatal(SupervisorError::ListenerFailure),
            };
            let child_guard = registry.track_supervisor_child();
            let connection_guard = registry.track_connection_task();
            let handler = Arc::clone(&handler);
            let token = cancellation_token.clone();
            children.spawn(async move {
                let _child_guard = child_guard;
                let _connection_guard = connection_guard;
                let _permit_guard = permit_guard;
                let _permit = permit;
                handler(stream, token).await;
            });
        };

        drop(listener);
        drop(listener_guard);

        match stop {
            Stop::Fatal(error) => {
                cancellation_source.cancel();
                match drain_mode {
                    DrainMode::Relative(shutdown_grace) => {
                        drain_cancelled_children(&mut children, shutdown_grace, &registry).await;
                    }
                    DrainMode::Process(_) => {
                        force_and_reap_children(&mut children, &registry).await;
                    }
                }
                Err(error)
            }
            Stop::Operator => match drain_mode {
                DrainMode::Relative(shutdown_grace) => {
                    drain_for_shutdown(
                        &mut children,
                        shutdown_grace,
                        &cancellation_source,
                        &registry,
                    )
                    .await
                }
                DrainMode::Process(cancellation) => {
                    drain_for_process_shutdown(
                        &mut children,
                        cancellation,
                        &cancellation_source,
                        &registry,
                    )
                    .await
                }
            },
        }
    }
}

enum DrainMode {
    Relative(Duration),
    Process(ProcessCancellation),
}

async fn drain_for_process_shutdown(
    children: &mut JoinSet<()>,
    mut cancellation: ProcessCancellation,
    cancellation_source: &CancellationSource,
    registry: &OwnerRegistry,
) -> Result<(), SupervisorError> {
    if children.is_empty() {
        return Ok(());
    }
    loop {
        tokio::select! {
            biased;
            result = children.join_next(), if !children.is_empty() => {
                match result {
                    Some(Ok(())) => {
                        if children.is_empty() {
                            return Ok(());
                        }
                    }
                    Some(Err(_)) => {
                        cancellation_source.cancel();
                        force_and_reap_children(children, registry).await;
                        return Err(SupervisorError::ChildFailure);
                    }
                    None => return Ok(()),
                }
            }
            () = cancellation.forced() => {
                cancellation_source.cancel();
                force_and_reap_children(children, registry).await;
                return Ok(());
            }
        }
    }
}

async fn force_and_reap_children(children: &mut JoinSet<()>, registry: &OwnerRegistry) {
    if children.is_empty() {
        return;
    }
    registry.record_forced_shutdowns(children.len());
    children.abort_all();
    reap_children(children).await;
}

async fn drain_cancelled_children(
    children: &mut JoinSet<()>,
    shutdown_grace: Duration,
    registry: &OwnerRegistry,
) {
    if children.is_empty() {
        return;
    }
    let deadline = Instant::now() + shutdown_grace;
    loop {
        tokio::select! {
            result = children.join_next(), if !children.is_empty() => {
                if result.is_none() || children.is_empty() {
                    return;
                }
            }
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    registry.record_forced_shutdowns(children.len());
    children.abort_all();
    reap_children(children).await;
}

async fn drain_for_shutdown(
    children: &mut JoinSet<()>,
    shutdown_grace: Duration,
    cancellation_source: &CancellationSource,
    registry: &OwnerRegistry,
) -> Result<(), SupervisorError> {
    if children.is_empty() {
        return Ok(());
    }

    let deadline = Instant::now() + shutdown_grace;
    loop {
        tokio::select! {
            result = children.join_next(), if !children.is_empty() => {
                match result {
                    Some(Ok(())) => {
                        if children.is_empty() {
                            return Ok(());
                        }
                    }
                    Some(Err(_)) => {
                        cancellation_source.cancel();
                        children.abort_all();
                        reap_children(children).await;
                        return Err(SupervisorError::ChildFailure);
                    }
                    None => return Ok(()),
                }
            }
            () = tokio::time::sleep_until(deadline) => break,
        }
    }

    let forced = children.len();
    registry.record_forced_shutdowns(forced);
    cancellation_source.cancel();
    tokio::task::yield_now().await;
    children.abort_all();
    reap_children(children).await;
    Ok(())
}

async fn reap_children(children: &mut JoinSet<()>) {
    while children.join_next().await.is_some() {}
}

async fn future_is_ready<F>(mut future: Pin<&mut F>) -> bool
where
    F: Future + ?Sized,
{
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_ready())).await
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}
