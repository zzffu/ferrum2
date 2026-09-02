use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::Instant;

use crate::supervisor::{CancellationSource, future_is_ready, is_transient_accept_error};
use crate::{
    AcceptListener, CancellationToken, OwnerRegistry, ProcessCancellation, SupervisorConfigError,
    SupervisorError,
};

/// Extends an accepted-stream Adapter with the reactor transfer needed by an
/// [`AffineConnectionExecutor`].
///
/// `into_transfer` runs on the accepting runtime. `from_transfer` runs on the
/// selected shard before the connection handler is created. Implementations
/// must preserve the accepted transport's nonblocking mode and socket options.
pub trait AffineAcceptListener: AcceptListener {
    /// Reactor-independent value sent to one connection shard.
    type Transfer: Send + 'static;
    /// Stream value presented to the connection handler on its shard.
    type AffineStream: 'static;

    /// Detaches one accepted stream from the accepting reactor.
    fn into_transfer(stream: Self::Stream) -> io::Result<Self::Transfer>;

    /// Registers one transferred stream with the current shard reactor.
    fn from_transfer(transfer: Self::Transfer) -> io::Result<Self::AffineStream>;
}

impl AffineAcceptListener for TcpListener {
    type Transfer = std::net::TcpStream;
    type AffineStream = TcpStream;

    fn into_transfer(stream: Self::Stream) -> io::Result<Self::Transfer> {
        stream.into_std()
    }

    fn from_transfer(transfer: Self::Transfer) -> io::Result<Self::AffineStream> {
        TcpStream::from_std(transfer)
    }
}

/// Owns bounded admission, fixed current-thread runtime shards, and every
/// accepted connection assigned to those shards.
///
/// A connection is assigned once. Its stream is registered, its handler future
/// is created, and that future is polled only on the selected shard thread.
/// The process-root runtime observes shard lifecycle rather than polling
/// individual connection futures.
pub struct AffineConnectionExecutor<L> {
    listener: L,
    max_connections: usize,
    shutdown_grace: Duration,
    registry: OwnerRegistry,
    shard_count: NonZeroUsize,
}

impl<L> AffineConnectionExecutor<L>
where
    L: AffineAcceptListener,
{
    /// Creates an executor using the process's available logical parallelism.
    pub fn new(
        listener: L,
        max_connections: usize,
        shutdown_grace: Duration,
        registry: OwnerRegistry,
    ) -> Result<Self, SupervisorConfigError> {
        let shard_count = std::thread::available_parallelism()
            .unwrap_or_else(|_| NonZeroUsize::new(1).expect("one is non-zero"));
        Self::with_shard_count(
            listener,
            max_connections,
            shutdown_grace,
            registry,
            shard_count,
        )
    }

    fn with_shard_count(
        listener: L,
        max_connections: usize,
        shutdown_grace: Duration,
        registry: OwnerRegistry,
        shard_count: NonZeroUsize,
    ) -> Result<Self, SupervisorConfigError> {
        if max_connections == 0 {
            return Err(SupervisorConfigError::ZeroConnectionLimit);
        }
        Ok(Self {
            listener,
            max_connections,
            shutdown_grace,
            registry,
            shard_count,
        })
    }

    /// Accepts bounded connections until `shutdown`, then drains them for the
    /// configured grace period before cancellation and forced reaping.
    pub async fn run_until<H, Fut, S>(self, handler: H, shutdown: S) -> Result<(), SupervisorError>
    where
        H: Fn(L::AffineStream, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
        S: Future<Output = ()> + Send,
    {
        let grace = self.shutdown_grace;
        self.run_with_shutdown(handler, shutdown, DrainMode::Relative(grace))
            .await
    }

    /// Accepts until the process lineage quiesces and drains until that lineage
    /// forces shutdown, without starting another grace interval.
    pub async fn run_with_cancellation<H, Fut>(
        self,
        handler: H,
        mut cancellation: ProcessCancellation,
    ) -> Result<(), SupervisorError>
    where
        H: Fn(L::AffineStream, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let drain_cancellation = cancellation.clone();
        self.run_with_shutdown(
            handler,
            async move { cancellation.cancelled().await },
            DrainMode::Process(drain_cancellation),
        )
        .await
    }

    async fn run_with_shutdown<H, Fut, S>(
        self,
        handler: H,
        shutdown: S,
        drain_mode: DrainMode,
    ) -> Result<(), SupervisorError>
    where
        H: Fn(L::AffineStream, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
        S: Future<Output = ()> + Send,
    {
        let Self {
            listener,
            max_connections,
            shutdown_grace: _,
            registry,
            shard_count,
        } = self;
        let handler = Arc::new(handler);
        let semaphore = Arc::new(Semaphore::new(max_connections));
        let (cancellation_source, cancellation_token) = CancellationSource::new();
        let (force_sender, force_receiver) = watch::channel(false);
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
        let queue_capacity = max_connections.div_ceil(shard_count.get()).max(1);
        let mut shards = Vec::with_capacity(shard_count.get());
        let mut threads = Vec::with_capacity(shard_count.get());

        for shard_index in 0..shard_count.get() {
            let (sender, receiver) = mpsc::channel(queue_capacity);
            let load = Arc::new(AtomicUsize::new(0));
            let worker = start_shard::<L, H, Fut>(
                shard_index,
                receiver,
                Arc::clone(&handler),
                registry.clone(),
                force_receiver.clone(),
                event_sender.clone(),
            );
            let Ok(worker) = worker else {
                drop(sender);
                shards.clear();
                cancellation_source.cancel();
                force_shards(&force_sender);
                wait_for_shards(&mut event_receiver, threads.len()).await;
                join_shards(threads)?;
                return Err(SupervisorError::ChildFailure);
            };
            shards.push(ShardControl {
                sender: Some(sender),
                load,
            });
            threads.push(worker);
        }
        drop(event_sender);

        let listener_guard = registry.track_listener();
        let next_pair = AtomicUsize::new(0);
        let mut stopped_shards = 0usize;
        tokio::pin!(shutdown);

        enum Stop {
            Operator,
            Fatal(SupervisorError),
        }

        let stop = 'accepting: loop {
            let permit = tokio::select! {
                biased;
                _ = &mut shutdown => break 'accepting Stop::Operator,
                event = event_receiver.recv() => {
                    stopped_shards += usize::from(event.is_some());
                    break 'accepting Stop::Fatal(SupervisorError::ChildFailure);
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

            let accepted = tokio::select! {
                biased;
                _ = &mut shutdown => break 'accepting Stop::Operator,
                event = event_receiver.recv() => {
                    stopped_shards += usize::from(event.is_some());
                    break 'accepting Stop::Fatal(SupervisorError::ChildFailure);
                }
                result = listener.accept() => result,
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
            let transfer = match L::into_transfer(stream) {
                Ok(transfer) => transfer,
                Err(_) => break Stop::Fatal(SupervisorError::ListenerFailure),
            };
            let pending = PendingConnection {
                transfer,
                token: cancellation_token.clone(),
                _child_guard: registry.track_supervisor_child(),
                _connection_guard: registry.track_connection_task(),
                _permit_guard: permit_guard,
                _permit: permit,
            };

            match try_dispatch(&shards, &next_pair, pending) {
                TryDispatch::Sent => {}
                TryDispatch::Closed(_pending) => {
                    break Stop::Fatal(SupervisorError::ChildFailure);
                }
                TryDispatch::Full(pending) => {
                    let reserved = tokio::select! {
                        biased;
                        _ = &mut shutdown => break 'accepting Stop::Operator,
                        event = event_receiver.recv() => {
                            stopped_shards += usize::from(event.is_some());
                            break 'accepting Stop::Fatal(SupervisorError::ChildFailure);
                        }
                        reserved = reserve_any_sender(
                            shards
                                .iter()
                                .enumerate()
                                .map(|(index, shard)| (index, shard.sender().clone())),
                        ) => reserved,
                    };
                    let Some((shard_index, reserved)) = reserved else {
                        break Stop::Fatal(SupervisorError::ChildFailure);
                    };
                    reserved.send(ShardJob::new(
                        pending,
                        Arc::clone(&shards[shard_index].load),
                    ));
                }
            }
        };

        drop(listener);
        drop(listener_guard);
        shards.iter_mut().for_each(ShardControl::close);

        let result = match stop {
            Stop::Fatal(error) => {
                drain_fatal_shards(
                    &mut event_receiver,
                    shard_count.get().saturating_sub(stopped_shards),
                    drain_mode,
                    &cancellation_source,
                    &force_sender,
                )
                .await;
                Err(error)
            }
            Stop::Operator => {
                drain_shards(
                    &mut event_receiver,
                    shard_count.get().saturating_sub(stopped_shards),
                    drain_mode,
                    &cancellation_source,
                    &force_sender,
                )
                .await
            }
        };
        join_shards(threads)?;
        result
    }
}

struct ShardControl<T> {
    sender: Option<mpsc::Sender<ShardJob<T>>>,
    load: Arc<AtomicUsize>,
}

impl<T> ShardControl<T> {
    fn sender(&self) -> &mpsc::Sender<ShardJob<T>> {
        self.sender.as_ref().expect("open connection shard")
    }

    fn close(&mut self) {
        self.sender.take();
    }
}

struct PendingConnection<T> {
    transfer: T,
    token: CancellationToken,
    _child_guard: crate::owner::OwnerGuard,
    _connection_guard: crate::owner::OwnerGuard,
    _permit_guard: crate::owner::OwnerGuard,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

struct ShardJob<T> {
    connection: PendingConnection<T>,
    _assignment: ShardAssignment,
}

impl<T> ShardJob<T> {
    fn new(connection: PendingConnection<T>, load: Arc<AtomicUsize>) -> Self {
        load.fetch_add(1, Ordering::Relaxed);
        Self {
            connection,
            _assignment: ShardAssignment { load },
        }
    }
}

struct ShardAssignment {
    load: Arc<AtomicUsize>,
}

impl Drop for ShardAssignment {
    fn drop(&mut self) {
        let previous = self.load.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "connection shard load underflow");
    }
}

enum TryDispatch<T> {
    Sent,
    Full(PendingConnection<T>),
    Closed(PendingConnection<T>),
}

fn try_dispatch<T>(
    shards: &[ShardControl<T>],
    next_pair: &AtomicUsize,
    pending: PendingConnection<T>,
) -> TryDispatch<T> {
    let shard_count = shards.len();
    let first_candidate = next_pair.fetch_add(1, Ordering::Relaxed) % shard_count;
    let second_candidate = if shard_count == 1 {
        first_candidate
    } else {
        (first_candidate + 1) % shard_count
    };
    let (preferred, alternate) = if shards[first_candidate].load.load(Ordering::Relaxed)
        <= shards[second_candidate].load.load(Ordering::Relaxed)
    {
        (first_candidate, second_candidate)
    } else {
        (second_candidate, first_candidate)
    };

    let mut pending = Some(pending);
    match try_one_shard(
        &shards[preferred],
        pending.take().expect("pending connection"),
    ) {
        Ok(()) => return TryDispatch::Sent,
        Err(TrySendError::Full(connection)) => pending = Some(connection),
        Err(TrySendError::Closed(connection)) => return TryDispatch::Closed(connection),
    }
    if alternate != preferred {
        match try_one_shard(
            &shards[alternate],
            pending.take().expect("pending connection"),
        ) {
            Ok(()) => return TryDispatch::Sent,
            Err(TrySendError::Full(connection)) => pending = Some(connection),
            Err(TrySendError::Closed(connection)) => return TryDispatch::Closed(connection),
        }
    }
    for offset in 2..shard_count {
        let shard_index = (first_candidate + offset) % shard_count;
        if shard_index == preferred || shard_index == alternate {
            continue;
        }
        match try_one_shard(
            &shards[shard_index],
            pending.take().expect("pending connection"),
        ) {
            Ok(()) => return TryDispatch::Sent,
            Err(TrySendError::Full(connection)) => pending = Some(connection),
            Err(TrySendError::Closed(connection)) => return TryDispatch::Closed(connection),
        }
    }
    TryDispatch::Full(pending.expect("pending connection"))
}

enum TrySendError<T> {
    Full(PendingConnection<T>),
    Closed(PendingConnection<T>),
}

fn try_one_shard<T>(
    shard: &ShardControl<T>,
    connection: PendingConnection<T>,
) -> Result<(), TrySendError<T>> {
    let job = ShardJob::new(connection, Arc::clone(&shard.load));
    match shard.sender().try_send(job) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(job)) => {
            let ShardJob {
                connection,
                _assignment,
            } = job;
            drop(_assignment);
            Err(TrySendError::Full(connection))
        }
        Err(mpsc::error::TrySendError::Closed(job)) => {
            let ShardJob {
                connection,
                _assignment,
            } = job;
            drop(_assignment);
            Err(TrySendError::Closed(connection))
        }
    }
}

async fn reserve_any_sender<T, I>(senders: I) -> Option<(usize, mpsc::OwnedPermit<T>)>
where
    I: IntoIterator<Item = (usize, mpsc::Sender<T>)>,
{
    let mut reservations = FuturesUnordered::new();
    for (shard_index, sender) in senders {
        reservations.push(async move { (shard_index, sender.reserve_owned().await) });
    }
    let (shard_index, reservation) = reservations.next().await?;
    reservation
        .ok()
        .map(|reservation| (shard_index, reservation))
}

struct ShardEvent {
    result: Result<(), SupervisorError>,
}

fn start_shard<L, H, Fut>(
    shard_index: usize,
    receiver: mpsc::Receiver<ShardJob<L::Transfer>>,
    handler: Arc<H>,
    registry: OwnerRegistry,
    force: watch::Receiver<bool>,
    events: mpsc::UnboundedSender<ShardEvent>,
) -> io::Result<JoinHandle<()>>
where
    L: AffineAcceptListener,
    H: Fn(L::AffineStream, CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .name(format!("ferrum2-connection-{shard_index}"))
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| SupervisorError::ChildFailure)?;
                let local = tokio::task::LocalSet::new();
                runtime.block_on(
                    local.run_until(run_shard::<L, H, Fut>(receiver, handler, registry, force)),
                )
            }))
            .unwrap_or(Err(SupervisorError::ChildFailure));
            let _closed = events.send(ShardEvent { result });
        })
}

async fn run_shard<L, H, Fut>(
    mut receiver: mpsc::Receiver<ShardJob<L::Transfer>>,
    handler: Arc<H>,
    registry: OwnerRegistry,
    mut force: watch::Receiver<bool>,
) -> Result<(), SupervisorError>
where
    L: AffineAcceptListener,
    H: Fn(L::AffineStream, CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let mut accepting = true;
    let mut children = tokio::task::JoinSet::new();
    loop {
        if !accepting && children.is_empty() {
            return Ok(());
        }
        tokio::select! {
            biased;
            changed = force.changed() => {
                if changed.is_err() || *force.borrow() {
                    force_and_reap_local(&mut receiver, &mut children, &registry).await;
                    return Ok(());
                }
            }
            result = children.join_next(), if !children.is_empty() => {
                if result.is_some_and(|result| result.is_err()) {
                    force_and_reap_local(&mut receiver, &mut children, &registry).await;
                    return Err(SupervisorError::ChildFailure);
                }
            }
            job = receiver.recv(), if accepting => {
                let Some(job) = job else {
                    accepting = false;
                    continue;
                };
                let ShardJob {
                    connection,
                    _assignment,
                } = job;
                let PendingConnection {
                    transfer,
                    token,
                    _child_guard,
                    _connection_guard,
                    _permit_guard,
                    _permit,
                } = connection;
                let stream = match L::from_transfer(transfer) {
                    Ok(stream) => stream,
                    Err(_) => {
                        force_and_reap_local(&mut receiver, &mut children, &registry).await;
                        return Err(SupervisorError::ChildFailure);
                    }
                };
                let handler = Arc::clone(&handler);
                children.spawn_local(async move {
                    let _assignment = _assignment;
                    let _child_guard = _child_guard;
                    let _connection_guard = _connection_guard;
                    let _permit_guard = _permit_guard;
                    let _permit = _permit;
                    handler(stream, token).await;
                });
            }
        }
    }
}

async fn force_and_reap_local<T>(
    receiver: &mut mpsc::Receiver<T>,
    children: &mut tokio::task::JoinSet<()>,
    registry: &OwnerRegistry,
) {
    receiver.close();
    while children.try_join_next().is_some() {}
    registry.record_forced_shutdowns(children.len() + receiver.len());
    children.abort_all();
    while children.join_next().await.is_some() {}
    while receiver.try_recv().is_ok() {}
}

enum DrainMode {
    Relative(Duration),
    Process(ProcessCancellation),
}

async fn drain_fatal_shards(
    events: &mut mpsc::UnboundedReceiver<ShardEvent>,
    mut remaining: usize,
    drain_mode: DrainMode,
    cancellation_source: &CancellationSource,
    force_sender: &watch::Sender<bool>,
) {
    match drain_mode {
        DrainMode::Relative(grace) => {
            cancellation_source.cancel();
            let deadline = Instant::now() + grace;
            while remaining > 0 {
                tokio::select! {
                    event = events.recv() => {
                        let Some(_event) = event else {
                            return;
                        };
                        remaining -= 1;
                    }
                    () = tokio::time::sleep_until(deadline) => break,
                }
            }
            if remaining > 0 {
                tokio::task::yield_now().await;
                force_shards(force_sender);
                wait_for_shards(events, remaining).await;
            }
        }
        DrainMode::Process(_) => {
            if remaining > 0 {
                force_process_shards(events, remaining, force_sender, cancellation_source).await;
            }
        }
    }
}

async fn drain_shards(
    events: &mut mpsc::UnboundedReceiver<ShardEvent>,
    mut remaining: usize,
    drain_mode: DrainMode,
    cancellation_source: &CancellationSource,
    force_sender: &watch::Sender<bool>,
) -> Result<(), SupervisorError> {
    let mut failure = None;
    let poll_cancelled_handler = match drain_mode {
        DrainMode::Relative(grace) => {
            let deadline = Instant::now() + grace;
            while remaining > 0 {
                tokio::select! {
                    event = events.recv() => {
                        remaining -= 1;
                        if event.is_none_or(|event| event.result.is_err()) {
                            failure = Some(SupervisorError::ChildFailure);
                            break;
                        }
                    }
                    () = tokio::time::sleep_until(deadline) => break,
                }
            }
            true
        }
        DrainMode::Process(mut cancellation) => {
            while remaining > 0 {
                tokio::select! {
                    biased;
                    event = events.recv() => {
                        remaining -= 1;
                        if event.is_none_or(|event| event.result.is_err()) {
                            failure = Some(SupervisorError::ChildFailure);
                            break;
                        }
                    }
                    () = cancellation.forced() => break,
                }
            }
            false
        }
    };

    if remaining > 0 {
        if poll_cancelled_handler {
            cancellation_source.cancel();
            tokio::task::yield_now().await;
            force_shards(force_sender);
            wait_for_shards(events, remaining).await;
        } else {
            force_process_shards(events, remaining, force_sender, cancellation_source).await;
        }
    }
    failure.map_or(Ok(()), Err)
}

fn force_shards(force_sender: &watch::Sender<bool>) {
    force_sender.send_replace(true);
}

async fn force_process_shards(
    events: &mut mpsc::UnboundedReceiver<ShardEvent>,
    remaining: usize,
    force_sender: &watch::Sender<bool>,
    cancellation_source: &CancellationSource,
) {
    // Shards run on separate OS threads. Do not wake cancellation-aware
    // handlers until every shard has observed force and accounted for its
    // remaining work; otherwise a handler can finish in that cross-thread gap.
    force_shards(force_sender);
    wait_for_shards(events, remaining).await;
    cancellation_source.cancel();
}

async fn wait_for_shards(events: &mut mpsc::UnboundedReceiver<ShardEvent>, mut remaining: usize) {
    while remaining > 0 {
        if events.recv().await.is_none() {
            return;
        }
        remaining -= 1;
    }
}

fn join_shards(threads: Vec<JoinHandle<()>>) -> Result<(), SupervisorError> {
    for thread in threads {
        if thread.join().is_err() {
            return Err(SupervisorError::ChildFailure);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::future::pending;
    use std::net::SocketAddr;
    use std::rc::Rc;
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::{Barrier, Notify};

    use super::*;

    struct TestListener {
        receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<io::Result<usize>>>,
        accept_calls: Arc<AtomicUsize>,
    }

    impl TestListener {
        fn new() -> (
            Self,
            mpsc::UnboundedSender<io::Result<usize>>,
            Arc<AtomicUsize>,
        ) {
            let (sender, receiver) = mpsc::unbounded_channel();
            let accept_calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    receiver: tokio::sync::Mutex::new(receiver),
                    accept_calls: Arc::clone(&accept_calls),
                },
                sender,
                accept_calls,
            )
        }
    }

    impl AcceptListener for TestListener {
        type Stream = usize;

        async fn accept(&self) -> io::Result<Self::Stream> {
            self.accept_calls.fetch_add(1, Ordering::SeqCst);
            self.receiver
                .lock()
                .await
                .recv()
                .await
                .unwrap_or_else(|| Err(io::ErrorKind::BrokenPipe.into()))
        }
    }

    impl AffineAcceptListener for TestListener {
        type Transfer = usize;
        type AffineStream = usize;

        fn into_transfer(stream: Self::Stream) -> io::Result<Self::Transfer> {
            if stream == usize::MAX {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(stream)
        }

        fn from_transfer(transfer: Self::Transfer) -> io::Result<Self::AffineStream> {
            if transfer == usize::MAX - 1 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(transfer)
        }
    }

    #[tokio::test]
    async fn all_full_queues_wait_for_whichever_shard_has_capacity() {
        let (first_sender, _first_receiver) = mpsc::channel(1);
        let (second_sender, mut second_receiver) = mpsc::channel(1);
        first_sender.try_send(1).expect("fill first shard");
        second_sender.try_send(2).expect("fill second shard");

        let (reservation, ()) = tokio::join!(
            reserve_any_sender(
                [first_sender.clone(), second_sender.clone()]
                    .into_iter()
                    .enumerate(),
            ),
            async {
                tokio::task::yield_now().await;
                assert_eq!(second_receiver.recv().await, Some(2));
            }
        );
        let (shard_index, reservation) = reservation.expect("one shard becomes writable");
        assert_eq!(shard_index, 1);
        reservation.send(3);
        assert_eq!(second_receiver.recv().await, Some(3));
    }

    #[tokio::test]
    async fn process_force_accounts_shards_before_waking_handler_cancellation() {
        let (force_sender, mut force_receiver) = watch::channel(false);
        let (cancellation_source, cancellation) = CancellationSource::new();
        let observed_cancellation = cancellation.clone();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();

        let ((), ()) = tokio::join!(
            force_process_shards(&mut event_receiver, 1, &force_sender, &cancellation_source,),
            async move {
                force_receiver.changed().await.expect("force signal");
                assert!(*force_receiver.borrow());
                assert!(!observed_cancellation.is_cancelled());
                event_sender
                    .send(ShardEvent { result: Ok(()) })
                    .expect("accounted shard");
            },
        );

        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn accept_transfer_and_reregistration_failures_release_every_owner() {
        enum Failure {
            Accept,
            Transfer,
            Reregister,
        }

        for (failure, expected) in [
            (Failure::Accept, SupervisorError::ListenerFailure),
            (Failure::Transfer, SupervisorError::ListenerFailure),
            (Failure::Reregister, SupervisorError::ChildFailure),
        ] {
            let (listener, sender, _accept_calls) = TestListener::new();
            let response = match failure {
                Failure::Accept => Err(io::ErrorKind::PermissionDenied.into()),
                Failure::Transfer => Ok(usize::MAX),
                Failure::Reregister => Ok(usize::MAX - 1),
            };
            sender.send(response).expect("queue failure");
            let registry = OwnerRegistry::new();
            let executor = AffineConnectionExecutor::with_shard_count(
                listener,
                1,
                Duration::ZERO,
                registry.clone(),
                NonZeroUsize::new(1).expect("one shard"),
            )
            .expect("executor");

            let result = executor
                .run_until(
                    |_connection, _cancellation| async move {
                        panic!("failed connection reached handler");
                    },
                    pending::<()>(),
                )
                .await;

            assert_eq!(result, Err(expected));
            let snapshot = registry.snapshot();
            assert_eq!(snapshot.connection_tasks, 0);
            assert_eq!(snapshot.active_supervisor_children, 0);
            assert_eq!(snapshot.owned_permits, 0);
            assert_eq!(snapshot.listeners, 0);
            assert_eq!(snapshot.forced_shutdowns, 0);
        }
    }

    #[tokio::test]
    async fn handlers_are_created_and_completed_on_one_of_multiple_shards() {
        const CONNECTIONS: usize = 4;

        let (listener, sender, _accept_calls) = TestListener::new();
        for connection in 0..CONNECTIONS {
            sender.send(Ok(connection)).expect("queue connection");
        }
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            CONNECTIONS,
            Duration::from_secs(1),
            registry.clone(),
            NonZeroUsize::new(2).expect("two shards"),
        )
        .expect("executor");
        let barrier = Arc::new(Barrier::new(CONNECTIONS + 1));
        let handler_barrier = Arc::clone(&barrier);
        let threads = Arc::new(Mutex::new(HashMap::new()));
        let handler_threads = Arc::clone(&threads);

        executor
            .run_until(
                move |connection, _cancellation| {
                    let barrier = Arc::clone(&handler_barrier);
                    let threads = Arc::clone(&handler_threads);
                    async move {
                        let shard_thread = std::thread::current().id();
                        let local_only = Rc::new(connection);
                        for _ in 0..32 {
                            tokio::task::yield_now().await;
                            assert_eq!(std::thread::current().id(), shard_thread);
                            assert_eq!(*local_only, connection);
                        }
                        threads
                            .lock()
                            .expect("thread map")
                            .insert(connection, shard_thread);
                        barrier.wait().await;
                    }
                },
                async move {
                    barrier.wait().await;
                },
            )
            .await
            .expect("controlled shutdown");

        let threads = threads.lock().expect("thread map");
        assert_eq!(threads.len(), CONNECTIONS);
        assert_eq!(threads.values().copied().collect::<HashSet<_>>().len(), 2);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.connection_tasks, 0);
        assert_eq!(snapshot.active_supervisor_children, 0);
        assert_eq!(snapshot.owned_permits, 0);
        assert_eq!(snapshot.listeners, 0);
    }

    #[tokio::test]
    async fn one_global_permit_bound_is_not_multiplied_by_shards() {
        let (listener, sender, accept_calls) = TestListener::new();
        sender.send(Ok(1)).expect("first connection");
        sender.send(Ok(2)).expect("second connection");
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            1,
            Duration::ZERO,
            registry.clone(),
            NonZeroUsize::new(2).expect("two shards"),
        )
        .expect("executor");
        let shutdown = Arc::new(Notify::new());
        let shutdown_request = Arc::clone(&shutdown);
        let observed_registry = registry.clone();

        let (result, ()) = tokio::join!(
            executor.run_until(
                |_connection, mut cancellation| async move {
                    cancellation.cancelled().await;
                },
                shutdown.notified(),
            ),
            async move {
                while observed_registry.snapshot().connection_tasks != 1 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(accept_calls.load(Ordering::SeqCst), 1);
                shutdown_request.notify_one();
            }
        );

        result.expect("controlled shutdown");
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.connection_tasks, 0);
        assert_eq!(snapshot.active_supervisor_children, 0);
        assert_eq!(snapshot.owned_permits, 0);
        assert_eq!(snapshot.listeners, 0);
    }

    #[tokio::test]
    async fn transient_accept_error_is_retried_on_the_accepting_runtime() {
        let (listener, sender, accept_calls) = TestListener::new();
        sender
            .send(Err(io::ErrorKind::Interrupted.into()))
            .expect("queue transient error");
        sender.send(Ok(7)).expect("queue connection");
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            1,
            Duration::from_secs(1),
            registry.clone(),
            NonZeroUsize::new(1).expect("one shard"),
        )
        .expect("executor");
        let complete = Arc::new(Notify::new());
        let handler_complete = Arc::clone(&complete);

        executor
            .run_until(
                move |connection, _cancellation| {
                    let complete = Arc::clone(&handler_complete);
                    async move {
                        assert_eq!(connection, 7);
                        complete.notify_one();
                    }
                },
                complete.notified(),
            )
            .await
            .expect("transient failure is retried");

        assert_eq!(accept_calls.load(Ordering::SeqCst), 2);
        assert_eq!(registry.snapshot().connection_tasks, 0);
    }

    #[tokio::test]
    async fn fatal_accept_cancels_live_handler_before_relative_force() {
        let (listener, sender, _accept_calls) = TestListener::new();
        sender.send(Ok(1)).expect("queue live connection");
        sender
            .send(Err(io::ErrorKind::PermissionDenied.into()))
            .expect("queue fatal accept error");
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            2,
            Duration::from_secs(1),
            registry.clone(),
            NonZeroUsize::new(1).expect("one shard"),
        )
        .expect("executor");
        let cancellations = Arc::new(AtomicUsize::new(0));
        let handler_cancellations = Arc::clone(&cancellations);

        let result = executor
            .run_until(
                move |_connection, mut cancellation| {
                    let cancellations = Arc::clone(&handler_cancellations);
                    async move {
                        cancellation.cancelled().await;
                        cancellations.fetch_add(1, Ordering::SeqCst);
                    }
                },
                pending::<()>(),
            )
            .await;

        assert_eq!(result, Err(SupervisorError::ListenerFailure));
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.forced_shutdowns, 0);
        assert_eq!(snapshot.connection_tasks, 0);
        assert_eq!(snapshot.active_supervisor_children, 0);
        assert_eq!(snapshot.owned_permits, 0);
        assert_eq!(snapshot.listeners, 0);
    }

    #[tokio::test]
    async fn handler_panic_is_a_child_failure_and_releases_all_owners() {
        let (listener, sender, _accept_calls) = TestListener::new();
        sender.send(Ok(1)).expect("queue connection");
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            1,
            Duration::ZERO,
            registry.clone(),
            NonZeroUsize::new(1).expect("one shard"),
        )
        .expect("executor");

        let result = executor
            .run_until(
                |_connection, _cancellation| async move {
                    panic!("intentional connection panic");
                },
                pending::<()>(),
            )
            .await;

        assert_eq!(result, Err(SupervisorError::ChildFailure));
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.connection_tasks, 0);
        assert_eq!(snapshot.active_supervisor_children, 0);
        assert_eq!(snapshot.owned_permits, 0);
        assert_eq!(snapshot.listeners, 0);
    }

    #[tokio::test]
    async fn handler_panic_counts_each_forced_sibling_once() {
        let (listener, sender, _accept_calls) = TestListener::new();
        sender.send(Ok(0)).expect("queue blocked connection");
        sender.send(Ok(1)).expect("queue panicking connection");
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            2,
            Duration::ZERO,
            registry.clone(),
            NonZeroUsize::new(1).expect("one shard"),
        )
        .expect("executor");

        let result = executor
            .run_until(
                |connection, _cancellation| async move {
                    if connection == 0 {
                        pending::<()>().await;
                    }
                    panic!("intentional connection panic");
                },
                pending::<()>(),
            )
            .await;

        assert_eq!(result, Err(SupervisorError::ChildFailure));
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.forced_shutdowns, 1);
        assert_eq!(snapshot.connection_tasks, 0);
        assert_eq!(snapshot.active_supervisor_children, 0);
        assert_eq!(snapshot.owned_permits, 0);
        assert_eq!(snapshot.listeners, 0);
    }

    #[tokio::test]
    async fn tcp_stream_reregistration_preserves_endpoints_nodelay_and_io() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let listen_address = listener.local_addr().expect("listener address");
        let registry = OwnerRegistry::new();
        let executor = AffineConnectionExecutor::with_shard_count(
            listener,
            1,
            Duration::from_secs(1),
            registry.clone(),
            NonZeroUsize::new(1).expect("one shard"),
        )
        .expect("executor");
        let client_address = Arc::new(Mutex::new(None::<SocketAddr>));
        let expected_client_address = Arc::clone(&client_address);
        let complete = Arc::new(Notify::new());
        let handler_complete = Arc::clone(&complete);

        let (result, ()) = tokio::join!(
            executor.run_until(
                move |mut stream, _cancellation| {
                    let expected_client_address = Arc::clone(&expected_client_address);
                    let complete = Arc::clone(&handler_complete);
                    async move {
                        let mut request = [0_u8; 4];
                        stream.read_exact(&mut request).await.expect("read request");
                        assert_eq!(&request, b"ping");
                        assert!(stream.nodelay().expect("read NODELAY"));
                        assert_eq!(stream.local_addr().expect("local endpoint"), listen_address);
                        assert_eq!(
                            stream.peer_addr().expect("peer endpoint"),
                            expected_client_address
                                .lock()
                                .expect("client endpoint")
                                .expect("published client endpoint")
                        );
                        stream.write_all(b"pong").await.expect("write response");
                        complete.notify_one();
                    }
                },
                complete.notified(),
            ),
            async move {
                let mut client = TcpStream::connect(listen_address)
                    .await
                    .expect("connect client");
                *client_address.lock().expect("client endpoint") =
                    Some(client.local_addr().expect("client local endpoint"));
                client.write_all(b"ping").await.expect("write request");
                let mut response = [0_u8; 4];
                client
                    .read_exact(&mut response)
                    .await
                    .expect("read response");
                assert_eq!(&response, b"pong");
            }
        );

        result.expect("controlled shutdown");
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.connection_tasks, 0);
        assert_eq!(snapshot.active_supervisor_children, 0);
        assert_eq!(snapshot.owned_permits, 0);
        assert_eq!(snapshot.listeners, 0);
    }
}
