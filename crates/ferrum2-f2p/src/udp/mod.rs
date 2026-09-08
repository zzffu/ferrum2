//! Multiplexed fixed-target datagrams with owned drivers and partitioned memory budgets.
//!
//! Initial policies (not benchmark-derived): Balanced uses 256 KiB/session,
//! 250 ms residence and 32-frame/256-KiB write turns; Realtime uses 128 KiB,
//! 25 ms and 4-frame/16-KiB turns. A single indivisible frame may exceed a
//! turn's byte ceiling. Only ready packets are batched, with round-robin sessions.
//! The supplied partition includes 4096 base bytes, 2048 bytes per live session,
//! exact boxed payload allocations plus 256 bytes per packet (including empty
//! packets and in-flight frames), and 65764 global bytes for one server receive scratch.
//! Linked queues release nodes on removal; no retained spare capacity is hidden.
//! Socket/TLS buffers and Tokio task allocator overhead are external overhead.
//! Overflow drops uncommitted incoming DATA, fails client send with WouldBlock,
//! and closes the tunnel if a required control cannot be admitted.
//! Datagrams are limited to 65507 bytes, matching the existing UDP runtime.
use crate::{Profile, wire};
use ferrum2_core::TargetAddr;
use std::{
    collections::{BTreeMap, LinkedList},
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};

mod framing;
mod receive;
mod server;
use framing::{client_reader, maintenance, read_frame, write_loop};
pub use server::serve_udp;

const OPEN: u8 = 1;
const OPEN_RESULT: u8 = 2;
const DATA: u8 = 3;
const CLOSE: u8 = 4;
const PING: u8 = 5;
const PONG: u8 = 6;
const MAX_DATA: usize = 65507;
const PACKET_OVERHEAD: usize = 256;
const SESSION_OVERHEAD: usize = 2048;
const BASE_OVERHEAD: usize = 4096;
const MAX_CONTROLS: usize = 64;
const STALL: Duration = Duration::from_secs(10);

/// A reserved partition of the adapter's application-buffer budget.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_sessions: usize,
    pub max_buffered_bytes: usize,
    pub idle_timeout: Duration,
}

/// Injected routing and destination creation. The driver sends `first_payload` itself.
/// Implementors reserve aggregate capacity before an OPEN worker is created.
/// A reservation must release capacity on drop; successful connect transfers
/// that ownership to the returned socket until its session closes.
pub trait UdpBackend: Send + Sync + 'static {
    type Socket: UdpSocket;
    type Reservation: Send + 'static;
    fn reserve_session(&self) -> io::Result<Self::Reservation>;
    fn connect(
        &self,
        reservation: Self::Reservation,
        target: &TargetAddr,
        first_payload: &[u8],
    ) -> impl Future<Output = io::Result<Self::Socket>> + Send;
}
/// A connected, fixed-peer datagram socket; receiving an empty datagram returns zero.
pub trait UdpSocket: Send + Sync + 'static {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn send(&self, payload: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    /// Waits without consuming a datagram or retaining a receive buffer.
    fn readable(&self) -> impl Future<Output = io::Result<()>> + Send;
    /// Receives immediately, returning WouldBlock on false readiness and rearming
    /// the next readiness wait. Zero is a valid empty datagram, not EOF.
    /// The driver supplies 65508 bytes to detect datagrams above the 65507 limit;
    /// adapters must not silently truncate them to the protocol limit.
    fn try_receive(&self, destination: &mut [u8]) -> io::Result<usize>;
}
#[derive(Clone, Copy)]
struct Policy {
    session_bytes: usize,
    residence: Duration,
    turn_bytes: usize,
    turn_frames: usize,
}
impl Policy {
    fn new(profile: Profile) -> Self {
        match profile {
            Profile::Balanced => Self {
                session_bytes: 256 * 1024,
                residence: Duration::from_millis(250),
                turn_bytes: 256 * 1024,
                turn_frames: 32,
            },
            Profile::Realtime => Self {
                session_bytes: 128 * 1024,
                residence: Duration::from_millis(25),
                turn_bytes: 16 * 1024,
                turn_frames: 4,
            },
        }
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "F2P UDP session closed")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid F2P UDP frame")
}
fn full() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "F2P UDP buffer partition exhausted",
    )
}
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
struct Budget {
    used: AtomicUsize,
    maximum: usize,
}
impl Budget {
    fn take(self: &Arc<Self>, bytes: usize) -> io::Result<Reservation> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| full())?;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }
}
struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
struct Charge {
    _global: Reservation,
    _session: Option<Reservation>,
}
struct Packet {
    kind: u8,
    id: u32,
    body: Box<[u8]>,
    created: Instant,
    _charge: Charge,
}
struct SessionState {
    outbound: LinkedList<Packet>,
    inbound: LinkedList<Packet>,
    peer: Option<SocketAddr>,
    last: Instant,
    receiver: Option<Waker>,
}
struct Session {
    id: u32,
    state: Mutex<SessionState>,
    budget: Arc<Budget>,
    notify: Notify,
    cancelled: AtomicBool,
    cancel: Notify,
    _charge: Charge,
}
impl Session {
    fn stop(&self) {
        self.cancelled.store(true, Ordering::Release);
        let mut state = lock(&self.state);
        state.outbound.clear();
        state.inbound.clear();
        if let Some(waker) = state.receiver.take() {
            waker.wake();
        }
        self.notify.notify_waiters();
        self.cancel.notify_waiters();
    }
    async fn cancelled(&self) {
        loop {
            let notified = self.cancel.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}
struct State {
    sessions: BTreeMap<u32, Arc<Session>>,
    controls: LinkedList<Packet>,
    next: u32,
}
struct Shared {
    state: Mutex<State>,
    budget: Arc<Budget>,
    policy: Policy,
    limits: Limits,
    closed: AtomicBool,
    wake: Notify,
    cancel: Notify,
    _base: Reservation,
    _resources: Box<dyn Send + Sync>,
}
impl Shared {
    fn new<R: Send + Sync + 'static>(
        profile: Profile,
        limits: Limits,
        resources: R,
    ) -> io::Result<Arc<Self>> {
        if limits.max_sessions == 0 || limits.idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid F2P UDP limits",
            ));
        }
        let budget = Arc::new(Budget {
            used: AtomicUsize::new(0),
            maximum: limits.max_buffered_bytes,
        });
        let base = budget.take(BASE_OVERHEAD)?;
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                sessions: BTreeMap::new(),
                controls: LinkedList::new(),
                next: 1,
            }),
            budget,
            policy: Policy::new(profile),
            limits,
            closed: AtomicBool::new(false),
            wake: Notify::new(),
            cancel: Notify::new(),
            _base: base,
            _resources: Box::new(resources),
        }))
    }
    fn charge(&self, session: Option<&Session>, bytes: usize) -> io::Result<Charge> {
        Ok(Charge {
            _global: self.budget.take(bytes)?,
            _session: session.map(|s| s.budget.take(bytes)).transpose()?,
        })
    }
    fn packet(
        &self,
        session: Option<&Session>,
        kind: u8,
        id: u32,
        body: &[u8],
    ) -> io::Result<Packet> {
        let charge = self.charge(session, body.len() + PACKET_OVERHEAD)?;
        Ok(Packet {
            kind,
            id,
            body: body.into(),
            created: Instant::now(),
            _charge: charge,
        })
    }
    fn insert(&self, state: &mut State, id: u32) -> io::Result<Arc<Session>> {
        if state.sessions.len() >= self.limits.max_sessions {
            return Err(full());
        }
        let session = Arc::new(Session {
            id,
            state: Mutex::new(SessionState {
                outbound: LinkedList::new(),
                inbound: LinkedList::new(),
                peer: None,
                last: Instant::now(),
                receiver: None,
            }),
            budget: Arc::new(Budget {
                used: AtomicUsize::new(0),
                maximum: self.policy.session_bytes,
            }),
            notify: Notify::new(),
            cancelled: AtomicBool::new(false),
            cancel: Notify::new(),
            _charge: self.charge(None, SESSION_OVERHEAD)?,
        });
        state.sessions.insert(id, session.clone());
        Ok(session)
    }
    fn control(&self, kind: u8, id: u32, body: &[u8]) -> io::Result<()> {
        let packet = self.packet(None, kind, id, body)?;
        let mut state = lock(&self.state);
        if state.controls.len() >= MAX_CONTROLS {
            return Err(full());
        }
        state.controls.push_back(packet);
        self.wake.notify_one();
        Ok(())
    }
    fn remove(&self, id: u32, notify: bool) {
        let session = lock(&self.state).sessions.remove(&id);
        if let Some(session) = session {
            session.stop();
            if notify && self.control(CLOSE, id, &[]).is_err() {
                self.stop();
            }
        }
    }
    fn stop(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let mut state = lock(&self.state);
            for session in state.sessions.values() {
                session.stop();
            }
            state.sessions.clear();
            state.controls.clear();
            self.cancel.notify_waiters();
            self.wake.notify_waiters();
        }
    }
    async fn cancelled(&self) {
        loop {
            let notified = self.cancel.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
    fn enqueue(&self, session: &Session, packet: Packet, outbound: bool) -> io::Result<()> {
        let mut state = lock(&session.state);
        if session.cancelled.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        state.last = Instant::now();
        let queue = if outbound {
            &mut state.outbound
        } else {
            &mut state.inbound
        };
        while queue
            .front()
            .is_some_and(|p| p.kind == DATA && p.created.elapsed() > self.policy.residence)
        {
            queue.pop_front();
        }
        queue.push_back(packet);
        if let Some(waker) = state.receiver.take() {
            waker.wake();
        }
        session.notify.notify_waiters();
        self.wake.notify_one();
        Ok(())
    }
}

/// Sole owner of a client tunnel's driver. Sessions cannot keep the driver alive.
pub struct ClientTunnel {
    shared: Arc<Shared>,
    driver: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    abort: tokio::task::AbortHandle,
}
impl ClientTunnel {
    /// Retains the caller's aggregate reservation until every driver/session drops.
    pub fn start<S, R>(
        stream: S,
        profile: Profile,
        limits: Limits,
        resources: R,
    ) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        R: Send + Sync + 'static,
    {
        let shared = Shared::new(profile, limits, resources)?;
        let owner = shared.clone();
        let driver = tokio::spawn(async move {
            let (reader, writer) = tokio::io::split(stream);
            tokio::select! { _ = client_reader(reader, owner.clone()) => {}, _ = write_loop(writer, owner.clone()) => {}, _ = maintenance(owner.clone()) => {}, _ = owner.cancelled() => {} }
            owner.stop();
        });
        let abort = driver.abort_handle();
        Ok(Self {
            shared,
            driver: tokio::sync::Mutex::new(Some(driver)),
            abort,
        })
    }
    pub async fn open(&self, target: TargetAddr) -> io::Result<ClientSession> {
        if self.is_closed() {
            return Err(closed());
        }
        let mut state = lock(&self.shared.state);
        // Serialize this bounded encoding allocation within the base reservation.
        let mut body = Vec::with_capacity(wire::MAX_TARGET_LEN);
        wire::encode_target(&target, &mut body);
        if self.is_closed() {
            return Err(closed());
        }
        let id = state.next;
        if id == 0 {
            drop(state);
            self.close();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "F2P UDP session IDs exhausted",
            ));
        }
        state.next = id.checked_add(1).unwrap_or(0);
        let session = self.shared.insert(&mut state, id)?;
        let packet = match self.shared.packet(Some(&session), OPEN, id, &body) {
            Ok(packet) => packet,
            Err(error) => {
                state.sessions.remove(&id);
                return Err(error);
            }
        };
        lock(&session.state).outbound.push_back(packet);
        self.shared.wake.notify_one();
        Ok(ClientSession {
            shared: self.shared.clone(),
            session,
        })
    }
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        self.shared.stop();
        self.abort.abort();
    }

    /// Cancels and joins the driver before the caller checks process ownership.
    /// Concurrent shutdown calls serialize; cancelling a wait retains join custody.
    pub async fn shutdown(&self) -> io::Result<()> {
        self.close();
        let mut driver = self.driver.lock().await;
        let result = match driver.as_mut() {
            Some(driver) => driver.await,
            None => return Ok(()),
        };
        driver.take();
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(_) => Err(io::Error::other("F2P UDP driver failed")),
        }
    }
}
impl Drop for ClientTunnel {
    fn drop(&mut self) {
        self.close();
    }
}
/// A fixed-target session; dropping it discards queued packets without replay.
pub struct ClientSession {
    shared: Arc<Shared>,
    session: Arc<Session>,
}
impl ClientSession {
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "F2P UDP datagram too large",
            ));
        }
        if self.is_closed() {
            return Err(closed());
        }
        let packet = self
            .shared
            .packet(Some(&self.session), DATA, self.session.id, payload)?;
        self.shared.enqueue(&self.session, packet, true)
    }
    pub async fn receive(&mut self, destination: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| self.poll_receive(cx, destination)).await
    }
    /// Poll without a per-session scratch allocation, allowing adapters to fairly
    /// scan many sessions with one bounded receive buffer.
    pub fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut state = lock(&self.session.state);
        if self.is_closed() {
            return Poll::Ready(Err(closed()));
        }
        if let Some(peer) = state.peer {
            while let Some(packet) = state.inbound.pop_front() {
                if packet.created.elapsed() > self.shared.policy.residence {
                    continue;
                }
                let count = destination.len().min(packet.body.len());
                destination[..count].copy_from_slice(&packet.body[..count]);
                return Poll::Ready(Ok((count, peer)));
            }
        }
        if !state
            .receiver
            .as_ref()
            .is_some_and(|w| w.will_wake(cx.waker()))
        {
            state.receiver = Some(cx.waker().clone());
        }
        Poll::Pending
    }
    pub fn is_closed(&self) -> bool {
        self.session.cancelled.load(Ordering::Acquire) || self.shared.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        self.shared.remove(self.session.id, true);
    }
}
impl Drop for ClientSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
