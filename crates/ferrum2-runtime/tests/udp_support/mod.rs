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

pub(crate) fn limits(max_sessions: usize) -> UdpRuntimeLimits {
    UdpRuntimeLimits::new(
        max_sessions,
        MIN_UDP_MAX_BUFFERED_BYTES,
        MIN_UDP_IDLE_TIMEOUT,
    )
    .expect("valid test limits")
}

pub(crate) fn selection_destination() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9))
}

pub(crate) fn ip_datagram(payload: &'static [u8]) -> Datagram {
    Datagram::new(
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("non-zero target"),
        BytesMut::from(payload),
        payload.len(),
    )
    .expect("bounded datagram")
}

pub(crate) fn ip_datagram_with_capacity(payload: &[u8], capacity: usize) -> Datagram {
    let mut owned = BytesMut::with_capacity(capacity);
    owned.extend_from_slice(payload);
    Datagram::new(
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("non-zero target"),
        owned,
        capacity,
    )
    .expect("bounded datagram")
}

pub(crate) fn domain_datagram(payload: &'static [u8]) -> Datagram {
    Datagram::new(
        TargetAddr::domain("example.test", 53).expect("bounded target"),
        BytesMut::from(payload),
        payload.len(),
    )
    .expect("bounded datagram")
}

pub(crate) fn committed_session(
    manager: &UdpSessionManager,
    now: Instant,
    payload: &'static [u8],
) -> UdpSessionHandle {
    let session = manager.reserve_session(now).expect("session capacity");
    let reservation = session
        .reserve_datagram(UdpDirection::ToTarget, payload.len())
        .expect("datagram capacity");
    session
        .commit(reservation, ip_datagram(payload), now)
        .expect("commit session")
}

pub(crate) struct ScriptedResolver {
    pub(crate) delay: Duration,
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) calls: Arc<AtomicUsize>,
}

impl UdpResolver for ScriptedResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.candidates.clone())
    }
}

#[derive(Clone)]
pub(crate) struct FailingOnCallResolver {
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) fail_on_call: usize,
    pub(crate) calls: Arc<AtomicUsize>,
}

impl UdpResolver for FailingOnCallResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_on_call {
            Err(io::Error::other("injected configured resolver failure"))
        } else {
            Ok(self.candidates.clone())
        }
    }
}

#[derive(Clone)]
pub(crate) struct ScriptedSocket {
    pub(crate) send_delay: Duration,
    pub(crate) send_failures: Arc<Mutex<VecDeque<bool>>>,
    pub(crate) sends: Arc<Mutex<Vec<SocketAddr>>>,
    pub(crate) send_completed: Arc<Notify>,
    pub(crate) responses: SharedResponses,
    pub(crate) response_ready: Arc<Notify>,
}

type SharedResponses = Arc<Mutex<VecDeque<(Vec<u8>, SocketAddr)>>>;

impl DirectUdpSocket for ScriptedSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.sends.lock().expect("send lock").push(target);
        tokio::time::sleep(self.send_delay).await;
        self.send_completed.notify_one();
        if self
            .send_failures
            .lock()
            .expect("failure lock")
            .pop_front()
            .unwrap_or(false)
        {
            Err(io::Error::other("scripted send failure"))
        } else {
            Ok(payload.len())
        }
    }

    async fn readable(&self) -> io::Result<()> {
        if !self.responses.lock().expect("response lock").is_empty() {
            return Ok(());
        }
        self.response_ready.notified().await;
        Ok(())
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        loop {
            if let Some((response, source)) =
                self.responses.lock().expect("response lock").pop_front()
            {
                payload.extend_from_slice(&response);
                return Ok((response.len(), source));
            }
            self.response_ready.notified().await;
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let Some((response, source)) = self.responses.lock().expect("response lock").pop_front()
        else {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        payload.extend_from_slice(&response);
        Ok((response.len(), source))
    }
}

#[derive(Clone)]
pub(crate) struct ScriptedFactory {
    pub(crate) socket: ScriptedSocket,
    pub(crate) opens: Arc<AtomicUsize>,
    pub(crate) selections: Arc<Mutex<Vec<SocketAddr>>>,
}

impl DirectUdpSocketFactory for ScriptedFactory {
    type Socket = ScriptedSocket;
    type OpenContext = ();

    async fn open(&self, (): (), selection_destination: SocketAddr) -> io::Result<Self::Socket> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.selections
            .lock()
            .expect("selection destinations")
            .push(selection_destination);
        Ok(self.socket.clone())
    }
}

#[derive(Clone)]
pub(crate) struct ContextRecordingFactory {
    pub(crate) inner: ScriptedFactory,
    pub(crate) contexts: Arc<Mutex<Vec<u64>>>,
}

impl DirectUdpSocketFactory for ContextRecordingFactory {
    type Socket = ScriptedSocket;
    type OpenContext = u64;

    async fn open(
        &self,
        context: Self::OpenContext,
        selection_destination: SocketAddr,
    ) -> io::Result<Self::Socket> {
        self.contexts.lock().expect("open contexts").push(context);
        self.inner.open((), selection_destination).await
    }
}

#[derive(Clone, Default)]
pub(crate) struct RecordingHandler {
    pub(crate) responses: Arc<Mutex<Vec<Vec<u8>>>>,
    pub(crate) entered: Arc<Notify>,
    pub(crate) block: bool,
}

impl DirectUdpPacketHandler for RecordingHandler {
    type Error = ();

    async fn handle_target_response(
        &self,
        _session: UdpSessionHandle,
        response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        self.responses
            .lock()
            .expect("handler lock")
            .push(response.datagram().payload().to_vec());
        self.entered.notify_one();
        if self.block {
            pending::<()>().await;
        }
        Ok(())
    }
}

type ScriptedRuntime = DirectUdpRuntime<ScriptedResolver, ScriptedFactory, RecordingHandler>;

pub(crate) struct UdpProcessRoot(pub(crate) ScriptedRuntime);

impl PreparedProcessRoot<()> for UdpProcessRoot {
    fn activate(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), ()>> {
        Box::pin(async move {
            cancellation.cancelled().await;
            self.0.shutdown_with_cancellation(cancellation).await;
            Ok(())
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), ()>> {
        Box::pin(async move {
            self.0.shutdown(Duration::ZERO).await;
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(crate) struct FailingGateHandler {
    pub(crate) entered: Arc<Notify>,
    pub(crate) release: Arc<Notify>,
}

impl DirectUdpPacketHandler for FailingGateHandler {
    type Error = ();

    async fn handle_target_response(
        &self,
        _session: UdpSessionHandle,
        _response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        self.entered.notify_one();
        self.release.notified().await;
        Err(())
    }
}

pub(crate) fn socket_fixture(
    delay: Duration,
    failures: impl IntoIterator<Item = bool>,
) -> (ScriptedSocket, Arc<Mutex<Vec<SocketAddr>>>) {
    let sends = Arc::new(Mutex::new(Vec::new()));
    (
        ScriptedSocket {
            send_delay: delay,
            send_failures: Arc::new(Mutex::new(failures.into_iter().collect())),
            sends: Arc::clone(&sends),
            send_completed: Arc::new(Notify::new()),
            responses: Arc::new(Mutex::new(VecDeque::new())),
            response_ready: Arc::new(Notify::new()),
        },
        sends,
    )
}

pub(crate) fn recording_runtime(
    registry: &OwnerRegistry,
    resolver: ScriptedResolver,
    socket: ScriptedSocket,
    send_timeout: Duration,
    block: bool,
) -> (ScriptedRuntime, Arc<Notify>) {
    let entered = Arc::new(Notify::new());
    let runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        send_timeout,
        resolver,
        scripted_factory(socket),
        RecordingHandler {
            responses: Arc::new(Mutex::new(Vec::new())),
            entered: Arc::clone(&entered),
            block,
        },
        registry.clone(),
    );
    (runtime, entered)
}

pub(crate) fn empty_resolver() -> ScriptedResolver {
    ScriptedResolver {
        delay: Duration::ZERO,
        candidates: Vec::new(),
        calls: Arc::new(AtomicUsize::new(0)),
    }
}

pub(crate) fn scripted_factory(socket: ScriptedSocket) -> ScriptedFactory {
    ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
        selections: Arc::new(Mutex::new(Vec::new())),
    }
}

pub(crate) fn shared_runtime(
    manager: UdpSessionManager,
    registry: &OwnerRegistry,
    socket: ScriptedSocket,
) -> ScriptedRuntime {
    DirectUdpRuntime::with_shared_adapters(
        manager,
        Duration::from_secs(1),
        empty_resolver(),
        scripted_factory(socket),
        RecordingHandler::default(),
        registry.clone(),
    )
}

pub(crate) async fn wait_for_zero_udp_owners(registry: &OwnerRegistry) {
    for _ in 0..200 {
        let snapshot = registry.snapshot();
        if snapshot.udp_sessions == 0
            && snapshot.udp_sockets == 0
            && snapshot.udp_tasks == 0
            && snapshot.udp_queued_datagrams == 0
            && snapshot.udp_buffered_bytes == 0
            && snapshot.udp_scratch_buffers == 0
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("UDP owners did not return to baseline");
}
