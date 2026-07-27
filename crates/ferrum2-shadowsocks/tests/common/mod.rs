#![allow(dead_code)]

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::future::ready;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, LocalEndpoint, TargetAddr,
};
use ferrum2_crypto::{
    Aes128Psk, Clock, ClockError, KeyProvider, KeyProviderError, KeySelector, MonotonicInstant,
    RandomError, SecretKeyRef, SecureRandom, SinglePskProvider, TcpMethod, TcpSalt, TcpSealer,
};
use ferrum2_shadowsocks::{
    BufferObserver, BufferRole, FlowObserver, FlowTerminal, PlainDuplex, REQUEST_FIRST_READ_LEN,
    ShadowsocksError, TransportIo, encode_request_first_write,
};

pub const NOW: u64 = 1_700_000_000;

pub fn provider() -> SinglePskProvider {
    SinglePskProvider::new(Aes128Psk::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]))
}

pub struct CountingKeyProvider {
    inner: SinglePskProvider,
    calls: AtomicUsize,
}

impl CountingKeyProvider {
    pub fn new() -> Self {
        Self {
            inner: provider(),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl KeyProvider for CountingKeyProvider {
    type Error = KeyProviderError;

    fn with_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(SecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.with_key(selector, use_key)
    }
}

pub fn target() -> TargetAddr {
    TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)).expect("valid target")
}

pub fn server_target() -> TargetAddr {
    TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)).expect("valid server")
}

pub fn salt_with_last(last: u8) -> TcpSalt {
    let mut salt = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x00,
    ];
    salt[15] = last;
    TcpSalt::from_bytes(salt)
}

pub fn salt_from_u64(value: u64) -> TcpSalt {
    let mut salt = [0x5a; 16];
    salt[8..].copy_from_slice(&value.to_be_bytes());
    TcpSalt::from_bytes(salt)
}

pub fn valid_request_wire(timestamp: u64, salt: &TcpSalt) -> Vec<u8> {
    encode_request_first_write(&provider(), salt, timestamp, &target(), &[0xa1], &[])
        .expect("valid request")
        .to_vec()
}

pub fn custom_request_wire(
    salt: &TcpSalt,
    message_type: u8,
    timestamp: u64,
    variable: &[u8],
) -> Vec<u8> {
    let mut fixed = BytesMut::with_capacity(11);
    fixed.extend_from_slice(&[message_type]);
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    let mut variable = BytesMut::from(variable);
    provider()
        .with_key(KeySelector::Default, |key| {
            let mut sealer =
                TcpSealer::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, salt));
            sealer.seal_in_place(&mut fixed).expect("fixture fixed");
            sealer
                .seal_in_place(&mut variable)
                .expect("fixture variable");
        })
        .expect("default key");
    let mut wire = salt.as_bytes().to_vec();
    wire.extend_from_slice(&fixed);
    wire.extend_from_slice(&variable);
    wire
}

pub fn seal_data_frame(sealer: &mut TcpSealer, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut length = BytesMut::from(&(payload.len() as u16).to_be_bytes()[..]);
    let mut payload = BytesMut::from(payload);
    sealer.seal_in_place(&mut length).expect("seal length");
    sealer.seal_in_place(&mut payload).expect("seal payload");
    (length.to_vec(), payload.to_vec())
}

pub fn request_data_frames(salt: &TcpSalt, payloads: &[&[u8]]) -> Vec<Vec<u8>> {
    let variable = [1, 127, 0, 0, 1, 0x1f, 0x90, 0, 1, 0xa1];
    let mut fixed = BytesMut::new();
    fixed.extend_from_slice(&[0]);
    fixed.extend_from_slice(&NOW.to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    let mut variable = BytesMut::from(&variable[..]);
    let mut sealer = provider()
        .with_key(KeySelector::Default, |key| {
            TcpSealer::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, salt))
        })
        .expect("default key");
    sealer.seal_in_place(&mut fixed).expect("fixed");
    sealer.seal_in_place(&mut variable).expect("variable");
    payloads
        .iter()
        .flat_map(|payload| {
            let (length, payload) = seal_data_frame(&mut sealer, payload);
            [length, payload]
        })
        .collect()
}

pub fn response_wire_and_frames(
    request_salt: &TcpSalt,
    response_salt: &TcpSalt,
    first_payload: &[u8],
    subsequent: &[&[u8]],
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let wire = ferrum2_shadowsocks::encode_response_first_write(
        &provider(),
        response_salt,
        NOW,
        request_salt,
        first_payload,
    )
    .expect("response wire")
    .to_vec();
    let mut fixed = BytesMut::new();
    fixed.extend_from_slice(&[1]);
    fixed.extend_from_slice(&NOW.to_be_bytes());
    fixed.extend_from_slice(request_salt.as_bytes());
    fixed.extend_from_slice(&(first_payload.len() as u16).to_be_bytes());
    let mut first = BytesMut::from(first_payload);
    let mut sealer = provider()
        .with_key(KeySelector::Default, |key| {
            TcpSealer::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, response_salt))
        })
        .expect("default key");
    sealer.seal_in_place(&mut fixed).expect("fixed");
    sealer.seal_in_place(&mut first).expect("first");
    let frames = subsequent
        .iter()
        .flat_map(|payload| {
            let (length, payload) = seal_data_frame(&mut sealer, payload);
            [length, payload]
        })
        .collect();
    (wire, frames)
}

pub fn custom_response_wire(
    response_salt: &TcpSalt,
    message_type: u8,
    timestamp: u64,
    bound_request_salt: &TcpSalt,
    first_payload: &[u8],
) -> Vec<u8> {
    let mut fixed = BytesMut::new();
    fixed.extend_from_slice(&[message_type]);
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(bound_request_salt.as_bytes());
    fixed.extend_from_slice(&(first_payload.len() as u16).to_be_bytes());
    let mut payload = BytesMut::from(first_payload);
    provider()
        .with_key(KeySelector::Default, |key| {
            let mut sealer = TcpSealer::new(
                key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, response_salt),
            );
            sealer.seal_in_place(&mut fixed).expect("response fixed");
            sealer
                .seal_in_place(&mut payload)
                .expect("response payload");
        })
        .expect("default key");
    let mut wire = response_salt.as_bytes().to_vec();
    wire.extend_from_slice(&fixed);
    wire.extend_from_slice(&payload);
    wire
}

#[derive(Default)]
pub struct IoObservation {
    pub read_calls: usize,
    pub read_lengths: Vec<usize>,
    pub write_calls: usize,
    pub write_lengths: Vec<usize>,
    pub flush_calls: usize,
    pub shutdown_calls: usize,
    pub abortive_calls: usize,
    pub endpoint_calls: usize,
    pub writes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub struct SourceSentinel;

impl fmt::Debug for SourceSentinel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sentinel-source-debug")
    }
}

impl fmt::Display for SourceSentinel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sentinel-source-display")
    }
}

impl Error for SourceSentinel {}

pub struct RecordingIo {
    reads: VecDeque<Vec<u8>>,
    observation: Arc<Mutex<IoObservation>>,
    write_limit: Option<usize>,
    write_limit_after: Option<(usize, usize)>,
    pending_reads: usize,
    pending_writes: usize,
    fail_read: bool,
    fail_read_after: Option<usize>,
    fail_write: bool,
    fail_write_after: Option<usize>,
    fail_flush: bool,
    fail_shutdown: bool,
    fail_abortive: bool,
    endpoint: SocketAddrV4,
    sequence: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl RecordingIo {
    pub fn new(reads: impl IntoIterator<Item = Vec<u8>>) -> (Self, Arc<Mutex<IoObservation>>) {
        let observation = Arc::new(Mutex::new(IoObservation::default()));
        (
            Self {
                reads: reads.into_iter().collect(),
                observation: Arc::clone(&observation),
                write_limit: None,
                write_limit_after: None,
                pending_reads: 0,
                pending_writes: 0,
                fail_read: false,
                fail_read_after: None,
                fail_write: false,
                fail_write_after: None,
                fail_flush: false,
                fail_shutdown: false,
                fail_abortive: false,
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152),
                sequence: None,
            },
            observation,
        )
    }

    pub fn request(wire: &[u8]) -> (Self, Arc<Mutex<IoObservation>>) {
        Self::new([
            wire[..REQUEST_FIRST_READ_LEN].to_vec(),
            wire[REQUEST_FIRST_READ_LEN..].to_vec(),
        ])
    }

    pub fn with_write_limit(mut self, limit: usize) -> Self {
        self.write_limit = Some(limit);
        self
    }

    pub fn with_write_limit_after(mut self, successful_writes: usize, limit: usize) -> Self {
        self.write_limit_after = Some((successful_writes, limit));
        self
    }

    pub fn with_read_failure(mut self) -> Self {
        self.fail_read = true;
        self
    }

    pub fn with_read_failure_after(mut self, successful_reads: usize) -> Self {
        self.fail_read_after = Some(successful_reads);
        self
    }

    pub fn with_pending_reads(mut self, polls: usize) -> Self {
        self.pending_reads = polls;
        self
    }

    pub fn with_pending_writes(mut self, polls: usize) -> Self {
        self.pending_writes = polls;
        self
    }

    pub fn with_write_failure(mut self) -> Self {
        self.fail_write = true;
        self
    }

    pub fn with_write_failure_after(mut self, successful_writes: usize) -> Self {
        self.fail_write_after = Some(successful_writes);
        self
    }

    pub fn with_flush_failure(mut self) -> Self {
        self.fail_flush = true;
        self
    }

    pub fn with_shutdown_failure(mut self) -> Self {
        self.fail_shutdown = true;
        self
    }

    pub fn with_abortive_failure(mut self) -> Self {
        self.fail_abortive = true;
        self
    }

    pub fn with_sequence(mut self, sequence: Arc<Mutex<Vec<&'static str>>>) -> Self {
        self.sequence = Some(sequence);
        self
    }
}

impl TransportIo for RecordingIo {
    type IoError = SourceSentinel;

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        if self.pending_reads > 0 {
            self.pending_reads -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut observation = self.observation.lock().expect("observation lock");
        observation.read_calls += 1;
        observation.read_lengths.push(destination.len());
        if self.fail_read
            || self
                .fail_read_after
                .is_some_and(|successful| observation.read_calls > successful)
        {
            return Poll::Ready(Err(SourceSentinel));
        }
        drop(observation);
        let source = self.reads.pop_front().unwrap_or_default();
        let copied = source.len().min(destination.len());
        destination[..copied].copy_from_slice(&source[..copied]);
        if copied < source.len() {
            self.reads.push_front(source[copied..].to_vec());
        }
        Poll::Ready(Ok(copied))
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        if self.pending_writes > 0 {
            self.pending_writes -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut observation = self.observation.lock().expect("observation lock");
        observation.write_calls += 1;
        observation.write_lengths.push(source.len());
        observation.writes.push(source.to_vec());
        if self.fail_write
            || self
                .fail_write_after
                .is_some_and(|successful| observation.write_calls > successful)
        {
            return Poll::Ready(Err(SourceSentinel));
        }
        let limit = self
            .write_limit_after
            .filter(|(successful, _)| observation.write_calls > *successful)
            .map(|(_, limit)| limit)
            .or(self.write_limit)
            .unwrap_or(source.len());
        Poll::Ready(Ok(limit.min(source.len())))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::IoError>> {
        self.observation.lock().expect("observation").flush_calls += 1;
        if self.fail_flush {
            Poll::Ready(Err(SourceSentinel))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        self.observation.lock().expect("observation").shutdown_calls += 1;
        if self.fail_shutdown {
            Poll::Ready(Err(SourceSentinel))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AbortiveClose for RecordingIo {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        if let Some(sequence) = &self.sequence {
            sequence.lock().expect("sequence").push("abortive");
        }
        self.observation
            .lock()
            .expect("observation lock")
            .abortive_calls += 1;
        if self.fail_abortive { Err(()) } else { Ok(()) }
    }
}

impl LocalEndpoint for RecordingIo {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.observation
            .lock()
            .expect("observation lock")
            .endpoint_calls += 1;
        self.endpoint
    }
}

pub struct RecordingConnector {
    stream: Mutex<Option<RecordingIo>>,
    failure: Option<ConnectErrorKind>,
    calls: AtomicUsize,
    targets: Mutex<Vec<TargetAddr>>,
}

impl RecordingConnector {
    pub fn succeeds(stream: RecordingIo) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            failure: None,
            calls: AtomicUsize::new(0),
            targets: Mutex::new(Vec::new()),
        }
    }

    pub fn fails(kind: ConnectErrorKind) -> Self {
        Self {
            stream: Mutex::new(None),
            failure: Some(kind),
            calls: AtomicUsize::new(0),
            targets: Mutex::new(Vec::new()),
        }
    }

    pub fn fails_with_unreturned_stream(kind: ConnectErrorKind, stream: RecordingIo) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            failure: Some(kind),
            calls: AtomicUsize::new(0),
            targets: Mutex::new(Vec::new()),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn targets(&self) -> Vec<TargetAddr> {
        self.targets.lock().expect("targets").clone()
    }
}

impl Connector for RecordingConnector {
    type Stream = RecordingIo;

    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.targets.lock().expect("targets").push(target.clone());
        let result = if let Some(kind) = self.failure {
            Err(ConnectError::new(kind))
        } else {
            Ok(self
                .stream
                .lock()
                .expect("connector lock")
                .take()
                .expect("connector called once"))
        };
        ready(result)
    }
}

pub struct FakeClock {
    wall: AtomicU64,
    monotonic_millis: AtomicU64,
    fail_wall: bool,
}

impl FakeClock {
    pub fn new(wall: u64, monotonic_millis: u64) -> Self {
        Self {
            wall: AtomicU64::new(wall),
            monotonic_millis: AtomicU64::new(monotonic_millis),
            fail_wall: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            wall: AtomicU64::new(0),
            monotonic_millis: AtomicU64::new(0),
            fail_wall: true,
        }
    }

    pub fn set_wall(&self, wall: u64) {
        self.wall.store(wall, Ordering::SeqCst);
    }

    pub fn set_monotonic_millis(&self, millis: u64) {
        self.monotonic_millis.store(millis, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn unix_seconds(&self) -> Result<u64, ClockError> {
        if self.fail_wall {
            Err(ClockError::Unavailable)
        } else {
            Ok(self.wall.load(Ordering::SeqCst))
        }
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant::from_duration(Duration::from_millis(
            self.monotonic_millis.load(Ordering::SeqCst),
        ))
    }
}

pub struct ScriptedRandom {
    bytes: Mutex<VecDeque<u8>>,
    fail: bool,
}

impl ScriptedRandom {
    pub fn new(bytes: impl IntoIterator<Item = u8>) -> Self {
        Self {
            bytes: Mutex::new(bytes.into_iter().collect()),
            fail: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            bytes: Mutex::new(VecDeque::new()),
            fail: true,
        }
    }
}

impl SecureRandom for ScriptedRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        if self.fail {
            return Err(RandomError::Unavailable);
        }
        let mut bytes = self.bytes.lock().expect("random lock");
        for destination_byte in destination {
            *destination_byte = bytes.pop_front().expect("scripted random byte");
        }
        Ok(())
    }
}

pub fn client_random_bytes(request_salt: &TcpSalt) -> Vec<u8> {
    let mut bytes = request_salt.as_bytes().to_vec();
    bytes.extend_from_slice(&[0, 0]);
    bytes.push(0xa1);
    bytes
}

pub async fn read_plain(
    flow: &mut (impl PlainDuplex + ?Sized),
    destination: &mut [u8],
) -> Result<usize, ShadowsocksError> {
    std::future::poll_fn(|cx| Pin::new(&mut *flow).poll_read_plain(cx, destination)).await
}

pub async fn write_plain(
    flow: &mut (impl PlainDuplex + ?Sized),
    source: &[u8],
) -> Result<usize, ShadowsocksError> {
    std::future::poll_fn(|cx| Pin::new(&mut *flow).poll_write_plain(cx, source)).await
}

pub async fn flush_plain(flow: &mut (impl PlainDuplex + ?Sized)) -> Result<(), ShadowsocksError> {
    std::future::poll_fn(|cx| Pin::new(&mut *flow).poll_flush_plain(cx)).await
}

pub async fn shutdown_plain(
    flow: &mut (impl PlainDuplex + ?Sized),
) -> Result<(), ShadowsocksError> {
    std::future::poll_fn(|cx| Pin::new(&mut *flow).poll_shutdown_plain(cx)).await
}

#[derive(Default)]
pub struct RecordingObservers {
    pub buffers: Mutex<Vec<(BufferRole, usize, usize)>>,
    pub inspections: Mutex<Vec<(BufferRole, usize)>>,
    pub capacities: Mutex<Vec<(BufferRole, usize, usize)>>,
    pub terminals: Mutex<Vec<FlowTerminal>>,
    pub sequence: Arc<Mutex<Vec<&'static str>>>,
}

impl BufferObserver for RecordingObservers {
    fn allocated(&self, role: BufferRole, usable_limit: usize, storage_identity: usize) {
        self.buffers
            .lock()
            .expect("buffers")
            .push((role, usable_limit, storage_identity));
    }

    fn inspected(&self, role: BufferRole, storage_identity: usize) {
        self.inspections
            .lock()
            .expect("inspections")
            .push((role, storage_identity));
    }

    fn capacity_inspected(&self, role: BufferRole, storage_identity: usize, capacity: usize) {
        self.capacities
            .lock()
            .expect("capacities")
            .push((role, storage_identity, capacity));
    }
}

impl FlowObserver for RecordingObservers {
    fn terminal_installed(&self, terminal: FlowTerminal) {
        self.terminals.lock().expect("terminals").push(terminal);
        self.sequence.lock().expect("sequence").push("terminal");
    }
}
