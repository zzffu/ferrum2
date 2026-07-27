#![allow(dead_code)]

use std::collections::VecDeque;
use std::future::ready;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, LocalEndpoint, TargetAddr,
};
use ferrum2_crypto::{
    Aes128Psk, Clock, ClockError, KeyProvider, KeySelector, MonotonicInstant, RandomError,
    SecureRandom, SinglePskProvider, TcpMethod, TcpSalt, TcpSealer,
};
use ferrum2_shadowsocks::{HeaderIo, REQUEST_FIRST_READ_LEN, encode_request_first_write};

pub const NOW: u64 = 1_700_000_000;

pub fn provider() -> SinglePskProvider {
    SinglePskProvider::new(Aes128Psk::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]))
}

pub fn target() -> TargetAddr {
    TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)).expect("valid target")
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

#[derive(Default)]
pub struct IoObservation {
    pub read_calls: usize,
    pub read_lengths: Vec<usize>,
    pub write_calls: usize,
    pub write_lengths: Vec<usize>,
    pub abortive_calls: usize,
    pub endpoint_calls: usize,
    pub writes: Vec<Vec<u8>>,
}

pub struct RecordingIo {
    reads: VecDeque<Vec<u8>>,
    observation: Arc<Mutex<IoObservation>>,
    write_limit: Option<usize>,
    fail_read: bool,
    fail_write: bool,
    fail_abortive: bool,
    endpoint: SocketAddrV4,
}

impl RecordingIo {
    pub fn new(reads: impl IntoIterator<Item = Vec<u8>>) -> (Self, Arc<Mutex<IoObservation>>) {
        let observation = Arc::new(Mutex::new(IoObservation::default()));
        (
            Self {
                reads: reads.into_iter().collect(),
                observation: Arc::clone(&observation),
                write_limit: None,
                fail_read: false,
                fail_write: false,
                fail_abortive: false,
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152),
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

    pub fn with_read_failure(mut self) -> Self {
        self.fail_read = true;
        self
    }

    pub fn with_write_failure(mut self) -> Self {
        self.fail_write = true;
        self
    }

    pub fn with_abortive_failure(mut self) -> Self {
        self.fail_abortive = true;
        self
    }
}

impl HeaderIo for RecordingIo {
    type Error = ();

    fn read_header<'a>(
        &'a mut self,
        destination: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send {
        let mut observation = self.observation.lock().expect("observation lock");
        observation.read_calls += 1;
        observation.read_lengths.push(destination.len());
        if self.fail_read {
            return ready(Err(()));
        }
        let source = self.reads.pop_front().unwrap_or_default();
        let copied = source.len().min(destination.len());
        destination[..copied].copy_from_slice(&source[..copied]);
        ready(Ok(copied))
    }

    fn write_header<'a>(
        &'a mut self,
        source: &'a [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send {
        let mut observation = self.observation.lock().expect("observation lock");
        observation.write_calls += 1;
        observation.write_lengths.push(source.len());
        observation.writes.push(source.to_vec());
        if self.fail_write {
            return ready(Err(()));
        }
        ready(Ok(self
            .write_limit
            .unwrap_or(source.len())
            .min(source.len())))
    }
}

impl AbortiveClose for RecordingIo {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
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
}

impl RecordingConnector {
    pub fn succeeds(stream: RecordingIo) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            failure: None,
            calls: AtomicUsize::new(0),
        }
    }

    pub fn fails(kind: ConnectErrorKind) -> Self {
        Self {
            stream: Mutex::new(None),
            failure: Some(kind),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn fails_with_unreturned_stream(kind: ConnectErrorKind, stream: RecordingIo) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            failure: Some(kind),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Connector for RecordingConnector {
    type Stream = RecordingIo;

    fn connect(
        &self,
        _target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
