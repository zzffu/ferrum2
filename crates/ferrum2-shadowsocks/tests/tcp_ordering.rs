mod common;

use std::future::{Future, poll_fn};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, LocalEndpoint, Session, TargetAddr,
};
use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, REQUEST_FIRST_READ_LEN, ShadowsocksError,
    ShadowsocksTcpInbound, TcpReplayStore, TransportIo,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, SourceSentinel,
    client_random_bytes, custom_request_wire, provider, salt_with_last, server_target, target,
    valid_request_wire,
};

#[derive(Default)]
struct ClientOpenControl {
    connect_ready: AtomicBool,
    write_ready: AtomicBool,
    write_polls: AtomicUsize,
    completed_writes: AtomicUsize,
    abortive_calls: AtomicUsize,
    dropped_streams: AtomicUsize,
    targets: Mutex<Vec<TargetAddr>>,
    writes: Mutex<Vec<Vec<u8>>>,
}

struct ControlledClientIo {
    control: Arc<ClientOpenControl>,
    fail_write: bool,
}

impl Drop for ControlledClientIo {
    fn drop(&mut self) {
        self.control.dropped_streams.fetch_add(1, Ordering::SeqCst);
    }
}

impl AbortiveClose for ControlledClientIo {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.control.abortive_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl LocalEndpoint for ControlledClientIo {
    fn local_socket_addr(&self) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152).into()
    }
}

impl TransportIo for ControlledClientIo {
    type IoError = SourceSentinel;

    fn poll_read_buf(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _destination: &mut BytesMut,
        _limit: usize,
    ) -> Poll<Result<usize, Self::IoError>> {
        Poll::Ready(Ok(0))
    }

    fn poll_read_initialized(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Poll::Ready(Ok(0))
    }

    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        self.control.write_polls.fetch_add(1, Ordering::SeqCst);
        if !self.control.write_ready.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        self.control.completed_writes.fetch_add(1, Ordering::SeqCst);
        self.control
            .writes
            .lock()
            .expect("writes")
            .push(source.to_vec());
        if self.fail_write {
            Poll::Ready(Err(SourceSentinel))
        } else {
            Poll::Ready(Ok(source.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::IoError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Poll::Ready(Ok(()))
    }
}

struct ControlledClientConnector {
    control: Arc<ClientOpenControl>,
    stream: Mutex<Option<ControlledClientIo>>,
}

impl ControlledClientConnector {
    fn new(control: Arc<ClientOpenControl>, fail_write: bool) -> Self {
        Self {
            stream: Mutex::new(Some(ControlledClientIo {
                control: Arc::clone(&control),
                fail_write,
            })),
            control,
        }
    }
}

impl Connector for ControlledClientConnector {
    type Stream = ControlledClientIo;

    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        self.control
            .targets
            .lock()
            .expect("targets")
            .push(target.clone());
        poll_fn(move |_cx| {
            if !self.control.connect_ready.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            Poll::Ready(Ok(self
                .stream
                .lock()
                .expect("stream")
                .take()
                .expect("connector called once")))
        })
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[derive(Default)]
struct DownstreamEffects {
    accepted_sessions: usize,
    connector_calls: usize,
    forwarded_bytes: usize,
}

impl DownstreamEffects {
    fn consume<S, R>(&mut self, session: Session<S, R>) {
        self.accepted_sessions += 1;
        self.connector_calls += 1;
        self.forwarded_bytes += session.initial_payload.len();
    }
}

#[tokio::test]
async fn every_s0_through_s3_reject_precedes_all_downstream_and_replay_mutation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let valid = valid_request_wire(NOW, &salt_with_last(1));
    let mut fixed_auth = valid.clone();
    fixed_auth[20] ^= 1;
    let mut variable_auth = valid.clone();
    *variable_auth.last_mut().expect("variable tag") ^= 1;
    let bad_type = custom_request_wire(
        &salt_with_last(2),
        1,
        NOW,
        &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_time = custom_request_wire(
        &salt_with_last(3),
        0,
        NOW + 31,
        &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_address = custom_request_wire(
        &salt_with_last(4),
        0,
        NOW,
        &[2, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_padding = custom_request_wire(
        &salt_with_last(5),
        0,
        NOW,
        &[1, 127, 0, 0, 1, 0, 80, 0x03, 0x85],
    );
    let empty_request =
        custom_request_wire(&salt_with_last(6), 0, NOW, &[1, 127, 0, 0, 1, 0, 80, 0, 0]);
    let cases = vec![
        (
            "short fixed",
            RecordingIo::new([valid[..REQUEST_FIRST_READ_LEN - 1].to_vec()]).0,
            DetectionReason::ShortRead,
        ),
        (
            "fixed transport",
            RecordingIo::new([]).0.with_read_failure(),
            DetectionReason::ReadFailed,
        ),
        (
            "fixed auth",
            RecordingIo::new([fixed_auth[..REQUEST_FIRST_READ_LEN].to_vec()]).0,
            DetectionReason::Authentication,
        ),
        (
            "fixed type",
            RecordingIo::new([bad_type[..REQUEST_FIRST_READ_LEN].to_vec()]).0,
            DetectionReason::InvalidType,
        ),
        (
            "fixed time",
            RecordingIo::new([bad_time[..REQUEST_FIRST_READ_LEN].to_vec()]).0,
            DetectionReason::TimestampSkew,
        ),
        (
            "short variable",
            RecordingIo::new([
                valid[..REQUEST_FIRST_READ_LEN].to_vec(),
                valid[REQUEST_FIRST_READ_LEN..REQUEST_FIRST_READ_LEN + 1].to_vec(),
            ])
            .0,
            DetectionReason::ShortRead,
        ),
        (
            "variable auth",
            RecordingIo::request(&variable_auth).0,
            DetectionReason::Authentication,
        ),
        (
            "address semantics",
            RecordingIo::request(&bad_address).0,
            DetectionReason::AddressBounds,
        ),
        (
            "padding semantics",
            RecordingIo::request(&bad_padding).0,
            DetectionReason::PaddingBounds,
        ),
        (
            "empty semantics",
            RecordingIo::request(&empty_request).0,
            DetectionReason::EmptyRequest,
        ),
    ];

    for (name, io, expected) in cases {
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let mut effects = DownstreamEffects::default();

        let error = match inbound.accept_stream(io).await {
            Ok(session) => {
                effects.consume(session);
                panic!("{name}: reject unexpectedly returned a session");
            }
            Err(error) => error,
        };

        assert_eq!(
            error,
            ShadowsocksError::Detection(expected),
            "{name}: closed reason"
        );
        assert_eq!(
            (
                effects.connector_calls,
                effects.forwarded_bytes,
                effects.accepted_sessions,
                replay.entry_count().expect("replay snapshot"),
            ),
            (0, 0, 0, 0),
            "{name}: reject ordering"
        );
    }
}

#[tokio::test]
async fn valid_request_is_reserved_before_session_is_returned() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_with_last(2);
    let wire = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::request(&wire);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);

    let session = inbound
        .accept_stream(io)
        .await
        .expect("authenticated request");

    assert_eq!(session.target, target());
    assert!(session.initial_payload.is_empty());
    assert_eq!(replay.entry_count().expect("replay snapshot"), 1);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
}

#[tokio::test]
async fn connector_error_before_write() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::failing();
    let (unreturned_io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::fails_with_unreturned_stream(
        ConnectErrorKind::NetworkUnreachable,
        unreturned_io,
    );
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let error = outbound
        .connect_server()
        .await
        .err()
        .expect("connector failure");

    assert_eq!(
        error,
        ShadowsocksError::Connect(ConnectErrorKind::NetworkUnreachable)
    );
    assert_eq!(connector.call_count(), 1);
    assert_eq!(connector.targets(), vec![server_target()]);
    assert_eq!(observation.lock().expect("observation").write_calls, 0);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
}

#[tokio::test]
async fn connector_target_and_request_target() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_with_last(3);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let _flow = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("request first-write");

    assert_eq!(connector.targets(), vec![server_target()]);
    let wire = observation.lock().expect("observation").writes[0].clone();
    let (server_io, _) = RecordingIo::request(&wire);
    let server_random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let session = inbound
        .accept_stream(server_io)
        .await
        .expect("authenticated request");
    assert_eq!(session.target, target());
}

#[test]
fn client_open_phase_contract() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let application_target = target();

    let control = Arc::new(ClientOpenControl::default());
    let connector = ControlledClientConnector::new(Arc::clone(&control), false);
    let request_salt = salt_with_last(30);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let mut connect = Box::pin(outbound.connect_server());
    assert!(poll_once(connect.as_mut()).is_pending());
    assert_eq!(
        control.targets.lock().expect("targets").as_slice(),
        &[server_target()]
    );
    assert_eq!(control.write_polls.load(Ordering::SeqCst), 0);
    assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);

    control.connect_ready.store(true, Ordering::SeqCst);
    let phase = match poll_once(connect.as_mut()) {
        Poll::Ready(Ok(phase)) => phase,
        Poll::Ready(Err(error)) => panic!("connect failed: {error}"),
        Poll::Pending => panic!("connect did not complete"),
    };
    drop(connect);
    assert_eq!(control.write_polls.load(Ordering::SeqCst), 0);

    let mut request = Box::pin(phase.write_request(&application_target));
    assert!(poll_once(request.as_mut()).is_pending());
    assert_eq!(control.write_polls.load(Ordering::SeqCst), 1);
    assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);

    control.write_ready.store(true, Ordering::SeqCst);
    let flow = match poll_once(request.as_mut()) {
        Poll::Ready(Ok(flow)) => flow,
        Poll::Ready(Err(error)) => panic!("request first-write failed: {error}"),
        Poll::Pending => panic!("request first-write did not complete"),
    };
    drop(request);
    assert_eq!(control.completed_writes.load(Ordering::SeqCst), 1);
    let wire = control.writes.lock().expect("writes")[0].clone();
    let (server_io, _) = RecordingIo::request(&wire);
    let server_random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let mut accept = Box::pin(inbound.accept_stream(server_io));
    let session = match poll_once(accept.as_mut()) {
        Poll::Ready(Ok(session)) => session,
        Poll::Ready(Err(error)) => panic!("request decode failed: {error}"),
        Poll::Pending => panic!("request decode did not complete"),
    };
    assert_eq!(session.target, application_target);
    drop(flow);
    assert_eq!(control.dropped_streams.load(Ordering::SeqCst), 1);

    let cancelled_control = Arc::new(ClientOpenControl::default());
    cancelled_control
        .connect_ready
        .store(true, Ordering::SeqCst);
    let cancelled_connector = ControlledClientConnector::new(Arc::clone(&cancelled_control), false);
    let cancelled_random = ScriptedRandom::new(client_random_bytes(&salt_with_last(31)));
    let cancelled_outbound = ClientTcpOutbound::new(
        server_target(),
        &keys,
        &cancelled_connector,
        &clock,
        &cancelled_random,
    );
    let mut cancelled_connect = Box::pin(cancelled_outbound.connect_server());
    let cancelled_phase = match poll_once(cancelled_connect.as_mut()) {
        Poll::Ready(Ok(phase)) => phase,
        Poll::Ready(Err(error)) => panic!("connect failed: {error}"),
        Poll::Pending => panic!("connect did not complete"),
    };
    drop(cancelled_connect);
    let mut cancelled_request = Box::pin(cancelled_phase.write_request(&application_target));
    assert!(poll_once(cancelled_request.as_mut()).is_pending());
    drop(cancelled_request);
    assert_eq!(cancelled_control.dropped_streams.load(Ordering::SeqCst), 1);
    cancelled_control.write_ready.store(true, Ordering::SeqCst);
    assert_eq!(cancelled_control.completed_writes.load(Ordering::SeqCst), 0);

    let failure_control = Arc::new(ClientOpenControl::default());
    failure_control.connect_ready.store(true, Ordering::SeqCst);
    failure_control.write_ready.store(true, Ordering::SeqCst);
    let failure_connector = ControlledClientConnector::new(Arc::clone(&failure_control), true);
    let failure_random = ScriptedRandom::new(client_random_bytes(&salt_with_last(32)));
    let failure_outbound = ClientTcpOutbound::new(
        server_target(),
        &keys,
        &failure_connector,
        &clock,
        &failure_random,
    );
    let mut failure_connect = Box::pin(failure_outbound.connect_server());
    let failure_phase = match poll_once(failure_connect.as_mut()) {
        Poll::Ready(Ok(phase)) => phase,
        Poll::Ready(Err(error)) => panic!("connect failed: {error}"),
        Poll::Pending => panic!("connect did not complete"),
    };
    drop(failure_connect);
    let mut failed_request = Box::pin(failure_phase.write_request(&application_target));
    let error = match poll_once(failed_request.as_mut()) {
        Poll::Ready(Err(error)) => error,
        Poll::Ready(Ok(_)) => panic!("write failure returned a flow"),
        Poll::Pending => panic!("write failure did not complete"),
    };
    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::WriteFailed)
    );
    assert_eq!(failure_control.abortive_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn opened_stream_delegates_stored_local_endpoint_without_open_time_query() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_with_last(4);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let opened = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("request first-write");
    {
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.write_calls, 1);
        assert_eq!(observed.endpoint_calls, 0);
    }
    assert_eq!(opened.local_socket_addr().port(), 49152);
    assert_eq!(observation.lock().expect("observation").endpoint_calls, 1);
}
