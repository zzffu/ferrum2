#![cfg(feature = "tokio")]

mod common;

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, ConnectError, Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{MethodProfile, MethodSinglePskProvider};
use ferrum2_shadowsocks::tokio::{
    FusedRelayDirection, TokioTransport, relay_client_flow, relay_server_flow,
};
use ferrum2_shadowsocks::{
    ClientFlow, ClientTcpOutbound, MethodKeyAdapter, ShadowsocksTcpInbound, TcpReplayStore,
    TransportIo,
};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralCounter, StructuralHub};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use common::{
    FakeClock, NOW, RecordingIo, ScriptedRandom, SourceSentinel, client_random_bytes,
    method_provider, method_salt_from_u64, server_target, target, valid_request_wire_for,
};

struct EndpointIo {
    inner: tokio::io::DuplexStream,
    endpoint: SocketAddr,
}

impl AsyncRead for EndpointIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for EndpointIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, source)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AbortiveClose for EndpointIo {
    type Error = io::Error;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl LocalEndpoint for EndpointIo {
    fn local_socket_addr(&self) -> SocketAddr {
        self.endpoint
    }
}

struct OneConnector(Mutex<Option<TokioTransport<EndpointIo>>>);

impl Connector for OneConnector {
    type Stream = TokioTransport<EndpointIo>;

    fn connect(
        &self,
        _target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        ready(Ok(self
            .0
            .lock()
            .expect("connector lock")
            .take()
            .expect("connector used once")))
    }
}

struct SequencedIo {
    inner: RecordingIo,
    sequence: Arc<Mutex<Vec<&'static str>>>,
    successful_writes: usize,
    pending_after_handshake: bool,
    returned_pending: bool,
    pending_shutdowns: usize,
    shutdown_polls: Arc<AtomicUsize>,
}

impl TransportIo for SequencedIo {
    type IoError = SourceSentinel;

    fn poll_read_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut BytesMut,
        limit: usize,
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut self.inner).poll_read_buf(cx, destination, limit)
    }

    fn poll_read_initialized(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut self.inner).poll_read_initialized(cx, destination)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        if self.pending_after_handshake && self.successful_writes != 0 && !self.returned_pending {
            self.returned_pending = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = Pin::new(&mut self.inner).poll_write(cx, source);
        if matches!(result, Poll::Ready(Ok(_))) {
            self.successful_writes += 1;
            self.sequence.lock().expect("sequence").push("WRITE");
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        self.shutdown_polls.fetch_add(1, Ordering::SeqCst);
        if self.pending_shutdowns != 0 {
            self.pending_shutdowns -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AbortiveClose for SequencedIo {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.inner.mark_abortive()
    }
}

impl LocalEndpoint for SequencedIo {
    fn local_socket_addr(&self) -> SocketAddr {
        self.inner.local_socket_addr()
    }
}

struct SequencedConnector(Mutex<Option<SequencedIo>>);

impl Connector for SequencedConnector {
    type Stream = SequencedIo;

    fn connect(
        &self,
        _target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        ready(Ok(self
            .0
            .lock()
            .expect("connector lock")
            .take()
            .expect("connector used once")))
    }
}

struct AlwaysReadyPlain {
    reads: VecDeque<Vec<u8>>,
    sequence: Arc<Mutex<Vec<&'static str>>>,
    read_count: Arc<AtomicUsize>,
    read_polls: Arc<AtomicUsize>,
    shutdown_polls: Arc<AtomicUsize>,
    pending_shutdowns: usize,
}

impl AsyncRead for AlwaysReadyPlain {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_polls.fetch_add(1, Ordering::SeqCst);
        let Some(source) = self.reads.pop_front() else {
            return Poll::Ready(Ok(()));
        };
        assert!(source.len() <= buffer.remaining());
        buffer.put_slice(&source);
        self.read_count.fetch_add(1, Ordering::SeqCst);
        self.sequence.lock().expect("sequence").push("READ");
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AlwaysReadyPlain {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(source.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown_polls.fetch_add(1, Ordering::SeqCst);
        if self.pending_shutdowns != 0 {
            self.pending_shutdowns -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn fused_round_trip_covers_all_ciphers_and_boundary_payloads() {
    for (profile_index, profile) in MethodProfile::ALL.into_iter().enumerate() {
        for payload_len in [1, 32 * 1024] {
            fused_round_trip(profile, profile_index as u64, payload_len).await;
        }
    }
}

#[tokio::test]
async fn always_ready_upload_alternates_read_and_complete_wire_write() {
    let sequence = Arc::new(Mutex::new(Vec::new()));
    let read_count = Arc::new(AtomicUsize::new(0));
    let mut flow = sequenced_client_flow(
        Arc::clone(&sequence),
        false,
        None,
        0,
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    sequence.lock().expect("sequence").clear();
    let mut plain = AlwaysReadyPlain {
        reads: [vec![0x11; 4096], vec![0x22; 4096], vec![0x33; 4096]].into(),
        sequence: Arc::clone(&sequence),
        read_count: Arc::clone(&read_count),
        read_polls: Arc::new(AtomicUsize::new(0)),
        shutdown_polls: Arc::new(AtomicUsize::new(0)),
        pending_shutdowns: 0,
    };
    #[cfg(feature = "structural-metrics")]
    let structural = StructuralHub::new().local();
    let mut relay = Box::pin(relay_client_flow(
        &mut plain,
        &mut flow,
        |_, _| {},
        #[cfg(feature = "structural-metrics")]
        &structural,
    ));
    let mut cx = Context::from_waker(std::task::Waker::noop());

    for _ in 0..3 {
        assert!(matches!(relay.as_mut().poll(&mut cx), Poll::Pending));
    }
    assert_eq!(read_count.load(Ordering::SeqCst), 3);
    assert_eq!(
        *sequence.lock().expect("sequence"),
        ["READ", "WRITE", "READ", "WRITE", "READ", "WRITE"]
    );
}

#[tokio::test]
async fn pending_and_partial_wire_drain_never_reads_ahead() {
    let sequence = Arc::new(Mutex::new(Vec::new()));
    let read_count = Arc::new(AtomicUsize::new(0));
    let mut flow = sequenced_client_flow(
        Arc::clone(&sequence),
        true,
        Some(257),
        0,
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    sequence.lock().expect("sequence").clear();
    let mut plain = AlwaysReadyPlain {
        reads: [vec![0x44; 32 * 1024], vec![0x55]].into(),
        sequence: Arc::clone(&sequence),
        read_count: Arc::clone(&read_count),
        read_polls: Arc::new(AtomicUsize::new(0)),
        shutdown_polls: Arc::new(AtomicUsize::new(0)),
        pending_shutdowns: 0,
    };
    let progressed = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&progressed);
    #[cfg(feature = "structural-metrics")]
    let structural_hub = StructuralHub::new();
    #[cfg(feature = "structural-metrics")]
    let structural = structural_hub.local();
    let mut relay = Box::pin(relay_client_flow(
        &mut plain,
        &mut flow,
        move |direction, bytes| {
            if direction == FusedRelayDirection::PlainToTunnel {
                observed.fetch_add(bytes, Ordering::SeqCst);
            }
        },
        #[cfg(feature = "structural-metrics")]
        &structural,
    ));
    let mut cx = Context::from_waker(std::task::Waker::noop());

    assert!(matches!(relay.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(progressed.load(Ordering::SeqCst), 0);
    assert!(matches!(relay.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(
        progressed.load(Ordering::SeqCst),
        0,
        "partial wire is not plaintext progress"
    );
    for _ in 0..14 {
        assert!(matches!(relay.as_mut().poll(&mut cx), Poll::Pending));
        if read_count.load(Ordering::SeqCst) == 2 {
            break;
        }
    }
    assert_eq!(read_count.load(Ordering::SeqCst), 2);
    let sequence = sequence.lock().expect("sequence");
    assert_eq!(sequence.first(), Some(&"READ"));
    assert!(sequence.windows(2).all(|events| events != ["READ", "READ"]));
    assert!(sequence.iter().filter(|event| **event == "WRITE").count() > 1);
    drop(sequence);
    drop(relay);
    #[cfg(feature = "structural-metrics")]
    {
        let snapshot = structural_hub.snapshot();
        assert_eq!(snapshot.get(StructuralCounter::FtbrOwnedUploadFrames), 2);
        assert_eq!(
            snapshot.get(StructuralCounter::FtbrBorrowedDownloadFrames),
            0
        );
        assert_eq!(snapshot.get(StructuralCounter::FtbrFrames), 2);
        assert!(snapshot.get(StructuralCounter::FtbrPartialWrites) > 0);
        assert_eq!(
            snapshot.get(StructuralCounter::FtbrEncryptBufferCapacityBytes),
            ferrum2_shadowsocks::INITIAL_ENCRYPT_WIRE_LEN as u64
        );
        assert_eq!(
            snapshot.get(StructuralCounter::FtbrDecryptBufferCapacityBytes),
            ferrum2_shadowsocks::MAX_DECRYPT_WIRE_LEN as u64
        );
        assert_eq!(
            snapshot.get(StructuralCounter::TcpPlainToEncryptCopyBytes),
            0
        );
        assert_eq!(
            snapshot.get(StructuralCounter::TcpDecryptToPlainCopyBytes),
            0
        );
    }
}

#[tokio::test]
async fn server_raw_eof_before_first_response_sends_no_wire() {
    let keys = method_provider(MethodProfile::Blake3Aes128Gcm2022);
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::failing();
    let replay = TcpReplayStore::new(1024).expect("replay capacity");
    let request_salt = method_salt_from_u64(MethodProfile::Blake3Aes128Gcm2022, 60);
    let request = valid_request_wire_for(&keys, NOW, &request_salt);
    let (io, observation) = RecordingIo::request(&request);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound
        .accept_stream(io)
        .await
        .expect("server request")
        .stream;
    let read_polls = Arc::new(AtomicUsize::new(0));
    let shutdown_polls = Arc::new(AtomicUsize::new(0));
    let mut plain = AlwaysReadyPlain {
        reads: VecDeque::new(),
        sequence: Arc::new(Mutex::new(Vec::new())),
        read_count: Arc::new(AtomicUsize::new(0)),
        read_polls: Arc::clone(&read_polls),
        shutdown_polls: Arc::clone(&shutdown_polls),
        pending_shutdowns: 1,
    };

    #[cfg(feature = "structural-metrics")]
    let structural = StructuralHub::new().local();
    relay_server_flow(
        &mut plain,
        &mut flow,
        |_, _| {},
        #[cfg(feature = "structural-metrics")]
        &structural,
    )
    .await
    .expect("clean raw EOF");

    assert_eq!(observation.lock().expect("observation").write_calls, 0);
    assert_eq!(read_polls.load(Ordering::SeqCst), 1);
    assert_eq!(shutdown_polls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn pending_upload_shutdown_never_repolls_raw_eof() {
    let sequence = Arc::new(Mutex::new(Vec::new()));
    let tunnel_shutdown_polls = Arc::new(AtomicUsize::new(0));
    let mut flow =
        sequenced_client_flow(sequence, false, None, 1, Arc::clone(&tunnel_shutdown_polls)).await;
    let read_polls = Arc::new(AtomicUsize::new(0));
    let mut plain = AlwaysReadyPlain {
        reads: VecDeque::new(),
        sequence: Arc::new(Mutex::new(Vec::new())),
        read_count: Arc::new(AtomicUsize::new(0)),
        read_polls: Arc::clone(&read_polls),
        shutdown_polls: Arc::new(AtomicUsize::new(0)),
        pending_shutdowns: 0,
    };
    #[cfg(feature = "structural-metrics")]
    let structural = StructuralHub::new().local();
    let mut relay = Box::pin(relay_client_flow(
        &mut plain,
        &mut flow,
        |_, _| {},
        #[cfg(feature = "structural-metrics")]
        &structural,
    ));
    let mut cx = Context::from_waker(std::task::Waker::noop());

    for _ in 0..3 {
        assert!(matches!(relay.as_mut().poll(&mut cx), Poll::Pending));
    }
    assert_eq!(read_polls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel_shutdown_polls.load(Ordering::SeqCst), 2);
}

async fn sequenced_client_flow(
    sequence: Arc<Mutex<Vec<&'static str>>>,
    pending_after_handshake: bool,
    write_limit: Option<usize>,
    pending_shutdowns: usize,
    shutdown_polls: Arc<AtomicUsize>,
) -> ClientFlow<'static, SequencedIo, MethodKeyAdapter<MethodSinglePskProvider>, FakeClock> {
    let keys = Box::leak(Box::new(method_provider(
        MethodProfile::Blake3Aes128Gcm2022,
    )));
    let clock = Box::leak(Box::new(FakeClock::new(NOW, 0)));
    let request_salt = method_salt_from_u64(MethodProfile::Blake3Aes128Gcm2022, 50);
    let random = Box::leak(Box::new(ScriptedRandom::new(client_random_bytes(
        &request_salt,
    ))));
    let (inner, _) = RecordingIo::new([]);
    let inner = inner.with_pending_reads(usize::MAX);
    let inner = match write_limit {
        Some(limit) => inner.with_write_limit_after(1, limit),
        None => inner,
    };
    let connector = Box::leak(Box::new(SequencedConnector(Mutex::new(Some(
        SequencedIo {
            inner,
            sequence,
            successful_writes: 0,
            pending_after_handshake,
            returned_pending: false,
            pending_shutdowns,
            shutdown_polls,
        },
    )))));
    let outbound = ClientTcpOutbound::new(server_target(), keys, connector, clock, random);
    outbound
        .connect_server()
        .await
        .expect("client connect")
        .write_request(&target())
        .await
        .expect("client request")
}

async fn fused_round_trip(profile: MethodProfile, profile_index: u64, payload_len: usize) {
    let keys = method_provider(profile);
    let clock = FakeClock::new(NOW, 0);
    let request_salt = method_salt_from_u64(profile, 10 + profile_index * 10 + payload_len as u64);
    let response_salt = method_salt_from_u64(profile, 11 + profile_index * 10 + payload_len as u64);
    let client_random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let server_random = ScriptedRandom::new(response_salt.as_bytes().iter().copied());
    let replay = TcpReplayStore::new(1024).expect("replay capacity");

    let tunnel_capacity = 4 * ferrum2_shadowsocks::MAX_ENCRYPT_WIRE_LEN;
    let (client_tunnel, server_tunnel) = tokio::io::duplex(tunnel_capacity);
    let connector = OneConnector(Mutex::new(Some(TokioTransport::new(EndpointIo {
        inner: client_tunnel,
        endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_001).into(),
    }))));
    let outbound =
        ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &client_random);
    let mut client_flow = outbound
        .connect_server()
        .await
        .expect("client connect")
        .write_request(&target())
        .await
        .expect("client request");

    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let session = inbound
        .accept_stream(TokioTransport::new(EndpointIo {
            inner: server_tunnel,
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_002).into(),
        }))
        .await
        .expect("server request");
    assert!(session.initial_payload.is_empty());
    let mut server_flow = session.stream;

    let raw_capacity = 4 * 32 * 1024;
    let (mut client_plain, mut application) = tokio::io::duplex(raw_capacity);
    let (mut server_plain, mut target_peer) = tokio::io::duplex(raw_capacity);
    let client_progress = Arc::new(Mutex::new(Vec::new()));
    let server_progress = Arc::new(Mutex::new(Vec::new()));
    let client_observation = Arc::clone(&client_progress);
    let server_observation = Arc::clone(&server_progress);
    let upload = vec![0x5a; payload_len];
    let response = vec![0xa5; payload_len];
    let expected_upload = upload.clone();
    let expected_response = response.clone();
    #[cfg(feature = "structural-metrics")]
    let structural_hub = StructuralHub::new();
    #[cfg(feature = "structural-metrics")]
    let client_structural = structural_hub.local();
    #[cfg(feature = "structural-metrics")]
    let server_structural = structural_hub.local();

    let client_relay = relay_client_flow(
        &mut client_plain,
        &mut client_flow,
        move |direction, bytes| {
            client_observation
                .lock()
                .expect("client progress")
                .push((direction, bytes));
        },
        #[cfg(feature = "structural-metrics")]
        &client_structural,
    );
    let server_relay = relay_server_flow(
        &mut server_plain,
        &mut server_flow,
        move |direction, bytes| {
            server_observation
                .lock()
                .expect("server progress")
                .push((direction, bytes));
        },
        #[cfg(feature = "structural-metrics")]
        &server_structural,
    );
    let exchange = async move {
        application.write_all(&upload).await.expect("upload");
        application
            .shutdown()
            .await
            .expect("application half-close");

        let mut received_upload = vec![0; expected_upload.len()];
        target_peer
            .read_exact(&mut received_upload)
            .await
            .expect("target upload");
        assert_eq!(received_upload, expected_upload);
        target_peer.write_all(&response).await.expect("response");
        target_peer.shutdown().await.expect("target half-close");

        let mut received_response = vec![0; expected_response.len()];
        application
            .read_exact(&mut received_response)
            .await
            .expect("application response");
        assert_eq!(received_response, expected_response);
    };

    let (client_result, server_result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client_relay, server_relay, exchange)
    })
    .await
    .expect("fused relay timeout");
    client_result.expect("client fused relay");
    server_result.expect("server fused relay");

    assert_eq!(
        progress_total(&client_progress, FusedRelayDirection::PlainToTunnel),
        payload_len
    );
    assert_eq!(
        progress_total(&client_progress, FusedRelayDirection::TunnelToPlain),
        payload_len
    );
    assert_eq!(
        progress_total(&server_progress, FusedRelayDirection::PlainToTunnel),
        payload_len
    );
    assert_eq!(
        progress_total(&server_progress, FusedRelayDirection::TunnelToPlain),
        payload_len
    );
    #[cfg(feature = "structural-metrics")]
    {
        let snapshot = structural_hub.snapshot();
        assert_eq!(snapshot.get(StructuralCounter::FtbrOwnedUploadFrames), 2);
        assert_eq!(
            snapshot.get(StructuralCounter::FtbrBorrowedDownloadFrames),
            2
        );
        assert_eq!(snapshot.get(StructuralCounter::FtbrFrames), 4);
        assert_eq!(
            snapshot.get(StructuralCounter::TcpPlainToEncryptCopyBytes),
            0
        );
        assert_eq!(
            snapshot.get(StructuralCounter::TcpDecryptToPlainCopyBytes),
            0
        );
    }
}

fn progress_total(
    progress: &Mutex<Vec<(FusedRelayDirection, usize)>>,
    direction: FusedRelayDirection,
) -> usize {
    progress
        .lock()
        .expect("progress")
        .iter()
        .filter(|(observed, _)| *observed == direction)
        .map(|(_, bytes)| *bytes)
        .sum()
}
