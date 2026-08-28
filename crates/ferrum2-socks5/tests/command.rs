use ferrum2_core::{ConnectErrorKind, SessionReply, TargetAddr};
use ferrum2_socks5::{Socks5Inbound, SocksCommand, SocksConnect, SocksError};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

const METHOD: &[u8] = &[5, 0];
const GENERAL: &[u8] = &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0];
const DENIED: &[u8] = &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0];
const NETWORK: &[u8] = &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
const HOST: &[u8] = &[5, 4, 0, 1, 0, 0, 0, 0, 0, 0];
const REFUSED: &[u8] = &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
const COMMAND: &[u8] = &[5, 7, 0, 1, 0, 0, 0, 0, 0, 0];
const ADDRESS: &[u8] = &[5, 8, 0, 1, 0, 0, 0, 0, 0, 0];
#[tokio::test]
async fn connect_rows_keep_targets_replies_and_stream_exact() {
    let (mut client, server) = tokio::io::duplex(128);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept_command(server).await });
    fragmented(&mut client, &[5, 1, 0]).await;
    assert_eq!(
        read::<2>(&mut client).await,
        METHOD,
        "fragmented-ipv4 method"
    );
    fragmented(&mut client, &[5, 1, 0, 1, 192, 0, 2, 10, 0x1f, 0x90]).await;
    let SocksCommand::Connect(accepted) = task.await.unwrap().unwrap() else {
        panic!("fragmented IPv4 CONNECT command")
    };
    let (target, pending) = accepted.into_parts();
    assert_eq!(target, ip("192.0.2.10:8080"), "ipv4 target");
    let mut stream = pending
        .succeeded_socket("127.0.0.7:49152".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        read::<10>(&mut client).await,
        [5, 0, 0, 1, 127, 0, 0, 7, 0xc0, 0],
        "ipv4 reply"
    );
    client.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ping", "inbound stream");
    stream.write_all(b"pong").await.unwrap();
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"pong", "outbound stream");

    let bound = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
    for (case, suffix, target) in [
        (
            "ipv6",
            [
                vec![4],
                Ipv6Addr::LOCALHOST.octets().to_vec(),
                vec![1, 0xbb],
            ]
            .concat(),
            ip("[::1]:443"),
        ),
        (
            "domain",
            [vec![3, 12], b"example.test".to_vec(), vec![1, 0xbb]].concat(),
            TargetAddr::domain("example.test", 443).unwrap(),
        ),
    ] {
        let (mut client, connect) = connect(&wire(1, &suffix)).await;
        let (actual_target, pending) = connect.into_parts();
        assert_eq!(actual_target, target, "{case} target");
        let _stream = pending
            .succeeded_socket(SocketAddr::V6(SocketAddrV6::new(bound, 49_152, 0, 0)))
            .await
            .unwrap();
        let reply = read::<22>(&mut client).await;
        assert_eq!(&reply[..4], &[5, 0, 0, 4], "{case} reply header");
        assert_eq!(&reply[4..20], &bound.octets(), "{case} reply address");
        assert_eq!(&reply[20..], &[0xc0, 0], "{case} reply port");
    }
}

#[tokio::test]
async fn connect_negative_rows_keep_every_exact_byte() {
    let selected = |reply: &[u8]| [METHOD, reply].concat();
    let full = wire(1, &[1, 127, 0, 0, 1, 0, 80]);
    let rows = vec![
        (
            "greeting-version",
            vec![4, 1, 0],
            vec![],
            SocksError::Malformed,
        ),
        (
            "greeting-zero-methods",
            vec![5, 0],
            vec![],
            SocksError::Malformed,
        ),
        (
            "greeting-short-header",
            vec![5],
            vec![],
            SocksError::Malformed,
        ),
        (
            "greeting-short-methods",
            vec![5, 2, 0],
            vec![],
            SocksError::Malformed,
        ),
        (
            "request-version",
            [vec![5, 1, 0, 4], full[4..].to_vec()].concat(),
            METHOD.to_vec(),
            SocksError::Malformed,
        ),
        (
            "request-rsv",
            [vec![5, 1, 0, 5, 1, 1], full[6..].to_vec()].concat(),
            METHOD.to_vec(),
            SocksError::Malformed,
        ),
        (
            "request-short-header",
            vec![5, 1, 0, 5, 1, 0],
            METHOD.to_vec(),
            SocksError::Malformed,
        ),
        (
            "request-short-ipv4",
            vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0],
            METHOD.to_vec(),
            SocksError::Malformed,
        ),
        (
            "method-rejection",
            vec![5, 3, 1, 2, 0x80],
            vec![5, 0xff],
            SocksError::NoAcceptableMethod,
        ),
        (
            "connect-atyp",
            wire(1, &[0x7f]),
            selected(ADDRESS),
            SocksError::AddressTypeNotSupported,
        ),
        (
            "connect-domain-empty",
            wire(1, &[3, 0, 0, 80]),
            selected(GENERAL),
            SocksError::InvalidTarget,
        ),
        (
            "connect-domain-nonascii",
            wire(1, &[3, 2, 0xc3, 0xa9, 0, 80]),
            selected(GENERAL),
            SocksError::InvalidTarget,
        ),
        (
            "connect-domain-zero-port",
            wire(1, &[3, 1, b'a', 0, 0]),
            selected(GENERAL),
            SocksError::InvalidTarget,
        ),
        (
            "connect-ipv4-zero-port",
            wire(1, &[1, 127, 0, 0, 1, 0, 0]),
            selected(GENERAL),
            SocksError::InvalidTarget,
        ),
    ];
    for (case, input, output, error) in rows {
        rejected(case, &input, &output, error).await;
    }
}

#[tokio::test]
async fn connect_failure_replies_are_mapped_and_exactly_once() {
    for (case, kind, expected) in [
        ("network", ConnectErrorKind::NetworkUnreachable, NETWORK),
        ("host", ConnectErrorKind::HostUnreachable, HOST),
        ("refused", ConnectErrorKind::ConnectionRefused, REFUSED),
        ("policy-denied", ConnectErrorKind::PolicyDenied, DENIED),
        ("timeout", ConnectErrorKind::Timeout, GENERAL),
        ("other", ConnectErrorKind::Other, GENERAL),
    ] {
        let (mut client, connect) = connect(&wire(1, &[1, 192, 0, 2, 10, 0, 80])).await;
        let (_, pending) = connect.into_parts();
        pending.failed(kind).await.unwrap();
        let mut actual = Vec::new();
        client.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected, "reply-{case}");
    }
}

#[tokio::test]
async fn connect_success_returns_owned_io_after_half_close_and_drops_it_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut client, server) = tokio::io::duplex(128);
    let tracked = DropTrackedIo {
        io: server,
        drops: Arc::clone(&drops),
    };
    let accepted = tokio::spawn(async move { Socks5Inbound::new().accept_command(tracked).await });
    client
        .write_all(&wire(1, &[1, 192, 0, 2, 10, 0, 80]))
        .await
        .expect("CONNECT request");
    assert_eq!(read::<2>(&mut client).await, METHOD);
    let SocksCommand::Connect(connect) = accepted.await.expect("accept join").expect("CONNECT")
    else {
        panic!("CONNECT command")
    };
    client.shutdown().await.expect("client write half-close");
    let (_, pending) = connect.into_parts();
    let mut owned = pending
        .succeeded_socket("127.0.0.1:49152".parse().expect("bound address"))
        .await
        .expect("success reply after client half-close");
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        read::<10>(&mut client).await,
        [5, 0, 0, 1, 127, 0, 0, 1, 0xc0, 0]
    );

    let mut eof = [0_u8; 1];
    assert_eq!(owned.read(&mut eof).await.expect("owned read EOF"), 0);
    owned
        .write_all(b"after-half-close")
        .await
        .expect("owned write after read EOF");
    let mut payload = [0_u8; 16];
    client
        .read_exact(&mut payload)
        .await
        .expect("client reads after half-close");
    assert_eq!(&payload, b"after-half-close");
    drop(owned);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_partial_success_and_failure_replies_close_exactly_once() {
    let input = wire(1, &[1, 192, 0, 2, 10, 0, 80]);

    let success_output = Arc::new(Mutex::new(Vec::new()));
    let success_drops = Arc::new(AtomicUsize::new(0));
    let success_polls = Arc::new(AtomicUsize::new(0));
    let command = Socks5Inbound::new()
        .accept_command(ScriptedIo::new(
            input.clone(),
            Arc::clone(&success_output),
            Arc::clone(&success_drops),
            Arc::clone(&success_polls),
            1,
            None,
        ))
        .await
        .expect("partial success CONNECT");
    let SocksCommand::Connect(connect) = command else {
        panic!("partial success CONNECT command")
    };
    let (_, pending) = connect.into_parts();
    let owned = pending
        .succeeded_socket("127.0.0.7:49152".parse().expect("success bound"))
        .await
        .expect("fragmented success reply");
    assert_eq!(
        *success_output.lock().expect("success output"),
        [METHOD, &[5, 0, 0, 1, 127, 0, 0, 7, 0xc0, 0]].concat()
    );
    assert_eq!(success_drops.load(Ordering::SeqCst), 0);
    drop(owned);
    assert_eq!(success_drops.load(Ordering::SeqCst), 1);

    let failure_output = Arc::new(Mutex::new(Vec::new()));
    let failure_drops = Arc::new(AtomicUsize::new(0));
    let failure_polls = Arc::new(AtomicUsize::new(0));
    let command = Socks5Inbound::new()
        .accept_command(ScriptedIo::new(
            input,
            Arc::clone(&failure_output),
            Arc::clone(&failure_drops),
            failure_polls,
            1,
            None,
        ))
        .await
        .expect("partial failure CONNECT");
    let SocksCommand::Connect(connect) = command else {
        panic!("partial failure CONNECT command")
    };
    let (_, pending) = connect.into_parts();
    pending
        .failed(ConnectErrorKind::PolicyDenied)
        .await
        .expect("fragmented failure reply");
    assert_eq!(
        *failure_output.lock().expect("failure output"),
        [METHOD, DENIED].concat()
    );
    assert_eq!(failure_drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_reply_cancellation_and_early_close_drop_io_once() {
    let input = wire(1, &[1, 192, 0, 2, 10, 0, 80]);
    let output = Arc::new(Mutex::new(Vec::new()));
    let drops = Arc::new(AtomicUsize::new(0));
    let write_polls = Arc::new(AtomicUsize::new(0));
    let command = Socks5Inbound::new()
        .accept_command(ScriptedIo::new(
            input.clone(),
            Arc::clone(&output),
            Arc::clone(&drops),
            Arc::clone(&write_polls),
            usize::MAX,
            Some(METHOD.len()),
        ))
        .await
        .expect("cancellable CONNECT");
    let SocksCommand::Connect(connect) = command else {
        panic!("cancellable CONNECT command")
    };
    let (_, pending) = connect.into_parts();
    let reply = tokio::spawn(async move {
        pending
            .succeeded_socket("127.0.0.1:49152".parse().expect("cancel bound"))
            .await
    });
    while write_polls.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    assert_eq!(*output.lock().expect("cancel output"), METHOD);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    reply.abort();
    assert!(matches!(reply.await, Err(error) if error.is_cancelled()));
    assert_eq!(drops.load(Ordering::SeqCst), 1);

    let peer_drops = Arc::new(AtomicUsize::new(0));
    let (mut client, server) = tokio::io::duplex(128);
    let tracked = DropTrackedIo {
        io: server,
        drops: Arc::clone(&peer_drops),
    };
    let accepted = tokio::spawn(async move { Socks5Inbound::new().accept_command(tracked).await });
    client.write_all(&input).await.expect("early-close request");
    assert_eq!(read::<2>(&mut client).await, METHOD);
    let SocksCommand::Connect(connect) = accepted.await.expect("accept join").expect("CONNECT")
    else {
        panic!("early-close CONNECT command")
    };
    drop(client);
    let (_, pending) = connect.into_parts();
    assert!(matches!(
        pending
            .succeeded_socket("127.0.0.1:49152".parse().expect("early-close bound"))
            .await,
        Err(SocksError::Io)
    ));
    assert_eq!(peer_drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn command_variant_and_udp_source_hint_rows_are_validated() {
    let (mut client, command) = commands(&wire(1, &[1, 192, 0, 2, 8, 1, 0xbb])).await;
    let SocksCommand::Connect(connect) = command else {
        panic!("command-connect variant")
    };
    assert_eq!(
        connect.target(),
        &ip("192.0.2.8:443"),
        "command-connect target"
    );
    let (_, pending) = connect.into_parts();
    pending.failed(ConnectErrorKind::Other).await.unwrap();
    assert_eq!(
        read::<10>(&mut client).await,
        GENERAL,
        "command-connect reply"
    );

    let (mut client, command) = commands(&wire(3, &[1, 127, 0, 0, 1, 0, 0])).await;
    let SocksCommand::UdpAssociate(association) = command else {
        panic!("UDP ASSOCIATE command")
    };
    association.reject_command_not_supported().await.unwrap();
    assert_eq!(
        read::<10>(&mut client).await,
        COMMAND,
        "composition command rejection"
    );

    let maximum = "a".repeat(255);
    for (case, suffix, port) in [
        ("hint-ipv4-zero", vec![1, 0, 0, 0, 0, 0, 0], 0),
        (
            "hint-ipv6-nonzero",
            [
                vec![4],
                Ipv6Addr::LOCALHOST.octets().to_vec(),
                vec![0x12, 0x34],
            ]
            .concat(),
            0x1234,
        ),
        (
            "hint-domain-zero",
            [vec![3, 1, b'a'], vec![0, 0]].concat(),
            0,
        ),
        (
            "hint-domain-255",
            [vec![3, 255], maximum.into_bytes(), vec![0xff, 0xff]].concat(),
            u16::MAX,
        ),
    ] {
        let (_, command) = commands(&wire(3, &suffix)).await;
        let SocksCommand::UdpAssociate(association) = command else {
            panic!("{case} variant")
        };
        assert_eq!(association.source_port(), port, "{case} port");
    }
}

#[tokio::test]
async fn fragmented_udp_command_retains_control_and_actual_reply() {
    let (mut client, server) = tokio::io::duplex(128);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept_command(server).await });
    fragmented(&mut client, &wire(3, &[1, 127, 0, 0, 1, 0, 0])).await;
    assert_eq!(
        read::<2>(&mut client).await,
        METHOD,
        "fragmented-command method"
    );
    let SocksCommand::UdpAssociate(mut association) = task.await.unwrap().unwrap() else {
        panic!("fragmented-command variant")
    };
    client.write_all(b"control").await.unwrap();
    let mut control = [0; 7];
    association.control.read_exact(&mut control).await.unwrap();
    assert_eq!(&control, b"control", "retained-control");
    association
        .reply
        .succeeded_socket(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            49_152,
        )))
        .await
        .unwrap();
    assert_eq!(
        read::<10>(&mut client).await,
        [5, 0, 0, 1, 127, 0, 0, 1, 0xc0, 0],
        "udp-actual-success"
    );
}

#[tokio::test]
async fn command_failure_rows_and_one_shot_write_failure_are_exact() {
    let selected = |reply: &[u8]| [METHOD, reply].concat();
    for (case, input, output, error) in [
        (
            "enabled-bind",
            wire(2, &[1]),
            selected(COMMAND),
            SocksError::CommandNotSupported,
        ),
        (
            "udp-atyp",
            wire(3, &[0x7f]),
            selected(ADDRESS),
            SocksError::AddressTypeNotSupported,
        ),
        (
            "udp-domain-empty",
            wire(3, &[3, 0, 0, 0]),
            selected(GENERAL),
            SocksError::InvalidTarget,
        ),
        (
            "udp-domain-nonascii",
            wire(3, &[3, 2, 0xc3, 0xa9, 0, 53]),
            selected(GENERAL),
            SocksError::InvalidTarget,
        ),
        (
            "udp-truncated",
            vec![5, 1, 0, 5, 3, 0, 1, 127],
            METHOD.to_vec(),
            SocksError::Malformed,
        ),
    ] {
        rejected(case, &input, &output, error).await;
    }
    let request = wire(3, &[1, 127, 0, 0, 1, 0, 0]);
    let (mut client, command) = commands(&request).await;
    let SocksCommand::UdpAssociate(association) = command else {
        panic!("setup-failure variant")
    };
    association
        .reply
        .failed(ConnectErrorKind::Other)
        .await
        .unwrap();
    assert_eq!(
        read::<10>(&mut client).await,
        GENERAL,
        "setup-failure reply"
    );
    let (client, command) = commands(&request).await;
    let SocksCommand::UdpAssociate(association) = command else {
        panic!("write-failure variant")
    };
    drop(client);
    assert_eq!(
        association.reply.failed(ConnectErrorKind::Other).await,
        Err(SocksError::Io),
        "write-failure terminal"
    );
    let output = Arc::new(Mutex::new(Vec::new()));
    let result = Socks5Inbound::new()
        .accept_command(RequestReadFailure {
            offset: 0,
            output: Arc::clone(&output),
        })
        .await;
    assert!(result.is_err(), "request-read-reset error");
    assert_eq!(
        *output.lock().unwrap(),
        [5, 0],
        "request-read-reset no request reply"
    );
}

struct RequestReadFailure {
    offset: usize,
    output: Arc<Mutex<Vec<u8>>>,
}
const REQUEST_READ_FAILURE: &[u8] = &[5, 1, 0, 5, 3, 0, 1];
impl AsyncRead for RequestReadFailure {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == REQUEST_READ_FAILURE.len() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        }
        let len = buffer
            .remaining()
            .min(REQUEST_READ_FAILURE.len() - self.offset);
        buffer.put_slice(&REQUEST_READ_FAILURE[self.offset..self.offset + len]);
        self.offset += len;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for RequestReadFailure {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.output.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct DropTrackedIo<IO> {
    io: IO,
    drops: Arc<AtomicUsize>,
}

impl<IO> Drop for DropTrackedIo<IO> {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl<IO> AsyncRead for DropTrackedIo<IO>
where
    IO: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(context, buffer)
    }
}

impl<IO> AsyncWrite for DropTrackedIo<IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}

struct ScriptedIo {
    input: Vec<u8>,
    offset: usize,
    output: Arc<Mutex<Vec<u8>>>,
    drops: Arc<AtomicUsize>,
    write_polls: Arc<AtomicUsize>,
    max_write: usize,
    stall_after: Option<usize>,
}

impl ScriptedIo {
    fn new(
        input: Vec<u8>,
        output: Arc<Mutex<Vec<u8>>>,
        drops: Arc<AtomicUsize>,
        write_polls: Arc<AtomicUsize>,
        max_write: usize,
        stall_after: Option<usize>,
    ) -> Self {
        Self {
            input,
            offset: 0,
            output,
            drops,
            write_polls,
            max_write,
            stall_after,
        }
    }
}

impl Drop for ScriptedIo {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let length = buffer.remaining().min(self.input.len() - self.offset);
        buffer.put_slice(&self.input[self.offset..self.offset + length]);
        self.offset += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_polls.fetch_add(1, Ordering::SeqCst);
        let mut output = self.output.lock().expect("scripted output");
        let remaining = self
            .stall_after
            .map_or(usize::MAX, |limit| limit.saturating_sub(output.len()));
        let length = buffer.len().min(self.max_write).min(remaining);
        if length == 0 {
            return Poll::Pending;
        }
        output.extend_from_slice(&buffer[..length]);
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn wire(command: u8, suffix: &[u8]) -> Vec<u8> {
    [&[5, 1, 0, 5, command, 0][..], suffix].concat()
}
fn ip(value: &str) -> TargetAddr {
    TargetAddr::ip(value.parse().unwrap()).unwrap()
}
async fn fragmented(io: &mut DuplexStream, bytes: &[u8]) {
    for byte in bytes {
        io.write_all(&[*byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
}
async fn read<const N: usize>(io: &mut DuplexStream) -> [u8; N] {
    let mut bytes = [0; N];
    io.read_exact(&mut bytes).await.unwrap();
    bytes
}
async fn commands(input: &[u8]) -> (DuplexStream, SocksCommand<DuplexStream>) {
    let (mut client, server) = tokio::io::duplex(512);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept_command(server).await });
    client.write_all(input).await.unwrap();
    assert_eq!(
        read::<2>(&mut client).await,
        METHOD,
        "command helper method"
    );
    (client, task.await.unwrap().unwrap())
}
async fn connect(input: &[u8]) -> (DuplexStream, SocksConnect<DuplexStream>) {
    let (client, command) = commands(input).await;
    let SocksCommand::Connect(session) = command else {
        panic!("CONNECT command")
    };
    (client, session)
}
async fn rejected(case: &str, input: &[u8], output: &[u8], error: SocksError) {
    let (mut client, server) = tokio::io::duplex(512);
    let task = tokio::spawn(async move {
        Socks5Inbound::new()
            .accept_command(server)
            .await
            .map(|_| ())
    });
    client.write_all(input).await.unwrap();
    client.shutdown().await.unwrap();
    let mut actual = Vec::new();
    client.read_to_end(&mut actual).await.unwrap();
    assert_eq!(actual, output, "{case} bytes");
    assert_eq!(task.await.unwrap().unwrap_err(), error, "{case} error");
}
