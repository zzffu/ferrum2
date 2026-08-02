use ferrum2_core::{ConnectErrorKind, Inbound, Session, SessionReply, TargetAddr};
use ferrum2_socks5::{Socks5Inbound, SocksCommand, SocksError, SocksReplyPending, SocksStream};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const METHOD: &[u8] = &[5, 0];
const GENERAL: &[u8] = &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0];
const NETWORK: &[u8] = &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
const HOST: &[u8] = &[5, 4, 0, 1, 0, 0, 0, 0, 0, 0];
const REFUSED: &[u8] = &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
const COMMAND: &[u8] = &[5, 7, 0, 1, 0, 0, 0, 0, 0, 0];
const ADDRESS: &[u8] = &[5, 8, 0, 1, 0, 0, 0, 0, 0, 0];
type Legacy = Session<SocksStream<DuplexStream>, SocksReplyPending<DuplexStream>>;

#[tokio::test]
#[rustfmt::skip]
async fn legacy_connect_rows_keep_targets_replies_and_stream_exact() {
    let (mut client, server) = tokio::io::duplex(128);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept(server).await });
    fragmented(&mut client, &[5, 1, 0]).await;
    assert_eq!(read::<2>(&mut client).await, METHOD, "legacy-fragmented-ipv4 method");
    fragmented(&mut client, &[5, 1, 0, 1, 192, 0, 2, 10, 0x1f, 0x90]).await;
    let mut session = task.await.unwrap().unwrap();
    assert_eq!(session.target, ip("192.0.2.10:8080"), "legacy-ipv4 target");
    assert!(session.initial_payload.is_empty(), "legacy-ipv4 initial payload");
    session.reply.succeeded("127.0.0.7:49152".parse().unwrap()).await.unwrap();
    assert_eq!(read::<10>(&mut client).await, [5, 0, 0, 1, 127, 0, 0, 7, 0xc0, 0], "legacy-ipv4 reply");
    client.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4]; session.stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ping", "legacy inbound stream");
    session.stream.write_all(b"pong").await.unwrap(); client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"pong", "legacy outbound stream");

    let bound = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
    for (case, suffix, target) in [
        ("legacy-ipv6", [vec![4], Ipv6Addr::LOCALHOST.octets().to_vec(), vec![1, 0xbb]].concat(), ip("[::1]:443")),
        ("legacy-domain", [vec![3, 12], b"example.test".to_vec(), vec![1, 0xbb]].concat(), TargetAddr::domain("example.test", 443).unwrap()),
    ] {
        let (mut client, session) = legacy(&wire(1, &suffix)).await;
        assert_eq!(session.target, target, "{case} target");
        session.reply.succeeded_socket(SocketAddr::V6(SocketAddrV6::new(bound, 49_152, 0, 0))).await.unwrap();
        let reply = read::<22>(&mut client).await;
        assert_eq!(&reply[..4], &[5, 0, 0, 4], "{case} reply header");
        assert_eq!(&reply[4..20], &bound.octets(), "{case} reply address");
        assert_eq!(&reply[20..], &[0xc0, 0], "{case} reply port");
    }
}

#[tokio::test]
#[rustfmt::skip]
async fn legacy_negative_rows_keep_every_exact_byte() {
    let selected = |reply: &[u8]| [METHOD, reply].concat();
    let full = wire(1, &[1, 127, 0, 0, 1, 0, 80]);
    let rows = vec![
        ("greeting-version", vec![4, 1, 0], vec![], SocksError::Malformed),
        ("greeting-zero-methods", vec![5, 0], vec![], SocksError::Malformed),
        ("greeting-short-header", vec![5], vec![], SocksError::Malformed),
        ("greeting-short-methods", vec![5, 2, 0], vec![], SocksError::Malformed),
        ("request-version", [vec![5, 1, 0, 4], full[4..].to_vec()].concat(), METHOD.to_vec(), SocksError::Malformed),
        ("request-rsv", [vec![5, 1, 0, 5, 1, 1], full[6..].to_vec()].concat(), METHOD.to_vec(), SocksError::Malformed),
        ("request-short-header", vec![5, 1, 0, 5, 1, 0], METHOD.to_vec(), SocksError::Malformed),
        ("request-short-ipv4", vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0], METHOD.to_vec(), SocksError::Malformed),
        ("method-rejection", vec![5, 3, 1, 2, 0x80], vec![5, 0xff], SocksError::NoAcceptableMethod),
        ("connect-atyp", wire(1, &[0x7f]), selected(ADDRESS), SocksError::AddressTypeNotSupported),
        ("connect-domain-empty", wire(1, &[3, 0, 0, 80]), selected(GENERAL), SocksError::InvalidTarget),
        ("connect-domain-nonascii", wire(1, &[3, 2, 0xc3, 0xa9, 0, 80]), selected(GENERAL), SocksError::InvalidTarget),
        ("connect-domain-zero-port", wire(1, &[3, 1, b'a', 0, 0]), selected(GENERAL), SocksError::InvalidTarget),
        ("connect-ipv4-zero-port", wire(1, &[1, 127, 0, 0, 1, 0, 0]), selected(GENERAL), SocksError::InvalidTarget),
    ];
    for (case, input, output, error) in rows { rejected(case, &input, &output, error, false).await; }
    for (case, command) in [("legacy-bind", 2), ("legacy-udp-disabled", 3)] {
        rejected(case, &wire(command, &[1, 127, 0, 0, 1, 0, 80]), &selected(COMMAND), SocksError::CommandNotSupported, false).await;
    }
}

#[tokio::test]
#[rustfmt::skip]
async fn legacy_failure_replies_are_mapped_and_exactly_once() {
    for (case, kind, expected) in [
        ("network", ConnectErrorKind::NetworkUnreachable, NETWORK),
        ("host", ConnectErrorKind::HostUnreachable, HOST),
        ("refused", ConnectErrorKind::ConnectionRefused, REFUSED),
        ("timeout", ConnectErrorKind::Timeout, GENERAL),
        ("other", ConnectErrorKind::Other, GENERAL),
    ] {
        let (mut client, session) = legacy(&wire(1, &[1, 192, 0, 2, 10, 0, 80])).await;
        session.reply.failed(kind).await.unwrap(); drop(session.stream);
        let mut actual = Vec::new(); client.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected, "legacy-reply-{case}");
    }
}

#[tokio::test]
#[rustfmt::skip]
async fn command_variant_and_udp_source_hint_rows_are_validated() {
    let (mut client, command) = commands(&wire(1, &[1, 192, 0, 2, 8, 1, 0xbb])).await;
    let SocksCommand::Connect(session) = command else { panic!("command-connect variant") };
    assert_eq!(session.target, ip("192.0.2.8:443"), "command-connect target");
    session.reply.failed(ConnectErrorKind::Other).await.unwrap();
    assert_eq!(read::<10>(&mut client).await, GENERAL, "command-connect reply");
    let maximum = "a".repeat(255);
    for (case, suffix, port) in [
        ("hint-ipv4-zero", vec![1, 0, 0, 0, 0, 0, 0], 0),
        ("hint-ipv6-nonzero", [vec![4], Ipv6Addr::LOCALHOST.octets().to_vec(), vec![0x12, 0x34]].concat(), 0x1234),
        ("hint-domain-zero", [vec![3, 1, b'a'], vec![0, 0]].concat(), 0),
        ("hint-domain-255", [vec![3, 255], maximum.into_bytes(), vec![0xff, 0xff]].concat(), u16::MAX),
    ] {
        let (_, command) = commands(&wire(3, &suffix)).await;
        let SocksCommand::UdpAssociate(association) = command else { panic!("{case} variant") };
        assert_eq!(association.source_port(), port, "{case} port");
    }
}

#[tokio::test]
#[rustfmt::skip]
async fn fragmented_udp_command_retains_control_and_actual_reply() {
    let (mut client, server) = tokio::io::duplex(128);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept_command(server).await });
    fragmented(&mut client, &wire(3, &[1, 127, 0, 0, 1, 0, 0])).await;
    assert_eq!(read::<2>(&mut client).await, METHOD, "fragmented-command method");
    let SocksCommand::UdpAssociate(mut association) = task.await.unwrap().unwrap() else { panic!("fragmented-command variant") };
    client.write_all(b"control").await.unwrap();
    let mut control = [0; 7]; association.control.read_exact(&mut control).await.unwrap();
    assert_eq!(&control, b"control", "retained-control");
    association.reply.succeeded(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152)).await.unwrap();
    assert_eq!(read::<10>(&mut client).await, [5, 0, 0, 1, 127, 0, 0, 1, 0xc0, 0], "udp-actual-success");
}

#[tokio::test]
#[rustfmt::skip]
async fn command_failure_rows_and_one_shot_write_failure_are_exact() {
    let selected = |reply: &[u8]| [METHOD, reply].concat();
    for (case, input, output, error) in [
        ("enabled-bind", wire(2, &[1]), selected(COMMAND), SocksError::CommandNotSupported),
        ("udp-atyp", wire(3, &[0x7f]), selected(ADDRESS), SocksError::AddressTypeNotSupported),
        ("udp-domain-empty", wire(3, &[3, 0, 0, 0]), selected(GENERAL), SocksError::InvalidTarget),
        ("udp-domain-nonascii", wire(3, &[3, 2, 0xc3, 0xa9, 0, 53]), selected(GENERAL), SocksError::InvalidTarget),
        ("udp-truncated", vec![5, 1, 0, 5, 3, 0, 1, 127], METHOD.to_vec(), SocksError::Malformed),
    ] { rejected(case, &input, &output, error, true).await; }
    let request = wire(3, &[1, 127, 0, 0, 1, 0, 0]);
    let (mut client, command) = commands(&request).await;
    let SocksCommand::UdpAssociate(association) = command else { panic!("setup-failure variant") };
    association.reply.failed(ConnectErrorKind::Other).await.unwrap();
    assert_eq!(read::<10>(&mut client).await, GENERAL, "setup-failure reply");
    let (client, command) = commands(&request).await;
    let SocksCommand::UdpAssociate(association) = command else { panic!("write-failure variant") };
    drop(client);
    assert_eq!(association.reply.failed(ConnectErrorKind::Other).await, Err(SocksError::Io), "write-failure terminal");
}

#[rustfmt::skip]
fn wire(command: u8, suffix: &[u8]) -> Vec<u8> { [&[5, 1, 0, 5, command, 0][..], suffix].concat() }
#[rustfmt::skip]
fn ip(value: &str) -> TargetAddr { TargetAddr::ip(value.parse().unwrap()).unwrap() }
#[rustfmt::skip]
async fn fragmented(io: &mut DuplexStream, bytes: &[u8]) {
    for byte in bytes { io.write_all(&[*byte]).await.unwrap(); tokio::task::yield_now().await; }
}
#[rustfmt::skip]
async fn read<const N: usize>(io: &mut DuplexStream) -> [u8; N] {
    let mut bytes = [0; N]; io.read_exact(&mut bytes).await.unwrap(); bytes
}
#[rustfmt::skip]
async fn legacy(input: &[u8]) -> (DuplexStream, Legacy) {
    let (mut client, server) = tokio::io::duplex(512);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept(server).await });
    client.write_all(input).await.unwrap(); assert_eq!(read::<2>(&mut client).await, METHOD, "legacy helper method");
    (client, task.await.unwrap().unwrap())
}
#[rustfmt::skip]
async fn commands(input: &[u8]) -> (DuplexStream, SocksCommand<DuplexStream>) {
    let (mut client, server) = tokio::io::duplex(512);
    let task = tokio::spawn(async move { Socks5Inbound::new().accept_command(server).await });
    client.write_all(input).await.unwrap(); assert_eq!(read::<2>(&mut client).await, METHOD, "command helper method");
    (client, task.await.unwrap().unwrap())
}
#[rustfmt::skip]
async fn rejected(case: &str, input: &[u8], output: &[u8], error: SocksError, commands: bool) {
    let (mut client, server) = tokio::io::duplex(512);
    let task = tokio::spawn(async move {
        if commands { Socks5Inbound::new().accept_command(server).await.map(|_| ()) }
        else { Socks5Inbound::new().accept(server).await.map(|_| ()) }
    });
    client.write_all(input).await.unwrap(); client.shutdown().await.unwrap();
    let mut actual = Vec::new(); client.read_to_end(&mut actual).await.unwrap();
    assert_eq!(actual, output, "{case} bytes");
    assert_eq!(task.await.unwrap().unwrap_err(), error, "{case} error");
}
