use std::net::SocketAddr;

use ferrum2_core::{ConnectErrorKind, Inbound, SessionReply};
use ferrum2_socks5::{Socks5Inbound, SocksError};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const METHOD_SELECTED: &[u8] = &[0x05, 0x00];
const NO_ACCEPTABLE_METHOD: &[u8] = &[0x05, 0xff];
const GENERAL_FAILURE: &[u8] = &[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const NETWORK_UNREACHABLE: &[u8] = &[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const HOST_UNREACHABLE: &[u8] = &[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const CONNECTION_REFUSED: &[u8] = &[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const COMMAND_NOT_SUPPORTED: &[u8] = &[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const ADDRESS_TYPE_NOT_SUPPORTED: &[u8] = &[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

#[tokio::test]
async fn no_acceptable_authentication_writes_only_method_rejection() {
    assert_rejected(
        &[0x05, 0x03, 0x01, 0x02, 0x80],
        NO_ACCEPTABLE_METHOD,
        SocksError::NoAcceptableMethod,
    )
    .await;
}

#[tokio::test]
async fn malformed_or_short_input_closes_without_a_request_failure() {
    let cases: &[&[u8]] = &[
        &[0x04, 0x01, 0x00],
        &[0x05, 0x00],
        &[0x05],
        &[0x05, 0x02, 0x00],
        &[
            0x05, 0x01, 0x00, 0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80,
        ],
        &[
            0x05, 0x01, 0x00, 0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0, 80,
        ],
        &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00],
        &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0],
    ];

    for input in cases {
        let expected = if input.starts_with(&[0x05, 0x01, 0x00]) && input.len() > 3 {
            METHOD_SELECTED
        } else {
            &[]
        };
        assert_rejected(input, expected, SocksError::Malformed).await;
    }
}

#[tokio::test]
async fn bind_and_udp_associate_write_command_not_supported() {
    for command in [0x02, 0x03] {
        let mut input = vec![0x05, 0x01, 0x00, 0x05, command, 0x00, 0x01];
        input.extend_from_slice(&[127, 0, 0, 1, 0, 80]);
        let mut expected = METHOD_SELECTED.to_vec();
        expected.extend_from_slice(COMMAND_NOT_SUPPORTED);
        assert_rejected(&input, &expected, SocksError::CommandNotSupported).await;
    }
}

#[tokio::test]
async fn unsupported_address_type_writes_address_type_not_supported() {
    let input = [0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x7f];
    let mut expected = METHOD_SELECTED.to_vec();
    expected.extend_from_slice(ADDRESS_TYPE_NOT_SUPPORTED);
    assert_rejected(&input, &expected, SocksError::AddressTypeNotSupported).await;
}

#[tokio::test]
async fn empty_non_ascii_and_zero_port_domains_are_invalid_targets() {
    for suffix in [
        vec![0x03, 0, 0, 80],
        vec![0x03, 2, 0xc3, 0xa9, 0, 80],
        [vec![0x03, 1], b"a".to_vec(), vec![0, 0]].concat(),
    ] {
        let input = [[0x05, 0x01, 0x00, 0x05, 0x01, 0x00].as_slice(), &suffix].concat();
        let mut expected = METHOD_SELECTED.to_vec();
        expected.extend_from_slice(GENERAL_FAILURE);
        assert_rejected(&input, &expected, SocksError::InvalidTarget).await;
    }
}

#[tokio::test]
async fn port_zero_writes_general_failure_with_zero_ipv4_bound_address() {
    let input = [0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0];
    let mut expected = METHOD_SELECTED.to_vec();
    expected.extend_from_slice(GENERAL_FAILURE);
    assert_rejected(&input, &expected, SocksError::InvalidTarget).await;
}

#[tokio::test]
async fn pre_open_error_mapping_writes_exact_failure_replies() {
    for (kind, expected) in [
        (ConnectErrorKind::NetworkUnreachable, NETWORK_UNREACHABLE),
        (ConnectErrorKind::HostUnreachable, HOST_UNREACHABLE),
        (ConnectErrorKind::ConnectionRefused, CONNECTION_REFUSED),
        (ConnectErrorKind::Timeout, GENERAL_FAILURE),
        (ConnectErrorKind::Other, GENERAL_FAILURE),
    ] {
        let (mut client, session) = accepted_session().await;
        session
            .reply
            .failed(kind)
            .await
            .expect("failure reply is written");
        let mut actual = [0_u8; 10];
        client
            .read_exact(&mut actual)
            .await
            .expect("read failure reply");
        assert_eq!(&actual, expected);
    }
}

#[tokio::test]
async fn general_failure_is_written_exactly_once() {
    let (mut client, session) = accepted_session().await;
    session
        .reply
        .failed(ConnectErrorKind::Other)
        .await
        .expect("failure reply is written");
    drop(session.stream);

    let mut actual = Vec::new();
    client
        .read_to_end(&mut actual)
        .await
        .expect("read complete reply");
    assert_eq!(actual, GENERAL_FAILURE);
}

async fn accepted_session() -> (
    DuplexStream,
    ferrum2_core::Session<
        ferrum2_socks5::SocksStream<DuplexStream>,
        ferrum2_socks5::SocksReplyPending<DuplexStream>,
    >,
) {
    let (mut client, server) = tokio::io::duplex(64);
    let accepted = tokio::spawn(async move { Socks5Inbound::new().accept(server).await });
    client
        .write_all(&[
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0, 80,
        ])
        .await
        .expect("write valid negotiation and request");

    let mut selected = [0_u8; 2];
    client
        .read_exact(&mut selected)
        .await
        .expect("read selected method");
    assert_eq!(selected, METHOD_SELECTED);

    let session = accepted
        .await
        .expect("accept task completes")
        .expect("request is accepted");
    assert_eq!(
        session.target.as_socket_addr(),
        Some("192.0.2.10:80".parse::<SocketAddr>().expect("literal"))
    );
    (client, session)
}

async fn assert_rejected(input: &[u8], expected_reply: &[u8], expected_error: SocksError) {
    let (mut client, server) = tokio::io::duplex(512);
    let accepted = tokio::spawn(async move { Socks5Inbound::new().accept(server).await });
    client.write_all(input).await.expect("write scripted input");
    client.shutdown().await.expect("close scripted input");

    let mut actual_reply = Vec::new();
    client
        .read_to_end(&mut actual_reply)
        .await
        .expect("read complete rejection");
    assert_eq!(actual_reply, expected_reply);

    let error = match accepted.await.expect("accept task completes") {
        Ok(_) => panic!("input was unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error, expected_error);
}
