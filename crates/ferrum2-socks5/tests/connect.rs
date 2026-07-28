use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ferrum2_core::{Inbound, SessionReply};
use ferrum2_socks5::Socks5Inbound;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn fragmented_ipv4_connect_yields_session_and_exact_success_reply() {
    let (mut client, server) = tokio::io::duplex(64);
    let accepted = tokio::spawn(async move { Socks5Inbound::new().accept(server).await });

    for byte in [0x05, 0x01, 0x00] {
        client
            .write_all(&[byte])
            .await
            .expect("write greeting byte");
        tokio::task::yield_now().await;
    }

    let mut method_reply = [0_u8; 2];
    client
        .read_exact(&mut method_reply)
        .await
        .expect("read method reply");
    assert_eq!(method_reply, [0x05, 0x00]);

    for byte in [0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x1f, 0x90] {
        client.write_all(&[byte]).await.expect("write request byte");
        tokio::task::yield_now().await;
    }

    let mut session = accepted
        .await
        .expect("accept task completes")
        .expect("valid CONNECT is accepted");
    assert_eq!(
        session.target.as_socket_addr(),
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 0, 2, 10),
            8080,
        )))
    );
    assert!(session.initial_payload.is_empty());

    let bound = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 7), 49_152);
    session
        .reply
        .succeeded(SocketAddr::V4(bound))
        .await
        .expect("write success reply");

    let mut success_reply = [0_u8; 10];
    client
        .read_exact(&mut success_reply)
        .await
        .expect("read success reply");
    assert_eq!(
        success_reply,
        [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 7, 0xc0, 0x00]
    );

    client
        .write_all(b"ping")
        .await
        .expect("write application data");
    let mut inbound = [0_u8; 4];
    session
        .stream
        .read_exact(&mut inbound)
        .await
        .expect("read through returned stream");
    assert_eq!(&inbound, b"ping");

    session
        .stream
        .write_all(b"pong")
        .await
        .expect("write through returned stream");
    let mut outbound = [0_u8; 4];
    client
        .read_exact(&mut outbound)
        .await
        .expect("read application response");
    assert_eq!(&outbound, b"pong");
}

#[tokio::test]
async fn ipv6_and_domain_targets_round_trip_and_ipv6_success_uses_actual_endpoint() {
    for (request, expected) in [
        (
            [
                &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04][..],
                &Ipv6Addr::LOCALHOST.octets(),
                &[0x01, 0xbb],
            ]
            .concat(),
            TargetCase::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                443,
                0,
                0,
            ))),
        ),
        (
            [
                &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 12][..],
                b"example.test",
                &[0x01, 0xbb],
            ]
            .concat(),
            TargetCase::Domain("example.test"),
        ),
    ] {
        let (mut client, server) = tokio::io::duplex(128);
        let accepted = tokio::spawn(async move { Socks5Inbound::new().accept(server).await });
        client.write_all(&request).await.expect("write request");
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.expect("method reply");
        let session = accepted
            .await
            .expect("accept task")
            .expect("target accepted");
        match expected {
            TargetCase::Ip(address) => assert_eq!(session.target.as_socket_addr(), Some(address)),
            TargetCase::Domain(domain) => {
                assert_eq!(
                    session.target.host(),
                    ferrum2_core::TargetHostRef::Domain(domain)
                );
            }
        }

        let bound = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::7".parse().expect("IPv6"),
            49_152,
            0,
            0,
        ));
        session.reply.succeeded(bound).await.expect("success reply");
        let mut reply = [0_u8; 22];
        client.read_exact(&mut reply).await.expect("IPv6 reply");
        assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x04]);
        assert_eq!(
            &reply[4..20],
            &"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(&reply[20..], &[0xc0, 0x00]);
    }
}

enum TargetCase {
    Ip(SocketAddr),
    Domain(&'static str),
}
