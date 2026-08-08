use std::sync::Arc;

use ferrum2_sniff::{Metadata, Progress, Protocol, Transport, sniff};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{DNSClass, Name, RecordType},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, SupportedProtocolVersion,
    pki_types::ServerName,
    version::{TLS12, TLS13},
};

fn dns_query(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(
        Name::from_ascii(name).expect("test DNS name"),
        RecordType::A,
    ));
    message.to_vec().expect("test DNS message")
}

fn client_hello(
    version: &'static SupportedProtocolVersion,
    sni: bool,
    max_fragment_size: Option<usize>,
) -> Vec<u8> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .expect("test TLS version")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    config.enable_sni = sni;
    config.max_fragment_size = max_fragment_size;
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("tls.test")
            .expect("test server name")
            .to_owned(),
    )
    .expect("test TLS client");
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).expect("test ClientHello");
    }
    wire
}

fn with_ech_client_hello_outer(mut wire: Vec<u8>) -> Vec<u8> {
    const ECH_OUTER: [u8; 15] = [
        0xfe, 0x0d, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    ];

    let u16_at = |offset: usize| {
        u16::from_be_bytes(
            wire.get(offset..offset.checked_add(2).expect("u16 offset"))
                .expect("complete u16")
                .try_into()
                .expect("two bytes"),
        )
    };
    assert_eq!(wire.first(), Some(&0x16), "record must be a handshake");
    let record_len = usize::from(u16_at(3));
    assert_eq!(
        5_usize.checked_add(record_len),
        Some(wire.len()),
        "mutation requires one complete TLS record"
    );
    let handshake = wire.get(5..9).expect("ClientHello handshake header");
    assert_eq!(handshake[0], 1, "handshake must be ClientHello");
    let handshake_len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    assert_eq!(
        handshake_len.checked_add(4),
        Some(record_len),
        "record must contain one complete ClientHello"
    );

    let mut cursor = 9 + 2 + 32;
    let session_id_len = usize::from(*wire.get(cursor).expect("session id length"));
    cursor = cursor
        .checked_add(1 + session_id_len)
        .expect("complete session id");
    let cipher_len = usize::from(u16_at(cursor));
    assert_eq!(cipher_len % 2, 0, "cipher suite vector framing");
    cursor = cursor
        .checked_add(2)
        .and_then(|start| start.checked_add(cipher_len))
        .expect("complete cipher suites");
    let compression_len = usize::from(*wire.get(cursor).expect("compression length"));
    cursor = cursor
        .checked_add(1 + compression_len)
        .expect("complete compression methods");

    let extensions_len_offset = cursor;
    let extensions_len = usize::from(u16_at(cursor));
    cursor = cursor.checked_add(2).expect("extensions start");
    assert_eq!(
        cursor.checked_add(extensions_len),
        Some(wire.len()),
        "extensions must terminate ClientHello"
    );
    while cursor < wire.len() {
        assert_ne!(u16_at(cursor), 0xfe0d, "generated hello already has ECH");
        let extension_len = usize::from(u16_at(cursor + 2));
        cursor = cursor
            .checked_add(4)
            .and_then(|start| start.checked_add(extension_len))
            .filter(|end| *end <= wire.len())
            .expect("complete extension");
    }

    let updated = |length: usize| {
        length
            .checked_add(ECH_OUTER.len())
            .expect("updated TLS length")
    };
    let record_len = u16::try_from(updated(record_len)).expect("record length width");
    wire[3..5].copy_from_slice(&record_len.to_be_bytes());
    let handshake_len = u32::try_from(updated(handshake_len))
        .expect("handshake length width")
        .to_be_bytes();
    assert_eq!(handshake_len[0], 0, "TLS handshake uses a 24-bit length");
    wire[6..9].copy_from_slice(&handshake_len[1..]);
    let extensions_len = u16::try_from(updated(extensions_len)).expect("extensions length width");
    wire[extensions_len_offset..extensions_len_offset + 2]
        .copy_from_slice(&extensions_len.to_be_bytes());
    wire.extend_from_slice(&ECH_OUTER);
    wire
}

#[test]
fn dns_transport_strictness_fragmentation_and_limits_are_bounded() {
    let wire = dns_query("query.test.");
    let matched = Progress::Matched(Metadata::Dns {
        domain: "query.test.".to_owned(),
    });
    let mut frame = u16::try_from(wire.len())
        .expect("test DNS frame length")
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(&wire);

    assert_eq!(
        sniff(&frame, frame.len(), Transport::Tcp, 53, &[Protocol::Dns]),
        matched
    );
    assert_eq!(
        sniff(&wire, wire.len(), Transport::Udp, 5353, &[Protocol::Dns]),
        matched,
        "a complete valid DNS message is recognized on a non-53 port"
    );
    let mut two_frames = frame.clone();
    two_frames.extend_from_slice(&frame);
    assert_eq!(
        sniff(
            &two_frames,
            two_frames.len(),
            Transport::Tcp,
            53,
            &[Protocol::Dns]
        ),
        matched
    );
    for boundary in 0..frame.len() {
        assert_eq!(
            sniff(
                &frame[..boundary],
                frame.len(),
                Transport::Tcp,
                53,
                &[Protocol::Dns]
            ),
            Progress::NeedMore,
            "TCP DNS boundary {boundary}"
        );
        assert_eq!(
            sniff(
                &frame[..boundary],
                frame.len(),
                Transport::Tcp,
                5353,
                &[Protocol::Dns]
            ),
            Progress::NoMatch,
            "non-53 TCP DNS boundary {boundary}"
        );
    }
    for boundary in 0..wire.len() {
        assert_eq!(
            sniff(
                &wire[..boundary],
                wire.len(),
                Transport::Udp,
                53,
                &[Protocol::Dns]
            ),
            Progress::Invalid,
            "UDP DNS is a complete datagram at boundary {boundary}"
        );
    }

    assert_eq!(
        sniff(
            &frame[..frame.len() - 1],
            frame.len() - 1,
            Transport::Tcp,
            53,
            &[Protocol::Dns]
        ),
        Progress::Invalid,
        "a partial frame at the exact limit cannot request another byte"
    );
    assert_eq!(
        sniff(&wire, wire.len() - 1, Transport::Udp, 53, &[Protocol::Dns]),
        Progress::Invalid,
        "caller bytes beyond the limit are rejected before parsing"
    );

    let mut messages = Vec::new();
    let mut response = Message::new(1, MessageType::Response, OpCode::Query);
    response.add_query(Query::query(
        Name::from_ascii("query.test.").expect("response name"),
        RecordType::A,
    ));
    messages.push(response);
    let mut status = Message::new(2, MessageType::Query, OpCode::Status);
    status.add_query(Query::query(
        Name::from_ascii("query.test.").expect("status name"),
        RecordType::A,
    ));
    messages.push(status);
    let mut multiple = Message::query();
    multiple.add_query(Query::query(
        Name::from_ascii("one.test.").expect("first name"),
        RecordType::A,
    ));
    multiple.add_query(Query::query(
        Name::from_ascii("two.test.").expect("second name"),
        RecordType::AAAA,
    ));
    messages.push(multiple);
    let mut wrong_class = Message::query();
    let mut query = Query::query(
        Name::from_ascii("query.test.").expect("class name"),
        RecordType::A,
    );
    query.set_query_class(DNSClass::CH);
    wrong_class.add_query(query);
    messages.push(wrong_class);
    for message in messages {
        let invalid = message.to_vec().expect("negative DNS message");
        assert_eq!(
            sniff(
                &invalid,
                invalid.len(),
                Transport::Udp,
                53,
                &[Protocol::Dns]
            ),
            Progress::Invalid
        );
    }

    let mut trailing = wire.clone();
    trailing.push(0);
    for malformed in [&b"not dns"[..], &trailing] {
        assert_eq!(
            sniff(
                malformed,
                malformed.len(),
                Transport::Udp,
                53,
                &[Protocol::Dns]
            ),
            Progress::Invalid
        );
    }
    for (section, offset) in [
        ("question", 4),
        ("answer", 6),
        ("authority", 8),
        ("additional", 10),
    ] {
        let mut extreme_count = wire.clone();
        extreme_count[offset..offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            sniff(
                &extreme_count,
                extreme_count.len(),
                Transport::Udp,
                53,
                &[Protocol::Dns]
            ),
            Progress::Invalid,
            "extreme {section} count"
        );
    }
    assert_eq!(
        sniff(&[0, 0], 2, Transport::Tcp, 53, &[Protocol::Dns]),
        Progress::Invalid
    );
}

#[test]
fn tls_versions_sni_records_fragmentation_and_limits_are_bounded() {
    for (version, version_name) in [(&TLS12, "TLS1.2"), (&TLS13, "TLS1.3")] {
        for sni in [false, true] {
            for max_fragment_size in [None, Some(64)] {
                let wire = client_hello(version, sni, max_fragment_size);
                let expected = Progress::Matched(Metadata::Tls {
                    domain: sni.then(|| "tls.test".to_owned()),
                });
                assert_eq!(
                    sniff(&wire, wire.len(), Transport::Tcp, 443, &[Protocol::Tls]),
                    expected,
                    "{version_name} sni={sni} fragment={max_fragment_size:?}"
                );
                if max_fragment_size.is_some() {
                    let mut records = 0;
                    let mut offset = 0;
                    while let Some(header) = wire.get(offset..offset + 5) {
                        offset += 5 + usize::from(u16::from_be_bytes([header[3], header[4]]));
                        records += 1;
                    }
                    assert_eq!(offset, wire.len(), "test ClientHello record framing");
                    assert!(records > 1, "rustls client must generate multiple records");
                }
                for boundary in 0..wire.len() {
                    assert_eq!(
                        sniff(
                            &wire[..boundary],
                            wire.len(),
                            Transport::Tcp,
                            443,
                            &[Protocol::Tls]
                        ),
                        Progress::NeedMore,
                        "{version_name} sni={sni} fragment={max_fragment_size:?} boundary={boundary}"
                    );
                }
                assert_eq!(
                    sniff(
                        &wire[..wire.len() - 1],
                        wire.len() - 1,
                        Transport::Tcp,
                        443,
                        &[Protocol::Tls]
                    ),
                    Progress::Invalid,
                    "partial {version_name} at exact limit"
                );
                assert_eq!(
                    sniff(&wire, wire.len() - 1, Transport::Tcp, 443, &[Protocol::Tls]),
                    Progress::Invalid,
                    "complete {version_name} beyond caller limit"
                );
            }
        }
    }

    let ech_outer = with_ech_client_hello_outer(client_hello(&TLS13, true, None));
    let observable_outer_name = Progress::Matched(Metadata::Tls {
        domain: Some("tls.test".to_owned()),
    });
    assert_eq!(
        sniff(
            &ech_outer,
            ech_outer.len(),
            Transport::Tcp,
            443,
            &[Protocol::Tls]
        ),
        observable_outer_name,
        "ECH ClientHelloOuter exposes only rustls' outer public/cover SNI"
    );
    // This is outer-name observability evidence, not ECH termination, decryption,
    // interoperability, or evidence about an encrypted inner name.
    for boundary in 0..ech_outer.len() {
        assert_eq!(
            sniff(
                &ech_outer[..boundary],
                ech_outer.len(),
                Transport::Tcp,
                443,
                &[Protocol::Tls]
            ),
            Progress::NeedMore,
            "ECH ClientHelloOuter boundary={boundary}"
        );
    }

    for plausible in [&b""[..], &b"\x16"[..], &b"\x16\x03"[..]] {
        assert_eq!(
            sniff(plausible, 8, Transport::Tcp, 443, &[Protocol::Tls]),
            Progress::NeedMore
        );
    }
    for implausible in [&b"G"[..], &b"\x15"[..], &b"\x16\x02"[..]] {
        assert_eq!(
            sniff(implausible, 8, Transport::Tcp, 443, &[Protocol::Tls]),
            Progress::NoMatch
        );
    }
    for malformed in [
        &b"\x16\x03\x03\x00\x01\xff"[..],
        &b"\x16\x03\x03\x00\x00"[..],
    ] {
        let progress = sniff(
            malformed,
            malformed.len(),
            Transport::Tcp,
            443,
            &[Protocol::Tls],
        );
        assert_eq!(progress, Progress::Invalid);
        assert_eq!(format!("{progress:?}"), "Invalid");
    }
    assert_eq!(
        sniff(&b"\x16"[..], 8, Transport::Udp, 443, &[Protocol::Tls]),
        Progress::NoMatch
    );
    let matched = sniff(
        &client_hello(&TLS13, true, None),
        16_384,
        Transport::Tcp,
        443,
        &[Protocol::Tls],
    );
    assert!(
        !format!("{matched:?}").contains("tls.test"),
        "Debug must never expose sniffed domains"
    );
}

#[test]
fn http_requests_headers_fragmentation_and_limits_are_bounded() {
    let cases: [(&str, &[u8], Option<&str>); 10] = [
        (
            "GET mixed-case Host",
            b"GET / HTTP/1.1\r\nhOsT: get.test\r\n\r\n",
            Some("get.test"),
        ),
        (
            "POST Host",
            b"POST /submit HTTP/1.1\r\nHost: post.test:8080\r\n\r\n",
            Some("post.test"),
        ),
        (
            "CONNECT authority preferred",
            b"CONNECT tunnel.test:443 HTTP/1.1\r\nHost: ignored.test\r\nHost: duplicate.test\r\n\r\n",
            Some("tunnel.test"),
        ),
        (
            "CONNECT IP authority",
            b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: ignored.test\r\n\r\n",
            None,
        ),
        (
            "duplicate Host",
            b"GET / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\n\r\n",
            None,
        ),
        (
            "invalid Host",
            b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n",
            None,
        ),
        (
            "IPv4 literal",
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n",
            None,
        ),
        (
            "IPv6 literal",
            b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
            None,
        ),
        (
            "lowercase extension method",
            b"custom / HTTP/1.1\r\nHost: lowercase.test\r\n\r\n",
            Some("lowercase.test"),
        ),
        (
            "digit tchar extension method",
            b"9!probe / HTTP/1.1\r\nHost: tchar.test\r\n\r\n",
            Some("tchar.test"),
        ),
    ];
    for (name, request, domain) in cases {
        assert_eq!(
            sniff(
                request,
                request.len(),
                Transport::Tcp,
                80,
                &[Protocol::Http]
            ),
            Progress::Matched(Metadata::Http {
                domain: domain.map(str::to_owned),
            }),
            "{name}"
        );
        if matches!(
            name,
            "GET mixed-case Host"
                | "POST Host"
                | "CONNECT authority preferred"
                | "lowercase extension method"
                | "digit tchar extension method"
        ) {
            for boundary in 0..request.len() {
                assert_eq!(
                    sniff(
                        &request[..boundary],
                        request.len(),
                        Transport::Tcp,
                        80,
                        &[Protocol::Http]
                    ),
                    Progress::NeedMore,
                    "{name} boundary={boundary}"
                );
            }
        }
    }

    let body = b"POST / HTTP/1.1\r\nHost: header.test\r\nContent-Length: 21\r\n\r\nHost: body.test\r\n\r\n";
    assert_eq!(
        sniff(body, body.len(), Transport::Tcp, 80, &[Protocol::Http]),
        Progress::Matched(Metadata::Http {
            domain: Some("header.test".to_owned()),
        }),
        "body bytes are outside sniff metadata"
    );

    let mut sixty_four = String::from("GET / HTTP/1.1\r\nHost: headers.test\r\n");
    for index in 0..63 {
        sixty_four.push_str(&format!("X-{index}: value\r\n"));
    }
    sixty_four.push_str("\r\n");
    assert_eq!(
        sniff(
            sixty_four.as_bytes(),
            sixty_four.len(),
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::Matched(Metadata::Http {
            domain: Some("headers.test".to_owned()),
        })
    );
    let sixty_five = sixty_four.replacen("\r\n\r\n", "\r\nX-64: value\r\n\r\n", 1);
    assert_eq!(
        sniff(
            sixty_five.as_bytes(),
            sixty_five.len(),
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::Invalid
    );

    let partial = b"GET / HTTP/1.1\r\nHost: partial.test\r\n";
    assert_eq!(
        sniff(
            partial,
            partial.len() + 1,
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::NeedMore
    );
    assert_eq!(
        sniff(
            partial,
            partial.len(),
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::Invalid,
        "partial HTTP at the exact limit cannot request another byte"
    );
    let complete = b"GET / HTTP/1.1\r\n\r\n";
    assert_eq!(
        sniff(
            complete,
            complete.len(),
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::Matched(Metadata::Http { domain: None })
    );
    assert_eq!(
        sniff(
            complete,
            complete.len() - 1,
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::Invalid
    );

    assert_eq!(
        sniff(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            64,
            Transport::Tcp,
            80,
            &[Protocol::Http]
        ),
        Progress::Invalid,
        "responses are not requests"
    );
    for (prefix, expected) in [
        (&b""[..], Progress::NeedMore),
        (&b"G"[..], Progress::NeedMore),
        (&b"g"[..], Progress::NeedMore),
        (&b"\x01"[..], Progress::NoMatch),
    ] {
        assert_eq!(
            sniff(prefix, 8, Transport::Tcp, 80, &[Protocol::Http]),
            expected
        );
    }
    assert_eq!(
        sniff(b"GET", 8, Transport::Udp, 80, &[Protocol::Http]),
        Progress::NoMatch
    );
}

#[test]
fn composite_order_invalid_continuation_and_need_more_arbitration_are_closed() {
    let dns_wire = dns_query("ordered.test.");
    let mut dns_frame = u16::try_from(dns_wire.len())
        .expect("test DNS frame length")
        .to_be_bytes()
        .to_vec();
    dns_frame.extend_from_slice(&dns_wire);
    let tls_wire = client_hello(&TLS13, true, None);
    let http_wire = b"GET / HTTP/1.1\r\nHost: ordered-http.test\r\n\r\n";

    struct Case<'a> {
        name: &'a str,
        bytes: &'a [u8],
        max_bytes: usize,
        port: u16,
        order: &'a [Protocol],
        expected: Progress,
    }
    let cases = [
        Case {
            name: "configured HTTP then DNS",
            bytes: &dns_frame,
            max_bytes: dns_frame.len(),
            port: 53,
            order: &[Protocol::Http, Protocol::Dns],
            expected: Progress::Matched(Metadata::Dns {
                domain: "ordered.test.".to_owned(),
            }),
        },
        Case {
            name: "configured HTTP then TLS",
            bytes: &tls_wire,
            max_bytes: 8192,
            port: 443,
            order: &[Protocol::Http, Protocol::Tls],
            expected: Progress::Matched(Metadata::Tls {
                domain: Some("tls.test".to_owned()),
            }),
        },
        Case {
            name: "invalid DNS continues to HTTP",
            bytes: http_wire,
            max_bytes: 8192,
            port: 80,
            order: &[Protocol::Dns, Protocol::Http],
            expected: Progress::Matched(Metadata::Http {
                domain: Some("ordered-http.test".to_owned()),
            }),
        },
        Case {
            name: "incomplete non-53 DNS does not delay TLS",
            bytes: &tls_wire,
            max_bytes: 8192,
            port: 443,
            order: &[Protocol::Dns, Protocol::Tls],
            expected: Progress::Matched(Metadata::Tls {
                domain: Some("tls.test".to_owned()),
            }),
        },
        Case {
            name: "incomplete port-53 DNS wins configured arbitration",
            bytes: &tls_wire,
            max_bytes: 8192,
            port: 53,
            order: &[Protocol::Dns, Protocol::Tls],
            expected: Progress::NeedMore,
        },
        Case {
            name: "configured TLS wins before incomplete port-53 DNS",
            bytes: &tls_wire,
            max_bytes: 8192,
            port: 53,
            order: &[Protocol::Tls, Protocol::Dns],
            expected: Progress::Matched(Metadata::Tls {
                domain: Some("tls.test".to_owned()),
            }),
        },
        Case {
            name: "implausible HTTP continues to TLS NeedMore",
            bytes: b"\x16",
            max_bytes: 8,
            port: 443,
            order: &[Protocol::Http, Protocol::Tls],
            expected: Progress::NeedMore,
        },
        Case {
            name: "implausible TLS continues to HTTP NeedMore",
            bytes: b"G",
            max_bytes: 8,
            port: 80,
            order: &[Protocol::Tls, Protocol::Http],
            expected: Progress::NeedMore,
        },
        Case {
            name: "all invalid remains closed Invalid",
            bytes: b"HTTP/1.1 200 OK\r\n\r\n",
            max_bytes: 64,
            port: 80,
            order: &[Protocol::Dns, Protocol::Http],
            expected: Progress::Invalid,
        },
        Case {
            name: "empty order is NoMatch",
            bytes: http_wire,
            max_bytes: http_wire.len(),
            port: 80,
            order: &[],
            expected: Progress::NoMatch,
        },
    ];
    for case in cases {
        assert_eq!(
            sniff(
                case.bytes,
                case.max_bytes,
                Transport::Tcp,
                case.port,
                case.order
            ),
            case.expected,
            "{}",
            case.name
        );
    }

    for matched in [
        sniff(
            &dns_wire,
            dns_wire.len(),
            Transport::Udp,
            53,
            &[Protocol::Dns],
        ),
        sniff(
            http_wire,
            http_wire.len(),
            Transport::Tcp,
            80,
            &[Protocol::Http],
        ),
    ] {
        let debug = format!("{matched:?}");
        assert!(!debug.contains("ordered.test"));
        assert!(!debug.contains("ordered-http.test"));
    }
}
