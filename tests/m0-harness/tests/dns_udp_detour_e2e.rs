#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use local_support::{
    ChildGuard, DnsReply, DnsStep, SYNTHETIC_PSK, active_child_count, bind_loopback_listener,
    start_dns_script, unused_loopback, unused_tcp_udp_loopback, wait_for_listener,
    write_server_config,
};

#[test]
fn dedicated_dns_udp_upstream_uses_shadowsocks_detour() {
    let spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("dedicated DNS detour tempdir");
    let upstream = start_dns_script(
        ["UDP", "TCP"]
            .map(|_| DnsStep {
                record_type: RecordType::A,
                reply: DnsReply::Addresses(vec![Ipv4Addr::new(192, 0, 2, 80)]),
            })
            .into(),
    );
    let upstream_address = upstream.address();
    let server_address = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let dns_listen = unused_tcp_udp_loopback();
    let server_config =
        write_server_config(directory.path(), server_address, None).expect("DNS detour server");
    let client_config = directory.path().join("dns-udp-detour-client.toml");
    std::fs::write(
        &client_config,
        format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"socks\"\nlisten = \"{client_address}\"\n\
             [[outbounds]]\ntag = \"dns-hop\"\ntype = \"shadowsocks\"\nserver = \"{server_address}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [route]\nfinal = \"dns-hop\"\n\
             [dns]\ntimeout_ms = 5000\nmax_inflight = 4\n\
             [[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"{dns_listen}\"\n\
             [[dns.servers]]\ntag = \"core\"\ntransport = \"udp\"\naddress = \"{upstream_address}\"\ndetour = \"dns-hop\"\n\
             [dns.route]\nfinal = \"core\"\n\
             [udp]\n"
        ),
    )
    .expect("DNS detour client config");

    let mut server =
        ChildGuard::spawn_while_holding("ferrum2-server", &server_config, &spawn_guard);
    wait_for_listener(&mut server, server_address);
    let mut client =
        ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &spawn_guard);
    wait_for_listener(&mut client, dns_listen);
    drop(spawn_guard);

    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("DNS detour probe");
    probe
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("DNS detour probe timeout");
    let query = qualification_query(0x1201, "udp-answer.qualification.test.");
    probe
        .send_to(&query, dns_listen)
        .expect("send DNS detour query");
    let mut wire = [0_u8; 4096];
    let (length, source) = probe
        .recv_from(&mut wire)
        .expect("receive DNS detour response");
    assert_eq!(source, SocketAddr::V4(dns_listen));
    assert_a_response(&wire[..length], 0x1201);
    drop(probe);

    let mut tcp = TcpStream::connect(dns_listen).expect("connect TCP DNS detour probe");
    tcp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("TCP DNS detour read timeout");
    tcp.set_write_timeout(Some(Duration::from_secs(2)))
        .expect("TCP DNS detour write timeout");
    let query = qualification_query(0x1202, "tcp-answer.qualification.test.");
    tcp.write_all(
        &u16::try_from(query.len())
            .expect("TCP DNS query length")
            .to_be_bytes(),
    )
    .expect("write TCP DNS detour length");
    tcp.write_all(&query).expect("write TCP DNS detour query");
    let mut length = [0_u8; 2];
    tcp.read_exact(&mut length)
        .expect("read TCP DNS detour length");
    let mut wire = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    tcp.read_exact(&mut wire)
        .expect("read TCP DNS detour response");
    assert_a_response(&wire, 0x1202);
    drop(tcp);
    assert_eq!(upstream.join(), [RecordType::A, RecordType::A]);

    let exits = [
        client.terminate_and_reap_with_exit(Duration::from_secs(5)),
        server.terminate_and_reap_with_exit(Duration::from_secs(5)),
    ];
    for exit in &exits {
        exit.assert_stderr_excludes(&[
            "answer.qualification.test",
            "dns-hop",
            "dns-in",
            SYNTHETIC_PSK,
        ]);
    }
    let spawn_guard = local_support::hold_process_spawns_at_or_below(baseline_children);
    assert_eq!(active_child_count(), baseline_children);
    for address in [client_address, dns_listen, server_address] {
        drop(bind_loopback_listener(address).expect("DNS detour TCP exact rebind"));
        drop(UdpSocket::bind(address).expect("DNS detour UDP exact rebind"));
    }
    drop(UdpSocket::bind(upstream_address).expect("DNS upstream exact rebind"));
    drop(spawn_guard);
}

fn qualification_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query
        .add_query(Query::query(
            Name::from_ascii(name).expect("DNS detour query name"),
            RecordType::A,
        ))
        .set_edns({
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns
        });
    query.to_vec().expect("DNS detour query")
}

fn assert_a_response(wire: &[u8], id: u16) {
    let response = Message::from_vec(wire).expect("typed DNS detour response");
    assert_eq!(response.id, id);
    assert!(response.answers.iter().any(|record| {
        matches!(&record.data, RData::A(address) if address.0 == Ipv4Addr::new(192, 0, 2, 80))
    }));
}
