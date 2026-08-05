use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use ferrum2_dns::{DnsProxy, DnsProxyListeners, ProxyTransport, TaggedResolver};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[tokio::test]
async fn valid_udp_query_uses_selected_server_and_returns_response() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream bind");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        let (length, peer) = upstream.recv_from(&mut wire).await.expect("query");
        let request = Message::from_vec(&wire[..length]).expect("Hickory request");
        let query = request.queries.first().expect("one question").clone();
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response
            .add_query(query.clone())
            .add_answer(Record::from_rdata(
                query.name().clone(),
                30,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 44))),
            ));
        upstream
            .send_to(&response.to_vec().expect("response encode"), peer)
            .await
            .expect("response send");
    });
    let server = DnsServerConfig {
        transport: DnsTransport::Udp,
        address: upstream_address,
        server_name: None,
        path: None,
        detour: None,
    };
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("nonzero admission"),
    )
    .expect("resolver");
    owner.ready().await.expect("resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = DnsProxy::new(Arc::clone(&resolver), |inbound, transport, name| {
        assert_eq!(inbound, 3);
        assert_eq!(transport, ProxyTransport::Udp);
        assert_eq!(name, &Name::from_ascii("selected.example.").expect("name"));
        0
    });
    let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("selected.example.").expect("query name"),
        RecordType::A,
    ));

    let response = proxy
        .answer(
            3,
            ProxyTransport::Udp,
            &request.to_vec().expect("request encode"),
        )
        .await
        .expect("safe response");
    let response = Message::from_vec(&response).expect("Hickory response");
    assert_eq!(response.id, 0x1234);
    assert_eq!(
        response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(192, 0, 2, 44))))
    );

    upstream_task.await.expect("upstream task");
    drop(proxy);
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("resolver shutdown")
            .runtime_tasks,
        0
    );
    assert!(
        UdpSocket::bind(SocketAddr::new(
            upstream_address.ip(),
            upstream_address.port()
        ))
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn tcp_listener_frames_one_query_and_shuts_down_cleanly() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream bind");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        let (length, peer) = upstream.recv_from(&mut wire).await.expect("query");
        let request = Message::from_vec(&wire[..length]).expect("Hickory request");
        let query = request.queries[0].clone();
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response
            .add_query(query.clone())
            .add_answer(Record::from_rdata(
                query.name().clone(),
                30,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 8))),
            ));
        upstream
            .send_to(&response.to_vec().expect("response encode"), peer)
            .await
            .expect("response send");
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsServerConfig {
            transport: DnsTransport::Udp,
            address: upstream_address,
            server_name: None,
            path: None,
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("nonzero admission"),
    )
    .expect("resolver");
    owner.ready().await.expect("resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = Arc::new(DnsProxy::new(Arc::clone(&resolver), |_, transport, _| {
        assert_eq!(transport, ProxyTransport::Tcp);
        0
    }));
    let reserved = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve");
    let listen = reserved.local_addr().expect("listen");
    drop(reserved);
    let listeners = DnsProxyListeners::bind(
        vec![listen],
        16,
        NonZeroU16::new(1).expect("nonzero connections"),
        Duration::from_secs(1),
        proxy,
    )
    .await
    .expect("paired listeners");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(listeners.run(async move {
        let _ = stopped.await;
    }));
    let mut client = TcpStream::connect(listen).await.expect("TCP connect");
    let mut request = Message::new(0x2345, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("tcp.example.").expect("query name"),
        RecordType::A,
    ));
    let request = request.to_vec().expect("request encode");
    client
        .write_u16(request.len() as u16)
        .await
        .expect("request length");
    client.write_all(&request).await.expect("request");
    let length = client.read_u16().await.expect("response length");
    let mut response = vec![0; usize::from(length)];
    client.read_exact(&mut response).await.expect("response");
    assert_eq!(
        Message::from_vec(&response).expect("response decode").id,
        0x2345
    );

    stop.send(()).expect("stop listeners");
    assert!(running.await.expect("listener task").is_ok());
    upstream_task.await.expect("upstream task");
    drop(client);
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("resolver shutdown")
            .runtime_tasks,
        0
    );
}
