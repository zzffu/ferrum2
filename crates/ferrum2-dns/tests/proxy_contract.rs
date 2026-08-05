use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use ferrum2_dns::{DnsProxy, ProxyTransport, TaggedResolver};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

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
        response.add_query(query.clone()).add_answer(Record::from_rdata(
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
    assert_eq!(owner.shutdown().await.expect("resolver shutdown").runtime_tasks, 0);
    assert!(UdpSocket::bind(SocketAddr::new(upstream_address.ip(), upstream_address.port()))
        .await
        .is_ok());
}
