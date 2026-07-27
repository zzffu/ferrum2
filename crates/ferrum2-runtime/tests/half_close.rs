use ferrum2_runtime::relay_bidirectional;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn one_way_eof_allows_reverse_direction_to_drain() {
    let (mut application, mut relay_inbound) = tokio::io::duplex(64);
    let (mut relay_outbound, mut target) = tokio::io::duplex(64);

    let owner =
        tokio::spawn(
            async move { relay_bidirectional(&mut relay_inbound, &mut relay_outbound).await },
        );

    application
        .write_all(b"request")
        .await
        .expect("write request");
    application.shutdown().await.expect("half-close request");

    let mut request = Vec::new();
    target
        .read_to_end(&mut request)
        .await
        .expect("read request through relay");
    assert_eq!(request, b"request");

    target
        .write_all(b"response-after-eof")
        .await
        .expect("write reverse response");
    target.shutdown().await.expect("half-close response");

    let mut response = Vec::new();
    application
        .read_to_end(&mut response)
        .await
        .expect("drain reverse response");
    assert_eq!(response, b"response-after-eof");

    let stats = owner.await.expect("owner task").expect("relay completes");
    assert_eq!(stats.inbound_to_outbound, 7);
    assert_eq!(stats.outbound_to_inbound, 18);
}
