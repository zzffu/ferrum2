use std::future::pending;
use std::time::Duration;

use ferrum2_runtime::{OwnerRegistry, relay_lifecycle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn one_way_eof_allows_reverse_direction_to_drain() {
    let (mut application, mut relay_inbound) = tokio::io::duplex(64);
    let (mut relay_outbound, mut target) = tokio::io::duplex(64);
    let registry = OwnerRegistry::new();
    let registry_for_owner = registry.clone();

    let owner = tokio::spawn(async move {
        relay_lifecycle(
            &mut relay_inbound,
            &mut relay_outbound,
            Duration::from_secs(60),
            &registry_for_owner,
            pending(),
        )
        .await
    });

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
    assert_eq!(registry.snapshot().owned_buffers, 0);
}
