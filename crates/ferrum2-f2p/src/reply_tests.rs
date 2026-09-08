use super::*;

#[tokio::test]
async fn partial_tcp_reply_survives_cancelled_read_wait() {
    let (client_config, server_config) = tests::configs(false, "resolver.test", true);
    let (left, right) = tokio::io::duplex(8192);
    let target = TargetAddr::domain("destination.test", 443).unwrap();
    let (client, server) = tokio::join!(
        connect_tcp(left, &client_config, Profile::Balanced, &target),
        accept(right, &server_config)
    );
    let mut client = client.unwrap();
    let Accepted::Tcp { mut stream, .. } = server.unwrap() else {
        panic!("TCP mode");
    };
    // Success + IPv4 endpoint length, with only half of its address delivered.
    stream.inner.write_all(&[0, 7, 1, 127, 0]).await.unwrap();
    stream.inner.flush().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(5), client.read_u8())
            .await
            .is_err()
    );
    stream.inner.write_all(&[0, 1, 0, 80, 42]).await.unwrap();
    stream.inner.flush().await.unwrap();
    assert_eq!(client.read_u8().await.unwrap(), 42);
}

#[tokio::test]
async fn malformed_tcp_reply_cannot_expose_payload_or_resume_writes() {
    let (client_config, server_config) = tests::configs(false, "resolver.test", true);
    let (left, right) = tokio::io::duplex(8192);
    let target = TargetAddr::domain("destination.test", 443).unwrap();
    let (client, server) = tokio::join!(
        connect_tcp(left, &client_config, Profile::Balanced, &target),
        accept(right, &server_config)
    );
    let mut client = client.unwrap();
    let Accepted::Tcp { mut stream, .. } = server.unwrap() else {
        panic!("TCP mode");
    };
    stream.inner.write_all(&[0, 255, 42]).await.unwrap();
    stream.inner.flush().await.unwrap();
    assert_eq!(
        client.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(client.write_all(b"not a relay").await.is_err());
}

#[tokio::test(start_paused = true)]
async fn delayed_first_read_accepts_already_delivered_target_reply() {
    let (client_config, server_config) = tests::configs(false, "resolver.test", true);
    let (left, right) = tokio::io::duplex(8192);
    let target = TargetAddr::domain("destination.test", 443).unwrap();
    let (client, server) = tokio::join!(
        connect_tcp(left, &client_config, Profile::Balanced, &target),
        accept(right, &server_config)
    );
    let mut client = client.unwrap();
    let Accepted::Tcp { mut stream, .. } = server.unwrap() else {
        panic!("TCP mode");
    };
    respond_tcp(&mut stream, Ok("127.0.0.1:80".parse().unwrap()))
        .await
        .unwrap();
    stream.write_all(b"ready").await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
    let mut response = [0_u8; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ready");
}
