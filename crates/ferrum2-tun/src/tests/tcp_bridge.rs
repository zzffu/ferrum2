use super::support::*;

#[tokio::test]
async fn tcp_flow_queue_backpressure_partial_writes_fin_and_reset_are_lossless() {
    let target: SocketAddr = "192.0.2.10:443".parse().expect("target");
    let (mut flow, mut owner) = tcp_flow_pair(target, 4);
    assert_eq!(flow.target(), target);

    assert_eq!(flow.write(b"abcdef").await.expect("bounded write"), 4);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), flow.write(b"x"))
            .await
            .is_err(),
        "a full Tokio-to-stack queue applies backpressure"
    );
    let mut bytes = [0; 8];
    assert_eq!(owner.read_to_stack(&mut bytes[..2]), 2);
    assert_eq!(&bytes[..2], b"ab");
    assert_eq!(flow.write(b"ef").await.expect("released write"), 2);
    assert_eq!(owner.read_to_stack(&mut bytes), 4);
    assert_eq!(&bytes[..4], b"cdef");

    assert_eq!(owner.write_from_stack(b"abcdef"), 4);
    flow.read_exact(&mut bytes[..2])
        .await
        .expect("partial read");
    assert_eq!(&bytes[..2], b"ab");
    assert_eq!(owner.write_from_stack(b"ef"), 2);
    flow.read_exact(&mut bytes[..4])
        .await
        .expect("retained read");
    assert_eq!(&bytes[..4], b"cdef");

    flow.write_all(b"xy").await.expect("write before FIN");
    assert!(
        tokio::time::timeout(Duration::from_millis(10), flow.shutdown())
            .await
            .is_err(),
        "FIN waits behind accepted bytes"
    );
    assert_eq!(owner.read_to_stack(&mut bytes), 2);
    assert_eq!(&bytes[..2], b"xy");
    assert!(owner.shutdown_requested());
    owner.mark_fin_sent();
    flow.shutdown().await.expect("ordered FIN");
    owner.mark_remote_closed();
    assert_eq!(flow.read(&mut bytes).await.expect("remote FIN"), 0);

    let (mut reset_flow, mut reset_owner) = tcp_flow_pair(target, 4);
    reset_owner.mark_reset();
    assert_eq!(
        reset_flow
            .write(b"closed")
            .await
            .expect_err("reset is terminal")
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );

    let (dropped, owner) = tcp_flow_pair(target, 4);
    drop(dropped);
    assert!(owner.is_aborted(), "dropping a live flow requests reset");
}
