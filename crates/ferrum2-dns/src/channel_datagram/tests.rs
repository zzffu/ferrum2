use std::future::poll_fn;
use std::io;
use std::num::NonZeroUsize;

use super::ChannelDnsDatagram;

#[tokio::test]
async fn session_observes_complete_outgoing_datagram_and_publishes_response() {
    let (io, mut outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(512).expect("non-zero limit")).into_parts();

    let sent = poll_fn(|context| io.poll_send(context, b"query"))
        .await
        .expect("send query");
    assert_eq!(sent, 5);
    assert_eq!(outgoing.recv().await.as_deref(), Some(b"query".as_slice()));

    incoming.send(b"response".to_vec()).await.expect("response");
    let mut buffer = [0_u8; 16];
    let received = poll_fn(|context| io.poll_recv(context, &mut buffer))
        .await
        .expect("receive response");
    assert_eq!(&buffer[..received], b"response");
}

#[tokio::test]
async fn oversize_datagrams_fail_closed_at_both_channel_edges() {
    let (io, _outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(4).expect("non-zero limit")).into_parts();

    let send_error = poll_fn(|context| io.poll_send(context, b"large"))
        .await
        .expect_err("oversize send must fail");
    assert_eq!(send_error.kind(), io::ErrorKind::InvalidData);

    incoming.send(b"large".to_vec()).await.expect("response");
    let mut buffer = [0_u8; 4];
    let receive_error = poll_fn(|context| io.poll_recv(context, &mut buffer))
        .await
        .expect_err("oversize response must fail");
    assert_eq!(receive_error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn closed_session_edges_surface_broken_pipe() {
    let (send_io, outgoing, _incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::MIN).into_parts();
    drop(outgoing);
    let send_error = poll_fn(|context| send_io.poll_send(context, b"x"))
        .await
        .expect_err("closed outgoing channel");
    assert_eq!(send_error.kind(), io::ErrorKind::BrokenPipe);

    let (receive_io, _outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::MIN).into_parts();
    drop(incoming);
    let mut buffer = [0_u8; 1];
    let receive_error = poll_fn(|context| receive_io.poll_recv(context, &mut buffer))
        .await
        .expect_err("closed incoming channel");
    assert_eq!(receive_error.kind(), io::ErrorKind::BrokenPipe);
}
