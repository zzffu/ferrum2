use std::future::poll_fn;
use std::io;
use std::num::NonZeroUsize;
use std::time::Duration;

use tokio::time::timeout;

use super::ChannelDnsDatagram;

#[cfg(feature = "structural-metrics")]
#[tokio::test]
async fn structural_counters_report_fixed_leases_and_only_actual_slice_copies() {
    use ferrum2_structural::{StructuralCounter, StructuralHub};

    let structural = StructuralHub::new();
    let local = structural.local();
    let (io, mut outgoing, incoming) = ChannelDnsDatagram::bounded_structural(
        NonZeroUsize::new(32).expect("non-zero limit"),
        &local,
    )
    .into_parts();
    assert_eq!(
        structural
            .snapshot()
            .get(StructuralCounter::DnsUdpAllocations),
        2,
        "one fixed lease is allocated for each channel direction",
    );

    poll_fn(|context| io.poll_send(context, b"query"))
        .await
        .expect("instrumented query");
    let query = outgoing.recv().await.expect("instrumented outgoing lease");
    assert_eq!(query.as_slice(), b"query");
    drop(query);

    let mut response = incoming.lease().await.expect("instrumented response lease");
    response
        .extend_from_slice(b"answer")
        .expect("bounded instrumented response");
    incoming
        .send(response)
        .await
        .expect("instrumented response");
    let mut output = [0_u8; 16];
    let received = poll_fn(|context| io.poll_recv(context, &mut output))
        .await
        .expect("instrumented receive");
    assert_eq!(&output[..received], b"answer");

    let snapshot = structural.snapshot();
    assert_eq!(snapshot.get(StructuralCounter::DnsUdpAllocations), 2);
    assert_eq!(
        snapshot.get(StructuralCounter::DnsUdpCopyBytes),
        u64::try_from(b"query".len() + b"answer".len()).expect("small copy count"),
        "only the two required slice-oriented DnsDatagramIo boundaries copy bytes",
    );
}

#[tokio::test]
async fn session_observes_complete_outgoing_datagram_and_publishes_response() {
    let (io, mut outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(512).expect("non-zero limit")).into_parts();

    let sent = poll_fn(|context| io.poll_send(context, b"query"))
        .await
        .expect("send query");
    assert_eq!(sent, 5);
    let packet = outgoing.recv().await.expect("outgoing query");
    assert_eq!(packet.as_slice(), b"query");
    drop(packet);

    let mut response = incoming.lease().await.expect("incoming lease");
    response
        .extend_from_slice(b"response")
        .expect("bounded response");
    incoming.send(response).await.expect("response");
    let mut buffer = [0_u8; 16];
    let received = poll_fn(|context| io.poll_recv(context, &mut buffer))
        .await
        .expect("receive response");
    assert_eq!(&buffer[..received], b"response");
}

#[tokio::test]
async fn both_direction_allocations_are_reused_by_identity() {
    let (io, mut outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(512).expect("non-zero limit")).into_parts();

    poll_fn(|context| io.poll_send(context, b"first"))
        .await
        .expect("first send");
    let first = outgoing.recv().await.expect("first outgoing lease");
    let outgoing_pointer = first.as_slice().as_ptr();
    drop(first);
    poll_fn(|context| io.poll_send(context, b"second"))
        .await
        .expect("second send");
    let second = outgoing.recv().await.expect("second outgoing lease");
    assert_eq!(second.as_slice().as_ptr(), outgoing_pointer);
    drop(second);

    let mut first = incoming.lease().await.expect("first incoming lease");
    let incoming_pointer = first.as_slice().as_ptr();
    first.extend_from_slice(b"one").expect("first response");
    incoming.send(first).await.expect("send first response");
    let mut buffer = [0_u8; 16];
    poll_fn(|context| io.poll_recv(context, &mut buffer))
        .await
        .expect("receive first response");
    let second = incoming.lease().await.expect("second incoming lease");
    assert_eq!(second.as_slice().as_ptr(), incoming_pointer);
}

#[tokio::test]
async fn small_large_small_reuses_identity_and_owned_response_swap_does_not_copy() {
    let (io, mut outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(512).expect("non-zero limit")).into_parts();
    let mut outgoing_pointer = None;
    for payload in [&b"small"[..], &[0x5a; 400][..], &b"again"[..]] {
        poll_fn(|context| io.poll_send(context, payload))
            .await
            .expect("bounded outgoing datagram");
        let packet = outgoing.recv().await.expect("outgoing lease");
        match outgoing_pointer {
            Some(pointer) => assert_eq!(packet.as_slice().as_ptr(), pointer),
            None => outgoing_pointer = Some(packet.as_slice().as_ptr()),
        }
        assert_eq!(packet.as_slice(), payload);
        drop(packet);
    }

    let mut response = incoming.lease().await.expect("incoming lease");
    let displaced_pointer = response.as_slice().as_ptr();
    let mut owned = bytes::BytesMut::from(&b"owned response"[..]);
    let owned_pointer = owned.as_ptr();
    response
        .swap_bytes_mut(&mut owned)
        .expect("bounded owned response");
    assert_eq!(response.as_slice().as_ptr(), owned_pointer);
    assert_eq!(owned.as_ptr(), displaced_pointer);
    incoming.send(response).await.expect("send moved response");
    let mut buffer = [0_u8; 32];
    let received = poll_fn(|context| io.poll_recv(context, &mut buffer))
        .await
        .expect("receive moved response");
    assert_eq!(&buffer[..received], b"owned response");
}

#[tokio::test]
async fn cancelled_lease_wait_returns_the_buffer_and_wakes_the_next_waiter() {
    let (_io, _outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(32).expect("non-zero limit")).into_parts();
    let lease = incoming.lease().await.expect("first lease");
    let pointer = lease.as_slice().as_ptr();

    let cancelled = timeout(Duration::from_millis(10), incoming.lease()).await;
    assert!(cancelled.is_err(), "sole lease must apply backpressure");
    drop(lease);

    let recycled = timeout(Duration::from_secs(1), incoming.lease())
        .await
        .expect("returned lease must wake waiter")
        .expect("recycled lease");
    assert_eq!(recycled.as_slice().as_ptr(), pointer);
}

#[tokio::test]
async fn dropping_io_returns_a_queued_incoming_lease() {
    let (io, _outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(32).expect("non-zero limit")).into_parts();
    let mut lease = incoming.lease().await.expect("incoming lease");
    let pointer = lease.as_slice().as_ptr();
    lease.extend_from_slice(b"response").expect("response");
    incoming.send(lease).await.expect("queue response");

    drop(io);

    let recycled = timeout(Duration::from_secs(1), incoming.lease())
        .await
        .expect("dropping receiver must return queued lease")
        .expect("recycled lease");
    assert_eq!(recycled.as_slice().as_ptr(), pointer);
    assert!(recycled.is_empty());
    assert!(incoming.is_closed());
}

#[tokio::test]
async fn oversize_datagrams_fail_closed_at_both_channel_edges() {
    let (io, _outgoing, incoming) =
        ChannelDnsDatagram::bounded(NonZeroUsize::new(4).expect("non-zero limit")).into_parts();

    let send_error = poll_fn(|context| io.poll_send(context, b"large"))
        .await
        .expect_err("oversize send must fail");
    assert_eq!(send_error.kind(), io::ErrorKind::InvalidData);

    let mut response = incoming.lease().await.expect("incoming lease");
    let extend_error = response
        .extend_from_slice(b"large")
        .expect_err("bounded lease must reject oversize response");
    assert_eq!(extend_error.kind(), io::ErrorKind::InvalidData);

    response.as_bytes_mut().extend_from_slice(b"large");
    incoming.send(response).await.expect("malformed response");
    let mut buffer = [0_u8; 8];
    let receive_error = poll_fn(|context| io.poll_recv(context, &mut buffer))
        .await
        .expect_err("oversize response must fail");
    assert_eq!(receive_error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn pending_send_observes_session_close_as_broken_pipe() {
    let (io, outgoing, _incoming) = ChannelDnsDatagram::bounded(NonZeroUsize::MIN).into_parts();
    poll_fn(|context| io.poll_send(context, b"x"))
        .await
        .expect("first send fills channel");

    let pending = timeout(
        Duration::from_millis(10),
        poll_fn(|context| io.poll_send(context, b"y")),
    )
    .await;
    assert!(
        pending.is_err(),
        "full lease channel must apply backpressure"
    );
    drop(outgoing);

    let send_error = timeout(
        Duration::from_secs(1),
        poll_fn(|context| io.poll_send(context, b"y")),
    )
    .await
    .expect("close must wake pending sender")
    .expect_err("closed outgoing channel");
    assert_eq!(send_error.kind(), io::ErrorKind::BrokenPipe);
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
