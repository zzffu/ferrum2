use std::collections::VecDeque;
use std::sync::Mutex;

use bytes::BytesMut;

use super::*;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(value) => value,
        Err(_) => panic!("response adapter lock poisoned"),
    }
}
struct Responses {
    packets: Mutex<VecDeque<io::Result<Vec<u8>>>>,
    buffers: Mutex<Vec<usize>>,
}

impl Responses {
    fn new(packets: impl IntoIterator<Item = io::Result<Vec<u8>>>) -> Self {
        Self {
            packets: Mutex::new(packets.into_iter().collect()),
            buffers: Mutex::new(Vec::new()),
        }
    }
}

impl DirectUdpSocket for Responses {
    async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn readable(&self) -> io::Result<()> {
        if lock(&self.packets).is_empty() {
            std::future::pending().await
        } else {
            Ok(())
        }
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        self.try_recv_buf_from(payload)
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        lock(&self.buffers).push(payload.as_ptr() as usize);
        let packet = lock(&self.packets).pop_front().unwrap()?;
        assert!(
            payload.capacity() >= packet.len(),
            "complete UDP reception capacity"
        );
        payload.extend_from_slice(&packet);
        Ok((packet.len(), "127.0.0.1:9000".parse().unwrap()))
    }
}

#[tokio::test]
async fn retained_bytes_and_reservation_each_keep_physical_capacity_charged() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget = UdpBufferBudget::new(MAX_UDP_WIRE_DATAGRAM_BYTES, registry.clone());
    let socket = Responses::new([Ok(vec![1, 2, 3, 4])]);
    let response = receive_target(&socket, budget.clone(), registry.clone())
        .await
        .unwrap();
    let (datagram, reservation) = response.into_parts();
    let (_, bytes) = datagram.into_parts();
    let retained = bytes.slice(1..3);
    drop(bytes);
    drop(reservation);
    assert_eq!(&retained[..], &[2, 3]);
    assert_eq!(budget.reserved_bytes(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    assert_eq!(budget.reserve(1).unwrap_err(), UdpRuntimeError::BufferLimit);

    // A reset can evict idle storage, not storage still retained by a consumer.
    budget.clear_receive_cache();
    assert_eq!(budget.reserved_bytes(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot(), baseline);

    let socket = Responses::new([Ok(vec![5])]);
    let response = receive_target(&socket, budget.clone(), registry.clone())
        .await
        .unwrap();
    let (datagram, reservation) = response.into_parts();
    drop(datagram);
    budget.clear_receive_cache();
    assert_eq!(budget.reserve(1).unwrap_err(), UdpRuntimeError::BufferLimit);
    drop(reservation);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn false_readiness_and_full_size_responses_reuse_one_shared_allocation() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget = UdpBufferBudget::new(MAX_UDP_WIRE_DATAGRAM_BYTES, registry.clone());
    let large = vec![0xa5; MAX_UDP_WIRE_DATAGRAM_BYTES];
    let first_socket = Responses::new([Err(io::ErrorKind::WouldBlock.into()), Ok(large.clone())]);
    let response = receive_target(&first_socket, budget.clone(), registry.clone())
        .await
        .unwrap();
    assert_eq!(response.datagram().payload(), large);
    assert_eq!(response.allocated_capacity(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    let address = response.datagram().payload().as_ptr() as usize;
    assert_eq!(*lock(&first_socket.buffers), vec![address, address]);
    drop(response);

    // Different sessions sharing the byte domain reuse the same idle allocation.
    let second_socket = Responses::new([Ok(vec![7, 8])]);
    let response = receive_target(&second_socket, budget.clone(), registry.clone())
        .await
        .unwrap();
    assert_eq!(response.datagram().payload(), &[7, 8]);
    assert_eq!(response.datagram().payload().as_ptr() as usize, address);
    drop(response);
    assert_eq!(budget.reserved_bytes(), MAX_UDP_WIRE_DATAGRAM_BYTES);

    // Cached storage never starves a non-receive reservation.
    let ordinary = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES).unwrap();
    drop(ordinary);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn receive_errors_and_cancelled_false_readiness_release_active_owners() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget = UdpBufferBudget::new(MAX_UDP_WIRE_DATAGRAM_BYTES, registry.clone());
    let failed_socket = Responses::new([Err(io::ErrorKind::ConnectionReset.into())]);
    assert_eq!(
        receive_target(&failed_socket, budget.clone(), registry.clone())
            .await
            .unwrap_err(),
        UdpRuntimeError::Receive,
    );
    budget.clear_receive_cache();
    assert_eq!(registry.snapshot(), baseline);

    let false_ready = Responses::new([Err(io::ErrorKind::WouldBlock.into())]);
    {
        let receive = receive_target(&false_ready, budget.clone(), registry.clone());
        tokio::pin!(receive);
        tokio::select! {
            biased;
            result = &mut receive => panic!("false readiness completed: {result:?}"),
            () = std::future::ready(()) => {}
        }
    }
    assert_eq!(registry.snapshot().udp_scratch_buffers, 0);
    budget.clear_receive_cache();
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn idle_receive_does_not_allocate_or_reserve_capacity() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget = UdpBufferBudget::new(MAX_UDP_WIRE_DATAGRAM_BYTES, registry.clone());
    let socket = Responses::new([]);
    let receive = receive_target(&socket, budget, registry.clone());
    tokio::pin!(receive);
    tokio::select! {
        biased;
        result = &mut receive => panic!("idle receive completed: {result:?}"),
        () = std::future::ready(()) => {}
    }
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn concurrent_responses_cache_only_one_buffer_and_last_owner_releases_it() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget = UdpBufferBudget::new(2 * MAX_UDP_WIRE_DATAGRAM_BYTES, registry.clone());
    let socket = Responses::new([Ok(vec![1]), Ok(vec![2])]);
    let first = receive_target(&socket, budget.clone(), registry.clone())
        .await
        .unwrap();
    let second = receive_target(&socket, budget.clone(), registry.clone())
        .await
        .unwrap();
    assert_eq!(first.datagram().payload(), &[1]);
    assert_eq!(second.datagram().payload(), &[2]);
    assert_eq!(budget.reserved_bytes(), 2 * MAX_UDP_WIRE_DATAGRAM_BYTES);
    drop(first);
    drop(second);
    assert_eq!(budget.reserved_bytes(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    drop(budget);
    assert_eq!(registry.snapshot(), baseline);
}
