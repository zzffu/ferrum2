use super::*;
/// Runs and drains an authenticated tunnel. Cancellation retains resource guards
/// in aborted workers until their actual destruction.
pub async fn serve_udp<S, B, R>(
    stream: S,
    profile: Profile,
    limits: Limits,
    backend: B,
    resources: R,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    B: UdpBackend,
    R: Send + Sync + 'static,
{
    let shared = Shared::new(profile, limits, resources)?;
    let scratch = Arc::new(receive::Scratch::new(shared.clone())?);
    let mut workers = JoinSet::new();
    let (reader, writer) = tokio::io::split(stream);
    let result = tokio::select! { result = server_reader(reader, shared.clone(), scratch, Arc::new(backend), &mut workers) => result, result = write_loop(writer, shared.clone()) => result, _ = maintenance(shared.clone()) => Ok(()), _ = shared.cancelled() => Err(closed()) };
    shared.stop();
    workers.shutdown().await;
    result
}
async fn server_reader<R: AsyncRead + Unpin, B: UdpBackend>(
    mut reader: R,
    shared: Arc<Shared>,
    scratch: Arc<receive::Scratch>,
    backend: Arc<B>,
    workers: &mut JoinSet<()>,
) -> io::Result<()> {
    let mut highest = 0;
    loop {
        while workers.try_join_next().is_some() {}
        let Some(packet) = read_frame(&mut reader, &shared).await? else {
            continue;
        };
        match packet.kind {
            OPEN => {
                if packet.id <= highest {
                    return Err(invalid());
                }
                highest = packet.id;
                let target = wire::decode_target(&packet.body)?;
                let reservation = match backend.reserve_session() {
                    Ok(reservation) => reservation,
                    Err(_) => {
                        shared.control(OPEN_RESULT, packet.id, &[1])?;
                        continue;
                    }
                };
                let session = {
                    let mut state = lock(&shared.state);
                    shared.insert(&mut state, packet.id)
                };
                match session {
                    Ok(session) => {
                        let owner = shared.clone();
                        let backend = backend.clone();
                        let scratch = scratch.clone();
                        workers.spawn(async move {
                            let result = tokio::select! { result = server_session(owner.clone(), session.clone(), scratch, backend, reservation, target) => Some(result), _ = session.cancelled() => None, _ = owner.cancelled() => None };
                            if let Some(Err(_)) = result {
                                let pending = lock(&session.state).peer.is_none();
                                if pending && owner.control(OPEN_RESULT, session.id, &[1]).is_err() { owner.stop(); }
                                owner.remove(session.id, !pending);
                            }
                        });
                    }
                    Err(_) => shared.control(OPEN_RESULT, packet.id, &[1])?,
                }
            }
            DATA => {
                let session = lock(&shared.state).sessions.get(&packet.id).cloned();
                if let Some(session) = session {
                    let _ = shared.enqueue(&session, packet, false);
                }
            }
            CLOSE => shared.remove(packet.id, false),
            PING => shared.control(PONG, 0, &[])?,
            PONG => {}
            _ => return Err(invalid()),
        }
    }
}
async fn incoming(shared: &Shared, session: &Session) -> Packet {
    loop {
        let notified = session.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut state = lock(&session.state);
            while let Some(packet) = state.inbound.pop_front() {
                if packet.created.elapsed() <= shared.policy.residence {
                    return packet;
                }
            }
        }
        notified.await;
    }
}
async fn server_session<B: UdpBackend>(
    shared: Arc<Shared>,
    session: Arc<Session>,
    scratch: Arc<receive::Scratch>,
    backend: Arc<B>,
    reservation: B::Reservation,
    target: TargetAddr,
) -> io::Result<()> {
    let first = timeout(
        shared.limits.idle_timeout.min(STALL),
        incoming(&shared, &session),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "F2P UDP open expired"))?;
    let socket = timeout(STALL, backend.connect(reservation, &target, &first.body))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "F2P UDP destination stalled"))??;
    let peer = socket.peer_addr()?;
    let mut response = Vec::with_capacity(20);
    response.push(0);
    wire::encode_endpoint(peer, &mut response);
    let reply = shared.packet(Some(&session), OPEN_RESULT, session.id, &response)?;
    shared.enqueue(&session, reply, true)?;
    lock(&session.state).peer = Some(peer);
    if first.created.elapsed() <= shared.policy.residence {
        timeout(
            shared
                .policy
                .residence
                .saturating_sub(first.created.elapsed()),
            socket.send(&first.body),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "F2P UDP destination send stalled")
        })??;
    }
    drop(first);
    let send = async {
        loop {
            let packet = incoming(&shared, &session).await;
            match timeout(
                shared
                    .policy
                    .residence
                    .saturating_sub(packet.created.elapsed()),
                socket.send(&packet.body),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "F2P UDP destination send stalled",
                    ));
                }
            }
            tokio::task::yield_now().await;
        }
    };
    let receive = async {
        loop {
            socket.readable().await?;
            match scratch.receive(&socket, &session) {
                Ok(packet) => {
                    shared.enqueue(&session, packet, true)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! { result = send => result, result = receive => result }
}
