use super::*;
// This future is never cancelled and restarted: only tunnel teardown cancels it.
pub(super) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    shared: &Shared,
) -> io::Result<Option<Packet>> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;
    let kind = header[0];
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let id = u32::from_be_bytes(header[4..8].try_into().map_err(|_| invalid())?);
    if header[1] != 0 || !matches!(kind, OPEN..=PONG) || ((id == 0) != matches!(kind, PING | PONG))
    {
        return Err(invalid());
    }
    match kind {
        OPEN if !(5..=wire::MAX_TARGET_LEN).contains(&length) => return Err(invalid()),
        OPEN_RESULT if !(1..=20).contains(&length) => return Err(invalid()),
        DATA if length > MAX_DATA => return Err(invalid()),
        CLOSE | PING | PONG if length != 0 => return Err(invalid()),
        _ => {}
    }
    let session = lock(&shared.state).sessions.get(&id).cloned();
    let charge = shared.charge(session.as_deref(), length + PACKET_OVERHEAD);
    if kind == DATA && (session.is_none() || charge.is_err()) {
        let mut discard = [0u8; 1024];
        let mut left = length;
        while left != 0 {
            let count = left.min(discard.len());
            reader.read_exact(&mut discard[..count]).await?;
            left -= count;
        }
        return Ok(None);
    }
    let charge = charge?;
    let mut body = vec![0u8; length].into_boxed_slice();
    reader.read_exact(&mut body).await?;
    Ok(Some(Packet {
        kind,
        id,
        body,
        created: Instant::now(),
        _charge: charge,
    }))
}
pub(super) async fn client_reader<R: AsyncRead + Unpin>(
    mut reader: R,
    shared: Arc<Shared>,
) -> io::Result<()> {
    loop {
        let Some(packet) = read_frame(&mut reader, &shared).await? else {
            continue;
        };
        match packet.kind {
            DATA => {
                let session = lock(&shared.state).sessions.get(&packet.id).cloned();
                if let Some(session) = session {
                    if lock(&session.state).peer.is_none() {
                        return Err(invalid());
                    }
                    let _ = shared.enqueue(&session, packet, false);
                }
            }
            OPEN_RESULT => {
                let peer = if packet.body[0] == 0 {
                    Some(wire::decode_endpoint(&packet.body[1..])?)
                } else {
                    if packet.body.len() != 1 {
                        return Err(invalid());
                    }
                    wire::decode_error(packet.body[0])?;
                    None
                };
                let session = lock(&shared.state).sessions.get(&packet.id).cloned();
                if let Some(session) = session {
                    if let Some(peer) = peer {
                        let mut state = lock(&session.state);
                        if state.peer.replace(peer).is_some() {
                            return Err(invalid());
                        }
                        if let Some(waker) = state.receiver.take() {
                            waker.wake();
                        }
                        session.notify.notify_waiters();
                    } else {
                        shared.remove(packet.id, false);
                    }
                }
            }
            CLOSE => shared.remove(packet.id, false),
            PING => shared.control(PONG, 0, &[])?,
            PONG => {}
            _ => return Err(invalid()),
        }
    }
}
fn next_packet(shared: &Shared, cursor: &mut u32, control_turn: &mut bool) -> Option<Packet> {
    let mut state = lock(&shared.state);
    if *control_turn && let Some(packet) = state.controls.pop_front() {
        *control_turn = false;
        return Some(packet);
    }
    let candidate = state
        .sessions
        .range((
            std::ops::Bound::Excluded(*cursor),
            std::ops::Bound::Unbounded,
        ))
        .chain(state.sessions.range(..=*cursor))
        .find_map(|(id, session)| {
            let mut queues = lock(&session.state);
            while let Some(packet) = queues.outbound.pop_front() {
                if packet.kind != DATA || packet.created.elapsed() <= shared.policy.residence {
                    return Some((*id, packet));
                }
            }
            None
        });
    if let Some((id, packet)) = candidate {
        *cursor = id;
        *control_turn = true;
        Some(packet)
    } else {
        state.controls.pop_front()
    }
}
pub(super) async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let mut cursor = 0;
    let mut control_turn = true;
    loop {
        let notified = shared.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let mut count = 0;
        let mut bytes = 0;
        while count < shared.policy.turn_frames && bytes < shared.policy.turn_bytes {
            let Some(packet) = next_packet(&shared, &mut cursor, &mut control_turn) else {
                break;
            };
            let length = (packet.body.len() as u16).to_be_bytes();
            let id = packet.id.to_be_bytes();
            let header = [
                packet.kind,
                0,
                length[0],
                length[1],
                id[0],
                id[1],
                id[2],
                id[3],
            ];
            // Once the first byte is committed, expiry cannot interrupt this frame.
            timeout(STALL, async {
                writer.write_all(&header).await?;
                writer.write_all(&packet.body).await
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "F2P UDP write stalled"))??;
            count += 1;
            bytes += packet.body.len() + 8;
        }
        if count != 0 {
            timeout(STALL, writer.flush())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "F2P UDP flush stalled"))??;
            tokio::task::yield_now().await;
        } else {
            notified.await;
        }
    }
}
pub(super) async fn maintenance(shared: Arc<Shared>) {
    let period = shared.limits.idle_timeout.min(Duration::from_millis(250));
    loop {
        tokio::time::sleep(period).await;
        // Remove one at a time; do not allocate a second unbudgeted ID list.
        loop {
            let expired = {
                let state = lock(&shared.state);
                state.sessions.iter().find_map(|(id, session)| {
                    (lock(&session.state).last.elapsed() >= shared.limits.idle_timeout)
                        .then_some(*id)
                })
            };
            if let Some(id) = expired {
                shared.remove(id, true);
            } else {
                break;
            }
        }
    }
}
