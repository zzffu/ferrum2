use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::wire::IpEndpoint;

use super::{Stack, ip_address};
use crate::packet::{ParsedIpPacket, ParsedPacket, TransportMetadata};
use crate::udp::GenerationId;
use crate::{TCP_REAP_QUANTUM, TcpFlow, TunEvent, TunRejectReason};

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TcpTuple {
    pub(crate) source: SocketAddr,
    pub(crate) target: SocketAddr,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) struct TcpFlowEntry {
    pub(crate) tuple: TcpTuple,
    pub(crate) generation: GenerationId,
    pub(crate) socket: SocketHandle,
    pub(crate) owner: crate::tcp::FlowOwner,
    pub(crate) _registry_owner: ferrum2_runtime::TunTcpFlowOwner,
    pub(crate) pending: Option<TcpFlow>,
    pub(crate) published: bool,
    pub(crate) remote_closed: bool,
    pub(crate) fin_started: bool,
    pub(crate) drive_rx_first: bool,
    pub(crate) active_prev: Option<usize>,
    pub(crate) active_next: Option<usize>,
}

impl Stack {
    pub(crate) fn admit_tcp(&mut self, tuple: TcpTuple, admitting: bool) -> bool {
        if self.flow_index.contains_key(&tuple) {
            return true;
        }
        if !admitting {
            self.reject(TunRejectReason::StaleGeneration);
            return false;
        }
        let Some(&slot) = self.free_flow_slots.last() else {
            self.events.emit(TunEvent::TcpFlowRejectedLimit);
            self.reject(TunRejectReason::TcpFlowLimit);
            return false;
        };
        let Some(generation) = self.generations.current(slot) else {
            self.reject(TunRejectReason::StaleGeneration);
            return false;
        };
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0; self.tcp_buffer_bytes]),
            TcpSocketBuffer::new(vec![0; self.tcp_buffer_bytes]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_millis(
            self.tcp_timeout_millis,
        )));
        socket.set_nagle_enabled(false);
        let endpoint = IpEndpoint::new(ip_address(tuple.target.ip()), tuple.target.port());
        if socket.listen(endpoint).is_err() {
            self.reject(TunRejectReason::InvalidDestination);
            return false;
        }
        let socket = self.sockets.add(socket);
        let (flow, owner) = crate::tcp::tcp_flow_pair_with_events(
            tuple.target,
            self.bridge_capacity,
            self.owner_wake.clone(),
            self.events.clone(),
        );
        let registry_owner = self.registry.track_tun_tcp_flow();
        let claimed_slot = self
            .free_flow_slots
            .pop()
            .expect("observed TCP free slot remains available");
        debug_assert_eq!(claimed_slot, slot);
        self.flows[slot] = Some(TcpFlowEntry {
            tuple,
            generation,
            socket,
            owner,
            _registry_owner: registry_owner,
            pending: Some(flow),
            published: false,
            remote_closed: false,
            fin_started: false,
            drive_rx_first: true,
            active_prev: None,
            active_next: None,
        });
        let replaced = self.flow_index.insert(tuple, generation);
        debug_assert!(replaced.is_none(), "TCP tuple index admitted a duplicate");
        self.attach_tcp_flow(slot);
        self.flow_count.fetch_add(1, Ordering::AcqRel);
        self.events
            .emit(TunEvent::TcpFlowsActive(self.live_tcp_flows()));
        true
    }

    pub(crate) fn attach_tcp_flow(&mut self, slot: usize) {
        let previous = self.active_flow_tail;
        let entry = self.flows[slot]
            .as_mut()
            .expect("new TCP flow occupies its claimed slot");
        entry.active_prev = previous;
        entry.active_next = None;
        if let Some(previous) = previous {
            self.flows[previous]
                .as_mut()
                .expect("TCP active-list tail is live")
                .active_next = Some(slot);
        } else {
            self.active_flow_head = Some(slot);
        }
        self.active_flow_tail = Some(slot);
        self.live_tcp_flow_count += 1;
        self.next_flow_cursor.get_or_insert(slot);
        self.next_reap_cursor.get_or_insert(slot);
    }

    pub(crate) fn active_flow_successor(&self, slot: usize) -> Option<usize> {
        let entry = self.flows.get(slot)?.as_ref()?;
        entry.active_next.or(self.active_flow_head)
    }

    pub(crate) fn take_tcp_flow(&mut self, slot: usize) -> Option<TcpFlowEntry> {
        let entry = self.flows.get_mut(slot)?.take()?;
        match entry.active_prev {
            Some(previous) => {
                self.flows[previous]
                    .as_mut()
                    .expect("TCP active-list predecessor is live")
                    .active_next = entry.active_next;
            }
            None => self.active_flow_head = entry.active_next,
        }
        match entry.active_next {
            Some(next) => {
                self.flows[next]
                    .as_mut()
                    .expect("TCP active-list successor is live")
                    .active_prev = entry.active_prev;
            }
            None => self.active_flow_tail = entry.active_prev,
        }

        let replacement = entry.active_next.or(self.active_flow_head);
        if self.next_flow_cursor == Some(slot) {
            self.next_flow_cursor = replacement;
        }
        if self.next_reap_cursor == Some(slot) {
            self.next_reap_cursor = replacement;
        }
        let indexed = self.flow_index.remove(&entry.tuple);
        debug_assert_eq!(indexed, Some(entry.generation));
        self.live_tcp_flow_count -= 1;
        if self.generations.recycle(entry.generation) {
            self.free_flow_slots.push(slot);
        }
        self.flow_count.fetch_sub(1, Ordering::AcqRel);
        Some(entry)
    }

    pub(crate) fn live_tcp_flows(&self) -> usize {
        self.live_tcp_flow_count
    }

    pub(crate) fn drive_tcp(&mut self) -> bool {
        let flow_visits = self.live_tcp_flow_count;
        if flow_visits == 0 {
            return false;
        }
        let mut worked = false;
        let start = self
            .next_flow_cursor
            .or(self.active_flow_head)
            .expect("non-empty TCP active list has a drive cursor");
        let per_flow_quantum = self.device.validator.mtu.saturating_mul(4).max(16 * 1024);
        let mut total_remaining = per_flow_quantum.saturating_mul(flow_visits.min(16));
        let mut index = start;
        let mut resume = self
            .active_flow_successor(start)
            .expect("TCP active-list cursor has a successor");

        for _ in 0..flow_visits {
            let next = self
                .active_flow_successor(index)
                .expect("visited TCP flow remains linked");
            let entry = self.flows[index]
                .as_mut()
                .expect("TCP active-list slot is live");
            let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);

            if socket.state() == TcpState::Established
                && let Some(flow) = entry.pending.take()
            {
                match self.flow_sender.try_send(flow) {
                    Ok(()) => {
                        entry.published = true;
                        worked = true;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(flow)) => {
                        entry.pending = Some(flow);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        socket.abort();
                        worked = true;
                    }
                }
            }

            if entry.owner.is_aborted() {
                socket.abort();
                worked = true;
            } else {
                let mut flow_remaining = per_flow_quantum.min(total_remaining);
                let receive_ready = entry.owner.application_capacity() != 0 && socket.can_recv();
                let send_ready = entry.owner.stack_buffered() != 0 && socket.may_send();
                let receive_first = entry.drive_rx_first;
                if receive_ready && send_ready {
                    entry.drive_rx_first = !entry.drive_rx_first;
                }
                for receive in [receive_first, !receive_first] {
                    if flow_remaining == 0 {
                        break;
                    }
                    if receive && entry.owner.application_capacity() != 0 && socket.can_recv() {
                        let received = socket
                            .recv(|bytes| {
                                let count = bytes.len().min(flow_remaining);
                                let copied = entry.owner.write_from_stack(&bytes[..count]);
                                (copied, copied)
                            })
                            .unwrap_or(0);
                        flow_remaining -= received;
                        total_remaining -= received;
                        if received != 0 {
                            worked = true;
                            resume = next;
                        }
                    } else if !receive && entry.owner.stack_buffered() != 0 && socket.may_send() {
                        let sent = entry.owner.drain_to_stack(|bytes| {
                            let count = bytes.len().min(flow_remaining);
                            socket.send_slice(&bytes[..count]).unwrap_or(0)
                        });
                        flow_remaining -= sent;
                        total_remaining -= sent;
                        if sent != 0 {
                            worked = true;
                            resume = next;
                        }
                    }
                }
                if socket.state() != TcpState::Closed
                    && !entry.remote_closed
                    && !socket.may_recv()
                    && entry.published
                {
                    entry.owner.mark_remote_closed();
                    entry.remote_closed = true;
                    worked = true;
                }
                if entry.owner.shutdown_requested()
                    && entry.owner.stack_buffered() == 0
                    && !entry.fin_started
                    && socket.may_send()
                {
                    socket.close();
                    entry.fin_started = true;
                    worked = true;
                }
            }

            if socket.state() == TcpState::Closed && !entry.remote_closed {
                entry.owner.mark_reset();
                worked = true;
            }
            index = next;
        }
        self.next_flow_cursor = Some(resume);
        worked
    }

    pub(crate) fn reap_tcp(&mut self) -> usize {
        let mut reaped = 0;
        let flow_visits = self.live_tcp_flow_count.min(TCP_REAP_QUANTUM);
        let output_drained = !self.device.has_output();
        for _ in 0..flow_visits {
            let Some(index) = self.next_reap_cursor else {
                break;
            };
            self.next_reap_cursor = self.active_flow_successor(index);
            let remove = self.flows[index].as_ref().is_some_and(|entry| {
                let socket = self.sockets.get::<TcpSocket>(entry.socket);
                match socket.state() {
                    TcpState::Closed => output_drained && socket.remote_endpoint().is_none(),
                    TcpState::TimeWait => output_drained && entry.remote_closed,
                    _ => false,
                }
            });
            if remove && let Some(entry) = self.take_tcp_flow(index) {
                self.sockets.remove(entry.socket);
                reaped += 1;
            }
        }
        if reaped != 0 {
            self.events
                .emit(TunEvent::TcpFlowsActive(self.live_tcp_flows()));
        }
        reaped
    }

    pub(crate) fn pending_tcp_fin_generation(&self) -> Option<GenerationId> {
        let packet = self.device.front_output()?;
        let Ok(ParsedPacket::Complete(parsed)) = self.device.validator.parse_ingress(packet) else {
            return None;
        };
        let TransportMetadata::Tcp(tcp) = parsed.transport else {
            return None;
        };
        if tcp.flags & 0x01 == 0 {
            return None;
        }
        let tuple = TcpTuple {
            source: SocketAddr::new(parsed.destination, tcp.destination_port),
            target: SocketAddr::new(parsed.source, tcp.source_port),
        };
        let generation = self.flow_index.get(&tuple).copied()?;
        self.flows[generation.slot].as_ref().and_then(|entry| {
            (entry.generation == generation && entry.fin_started).then_some(generation)
        })
    }

    pub(crate) fn complete_sent_tcp_fin(&mut self, generation: GenerationId) {
        let Some(entry) = self.flows[generation.slot].as_mut() else {
            return;
        };
        if entry.generation == generation && entry.fin_started {
            entry.owner.mark_fin_sent();
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) fn initial_tcp_tuple(parsed: ParsedIpPacket) -> Result<Option<TcpTuple>, ()> {
    let TransportMetadata::Tcp(tcp) = parsed.transport else {
        return Ok(None);
    };
    if tcp.flags & 0x02 == 0 {
        return Ok(None);
    }
    if !tcp.is_initial_syn() {
        return Err(());
    }
    Ok(Some(TcpTuple {
        source: SocketAddr::new(parsed.source, tcp.source_port),
        target: SocketAddr::new(parsed.destination, tcp.destination_port),
    }))
}
