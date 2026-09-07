use super::Stack;
use crate::{TunEvent, UdpResponseDropReason};

impl Stack {
    /// The native owner must stop packet polling and admission before this call.
    /// Fencing wakes applications but keeps all bounded storage for retirement.
    pub(crate) fn fence_generation(&mut self, next_generation: u64) -> Result<(), ()> {
        if let Some(fenced) = self.fenced_generation {
            return if fenced == next_generation {
                Ok(())
            } else {
                Err(())
            };
        }
        if next_generation <= self.session_generation {
            return Err(());
        }
        self.fence_owners(next_generation);
        Ok(())
    }

    fn fence_owners(&mut self, next_generation: u64) {
        self.fenced_generation = Some(next_generation);
        self.udp.fence_session(next_generation);
        let mut active = self.active_flow_head;
        while let Some(slot) = active {
            let entry = self.flows[slot].as_mut().expect("active TCP flow");
            entry.owner.fence_generation();
            active = entry.active_next;
        }
    }

    /// Final shutdown/full rebuild may also close the last representable generation.
    pub(crate) fn quiesce(&mut self, next_generation: u64, reason: UdpResponseDropReason) -> usize {
        if self.fenced_generation.is_none() && self.fence_generation(next_generation).is_err() {
            // This epoch is used only to invalidate a terminal stack, never for reopening.
            self.fence_owners(self.session_generation.wrapping_add(1));
        }
        let generation = self.fenced_generation.expect("quiescent stack is fenced");
        self.retire_generation(generation, reason)
            .expect("owned fence")
    }

    pub(crate) fn retire_generation(
        &mut self,
        next_generation: u64,
        udp_response_drop_reason: UdpResponseDropReason,
    ) -> Result<usize, ()> {
        if self.fenced_generation != Some(next_generation) {
            return Err(());
        }
        let mut sockets = Vec::new();
        let mut reset = 0_usize;
        while let Some(slot) = self.active_flow_head {
            self.flows[slot]
                .as_mut()
                .expect("TCP active-list head is live")
                .owner
                .mark_reset();
            let entry = self
                .take_tcp_flow(slot)
                .expect("TCP active-list head remains removable");
            sockets.push(entry.socket);
            reset += 1;
        }
        for socket in sockets {
            self.sockets.remove(socket);
        }
        if reset != 0 {
            for _ in 0..reset {
                self.events.emit(TunEvent::TcpFlowResetRestart);
            }
        }
        self.udp
            .invalidate_session(next_generation, udp_response_drop_reason);
        self.reassembly.clear();
        self.device.clear_session_buffers();
        self.packet_generation = next_generation;
        self.events.emit(TunEvent::TcpFlowsActive(0));
        self.events.emit(TunEvent::UdpAssociationsActive(0));
        self.events.emit(TunEvent::UdpCandidatesActive(0));
        self.events.emit(TunEvent::ReassemblyEntriesActive(0));
        Ok(reset)
    }
}
