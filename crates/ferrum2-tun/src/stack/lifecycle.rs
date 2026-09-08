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
        self.system_tcp.fence(next_generation)?;
        self.fenced_generation = Some(next_generation);
        self.udp.fence_session(next_generation);
        Ok(())
    }

    #[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
    /// Final shutdown/full rebuild may also close the last representable generation.
    pub(crate) fn quiesce(&mut self, next_generation: u64, reason: UdpResponseDropReason) -> usize {
        if self.fenced_generation.is_none() && self.fence_generation(next_generation).is_err() {
            let terminal_generation = self.session_generation.wrapping_add(1);
            let _ = self.system_tcp.fence(terminal_generation);
            self.fenced_generation = Some(terminal_generation);
            self.udp.fence_session(terminal_generation);
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
        let reset = self.system_tcp.retire(next_generation);
        for _ in 0..reset {
            self.events.emit(TunEvent::TcpFlowResetRestart);
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
