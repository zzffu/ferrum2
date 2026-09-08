use std::net::SocketAddr;

use super::{FlowTuple, ResetNotification, SystemTcp, TCP_RST};
use crate::packet::{ParsedIpPacket, TransportMetadata};

impl SystemTcp {
    /// Ordinary output pays only this scalar check. Normal FIN history is
    /// independent: reset completion requires the fenced socket's abort RST.
    pub(crate) fn has_reset_output(&self) -> bool {
        self.reset_outputs_pending != 0
    }

    pub(crate) fn reset_output_sent(&mut self, parsed: ParsedIpPacket) {
        let TransportMetadata::Tcp(tcp) = parsed.transport else {
            return;
        };
        if tcp.flags & TCP_RST == 0 {
            return;
        }
        let forward = FlowTuple {
            source: SocketAddr::new(parsed.destination, tcp.destination_port),
            target: SocketAddr::new(parsed.source, tcp.source_port),
        };
        let Some(slot) = self.forward.get(&forward).copied() else {
            return;
        };
        let mapping = self.slots[slot].as_mut().expect("live output tuple");
        if mapping.reset_notification == ResetNotification::AwaitingDelivery {
            mapping.reset_notification = ResetNotification::Delivered;
            self.reset_outputs_pending -= 1;
        }
    }

    #[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
    pub(crate) fn pending_close_notifications(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|mapping| {
                matches!(
                    mapping.reset_notification,
                    ResetNotification::AwaitingKernelReset | ResetNotification::AwaitingDelivery
                )
            })
            .count()
    }
}
