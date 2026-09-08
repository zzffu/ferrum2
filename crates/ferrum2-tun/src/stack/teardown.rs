use super::{OutputFlushOutcome, OutputSendOutcome, Stack};
use crate::packet::{ParsedPacket, TransportMetadata};

impl Stack {
    pub(crate) fn pending_tcp_close_notifications(&self) -> usize {
        self.system_tcp.pending_close_notifications()
    }

    /// During the generation barrier only old, already-owned TCP tuples may
    /// cross the packet adapter. SystemTcp rejects all new admission and payload
    /// from the application while permitting the kernel's terminal delivery.
    pub(crate) fn enqueue_fenced_tcp(&mut self, packet: &[u8], now: i64) -> bool {
        if self.fenced_generation.is_none() || packet.len() > self.device.validator.mtu {
            return false;
        }
        let Ok(ParsedPacket::Complete(parsed)) = self.device.validator.parse_ingress(packet) else {
            return false;
        };
        if !matches!(parsed.transport, TransportMetadata::Tcp(_)) {
            return false;
        }
        self.device
            .enqueue_rewritten(packet, parsed, |packet, parsed| {
                self.system_tcp.rewrite(packet, parsed, false, now)
            })
            .unwrap_or(false)
    }

    /// Discard generation-bound UDP/control output without pretending it reached
    /// the adapter. Existing TCP output stays ordered ahead of kernel FIN/RST.
    pub(crate) fn flush_fenced_tcp(
        &mut self,
        send: impl FnOnce(&[u8]) -> OutputSendOutcome,
    ) -> OutputFlushOutcome {
        let Some(packet) = self.device.front_output() else {
            return OutputFlushOutcome::Empty;
        };
        if !matches!(self.device.validator.parse_ingress(packet),
            Ok(ParsedPacket::Complete(parsed)) if matches!(parsed.transport, TransportMetadata::Tcp(_)))
        {
            self.device.pop_output();
            return OutputFlushOutcome::Empty;
        }
        self.flush_output(send)
    }

    pub(crate) fn tcp_teardown_output_pending(&self) -> bool {
        self.device.ingress_len != 0 || self.device.has_output()
    }
}
