use std::fmt;

use super::{REPLAY_WORDS, UDP_REPLAY_LAG, UdpPacketError};

/// Exact sliding window representing the highest ID plus 8,128 earlier IDs.
#[derive(Clone)]
pub struct UdpReplayWindow {
    highest: Option<u64>,
    bits: [u64; REPLAY_WORDS],
}

impl UdpReplayWindow {
    /// Creates an empty replay window.
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WORDS],
        }
    }

    /// Returns the highest accepted ID, if any.
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Checks an ID without changing accepted state.
    pub fn check(&self, packet_id: u64) -> Result<(), UdpPacketError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if packet_id > highest {
            return Ok(());
        }
        let distance = highest - packet_id;
        if distance > UDP_REPLAY_LAG {
            return Err(UdpPacketError::TooOld);
        }
        let index = usize::try_from(distance).map_err(|_| UdpPacketError::TooOld)?;
        if self.bit(index) {
            Err(UdpPacketError::Duplicate)
        } else {
            Ok(())
        }
    }

    /// Atomically rechecks and marks an ID under the caller's serialized owner.
    pub fn commit(&mut self, packet_id: u64) -> Result<(), UdpPacketError> {
        self.check(packet_id)?;
        match self.highest {
            None => {
                self.highest = Some(packet_id);
                self.bits[0] = 1;
            }
            Some(highest) if packet_id > highest => {
                let advance = packet_id - highest;
                self.shift(advance);
                self.highest = Some(packet_id);
                self.bits[0] |= 1;
            }
            Some(highest) => {
                let distance =
                    usize::try_from(highest - packet_id).map_err(|_| UdpPacketError::TooOld)?;
                self.set_bit(distance);
            }
        }
        Ok(())
    }

    fn bit(&self, index: usize) -> bool {
        self.bits[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn set_bit(&mut self, index: usize) {
        self.bits[index / 64] |= 1_u64 << (index % 64);
    }

    fn shift(&mut self, advance: u64) {
        if advance > UDP_REPLAY_LAG {
            self.bits.fill(0);
            return;
        }
        let advance = usize::try_from(advance).expect("replay advance is at most 8128");
        let word_shift = advance / 64;
        let bit_shift = advance % 64;
        let old = self.bits;
        self.bits.fill(0);
        for destination in word_shift..REPLAY_WORDS {
            let source = destination - word_shift;
            self.bits[destination] |= old[source] << bit_shift;
            if bit_shift != 0 && source > 0 {
                self.bits[destination] |= old[source - 1] >> (64 - bit_shift);
            }
        }
        self.bits[REPLAY_WORDS - 1] &= 1;
    }
}

impl Default for UdpReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UdpReplayWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpReplayWindow")
            .field("highest", &"[redacted]")
            .finish_non_exhaustive()
    }
}
