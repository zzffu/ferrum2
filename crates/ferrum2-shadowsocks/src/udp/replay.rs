use std::fmt;

use super::{REPLAY_WORDS, UDP_REPLAY_LAG, UdpPacketError};

/// Exact sliding window representing the highest ID plus 8,128 earlier IDs.
#[derive(Clone)]
pub struct UdpReplayWindow {
    highest: Option<u64>,
    bits: [u64; REPLAY_WORDS],
    head: usize,
    last_advance_word_clears: u16,
    #[cfg(feature = "structural-metrics")]
    last_advance_bit_clears: u16,
}

const REPLAY_PHYSICAL_BITS: usize = REPLAY_WORDS * u64::BITS as usize;
const REPLAY_PHYSICAL_MASK: usize = REPLAY_PHYSICAL_BITS - 1;

impl UdpReplayWindow {
    /// Creates an empty replay window.
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WORDS],
            head: 0,
            last_advance_word_clears: 0,
            #[cfg(feature = "structural-metrics")]
            last_advance_bit_clears: 0,
        }
    }

    /// Returns the highest accepted ID, if any.
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Returns physical bitmap words cleared by the last forward advance.
    ///
    /// This deterministic qualification seam is zero for first/out-of-order
    /// commits, one for the common sequential advance, and at most 128.
    pub const fn last_advance_word_clears(&self) -> u16 {
        self.last_advance_word_clears
    }

    #[cfg(feature = "structural-metrics")]
    pub(super) const fn last_advance_bit_clears(&self) -> u16 {
        self.last_advance_bit_clears
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
        self.last_advance_word_clears = 0;
        #[cfg(feature = "structural-metrics")]
        {
            self.last_advance_bit_clears = 0;
        }
        match self.highest {
            None => {
                self.highest = Some(packet_id);
                self.set_bit(0);
            }
            Some(highest) if packet_id > highest => {
                let advance = packet_id - highest;
                self.advance(advance);
                self.highest = Some(packet_id);
                self.set_bit(0);
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
        let physical = (self.head + index) & REPLAY_PHYSICAL_MASK;
        self.bits[physical / 64] & (1_u64 << (physical % 64)) != 0
    }

    fn set_bit(&mut self, index: usize) {
        let physical = (self.head + index) & REPLAY_PHYSICAL_MASK;
        self.bits[physical / 64] |= 1_u64 << (physical % 64);
    }

    fn advance(&mut self, advance: u64) {
        if advance > UDP_REPLAY_LAG {
            self.bits.fill(0);
            self.head = 0;
            self.last_advance_word_clears = REPLAY_WORDS as u16;
            #[cfg(feature = "structural-metrics")]
            {
                self.last_advance_bit_clears = REPLAY_PHYSICAL_BITS as u16;
            }
            return;
        }
        let advance = usize::try_from(advance).expect("replay advance is at most 8128");
        #[cfg(feature = "structural-metrics")]
        {
            self.last_advance_bit_clears = advance as u16;
        }
        self.head = self.head.wrapping_sub(advance) & REPLAY_PHYSICAL_MASK;
        let mut cleared = 0_u16;
        let mut logical = 0_usize;
        while logical < advance {
            let physical = (self.head + logical) & REPLAY_PHYSICAL_MASK;
            let bit = physical % 64;
            let count = (advance - logical).min(64 - bit);
            let mask = if count == 64 {
                u64::MAX
            } else {
                ((1_u64 << count) - 1) << bit
            };
            self.bits[physical / 64] &= !mask;
            cleared += 1;
            logical += count;
        }
        self.last_advance_word_clears = cleared;
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
