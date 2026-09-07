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
        if self.bit(Self::index(packet_id)) {
            Err(UdpPacketError::Duplicate)
        } else {
            Ok(())
        }
    }

    /// Atomically rechecks and marks an ID under the caller's serialized owner.
    pub fn commit(&mut self, packet_id: u64) -> Result<(), UdpPacketError> {
        self.check(packet_id)?;
        match self.highest {
            None => self.highest = Some(packet_id),
            Some(highest) if packet_id > highest => {
                self.shift(highest, packet_id - highest);
                self.highest = Some(packet_id);
            }
            Some(_) => {}
        }
        self.set_bit(Self::index(packet_id));
        Ok(())
    }

    fn index(packet_id: u64) -> usize {
        (packet_id % (UDP_REPLAY_LAG + 1)) as usize
    }

    fn bit(&self, index: usize) -> bool {
        self.bits[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn set_bit(&mut self, index: usize) {
        self.bits[index / 64] |= 1_u64 << (index % 64);
    }

    fn shift(&mut self, highest: u64, advance: u64) {
        if advance > UDP_REPLAY_LAG {
            self.bits.fill(0);
            return;
        }
        // The new highest ID is marked by commit. Only skipped IDs need their
        // recycled positions cleared; sequential traffic does not move the bitmap.
        let mut remaining = advance as usize - 1;
        let mut index = Self::index(highest + 1);
        let positions = UDP_REPLAY_LAG as usize + 1;
        while remaining != 0 {
            let offset = index % 64;
            let count = remaining.min(64 - offset).min(positions - index);
            let mask = (u64::MAX >> (64 - count)) << offset;
            self.bits[index / 64] &= !mask;
            remaining -= count;
            index += count;
            if index == positions {
                index = 0;
            }
        }
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
