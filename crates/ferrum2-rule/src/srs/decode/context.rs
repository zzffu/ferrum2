use std::io::{self, Read};

use crate::srs::{SrsDecodeLimits, SrsError, SrsErrorKind, SrsLimitKind};

/// One parser accounting owner. Reader layers own encoded/decoded byte counters;
/// this owner charges parser-visible bytes, declarations and derived expansion.
pub(super) struct DecodeContext<R> {
    pub(super) reader: R,
    pub(super) limits: SrsDecodeLimits,
    used: [u64; SrsLimitKind::ALL.len()],
}

impl<R> DecodeContext<R> {
    pub(super) fn new(reader: R, limits: SrsDecodeLimits) -> Self {
        Self {
            reader,
            limits,
            used: [0; SrsLimitKind::ALL.len()],
        }
    }

    pub(super) fn charge(&mut self, kind: SrsLimitKind, amount: u64) -> Result<(), SrsError> {
        let used = self.used[kind as usize]
            .checked_add(amount)
            .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
        if used > self.limits.maximum(kind) {
            return Err(SrsError::limit(kind));
        }
        self.used[kind as usize] = used;
        Ok(())
    }

    pub(super) fn work(&mut self, amount: u64) -> Result<(), SrsError> {
        self.charge(SrsLimitKind::Work, amount)
    }

    pub(super) fn depth(&self, kind: SrsLimitKind, depth: usize) -> Result<(), SrsError> {
        if depth as u64 > self.limits.maximum(kind) {
            return Err(SrsError::limit(kind));
        }
        Ok(())
    }

    pub(super) fn collection(&mut self, count: u64, minimum_bytes: u64) -> Result<usize, SrsError> {
        self.charge(SrsLimitKind::Collection, count)?;
        self.work(count)?;
        let minimum = count
            .checked_mul(minimum_bytes)
            .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
        self.require_payload(minimum)?;
        usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))
    }

    pub(super) fn require_payload(&self, bytes: u64) -> Result<(), SrsError> {
        if bytes
            > self.limits.maximum(SrsLimitKind::DecodedBytes)
                - self.used[SrsLimitKind::DecodedBytes as usize]
        {
            return Err(SrsError::limit(SrsLimitKind::DecodedBytes));
        }
        Ok(())
    }

    pub(super) fn rule_count(&self, count: u64) -> Result<(), SrsError> {
        if count
            > self.limits.maximum(SrsLimitKind::Rules) - self.used[SrsLimitKind::Rules as usize]
        {
            return Err(SrsError::limit(SrsLimitKind::Rules));
        }
        Ok(())
    }

    pub(super) fn entry(&mut self, expanded_bytes: usize) -> Result<(), SrsError> {
        self.charge(SrsLimitKind::Entries, 1)?;
        self.charge(SrsLimitKind::ExpandedBytes, expanded_bytes as u64)?;
        self.work(1 + expanded_bytes as u64)
    }
}

#[derive(Debug)]
pub(super) struct ByteLimit(pub(super) SrsLimitKind);

impl std::fmt::Display for ByteLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

impl std::error::Error for ByteLimit {}

/// A cap below buffering; reaching the cap permits only one independent EOF
/// probe. Excess is a typed limit error, never ordinary EOF or compression error.
pub(super) struct BoundedReader<R> {
    reader: R,
    remaining: u64,
    kind: SrsLimitKind,
    excess: bool,
    eof: bool,
}

impl<R> BoundedReader<R> {
    pub(super) fn new(reader: R, limits: SrsDecodeLimits, kind: SrsLimitKind) -> Self {
        Self {
            reader,
            remaining: limits.maximum(kind),
            kind,
            excess: false,
            eof: false,
        }
    }

    pub(super) fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.excess {
            return Err(io::Error::other(ByteLimit(self.kind)));
        }
        if self.eof {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0];
            if self.reader.read(&mut probe)? == 0 {
                self.eof = true;
                return Ok(0);
            }
            self.excess = true;
            return Err(io::Error::other(ByteLimit(self.kind)));
        }
        let count = buffer
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.reader.read(&mut buffer[..count])?;
        self.remaining -= read as u64;
        self.eof = read == 0;
        Ok(read)
    }
}
