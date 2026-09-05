use super::{SrsError, SrsErrorKind};

/// Closed dimensions admitted before decoder allocation or expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SrsLimitKind {
    EncodedBytes,
    DecodedBytes,
    Rules,
    Entries,
    Collection,
    DomainNodes,
    DomainDepth,
    LogicalDepth,
    ExpandedBytes,
    KeywordBytes,
    KeywordLength,
    UnsupportedStringBytes,
    Work,
}

impl SrsLimitKind {
    pub(super) const ALL: [Self; 13] = [
        Self::EncodedBytes,
        Self::DecodedBytes,
        Self::Rules,
        Self::Entries,
        Self::Collection,
        Self::DomainNodes,
        Self::DomainDepth,
        Self::LogicalDepth,
        Self::ExpandedBytes,
        Self::KeywordBytes,
        Self::KeywordLength,
        Self::UnsupportedStringBytes,
        Self::Work,
    ];

    const fn default_maximum(self) -> u64 {
        match self {
            Self::EncodedBytes | Self::ExpandedBytes => 64 * 1024 * 1024,
            Self::DecodedBytes => 128 * 1024 * 1024,
            Self::Rules => 100_000,
            Self::Entries => 1_000_000,
            Self::Collection | Self::DomainNodes => 8_000_000,
            Self::DomainDepth => 258,
            Self::LogicalDepth => 100,
            Self::KeywordBytes => 2 * 1024 * 1024,
            Self::KeywordLength => 255,
            Self::UnsupportedStringBytes => 8 * 1024,
            Self::Work => 512 * 1024 * 1024,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncodedBytes => "encoded_bytes",
            Self::DecodedBytes => "decoded_bytes",
            Self::Rules => "rules",
            Self::Entries => "entries",
            Self::Collection => "collection",
            Self::DomainNodes => "domain_nodes",
            Self::DomainDepth => "domain_depth",
            Self::LogicalDepth => "logical_depth",
            Self::ExpandedBytes => "expanded_bytes",
            Self::KeywordBytes => "keyword_bytes",
            Self::KeywordLength => "keyword_length",
            Self::UnsupportedStringBytes => "unsupported_string_bytes",
            Self::Work => "work",
        }
    }
}

/// Per-file decoder admission limits, independent of matcher or snapshot RSS.
///
/// Defaults admit 64 MiB encoded, 128 MiB decoded, 100k rule attempts, 1M entry
/// attempts, 8M collection elements and 8M succinct nodes. Expanded strings are
/// limited to 64 MiB, supported keywords to 2 MiB total/255 bytes each, and
/// unsupported strings to 8 KiB each. Domain wire depth is at most 258 bytes;
/// logical depth retains 100. Work admits 512 Mi deterministic operation units.
/// Work reserves one unit per primitive payload byte requested, declared
/// collection element, rule attempt, scanned LOUDS bit/traversal step, emitted
/// entry and expanded string byte. This is not a CPU-time or RSS measurement.
/// Collection and node allowances are cumulative and independent; auxiliary
/// collections can exhaust their allowance before the node maximum is reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SrsDecodeLimits {
    maximum: [u64; SrsLimitKind::ALL.len()],
}

impl Default for SrsDecodeLimits {
    fn default() -> Self {
        Self {
            maximum: SrsLimitKind::ALL.map(SrsLimitKind::default_maximum),
        }
    }
}

impl SrsDecodeLimits {
    /// Constructs defaults with distinct, nonzero, no-larger overrides.
    /// Invalid/duplicate overrides fail before any input is read.
    pub fn try_new(overrides: &[(SrsLimitKind, u64)]) -> Result<Self, SrsError> {
        let mut limits = Self::default();
        let mut seen = 0_u16;
        for &(kind, maximum) in overrides {
            let bit = 1_u16 << kind as usize;
            if maximum == 0 || maximum > limits.maximum(kind) || seen & bit != 0 {
                return Err(SrsError::new(SrsErrorKind::InvalidLimits));
            }
            seen |= bit;
            limits.maximum[kind as usize] = maximum;
        }
        Ok(limits)
    }

    /// Returns the admitted maximum for one closed dimension.
    pub const fn maximum(self, kind: SrsLimitKind) -> u64 {
        self.maximum[kind as usize]
    }
}
