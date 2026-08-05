use std::fmt;

/// Closed, low-cardinality DNS terminal reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// The aggregate query admission limit is full.
    Busy,
    /// The one absolute query deadline elapsed.
    Timeout,
    /// The selected upstream transport failed.
    Transport,
    /// Hickory rejected the selected upstream response or configuration.
    Protocol,
    /// The selected upstream authoritatively reported that the name does not exist.
    NxDomain,
    /// The selected upstream reported that the name exists without the requested type.
    NoData,
    /// The resolver owner is shutting down.
    Shutdown,
    /// The requested selected-server identity is outside the validated graph.
    InvalidServer,
    /// The exclusive runtime could not start or did not drain completely.
    Runtime,
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "DNS admission is full",
            Self::Timeout => "DNS deadline elapsed",
            Self::Transport => "DNS transport failed",
            Self::Protocol => "DNS protocol failed",
            Self::NxDomain => "DNS name does not exist",
            Self::NoData => "DNS record type does not exist",
            Self::Shutdown => "DNS runtime is shutting down",
            Self::InvalidServer => "DNS server selection is invalid",
            Self::Runtime => "DNS runtime failed",
        })
    }
}

impl std::error::Error for DnsError {}
