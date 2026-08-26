use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wall and monotonic time required by the SIP022 protocol path.
pub trait Clock {
    /// Returns Unix wall-clock seconds or a closed failure.
    fn unix_seconds(&self) -> Result<u64, ClockError>;

    /// Returns monotonic time in this clock's epoch.
    fn monotonic_now(&self) -> MonotonicInstant;
}

/// An opaque monotonic instant comparable only within one clock epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    /// The start of a synthetic or system clock epoch.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Creates an instant for deterministic clock adapters.
    pub const fn from_duration(since_epoch: Duration) -> Self {
        Self(since_epoch)
    }

    /// Returns elapsed monotonic time, or `None` for reversed instants.
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }
}

/// The production wall/monotonic clock adapter.
pub struct SystemClock {
    monotonic_origin: Instant,
}

impl SystemClock {
    /// Starts a new monotonic epoch.
    pub fn new() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn unix_seconds(&self) -> Result<u64, ClockError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| ClockError::Unavailable)
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant(self.monotonic_origin.elapsed())
    }
}

/// A closed wall-clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// Wall time could not be represented as Unix seconds.
    Unavailable,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("clock unavailable")
    }
}

impl Error for ClockError {}
