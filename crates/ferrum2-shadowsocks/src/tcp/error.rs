use ferrum2_core::{AbortiveClose, ConnectErrorKind};
use ferrum2_crypto::AeadError;
use thiserror::Error;

use super::observe::FlowObserver;

/// A closed deterministic codec failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FrameError {
    /// The configured key could not be selected.
    #[error("key unavailable")]
    KeyUnavailable,
    /// The cryptographic operation failed without exposing its source.
    #[error("cipher operation failed")]
    Cipher,
    /// The nonce owner has no unused nonce.
    #[error("nonce exhausted")]
    NonceExhausted,
    /// A length cannot be represented by the SIP022 frame.
    #[error("frame bounds invalid")]
    Bounds,
    /// The target address type or encoding is unsupported.
    #[error("target address unsupported")]
    AddressUnsupported,
    /// Padding exceeds the fixed implementation bound.
    #[error("padding bounds invalid")]
    PaddingBounds,
    /// A request supplied neither padding nor initial payload.
    #[error("request content is empty")]
    EmptyRequest,
    /// A first response payload must be nonempty.
    #[error("response payload is empty")]
    EmptyResponse,
    /// Response and request salt must differ.
    #[error("response salt repeats request salt")]
    ResponseSaltReuse,
}

/// Closed reason for an initial-envelope detection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionReason {
    /// An initial fixed read completed short.
    ShortRead,
    /// An initial contiguous write completed short.
    ShortWrite,
    /// An authenticated chunk failed verification.
    Authentication,
    /// The authenticated message type was invalid for this direction.
    InvalidType,
    /// The authenticated timestamp exceeded the inclusive 30-second window.
    TimestampSkew,
    /// Authenticated frame lengths were invalid.
    FrameBounds,
    /// The authenticated address encoding was invalid or unsupported.
    AddressBounds,
    /// Authenticated padding was malformed or exceeded 900 bytes.
    PaddingBounds,
    /// A request had neither padding nor initial payload.
    EmptyRequest,
    /// A response did not bind the complete request salt.
    ResponseBinding,
    /// The configured key was unavailable.
    KeyUnavailable,
    /// Wall time was unavailable.
    ClockUnavailable,
    /// Secure randomness was unavailable or repeatedly collided.
    RandomUnavailable,
    /// The exact incoming TCP salt was already live.
    Replay,
    /// All replay slots were occupied by live entries.
    ReplayCapacity,
    /// Exact replay state could not be safely mutated.
    ReplayUnavailable,
    /// The underlying initial read failed.
    ReadFailed,
    /// The underlying initial write failed.
    WriteFailed,
}

/// Closed reason for a post-first-envelope protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolReason {
    /// A subsequent authenticated chunk failed verification.
    Authentication,
    /// A subsequent frame was truncated or outside its bounds.
    FrameBounds,
    /// A cipher owner had no unused nonce.
    NonceExhausted,
}

/// Closed phase for a post-first-envelope transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPhase {
    /// A read operation failed.
    Read,
    /// A write operation failed.
    Write,
    /// A nonempty pending write completed with zero bytes.
    WriteZero,
    /// A flush operation failed.
    Flush,
    /// A shutdown operation failed.
    Shutdown,
}

/// Immutable terminal state for an opaque duplex flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowTerminal {
    /// Both logical directions closed normally.
    Normal,
    /// An initial-envelope failure installed an abortive terminal.
    Detection(DetectionReason),
    /// A subsequent wire failure terminated both directions.
    Protocol(ProtocolReason),
    /// A subsequent transport failure terminated both directions.
    Transport(TransportPhase),
}

/// Closed public error surface. No variant retains an underlying source.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShadowsocksError {
    /// A configured-server connector failed before any protocol write.
    #[error("connection failed")]
    Connect(ConnectErrorKind),
    /// An initial envelope failed closed.
    #[error("SIP022 detection failure")]
    Detection(DetectionReason),
    /// A subsequent protocol operation failed closed.
    #[error("SIP022 protocol failure")]
    Protocol(ProtocolReason),
    /// A subsequent transport operation failed closed.
    #[error("SIP022 transport failure")]
    Transport(TransportPhase),
}

pub(super) fn terminate_detection<S: AbortiveClose>(
    io: &mut S,
    observer: &dyn FlowObserver,
    reason: DetectionReason,
) -> ShadowsocksError {
    observer.terminal_installed(FlowTerminal::Detection(reason));
    let _ = io.mark_abortive();
    ShadowsocksError::Detection(reason)
}

pub(super) fn detection_from_aead(error: AeadError) -> DetectionReason {
    match error {
        AeadError::NonceExhausted => DetectionReason::FrameBounds,
        AeadError::AuthenticationFailed | AeadError::OperationFailed => {
            DetectionReason::Authentication
        }
    }
}

pub(super) fn frame_from_seal_aead(error: AeadError) -> FrameError {
    match error {
        AeadError::NonceExhausted => FrameError::NonceExhausted,
        AeadError::AuthenticationFailed | AeadError::OperationFailed => FrameError::Cipher,
    }
}

pub(super) fn frame_from_open_aead(error: AeadError) -> FrameError {
    match error {
        AeadError::NonceExhausted => FrameError::NonceExhausted,
        AeadError::AuthenticationFailed | AeadError::OperationFailed => FrameError::Cipher,
    }
}

pub(super) fn detection_from_frame(error: FrameError) -> DetectionReason {
    match error {
        FrameError::KeyUnavailable => DetectionReason::KeyUnavailable,
        FrameError::Cipher => DetectionReason::Authentication,
        FrameError::NonceExhausted | FrameError::Bounds | FrameError::EmptyResponse => {
            DetectionReason::FrameBounds
        }
        FrameError::AddressUnsupported => DetectionReason::AddressBounds,
        FrameError::PaddingBounds => DetectionReason::PaddingBounds,
        FrameError::EmptyRequest => DetectionReason::EmptyRequest,
        FrameError::ResponseSaltReuse => DetectionReason::ResponseBinding,
    }
}

pub(super) fn protocol_from_frame(error: FrameError) -> ProtocolReason {
    match error {
        FrameError::NonceExhausted => ProtocolReason::NonceExhausted,
        FrameError::Cipher => ProtocolReason::Authentication,
        FrameError::KeyUnavailable
        | FrameError::Bounds
        | FrameError::AddressUnsupported
        | FrameError::PaddingBounds
        | FrameError::EmptyRequest
        | FrameError::EmptyResponse
        | FrameError::ResponseSaltReuse => ProtocolReason::FrameBounds,
    }
}

#[cfg(test)]
pub(super) struct OneShotCipherFault {
    armed: bool,
    calls: usize,
}

#[cfg(test)]
impl Default for OneShotCipherFault {
    fn default() -> Self {
        Self {
            armed: true,
            calls: 0,
        }
    }
}

#[cfg(test)]
impl OneShotCipherFault {
    pub(super) fn seal(&mut self) -> Result<(), AeadError> {
        self.fail()
    }

    pub(super) fn open(&mut self) -> Result<(), AeadError> {
        self.fail()
    }

    fn fail(&mut self) -> Result<(), AeadError> {
        self.calls += 1;
        if std::mem::take(&mut self.armed) {
            Err(AeadError::NonceExhausted)
        } else {
            Ok(())
        }
    }

    pub(super) const fn calls(&self) -> usize {
        self.calls
    }
}
