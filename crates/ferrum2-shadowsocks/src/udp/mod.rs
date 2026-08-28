mod client;
mod replay;
mod server;
mod wire;

pub use client::{
    BorrowedPendingUdpResponse, ClientAssociationSnapshot, PendingUdpResponse, UdpClientSession,
    UdpResponseCommit,
};
pub use replay::UdpReplayWindow;
pub use server::{
    AcceptedUdpRequest, EncodedUdpResponse, PendingUdpRequest, ServerResponseCapability,
    ServerSessionSnapshot, UdpRequestCommit, UdpServer,
};
pub use wire::{max_udp_payload_len, max_udp_payload_len_for_encoded_target};

use std::fmt;
use std::time::Duration;

use bytes::BytesMut;
use thiserror::Error;

/// Hard maximum for one complete Shadowsocks UDP wire datagram.
pub const MAX_UDP_WIRE_LEN: usize = 65_507;
/// Number of packet IDs represented behind the highest accepted ID.
pub const UDP_REPLAY_LAG: u64 = 8_128;
/// Minimum valid lifetime of a replay/session association.
pub const UDP_ASSOCIATION_RETENTION: Duration = Duration::from_secs(60);

const TIMESTAMP_LEN: usize = 8;
const SESSION_ID_LEN: usize = 8;
const PADDING_LEN: usize = 2;
const COMMON_HEADER_LEN: usize = 1 + TIMESTAMP_LEN + PADDING_LEN;
const RESPONSE_BINDING_LEN: usize = SESSION_ID_LEN;
const REPLAY_WORDS: usize = 128;

/// Fixed caller-reusable storage for the legacy borrowed-wire open path.
pub struct UdpPacketScratch {
    pub(super) body: BytesMut,
}

impl UdpPacketScratch {
    /// Allocates the one fixed hard-bounded borrowed-open scratch.
    pub fn new() -> Self {
        Self {
            body: BytesMut::with_capacity(MAX_UDP_WIRE_LEN),
        }
    }

    /// Returns the fixed usable bound.
    pub const fn usable_limit(&self) -> usize {
        MAX_UDP_WIRE_LEN
    }

    /// Returns an opaque allocation identity for reuse evidence.
    pub fn storage_identity(&self) -> usize {
        self.body.as_ptr() as usize
    }
}

impl Default for UdpPacketScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UdpPacketScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpPacketScratch")
            .field("usable_limit", &MAX_UDP_WIRE_LEN)
            .finish()
    }
}

/// Closed packet, replay, association, or generation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UdpPacketError {
    /// A complete wire, output, padding, or payload bound was violated.
    #[error("UDP bounds rejected")]
    Bounds,
    /// Cryptographic authentication failed.
    #[error("UDP authentication rejected")]
    Authentication,
    /// The authenticated message type was wrong for the direction.
    #[error("UDP type rejected")]
    Type,
    /// Wall time was unavailable.
    #[error("UDP clock unavailable")]
    Clock,
    /// The authenticated timestamp was outside the inclusive 30-second window.
    #[error("UDP timestamp rejected")]
    Timestamp,
    /// The authenticated address was malformed.
    #[error("UDP address rejected")]
    Address,
    /// The authenticated padding encoding was malformed.
    #[error("UDP padding rejected")]
    Padding,
    /// A server response did not bind the requesting client session.
    #[error("UDP response binding rejected")]
    Binding,
    /// The packet ID was already accepted.
    #[error("UDP duplicate rejected")]
    Duplicate,
    /// The packet ID fell behind the represented replay window.
    #[error("UDP packet too old")]
    TooOld,
    /// Current and old client associations are both still retained.
    #[error("UDP association limit reached")]
    AssociationLimit,
    /// A response capability no longer names the same live generation.
    #[error("UDP generation rejected")]
    Generation,
    /// The configured method-bound key could not be selected.
    #[error("UDP key unavailable")]
    Key,
    /// Secure randomness was unavailable.
    #[error("UDP random unavailable")]
    Random,
    /// Every outbound packet ID was consumed.
    #[error("UDP packet counter exhausted")]
    Counter,
    /// Accepted state could not be safely serialized.
    #[error("UDP state unavailable")]
    StateUnavailable,
}
