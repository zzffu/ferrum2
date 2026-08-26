mod aead;
mod session;

pub use aead::{UdpCrypto, UdpCryptoError, UdpOpenResult, UdpSealResult};
pub use session::{UdpOutboundSession, UdpSessionId};

pub(super) const UDP_SESSION_ID_BYTES: usize = 8;
pub(super) const UDP_PACKET_ID_BYTES: usize = 8;
pub(super) const UDP_IDENTITY_BYTES: usize = UDP_SESSION_ID_BYTES + UDP_PACKET_ID_BYTES;
pub(super) const XCHACHA_NONCE_BYTES: usize = 24;
