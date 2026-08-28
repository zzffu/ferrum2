#![forbid(unsafe_code)]

mod clock;
mod method;
mod random;
mod tcp;
mod udp;

pub use clock::{Clock, ClockError, MonotonicInstant, SystemClock};
pub use method::{
    KeyProviderError, KeySelector, MethodKeyProvider, MethodProfile, MethodProfileMismatchError,
    MethodPsk, MethodPskLengthError, MethodSaltLengthError, MethodSecretKeyRef,
    MethodSinglePskProvider, MethodTcpSalt,
};
pub use random::{
    RandomError, SecureRandom, SystemRandom, generate_method_request_salt,
    generate_method_response_salt,
};
pub use tcp::{AeadError, NonceCounter, TcpOpener, TcpSealer, TcpSubkey};
pub use udp::{
    UdpCrypto, UdpCryptoError, UdpOpenResult, UdpOutboundSession, UdpSealReservation,
    UdpSealResult, UdpSessionId,
};
