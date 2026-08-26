use std::error::Error;
use std::fmt;

use zeroize::Zeroizing;

use crate::method::{MethodProfile, MethodTcpSalt, WIDE_KEY_BYTES};

const RESPONSE_SALT_ATTEMPTS: usize = 8;

/// A narrow secure-random capability shared by production and test adapters.
pub trait SecureRandom: Send + Sync {
    /// Fills the complete destination or fails without a weak fallback.
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError>;
}

/// The production OS CSPRNG adapter.
pub struct SystemRandom;

impl SecureRandom for SystemRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(destination).map_err(|_| RandomError::Unavailable)
    }
}

/// Generates a request salt with the exact width of the selected profile.
pub fn generate_method_request_salt(
    profile: MethodProfile,
    random: &(impl SecureRandom + ?Sized),
) -> Result<MethodTcpSalt, RandomError> {
    let mut bytes = Zeroizing::new([0_u8; WIDE_KEY_BYTES]);
    random.fill(&mut bytes[..profile.salt_bytes()])?;
    MethodTcpSalt::try_from_slice(profile, &bytes[..profile.salt_bytes()])
        .map_err(|_| RandomError::Unavailable)
}

/// Generates a profile-bound response salt distinct from its request salt.
///
/// Eight consecutive full-width collisions fail closed.
pub fn generate_method_response_salt(
    random: &(impl SecureRandom + ?Sized),
    request: &MethodTcpSalt,
) -> Result<MethodTcpSalt, RandomError> {
    for _ in 0..RESPONSE_SALT_ATTEMPTS {
        let candidate = generate_method_request_salt(request.profile(), random)?;
        if candidate != *request {
            return Ok(candidate);
        }
    }
    Err(RandomError::RepeatedSalt)
}

/// A closed secure-random failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomError {
    /// The OS or injected secure-random capability failed.
    Unavailable,
    /// Eight response-salt draws collided with the request salt.
    RepeatedSalt,
    /// Eight UDP session-ID draws collided with live state.
    RepeatedSessionId,
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "secure random unavailable",
            Self::RepeatedSalt => "secure random repeated request salt",
            Self::RepeatedSessionId => "secure random repeated live session ID",
        };
        formatter.write_str(message)
    }
}

impl Error for RandomError {}
