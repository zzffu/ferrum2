use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

// Process-local constructor identities are never reset, wrapped, or reused.
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) struct CryptoOwnerId(NonZeroU64);

impl CryptoOwnerId {
    pub(super) fn allocate() -> Result<Self, crate::UdpCryptoError> {
        allocate(&NEXT_OWNER).map(Self)
    }
}

fn allocate(sequence: &AtomicU64) -> Result<NonZeroU64, crate::UdpCryptoError> {
    sequence
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(crate::UdpCryptoError::OwnerExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_identity_sequence_never_reuses_an_identity() {
        let sequence = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            allocate(&sequence).expect("last identity").get(),
            u64::MAX - 1
        );
        assert_eq!(
            allocate(&sequence),
            Err(crate::UdpCryptoError::OwnerExhausted)
        );
        assert_eq!(
            allocate(&sequence),
            Err(crate::UdpCryptoError::OwnerExhausted)
        );
    }
}
