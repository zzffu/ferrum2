use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_crypto::{
    AeadError, Aes128Psk, Clock, ClockError, KeyProvider, KeyProviderError, KeySelector,
    MonotonicInstant, NonceCounter, PskLengthError, RandomError, SecureRandom, SinglePskProvider,
    SystemClock, SystemRandom, TcpMethod, TcpSalt, TcpSealer, generate_request_salt,
    generate_response_salt,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

fn seal_with_provider(provider: &SinglePskProvider) -> BytesMut {
    let salt = TcpSalt::from_bytes([0x44; 16]);
    let subkey = provider
        .with_key(KeySelector::Default, |key| {
            key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, &salt)
        })
        .expect("default key");
    let mut buffer = BytesMut::with_capacity(20);
    buffer.extend_from_slice(b"test");
    TcpSealer::new(subkey)
        .seal_in_place(&mut buffer)
        .expect("seal");
    buffer
}

#[test]
fn secret_owners_are_redacted_explicitly_clearable_and_drop_zeroizing() {
    let sentinel = *b"visible-secret!!";
    let mut psk = Aes128Psk::from_bytes(sentinel);
    assert_eq!(format!("{psk:?}"), "Aes128Psk([REDACTED])");
    assert!(!format!("{psk:?}").contains("visible-secret"));
    assert_zeroize_on_drop::<Aes128Psk>();

    psk.clear();
    let cleared = seal_with_provider(&SinglePskProvider::new(psk));
    let all_zero = seal_with_provider(&SinglePskProvider::new(Aes128Psk::from_bytes([0; 16])));
    assert_eq!(cleared, all_zero);

    assert_eq!(
        Aes128Psk::try_from(&b"short"[..]).unwrap_err(),
        PskLengthError
    );
    assert!(!PskLengthError.to_string().contains("short"));
}

#[test]
fn single_psk_provider_rejects_identity_without_disclosing_it() {
    let provider = SinglePskProvider::new(Aes128Psk::from_bytes([7; 16]));
    let identity = *b"identity-secret!";
    let error = provider
        .with_key(KeySelector::Identity(&identity), |_| ())
        .unwrap_err();
    assert_eq!(error, KeyProviderError::IdentityUnsupported);
    assert!(!error.to_string().contains("identity-secret"));
}

struct ScriptedRandom {
    outcomes: Mutex<VecDeque<Result<[u8; 16], RandomError>>>,
}

impl ScriptedRandom {
    fn new(outcomes: impl IntoIterator<Item = Result<[u8; 16], RandomError>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
        }
    }
}

impl SecureRandom for ScriptedRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        let outcome = self
            .outcomes
            .lock()
            .expect("script mutex")
            .pop_front()
            .expect("script has an outcome")?;
        assert_eq!(destination.len(), outcome.len());
        destination.copy_from_slice(&outcome);
        Ok(())
    }
}

#[test]
fn entropy_failure_has_no_fallback_and_response_salt_retries_are_bounded() {
    let unavailable = ScriptedRandom::new([Err(RandomError::Unavailable)]);
    assert_eq!(
        generate_request_salt(&unavailable).unwrap_err(),
        RandomError::Unavailable
    );

    let request = TcpSalt::from_bytes([0x11; 16]);
    let eight_collisions = ScriptedRandom::new((0..8).map(|_| Ok([0x11; 16])));
    assert_eq!(
        generate_response_salt(&eight_collisions, &request).unwrap_err(),
        RandomError::RepeatedSalt
    );

    let seventh_then_distinct =
        ScriptedRandom::new((0..7).map(|_| Ok([0x11; 16])).chain([Ok([0x22; 16])]));
    let response =
        generate_response_salt(&seventh_then_distinct, &request).expect("eighth draw differs");
    assert_eq!(response.as_bytes(), &[0x22; 16]);
}

#[test]
fn nonce_overflow_returns_no_nonce_and_preserves_state() {
    let mut counter = NonceCounter::from_le_bytes([0xff; 12]);
    assert_eq!(counter.checked_take(), Err(AeadError::NonceExhausted));
    assert_eq!(counter.current_bytes(), [0xff; 12]);
}

#[test]
fn nonce_counter_has_explicit_clear_and_drop_zeroizing_contract() {
    assert_zeroize_on_drop::<NonceCounter>();

    let mut counter = NonceCounter::from_le_bytes([0x5a; 12]);
    counter.zeroize();
    assert_eq!(counter.current_bytes(), [0; 12]);
}

struct ScriptedClock {
    wall: u64,
    monotonic: MonotonicInstant,
}

impl Clock for ScriptedClock {
    fn unix_seconds(&self) -> Result<u64, ClockError> {
        Ok(self.wall)
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        self.monotonic
    }
}

#[test]
fn clock_seam_keeps_wall_and_monotonic_time_independent() {
    let clock = ScriptedClock {
        wall: 1_700_000_000,
        monotonic: MonotonicInstant::from_duration(Duration::from_millis(59_999)),
    };
    assert_eq!(clock.unix_seconds(), Ok(1_700_000_000));
    assert_eq!(
        clock.monotonic_now().duration_since(MonotonicInstant::ZERO),
        Some(Duration::from_millis(59_999))
    );

    let system = SystemClock::new();
    assert!(system.unix_seconds().is_ok());
    assert!(
        system
            .monotonic_now()
            .duration_since(MonotonicInstant::ZERO)
            .is_some()
    );

    let random = SystemRandom;
    let mut destination = [0_u8; 16];
    random
        .fill(&mut destination)
        .expect("OS random is available");
}
