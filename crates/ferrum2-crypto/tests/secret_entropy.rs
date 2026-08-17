use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_crypto::{
    AeadError, Aes128Psk, Clock, ClockError, KeyProvider, KeyProviderError, KeySelector,
    MethodKeyProvider, MethodProfile, MethodProfileMismatchError, MethodPsk, MethodPskLengthError,
    MethodSaltLengthError, MethodSinglePskProvider, MethodTcpSalt, MonotonicInstant, NonceCounter,
    PskLengthError, RandomError, SecureRandom, SinglePskProvider, SystemClock, SystemRandom,
    TcpMethod, TcpMethodProfile, TcpSalt, TcpSealer, UdpOutboundSession, UdpSessionId,
    generate_method_request_salt, generate_method_response_salt, generate_request_salt,
    generate_response_salt,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[derive(Default)]
struct RecordingHasher(Vec<u8>);

impl Hasher for RecordingHasher {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

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

fn seal_with_method_provider(provider: &MethodSinglePskProvider, salt: &MethodTcpSalt) -> BytesMut {
    let subkey = provider
        .with_method_key(KeySelector::Default, |key| key.derive_tcp_subkey(salt))
        .expect("default method key")
        .expect("matching method profile");
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
    let rendered = format!("{psk:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("visible-secret"));
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
    outcomes: Mutex<VecDeque<Result<Vec<u8>, RandomError>>>,
}

impl ScriptedRandom {
    fn new<const N: usize>(
        outcomes: impl IntoIterator<Item = Result<[u8; N], RandomError>>,
    ) -> Self {
        Self {
            outcomes: Mutex::new(
                outcomes
                    .into_iter()
                    .map(|outcome| outcome.map(Vec::from))
                    .collect(),
            ),
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
    let unavailable = ScriptedRandom::new::<16>([Err(RandomError::Unavailable)]);
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
fn method_profiles_bind_exact_width_secret_salt_and_key_capabilities() {
    let rows = [
        (
            MethodProfile::Blake3Aes128Gcm2022,
            16,
            43,
            59,
            32,
            vec![0x11; 16],
        ),
        (
            MethodProfile::Blake3Aes256Gcm2022,
            32,
            59,
            91,
            32,
            vec![0x22; 32],
        ),
        (
            MethodProfile::Blake3ChaCha20Poly13052022,
            32,
            59,
            91,
            56,
            vec![0x33; 32],
        ),
    ];
    assert_eq!(MethodProfile::ALL.len(), rows.len());
    assert_zeroize_on_drop::<MethodPsk>();
    assert_zeroize_on_drop::<MethodTcpSalt>();

    for (profile, width, request_read, response_read, udp_overhead, bytes) in rows {
        let tcp_alias: TcpMethodProfile = profile;
        assert_eq!(tcp_alias, profile);
        assert_eq!(profile.key_bytes(), width);
        assert_eq!(profile.salt_bytes(), width);
        assert_eq!(profile.tag_bytes(), 16);
        assert_eq!(profile.nonce_bytes(), 12);
        assert_eq!(profile.initial_request_read_bytes(), request_read);
        assert_eq!(profile.initial_response_read_bytes(), response_read);
        assert_eq!(profile.udp_wire_overhead_bytes(), udp_overhead);

        let psk = MethodPsk::try_from_slice(profile, &bytes).expect("method-width PSK");
        assert_eq!(psk.profile(), profile);
        assert!(format!("{psk:?}").contains("[REDACTED]"));
        assert_eq!(
            MethodPsk::try_from_slice(profile, &bytes[..width - 1]).unwrap_err(),
            MethodPskLengthError
        );
        assert_eq!(
            MethodPsk::try_from_slice(profile, &vec![0x11; width + 1]).unwrap_err(),
            MethodPskLengthError
        );
        assert!(!MethodPskLengthError.to_string().contains("11"));

        let salt = MethodTcpSalt::try_from_slice(profile, &bytes).expect("method-width salt");
        assert_eq!(salt.profile(), profile);
        assert_eq!(salt.as_bytes().len(), width);
        assert!(format!("{salt:?}").contains("[REDACTED]"));
        assert_eq!(
            MethodTcpSalt::try_from_slice(profile, &bytes[..width - 1]).unwrap_err(),
            MethodSaltLengthError
        );
        assert_eq!(
            MethodTcpSalt::try_from_slice(profile, &vec![0x11; width + 1]).unwrap_err(),
            MethodSaltLengthError
        );
        assert!(!MethodSaltLengthError.to_string().contains("11"));
        let mut cleared_salt = salt.clone();
        cleared_salt.zeroize();
        assert!(cleared_salt.as_bytes().iter().all(|byte| *byte == 0));

        let provider = MethodSinglePskProvider::new(psk);
        let subkey = provider
            .with_method_key(KeySelector::Default, |key| key.derive_tcp_subkey(&salt))
            .expect("default method key")
            .expect("matching method profile");
        assert_eq!(subkey.profile(), profile);

        let mut cleared =
            MethodPsk::try_from_slice(profile, &bytes).expect("second method-width PSK");
        cleared.clear();
        let cleared = seal_with_method_provider(&MethodSinglePskProvider::new(cleared), &salt);
        let zeroed = seal_with_method_provider(
            &MethodSinglePskProvider::new(
                MethodPsk::try_from_slice(profile, &vec![0; width]).expect("zero PSK"),
            ),
            &salt,
        );
        assert_eq!(cleared, zeroed);
    }

    for psk_profile in TcpMethodProfile::ALL {
        for salt_profile in TcpMethodProfile::ALL {
            if psk_profile == salt_profile {
                continue;
            }
            let provider = MethodSinglePskProvider::new(
                MethodPsk::try_from_slice(psk_profile, &vec![0x44; psk_profile.key_bytes()])
                    .expect("method-width PSK"),
            );
            let other_method_salt =
                MethodTcpSalt::try_from_slice(salt_profile, &vec![0x55; salt_profile.salt_bytes()])
                    .expect("method-width salt");
            assert!(matches!(
                provider
                    .with_method_key(KeySelector::Default, |key| {
                        key.derive_tcp_subkey(&other_method_salt)
                    })
                    .expect("default method key"),
                Err(MethodProfileMismatchError)
            ));
        }
    }
    let provider = MethodSinglePskProvider::new(MethodPsk::aes256([0x44; 32]));
    let identity = *b"identity-secret!";
    let error = provider
        .with_method_key(KeySelector::Identity(&identity), |_| ())
        .unwrap_err();
    assert_eq!(error, KeyProviderError::IdentityUnsupported);
    assert!(!error.to_string().contains("identity-secret"));
}

#[test]
fn udp_session_ids_retry_live_collisions_without_exposing_partial_state() {
    assert_zeroize_on_drop::<UdpSessionId>();
    assert_zeroize_on_drop::<UdpOutboundSession>();
    let provider = MethodSinglePskProvider::new(MethodPsk::aes128([0x11; 16]));
    let crypto = provider
        .with_method_key(KeySelector::Default, |key| key.udp_crypto())
        .expect("default key");

    for collisions in 0..8 {
        let random = ScriptedRandom::new((0..=collisions).map(|draw| Ok([draw as u8 + 1; 8])));
        let mut observed = 0;
        let outbound = crypto
            .generate_outbound_session(&random, |_| {
                let collides = observed < collisions;
                observed += 1;
                collides
            })
            .expect("one of the first eight draws is distinct");
        assert_eq!(observed, collisions + 1);
        assert!(format!("{outbound:?}").contains("[REDACTED]"));
        assert!(format!("{:?}", outbound.session_id()).contains("[REDACTED]"));
    }

    let random = ScriptedRandom::new((0..8).map(|_| Ok([0x41; 8])));
    assert_eq!(
        crypto
            .generate_outbound_session(&random, |_| true)
            .unwrap_err(),
        RandomError::RepeatedSessionId
    );

    let client_random = ScriptedRandom::new([Ok([0x51; 8])]);
    let client = crypto
        .generate_outbound_session(&client_random, |_| false)
        .expect("client session");
    let mut hasher = RecordingHasher::default();
    client.session_id().hash(&mut hasher);
    assert_eq!(hasher.0.len(), 8);
    assert!(!hasher.0.windows(8).any(|window| window == [0x51; 8]));
    let server_random = ScriptedRandom::new([Ok([0x51; 8]), Ok([0x52; 8])]);
    let server = crypto
        .generate_distinct_outbound_session(&server_random, client.session_id(), |_| false)
        .expect("server retries the direction collision");
    assert_ne!(client.session_id(), server.session_id());

    let unavailable = ScriptedRandom::new::<8>([Err(RandomError::Unavailable)]);
    assert_eq!(
        crypto
            .generate_outbound_session(&unavailable, |_| false)
            .unwrap_err(),
        RandomError::Unavailable
    );
}

#[test]
fn profile_salt_entropy_uses_complete_width_and_full_width_collision_checks() {
    for (profile, first, second) in [
        (
            TcpMethodProfile::Blake3Aes128Gcm2022,
            vec![0x61; 16],
            vec![0x62; 16],
        ),
        (
            TcpMethodProfile::Blake3Aes256Gcm2022,
            vec![0x71; 32],
            vec![0x72; 32],
        ),
        (
            TcpMethodProfile::Blake3ChaCha20Poly13052022,
            vec![0x81; 32],
            vec![0x82; 32],
        ),
    ] {
        let request_random = ScriptedRandom {
            outcomes: Mutex::new(VecDeque::from([Ok(first.clone())])),
        };
        let request = generate_method_request_salt(profile, &request_random).expect("request salt");
        assert_eq!(request.as_bytes(), first);

        let response_random = ScriptedRandom {
            outcomes: Mutex::new(VecDeque::from([Ok(first), Ok(second.clone())])),
        };
        let response = generate_method_response_salt(&response_random, &request)
            .expect("full-width distinct response salt");
        assert_eq!(response.as_bytes(), second);
        assert_eq!(response.profile(), profile);
    }
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
