use super::*;

#[test]
fn live_udp_registry_accepts_zero_through_seven_collisions_and_rejects_eight() {
    let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes128([0x11; 16])));
    for collisions in 0..8 {
        let live = Mutex::new(HashSet::new());
        let (_first, first_id) =
            register_udp_session(&keys, &IdSequenceRandom::new([1]), &live).expect("first session");
        let draws = std::iter::repeat_n(1, collisions).chain([2]);
        let (_second, second_id) =
            register_udp_session(&keys, &IdSequenceRandom::new(draws), &live)
                .expect("distinct draw within eight attempts");
        assert_ne!(first_id, second_id);
        assert_eq!(live.lock().expect("live IDs").len(), 2);
    }

    let live = Mutex::new(HashSet::new());
    let _ = register_udp_session(&keys, &IdSequenceRandom::new([1]), &live).expect("first session");
    assert!(
        register_udp_session(
            &keys,
            &IdSequenceRandom::new(std::iter::repeat_n(1, 8)),
            &live,
        )
        .is_err()
    );
    assert_eq!(live.lock().expect("live IDs").len(), 1);
}

struct MissingMethodKey;

impl MethodKeyProvider for MissingMethodKey {
    type Error = ();

    fn profile(&self) -> MethodProfile {
        MethodProfile::Blake3Aes128Gcm2022
    }

    fn with_method_key<T>(
        &self,
        _selector: KeySelector<'_>,
        _use_key: impl FnOnce(MethodSecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error> {
        Err(())
    }
}

#[tokio::test]
async fn random_and_key_setup_failures_roll_back_every_prior_owner() {
    let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes128([0x11; 16])));
    assert_registration_failure_rolls_back_setup(keys, &IdSequenceRandom::new([])).await;
    assert_registration_failure_rolls_back_setup(
        MethodKeyAdapter::new(MissingMethodKey),
        &FixedRandom,
    )
    .await;
}
