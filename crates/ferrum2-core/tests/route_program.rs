use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr};

#[test]
fn canonical_domain_is_a_bounded_redacted_policy_key() {
    let canonical = CanonicalDomain::new("ExAmPlE.Test.").expect("canonical domain");
    assert_eq!(canonical.as_str(), "example.test");
    assert!(format!("{canonical:?}").contains("[redacted]"));
    assert!(!format!("{canonical:?}").contains("example.test"));
    assert!(CanonicalDomain::new(&format!("{}.", "a".repeat(255))).is_err());
}

#[test]
fn target_and_domain_share_the_same_canonical_storage_contract() {
    let domain = DomainName::new("EXAMPLE.TEST.").expect("domain");
    let target = TargetAddr::domain("EXAMPLE.TEST.", 443).expect("target");
    assert_eq!(
        domain.canonical().map(CanonicalDomain::as_str),
        target.canonical_domain().map(CanonicalDomain::as_str)
    );
}
