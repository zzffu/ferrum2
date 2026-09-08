use super::*;

#[test]
fn reviewed_owner_can_split_modules_and_add_narrow_allowances() {
    let sources = vec![
        (
            PathBuf::from("reviewed/first.rs"),
            "#[allow(unsafe_code)] fn first() { unsafe {} }".to_owned(),
        ),
        (
            PathBuf::from("reviewed/nested/second.rs"),
            "#[cfg_attr(windows, allow(dead_code, unsafe_code))] fn second() { unsafe {} }"
                .to_owned(),
        ),
    ];
    assert!(validate_unsafe_sources(&sources, None, &[PathBuf::from("reviewed")]).is_ok());
}

#[test]
fn unsafe_mentions_are_not_code_or_allowances() {
    let sources = vec![(
        PathBuf::from("outside.rs"),
        r##"
        // unsafe {} #[allow(unsafe_code)]
        const EXAMPLE: &str = "#[allow(unsafe_code)] unsafe {}";
        #[doc = "#[allow(unsafe_code)] unsafe {}"]
        fn safe() {}
    "##
        .to_owned(),
    )];
    assert!(validate_unsafe_sources(&sources, None, &[]).is_ok());
}

#[test]
fn unsafe_code_and_weakening_attributes_cannot_escape_owner() {
    for source in [
        "fn bad() { unsafe {} }",
        "#![allow(unsafe_code)]",
        "#[allow(dead_code, unsafe_code)] fn safe() {}",
        "#![cfg_attr(windows, allow(dead_code, unsafe_code))]",
        "#![cfg_attr(windows, cfg_attr(feature = \"ffi\", expect(unsafe_code)))]",
        "#![warn(unsafe_code)]",
    ] {
        let sources = vec![(
            PathBuf::from("reviewed_neighbor/outside.rs"),
            source.to_owned(),
        )];
        assert!(
            validate_unsafe_sources(&sources, None, &[PathBuf::from("reviewed")]).is_err(),
            "{source}"
        );
    }
}

#[test]
fn fixture_consumers_can_move_and_extract_helpers() {
    let canonical = "tests/fixtures/dns-tls";
    let sources = BTreeMap::from([
        (
            "crates/new/tests/helper.rs".to_owned(),
            format!("const ROOT: &[u8] = include_bytes!(\"../../../{canonical}/ca.der\");"),
        ),
        (
            "tests/new_consumer.rs".to_owned(),
            format!("fn fixture(root: &Path) {{ root.join(\"{canonical}\"); }}"),
        ),
    ]);
    let forbidden = BTreeSet::from(["crates/ferrum2-dns/tests/fixtures".to_owned()]);
    assert!(validate_fixture_references(&sources, &forbidden).is_ok());
}

#[test]
fn fixture_path_mentions_do_not_count_as_references() {
    let sources = BTreeMap::from([(
        "tests/example.rs".to_owned(),
        r##"
        // include_bytes!("crates/ferrum2-dns/tests/fixtures/ca.der")
        const OLD_PATH: &str = "crates/ferrum2-dns/tests/fixtures/ca.der";
        #[doc = "crates/ferrum2-dns/tests/fixtures/ca.der"]
        fn example() {}
    "##
        .to_owned(),
    )]);
    assert!(
        validate_fixture_references(
            &sources,
            &BTreeSet::from(["crates/ferrum2-dns/tests/fixtures".to_owned()])
        )
        .is_ok()
    );
}

#[test]
fn actual_private_fixture_references_are_rejected() {
    let forbidden = BTreeSet::from(["crates/ferrum2-dns/tests/fixtures".to_owned()]);
    for source in [
        r#"const ROOT: &[u8] = include_bytes!("../tests/fixtures/ca.der");"#,
        r#"fn fixture(root: &Path) { root.join("crates/ferrum2-dns/tests/fixtures"); }"#,
        "const ROOT: &[u8] = include_bytes!(r#\"../tests/fixtures/ca.der\"#);",
    ] {
        let sources = BTreeMap::from([(
            "crates/ferrum2-dns/src/helper.rs".to_owned(),
            source.to_owned(),
        )]);
        assert!(
            validate_fixture_references(&sources, &forbidden).is_err(),
            "{source}"
        );
    }
}

#[test]
fn fixture_integrity_and_private_copies_remain_protected() {
    let root = tempfile::tempdir().expect("isolated fixture tree");
    let canonical = root.path().join("shared");
    fs::create_dir(&canonical).unwrap();
    let bytes = b"synthetic fixture";
    let hash = hex::encode(Sha256::digest(bytes));
    let fixtures = [("ca.der".to_owned(), bytes.len(), hash.clone())];
    fs::write(canonical.join("ca.der"), bytes).unwrap();
    assert!(validate_fixture_bytes(bytes, bytes.len(), &hash).is_ok());
    assert!(validate_fixture_bytes(b"synthetic fixturE", bytes.len(), &hash).is_err());
    assert!(validate_fixture_ownership(root.path(), &canonical, &fixtures).is_ok());
    fs::write(root.path().join("renamed-private-copy.bin"), bytes).unwrap();
    assert!(validate_fixture_ownership(root.path(), &canonical, &fixtures).is_err());
    fs::remove_file(root.path().join("renamed-private-copy.bin")).unwrap();
    fs::write(root.path().join("ca.der"), b"changed private credential").unwrap();
    assert!(validate_fixture_ownership(root.path(), &canonical, &fixtures).is_err());
}
