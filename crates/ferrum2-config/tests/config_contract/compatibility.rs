use super::support::*;

#[test]
fn production_config_and_public_docs_cannot_reintroduce_removed_compatibility() {
    fn contains_removed_compatibility(source: &str) -> bool {
        fn contains_bounded(
            compact: &str,
            needle: &str,
            valid_suffix: impl Fn(char) -> bool,
        ) -> bool {
            compact.match_indices(needle).any(|(index, _)| {
                compact[index + needle.len()..]
                    .chars()
                    .next()
                    .is_none_or(&valid_suffix)
            })
        }

        let compact = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        contains_bounded(&compact, "schema_version==1", |suffix| {
            !suffix.is_ascii_digit()
        }) || contains_bounded(&compact, "schema_version=1", |suffix| {
            !suffix.is_ascii_digit()
        }) || contains_bounded(&compact, "SchemaVersion::V1", |suffix| {
            !(suffix.is_ascii_alphanumeric() || suffix == '_')
        }) || compact.contains("target={")
            || source.contains("RawRouteTarget")
            || source.contains("LegacyTarget")
            || source.contains("RawTarget")
    }

    fn scan(
        path: &Path,
        extensions: &[&str],
        scanned_files: &mut usize,
        violations: &mut Vec<String>,
    ) {
        if path.is_dir() {
            if path.file_name().and_then(|value| value.to_str()) == Some("tests") {
                return;
            }
            for entry in fs::read_dir(path).expect("read anti-regression directory") {
                let path = entry.expect("read anti-regression entry").path();
                scan(&path, extensions, scanned_files, violations);
            }
            return;
        }
        if !extensions
            .iter()
            .any(|extension| path.extension().and_then(|value| value.to_str()) == Some(extension))
        {
            return;
        }
        let normalized = path.to_string_lossy().replace('\\', "/").to_lowercase();
        if normalized.contains("migration") {
            return;
        }
        *scanned_files += 1;
        let source = fs::read_to_string(path).expect("read anti-regression source");
        let violations_before_file = violations.len();
        for (index, line) in source.lines().enumerate() {
            if contains_removed_compatibility(line) {
                violations.push(format!("{}:{}", path.display(), index + 1));
            }
        }
        if violations.len() == violations_before_file && contains_removed_compatibility(&source) {
            violations.push(path.display().to_string());
        }
    }

    fn scan_package_sources(
        parent: &Path,
        scanned_files: &mut usize,
        violations: &mut Vec<String>,
    ) {
        for entry in fs::read_dir(parent).expect("read workspace package directory") {
            let source = entry
                .expect("read workspace package entry")
                .path()
                .join("src");
            if source.is_dir() {
                scan(&source, &["rs"], scanned_files, violations);
            }
        }
    }

    for needle in [
        "if raw.schema_version\n ==\n 1 { unreachable!() }",
        "schema_version \n= \n1",
        "SchemaVersion ::\n V1",
    ] {
        assert!(
            contains_removed_compatibility(needle),
            "anti-regression scanner missed synthetic needle: {needle}"
        );
    }
    for allowed in ["schema_version = 10", "SchemaVersion::V10"] {
        assert!(
            !contains_removed_compatibility(allowed),
            "anti-regression scanner rejected a non-v1 version: {allowed}"
        );
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repository = manifest.join("../..");
    let mut scanned_files = 0;
    let mut violations = Vec::new();
    scan_package_sources(
        &repository.join("bins"),
        &mut scanned_files,
        &mut violations,
    );
    scan_package_sources(
        &repository.join("crates"),
        &mut scanned_files,
        &mut violations,
    );
    assert!(
        scanned_files > 0,
        "anti-regression scan visited no production source files"
    );
    scan(
        &repository.join("docs"),
        &["md", "toml"],
        &mut scanned_files,
        &mut violations,
    );
    assert!(
        violations.is_empty(),
        "removed compatibility branch reappeared in production config or public docs: {violations:?}"
    );
}

#[test]
fn removed_tun_udp_memory_field_is_limited_to_negative_and_migration_material() {
    fn scan(path: &Path, removed: &str, violations: &mut Vec<String>) {
        if path.is_dir() {
            let name = path.file_name().and_then(|value| value.to_str());
            if matches!(
                name,
                Some(".git" | "target" | "profiles" | "vendor" | "__pycache__")
            ) {
                return;
            }
            for entry in fs::read_dir(path).expect("read removed-field scan directory") {
                scan(
                    &entry.expect("read removed-field scan entry").path(),
                    removed,
                    violations,
                );
            }
            return;
        }
        let extension = path.extension().and_then(|value| value.to_str());
        if !matches!(
            extension,
            Some("json" | "md" | "ps1" | "py" | "rs" | "toml" | "yaml" | "yml")
        ) {
            return;
        }
        let source = fs::read_to_string(path).expect("read removed-field scan source");
        let occurrences = source.matches(removed).count();
        if occurrences == 0 {
            return;
        }
        let normalized = path.to_string_lossy().replace('\\', "/").to_lowercase();
        if normalized.ends_with("/crates/ferrum2-config/tests/config_contract/tun.rs")
            || normalized.ends_with("/tests/m0-harness/tests/config_cli.rs")
            || normalized.ends_with("/crates/ferrum2-tun/fuzz/src/config_legacy.rs")
            || normalized.ends_with("/crates/ferrum2-tun/fuzz/corpus/provenance.toml")
        {
            if occurrences != 1 {
                violations.push(format!(
                    "{}: expected one negative-contract occurrence, found {occurrences}",
                    path.display()
                ));
            }
            return;
        }
        let migration_document = extension == Some("md")
            && (normalized.contains("migration")
                || normalized.ends_with("/ferrum2-singbox-network-model-refactor-plan.md")
                || normalized.ends_with("/ferrum2-tun-complete-implementation-plan.md"));
        if !migration_document {
            violations.push(format!("{}: {occurrences}", path.display()));
        }
    }

    let removed = ["max_udp", "_buffered_bytes"].concat();
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut violations = Vec::new();
    scan(&repository, &removed, &mut violations);
    assert!(
        violations.is_empty(),
        "removed TUN UDP memory field reappeared outside negative contracts or migration docs: \
         {violations:?}"
    );
}
