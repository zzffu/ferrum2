use std::collections::{BTreeMap, BTreeSet};

// This is deliberately a command grammar, not a shell interpreter. Callers must
// validate any assignment, pipeline, or control-flow envelope separately.
pub(super) fn words(source: &str) -> Option<Vec<String>> {
    let chars: Vec<_> = source.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        // Actions expressions are substituted before shell quoting is evaluated.
        if chars[index..].starts_with(&['$', '{', '{']) {
            let end = chars[index + 3..]
                .windows(2)
                .position(|pair| pair == ['}', '}'])?
                + index
                + 3;
            word.extend(chars[index..end + 2].iter());
            started = true;
            index = end + 2;
            continue;
        }
        if quote != Some('\'') && matches!(c, '\\' | '`') {
            if chars.get(index + 1) == Some(&'\n') {
                index += 2;
                continue;
            }
            if chars.get(index + 1..index + 3) == Some(&['\r', '\n'][..]) {
                index += 3;
                continue;
            }
            // Escaping is shell-dependent; only continuations are supported.
            return None;
        }
        if let Some(delimiter) = quote {
            if c == delimiter {
                quote = None;
            } else {
                if c == '$' && delimiter == '\'' {
                    word.push('\0'); // literal dollars are not variable expansion
                } else if c == '$' && chars.get(index + 1) == Some(&'(') {
                    return None;
                }
                word.push(c);
            }
            started = true;
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if c == '#' && !started {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        } else if c.is_ascii_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
            if c == '\n'
                && !words.is_empty()
                && chars[index..].iter().any(|c| !c.is_ascii_whitespace())
            {
                // A newline must not introduce a second command.
                return None;
            }
        } else if matches!(
            c,
            ';' | '|' | '&' | '<' | '>' | '(' | ')' | '*' | '?' | '[' | ']'
        ) {
            return None;
        } else {
            word.push(c);
            started = true;
        }
        index += 1;
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

#[derive(Debug, PartialEq, Eq)]
struct Command {
    identity: Vec<String>,
    options: BTreeMap<String, BTreeSet<String>>,
    positionals: Vec<String>,
}

fn arguments(
    tokens: &[String],
    identity: Vec<String>,
    valued: &[&str],
    switches: &[&str],
    repeated: &[&str],
    cargo: bool,
) -> Option<Command> {
    let mut command = Command {
        identity,
        options: BTreeMap::new(),
        positionals: Vec::new(),
    };
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if !token.starts_with('-') {
            command.positionals.push(token.clone());
            index += 1;
            continue;
        }
        let powershell = token.starts_with("-Package") || token.starts_with("-TargetName");
        let (raw_key, inline) = if powershell {
            if token.contains('=') {
                return None;
            }
            token.split_once(':')
        } else {
            token.split_once('=')
        }
        .map_or((token.as_str(), None), |(key, value)| (key, Some(value)));
        if !cargo
            && raw_key.starts_with('-')
            && !raw_key.starts_with("--")
            && !powershell
            && inline.is_none()
        {
            // libFuzzer does not accept the GNU '--option value' convention.
            return None;
        }
        let key = if cargo {
            match raw_key {
                "-p" => "--package",
                "-F" => "--features",
                other => other,
            }
        } else {
            raw_key
        };
        let value = if switches.contains(&key) {
            if inline.is_some() {
                return None;
            }
            String::new()
        } else if valued.contains(&key) {
            let value = match inline {
                Some(value) => value,
                None => {
                    index += 1;
                    tokens.get(index)?.as_str()
                }
            };
            if value.is_empty() || value.starts_with('-') {
                return None;
            }
            value.to_owned()
        } else {
            return None;
        };
        if command.options.contains_key(key) && !repeated.contains(&key) {
            return None;
        }
        let values = command.options.entry(key.to_owned()).or_default();
        if cargo && key == "--features" {
            for feature in value.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
                if feature.is_empty() || !values.insert(feature.to_owned()) {
                    return None;
                }
            }
        } else if !values.insert(value) {
            return None;
        }
        index += 1;
    }
    Some(command)
}

fn parse(source: &str) -> Option<Command> {
    let tokens = words(source)?;
    let executable = tokens.first()?.as_str();
    match executable {
        "cargo" => {
            let mut index = 1;
            if tokens.get(index).is_some_and(|word| word.starts_with('+')) {
                index += 1;
            }
            match tokens.get(index)?.as_str() {
                "test" => index += 1,
                "fuzz" if tokens.get(index + 1).map(String::as_str) == Some("build") => index += 2,
                "fuzz" if tokens.get(index + 1).map(String::as_str) == Some("--version") => {
                    index += 1
                }
                _ => return None,
            }
            arguments(
                &tokens[index..],
                tokens[..index].to_vec(),
                &[
                    "--package",
                    "--features",
                    "--exclude",
                    "--target",
                    "--message-format",
                    "--manifest-path",
                ],
                &[
                    "--lib",
                    "--no-default-features",
                    "--all-features",
                    "--locked",
                    "--no-run",
                    "--workspace",
                    "--all",
                    "--version",
                ],
                &["--exclude", "--features"],
                true,
            )
        }
        "python3" => {
            // Interpreter flags are not module arguments. In particular, moving
            // -B after -m would silently change what Python executes.
            let module = tokens.iter().position(|token| token == "-m")?;
            let mut flags = BTreeSet::new();
            for flag in &tokens[1..module] {
                if flag != "-B" || !flags.insert(flag.clone()) {
                    return None;
                }
            }
            let mut identity = vec![executable.to_owned()];
            identity.extend(flags);
            identity.push("-m".to_owned());
            identity.push(tokens.get(module + 1)?.clone());
            arguments(
                &tokens[module + 2..],
                identity,
                &[
                    "--policy",
                    "--repository",
                    "--event-name",
                    "--base-sha",
                    "--head-sha",
                    "--github-output",
                    "--github-summary",
                    "--mode",
                    "--decision",
                    "--dependency",
                ],
                &[],
                &["--dependency"],
                false,
            )
        }
        "Resolve-HostedTestExecutable" => arguments(
            &tokens[1..],
            vec![executable.to_owned()],
            &["-Package", "-TargetName"],
            &[],
            &[],
            false,
        ),
        "timeout" => {
            // timeout options end at the duration; the executable and corpus
            // remain ordered positionals, and only libFuzzer flags may follow.
            let mut index = 1;
            while tokens.get(index).is_some_and(|word| word.starts_with('-')) {
                let token = &tokens[index];
                index += if token.contains('=') { 1 } else { 2 };
            }
            let mut wrapper = arguments(
                tokens.get(1..index)?,
                vec![executable.to_owned()],
                &["--signal", "--kill-after"],
                &[],
                &[],
                false,
            )?;
            wrapper.positionals = tokens.get(index..index + 3)?.to_vec();
            let fuzz = arguments(
                &tokens[index + 3..],
                Vec::new(),
                &[
                    "-artifact_prefix",
                    "-max_total_time",
                    "-timeout",
                    "-rss_limit_mb",
                    "-print_final_stats",
                ],
                &[],
                &[],
                false,
            )?;
            if !fuzz.positionals.is_empty() {
                return None;
            }
            wrapper.options.extend(fuzz.options);
            Some(wrapper)
        }
        _ => None,
    }
}

pub(super) fn commands_equivalent(actual: &str, expected: &str) -> bool {
    match (parse(actual), parse(expected)) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::commands_equivalent;

    #[test]
    fn paired_options_preserve_execution_contract() {
        let expected =
            "cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked";
        for actual in [
            "cargo test --locked --features=fuzzing --package ferrum2-tun --no-default-features --lib",
            "cargo test --lib --package=ferrum2-tun -F fuzzing --locked --no-default-features # reviewed",
            "cargo test \\\n --package ferrum2-tun --lib --locked --features fuzzing --no-default-features",
        ] {
            assert!(commands_equivalent(actual, expected), "{actual}");
        }
        for extra in [
            " --no-run",
            " --features live-backend",
            " --locked",
            " || true",
            "; exit 0",
            "\ncargo test",
        ] {
            assert!(!commands_equivalent(
                &format!("{expected}{extra}"),
                expected
            ));
        }
        assert!(!commands_equivalent(
            &expected.replace("-p ferrum2-tun", ""),
            expected
        ));
        assert!(!commands_equivalent(
            &expected
                .replace("--features fuzzing", "--features ferrum2-tun")
                .replace("-p ferrum2-tun", "-p fuzzing"),
            expected
        ));
    }

    #[test]
    fn quoting_and_interpreter_boundaries_are_significant() {
        let expected = "python3 -B -m tools.ci.required_gate --mode ordinary --decision \"$RUN_EXPENSIVE\" --dependency \"quality=$QUALITY_RESULT\"";
        assert!(commands_equivalent(
            "python3 -B -m tools.ci.required_gate --dependency=\"quality=$QUALITY_RESULT\" --decision=\"$RUN_EXPENSIVE\" --mode=ordinary",
            expected
        ));
        assert!(!commands_equivalent(
            &expected.replace("\"$RUN_EXPENSIVE\"", "'$RUN_EXPENSIVE'"),
            expected
        ));
        assert!(!commands_equivalent(
            &expected
                .replace("-B -m", "-m")
                .replace("--mode", "-B --mode"),
            expected
        ));
        assert!(!commands_equivalent(
            &format!("{expected} --dependency \"quality=$QUALITY_RESULT\""),
            expected
        ));
        assert!(!commands_equivalent(
            &expected.replace("$RUN_EXPENSIVE", "$(echo true)"),
            expected
        ));
    }

    #[test]
    fn wrapper_positionals_and_native_flag_syntax_remain_significant() {
        let expected = "timeout --signal=TERM --kill-after=30s \"$SECONDS\" \"$BINARY\" \"$CORPUS\" -timeout=15 -max_total_time=\"$BUDGET\"";
        assert!(commands_equivalent(
            "timeout --kill-after 30s --signal TERM \"$SECONDS\" \"$BINARY\" \"$CORPUS\" -max_total_time=\"$BUDGET\" -timeout=15",
            expected
        ));
        assert!(!commands_equivalent(
            &expected.replace("-timeout=15", "-timeout 15"),
            expected
        ));
        assert!(!commands_equivalent(
            &expected.replace("\"$BINARY\" \"$CORPUS\"", "\"$CORPUS\" \"$BINARY\""),
            expected
        ));
        assert!(!commands_equivalent(
            &expected.replace("$BUDGET", "0"),
            expected
        ));
        let resolver =
            "Resolve-HostedTestExecutable -Package 'ferrum2-tun' -TargetName 'ferrum2_tun'";
        assert!(commands_equivalent(
            "Resolve-HostedTestExecutable -TargetName:ferrum2_tun -Package:ferrum2-tun",
            resolver
        ));
        assert!(!commands_equivalent(
            &resolver.replace("-Package ", "-Package="),
            resolver
        ));
        let target = "cargo +1.97.1 test -p $Package --target '${{ matrix.target }}'";
        assert!(commands_equivalent(
            "cargo +1.97.1 test --target=\"${{ matrix.target }}\" --package \"$Package\"",
            target
        ));
        assert!(!commands_equivalent(
            &target.replace("$Package", "'$Package'"),
            target
        ));
    }
}
