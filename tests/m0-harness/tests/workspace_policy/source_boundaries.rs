use proc_macro2::{Delimiter, TokenStream, TokenTree};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

fn ident(token: Option<&TokenTree>, expected: &str) -> bool {
    matches!(token, Some(TokenTree::Ident(value)) if value == expected)
}

fn weakening_lint(tokens: TokenStream) -> bool {
    let tokens: Vec<_> = tokens.into_iter().collect();
    tokens.windows(2).any(|pair| {
        let TokenTree::Group(arguments) = &pair[1] else {
            return false;
        };
        if arguments.delimiter() != Delimiter::Parenthesis {
            return false;
        }
        if ["allow", "expect", "warn"]
            .iter()
            .any(|name| ident(pair.first(), name))
        {
            arguments
                .stream()
                .into_iter()
                .any(|token| ident(Some(&token), "unsafe_code"))
        } else if ident(pair.first(), "cfg_attr") {
            weakening_lint(arguments.stream())
        } else {
            false
        }
    })
}

fn has_unsafe_boundary_token(tokens: TokenStream) -> bool {
    let tokens: Vec<_> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        if ident(Some(token), "unsafe") {
            return true;
        }
        if let TokenTree::Group(group) = token
            && has_unsafe_boundary_token(group.stream())
        {
            return true;
        }
        if matches!(token, TokenTree::Punct(punct) if punct.as_char() == '#') {
            let mut next = index + 1;
            if matches!(tokens.get(next), Some(TokenTree::Punct(punct)) if punct.as_char() == '!') {
                next += 1;
            }
            if let Some(TokenTree::Group(attribute)) = tokens.get(next)
                && attribute.delimiter() == Delimiter::Bracket
                && weakening_lint(attribute.stream())
            {
                return true;
            }
        }
    }
    false
}

pub(super) fn validate_unsafe_sources(
    sources: &[(PathBuf, String)],
    legacy: Option<&Path>,
    allowed_paths: &[PathBuf],
) -> Result<(), String> {
    for (path, source) in sources {
        let tokens = source
            .parse::<TokenStream>()
            .map_err(|error| format!("invalid Rust source {}: {error}", path.display()))?;
        if has_unsafe_boundary_token(tokens)
            && !legacy.is_some_and(|legacy| path == legacy)
            && !allowed_paths
                .iter()
                .any(|allowed| path == allowed || path.starts_with(allowed))
        {
            return Err(format!(
                "unsafe token or weakening allowance escaped declared boundary: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn string_literal(token: &TokenTree) -> Result<Option<String>, String> {
    let TokenTree::Literal(literal) = token else {
        return Ok(None);
    };
    let text = literal.to_string();
    if text.starts_with('"') {
        return serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| format!("unsupported escaped fixture path literal: {text}"));
    }
    if let Some(raw) = text.strip_prefix('r') {
        let hashes = raw.bytes().take_while(|byte| *byte == b'#').count();
        let suffix = format!("\"{}", "#".repeat(hashes));
        if let Some(body) = raw[hashes..]
            .strip_prefix('"')
            .and_then(|body| body.strip_suffix(&suffix))
        {
            return Ok(Some(body.to_owned()));
        }
    }
    Ok(None)
}

fn path_literals(tokens: TokenStream, values: &mut Vec<String>) -> Result<(), String> {
    for token in tokens {
        if let Some(value) = string_literal(&token)? {
            values.push(value);
        } else if let TokenTree::Group(group) = token {
            path_literals(group.stream(), values)?;
        }
    }
    Ok(())
}

// Only inspect path-bearing operations, not arbitrary strings or documentation.
// This deliberately recognizes the include!/Path/join style used by the fixtures,
// not Rust dataflow through arbitrary computed strings.
fn fixture_references(tokens: TokenStream, references: &mut Vec<String>) -> Result<(), String> {
    let tokens: Vec<_> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        let TokenTree::Group(group) = token else {
            continue;
        };
        let previous = index.checked_sub(1).and_then(|index| tokens.get(index));
        let include = matches!(previous, Some(TokenTree::Punct(punct)) if punct.as_char() == '!')
            && index >= 2
            && ["include", "include_bytes", "include_str"]
                .iter()
                .any(|name| ident(tokens.get(index - 2), name));
        let constructor = ["new", "from"].iter().any(|name| ident(previous, name))
            && index >= 4
            && ["Path", "PathBuf"]
                .iter()
                .any(|name| ident(tokens.get(index - 4), name));
        let path_call = constructor
            || ["join", "push", "read", "read_to_string", "open"]
                .iter()
                .any(|name| ident(previous, name));
        if group.delimiter() == Delimiter::Parenthesis && (include || path_call) {
            let mut fragments = Vec::new();
            path_literals(group.stream(), &mut fragments)?;
            if fragments.len() > 1 {
                references.push(fragments.concat());
            }
            references.extend(fragments);
        } else {
            fixture_references(group.stream(), references)?;
        }
    }
    Ok(())
}

fn normalized(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            component => result.push(component.as_os_str()),
        }
    }
    result
}

pub(super) fn validate_fixture_references(
    sources: &BTreeMap<String, String>,
    forbidden_paths: &BTreeSet<String>,
) -> Result<(), String> {
    for (path, source) in sources {
        let tokens = source
            .parse::<TokenStream>()
            .map_err(|error| format!("invalid Rust source {path}: {error}"))?;
        let mut references = Vec::new();
        fixture_references(tokens, &mut references).map_err(|error| format!("{path}: {error}"))?;
        for reference in references {
            let reference = reference.replace('\\', "/");
            let relative = normalized(
                &Path::new(path)
                    .parent()
                    .unwrap_or(Path::new(""))
                    .join(&reference),
            );
            if forbidden_paths.iter().any(|forbidden| {
                let components: Vec<_> = reference.split('/').collect();
                let forbidden_components: Vec<_> = forbidden.split('/').collect();
                (!forbidden_components.is_empty()
                    && components
                        .windows(forbidden_components.len())
                        .any(|window| window == forbidden_components))
                    || normalized(Path::new(&reference)).starts_with(forbidden)
                    || relative.starts_with(forbidden)
            }) {
                return Err(format!(
                    "{path} references forbidden private fixture path: {reference}"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_fixture_bytes(
    bytes: &[u8],
    expected_len: usize,
    expected_hash: &str,
) -> Result<(), String> {
    if bytes.len() != expected_len || hex::encode(Sha256::digest(bytes)) != expected_hash {
        return Err("shared DNS TLS fixture bytes/hash drift".to_owned());
    }
    Ok(())
}

pub(super) fn validate_fixture_ownership(
    directory: &Path,
    canonical: &Path,
    fixtures: &[(String, usize, String)],
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        let path = entry.path();
        if path == canonical || entry.file_name() == "target" || kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            validate_fixture_ownership(&path, canonical, fixtures)?;
        } else if kind.is_file() {
            if fixtures
                .iter()
                .any(|(name, _, _)| entry.file_name() == name.as_str())
            {
                return Err(format!(
                    "private shared DNS TLS fixture name: {}",
                    path.display()
                ));
            }
            let length = entry.metadata().map_err(|error| error.to_string())?.len();
            if fixtures.iter().any(|(_, size, _)| *size as u64 == length) {
                let bytes = fs::read(&path).map_err(|error| error.to_string())?;
                let hash = hex::encode(Sha256::digest(&bytes));
                if fixtures.iter().any(|(_, _, expected)| expected == &hash) {
                    return Err(format!(
                        "private shared DNS TLS fixture copy: {}",
                        path.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

#[path = "source_boundaries_tests.rs"]
mod tests;
