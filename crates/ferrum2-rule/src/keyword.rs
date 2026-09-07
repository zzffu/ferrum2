use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};

use crate::RuleCompileError;

/// Both composite and candidate indexes use the same admitted non-DFA builder.
/// Pinned aho-corasick 1.1.4 copies suffix outputs into failure states: up to
/// 255 outputs per ordinary trie state for unique patterns of at most 255 bytes.
/// This bounds input/representation dimensions, not exact allocation or RSS.
pub(crate) fn compile_keywords<'a>(
    patterns: impl Iterator<Item = &'a str> + Clone,
) -> Result<Option<AhoCorasick>, RuleCompileError> {
    let mut bytes = 0_usize;
    for pattern in patterns.clone() {
        if pattern.len() > 255 {
            return Err(RuleCompileError::ResourceLimit);
        }
        bytes = bytes
            .checked_add(pattern.len())
            .ok_or(RuleCompileError::ResourceLimit)?;
        if bytes > 2 * 1024 * 1024 {
            return Err(RuleCompileError::ResourceLimit);
        }
    }
    if bytes == 0 {
        return Ok(None);
    }
    AhoCorasickBuilder::new()
        .kind(Some(AhoCorasickKind::NoncontiguousNFA))
        .build(patterns)
        .map(Some)
        .map_err(|_| RuleCompileError::Internal)
}
