use std::io::Read;

use super::primitives::{read_byte, read_byte_vec, read_u64_words};
use crate::srs::{SrsError, SrsErrorKind};

const DOMAIN_PREFIX_LABEL: char = '\r';
const DOMAIN_ROOT_LABEL: char = '\n';

fn normalize_domain(mut value: String) -> Result<String, SrsError> {
    if value.ends_with('.') {
        value.pop();
    }
    if value.is_empty() || value.len() > 255 || !value.is_ascii() {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    value.make_ascii_lowercase();
    Ok(value)
}

pub(super) struct DomainEntries {
    pub(super) exact: Vec<String>,
    pub(super) suffix: Vec<String>,
}

pub(super) fn read_domain_set<R: Read>(reader: &mut R) -> Result<DomainEntries, SrsError> {
    let keys = read_succinct_set(reader)?;
    let mut exact = Vec::new();
    let mut suffix = Vec::new();
    exact
        .try_reserve(keys.len())
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    suffix
        .try_reserve(keys.len())
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for key in keys {
        let reversed =
            std::str::from_utf8(&key).map_err(|_| SrsError::new(SrsErrorKind::InvalidUtf8))?;
        let mut value = String::new();
        value
            .try_reserve_exact(reversed.len())
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        value.extend(reversed.chars().rev());
        match value.chars().next() {
            Some(DOMAIN_ROOT_LABEL) => {
                value.remove(0);
                suffix.push(normalize_domain(value)?);
            }
            Some(DOMAIN_PREFIX_LABEL) => {
                value.remove(0);
                if value.starts_with('.') {
                    value.remove(0);
                }
                suffix.push(normalize_domain(value)?);
            }
            Some(_) => exact.push(normalize_domain(value)?),
            None => return Err(SrsError::new(SrsErrorKind::InvalidDomainSet)),
        }
    }
    Ok(DomainEntries { exact, suffix })
}

pub(super) fn read_succinct_set<R: Read>(reader: &mut R) -> Result<Vec<Vec<u8>>, SrsError> {
    if read_byte(reader)? != 0 {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    let leaves = read_u64_words(reader)?;
    let bitmap = read_u64_words(reader)?;
    let labels = read_byte_vec(reader)?;
    if bitmap.is_empty() {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }

    let Some((last_word, last_value)) = bitmap
        .iter()
        .copied()
        .enumerate()
        .rev()
        .find(|(_, word)| *word != 0)
    else {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    };
    if bitmap[last_word + 1..].iter().any(|word| *word != 0) {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    let last_one = last_word
        .checked_mul(64)
        .and_then(|base| base.checked_add(63 - last_value.leading_zeros() as usize))
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let ones = bitmap
        .iter()
        .try_fold(0_usize, |count, word| {
            count.checked_add(word.count_ones() as usize)
        })
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let used_bits = last_one
        .checked_add(1)
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let zeros = used_bits
        .checked_sub(ones)
        .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
    if ones != zeros.saturating_add(1) || labels.len() != zeros {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    if has_set_bit_at_or_after(&leaves, ones) {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }

    let mut selects = Vec::new();
    selects
        .try_reserve_exact(ones)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for position in 0..used_bits {
        if bit(&bitmap, position) {
            selects.push(position);
        }
    }
    if selects.len() != ones || bit(&leaves, 0) {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    let ranks = word_ranks(&bitmap)?;

    #[derive(Clone, Copy)]
    struct Frame {
        node: usize,
        bitmap: usize,
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(256)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    frames.push(Frame { node: 0, bitmap: 0 });
    let mut current = Vec::new();
    current
        .try_reserve_exact(256)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    let mut keys = Vec::new();
    keys.try_reserve_exact(ones.min(labels.len()))
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;

    while let Some(frame) = frames.last_mut() {
        if frame.bitmap > last_one {
            return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
        }
        if bit(&bitmap, frame.bitmap) {
            frames.pop();
            if !frames.is_empty() {
                current
                    .pop()
                    .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
                frames
                    .last_mut()
                    .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?
                    .bitmap += 1;
            }
            continue;
        }
        let label_index = frame
            .bitmap
            .checked_sub(frame.node)
            .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
        let label = *labels
            .get(label_index)
            .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
        current
            .try_reserve(1)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        current.push(label);
        let next_node = count_zeros(&bitmap, &ranks, frame.bitmap + 1)?;
        if next_node == 0 || next_node >= ones {
            return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
        }
        let next_bitmap = selects
            .get(next_node - 1)
            .and_then(|position| position.checked_add(1))
            .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
        if bit(&leaves, next_node) {
            let mut key = Vec::new();
            key.try_reserve_exact(current.len())
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            key.extend_from_slice(&current);
            keys.try_reserve(1)
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            keys.push(key);
        }
        frames
            .try_reserve(1)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        frames.push(Frame {
            node: next_node,
            bitmap: next_bitmap,
        });
    }
    if keys.is_empty() {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    Ok(keys)
}

fn word_ranks(words: &[u64]) -> Result<Vec<usize>, SrsError> {
    let mut ranks = Vec::<usize>::new();
    ranks
        .try_reserve_exact(words.len() + 1)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    ranks.push(0);
    for word in words {
        let next = ranks
            .last()
            .copied()
            .and_then(|rank| rank.checked_add(word.count_ones() as usize))
            .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
        ranks.push(next);
    }
    Ok(ranks)
}

fn count_zeros(words: &[u64], ranks: &[usize], position: usize) -> Result<usize, SrsError> {
    let word = position / 64;
    let offset = position % 64;
    let base = *ranks
        .get(word)
        .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
    let partial = if offset == 0 {
        0
    } else {
        words
            .get(word)
            .map(|value| (value & ((1_u64 << offset) - 1)).count_ones() as usize)
            .unwrap_or(0)
    };
    let ones = base
        .checked_add(partial)
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    position
        .checked_sub(ones)
        .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))
}

fn bit(words: &[u64], position: usize) -> bool {
    words
        .get(position / 64)
        .is_some_and(|word| word & (1_u64 << (position % 64)) != 0)
}

fn has_set_bit_at_or_after(words: &[u64], position: usize) -> bool {
    let word = position / 64;
    let offset = position % 64;
    words.get(word).is_some_and(|value| {
        let mask = if offset == 0 {
            u64::MAX
        } else {
            u64::MAX << offset
        };
        value & mask != 0
    }) || words
        .get(word + 1..)
        .is_some_and(|tail| tail.iter().any(|value| *value != 0))
}
