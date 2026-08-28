use crate::RuleCompileError;

const DOMAIN_SUFFIX_TRIE_THRESHOLD: usize = 64;
const CIDR_RADIX_THRESHOLD: usize = 64;

pub(crate) const fn use_suffix_trie(entries: usize) -> bool {
    cfg!(feature = "candidate-domain-suffix-trie") && entries > DOMAIN_SUFFIX_TRIE_THRESHOLD
}

pub(crate) const fn use_cidr_radix(entries: usize) -> bool {
    cfg!(feature = "candidate-cidr-radix") && entries > CIDR_RADIX_THRESHOLD
}

pub(crate) struct SuffixTrie<V> {
    nodes: Box<[SuffixNode<V>]>,
}

struct SuffixNode<V> {
    edges: Box<[(u8, u32)]>,
    value: Option<V>,
}

struct SuffixBuildNode<V> {
    edges: Vec<(u8, usize)>,
    value: Option<V>,
}

impl<V> SuffixTrie<V> {
    pub(crate) fn try_build<I, S>(entries: I) -> Result<Self, RuleCompileError>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
    {
        let mut nodes = Vec::new();
        nodes
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        nodes.push(SuffixBuildNode {
            edges: Vec::new(),
            value: None,
        });

        for (domain, value) in entries {
            let mut node = 0;
            for byte in domain.as_ref().bytes().rev() {
                let existing = nodes[node]
                    .edges
                    .iter()
                    .find_map(|(edge, child)| (*edge == byte).then_some(*child));
                node = if let Some(child) = existing {
                    child
                } else {
                    let child = nodes.len();
                    nodes
                        .try_reserve(1)
                        .map_err(|_| RuleCompileError::Allocation)?;
                    nodes.push(SuffixBuildNode {
                        edges: Vec::new(),
                        value: None,
                    });
                    nodes[node]
                        .edges
                        .try_reserve(1)
                        .map_err(|_| RuleCompileError::Allocation)?;
                    nodes[node].edges.push((byte, child));
                    child
                };
            }
            if nodes[node].value.replace(value).is_some() {
                return Err(RuleCompileError::Internal);
            }
        }

        let mut compact = Vec::new();
        compact
            .try_reserve_exact(nodes.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for mut node in nodes {
            node.edges.sort_unstable_by_key(|(edge, _)| *edge);
            let mut edges = Vec::new();
            edges
                .try_reserve_exact(node.edges.len())
                .map_err(|_| RuleCompileError::Allocation)?;
            for (edge, child) in node.edges {
                edges.push((
                    edge,
                    u32::try_from(child).map_err(|_| RuleCompileError::IndexOverflow)?,
                ));
            }
            compact.push(SuffixNode {
                edges: edges.into_boxed_slice(),
                value: node.value,
            });
        }
        Ok(Self {
            nodes: compact.into_boxed_slice(),
        })
    }

    pub(crate) fn visit(&self, domain: &str, mut visit: impl FnMut(&V)) {
        let bytes = domain.as_bytes();
        let mut node = 0_usize;
        let mut consumed = 0_usize;
        for &byte in bytes.iter().rev() {
            let Ok(edge) = self.nodes[node]
                .edges
                .binary_search_by_key(&byte, |(edge, _)| *edge)
            else {
                break;
            };
            node = self.nodes[node].edges[edge].1 as usize;
            consumed += 1;
            let label_boundary =
                consumed == bytes.len() || bytes[bytes.len() - consumed - 1] == b'.';
            if label_boundary && let Some(value) = self.nodes[node].value.as_ref() {
                visit(value);
            }
        }
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        let mut matched = false;
        self.visit(domain, |_| matched = true);
        matched
    }
}

pub(crate) struct RadixTrie<V, const BITS: u8> {
    nodes: Box<[RadixNode<V>]>,
}

struct RadixNode<V> {
    children: [Option<u32>; 2],
    value: Option<V>,
}

struct RadixBuildNode<V> {
    children: [Option<usize>; 2],
    value: Option<V>,
}

impl<V, const BITS: u8> RadixTrie<V, BITS> {
    pub(crate) fn try_build(
        entries: impl IntoIterator<Item = (u8, u128, V)>,
    ) -> Result<Self, RuleCompileError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        nodes.push(RadixBuildNode {
            children: [None, None],
            value: None,
        });

        for (prefix, network, value) in entries {
            if prefix > BITS {
                return Err(RuleCompileError::Internal);
            }
            let mut node = 0_usize;
            for depth in 0..prefix {
                let bit = ((network >> u32::from(BITS - depth - 1)) & 1) as usize;
                node = if let Some(child) = nodes[node].children[bit] {
                    child
                } else {
                    let child = nodes.len();
                    nodes
                        .try_reserve(1)
                        .map_err(|_| RuleCompileError::Allocation)?;
                    nodes.push(RadixBuildNode {
                        children: [None, None],
                        value: None,
                    });
                    nodes[node].children[bit] = Some(child);
                    child
                };
            }
            if nodes[node].value.replace(value).is_some() {
                return Err(RuleCompileError::Internal);
            }
        }

        let mut compact = Vec::new();
        compact
            .try_reserve_exact(nodes.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for node in nodes {
            compact.push(RadixNode {
                children: [
                    node.children[0]
                        .map(u32::try_from)
                        .transpose()
                        .map_err(|_| RuleCompileError::IndexOverflow)?,
                    node.children[1]
                        .map(u32::try_from)
                        .transpose()
                        .map_err(|_| RuleCompileError::IndexOverflow)?,
                ],
                value: node.value,
            });
        }
        Ok(Self {
            nodes: compact.into_boxed_slice(),
        })
    }

    pub(crate) fn visit(&self, address: u128, mut visit: impl FnMut(&V)) {
        let mut node = 0_usize;
        if let Some(value) = self.nodes[node].value.as_ref() {
            visit(value);
        }
        for depth in 0..BITS {
            let bit = ((address >> u32::from(BITS - depth - 1)) & 1) as usize;
            let Some(child) = self.nodes[node].children[bit] else {
                break;
            };
            node = child as usize;
            if let Some(value) = self.nodes[node].value.as_ref() {
                visit(value);
            }
        }
    }

    pub(crate) fn matches(&self, address: u128) -> bool {
        let mut matched = false;
        self.visit(address, |_| matched = true);
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_index_boundaries_are_feature_gated() {
        assert!(!use_suffix_trie(64));
        assert_eq!(
            use_suffix_trie(65),
            cfg!(feature = "candidate-domain-suffix-trie")
        );
        assert!(!use_cidr_radix(64));
        assert_eq!(use_cidr_radix(65), cfg!(feature = "candidate-cidr-radix"));
    }
}
