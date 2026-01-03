//! Merkle tree implementation for FryChain

use crate::types::Hash256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A Merkle tree for transaction and state proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTree {
    /// All nodes in the tree (bottom-up, level by level)
    nodes: Vec<Hash256>,
    /// Number of leaves
    leaf_count: usize,
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaf hashes
    pub fn from_hashes(leaves: Vec<Hash256>) -> Self {
        if leaves.is_empty() {
            return Self {
                nodes: vec![Hash256::zero()],
                leaf_count: 0,
            };
        }

        let leaf_count = leaves.len();
        // Ensure power of 2 by padding with zeros
        let padded_size = leaf_count.next_power_of_two();
        let mut current_level: Vec<Hash256> = leaves;

        // Pad to power of 2
        while current_level.len() < padded_size {
            current_level.push(Hash256::zero());
        }

        let mut all_nodes = current_level.clone();

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);

            for chunk in current_level.chunks(2) {
                let hash = hash_pair(&chunk[0], &chunk[1]);
                next_level.push(hash);
            }

            all_nodes.extend(next_level.clone());
            current_level = next_level;
        }

        Self {
            nodes: all_nodes,
            leaf_count,
        }
    }

    /// Create from raw data (will hash each item)
    pub fn from_data<T: AsRef<[u8]>>(items: &[T]) -> Self {
        let hashes: Vec<Hash256> = items
            .iter()
            .map(|item| {
                let mut hasher = Sha3_256::new();
                hasher.update(item.as_ref());
                let hash = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&hash);
                Hash256(bytes)
            })
            .collect();

        Self::from_hashes(hashes)
    }

    /// Get the Merkle root
    pub fn root(&self) -> Hash256 {
        if self.nodes.is_empty() {
            Hash256::zero()
        } else {
            self.nodes[self.nodes.len() - 1]
        }
    }

    /// Get a proof for a leaf at the given index
    pub fn get_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaf_count {
            return None;
        }

        let padded_size = self.leaf_count.next_power_of_two();
        let mut proof_hashes = Vec::new();
        let mut current_index = index;
        let mut level_start = 0;
        let mut level_size = padded_size;

        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if level_start + sibling_index < self.nodes.len() {
                proof_hashes.push(self.nodes[level_start + sibling_index]);
            } else {
                proof_hashes.push(Hash256::zero());
            }

            level_start += level_size;
            level_size /= 2;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.nodes[index],
            proof_hashes,
            root: self.root(),
        })
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get a leaf hash by index
    pub fn get_leaf(&self, index: usize) -> Option<Hash256> {
        if index < self.leaf_count {
            Some(self.nodes[index])
        } else {
            None
        }
    }
}

/// A Merkle proof for a single leaf
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf being proven
    pub leaf_index: usize,
    /// Hash of the leaf
    pub leaf_hash: Hash256,
    /// Sibling hashes from leaf to root
    pub proof_hashes: Vec<Hash256>,
    /// The expected root
    pub root: Hash256,
}

impl MerkleProof {
    /// Verify this proof
    pub fn verify(&self) -> bool {
        let mut current_hash = self.leaf_hash;
        let mut current_index = self.leaf_index;

        for sibling in &self.proof_hashes {
            current_hash = if current_index % 2 == 0 {
                hash_pair(&current_hash, sibling)
            } else {
                hash_pair(sibling, &current_hash)
            };
            current_index /= 2;
        }

        current_hash == self.root
    }

    /// Verify this proof against a specific leaf hash
    pub fn verify_leaf(&self, leaf_hash: &Hash256) -> bool {
        if *leaf_hash != self.leaf_hash {
            return false;
        }
        self.verify()
    }
}

/// Hash two nodes together
fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256(bytes)
}

/// Sparse Merkle tree for account state (256-bit keys)
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    /// Non-zero leaves (key -> value)
    leaves: std::collections::HashMap<Hash256, Hash256>,
    /// Cached intermediate nodes
    cache: std::collections::HashMap<(Hash256, u16), Hash256>,
    /// Tree depth (256 for full address space, stored as u16)
    depth: u16,
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree
    pub fn new() -> Self {
        Self {
            leaves: std::collections::HashMap::new(),
            cache: std::collections::HashMap::new(),
            depth: 256,
        }
    }

    /// Insert or update a leaf
    pub fn insert(&mut self, key: Hash256, value: Hash256) {
        self.leaves.insert(key, value);
        // Invalidate cache along the path
        self.invalidate_path(&key);
    }

    /// Get a leaf value
    pub fn get(&self, key: &Hash256) -> Hash256 {
        self.leaves.get(key).cloned().unwrap_or_default()
    }

    /// Delete a leaf
    pub fn delete(&mut self, key: &Hash256) {
        self.leaves.remove(key);
        self.invalidate_path(key);
    }

    /// Calculate the root hash
    pub fn root(&self) -> Hash256 {
        if self.leaves.is_empty() {
            return Hash256::zero();
        }

        // Simplified root calculation
        let mut hasher = Sha3_256::new();
        let mut keys: Vec<_> = self.leaves.keys().collect();
        keys.sort_by_key(|k| k.as_bytes());

        for key in keys {
            if let Some(value) = self.leaves.get(key) {
                hasher.update(key.as_bytes());
                hasher.update(value.as_bytes());
            }
        }

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Invalidate cached nodes along a path
    fn invalidate_path(&mut self, key: &Hash256) {
        // Clear all cache entries for this key's path
        for depth in 0..self.depth {
            self.cache.remove(&(*key, depth));
        }
    }

    /// Get the number of non-zero leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![Hash256::from_hex(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap()];
        let tree = MerkleTree::from_hashes(leaves.clone());

        assert_eq!(tree.leaf_count(), 1);
        // Root should be hash of (leaf, zero) due to padding
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let leaves = vec![
            Hash256::new([1u8; 32]),
            Hash256::new([2u8; 32]),
        ];
        let tree = MerkleTree::from_hashes(leaves);

        assert_eq!(tree.leaf_count(), 2);
        assert!(!tree.root().is_zero());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![
            Hash256::new([1u8; 32]),
            Hash256::new([2u8; 32]),
            Hash256::new([3u8; 32]),
            Hash256::new([4u8; 32]),
        ];
        let tree = MerkleTree::from_hashes(leaves.clone());

        for i in 0..4 {
            let proof = tree.get_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} should be valid", i);
            assert!(proof.verify_leaf(&leaves[i]));
        }
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let leaves = vec![
            Hash256::new([1u8; 32]),
            Hash256::new([2u8; 32]),
        ];
        let tree = MerkleTree::from_hashes(leaves);

        let mut proof = tree.get_proof(0).unwrap();
        proof.leaf_hash = Hash256::new([99u8; 32]); // Tamper with leaf

        assert!(!proof.verify());
    }

    #[test]
    fn test_sparse_merkle_tree() {
        let mut smt = SparseMerkleTree::new();

        let key1 = Hash256::new([1u8; 32]);
        let value1 = Hash256::new([10u8; 32]);

        smt.insert(key1, value1);
        assert_eq!(smt.get(&key1), value1);
        assert!(!smt.root().is_zero());

        smt.delete(&key1);
        assert_eq!(smt.get(&key1), Hash256::zero());
    }
}
