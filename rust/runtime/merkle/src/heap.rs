// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Merkle Heap implementation.
//!
//! A **Merkle Heap** is a static, fixed-shape binary tree stored in a 1-indexed array of size `2 *
//! n`, where `n` is a fixed constant (specifically a power of two, such as the codeword length in
//! Ligero/ZK).
//!
//! # Structural Properties
//! - The tree shape and node positions are 100% static and fixed by `n`.
//! - Leaves are strictly located at heap array positions `n..2*n`.
//! - Internal nodes are strictly located at heap array positions `1..n`.
//! - The root is always at heap position `1`.
//! - For any node `i`, its left child is at `2*i`, right child is at `2*i + 1`, and parent is at
//!   `i/2`.
//!
//! # Why Domain Separation is Not Necessary
//! In a general, dynamic Merkle tree where tree depth is variable or arbitrary subtrees can be
//! verified independently, domain separation (e.g., prefixing leaf hashes with 0x00 and internal
//! hashes with 0x01) is required to prevent type-confusion / second-preimage attacks (presenting an
//! internal node as a leaf).
//!
//! In a **Merkle Heap** with a fixed constant `n`, type-confusion between internal nodes (depth `<
//! log2(n)`) and leaves (depth `== log2(n)`) is **structurally impossible**. The verifier knows the
//! fixed heap shape and strictly verifies leaf openings at array indices `n + idx`. Therefore,
//! explicit domain separation tags are unnecessary.

use sha2::{Digest as ShaDigest, Sha256};

use super::{Digest, MerkleError};

/// Calculates the height (number of levels) of a Merkle heap with `num_leaves`
/// leaves. For a power-of-two number of leaves, this is `log2(num_leaves)` + 1.
#[must_use]
pub fn merkle_heap_len(num_leaves: usize) -> usize {
    if num_leaves == 0 {
        return 0;
    }
    (num_leaves.next_power_of_two().trailing_zeros() as usize) + 1
}

/// Returns a mask indicating which nodes in the heap lie on the path
/// from the requested leaves (`leaf_indices`) to the root.
fn mark_paths_to_root(num_leaves: usize, leaf_indices: &[usize]) -> Result<Vec<bool>, MerkleError> {
    if leaf_indices.is_empty() {
        return Err(MerkleError::EmptyLeaves);
    }
    let mut is_node_on_path = vec![false; 2 * num_leaves];
    for &leaf_idx in leaf_indices {
        if leaf_idx >= num_leaves {
            return Err(MerkleError::LeafIndexOutOfBounds {
                index: leaf_idx,
                num_leaves,
            });
        }
        let heap_idx = leaf_idx + num_leaves;
        if is_node_on_path[heap_idx] {
            return Err(MerkleError::DuplicateLeafIndex { index: leaf_idx });
        }
        is_node_on_path[heap_idx] = true;
    }
    for i in (1..num_leaves).rev() {
        is_node_on_path[i] = is_node_on_path[2 * i] || is_node_on_path[2 * i + 1];
    }
    if !is_node_on_path[1] {
        return Err(MerkleError::LeafIndexNotOnPath);
    }
    Ok(is_node_on_path)
}

/// Representation of a built, immutable Merkle heap.
pub struct MerkleHeap {
    pub num_leaves: usize,
    pub layers: Vec<Digest>,
}

impl MerkleHeap {
    /// Constructs a Merkle heap from a complete slice of leaf digests.
    /// It automatically computes all internal parent digests.
    #[must_use]
    pub fn new(leaves: &[Digest]) -> Self {
        let num_leaves = leaves.len();
        assert!(num_leaves > 0, "Cannot construct an empty Merkle heap");
        let mut layers = vec![Digest::default(); 2 * num_leaves];

        // Copy leaves
        layers[num_leaves..2 * num_leaves].copy_from_slice(leaves);

        // Build parent nodes bottom-up
        for i in (1..num_leaves).rev() {
            layers[i] = hash2(&layers[2 * i], &layers[2 * i + 1]);
        }

        Self { num_leaves, layers }
    }

    /// Returns the root digest of the Merkle heap.
    #[must_use]
    pub fn root(&self) -> Digest {
        self.layers[1]
    }

    /// Generates a multi-leaf opening proof for the queried leaf positions.
    #[must_use]
    pub fn generate_proof(&self, leaf_indices: &[usize]) -> Vec<Digest> {
        let is_node_on_path = mark_paths_to_root(self.num_leaves, leaf_indices)
            .expect("Invalid leaf indices for proof generation");
        let mut proof = Vec::new();

        // Traverse internal nodes from bottom to top
        for i in (1..self.num_leaves).rev() {
            if is_node_on_path[i] {
                // If only one of the children is on the path, the other child's
                // digest must be included in the proof so the
                // verifier can compute the parent digest.
                if is_node_on_path[2 * i] && !is_node_on_path[2 * i + 1] {
                    proof.push(self.layers[2 * i + 1]);
                } else if !is_node_on_path[2 * i] && is_node_on_path[2 * i + 1] {
                    proof.push(self.layers[2 * i]);
                }
            }
        }
        proof
    }
}

/// Verifies that the opened leaf digests match the commitment root.
///
/// # Safety Note on Static Heap Shape
/// Both Prover and Verifier know the static heap size `num_leaves` from protocol geometry.
/// Because `num_leaves` is fixed, leaf node positions are strictly mapped to array indices
/// `num_leaves + idx`. This fixed heap shape prevents type-confusion / second-preimage attacks
/// without requiring dynamic domain separation tags.
pub fn verify_proof(
    num_leaves: usize,
    root: &Digest,
    proof: &[Digest],
    leaves: &[(usize, Digest)],
) -> Result<(), MerkleError> {
    let leaf_indices: Vec<usize> = leaves.iter().map(|(idx, _)| *idx).collect();
    let mut computed_nodes = vec![Digest::default(); 2 * num_leaves];
    let mut is_node_known = vec![false; 2 * num_leaves];

    let is_node_on_path = mark_paths_to_root(num_leaves, &leaf_indices)?;
    let mut proof_idx = 0;

    // 1. Populate sibling nodes from the proof path
    for i in (1..num_leaves).rev() {
        if is_node_on_path[i] {
            if is_node_on_path[2 * i] && !is_node_on_path[2 * i + 1] {
                if proof_idx >= proof.len() {
                    return Err(MerkleError::ProofLengthMismatch {
                        expected: proof_idx + 1,
                        found: proof.len(),
                    });
                }
                computed_nodes[2 * i + 1] = proof[proof_idx];
                is_node_known[2 * i + 1] = true;
                proof_idx += 1;
            } else if !is_node_on_path[2 * i] && is_node_on_path[2 * i + 1] {
                if proof_idx >= proof.len() {
                    return Err(MerkleError::ProofLengthMismatch {
                        expected: proof_idx + 1,
                        found: proof.len(),
                    });
                }
                computed_nodes[2 * i] = proof[proof_idx];
                is_node_known[2 * i] = true;
                proof_idx += 1;
            }
        }
    }

    if proof_idx != proof.len() {
        return Err(MerkleError::ProofLengthMismatch {
            expected: proof_idx,
            found: proof.len(),
        });
    }

    // 2. Populate the opened leaves
    for &(leaf_idx, leaf_digest) in leaves {
        let heap_idx = leaf_idx + num_leaves;
        computed_nodes[heap_idx] = leaf_digest;
        is_node_known[heap_idx] = true;
    }

    // 3. Reconstruct internal nodes bottom-up
    for i in (1..num_leaves).rev() {
        if is_node_known[2 * i] && is_node_known[2 * i + 1] {
            computed_nodes[i] = hash2(&computed_nodes[2 * i], &computed_nodes[2 * i + 1]);
            is_node_known[i] = true;
        }
    }

    if !is_node_known[1] {
        return Err(MerkleError::RootMismatch {
            expected: *root,
            found: Digest::default(),
        });
    }
    if root != &computed_nodes[1] {
        return Err(MerkleError::RootMismatch {
            expected: *root,
            found: computed_nodes[1],
        });
    }
    Ok(())
}

fn hash2(l: &Digest, r: &Digest) -> Digest {
    let mut sha = Sha256::new();
    sha.update(l.data);
    sha.update(r.data);
    let mut output = Digest::default();
    output.data.copy_from_slice(&sha.finalize());
    output
}
