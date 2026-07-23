use runtime_proto::{MerkleNonce, MerkleProof};
use runtime_random::RandomEngine;
use sha2::{Digest as ShaDigest, Sha256};

use super::{
    heap::{verify_proof, MerkleHeap},
    Digest, MerkleError,
};

/// Pure data structure representing the full Merkle commitment state.
/// It holds:
/// - `num_leaves`: The total number of leaves (columns) committed to.
/// - `mh`: The fully built `MerkleHeap` containing leaf and internal node digests.
/// - `nonce`: The generated `MerkleNonce` salts for all columns/leaves.
pub struct MerkleCommitment {
    pub num_leaves: usize,
    pub mh: MerkleHeap,
    pub nonce: Vec<MerkleNonce>,
}

/// Commits to a set of `num_leaves` leaves/columns.
///
/// For each leaf:
/// 1. Generates a random `MerkleNonce` using the random engine `rng`.
/// 2. Salts the leaf hash by feeding the nonce first into a SHA256 hasher.
/// 3. Computes the leaf data hash by passing the hasher to the closure `update_leaf_hash`.
/// 4. Inserts the computed leaf digest into the `MerkleHeap`.
///
/// Returns the constructed `MerkleCommitment` and the root `Digest`.
pub fn commit<F, R>(
    num_leaves: usize,
    rng: &mut R,
    mut update_leaf_hash: F,
) -> (MerkleCommitment, Digest)
where
    F: FnMut(usize, &mut Sha256),
    R: RandomEngine,
{
    let mut nonce = Vec::with_capacity(num_leaves);
    let mut leaves = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let nonce_bytes = rng.bytes(32);
        let n = MerkleNonce {
            bytes: nonce_bytes.try_into().unwrap(),
        };

        let mut sha = Sha256::new();
        sha.update(n.bytes);
        update_leaf_hash(i, &mut sha);

        let mut dig = Digest::default();
        dig.data.copy_from_slice(&sha.finalize());

        leaves.push(dig);
        nonce.push(n);
    }

    let mh = MerkleHeap::new(&leaves);
    let root = mh.root();
    (
        MerkleCommitment {
            num_leaves,
            mh,
            nonce,
        },
        root,
    )
}

/// Opens the commitment at the queried leaf positions `opened_indices`.
///
/// # Safety Note
/// `open` is called by the Prover during Fiat-Shamir proof generation using transcript-derived
/// query indices. An assertion checks that all queried leaf indices fall strictly within
/// `0..commitment.num_leaves`.
///
/// Returns a `MerkleProof` containing:
/// - The nonces at the queried positions.
/// - The sibling digests path needed to reconstruct the path to the root.
#[must_use]
pub fn open(commitment: &MerkleCommitment, opened_indices: &[usize]) -> MerkleProof {
    let np = opened_indices.len();
    let mut nonce = Vec::with_capacity(np);
    for &idx in opened_indices {
        assert!(
            idx < commitment.num_leaves,
            "leaf index {} out of bounds (num_leaves = {})",
            idx,
            commitment.num_leaves
        );
        nonce.push(commitment.nonce[idx]);
    }
    let path = commitment.mh.generate_proof(opened_indices);
    MerkleProof { nonce, path }
}

/// Verifies that the opened column data (hashed via `update_leaf_hash`) matches
/// the commitment root at the queried leaf positions `opened_indices`.
///
/// 1. Reconstructs each leaf digest by hashing the provided nonce (from the proof) along with the
///    leaf data (supplied by the caller via `update_leaf_hash`). The callback receives both the
///    local query index (`0..num_queries`) and the global leaf index (`opened_indices[r]`).
/// 2. Performs Merkle path verification using `verify_proof`.
pub fn verify<F>(
    num_leaves: usize,
    root: &Digest,
    opened_indices: &[usize],
    proof: &MerkleProof,
    mut update_leaf_hash: F,
) -> Result<(), MerkleError>
where
    F: FnMut(usize, usize, &mut Sha256),
{
    let num_queries = opened_indices.len();
    if proof.nonce.len() != num_queries {
        return Err(MerkleError::InvalidNonceLength {
            expected: num_queries,
            found: proof.nonce.len(),
        });
    }
    let mut leaves = vec![Digest::default(); num_queries];
    for r in 0..num_queries {
        let mut sha = Sha256::new();
        sha.update(proof.nonce[r].bytes);
        update_leaf_hash(r, opened_indices[r], &mut sha);
        leaves[r].data.copy_from_slice(&sha.finalize());
    }

    let leaves_pairs: Vec<(usize, Digest)> = opened_indices.iter().copied().zip(leaves).collect();

    verify_proof(num_leaves, root, &proof.path, &leaves_pairs)
}
