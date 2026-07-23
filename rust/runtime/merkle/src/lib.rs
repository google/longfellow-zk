pub mod commitment;
pub mod heap;

use std::fmt;

pub use commitment::{commit, open, verify, MerkleCommitment};
pub use heap::{merkle_heap_len, verify_proof, MerkleHeap};
pub use runtime_proto::{Digest, MerkleNonce, MerkleProof};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    InvalidNonceLength { expected: usize, found: usize },
    DuplicateLeafIndex { index: usize },
    LeafIndexOutOfBounds { index: usize, num_leaves: usize },
    ProofLengthMismatch { expected: usize, found: usize },
    RootMismatch { expected: Digest, found: Digest },
    EmptyLeaves,
    LeafIndexNotOnPath,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNonceLength { expected, found } => write!(
                f,
                "invalid nonce length in proof: expected {expected}, found {found}"
            ),
            Self::DuplicateLeafIndex { index } => {
                write!(f, "duplicate leaf index requested: {index}")
            }
            Self::LeafIndexOutOfBounds { index, num_leaves } => write!(
                f,
                "leaf index {index} out of bounds (tree has {num_leaves} leaves)"
            ),
            Self::ProofLengthMismatch { expected, found } => write!(
                f,
                "proof length mismatch: expected {expected}, found {found}"
            ),
            Self::RootMismatch { expected, found } => write!(
                f,
                "root mismatch: expected root {:?}, computed root {:?}",
                expected.data, found.data
            ),
            Self::EmptyLeaves => {
                write!(f, "empty leaves requested for verification")
            }
            Self::LeafIndexNotOnPath => {
                write!(f, "leaf index is not on the path to the root")
            }
        }
    }
}

impl std::error::Error for MerkleError {}
