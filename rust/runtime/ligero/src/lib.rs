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

pub mod common;
pub mod geometry;
pub mod param;
pub mod prover;
pub mod tableau;
pub mod transcript;
pub mod verifier;

use std::fmt;

pub use common::{inner_product_vector, layout_aext_into};
pub use geometry::{estimate_proof_size, optimize_geometry};
pub use param::{LigeroConfig, LigeroLinearConstraint, LigeroParam, LigeroQuadraticConstraint};
pub use prover::LigeroProver;
pub use runtime_proto::{LigeroCommitment, LigeroProof};
pub use transcript::TranscriptLigero;
pub use verifier::LigeroVerifier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LigeroError {
    InvalidProof(String),
    MerkleCheckFailed(runtime_merkle::MerkleError),
    LowDegreeCheckFailed,
    DotCheckFailed,
    LinearInnerProductMismatch,
    QuadraticCheckFailed,
}

impl fmt::Display for LigeroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof(msg) => write!(f, "invalid proof: {msg}"),
            Self::MerkleCheckFailed(err) => {
                write!(f, "merkle_check failed: {err}")
            }
            Self::LowDegreeCheckFailed => write!(f, "low_degree_check failed"),
            Self::DotCheckFailed => write!(f, "dot_check failed"),
            Self::LinearInnerProductMismatch => {
                write!(f, "linear inner product mismatch")
            }
            Self::QuadraticCheckFailed => write!(f, "quadratic_check failed"),
        }
    }
}

impl std::error::Error for LigeroError {}
