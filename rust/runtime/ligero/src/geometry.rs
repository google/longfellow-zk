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

use runtime_algebra::{field::RuntimeField, interpolator::InterpolatorFactory};
use runtime_proto::{DIGEST_LEN, NONCE_LEN};

use crate::param::{LigeroConfig, LigeroParam};

/// Computes total digests inside the Merkle path.
/// Given a binary tree with h levels (0 to h-1):
/// 1. Level 0: root (no siblings)
/// 2. Level 1: 2 nodes
/// 3. ...
/// 4. Level L: 2^L nodes
///
/// If we query `nreq` nodes at the bottom level, we trace their paths up the tree.
/// At each level `level`, we have a certain number of queried nodes. We only need
/// to output the siblings of those nodes if the siblings themselves are NOT queried.
///
/// An upper bound on the number of sibling digests we need at `level` is `nreq` (since
/// each queried node has at most 1 sibling).
/// Another upper bound is the number of unqueried nodes at `level`, which is `2^level - nreq`.
/// So at `level`, we need at most `min(nreq, 2^level - nreq)` sibling digests.
///
/// We sum this bound over all levels from 1 to h-1.
/// At each level `level` of width `level_width = 2^level`, we must reveal
/// siblings of queried nodes. We query `nreq` nodes. The number of revealed siblings
/// is at most `level_width - nreq` digests.
fn merkle_path_length_digests(h: usize, nreq: usize) -> usize {
    let mut total_digests = 0;
    // Level 0 is the root (no sibling). We iterate over levels 1 to h-1.
    for level in 1..h {
        let level_width = 1_usize.checked_shl(level as u32).unwrap_or(usize::MAX);
        let unqueried = level_width.saturating_sub(nreq);
        total_digests += std::cmp::min(nreq, unqueried);
    }
    total_digests
}

/// Estimates the size of the Ligero commitment proof for the given parameters.
pub fn estimate_proof_size<const W: usize, F: RuntimeField<W>, IF: InterpolatorFactory<W, F>>(
    nw: usize,
    nq: usize,
    config: LigeroConfig,
    k_bytes: usize,
    k_subfield_bytes: usize,
    make_interpolator: &IF,
) -> Option<usize> {
    let param = LigeroParam::try_new::<W, F, _>(nw, nq, config, make_interpolator)?;

    let mut sz = DIGEST_LEN; // sizeof(Digest)
    sz += merkle_path_length_digests(param.geom.mc_pathlen, param.geom.nreq) * DIGEST_LEN;
    sz += param.geom.block * k_bytes;
    sz += param.geom.dblock * k_bytes;
    sz += (param.geom.dblock - param.w) * k_bytes;
    sz += param.geom.nreq * NONCE_LEN; // nonces
    sz += param.nwqrow * param.geom.nreq * k_subfield_bytes;
    sz += 3 * param.geom.nreq * k_bytes;

    Some(sz)
}

/// Optimizes the `block_enc` parameter to minimize the proof size.
pub fn optimize_geometry<const W: usize, F: RuntimeField<W>, IF: InterpolatorFactory<W, F>>(
    nw: usize,
    nq: usize,
    rateinv: usize,
    nreq: usize,
    k_bytes: usize,
    k_subfield_bytes: usize,
    make_interpolator: &IF,
) -> usize {
    let mut min_proof_size = usize::MAX;
    let mut best_block_enc = 0;

    for e in 100..=8192 {
        let config = LigeroConfig {
            rateinv,
            nreq,
            block_enc: e,
        };
        if let Some(proof_size) = estimate_proof_size::<W, F, IF>(
            nw,
            nq,
            config,
            k_bytes,
            k_subfield_bytes,
            make_interpolator,
        ) {
            if proof_size < min_proof_size {
                min_proof_size = proof_size;
                best_block_enc = e;
            }
        }
    }

    best_block_enc
}
