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

#![allow(clippy::needless_range_loop)]

use sha2::{Digest, Sha256};

use crate::algebra::Rng;

pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[derive(Clone, Debug)]
pub struct MerkleHeap {
    pub num_leaves: usize,
    pub layers: Vec<Vec<u8>>,
    pub root: Vec<u8>,
}

impl MerkleHeap {
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        let n = leaves.len();
        let mut layers = vec![Vec::new(); 2 * n];
        layers[n..(n + n)].clone_from_slice(&leaves[..n]);
        for i in (1..n).rev() {
            let mut data = Vec::new();
            data.extend_from_slice(&layers[2 * i]);
            data.extend_from_slice(&layers[2 * i + 1]);
            layers[i] = sha256_bytes(&data);
        }
        let root = layers[1].clone();
        Self {
            num_leaves: n,
            layers,
            root,
        }
    }
}

pub fn commit_merkle_heap<R, F>(
    num_leaves: usize,
    update_leaf_hash_fn: F,
    rng: &mut R,
) -> (MerkleHeap, Vec<Vec<u8>>)
where
    R: Rng,
    F: Fn(usize) -> Vec<u8>,
{
    let mut nonces = Vec::with_capacity(num_leaves);
    for _ in 0..num_leaves {
        nonces.push(rng.bytes(32));
    }

    let mut leaves_digests = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let mut data = Vec::new();
        data.extend_from_slice(&nonces[i]);
        data.extend_from_slice(&update_leaf_hash_fn(i));
        leaves_digests.push(sha256_bytes(&data));
    }

    let heap = MerkleHeap::new(&leaves_digests);
    (heap, nonces)
}

pub fn open_merkle_heap(
    mh: &MerkleHeap,
    leaf_indices: &[usize],
) -> Result<Vec<Vec<u8>>, &'static str> {
    let n = mh.num_leaves;
    let mut seen = vec![false; n];
    let mut is_on_path = vec![false; 2 * n];
    for &idx in leaf_indices {
        if idx >= n {
            return Err("Leaf index out of bounds in Merkle opening");
        }
        if seen[idx] {
            return Err("Duplicate leaf index in Merkle opening");
        }
        seen[idx] = true;
        is_on_path[n + idx] = true;
    }
    for i in (1..n).rev() {
        is_on_path[i] = is_on_path[2 * i] || is_on_path[2 * i + 1];
    }

    let mut path = Vec::new();
    for i in (1..n).rev() {
        if is_on_path[i] {
            if is_on_path[2 * i] && !is_on_path[2 * i + 1] {
                path.push(mh.layers[2 * i + 1].clone());
            } else if !is_on_path[2 * i] && is_on_path[2 * i + 1] {
                path.push(mh.layers[2 * i].clone());
            }
        }
    }
    Ok(path)
}

pub fn verify_merkle_proof<F>(
    n: usize,
    root: &[u8],
    leaf_indices: &[usize],
    path: &[Vec<u8>],
    mut leaf_hash_fn: F,
) -> Result<(), &'static str>
where
    F: FnMut(usize) -> Vec<u8>,
{
    let mut seen = vec![false; n];
    let mut is_on_path = vec![false; 2 * n];
    for &idx in leaf_indices {
        if idx >= n {
            return Err("Leaf index out of bounds in Merkle proof verification");
        }
        if seen[idx] {
            return Err("Duplicate leaf index in Merkle proof verification");
        }
        seen[idx] = true;
        is_on_path[n + idx] = true;
    }
    for i in (1..n).rev() {
        is_on_path[i] = is_on_path[2 * i] || is_on_path[2 * i + 1];
    }

    let mut layers: Vec<Option<Vec<u8>>> = vec![None; 2 * n];
    for &idx in leaf_indices {
        layers[n + idx] = Some(leaf_hash_fn(idx));
    }

    let mut path_idx = 0;
    for i in (1..n).rev() {
        if is_on_path[i] {
            let left_val = if is_on_path[2 * i] {
                layers[2 * i].clone()
            } else {
                let val = path.get(path_idx).cloned();
                path_idx += 1;
                val
            };
            let right_val = if is_on_path[2 * i + 1] {
                layers[2 * i + 1].clone()
            } else {
                let val = path.get(path_idx).cloned();
                path_idx += 1;
                val
            };

            if let (Some(left_val), Some(right_val)) = (left_val, right_val) {
                let mut data = Vec::with_capacity(left_val.len() + right_val.len());
                data.extend_from_slice(&left_val);
                data.extend_from_slice(&right_val);
                layers[i] = Some(sha256_bytes(&data));
            } else {
                return Err("Missing path value in Merkle proof verification");
            }
        }
    }

    if path_idx != path.len() {
        return Err("Not all Merkle path elements were consumed");
    }

    if let Some(computed_root) = &layers[1] {
        if computed_root == root {
            Ok(())
        } else {
            Err("Merkle root mismatch")
        }
    } else {
        Err("Merkle root was not computed")
    }
}
