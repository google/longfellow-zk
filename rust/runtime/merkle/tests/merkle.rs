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

use runtime_merkle::{commit, open, verify, verify_proof, Digest, MerkleHeap};
use runtime_random::RandomEngine;
use sha2::Digest as ShaDigest;

struct FakeRng {
    counter: u8,
}

impl RandomEngine for FakeRng {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(self.counter);
            self.counter = self.counter.wrapping_add(1);
        }
        buf
    }
}

#[test]
fn test_merkle_heap_simple() {
    let d0 = Digest { data: [0; 32] };
    let d1 = Digest { data: [1; 32] };
    let d2 = Digest { data: [2; 32] };
    let d3 = Digest { data: [3; 32] };
    let mh = MerkleHeap::new(&[d0, d1, d2, d3]);
    let root = mh.root();

    let proof_path = mh.generate_proof(&[1, 2]);

    assert!(verify_proof(4, &root, &proof_path, &[(1, d1), (2, d2)]).is_ok());
}

#[test]
fn test_merkle_commitment() {
    let mut rng = FakeRng { counter: 0 };
    let data = [
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
        vec![10, 11, 12],
    ];

    let (mc, root) = commit(4, &mut rng, |idx, sha| {
        sha.update(&data[idx]);
    });

    let opened_indices = vec![1, 3];
    let proof = open(&mc, &opened_indices);

    assert!(verify(4, &root, &opened_indices, &proof, |_r, idx, sha| {
        sha.update(&data[idx]);
    })
    .is_ok());
}

#[test]
fn test_merkle_heap_large_and_random() {
    let n = 16;
    let mut leaves = Vec::new();
    for i in 0..n {
        let digest = Digest {
            data: [i as u8; 32],
        };
        leaves.push(digest);
    }
    let mh = MerkleHeap::new(&leaves);
    let root = mh.root();

    // 1. Verify single leaf paths
    for (i, &leaf) in leaves.iter().enumerate().take(n) {
        let proof_path = mh.generate_proof(&[i]);
        assert!(verify_proof(n, &root, &proof_path, &[(i, leaf)]).is_ok());
    }

    // 2. Verify multiple non-contiguous leaf subsets
    let test_subsets = vec![
        vec![0, 15],
        vec![1, 2, 3],
        vec![0, 2, 4, 6, 8, 10, 12, 14],
        vec![1, 5, 9, 13],
        vec![4, 5, 6, 7],
    ];

    for subset in test_subsets {
        let proof_path = mh.generate_proof(&subset);
        let opened_leaves: Vec<(usize, Digest)> =
            subset.iter().map(|&idx| (idx, leaves[idx])).collect();
        assert!(verify_proof(n, &root, &proof_path, &opened_leaves).is_ok());
    }
}

#[test]
fn test_merkle_heap_invalid_proofs() {
    let n = 8;
    let mut leaves = Vec::new();
    for i in 0..n {
        let digest = Digest {
            data: [i as u8; 32],
        };
        leaves.push(digest);
    }
    let mh = MerkleHeap::new(&leaves);
    let root = mh.root();

    let subset = vec![2, 5];
    let proof_path = mh.generate_proof(&subset);
    let opened_leaves: Vec<(usize, Digest)> =
        subset.iter().map(|&idx| (idx, leaves[idx])).collect();

    // Verify valid proof passes
    assert!(verify_proof(n, &root, &proof_path, &opened_leaves).is_ok());

    // 1. Modifying a proof element should fail verification
    if !proof_path.is_empty() {
        let mut tampered_proof = proof_path.clone();
        tampered_proof[0].data[0] ^= 1;
        assert!(verify_proof(n, &root, &tampered_proof, &opened_leaves).is_err());
    }

    // 2. Modifying one of the opened leaf values should fail verification
    let mut tampered_leaves = opened_leaves.clone();
    tampered_leaves[0].1.data[0] ^= 1;
    assert!(verify_proof(n, &root, &proof_path, &tampered_leaves).is_err());

    // 3. Modifying one of the opened leaf indices should fail verification
    let mut tampered_leaves_idx = opened_leaves.clone();
    tampered_leaves_idx[0].0 = 0; // change index from 2 to 0
    assert!(verify_proof(n, &root, &proof_path, &tampered_leaves_idx).is_err());

    // 4. Modifying the root should fail verification
    let mut tampered_root = root;
    tampered_root.data[0] ^= 1;
    assert!(verify_proof(n, &tampered_root, &proof_path, &opened_leaves).is_err());
}

#[test]
fn test_merkle_commitment_tampering() {
    let mut rng = FakeRng { counter: 42 };
    let num_cols = 16;
    let data: Vec<Vec<u8>> = (0..num_cols)
        .map(|col| vec![col as u8, (col * 2) as u8, (col * 3) as u8])
        .collect();

    let (mc, root) = commit(num_cols, &mut rng, |idx, sha| {
        sha.update(&data[idx]);
    });

    let opened_indices = vec![3, 7, 11];
    let proof = open(&mc, &opened_indices);

    // Valid verification passes
    assert!(
        verify(num_cols, &root, &opened_indices, &proof, |_r, idx, sha| {
            sha.update(&data[idx]);
        })
        .is_ok()
    );

    // Verification fails if data is modified
    assert!(
        verify(num_cols, &root, &opened_indices, &proof, |r, idx, sha| {
            if r == 1 {
                sha.update([0, 0, 0]); // tampered column data
            } else {
                sha.update(&data[idx]);
            }
        })
        .is_err()
    );
}

#[test]
fn test_merkle_cpp_compatibility() {
    let test_vector = include_bytes!("merkle_test_vector.bin");

    let mut offset = 0;

    // 1. Read num_leaves
    let num_leaves =
        u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    // 2. Read leaves digests
    let mut leaves = Vec::new();
    for _ in 0..num_leaves {
        let mut data = [0u8; 32];
        data.copy_from_slice(&test_vector[offset..offset + 32]);
        leaves.push(Digest { data });
        offset += 32;
    }

    // 3. Read num_queries
    let num_queries =
        u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    // 4. Read query_indices
    let mut query_indices = Vec::new();
    for _ in 0..num_queries {
        let idx = u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
        query_indices.push(idx);
        offset += 8;
    }

    // 5. Read expected root
    let mut expected_root = Digest::default();
    expected_root
        .data
        .copy_from_slice(&test_vector[offset..offset + 32]);
    offset += 32;

    // 6. Read proof_len
    let proof_len =
        u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    // 7. Read proof digests
    let mut expected_proof = Vec::new();
    for _ in 0..proof_len {
        let mut data = [0u8; 32];
        data.copy_from_slice(&test_vector[offset..offset + 32]);
        expected_proof.push(Digest { data });
        offset += 32;
    }

    assert_eq!(
        offset,
        test_vector.len(),
        "Did not read entire test vector file"
    );

    // Reconstruct heap in Rust
    let mh = MerkleHeap::new(&leaves);

    // Verify root matches exactly
    assert_eq!(mh.root(), expected_root, "Merkle root mismatch with C++");

    // Generate proof using Rust MerkleHeap
    let proof = mh.generate_proof(&query_indices);

    // Verify proof matches C++ proof exactly
    assert_eq!(proof, expected_proof, "Merkle proof mismatch with C++");

    // Verify proof using Rust verify_proof
    let opened_leaves: Vec<(usize, Digest)> = query_indices
        .iter()
        .map(|&idx| (idx, leaves[idx]))
        .collect();
    assert!(
        verify_proof(num_leaves, &expected_root, &proof, &opened_leaves).is_ok(),
        "Rust verify_proof failed"
    );
}

#[test]
fn test_merkle_commitment_cpp_compatibility() {
    struct DeterministicRng {
        counter: u8,
    }

    impl RandomEngine for DeterministicRng {
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(self.counter);
                self.counter = self.counter.wrapping_add(1);
            }
            buf
        }
    }

    let test_vector = include_bytes!("commitment_test_vector.bin");
    let mut offset = 0;

    // 1. Read num_leaves
    let num_leaves =
        u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    // 2. Read num_queries
    let num_queries =
        u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    // 3. Read query_indices
    let mut query_indices = Vec::new();
    for _ in 0..num_queries {
        let idx = u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
        query_indices.push(idx);
        offset += 8;
    }

    // 4. Read expected root
    let mut expected_root = Digest::default();
    expected_root
        .data
        .copy_from_slice(&test_vector[offset..offset + 32]);
    offset += 32;

    // 5. Read expected nonces
    let mut expected_nonces = Vec::new();
    for _ in 0..num_queries {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes.copy_from_slice(&test_vector[offset..offset + 32]);
        expected_nonces.push(nonce_bytes);
        offset += 32;
    }

    // 6. Read path_len
    let path_len = u64::from_le_bytes(test_vector[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    // 7. Read expected path
    let mut expected_path = Vec::new();
    for _ in 0..path_len {
        let mut data = [0u8; 32];
        data.copy_from_slice(&test_vector[offset..offset + 32]);
        expected_path.push(Digest { data });
        offset += 32;
    }

    assert_eq!(
        offset,
        test_vector.len(),
        "Did not read entire test vector file"
    );

    // Setup deterministic RNG matching C++ (starting at 42)
    let mut rng = DeterministicRng { counter: 42 };

    // Commit in Rust
    let (mc, root) = commit(num_leaves, &mut rng, |idx, sha| {
        let col_data = [
            (idx * 3) as u8,
            (idx * 5) as u8,
            (idx * 7) as u8,
            (idx * 11) as u8,
        ];
        sha.update(col_data);
    });

    // Verify root matches exactly
    assert_eq!(root, expected_root, "Merkle root mismatch with C++");

    // Open commitment proof
    let proof = open(&mc, &query_indices);

    // Verify nonces match exactly
    for (i, expected_nonce) in expected_nonces.iter().enumerate().take(num_queries) {
        assert_eq!(
            &proof.nonce[i].bytes, expected_nonce,
            "Nonce mismatch at index {i}"
        );
    }

    // Verify path matches exactly
    assert_eq!(proof.path, expected_path, "Merkle path mismatch with C++");

    // Verify commitment verifier passes
    assert!(
        verify(num_leaves, &root, &query_indices, &proof, |_r, idx, sha| {
            let col_data = [
                (idx * 3) as u8,
                (idx * 5) as u8,
                (idx * 7) as u8,
                (idx * 11) as u8,
            ];
            sha.update(col_data);
        })
        .is_ok(),
        "Rust Merkle commitment verification failed"
    );
}
