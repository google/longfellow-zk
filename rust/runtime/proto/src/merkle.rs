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

pub const DIGEST_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;

/// A 32-byte cryptographic hash digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Digest {
    pub data: [u8; DIGEST_LEN],
}

/// A 32-byte salt value generated randomly per leaf/column to make the
/// commitment zero-knowledge (hiding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleNonce {
    pub bytes: [u8; NONCE_LEN],
}

/// A Merkle proof of opening for a subset of leaves.
/// It contains:
/// - `nonce`: The nonces corresponding to the opened leaves, allowing the verifier to reconstruct
///   the leaf hashes.
/// - `path`: Sibling digests along the paths from the opened leaves to the root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MerkleProof {
    pub nonce: Vec<MerkleNonce>,
    pub path: Vec<Digest>,
}

impl MerkleProof {
    /// Writes the nonces to a byte buffer (raw bytes of each nonce, no length
    /// prefix).
    pub fn write_nonces(&self, buf: &mut Vec<u8>) {
        for n in &self.nonce {
            buf.extend_from_slice(&n.bytes);
        }
    }

    /// Reads `num_queries` nonces from the byte buffer.
    pub fn read_nonces(
        bytes: &mut &[u8],
        num_queries: usize,
    ) -> Result<Vec<MerkleNonce>, std::io::Error> {
        let mut nonce = Vec::with_capacity(num_queries);
        for _ in 0..num_queries {
            let n_bytes = crate::util::read_bytes_32(bytes)?;
            nonce.push(MerkleNonce { bytes: n_bytes });
        }
        Ok(nonce)
    }

    /// Writes the path to a byte buffer (4-byte little-endian length prefix,
    /// followed by raw digests).
    pub fn write_path(&self, buf: &mut Vec<u8>) {
        let len = self.path.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        for d in &self.path {
            buf.extend_from_slice(&d.data);
        }
    }

    /// Reads the path from the byte buffer.
    pub fn read_path(
        bytes: &mut &[u8],
        num_queries: usize,
        mc_pathlen: usize,
    ) -> Result<Vec<Digest>, std::io::Error> {
        let path_len = crate::util::read_size_4bytes(bytes)?;
        let max_sz = num_queries.checked_mul(mc_pathlen).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Overflow computing max Merkle path size",
            )
        })?;
        if path_len > max_sz {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Merkle path size: {path_len} (max_sz={max_sz})"),
            ));
        }

        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let p_bytes = crate::util::read_bytes_32(bytes)?;
            path.push(Digest { data: p_bytes });
        }
        Ok(path)
    }
}
