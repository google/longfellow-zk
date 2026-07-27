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

use core_algebra::{ElementOf, SerializableField};
use runtime_algebra::{field::RuntimeField, Subfield};

use crate::{
    util::{
        read_bytes_32, read_elt_field, read_size_4bytes, read_subfield_elt, read_vec_field,
        write_elt_field, write_size_4bytes, write_subfield_elt,
    },
    Digest, MerkleNonce, MerkleProof,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LigeroGeometry {
    pub block: usize,
    pub dblock: usize,
    pub r: usize,
    pub block_enc: usize,
    pub nrow: usize,
    pub nreq: usize,
    pub mc_pathlen: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LigeroProof<const W: usize, F: SerializableField> {
    /// Blinding row for low-degree test. [block]
    pub y_ldt: Vec<ElementOf<F>>,
    /// Blinding row for dot-product check. [dblock]
    pub y_dot: Vec<ElementOf<F>>,
    /// First part of blinding row for quadratic check. [r]
    pub y_quad_0: Vec<ElementOf<F>>,
    /// Last part of blinding row for quadratic check. [dblock - block]
    pub y_quad_2: Vec<ElementOf<F>>,
    /// Query responses for column openings. [nrow * nreq]
    pub req: Vec<ElementOf<F>>,
    pub merkle: MerkleProof,
}

impl<const W: usize, F: RuntimeField<W> + SerializableField> LigeroProof<W, F> {
    pub fn write_to_buf<SF: Subfield<E = ElementOf<F>>>(
        &self,
        bytes: &mut Vec<u8>,
        geom: &LigeroGeometry,
        f: &F,
        sf: &SF,
    ) -> Result<(), std::io::Error> {
        assert_eq!(self.y_ldt.len(), geom.block, "y_ldt length mismatch");
        assert_eq!(self.y_dot.len(), geom.dblock, "y_dot length mismatch");
        assert_eq!(self.y_quad_0.len(), geom.r, "y_quad_0 length mismatch");
        assert_eq!(
            self.y_quad_2.len(),
            geom.dblock - geom.block,
            "y_quad_2 length mismatch"
        );
        assert_eq!(self.merkle.nonce.len(), geom.nreq, "nonce length mismatch");
        assert_eq!(self.req.len(), geom.nreq * geom.nrow, "req length mismatch");

        // 1. y_ldt
        for elt in &self.y_ldt {
            write_elt_field(bytes, elt, f);
        }

        // 2. y_dot
        for elt in &self.y_dot {
            write_elt_field(bytes, elt, f);
        }

        // 3. y_quad_0
        for elt in &self.y_quad_0 {
            write_elt_field(bytes, elt, f);
        }

        // 4. y_quad_2
        for elt in &self.y_quad_2 {
            write_elt_field(bytes, elt, f);
        }

        // 5. nonces
        for nonce in &self.merkle.nonce {
            bytes.extend_from_slice(&nonce.bytes);
        }

        // 6. req RLE
        let mut subfield_run = false;
        let mut i = 0;
        let total_elts = self.req.len();

        while i < total_elts {
            let mut runlen = 0;
            while i + runlen < total_elts {
                let elt = &self.req[i + runlen];
                let is_sub = sf.contains(elt);
                if is_sub == subfield_run {
                    runlen += 1;
                } else {
                    break;
                }
            }

            write_size_4bytes(bytes, runlen);

            for j in 0..runlen {
                let elt = &self.req[i + j];
                if subfield_run {
                    write_subfield_elt(bytes, elt, sf)?;
                } else {
                    write_elt_field(bytes, elt, f);
                }
            }

            i += runlen;
            subfield_run = !subfield_run;
        }

        // 7. merkle path
        write_size_4bytes(bytes, self.merkle.path.len());
        for p in &self.merkle.path {
            bytes.extend_from_slice(&p.data);
        }

        Ok(())
    }

    pub fn write<SF: Subfield<E = ElementOf<F>>>(
        &self,
        geom: &LigeroGeometry,
        f: &F,
        sf: &SF,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes = Vec::new();
        self.write_to_buf(&mut bytes, geom, f, sf)?;
        Ok(bytes)
    }

    pub fn read<SF: Subfield<E = ElementOf<F>>>(
        bytes: &mut &[u8],
        geom: &LigeroGeometry,
        f: &F,
        sf: &SF,
    ) -> Result<Self, std::io::Error> {
        // 1. y_ldt
        let y_ldt = read_vec_field(bytes, geom.block, f)?;

        // 2. y_dot
        let y_dot = read_vec_field(bytes, geom.dblock, f)?;

        // 3. y_quad_0
        let y_quad_0 = read_vec_field(bytes, geom.r, f)?;

        // 4. y_quad_2
        let y_quad_2 = read_vec_field(bytes, geom.dblock - geom.block, f)?;

        // 5. nonces
        let mut nonce = Vec::with_capacity(geom.nreq);
        for _ in 0..geom.nreq {
            let n_bytes = read_bytes_32(bytes)?;
            nonce.push(MerkleNonce { bytes: n_bytes });
        }

        // 6. RLE req
        const MAX_RUN_LEN: usize = 1 << 25;
        let mut req = Vec::with_capacity(geom.nreq * geom.nrow);
        let mut ci = 0;
        let mut subfield_run = false;
        let mut first_run = true;
        let total_elts = geom.nreq * geom.nrow;

        while ci < total_elts {
            let runlen = read_size_4bytes(bytes)?;
            // The writer uses an empty first run only when the first element
            // belongs to the subfield.  Empty runs anywhere else are
            // non-canonical (and two consecutive empty runs do not advance
            // `ci`), so accepting them would permit multiple encodings of a
            // proof and could loop forever on attacker-controlled input.
            if (runlen == 0 && !first_run) || runlen >= MAX_RUN_LEN || ci + runlen > total_elts {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Non-canonical or invalid RLE run length in LigeroProof",
                ));
            }
            first_run = false;

            for _ in 0..runlen {
                if subfield_run {
                    let elt = read_subfield_elt(bytes, sf)?;
                    req.push(elt);
                } else {
                    let elt = read_elt_field(bytes, f)?;
                    // Request elements in the subfield must use the compact
                    // subfield encoding.  Otherwise the same value has both
                    // a field and a subfield representation.
                    if sf.contains(&elt) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Non-canonical field encoding of subfield element in LigeroProof",
                        ));
                    }
                    req.push(elt);
                }
            }

            ci += runlen;
            subfield_run = !subfield_run;
        }

        // 7. merkle path
        let path_len = read_size_4bytes(bytes)?;
        if path_len > geom.nreq * geom.mc_pathlen {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid Merkle path size in LigeroProof",
            ));
        }

        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let p_bytes = read_bytes_32(bytes)?;
            path.push(Digest { data: p_bytes });
        }

        Ok(Self {
            y_ldt,
            y_dot,
            y_quad_0,
            y_quad_2,
            req,
            merkle: MerkleProof { nonce, path },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LigeroCommitment {
    pub root: Digest,
}
