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

//! This is an implementation of the Ligero protocol described in:
//!
//!   Ligero: Lightweight Sublinear Arguments Without a Trusted Setup,
//!   Scott Ames and Carmit Hazay and Yuval Ishai and Muthuramakrishnan
//! Venkitasubramaniam,   <https://eprint.iacr.org/2022/1608>, doi = {10.1145/3133956}.
//!
//! The main data structure in the prover is a 2D array which we call a
//! tableau organized as follows.
//!
//! Fix a block size `BLOCK` and let `DBLOCK = 2 * BLOCK - 1`. Fix another
//! quantity `BLOCK_EXT >= 0`.
//!
//! Each row in the tableau has the form `[X XD XEXT]`, where `X` is a row
//! of `BLOCK` elements, `XD` is a row of `BLOCK - 1` elements, and `XEXT` is a
//! row of `BLOCK_EXT` elements. We call the `X` part the "block" and the
//! `XEXT` part the "extension".
//!
//! Let `BLOCK_ENC = 2 * BLOCK - 1 + BLOCK_EXT = DBLOCK + BLOCK_EXT` be
//! the total size of the row.
//!
//! A "witness block" has the form `[RANDOM[R], WITNESS[W]]`, where `R + W =
//! BLOCK`. The randomness (of size `R`) is used for zero-knowledge blinding.
//! Although not strictly required by Ligero, we require `W >= R` to avoid
//! wasting too much space, so that a witness block is at least half full.
//!
//! A block is interpreted as evaluations of some polynomial at point
//! `INJ(j)` for `0 <= j < BLOCK`, where `INJ(.)` is some field-specific
//! injection that injects small natural numbers into distinct field
//! elements. With the condition that the degree of the polynomial be
//! less than `BLOCK`, the polynomial is uniquely determined, and the rest
//! `[XD XEXT]` of the row is then computed as the evaluations of that
//! polynomial for `BLOCK <= j < BLOCK_ENC`.
//!
//! To the extent that Ligero is based on Reed-Solomon codes, `X` is the
//! "message" and `XEXT` is the "codeword". The "rate" is thus `BLOCK /
//! BLOCK_EXT`.
//!
//! However, Ligero also needs products of two polynomials of degree
//! less than `BLOCK`, so that the product has degree less than `2 * BLOCK - 1 =
//! DBLOCK`. `XD` exists in the tableau to facilitate the computation of these
//! products. For zero knowledge, the indices of `XD` must be distinct from the
//! indices of `BLOCK_EXT`.
//!
//! We now discuss the row structure of the tableau. The first three
//! rows are special and used for zero-knowledge blinding purposes.
//!
//! The first row, row `ILDT` for `ILDT = 0`, used for the low-degree test,
//! consists of `BLOCK` random field elements, extended to `BLOCK_ENC`.
//!
//! The second row, row `IDOT` for `IDOT = 1`, used in the linear test,
//! consists of `DBLOCK` random field elements, with the additional
//! constraint that the double block sum to 0. As usual, the row is
//! extended to `BLOCK_ENC` by interpolation.
//!
//! The third row, row `IQUAD` for `IQUAD = 2`, used in the quadratic test,
//! consists of `DBLOCK` random field elements, with the additional
//! constraint that the `WITNESS` portion of the block be zero. Thus, the
//! structure is really `[RANDOM[R] ZERO[W] RANDOM[BLOCK-1]]`, extended to
//! `BLOCK_ENC` by interpolation.
//!
//! The next group of "witness rows" `IW <= I < IQ` for `IW = 3`, stores
//! witnesses. Each row is a witness block extended to `BLOCK_ENC`.
//!
//! The next group of "quadratic" rows `IQ <= I < NROW`, has the same
//! syntactic structure as the "witness" rows, but they are used in the
//! quadratic check in addition to the linear check. In Ligero, a
//! quadratic constraint induces three entries in three quadratic rows.
//! Thus, for `NQ` total quadratic constraints and `W` useful entries per
//! row, we have a total of `3 * (NQ / W)` quadratic rows. To enforce
//! this structure, the code stores `NQTRIPLES = (NQ / W)` instead of the
//! number `3 * NQTRIPLES` of rows.

use runtime_algebra::{field::RuntimeField, interpolator::InterpolatorFactory};
pub use runtime_proto::{LigeroCommitment, LigeroGeometry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LigeroConfig {
    pub rateinv: usize,
    pub nreq: usize,
    pub block_enc: usize,
}

#[derive(Debug)]
pub struct LigeroParam {
    /// Geometry parameters containing row & block sizes.
    pub geom: LigeroGeometry,

    pub nw: usize, // total number of witnesses
    pub nq: usize, // total number of quadratic constraints

    // computed parameters
    pub w: usize,         // number of witnesses in a witness block
    pub nwrow: usize,     // number of witness rows
    pub nqtriples: usize, // number of triples of quadratic-check rows
    pub nwqrow: usize,    // nwqrow + nqtriples

    // layout of rows
    pub ildt: usize,  // blinding for the low-degree test
    pub idot: usize,  // blinding row for the dot-product check
    pub iquad: usize, // blinding row for the quadratic check
    pub iw: usize,    // first witness row
    pub iq: usize,    // first quadratic row
}

impl LigeroParam {
    pub fn new<const W: usize, F: RuntimeField<W>, IF: InterpolatorFactory<W, F>>(
        nw: usize,
        nq: usize,
        config: LigeroConfig,
        make_interpolator: &IF,
    ) -> Self {
        let param = Self::try_new(nw, nq, config, make_interpolator)
            .expect("invalid LigeroParam parameters");
        param.sanity();
        param
    }

    pub fn try_new<const W: usize, F: RuntimeField<W>, IF: InterpolatorFactory<W, F>>(
        nw: usize,
        nq: usize,
        config: LigeroConfig,
        make_interpolator: &IF,
    ) -> Option<Self> {
        let max_lg_size = 28;
        let max_size = 1 << max_lg_size;

        if config.block_enc > max_size
            || config.rateinv > max_size
            || (config.block_enc + 1) < (2 + config.rateinv)
        {
            return None;
        }

        let block = (config.block_enc + 1) / (2 + config.rateinv);
        if !make_interpolator.can_encode(block, config.block_enc) {
            return None;
        }
        if block < config.nreq {
            return None;
        }

        let w = block - config.nreq;
        if w < config.nreq {
            return None;
        }

        let dblock = 2 * block - 1;
        if config.block_enc < dblock || config.block_enc - dblock < config.nreq {
            return None;
        }

        let nwrow = nw.div_ceil(w);
        let nqtriples = nq.div_ceil(w);

        let ildt = 0;
        let idot = 1;
        let iquad = 2;
        let iw = 3;
        let iq = iw + nwrow;
        let nwqrow = nwrow + 3 * nqtriples;
        let nrow = iw + nwqrow;

        let geom = LigeroGeometry {
            block,
            dblock,
            r: config.nreq,
            block_enc: config.block_enc,
            nrow,
            nreq: config.nreq,
            mc_pathlen: runtime_merkle::merkle_heap_len(config.block_enc - dblock),
        };

        Some(Self {
            geom,
            nw,
            nq,
            w,
            nwrow,
            nqtriples,
            nwqrow,
            ildt,
            idot,
            iquad,
            iw,
            iq,
        })
    }

    pub fn sanity(&self) {
        assert!(self.geom.block >= self.geom.nreq);
        assert_eq!(self.w, self.geom.block - self.geom.nreq);
        assert_eq!(self.geom.dblock, 2 * self.geom.block - 1);
        assert!(self.geom.block_enc >= self.geom.dblock);
        assert_eq!(self.iw, 3);
        assert_eq!(self.iq, self.iw + self.nwrow);
        assert_eq!(self.nwqrow, self.nwrow + 3 * self.nqtriples);
        assert_eq!(self.geom.nrow, self.iw + self.nwqrow);
        assert_eq!(
            self.geom.mc_pathlen,
            runtime_merkle::merkle_heap_len(self.geom.block_enc - self.geom.dblock)
        );
    }
}

impl std::ops::Deref for LigeroParam {
    type Target = LigeroGeometry;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.geom
    }
}

impl Clone for LigeroParam {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for LigeroParam {}

#[derive(Debug)]
pub struct LigeroLinearConstraint<const W: usize, F: RuntimeField<W>> {
    pub c: usize,
    pub w: usize,
    pub k: F::E,
}

impl<const W: usize, F: RuntimeField<W>> Clone for LigeroLinearConstraint<W, F> {
    fn clone(&self) -> Self {
        Self {
            c: self.c,
            w: self.w,
            k: self.k.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LigeroQuadraticConstraint {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}
