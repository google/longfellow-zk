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

use crate::gf2_128::Gf2_128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinarySubfield {
    basis: [Gf2_128; 16],
    u: [Gf2_128; 16],
    linv: [u64; 16],
    ldnz: [usize; 16],
    len: usize,
    serialized_size_bytes: usize,
}

/// Computes the Row Echelon Form (RREF) of a linearly independent basis of size `subfield_bits`
/// over GF(2) to derive projection information.
///
/// Under the hood, this sets up and solves a system of linear equations to reconstruct the
/// coefficients of any field element with respect to the given basis.
///
/// Specifically, we treat each basis element as a 128-dimensional vector over GF(2) (its bit
/// representation). We start with:
/// - `u`: a copy of the basis vectors.
/// - `linv`: tracking the linear combination coefficients. Initially, the i-th row has coefficient
///   `1 << i`.
///
/// We run Gaussian elimination over the 128 coordinates `j`:
/// 1. Pivot selection: find a row `i0 >= rnk` with a 1 at coordinate `j`.
/// 2. If found, swap it to row `rnk`, and record `ldnz[rnk] = j` (the leading non-zero index for
///    this pivot row).
/// 3. Clear coordinate `j` in all other rows `i1 != rnk` by adding row `rnk` (which is XOR over
///    GF(2)) to `u[i1]`, and simultaneously `XORing` the coefficients `linv[rnk]` into `linv[i1]`.
///
/// After processing, `rnk` must equal the number of basis elements (linear independence).
/// The resulting `u`, `linv`, and `ldnz` are used by the projection solver (`solve`) to project
/// any field element back to the subfield's basis coordinates.
fn rref(basis: &[Gf2_128], subfield_bits: usize) -> ([Gf2_128; 16], [u64; 16], [usize; 16]) {
    let mut u = [Gf2_128::default(); 16];
    u[..subfield_bits].copy_from_slice(basis);

    let mut linv = [0u64; 16];
    for (i, cell) in linv.iter_mut().enumerate().take(subfield_bits) {
        *cell = 1u64 << i;
    }

    let mut ldnz = [0usize; 16];
    let mut rnk = 0;
    for j in 0..128 {
        let mut i0 = rnk;
        while i0 < subfield_bits && !u[i0].bit(j) {
            i0 += 1;
        }
        if i0 < subfield_bits {
            u.swap(rnk, i0);
            linv.swap(rnk, i0);
            ldnz[rnk] = j;

            let rnk_u = u[rnk];
            let rnk_linv = linv[rnk];

            for i1 in 0..subfield_bits {
                if i1 != rnk && u[i1].bit(j) {
                    u[i1].add(&rnk_u);
                    linv[i1] ^= rnk_linv;
                }
            }
            rnk += 1;
        }
    }
    assert_eq!(rnk, subfield_bits, "basis must have full rank");
    (u, linv, ldnz)
}

impl BinarySubfield {
    pub fn new(basis: &[u128]) -> Self {
        let subfield_bits = basis.len();
        assert!(
            subfield_bits <= 16,
            "BinarySubfield only supports up to 16 bits"
        );
        assert_eq!(
            subfield_bits % 8,
            0,
            "BinarySubfield dimension must be byte-aligned"
        );
        let basis_elts: Vec<Gf2_128> = basis.iter().copied().map(Gf2_128::from).collect();
        let (u, linv, ldnz) = rref(&basis_elts, subfield_bits);
        let serialized_size_bytes = subfield_bits / 8;

        let mut basis_arr = [Gf2_128::default(); 16];
        basis_arr[..subfield_bits].copy_from_slice(&basis_elts);

        Self {
            basis: basis_arr,
            u,
            linv,
            ldnz,
            len: subfield_bits,
            serialized_size_bytes,
        }
    }

    #[must_use]
    pub fn basis(&self) -> &[Gf2_128] {
        &self.basis[..self.len]
    }

    #[must_use]
    pub fn dimension(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn embed(&self, mut u: u64) -> Gf2_128 {
        let mut t = Gf2_128::default();
        for i in 0..self.len {
            if (u & 1) != 0 {
                t.add(&self.basis[i]);
            }
            u >>= 1;
        }
        assert_eq!(u, 0, "embed(u), too many bits");
        t
    }

    fn solve(&self, e: &Gf2_128) -> (Gf2_128, u64) {
        let mut u = 0u64;
        let mut ue = *e;
        for rnk in 0..self.len {
            let j = self.ldnz[rnk];
            if ue.bit(j) {
                let u_rnk = self.u[rnk];
                ue.add(&u_rnk);
                u ^= self.linv[rnk];
            }
        }
        (ue, u)
    }

    pub fn project(&self, e: &Gf2_128) -> Result<u64, String> {
        let (ue, u) = self.solve(e);
        if !self.is_zero(&ue) {
            return Err("element not in subfield".to_string());
        }
        Ok(u)
    }

    #[must_use]
    pub fn contains(&self, e: &Gf2_128) -> bool {
        let (ue, _) = self.solve(e);
        self.is_zero(&ue)
    }

    fn is_zero(&self, e: &Gf2_128) -> bool {
        e.is_zero()
    }
}

pub trait Subfield {
    type E;
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]);
    #[inline]
    fn to_bytes(&self, e: &Self::E) -> Vec<u8> {
        let len = self.serialized_size_bytes();
        let mut buf = vec![0u8; len];
        self.to_bytes_into(e, &mut buf);
        buf
    }
    fn contains(&self, e: &Self::E) -> bool;
    fn serialized_size_bytes(&self) -> usize;
    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String>;
    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, rng: R) -> Self::E;
}

impl Subfield for BinarySubfield {
    type E = Gf2_128;

    #[inline]
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        let size = self.serialized_size_bytes();
        assert_eq!(
            dst.len(),
            size,
            "destination slice length mismatch: {} != {}",
            dst.len(),
            size
        );
        let u = self.project(e).expect("element not in subfield");
        let bytes = u.to_le_bytes();
        dst.copy_from_slice(&bytes[..size]);
    }

    fn contains(&self, e: &Self::E) -> bool {
        self.contains(e)
    }

    fn serialized_size_bytes(&self) -> usize {
        self.serialized_size_bytes
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        let size = self.serialized_size_bytes();
        if bytes.len() != size {
            return Err("Invalid byte length for subfield element".to_string());
        }
        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(bytes);
        let u = u64::from_le_bytes(buf);
        Ok(self.embed(u))
    }

    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, mut rng: R) -> Self::E {
        let size = self.serialized_size_bytes();
        let mut buf = [0u8; 8];
        let bytes = rng(size);
        buf[..size].copy_from_slice(&bytes);
        let mut val = u64::from_le_bytes(buf);
        if self.len < 64 {
            val &= (1u64 << self.len) - 1;
        }
        self.embed(val)
    }
}
