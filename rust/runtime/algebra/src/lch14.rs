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

// The algorithm from [LCH14] following [DP24, Algorithm 2]
//
// [LCH14] Sian-Jheng Lin, Wei-Ho Chung, and Yunghsiang S. Han: Novel
// Polynomial Basis and Its Application to Reed-Solomon Erasure Codes,
// https://arxiv.org/pdf/1404.3458
//
// [DP24] Benjamin E. Diamond and Jim Posen, Polylogarithmic Proofs
// for Multilinears over Binary Towers, https://eprint.iacr.org/2024/504

use crate::{field::RuntimeBinaryField, subfield::BinarySubfield};

pub struct Lch14<'a, const W: usize, F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>> {
    f: &'a F,
    subfield: &'a BinarySubfield,
    w_hat: Vec<F::E>,
}

impl<'a, const W: usize, F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>> Lch14<'a, W, F> {
    pub fn new(f: &'a F, subfield: &'a BinarySubfield) -> Self {
        // Compute W_i(\beta_j) for all i, j.
        //
        // We store the unnormalized W_[i][j] = W_i(\beta_j)
        // in the same memory as the normalized \hat{W}_i(\beta_j), since
        // the unnormalized values are not needed after normalization.
        let dimension_subfield = subfield.dimension();
        let mut w_hat = vec![f.zero(); dimension_subfield * dimension_subfield];

        // Base case: W_0(X) = X => W_0(\beta_j) = \beta_j
        let basis = subfield.basis();
        w_hat[..dimension_subfield].clone_from_slice(basis);

        // Inductive case: W_{i+1}(X) = W_i(X)(W_i(X) + W_i(\beta_i))
        for i in 0..(dimension_subfield - 1) {
            let w_i_beta_i = w_hat[i * dimension_subfield + i];
            for j in 0..dimension_subfield {
                let mut sum = w_hat[i * dimension_subfield + j];
                f.add(&mut sum, &w_i_beta_i);
                let mut prod = w_hat[i * dimension_subfield + j];
                f.mul(&mut prod, &sum);
                w_hat[(i + 1) * dimension_subfield + j] = prod;
            }
        }

        // Normalize: \hat{W}_i(\beta_j) = W_i(\beta_j) / W_i(\beta_i)
        for i in 0..dimension_subfield {
            let scale = f.invert(&w_hat[i * dimension_subfield + i]);
            for j in 0..dimension_subfield {
                f.mul(&mut w_hat[i * dimension_subfield + j], &scale);
            }
        }

        Self { f, subfield, w_hat }
    }

    #[must_use]
    pub fn w_hat(&self, i: usize, j: usize) -> &F::E {
        &self.w_hat[i * self.subfield.dimension() + j]
    }

    // Computation of a single twiddle factor.
    // Implicit in [LCH14, III.E], explicit in [DP24, Algorithm 2].
    #[must_use]
    pub fn twiddle(&self, i: usize, mut u: usize) -> F::E {
        let mut t = self.f.zero();
        let mut k = 0;
        while u != 0 {
            if (u & 1) != 0 {
                self.f.add(&mut t, self.w_hat(i, k));
            }
            k += 1;
            u >>= 1;
        }
        t
    }

    // linear-time computation of all twiddles at the same time
    pub fn twiddles(&self, i: usize, l: usize, coset: usize, tw: &mut [F::E]) {
        tw[0] = self.twiddle(i, coset);
        for k in 0..((l - 1) - i) {
            let len = 1 << k;
            let shift = *self.w_hat(i, (i + 1) + k);
            let (first, second) = tw[..2 * len].split_at_mut(len);
            for (dest, src) in second.iter_mut().zip(first.iter()) {
                let mut tmp = *src;
                self.f.add(&mut tmp, &shift);
                *dest = tmp;
            }
        }
    }

    // Notation from [DP24, Algorithm 2], except that we hardcode R=0
    // and add the coset parameter.
    pub fn fft(&self, l: usize, coset: usize, b: &mut [F::E]) {
        assert!(l <= self.subfield.dimension());

        if l > 0 {
            let len = 1 << l;
            assert!(b.len() >= len);
            let b_slice = &mut b[..len];
            let n_tw = 1 << (l - 1);
            let mut tw = vec![self.f.zero(); n_tw];

            for i in (0..l).rev() {
                let s = 1 << i;
                self.twiddles(i, l, coset, &mut tw);
                for (chunk, twu) in b_slice.chunks_exact_mut(2 * s).zip(tw.iter()) {
                    let (left, right) = chunk.split_at_mut(s);
                    for (b_uv, b_uv_s) in left.iter_mut().zip(right.iter_mut()) {
                        self.butterfly_fwd_pair(b_uv, b_uv_s, twu);
                    }
                }
            }
        }
    }

    pub fn ifft(&self, l: usize, coset: usize, b: &mut [F::E]) {
        assert!(l <= self.subfield.dimension());

        if l > 0 {
            let len = 1 << l;
            assert!(b.len() >= len);
            let b_slice = &mut b[..len];
            let n_tw = 1 << (l - 1);
            let mut tw = vec![self.f.zero(); n_tw];

            for i in 0..l {
                let s = 1 << i;
                self.twiddles(i, l, coset, &mut tw);
                for (chunk, twu) in b_slice.chunks_exact_mut(2 * s).zip(tw.iter()) {
                    let (left, right) = chunk.split_at_mut(s);
                    for (b_uv, b_uv_s) in left.iter_mut().zip(right.iter_mut()) {
                        self.butterfly_bwd_pair(b_uv, b_uv_s, twu);
                    }
                }
            }
        }
    }

    // The algorithm described in Joris van der Hoeven, "The Truncated
    // Fourier Transform and Applications". This implementation is
    // based on the pseudo-code from the followup paper "Notes on the
    // Truncated Fourier Transform", also by Joris van der Hoeven.
    //
    // Van der Hoeven considers the classic multiplicative FFT;
    // here we port the algorithm to the [LCH14] adaptive FFT.
    //
    // Here we call the algorithm the "Bidirectional FFT", because
    // the algorithm takes a set of points in the "time" domain
    // and the complementary set of points in the "frequency" domain,
    // and it flips time and frequency, so the algorithm can be
    // used to compute the forward and backward transforms, as well
    // as combinations of the two.
    //
    // The literature on the truncated Fourier transforms assumes that
    // the complementary set of points are implicitly set to zero, and
    // the main problem is how to avoid storing the zeroes. Our main
    // problem is not time or space efficiency, but polynomial
    // interpolation. Given k evaluations of a polynomial of degree <k,
    // compute the other evaluations up to n=2^l. So we care about both
    // the unknown nonzero coefficients and the unknown n-k evaluations.
    pub fn bidirectional_fft(&self, l: usize, k: usize, b: &mut [F::E]) {
        assert!(l <= self.subfield.dimension());
        self.bidir_recur(l, 0, k, b);
    }

    fn bidir_recur(&self, mut i: usize, coset: usize, k: usize, b: &mut [F::E]) {
        if i > 0 {
            i -= 1;
            let s = 1 << i;
            let twu = self.twiddle(i, coset);
            let b_slice = &mut b[..2 * s];

            if k < s {
                let (left, right) = b_slice.split_at_mut(s);
                for (b_uv, b_uv_s) in left[k..s].iter_mut().zip(right[k..s].iter_mut()) {
                    self.butterfly_fwd_pair(b_uv, b_uv_s, &twu);
                }

                self.bidir_recur(i, coset, k, left);

                for (b_uv, b_uv_s) in left[..k].iter_mut().zip(right[..k].iter_mut()) {
                    self.butterfly_diag_pair(b_uv, b_uv_s, &twu);
                }

                self.fft(i, coset + s, right);
            } else {
                let (left, right) = b_slice.split_at_mut(s);
                self.ifft(i, coset, left);

                let k_sub = k - s;
                for (b_uv, b_uv_s) in left[k_sub..s].iter_mut().zip(right[k_sub..s].iter_mut()) {
                    self.butterfly_diag_pair(b_uv, b_uv_s, &twu);
                }

                self.bidir_recur(i, coset + s, k_sub, right);

                for (b_uv, b_uv_s) in left[..k_sub].iter_mut().zip(right[..k_sub].iter_mut()) {
                    self.butterfly_bwd_pair(b_uv, b_uv_s, &twu);
                }
            }
        }
    }

    #[inline(always)]
    fn butterfly_fwd_pair(&self, b_uv: &mut F::E, b_uv_s: &mut F::E, twu: &F::E) {
        let mut prod = *b_uv_s;
        self.f.mul(&mut prod, twu);
        self.f.add(b_uv, &prod);
        let tmp = *b_uv;
        self.f.add(b_uv_s, &tmp);
    }

    #[inline(always)]
    fn butterfly_bwd_pair(&self, b_uv: &mut F::E, b_uv_s: &mut F::E, twu: &F::E) {
        let tmp = *b_uv;
        self.f.sub(b_uv_s, &tmp);
        let mut prod = *b_uv_s;
        self.f.mul(&mut prod, twu);
        self.f.sub(b_uv, &prod);
    }

    #[inline(always)]
    fn butterfly_diag_pair(&self, b_uv: &mut F::E, b_uv_s: &mut F::E, twu: &F::E) {
        let b1 = *b_uv_s;
        let tmp = *b_uv;
        self.f.add(b_uv_s, &tmp);
        let mut prod = b1;
        self.f.mul(&mut prod, twu);
        self.f.sub(b_uv, &prod);
    }
}
