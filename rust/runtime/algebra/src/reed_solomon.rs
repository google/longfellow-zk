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

use crate::{convolution::Convolver, field::RuntimeField, utility::AlgebraUtil};

// All of the classes in this package compute convolutions.
// That is, given inputs arrays of field elements x, y, with |x|=n, |y|=m,
// these methods compute the first m entries of
//
//    z[k] = \sum_{i=0}^{n-1} x[i] y[k-i]

/// The `ReedSolomon` class interpolates a polynomial given as input in point-eval
/// form at a set of different points, thereby computing a form of RS encoding.
/// Specifically, the input polynomial of degree d=n-1 is given as evaluations
/// at 0, 1, 2, ..., n-1, and the output is the values at n, n+1, n+2, ...,
/// n+m-1. The algorithm uses the following relation:
///
///   p(k) = (-1)^d (k-d)(k choose d) sum_{j=0}^{d} (1/k-j)(-1)^j (d choose
/// j)p(j)
///
/// which can be efficiently computed using a convolution, whose implementation
/// is instantiated via the `make_convolver` closure parameter.
pub struct ReedSolomon<
    'a,
    const W: usize,
    F: RuntimeField<W> + core_algebra::SupportsU64Conversions,
    C: Convolver<W, F>,
> {
    f: &'a F,
    degree_bound: usize,
    m: usize,
    leading_constant: Vec<F::E>,
    binom_i: Vec<F::E>,
    c: C,
}

impl<
        'a,
        const W: usize,
        F: RuntimeField<W> + core_algebra::SupportsU64Conversions,
        C: Convolver<W, F>,
    > ReedSolomon<'a, W, F, C>
{
    /// n is the number of points provided
    /// m is the total number of points output (including the initial n points)
    pub fn new(n: usize, m: usize, f: &'a F, make_convolver: impl FnOnce(&[F::E]) -> C) -> Self {
        assert!(n > 0, "ReedSolomon requires n > 0");
        assert!(
            m >= n,
            "ReedSolomon requires m >= n (total points m must be >= input points n)"
        );
        let degree_bound = n - 1;
        // inverses[i] = 1/i from i = 1 to m-1 (inverses[0] = 0)
        let mut inverses = vec![f.zero(); m];
        AlgebraUtil::batch_inverse_arithmetic(m, &mut inverses, f);

        let c = make_convolver(&inverses);

        let mut leading_constant = vec![f.zero(); m - n + 1];
        let mut binom_i = vec![f.zero(); n];

        leading_constant[0] = f.one();
        binom_i[0] = f.one();

        // Set leading_constant[i] = (i + degree_bound) choose degree_bound
        // (from i=0 to i=m-n)
        let mut deg_val = f.u64_to_element((degree_bound + 1) as u64);
        let one = f.one();
        for i in 1..=(m - n) {
            let tmp = f.mulf(&deg_val, &inverses[i]);
            leading_constant[i] = f.mulf(&leading_constant[i - 1], &tmp);
            deg_val = f.addf(&deg_val, &one);
        }

        // Finish computing the leading constants:
        // (-1)^degree_bound * (k - degree_bound) * \binom{k}{degree_bound}
        let mut factor_val = f.zero();
        for k in degree_bound..m {
            let idx = k - degree_bound;
            leading_constant[idx] = f.mulf(&leading_constant[idx], &factor_val);
            if degree_bound % 2 == 1 {
                leading_constant[idx] = f.neg(&leading_constant[idx]);
            }
            factor_val = f.addf(&factor_val, &one);
        }

        // Compute binom_i[i] = \binom{n-1}{i}
        let mut binom_val = f.u64_to_element((n - 1) as u64);
        for i in 1..n {
            let tmp = f.mulf(&binom_val, &inverses[i]);
            binom_i[i] = f.mulf(&binom_i[i - 1], &tmp);
            binom_val = f.subf(&binom_val, &one);
        }
        // Incorporate (-1)^i signs into binom_i[i]
        for i in (1..n).step_by(2) {
            binom_i[i] = f.neg(&binom_i[i]);
        }

        Self {
            f,
            degree_bound,
            m,
            leading_constant,
            binom_i,
            c,
        }
    }
}

impl<
        const W: usize,
        F: RuntimeField<W> + core_algebra::SupportsU64Conversions,
        C: Convolver<W, F>,
    > crate::Interpolator<W, F> for ReedSolomon<'_, W, F, C>
{
    /// Given the values of a polynomial of degree at most n-1 at 0, 1, 2, ...,
    /// n-1, this computes the values at n, n+1, n+2, ..., m-1.
    /// (n points go in, m points come out)
    fn interpolate(&self, y: &mut [F::E]) {
        let n = self.degree_bound + 1;

        // Define x[i] = (-1)^i * \binom{n-1}{i} * p(i) for i=0 through n-1
        let mut x = vec![self.f.zero(); n];
        for i in 0..n {
            x[i] = self.f.mulf(&self.binom_i[i], &y[i]);
        }

        let mut t = vec![self.f.zero(); self.m];
        self.c.convolution(&x, &mut t);

        // Multiply the leading constants by the convolution result
        for i in n..self.m {
            y[i] = self
                .f
                .mulf(&self.leading_constant[i - self.degree_bound], &t[i]);
        }
    }
}

pub struct FftInterpolatorFactory<
    'a,
    const W: usize,
    const W2: usize,
    F: RuntimeField<W>
        + core_algebra::SupportsU64Conversions
        + crate::field::SupportsQuadraticExtension<W>,
> {
    f: &'a F,
    f2: &'a crate::fp2::Fp2Field<'a, W, W2, F>,
    omega: crate::fp2::Fp2Element<W, F>,
    omega_order: u64,
}

impl<
        'a,
        const W: usize,
        const W2: usize,
        F: RuntimeField<W>
            + core_algebra::SupportsU64Conversions
            + crate::field::SupportsQuadraticExtension<W>,
    > FftInterpolatorFactory<'a, W, W2, F>
{
    pub fn new(
        f: &'a F,
        f2: &'a crate::fp2::Fp2Field<'a, W, W2, F>,
        omega: crate::fp2::Fp2Element<W, F>,
        omega_order: u64,
    ) -> Self {
        Self {
            f,
            f2,
            omega,
            omega_order,
        }
    }
}

impl<
        'a,
        const W: usize,
        const W2: usize,
        F: RuntimeField<W>
            + core_algebra::SupportsU64Conversions
            + crate::field::SupportsQuadraticExtension<W>,
    > crate::interpolator::InterpolatorFactory<W, F> for FftInterpolatorFactory<'a, W, W2, F>
{
    type Interpolator = ReedSolomon<'a, W, F, crate::convolution::FFTExtConvolution<'a, W, W2, F>>;

    fn make(&self, ylen: usize, block_enc: usize) -> Self::Interpolator {
        ReedSolomon::new(ylen, block_enc, self.f, |inverses| {
            crate::convolution::FFTExtConvolution::new(
                ylen,
                block_enc,
                &self.omega,
                self.omega_order,
                inverses,
                self.f,
                self.f2,
            )
        })
    }

    fn can_encode(&self, ylen: usize, block_enc: usize) -> bool {
        // Multiplicative FFT interpolation uses polynomial convolution.
        // To prevent aliasing/wrap-around during the convolution of the input (len `ylen`)
        // with the interpolation kernel (len `block_enc`), the FFT size must be at least
        // `ylen + block_enc - 1`. The nearest power of two of this size cannot exceed
        // the order of the multiplicative group's largest power-of-two subgroup (`omega_order`).
        let fft_size = (ylen + block_enc - 1).next_power_of_two();
        (fft_size as u64) <= self.omega_order
    }
}
