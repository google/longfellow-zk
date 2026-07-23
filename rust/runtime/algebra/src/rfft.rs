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

// Real FFT and its inverse.
//
// The FFT F[j] of a real input R[k] is complex and
// conjugate-symmetric: F[j] = conj(F[n - j]).
//
// Following the FFTW conventions, to avoid doubling the
// storage, we store F[j] as a "half-complex" array HC[j] of elements
// in the base field.
//
//   HC[j] = (2j <= n) ? real(F[j]) : imag(F[n - j])
//
// Thus we have two kinds of transforms: R2HC (real to
// half-complex) and HC2R (half-complex to real).
//
// Again following the FFTW conventions, we say that
// the R2HC transform is "forward" (minus sign in the exponent)
// and the HC2R sign is "backward" (plus sign in the exponent).
// See fft.rs for a definition of forward and backward.
//
// ------------------------------------------------------------
// Main algorithm details:
//
// The overall algorithm is a radix-4 Cooley-Tukey FFT.  Generally
// speaking, Cooley-Tukey decomposes a problem of size N into R
// subproblems of size N/R and N/R subproblems of size R, where R is
// called the "radix".  For quadratic field extensions, R=4 is
// better than R=2 because one can hardcode a size-4 FFT requiring
// no multiplications, as multiplying by the fourth root of unity I
// is free.  This is true as long as I^2 = -1, which we assume.
//
// The main complexity of the code is due to the fact that the input
// is in the base field of the quadratic extension (henceforth we
// say that the input is "real").  Under this assumption, the output
// C is in the extension field ("complex"), but it is conjugate
// symmetric C[n-i] = conj(C[j]), so it has only n degrees of
// freedom and not 2n.  Note that C[0] is real and, for even n,
// C[n/2] is also real.
//
// Because the output is conjugate symmetric, we can compute the FFT
// of a real input of size N by doing a complex FFT of size N/2 and
// then doing some cheap post-processing.  This is the standard way
// to compute real FFTs.
//
// However, here we choose to implement a *native* real FFT.  This
// means that we run the Cooley-Tukey algorithm directly on the real
// input.  At the leaves of the recursion, we do real FFTs of size 2
// or 4.  During the recursion, we merge the outputs of the
// subproblems.
//
// The recursion step merges 4 real inputs of size M into a real
// input of size 4M.  The merging requires multiplying by the
// twiddle factors.  Because the input is real, the twiddle factors
// have conjugate symmetries, which we exploit to reduce the number
// of multiplications.
//
// The native real FFT is slightly more complex to implement than the
// N/2 complex FFT approach, but it has some advantages:
// 1. It is slightly faster because it avoids the post-processing pass.
// 2. It is more symmetric and easier to parallelize.
//
// The native real FFT algorithm is described in:
// "A new native real-path FFT algorithm" by Sorensen et al. (1987).
//
// We follow the Sorensen algorithm, but we adapt it to radix 4.
// Sorensen's algorithm is described for radix 2, but radix 4 is a
// straightforward generalization.
//
// The Sorensen algorithm is decimation-in-frequency (Sande-Tukey).
// We use decimation-in-time (Cooley-Tukey) because it is easier to
// implement in-place.
//
// In Cooley-Tukey decimation-in-time, the input is permuted (bit-reversed)
// and then merged.  For real FFT, the permutation is slightly different
// because the input is real and the output is half-complex.
// Specifically, the input is permuted in a way that is compatible
// with the half-complex layout.  This permutation is called
// "real bit-reversal".
//
// In our implementation, we choose to do the bit-reversal on the
// input.  This is in-place and very fast.
//
// For the backward transform (HC2R), the input is half-complex and
// the output is real.  The algorithm is the exact transpose of the
// forward transform.  Because the input is half-complex, the merging
// steps are different.  The leaf transforms are also different.
// The permutation at the end is the inverse of the real bit-reversal,
// which is also done in-place.
//
// The Sorensen radix-2 decimation-in-time algorithm is described in
// "Real-valued fast Fourier transform algorithms" by Duhamel (1986).
// Our radix-4 decimation-in-time algorithm is a novel generalization.
//
// Note on signs:
// Sorensen's paper uses the opposite sign convention than FFTW.
// We follow the FFTW convention.
//
// ------------------------------------------------------------
// Layout of the half-complex array:
//
// Let n be the size of the transform.
// The input R is a real array of size n.
// The output F is a complex array of size n, conjugate symmetric.
// We store F in a real array A of size n as follows:
//
//   A[0] = F[0].re
//   A[1] = F[1].re
//   ...
//   A[n/2] = F[n/2].re
//   A[n/2 + 1] = F[n/2 - 1].im
//   ...
//   A[n - 1] = F[1].im
//
// This is the "half-complex" layout.  Note that F[0] and F[n/2] are
// real, so we only need to store their real parts.  The imaginary
// parts of F[j] for 0 < j < n/2 are stored in the second half of
// the array, in reverse order.
//
// The leaf transforms (size 2 and 4) are implemented in-place on
// this layout.
//
// The merging steps are also implemented in-place.
// ------------------------------------------------------------

use crate::{
    field::{AlgebraicField, SupportsQuadraticExtension},
    fp2::{Fp2Element, Fp2Field},
};

pub struct Twiddle<const W: usize, F: SupportsQuadraticExtension<W>> {
    pub order: usize,
    pub w: Vec<Fp2Element<W, F>>,
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> Twiddle<W, F> {
    pub fn new(
        order: usize,
        omega_order: &Fp2Element<W, F>,
        field_ext: &Fp2Field<'_, W, F>,
    ) -> Self {
        let mut w = Vec::with_capacity(order / 2);
        let mut curr = field_ext.one();
        for _ in 0..(order / 2) {
            w.push(curr.clone());
            field_ext.mul(&mut curr, omega_order);
        }
        Self { order, w }
    }

    pub fn reroot(
        omega_n: &Fp2Element<W, F>,
        n: u64,
        mut r: u64,
        field_ext: &Fp2Field<'_, W, F>,
    ) -> Fp2Element<W, F> {
        let mut omega_r = omega_n.clone();
        while r < n {
            let tmp = omega_r.clone();
            field_ext.mul(&mut omega_r, &tmp);
            r += r;
        }
        omega_r
    }
}

pub fn bitrev<T>(a: &mut [T]) {
    let n = a.len();
    let mut revi = 0;
    for i in 0..(n - 1) {
        if i < revi {
            a.swap(i, revi);
        }
        let mut bit = n;
        loop {
            bit >>= 1;
            revi ^= bit;
            if (revi & bit) != 0 {
                break;
            }
        }
    }
}

#[cfg(debug_assertions)]
// The machinery in this file only works if the root is
// on the unit circle, because we multiply by the conjugate
// instead of by the inverse.
fn validate_root<const W: usize, F: SupportsQuadraticExtension<W>>(
    omega: &Fp2Element<W, F>,
    c: &Fp2Field<'_, W, F>,
) {
    let conj = Fp2Element {
        re: omega.re.clone(),
        im: c.base_field().neg(&omega.im),
    };
    assert_eq!(
        c.mulf(omega, &conj),
        c.one(),
        "root of unity not on the unit circle"
    );
}

#[cfg(debug_assertions)]
// The machinery in this file only works if omega^{n/4} == (0, 1)
// (== c.i()) as opposed to the conjugate (0, -1).  There is nothing
// wrong with c.conj(c.i()), but we hardcode the positive sign
// in all the radix-4 butterflies.
fn validate_i<const W: usize, F: SupportsQuadraticExtension<W>>(
    ii: &Fp2Element<W, F>,
    c: &Fp2Field<'_, W, F>,
) {
    assert_eq!(ii, &c.i(), "wrong sign for i(), need the conjugate root");
}

#[cfg(debug_assertions)]
// We hardcode w8.re == w8.im for 8th-roots of unity.
// This always holds if p mod 8 == 7, in which case the
// 8-th root is the usual +/- (1+i)/sqrt(2), assuming w8^2 = I
// (as opposed to -I).
fn validate_w8<const W: usize, F: SupportsQuadraticExtension<W>>(w8: &Fp2Element<W, F>) {
    assert_eq!(w8.re, w8.im, "wrong 8-th root of unity");
}

pub fn cmul<const W: usize, F: SupportsQuadraticExtension<W>>(
    xr: &mut F::E,
    xi: &mut F::E,
    br: &F::E,
    bi: &F::E,
    r: &F,
) {
    let mut a01 = xr.clone();
    r.add(&mut a01, xi);
    let mut b01 = br.clone();
    r.add(&mut b01, bi);

    let mut p1 = xi.clone();
    r.mul(&mut p1, bi);

    r.mul(xr, br);
    r.mul(&mut a01, &b01);
    r.sub(&mut a01, xr);
    r.sub(&mut a01, &p1);

    r.sub(xr, &p1);
    *xi = a01;
}

fn cmul_conj<const W: usize, F: SupportsQuadraticExtension<W>>(
    xr: &mut F::E,
    xi: &mut F::E,
    br: &F::E,
    bi: &F::E,
    r: &F,
) {
    let mut a01 = xr.clone();
    r.add(&mut a01, xi);
    let mut b01 = br.clone();
    r.sub(&mut b01, bi);

    let mut p1 = xi.clone();
    r.mul(&mut p1, bi);

    r.mul(xr, br);
    r.mul(&mut a01, &b01);
    r.sub(&mut a01, xr);
    r.add(&mut a01, &p1);

    r.add(xr, &p1);
    *xi = a01;
}

// r2hcI_2() implements a real->half-complex FFT of size 2.
fn r2hc_i_2<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx: usize,
    s: usize,
    r: &F,
) {
    let t = a[idx + s].clone();
    a[idx + s] = a[idx].clone();
    r.sub(&mut a[idx + s], &t);
    r.add(&mut a[idx], &t);
}

// r2hcI_4() implements a real->half-complex FFT of size 4.
fn r2hc_i_4<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx: usize,
    s: usize,
    r: &F,
) {
    let x1 = a[idx + s].clone();
    let x3 = a[idx + 3 * s].clone();

    a[idx + s] = a[idx].clone();
    r.sub(&mut a[idx + s], &x1);
    r.add(&mut a[idx], &x1);

    let x2 = a[idx + 2 * s].clone();
    a[idx + 3 * s] = x3.clone();
    r.sub(&mut a[idx + 3 * s], &x2);
    r.add(&mut a[idx + 2 * s], &x3);

    let z1 = a[idx + 2 * s].clone();
    a[idx + 2 * s] = a[idx].clone();
    r.sub(&mut a[idx + 2 * s], &z1);
    r.add(&mut a[idx], &z1);
}

// j = m/2 butterfly in the main loop, where w8^2 = I
fn r2hc_ii_4<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx: usize,
    s: usize,
    w8: &Fp2Element<W, F>,
    r: &F,
) {
    let x1 = a[idx + s].clone();
    let x2 = a[idx + 2 * s].clone();
    let x3 = a[idx + 3 * s].clone();

    let mut z0_val = x2.clone();
    r.add(&mut z0_val, &x3);
    r.mul(&mut z0_val, &w8.im);

    let mut z1_val = x2;
    r.sub(&mut z1_val, &x3);
    r.mul(&mut z1_val, &w8.re);

    let x0 = a[idx].clone();
    a[idx + s] = x0;
    r.sub(&mut a[idx + s], &z1_val);
    r.add(&mut a[idx], &z1_val);

    a[idx + 3 * s] = x1.clone();
    r.add(&mut a[idx + 3 * s], &z0_val);
    a[idx + 3 * s] = r.neg(&a[idx + 3 * s]);

    a[idx + 2 * s] = x1;
    r.sub(&mut a[idx + 2 * s], &z0_val);
}

#[allow(clippy::too_many_arguments)]
fn hc2hc_f_4<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx_r: usize,
    idx_i: usize,
    s: usize,
    tw1: &Fp2Element<W, F>,
    tw2: &Fp2Element<W, F>,
    tw3: &Fp2Element<W, F>,
    r: &F,
) {
    let x0r = a[idx_r].clone();
    let x0i = a[idx_i].clone();
    let mut x1r = a[idx_r + s].clone();
    let mut x1i = a[idx_i + s].clone();
    let mut x2r = a[idx_r + 2 * s].clone();
    let mut x2i = a[idx_i + 2 * s].clone();
    let mut x3r = a[idx_r + 3 * s].clone();
    let mut x3i = a[idx_i + 3 * s].clone();

    cmul_conj(&mut x1r, &mut x1i, &tw2.re, &tw2.im, r);
    cmul_conj(&mut x2r, &mut x2i, &tw1.re, &tw1.im, r);
    cmul_conj(&mut x3r, &mut x3i, &tw3.re, &tw3.im, r);

    let mut y0r = x0r.clone();
    r.add(&mut y0r, &x1r);
    let mut y0i = x0i.clone();
    r.add(&mut y0i, &x1i);
    let mut y1r = x0r;
    r.sub(&mut y1r, &x1r);
    let mut y1i = x0i;
    r.sub(&mut y1i, &x1i);

    let mut y2r = x3r.clone();
    r.add(&mut y2r, &x2r);
    let mut y3r = x3r;
    r.sub(&mut y3r, &x2r);
    let mut y2i = x2i.clone();
    r.add(&mut y2i, &x3i);
    let mut y3i = x2i;
    r.sub(&mut y3i, &x3i);

    a[idx_r] = y0r.clone();
    r.add(&mut a[idx_r], &y2r);
    a[idx_i + s] = y0r;
    r.sub(&mut a[idx_i + s], &y2r);

    a[idx_r + s] = y1r.clone();
    r.add(&mut a[idx_r + s], &y3i);
    a[idx_i] = y1r;
    r.sub(&mut a[idx_i], &y3i);

    a[idx_i + 3 * s] = y2i.clone();
    r.add(&mut a[idx_i + 3 * s], &y0i);
    a[idx_r + 2 * s] = y2i;
    r.sub(&mut a[idx_r + 2 * s], &y0i);

    a[idx_i + 2 * s] = y3r.clone();
    r.add(&mut a[idx_i + 2 * s], &y1i);
    a[idx_r + 3 * s] = y3r;
    r.sub(&mut a[idx_r + 3 * s], &y1i);
}

// hc2rI_2: half-complex->real backward transform of size 2.
fn hc2r_i_2<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx: usize,
    s: usize,
    r: &F,
) {
    let t = a[idx + s].clone();
    a[idx + s] = a[idx].clone();
    r.sub(&mut a[idx + s], &t);
    r.add(&mut a[idx], &t);
}

// hc2rI_4: half-complex->real backward transform of size 4.
fn hc2r_i_4<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx: usize,
    s: usize,
    r: &F,
) {
    let mut y0 = a[idx].clone();
    r.add(&mut y0, &a[idx + 2 * s]);
    let mut y1 = a[idx].clone();
    r.sub(&mut y1, &a[idx + 2 * s]);
    let mut y2 = a[idx + s].clone();
    r.add(&mut y2, &a[idx + s]);
    let mut y3 = a[idx + 3 * s].clone();
    r.add(&mut y3, &a[idx + 3 * s]);

    a[idx] = y0.clone();
    r.add(&mut a[idx], &y2);
    a[idx + s] = y0;
    r.sub(&mut a[idx + s], &y2);
    a[idx + 2 * s] = y1.clone();
    r.sub(&mut a[idx + 2 * s], &y3);
    a[idx + 3 * s] = y1;
    r.add(&mut a[idx + 3 * s], &y3);
}

// hc2rIII_4: half-complex->real backward transform with w_8^j twiddle factors.
fn hc2r_iii_4<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx: usize,
    s: usize,
    w8: &Fp2Element<W, F>,
    r: &F,
) {
    let mut x0 = a[idx].clone();
    r.add(&mut x0, &a[idx]);
    let mut x1 = a[idx + s].clone();
    r.add(&mut x1, &a[idx + s]);
    let mut x2 = a[idx + 2 * s].clone();
    r.add(&mut x2, &a[idx + 2 * s]);
    let mut x3 = a[idx + 3 * s].clone();
    r.add(&mut x3, &a[idx + 3 * s]);

    let mut a0 = x0.clone();
    r.add(&mut a0, &x1);
    let mut as_val = x2.clone();
    r.sub(&mut as_val, &x3);

    let mut z0 = x0;
    r.sub(&mut z0, &x1);
    r.mul(&mut z0, &w8.re);
    let mut z1 = x3;
    r.add(&mut z1, &x2);
    r.mul(&mut z1, &w8.im);

    let mut a2 = z0.clone();
    r.sub(&mut a2, &z1);
    let mut a3 = z0;
    r.add(&mut a3, &z1);
    a3 = r.neg(&a3);

    a[idx] = a0;
    a[idx + s] = as_val;
    a[idx + 2 * s] = a2;
    a[idx + 3 * s] = a3;
}

// hc2hcb_4(): the main complex->complex backward butterfly.
#[allow(clippy::too_many_arguments)]
fn hc2hc_b_4<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    idx_r: usize,
    idx_i: usize,
    s: usize,
    tw1: &Fp2Element<W, F>,
    tw2: &Fp2Element<W, F>,
    tw3: &Fp2Element<W, F>,
    r: &F,
) {
    let mut x0r = a[idx_r].clone();
    let mut x0i = a[idx_i].clone();
    let mut x1r = a[idx_r + s].clone();
    let mut x1i = a[idx_i + s].clone();
    let mut x2r = a[idx_r + 2 * s].clone();
    let mut x2i = a[idx_i + 2 * s].clone();
    let mut x3r = a[idx_r + 3 * s].clone();
    let mut x3i = a[idx_i + 3 * s].clone();

    let mut z0 = x0r.clone();
    r.add(&mut z0, &x1i);
    let mut z1 = x0r.clone();
    r.sub(&mut z1, &x1i);
    let mut z2 = x1r.clone();
    r.add(&mut z2, &x0i);
    let mut z3 = x1r;
    r.sub(&mut z3, &x0i);
    let mut z4 = x3i.clone();
    r.add(&mut z4, &x2r);
    let mut z5 = x3i.clone();
    r.sub(&mut z5, &x2r);
    let mut z6 = x2i.clone();
    r.add(&mut z6, &x3r);
    let mut z7 = x2i;
    r.sub(&mut z7, &x3r);

    x0r = z0.clone();
    r.add(&mut x0r, &z2);
    x0i = z5.clone();
    r.add(&mut x0i, &z7);
    x1r = z0;
    r.sub(&mut x1r, &z2);
    x1i = z5;
    r.sub(&mut x1i, &z7);

    cmul(&mut x1r, &mut x1i, &tw2.re, &tw2.im, r);

    x2r = z1.clone();
    r.sub(&mut x2r, &z6);
    x2i = z4.clone();
    r.add(&mut x2i, &z3);

    cmul(&mut x2r, &mut x2i, &tw1.re, &tw1.im, r);

    x3r = z1;
    r.add(&mut x3r, &z6);
    x3i = z4;
    r.sub(&mut x3i, &z3);

    cmul(&mut x3r, &mut x3i, &tw3.re, &tw3.im, r);

    a[idx_r] = x0r;
    a[idx_i] = x0i;
    a[idx_r + s] = x1r;
    a[idx_i + s] = x1i;
    a[idx_r + 2 * s] = x2r;
    a[idx_i + 2 * s] = x2i;
    a[idx_r + 3 * s] = x3r;
    a[idx_i + 3 * s] = x3i;
}

pub fn r2hc<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    omega: &Fp2Element<W, F>,
    omega_order: u64,
    c: &Fp2Field<'_, W, F>,
) {
    let n = a.len();
    let r = c.base_field();
    #[cfg(debug_assertions)]
    validate_root(omega, c);

    if n == 2 {
        r2hc_i_2(a, 0, 1, r);
    } else if n >= 4 {
        let omega_n = Twiddle::<W, F>::reroot(omega, omega_order, n as u64, c);
        let roots = Twiddle::<W, F>::new(n, &omega_n, c);
        #[cfg(debug_assertions)]
        validate_i(&roots.w[n / 4], c);
        #[cfg(debug_assertions)]
        if n >= 8 {
            validate_w8(&roots.w[n / 8]);
        }
        bitrev(a);

        let mut m = n;
        while m > 4 {
            m /= 4;
        }

        if m == 2 {
            for chunk in a.chunks_exact_mut(2) {
                r2hc_i_2(chunk, 0, 1, r);
            }
        } else {
            for chunk in a.chunks_exact_mut(4) {
                r2hc_i_4(chunk, 0, 1, r);
            }
        }

        let mut current_m = if m == 2 { 2 } else { 4 };
        while current_m < n {
            let ws = n / (4 * current_m);
            for chunk in a.chunks_exact_mut(4 * current_m) {
                r2hc_i_4(chunk, 0, current_m, r); // j==0

                for j in 1..(current_m / 2) {
                    hc2hc_f_4(
                        chunk,
                        j,
                        current_m - j,
                        current_m,
                        &roots.w[j * ws],
                        &roots.w[2 * j * ws],
                        &roots.w[3 * j * ws],
                        r,
                    );
                }

                r2hc_ii_4(
                    chunk,
                    current_m / 2,
                    current_m,
                    &roots.w[(current_m / 2) * ws],
                    r,
                ); // j==m/2
            }
            current_m *= 4;
        }
    }
}

pub fn hc2r<const W: usize, F: SupportsQuadraticExtension<W>>(
    a: &mut [F::E],
    omega: &Fp2Element<W, F>,
    omega_order: u64,
    c: &Fp2Field<'_, W, F>,
) {
    let n = a.len();
    let r = c.base_field();
    #[cfg(debug_assertions)]
    validate_root(omega, c);

    if n == 2 {
        hc2r_i_2(a, 0, 1, r);
    } else if n >= 4 {
        let omega_n = Twiddle::<W, F>::reroot(omega, omega_order, n as u64, c);
        let roots = Twiddle::<W, F>::new(n, &omega_n, c);
        #[cfg(debug_assertions)]
        validate_i(&roots.w[n / 4], c);
        #[cfg(debug_assertions)]
        if n >= 8 {
            validate_w8(&roots.w[n / 8]);
        }

        let mut m = n;
        while m > 4 {
            m /= 4;
            let ws = n / (4 * m);
            for chunk in a.chunks_exact_mut(4 * m) {
                hc2r_i_4(chunk, 0, m, r); // j==0

                for j in 1..(m / 2) {
                    hc2hc_b_4(
                        chunk,
                        j,
                        m - j,
                        m,
                        &roots.w[j * ws],
                        &roots.w[2 * j * ws],
                        &roots.w[3 * j * ws],
                        r,
                    );
                }

                hc2r_iii_4(chunk, m / 2, m, &roots.w[(m / 2) * ws], r); // j==m/2
            }
        }

        if m == 2 {
            for chunk in a.chunks_exact_mut(2) {
                hc2r_i_2(chunk, 0, 1, r);
            }
        } else {
            for chunk in a.chunks_exact_mut(4) {
                hc2r_i_4(chunk, 0, 1, r);
            }
        }

        bitrev(a);
    }
}
