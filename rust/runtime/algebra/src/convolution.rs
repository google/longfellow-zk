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

// All of the classes in this package compute convolutions.
// That is, given inputs arrays of field elements x, y, with |x|=n, |y|=m,
// these methods compute the first m entries of
//
//    z[k] = \sum_{i=0}^{n-1} x[i] y[k-i]
//
// SlowConvolution uses an O(n*m) method for testing validation.
//
// FFTConvolution and FFTExtConvolution first pad y to length n and use advanced
// FFT algorithms to compute the same in O(nlogn) time.

use crate::{
    fft,
    field::{RuntimeField, SupportsQuadraticExtension},
    rfft,
};

// Returns the smallest power of 2 that is at least n.
#[must_use]
pub fn choose_padding(n: usize) -> usize {
    n.next_power_of_two()
}

pub trait Convolver<const W: usize, F: RuntimeField<W>> {
    fn convolution(&self, x: &[F::E], z: &mut [F::E]);
}

pub struct FFTConvolution<
    'a,
    const W: usize,
    F: RuntimeField<W> + core_algebra::SupportsU64Conversions,
> {
    f: &'a F,
    omega: F::E,
    omega_order: u64,
    n: usize,
    m: usize,
    padding: usize,
    y_fft: Vec<F::E>,
}

impl<'a, const W: usize, F: RuntimeField<W> + core_algebra::SupportsU64Conversions>
    FFTConvolution<'a, W, F>
{
    pub fn new(n: usize, m: usize, omega: &F::E, omega_order: u64, y: &[F::E], f: &'a F) -> Self {
        let padding = choose_padding(m);
        let mut y_fft = vec![f.zero(); padding];
        y_fft[..m].clone_from_slice(y);
        fft::fftf(&mut y_fft, omega, omega_order, f);

        // Pre-scale Y by 1/N to compensate for the scaling in FFTB(FFTF(.))
        let inv_n = f.invert(&f.u64_to_element(padding as u64));
        for val in &mut y_fft {
            f.mul(val, &inv_n);
        }

        Self {
            f,
            omega: omega.clone(),
            omega_order,
            n,
            m,
            padding,
            y_fft,
        }
    }
}

impl<const W: usize, F: RuntimeField<W> + core_algebra::SupportsU64Conversions> Convolver<W, F>
    for FFTConvolution<'_, W, F>
{
    // Computes (first m entries of) convolution of x with y, outputs in z:
    // z[k] = \sum_{i=0}^{n-1} x[i] y[k-i].
    // Note that y has already been FFT'd and divided by padding_ in
    // constructor.
    fn convolution(&self, x: &[F::E], z: &mut [F::E]) {
        assert_eq!(x.len(), self.n);
        assert_eq!(z.len(), self.m);
        let mut x_fft = vec![self.f.zero(); self.padding];
        x_fft[..self.n].clone_from_slice(x);
        fft::fftf(&mut x_fft, &self.omega, self.omega_order, self.f);

        // Pointwise multiplication
        for (xi, yi) in x_fft.iter_mut().zip(&self.y_fft).take(self.padding) {
            self.f.mul(xi, yi);
        }

        // Backward FFT
        fft::fftb(&mut x_fft, &self.omega, self.omega_order, self.f);
        z.clone_from_slice(&x_fft[..self.m]);
    }
}

pub struct FFTExtConvolution<
    'a,
    const W: usize,
    F: SupportsQuadraticExtension<W> + core_algebra::SupportsU64Conversions,
> {
    f: &'a F,
    f_ext: &'a crate::fp2::Fp2Field<'a, W, F>,
    omega: crate::fp2::Fp2Element<W, F>,
    omega_order: u64,
    n: usize,
    m: usize,
    padding: usize,
    y_fft: Vec<F::E>,
}

impl<
        'a,
        const W: usize,
        F: SupportsQuadraticExtension<W> + core_algebra::SupportsU64Conversions,
    > FFTExtConvolution<'a, W, F>
{
    pub fn new(
        n: usize,
        m: usize,
        omega: &crate::fp2::Fp2Element<W, F>,
        omega_order: u64,
        y: &[F::E],
        f: &'a F,
        f_ext: &'a crate::fp2::Fp2Field<'a, W, F>,
    ) -> Self {
        let padding = choose_padding(m);
        let mut y_fft = vec![f.zero(); padding];
        y_fft[..m].clone_from_slice(y);
        rfft::r2hc(&mut y_fft, omega, omega_order, f_ext);

        // Pre-scale Y by 1/N to compensate for the scaling in HC2R(R2HC(.))
        let inv_n = f.invert(&f.u64_to_element(padding as u64));
        for val in &mut y_fft {
            f.mul(val, &inv_n);
        }

        Self {
            f,
            f_ext,
            omega: omega.clone(),
            omega_order,
            n,
            m,
            padding,
            y_fft,
        }
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W> + core_algebra::SupportsU64Conversions>
    Convolver<W, F> for FFTExtConvolution<'_, W, F>
{
    // Computes (first m entries of) convolution of x with y, stores in z:
    // z[k] = \sum_{i=0}^{n-1} x[i] y[k-i].
    // Note that y has already been FFT'd and divided by padding_ in
    // constructor.
    fn convolution(&self, x: &[F::E], z: &mut [F::E]) {
        assert_eq!(x.len(), self.n);
        assert_eq!(z.len(), self.m);
        let mut x_fft = vec![self.f.zero(); self.padding];
        x_fft[..self.n].clone_from_slice(x);
        rfft::r2hc(&mut x_fft, &self.omega, self.omega_order, self.f_ext);

        // Pointwise multiplication
        self.f.mul(&mut x_fft[0], &self.y_fft[0]); // DC is real
        let nyquist = self.padding / 2;
        let (x_left, x_right) = x_fft.split_at_mut(nyquist);
        let (y_left, y_right) = self.y_fft.split_at(nyquist);

        let x_l = &mut x_left[1..nyquist];
        let x_r = &mut x_right[1..nyquist];
        let y_l = &y_left[1..nyquist];
        let y_r = &y_right[1..nyquist];

        for (((xl, xr), yl), yr) in x_l
            .iter_mut()
            .zip(x_r.iter_mut().rev())
            .zip(y_l.iter())
            .zip(y_r.iter().rev())
        {
            rfft::cmul::<W, F>(xl, xr, yl, yr, self.f);
        }
        self.f.mul(&mut x_fft[nyquist], &self.y_fft[nyquist]); // Nyquist is real

        // Backward FFT
        rfft::hc2r(&mut x_fft, &self.omega, self.omega_order, self.f_ext);
        z.clone_from_slice(&x_fft[..self.m]);
    }
}
