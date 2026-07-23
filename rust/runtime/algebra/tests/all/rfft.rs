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

use runtime_algebra::{
    fft::fftb,
    field::SupportsU64Conversions,
    fp2::{Fp2Element, Fp2Field},
    p256::P256Field,
    rfft::{hc2r, r2hc},
    AlgebraicField, SupportsFFT,
};

#[test]
fn test_rfft_vs_fft() {
    let p256 = P256Field::new();
    let fp2: Fp2Field<'_, 4, 8, _> = Fp2Field::new(&p256);

    let omega0 = fp2.omega();
    let omega_order = fp2.omega_order();

    let mut omega = omega0;
    for _iter in 0..2 {
        let conj: Fp2Element<4, P256Field> = Fp2Element {
            re: omega.re,
            im: p256.neg(&omega.im),
        };
        assert_eq!(fp2.mulf(&omega, &conj), fp2.one());

        for n in [2, 4, 8, 16, 32, 64, 128, 256, 512] {
            let mut ar0 = Vec::with_capacity(n);
            let mut ar1 = Vec::with_capacity(n);
            let mut ac = Vec::with_capacity(n);
            for i in 0..n {
                let val = (i * i * i + (i & 0xF) + (i ^ (i << 2))) as u64;
                let el = p256.u64_to_element(val);
                ar0.push(el);
                ar1.push(el);
                ac.push(Fp2Element {
                    re: el,
                    im: p256.zero(),
                });
            }

            // Compare RFFT (r2hc) against FFT (fftb)
            fftb(&mut ac, &omega, omega_order, &fp2);
            r2hc::<4, 8, P256Field>(&mut ar0, &omega, omega_order, &fp2);

            for i in 0..n {
                if i + i <= n {
                    assert_eq!(
                        ar0[i], ac[i].re,
                        "Forward RFFT real part mismatch at index {i} for n={n}"
                    );
                } else {
                    assert_eq!(
                        ar0[i], ac[i].im,
                        "Forward RFFT imag part mismatch at index {i} for n={n}"
                    );
                }
            }

            // Invert and compare against original input scaled by n
            hc2r::<4, 8, P256Field>(&mut ar0, &omega, omega_order, &fp2);
            let scale = p256.u64_to_element(n as u64);
            for i in 0..n {
                assert_eq!(
                    ar0[i],
                    p256.mulf(&scale, &ar1[i]),
                    "Backward RFFT scaled mismatch at index {i} for n={n}"
                );
            }
        }

        let mut omega0_pow4 = omega0;
        for _ in 0..3 {
            omega0_pow4 = fp2.mulf(&omega0_pow4, &omega0);
        }
        omega = fp2.mulf(&omega, &omega0_pow4);
    }
}
