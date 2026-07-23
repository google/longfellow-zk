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
    field::{AlgebraicField, RuntimeField, SupportsFFT, SupportsU64Conversions},
    fp2::Fp2Field,
    middle_product::MiddleProduct,
    p256::P256Field,
    reed_solomon::*,
    Interpolator, InterpolatorFactory,
};

struct SlowMiddleProduct<const W: usize, F: RuntimeField<W>> {
    f: F,
    y: Vec<F::E>,
}

impl<const W: usize, F: RuntimeField<W>> MiddleProduct<W, F> for SlowMiddleProduct<W, F> {
    fn middle_product(&self, x: &[F::E], z: &mut [F::E]) {
        let n = x.len();
        let m = z.len();
        for (k, z_val) in z.iter_mut().enumerate().take(m).skip(n - 1) {
            let mut s = self.f.zero();
            for (i, x_val) in x.iter().enumerate().take(n) {
                if k >= i && (k - i) < self.y.len() {
                    let term = self.f.mulf(x_val, &self.y[k - i]);
                    s = self.f.addf(&s, &term);
                }
            }
            *z_val = s;
        }
    }
}

#[test]
fn test_reed_solomon_slow() {
    let f = P256Field::new();

    let n = 5;
    let m = 10;

    let mut y = vec![
        f.u64_to_element(1),
        f.u64_to_element(2),
        f.u64_to_element(5),
        f.u64_to_element(10),
        f.u64_to_element(17),
        f.zero(),
        f.zero(),
        f.zero(),
        f.zero(),
        f.zero(),
    ];

    let rs = ReedSolomon::<4, _, _>::new(n, m, &f, |inverses| SlowMiddleProduct {
        f: f.clone(),
        y: inverses.to_vec(),
    });

    rs.interpolate(&mut y);

    let expected = [
        f.u64_to_element(26),
        f.u64_to_element(37),
        f.u64_to_element(50),
        f.u64_to_element(65),
        f.u64_to_element(82),
    ];

    for i in 0..5 {
        assert_eq!(y[n + i], expected[i], "Mismatch at index {}", n + i);
    }
}

#[test]
fn test_fft_interpolator_can_encode_middle_product() {
    let f = P256Field::new();
    let f2: Fp2Field<'_, 4, _> = Fp2Field::new(&f);
    let omega = <Fp2Field<'_, 4, P256Field> as SupportsFFT<4>>::omega(&f2);
    let omega_order = <Fp2Field<'_, 4, P256Field> as SupportsFFT<4>>::omega_order(&f2);
    let factory = FftInterpolatorFactory::new(&f, &f2, omega, omega_order);

    assert!(!factory.can_encode(0, 2));
    assert!(!factory.can_encode(3, 2));
    assert!(!factory.can_encode(1, 1));
    assert!(factory.can_encode(1, 2));

    let max_size = usize::try_from(omega_order).unwrap();
    assert!(factory.can_encode(max_size, max_size));
    assert!(!factory.can_encode(max_size, max_size + 1));
}
