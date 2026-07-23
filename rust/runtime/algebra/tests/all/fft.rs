use core_algebra::{SerializableField, SupportsU64Conversions};
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
    fft::*,
    field::RuntimeField,
    fp2::{Fp2Element, Fp2Field},
    p256::P256Field,
    AlgebraicField,
};

fn get_test_field_and_omega(
    p256: &P256Field,
) -> (Fp2Field<'_, 4, P256Field>, Fp2Element<4, P256Field>, u64) {
    let f: Fp2Field<'_, 4, _> = Fp2Field::new(p256);
    let re_bytes = [
        98, 37, 36, 75, 50, 101, 90, 152, 76, 74, 42, 56, 59, 86, 201, 159, 55, 227, 144, 121, 198,
        133, 252, 92, 102, 245, 132, 189, 142, 51, 13, 249,
    ];
    let im_bytes = [
        172, 62, 164, 96, 79, 23, 244, 219, 198, 50, 210, 116, 100, 138, 115, 132, 64, 227, 6, 1,
        226, 194, 79, 160, 77, 204, 151, 188, 66, 30, 232, 185,
    ];
    let omega = Fp2Element {
        re: p256.bytes_to_element(&re_bytes).unwrap(),
        im: p256.bytes_to_element(&im_bytes).unwrap(),
    };
    (f, omega, 1 << 31)
}

struct SimplePrg {
    state: u64,
}

impl SimplePrg {
    fn new() -> Self {
        Self { state: 42 }
    }
    fn next<const W: usize, F: RuntimeField<W> + core_algebra::SupportsU64Conversions>(
        &mut self,
        f: &F,
    ) -> F::E {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        f.u64_to_element(self.state)
    }
}

#[test]
fn test_fft_inverse() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);
    let mut prg = SimplePrg::new();

    for power in 0..8 {
        let n = 1 << power;
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        for _ in 0..n {
            let val = prg.next(&f);
            a.push(val);
            b.push(val);
        }

        fftf(&mut a, &omega, omega_order, &f);
        fftb(&mut a, &omega, omega_order, &f);

        let inv_n = f.invert(&f.u64_to_element(n as u64));
        for i in 0..n {
            a[i] = f.mulf(&a[i], &inv_n);
            assert_eq!(a[i], b[i]);
        }
    }
}

#[test]
fn test_fft_linearity() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);
    let mut prg = SimplePrg::new();

    for power in 0..8 {
        let n = 1 << power;
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        let mut c = Vec::with_capacity(n);

        let k0 = prg.next(&f);
        let k1 = prg.next(&f);

        for _ in 0..n {
            let av = prg.next(&f);
            let bv = prg.next(&f);
            let cv = f.addf(&f.mulf(&k0, &av), &f.mulf(&k1, &bv));
            a.push(av);
            b.push(bv);
            c.push(cv);
        }

        fftf(&mut a, &omega, omega_order, &f);
        fftf(&mut b, &omega, omega_order, &f);
        fftf(&mut c, &omega, omega_order, &f);

        for i in 0..n {
            let expected = f.addf(&f.mulf(&k0, &a[i]), &f.mulf(&k1, &b[i]));
            assert_eq!(c[i], expected);
        }
    }
}

#[test]
fn test_fft_shift() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);
    let mut prg = SimplePrg::new();

    for power in 1..8 {
        let n = 1 << power;
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        let mut c = Vec::with_capacity(n);

        let omega_n = Twiddle::reroot(&omega, omega_order, n as u64, &f);
        let k0 = prg.next(&f);
        let k1 = prg.next(&f);

        for _ in 0..n {
            a.push(prg.next(&f));
            b.push(prg.next(&f));
        }

        for i in 0..n {
            let shifted_a = &a[(i + 1) % n];
            let cv = f.addf(&f.mulf(&k0, shifted_a), &f.mulf(&k1, &b[i]));
            c.push(cv);
        }

        fftb(&mut a, &omega, omega_order, &f);
        fftb(&mut b, &omega, omega_order, &f);
        fftb(&mut c, &omega, omega_order, &f);

        let mut w = f.one();
        for i in 0..n {
            let lhs = f.addf(&f.mulf(&k0, &a[i]), &f.mulf(&f.mulf(&k1, &b[i]), &w));
            let rhs = f.mulf(&w, &c[i]);
            assert_eq!(lhs, rhs);
            w = f.mulf(&w, &omega_n);
        }
    }
}

#[test]
fn test_fft_impulse() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);

    for power in 0..8 {
        let n = 1 << power;
        let mut a = Vec::with_capacity(n);
        for i in 0..n {
            a.push(if i == 0 { f.one() } else { f.zero() });
        }

        fftf(&mut a, &omega, omega_order, &f);

        for (i, a_val) in a.iter().enumerate().take(n) {
            assert_eq!(*a_val, f.one(), "Impulse response mismatch at index {i}");
        }
    }
}

#[test]
fn test_fft_step_linearity() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);
    let mut prg = SimplePrg::new();

    for power in 0..8 {
        let n = 1 << power;
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        let mut c = Vec::with_capacity(n);

        let k0 = prg.next(&f);
        let k1 = prg.next(&f);

        for i in 0..n {
            let av = if i == 0 { f.zero() } else { f.one() };
            let bv = prg.next(&f);
            let cv = f.addf(&f.mulf(&k0, &av), &f.mulf(&k1, &bv));
            a.push(av);
            b.push(bv);
            c.push(cv);
        }

        fftf(&mut a, &omega, omega_order, &f);
        fftf(&mut b, &omega, omega_order, &f);
        fftf(&mut c, &omega, omega_order, &f);

        for i in 0..n {
            let expected = f.addf(&f.mulf(&k0, &a[i]), &f.mulf(&k1, &b[i]));
            assert_eq!(c[i], expected);
        }
    }
}

#[test]
fn test_fft_impulse_addition() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);
    let mut prg = SimplePrg::new();

    for power in 0..8 {
        let n = 1 << power;
        let mut x = Vec::with_capacity(n);
        let mut y = Vec::with_capacity(n);

        for i in 0..n {
            let xv = prg.next(&f);
            let impulse = if i == 0 { f.one() } else { f.zero() };
            let yv = f.addf(&xv, &impulse);
            x.push(xv);
            y.push(yv);
        }

        fftf(&mut x, &omega, omega_order, &f);
        fftf(&mut y, &omega, omega_order, &f);

        for i in 0..n {
            let expected = f.addf(&x[i], &f.one());
            assert_eq!(y[i], expected, "Impulse addition mismatch at index {i}");
        }
    }
}

#[test]
fn test_fft_rejects_invalid_orders() {
    let p256 = P256Field::new();
    let (f, omega, _) = get_test_field_and_omega(&p256);

    for (len, root_order) in [(0, 8), (3, 8), (4, 3), (4, 2)] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut values = vec![f.zero(); len];
                fftb(&mut values, &omega, root_order, &f);
            }))
            .is_err(),
            "accepted FFT length {len} with root order {root_order}"
        );
    }
}
