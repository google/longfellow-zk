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
    field::{AlgebraicField, RuntimeField},
    gf2_128::{Gf2_128, Gf2_128RuntimeField},
    lch14::*,
    lch14_reed_solomon::{Lch14InterpolatorFactory, Lch14ReedSolomon},
    subfield::BinarySubfield,
    InterpolatorFactory,
};

fn w_ref(f: &Gf2_128RuntimeField, subfield: &BinarySubfield, i: usize, x: &Gf2_128) -> Gf2_128 {
    let mut prod = f.one();
    for j in 0..(1 << i) {
        let j_elt = subfield.embed(j as u64);
        prod = f.mulf(&prod, &f.subf(x, &j_elt));
    }
    prod
}

fn w_hat_ref(f: &Gf2_128RuntimeField, subfield: &BinarySubfield, i: usize, x: &Gf2_128) -> Gf2_128 {
    let numer = w_ref(f, subfield, i, x);
    let denom = w_ref(f, subfield, i, &subfield.embed(1 << i));
    f.mulf(&numer, &f.invert(&denom))
}

#[test]
fn test_w_additivity() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let r = 6;
    for i in 0..r {
        for x in 0..(1 << r) {
            let xx = subfield.embed(x as u64);
            let wx = w_ref(&f, &subfield, i, &xx);

            if x < (1 << i) {
                assert_eq!(wx, f.zero());
            } else {
                assert_ne!(wx, f.zero());
            }

            for y in 0..(1 << r) {
                let yy = subfield.embed(y as u64);
                let sum_xy = f.addf(&xx, &yy);
                assert_eq!(
                    w_ref(&f, &subfield, i, &sum_xy),
                    f.addf(&w_ref(&f, &subfield, i, &xx), &w_ref(&f, &subfield, i, &yy))
                );
            }
        }
    }
}

#[test]
fn test_w_recursion() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let r = 6;
    for i in 0..r {
        let wibi = w_ref(&f, &subfield, i, &subfield.embed(1 << i));
        for x in 0..(1 << r) {
            let xx = subfield.embed(x as u64);
            let wix = w_ref(&f, &subfield, i, &xx);
            let wi1x = w_ref(&f, &subfield, i + 1, &xx);
            assert_eq!(wi1x, f.mulf(&wix, &f.addf(&wix, &wibi)));
        }
    }
}

#[test]
fn test_w_hat() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let fft = Lch14::new(&f, &subfield);
    let dimension_subfield = subfield.dimension();
    // Limit i for fast test run
    for i in 0..std::cmp::min(dimension_subfield, 8) {
        for j in 0..dimension_subfield {
            assert_eq!(
                fft.w_hat(i, j).clone(),
                w_hat_ref(&f, &subfield, i, &subfield.embed(1 << j))
            );
        }
    }
}

#[test]
fn test_twiddle() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let fft = Lch14::new(&f, &subfield);
    let l = 8;
    let mut tw = vec![f.zero(); 1 << (l - 1)];
    for i in 0..l {
        fft.twiddles(i, l, 0, &mut tw);
        for (u, tw_val) in tw.iter().enumerate().take(1 << (l - 1 - i)) {
            let expected = fft.twiddle(i, u << (i + 1));
            assert_eq!(*tw_val, expected);
        }
    }
}

#[test]
fn test_fft_ifft_roundtrip() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let fft = Lch14::new(&f, &subfield);
    let l = 6;
    let n = 1 << l;
    let mut b = vec![f.zero(); n];
    for (i, b_val) in b.iter_mut().enumerate().take(n) {
        *b_val = subfield.embed((i * i + 42) as u64);
    }

    let original = b.clone();
    fft.fft(l, 0, &mut b);
    assert_ne!(b, original);

    fft.ifft(l, 0, &mut b);
    assert_eq!(b, original);
}

#[test]
fn test_bidirectional_fft() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let fft = Lch14::new(&f, &subfield);
    let l = 6;
    let n = 1 << l;

    for k in 0..=n {
        let mut c = vec![f.zero(); n];
        let mut e = vec![f.zero(); n];
        for i in 0..n {
            e[i] = subfield.embed((i * i + 42) as u64);
            c[i] = e[i];
        }

        fft.fft(l, 0, &mut e);

        let mut b = vec![f.zero(); n];
        for i in 0..n {
            b[i] = if i < k { e[i] } else { c[i] };
        }

        fft.bidirectional_fft(l, k, &mut b);

        for i in 0..n {
            let expected = if i < k { c[i] } else { e[i] };
            assert_eq!(b[i], expected);
        }
    }
}

fn newton_of_lagrange<const W: usize, F: RuntimeField<W>>(
    f: &F,
    a: &[F::E],
    x: &[F::E],
) -> Vec<F::E> {
    let n = a.len();
    assert_eq!(x.len(), n);
    let mut c = a.to_vec();
    for i in 1..n {
        for k in (i..n).rev() {
            let dx = f.subf(&x[k], &x[k - i]);
            let inv_dx = f.invert(&dx);
            let diff = f.subf(&c[k], &c[k - 1]);
            c[k] = f.mulf(&diff, &inv_dx);
        }
    }
    c
}

fn eval_newton<const W: usize, F: RuntimeField<W>>(
    f: &F,
    c: &[F::E],
    x: &[F::E],
    point: &F::E,
) -> F::E {
    let n = c.len();
    let mut sum = f.zero();
    let mut term = f.one();
    for i in 0..n {
        sum = f.addf(&sum, &f.mulf(&c[i], &term));
        term = f.mulf(&term, &f.subf(point, &x[i]));
    }
    sum
}

#[test]
fn test_lch14_interpolation() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let fft = Lch14::new(&f, &subfield);

    const L: usize = 5;
    const COSETS: usize = 7;
    const N: usize = 1 << L;

    // check interpolations from all cosets CA to all cosets CB
    for ca in 0..COSETS {
        let mut x = Vec::with_capacity(N);
        let mut a = Vec::with_capacity(N);
        for i in 0..N {
            x.push(subfield.embed((i + (ca << L)) as u64));
            a.push(subfield.embed(((i * (i + ca)) ^ 42) as u64));
        }

        let newton = newton_of_lagrange(&f, &a, &x);

        let mut a_fft = a.clone();
        fft.ifft(L, ca << L, &mut a_fft);

        for cb in 0..COSETS {
            let mut b = a_fft.clone();
            fft.fft(L, cb << L, &mut b);

            for (i, b_val) in b.iter().enumerate().take(N) {
                let point = subfield.embed((i + (cb << L)) as u64);
                let expected = eval_newton(&f, &newton, &x, &point);
                assert_eq!(*b_val, expected);
            }
        }
    }
}

#[test]
fn test_lch14_interpolator_rejects_invalid_dimensions() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let factory = Lch14InterpolatorFactory::new(&f, &subfield);
    let capacity = 1 << subfield.dimension();

    assert!(!factory.can_encode(0, 1));
    assert!(!factory.can_encode(2, 1));
    assert!(factory.can_encode(1, 1));
    assert!(factory.can_encode(capacity, capacity));
    assert!(!factory.can_encode(capacity, capacity + 1));

    assert!(std::panic::catch_unwind(|| Lch14ReedSolomon::new(0, 1, &f, &subfield)).is_err());
    assert!(std::panic::catch_unwind(|| Lch14ReedSolomon::new(2, 1, &f, &subfield)).is_err());
    assert!(std::panic::catch_unwind(|| {
        Lch14ReedSolomon::new(capacity, capacity + 1, &f, &subfield)
    })
    .is_err());
}
