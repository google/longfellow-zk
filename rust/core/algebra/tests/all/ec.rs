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

use core_algebra::{ec::*, nat::Nat, AlgebraicField, BareField, Curve, ElementOf};
use num_bigint::BigUint;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct TestNat(BigUint);

impl Nat<4> for TestNat {
    fn to_bytes_le(&self) -> Vec<u8> {
        let mut bytes = self.0.to_bytes_le();
        bytes.resize(32, 0);
        bytes
    }
    fn from_bytes_le(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            32,
            "TestNat::from_bytes_le: invalid bytes length"
        );
        Self(BigUint::from_bytes_le(bytes))
    }
    fn to_limbs(&self) -> [u64; 4] {
        let mut bytes = self.0.to_bytes_le();
        bytes.resize(32, 0);
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        limbs
    }
    fn from_limbs(limbs: &[u64; 4]) -> Self {
        let mut bytes = vec![0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
        Self(BigUint::from_bytes_le(&bytes))
    }
    fn from_u64(val: u64) -> Self {
        Self(BigUint::from(val))
    }
    fn bit(&self, i: usize) -> bool {
        ((&self.0 >> i) & BigUint::from(1u32)) == BigUint::from(1u32)
    }
    fn to_bits(&self, n: usize) -> Vec<bool> {
        (0..n).map(|i| self.bit(i)).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Elt17(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct F17;

impl BareField for F17 {
    type E = Elt17;
}

impl AlgebraicField for F17 {
    fn zero(&self) -> Self::E {
        Elt17(0)
    }
    fn one(&self) -> Self::E {
        Elt17(1)
    }
    fn add(&self, a: &mut Self::E, b: &Self::E) {
        a.0 = (a.0 + b.0) % 17;
    }
    fn sub(&self, a: &mut Self::E, b: &Self::E) {
        a.0 = (a.0 + 17 - b.0) % 17;
    }
    fn mul(&self, a: &mut Self::E, b: &Self::E) {
        a.0 = (a.0 * b.0) % 17;
    }
    fn invert(&self, a: &Self::E) -> Self::E {
        assert!(a.0 != 0, "Division by zero");
        for i in 1..17 {
            if (a.0 * i) % 17 == 1 {
                return Elt17(i);
            }
        }
        unreachable!()
    }
}

struct Curve17 {
    a: Elt17,
    b: Elt17,
    g: (Elt17, Elt17),
}

impl Curve<4> for Curve17 {
    type F = F17;
    type N = TestNat;
    fn order(&self) -> Self::N {
        TestNat(BigUint::from(18u32))
    }
    fn a(&self) -> &ElementOf<Self::F> {
        &self.a
    }
    fn b(&self) -> &ElementOf<Self::F> {
        &self.b
    }
    fn g(&self) -> &(ElementOf<Self::F>, ElementOf<Self::F>) {
        &self.g
    }
}

// Helper to check if a point is on the curve: y^2 == x^3 + a*x + b
fn is_on_curve(curve: &Curve17, f: F17, p: &Pt3<F17>) -> bool {
    let (x, y, z) = p;
    if z.0 == 0 {
        // Point at infinity (0, 1, 0)
        return x.0 == 0 && y.0 == 1;
    }
    // Convert to affine coordinates first for simplicity
    let (ax, ay) = affine(&f, p);
    let lhs = f.mulf(&ay, &ay);
    let rhs = f.addf(
        &f.mulf(&ax, &f.mulf(&ax, &ax)),
        &f.addf(&f.mulf(curve.a(), &ax), curve.b()),
    );
    lhs == rhs
}

fn assert_eq_pts(f: F17, p1: &Pt3<F17>, p2: &Pt3<F17>) {
    let is_inf1 = p1.2 .0 == 0;
    let is_inf2 = p2.2 .0 == 0;
    assert_eq!(is_inf1, is_inf2, "Infinity mismatch");
    if !is_inf1 {
        let a1 = affine(&f, p1);
        let a2 = affine(&f, p2);
        assert_eq!(a1, a2, "Affine coordinates mismatch");
    }
}

#[test]
fn test_mock_field_properties() {
    let f = F17;
    assert_eq!(f.addf(&Elt17(5), &Elt17(13)), Elt17(1));
    assert_eq!(f.subf(&Elt17(5), &Elt17(13)), Elt17(9));
    assert_eq!(f.mulf(&Elt17(5), &Elt17(13)), Elt17(14));
    assert_eq!(f.invert(&Elt17(5)), Elt17(7));
    assert_eq!(f.mone(), Elt17(16));
    assert!(f.is_zero(&Elt17(0)));
    assert!(!f.is_zero(&Elt17(5)));
}

#[test]
fn test_ec_properties() {
    let f = F17;
    let curve = Curve17 {
        a: Elt17(3),
        b: Elt17(5),
        g: (Elt17(1), Elt17(3)), // 3^2 = 9. 1^3 + 3*1 + 5 = 9.
    };

    let g_proj = projective(&curve, &f, curve.g());
    assert!(is_on_curve(&curve, f, &g_proj));

    let inf = zero(&f);
    assert!(is_on_curve(&curve, f, &inf));

    // identity tests: P + 0 = P, 0 + P = P
    assert_eq_pts(f, &add(&curve, &f, &g_proj, &inf), &g_proj);
    assert_eq_pts(f, &add(&curve, &f, &inf, &g_proj), &g_proj);
    assert_eq_pts(f, &add(&curve, &f, &inf, &inf), &inf);

    // doubling tests
    let g2 = double(&curve, &f, &g_proj);
    assert!(is_on_curve(&curve, f, &g2));
    assert_eq_pts(f, &add(&curve, &f, &g_proj, &g_proj), &g2);

    // doubling of infinity
    assert_eq_pts(f, &double(&curve, &f, &inf), &inf);

    // add distinct points: G + 2G = 3G
    let g3 = add(&curve, &f, &g_proj, &g2);
    assert!(is_on_curve(&curve, f, &g3));

    // scalar multiplication tests
    let g3_mul = scalar_mul(&curve, &f, 3, &TestNat::from_u64(3), &g_proj);
    assert_eq_pts(f, &g3, &g3_mul);

    // scalar multiplication by 0
    assert_eq_pts(
        f,
        &scalar_mul(&curve, &f, 1, &TestNat::from_u64(0), &g_proj),
        &inf,
    );

    // scalar multiplication of infinity
    assert_eq_pts(
        f,
        &scalar_mul(&curve, &f, 5, &TestNat::from_u64(5), &inf),
        &inf,
    );

    // scalar_mul_bytes test
    let mut bytes = [0u8; 32];
    bytes[0] = 3;
    let g3_mul_bytes = scalar_mul_bytes(&curve, &f, &bytes, &g_proj);
    assert_eq_pts(f, &g3, &g3_mul_bytes);

    // additive inverses: P + (-P) = inf
    // For affine point (x, y), inverse is (x, -y).
    // g = (1, 3). neg_g = (1, -3) = (1, 14).
    let neg_g_proj = projective(&curve, &f, &(Elt17(1), Elt17(14)));
    assert!(is_on_curve(&curve, f, &neg_g_proj));
    assert_eq_pts(f, &add(&curve, &f, &g_proj, &neg_g_proj), &inf);
}
