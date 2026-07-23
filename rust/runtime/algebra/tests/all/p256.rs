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

use compile_algebra::p256::P256Field as P256CompileField;
use core_algebra::{
    AlgebraicField, Curve, Nat, SerializableField, SupportsNatConversions, SupportsU64Conversions,
};
use num_bigint::BigUint;
use runtime_algebra::{field::RuntimeSerializableField, p256::*, poly::InterpolationField};

#[test]
fn test_specific_mul() {
    let field = P256Field::new();
    let x: P256Element = field
        .words64_to_element(&[
            1993877568177495041,
            10345888787846536528,
            7746511691117935375,
            14517043990409914413,
        ])
        .unwrap();
    let inv = field.invert(&x);
    println!("SPECIFIC INV: {:?}", inv.0);
}

#[test]
fn test_specific_double() {
    let fr = P256Field::new();
    let curve = runtime_algebra::secp256r1::Secp256r1::new(&fr);
    let g_2d = curve.g();
    let g = core_algebra::ec::projective(&curve, &fr, g_2d);
    let g2 = core_algebra::ec::double(&curve, &fr, &g);
    let g2_normalized = core_algebra::ec::affine(&fr, &g2);
    println!("SPECIFIC DOUBLE X: {:?}", fr.to_bytes(&g2_normalized.0));
}

#[test]
fn test_runtime_double_vs_affine() {
    let fr = P256Field::new();
    let curve = runtime_algebra::secp256r1::Secp256r1::new(&fr);
    let g_2d = *curve.g();
    let g = core_algebra::ec::projective(&curve, &fr, &g_2d);
    let g2 = core_algebra::ec::double(&curve, &fr, &g);
    let g2_normalized = core_algebra::ec::affine(&fr, &g2);

    let g2_affine = {
        let (x, y) = &g_2d;
        let three = fr.addf(&fr.one(), &fr.addf(&fr.one(), &fr.one()));
        let two = fr.addf(&fr.one(), &fr.one());
        let x_sq = fr.mulf(x, x);
        let a_val = curve.a();
        let num = fr.addf(&fr.mulf(&three, &x_sq), a_val);
        let den = fr.mulf(&two, y);
        let lambda = fr.mulf(&num, &fr.invert(&den));
        let two_x = fr.mulf(&two, x);
        let x3 = fr.subf(&fr.mulf(&lambda, &lambda), &two_x);
        let y3 = fr.subf(&fr.mulf(&lambda, &fr.subf(x, &x3)), y);
        (x3, y3)
    };

    assert_eq!(g2_normalized.0, g2_affine.0);
    assert_eq!(g2_normalized.1, g2_affine.1);
}

#[test]
fn test_p256_optimized_vs_unoptimized() {
    let field_unopt = P256CompileField::new();
    let field_opt = P256Field::new();

    let inputs = vec![
        [0u8; 32],
        {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        },
        {
            let mut b = [0u8; 32];
            b[0] = 0xd2;
            b[1] = 0x02;
            b[2] = 0x96;
            b[3] = 0x49;
            b
        },
        [
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff,
        ],
    ];

    for b1 in &inputs {
        for b2 in &inputs {
            let e1_unopt = field_unopt.bytes_to_element(b1).unwrap();
            let e2_unopt = field_unopt.bytes_to_element(b2).unwrap();
            let res_unopt = field_unopt.addf(&e1_unopt, &e2_unopt);

            let e1_opt = field_opt.bytes_to_element(b1).unwrap();
            let e2_opt = field_opt.bytes_to_element(b2).unwrap();
            let res_opt = field_opt.addf(&e1_opt, &e2_opt);

            assert_eq!(
                field_unopt.to_bytes(&res_unopt),
                field_opt.to_bytes(&res_opt)
            );

            let res_unopt_sub = field_unopt.subf(&e1_unopt, &e2_unopt);
            let res_opt_sub = field_opt.subf(&e1_opt, &e2_opt);
            assert_eq!(
                field_unopt.to_bytes(&res_unopt_sub),
                field_opt.to_bytes(&res_opt_sub)
            );

            let res_unopt_mul = field_unopt.mulf(&e1_unopt, &e2_unopt);
            let res_opt_mul = field_opt.mulf(&e1_opt, &e2_opt);
            assert_eq!(
                field_unopt.to_bytes(&res_unopt_mul),
                field_opt.to_bytes(&res_opt_mul)
            );

            if !field_unopt.is_zero(&e1_unopt) {
                let res_unopt_inv = field_unopt.invert(&e1_unopt);
                let res_opt_inv = field_opt.invert(&e1_opt);
                assert_eq!(
                    field_unopt.to_bytes(&res_unopt_inv),
                    field_opt.to_bytes(&res_opt_inv)
                );
            }
        }
    }
}

#[test]
fn test_p256_reduce_nat() {
    let field = P256Field::new();
    let modulus = BigUint::parse_bytes(
        b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        16,
    )
    .unwrap();
    let limit = BigUint::from(1u32) << 256;
    let mut values = vec![
        BigUint::from(0u32),
        BigUint::from(1u32),
        &modulus - 1u32,
        modulus.clone(),
        &modulus + 1u32,
        &limit - 1u32,
    ];

    let mut state = 0xbb67_ae85_84ca_a73bu64;
    for _ in 0..512 {
        let mut words = [0u64; 4];
        for word in &mut words {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            *word = state;
        }
        let mut bytes = Vec::with_capacity(32);
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        values.push(BigUint::from_bytes_le(&bytes));
    }

    for value in values {
        let mut bytes = value.to_bytes_le();
        bytes.resize(32, 0);
        let nat = runtime_algebra::RuntimeNat::<4>::from_bytes_le(&bytes);
        let reduced = field.reduce_nat(&nat);
        assert_eq!(
            BigUint::from_bytes_le(&field.to_bytes(&reduced)),
            &value % &modulus,
            "incorrect P-256 reduction for {value}"
        );
    }
}

#[test]
fn test_precomputed_agrees_with_algebra() {
    let field_unopt = P256CompileField::new();
    let field_opt = P256Field::new();

    // Check poly_evaluation_points
    for i in 0..6 {
        let expected = field_unopt.u64_to_element(i as u64);
        assert_eq!(
            field_unopt.to_bytes(&expected),
            field_opt.to_bytes(&field_opt.poly_evaluation_point(i))
        );
    }

    // Check newton_denominators
    for i in 1..6 {
        let val = field_unopt.u64_to_element(i as u64);
        let expected_denom = field_unopt.invert(&val);
        for k in i..6 {
            assert_eq!(
                field_unopt.to_bytes(&expected_denom),
                field_opt.to_bytes(&field_opt.newton_denominator(k, i))
            );
        }
    }
}

#[test]
fn test_serialization() {
    let field = P256Field::new();
    let one = field.one();
    let bytes = field.to_bytes(&one);
    assert_eq!(bytes.len(), field.serialized_size_bytes());
}

struct SimpleRng(u64);
impl SimpleRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let val = self.next_u64();
            let val_bytes = val.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&val_bytes[..len]);
        }
    }
}

#[test]
fn test_p256_random_mul_robust() {
    let field_unopt = P256CompileField::new();
    let field_opt = P256Field::new();
    let mut rng = SimpleRng(0x123456789abcdef);

    for _ in 0..10000 {
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        rng.fill_bytes(&mut b1);
        rng.fill_bytes(&mut b2);

        let Ok(e1_unopt) = field_unopt.bytes_to_element(&b1) else {
            continue;
        };
        let Ok(e2_unopt) = field_unopt.bytes_to_element(&b2) else {
            continue;
        };

        let e1_opt = field_opt.bytes_to_element(&b1).unwrap();
        let e2_opt = field_opt.bytes_to_element(&b2).unwrap();

        // Test add
        let res_unopt_add = field_unopt.addf(&e1_unopt, &e2_unopt);
        let res_opt_add = field_opt.addf(&e1_opt, &e2_opt);
        assert_eq!(
            field_unopt.to_bytes(&res_unopt_add),
            field_opt.to_bytes(&res_opt_add)
        );

        // Test sub
        let res_unopt_sub = field_unopt.subf(&e1_unopt, &e2_unopt);
        let res_opt_sub = field_opt.subf(&e1_opt, &e2_opt);
        assert_eq!(
            field_unopt.to_bytes(&res_unopt_sub),
            field_opt.to_bytes(&res_opt_sub)
        );

        // Test mul
        let res_unopt_mul = field_unopt.mulf(&e1_unopt, &e2_unopt);
        let res_opt_mul = field_opt.mulf(&e1_opt, &e2_opt);
        assert_eq!(
            field_unopt.to_bytes(&res_unopt_mul),
            field_opt.to_bytes(&res_opt_mul)
        );

        // Test invert
        if !field_unopt.is_zero(&e1_unopt) {
            let res_unopt_inv = field_unopt.invert(&e1_unopt);
            let res_opt_inv = field_opt.invert(&e1_opt);
            assert_eq!(
                field_unopt.to_bytes(&res_unopt_inv),
                field_opt.to_bytes(&res_opt_inv)
            );
        }
    }
}
