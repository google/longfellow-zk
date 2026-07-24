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

use circuits_bit_plucker::{encoding_point, BitPlucker};
use circuits_boolean::Boolean;
use compile_algebra::{
    field::{CompileField, SupportsU64Conversions},
    gf2_128::Gf2_128Field,
    p256::P256Field,
};
use compile_logic::{eval::EvalLogic, Logic};

fn compare_bool<L: Logic>(boolean: &Boolean<L>, want: bool, got: &circuits_boolean::Bitw<L>)
where compile_logic::Eltw<L>: PartialEq + std::fmt::Debug {
    let got_val = boolean.as_eltw(got);
    let want_val = boolean.as_eltw(&boolean.konst(want));
    assert_eq!(got_val, want_val);
}

fn compare_bitvec<L: Logic, const N: usize>(
    boolean: &Boolean<L>,
    want: u64,
    got: &circuits_bitvec::Bitvec<L, N>,
) where
    compile_logic::Eltw<L>: PartialEq + std::fmt::Debug,
{
    for i in 0..N {
        let want_bit = ((want >> i) & 1) == 1;
        compare_bool(boolean, want_bit, got.bit(i));
    }
}

fn run_bit_plucker_eval_tests<const W: usize, F: CompileField>(f: &F) {
    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(f, &tracker);
    let boolean = Boolean::new(&l);

    let plucker = BitPlucker::<_, 2>::new(&l);

    // Test pluck:
    for v in 0..4 {
        let point_val = encoding_point::<_, 2>(f, v);
        let point_eltw = l.konst(&point_val);

        let plucked = plucker.pluck(&point_eltw);
        compare_bitvec(&boolean, v as u64, &plucked);
    }

    // Test unpack:
    // v0 = 1 (bits: true, false)
    // v1 = 2 (bits: false, true)
    // v2 = 3 (bits: true, true)
    let p0 = encoding_point::<_, 2>(f, 1);
    let p1 = encoding_point::<_, 2>(f, 2);
    let p2 = encoding_point::<_, 2>(f, 3);

    let input_slice = [l.konst(&p0), l.konst(&p1), l.konst(&p2)];
    let unpacked = plucker.unpack::<6>(&input_slice);

    // Reconstructed 6-bit value = 1 | (2 << 2) | (3 << 4) = 57
    compare_bitvec(&boolean, 57, &unpacked);
}

fn run_bit_plucker_invalid_points_test<const W: usize, F: CompileField + SupportsU64Conversions>(
    f: &F,
    max_test_range: usize,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(f, &tracker);
    let boolean = Boolean::new(&l);

    let plucker = BitPlucker::<_, 2>::new(&l);

    // Valid points for LOGN = 2:
    let valid_points = [
        encoding_point::<_, 2>(f, 0),
        encoding_point::<_, 2>(f, 1),
        encoding_point::<_, 2>(f, 2),
        encoding_point::<_, 2>(f, 3),
    ];

    // Test a range of elements to verify that invalid points fail assertions
    let mut passing_invalid_points = Vec::new();
    for u in 0..max_test_range {
        let val = f.u64_to_element(u as u64);
        let is_valid = valid_points.contains(&val);

        let eltw = l.konst(&val);
        let plucked = plucker.pluck(&eltw);

        let mut has_error = false;
        for bit in plucked.as_array() {
            let bit_eltw = boolean.as_eltw(bit);
            if bit_eltw
                .assertions
                .values()
                .any(|s| matches!(s, compile_logic::scope::AssertionStatus::Failed(_)))
            {
                has_error = true;
            }
        }

        if is_valid {
            assert!(!has_error, "Valid point {u} failed assertions!");
        } else if !has_error {
            passing_invalid_points.push(u);
        }
    }

    assert!(
        passing_invalid_points.is_empty(),
        "Plucker security vulnerability: some invalid points passed assertions without failure: {passing_invalid_points:?}"
    );
}

#[test]
fn test_bit_plucker_eval_bin() {
    let f = Gf2_128Field::new();
    run_bit_plucker_eval_tests::<2, _>(&f);
}

#[test]
fn test_bit_plucker_eval_prime() {
    let f = P256Field::new();
    run_bit_plucker_eval_tests::<4, _>(&f);
}

#[test]
fn test_bit_plucker_invalid_points_bin() {
    let f = Gf2_128Field::new();
    // Test the entire GF(2^16) subfield
    run_bit_plucker_invalid_points_test::<2, _>(&f, 65536);
}

#[test]
fn test_bit_plucker_invalid_points_prime() {
    let f = P256Field::new();
    // Test a sample of 1000 elements for the prime field
    run_bit_plucker_invalid_points_test::<4, _>(&f, 1000);
}
