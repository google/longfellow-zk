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

use circuits_bitvec::{concrete::push_bitvec_u128, Bitvec, BitvecIO, BitvecLogic};
use circuits_boolean::Boolean;
use circuits_gf2_128::Gf2_128Mul;
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use core_algebra::{ElementOf, SerializableField};

fn ref_mul(x: u128, y: u128) -> u128 {
    let poly: u128 = 0x87;
    let mut a: u128 = 0;
    let mut y_shift = y;
    for _ in 0..128 {
        let msb = (a & (1 << 127)) != 0;
        a <<= 1;
        if msb {
            a ^= poly;
        }
        if (y_shift & (1 << 127)) != 0 {
            a ^= x;
        }
        y_shift <<= 1;
    }
    a
}

use compile_eval::FieldID;
use runtime_algebra::field::RuntimeField;

fn test_compile_gf2_128_mul_for_field<
    const W: usize,
    FC: CompileField + SerializableField,
    FR: RuntimeField<W> + SerializableField,
>(
    fc: &FC,
    fr: &FR,
    name: &str,
    field_id: FieldID,
    expected_stats: compile_eval::CircuitGeometry,
) {
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);
    let bv = BitvecLogic::new(&iologic);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let bitvec_io = BitvecIO::new(&bv);
    let a = bitvec_io.next::<128>(&mut pos);
    let b = bitvec_io.next::<128>(&mut pos);

    let mul_circuit = Gf2_128Mul::new(&iologic);
    let c = mul_circuit.mul(&a, &b);

    let target = bitvec_io.next::<128>(&mut pos);
    let assertion = bv.assert_eq("c_eq_target", &c, &target);

    // Compile!
    let (circuit, stats, symbols) = compile_compiler::top::compile(&arena, fc, assertion, 1, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);
    assert_eq!(stats, expected_stats);

    // Evaluate in compiled mode!
    let mut inputs = compile_eval::initial_inputs(fr);

    let x = 0x123456789abcdef0123456789abcdef0u128;
    let y = 0x0f0e0d0c0b0a09080706050403020100u128;
    let target_val = ref_mul(x, y);

    push_bitvec_u128(fr, x, 128, &mut inputs);
    push_bitvec_u128(fr, y, 128, &mut inputs);
    push_bitvec_u128(fr, target_val, 128, &mut inputs);

    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_gf2_128_mul() {
    let fc_bin = Gf2_128Field::new();
    let fr_bin = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_gf2_128_mul_for_field(
        &fc_bin,
        &fr_bin,
        "gf2_128_mul_bin",
        FieldID::Gf2_128,
        compile_eval::CircuitGeometry {
            ninput: 385,
            npublic_input: 1,
            noutput: 385,
            nwires: 1811,
            nterms: 10306,
            nlayers: 2,
            nassertions: 385,
        },
    );

    let fc_prime = P256Field::new();
    let fr_prime = runtime_algebra::p256::P256Field::new();
    test_compile_gf2_128_mul_for_field(
        &fc_prime,
        &fr_prime,
        "gf2_128_mul_prime",
        FieldID::P256,
        compile_eval::CircuitGeometry {
            ninput: 385,
            npublic_input: 1,
            noutput: 1,
            nwires: 19645,
            nterms: 27869,
            nlayers: 19,
            nassertions: 385,
        },
    );
}

use compile_logic::{eval::EvalLogic, Logic};

fn u128_to_bitvec<L: Logic>(logic: &L, val: u128) -> Bitvec<L, 128> {
    let boolean = Boolean::new(logic);
    let mut bits = Vec::with_capacity(128);
    for i in 0..128 {
        bits.push(boolean.konst(((val >> i) & 1) == 1));
    }
    Bitvec::new(bits)
}

fn field_elt_to_u128<F: CompileField + SerializableField>(f: &F, e: &ElementOf<F>) -> u128 {
    let bytes = f.to_bytes(e);
    let mut padded = [0u8; 16];
    let len = std::cmp::min(bytes.len(), 16);
    padded[..len].copy_from_slice(&bytes[..len]);
    u128::from_le_bytes(padded)
}

fn eval_logic_to_u128<'a, F: CompileField + SerializableField>(
    f: &F,
    boolean: &Boolean<'_, EvalLogic<'a, F>>,
    bv: &Bitvec<EvalLogic<'a, F>, 128>,
) -> u128 {
    let mut val: u128 = 0;
    for i in 0..128 {
        let bit = bv.bit(i);
        let eltw = boolean.as_eltw(bit);
        let bit_val = field_elt_to_u128(f, &eltw.value);
        if bit_val == 1 {
            val |= 1 << i;
        }
    }
    val
}

fn test_gf2_128_mul_basic_for_field<F: CompileField + SerializableField>(f: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(f);
    let boolean = Boolean::new(&l);

    let mul_circuit = Gf2_128Mul::new(&l);

    // Test simple identity: 1 * 1 = 1
    let a1 = u128_to_bitvec(&l, 1);
    let b1 = u128_to_bitvec(&l, 1);
    let c1 = mul_circuit.mul(&a1, &b1);
    assert_eq!(eval_logic_to_u128(f, &boolean, &c1), 1);

    // Test 2 * 2 = 4 (representing x * x = x^2)
    let a2 = u128_to_bitvec(&l, 2);
    let b2 = u128_to_bitvec(&l, 2);
    let c2 = mul_circuit.mul(&a2, &b2);
    assert_eq!(eval_logic_to_u128(f, &boolean, &c2), 4);
}

fn test_gf2_128_mul_random_for_field<F: CompileField + SerializableField>(f: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(f);
    let boolean = Boolean::new(&l);

    let mul_circuit = Gf2_128Mul::new(&l);

    let test_cases = vec![
        (
            0x123456789abcdef0123456789abcdef0u128,
            0x0f0e0d0c0b0a09080706050403020100u128,
        ),
        (1, 0x80000000000000000000000000000000u128),
        (0x80000000000000000000000000000000u128, 2),
        (0xdeadbeefu128, 0x123456789abcdefu128),
    ];

    for (x, y) in test_cases {
        let expected = ref_mul(x, y);

        let a = u128_to_bitvec(&l, x);
        let b = u128_to_bitvec(&l, y);
        let c = mul_circuit.mul(&a, &b);

        let got = eval_logic_to_u128(f, &boolean, &c);
        assert_eq!(
            got, expected,
            "Multiplication mismatch for inputs {x:x} and {y:x}"
        );
    }
}

#[test]
fn test_gf2_128_mul_basic() {
    let f_bin = Gf2_128Field::new();
    test_gf2_128_mul_basic_for_field(&f_bin);

    let f_prime = P256Field::new();
    test_gf2_128_mul_basic_for_field(&f_prime);
}

#[test]
fn test_gf2_128_mul_random() {
    let f_bin = Gf2_128Field::new();
    test_gf2_128_mul_random_for_field(&f_bin);

    let f_prime = P256Field::new();
    test_gf2_128_mul_random_for_field(&f_prime);
}
