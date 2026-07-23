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

use circuits_bitvec::BitvecLogic;
use circuits_experimental::sha3::{
    concrete::{self, keccak_f_1600_trajectory, ConcreteGiven},
    Sha3,
};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::FieldID;
use core_algebra::SerializableField;
use runtime_algebra::field::RuntimeField;

fn test_compile_keccak_f_1600_for_field<
    'a,
    const W: usize,
    FC: CompileField + SerializableField,
    FR: RuntimeField<W> + SerializableField,
>(
    fc: &'a FC,
    fr: &'a FR,
    name: &str,
    field_id: FieldID,
    expected_stats: compile_eval::CircuitGeometry,
) {
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let sha3 = Sha3::new(&iologic);
    let given = circuits_experimental::sha3::allocate_given(&sha3.bv, &mut pos);
    let derived = circuits_experimental::sha3::allocate_derived(&sha3.bv, &mut pos);

    let assertion = sha3.assert_circuit(&given, &derived);

    let (circuit, stats, symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);

    assert_eq!(stats, expected_stats);

    // Initialize state 0 values
    let mut s0 = [[0u64; 5]; 5];
    for (x, row) in s0.iter_mut().enumerate() {
        for (y, val) in row.iter_mut().enumerate() {
            *val = ((x * 5 + y) as u64 + 1) * 0x123456789abcdef;
        }
    }

    let concrete_given = ConcreteGiven { initial_state: s0 };
    let concrete_derived = concrete::derived(&concrete_given);

    let mut inputs = compile_eval::initial_inputs(fr);
    concrete_given.push_wires(fr, &mut inputs);
    concrete_derived.push_wires(fr, &mut inputs);

    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();
}

fn test_compile_keccak_f_1600_unrolled_for_field<
    'a,
    const W: usize,
    FC: CompileField + SerializableField,
    FR: RuntimeField<W> + SerializableField,
>(
    fc: &'a FC,
    fr: &'a FR,
    name: &str,
    field_id: FieldID,
) {
    use circuits_bitvec::BitvecIO;
    use circuits_experimental::sha3::State;

    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);
    let bv = BitvecLogic::new(&iologic);
    let bitvec_io = BitvecIO::new(&bv);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    // Input state 0 and expected final state 24 as inputs (Public)
    let s0: State<_> = std::array::from_fn(|_x| std::array::from_fn(|_y| bitvec_io.next(&mut pos)));
    let s24_expected: State<_> =
        std::array::from_fn(|_x| std::array::from_fn(|_y| bitvec_io.next(&mut pos)));

    // Compute the circuit transition internally
    let sha3 = Sha3::new(&iologic);
    let s24_without_iota = sha3.keccak_f_1600_without_final_iota(&s0);

    let mut rhs = s24_expected.clone();
    let rc = circuits_experimental::sha3::constants::ROUNDC[23];
    let boolean = circuits_boolean::Boolean::new(&iologic);
    rhs[0][0] = sha3.bv.from_fn(|idx| {
        let bit = s24_expected[0][0].bit(idx);
        if (rc.checked_shr(idx as u32).unwrap_or(0) & 1) != 0 {
            boolean.notb(bit)
        } else {
            bit.clone()
        }
    });

    let assertion = sha3.assert_eq_state(&s24_without_iota, &rhs);

    let (circuit, stats, symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);

    // Initial state 0 concrete values
    let mut s0_val = [[0u64; 5]; 5];
    for (x, row) in s0_val.iter_mut().enumerate() {
        for (y, val) in row.iter_mut().enumerate() {
            *val = ((x * 5 + y) as u64 + 1) * 0x123456789abcdef;
        }
    }

    let rust_states = keccak_f_1600_trajectory(s0_val);
    let s24_val = rust_states[24];

    let mut inputs = compile_eval::initial_inputs(fr);
    for row in &s0_val {
        for &val in row {
            circuits_bitvec::concrete::push_bitvec_u64(fr, val, 64, &mut inputs);
        }
    }
    for row in &s24_val {
        for &val in row {
            circuits_bitvec::concrete::push_bitvec_u64(fr, val, 64, &mut inputs);
        }
    }

    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_keccak_f_1600() {
    let gf2_c = Gf2_128Field::new();
    let gf2_r = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_keccak_f_1600_for_field::<2, _, _>(
        &gf2_c,
        &gf2_r,
        "keccak_f_1600_gf2_128",
        FieldID::Gf2_128,
        compile_eval::CircuitGeometry {
            ninput: 40001,
            npublic_input: 0,
            noutput: 40600,
            nlayers: 2,
            nwires: 119601,
            nterms: 696625,
            nassertions: 40600,
        },
    );
    let p256_c = P256Field::new();
    let p256_r = runtime_algebra::p256::P256Field::new();
    test_compile_keccak_f_1600_for_field::<4, _, _>(
        &p256_c,
        &p256_r,
        "keccak_f_1600_p256",
        FieldID::P256,
        compile_eval::CircuitGeometry {
            ninput: 40001,
            npublic_input: 0,
            noutput: 600,
            nlayers: 7,
            nwires: 429806,
            nterms: 738606,
            nassertions: 40600,
        },
    );
}

#[test]
fn test_compile_keccak_f_1600_unrolled() {
    let gf2_c = Gf2_128Field::new();
    let gf2_r = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_keccak_f_1600_unrolled_for_field::<2, _, _>(
        &gf2_c,
        &gf2_r,
        "keccak_f_1600_unrolled_gf2_128",
        FieldID::Gf2_128,
    );
    let p256_c = P256Field::new();
    let p256_r = runtime_algebra::p256::P256Field::new();
    test_compile_keccak_f_1600_unrolled_for_field::<4, _, _>(
        &p256_c,
        &p256_r,
        "keccak_f_1600_unrolled_p256",
        FieldID::P256,
    );
}

fn test_compile_keccak_f_1600_sliced_for_field<
    'a,
    const W: usize,
    FC: CompileField + SerializableField,
    FR: RuntimeField<W> + SerializableField,
>(
    fc: &'a FC,
    fr: &'a FR,
    name: &str,
    field_id: FieldID,
) {
    use circuits_bitvec::BitvecIO;
    use circuits_experimental::sha3::State;

    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);
    let bv = BitvecLogic::new(&iologic);
    let bitvec_io = BitvecIO::new(&bv);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    // Input state 0 (Public)
    let s0: State<_> = std::array::from_fn(|_x| std::array::from_fn(|_y| bitvec_io.next(&mut pos)));

    // Determine slice rounds (period = 6: rounds 5, 11, 17, 23 are sliced)
    let slice_rounds = [5, 11, 17, 23];
    let a_intermediates: [Option<State<_>>; 24] = std::array::from_fn(|t| {
        if slice_rounds.contains(&t) {
            Some(std::array::from_fn(|_x| {
                std::array::from_fn(|_y| bitvec_io.next(&mut pos))
            }))
        } else {
            None
        }
    });

    let sha3 = Sha3::new(&iologic);
    let (_s24, all_assertions) = sha3.assert_keccak_f_1600_sliced(&s0, &a_intermediates);

    let (circuit, stats, symbols) =
        compile_compiler::top::compile(&arena, fc, all_assertions, 0, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);

    // Initial state 0 concrete values
    let mut s0_val = [[0u64; 5]; 5];
    for (x, row) in s0_val.iter_mut().enumerate() {
        for (y, val) in row.iter_mut().enumerate() {
            *val = ((x * 5 + y) as u64 + 1) * 0x123456789abcdef;
        }
    }

    let rust_states = keccak_f_1600_trajectory(s0_val);

    let mut inputs = compile_eval::initial_inputs(fr);
    // Push initial state
    for row in &s0_val {
        for &val in row {
            circuits_bitvec::concrete::push_bitvec_u64(fr, val, 64, &mut inputs);
        }
    }
    // Push slices
    for t in 0..24 {
        if let Some(ref _slice) = a_intermediates[t] {
            let slice_val = rust_states[t + 1];
            for row in &slice_val {
                for &val in row {
                    circuits_bitvec::concrete::push_bitvec_u64(fr, val, 64, &mut inputs);
                }
            }
        }
    }

    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_keccak_f_1600_sliced() {
    let gf2_c = Gf2_128Field::new();
    let gf2_r = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_keccak_f_1600_sliced_for_field::<2, _, _>(
        &gf2_c,
        &gf2_r,
        "keccak_f_1600_sliced_gf2_128",
        FieldID::Gf2_128,
    );
    let p256_c = P256Field::new();
    let p256_r = runtime_algebra::p256::P256Field::new();
    test_compile_keccak_f_1600_sliced_for_field::<4, _, _>(
        &p256_c,
        &p256_r,
        "keccak_f_1600_sliced_p256",
        FieldID::P256,
    );
}
