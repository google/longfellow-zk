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

use circuits_bit_plucker::BitPlucker;
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_logic::LogicIO;
use core_algebra::SerializableField;

fn test_compile_bit_plucker_for_field_n<
    const W: usize,
    FC: CompileField + SerializableField,
    const LOGN: usize,
>(
    fc: &FC,
    name: &str,
) {
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let input_elt = iologic.next(&mut pos);

    let plucker = BitPlucker::<_, LOGN>::new(&iologic);
    let plucked = plucker.pluck(&input_elt);

    // Dummy assertion to compile the circuit
    let boolean = circuits_boolean::Boolean::new(&iologic);
    let assertion = boolean.assert_false("bit0_false", plucked.bit(0));

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, fc, assertion, 1, 0);

    compile_compiler::top::dump_stats(&format!("{name}_{LOGN}"), &circuit, &stats);
}

#[test]
fn test_compile_bit_plucker() {
    let fc_bin = Gf2_128Field::new();
    test_compile_bit_plucker_for_field_n::<2, _, 1>(&fc_bin, "bit_plucker_bin");
    test_compile_bit_plucker_for_field_n::<2, _, 2>(&fc_bin, "bit_plucker_bin");
    test_compile_bit_plucker_for_field_n::<2, _, 3>(&fc_bin, "bit_plucker_bin");
    test_compile_bit_plucker_for_field_n::<2, _, 4>(&fc_bin, "bit_plucker_bin");
    test_compile_bit_plucker_for_field_n::<2, _, 5>(&fc_bin, "bit_plucker_bin");

    let fc_prime = P256Field::new();
    test_compile_bit_plucker_for_field_n::<4, _, 1>(&fc_prime, "bit_plucker_prime");
    test_compile_bit_plucker_for_field_n::<4, _, 2>(&fc_prime, "bit_plucker_prime");
    test_compile_bit_plucker_for_field_n::<4, _, 3>(&fc_prime, "bit_plucker_prime");
    test_compile_bit_plucker_for_field_n::<4, _, 4>(&fc_prime, "bit_plucker_prime");
    test_compile_bit_plucker_for_field_n::<4, _, 5>(&fc_prime, "bit_plucker_prime");
}
