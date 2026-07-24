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

use circuits_bitvec::{Bitvec, BitvecLogic};
use circuits_boolean::Boolean;
use circuits_memcmp::Memcmp;
use compile_algebra::gf2_128::Gf2_128Field;
use compile_logic::eval::EvalLogic;

fn compare_bool<L: compile_logic::Logic>(
    boolean: &Boolean<L>,
    want: bool,
    got: &circuits_boolean::Bitw<L>,
) where
    compile_logic::Eltw<L>: PartialEq + std::fmt::Debug,
{
    let got_val = boolean.as_eltw(got);
    let want_val = boolean.as_eltw(&boolean.konst(want));
    assert_eq!(got_val, want_val);
}

#[test]
fn test_memcmp_leq() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f, &tracker);
    let bv = BitvecLogic::new(&l);
    let boolean = Boolean::new(&l);
    let cmp = Memcmp::new(&l);

    let test_cases = vec![
        (vec![1, 2, 3], vec![1, 2, 3], true),
        (vec![1, 2, 2], vec![1, 2, 3], true),
        (vec![1, 2, 4], vec![1, 2, 3], false),
        (vec![1, 1, 3], vec![1, 2, 3], true),
        (vec![2, 2, 3], vec![1, 2, 3], false),
        (vec![0, 255], vec![1, 0], true),
        (vec![1, 0], vec![0, 255], false),
        (vec![0], vec![0], true),
        (vec![0], vec![1], true),
        (vec![1], vec![0], false),
        (vec![127], vec![128], true),
        (vec![128], vec![127], false),
        (vec![255], vec![255], true),
        (vec![255, 255], vec![255, 255], true),
        (vec![255, 255], vec![255, 254], false),
    ];

    for (a_val, b_val, expected) in test_cases {
        let a_wires: Vec<Bitvec<L, 8>> = a_val.iter().map(|&x| bv.of_u8(x)).collect();
        let b_wires: Vec<Bitvec<L, 8>> = b_val.iter().map(|&x| bv.of_u8(x)).collect();

        let leq_wire = cmp.leq(&a_wires, &b_wires);
        compare_bool(&boolean, expected, &leq_wire);
    }
}
