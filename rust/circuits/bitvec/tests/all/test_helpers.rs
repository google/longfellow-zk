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

#![allow(dead_code)]

use circuits_boolean::{Bitw, Boolean};
use compile_logic::{Eltw, Logic};

pub(crate) struct F65537Tag;
pub(crate) type F65537Field = compile_algebra::fp::FpField<F65537Tag>;

pub(crate) type LPrime<'a> = compile_logic::eval::EvalLogic<'a, F65537Field>;

pub(crate) fn new_f65537_field() -> F65537Field {
    compile_algebra::fp::FpField::new_field(compile_algebra::fp::FpParameters {
        length_bytes: 3,
        modulo: compile_algebra::CompileNat::<4>::from(65537),
        id: 999,
    })
}

pub(crate) fn compare_bitw<L: Logic>(boolean: &Boolean<L>, want: &Bitw<L>, got: &Bitw<L>)
where Eltw<L>: PartialEq + std::fmt::Debug {
    let got_val = boolean.as_eltw(got);
    let want_val = boolean.as_eltw(want);
    assert_eq!(got_val, want_val);
}
