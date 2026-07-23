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

use compile_logic::LogicIO;

use super::circuit::{Derived, Given, Slicing};

pub fn allocate_given_wires<L: LogicIO>(logic: &L, pos: &mut usize) -> Given<L> {
    let pkxy = (logic.next(pos), logic.next(pos));
    let e = logic.next(pos);
    let rxy = (logic.next(pos), logic.next(pos));
    let ers = std::array::from_fn(|_| logic.next(pos));
    Given { pkxy, e, rxy, ers }
}

pub fn allocate_derived_wires<L: LogicIO>(logic: &L, pos: &mut usize) -> Derived<L> {
    let pkxinv = logic.next(pos);
    let rxinv = logic.next(pos);
    let nmsinv = logic.next(pos);
    let yinv = logic.next(pos);

    let g_pk = (logic.next(pos), logic.next(pos));
    let g_r = (logic.next(pos), logic.next(pos));
    let pk_r = (logic.next(pos), logic.next(pos));
    let g_pk_r = (logic.next(pos), logic.next(pos));

    let round = std::array::from_fn(|_| (logic.next(pos), logic.next(pos), logic.next(pos)));

    Derived {
        pkxinv,
        rxinv,
        nmsinv,
        yinv,
        slicing: Slicing {
            g_pk,
            g_r,
            pk_r,
            g_pk_r,
            round,
        },
    }
}
