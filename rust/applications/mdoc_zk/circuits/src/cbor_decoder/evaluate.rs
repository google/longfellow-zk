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
use compile_logic::Logic;

use super::{circuit::Given as WireGiven, concrete::ConcreteGiven};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> WireGiven<L> {
    let v = bv.of_u8(given.v);
    WireGiven { v }
}
