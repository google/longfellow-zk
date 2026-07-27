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

pub mod allocate;
pub mod circuit;
pub use allocate::{allocate_derived_wires, allocate_given_wires};
pub use circuit::{Derived, EcdsaCircuit, Given, Slicing};
#[cfg(feature = "testonly")]
pub mod evaluate;
#[cfg(feature = "testonly")]
pub use evaluate::{evaluate_derived, evaluate_given};
pub mod concrete;
pub mod traits;
pub use concrete::{derived, given, ConcreteDerived, ConcreteGiven};
pub use traits::EcdsaCompileField;
