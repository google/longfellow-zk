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

use compile_algebra::field::{CompileField, SupportsNatConversions};
use core_algebra::SupportsU64Conversions;

/// Bundles all compile-time field requirements for `EcdsaCircuit`.
pub trait EcdsaCompileField<const W: usize>:
    CompileField + SupportsNatConversions<W> + SupportsU64Conversions
{
}

impl<const W: usize, F> EcdsaCompileField<W> for F where F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions
{}
