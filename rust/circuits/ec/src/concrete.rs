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
use compile_logic::Logic;
pub use core_algebra::ec::*;

use crate::{Pt2 as WirePt2, Pt3 as WirePt3};

pub fn evaluate_pt2<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    pt: &Pt2<F>,
    l: &L,
) -> WirePt2<compile_logic::Eltw<L>> {
    (l.konst(&pt.0), l.konst(&pt.1))
}

pub fn evaluate_pt3<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    pt: &Pt3<F>,
    l: &L,
) -> WirePt3<compile_logic::Eltw<L>> {
    (l.konst(&pt.0), l.konst(&pt.1), l.konst(&pt.2))
}

#[cfg(feature = "testonly")]
pub fn push_pt2<E: Clone>(value: &(E, E), dest: &mut Vec<E>) {
    dest.push(value.0.clone());
    dest.push(value.1.clone());
}

#[cfg(feature = "testonly")]
pub fn push_pt3<E: Clone>(value: &(E, E, E), dest: &mut Vec<E>) {
    dest.push(value.0.clone());
    dest.push(value.1.clone());
    dest.push(value.2.clone());
}
