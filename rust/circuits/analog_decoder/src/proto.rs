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

use core_algebra::{ElementOf, HasLookupPoints};

pub fn binary_point<F: HasLookupPoints>(field: &F, width: usize, i: usize) -> ElementOf<F> {
    let n = 1 << width;
    field.lookup_point(n + 1, i)
}

pub fn unary_point<F: HasLookupPoints>(field: &F, n: usize, i: usize) -> ElementOf<F> {
    field.lookup_point(n + 1, i)
}
