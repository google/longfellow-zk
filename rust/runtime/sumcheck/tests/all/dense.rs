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

use runtime_algebra::{field::SupportsU64Conversions, p256::P256Field, AlgebraicField, ElementOf};
use runtime_sumcheck::{as_scalar, normalize};

#[test]
fn test_normalize() {
    let f = P256Field::new();
    let empty: Vec<ElementOf<P256Field>> = vec![];
    let norm_empty = normalize::<4, P256Field>(empty, &f);
    assert_eq!(norm_empty.len(), 1);
    assert_eq!(norm_empty[0], f.zero());

    let non_empty = vec![f.u64_to_element(42), f.u64_to_element(100)];
    let norm_non_empty = normalize::<4, P256Field>(non_empty.clone(), &f);
    assert_eq!(norm_non_empty, non_empty);
}

#[test]
fn test_as_scalar() {
    let f = P256Field::new();
    let vec_one = vec![f.u64_to_element(42)];
    assert_eq!(as_scalar::<4, P256Field>(&vec_one), f.u64_to_element(42));
}

#[test]
#[should_panic(expected = "vector length must be 1")]
fn test_as_scalar_panic() {
    let f = P256Field::new();
    let vec_two = vec![f.u64_to_element(1), f.u64_to_element(2)];
    as_scalar::<4, P256Field>(&vec_two);
}
