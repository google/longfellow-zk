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

use runtime_algebra::{field::AlgebraicField, gf2_128::Gf2_128RuntimeField, Poly};

#[test]
fn test_zero_length_polynomial_rejects_evaluation() {
    let f = Gf2_128RuntimeField::new();
    let p = Poly::<0, 2, _>::zero(&f);
    let x = f.zero();

    assert!(
        std::panic::catch_unwind(|| p.eval_monomial(&x, &f)).is_err(),
        "accepted monomial evaluation of a zero-length polynomial"
    );
    assert!(
        std::panic::catch_unwind(|| p.eval_newton(&x, &f)).is_err(),
        "accepted Newton evaluation of a zero-length polynomial"
    );
}
