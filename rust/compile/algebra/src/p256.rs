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

use num_bigint::BigUint;

use crate::fp::{FpField, FpParameters};

fn p256_params() -> FpParameters<4> {
    FpParameters {
        length_bytes: 32,
        modulo: crate::CompileNat::from_biguint(
            &BigUint::parse_bytes(
                b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                16,
            )
            .unwrap(),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256Tag;
pub type P256Field = FpField<P256Tag>;

impl Default for P256Field {
    fn default() -> Self {
        Self::new()
    }
}

impl P256Field {
    #[must_use]
    pub fn new() -> Self {
        FpField::new_field(p256_params())
    }
}
