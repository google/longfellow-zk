// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use num_bigint::BigUint;

use crate::fp::{FpField, FpParameters};

fn q256_params() -> FpParameters<4> {
    FpParameters {
        length_bytes: 32,
        modulo: crate::CompileNat::from_biguint(
            &BigUint::parse_bytes(
                b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                16,
            )
            .unwrap(),
        ),
        id: 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Q256Tag;
pub type Q256Field = FpField<Q256Tag>;

impl Default for Q256Field {
    fn default() -> Self {
        Self::new()
    }
}

impl Q256Field {
    #[must_use]
    pub fn new() -> Self {
        FpField::new_field(q256_params())
    }
}
