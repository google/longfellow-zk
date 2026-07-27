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

pub mod lfc1;
pub mod lfc2;

use super::{FieldID, SerializableField};
use crate::circuit::Circuit;

pub struct CircuitWriter<'a, F> {
    f: &'a F,
    pub(super) field_id: FieldID,
}

impl<'a, F: SerializableField> CircuitWriter<'a, F> {
    pub fn new(f: &'a F, field_id: FieldID) -> Self {
        Self { f, field_id }
    }

    #[must_use]
    pub fn to_bytes(&self, sc_c: &Circuit<F>) -> Vec<u8> {
        self.to_bytes_lfc2(sc_c)
    }

    #[must_use]
    pub fn to_bytes_lfc1(&self, sc_c: &Circuit<F>) -> Vec<u8> {
        lfc1::to_bytes_lfc1(self, sc_c)
    }

    #[must_use]
    pub fn to_bytes_lfc2(&self, sc_c: &Circuit<F>) -> Vec<u8> {
        lfc2::to_bytes_lfc2(self, sc_c)
    }

    pub(super) fn serialize_elt(&self, bytes: &mut Vec<u8>, v: &F::E) {
        let elt_bytes = self.f.to_bytes(v);
        bytes.extend_from_slice(&elt_bytes);
    }
}
