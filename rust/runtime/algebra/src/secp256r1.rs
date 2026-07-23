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

use core_algebra::{Curve, ElementOf};

use crate::field::RuntimeField;

const SECP256R1_A: [u64; 4] = [
    0xfffffffffffffffc,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
];
const SECP256R1_B: [u64; 4] = [
    0x3bce3c3e27d2604b,
    0x651d06b0cc53b0f6,
    0xb3ebbd55769886bc,
    0x5ac635d8aa3a93e7,
];
const SECP256R1_GX: [u64; 4] = [
    0xf4a13945d898c296,
    0x77037d812deb33a0,
    0xf8bce6e563a440f2,
    0x6b17d1f2e12c4247,
];
const SECP256R1_GY: [u64; 4] = [
    0xcbb6406837bf51f5,
    0x2bce33576b315ece,
    0x8ee7eb4a7c0f9e16,
    0x4fe342e2fe1a7f9b,
];
const SECP256R1_ORDER: [u64; 4] = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];

pub struct Secp256r1<F: RuntimeField<4> + core_algebra::SerializableField> {
    a: ElementOf<F>,
    b: ElementOf<F>,
    g: (ElementOf<F>, ElementOf<F>),
    order: [u64; 4],
}

impl<F: RuntimeField<4> + core_algebra::SerializableField> Clone for Secp256r1<F> {
    fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            b: self.b.clone(),
            g: self.g.clone(),
            order: self.order,
        }
    }
}

impl<F: RuntimeField<4> + core_algebra::SerializableField> std::fmt::Debug for Secp256r1<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256r1")
            .field("a", &self.a)
            .field("b", &self.b)
            .field("g", &self.g)
            .field("order", &self.order)
            .finish()
    }
}

impl<F: RuntimeField<4> + core_algebra::SerializableField> PartialEq for Secp256r1<F> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b && self.g == other.g && self.order == other.order
    }
}

impl<F: RuntimeField<4> + core_algebra::SerializableField> Eq for Secp256r1<F> {}

impl<F: RuntimeField<4> + core_algebra::SerializableField> Secp256r1<F> {
    pub fn new(f: &F) -> Self {
        Self {
            a: f.words64_to_element(&SECP256R1_A).unwrap(),
            b: f.words64_to_element(&SECP256R1_B).unwrap(),
            g: (
                f.words64_to_element(&SECP256R1_GX).unwrap(),
                f.words64_to_element(&SECP256R1_GY).unwrap(),
            ),
            order: SECP256R1_ORDER,
        }
    }
}

impl<F: RuntimeField<4> + core_algebra::SerializableField> Curve<4> for Secp256r1<F> {
    type F = F;
    type N = crate::RuntimeNat<4>;

    fn order(&self) -> Self::N {
        Self::N::from_limbs(self.order)
    }

    fn a(&self) -> &ElementOf<Self::F> {
        &self.a
    }

    fn b(&self) -> &ElementOf<Self::F> {
        &self.b
    }

    fn g(&self) -> &(ElementOf<Self::F>, ElementOf<Self::F>) {
        &self.g
    }
}
