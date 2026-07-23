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

use core_algebra::{ElementOf, Nat};
use num_bigint::BigUint;

use crate::{
    field::{CompilePrimeField, SupportsNatConversions},
    Curve,
};

pub struct Secp256r1<F: CompilePrimeField + SupportsNatConversions<4>> {
    a: ElementOf<F>,
    b: ElementOf<F>,
    g: (ElementOf<F>, ElementOf<F>),
    order: crate::CompileNat<4>,
}

impl<F: CompilePrimeField + SupportsNatConversions<4>> std::fmt::Debug for Secp256r1<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256r1")
            .field("a", &self.a)
            .field("b", &self.b)
            .field("g", &self.g)
            .field("order", &self.order)
            .finish()
    }
}

impl<F: CompilePrimeField + SupportsNatConversions<4>> Secp256r1<F> {
    pub fn new(f: &F) -> Self {
        let val_a = BigUint::parse_bytes(
            b"115792089210356248762697446949407573530086143415290314195533631308867097853948",
            10,
        )
        .unwrap();
        let val_b = BigUint::parse_bytes(
            b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            16,
        )
        .unwrap();
        let gx = BigUint::parse_bytes(
            b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            16,
        )
        .unwrap();
        let gy = BigUint::parse_bytes(
            b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            16,
        )
        .unwrap();
        let order_limbs = [
            0xf3b9cac2fc632551,
            0xbce6faada7179e84,
            0xffffffffffffffff,
            0xffffffff00000000,
        ];
        let order = crate::CompileNat::from_limbs(&order_limbs);

        // Convert big uints to limbs
        let mut limbs_a = [0u64; 4];
        let bytes_a = val_a.to_bytes_le();
        for i in 0..4 {
            if i * 8 < bytes_a.len() {
                let limit = std::cmp::min((i + 1) * 8, bytes_a.len());
                let mut buf = [0u8; 8];
                buf[..limit - i * 8].copy_from_slice(&bytes_a[i * 8..limit]);
                limbs_a[i] = u64::from_le_bytes(buf);
            }
        }
        let nat_a = F::N::from_limbs(&limbs_a);

        let mut limbs_b = [0u64; 4];
        let bytes_b = val_b.to_bytes_le();
        for i in 0..4 {
            if i * 8 < bytes_b.len() {
                let limit = std::cmp::min((i + 1) * 8, bytes_b.len());
                let mut buf = [0u8; 8];
                buf[..limit - i * 8].copy_from_slice(&bytes_b[i * 8..limit]);
                limbs_b[i] = u64::from_le_bytes(buf);
            }
        }
        let nat_b = F::N::from_limbs(&limbs_b);

        let mut limbs_gx = [0u64; 4];
        let bytes_gx = gx.to_bytes_le();
        for i in 0..4 {
            if i * 8 < bytes_gx.len() {
                let limit = std::cmp::min((i + 1) * 8, bytes_gx.len());
                let mut buf = [0u8; 8];
                buf[..limit - i * 8].copy_from_slice(&bytes_gx[i * 8..limit]);
                limbs_gx[i] = u64::from_le_bytes(buf);
            }
        }
        let nat_gx = F::N::from_limbs(&limbs_gx);

        let mut limbs_gy = [0u64; 4];
        let bytes_gy = gy.to_bytes_le();
        for i in 0..4 {
            if i * 8 < bytes_gy.len() {
                let limit = std::cmp::min((i + 1) * 8, bytes_gy.len());
                let mut buf = [0u8; 8];
                buf[..limit - i * 8].copy_from_slice(&bytes_gy[i * 8..limit]);
                limbs_gy[i] = u64::from_le_bytes(buf);
            }
        }
        let nat_gy = F::N::from_limbs(&limbs_gy);

        Self {
            a: f.reduce_nat(&nat_a),
            b: f.reduce_nat(&nat_b),
            g: (f.reduce_nat(&nat_gx), f.reduce_nat(&nat_gy)),
            order,
        }
    }
}

impl<F: CompilePrimeField + SupportsNatConversions<4>> Curve<4> for Secp256r1<F> {
    type F = F;
    type N = crate::CompileNat<4>;

    fn order(&self) -> Self::N {
        self.order.clone()
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
