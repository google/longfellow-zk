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

pub use core_algebra::AlgebraicField;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    OutOfBounds,
}

/// Trait for fields used at circuit compile-time. Inherits from
/// [`core_algebra::AlgebraicField`] to define its associated
/// [`core_algebra::BareField::E`] type and algebraic operations.
pub trait CompileField:
    core_algebra::AlgebraicField
    + core_algebra::SerializableField
    + core_algebra::Comparable
    + core_algebra::HasLookupPoints
{
    /// The field characteristic: the smallest positive integer `p` such that
    /// `p` times the multiplicative identity `1` equals `0`.
    /// For prime fields Fp, this is the prime modulus `P`.
    /// For binary extension fields GF(2^m), this is `2`.
    fn characteristic(&self) -> BigUint;

    /// Returns the i-th basis vector allowing binary combinations with
    /// coefficients {0,1} to represent any field element.
    fn pseudo_basis(&self, i: usize) -> Self::E;

    /// Returns the dimension (number of independent basis vectors) of the field.
    fn pseudo_dimension(&self) -> usize;

    /// Returns the i-th basis vector of the field without checking
    /// dimension boundaries.
    fn pseudo_basis_unsafe(&self, i: usize) -> Self::E;

    fn fma(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = a.clone();
        self.mul(&mut prod, b);
        self.add(e1, &prod);
    }

    fn fms(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = a.clone();
        self.mul(&mut prod, b);
        self.sub(&mut prod, e1);
        *e1 = prod;
    }

    fn fnma(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = a.clone();
        self.mul(&mut prod, b);
        self.add(&mut prod, e1);
        *e1 = self.neg(&prod);
    }

    fn fnms(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = a.clone();
        self.mul(&mut prod, b);
        self.sub(e1, &prod);
    }

    fn pseudo_dimension_of_multiplicative_group(&self) -> usize;
}

/// Optional trait implemented by compile-time fields that support conversions
/// to and from arbitrary-precision non-negative integers (`BigUint`).
/// Typically used by prime fields and elliptic curve coordinates where elements
/// are manipulated as standard large integers.
pub use core_algebra::SupportsNatConversions;
pub use core_algebra::{SupportsU128Conversions, SupportsU64Conversions};

pub trait CompilePrimeField: CompileField {}

pub trait CompileBinaryField: CompileField {
    fn generator(&self) -> Self::E;
}
