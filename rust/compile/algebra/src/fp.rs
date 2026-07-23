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

use std::marker::PhantomData;

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::field::{AlgebraicField, CompileField, SupportsNatConversions};

/// Represents parameter constraints for a prime field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpParameters<const W: usize> {
    pub length_bytes: usize,
    pub modulo: crate::CompileNat<W>,
}

/// Represents the mathematical field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpField<T> {
    length_bytes: usize,
    modulo: BigUint,
    basis: Vec<Elt<T>>,
    dimension: usize,
    _marker: PhantomData<T>,
}

impl<T> FpField<T> {
    #[must_use]
    pub fn new_field<const W: usize>(params: FpParameters<W>) -> Self {
        let modulo = params.modulo.to_biguint();
        let bits = modulo.bits();
        assert!(modulo > BigUint::one(), "field modulus must exceed one");
        assert!(
            params.length_bytes >= (bits as usize).div_ceil(8),
            "serialized field size is too small for the modulus"
        );
        let dimension = (bits - 1) as usize;

        let mut basis = Vec::with_capacity(dimension);
        for i in 0..dimension {
            basis.push(Elt {
                n: (&BigUint::from(1u32) << i) % &modulo,
                _marker: PhantomData,
            });
        }

        Self {
            length_bytes: params.length_bytes,
            modulo,
            basis,
            dimension,
            _marker: PhantomData,
        }
    }

    #[must_use]
    pub fn value<'a>(&self, e: &'a Elt<T>) -> &'a BigUint {
        &e.n
    }
}

impl<T> core_algebra::BareField for FpField<T> {
    type E = Elt<T>;
}

impl<T> core_algebra::Comparable for FpField<T> {
    fn compare(&self, a: &Self::E, b: &Self::E) -> std::cmp::Ordering {
        a.n.cmp(&b.n)
    }
}

impl<T> core_algebra::AlgebraicField for FpField<T> {
    fn zero(&self) -> Self::E {
        Elt {
            n: BigUint::zero(),
            _marker: PhantomData,
        }
    }

    fn one(&self) -> Self::E {
        Elt {
            n: BigUint::one(),
            _marker: PhantomData,
        }
    }

    fn add(&self, a: &mut Self::E, b: &Self::E) {
        a.n = (&a.n + &b.n) % &self.modulo;
    }

    fn sub(&self, a: &mut Self::E, b: &Self::E) {
        a.n = if a.n >= b.n {
            &a.n - &b.n
        } else {
            &self.modulo - (&b.n - &a.n)
        };
    }

    fn mul(&self, a: &mut Self::E, b: &Self::E) {
        a.n = (&a.n * &b.n) % &self.modulo;
    }

    fn invert(&self, a: &Self::E) -> Self::E {
        assert!(!self.is_zero(a), "Cannot invert zero");
        let inv = a.n.clone().modpow(&(&self.modulo - 2u32), &self.modulo);
        Elt {
            n: inv,
            _marker: PhantomData,
        }
    }
}

impl<T> CompileField for FpField<T> {
    fn characteristic(&self) -> BigUint {
        self.modulo.clone()
    }

    fn pseudo_basis(&self, i: usize) -> Self::E {
        self.basis[i].clone()
    }

    fn pseudo_dimension(&self) -> usize {
        self.dimension
    }

    fn pseudo_basis_unsafe(&self, i: usize) -> Self::E {
        Elt {
            n: &BigUint::from(1u32) << i,
            _marker: PhantomData,
        }
    }

    fn pseudo_dimension_of_multiplicative_group(&self) -> usize {
        let order = &self.modulo - 1u32;
        (order.bits() - 1) as usize
    }
}

impl<const W: usize, T> SupportsNatConversions<W> for FpField<T> {
    type N = crate::CompileNat<W>;

    fn nat_to_element(&self, n: &Self::N) -> Self::E {
        let value = &n.0 % &self.modulo;
        Elt {
            n: value,
            _marker: PhantomData,
        }
    }

    fn to_nat(&self, e: &Self::E) -> Self::N {
        crate::CompileNat::from_biguint(&e.n)
    }
}

/// Represents an element of the field
pub struct Elt<T> {
    n: BigUint,
    _marker: PhantomData<T>,
}

impl<T> Clone for Elt<T> {
    fn clone(&self) -> Self {
        Self {
            n: self.n.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T> PartialEq for Elt<T> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n
    }
}

impl<T> Eq for Elt<T> {}

impl<T> std::hash::Hash for Elt<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.n.hash(state);
    }
}

impl<T> std::fmt::Debug for Elt<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elt").field("n", &self.n).finish()
    }
}

impl<T> crate::field::CompilePrimeField for FpField<T> {}

impl<T> core_algebra::SerializableField for FpField<T> {
    fn is_binary(&self) -> bool {
        false
    }

    fn serialized_size_bytes(&self) -> usize {
        self.length_bytes
    }

    #[inline]
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        assert_eq!(
            dst.len(),
            self.length_bytes,
            "destination slice length mismatch: {} != {}",
            dst.len(),
            self.length_bytes
        );
        let bytes = e.n.to_bytes_le();
        let len = bytes.len().min(self.length_bytes);
        dst[..len].copy_from_slice(&bytes[..len]);
        if len < self.length_bytes {
            dst[len..].fill(0);
        }
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        if bytes.len() != self.length_bytes {
            return Err("Invalid size".to_string());
        }
        let value = BigUint::from_bytes_le(bytes);
        if value >= self.modulo {
            return Err("Out of bounds".to_string());
        }
        Ok(Elt {
            n: value,
            _marker: PhantomData,
        })
    }

    fn serialized_mone(&self) -> Vec<u8> {
        let mone = self.mone();
        self.to_bytes(&mone)
    }
}

impl<T> core_algebra::HasLookupPoints for FpField<T> {
    fn lookup_point(&self, n: usize, i: usize) -> Self::E {
        let two_i = Elt {
            n: BigUint::from((2 * i) as u64),
            _marker: std::marker::PhantomData,
        };
        let n_minus_1 = Elt {
            n: BigUint::from((n - 1) as u64),
            _marker: std::marker::PhantomData,
        };
        self.subf(&two_i, &n_minus_1)
    }
}

impl<T> core_algebra::SupportsU64Conversions for FpField<T> {
    fn u64_to_element(&self, n: u64) -> Self::E {
        let value = BigUint::from(n);
        assert!(
            value < self.modulo,
            "integer is not a canonical field element"
        );
        Elt {
            n: value,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> core_algebra::SupportsU128Conversions for FpField<T> {
    fn u128_to_element(&self, n: u128) -> Self::E {
        let value = BigUint::from(n);
        assert!(
            value < self.modulo,
            "integer is not a canonical field element"
        );
        Elt {
            n: value,
            _marker: std::marker::PhantomData,
        }
    }
}
