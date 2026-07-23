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

pub trait FieldElement: Sized + Clone + std::fmt::Debug + Eq + std::hash::Hash {}

impl<T> FieldElement for T where T: Sized + Clone + std::fmt::Debug + Eq + std::hash::Hash {}

pub trait BareField {
    type E: FieldElement;
}

pub trait Comparable: BareField {
    fn compare(&self, a: &Self::E, b: &Self::E) -> std::cmp::Ordering;
}

pub trait AlgebraicField: BareField {
    fn zero(&self) -> Self::E;
    fn one(&self) -> Self::E;
    fn add(&self, a: &mut Self::E, b: &Self::E);
    fn sub(&self, a: &mut Self::E, b: &Self::E);
    fn mul(&self, a: &mut Self::E, b: &Self::E);
    fn invert(&self, a: &Self::E) -> Self::E;

    #[inline]
    fn addf(&self, a: &Self::E, b: &Self::E) -> Self::E {
        let mut res = a.clone();
        self.add(&mut res, b);
        res
    }

    #[inline]
    fn subf(&self, a: &Self::E, b: &Self::E) -> Self::E {
        let mut res = a.clone();
        self.sub(&mut res, b);
        res
    }

    #[inline]
    fn mulf(&self, a: &Self::E, b: &Self::E) -> Self::E {
        let mut res = a.clone();
        self.mul(&mut res, b);
        res
    }

    #[inline]
    fn neg(&self, a: &Self::E) -> Self::E {
        self.subf(&self.zero(), a)
    }

    #[inline]
    fn mone(&self) -> Self::E {
        self.subf(&self.zero(), &self.one())
    }

    #[inline]
    fn is_zero(&self, e: &Self::E) -> bool {
        e == &self.zero()
    }
}

pub trait SerializableField: BareField {
    // Metadata
    fn name(&self) -> String;
    fn id(&self) -> usize;
    fn is_binary(&self) -> bool;

    // Serialization
    fn serialized_size_bytes(&self) -> usize;
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]);
    #[inline]
    fn to_bytes(&self, e: &Self::E) -> Vec<u8> {
        let len = self.serialized_size_bytes();
        let mut buf = vec![0u8; len];
        self.to_bytes_into(e, &mut buf);
        buf
    }
    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String>;

    // Serialized Constants
    fn serialized_mone(&self) -> Vec<u8>;
}

pub type ElementOf<F> = <F as BareField>::E;

pub trait HasLookupPoints: BareField {
    fn lookup_point(&self, n: usize, i: usize) -> Self::E;
}

pub trait SupportsNatConversions<const W: usize>: SerializableField {
    type N: crate::Nat<W>;

    fn nat_to_element(&self, n: &Self::N) -> Self::E;
    fn to_nat(&self, e: &Self::E) -> Self::N;
}

pub trait SupportsU64Conversions: SerializableField {
    fn u64_to_element(&self, n: u64) -> Self::E;
}

pub trait SupportsU128Conversions: SerializableField {
    fn u128_to_element(&self, n: u128) -> Self::E;
}

pub type NatOf<const W: usize, F> = <F as SupportsNatConversions<W>>::N;
