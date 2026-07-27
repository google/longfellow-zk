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

use compile_algebra::field::CompileField;

/// Bundles all compile-time circuit generation requirements for `MdocHash`.
pub trait MdocHashCompileField:
    Sized + CompileField + circuits_analog_adder::FieldWrappingSum + core_algebra::SerializableField
{
}

impl<F> MdocHashCompileField for F where F: Sized
        + CompileField
        + circuits_analog_adder::FieldWrappingSum
        + core_algebra::SerializableField
{
}

/// Bundles all compile-time circuit generation requirements for `MdocSignature`.
pub trait MdocSigCompileField:
    Sized
    + compile_algebra::field::CompilePrimeField
    + compile_algebra::field::SupportsNatConversions<4, N = compile_algebra::CompileNat<4>>
    + core_algebra::SupportsU64Conversions
    + core_algebra::SerializableField
{
}

impl<F> MdocSigCompileField for F where F: Sized
        + compile_algebra::field::CompilePrimeField
        + compile_algebra::field::SupportsNatConversions<4, N = compile_algebra::CompileNat<4>>
        + core_algebra::SupportsU64Conversions
        + core_algebra::SerializableField
{
}

/// Bundles all runtime derived value derivation and evaluation requirements for `MdocHash`.
#[cfg(feature = "testonly")]
pub trait MdocHashRuntimeField:
    Sized
    + runtime_algebra::field::RuntimeField<2>
    + core_algebra::SerializableField
    + core_algebra::HasLookupPoints
    + core_algebra::SupportsU128Conversions
{
}

#[cfg(feature = "testonly")]
impl<F> MdocHashRuntimeField for F where F: Sized
        + runtime_algebra::field::RuntimeField<2>
        + core_algebra::SerializableField
        + core_algebra::HasLookupPoints
        + core_algebra::SupportsU128Conversions
{
}

/// Bundles all runtime derived value derivation requirements for `MdocSignature` field arithmetic.
#[cfg(feature = "testonly")]
pub trait MdocSigRuntimeField:
    Sized
    + core_algebra::BareField
    + runtime_algebra::field::RuntimeField<4>
    + core_algebra::SupportsNatConversions<4>
    + core_algebra::SupportsU64Conversions
    + core_algebra::HasLookupPoints
where <Self as core_algebra::SupportsNatConversions<4>>::N: core_algebra::Nat<4>
{
}

#[cfg(feature = "testonly")]
impl<F> MdocSigRuntimeField for F
where
    F: Sized
        + core_algebra::BareField
        + runtime_algebra::field::RuntimeField<4>
        + core_algebra::SupportsNatConversions<4>
        + core_algebra::SupportsU64Conversions
        + core_algebra::HasLookupPoints,
    <F as core_algebra::SupportsNatConversions<4>>::N: core_algebra::Nat<4>,
{
}
