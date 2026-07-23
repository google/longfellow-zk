use crate::{
    field::{RuntimeSerializableField, SupportsFFT},
    fp_generic::{FpGenericAccum, FpGenericElement, FpGenericField},
    Subfield,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct P256Tag;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct P256Strategy;

pub type P256Element = FpGenericElement<{ 4 * crate::LIMBS_PER_U64 }, P256Tag>;
pub type P256Field = FpGenericField<
    4,
    { 4 * crate::LIMBS_PER_U64 },
    { 9 * crate::LIMBS_PER_U64 },
    P256Tag,
    P256Strategy,
>;
pub type P256Accum = FpGenericAccum<{ 9 * crate::LIMBS_PER_U64 }>;

pub(crate) const P256_MODULUS: [u64; 4] = [
    0xffffffffffffffff,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
];

#[cfg(any(target_pointer_width = "32", feature = "force-32bit-limbs"))]
#[allow(dead_code)]
pub(crate) const NEG_P256_MODULUS_32: [u32; 8] =
    [1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0];

#[cfg(all(target_pointer_width = "64", not(feature = "force-32bit-limbs")))]
mod p256_64;
#[cfg(all(target_pointer_width = "64", not(feature = "force-32bit-limbs")))]
#[allow(unused_imports)]
use p256_64::*;

#[cfg(any(target_pointer_width = "32", feature = "force-32bit-limbs"))]
mod p256_32;
#[cfg(any(target_pointer_width = "32", feature = "force-32bit-limbs"))]
#[allow(unused_imports)]
use p256_32::*;

impl Default for P256Field {
    fn default() -> Self {
        Self::new()
    }
}

impl P256Field {
    #[must_use]
    pub fn new() -> Self {
        Self::new_generic(
            P256_MODULUS,
            1,
            "Fp(115792089210356248762697446949407573530086143415290314195533631308867097853951)",
        )
    }
}

const P256_ROOT_OF_UNITY_RE: [u64; 4] = [
    0x985a65324b242562,
    0x9fc9563b382a4a4c,
    0x5cfc85c67990e337,
    0xf90d338ebd84f566,
];
const P256_ROOT_OF_UNITY_IM: [u64; 4] = [
    0xdbf4174f60a43eac,
    0x84738a6474d232c6,
    0xa04fc2e20106e340,
    0xb9e81e42bc97cc4d,
];

impl SupportsFFT<8> for crate::fp2::Fp2Field<'_, 4, 8, P256Field> {
    fn omega(&self) -> Self::E {
        crate::fp2::Fp2Element {
            re: self
                .base_field()
                .words64_to_element(&P256_ROOT_OF_UNITY_RE)
                .unwrap(),
            im: self
                .base_field()
                .words64_to_element(&P256_ROOT_OF_UNITY_IM)
                .unwrap(),
        }
    }

    fn omega_order(&self) -> u64 {
        1u64 << 31
    }
}

pub struct P256Subfield<'a> {
    field: &'a P256Field,
}

impl<'a> P256Subfield<'a> {
    #[must_use]
    pub fn new(field: &'a P256Field) -> Self {
        Self { field }
    }
}

impl Subfield for P256Subfield<'_> {
    type E = P256Element;

    #[inline]
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        assert_eq!(
            dst.len(),
            self.serialized_size_bytes(),
            "destination slice length mismatch: {} != {}",
            dst.len(),
            self.serialized_size_bytes()
        );
        core_algebra::SerializableField::to_bytes_into(self.field, e, dst);
    }

    fn contains(&self, _e: &Self::E) -> bool {
        true
    }

    fn serialized_size_bytes(&self) -> usize {
        core_algebra::SerializableField::serialized_size_bytes(self.field)
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        core_algebra::SerializableField::bytes_to_element(self.field, bytes)
    }

    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, rng: R) -> Self::E {
        crate::field::SupportsSampling::sample(self.field, rng)
    }
}
