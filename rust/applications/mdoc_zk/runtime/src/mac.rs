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

use core_algebra::{AlgebraicField, Nat, SerializableField, SupportsU128Conversions};
use runtime_algebra::{field::RuntimeSerializableField, gf2_128::Gf2_128Field};

pub fn generate_mac_ap<RNG: runtime_random::RandomEngine + ?Sized>(
    rng: &mut RNG,
) -> [[u128; 2]; 3] {
    std::array::from_fn(|_| [rng.u128(), rng.u128()])
}

pub fn push_macs<N: Nat<4>>(
    gf2: &Gf2_128Field,
    version: usize,
    issuer_sig_e: &N,
    device_pk: &(N, N),
    av: u128,
    mac_ap: &[[u128; 2]; 3],
) -> [u128; 6] {
    if version >= 8 {
        push_modern_macs(issuer_sig_e, device_pk, av, mac_ap)
    } else {
        push_legacy_macs(gf2, issuer_sig_e, device_pk, av, mac_ap)
    }
}

fn nat_to_32bytes<N: Nat<4>>(val: &N) -> [u8; 32] {
    let limbs = val.to_limbs();
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn push_modern_macs<N: Nat<4>>(
    issuer_sig_e: &N,
    device_pk: &(N, N),
    av: u128,
    mac_ap: &[[u128; 2]; 3],
) -> [u128; 6] {
    let mut out = [0u128; 6];
    for (i, &nat) in [issuer_sig_e, &device_pk.0, &device_pk.1]
        .iter()
        .enumerate()
    {
        let tag = circuits_mac::concrete::compute_tag(&nat_to_32bytes(nat), av, &mac_ap[i]);
        out[2 * i..2 * i + 2].copy_from_slice(&tag);
    }
    out
}

fn push_legacy_macs<N: Nat<4>>(
    gf2: &Gf2_128Field,
    issuer_sig_e: &N,
    device_pk: &(N, N),
    av: u128,
    mac_ap: &[[u128; 2]; 3],
) -> [u128; 6] {
    let av_elt = gf2.u128_to_element(av);
    let mut out = [0u128; 6];

    for (i, &nat) in [issuer_sig_e, &device_pk.0, &device_pk.1]
        .iter()
        .enumerate()
    {
        let bytes = nat_to_32bytes(nat);
        let m0 = gf2.bytes_to_element(&bytes[..16]).unwrap();
        let m1 = gf2.bytes_to_element(&bytes[16..]).unwrap();

        let term0 = gf2.addf(&av_elt, &gf2.u128_to_element(mac_ap[i][0]));
        let term1 = gf2.addf(&av_elt, &gf2.u128_to_element(mac_ap[i][1]));

        let mac0 = gf2.mulf(&term0, &m0);
        let mac1 = gf2.mulf(&term1, &m1);
        let l0 = gf2.to_words64(&mac0);
        let l1 = gf2.to_words64(&mac1);
        out[2 * i] = u128::from(l0[0]) | (u128::from(l0[1]) << 64);
        out[2 * i + 1] = u128::from(l1[0]) | (u128::from(l1[1]) << 64);
    }
    out
}
