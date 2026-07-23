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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcreteGiven {
    pub message: [u8; 32],
    pub mac_av: u128,
    pub mac_ap: [u128; 2],
    pub tag: [u128; 2],
}

fn gf2_128_mul(x: u128, y: u128) -> u128 {
    let poly: u128 = 0x87;
    let mut a: u128 = 0;
    let mut y_shift = y;
    for _ in 0..128 {
        let msb = (a & (1 << 127)) != 0;
        a <<= 1;
        if msb {
            a ^= poly;
        }
        if (y_shift & (1 << 127)) != 0 {
            a ^= x;
        }
        y_shift <<= 1;
    }
    a
}

fn compute_mac(mac_av: u128, mac_ap: u128, msg: u128) -> u128 {
    gf2_128_mul(mac_av, msg) ^ mac_ap
}

#[must_use]
pub fn compute_tag(message: &[u8; 32], mac_av: u128, mac_ap: &[u128; 2]) -> [u128; 2] {
    let to_128_le = |bytes: &[u8]| -> u128 {
        let mut padded = [0u8; 16];
        padded.copy_from_slice(bytes);
        u128::from_le_bytes(padded)
    };

    let msg0 = to_128_le(&message[0..16]);
    let msg1 = to_128_le(&message[16..32]);

    let tag0 = compute_mac(mac_av, mac_ap[0], msg0);
    let tag1 = compute_mac(mac_av, mac_ap[1], msg1);

    [tag0, tag1]
}

#[must_use]
pub fn given(message: [u8; 32], mac_av: u128, mac_ap: [u128; 2]) -> ConcreteGiven {
    let tag = compute_tag(&message, mac_av, &mac_ap);
    ConcreteGiven {
        message,
        mac_av,
        mac_ap,
        tag,
    }
}
