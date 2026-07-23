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

use runtime_algebra::field::RuntimeField;

pub fn push_bitvec_u64<const W: usize, FR: RuntimeField<W>>(
    fr: &FR,
    value: u64,
    n: usize,
    dest: &mut Vec<FR::E>,
) {
    assert!(n <= 64);
    let mut cur_val = value;
    for _ in 0..n {
        let val_f = if (cur_val & 1) != 0 {
            fr.one()
        } else {
            fr.zero()
        };
        dest.push(val_f);
        cur_val >>= 1;
    }
}

pub fn push_bitvec_u128<const W: usize, FR: RuntimeField<W>>(
    fr: &FR,
    value: u128,
    n: usize,
    dest: &mut Vec<FR::E>,
) {
    assert!(n <= 128);
    let mut cur_val = value;
    for _ in 0..n {
        let val_f = if (cur_val & 1) != 0 {
            fr.one()
        } else {
            fr.zero()
        };
        dest.push(val_f);
        cur_val >>= 1;
    }
}

pub fn push_bitvec_bytes<const W: usize, FR: RuntimeField<W>>(
    fr: &FR,
    bytes: &[u8],
    n: usize,
    dest: &mut Vec<FR::E>,
) {
    assert_eq!(bytes.len() * 8, n);
    for &cur_byte in bytes {
        let mut cur = cur_byte;
        for _ in 0..8 {
            let val_f = if (cur & 1) != 0 { fr.one() } else { fr.zero() };
            dest.push(val_f);
            cur >>= 1;
        }
    }
}
