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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcreteGiven {
    pub v: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborDecodeResult {
    pub atomp: bool,
    pub itemsp: bool,
    pub stringp: bool,
    pub arrayp: bool,
    pub mapp: bool,
    pub tagp: bool,
    pub specialp: bool,
    pub simple_specialp: bool,
    pub count0_23: bool,
    pub count24_27: bool,
    pub count24: bool,
    pub count25: bool,
    pub count26: bool,
    pub count27: bool,
    pub length_plus_next_v8: bool,
    pub count_is_next_v8: bool,
    pub invalid: bool,
    pub length: u64,
}

#[must_use]
pub fn decode_one_v8(v: u8) -> CborDecodeResult {
    let count = v & 0x1f;
    let type_val = (v >> 5) & 0x07;

    let atomp = (type_val & 0b110) == 0b000;
    let stringp = (type_val & 0b110) == 0b010;
    let itemsp = (type_val & 0b110) == 0b100;

    let specialp = type_val == 7;
    let tagp = type_val == 6;
    let arrayp = itemsp && ((type_val & 1) == 0);
    let mapp = itemsp && ((type_val & 1) == 1);

    let count0_23 = count < 24;
    let count24_27 = (count & 0b11100) == 0b11000;

    let count24 = count == 24;
    let count25 = count == 25;
    let count26 = count == 26;
    let count27 = count == 27;

    let simple_specialp = specialp && ((count & 0b11100) == 0b10100);
    let length_plus_next_v8 = (v & 0xDF) == 0x58;
    let count_is_next_v8 = (v & 0xDF) == 0x98;

    let good_count = (count <= 24) || ((atomp || tagp) && (count <= 27));
    let invalid_special = specialp && !simple_specialp;
    let invalid = invalid_special || !good_count;

    let mut length = match count {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        28 => 2,
        29 => 3,
        30 => 5,
        31 => 9,
        _ => unreachable!(),
    };
    if stringp && count0_23 {
        length += u64::from(count);
    }

    CborDecodeResult {
        atomp,
        itemsp,
        stringp,
        arrayp,
        mapp,
        tagp,
        specialp,
        simple_specialp,
        count0_23,
        count24_27,
        count24,
        count25,
        count26,
        count27,
        length_plus_next_v8,
        count_is_next_v8,
        invalid,
        length,
    }
}
