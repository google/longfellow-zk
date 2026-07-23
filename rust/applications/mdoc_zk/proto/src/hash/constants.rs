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

pub const K_MAX_SHA_BLOCKS: usize = 40;
pub const K_MSO_PREIMAGE_LEN: usize = K_MAX_SHA_BLOCKS * 64;
pub const K_HASH_INDEX_BITS: usize = 16;

pub const K_COSE1_PREFIX: [u8; 18] = [
    0x84, 0x6A, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xA1, 0x01, 0x26,
    0x40, 0x59,
];
pub const K_COSE1_PREFIX_LEN: usize = 18;
pub const K_TAG32: [u8; 2] = [0x58, 0x20];

pub const K_DOCTYPE_HEADER_CHECK_CBOR: [u8; 8] = [0x67, b'd', b'o', b'c', b'T', b'y', b'p', b'e'];

pub const K_NAMESPACE_CHECK_CBOR: [u8; 17] = [
    b'o', b'r', b'g', b'.', b'i', b's', b'o', b'.', b'1', b'8', b'0', b'1', b'3', b'.', b'5', b'.',
    b'1',
];

pub const K_VALID_FROM_LEN: usize = 12;
pub const K_VALID_FROM_CHECK_CBOR: [u8; 12] = [
    0x69, b'v', b'a', b'l', b'i', b'd', b'F', b'r', b'o', b'm', 0xC0, 0x74,
];

pub const K_VALID_UNTIL_LEN: usize = 13;
pub const K_VALID_UNTIL_CHECK_CBOR: [u8; 13] = [
    0x6A, b'v', b'a', b'l', b'i', b'd', b'U', b'n', b't', b'i', b'l', 0xC0, 0x74,
];

pub const K_DEVICE_KEY_INFO_CHECK_CBOR: [u8; 33] = [
    0x6D, b'd', b'e', b'v', b'i', b'c', b'e', b'K', b'e', b'y', b'I', b'n', b'f', b'o', 0xA1, 0x69,
    b'd', b'e', b'v', b'i', b'c', b'e', b'K', b'e', b'y', 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58,
    0x20,
];

pub const K_VALUE_DIGESTS_CHECK_CBOR: [u8; 13] = [
    0x6C, b'v', b'a', b'l', b'u', b'e', b'D', b'i', b'g', b'e', b's', b't', b's',
];

pub const K_TIMESTAMP_LEN: usize = 20;
