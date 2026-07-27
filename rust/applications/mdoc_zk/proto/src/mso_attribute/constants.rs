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

pub const K_ATTR_INDEX_BITS: usize = 10;
pub const K_DIGEST_ID: [u8; 9] = [0x68, b'd', b'i', b'g', b'e', b's', b't', b'I', b'D'];

pub const K_RANDOM_ID: [u8; 7] = [0x66, b'r', b'a', b'n', b'd', b'o', b'm'];

pub const K_ELEMENT_IDENTIFIER_PREFIX: [u8; 18] = [
    0x71, b'e', b'l', b'e', b'm', b'e', b'n', b't', b'I', b'd', b'e', b'n', b't', b'i', b'f', b'i',
    b'e', b'r',
];
pub const K_ELEMENT_VALUE_PREFIX: [u8; 13] = [
    0x6c, b'e', b'l', b'e', b'm', b'e', b'n', b't', b'V', b'a', b'l', b'u', b'e',
];

pub const K_SHA256_BLOCK_SIZE: usize = 64;
pub const K_SHA256_PADDING_LEN: usize = 9;
/// The maximum number of SHA-256 blocks for an attribute.
pub const K_MAX_ATTR_SHA_BLOCKS: usize = 2;
/// The maximum size of the `IssuerSignedItem` CBOR structure that fits in the
/// maximum number of blocks.
pub const K_MAX_ATTR_CBOR_LEN: usize =
    K_MAX_ATTR_SHA_BLOCKS * K_SHA256_BLOCK_SIZE - K_SHA256_PADDING_LEN; // 119
pub const K_ATTR_PREIMAGE_LEN: usize = K_MAX_ATTR_SHA_BLOCKS * K_SHA256_BLOCK_SIZE; // 128
