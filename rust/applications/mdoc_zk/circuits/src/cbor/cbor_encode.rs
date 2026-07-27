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

/// Appends the CBOR text string header (major type 3 / 0x60) for a given byte length to `buf`.
pub fn append_text_len(buf: &mut Vec<u8>, len: usize) {
    if len < 24 {
        buf.push(0x60 + len as u8);
    } else if len < 256 {
        buf.extend_from_slice(&[0x78, len as u8]);
    } else {
        buf.extend_from_slice(&[0x79, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8]);
    }
}

/// Appends the CBOR byte string header (major type 2 / 0x40) for a given byte length to `buf`.
pub fn append_bytes_len(buf: &mut Vec<u8>, len: usize) {
    if len < 24 {
        buf.push(0x40 + len as u8);
    } else if len < 256 {
        buf.extend_from_slice(&[0x58, len as u8]);
    } else {
        buf.extend_from_slice(&[0x59, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8]);
    }
}

/// Encodes a slice of bytes as a CBOR text string into an existing buffer.
pub fn encode_cbor_string_into(s: &[u8], buf: &mut Vec<u8>) {
    append_text_len(buf, s.len());
    buf.extend_from_slice(s);
}

/// Encodes a slice of bytes as a CBOR text string and returns a new Vec<u8>.
#[must_use]
pub fn encode_cbor_string(s: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + s.len());
    encode_cbor_string_into(s, &mut buf);
    buf
}
