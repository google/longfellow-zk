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
    append_len(buf, 0x60, len);
}

/// Appends the CBOR byte string header (major type 2 / 0x40) for a given byte length to `buf`.
pub fn append_bytes_len(buf: &mut Vec<u8>, len: usize) {
    append_len(buf, 0x40, len);
}

fn append_len(buf: &mut Vec<u8>, major_type: u8, len: usize) {
    match len {
        0..=23 => buf.push(major_type | len as u8),
        24..=0xff => {
            buf.push(major_type | 24);
            buf.push(len as u8);
        }
        0x100..=0xffff => {
            buf.push(major_type | 25);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buf.push(major_type | 26);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
        _ => {
            buf.push(major_type | 27);
            buf.extend_from_slice(&(len as u64).to_be_bytes());
        }
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

#[cfg(test)]
mod tests {
    use super::{append_bytes_len, append_text_len};

    #[test]
    fn byte_string_length_boundaries() {
        let cases: &[(usize, &[u8])] = &[
            (23, &[0x57]),
            (24, &[0x58, 0x18]),
            (255, &[0x58, 0xff]),
            (256, &[0x59, 0x01, 0x00]),
            (65_535, &[0x59, 0xff, 0xff]),
            (65_536, &[0x5a, 0x00, 0x01, 0x00, 0x00]),
            (u32::MAX as usize, &[0x5a, 0xff, 0xff, 0xff, 0xff]),
        ];

        for &(len, expected) in cases {
            let mut encoded = Vec::new();
            append_bytes_len(&mut encoded, len);
            assert_eq!(encoded, expected, "incorrect encoding for length {len}");
        }
    }

    #[test]
    fn text_string_length_boundaries() {
        let cases: &[(usize, &[u8])] = &[
            (23, &[0x77]),
            (24, &[0x78, 0x18]),
            (255, &[0x78, 0xff]),
            (256, &[0x79, 0x01, 0x00]),
            (65_535, &[0x79, 0xff, 0xff]),
            (65_536, &[0x7a, 0x00, 0x01, 0x00, 0x00]),
            (u32::MAX as usize, &[0x7a, 0xff, 0xff, 0xff, 0xff]),
        ];

        for &(len, expected) in cases {
            let mut encoded = Vec::new();
            append_text_len(&mut encoded, len);
            assert_eq!(encoded, expected, "incorrect encoding for length {len}");
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn string_length_above_u32() {
        let len = u32::MAX as usize + 1;

        let mut bytes = Vec::new();
        append_bytes_len(&mut bytes, len);
        assert_eq!(bytes, [0x5b, 0, 0, 0, 1, 0, 0, 0, 0]);

        let mut text = Vec::new();
        append_text_len(&mut text, len);
        assert_eq!(text, [0x7b, 0, 0, 0, 1, 0, 0, 0, 0]);
    }
}
