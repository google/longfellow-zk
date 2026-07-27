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

use std::io::BufRead;

/// Serializes a `usize` value as a standard ULEB128 byte sequence.
#[inline]
pub fn serialize_uleb128(bytes: &mut Vec<u8>, mut val: usize) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
            bytes.push(byte);
        } else {
            bytes.push(byte);
            break;
        }
    }
}

/// Reads a standard ULEB128 `usize` value from a `BufRead` stream.
#[inline]
pub fn read_uleb128<R: BufRead>(stream: &mut R) -> Result<usize, String> {
    let mut val: usize = 0;
    let mut shift = 0;
    for _ in 0..8 {
        let mut b = [0u8; 1];
        stream
            .read_exact(&mut b)
            .map_err(|_| "Unexpected EOF reading ULEB128".to_string())?;
        let byte = b[0];
        val |= ((byte & 0x7F) as usize) << shift;
        if (byte & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
    Err("ULEB128 value too large".to_string())
}

/// High-performance 4-byte max ULEB128 serializer for circuit deltas.
#[inline(always)]
pub fn serialize_uleb128_max4_u32(bytes: &mut Vec<u8>, mut val: u32) {
    assert!(
        val <= 0x0FFF_FFFF,
        "ULEB128 max 4 bytes limit exceeded: val {val} > 0x0FFF_FFFF"
    );
    for _ in 0..4 {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            bytes.push(byte);
            break;
        }
        bytes.push(byte | 0x80);
    }
}

/// High-performance 4-byte max ULEB128 serializer for circuit layer dimensions (`usize`).
#[inline(always)]
pub fn serialize_uleb128_max4(bytes: &mut Vec<u8>, val: usize) {
    assert!(
        val <= 0x0FFF_FFFF,
        "ULEB128 max 4 bytes limit exceeded: val {val} > 0x0FFF_FFFF"
    );
    serialize_uleb128_max4_u32(bytes, val as u32);
}

/// High-performance zero-copy 4-byte max ULEB128 reader for circuit deltas.
#[inline(always)]
pub fn read_uleb128_max4_u32<R: BufRead>(stream: &mut R) -> Result<u32, String> {
    let buf = stream
        .fill_buf()
        .map_err(|e| format!("Stream read error: {e}"))?;
    if !buf.is_empty() {
        let b0 = buf[0];
        if b0 < 0x80 {
            stream.consume(1);
            return Ok(u32::from(b0));
        }
        if buf.len() >= 2 {
            let b1 = buf[1];
            if b1 < 0x80 {
                let val = u32::from(b0 & 0x7F) | (u32::from(b1) << 7);
                if val > 0x0FFF_FFFF {
                    return Err(format!("ULEB128 value {val} exceeds max 28 bits payload"));
                }
                stream.consume(2);
                return Ok(val);
            }
            if buf.len() >= 3 {
                let b2 = buf[2];
                if b2 < 0x80 {
                    let val =
                        u32::from(b0 & 0x7F) | (u32::from(b1 & 0x7F) << 7) | (u32::from(b2) << 14);
                    if val > 0x0FFF_FFFF {
                        return Err(format!("ULEB128 value {val} exceeds max 28 bits payload"));
                    }
                    stream.consume(3);
                    return Ok(val);
                }
                if buf.len() >= 4 {
                    let b3 = buf[3];
                    if b3 < 0x80 {
                        let val = u32::from(b0 & 0x7F)
                            | (u32::from(b1 & 0x7F) << 7)
                            | (u32::from(b2 & 0x7F) << 14)
                            | (u32::from(b3) << 21);
                        if val > 0x0FFF_FFFF {
                            return Err(format!("ULEB128 value {val} exceeds max 28 bits payload"));
                        }
                        stream.consume(4);
                        return Ok(val);
                    }
                }
            }
        }
    }
    // Fallback when near buffer boundary or > 4 bytes
    let mut result = 0u32;
    let mut shift = 0;
    let mut byte_buf = [0u8; 1];
    for _ in 0..4 {
        stream
            .read_exact(&mut byte_buf)
            .map_err(|e| format!("Failed to read ULEB128 byte: {e}"))?;
        let byte = byte_buf[0];
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            if result > 0x0FFF_FFFF {
                return Err(format!(
                    "ULEB128 value {result} exceeds max 28 bits payload"
                ));
            }
            return Ok(result);
        }
        shift += 7;
    }
    Err("ULEB128 value exceeded 4 bytes (max 28 bits payload)".to_string())
}

/// High-performance 4-byte max ULEB128 reader returning `usize`.
#[inline(always)]
pub fn read_uleb128_max4<R: BufRead>(stream: &mut R) -> Result<usize, String> {
    read_uleb128_max4_u32(stream).map(|v| v as usize)
}

/// Calculates output byte length of a u32 ULEB128.
#[inline(always)]
pub fn uleb128_len_u32(mut val: u32) -> u32 {
    let mut len = 1;
    while val >= 0x80 {
        val >>= 7;
        len += 1;
    }
    len
}
