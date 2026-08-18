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

#[derive(Debug, Clone, Copy)]
pub struct CborIndexVal {
    pub k: usize,
    pub v: usize,
}

#[derive(Debug, Clone)]
pub struct CborElement {
    pub value: CborValue,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub enum CborValue {
    Integer(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborElement>),
    Map(Vec<(CborElement, CborElement)>),
    Tag(u64, Box<CborElement>),
    Simple(u8),
    Float16(u16),
    Float32(u32),
    Float64(u64),
}

pub struct CborParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CborParser<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, String> {
        if self.offset >= self.data.len() {
            return Err("Unexpected EOF".to_string());
        }
        let b = self.data[self.offset];
        self.offset += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "CBOR length overflow".to_string())?;
        let res = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| "Unexpected EOF".to_string())?;
        self.offset = end;
        Ok(res)
    }

    fn parse_val(&mut self) -> Result<CborElement, String> {
        let start = self.offset;
        let b = self.read_byte()?;
        let major = b >> 5;
        let info = b & 0x1f;

        let val = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.read_byte()?),
            25 => {
                let bytes = self.read_bytes(2)?;
                u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
            _ => return Err(format!("Unsupported length info: {info}")),
        };

        let value = match major {
            0 => CborValue::Integer(i128::from(val)),
            1 => CborValue::Integer(-1 - i128::from(val)),
            2 => {
                let len = usize::try_from(val)
                    .map_err(|_| "CBOR byte string length does not fit usize".to_string())?;
                let bytes = self.read_bytes(len)?.to_vec();
                CborValue::Bytes(bytes)
            }
            3 => {
                let len = usize::try_from(val)
                    .map_err(|_| "CBOR text string length does not fit usize".to_string())?;
                let bytes = self.read_bytes(len)?;
                let s = String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())?;
                CborValue::Text(s)
            }
            4 => {
                let mut arr = Vec::new();
                for _ in 0..val {
                    arr.push(self.parse_val()?);
                }
                CborValue::Array(arr)
            }
            5 => {
                let mut map = Vec::new();
                for _ in 0..val {
                    let k = self.parse_val()?;
                    let v = self.parse_val()?;
                    map.push((k, v));
                }
                CborValue::Map(map)
            }
            6 => {
                let inner = self.parse_val()?;
                CborValue::Tag(val, Box::new(inner))
            }
            7 => match info {
                0..=23 => CborValue::Simple(info),
                24 => CborValue::Simple(
                    u8::try_from(val)
                        .map_err(|_| "CBOR simple value does not fit u8".to_string())?,
                ),
                25 => CborValue::Float16(
                    u16::try_from(val)
                        .map_err(|_| "CBOR half-float bits do not fit u16".to_string())?,
                ),
                26 => CborValue::Float32(
                    u32::try_from(val).map_err(|_| "CBOR float bits do not fit u32".to_string())?,
                ),
                27 => CborValue::Float64(val),
                _ => return Err(format!("Unsupported simple value info: {info}")),
            },
            _ => return Err(format!("Unsupported major type: {major}")),
        };

        let end = self.offset;
        Ok(CborElement { value, start, end })
    }

    pub fn parse_exact(&mut self) -> Result<CborElement, String> {
        let element = self.parse_val()?;
        if self.offset != self.data.len() {
            return Err(format!(
                "Trailing data after CBOR item: {} bytes",
                self.data.len() - self.offset
            ));
        }
        Ok(element)
    }
}

#[cfg(test)]
mod tests {
    use super::{CborParser, CborValue};

    fn parse_integer(data: &[u8]) -> i128 {
        let mut parser = CborParser::new(data);
        let element = parser.parse_exact().expect("test CBOR must be valid");
        let CborValue::Integer(value) = element.value else {
            panic!("test CBOR must be an integer");
        };
        value
    }

    #[test]
    fn parses_positive_and_negative_integers_semantically() {
        assert_eq!(parse_integer(&[0x00]), 0);
        assert_eq!(
            parse_integer(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            u64::MAX.into()
        );
        assert_eq!(parse_integer(&[0x20]), -1);
        assert_eq!(parse_integer(&[0x21]), -2);
        assert_eq!(
            parse_integer(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            -18_446_744_073_709_551_616
        );
    }

    #[test]
    fn parses_extended_simple_values() {
        let mut parser = CborParser::new(&[0xf8, 0x20]);
        let element = parser.parse_exact().expect("test CBOR must be valid");
        assert!(matches!(element.value, CborValue::Simple(32)));
    }

    #[test]
    fn preserves_floating_point_bits() {
        let mut half_parser = CborParser::new(&[0xf9, 0x3c, 0x00]);
        let half = half_parser
            .parse_exact()
            .expect("half-float CBOR must be valid");
        assert!(matches!(half.value, CborValue::Float16(0x3c00)));

        let mut single_parser = CborParser::new(&[0xfa, 0x3f, 0x80, 0x00, 0x00]);
        let single = single_parser
            .parse_exact()
            .expect("single-float CBOR must be valid");
        assert!(matches!(single.value, CborValue::Float32(0x3f80_0000)));

        let mut double_parser =
            CborParser::new(&[0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let double = double_parser
            .parse_exact()
            .expect("double-float CBOR must be valid");
        assert!(matches!(
            double.value,
            CborValue::Float64(0x3ff0_0000_0000_0000)
        ));
    }

    #[test]
    fn rejects_trailing_data_without_parsing_it() {
        let mut parser = CborParser::new(&[0x01, 0xff]);
        assert_eq!(
            parser
                .parse_exact()
                .expect_err("trailing data must be rejected"),
            "Trailing data after CBOR item: 1 bytes"
        );
    }
}
