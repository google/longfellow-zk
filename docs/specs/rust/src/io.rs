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

use std::io::Read;

use crate::algebra::{Field, Subfield};

pub fn read_uleb128<R: Read>(reader: &mut R) -> std::io::Result<u64> {
    let mut val = 0u64;
    let mut shift = 0;
    loop {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        let byte = b[0];
        val |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    Ok(val)
}

pub fn zigzag_decode_delta(val: u64) -> isize {
    if val % 2 == 0 {
        (val >> 1) as isize
    } else {
        -((val >> 1) as isize) - 1
    }
}

pub fn read_size_4bytes<R: Read>(reader: &mut R) -> std::io::Result<usize> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    let val = u32::from_le_bytes(buf);
    Ok(val as usize)
}

pub fn write_size_4bytes<W: std::io::Write>(writer: &mut W, val: usize) -> std::io::Result<()> {
    writer.write_all(&(val as u32).to_le_bytes())
}

pub fn read_elt_field<F: Field, R: Read>(reader: &mut R) -> std::io::Result<F> {
    let mut buf = vec![0u8; F::serialized_size()];
    reader.read_exact(&mut buf)?;
    F::from_bytes(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

pub fn read_subfield_elt<F: Field + 'static, R: Read>(
    reader: &mut R,
    sf: &F::Subfield,
) -> std::io::Result<F> {
    let size = sf.subfield_serialized_size();
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    sf.from_subfield_bytes(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}
