use std::io::{Error, ErrorKind, Result};

use core_algebra::{ElementOf, SerializableField};
use runtime_algebra::Subfield;

/// Helper to read a single serialized field element.
pub fn read_elt_field<F: SerializableField>(bytes: &mut &[u8], f: &F) -> Result<ElementOf<F>> {
    let elt_size = f.serialized_size_bytes();
    if elt_size > bytes.len() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "EOF reading proof element",
        ));
    }
    let (chunk, rem) = bytes.split_at(elt_size);
    *bytes = rem;
    let elt = f
        .bytes_to_element(chunk)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{e:?}")))?;
    Ok(elt)
}

/// Helper to read a vector of field elements.
pub fn read_vec_field<F: SerializableField>(
    bytes: &mut &[u8],
    n: usize,
    f: &F,
) -> Result<Vec<ElementOf<F>>> {
    let mut vec = Vec::with_capacity(n);
    for _ in 0..n {
        let elt = read_elt_field(bytes, f)?;
        vec.push(elt);
    }
    Ok(vec)
}

/// Helper to serialize and write a single field element.
pub fn write_elt_field<F: SerializableField>(bytes: &mut Vec<u8>, e: &ElementOf<F>, f: &F) {
    let len = f.serialized_size_bytes();
    let start = bytes.len();
    bytes.resize(start + len, 0);
    f.to_bytes_into(e, &mut bytes[start..]);
}

pub fn write_subfield_elt<SF: Subfield>(bytes: &mut Vec<u8>, x: &SF::E, sf: &SF) -> Result<()> {
    if !sf.contains(x) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "element not in subfield",
        ));
    }
    let len = sf.serialized_size_bytes();
    let start = bytes.len();
    bytes.resize(start + len, 0);
    sf.to_bytes_into(x, &mut bytes[start..]);
    Ok(())
}

/// Helper to read a subfield element.
pub fn read_subfield_elt<SF: Subfield>(bytes: &mut &[u8], sf: &SF) -> Result<SF::E> {
    let size = sf.serialized_size_bytes();
    if size > bytes.len() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "EOF reading subfield element",
        ));
    }
    let (chunk, rem) = bytes.split_at(size);
    *bytes = rem;
    let elt = sf.bytes_to_element(chunk).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to parse subfield element: {e:?}"),
        )
    })?;
    Ok(elt)
}

/// Helper to write size (4 bytes).
pub fn write_size_4bytes(bytes: &mut Vec<u8>, val: usize) {
    bytes.extend_from_slice(&(val as u32).to_le_bytes());
}

/// Helper to read size (4 bytes).
pub fn read_size_4bytes(bytes: &mut &[u8]) -> Result<usize> {
    if 4 > bytes.len() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "EOF reading size"));
    }
    let (chunk, rem) = bytes.split_at(4);
    *bytes = rem;
    let val = u32::from_le_bytes(chunk.try_into().unwrap());
    Ok(val as usize)
}

/// Helper to read exactly 32 bytes (for digests and nonces).
pub fn read_bytes_32(bytes: &mut &[u8]) -> Result<[u8; 32]> {
    if 32 > bytes.len() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "EOF reading 32 bytes"));
    }
    let (chunk, rem) = bytes.split_at(32);
    *bytes = rem;
    Ok(chunk.try_into().unwrap())
}

/// Helper to fake a zero element using deserialization of all-zeros buffer.
pub fn zero_field_element<F: SerializableField>(f: &F) -> Result<ElementOf<F>> {
    let zero_bytes = vec![0u8; f.serialized_size_bytes()];
    f.bytes_to_element(&zero_bytes).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to fake zero element: {e:?}"),
        )
    })
}
