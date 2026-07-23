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

use core_proto::SerializableField;
use runtime_algebra::{ElementOf, RuntimeField, Subfield};
use runtime_proto::{ZkProof, ZkProofGeometry};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdocProofGeometry {
    pub geom_hash: ZkProofGeometry,
    pub geom_sig: ZkProofGeometry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdocProof<F1: SerializableField, F2: SerializableField> {
    pub macs: [u128; 6],
    pub proof_hash: ZkProof<2, F1>,
    pub proof_sig: ZkProof<4, F2>,
}

impl<F1: RuntimeField<2> + SerializableField, F2: RuntimeField<4> + SerializableField>
    MdocProof<F1, F2>
{
    pub fn write<SF1: Subfield<E = ElementOf<F1>>, SF2: Subfield<E = ElementOf<F2>>>(
        &self,
        geom: &MdocProofGeometry,
        f1: &F1,
        sf1: &SF1,
        f2: &F2,
        sf2: &SF2,
    ) -> Result<Vec<u8>, String> {
        let mut proof_bytes = Vec::with_capacity(360_276);
        for m in &self.macs {
            proof_bytes.extend_from_slice(&m.to_le_bytes());
        }
        self.proof_hash
            .write_to_buf(&mut proof_bytes, &geom.geom_hash, f1, sf1)
            .map_err(|e| e.to_string())?;

        self.proof_sig
            .write_to_buf(&mut proof_bytes, &geom.geom_sig, f2, sf2)
            .map_err(|e| e.to_string())?;

        Ok(proof_bytes)
    }

    pub fn read<'a, SF1: Subfield<E = ElementOf<F1>>, SF2: Subfield<E = ElementOf<F2>>>(
        bytes: &'a [u8],
        geom: &MdocProofGeometry,
        f1: &F1,
        sf1: &SF1,
        f2: &F2,
        sf2: &SF2,
    ) -> Result<(&'a [u8], Self), String> {
        let mut remaining = bytes;
        if remaining.len() < 6 * 16 {
            return Err("Proof size too small for MACs".to_string());
        }
        let mut macs = [0u128; 6];
        for val in &mut macs {
            let chunk = &remaining[..16];
            *val = u128::from_le_bytes(chunk.try_into().unwrap());
            remaining = &remaining[16..];
        }

        let proof_hash = ZkProof::read(&mut remaining, &geom.geom_hash, f1, sf1)
            .map_err(|e| format!("Failed to read hash proof: {e:?}"))?;

        let proof_sig = ZkProof::read(&mut remaining, &geom.geom_sig, f2, sf2)
            .map_err(|e| format!("Failed to read signature proof: {e:?}"))?;

        Ok((
            remaining,
            Self {
                macs,
                proof_hash,
                proof_sig,
            },
        ))
    }
}

pub fn decompress_circuits(
    compressed: &[u8],
    p256: &runtime_algebra::p256::P256Field,
    gf2: &runtime_algebra::gf2_128::Gf2_128Field,
) -> Result<
    (
        core_proto::circuit::Circuit<runtime_algebra::p256::P256Field>,
        core_proto::circuit::Circuit<runtime_algebra::gf2_128::Gf2_128Field>,
    ),
    String,
> {
    let decompressed_bytes =
        zstd::decode_all(compressed).map_err(|e| format!("Failed to decompress circuits: {e}"))?;

    if decompressed_bytes.starts_with(core_proto::archive::LFA2_MAGIC) {
        let archive = core_proto::archive::CircuitArchive::from_bytes(&decompressed_bytes)?;

        let sig_entry = archive
            .get("sig")
            .ok_or_else(|| "Missing 'sig' entry in circuit archive".to_string())?;
        let reader_sig = core_proto::reader::CircuitReader::new(p256, core_proto::FieldID::P256);
        let (c_sig, _) = reader_sig.from_bytes(&sig_entry.payload, false)?;

        let hash_entry = archive
            .get("hash")
            .ok_or_else(|| "Missing 'hash' entry in circuit archive".to_string())?;
        let reader_hash = core_proto::reader::CircuitReader::new(gf2, core_proto::FieldID::Gf2_128);
        let (c_hash, _) = reader_hash.from_bytes(&hash_entry.payload, false)?;

        Ok((c_sig, c_hash))
    } else {
        let mut buf_stream = std::io::Cursor::new(&decompressed_bytes);

        let reader1 = core_proto::reader::CircuitReader::new(p256, core_proto::FieldID::P256);
        let c_sig = reader1.from_stream(&mut buf_stream, false)?;

        let reader2 = core_proto::reader::CircuitReader::new(gf2, core_proto::FieldID::Gf2_128);
        let c_hash = reader2.from_stream(&mut buf_stream, false)?;

        Ok((c_sig, c_hash))
    }
}
