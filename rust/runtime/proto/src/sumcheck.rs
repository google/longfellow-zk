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

//! Serialization and deserialization structures for Sumcheck proofs.
//!
//! This module defines the binary representation of a Sumcheck proof, designed
//! for compatibility with the C++ verifier.

use core_algebra::{ElementOf, SerializableField};

use crate::util::{read_elt_field, write_elt_field};

#[derive(Debug, Eq, PartialEq)]
pub struct RoundPoly<const W: usize, F: SerializableField> {
    pub evaluations: [F::E; 2],
}

impl<const W: usize, F: SerializableField> Clone for RoundPoly<W, F> {
    fn clone(&self) -> Self {
        Self {
            evaluations: self.evaluations.clone(),
        }
    }
}

pub use core_proto::{sane_logw, MAX_LOGW};

/// The proof of a single layer inside the circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerProof<const W: usize, F: SerializableField> {
    /// The round polynomials for each hand (right, left) in this layer.
    pub hp: [Vec<RoundPoly<W, F>>; 2],
    /// The final evaluated values of the layer, representing w(0) and w(1).
    pub claims: [ElementOf<F>; 2],
}

/// A complete Sumcheck proof, consisting of individual layer proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof<const W: usize, F: SerializableField> {
    /// The list of layer proofs, ordered from outputs to inputs.
    pub layers: Vec<LayerProof<W, F>>,
}

impl<const W: usize, F: SerializableField> SumcheckProof<W, F> {
    /// Deserializes a `SumcheckProof` from a raw byte buffer.
    ///
    /// The deserialization uses the provided `SumcheckProofGeometry` to
    /// determine the number of layers, variables, and hands, reading the
    /// expected number of field elements sequentially.
    pub fn read(
        bytes: &mut &[u8],
        geom: &SumcheckProofGeometry,
        f: &F,
    ) -> Result<Self, std::io::Error> {
        let mut total_len = 0usize;
        let elt_size = f.serialized_size_bytes();
        for &logw in &geom.logw_layers {
            if !sane_logw(logw) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Sumcheck layer logw {logw} exceeds MAX_LOGW {MAX_LOGW}"),
                ));
            }
            let cp_elts = 0usize;
            let hp_elts = logw.checked_mul(4).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Overflow computing hp elements",
                )
            })?;
            let layer_elts = cp_elts
                .checked_add(hp_elts)
                .and_then(|sum| sum.checked_add(2))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Overflow computing layer elements",
                    )
                })?;
            let layer_bytes = layer_elts.checked_mul(elt_size).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Overflow computing layer bytes",
                )
            })?;
            total_len = total_len.checked_add(layer_bytes).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Overflow computing total bytes",
                )
            })?;
        }

        if bytes.len() < total_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "SumcheckProof size mismatch: expected at least {} bytes, got {}",
                    total_len,
                    bytes.len()
                ),
            ));
        }

        let mut layers = Vec::with_capacity(geom.logw_layers.len());

        for &logw in &geom.logw_layers {
            let mut hp0 = Vec::with_capacity(logw);
            let mut hp1 = Vec::with_capacity(logw);
            for _ in 0..logw {
                let p0_0 = read_elt_field(bytes, f)?;
                let p1_0 = read_elt_field(bytes, f)?;
                let p0_2 = read_elt_field(bytes, f)?;
                let p1_2 = read_elt_field(bytes, f)?;
                hp0.push(RoundPoly {
                    evaluations: [p0_0, p0_2],
                });
                hp1.push(RoundPoly {
                    evaluations: [p1_0, p1_2],
                });
            }

            let c0 = read_elt_field(bytes, f)?;
            let c1 = read_elt_field(bytes, f)?;
            let claims = [c0, c1];

            layers.push(LayerProof {
                hp: [hp0, hp1],
                claims,
            });
        }

        Ok(SumcheckProof { layers })
    }

    /// Serializes the `SumcheckProof` to a byte vector.
    ///
    /// The serialization writes the coefficients of the copy polynomials, the
    /// non-middle coefficients of the hand polynomials, and the final
    /// checked values to the stream.
    pub fn write_to_buf(
        &self,
        bytes: &mut Vec<u8>,
        geom: &SumcheckProofGeometry,
        f: &F,
    ) -> Result<(), std::io::Error> {
        assert_eq!(
            self.layers.len(),
            geom.logw_layers.len(),
            "nlayers mismatch"
        );

        for ly in 0..geom.logw_layers.len() {
            let logw = geom.logw_layers[ly];
            if !sane_logw(logw) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Sumcheck layer logw {logw} exceeds MAX_LOGW {MAX_LOGW}"),
                ));
            }

            assert_eq!(
                self.layers[ly].hp[0].len(),
                logw,
                "logw mismatch for hp[0] at layer {ly}"
            );
            assert_eq!(
                self.layers[ly].hp[1].len(),
                logw,
                "logw mismatch for hp[1] at layer {ly}"
            );

            // 2. Serialize hand polynomials
            for r in 0..logw {
                for k in 0..2 {
                    for hand in 0..2 {
                        write_elt_field(bytes, &self.layers[ly].hp[hand][r].evaluations[k], f);
                    }
                }
            }
            // 3. Serialize final layer values claims
            for k in 0..2 {
                write_elt_field(bytes, &self.layers[ly].claims[k], f);
            }
        }

        Ok(())
    }

    pub fn write(&self, geom: &SumcheckProofGeometry, f: &F) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes = Vec::new();
        self.write_to_buf(&mut bytes, geom, f)?;
        Ok(bytes)
    }
}

/// The dimension and layer configuration (geometry) of a Sumcheck proof.
///
/// This metadata is required to correctly read or write a serialized proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumcheckProofGeometry {
    /// The logarithm of the input width (number of variables) for each layer.
    pub logw_layers: Vec<usize>,
}
