use core_algebra::SerializableField;
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
use runtime_algebra::{p256::P256Field, Subfield};
use runtime_random::{RandomEngine, Transcript};

#[test]
fn test_transcript_cpp_compatibility() {
    let expected_bytes = include_bytes!("transcript_test_vector.bin");

    let init = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut ts = Transcript::new(&init);

    let field = P256Field::new();

    let mut offset = 0;
    for i in 0..100 {
        // 1. Write some bytes
        let mut data = [0u8; 64];
        for (j, cell) in data.iter_mut().enumerate() {
            *cell = (i * 7 + j * 13) as u8;
        }
        ts.write_bytes(&data);

        // 2. Write some zeros
        ts.write0(100 + i);

        // 3. Write single field element
        let mut elt_bytes = [0u8; 32];
        for (j, cell) in elt_bytes.iter_mut().enumerate() {
            *cell = (i * 17 + j * 19) as u8;
        }
        let elt = field.bytes_to_element(&elt_bytes).unwrap();
        ts.write_elt_field(&elt, &field);

        // 4. Write array of 5 field elements
        let mut elts = Vec::new();
        for k in 0..5 {
            let mut arr_elt_bytes = [0u8; 32];
            for (j, cell) in arr_elt_bytes.iter_mut().enumerate() {
                *cell = (i * 23 + k * 29 + j * 31) as u8;
            }
            let e = field.bytes_to_element(&arr_elt_bytes).unwrap();
            elts.push(e);
        }
        ts.write_elt_field_slice(&elts, &field);

        // 5. Generate pseudorandom bytes (256 bytes per iteration)
        let prf_buf = ts.bytes(256);

        let expected_chunk = &expected_bytes[offset..offset + 256];
        assert_eq!(prf_buf, expected_chunk, "Mismatch at iteration {i}");
        offset += 256;
    }
    assert_eq!(offset, expected_bytes.len());
}

#[test]
fn test_transcript_gf2_128_subfield_sampling() {
    let sf = runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let init = [1u8, 2, 3, 4];
    let mut ts = Transcript::new(&init);

    for _ in 0..100 {
        let val = ts.elt_subfield(&sf);
        assert!(sf.contains(&val), "Sampled value not in subfield");

        let bytes = sf.to_bytes(&val);
        let u = u64::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let embedded = sf.embed(u);
        assert_eq!(val, embedded, "Embed/to_bytes roundtrip failed");
    }
}

#[test]
fn test_transcript_clone_preserves_prng_state() {
    let mut ts = Transcript::new(b"test_clone_seed");
    ts.write_bytes(b"hello_world");

    // Draw initial 16 bytes
    let draw1 = ts.bytes(16);

    // Clone transcript mid-stream
    let mut ts_cloned = ts.clone();

    // Both original and clone should draw the EXACT SAME next 16 bytes (block 1, not block 0)
    let draw2_orig = ts.bytes(16);
    let draw2_clone = ts_cloned.bytes(16);

    assert_eq!(
        draw2_orig, draw2_clone,
        "Cloned transcript must preserve PRNG block counter state"
    );
    assert_ne!(
        draw1, draw2_orig,
        "Successive draws must produce unique bytes"
    );
}
