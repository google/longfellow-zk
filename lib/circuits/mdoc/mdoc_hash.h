// Copyright 2025 Google LLC.
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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/routing.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

static constexpr size_t kSHAPluckerBits = 4u;

// This class (only) verifies the hashing and pseudo-parsing of an mdoc.
// Specifically, it checks
//   (a) the hash of the mdoc matches its mac.
//   (b) the values dpk_{x,y} appear in approximate cbor form, and their macs
//       match the expected values
//   (c) validFrom, validUntil appear in approximate cbor form, and that
//         validFrom <= now <= validUntil
//   (d) For each expected attribute, there exists a preimage to a sha hash
//       that appears in the mso, the preimage is approximately cbor formatted,
//       and the preimage includes the expected attribute id and value.
template <class LogicCircuit, class Field>
class MdocHash {
  using v8 = typename LogicCircuit::v8;
  using v32 = typename LogicCircuit::v32;
  using v256 = typename LogicCircuit::v256;

  using vind = typename LogicCircuit::template bitvec<kCborIndexBits>;

  using Flatsha = FlatSHA256Circuit<LogicCircuit,
                                    BitPlucker<LogicCircuit, kSHAPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;

 public:
  // These structures mimic the similarly named structures in Witness, but
  // their members are circuit wire objects instead of size_t.
  struct OpenedAttribute {
    v8 attr[32]; /* 32b representing attribute name in be. */
    v8 v1[64];   /* 64b of attribute value */
  };
  struct CborIndex {
    vind k;
    void input(const LogicCircuit& lc) {
      k = lc.template vinput<kCborIndexBits>();
    }
  };

  struct AttrShift {
    vind offset;
    vind len;
    void input(const LogicCircuit& lc) {
      offset = lc.template vinput<kCborIndexBits>();
      len = lc.template vinput<kCborIndexBits>();
    }
  };

  class Witness {
   public:
    v8 in_[64 * kMaxSHABlocks]; /* input bytes, 64 * MAX */

    v8 nb_; /* index of sha block that contains the real hash  */
    ShaBlockWitness sig_sha_[kMaxSHABlocks];

    std::vector<std::vector<ShaBlockWitness>> attr_sha_;
    std::vector<std::vector<v8>> attrb_;

    CborIndex valid_from_, valid_until_;
    CborIndex dev_key_info_;
    CborIndex value_digests_;
    std::vector<CborIndex> attr_mso_;
    std::vector<AttrShift> attr_ei_;
    std::vector<AttrShift> attr_ev_;
    size_t num_attr_;

    explicit Witness(size_t num_attr) {
      num_attr_ = num_attr;
      attr_mso_.resize(num_attr);
      attr_ei_.resize(num_attr);
      attr_ev_.resize(num_attr);
      attr_sha_.resize(num_attr);
      for (size_t i = 0; i < num_attr; ++i) {
        attr_sha_[i].resize(2);
      }

      attrb_.resize(num_attr);
    }

    void input(QuadCircuit<Field>& Q, const LogicCircuit& lc) {
      nb_ = lc.template vinput<8>();

      // sha input init =========================
      for (size_t i = 0; i + kCose1PrefixLen < 64 * kMaxSHABlocks; ++i) {
        in_[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kMaxSHABlocks; j++) {
        sig_sha_[j].input(Q);
      }

      valid_from_.input(lc);
      valid_until_.input(lc);
      dev_key_info_.input(lc);
      value_digests_.input(lc);

      // // Attribute opening witnesses
      for (size_t ai = 0; ai < num_attr_; ++ai) {
        for (size_t i = 0; i < 64 * 2; ++i) {
          attrb_[ai].push_back(lc.template vinput<8>());
        }
        for (size_t j = 0; j < 2; j++) {
          attr_sha_[ai][j].input(Q);
        }
        attr_mso_[ai].input(lc);
        attr_ei_[ai].input(lc);
        attr_ev_[ai].input(lc);
      }
    }
  };

  explicit MdocHash(const LogicCircuit& lc) : lc_(lc), sha_(lc), r_(lc) {}

  void assert_valid_hash_mdoc(OpenedAttribute oa[/* NUM_ATTR */],
                              const v8 now[/*20*/], const v256& e,
                              const v256& dpkx, const v256& dpky,
                              const Witness& vw) const {
    sha_.assert_message_hash_with_prefix(kMaxSHABlocks, vw.nb_, vw.in_,
                                         kCose1Prefix, kCose1PrefixLen, e,
                                         vw.sig_sha_);

    // Shift a portion of the MSO into buf and check it.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings
    std::vector<v8> cmp_buf(kMaxMsoLen);
    const Memcmp<LogicCircuit> CMP(lc_);

    // In the shifting below, the +5 corresponds to the prefix
    // D8 18 <len2> prefix of the mso that we want to skip parsing.
    // The +2 corresponds to the length.

    // validFrom <= now
    r_.shift(vw.valid_from_.k, kValidFromLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidFromLen, &cmp_buf[0], kValidFromCheck);
    auto cmp = CMP.leq(kDateLen, &cmp_buf[kValidFromLen], &now[0]);
    lc_.assert1(cmp);

    // now <= validUntil
    r_.shift(vw.valid_until_.k, kValidUntilLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidUntilLen, &cmp_buf[0], kValidUntilCheck);
    cmp = CMP.leq(kDateLen, &now[0], &cmp_buf[kValidUntilLen]);
    lc_.assert1(cmp);

    // DPK_{x,y}
    r_.shift(vw.dev_key_info_.k, kDeviceKeyInfoLen + 3 + 32 + 32, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kDeviceKeyInfoLen, &cmp_buf[0], kDeviceKeyInfoCheck);
    uint8_t dpkyCheck[] = {0x22, 0x58, 0x20};
    assert_bytes_at(sizeof(dpkyCheck), &cmp_buf[65], dpkyCheck);

    assert_key(dpkx, &cmp_buf[kPkxInd]);
    assert_key(dpky, &cmp_buf[kPkyInd]);

    // Attributes parsing
    // valueDigests, ignore byte 13 \in {A1,A2} representing map size.
    r_.shift(vw.value_digests_.k, kValueDigestsLen, cmp_buf.data(), kMaxMsoLen,
             vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(13, &cmp_buf[0], kValueDigestsCheck);
    assert_bytes_at(18, &cmp_buf[14], &kValueDigestsCheck[14]);

    // Attributes: Equality of hash with MSO value
    for (size_t ai = 0; ai < vw.num_attr_; ++ai) {
      v8 B[96];
      // Check the hash matches the value in the signed MSO.
      r_.shift(vw.attr_mso_[ai].k, 2 + 32, &cmp_buf[0], kMaxMsoLen,
               vw.in_ + 5 + 2, zz, /*unroll=*/3);

      // Basic CBOR check of the Tag
      assert_bytes_at(2, &cmp_buf[0], kTag32);

      v256 mm;
      // The loop below accounts for endian and v256 vs v8 types.
      for (size_t j = 0; j < 256; ++j) {
        mm[j] = cmp_buf[2 + (255 - j) / 8][(j % 8)];
      }

      auto two = lc_.template vbit<8>(2);
      sha_.assert_message_hash(2, two, vw.attrb_[ai].data(), mm,
                               vw.attr_sha_[ai].data());

      // Check that the attribute_id and value occur in the hashed text.
      r_.shift(vw.attr_ei_[ai].offset, 96, B, 128, vw.attrb_[ai].data(), zz, 3);
      assert_attribute(96, vw.attr_ei_[ai].len, B, oa[ai]);
    }
  }

 private:
  void assert_bytes_at(size_t len, const v8 buf[/*>=len*/],
                       const uint8_t want[/*len*/]) const {
    for (size_t i = 0; i < len; ++i) {
      auto want_i = lc_.template vbit<8>(want[i]);
      lc_.vassert_eq(&buf[i], want_i);
    }
  }

  // Checks that an attribute id or attribute value is as expected.
  // The len parameter holds the byte length of the expected id or value.
  void assert_attribute(size_t max, const vind& len, const v8 got[/*max*/],
                        const OpenedAttribute& oa) const {
    // Copy the attribute id and value into a single array.
    v8 want[96];
    for (size_t j = 0; j < 32; ++j) {
      want[j] = oa.attr[j];
    }
    for (size_t j = 0; j < 64; ++j) {
      want[32 + j] = oa.v1[j];
    }

    // Perform an equality check on the first len bytes.
    for (size_t j = 0; j < max; ++j) {
      auto ll = lc_.vlt(j, len);
      auto same = lc_.eq(8, got[j].data(), want[j].data());
      lc_.assert_implies(&ll, same);
    }
  }

  // Asserts that the key is equal to the value in big-endian order in buf_be.
  void assert_key(v256 key, const v8 buf_be[/*32*/]) const {
    v256 m;
    for (size_t i = 0; i < 256; ++i) {
      m[i] = buf_be[31 - (i / 8)][i % 8];
    }
    lc_.vassert_eq(&m, key);
  }

  // The constants below define the prefix of each field that is verified
  // in the MDOC. This string matching approach is substantially faster than
  // parsing the MDOC into cbor, and its soundness analysis provides at least 96
  // bits of static security.  These constants differ from similarly named ones
  // in mdoc_constants because they include header bytes; the mdoc_constants
  // values are used for cbor parsing of the raw mdoc, whereas these are used by
  // the circuit.

  // 69 [text(9)] 76616C696446726F6D [validFrom] C0 [tag(0)] 74 [len 20]
  static constexpr uint8_t kValidFromCheck[] = {
      0x69, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x46, 0x72, 0x6F, 0x6D, 0xC0, 0x74};
  static constexpr size_t kValidFromLen = sizeof(kValidFromCheck);

  // 6A [text(10)] 76616C6964556E74696C [validUntil] C0 [tag(0)] 74
  static constexpr uint8_t kValidUntilCheck[] = {0x6A, 0x76, 0x61, 0x6C, 0x69,
                                                 0x64, 0x55, 0x6E, 0x74, 0x69,
                                                 0x6C, 0xC0, 0x74};
  static constexpr size_t kValidUntilLen = sizeof(kValidUntilCheck);

  // 6D text(13) 6465766963654B6579496E666F "deviceKeyInfo"
  //   A1 map(1) 69 text(9) 6465766963654B6579 "deviceKey"
  //      A4 map(4) 01 02 20 01
  //      21 negative(1) 58 20 bytes(32)
  //      <dpkx>
  //      22 negative(2) 58 20 bytes(32)
  //      <dpky>
  static constexpr uint8_t kDeviceKeyInfoCheck[] = {
      0x6D, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4B, 0x65, 0x79, 0x49,
      0x6E, 0x66, 0x6F, 0xA1, 0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
      0x4B, 0x65, 0x79, 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20};
  static constexpr size_t kDeviceKeyInfoLen = sizeof(kDeviceKeyInfoCheck);
  static constexpr size_t kPkxInd = kDeviceKeyInfoLen;
  static constexpr size_t kPkyInd = 68; /* 64 + 3 byte tag + 1*/

  // 6C text(12) 76616C756544696765737473  "valueDigests" A{1,2} # map(1,2)
  //     71 text(17) 6F72672E69736F2E31383031332E352E31 "org.iso.18013.5.1"
  static constexpr uint8_t kValueDigestsCheck[] = {
      0x6C, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x44, 0x69, 0x67,
      0x65, 0x73, 0x74, 0x73,
      0xA0,  // either {A1, A2}
      0x77,                                     // text(23)
      0x65, 0x75, 0x2E, 0x65, 0x75, 0x72, 0x6F,
      0x70, 0x61, 0x2E, 0x65, 0x63, 0x2E, 0x65,
      0x75, 0x64, 0x69, 0x2E, 0x70, 0x69, 0x64,
      0x2E, 0x31                                // "eu.europa.ec.eudi.pid.1"
  };
  static constexpr size_t kValueDigestsLen = sizeof(kValueDigestsCheck);

  static constexpr size_t kDateLen = 20;

  const LogicCircuit& lc_;
  Flatsha sha_;
  Routing<LogicCircuit> r_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
