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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/cbor_parser/cbor_byte_decoder.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/routing.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/hmac_circuit.h"

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
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using v32 = typename LogicCircuit::v32;
  using v64 = typename LogicCircuit::v64;
  using v256 = typename LogicCircuit::v256;

  using vind = typename LogicCircuit::template bitvec<kCborIndexBits>;

  using Flatsha = FlatSHA256Circuit<LogicCircuit,
                                    BitPlucker<LogicCircuit, kSHAPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;
  
  using Hmac = HMAC_Circuit<LogicCircuit, BitPlucker<LogicCircuit, kSHAPluckerBits>>;

 public:
  // These structures mimic the similarly named structures in Witness, but
  // their members are circuit wire objects instead of size_t.
  struct OpenedAttribute {
    v8 attr[32]; /* 32b representing attribute name in be. */
    v8 v1[64];   /* 64b of attribute value */
    // NOTE: although these arrays are sized {32,64}, other aspects of the
    // system constrain the sum of the elementIdentifier and elementValue to be
    // at most 56 bytes for a proof to succeed.  We will maintain this API, but
    // publish the constraint about the sum in the documentation.
    v8 len;      /* public length of the encoded attribute id */
    v8 vlen;     /* public length of the encoded attribute value */
    void input(const LogicCircuit& lc) {
      for (size_t j = 0; j < 32; ++j) {
        attr[j] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < 64; ++j) {
        v1[j] = lc.template vinput<8>();
      }
      len = lc.template vinput<8>();
      vlen = lc.template vinput<8>();
    }
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

  struct SaltedHash {
    vind i1, i2, i3;
    vind l[4];
    v8 perm;
    void input(const LogicCircuit& lc) {
      i1 = lc.template vinput<kCborIndexBits>();
      i2 = lc.template vinput<kCborIndexBits>();
      i3 = lc.template vinput<kCborIndexBits>();
      for (size_t j = 0; j < 4; ++j) {
        l[j] = lc.template vinput<kCborIndexBits>();
      }
      perm = lc.template vinput<8>();
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
    std::vector<SaltedHash> salted_hashes_;
    size_t num_attr_;

    explicit Witness(size_t num_attr) {
      num_attr_ = num_attr;
      attr_mso_.resize(num_attr);
      attr_ei_.resize(num_attr);
      attr_ev_.resize(num_attr);
      attr_sha_.resize(num_attr);
      salted_hashes_.resize(num_attr);
      for (size_t i = 0; i < num_attr; ++i) {
        attr_sha_[i].resize(2);
      }
      attrb_.resize(num_attr);
    }

    v8 ppid_inner_nb_;
    v8 ppid_seed_[32];
    v8 ppid_inner_padded_m_[9 * 64]; // max 513 bytes padding
    ShaBlockWitness ppid_inner_bw_[10];
    ShaBlockWitness ppid_outer_bw_[2];

    void input(const LogicCircuit& lc, size_t version = 7) {
      nb_ = lc.template vinput<8>();

      // sha input init =========================
      for (size_t i = 0; i + kCose1PrefixLen < 64 * kMaxSHABlocks; ++i) {
        in_[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kMaxSHABlocks; j++) {
        sig_sha_[j].input(lc);
      }

      valid_from_.input(lc);
      valid_until_.input(lc);
      dev_key_info_.input(lc);
      value_digests_.input(lc);

      // Attribute opening witnesses
      for (size_t ai = 0; ai < num_attr_; ++ai) {
        for (size_t i = 0; i < 64 * 2; ++i) {
          attrb_[ai].push_back(lc.template vinput<8>());
        }
        for (size_t j = 0; j < 2; j++) {
          attr_sha_[ai][j].input(lc);
        }
        attr_mso_[ai].input(lc);
        attr_ei_[ai].input(lc);
        attr_ev_[ai].input(lc);
        salted_hashes_[ai].input(lc);
      }

      if (version >= 8) {
        ppid_inner_nb_ = lc.template vinput<8>();
        for (size_t i = 0; i < 32; ++i) {
          ppid_seed_[i] = lc.template vinput<8>();
        }
        for (size_t i = 0; i < 9 * 64; ++i) {
          ppid_inner_padded_m_[i] = lc.template vinput<8>();
        }
        for (size_t i = 0; i < 10; ++i) {
          ppid_inner_bw_[i].input(lc);
        }
        for (size_t i = 0; i < 2; ++i) {
          ppid_outer_bw_[i].input(lc);
        }
      }
    }
  };

  explicit MdocHash(const LogicCircuit& lc)
      : lc_(lc), sha_(lc), r_(lc), cb_(lc), hmac_(lc, sha_) {}

  void assert_valid_hash_mdoc(OpenedAttribute oa[/* NUM_ATTR */],
                              const v8 now[/*20*/], const v256& e,
                              const v256& dpkx, const v256& dpky,
                              const Witness& vw, size_t version,
                              const v8 verifier_id[32],
                              const v8 ppid_context[32]) const {
    v256 hmac_out_v256;
    if (version >= 8) {
        // Construct data = verifier_id || context (32 bytes + 32 bytes = 64 bytes)
        v8 hmac_data[64];
        for (size_t i = 0; i < 32; ++i) {
            hmac_data[i] = verifier_id[i];
            hmac_data[32 + i] = ppid_context[i];
        }
        
        // Verify that the prover's inner_padded_m starts with hmac_data
        auto true_cond = lc_.template vbit<1>(1);
        for (size_t k = 0; k < 64; ++k) {
            auto match = lc_.eq(8, hmac_data[k].data(), vw.ppid_inner_padded_m_[k].data());
            lc_.assert_implies(true_cond.data(), match);
        }

        // Compute HMAC(seed, hmac_data, total_len)
        v8 padded_key[64];
        auto zero8 = lc_.template vbit<8>(0);
        for(size_t i = 0; i < 32; ++i) padded_key[i] = vw.ppid_seed_[i];
        for(size_t i = 32; i < 64; ++i) padded_key[i] = zero8;

        // Since the data is exactly 64 bytes, the padded length for the inner SHA
        // requires 128 bytes of data (64 byte K_ipad + 64 byte payload)
        // Pad for 1024 bits: + 0x80, + 0s, + (0x0400 length). That takes 64 more bytes.
        // Total padded inner message = 192 bytes = 3 blocks.
        // The padded part after the first 64 bytes is provided via vw.ppid_inner_padded_m_
        hmac_out_v256 = hmac_.compute_hmac(padded_key, 3, vw.ppid_inner_nb_, vw.ppid_inner_padded_m_, vw.ppid_inner_bw_, vw.ppid_outer_bw_);
    } else {
        auto zero1 = lc_.template vbit<1>(0)[0];
        for (size_t i = 0; i < 256; ++i) hmac_out_v256[i] = zero1;
    }

    auto preimage = construct_signature_preimage(vw);
    lc_.vassert_is_bit(vw.nb_);
    lc_.vleq(vw.nb_, kMaxSHABlocks);
    sha_.assert_message_hash(kMaxSHABlocks, vw.nb_, preimage.data(), e,
                             vw.sig_sha_);

    // Find the length of the MSO in bytes. Use this to range check each index.
    v64 len = sha_.find_len(kMaxSHABlocks, preimage.data(), vw.nb_);

    // Shift a portion of the MSO into buf and check it.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings
    std::vector<v8> cmp_buf(kMaxMsoLen);
    const Memcmp<LogicCircuit> CMP(lc_);

    // In the shifting below, the +5 corresponds to the prefix
    // D8 18 <len2> prefix of the mso that we want to skip parsing.
    // The +2 corresponds to the length.

    // validFrom <= now
    check_index(vw.valid_from_.k, len);
    r_.shift(vw.valid_from_.k, kValidFromLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidFromLen, &cmp_buf[0], kValidFromCheck);
    auto cmp = CMP.leq(kDateLen, &cmp_buf[kValidFromLen], &now[0]);
    lc_.assert1(cmp);

    // now <= validUntil
    check_index(vw.valid_until_.k, len);
    r_.shift(vw.valid_until_.k, kValidUntilLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidUntilLen, &cmp_buf[0], kValidUntilCheck);
    cmp = CMP.leq(kDateLen, &now[0], &cmp_buf[kValidUntilLen]);
    lc_.assert1(cmp);

    // DPK_{x,y}
    check_index(vw.dev_key_info_.k, len);
    r_.shift(vw.dev_key_info_.k, kDeviceKeyInfoLen + 3 + 32 + 32, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kDeviceKeyInfoLen, &cmp_buf[0], kDeviceKeyInfoCheck);
    uint8_t dpkyCheck[] = {0x22, 0x58, 0x20};
    assert_bytes_at(sizeof(dpkyCheck), &cmp_buf[65], dpkyCheck);

    assert_key(dpkx, &cmp_buf[kPkxInd]);
    assert_key(dpky, &cmp_buf[kPkyInd]);

    // Attributes parsing
    // valueDigests, ignore byte 13 \in {A1,A2} representing map size.
    check_index(vw.value_digests_.k, len);
    r_.shift(vw.value_digests_.k, kValueDigestsLen, cmp_buf.data(), kMaxMsoLen,
             vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(13, &cmp_buf[0], kValueDigestsCheck);

    // Attributes: Equality of hash with MSO value.

    for (size_t ai = 0; ai < vw.num_attr_; ++ai) {
      // Recall that the MSO contains a hash value e2 where
      //   e2 = hash( cbor.bstr( IssuerSignedItem ))
      // and IssuerSignedItem is a CBOR structure defined as:
      // IssuerSignedItem = {
      //     "digestID" : uint,
      //     "random" : bstr,
      //     "elementIdentifier" : DataElementIdentifier,
      //     "elementValue" : DataElementValue };
      // The order of the elements in the IssuerSignedItem is not specified.
      //
      // The constraints below verify the following:
      //     1. the index attr_mso_[ai].k < len(mso)
      //     2. a 32-byte cbor array e2 occurs at index attr_mso_[ai].k in mso
      //     -- attrb_[ai] is a SHA-256 length-padded 128-byte witness array
      //     3. e2 = hash(attrb_[ai].data())
      //     4. sl is the length of attrb_[ai] as per the SHA-256 padding rule
      //     5. The attrb_[ai] array is well-formed cbor that includes the
      //        expected elementIdentifier, and elementValue fields as per the
      //        public oa[ai] argument.
      check_index(vw.attr_mso_[ai].k, len);
      r_.shift(vw.attr_mso_[ai].k, 2 + 32, &cmp_buf[0], kMaxMsoLen,
               vw.in_ + 5 + 2, zz, /*unroll=*/3);

      // 2. Basic CBOR check of the Tag
      assert_bytes_at(2, &cmp_buf[0], kTag32);

      v256 mm;
      // The loop below accounts for endian and v256 vs v8 types.
      for (size_t j = 0; j < 256; ++j) {
        mm[j] = cmp_buf[2 + (255 - j) / 8][(j % 8)];
      }
      lc_.vassert_is_bit(mm);

      // 3. Check the hash matches the value in the witness.
      auto two = lc_.template vbit<8>(2);
      sha_.assert_message_hash(2, two, vw.attrb_[ai].data(), mm,
                               vw.attr_sha_[ai].data());

      // 4. Check the length of the witness.
      v64 salted_len = sha_.find_len(2, vw.attrb_[ai].data(), two);

      // 5. Check the attribute is well-formed and matches the public argument.
      assert_attribute(128, vw.attrb_[ai].data(), vw.salted_hashes_[ai], oa[ai],
                       salted_len, version, hmac_out_v256, vw);
    }
  }

 private:
  std::vector<v8> construct_signature_preimage(const Witness& vw) const {
    std::vector<v8> bbuf(64 * kMaxSHABlocks);
    for (size_t i = 0; i < 64 * kMaxSHABlocks; ++i) {
      if (i < kCose1PrefixLen) {
        lc_.bits(8, bbuf[i].data(), kCose1Prefix[i]);
      } else {
        bbuf[i] = vw.in_[i - kCose1PrefixLen];
      }
    }
    return bbuf;
  }

  vind extract_vind(v64 len) const {
    auto low = lc_.template slice<0, 3>(len);
    auto mid = lc_.template slice<3, 3 + kCborIndexBits>(len);
    auto hi = lc_.template slice<3 + kCborIndexBits, 64>(len);
    // Because check_index is called on several indices, the following two
    // checks will be called several times. However, the compiler removes
    // redundant checks, and it is convenient to verify the ranges in one
    // function. An alternative would be to verify the low 3 bits of len
    // and upper 40+ bits of len are 0, and then rely on that invariant in
    // this method, but that separates the logic, and this is easier to audit.
    lc_.vassert0(low);
    lc_.vassert0(hi);
    return mid;
  }

  // Checks that the index is less than the length. The len is given as bits
  // in a v64 in big endian order, and the index is given as a byte index.
  void check_index(vind index, v64 len) const {
    lc_.vassert_is_bit(index);
    auto mid = extract_vind(len);
    lc_.assert1(lc_.vlt(&index, mid));
  }

  void assert_bytes_at(size_t len, const v8 buf[/*>=len*/],
                       const uint8_t want[/*len*/]) const {
    for (size_t i = 0; i < len; ++i) {
      auto want_i = lc_.template vbit<8>(want[i]);
      lc_.vassert_eq(&buf[i], want_i);
    }
  }

  void format_element(v8 buf[/*max*/], size_t max,
                      const uint8_t prefix[/*prefix_len*/], size_t prefix_len,
                      const v8 str[/*str_len*/], size_t str_len) const {
    for (size_t i = 0; i < max; ++i) {
      buf[i] = lc_.template vbit<8>(0);
    }
    for (size_t i = 0; i < prefix_len; ++i) {
      buf[i] = lc_.template vbit<8>(prefix[i]);
    }
    for (size_t i = 0; i < str_len && prefix_len + i < max; ++i) {
      buf[prefix_len + i] = str[i];
    }
  }

  // This function verifies that the length of a cbor key-value pair in an array
  // matches the claimed length.
  //    key_len: the length of the key with its header byte included.
  //    val_hdr_index: the index of the value's cbor header
  //                   byte in the buffer.
  //    atom:  true if the value is an atom, e.g., the digestID.
  //           false it is a string or array.
  void check_cbor_length(const v8 buf[/*max*/], size_t max,
                         const vind& expected_len, size_t val_hdr_index,
                         bool atom = false) const {
    // The length of a key-value field for a known key will be:
    // len(encoding of key) + len(key) + len(header of value) + len(value)

    auto cbor = cb_.decode_one_v8(buf[val_hdr_index]);
    lc_.assert0(cbor.invalid);

    vind l1 = lc_.template vbit<kCborIndexBits>(0),  // len of value
        l2 = lc_.template vbit<kCborIndexBits>(0);   // len of header of value
    vind one = lc_.template vbit<kCborIndexBits>(1),
         two = lc_.template vbit<kCborIndexBits>(2);
    if (!atom) {
      // Mux the length of the value into l1.
      // In this case, the value is either encoded in the last 5 bits of the
      // header byte, or in the next byte.  The array length is < 256 by
      // external constraints, and thus its length is in 1 or 2 bytes.
      for (size_t j = 0; j < 8; ++j) {
        l1[j] = lc_.mux(&cbor.length_plus_next_v8, &buf[val_hdr_index + 1][j],
                        j < 5 ? buf[val_hdr_index][j] : lc_.bit(0));
      }
      lc_.vmux(cbor.length_plus_next_v8, l2, two, one);
    } else {
      // For atoms, the value length is zero. The header length is 1,2,3, or 5
      // because the digestID is constrained to be < 2^31 [18013-5, 9.1.2.4].
      lc_.assert0(cbor.count27);
      l2[2] = cbor.count26;
      l2[1] = lc_.lor(&cbor.count24, cbor.count25);
      l2[0] = lc_.lnot(cbor.count24);
    }

    // Compute the read length.
    vind k_len = lc_.template vbit<kCborIndexBits>(val_hdr_index);
    vind v_len = lc_.template vadd<kCborIndexBits>(l1, l2);
    lc_.assert_sum(kCborIndexBits, expected_len.data(), k_len.data(),
                   v_len.data());
  }

  // assert_attribute checks that the bytes in buf correspond to a valid
  // cbor structure that encodes the OpenedAttribute oa.
  void assert_attribute(size_t max, const v8 buf[/*max*/], const SaltedHash& sh,
                        const OpenedAttribute& oa, const v64 salted_len,
                        size_t version, const v256& hmac_out, const Witness& vw) const {
    // Perform a cbor parsing of the buffer, which is expected to be
    // a 4-element key-value array consisting of keys digestId, random,
    // elementIdentifier, and elementValue. Then perform a check on the
    // last two.  The complexity of check stems from the fact that the 4 pairs
    // can occur in any order.
    // The prover provides the following witnesses in SaltedHash:
    // -- (5, l0), (i1, l1), (i2, l2), (i3, l3)
    //    where li is the length of the i-th element in bytes.
    // -- j7j6 j5j4 j3j2 j1j0 where ji \in {0,1}, and
    //    j1j0: specifies the index in the previous array of digestId
    //    j3j2: specifies the index in the previous array of random
    //    j5j4: specifies the index in the previous array of elementIdentifier
    //    j7j6: specifies the index in the previous array of elementValue

    // Verify the cbor prefix for IssuerSignedItem.
    static const uint8_t cbor_tag[] = {0xD8, 0x18, 0x58};
    static const uint8_t cbor_array[] = {0xA4};
    assert_bytes_at(3, buf, cbor_tag);
    assert_bytes_at(1, &buf[4], cbor_array);

    // Verify all of the indices and lengths are contiguous and consistent.
    vind five = lc_.template vbit<kCborIndexBits>(5);
    vind tot = extract_vind(salted_len);
    lc_.assert_sum(kCborIndexBits, sh.i1.data(), five.data(), sh.l[0].data());
    lc_.assert_sum(kCborIndexBits, sh.i2.data(), sh.i1.data(), sh.l[1].data());
    lc_.assert_sum(kCborIndexBits, sh.i3.data(), sh.i2.data(), sh.l[2].data());
    lc_.assert_sum(kCborIndexBits, tot.data(), sh.i3.data(), sh.l[3].data());

    // Verify expected structure of the salted hash cbor array.
    vind shift, len;
    const size_t MAX_BUF = 119;
    v8 got[MAX_BUF];  // Max buffer length for a 2-block SHA hash.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings

    // Shift each of the 4 fields into place, and perform consistency checks.
    // "digestID" checks the cbor key and consistency with the total length.
    mux_offset(0, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    assert_bytes_at(kDigestLen, &got[0], kDigestID);
    check_cbor_length(got, MAX_BUF, len, 9, true);

    // "random" checks the cbor key and consistency with the total length.
    mux_offset(1, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    assert_bytes_at(kRandomLen, &got[0], kRandomID);
    check_cbor_length(got, MAX_BUF, len, 7);

    const size_t MAX_EI =
        1 + 17 + 32;  // The 32/64 includes len of any headers.
    const size_t MAX_EV = 1 + 12 + 64;
    v8 want_ei[MAX_EI], want_ev[MAX_EV];
    uint8_t ei_bytes[] = {0x60 + 17, 'e', 'l', 'e', 'm', 'e', 'n', 't', 'I',
                          'd',       'e', 'n', 't', 'i', 'f', 'i', 'e', 'r'};
    uint8_t ev_bytes[] = {0x60 + 12, 'e', 'l', 'e', 'm', 'e', 'n',
                          't',       'V', 'a', 'l', 'u', 'e'};
    format_element(want_ei, MAX_EI, ei_bytes, sizeof(ei_bytes), oa.attr, 32);
    format_element(want_ev, MAX_EV, ev_bytes, sizeof(ev_bytes), oa.v1, 64);

    // Check if this is a pseudonym_seed attribute (in MSO) but requested as pairwise_pseudonym
    auto is_ppid = lc_.template vbit<1>(0);
    // The public requested attribute (oa.attr) must match pairwise_pseudonym for this to be valid.
    if (version >= 8) {
      uint8_t ppid_id[] = {'p', 'a', 'i', 'r', 'w', 'i', 's', 'e', '_', 'p', 's', 'e', 'u', 'd', 'o', 'n', 'y', 'm'};
      auto ppid_match = lc_.template vbit<1>(1)[0];
      
      // Check the text string prefix byte (0x60 + 18 = 0x72)
      auto expected_prefix = lc_.template vbit<8>(0x72);
      auto e_prefix = lc_.eq(8, oa.attr[0].data(), expected_prefix.data());
      ppid_match = lc_.land(&ppid_match, e_prefix);
      
      for (size_t j = 0; j < sizeof(ppid_id); ++j) {
        auto ppid_curr_byte = lc_.template vbit<8>(ppid_id[j]);
        auto e = lc_.eq(8, oa.attr[j + 1].data(), ppid_curr_byte.data());
        ppid_match = lc_.land(&ppid_match, e);
      }
      // Also check the public length (1 byte key length + 17 bytes key + 1 byte value length + 18 bytes value = 37)
      auto expected_len = lc_.template vbit<8>(1 + 17 + 1 + sizeof(ppid_id));
      auto e2 = lc_.eq(8, expected_len.data(), oa.len.data());
      ppid_match = lc_.land(&ppid_match, e2);
      is_ppid[0] = ppid_match;
    }
    
    // In the MSO, the elementIdentifier is "pseudonym_seed". We should check that got[] matches this.
    v8 want_seed_str[32];
    for (size_t i = 0; i < 32; i++) want_seed_str[i] = lc_.template vbit<8>(0);
    uint8_t seed_id[] = {0x60 + 14, 'p', 's', 'e', 'u', 'd', 'o', 'n', 'y', 'm', '_', 's', 'e', 'e', 'd'};
    for (size_t i = 0; i < sizeof(seed_id); ++i) want_seed_str[i] = lc_.template vbit<8>(seed_id[i]);
    
    v8 want_seed_ei[MAX_EI];
    format_element(want_seed_ei, MAX_EI, ei_bytes, sizeof(ei_bytes), want_seed_str, 32);
    
    // Convert 256v hmac_out to v8 array for comparison.
    v8 hmac_out_bytes[32];
    for (size_t i = 0; i < 32; ++i) {
        for (size_t bit = 0; bit < 8; ++bit) { 
             // FlatSHA256 unpacks so that hmac_out[255] is MSB of first byte
             size_t j = 8 * (31 - i) + bit;
             hmac_out_bytes[i][bit] = hmac_out[j];
        }
    }

    // Calculate actual expected length based on whether we are handling a PPID attribute.
    // We need to bypass the public `pairwise_pseudonym` length if the attribute is actually the seed.
    auto expected_len = oa.len;
    if (version >= 8) {
        auto ppid_expected_id_len = lc_.template vbit<8>(33); // 1 + 17 + 1 + 14
        lc_.vmux(is_ppid[0], expected_len, ppid_expected_id_len, oa.len);
    }

    // "elementIdentifier" checks the full cbor key-value, because it is public.
    mux_offset(2, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    for (size_t j = 0; j < MAX_EI; ++j) {
      auto ll = lc_.vlt(j, expected_len);
      for (size_t i = 0; i < 8; ++i) {
        auto same = lc_.eq(1, &got[j][i], &want_ei[j][i]);
        if (version >= 8) {
           auto same_seed = lc_.eq(1, &got[j][i], &want_seed_ei[j][i]);
           auto same_ppid_aware = lc_.mux(&is_ppid[0], &same_seed, same);
           lc_.assert_implies(&ll, same_ppid_aware);
        } else {
           lc_.assert_implies(&ll, same);
        }
      }
    }
    v8 tmp;
    std::copy(len.begin(), len.begin() + 8, tmp.begin());  // cast vind into v8.
    
    lc_.vassert_eq(&tmp, expected_len);

    auto expected_vlen = oa.vlen;
    if (version >= 8) {
        auto ppid_expected_val_len = lc_.template vbit<8>(47); // 1 + 12 + 2 + 32
        lc_.vmux(is_ppid[0], expected_vlen, ppid_expected_val_len, oa.vlen);
    }

    // "elementValue" checks the full cbor key-value, because it is public.
    mux_offset(3, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    
    for (size_t j = 0; j < MAX_EV; ++j) {
      auto ll = lc_.vlt(j, expected_vlen);
      for (size_t i = 0; i < 8; ++i) {
        auto same = lc_.eq(1, &got[j][i], &want_ev[j][i]);
        
        if (version >= 8) {
           auto bit_1 = lc_.bit(1);
           auto same_ppid_aware = lc_.mux(&is_ppid[0], &bit_1, same);
           lc_.assert_implies(&ll, same_ppid_aware);
        } else {
           lc_.assert_implies(&ll, same);
        }
      }
    }
    
    if (version >= 8) {
        for (size_t k = 0; k < 32; ++k) {
            auto is_valid_hmac = lc_.eq(8, &oa.v1[k + 2][0], &hmac_out_bytes[k][0]); // +2 to skip 0x58 0x20
            lc_.assert_implies(&is_ppid[0], is_valid_hmac);
        }
    }

    std::copy(len.begin(), len.begin() + 8, tmp.begin());  // cast vind into v8.
    
    lc_.vassert_eq(&tmp, expected_vlen);
  }

  void mux_offset(size_t slot, vind& shift, vind& len,
                  const SaltedHash& sh) const {
    vind t[2];
    vind five = lc_.template vbit<kCborIndexBits>(5);
    lc_.vmux(sh.perm[2 * slot + 1], t[0], sh.i2, five);
    lc_.vmux(sh.perm[2 * slot + 1], t[1], sh.i3, sh.i1);
    lc_.vmux(sh.perm[2 * slot], shift, t[1], t[0]);

    lc_.vmux(sh.perm[2 * slot + 1], t[0], sh.l[2], sh.l[0]);
    lc_.vmux(sh.perm[2 * slot + 1], t[1], sh.l[3], sh.l[1]);
    lc_.vmux(sh.perm[2 * slot], len, t[1], t[0]);
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
      0x6C, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x44,
      0x69, 0x67, 0x65, 0x73, 0x74, 0x73,
  };
  static constexpr size_t kValueDigestsLen = sizeof(kValueDigestsCheck);

  static constexpr size_t kDateLen = 20;

  const LogicCircuit& lc_;
  Flatsha sha_;
  Routing<LogicCircuit> r_;
  CborByteDecoder<LogicCircuit> cb_;
  Hmac hmac_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
