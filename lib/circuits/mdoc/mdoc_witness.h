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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_WITNESS_H_

#include <stddef.h>
#include <string.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <vector>

#include "arrays/dense.h"
#include "cbor/host_decoder.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_attribute_ids.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/mdoc/mdoc_hash.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/sha/flatsha256_witness.h"
#include "gf2k/gf2_128.h"
#include "util/crypto.h"
#include "util/log.h"
#include "util/panic.h"

namespace proofs {

struct CborIndex {
  size_t k, v, ndx;
  size_t pos, len; /* optional fields for string/byte values */
};

struct AttrShift {
  size_t offset, len;
};

struct SaltedHash {
  size_t i1;
  size_t i2;
  size_t i3;
  size_t l[4];
  size_t perm;
};

struct pos {
  size_t i, l, p, ord;
};

// This class represents an attribute that is parsed out of the deviceResponse
// data structure. It includes offsets into the original mdoc which can be used
// to construct SHA witnesses for disclosing the value of an attribute.
struct FullAttribute {
  // Offset and length of the attribute identifier and attribute value.
  size_t id_ind;
  size_t id_len;
  size_t val_ind;
  size_t val_len;

  // For version 7+ circuits.
  size_t dig_ind, dig_len;
  size_t rand_ind, rand_len;

  const uint8_t* mdl_ns;  // mdl namespace for the attribute

  // Index for this attribute among all attributes in the mdoc hash list.
  size_t digest_id;
  CborIndex mso;

  // Offset and length of the attribute tag.
  size_t tag_ind;
  size_t tag_len;

  // The original mdoc into which all offsets point.
  const uint8_t* doc;

  bool operator==(const RequestedAttribute& y) const {
    return y.id_len == id_len && memcmp(y.id, &doc[id_ind], id_len) == 0;
  }

  size_t witness_length(const RequestedAttribute& attr) {
    return id_len + val_len + 1 + 12;
  }
};

class ParsedMdoc {
 public:
  // Various cbor indices/witnesses for intermediate structures.
  CborIndex t_mso_, sig_, dksig_;
  CborIndex valid_, valid_from_, valid_until_;
  CborIndex dev_key_info_, dev_key_, dev_key_pkx_, dev_key_pky_;
  CborIndex value_digests_, org_;
  std::vector<FullAttribute> attributes_;
  std::vector<uint8_t> doc_type_;

  // These are the exact bytes which produce the hash that is signed.
  std::vector<uint8_t> tagged_mso_bytes_;

  size_t doc_len_;

  // Helper function to dynamically extract a specific CBOR elementValue from a parsed mdoc's
  // IssuerSignedItemBytes tagged attributes. This isolates callers from version-specific CBOR key ordering.
  bool extract_cbor_value(const char* expected_id, const uint8_t** out_val, size_t* out_len) const {
    size_t expected_id_len = strlen(expected_id);
    for (const auto &attr : attributes_) {
      // `attr.tag_ind` points to the start of the `IssuerSignedItemBytes` tag
      CborDoc itemDoc;
      size_t pos = 0;
      const uint8_t *p_item = &attr.doc[attr.tag_ind];
      CborDoc tagDoc;
      
      // Safely parse the tagged CBOR item
      if (tagDoc.decode(p_item, doc_len_ - attr.tag_ind, pos, 0) && tagDoc.children_.size() > 0) {
        CborDoc &bstr = tagDoc.children_[0]; // inner byte string
        CborDoc innerMap;
        size_t inner_pos = 0;
        if (innerMap.decode(&p_item[bstr.u_.string.pos], bstr.u_.string.len, inner_pos, 0)) {
          size_t di = 0;
          auto ev = innerMap.lookup(&p_item[bstr.u_.string.pos], 12, (const uint8_t *)"elementValue", di);
          if (ev != nullptr) {
            if (attr.id_len == expected_id_len && memcmp(&attr.doc[attr.id_ind], expected_id, expected_id_len) == 0) {
              *out_val = &p_item[bstr.u_.string.pos + ev[1].position()];
              *out_len = ev[1].length();
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  /*
    Parses a byte representation of the "DeviceResponse" string from a phone.
    This contains all of the information needed to respond to an mdoc verifier.
    This method attempts to construct a witness from this.

    8.3.2.1.2.2: first field is "version", 2nd optional field is "documents"
    [documents][0][issuerSigned][issuerAuth]{2} --> tagged mso
    [documents][0][issuerSigned][issuerAuth]{3} --> issuer sig
    [documents][0][issuerSigned][nameSpaces][ns][index-of-attr] --> enc attr
    [documents][0][deviceSigned][deviceAuth][deviceSignature][3] --> sig

    This method produces indices into doc as state.
  */
  MdocProverErrorCode parse_device_response(size_t len,
                                            const uint8_t resp[/* len */]) {
    doc_len_ = len;
    size_t np = 0;
    // When this object falls out of scope, all parsing objects will be
    // garbage collected.
    CborDoc root;
    bool ok = root.decode(resp, len, np, 0);
    if (!ok) {
      log(ERROR, "Failed to decode root");
      return MDOC_PROVER_ROOT_DECODING_FAILURE;
    }

    size_t di;
    auto docs = root.lookup(resp, 9, (uint8_t*)"documents", di);
    if (docs == nullptr) return MDOC_PROVER_DOCUMENTS_MISSING;
    // Fields of Document are "docType", "issuerSigned", "deviceSigned", ?errors

    auto docs0 = docs[1].index(0);
    if (docs0 == nullptr) return MDOC_PROVER_DOCUMENT_0_MISSING;

    auto dt = docs0[0].lookup(resp, 7, (uint8_t*)"docType", di);
    if (dt == nullptr) return MDOC_PROVER_DOCTYPE_MISSING;
    doc_type_.insert(doc_type_.begin(), resp + dt[1].u_.string.pos,
                     resp + dt[1].u_.string.pos + dt[1].u_.string.len);

    // The returned docs0 is the map, so index at [0].
    auto is = docs0[0].lookup(resp, 12, (uint8_t*)"issuerSigned", di);
    if (is == nullptr) return MDOC_PROVER_ISSUER_SIGNED_MISSING;

    auto ia = is[1].lookup(resp, 10, (uint8_t*)"issuerAuth", di);
    if (ia == nullptr) return MDOC_PROVER_ISSUER_AUTH_MISSING;

    auto tmso = ia[1].index(2);
    if (tmso == nullptr) return MDOC_PROVER_MSO_MISSING;
    copy_header(t_mso_, tmso);
    auto nsig = ia[1].index(3);
    if (nsig == nullptr) return MDOC_PROVER_NSIG_MISSING;
    copy_header(sig_, nsig);

    auto ns = is[1].lookup(resp, 10, (uint8_t*)"nameSpaces", di);
    if (ns == nullptr) return MDOC_PROVER_NAMESPACES_MISSING;

    // Find the attribute witness we need from here.
    for (const char* sn : kSupportedNamespaces) {
      auto mldns = ns[1].lookup(resp, strlen(sn), (const uint8_t*)sn, di);
      if (mldns == nullptr) continue;
      size_t ai = 0;
      auto tattr = mldns[1].index(ai++);
      while (tattr != nullptr) {
        CborDoc er;
        // Decode the map in this tagged attribute.
        size_t pos = tattr->children_[0].u_.string.pos;
        size_t end = pos + tattr->children_[0].u_.string.len;
        if (!er.decode(resp, end, pos, 0)) {
          return MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE;
        }

        auto ei = er.lookup(resp, 17, (uint8_t*)"elementIdentifier", di);
        if (ei == nullptr) return MDOC_PROVER_ATTRIBUTE_EI_MISSING;
        auto ev = er.lookup(resp, 12, (uint8_t*)"elementValue", di);
        if (ev == nullptr) return MDOC_PROVER_ATTRIBUTE_EV_MISSING;
        auto digid = er.lookup(resp, 8, (uint8_t*)"digestID", di);
        if (digid == nullptr) return MDOC_PROVER_ATTRIBUTE_DID_MISSING;
        auto rand = er.lookup(resp, 6, (uint8_t*)"random", di);
        if (rand == nullptr) return MDOC_PROVER_ATTRIBUTE_RANDOM_MISSING;

        attributes_.push_back((FullAttribute){
            //  For the elementIdentifier, the [1] index is the position and
            //  length of the value.
            ei[1].position(),
            ei[1].length(),
            // For version 7, record the index of the elementValue key, i.e.,
            // ev[0], instead of the value. This makes it easier to handle
            // different orderings of the elementIdentifier and elementValue
            // keys in the CBOR encoding. Previous versions of the circuit did
            // not use the ev[1] index, because they assumed canonical order.
            ev[0].position(),
            ev[1].length(),
            digid[0].position(),
            digid[0].length() + digid[1].length() + 1,
            rand[0].position(),
            rand[0].length() + rand[1].length() + 1 +
                (rand[1].length() < 24 ? 1 : 2),
            (const uint8_t*)sn,
            static_cast<size_t>(digid[1].u_.u64), /* digest_id */
            {0, 0, 0},                            /* default mso_ind */
            tattr->header_pos_,                   /* tag_ind */
            tattr->children_[0].u_.string.len +
                4, /* +4 for the D8 18 58 <> prefix */
            resp});

        tattr = mldns[1].index(ai++);
      }
    }

    auto ds = docs0[0].lookup(resp, 12, (uint8_t*)"deviceSigned", di);
    if (ds == nullptr) return MDOC_PROVER_DEVICE_SIGNED_MISSING;
    auto da = ds[1].lookup(resp, 10, (uint8_t*)"deviceAuth", di);
    if (da == nullptr) return MDOC_PROVER_DEVICE_AUTH_MISSING;
    auto dsi = da[1].lookup(resp, 15, (uint8_t*)"deviceSignature", di);
    if (dsi == nullptr) return MDOC_PROVER_DEVICE_SIGNATURE_MISSING;
    auto ndksig = dsi[1].index(3);
    if (ndksig == nullptr) return MDOC_PROVER_DEVICE_SIGNATURE_MISSING;
    copy_header(dksig_, ndksig);

    // Then parse tagged mso. Skip 5 bytes to skip the D8 18 59 <len2>.
    const uint8_t* pmso = resp + tmso->u_.string.pos + 5;
    size_t pos = 0;
    CborDoc mso;
    if (!mso.decode(pmso, tmso->u_.string.len - 5, pos, 0))
      return MDOC_PROVER_MSO_DECODING_FAILURE;
    auto nv = mso.lookup(pmso, kValidityInfoLen, kValidityInfoID, valid_.ndx);
    if (nv == nullptr) return MDOC_PROVER_VALIDITY_INFO_MISSING;
    copy_kv_header(valid_, nv);

    auto nvf = nv[1].lookup(pmso, kValidFromLen, kValidFromID, valid_from_.ndx);
    if (nvf == nullptr) return MDOC_PROVER_VALIDITY_INFO_MISSING;
    copy_kv_header(valid_from_, nvf);

    auto nvu =
        nv[1].lookup(pmso, kValidUntilLen, kValidUntilID, valid_until_.ndx);
    if (nvu == nullptr) return MDOC_PROVER_VALIDITY_INFO_MISSING;
    copy_kv_header(valid_until_, nvu);

    auto ndki = mso.lookup(pmso, kDeviceKeyInfoLen, kDeviceKeyInfoID,
                           dev_key_info_.ndx);
    if (ndki == nullptr) return MDOC_PROVER_DEVICE_KEY_INFO_MISSING;
    copy_kv_header(dev_key_info_, ndki);

    auto ndk = ndki[1].lookup(pmso, kDeviceKeyLen, kDeviceKeyID, dev_key_.ndx);
    if (ndk == nullptr) return MDOC_PROVER_DEVICE_KEY_MISSING;
    copy_kv_header(dev_key_, ndk);

    auto npkx = ndk[1].lookup_negative(-1, dev_key_pkx_.ndx);
    if (npkx == nullptr) return MDOC_PROVER_DEVICE_KEY_MISSING;
    copy_kv_header(dev_key_pkx_, npkx);

    auto npky = ndk[1].lookup_negative(-2, dev_key_pky_.ndx);
    if (npky == nullptr) return MDOC_PROVER_DEVICE_KEY_MISSING;
    copy_kv_header(dev_key_pky_, npky);

    auto nvd =
        mso.lookup(pmso, kValueDigestsLen, kValueDigestsID, value_digests_.ndx);
    if (nvd == nullptr) return MDOC_PROVER_MSO_DECODING_FAILURE;
    copy_kv_header(value_digests_, nvd);

    // For backwards compatibility with 1f circuits, copy the hard-coded org_ if
    // it is present. TODO(shelat): Remove this once all 1f circuits have
    // been updated.
    auto norg = nvd[1].lookup(pmso, kOrgLen, kOrgID, org_.ndx);
    if (norg != nullptr) {
      copy_kv_header(org_, norg);
    }

    for (auto& attr : attributes_) {
      size_t index;
      auto nss = nvd[1].lookup(pmso, strlen((const char*)attr.mdl_ns),
                               attr.mdl_ns, index);
      if (nss == nullptr) return MDOC_PROVER_MSO_DECODING_FAILURE;
      uint64_t hi = (uint64_t)attr.digest_id;
      auto hattr = nss[1].lookup_unsigned(hi, attr.mso.ndx);
      if (hattr == nullptr) return MDOC_PROVER_MSO_DECODING_FAILURE;
      copy_kv_header(attr.mso, hattr);
    }

    tagged_mso_bytes_.assign(std::begin(kCose1Prefix), std::end(kCose1Prefix));
    // Add 2-byte length
    tagged_mso_bytes_.push_back((t_mso_.len >> 8) & 0xff);
    tagged_mso_bytes_.push_back(t_mso_.len & 0xff);
    for (size_t i = 0; i < t_mso_.len; ++i) {
      tagged_mso_bytes_.push_back(resp[t_mso_.pos + i]);
    }

    return MDOC_PROVER_SUCCESS;
  }

 private:
  // Used to copy the results of a map lookup.
  static void copy_kv_header(CborIndex& ind, const CborDoc* n) {
    ind.k = n[0].header_pos_;
    ind.v = n[1].header_pos_;

    if (n[1].t_ == TEXT || n[1].t_ == BYTES) {
      ind.pos = n[1].u_.string.pos;
      ind.len = n[1].u_.string.len;
    }
  }

  // Used to copy the results of an index lookup.
  static void copy_header(CborIndex& ind, const CborDoc* n) {
    ind.k = n->header_pos_;
    ind.pos = n->u_.string.pos;
    ind.len = n->u_.string.len;
  }
};

// Transform from u8 be (i.e., be[31] is the most significant byte) into
// nat form, which requires first converting to le byte order.
template <class Nat>
Nat nat_from_be(const uint8_t be[/* Nat::kBytes */]) {
  uint8_t tmp[Nat::kBytes];
  // Transform into byte-wise le representation.
  for (size_t i = 0; i < Nat::kBytes; ++i) {
    tmp[i] = be[Nat::kBytes - i - 1];
  }
  return Nat::of_bytes(tmp);
}

// Transform from u32 be (i.e., be[0] is the most significant nibble)
// into nat form, which requires first converting to le byte order.
template <class Nat>
Nat nat_from_u32(const uint32_t be[]) {
  uint8_t tmp[Nat::kBytes];
  const size_t top = Nat::kBytes / 4;
  for (size_t i = 0; i < Nat::kBytes; ++i) {
    tmp[i] = (be[top - i / 4 - 1] >> ((i % 4) * 8)) & 0xff;
  }
  return Nat::of_bytes(tmp);
}

template <typename Nat>
Nat nat_from_hash(const uint8_t data[], size_t len) {
  uint8_t hash[kSHA256DigestSize];
  SHA256 sha;
  sha.Update(data, len);
  sha.DigestData(hash);
  Nat ne = nat_from_be<Nat>(hash);
  return ne;
}

// Append the cbor encoding of the length of a bytestring to buf.
// This method handles bytestrings that are up to 255 bytes long.
static inline void append_bytes_len(std::vector<uint8_t>& buf, size_t len) {
  check(len < 65536, "Bytestring length too large");
  if (len < 24) {
    buf.push_back(0x40 + len);
  } else if (len < 256) {
    uint8_t ll[] = {0x58, static_cast<uint8_t>(len & 0xff)};
    buf.insert(buf.end(), ll, ll + 2);
  } else {
    uint8_t ll[] = {0x59, (uint8_t)((len >> 8) & 0xff), (uint8_t)(len & 0xff)};
    buf.insert(buf.end(), ll, ll + 3);
  }
}

// Append the cbor encoding of the length of a text string to buf.
// This method handles text strings that are up to 255 bytes long.
static inline void append_text_len(std::vector<uint8_t>& buf, size_t len) {
  check(len < 256, "Text length too large");
  if (len < 24) {
    buf.push_back(0x60 + len);
  } else if (len < 256) {
    buf.push_back(0x78);
    buf.push_back(len);
  }
}

// Form the COSE1 encoding of the DeviceAuthenticationBytes,
// then compute its SHA-256 hash, and cast into a Nat.
// The original form follows S9.1.3.4 of the mdoc spec and
// assumed that the transcript was a simple string.
// The Jan'2024 demo requires using the "AndroidHandover" version
// of the DeviceAuthenticationBytes formatting, which is not
// specified in the spec. As a result, this function is a hack
// that mimics the bytes produced by the Android com.android.identity.wallet
// library.
template <class Nat>
static Nat compute_transcript_hash(
    const uint8_t transcript[], size_t len,
    const std::vector<uint8_t>* docType = nullptr) {
  // The DeviceAuthenticationBytes is defined in 9.1.3.4 as:
  // DeviceAuthentication = [
  //    "DeviceAuthentication",
  //    SessionTranscript,
  //    DocType, ; Same as in mdoc response
  //    DeviceNameSpacesBytes ; Same as in mdoc response
  // ]
  std::vector<uint8_t> deviceAuthentication = {
      0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
      'h',  'e',  'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
  };
  std::vector<uint8_t> docTypeBytes = {
      0x75, 'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8',
      '0',  '1', '3', '.', '5', '.', '1', '.', 'm', 'D', 'L',
  };
  std::vector<uint8_t> deviceNameSpacesBytes = {0xD8, 0x18, 0x41, 0xA0};

  if (docType != nullptr && docType->size() < 256) {
    docTypeBytes.clear();
    append_text_len(docTypeBytes, docType->size());
    docTypeBytes.insert(docTypeBytes.end(), docType->begin(), docType->end());
  }

  // Provide the DeviceAuthentication bytes
  std::vector<uint8_t> da(deviceAuthentication);
  da.insert(da.end(), transcript, transcript + len);
  da.insert(da.end(), docTypeBytes.begin(), docTypeBytes.end());
  da.insert(da.end(), deviceNameSpacesBytes.begin(),
            deviceNameSpacesBytes.end());

  // Form the COSE1 encoding of the DeviceAuthenticationBytes.
  std::vector<uint8_t> cose1{0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E,
                             0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                             0x43, 0xA1, 0x01, 0x26, 0x40};
  uint8_t tag[] = {0xD8, 0x18};

  size_t l1 = da.size();
  size_t l2 = l1 + (l1 < 256 ? 4 : 5); /* Tagged array length. */
  append_bytes_len(cose1, l2);
  cose1.insert(cose1.end(), tag, tag + 2);
  append_bytes_len(cose1, l1);
  cose1.insert(cose1.end(), da.begin(), da.end());

  return nat_from_hash<Nat>(cose1.data(), cose1.size());
}

// Interpret input s as an len*8-bit string, and use it to fill max*8 bits
// in the dense filler.
// Pad the input with the Field value 2 to indicate the positions
// that are not part of the string.
template <class Field>
void fill_bit_string(DenseFiller<Field>& filler, const uint8_t s[/*len*/],
                     size_t len, size_t max, const Field& Fs) {
  std::vector<typename Field::Elt> v(max * 8, Fs.of_scalar(2));
  for (size_t i = 0; i < max && i < len; ++i) {
    fill_byte(v, s[i], i, Fs);
  }
  filler.push_back(v);
}

template <class Field>
void fill_byte(std::vector<typename Field::Elt>& v, uint8_t b, size_t i,
               const Field& F) {
  for (size_t j = 0; j < 8; ++j) {
    v[i * 8 + j] = (b >> j & 0x1) ? F.one() : F.zero();
  }
}

template <class Field>
MdocProverErrorCode fill_attribute(DenseFiller<Field>& filler,
                                   const RequestedAttribute& attr,
                                   const Field& F, size_t version) {
  // In version >= 4, the attribute is encoded as
  // <len(identifier)> <name of identifier> <elementValue> <attributeValue>.
  // This extra length field distinguishes the two attributes:
  //   "aamva/domestic_driving_privileges" from "iso/driving_privileges." No
  // other valid attribute name is a proper suffix of another.  See the
  // mdoc_attribute_ids.h file for the full list of attribute names and our
  // restrictions.
  // In version >= 7, the attribute is encoded in two parts:
  // The first 32 bytes of the ei are "<len> <ei value>" padded to 32
  // The next 64 bytes of the ev are "<ev value>"

  // Both cases rely on the zero-padding of v.
  std::vector<typename Field::Elt> v(96 * 8, F.zero());

  if (version >= 7) {
    std::vector<uint8_t> vbuf;
    append_text_len(vbuf, attr.id_len);
    vbuf.insert(vbuf.end(), attr.id, attr.id + attr.id_len);
    for (size_t j = 0; j < vbuf.size() && j < 32; ++j) {
      fill_byte(v, vbuf[j], j, F);
    }

    // Now fill the value
    for (size_t j = 0; j < 64 && j < attr.cbor_value_len; ++j) {
      fill_byte(v, attr.cbor_value[j], 32 + j, F);
    }

    filler.push_back(v);

    // The v7 circuit use "<17> elementIdentifier <32 b of above>"
    // to form the string that it compares against.
    filler.push_back(1 + 17 + 1 + attr.id_len, 8, F);

    // For the value, the v7 circuit uses "<12> elementValue <cbor_value>"
    // as the comparison string.
    size_t vlen = attr.cbor_value_len + 12 + 1;

    filler.push_back(vlen, 8, F);
  } else {
    // version < 7
    // Append the length of the elementIdentifier.
    std::vector<uint8_t> vbuf;
    append_text_len(vbuf, attr.id_len);
    vbuf.insert(vbuf.end(), attr.id, attr.id + attr.id_len);
    append_text_len(vbuf, 12);  // len of "elementValue"
    const char* ev = "elementValue";
    vbuf.insert(vbuf.end(), ev, ev + 12);

    vbuf.insert(vbuf.end(), attr.cbor_value,
                attr.cbor_value + attr.cbor_value_len);

    if (vbuf.size() > 96) {
      log(ERROR, "Attribute %s is too long: %zu", attr.id, vbuf.size());
      return MDOC_PROVER_ATTRIBUTE_TOO_LONG;
    }
    size_t len = 0;
    for (size_t j = 0; j < vbuf.size() && len < 96; ++j, ++len) {
      fill_byte(v, vbuf[j], len, F);
    }
    filler.push_back(v);
    filler.push_back(len, 8, F);
  }
  return MDOC_PROVER_SUCCESS;
}

template <class EC, class ScalarField>
class MdocSignatureWitness {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EcdsaWitness = VerifyWitness3<EC, ScalarField>;
  using MacWitnessF = MacWitness<Field>;
  using f_128 = GF2_128<>;
  const EC& ec_;
  const f_128& gf_;

 public:
  Elt e_, e2_;      /* Issuer signature values. */
  Elt dpkx_, dpky_; /* device key */
  EcdsaWitness ew_, dkw_;
  MacWitnessF macs_[3]; /* macs for e_, dpkx_, dpky_ */

  explicit MdocSignatureWitness(const EC& ec, const ScalarField& Fn,
                                const f_128& gf)
      : ec_(ec),
        gf_(gf),
        ew_(Fn, ec),
        dkw_(Fn, ec),
        macs_{MacWitnessF(ec.f_, gf_), MacWitnessF(ec.f_, gf_),
              MacWitnessF(ec.f_, gf_)} {}

  void fill_witness(DenseFiller<Field>& filler) const {
    filler.push_back(e_);
    filler.push_back(dpkx_);
    filler.push_back(dpky_);

    ew_.fill_witness(filler);
    dkw_.fill_witness(filler);
    for (auto& mac : macs_) {
      mac.fill_witness(filler);
    }
  }

  MdocProverErrorCode compute_witness(Elt pkX, Elt pkY,
                                      const uint8_t mdoc[/* len */], size_t len,
                                      const uint8_t transcript[/* tlen */],
                                      size_t tlen) {
    ParsedMdoc pm;

    MdocProverErrorCode err = pm.parse_device_response(len, mdoc);
    if (err != MDOC_PROVER_SUCCESS) {
      return err;
    }

    Nat ne = nat_from_hash<Nat>(pm.tagged_mso_bytes_.data(),
                                pm.tagged_mso_bytes_.size());
    e_ = ec_.f_.to_montgomery(ne);

    // Parse (r,s).
    const size_t l = pm.sig_.len;
    Nat nr = nat_from_be<Nat>(&mdoc[pm.sig_.pos]);
    Nat ns = nat_from_be<Nat>(&mdoc[pm.sig_.pos + l / 2]);
    bool sig_ok = ew_.compute_witness(pkX, pkY, ne, nr, ns);
    if (!sig_ok) {
      return MDOC_PROVER_SIGNATURE_FAILURE;
    }

    Nat ne2 = compute_transcript_hash<Nat>(transcript, tlen, &pm.doc_type_);
    const size_t l2 = pm.dksig_.len;
    Nat nr2 = nat_from_be<Nat>(&mdoc[pm.dksig_.pos]);
    Nat ns2 = nat_from_be<Nat>(&mdoc[pm.dksig_.pos + l2 / 2]);
    size_t pmso = pm.t_mso_.pos + 5; /* skip the tag */
    dpkx_ = ec_.f_.to_montgomery(
        nat_from_be<Nat>(&mdoc[pmso + pm.dev_key_pkx_.pos]));
    dpky_ = ec_.f_.to_montgomery(
        nat_from_be<Nat>(&mdoc[pmso + pm.dev_key_pky_.pos]));
    e2_ = ec_.f_.to_montgomery(ne2);
    bool dksig_ok = dkw_.compute_witness(dpkx_, dpky_, ne2, nr2, ns2);
    if (!dksig_ok) {
      return MDOC_PROVER_DEVICE_SIGNATURE_FAILURE;
    }
    return MDOC_PROVER_SUCCESS;
  }
};

// EC: implements the elliptic curve for the mdoc
// Field: implements the field used to define the sumcheck circuit, which can
//        be smaller than the EC field
template <typename EC, typename Field>
class MdocHashWitness {
  using ECField = typename EC::Field;
  using ECElt = typename ECField::Elt;
  using ECNat = typename ECField::N;
  using Elt = typename Field::Elt;
  using vindex = std::array<Elt, kCborIndexBits>;

  const EC& ec_;
  const Field& fn_;

 public:
  ECElt e_;           /* Issuer signature values. */
  ECElt dpkx_, dpky_; /* device key */
  uint8_t signed_bytes_[kMaxSHABlocks * 64];
  uint8_t numb_; /* Number of the correct sha block. */

  size_t num_attr_;
  std::vector<std::vector<uint8_t>> attr_bytes_;
  std::vector<std::vector<FlatSHA256Witness::BlockWitness>> atw_;

  std::vector<uint8_t> attr_n_; /* All attributes currently require 2 SHA. */
  std::vector<CborIndex> attr_mso_; /* The cbor indices of the attributes. */
  std::vector<AttrShift> attr_ei_;
  std::vector<AttrShift> attr_ev_;
  std::vector<SaltedHash> attr_sh_;

  FlatSHA256Witness::BlockWitness bw_[kMaxSHABlocks];

  uint8_t ppid_inner_nb_;
  uint8_t ppid_outer_nb_;
  uint8_t ppid_seed_[32];
  uint8_t ppid_inner_padded_m_[9 * 64];
  FlatSHA256Witness::BlockWitness ppid_inner_bw_[10];
  FlatSHA256Witness::BlockWitness ppid_outer_bw_[2];

  ParsedMdoc pm_;

  explicit MdocHashWitness(size_t num_attr, const EC& ec, const Field& Fn)
      : ec_(ec), fn_(Fn), num_attr_(num_attr) {}

  void fill_cbor_index(DenseFiller<Field>& df, const CborIndex& ind) const {
    df.push_back(ind.k, kCborIndexBits, fn_);
  }

  void fill_attr_shift(DenseFiller<Field>& df, const AttrShift& attr) const {
    df.push_back(attr.offset, kCborIndexBits, fn_);
    df.push_back(attr.len, kCborIndexBits, fn_);
  }

  void fill_salted_attr(DenseFiller<Field>& df, const SaltedHash& sh) const {
    df.push_back(sh.i1, kCborIndexBits, fn_);
    df.push_back(sh.i2, kCborIndexBits, fn_);
    df.push_back(sh.i3, kCborIndexBits, fn_);
    df.push_back(sh.l[0], kCborIndexBits, fn_);
    df.push_back(sh.l[1], kCborIndexBits, fn_);
    df.push_back(sh.l[2], kCborIndexBits, fn_);
    df.push_back(sh.l[3], kCborIndexBits, fn_);
    df.push_back(sh.perm, 8, fn_);
  }

  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, kSHAPluckerBits> BPENC(fn_);
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
      filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
    }
  }

  void fill_witness(DenseFiller<Field>& filler, size_t version = 7) const {
    // Fill sha of main mso.
    filler.push_back(numb_, 8, fn_);
    // Don't push the prefix.  Version <=7 has a 35-block limit.
    for (size_t i = kCose1PrefixLen; i < max_shablocks(version) * 64; ++i) {
      filler.push_back(signed_bytes_[i], 8, fn_);
    }
    for (size_t j = 0; j < max_shablocks(version); j++) {
      fill_sha(filler, bw_[j]);
    }
    // === done with sha

    fill_cbor_index(filler, pm_.valid_from_);
    fill_cbor_index(filler, pm_.valid_until_);
    fill_cbor_index(filler, pm_.dev_key_info_);
    fill_cbor_index(filler, pm_.value_digests_);

    // Fill all attribute witnesses.
    for (size_t ai = 0; ai < num_attr_; ++ai) {
      for (size_t i = 0; i < 2 * 64; ++i) {
        filler.push_back(attr_bytes_[ai][i], 8, fn_);
      }
      for (size_t j = 0; j < 2; j++) {
        fill_sha(filler, atw_[ai][j]);
      }

      // In the case of attribute mso, push the value to avoid having to
      // deal with 1- or 2- byte key length.
      filler.push_back(attr_mso_[ai].v, kCborIndexBits, fn_);
      fill_attr_shift(filler, attr_ei_[ai]);
      fill_attr_shift(filler, attr_ev_[ai]);

      if (version >= 7) {
        fill_salted_attr(filler, attr_sh_[ai]);
      }
    }

    if (version >= 8) {
      filler.push_back(ppid_inner_nb_, 8, fn_);
      for (size_t i = 0; i < 32; ++i) {
          filler.push_back(ppid_seed_[i], 8, fn_);
      }
      for (size_t i = 0; i < 9 * 64; ++i) {
          filler.push_back(ppid_inner_padded_m_[i], 8, fn_);
      }
      for (size_t i = 0; i < 10; ++i) {
          fill_sha(filler, ppid_inner_bw_[i]);
      }
      for (size_t i = 0; i < 2; ++i) {
          fill_sha(filler, ppid_outer_bw_[i]);
      }
    }
  }

  size_t max_shablocks(size_t version) const {
    if (version <= 6) return 35;
    return kMaxSHABlocks;
  }

  MdocProverErrorCode compute_witness(const uint8_t mdoc[/* len */], size_t len,
                                      const uint8_t transcript[/* tlen */],
                                      size_t tlen,
                                      const RequestedAttribute attrs[],
                                      size_t attrs_len, size_t version) {
    MdocProverErrorCode err = pm_.parse_device_response(len, mdoc);
    if (err != MDOC_PROVER_SUCCESS) {
      log(ERROR, "Failed to parse device response");
      return err;
    }

    if (version < 4) return MDOC_PROVER_VERSION_NOT_SUPPORTED;

    std::vector<uint8_t> buf;
    if (pm_.t_mso_.len >= max_shablocks(version) * 64 - 9 - kCose1PrefixLen) {
      log(ERROR, "tagged mso is too big: %zu", pm_.t_mso_.len);
      return MDOC_PROVER_TAGGED_MSO_TOO_BIG;
    }

    buf.assign(std::begin(kCose1Prefix), std::end(kCose1Prefix));
    // Add 2-byte length
    buf.push_back((pm_.t_mso_.len >> 8) & 0xff);
    buf.push_back(pm_.t_mso_.len & 0xff);
    for (size_t i = 0; i < pm_.t_mso_.len; ++i) {
      buf.push_back(mdoc[pm_.t_mso_.pos + i]);
    }

    FlatSHA256Witness::transform_and_witness_message(buf.size(), buf.data(),
                                                     max_shablocks(version),
                                                     numb_, signed_bytes_, bw_);

    ECNat ne = nat_from_u32<ECNat>(bw_[numb_ - 1].h1);
    e_ = ec_.f_.to_montgomery(ne);

    size_t pmso = pm_.t_mso_.pos + 5; /* +5 to skip the tag */
    dpkx_ = ec_.f_.to_montgomery(
        nat_from_be<ECNat>(&mdoc[pmso + pm_.dev_key_pkx_.pos]));
    dpky_ = ec_.f_.to_montgomery(
        nat_from_be<ECNat>(&mdoc[pmso + pm_.dev_key_pky_.pos]));

    // initialize variables
    attr_n_.resize(attrs_len);
    attr_mso_.resize(attrs_len);
    attr_ev_.resize(attrs_len);
    attr_ei_.resize(attrs_len);
    attr_bytes_.resize(attrs_len);
    atw_.resize(attrs_len);
    attr_sh_.resize(attrs_len);

    // Match the attributes with the witnesses from the deviceResponse.
    for (size_t i = 0; i < attrs_len; ++i) {
      attr_bytes_[i].resize(128);
      atw_[i].resize(2);
      bool found = false;
      for (auto fa : pm_.attributes_) {
        bool is_match = (fa == attrs[i]);
        if (version >= 8 && !is_match) {
            // Alias match: if the user requested "pairwise_pseudonym" but the MSO holds "pseudonym_seed"
            if (attrs[i].id_len == 18 && memcmp(attrs[i].id, "pairwise_pseudonym", 18) == 0 &&
                fa.id_len == 14 && memcmp(&fa.doc[fa.id_ind], "pseudonym_seed", 14) == 0) {
                is_match = true;
            }
        }
        if (is_match) {
          FlatSHA256Witness::transform_and_witness_message(
              fa.tag_len, &fa.doc[fa.tag_ind], 2, attr_n_[i],
              &attr_bytes_[i][0], &atw_[i][0]);
          attr_mso_[i] = fa.mso;
          // In version >= 4, the attribute id is encoded as the length of the
          // id followed by the id.  The witness starts at the id, so we
          // subtract 1 or 2 to get the offset, depending on the id length.
          attr_ei_[i].offset = fa.id_ind - fa.tag_ind - 1;
          if (fa.id_len > 23) {
            attr_ei_[i].offset -= 1;
          }
          attr_ei_[i].len = fa.witness_length(attrs[i]);

          attr_ev_[i].offset = fa.val_ind - fa.tag_ind;
          attr_ev_[i].len = fa.val_len;

          // Version 7+ circuits support salted hashes in which ev may occur
          // before ei. In this case, we provide two separate indices for the ev
          // and ei. The circuit augments the check buffer with the
          // "elementValue" and "elementIdentifier" prefixes respectively.
          if (version >= 7) {
            attr_ei_[i].offset =
                fa.id_ind - fa.tag_ind;  // points to name of attribute
            attr_ei_[i].offset -=
                fa.id_len < 24 ? 1 : 2;  // subtract length of name
            attr_ei_[i].offset -=
                (17 + 1);  // subtract "elementIdentifier" & length
            attr_ei_[i].len = 17 + 1 + fa.id_len + (fa.id_len < 24 ? 1 : 2);

            // -1 for len of elementValue
            attr_ev_[i].offset = fa.val_ind - fa.tag_ind - 1;
            attr_ev_[i].len = attrs[i].cbor_value_len + 12 + 1;

            pos triples[4] = {
                {fa.dig_ind - fa.tag_ind - 1, fa.dig_len, 0},
                {fa.rand_ind - fa.tag_ind - 1, fa.rand_len, 1},
                {attr_ei_[i].offset, attr_ei_[i].len, 2},
                {attr_ev_[i].offset, attr_ev_[i].len, 3},
            };
            std::sort(triples, triples + 4,
                      [](const pos& a, const pos& b) { return a.i < b.i; });

            attr_sh_[i].l[0] = triples[0].l;
            attr_sh_[i].i1 = triples[1].i;
            attr_sh_[i].l[1] = triples[1].l;
            attr_sh_[i].i2 = triples[2].i;
            attr_sh_[i].l[2] = triples[2].l;
            attr_sh_[i].i3 = triples[3].i;
            attr_sh_[i].l[3] = triples[3].l;
            triples[0].ord = 0;
            triples[1].ord = 1;
            triples[2].ord = 2;
            triples[3].ord = 3;

            std::sort(triples, triples + 4,
                      [](const pos& a, const pos& b) { return a.p < b.p; });
            attr_sh_[i].perm = triples[0].ord;
            attr_sh_[i].perm |= triples[1].ord << 2;
            attr_sh_[i].perm |= triples[2].ord << 4;
            attr_sh_[i].perm |= triples[3].ord << 6;
          }

          found = true;
          break;
        }
      }
      if (!found) {
        log(ERROR, "Could not find attribute %.*s", attrs[i].id_len,
            attrs[i].id);
        return MDOC_PROVER_ATTRIBUTE_NOT_FOUND;
      }
    }

    memset(ppid_inner_padded_m_, 0, sizeof(ppid_inner_padded_m_));
    memset(ppid_inner_bw_, 0, sizeof(ppid_inner_bw_));
    memset(ppid_outer_bw_, 0, sizeof(ppid_outer_bw_));
    ppid_inner_nb_ = 0;
    ppid_outer_nb_ = 2; // Outer hash always takes exactly 2 blocks due to fixed 96 byte length

    if (version >= 8) {
        uint8_t hmac_key[64] = {0};
        const uint8_t* v_id = nullptr;
        const uint8_t* p_ctx = nullptr;
        bool found = false;
        for (size_t i = 0; i < attrs_len; ++i) {
            std::string attr_name((const char*)attrs[i].id, attrs[i].id_len);
            if (attr_name == "pairwise_pseudonym") {
                v_id = attrs[i].verifier_id;
                p_ctx = attrs[i].ppid_context;
                // The pseudonym seed is 32 bytes and encoded as a cbor bytestring.
                // The attribute value is at &mdoc[pm_.t_mso_.pos + 5 + attr_ev_[i].offset]
                // but we extract it from fa.doc using the parsed attribute list logic.
                for (auto fa : pm_.attributes_) {
                    bool is_match = (fa == attrs[i]);
                    if (!is_match && attrs[i].id_len == 18 && memcmp(attrs[i].id, "pairwise_pseudonym", 18) == 0 &&
                        fa.id_len == 14 && memcmp(&fa.doc[fa.id_ind], "pseudonym_seed", 14) == 0) {
                        is_match = true;
                    }

                    if (is_match) {
                        // Extract 32 bytes from offset + 14
                        // fa.val_ind points to the 'e' in "elementValue".
                        // "+ 12" skips the 12 character string.
                        // "+ 2" skips the CBOR bytestring prefix (0x58 0x20).
                        size_t key_pos = fa.val_ind + 14;
                        if (key_pos + 32 <= len) {
                            memcpy(hmac_key, &fa.doc[key_pos], 32);
                        }
                        found = true;
                        break;
                    }
                }
            }
        }
        memcpy(ppid_seed_, hmac_key, 32);
        
        // Construct HMAC Data (Exactly 64 bytes)
        std::vector<uint8_t> hmac_data;
        if (v_id) hmac_data.insert(hmac_data.end(), v_id, v_id + 32);
        else hmac_data.insert(hmac_data.end(), 32, 0);
        
        if (p_ctx) hmac_data.insert(hmac_data.end(), p_ctx, p_ctx + 32);
        else hmac_data.insert(hmac_data.end(), 32, 0);

        std::vector<uint8_t> inner_full_data;
        std::vector<uint8_t> padded_hmac_key(64, 0);
        memcpy(padded_hmac_key.data(), hmac_key, 32);

        for(size_t i = 0; i < 64; ++i) inner_full_data.push_back(padded_hmac_key[i] ^ 0x36); // k_ipad
        inner_full_data.insert(inner_full_data.end(), hmac_data.begin(), hmac_data.end());

        uint8_t inner_padded_full[64 * 3] = {0};
        FlatSHA256Witness::transform_and_witness_message(inner_full_data.size(), inner_full_data.data(), 3, ppid_inner_nb_, inner_padded_full, ppid_inner_bw_);
        
        // ppid_inner_padded_m_ receives the padding AFTER the 64 byte K_ipad, so we skip the first 64 bytes
        memcpy(ppid_inner_padded_m_, inner_padded_full + 64, 2 * 64);

        // Extract inner hash
        uint32_t inner_hash[8];
        for (size_t i = 0; i < 8; ++i) inner_hash[i] = ppid_inner_bw_[ppid_inner_nb_ - 1].h1[i];
        
        std::vector<uint8_t> outer_full_data;
        for (size_t i = 0; i < 64; ++i) outer_full_data.push_back(padded_hmac_key[i] ^ 0x5c); // k_opad
        for (size_t i = 0; i < 8; ++i) {
            outer_full_data.push_back((inner_hash[i] >> 24) & 0xff);
            outer_full_data.push_back((inner_hash[i] >> 16) & 0xff);
            outer_full_data.push_back((inner_hash[i] >> 8) & 0xff);
            outer_full_data.push_back(inner_hash[i] & 0xff);
        }
        uint8_t outer_padded_full[64 * 2] = {0};
        FlatSHA256Witness::transform_and_witness_message(outer_full_data.size(), outer_full_data.data(), 2, ppid_outer_nb_, outer_padded_full, ppid_outer_bw_);
    }

    return MDOC_PROVER_SUCCESS;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_WITNESS_H_
