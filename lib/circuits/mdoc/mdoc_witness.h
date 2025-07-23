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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_WITNESS_H_

#include <stddef.h>
#include <string.h>

#include <array>
#include <cstdint>
#include <iterator>
#include <vector>

#include "arrays/dense.h"
#include "cbor/host_decoder.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/mac/mac_witness.h"
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

// This class represents an attribute that is parsed out of the deviceResponse
// data structure. It includes offsets into the original mdoc which can be used
// to construct SHA witnesses for disclosing the value of an attribute.
struct FullAttribute {
  // Offset and length of the attribute identifier and attribute value.
  size_t id_ind;
  size_t id_len;
  size_t val_ind;
  size_t val_len;

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

  size_t witness_length(const RequestedAttribute&  attr) {
    size_t r = id_len + val_len + 1 + 12;
    if (attr.type == CborAttributeType::kDate) {
      r += 4;
    } else if (attr.type == CborAttributeType::kString ||
               attr.type == CborAttributeType::kBytes) {
      r += 1;
      if (val_len > 23) r++;
      if (val_len > 255) r++;
    }
    return r;
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
  bool parse_device_response(size_t len, const uint8_t resp[/* len */]) {
    size_t np = 0;
    // When this object falls out of scope, all parsing objects will be
    // garbage collected.
    CborDoc root;
    bool ok = root.decode(resp, len, np, 0);
    if (!ok) {
      log(ERROR, "Failed to decode root");
      return false;
    }

    size_t di;
    auto docs = root.lookup(resp, 9, (uint8_t*)"documents", di);
    if (docs == nullptr) return false;
    // Fields of Document are "docType", "issuerSigned", "deviceSigned", ?errors

    auto docs0 = docs[1].index(0);
    if (docs0 == nullptr) return false;

    auto dt = docs0[0].lookup(resp, 7, (uint8_t*)"docType", di);
    if (dt == nullptr) return false;
    doc_type_.insert(doc_type_.begin(), resp + dt[1].u_.string.pos,
                     resp + dt[1].u_.string.pos + dt[1].u_.string.len);

    // The returned docs0 is the map, so index at [0].
    auto is = docs0[0].lookup(resp, 12, (uint8_t*)"issuerSigned", di);
    if (is == nullptr) return false;

    auto ia = is[1].lookup(resp, 10, (uint8_t*)"issuerAuth", di);
    if (ia == nullptr) return false;

    auto tmso = ia[1].index(2);
    if (tmso == nullptr) return false;
    copy_header(t_mso_, tmso);
    auto nsig = ia[1].index(3);
    if (nsig == nullptr) return false;
    copy_header(sig_, nsig);

    auto ns = is[1].lookup(resp, 10, (uint8_t*)"nameSpaces", di);
    if (ns == nullptr) return false;

    // Find the attribute witness we need from here.
    // For now, we only support 1 namespace.
    auto mldns = ns[1].lookup(resp, 17, (uint8_t*)"eu.europa.ec.eudi.pid.1", di);
    if (mldns == nullptr) return false;
    size_t ai = 0;
    auto tattr = mldns[1].index(ai++);
    while (tattr != nullptr) {
      CborDoc er;
      // Decode the map in this tagged attribute.
      size_t pos = tattr->children_[0].u_.string.pos;
      size_t end = pos + tattr->children_[0].u_.string.len;
      if (!er.decode(resp, end, pos, 0)) {
        return false;
      }

      auto ei = er.lookup(resp, 17, (uint8_t*)"elementIdentifier", di);
      if (ei == nullptr) return false;
      auto ev = er.lookup(resp, 12, (uint8_t*)"elementValue", di);
      if (ev == nullptr) return false;
      auto digid = er.lookup(resp, 8, (uint8_t*)"digestID", di);
      if (digid == nullptr) return false;

      attributes_.push_back(
          (FullAttribute){ei[1].position(),
                          ei[1].length(),
                          ev[1].position(),
                          ev[1].length(),
                          static_cast<size_t>(digid[1].u_.u64), /* digest_id */
                          {0, 0, 0},          /* default mso_ind */
                          tattr->header_pos_, /* tag_ind */
                          tattr->children_[0].u_.string.len +
                              4, /* +4 for the D8 18 58 <> prefix */
                          resp});

      tattr = mldns[1].index(ai++);
    }

    auto ds = docs0[0].lookup(resp, 12, (uint8_t*)"deviceSigned", di);
    if (ds == nullptr) return false;
    auto da = ds[1].lookup(resp, 10, (uint8_t*)"deviceAuth", di);
    if (da == nullptr) return false;
    auto dsi = da[1].lookup(resp, 15, (uint8_t*)"deviceSignature", di);
    if (dsi == nullptr) return false;
    auto ndksig = dsi[1].index(3);
    if (ndksig == nullptr) return false;
    copy_header(dksig_, ndksig);

    // Then parse tagged mso. Skip 5 bytes to skip the D8 18 59 <len2>.
    const uint8_t* pmso = resp + tmso->u_.string.pos + 5;
    size_t pos = 0;
    CborDoc mso;
    if (!mso.decode(pmso, tmso->u_.string.len - 5, pos, 0)) return false;
    auto nv = mso.lookup(pmso, kValidityInfoLen, kValidityInfoID, valid_.ndx);
    if (nv == nullptr) return false;
    copy_kv_header(valid_, nv);

    auto nvf = nv[1].lookup(pmso, kValidFromLen, kValidFromID, valid_from_.ndx);
    if (nvf == nullptr) return false;
    copy_kv_header(valid_from_, nvf);

    auto nvu =
        nv[1].lookup(pmso, kValidUntilLen, kValidUntilID, valid_until_.ndx);
    if (nvu == nullptr) return false;
    copy_kv_header(valid_until_, nvu);

    auto ndki = mso.lookup(pmso, kDeviceKeyInfoLen, kDeviceKeyInfoID,
                           dev_key_info_.ndx);
    if (ndki == nullptr) return false;
    copy_kv_header(dev_key_info_, ndki);

    auto ndk = ndki[1].lookup(pmso, kDeviceKeyLen, kDeviceKeyID, dev_key_.ndx);
    if (ndk == nullptr) return false;
    copy_kv_header(dev_key_, ndk);

    auto npkx = ndk[1].lookup_negative(-1, dev_key_pkx_.ndx);
    if (npkx == nullptr) return false;
    copy_kv_header(dev_key_pkx_, npkx);

    auto npky = ndk[1].lookup_negative(-2, dev_key_pky_.ndx);
    if (npky == nullptr) return false;
    copy_kv_header(dev_key_pky_, npky);

    auto nvd =
        mso.lookup(pmso, kValueDigestsLen, kValueDigestsID, value_digests_.ndx);
    if (nvd == nullptr) return false;
    copy_kv_header(value_digests_, nvd);

    auto norg = nvd[1].lookup(pmso, kOrgLen, kOrgID, org_.ndx);
    if (norg == nullptr) return false;
    copy_kv_header(org_, norg);

    for (auto& attr : attributes_) {
      uint64_t hi = (uint64_t)attr.digest_id;
      auto hattr = norg[1].lookup_unsigned(hi, attr.mso.ndx);
      if (hattr == nullptr) return false;
      copy_kv_header(attr.mso, hattr);
    }

    tagged_mso_bytes_.assign(std::begin(kCose1Prefix), std::end(kCose1Prefix));
    // Add 2-byte length
    tagged_mso_bytes_.push_back((t_mso_.len >> 8) & 0xff);
    tagged_mso_bytes_.push_back(t_mso_.len & 0xff);
    for (size_t i = 0; i < t_mso_.len; ++i) {
      tagged_mso_bytes_.push_back(resp[t_mso_.pos + i]);
    }

    return true;
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

static inline void append_bytes_len(std::vector<uint8_t>& buf, size_t len) {
  if (len > 256) {
    uint8_t ll[] = {0x59, (uint8_t)((len >> 8) & 0xff), (uint8_t)(len & 0xff)};
    buf.insert(buf.end(), ll, ll + 3);
  } else {
    uint8_t ll[] = {0x58, static_cast<uint8_t>(len & 0xff)};
    buf.insert(buf.end(), ll, ll + 2);
  }
}

static inline void append_text_len(std::vector<uint8_t>& buf, size_t len) {
  check(len < 256, "Text length too large");
  if (len < 24) {
    buf.push_back(0x60 + len);
  } else if (len < 255) {
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

  if (docType != nullptr) {
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
    v[i*8 + j] = ( b >> j & 0x1 ) ? F.one() : F.zero();
  }
}

template <class Field>
void fill_attribute(DenseFiller<Field> &filler, const RequestedAttribute &attr,
                    const Field &F, size_t version = 2) {
  if (version <= 2) {
    fill_bit_string(filler, attr.id, attr.id_len, 32, F);
    fill_bit_string(filler, attr.value, attr.value_len, 64, F);
  } else if (version == 3) {
    // In version 3, the attribute is encoded as the raw cbor string that
    // included <name of identifier> <elementValue> <attributeValue>
    std::vector<typename Field::Elt> v(96 * 8, F.of_scalar(0));

    size_t i = 0;
    for (size_t j = 0; j < attr.id_len && i < 96; ++j, ++i) {
      fill_byte(v, attr.id[j], i, F);
    }
    fill_byte(v, 0x6C, i++, F);  // Cbor type for length 12 string.
    const char* ev = "elementValue";
    for (size_t j = 0; j < 12 && i < 96; ++j, ++i) {
      fill_byte(v, ev[j], i, F);
    }
    std::vector<uint8_t> vbuf;
    uint8_t tag[] = {0xD9, 0x03, 0xEC, 0x6A};
    switch (attr.type) {
      case CborAttributeType::kPrimitive:
        vbuf.push_back(attr.value[0]);
        break;
      case CborAttributeType::kString:
        append_text_len(vbuf, attr.value_len);
        vbuf.insert(vbuf.end(), attr.value, attr.value + attr.value_len);
        break;
      case CborAttributeType::kBytes:
        append_bytes_len(vbuf, attr.value_len);
        vbuf.insert(vbuf.end(), attr.value, attr.value + attr.value_len);
        break;
      case CborAttributeType::kDate:
        vbuf.insert(vbuf.end(), tag, tag + 4);
        vbuf.insert(vbuf.end(), attr.value, attr.value + attr.value_len);
        break;
      case CborAttributeType::kInt:
        vbuf.insert(vbuf.end(), attr.value, attr.value + attr.value_len);
        break;
    }
    for (size_t j = 0; j < vbuf.size() && i < 96; ++j, ++i) {
      fill_byte(v, vbuf[j], i, F);
    }
    filler.push_back(v);
  }
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

  bool compute_witness(Elt pkX, Elt pkY, const uint8_t mdoc[/* len */],
                       size_t len, const uint8_t transcript[/* tlen */],
                       size_t tlen) {
    ParsedMdoc pm;

    if (!pm.parse_device_response(len, mdoc)) {
      return false;
    }

    Nat ne = nat_from_hash<Nat>(pm.tagged_mso_bytes_.data(),
                                pm.tagged_mso_bytes_.size());
    e_ = ec_.f_.to_montgomery(ne);

    // Parse (r,s).
    const size_t l = pm.sig_.len;
    Nat nr = nat_from_be<Nat>(&mdoc[pm.sig_.pos]);
    Nat ns = nat_from_be<Nat>(&mdoc[pm.sig_.pos + l / 2]);
    ew_.compute_witness(pkX, pkY, ne, nr, ns);

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
    dkw_.compute_witness(dpkx_, dpky_, ne2, nr2, ns2);
    return true;
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

  FlatSHA256Witness::BlockWitness bw_[kMaxSHABlocks];

  ParsedMdoc pm_;

  uint8_t now_[20]; /* CBOR-formatted time used for expiry comparison. */

  explicit MdocHashWitness(size_t num_attr, const EC& ec, const Field& Fn)
      : ec_(ec), fn_(Fn), num_attr_(num_attr) {}

  void fill_cbor_index(DenseFiller<Field>& df, const CborIndex& ind) const {
    df.push_back(ind.k, kCborIndexBits, fn_);
  }

  void fill_attr_shift(DenseFiller<Field>& df, const AttrShift& attr) const {
    df.push_back(attr.offset, kCborIndexBits, fn_);
    df.push_back(attr.len, kCborIndexBits, fn_);
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

  void fill_witness(DenseFiller<Field>& filler) const {
    // Fill sha of main mso.
    filler.push_back(numb_, 8, fn_);
    // Don't push the prefix.
    for (size_t i = kCose1PrefixLen; i < kMaxSHABlocks * 64; ++i) {
      filler.push_back(signed_bytes_[i], 8, fn_);
    }
    for (size_t j = 0; j < kMaxSHABlocks; j++) {
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
    }
  }

  bool compute_witness(const uint8_t mdoc[/* len */], size_t len,
                       const uint8_t transcript[/* tlen */], size_t tlen,
                       const RequestedAttribute attrs[], size_t attrs_len,
                       const uint8_t tnow[/*20*/], size_t version = 2) {
    if (!pm_.parse_device_response(len, mdoc)) {
      log(ERROR, "Failed to parse device response");
      return false;
    }

    std::vector<uint8_t> buf;
    if (pm_.t_mso_.len >= kMaxSHABlocks * 64 - 9 - kCose1PrefixLen) {
      log(ERROR, "tagged mso is too big: %zu", pm_.t_mso_.len);
      return false;
    }

    buf.assign(std::begin(kCose1Prefix), std::end(kCose1Prefix));
    // Add 2-byte length
    buf.push_back((pm_.t_mso_.len >> 8) & 0xff);
    buf.push_back(pm_.t_mso_.len & 0xff);
    for (size_t i = 0; i < pm_.t_mso_.len; ++i) {
      buf.push_back(mdoc[pm_.t_mso_.pos + i]);
    }

    FlatSHA256Witness::transform_and_witness_message(
        buf.size(), buf.data(), kMaxSHABlocks, numb_, signed_bytes_, bw_);

    ECNat ne = nat_from_u32<ECNat>(bw_[numb_ - 1].h1);
    e_ = ec_.f_.to_montgomery(ne);

    memcpy(now_, tnow, 20);

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

    // Match the attributes with the witnesses from the deviceResponse.
    for (size_t i = 0; i < attrs_len; ++i) {
      attr_bytes_[i].resize(128);
      atw_[i].resize(2);
      bool found = false;
      for (auto fa : pm_.attributes_) {
        if (fa == attrs[i]) {
          FlatSHA256Witness::transform_and_witness_message(
              fa.tag_len, &fa.doc[fa.tag_ind], 2, attr_n_[i],
              &attr_bytes_[i][0], &atw_[i][0]);
          attr_mso_[i] = fa.mso;
          attr_ei_[i].offset = fa.id_ind - fa.tag_ind;
          attr_ei_[i].len = fa.id_len;
          if (version > 2) {
            attr_ei_[i].len = fa.witness_length(attrs[i]);
          }
          attr_ev_[i].offset = fa.val_ind - fa.tag_ind;
          attr_ev_[i].len = fa.val_len;
          found = true;
          break;
        }
      }
      if (!found) {
        log(ERROR, "Could not find attribute %.*s", attrs[i].id_len,
            attrs[i].id);
        return false;
      }
    }
    return true;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_WITNESS_H_
