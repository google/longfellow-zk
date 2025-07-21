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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_REVOCATION_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_REVOCATION_H_

#include <cstddef>

#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/mdoc/mdoc_revocation_constants.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

// The first revocation approach works for small lists that are expected to
// be small. In this case, the prover simply asserts that their identifier is
// different from all the identifiers in the list.
template <class LogicCircuit>
class MdocRevocationList {
  using EltW = typename LogicCircuit::EltW;

 public:
  explicit MdocRevocationList(const LogicCircuit& lc) : lc_(lc) {}

  // This function asserts that a given identifier is not on a revocation list.
  // The method is to assert that Prod_i (list[i) - id) != 0.
  void assert_not_on_list(EltW list[], size_t list_size,
                          /* the witness */ EltW id, EltW prodinv) const {
    EltW prod =
        lc_.mul(0, list_size, [&](size_t i) { return lc_.sub(&list[i], id); });
    EltW want_one = lc_.mul(&prod, prodinv);
    lc_.assert_eq(&want_one, lc_.konst(lc_.one()));
  }

  const LogicCircuit& lc_;
};

// The second revocation approach works for larger lists. In this case, the
// prover retrieves a witness that their credential is *not* on the revoked
// list by presenting a signature of the span (l,r) and proving that their
// revocation identifier rev_id satisfied l < rev_id < r.
// Specifically, the format of the span is:
//   epoch || l || r
// where epoch is a 64 bit integer, l and r are 256 bit integers. All of
// the values are encoded in little endian order.
template <class LogicCircuit, class Field, class EC>
class MdocRevocationSpan {
  using EltW = typename LogicCircuit::EltW;
  using Nat = typename Field::N;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;
  using EcdsaWitness = typename Ecdsa::Witness;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Flatsha =
      FlatSHA256Circuit<LogicCircuit,
                        BitPlucker<LogicCircuit, kSHARevocationPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;

 public:
  class Witness {
   public:
    EltW r_, s_, e_;
    EcdsaWitness rev_sig_;
    v8 preimage_[64 * 2];  //  epoch || l || r  in little endian order
    v256 id_bits_;
    v256 e_bits_;
    ShaBlockWitness sha_[2];

    void input(QuadCircuit<Field>& Q, const LogicCircuit& lc) {
      r_ = Q.input();
      s_ = Q.input();
      e_ = Q.input();
      rev_sig_.input(Q);
      for (size_t i = 0; i < 64 * 2; ++i) {
        preimage_[i] = lc.template vinput<8>();
      }
      id_bits_ = lc.template vinput<256>();
      e_bits_ = lc.template vinput<256>();
      for (size_t j = 0; j < 2; j++) {
        sha_[j].input(Q);
      }
    }
  };

  explicit MdocRevocationSpan(const LogicCircuit& lc, const EC& ec,
                              const Nat& order)
      : lc_(lc), ec_(ec), order_(order), sha_(lc) {}

  // This function asserts that id is not on the revocation list by verifying
  // that the signature (r,s) on the span (l,r) is valid, and then verifying
  // that l < id < r.  The argument (craPkX, craPkY) represent the public key
  // of the issuer of the revocation list.
  void assert_not_on_list(EltW craPkx, EltW craPkY,
                          /* the witness */ EltW id, Witness& vw) const {
    Ecdsa ecc(lc_, ec_, order_);

    ecc.verify_signature3(craPkx, craPkY, vw.e_, vw.rev_sig_);

    lc_.vassert_is_bit(vw.e_bits_);
    lc_.vassert_is_bit(vw.id_bits_);

    // Check that e = hash(epoch || l || r)
    auto two = lc_.template vbit<8>(2);
    sha_.assert_message_hash(2, two, vw.preimage_, vw.e_bits_, vw.sha_);

    // Check that the bits of e match the EltW for e.
    auto twok = lc_.one();
    auto est = lc_.konst(0);
    for (size_t i = 0; i < 256; ++i) {
      est = lc_.axpy(&est, twok, lc_.eval(vw.e_bits_[i]));
      lc_.f_.add(twok, twok);
    }
    lc_.assert_eq(&est, vw.e_);

    // // Check that l < id < r
    v256 ll, rr;
    for (size_t i = 0; i < 256; ++i) {
      ll[i] = vw.preimage_[8 + i / 8][i % 8];
      rr[i] = vw.preimage_[40 + i / 8][i % 8];
    }
    lc_.assert1(lc_.vlt(&ll, vw.id_bits_));
    lc_.assert1(lc_.vlt(&vw.id_bits_, rr));
  }

  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;
  Flatsha sha_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_REVOCATION_H_
