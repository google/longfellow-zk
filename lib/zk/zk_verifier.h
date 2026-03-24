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

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_VERIFIER_H_

#include <stddef.h>

#include <vector>

#include "arrays/dense.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_verifier.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"

namespace proofs {
// ZK Verifier
//
// Verifies a zk proof. See note in the prover for the design.
// To verify a proof, instantiate the class, then call recv_commitment with
// the commitment, and finally call verify. It is possible to receive several
// commitments, or run other protocols between the recv_commitment and verify
// calls. This allows composing two proofs in parallel.
// To support this, the interface to both accepts a raw Transcript.
template <class Field, class RSFactory>
class ZkVerifier {
  using Elt = typename Field::Elt;

 public:
  explicit ZkVerifier(const Circuit<Field>& c, const RSFactory& rsf,
                      size_t rate, size_t nreq, const Field& F)
      : circ_(c),
        n_witness_(c.ninputs - c.npub_in),
        param_(n_witness_ + ZkCommon<Field>::pad_size(c), c.nl, rate, nreq),
        lqc_(c.nl),
        rsf_(rsf),
        f_(F) {
    ZkCommon<Field>::setup_lqc(c, lqc_, n_witness_);
  }

  explicit ZkVerifier(const Circuit<Field>& c, const RSFactory& rsf,
                      size_t rate, size_t nreq, size_t block_enc,
                      const Field& F)
      : circ_(c),
        n_witness_(c.ninputs - c.npub_in),
        param_(n_witness_ + ZkCommon<Field>::pad_size(c), c.nl, rate, nreq,
               block_enc),
        lqc_(c.nl),
        rsf_(rsf),
        f_(F) {
    ZkCommon<Field>::setup_lqc(c, lqc_, n_witness_);
  }

  void recv_commitment(const ZkProof<Field>& zk, Transcript& t) const {
    log(INFO, "verifier: recv commit");
    LigeroVerifier<Field, RSFactory>::receive_commitment(zk.com, t);
  }

  // Verifies the proof.
  bool verify(const ZkProof<Field>& zk, const Dense<Field>& pub,
              Transcript& tv) const {
    log(INFO, "verifier: verify");

    ZkCommon<Field>::initialize_sumcheck_fiat_shamir(tv, circ_, pub, f_);

    // Derive constraints on the witness.
    using Llc = LigeroLinearConstraint<Field>;
    std::vector<Llc> A;
    std::vector<Elt> b;
    const LigeroHash hash_of_A{0xde, 0xad, 0xbe, 0xef};
    size_t cn = ZkCommon<Field>::verifier_constraints(circ_, pub, zk.proof,
                                                      /*aux=*/nullptr, A, b, tv,
                                                      n_witness_, f_);

    const char* why = "";
    bool ok = LigeroVerifier<Field, RSFactory>::verify(
        &why, param_, zk.com, zk.com_proof, tv, cn, A.size(), &A[0], hash_of_A,
        &b[0], &lqc_[0], rsf_, f_);

    log(INFO, "verify done: %s", why);
    return ok;
  }

 private:
  const Circuit<Field>& circ_;
  const size_t n_witness_;
  const LigeroParam<Field> param_;
  std::vector<LigeroQuadraticConstraint> lqc_;
  const RSFactory& rsf_;
  const Field& f_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_VERIFIER_H_
