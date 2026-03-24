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

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_PROVER_H_

#include <stddef.h>

#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "random/random.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover_layers.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"

namespace proofs {
// ZK Prover
//
// This class implements a zero-knowledge argument over a sumcheck transcript
// by first committing to a sumcheck witness and a random pad to encrypt
// a sumcheck transcript, then running the sumcheck protocol over the original
// claim and witness, but outputting the encrypted transcript, and finally
// using a Ligero prover to prove the statement: "the committed witness and
// pad, when used to decrypt the encrypted sumcheck transcript satisfies the
// sumcheck verifier."
//
// While this statement is complex, it can be implemented easily because
// the sumcheck verifier essentially checks the evaluations of degree-2 or -3
// polynomials, and performs one multiplication per layer of the circuit. The
// Hyrax paper makes a similar observation, but uses an elliptic-curve based
// proof, whereas here we use the Ligero system.
template <class Field, class ReedSolomonFactory>
class ZkProver : public ProverLayers<Field> {
  using super = ProverLayers<Field>;
  using typename super::bindings;
  using Elt = typename Field::Elt;
  using typename super::inputs;

 public:
  ZkProver(const Circuit<Field>& CIRCUIT, const Field& F,
           const ReedSolomonFactory& rs_factory)
      : ProverLayers<Field>(F),
        c_(CIRCUIT),
        n_witness_(c_.ninputs - c_.npub_in),
        f_(F),
        rsf_(rs_factory),
        pad_(c_.nl),
        witness_(n_witness_),
        lqc_(c_.nl),
        lp_(nullptr) {}

  void commit(ZkProof<Field>& zkp, const Dense<Field>& W, Transcript& tp,
              RandomEngine& rng) {
    log(INFO, "ZK Commit start");

    // Copy witnesses for commitment
    // Layout of the com: 0 ...<witnesses>... start_pad <pad> len
    // Only commit the private witnesses, which begin at index c_.npub_in.
    for (size_t i = 0; i < n_witness_; ++i) {
      witness_[i] = W.v_[i + c_.npub_in];
    }

    // Rebase the circuit SUBFIELD_BOUNDARY (if any) to start at
    // NPUB_IN,
    size_t subfield_boundary = 0;
    if (c_.subfield_boundary >= c_.npub_in) {
      subfield_boundary = c_.subfield_boundary - c_.npub_in;
    }

    // Fill pad with random values, add pad to witness, record lqc.
    fill_pad(rng);
    ZkCommon<Field>::setup_lqc(c_, lqc_, n_witness_ /* = start_pad */);

    // Commit to witness and pad.
    lp_ = std::make_unique<LigeroProver<Field, ReedSolomonFactory>>(zkp.param);
    lp_->commit(zkp.com, tp, &witness_[0], subfield_boundary, &lqc_[0], rsf_,
                rng, f_);

    log(INFO, "ZK Commitment done");
  }

  bool prove(ZkProof<Field>& zkp, const Dense<Field>& W, Transcript& tsp) {
    check(lp_ != nullptr, "must run commit before prove");

    // Interpret W as public parameters, we only append
    // c_.npub_in elements of W to the transcript
    ZkCommon<Field>::initialize_sumcheck_fiat_shamir(tsp, c_, W, f_);
    Transcript tst = tsp.clone();

    // Run sumcheck to generate a padded proof.
    inputs in;
    auto V = super::eval_circuit(&in, &c_, W.clone(), f_);
    if (V == nullptr) {
      log(ERROR, "eval_circuit failed");
      return false;
    }
    for (size_t i = 0; i < V->n1_; ++i) {
      if (V->v_[i] != f_.zero()) {
        log(ERROR, "V->v_[i] != F.zero()");
        return false;
      };
    }
    bindings bnd;
    ProofAux<Field> aux(c_.nl);

    TranscriptSumcheck<Field> tsts(tst, f_);
    super::prove(&zkp.proof, &pad_, &c_, in, &aux, bnd, tsts, f_);
    log(INFO, "ZK sumcheck done");

    // 5. Simulate the verifier to assemble constraints on the committed vals.
    //    Form the sparse matrix A and vector b such that A*w = b.
    std::vector<LigeroLinearConstraint<Field>> a;
    std::vector<Elt> b;
    size_t ci = ZkCommon<Field>::verifier_constraints(c_, W, zkp.proof, &aux, a,
                                                      b, tsp, n_witness_, f_);
    log(INFO, "ZK constraints done");

    // 6. Produce proof over commitment.
    // For FS soundness, it is ok for hash_of_A to be any string.
    // In the interactive version, the verifier provides a challenge for the
    // com proof. The last prover message is the (wc_l,wc_r) pair, and this
    // has already been added to the transcript.
    const LigeroHash hash_of_A{0xde, 0xad, 0xbe, 0xef};
    lp_->prove(zkp.com_proof, tsp, ci, a.size(), &a[0], hash_of_A, &lqc_[0],
               rsf_, f_);

    log(INFO, "Prover Done: flag");
    return true;
  }

  // Fill proof with random pad values for a given circuit.
  void fill_pad(RandomEngine& rng) {
    for (size_t i = 0; i < c_.nl; ++i) {
      for (size_t j = 0; j < c_.logc; ++j) {
        for (size_t k = 0; k < 4; ++k) {
          if (k != 1) {  // P(1) optimization
            Elt r = rng.elt(f_);
            pad_.l[i].cp[j].t_[k] = r;
            witness_.push_back(r);
          } else {
            pad_.l[i].cp[j].t_[k] = f_.zero();
          }
        }
      }
      for (size_t j = 0; j < c_.l[i].logw; ++j) {
        for (size_t h = 0; h < 2; ++h) {
          for (size_t k = 0; k < 3; ++k) {
            if (k != 1) {  // P(1) optimization
              Elt r = rng.elt(f_);
              pad_.l[i].hp[h][j].t_[k] = r;
              witness_.push_back(r);
            } else {
              pad_.l[i].hp[h][j].t_[k] = f_.zero();
            }
          }
        }
      }
      for (size_t k = 0; k < 2; ++k) {
        Elt r = rng.elt(f_);
        pad_.l[i].wc[k] = r;
        witness_.push_back(r);
      }

      // Commit to product of pads for product proof.
      Elt rr = f_.mulf(pad_.l[i].wc[0], pad_.l[i].wc[1]);
      witness_.push_back(rr);
    }
  }

  const Circuit<Field>& c_;
  const size_t n_witness_;
  const Field& f_;
  const ReedSolomonFactory& rsf_;
  Proof<Field> pad_;
  std::vector<Elt> witness_;
  std::vector<LigeroQuadraticConstraint> lqc_;
  std::unique_ptr<LigeroProver<Field, ReedSolomonFactory>> lp_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_PROVER_H_
