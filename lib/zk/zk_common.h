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

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_COMMON_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_COMMON_H_

#include <cstddef>
#include <vector>

#include "arrays/dense.h"
#include "arrays/eq.h"
#include "arrays/eqs.h"
#include "ligero/ligero_param.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/quad.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/panic.h"

namespace proofs {

template <class Field>
// ZkCommon
//
// Used by prover and verifier to mimic the checks that the sumcheck verifier
// applies to the sumcheck transcript. The difference is that the transcript
// will now be encrypted with a random pad, and the checks will be verified
// by the Ligero proof system with respect to a hiding commitment scheme.
class ZkCommon {
  using index_t = typename Quad<Field>::index_t;
  using Llc = LigeroLinearConstraint<Field>;
  using Elt = typename Field::Elt;
  using CPoly = typename LayerProof<Field>::CPoly;
  using WPoly = typename LayerProof<Field>::WPoly;

 public:
  // pi: witness index for first pad element in a larger commitment
  static size_t verifier_constraints(
      const Circuit<Field>& circuit, const Dense<Field>& pub,
      const Proof<Field>& proof, const ProofAux<Field>* aux,
      std::vector<Llc>& a, std::vector<typename Field::Elt>& b, Transcript& tsv,
      size_t pi, const Field& F) {
    const size_t ninp = circuit.ninputs, npub = circuit.npub_in;

    Challenge<Field> ch(circuit.nl);
    TranscriptSumcheck<Field> tss(tsv, F);

    tss.begin_circuit(ch.q, ch.g);
    Claims cla = Claims{
        .logv = circuit.logv,
        .claim = {F.zero(), F.zero()},
        .q = ch.q,
        .g = {ch.g, ch.g},
    };

    size_t ci = 0;  // Index of the next Ligero constraint.

    const typename WPoly::dot_interpolation dot_wpoly(F);

    // no copies in this version.
    check(circuit.logc == 0, "assuming that copies=1");

    // Constraints from the sumcheck verifier.
    for (size_t ly = 0; ly < circuit.nl; ++ly) {
      auto clr = &circuit.l.at(ly);
      auto plr = &proof.l[ly];
      auto challenge = &ch.l[ly];

      tss.begin_layer(challenge->alpha, challenge->beta, ly);

      // The loop below assumes at least one round.
      check(clr->logw > 0, "clr->logw > 0");

      PadLayout pl(clr->logw);
      ConstraintBuilder cb(pl, F);  // representing 0

      cb.first(challenge->alpha, cla.claim);
      // now cb contains claim_{-1} from the previous layer

      for (size_t round = 0; round < clr->logw; ++round) {
        for (size_t hand = 0; hand < 2; ++hand) {
          size_t r = 2 * round + hand;
          const WPoly& hp = plr->hp[hand][round];
          challenge->hb[hand][round] = tss.round(hp);
          const WPoly lag = dot_wpoly.coef(challenge->hb[hand][round], F);

          cb.next(r, &lag[0], hp.t_);
          // now cb contains a symbolic representation of claim_{r}
        }
      }

      // Verify
      //        claim = EQ[Q,C] QUAD[R,L] W[R,C] W[L,C]
      // by substituting in the symbolic constraint on p(1) from the relation:
      //      claim = <lag, (p(0), p(1), p(2))>.
      Elt quad = aux == nullptr ? bind_quad(clr, cla, challenge, F)
                                : aux->bound_quad[ly];
      Elt eqv =
          Eq<Field>::eval(circuit.logc, circuit.nc, ch.q, challenge->cb, F);
      Elt eqq = F.mulf(eqv, quad);

      // Add the final constraint from above.
      cb.finalize(plr->wc, eqq, ci++, ly, pi, a, b);

      tss.write(&plr->wc[0], 1, 2);

      cla = Claims{
          .logv = clr->logw,
          .claim = {plr->wc[0], plr->wc[1]},
          .q = challenge->cb,
          .g = {challenge->hb[0], challenge->hb[1]},
      };

      pi += pl.layer_size();  // Update index to poly_pad(0,0) of the
                              // next layer
    }

    // Constraints induced by the input binding
    //   <eq0 + alpha.eq1, witness> = W_l + alpha.W_r
    Elt alpha = tsv.elt(F);
    auto plr = &proof.l[circuit.nl - 1];
    Elt got = F.addf(plr->wc[0], F.mulf(alpha, plr->wc[1]));

    return input_constraint(cla, pub, npub, ninp, pi, got, alpha, a, b, ci, F);
  }

  // Returns the size of the proof pad for circuit C.
  static size_t pad_size(const Circuit<Field>& C) {
    size_t sz = 0;
    for (size_t i = 0; i < C.nl; ++i) {
      PadLayout pl(C.l[i].logw);
      sz += pl.layer_size();
    }
    return sz;
  }

  // Setup lqc based on proof pad layout.
  static void setup_lqc(const Circuit<Field>& C,
                        std::vector<LigeroQuadraticConstraint>& lqc,
                        size_t start_pad) {
    size_t pi = start_pad;
    for (size_t i = 0; i < C.nl; ++i) {
      PadLayout pl(C.l[i].logw);
      lqc[i].x = pi + pl.claim_pad(0);
      lqc[i].y = pi + pl.claim_pad(1);
      lqc[i].z = pi + pl.claim_pad(2);
      pi += pl.layer_size();
    }
  }

  // append public parameters to the FS transcript
  static void initialize_sumcheck_fiat_shamir(Transcript& ts,
                                              const Circuit<Field>& circuit,
                                              const Dense<Field>& pub,
                                              const Field& F) {
    ts.write(circuit.id, sizeof(circuit.id));

    // Public inputs:
    for (size_t i = 0; i < circuit.npub_in; ++i) {
      ts.write(pub.at(i), F);
    }

    // Outputs pro-forma:
    ts.write(F.zero(), F);

    // Enough zeroes for correlation intractability, one byte
    // per term.
    ts.write0(circuit.nterms());
  }

 private:
  // The claims struct mimics the same object in the sumcheck code. This
  // helps the verifier_constraints method above mimic the same steps as
  // the sumcheck verifier.
  struct Claims {
    size_t logv;
    Elt claim[2];
    const Elt* q;
    const Elt* g[2];
  };

  class PadLayout {
    size_t logw_;

   public:
    explicit PadLayout(size_t logw) : logw_(logw) {}

    // Layout of padding in the expr_.symbolic array.
    //
    // A *claim pad* is a triple [dWC[0], dWC[1], dWC[0]*dWC[1]].
    //
    // A *poly pad* is a pair [dP(0), dP(2)], where "2" is a generic
    // name for the third evaluation point of the sumcheck round
    // polynomial (could be X for binary fields GF(2)[X] / (Q(X))).
    //
    // The layout of expr_.symbolic is
    //  [CLAIM_PAD[layer - 1], POLY_PAD[0], POLY_PAD[1], ..
    //   POLY_PAD[LOGW - 1], CLAIM_PAD[layer]]
    //
    // The layout of adjacent layers thus overlaps.  For layer 0
    // we still lay out CLAIM_PAD[layer - 1] to keep the representation
    // uniform, but we don't output the corresponding Ligero terms.

    // Because of different use cases, we have two indexing schemes:
    //
    //  "with overlap":     the first element is CLAIM_PAD[layer - 1][0]
    //  "without overlap":  the first element is POLY_PAD[0][0]

    //------------------------------------------------------------
    // Indexing without overlap.
    //------------------------------------------------------------
    size_t poly_pad(size_t r, size_t point) const {
      check(point == 0 || point == 2, "unknown poly_pad() layout");
      if (point == 0) {
        return 2 * r;
      } else if (point == 2) {
        return 2 * r + 1;
      }
      return 0;  // silence noreturn warning
    }
    // index of CLAIM_PAD[layer][n]
    size_t claim_pad(size_t n) const { return poly_pad(2 * logw_, 0) + n; }

    // size of the layer
    size_t layer_size() const { return claim_pad(3); }

    //------------------------------------------------------------
    // Indexing with overlap.
    //------------------------------------------------------------
    // index of CLAIM_PAD[layer - 1][n]
    size_t ovp_claim_pad_m1(size_t n) const { return n; }
    size_t ovp_poly_pad(size_t r, size_t point) const {
      return 3 + poly_pad(r, point);
    }
    size_t ovp_claim_pad(size_t n) const { return 3 + claim_pad(n); }
    size_t ovp_layer_size() const { return ovp_claim_pad(3); }
  };

  // Represent symbolic expressions of the form
  //
  // KNOWN + SUM_{i} SYMBOLIC[i] * WITNESS[i]
  //
  // and support simple linear operations on such quantities
  class Expression {
    Elt known_;
    std::vector<Elt> symbolic_;
    const Field& f_;

   public:
    Expression(size_t nvar, const Field& F)
        : known_(F.zero()), symbolic_(nvar, F.zero()), f_(F) {}

    Elt known() { return known_; }
    std::vector<Elt> symbolic() { return symbolic_; }

    void scale(const Elt& k) {
      f_.mul(known_, k);
      for (auto& e : symbolic_) {
        f_.mul(e, k);
      }
    }

    // We don't need the general case of combining two
    // Expressions.  Instead, we only need the two operations
    // below.

    // *this += k * (known_value + witness[var]).
    void axpy(size_t var, const Elt& known_value, const Elt& k) {
      f_.add(known_, f_.mulf(k, known_value));
      f_.add(symbolic_[var], k);
    }

    // *this -= k * (known_value + witness[var])
    void axmy(size_t var, const Elt& known_value, const Elt& k) {
      f_.sub(known_, f_.mulf(k, known_value));
      f_.sub(symbolic_[var], k);
    }
  };

  class ConstraintBuilder {
    Expression expr_;
    const PadLayout& pl_;
    const Field& f_;

   public:
    ConstraintBuilder(const PadLayout& pl, const Field& F)
        : expr_(pl.ovp_layer_size(), F), pl_(pl), f_(F) {}

    // For given unpadded variable X in the original non-ZK prover,
    // the transcript contains the padded variable Xhat = X - dX
    // where dX is the padding of X.  Thus the unpadded variable is
    //
    //    X = Xhat + dX
    //
    // The ZK verifier needs to compute linear combinations (and one
    // quadratic combination) of the X's, but it only has access to
    // the Xhat's and to a commitment to the dX's.  We also want to
    // discuss the verifier algorithm as if the verifier were
    // operating on X, in order to keep the discussion simple.
    //
    // To this end, the Expression class keeps a symbolic
    // representation of a variable X as
    //
    //     X = KNOWN + SUM_{i} SYMBOLIC[i] dX[i]
    //
    // which is sufficient to capture any linear combination of
    // X variables.  We do something special for the quadratic
    // combination in finalize().

    // We store only one quantity EXPR_ that represents either
    // p(1) at some certain round, or a claim at some round.
    // Comments make it clear which is which.

    // Initially, compute claim_{-1} = cl0 + alpha*cl1
    void first(Elt alpha, const Elt claims[]) {
      // expr_ contains zero
      expr_.axpy(pl_.ovp_claim_pad_m1(0), claims[0], f_.one());
      expr_.axpy(pl_.ovp_claim_pad_m1(1), claims[1], alpha);
      // expr_ contains claim_{-1} = cl0 + alpha*cl1
    }

    // Given claim_{r-1}, compute claim_{r}
    void next(size_t r, const Elt lag[], const Elt tr[]) {
      // expr contains claim_{r-1}
      expr_.axmy(pl_.ovp_poly_pad(r, 0), tr[0], f_.one());
      // expr contains p_{r}(1) = claim_{r-1} - p_{r}(0)

      // Compute the dot-product <lag_{r}, p_{r}> in place:
      //  claim_{r} = p_{r}(1) * lag[1], overwriting expr_
      //  claim_{r} += lag[0] * p_{r}(0)
      //  claim_{r} += lag[2] * p_{r}(2)
      expr_.scale(lag[1]);
      expr_.axpy(pl_.ovp_poly_pad(r, 0), tr[0], lag[0]);
      expr_.axpy(pl_.ovp_poly_pad(r, 2), tr[2], lag[2]);
      // expr_ contains claim_{r} = <lag_{r}, p_{r}>
    }

    // The finalize method uses the last sumcheck claim to
    // add a constraint on the dX's (the pad) to the Ligero system.
    //
    // Our goal is to verify that
    //
    //            CLAIM = EQQ * W[R,C] * W[L,C]
    //
    // where EQQ = EQ[Q,C] QUAD[R,L] and all variables are unpadded.
    //
    // We have a symbolic representation of CLAIM in expr_, the proof
    // contains W_hat[{R,L},C], the padding witnesses are at index pi,
    // pi+1, and their product is at index pi+2.
    //
    // Let CLAIM = KNOWN + SUM_{i} SYMBOLIC[i] dX[i] from the
    // Expression class.  Then
    //
    //     KNOWN + SUM_{i} SYMBOLIC[i] dX[i]
    //        = EQQ * (W_hat[R,C] + dW[R,C]) * (W_hat[L,C] + dW[L,C])
    //
    // Rearranging in the Ax = b form needed for ligero, we have
    //
    //  SUM_{i} SYMBOLIC[i] dX[i] - (EQQ * W[R, C]) dW[L, C]
    //      - (EQQ * W[L, C]) dW[R, C] - EQQ * dW[R,C] * dW[L,C]
    //   = EQQ * W[R,C] * W[L,C] - KNOWN
    void finalize(const Elt wc[], const Elt& eqq, size_t ci, size_t ly,
                  size_t pi, std::vector<Llc>& a, std::vector<Elt>& b) {
      // break the Expression abstraction and split into constituents.

      // EQQ * W[R,C] * W[L,C] - known
      Elt rhs = f_.subf(f_.mulf(eqq, f_.mulf(wc[0], wc[1])), expr_.known());

      // symbolic part
      std::vector<Elt> lhs = expr_.symbolic();
      f_.sub(lhs[pl_.ovp_claim_pad(0)], f_.mulf(eqq, wc[1]));
      f_.sub(lhs[pl_.ovp_claim_pad(1)], f_.mulf(eqq, wc[0]));
      f_.sub(lhs[pl_.ovp_claim_pad(2)], eqq);

      b.push_back(rhs);

      // Layer 0 does not refer to CLAIM_PAD[layer - 1]
      size_t i0 = (ly == 0) ? pl_.ovp_poly_pad(0, 0) : pl_.ovp_claim_pad_m1(0);

      for (size_t i = i0; i < lhs.size(); ++i) {
        // "i" is in the "with overlap" reference frame.
        // "pi" is in the "without overlap" reference frame.
        //
        // In theory at least, (pi - pl_.ovp_poly_pad(0, 0))
        // could overflow, but (pi + i) - pl_.ovp_poly_pad(0, 0) cannot.
        a.push_back(Llc{ci, (pi + i) - pl_.ovp_poly_pad(0, 0), lhs[i]});
      }
    }
  };

  // binding(inputs, R) = binding(pub_inputs, R_p) + binding(witness, R_w)
  // This method explicitly computes the public binding, and then adds the
  // constraints that
  //    binding(witness, R_w) = got - binding(pub_inputs, R_p)
  static size_t input_constraint(const Claims& cla, const Dense<Field>& pub,
                                 size_t pub_inputs, size_t num_inputs,
                                 size_t pi, Elt got, Elt alpha,
                                 std::vector<Llc>& a, std::vector<Elt>& b,
                                 size_t ci, const Field& F) {
    Eqs<Field> eq0(cla.logv, num_inputs, cla.g[0], F);
    Eqs<Field> eq1(cla.logv, num_inputs, cla.g[1], F);
    Elt pub_binding = F.zero();
    for (index_t i = 0; i < num_inputs; ++i) {
      Elt b_i = F.addf(eq0.at(i), F.mulf(alpha, eq1.at(i)));
      if (i < pub_inputs) {
        F.add(pub_binding, F.mulf(b_i, pub.at(i)));
      } else {
        // Use (i - pub_inputs) for the index of private inputs.
        a.push_back(Llc{ci, i - pub_inputs, b_i});
      }
    }

    // We view the input constraints as being at fake layer
    // one past the last real layer.  The alternative of
    // considering the input as part of the last real layer
    // yields code that looks even more convoluted.
    PadLayout pl(/*logw=*/0);

    // This paranoid assertion holds unless the circuit has zero
    // layers, which is not guaranteed by this function alone.
    check(pi >= pl.ovp_poly_pad(0, 0), "pi >= pl.ovp_poly_pad(0, 0)");

    size_t claim_pad_m1 = pi - pl.ovp_poly_pad(0, 0);
    a.push_back(Llc{ci, claim_pad_m1 + 0, F.mone()});
    a.push_back(Llc{ci, claim_pad_m1 + 1, F.negf(alpha)});
    b.push_back(F.subf(got, pub_binding));
    return ++ci;
  }

  static Elt bind_quad(const Layer<Field>* clr, const Claims& cla,
                       const LayerChallenge<Field>* chal, const Field& F) {
    return clr->quad->bind_gh_all(
        // G
        cla.logv, cla.g[0], cla.g[1], chal->alpha, chal->beta,
        // H
        clr->logw, chal->hb[0], chal->hb[1],
        // Field
        F);
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_COMMON_H_
