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

#ifndef PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_LAYERS_H_
#define PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_LAYERS_H_

#include <stddef.h>

#include <memory>
#include <vector>

#include "arrays/affine.h"
#include "arrays/dense.h"
#include "arrays/eqs.h"
#include "sumcheck/circuit.h"
#include "sumcheck/quad.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/panic.h"

namespace proofs {

// A high level idea is partially described in chapter 4.6.7 "Leveraging Data
// Parallelism for Further Speedups" in the book "Proofs, Arguments, and
// Zero-Knowledge" by Justin Thaler.
template <class Field>
class ProverLayers {
  using Elt = typename Field::Elt;

 public:
  using inputs = std::vector<std::unique_ptr<Dense<Field>>>;

  explicit ProverLayers(const Field& f) : f_(f) {}

  // Evaluate CIRCUIT on input wires W0.  This function stores the
  // input wires of each layer L into IN->at(L), and returns the
  // final output.  This asymmetry reflects the fact that for L
  // layers there are L+1 meaningful sets of wires, and that the
  // prover needs IN while the verifier needs the final output.
  std::unique_ptr<Dense<Field>> eval_circuit(inputs* in,
                                             const Circuit<Field>* circ,
                                             std::unique_ptr<Dense<Field>> W0,
                                             const Field& F) {
    if (in == nullptr || circ == nullptr || W0 == nullptr) return nullptr;

    std::unique_ptr<Dense<Field>> finalV;
    size_t nl = circ->nl, nc = circ->nc;
    check(nl >= 1, "nl >= 1");
    check(nc >= 1, "nc >= 1");

    Dense<Field>* W = W0.get();

    in->resize(nl);
    in->at(nl - 1).swap(W0);

    // Allocate memory and evaluate layer on input W and output V
    for (size_t l = nl; l-- > 0;) {
      Dense<Field>* V;
      if (l > 0) {
        // input of layer l-1 = output of layer l
        in->at(l - 1) = std::make_unique<Dense<Field>>(nc, circ->l[l - 1].nw);
        V = in->at(l - 1).get();
      } else {
        // final output = output of layer 0
        finalV = std::make_unique<Dense<Field>>(nc, circ->nv);
        V = finalV.get();
      }

      bool ok = eval_quad(circ->l[l].quad.get(), V, W, F);
      if (!ok) {
        // Early exit in case of assertion failure.
        // In this case IN is only partially allocated.
        // To avoid ambiguities, free all memory that we may have allocated.
        for (size_t i = 0; i < nl; ++i) {
          in->at(i) = nullptr;
        }
        finalV = nullptr;

        return /*finalV=*/nullptr;
      }

      W = V;
    }

    return finalV;
  }

 protected:
  const Field& f_;

  // A struct that collects the bindings generated while proving one
  // layer, to serve as initial bindings for the next layer.
  // This protected class must be defined before the public section.
  struct bindings {
    size_t logv;
    Elt q[Proof<Field>::kMaxBindings];
    Elt g[2][Proof<Field>::kMaxBindings];
  };

  // Generate proof for circuit, as a protected member, the caller must
  // ensure that input parameters are valid.
  void prove(Proof<Field>* pr, const Proof<Field>* pad,
             const Circuit<Field>* circ, const inputs& in, ProofAux<Field>* aux,
             bindings& bnd, TranscriptSumcheck<Field>& ts, const Field& F) {
    size_t logc = circ->logc;
    corner_t nc = circ->nc;

    check(circ->logv <= Proof<Field>::kMaxBindings,
          "CIRCUIT->logv <= kMaxBindings");
    bnd.logv = circ->logv;

    // obtain the initial Q and G[0] bindings from the verifier
    ts.begin_circuit(bnd.q, bnd.g[0]);

    // Duplicate the g[0] binding.
    // In general, the prover step takes two claims G[0], G[1] on the output
    // wires and reduces them to one claim on G[0] + alpha * G[1] for random
    // alpha. However, in the first step, there is only one claim, so we
    // need to make up G[1]. The code sets G[1] = G[0] and it doesn't affect
    // soundness.
    for (size_t i = 0; i < bnd.logv; ++i) {
      bnd.g[1][i] = bnd.g[0][i];
    }

    for (size_t ly = 0; ly < circ->nl; ++ly) {
      auto clr = &circ->l.at(ly);
      Elt alpha, beta;
      ts.begin_layer(alpha, beta, ly);
      Eqs<Field> EQ(logc, nc, bnd.q, F);
      auto QUAD = clr->quad->clone();
      QUAD->bind_g(bnd.logv, bnd.g[0], bnd.g[1], alpha, beta, F);

      layer(pr, pad, ts, bnd, ly, logc, clr->logw, &EQ, QUAD.get(),
            in.at(ly).get(), F);

      if (aux != nullptr) {
        aux->bound_quad[ly] = QUAD->scalar();
      }
    }
  }

 private:
  using index_t = typename Quad<Field>::index_t;
  using CPoly = typename LayerProof<Field>::CPoly;
  using WPoly = typename LayerProof<Field>::WPoly;
  using FCPoly = typename LayerProof<Field>::FCPoly;
  using FWPoly = typename LayerProof<Field>::FWPoly;

  /*
  Engage in single-layer sumcheck on

          EQ[|c] QUAD[|r,l] W[r,c] W[l,c]

  Bind c to C, r to R, and l to L (in that order).  Store claims
  W[R,C] and W[L,C] in the proof, and set BND to the new bindings for
  the next layer.

  logw: number of sumcheck rounds in r, l
  logc: number of sumcheck rounds in c
  */
  void layer(Proof<Field>* pr, const Proof<Field>* pad,
             TranscriptSumcheck<Field>& ts, bindings& bnd, size_t layer,
             size_t logc, size_t logw, Eqs<Field>* EQ, Quad<Field>* QUAD,
             Dense<Field>* W, const Field& F) {
    check(EQ->n() == W->n0_, "EQ->n() == W->n0_");

    check(logw <= Proof<Field>::kMaxBindings, "logw <= kMaxBindings");
    bnd.logv = logw;

    // Bind the C variables to Q.
    // Note that binding C variables takes O(number_of_copies * circuit_size)
    // while binding R, L takes O(circuit_size * log(circuit_size)). In most
    // cases number_of_copies > log(circuit_size), so we don't have to
    // optimize binding R, L.
    for (size_t round = 0; round < logc; ++round) {
      CPoly sum{};

      // sum over r,l: QUAD[|r,l] EQ[|c] W[r,c] W[l,c]
      for (index_t i = 0; i < QUAD->n_; i++) {
        corner_t r(QUAD->c_[i].h[0]);
        corner_t l(QUAD->c_[i].h[1]);

        // sum over c: EQ[|c] W[r,c] W[l,c]
        CPoly sumc{};

        // n0_ is the copy dimension, n1_ is the wire dimension.
        for (corner_t c = 0; c < W->n0_; c += 2) {
          CPoly poly = cpoly_at_dense(EQ, c, 0, F)
                           .mul(cpoly_at_dense(W, c, r, F), F)
                           .mul(cpoly_at_dense(W, c, l, F), F);
          sumc.add(poly, F);
        }

        sumc.mul_scalar(QUAD->c_[i].v, F);
        sum.add(sumc, F);
      }

      Elt rnd = round_c(pr, pad, ts, layer, round, sum, F);
      bnd.q[round] = rnd;

      // bind the c variable in both EQ and W
      EQ->bind(rnd, F);
      W->bind(rnd, F);
    }

    Elt eq0 = EQ->scalar();

    W->reshape(W->n1_);
    check(W->n1_ == 1, "W->n1_ == 1");

    auto Wclone = W->clone();                 // keep alive until function end
    Dense<Field>* WH[2] = {W, Wclone.get()};  // reuse W

    for (size_t round = 0; round < logw; ++round) {
      for (size_t hand = 0; hand < 2; hand++) {
        // In SUM_{l,r} Q[l,r] W[l] W[r], first precompute QW[l] =
        // SUM_{r} Q[l,r] W[r] as a dense array, and then compute
        // SUM_{l} QW[l] W[l].
        Dense<Field> QW(WH[hand]->n0_, 1);
        QW.clear(F);
        size_t ohand = 1 - hand;

        // QW[l] = SUM_{r} Q[l,r] W[r]
        for (index_t i = 0; i < QUAD->n_; ++i) {
          corner_t p0(QUAD->c_[i].h[hand]);
          corner_t p1(QUAD->c_[i].h[ohand]);
          F.add(QW.v_[p0], F.mulf(QUAD->c_[i].v, WH[ohand]->v_[p1]));
        }

        // SUM_{l} QW[l] W[l].
        WPoly sum{};
        for (corner_t l = 0; l < QW.n0_; l += 2) {
          WPoly poly = wpoly_at_dense(WH[hand], l, 0, F)
                           .mul(wpoly_at_dense(&QW, l, 0, F), F);
          sum.add(poly, F);
        }

        sum.mul_scalar(eq0, F);
        Elt rnd = round_h(pr, pad, ts, layer, hand, round, sum, F);
        bnd.g[hand][round] = rnd;

        // bind the r variable in W[hand] and QUAD
        WH[hand]->bind(rnd, F);
        QUAD->bind_h(rnd, hand, F);
      }
    }

    QUAD->scalar();  // for the side effect of assertions
    Elt WC[2] = {WH[0]->scalar(), WH[1]->scalar()};
    end_layer(pr, pad, ts, layer, WC, F);
  }

  // Evaluate the quadratic form
  //
  //         V[g,c] = QUAD[g|r,l] W[r,c] W[l,c]
  //
  // Returns false in the case the quad is an assert0 check that fails.
  bool eval_quad(const Quad<Field>* quad, Dense<Field>* V,
                 const Dense<Field>* W, const Field& F) {
    check(V->n0_ == W->n0_, "V->n0_ == W->n0_");
    corner_t n0 = V->n0_;

    V->clear(F);
    for (index_t i = 0; i < quad->n_; i++) {
      corner_t g(quad->c_[i].g);
      corner_t r(quad->c_[i].h[0]);
      corner_t l(quad->c_[i].h[1]);
      for (corner_t c = 0; c < n0; ++c) {
        auto x = quad->c_[i].v;
        if (x == F.zero()) {
          // assert that the computed W[l]W[r] is zero.
          auto y = W->v_[n0 * l + c];
          F.mul(y, W->v_[n0 * r + c]);
          if (y != F.zero()) {
            return false;
          }
        } else {
          F.mul(x, W->v_[n0 * l + c]);
          F.mul(x, W->v_[n0 * r + c]);
          F.add(V->v_[n0 * g + c], x);
        }
      }
    }
    return true;
  }

  Elt /*R*/ round_c(Proof<Field>* pr, const Proof<Field>* pad,
                    TranscriptSumcheck<Field>& ts, size_t layer, size_t round,
                    CPoly poly, const Field& F) {
    check(round <= Proof<Field>::kMaxBindings, "round <= kMaxBindings");

    if (pad) {
      poly.sub(pad->l[layer].cp[round], F);
    }

    pr->l[layer].cp[round] = poly;
    return ts.round(poly);
  }

  Elt /*R*/ round_h(Proof<Field>* pr, const Proof<Field>* pad,
                    TranscriptSumcheck<Field>& ts, size_t layer, size_t hand,
                    size_t round, WPoly poly, const Field& F) {
    check(round <= Proof<Field>::kMaxBindings, "round <= kMaxBindings");
    if (pad) {
      poly.sub(pad->l[layer].hp[hand][round], F);
    }
    pr->l[layer].hp[hand][round] = poly;
    return ts.round(poly);
  }

  void end_layer(Proof<Field>* pr, const Proof<Field>* pad,
                 TranscriptSumcheck<Field>& ts, size_t layer, const Elt wc[2],
                 const Field& F) {
    Elt tt[2] = {wc[0], wc[1]};
    if (pad) {
      F.sub(tt[0], pad->l[layer].wc[0]);
      F.sub(tt[1], pad->l[layer].wc[1]);
    }

    pr->l[layer].wc[0] = tt[0];
    pr->l[layer].wc[1] = tt[1];

    ts.write(tt, 1, 2);
  }

  CPoly cpoly_at_dense(const Dense<Field>* D, corner_t p0, corner_t p1,
                       const Field& F) {
    auto tmp = FCPoly::extend(D->t2_at_corners(p0, p1, F), F);
    return CPoly(tmp);
  }

  WPoly wpoly_at_dense(const Dense<Field>* D, corner_t p0, corner_t p1,
                       const Field& F) {
    auto tmp = FWPoly::extend(D->t2_at_corners(p0, p1, F), F);
    return WPoly(tmp);
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_LAYERS_H_
