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

#ifndef PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_VERIFIER_H_

#include <stddef.h>

#include <array>
#include <vector>

#include "algebra/blas.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_transcript.h"
#include "merkle/merkle_commitment.h"
#include "random/transcript.h"
#include "util/crypto.h"

namespace proofs {
template <class Field, class InterpolatorFactory>
class LigeroVerifier {
  using Elt = typename Field::Elt;

 public:
  static void receive_commitment(const LigeroCommitment<Field>& commitment,
                                 Transcript& ts) {
    // P -> V
    LigeroTranscript<Field>::write_commitment(commitment, ts);
  }

  static bool verify(const char** why, const LigeroParam<Field>& p,
                     const LigeroCommitment<Field>& commitment,
                     const LigeroProof<Field>& proof, Transcript& ts, size_t nl,
                     size_t nllterm,
                     const LigeroLinearConstraint<Field> llterm[/*nllterm*/],
                     const LigeroHash& hash_of_llterm, const Elt b[/*nl*/],
                     const LigeroQuadraticConstraint lqc[/*nq*/],
                     const InterpolatorFactory& interpolator, const Field& F) {
    if (why == nullptr) {
      return false;
    }

    std::vector<Elt> u_ldt(p.nwqrow);
    std::vector<Elt> alphal(nl);
    std::vector<std::array<Elt, 3>> alphaq(p.nq);
    std::vector<Elt> u_quad(p.nqtriples);
    std::vector<size_t> idx(p.nreq);

    // Replay the protocol first in order to compute all the
    // challenges.  In particular, we need IDX before we can do
    // anything useful.

    // P -> V
    ts.write(hash_of_llterm.bytes, hash_of_llterm.kLength);

    // V -> P
    LigeroTranscript<Field>::gen_uldt(&u_ldt[0], p, ts, F);

    // V -> P
    LigeroTranscript<Field>::gen_alphal(nl, &alphal[0], ts, F);
    LigeroTranscript<Field>::gen_alphaq(&alphaq[0], p, ts, F);

    // V -> P
    LigeroTranscript<Field>::gen_uquad(&u_quad[0], p, ts, F);

    // P -> V
    ts.write(&proof.y_ldt[0], 1, p.block, F);
    ts.write(&proof.y_dot[0], 1, p.dblock, F);
    ts.write(&proof.y_quad_0[0], 1, p.r, F);
    ts.write(&proof.y_quad_2[0], 1, p.dblock - p.block, F);

    // V -> P
    LigeroTranscript<Field>::gen_idx(&idx[0], p, ts, F);

    if (!merkle_check(p, commitment, proof, &idx[0], F)) {
      *why = "merkle_check failed";
      return false;
    }

    if (!low_degree_check(p, proof, &idx[0], &u_ldt[0], interpolator, F)) {
      *why = "low_degree_check failed";
      return false;
    }

    {
      // linear check
      std::vector<Elt> A(p.nwqrow * p.w);

      LigeroCommon<Field>::inner_product_vector(&A[0], p, nl, nllterm, llterm,
                                                &alphal[0], lqc, &alphaq[0], F);

      if (!dot_check(p, proof, &idx[0], &A[0], interpolator, F)) {
        *why = "dot_check failed";
        return false;
      }

      // check the putative value of the inner product
      Elt want_dot = Blas<Field>::dot(nl, b, 1, &alphal[0], 1, F);
      Elt proof_dot = Blas<Field>::dot1(p.w, &proof.y_dot[p.r], 1, F);
      if (want_dot != proof_dot) {
        *why = "wrong dot product";
        return false;
      }
    }

    if (!quadratic_check(p, proof, &idx[0], &u_quad[0], interpolator, F)) {
      *why = "quadratic_check failed";
      return false;
    }

    *why = "ok";
    return true;
  }

 private:
  static void interpolate_req_columns(Elt yp[/*nreq*/],
                                      const LigeroParam<Field>& p, size_t ylen,
                                      const Elt y[/*ylen*/],
                                      const size_t idx[/*nreq*/],
                                      const InterpolatorFactory& interpolator,
                                      const Field& F) {
    const auto interpy = interpolator.make(ylen, p.block_enc);
    std::vector<Elt> yext(p.block_enc);
    Blas<Field>::copy(ylen, &yext[0], 1, y, 1);
    interpy->interpolate(&yext[0]);
    Blas<Field>::gather(p.nreq, &yp[0], &yext[p.dblock], idx);
  }

  static bool merkle_check(const LigeroParam<Field>& p,
                           const LigeroCommitment<Field>& commitment,
                           const LigeroProof<Field>& proof,
                           const size_t idx[/*nreq*/], const Field& F) {
    auto updhash = [&](size_t r, SHA256& sha) {
      LigeroCommon<Field>::column_hash(p.nrow, &proof.req_at(0, r), p.nreq, sha,
                                       F);
    };

    return MerkleCommitmentVerifier::verify(p.block_enc - p.dblock,
                                            commitment.root, proof.merkle, idx,
                                            p.nreq, updhash);
  }

  static bool low_degree_check(const LigeroParam<Field>& p,
                               const LigeroProof<Field>& proof,
                               const size_t idx[/*nreq*/],
                               const Elt u_ldt[/*nrow*/],
                               const InterpolatorFactory& interpolator,
                               const Field& F) {
    std::vector<Elt> yc(p.nreq);

    // the ILDT blinding row with coefficient 1
    Blas<Field>::copy(p.nreq, &yc[0], 1, &proof.req_at(p.ildt, 0), 1);

    // all remaining rows with coefficient u_ldt[]
    for (size_t i = 0; i < p.nwqrow; ++i) {
      Blas<Field>::axpy(p.nreq, &yc[0], 1, u_ldt[i], &proof.req_at(i + p.iw, 0),
                        1, F);
    }

    std::vector<Elt> yp(p.nreq);
    interpolate_req_columns(&yp[0], p, p.block, &proof.y_ldt[0], idx,
                            interpolator, F);

    if (!Blas<Field>::equal(p.nreq, &yp[0], 1, &yc[0], 1, F)) {
      return false;
    }

    return true;
  }

  static bool dot_check(const LigeroParam<Field>& p,
                        const LigeroProof<Field>& proof,
                        const size_t idx[/*nreq*/], const Elt A[/*nwqrow, w*/],
                        const InterpolatorFactory& interpolator,
                        const Field& F) {
    std::vector<Elt> yc(p.nreq);

    // the IDOT blinding row with coefficient 1
    Blas<Field>::copy(p.nreq, &yc[0], 1, &proof.req_at(p.idot, 0), 1);

    {
      const auto interpA = interpolator.make(p.block, p.block_enc);

      std::vector<Elt> Aext(p.block_enc);
      std::vector<Elt> Areq(p.nreq);

      for (size_t i = 0; i < p.nwqrow; ++i) {
        LigeroCommon<Field>::layout_Aext(&Aext[0], p, i, &A[0], F);
        interpA->interpolate(&Aext[0]);
        Blas<Field>::gather(p.nreq, &Areq[0], &Aext[p.dblock], idx);

        // Accumulate z += A[j] \otimes W[j].
        Blas<Field>::vaxpy(p.nreq, &yc[0], 1, &Areq[0], 1,
                           &proof.req_at(i + p.iw, 0), 1, F);
      }
    }

    std::vector<Elt> yp(p.nreq);
    interpolate_req_columns(&yp[0], p, p.dblock, &proof.y_dot[0], idx,
                            interpolator, F);

    if (!Blas<Field>::equal(p.nreq, &yp[0], 1, &yc[0], 1, F)) {
      return false;
    }
    return true;
  }

  static bool quadratic_check(const LigeroParam<Field>& p,
                              const LigeroProof<Field>& proof,
                              const size_t idx[/*nreq*/],
                              const Elt u_quad[/*nqtriples*/],
                              const InterpolatorFactory& interpolator,
                              const Field& F) {
    std::vector<Elt> yc(p.nreq);

    // the IQUAD blinding row with coefficient 1
    Blas<Field>::copy(p.nreq, &yc[0], 1, &proof.req_at(p.iquad, 0), 1);

    {
      std::vector<Elt> tmp(p.nreq);
      size_t iqx = p.iq;
      size_t iqy = iqx + p.nqtriples;
      size_t iqz = iqy + p.nqtriples;

      // all quadratic triples with coefficient u_ldt[]
      for (size_t i = 0; i < p.nqtriples; ++i) {
        // yc += u_quad[i] * (z[i] - x[i] * y[i])

        // tmp = z[i]
        Blas<Field>::copy(p.nreq, &tmp[0], 1, &proof.req_at(iqz + i, 0), 1);

        // tmp -= x[i] \otimes y[i]
        Blas<Field>::vymax(p.nreq, &tmp[0], 1, &proof.req_at(iqx + i, 0), 1,
                           &proof.req_at(iqy + i, 0), 1, F);

        // yc += u_quad[i] * tmp
        Blas<Field>::axpy(p.nreq, &yc[0], 1, u_quad[i], &tmp[0], 1, F);
      }
    }

    // reconstruct y_quad from the two parts in the proof
    std::vector<Elt> yquad(p.dblock);
    Blas<Field>::copy(p.r, &yquad[0], 1, &proof.y_quad_0[0], 1);
    Blas<Field>::clear(p.w, &yquad[p.r], 1, F);
    Blas<Field>::copy(p.dblock - p.block, &yquad[p.block], 1,
                      &proof.y_quad_2[0], 1);

    // interpolate y_quad at the opened columns
    std::vector<Elt> yp(p.nreq);
    interpolate_req_columns(&yp[0], p, p.dblock, &yquad[0], idx, interpolator,
                            F);

    if (!Blas<Field>::equal(p.nreq, &yp[0], 1, &yc[0], 1, F)) {
      return false;
    }
    return true;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_VERIFIER_H_
