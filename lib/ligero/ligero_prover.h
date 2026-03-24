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

#ifndef PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PROVER_H_

#include <stddef.h>

#include <algorithm>
#include <array>
#include <vector>

#include "algebra/blas.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_transcript.h"
#include "merkle/merkle_commitment.h"
#include "random/random.h"
#include "random/transcript.h"
#include "util/crypto.h"
#include "util/panic.h"

namespace proofs {
template <class Field, class InterpolatorFactory>
class LigeroProver {
  using Elt = typename Field::Elt;

 public:
  explicit LigeroProver(const LigeroParam<Field> &p)
      : p_(p), mc_(p.block_enc - p.dblock), tableau_(p.nrow * p.block_enc) {}

  // The SUBFIELD_BOUNDARY parameter is kind of a hack.
  //
  // Most, but not all, witnesses in W[] are known statically to be in
  // the subfield of Field, for example because they are bits or
  // bit-plucked values in the subfield.  For zero-knowledge, for
  // these witnesses, it suffices to choose blinding randomness in the
  // subfield, which yields a shorter proof since most column openings
  // are fully in the subfield.  The problem is now to distinguish
  // subfield witnesses from field witnesses.
  //
  // In the fullness of time we should have a compiler with typing
  // information (field vs subfield) of all input wires.  For now
  // we implement the following hack: W[i] is in the subfield for
  // i < SUBFIELD_BOUNDARY, and in the full field otherwise.
  // If you don't know better, set SUBFIELD_BOUNDARY = 0 which
  // trivially works for any input.
  void commit(LigeroCommitment<Field> &commitment, Transcript &ts,
              const Elt W[/*p_.nw*/], const size_t subfield_boundary,
              const LigeroQuadraticConstraint lqc[/*nq*/],
              const InterpolatorFactory &interpolator, RandomEngine &rng,
              const Field &F) {
    // Paranoid check on the SUBFIELD_BOUNDARY correctness condition
    for (size_t i = 0; i < subfield_boundary; ++i) {
      check(F.in_subfield(W[i]), "element not in subfield");
    }

    layout(W, subfield_boundary, lqc, interpolator, rng, F);

    // Merkle commitment
    auto updhash = [&](size_t j, SHA256 &sha) {
      LigeroCommon<Field>::column_hash(p_.nrow, &tableau_at(0, j + p_.dblock),
                                       p_.block_enc, sha, F);
    };
    commitment.root = mc_.commit(updhash, rng);

    // P -> V
    LigeroTranscript<Field>::write_commitment(commitment, ts);
  }

  // HASH_OF_LLTERM is a hash of LLTERM provided by the caller.  We
  // could compute the hash locally, but usually LLTERM has a special
  // structure that makes the computation faster on the caller's side.
  void prove(LigeroProof<Field> &proof, Transcript &ts, size_t nl,
             size_t nllterm,
             const LigeroLinearConstraint<Field> llterm[/*nllterm*/],
             const LigeroHash &hash_of_llterm,
             const LigeroQuadraticConstraint lqc[/*nq*/],
             const InterpolatorFactory &interpolator, const Field &F) {
    {
      // P -> V
      // theorem statement
      ts.write(hash_of_llterm.bytes, hash_of_llterm.kLength);
    }

    {
      std::vector<Elt> u_ldt(p_.nwqrow);

      // V -> P
      LigeroTranscript<Field>::gen_uldt(&u_ldt[0], p_, ts, F);
      low_degree_proof(&proof.y_ldt[0], &u_ldt[0], F);
    }

    {
      std::vector<Elt> alphal(nl);
      std::vector<std::array<Elt, 3>> alphaq(p_.nq);
      std::vector<Elt> A(p_.nwqrow * p_.w);

      // V -> P
      LigeroTranscript<Field>::gen_alphal(nl, &alphal[0], ts, F);
      LigeroTranscript<Field>::gen_alphaq(&alphaq[0], p_, ts, F);

      LigeroCommon<Field>::inner_product_vector(&A[0], p_, nl, nllterm, llterm,
                                                &alphal[0], lqc, &alphaq[0], F);

      dot_proof(&proof.y_dot[0], &A[0], interpolator, F);
    }

    {
      std::vector<Elt> u_quad(p_.nqtriples);

      // V -> P
      LigeroTranscript<Field>::gen_uquad(&u_quad[0], p_, ts, F);
      quadratic_proof(&proof.y_quad_0[0], &proof.y_quad_2[0], &u_quad[0], F);
    }

    {
      // P -> V
      ts.write(&proof.y_ldt[0], 1, p_.block, F);
      ts.write(&proof.y_dot[0], 1, p_.dblock, F);
      ts.write(&proof.y_quad_0[0], 1, p_.r, F);
      ts.write(&proof.y_quad_2[0], 1, p_.dblock - p_.block, F);
    }

    {
      std::vector<size_t> idx(p_.nreq);
      // V -> P
      LigeroTranscript<Field>::gen_idx(&idx[0], p_, ts, F);

      compute_req(proof, &idx[0]);

      mc_.open(proof.merkle, &idx[0], p_.nreq);
    }
  }

 private:
  Elt &tableau_at(size_t i, size_t j) {
    size_t ld = p_.block_enc;
    return tableau_[i * ld + j];
  }

  // fill t_[i, [0,n)] with random elements
  // If the base_only flag is true, then the random element is chosen from
  // the base field if F is a field extension.
  void random_row(size_t i, size_t n, RandomEngine &rng, const Field &F) {
    for (size_t j = 0; j < n; ++j) {
      tableau_at(i, j) = rng.elt(F);
    }
  }

  void random_subfield_row(size_t i, size_t n, RandomEngine &rng,
                           const Field &F) {
    for (size_t j = 0; j < n; ++j) {
      tableau_at(i, j) = rng.subfield_elt(F);
    }
  }

  // generate the ILDT and IDOT blinding rows
  void layout_blinding_rows(const InterpolatorFactory &interpolator,
                            RandomEngine &rng, const Field &F) {
    {
      // blinds of size [BLOCK]
      const auto interp = interpolator.make(p_.block, p_.block_enc);

      // low-degree blinding row
      random_row(p_.ildt, p_.block, rng, F);
      interp->interpolate(&tableau_at(p_.ildt, 0));
    }

    {
      // blinds of size [DBLOCK]
      const auto interp = interpolator.make(p_.dblock, p_.block_enc);

      // dot-product blinding row constrained to SUM(W) = 0. First
      // randomize the dblock:
      random_row(p_.idot, p_.dblock, rng, F);

      // Then constrain to sum(W) = 0
      Elt sum = Blas<Field>::dot1(p_.w, &tableau_at(p_.idot, p_.r), 1, F);
      F.sub(tableau_at(p_.idot, p_.r), sum);

      interp->interpolate(&tableau_at(p_.idot, 0));

      // quadratic-test blinding row constrained to W = 0.  First
      // randomize the entire dblock:
      random_row(p_.iquad, p_.dblock, rng, F);

      // Then constrain to W = 0
      Blas<Field>::clear(p_.w, &tableau_at(p_.iquad, p_.r), 1, F);

      interp->interpolate(&tableau_at(p_.iquad, 0));
    }
  }

  void layout_witness_rows(const Elt W[/*nw*/], size_t subfield_boundary,
                           const InterpolatorFactory &interpolator,
                           RandomEngine &rng, const Field &F) {
    const auto interp = interpolator.make(p_.block, p_.block_enc);

    // witness row EXTEND([RANDOM[R], WITNESS[W]], BLOCK)
    for (size_t i = 0; i < p_.nwrow; ++i) {
      // TRUE if the entire row is in the subfield
      bool subfield_only = ((i + 1) * p_.w <= subfield_boundary);

      if (subfield_only) {
        random_subfield_row(i + p_.iw, p_.r, rng, F);
      } else {
        random_row(i + p_.iw, p_.r, rng, F);
      }

      // Set the WITNESS columns to zero first, and then
      // overwrite with the witnesses that actually exist
      Blas<Field>::clear(p_.w, &tableau_at(i + p_.iw, p_.r), 1, F);
      size_t max_col = std::min(p_.w, p_.nw - i * p_.w);
      Blas<Field>::copy(max_col, &tableau_at(i + p_.iw, p_.r), 1, &W[i * p_.w],
                        1);
      interp->interpolate(&tableau_at(i + p_.iw, 0));
    }
  }

  void layout_quadratic_rows(const Elt W[/*nw*/],
                             const LigeroQuadraticConstraint lqc[/*nq*/],
                             const InterpolatorFactory &interpolator,
                             RandomEngine &rng, const Field &F) {
    const auto interp = interpolator.make(p_.block, p_.block_enc);

    // copy the multiplicand witnesses into the quadratic rows
    size_t iqx = p_.iq;
    size_t iqy = iqx + p_.nqtriples;
    size_t iqz = iqy + p_.nqtriples;

    for (size_t i = 0; i < p_.nqtriples; ++i) {
      random_row(iqx + i, p_.r, rng, F);
      random_row(iqy + i, p_.r, rng, F);
      random_row(iqz + i, p_.r, rng, F);

      // clear everything first, then overwrite the witnesses that
      // actually exist
      Blas<Field>::clear(p_.w, &tableau_at(iqx + i, p_.r), 1, F);
      Blas<Field>::clear(p_.w, &tableau_at(iqy + i, p_.r), 1, F);
      Blas<Field>::clear(p_.w, &tableau_at(iqz + i, p_.r), 1, F);

      for (size_t j = 0; j < p_.w && j + i * p_.w < p_.nq; ++j) {
        const auto *l = &lqc[j + i * p_.w];
        check(W[l->z] == F.mulf(W[l->x], W[l->y]),
              "invalid quadratic constraints");
        tableau_at(iqx + i, j + p_.r) = W[l->x];
        tableau_at(iqy + i, j + p_.r) = W[l->y];
        tableau_at(iqz + i, j + p_.r) = W[l->z];
      }
      interp->interpolate(&tableau_at(iqx + i, 0));
      interp->interpolate(&tableau_at(iqy + i, 0));
      interp->interpolate(&tableau_at(iqz + i, 0));
    }
  }

  void layout(const Elt W[/*nw*/], size_t subfield_boundary,
              const LigeroQuadraticConstraint lqc[/*nq*/],
              const InterpolatorFactory &interpolator, RandomEngine &rng,
              const Field &F) {
    layout_blinding_rows(interpolator, rng, F);
    layout_witness_rows(W, subfield_boundary, interpolator, rng, F);
    layout_quadratic_rows(W, lqc, interpolator, rng, F);
  }

  void low_degree_proof(Elt y[/*block*/], const Elt u_ldt[/*nwqrow*/],
                        const Field &F) {
    // ILDT blinding row with coefficient 1
    Blas<Field>::copy(p_.block, y, 1, &tableau_at(p_.ildt, 0), 1);

    // all witness and quadratic rows with coefficient u_ldt[]
    for (size_t i = 0; i < p_.nwqrow; ++i) {
      Blas<Field>::axpy(p_.block, y, 1, u_ldt[i], &tableau_at(i + p_.iw, 0), 1,
                        F);
    }
  }

  void dot_proof(Elt y[/*dblock*/], const Elt A[/*nwqrow, w*/],
                 const InterpolatorFactory &interpolator, const Field &F) {
    const auto interpA = interpolator.make(p_.block, p_.dblock);

    // IDOT blinding row with coefficient 1
    Blas<Field>::copy(p_.dblock, y, 1, &tableau_at(p_.idot, 0), 1);

    std::vector<Elt> Aext(p_.dblock);
    for (size_t i = 0; i < p_.nwqrow; ++i) {
      LigeroCommon<Field>::layout_Aext(&Aext[0], p_, i, &A[0], F);
      interpA->interpolate(&Aext[0]);

      // Accumulate y += A \otimes W.
      Blas<Field>::vaxpy(p_.dblock, &y[0], 1, &Aext[0], 1,
                         &tableau_at(i + p_.iw, 0), 1, F);
    }
  }

  void quadratic_proof(Elt y0[/*r*/], Elt y2[/*dblock - block*/],
                       const Elt u_quad[/*nqtriples*/], const Field &F) {
    std::vector<Elt> y(p_.dblock);
    std::vector<Elt> tmp(p_.dblock);

    // IQUAD blinding row with coefficient 1
    Blas<Field>::copy(p_.dblock, &y[0], 1, &tableau_at(p_.iquad, 0), 1);

    size_t iqx = p_.iq;
    size_t iqy = iqx + p_.nqtriples;
    size_t iqz = iqy + p_.nqtriples;

    for (size_t i = 0; i < p_.nqtriples; ++i) {
      // y += u_quad[i] * (z[i] - x[i] * y[i])

      // tmp = z[i]
      Blas<Field>::copy(p_.dblock, &tmp[0], 1, &tableau_at(iqz + i, 0), 1);

      // tmp -= x[i] \otimes y[i]
      Blas<Field>::vymax(p_.dblock, &tmp[0], 1, &tableau_at(iqx + i, 0), 1,
                         &tableau_at(iqy + i, 0), 1, F);

      // y += u_quad[i] * tmp
      Blas<Field>::axpy(p_.dblock, &y[0], 1, u_quad[i], &tmp[0], 1, F);
    }

    // sanity check: the W part of Y is zero
    bool ok = Blas<Field>::equal0(p_.w, &y[p_.r], 1, F);
    check(ok, "W part is nonzero");

    // extract the first and last parts
    Blas<Field>::copy(p_.r, y0, 1, &y[0], 1);
    Blas<Field>::copy(p_.dblock - p_.block, y2, 1, &y[p_.block], 1);
  }

  void compute_req(LigeroProof<Field> &proof, const size_t idx[/*nreq*/]) {
    for (size_t i = 0; i < p_.nrow; ++i) {
      Blas<Field>::gather(p_.nreq, &proof.req_at(i, 0),
                          &tableau_at(i, p_.dblock), idx);
    }
  }

  const LigeroParam<Field> p_; /* safer to make copy */
  MerkleCommitment mc_;
  std::vector<Elt> tableau_ /*[nrow, block_enc]*/;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PROVER_H_
