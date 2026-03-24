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

#ifndef PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PARAM_H_
#define PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PARAM_H_

#include <stddef.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "algebra/blas.h"
#include "merkle/merkle_commitment.h"
#include "merkle/merkle_tree.h"
#include "util/ceildiv.h"
#include "util/crypto.h"
#include "util/panic.h"

/*

  This is an implementation of the Ligero protocol described in

    Ligero: Lightweight Sublinear Arguments
            Without a Trusted Setup,

    Scott Ames and Carmit Hazay and Yuval Ishai and
    Muthuramakrishnan Venkitasubramaniam,
    https://eprint.iacr.org/2022/1608
    doi = {10.1145/3133956},

  The main data structure in the prover is a 2D array which we call a
  tableau organized as follows.

  Fix a block size BLOCK and let DBLOCK = 2 * BLOCK - 1.  Fix another
  quantity BLOCK_EXT >= 0.

  Each row in the tableau has the form [X XD XEXT], where X is a row
  of BLOCK elements, XD is a row of BLOCK - 1 elements, and XEXT is a
  row of BLOCK_EXT elements.  We call the X part the "block" and the
  XEXT part the "extension".

  Let BLOCK_ENC = 2 * BLOCK - 1 + BLOCK_EXT = DBLOCK + BLOCK_EXT be
  the total size of the row.

  A "witness block" has the form [RANDOM[R], WITNESS[W]], where R + W
  = BLOCK.  The randomess (of size R) is used for zero-knowledge
  blinding. Although not strictly required by Ligero, we require W >=
  R to avoid wasting too much space, so that a witness block is at
  least half full.

  A block is interpreted as evaluations of some polynomial at point
  INJ(j) for 0 <= j < BLOCK, where INJ(.) is some field-specific
  injection that injects small natural numbers into distinct field
  elements.  With the condition that the degree of the polynomial be
  less than BLOCK, the polynomial is uniquely determined, and the rest
  [XD XEXT] of the row is then computed as the evaluations of that
  polynomial for BLOCK <= j < BLOCK_ENC.

  To the extent that Ligero is based on Reed-Solomon codes, X is the
  "message" and XEXT is the "codeword". The "rate" is thus BLOCK /
  BLOCK_EXT.

  However, Ligero also needs products of two polynomials of degree
  less than BLOCK, so that the product has degree less than 2 * BLOCK
  - 1 = DBLOCK.  XD exists in the tableau to facilitate the
  computation of these products.  For zero knowledge, the indices of
  XD must be distinct from the indices of BLOCK_EXT.

  We now discuss the row structure of the tableau.  The first three
  rows are special and used for zero-knowledge blinding purposes.

  The first row, row ILDT for ILDT = 0, used for the low-degree test,
  consists of BLOCK random field elements, extended to BLOCK_ENC.

  The second row, row IDOT for IDOT = 1, used in the linear test,
  consists of DBLOCK random field elements, with the additional
  constraint that the double block sum to 0.  As usual, the row is
  extended to BLOCK_ENC by interpolation.

  The third row, row IQUAD for IQUAD = 2, used in the quadratic test,
  consists of DBLOCK random field elements, with the additional
  constraint that the WITNESS portion of the block be zero.  Thus, the
  structure is really [RANDOM[R] ZERO[W] RANDOM[BLOCK-1]], extended to
  BLOCK_ENC by interpolation.

  The next group of "witness rows" IW <= I < IQ for IW = 3, stores
  witnesses.  Each row is a witness block extended to BLOCK_ENC.

  The next group of "quadratic" rows IQ <= I < NROW, has the same
  syntactic structure as the "witness" rows, but they are used in the
  quadratic check in addition to the linear check.  In Ligero, a
  quadratic constraint induces three entries in three quadratic rows.
  Thus, for NQ total quadratic constraints and W useful entries per
  row, we have a total of 3 * (NQ / W) quadratic rows.  To enforce
  this structure, the code stores NQTRIPLES = (NQ / W) instead of the
  number 3 * NQTRIPLES of rows.

 */

namespace proofs {

template <class Field>
struct LigeroParam {
  using Elt = typename Field::Elt;

  // parameters passed by the user
  size_t nw;       // total number of witnesses
  size_t nq;       // total number of quadratic constraints
  size_t rateinv;  // inverse rate of the error-correcting code
  size_t nreq;     // number of opened columns

  // computed parameters
  size_t block_enc;   // total number of elts per row
  size_t block;       // number of elts per block
  size_t dblock;      // 2 * BLOCK - 1
  size_t block_ext;   // BLOCK_ENC - DBLOCK (number of leaves in the
                      // Merkle tree).
  size_t r;           // number of random elts in a witness block
  size_t w;           // number of witnesses in a witness block
  size_t nwrow;       // number of witness rows
  size_t nqtriples;   // number of triples of quadratic-check rows
  size_t nwqrow;      // nwqrow + nqtriples
  size_t nrow;        // total number of rows (nwqrow + three blinding rows)
  size_t mc_pathlen;  // length of a Merkle-tree proof
                      // with BLOCK_ENC-BLOCK leaves

  // layout of rows
  size_t ildt;   // blinding for the low-degree test
  size_t idot;   // blinding row for the dot-product check
  size_t iquad;  // blinding row for the quadratic check
  size_t iw;     // first witness row
  size_t iq;     // first quadratic row

  // Deprecated version of the constructor attempts to optimize the block_enc
  // parameter. This optimization can now be performed offline and stored as
  // a parameter in ZkSpecStruct.
  // TODO(shelat): Remove this constructor once version 3 is deprecated.
  LigeroParam(size_t nw, size_t nq, size_t rateinv, size_t nreq)
      : nw(nw), nq(nq), rateinv(rateinv), nreq(nreq) {
    r = nreq;

    size_t min_proof_size = SIZE_MAX;
    size_t best_block_enc = 1;
    for (size_t e = 1; e <= (1 << 28); e *= 2) {
      size_t proof_size = layout(e);
      if (proof_size < min_proof_size) {
        min_proof_size = proof_size;
        best_block_enc = e;
      }
    }

    // recompute parameters
    layout(best_block_enc);
    sanity();
  }

  // Constructor that accepts a pre-computed block_enc.
  LigeroParam(size_t nw, size_t nq, size_t rateinv, size_t nreq,
              size_t be)
      : nw(nw), nq(nq), rateinv(rateinv), nreq(nreq), block_enc(be) {
    r = nreq;
    check(layout(block_enc) < SIZE_MAX, "block_enc too large");
    sanity();
  }

  // Return an estimate of the proof size.
  //
  // This function is kind of a hack in that it breaks abstraction
  // boundaries, e.g. it knows about the size and layout of the Merkle
  // commitment.  Punt on this wart until we have a better theory.
  size_t layout(size_t e) {
    // Maximum size we are prepared to handle.  All dimensions will be
    // required to be < MAX_SIZE.  In principle we could handle all
    // size_t, but we want 64-bit code to fail if it would fail on a
    // 32-bit machine, and for maximum paranoia we restrict to 28
    // bits, since one cannot malloc 2^{28} Elts on a 32-bit machine
    // anyway.
    constexpr size_t max_lg_size = 28;
    constexpr size_t max_size = static_cast<size_t>(1) << max_lg_size;
    block_enc = e;

    // block_enc must fit in the subfield
    size_t subfield_bits = 8 * Field::kSubFieldBytes;
    if (subfield_bits <= max_lg_size) {
      if (block_enc >= (static_cast<size_t>(1) << subfield_bits)) {
        return SIZE_MAX;
      }
    }

    // limit block_enc to avoid overflow in the computation
    // of the proof size
    if (block_enc > max_size || rateinv > max_size ||
        (block_enc + 1) < (2 + rateinv)) {
      return SIZE_MAX;
    }

    block = (block_enc + 1) / (2 + rateinv);
    // now 1 <= BLOCK < MAX_SIZE / 2

    // Ensure BLOCK = R + W (syntactic property)
    if (block < r) {
      return SIZE_MAX;
    }
    w = block - r;

    // now r <= BLOCK < MAX_SIZE / 2
    //     0 <= W < MAX_SIZE / 2
    //     0 <= W <= BLOCK
    //     0 <= R <= BLOCK
    //     W + R == BLOCK

    // Ensure W >= R (needed for reasonable space utilization).
    if (w < r) {
      return SIZE_MAX;
    }
    // now R <= W < MAX_SIZE

    // Finish the layout of a row
    dblock = 2 * block - 1;
    // now DBLOCK < MAX_SIZE

    // Ensure BLOCK_ENC >= 0 (syntactic property).  Should be true
    // for any reasonable rateinv, but check anyway.
    if (block_enc < dblock) {
      return SIZE_MAX;
    }
    // now DBLOCK <= BLOCK_ENC

    block_ext = block_enc - dblock;
    // now 0 <= BLOCK_EXT < MAX_SIZE

    nwrow = ceildiv(nw, w);
    nqtriples = ceildiv(nq, w);

    nwqrow = nwrow + 3 * nqtriples;
    nrow = nwqrow + /*blinding rows=*/3;

    // The total number of elements (NROW * BLOCK_ENC) in the tableau
    // must fit in MAX_SIZE.
    if (nrow >= max_size / block_enc) {
      return SIZE_MAX;
    }

    mc_pathlen = merkle_commitment_len(block_ext);

    /* proof+commitment size.  */
    // Compute the size in uint64_t instead of size_t since
    // I am too lazy to worry about overflow.
    uint64_t sz = 0;

    // commitment
    sz += sizeof(Digest);

    // Merkle openings, approximated because the exact # of leaves depends
    // on the random coins.
    sz += static_cast<uint64_t>(mc_pathlen) / 2 * static_cast<uint64_t>(nreq) *
          static_cast<uint64_t>(Digest::kLength);

    // y_ldt
    sz += static_cast<uint64_t>(block) * static_cast<uint64_t>(Field::kBytes);

    // y_dot
    sz += static_cast<uint64_t>(dblock) * static_cast<uint64_t>(Field::kBytes);

    // y_quad
    // The quadratic-test response has size DBLOCK, but W elements
    // are expected to be zero and not serialized.
    sz += static_cast<uint64_t>(dblock - w) *
          static_cast<uint64_t>(Field::kBytes);

    // nonces
    sz += static_cast<uint64_t>(nreq) *
          static_cast<uint64_t>(MerkleNonce::kLength);

    // req.   Assume optimistically that all elements are in the subfield.
    sz += static_cast<uint64_t>(nrow) * static_cast<uint64_t>(nreq) *
          static_cast<uint64_t>(Field::kSubFieldBytes);

    sz = std::min<uint64_t>(sz, SIZE_MAX);
    return static_cast<size_t>(sz);
  }

 private:
  void sanity() {
    proofs::check(block_enc > block, "block_enc > block");
    ildt = 0;
    idot = 1;
    iquad = 2;
    iw = 3;
    iq = iw + nwrow;
    proofs::check(nrow == iq + 3 * nqtriples, "nrow == iq + 3 * nqtriples");
  }
};

template <class Field>
struct LigeroCommitment {
  Digest root;
};

template <class Field>
struct LigeroProof {
  using Elt = typename Field::Elt;
  explicit LigeroProof(const LigeroParam<Field> *p)
      : block(p->block),
        dblock(p->dblock),
        r(p->r),
        block_enc(p->block_enc),
        nrow(p->nrow),
        nreq(p->nreq),
        mc_pathlen(p->mc_pathlen),
        y_ldt(p->block),
        y_dot(p->dblock),
        y_quad_0(p->r),
        y_quad_2(p->dblock - p->block),
        req(p->nrow * p->nreq),
        merkle(p->nreq) {}

  // The proof stores a copy of all parameters relevant to the proof.
  size_t block;
  size_t dblock;
  size_t r;
  size_t block_enc;
  size_t nrow;
  size_t nreq;
  size_t mc_pathlen;

  std::vector<Elt> y_ldt;     // [block]
  std::vector<Elt> y_dot;     // [dblock]
  std::vector<Elt> y_quad_0;  // [r] first part of y_quad.
  // The middle part [w] of y_quad is zero and not transmitted.
  std::vector<Elt> y_quad_2;  // [dblock - block] last part of y_quad
  std::vector<Elt> req;       // [nrow, nreq]
  MerkleProof merkle;

  Elt &req_at(size_t i, size_t j) { return req[i * nreq + j]; }
  const Elt &req_at(size_t i, size_t j) const { return req[i * nreq + j]; }
};

// a nonzero entry in the matrix A that defines
// the linear constraints A w = b.  The term
// states that A[c, w] = k, where the "row"
// c is interpreted as the constraint index, and
// the "column" w is interpreted as the witness
// index
template <class Field>
struct LigeroLinearConstraint {
  using Elt = typename Field::Elt;
  size_t c;
  size_t w;
  Elt k;
};

// encode W[X] * W[Y] - W[Z] = 0
struct LigeroQuadraticConstraint {
  size_t x;
  size_t y;
  size_t z;
};

template <class Field>
class LigeroCommon {
  using Elt = typename Field::Elt;

 public:
  // create a grand dot product by A given the user-provided
  // linear-constraint terms LLTERM, the quadratic constraints LQC,
  // and their random challenges ALPHAL, ALPHAQ.
  static void inner_product_vector(
      Elt A[/*nwqrow, w*/], const LigeroParam<Field> &p, size_t nl,
      size_t nllterm, const LigeroLinearConstraint<Field> llterm[/*nllterm*/],
      const Elt alphal[/*nl*/], const LigeroQuadraticConstraint lqc[/*nq*/],
      const std::array<Elt, 3> alphaq[/*nq*/], const Field &F) {
    // clear A and overwrite it later.
    Blas<Field>::clear(p.nwqrow * p.w, A, 1, F);

    // random linear combinations of the linear constraints
    for (size_t l = 0; l < nllterm; ++l) {
      const auto &term = llterm[l];
      proofs::check(term.w < p.nw, "term.w < p.nw");
      proofs::check(term.c < nl, "term.c < nl");
      F.add(A[term.w], F.mulf(term.k, alphal[term.c]));
    }

    // routing terms for quadratic constraints
    Elt *Ax = &A[p.nwrow * p.w];
    Elt *Ay = Ax + (p.nqtriples * p.w);
    Elt *Az = Ay + (p.nqtriples * p.w);

    for (size_t i = 0; i < p.nqtriples; ++i) {
      for (size_t j = 0; j < p.w && j + i * p.w < p.nq; ++j) {
        // index into [_ , W] arrays
        size_t iw = j + i * p.w;
        const auto *l = &lqc[iw];
        F.add(Ax[iw], alphaq[iw][0]);
        F.sub(A[l->x], alphaq[iw][0]);

        F.add(Ay[iw], alphaq[iw][1]);
        F.sub(A[l->y], alphaq[iw][1]);

        F.add(Az[iw], alphaq[iw][2]);
        F.sub(A[l->z], alphaq[iw][2]);
      }
    }
  }

  // layout a witness block where the "witness" is public, and
  // thus the randomess is zero.
  static void layout_Aext(Elt Aext[/*>=block*/], const LigeroParam<Field> &p,
                          size_t i, const Elt A[/*nwqrow, nw*/],
                          const Field &F) {
    Blas<Field>::clear(p.r, &Aext[0], 1, F);
    Blas<Field>::copy(p.w, &Aext[p.r], 1, &A[i * p.w], 1);
  }

  static void column_hash(size_t n, const Elt x[/*n:incx*/], size_t incx,
                          SHA256 &sha, const Field &F) {
    for (size_t i = 0; i < n; ++i) {
      uint8_t buf[Field::kBytes];
      F.to_bytes_field(buf, x[i * incx]);
      sha.Update(buf, sizeof(buf));
    }
  }
};

// A struct representing the hash of llterms.  It is really the
// same as Digest, but in theory Ligero should exist independently
// of the Merkle tree.
struct LigeroHash {
  static constexpr size_t kLength = kSHA256DigestSize;
  uint8_t bytes[kLength];
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PARAM_H_
