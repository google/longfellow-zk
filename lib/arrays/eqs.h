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

#ifndef PRIVACY_PROOFS_ZK_LIB_ARRAYS_EQS_H_
#define PRIVACY_PROOFS_ZK_LIB_ARRAYS_EQS_H_

#include <stddef.h>

#include <vector>

#include "algebra/blas.h"
#include "arrays/affine.h"
#include "arrays/dense.h"
#include "util/panic.h"

namespace proofs {

// Stateful implementation of EQ[I, j] which, for fixed
// I, holds an array indexed by j.
template <class Field>
class Eqs : public Dense<Field> {
  using Elt = typename Field::Elt;
  using Dense<Field>::v_;
  using Dense<Field>::n0_;

 public:
  Eqs(size_t logn, corner_t n, const Elt I[/*logn*/], const Field& F)
      : Dense<Field>(n, 1) {
    filleq(&v_[0], logn, n, I, F);
  }

  corner_t n() const { return n0_; }

  // Optimization for a special case: return a raw vector EQ[G0|.] + alpha *
  // EQ[G1|.]  Return std::vector<> because we don't need the full
  // dense<> machinery.
  static std::vector<Elt> raw_eq2(size_t logn, corner_t n, const Elt* G0,
                                  const Elt* G1, const Elt& alpha,
                                  const Field& F) {
    std::vector<Elt> eq0(n);
    std::vector<Elt> eq1(n);
    filleq(&eq0[0], logn, n, G0, F);
    filleq(&eq1[0], logn, n, G1, F);
    Blas<Field>::axpy(n, &eq0[0], 1, alpha, &eq1[0], 1, F);
    return eq0;
  }

 private:
  // Return ceil(a / 2^{n}) for a != 0.
  //
  // Several ways exist to compute ceil(a/b) given a primitive that
  // computes floor(a/b), such as the C++ unsigned division operator.
  // The simplest one is floor((a+(b-1))/b), which potentially overflows.
  // Another way is 1+floor((a-1)/b), which underflows for a==0 but
  // otherwise does not overflow.  More complicated ways exist that neither
  // overflow nor underflow.  Since the rest of the code assumes
  // a!=0 anyway, we use the 1+floor((a-1)/b) version.
  static corner_t ceilshr(corner_t a, size_t n) { return 1u + ((a - 1u) >> n); }

  // Compute the array EQ[Q, i] for all 0<=i<n, for n <= 2^{logn}.
  // (logn can otherwise be arbitrarily large.)
  //
  // Let Q be the array of field elements Q[0,logn), and let
  // i[l] be the l-th bit of the binary representation of i, for
  // 0 <= l < logn.
  //
  // We have
  //   EQ[Q, i] = (1 - Q[0]) * EQ[Q[1:], i[1:]]     if i[0] = 0;
  //   EQ[Q, i] =       Q[0] * EQ[Q[1:], i[1:]]     if i[0] = 1.
  //
  // Thus, EQ{n, logn} can be expressed in terms of EQ{ceil(n/2), logn-1}
  // of half the size.
  static void filleq(Elt* eq, size_t logn, corner_t n, const Elt* Q,
                     const Field& F) {
    check(n > 0, "n > 0");
    eq[0] = F.one();
    for (size_t l = logn; l-- > 0;) {
      corner_t nl = ceilshr(n, l);
      corner_t i = ceilshr(nl, 1);

      // Special case for the first iteration of the i-loop
      // below: don't compute eq[2*i+1] (post decrement) if it
      // would overflow the array.
      if (/*2*(i-1)+1 = */ 2 * i - 1 >= nl) {
        i--;
        Elt v = eq[i], qv = Q[l];
        F.mul(qv, v);
        eq[2 * i] = v;
        F.sub(eq[2 * i], qv);
      }
      while (i-- > 0) {
        // Assign
        //   eq[2*i]   = (1-Q[l])*eq[i]
        //   eq[2*i+1] = Q[l]*eq[i]
        // with one multiplication.
        Elt v = eq[i], qv = Q[l];
        F.mul(qv, v);
        eq[2 * i] = v;
        F.sub(eq[2 * i], qv);
        eq[2 * i + 1] = qv;
      }
    }
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ARRAYS_EQS_H_
