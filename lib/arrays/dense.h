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

#ifndef PRIVACY_PROOFS_ZK_LIB_ARRAYS_DENSE_H_
#define PRIVACY_PROOFS_ZK_LIB_ARRAYS_DENSE_H_

#include <stddef.h>
#include <string.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/blas.h"
#include "algebra/poly.h"
#include "arrays/affine.h"
#include "util/panic.h"

namespace proofs {
// ------------------------------------------------------------
// Dense representation of multi-affine function, heap-allocated.
// The caller is responsible for instantiating const Field throughout call
// duration.
template <class Field>
class Dense {
  using T2 = Poly<2, Field>;
  using Elt = typename Field::Elt;

 public:
  corner_t n0_, n1_;

  // Row-major indexing: v_[i1*n0+i0] stores the value at (i0, i1)
  std::vector<Elt> v_;

  explicit Dense(corner_t n0, corner_t n1) : n0_(n0), n1_(n1), v_(n0 * n1) {}

  // make0 replacement
  explicit Dense(const Field& F) : n0_(1), n1_(1), v_(1) { v_[0] = F.zero(); }

  // initialize dense array from P[i1*ldp+i0]
  explicit Dense(corner_t n0, corner_t n1, const Elt p[], size_t ldp)
      : n0_(n0), n1_(n1), v_(n0 * n1) {
    for (corner_t i1 = 0; i1 < n1; ++i1) {
      Blas<Field>::copy(n0, v_[i1 * n0], 1, &p[i1 * ldp], 1);
    }
  }

  Dense(const Dense& y) = delete;
  Dense(const Dense&& y) = delete;
  Dense operator=(const Dense& y) = delete;

  std::unique_ptr<Dense> clone() const {
    auto d = std::make_unique<Dense>(n0_, n1_);
    for (corner_t i = 0; i < n0_ * n1_; ++i) {
      d->v_[i] = v_[i];
    }
    return d;
  }

  void clear(const Field& F) { Blas<Field>::clear(n0_ * n1_, &v_[0], 1, F); }

  // For a given random number r, the binding operation computes
  //   v[i] = (1 - r) * v[2 * i] + r * v[2 * i + 1]
  //        = v[2 * i] + r * (v[2 * i + 1] - v[2 * i])
  // and shrinks the array v by half.
  void bind(const Elt& r, const Field& F) {
    corner_t rd = 0, wr = 0;
    for (corner_t i1 = 0; i1 < n1_; ++i1) {
      corner_t i0 = 0;
      while (2 * i0 + 1 < n0_) {
        v_[wr] = affine_interpolation(r, v_[rd], v_[rd + 1], F);
        i0++, rd += 2, wr += 1;
      }
      if (2 * i0 < n0_) {
        v_[wr] = affine_interpolation(r, v_[rd], F.zero(), F);
        i0++, rd++, wr++;
      }
    }
    n0_ = (n0_ + 1u) / 2u;
  }

  void bind_all(size_t logv, const Elt r[/*logv*/], const Field& F) {
    for (size_t v = 0; v < logv; ++v) {
      bind(r[v], F);
    }
  }

  Elt at(corner_t j) const { return v_[j]; }

  // Scale all elements by x, except for the last element in
  // the n0_ dimension, which is scaled by x_last.  This "last" quirk
  // is used by EQ.
  void scale(const Elt& x, const Elt& x_last, const Field& F) {
    corner_t ndx = 0;
    for (corner_t i1 = 0; i1 < n1_; ++i1) {
      corner_t i0 = 0;
      for (; i0 + 1 < n0_; ++i0) {
        F.mul(v_[ndx++], x);
      }
      if (i0 < n0_) {
        F.mul(v_[ndx++], x_last);
      }
    }
  }

  Elt at_corners(corner_t p0, corner_t p1, const Field& F) const {
    if (p0 < n0_) {
      return v_[p1 * n0_ + p0];
    } else {
      return F.zero();
    }
  }

  T2 t2_at_corners(corner_t p0, corner_t p1, const Field& F) const {
    return T2{at_corners(p0, p1, F), at_corners(p0 + 1, p1, F)};
  }

  // The precondition for reshaping is that the first dimension must be
  // fully bound.
  void reshape(corner_t n0) {
    check(n0_ == 1, "n0_ == 1");
    check(n0 > 0, "n0 > 0");
    corner_t wasn1 = n1_;
    n0_ = n0;
    n1_ = n1_ / n0;
    check(n1_ * n0 == wasn1, "n1_*n0 == wasn1");
  }

  // This method can only be called after full binding; the caller
  // is responsible for ensuring that pre-condition.
  Elt scalar() {
    check(n0_ == 1, "n0_ == 1");
    check(n1_ == 1, "n1_ == 1");
    return v_[0];
  }
};

// Helper class to fill a dense array a la std::vector<>
//
template <class Field>
class DenseFiller {
  using Elt = typename Field::Elt;
  using CElt = typename Field::CElt;

 public:
  // Caller must ensure that W remains valid.
  explicit DenseFiller(Dense<Field>& W) : pos_(0), w_(W) {
    // only works in this special case
    check(w_.n0_ == 1, "W_.n0_ == 1");
  }

  DenseFiller& push_back(const Elt& x) {
    check(pos_ < w_.n1_, "pos_ < w_.n1_");
    w_.v_[pos_++] = x;
    return *this;
  }

  DenseFiller& push_back(const CElt& x) { return push_back(x.e); }

  template <size_t N>
  DenseFiller& push_back(const std::array<Elt, N>& a) {
    for (size_t i = 0; i < N; ++i) {
      push_back(a[i]);
    }
    return *this;
  }

  DenseFiller& push_back(const std::vector<Elt>& a) {
    for (size_t i = 0; i < a.size(); ++i) {
      push_back(a[i]);
    }
    return *this;
  }

  // Push back a bit string derived from a number.  The parameter "bits" is the
  // number of bits in the string, and "x" is the number to be converted. This
  // works for pushing v8, v32, etc.
  DenseFiller& push_back(uint64_t x, size_t bits, const Field& F) {
    for (size_t i = 0; i < bits; ++i) {
      push_back(F.of_scalar((x >> i) & 1));
    }
    return *this;
  }

  size_t size() const { return pos_; }

 private:
  size_t pos_;
  Dense<Field>& w_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ARRAYS_DENSE_H_
