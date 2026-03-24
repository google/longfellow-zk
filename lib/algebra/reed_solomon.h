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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_H_

#include <stddef.h>

#include <memory>
#include <vector>

#include "algebra/utility.h"

namespace proofs {

/*
The ReedSolomon class interpolates a polynomial given as input in point-eval
form at a set of different points, thereby computing a form of RS encoding.
Specifically, the input polynomial of degree d=n-1 is given as evaluations
at 0, 1, 2, ..., n-1, and the output is the values at n, n+1, n+2, ..., n+m-1.
The algorithm uses the following relation:

  p(k) = (-1)^d (k-d)(k choose d) sum_{j=0}^{d} (1/k-j)(-1)^j (d choose j)p(j)

which can be efficiently computed using a convolution, whose implementation
is provided by a ConvolutionFactory for the field.

The const Field& objects that are passed have lifetimes that exceed the call
durations and can be safely passed by const reference.

*/
template <class Field, class ConvolutionFactory>
class ReedSolomon {
  using Elt = typename Field::Elt;
  using Convolver = typename ConvolutionFactory::Convolver;

 public:
  // n is the number of points provided
  // m is the total number of points output (including the initial n points)
  ReedSolomon(size_t n, size_t m, const Field& F,
              const ConvolutionFactory& factory)
      : f_(F),  // could grab this from the factory
        degree_bound_(n - 1),
        m_(m),
        leading_constant_(m - n + 1),
        binom_i_(n) {
    // inverses[i]: inverses[i] = 1/i from i = 1 to m-1 (inverses[0] = 0)
    std::vector<Elt> inverses(m_);
    AlgebraUtil<Field>::batch_inverse_arithmetic(m, &inverses[0], F);
    c_ = factory.make(n, m, &inverses[0]);
    leading_constant_[0] = F.one();
    binom_i_[0] = F.one();
    // Set leading_constant_[i] = (i+degree_bound_) choose degree_bound_
    // (from i=0 to i=m)
    for (size_t i = 1; i + degree_bound_ < m; ++i) {
      leading_constant_[i] =
          F.mulf(leading_constant_[i - 1],
                 F.mulf(F.of_scalar(degree_bound_ + i), inverses[i]));
    }
    // Finish computing the leading constants:
    // (-1)^degree_bound_ (k-degree_bound_) \binom{k}{degree_bound_}
    for (size_t k = degree_bound_; k < m; ++k) {
      F.mul(leading_constant_[k - degree_bound_],
            F.of_scalar(k - degree_bound_));
      if (degree_bound_ % 2 == 1) {
        F.neg(leading_constant_[k - degree_bound_]);
      }
    }

    for (size_t i = 1; i < n; ++i) {
      binom_i_[i] =
          F.mulf(binom_i_[i - 1], F.mulf(F.of_scalar(n - i), inverses[i]));
    }
    for (size_t i = 1; i < n; i += 2) {
      F.neg(binom_i_[i]);
    }
  }

  // Given the values of a polynomial of degree at most n at 0, 1, 2, ..., n-1,
  // this computes the values at n, n+1, n+2, ..., m-1.
  // (n points go in, m points come out)
  void interpolate(Elt y[/*m*/]) const {
    // shorthands
    const Field& F = f_;
    size_t n = degree_bound_ + 1;  // number of points input

    // Define x[i] = (-1)^i \binom{n}{i} p(i) for i=0 through i=n
    std::vector<Elt> x(n);
    for (size_t i = 0; i < n; i++) {
      x[i] = F.mulf(binom_i_[i], y[i]);
    }

    std::vector<Elt> T(m_);
    c_->convolution(&x[0], &T[0]);
    // Multiply the leading constants by the convolution
    for (size_t i = n; i < m_; ++i) {
      y[i] = F.mulf(leading_constant_[i - degree_bound_], T[i]);
    }
  }

 private:
  const Field& f_;

  // n is the number of points input, and degree_bound = n + 1.
  // degree_bound_ is useful since the LaTeX math is written in terms of it
  const size_t degree_bound_;  // degree bound, i.e., n - 1
  // total number of points output (points in + new points out)
  const size_t m_;

  std::unique_ptr<const Convolver> c_;

  // leading_constant_[i] = \binom{i+degree_bound_}{degree_bound_} *
  // (-1)^{degree_bound_} (i+degree_bound_ - degree_bound_) (from i=0 to i=m-n)
  // i.e., the leading constant \binom{k}{degree_bound_} *
  // (-1)^degree_bound_ (k - degree_bound_), shifted left by degree_bound_
  std::vector<Elt> leading_constant_;
  // (-1)^i (degree_bound_ choose i) from i=0 to i=degree_bound_
  std::vector<Elt> binom_i_;
};

template <class Field, class ConvolutionFactory>
class ReedSolomonFactory {
 public:
  ReedSolomonFactory(const ConvolutionFactory& factory, const Field& f)
      : factory_(factory), f_(f) {}

  std::unique_ptr<ReedSolomon<Field, ConvolutionFactory>> make(size_t n,
                                                               size_t m) const {
    return std::make_unique<ReedSolomon<Field, ConvolutionFactory>>(n, m, f_,
                                                                    factory_);
  }

 private:
  const ConvolutionFactory& factory_;
  const Field& f_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_H_
