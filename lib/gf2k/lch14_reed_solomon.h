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

#ifndef PRIVACY_PROOFS_ZK_LIB_GF2K_LCH14_REED_SOLOMON_H_
#define PRIVACY_PROOFS_ZK_LIB_GF2K_LCH14_REED_SOLOMON_H_

#include <stdio.h>

#include <algorithm>
#include <memory>
#include <vector>

#include "gf2k/lch14.h"

namespace proofs {

template <class Field>
class LCH14ReedSolomon {
  using Elt = typename Field::Elt;

  // only works in binary fields
  static_assert(Field::kCharacteristicTwo);

 public:
  // We interpolate N points, assumed to be the evaluations at
  // F.of_scalar(i), 0 <= i < N, of a polynomial of degree <N, to M
  // points 0 <= i < M.  (Thus, the M points include the N points
  // we started with.)
  //
  // In principle we don't need to know N and M at construction time,
  // but we require N and M for compatibility of the interface with
  // the ReedSolomon class over prime fields.
  LCH14ReedSolomon(size_t n, size_t m, const Field& F)
      : f_(F), n_(n), m_(m), fft_(F) {}

  // Y[i] is expected to be defined for 0 <= i < N, and this
  // routine fills it for 0 <= i < M
  void interpolate(Elt y[/*m*/]) const {
    // determine the FFT size
    size_t l = 0;
    size_t fftn = 1;
    while (fftn < n_) {
      fftn <<= 1;
      ++l;
    }

    // "coefficients" in the LCH14 novel polynomial basis
    std::vector<Elt> C(fftn);

    // compute the "coefficients" under the assumption
    // that we know n_ evaluations and that the higher-order
    // (fftn - n_) "coefficients" are zero.
    for (size_t i = 0; i < n_; ++i) {
      C[i] = y[i];
    }
    for (size_t i = n_; i < fftn; ++i) {
      C[i] = f_.zero();
    }
    fft_.BidirectionalFFT(l, /*k=*/n_, &C[0]);

    // fill in the missing evaluations in the first coset, since we
    // already have the missing evaluations in C[[n_, (1<<l))]
    for (size_t i = n_; i < std::min(m_, fftn); ++i) {
      y[i] = C[i];
    }

    // revert C to pure coefficients for later use
    for (size_t i = n_; i < fftn; ++i) {
      C[i] = f_.zero();
    }

    // all remaining cosets:
    for (size_t coset = 1; (coset << l) < m_; ++coset) {
      size_t b = (coset << l);
      if (b + fftn <= m_) {
        // if the coset fits completely within Y[],
        // copy the coefficients into Y and transform in place
        for (size_t i = 0; i < fftn; ++i) {
          y[i + b] = C[i];
        }
        fft_.FFT(l, b, &y[b]);
      } else {
        // Partial fit.  Transform C and copy the output.
        fft_.FFT(l, b, &C[0]);
        for (size_t i = 0; i + b < m_; ++i) {
          y[i + b] = C[i];
        }
        // Now we have destroyed C, but this is ok because
        // this is the last iteration
      }
    }
  }

 private:
  const Field& f_;
  size_t n_;
  size_t m_;
  LCH14<Field> fft_;
};

template <class Field>
class LCH14ReedSolomonFactory {
 public:
  explicit LCH14ReedSolomonFactory(const Field& f) : f_(f) {}

  std::unique_ptr<LCH14ReedSolomon<Field>> make(size_t n, size_t m) const {
    return std::make_unique<LCH14ReedSolomon<Field>>(n, m, f_);
  }

 private:
  const Field& f_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_GF2K_LCH14_REED_SOLOMON_H_
