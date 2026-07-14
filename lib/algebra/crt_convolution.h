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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CRT_CONVOLUTION_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CRT_CONVOLUTION_H_

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fft.h"
#include "util/power_of_two.h"

namespace proofs {

// Uses a fixed basis of primes to compute a convolution for 64--521 bit values.
// The CRT class must use the same Field in its definition.
template <class CRT, class Field>
class CRTConvolution {
  using Elt = typename Field::Elt;
  using CRTElt = typename CRT::Elt;

 public:
  CRT crt_;

  CRTConvolution(size_t n, size_t m, const Field& f, const Elt y[/*m*/])
      : crt_(f),
        f_(f),
        n_(n),
        m_(m),
        padding_(next_power_of_two(m)),
        y_fft_(padding_, crt_.zero()),
        omega_order_(crt_.omega_order()),
        omega_(crt_.omega()) {
    // Pre-compute the y coefficients in crt form.
    // Pre-scale Y by 1/N to compensate for the scaling in FFTB(FFTF(.))
    auto pni = crt_.invertf(crt_.to_crt(f.of_scalar(padding_)));
    for (size_t i = 0; i < m; ++i) {
      y_fft_[i] = crt_.mulf(pni, crt_.to_crt(y[i]));
    }

    FFT<CRT>::fftf(&y_fft_[0], padding_, omega_, omega_order_, crt_);
  }

  // Computes (first m entries of) convolution of x with y, outputs in z:
  // z[k] = \sum_{i=0}^{n-1} x[i] y[k-i].
  // Note that y has already been FFT'd and divided by padding_ in constructor
  void convolution(const Elt x[/*n_*/], Elt z[/*m_*/]) const {
    std::vector<CRTElt> x_fft(padding_, crt_.zero());
    for (size_t i = 0; i < n_; ++i) {
      x_fft[i] = crt_.to_crt(x[i]);
    }

    FFT<CRT>::fftf(&x_fft[0], padding_, omega_, omega_order_, crt_);

    // Pointwise multiplication.
    for (size_t i = 0; i < padding_; ++i) {
      crt_.mul(x_fft[i], y_fft_[i]);
    }

    // Backward fft.
    FFT<CRT>::fftb(&x_fft[0], padding_, omega_, omega_order_, crt_);

    // Convert back to field form
    for (size_t i = 0; i < m_; ++i) {
      z[i] = crt_.to_field(x_fft[i]);
    }
  }

 private:
  const Field& f_;

  // n is the number of points input
  size_t n_;
  size_t m_;  // total number of points output (points in + new points out)
  size_t padding_;
  std::vector<CRTElt> y_fft_;
  uint64_t omega_order_;
  CRTElt omega_;
};

template <class CRT, class Field>
class CrtConvolutionFactory {
  using Elt = typename Field::Elt;

 public:
  using Convolver = CRTConvolution<CRT, Field>;
  explicit CrtConvolutionFactory(const Field& f) : f_(f) {}

  std::unique_ptr<const Convolver> make(size_t n, size_t m,
                                        const Elt y[/*m*/]) const {
    return std::make_unique<const Convolver>(n, m, f_, y);
  }

 private:
  const Field& f_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CRT_CONVOLUTION_H_
