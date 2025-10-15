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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CRT_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CRT_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "algebra/fp.h"
#include "algebra/nat.h"
#include "util/panic.h"

// The idea behind this class is to mimic the Field interface for F_p with
// an underlying CRT implementation over a basis of primes. Then a
// convolution template can be instantiated with this class instead of an
// F_p field, and this convolution can be used by ReedSolomon.

namespace proofs {

// Every prime field of 1-64b word has the same type, but are different classes.
using BaseField = Fp<1, false>;
using BaseNat = typename BaseField::N;
using BaseElt = typename BaseField::Elt;

// constants
namespace crt {
static constexpr size_t kBasisSize = 17;
static constexpr uint64_t kOmegaOrder = 1ull << 22;

extern const uint64_t kPrimes17[kBasisSize];
extern const uint64_t kOmega17[kBasisSize];
}  // namespace crt

// ==========================================

// Fp_crt implementation of field Field. This implementation works as long
// as the sequence of field operations that are performed on elements before
// the from_crt method is called can be range-bounded by the max value that can
// be represented using the CRT basis formed by the first VS primes defined in
// kBasis.
// The initialize of this class computes the auxiliary information needed to
// efficiently move into and out of the CRT representation. Therefore, this
// class can be instantiated once and used for many convolutions/etc.
template <size_t VS, class Field>
class CRT {
  static constexpr size_t kWField = Field::N::kU64;

 public:
  static constexpr size_t kVS = VS;
  const Field& f_;

  struct Elt {
    BaseElt r[VS];
    bool operator==(const Elt& y) const {
      bool res = true;
      for (size_t i = 0; i < VS; ++i) {
        res = res && (r[i] == y.r[i]);
      }
      return res;
    }
    bool operator!=(const Elt& y) const { return !operator==(y); }
  };

  explicit CRT(const Field& f) : f_(f) {
    check(VS <= crt::kBasisSize, "VS <= crt::kBasisSize");

    for (size_t b = 0; b < VS; ++b) {
      bf_[b] = std::make_unique<BaseField>(BaseNat(crt::kPrimes17[b]));
    }

    for (size_t b = 0; b < VS; ++b) {
      k_[0].r[b] = bf_[b]->zero();
      k_[1].r[b] = bf_[b]->one();
      k_[2].r[b] = bf_[b]->two();
      reduce_scale_[b] = bf_[b]->template reduce_scale<kWField>();
    }

    // Standard CRT integer conversion requires computing a dot-product between
    // the CRT representation and a vector of constants.
    // The reconstruction pre-processing is to compute:
    // 1. Compute P_i = prod_{j neq i} prime_j  and
    //              P = prod_{j} prime_j
    // 2. Compute inv_i such that inv_i * P_i = 1 mod prime_i
    // The online reconstruction step is then:
    // a. v = (sum_{i} r_i * recon_i) (mod  P)) mod f_p
    // for (size_t i = 0; i < VS; ++i) {
    //   recon_[i] = ring_.of_string(kRecon[i]);
    // }
    // However, we use the Garner method which requires more pre-processed
    // elements, but produces a result that is guaranteed to be in [0,m] and
    // does so using smaller operations.

    // garner_[i] are terms prod p_k in CRT formula, prepared for
    // optimized FMA operations by 64-bit scalar vi[i] in to_field.
    for (size_t i = 0; i < VS; ++i) {
      auto g = f.one();
      for (size_t j = 0; j < i; ++j) {
        Nat<1> n(crt::kPrimes17[j]);
        f.mul(g, f.reduce(n));
      }
      garner_[i] = f.prescale_for_dot(g);
    }

    // Initialize Garner constants Cij.
    for (size_t i = 0; i < VS; ++i) {
      for (size_t j = 0; j < i; ++j) {
        cij_[i][j] = bf_[i]->invertf(bf_[i]->of_scalar(crt::kPrimes17[j]));
      }
    }
  }

  CRT(const CRT&) = delete;
  CRT& operator=(const CRT&) = delete;

  Elt to_crt(const typename Field::Elt& e) const {
    Elt r;
    auto n = f_.from_montgomery(e);
    for (size_t b = 0; b < VS; ++b) {
      r.r[b] = bf_[b]->reduce(n, reduce_scale_[b]);
    }
    return r;
  }

  // The standard CRT reconstruction algorithm to convert
  // from the CRT representation to the BigRing representation involves
  // several operations between "ring-element"-sized values and prime-element
  // sized values. This method is slower, and it produces a result that must
  // also be reduced modulo the ring.
  //
  // result = (sum_{i} x_i * recon_i) (mod  P_))
  // CRTRing::Elt from_crt(const Elt& x) const {
  //   typename CRTRing::Elt r = ring_.zero();
  //   for (size_t i = 0; i < VS; ++i) {
  //     Nat<1> xi = kBasis[i].from_montgomery(x.r[i]);
  //     ring_.add(r, ring_.mulf(recon_[i], ring_.of_scalar(xi.limb_[0])));
  //   }
  //   return r;
  // }
  // BM_FromCRT     2.482µ ± ∞ ¹
  // BM_FromCRT     22.08k ± ∞ ¹ (instructions)
  // Instead, we use Garner's method, which can also reduce the returned value
  // by the Field modulus in the same step. This method is roughly 4x faster.
  //
  // BM_ToField     729.6n ± ∞ ¹
  // BM_ToField     6.282k ± ∞ ¹ (instructions)
  //
  // The Garner CRT reconstruction produces a result that lies in 0..m, and
  // only uses single-word arithmetic to produce the intermediate values
  // v1..vn.
  // If the eventual goal is to reconstruct an element in Fp, then the last
  // reconstruction step can be done in Fp, thereby requiring no arithmetic
  // in the Bigring.
  typename Field::Elt to_field(const Elt& x) const {
    // Let cij be s.t. c_ij.pi = 1 mod pj
    // v1 = x1
    // v2 = (x2 - v1).c12 mod p2
    // v3 = ((x3 - v1).c13 - v2).c23 mod p3
    // v4 = (((x4 - v1).c14 - v2).c24 - v3).c34 mod p4
    // ...
    // u = vr.p_{r-1}p_{r-2}...p_1 + ... + v4.p3.p2.p1 + v3.p2.p1 + ... + v1
    //   Because the goal is to compute u mod F_p, it suffices to maintain
    //   each of the p_{r-j}...p1 products modulo F_p.

    BaseNat vi[VS];
    // This inner loop breaks our field abstraction. Instead of maintaining
    // vi in Montgomery form, it is kept as a natural in [0,p-1].
    // The F.sub method works in this form, and because cij_ is in
    // Montgomery form, the last mul operation returns a result that is also
    // "natural." This maneuver saves an of_scalar and a from_montgomery
    // call in the inner-loop.
    for (size_t j = 0; j < VS; ++j) {
      vi[j] = bf_[j]->from_montgomery(x.r[j]);
    }

    // Change the order of operations to exploit data (in)dependencies. The
    // subtractions and mults can all issue in parallel.
    for (size_t j = 1; j < VS; ++j) {
      for (size_t i = j; i < VS; ++i) {
        const BaseField* Fi = bf_[i].get();
        Fi->sub(vi[i], vi[j - 1]);
        Fi->mul(vi[i], cij_[i][j - 1]);
      }
    }

    return f_.dot(VS, vi, garner_);
  }

  // Returns a root of unity consisting of a root of unity of the same degree
  // for each base prime.
  Elt omega() const {
    Elt r;
    for (size_t b = 0; b < VS; ++b) {
      r.r[b] = bf_[b]->of_scalar(crt::kOmega17[b]);
    }
    return r;
  }
  uint64_t omega_order() const { return crt::kOmegaOrder; }

  // x += y
  void add(Elt& x, const Elt& y) const {
    for (size_t i = 0; i < VS; ++i) {
      bf_[i]->add(x.r[i], y.r[i]);
    }
  }
  // x -= y
  void sub(Elt& x, const Elt& y) const {
    for (size_t i = 0; i < VS; ++i) {
      bf_[i]->sub(x.r[i], y.r[i]);
    }
  }

  // x *= y, Montgomery
  void mul(Elt& x, const Elt& y) const {
    for (size_t i = 0; i < VS; ++i) {
      bf_[i]->mul(x.r[i], y.r[i]);
    }
  }

  void neg(Elt& x) const {
    for (size_t i = 0; i < VS; ++i) {
      bf_[i]->neg(x.r[i]);
    }
  }

  void invert(Elt& x) const {
    for (size_t i = 0; i < VS; ++i) {
      check(x.r[i] != bf_[i]->zero(), "Non-invertible element");
      bf_[i]->invert(x.r[i]);
    }
  }

  // functional interface
  Elt addf(Elt a, const Elt& y) const {
    add(a, y);
    return a;
  }
  Elt subf(Elt a, const Elt& y) const {
    sub(a, y);
    return a;
  }
  Elt mulf(Elt a, const Elt& y) const {
    mul(a, y);
    return a;
  }
  Elt negf(Elt a) const {
    neg(a);
    return a;
  }

  Elt invertf(Elt a) const {
    invert(a);
    return a;
  }

  const Elt& zero() const { return k_[0]; }
  const Elt& one() const { return k_[1]; }
  const Elt& two() const { return k_[2]; }

 private:
  std::unique_ptr<BaseField> bf_[VS];
  Elt k_[3];  // small constants
  BaseField::template ScaleElt<kWField> reduce_scale_[VS];
  typename Field::NatScaledForDot garner_[VS];
  BaseElt cij_[VS][VS];
};

template <class Field>
using CRT256 = CRT<9, Field>;

template <class Field>
using CRT384 = CRT<13, Field>;

template <class Field>
using CRT521 = CRT<17, Field>;

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CRT_H_
