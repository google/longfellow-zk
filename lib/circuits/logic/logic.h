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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_LOGIC_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_LOGIC_H_

#include <stddef.h>

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

#include "algebra/fp_generic.h"
#include "gf2k/gf2_128.h"
#include "util/panic.h"

namespace proofs {
/*
  Arithmetization of boolean logic in a field.
  This class builds logical and arithmetic operations such as add, sub, mul,
  and, or, xor, etc. over bits in the arithmetic circuit model.
  The class utilizes several optimizations, including changing from the {0,1}
  basis to the {-1,1} basis for representing bits.
 */
template <typename Field_, class Backend>
class Logic {
 public:
  using Field = Field_; /* this class export Field, Elt, and EltW */
  using Elt = typename Field::Elt;
  // an "Elt Wire", a wire carrying an Elt.
  using EltW = typename Backend::V;

  const Field& f_;

  explicit Logic(const Backend* bk, const Field& F) : f_(F), bk_(bk) {}

  //------------------------------------------------------------
  // Arithmetic.

  //
  // Re-export field operations
  Elt addf(const Elt& a, const Elt& b) const { return f_.addf(a, b); }
  Elt mulf(const Elt& a, const Elt& b) const { return f_.mulf(a, b); }
  Elt invertf(const Elt& a) const { return f_.invertf(a); }
  Elt negf(const Elt& a) const { return f_.negf(a); }
  Elt zero() const { return f_.zero(); }
  Elt one() const { return f_.one(); }
  Elt mone() const { return f_.mone(); }
  Elt elt(uint64_t a) const { return f_.of_scalar(a); }

  template <size_t N>
  Elt elt(const char (&s)[N]) const {
    return f_.of_string(s);
  }

  // To ensure deterministic behavior, the order of function calls that produce
  // circuit wires must be well-defined at compile time.
  // The C spec leaves certain order of operations unspecified in expressions.
  // One such ambiguity arises in the order of function calls in an argument
  // list. For example, the expression f(creates_wire(x), creates_wire(y))
  // results in an ambiguous order.
  // To help prevent this, all function calls that create wires can have at most
  // one argument that is itself a function. To enforce this property, we
  // require that all but the last argument to a function be a const pointer.

  // Re-export backend operations
  EltW assert0(const EltW& a) const { return bk_->assert0(a); }
  EltW add(const EltW* a, const EltW& b) const { return bk_->add(*a, b); }

  EltW sub(const EltW* a, const EltW& b) const { return bk_->sub(*a, b); }

  EltW mul(const EltW* a, const EltW& b) const { return bk_->mul(*a, b); }
  EltW mul(const Elt& k, const EltW& b) const { return bk_->mul(k, b); }
  EltW mul(const Elt& k, const EltW* a, const EltW& b) const {
    return bk_->mul(k, a, b);
  }

  EltW ax(const Elt& a, const EltW& x) const { return bk_->ax(a, x); }
  EltW axy(const Elt& a, const EltW* x, const EltW& y) const {
    return bk_->axy(a, *x, y);
  }
  EltW axpy(const EltW* y, const Elt& a, const EltW& x) const {
    return bk_->axpy(*y, a, x);
  }
  EltW apy(const EltW& y, const Elt& a) const { return bk_->apy(y, a); }

  EltW konst(const Elt& a) const { return bk_->konst(a); }
  EltW konst(uint64_t a) const { return konst(elt(a)); }

  template <size_t N>
  std::array<EltW, N> konst(const std::array<Elt, N>& a) const {
    std::array<EltW, N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = konst(a[i]);
    }
    return r;
  }

  //------------------------------------------------------------
  // Boolean logic.
  //
  // We map TRUE to one() and FALSE to zero().  We call this convention
  // the "standard basis".
  //
  // However, actual values on wires may use different conventions,
  // e.g. -1 for TRUE and 1 for FALSE.  To keep track of these changes,
  // we represent boolean values as (c0, c1, x) where c0+c1*x is
  // the value in the standard basis.   c0 and c1
  // are compile-time constants that can be manipulated, and
  // x is a runtime value not known in advance.
  //
  // For example, let the "xor basis" denote the mapping FALSE -> 1,
  // TRUE -> -1.  In the xor basis, xor(a,b)=a*b.  The output of the
  // xor gate in the standard basis would be represented as 1/2 + (-1/2)*x
  // where x=a*b is the wire value in the xor basis.

  // a "bit Wire", a wire carrying a bit
  struct BitW {
    Elt c0, c1;
    EltW x;
    BitW() = default;

    // constructor in the standard basis
    explicit BitW(const EltW& bv, const Field& F)
        : BitW(F.zero(), F.one(), bv) {}

    BitW(Elt c0_, Elt c1_, const EltW& x_) : c0(c0_), c1(c1_), x(x_) {}
  };

  // vectors of N bits
  template <size_t N>
  class bitvec : public std::array<BitW, N> {};

  // Common sizes, publicly exported for convenience. The type names are
  // intentionally lower-case to capture the spirit of basic "intx_t" types.
  using v1 = bitvec<1>;
  using v4 = bitvec<4>;
  using v8 = bitvec<8>;
  using v16 = bitvec<16>;
  using v32 = bitvec<32>;
  using v64 = bitvec<64>;
  using v128 = bitvec<128>;
  using v129 = bitvec<129>;
  using v256 = bitvec<256>;

  // Let v(x)=c0+c1*x.  Return a representation of
  // d0+d1*v(x)=(d0+d1*c0)+(d1*c1)*x without changing x.
  // Does not involve the backend at all.
  BitW rebase(const Elt& d0, const Elt& d1, const BitW& v) const {
    return BitW(addf(d0, mulf(d1, v.c0)), mulf(d1, v.c1), v.x);
  }

  EltW eval(const BitW& v) const {
    EltW r = ax(v.c1, v.x);
    if (v.c0 != zero()) {
      auto c0 = konst(v.c0);
      r = add(&c0, r);
    }
    return r;
  }

  // compute in the circuit what F.of_scalar(sum_i v[i] 2^i) would compute
  // outside the circuit
  template <size_t N>
  EltW as_scalar(const bitvec<N>& v) const {
    EltW r = konst(zero());
    for (size_t i = 0; i < N; ++i) {
      auto vi = eval(v[i]);
      r = axpy(&r, f_.beta(i), vi);
    }
    return r;
  }

  // return an EltW which is 0 iff v is 0
  EltW assert0(const BitW& v) const {
    auto e = eval(v);
    return assert0(e);
  }
  // return an EltW which is 0 iff v is 1
  EltW assert1(const BitW& v) const {
    auto e = lnot(v);
    return assert0(e);
  }

  // 0 iff a==b
  EltW assert_eq(const EltW* a, const EltW& b) const {
    return assert0(sub(a, b));
  }
  EltW assert_eq(const BitW* a, const BitW& b) const {
    return assert0(lxor(a, b));
  }
  EltW assert_implies(const BitW* a, const BitW& b) const {
    return assert1(limplies(a, b));
  }

  // special test for asserting that b \in {0,1} (i.e.,
  // not some other field element).
  EltW assert_is_bit(const BitW& b) const {
    // b - b*b
    // Seems to work better than b*(1-b)
    // Equivalent to land(b,lnot(b)) but does not rely
    // on the specific arithmetization.
    auto eb = eval(b);
    return assert_is_bit(eb);
  }
  EltW assert_is_bit(const EltW& v) const {
    auto vvmv = sub(&v, mul(&v, v));
    return assert0(vvmv);
  }

  // bits in their own basis b + 0*1, to allow for some
  // compile-time constant folding
  BitW bit(size_t b) const {
    return BitW((b == 0) ? zero() : one(), zero(), konst(one()));
  }

  void bits(size_t n, BitW a[/*n*/], uint64_t x) const {
    for (size_t i = 0; i < n; ++i) {
      a[i] = bit((x >> i) & 1u);
    }
  }

  // gates
  BitW lnot(const BitW& x) const {
    // lnot() is a pure representation change that does not
    // involve actual circuit gates

    // 1 - x in the standard basis
    return rebase(one(), mone(), x);
  }

  BitW land(const BitW* a, const BitW& b) const {
    // a * b in the standard basis
    return mulv(a, b);
  }

  // special case of product of a logic value by a field
  // element
  EltW lmul(const BitW* a, const EltW& b) const {
    // a * b in the standard basis
    auto ab = mulv(a, BitW(b, f_));
    return eval(ab);
  }
  EltW lmul(const EltW* b, const BitW& a) const { return lmul(&a, *b); }

  BitW lxor(const BitW* a, const BitW& b) const {
    return lxor_aux(*a, b, typename Field::TypeTag());
  }
  BitW lxor(const BitW* a, const BitW* b) const {
    return lxor_aux(*a, *b, typename Field::TypeTag());
  }

  BitW lor(const BitW* a, const BitW& b) const {
    auto na = lnot(*a);
    auto nab = land(&na, lnot(b));
    return lnot(nab);
  }

  // a => b
  BitW limplies(const BitW* a, const BitW& b) const {
    auto na = lnot(*a);
    return lor(&na, b);
  }

  // OR of two quantities known to be mutually exclusive
  BitW lor_exclusive(const BitW* a, const BitW& b) const { return addv(*a, b); }

  BitW lxor3(const BitW* a, const BitW* b, const BitW& c) const {
    BitW p = lxor(a, b);
    return lxor(&p, c);
  }

  // sha256 Ch(): (x & y) ^ (~x & z);
  BitW lCh(const BitW* x, const BitW* y, const BitW& z) const {
    auto xy = land(x, *y);
    auto nx = lnot(*x);
    return lor_exclusive(&xy, land(&nx, z));
  }

  // sha256 Maj(): (x & y) ^ (x & z) ^ (y & z);
  BitW lMaj(const BitW* x, const BitW* y, const BitW& z) const {
    // Interpret as x + y + z >= 2 and compute the carry
    // for an adder in the (p, g) basis
    BitW p = lxor(x, *y);
    BitW g = land(x, *y);
    return lor_exclusive(&g, land(&p, z));
  }

  // mux over logic values
  BitW mux(const BitW* control, const BitW* iftrue, const BitW& iffalse) const {
    auto cif = land(control, *iftrue);
    auto nc = lnot(*control);
    auto ciff = land(&nc, iffalse);
    return lor_exclusive(&cif, ciff);
  }

  // mux over backend values
  EltW mux(const BitW* control, const EltW* iftrue, const EltW& iffalse) const {
    auto cif = lmul(control, *iftrue);
    auto nc = lnot(*control);
    auto ciff = lmul(&nc, iffalse);
    return add(&cif, ciff);
  }

  // sum_{i0 <= i < i1} f(i)
  EltW add(size_t i0, size_t i1, const std::function<EltW(size_t)>& f) const {
    if (i1 <= i0) {
      return konst(0);
    } else if (i1 == i0 + 1) {
      return f(i0);
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto lh = add(i0, im, f);
      auto rh = add(im, i1, f);
      return add(&lh, rh);
    }
  }

  // lor_exclusive_{i0 <= i < i1} f(i)
  BitW lor_exclusive(size_t i0, size_t i1,
                     const std::function<BitW(size_t)>& f) const {
    if (i1 <= i0) {
      return bit(0);
    } else if (i1 == i0 + 1) {
      return f(i0);
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto lh = lor_exclusive(i0, im, f);
      auto rh = lor_exclusive(im, i1, f);
      return lor_exclusive(&lh, rh);
    }
  }

  // and_{i0 <= i < i1} f(i)
  BitW land(size_t i0, size_t i1, const std::function<BitW(size_t)>& f) const {
    if (i1 <= i0) {
      return bit(1);
    } else if (i1 == i0 + 1) {
      return f(i0);
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto lh = land(i0, im, f);
      auto rh = land(im, i1, f);
      return land(&lh, rh);
    }
  }

  // or_{i0 <= i < i1} f(i)
  BitW lor(size_t i0, size_t i1, const std::function<BitW(size_t)>& f) const {
    if (i1 <= i0) {
      return bit(0);
    } else if (i1 == i0 + 1) {
      return f(i0);
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto lh = lor(i0, im, f);
      auto rh = lor(im, i1, f);
      return lor(&lh, rh);
    }
  }

  BitW or_of_and(std::vector<std::vector<BitW>> clauses_of_ands) const {
    std::vector<BitW> ands(clauses_of_ands.size());
    for (size_t i = 0; i < clauses_of_ands.size(); ++i) {
      auto ai = clauses_of_ands[i];
      BitW res = land(0, ai.size(), [&](size_t i) { return ai[i]; });
      ands[i] = res;
    }
    return lor(0, ands.size(), [&](size_t i) { return ands[i]; });
  }

  // prod_{i0 <= i < i1} f(i)
  EltW mul(size_t i0, size_t i1, const std::function<EltW(size_t)>& f) const {
    if (i1 <= i0) {
      return konst(1);
    } else if (i1 == i0 + 1) {
      return f(i0);
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto lh = mul(i0, im, f);
      auto rh = mul(im, i1, f);
      return mul(&lh, rh);
    }
  }

  // assert that a + b = c in constant depth
  void assert_sum(size_t w, const BitW c[/*w*/], const BitW a[/*w*/],
                  const BitW b[/*w*/]) const {
    // first step of generic_gp_add(): change the basis from
    // (a, b) to (g, p):
    std::vector<BitW> g(w), p(w), cy(w);
    for (size_t i = 0; i < w; ++i) {
      g[i] = land(&a[i], b[i]);
      p[i] = lxor(&a[i], &b[i]);
    }

    // invert the last step of generic_gp_add(): derive
    // cy[i - 1] (called g[i - 1] there) from
    // c[i] and p[i].
    assert_eq(&c[0], p[0]);
    for (size_t i = 1; i < w; ++i) {
      cy[i - 1] = lxor(&c[i], p[i]);
    }

    // Verify that applying ripple_scan to g[] produces cy[].
    // Note that ripple_scan() operates in-place on g[].  Here, however, g[] is
    // the input to ripple_scan(), and cy[] is the output.
    assert_eq(&cy[0], g[0]);
    for (size_t i = 1; i + 1 < w; ++i) {
      auto cyp = land(&cy[i - 1], p[i]);
      auto g_cyp = lor_exclusive(&g[i], cyp);
      assert_eq(&cy[i], g_cyp);
    }
  }

  // (carry, c) = a + b, returning the carry.
  BitW ripple_carry_add(size_t w, BitW c[/*w*/], const BitW a[/*w*/],
                        const BitW b[/*w*/]) const {
    return generic_gp_add(w, c, a, b, &Logic::ripple_scan);
  }

  // (carry, c) = a - b, returning the carry.
  BitW ripple_carry_sub(size_t w, BitW c[/*w*/], const BitW a[/*w*/],
                        const BitW b[/*w*/]) const {
    return generic_gp_sub(w, c, a, b, &Logic::ripple_scan);
  }

  BitW parallel_prefix_add(size_t w, BitW c[/*w*/], const BitW a[/*w*/],
                           const BitW b[/*w*/]) const {
    return generic_gp_add(w, c, a, b, &Logic::sklansky_scan);
  }

  BitW parallel_prefix_sub(size_t w, BitW c[/*w*/], const BitW a[/*w*/],
                           const BitW b[/*w*/]) const {
    return generic_gp_sub(w, c, a, b, &Logic::sklansky_scan);
  }

  // w x w -> 2w-bit multiplier c = a * b
  void multiplier(size_t w, BitW c[/*2*w*/], const BitW a[/*w*/],
                  const BitW b[/*w*/]) const {
    std::vector<BitW> t(w);
    for (size_t i = 0; i < w; ++i) {
      if (i == 0) {
        for (size_t j = 0; j < w; ++j) {
          c[j] = land(&a[0], b[j]);
        }
        c[w] = bit(0);
      } else {
        for (size_t j = 0; j < w; ++j) {
          t[j] = land(&a[i], b[j]);
        }
        BitW carry = ripple_carry_add(w, c + i, t.data(), c + i);
        c[i + w] = carry;
      }
    }
  }

  // w x w -> 2w-bit polynomial multiplier over gf2.  c(x) = a(x) * b(x)
  void gf2_polynomial_multiplier(size_t w, BitW c[/*2*w*/], const BitW a[/*w*/],
                                 const BitW b[/*w*/]) const {
    std::vector<BitW> t(w);
    for (size_t k = 0; k < 2 * w; ++k) {
      size_t n = 0;
      for (size_t i = 0; i < w; ++i) {
        if (k >= i && k - i < w) {
          t[n++] = land(&a[i], b[k - i]);
        }
      }
      c[k] = parity(0, n, t.data());
    }
  }

  // w x w -> 2w-bit polynomial multiplier over gf2.  c(x) = a(x) * b(x)
  // via the Karatsuba recurrence.  Only works for w = 2^k.
  void gf2_polynomial_multiplier_karat(size_t w, BitW c[/*2*w*/],
                                       const BitW a[/*w*/],
                                       const BitW b[/*w*/]) const {
    check(w == 128 || w == 64 || w < 64, "input length is not a power of 2");
    if (w < 64) {
      gf2_polynomial_multiplier(w, c, a, b);
      return;
    } else {
      // We only run this look on w=128 bits. To support odd w,
      std::vector<BitW> a01(w / 2); /* a0 plus a1 */
      std::vector<BitW> b01(w / 2); /* b0 plus b1 */
      std::vector<BitW> ab01(w);
      std::vector<BitW> a0b0(w);
      std::vector<BitW> a1b1(w);

      for (size_t i = 0; i < w / 2; ++i) {
        a01[i] = lxor(&a[i], a[i + w / 2]);
        b01[i] = lxor(&b[i], b[i + w / 2]);
      }

      gf2_polynomial_multiplier_karat(w / 2, &ab01[0], &a01[0], &b01[0]);
      gf2_polynomial_multiplier_karat(w / 2, &a0b0[0], a, b);
      gf2_polynomial_multiplier_karat(w / 2, &a1b1[0], a + w / 2, b + w / 2);

      for (size_t i = 0; i < w; ++i) {
        ab01[i] = lxor3(&ab01[i], &a0b0[i], a1b1[i]);
      }

      for (size_t i = 0; i < w / 2; ++i) {
        c[i] = a0b0[i];
        c[i + w / 2] = lxor(&a0b0[i + w / 2], ab01[i]);
        c[i + w] = lxor(&ab01[i + w / 2], a1b1[i]);
        c[i + 3 * w / 2] = a1b1[i + w / 2];
      }
    }
  }

  // Performs field multiplication in GF2^128 defined by the irreducible
  // x^128 + x^7 + x^2 + x + 1. This routine is generated in a sage script that
  // computes a sparse matrix-vector mult via the powers of x^k mod p(x).
  //
  // def make_mulmod(F, n):
  //   r = F(1)
  //   gen = F.gen()
  //   nl = [[] for _ in range(n)]
  //   terms = 0
  //   for i in range(0, 2*n-1):
  //       for j, var in enumerate(r.polynomial().list()):
  //           if var == 1:
  //               nl[j].append(i)
  //       r = r * gen
  //   print(nl)
  void gf2_128_mul(v128& c, const v128 a, const v128 b) const {
    const std::vector<uint16_t> taps[128] = {
        {0, 128, 249, 254},
        {1, 128, 129, 249, 250, 254},
        {2, 128, 129, 130, 249, 250, 251, 254},
        {3, 129, 130, 131, 250, 251, 252},
        {4, 130, 131, 132, 251, 252, 253},
        {5, 131, 132, 133, 252, 253, 254},
        {6, 132, 133, 134, 253, 254},
        {7, 128, 133, 134, 135, 249},
        {8, 129, 134, 135, 136, 250},
        {9, 130, 135, 136, 137, 251},
        {10, 131, 136, 137, 138, 252},
        {11, 132, 137, 138, 139, 253},
        {12, 133, 138, 139, 140, 254},
        {13, 134, 139, 140, 141},
        {14, 135, 140, 141, 142},
        {15, 136, 141, 142, 143},
        {16, 137, 142, 143, 144},
        {17, 138, 143, 144, 145},
        {18, 139, 144, 145, 146},
        {19, 140, 145, 146, 147},
        {20, 141, 146, 147, 148},
        {21, 142, 147, 148, 149},
        {22, 143, 148, 149, 150},
        {23, 144, 149, 150, 151},
        {24, 145, 150, 151, 152},
        {25, 146, 151, 152, 153},
        {26, 147, 152, 153, 154},
        {27, 148, 153, 154, 155},
        {28, 149, 154, 155, 156},
        {29, 150, 155, 156, 157},
        {30, 151, 156, 157, 158},
        {31, 152, 157, 158, 159},
        {32, 153, 158, 159, 160},
        {33, 154, 159, 160, 161},
        {34, 155, 160, 161, 162},
        {35, 156, 161, 162, 163},
        {36, 157, 162, 163, 164},
        {37, 158, 163, 164, 165},
        {38, 159, 164, 165, 166},
        {39, 160, 165, 166, 167},
        {40, 161, 166, 167, 168},
        {41, 162, 167, 168, 169},
        {42, 163, 168, 169, 170},
        {43, 164, 169, 170, 171},
        {44, 165, 170, 171, 172},
        {45, 166, 171, 172, 173},
        {46, 167, 172, 173, 174},
        {47, 168, 173, 174, 175},
        {48, 169, 174, 175, 176},
        {49, 170, 175, 176, 177},
        {50, 171, 176, 177, 178},
        {51, 172, 177, 178, 179},
        {52, 173, 178, 179, 180},
        {53, 174, 179, 180, 181},
        {54, 175, 180, 181, 182},
        {55, 176, 181, 182, 183},
        {56, 177, 182, 183, 184},
        {57, 178, 183, 184, 185},
        {58, 179, 184, 185, 186},
        {59, 180, 185, 186, 187},
        {60, 181, 186, 187, 188},
        {61, 182, 187, 188, 189},
        {62, 183, 188, 189, 190},
        {63, 184, 189, 190, 191},
        {64, 185, 190, 191, 192},
        {65, 186, 191, 192, 193},
        {66, 187, 192, 193, 194},
        {67, 188, 193, 194, 195},
        {68, 189, 194, 195, 196},
        {69, 190, 195, 196, 197},
        {70, 191, 196, 197, 198},
        {71, 192, 197, 198, 199},
        {72, 193, 198, 199, 200},
        {73, 194, 199, 200, 201},
        {74, 195, 200, 201, 202},
        {75, 196, 201, 202, 203},
        {76, 197, 202, 203, 204},
        {77, 198, 203, 204, 205},
        {78, 199, 204, 205, 206},
        {79, 200, 205, 206, 207},
        {80, 201, 206, 207, 208},
        {81, 202, 207, 208, 209},
        {82, 203, 208, 209, 210},
        {83, 204, 209, 210, 211},
        {84, 205, 210, 211, 212},
        {85, 206, 211, 212, 213},
        {86, 207, 212, 213, 214},
        {87, 208, 213, 214, 215},
        {88, 209, 214, 215, 216},
        {89, 210, 215, 216, 217},
        {90, 211, 216, 217, 218},
        {91, 212, 217, 218, 219},
        {92, 213, 218, 219, 220},
        {93, 214, 219, 220, 221},
        {94, 215, 220, 221, 222},
        {95, 216, 221, 222, 223},
        {96, 217, 222, 223, 224},
        {97, 218, 223, 224, 225},
        {98, 219, 224, 225, 226},
        {99, 220, 225, 226, 227},
        {100, 221, 226, 227, 228},
        {101, 222, 227, 228, 229},
        {102, 223, 228, 229, 230},
        {103, 224, 229, 230, 231},
        {104, 225, 230, 231, 232},
        {105, 226, 231, 232, 233},
        {106, 227, 232, 233, 234},
        {107, 228, 233, 234, 235},
        {108, 229, 234, 235, 236},
        {109, 230, 235, 236, 237},
        {110, 231, 236, 237, 238},
        {111, 232, 237, 238, 239},
        {112, 233, 238, 239, 240},
        {113, 234, 239, 240, 241},
        {114, 235, 240, 241, 242},
        {115, 236, 241, 242, 243},
        {116, 237, 242, 243, 244},
        {117, 238, 243, 244, 245},
        {118, 239, 244, 245, 246},
        {119, 240, 245, 246, 247},
        {120, 241, 246, 247, 248},
        {121, 242, 247, 248, 249},
        {122, 243, 248, 249, 250},
        {123, 244, 249, 250, 251},
        {124, 245, 250, 251, 252},
        {125, 246, 251, 252, 253},
        {126, 247, 252, 253, 254},
        {127, 248, 253, 254},
    };
    gf2k_mul(c.data(), a.data(), b.data(), taps, 128);
  }

  // Performs field multiplication in GF2^k using a sparse matrix datastructure.
  void gf2k_mul(BitW c[/*w*/], const BitW a[/*w*/], const BitW b[/*w*/],
                const std::vector<uint16_t> M[], size_t w) const {
    std::vector<BitW> t(w * 2);
    gf2_polynomial_multiplier_karat(w, t.data(), a, b);

    std::vector<BitW> tmp(w);
    for (size_t i = 0; i < w; ++i) {
      size_t n = 0;
      for (auto ti : M[i]) {
        tmp[n++] = t[ti];
      }
      c[i] = parity(0, n, tmp.data());
    }
  }

  // a == 0
  BitW eq0(size_t w, const BitW a[/*w*/]) const { return eq0(0, w, a); }

  // a == b
  BitW eq(size_t w, const BitW a[/*w*/], const BitW b[/*w*/]) const {
    return eq_reduce(0, w, a, b);
  }

  // a < b.
  // Specialization of the subtractor for the case (a - b) < 0
  BitW lt(size_t w, const BitW a[/*w*/], const BitW b[/*w*/]) const {
    if (w == 0) {
      return bit(0);
    } else {
      BitW xeq, xlt;
      lt_reduce(0, w, &xeq, &xlt, a, b);
      return xlt;
    }
  }

  // a <= b
  BitW leq(size_t w, const BitW a[/*w*/], const BitW b[/*w*/]) const {
    auto blt = lt(w, b, a);
    return lnot(blt);
  }

  // Parallel prefix of various kinds
  template <class T>
  void scan(const std::function<void(T*, const T&, const T&)>& op, T x[],
            size_t i0, size_t i1, bool backward = false) const {
    // generic Sklansky scan
    if (i1 - i0 > 1) {
      size_t im = i0 + (i1 - i0) / 2;
      scan(op, x, i0, im, backward);
      scan(op, x, im, i1, backward);
      if (backward) {
        for (size_t i = i0; i < im; ++i) {
          op(&x[i], x[i], x[im]);
        }
      } else {
        for (size_t i = im; i < i1; ++i) {
          op(&x[i], x[im - 1], x[i]);
        }
      }
    }
  }

  void scan_and(BitW x[], size_t i0, size_t i1, bool backward = false) const {
    scan<BitW>(
        [&](BitW* out, const BitW& l, const BitW& r) { *out = land(&l, r); }, x,
        i0, i1, backward);
  }

  void scan_or(BitW x[], size_t i0, size_t i1, bool backward = false) const {
    scan<BitW>(
        [&](BitW* out, const BitW& l, const BitW& r) { *out = lor(&l, r); }, x,
        i0, i1, backward);
  }

  void scan_xor(BitW x[], size_t i0, size_t i1, bool backward = false) const {
    scan<BitW>(
        [&](BitW* out, const BitW& l, const BitW& r) { *out = lxor(&l, r); }, x,
        i0, i1, backward);
  }

  template <size_t I0, size_t I1, size_t N>
  bitvec<I1 - I0> slice(const bitvec<N>& a) const {
    bitvec<I1 - I0> r;
    for (size_t i = I0; i < I1; ++i) {
      r[i - I0] = a[i];
    }
    return r;
  }

  // Little-endian append of A and B.  A[0] is the LSB, B starts at
  // position [NA].
  template <size_t NA, size_t NB>
  bitvec<NA + NB> vappend(const bitvec<NA>& a, const bitvec<NB>& b) const {
    bitvec<NA + NB> r;
    for (size_t i = 0; i < NA; ++i) {
      r[i] = a[i];
    }
    for (size_t i = 0; i < NB; ++i) {
      r[i + NA] = b[i];
    }
    return r;
  }

  template <size_t N>
  bool vequal(const bitvec<N>* a, const bitvec<N>& b) const {
    for (size_t i = 0; i < N; ++i) {
      auto eai = eval((*a)[i]);
      auto ebi = eval(b[i]);
      if (eai != ebi) return false;
    }
    return true;
  }

  template <size_t N>
  bitvec<N> vbit(uint64_t x) const {
    bitvec<N> r;
    bits(N, r.data(), x);
    return r;
  }

  // shorthands for the silly "template" notation
  v8 vbit8(uint64_t x) const { return vbit<8>(x); }
  v32 vbit32(uint64_t x) const { return vbit<32>(x); }

  template <size_t N>
  bitvec<N> vnot(const bitvec<N>& x) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lnot(x[i]);
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vand(const bitvec<N>* a, const bitvec<N>& b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = land(&(*a)[i], b[i]);
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vand(const BitW* a, const bitvec<N>& b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = land(a, b[i]);
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vor(const bitvec<N>* a, const bitvec<N>& b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lor(&(*a)[i], b[i]);
    }
    return r;
  }
  template <size_t N>
  bitvec<N> vor_exclusive(const bitvec<N>* a, const bitvec<N>& b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lor_exclusive(&(*a)[i], b[i]);
    }
    return r;
  }
  template <size_t N>
  bitvec<N> vxor(const bitvec<N>* a, const bitvec<N>& b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lxor(&(*a)[i], b[i]);
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vCh(const bitvec<N>* x, const bitvec<N>* y,
                const bitvec<N>& z) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lCh(&(*x)[i], &(*y)[i], z[i]);
    }
    return r;
  }
  template <size_t N>
  bitvec<N> vMaj(const bitvec<N>* x, const bitvec<N>* y,
                 const bitvec<N>& z) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lMaj(&(*x)[i], &(*y)[i], z[i]);
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vxor3(const bitvec<N>* x, const bitvec<N>* y,
                  const bitvec<N>& z) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = lxor3(&(*x)[i], &(*y)[i], z[i]);
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vshr(const bitvec<N>& a, size_t shift, size_t b = 0) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      if (i + shift < N) {
        r[i] = a[i + shift];
      } else {
        r[i] = bit(b);
      }
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vshl(const bitvec<N>& a, size_t shift, size_t b = 0) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      if (i >= shift) {
        r[i] = a[i - shift];
      } else {
        r[i] = bit(b);
      }
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vrotr(const bitvec<N>& a, size_t b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = a[(i + b) % N];
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vrotl(const bitvec<N>& a, size_t b) const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[(i + b) % N] = a[i];
    }
    return r;
  }

  template <size_t N>
  bitvec<N> vadd(const bitvec<N>& a, const bitvec<N>& b) const {
    bitvec<N> r;
    (void)parallel_prefix_add(N, &r[0], &a[0], &b[0]);
    return r;
  }
  template <size_t N>
  bitvec<N> vadd(const bitvec<N>& a, uint64_t val) const {
    return vadd(a, vbit<N>(val));
  }

  template <size_t N>
  BitW veq(const bitvec<N>& a, const bitvec<N>& b) const {
    return eq(N, a.data(), b.data());
  }
  template <size_t N>
  BitW veq(const bitvec<N>& a, uint64_t val) const {
    auto v = vbit<N>(val);
    return veq(a, v);
  }
  template <size_t N>
  BitW vlt(const bitvec<N>* a, const bitvec<N>& b) const {
    return lt(N, (*a).data(), b.data());
  }
  template <size_t N>
  BitW vlt(const bitvec<N>& a, uint64_t val) const {
    auto v = vbit<N>(val);
    return vlt(&a, v);
  }
  template <size_t N>
  BitW vlt(uint64_t a, const bitvec<N>& b) const {
    auto va = vbit<N>(a);
    return vlt(&va, b);
  }
  template <size_t N>
  BitW vleq(const bitvec<N>* a, const bitvec<N>& b) const {
    return leq(N, (*a).data(), b.data());
  }
  template <size_t N>
  BitW vleq(const bitvec<N>& a, uint64_t val) const {
    auto v = vbit<N>(val);
    return vleq(&a, v);
  }

  // (a ^ val) & mask == 0
  template <size_t N>
  BitW veqmask(const bitvec<N>* a, uint64_t mask, const bitvec<N>& val) const {
    auto r = vxor(a, val);
    size_t n = pack(mask, N, &r[0]);
    return eq0(0, n, &r[0]);
  }

  template <size_t N>
  BitW veqmask(const bitvec<N>& a, uint64_t mask, uint64_t val) const {
    auto v = vbit<N>(val);
    return veqmask(&a, mask, v);
  }

  // I/O.  This is a hack which only works if the backend supports
  // bk_->{input,output}.  Because C++ templates are lazily expanded,
  // this class compiles even with backends that do not support I/O,
  // as long as you don't expand vinput(), voutput().
  EltW eltw_input() const { return bk_->input(); }
  BitW input() const { return BitW(bk_->input(), f_); }
  void output(const BitW& x, size_t i) const { bk_->output(eval(x), i); }
  size_t wire_id(const BitW& v) const { return bk_->wire_id(v.x); }
  size_t wire_id(const EltW& x) const { return bk_->wire_id(x); }

  template <size_t N>
  bitvec<N> vinput() const {
    bitvec<N> r;
    for (size_t i = 0; i < N; ++i) {
      r[i] = input();
    }
    return r;
  }

  template <size_t N>
  void voutput(const bitvec<N>& x, size_t i0) const {
    for (size_t i = 0; i < N; ++i) {
      output(x[i], i + i0);
    }
  }

  template <size_t N>
  void vassert0(const bitvec<N>& x) const {
    for (size_t i = 0; i < N; ++i) {
      (void)assert0(x[i]);
    }
  }

  template <size_t N>
  void vassert_eq(const bitvec<N>* x, const bitvec<N>& y) const {
    for (size_t i = 0; i < N; ++i) {
      (void)assert_eq(&(*x)[i], y[i]);
    }
  }

  template <size_t N>
  void vassert_eq(const bitvec<N>& x, uint64_t y) const {
    auto v = vbit<N>(y);
    vassert_eq(&x, v);
  }

  template <size_t N>
  void vassert_is_bit(const bitvec<N>& a) const {
    for (size_t i = 0; i < N; ++i) {
      (void)assert_is_bit(a[i]);
    }
  }

 private:
  // return one quad gate for the product eval(a)*eval(b),
  // optimizing some "obvious" cases.
  BitW mulv(const BitW* a, const BitW& b) const {
    if (a->c1 == zero()) {
      return rebase(zero(), a->c0, b);
    } else if (b.c1 == zero()) {
      return mulv(&b, *a);
    } else {
      // Avoid creating the intermediate term 1 * a.x * b.x which is
      // likely a useless node.  Moreover, two nodes (k1 * a.x * b.x)
      // and (k2 * a.x * b.x) will detect the common subexpression
      // (a.x * b.x), which will confusingly increment the
      // common-subexpression counter.
      EltW x = axy(mulf(a->c1, b.c1), &a->x, b.x);
      x = axpy(&x, mulf(a->c0, b.c1), b.x);
      x = axpy(&x, mulf(a->c1, b.c0), a->x);
      x = apy(x, mulf(a->c0, b.c0));
      return BitW(x, f_);
    }
  }

  BitW addv(const BitW& a, const BitW& b) const {
    if (a.c1 == zero()) {
      return BitW(addf(a.c0, b.c0), b.c1, b.x);
    } else if (b.c1 == zero()) {
      return addv(b, a);
    } else {
      EltW x = ax(a.c1, a.x);
      auto axb = ax(b.c1, b.x);
      x = add(&x, axb);
      x = apy(x, addf(a.c0, b.c0));
      return BitW(x, f_);
    }
  }

  BitW lxor_aux(const BitW& a, const BitW& b, PrimeFieldTypeTag tt) const {
    // a * b in the xor basis TRUE -> -1, FALSE -> 1
    // map a, b from standard basis to xor basis
    Elt mtwo = f_.negf(f_.two());
    Elt half = f_.half();
    Elt mhalf = f_.negf(half);

    BitW a1 = rebase(one(), mtwo, a);
    BitW b1 = rebase(one(), mtwo, b);
    BitW p = mulv(&a1, b1);
    return rebase(half, mhalf, p);
  }
  BitW lxor_aux(const BitW& a, const BitW& b, BinaryFieldTypeTag tt) const {
    return addv(a, b);
  }

  size_t pack(uint64_t mask, size_t n, BitW a[/*n*/]) const {
    size_t j = 0;
    for (size_t i = 0; i < n; ++i) {
      if (mask & 1) {
        a[j++] = a[i];
      }
      mask >>= 1;
    }
    return j;
  }

  // carry-propagation equations
  // (g0, p0) + (g1, p1) = (g1 | (g0 & p1), p0 & p1)
  // Accumulate in-place into (g1, p1).
  //
  // We use the property that g1 and p1 are mutually exclusive (g1&p1
  // is false), and therefore g1 and (g0 & p1) are also mutually
  // exclusive.
  void gp_reduce(const BitW& g0, const BitW& p0, BitW* g1, BitW* p1) const {
    auto g0p1 = land(&g0, *p1);
    *g1 = lor_exclusive(g1, g0p1);
    *p1 = land(&p0, *p1);
  }

  // ripple carry propagation
  void ripple_scan(std::vector<BitW>& g, std::vector<BitW>& p, size_t i0,
                   size_t i1) const {
    for (size_t i = i0 + 1; i < i1; ++i) {
      gp_reduce(g[i - 1], p[i - 1], &g[i], &p[i]);
    }
  }

  // parallel-prefix carry propagation, Sklansky-style [1960]
  void sklansky_scan(std::vector<BitW>& g, std::vector<BitW>& p, size_t i0,
                     size_t i1) const {
    if (i1 - i0 > 1) {
      size_t im = i0 + (i1 - i0) / 2;
      sklansky_scan(g, p, i0, im);
      sklansky_scan(g, p, im, i1);
      for (size_t i = im; i < i1; ++i) {
        gp_reduce(g[im - 1], p[im - 1], &g[i], &p[i]);
      }
    }
  }

  // generic add in generate/propagate form, parametrized
  // by the scan primitive.
  //
  // (carry, c) = a + b
  BitW generic_gp_add(size_t w, BitW c[/*w*/], const BitW a[/*w*/],
                      const BitW b[/*w*/],
                      void (Logic::*scan)(std::vector<BitW>& /*g*/,
                                          std::vector<BitW>& /*p*/,
                                          size_t /*i0*/, size_t /*i1*/)
                          const) const {
    if (w == 0) {
      return bit(0);
    } else {
      std::vector<BitW> g(w), p(w);
      for (size_t i = 0; i < w; ++i) {
        g[i] = land(&a[i], b[i]);
        p[i] = lxor(&a[i], b[i]);
        c[i] = p[i];
      }
      (this->*scan)(g, p, 0, w);
      for (size_t i = 1; i < w; ++i) {
        c[i] = lxor(&c[i], g[i - 1]);
      }
      return g[w - 1];
    }
  }

  BitW generic_gp_sub(size_t w, BitW c[/*w*/], const BitW a[/*w*/],
                      const BitW b[/*w*/],
                      void (Logic::*scan)(std::vector<BitW>& /*g*/,
                                          std::vector<BitW>& /*p*/,
                                          size_t /*i0*/, size_t /*i1*/)
                          const) const {
    // implement as ~(~a + b)
    std::vector<BitW> t(w);
    for (size_t j = 0; j < w; ++j) {
      t[j] = lnot(a[j]);
    }
    BitW carry = generic_gp_add(w, c, t.data(), b, scan);
    for (size_t j = 0; j < w; ++j) {
      c[j] = lnot(c[j]);
    }
    return carry;
  }

  // Recursion for the a < b comparison.
  // Let a = (a1, a0) and b = (b1, b0).  Then:
  //
  // a == b   iff a1 == b1 && a0 == b0
  // a < b    iff a1 < b1 || (a1 == b1 && a0 < b0)
  void lt_reduce(size_t i0, size_t i1, BitW* xeq, BitW* xlt,
                 const BitW a[/*w*/], const BitW b[/*w*/]) const {
    if (i1 - i0 > 1) {
      BitW eq0, eq1, lt0, lt1;
      size_t im = i0 + (i1 - i0) / 2;
      lt_reduce(i0, im, &eq0, &lt0, a, b);
      lt_reduce(im, i1, &eq1, &lt1, a, b);
      *xeq = land(&eq1, eq0);
      auto lt0_and_eq1 = land(&eq1, lt0);
      *xlt = lor_exclusive(&lt1, lt0_and_eq1);
    } else {
      auto axb = lxor(&a[i0], b[i0]);
      *xeq = lnot(axb);
      auto na = lnot(a[i0]);
      *xlt = land(&na, b[i0]);
    }
  }

  BitW parity(size_t i0, size_t i1, const BitW a[]) const {
    if (i1 <= i0) {
      return bit(0);
    } else if (i1 == i0 + 1) {
      return a[i0];
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto lp = parity(i0, im, a);
      auto rp = parity(im, i1, a);
      return lxor(&lp, rp);
    }
  }

  BitW eq0(size_t i0, size_t i1, const BitW a[]) const {
    if (i1 <= i0) {
      return bit(1);
    } else if (i1 == i0 + 1) {
      return lnot(a[i0]);
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto le = eq0(i0, im, a);
      auto re = eq0(im, i1, a);
      return land(&le, re);
    }
  }

  BitW eq_reduce(size_t i0, size_t i1, const BitW a[], const BitW b[]) const {
    if (i1 <= i0) {
      return bit(1);
    } else if (i1 == i0 + 1) {
      return lnot(lxor(&a[i0], b[i0]));
    } else {
      size_t im = i0 + (i1 - i0) / 2;
      auto le = eq_reduce(i0, im, a, b);
      auto re = eq_reduce(im, i1, a, b);
      return land(&le, re);
    }
  }

  const Backend* bk_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_LOGIC_H_
