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

#ifndef PRIVACY_PROOFS_ZK_LIB_GF2K_SYSDEP_H_
#define PRIVACY_PROOFS_ZK_LIB_GF2K_SYSDEP_H_

#include <stddef.h>
#include <stdint.h>

#include <array>

// Hardcoded GF(2^128) SIMD arithmetic where
// GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>  // IWYU pragma: keep

namespace proofs {

using gf2_128_elt_t = __m128i;

static inline std::array<uint64_t, 2> uint64x2_of_gf2_128(gf2_128_elt_t x) {
  return std::array<uint64_t, 2>{static_cast<uint64_t>(x[0]),
                                 static_cast<uint64_t>(x[1])};
}

static inline gf2_128_elt_t gf2_128_of_uint64x2(
    const std::array<uint64_t, 2> &x) {
  // Cast to long long (as opposed to int64_t) is necessary because __m128i is
  // defined in terms of long long.
  return gf2_128_elt_t{static_cast<long long>(x[0]),
                       static_cast<long long>(x[1])};
}

static inline gf2_128_elt_t gf2_128_add(gf2_128_elt_t x, gf2_128_elt_t y) {
  return _mm_xor_si128(x, y);
}

// return t0 + x^64 * t1
static inline gf2_128_elt_t gf2_128_reduce(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  const gf2_128_elt_t poly = {0x87};
  t0 = _mm_xor_si128(t0, _mm_slli_si128(t1, 64 /*bits*/ / 8 /*bits/byte*/));
  t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(t1, poly, 0x01));
  return t0;
}
static inline gf2_128_elt_t gf2_128_mul(gf2_128_elt_t x, gf2_128_elt_t y) {
  gf2_128_elt_t t1a = _mm_clmulepi64_si128(x, y, 0x01);
  gf2_128_elt_t t1b = _mm_clmulepi64_si128(x, y, 0x10);
  gf2_128_elt_t t1 = gf2_128_add(t1a, t1b);
  gf2_128_elt_t t2 = _mm_clmulepi64_si128(x, y, 0x11);
  t1 = gf2_128_reduce(t1, t2);
  gf2_128_elt_t t0 = _mm_clmulepi64_si128(x, y, 0x00);
  t0 = gf2_128_reduce(t0, t1);
  return t0;
}
}  // namespace proofs
#elif defined(__aarch64__)
//
// Implementation for arm/neon with AES instructions.
// We assume that __aarch64__ implies AES, which isn't necessarily
// the case.  If this is a problem, change the defined(__aarch64__)
// above and the code will fall back to the non-AES implementation
// below.
//
#include <arm_neon.h>  // IWYU pragma: keep

namespace proofs {
using gf2_128_elt_t = poly64x2_t;

static inline std::array<uint64_t, 2> uint64x2_of_gf2_128(gf2_128_elt_t x) {
  return std::array<uint64_t, 2>{static_cast<uint64_t>(x[0]),
                                 static_cast<uint64_t>(x[1])};
}

static inline gf2_128_elt_t gf2_128_of_uint64x2(
    const std::array<uint64_t, 2>& x) {
  return gf2_128_elt_t{static_cast<poly64_t>(x[0]),
                       static_cast<poly64_t>(x[1])};
}

static inline gf2_128_elt_t vmull_low(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  poly64_t tt0 = vgetq_lane_p64(t0, 0);
  poly64_t tt1 = vgetq_lane_p64(t1, 0);
  return vreinterpretq_p64_p128(vmull_p64(tt0, tt1));
}
static inline gf2_128_elt_t vmull_high(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  return vreinterpretq_p64_p128(vmull_high_p64(t0, t1));
}

// return t0 + x^64 * t1
static inline gf2_128_elt_t gf2_128_reduce(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  const gf2_128_elt_t poly = {0x0, 0x87};
  const gf2_128_elt_t zero = {0x0, 0x0};
  t0 = vaddq_p64(t0, vextq_p64(zero, t1, 1));
  t0 = vaddq_p64(t0, vmull_high(t1, poly));
  return t0;
}
static inline gf2_128_elt_t gf2_128_add(gf2_128_elt_t x, gf2_128_elt_t y) {
  return vaddq_p64(x, y);
}
static inline gf2_128_elt_t gf2_128_mul(gf2_128_elt_t x, gf2_128_elt_t y) {
  gf2_128_elt_t swx = vextq_p64(x, x, 1);
  gf2_128_elt_t t1a = vmull_high(swx, y);
  gf2_128_elt_t t1b = vmull_low(swx, y);
  gf2_128_elt_t t1 = vaddq_p64(t1a, t1b);
  gf2_128_elt_t t2 = vmull_high(x, y);
  t1 = gf2_128_reduce(t1, t2);
  gf2_128_elt_t t0 = vmull_low(x, y);
  t0 = gf2_128_reduce(t0, t1);
  return t0;
}
}  // namespace proofs

#elif defined(__arm__) || defined(__aarch64__)
//
// Implementation for arm/neon without AES instructions
//
#include <arm_neon.h>  // IWYU pragma: keep

namespace proofs {
using gf2_128_elt_t = poly64x2_t;

static inline std::array<uint64_t, 2> uint64x2_of_gf2_128(gf2_128_elt_t x) {
  return std::array<uint64_t, 2>{static_cast<uint64_t>(x[0]),
                                 static_cast<uint64_t>(x[1])};
}

static inline gf2_128_elt_t gf2_128_of_uint64x2(
    const std::array<uint64_t, 2>& x) {
  return gf2_128_elt_t{static_cast<poly64_t>(x[0]),
                       static_cast<poly64_t>(x[1])};
}

static inline gf2_128_elt_t gf2_128_add(gf2_128_elt_t x, gf2_128_elt_t y) {
  return vaddq_p64(x, y);
}

// Emulate vmull_p64() with vmull_p8().
//
// This emulation is pretty naive and it performs a lot of permutations.
//
// A possibly better alternative appears in Danilo Câmara, Conrado
// Gouvêa, Julio López, Ricardo Dahab, "Fast Software Polynomial
// Multiplication on ARM Processors Using the NEON Engine", 1st
// Cross-Domain Conference and Workshop on Availability, Reliability,
// and Security in Information Systems (CD-ARES), Sep 2013,
// Regensburg, Germany. pp.137-154. ⟨hal-01506572⟩
//
// However, the code from that paper makes heavy use of type
// punning of 128-bit registers as two 64-bit registers, which
// I don't know how to express in C.
static inline poly8x16_t pmul64x8(poly8x8_t x, poly8_t y) {
  const poly8x16_t zero{};
  poly8x16_t prod = vmull_p8(x, vdup_n_p8(y));
  poly8x16x2_t uzp = vuzpq_p8(prod, zero);
  return vaddq_p8(uzp.val[0], vextq_p8(uzp.val[1], uzp.val[1], 15));
}

// multiply/add.  Return (cout, s) = cin + x * y where the final sum
// would be (cout << 8) + s.
static inline poly8x16x2_t pmac64x8(poly8x16_t cin, poly8x8_t x, poly8_t y) {
  const poly8x16_t zero{};
  poly8x16_t prod = vmull_p8(x, vdup_n_p8(y));
  poly8x16x2_t uzp = vuzpq_p8(prod, zero);
  uzp.val[0] = vaddq_p8(uzp.val[0], cin);
  return uzp;
}

static inline poly8x16_t pmul64x64(poly8x8_t x, poly8x8_t y) {
  poly8x16_t r{};

  poly8x16x2_t prod = pmac64x8(r, x, y[0]);
  r = prod.val[0];

  prod = pmac64x8(prod.val[1], x, y[1]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 15));

  prod = pmac64x8(prod.val[1], x, y[2]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 14));

  prod = pmac64x8(prod.val[1], x, y[3]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 13));

  prod = pmac64x8(prod.val[1], x, y[4]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 12));

  prod = pmac64x8(prod.val[1], x, y[5]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 11));

  prod = pmac64x8(prod.val[1], x, y[6]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 10));

  prod = pmac64x8(prod.val[1], x, y[7]);
  r = vaddq_p8(r, vextq_p8(prod.val[0], prod.val[0], 9));
  r = vaddq_p8(r, vextq_p8(prod.val[1], prod.val[1], 8));

  return r;
}

static inline gf2_128_elt_t vmull_low(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  // vreinterpretq_p64_p8() seems not to be defined, use
  // static_cast<poly64x2_t>
  return static_cast<poly64x2_t>(pmul64x64(vget_low_p8(t0), vget_low_p8(t1)));
}
static inline gf2_128_elt_t vmull_high(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  return static_cast<poly64x2_t>(pmul64x64(vget_high_p8(t0), vget_high_p8(t1)));
}

// vextq_p64() seems not to be defined.
static inline gf2_128_elt_t vextq_p64_1_emul(gf2_128_elt_t t0,
                                             gf2_128_elt_t t1) {
  return static_cast<poly64x2_t>(
      vextq_p8(static_cast<poly8x16_t>(t0), static_cast<poly8x16_t>(t1), 8));
}

// return t0 + x^64 * t1
static inline gf2_128_elt_t gf2_128_reduce(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  const poly8_t poly = static_cast<poly8_t>(0x87);
  const gf2_128_elt_t zero = {0x0, 0x0};
  t0 = vaddq_p64(t0, vextq_p64_1_emul(zero, t1));
  t0 = vaddq_p64(t0, pmul64x8(vget_high_p8(t1), poly));
  return t0;
}

static inline gf2_128_elt_t gf2_128_mul(gf2_128_elt_t x, gf2_128_elt_t y) {
  gf2_128_elt_t swx = vextq_p64_1_emul(x, x);
  gf2_128_elt_t t1a = vmull_high(swx, y);
  gf2_128_elt_t t1b = vmull_low(swx, y);
  gf2_128_elt_t t1 = vaddq_p64(t1a, t1b);
  gf2_128_elt_t t2 = vmull_high(x, y);
  t1 = gf2_128_reduce(t1, t2);
  gf2_128_elt_t t0 = vmull_low(x, y);
  t0 = gf2_128_reduce(t0, t1);
  return t0;
}

}  // namespace proofs
#else

// Generic implementation assuming a 64x64->64 integer multiplier.
struct gf2_128_elt_t {
  uint64_t l[2];
};

static inline std::array<uint64_t, 2> uint64x2_of_gf2_128(gf2_128_elt_t x) {
  return std::array<uint64_t, 2>{x.l[0], x.l[1]};
}

static inline gf2_128_elt_t gf2_128_of_uint64x2(
    const std::array<uint64_t, 2>& x) {
  return gf2_128_elt_t{x[0], x[1]};
}

static inline gf2_128_elt_t gf2_128_add(gf2_128_elt_t x, gf2_128_elt_t y) {
  return gf2_128_elt_t{x.l[0] ^ y.l[0], x.l[1] ^ y.l[1]};
}

// 64x64->64 bit GF(2)[X] multiplication via Kronecker
// substitution.  Modeled after the Highway library
// https://github.com/google/highway/blob/master/hwy/ops/generic_ops-inl.h
// and the ghash implementation in BearSSL.
static inline uint64_t clmul64_lo(uint64_t x, uint64_t y) {
  uint64_t m0 = 0x1111111111111111ull, m1 = 0x2222222222222222ull,
           m2 = 0x4444444444444444ull, m3 = 0x8888888888888888ull;
  uint64_t x0 = x & m0, x1 = x & m1, x2 = x & m2, x3 = x & m3;
  uint64_t y0 = y & m0, y1 = y & m1, y2 = y & m2, y3 = y & m3;
  uint64_t z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
  uint64_t z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
  uint64_t z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
  uint64_t z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
  return (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3);
}

static inline uint64_t bitrev64(uint64_t n) {
  n = ((n >> 1) & 0x5555555555555555ull) | ((n & 0x5555555555555555ull) << 1);
  n = ((n >> 2) & 0x3333333333333333ull) | ((n & 0x3333333333333333ull) << 2);
  n = ((n >> 4) & 0x0f0f0f0f0f0f0f0full) | ((n & 0x0f0f0f0f0f0f0f0full) << 4);
  n = ((n >> 8) & 0x00ff00ff00ff00ffull) | ((n & 0x00ff00ff00ff00ffull) << 8);
  n = ((n >> 16) & 0x0000ffff0000ffffull) | ((n & 0x0000ffff0000ffffull) << 16);
  return (n << 32) | (n >> 32);
}

static inline uint64_t clmul64_hi(uint64_t x, uint64_t y) {
  return bitrev64(clmul64_lo(bitrev64(x), bitrev64(y))) >> 1;
}

// 64x64 -> 128
static inline gf2_128_elt_t clmul64(uint64_t x, uint64_t y) {
  return gf2_128_elt_t{clmul64_lo(x, y), clmul64_hi(x, y)};
}

// return (t0 + x^64 * t1)
static inline gf2_128_elt_t gf2_128_reduce(gf2_128_elt_t t0, gf2_128_elt_t t1) {
  uint64_t a = t1.l[1];
  t0.l[0] ^= a;
  t0.l[0] ^= a << 1;
  t0.l[1] ^= a >> 63;
  t0.l[0] ^= a << 2;
  t0.l[1] ^= a >> 62;
  t0.l[0] ^= a << 7;
  t0.l[1] ^= a >> 57;
  t0.l[1] ^= t1.l[0];
  return t0;
}
static inline gf2_128_elt_t gf2_128_mul(gf2_128_elt_t x, gf2_128_elt_t y) {
  // karatsuba
  gf2_128_elt_t t0 = clmul64(x.l[0], y.l[0]);
  gf2_128_elt_t t2 = clmul64(x.l[1], y.l[1]);
  gf2_128_elt_t t1 = clmul64(x.l[0] ^ x.l[1], y.l[0] ^ y.l[1]);
  t1 = gf2_128_add(t1, gf2_128_add(t0, t2));
  t1 = gf2_128_reduce(t1, t2);
  t0 = gf2_128_reduce(t0, t1);
  return t0;
}

#endif

#endif  // PRIVACY_PROOFS_ZK_LIB_GF2K_SYSDEP_H_
