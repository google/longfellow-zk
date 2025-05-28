// Copyright 2024 Google LLC.
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
    const std::array<uint64_t, 2> &x) {
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
    const std::array<uint64_t, 2> &x) {
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
#elif defined(__wasm_simd128__) // defined(__wasi__) || (defined(__wasm__) || defined(__EMSCRIPTEN__))
#include <cstdint>
#include <wasm_simd128.h>
namespace proofs {
using gf2_128_elt_t = v128_t;
// trivial identity operations to provide the same function signatures
static inline std::array<uint64_t, 2> uint64x2_of_gf2_128(gf2_128_elt_t x) {
  std::array<uint64_t, 2> result;
  wasm_v128_store(result.data(), x);
  return result;
}
static inline gf2_128_elt_t gf2_128_of_uint64x2(const std::array<uint64_t, 2>& x) {
  return wasm_v128_load(x.data());
}
static inline gf2_128_elt_t gf2_128_add(gf2_128_elt_t x, gf2_128_elt_t y) {
  return wasm_v128_xor(x, y);
}
  static inline gf2_128_elt_t gf2_128_mul(gf2_128_elt_t x, gf2_128_elt_t y) {
    const v128_t poly = wasm_i64x2_splat(0x87);
    // split into 32-bit halves for 32x32->64 multiplication
    v128_t x_lo = wasm_u32x4_shr(x, 0);    // x0_lo, x1_lo, x2_lo, x3_lo
    v128_t x_hi = wasm_u32x4_shr(x, 32);   // x0_hi, x1_hi, x2_hi, x3_hi
    v128_t y_lo = wasm_u32x4_shr(y, 0);    // y0_lo, y1_lo, y2_lo, y3_lo
    v128_t y_hi = wasm_u32x4_shr(y, 32);   // y0_hi, y1_hi, y2_hi, y3_hi
    // compute partial products (32x32->64)
    v128_t t0 = wasm_i64x2_mul(x_lo, y_lo);
    v128_t t1a = wasm_i64x2_mul(x_lo, y_hi);
    v128_t t1b = wasm_i64x2_mul(x_hi, y_lo);
    v128_t t2 = wasm_i64x2_mul(x_hi, y_hi);
    // combine middle terms (t1a + t1b)
    v128_t t1 = wasm_v128_xor(t1a, t1b);
    // reduction modulo x^128 + x^7 + x^2 + x + 1 (0x87)
    v128_t shifted = wasm_i64x2_shl(t1, 32);
    v128_t reduced = wasm_i64x2_shr(t1, 63);  // Mask for reduction
    reduced = wasm_v128_and(reduced, poly);
    return wasm_v128_xor(t0, wasm_v128_xor(shifted, reduced));
  }
}  // namespace proofs
#else
#error "unimplemented gf2k/sysdep.h"
#endif

#endif  // PRIVACY_PROOFS_ZK_LIB_GF2K_SYSDEP_H_
