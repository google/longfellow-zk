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

#include "circuits/logic/logic.h"

#include <stddef.h>

#include <cstdint>
#include <vector>

#include "algebra/fp.h"
#include "circuits/logic/evaluation_backend.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp<1>;
const Field F("18446744073709551557");
using EvaluationBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvaluationBackend>;
using EltW = Logic::EltW;

template <size_t N>
void expect_vequal(const Logic& L, const Logic::bitvec<N>& a,
                   const Logic::bitvec<N>& b) {
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(L.eval(a[i]), L.eval(b[i]));
  }
}

TEST(Logic, Assert0) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  EXPECT_DEATH(L.assert0(L.konst(1)), "a != F.zero()");
}

TEST(Logic, Simple) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  EXPECT_NE(L.eval(L.bit(0)), L.eval(L.bit(1)));
  for (size_t a = 0; a < 2; ++a) {
    auto ea = L.bit(a);
    EXPECT_EQ(L.eval(L.lnot(ea)), L.eval(L.bit(!a)));
    for (size_t b = 0; b < 2; ++b) {
      auto eb = L.bit(b);
      EXPECT_EQ(L.eval(L.land(&ea, eb)), L.eval(L.bit(a & b)));
      EXPECT_EQ(L.eval(L.land(&ea, L.lnot(eb))), L.eval(L.bit(a & (!b))));
      EXPECT_EQ(L.eval(L.land(&eb, L.lnot(ea))), L.eval(L.bit((!a) & b)));
      auto nea = L.lnot(ea);
      EXPECT_EQ(L.eval(L.land(&nea, L.lnot(eb))), L.eval(L.bit((!a) & (!b))));

      EXPECT_EQ(L.eval(L.lor(&ea, eb)), L.eval(L.bit(a | b)));
      EXPECT_EQ(L.eval(L.lor(&ea, L.lnot(eb))), L.eval(L.bit(a | (!b))));
      EXPECT_EQ(L.eval(L.lor(&eb, L.lnot(ea))), L.eval(L.bit((!a) | b)));
      auto na = L.lnot(ea);
      EXPECT_EQ(L.eval(L.lor(&na, L.lnot(eb))), L.eval(L.bit((!a) | (!b))));

      EXPECT_EQ(L.eval(L.lxor(&ea, eb)), L.eval(L.bit(a ^ b)));
      EXPECT_EQ(L.eval(L.lxor(&ea, L.lnot(eb))), L.eval(L.bit(a ^ (!b))));
      EXPECT_EQ(L.eval(L.lxor(&eb, L.lnot(ea))), L.eval(L.bit((!a) ^ b)));
      EXPECT_EQ(L.eval(L.lxor(&na, L.lnot(eb))), L.eval(L.bit((!a) ^ (!b))));

      if (!(a & b)) {
        EXPECT_EQ(L.eval(L.lor_exclusive(&ea, eb)), L.eval(L.bit(a | b)));
      }

      auto axb = L.bit(a ^ b);
      L.assert_eq(&axb, L.lxor(&ea, eb));

      for (size_t c = 0; c < 2; ++c) {
        auto ec = L.bit(c);
        EXPECT_EQ(L.eval(L.lxor3(&ea, &eb, ec)), L.eval(L.bit(a ^ b ^ c)));
        EXPECT_EQ(L.eval(L.land(&ea, L.lxor(&eb, ec))),
                  L.eval(L.bit(a & (b ^ c))));
        EXPECT_EQ(L.eval(L.land(&ea, L.lor(&eb, ec))),
                  L.eval(L.bit(a & (b | c))));
        EXPECT_EQ(L.eval(L.lor(&ea, L.land(&eb, ec))),
                  L.eval(L.bit(a | (b & c))));
        EXPECT_EQ(L.eval(L.lor(&ea, L.lxor(&eb, ec))),
                  L.eval(L.bit(a | (b ^ c))));
        EXPECT_EQ(L.eval(L.lxor(&ea, L.land(&eb, ec))),
                  L.eval(L.bit(a ^ (b & c))));
        EXPECT_EQ(L.eval(L.lxor(&ea, L.lor(&eb, ec))),
                  L.eval(L.bit(a ^ (b | c))));
        EXPECT_EQ(L.eval(L.mux(&ea, &eb, ec)), L.eval(L.bit(a ? b : c)));

        EXPECT_EQ(L.eval(L.lCh(&ea, &eb, ec)),
                  L.eval(L.bit((a & b) ^ ((!a) & c))));
        EXPECT_EQ(L.eval(L.lMaj(&ea, &eb, ec)),
                  L.eval(L.bit((a & b) ^ (a & c) ^ (b & c))));
      }
    }
  }
}

TEST(Logic, Scan) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  static constexpr size_t maxw = 16;
  Logic::BitW x[maxw], ya[maxw], yo[maxw], yx[maxw];
  for (size_t w = 1; w <= maxw; ++w) {
    for (size_t a = 0; a < (1 << w); ++a) {
      for (size_t i = 0; i < w; ++i) {
        x[i] = L.bit((a >> i) & 1);
      }

      {
        // Forward:
        for (size_t i = 0; i < w; ++i) {
          ya[i] = yo[i] = yx[i] = x[i];
        }
        L.scan_and(ya, 0, w);
        L.scan_or(yo, 0, w);
        L.scan_xor(yx, 0, w);
        auto za = L.bit(1);
        auto zo = L.bit(0);
        auto zx = L.bit(0);
        for (size_t i = 0; i < w; ++i) {
          za = L.land(&za, x[i]);
          EXPECT_EQ(L.eval(za), L.eval(ya[i]));
          zo = L.lor(&zo, x[i]);
          EXPECT_EQ(L.eval(zo), L.eval(yo[i]));
          zx = L.lxor(&zx, x[i]);
          EXPECT_EQ(L.eval(zx), L.eval(yx[i]));
        }
      }

      {
        // Backward:
        for (size_t i = 0; i < w; ++i) {
          ya[i] = yo[i] = yx[i] = x[i];
        }
        L.scan_and(ya, 0, w, /*backward=*/true);
        L.scan_or(yo, 0, w, /*backward=*/true);
        L.scan_xor(yx, 0, w, /*backward=*/true);
        auto za = L.bit(1);
        auto zo = L.bit(0);
        auto zx = L.bit(0);
        for (size_t i = w; i-- > 0;) {
          za = L.land(&za, x[i]);
          EXPECT_EQ(L.eval(za), L.eval(ya[i]));
          zo = L.lor(&zo, x[i]);
          EXPECT_EQ(L.eval(zo), L.eval(yo[i]));
          zx = L.lxor(&zx, x[i]);
          EXPECT_EQ(L.eval(zx), L.eval(yx[i]));
        }
      }
    }
  }
}

TEST(Logic, AddSub) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  static constexpr size_t w = 7;

  for (size_t kind = 0; kind < 4; ++kind) {
    for (size_t a = 0; a < (1 << w); ++a) {
      for (size_t b = 0; b < (1 << w); ++b) {
        Logic::BitW ea[w], eb[w], ec[w];
        for (size_t i = 0; i < w; ++i) {
          ea[i] = L.bit((a >> i) & 1);
          eb[i] = L.bit((b >> i) & 1);
        }
        Logic::BitW ecarry;
        size_t c;
        switch (kind) {
          case 0:
            ecarry = L.ripple_carry_add(w, ec, ea, eb);
            c = a + b;
            break;
          case 1:
            ecarry = L.ripple_carry_sub(w, ec, ea, eb);
            c = a - b;
            break;
          case 2:
            ecarry = L.parallel_prefix_add(w, ec, ea, eb);
            c = a + b;
            break;
          case 3:
            ecarry = L.parallel_prefix_sub(w, ec, ea, eb);
            c = a - b;
            break;
        }

        for (size_t i = 0; i < w; ++i) {
          EXPECT_EQ(L.eval(ec[i]), L.eval(L.bit((c >> i) & 1)));
        }
        EXPECT_EQ(L.eval(ecarry), L.eval(L.bit((c >> w) & 1)));
      }
    }
  }
}

TEST(Logic, Comparison) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  static constexpr size_t w = 9;

  for (size_t a = 0; a < (1 << w); ++a) {
    for (size_t b = 0; b < (1 << w); ++b) {
      Logic::BitW ea[w], eb[w];
      for (size_t i = 0; i < w; ++i) {
        ea[i] = L.bit((a >> i) & 1);
        eb[i] = L.bit((b >> i) & 1);
      }
      EXPECT_EQ(L.eval(L.eq(w, ea, eb)), L.eval(L.bit(a == b)));
      EXPECT_EQ(L.eval(L.lt(w, ea, eb)), L.eval(L.bit(a < b)));
      EXPECT_EQ(L.eval(L.leq(w, ea, eb)), L.eval(L.bit(a <= b)));

      // Corner cases
      EXPECT_EQ(L.eval(L.lt(0, ea, eb)), L.konst(0));
      EXPECT_EQ(L.eval(L.eq(0, ea, eb)), L.konst(1));
    }
  }
}

TEST(Logic, Multiplier) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  static constexpr size_t w = 7;

  for (size_t a = 0; a < (1 << w); ++a) {
    for (size_t b = 0; b < (1 << w); ++b) {
      Logic::BitW ea[w], eb[w], ec[2 * w];
      for (size_t i = 0; i < w; ++i) {
        ea[i] = L.bit((a >> i) & 1);
        eb[i] = L.bit((b >> i) & 1);
      }

      L.multiplier(w, ec, ea, eb);
      size_t c = a * b;
      for (size_t i = 0; i < 2 * w; ++i) {
        EXPECT_EQ(L.eval(ec[i]), L.eval(L.bit((c >> i) & 1)));
      }
    }
  }
}

TEST(Logic, AssertSum) {
  static constexpr size_t w = 5;
  const size_t mask = (1 << w) - 1;

  for (size_t a = 0; a < (1 << w); ++a) {
    for (size_t b = 0; b < (1 << w); ++b) {
      for (size_t c = 0; c < (1 << w); ++c) {
        const EvaluationBackend ebk(F, /* panic_on_assertion_failure=*/false);
        const Logic L(&ebk, F);
        Logic::BitW ea[w], eb[w], ec[w];
        for (size_t i = 0; i < w; ++i) {
          ea[i] = L.bit((a >> i) & 1);
          eb[i] = L.bit((b >> i) & 1);
          ec[i] = L.bit((c >> i) & 1);
        }

        L.assert_sum(w, ec, ea, eb);
        EXPECT_EQ(ebk.assertion_failed(), (((a + b) ^ c) & mask) != 0);
      }
    }
  }
}

TEST(Logic, GF2PolynomialMultiplier) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  static constexpr size_t w = 10;

  for (size_t a = 0; a < (1 << w); ++a) {
    for (size_t b = 0; b < (1 << w); ++b) {
      Logic::BitW ea[w], eb[w], ec[2 * w], ec2[2 * w];
      for (size_t i = 0; i < w; ++i) {
        ea[i] = L.bit((a >> i) & 1);
        eb[i] = L.bit((b >> i) & 1);
      }

      L.gf2_polynomial_multiplier(w, ec, ea, eb);
      L.gf2_polynomial_multiplier_karat(w, ec2, ea, eb);
      size_t c = 0;
      for (size_t i = 0; i < w; ++i) {
        if ((a >> i) & 1) {
          c ^= (b << i);
        }
      }

      for (size_t i = 0; i < 2 * w; ++i) {
        EXPECT_EQ(L.eval(ec[i]), L.eval(L.bit((c >> i) & 1)));
        EXPECT_EQ(L.eval(ec2[i]), L.eval(L.bit((c >> i) & 1)));
      }
    }
  }
}

// Creates an array representation of a polynomial in GF2^k from a list
// of its non-zero terms.
void gf2_init(size_t w, Logic::BitW a[], std::vector<uint16_t> aa) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  for (size_t j = 0; j < w; ++j) {
    a[j] = L.bit(0);
  }
  for (auto ai : aa) {
    a[ai] = L.bit(1);
  }
}

struct gf2_testvec {
  std::vector<uint16_t> a, b, c;
};

TEST(Logic, GF2_128Multiplier) {
  // These polynomials are represented in sparse form by the non-zero indices.
  // For example {0,2} represents "x^2 + 1".
  // This test cases are generated using the following sage script:
  //
  // F2 = FiniteField(2)['x']
  // x = F2.gen()
  // p128 = (x^128 + x^7 + x^2 + x + 1)
  // F128.<a> = GF(2^128, modulus=p128)
  // def gf2_str(x):
  //     return '{' +
  //        ','.join([str(i) for (i,v) in enumerate(x.polynomial().list())
  //                  if v == 1]) + '}'
  // def make_tests(F):
  //     a = F.random_element()
  //     b = F.random_element()
  //     c = a * b
  //     print(gf2_str(a),',', gf2_str(b),',', gf2_str(c))
  //
  const struct gf2_testvec TESTS[] = {
      {{0}, {0}, {0}},
      {{1}, {1}, {2}},
      {
          {0,  2,  4,  5,   7,   8,   9,   10,  11,  13,  15,  17, 18,
           19, 20, 22, 23,  25,  28,  30,  33,  34,  38,  39,  42, 44,
           45, 46, 49, 53,  56,  61,  64,  65,  66,  69,  70,  71, 77,
           78, 79, 80, 81,  82,  83,  84,  85,  86,  90,  91,  93, 96,
           97, 98, 99, 103, 105, 110, 113, 116, 117, 125, 126, 127},
          {0,   1,   2,   5,   9,   10,  11,  12,  14,  15,  17,  18,  19,
           21,  22,  25,  27,  28,  30,  32,  33,  34,  35,  39,  40,  41,
           42,  45,  50,  52,  54,  60,  64,  66,  67,  68,  69,  70,  71,
           76,  79,  83,  85,  87,  88,  89,  97,  98,  99,  102, 105, 107,
           109, 110, 111, 112, 114, 115, 116, 118, 121, 122, 124, 126},
          {0,   1,   3,   5,   6,   7,   10,  12,  13,  15,  16,  17,  18,  19,
           20,  21,  22,  23,  28,  29,  31,  32,  33,  36,  38,  41,  50,  51,
           53,  54,  55,  57,  58,  59,  60,  61,  63,  64,  66,  68,  69,  71,
           76,  77,  78,  81,  82,  83,  86,  88,  90,  94,  96,  98,  101, 104,
           105, 108, 109, 111, 112, 116, 118, 119, 120, 121, 122, 125, 126},
      },
      {{1,   5,   8,   10,  12,  13,  15,  16,  19,  21,  23,  24,
        25,  26,  27,  30,  32,  33,  34,  40,  42,  43,  47,  48,
        51,  52,  56,  57,  59,  62,  64,  67,  68,  71,  72,  74,
        76,  77,  78,  79,  80,  85,  87,  88,  89,  92,  93,  94,
        95,  97,  98,  101, 102, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 117, 120, 121, 123, 124, 125, 127},
       {1,   4,   8,   9,   10,  16,  17,  21,  24,  25,  28,  29,  31,  33,
        35,  36,  39,  40,  41,  44,  45,  46,  48,  49,  50,  54,  55,  56,
        57,  59,  61,  62,  64,  65,  66,  67,  68,  69,  71,  72,  73,  75,
        78,  79,  80,  83,  87,  92,  95,  96,  97,  98,  104, 105, 106, 107,
        108, 109, 111, 113, 114, 117, 119, 120, 122, 123, 124, 125},
       {0,   1,   5,   6,   9,   11,  12,  16,  18,  21,  22,  23,  24,
        25,  26,  27,  29,  32,  33,  34,  35,  36,  37,  43,  44,  45,
        49,  50,  52,  53,  54,  56,  57,  59,  60,  61,  62,  63,  65,
        67,  68,  69,  70,  72,  75,  79,  81,  82,  84,  87,  89,  91,
        94,  95,  96,  97,  99,  100, 101, 103, 105, 106, 109, 111, 112,
        113, 114, 117, 118, 119, 120, 125, 126, 127}},
      {{5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  18,  19, 22,
        25,  26,  28,  29,  33,  34,  37,  38,  39,  41,  43,  44,  45, 46,
        48,  49,  50,  53,  54,  55,  56,  57,  58,  60,  62,  64,  65, 68,
        69,  70,  73,  76,  78,  80,  83,  84,  85,  86,  88,  90,  91, 94,
        100, 101, 103, 104, 105, 106, 110, 113, 115, 119, 124, 125, 127},
       {0,   11,  12,  14,  15,  18,  20,  22,  23,  29,  31,  34,  35,
        39,  43,  45,  47,  48,  49,  51,  52,  54,  59,  60,  62,  66,
        67,  68,  70,  71,  72,  73,  74,  75,  76,  77,  79,  80,  85,
        89,  90,  92,  93,  95,  96,  97,  99,  101, 102, 104, 105, 107,
        109, 110, 111, 112, 115, 116, 118, 119, 123, 124, 125},
       {2,   4,   6,   11,  12,  13,  15,  18,  19,  20,  21,  23,  24,  25,
        26,  30,  31,  33,  34,  35,  36,  39,  40,  44,  47,  48,  51,  52,
        53,  57,  58,  59,  60,  64,  65,  67,  69,  71,  74,  76,  78,  79,
        80,  81,  87,  88,  89,  92,  93,  94,  99,  100, 101, 109, 110, 113,
        114, 115, 116, 117, 119, 120, 121, 122, 125, 126}},
      {{0,   1,   2,   6,   7,   8,   10,  14,  15,  16,  18,  19, 21, 25, 27,
        28,  29,  30,  40,  44,  45,  52,  56,  57,  58,  59,  60, 62, 63, 66,
        67,  70,  71,  72,  73,  74,  77,  78,  86,  91,  92,  93, 96, 97, 98,
        102, 103, 105, 107, 108, 109, 115, 116, 121, 122, 125, 126},
       {0,   1,   3,   4,   5,   6,   9,   10,  15,  16,  18,  19,  21,
        22,  24,  25,  28,  29,  33,  34,  36,  40,  41,  43,  45,  46,
        50,  51,  53,  54,  56,  59,  60,  62,  63,  67,  70,  71,  72,
        73,  77,  78,  79,  81,  82,  83,  84,  85,  87,  90,  92,  94,
        96,  98,  99,  100, 101, 102, 103, 105, 107, 108, 109, 110, 111,
        112, 114, 116, 117, 118, 120, 121, 122},
       {0,   1,   3,   5,   6,   7,   8,   11,  12,  14,  15,  17,  18,  19,
        20,  22,  26,  27,  28,  33,  34,  35,  43,  45,  47,  50,  51,  53,
        54,  56,  58,  61,  65,  66,  71,  76,  77,  78,  79,  85,  86,  87,
        90,  91,  92,  95,  97,  98,  99,  101, 103, 105, 106, 109, 110, 111,
        112, 115, 116, 118, 119, 120, 123, 124, 125, 126, 127}},
      {{0,   1,   2,   5,   6,   8,   10,  14,  16,  19,  20,  21,  25,  26,
        28,  29,  31,  32,  36,  37,  40,  41,  42,  43,  45,  47,  49,  50,
        51,  52,  53,  55,  59,  60,  61,  63,  65,  66,  68,  69,  74,  75,
        76,  77,  79,  80,  81,  82,  84,  87,  91,  92,  94,  96,  99,  100,
        101, 102, 103, 104, 108, 110, 112, 114, 115, 116, 117, 120, 121, 127},
       {0,   1,   2,   4,   7,   9,   12,  15,  19,  22,  25,  26,
        29,  30,  32,  34,  35,  37,  39,  41,  42,  43,  46,  50,
        54,  58,  59,  65,  68,  69,  71,  73,  75,  76,  79,  80,
        82,  83,  84,  88,  90,  92,  95,  98,  99,  100, 102, 103,
        104, 105, 106, 109, 110, 112, 113, 115, 117, 120, 123, 125},
       {2,   5,   6,   7,   13,  16,  17,  19,  21,  22, 23,  24,  26,
        28,  29,  34,  35,  37,  40,  41,  45,  46,  47, 48,  49,  54,
        57,  58,  61,  63,  65,  67,  68,  71,  73,  74, 75,  76,  77,
        80,  82,  85,  86,  87,  91,  92,  93,  96,  97, 100, 104, 105,
        107, 109, 111, 112, 113, 117, 118, 120, 122, 125}},
      {{5,   6,   7,   8,   9,   11,  12,  13,  17,  19,  20,  25, 28, 29,
        30,  39,  40,  41,  42,  47,  48,  49,  51,  52,  54,  61, 63, 68,
        70,  71,  73,  75,  76,  77,  80,  81,  82,  88,  89,  90, 91, 98,
        100, 101, 104, 105, 106, 111, 114, 116, 119, 122, 124, 127},
       {4,  6,  7,  8,   9,   10,  12,  13,  14,  15,  17,  18,  19,
        20, 21, 23, 24,  26,  27,  28,  31,  32,  38,  40,  41,  43,
        44, 45, 47, 49,  51,  53,  59,  60,  61,  65,  66,  67,  69,
        72, 74, 75, 77,  78,  79,  80,  83,  85,  86,  89,  92,  94,
        95, 97, 99, 100, 103, 104, 105, 113, 120, 123, 124, 126, 127},
       {0,   3,   4,   5,   7,   8,   14,  15,  16,  17,  19,  23,  24,  25,
        26,  27,  28,  29,  33,  34,  38,  39,  41,  42,  43,  44,  45,  49,
        51,  52,  60,  61,  63,  64,  69,  70,  71,  73,  74,  75,  76,  77,
        80,  82,  87,  90,  91,  93,  94,  97,  98,  99,  100, 104, 105, 107,
        109, 114, 115, 116, 119, 120, 121, 122, 123, 124, 125, 126, 127}},
  };
  constexpr size_t w = 128;
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);

  for (size_t i = 0; i < sizeof(TESTS) / sizeof(TESTS[0]); ++i) {
    gf2_testvec test = TESTS[i];
    Logic::v128 ea, eb, want, got;
    gf2_init(w, ea.data(), test.a);
    gf2_init(w, eb.data(), test.b);
    gf2_init(w, want.data(), test.c);

    L.gf2_128_mul(got, ea, eb);
    L.vassert_eq(&got, want);
  }
}

TEST(Logic, Bitvec) {
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  constexpr size_t w = 7;

  for (size_t a = 0; a < (1 << w); ++a) {
    auto ea = L.vbit<w>(a);
    auto nea = L.vnot(ea);
    expect_vequal(L, nea, L.vbit<w>(~a));

    // as_scalar() of the bitvec produces the constant A
    // that we started with
    EXPECT_EQ(L.konst(a), L.as_scalar(ea));

    for (size_t b = 0; b < (1 << w); ++b) {
      auto eb = L.vbit<w>(b);
      auto vand = L.vand(&ea, eb);
      auto vor = L.vor(&ea, eb);
      auto vxor = L.vxor(&ea, eb);
      auto vadd = L.vadd(ea, eb);
      expect_vequal(L, vand, L.vbit<w>(a & b));
      expect_vequal(L, vor, L.vbit<w>(a | b));
      expect_vequal(L, vxor, L.vbit<w>(a ^ b));
      expect_vequal(L, vadd, L.vbit<w>(a + b));
      EXPECT_EQ(L.eval(L.veq(&ea, eb)), L.eval(L.bit(a == b)));
      EXPECT_EQ(L.eval(L.veq(ea, b)), L.eval(L.bit(a == b)));
      EXPECT_EQ(L.eval(L.vlt(&ea, eb)), L.eval(L.bit(a < b)));
      EXPECT_EQ(L.eval(L.vlt(ea, b)), L.eval(L.bit(a < b)));
      EXPECT_EQ(L.eval(L.vleq(&ea, eb)), L.eval(L.bit(a <= b)));
      EXPECT_EQ(L.eval(L.vleq(ea, b)), L.eval(L.bit(a <= b)));

      for (size_t c = 0; c < (1 << w); ++c) {
        auto ec = L.vbit<w>(c);
        auto vxor3 = L.vxor3(&ea, &eb, ec);
        auto vch = L.vCh(&ea, &eb, ec);
        auto vmaj = L.vMaj(&ea, &eb, ec);
        expect_vequal(L, vxor3, L.vbit<w>(a ^ b ^ c));
        expect_vequal(L, vch, L.vbit<w>((a & b) ^ (~a & c)));
        expect_vequal(L, vmaj, L.vbit<w>((a & b) ^ (a & c) ^ (b & c)));
        EXPECT_EQ(L.eval(L.veqmask(&ea, b, ec)),
                  L.eval(L.bit(((a ^ c) & b) == 0)));
        EXPECT_EQ(L.eval(L.veqmask(ea, b, c)),
                  L.eval(L.bit(((a ^ c) & b) == 0)));
      }
    }

    for (size_t b = 0; b <= w; ++b) {
      auto vshr = L.vshr(ea, b);
      expect_vequal(L, vshr, L.vbit<w>(a >> b));
      auto vrotr = L.vrotr(ea, b);
      expect_vequal(L, vrotr, L.vbit<w>((a >> b) | (a << (w - b))));
      auto vrotl = L.vrotl(ea, b);
      expect_vequal(L, vrotl, L.vbit<w>((a << b) | (a >> (w - b))));
    }
  }

  // Corner cases of length
  auto ea = L.vbit<w>(9);
  auto lambda_ea = [&](size_t i) { return ea[i]; };
  auto lambda_eval_ea = [&](size_t i) { return L.eval(ea[i]); };
  EXPECT_EQ(L.eval(L.lor(1, 0, lambda_ea)), L.konst(0));
  EXPECT_EQ(L.eval(L.lor_exclusive(1, 0, lambda_ea)), L.konst(0));
  EXPECT_EQ(L.eval(L.land(1, 0, lambda_ea)), L.konst(1));
  EXPECT_EQ(L.mul(1, 0, lambda_eval_ea), L.konst(1));
  EXPECT_EQ(L.add(1, 0, lambda_eval_ea), L.konst(0));
}
}  // namespace
}  // namespace proofs
