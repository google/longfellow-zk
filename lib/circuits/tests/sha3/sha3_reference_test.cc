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

#include "circuits/tests/sha3/sha3_reference.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "circuits/tests/sha3/shake_test_vectors.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
TEST(Sha3Reference, TestVec) {
  constexpr size_t mdlen = 32;
  struct testvec {
    const char* str;
    uint8_t hash[mdlen];
  };

  static const struct testvec tv[] = {
      {"",
       {
           0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47,
           0x56, 0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b,
           0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
       }},
      {"abc",
       {
           0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17,
           0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d,
           0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
       }},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       {
           0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08, 0x49, 0x10, 0x03,
           0x76, 0xa8, 0x23, 0x5e, 0x2c, 0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99,
           0x9e, 0x21, 0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76,
       }},

      // test the block boundary length
      {
          // len=134
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdab",
          {
              0x64, 0x17, 0x63, 0x24, 0xb8, 0x40, 0x94, 0x6a, 0x39, 0x68, 0xb2,
              0xbc, 0x0f, 0x0d, 0x46, 0xc0, 0x41, 0x5f, 0x2d, 0x4a, 0xa4, 0x72,
              0xd9, 0xe1, 0xa6, 0x76, 0x3a, 0xca, 0x2a, 0x16, 0x04, 0xca,
          },
      },
      {
          // len=135
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc",
          {
              0x14, 0xc6, 0xa7, 0x8b, 0x26, 0x5b, 0xa3, 0x05, 0x07, 0x27, 0x82,
              0x89, 0xf2, 0x17, 0x64, 0x28, 0x4a, 0x3a, 0x6f, 0x46, 0x8d, 0x97,
              0x90, 0x06, 0xdd, 0x02, 0x11, 0x9f, 0x89, 0xb2, 0x15, 0x68,
          },
      },
      {
          // len=136
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"
          "d",
          {
              0x7b, 0xcb, 0x7e, 0x15, 0xce, 0x26, 0x90, 0x46, 0xeb, 0xa7, 0x84,
              0x98, 0x8e, 0x07, 0xc5, 0x73, 0xde, 0x14, 0xdf, 0x4c, 0x91, 0xf8,
              0xb2, 0x15, 0x37, 0x0e, 0x60, 0x34, 0xb1, 0x70, 0x32, 0x02,
          },
      },
      {
          // len=137
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
          "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
          "a",
          {
              0x47, 0xbb, 0x76, 0xa3, 0x53, 0x7a, 0x56, 0x48, 0x98, 0x89, 0xca,
              0xf3, 0x32, 0x92, 0x5e, 0xdb, 0xa7, 0x14, 0xb2, 0x1e, 0xf7, 0x24,
              0x1a, 0x1d, 0x59, 0x2a, 0x00, 0x3b, 0x96, 0x8b, 0x7a, 0xa0,
          },
      },
  };

  for (size_t i = 0; i < sizeof(tv) / sizeof(tv[0]); ++i) {
    Sha3Reference ctx(mdlen);
    uint8_t hash[mdlen];
    ctx.update(tv[i].str, strlen(tv[i].str));
    ctx.final(hash);
    for (size_t j = 0; j < mdlen; ++j) {
      EXPECT_EQ(hash[j], tv[i].hash[j]);
    }
  }
}

TEST(Sha3Reference, OneMillionAs) {
  constexpr size_t mdlen = 32;
  Sha3Reference ctx(mdlen);
  static const char* A = "aaaaaaaaaa";
  uint8_t hash[mdlen];
  for (size_t i = 0; i < 1000000 / 10; ++i) {
    ctx.update(A, 10);
  }
  ctx.final(hash);
  static const uint8_t expected[mdlen] = {
      0x5c, 0x88, 0x75, 0xae, 0x47, 0x4a, 0x36, 0x34, 0xba, 0x4f, 0xd5,
      0x5e, 0xc8, 0x5b, 0xff, 0xd6, 0x61, 0xf3, 0x2a, 0xca, 0x75, 0xc6,
      0xd6, 0x99, 0xd0, 0xcd, 0xcb, 0x6c, 0x11, 0x58, 0x91, 0xc1,
  };
  for (size_t j = 0; j < mdlen; ++j) {
    EXPECT_EQ(hash[j], expected[j]);
  }
}

TEST(Sha3Reference, Shake128Test) {
  for (const auto& vec : sha3::GetShake128TestVectors()) {
    std::vector<uint8_t> actual(vec.out.size());
    Sha3Reference::shake128Hash(vec.in.data(), vec.in.size(), actual.data(),
                                actual.size());

    for (size_t i = 0; i < vec.out.size(); ++i) {
      EXPECT_EQ(actual[i], vec.out[i]);
    }
  }
}

TEST(Sha3Reference, Shake256Test) {
  for (const auto& vec : sha3::GetShake256TestVectors()) {
    std::vector<uint8_t> actual(vec.out.size());
    Sha3Reference::shake256Hash(vec.in.data(), vec.in.size(), actual.data(),
                                actual.size());

    for (size_t i = 0; i < vec.out.size(); ++i) {
      EXPECT_EQ(actual[i], vec.out[i]);
    }
  }
}

// Known-vector check: keccak256("") and keccak256("abc").
// These differ from SHA3-256 only in the padding byte (0x01 vs 0x06).
TEST(Sha3Reference, Keccak256KnownVectors) {
  struct tv {
    const char* msg;
    uint8_t hash[32];
  };
  static const tv vecs[] = {
      // keccak256("") - used as the canonical Ethereum empty-input vector
      {"",
       {0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d,
        0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82,
        0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70}},
      // keccak256("abc")
      {"abc",
       {0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b,
        0xa8, 0x26, 0xc8, 0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64,
        0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45}},
  };
  for (const auto& v : vecs) {
    uint8_t out[32];
    Sha3Reference::keccak256Hash(reinterpret_cast<const uint8_t*>(v.msg),
                                 strlen(v.msg), out);
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(out[i], v.hash[i]) << "byte " << i << " for input \"" << v.msg
                                   << "\"";
    }
  }
}

// Sanity check: derive an Ethereum address from a known public key.
//
// Ethereum address derivation: keccak256(pubkey_x || pubkey_y)[12:32]
// i.e., the last 20 bytes of the 32-byte keccak256 digest.
//
// Public key (64 bytes, uncompressed, no 0x04 prefix):
//   2e308d25d27f4c595c4a7543253f3c23 50c9d323bcd50229c837681f08da6a33
//   b8ab238faecd9cf2a7359e6a69089710 876ab136ab017f88505c03516cc099c6
//
// Full keccak256 digest:
//   0c2be79367ba0c0b59460475b90d65a624909bc36eee6bffdecf3c5acd7774c0
//
// Ethereum address = digest[12..31]:
//   0xb90d65a624909bc36eee6bffdecf3c5acd7774c0
TEST(Sha3Reference, Keccak256EthereumAddress) {
  static const uint8_t pubkey[64] = {
      0x2e, 0x30, 0x8d, 0x25, 0xd2, 0x7f, 0x4c, 0x59, 0x5c, 0x4a, 0x75,
      0x43, 0x25, 0x3f, 0x3c, 0x23, 0x50, 0xc9, 0xd3, 0x23, 0xbc, 0xd5,
      0x02, 0x29, 0xc8, 0x37, 0x68, 0x1f, 0x08, 0xda, 0x6a, 0x33, 0xb8,
      0xab, 0x23, 0x8f, 0xae, 0xcd, 0x9c, 0xf2, 0xa7, 0x35, 0x9e, 0x6a,
      0x69, 0x08, 0x97, 0x10, 0x87, 0x6a, 0xb1, 0x36, 0xab, 0x01, 0x7f,
      0x88, 0x50, 0x5c, 0x03, 0x51, 0x6c, 0xc0, 0x99, 0xc6,
  };
  // Expected: last 20 bytes of keccak256(pubkey), i.e., digest[12..31].
  static const uint8_t expected_addr[20] = {
      0xb9, 0x0d, 0x65, 0xa6, 0x24, 0x90, 0x9b, 0xc3, 0x6e, 0xee,
      0x6b, 0xff, 0xde, 0xcf, 0x3c, 0x5a, 0xcd, 0x77, 0x74, 0xc0,
  };

  uint8_t hash[32];
  Sha3Reference::keccak256Hash(pubkey, sizeof(pubkey), hash);

  // Ethereum address = last 20 bytes of the 32-byte keccak256 digest.
  for (size_t i = 0; i < 20; ++i) {
    EXPECT_EQ(hash[12 + i], expected_addr[i])
        << "address byte " << i << " mismatch";
  }
}

}  // namespace
}  // namespace proofs
