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

#include "random/transcript.h"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "algebra/fp.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef Fp<4> Field;
static const Field F(
    "11579208923731619542357098500868790785326998466564056403945758400790883467"
    "1663");
typedef Field::Elt Elt;

TEST(Transcript, Write) {
  uint8_t buf1[4], buf2[4];

  Transcript ts1((uint8_t *)"test", 4);
  ts1.write(F.of_scalar(7), F);
  ts1.bytes(buf1, 4);

  Transcript ts2((uint8_t *)"test", 4);
  ts2.write(F.of_scalar(8), F);
  ts2.bytes(buf2, 4);

  EXPECT_NE(buf1, buf2);
}

TEST(Transcript, TwoBlocks) {
  // Generate two blocks and check that they are not the same.
  // Hardcoded 16 assumes AES PRF
  uint8_t a[16], b[16];
  Transcript ts((uint8_t *)"test", 4);
  ts.write(F.of_scalar(8), F);
  ts.bytes(a, 16);
  ts.bytes(b, 16);
  bool same = true;
  for (size_t i = 0; i < 16; ++i) {
    same &= (a[i] == b[i]);
  }
  EXPECT_FALSE(same);
}

TEST(Transcript, Associative) {
  constexpr size_t n = 100;
  uint8_t a[n], b[n];
  for (size_t i = 0; i < n; ++i) {
    Transcript ts((uint8_t *)"test", 4);
    ts.write(F.of_scalar(7), F);
    {
      Transcript ts1 = ts.clone();
      ts.bytes(a, i);
      ts.bytes(a + i, n - i);
    }
    {
      Transcript ts1 = ts.clone();
      ts1.bytes(b, n);
    }
    for (size_t j = 0; j < n; ++j) {
      EXPECT_EQ(a[i], b[i]);
    }
  }
}

void dump_elt(Elt elt) {
  uint8_t buf[Field::kBytes];
  F.to_bytes_field(buf, elt);
  for (size_t i = 0; i < Field::kBytes; i++) {
    printf("%02x", buf[i]);
  }
  printf(",\n");
}

TEST(Transcript, GenArrayChallenge) {
  Transcript ts((uint8_t *)"test", 4);
  // write a byte array
  uint8_t d[100];
  for (size_t i = 0; i < 100; ++i) {
    d[i] = static_cast<uint8_t>(i);
  }
  ts.write(d, 100);

  // write a field element
  ts.write(F.of_scalar(7), F);

  // write a field element array
  Elt array[2] = {F.of_scalar(8), F.of_scalar(9)};
  ts.write(array, 1, 2, F);

  Elt e[16];
  ts.clone().elt(e, 16, F);

  for (size_t i = 0; i < 16; ++i) {
    // Generating challenge one element at a time is equivalent to generating
    // multiple elements together.
    EXPECT_EQ(ts.elt(F), e[i]);

    dump_elt(e[i]);
  }
}

TEST(Transcript, TestWriteByteArray) {
  Transcript ts((uint8_t*)"test", 4);
  // write a byte array
  uint8_t d[100];
  for (size_t i = 0; i < 100; ++i) {
    d[i] = static_cast<uint8_t>(i);
  }
  ts.write(d, 100);

  Elt e[16];
  ts.clone().elt(e, 16, F);

  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ(ts.elt(F), e[i]);

    dump_elt(e[i]);
  }
}

TEST(Transcript, TestWriteFieldElement) {
  Transcript ts((uint8_t*)"test", 4);

  // write a field element
  ts.write(F.of_scalar(7), F);

  Elt e[16];
  ts.clone().elt(e, 16, F);

  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ(ts.elt(F), e[i]);

    dump_elt(e[i]);
  }
}

TEST(Transcript, TestWriteFieldElementArray) {
  Transcript ts((uint8_t*)"test", 4);

  // write a field element array
  Elt array[2] = {F.of_scalar(8), F.of_scalar(9)};
  ts.write(array, 1, 2, F);

  Elt e[16];
  ts.clone().elt(e, 16, F);

  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ(ts.elt(F), e[i]);

    dump_elt(e[i]);
  }
}

TEST(Transcript, TestVec) {
  uint8_t key[32];

  Transcript ts((uint8_t *)"test", 4);
  uint8_t d[100];
  for (size_t i = 0; i < 100; ++i) {
    d[i] = static_cast<uint8_t>(i);
  }
  ts.write(d, 100);
  ts.get(key);

  // manually computed SHA256 of
  //    0
  //    4 0 0 0 0 0 0 0
  //    t e s t
  //    0                   // TAG
  //    100 0 0 0 0 0 0 0   // LENGTH
  //    0 1 2 ...           // PAYLOAD
  {
    const uint8_t key1[32] = {
        0x60, 0xcd, 0x16, 0x34, 0x92, 0x0f, 0x1c, 0xf2, 0xae, 0x83, 0x15,
        0x02, 0xbf, 0x4b, 0xb9, 0x3a, 0x60, 0xcd, 0x03, 0xee, 0xb1, 0x9f,
        0x93, 0xe2, 0xd6, 0xd5, 0x0d, 0xbd, 0x09, 0x84, 0xcb, 0xd8
    };
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(key[i], key1[i]);
    }
  }

  {
    // obtain two AES blocks
    uint8_t bytes[32];
    ts.bytes(bytes, 32);

    // manually computed AES256 of [0 0 0 0 0 0 0 0] and
    /// [1 0 0 0 0 0 0 0] under KEY
    const uint8_t bytes1[32] = {0x14, 0x1B, 0xBC, 0xBB, 0x54, 0x10, 0xDD, 0xEB,
                                0x70, 0x39, 0x83, 0x3B, 0x73, 0x65, 0x86, 0xA0,
                                0x20, 0xFD, 0xD5, 0x85, 0x63, 0x79, 0xB6, 0xC6,
                                0xC6, 0x83, 0xD5, 0xFF, 0x0B, 0x7F, 0x29, 0x8B};
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(bytes[i], bytes1[i]);
    }
  }

  // append another zero
  ts.write(d, 1);
  ts.get(key);

  {
    const uint8_t key1[32] = {0x18, 0x19, 0x78, 0x38, 0x0b, 0x6f, 0xf3, 0x21,
                              0x85, 0xc8, 0x28, 0xd9, 0xa0, 0x07, 0xee, 0x93,
                              0x0b, 0xce, 0x2e, 0x94, 0x7f, 0x88, 0x7f, 0x85,
                              0xb6, 0x4f, 0x39, 0x9a, 0x94, 0xcb, 0xe4, 0xa8};
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(key[i], key1[i]);
    }
  }
}
}  // namespace
}  // namespace proofs
