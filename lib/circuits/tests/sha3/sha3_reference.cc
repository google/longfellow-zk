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

#include <algorithm>
#include <cstdint>
#include <cstdlib>

#include "circuits/tests/sha3/sha3_round_constants.h"

namespace proofs {
static uint64_t rotl(uint64_t x, size_t b) {
  return (x << b) | (x >> (64 - b));
}

void Sha3Reference::keccak_f_1600_DEBUG_ONLY(uint64_t A[5][5]) {
  return keccak_f_1600(A);
}

// FIPS 202 3.2.1, theta
void Sha3Reference::theta(uint64_t A[5][5]) {
  uint64_t C[5];
  for (size_t x = 0; x < 5; ++x) {
    C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
  }

  for (size_t x = 0; x < 5; ++x) {
    uint64_t D_x = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
    for (size_t y = 0; y < 5; ++y) {
      A[x][y] ^= D_x;
    }
  }
}

// FIPS 202 3.2.2, rho
void Sha3Reference::rho(uint64_t A[5][5]) {
  size_t x = 1, y = 0;
  for (size_t t = 0; t < 24; ++t) {
    A[x][y] = rotl(A[x][y], sha3::sha3_rotc[t]);
    size_t nx = y, ny = (2 * x + 3 * y) % 5;
    x = nx;
    y = ny;
  }
}

// FIPS 202 3.2.3, pi
void Sha3Reference::pi(const uint64_t A[5][5], uint64_t A1[5][5]) {
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      A1[x][y] = A[(x + 3 * y) % 5][x];
    }
  }
}

// FIPS 202 3.2.4, chi
void Sha3Reference::chi(const uint64_t A1[5][5], uint64_t A[5][5]) {
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      A[x][y] = A1[x][y] ^ ((~A1[(x + 1) % 5][y]) & A1[(x + 2) % 5][y]);
    }
  }
}

// FIPS 202 3.2.5, iota
void Sha3Reference::iota(uint64_t A[5][5], size_t round) {
  A[0][0] ^= sha3::sha3_rc[round];
}

void Sha3Reference::keccak_f_1600(uint64_t A[5][5]) {
  for (size_t round = 0; round < 24; ++round) {
    theta(A);
    rho(A);
    uint64_t A1[5][5];
    pi(A, A1);
    chi(A1, A);
    iota(A, round);
  }
}

static uint64_t ru64le(const uint8_t* d) {
  uint64_t r = 0;
  for (size_t i = 8; i-- > 0;) {
    r = (r << 8) + (d[i] & 0xffu);
  }
  return r;
}

static void wu64le(uint8_t* d, uint64_t n) {
  for (size_t i = 0; i < 8; ++i) {
    d[i] = (n >> (8 * i)) & 0xffu;
  }
}

void Sha3Reference::xorin(uint64_t A[5][5], const uint8_t* d, size_t n) {
  size_t x = 0, y = 0;
  while (n > 0) {
    A[x][y] ^= ru64le(d);
    ++x;
    if (x == 5) {
      ++y;
      x = 0;
    }
    d += sizeof(uint64_t);
    n -= sizeof(uint64_t);
  }
}

void Sha3Reference::update(const char* data, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    buf_[wrptr_++] = data[i];
    if (wrptr_ == rate_) {
      xorin(a_, buf_, rate_);
      wrptr_ = 0;
      keccak_f_1600(a_);
    }
  }
}

void Sha3Reference::final(uint8_t digest[/*mdlen*/]) {
  buf_[wrptr_++] = 0x06;
  while (wrptr_ < rate_) {
    buf_[wrptr_++] = 0;
  }
  buf_[rate_ - 1] ^= 0x80;
  xorin(a_, buf_, rate_);
  wrptr_ = 0;
  keccak_f_1600(a_);

  size_t x = 0, y = 0;
  for (size_t i = 0; i < mdlen_; i += 8) {
    wu64le(&digest[i], a_[x][y]);
    ++x;
    if (x == 5) {
      ++y;
      x = 0;
    }
  }
}

void Sha3Reference::shake(size_t rate, const uint8_t* in, size_t inlen,
                          uint8_t* out, size_t outlen) {
  uint64_t A[5][5] = {};
  uint8_t block[200] = {};
  size_t ptr = 0;

  for (size_t i = 0; i < inlen; ++i) {
    block[ptr++] = in[i];
    if (ptr == rate) {
      xorin(A, block, rate);
      Sha3Reference::keccak_f_1600_DEBUG_ONLY(A);
      ptr = 0;
      for (size_t j = 0; j < rate; ++j) block[j] = 0;
    }
  }

  // Padding
  block[ptr] ^= 0x1F;
  block[rate - 1] ^= 0x80;
  xorin(A, block, rate);
  Sha3Reference::keccak_f_1600_DEBUG_ONLY(A);

  // Squeeze
  size_t out_ptr = 0;
  while (out_ptr < outlen) {
    uint8_t squeeze_block[200];
    size_t x = 0, y = 0;
    for (size_t i = 0; i < rate; i += 8) {
      wu64le(&squeeze_block[i], A[x][y]);
      ++x;
      if (x == 5) {
        ++y;
        x = 0;
      }
    }
    size_t take = std::min(rate, outlen - out_ptr);
    for (size_t i = 0; i < take; ++i) {
      out[out_ptr++] = squeeze_block[i];
    }
    if (out_ptr < outlen) {
      Sha3Reference::keccak_f_1600_DEBUG_ONLY(A);
    }
  }
}

void Sha3Reference::shake128Hash(const uint8_t* in, size_t inlen, uint8_t* out,
                                 size_t outlen) {
  shake(168, in, inlen, out, outlen);
}

void Sha3Reference::shake256Hash(const uint8_t* in, size_t inlen, uint8_t* out,
                                 size_t outlen) {
  shake(136, in, inlen, out, outlen);
}

void Sha3Reference::keccak256Hash(const uint8_t* in, size_t inlen,
                                  uint8_t out[32]) {
  // Keccak-256 rate = 200 - 2*32 = 136 bytes (same as SHA3-256).
  // The only difference from SHA3-256 is the padding byte: 0x01 here vs 0x06.
  constexpr size_t rate = 136;
  constexpr size_t mdlen = 32;
  uint64_t A[5][5] = {};
  uint8_t block[200] = {};
  size_t ptr = 0;

  for (size_t i = 0; i < inlen; ++i) {
    block[ptr++] = in[i];
    if (ptr == rate) {
      xorin(A, block, rate);
      keccak_f_1600(A);
      ptr = 0;
      for (size_t j = 0; j < rate; ++j) block[j] = 0;
    }
  }

  // Keccak-256 padding: 0x01 (SHA3 uses 0x06, SHAKE uses 0x1F).
  block[ptr] ^= 0x01;
  block[rate - 1] ^= 0x80;
  xorin(A, block, rate);
  keccak_f_1600(A);

  size_t x = 0, y = 0;
  for (size_t i = 0; i < mdlen; i += 8) {
    wu64le(&out[i], A[x][y]);
    ++x;
    if (x == 5) {
      ++y;
      x = 0;
    }
  }
}

}  // namespace proofs
