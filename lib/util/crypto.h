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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_

// Encapsulates all of the cryptographic primitives used by this library.
// Specifically, for the collision-resistant hash function, this library uses
// SHA256. For a pseudo-random function, this library uses AES in ECB mode.
// Finally, this library provides a method to generate random bytes using the
// openssl library.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "util/panic.h"

#if !defined(WITHOUT_OPENSSL)
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#endif

namespace proofs {

constexpr size_t kSHA256DigestSize = 32;
constexpr size_t kPRFKeySize = 32;
constexpr size_t kPRFInputSize = 16;
constexpr size_t kPRFOutputSize = 16;

#if !defined(WITHOUT_OPENSSL)
class SHA256 {
 public:
  SHA256() { SHA256_Init(&sha_); }

  // Disable copy for good measure.
  SHA256(const SHA256&) = delete;
  SHA256& operator=(const SHA256&) = delete;

  void Update(const uint8_t bytes[/*n*/], size_t n) { SHA256_Update(&sha_, bytes, n); }
  void DigestData(uint8_t digest[/* kSHA256DigestSize */]) {
    SHA256_Final(digest, &sha_);
  }
  void CopyState(const SHA256& src) { sha_ = src.sha_; }

  void Update8(uint64_t x) {
    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
      buf[i] = x & 0xff;
      x >>= 8;
    }
    Update(buf, 8);
  }

 private:
  SHA256_CTX sha_;
};
#else
#include "util/sha2.h" // Replace OpenSSL includes with this
#include <vector>   // For managing internal buffers
#include <algorithm> // For std::min
// SHA256 uses 64-byte blocks
constexpr size_t kSHA256BlockSize = 64;
class SHA256 {
 public:
  SHA256() : internal_ctx_buffer_(PQC_SHA256CTX_BYTES) {
    state_.ctx = internal_ctx_buffer_.data();
    sha256_inc_init(&state_);
  }
  SHA256(const SHA256&) = delete;
  SHA256& operator=(const SHA256&) = delete;
  ~SHA256() {
    if (state_.ctx) {
        if (!finalized_) {
             sha256_inc_ctx_release(&state_);
        }
    }
  }
  void Update(const uint8_t* bytes, size_t n) {
    if (finalized_) {
        ReInit();
    }
    size_t offset = 0;
    if (!buffer_.empty()) {
        size_t needed = kSHA256BlockSize - buffer_.size();
        size_t to_copy = std::min(n, needed);
        buffer_.insert(buffer_.end(), bytes, bytes + to_copy);
        offset += to_copy;
        if (buffer_.size() == kSHA256BlockSize) {
            sha256_inc_blocks(&state_, buffer_.data(), 1);
            buffer_.clear();
        }
    }
    size_t remaining_bytes = n - offset;
    size_t num_full_blocks = remaining_bytes / kSHA256BlockSize;
    if (num_full_blocks > 0) {
        sha256_inc_blocks(&state_, bytes + offset, num_full_blocks);
        offset += num_full_blocks * kSHA256BlockSize;
    }
    remaining_bytes = n - offset;
    if (remaining_bytes > 0) {
        buffer_.insert(buffer_.end(), bytes + offset, bytes + offset + remaining_bytes);
    }
  }
  void DigestData(uint8_t digest[/* kSHA256DigestSize */]) {
    if (finalized_) {
        ReInit();
    }
    sha256_inc_finalize(digest, &state_, buffer_.data(), buffer_.size());
    buffer_.clear();
    finalized_ = true;
  }
  void CopyState(const SHA256& src) {
    if (this == &src) return;
    sha256_inc_ctx_clone(&state_, &src.state_);
    // Copy the pending data buffer
    buffer_ = src.buffer_;
    finalized_ = src.finalized_;
  }
  void Update8(uint64_t x) {
    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
      buf[i] = static_cast<uint8_t>(x & 0xff); // LSB first
      x >>= 8;
    }
    Update(buf, 8);
  }
 private:
  void ReInit() {
    state_.ctx = internal_ctx_buffer_.data(); // ctx points to our buffer
    sha256_inc_init(&state_);
    buffer_.clear();
    finalized_ = false;
  }
  sha256ctx state_;
  std::vector<uint8_t> internal_ctx_buffer_; //  memory for state_.ctx
  std::vector<uint8_t> buffer_;              //  partial blocks (max kSHA256BlockSize - 1 bytes)
  bool finalized_ = false;
};
#endif // WITHOUT_OPENSSL

// A pseudo-random function interface. This implementation uses AES in ECB mode.
// The caller must ensure that arguments are not reused.
class PRF {
 public:
  explicit PRF(const uint8_t key[/*kPRFKeySize*/]) {
    ctx_ = EVP_CIPHER_CTX_new();
    int ret =
        EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, key, nullptr);
    check(ret == 1, "EVP_EncryptInit_ex failed");
  }

  ~PRF() { EVP_CIPHER_CTX_free(ctx_); }

  // Disable copy for good measure.
  PRF(const PRF&) = delete;
  PRF& operator=(const PRF&) = delete;

  // Evaluate the PRF on the input and write the output to the output buffer.
  // This method should only be used internally by the Transcript class. The
  // caller must ensure that the input and output buffers are different.
  // This function implements a permutation, but we only need to exploit its
  // pseudo-random function property in this application.
  void Eval(uint8_t out[/*kPRFOutputSize*/], uint8_t in[/*kPRFInputSize*/]) {
    int out_len = static_cast<int>(kPRFOutputSize);
    int ret = EVP_EncryptUpdate(ctx_, out, &out_len, in,
                                static_cast<int>(kPRFInputSize));
    check(ret == 1, "EVP_EncryptUpdate failed");
  }

 private:
  EVP_CIPHER_CTX* ctx_;
};

// Generate n random bytes, following the openssl API convention.
// This method will panic if the openssl library fails.
void rand_bytes(uint8_t out[/*n*/], size_t n);

void hex_to_str(char out[/* 2*n + 1*/], const uint8_t in[/*n*/], size_t n);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
