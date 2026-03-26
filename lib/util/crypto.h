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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_

// Encapsulates all of the cryptographic primitives used by this library.
// Specifically, for the collision-resistant hash function, this library uses
// SHA256. For a pseudo-random function, this library uses AES in ECB mode.
// Finally, this library provides a method to generate random bytes.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "util/panic.h"

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#else
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#endif

namespace proofs {

constexpr size_t kSHA256DigestSize = 32;
constexpr size_t kPRFKeySize = 32;
constexpr size_t kPRFInputSize = 16;
constexpr size_t kPRFOutputSize = 16;

class SHA256 {
 public:
#ifdef __APPLE__
  SHA256() { CC_SHA256_Init(&sha_); }
#else
  SHA256() { SHA256_Init(&sha_); }
#endif

  // Disable copy for good measure.
  SHA256(const SHA256&) = delete;
  SHA256& operator=(const SHA256&) = delete;

#ifdef __APPLE__
  void Update(const uint8_t bytes[/*n*/], size_t n) {
    CC_SHA256_Update(&sha_, bytes, static_cast<CC_LONG>(n));
  }
  void DigestData(uint8_t digest[/* kSHA256DigestSize */]) {
    CC_SHA256_Final(digest, &sha_);
  }
  void CopyState(const SHA256& src) { sha_ = src.sha_; }
#else
  void Update(const uint8_t bytes[/*n*/], size_t n) { SHA256_Update(&sha_, bytes, n); }
  void DigestData(uint8_t digest[/* kSHA256DigestSize */]) {
    SHA256_Final(digest, &sha_);
  }
  void CopyState(const SHA256& src) { sha_ = src.sha_; }
#endif

  void Update8(uint64_t x) {
    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
      buf[i] = x & 0xff;
      x >>= 8;
    }
    Update(buf, 8);
  }

 private:
#ifdef __APPLE__
  CC_SHA256_CTX sha_;
#else
  SHA256_CTX sha_;
#endif
};

// A pseudo-random function interface. This implementation uses AES in ECB mode.
// The caller must ensure that arguments are not reused.
class PRF {
 public:
#ifdef __APPLE__
  explicit PRF(const uint8_t key[/*kPRFKeySize*/]) {
    CCCryptorStatus status = CCCryptorCreate(
        kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
        key, kCCKeySizeAES256, nullptr, &cryptor_);
    check(status == kCCSuccess, "CCCryptorCreate failed");
  }

  ~PRF() { CCCryptorRelease(cryptor_); }
#else
  explicit PRF(const uint8_t key[/*kPRFKeySize*/]) {
    ctx_ = EVP_CIPHER_CTX_new();
    int ret =
        EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, key, nullptr);
    check(ret == 1, "EVP_EncryptInit_ex failed");
  }

  ~PRF() { EVP_CIPHER_CTX_free(ctx_); }
#endif

  // Disable copy for good measure.
  PRF(const PRF&) = delete;
  PRF& operator=(const PRF&) = delete;

  // Evaluate the PRF on the input and write the output to the output buffer.
  // This method should only be used internally by the Transcript class. The
  // caller must ensure that the input and output buffers are different.
  // This function implements a permutation, but we only need to exploit its
  // pseudo-random function property in this application.
#ifdef __APPLE__
  void Eval(uint8_t out[/*kPRFOutputSize*/], uint8_t in[/*kPRFInputSize*/]) {
    size_t data_out_moved = 0;
    CCCryptorStatus status = CCCryptorUpdate(
        cryptor_, in, kPRFInputSize, out, kPRFOutputSize, &data_out_moved);
    check(status == kCCSuccess, "CCCryptorUpdate failed");
  }
#else
  void Eval(uint8_t out[/*kPRFOutputSize*/], uint8_t in[/*kPRFInputSize*/]) {
    int out_len = static_cast<int>(kPRFOutputSize);
    int ret = EVP_EncryptUpdate(ctx_, out, &out_len, in,
                                static_cast<int>(kPRFInputSize));
    check(ret == 1, "EVP_EncryptUpdate failed");
  }
#endif

 private:
#ifdef __APPLE__
  CCCryptorRef cryptor_;
#else
  EVP_CIPHER_CTX* ctx_;
#endif
};

// Generate n random bytes.
// This method will panic if the underlying API fails.
void rand_bytes(uint8_t out[/*n*/], size_t n);

void hex_to_str(char out[/* 2*n + 1*/], const uint8_t in[/*n*/], size_t n);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
