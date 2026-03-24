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

#ifndef PRIVACY_PROOFS_ZK_LIB_MERKLE_MERKLE_COMMITMENT_H_
#define PRIVACY_PROOFS_ZK_LIB_MERKLE_MERKLE_COMMITMENT_H_

#include <stddef.h>
#include <stdint.h>

#include <cstring>
#include <functional>
#include <vector>

#include "merkle/merkle_tree.h"
#include "random/random.h"
#include "util/crypto.h"

namespace proofs {

struct MerkleNonce {
  static constexpr size_t kLength = kSHA256DigestSize;
  uint8_t bytes[kLength];
};

struct MerkleProof {
  explicit MerkleProof(size_t nreq) : nonce(nreq), path() {}

  std::vector<MerkleNonce> nonce;  // [nreq]
  std::vector<Digest> path;        // variable size, but < nreq * mt_pathlen
};

inline size_t merkle_commitment_len(size_t n) { return merkle_tree_len(n); }

// prover-side
class MerkleCommitment {
 public:
  explicit MerkleCommitment(size_t n) : n_(n), mt_(n), nonce_(n) {}

  Digest commit(const std::function<void(size_t, SHA256 &)> &updhash,
                RandomEngine &rng) {
    for (size_t i = 0; i < n_; ++i) {
      SHA256 sha;
      rng.bytes(nonce_[i].bytes, MerkleNonce::kLength);
      sha.Update(nonce_[i].bytes, MerkleNonce::kLength);
      updhash(i, sha);

      Digest dig;
      sha.DigestData(dig.data);
      mt_.set_leaf(i, dig);
    }

    return mt_.build_tree();
  }

  void open(MerkleProof &proof, const size_t pos[/*np*/], size_t np) {
    // fill in the nonces of the opening
    for (size_t i = 0; i < np; ++i) {
      proof.nonce[i] = nonce_[pos[i]];
    }

    (void)mt_.generate_compressed_proof(proof.path, pos, np);
  }

 private:
  size_t n_;
  MerkleTree mt_;
  std::vector<MerkleNonce> nonce_;
};

// Declare a class for symmetry, but this class is never instantiated
class MerkleCommitmentVerifier {
 public:
  static bool verify(size_t n, const Digest &root, const MerkleProof &proof,
                     const size_t pos[/*nreq*/], size_t nreq,
                     const std::function<void(size_t, SHA256 &)> &updhash) {
    // Assemble the expected leaf values
    std::vector<Digest> leaves(nreq);
    for (size_t r = 0; r < nreq; ++r) {
      SHA256 sha;
      sha.Update(proof.nonce[r].bytes, MerkleNonce::kLength);
      updhash(r, sha);
      sha.DigestData(leaves[r].data);
    }

    MerkleTreeVerifier mtv(n, root);
    return mtv.verify_compressed_proof(proof.path.data(), proof.path.size(),
                                       &leaves[0], pos, nreq);
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_MERKLE_MERKLE_COMMITMENT_H_
