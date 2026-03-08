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

#include <stdint.h>

#include <cstring>

#include "circuits/mdoc/mdoc_zk.h"

extern "C" {
// This is a hardcoded list of all the ZK specifications supported by this
// library. Every time a new breaking change is introduced in either the circuit
// format or its interpretation, a new version must be added here.
// It is possible to remove old versions, if we're sure that they are not used
// by either provers of verifiers in the wild.
//
// The format is:
// {
//   - system - The ZK system name and version ("longfellow-libzk-v*" for Google
//   library).
//   - circuit_hash - SHA265 hash of the output of generate_circuit() function,
//   the circuit in compressed format. It's converted to a hex string. Every
//   time the circuit changes, the hash must be manually calculated and a new
//   ZKSpec added to this list.
//   - num_attributes. number of attributes the circuit supports,
//   - version. version of the ZK specification
//.  - block_enc_hash. block_enc parameter for the ZK proof of the hash
//     component. Version 3 uses the legacy-computed value, v4 uses optimized
//     values.
//   - block_enc_sig. block_enc parameter for the ZK proof of the signature
//     component.
// }

const ZkSpecStruct kZkSpecs[kNumZkSpecs] = {
    // Circuits produced 2026-03-05 (Version 8 - Supports PPID)
    {"longfellow-libzk-v1",
     "dd284984bd51a2e070277f07c73abb20bee973e20083d23d234db026b8e28530", 1, 8,
     4607, 2945},
    {"longfellow-libzk-v1",
     "d454ec95cde8d3cc3aa546330e898acd8ab8eb13dad04c628df3dfe1c0b9e83e", 2, 8,
     4685, 2945},
    {"longfellow-libzk-v1",
     "51daaab447c0b211c5316b3f3fc3694ad998e1dd5d27af238f19d9782771e6b8", 3, 8,
     4715, 2945},
    {"longfellow-libzk-v1",
     "c72b65a6a525d8b29a24d7f14e778080ffbb1b888ceec83fa44b6c13157f7de7", 4, 8,
     4787, 2945},
    // Circuits produced 2026-01-09
    {"longfellow-libzk-v1",
     "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121", 1, 7,
     4151, 4096},
    {"longfellow-libzk-v1",
     "6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad", 2, 7,
     4265, 4096},
    {"longfellow-libzk-v1",
     "8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f", 3, 7,
     4307, 4096},
    {"longfellow-libzk-v1",
     "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460", 4, 7,
     4415, 4096},
    // Circuits produced on 2025-10-10
    {"longfellow-libzk-v1",
     "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6", 1, 6,
     4096, 2945},
    {"longfellow-libzk-v1",
     "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e", 2, 6,
     4025, 2945},
    {"longfellow-libzk-v1",
     "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010", 3, 6,
     4121, 2945},
    {"longfellow-libzk-v1",
     "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6", 4, 6,
     4283, 2945},
    // Circuits produced on 2025-08-21
    {"longfellow-libzk-v1",
     "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f", 1, 5,
     4096, 2945},
    {"longfellow-libzk-v1",
     "f51b7248b364462854d306326abded169854697d752d3bb6d9a9446ff7605ddb", 2, 5,
     4025, 2945},
    {"longfellow-libzk-v1",
     "c27195e03e22c9ab4efe9e1dabd2c33aa8b2429cc4e86410c6f12542d3c5e0a1", 3, 5,
     4121, 2945},
    {"longfellow-libzk-v1",
     "fa5fadfb2a916d3b71144e9b412eff78f71fd6a6d4607eac10de66b195868b7a", 4, 5,
     4283, 2945},

};

const ZkSpecStruct* find_zk_spec(const char* system_name,
                                 const char* circuit_hash) {
  for (size_t i = 0; i < kNumZkSpecs; ++i) {
    const ZkSpecStruct& zk_spec = kZkSpecs[i];
    if (strcmp(zk_spec.system, system_name) == 0 &&
        strcmp(zk_spec.circuit_hash, circuit_hash) == 0) {
      return &zk_spec;
    }
  }
  return nullptr;
}

}  // extern "C"
