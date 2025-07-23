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
//   time the circuit changes, the hash must be manaully calculated and a new
//   ZKSpec added to this list.
//   - num_attributes. number of attributes the circuit supports,
//   - version. version of the ZK specification
// }

const ZkSpecStruct kZkSpecs[kNumZkSpecs] = {
    // Circuits for eu.europa.ec.eudi.pid.1
    {"longfellow-libzk-v1",
     "e34d209944bed3d59aa2215010ab0ce7fdcc1aa67e0349db94e7f6ae1076ac83", 1, 4},
    {"longfellow-libzk-v1",
     "00631984cf09c254166995c73ffaa01a20b2640988699b69a7835afbc8091ca0", 2, 4},
    {"longfellow-libzk-v1",
     "af1b27c82781abcd1e271edfba46c7788b648dc092c81574601f60bfdd6e0f78", 3, 4},
    {"longfellow-libzk-v1",
     "7f8a814d9675063d12cc8532b9c53a417fb9590c40d1ad9acf0ce8128e7ee5a8", 4, 4},
    // Circuits produced on 2025-06-13
    {"longfellow-libzk-v1",
     "bd3168ea0a9096b4f7b9b61d1c210dac1b7126a9ec40b8bc770d4d485efce4e9", 1, 3},
    {"longfellow-libzk-v1",
     "40b2b68088f1d4c93a42edf01330fed8cac471cdae2b192b198b4d4fc41c9083", 2, 3},
    {"longfellow-libzk-v1",
     "99a5da3739df68c87c7a380cc904bb275dbd4f1b916c3d297ba9d15ee86dd585", 3, 3},
    {"longfellow-libzk-v1",
     "5249dac202b61e03361a2857867297ee7b1d96a8a4c477d15a4560bde29f704f", 4, 3},
    // Circuits produced on 2025-05-15
    {"longfellow-libzk-v1",
     "2093f64f54c81fb2f7f96a46593951d04005784da3d479e4543e2190dcf205d6", 1, 2},
    {"longfellow-libzk-v1",
     "037f99104ca73b8828fc0b7754b9103fd72d36e82456ccac20f9ce778f09c0ee", 2, 2},
    {"longfellow-libzk-v1",
     "a83b9b575c296717a0902c717599016e50cbbb4252bdf4d3450c752d53ae1d29", 3, 2},
    {"longfellow-libzk-v1",
     "fd7e7cfd5fd8ab02ad839f0c198c68822659fa269c0cd66a8d01f98086ede60e", 4, 2},
    // Legacy circuits produced on 2025-04-18
    /*{"longfellow-libzk-v1",
     "2836f0df5b7c2c431be21411831f8b3d2b7694b025a9d56a25086276161f7a93", 1, 1},
    {"longfellow-libzk-v1",
     "40a24808f53f516b3e653ec898342c46acf3b4a98433013548e780d2ffb1b4d0", 2, 1},
    {"longfellow-libzk-v1",
     "0f5a3bfa24a1252544fda4602fea98fc69b6296b64d4c7e48f2420de2910bf55", 3, 1},
    {"longfellow-libzk-v1",
     "96b71d7173c0341860d7b1b8fbcceca3d55347ecca1c9617e7d6efbb6b5cf344", 4, 1},*/
};

const ZkSpecStruct *find_zk_spec(const char *system_name,
                                 const char *circuit_hash) {
  for (size_t i = 0; i < kNumZkSpecs; ++i) {
    const ZkSpecStruct &zk_spec = kZkSpecs[i];
    if (strcmp(zk_spec.system, system_name) == 0 &&
        strcmp(zk_spec.circuit_hash, circuit_hash) == 0) {
      return &zk_spec;
    }
  }
  return nullptr;
}

}  // extern "C"
