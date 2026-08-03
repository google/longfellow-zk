/-
# Copyright 2026 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
-/

import ECDSA.EC

section Spec

variable {F : Type} [Field F]

/--
  The standard ECDSA signature verification specification.
  Returns True if the signature (r, s) is valid for message hash `e` and public key `pk`.
-/
def StandardEcdsaVerify (pk : AffinePoint F) (e : Nat) (r s : Nat) (order : Nat) (params : CurveParameters F) : Prop :=
  -- 1. Public key validation
  pk.IsOnCurve params ∧
  let PK_proj := pk.toProjective
  bsmul (padBits (natToBits order) params.kBits) PK_proj params = infinityPoint ∧
  
  -- 2. Signature validation
  0 < r ∧ r < order ∧
  0 < s ∧ s < order ∧
  
  -- 3. Verification
  let z := e % order
  ∃ (s_inv : Nat), (s * s_inv) % order = 1 ∧
  let u1 := (z * s_inv) % order
  let u2 := (r * s_inv) % order
  
  let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let u1_G := bsmul (padBits (natToBits u1) params.kBits) G_proj params
  let u2_PK := bsmul (padBits (natToBits u2) params.kBits) PK_proj params
  let R := addE u1_G u2_PK params
  
  -- R != O
  ¬(R.X = 0 ∧ R.Z = 0) ∧
  
  -- r ≡ R.x mod n
  ∃ (R_Z_inv : F), R.Z * R_Z_inv = 1 ∧
  let Rx := R.X * R_Z_inv
  (r : F) = Rx

end Spec
