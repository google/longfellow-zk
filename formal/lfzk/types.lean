import Mathlib
import sumcheck_soundness

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

variable {F : Type} [Field F] [Fintype F]
variable {Circuit Input Witness : Type}
variable {Ω : Type} [Fintype Ω]
variable (C : Circuit) (x : Input)
variable (eval : Circuit → Input → Witness → Bool)
variable {nc nv : ℕ}
variable (eps_FSK eps_sumcheck : ℕ)

noncomputable def event_card (E : Finset Ω) : ℕ := E.card



/--
`Expression` models the state in `zk_common.h` that tracks the symbolic evaluation
of a sumcheck polynomial. It maintains:
- `known`: the public scalar value
- `symbolic`: an array of coefficients for the pad variables.
-/
def Expression (M : ℕ) (F : Type) [Field F] :=
  F × (Fin M → F)


def Pad (M : ℕ) (F : Type) := Fin M → F


def AugmentedWitness (M : ℕ) (F : Type) (Witness : Type) := Witness × Pad M F


/--
**Structure: Transcript**

Models the **decrypted (plaintext) interactive sumcheck transcript** between the prover and verifier
after secret blinding pads have been removed (via `decrypt`).

### Fields:
- `polys`: The sequence of univariate round polynomials ($p_1(X), \dots, p_R(X)$) sent by the prover in each round of sumcheck (`LayerProof::cp` in `privacy/proofs/zk/lib/sumcheck/circuit.h`).
- `challenges`: The random field challenges ($r_1, \dots, r_R$) sampled by the verifier (`ch->cb[round]`).
- `claim_last`: The verifier's claim at the end of the sumcheck rounds (`*claim` after the final round in `verifier_layers.h:L160`).
- `w_r_eval`, `w_l_eval`: The evaluations of the right-hand and left-hand witness polynomials claimed by the prover at evaluation points $R$ and $L$.
- `w_r_true`, `w_l_true`: The actual, mathematically honest multilinear evaluations of the right-hand and left-hand witness MLEs (`W_mle r copy`, `W_mle l copy`) at the challenge point (`got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C]` in `verifier_layers.h:L160`).
-/
structure Transcript (F : Type) [Field F] where
  polys : List (RoundPoly F)
  challenges : List F
  claim_last : F
  w_r_eval : F
  w_l_eval : F
  w_r_true : F
  w_l_true : F


/--
`Transcript.checkV` models the unpadded, ideal verifier check on a decrypted transcript `t` and equality factor `eqq`.

It evaluates key verifier conditions:
1. **Sumcheck Multiplication Check** (`t.claim_last == eqq * t.w_r_eval * t.w_l_eval`):
   Verifies that the final sumcheck evaluation `claim_last` equals `EQQ * W_R * W_L`.
   - **Paper Reference**: *Longfellow ZK Paper*, Page 11: `CLAIM = EQQ * W[R,C] * W[L,C]`
   - **Code Reference**: `privacy/proofs/zk/lib/zk/zk_common.h:L340`: `CLAIM = EQQ * W[R,C] * W[L,C]`
2. **Right Witness Binding Check** (`t.w_r_eval == t.w_r_true`):
   Verifies that the transcript's public witness evaluation claim matches the extracted witness evaluation at $R$.
3. **Left Witness Binding Check** (`t.w_l_eval == t.w_l_true`):
   Verifies that the transcript's public witness evaluation claim matches the extracted witness evaluation at $L$.
-/
def Transcript.checkV {F : Type} [Field F] [DecidableEq F] (t : Transcript F) (eqq : F) : Bool :=
  (t.claim_last == eqq * t.w_r_eval * t.w_l_eval) && 
  (t.w_r_eval == t.w_r_true) && 
  (t.w_l_eval == t.w_l_true)


/--
**Structure: EncTranscript**

Models the **encrypted (padded / masked) zero-knowledge transcript** produced by the Longfellow ZK prover,
where `M` is the number of secret blinding variables in the pad (`Pad M F`).

In zero-knowledge sumcheck, the prover masks its polynomial evaluations and witness claims using random
blinding variables so that the verifier learns nothing about the secret witness. The function `decrypt`
combines an `EncTranscript` with a secret pad `p : Pad M F` to recover the underlying plaintext `Transcript`.

### Fields:
- `polys`: The sequence of padded/masked round polynomials sent by the prover during sumcheck.
- `challenges`: The verifier's challenge vector ($r_1, \dots, r_R$).
- `e`: The symbolic linear combination expression (`Expression M F`) tracking the masked evaluation state in `ConstraintBuilder` (`zk_common.h`).
- `wc0`, `wc1`: The public masked witness evaluations at $L$ and $R$: $\widehat{W}(L) = W(L) + \text{pad}_L$ (`wc[0]`) and $\widehat{W}(R) = W(R) + \text{pad}_R$ (`wc[1]`). Corresponds to `W_hat[L,C]` and `W_hat[R,C]` in `verifier_layers.h`.
- `pub_r`, `pub_l`: The public evaluations / commitment constants for the right and left hands.
- `w_r_bind`, `w_l_bind`: The linear coefficient bindings mapping the pad variables to the right and left witness evaluations (`w_r_bind`, `w_l_bind : Fin M → F`).
-/
structure EncTranscript (M : ℕ) (F : Type) [Field F] where
  polys : List (RoundPoly F)
  challenges : List F
  e : Expression M F
  wc0 : F
  wc1 : F
  pub_r : F
  pub_l : F
  w_r_bind : Fin M → F
  w_l_bind : Fin M → F

def evaluates_to {M : ℕ} {F : Type} [Field F] (e : Expression M F) (pad : Fin M → F) : F :=
  e.1 + ∑ i : Fin M, e.2 i * pad i

/--
`decrypt` models the homomorphic reconstruction of the sumcheck transcript from its encrypted (Ligero-committed) form.
The prover commits to polynomials and witness bounds via Ligero, which mathematically acts as an encrypted transcript `EncTranscript`.
By providing the random linear combination `p : Pad M F` extracted from Ligero, the verifier computes the plain sumcheck evaluations:
- `claim_last`: The evaluation of the final sumcheck expression (`e(pad)`).
- `w_r_eval` / `w_l_eval`: The decrypted queries to the witness columns at the challenge points.
- `w_r_true` / `w_l_true`: The linear consistency checks that bind the witness queries back to the original public/committed bounds.
-/
def EncTranscript.decrypt {M : ℕ} {F : Type} [Field F] (t_prime : EncTranscript M F) (p : Pad M F) (var_dwR var_dwL : Fin M) : Transcript F :=
  {
    polys := t_prime.polys,
    challenges := t_prime.challenges,
    claim_last := evaluates_to t_prime.e p,
    w_r_eval   := t_prime.wc1 + p var_dwR,
    w_l_eval   := t_prime.wc0 + p var_dwL,
    w_r_true   := (∑ i, t_prime.w_r_bind i * p i) + t_prime.pub_r,
    w_l_true   := (∑ i, t_prime.w_l_bind i * p i) + t_prime.pub_l
  }

