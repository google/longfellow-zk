import Mathlib
import sumcheck_soundness
import types

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# `ConstraintBuilder`

This file models `ZkCommon::Expression` and `ZkCommon::ConstraintBuilder`
(`zk_common.h:L250-L400`) — the symbolic machinery by which the ZK verifier turns a run of
the sumcheck into a single linear row of the Ligero constraint system.

An `Expression` represents an unpadded quantity as `KNOWN + Σ_i SYMBOLIC[i] · dX[i]`, where
`dX` is the secret pad.  `types.lean` already defines `Expression M F = F × (Fin M → F)` and
`evaluates_to e pad = e.1 + Σ_i e.2 i * pad i`; here are the three operations the builder
uses and the two methods built from them.

## Why this matters

`IsLigeroKnowledgeSound.accepted_sumcheck` used to *assume* that on an accepted run the
sumcheck rounds close on the decrypted expression `e(pad)`.  That is the entire link between
the Ligero constraint system and the sumcheck, and assuming it assumed most of the
integration.  `builder_sumcheck_accepts` below **proves** it.

## The substitution, not a check

`ConstraintBuilder::next` never tests `p(0) + p(1) == claim`.  It *substitutes*
`p_r(1) := claim_{r-1} − p_r(0)` (`zk_common.h:L336-L337`) and then forms the Lagrange dot
product.  So in the ZK path the sum-consistency relation holds by construction, and
`check_round_c` — which models the *non-ZK* `VerifierLayers::layer_h` — passes
automatically.  That is exactly what makes `builder_sumcheck_accepts` provable rather than
assumable, and it resolves which of the two verifiers the composition is about.
-/

-- `Fin M` decidable equality is canonical here rather than an instance parameter, so that
-- `EncTranscript.e` has a single elaboration everywhere it is used.
variable {M : ℕ} {F : Type} [Field F] [DecidableEq F] [SumcheckInterp F]

namespace Expression

/-- The expression representing `0` (`Expression(nvar, F)` at `zk_common.h:L261`). -/
def zero (M : ℕ) (F : Type) [Field F] : Expression M F := (0, fun _ => 0)

/-- `*this += k * (known_value + witness[var])` (`zk_common.h:L279-L282`). -/
def axpy (e : Expression M F) (var : Fin M) (kv k : F) : Expression M F :=
  (e.1 + k * kv, fun j => if j = var then e.2 j + k else e.2 j)

/-- `*this -= k * (known_value + witness[var])` (`zk_common.h:L285-L288`). -/
def axmy (e : Expression M F) (var : Fin M) (kv k : F) : Expression M F :=
  (e.1 - k * kv, fun j => if j = var then e.2 j - k else e.2 j)

/-- `scale` (`zk_common.h:L267-L272`). -/
def scale (e : Expression M F) (k : F) : Expression M F :=
  (k * e.1, fun j => k * e.2 j)

omit [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma evaluates_to_zero (pad : Pad M F) :
    evaluates_to (Expression.zero M F) pad = 0 := by
  simp [evaluates_to, Expression.zero]

omit [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma evaluates_to_axpy (e : Expression M F) (var : Fin M) (kv k : F) (pad : Pad M F) :
    evaluates_to (e.axpy var kv k) pad = evaluates_to e pad + k * (kv + pad var) := by
  dsimp [evaluates_to, Expression.axpy]
  have h : ∀ j : Fin M, (if j = var then e.2 j + k else e.2 j) * pad j
      = e.2 j * pad j + (if j = var then k * pad j else 0) := by
    intro j; split_ifs <;> ring
  rw [Finset.sum_congr rfl (fun j _ => h j), Finset.sum_add_distrib]
  simp
  ring

omit [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma evaluates_to_axmy (e : Expression M F) (var : Fin M) (kv k : F) (pad : Pad M F) :
    evaluates_to (e.axmy var kv k) pad = evaluates_to e pad - k * (kv + pad var) := by
  dsimp [evaluates_to, Expression.axmy]
  have h : ∀ j : Fin M, (if j = var then e.2 j - k else e.2 j) * pad j
      = e.2 j * pad j - (if j = var then k * pad j else 0) := by
    intro j; split_ifs <;> ring
  rw [Finset.sum_congr rfl (fun j _ => h j), Finset.sum_sub_distrib]
  simp
  ring

omit [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma evaluates_to_scale (e : Expression M F) (k : F) (pad : Pad M F) :
    evaluates_to (e.scale k) pad = k * evaluates_to e pad := by
  dsimp [evaluates_to, Expression.scale]
  rw [mul_add, Finset.mul_sum]
  congr 1
  exact Finset.sum_congr rfl (fun j _ => by ring)

end Expression

/--
The Lagrange coefficient vector `V(r)` of `Poly<3, Field>::dot_interpolation`
(`algebra/poly.h`), for which `P(r) = dot(V(r), [P(0), P(1), P(2)])`.

`ConstraintBuilder::next` receives it as `lag = dot_wpoly.coef(challenge, F)`
(`zk_common.h:L96`) and forms the dot product against the round polynomial.
-/
noncomputable def lag_coeffs (r : F) : F × F × F :=
  ( ((r - 1) * (r - (pt2 : F))) * (pt2 : F)⁻¹
  , (r * (r - (pt2 : F))) * (1 - (pt2 : F))⁻¹
  , (r * (r - 1)) * ((pt2 : F) * ((pt2 : F) - 1))⁻¹ )

omit [DecidableEq F] in
/-- The dot product against `lag_coeffs r` is evaluation at `r`. -/
lemma lag_coeffs_dot (poly : RoundPoly F) (r : F) :
    (lag_coeffs r).1 * poly.eval0 + (lag_coeffs r).2.1 * poly.eval1
      + (lag_coeffs r).2.2 * poly.eval2 = poly.eval_lagrange r := by
  simp only [lag_coeffs, RoundPoly.eval_lagrange]
  ring

/--
The per-round data `ConstraintBuilder::next` consumes: the two transmitted evaluations
`tr[0]` and `tr[2]`, the pad indices `ovp_poly_pad(r, 0)` and `ovp_poly_pad(r, 2)` of their
blinders, and the round challenge.

`tr[1]` is deliberately absent — `next` never reads it, because `p(1)` is derived.
-/
structure RoundData (M : ℕ) (F : Type) where
  tr0 : F
  tr2 : F
  pp0 : Fin M
  pp2 : Fin M
  chal : F

/-- The *unpadded* round polynomial: `p(0)` and `p(2)` are the transmitted values plus their
blinders, and `p(1)` is `claim − p(0)` by the substitution at `zk_common.h:L336-L337`. -/
noncomputable def RoundData.unpad (rd : RoundData M F) (pad : Pad M F) (claim : F) : RoundPoly F :=
  { eval0 := rd.tr0 + pad rd.pp0
    eval1 := claim - (rd.tr0 + pad rd.pp0)
    eval2 := rd.tr2 + pad rd.pp2 }

omit [DecidableEq F] [SumcheckInterp F] in
/-- Because `p(1)` is defined as `claim − p(0)`, the sum-consistency relation holds by
construction.  This is why the ZK path has no `p(0) + p(1) == claim` test. -/
@[simp] lemma RoundData.unpad_sum (rd : RoundData M F) (pad : Pad M F) (claim : F) :
    (rd.unpad pad claim).eval0 + (rd.unpad pad claim).eval1 = claim := by
  simp [RoundData.unpad]

/-- The claim after one round. -/
noncomputable def RoundData.step (rd : RoundData M F) (pad : Pad M F) (claim : F) : F :=
  (rd.unpad pad claim).eval_lagrange rd.chal

/-- `ConstraintBuilder::next` (`zk_common.h:L334-L347`), as an operation on expressions. -/
noncomputable def builder_next (e : Expression M F) (rd : RoundData M F) : Expression M F :=
  (((e.axmy rd.pp0 rd.tr0 1).scale (lag_coeffs rd.chal).2.1).axpy rd.pp0 rd.tr0
      (lag_coeffs rd.chal).1).axpy rd.pp2 rd.tr2 (lag_coeffs rd.chal).2.2

/-- `ConstraintBuilder::first` (`zk_common.h:L326-L331`): `claim_{-1} = cl0 + alpha * cl1`,
with each claim unpadded by its own claim-pad entry. -/
noncomputable def builder_first (alpha claim0 claim1 : F) (cp0 cp1 : Fin M) : Expression M F :=
  ((Expression.zero M F).axpy cp0 claim0 1).axpy cp1 claim1 alpha

omit [DecidableEq F] [SumcheckInterp F] in
lemma builder_first_eval (alpha claim0 claim1 : F) (cp0 cp1 : Fin M) (pad : Pad M F) :
    evaluates_to (builder_first alpha claim0 claim1 cp0 cp1) pad
      = (claim0 + pad cp0) + alpha * (claim1 + pad cp1) := by
  simp [builder_first]

omit [DecidableEq F] in
/-- One `next` step advances the expression exactly as the verifier's claim advances. -/
lemma builder_next_eval (e : Expression M F) (rd : RoundData M F) (pad : Pad M F) :
    evaluates_to (builder_next e rd) pad = rd.step pad (evaluates_to e pad) := by
  rw [RoundData.step, ← lag_coeffs_dot]
  simp only [builder_next, Expression.evaluates_to_axpy, Expression.evaluates_to_scale,
             Expression.evaluates_to_axmy, RoundData.unpad]
  ring

/-- `ConstraintBuilder::next` run over all the rounds of a layer. -/
noncomputable def builder_run (e : Expression M F) : List (RoundData M F) → Expression M F
  | [] => e
  | rd :: rest => builder_run (builder_next e rd) rest

/-- The unpadded round polynomials of a run. -/
noncomputable def run_polys (pad : Pad M F) : F → List (RoundData M F) → List (RoundPoly F)
  | _, [] => []
  | claim, rd :: rest => rd.unpad pad claim :: run_polys pad (rd.step pad claim) rest

/-- The challenges of a run. -/
def run_challenges : List (RoundData M F) → List F
  | [] => []
  | rd :: rest => rd.chal :: run_challenges rest

omit [DecidableEq F] in
@[simp] lemma run_polys_length (pad : Pad M F) (claim : F) (rds : List (RoundData M F)) :
    (run_polys pad claim rds).length = rds.length := by
  induction rds generalizing claim with
  | nil => rfl
  | cons rd rest ih => simp [run_polys, ih]

omit [Field F] [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma run_challenges_length (rds : List (RoundData M F)) :
    (run_challenges rds).length = rds.length := by
  induction rds with
  | nil => rfl
  | cons rd rest ih => simp [run_challenges, ih]

/--
**The sumcheck rounds close on the decrypted expression.**

Running `check_round_c` over the unpadded round polynomials of a builder run always
succeeds, and the claim it ends on is exactly `e(pad)` for the expression the builder
produced.

Every round check passes *by construction*: `RoundData.unpad_sum` says
`p(0) + p(1) = claim` because `p(1)` was defined that way, and `builder_next_eval` says the
expression tracks the claim.

This is the theorem that replaces `IsLigeroKnowledgeSound.accepted_sumcheck`.
-/
theorem builder_run_verifies (pad : Pad M F) :
    ∀ (rds : List (RoundData M F)) (e : Expression M F),
      verify_multi_round (evaluates_to e pad) (run_polys pad (evaluates_to e pad) rds)
          (run_challenges rds)
        = some (evaluates_to (builder_run e rds) pad) := by
  intro rds
  induction rds with
  | nil => intro e; rfl
  | cons rd rest ih =>
    intro e
    rw [run_polys, run_challenges, builder_run, verify_multi_round]
    have h_check : check_round_c (evaluates_to e pad) (rd.unpad pad (evaluates_to e pad)) rd.chal
        = some (rd.step pad (evaluates_to e pad)) := by
      rw [check_round_c, if_pos (by simp), RoundData.step]
    rw [h_check, ← builder_next_eval e rd pad]
    exact ih (builder_next e rd)

/--
The layer-0 form, which is what `IsLigeroKnowledgeSound.accepted_sumcheck` assumed:
the two inherited claims are `0`, and their claim-pad entries are not part of the
constraint system (`finalize` starts at `ovp_poly_pad(0, 0)` when `ly == 0`,
`zk_common.h:L389`), so the sumcheck starts from the claim `0`.
-/
theorem builder_sumcheck_accepts (pad : Pad M F) (alpha : F) (cp0 cp1 : Fin M)
    (rds : List (RoundData M F)) (h0 : pad cp0 = 0) (h1 : pad cp1 = 0) :
    verify_multi_round 0 (run_polys pad 0 rds) (run_challenges rds)
      = some (evaluates_to (builder_run (builder_first alpha 0 0 cp0 cp1) rds) pad) := by
  have hz : evaluates_to (builder_first alpha (0 : F) 0 cp0 cp1) pad = 0 := by
    rw [builder_first_eval, h0, h1]; ring
  have h := builder_run_verifies pad rds (builder_first alpha 0 0 cp0 cp1)
  rwa [hz] at h


/--
The layer-0 form: there is no previous layer, so there are no inherited claims and no
`CLAIM_PAD[layer - 1]` entries in the constraint row (`finalize` starts the loop at
`ovp_poly_pad(0, 0)` when `ly == 0`, `zk_common.h:L389`).  The sumcheck therefore starts
from the claim `0`.

This is exactly the statement `IsLigeroKnowledgeSound.accepted_sumcheck` used to assume.
-/
theorem builder_sumcheck_accepts_zero (pad : Pad M F) (rds : List (RoundData M F)) :
    verify_multi_round 0 (run_polys pad 0 rds) (run_challenges rds)
      = some (evaluates_to (builder_run (Expression.zero M F) rds) pad) := by
  have h := builder_run_verifies pad rds (Expression.zero M F)
  rwa [Expression.evaluates_to_zero] at h


/--
**Structure: EncTranscript**

The encrypted (padded) transcript of one layer, as the ZK verifier actually receives it:
a list of rounds — the transmitted `tr[0]`, `tr[2]`, the pad indices of their blinders, and
the challenge — plus the two masked witness evaluations `wc[0]`, `wc[1]`.

Everything else is *derived*: the symbolic claim `e` is what `ConstraintBuilder` computes,
the challenge list is read off the rounds, and the unpadded round polynomials `polys`
depend on the pad (as they must — `p(0) = tr[0] + dP(0)`).

An earlier version carried `polys`, `challenges` and `e` as independent fields, which meant
the relation between them — that the rounds close on `e(pad)` — had to be assumed.
-/
structure EncTranscript (M : ℕ) (F : Type) [Field F] where
  rounds : List (RoundData M F)
  wc0 : F
  wc1 : F

/-- The symbolic claim `expr_` after the layer's rounds (`zk_common.h:L91-L101`). -/
noncomputable def EncTranscript.e (t : EncTranscript M F) : Expression M F :=
  builder_run (Expression.zero M F) t.rounds

/-- The layer's challenges, `ch->hb[hand][round]`. -/
def EncTranscript.challenges (t : EncTranscript M F) : List F := run_challenges t.rounds

/-- The unpadded round polynomials.  These are a function of the pad: the prover transmits
`tr[0]`, `tr[2]` and the verifier only recovers `p(0)`, `p(2)` once the blinders are known. -/
noncomputable def EncTranscript.polys (t : EncTranscript M F) (pad : Pad M F) : List (RoundPoly F) :=
  run_polys pad 0 t.rounds

omit [DecidableEq F] in
@[simp] lemma EncTranscript.polys_length (t : EncTranscript M F) (pad : Pad M F) :
    (t.polys pad).length = t.rounds.length := by simp [EncTranscript.polys]

omit [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma EncTranscript.challenges_length (t : EncTranscript M F) :
    t.challenges.length = t.rounds.length := by simp [EncTranscript.challenges]

/--
**The sumcheck rounds close on the decrypted expression — derived.**

Formerly `IsLigeroKnowledgeSound.accepted_sumcheck`.
-/
theorem EncTranscript.rounds_verify (t : EncTranscript M F) (pad : Pad M F) :
    verify_multi_round 0 (t.polys pad) t.challenges = some (evaluates_to t.e pad) :=
  builder_sumcheck_accepts_zero pad t.rounds

/--
`decrypt` reconstructs the plaintext transcript from the pad.  `w_l_true` / `w_r_true` are
supplied by the caller and instantiated with the honest multilinear evaluations of the
extracted witness (`true_evals` in `circuit.lean`).
-/
noncomputable def EncTranscript.decrypt (t : EncTranscript M F) (p : Pad M F)
    (var_dwR var_dwL : Fin M) (w_l_true w_r_true : F) : Transcript F :=
  { polys := t.polys p
    challenges := t.challenges
    claim_last := evaluates_to t.e p
    w_r_eval := t.wc1 + p var_dwR
    w_l_eval := t.wc0 + p var_dwL
    w_r_true := w_r_true
    w_l_true := w_l_true }
