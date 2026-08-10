import Mathlib
import sumcheck_soundness
import types
import builder
import circuit
import ligero
import zk_hiding
import ligero_sys

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# The Ligero constraint system is public

The simulator argument is *sequential*: sample the transmitted values (perfect, by
`zk_hiding.lean`), derive the Ligero constraint system from them, then invoke Ligero's own
simulator on that system.  That only works if the system is a function of public data and
transmitted values — with no witness in it.

This file makes that checkable.  `LigeroSystem` separates the **row data** from the
**assignment** that satisfies it, and `buildSystem` constructs the rows.  The point is its
*type*: `buildSystem` has no `Witness` argument at all, so witness-freeness is enforced by
Lean rather than argued.  The theorems here are the bridge — that the rows built this way are
satisfied exactly when the existing `ligero_layer_checks` / `ligero_input_row` hold.
-/

/-! `LigeroRow`, `LigeroSystem` and `LigeroSystem.Sat` are in `ligero_sys.lean`, together with
the generic knowledge-soundness interface `IsLigeroSound` that the bridges below discharge
Longfellow's row facts from. -/

/-! ## Building the rows — note the absence of a `Witness` argument -/

/-- The layer row emitted by `ConstraintBuilder::finalize` (`zk_common.h:L373`).  It touches
only the pad, so its input-column coefficients are zero. -/
noncomputable def layerRow (ninp : ℕ) {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (e : Expression M F) (eqq wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M) :
    LigeroRow ninp M F :=
  { cw := fun _ => 0
    cp := (builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).1
    rhs := (builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).2 }

/-- The single input row of `ZkCommon::input_constraint` (`zk_common.h:L406`): coefficients
`b_i` on the *private* columns, `-1` and `-alpha` on the two claim pads. -/
noncomputable def inputRow {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (b : Fin ninp → F) (pub_binding got alpha : F) (var_dwL var_dwR : Fin M) :
    LigeroRow ninp M F :=
  { cw := fun i => if npub ≤ i.val then b i else 0
    cp := fun j => (if j = var_dwL then -1 else 0) + (if j = var_dwR then -alpha else 0)
    rhs := got - pub_binding }

/--
**The whole system of a run.**

Every argument is public (`npub`, `alpha`, the circuit-derived `eqq`, `pub_binding`, the pad
indices) or transmitted (`e`, built from the round data; `wc0`, `wc1`; `got`).  There is no
`Witness` parameter — that is the property the simulator argument needs, and here it is a
fact about the *type*, not a theorem that could rot.
-/
noncomputable def buildSystem {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (e : Expression M F) (eqq wc0 wc1 : F)
    (b : Fin ninp → F) (pub_binding alpha : F)
    (var_dwL var_dwR var_dwL_dwR : Fin M) : LigeroSystem ninp M F :=
  { linear := [layerRow ninp e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR,
               inputRow npub b pub_binding (wc0 + alpha * wc1) alpha var_dwL var_dwR]
    quad := [(var_dwL, var_dwR, var_dwL_dwR)] }

/-!
### The whole run: one row and one triple per layer

`ZkCommon` runs `cb.finalize(...)` once per layer inside the `for (ly)` loop
(`zk_common.h:L112`), advancing the pad base by `pl.layer_size()` each time, and emits the
single input row afterwards from the *last* layer's `wc` (`zk_common.h:L128-L133`).  So the
system is `nl` layer rows, `nl` quadratic triples, and one input row.
-/

/-- The per-layer data the Ligero rows are built from.  All of it is public or transmitted:
`e` is `builder_run` of the round data, `eqq` is what the verifier recomputes, `wc0`/`wc1`
are on the wire, and the three indices come from `PadLayout`. -/
structure LayerRowData (M : ℕ) (F : Type) [Field F] where
  e : Expression M F
  eqq : F
  wc0 : F
  wc1 : F
  var_dwL : Fin M
  var_dwR : Fin M
  var_dwLR : Fin M

/--
**The full multi-layer system.**  `got` and the two input-row pad indices come from the last
layer (`plr = &proof.l[circuit.nl - 1]`); they are parameters here rather than projected out,
so the definition stays total on the empty list.
-/
noncomputable def buildSystemMulti {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (layers : List (LayerRowData M F))
    (b : Fin ninp → F) (pub_binding got alpha : F) (ivL ivR : Fin M) :
    LigeroSystem ninp M F :=
  { linear := layers.map (fun L => layerRow ninp L.e L.eqq L.wc0 L.wc1 L.var_dwL L.var_dwR
                            L.var_dwLR)
                ++ [inputRow npub b pub_binding got alpha ivL ivR]
    quad := layers.map (fun L => (L.var_dwL, L.var_dwR, L.var_dwLR)) }

/-! ## The bridge: these rows are the ones the soundness side already uses -/

/-- The layer row is satisfied exactly when `ligero_layer_checks`'s linear conjunct holds.
Its input-column coefficients vanish, so the assignment's witness half is irrelevant. -/
lemma layerRow_Sat {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (e : Expression M F) (eqq wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M)
    (wcol : Fin ninp → F) (pad : Fin M → F) :
    (layerRow ninp e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).Sat wcol pad
      ↔ (∑ j, (builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).1 j * pad j)
          = (builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).2 := by
  simp [LigeroRow.Sat, layerRow]

/-- The input row is satisfied exactly when `ligero_input_row` holds.  The `if` on the
coefficients restricts the sum to the private columns, matching `privIdx`; the two pad
coefficients contribute `-pad var_dwL - alpha * pad var_dwR`. -/
lemma inputRow_Sat {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (b : Fin ninp → F) (pub_binding got alpha : F) (var_dwL var_dwR : Fin M)
    (wcol : Fin ninp → F) (pad : Fin M → F) :
    (inputRow npub b pub_binding got alpha var_dwL var_dwR).Sat wcol pad
      ↔ ligero_input_row npub wcol pad b pub_binding got alpha var_dwL var_dwR := by
  have hw : (∑ i, (if npub ≤ i.val then b i else 0) * wcol i)
      = ∑ i ∈ privIdx ninp npub, b i * wcol i := by
    rw [privIdx, Finset.sum_filter]
    exact Finset.sum_congr rfl (fun i _ => by by_cases h : npub ≤ i.val <;> simp [h])
  have hp : (∑ j, ((if j = var_dwL then (-1 : F) else 0)
        + (if j = var_dwR then -alpha else 0)) * pad j)
      = -pad var_dwL - alpha * pad var_dwR := by
    rw [Finset.sum_congr rfl (fun j _ => add_mul _ _ _), Finset.sum_add_distrib]
    rw [Finset.sum_congr rfl (fun j _ => ite_mul _ _ _ _),
        Finset.sum_congr rfl (fun j _ => ite_mul _ _ _ _)]
    simp [Finset.sum_ite_eq']
    ring
  rw [LigeroRow.Sat, inputRow, hw, hp, ligero_input_row]
  constructor <;> intro h <;> linear_combination h

/--
**The whole system is satisfied exactly when the soundness-side predicates hold.**

So `buildSystem` is not a new model: it is the *same* constraint system the soundness
development already feeds to Ligero, with the row data separated from the assignment.  What
the separation buys is that the row half provably mentions no witness.
-/
theorem buildSystem_Sat {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (e : Expression M F) (eqq wc0 wc1 : F)
    (b : Fin ninp → F) (pub_binding alpha : F) (var_dwL var_dwR var_dwL_dwR : Fin M)
    (wcol : Fin ninp → F) (pad : Fin M → F) :
    (buildSystem npub e eqq wc0 wc1 b pub_binding alpha var_dwL var_dwR var_dwL_dwR).Sat
        wcol pad
      ↔ ligero_layer_checks e pad eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR
        ∧ ligero_input_row npub wcol pad b pub_binding (wc0 + alpha * wc1) alpha
            var_dwL var_dwR := by
  rw [LigeroSystem.Sat, buildSystem]
  constructor
  · rintro ⟨hlin, hquad⟩
    refine ⟨⟨?_, ?_⟩, ?_⟩
    · have := hlin (layerRow ninp e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR) (by simp)
      rw [layerRow_Sat] at this
      exact this
    · exact hquad (var_dwL, var_dwR, var_dwL_dwR) (by simp)
    · have := hlin (inputRow npub b pub_binding (wc0 + alpha * wc1) alpha var_dwL var_dwR)
        (by simp)
      rw [inputRow_Sat] at this
      exact this
  · rintro ⟨⟨hlay, hq⟩, hinp⟩
    refine ⟨?_, ?_⟩
    · intro row hrow
      rcases List.mem_cons.mp hrow with h | h
      · subst h; rw [layerRow_Sat]; exact hlay
      · rcases List.mem_cons.mp h with h2 | h2
        · subst h2; rw [inputRow_Sat]; exact hinp
        · cases h2
    · intro t ht
      rcases List.mem_cons.mp ht with h | h
      · subst h; exact hq
      · cases h

/-!
## What this establishes

`buildSystem`'s arguments are `npub`, `e`, `eqq`, `wc0`, `wc1`, `b`, `pub_binding`, `alpha`
and the three pad indices.  Of these:

* `e` is `builder_run` of the round data — the *transmitted* `tr[0]`, `tr[2]` and the pad
  indices and challenges;
* `wc0`, `wc1` are transmitted (`tss.write(&plr->wc[0], 1, 2)`, `zk_common.h:L116`);
* `eqq` is `layer_eqq`, which the verifier recomputes from the circuit and the challenges —
  its type carries no `Witness`;
* `b` is `input_row_coeffs alpha chal`, likewise;
* `pub_binding` is `pubBinding`, which *syntactically* takes a witness but is provably
  independent of it (`pub_consistent_of_indep`, `ligero.lean`);
* `npub`, `alpha` and the pad indices are public.

So the system is a function of the public data and the transcript.  That is the hypothesis
the sequential composition in `zkClose_seq` needs, and it holds.
-/

/-!
# Honest-verifier zero-knowledge

Ligero is a black box here, exactly as it is for soundness: `IsLigeroKnowledgeSound` assumes
extraction, `IsLigeroZeroKnowledge` assumes simulatability.  What Longfellow contributes is
the pad blinding, which is *perfect*, and the fact that the constraint system handed to
Ligero is public — proved above.

The composition is sequential, and `zkClose_seq` is the exact shape:

* stage one samples the transmitted values.  It is a bijection on blinders
  (`blindEquiv`, `zk_hiding.lean`), hence perfect and witness-free;
* stage two is Ligero, invoked on the system that stage one's output determines.
-/

/--
**Ligero's zero-knowledge, as a black box.**

For every constraint system and every assignment satisfying it, the real proof and the
simulated one agree under a bijection on coins, outside at most `eps_hide` of them.

`eps_hide` is where the Merkle commitment fails to hide; the tableau blinding — the per-block
randomness `RANDOM[R]` with `r = nreq` (`ligero_param.h:L154`), and the three blinding rows
for the low-degree, linear and quadratic disclosures — is what makes it small.  None of that
is modelled here.  The shape mirrors `IsLigeroKnowledgeSound.extraction_bound` exactly: a bad
set of coins, bounded.
-/
structure IsLigeroZeroKnowledge {ninp M : ℕ} {F LigProof LigRand SimRand : Type} [Field F]
    [Fintype LigRand] [Fintype SimRand] (eps_hide : ℚ)
    (realProof : LigeroSystem ninp M F → (Fin ninp → F) → Pad M F → LigRand → LigProof)
    (sim : LigeroSystem ninp M F → SimRand → LigProof) : Prop where
  nonneg : 0 ≤ eps_hide
  close : ∀ (cs : LigeroSystem ninp M F) (wcol : Fin ninp → F) (pad : Pad M F),
    cs.Sat wcol pad → StatClose eps_hide (realProof cs wcol pad) (sim cs)

/--
**The data of one run, as the simulator argument needs it.**

`nb` is the number of blinding slots — `4·logw + 2` per layer (`zk_hiding.lean`).  `Chal` is
the verifier's challenge sequence, which is an *input* here: this is honest-verifier ZK, so
the challenges are given and the same on both sides.

* `honest w chal` — the values the honest prover would transmit before blinding.  This is the
  only place the witness enters the transcript.  It depends on the challenges because round
  `r`'s polynomial does.
* `padOf b` — the pad built from the blinders; challenge-independent, since the pad is the
  prover's own randomness.  `padOfBlinders` (`zk_hiding.lean`) is the concrete one: it reads
  the blinders straight out of the layer's contiguous block and leaves everything else to the
  surrounding run.  A run's claim triple additionally needs its third slot to hold the product
  of the first two, which `PadLayout.claimTriple_not_blinding` shows is never a blinding slot
  and so cannot disturb the masking.
* `sys chal t` — the Ligero system.  A function of the challenges and the *transmission*;
  `buildSystem` and `buildSystemMulti` have this shape by construction.
* `honest_sat` — the honest run satisfies its own system.  `honest_buildSystemMulti_Sat`
  derives this for a system built from the model's own pieces.

**Scope.**  Taking `chal` as given is what makes this *honest-verifier*.  Under Fiat–Shamir
the challenges are derived from earlier messages, so `honest` would feed back into itself and
the blinders-to-transmissions map would be *triangular* rather than a translation — still a
bijection, but proved by induction over rounds rather than by `blindEquiv`.  That is the NIZK
case and it is not covered.
-/
structure ZkSetup (ninp M nb : ℕ) (F Witness Chal : Type) [Field F] where
  honest : Witness → Chal → Fin nb → F
  padOf : (Fin nb → F) → Pad M F
  /-- The committed input columns.  These may be read at a *copy point* the challenges
  determine, which is why `Chal` appears; they do not otherwise depend on it — the columns are
  fixed by `ZkProver::commit` before any challenge exists. -/
  wcol : Witness → Chal → Fin ninp → F
  sys : Chal → (Fin nb → F) → LigeroSystem ninp M F
  honest_sat : ∀ (w : Witness) (chal : Chal) (b : Fin nb → F),
    (sys chal (blindEquiv (honest w chal) b)).Sat (wcol w chal) (padOf b)

/-- The real transcript of a run at a given challenge sequence: the challenges, the blinded
values, and Ligero's proof of the system they determine. -/
noncomputable def realTranscript {ninp M nb : ℕ} {F Witness Chal LigProof LigRand : Type}
    [Field F] (S : ZkSetup ninp M nb F Witness Chal)
    (realProof : LigeroSystem ninp M F → (Fin ninp → F) → Pad M F → LigRand → LigProof)
    (w : Witness) (chal : Chal) :
    ((Fin nb → F) × LigRand) → ((Chal × (Fin nb → F)) × LigProof) :=
  fun p => ((chal, blindEquiv (S.honest w chal) p.1),
            realProof (S.sys chal (blindEquiv (S.honest w chal) p.1)) (S.wcol w chal)
              (S.padOf p.1) p.2)

/-- The simulator: sample the transmitted values uniformly, then run Ligero's simulator on the
system they determine.  It never sees a witness. -/
noncomputable def simulate {ninp M nb : ℕ} {F Witness Chal LigProof SimRand : Type} [Field F]
    (S : ZkSetup ninp M nb F Witness Chal)
    (sim : LigeroSystem ninp M F → SimRand → LigProof) (chal : Chal) :
    ((Fin nb → F) × SimRand) → ((Chal × (Fin nb → F)) × LigProof) :=
  fun q => ((chal, q.1), sim (S.sys chal q.1) q.2)

/--
**Honest-verifier zero-knowledge for Longfellow.**

For every witness and **every challenge sequence**, no test distinguishes the real transcript
from a simulation that never sees a witness with advantage more than `eps_hide`.

`eps_hide` is Ligero's, unchanged: the pad stage is a bijection, so it contributes nothing and
there is no factor for the blinder space.  At `eps_hide = 0` this is perfect HVZK.

The simulator uses its **own** randomness — `SimRand` and `LigRand` are unrelated types of
possibly different size — which is why the statement is in `StatClose` rather than in the
coupling form the pad stage supplies.
-/
theorem longfellow_hvzk {ninp M nb : ℕ} {F Witness Chal LigProof LigRand SimRand : Type}
    [Field F] [Fintype F] [Fintype LigRand] [Fintype SimRand] {eps_hide : ℚ}
    (S : ZkSetup ninp M nb F Witness Chal)
    (realProof : LigeroSystem ninp M F → (Fin ninp → F) → Pad M F → LigRand → LigProof)
    (sim : LigeroSystem ninp M F → SimRand → LigProof)
    (lzk : IsLigeroZeroKnowledge eps_hide realProof sim) (w : Witness) (chal : Chal) :
    StatClose eps_hide (realTranscript S realProof w chal) (simulate S sim chal) :=
  statClose_seq (blindEquiv (S.honest w chal))
    (fun b => (chal, blindEquiv (S.honest w chal) b)) (fun t => (chal, t)) (fun _ => rfl)
    (fun b lr => realProof (S.sys chal (blindEquiv (S.honest w chal) b)) (S.wcol w chal)
      (S.padOf b) lr)
    (fun t sr => sim (S.sys chal t) sr) eps_hide lzk.nonneg
    (fun b => lzk.close (S.sys chal (blindEquiv (S.honest w chal) b)) (S.wcol w chal)
      (S.padOf b) (S.honest_sat w chal b))

/--
**The same statement as total variation distance.**

`longfellow_hvzk` bounds every test's advantage; total variation distance is the supremum of
that advantage over tests, so it is bounded by the same number.  This is the form to compare
against a paper.  It needs the transcript type to be finite and decidable, which the
distinguisher form does not.
-/
theorem longfellow_hvzk_statDist {ninp M nb : ℕ} {F Witness Chal LigProof LigRand SimRand : Type}
    [Field F] [Fintype F] [Fintype LigRand] [Fintype SimRand] {eps_hide : ℚ}
    [Fintype ((Chal × (Fin nb → F)) × LigProof)]
    [DecidableEq ((Chal × (Fin nb → F)) × LigProof)]
    (S : ZkSetup ninp M nb F Witness Chal)
    (realProof : LigeroSystem ninp M F → (Fin ninp → F) → Pad M F → LigRand → LigProof)
    (sim : LigeroSystem ninp M F → SimRand → LigProof)
    (lzk : IsLigeroZeroKnowledge eps_hide realProof sim) (w : Witness) (chal : Chal) :
    statDist (realTranscript S realProof w chal) (simulate S sim chal) ≤ eps_hide :=
  statDist_le_of_statClose (longfellow_hvzk S realProof sim lzk w chal)

/--
**Witness indistinguishability.**  At every challenge sequence, two witnesses give transcripts
`2 · eps_hide`-indistinguishable from each other — `0` when the commitment is perfectly hiding.
No simulator appears in the statement.
-/
theorem longfellow_wi {ninp M nb : ℕ} {F Witness Chal LigProof LigRand SimRand : Type}
    [Field F] [Fintype F] [Fintype LigRand] [Fintype SimRand] {eps_hide : ℚ}
    (S : ZkSetup ninp M nb F Witness Chal)
    (realProof : LigeroSystem ninp M F → (Fin ninp → F) → Pad M F → LigRand → LigProof)
    (sim : LigeroSystem ninp M F → SimRand → LigProof)
    (lzk : IsLigeroZeroKnowledge eps_hide realProof sim) (w₁ w₂ : Witness) (chal : Chal) :
    StatClose (eps_hide + eps_hide)
      (realTranscript S realProof w₁ chal) (realTranscript S realProof w₂ chal) :=
  (longfellow_hvzk S realProof sim lzk w₁ chal).trans
    ((longfellow_hvzk (SimRand := SimRand) S realProof sim lzk w₂ chal).symm)



/-!
# Constructing a `ZkSetup` from the model

`ZkSetup.honest_sat` is a field, so on its own it *assumes* that the honest prover's
assignment satisfies its own rows.  This section derives it instead, for a layer built out of
the model's own pieces, leaving exactly one residual hypothesis — sumcheck completeness — with
a name.

The three obligations of `LigeroSystem.Sat` come apart cleanly:

* the **quadratic triple** holds by construction of the pad (`padOfBlinders` writes
  `dWC[0]·dWC[1]` into the third claim slot, which `claimTriple_not_blinding` shows is never a
  blinding slot);
* the **layer row** is `builder_finalize_complete` applied to the final claim;
* the **input row** is pure algebra on the claim blinders.
-/

/-- The final claim an honest prover reaches.  For a satisfied circuit the sumcheck's
completeness makes this the layer polynomial at the transcript's own challenge point, which
`layer_poly_factors` factors as `EQQ · W[L] · W[R]`; `evaluates_to e pad` is what
`builder_run_verifies` says the `ConstraintBuilder` tracks. -/
def HonestFinalClaim {M : ℕ} {F : Type} [Field F]
    (e : Expression M F) (pad : Pad M F) (eqq wc0 wc1 : F) (var_dwL var_dwR : Fin M) : Prop :=
  evaluates_to e pad = eqq * (wc0 + pad var_dwL) * (wc1 + pad var_dwR)

/-- The honest prover's blinding of the two hand evaluations: `wc = W_hat − dW`. -/
def HonestClaimBlinding {M : ℕ} {F : Type} [Field F]
    (pad : Pad M F) (wc0 wc1 wl wr : F) (var_dwL var_dwR : Fin M) : Prop :=
  wc0 = wl - pad var_dwL ∧ wc1 = wr - pad var_dwR


/-!
## The honest prover's rounds reproduce the true polynomials

`honest_final_claim` needs `HonestRounds`: that the *unpadded* round polynomials of the
transcript agree with the true ones at `0`, `1` and the challenge.  For an honest prover that
is not an assumption — it is what blinding is arranged to give.  `RoundData.unpad` sets
`eval0 = tr[0] + pad pp0`, and the honest `tr[0]` is `P(0) − dP(0)`, so the blinder cancels.

The one place it could fail is `eval1`, which `unpad` *defines* as `claim − eval0` rather than
transmitting.  So `eval1 = P(1)` exactly when the claim entering the round is the true one —
which is the sumcheck chain, and is why this is an induction rather than a per-round check.
-/

/-- One round of an honest run: the transmitted pair matches the true polynomial at `0` and
`pt2` once the blinders are added back. -/
def HonestRoundData {M : ℕ} {F : Type} [Field F] [SumcheckInterp F]
    (rd : RoundData M F) (pad : Pad M F) (P : Polynomial F) : Prop :=
  rd.tr0 + pad rd.pp0 = P.eval 0 ∧ rd.tr2 + pad rd.pp2 = P.eval (pt2 : F)

/--
**The unpadded round polynomial is the true one, and the claim advances correctly.**

Given that the incoming claim is the true hypercube sum of `P`, the honest round data unpads
to a triple agreeing with `P` at all three points, and the next claim is `P` at the challenge.
-/
lemma unpad_agrees {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (rd : RoundData M F) (pad : Pad M F) (P : Polynomial F) (claim : F)
    (hdeg : P.natDegree ≤ 2)
    (hrd : HonestRoundData rd pad P)
    (hclaim : claim = P.eval 0 + P.eval 1) :
    ((rd.unpad pad claim).eval0 = P.eval 0 ∧ (rd.unpad pad claim).eval1 = P.eval 1 ∧
      (rd.unpad pad claim).eval2 = P.eval (pt2 : F))
    ∧ rd.step pad claim = P.eval rd.chal := by
  obtain ⟨h0, h2⟩ := hrd
  have e0 : (rd.unpad pad claim).eval0 = P.eval 0 := h0
  have e1 : (rd.unpad pad claim).eval1 = P.eval 1 := by
    show claim - (rd.tr0 + pad rd.pp0) = P.eval 1
    rw [h0, hclaim]; ring
  have e2 : (rd.unpad pad claim).eval2 = P.eval (pt2 : F) := h2
  refine ⟨⟨e0, e1, e2⟩, ?_⟩
  show (rd.unpad pad claim).eval_lagrange rd.chal = P.eval rd.chal
  exact RoundPoly.eval_lagrange_eq_of_agree _ P hdeg e0 e1 e2 rd.chal

/--
**`HonestRounds`, for a whole layer.**

The induction over rounds: each round's claim is the true one, so its unpadded triple matches
the true polynomial, so the next claim is again the true one.  `hcons` is the honest chain's
own consistency (`consistent_generate`), and `hstart` says the run starts from the true claim
— for a satisfying witness and a run starting at `0`, that is exactly "the circuit is
satisfied".
-/
theorem honestRounds_of_roundData {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    [SumcheckInterp F] :
    ∀ (rds : List (RoundData M F)) (Ps : List (Polynomial F)) (pad : Pad M F) (claim : F),
      Ps.length = rds.length →
      (∀ P ∈ Ps, P.natDegree ≤ 2) →
      (∀ (r : ℕ) (hr : r < rds.length) (hp : r < Ps.length),
        HonestRoundData (rds.get ⟨r, hr⟩) pad (Ps.get ⟨r, hp⟩)) →
      consistent_true_polys Ps (run_challenges rds) →
      claim = Ps.head!.eval 0 + Ps.head!.eval 1 →
      rds ≠ [] →
      HonestRounds Ps (run_polys pad claim rds) (run_challenges rds) := by
  intro rds
  induction rds with
  | nil => intro Ps pad claim _ _ _ _ _ hne; exact absurd rfl hne
  | cons rd rest ih =>
    intro Ps pad claim hlen hdeg hrd hcons hstart _
    cases Ps with
    | nil => simp at hlen
    | cons P Pt =>
      have hP : P.natDegree ≤ 2 := hdeg P (by simp)
      have hrd0 : HonestRoundData rd pad P := hrd 0 (by simp) (by simp)
      obtain ⟨⟨e0, e1, e2⟩, hstep⟩ :=
        unpad_agrees rd pad P claim hP hrd0 (by simpa using hstart)
      rw [run_polys, run_challenges]
      refine ⟨⟨e0, e1, ?_⟩, ?_⟩
      · exact RoundPoly.eval_lagrange_eq_of_agree _ P hP e0 e1 e2 rd.chal
      cases rest with
      | nil =>
        cases Pt with
        | nil => exact trivial
        | cons _ _ => simp at hlen
      | cons rd' rest' =>
        cases Pt with
        | nil => simp at hlen
        | cons P' Pt' =>
          rw [run_challenges, consistent_true_polys] at hcons
          refine ih (P' :: Pt') pad (rd.step pad claim) (by simpa using hlen)
            (fun Q hQ => hdeg Q (by simp [hQ])) (fun r hr hp => hrd (r + 1) (by simpa using hr)
              (by simpa using hp)) (by simpa using hcons.2) ?_ (by simp)
          rw [hstep]
          simpa using hcons.1.symm

/-!
## `HonestFinalClaim`, derived

The last named hypothesis on this side.  `builder_run_verifies` says the rounds *always* close
on `evaluates_to e pad` — that is true of any prover, honest or not, because the ZK verifier
substitutes `p(1) = claim − p(0)`.  What it does not say is *which* value that is.

Sumcheck completeness supplies the missing half: when the transmitted triples agree with the
true round polynomials, the same run also closes on `get_last_eval` of the honest chain, which
`get_last_eval_generate` identifies as the layer polynomial at the transcript's own challenge
point.  Two expressions for one value, hence the value.

The hypothesis `hzero` is where "the circuit is satisfied" enters: the honest run starts from
the claim `0`, which is how both verifiers initialise, and for a satisfying witness that *is*
the true hypercube sum.
-/

/--
**An honest run closes on the layer polynomial at its own challenge point.**

Stated for an arbitrary `f` so that the sumcheck content is separated from the
arithmetization; `honest_final_claim` below specialises it.
-/
theorem honest_run_final_value {n M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    [SumcheckInterp F] (f : Vector F n → F) (t : EncTranscript M F) (pad : Pad M F)
    (hn : 0 < n) (hlen : t.challenges.length = n)
    (hh : HonestRounds (generate_true_polys f (chalVec t.challenges n)) (t.polys pad)
      t.challenges)
    (hzero : ∑ j ∈ Finset.range (2 ^ n), f (boolean_vector j) = 0) :
    evaluates_to t.e pad = f (chalVec t.challenges n) := by
  have hrounds : t.rounds.length = n := by
    rw [← EncTranscript.challenges_length t]; exact hlen
  have hne : t.polys pad ≠ [] := by
    intro h0
    have : (t.polys pad).length = 0 := by rw [h0, List.length_nil]
    rw [EncTranscript.polys_length, hrounds] at this
    omega
  have hstart : (0 : F)
      = (generate_true_polys f (chalVec t.challenges n)).head!.eval 0
        + (generate_true_polys f (chalVec t.challenges n)).head!.eval 1 := by
    rw [head_generate f _ hn]; exact hzero.symm
  have hcomp := sumcheck_multi_completeness (generate_true_polys f (chalVec t.challenges n))
    (t.polys pad) t.challenges 0 hh (consistent_generate f t.challenges hlen) hne hstart
  have hver := t.rounds_verify pad
  rw [hcomp, get_last_eval_generate f t.challenges hlen hn] at hver
  exact (Option.some.inj hver).symm

/--
**`HonestFinalClaim`, no longer a hypothesis.**

For an honest prover on a satisfying witness, the claim the layer row is built against is
exactly `EQQ · W[L] · W[R]`.  `layer_poly_factors` does the factoring; the claim blinding
`wc = W_hat − dW` turns the two honest evaluations into `wc + pad`.
-/
theorem honest_final_claim {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F]
    [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F)
    (q : Vector F logc) (g0 g1 : Vector F logv)
    (t : EncTranscript M F) (pad : Pad M F) (var_dwL var_dwR : Fin M)
    (hpos : 0 < logc + 2 * logw)
    (hlen : t.challenges.length = logc + 2 * logw)
    (hh : HonestRounds
      (generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
        (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1)
        (chalVec t.challenges (logc + 2 * logw))) (t.polys pad) t.challenges)
    (hsat : layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w)
      alpha q g0 g1 = 0)
    (hblind : HonestClaimBlinding pad t.wc0 t.wc1
      (true_evals AC inp w t.challenges).1 (true_evals AC inp w t.challenges).2
      var_dwL var_dwR) :
    HonestFinalClaim t.e pad (layer_eqq AC c alpha beta q g0 g1 t.challenges)
      t.wc0 t.wc1 var_dwL var_dwR := by
  obtain ⟨h0, h1⟩ := hblind
  have hval := honest_run_final_value
    (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w)
      alpha q g0 g1) t pad hpos hlen hh hsat
  have hchal : chalVec t.challenges (logc + 2 * logw)
      = (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0) := rfl
  rw [HonestFinalClaim, hval, hchal,
      layer_poly_factors AC c inp w alpha beta q g0 g1 t.challenges, h0, h1]
  ring

/-!
### Interior layers: starting from the previous layer's claim

`honest_run_final_value` reads the start off `EncTranscript.e`, which is
`builder_run Expression.zero`, so it is a layer-0 statement.  An interior layer starts from
`ConstraintBuilder::first` on the previous layer's `wc`s and claim pads (`zkExpr`), so the
value it closes on is different.

`builder_run_verifies` is already general in the starting expression; only the wrapper was
specialised.  These are the general forms, and `honest_run_final_value` is the `e₀ = 0` case.
-/

/--
**An honest run closes on the layer polynomial, from any starting expression.**

`hstart` says the expression the layer begins with evaluates to the true hypercube sum.  At
layer 0 that is "the circuit is satisfied" (the sum is `0` and the builder starts at
`Expression.zero`); at an interior layer it is the claim the previous layer handed on, which
is what the GKR reduction maintains.
-/
theorem honest_run_final_value_from {n M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    [SumcheckInterp F] (f : Vector F n → F) (rds : List (RoundData M F)) (e₀ : Expression M F)
    (pad : Pad M F) (hn : 0 < n) (hlen : (run_challenges rds).length = n)
    (hh : HonestRounds (generate_true_polys f (chalVec (run_challenges rds) n))
      (run_polys pad (evaluates_to e₀ pad) rds) (run_challenges rds))
    (hstart : evaluates_to e₀ pad = ∑ j ∈ Finset.range (2 ^ n), f (boolean_vector j)) :
    evaluates_to (builder_run e₀ rds) pad = f (chalVec (run_challenges rds) n) := by
  have hrds : rds.length = n := by rw [← run_challenges_length rds]; exact hlen
  have hne : run_polys pad (evaluates_to e₀ pad) rds ≠ [] := by
    intro h0
    have : (run_polys pad (evaluates_to e₀ pad) rds).length = 0 := by rw [h0, List.length_nil]
    rw [run_polys_length, hrds] at this
    omega
  have hstart' : evaluates_to e₀ pad
      = (generate_true_polys f (chalVec (run_challenges rds) n)).head!.eval 0
        + (generate_true_polys f (chalVec (run_challenges rds) n)).head!.eval 1 := by
    rw [head_generate f _ hn]; exact hstart
  have hcomp := sumcheck_multi_completeness
    (generate_true_polys f (chalVec (run_challenges rds) n))
    (run_polys pad (evaluates_to e₀ pad) rds) (run_challenges rds) (evaluates_to e₀ pad)
    hh (consistent_generate f (run_challenges rds) hlen) hne hstart'
  have hver := builder_run_verifies pad rds e₀
  rw [hcomp, get_last_eval_generate f (run_challenges rds) hlen hn] at hver
  exact (Option.some.inj hver).symm

/--
**`HonestFinalClaim` for a layer starting anywhere.**

Same content as `honest_final_claim`, with the starting expression a parameter.  This is what
an interior layer of a multi-layer run needs: its `e₀` is `builder_first` on the previous
layer's data, not `Expression.zero`.
-/
theorem honest_final_claim_from {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F]
    [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F)
    (q : Vector F logc) (g0 g1 : Vector F logv)
    (rds : List (RoundData M F)) (e₀ : Expression M F) (pad : Pad M F)
    (wc0 wc1 : F) (var_dwL var_dwR : Fin M)
    (hpos : 0 < logc + 2 * logw)
    (hlen : (run_challenges rds).length = logc + 2 * logw)
    (hh : HonestRounds
      (generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
        (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1)
        (chalVec (run_challenges rds) (logc + 2 * logw)))
      (run_polys pad (evaluates_to e₀ pad) rds) (run_challenges rds))
    (hstart : evaluates_to e₀ pad
      = layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w)
          alpha q g0 g1)
    (hblind : HonestClaimBlinding pad wc0 wc1
      (true_evals AC inp w (run_challenges rds)).1
      (true_evals AC inp w (run_challenges rds)).2 var_dwL var_dwR) :
    HonestFinalClaim (builder_run e₀ rds) pad
      (layer_eqq AC c alpha beta q g0 g1 (run_challenges rds)) wc0 wc1 var_dwL var_dwR := by
  obtain ⟨h0, h1⟩ := hblind
  have hval := honest_run_final_value_from
    (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w)
      alpha q g0 g1) rds e₀ pad hpos hlen hh hstart
  have hchal : chalVec (run_challenges rds) (logc + 2 * logw)
      = (Vector.ofFn (n := logc + 2 * logw) fun i => (run_challenges rds).getD i.val 0) := rfl
  rw [HonestFinalClaim, hval, hchal,
      layer_poly_factors AC c inp w alpha beta q g0 g1 (run_challenges rds), h0, h1]
  ring

/--
**The layer row is satisfied by an honest run.**  No assumption beyond the final claim.
-/
theorem honest_layerRow {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (e : Expression M F) (pad : Pad M F) (eqq wc0 wc1 : F)
    (var_dwL var_dwR var_dwL_dwR : Fin M) (wcol : Fin ninp → F)
    (hquad : pad var_dwL_dwR = pad var_dwL * pad var_dwR)
    (hclaim : HonestFinalClaim e pad eqq wc0 wc1 var_dwL var_dwR) :
    (layerRow ninp e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).Sat wcol pad := by
  rw [layerRow_Sat]
  exact builder_finalize_complete e pad eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR hquad hclaim

/--
**The input row is satisfied by an honest run.**

`ligero_input_row` asks that the private columns, corrected by the two claim blinders, hit
`got − pub_binding`.  For an honest prover `got = wc0 + alpha·wc1` with `wc = W_hat − dW`, and
the full weighted column sum is `W_hat[L] + alpha·W_hat[R]` — so the blinders cancel exactly.
The public half is `pub_binding`, which is where `pub_consistent_of_indep` enters.
-/
theorem honest_inputRow {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (b : Fin ninp → F) (pub_binding alpha wl wr : F) (wc0 wc1 : F)
    (var_dwL var_dwR : Fin M) (wcol : Fin ninp → F) (pad : Pad M F)
    (hblind : HonestClaimBlinding pad wc0 wc1 wl wr var_dwL var_dwR)
    (hpub : pub_binding = ∑ i ∈ Finset.univ \ privIdx ninp npub, b i * wcol i)
    (hmle : (∑ i, b i * wcol i) = wl + alpha * wr) :
    (inputRow npub b pub_binding (wc0 + alpha * wc1) alpha var_dwL var_dwR).Sat wcol pad := by
  rw [inputRow_Sat, ligero_input_row]
  obtain ⟨h0, h1⟩ := hblind
  have hsplit : (∑ i ∈ privIdx ninp npub, b i * wcol i)
      + (∑ i ∈ Finset.univ \ privIdx ninp npub, b i * wcol i) = ∑ i, b i * wcol i :=
    Finset.sum_add_sum_compl (privIdx ninp npub) _
  rw [h0, h1, hpub]
  linear_combination hsplit + hmle

/--
**`honest_sat`, derived.**

Every obligation of `LigeroSystem.Sat` for `buildSystem` follows from three facts about an
honest run: the pad's quadratic relation, the final claim, and the claim blinding — plus
public-input consistency and the input-row/MLE identity, both of which the soundness
development already proves.

Nothing here is assumed about the *rows*; they are the ones `buildSystem` constructs.
-/
theorem honest_buildSystem_Sat {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (e : Expression M F) (pad : Pad M F) (eqq wc0 wc1 : F)
    (b : Fin ninp → F) (pub_binding alpha wl wr : F)
    (var_dwL var_dwR var_dwL_dwR : Fin M) (wcol : Fin ninp → F)
    (hquad : pad var_dwL_dwR = pad var_dwL * pad var_dwR)
    (hclaim : HonestFinalClaim e pad eqq wc0 wc1 var_dwL var_dwR)
    (hblind : HonestClaimBlinding pad wc0 wc1 wl wr var_dwL var_dwR)
    (hpub : pub_binding = ∑ i ∈ Finset.univ \ privIdx ninp npub, b i * wcol i)
    (hmle : (∑ i, b i * wcol i) = wl + alpha * wr) :
    (buildSystem npub e eqq wc0 wc1 b pub_binding alpha var_dwL var_dwR var_dwL_dwR).Sat
      wcol pad := by
  refine ⟨?_, ?_⟩
  · intro row hrow
    rcases List.mem_cons.mp hrow with h | h
    · subst h
      exact honest_layerRow e pad eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR wcol hquad hclaim
    · rcases List.mem_cons.mp h with h2 | h2
      · subst h2
        exact honest_inputRow npub b pub_binding alpha wl wr wc0 wc1 var_dwL var_dwR wcol pad
          hblind hpub hmle
      · cases h2
  · intro t ht
    rcases List.mem_cons.mp ht with h | h
    · subst h; exact hquad
    · cases h

/-- **The multi-layer system is satisfied exactly when every layer's checks and the input row
hold.**  Same content as `buildSystem_Sat`, over the whole run. -/
theorem buildSystemMulti_Sat {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (layers : List (LayerRowData M F))
    (b : Fin ninp → F) (pub_binding got alpha : F) (ivL ivR : Fin M)
    (wcol : Fin ninp → F) (pad : Pad M F) :
    (buildSystemMulti npub layers b pub_binding got alpha ivL ivR).Sat wcol pad
      ↔ (∀ L ∈ layers, ligero_layer_checks L.e pad L.eqq L.wc0 L.wc1 L.var_dwL L.var_dwR
            L.var_dwLR)
        ∧ ligero_input_row npub wcol pad b pub_binding got alpha ivL ivR := by
  rw [LigeroSystem.Sat, buildSystemMulti]
  constructor
  · rintro ⟨hlin, hquad⟩
    refine ⟨fun L hL => ⟨?_, ?_⟩, ?_⟩
    · have := hlin (layerRow ninp L.e L.eqq L.wc0 L.wc1 L.var_dwL L.var_dwR L.var_dwLR)
        (by simp only [List.mem_append, List.mem_map]; exact Or.inl ⟨L, hL, rfl⟩)
      rw [layerRow_Sat] at this
      exact this
    · exact hquad (L.var_dwL, L.var_dwR, L.var_dwLR)
        (by simp only [List.mem_map]; exact ⟨L, hL, rfl⟩)
    · have := hlin (inputRow npub b pub_binding got alpha ivL ivR) (by simp)
      rw [inputRow_Sat] at this
      exact this
  · rintro ⟨hlay, hinp⟩
    refine ⟨?_, ?_⟩
    · intro row hrow
      simp only [List.mem_append, List.mem_map, List.mem_singleton] at hrow
      rcases hrow with ⟨L, hL, rfl⟩ | rfl
      · rw [layerRow_Sat]; exact (hlay L hL).1
      · rw [inputRow_Sat]; exact hinp
    · intro t ht
      simp only [List.mem_map] at ht
      obtain ⟨L, hL, rfl⟩ := ht
      exact (hlay L hL).2

/--
**`honest_sat` for the whole run.**

Per layer: the pad's quadratic relation and the final claim.  Once, at the end: the claim
blinding of the last layer, public-input consistency, and the input-row/MLE identity.  Nothing
about the rows is assumed.
-/
theorem honest_buildSystemMulti_Sat {ninp M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (npub : ℕ) (layers : List (LayerRowData M F))
    (b : Fin ninp → F) (pub_binding alpha wl wr : F) (wc0 wc1 : F) (ivL ivR : Fin M)
    (wcol : Fin ninp → F) (pad : Pad M F)
    (hquad : ∀ L ∈ layers, pad L.var_dwLR = pad L.var_dwL * pad L.var_dwR)
    (hclaim : ∀ L ∈ layers,
      HonestFinalClaim L.e pad L.eqq L.wc0 L.wc1 L.var_dwL L.var_dwR)
    (hblind : HonestClaimBlinding pad wc0 wc1 wl wr ivL ivR)
    (hpub : pub_binding = ∑ i ∈ Finset.univ \ privIdx ninp npub, b i * wcol i)
    (hmle : (∑ i, b i * wcol i) = wl + alpha * wr) :
    (buildSystemMulti npub layers b pub_binding (wc0 + alpha * wc1) alpha ivL ivR).Sat
      wcol pad := by
  rw [buildSystemMulti_Sat]
  refine ⟨fun L hL => ⟨?_, hquad L hL⟩, ?_⟩
  · have := honest_layerRow (ninp := ninp) L.e pad L.eqq L.wc0 L.wc1 L.var_dwL L.var_dwR
      L.var_dwLR wcol (hquad L hL) (hclaim L hL)
    rw [layerRow_Sat] at this
    exact this
  · have := honest_inputRow npub b pub_binding alpha wl wr wc0 wc1 ivL ivR wcol pad
      hblind hpub hmle
    rw [inputRow_Sat] at this
    exact this

/-!
## Non-vacuity

`longfellow_hvzk` is an implication, so it says nothing unless `ZkSetup` and
`IsLigeroZeroKnowledge` are jointly inhabitable — and inhabitable in the regime the theorem
is *about*, which for hiding means at least one blinding slot and two witnesses that a
transcript could distinguish.

The instance below has `nb = 2`: the two *claim* blinding slots, masking `wc[0]` and `wc[1]`.
A full layer has `4·logw + 2` slots, the other `4·logw` blinding each round's `tr[0]`, `tr[2]`.
At `nb = 0` there would be nothing to blind and the statement would be empty.

Its Ligero system is a **real** `buildSystem` — layer row, input row, quadratic triple — read
off the transmitted values, and `honest_sat` is discharged by `honest_buildSystem_Sat` rather
than by `simp` on an empty list.  What is still a stand-in is Ligero itself: a `Unit` proof at
`eps_hide = 0`.  And this layer has no rounds, which forces `eqq = 0`.

A layer *with* rounds is now reachable — `padOfBlinders` (`zk_hiding.lean`) is the pad as a
function of the blinders and `honestRounds_of_roundData` supplies the `HonestRounds`
hypothesis — but assembling a `ZkSetup` from an `EncTranscript`, a `PadLayout` and an
`ArithmetizedCircuit` has not been done; see the README's gap 3.
-/

namespace ZkExample

instance : Fact (Nat.Prime 7) := ⟨by norm_num⟩

abbrev F7 := ZMod 7

/-- The witness's committed value. -/
def vOf : Bool → F7 := fun w => if w then 1 else 0

/-- The honest prover's two claim transmissions before blinding — `W[L]` and `W[R]`, both
`vOf w` on this layer.  These are what the wire would carry if nothing masked them. -/
def honestOf : Bool → Fin 2 → F7 := fun w _ => vOf w

/-- The two witnesses really are distinguishable before blinding. -/
theorem honest_differs : honestOf false ≠ honestOf true := by
  intro h
  have hc := congrFun h ⟨0, by omega⟩
  simp only [honestOf, vOf] at hc
  exact absurd hc (by decide)

/-- The pad: the two claim blinders `dW[L]`, `dW[R]`, and their product in the third slot.
Writing the product there is what `PadLayout.claimTriple_not_blinding` shows is safe — that
slot is never a blinding slot, so it carries no information about the witness. -/
def padOfB : (Fin 2 → F7) → Pad 3 F7 :=
  fun b => fun j => if j = 0 then b 0 else if j = 1 then b 1 else b 0 * b 1

/-- The committed input column.  The input row asks for `W[L] + alpha·W[R]`, which at
`alpha = 3` is `4 · vOf w`. -/
def wcolOf : Bool → Fin 1 → F7 := fun w _ => 4 * vOf w

/--
**The real Ligero system of this run.**

Not an empty system: `buildSystem`'s layer row, input row and quadratic triple, and it reads
the two transmitted values `t 0`, `t 1`.  So the instance exercises the rows the soundness side
feeds to Ligero, and `honest_sat` below is discharged by `honest_buildSystem_Sat` rather than
by `simp` on an empty list.

`eqq = 0` because this layer has no rounds: `e` is `Expression.zero`, so the claim the layer
row is built against is `0`, and `HonestFinalClaim` forces `eqq · W[L] · W[R] = 0`.
-/
noncomputable def sysOf : Unit → (Fin 2 → F7) → LigeroSystem 1 3 F7 :=
  fun _ t => buildSystem 0 (Expression.zero 3 F7) 0 (t 0) (t 1) (fun _ => 1) 0 3 0 1 2

/-- Challenges are a single point here: the instance is about the blinding and the rows, not
the rounds. -/
noncomputable def setup : ZkSetup 1 3 2 F7 Bool Unit where
  honest := fun w _ => honestOf w
  padOf := padOfB
  wcol := fun w _ => wcolOf w
  sys := sysOf
  honest_sat := by
    intro w chal bl
    refine honest_buildSystem_Sat 0 (Expression.zero 3 F7) (padOfB bl) 0
      (blindEquiv (honestOf w) bl 0) (blindEquiv (honestOf w) bl 1)
      (fun _ => 1) 0 3 (vOf w) (vOf w) 0 1 2 (wcolOf w) ?_ ?_ ?_ ?_ ?_
    · -- the quadratic triple, by construction of the pad
      simp [padOfB]
    · -- the final claim: `e` is zero and `eqq` is zero
      simp [HonestFinalClaim, Expression.evaluates_to_zero]
    · -- the claim blinding: `wc = W − dW` is exactly what `blindEquiv` computes
      exact ⟨by simp [padOfB, honestOf], by simp [padOfB, honestOf]⟩
    · -- `npub = 0`, so the public half of the input sum is empty
      simp [privIdx]
    · -- the input row's weighted column sum is `W[L] + alpha·W[R]`
      simp [wcolOf]
      ring

/-- A perfectly-hiding Ligero: the proof carries nothing, so `eps_hide = 0`.

The simulator is given **twice** the prover's randomness — `SimRand = Bool` against
`LigRand = Unit` — which the coupling form of the assumption could not have expressed, since
a bijection between the two coin spaces does not exist. -/
theorem triv_lzk :
    IsLigeroZeroKnowledge (ninp := 1) (M := 3) (F := F7) (LigProof := Unit)
      (LigRand := Unit) (SimRand := Bool) 0
      (fun _ _ _ _ => ()) (fun _ _ => ()) where
  nonneg := le_refl 0
  close := by
    intro cs wcol pad _ P
    by_cases hP : P () <;> simp [probOf, hP]

/-- **The theorem applies, at `eps_hide = 0`.**  The real transcript of *either* witness is
perfectly indistinguishable from a simulation that never sees one. -/
theorem hvzk_applies (w : Bool) :
    StatClose 0
      (realTranscript (LigRand := Unit) setup (fun _ _ _ _ => ()) w ())
      (simulate (SimRand := Bool) setup (fun (_ : LigeroSystem 1 3 F7) (_ : Bool) => ()) ()) :=
  longfellow_hvzk setup (fun _ _ _ _ => ()) (fun _ _ => ()) triv_lzk w ()

/-- **And the two witnesses are perfectly indistinguishable from each other**, despite
`honest_differs`: the blinding is exactly what erases the difference. -/
theorem wi_applies :
    StatClose 0
      (realTranscript (LigRand := Unit) setup (fun _ _ _ _ => ()) false ())
      (realTranscript (LigRand := Unit) setup (fun _ _ _ _ => ()) true ()) := by
  have h := longfellow_wi (SimRand := Bool) setup (fun _ _ _ _ => ()) (fun _ _ => ()) triv_lzk
    false true ()
  simpa using h

/-- The system really is non-trivial: it has two linear rows and one quadratic triple. -/
example (t : Fin 2 → F7) : (sysOf () t).linear.length = 2 ∧ (sysOf () t).quad.length = 1 :=
  ⟨rfl, rfl⟩

end ZkExample

/-!
# A `ZkSetup` from the model's own pieces

Everything above is generic: `ZkSetup` is a structure and `longfellow_hvzk` an implication.
This section builds one from an `ArithmetizedCircuit`, a `PadLayout` slot assignment and the
transcript shape, for a layer that **has rounds** — so the hiding statement is instantiated at
the object the protocol actually produces rather than at a stand-in.

The layer has `logw` hand rounds per side, so `n = 2·logw` rounds and `nb = 4·logw + 2`
blinding slots: two per round for `tr[0]`, `tr[2]`, then two for `wc[0]`, `wc[1]`.  The pad
indices are parameters satisfying the `PadLayout` laws rather than computed, so a caller can
place the layer anywhere in a run's pad.

`honest_sat` is **derived**, not assumed.  It comes from `honest_buildSystem_Sat`, whose three
obligations are met by: the pad's quadratic slot (`hquadLR`), `honest_final_claim` fed by
`honestRounds_of_roundData`, and the claim blinding — which is what `padOfBlinders` makes true
by construction.
-/

section ZkSetupOfLayer

variable {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]

/-- The honest transmission of a layer, before blinding: each round's `P(0)` and `P(pt2)`, then
the two hand evaluations `W[L]`, `W[R]`. -/
noncomputable def honestVals {logw : ℕ} (P : Fin (2 * logw) → Polynomial F) (wl wr : F) :
    Fin (4 * logw + 2) → F :=
  fun j =>
    if h : j.val < 4 * logw then
      (if j.val % 2 = 0 then (P ⟨j.val / 2, by omega⟩).eval 0
                        else (P ⟨j.val / 2, by omega⟩).eval (pt2 : F))
    else if j.val = 4 * logw then wl else wr

omit [Fintype F] [DecidableEq F] in
@[simp] lemma honestVals_round0 {logw : ℕ} (P : Fin (2 * logw) → Polynomial F) (wl wr : F)
    (j : Fin (4 * logw + 2)) (r : Fin (2 * logw)) (hj : j.val = 2 * r.val) :
    honestVals P wl wr j = (P r).eval 0 := by
  have hr := r.isLt
  show (if _ : j.val < 4 * logw then _ else _) = _
  have hdiv : j.val / 2 = r.val := by omega
  have hlt : j.val / 2 < 2 * logw := by omega
  have hfin : (⟨j.val / 2, hlt⟩ : Fin (2 * logw)) = r := by apply Fin.ext; exact hdiv
  rw [dif_pos (by omega), if_pos (by omega)]
  exact congrArg (fun x => (P x).eval 0) hfin

omit [Fintype F] [DecidableEq F] in
@[simp] lemma honestVals_round2 {logw : ℕ} (P : Fin (2 * logw) → Polynomial F) (wl wr : F)
    (j : Fin (4 * logw + 2)) (r : Fin (2 * logw)) (hj : j.val = 2 * r.val + 1) :
    honestVals P wl wr j = (P r).eval (pt2 : F) := by
  have hr := r.isLt
  show (if _ : j.val < 4 * logw then _ else _) = _
  have hdiv : j.val / 2 = r.val := by omega
  have hlt : j.val / 2 < 2 * logw := by omega
  have hfin : (⟨j.val / 2, hlt⟩ : Fin (2 * logw)) = r := by apply Fin.ext; exact hdiv
  rw [dif_pos (by omega), if_neg (by omega)]
  exact congrArg (fun x => (P x).eval (pt2 : F)) hfin

omit [Fintype F] [DecidableEq F] in
@[simp] lemma honestVals_claimL {logw : ℕ} (P : Fin (2 * logw) → Polynomial F) (wl wr : F)
    (j : Fin (4 * logw + 2)) (hj : j.val = 4 * logw) : honestVals P wl wr j = wl := by
  show (if _ : j.val < 4 * logw then _ else _) = _
  rw [dif_neg (by omega), if_pos hj]

omit [Fintype F] [DecidableEq F] in
@[simp] lemma honestVals_claimR {logw : ℕ} (P : Fin (2 * logw) → Polynomial F) (wl wr : F)
    (j : Fin (4 * logw + 2)) (hj : j.val = 4 * logw + 1) : honestVals P wl wr j = wr := by
  show (if _ : j.val < 4 * logw then _ else _) = _
  rw [dif_neg (by omega), if_neg (by omega)]

/--
The rounds a transmission determines.  Round `r` reads slots `2r` and `2r+1` for its `tr[0]`
and `tr[2]`; the blinder indices and the challenge are public.
-/
noncomputable def roundsOf {logw M : ℕ} (pp0 pp2 : Fin (2 * logw) → Fin M)
    (chal : Fin (2 * logw) → F) (t : Fin (4 * logw + 2) → F) : List (RoundData M F) :=
  List.ofFn (fun r : Fin (2 * logw) =>
    ({ tr0 := t ⟨2 * r.val, by omega⟩
       tr2 := t ⟨2 * r.val + 1, by omega⟩
       pp0 := pp0 r
       pp2 := pp2 r
       chal := chal r } : RoundData M F))

/-- The encrypted transcript of the layer: those rounds, plus the two masked evaluations. -/
noncomputable def encOf {logw M : ℕ} (pp0 pp2 : Fin (2 * logw) → Fin M)
    (chal : Fin (2 * logw) → F) (t : Fin (4 * logw + 2) → F) : EncTranscript M F :=
  { rounds := roundsOf pp0 pp2 chal t
    wc0 := t ⟨4 * logw, by omega⟩
    wc1 := t ⟨4 * logw + 1, by omega⟩ }

omit [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma roundsOf_length {logw M : ℕ} (pp0 pp2 : Fin (2 * logw) → Fin M)
    (chal : Fin (2 * logw) → F) (t : Fin (4 * logw + 2) → F) :
    (roundsOf pp0 pp2 chal t).length = 2 * logw := by
  simp [roundsOf]

omit [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F] in
lemma run_challenges_eq_map {M : ℕ} (l : List (RoundData M F)) :
    run_challenges l = l.map RoundData.chal := by
  induction l with
  | nil => rfl
  | cons a tl ih => rw [run_challenges, ih]; rfl

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- The layer's challenge list is the challenge sequence, as `challenges_eq` would ask. -/
@[simp] lemma encOf_challenges {logw M : ℕ} (pp0 pp2 : Fin (2 * logw) → Fin M)
    (chal : Fin (2 * logw) → F) (t : Fin (4 * logw + 2) → F) :
    (encOf pp0 pp2 chal t).challenges = List.ofFn chal := by
  show run_challenges (roundsOf pp0 pp2 chal t) = _
  rw [run_challenges_eq_map, roundsOf, List.map_ofFn]
  rfl

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
@[simp] lemma encOf_rounds_length {logw M : ℕ} (pp0 pp2 : Fin (2 * logw) → Fin M)
    (chal : Fin (2 * logw) → F) (t : Fin (4 * logw + 2) → F) :
    (encOf pp0 pp2 chal t).rounds.length = 2 * logw := roundsOf_length _ _ _ _

omit [Fintype F] [DecidableEq F] in
/--
**The honest run's rounds carry the true polynomials.**

At round `r` the transmitted `tr[0]` is `P_r(0) − b(2r)` and the pad slot holds `b(2r)`, so
they add back to `P_r(0)`; likewise at `pt2`.  This is `padOfBlinders_blind` read at the two
round slots, and it is what `honestRounds_of_roundData` consumes.
-/
lemma honestRoundData_of_padOfBlinders {logw M : ℕ} (pi : ℕ)
    (pp0 pp2 : Fin (2 * logw) → Fin M) (chal : Fin (2 * logw) → F)
    (P : Fin (2 * logw) → Polynomial F) (wl wr : F) (base : Pad M F)
    (b : Fin (4 * logw + 2) → F)
    (h0 : ∀ r : Fin (2 * logw), (pp0 r : ℕ) = pi + PadLayout.blindIdx (2 * r.val))
    (h2 : ∀ r : Fin (2 * logw), (pp2 r : ℕ) = pi + PadLayout.blindIdx (2 * r.val + 1))
    (r : ℕ) (hr : r < (roundsOf pp0 pp2 chal
        (blindEquiv (honestVals P wl wr) b)).length)
    (hp : r < (List.ofFn P).length) :
    HonestRoundData ((roundsOf pp0 pp2 chal (blindEquiv (honestVals P wl wr) b)).get ⟨r, hr⟩)
      (padOfBlinders pi (4 * logw + 2) base b) ((List.ofFn P).get ⟨r, hp⟩) := by
  have hrlt : r < 2 * logw := by simpa using hr
  have hget : (roundsOf pp0 pp2 chal (blindEquiv (honestVals P wl wr) b)).get ⟨r, hr⟩
      = { tr0 := blindEquiv (honestVals P wl wr) b ⟨2 * r, by omega⟩
          tr2 := blindEquiv (honestVals P wl wr) b ⟨2 * r + 1, by omega⟩
          pp0 := pp0 ⟨r, hrlt⟩, pp2 := pp2 ⟨r, hrlt⟩, chal := chal ⟨r, hrlt⟩ } := by
    simp [roundsOf]
  have hPget : (List.ofFn P).get ⟨r, hp⟩ = P ⟨r, hrlt⟩ := by simp
  rw [hget, hPget, HonestRoundData]
  refine ⟨?_, ?_⟩
  · show blindEquiv (honestVals P wl wr) b ⟨2 * r, by omega⟩
        + padOfBlinders pi (4 * logw + 2) base b (pp0 ⟨r, hrlt⟩) = _
    rw [padOfBlinders_blind pi (4 * logw + 2) base b (honestVals P wl wr)
          ⟨2 * r, by omega⟩ (pp0 ⟨r, hrlt⟩) (by rw [h0 ⟨r, hrlt⟩])]
    exact honestVals_round0 P wl wr ⟨2 * r, by omega⟩ ⟨r, hrlt⟩ rfl
  · show blindEquiv (honestVals P wl wr) b ⟨2 * r + 1, by omega⟩
        + padOfBlinders pi (4 * logw + 2) base b (pp2 ⟨r, hrlt⟩) = _
    rw [padOfBlinders_blind pi (4 * logw + 2) base b (honestVals P wl wr)
          ⟨2 * r + 1, by omega⟩ (pp2 ⟨r, hrlt⟩) (by rw [h2 ⟨r, hrlt⟩])]
    exact honestVals_round2 P wl wr ⟨2 * r + 1, by omega⟩ ⟨r, hrlt⟩ rfl

omit [Fintype F] [DecidableEq F] in
/--
**The claim blinding, from the pad construction.**

`wc[0] = W[L] − dW[L]` is not an assumption about the prover: `blindEquiv` subtracts the
blinder and `padOfBlinders` puts that same blinder at the claim slot.
-/
lemma honestClaimBlinding_of_padOfBlinders {logw M : ℕ} (pi : ℕ)
    (P : Fin (2 * logw) → Polynomial F) (wl wr : F) (base : Pad M F)
    (b : Fin (4 * logw + 2) → F) (ivL ivR : Fin M)
    (hL : (ivL : ℕ) = pi + PadLayout.blindIdx (4 * logw))
    (hR : (ivR : ℕ) = pi + PadLayout.blindIdx (4 * logw + 1)) :
    HonestClaimBlinding (padOfBlinders pi (4 * logw + 2) base b)
      (blindEquiv (honestVals P wl wr) b ⟨4 * logw, by omega⟩)
      (blindEquiv (honestVals P wl wr) b ⟨4 * logw + 1, by omega⟩) wl wr ivL ivR := by
  constructor
  · have h := padOfBlinders_blind pi (4 * logw + 2) base b (honestVals P wl wr)
      ⟨4 * logw, by omega⟩ ivL hL
    rw [honestVals_claimL P wl wr ⟨4 * logw, by omega⟩ rfl] at h
    linear_combination h
  · have h := padOfBlinders_blind pi (4 * logw + 2) base b (honestVals P wl wr)
      ⟨4 * logw + 1, by omega⟩ ivR hR
    rw [honestVals_claimR P wl wr ⟨4 * logw + 1, by omega⟩ rfl] at h
    linear_combination h

/--
**The layer data a `ZkSetup` is built from.**

Everything here is public: the circuit and its layer-0 arithmetization, the pad base `pi`, and
the `PadLayout` slot assignment.  The laws say the slots really are the ones `PadLayout` gives,
which is what makes the blinding a one-time pad (`padIndices_distinct`).
-/
structure LayerSlots (logw M : ℕ) where
  /-- Pad base of this layer. -/
  pi : ℕ
  pp0 : Fin (2 * logw) → Fin M
  pp2 : Fin (2 * logw) → Fin M
  ivL : Fin M
  ivR : Fin M
  ivLR : Fin M
  hpp0 : ∀ r : Fin (2 * logw), (pp0 r : ℕ) = pi + PadLayout.blindIdx (2 * r.val)
  hpp2 : ∀ r : Fin (2 * logw), (pp2 r : ℕ) = pi + PadLayout.blindIdx (2 * r.val + 1)
  hivL : (ivL : ℕ) = pi + PadLayout.blindIdx (4 * logw)
  hivR : (ivR : ℕ) = pi + PadLayout.blindIdx (4 * logw + 1)
  /-- The quadratic slot sits just past the blinding block — `claimTriple_not_blinding`. -/
  hivLR : (ivLR : ℕ) = pi + PadLayout.blindIdx (4 * logw + 2)

/-- Outside the blinding block a layer's pad is only constrained at the quadratic slot, which
must hold `dW[L]·dW[R]`.  `claimTriple_not_blinding` is what makes that safe: it is never a
blinding slot, so it reveals nothing about the witness. -/
noncomputable def LayerSlots.quadBase {logw M : ℕ} (S : LayerSlots logw M)
    (b : Fin (4 * logw + 2) → F) : Pad M F :=
  fun i => if (i : ℕ) = S.pi + PadLayout.blindIdx (4 * logw + 2)
           then b ⟨4 * logw, by omega⟩ * b ⟨4 * logw + 1, by omega⟩ else 0

/-- The pad of a run: the blinders in the layer's block, the product at the quadratic slot. -/
noncomputable def LayerSlots.pad {logw M : ℕ} (S : LayerSlots logw M)
    (b : Fin (4 * logw + 2) → F) : Pad M F :=
  padOfBlinders S.pi (4 * logw + 2) (S.quadBase b) b

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
lemma LayerSlots.pad_ivL {logw M : ℕ} (S : LayerSlots logw M) (b : Fin (4 * logw + 2) → F) :
    S.pad b S.ivL = b ⟨4 * logw, by omega⟩ :=
  padOfBlinders_at S.pi (4 * logw + 2) (S.quadBase b) b ⟨4 * logw, by omega⟩ S.ivL S.hivL

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
lemma LayerSlots.pad_ivR {logw M : ℕ} (S : LayerSlots logw M) (b : Fin (4 * logw + 2) → F) :
    S.pad b S.ivR = b ⟨4 * logw + 1, by omega⟩ :=
  padOfBlinders_at S.pi (4 * logw + 2) (S.quadBase b) b ⟨4 * logw + 1, by omega⟩ S.ivR S.hivR

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- The quadratic triple holds by construction. -/
lemma LayerSlots.pad_quad {logw M : ℕ} (S : LayerSlots logw M) (b : Fin (4 * logw + 2) → F) :
    S.pad b S.ivLR = S.pad b S.ivL * S.pad b S.ivR := by
  rw [S.pad_ivL, S.pad_ivR]
  show padOfBlinders S.pi (4 * logw + 2) (S.quadBase b) b S.ivLR = _
  rw [padOfBlinders_outside _ _ _ _ _
    (by rw [S.hivLR]; simp only [PadLayout.blindIdx]; omega)]
  show (if (S.ivLR : ℕ) = S.pi + PadLayout.blindIdx (4 * logw + 2) then _ else _) = _
  rw [if_pos S.hivLR]

omit [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- On the ZK path `logc = 0`, so a copy point is the unique element of `Vector F 0`.  With
`ZkSetup.wcol` taking the challenges this is no longer needed to state the layer setup — the
copy point is read off `challenge_split` — but it records why the layer's own `q` and the
challenge-derived one coincide there. -/
lemma copy_subsingleton (u v : Vector F 0) : u = v :=
  Vector.ext (fun i hi => absurd hi (by omega))

/--
**A `ZkSetup` for one layer of a real run.**

Assembled entirely from the model's own pieces: the transcript shape `encOf`, the `PadLayout`
slots `S`, the pad `S.pad`, and the layer arithmetization of an `ArithmetizedCircuit`.  The
layer **has rounds** — `2·logw` of them — and all `4·logw + 2` blinding slots are live.

`alpha` and `beta` are the layer's own challenges, drawn together by `begin_layer`; `alpha_in`
is the separate one drawn after the layer loop closes
(`symbolic_sumcheck_verifier.rs:L247`) and only the input row reads it — its coefficients, the
public binding, the combined claim `got` and the second claim pad's coefficient.  Sharing one
draw between the two would make the model stronger than the protocol: it would let them fail
together on one unlucky draw, which no prover can arrange.

The hypotheses are the honest prover's own situation, not restrictions on an adversary:

* `hsat` — every witness satisfies the circuit, so the run starts from the claim `0`.  ZK is a
  statement about honest provers, so this is the right shape.
* `hdeg` — the honest round polynomials have degree `≤ 2`, which
  `ArithmetizedCircuit.round_poly_natDegree_le_two` supplies.
* `htrue` — the family `P` fed to `honestVals` really is the honest one.

`honest_sat` is **derived**.  `honest_buildSystem_Sat` reduces it to the pad's quadratic slot
(`LayerSlots.pad_quad`), the final claim (`honest_final_claim`, fed by
`honestRounds_of_roundData` and `honestRoundData_of_padOfBlinders`) and the claim blinding
(`honestClaimBlinding_of_padOfBlinders`) — plus public-input consistency and the input-row
identity, both of which the soundness side already proves.
-/
noncomputable def zkSetupOfLayer
    {nc nv ninp npub logv logw M : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (w_ref : Witness) (alpha beta alpha_in : F)
    (q : Vector F 0) (g0 g1 : Vector F logv) (S : LayerSlots logw M)
    (P : Witness → (Fin (2 * logw) → F) → Fin (2 * logw) → Polynomial F)
    (hpos : 0 < 0 + 2 * logw)
    (hdeg : ∀ w chal r, (P w chal r).natDegree ≤ 2)
    (htrue : ∀ w chal, List.ofFn (P w chal)
      = generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
          (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1)
          (chalVec (List.ofFn chal) (0 + 2 * logw)))
    (hcons : ∀ w chal, consistent_true_polys (List.ofFn (P w chal)) (List.ofFn chal))
    (hsat : ∀ w, layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w)
      alpha q g0 g1 = 0) :
    ZkSetup ninp M (4 * logw + 2) F Witness (Fin (2 * logw) → F) where
  honest := fun w chal =>
    honestVals (P w chal)
      (true_evals AC inp w (List.ofFn chal)).1 (true_evals AC inp w (List.ofFn chal)).2
  padOf := fun b => S.pad b
  wcol := fun w chal =>
    AC.W_col inp w (challenge_split (logw := logw) (logc := 0) (List.ofFn chal)).1
  sys := fun chal t =>
    buildSystem npub (encOf S.pp0 S.pp2 chal t).e
      (layer_eqq AC c alpha beta q g0 g1 (List.ofFn chal))
      (encOf S.pp0 S.pp2 chal t).wc0 (encOf S.pp0 S.pp2 chal t).wc1
      (input_row_coeffs (logw := logw) (logc := 0) (ninp := ninp) alpha_in (List.ofFn chal))
      (pubBinding AC inp w_ref alpha_in (List.ofFn chal)) alpha_in S.ivL S.ivR S.ivLR
  honest_sat := by
    intro w chal b
    set wl := (true_evals AC inp w (List.ofFn chal)).1 with hwl
    set wr := (true_evals AC inp w (List.ofFn chal)).2 with hwr
    set t := blindEquiv (honestVals (P w chal) wl wr) b with ht
    set E := encOf S.pp0 S.pp2 chal t with hE
    -- the layer's challenge list, and its length
    have hch : E.challenges = List.ofFn chal := encOf_challenges _ _ _ _
    have hlen : E.challenges.length = 0 + 2 * logw := by rw [hch]; simp
    -- the honest rounds carry the true polynomials
    have hh0 : HonestRounds (List.ofFn (P w chal)) (E.polys (S.pad b)) E.challenges :=
      honestRounds_of_roundData (roundsOf S.pp0 S.pp2 chal t) (List.ofFn (P w chal))
        (S.pad b) 0 (by simp) (fun Q hQ => by
          obtain ⟨r, rfl⟩ := List.mem_ofFn.mp hQ; exact hdeg w chal r)
        (fun r hr hp => honestRoundData_of_padOfBlinders S.pi S.pp0 S.pp2 chal (P w chal)
          wl wr (S.quadBase b) b S.hpp0 S.hpp2 r hr hp)
        (by rw [run_challenges_eq_map, roundsOf, List.map_ofFn]; exact hcons w chal)
        (by
          have hhead := head_generate (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
            (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1)
            (chalVec (List.ofFn chal) (0 + 2 * logw)) hpos
          rw [htrue w chal, hhead]
          exact (hsat w).symm)
        (by simp [roundsOf]; omega)
    have hh : HonestRounds
        (generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
          (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1)
          (chalVec E.challenges (0 + 2 * logw))) (E.polys (S.pad b)) E.challenges := by
      rw [hch] at hh0 ⊢
      rw [← htrue w chal]
      exact hh0
    -- the claim blinding
    have hblind : HonestClaimBlinding (S.pad b) E.wc0 E.wc1 wl wr S.ivL S.ivR :=
      honestClaimBlinding_of_padOfBlinders S.pi (P w chal) wl wr (S.quadBase b) b
        S.ivL S.ivR S.hivL S.hivR
    have hblind' : HonestClaimBlinding (S.pad b) E.wc0 E.wc1
        (true_evals AC inp w E.challenges).1 (true_evals AC inp w E.challenges).2
        S.ivL S.ivR := by rw [hch]; exact hblind
    refine honest_buildSystem_Sat npub E.e (S.pad b)
      (layer_eqq AC c alpha beta q g0 g1 (List.ofFn chal)) E.wc0 E.wc1
      (input_row_coeffs (logw := logw) (logc := 0) (ninp := ninp) alpha_in (List.ofFn chal))
      (pubBinding AC inp w_ref alpha_in (List.ofFn chal)) alpha_in wl wr
      S.ivL S.ivR S.ivLR
      (AC.W_col inp w (challenge_split (logw := logw) (logc := 0) (List.ofFn chal)).1)
      (S.pad_quad b) ?_ hblind ?_ ?_
    · -- the final claim
      have hfc := honest_final_claim AC c inp w alpha beta q g0 g1 E (S.pad b) S.ivL S.ivR
        hpos hlen hh (hsat w) hblind'
      rwa [hch] at hfc
    · -- public-input consistency
      exact pub_consistent_of_indep (AC := AC) inp w_ref w alpha_in (List.ofFn chal)
    · -- the weighted column sum is the alpha_in-combination of the honest evaluations
      have hmle := input_row_coeffs_give_mle AC inp w
        (challenge_split (logw := logw) (logc := 0) (List.ofFn chal)).1
        (challenge_split (logw := logw) (logc := 0) (List.ofFn chal)).2.1
        (challenge_split (logw := logw) (logc := 0) (List.ofFn chal)).2.2 alpha_in
      simp only [input_row_coeffs, hwl, hwr, true_evals]
      exact hmle

/-!
## A whole run: `nl` layers

`zkSetupOfLayer` is one layer.  A run is `nl` of them sharing a pad, with `buildSystemMulti`'s
rows: one layer row and one quadratic triple per layer, then a single input row from the last
layer's `wc`s (`zk_common.h:L128-L133`).

`RunPad` states the layout as data with laws, and `stdRunPad` **constructs** the standard one:
`PadLayout` places layer `ly` at base `ly · layerSize logw` with windows that *overlap* by the
claim triple (`claim_pad_overlap`), and the run's pad is nevertheless well defined because the
blinding blocks are globally disjoint (`PadLayout.blindSlot_inj`) and no layer's quadratic slot
is any layer's blinding slot (`PadLayout.quadSlot_ne_blindSlot`).
-/

/--
**The pad of a whole run.**

`slots ly` is layer `ly`'s slot assignment; `gidx ly k` says where layer `ly`'s blinder `k`
lives in the run's blinder vector.  The two laws are what the hiding argument uses: at a
blinding slot the pad holds the corresponding run blinder, and each layer's quadratic slot
holds the product of its own two claim blinders.

-/
structure RunPad (logw nl M nb : ℕ) (F : Type) [Field F] where
  slots : Fin nl → LayerSlots logw M
  /-- Where layer `ly`'s blinder `k` sits in the run's blinder vector.  A *bijection*: the
  run's blinders are exactly the layers' blinders, none shared and none spare.  That is the
  content of `layer_blind_disjoint`, and it is what lets `ZkSetup.honest` — one vector over the
  whole run — restrict to each layer's own transmission. -/
  gidx : Fin nl × Fin (4 * logw + 2) ≃ Fin nb
  pad : (Fin nb → F) → Pad M F
  pad_blind : ∀ (b : Fin nb → F) (ly : Fin nl) (k : Fin (4 * logw + 2)) (i : Fin M),
    (i : ℕ) = (slots ly).pi + PadLayout.blindIdx k.val → pad b i = b (gidx (ly, k))
  pad_quad : ∀ (b : Fin nb → F) (ly : Fin nl),
    pad b (slots ly).ivLR = pad b (slots ly).ivL * pad b (slots ly).ivR

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- A one-layer run: `LayerSlots.pad` inhabits `RunPad` directly, at `nb = 4·logw + 2` rather
than `1 · (4·logw + 2)`.  `stdRunPad` below is the general construction; this one is kept
because it lets a single layer be placed anywhere, at any `pi`, without the run's stride. -/
noncomputable def RunPad.ofSingle {logw M : ℕ} (S : LayerSlots logw M) :
    RunPad logw 1 M (4 * logw + 2) F where
  slots := fun _ => S
  gidx :=
    { toFun := fun p => p.2
      invFun := fun k => (⟨0, by omega⟩, k)
      left_inv := by rintro ⟨⟨a, ha⟩, k⟩; exact Prod.ext (Fin.ext (by omega)) rfl
      right_inv := fun _ => rfl }
  pad := fun b => S.pad b
  pad_blind := fun b _ k i hi => padOfBlinders_at S.pi (4 * logw + 2) (S.quadBase b) b k i hi
  pad_quad := fun b _ => S.pad_quad b

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- The two claim blinders of layer `ly`, read off the pad. -/
lemma RunPad.pad_ivL {logw nl M nb : ℕ} (R : RunPad logw nl M nb F) (b : Fin nb → F)
    (ly : Fin nl) : R.pad b (R.slots ly).ivL = b (R.gidx (ly, ⟨4 * logw, by omega⟩)) :=
  R.pad_blind b ly ⟨4 * logw, by omega⟩ (R.slots ly).ivL (R.slots ly).hivL

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
lemma RunPad.pad_ivR {logw nl M nb : ℕ} (R : RunPad logw nl M nb F) (b : Fin nb → F)
    (ly : Fin nl) : R.pad b (R.slots ly).ivR = b (R.gidx (ly, ⟨4 * logw + 1, by omega⟩)) :=
  R.pad_blind b ly ⟨4 * logw + 1, by omega⟩ (R.slots ly).ivR (R.slots ly).hivR

/-!
### The standard layout, computed

`RunPad.ofSingle` shows the interface is inhabited.  What follows builds the layout the
implementation actually uses, for **any** number of layers: layer `ly` sits at base
`ly · layerSize logw`, its blinders occupy the contiguous block `blindSlot logw ly ·`, and its
quadratic slot is `quadSlot logw ly`.

The pad is a *function of the run's blinder vector*, defined by asking which layer-and-blinder
pair a given index is.  That question has at most one answer — `PadLayout.blindSlot_inj` — and
an index that is no layer's blinder but is some layer's quadratic slot has exactly one answer
there too (`PadLayout.quadSlot_inj`), which is what makes the definition well posed.  No
division by the symbolic stride is needed: the search is over the finitely many layers.
-/

/-- Layer `ly`'s `PadLayout` slots inside a run's pad of size `M`. -/
noncomputable def stdSlots (logw nl M : ℕ) (hM : nl * PadLayout.layerSize logw + 3 ≤ M)
    (ly : Fin nl) : LayerSlots logw M where
  pi := PadLayout.layerBase logw ly.val
  pp0 := fun r => ⟨PadLayout.blindSlot logw ly.val (2 * r.val),
    lt_of_lt_of_le (PadLayout.blindSlot_lt_pad logw nl ly.val (2 * r.val) ly.isLt
      (by have := r.isLt; omega)) hM⟩
  pp2 := fun r => ⟨PadLayout.blindSlot logw ly.val (2 * r.val + 1),
    lt_of_lt_of_le (PadLayout.blindSlot_lt_pad logw nl ly.val (2 * r.val + 1) ly.isLt
      (by have := r.isLt; omega)) hM⟩
  ivL := ⟨PadLayout.blindSlot logw ly.val (4 * logw),
    lt_of_lt_of_le (PadLayout.blindSlot_lt_pad logw nl ly.val (4 * logw) ly.isLt (by omega)) hM⟩
  ivR := ⟨PadLayout.blindSlot logw ly.val (4 * logw + 1),
    lt_of_lt_of_le (PadLayout.blindSlot_lt_pad logw nl ly.val (4 * logw + 1) ly.isLt
      (by omega)) hM⟩
  ivLR := ⟨PadLayout.quadSlot logw ly.val,
    lt_of_lt_of_le (PadLayout.quadSlot_lt_pad logw nl ly.val ly.isLt) hM⟩
  hpp0 := fun _ => rfl
  hpp2 := fun _ => rfl
  hivL := rfl
  hivR := rfl
  hivLR := rfl

/--
**The run's pad, computed from its blinder vector.**

At a blinding slot it holds that blinder; at a layer's quadratic slot the product of that
layer's two claim blinders; elsewhere `0`.  The two `Exists.choose`s are single-valued by
`blindSlot_inj` and `quadSlot_inj`, which is what `stdPad_blind` and `stdPad_quad` extract.
-/
noncomputable def stdPad {logw nl M nb : ℕ} (gidx : Fin nl × Fin (4 * logw + 2) ≃ Fin nb)
    (b : Fin nb → F) : Pad M F :=
  fun i =>
    if h : ∃ p : Fin nl × Fin (4 * logw + 2),
        (i : ℕ) = PadLayout.blindSlot logw p.1.val p.2.val then
      b (gidx h.choose)
    else if h2 : ∃ ly : Fin nl, (i : ℕ) = PadLayout.quadSlot logw ly.val then
      b (gidx (h2.choose, ⟨4 * logw, by omega⟩)) *
        b (gidx (h2.choose, ⟨4 * logw + 1, by omega⟩))
    else 0

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- At layer `ly`'s blinder `k`, the run's pad holds that blinder. -/
lemma stdPad_blind {logw nl M nb : ℕ} (gidx : Fin nl × Fin (4 * logw + 2) ≃ Fin nb)
    (b : Fin nb → F) (ly : Fin nl) (k : Fin (4 * logw + 2)) (i : Fin M)
    (hi : (i : ℕ) = PadLayout.blindSlot logw ly.val k.val) :
    stdPad (M := M) gidx b i = b (gidx (ly, k)) := by
  have hex : ∃ p : Fin nl × Fin (4 * logw + 2),
      (i : ℕ) = PadLayout.blindSlot logw p.1.val p.2.val := ⟨(ly, k), hi⟩
  show (if h : ∃ p : Fin nl × Fin (4 * logw + 2),
      (i : ℕ) = PadLayout.blindSlot logw p.1.val p.2.val then _ else _) = _
  rw [dif_pos hex]
  have hs := hex.choose_spec
  obtain ⟨h1, h2⟩ := PadLayout.blindSlot_inj hex.choose.2.isLt k.isLt (hs.symm.trans hi)
  have : hex.choose = (ly, k) := Prod.ext (Fin.ext h1) (Fin.ext h2)
  rw [this]

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- At layer `ly`'s quadratic slot, the run's pad holds the product of that layer's two claim
blinders.  The first branch cannot fire: `quadSlot_ne_blindSlot` says the slot is no layer's
blinder. -/
lemma stdPad_quadAt {logw nl M nb : ℕ} (gidx : Fin nl × Fin (4 * logw + 2) ≃ Fin nb)
    (b : Fin nb → F) (ly : Fin nl) (i : Fin M)
    (hi : (i : ℕ) = PadLayout.quadSlot logw ly.val) :
    stdPad (M := M) gidx b i
      = b (gidx (ly, ⟨4 * logw, by omega⟩)) * b (gidx (ly, ⟨4 * logw + 1, by omega⟩)) := by
  have hne : ¬ ∃ p : Fin nl × Fin (4 * logw + 2),
      (i : ℕ) = PadLayout.blindSlot logw p.1.val p.2.val := by
    rintro ⟨p, hp⟩
    exact PadLayout.quadSlot_ne_blindSlot logw ly.val p.1.val p.2.val p.2.isLt
      (hi.symm.trans hp)
  have hex : ∃ l : Fin nl, (i : ℕ) = PadLayout.quadSlot logw l.val := ⟨ly, hi⟩
  show (if h : ∃ p : Fin nl × Fin (4 * logw + 2),
      (i : ℕ) = PadLayout.blindSlot logw p.1.val p.2.val then _ else _) = _
  rw [dif_neg hne, dif_pos hex]
  have hs := hex.choose_spec
  have hc : hex.choose = ly := Fin.ext (PadLayout.quadSlot_inj (hs.symm.trans hi))
  rw [hc]

/--
**The standard `RunPad`, for any number of layers.**

`gidx` is `finProdFinEquiv`: the run has exactly `nl · (4·logw + 2)` blinders, one per layer per
transmitted value, which is what the `Equiv` in `RunPad` asks for.  The pad is `stdPad`; both
laws are the two lemmas above.  `hM` is the pad size `zk_common.h` allocates — the stride times
the layer count, plus the trailing claim triple.
-/
noncomputable def stdRunPad (logw nl M : ℕ) (hM : nl * PadLayout.layerSize logw + 3 ≤ M) :
    RunPad logw nl M (nl * (4 * logw + 2)) F where
  slots := stdSlots logw nl M hM
  gidx := finProdFinEquiv
  pad := fun b => stdPad finProdFinEquiv b
  pad_blind := fun b ly k i hi => stdPad_blind finProdFinEquiv b ly k i hi
  pad_quad := fun b ly => by
    rw [stdPad_quadAt finProdFinEquiv b ly (stdSlots logw nl M hM ly).ivLR rfl,
        stdPad_blind finProdFinEquiv b ly ⟨4 * logw, by omega⟩
          (stdSlots logw nl M hM ly).ivL rfl,
        stdPad_blind finProdFinEquiv b ly ⟨4 * logw + 1, by omega⟩
          (stdSlots logw nl M hM ly).ivR rfl]

omit [Fintype F] [DecidableEq F] in
/--
**The honest run's rounds carry the true polynomials, at layer `ly` of a run.**

The single-layer version read the blinder straight out of the layer's own block; here it goes
through `gidx`, so the run's blinder vector is shared across layers while each layer still sees
its own slots.
-/
lemma runHonestRoundData {logw nl M nb : ℕ} (R : RunPad logw nl M nb F) (ly : Fin nl)
    (chal : Fin (2 * logw) → F) (P : Fin (2 * logw) → Polynomial F) (wl wr : F)
    (b : Fin nb → F) (t : Fin (4 * logw + 2) → F)
    (ht : ∀ k, t k = honestVals P wl wr k - b (R.gidx (ly, k)))
    (r : ℕ) (hr : r < (roundsOf (R.slots ly).pp0 (R.slots ly).pp2 chal t).length)
    (hp : r < (List.ofFn P).length) :
    HonestRoundData ((roundsOf (R.slots ly).pp0 (R.slots ly).pp2 chal t).get ⟨r, hr⟩)
      (R.pad b) ((List.ofFn P).get ⟨r, hp⟩) := by
  have hrlt : r < 2 * logw := by simpa using hr
  have hget : (roundsOf (R.slots ly).pp0 (R.slots ly).pp2 chal t).get ⟨r, hr⟩
      = { tr0 := t ⟨2 * r, by omega⟩, tr2 := t ⟨2 * r + 1, by omega⟩
          pp0 := (R.slots ly).pp0 ⟨r, hrlt⟩, pp2 := (R.slots ly).pp2 ⟨r, hrlt⟩
          chal := chal ⟨r, hrlt⟩ } := by
    simp [roundsOf]
  have hPget : (List.ofFn P).get ⟨r, hp⟩ = P ⟨r, hrlt⟩ := by simp
  rw [hget, hPget, HonestRoundData]
  refine ⟨?_, ?_⟩
  · show t ⟨2 * r, by omega⟩ + R.pad b ((R.slots ly).pp0 ⟨r, hrlt⟩) = _
    rw [ht ⟨2 * r, by omega⟩,
        R.pad_blind b ly ⟨2 * r, by omega⟩ ((R.slots ly).pp0 ⟨r, hrlt⟩)
          (by rw [(R.slots ly).hpp0 ⟨r, hrlt⟩]),
        honestVals_round0 P wl wr ⟨2 * r, by omega⟩ ⟨r, hrlt⟩ rfl]
    ring
  · show t ⟨2 * r + 1, by omega⟩ + R.pad b ((R.slots ly).pp2 ⟨r, hrlt⟩) = _
    rw [ht ⟨2 * r + 1, by omega⟩,
        R.pad_blind b ly ⟨2 * r + 1, by omega⟩ ((R.slots ly).pp2 ⟨r, hrlt⟩)
          (by rw [(R.slots ly).hpp2 ⟨r, hrlt⟩]),
        honestVals_round2 P wl wr ⟨2 * r + 1, by omega⟩ ⟨r, hrlt⟩ rfl]
    ring

omit [Fintype F] [DecidableEq F] in
/-- The claim blinding at layer `ly` of a run. -/
lemma runHonestClaimBlinding {logw nl M nb : ℕ} (R : RunPad logw nl M nb F) (ly : Fin nl)
    (P : Fin (2 * logw) → Polynomial F) (wl wr : F) (b : Fin nb → F)
    (t : Fin (4 * logw + 2) → F)
    (ht : ∀ k, t k = honestVals P wl wr k - b (R.gidx (ly, k))) :
    HonestClaimBlinding (R.pad b) (t ⟨4 * logw, by omega⟩) (t ⟨4 * logw + 1, by omega⟩)
      wl wr (R.slots ly).ivL (R.slots ly).ivR := by
  refine ⟨?_, ?_⟩
  · rw [ht ⟨4 * logw, by omega⟩, R.pad_ivL b ly,
        honestVals_claimL P wl wr ⟨4 * logw, by omega⟩ rfl]
  · rw [ht ⟨4 * logw + 1, by omega⟩, R.pad_ivR b ly,
        honestVals_claimR P wl wr ⟨4 * logw + 1, by omega⟩ rfl]

/-- The starting expression of layer `ly`: `Expression.zero` at layer 0, matching
`claims_state.claim = [zero, zero]`, and `ConstraintBuilder::first` on the previous layer's
`wc`s and claim pads otherwise (`zk_common.h:L328-L329`).  Witness-free: it reads only the
transmission and public slot data.

The `alpha` it combines the previous layer's two claims with is **this** layer's, drawn by
`begin_layer` at the top of iteration `ly` (`symbolic_sumcheck_verifier.rs:L73`) — which is why
the schedule is a parameter and the layer index selects from it.  `zkExpr` on the soundness
side reads it the same way, off `zl.alpha` of the layer being entered. -/
noncomputable def runStartExpr {logw nl M nb : ℕ} (R : RunPad logw nl M nb F)
    (alphas : Fin nl → F) (T : Fin nl → Fin (4 * logw + 2) → F) (ly : Fin nl) :
    Expression M F :=
  if h : ly.val = 0 then Expression.zero M F
  else
    builder_first (alphas ly)
      (T ⟨ly.val - 1, by omega⟩ ⟨4 * logw, by omega⟩)
      (T ⟨ly.val - 1, by omega⟩ ⟨4 * logw + 1, by omega⟩)
      (R.slots ⟨ly.val - 1, by omega⟩).ivL (R.slots ⟨ly.val - 1, by omega⟩).ivR

/-- Layer `ly`'s row data, as `buildSystemMulti` wants it.  Every field is public or
transmitted; there is no `Witness` argument. -/
noncomputable def runLayerData {logw nl M nb : ℕ} (R : RunPad logw nl M nb F)
    (chal : Fin nl → Fin (2 * logw) → F) (eqq : Fin nl → F) (alphas : Fin nl → F)
    (T : Fin nl → Fin (4 * logw + 2) → F) (ly : Fin nl) : LayerRowData M F :=
  { e := builder_run (runStartExpr R alphas T ly)
           (roundsOf (R.slots ly).pp0 (R.slots ly).pp2 (chal ly) (T ly))
    eqq := eqq ly
    wc0 := T ly ⟨4 * logw, by omega⟩
    wc1 := T ly ⟨4 * logw + 1, by omega⟩
    var_dwL := (R.slots ly).ivL
    var_dwR := (R.slots ly).ivR
    var_dwLR := (R.slots ly).ivLR }

/-- The run's transmission, split back into per-layer blocks along `gidx`. -/
noncomputable def runSplit {logw nl M nb : ℕ} (R : RunPad logw nl M nb F)
    (t : Fin nb → F) : Fin nl → Fin (4 * logw + 2) → F :=
  fun ly k => t (R.gidx (ly, k))

/-- The run's honest transmission: each layer's `honestVals`, transported along `gidx`. -/
noncomputable def runHonest {logw nl M nb : ℕ} (R : RunPad logw nl M nb F)
    (P : Fin nl → Fin (2 * logw) → Polynomial F) (wl wr : Fin nl → F) : Fin nb → F :=
  fun j => honestVals (P (R.gidx.symm j).1) (wl (R.gidx.symm j).1) (wr (R.gidx.symm j).1)
    (R.gidx.symm j).2

omit [Fintype F] [DecidableEq F] in
/-- Splitting the blinded run transmission gives each layer its own blinded transmission —
the shape `runHonestRoundData` and `runHonestClaimBlinding` consume. -/
lemma runSplit_blindEquiv {logw nl M nb : ℕ} (R : RunPad logw nl M nb F)
    (P : Fin nl → Fin (2 * logw) → Polynomial F) (wl wr : Fin nl → F) (b : Fin nb → F)
    (ly : Fin nl) (k : Fin (4 * logw + 2)) :
    runSplit R (blindEquiv (runHonest R P wl wr) b) ly k
      = honestVals (P ly) (wl ly) (wr ly) k - b (R.gidx (ly, k)) := by
  show runHonest R P wl wr (R.gidx (ly, k)) - b (R.gidx (ly, k)) = _
  rw [runHonest]
  simp only [Equiv.symm_apply_apply]

/--
**A run's verifier challenges, on the runtime's schedule.**

Every challenge the verifier sends, in the shape the runtime draws them:

| field | drawn by | read by |
|---|---|---|
| `rounds ly` | `round`, one per message of layer `ly` | the round reduction |
| `alphas ly`, `betas ly` | `begin_layer`, at the top of iteration `ly` (`symbolic_sumcheck_verifier.rs:L73`) | layer `ly`'s claim combination and `prep_v` |
| `alpha_in` | `transcript.elt_field` after the whole layer loop (`symbolic_sumcheck_verifier.rs:L247`) | the input row |

The distinction between `alphas` and `alpha_in` is the same one the soundness side draws
(`ligero.lean`, "Three challenges, not two"): sharing one draw between the layer relation and
the input binding would let them fail together, which is not something a prover can arrange.
`alphas` being a *schedule* rather than one element matters for the same reason across layers.

`ZkSetup` quantifies `honest_sat` over this type, so a `ZkSetup` at `RunChal` is HVZK at every
challenge sequence, not at one.
-/
structure RunChal (logw nl : ℕ) (F : Type) where
  /-- Layer `ly`'s `2·logw` sumcheck challenges. -/
  rounds : Fin nl → Fin (2 * logw) → F
  /-- Layer `ly`'s claim-combining challenge, drawn by `begin_layer`. -/
  alphas : Fin nl → F
  /-- Layer `ly`'s assert-zero coefficient, drawn by `begin_layer` alongside `alphas ly`. -/
  betas : Fin nl → F
  /-- The fresh challenge drawn after every layer has closed; only the input row reads it. -/
  alpha_in : F

/--
**`hclaim` derived, layer by layer.**

`zkSetupOfRun` takes the per-layer final claims as a parameter.  They are not an assumption
about the prover: this lemma produces exactly that parameter from the honest run's own data,
by `honest_final_claim_from` fed through `honestRounds_of_roundData` and the run's blinding.

The starting expression is a parameter, which is the point — `runStartExpr` supplies
`Expression.zero` at layer 0 and `ConstraintBuilder::first` at an interior layer, and `hstart`
is the one fact that distinguishes them: the layer is entered on the claim the layer relation
predicts.
-/
theorem runHonestFinalClaim {nc nv ninp npub logv logw nl M nb : ℕ}
    (R : RunPad logw nl M nb F) (c : RunChal logw nl F)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (crc : Circuit) (inp : Input) (q : Vector F 0) (g0 g1 : Vector F logv)
    (w : Witness) (b : Fin nb → F) (ly : Fin nl) (e₀ : Expression M F)
    (P : Fin (2 * logw) → Polynomial F) (wl wr : F) (t : Fin (4 * logw + 2) → F)
    (ht : ∀ k, t k = honestVals P wl wr k - b (R.gidx (ly, k)))
    (hpos : 0 < 0 + 2 * logw)
    (hdeg : ∀ r, (P r).natDegree ≤ 2)
    (htrue : List.ofFn P = generate_true_polys
      (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
        (AC.Quad_mle crc (c.betas ly)) (AC.W_mle inp w) (c.alphas ly) q g0 g1)
      (chalVec (List.ofFn (c.rounds ly)) (0 + 2 * logw)))
    (hcons : consistent_true_polys (List.ofFn P) (List.ofFn (c.rounds ly)))
    (hstart : evaluates_to e₀ (R.pad b)
      = layer_claim (nc := nc) (nv := nv) (AC.Quad_mle crc (c.betas ly)) (AC.W_mle inp w)
          (c.alphas ly) q g0 g1)
    (hwl : wl = (true_evals AC inp w (List.ofFn (c.rounds ly))).1)
    (hwr : wr = (true_evals AC inp w (List.ofFn (c.rounds ly))).2) :
    HonestFinalClaim
      (builder_run e₀ (roundsOf (R.slots ly).pp0 (R.slots ly).pp2 (c.rounds ly) t))
      (R.pad b)
      (layer_eqq AC crc (c.alphas ly) (c.betas ly) q g0 g1 (List.ofFn (c.rounds ly)))
      (t ⟨4 * logw, by omega⟩) (t ⟨4 * logw + 1, by omega⟩)
      (R.slots ly).ivL (R.slots ly).ivR := by
  classical
  set rds := roundsOf (R.slots ly).pp0 (R.slots ly).pp2 (c.rounds ly) t with hrds
  have hch : run_challenges rds = List.ofFn (c.rounds ly) := by
    rw [hrds, run_challenges_eq_map, roundsOf, List.map_ofFn]; rfl
  have hlen : (run_challenges rds).length = 0 + 2 * logw := by rw [hch]; simp
  -- the run's rounds carry the true polynomials
  have hh0 : HonestRounds (List.ofFn P) (run_polys (R.pad b) (evaluates_to e₀ (R.pad b)) rds)
      (run_challenges rds) :=
    honestRounds_of_roundData rds (List.ofFn P) (R.pad b) (evaluates_to e₀ (R.pad b))
      (by simp [hrds]) (fun Q hQ => by obtain ⟨r, rfl⟩ := List.mem_ofFn.mp hQ; exact hdeg r)
      (fun r hr hp => runHonestRoundData R ly (c.rounds ly) P wl wr b t ht r hr hp)
      (by rw [hch]; exact hcons)
      (by
        have hhead := head_generate (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
          (AC.Quad_mle crc (c.betas ly)) (AC.W_mle inp w) (c.alphas ly) q g0 g1)
          (chalVec (List.ofFn (c.rounds ly)) (0 + 2 * logw)) hpos
        rw [htrue, hhead]
        exact hstart)
      (by simp [hrds, roundsOf]; omega)
  have hh : HonestRounds
      (generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
        (AC.Quad_mle crc (c.betas ly)) (AC.W_mle inp w) (c.alphas ly) q g0 g1)
        (chalVec (run_challenges rds) (0 + 2 * logw)))
      (run_polys (R.pad b) (evaluates_to e₀ (R.pad b)) rds) (run_challenges rds) := by
    rw [hch] at hh0 ⊢
    rw [← htrue]
    exact hh0
  -- the claim blinding
  have hblind := runHonestClaimBlinding R ly P wl wr b t ht
  rw [hwl, hwr] at hblind
  have hfc := honest_final_claim_from AC crc inp w (c.alphas ly) (c.betas ly) q g0 g1
    rds e₀ (R.pad b) (t ⟨4 * logw, by omega⟩) (t ⟨4 * logw + 1, by omega⟩)
    (R.slots ly).ivL (R.slots ly).ivR hpos hlen hh hstart (by rwa [hch])
  rwa [hch] at hfc

/--
**A `ZkSetup` for a whole `nl`-layer run, at every challenge sequence.**

The rows are `buildSystemMulti`'s: one layer row and one quadratic triple per layer, then the
single input row taken from the **last** layer's `wc`s (`zk_common.h:L128-L133`).  The pad is
the run's, shared across layers, and every layer's `4·logw + 2` blinding slots are live — `gidx`
being an `Equiv` says the run's blinders are exactly the layers' blinders.

`Chal` is `RunChal`, so this is HVZK **at every challenge sequence**.  Everything the
challenges determine is therefore a function of them: the honest round polynomials `P`, the
hand evaluations `wl`, `wr`, the layer coefficients `eqq`, the input-row coefficients `bcoef`
and the public binding `pub_binding`.  `wcolOf` is *not* — the committed input columns are the
witness's, fixed before any challenge is sent, which is what makes the sumcheck sound.

The challenges are read **where the runtime reads them**: layer `ly`'s start expression takes
`alphas ly`, and only the input row takes `alpha_in`.

`honest_sat` is derived from `honest_buildSystemMulti_Sat`.  The per-layer obligations are
`RunPad.pad_quad` and `hclaim`; `hclaim` is what `honest_final_claim_from` discharges, and the
reason that generalisation was needed is here — interior layers start from
`ConstraintBuilder::first`, not `Expression.zero`, which is exactly `runStartExpr`.
-/
noncomputable def zkSetupOfRun {ninp npub logw nl M nb : ℕ}
    (R : RunPad logw nl M nb F) (last : Fin nl)
    (eqq : RunChal logw nl F → Fin nl → F)
    (P : Witness → RunChal logw nl F → Fin nl → Fin (2 * logw) → Polynomial F)
    (wl wr : Witness → RunChal logw nl F → Fin nl → F)
    (wcolOf : Witness → RunChal logw nl F → Fin ninp → F)
    (bcoef : RunChal logw nl F → Fin ninp → F) (pub_binding : RunChal logw nl F → F)
    (hpub : ∀ w c, pub_binding c
      = ∑ i ∈ Finset.univ \ privIdx ninp npub, bcoef c i * wcolOf w c i)
    (hmle : ∀ w c, (∑ i, bcoef c i * wcolOf w c i) = wl w c last + c.alpha_in * wr w c last)
    (hclaim : ∀ (w : Witness) (c : RunChal logw nl F) (b : Fin nb → F) (ly : Fin nl),
      HonestFinalClaim
        (runLayerData R c.rounds (eqq c) c.alphas
          (runSplit R (blindEquiv (runHonest R (P w c) (wl w c) (wr w c)) b)) ly).e
        (R.pad b) (eqq c ly)
        (runLayerData R c.rounds (eqq c) c.alphas
          (runSplit R (blindEquiv (runHonest R (P w c) (wl w c) (wr w c)) b)) ly).wc0
        (runLayerData R c.rounds (eqq c) c.alphas
          (runSplit R (blindEquiv (runHonest R (P w c) (wl w c) (wr w c)) b)) ly).wc1
        (R.slots ly).ivL (R.slots ly).ivR) :
    ZkSetup ninp M nb F Witness (RunChal logw nl F) where
  honest := fun w c => runHonest R (P w c) (wl w c) (wr w c)
  padOf := fun b => R.pad b
  wcol := wcolOf
  sys := fun c t =>
    buildSystemMulti npub
      (List.ofFn (fun ly : Fin nl =>
        runLayerData R c.rounds (eqq c) c.alphas (runSplit R t) ly))
      (bcoef c) (pub_binding c)
      (runSplit R t last ⟨4 * logw, by omega⟩
        + c.alpha_in * runSplit R t last ⟨4 * logw + 1, by omega⟩)
      c.alpha_in (R.slots last).ivL (R.slots last).ivR
  honest_sat := by
    intro w c b
    refine honest_buildSystemMulti_Sat npub
      (List.ofFn (fun ly : Fin nl =>
        runLayerData R c.rounds (eqq c) c.alphas
          (runSplit R (blindEquiv (runHonest R (P w c) (wl w c) (wr w c)) b)) ly))
      (bcoef c) (pub_binding c) c.alpha_in (wl w c last) (wr w c last) _ _
      (R.slots last).ivL (R.slots last).ivR (wcolOf w c) (R.pad b) ?_ ?_ ?_
      (hpub w c) (hmle w c)
    · rintro L hL
      obtain ⟨ly, rfl⟩ := List.mem_ofFn.mp hL
      exact R.pad_quad b ly
    · rintro L hL
      obtain ⟨ly, rfl⟩ := List.mem_ofFn.mp hL
      exact hclaim w c b ly
    · exact runHonestClaimBlinding R last (P w c last) (wl w c last) (wr w c last) b _
        (fun k => runSplit_blindEquiv R (P w c) (wl w c) (wr w c) b last k)

/-!
### The challenge argument is not inert

A parameter a statement does not actually depend on is worse than no parameter: it reads as
strength and supplies none.  These two lemmas check that `RunChal` is load-bearing — the
honest transmission reads the challenges through `P` at every round slot and through `wl`,
`wr` at the two claim slots, so a challenge sequence that moves either moves the transcript.
-/

omit [Fintype F] [DecidableEq F] in
/-- At layer `ly`'s round-`r` slot, the honest transmission is that round's true polynomial at
`0` — so the round challenges reach it through `P`. -/
lemma zkSetupOfRun_honest_round {ninp npub logw nl M nb : ℕ}
    (R : RunPad logw nl M nb F) (last : Fin nl)
    (eqq : RunChal logw nl F → Fin nl → F)
    (P : Witness → RunChal logw nl F → Fin nl → Fin (2 * logw) → Polynomial F)
    (wl wr : Witness → RunChal logw nl F → Fin nl → F)
    (wcolOf : Witness → RunChal logw nl F → Fin ninp → F)
    (bcoef : RunChal logw nl F → Fin ninp → F) (pub_binding : RunChal logw nl F → F)
    (hpub hmle hclaim) (w : Witness) (c : RunChal logw nl F) (ly : Fin nl)
    (r : Fin (2 * logw)) :
    (zkSetupOfRun (npub := npub) R last eqq P wl wr wcolOf bcoef pub_binding
        hpub hmle hclaim).honest w c (R.gidx (ly, ⟨2 * r.val, by have := r.isLt; omega⟩))
      = (P w c ly r).eval 0 := by
  show runHonest R (P w c) (wl w c) (wr w c) (R.gidx (ly, ⟨2 * r.val, _⟩)) = _
  rw [runHonest]
  simp only [Equiv.symm_apply_apply]
  exact honestVals_round0 (P w c ly) _ _ ⟨2 * r.val, by have := r.isLt; omega⟩ r rfl

omit [Fintype F] [DecidableEq F] in
/-- **Two challenge sequences with different hand evaluations give different transcripts.**
At the `wc[0]` slot the honest transmission is literally `wl w c ly`, so `RunChal` is not a
decorative parameter. -/
theorem zkSetupOfRun_honest_ne {ninp npub logw nl M nb : ℕ}
    (R : RunPad logw nl M nb F) (last : Fin nl)
    (eqq : RunChal logw nl F → Fin nl → F)
    (P : Witness → RunChal logw nl F → Fin nl → Fin (2 * logw) → Polynomial F)
    (wl wr : Witness → RunChal logw nl F → Fin nl → F)
    (wcolOf : Witness → RunChal logw nl F → Fin ninp → F)
    (bcoef : RunChal logw nl F → Fin ninp → F) (pub_binding : RunChal logw nl F → F)
    (hpub hmle hclaim) (w : Witness) (c c' : RunChal logw nl F) (ly : Fin nl)
    (h : wl w c ly ≠ wl w c' ly) :
    (zkSetupOfRun (npub := npub) R last eqq P wl wr wcolOf bcoef pub_binding
        hpub hmle hclaim).honest w c
      ≠ (zkSetupOfRun (npub := npub) R last eqq P wl wr wcolOf bcoef pub_binding
        hpub hmle hclaim).honest w c' := by
  intro he
  refine h ?_
  have hc := congrFun he (R.gidx (ly, ⟨4 * logw, by omega⟩))
  have hval : ∀ d : RunChal logw nl F,
      runHonest R (P w d) (wl w d) (wr w d) (R.gidx (ly, ⟨4 * logw, by omega⟩))
        = wl w d ly := by
    intro d
    rw [runHonest]
    simp only [Equiv.symm_apply_apply]
    exact honestVals_claimL (P w d ly) _ _ ⟨4 * logw, by omega⟩ rfl
  rw [show (zkSetupOfRun (npub := npub) R last eqq P wl wr wcolOf bcoef pub_binding
      hpub hmle hclaim).honest w c = runHonest R (P w c) (wl w c) (wr w c) from rfl,
      show (zkSetupOfRun (npub := npub) R last eqq P wl wr wcolOf bcoef pub_binding
      hpub hmle hclaim).honest w c' = runHonest R (P w c') (wl w c') (wr w c') from rfl,
      hval c, hval c'] at hc
  exact hc

end ZkSetupOfLayer

/-!
## The computed layout, concretely

`stdRunPad` is a construction, so it can be *evaluated*.  Three layers at `logw = 2`: the
stride is `4·2 + 3 = 11`, the pad is `3·11 + 3 = 36` wide and the run has `3·10 = 30` blinders.
The checks below pin down the two features that make the layout awkward — the windows overlap,
and the quadratic slot sits in the gap between blinding blocks — at concrete numbers.
-/

namespace StdLayoutExample

abbrev F7 := ZMod 7

lemma hM : 3 * PadLayout.layerSize 2 + 3 ≤ 36 := by norm_num [PadLayout.layerSize]

/-- Layer `ly` blinds with the contiguous block `11·ly + 3 … 11·ly + 12`. -/
example : ((stdSlots 2 3 36 hM (0 : Fin 3)).pp0 (0 : Fin 4) : ℕ) = 3 := rfl
example : ((stdSlots 2 3 36 hM (1 : Fin 3)).pp0 (0 : Fin 4) : ℕ) = 14 := rfl
example : ((stdSlots 2 3 36 hM (2 : Fin 3)).pp0 (0 : Fin 4) : ℕ) = 25 := rfl

/-- **The overlap, at a number.**  Layer `0`'s `wc[0]` blinder sits exactly at layer `1`'s
window base — that is `claim_pad_overlap`, and it is why the blocks are not simply
`layerSize`-periodic. -/
example : ((stdSlots 2 3 36 hM (0 : Fin 3)).ivL : ℕ) = PadLayout.layerBase 2 1 := rfl

/-- **The gap, at a number.**  Layer `0`'s quadratic slot is `13`: past its own block, which
ends at `12`, and before layer `1`'s, which starts at `14`. -/
example : ((stdSlots 2 3 36 hM (0 : Fin 3)).ivLR : ℕ) = 13 := rfl

/-- The run's blinder count: one per layer per transmitted value. -/
example : 3 * (4 * 2 + 2) = 30 := rfl

/-- The pad is a *function*: at layer `1`'s round-`0` slot it returns that layer's blinder,
by evaluation rather than by hypothesis. -/
example (b : Fin 30 → F7) :
    (stdRunPad (F := F7) 2 3 36 hM).pad b (⟨14, by omega⟩ : Fin 36)
      = b (finProdFinEquiv ((⟨1, by omega⟩ : Fin 3), (⟨0, by omega⟩ : Fin 10))) :=
  stdPad_blind (F := F7) (logw := 2) (nl := 3) (M := 36) (nb := 30) finProdFinEquiv b
    ⟨1, by omega⟩ ⟨0, by omega⟩ ⟨14, by omega⟩ rfl

/-- And at layer `0`'s quadratic slot it returns the product of that layer's two claim
blinders — the triple Ligero needs, with no side condition left over. -/
example (b : Fin 30 → F7) :
    (stdRunPad (F := F7) 2 3 36 hM).pad b (⟨13, by omega⟩ : Fin 36)
      = b (finProdFinEquiv ((⟨0, by omega⟩ : Fin 3), (⟨8, by omega⟩ : Fin 10)))
        * b (finProdFinEquiv ((⟨0, by omega⟩ : Fin 3), (⟨9, by omega⟩ : Fin 10))) :=
  stdPad_quadAt (F := F7) (logw := 2) (nl := 3) (M := 36) (nb := 30) finProdFinEquiv b
    ⟨0, by omega⟩ ⟨13, by omega⟩ rfl

end StdLayoutExample
