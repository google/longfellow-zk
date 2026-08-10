import Mathlib
import sumcheck_soundness
import types

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Ligero as a black box over a public constraint system

Both sides treat Ligero generically: `ZkSetup.sys` produces a `LigeroSystem` from public data
and the transmission, and `longfellow_hvzk` never looks inside it.  `IsLigeroKnowledgeSound`
(`ligero.lean`) is the opposite shape — it bundles Longfellow's *own* layer row, input row,
transcript and challenges — so it is not a statement one could import from a Ligero paper or
from a separate Ligero formalisation.

This file supplies the statement one *would* import:

> if the verifier accepts, then — outside the knowledge error — the extractor returns an
> assignment satisfying the public system.

`IsLigeroSound` says exactly that, over an arbitrary `system : Ω → LigeroSystem ninp M F`.
Everything Longfellow-specific then becomes a *derived* lemma: `isLigeroKnowledgeSound_of_sound`
(`zk_sim.lean`) reads the layer row and the input row off `buildSystem_Sat`, and
`zkRowsHold_of_sound` (`ligero_bridge.lean`) reads a whole run's rows off `buildSystemMulti_Sat`.

The row and system types live here rather than in `zk_sim.lean` so that both the soundness
side and the hiding side can name them without importing each other.
-/

/-- One Ligero row: coefficients on the committed input columns, coefficients on the pad, and
a right-hand side. -/
structure LigeroRow (ninp M : ℕ) (F : Type) where
  cw : Fin ninp → F
  cp : Fin M → F
  rhs : F

/-- What it means for an assignment — the input columns and the pad — to satisfy a row. -/
def LigeroRow.Sat {ninp M : ℕ} {F : Type} [Field F] (row : LigeroRow ninp M F)
    (wcol : Fin ninp → F) (pad : Fin M → F) : Prop :=
  (∑ i, row.cw i * wcol i) + (∑ j, row.cp j * pad j) = row.rhs

/-- A Ligero instance: linear rows plus the quadratic pad triples `z = x * y`. -/
structure LigeroSystem (ninp M : ℕ) (F : Type) where
  linear : List (LigeroRow ninp M F)
  quad : List (Fin M × Fin M × Fin M)

def LigeroSystem.Sat {ninp M : ℕ} {F : Type} [Field F] (S : LigeroSystem ninp M F)
    (wcol : Fin ninp → F) (pad : Fin M → F) : Prop :=
  (∀ row ∈ S.linear, row.Sat wcol pad) ∧
  (∀ t ∈ S.quad, pad t.2.2 = pad t.1 * pad t.2.1)

/-- What a Ligero extractor returns: the committed input columns and the pad.  Note there is
no `Witness` here — a Ligero theorem knows nothing about what the columns *mean*.  Longfellow
recovers its witness by composing with `ArithmetizedCircuit.W_col`. -/
def LigeroAssignment (ninp M : ℕ) (F : Type) : Type := (Fin ninp → F) × Pad M F

/--
**Ligero knowledge soundness, as a Ligero theorem would state it.**

Two fields and no Longfellow in either:

* `extraction` — the verifier accepts and the extractor fails on at most `eps` sample points.
  This is the knowledge error; it is the *only* thing the whole development takes on trust
  about Ligero.
* `sound` — whenever the extractor succeeds on an accepted run, what it returns satisfies the
  public system.

`system` is a function of `ω` because the system Longfellow builds depends on the transmitted
values and the challenges, both of which are coordinates of the sample space.  A Ligero
theorem proved for a *fixed* system lifts to this shape by quantifying over the system, and
its error over Ligero's own coins lifts to the global count by `fiber_lift`.
-/
structure IsLigeroSound {ninp M : ℕ} {F Ω : Type} [Field F] [Fintype Ω]
    (accepts : Ω → Prop) (system : Ω → LigeroSystem ninp M F)
    (E : Ω → Option (LigeroAssignment ninp M F)) (eps : ℕ) : Prop where
  extraction :
    event_card (Finset.filter (fun ω => accepts ω ∧ E ω = none) Finset.univ) ≤ eps
  sound : ∀ (ω : Ω) (a : LigeroAssignment ninp M F), accepts ω → E ω = some a →
    (system ω).Sat a.1 a.2

/--
**Fibrewise lifting.**

A Ligero theorem states its error over Ligero's *own* coins, for each fixed prefix: "for every
commitment and challenge sequence, at most `e` of the openings fool the verifier".  The
counting development here needs one number over the whole sample space.  If every fibre of the
first coordinate is bad at most `e` times, the whole space is bad at most `|D| · e` times —
which is the shape `eps_FSK` is used at.

This is deliberately stated for a bare predicate rather than for `IsLigeroSound`, because it is
the same lemma for any per-fibre bound; `fiber_lift_extraction` specialises it.
-/
theorem fiber_lift {D R : Type} [Fintype D] [Fintype R]
    (bad : D × R → Prop) (e : ℕ)
    (h : ∀ d : D, (Finset.filter (fun r : R => bad (d, r)) Finset.univ).card ≤ e) :
    event_card (Finset.filter (fun p : D × R => bad p) Finset.univ) ≤ Fintype.card D * e := by
  classical
  have hsub : Finset.filter (fun p : D × R => bad p) Finset.univ
      ⊆ Finset.univ.biUnion (fun d : D =>
          (Finset.filter (fun r : R => bad (d, r)) Finset.univ).image (fun r => (d, r))) := by
    rintro ⟨d, r⟩ hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp
    simp only [Finset.mem_biUnion, Finset.mem_univ, true_and, Finset.mem_image,
      Finset.mem_filter]
    exact ⟨d, r, hp, rfl⟩
  dsimp only [event_card]
  refine le_trans (Finset.card_le_card hsub) (le_trans Finset.card_biUnion_le ?_)
  calc ∑ d : D, ((Finset.filter (fun r : R => bad (d, r)) Finset.univ).image
          (fun r => (d, r))).card
      ≤ ∑ _d : D, e :=
        Finset.sum_le_sum (fun d _ => le_trans Finset.card_image_le (h d))
    _ = Fintype.card D * e := by
        rw [Finset.sum_const, Finset.card_univ, smul_eq_mul]

/-- `fiber_lift` at the extraction event: a per-commitment knowledge error `e` over Ligero's
coins becomes the global count `|D| · e` the soundness theorems take as `eps_FSK`. -/
theorem fiber_lift_extraction {ninp M : ℕ} {F D R : Type} [Field F] [Fintype D] [Fintype R]
    (accepts : D × R → Prop) (E : D × R → Option (LigeroAssignment ninp M F)) (e : ℕ)
    (h : ∀ d : D, (Finset.filter (fun r : R => accepts (d, r) ∧ E (d, r) = none)
      Finset.univ).card ≤ e) :
    event_card (Finset.filter (fun p : D × R => accepts p ∧ E p = none) Finset.univ)
      ≤ Fintype.card D * e := by
  classical
  have hlift := fiber_lift (D := D) (R := R) (fun p => accepts p ∧ E p = none) e (fun d =>
    le_trans (Finset.card_le_card (by
      intro r hr
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hr ⊢
      exact hr)) (h d))
  refine le_trans (le_trans (Finset.card_le_card ?_) hlift) le_rfl
  intro p hp
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢
  exact hp
