import Mathlib
import types

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Inside the Ligero box: the parts that are counting

`eps_FSK` is the one free parameter of `core_soundness_theorem`, and `ligero.lean` treats
Ligero as an oracle.  Bounding it needs three things:

1. **The commitment binds.**  A committed tableau cannot be opened two ways.  This is Merkle
   binding, and it is *already formalized in this repository* — `merkle/Binding.lean`
   (`mh_binding_of_collision` from collision resistance alone, `mh_binding_bound_rom` for the
   closed-form ROM bound).  Connecting it needs a model of Ligero's tableau, which does not
   exist here yet.
2. **Interleaved Reed–Solomon proximity.**  If the committed rows are far from the code, a
   random linear combination of them is far too.  This is the hard step and it is *not* proved
   anywhere in this repository.
3. **The column test catches a far word.**  If the committed word disagrees with the claimed
   codeword often, `t` random column openings hit a disagreement.

This file proves the pieces of (1) and (3) that are pure finite-field counting, plus the code
geometry (2) would be stated against: the Reed–Solomon minimum distance and unique decoding.
It does **not** prove (2), and `eps_FSK` remains assumed.  What it buys is that the box now has
named parts, two of which are theorems, and the residual is a single identified statement
rather than the whole primitive.

Nothing here depends on the rest of the development; it is stated over an abstract evaluation
domain so that a future tableau model can instantiate it.
-/

variable {F : Type} [Field F] [Fintype F] [DecidableEq F]

/-! ## Reed–Solomon codewords -/

/--
`u` is a Reed–Solomon codeword for the evaluation points `pts` and rate parameter `k`: it is
the evaluation of some polynomial of degree `< k`.  This is `lib/algebra/reed_solomon.h`'s
code, written extensionally.
-/
def IsRSCodeword {n k : ℕ} (pts : Fin n → F) (u : Fin n → F) : Prop :=
  ∃ p : Polynomial F, p.natDegree < k ∧ ∀ i, u i = p.eval (pts i)

/-- The positions where two words agree. -/
def agreeSet {n : ℕ} (u v : Fin n → F) : Finset (Fin n) :=
  Finset.univ.filter (fun i => u i = v i)

/-- Hamming distance: the number of positions where two words differ. -/
def hamDist {n : ℕ} (u v : Fin n → F) : ℕ :=
  (Finset.univ.filter (fun i => u i ≠ v i)).card

omit [Field F] [Fintype F] in
/-- Agreement and distance partition the coordinates. -/
lemma agree_add_dist {n : ℕ} (u v : Fin n → F) :
    (agreeSet u v).card + hamDist u v = n := by
  classical
  rw [agreeSet, hamDist, Finset.card_filter_add_card_filter_not
        (p := fun i : Fin n => u i = v i)]
  simp

omit [Field F] [Fintype F] in
lemma hamDist_comm {n : ℕ} (u v : Fin n → F) : hamDist u v = hamDist v u := by
  rw [hamDist, hamDist]
  exact congrArg Finset.card (Finset.filter_congr (fun i _ => by rw [ne_comm]))

omit [Field F] [Fintype F] in
/-- The triangle inequality: a disagreement between `u` and `w` is a disagreement with `v` on
at least one side. -/
lemma hamDist_triangle {n : ℕ} (u v w : Fin n → F) :
    hamDist u w ≤ hamDist u v + hamDist v w := by
  classical
  refine le_trans (Finset.card_le_card (t :=
    (Finset.univ.filter (fun i : Fin n => u i ≠ v i))
      ∪ (Finset.univ.filter (fun i : Fin n => v i ≠ w i))) ?_) (Finset.card_union_le _ _)
  intro i hi
  simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at hi ⊢
  by_cases h : u i = v i
  · right; rw [← h]; exact hi
  · left; exact h

/-! ## The minimum distance of the code

This is the only place polynomial degree enters, and it is the classical argument: two
distinct polynomials of degree `< k` agree at fewer than `k` points, because their difference
is a non-zero polynomial of degree `< k`.
-/

omit [Fintype F] in
/--
**Distinct low-degree polynomials agree at fewer than `k` of the evaluation points.**

The evaluation points must be distinct — `hpts` — which is what makes a Reed–Solomon code a
code at all.
-/
theorem rs_agree_card_lt {n k : ℕ} (pts : Fin n → F) (hpts : Function.Injective pts)
    (p q : Polynomial F) (hp : p.natDegree < k) (hq : q.natDegree < k) (hne : p ≠ q) :
    (Finset.univ.filter (fun i : Fin n => p.eval (pts i) = q.eval (pts i))).card < k := by
  classical
  have hd : p - q ≠ 0 := sub_ne_zero.mpr hne
  have hdeg : (p - q).natDegree < k :=
    lt_of_le_of_lt (Polynomial.natDegree_sub_le p q) (max_lt hp hq)
  have hmap : (Finset.univ.filter (fun i : Fin n => p.eval (pts i) = q.eval (pts i))).card
      ≤ (p - q).roots.toFinset.card := by
    refine Finset.card_le_card_of_injOn pts (fun i hi => ?_) (fun a _ b _ h => hpts h)
    have hieq : p.eval (pts i) = q.eval (pts i) := (Finset.mem_filter.mp hi).2
    have hroot : (p - q).IsRoot (pts i) := by
      show Polynomial.eval (pts i) (p - q) = 0
      rw [Polynomial.eval_sub, hieq, sub_self]
    simpa [Multiset.mem_toFinset, Polynomial.mem_roots hd] using hroot
  calc (Finset.univ.filter (fun i : Fin n => p.eval (pts i) = q.eval (pts i))).card
      ≤ (p - q).roots.toFinset.card := hmap
    _ ≤ Multiset.card (p - q).roots := (p - q).roots.toFinset_card_le
    _ ≤ (p - q).natDegree := Polynomial.card_roots' _
    _ < k := hdeg

omit [Fintype F] in
/--
**The Reed–Solomon minimum distance.**

Distinct codewords differ in more than `n − k` positions — the Singleton bound, met with
equality, which is why Reed–Solomon is MDS.  Stated as `n < hamDist + k` to avoid truncated
subtraction.
-/
theorem rs_min_distance {n k : ℕ} (pts : Fin n → F) (hpts : Function.Injective pts)
    (u v : Fin n → F) (hu : IsRSCodeword (k := k) pts u) (hv : IsRSCodeword (k := k) pts v)
    (hne : u ≠ v) : n < hamDist u v + k := by
  classical
  obtain ⟨p, hp, hpu⟩ := hu
  obtain ⟨q, hq, hqv⟩ := hv
  have hpq : p ≠ q := by
    intro h
    exact hne (funext (fun i => by rw [hpu i, hqv i, h]))
  have hagree : agreeSet u v
      = Finset.univ.filter (fun i : Fin n => p.eval (pts i) = q.eval (pts i)) :=
    Finset.filter_congr (fun i _ => by rw [hpu i, hqv i])
  have hlt : (agreeSet u v).card < k := by
    rw [hagree]; exact rs_agree_card_lt pts hpts p q hp hq hpq
  have := agree_add_dist u v
  omega

omit [Fintype F] in
/--
**Unique decoding.**

A word closer than half the minimum distance to two codewords forces them equal.  This is what
makes "the committed row decodes to a unique polynomial" meaningful, and it is the bound the
Ligero parameters are chosen against.
-/
theorem rs_unique_decoding {n k : ℕ} (pts : Fin n → F) (hpts : Function.Injective pts)
    (w u v : Fin n → F) (hu : IsRSCodeword (k := k) pts u) (hv : IsRSCodeword (k := k) pts v)
    (hclose : hamDist w u + hamDist w v + k ≤ n) : u = v := by
  by_contra hne
  have hmin := rs_min_distance pts hpts u v hu hv hne
  have htri : hamDist u v ≤ hamDist u w + hamDist w v := hamDist_triangle u w v
  rw [hamDist_comm u w] at htri
  omega

/-! ## The column test

The verifier opens `t` columns, each drawn uniformly from the `n` positions and
independently — `ligero_param.h`'s `nrequests`.  This is the same counting shape as
`combinatorial_fiat_shamir`: a set of "good for the prover" outcomes inside a product space.
-/

/--
**Exactly `|A|^t` of the `n^t` opening sequences land entirely inside `A`.**

An equality, not a bound: the opened columns are independent, so the count is a product.
-/
theorem opening_all_agree_card {n t : ℕ} (A : Finset (Fin n)) :
    (Finset.filter (fun s : Fin t → Fin n => ∀ j, s j ∈ A) Finset.univ).card = A.card ^ t := by
  classical
  have h : (Finset.filter (fun s : Fin t → Fin n => ∀ j, s j ∈ A) Finset.univ)
      = Fintype.piFinset (fun _ : Fin t => A) := by
    ext s; simp [Fintype.mem_piFinset]
  rw [h, Fintype.card_piFinset]
  simp

/--
**The column test, as a probability.**

If the committed word agrees with the claimed codeword on `A`, the chance that all `t` opened
columns miss every disagreement is exactly `(|A|/n)^t`.  With `|A| ≤ n − e` that is at most
`((n−e)/n)^t`, which is the term Ligero's parameter choice drives below `2^-λ`.
-/
theorem opening_all_agree_prob {n t : ℕ} (A : Finset (Fin n)) :
    ((Finset.filter (fun s : Fin t → Fin n => ∀ j, s j ∈ A) Finset.univ).card : ℚ)
        / (Fintype.card (Fin t → Fin n))
      = ((A.card : ℚ) / n) ^ t := by
  rw [opening_all_agree_card, Fintype.card_fun, Fintype.card_fin, Fintype.card_fin, div_pow]
  push_cast
  ring

omit [Field F] [Fintype F] in
/--
**A word at distance `e` survives `t` openings with probability at most `((n−e)/n)^t`.**

This is the statement the Ligero verifier's `nrequests` is sized by.  It is stated against the
*agreement* set, so it needs no proximity theory: given that `w` differs from `u` in `e`
places, at most `n − e` columns can agree.
-/
theorem column_test_bound {n t e : ℕ} (w u : Fin n → F) (he : e ≤ hamDist w u) :
    (Finset.filter (fun s : Fin t → Fin n => ∀ j, s j ∈ agreeSet w u) Finset.univ).card
      ≤ (n - e) ^ t := by
  rw [opening_all_agree_card]
  refine Nat.pow_le_pow_left ?_ t
  have := agree_add_dist w u
  omega

/-!
## What this does and does not give

**Proved here.**  The code geometry — `rs_min_distance` and `rs_unique_decoding` — and the
column test — `opening_all_agree_card`, an exact count, with `column_test_bound` as the form
Ligero's parameters are read off.

**Proved elsewhere in this repository.**  Merkle binding and hiding, in `merkle/`:
`mh_binding_of_collision` needs only collision resistance, `mh_binding_bound_rom` gives the
closed-form ROM bound, and `mh_root_hiding_rom` / `mh_opening_hiding_rom` are the hiding side
that `eps_hide` rests on.  Those files build clean with no `sorry` and no custom axiom, but
they are a separate Lean library and nothing here imports them: joining them to `eps_FSK`
needs a model of Ligero's tableau — rows, the RS encoding, the three blinding rows, the
column-opening protocol — which this development does not have.

**Not proved anywhere.**  Interleaved Reed–Solomon proximity: that if the committed rows are
jointly far from the code then a random linear combination of them is far as well.  That is
the step which turns "the column test passes" into "the rows decode", and it is the reason
`eps_FSK` is still a parameter.  It is a substantial theorem in its own right.

So gap 2 is **not** closed.  What has changed is that the box has three named parts instead of
one opaque constant, and only the third is open.
-/
