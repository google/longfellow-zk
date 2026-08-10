import Mathlib
import sumcheck_soundness
import types

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Multilinear Schwartz–Zippel

The development has two root counts: `univariate_roots_bound`, for one variable, and
`bilinear_zero_card`, for the two-variable form `S(alpha, beta)`.  Neither covers a
multilinear polynomial in `n` variables, which is what the *initial* challenge point
`(q, g0, g1)` needs — the circuit's output multilinear extension, evaluated where
`begin_circuit` samples it.

Without this count, "the arithmetization detects an unsatisfied circuit" has to be assumed at
**every** initial point, which is stronger than ordinary compiler correctness: a non-zero
output extension can vanish at a sampled off-cube point, exactly as the extension of `(1,0)`
does at a Boolean corner.  With it, the assumption weakens to "the extension is non-zero
somewhere" and the difference becomes a counted `n/|F|`.

`MLin` is multilinearity in the form the induction wants: freezing every coordinate but one
leaves an affine function.  It is the `Fin n → F` twin of `IsMultilinear` (`circuit.lean`),
which is stated on `Vector`; `mlin_of_isMultilinear` connects them.
-/

variable {F : Type} [Field F]

/-- Multilinear: freezing every coordinate but one leaves an affine function. -/
def MLin {n : ℕ} (h : (Fin n → F) → F) : Prop :=
  ∀ (v : Fin n → F) (j : Fin n), ∃ a b : F, ∀ X : F, h (Function.update v j X) = a + b * X

/-! ## The two halves of a multilinear function in its first variable -/

/-- `h` with its first variable set to `0`. -/
def mlinLo {n : ℕ} (h : (Fin (n + 1) → F) → F) : (Fin n → F) → F :=
  fun v' => h (Fin.cons 0 v')

/-- The slope of `h` in its first variable. -/
def mlinSlope {n : ℕ} (h : (Fin (n + 1) → F) → F) : (Fin n → F) → F :=
  fun v' => h (Fin.cons 1 v') - h (Fin.cons 0 v')

/--
**A multilinear function is affine in its first variable, with these two halves.**

`MLin` gives affineness pointwise, with unnamed coefficients; evaluating at `0` and `1`
identifies them.
-/
lemma mlin_split {n : ℕ} (h : (Fin (n + 1) → F) → F) (H : MLin h) (v' : Fin n → F) (X : F) :
    h (Fin.cons X v') = mlinLo h v' + mlinSlope h v' * X := by
  obtain ⟨a, b, hab⟩ := H (Fin.cons 0 v') 0
  have hupd : ∀ Y : F, Function.update (Fin.cons (0 : F) v' : Fin (n+1) → F) 0 Y
      = (Fin.cons Y v' : Fin (n+1) → F) := by
    intro Y
    funext i
    refine Fin.cases ?_ ?_ i
    · simp
    · intro k; simp
  have h0 : h (Fin.cons (0 : F) v') = a := by
    have := hab 0
    rw [hupd 0] at this
    rw [this]; ring
  have h1 : h (Fin.cons (1 : F) v') = a + b := by
    have := hab 1
    rw [hupd 1] at this
    rw [this]; ring
  have hX := hab X
  rw [hupd X] at hX
  rw [hX, mlinLo, mlinSlope, h0, h1]
  ring

omit [Field F] in
/-- Freezing a later coordinate of `h` is freezing a coordinate of each half. -/
lemma cons_update_succ {n : ℕ} (v' : Fin n → F) (X Y : F) (j : Fin n) :
    Function.update (Fin.cons X v' : Fin (n+1) → F) j.succ Y
      = (Fin.cons X (Function.update v' j Y) : Fin (n+1) → F) := by
  funext i
  refine Fin.cases ?_ ?_ i
  · simp [Function.update_of_ne (Fin.succ_ne_zero j).symm]
  · intro k
    by_cases hk : k = j
    · subst hk; simp
    · rw [Function.update_of_ne (by simpa using hk), Fin.cons_succ, Fin.cons_succ,
        Function.update_of_ne hk]

/-- Both halves of a multilinear function are multilinear. -/
lemma mlinLo_mlin {n : ℕ} (h : (Fin (n + 1) → F) → F) (H : MLin h) : MLin (mlinLo h) := by
  intro v' j
  obtain ⟨a, b, hab⟩ := H (Fin.cons 0 v') j.succ
  refine ⟨a, b, fun X => ?_⟩
  have hx := hab X
  rw [cons_update_succ] at hx
  exact hx

lemma mlinSlope_mlin {n : ℕ} (h : (Fin (n + 1) → F) → F) (H : MLin h) :
    MLin (mlinSlope h) := by
  intro v' j
  obtain ⟨a1, b1, h1⟩ := H (Fin.cons 1 v') j.succ
  obtain ⟨a0, b0, h0⟩ := H (Fin.cons 0 v') j.succ
  refine ⟨a1 - a0, b1 - b0, fun X => ?_⟩
  have e1 := h1 X
  have e0 := h0 X
  rw [cons_update_succ] at e1 e0
  show h (Fin.cons 1 (Function.update v' j X)) - h (Fin.cons 0 (Function.update v' j X)) = _
  rw [e1, e0]; ring

/-! ## The count -/

variable [Fintype F] [DecidableEq F]

omit [Field F] in
/-- Counting over `Fin (n+1) → F` by splitting off the first coordinate.  Stated as a bound
rather than an equality so that it composes with the per-fibre estimate directly. -/
lemma card_cons_split_le {n : ℕ} (P : (Fin (n + 1) → F) → Prop) [DecidablePred P]
    (g : (Fin n → F) → ℕ)
    (hg : ∀ v' : Fin n → F,
      (Finset.univ.filter (fun X : F => P (Fin.cons X v'))).card ≤ g v') :
    (Finset.univ.filter P).card ≤ ∑ v' : Fin n → F, g v' := by
  classical
  have hfib : (Finset.univ.filter P).card
      = ∑ v' : Fin n → F,
          ((Finset.univ.filter P).filter (fun v => Fin.tail v = v')).card :=
    Finset.card_eq_sum_card_fiberwise (fun v _ => Finset.mem_univ _)
  rw [hfib]
  refine Finset.sum_le_sum (fun v' _ => ?_)
  refine le_trans (Finset.card_le_card_of_injOn (fun v => v 0) ?_ ?_) (hg v')
  · intro v hv
    simp only [Finset.mem_coe, Finset.mem_filter, Finset.mem_univ, true_and] at hv ⊢
    obtain ⟨hP, ht⟩ := hv
    rw [← ht, show Fin.cons (v 0) (Fin.tail v) = v from Fin.cons_self_tail v]
    exact hP
  · intro a ha b hb hab
    simp only [Finset.mem_coe, Finset.mem_filter, Finset.mem_univ, true_and] at ha hb
    have hab0 : a 0 = b 0 := hab
    rw [← Fin.cons_self_tail a, ← Fin.cons_self_tail b, hab0, ha.2, hb.2]

/--
**Multilinear Schwartz–Zippel.**

A multilinear function of `n` variables that is not identically zero vanishes on at most
`n · |F|^(n-1)` of the `|F|^n` points — the same `n/|F|` fraction the univariate bound gives
per variable.

The induction is on the first variable.  For each setting of the rest, `mlin_split` makes the
function affine in it: if the slope is non-zero at most one value vanishes, and if the slope is
zero the function is constant, so either none or all `|F|` do.  The "all" case is confined to
the common zero set of the two halves, which the induction hypothesis bounds.
-/
theorem mlin_zero_card : ∀ (n : ℕ) (h : (Fin n → F) → F), MLin h → (∃ v, h v ≠ 0) →
    (Finset.univ.filter (fun v : Fin n → F => h v = 0)).card
      ≤ n * (Fintype.card F) ^ (n - 1) := by
  intro n
  induction n with
  | zero =>
    intro h _ hne
    obtain ⟨v, hv⟩ := hne
    have hempty : Finset.univ.filter (fun w : Fin 0 → F => h w = 0) = ∅ := by
      refine Finset.filter_false_of_mem (fun w _ => ?_)
      have hwv : w = v := funext (fun i => absurd i.isLt (by omega))
      rw [hwv]; exact hv
    rw [hempty]; simp
  | succ k ih =>
    intro h H hne
    classical
    -- the common zero set of the two halves
    set Z : Finset (Fin k → F) :=
      Finset.univ.filter (fun v' => mlinLo h v' = 0 ∧ mlinSlope h v' = 0) with hZ
    have hterm : ∀ v' : Fin k → F,
        (Finset.univ.filter (fun X : F => h (Fin.cons X v') = 0)).card
          ≤ (if v' ∈ Z then Fintype.card F else 1) := by
      intro v'
      by_cases hmem : v' ∈ Z
      · rw [if_pos hmem]; exact le_trans (Finset.card_filter_le _ _) (le_of_eq (by simp))
      · rw [if_neg hmem]
        simp only [hZ, Finset.mem_filter, Finset.mem_univ, true_and] at hmem
        refine Finset.card_le_one.mpr (fun a ha b hb => ?_)
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha hb
        rw [mlin_split h H v' a] at ha
        rw [mlin_split h H v' b] at hb
        by_cases hs : mlinSlope h v' = 0
        · exfalso
          rw [hs] at ha
          simp only [zero_mul, add_zero] at ha
          exact hmem ⟨ha, hs⟩
        · exact mul_left_cancel₀ hs (by linear_combination ha - hb)
    -- at least one half is not identically zero
    have hhalf : (∃ v', mlinLo h v' ≠ 0) ∨ (∃ v', mlinSlope h v' ≠ 0) := by
      obtain ⟨v, hv⟩ := hne
      by_contra hc
      push Not at hc
      obtain ⟨hlo, hsl⟩ := hc
      refine hv ?_
      rw [← Fin.cons_self_tail v, mlin_split h H (Fin.tail v) (v 0), hlo, hsl]
      ring
    have hZcard : Z.card ≤ k * (Fintype.card F) ^ (k - 1) := by
      rcases hhalf with ⟨v', hv'⟩ | ⟨v', hv'⟩
      · refine le_trans (Finset.card_le_card ?_) (ih (mlinLo h) (mlinLo_mlin h H) ⟨v', hv'⟩)
        intro x hx
        simp only [hZ, Finset.mem_filter, Finset.mem_univ, true_and] at hx ⊢
        exact hx.1
      · refine le_trans (Finset.card_le_card ?_)
          (ih (mlinSlope h) (mlinSlope_mlin h H) ⟨v', hv'⟩)
        intro x hx
        simp only [hZ, Finset.mem_filter, Finset.mem_univ, true_and] at hx ⊢
        exact hx.2
    refine le_trans (card_cons_split_le (P := fun v : Fin (k+1) → F => h v = 0)
      (fun v' => if v' ∈ Z then Fintype.card F else 1) hterm) ?_
    calc ∑ v' : Fin k → F, (if v' ∈ Z then Fintype.card F else 1)
        ≤ ∑ v' : Fin k → F, ((if v' ∈ Z then Fintype.card F else 0) + 1) :=
          Finset.sum_le_sum (fun v' _ => by by_cases hv : v' ∈ Z <;> simp [hv])
      _ = Z.card * Fintype.card F + Fintype.card (Fin k → F) := by
          rw [Finset.sum_add_distrib, Finset.sum_ite_mem, Finset.univ_inter,
            Finset.sum_const, Finset.sum_const, Finset.card_univ]
          simp [mul_comm]
      _ ≤ (k * (Fintype.card F) ^ (k - 1)) * Fintype.card F + (Fintype.card F) ^ k := by
          have hc : Fintype.card (Fin k → F) = (Fintype.card F) ^ k := by simp
          rw [hc]
          exact Nat.add_le_add_right (Nat.mul_le_mul_right _ hZcard) _
      _ = (k + 1) * (Fintype.card F) ^ (k + 1 - 1) := by
          cases k with
          | zero => simp
          | succ m =>
            rw [Nat.succ_sub_one, Nat.add_sub_cancel, mul_assoc, ← pow_succ]
            ring

/-!
## The initial challenge point, counted

`ArithmetizedCircuit.arith` is quantified over `q_challenge`, `g0` and `g1`: it demands the
output claim be non-vanishing at **every** initial point.  That is stronger than ordinary
compiler correctness, and for a circuit with several output coordinates the two differ — a
non-zero output extension can vanish where `begin_circuit` happens to sample.

`initial_point_bad_card` is what removes the gap.  Assume only that the claim is non-zero
*somewhere* — which is what a compiler theorem gives, and what "the arithmetization encodes
`eval`" means — and pay `k/|F|` for the draw, where `k = logc + 2·logv` is the number of
coordinates in `(q, g0, g1)`.

The splitting is the usual one: everything decided before `begin_circuit` samples the point,
then the point.  `hne` is the weakened assumption and `hml` is multilinearity of the claim in
those coordinates, which holds because they enter only through `eq` factors.
-/

variable {Ω : Type} [Fintype Ω]

/--
**The initial point costs `k/|F|`, not an assumption.**

At most `|D| · k · |F|^(k-1)` of the `|D| · |F|^k` runs draw an initial point at which the
claim vanishes even though it is non-zero somewhere.
-/
theorem initial_point_bad_card {D A : Type} [Fintype D] [DecidableEq D] {k : ℕ}
    (E : D → Option A) (claim : D → A → (Fin k → F) → F)
    (hml : ∀ (d : D) (v : A), MLin (claim d v))
    (hne : ∀ (d : D) (v : A), ∃ g, claim d v g ≠ 0)
    (dataOf : Ω → D) (gOf : Ω → (Fin k → F))
    (hinj : Function.Injective (fun ω => (dataOf ω, gOf ω))) :
    event_card (Finset.filter
        (fun ω => ∃ v : A, E (dataOf ω) = some v ∧ claim (dataOf ω) v (gOf ω) = 0)
        Finset.univ)
      ≤ Fintype.card D * (k * (Fintype.card F) ^ (k - 1)) := by
  classical
  obtain ⟨Q, hQdef⟩ : ∃ Q : D × (Fin k → F) → Prop, Q = fun p =>
      ∃ v : A, E p.1 = some v ∧ claim p.1 v p.2 = 0 := ⟨_, rfl⟩
  have hQ : (Finset.filter Q Finset.univ).card
      ≤ Fintype.card D * (k * (Fintype.card F) ^ (k - 1)) := by
    refine le_trans (Finset.card_le_card ?_)
      (option_bad_pairs_card_mul E (fun d v g => claim d v g = 0)
        (k * (Fintype.card F) ^ (k - 1))
        (fun d v => le_trans (Finset.card_le_card (fun g hg => by simpa using hg))
          (mlin_zero_card k (claim d v) (hml d v) (hne d v))))
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hQdef] at hp ⊢
    exact hp
  have hmain := event_card_le_split (Ω := Ω) dataOf gOf hinj
    (fun ω => ∃ v : A, E (dataOf ω) = some v ∧ claim (dataOf ω) v (gOf ω) = 0)
    Q (fun ω hω => by rw [hQdef]; exact hω)
    (Fintype.card D * (k * (Fintype.card F) ^ (k - 1))) hQ
  refine le_trans (Finset.card_le_card ?_) hmain
  intro ω hω
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

/-!
## Non-vacuity

`mlin_zero_card` bounds a set of zeros; the bound is worthless if the hypotheses force that set
empty, or if it is so loose that no instance approaches it.  Both instances below are computed,
not argued.
-/

namespace MlinExample

instance : Fact (Nat.Prime 5) := ⟨by norm_num⟩

abbrev F5 := ZMod 5

/-- One variable: the identity. -/
def h1 : (Fin 1 → F5) → F5 := fun v => v 0

lemma h1_mlin : MLin h1 := by
  intro v j
  refine ⟨0, 1, fun X => ?_⟩
  have hj : j = 0 := Subsingleton.elim _ _
  subst hj
  show Function.update v 0 X 0 = 0 + 1 * X
  simp

lemma h1_ne : ∃ v, h1 v ≠ 0 := ⟨fun _ => 1, by decide⟩

/-- **The bound is tight at `k = 1`.**  The identity has exactly one zero out of `5`, and
`1 · |F|^0 = 1`. -/
theorem h1_tight :
    (Finset.univ.filter (fun v : Fin 1 → F5 => h1 v = 0)).card
      = 1 * (Fintype.card F5) ^ (1 - 1) := by decide

example :
    (Finset.univ.filter (fun v : Fin 1 → F5 => h1 v = 0)).card
      ≤ 1 * (Fintype.card F5) ^ (1 - 1) :=
  mlin_zero_card 1 h1 h1_mlin h1_ne

/-- Two variables: a product, which is where multilinearity does real work — it is not affine,
but freezing either coordinate leaves an affine function. -/
def h2 : (Fin 2 → F5) → F5 := fun v => v 0 * v 1

lemma h2_mlin : MLin h2 := by
  intro v j
  refine Fin.cases ?_ ?_ j
  · refine ⟨0, v 1, fun X => ?_⟩
    show Function.update v 0 X 0 * Function.update v 0 X 1 = 0 + v 1 * X
    rw [Function.update_self, Function.update_of_ne (by decide)]
    ring
  · intro k
    have hk : k = 0 := Subsingleton.elim _ _
    subst hk
    refine ⟨0, v 0, fun X => ?_⟩
    show Function.update v 1 X 0 * Function.update v 1 X 1 = 0 + v 0 * X
    rw [Function.update_self, Function.update_of_ne (by decide)]
    ring

lemma h2_ne : ∃ v, h2 v ≠ 0 := ⟨fun _ => 1, by decide⟩

/-- **And the bound is about a large set, not an empty one.**  The product vanishes on `9` of
the `25` points — the two axes — against a bound of `2 · 5 = 10`.  So the count is neither
vacuous nor far off. -/
theorem h2_card : (Finset.univ.filter (fun v : Fin 2 → F5 => h2 v = 0)).card = 9 := by decide

example :
    (Finset.univ.filter (fun v : Fin 2 → F5 => h2 v = 0)).card
      ≤ 2 * (Fintype.card F5) ^ (2 - 1) :=
  mlin_zero_card 2 h2 h2_mlin h2_ne

example : 2 * (Fintype.card F5) ^ (2 - 1) = 10 := by decide

/-- The hypothesis is load-bearing: the zero function has all `25` points as zeros, which
exceeds the bound.  So `mlin_zero_card` cannot drop `hne`. -/
theorem hne_needed :
    (Finset.univ.filter (fun v : Fin 2 → F5 => (fun _ => (0 : F5)) v = 0)).card
      > 2 * (Fintype.card F5) ^ (2 - 1) := by decide

end MlinExample
