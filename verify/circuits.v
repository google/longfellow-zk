From Stdlib Require Import Lia Zmod.

Local Open Scope Z_scope.
Local Open Scope Zmod_scope.
Local Coercion Zmod.to_Z : Zmod >-> Z.

Definition p : Z := 2^127-1. (*chageme: field*)
Local Notation F := (Zmod p).

(** Simple function, specification, proof *)

Definition field_gallina_add (x y : F) : F := x+y.

Lemma field_gallina_add_Z (x y : F) : 0 <= (x + y)%Z < p -> Zmod.to_Z (x + y) = (x+y)%Z.
Proof.
  intros.
  rewrite Zmod.to_Z_add, Z.mod_small; lia.
Qed.

(** Now a language for such programs *)

Module type.
  Local Notation top_F := F.
  Inductive type := unit | F | prod (_ _ : type) | prop.
  Fixpoint interp (t : type) : Type :=
    match t with
    | unit => Datatypes.unit
    | F => top_F
    | prod a b => Datatypes.prod (interp a) (interp b)
    | prop => Prop
    end.
End type.
Notation type := type.type.

Module op.
  Import type.
  Inductive bin : type -> type -> type -> Type :=
  | add : bin F F F
  | mul : bin F F F
  | pair {a b : type} : bin a b (prod a b)
  | fst {a b : type} : bin (prod a b) unit a
  | snd {a b : type} : bin (prod a b) unit b
  | eq : bin F F prop
  | and  : bin prop prop prop.
  Fixpoint interp {a b c} (op : bin a b c) : interp a -> interp b -> interp c :=
    match op with
    | add => Zmod.add
    | mul => Zmod.mul
    | pair => Datatypes.pair
    | fst => fun x _ => Datatypes.fst x
    | snd => fun x _ => Datatypes.snd x
    | and => Logic.and
    | eq => Logic.eq
    end.
End op.

Module expr.
  Section WithSubstitutionType.
    Context {var : type -> Type}.
    Import type op.
    Inductive expr : forall (t:type), Type :=
      | tt : expr unit
      | BinOp
          {t1 t2 tR : type}
          (op : op.bin t1 t2 tR)
          (e1 : expr t1)
          (e2 : expr t2)
          : expr tR
      | LetIn
          {tx : type}
          (ex : expr tx)
          {tC : type}
          (eC : var tx -> expr tC)
          : expr tC
      | Var
          {tx : type}
          (x : var tx)
          : expr tx.
  End WithSubstitutionType.
  Arguments expr : clear implicits.

  Fixpoint interp {t} (e : expr type.interp t) : type.interp t :=
    match e in expr _ t return type.interp t with
    | tt => Datatypes.tt
    | BinOp op e1 e2 => op.interp op (interp e1) (interp e2)
    | LetIn ex eC => let x := interp ex in interp (eC x)
    | Var x => x
    end.
End expr.
Notation expr := expr.expr.

Module constraints.
  Section WithSubstitutionType.
    Context {var : type -> Type}.
    Import type op.
    Inductive constraints : type -> Type :=
      | Assert
          (e : expr var type.prop)
          {tC : type}
          (eC : constraints tC)
          : constraints tC
      | Bind
          {tx : type}
          (ex : constraints tx)
          {tC : type}
          (eC : var tx -> constraints tC)
          : constraints tC
      | Ret
          {t : type}
          (ex : expr var t)
          : constraints t.
  End WithSubstitutionType.
  Arguments constraints : clear implicits.

  Fixpoint interp {t} (c : constraints type.interp t) : Prop * type.interp t :=
    match c in constraints _ t return Prop * type.interp t with
    | Assert ep eC =>
        let p := expr.interp ep in
        let q_v := interp eC in
        (p /\ fst q_v, snd q_v)
    | Bind ex eC =>
        let p_x := interp ex in
        let q_y := interp (eC (snd p_x)) in
        (fst p_x /\ fst q_y, snd q_y)
    | Ret ex => (True, expr.interp ex)
    end.
End constraints.
Notation constraints := constraints.constraints.

(** Returning to the example *)
Module example.
  Section WithSubstitutionType.
    Context {var : type -> Type}.

    (* PHOAS boilerplate *)
    Local Coercion var : type >-> Sortclass.
    Let exprVar {t} := expr.Var (var:=var) (tx:=t).
    Local Coercion exprVar : var >-> expr.

    Definition add (x y : type.F) : expr var type.F :=
      expr.BinOp op.add x y.

    Definition constrainAdd (x y z : type.F) : constraints var type.unit :=
      constraints.Assert (expr.BinOp op.eq (add x y) z) (
      constraints.Ret expr.tt).
  End WithSubstitutionType.

  Lemma add_Z (x y : F) :
    0 <= (x + y)%Z < p ->
    expr.interp (add x y) = (x+y)%Z :> Z.
  Proof.
    cbv [add]. (* unfold the program *)
    cbn [op.interp expr.interp constraints.interp fst snd]. (* partially evaluate the interpeter *)

    (* same proof as field_gallina_add_Z *)
    intros.
    rewrite Zmod.to_Z_add, Z.mod_small; lia.
  Qed.

  (* proving a simple constraint program *)

  Lemma constrainAdd_Z (x y z : F) :
    0 <= (x + y)%Z < p ->
    fst (constraints.interp (constrainAdd x y z)) <-> (x+y = z)%Z.
  Proof.
    cbv [constrainAdd]. (* unfold the program *)
    cbn [op.interp expr.interp constraints.interp fst snd]. (* partially evaluate the interpeter *)

    intros.
    rewrite <-add_Z by eauto.
    Local Set Printing Coercions.
    rewrite Zmod.unsigned_inj_iff.
    Local Unset Printing Coercions.
    intuition idtac.
  Qed.
End example.

(** References:
   - stdlib https://rocq-prover.org/doc/master/stdlib/Stdlib.Zmod.Zmod.html
   - expression encoding: http://adam.chlipala.net/cpdt/html/Cpdt.ProgLang.html#:~:text=Parametric%20Higher%2DOrder%20Abstract%20Syntax and http://adam.chlipala.net/theses/andreser_meng.pdf section 4.4 is my own recap of it

   - you may want Notations like https://github.com/mit-plv/fiat2/blob/main/fiat2/src/fiat2/Notations.v#L53-L84
   - proof tactics nsatz and lia https://rocq-prover.org/doc/V8.19.0/refman/addendum/nsatz.html https://rocq-prover.org/doc/V8.19.0/refman/addendum/micromega.html
*)
