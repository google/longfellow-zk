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

use circuits_arithmetic::Arithmetic;
use circuits_boolean::{Bitw, Boolean, BooleanIO};
use compile_algebra::field::CompileField;
use compile_logic::{Eltw, Logic};
use util::array::{init, map, map2, map3};

pub struct Bitvec<L: Logic, const N: usize> {
    bits: Vec<Bitw<L>>,
}
// We implement Clone manually to avoid the standard derive adding an
// unnecessary `L: Clone` bound. L represents the logic type (e.g. EvalLogic or
// CompilerLogic) which does not need to be Clone for the bit-vector itself to
// be cloned.
impl<L: Logic, const N: usize> Clone for Bitvec<L, N> {
    fn clone(&self) -> Self {
        Self {
            bits: self.bits.clone(),
        }
    }
}

impl<L: Logic, const N: usize> Bitvec<L, N> {
    #[must_use]
    pub fn new(bits: Vec<Bitw<L>>) -> Self {
        assert_eq!(bits.len(), N);
        Self { bits }
    }

    #[must_use]
    pub fn nbits(&self) -> usize {
        N
    }

    #[must_use]
    pub fn len(&self) -> usize {
        N
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        N == 0
    }

    #[must_use]
    pub fn as_array(&self) -> &[Bitw<L>] {
        &self.bits
    }

    #[must_use]
    pub fn bit(&self, k: usize) -> &Bitw<L> {
        &self.bits[k]
    }

    pub fn bit_mut(&mut self, k: usize) -> &mut Bitw<L> {
        &mut self.bits[k]
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Bitw<L>> {
        self.bits.iter()
    }
}

impl<L: Logic, const N: usize> std::ops::Index<usize> for Bitvec<L, N> {
    type Output = Bitw<L>;
    fn index(&self, index: usize) -> &Self::Output {
        &self.bits[index]
    }
}

pub struct BitvecLogic<'a, L: Logic> {
    logic: &'a L,
    arith: Arithmetic<'a, L>,
    boolean: Boolean<'a, L>,
}

impl<'a, Fld: CompileField, L: Logic<F = Fld>> BitvecLogic<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            arith: Arithmetic::new(logic),
            boolean: Boolean::new(logic),
        }
    }

    pub fn logic(&self) -> &L {
        self.logic
    }

    pub fn b(&self, bit: &Bitw<L>) -> Bitw<L> {
        self.boolean.b(bit)
    }

    pub fn from_fn<const N: usize, F>(&self, f: F) -> Bitvec<L, N>
    where
        F: Fn(usize) -> Bitw<L>,
    {
        Bitvec { bits: init(N, f) }
    }

    pub fn from_vec<const N: usize>(
        &self,
        vec: Vec<Bitw<L>>,
    ) -> Result<Bitvec<L, N>, &'static str> {
        if vec.len() == N {
            Ok(Bitvec { bits: vec })
        } else {
            Err("Out of bounds: vector length mismatch")
        }
    }

    pub fn zext_bit<const N: usize>(
        &self,
        bv: &Bitvec<L, N>,
        i: usize,
    ) -> Result<Bitw<L>, &'static str> {
        if i < N {
            Ok(self.b(&bv.bits[i]))
        } else {
            Ok(self.boolean.falseb())
        }
    }

    pub fn map<const N: usize, F>(&self, bv: &Bitvec<L, N>, f: F) -> Bitvec<L, N>
    where
        F: Fn(&Bitw<L>) -> Bitw<L>,
    {
        Bitvec {
            bits: map(&bv.bits, f),
        }
    }

    pub fn map2<const N: usize, F>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>, f: F) -> Bitvec<L, N>
    where
        F: Fn(&Bitw<L>, &Bitw<L>) -> Bitw<L>,
    {
        Bitvec {
            bits: map2(&a.bits, &b.bits, f),
        }
    }

    pub fn map3<const N: usize, F>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
        c: &Bitvec<L, N>,
        f: F,
    ) -> Bitvec<L, N>
    where
        F: Fn(&Bitw<L>, &Bitw<L>, &Bitw<L>) -> Bitw<L>,
    {
        Bitvec {
            bits: map3(&a.bits, &b.bits, &c.bits, f),
        }
    }

    pub fn fold<const N: usize, R, F, Bidx>(
        &self,
        bv: &Bitvec<L, N>,
        f: &F,
        base: &Bidx,
        default: R,
    ) -> R
    where
        F: Fn(R, R) -> R,
        Bidx: Fn(&Bitw<L>) -> R,
    {
        self.arith.fold(&bv.bits, f, base, default)
    }

    pub fn fold2<const N: usize, R, F, Bidx>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
        f: &F,
        base: &Bidx,
        default: R,
    ) -> R
    where
        F: Fn(R, R) -> R,
        Bidx: Fn(&Bitw<L>, &Bitw<L>) -> R,
    {
        self.arith.fold2(&a.bits, &b.bits, f, base, default)
    }

    pub fn all<const N: usize>(
        &self,
        bv: &Bitvec<L, N>,
        f: &dyn Fn(&Bitw<L>) -> Bitw<L>,
    ) -> Bitw<L> {
        self.arith.all(f, &bv.bits)
    }

    pub fn any<const N: usize>(
        &self,
        bv: &Bitvec<L, N>,
        f: &dyn Fn(&Bitw<L>) -> Bitw<L>,
    ) -> Bitw<L> {
        self.arith.any(f, &bv.bits)
    }

    pub fn eqb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.eqb(&a.bits, &b.bits)
    }

    pub fn neqb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.neqb(&a.bits, &b.bits)
    }

    pub fn eqmask<const N: usize>(&self, a: &Bitvec<L, N>, b: u64, mask: u64) -> Bitw<L> {
        self.arith.eqmask(&a.bits, b, mask)
    }

    pub fn lt<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.lt(&a.bits, &b.bits)
    }

    pub fn leq<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.leq(&a.bits, &b.bits)
    }

    pub fn gt<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.gt(&a.bits, &b.bits)
    }

    pub fn geq<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.geq(&a.bits, &b.bits)
    }

    pub fn relint<const N: usize>(
        &self,
        bv: &Bitvec<L, N>,
        f: &dyn Fn(&[Bitw<L>], &[Bitw<L>]) -> Bitw<L>,
        i: u64,
    ) -> Bitw<L> {
        self.arith.relint(f, &bv.bits, i)
    }

    #[must_use = "unchecked_add returns a carry bit that must be checked or propagated to prevent silent overflow"]
    pub fn unchecked_add<const N: usize>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> (Bitvec<L, N>, Bitw<L>) {
        let (c, carry) = self.arith.unchecked_add(&a.bits, &b.bits);
        (Bitvec { bits: c }, carry)
    }

    #[must_use = "unchecked_sub returns a borrow bit that must be checked or propagated to prevent silent underflow/overflow"]
    pub fn unchecked_sub<const N: usize>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> (Bitvec<L, N>, Bitw<L>) {
        let (c, borrow) = self.arith.unchecked_sub(&a.bits, &b.bits);
        (Bitvec { bits: c }, borrow)
    }

    #[must_use = "checked_add returns assertions that must be constraint-asserted to prevent silent overflow"]
    pub fn checked_add<const N: usize>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> (Bitvec<L, N>, L::Assertions) {
        let (sum, assert) = self.arith.checked_add(&a.bits, &b.bits);
        (Bitvec { bits: sum }, assert)
    }

    #[must_use = "checked_sub returns assertions that must be constraint-asserted to prevent silent underflow/overflow"]
    pub fn checked_sub<const N: usize>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> (Bitvec<L, N>, L::Assertions) {
        let (diff, assert) = self.arith.checked_sub(&a.bits, &b.bits);
        (Bitvec { bits: diff }, assert)
    }

    pub fn wrapping_add<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.wrapping_add(&a.bits, &b.bits),
        }
    }

    pub fn wrapping_sub<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.wrapping_sub(&a.bits, &b.bits),
        }
    }

    pub fn assert_wrapping_add<const N: usize>(
        &self,
        c: &Bitvec<L, N>,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> L::Assertions {
        self.arith.assert_wrapping_add(&c.bits, &a.bits, &b.bits)
    }

    pub fn assert_checked_add<const N: usize>(
        &self,
        c: &Bitvec<L, N>,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> L::Assertions {
        self.arith.assert_checked_add(&c.bits, &a.bits, &b.bits)
    }

    pub fn muxb<const N: usize>(
        &self,
        selector: &Bitvec<L, N>,
        iftrue: &Bitvec<L, N>,
        iffalse: &Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.muxb(&selector.bits, &iftrue.bits, &iffalse.bits),
        }
    }

    pub fn select<const N: usize>(
        &self,
        b: &Bitw<L>,
        iftrue: &Bitvec<L, N>,
        iffalse: &Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        let boolean = Boolean::new(self.logic);
        let mut bits = Vec::with_capacity(N);
        for i in 0..N {
            bits.push(boolean.muxb(b, iftrue.bit(i), iffalse.bit(i)));
        }
        Bitvec::new(bits)
    }

    pub fn xor3<const N: usize>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
        c: &Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.xor3(&a.bits, &b.bits, &c.bits),
        }
    }

    pub fn maj<const N: usize>(
        &self,
        x: &Bitvec<L, N>,
        y: &Bitvec<L, N>,
        z: &Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.maj(&x.bits, &y.bits, &z.bits),
        }
    }

    pub fn andb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.andb(&a.bits, &b.bits),
        }
    }

    pub fn chi_laneb<const N: usize>(
        &self,
        x: &Bitvec<L, N>,
        y: &Bitvec<L, N>,
        z: &Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        self.map3(x, y, z, |a, b, c| self.boolean.chi_laneb(a, b, c))
    }

    pub fn orb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.orb(&a.bits, &b.bits),
        }
    }

    pub fn or_assuming_at_most_one_true<const N: usize>(
        &self,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.or_assuming_at_most_one_true(&a.bits, &b.bits),
        }
    }

    pub fn xorb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.xorb(&a.bits, &b.bits),
        }
    }

    pub fn tree_xorb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.tree_xorb(&a.bits, &b.bits),
        }
    }

    pub fn eq<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.eq(&a.bits, &b.bits),
        }
    }

    pub fn ltb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.ltb(&a.bits, &b.bits),
        }
    }

    pub fn notb<const N: usize>(&self, a: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.notb(&a.bits),
        }
    }

    pub fn impliesb<const N: usize>(&self, a: &Bitvec<L, N>, b: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.impliesb(&a.bits, &b.bits),
        }
    }

    pub fn precious<const N: usize>(&self, a: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.precious(&a.bits),
        }
    }

    pub fn shl<const N: usize>(&self, s: usize, a: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.shl(s, &a.bits),
        }
    }

    pub fn shr<const N: usize>(&self, s: usize, a: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.shr(s, &a.bits),
        }
    }

    pub fn rotl<const N: usize>(&self, s: usize, a: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.rotl(s, &a.bits),
        }
    }

    pub fn rotr<const N: usize>(&self, s: usize, a: &Bitvec<L, N>) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.rotr(s, &a.bits),
        }
    }

    pub fn as_eltw_field<const N: usize>(&self, bv: &Bitvec<L, N>) -> Eltw<L> {
        self.arith.as_eltw_field(&bv.bits)
    }

    pub fn as_eltw_unsafe<const N: usize>(&self, bv: &Bitvec<L, N>) -> Eltw<L> {
        self.arith.as_eltw_unsafe(&bv.bits)
    }

    pub fn zero<const N: usize>(&self) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.zero(N),
        }
    }

    pub fn is_zero<const N: usize>(&self, a: &Bitvec<L, N>) -> Bitw<L> {
        self.arith.is_zero(&a.bits)
    }

    pub fn of_u64<const N: usize>(&self, z: u64) -> Bitvec<L, N> {
        Bitvec {
            bits: self.arith.of_u64(N, z),
        }
    }

    pub fn of_bit<const N: usize>(&self, b: &Bitw<L>) -> Bitvec<L, N> {
        Bitvec {
            bits: vec![b.clone(); N],
        }
    }

    pub fn of_u8(&self, z: u8) -> Bitvec<L, 8> {
        Bitvec {
            bits: self.arith.of_u8(z),
        }
    }

    pub fn of_u32(&self, z: u32) -> Bitvec<L, 32> {
        Bitvec {
            bits: self.arith.of_u32(z),
        }
    }

    pub fn of_u64_val(&self, z: u64) -> Bitvec<L, 64> {
        Bitvec {
            bits: self.arith.of_u64_val(z),
        }
    }

    pub fn assert_false<const N: usize>(&self, name: &str, bv: &Bitvec<L, N>) -> L::Assertions {
        self.arith.assert_false(name, &bv.bits)
    }

    pub fn assert_true<const N: usize>(&self, name: &str, bv: &Bitvec<L, N>) -> L::Assertions {
        self.arith.assert_true(name, &bv.bits)
    }

    pub fn assert_eq<const N: usize>(
        &self,
        name: &str,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> L::Assertions {
        self.arith.assert_eq(name, &a.bits, &b.bits)
    }

    pub fn assert_neq<const N: usize>(
        &self,
        name: &str,
        a: &Bitvec<L, N>,
        b: &Bitvec<L, N>,
    ) -> L::Assertions {
        let neq = self.neqb(a, b);
        self.boolean.assert_true(name, &neq)
    }

    pub fn one_hot_mux<const N: usize>(
        &self,
        selector: &[Bitw<L>],
        data: &dyn Fn(usize) -> Bitvec<L, N>,
    ) -> Bitvec<L, N> {
        let vec_data = |idx: usize| data(idx).bits;
        let res = self.arith.one_hot_mux(N, selector, &vec_data);
        Bitvec { bits: res }
    }

    pub fn shl_safe<const N: usize>(
        &self,
        k: usize,
        a: &Bitvec<L, N>,
    ) -> (Bitvec<L, N>, L::Assertions) {
        assert!(k < N);
        let boolean = Boolean::new(self.logic);
        let assertions = self.logic.assert_mapi("shl_exact", (N - k)..N, |i| {
            boolean.assert_false(&format!("overflow_bit.{i}"), a.bit(i))
        });
        let shifted = self.shl(k, a);
        (shifted, assertions)
    }

    pub fn split<const N: usize, const M: usize, const K: usize>(
        &self,
        bv: &Bitvec<L, N>,
    ) -> (Bitvec<L, M>, Bitvec<L, K>) {
        const { assert!(M + K == N, "split sizes must sum to N") };
        let bits = &bv.bits;
        let low = self
            .from_vec::<M>(bits[0..M].to_vec())
            .expect("split low failed");
        let high = self
            .from_vec::<K>(bits[M..N].to_vec())
            .expect("split high failed");
        (low, high)
    }

    pub fn zext<const N: usize, const M: usize>(&self, bv: &Bitvec<L, N>) -> Bitvec<L, M> {
        const { assert!(M >= N, "zext can only extend, not truncate") };
        Bitvec::new(self.boolean.zext(&bv.bits, M))
    }
}

pub struct BitvecIO<'a, L: compile_logic::LogicIO> {
    bools_io: BooleanIO<'a, L>,
}

impl<'a, L: compile_logic::LogicIO> BitvecIO<'a, L> {
    pub fn new(bv: &'a BitvecLogic<'a, L>) -> Self {
        Self {
            bools_io: BooleanIO::new(bv.logic),
        }
    }

    pub fn input<const N: usize>(&self, start_position: usize) -> Bitvec<L, N> {
        let bits = init(N, |i| self.bools_io.input(start_position + i));
        Bitvec { bits }
    }

    pub fn next<const N: usize>(&self, pos: &mut usize) -> Bitvec<L, N> {
        let bv = self.input(*pos);
        *pos += N;
        bv
    }

    pub fn position_in_input_array<const N: usize>(&self, bitvec: &Bitvec<L, N>) -> usize {
        self.bools_io.position_in_input_array(bitvec.bit(0))
    }
}

impl<L: Logic, const N: usize> std::fmt::Debug for Bitvec<L, N>
where
    Bitw<L>: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bitvec").field("bits", &self.bits).finish()
    }
}

pub struct Slice<L: Logic, T, const N: usize, const W: usize> {
    pub data: [T; N],
    pub len: Bitvec<L, W>,
}

impl<L: Logic, T: Clone, const N: usize, const W: usize> Clone for Slice<L, T, N, W> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            len: self.len.clone(),
        }
    }
}
