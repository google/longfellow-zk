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

use circuits_boolean::{Bitw, Boolean};
use compile_algebra::field::CompileField;
use compile_logic::{Eltw, Logic};
use util::array::{init, map, map2, map3, tree_fold, tree_fold2};

type PrefixOp<'a, L> = dyn Fn(&(Bitw<L>, Bitw<L>), &(Bitw<L>, Bitw<L>)) -> (Bitw<L>, Bitw<L>) + 'a;

pub struct Arithmetic<'a, L: Logic> {
    logic: &'a L,
    boolean: Boolean<'a, L>,
}

impl<'a, F: CompileField, L: Logic<F = F>> Arithmetic<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            boolean: Boolean::new(logic),
        }
    }

    // Assertions
    pub fn assert_false(&self, name: &str, a: &[Bitw<L>]) -> L::Assertions {
        self.logic.assert_mapi(name, 0..a.len(), |i| {
            self.boolean.assert_false(&format!("bit.{i}"), &a[i])
        })
    }

    pub fn assert_true(&self, name: &str, a: &[Bitw<L>]) -> L::Assertions {
        self.logic.assert_mapi(name, 0..a.len(), |i| {
            self.boolean.assert_true(&format!("bit.{i}"), &a[i])
        })
    }

    pub fn assert_eq(&self, name: &str, a: &[Bitw<L>], b: &[Bitw<L>]) -> L::Assertions {
        let f = self.logic.field();
        let dim = f.pseudo_dimension();
        assert_eq!(a.len(), b.len(), "assert_eq: slice lengths must match");

        let n = a.len();
        if n == 0 {
            return self.logic.ok();
        }

        let k = n.div_ceil(dim); // Number of chunks (ceil(n / dim))

        let mut remaining_n = n;
        let mut remaining_k = k;
        let mut idx = 0;

        self.logic.assert_mapi(name, 0..k, |_| {
            let chunk_size = remaining_n / remaining_k;
            let chunk_a = &a[idx..idx + chunk_size];
            let chunk_b = &b[idx..idx + chunk_size];
            idx += chunk_size;
            remaining_n -= chunk_size;
            remaining_k -= 1;

            let elt_a = self.as_eltw_field(chunk_a);
            let elt_b = self.as_eltw_field(chunk_b);
            self.logic.assert_eq("chunk_eq", &elt_a, &elt_b)
        })
    }

    pub fn assert_exactly_one(&self, a: &[Bitw<L>]) -> L::Assertions {
        match a {
            [] => panic!("assert_exactly_one of empty array"),
            [single] => self.boolean.assert_true("single", single),
            _ => {
                let base_fn = |x: &Bitw<L>| (self.boolean.b(x), self.logic.ok());

                let fold_fn =
                    |(any_l, assert_l): (Bitw<L>, L::Assertions),
                     (any_r, assert_r): (Bitw<L>, L::Assertions)| {
                        let at_most_one = self
                            .boolean
                            .assert_false("at_most_one", &self.boolean.andb(&any_l, &any_r));
                        let combined_assert = self
                            .logic
                            .assert_all("at_most_one_step", &[assert_l, assert_r, at_most_one]);
                        let combined_any =
                            self.boolean.or_assuming_at_most_one_true(&any_l, &any_r);
                        (combined_any, combined_assert)
                    };

                let (any_root, assert_root) = tree_fold(a, &fold_fn, &base_fn);
                self.logic.assert_all(
                    "assert_exactly_one",
                    &[self.boolean.assert_true("any_root", &any_root), assert_root],
                )
            }
        }
    }

    // Adders and Subtractors
    /// Sklansky's parallel prefix scan algorithm on tuples.
    fn sklansky(
        &self,
        arr: &mut [(Bitw<L>, Bitw<L>)],
        i0: usize,
        i1: usize,
        reduce: &PrefixOp<'_, L>,
    ) {
        if i1 - i0 > 1 {
            let im = i0 + (i1 - i0) / 2;
            self.sklansky(arr, i0, im, reduce);
            self.sklansky(arr, im, i1, reduce);
            let prev = (
                self.boolean.b(&arr[im - 1].0),
                self.boolean.b(&arr[im - 1].1),
            );
            for item in &mut arr[im..i1] {
                *item = reduce(&prev, item);
            }
        }
    }

    pub fn scan<FUNC>(&self, reduce: FUNC, oarr: &[(Bitw<L>, Bitw<L>)]) -> Vec<(Bitw<L>, Bitw<L>)>
    where FUNC: Fn(&(Bitw<L>, Bitw<L>), &(Bitw<L>, Bitw<L>)) -> (Bitw<L>, Bitw<L>) {
        let mut arr: Vec<(Bitw<L>, Bitw<L>)> = oarr
            .iter()
            .map(|(x, y)| (self.boolean.b(x), self.boolean.b(y)))
            .collect();
        let n = arr.len();
        if n == 0 {
            return arr;
        }
        self.sklansky(&mut arr, 0, n, &reduce);
        arr
    }

    pub fn lt_reduce(&self, a: &(Bitw<L>, Bitw<L>), b: &(Bitw<L>, Bitw<L>)) -> (Bitw<L>, Bitw<L>) {
        let (eq0, lt0) = a;
        let (eq1, lt1) = b;
        (
            self.boolean
                .tree_andb(&self.boolean.precious(eq0), &self.boolean.precious(eq1)),
            self.boolean.or_assuming_at_most_one_true(
                &self.boolean.precious(lt1),
                &self
                    .boolean
                    .andb(&self.boolean.precious(eq1), &self.boolean.precious(lt0)),
            ),
        )
    }

    pub fn lt_base(&self, a: &Bitw<L>, b: &Bitw<L>) -> (Bitw<L>, Bitw<L>) {
        (self.boolean.eqb(a, b), self.boolean.ltb(a, b))
    }

    #[must_use = "unchecked_sub returns a borrow bit that must be checked or propagated to prevent silent underflow/overflow"]
    pub fn unchecked_sub(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> (Vec<Bitw<L>>, Bitw<L>) {
        assert_eq!(a.len(), b.len(), "unchecked_sub: slice lengths must match");
        let n = a.len();
        assert!(n > 0);
        let olteq: Vec<(Bitw<L>, Bitw<L>)> = init(n, |i| self.lt_base(&a[i], &b[i]));
        let lteq = self.scan(|x, y| self.lt_reduce(x, y), &olteq);
        let c: Vec<Bitw<L>> = init(n, |i| {
            let carry = if i == 0 {
                self.boolean.falseb()
            } else {
                self.boolean.b(&lteq[i - 1].1)
            };
            self.boolean.eqb(&olteq[i].0, &carry)
        });
        (c, self.boolean.b(&lteq[n - 1].1))
    }

    #[must_use = "unchecked_add returns a carry bit that must be checked or propagated to prevent silent overflow"]
    pub fn unchecked_add(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> (Vec<Bitw<L>>, Bitw<L>) {
        assert_eq!(a.len(), b.len(), "unchecked_add: slice lengths must match");
        let not_a: Vec<Bitw<L>> = a.iter().map(|x| self.boolean.notb(x)).collect();
        let (c, carry) = self.unchecked_sub(&not_a, b);
        let not_c: Vec<Bitw<L>> = c.iter().map(|x| self.boolean.notb(x)).collect();
        (not_c, carry)
    }

    #[must_use = "checked_add returns assertions that must be constraint-asserted to prevent silent overflow"]
    pub fn checked_add(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> (Vec<Bitw<L>>, L::Assertions) {
        assert_eq!(a.len(), b.len(), "checked_add: slice lengths must match");
        let (sum, carry) = self.unchecked_add(a, b);
        (sum, self.boolean.assert_false("no_carry", &carry))
    }

    #[must_use = "checked_sub returns assertions that must be constraint-asserted to prevent silent underflow/overflow"]
    pub fn checked_sub(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> (Vec<Bitw<L>>, L::Assertions) {
        assert_eq!(a.len(), b.len(), "checked_sub: slice lengths must match");
        let (diff, borrow) = self.unchecked_sub(a, b);
        (diff, self.boolean.assert_false("no_borrow", &borrow))
    }

    pub fn wrapping_add(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "wrapping_add: slice lengths must match");
        self.unchecked_add(a, b).0
    }

    pub fn wrapping_sub(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "wrapping_sub: slice lengths must match");
        self.unchecked_sub(a, b).0
    }

    pub fn assert_wrapping_add(
        &self,
        c: &[Bitw<L>],
        a: &[Bitw<L>],
        b: &[Bitw<L>],
    ) -> L::Assertions {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        let n = a.len();
        if n == 0 {
            return self.logic.ok();
        }
        let first_assert = self
            .boolean
            .assert_eq("bit0", &c[0], &self.boolean.xorb(&a[0], &b[0]));
        let rest_assert = {
            let cy_len = n - 1;
            let cy = init(cy_len, |i| {
                self.boolean.xor3(&a[i + 1], &b[i + 1], &c[i + 1])
            });
            self.logic.assert_mapi("rest_assert", 0..n - 1, |i| {
                let text_eq_to = if i == 0 {
                    self.boolean.andb(&a[0], &b[0])
                } else {
                    self.boolean.maj(&cy[i - 1], &a[i], &b[i])
                };
                self.boolean.assert_eq("bit_carry", &cy[i], &text_eq_to)
            })
        };
        self.logic
            .assert_all("assert_wrapping_add", &[first_assert, rest_assert])
    }

    pub fn assert_checked_add(&self, c: &[Bitw<L>], a: &[Bitw<L>], b: &[Bitw<L>]) -> L::Assertions {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        let n = a.len();
        if n == 0 {
            return self.logic.ok();
        }
        let carry_out = if n == 1 {
            self.boolean.andb(&a[0], &b[0])
        } else {
            let cy_n_minus_2 = self.boolean.xor3(&a[n - 1], &b[n - 1], &c[n - 1]);
            self.boolean.maj(&cy_n_minus_2, &a[n - 1], &b[n - 1])
        };
        let wrapping = self.assert_wrapping_add(c, a, b);
        let no_carry = self.boolean.assert_false("no_carry_out", &carry_out);

        self.logic
            .assert_all("assert_checked_add", &[wrapping, no_carry])
    }

    // Reductions
    pub fn fold<R, FUNC, Bidx>(&self, a: &[Bitw<L>], f: &FUNC, base: &Bidx, default: R) -> R
    where
        FUNC: Fn(R, R) -> R,
        Bidx: Fn(&Bitw<L>) -> R,
    {
        if a.is_empty() {
            default
        } else {
            tree_fold(a, f, base)
        }
    }

    pub fn fold2<R, FUNC, Bidx>(
        &self,
        a: &[Bitw<L>],
        b: &[Bitw<L>],
        f: &FUNC,
        base: &Bidx,
        default: R,
    ) -> R
    where
        FUNC: Fn(R, R) -> R,
        Bidx: Fn(&Bitw<L>, &Bitw<L>) -> R,
    {
        assert_eq!(a.len(), b.len(), "fold2: slice lengths must match");
        if a.is_empty() {
            default
        } else {
            tree_fold2(a, b, f, base)
        }
    }

    pub fn all(&self, f: &dyn Fn(&Bitw<L>) -> Bitw<L>, a: &[Bitw<L>]) -> Bitw<L> {
        let fold = |x: Bitw<L>, y: Bitw<L>| self.boolean.tree_andb(&x, &y);
        let base = |x: &Bitw<L>| f(x);
        self.fold(a, &fold, &base, self.boolean.trueb())
    }

    pub fn any(&self, f: &dyn Fn(&Bitw<L>) -> Bitw<L>, a: &[Bitw<L>]) -> Bitw<L> {
        let fold = |x: Bitw<L>, y: Bitw<L>| self.boolean.tree_orb(&x, &y);
        let base = |x: &Bitw<L>| f(x);
        self.fold(a, &fold, &base, self.boolean.falseb())
    }

    pub fn eqb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Bitw<L> {
        assert_eq!(a.len(), b.len(), "eqb: slice lengths must match");
        let fold = |x: Bitw<L>, y: Bitw<L>| self.boolean.tree_andb(&x, &y);
        let base = |x: &Bitw<L>, y: &Bitw<L>| self.boolean.eqb(x, y);
        self.fold2(a, b, &fold, &base, self.boolean.trueb())
    }

    pub fn neqb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Bitw<L> {
        assert_eq!(a.len(), b.len(), "neqb: slice lengths must match");
        let eq = self.eqb(a, b);
        self.boolean.notb(&eq)
    }

    pub fn eqmask(&self, a: &[Bitw<L>], b: u64, mask: u64) -> Bitw<L> {
        let mut eq_bits = Vec::new();
        let mut cur_mask = mask;
        let mut cur_b = b;
        for bit_a in a {
            if (cur_mask & 1) == 1 {
                let bit_b = (cur_b & 1) == 1;
                let eq_bit = if bit_b {
                    bit_a.clone()
                } else {
                    self.boolean.notb(bit_a)
                };
                eq_bits.push(eq_bit);
            }
            cur_mask >>= 1;
            cur_b >>= 1;
        }
        self.all(&|x| x.clone(), &eq_bits)
    }

    pub fn lt(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Bitw<L> {
        assert_eq!(a.len(), b.len(), "lt: slice lengths must match");
        let fold = |x: (Bitw<L>, Bitw<L>), y: (Bitw<L>, Bitw<L>)| self.lt_reduce(&x, &y);
        let base = |x: &Bitw<L>, y: &Bitw<L>| self.lt_base(x, y);
        let res = self.fold2(
            a,
            b,
            &fold,
            &base,
            (self.boolean.trueb(), self.boolean.falseb()),
        );
        res.1
    }

    pub fn leq(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Bitw<L> {
        assert_eq!(a.len(), b.len(), "leq: slice lengths must match");
        self.boolean.notb(&self.lt(b, a))
    }

    pub fn gt(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Bitw<L> {
        assert_eq!(a.len(), b.len(), "gt: slice lengths must match");
        self.lt(b, a)
    }

    pub fn geq(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Bitw<L> {
        assert_eq!(a.len(), b.len(), "geq: slice lengths must match");
        self.leq(b, a)
    }

    pub fn relint(
        &self,
        f: &dyn Fn(&[Bitw<L>], &[Bitw<L>]) -> Bitw<L>,
        a: &[Bitw<L>],
        i: u64,
    ) -> Bitw<L> {
        f(a, &self.of_u64(a.len(), i))
    }

    // Elementwise operations
    pub fn muxb(&self, b: &[Bitw<L>], iftrue: &[Bitw<L>], iffalse: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(
            b.len(),
            iftrue.len(),
            "muxb: condition and iftrue lengths must match"
        );
        assert_eq!(
            b.len(),
            iffalse.len(),
            "muxb: condition and iffalse lengths must match"
        );
        map3(b, iftrue, iffalse, |x, y, z| self.boolean.muxb(x, y, z))
    }

    pub fn xor3(&self, a: &[Bitw<L>], b: &[Bitw<L>], c: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "xor3: a and b lengths must match");
        assert_eq!(a.len(), c.len(), "xor3: a and c lengths must match");
        map3(a, b, c, |x, y, z| self.boolean.xor3(x, y, z))
    }

    pub fn maj(&self, x: &[Bitw<L>], y: &[Bitw<L>], z: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(x.len(), y.len(), "maj: x and y lengths must match");
        assert_eq!(x.len(), z.len(), "maj: x and z lengths must match");
        map3(x, y, z, |a, b, c| self.boolean.maj(a, b, c))
    }

    pub fn andb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "andb: slice lengths must match");
        map2(a, b, |x, y| self.boolean.andb(x, y))
    }

    pub fn orb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "orb: slice lengths must match");
        map2(a, b, |x, y| self.boolean.orb(x, y))
    }

    pub fn or_assuming_at_most_one_true(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(
            a.len(),
            b.len(),
            "or_assuming_at_most_one_true: slice lengths must match"
        );
        map2(a, b, |x, y| self.boolean.or_assuming_at_most_one_true(x, y))
    }

    pub fn xorb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "xorb: slice lengths must match");
        map2(a, b, |x, y| self.boolean.xorb(x, y))
    }

    pub fn tree_xorb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "tree_xorb: slice lengths must match");
        map2(a, b, |x, y| self.boolean.tree_xorb(x, y))
    }

    pub fn eq(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "eq: slice lengths must match");
        map2(a, b, |x, y| self.boolean.eqb(x, y))
    }

    pub fn ltb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "ltb: slice lengths must match");
        map2(a, b, |x, y| self.boolean.ltb(x, y))
    }

    pub fn notb(&self, a: &[Bitw<L>]) -> Vec<Bitw<L>> {
        map(a, |x| self.boolean.notb(x))
    }

    pub fn impliesb(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        assert_eq!(a.len(), b.len(), "impliesb: slice lengths must match");
        map2(a, b, |x, y| self.boolean.impliesb(x, y))
    }

    pub fn precious(&self, a: &[Bitw<L>]) -> Vec<Bitw<L>> {
        map(a, |x| self.boolean.precious(x))
    }

    // Shifts
    pub fn shl(&self, s: usize, a: &[Bitw<L>]) -> Vec<Bitw<L>> {
        let n = a.len();
        init(n, |i| {
            if i >= s {
                self.boolean.b(&a[i - s])
            } else {
                self.boolean.falseb()
            }
        })
    }

    pub fn shr(&self, s: usize, a: &[Bitw<L>]) -> Vec<Bitw<L>> {
        let n = a.len();
        init(n, |i| {
            if i + s < n {
                self.boolean.b(&a[i + s])
            } else {
                self.boolean.falseb()
            }
        })
    }

    pub fn rotr(&self, s: usize, a: &[Bitw<L>]) -> Vec<Bitw<L>> {
        let n = a.len();
        if n == 0 {
            return Vec::new();
        }
        init(n, |i| self.boolean.b(&a[(i + s) % n]))
    }

    pub fn rotl(&self, s: usize, a: &[Bitw<L>]) -> Vec<Bitw<L>> {
        let n = a.len();
        if n == 0 {
            return Vec::new();
        }
        init(n, |i| {
            let idx = ((i as isize - s as isize) % n as isize + n as isize) as usize % n;
            self.boolean.b(&a[idx])
        })
    }

    pub fn as_eltw_field(&self, a: &[Bitw<L>]) -> Eltw<L> {
        let f = self.logic.field();
        assert!(
            a.len() <= f.pseudo_dimension(),
            "Bitvector length {} exceeds field capacity {}",
            a.len(),
            f.pseudo_dimension()
        );
        let terms: Vec<_> = a
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let field_coef = f.pseudo_basis(i);
                self.logic.mulk(&field_coef, &self.boolean.as_eltw(x))
            })
            .collect();
        self.logic.sum(&terms)
    }

    pub fn as_eltw_unsafe(&self, a: &[Bitw<L>]) -> Eltw<L> {
        let f = self.logic.field();
        let terms: Vec<_> = a
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let field_coef = f.pseudo_basis_unsafe(i);
                self.logic.mulk(&field_coef, &self.boolean.as_eltw(x))
            })
            .collect();
        self.logic.sum(&terms)
    }

    pub fn konst(&self, bools: &[bool]) -> Vec<Bitw<L>> {
        bools.iter().map(|&b| self.boolean.konst(b)).collect()
    }

    pub fn zero(&self, n: usize) -> Vec<Bitw<L>> {
        init(n, |_| self.boolean.falseb())
    }

    pub fn is_zero(&self, a: &[Bitw<L>]) -> Bitw<L> {
        self.eqb(a, &self.zero(a.len()))
    }

    pub fn of_u64(&self, n: usize, z: u64) -> Vec<Bitw<L>> {
        if n < 64 {
            let limit = 1u64 << n;
            assert!(z < limit, "of_u64: integer does not fit");
        }
        init(n, |i| {
            let bit_val = (z.checked_shr(i as u32).unwrap_or(0) & 1) == 1;
            self.boolean.konst(bit_val)
        })
    }

    pub fn of_u8(&self, z: u8) -> Vec<Bitw<L>> {
        self.of_u64(8, u64::from(z))
    }

    pub fn of_u32(&self, z: u32) -> Vec<Bitw<L>> {
        init(32, |i| {
            self.boolean
                .konst((z.checked_shr(i as u32).unwrap_or(0) & 1) == 1)
        })
    }

    pub fn of_u64_val(&self, z: u64) -> Vec<Bitw<L>> {
        init(64, |i| {
            self.boolean
                .konst((z.checked_shr(i as u32).unwrap_or(0) & 1) == 1)
        })
    }

    pub fn one_hot_mux(
        &self,
        n: usize,
        selector: &[Bitw<L>],
        data: &dyn Fn(usize) -> Vec<Bitw<L>>,
    ) -> Vec<Bitw<L>> {
        let addends: Vec<Vec<Bitw<L>>> = init(selector.len(), |i| {
            let addend = data(i);
            assert_eq!(addend.len(), n, "one_hot_mux: arrays of different length");
            addend
        });

        init(n, |j| {
            self.boolean
                .one_hot_muxb(selector, &|i| addends[i][j].clone())
        })
    }
}
