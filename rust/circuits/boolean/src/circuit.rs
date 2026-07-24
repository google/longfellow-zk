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

use compile_algebra::field::CompileField;
use compile_logic::{Eltw, Logic, LogicIO};
use core_algebra::ElementOf;

mod imp {
    use super::{CompileField, ElementOf, Eltw, Logic};

    pub(crate) enum Inner<L: Logic> {
        True,
        False,
        P(Eltw<L>),
        N(Eltw<L>),
        X(Eltw<L>),
    }

    impl<L: Logic> Clone for Inner<L> {
        fn clone(&self) -> Self {
            match self {
                Inner::True => Inner::True,
                Inner::False => Inner::False,
                Inner::P(x) => Inner::P(x.clone()),
                Inner::N(x) => Inner::N(x.clone()),
                Inner::X(x) => Inner::X(x.clone()),
            }
        }
    }

    pub struct Bitw<L: Logic>(Inner<L>);

    impl<L: Logic> Clone for Bitw<L> {
        fn clone(&self) -> Self {
            Bitw(self.0.clone())
        }
    }

    impl<L: Logic> PartialEq for Inner<L> {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Inner::True, Inner::True) => true,
                (Inner::False, Inner::False) => true,
                (Inner::P(x), Inner::P(y)) => x == y,
                (Inner::N(x), Inner::N(y)) => x == y,
                (Inner::X(x), Inner::X(y)) => x == y,
                _ => false,
            }
        }
    }

    impl<L: Logic> Eq for Inner<L> {}

    impl<L: Logic> PartialEq for Bitw<L> {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl<L: Logic> Eq for Bitw<L> {}

    pub struct Boolean<'a, L: Logic> {
        logic: &'a L,
        two: ElementOf<L::F>,
        mtwo: ElementOf<L::F>,
        half: ElementOf<L::F>,
        mhalf: ElementOf<L::F>,
    }

    impl<'a, F: CompileField, L: Logic<F = F>> Boolean<'a, L> {
        pub fn new(logic: &'a L) -> Self {
            let f = logic.field();
            let one = f.one();
            let two = f.addf(&one, &one);
            let mtwo = f.addf(&f.mone(), &f.mone());
            let (half, mhalf) = if f.is_zero(&two) {
                (f.zero(), f.zero())
            } else {
                let h = f.invert(&two);
                let mh = f.neg(&h);
                (h, mh)
            };
            Self {
                logic,
                two,
                mtwo,
                half,
                mhalf,
            }
        }

        pub fn logic(&self) -> &'a L {
            self.logic
        }

        pub fn konst(&self, b: bool) -> Bitw<L> {
            if b {
                Bitw(Inner::True)
            } else {
                Bitw(Inner::False)
            }
        }

        pub fn zext(&self, a: &[Bitw<L>], n: usize) -> Vec<Bitw<L>> {
            assert!(n >= a.len(), "zext: target width n must be >= source width");
            let mut bits = Vec::with_capacity(n);
            bits.extend(a.iter().cloned());
            bits.resize(n, self.falseb());
            bits
        }

        pub fn trueb(&self) -> Bitw<L> {
            Bitw(Inner::True)
        }

        pub fn falseb(&self) -> Bitw<L> {
            Bitw(Inner::False)
        }

        pub fn as_eltw(&self, x: &Bitw<L>) -> Eltw<L> {
            let logic = &self.logic;
            match &x.0 {
                Inner::False => logic.zero(),
                Inner::True => logic.one(),
                Inner::P(xv) => xv.clone(),
                Inner::N(xv) => logic.sub(&logic.one(), xv),
                Inner::X(xv) => {
                    assert!(!logic.field().is_zero(&self.two));
                    logic.sum(&[logic.konst(&self.half), logic.mulk(&self.mhalf, xv)])
                }
            }
        }

        fn positive(&self, x: &Bitw<L>) -> Bitw<L> {
            Bitw(Inner::P(self.as_eltw(x)))
        }

        fn as_x(&self, x: &Bitw<L>) -> Eltw<L> {
            let logic = &self.logic;
            let f = logic.field();
            match &x.0 {
                Inner::True => logic.konst(&f.mone()),
                Inner::False => logic.one(),
                Inner::P(xv) => logic.sum(&[logic.one(), logic.mulk(&self.mtwo, xv)]),
                Inner::N(xv) => logic.sum(&[logic.konst(&f.mone()), logic.mulk(&self.two, xv)]),
                Inner::X(xv) => {
                    assert!(!f.is_zero(&self.two));
                    xv.clone()
                }
            }
        }

        pub fn precious(&self, x: &Bitw<L>) -> Bitw<L> {
            let logic = &self.logic;
            match &x.0 {
                Inner::True => Bitw(Inner::True),
                Inner::False => Bitw(Inner::False),
                Inner::P(xv) => Bitw(Inner::P(logic.precious(xv))),
                Inner::N(xv) => Bitw(Inner::N(logic.precious(xv))),
                Inner::X(xv) => Bitw(Inner::X(logic.precious(xv))),
            }
        }

        pub fn of_eltw(&self, x: Eltw<L>) -> Bitw<L> {
            let logic = &self.logic;
            let zero_or_one = logic.assert0("is_boolean", &logic.sub(&x, &logic.mul(&x, &x)));
            Bitw(Inner::P(logic.with_assertions(zero_or_one, &x)))
        }

        pub fn of_eltw_with_assertion(&self, x: Eltw<L>, assertion: L::Assertions) -> Bitw<L> {
            Bitw(Inner::P(self.logic.with_assertions(assertion, &x)))
        }

        pub fn b(&self, bit: &Bitw<L>) -> Bitw<L> {
            match &bit.0 {
                Inner::True => Bitw(Inner::True),
                Inner::False => Bitw(Inner::False),
                Inner::P(xv) => Bitw(Inner::P(xv.clone())),
                Inner::N(xv) => Bitw(Inner::N(xv.clone())),
                Inner::X(xv) => Bitw(Inner::X(xv.clone())),
            }
        }

        pub fn notb(&self, x: &Bitw<L>) -> Bitw<L> {
            match &x.0 {
                Inner::True => Bitw(Inner::False),
                Inner::False => Bitw(Inner::True),
                Inner::P(xv) => Bitw(Inner::N(xv.clone())),
                Inner::N(xv) => Bitw(Inner::P(xv.clone())),
                Inner::X(xv) => Bitw(Inner::X(self.logic.neg(xv))),
            }
        }

        pub fn or_assuming_at_most_one_true(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            let logic = &self.logic;
            match (&a.0, &b.0) {
                (Inner::True, _) | (_, Inner::True) => Bitw(Inner::True),
                (Inner::False, _) => self.b(b),
                (_, Inner::False) => self.b(a),
                (Inner::P(x), Inner::P(y)) => Bitw(Inner::P(logic.add(x, y))),
                (Inner::P(x), Inner::N(y)) => Bitw(Inner::N(logic.sub(y, x))),
                (Inner::N(x), Inner::P(y)) => Bitw(Inner::N(logic.sub(x, y))),
                (Inner::N(x), Inner::N(y)) => {
                    let mone = logic.neg(&logic.one());
                    Bitw(Inner::N(logic.sum(&[x.clone(), y.clone(), mone])))
                }
                _ => {
                    let ap = self.as_eltw(a);
                    let bp = self.as_eltw(b);
                    Bitw(Inner::P(logic.add(&ap, &bp)))
                }
            }
        }
        pub fn sum_assuming_at_most_one_true(&self, a: &[Bitw<L>]) -> Bitw<L> {
            let elts: Vec<Eltw<L>> = a.iter().map(|x| self.as_eltw(x)).collect();
            Bitw(Inner::P(self.logic.sum(&elts)))
        }
        pub fn andb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            let logic = &self.logic;
            match (&a.0, &b.0) {
                (Inner::True, _) => self.b(b),
                (_, Inner::True) => self.b(a),
                (Inner::False, _) | (_, Inner::False) => Bitw(Inner::False),
                (Inner::P(x), Inner::P(y)) => Bitw(Inner::P(logic.mul(x, y))),
                (Inner::P(x), Inner::N(y)) => {
                    let negmul = logic.neg(&logic.mul(x, y));
                    Bitw(Inner::P(logic.sum(&[logic.precious(x), negmul])))
                }
                (Inner::N(_), Inner::P(_)) => self.andb(b, a),
                (Inner::N(x), Inner::N(y)) => {
                    let negmul = logic.neg(&logic.mul(x, y));
                    Bitw(Inner::N(logic.sum(&[
                        logic.precious(x),
                        logic.precious(y),
                        negmul,
                    ])))
                }
                _ => {
                    let ap = self.as_eltw(a);
                    let bp = self.as_eltw(b);
                    Bitw(Inner::P(logic.mul(&ap, &bp)))
                }
            }
        }

        pub fn tree_andb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.positive(&self.andb(a, b))
        }

        pub fn orb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.notb(&self.andb(&self.notb(a), &self.notb(b)))
        }

        pub fn tree_orb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.notb(&self.tree_andb(&self.notb(a), &self.notb(b)))
        }

        pub fn xorb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            let logic = &self.logic;
            let f = logic.field();
            match (&a.0, &b.0) {
                (Inner::False, _) => self.b(b),
                (_, Inner::False) => self.b(a),
                (Inner::True, _) => self.notb(b),
                (_, Inner::True) => self.notb(a),
                (Inner::X(_), _) | (_, Inner::X(_)) => {
                    if f.is_zero(&self.two) {
                        Bitw(Inner::P(logic.add(&self.as_eltw(a), &self.as_eltw(b))))
                    } else {
                        Bitw(Inner::X(logic.mul(&self.as_x(a), &self.as_x(b))))
                    }
                }
                (Inner::P(x), Inner::P(y)) => Bitw(Inner::P(self.xor_base(x, y))),
                (Inner::P(_), Inner::N(_)) => self.notb(&self.xorb(a, &self.notb(b))),
                (Inner::N(_), Inner::P(_)) => self.notb(&self.xorb(&self.notb(a), b)),
                (Inner::N(_), Inner::N(_)) => self.xorb(&self.notb(a), &self.notb(b)),
            }
        }

        pub fn tree_xorb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            let logic = &self.logic;
            let f = logic.field();
            if f.is_zero(&self.two) {
                self.xorb(a, b)
            } else {
                match (&a.0, &b.0) {
                    (Inner::False, x) | (x, Inner::False) => Bitw(x.clone()),
                    (Inner::True, x) | (x, Inner::True) => self.notb(&Bitw(x.clone())),
                    _ => {
                        let ax = self.as_x(a);
                        let bx = self.as_x(b);
                        Bitw(Inner::X(logic.mul(&ax, &bx)))
                    }
                }
            }
        }

        fn xor_base(&self, x: &Eltw<L>, y: &Eltw<L>) -> Eltw<L> {
            let logic = &self.logic;
            let f = logic.field();
            if f.is_zero(&self.two) {
                logic.add(x, y)
            } else {
                logic.sum(&[
                    logic.precious(x),
                    logic.precious(y),
                    logic.mulk(&self.mtwo, &logic.mul(x, y)),
                ])
            }
        }

        pub fn eqb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.notb(&self.xorb(a, b))
        }

        pub fn neqb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.xorb(a, b)
        }

        pub fn parity(&self, a: &[Bitw<L>]) -> Bitw<L> {
            if a.is_empty() {
                self.falseb()
            } else {
                util::array::tree_fold(
                    a,
                    &|x: Bitw<L>, y: Bitw<L>| self.tree_xorb(&x, &y),
                    &|x: &Bitw<L>| x.clone(),
                )
            }
        }

        pub fn mulbe(&self, b: &Bitw<L>, e: &Eltw<L>) -> Eltw<L> {
            self.logic.mul(&self.as_eltw(b), e)
        }

        pub fn muxe(&self, b: &Bitw<L>, iftrue: &Eltw<L>, iffalse: &Eltw<L>) -> Eltw<L> {
            self.logic
                .sum(&[self.mulbe(b, iftrue), self.mulbe(&self.notb(b), iffalse)])
        }

        pub fn one_hot_muxe(
            &self,
            selector: &[Bitw<L>],
            data: &dyn Fn(usize) -> Eltw<L>,
        ) -> Eltw<L> {
            let elts: Vec<Eltw<L>> = selector
                .iter()
                .enumerate()
                .map(|(i, s)| self.mulbe(s, &data(i)))
                .collect();
            self.logic.sum(&elts)
        }

        pub fn muxb(&self, b: &Bitw<L>, iftrue: &Bitw<L>, iffalse: &Bitw<L>) -> Bitw<L> {
            self.or_assuming_at_most_one_true(
                &self.andb(b, iftrue),
                &self.andb(&self.notb(b), iffalse),
            )
        }

        pub fn one_hot_muxb(
            &self,
            selector: &[Bitw<L>],
            data: &dyn Fn(usize) -> Bitw<L>,
        ) -> Bitw<L> {
            let bitws: Vec<Bitw<L>> = selector
                .iter()
                .enumerate()
                .map(|(i, s)| self.andb(s, &data(i)))
                .collect();
            self.sum_assuming_at_most_one_true(&bitws)
        }

        pub fn maj(&self, x: &Bitw<L>, y: &Bitw<L>, z: &Bitw<L>) -> Bitw<L> {
            let g = self.andb(x, y);
            let p = self.xorb(x, y);
            self.or_assuming_at_most_one_true(&self.precious(&g), &self.andb(&p, z))
        }

        pub fn xor3(&self, a: &Bitw<L>, b: &Bitw<L>, c: &Bitw<L>) -> Bitw<L> {
            self.xorb(a, &self.xorb(b, c))
        }

        pub fn impliesb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.orb(b, &self.notb(a))
        }

        pub fn ltb(&self, a: &Bitw<L>, b: &Bitw<L>) -> Bitw<L> {
            self.andb(b, &self.notb(a))
        }

        pub fn chi_laneb(&self, x: &Bitw<L>, y: &Bitw<L>, z: &Bitw<L>) -> Bitw<L> {
            let logic = &self.logic;
            let f = logic.field();
            if f.is_zero(&self.two) {
                let not_y = self.notb(y);
                let and_not_y_z = self.andb(&not_y, z);
                self.xorb(x, &and_not_y_z)
            } else {
                let xx = self.as_x(x);
                let xy = self.as_x(y);
                let xz = self.as_x(z);
                let w = logic.mul(&xx, &xy);
                let num = logic.sum(&[
                    xx.clone(),
                    logic.neg(&w),
                    logic.mul(&logic.sum(&[xx, w]), &xz),
                ]);
                Bitw(Inner::X(logic.mulk(&self.half, &num)))
            }
        }

        pub fn assert_false(&self, name: &str, x: &Bitw<L>) -> L::Assertions {
            self.logic.assert0(name, &self.as_eltw(x))
        }

        pub fn assert_true(&self, name: &str, x: &Bitw<L>) -> L::Assertions {
            self.assert_false(name, &self.notb(x))
        }

        pub fn assert_eq(&self, name: &str, x: &Bitw<L>, y: &Bitw<L>) -> L::Assertions {
            let logic = &self.logic;
            match (&x.0, &y.0) {
                (Inner::True, Inner::True) | (Inner::False, Inner::False) => logic.ok(),
                (Inner::True, Inner::False) | (Inner::False, Inner::True) => {
                    logic.assert0(name, &logic.one())
                }
                (Inner::P(xv), Inner::P(yv))
                | (Inner::N(xv), Inner::N(yv))
                | (Inner::X(xv), Inner::X(yv)) => logic.assert0(name, &logic.sub(xv, yv)),
                _ => logic.assert0(name, &logic.sub(&self.as_eltw(x), &self.as_eltw(y))),
            }
        }

        pub fn to_stringw_debug(&self, x: &Bitw<L>) -> String {
            self.logic.to_stringw_debug(&self.as_eltw(x))
        }
    }

    impl<L: Logic> std::fmt::Debug for Bitw<L>
    where
        Eltw<L>: std::fmt::Debug,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.0 {
                Inner::True => write!(f, "True"),
                Inner::False => write!(f, "False"),
                Inner::P(x) => write!(f, "P({x:?})"),
                Inner::N(x) => write!(f, "N({x:?})"),
                Inner::X(x) => write!(f, "X({x:?})"),
            }
        }
    }

    impl<L: Logic> std::fmt::Display for Bitw<L>
    where
        Eltw<L>: std::fmt::Debug,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.0 {
                Inner::True => write!(f, "True"),
                Inner::False => write!(f, "False"),
                Inner::P(x) => write!(f, "P({x:?})"),
                Inner::N(x) => write!(f, "N({x:?})"),
                Inner::X(x) => write!(f, "X({x:?})"),
            }
        }
    }
}

pub use imp::{Bitw, Boolean};

pub struct BooleanIO<'a, L: LogicIO> {
    logic: &'a L,
    boolean: Boolean<'a, L>,
}

impl<'a, L: LogicIO> BooleanIO<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            boolean: Boolean::new(logic),
        }
    }

    pub fn input(&self, position_in_input_array: usize) -> Bitw<L> {
        let input_wire = self.logic.input(position_in_input_array);
        self.boolean.of_eltw(input_wire)
    }

    pub fn next(&self, pos: &mut usize) -> Bitw<L> {
        let wire = self.input(*pos);
        *pos += 1;
        wire
    }

    pub fn position_in_input_array(&self, x: &Bitw<L>) -> usize {
        self.logic.position_in_input_array(&self.boolean.as_eltw(x))
    }
}
