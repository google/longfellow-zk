use circuits_ec::concrete as ec_concrete;
use core_algebra::{AlgebraicField, Curve, ElementOf, SupportsNatConversions};
use ec_concrete::{Pt2, Pt3};

#[derive(Clone, Debug)]
pub struct ConcreteGiven<const W: usize, F: AlgebraicField> {
    pub exp: num_bigint::BigUint,
    pub a: Pt2<F>,
    pub b: Pt2<F>,
}

#[derive(Clone, Debug)]
pub struct ConcreteDerived<const W: usize, F: AlgebraicField> {
    pub round: Vec<Pt3<F>>,
    pub zinv: ElementOf<F>,
}

pub fn given<const W: usize, F: AlgebraicField>(
    exp: num_bigint::BigUint,
    a: Pt2<F>,
    b: Pt2<F>,
) -> ConcreteGiven<W, F> {
    ConcreteGiven { exp, a, b }
}

pub fn derived<
    const W: usize,
    F: AlgebraicField + SupportsNatConversions<W>,
    C: Curve<W, F = F>,
>(
    curve: &C,
    n: usize,
    given: &ConcreteGiven<W, F>,
    f: &F,
) -> ConcreteDerived<W, F> {
    let a = given.a.clone();

    let mut round_f = vec![ec_concrete::zero(f); n];
    let mut p = ec_concrete::zero(f);
    let a_proj = ec_concrete::projective(curve, f, &a);
    for i in (0..n).rev() {
        let bit_val = ((&given.exp >> i) & num_bigint::BigUint::from(1u32))
            == num_bigint::BigUint::from(1u32);
        let addend = if bit_val {
            a_proj.clone()
        } else {
            ec_concrete::zero(f)
        };
        round_f[i] = ec_concrete::add(curve, f, &ec_concrete::double(curve, f, &p), &addend);
        p = round_f[i].clone();
    }
    let zinv = f.invert(&p.2);

    ConcreteDerived {
        round: round_f,
        zinv,
    }
}

#[cfg(feature = "testonly")]
impl<const W: usize, FR: runtime_algebra::field::RuntimeField<W>> ConcreteGiven<W, FR> {
    pub fn push_elements(&self, n: usize, fr: &FR, mut push: impl FnMut(FR::E)) {
        let mut dest = Vec::new();
        for i in 0..n {
            let bit_val = ((&self.exp >> i) & num_bigint::BigUint::from(1u32))
                == num_bigint::BigUint::from(1u32);
            circuits_boolean::concrete::push_bool(fr, bit_val, &mut dest);
        }
        circuits_ec::concrete::push_pt2(&self.a, &mut dest);
        circuits_ec::concrete::push_pt2(&self.b, &mut dest);
        for e in dest {
            push(e);
        }
    }
}

#[cfg(feature = "testonly")]
impl<const W: usize, FR: runtime_algebra::field::RuntimeField<W>> ConcreteDerived<W, FR> {
    pub fn push_elements(&self, mut push: impl FnMut(FR::E)) {
        let mut dest = Vec::new();
        for pt3 in &self.round {
            circuits_ec::concrete::push_pt3(pt3, &mut dest);
        }
        compile_logic::concrete::push_eltw(self.zinv.clone(), &mut dest);
        for e in dest {
            push(e);
        }
    }
}
