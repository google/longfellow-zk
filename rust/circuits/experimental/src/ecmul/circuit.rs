use circuits_boolean::{Bitw, Boolean};
use circuits_ec::{EcCircuit, Pt2, Pt3};
use compile_algebra::Curve;
use compile_logic::{Eltw, Logic};

pub struct Given<L: Logic> {
    pub exp_bits: Vec<Bitw<L>>,
    pub a: Pt2<Eltw<L>>,
    pub b: Pt2<Eltw<L>>,
}

pub struct Derived<L: Logic> {
    pub round: Vec<Pt3<Eltw<L>>>,
    pub zinv: Eltw<L>,
}

pub struct EcmulCircuit<'a, const W: usize, C: Curve<W>, L: Logic<F = C::F>> {
    pub(crate) ec: EcCircuit<'a, W, C, L>,
    pub(crate) boolean: Boolean<'a, L>,
    pub(crate) logic: &'a L,
    pub n: usize,
}

impl<'a, const W: usize, C, L, F> EcmulCircuit<'a, W, C, L>
where
    C: Curve<W, F = F>,
    L: Logic<F = F>,
    F: compile_algebra::field::CompileField + compile_algebra::field::SupportsNatConversions<W>,
{
    pub fn new(logic: &'a L, curve: &'a C, n: usize) -> Self {
        let ec = EcCircuit::new(logic, curve);
        let boolean = Boolean::new(logic);
        Self {
            ec,
            boolean,
            logic,
            n,
        }
    }

    fn mux(&self, b: &Bitw<L>, p1: &Pt3<Eltw<L>>, p2: &Pt3<Eltw<L>>) -> Pt3<Eltw<L>> {
        let (x1, y1, z1) = p1;
        let (x2, y2, z2) = p2;
        (
            self.boolean.muxe(b, x1, x2),
            self.boolean.muxe(b, y1, y2),
            self.boolean.muxe(b, z1, z2),
        )
    }

    pub fn assert_scalar_mul(&self, given: &Given<L>, derived: &Derived<L>) -> L::Assertions {
        assert_eq!(self.n, given.exp_bits.len());
        assert_eq!(self.n, derived.round.len());

        let mut p = self.ec.zero();
        for i in (0..self.n).rev() {
            let addend = self.mux(
                &given.exp_bits[i],
                &self.ec.projective(&given.a),
                &self.ec.zero(),
            );
            let sum_val = self.ec.add(&self.ec.double(&p), &addend);
            p = self.ec.slicing3(&derived.round[i], &sum_val);
        }

        self.logic.assert_all(
            "ecmul",
            &[
                self.ec.point_equality(&p, &derived.zinv, &given.b),
                self.ec.is_on_curve(&given.a),
            ],
        )
    }
}
