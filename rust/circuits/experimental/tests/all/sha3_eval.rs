use circuits_bitvec::BitvecLogic;
use circuits_experimental::sha3::{
    derived,
    evaluate::{evaluate_derived, evaluate_given},
    ConcreteGiven, Sha3,
};
use compile_algebra::gf2_128::Gf2_128Field;
use compile_logic::eval::EvalLogic;

#[test]
fn test_eval_keccak_f_1600() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);

    // Initialize state 0 values
    let mut s0 = [[0u64; 5]; 5];
    for (x, row) in s0.iter_mut().enumerate() {
        for (y, val) in row.iter_mut().enumerate() {
            *val = ((x * 5 + y) as u64 + 1) * 0x123456789abcdef;
        }
    }

    let concrete_given = ConcreteGiven { initial_state: s0 };
    let concrete_derived = derived(&concrete_given);

    let wire_given = evaluate_given(&concrete_given, &bv);
    let wire_derived = evaluate_derived(&concrete_derived, &bv);

    let sha3 = Sha3::new(&l);
    let assertion = sha3.assert_circuit(&wire_given, &wire_derived);
    assertion.unwrap();
}
