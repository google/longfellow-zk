use reference::{
    algebra::{Field, FieldError, Gf2_128, P256},
    zk::symbolic_sumcheck_verifier::{Expression, Var},
};

#[test]
fn test_p256_from_bytes_range_check() {
    let valid_bytes = vec![0u8; 32];
    assert!(P256::from_bytes(&valid_bytes).is_ok());

    let invalid_bytes = vec![0xffu8; 32];
    assert_eq!(
        P256::from_bytes(&invalid_bytes),
        Err(FieldError::ValueOutOfRange)
    );
}

#[test]
#[should_panic(expected = "cannot invert zero")]
fn test_p256_inv_zero_panics() {
    let _ = P256::zero().inv();
}

#[test]
#[should_panic(expected = "cannot invert zero")]
fn test_gf2_128_inv_zero_panics() {
    let _ = Gf2_128::zero().inv();
}

#[test]
fn test_expression_auto_dedup() {
    let mut expr = Expression::<Gf2_128>::from(Gf2_128 { v: 5 });
    expr += Var(2) * Gf2_128 { v: 10 };
    expr += Var(0) * Gf2_128 { v: 3 };
    expr += Var(2) * Gf2_128 { v: 4 };
    expr += Var(1) * Gf2_128 { v: 7 };
    expr += Var(0) * Gf2_128 { v: 3 }; // 3 ^ 3 in GF(2^128) is 0

    // 0-term should be automatically removed (3 ^ 3 == 0)
    // 1-term: coeff 7
    // 2-term: coeff 10 ^ 4 = 14
    assert_eq!(expr.terms.len(), 2);
    assert_eq!(expr.terms.get(&1), Some(&Gf2_128 { v: 7 }));
    assert_eq!(
        expr.terms.get(&2),
        Some(&(Gf2_128 { v: 10 } + Gf2_128 { v: 4 }))
    );
}

#[test]
fn test_expression_operator_math() {
    // Test natural math expressions with operators: +, -, *
    let e1: Expression<Gf2_128> = Var::<Gf2_128>(0) * Gf2_128 { v: 3 } + Gf2_128 { v: 5 };
    let e2: Expression<Gf2_128> =
        Var::<Gf2_128>(0) * Gf2_128 { v: 2 } + Var::<Gf2_128>(1) * Gf2_128 { v: 4 };

    let diff = e1 - e2; // 3^2=1 for v=0, 4 for v=1, 5 for known
    assert_eq!(diff.known, Gf2_128 { v: 5 });
    assert_eq!(
        diff.terms.get(&0),
        Some(&(Gf2_128 { v: 3 } + Gf2_128 { v: 2 }))
    );
    assert_eq!(diff.terms.get(&1), Some(&Gf2_128 { v: 4 }));
}

#[test]
fn test_layer_pad_isomorphism() {
    use reference::sumcheck::LayerPad;

    let logw = 3;
    let mut base = 100;
    let idx_pad = LayerPad::generate_indices(logw, &mut base);

    assert_eq!(base, 100 + 4 * logw + 3);
    assert_eq!(idx_pad.rounds.len(), logw);
    assert_eq!(idx_pad.rounds[0].hp[0], [100, 101]);
    assert_eq!(idx_pad.rounds[0].hp[1], [102, 103]);
    assert_eq!(idx_pad.claims.c0, 112);
    assert_eq!(idx_pad.claims.c1, 113);
    assert_eq!(idx_pad.claims.cr, 114);
}

#[test]
fn test_ceil_lg2_works_as_intended() {
    use reference::algebra::ceil_lg2;

    assert_eq!(ceil_lg2(0), 0);
    assert_eq!(ceil_lg2(1), 0);
    assert_eq!(ceil_lg2(2), 1);
    assert_eq!(ceil_lg2(3), 2);
    assert_eq!(ceil_lg2(4), 2);
    assert_eq!(ceil_lg2(5), 3);
    assert_eq!(ceil_lg2(7), 3);
    assert_eq!(ceil_lg2(8), 3);
    assert_eq!(ceil_lg2(9), 4);
    assert_eq!(ceil_lg2(16), 4);
    assert_eq!(ceil_lg2(17), 5);
    assert_eq!(ceil_lg2(255), 8);
    assert_eq!(ceil_lg2(256), 8);
    assert_eq!(ceil_lg2(257), 9);
    assert_eq!(ceil_lg2(1024), 10);
    assert_eq!(ceil_lg2(6657), 13);
}

#[test]
fn test_zk_error_conversions() {
    use reference::{
        ZkError, algebra::FieldError, ligero::VerificationError, sumcheck::CircuitEvaluationError,
        zk::ZkVerificationError,
    };

    let field_err: ZkError = FieldError::ValueOutOfRange.into();
    assert!(format!("{}", field_err).contains("Field error"));

    let ligero_err: ZkError = VerificationError::MerkleProofInvalid.into();
    assert!(format!("{}", ligero_err).contains("Ligero error"));

    let zk_err: ZkError = ZkVerificationError::PublicInputLengthMismatch {
        expected: 2,
        actual: 4,
    }
    .into();
    assert!(format!("{}", zk_err).contains("ZK verification error"));

    let circuit_err: ZkError = CircuitEvaluationError::CircuitOutputNotZero.into();
    assert!(format!("{}", circuit_err).contains("Circuit evaluation error"));

    let io_err: ZkError = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF").into();
    assert!(format!("{}", io_err).contains("I/O error"));

    let custom_err = ZkError::InvalidData("test error".to_string());
    assert!(format!("{}", custom_err).contains("Invalid data error"));
}
