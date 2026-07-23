use compile_algebra::{p256::P256Field, secp256r1::Secp256r1};
use compile_compiler::{CompilerArena, CompilerLogic};
use mdoc_zk_circuits::{config::K_ZSTD_LEVEL, signature::MdocSignature, MdocSigCompileField};

fn test_mdoc_zk_circuits_signature_generic(fc: &P256Field, _fr: &runtime_algebra::p256::P256Field) {
    let arena = CompilerArena::new();
    let curve_c = Secp256r1::new(fc);
    let iologic = CompilerLogic::new(&arena, fc);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let mdoc_sig = MdocSignature::new(&iologic, &curve_c);
    let bv = circuits_bitvec::BitvecLogic::new(&iologic);
    let given_wires = mdoc_zk_circuits::signature::allocate_given(&iologic, &bv, &mut pos);
    let derived_wires = mdoc_zk_circuits::signature::allocate_derived(&iologic, &mut pos);

    let assertion = mdoc_sig.assert_signatures_and_macs(&given_wires, &derived_wires);

    let (_circuit, stats, _symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);
    assert_eq!(
        stats,
        compile_eval::CircuitGeometry {
            ninput: 4773,
            npublic_input: 0,
            noutput: 6,
            nlayers: 19,
            nwires: 167739,
            nterms: 259551,
            nassertions: 4115,
        }
    );
}

#[test]
fn test_mdoc_zk_circuits_signature() {
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    test_mdoc_zk_circuits_signature_generic(&fc, &fr);
}

fn mdoc_zk_circuits_signature_circuit<FC>(
    fc: &FC,
) -> (compile_eval::Circuit<FC>, compile_eval::CircuitGeometry)
where FC: MdocSigCompileField {
    let arena = CompilerArena::new();
    let curve_c = Secp256r1::new(fc);

    let iologic = CompilerLogic::new(&arena, fc);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let mdoc_sig = MdocSignature::new(&iologic, &curve_c);
    let bv = circuits_bitvec::BitvecLogic::new(&iologic);
    let given_wires = mdoc_zk_circuits::signature::allocate_given(&iologic, &bv, &mut pos);
    let derived_wires = mdoc_zk_circuits::signature::allocate_derived(&iologic, &mut pos);
    let assertion = mdoc_sig.assert_signatures_and_macs(&given_wires, &derived_wires);

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);
    (circuit, stats)
}

#[test]

fn test_serialize_and_verify_mdoc_signature_circuit() {
    use core_proto::{writer::CircuitWriter, FieldID};

    let p256_c = P256Field::new();
    let (circuit, _stats) = mdoc_zk_circuits_signature_circuit(&p256_c);

    let expected_id: [u8; 32] = [
        0xb7, 0xe1, 0xc2, 0x00, 0xe1, 0x88, 0x02, 0xf1, 0x92, 0xf1, 0xe3, 0x0d, 0xcb, 0x33, 0x36,
        0x26, 0x31, 0x3e, 0x20, 0x25, 0xab, 0xb1, 0xa8, 0x0f, 0x88, 0x7c, 0x05, 0x49, 0x69, 0xd1,
        0x8f, 0x0b,
    ];
    assert_eq!(
        circuit.id, expected_id,
        "Circuit hash changed! Expected {:?}, got {:?}",
        expected_id, circuit.id
    );

    let writer = CircuitWriter::new(&p256_c, FieldID::P256);
    let serialized = writer.to_bytes(&circuit);
    let _compressed =
        zstd::bulk::compress(&serialized, K_ZSTD_LEVEL).expect("zstd compression failed");
}
