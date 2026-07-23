use std::hint::black_box;

use mdoc_zk_runtime::{run_mdoc_verifier_inner, RequestedAttribute, CURRENT_ZK_SPECS};

fn main() {
    let spec = black_box(CURRENT_ZK_SPECS[0]);
    let circuits = black_box(&[0u8; 10][..]);
    let pkx = black_box("0x00");
    let pky = black_box("0x00");
    let transcript = black_box(&[0u8; 10][..]);
    let attrs: [RequestedAttribute; 0] = [];
    let now = black_box("2026-07-08");
    let doc_type = black_box("org.iso.18013.5.1.mDL");
    let proof = black_box(&[0u8; 10][..]);

    let _res = black_box(run_mdoc_verifier_inner(
        &spec,
        circuits,
        pkx,
        pky,
        transcript,
        black_box(&attrs[..]),
        now,
        doc_type,
        proof,
    ));
}
