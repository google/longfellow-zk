use crate::{algebra::Field, circuit::Circuit, ligero::LqcTriple, transcript::Transcript};

pub const DEFAULT_STATEMENT_HASH: [u8; 32] = {
    let mut h = [0u8; 32];
    h[0] = 0xde;
    h[1] = 0xad;
    h[2] = 0xbe;
    h[3] = 0xef;
    h
};

pub fn write_sumcheck_statement<F: Field + 'static>(
    t: &mut Transcript,
    circuit_data: &Circuit<F>,
    inputs: &[F],
) {
    let npublic_input = circuit_data.npublic_input;
    let public_inputs = &inputs[0..npublic_input];
    t.write_bytes(&circuit_data.id);
    for &inp in public_inputs {
        t.write_elt_field(inp);
    }
    t.write_elt_field(F::zero());
    let mut nterms = 0;
    for layer in &circuit_data.layers {
        nterms += layer.quad.len();
    }
    t.write0(nterms);
}

pub fn generate_lqc_triples<F: Field>(circuit_data: &Circuit<F>) -> Vec<LqcTriple> {
    let mut lqc = Vec::new();
    let mut pi = circuit_data.ninput - circuit_data.npublic_input;
    for layer in &circuit_data.layers {
        let logw = layer.logw;
        pi += 4 * logw;
        lqc.push(LqcTriple {
            x: pi,
            y: pi + 1,
            z: pi + 2,
        });
        pi += 3;
    }
    lqc
}
