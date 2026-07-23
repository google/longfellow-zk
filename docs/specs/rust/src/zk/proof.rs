use std::io::{Read, Write};

use crate::{
    algebra::Field,
    circuit::Circuit,
    ligero::{LigeroConfig, LigeroProof, read_ligero_proof, write_ligero_proof},
    sumcheck::{SumcheckLayerProof, read_sumcheck_proof, write_sumcheck_proof},
};

#[derive(Clone, Debug)]
pub struct ZkProof<F> {
    pub root: [u8; 32],
    pub sumcheck_proof: Vec<SumcheckLayerProof<F>>,
    pub ligero_proof: LigeroProof<F>,
}

pub fn read_zk_proof<F: Field + 'static, R: Read>(
    io: &mut R,
    circuit: &Circuit<F>,
    sf: &F::Subfield,
    config: &LigeroConfig,
) -> std::io::Result<ZkProof<F>> {
    let mut root = [0u8; 32];
    io.read_exact(&mut root)?;
    let sumcheck_proof = read_sumcheck_proof(io, circuit)?;
    let ligero_proof = read_ligero_proof(io, config, circuit, sf)?;
    Ok(ZkProof {
        root,
        sumcheck_proof,
        ligero_proof,
    })
}

pub fn write_zk_proof<F: Field + 'static, W: Write>(
    io: &mut W,
    proof: &ZkProof<F>,
    sf: &F::Subfield,
) -> std::io::Result<()> {
    io.write_all(&proof.root)?;
    write_sumcheck_proof(io, &proof.sumcheck_proof)?;
    write_ligero_proof(io, &proof.ligero_proof, sf)?;
    Ok(())
}
