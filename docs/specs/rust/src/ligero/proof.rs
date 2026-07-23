use std::io::{Read, Write};

use super::{LigeroConfig, LigeroGeometry, LigeroProof};
use crate::{
    algebra::{Field, Subfield},
    circuit::Circuit,
    io::{read_elt_field, read_size_4bytes, read_subfield_elt, write_size_4bytes},
};

pub fn read_ligero_proof<F: Field + 'static, R: Read>(
    io: &mut R,
    config: &LigeroConfig,
    circuit: &Circuit<F>,
    sf: &F::Subfield,
) -> std::io::Result<LigeroProof<F>> {
    let witness_only_len = circuit.ninput - circuit.npublic_input;
    let mut pad_witness_len = 3 * circuit.layers.len();
    for layer in &circuit.layers {
        pad_witness_len += 4 * layer.logw;
    }
    let nw = witness_only_len + pad_witness_len;
    let nq = circuit.layers.len();

    let geom = LigeroGeometry::new(config, nw, nq);
    let total_req_elts = geom.total_rows * geom.num_queries;

    let mut ldt_poly = Vec::with_capacity(geom.block_len);
    for _ in 0..geom.block_len {
        ldt_poly.push(read_elt_field(io)?);
    }
    let mut linear_poly = Vec::with_capacity(geom.dblock_len);
    for _ in 0..geom.dblock_len {
        linear_poly.push(read_elt_field(io)?);
    }
    let mut quad_poly_low = Vec::with_capacity(geom.num_queries);
    for _ in 0..geom.num_queries {
        quad_poly_low.push(read_elt_field(io)?);
    }
    let mut quad_poly_high = Vec::with_capacity(geom.dblock_len - geom.block_len);
    for _ in 0..(geom.dblock_len - geom.block_len) {
        quad_poly_high.push(read_elt_field(io)?);
    }
    let mut column_nonces = Vec::with_capacity(geom.num_queries);
    for _ in 0..geom.num_queries {
        let mut nonce = vec![0u8; 32];
        io.read_exact(&mut nonce)?;
        column_nonces.push(nonce);
    }

    let mut queried_columns = Vec::new();
    let mut read_req_count = 0;
    let mut subfield_run = false;
    let mut zero_run_count = 0;
    while read_req_count < total_req_elts {
        let runlen = read_size_4bytes(io)?;
        if runlen == 0 {
            if read_req_count > 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Empty runlen in RLE deserialization is only allowed at the start",
                ));
            }
            zero_run_count += 1;
            if zero_run_count > 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Repeated empty runlen in RLE deserialization",
                ));
            }
        } else {
            zero_run_count = 0;
        }
        for _ in 0..runlen {
            queried_columns.push(if subfield_run {
                read_subfield_elt(io, sf)?
            } else {
                read_elt_field(io)?
            });
        }
        read_req_count += runlen;
        subfield_run = !subfield_run;
    }

    if queried_columns.len() != total_req_elts {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Deserialized request elements length mismatch",
        ));
    }

    let num_paths = read_size_4bytes(io)?;
    let mut merkle_paths = Vec::with_capacity(num_paths);
    for _ in 0..num_paths {
        let mut path = vec![0u8; 32];
        io.read_exact(&mut path)?;
        merkle_paths.push(path);
    }

    Ok(LigeroProof {
        ldt_poly,
        linear_poly,
        quad_poly_low,
        quad_poly_high,
        column_nonces,
        queried_columns,
        merkle_paths,
    })
}

pub fn write_ligero_proof<F: Field + 'static, W: Write>(
    io: &mut W,
    cp: &LigeroProof<F>,
    sf: &F::Subfield,
) -> std::io::Result<()> {
    for val in &cp.ldt_poly {
        io.write_all(&val.to_bytes())?;
    }
    for val in &cp.linear_poly {
        io.write_all(&val.to_bytes())?;
    }
    for val in &cp.quad_poly_low {
        io.write_all(&val.to_bytes())?;
    }
    for val in &cp.quad_poly_high {
        io.write_all(&val.to_bytes())?;
    }
    for nonce in &cp.column_nonces {
        io.write_all(nonce)?;
    }

    let req = &cp.queried_columns;
    let mut subfield_run = false;
    let mut i = 0;
    let total_elts = req.len();
    while i < total_elts {
        let mut runlen = 0;
        while i + runlen < total_elts {
            if sf.contains_subfield(req[i + runlen]) == subfield_run {
                runlen += 1;
            } else {
                break;
            }
        }
        write_size_4bytes(io, runlen)?;
        for j in i..(i + runlen) {
            if subfield_run {
                io.write_all(&sf.to_subfield_bytes(req[j]))?;
            } else {
                io.write_all(&req[j].to_bytes())?;
            }
        }
        i += runlen;
        subfield_run = !subfield_run;
    }

    write_size_4bytes(io, cp.merkle_paths.len())?;
    for p in &cp.merkle_paths {
        io.write_all(p)?;
    }
    Ok(())
}
