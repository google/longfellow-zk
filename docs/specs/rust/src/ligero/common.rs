use crate::{algebra::Field, transcript::Transcript};

#[derive(Clone, Debug)]
pub struct LigeroConfig {
    pub rate_inv: usize,
    pub num_queries: usize,
    pub encoded_len: usize,
}

impl Default for LigeroConfig {
    fn default() -> Self {
        Self {
            rate_inv: 4,
            num_queries: 16,
            encoded_len: 256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LigeroProof<F> {
    pub ldt_poly: Vec<F>,
    pub linear_poly: Vec<F>,
    pub quad_poly_low: Vec<F>,
    pub quad_poly_high: Vec<F>,
    pub column_nonces: Vec<Vec<u8>>,
    pub queried_columns: Vec<F>,
    pub merkle_paths: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub struct LigeroTerm<F> {
    pub coeff: F,
    pub constraint_idx: usize,
    pub witness_idx: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LqcTriple {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LigeroGeometry {
    pub num_witnesses: usize,
    pub block_len: usize,
    pub encoded_len: usize,
    pub dblock_len: usize,
    pub num_queries: usize,
    pub witnesses_per_row: usize,
    pub num_witness_rows: usize,
    pub num_quad_rows: usize,
    pub total_rows: usize,
}

impl LigeroGeometry {
    pub fn new(config: &LigeroConfig, num_witness: usize, num_quad_triples: usize) -> Self {
        assert!(config.encoded_len > 0, "encoded_len must be positive");
        assert!(config.num_queries > 0, "num_queries must be positive");
        let encoded_len = config.encoded_len;
        let block_len = (encoded_len + 1) / (2 + config.rate_inv);
        assert!(block_len > 0, "block_len must be positive");
        let dblock_len = 2 * block_len - 1;
        assert!(
            encoded_len >= dblock_len,
            "encoded_len must be >= dblock_len (2*block_len - 1)"
        );
        let num_queries = config.num_queries;
        assert!(
            encoded_len - dblock_len >= num_queries,
            "encoded_len - dblock_len must be >= num_queries"
        );
        assert!(
            block_len > num_queries,
            "block_len must be greater than num_queries"
        );
        let witnesses_per_row = block_len - num_queries;
        assert!(
            witnesses_per_row > 0,
            "witnesses_per_row (block_len - num_queries) must be positive"
        );
        let num_witness_rows = (num_witness + witnesses_per_row - 1) / witnesses_per_row;
        let num_quad_rows = (num_quad_triples + witnesses_per_row - 1) / witnesses_per_row;
        let total_rows = 3 + num_witness_rows + 3 * num_quad_rows;

        Self {
            num_witnesses: num_witness,
            block_len,
            encoded_len,
            dblock_len,
            num_queries,
            witnesses_per_row,
            num_witness_rows,
            num_quad_rows,
            total_rows,
        }
    }

    pub fn ldt_row_idx(&self) -> usize {
        0
    }
    pub fn linear_row_idx(&self) -> usize {
        self.ldt_row_idx() + 1
    }
    pub fn quad_row_idx(&self) -> usize {
        self.linear_row_idx() + 1
    }
    pub fn witness_row_start(&self) -> usize {
        self.quad_row_idx() + 1
    }
    pub fn quad_x_row_start(&self) -> usize {
        self.witness_row_start() + self.num_witness_rows
    }
    pub fn quad_y_row_start(&self) -> usize {
        self.quad_x_row_start() + self.num_quad_rows
    }
    pub fn quad_z_row_start(&self) -> usize {
        self.quad_y_row_start() + self.num_quad_rows
    }
}

pub fn gen_uldt<F: Field + 'static>(ts: &mut Transcript, nwqrow: usize) -> Vec<F> {
    (0..nwqrow).map(|_| ts.get_elt_field()).collect()
}

pub fn gen_alphal<F: Field + 'static>(ts: &mut Transcript, nl: usize) -> Vec<F> {
    (0..nl).map(|_| ts.get_elt_field()).collect()
}

pub fn gen_alphaq<F: Field + 'static>(ts: &mut Transcript, nqtriples: usize) -> Vec<Vec<F>> {
    (0..nqtriples)
        .map(|_| vec![ts.get_elt_field(), ts.get_elt_field(), ts.get_elt_field()])
        .collect()
}

pub fn gen_uquad<F: Field + 'static>(ts: &mut Transcript, nqtriples: usize) -> Vec<F> {
    (0..nqtriples).map(|_| ts.get_elt_field()).collect()
}
