pub mod dense;
pub mod eq;
pub mod eval;
pub mod hquad;
pub mod pad;
pub mod poly;
pub use runtime_proto::sumcheck as proof;
pub mod prover;
pub mod transcript;
pub mod verifier;

pub use dense::{as_scalar, bind, bind_all, normalize};
pub use eq::eval as eq;
pub use hquad::HQuad;
pub use poly::{LagrangeBasis, Poly, QuadRoundPoly, QuadWirePoly};
pub use proof::{sane_logw, LayerProof, RoundPoly, SumcheckProof, MAX_LOGW};
pub use prover::{prove, prove_core, SumcheckProofAux};
pub use runtime_random::{RandomEngine, Transcript};
pub use transcript::TranscriptSumcheck;
pub use verifier::{verify, Claims};

pub use crate::eval::{eval_circuit, eval_quad};
