use super::*;

pub(super) use super::{
    linear_proof_parameters as parameters, linear_proof_transcript as transcript,
};

#[path = "linear_proof/statement/statement_transcript.rs"]
mod statement_transcript;

#[cfg(test)]
pub use statement_transcript::derive_linear_statement_transcript;
pub(crate) use statement_transcript::*;

#[cfg(test)]
#[path = "linear_proof/statement/statement_transcript_tests.rs"]
mod statement_transcript_tests;
