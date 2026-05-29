use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(super) use super::linear_proof_parameters as parameters;

#[path = "linear_proof/proof_coder/gaussian_fields.rs"]
mod gaussian_fields;
#[path = "linear_proof/proof_coder/proof_fields.rs"]
mod proof_fields;

use gaussian_fields::*;
pub use proof_fields::*;
