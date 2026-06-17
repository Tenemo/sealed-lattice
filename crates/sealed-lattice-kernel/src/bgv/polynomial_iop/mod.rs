pub(in crate::bgv) mod evaluation_domain;
pub(in crate::bgv) mod extension_field;
pub(in crate::bgv) mod fiat_shamir_transcript;
pub(in crate::bgv) mod low_degree_proof;
pub(in crate::bgv) mod merkle_commitment;

use crate::{
    bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(in crate::bgv) const DOMAIN_BLOWUP: usize = 4;
pub(in crate::bgv) const COMMITMENT_BOUND_FACTOR: usize = 2;
pub(in crate::bgv) const DEEP_POINT_COUNT: usize = 2;
pub(in crate::bgv) const LOW_DEGREE_QUERY_COUNT: usize = 288;
pub(in crate::bgv) const LOW_DEGREE_FINAL_COEFFICIENT_COUNT: usize = 8;
pub(in crate::bgv) const MINIMUM_TRACE_SIZE: usize = 64;

fn invalid_polynomial_iop(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}
