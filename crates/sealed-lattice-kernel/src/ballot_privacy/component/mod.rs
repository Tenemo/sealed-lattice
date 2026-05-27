use super::*;

mod backend_sparse;
mod bundle_validation;
mod contracts;
mod linear_proof_verification;
mod share_commitment_backend_helpers;
mod structured_receiver_encryption_statement;
mod structured_share_commitment_statement;

pub(crate) use backend_sparse::{
    ComponentProofBackendError, ParsedSparseComponentProofStatement,
    ParsedStructuredReceiverEncryptionStatement, component_proof_backend_rejection, integer_value,
    sparse_matrix_from_sparse_component_statement, u64_object_field, usize_object_field,
};
pub(crate) use bundle_validation::{
    collect_ballot_component_bundle_refusals, collect_ballot_component_proof_bundle_refusals,
    collect_component_proof_statement_plan_shape_refusals,
    supplied_component_proof_statement_digest,
};
pub(crate) use contracts::{
    ALLOWED_BALLOT_PROOF_COMPONENT_STATEMENT_FORMATS, COMPONENT_BUNDLE_INCOMPLETE_COVERAGE,
    DENSE_COMPONENT_PROOF_STATEMENT_FORMAT, FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
    FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID, FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
    MAX_GENERIC_SPARSE_COMPONENT_SHORT_RESPONSE_VECTOR_LENGTH, PUBLIC_ZERO_PROOF_STATEMENT_FORMAT,
    RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID, RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID,
    REQUIRED_BALLOT_PROOF_COMPONENT_IDS, SHARE_COMMITMENT_MODULE_DEGREE,
    SHARE_COMMITMENT_MODULE_RANK, SHARE_COMMITMENT_OPENING_DIMENSION,
    SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT, STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT,
    STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT,
    component_proof_bytes_availability_is_expected, component_proof_bytes_must_be_empty,
    component_proof_statement_format_is_expected, encoded_share_vector_width,
    expected_component_proof_statement_format_label,
};
pub(crate) use linear_proof_verification::verify_component_proof_bundle_backend;
pub(crate) use share_commitment_backend_helpers::{
    derive_share_commitment_message_matrix, derive_share_commitment_randomness_matrix,
    negate_share_commitment_polynomial, push_share_commitment_sparse_entry,
    share_commitment_message_entry_polynomial, split_share_commitment_polynomial,
};
pub(crate) use structured_receiver_encryption_statement::parse_structured_receiver_encryption_statement;
pub(crate) use structured_share_commitment_statement::parse_structured_share_commitment_statement;

#[cfg(test)]
pub(crate) use backend_sparse::{
    dense_matrix_from_sparse_component_statement, derive_sparse_statement_matrix_digest,
    derive_sparse_target_vector_digest,
};
#[cfg(test)]
pub(crate) use linear_proof_verification::verify_component_linear_proof_bytes;
#[cfg(test)]
pub(crate) use share_commitment_backend_helpers::add_structured_constant_entry;
#[cfg(test)]
pub(crate) use structured_share_commitment_statement::structured_receiver_encryption_statement_as_sparse;
