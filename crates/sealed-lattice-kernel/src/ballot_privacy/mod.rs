mod abdlop_commitment;
mod encoded_relation_vectors;
mod linear_proof_abdlop;
mod linear_proof_norms;
mod linear_proof_parameters;
mod linear_proof_profile_constants;
mod linear_proof_prover;
mod linear_proof_public_parameters;
mod linear_proof_rng;
mod linear_proof_statement;
mod linear_proof_tbox;
mod linear_proof_transcript;
mod linear_proof_verifier;
mod many_quadratic;
mod polynomial_matrix;
mod polynomial_ring;
mod polynomial_vector;
mod proof_coder;
mod protocol_constants;
mod quadratic_challenge;
mod quadratic_equation;
mod receiver_key_vectors;
mod sparse_linear_proof_statement;
mod sparse_polynomial_matrix;
mod sparse_polynomial_vector;
mod tbox_relations;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::{
    hashing::{canonical_json, derive_protocol_digest, hash512, to_hex},
    transcript_core::decode_hex,
};

use self::{
    linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
    linear_proof_prover::{
        LinearProverCommitmentInput, LinearProverProofInput, LinearProverWitnessInput,
        SparseLinearProverProofInput, StreamedLinearProverProofInput, generate_linear_proof,
        generate_receiver_key_linear_proof, generate_sparse_linear_proof,
        generate_streamed_linear_proof, prepare_linear_prover_commitment,
        prepare_linear_prover_witness,
    },
    linear_proof_statement::{
        LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
        StreamedLinearProofStatement,
        derive_linear_statement_transcript_with_matrix_coefficient_representation,
        source_polynomial_split_factor, transform_target_vector_to_proof_ring,
    },
    linear_proof_transcript::shake128_32,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    protocol_constants::{
        BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION, BALLOT_PRIVACY_FIELD_MODULUS,
        BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT, BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT,
        BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT, BALLOT_PRIVACY_MINIMUM_OPTION_COUNT,
        BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT,
        BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT, SHARE_COMMITMENT_MODULUS,
    },
    receiver_key_vectors::{
        RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK,
        RECEIVER_ENCRYPTION_MODULUS, derive_receiver_encryption_public_matrix,
    },
    sparse_linear_proof_statement::transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
};

#[cfg(test)]
pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = true;

mod aggregate_derivation_proof;
mod backend_status;
mod ballot_linear_verifier;
mod ballot_package_verifier;
mod ballot_proof_digest_helpers;
mod ballot_proof_generation_core;
mod ballot_proof_record_builders;
mod ballot_proof_record_generation;
mod ballot_proof_record_inputs;
mod ballot_proof_refusals;
mod component_backend_sparse;
mod component_bundle_validation;
mod component_contracts;
mod component_linear_proof_verification;
mod json_helpers;
mod linear_proof_binding_validation;
mod linear_proof_contract_validation;
mod proof_binding_digests;
mod proof_preflight_parsing;
mod receiver_key_package_refusals;
mod receiver_key_proof;
mod receiver_polynomial_helpers;
mod share_commitment_backend_helpers;
mod structured_receiver_encryption_statement;
mod structured_share_commitment_statement;

pub(crate) use aggregate_derivation_proof::{
    generate_aggregate_derivation_proof_from_command_request,
    verify_aggregate_derivation_proof_from_command_request,
};
pub(crate) use backend_status::{describe_proof_backend, structural_refusal, structural_rejection};
pub(crate) use ballot_linear_verifier::{
    BallotProofVerificationInputs, ComponentProofVerificationMode, verify_ballot_proof,
    verify_ballot_proof_from_command_request,
};
pub(crate) use ballot_proof_digest_helpers::{
    derive_ballot_component_bundle_statement_digest, derive_ballot_component_proof_bundle_digest,
    derive_ballot_component_proof_record_digest, derive_ballot_component_proof_root,
    derive_ballot_component_statement_digest, derive_ballot_proof_challenge_digest,
};
pub(crate) use ballot_proof_generation_core::{
    BallotComponentProofGenerationInput, BallotProofGenerationInput,
    generate_ballot_component_proof_inner, generate_ballot_proof_inner,
};
pub(crate) use ballot_proof_refusals::{
    collect_ballot_proof_refusals, collect_claim_bearing_package_refusals,
    collect_proof_bytes_refusals, reference_map,
};
pub(crate) use component_backend_sparse::{
    ComponentProofBackendError, ParsedSparseComponentProofStatement,
    ParsedStructuredReceiverEncryptionStatement, component_proof_backend_rejection, integer_value,
    sparse_matrix_from_sparse_component_statement, u64_object_field, usize_object_field,
};
pub(crate) use component_bundle_validation::{
    collect_ballot_component_bundle_refusals, collect_ballot_component_proof_bundle_refusals,
    collect_component_proof_statement_plan_shape_refusals,
    supplied_component_proof_statement_digest,
};
pub(crate) use component_contracts::{
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
pub(crate) use component_linear_proof_verification::verify_component_proof_bundle_backend;
pub(crate) use json_helpers::{
    array_field, collect_receiver_reference_refusals, derive_digest, is_protocol_digest,
    object_map, positive_roster_position, receiver_reference_key, required_json_field,
    required_string_field, string_field, unsigned_decimal_string, value_without_field,
    value_without_fields,
};
pub(crate) use linear_proof_binding_validation::{
    LinearProofBindingValidationInput, LinearProofBindingValidationMessages,
    LinearProofProfileRequirement, collect_linear_proof_binding_refusals,
};
pub(crate) use linear_proof_contract_validation::{
    collect_full_ballot_binding_contract_refusals, collect_full_ballot_relation_binding_refusals,
    collect_supported_ballot_privacy_dimension_refusals,
};
pub(crate) use proof_binding_digests::{
    derive_ballot_component_proof_statement_plan_digest,
    derive_ballot_proof_encoding_profile_digest, derive_ballot_proof_linear_statement_digest,
    derive_ballot_proof_parameter_set_digest, derive_ballot_proof_public_randomness_digest,
    derive_ballot_sparse_linear_statement_digest,
    derive_ballot_structured_receiver_encryption_statement_digest,
    derive_ballot_structured_share_commitment_statement_digest,
    derive_receiver_key_linear_statement_digest, derive_receiver_key_proof_encoding_profile_digest,
    derive_receiver_key_proof_parameter_set_digest, derive_receiver_key_public_randomness_digest,
};
pub(crate) use proof_preflight_parsing::{
    decode_32_byte_hex, invalid_preflight, matrix_coefficient_representation_from_statement,
    receiver_key_source_witness_coefficients, source_witness_coefficients, string_array_length,
    string_array_matches_expected,
};
pub(crate) use receiver_key_package_refusals::{
    collect_receiver_key_proof_refusals, collect_receiver_key_proof_root_evidence_refusals,
    derive_claim_bearing_ballot_package_digest,
};
pub(crate) use receiver_polynomial_helpers::{
    negate_receiver_polynomial, parse_receiver_column_index, parse_receiver_column_vector,
    parse_receiver_polynomial, parse_receiver_polynomial_vector,
    parse_share_commitment_polynomial_vector, push_receiver_sparse_entry,
    receiver_constant_polynomial,
};
pub(crate) use share_commitment_backend_helpers::{
    derive_share_commitment_message_matrix, derive_share_commitment_randomness_matrix,
    negate_share_commitment_polynomial, push_share_commitment_sparse_entry,
    share_commitment_message_entry_polynomial, split_share_commitment_polynomial,
};
pub(crate) use structured_receiver_encryption_statement::parse_structured_receiver_encryption_statement;
pub(crate) use structured_share_commitment_statement::parse_structured_share_commitment_statement;

#[cfg(test)]
pub(crate) use component_backend_sparse::{
    dense_matrix_from_sparse_component_statement, derive_sparse_statement_matrix_digest,
    derive_sparse_target_vector_digest,
};
#[cfg(test)]
pub(crate) use component_linear_proof_verification::verify_component_linear_proof_bytes;
#[cfg(test)]
pub(crate) use receiver_polynomial_helpers::{
    negacyclic_receiver_coefficient, parse_receiver_column_matrix,
};
#[cfg(test)]
pub(crate) use share_commitment_backend_helpers::add_structured_constant_entry;
#[cfg(test)]
pub(crate) use structured_share_commitment_statement::structured_receiver_encryption_statement_as_sparse;

pub(crate) use ballot_package_verifier::{
    verify_claim_bearing_ballot_package, verify_encoded_relation_vector_case,
    verify_linear_proof_vector_case, verify_receiver_key_vector_case,
};
pub(crate) use ballot_proof_generation_core::{
    generate_ballot_component_proof_from_command_request,
    generate_ballot_proof_from_command_request,
};
#[cfg(test)]
pub(crate) use ballot_proof_record_generation::generate_ballot_proof_record;
pub(crate) use ballot_proof_record_generation::generate_ballot_proof_record_from_command_request;
#[cfg(test)]
pub(crate) use ballot_proof_record_inputs::BallotProofRecordGenerationInput;
pub(crate) use receiver_key_proof::{
    generate_receiver_key_proof_from_command_request,
    prepare_receiver_key_proof_generation_from_command_request,
    verify_receiver_key_proof_from_command_request,
};

#[cfg(test)]
mod tests;
