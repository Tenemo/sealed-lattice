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
mod sparse_linear_proof_statement;
mod sparse_polynomial_matrix;
mod sparse_polynomial_vector;
mod tbox_relations;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::{
    hashing::{
        canonical_json, derive_protocol_hash, derive_protocol_hash_for_proof_bytes_payload,
        hash512, to_hex,
    },
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
    receiver_key::{
        RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK,
        RECEIVER_ENCRYPTION_MODULUS, derive_receiver_encryption_public_matrix,
    },
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
};

#[cfg(test)]
pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = true;

mod aggregate_bridge_proof;
mod aggregate_derivation_proof;
mod backend_status;
mod ballot_proof;
mod component;
mod json_helpers;
#[path = "linear_proof/binding_validation.rs"]
mod linear_proof_binding_validation;
#[path = "linear_proof/contract_validation.rs"]
mod linear_proof_contract_validation;
mod proof_binding_hashes;
mod proof_preflight_parsing;
mod receiver_key;

pub(crate) mod linear_proof {
    pub(crate) mod abdlop {
        pub use crate::ballot_privacy::linear_proof_abdlop::validate_abdlop_linear_opening;
    }

    pub(crate) mod abdlop_commitment {
        pub use crate::ballot_privacy::abdlop_commitment::hash_abdlop_commitment;
    }

    #[cfg(test)]
    pub(crate) mod contract_validation {
        pub(crate) use crate::ballot_privacy::linear_proof_contract_validation::{
            binding_scalar_from_hash, derive_full_relation_binding_hash,
        };
    }

    pub(crate) mod parameters {
        pub(crate) use crate::ballot_privacy::linear_proof_parameters::*;

        pub(crate) fn linear_proof_claim_boundary_status_labels(
            proof_encoding: &LinearProofEncoding,
        ) -> Vec<&'static str> {
            match proof_encoding.profile_id.as_str() {
                "full-encoded-score-ballot-linear-proof-encoding-v1"
                | "payload-plaintext-field-linear-proof-encoding-v1"
                | "receiver-encryption-linear-proof-encoding-v1"
                | "share-commitment-linear-proof-encoding-v1"
                | "aggregate-derivation-linear-proof-encoding-v1" => vec![
                    "LinearProofParameterBoundsOnly",
                    "LinearProofStandaloneSoundnessEvidenceMissing",
                ],
                _ => Vec::new(),
            }
        }
    }

    #[cfg(test)]
    pub(crate) mod profile_constants {
        pub(crate) use crate::ballot_privacy::linear_proof_profile_constants::{
            DEMO_GENERATED_PARAMETER_CONTRACT, DEMO_GENERATED_PROFILE,
            GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED,
            GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED,
            RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT, RECEIVER_KEY_GENERATED_PROFILE,
        };
    }

    pub(crate) mod many_quadratic {
        pub(crate) use crate::ballot_privacy::many_quadratic::*;
    }

    pub(crate) mod norms {
        pub use crate::ballot_privacy::linear_proof_norms::validate_linear_proof_norms as validate_norms;
    }

    pub(crate) mod proof_coder {
        pub(crate) use crate::ballot_privacy::proof_coder::*;
    }

    pub(crate) mod prover {
        pub(crate) use crate::ballot_privacy::linear_proof_prover::*;
    }

    pub(crate) mod public_parameters {
        pub(crate) use crate::ballot_privacy::linear_proof_public_parameters::*;
    }

    pub(crate) mod quadratic_challenge {
        pub(crate) use crate::ballot_privacy::quadratic_challenge::*;
    }

    #[cfg(test)]
    pub(crate) mod rng {
        pub(crate) use crate::ballot_privacy::linear_proof_rng::sample_linear_proof_uniform_u64_values;
    }

    pub(crate) mod sparse_statement {
        pub(crate) use crate::ballot_privacy::sparse_linear_proof_statement::*;
    }

    pub(crate) mod statement {
        pub(crate) use crate::ballot_privacy::linear_proof_statement::*;
    }

    pub(crate) mod tbox {
        pub use crate::ballot_privacy::linear_proof_tbox::validate_linear_proof_tbox_public_checks as validate_tbox_public_checks;
    }

    pub(crate) mod tbox_relations {
        pub(crate) use crate::ballot_privacy::tbox_relations::*;
    }

    pub(crate) mod transcript {
        pub(crate) use crate::ballot_privacy::linear_proof_transcript::*;
    }

    #[cfg(test)]
    pub(crate) mod verifier {
        pub(crate) use crate::ballot_privacy::linear_proof_verifier::{
            SparseLinearProofVerificationInput, verify_linear_proof_vector_case_value,
            verify_sparse_linear_proof_components,
        };
    }
}

pub(crate) use aggregate_bridge_proof::{
    evaluate_aggregate_bridge_relation_from_command_request,
    generate_aggregate_bridge_encryption_from_command_request,
    verify_aggregate_bridge_encryption_from_command_request,
};
pub(crate) use aggregate_derivation_proof::{
    check_aggregate_derivation_witness_relation,
    generate_aggregate_derivation_proof_from_command_request,
    verify_aggregate_derivation_proof_from_command_request,
    verify_aggregate_derivation_relation_subproof_for_component,
};
pub(crate) use backend_status::{describe_proof_backend, structural_refusal, structural_rejection};
#[cfg(test)]
pub(crate) use ballot_proof::derive_ballot_proof_challenge_hash;
pub(crate) use ballot_proof::verify_ballot_proof_from_command_request;
#[cfg(test)]
pub(crate) use ballot_proof::{
    BallotProofVerificationInputs, ComponentProofVerificationMode, verify_ballot_proof,
};
pub(crate) use ballot_proof::{collect_proof_bytes_refusals, reference_map};
pub(crate) use ballot_proof::{
    derive_ballot_component_bundle_statement_hash, derive_ballot_component_proof_bundle_hash,
    derive_ballot_component_proof_record_hash, derive_ballot_component_proof_root,
    derive_ballot_component_statement_hash,
};
#[cfg(test)]
pub(crate) use component::COMPONENT_BUNDLE_INCOMPLETE_COVERAGE;
pub(crate) use component::parse_structured_receiver_encryption_statement;
pub(crate) use component::parse_structured_share_commitment_statement;
pub(crate) use component::verify_component_proof_bundle_backend;
pub(crate) use component::{
    ComponentProofBackendError, component_proof_backend_rejection, integer_value,
    sparse_matrix_from_sparse_component_statement, u64_object_field, usize_object_field,
};
pub(crate) use component::{
    DENSE_COMPONENT_PROOF_STATEMENT_FORMAT, FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
    FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID, FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
    MAX_GENERIC_SPARSE_COMPONENT_SHORT_RESPONSE_VECTOR_LENGTH,
    PUBLIC_BINDING_CHECK_PROOF_STATEMENT_FORMAT, RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID,
    RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID, REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
    SHARE_COMMITMENT_MODULE_DEGREE, SHARE_COMMITMENT_MODULE_RANK,
    SHARE_COMMITMENT_OPENING_DIMENSION, SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT,
    STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT,
    STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT, component_proof_bytes_must_be_empty,
    encoded_share_vector_width,
};
pub(crate) use component::{
    collect_ballot_component_bundle_refusals, collect_ballot_component_proof_bundle_refusals,
    supplied_component_proof_statement_hash,
};
pub(crate) use json_helpers::{
    array_field, collect_receiver_reference_refusals, derive_hash, is_nfc_normalized,
    is_protocol_hash, object_map, positive_roster_position, receiver_reference_key,
    required_json_field, required_string_field, string_field, unsigned_decimal_string,
    value_without_field, value_without_fields,
};
pub(crate) use linear_proof_binding_validation::{
    LinearProofBindingValidationInput, LinearProofBindingValidationMessages,
    LinearProofProfileRequirement, collect_linear_proof_binding_refusals,
};
pub(crate) use linear_proof_contract_validation::{
    collect_full_ballot_binding_contract_refusals, collect_full_ballot_relation_binding_refusals,
    collect_supported_ballot_privacy_dimension_refusals,
};
pub(crate) use proof_binding_hashes::{
    derive_ballot_component_proof_statement_descriptor_hash,
    derive_ballot_proof_encoding_profile_hash, derive_ballot_proof_linear_statement_hash,
    derive_ballot_proof_parameter_set_hash, derive_ballot_proof_public_randomness_hash,
    derive_ballot_sparse_linear_statement_hash,
    derive_ballot_structured_receiver_encryption_statement_hash,
    derive_ballot_structured_share_commitment_statement_hash,
    derive_receiver_key_linear_statement_hash, derive_receiver_key_proof_encoding_profile_hash,
    derive_receiver_key_proof_parameter_set_hash, derive_receiver_key_public_randomness_hash,
};
pub(crate) use proof_preflight_parsing::{
    decode_32_byte_hex, invalid_preflight, matrix_coefficient_representation_from_statement,
    receiver_key_source_witness_coefficients, source_witness_coefficients, string_array_length,
    string_array_matches_expected,
};
pub(crate) use receiver_key::{
    collect_receiver_key_proof_root_evidence_refusals, derive_claim_bearing_ballot_package_hash,
};
pub(crate) use receiver_key::{
    negate_receiver_polynomial, parse_receiver_column_index, parse_receiver_column_vector,
    parse_receiver_polynomial, parse_receiver_polynomial_vector,
    parse_share_commitment_polynomial_vector, push_receiver_sparse_entry,
    receiver_constant_polynomial,
};

#[cfg(test)]
pub(crate) use component::structured_receiver_encryption_statement_as_sparse;
#[cfg(test)]
pub(crate) use component::verify_component_linear_proof_bytes;
#[cfg(test)]
pub(crate) use component::{
    dense_matrix_from_sparse_component_statement, derive_sparse_statement_matrix_hash,
    derive_sparse_target_vector_hash,
};
#[cfg(test)]
pub(crate) use receiver_key::{negacyclic_receiver_coefficient, parse_receiver_column_matrix};

#[cfg(test)]
pub(crate) use ballot_proof::BallotProofRecordGenerationInput;
#[cfg(test)]
pub(crate) use ballot_proof::generate_ballot_proof_record;
pub(crate) use ballot_proof::generate_ballot_proof_record_from_command_request;
pub(crate) use ballot_proof::{
    generate_ballot_component_proof_from_command_request,
    generate_ballot_proof_from_command_request,
};
pub(crate) use ballot_proof::{
    verify_claim_bearing_ballot_package, verify_encoded_relation_vector_case,
    verify_linear_proof_vector_case, verify_receiver_key_vector_case,
};
pub(crate) use receiver_key::{
    generate_receiver_key_proof_from_command_request,
    prepare_receiver_key_proof_generation_from_command_request,
    verify_receiver_key_proof_from_command_request,
};

#[cfg(test)]
mod tests;
