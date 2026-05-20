use super::*;

mod bundle_backend;
mod dense_component;
mod dense_vector_case;
mod public_zero_witness;
mod sparse_component;
mod structured_receiver_encryption;

use dense_component::verify_dense_component_proof;
use public_zero_witness::verify_public_zero_witness_component_proof;
use sparse_component::verify_sparse_compatible_component_proof;
use structured_receiver_encryption::verify_structured_receiver_encryption_component_proof;

pub(crate) use bundle_backend::verify_component_proof_bundle_backend;
pub(crate) use dense_vector_case::component_linear_proof_vector_case;

pub(crate) fn verify_component_linear_proof_bytes(
    operation: &str,
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Value {
    let proof_statement_format = string_field(proof_input, "proofStatementFormat");

    if proof_statement_format == Some(STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT) {
        return verify_structured_receiver_encryption_component_proof(
            operation,
            component_id,
            component_proof,
            proof_input,
        );
    }

    if proof_statement_format == Some(PUBLIC_ZERO_PROOF_STATEMENT_FORMAT) {
        return verify_public_zero_witness_component_proof(
            operation,
            component_id,
            component_proof,
            proof_input,
        );
    }

    if proof_statement_format.is_some_and(|format| {
        format == SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT
            || format == STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT
    }) {
        return verify_sparse_compatible_component_proof(
            operation,
            component_id,
            component_proof,
            proof_input,
        );
    }

    verify_dense_component_proof(operation, component_id, component_proof, proof_input)
}
