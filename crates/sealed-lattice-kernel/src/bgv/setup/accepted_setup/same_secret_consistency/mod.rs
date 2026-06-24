use super::*;

mod accessors;
mod anchor_proofs;
mod consistency;
mod family_binding;
mod proof_transport;

pub(super) use accessors::{
    same_secret_consistency_root_from_package,
    same_secret_constant_commitment_values_from_material, same_secret_proof_bindings_from_package,
    same_secret_proof_set_root_from_package, same_secret_statement_bindings_from_package,
    same_secret_statement_records_by_roster_position,
    same_secret_transported_constant_commitments_by_roster_position,
};
pub(super) use anchor_proofs::verify_optional_same_secret_proofs;
pub(super) use consistency::verify_same_secret_consistency;
pub(super) use family_binding::{
    same_secret_proof_family_binding_root, verify_same_secret_context,
};
#[cfg(test)]
pub(in crate::bgv::setup) use proof_transport::same_secret_anchor_proof_material_root;

struct SameSecretTrusteeBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    vss_source_trustee_commitment_root: String,
    constant_commitment_roots: Vec<Value>,
}

pub(super) struct SameSecretStatementBinding {
    pub(super) trustee_identity: String,
    pub(super) trustee_secret_commitment_root: String,
    pub(super) same_secret_statement_root: String,
}

pub(super) struct SameSecretProofBinding {
    pub(super) trustee_identity: String,
    pub(super) trustee_secret_commitment_root: String,
    pub(super) same_secret_statement_root: String,
    pub(super) same_secret_proof_family_binding_root: String,
    pub(super) same_secret_proof_root: String,
}

fn same_secret_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn same_secret_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("proofVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
