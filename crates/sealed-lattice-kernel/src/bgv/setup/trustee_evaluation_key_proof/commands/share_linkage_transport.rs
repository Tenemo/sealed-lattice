use super::decoding::*;
use super::share_linkage_verification::*;
use super::*;
use crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY;

pub(super) struct ValidatedVssShareLinkageProofReference {
    pub(super) proof_bytes_hash: String,
}

pub(super) fn validate_vss_share_linkage_proof_reference(
    proof_record: &Value,
) -> CanonicalResult<ValidatedVssShareLinkageProofReference> {
    let proof_bytes_hash = read_string(proof_record, "proofBytesHash")?.to_string();
    Ok(ValidatedVssShareLinkageProofReference { proof_bytes_hash })
}

pub(super) fn resolve_vss_share_linkage_proof_bytes(
    reference: ValidatedVssShareLinkageProofReference,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    verified_vss_share_linkage_proof_material_bytes(
        &reference.proof_bytes_hash,
        proof_binding_session,
    )
}

pub(in crate::bgv::setup) fn verified_vss_share_linkage_proof_material_bytes(
    expected_proof_bytes_hash: &str,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let proof_bytes = take_verified_setup_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        expected_proof_bytes_hash,
        "VSS share-linkage proofBytesHash",
        proof_binding_session,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_string_value(
        &proof_bytes_hash,
        expected_proof_bytes_hash,
        "VSS share-linkage proof bytes hash",
    )?;

    Ok(proof_bytes)
}
