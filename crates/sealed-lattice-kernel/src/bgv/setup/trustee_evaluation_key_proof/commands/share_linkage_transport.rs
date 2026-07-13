use super::decoding::*;
use super::share_linkage_verification::*;
use super::*;
use crate::bgv::setup_helpers::compare_required_string;

pub(super) struct ResolvedVssShareLinkageProofBytes {
    pub(super) proof_bytes: SetupProofMaterialBytes,
}

pub(super) struct ValidatedVssShareLinkageProofReference {
    pub(super) proof_bytes_hash: String,
    pub(super) proof_material_root: String,
}

pub(super) fn validate_vss_share_linkage_proof_reference(
    proof_record: &Value,
) -> CanonicalResult<ValidatedVssShareLinkageProofReference> {
    let proof_bytes_hash = read_string(proof_record, "proofBytesHash")?.to_string();
    let proof_material_root = read_string(proof_record, "proofMaterialRoot")?.to_string();
    compare_string_value(
        &proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "share-linkage proof material root",
    )?;
    Ok(ValidatedVssShareLinkageProofReference {
        proof_bytes_hash,
        proof_material_root,
    })
}

pub(super) fn resolve_vss_share_linkage_proof_bytes(
    reference: ValidatedVssShareLinkageProofReference,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<ResolvedVssShareLinkageProofBytes> {
    let proof_bytes = take_verified_setup_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        &reference.proof_material_root,
        "vssShareLinkageProofRecord.proofMaterialRoot",
        proof_binding_session,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_string_value(
        &reference.proof_bytes_hash,
        &proof_bytes_hash,
        "share-linkage proof record proofBytesHash",
    )?;
    compare_required_string(
        &reference.proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "share-linkage proof material root",
    )?;

    Ok(ResolvedVssShareLinkageProofBytes {
        proof_bytes,
    })
}

pub(in crate::bgv::setup) fn verified_vss_share_linkage_proof_material_bytes(
    expected_proof_material_root: &str,
    expected_proof_bytes_hash: &str,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let proof_bytes = take_verified_setup_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        expected_proof_material_root,
        "vssShareLinkageProofRecord.proofMaterialRoot",
        proof_binding_session,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_required_string(
        expected_proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "share-linkage proof material root",
    )?;
    compare_string_value(
        &proof_bytes_hash,
        expected_proof_bytes_hash,
        "VSS share-linkage proof bytes hash",
    )?;

    Ok(proof_bytes)
}
