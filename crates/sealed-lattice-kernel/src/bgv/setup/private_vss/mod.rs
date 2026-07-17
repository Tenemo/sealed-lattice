use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::{bgv::parameters::DATA_PRIMES, encoding::CanonicalResult};

use super::{
    commitment::{SetupCommitmentValue, parse_setup_commitment_full_value, setup_commitment_root},
    private_vss_share_proof::{
        PrivateVssShareSuccinctProofVerificationInput, private_vss_share_succinct_statement_hash,
        verify_private_vss_share_succinct_relation_proof,
    },
};

use super::accepted_setup;
#[cfg(test)]
use super::private_vss_share_proof::{
    PrivateVssShareSuccinctProofGenerationInput, PrivateVssShareSuccinctProofWitness,
    private_vss_share_succinct_proof_bytes_hash_for_tests,
};
#[cfg(test)]
use super::sharing::canonical_trustee_point;

mod bindings;
mod envelope;
#[cfg(test)]
mod proof_generation;
mod refusal;
mod request_fields;

use bindings::*;
use envelope::*;
use refusal::*;
use request_fields::*;

#[cfg(test)]
pub(crate) use proof_generation::generate_private_vss_share_proof_from_request;

pub(crate) fn verify_private_vss_share_envelope_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    match verify_private_vss_share_envelope_inner(request)? {
        Ok(response) => Ok(response),
        Err(refusal) => Ok(json!({
            "isValid": false,
            "refusalReason": refusal.refusal_reason().name(),
        })),
    }
}

pub(crate) fn derive_private_vss_share_statement_hash_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_context = object_field(
        request,
        "setupContext",
        "setupContext",
        PrivateVssRefusalCode::missing("setupContextMissing"),
        "setupContext must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if let Err(refusal) = verify_setup_context(setup_context)? {
        return Err(private_vss_refusal_to_error(refusal));
    }
    let public_matrix_seed_hash = hash_string_field(
        request,
        "publicMatrixSeedHash",
        PrivateVssRefusalCode::missing("publicMatrixSeedHashMissing"),
        "publicMatrixSeedHash must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let private_envelope_aad_hash = hash_string_field(
        request,
        "privateEnvelopeAadHash",
        PrivateVssRefusalCode::missing("privateEnvelopeAadHashMissing"),
        "privateEnvelopeAadHash must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    validate_hash_string(private_envelope_aad_hash, "privateEnvelopeAadHash")?;
    let source_trustee_identity = string_field(
        request,
        "sourceTrusteeIdentity",
        PrivateVssRefusalCode::missing("sourceTrusteeIdentityMissing"),
        "sourceTrusteeIdentity must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let source_trustee_roster_position = u64_field(
        request,
        "sourceTrusteeRosterPosition",
        PrivateVssRefusalCode::missing("sourceTrusteeRosterPositionMissing"),
        "sourceTrusteeRosterPosition must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let recipient_roster_position = u64_field(
        request,
        "recipientRosterPosition",
        PrivateVssRefusalCode::missing("recipientRosterPositionMissing"),
        "recipientRosterPosition must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let roster = accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    if source_trustee_roster_position >= roster.participant_count
        || recipient_roster_position >= roster.participant_count
    {
        return Err(crate::encoding::CanonicalError::new(
            crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
            "private VSS statement roster positions are outside the setup roster",
        ));
    }
    let rns_limb_index = usize_field(
        request,
        "rnsLimbIndex",
        "rnsLimbIndex",
        PrivateVssRefusalCode::missing("rnsLimbIndexMissing"),
        "rnsLimbIndex must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let rns_prime = DATA_PRIMES.get(rns_limb_index).copied().ok_or_else(|| {
        crate::encoding::CanonicalError::new(
            crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
            "rnsLimbIndex is outside Q_share",
        )
    })?;
    let share_values = u64_vector_field(
        request,
        "shareValues",
        "shareValues",
        PrivateVssRefusalCode::missing("shareValuesMissing"),
        "shareValues must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if share_values.is_empty() || share_values.iter().any(|value| *value >= rns_prime) {
        return Err(crate::encoding::CanonicalError::new(
            crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
            "shareValues must be a non-empty canonical Q_share residue vector",
        ));
    }
    let material_records = array_field(
        request,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        PrivateVssRefusalCode::missing("sourceTrusteeCommitmentMaterialMissing"),
        "sourceTrusteeCoefficientCommitmentMaterialRecords must be provided for private VSS statement derivation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let coefficient_commitment_roots = material_records
        .iter()
        .map(parse_setup_commitment_full_value)
        .map(|commitment| commitment.and_then(|commitment| setup_commitment_root(&commitment)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let source_trustee_record = json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
    });
    let source_trustee_binding = verify_source_trustee_commitment_record(
        &source_trustee_record,
        setup_context,
        source_trustee_roster_position,
    )?
    .map_err(private_vss_refusal_to_error)?;
    let commitment_bindings = verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        &source_trustee_binding,
    )?
    .map_err(private_vss_refusal_to_error)?;
    let decryption_threshold = usize::try_from(roster.decryption_threshold).map_err(|_| {
        crate::encoding::CanonicalError::new(
            crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
            "setup decryption threshold does not fit usize",
        )
    })?;
    let mut selected_commitment_roots = Vec::with_capacity(decryption_threshold);
    let mut selected_commitments = Vec::with_capacity(decryption_threshold);
    for shamir_coefficient_index in 0..roster.decryption_threshold {
        let binding = commitment_bindings
            .get(&(rns_limb_index, shamir_coefficient_index))
            .ok_or_else(|| {
                crate::encoding::CanonicalError::new(
                    crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
                    "private VSS statement material is missing a selected commitment",
                )
            })?;
        selected_commitment_roots.push(binding.commitment_root.clone());
        selected_commitments.push(binding.commitment.clone());
    }

    let statement_hash = private_vss_share_succinct_statement_hash(
        &PrivateVssShareSuccinctProofVerificationInput {
            setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_roster_position,
            recipient_roster_position,
            source_trustee_commitment_root: &source_trustee_binding.source_trustee_commitment_root,
            rns_limb_index,
            coefficient_commitment_roots: &selected_commitment_roots,
            share_values: &share_values,
            coefficient_commitments: &selected_commitments,
            proof_bytes_hash: "",
        },
    )?;

    Ok(json!({ "statementHash": statement_hash }))
}

fn verify_private_vss_share_envelope_inner(
    request: &Value,
) -> CanonicalResult<Result<Value, PrivateVssRefusal>> {
    let setup_context = match object_field(
        request,
        "setupContext",
        "setupContext",
        PrivateVssRefusalCode::missing("setupContextMissing"),
        "setupContext must be provided for private VSS verification",
    ) {
        Ok(setup_context) => setup_context,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = verify_setup_context(setup_context)? {
        return Ok(Err(refusal));
    }

    let public_matrix_seed_hash = match hash_string_field(
        request,
        "publicMatrixSeedHash",
        PrivateVssRefusalCode::missing("publicMatrixSeedHashMissing"),
        "publicMatrixSeedHash must be provided for private VSS verification",
    ) {
        Ok(public_matrix_seed_hash) => public_matrix_seed_hash,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_record = match object_field(
        request,
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCoefficientCommitmentRecord",
        PrivateVssRefusalCode::missing("sourceTrusteeCommitmentRecordMissing"),
        "sourceTrusteeCoefficientCommitmentRecord must be provided for private VSS verification",
    ) {
        Ok(source_trustee_record) => source_trustee_record,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let private_envelope = match object_field(
        request,
        "privateEnvelope",
        "privateEnvelope",
        PrivateVssRefusalCode::missing("privateEnvelopeMissing"),
        "privateEnvelope must be provided for private VSS verification",
    ) {
        Ok(private_envelope) => private_envelope,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_roster_position = match u64_field(
        private_envelope,
        "sourceTrusteeRosterPosition",
        PrivateVssRefusalCode::missing("sourceTrusteeRosterPositionMissing"),
        "privateEnvelope.sourceTrusteeRosterPosition is required",
    ) {
        Ok(source_trustee_roster_position) => source_trustee_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let source_trustee_binding = match verify_source_trustee_commitment_record(
        source_trustee_record,
        setup_context,
        source_trustee_roster_position,
    )? {
        Ok(source_trustee_binding) => source_trustee_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let material_records = match array_field(
        request,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        PrivateVssRefusalCode::missing("sourceTrusteeCommitmentMaterialMissing"),
        "sourceTrusteeCoefficientCommitmentMaterialRecords must provide full public commitment material for private VSS verification",
    ) {
        Ok(material_records) => material_records,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        &source_trustee_binding,
    )? {
        Ok(coefficient_commitments) => coefficient_commitments,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let envelope_binding = match verify_private_envelope_header(
        private_envelope,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
    )? {
        Ok(envelope_binding) => envelope_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    match verify_private_envelope_limbs(
        private_envelope,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
        &coefficient_commitments,
        &envelope_binding,
    )? {
        Ok(()) => {}
        Err(refusal) => return Ok(Err(refusal)),
    }

    if let Some(expected_private_envelope_hash) = request
        .get("expectedPrivateEnvelopeHash")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            expected_private_envelope_hash,
            "expectedPrivateEnvelopeHash",
        )?;
        if expected_private_envelope_hash != envelope_binding.private_envelope_hash {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::wrong_hash("expectedPrivateEnvelopeHashMismatch"),
                "computed private envelope hash does not match expectedPrivateEnvelopeHash",
            )));
        }
    }
    Ok(Ok(json!({
        "isValid": true,
        "value": {
            "privateEnvelopeHash": envelope_binding.private_envelope_hash,
        },
    })))
}
