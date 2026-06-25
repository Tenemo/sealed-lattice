use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::{
    bgv::{
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        setup_helpers::decimal_i128_value,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

use super::{
    commitment::{SetupCommitmentValue, parse_setup_commitment_full_value, setup_commitment_root},
    private_vss_share_proof::{
        PrivateVssShareSuccinctProofGenerationInput, PrivateVssShareSuccinctProofVerificationInput,
        PrivateVssShareSuccinctProofWitness, private_vss_share_succinct_proof_record,
        verify_private_vss_share_succinct_relation_proof,
    },
    sharing::canonical_trustee_point,
};

// The private VSS delivery path is split by responsibility into sibling
// sub-modules. This module owns the request/response boundary: the public
// verify entry point and the verifier pipeline `verify_private_vss_share_envelope_inner`.
// The `accepted_setup` module is re-exported so sub-modules keep referencing
// `super::accepted_setup::accepted_roster_from_setup_context` unchanged after
// the move under this `private_vss/` directory.
use super::accepted_setup;

mod bindings;
mod envelope;
mod local_verification_record;
mod proof_generation;
mod refusal;
mod request_fields;

use bindings::*;
use envelope::*;
use local_verification_record::*;
use refusal::*;
use request_fields::*;

pub(crate) use proof_generation::generate_private_vss_share_proof_from_request;

pub(crate) fn verify_private_vss_share_envelope_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    match verify_private_vss_share_envelope_inner(request)? {
        Ok(response) => Ok(response),
        Err(refusal) => Ok(verification_response(
            false,
            "refused",
            None,
            None,
            Vec::new(),
            vec![refusal],
        )),
    }
}

fn verify_private_vss_share_envelope_inner(
    request: &Value,
) -> CanonicalResult<Result<Value, PrivateVssRefusal>> {
    let setup_context = match object_field(
        request,
        "setupContext",
        "setupContext",
        "setupContextMissing",
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
        "publicMatrixSeedHash",
        "publicMatrixSeedHashMissing",
        "publicMatrixSeedHash must be provided for private VSS verification",
    ) {
        Ok(public_matrix_seed_hash) => public_matrix_seed_hash,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_record = match object_field(
        request,
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCommitmentRecordMissing",
        "sourceTrusteeCoefficientCommitmentRecord must be provided for private VSS verification",
    ) {
        Ok(source_trustee_record) => source_trustee_record,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let private_envelope = match object_field(
        request,
        "privateEnvelope",
        "privateEnvelope",
        "privateEnvelopeMissing",
        "privateEnvelope must be provided for private VSS verification",
    ) {
        Ok(private_envelope) => private_envelope,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let source_trustee_binding = match verify_source_trustee_commitment_record(
        source_trustee_record,
        setup_context,
        public_matrix_seed_hash,
    )? {
        Ok(source_trustee_binding) => source_trustee_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let material_records = match array_field(
        request,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCommitmentMaterialMissing",
        "sourceTrusteeCoefficientCommitmentMaterialRecords must provide full public commitment material for private VSS verification",
    ) {
        Ok(material_records) => material_records,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        public_matrix_seed_hash,
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
    let limb_verifications = match verify_private_envelope_limbs(
        private_envelope,
        request.get("transportedPrivateVssShareProofMaterial"),
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
        &coefficient_commitments,
        &envelope_binding,
    )? {
        Ok(limb_verifications) => limb_verifications,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ring_degree = limb_verifications
        .first()
        .map(|verification| verification.ring_degree)
        .unwrap_or(0);
    let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
        "full-ring"
    } else {
        "development-reduced-ring"
    };

    let local_verification_record = local_verification_record(
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
        &envelope_binding,
        ring_degree,
        ring_degree_status,
        &limb_verifications,
    )?;
    let local_verification_root = derive_canonical_object_hash(&local_verification_record)?;

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
                "expectedPrivateEnvelopeHashMismatch",
                "computed private envelope hash does not match expectedPrivateEnvelopeHash",
                "expectedPrivateEnvelopeHash",
            )));
        }
    }
    if let Some(expected_local_verification_root) = request
        .get("expectedLocalVerificationRoot")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            expected_local_verification_root,
            "expectedLocalVerificationRoot",
        )?;
        if expected_local_verification_root != local_verification_root {
            return Ok(Err(PrivateVssRefusal::new(
                "expectedLocalVerificationRootMismatch",
                "computed private VSS local verification root does not match expectedLocalVerificationRoot",
                "expectedLocalVerificationRoot",
            )));
        }
    }

    let mut response = verification_response(
        true,
        "accepted",
        Some(envelope_binding.private_envelope_hash),
        Some(local_verification_root),
        limb_verifications
            .into_iter()
            .map(limb_verification_value)
            .collect(),
        Vec::new(),
    );
    response["ringDegree"] = json!(ring_degree);
    response["ringDegreeStatus"] = json!(ring_degree_status);
    response["verifiedRnsLimbCount"] = json!(DATA_PRIMES.len());
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    response["verifiedShamirCoefficientCommitmentCount"] =
        json!(DATA_PRIMES.len() * roster.decryption_threshold as usize);
    response["verifiedPrivateVssShareProofCount"] = json!(DATA_PRIMES.len());

    Ok(Ok(response))
}
