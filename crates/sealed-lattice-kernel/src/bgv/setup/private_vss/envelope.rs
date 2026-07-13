use super::*;

use crate::bgv::setup::setup_proof::SetupProofMaterialMap;
use crate::hashing::derive_canonical_object_hash;

const PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "PrivateVssShareEnvelope";
const PRIVATE_VSS_LIMB_OPENING_OBJECT_TYPE: &str = "PrivateVssShareLimbOpening";

pub(super) fn verify_private_envelope_header(
    private_envelope: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<Result<PrivateEnvelopeBinding, PrivateVssRefusal>> {
    if private_envelope.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeTypeMismatch",
            "privateEnvelope.objectType must be PrivateVssShareEnvelope",
            "privateEnvelope.objectType",
        )));
    }
    if let Err(refusal) = compare_context_fields(private_envelope, setup_context, "privateEnvelope")
    {
        return Ok(Err(refusal));
    }
    if private_envelope
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopePublicMatrixSeedMismatch",
            "privateEnvelope.publicMatrixSeedHash must match publicMatrixSeedHash",
            "privateEnvelope.publicMatrixSeedHash",
        )));
    }

    let source_trustee_identity = match string_field(
        private_envelope,
        "sourceTrusteeIdentity",
        "privateEnvelope.sourceTrusteeIdentity",
        "privateEnvelopeSourceTrusteeMissing",
        "privateEnvelope.sourceTrusteeIdentity is required",
    ) {
        Ok(source_trustee_identity) => source_trustee_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_roster_position = match u64_field(
        private_envelope,
        "sourceTrusteeRosterPosition",
        "privateEnvelope.sourceTrusteeRosterPosition",
        "privateEnvelopeSourceTrusteePositionMissing",
        "privateEnvelope.sourceTrusteeRosterPosition is required",
    ) {
        Ok(source_trustee_roster_position) => source_trustee_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if source_trustee_identity != source_trustee_binding.source_trustee_identity
        || source_trustee_roster_position != source_trustee_binding.source_trustee_roster_position
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeSourceTrusteeMismatch",
            "privateEnvelope source trustee binding must match sourceTrusteeCoefficientCommitmentRecord",
            "privateEnvelope.sourceTrusteeIdentity",
        )));
    }
    if private_envelope
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(
            source_trustee_binding
                .source_trustee_commitment_root
                .as_str(),
        )
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "privateEnvelope.sourceTrusteeCommitmentRoot must match the accepted source trustee commitment root",
            "privateEnvelope.sourceTrusteeCommitmentRoot",
        )));
    }

    let recipient_identity = match string_field(
        private_envelope,
        "recipientIdentity",
        "privateEnvelope.recipientIdentity",
        "privateEnvelopeRecipientMissing",
        "privateEnvelope.recipientIdentity is required",
    ) {
        Ok(recipient_identity) => recipient_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let recipient_roster_position = match u64_field(
        private_envelope,
        "recipientRosterPosition",
        "privateEnvelope.recipientRosterPosition",
        "privateEnvelopeRecipientPositionMissing",
        "privateEnvelope.recipientRosterPosition is required",
    ) {
        Ok(recipient_roster_position) => recipient_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    if recipient_roster_position >= roster.participant_count {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeRecipientPositionInvalid",
            "privateEnvelope.recipientRosterPosition is outside the setup roster",
            "privateEnvelope.recipientRosterPosition",
        )));
    }
    let private_envelope_aad_hash = match hash_string_field(
        private_envelope,
        "privateEnvelopeAadHash",
        "privateEnvelope.privateEnvelopeAadHash",
        "privateEnvelopeAadHashMissing",
        "privateEnvelope.privateEnvelopeAadHash is required",
    ) {
        Ok(private_envelope_aad_hash) => private_envelope_aad_hash.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    validate_hash_string(
        &private_envelope_aad_hash,
        "privateEnvelope.privateEnvelopeAadHash",
    )?;
    let private_envelope_hash = derive_canonical_object_hash(private_envelope)?;

    Ok(Ok(PrivateEnvelopeBinding {
        private_envelope_hash,
        private_envelope_aad_hash,
        recipient_identity,
        recipient_roster_position,
    }))
}

pub(super) fn verify_private_envelope_limbs(
    private_envelope: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    coefficient_commitments: &BTreeMap<(usize, u64), CoefficientCommitmentBinding>,
    envelope_binding: &PrivateEnvelopeBinding,
) -> CanonicalResult<Result<Vec<LimbVerification>, PrivateVssRefusal>> {
    let rns_share_openings = match array_field(
        private_envelope,
        "rnsShareOpenings",
        "privateEnvelope.rnsShareOpenings",
        "privateEnvelopeOpeningsMissing",
        "privateEnvelope.rnsShareOpenings is required",
    ) {
        Ok(rns_share_openings) => rns_share_openings,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if rns_share_openings.len() != DATA_PRIMES.len() {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeRnsOpeningCountMismatch",
            "privateEnvelope.rnsShareOpenings must contain one opening for every accepted Q_share limb",
            "privateEnvelope.rnsShareOpenings",
        )));
    }

    let mut seen_limbs = BTreeSet::new();
    let mut ring_degree: Option<usize> = None;
    let mut limb_verifications = Vec::with_capacity(DATA_PRIMES.len());
    for limb_opening in rns_share_openings {
        let limb_verification = match verify_private_envelope_limb(
            limb_opening,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_binding,
            coefficient_commitments,
            envelope_binding,
        )? {
            Ok(limb_verification) => limb_verification,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !seen_limbs.insert(limb_verification.rns_limb_index) {
            return Ok(Err(PrivateVssRefusal::new(
                "privateEnvelopeRnsOpeningDuplicate",
                "privateEnvelope.rnsShareOpenings must have distinct rnsLimbIndex values",
                "privateEnvelope.rnsShareOpenings",
            )));
        }
        match ring_degree {
            Some(expected_ring_degree) if expected_ring_degree != limb_verification.ring_degree => {
                return Ok(Err(PrivateVssRefusal::new(
                    "privateEnvelopeRingDegreeMismatch",
                    "all private VSS limb openings must use the same ring degree",
                    "privateEnvelope.rnsShareOpenings",
                )));
            }
            Some(_) => {}
            None => ring_degree = Some(limb_verification.ring_degree),
        }
        limb_verifications.push(limb_verification);
    }
    limb_verifications.sort_by_key(|verification| verification.rns_limb_index);

    Ok(Ok(limb_verifications))
}

fn verify_private_envelope_limb(
    limb_opening: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    coefficient_commitments: &BTreeMap<(usize, u64), CoefficientCommitmentBinding>,
    envelope_binding: &PrivateEnvelopeBinding,
) -> CanonicalResult<Result<LimbVerification, PrivateVssRefusal>> {
    if limb_opening.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_LIMB_OPENING_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssLimbOpeningTypeMismatch",
            "private VSS limb opening objectType must be PrivateVssShareLimbOpening",
            "privateEnvelope.rnsShareOpenings.objectType",
        )));
    }
    let rns_limb_index = match usize_field(
        limb_opening,
        "rnsLimbIndex",
        "privateEnvelope.rnsShareOpenings.rnsLimbIndex",
        "privateVssLimbIndexMissing",
        "private VSS limb opening must bind rnsLimbIndex",
    ) {
        Ok(rns_limb_index) => rns_limb_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let rns_prime = match u64_field(
        limb_opening,
        "rnsPrime",
        "privateEnvelope.rnsShareOpenings.rnsPrime",
        "privateVssRnsPrimeMissing",
        "private VSS limb opening must bind rnsPrime",
    ) {
        Ok(rns_prime) => rns_prime,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssRnsPrimeMismatch",
            "private VSS limb opening rnsPrime must match Q_share at rnsLimbIndex",
            "privateEnvelope.rnsShareOpenings.rnsPrime",
        )));
    }

    let share_values = match u64_vector_field(
        limb_opening,
        "shareValues",
        "privateEnvelope.rnsShareOpenings.shareValues",
        "privateVssShareValuesMissing",
        "private VSS limb opening must include shareValues",
    ) {
        Ok(share_values) => share_values,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ring_degree = share_values.len();
    if ring_degree == 0 {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssShareValuesEmpty",
            "private VSS share vector must be non-empty",
            "privateEnvelope.rnsShareOpenings.shareValues",
        )));
    }

    let coefficient_commitment_roots = match hash_vector_field(
        limb_opening,
        "coefficientCommitmentRoots",
        "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
        "privateVssCoefficientCommitmentRootsMissing",
        "private VSS limb opening must bind coefficientCommitmentRoots",
    ) {
        Ok(coefficient_commitment_roots) => coefficient_commitment_roots,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    if coefficient_commitment_roots.len() != roster.decryption_threshold as usize {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssCoefficientCommitmentRootCountMismatch",
            "private VSS limb opening must bind every Shamir coefficient commitment root",
            "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
        )));
    }

    let mut coefficient_commitment_values =
        Vec::with_capacity(roster.decryption_threshold as usize);
    for (shamir_coefficient_index, commitment_root) in
        coefficient_commitment_roots.iter().enumerate()
    {
        let shamir_coefficient_index = shamir_coefficient_index as u64;
        if source_trustee_binding
            .coefficient_commitment_roots
            .get(&(rns_limb_index, shamir_coefficient_index))
            .map(String::as_str)
            != Some(commitment_root.as_str())
        {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentRootMismatch",
                "private VSS limb coefficientCommitmentRoots must match the public source trustee commitment record",
                "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
            )));
        }
        let Some(material_binding) =
            coefficient_commitments.get(&(rns_limb_index, shamir_coefficient_index))
        else {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentMaterialMissing",
                "private VSS limb references coefficient commitment material that was not provided",
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        };
        if material_binding.commitment_root != *commitment_root {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentMaterialRootMismatch",
                "coefficient commitment material root must match private envelope root reference",
                "sourceTrusteeCoefficientCommitmentMaterialRecords.commitmentRoot",
            )));
        }
        coefficient_commitment_values.push(material_binding.commitment.clone());
    }

    let private_vss_share_proof = match object_field(
        limb_opening,
        "privateVssShareProof",
        "privateEnvelope.rnsShareOpenings.privateVssShareProof",
        "privateVssShareProofMissing",
        "private VSS limb opening must include a recipient-local zero-knowledge privateVssShareProof",
    ) {
        Ok(private_vss_share_proof) => private_vss_share_proof,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let share_values_hash = derive_canonical_object_hash(&json!({
        "objectType": "PrivateVssShareValueVector",
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shareValues": share_values,
    }))?;
    let proof_verification = match verify_private_vss_share_succinct_relation_proof(
        PrivateVssShareSuccinctProofVerificationInput {
            setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash: &envelope_binding.private_envelope_aad_hash,
            source_trustee_identity: &source_trustee_binding.source_trustee_identity,
            source_trustee_roster_position: source_trustee_binding.source_trustee_roster_position,
            recipient_identity: &envelope_binding.recipient_identity,
            recipient_roster_position: envelope_binding.recipient_roster_position,
            source_trustee_commitment_root: &source_trustee_binding.source_trustee_commitment_root,
            rns_limb_index,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitment_values,
            proof_record: private_vss_share_proof,
        },
    ) {
        Ok(verification) => verification,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssShareProofVerificationFailed",
                error.message,
                "privateEnvelope.rnsShareOpenings.privateVssShareProof",
            )));
        }
    };
    let limb_verification_record = json!({
        "objectType": "PrivateVssLimbVerification",
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "shareValuesHash": share_values_hash,
        "privateVssShareProofHash": proof_verification.proof_bytes_hash,
        "proofMaterialRoot": proof_verification.proof_material_root,
        "statementHash": proof_verification.statement_hash_hex,
    });
    let limb_verification_root = derive_canonical_object_hash(&limb_verification_record)?;

    Ok(Ok(LimbVerification {
        rns_limb_index,
        rns_prime,
        ring_degree,
        coefficient_commitment_roots,
        share_values_hash,
        private_vss_share_proof_hash: proof_verification.proof_bytes_hash,
        limb_verification_root,
    }))
}
