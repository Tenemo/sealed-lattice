use super::*;

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
            PrivateVssRefusalCode::wrong_type("privateEnvelopeTypeMismatch"),
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
            PrivateVssRefusalCode::wrong_hash("privateEnvelopePublicMatrixSeedMismatch"),
            "privateEnvelope.publicMatrixSeedHash must match publicMatrixSeedHash",
            "privateEnvelope.publicMatrixSeedHash",
        )));
    }

    let source_trustee_identity = match string_field(
        private_envelope,
        "sourceTrusteeIdentity",
        "privateEnvelope.sourceTrusteeIdentity",
        PrivateVssRefusalCode::missing("privateEnvelopeSourceTrusteeMissing"),
        "privateEnvelope.sourceTrusteeIdentity is required",
    ) {
        Ok(source_trustee_identity) => source_trustee_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_roster_position = match u64_field(
        private_envelope,
        "sourceTrusteeRosterPosition",
        "privateEnvelope.sourceTrusteeRosterPosition",
        PrivateVssRefusalCode::missing("privateEnvelopeSourceTrusteePositionMissing"),
        "privateEnvelope.sourceTrusteeRosterPosition is required",
    ) {
        Ok(source_trustee_roster_position) => source_trustee_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if source_trustee_identity != source_trustee_binding.source_trustee_identity
        || source_trustee_roster_position != source_trustee_binding.source_trustee_roster_position
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_context("privateEnvelopeSourceTrusteeMismatch"),
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
            PrivateVssRefusalCode::wrong_hash("privateEnvelopeSourceTrusteeCommitmentRootMismatch"),
            "privateEnvelope.sourceTrusteeCommitmentRoot must match the accepted source trustee commitment root",
            "privateEnvelope.sourceTrusteeCommitmentRoot",
        )));
    }

    if let Err(refusal) = string_field(
        private_envelope,
        "recipientIdentity",
        "privateEnvelope.recipientIdentity",
        PrivateVssRefusalCode::missing("privateEnvelopeRecipientMissing"),
        "privateEnvelope.recipientIdentity is required",
    ) {
        return Ok(Err(refusal));
    }
    let recipient_roster_position = match u64_field(
        private_envelope,
        "recipientRosterPosition",
        "privateEnvelope.recipientRosterPosition",
        PrivateVssRefusalCode::missing("privateEnvelopeRecipientPositionMissing"),
        "privateEnvelope.recipientRosterPosition is required",
    ) {
        Ok(recipient_roster_position) => recipient_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    if recipient_roster_position >= roster.participant_count {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("privateEnvelopeRecipientPositionInvalid"),
            "privateEnvelope.recipientRosterPosition is outside the setup roster",
            "privateEnvelope.recipientRosterPosition",
        )));
    }
    let private_envelope_aad_hash = match hash_string_field(
        private_envelope,
        "privateEnvelopeAadHash",
        "privateEnvelope.privateEnvelopeAadHash",
        PrivateVssRefusalCode::missing("privateEnvelopeAadHashMissing"),
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
) -> CanonicalResult<Result<(), PrivateVssRefusal>> {
    let rns_share_openings = match array_field(
        private_envelope,
        "rnsShareOpenings",
        "privateEnvelope.rnsShareOpenings",
        PrivateVssRefusalCode::missing("privateEnvelopeOpeningsMissing"),
        "privateEnvelope.rnsShareOpenings is required",
    ) {
        Ok(rns_share_openings) => rns_share_openings,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if rns_share_openings.len() != DATA_PRIMES.len() {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("privateEnvelopeRnsOpeningCountMismatch"),
            "privateEnvelope.rnsShareOpenings must contain one opening for every accepted Q_share limb",
            "privateEnvelope.rnsShareOpenings",
        )));
    }

    let mut seen_limbs = BTreeSet::new();
    let mut ring_degree: Option<usize> = None;
    for limb_opening in rns_share_openings {
        let verified_limb = match verify_private_envelope_limb(
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
        if !seen_limbs.insert(verified_limb.rns_limb_index) {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::equivocation("privateEnvelopeRnsOpeningDuplicate"),
                "privateEnvelope.rnsShareOpenings must have distinct rnsLimbIndex values",
                "privateEnvelope.rnsShareOpenings",
            )));
        }
        match ring_degree {
            Some(expected_ring_degree) if expected_ring_degree != verified_limb.ring_degree => {
                return Ok(Err(PrivateVssRefusal::new(
                    PrivateVssRefusalCode::wrong_type("privateEnvelopeRingDegreeMismatch"),
                    "all private VSS limb openings must use the same ring degree",
                    "privateEnvelope.rnsShareOpenings",
                )));
            }
            Some(_) => {}
            None => ring_degree = Some(verified_limb.ring_degree),
        }
    }

    Ok(Ok(()))
}

struct VerifiedLimb {
    rns_limb_index: usize,
    ring_degree: usize,
}

fn verify_private_envelope_limb(
    limb_opening: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    coefficient_commitments: &BTreeMap<(usize, u64), CoefficientCommitmentBinding>,
    envelope_binding: &PrivateEnvelopeBinding,
) -> CanonicalResult<Result<VerifiedLimb, PrivateVssRefusal>> {
    if limb_opening.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_LIMB_OPENING_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("privateVssLimbOpeningTypeMismatch"),
            "private VSS limb opening objectType must be PrivateVssShareLimbOpening",
            "privateEnvelope.rnsShareOpenings.objectType",
        )));
    }
    let rns_limb_index = match usize_field(
        limb_opening,
        "rnsLimbIndex",
        "privateEnvelope.rnsShareOpenings.rnsLimbIndex",
        PrivateVssRefusalCode::missing("privateVssLimbIndexMissing"),
        "private VSS limb opening must bind rnsLimbIndex",
    ) {
        Ok(rns_limb_index) => rns_limb_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if DATA_PRIMES.get(rns_limb_index).is_none() {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("privateVssRnsLimbIndexInvalid"),
            "private VSS limb opening rnsLimbIndex must select Q_share",
            "privateEnvelope.rnsShareOpenings.rnsLimbIndex",
        )));
    }

    let share_values = match u64_vector_field(
        limb_opening,
        "shareValues",
        "privateEnvelope.rnsShareOpenings.shareValues",
        PrivateVssRefusalCode::missing("privateVssShareValuesMissing"),
        "private VSS limb opening must include shareValues",
    ) {
        Ok(share_values) => share_values,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ring_degree = share_values.len();
    if ring_degree == 0 {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("privateVssShareValuesEmpty"),
            "private VSS share vector must be non-empty",
            "privateEnvelope.rnsShareOpenings.shareValues",
        )));
    }

    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    let mut coefficient_commitment_roots = Vec::with_capacity(roster.decryption_threshold as usize);
    let mut coefficient_commitment_values =
        Vec::with_capacity(roster.decryption_threshold as usize);
    for shamir_coefficient_index in 0..roster.decryption_threshold {
        let Some(commitment_root) = source_trustee_binding
            .coefficient_commitment_roots
            .get(&(rns_limb_index, shamir_coefficient_index))
            .cloned()
        else {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::missing("privateVssCoefficientCommitmentRootMissing"),
                "source trustee commitment record must include every coefficient root for the private VSS limb",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots",
            )));
        };
        let Some(material_binding) =
            coefficient_commitments.get(&(rns_limb_index, shamir_coefficient_index))
        else {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::missing("privateVssCoefficientCommitmentMaterialMissing"),
                "private VSS limb references coefficient commitment material that was not provided",
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        };
        if material_binding.commitment_root != commitment_root {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::wrong_hash(
                    "privateVssCoefficientCommitmentMaterialRootMismatch",
                ),
                "coefficient commitment material root must match the source trustee commitment record",
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        }
        coefficient_commitment_roots.push(commitment_root);
        coefficient_commitment_values.push(material_binding.commitment.clone());
    }

    let private_vss_share_proof_bytes_hash = match hash_string_field(
        limb_opening,
        "privateVssShareProofBytesHash",
        "privateEnvelope.rnsShareOpenings.privateVssShareProofBytesHash",
        PrivateVssRefusalCode::missing("privateVssShareProofBytesHashMissing"),
        "private VSS limb opening must include its recipient-local proof bytes hash",
    ) {
        Ok(private_vss_share_proof_bytes_hash) => private_vss_share_proof_bytes_hash,
        Err(refusal) => return Ok(Err(refusal)),
    };

    if let Err(error) = verify_private_vss_share_succinct_relation_proof(
        PrivateVssShareSuccinctProofVerificationInput {
            setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash: &envelope_binding.private_envelope_aad_hash,
            source_trustee_roster_position: source_trustee_binding.source_trustee_roster_position,
            recipient_roster_position: envelope_binding.recipient_roster_position,
            source_trustee_commitment_root: &source_trustee_binding.source_trustee_commitment_root,
            rns_limb_index,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            coefficient_commitments: &coefficient_commitment_values,
            proof_bytes_hash: private_vss_share_proof_bytes_hash,
        },
    ) {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::invalid_proof("privateVssShareProofVerificationFailed"),
            error.message,
            "privateEnvelope.rnsShareOpenings.privateVssShareProofBytesHash",
        )));
    }

    Ok(Ok(VerifiedLimb {
        rns_limb_index,
        ring_degree,
    }))
}
