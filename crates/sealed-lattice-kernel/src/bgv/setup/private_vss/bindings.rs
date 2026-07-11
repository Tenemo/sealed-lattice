use super::*;

use crate::hashing::derive_canonical_object_hash;

const VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE: &str = "VssSourceTrusteeCoefficientCommitments";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE: &str = "VssCoefficientCommitmentMaterial";

pub(super) struct SourceTrusteeCommitmentBinding {
    pub(super) source_trustee_identity: String,
    pub(super) source_trustee_roster_position: u64,
    pub(super) source_trustee_commitment_root: String,
    pub(super) coefficient_commitment_roots: BTreeMap<(usize, u64), String>,
}

pub(super) struct CoefficientCommitmentBinding {
    pub(super) commitment_root: String,
    pub(super) commitment: SetupCommitmentValue,
}

pub(super) type CoefficientCommitmentCoordinate = (usize, u64);
pub(super) type CoefficientCommitmentBindingsByCoordinate =
    BTreeMap<CoefficientCommitmentCoordinate, CoefficientCommitmentBinding>;
pub(super) type CoefficientCommitmentMaterialRecordsVerification =
    Result<CoefficientCommitmentBindingsByCoordinate, PrivateVssRefusal>;

pub(super) struct PrivateEnvelopeBinding {
    pub(super) private_envelope_hash: String,
    pub(super) private_envelope_aad_hash: String,
    pub(super) recipient_identity: String,
    pub(super) recipient_roster_position: u64,
}

pub(super) struct LimbVerification {
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) ring_degree: usize,
    pub(super) coefficient_commitment_roots: Vec<String>,
    pub(super) share_values_hash: String,
    pub(super) private_vss_share_proof_hash: String,
    pub(super) proof_statement_root: String,
    pub(super) limb_verification_root: String,
}

pub(super) fn verify_setup_context(
    setup_context: &Value,
) -> CanonicalResult<Result<(), PrivateVssRefusal>> {
    for field_name in setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Ok(Err(PrivateVssRefusal::new(
                "setupContextFieldMissing",
                format!("setupContext.{field_name} is required"),
                format!("setupContext.{field_name}"),
            )));
        }
    }
    for field_name in ["manifestHash", "rosterHash", "setupParametersHash"] {
        let hash = match hash_string_field(
            setup_context,
            field_name,
            &format!("setupContext.{field_name}"),
            "setupContextHashMalformed",
            format!("setupContext.{field_name} must be a protocol hash"),
        ) {
            Ok(hash) => hash,
            Err(refusal) => return Ok(Err(refusal)),
        };
        validate_hash_string(hash, &format!("setupContext.{field_name}"))?;
    }
    if string_field(
        setup_context,
        "ceremonyId",
        "setupContext.ceremonyId",
        "setupContextCeremonyMissing",
        "setupContext.ceremonyId must be a non-empty string",
    )
    .is_err()
    {
        return Ok(Err(PrivateVssRefusal::new(
            "setupContextCeremonyMissing",
            "setupContext.ceremonyId must be a non-empty string",
            "setupContext.ceremonyId",
        )));
    }
    if string_field(
        setup_context,
        "setupEpoch",
        "setupContext.setupEpoch",
        "setupContextEpochMissing",
        "setupContext.setupEpoch must be a non-empty string",
    )
    .is_err()
    {
        return Ok(Err(PrivateVssRefusal::new(
            "setupContextEpochMissing",
            "setupContext.setupEpoch must be a non-empty string",
            "setupContext.setupEpoch",
        )));
    }

    // The setup parameters hash is a roster family, so it must match the hash
    // derived from this setup context's roster. It binds Q_share, the
    // carry-aware VSS relation, commitment, and BGV parameters.
    let setup_parameters_roster =
        super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    if setup_context
        .get("setupParametersHash")
        .and_then(Value::as_str)
        != Some(
            super::accepted_setup::setup_parameters_hash_for_roster(&setup_parameters_roster)?
                .as_str(),
        )
    {
        return Ok(Err(PrivateVssRefusal::new(
            "setupParametersHashMismatch",
            "setupContext.setupParametersHash does not match the roster-derived CollectiveBgvSetup-v1 setup parameters",
            "setupContext.setupParametersHash",
        )));
    }

    Ok(Ok(()))
}

pub(super) fn verify_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Result<SourceTrusteeCommitmentBinding, PrivateVssRefusal>> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some(VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentRecordTypeMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.objectType must be VssSourceTrusteeCoefficientCommitments",
            "sourceTrusteeCoefficientCommitmentRecord.objectType",
        )));
    }
    if let Err(refusal) = compare_context_fields(
        source_trustee_record,
        setup_context,
        "sourceTrusteeCoefficientCommitmentRecord",
    ) {
        return Ok(Err(refusal));
    }
    if source_trustee_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentPublicMatrixSeedMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.publicMatrixSeedHash must match publicMatrixSeedHash",
            "sourceTrusteeCoefficientCommitmentRecord.publicMatrixSeedHash",
        )));
    }
    let source_trustee_identity = match string_field(
        source_trustee_record,
        "sourceTrusteeIdentity",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeIdentity",
        "sourceTrusteeIdentityMissing",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeIdentity is required",
    ) {
        Ok(source_trustee_identity) => source_trustee_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_roster_position = match u64_field(
        source_trustee_record,
        "sourceTrusteeRosterPosition",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeRosterPosition",
        "sourceTrusteeRosterPositionMissing",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeRosterPosition is required",
    ) {
        Ok(source_trustee_roster_position) => source_trustee_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match array_field(
        source_trustee_record,
        "coefficientCommitments",
        "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments",
        "sourceTrusteeCoefficientCommitmentsMissing",
        "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments is required",
    ) {
        Ok(coefficient_commitments) => coefficient_commitments,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    let expected_coefficient_count = DATA_PRIMES.len() * roster.decryption_threshold as usize;
    if coefficient_commitments.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCoefficientCommitmentCountMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments must contain every Q_share limb and Shamir coefficient",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments",
        )));
    }

    let mut seen_coordinates = BTreeSet::new();
    let mut coefficient_commitment_roots = BTreeMap::new();
    for coefficient_record in coefficient_commitments {
        let rns_limb_index = match usize_field(
            coefficient_record,
            "rnsLimbIndex",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.rnsLimbIndex",
            "sourceTrusteeCoefficientRnsLimbMissing",
            "source trustee coefficient commitment must bind rnsLimbIndex",
        ) {
            Ok(rns_limb_index) => rns_limb_index,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let rns_prime = match u64_field(
            coefficient_record,
            "rnsPrime",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.rnsPrime",
            "sourceTrusteeCoefficientRnsPrimeMissing",
            "source trustee coefficient commitment must bind rnsPrime",
        ) {
            Ok(rns_prime) => rns_prime,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCoefficientRnsPrimeMismatch",
                "source trustee coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.rnsPrime",
            )));
        }
        let shamir_coefficient_index = match u64_field(
            coefficient_record,
            "shamirCoefficientIndex",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.shamirCoefficientIndex",
            "sourceTrusteeCoefficientShamirIndexMissing",
            "source trustee coefficient commitment must bind shamirCoefficientIndex",
        ) {
            Ok(shamir_coefficient_index) => shamir_coefficient_index,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if shamir_coefficient_index >= roster.decryption_threshold {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCoefficientShamirIndexInvalid",
                "source trustee coefficient commitment shamirCoefficientIndex is outside the accepted threshold degree",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.shamirCoefficientIndex",
            )));
        }
        if !seen_coordinates.insert((rns_limb_index, shamir_coefficient_index)) {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCoefficientCommitmentDuplicate",
                "source trustee coefficient commitments must have distinct limb/coefficient coordinates",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments",
            )));
        }
        let commitment_root = match hash_string_field(
            coefficient_record,
            "commitmentRoot",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.commitmentRoot",
            "sourceTrusteeCoefficientCommitmentRootMissing",
            "source trustee coefficient commitment must bind commitmentRoot",
        ) {
            Ok(commitment_root) => commitment_root.to_string(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        coefficient_commitment_roots
            .insert((rns_limb_index, shamir_coefficient_index), commitment_root);
    }

    let source_trustee_commitment_root = match hash_string_field(
        source_trustee_record,
        "sourceTrusteeCommitmentRoot",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot",
        "sourceTrusteeCommitmentRootMissing",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot is required",
    ) {
        Ok(source_trustee_commitment_root) => source_trustee_commitment_root.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut root_input = source_trustee_record.clone();
    root_input
        .as_object_mut()
        .expect("source trustee commitment record object was checked")
        .remove("sourceTrusteeCommitmentRoot");
    let expected_source_trustee_commitment_root = derive_canonical_object_hash(&root_input)?;
    if source_trustee_commitment_root != expected_source_trustee_commitment_root {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentRootMismatch",
            "sourceTrusteeCommitmentRoot does not match the canonical source trustee coefficient commitment record",
            "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot",
        )));
    }

    Ok(Ok(SourceTrusteeCommitmentBinding {
        source_trustee_identity,
        source_trustee_roster_position,
        source_trustee_commitment_root,
        coefficient_commitment_roots,
    }))
}

pub(super) fn verify_coefficient_commitment_material_records(
    material_records: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<CoefficientCommitmentMaterialRecordsVerification> {
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    let expected_coefficient_count = DATA_PRIMES.len() * roster.decryption_threshold as usize;
    if material_records.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialCountMismatch",
            "sourceTrusteeCoefficientCommitmentMaterialRecords must contain full public commitment material for every Q_share limb and Shamir coefficient",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
        )));
    }

    let mut bindings = BTreeMap::new();
    for material_record in material_records {
        let binding = match verify_coefficient_commitment_material_record(
            material_record,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_binding,
        )? {
            Ok(binding) => binding,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let coordinate = (
            binding.commitment.source_rns_limb_index,
            binding.commitment.shamir_coefficient_index,
        );
        if bindings.insert(coordinate, binding).is_some() {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCommitmentMaterialDuplicate",
                "sourceTrusteeCoefficientCommitmentMaterialRecords must have distinct limb/coefficient coordinates",
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        }
    }

    for rns_limb_index in 0..DATA_PRIMES.len() {
        for shamir_coefficient_index in 0..roster.decryption_threshold {
            if !bindings.contains_key(&(rns_limb_index, shamir_coefficient_index)) {
                return Ok(Err(PrivateVssRefusal::new(
                    "sourceTrusteeCommitmentMaterialCoverageMismatch",
                    "sourceTrusteeCoefficientCommitmentMaterialRecords must cover every Q_share limb and Shamir coefficient",
                    "sourceTrusteeCoefficientCommitmentMaterialRecords",
                )));
            }
        }
    }

    Ok(Ok(bindings))
}

fn verify_coefficient_commitment_material_record(
    material_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<Result<CoefficientCommitmentBinding, PrivateVssRefusal>> {
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialTypeMismatch",
            "coefficient commitment material objectType must be VssCoefficientCommitmentMaterial",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.objectType",
        )));
    }
    if let Err(refusal) = compare_context_fields(
        material_record,
        setup_context,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
    ) {
        return Ok(Err(refusal));
    }
    if material_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialPublicMatrixSeedMismatch",
            "coefficient commitment material publicMatrixSeedHash must match publicMatrixSeedHash",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.publicMatrixSeedHash",
        )));
    }
    if material_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
        != Some(source_trustee_binding.source_trustee_identity.as_str())
        || material_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            != Some(source_trustee_binding.source_trustee_roster_position)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialSourceTrusteeMismatch",
            "coefficient commitment material source trustee binding must match sourceTrusteeCoefficientCommitmentRecord",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.sourceTrusteeIdentity",
        )));
    }

    let rns_limb_index = match usize_field(
        material_record,
        "rnsLimbIndex",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.rnsLimbIndex",
        "sourceTrusteeCommitmentMaterialRnsLimbMissing",
        "coefficient commitment material must bind rnsLimbIndex",
    ) {
        Ok(rns_limb_index) => rns_limb_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let rns_prime = match u64_field(
        material_record,
        "rnsPrime",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.rnsPrime",
        "sourceTrusteeCommitmentMaterialRnsPrimeMissing",
        "coefficient commitment material must bind rnsPrime",
    ) {
        Ok(rns_prime) => rns_prime,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialRnsPrimeMismatch",
            "coefficient commitment material rnsPrime must match Q_share at rnsLimbIndex",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.rnsPrime",
        )));
    }
    let shamir_coefficient_index = match u64_field(
        material_record,
        "shamirCoefficientIndex",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.shamirCoefficientIndex",
        "sourceTrusteeCommitmentMaterialShamirIndexMissing",
        "coefficient commitment material must bind shamirCoefficientIndex",
    ) {
        Ok(shamir_coefficient_index) => shamir_coefficient_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    if shamir_coefficient_index >= roster.decryption_threshold {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialShamirIndexInvalid",
            "coefficient commitment material shamirCoefficientIndex is outside the accepted threshold degree",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.shamirCoefficientIndex",
        )));
    }
    let commitment_root = match hash_string_field(
        material_record,
        "commitmentRoot",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.commitmentRoot",
        "sourceTrusteeCommitmentMaterialRootMissing",
        "coefficient commitment material must bind commitmentRoot",
    ) {
        Ok(commitment_root) => commitment_root.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    if source_trustee_binding
        .coefficient_commitment_roots
        .get(&(rns_limb_index, shamir_coefficient_index))
        .map(String::as_str)
        != Some(commitment_root.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialRootMismatch",
            "coefficient commitment material root must match the source trustee coefficient commitment record",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.commitmentRoot",
        )));
    }
    let commitment_value = match object_field(
        material_record,
        "commitment",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
        "sourceTrusteeCommitmentMaterialCommitmentMissing",
        "coefficient commitment material must include the full public commitment",
    ) {
        Ok(commitment_value) => commitment_value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let commitment = match parse_setup_commitment_full_value(commitment_value) {
        Ok(commitment) => commitment,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCommitmentMaterialInvalid",
                error.message,
                "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
            )));
        }
    };
    if commitment.source_rns_limb_index != rns_limb_index
        || commitment.source_message_modulus != rns_prime
        || commitment.shamir_coefficient_index != shamir_coefficient_index
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialDomainMismatch",
            "full setup commitment domain must match its material wrapper",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
        )));
    }
    let computed_commitment_root = setup_commitment_root(&commitment)?;
    if commitment_root != computed_commitment_root {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialRootMismatch",
            "full setup commitment material does not match commitmentRoot",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
        )));
    }

    Ok(Ok(CoefficientCommitmentBinding {
        commitment_root,
        commitment,
    }))
}
