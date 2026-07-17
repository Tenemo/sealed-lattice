use super::*;

use crate::hashing::derive_canonical_object_hash;

const VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE: &str = "VssSourceTrusteeCoefficientCommitments";

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
    pub(super) recipient_roster_position: u64,
}

pub(super) fn verify_setup_context(
    setup_context: &Value,
) -> CanonicalResult<Result<(), PrivateVssRefusal>> {
    for field_name in authoritative_setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::missing("setupContextFieldMissing"),
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
            PrivateVssRefusalCode::malformed("setupContextHashMalformed"),
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
        PrivateVssRefusalCode::missing("setupContextCeremonyMissing"),
        "setupContext.ceremonyId must be a non-empty string",
    )
    .is_err()
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::missing("setupContextCeremonyMissing"),
            "setupContext.ceremonyId must be a non-empty string",
            "setupContext.ceremonyId",
        )));
    }
    if string_field(
        setup_context,
        "setupEpoch",
        "setupContext.setupEpoch",
        PrivateVssRefusalCode::missing("setupContextEpochMissing"),
        "setupContext.setupEpoch must be a non-empty string",
    )
    .is_err()
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::missing("setupContextEpochMissing"),
            "setupContext.setupEpoch must be a non-empty string",
            "setupContext.setupEpoch",
        )));
    }

    // The setup parameters hash is a roster family, so it must match the hash
    // derived from this setup context's roster. It binds the thresholds,
    // Q_share, evaluator key schedule, and BGV parameters.
    let setup_parameters_roster =
        super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    if setup_context
        .get("setupParametersHash")
        .and_then(Value::as_str)
        != Some(
            super::accepted_setup::setup_parameters_hash_for_roster(&setup_parameters_roster)?
                .as_str(),
        )
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_hash("setupParametersHashMismatch"),
            "setupContext.setupParametersHash does not match the roster-derived collective BGV setup parameters",
            "setupContext.setupParametersHash",
        )));
    }

    Ok(Ok(()))
}

pub(super) fn verify_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    source_trustee_roster_position: u64,
) -> CanonicalResult<Result<SourceTrusteeCommitmentBinding, PrivateVssRefusal>> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some(VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("sourceTrusteeCommitmentRecordTypeMismatch"),
            "sourceTrusteeCoefficientCommitmentRecord.objectType must be VssSourceTrusteeCoefficientCommitments",
            "sourceTrusteeCoefficientCommitmentRecord.objectType",
        )));
    }
    let source_trustee_identity = match string_field(
        source_trustee_record,
        "sourceTrusteeIdentity",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeIdentity",
        PrivateVssRefusalCode::missing("sourceTrusteeIdentityMissing"),
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeIdentity is required",
    ) {
        Ok(source_trustee_identity) => source_trustee_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitment_root_values = match array_field(
        source_trustee_record,
        "coefficientCommitmentRoots",
        "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots",
        PrivateVssRefusalCode::missing("sourceTrusteeCoefficientCommitmentsMissing"),
        "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots is required",
    ) {
        Ok(coefficient_commitment_root_values) => coefficient_commitment_root_values,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    let expected_coefficient_count = DATA_PRIMES.len() * roster.decryption_threshold as usize;
    if coefficient_commitment_root_values.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("sourceTrusteeCoefficientCommitmentCountMismatch"),
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots must contain every Q_share limb and Shamir coefficient",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots",
        )));
    }

    let mut coefficient_commitment_roots = BTreeMap::new();
    let mut canonical_coefficient_commitment_roots =
        Vec::with_capacity(coefficient_commitment_root_values.len());
    let decryption_threshold = roster.decryption_threshold as usize;
    for (record_index, coefficient_root_value) in
        coefficient_commitment_root_values.iter().enumerate()
    {
        let rns_limb_index = record_index / decryption_threshold;
        let shamir_coefficient_index = (record_index % decryption_threshold) as u64;
        let Some(commitment_root) = coefficient_root_value.as_str() else {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::wrong_type(
                    "sourceTrusteeCoefficientCommitmentRootMalformed",
                ),
                "source trustee coefficient commitment roots must be protocol hashes",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots",
            )));
        };
        validate_hash_string(
            commitment_root,
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitmentRoots",
        )?;
        coefficient_commitment_roots.insert(
            (rns_limb_index, shamir_coefficient_index),
            commitment_root.to_string(),
        );
        canonical_coefficient_commitment_roots.push(commitment_root);
    }

    let source_trustee_commitment_root = derive_canonical_object_hash(&json!({
        "objectType": VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE,
        "sourceTrusteeIdentity": &source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "coefficientCommitmentRoots": canonical_coefficient_commitment_roots,
    }))?;

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
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<CoefficientCommitmentMaterialRecordsVerification> {
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context)?;
    let expected_coefficient_count = DATA_PRIMES.len() * roster.decryption_threshold as usize;
    if material_records.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("sourceTrusteeCommitmentMaterialCountMismatch"),
            "sourceTrusteeCoefficientCommitmentMaterialRecords must contain full public commitment material for every Q_share limb and Shamir coefficient",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
        )));
    }

    let mut bindings = BTreeMap::new();
    let decryption_threshold = roster.decryption_threshold as usize;
    for (record_index, material_record) in material_records.iter().enumerate() {
        let rns_limb_index = record_index / decryption_threshold;
        let shamir_coefficient_index = (record_index % decryption_threshold) as u64;
        let binding = match verify_coefficient_commitment_material_record(
            material_record,
            rns_limb_index,
            shamir_coefficient_index,
            source_trustee_binding,
        )? {
            Ok(binding) => binding,
            Err(refusal) => return Ok(Err(refusal)),
        };
        bindings.insert((rns_limb_index, shamir_coefficient_index), binding);
    }

    Ok(Ok(bindings))
}

fn verify_coefficient_commitment_material_record(
    commitment_value: &Value,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<Result<CoefficientCommitmentBinding, PrivateVssRefusal>> {
    let commitment = match parse_setup_commitment_full_value(commitment_value) {
        Ok(commitment) => commitment,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                PrivateVssRefusalCode::wrong_type("sourceTrusteeCommitmentMaterialInvalid"),
                error.message,
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        }
    };
    if commitment.source_rns_limb_index != rns_limb_index
        || commitment.shamir_coefficient_index != shamir_coefficient_index
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_type("sourceTrusteeCommitmentMaterialDomainMismatch"),
            "full setup commitment domain must match its canonical material position",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
        )));
    }
    let commitment_root = setup_commitment_root(&commitment)?;
    if source_trustee_binding
        .coefficient_commitment_roots
        .get(&(rns_limb_index, shamir_coefficient_index))
        .map(String::as_str)
        != Some(commitment_root.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_hash("sourceTrusteeCommitmentMaterialRootMismatch"),
            "full setup commitment material must match the source trustee coefficient commitment record",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
        )));
    }

    Ok(Ok(CoefficientCommitmentBinding {
        commitment_root,
        commitment,
    }))
}
