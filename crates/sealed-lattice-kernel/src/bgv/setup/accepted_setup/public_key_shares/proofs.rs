use super::common::*;

use super::succinct_proofs::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn verify_public_key_share_proofs(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(proof_set) = setup_package.get("publicKeyShareProofs") else {
        if public_key_share_proofs_have_terminal_dependents(setup_package) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofsMissing",
                "publicKeyShareProofs must be present before dependent public-key succinct proofs or terminal key material can be accepted",
                "setupPackage.publicKeyShareProofs",
            )?));
        }

        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !proof_set.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofsNotObject",
            "publicKeyShareProofs must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShareProofs",
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetTypeMismatch",
            "publicKeyShareProofs.objectType must be PublicKeyShareProofSet",
            "setupPackage.publicKeyShareProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetVersionMismatch",
            "publicKeyShareProofs.objectVersion must be 1",
            "setupPackage.publicKeyShareProofs.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share proof verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShareProofs",
        )?));
    }
    for (field_name, expected_value) in [("proofFamily", "public-key-share")] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofSetParametersMismatch",
                format!("publicKeyShareProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.{field_name}"),
            )?));
        }
    }
    let roster = super::accepted_roster_from_package(setup_package);
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofSetCountMismatch",
                format!("publicKeyShareProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.{field_name}"),
            )?));
        }
    }

    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) = verify_public_key_common_fields(
        proof_set,
        &common_binding,
        "publicKeyShareProofs",
        PublicKeyRefusalKind::Proof,
    )? {
        return Ok(Some(response));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if proof_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSameSecretRootMismatch",
            "publicKeyShareProofs.sameSecretConsistencyRoot must match accepted same-secret statements",
            "setupPackage.publicKeyShareProofs.sameSecretConsistencyRoot",
        )?));
    }
    let public_key_share_set_root = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSetRoot was required before public-key share proof verification",
            )
        })?;
    if proof_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
        != Some(public_key_share_set_root)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofShareSetRootMismatch",
            "publicKeyShareProofs.publicKeyShareSetRoot must match publicKeyShares",
            "setupPackage.publicKeyShareProofs.publicKeyShareSetRoot",
        )?));
    }

    let share_bindings = public_key_share_bindings_from_package(setup_package)?;
    let same_secret_bindings = same_secret_statement_bindings_from_package(setup_package)?;
    let Some(proof_records) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRecordsMissing",
            "publicKeyShareProofs.proofRecords must be present on the accepted proof set",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    };
    if proof_records.len() != roster.participant_count as usize {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofCountMismatch",
            "publicKeyShareProofs.proofRecords must contain one proof statement per trustee",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    for proof_record in proof_records {
        if let Some(response) = verify_public_key_share_proof_record(
            proof_record,
            setup_context,
            &share_bindings,
            &same_secret_bindings,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(public_key_share_proof_set_root) = proof_set
        .get("publicKeyShareProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetRootMissing",
            "publicKeyShareProofs.publicKeyShareProofSetRoot must be present on the accepted proof set",
            "setupPackage.publicKeyShareProofs.publicKeyShareProofSetRoot",
        )?));
    };
    validate_hash_string(
        public_key_share_proof_set_root,
        "publicKeyShareProofs.publicKeyShareProofSetRoot",
    )?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share proof set object was checked")
        .remove("publicKeyShareProofSetRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if public_key_share_proof_set_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetRootMismatch",
            "publicKeyShareProofSetRoot does not match the canonical public-key share proof set",
            "setupPackage.publicKeyShareProofs.publicKeyShareProofSetRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_proof_record(
    proof_record: &Value,
    setup_context: &Value,
    share_bindings: &BTreeMap<u64, PublicKeyShareBinding>,
    same_secret_bindings: &BTreeMap<u64, SameSecretStatementBinding>,
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !proof_record.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofNotObject",
            "public-key share proof records must be objects",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_PROOF_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofTypeMismatch",
            "public-key share proof objectType must be PublicKeyShareProof",
            "setupPackage.publicKeyShareProofs.proofRecords.objectType",
        )?));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofVersionMismatch",
            "public-key share proof objectVersion must be 1",
            "setupPackage.publicKeyShareProofs.proofRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(proof_record, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofContextMismatch",
            error.message,
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    for (field_name, expected_value) in [("proofFamily", "public-key-share")] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofParametersMismatch",
                format!("public-key share proof {field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.proofRecords.{field_name}"),
            )?));
        }
    }
    if proof_record.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRnsLimbCountMismatch",
            "public-key share proof rnsLimbCount must match Q_share",
            "setupPackage.publicKeyShareProofs.proofRecords.rnsLimbCount",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        proof_record,
        common_binding,
        "publicKeyShareProofs.proofRecords",
        PublicKeyRefusalKind::Proof,
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(proof_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofDuplicate",
            "public-key share proof records must have distinct trustee roster positions",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    let Some(share_binding) = share_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofShareMissing",
            "public-key share proof must reference an accepted public-key share",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeRosterPosition",
        )?));
    };
    let Some(same_secret_binding) = same_secret_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSameSecretMissing",
            "public-key share proof must reference an accepted same-secret statement",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeRosterPosition",
        )?));
    };
    if share_binding.trustee_roster_position != trustee_roster_position
        || share_binding.trustee_identity != trustee_identity
        || same_secret_binding.trustee_identity != trustee_identity
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofTrusteeMismatch",
            "public-key share proof trustee must match the accepted share and same-secret statement",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeIdentity",
        )?));
    }
    if proof_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
        != Some(share_binding.public_key_share_root.as_str())
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.trustee_secret_commitment_root.as_str())
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(share_binding.trustee_secret_commitment_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.same_secret_statement_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(share_binding.same_secret_statement_root.as_str())
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofBindingMismatch",
            "public-key share proof must bind the accepted share, trustee secret, and same-secret roots",
            "setupPackage.publicKeyShareProofs.proofRecords.publicKeyShareRoot",
        )?));
    }

    let Some(public_key_share_proof_root) = proof_record
        .get("publicKeyShareProofRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.proofRecords.publicKeyShareProofRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_proof_root,
        "publicKeyShareProofs.proofRecords.publicKeyShareProofRoot",
    )?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share proof object was checked")
        .remove("publicKeyShareProofRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if public_key_share_proof_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRootMismatch",
            "publicKeyShareProofRoot does not match the canonical public-key share proof statement",
            "setupPackage.publicKeyShareProofs.proofRecords.publicKeyShareProofRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_public_key_share_limb_hashes(
    limb_values: Option<&Vec<Value>>,
) -> CanonicalResult<Option<Value>> {
    let Some(limb_values) = limb_values else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if limb_values.len() != DATA_PRIMES.len() {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareCoefficientLimbCountMismatch",
            "public-key share must bind one coefficient hash for every Q_share limb",
            "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb",
        )?));
    }
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let limb_value = &limb_values[rns_limb_index];
        if limb_value.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || limb_value.get("rnsPrime").and_then(Value::as_u64) != Some(rns_prime)
            || limb_value.get("component").and_then(Value::as_str) != Some("b_i")
        {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareCoefficientLimbMismatch",
                "public-key share coefficient hash entries must follow Q_share order",
                "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb",
            )?));
        }
        let Some(hash) = limb_value
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
        else {
            return Ok(Some(verification_response(
                Some("publicKeyShareProofs"),
                vec![
                    "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb.coefficientVectorHash512"
                        .to_string(),
                ],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb.coefficientVectorHash512",
        )?;
    }

    Ok(None)
}

fn public_key_share_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareBinding>> {
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records were required before public-key share proof verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for share_record in share_records {
        let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
        if bindings
            .insert(
                trustee_roster_position,
                PublicKeyShareBinding {
                    trustee_identity: value_string(share_record, "trusteeIdentity")?.to_string(),
                    trustee_roster_position,
                    public_key_share_root: value_string(share_record, "publicKeyShareRoot")?
                        .to_string(),
                    trustee_secret_commitment_root: value_string(
                        share_record,
                        "trusteeSecretCommitmentRoot",
                    )?
                    .to_string(),
                    same_secret_statement_root: value_string(
                        share_record,
                        "sameSecretStatementRoot",
                    )?
                    .to_string(),
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public-key share records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}
