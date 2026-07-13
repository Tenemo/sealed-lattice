use super::*;

#[derive(Clone, Copy)]
pub(super) struct StatementSetBinding<'a> {
    pub(super) ceremony_id: &'a str,
    pub(super) manifest_hash: &'a str,
    pub(super) roster_hash: &'a str,
    pub(super) setup_parameters_hash: &'a str,
    pub(super) setup_epoch: &'a str,
    pub(super) public_matrix_seed_hash: &'a str,
}

pub(super) struct StatementRecordVerificationInput<'a> {
    pub(super) statement_record: &'a Value,
    pub(super) coefficient_commitment_set: &'a Value,
    pub(super) vss_coefficient_commitments: &'a Value,
    pub(super) expected_position: usize,
    pub(super) q_share_rns_limb_count: usize,
    pub(super) threshold_degree: usize,
    pub(super) ring_degree: usize,
    pub(super) statement_set: StatementSetBinding<'a>,
}

pub(super) struct ReconstructedSameSecretBridgeProofVerification<'a> {
    pub(super) bridge_statement: &'a Value,
    pub(super) statement_set: StatementSetBinding<'a>,
    pub(super) expected_position: usize,
    pub(super) source_constant_commitment_values: &'a [Value],
}

pub(in crate::bgv::setup) fn same_secret_bridge_proof_verification_request_from_public_records(
    statement_set: &Value,
    bridge_statement: &Value,
    vss_coefficient_commitments: &Value,
    expected_position: usize,
) -> CanonicalResult<Value> {
    let trustee_identity = string_at_path(bridge_statement, &["trusteeIdentity"])?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement_set,
        &["ringDegree"],
        "same-secret bridge proof verification ringDegree",
    )?;
    let source_constant_commitments =
        super::super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
            vss_coefficient_commitments,
            bridge_statement,
            trustee_identity,
            expected_position as u64,
            public_matrix_seed_hash,
            ring_degree,
        )?;

    reconstructed_same_secret_bridge_proof_verification_request(
        ReconstructedSameSecretBridgeProofVerification {
            bridge_statement,
            statement_set: StatementSetBinding {
                ceremony_id: read_non_empty_string(statement_set, "ceremonyId")?,
                manifest_hash: hash_at_path(statement_set, &["manifestHash"])?,
                roster_hash: hash_at_path(statement_set, &["rosterHash"])?,
                setup_parameters_hash: hash_at_path(statement_set, &["setupParametersHash"])?,
                setup_epoch: read_non_empty_string(statement_set, "setupEpoch")?,
                public_matrix_seed_hash,
            },
            expected_position,
            source_constant_commitment_values: &source_constant_commitments.commitment_values,
        },
    )
}

pub(super) fn reconstructed_same_secret_bridge_proof_verification_request(
    input: ReconstructedSameSecretBridgeProofVerification<'_>,
) -> CanonicalResult<Value> {
    let trustee_identity = string_at_path(input.bridge_statement, &["trusteeIdentity"])?;
    compare_required_u64(
        unsigned_at_path(input.bridge_statement, &["trusteeRosterPosition"])?,
        input.expected_position as u64,
        "same-secret bridge statement trusteeRosterPosition",
    )?;

    let bridge_target_constant_roots = array_at_path(
        input.bridge_statement,
        &["targetConstantCoefficientCommitmentRoots"],
    )?;
    let bridge_target_constant_commitments = array_at_path(
        input.bridge_statement,
        &["targetConstantCoefficientCommitments"],
    )?;
    if bridge_target_constant_commitments.len() != bridge_target_constant_roots.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge proof target commitments must match the bridge statement target roots",
        ));
    }
    let mut bridge_rns_primes = Vec::with_capacity(bridge_target_constant_roots.len());
    let mut target_constant_commitment_roots =
        Vec::with_capacity(bridge_target_constant_roots.len());
    let mut target_constant_commitments = Vec::with_capacity(bridge_target_constant_roots.len());
    for (target_rns_limb_index, bridge_target_root) in
        bridge_target_constant_roots.iter().enumerate()
    {
        let bridge_target_commitment = bridge_target_constant_commitments
            .get(target_rns_limb_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "same-secret bridge proof target commitment is missing",
                )
            })?;
        compare_required_u64(
            unsigned_at_path(bridge_target_root, &["rnsLimbIndex"])?,
            target_rns_limb_index as u64,
            "same-secret bridge target root rnsLimbIndex",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_target_commitment, &["rnsLimbIndex"])?,
            target_rns_limb_index as u64,
            "same-secret bridge target commitment rnsLimbIndex",
        )?;
        let target_rns_prime = unsigned_at_path(bridge_target_root, &["rnsPrime"])?;
        compare_required_u64(
            target_rns_prime,
            unsigned_at_path(bridge_target_commitment, &["rnsPrime"])?,
            "same-secret bridge target commitment rnsPrime",
        )?;
        let canonical_target_prime = DATA_PRIMES.get(target_rns_limb_index).copied().ok_or_else(
            || {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "same-secret bridge qShareRnsLimbCount exceeds the available Q_share primes",
                )
            },
        )?;
        compare_required_u64(
            target_rns_prime,
            canonical_target_prime,
            "same-secret bridge proof canonical Q_share prime",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_target_root, &["shamirCoefficientIndex"])?,
            0,
            "same-secret bridge target root shamirCoefficientIndex",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_target_commitment, &["shamirCoefficientIndex"])?,
            0,
            "same-secret bridge target commitment shamirCoefficientIndex",
        )?;
        let coefficient_commitment_root =
            hash_at_path(bridge_target_root, &["coefficientCommitmentRoot"])?;
        let target_commitment_body = value_at_path(bridge_target_commitment, &["commitment"])?;
        compare_required_string(
            &derive_canonical_object_hash(target_commitment_body)?,
            coefficient_commitment_root,
            "same-secret bridge target commitment body root",
        )?;
        bridge_rns_primes.push(target_rns_prime);
        target_constant_commitment_roots.push(coefficient_commitment_root.to_string());
        target_constant_commitments.push(target_commitment_body.clone());
    }

    Ok(json!({
        "context": {
            "ceremonyId": input.statement_set.ceremony_id,
            "manifestHash": input.statement_set.manifest_hash,
            "rosterHash": input.statement_set.roster_hash,
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": input.expected_position,
            "setupEpoch": input.statement_set.setup_epoch,
        },
        "ringDegree": unsigned_at_path(input.bridge_statement, &["ringDegree"])?,
        "sameSecretLinkage": {
            "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
            "commitments": input.source_constant_commitment_values,
        },
        "sameSecretBridge": {
            "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
            "setupParametersHash": input.statement_set.setup_parameters_hash,
            "sourceTrusteeIdentity": trustee_identity,
            "sourceTrusteeRosterPosition": input.expected_position,
            "bridgeRnsPrimes": bridge_rns_primes,
            "targetConstantCommitmentRoots": target_constant_commitment_roots,
            "targetConstantCommitments": target_constant_commitments,
        },
    }))
}

pub(super) fn verify_reconstructed_same_secret_bridge_proof(
    proof_verification_request: &Value,
    proof_bytes: &SetupProofMaterialBytes,
) -> CanonicalResult<Value> {
    let proof_verification =
        super::trustee_evaluation_key_proof::verify_same_secret_bridge_proof_source_from_request(
            proof_verification_request,
            proof_bytes.as_ref(),
        )?;
    compare_required_string(
        string_at_path(&proof_verification, &["proofFamily"])?,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "reconstructed same-secret bridge proof verification proofFamily",
    )?;
    hash_at_path(&proof_verification, &["statementHash"])?;

    Ok(proof_verification)
}

pub(in crate::bgv::setup) fn same_secret_bridge_proof_verification_binding_hash(
    proof_material_root: &str,
    proof_verification_request: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretBridgeProofVerificationBinding",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "proofMaterialRoot": proof_material_root,
        "verificationRequest": proof_verification_request,
    }))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_and_retain_same_secret_bridge_proof_binding(
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    proof_material_root: &str,
    proof_verification_request: &Value,
) -> CanonicalResult<Value> {
    let proof_bytes = crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        proof_material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "same-secret bridge proof binding requires authenticated proof bytes",
        )
    })?;
    let proof_bytes_hash = proof_bytes.hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_required_string(
        proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "same-secret bridge proof material root",
    )?;
    let verification =
        verify_reconstructed_same_secret_bridge_proof(proof_verification_request, &proof_bytes)?;
    drop(proof_bytes);
    crate::bgv::setup::retain_accepted_setup_proof_binding(
        proof_binding_session.session_handle,
        &proof_binding_session.capability,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        proof_material_root,
        same_secret_bridge_proof_verification_binding_hash(
            proof_material_root,
            proof_verification_request,
        )?,
    )?;

    Ok(verification)
}
