use super::*;

#[derive(Clone, Copy)]
pub(super) struct StatementSetBinding<'a> {
    pub(super) setup_context_hash: &'a str,
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
    pub(super) coefficient_commitment_set: &'a Value,
    pub(super) statement_set: StatementSetBinding<'a>,
    pub(super) expected_position: usize,
    pub(super) q_share_rns_limb_count: usize,
    pub(super) threshold_degree: usize,
    pub(super) ring_degree: usize,
    pub(super) source_constant_commitment_values: &'a [Value],
}

pub(in crate::bgv::setup) struct AuthoritativeSameSecretBridgeTarget<'a> {
    pub(in crate::bgv::setup) rns_prime: u64,
    pub(in crate::bgv::setup) coefficient_commitment_root: &'a str,
    pub(in crate::bgv::setup) commitment_body: &'a Value,
}

pub(in crate::bgv::setup) fn authoritative_same_secret_bridge_targets<'a>(
    coefficient_commitment_set: &'a Value,
    trustee_identity: &str,
    expected_position: usize,
    q_share_rns_limb_count: usize,
    threshold_degree: usize,
    ring_degree: usize,
) -> CanonicalResult<Vec<AuthoritativeSameSecretBridgeTarget<'a>>> {
    let source_records = array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let source_record = source_records.get(expected_position).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "authoritative VSS coefficient commitments do not cover the bridge trustee",
        )
    })?;
    compare_required_string(
        string_at_path(source_record, &["objectType"])?,
        "VssPublicSourceCoefficientCommitments",
        "authoritative bridge target source record objectType",
    )?;
    compare_required_string(
        string_at_path(source_record, &["sourceTrusteeIdentity"])?,
        trustee_identity,
        "authoritative bridge target source trustee identity",
    )?;
    let coefficient_records = array_at_path(source_record, &["coefficientCommitments"])?;
    let expected_record_count = q_share_rns_limb_count
        .checked_mul(threshold_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "authoritative bridge target coordinate count overflowed",
            )
        })?;
    if coefficient_records.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "authoritative VSS coefficient commitments must cover every bridge target coordinate",
        ));
    }

    (0..q_share_rns_limb_count)
        .map(|rns_limb_index| {
            let record_index = rns_limb_index
                .checked_mul(threshold_degree)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "authoritative bridge target record index overflowed",
                    )
                })?;
            let record = coefficient_records.get(record_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "authoritative VSS coefficient commitment is missing for a bridge target limb",
                )
            })?;
            compare_required_string(
                string_at_path(record, &["objectType"])?,
                "VssPublicCoefficientCommitment",
                "authoritative bridge target commitment objectType",
            )?;
            let canonical_prime = DATA_PRIMES.get(rns_limb_index).copied().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "same-secret bridge qShareRnsLimbCount exceeds the available Q_share primes",
                )
            })?;
            let coefficient_commitment_root = hash_at_path(record, &["coefficientCommitmentRoot"])?;
            let commitment_body = value_at_path(record, &["commitment"])?;
            compare_required_string(
                string_at_path(commitment_body, &["objectType"])?,
                "VssCommittedMaterialCommitment",
                "authoritative bridge target commitment body objectType",
            )?;
            compare_required_string(
                string_at_path(commitment_body, &["commitmentRole"])?,
                "coefficient",
                "authoritative bridge target commitment role",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["rnsLimbIndex"])?,
                rns_limb_index as u64,
                "authoritative bridge target commitment body rnsLimbIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["rnsPrime"])?,
                canonical_prime,
                "authoritative bridge target commitment body rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["ringDegree"])?,
                ring_degree as u64,
                "authoritative bridge target commitment ringDegree",
            )?;
            compare_required_string(
                &derive_canonical_object_hash(commitment_body)?,
                coefficient_commitment_root,
                "authoritative bridge target commitment body root",
            )?;

            Ok(AuthoritativeSameSecretBridgeTarget {
                rns_prime: canonical_prime,
                coefficient_commitment_root,
                commitment_body,
            })
        })
        .collect()
}

pub(in crate::bgv::setup) fn same_secret_bridge_proof_verification_request_from_public_records(
    statement_set: &Value,
    bridge_statement: &Value,
    coefficient_commitment_set: &Value,
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
    let q_share_rns_limb_count = read_positive_usize_at_path(
        statement_set,
        &["qShareRnsLimbCount"],
        "same-secret bridge proof verification qShareRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement_set,
        &["thresholdDegree"],
        "same-secret bridge proof verification thresholdDegree",
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
            coefficient_commitment_set,
            statement_set: StatementSetBinding {
                setup_context_hash: hash_at_path(statement_set, &["setupContextHash"])?,
                public_matrix_seed_hash,
            },
            expected_position,
            q_share_rns_limb_count,
            threshold_degree,
            ring_degree,
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

    compare_required_u64(
        unsigned_at_path(input.bridge_statement, &["ringDegree"])?,
        input.ring_degree as u64,
        "same-secret bridge statement ringDegree",
    )?;
    let authoritative_targets = authoritative_same_secret_bridge_targets(
        input.coefficient_commitment_set,
        trustee_identity,
        input.expected_position,
        input.q_share_rns_limb_count,
        input.threshold_degree,
        input.ring_degree,
    )?;
    let bridge_rns_primes = authoritative_targets
        .iter()
        .map(|target| target.rns_prime)
        .collect::<Vec<_>>();
    let target_constant_commitment_roots = authoritative_targets
        .iter()
        .map(|target| target.coefficient_commitment_root.to_string())
        .collect::<Vec<_>>();
    let target_constant_commitments = authoritative_targets
        .iter()
        .map(|target| target.commitment_body.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "context": {
            "setupContextHash": input.statement_set.setup_context_hash,
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": input.expected_position,
        },
        "ringDegree": input.ring_degree,
        "sameSecretLinkage": {
            "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
            "commitments": input.source_constant_commitment_values,
        },
        "sameSecretBridge": {
            "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
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
) -> CanonicalResult<()> {
    super::trustee_evaluation_key_proof::verify_same_secret_bridge_proof_source_from_request(
        proof_verification_request,
        proof_bytes.as_ref(),
    )
}

pub(in crate::bgv::setup) fn same_secret_bridge_proof_verification_binding_hash(
    proof_material_root: &str,
    proof_verification_request: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretBridgeProofVerificationBinding",
        "proofMaterialRoot": proof_material_root,
        "verificationRequest": proof_verification_request,
    }))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_and_retain_same_secret_bridge_proof_binding(
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    proof_material_root: &str,
    proof_verification_request: &Value,
) -> CanonicalResult<()> {
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
    verify_reconstructed_same_secret_bridge_proof(proof_verification_request, &proof_bytes)?;
    drop(proof_bytes);
    crate::bgv::setup::retain_accepted_setup_proof_binding(
        proof_binding_session.session_handle,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        proof_material_root,
        same_secret_bridge_proof_verification_binding_hash(
            proof_material_root,
            proof_verification_request,
        )?,
    )?;

    Ok(())
}
