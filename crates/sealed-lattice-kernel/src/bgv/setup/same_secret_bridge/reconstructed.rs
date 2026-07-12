use super::*;

#[derive(Clone, Copy)]
pub(super) struct StatementSetBinding<'a> {
    pub(super) ceremony_id: &'a str,
    pub(super) manifest_hash: &'a str,
    pub(super) roster_hash: &'a str,
    pub(super) setup_parameters_hash: &'a str,
    pub(super) setup_epoch: &'a str,
    pub(super) target_basis_hash: &'a str,
    pub(super) public_matrix_seed_hash: &'a str,
}

pub(super) struct StatementRecordVerificationInput<'a> {
    pub(super) statement_record: &'a Value,
    pub(super) coefficient_commitment_set: &'a Value,
    pub(super) vss_coefficient_commitments: &'a Value,
    pub(super) expected_position: usize,
    pub(super) target_rns_limb_count: usize,
    pub(super) threshold_degree: usize,
    pub(super) ring_degree: usize,
    pub(super) statement_set: StatementSetBinding<'a>,
}

pub(super) struct ReconstructedSameSecretBridgeProofVerification<'a> {
    pub(super) bridge_statement: &'a Value,
    pub(super) statement_set: StatementSetBinding<'a>,
    pub(super) expected_position: usize,
    pub(super) proof_bytes: &'a SetupProofMaterialBytes,
    pub(super) source_constant_commitment_values: &'a [Value],
}

pub(super) fn verify_reconstructed_same_secret_bridge_proof(
    input: ReconstructedSameSecretBridgeProofVerification<'_>,
) -> CanonicalResult<()> {
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
    let mut target_rns_primes = Vec::with_capacity(bridge_target_constant_roots.len());
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
        let canonical_target_prime =
            DATA_PRIMES
                .get(target_rns_limb_index)
                .copied()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "same-secret bridge targetRnsLimbCount exceeds the available target primes",
                    )
                })?;
        compare_required_u64(
            target_rns_prime,
            canonical_target_prime,
            "same-secret bridge proof canonical target prime",
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
        target_rns_primes.push(target_rns_prime);
        target_constant_commitment_roots.push(coefficient_commitment_root.to_string());
        target_constant_commitments.push(target_commitment_body.clone());
    }

    let proof_verification_request = json!({
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
            "sourceTrusteeIdentity": trustee_identity,
            "sourceTrusteeRosterPosition": input.expected_position,
            "targetBasisHash": input.statement_set.target_basis_hash,
            "targetRnsPrimes": target_rns_primes,
            "targetConstantCommitmentRoots": target_constant_commitment_roots,
            "targetConstantCommitments": target_constant_commitments,
        },
    });
    let proof_verification =
        super::trustee_evaluation_key_proof::verify_same_secret_bridge_proof_source_from_request(
            &proof_verification_request,
            input.proof_bytes.as_ref(),
        )?;
    compare_required_string(
        string_at_path(&proof_verification, &["proofFamily"])?,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "reconstructed same-secret bridge proof verification proofFamily",
    )?;
    hash_at_path(&proof_verification, &["statementHash"])?;

    Ok(())
}
