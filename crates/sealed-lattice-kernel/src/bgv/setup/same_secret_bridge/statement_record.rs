use super::reconstructed::*;
use super::*;

pub(super) fn verify_statement_record(
    input: StatementRecordVerificationInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.statement_record, &["objectType"])?,
        "VssSameSecretBridgeStatement",
        "VSS same-secret bridge statement objectType",
    )?;
    compare_setup_context(input.statement_record, input.statement_set)?;
    compare_required_string(
        hash_at_path(input.statement_record, &["publicMatrixSeedHash"])?,
        input.statement_set.public_matrix_seed_hash,
        "VSS same-secret bridge statement publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["ringDegree"])?,
        input.ring_degree as u64,
        "VSS same-secret bridge statement ringDegree",
    )?;

    let trustee_identity = read_non_empty_string(input.statement_record, "trusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["trusteeRosterPosition"])?,
        input.expected_position as u64,
        "VSS same-secret bridge statement trusteeRosterPosition",
    )?;
    let source_constant_commitments = super::super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
        input.vss_coefficient_commitments,
        input.statement_record,
        trustee_identity,
        input.expected_position as u64,
        input.statement_set.public_matrix_seed_hash,
        input.ring_degree,
    )?;
    let verified_source_constant_commitments = source_constant_commitments
        .commitment_values
        .iter()
        .enumerate()
        .map(|(source_rns_limb_index, commitment)| {
            json!({
                "rnsLimbIndex": source_rns_limb_index,
                "rnsPrime": DATA_PRIMES[source_rns_limb_index],
                "commitment": commitment,
            })
        })
        .collect::<Vec<_>>();
    authoritative_same_secret_bridge_targets(
        input.coefficient_commitment_set,
        trustee_identity,
        input.expected_position,
        input.q_share_rns_limb_count,
        input.threshold_degree,
        input.ring_degree,
    )?;

    let expected_statement_root = derive_canonical_object_hash(&json!({
        "objectType": "VssSameSecretBridgeStatement",
        "setupContextHash": input.statement_set.setup_context_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sourceConstantCoefficientCommitments": verified_source_constant_commitments,
    }))?;
    let statement_root = hash_at_path(input.statement_record, &["sameSecretBridgeStatementRoot"])?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "VSS same-secret bridge statement root does not match its bound roots: expected {expected_statement_root}, got {statement_root}",
            ),
        ));
    }

    Ok(json!({
        "objectType": "VssSameSecretBridgeStatement",
        "setupContextHash": input.statement_set.setup_context_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sourceConstantCoefficientCommitments": verified_source_constant_commitments,
        "sameSecretBridgeStatementRoot": statement_root,
    }))
}

pub(super) fn compare_setup_context(
    statement_record: &Value,
    statement_set: StatementSetBinding<'_>,
) -> CanonicalResult<()> {
    compare_required_string(
        hash_at_path(statement_record, &["setupContextHash"])?,
        statement_set.setup_context_hash,
        "VSS same-secret bridge statement setup context",
    )
}
