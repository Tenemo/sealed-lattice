use super::reconstructed::*;
use super::*;

pub(super) fn verify_statement_record(
    input: StatementRecordVerificationInput<'_>,
) -> CanonicalResult<()> {
    compare_required_string(
        string_at_path(input.statement_record, &["objectType"])?,
        "VssSameSecretBridgeStatement",
        "VSS same-secret bridge statement objectType",
    )?;
    let source_records =
        array_at_path(input.coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let source_record = source_records.get(input.expected_position).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitment set is missing the bridge source",
        )
    })?;
    let trustee_identity = string_at_path(source_record, &["sourceTrusteeIdentity"])?;
    super::super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
        input.vss_coefficient_commitments,
        input.statement_record,
        trustee_identity,
        input.expected_position as u64,
        input.statement_set.public_matrix_seed_hash,
        input.ring_degree,
    )?;
    authoritative_same_secret_bridge_targets(
        input.coefficient_commitment_set,
        trustee_identity,
        input.expected_position,
        input.q_share_rns_limb_count,
        input.threshold_degree,
        input.ring_degree,
    )?;
    Ok(())
}
