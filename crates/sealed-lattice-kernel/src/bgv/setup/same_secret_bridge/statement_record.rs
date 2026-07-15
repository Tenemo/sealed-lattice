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
    super::super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
        input.vss_coefficient_commitments,
        input.statement_record,
        input.trustee_identity,
        input.expected_position as u64,
        input.statement_set.public_matrix_seed_hash,
        input.ring_degree,
    )?;
    authoritative_same_secret_bridge_targets(
        input.coefficient_commitment_set,
        input.expected_position,
        input.q_share_rns_limb_count,
        input.threshold_degree,
        input.ring_degree,
    )?;
    Ok(())
}
