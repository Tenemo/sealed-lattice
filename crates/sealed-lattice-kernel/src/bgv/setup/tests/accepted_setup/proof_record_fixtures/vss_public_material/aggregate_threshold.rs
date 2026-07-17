use super::*;

// The aggregate set still carries one proof reference per recipient and target
// limb. The fixture binds each reference to the exact reconstructed statement,
// but deliberately supplies no accepted proof while the common-proof adapter is
// unavailable.
pub(in super::super) fn vss_aggregate_threshold_proof_bytes_hashes(
    package: &serde_json::Value,
    aggregate_set: &serde_json::Value,
    recipient_coordinates: &[(u64, usize)],
) -> Vec<String> {
    let participant_count = participant_count_from_package(package);
    let recipient_records = aggregate_set["recipientRecords"]
        .as_array()
        .expect("aggregate recipient records");
    assert_eq!(
        recipient_records.len(),
        recipient_coordinates.len(),
        "aggregate recipient records and canonical coordinates",
    );
    let proof_bytes_hashes = recipient_records
        .iter()
        .zip(recipient_coordinates.iter().copied())
        .map(
            |(aggregate_record, (recipient_roster_position, rns_limb_index))| {
                vss_aggregate_threshold_proof_bytes_hash(
                    package,
                    aggregate_record,
                    participant_count,
                    recipient_roster_position,
                    rns_limb_index,
                )
            },
        )
        .collect::<Vec<_>>();
    proof_bytes_hashes
}

fn vss_aggregate_threshold_proof_bytes_hash(
    package: &serde_json::Value,
    aggregate_record: &serde_json::Value,
    participant_count: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> String {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let coefficient_source_records =
        package["vssPublicCoefficientCommitmentSet"]["sourceTrusteeRecords"]
            .as_array()
            .expect("VSS coefficient source records");
    let recipient_source_records =
        package["vssPublicRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
            .as_array()
            .expect("VSS recipient-share source records");
    let aggregate_record_index = usize::try_from(recipient_roster_position)
        .expect("recipient roster position fits usize")
        .checked_mul(DATA_PRIMES.len())
        .and_then(|offset| offset.checked_add(rns_limb_index))
        .expect("aggregate record index fits usize");
    let trustee_identities = (0..participant_count)
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let vss_aggregate =
        crate::bgv::setup::vss_commitment::vss_aggregate_threshold_statement_from_commitment_records(
            crate::bgv::setup::vss_commitment::VssAggregateThresholdStatementInput {
                public_matrix_seed_hash,
                participant_count: usize::try_from(participant_count)
                    .expect("participant count fits usize"),
                rns_limb_count: DATA_PRIMES.len(),
                coefficient_source_records,
                recipient_source_records,
                aggregate_record,
                aggregate_record_index,
                trustee_identities: &trustee_identities,
            },
        )
        .expect("canonical VSS aggregate threshold statement");
    invalid_common_proof_fixture_hash(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
        &vss_aggregate,
    )
}
