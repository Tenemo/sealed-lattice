use super::*;

const VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "vssPublicAggregateThresholdCommitmentSet";
const VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "vssShareLinkageStatement";

// Shape validation does not confer setup authority.
fn require_setup_package_shape(setup_package: &Value) -> CanonicalResult<()> {
    if string_at_path(setup_package, &["objectType"])? != "SetupPackage" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target decryption requires a SetupPackage-shaped input",
        ));
    }
    Ok(())
}

pub(super) fn read_setup_binding(setup_package: &Value) -> CanonicalResult<SetupBinding> {
    require_setup_package_shape(setup_package)?;
    let setup_context_hashes = collective_bgv_setup_context_hashes_from_package(setup_package)?;
    let setup_package_hash = derive_collective_setup_package_hash(setup_package)?;
    let public_matrix_seed_hash =
        hash_at_path(setup_package, &["commonRandomness", "publicMatrixSeedHash"])?.to_string();
    // Setup-intent registrations define the roster; position + 1 is its nonzero Shamir point.
    let participants = accepted_setup_participant_roster_from_package(setup_package)?
        .into_iter()
        .map(|(roster_position, trustee_identity)| ParticipantBinding {
            trustee_identity,
            roster_position,
        })
        .collect::<Vec<_>>();
    let q_share_rns_limb_count = usize_at_path(
        setup_package,
        &[VSS_SHARE_LINKAGE_STATEMENT_FIELD, "qShareRnsLimbCount"],
    )?;
    let aggregate_threshold_commitment_set = read_aggregate_threshold_commitment_set_binding(
        value_at_path(
            setup_package,
            &[VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD],
        )?,
        &setup_context_hashes.setup_context_hash,
        &public_matrix_seed_hash,
        &participants,
        q_share_rns_limb_count,
    )?;
    Ok(SetupBinding {
        setup_package_hash,
        setup_context_hash: setup_context_hashes.setup_context_hash,
        public_matrix_seed_hash,
        participants,
        aggregate_threshold_commitment_set,
    })
}

fn read_aggregate_threshold_commitment_set_binding(
    aggregate_set: &Value,
    setup_context_hash: &str,
    setup_public_matrix_seed_hash: &str,
    participants: &[ParticipantBinding],
    rns_limb_count: usize,
) -> CanonicalResult<AggregateThresholdCommitmentSetBinding> {
    if participants.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate threshold commitment set requires setup participants",
        ));
    }
    if rns_limb_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate threshold commitment set requires a positive Q_share limb count",
        ));
    }
    if rns_limb_count > DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "aggregate threshold commitment set has more limbs than the canonical data basis",
        ));
    }
    let trustee_identities = participants
        .iter()
        .map(|participant| participant.trustee_identity.clone())
        .collect::<Vec<_>>();
    verify_vss_public_aggregate_threshold_commitment_set(
        aggregate_set,
        &VssPublicAggregateThresholdCommitmentSetContext {
            setup_context_hash,
            public_matrix_seed_hash: setup_public_matrix_seed_hash,
            participant_count: participants.len(),
            trustee_identities: &trustee_identities,
            rns_limb_count,
        },
    )?;

    let records = array_at_path(aggregate_set, &["recipientRecords"])?;
    let mut recipient_records = Vec::with_capacity(participants.len());
    for recipient_position in 0..participants.len() {
        let mut limb_records = Vec::with_capacity(rns_limb_count);
        for rns_limb_index in 0..rns_limb_count {
            let record_index = recipient_position
                .checked_mul(rns_limb_count)
                .and_then(|base| base.checked_add(rns_limb_index))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "aggregate threshold commitment record index overflowed",
                    )
                })?;
            let record = records.get(record_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate threshold commitment set is missing a recipient limb record",
                )
            })?;
            limb_records.push(AggregateThresholdCommitmentRecordBinding {
                aggregate_commitment_root: hash_at_path(record, &["aggregateCommitmentRoot"])?
                    .to_string(),
                aggregate_opening_root: hash_at_path(record, &["aggregateOpeningRoot"])?
                    .to_string(),
                aggregate_commitment: value_at_path(record, &["commitment"])?.clone(),
            });
        }
        recipient_records.push(limb_records);
    }

    Ok(AggregateThresholdCommitmentSetBinding {
        rns_limb_count,
        recipient_records,
    })
}

// Canonical consistency is not target-finality authorization.
pub(super) fn read_target_accepted_binding(
    record: &Value,
    setup_binding: &SetupBinding,
) -> CanonicalResult<TargetAcceptedBinding> {
    if string_at_path(record, &["objectType"])? != "TargetAcceptedRecord" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "targetAcceptedRecord must be a canonical TargetAcceptedRecord",
        ));
    }
    compare_hash_field(
        record,
        "setupPackageHash",
        &setup_binding.setup_package_hash,
        "target accepted setup package",
    )?;
    let expected_record_hash =
        derive_canonical_object_hash(&target_accepted_record_hash_preimage(record)?)?;

    Ok(TargetAcceptedBinding {
        target_accepted_record_hash: expected_record_hash,
        target_ciphertext_hash: hash_at_path(record, &["targetCiphertextHash"])?.to_string(),
    })
}

pub(super) fn target_accepted_record_hash_preimage(record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": string_at_path(record, &["objectType"])?,
        "setupPackageHash": hash_at_path(record, &["setupPackageHash"])?,
        "targetCiphertextHash": hash_at_path(record, &["targetCiphertextHash"])?,
    }))
}
