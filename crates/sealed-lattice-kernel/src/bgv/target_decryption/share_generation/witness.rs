use super::*;

pub(in super::super) fn read_local_target_decryption_share_witness(
    witness: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
) -> CanonicalResult<LocalTargetDecryptionShareWitness> {
    if string_at_path(witness, &["objectType"])?
        != "LocalTrusteeTargetDecryptionProofWitnessMaterial"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must be LocalTrusteeTargetDecryptionProofWitnessMaterial",
        ));
    }
    let private_flooding_seed_hex =
        string_at_path(witness, &["privateFloodingSeedHex"])?.to_string();
    let flooding_noise_openings = target_decryption_flooding_noise_openings(
        target_accepted,
        participant,
        &private_flooding_seed_hex,
    )?;
    let opening = value_at_path(witness, &["aggregateOpening"])?;
    if string_at_path(opening, &["objectType"])? != "LocalTrusteeVssPublicAggregateOpeningWitness" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must include aggregate opening material",
        ));
    }
    let aggregate_threshold_commitment_set = &setup_binding.aggregate_threshold_commitment_set;

    let active_limb_count = target_ciphertexts.target_id.level + 1;
    if active_limb_count > aggregate_threshold_commitment_set.rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted aggregate threshold commitment set does not cover every active target limb",
        ));
    }
    let credentials = array_at_path(opening, &["aggregateOpeningCredentials"])?;
    if credentials.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "local target-decryption share witness must include one aggregate opening credential per active limb",
        ));
    }
    let mut secret_share_by_limb = Vec::with_capacity(active_limb_count);
    let mut active_credential_bindings = Vec::with_capacity(active_limb_count);
    for (limb_index, credential) in credentials.iter().enumerate() {
        let Some(expected_modulus) = DATA_PRIMES.get(limb_index).copied() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "aggregate opening credential limb is outside the selected BGV basis",
            ));
        };

        let verified_credential =
            verify_aggregate_opening_credential(AggregateOpeningCheckInput {
                setup_binding,
                participant,
                credential,
                rns_limb_index: limb_index,
                rns_prime: expected_modulus,
            })?;
        secret_share_by_limb.push(verified_credential.aggregate_share_values.clone());
        let accepted_record = aggregate_threshold_commitment_set
            .recipient_records
            .get(participant.roster_position)
            .and_then(|limb_records| limb_records.get(limb_index))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "accepted aggregate threshold commitment set is missing the active recipient limb",
                )
            })?;
        if accepted_record.aggregate_commitment_root != verified_credential.commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "local target-decryption aggregate opening commitment root does not match the accepted aggregate commitment record",
            ));
        }
        if accepted_record.aggregate_opening_root != verified_credential.opening_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "local target-decryption aggregate opening root does not match the accepted aggregate commitment record",
            ));
        }
        active_credential_bindings.push(AggregateOpeningCredentialBinding {
            aggregate_commitment_root: verified_credential.commitment_root,
            aggregate_opening_root: verified_credential.opening_root,
            aggregate_commitment_message_values: verified_credential
                .aggregate_commitment_message_values,
            aggregate_material_seed_hex: verified_credential.aggregate_material_seed_hex,
        });
    }

    Ok(LocalTargetDecryptionShareWitness {
        secret_share_by_limb,
        private_flooding_seed_hex,
        flooding_noise_openings,
        active_credential_bindings,
    })
}
