use super::*;

pub(in super::super) fn read_local_target_decryption_share_witness(
    witness: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
) -> CanonicalResult<LocalTargetDecryptionShareWitness> {
    if string_at_path(witness, &["objectType"])?
        != "LocalTrusteeTargetDecryptionProofWitnessMaterial"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must be LocalTrusteeTargetDecryptionProofWitnessMaterial version 1",
        ));
    }
    compare_string_field(
        witness,
        "ceremonyId",
        &setup_binding.ceremony_id,
        "local target-decryption share witness ceremony",
    )?;
    compare_hash_field(
        witness,
        "manifestHash",
        &setup_binding.election_manifest_hash,
        "local target-decryption share witness manifest hash",
    )?;
    compare_hash_field(
        witness,
        "rosterHash",
        &setup_binding.roster_hash,
        "local target-decryption share witness roster hash",
    )?;
    compare_hash_field(
        witness,
        "setupParametersHash",
        &setup_binding.setup_parameters_hash,
        "local target-decryption share witness setup parameters hash",
    )?;
    compare_string_field(
        witness,
        "trusteeIdentity",
        &participant.trustee_identity,
        "local target-decryption share witness trustee identity",
    )?;
    compare_unsigned_field(
        witness,
        "trusteeRosterPosition",
        participant.roster_position as u64,
        "local target-decryption share witness roster position",
    )?;
    let smudging_witness = value_at_path(witness, &["targetDecryptionSmudging"])?;
    if string_at_path(smudging_witness, &["objectType"])?
        != "LocalTrusteeTargetDecryptionSmudgingWitness"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must include target-decryption smudging material",
        ));
    }
    for (field_name, expected) in [
        (
            "setupPackageHash",
            setup_binding.setup_package_hash.as_str(),
        ),
        (
            "targetAcceptedRecordHash",
            target_accepted.target_accepted_record_hash.as_str(),
        ),
        (
            "targetContextHash",
            target_accepted.target_context_hash.as_str(),
        ),
        (
            "targetCiphertextHash",
            target_accepted.target_ciphertext_hash.as_str(),
        ),
        ("targetShareProfileHash", target_share_profile.hash.as_str()),
        (
            "targetBasisHash",
            target_accepted.target_basis_hash.as_str(),
        ),
    ] {
        compare_hash_field(
            smudging_witness,
            field_name,
            expected,
            "local target-decryption smudging witness binding",
        )?;
    }
    compare_string_field(
        smudging_witness,
        "trusteeIdentity",
        &participant.trustee_identity,
        "local target-decryption smudging witness trustee identity",
    )?;
    compare_unsigned_field(
        smudging_witness,
        "rosterPosition",
        participant.roster_position as u64,
        "local target-decryption smudging witness roster position",
    )?;
    let smudging_seed_hex =
        target_decryption_smudging_seed_hex(setup_binding, target_accepted, target_share_profile);
    let smudging_polynomial_openings = target_decryption_smudging_polynomial_openings(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        &smudging_seed_hex,
    )?;
    let setup_epoch = required_string_field(witness, "setupEpoch")?;

    let opening = value_at_path(witness, &["aggregateOpening"])?;
    if string_at_path(opening, &["objectType"])? != "LocalTrusteeVssPublicAggregateOpeningWitness" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must include aggregate opening material",
        ));
    }
    compare_hash_field(
        opening,
        "targetBasisHash",
        &target_accepted.target_basis_hash,
        "local target-decryption share witness target basis hash",
    )?;
    compare_hash_field(
        opening,
        "publicMatrixSeedHash",
        &setup_binding.public_matrix_seed_hash,
        "local target-decryption share witness public matrix seed hash",
    )?;
    #[cfg(test)]
    let public_matrix_seed_hash = setup_binding.public_matrix_seed_hash.clone();
    let share_linkage_statement_root =
        hash_at_path(opening, &["shareLinkageStatementRoot"])?.to_string();
    let aggregate_threshold_commitment_root =
        hash_at_path(opening, &["aggregateThresholdCommitmentRoot"])?.to_string();
    if share_linkage_statement_root != setup_binding.share_linkage_statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "local target-decryption share-linkage statement root does not match the accepted setup statement",
        ));
    }
    let aggregate_threshold_commitment_set = &setup_binding.aggregate_threshold_commitment_set;
    if aggregate_threshold_commitment_root
        != aggregate_threshold_commitment_set.aggregate_threshold_commitment_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "local target-decryption aggregate opening root does not match the accepted aggregate commitment set",
        ));
    }

    let active_limb_count = target_ciphertexts.target_id.level + 1;
    if active_limb_count > aggregate_threshold_commitment_set.rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted aggregate threshold commitment set does not cover every active target limb",
        ));
    }
    let mut secret_share_by_limb: Vec<Option<Vec<u64>>> = vec![None; active_limb_count];
    let mut active_credential_bindings: Vec<Option<AggregateOpeningCredentialBinding>> =
        (0..active_limb_count).map(|_| None).collect();
    for credential in array_at_path(opening, &["aggregateOpeningCredentials"])? {
        if string_at_path(credential, &["objectType"])?
            != "LocalTrusteeVssPublicAggregateOpeningCredential"
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "aggregate opening credentials must be LocalTrusteeVssPublicAggregateOpeningCredential version 1",
            ));
        }
        compare_string_field(
            credential,
            "recipientIdentity",
            &participant.trustee_identity,
            "aggregate opening credential recipient identity",
        )?;
        compare_unsigned_field(
            credential,
            "recipientRosterPosition",
            participant.roster_position as u64,
            "aggregate opening credential recipient roster position",
        )?;
        compare_unsigned_field(
            credential,
            "recipientTrusteePoint",
            participant.interpolation_point()?,
            "aggregate opening credential recipient trustee point",
        )?;
        let limb_index = usize_at_path(credential, &["rnsLimbIndex"])?;
        let Some(expected_modulus) = DATA_PRIMES.get(limb_index).copied() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "aggregate opening credential limb is outside the selected BGV basis",
            ));
        };
        compare_unsigned_field(
            credential,
            "rnsPrime",
            expected_modulus,
            "aggregate opening credential rnsPrime",
        )?;
        if limb_index >= active_limb_count {
            continue;
        }
        if secret_share_by_limb[limb_index].is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "local target-decryption share witness contains duplicate active limbs",
            ));
        }

        let verified_credential =
            verify_aggregate_opening_credential(AggregateOpeningCheckInput {
                setup_binding,
                participant,
                setup_epoch,
                credential,
                rns_limb_index: limb_index,
                rns_prime: expected_modulus,
            })?;
        secret_share_by_limb[limb_index] = Some(verified_credential.aggregate_share_values.clone());
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
        if accepted_record.rns_prime != expected_modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "accepted aggregate threshold commitment RNS prime does not match the active target limb",
            ));
        }
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
        active_credential_bindings[limb_index] = Some(AggregateOpeningCredentialBinding {
            limb_index,
            rns_prime: expected_modulus,
            aggregate_commitment_root: verified_credential.commitment_root,
            aggregate_commitment_context_hash: verified_credential.commitment_context_hash,
            aggregate_opening_root: verified_credential.opening_root,
            aggregate_commitment_message_values: verified_credential
                .aggregate_commitment_message_values,
            aggregate_material_seed_hex: verified_credential.aggregate_material_seed_hex,
        });
    }

    let secret_share_by_limb = secret_share_by_limb
        .into_iter()
        .enumerate()
        .map(|(limb_index, coefficients)| {
            coefficients.ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!(
                        "local target-decryption share witness is missing active limb {limb_index}"
                    ),
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let active_credential_bindings = active_credential_bindings
        .into_iter()
        .enumerate()
        .map(|(limb_index, binding)| {
            binding.ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!(
                        "local target-decryption share witness is missing active credential binding {limb_index}"
                    ),
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(LocalTargetDecryptionShareWitness {
        secret_share_by_limb,
        smudging_seed_hex,
        smudging_polynomial_openings,
        opening: AggregateOpeningWitnessBinding {
            #[cfg(test)]
            public_matrix_seed_hash,
            #[cfg(test)]
            share_linkage_statement_root,
            #[cfg(test)]
            aggregate_threshold_commitment_root,
            active_credential_bindings,
        },
    })
}
