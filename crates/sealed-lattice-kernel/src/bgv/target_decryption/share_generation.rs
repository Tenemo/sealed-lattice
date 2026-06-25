use super::*;

pub(super) struct LocalTargetDecryptionShareWitness {
    pub(super) secret_share_by_limb: Vec<Vec<u64>>,
    pub(super) smudging_seed_hex: String,
    pub(super) compact_opening: CompactAggregateOpeningWitnessBinding,
}

pub(super) struct CompactAggregateOpeningWitnessBinding {
    pub(super) public_matrix_seed_hash: String,
    pub(super) share_linkage_statement_root: String,
    pub(super) aggregate_threshold_commitment_root: String,
    pub(super) active_credential_bindings: Vec<CompactAggregateOpeningCredentialBinding>,
}

pub(super) struct CompactAggregateOpeningCredentialBinding {
    pub(super) limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) aggregate_commitment_root: String,
    pub(super) aggregate_opening_root: String,
}

pub(super) fn generate_target_decryption_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    evaluator_key: &DevelopmentBgvKey,
    private_setup_seed: &str,
) -> CanonicalResult<Value> {
    let level = target_ciphertexts.target_id.level;
    let secret_share = derive_threshold_secret_share_by_limb(
        evaluator_key,
        &setup_binding.setup_package_hash,
        &target_share_profile.hash,
        private_setup_seed,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
        level,
    )?;
    let smudging_seed_hex = target_decryption_smudging_seed_hex(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        private_setup_seed,
    );
    generate_target_decryption_share_from_secret_share(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &secret_share,
        &smudging_seed_hex,
    )
}

pub(super) fn generate_target_decryption_share_from_secret_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    secret_share: &[Vec<u64>],
    smudging_seed_hex: &str,
) -> CanonicalResult<Value> {
    let level = target_ciphertexts.target_id.level;
    let target_id_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_id, secret_share)?;
    let target_order_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_order, secret_share)?;
    let (target_id_partials, target_id_smudging_report) =
        apply_plaintext_multiple_zero_share_smudging(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            participant,
            smudging_seed_hex,
            "targetId",
            &target_id_partials,
        )?;
    let (target_order_partials, target_order_smudging_report) =
        apply_plaintext_multiple_zero_share_smudging(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            participant,
            smudging_seed_hex,
            "targetOrder",
            &target_order_partials,
        )?;
    let smudging_input_report = target_decryption_smudging_input_report_value(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        target_id_smudging_report,
        target_order_smudging_report,
    );
    let smudging_input_report_hash = derive_protocol_hash(
        "TargetDecryptionSmudgingInputReportHash",
        &smudging_input_report,
    )?;
    let payload = share_payload(
        level,
        &target_id_partials,
        &target_order_partials,
        &smudging_input_report,
        &smudging_input_report_hash,
    )?;
    let share_root = derive_protocol_hash("BgvTargetDecryptionShareRoot", &payload)?;
    let record_hash_input = share_record_hash_input(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &share_root,
    );
    let target_decryption_share_hash =
        derive_protocol_hash("BgvTargetDecryptionShareHash", &record_hash_input)?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShare",
        "objectVersion": 1,
        "targetDecryptionShareHash": target_decryption_share_hash,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "interpolationPoint": participant.interpolation_point,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetProposalHash": target_accepted.target_proposal_hash,
        "targetPreimageHash": target_accepted.target_preimage_hash,
        "targetFinalityRecordHash": target_accepted.target_finality_record_hash,
        "targetFinalityCheckpointHash": target_accepted.target_finality_checkpoint_hash,
        "evaluatorReplayRecordHash": target_accepted.evaluator_replay_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetCiphertextBindingHash": target_ciphertexts.target_ciphertext_binding_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "shareRoot": share_root,
        "sharePayload": payload,
    }))
}

pub(super) fn read_local_target_decryption_share_witness(
    witness: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
) -> CanonicalResult<LocalTargetDecryptionShareWitness> {
    if string_at_path(witness, &["objectType"])?
        != "LocalTrusteeTargetDecryptionProofWitnessMaterial"
        || unsigned_at_path(witness, &["objectVersion"])? != 1
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
        "setupProfileHash",
        &setup_binding.setup_profile_hash,
        "local target-decryption share witness setup profile hash",
    )?;
    compare_hash_field(
        witness,
        "qShareHash",
        &setup_binding.q_share_hash,
        "local target-decryption share witness Q_share hash",
    )?;
    compare_hash_field(
        witness,
        "carryAwareVssShareRelationProfileHash",
        &setup_binding.carry_aware_vss_share_relation_profile_hash,
        "local target-decryption share witness carry-aware VSS relation profile hash",
    )?;
    compare_hash_field(
        witness,
        "commitmentProfileHash",
        &setup_binding.commitment_profile_hash,
        "local target-decryption share witness setup commitment profile hash",
    )?;
    compare_string_field(
        witness,
        "setupProfileId",
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "local target-decryption share witness setup profile id",
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
    compare_string_field(
        witness,
        "witnessOwnership",
        TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP,
        "local target-decryption share witness ownership",
    )?;
    let smudging_witness = value_at_path(witness, &["targetDecryptionSmudging"])?;
    if string_at_path(smudging_witness, &["objectType"])?
        != "LocalTrusteeTargetDecryptionSmudgingWitness"
        || unsigned_at_path(smudging_witness, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must include target-decryption smudging material",
        ));
    }
    compare_string_field(
        smudging_witness,
        "profileId",
        TARGET_DECRYPTION_SMUDGING_PROFILE_ID,
        "local target-decryption smudging witness profile",
    )?;
    compare_string_field(
        smudging_witness,
        "developmentScope",
        TARGET_DECRYPTION_SMUDGING_DEVELOPMENT_SCOPE,
        "local target-decryption smudging witness development scope",
    )?;
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
        (
            "targetDecryptionCiphertextHash",
            target_ciphertexts.target_ciphertext_hash.as_str(),
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
    compare_unsigned_field(
        smudging_witness,
        "interpolationPoint",
        participant.interpolation_point,
        "local target-decryption smudging witness interpolation point",
    )?;
    compare_unsigned_field(
        smudging_witness,
        "plaintextMultiple",
        PLAINTEXT_MODULUS,
        "local target-decryption smudging witness plaintext multiple",
    )?;
    compare_string_field(
        smudging_witness,
        "zeroSharingRule",
        TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE,
        "local target-decryption smudging witness zero-sharing rule",
    )?;
    let smudging_seed_hex = string_at_path(smudging_witness, &["smudgingSeedHex"])?.to_string();
    validate_smudging_seed_hex(&smudging_seed_hex)?;
    let setup_epoch = required_string_field(witness, "setupEpoch")?;

    let compact_opening = value_at_path(witness, &["compactAggregateOpening"])?;
    if string_at_path(compact_opening, &["objectType"])?
        != "LocalTrusteeCompactVssAggregateOpeningWitness"
        || unsigned_at_path(compact_opening, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "local target-decryption share witness must include compact aggregate opening material",
        ));
    }
    compare_hash_field(
        compact_opening,
        "targetBasisHash",
        &target_accepted.target_basis_hash,
        "local target-decryption share witness target basis hash",
    )?;
    compare_hash_field(
        compact_opening,
        "publicMatrixSeedHash",
        &setup_binding.public_matrix_seed_hash,
        "local target-decryption share witness public matrix seed hash",
    )?;
    let public_matrix_seed_hash = setup_binding.public_matrix_seed_hash.clone();
    let share_linkage_statement_root =
        hash_at_path(compact_opening, &["shareLinkageStatementRoot"])?.to_string();
    let aggregate_threshold_commitment_root =
        hash_at_path(compact_opening, &["aggregateThresholdCommitmentRoot"])?.to_string();

    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let mut secret_share_by_limb: Vec<Option<Vec<u64>>> = vec![None; active_limb_count];
    let mut active_credential_bindings: Vec<Option<CompactAggregateOpeningCredentialBinding>> =
        (0..active_limb_count).map(|_| None).collect();
    for credential in array_at_path(compact_opening, &["compactAggregateOpeningCredentials"])? {
        if string_at_path(credential, &["objectType"])?
            != "LocalTrusteeCompactVssAggregateOpeningCredential"
            || unsigned_at_path(credential, &["objectVersion"])? != 1
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact aggregate opening credentials must be LocalTrusteeCompactVssAggregateOpeningCredential version 1",
            ));
        }
        compare_string_field(
            credential,
            "recipientIdentity",
            &participant.trustee_identity,
            "compact aggregate opening credential recipient identity",
        )?;
        compare_unsigned_field(
            credential,
            "recipientRosterPosition",
            participant.roster_position as u64,
            "compact aggregate opening credential recipient roster position",
        )?;
        compare_unsigned_field(
            credential,
            "recipientTrusteePoint",
            participant.interpolation_point,
            "compact aggregate opening credential recipient trustee point",
        )?;
        let limb_index = usize_at_path(credential, &["rnsLimbIndex"])?;
        let Some(expected_modulus) = DATA_PRIMES.get(limb_index).copied() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "compact aggregate opening credential limb is outside the selected BGV basis",
            ));
        };
        compare_unsigned_field(
            credential,
            "rnsPrime",
            expected_modulus,
            "compact aggregate opening credential rnsPrime",
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

        let share_values = array_at_path(credential, &["aggregateShareValues"])?;
        if share_values.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "local target-decryption share witness limb has the wrong coefficient count",
            ));
        }
        let coefficients = share_values
            .iter()
            .enumerate()
            .map(|(coefficient_index, value)| {
                let coefficient = value.as_u64().ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "local target-decryption share witness coefficient {coefficient_index} must be a non-negative integer"
                        ),
                    )
                })?;
                if coefficient >= expected_modulus {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "local target-decryption share witness contains a non-canonical residue",
                    ));
                }

                Ok(coefficient)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        secret_share_by_limb[limb_index] = Some(coefficients);
        let (verified_aggregate_commitment_root, verified_aggregate_opening_root) =
            verify_compact_aggregate_opening_credential(CompactAggregateOpeningCheckInput {
                setup_binding,
                participant,
                setup_epoch,
                public_matrix_seed_hash: &public_matrix_seed_hash,
                credential,
                rns_limb_index: limb_index,
                rns_prime: expected_modulus,
                aggregate_share_values: secret_share_by_limb[limb_index]
                    .as_ref()
                    .expect("secret share stored before verification"),
            })?;
        active_credential_bindings[limb_index] = Some(CompactAggregateOpeningCredentialBinding {
            limb_index,
            rns_prime: expected_modulus,
            aggregate_commitment_root: verified_aggregate_commitment_root,
            aggregate_opening_root: verified_aggregate_opening_root,
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
        compact_opening: CompactAggregateOpeningWitnessBinding {
            public_matrix_seed_hash,
            share_linkage_statement_root,
            aggregate_threshold_commitment_root,
            active_credential_bindings,
        },
    })
}

pub(super) fn derive_threshold_secret_share_by_limb(
    evaluator_key: &DevelopmentBgvKey,
    setup_package_hash: &str,
    target_share_profile_hash: &str,
    private_setup_seed: &str,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let secret = evaluator_key.secret();

    #[cfg(not(target_arch = "wasm32"))]
    {
        DATA_PRIMES[..=level]
            .par_iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                derive_threshold_secret_share_limb(
                    secret,
                    setup_package_hash,
                    target_share_profile_hash,
                    private_setup_seed,
                    interpolation_point,
                    minimum_shares_for_interpolation,
                    limb_index,
                    *modulus,
                )
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        DATA_PRIMES[..=level]
            .iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                derive_threshold_secret_share_limb(
                    secret,
                    setup_package_hash,
                    target_share_profile_hash,
                    private_setup_seed,
                    interpolation_point,
                    minimum_shares_for_interpolation,
                    limb_index,
                    *modulus,
                )
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
// Development-only dealer: this reshares the actual secret coefficient (Shamir constant term) with a per-prime degree-(t-1) polynomial derived deterministically from private_setup_seed, so reconstruction at x=0 returns s. This is a centralized dealer simulating a DKG, not a real distributed key generation; the shares are only as private as the seed.
pub(super) fn derive_threshold_secret_share_limb(
    secret: &[i64],
    setup_package_hash: &str,
    target_share_profile_hash: &str,
    private_setup_seed: &str,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut share = secret
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let evaluation_point = interpolation_point % modulus;
    let mut evaluation_point_power = evaluation_point;
    let limb_index_bytes = (limb_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    for polynomial_degree in 1..minimum_shares_for_interpolation {
        let degree_bytes = (polynomial_degree as u64).to_le_bytes();
        let mut sampler = DeterministicSampler::new(
            "sealed-lattice-bgv-rns/target-decryption-shamir-polynomial-v1",
            &[
                private_setup_seed.as_bytes(),
                setup_package_hash.as_bytes(),
                target_share_profile_hash.as_bytes(),
                &limb_index_bytes,
                &modulus_bytes,
                &degree_bytes,
            ],
        );
        let coefficients = sampler.uniform_residues(modulus, POLYNOMIAL_DEGREE);
        for (share_coefficient, polynomial_coefficient) in share.iter_mut().zip(coefficients) {
            let term = mul_mod_fast(polynomial_coefficient, evaluation_point_power, modulus);
            *share_coefficient = add_mod_fast(*share_coefficient, term, modulus);
        }
        evaluation_point_power = mul_mod(evaluation_point_power, evaluation_point, modulus)?;
    }

    Ok(share)
}

pub(super) fn target_decryption_smudging_seed_hex(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    private_setup_seed: &str,
) -> String {
    hash512_hex(
        TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN,
        &[
            private_setup_seed.as_bytes(),
            setup_binding.setup_package_hash.as_bytes(),
            target_accepted.target_accepted_record_hash.as_bytes(),
            target_accepted.target_context_hash.as_bytes(),
            target_accepted.target_ciphertext_hash.as_bytes(),
            target_ciphertexts.target_ciphertext_hash.as_bytes(),
            target_share_profile.hash.as_bytes(),
            target_accepted.target_basis_hash.as_bytes(),
        ],
    )
}

pub(super) fn target_decryption_smudging_witness_value(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    private_setup_seed: &str,
) -> Value {
    json!({
        "objectType": "LocalTrusteeTargetDecryptionSmudgingWitness",
        "objectVersion": 1,
        "profileId": TARGET_DECRYPTION_SMUDGING_PROFILE_ID,
        "developmentScope": TARGET_DECRYPTION_SMUDGING_DEVELOPMENT_SCOPE,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "interpolationPoint": participant.interpolation_point,
        "plaintextMultiple": PLAINTEXT_MODULUS,
        "zeroSharingRule": TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE,
        "smudgingSeedHex": target_decryption_smudging_seed_hex(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            private_setup_seed,
        ),
    })
}

pub(super) fn validate_smudging_seed_hex(seed_hex: &str) -> CanonicalResult<()> {
    let seed_bytes = decode_hex(seed_hex)?;
    if seed_bytes.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption smudging seed must be a 64-byte lowercase hexadecimal value",
        ));
    }

    Ok(())
}

pub(super) fn smudging_noise_share_bound(
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
) -> CanonicalResult<u64> {
    let mut evaluation_point_power = i128::from(interpolation_point);
    let mut accumulated_power_sum = 0_i128;
    for _ in 1..minimum_shares_for_interpolation {
        accumulated_power_sum = accumulated_power_sum
            .checked_add(evaluation_point_power)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging bound overflowed",
                )
            })?;
        evaluation_point_power = evaluation_point_power
            .checked_mul(i128::from(interpolation_point))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging bound overflowed",
                )
            })?;
    }
    let bound = accumulated_power_sum
        .checked_mul(i128::from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target-decryption smudging bound overflowed",
            )
        })?;

    u64::try_from(bound).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-decryption smudging bound does not fit a non-negative integer",
        )
    })
}

struct TargetSmudgingNoiseShare {
    residues: Vec<u64>,
    noise_share_hash512: String,
    maximum_absolute_noise_share: u64,
}

#[allow(clippy::too_many_arguments)]
fn apply_plaintext_multiple_zero_share_smudging(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    smudging_seed_hex: &str,
    role: &str,
    partials_by_limb: &[Vec<u64>],
) -> CanonicalResult<(Vec<Vec<u64>>, Value)> {
    let mut smudged_partials = partials_by_limb.to_vec();
    let mut limb_reports = Vec::with_capacity(smudged_partials.len());
    for (rns_limb_index, limb_partials) in smudged_partials.iter_mut().enumerate() {
        let rns_prime = DATA_PRIMES[rns_limb_index];
        let noise_share = target_decryption_smudging_noise_share(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            participant,
            smudging_seed_hex,
            role,
            rns_limb_index,
            rns_prime,
        )?;
        let plaintext_multiple = PLAINTEXT_MODULUS % rns_prime;
        for (partial_coefficient, noise_residue) in
            limb_partials.iter_mut().zip(noise_share.residues.iter())
        {
            let smudging_term = mul_mod_fast(*noise_residue, plaintext_multiple, rns_prime);
            *partial_coefficient = add_mod_fast(*partial_coefficient, smudging_term, rns_prime);
        }
        limb_reports.push(json!({
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "noiseShareHash512": noise_share.noise_share_hash512,
            "maximumAbsoluteNoiseShare": noise_share.maximum_absolute_noise_share,
        }));
    }

    Ok((
        smudged_partials,
        json!({
            "role": role,
            "limbReports": limb_reports,
        }),
    ))
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_noise_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    smudging_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<TargetSmudgingNoiseShare> {
    let smudging_seed_bytes = decode_hex(smudging_seed_hex)?;
    if smudging_seed_bytes.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption smudging seed must be a 64-byte lowercase hexadecimal value",
        ));
    }
    let mut residues = vec![0_u64; POLYNOMIAL_DEGREE];
    let mut centered_values = vec![0_i128; POLYNOMIAL_DEGREE];
    let evaluation_point = participant.interpolation_point % rns_prime;
    let mut evaluation_point_power_mod = evaluation_point;
    let mut evaluation_point_power_wide = i128::from(participant.interpolation_point);
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();
    let minimum_shares_bytes =
        (target_share_profile.minimum_shares_for_interpolation as u64).to_le_bytes();
    for polynomial_degree in 1..target_share_profile.minimum_shares_for_interpolation {
        let polynomial_degree_bytes = (polynomial_degree as u64).to_le_bytes();
        let mut sampler = DeterministicSampler::new(
            TARGET_DECRYPTION_SMUDGING_ZERO_SHARE_DOMAIN,
            &[
                &smudging_seed_bytes,
                setup_binding.setup_package_hash.as_bytes(),
                target_accepted.target_accepted_record_hash.as_bytes(),
                target_accepted.target_context_hash.as_bytes(),
                target_accepted.target_ciphertext_hash.as_bytes(),
                target_ciphertexts.target_ciphertext_hash.as_bytes(),
                target_share_profile.hash.as_bytes(),
                role.as_bytes(),
                &rns_limb_index_bytes,
                &rns_prime_bytes,
                &minimum_shares_bytes,
                &polynomial_degree_bytes,
            ],
        );
        let coefficient_span = u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND * 2 + 1)
            .map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging coefficient bound is invalid",
                )
            })?;
        let polynomial_coefficients = sampler.uniform_residues(coefficient_span, POLYNOMIAL_DEGREE);
        for ((residue, centered_value), sampled_coefficient) in residues
            .iter_mut()
            .zip(centered_values.iter_mut())
            .zip(polynomial_coefficients)
        {
            let signed_coefficient = i64::try_from(sampled_coefficient).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging coefficient does not fit a signed integer",
                )
            })? - TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;
            let residue_term = mul_mod_fast(
                signed_residue(signed_coefficient, rns_prime),
                evaluation_point_power_mod,
                rns_prime,
            );
            *residue = add_mod_fast(*residue, residue_term, rns_prime);
            let centered_term = i128::from(signed_coefficient)
                .checked_mul(evaluation_point_power_wide)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "target-decryption smudging coefficient evaluation overflowed",
                    )
                })?;
            *centered_value = centered_value.checked_add(centered_term).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging coefficient evaluation overflowed",
                )
            })?;
        }
        evaluation_point_power_mod =
            mul_mod(evaluation_point_power_mod, evaluation_point, rns_prime)?;
        evaluation_point_power_wide = evaluation_point_power_wide
            .checked_mul(i128::from(participant.interpolation_point))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging coefficient evaluation overflowed",
                )
            })?;
    }

    let centered_i64_values = centered_values
        .iter()
        .copied()
        .map(|coefficient| {
            i64::try_from(coefficient).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target-decryption smudging evaluated share does not fit a signed integer",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut hash_input = Vec::with_capacity(centered_i64_values.len() * 8);
    let mut maximum_absolute_noise_share = 0_u64;
    for coefficient in &centered_i64_values {
        hash_input.extend_from_slice(&coefficient.to_le_bytes());
        maximum_absolute_noise_share = maximum_absolute_noise_share.max(coefficient.unsigned_abs());
    }
    let noise_share_hash512 = hash512_hex(
        TARGET_SMUDGING_NOISE_SHARE_HASH_DOMAIN,
        &[
            role.as_bytes(),
            &rns_limb_index_bytes,
            &rns_prime_bytes,
            &hash_input,
        ],
    );

    Ok(TargetSmudgingNoiseShare {
        residues,
        noise_share_hash512,
        maximum_absolute_noise_share,
    })
}

fn target_decryption_smudging_input_report_value(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    target_id_smudging_report: Value,
    target_order_smudging_report: Value,
) -> Value {
    json!({
        "objectType": "TargetDecryptionSmudgingInputReport",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "smudgingProfileId": TARGET_DECRYPTION_SMUDGING_PROFILE_ID,
        "developmentScope": TARGET_DECRYPTION_SMUDGING_DEVELOPMENT_SCOPE,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "interpolationPoint": participant.interpolation_point,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "minimumSharesForInterpolation": target_share_profile.minimum_shares_for_interpolation,
        "decryptionThreshold": target_share_profile.decryption_threshold,
        "activeRnsLimbCount": target_ciphertexts.target_id.level + 1,
        "ringDegree": POLYNOMIAL_DEGREE,
        "smudgingCoefficientBound": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
        "smudgingPolynomialDegree": target_share_profile.minimum_shares_for_interpolation.saturating_sub(1),
        "plaintextMultiple": PLAINTEXT_MODULUS,
        "zeroSharingRule": TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE,
        "correctnessRule": TARGET_DECRYPTION_SMUDGING_CORRECTNESS_RULE,
        "proofBoundary": TARGET_DECRYPTION_SMUDGING_PROOF_BOUNDARY,
        "roleReports": [
            target_id_smudging_report,
            target_order_smudging_report,
        ],
    })
}

// Development target shares now add plaintext-multiple Shamir zero-share masks
// before release. The report binds the mask hashes and cancellation rule, but a
// production target-decryption path still needs a zero-knowledge proof that the
// smudged share and compact opening witness satisfy the stated relation.
pub(super) fn partial_decryption_by_limb(
    ciphertext: &Ciphertext,
    secret_share_by_limb: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if ciphertext.components.len() != 2 || secret_share_by_limb.len() != ciphertext.primes().len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target PartDec requires a two-component ciphertext and one secret-share limb per active prime",
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        ciphertext
            .primes()
            .par_iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                negacyclic_mul(
                    &ciphertext.components[1][limb_index],
                    &secret_share_by_limb[limb_index],
                    *modulus,
                )
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        ciphertext
            .primes()
            .iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                negacyclic_mul(
                    &ciphertext.components[1][limb_index],
                    &secret_share_by_limb[limb_index],
                    *modulus,
                )
            })
            .collect()
    }
}
