use super::*;

pub(super) struct LocalTargetDecryptionShareWitness {
    pub(super) secret_share_by_limb: Vec<Vec<u64>>,
    pub(super) setup_epoch: String,
    pub(super) smudging_seed_hex: String,
    pub(super) smudging_polynomial_openings: Vec<TargetDecryptionSmudgingPolynomialOpening>,
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
    pub(super) aggregate_commitment_message_values: Vec<u64>,
    pub(super) aggregate_randomness_by_column: Vec<Vec<i64>>,
}

pub(super) struct TargetDecryptionSmudgingCommitmentSet {
    pub(super) value: Value,
    pub(super) root: String,
}

pub(super) struct TargetDecryptionSmudgingPolynomialOpening {
    pub(super) role: String,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) polynomial_degree: usize,
    pub(super) polynomial_coefficients: Vec<i64>,
}

struct TargetDecryptionSmudgingCommitmentOpening {
    role: String,
    rns_limb_index: usize,
    rns_prime: u64,
    polynomial_degree: usize,
    message_coefficients: Vec<u64>,
    randomness_by_column: Vec<Vec<i64>>,
    commitment_context: Value,
    public_matrix_seed_hash: String,
}

pub(super) struct TargetDecryptionSmudgingProofOpening {
    pub(super) message_coefficients: Vec<u64>,
    pub(super) randomness_by_column: Vec<Vec<i64>>,
}

pub(super) fn generate_target_decryption_share_from_secret_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    secret_share: &[Vec<u64>],
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
) -> CanonicalResult<Value> {
    let level = target_ciphertexts.target_id.level;
    let target_id_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_id, secret_share)?;
    let target_order_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_order, secret_share)?;
    let (target_id_partials, target_id_smudging_report) =
        apply_plaintext_multiple_zero_share_smudging(
            target_share_profile,
            participant,
            smudging_polynomial_openings,
            "targetId",
            &target_id_partials,
        )?;
    let (target_order_partials, target_order_smudging_report) =
        apply_plaintext_multiple_zero_share_smudging(
            target_share_profile,
            participant,
            smudging_polynomial_openings,
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
    let smudging_input_report_hash = derive_canonical_object_hash(&smudging_input_report)?;
    let payload = share_payload(
        level,
        &target_id_partials,
        &target_order_partials,
        &smudging_input_report,
        &smudging_input_report_hash,
    )?;
    let share_root = derive_canonical_object_hash(&payload)?;
    let record_hash_input = share_record_hash_input(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &share_root,
    );
    let target_decryption_share_hash = derive_canonical_object_hash(&record_hash_input)?;

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
        || unsigned_at_path(smudging_witness, &["objectVersion"])? != 1
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
    let smudging_seed_hex = target_decryption_smudging_seed_hex(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
    );
    let smudging_polynomial_openings = target_decryption_smudging_polynomial_openings(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        &smudging_seed_hex,
    )?;
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
    let accepted_share_linkage_statement_root = setup_binding
        .compact_share_linkage_statement_root
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "local target-decryption compact aggregate opening requires the accepted compact share-linkage statement",
            )
        })?;
    if &share_linkage_statement_root != accepted_share_linkage_statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "local target-decryption compact share-linkage statement root does not match the accepted setup statement",
        ));
    }
    let compact_aggregate_threshold_commitment_set = setup_binding
        .compact_aggregate_threshold_commitment_set
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "local target-decryption compact aggregate opening requires the accepted compact aggregate threshold commitment set",
            )
        })?;
    if aggregate_threshold_commitment_root
        != compact_aggregate_threshold_commitment_set.aggregate_threshold_commitment_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "local target-decryption compact aggregate opening root does not match the accepted aggregate commitment set",
        ));
    }

    let active_limb_count = target_ciphertexts.target_id.level + 1;
    if active_limb_count > compact_aggregate_threshold_commitment_set.rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted compact aggregate threshold commitment set does not cover every active target limb",
        ));
    }
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
                CanonicalErrorCode::ComponentMismatch,
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

        let verified_credential =
            verify_compact_aggregate_opening_credential(CompactAggregateOpeningCheckInput {
                setup_binding,
                participant,
                setup_epoch,
                public_matrix_seed_hash: &public_matrix_seed_hash,
                credential,
                rns_limb_index: limb_index,
                rns_prime: expected_modulus,
            })?;
        secret_share_by_limb[limb_index] = Some(verified_credential.aggregate_share_values.clone());
        let accepted_record = compact_aggregate_threshold_commitment_set
            .recipient_records
            .get(participant.roster_position)
            .and_then(|limb_records| limb_records.get(limb_index))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "accepted compact aggregate threshold commitment set is missing the active recipient limb",
                )
            })?;
        if accepted_record.rns_prime != expected_modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "accepted compact aggregate threshold commitment RNS prime does not match the active target limb",
            ));
        }
        if accepted_record.aggregate_commitment_root != verified_credential.commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "local target-decryption compact aggregate opening commitment root does not match the accepted aggregate commitment record",
            ));
        }
        if accepted_record.aggregate_opening_root != verified_credential.opening_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "local target-decryption compact aggregate opening root does not match the accepted aggregate commitment record",
            ));
        }
        active_credential_bindings[limb_index] = Some(CompactAggregateOpeningCredentialBinding {
            limb_index,
            rns_prime: expected_modulus,
            aggregate_commitment_root: verified_credential.commitment_root,
            aggregate_opening_root: verified_credential.opening_root,
            aggregate_commitment_message_values: verified_credential
                .aggregate_commitment_message_values,
            aggregate_randomness_by_column: verified_credential.aggregate_randomness_by_column,
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
        setup_epoch: setup_epoch.to_string(),
        smudging_seed_hex,
        smudging_polynomial_openings,
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
// Development-only dealer: this reshares the actual secret coefficient (Shamir
// constant term) with a per-prime degree-(t-1) polynomial derived
// deterministically from private_setup_seed, so reconstruction at x=0 returns s.
// This is a centralized dealer simulating a DKG, not a real distributed key
// generation; the shares are only as private as the seed. The random
// coefficients are domain-separated by the private seed, the target-share
// profile hash, and the limb, but NOT by the accepted setup package hash: the
// accepted package embeds the compact aggregate-threshold commitments derived
// from these very shares, so folding the package hash into the polynomial would
// be circular (the shares would depend on a hash that depends on the shares).
// The constant term is still the secret, so recombination at x=0 is unchanged.
pub(super) fn derive_threshold_secret_share_limb(
    secret: &[i64],
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
) -> String {
    hash512_hex(
        TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN,
        &[
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
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "LocalTrusteeTargetDecryptionSmudgingWitness",
        "objectVersion": 1,
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
    }))
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
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging bound overflowed",
                )
            })?;
        evaluation_point_power = evaluation_point_power
            .checked_mul(i128::from(interpolation_point))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging bound overflowed",
                )
            })?;
    }
    let bound = accumulated_power_sum
        .checked_mul(i128::from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target-decryption smudging bound overflowed",
            )
        })?;

    u64::try_from(bound).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption smudging bound does not fit a non-negative integer",
        )
    })
}

struct TargetSmudgingNoiseShare {
    residues: Vec<u64>,
    maximum_absolute_noise_share: u64,
}

fn apply_plaintext_multiple_zero_share_smudging(
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    partials_by_limb: &[Vec<u64>],
) -> CanonicalResult<(Vec<Vec<u64>>, Value)> {
    let mut smudged_partials = partials_by_limb.to_vec();
    let mut limb_reports = Vec::with_capacity(smudged_partials.len());
    for (rns_limb_index, limb_partials) in smudged_partials.iter_mut().enumerate() {
        let rns_prime = DATA_PRIMES[rns_limb_index];
        let noise_share = target_decryption_smudging_noise_share_from_openings(
            target_share_profile,
            participant,
            smudging_polynomial_openings,
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
fn target_decryption_smudging_noise_share_from_openings(
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<TargetSmudgingNoiseShare> {
    let mut residues = vec![0_u64; POLYNOMIAL_DEGREE];
    let mut centered_values = vec![0_i128; POLYNOMIAL_DEGREE];
    let evaluation_point = participant.interpolation_point % rns_prime;
    let mut evaluation_point_power_mod = evaluation_point;
    let mut evaluation_point_power_wide = i128::from(participant.interpolation_point);
    let polynomial_openings = target_decryption_smudging_polynomial_openings_for_limb(
        target_share_profile,
        smudging_polynomial_openings,
        role,
        rns_limb_index,
        rns_prime,
    )?;
    for polynomial_opening in polynomial_openings {
        for ((residue, centered_value), sampled_coefficient) in residues
            .iter_mut()
            .zip(centered_values.iter_mut())
            .zip(polynomial_opening.polynomial_coefficients.iter())
        {
            let residue_term = mul_mod_fast(
                signed_residue(*sampled_coefficient, rns_prime),
                evaluation_point_power_mod,
                rns_prime,
            );
            *residue = add_mod_fast(*residue, residue_term, rns_prime);
            let centered_term = i128::from(*sampled_coefficient)
                .checked_mul(evaluation_point_power_wide)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "target-decryption smudging coefficient evaluation overflowed",
                    )
                })?;
            *centered_value = centered_value.checked_add(centered_term).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
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
                    CanonicalErrorCode::ComponentMismatch,
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
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging evaluated share does not fit a signed integer",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut maximum_absolute_noise_share = 0_u64;
    for coefficient in &centered_i64_values {
        maximum_absolute_noise_share = maximum_absolute_noise_share.max(coefficient.unsigned_abs());
    }

    Ok(TargetSmudgingNoiseShare {
        residues,
        maximum_absolute_noise_share,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn target_decryption_smudging_polynomial_coefficients(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let smudging_seed_bytes = decode_hex(smudging_seed_hex)?;
    if smudging_seed_bytes.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption smudging seed must be a 64-byte lowercase hexadecimal value",
        ));
    }
    if !TARGET_DECRYPTION_SMUDGING_ROLES.contains(&role) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption smudging role is not supported",
        ));
    }
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();
    let minimum_shares_bytes =
        (target_share_profile.minimum_shares_for_interpolation as u64).to_le_bytes();
    let coefficient_span = u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND * 2 + 1)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target-decryption smudging coefficient bound is invalid",
            )
        })?;

    (1..target_share_profile.minimum_shares_for_interpolation)
        .map(|polynomial_degree| {
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

            sampler
                .uniform_residues(coefficient_span, POLYNOMIAL_DEGREE)
                .into_iter()
                .map(|sampled_coefficient| {
                    i64::try_from(sampled_coefficient).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "target-decryption smudging coefficient does not fit a signed integer",
                        )
                    }).map(|value| value - TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

pub(super) fn target_decryption_smudging_polynomial_openings(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
) -> CanonicalResult<Vec<TargetDecryptionSmudgingPolynomialOpening>> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let mut openings = Vec::with_capacity(
        TARGET_DECRYPTION_SMUDGING_ROLES.len()
            * active_limb_count
            * target_share_profile
                .minimum_shares_for_interpolation
                .saturating_sub(1),
    );
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            let coefficients_by_degree = target_decryption_smudging_polynomial_coefficients(
                setup_binding,
                target_accepted,
                target_ciphertexts,
                target_share_profile,
                smudging_seed_hex,
                role,
                rns_limb_index,
                rns_prime,
            )?;
            for (degree_offset, polynomial_coefficients) in
                coefficients_by_degree.into_iter().enumerate()
            {
                openings.push(TargetDecryptionSmudgingPolynomialOpening {
                    role: role.to_string(),
                    rns_limb_index,
                    rns_prime,
                    polynomial_degree: degree_offset + 1,
                    polynomial_coefficients,
                });
            }
        }
    }

    Ok(openings)
}

fn target_decryption_smudging_polynomial_openings_for_limb<'a>(
    target_share_profile: &TargetShareProfile,
    smudging_polynomial_openings: &'a [TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<&'a TargetDecryptionSmudgingPolynomialOpening>> {
    let smudging_polynomial_degree = target_share_profile
        .minimum_shares_for_interpolation
        .checked_sub(1)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target-decryption smudging polynomial degree is invalid",
            )
        })?;
    let mut openings_by_degree = vec![None; smudging_polynomial_degree + 1];
    for opening in smudging_polynomial_openings.iter().filter(|opening| {
        opening.role == role
            && opening.rns_limb_index == rns_limb_index
            && opening.rns_prime == rns_prime
    }) {
        if opening.polynomial_degree == 0
            || opening.polynomial_degree > smudging_polynomial_degree
            || opening.polynomial_coefficients.len() != POLYNOMIAL_DEGREE
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption smudging polynomial opening has an invalid degree or coefficient count",
            ));
        }
        if openings_by_degree[opening.polynomial_degree].is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption smudging polynomial openings contain a duplicate degree",
            ));
        }
        openings_by_degree[opening.polynomial_degree] = Some(opening);
    }

    (1..=smudging_polynomial_degree)
        .map(|polynomial_degree| {
            openings_by_degree[polynomial_degree].ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption smudging polynomial openings are missing an active degree",
                )
            })
        })
        .collect()
}

pub(super) fn target_decryption_smudging_commitment_set_from_polynomial_openings(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
) -> CanonicalResult<TargetDecryptionSmudgingCommitmentSet> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let smudging_polynomial_degree = target_share_profile
        .minimum_shares_for_interpolation
        .saturating_sub(1);
    let expected_record_count =
        TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count * smudging_polynomial_degree;
    if smudging_polynomial_openings.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption smudging polynomial openings do not cover the active target statement",
        ));
    }
    let mut records = Vec::with_capacity(expected_record_count);
    let mut opening_index = 0;
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            for polynomial_degree in 1..=smudging_polynomial_degree {
                let opening = &smudging_polynomial_openings[opening_index];
                if opening.role != role
                    || opening.rns_limb_index != rns_limb_index
                    || opening.rns_prime != rns_prime
                    || opening.polynomial_degree != polynomial_degree
                    || opening.polynomial_coefficients.len() != POLYNOMIAL_DEGREE
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target-decryption smudging polynomial openings are not in canonical statement order",
                    ));
                }
                let commitment_opening = target_decryption_smudging_commitment_opening(
                    setup_binding,
                    target_accepted,
                    target_ciphertexts,
                    target_share_profile,
                    smudging_seed_hex,
                    opening,
                )?;
                records.push(target_decryption_smudging_commitment_record(
                    &commitment_opening,
                )?);
                opening_index += 1;
            }
        }
    }

    let mut value = json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "objectVersion": 1,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "publicMatrixSeedHash": setup_binding.public_matrix_seed_hash,
        "activeRnsLimbCount": active_limb_count,
        "ringDegree": POLYNOMIAL_DEGREE,
        "smudgingCoefficientBound": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
        "signedCoefficientOffset": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
        "messageCoefficientBound": (TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND as u64) * 2 + 1,
        "smudgingPolynomialDegree": smudging_polynomial_degree,
        "commitmentRole": TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
        "commitmentRecords": records,
    });
    let root = derive_canonical_object_hash(&value)?;
    value["smudgingCommitmentSetRoot"] = json!(root);

    Ok(TargetDecryptionSmudgingCommitmentSet { value, root })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn target_decryption_smudging_proof_openings_for_slice(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<TargetDecryptionSmudgingProofOpening>> {
    target_decryption_smudging_polynomial_openings_for_limb(
        target_share_profile,
        smudging_polynomial_openings,
        role,
        rns_limb_index,
        rns_prime,
    )?
    .into_iter()
    .map(|polynomial_opening| {
        let commitment_opening = target_decryption_smudging_commitment_opening(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            smudging_seed_hex,
            polynomial_opening,
        )?;
        Ok(TargetDecryptionSmudgingProofOpening {
            message_coefficients: commitment_opening.message_coefficients,
            randomness_by_column: commitment_opening.randomness_by_column,
        })
    })
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_commitment_opening(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    polynomial_opening: &TargetDecryptionSmudgingPolynomialOpening,
) -> CanonicalResult<TargetDecryptionSmudgingCommitmentOpening> {
    let coefficient_offset = TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;
    let message_coefficients = polynomial_opening
        .polynomial_coefficients
        .iter()
        .map(|coefficient| {
            let shifted = coefficient.checked_add(coefficient_offset).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging coefficient encoding overflowed",
                )
            })?;
            u64::try_from(shifted).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging coefficient is outside the commitment encoding range",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_by_column = target_decryption_smudging_commitment_randomness_by_column(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        smudging_seed_hex,
        &polynomial_opening.role,
        polynomial_opening.rns_limb_index,
        polynomial_opening.rns_prime,
        polynomial_opening.polynomial_degree,
    )?;
    let commitment_context = target_decryption_smudging_commitment_context(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        &polynomial_opening.role,
        polynomial_opening.rns_limb_index,
        polynomial_opening.rns_prime,
        polynomial_opening.polynomial_degree,
    );

    Ok(TargetDecryptionSmudgingCommitmentOpening {
        role: polynomial_opening.role.clone(),
        rns_limb_index: polynomial_opening.rns_limb_index,
        rns_prime: polynomial_opening.rns_prime,
        polynomial_degree: polynomial_opening.polynomial_degree,
        message_coefficients,
        randomness_by_column,
        commitment_context,
        public_matrix_seed_hash: setup_binding.public_matrix_seed_hash.clone(),
    })
}

fn target_decryption_smudging_commitment_record(
    opening: &TargetDecryptionSmudgingCommitmentOpening,
) -> CanonicalResult<Value> {
    let message_digit_columns = crate::bgv::setup::compact_vss_canonical_message_digit_columns(
        &opening.message_coefficients,
        POLYNOMIAL_DEGREE,
    )?;
    let computation =
        compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
            commitment_role: TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
            commitment_context: &opening.commitment_context,
            public_matrix_seed_hash: &opening.public_matrix_seed_hash,
            rns_limb_index: opening.rns_limb_index,
            rns_prime: opening.rns_prime,
            ring_degree: POLYNOMIAL_DEGREE,
            message_coefficients: &opening.message_coefficients,
            message_digit_columns: &message_digit_columns,
            message_coefficient_bound: (TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND as u64) * 2
                + 1,
            randomness_by_column: &opening.randomness_by_column,
        })?;

    Ok(json!({
        "objectType": "TargetDecryptionSmudgingCommitment",
        "objectVersion": 1,
        "role": opening.role.as_str(),
        "rnsLimbIndex": opening.rns_limb_index,
        "rnsPrime": opening.rns_prime,
        "polynomialDegree": opening.polynomial_degree,
        "commitmentRoot": computation.commitment_root,
        "commitment": computation.commitment,
    }))
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_commitment_randomness_by_column(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    polynomial_degree: usize,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let smudging_seed_bytes = decode_hex(smudging_seed_hex)?;
    if smudging_seed_bytes.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption smudging seed must be a 64-byte lowercase hexadecimal value",
        ));
    }
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();
    let polynomial_degree_bytes = (polynomial_degree as u64).to_le_bytes();

    (0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            let column_index_bytes = (column_index as u64).to_le_bytes();
            let mut sampler = DeterministicSampler::new(
                TARGET_DECRYPTION_SMUDGING_COMMITMENT_RANDOMNESS_DOMAIN,
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
                    &polynomial_degree_bytes,
                    &column_index_bytes,
                ],
            );
            sampler
                .uniform_residues(3, POLYNOMIAL_DEGREE)
                .into_iter()
                .map(|value| {
                    i64::try_from(value).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "target-decryption smudging commitment randomness does not fit a signed integer",
                        )
                    }).map(|coefficient| coefficient - 1)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_commitment_context(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    polynomial_degree: usize,
) -> Value {
    json!({
        "objectType": "TargetDecryptionSmudgingPolynomialCoefficientCommitmentContext",
        "objectVersion": 1,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "role": role,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "polynomialDegree": polynomial_degree,
        "signedCoefficientOffset": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
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
        "roleReports": [
            target_id_smudging_report,
            target_order_smudging_report,
        ],
    })
}

// Development target shares now add plaintext-multiple Shamir zero-share masks
// before release. The report binds numeric parameters, but a production
// target-decryption path still needs a zero-knowledge proof that the smudged
// share and compact opening witness satisfy the stated relation.
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
