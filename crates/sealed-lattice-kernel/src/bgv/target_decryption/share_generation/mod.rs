use super::*;

mod smudging;
pub(super) use self::smudging::*;

pub(super) struct LocalTargetDecryptionShareWitness {
    pub(super) secret_share_by_limb: Vec<Vec<u64>>,
    pub(super) setup_epoch: String,
    pub(super) smudging_seed_hex: String,
    pub(super) smudging_polynomial_openings: Vec<TargetDecryptionSmudgingPolynomialOpening>,
    pub(super) opening: AggregateOpeningWitnessBinding,
}

pub(super) struct AggregateOpeningWitnessBinding {
    pub(super) public_matrix_seed_hash: String,
    pub(super) share_linkage_statement_root: String,
    pub(super) aggregate_threshold_commitment_root: String,
    pub(super) active_credential_bindings: Vec<AggregateOpeningCredentialBinding>,
}

pub(super) struct AggregateOpeningCredentialBinding {
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

    let opening = value_at_path(witness, &["aggregateOpening"])?;
    if string_at_path(opening, &["objectType"])? != "LocalTrusteeVssPublicAggregateOpeningWitness"
        || unsigned_at_path(opening, &["objectVersion"])? != 1
    {
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
    let public_matrix_seed_hash = setup_binding.public_matrix_seed_hash.clone();
    let share_linkage_statement_root =
        hash_at_path(opening, &["shareLinkageStatementRoot"])?.to_string();
    let aggregate_threshold_commitment_root =
        hash_at_path(opening, &["aggregateThresholdCommitmentRoot"])?.to_string();
    let accepted_share_linkage_statement_root = setup_binding
        .share_linkage_statement_root
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "local target-decryption aggregate opening requires the accepted share-linkage statement",
            )
        })?;
    if &share_linkage_statement_root != accepted_share_linkage_statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "local target-decryption share-linkage statement root does not match the accepted setup statement",
        ));
    }
    let aggregate_threshold_commitment_set = setup_binding
        .aggregate_threshold_commitment_set
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "local target-decryption aggregate opening requires the accepted aggregate threshold commitment set",
            )
        })?;
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
            || unsigned_at_path(credential, &["objectVersion"])? != 1
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
            participant.interpolation_point,
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
                public_matrix_seed_hash: &public_matrix_seed_hash,
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
        opening: AggregateOpeningWitnessBinding {
            public_matrix_seed_hash,
            share_linkage_statement_root,
            aggregate_threshold_commitment_root,
            active_credential_bindings,
        },
    })
}

#[cfg(test)]
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
// accepted package embeds the aggregate-threshold commitments derived
// from these very shares, so folding the package hash into the polynomial would
// be circular (the shares would depend on a hash that depends on the shares).
// The constant term is still the secret, so recombination at x=0 is unchanged.
#[cfg(test)]
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

// Development target shares now add plaintext-multiple Shamir zero-share masks
// before release. The report binds numeric parameters, but a production
// target-decryption path still needs a zero-knowledge proof that the smudged
// share and opening witness satisfy the stated relation.
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
