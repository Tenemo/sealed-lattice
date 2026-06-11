use super::*;

pub(super) fn verify_common_randomness(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(common_randomness) = setup_package.get("commonRandomness") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessCommit"),
            vec!["commonRandomness".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !common_randomness.is_object() {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessNotObject",
            "commonRandomness must be a JSON object",
            "setupPackage.commonRandomness",
        )?));
    }
    if common_randomness.get("objectType").and_then(Value::as_str) != Some("SetupCommonRandomness")
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessObjectTypeMismatch",
            "commonRandomness.objectType must be SetupCommonRandomness",
            "setupPackage.commonRandomness.objectType",
        )?));
    }
    if common_randomness
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessObjectVersionMismatch",
            "commonRandomness.objectVersion must be 1",
            "setupPackage.commonRandomness.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before common randomness verification",
        )
    })?;
    if let Some(response) = verify_common_randomness_context(common_randomness, setup_context)? {
        return Ok(Some(response));
    }

    let Some(commit_records) = common_randomness
        .get("commitRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessCommit"),
            vec!["commonRandomness.commitRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let Some(reveal_records) = common_randomness
        .get("revealRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessReveal"),
            vec!["commonRandomness.revealRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if commit_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessCommitCountMismatch",
            "commonRandomness.commitRecords must contain one commit per participant",
            "setupPackage.commonRandomness.commitRecords",
        )?));
    }
    if reveal_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRevealCountMismatch",
            "commonRandomness.revealRecords must contain one reveal per participant",
            "setupPackage.commonRandomness.revealRecords",
        )?));
    }

    let mut commit_reveal_hashes_by_position = BTreeMap::<u64, String>::new();
    for commit_record in commit_records {
        let (roster_position, reveal_hash) =
            verify_common_randomness_commit_record(commit_record, setup_context)?;
        if commit_reveal_hashes_by_position
            .insert(roster_position, reveal_hash)
            .is_some()
        {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessCommitDuplicate",
                "commonRandomness.commitRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.commitRecords",
            )?));
        }
    }

    let mut ordered_reveal_hashes = BTreeMap::<u64, String>::new();
    for reveal_record in reveal_records {
        let (roster_position, reveal_hash) =
            verify_common_randomness_reveal_record(reveal_record, setup_context)?;
        let Some(committed_reveal_hash) = commit_reveal_hashes_by_position.get(&roster_position)
        else {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealWithoutCommit",
                "commonRandomness.revealRecords contains a reveal without a matching commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        };
        if committed_reveal_hash != &reveal_hash {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealHashMismatch",
                "common-randomness reveal hash does not match the participant commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
        if ordered_reveal_hashes
            .insert(roster_position, reveal_hash)
            .is_some()
        {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealDuplicate",
                "commonRandomness.revealRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
    }
    if ordered_reveal_hashes.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRevealCoverageMismatch",
            "commonRandomness.revealRecords must cover the full first-profile roster",
            "setupPackage.commonRandomness.revealRecords",
        )?));
    }

    let ordered_reveal_hash_values = ordered_reveal_hashes
        .values()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let expected_public_matrix_seed_hash = derive_protocol_hash(
        "SetupPublicMatrixSeedHash",
        &json!({
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "orderedRevealHashes": ordered_reveal_hash_values,
        }),
    )?;
    if common_randomness
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(expected_public_matrix_seed_hash.as_str())
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessPublicMatrixSeedMismatch",
            "commonRandomness.publicMatrixSeedHash does not match the ordered reveal set",
            "setupPackage.commonRandomness.publicMatrixSeedHash",
        )?));
    }
    if let Some(response) =
        verify_public_derivations(common_randomness, &expected_public_matrix_seed_hash)?
    {
        return Ok(Some(response));
    }

    let Some(common_randomness_root) = common_randomness
        .get("commonRandomnessRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessReveal"),
            vec!["commonRandomness.commonRandomnessRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        common_randomness_root,
        "commonRandomness.commonRandomnessRoot",
    )?;
    let mut root_input = common_randomness.clone();
    root_input
        .as_object_mut()
        .expect("commonRandomness object was checked")
        .remove("commonRandomnessRoot");
    let expected_common_randomness_root =
        derive_protocol_hash("SetupCommonRandomnessRoot", &root_input)?;
    if common_randomness_root != expected_common_randomness_root {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRootMismatch",
            "commonRandomness.commonRandomnessRoot does not match the canonical payload",
            "setupPackage.commonRandomness.commonRandomnessRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_derivations(
    common_randomness: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Option<Value>> {
    let Some(public_derivations) = common_randomness.get("publicDerivations") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessReveal"),
            vec!["commonRandomness.publicDerivations".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let expected_public_derivations =
        derive_collective_bgv_setup_public_derivations(public_matrix_seed_hash)?;
    if public_derivations != &expected_public_derivations {
        return Ok(Some(common_randomness_refusal(
            "setupPublicDerivationsMismatch",
            "commonRandomness.publicDerivations does not match the accepted public matrix derivation recipe",
            "setupPackage.commonRandomness.publicDerivations",
        )?));
    }

    Ok(None)
}

pub(super) fn derive_collective_bgv_setup_public_derivations(
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Value> {
    let bgv_public_a = derive_bgv_public_a_polynomial(public_matrix_seed_hash)?;
    let public_matrices = derive_setup_public_matrices(public_matrix_seed_hash)?;
    let mut derivations = json!({
        "objectType": "SetupPublicDerivations",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "bgvPublicA": bgv_public_a,
        "publicMatrices": public_matrices,
        "crpRoots": {
            "publicKeyCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "public-key-crp")?,
            "relinearizationCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "relinearization-crp")?,
            "galoisKeyCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "galois-key-crp")?,
            "commitmentMatrixCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "commitment-matrix-crp")?,
            "proofMatrixCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "proof-matrix-crp")?,
        },
        "status": "deterministic-public-derivations-bound",
    });
    let derivation_root = derive_protocol_hash("SetupPublicDerivationRoot", &derivations)?;
    derivations["publicDerivationRoot"] = Value::String(derivation_root);

    Ok(derivations)
}

pub(super) fn derive_bgv_public_a_polynomial(
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Value> {
    let modulus_derivations = DATA_PRIMES
        .iter()
        .map(|modulus| {
            json!({
                "modulus": modulus,
                "coefficientDerivationHash": hash512_hex(
                    "sealed-lattice-bgv-rns/accepted-public-a-derivation-v1",
                    &[
                        public_matrix_seed_hash.as_bytes(),
                        "accepted-bgv-public-a".as_bytes(),
                        modulus.to_string().as_bytes(),
                    ],
                ),
            })
        })
        .collect::<Vec<_>>();
    let mut public_a = json!({
        "objectType": "BgvPublicAPolynomial",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "derivationLabel": "accepted-bgv-public-a",
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "modulusDerivations": modulus_derivations,
        "sampledResidues": sample_public_residues(
            public_matrix_seed_hash,
            "accepted-bgv-public-a",
            DATA_PRIMES[0],
        ),
    });
    let public_polynomial_root =
        derive_protocol_hash("BGVPublicCommonRandomPolynomialRoot", &public_a)?;
    public_a["publicPolynomialRoot"] = Value::String(public_polynomial_root);

    Ok(public_a)
}

fn derive_setup_public_matrices(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let commitment_matrix = derive_setup_commitment_matrix(public_matrix_seed_hash)?;
    let setup_proof_matrix = derive_setup_proof_matrix(public_matrix_seed_hash)?;
    let mut public_matrices = json!({
        "objectType": "SetupPublicMatrixMaterial",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "commitmentMatrix": commitment_matrix,
        "setupProofMatrix": setup_proof_matrix,
        "materializationStatus": "deterministic-entry-streams-bound",
    });
    let public_matrices_root = derive_protocol_hash("SetupPublicDerivationRoot", &public_matrices)?;
    public_matrices["publicMatricesRoot"] = Value::String(public_matrices_root);

    Ok(public_matrices)
}

fn derive_setup_commitment_matrix(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let crp_root = setup_public_derivation_root(public_matrix_seed_hash, "commitment-matrix-crp")?;
    let sampled_entries = commitment_matrix_sampled_entries(public_matrix_seed_hash)?;
    let mut matrix = json!({
        "objectType": "SetupPublicMatrix",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "matrixKind": "commitment",
        "profileId": SETUP_COMMITMENT_PROFILE_ID,
        "profileStatus": "commitment-profile-bound",
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "commitmentModulusLimbs": setup_commitment_modulus_limb_values(),
        "commitmentModuleRank": SETUP_COMMITMENT_MODULE_RANK,
        "commitmentRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "crpRoot": crp_root,
        "coordinateAxes": [
            "rnsLimbIndex",
            "commitmentModulusIndex",
            "matrixRowIndex",
            "randomnessColumnIndex",
            "ringCoefficientPosition"
        ],
        "rnsLimbCount": DATA_PRIMES.len(),
        "shamirCoefficientCount": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "ringDegree": POLYNOMIAL_DEGREE,
        "entryStreamEncoding": "xof-unbiased-residue-from-coordinate",
        "sampledEntries": sampled_entries,
    });
    let matrix_root = derive_protocol_hash("SetupPublicDerivationRoot", &matrix)?;
    matrix["matrixRoot"] = Value::String(matrix_root);

    Ok(matrix)
}

fn derive_setup_proof_matrix(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let crp_root = setup_public_derivation_root(public_matrix_seed_hash, "proof-matrix-crp")?;
    let sampled_entries = proof_matrix_sampled_entries(public_matrix_seed_hash)?;
    let mut matrix = json!({
        "objectType": "SetupPublicMatrix",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "matrixKind": "setupProof",
        "profileId": SETUP_PROOF_PROFILE_ID,
        "profileStatus": "setup-proof-profile-bound",
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "challengeDomainHash": setup_proof_challenge_domain_hash()?,
        "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
        "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "crpRoot": crp_root,
        "coordinateAxes": [
            "proofFamily",
            "rnsLimbIndex",
            "ringCoefficientPosition"
        ],
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": POLYNOMIAL_DEGREE,
        "entryStreamEncoding": "xof-unbiased-residue-from-coordinate",
        "sampledEntries": sampled_entries,
    });
    let matrix_root = derive_protocol_hash("SetupPublicDerivationRoot", &matrix)?;
    matrix["matrixRoot"] = Value::String(matrix_root);

    Ok(matrix)
}

fn commitment_matrix_sampled_entries(public_matrix_seed_hash: &str) -> CanonicalResult<Vec<Value>> {
    let limb_indices = [0_usize, DATA_PRIMES.len() - 1];
    setup_commitment_matrix_sampled_entries(
        public_matrix_seed_hash,
        &limb_indices,
        &sample_positions(),
    )
}

fn proof_matrix_sampled_entries(public_matrix_seed_hash: &str) -> CanonicalResult<Vec<Value>> {
    let limb_indices = [0_usize, DATA_PRIMES.len() - 1];
    let mut entries = Vec::new();
    for proof_family in SETUP_PROOF_FAMILIES {
        for limb_index in limb_indices {
            for ring_coefficient_position in sample_positions() {
                let coordinate = json!({
                    "proofFamily": proof_family,
                    "rnsLimbIndex": limb_index,
                    "rnsPrime": DATA_PRIMES[limb_index],
                    "ringCoefficientPosition": ring_coefficient_position,
                });
                let entry_derivation_hash = setup_public_matrix_entry_hash(
                    public_matrix_seed_hash,
                    "setupProof",
                    &coordinate,
                )?;
                let coefficient_value = setup_proof_matrix_coefficient(
                    public_matrix_seed_hash,
                    proof_family,
                    limb_index,
                    ring_coefficient_position,
                    DATA_PRIMES[limb_index],
                )?;
                entries.push(json!({
                    "coordinate": coordinate,
                    "coefficientValue": coefficient_value,
                    "entryDerivationHash": entry_derivation_hash,
                }));
            }
        }
    }

    Ok(entries)
}

fn setup_proof_matrix_coefficient(
    public_matrix_seed_hash: &str,
    proof_family: &str,
    rns_limb_index: usize,
    ring_coefficient_position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let rns_limb_text = rns_limb_index.to_string();
    let position_text = ring_coefficient_position.to_string();
    let modulus_text = modulus.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-lnp-setup-proof/matrix-coefficient-v1",
            &[
                public_matrix_seed_hash.as_bytes(),
                proof_family.as_bytes(),
                rns_limb_text.as_bytes(),
                position_text.as_bytes(),
                modulus_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for chunk in output.chunks_exact(8) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            if let Some(reduced_value) = reduce_unbiased_u64(u64::from_le_bytes(word), modulus) {
                return Ok(reduced_value);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setup-proof matrix sampling block index overflow",
            )
        })?;
    }
}

fn setup_public_matrix_entry_hash(
    public_matrix_seed_hash: &str,
    matrix_kind: &str,
    coordinate: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupPublicDerivationRoot",
        &json!({
            "objectType": "SetupPublicMatrixEntryDerivation",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "matrixKind": matrix_kind,
            "coordinate": coordinate,
        }),
    )
}

fn setup_public_derivation_root(
    public_matrix_seed_hash: &str,
    component_name: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupPublicDerivationRoot",
        &json!({
            "objectType": "SetupPublicDerivation",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "componentName": component_name,
        }),
    )
}

fn verify_common_randomness_context(
    value: &Value,
    setup_context: &Value,
) -> CanonicalResult<Option<Value>> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessContextMismatch",
                format!("commonRandomness.{field_name} does not match setupContext"),
                format!("setupPackage.commonRandomness.{field_name}"),
            )?));
        }
    }

    Ok(None)
}

fn verify_common_randomness_commit_record(
    commit_record: &Value,
    setup_context: &Value,
) -> CanonicalResult<(u64, String)> {
    verify_common_randomness_participant_record_shape(
        commit_record,
        setup_context,
        "CommonRandomnessCommit",
        "commonRandomness.commitRecords",
    )?;
    let Some(reveal_hash) = commit_record.get("revealHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.revealHash is required",
        ));
    };
    validate_hash_string(reveal_hash, "CommonRandomnessCommit.revealHash")?;
    let Some(commit_hash) = commit_record.get("commitHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.commitHash is required",
        ));
    };
    validate_hash_string(commit_hash, "CommonRandomnessCommit.commitHash")?;
    let mut hash_input = commit_record.clone();
    hash_input
        .as_object_mut()
        .expect("common-randomness commit object was checked")
        .remove("commitHash");
    let expected_commit_hash = derive_protocol_hash("CommonRandomnessCommitHash", &hash_input)?;
    if commit_hash != expected_commit_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.commitHash does not match its canonical payload",
        ));
    }

    Ok((
        commit_record["rosterPosition"]
            .as_u64()
            .expect("roster position was checked"),
        reveal_hash.to_string(),
    ))
}

fn verify_common_randomness_reveal_record(
    reveal_record: &Value,
    setup_context: &Value,
) -> CanonicalResult<(u64, String)> {
    verify_common_randomness_participant_record_shape(
        reveal_record,
        setup_context,
        "CommonRandomnessReveal",
        "commonRandomness.revealRecords",
    )?;
    let Some(reveal_hex) = reveal_record.get("revealHex").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHex is required",
        ));
    };
    validate_common_randomness_reveal_hex(reveal_hex)?;
    let Some(reveal_hash) = reveal_record.get("revealHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHash is required",
        ));
    };
    validate_hash_string(reveal_hash, "CommonRandomnessReveal.revealHash")?;
    let mut hash_input = reveal_record.clone();
    hash_input
        .as_object_mut()
        .expect("common-randomness reveal object was checked")
        .remove("revealHash");
    let expected_reveal_hash = derive_protocol_hash("CommonRandomnessRevealHash", &hash_input)?;
    if reveal_hash != expected_reveal_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHash does not match its canonical payload",
        ));
    }

    Ok((
        reveal_record["rosterPosition"]
            .as_u64()
            .expect("roster position was checked"),
        reveal_hash.to_string(),
    ))
}

fn verify_common_randomness_participant_record_shape(
    record: &Value,
    setup_context: &Value,
    object_type: &str,
    object_path: &str,
) -> CanonicalResult<()> {
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} entries must be objects"),
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} entries must use {object_type}"),
        ));
    }
    if record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.objectVersion must be 1"),
        ));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "setupEpoch",
    ] {
        if record.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_type}.{field_name} does not match setupContext"),
            ));
        }
    }
    if record.get("signerRole").and_then(Value::as_str) != Some("Trustee") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.signerRole must be Trustee"),
        ));
    }
    let Some(trustee_identity) = record.get("trusteeIdentity").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity is required"),
        ));
    };
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity must be non-empty NFC text"),
        ));
    }
    let Some(roster_position) = record.get("rosterPosition").and_then(Value::as_u64) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is required"),
        ));
    };
    if roster_position >= FIRST_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is outside the first accepted profile"),
        ));
    }
    for field_name in ["recoveryEpoch", "deviceEpoch"] {
        if record.get(field_name).and_then(Value::as_u64).is_none() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_type}.{field_name} is required"),
            ));
        }
    }
    let Some(signature_envelope_hash) = record.get("signatureEnvelopeHash").and_then(Value::as_str)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.signatureEnvelopeHash is required"),
        ));
    };
    validate_hash_string(
        signature_envelope_hash,
        &format!("{object_type}.signatureEnvelopeHash"),
    )?;

    Ok(())
}

fn validate_common_randomness_reveal_hex(reveal_hex: &str) -> CanonicalResult<()> {
    if reveal_hex.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "common-randomness revealHex must contain 64 lowercase hex characters",
        ));
    }
    if !reveal_hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "common-randomness revealHex must be lowercase hexadecimal",
        ));
    }

    Ok(())
}

fn common_randomness_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("commonRandomnessReveal"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
