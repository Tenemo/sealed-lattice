use super::*;

const DIRECT_BALLOT_AGGREGATE_PACKAGE_INPUT_FIELDS: &[&str] = &[
    "voterSigningPublicKeyHash",
    "encryptedBallotPackage",
    "proofChunks",
];

pub(crate) fn aggregate_direct_encrypted_ballot_packages(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_public_aggregation_private_fields(request)?;
    reject_unexpected_direct_ballot_object_fields(
        request,
        "aggregateDirectEncryptedBallotPackages request",
        &[
            "command",
            "acceptedPublicKeyMaterial",
            "acceptedSetupHandoff",
            "encryptedBallotPackages",
            "firstValidOrderHash",
            "firstValidPackageRoots",
        ],
    )?;
    reject_incomplete_direct_ballot_first_valid_binding(request)?;
    let accepted_public_key_material = required_object_field(request, "acceptedPublicKeyMaterial")?;
    let accepted_setup_handoff = required_object_field(request, "acceptedSetupHandoff")?;
    let accepted_setup_handoff_root =
        validate_direct_ballot_setup_handoff(accepted_public_key_material, accepted_setup_handoff)?;
    let package_inputs = request
        .get("encryptedBallotPackages")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encryptedBallotPackages must be an array",
            )
        })?;
    if package_inputs.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot aggregation requires at least one package",
        ));
    }
    if package_inputs.len() > DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot aggregation currently supports at most twenty packages",
        ));
    }

    let mut package_verifications = Vec::with_capacity(package_inputs.len());
    for (package_index, package_input) in package_inputs.iter().enumerate() {
        reject_unexpected_direct_ballot_object_fields(
            package_input,
            &format!("encryptedBallotPackages[{package_index}]"),
            DIRECT_BALLOT_AGGREGATE_PACKAGE_INPUT_FIELDS,
        )?;
        let verification_request = json!({
            "acceptedPublicKeyMaterial": accepted_public_key_material,
            "acceptedSetupHandoff": accepted_setup_handoff,
            "voterSigningPublicKeyHash": required_string_field(package_input, "voterSigningPublicKeyHash")?,
            "encryptedBallotPackage": required_object_field(package_input, "encryptedBallotPackage")?,
            "proofChunks": package_input.get("proofChunks").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encryptedBallotPackages[].proofChunks must be an array",
                )
            })?,
        });
        let verification = verify_direct_encrypted_ballot_package_request(&verification_request)?;
        if verification.accepted_setup_handoff_root.as_str() != accepted_setup_handoff_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "verified package setup handoff root does not match the aggregation setup handoff",
            ));
        }
        package_verifications.push(verification);
    }

    validate_verified_package_set(&package_verifications)?;
    let first_valid_binding =
        optional_direct_ballot_first_valid_binding(request, &package_verifications)?;
    aggregate_verified_direct_ballot_packages(
        accepted_public_key_material,
        &accepted_setup_handoff_root,
        package_verifications,
        first_valid_binding,
    )
}

pub(super) fn aggregate_verified_direct_ballot_packages(
    accepted_public_key_material: &Value,
    accepted_setup_handoff_root: &str,
    mut package_verifications: Vec<DirectBallotPackageVerification>,
    first_valid_binding: Option<DirectBallotFirstValidBinding>,
) -> CanonicalResult<Value> {
    validate_verified_package_set(&package_verifications)?;
    package_verifications.sort_by(|left, right| left.package_root.cmp(&right.package_root));

    let aggregate_ciphertext = aggregate_verified_package_ciphertexts(&package_verifications)?;
    let aggregate_ciphertext_root = ciphertext_object_root(&aggregate_ciphertext)?;
    let aggregate_ciphertext_transport =
        direct_ballot_ciphertext_transport(&aggregate_ciphertext, &aggregate_ciphertext_root)?;
    let aggregate_certificate = direct_ballot_public_aggregate_certificate(
        accepted_public_key_material,
        &accepted_setup_handoff_root,
        &package_verifications,
        first_valid_binding.as_ref(),
        &aggregate_ciphertext_root,
        &aggregate_ciphertext_transport,
    )?;
    let package_records = verified_package_records(&package_verifications);
    let package_verification_certificate_hashes = package_verifications
        .iter()
        .map(|verification| verification.package_verification_certificate_hash.clone())
        .collect::<Vec<_>>();
    let package_roots = package_verifications
        .iter()
        .map(|verification| verification.package_root.clone())
        .collect::<Vec<_>>();
    let ciphertext_roots = package_verifications
        .iter()
        .map(|verification| verification.ciphertext_root.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "operation": DIRECT_BALLOT_PUBLIC_AGGREGATE_OPERATION,
        "aggregationStatus": "accepted encrypted ballot packages were reverified from public artifacts and their BGV ciphertexts were aggregated",
        "acceptedSetupHandoffRoot": accepted_setup_handoff_root,
        "ballotCount": package_verifications.len(),
        "packageRoots": package_roots,
        "ciphertextRoots": ciphertext_roots,
        "firstValidOrderHash": first_valid_binding.as_ref().map(|binding| binding.order_hash.as_str()),
        "firstValidPackageRoots": first_valid_binding.as_ref().map(|binding| binding.package_roots.as_slice()),
        "packageVerificationCertificateHashes": package_verification_certificate_hashes,
        "verifiedPackages": package_records,
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextTransport": aggregate_ciphertext_transport,
        "aggregateCertificateHash": aggregate_certificate.hash,
        "aggregateCertificate": aggregate_certificate.value,
        "claimBoundary": "This command performs accepted public aggregation only: it re-verifies package signatures, package roots, ciphertext transports, proof chunks, statement bindings, verifier-certificate bindings, relation proofs, and package verification certificates, then sums the verified public BGV ciphertexts. It does not decrypt, score, rank, evaluate top-count targets, accept plaintext witnesses, accept fixture randomness, or use a development oracle.",
    }))
}

pub(super) fn verify_direct_ballot_aggregation(
    evaluator_key: &DevelopmentBgvKey,
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<DirectBallotAggregationResult> {
    let mut aggregate_ciphertext = encrypted_ballots
        .first()
        .map(|ballot| ballot.ciphertext.clone())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregation requires at least one ballot",
            )
        })?;
    for encrypted_ballot in encrypted_ballots.iter().skip(1) {
        aggregate_ciphertext = ciphertext_add(&aggregate_ciphertext, &encrypted_ballot.ciphertext)?;
    }

    let aggregate_slots = evaluator_key.decrypt_to_slots(&aggregate_ciphertext)?;
    let aggregate_scores = aggregate_slots[..DIRECT_BALLOT_OPTION_COUNT].to_vec();
    let expected_scores = direct_ballot_plaintext_aggregate_scores(encrypted_ballots)?;
    if aggregate_scores != expected_scores {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot aggregate scores do not match the plaintext oracle",
        ));
    }
    if aggregate_slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot aggregate has a non-zero reserved slot",
        ));
    }
    let aggregate_ciphertext_root = ciphertext_object_root(&aggregate_ciphertext)?;
    let aggregate_ciphertext_canonical_bytes_hex =
        ciphertext_canonical_bytes_hex(&aggregate_ciphertext)?;

    let report = json!({
        "result": "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and privately checked the aggregate against the plaintext oracle without publishing aggregate scores.",
        "ballotCount": encrypted_ballots.len(),
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_bytes_hex.len() / 2,
        "privateCorrectnessCheck": "aggregate score slots matched the plaintext oracle"
    });

    Ok(DirectBallotAggregationResult {
        report,
        aggregate_ciphertext,
        aggregate_scores,
    })
}

struct DirectBallotPublicAggregateCertificate {
    hash: String,
    value: Value,
}

#[derive(Debug)]
pub(super) struct DirectBallotFirstValidBinding {
    pub(super) order_hash: String,
    pub(super) package_roots: Vec<String>,
}

fn aggregate_verified_package_ciphertexts(
    package_verifications: &[DirectBallotPackageVerification],
) -> CanonicalResult<Ciphertext> {
    let mut aggregate_ciphertext = package_verifications
        .first()
        .map(|verification| verification.ballot.ciphertext.clone())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregation requires at least one verified package",
            )
        })?;
    for verification in package_verifications.iter().skip(1) {
        aggregate_ciphertext =
            ciphertext_add(&aggregate_ciphertext, &verification.ballot.ciphertext)?;
    }

    Ok(aggregate_ciphertext)
}

fn validate_verified_package_set(
    package_verifications: &[DirectBallotPackageVerification],
) -> CanonicalResult<()> {
    let package_roots = package_verifications
        .iter()
        .map(|verification| verification.package_root.clone())
        .collect::<Vec<_>>();
    validate_unique_strings(
        &package_roots,
        "encryptedBallotPackages.packageRoot",
        "duplicates a package root",
    )?;
    let ciphertext_roots = package_verifications
        .iter()
        .map(|verification| verification.ciphertext_root.clone())
        .collect::<Vec<_>>();
    validate_unique_strings(
        &ciphertext_roots,
        "encryptedBallotPackages.ciphertextRoot",
        "duplicates a ciphertext root",
    )?;

    let mut voter_identities = BTreeSet::new();
    let mut voter_roster_positions = BTreeSet::new();
    for verification in package_verifications {
        if !voter_identities.insert(verification.voter_identity.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot aggregation contains a duplicate voter identity",
            ));
        }
        if !voter_roster_positions.insert(verification.voter_roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot aggregation contains a duplicate voter roster position",
            ));
        }
    }

    Ok(())
}

pub(super) fn optional_direct_ballot_first_valid_binding(
    request: &Value,
    package_verifications: &[DirectBallotPackageVerification],
) -> CanonicalResult<Option<DirectBallotFirstValidBinding>> {
    reject_incomplete_direct_ballot_first_valid_binding(request)?;
    let has_order_hash = request.get("firstValidOrderHash").is_some();
    let has_package_roots = request.get("firstValidPackageRoots").is_some();
    if !has_order_hash && !has_package_roots {
        return Ok(None);
    }

    let order_hash = required_string_field(request, "firstValidOrderHash")?.to_string();
    validate_direct_ballot_hash_hex(&order_hash, "firstValidOrderHash")?;
    let package_roots = required_string_array_field(request, "firstValidPackageRoots")?;
    if package_roots.len() != package_verifications.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "firstValidPackageRoots length must match the verified package count",
        ));
    }
    validate_unique_strings(
        &package_roots,
        "firstValidPackageRoots",
        "duplicates a package root",
    )?;

    let verified_package_roots = package_verifications
        .iter()
        .map(|verification| verification.package_root.as_str())
        .collect::<BTreeSet<_>>();
    for (package_root_index, package_root) in package_roots.iter().enumerate() {
        validate_direct_ballot_hash_hex(
            package_root,
            &format!("firstValidPackageRoots[{package_root_index}]"),
        )?;
        if !verified_package_roots.contains(package_root.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "firstValidPackageRoots must exactly match the verified package roots",
            ));
        }
    }

    Ok(Some(DirectBallotFirstValidBinding {
        order_hash,
        package_roots,
    }))
}

fn reject_incomplete_direct_ballot_first_valid_binding(request: &Value) -> CanonicalResult<()> {
    let has_order_hash = request.get("firstValidOrderHash").is_some();
    let has_package_roots = request.get("firstValidPackageRoots").is_some();
    if has_order_hash != has_package_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateDirectEncryptedBallotPackages requires firstValidOrderHash and firstValidPackageRoots together",
        ));
    }

    Ok(())
}

fn direct_ballot_public_aggregate_certificate(
    accepted_public_key_material: &Value,
    accepted_setup_handoff_root: &str,
    package_verifications: &[DirectBallotPackageVerification],
    first_valid_binding: Option<&DirectBallotFirstValidBinding>,
    aggregate_ciphertext_root: &str,
    aggregate_ciphertext_transport: &Value,
) -> CanonicalResult<DirectBallotPublicAggregateCertificate> {
    let setup_context = direct_ballot_setup_context(accepted_public_key_material)?;
    let profile_binding = direct_ballot_profile_binding(accepted_public_key_material)?;
    let package_records = verified_package_records(package_verifications);
    let public_aggregation_inputs = package_verifications
        .iter()
        .map(|verification| verification.public_aggregation_input.clone())
        .collect::<Vec<_>>();
    let aggregate_ciphertext_canonical_byte_length =
        required_usize_field(aggregate_ciphertext_transport, "canonicalByteLength")?;

    let mut certificate = json!({
        "objectType": "DirectEncryptedBallotAggregateCertificate",
        "objectVersion": 1,
        "aggregation": "accepted encrypted ballot packages were reverified from public artifacts and aggregated by BGV ciphertext addition",
        "claimBoundary": "the aggregate certificate binds public package verification certificates and the aggregate ciphertext transport; it does not claim target decryption, plaintext tally recovery, top-count evaluation, mobile runtime evidence, or production readiness",
        "ceremonyId": setup_context.ceremony_id,
        "manifestHash": setup_context.manifest_hash,
        "rosterHash": setup_context.roster_hash,
        "thresholdProfileHash": setup_context.threshold_profile_hash,
        "acceptedSetupHandoffRoot": accepted_setup_handoff_root,
        "setupPackageRoot": setup_context.setup_package_root,
        "setupProfileHash": setup_context.setup_profile_hash,
        "collectivePublicKeyRoot": setup_context.collective_public_key_root,
        "bgvPublicKeyRoot": setup_context.bgv_public_key_root,
        "bgvProfileHash": profile_binding.bgv_profile_hash,
        "batchEncoderHash": profile_binding.batch_encoder_hash,
        "batchLayoutBindingHash": profile_binding.batch_layout_binding_hash,
        "ballotScoreEncodingProfileHash": profile_binding.ballot_score_encoding_profile_hash,
        "encryptedBallotLayoutHash": profile_binding.encrypted_ballot_layout_hash,
        "directBallotReservedSlotRuleHash": profile_binding.direct_ballot_reserved_slot_rule_hash,
        "directBallotEncoderMatrixRoot": profile_binding.direct_ballot_encoder_matrix_root,
        "verifierCertificateHash": profile_binding.verifier_certificate_hash,
        "proofProfileHash": direct_ballot_relation_proof_profile_hash()?,
        "ballotCount": package_verifications.len(),
        "firstValidOrderHash": first_valid_binding.map(|binding| binding.order_hash.as_str()),
        "firstValidPackageRoots": first_valid_binding.map(|binding| binding.package_roots.as_slice()),
        "packageVerificationInputs": public_aggregation_inputs,
        "verifiedPackages": package_records,
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_byte_length,
        "aggregateCiphertextTransport": aggregate_ciphertext_transport,
    });
    let certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotAggregateCertificateHash",
        &certificate,
    )?;
    certificate
        .as_object_mut()
        .expect("direct encrypted ballot aggregate certificate is an object")
        .insert(
            "aggregateCertificateHash".to_string(),
            json!(certificate_hash.clone()),
        );

    Ok(DirectBallotPublicAggregateCertificate {
        hash: certificate_hash,
        value: certificate,
    })
}

fn verified_package_records(
    package_verifications: &[DirectBallotPackageVerification],
) -> Vec<Value> {
    package_verifications
        .iter()
        .map(|verification| {
            json!({
                "packageRoot": verification.package_root.as_str(),
                "ciphertextRoot": verification.ciphertext_root.as_str(),
                "proofStatementHash": verification.proof_statement_hash.as_str(),
                "proofChunkRoot": verification.proof_chunk_root.as_str(),
                "packageVerificationCertificateHash": verification.package_verification_certificate_hash.as_str(),
                "voterIdentity": verification.voter_identity.as_str(),
                "voterRosterPosition": verification.voter_roster_position,
                "signatureHash": verification.signature_hash.as_str(),
            })
        })
        .collect()
}

fn reject_public_aggregation_private_fields(request: &Value) -> CanonicalResult<()> {
    for field_name in [
        "setupPackage",
        "setupPublicMaterial",
        "setupPrivateWitness",
        "ballots",
        "scores",
        "ballotEncryptionRandomness",
        "proofMaskRandomness",
        "topCount",
        "topCounts",
        "publicEvaluationKeyMaterial",
        "targetFinalityPolicyHash",
    ] {
        if request.get(field_name).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("aggregateDirectEncryptedBallotPackages does not accept {field_name}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn direct_ballot_plaintext_aggregate_scores(
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<Vec<u64>> {
    let mut aggregate_scores = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
    for encrypted_ballot in encrypted_ballots {
        if encrypted_ballot.input.scores.len() != DIRECT_BALLOT_OPTION_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregate oracle requires each ballot to have twenty scores",
            ));
        }
        for (aggregate_score, score) in aggregate_scores
            .iter_mut()
            .zip(encrypted_ballot.input.scores.iter())
        {
            *aggregate_score = add_mod(*aggregate_score, *score, PLAINTEXT_MODULUS)?;
        }
    }

    Ok(aggregate_scores)
}
