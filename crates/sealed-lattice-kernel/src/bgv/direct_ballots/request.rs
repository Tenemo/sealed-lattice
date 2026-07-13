use super::*;

pub(super) fn optional_direct_ballot_top_count_request(
    request: &Value,
) -> CanonicalResult<Option<DirectBallotTopCountRequest>> {
    let has_top_count = request.get("topCount").is_some();
    let has_top_counts = request.get("topCounts").is_some();
    if has_top_count && has_top_counts {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "supply either topCount or topCounts, not both",
        ));
    }
    let target_finality_policy_hash = request
        .get("targetFinalityPolicyHash")
        .and_then(Value::as_str)
        .map(|hash| {
            validate_direct_ballot_hash_hex(hash, "targetFinalityPolicyHash")?;
            Ok(hash.to_string())
        })
        .transpose()?;
    if has_top_counts {
        let values = request
            .get("topCounts")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "topCounts must be an array",
                )
            })?;
        if values.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "topCounts must contain at least one top count",
            ));
        }
        let top_counts = values
            .iter()
            .map(read_direct_ballot_top_count_value)
            .collect::<CanonicalResult<Vec<_>>>()?;
        validate_unique_top_counts(&top_counts)?;

        return Ok(Some(DirectBallotTopCountRequest {
            top_counts,
            report_single_result: false,
            target_finality_policy_hash,
        }));
    }

    let Some(value) = request.get("topCount") else {
        return Ok(None);
    };
    let top_count = read_direct_ballot_top_count_value(value)?;

    Ok(Some(DirectBallotTopCountRequest {
        top_counts: vec![top_count],
        report_single_result: true,
        target_finality_policy_hash,
    }))
}

pub(super) fn read_direct_ballot_top_count_value(value: &Value) -> CanonicalResult<usize> {
    let raw_top_count = value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "topCount must be an unsigned integer when supplied",
        )
    })?;
    let top_count = usize::try_from(raw_top_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount does not fit usize",
        )
    })?;
    if top_count == 0 || top_count > OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount must be between one and the direct ballot option count",
        ));
    }

    Ok(top_count)
}

pub(super) fn validate_unique_top_counts(top_counts: &[usize]) -> CanonicalResult<()> {
    let mut seen_top_counts = BTreeSet::new();
    for top_count in top_counts {
        if !seen_top_counts.insert(*top_count) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "topCounts must not contain duplicates",
            ));
        }
    }

    Ok(())
}

pub(super) fn usize_to_u64(value: usize, name: &str) -> CanonicalResult<u64> {
    u64::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{name} does not fit u64"),
        )
    })
}

#[cfg(test)]
pub(super) fn direct_ballot_proof_randomness_seed(
    private_setup_seed: &str,
    ballot: &DirectEncryptedBallot,
) -> String {
    hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/proof-randomness-seed",
        &[
            private_setup_seed.as_bytes(),
            ballot.ciphertext_root.as_bytes(),
            ballot.input.voter_identity.as_bytes(),
            ballot.input.action_context_hash.as_bytes(),
        ],
    )
}

pub(super) fn direct_ballot_slots(scores: &[u64]) -> Vec<u64> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[..OPTION_COUNT].copy_from_slice(scores);
    slots
}

pub(super) fn direct_encrypted_ballot_hash(
    setup_package: &Value,
    ballot: &DirectBallotInput,
    ciphertext_root: &str,
    ciphertext_canonical_byte_length: usize,
) -> CanonicalResult<String> {
    let package_json = canonical_json(&json!({
            "setupPackageHash": setup_package_hash(setup_package)?,
            "voterIdentity": ballot.voter_identity,
            "actionContextHash": ballot.action_context_hash,
            "ciphertextRoot": ciphertext_root,
            "ciphertextCanonicalByteLength": ciphertext_canonical_byte_length
    }))?;
    Ok(hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/encrypted-ballot-hash",
        &[package_json.as_bytes()],
    ))
}

pub(super) fn setup_package_hash(setup_package: &Value) -> CanonicalResult<String> {
    setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupPackageHash must be present",
            )
        })
}

pub(super) fn read_ballots(
    request: &Value,
) -> CanonicalResult<(Vec<DirectBallotInput>, DirectBallotEncryptionRandomness)> {
    let ballots = request
        .get("ballots")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "ballots must be an array",
            )
        })?;
    if ballots.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot command requires at least one ballot",
        ));
    }
    let ballot_encryption_randomness =
        read_direct_ballot_encryption_randomness(request, ballots.len())?;
    let parsed_ballots = ballots
        .iter()
        .enumerate()
        .map(|(ballot_index, ballot)| {
            Ok(DirectBallotInput {
                voter_identity: required_string_field(ballot, "voterIdentity")?.to_string(),
                action_context_hash: required_string_field(ballot, "actionContextHash")?
                    .to_string(),
                scores: required_u64_array(ballot, "scores")?,
                one_hot_witnesses: optional_one_hot_witnesses(ballot)?,
                encryption_seed_hex: ballot_encryption_randomness
                    .encryption_seed_hex(ballot_index)?
                    .to_string(),
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok((parsed_ballots, ballot_encryption_randomness))
}

pub(super) fn read_direct_ballot_encryption_randomness(
    request: &Value,
    ballot_count: usize,
) -> CanonicalResult<DirectBallotEncryptionRandomness> {
    let value = required_object_field(request, "ballotEncryptionRandomness")?;
    let encryption_seed_hexes = required_string_array_field(value, "encryptionSeedHexes")?;
    if encryption_seed_hexes.len() != ballot_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "ballotEncryptionRandomness.encryptionSeedHexes length must match the ballot count",
        ));
    }
    for (randomness_index, randomness_hex) in encryption_seed_hexes.iter().enumerate() {
        validate_direct_ballot_encryption_randomness_hex(
            randomness_hex,
            &format!("ballotEncryptionRandomness.encryptionSeedHexes[{randomness_index}]"),
        )?;
    }
    validate_unique_direct_ballot_randomness(
        &encryption_seed_hexes,
        "ballotEncryptionRandomness.encryptionSeedHexes",
    )?;

    Ok(DirectBallotEncryptionRandomness {
        encryption_seed_hexes,
    })
}

pub(super) fn read_direct_ballot_proof_mask_randomness(
    request: &Value,
    ballot_count: usize,
) -> CanonicalResult<DirectBallotProofMaskRandomness> {
    let value = required_object_field(request, "proofMaskRandomness")?;
    let ballot_proof_randomness_hexes =
        required_string_array_field(value, "ballotProofRandomnessHexes")?;
    if ballot_proof_randomness_hexes.len() != ballot_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proofMaskRandomness.ballotProofRandomnessHexes length must match the ballot proof count",
        ));
    }
    for (randomness_index, randomness_hex) in ballot_proof_randomness_hexes.iter().enumerate() {
        validate_direct_ballot_proof_randomness_hex(
            randomness_hex,
            &format!("proofMaskRandomness.ballotProofRandomnessHexes[{randomness_index}]"),
        )?;
    }
    validate_unique_direct_ballot_randomness(
        &ballot_proof_randomness_hexes,
        "proofMaskRandomness.ballotProofRandomnessHexes",
    )?;

    Ok(DirectBallotProofMaskRandomness {
        ballot_proof_randomness_hexes,
    })
}

pub(super) fn validate_unique_direct_ballot_randomness(
    values: &[String],
    label: &str,
) -> CanonicalResult<()> {
    validate_unique_strings(values, label, "repeats direct ballot randomness")
}

pub(super) fn validate_unique_strings(
    values: &[String],
    label: &str,
    duplicate_message: &str,
) -> CanonicalResult<()> {
    let mut seen_values = BTreeSet::new();
    for (value_index, value) in values.iter().enumerate() {
        if !seen_values.insert(value.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{label}[{value_index}] {duplicate_message}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_disjoint_direct_ballot_randomness(
    encryption_seed_hexes: &[String],
    proof_randomness_hexes: &[String],
) -> CanonicalResult<()> {
    let encryption_seed_set = encryption_seed_hexes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (proof_randomness_index, proof_randomness_hex) in proof_randomness_hexes.iter().enumerate()
    {
        if encryption_seed_set.contains(proof_randomness_hex.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "proofMaskRandomness.ballotProofRandomnessHexes[{proof_randomness_index}] must not reuse ballot encryption randomness"
                ),
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_direct_ballot_proof_randomness_hex(
    value: &str,
    label: &str,
) -> CanonicalResult<()> {
    validate_direct_ballot_randomness_hex(value, label, PROOF_MASK_RANDOMNESS_HEX_BYTES)
}

pub(super) fn validate_direct_ballot_encryption_randomness_hex(
    value: &str,
    label: &str,
) -> CanonicalResult<()> {
    validate_direct_ballot_randomness_hex(value, label, ENCRYPTION_RANDOMNESS_HEX_BYTES)
}

pub(super) fn validate_direct_ballot_hash_hex(value: &str, label: &str) -> CanonicalResult<()> {
    validate_direct_ballot_randomness_hex(value, label, 64)
}

pub(super) fn validate_direct_ballot_randomness_hex(
    value: &str,
    label: &str,
    byte_count: usize,
) -> CanonicalResult<()> {
    let expected_length = byte_count * 2;
    if value.len() != expected_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must contain {expected_length} lowercase hex characters"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} must be lowercase hexadecimal"),
        ));
    }

    Ok(())
}

pub(super) fn validate_direct_ballot_batch_order(
    ballots: &[DirectBallotInput],
) -> CanonicalResult<()> {
    let mut previous_voter_identity: Option<&str> = None;
    for ballot in ballots {
        if previous_voter_identity == Some(ballot.voter_identity.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot batch contains a duplicate voter identity",
            ));
        }
        if previous_voter_identity.is_some_and(|previous| previous > ballot.voter_identity.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot batch is not in deterministic voter identity order",
            ));
        }
        previous_voter_identity = Some(ballot.voter_identity.as_str());
    }

    Ok(())
}

pub(super) fn optional_one_hot_witnesses(ballot: &Value) -> CanonicalResult<Option<Vec<Vec<u64>>>> {
    let Some(value) = ballot.get("oneHotWitnesses") else {
        return Ok(None);
    };
    let rows = value.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "oneHotWitnesses must be an array",
        )
    })?;
    rows.iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "oneHotWitnesses rows must be arrays",
                    )
                })?
                .iter()
                .map(read_u64_value)
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()
        .map(Some)
}

pub(super) fn required_object_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an object"),
            )
        })
}

pub(super) fn required_string_path<'a>(
    value: &'a Value,
    path: &[&str],
) -> CanonicalResult<&'a str> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing required field {}", path.join(".")),
            )
        })?;
    }
    current.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{} must be a string", path.join(".")),
        )
    })
}

pub(super) fn required_string_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
}

pub(super) fn required_string_array_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<String>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} must be an array"),
            )
        })?
        .iter()
        .enumerate()
        .map(|(entry_index, entry)| {
            entry.as_str().map(ToString::to_string).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}[{entry_index}] must be a string"),
                )
            })
        })
        .collect()
}

pub(super) fn required_u64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<u64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} must be an array"),
            )
        })?
        .iter()
        .map(read_u64_value)
        .collect()
}

pub(super) fn read_u64_value(value: &Value) -> CanonicalResult<u64> {
    value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected an unsigned integer",
        )
    })
}
