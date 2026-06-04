use serde_json::{Value, json};

use crate::{
    bgv::{
        evaluator::engine::{
            Ciphertext, DevelopmentBgvKey, EncryptionWitness, ciphertext_canonical_bytes_hex,
            ciphertext_object_root, encode_slots_to_coefficients, negacyclic_mul, signed_residue,
        },
        modular_arithmetic::add_mod,
        profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID, profile_hash},
        setup::{
            development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512_hex},
};

const DIRECT_BALLOT_OPERATION: &str = "runDirectEncryptedBallotPrototype";
const DIRECT_BALLOT_OPTION_COUNT: usize = 20;
const DIRECT_BALLOT_MINIMUM_SCORE: u64 = 1;
const DIRECT_BALLOT_MAXIMUM_SCORE: u64 = 10;
const DIRECT_BALLOT_PROOF_RING_DEGREE: usize = 64;
const DIRECT_BALLOT_FIRST_LIMB_PROOF_COLUMNS: usize = 4;
const DIRECT_BALLOT_FIRST_LIMB_PROOF_ROWS: usize = 2;

#[derive(Clone)]
struct DirectBallotInput {
    voter_identity: String,
    action_context_hash: String,
    scores: Vec<u64>,
    one_hot_witnesses: Option<Vec<Vec<u64>>>,
    encryption_seed_hex: Option<String>,
}

struct DirectEncryptedBallot {
    input: DirectBallotInput,
    slots: Vec<u64>,
    plaintext_coefficients: Vec<u64>,
    ciphertext: Ciphertext,
    encryption_witness: EncryptionWitness,
    ballot_package_hash: String,
    ciphertext_root: String,
    ciphertext_canonical_byte_length: usize,
}

struct DirectBallotProofAssessment {
    generation: String,
    blocker: String,
    full_rns_coverage: String,
}

pub(crate) fn run_direct_encrypted_ballot_prototype(request: &Value) -> CanonicalResult<Value> {
    let setup_package = required_object_field(request, "setupPackage")?;
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    let private_setup_seed =
        required_string_path(request, &["setupPrivateWitness", "setupSeed"])?.to_string();
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, &private_setup_seed)?;

    let ballots = read_ballots(request)?;
    let mut encrypted_ballots = Vec::with_capacity(ballots.len());
    for ballot in ballots {
        let encrypted_ballot = encrypt_direct_ballot(
            setup_package,
            &evaluator_key,
            ballot,
            encrypted_ballots.len(),
        )?;
        validate_direct_ballot_preflight(&evaluator_key, &encrypted_ballot)?;
        encrypted_ballots.push(encrypted_ballot);
    }

    let proof_assessment = assess_first_limb_encryption_proof();

    let ciphertext_byte_lengths = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_canonical_byte_length)
        .collect::<Vec<_>>();
    let ballot_package_hashes = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ballot_package_hash.clone())
        .collect::<Vec<_>>();
    let ciphertext_roots = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_root.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "operation": DIRECT_BALLOT_OPERATION,
        "profile": {
            "profileId": PROFILE_ID,
            "profileHash": profile_hash()?,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataPrimeCount": DATA_PRIMES.len()
        },
        "ballotLayout": {
            "optionCount": DIRECT_BALLOT_OPTION_COUNT,
            "scoreSlots": "slots 0 through 19 hold one scalar score per option",
            "reservedSlots": "all remaining slots are zero before encryption",
            "scoreRange": "scores must be integers from 1 through 10"
        },
        "input": {
            "ballotCount": encrypted_ballots.len()
        },
        "ballotPackages": {
            "packageHashes": ballot_package_hashes,
            "ciphertextRoots": ciphertext_roots,
            "ciphertextCanonicalByteLengths": ciphertext_byte_lengths,
            "result": "Direct score slots, one-hot witnesses, batch encoding, encryption algebra, and reserved zero slots passed private preflight."
        },
        "proofAttempt": {
            "relation": "one first-data-prime BGV encryption equation for c0=b*u+p*e0+m and c1=a*u+p*e1",
            "coverage": "targeted lower-bound relation only: one RNS limb encryption equation is assessed; no complete direct ballot validity proof is generated",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "proofRingDegree": DIRECT_BALLOT_PROOF_RING_DEGREE,
            "statementRows": DIRECT_BALLOT_FIRST_LIMB_PROOF_ROWS,
            "statementColumns": DIRECT_BALLOT_FIRST_LIMB_PROOF_COLUMNS,
            "shortResponseVectorLength": direct_ballot_first_limb_short_response_vector_length(),
            "sourceModulus": DATA_PRIMES[0],
            "requiredRnsLimbProofCount": DATA_PRIMES.len(),
            "generation": proof_assessment.generation,
            "fullRnsCoverage": proof_assessment.full_rns_coverage,
            "blocker": proof_assessment.blocker
        },
        "aggregation": "Not run because the direct ballot proof gate is red.",
        "evaluatorReplay": "Not run because the direct ballot proof gate is red.",
        "decision": "Direct BGV ballot encryption and private preflight work on the prototype path. Complete claim-bearing ballot proof coverage needs a new proof backend shape before aggregation or evaluator replay should be treated as a closure path."
    }))
}

fn encrypt_direct_ballot(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: DirectBallotInput,
    ballot_index: usize,
) -> CanonicalResult<DirectEncryptedBallot> {
    validate_direct_ballot_input(&ballot)?;
    let slots = direct_ballot_slots(&ballot.scores);
    let plaintext_coefficients = encode_slots_to_coefficients(&slots)?;
    let seed_hex = ballot.encryption_seed_hex.clone().unwrap_or_else(|| {
        hash512_hex(
            "sealed-lattice/direct-encrypted-ballot/encryption-seed-v1",
            &[
                setup_package_hash_bytes(setup_package).as_slice(),
                ballot.voter_identity.as_bytes(),
                ballot.action_context_hash.as_bytes(),
                ballot_index.to_string().as_bytes(),
            ],
        )
    });
    let (ciphertext, encryption_witness) =
        evaluator_key.encrypt_coefficients_with_witness(&plaintext_coefficients, &seed_hex)?;
    let ciphertext_root = ciphertext_object_root(&ciphertext)?;
    let ciphertext_canonical_bytes_hex = ciphertext_canonical_bytes_hex(&ciphertext)?;
    let ballot_package_hash = direct_ballot_package_hash(
        setup_package,
        &ballot,
        &ciphertext_root,
        ciphertext_canonical_bytes_hex.len() / 2,
    )?;

    Ok(DirectEncryptedBallot {
        input: ballot,
        slots,
        plaintext_coefficients,
        ciphertext,
        encryption_witness,
        ballot_package_hash,
        ciphertext_root,
        ciphertext_canonical_byte_length: ciphertext_canonical_bytes_hex.len() / 2,
    })
}

fn validate_direct_ballot_input(ballot: &DirectBallotInput) -> CanonicalResult<()> {
    if ballot.scores.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot requires exactly twenty scores",
        ));
    }
    for (option_index, score) in ballot.scores.iter().enumerate() {
        if !(DIRECT_BALLOT_MINIMUM_SCORE..=DIRECT_BALLOT_MAXIMUM_SCORE).contains(score) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "direct encrypted ballot score at option {option_index} must be between 1 and 10"
                ),
            ));
        }
    }
    if let Some(one_hot_witnesses) = &ballot.one_hot_witnesses {
        validate_one_hot_witnesses(&ballot.scores, one_hot_witnesses)?;
    }

    Ok(())
}

fn validate_one_hot_witnesses(
    scores: &[u64],
    one_hot_witnesses: &[Vec<u64>],
) -> CanonicalResult<()> {
    if one_hot_witnesses.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot one-hot witness must have one row per option",
        ));
    }
    for (option_index, one_hot_row) in one_hot_witnesses.iter().enumerate() {
        if one_hot_row.len() != usize::try_from(DIRECT_BALLOT_MAXIMUM_SCORE).unwrap() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot one-hot witness rows must have ten entries",
            ));
        }
        if one_hot_row.iter().any(|entry| *entry > 1) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness entries must be zero or one",
            ));
        }
        let one_hot_sum = one_hot_row.iter().sum::<u64>();
        if one_hot_sum != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness must select exactly one score",
            ));
        }
        let derived_score = one_hot_row
            .iter()
            .enumerate()
            .map(|(score_index, indicator)| {
                u64::try_from(score_index + 1).expect("score index fits u64") * indicator
            })
            .sum::<u64>();
        if derived_score != scores[option_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness does not match its scalar score",
            ));
        }
    }

    Ok(())
}

fn validate_direct_ballot_preflight(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    if ballot.slots.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot slot vector must match the polynomial degree",
        ));
    }
    if ballot.slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot reserved slots must be zero",
        ));
    }
    let decrypted_slots = evaluator_key.decrypt_to_slots(&ballot.ciphertext)?;
    if decrypted_slots[..DIRECT_BALLOT_OPTION_COUNT] != ballot.input.scores[..] {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot does not decrypt to the submitted score slots",
        ));
    }
    if decrypted_slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot decrypts to a non-zero reserved slot",
        ));
    }
    validate_encryption_witness_support(&ballot.encryption_witness)?;
    validate_first_limb_encryption_relation(evaluator_key, ballot)
}

fn validate_encryption_witness_support(witness: &EncryptionWitness) -> CanonicalResult<()> {
    validate_signed_support(
        &witness.randomizer_coefficients,
        1,
        "direct encrypted ballot randomizer",
    )?;
    validate_signed_support(
        &witness.error_zero_coefficients,
        2,
        "direct encrypted ballot first error polynomial",
    )?;
    validate_signed_support(
        &witness.error_one_coefficients,
        2,
        "direct encrypted ballot second error polynomial",
    )
}

fn validate_signed_support(
    coefficients: &[i64],
    maximum_abs: i64,
    label: &str,
) -> CanonicalResult<()> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must match the polynomial degree"),
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| coefficient.abs() > maximum_abs)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} has a coefficient outside the expected support"),
        ));
    }

    Ok(())
}

fn validate_first_limb_encryption_relation(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    let modulus = DATA_PRIMES[0];
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    let randomizer_residues = ballot
        .encryption_witness
        .randomizer_coefficients
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let public_key_product =
        negacyclic_mul(&public_component_zero[0], &randomizer_residues, modulus)?;
    let public_sample_product =
        negacyclic_mul(&public_component_one[0], &randomizer_residues, modulus)?;
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let expected_component_zero = add_mod(
            add_mod(
                public_key_product[coefficient_index],
                signed_residue(
                    ballot.encryption_witness.error_zero_coefficients[coefficient_index]
                        * i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
                    modulus,
                ),
                modulus,
            )?,
            ballot.plaintext_coefficients[coefficient_index],
            modulus,
        )?;
        if expected_component_zero != ballot.ciphertext.components[0][0][coefficient_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot first-limb c0 relation failed",
            ));
        }
        let expected_component_one = add_mod(
            public_sample_product[coefficient_index],
            signed_residue(
                ballot.encryption_witness.error_one_coefficients[coefficient_index]
                    * i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
                modulus,
            ),
            modulus,
        )?;
        if expected_component_one != ballot.ciphertext.components[1][0][coefficient_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot first-limb c1 relation failed",
            ));
        }
    }

    Ok(())
}

fn direct_ballot_first_limb_short_response_vector_length() -> usize {
    DIRECT_BALLOT_FIRST_LIMB_PROOF_COLUMNS * (POLYNOMIAL_DEGREE / DIRECT_BALLOT_PROOF_RING_DEGREE)
        + 1
}

fn assess_first_limb_encryption_proof() -> DirectBallotProofAssessment {
    DirectBallotProofAssessment {
        generation: "Not generated by the prototype command. The required statement has 2049 short-response polynomials for one BGV limb, and the available generic linear proof profiles do not give a rapid supported encoding for that relation.".to_string(),
        full_rns_coverage: "A complete direct ballot proof would need all 17 BGV RNS limbs bound to the same plaintext and encryption randomness witnesses.".to_string(),
        blocker: "Current backend shape is wrong for direct BGV ballot proof coverage: it is single-source-modulus, lacks shared witness binding across RNS limbs, and the aggregate-compatible profile either fails its proof constraints or exceeds the rapid PoC runtime budget for one limb.".to_string(),
    }
}

fn direct_ballot_slots(scores: &[u64]) -> Vec<u64> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[..DIRECT_BALLOT_OPTION_COUNT].copy_from_slice(scores);
    slots
}

fn direct_ballot_package_hash(
    setup_package: &Value,
    ballot: &DirectBallotInput,
    ciphertext_root: &str,
    ciphertext_canonical_byte_length: usize,
) -> CanonicalResult<String> {
    let score_json = canonical_json(&json!(ballot.scores))?;
    let package_json = canonical_json(&json!({
            "setupPackageHash": setup_package_hash(setup_package)?,
            "voterIdentity": ballot.voter_identity,
            "actionContextHash": ballot.action_context_hash,
            "scoreCommitment": hash512_hex(
                "sealed-lattice/direct-encrypted-ballot/score-commitment-v1",
                &[score_json.as_bytes()],
            ),
            "ciphertextRoot": ciphertext_root,
            "ciphertextCanonicalByteLength": ciphertext_canonical_byte_length
    }))?;
    Ok(hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/package-hash-v1",
        &[package_json.as_bytes()],
    ))
}

fn setup_package_hash(setup_package: &Value) -> CanonicalResult<String> {
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

fn setup_package_hash_bytes(setup_package: &Value) -> Vec<u8> {
    setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .as_bytes()
        .to_vec()
}

fn read_ballots(request: &Value) -> CanonicalResult<Vec<DirectBallotInput>> {
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
            "direct encrypted ballot prototype requires at least one ballot",
        ));
    }
    ballots
        .iter()
        .map(|ballot| {
            Ok(DirectBallotInput {
                voter_identity: required_string_field(ballot, "voterIdentity")?.to_string(),
                action_context_hash: required_string_field(ballot, "actionContextHash")?
                    .to_string(),
                scores: required_u64_array(ballot, "scores")?,
                one_hot_witnesses: optional_one_hot_witnesses(ballot)?,
                encryption_seed_hex: optional_string_field(ballot, "encryptionSeedHex")?,
            })
        })
        .collect()
}

fn optional_one_hot_witnesses(ballot: &Value) -> CanonicalResult<Option<Vec<Vec<u64>>>> {
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

fn required_object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
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

fn required_string_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
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

fn required_string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
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

fn optional_string_field(value: &Value, field_name: &str) -> CanonicalResult<Option<String>> {
    match value.get(field_name) {
        Some(Value::String(raw_value)) => Ok(Some(raw_value.clone())),
        Some(_) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a string when supplied"),
        )),
        None => Ok(None),
    }
}

fn required_u64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<u64>> {
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

fn read_u64_value(value: &Value) -> CanonicalResult<u64> {
    value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected an unsigned integer",
        )
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::hashing::derive_protocol_hash;

    use super::*;

    const DIRECT_BALLOT_TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";

    #[test]
    fn direct_encrypted_ballot_command_reports_proof_blocker() {
        let setup_package = setup_package();
        let result = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballots": [
                {
                    "voterIdentity": "voter-1",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot test" }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect("direct encrypted ballot prototype succeeds");

        assert_eq!(
            result["proofAttempt"]["coverage"].as_str(),
            Some(
                "targeted lower-bound relation only: one RNS limb encryption equation is assessed; no complete direct ballot validity proof is generated"
            )
        );
        assert!(
            result["proofAttempt"]["generation"]
                .as_str()
                .expect("proof generation assessment")
                .starts_with("Not generated by the prototype command")
        );
        assert_eq!(
            result["ballotPackages"]["ciphertextRoots"]
                .as_array()
                .expect("ciphertext roots")
                .len(),
            1
        );
        assert_eq!(
            result["aggregation"].as_str(),
            Some("Not run because the direct ballot proof gate is red.")
        );
        assert_eq!(
            result["evaluatorReplay"].as_str(),
            Some("Not run because the direct ballot proof gate is red.")
        );
    }

    #[test]
    fn direct_ballot_validation_rejects_out_of_range_scores() {
        let mut ballot = valid_ballot_input();
        ballot.scores[7] = 11;

        let error = validate_direct_ballot_input(&ballot).expect_err("score is out of range");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("direct encrypted ballot score at option 7")
        );
    }

    #[test]
    fn direct_ballot_validation_rejects_mismatched_one_hot_witness() {
        let mut ballot = valid_ballot_input();
        let mut witnesses = ballot
            .scores
            .iter()
            .map(|score| {
                let mut row = vec![0_u64; 10];
                row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
                row
            })
            .collect::<Vec<_>>();
        witnesses[3] = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ballot.one_hot_witnesses = Some(witnesses);

        let error = validate_direct_ballot_input(&ballot).expect_err("witness is inconsistent");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("one-hot witness does not match its scalar score")
        );
    }

    fn valid_ballot_input() -> DirectBallotInput {
        DirectBallotInput {
            voter_identity: "voter-validation".to_string(),
            action_context_hash: "a".repeat(128),
            scores: vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            one_hot_witnesses: None,
            encryption_seed_hex: None,
        }
    }

    fn setup_package() -> Value {
        crate::bgv::commands::generate_bgv_passive_setup_from_request(&json!({
            "ceremonyId": "direct-encrypted-ballot-test-ceremony",
            "manifestHash": derive_protocol_hash(
                "ElectionManifestHash",
                &json!({ "manifest": "direct encrypted ballot test" }),
            ).expect("manifest hash"),
            "rosterHash": derive_protocol_hash(
                "RosterHash",
                &json!({ "roster": "direct encrypted ballot test" }),
            ).expect("roster hash"),
            "thresholdProfileHash": derive_protocol_hash(
                "ThresholdProfileHash",
                &json!({ "threshold": "direct encrypted ballot test" }),
            ).expect("threshold hash"),
            "participants": [
                { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 0 },
                { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
                { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
            ],
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        }))
        .expect("setup package")
    }
}
