use std::time::Instant;

use serde_json::{Value, json};

mod relation_proof;

use relation_proof::{
    direct_ballot_relation_challenge_bits, generate_direct_ballot_relation_proof,
    verify_direct_ballot_relation_proof,
};

use crate::{
    bgv::{
        evaluator::{
            circuit::{EvaluatorContext, modulus_switch_to},
            engine::{
                Ciphertext, DevelopmentBgvKey, EncryptionWitness, ciphertext_add,
                ciphertext_canonical_bytes_hex, ciphertext_object_root,
                encode_slots_to_coefficients, negacyclic_mul, signed_residue,
            },
            top_k::{
                evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
                pack_direct_score_slots, packed_score_slot,
                project_packed_sparse_target_from_rank_evaluation,
            },
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
const DIRECT_BALLOT_RNS_LIMB_PROOF_COLUMNS: usize = 4;
const DIRECT_BALLOT_RNS_LIMB_PROOF_ROWS: usize = 2;
const DIRECT_BALLOT_DEFAULT_EVALUATOR_WORKING_LEVEL: usize = 15;
const DIRECT_BALLOT_SINGLE_BALLOT_FULL_TARGET_WORKING_LEVEL: usize = 7;

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

struct DirectBallotAggregationResult {
    report: Value,
    aggregate_ciphertext: Ciphertext,
    aggregate_scores: Vec<u64>,
}

pub(crate) fn run_direct_encrypted_ballot_prototype(request: &Value) -> CanonicalResult<Value> {
    let setup_package = required_object_field(request, "setupPackage")?;
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    let private_setup_seed =
        required_string_path(request, &["setupPrivateWitness", "setupSeed"])?.to_string();
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, &private_setup_seed)?;

    let ballots = read_ballots(request)?;
    if ballots.len() > 10 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot proof experiment currently supports at most ten ballots",
        ));
    }
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

    let mut proof_generations = Vec::with_capacity(encrypted_ballots.len());
    let mut proof_verifications = Vec::with_capacity(encrypted_ballots.len());
    let mut total_proving_time_milliseconds = 0_u128;
    let mut total_verification_time_milliseconds = 0_u128;
    for encrypted_ballot in &encrypted_ballots {
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(&private_setup_seed, encrypted_ballot);
        let proof_generation_started = Instant::now();
        let proof_generation = generate_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            &proof_randomness_seed_hex,
        )?;
        total_proving_time_milliseconds += proof_generation_started.elapsed().as_millis();
        let proof_verification_started = Instant::now();
        let proof_verification = verify_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            &proof_generation.proof_bytes,
        )?;
        total_verification_time_milliseconds += proof_verification_started.elapsed().as_millis();
        proof_generations.push(proof_generation);
        proof_verifications.push(proof_verification);
    }
    let first_proof_generation = proof_generations.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot proof experiment requires at least one proof",
        )
    })?;
    let first_proof_verification = proof_verifications.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot proof experiment requires at least one proof verification",
        )
    })?;
    let total_proof_bytes = proof_generations
        .iter()
        .map(|proof_generation| proof_generation.proof_size_bytes)
        .sum::<usize>();
    let aggregation_result = verify_direct_ballot_aggregation(&evaluator_key, &encrypted_ballots)?;
    let evaluator_replay = match optional_direct_ballot_top_count(request)? {
        Some(top_count) => run_direct_ballot_direct_pair_evaluator(
            &evaluator_key,
            &private_setup_seed,
            &aggregation_result.aggregate_ciphertext,
            &aggregation_result.aggregate_scores,
            encrypted_ballots.len(),
            top_count,
        )?,
        None => json!(
            "Not run in this command. Supply topCount to attempt the direct-pair evaluator route over the direct aggregate."
        ),
    };

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
            "result": "Direct score slots, one-hot witnesses, batch encoding, all data-limb encryption algebra, and reserved zero slots passed private preflight."
        },
        "proofAttempt": {
            "relation": "all BGV data-prime encryption equations for c0=b*u+p*e0+encode(score) and c1=a*u+p*e1, with score-to-encoding carry linkage",
            "coverage": "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; zero-knowledge and claim-bearing soundness accounting are not included yet",
            "proofEncoding": "internal binary feasibility encoding",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "proofRingDegree": DIRECT_BALLOT_PROOF_RING_DEGREE,
            "rnsLimbCount": DATA_PRIMES.len(),
            "statementRowsPerLimb": DIRECT_BALLOT_RNS_LIMB_PROOF_ROWS,
            "statementColumnsPerLimb": DIRECT_BALLOT_RNS_LIMB_PROOF_COLUMNS,
            "totalRnsEquationRows": DATA_PRIMES.len() * DIRECT_BALLOT_RNS_LIMB_PROOF_ROWS,
            "sharedShortResponseVectorLength": direct_ballot_shared_short_response_vector_length(),
            "duplicatedShortResponseVectorLength": direct_ballot_duplicated_short_response_vector_length(),
            "binaryRelationCommitmentBytes": first_proof_generation.relation_commitment_bytes,
            "binarySharedResponseBytes": first_proof_generation.response_bytes,
            "proofCount": proof_generations.len(),
            "proofSizeBytes": first_proof_generation.proof_size_bytes,
            "verifiedProofSizeBytes": first_proof_verification.proof_size_bytes,
            "totalProofBytes": total_proof_bytes,
            "proofBytesHash": first_proof_generation.proof_bytes_hash,
            "statementHash": first_proof_generation.statement_hash_hex,
            "verifiedStatementHash": first_proof_verification.statement_hash_hex,
            "relationCommitmentHash": first_proof_generation.relation_commitment_hash_hex,
            "verifiedRelationCommitmentHash": first_proof_verification.relation_commitment_hash_hex,
            "challenge": first_proof_generation.challenge.to_string(),
            "verifiedChallenge": first_proof_verification.challenge.to_string(),
            "challengeSoundness": format!("single {}-bit challenge for feasibility measurement only; support polynomial checks are present, but zero-knowledge and claim-bearing soundness accounting are still missing", direct_ballot_relation_challenge_bits()),
            "relationCommitmentPolynomialCount": first_proof_generation.relation_commitment_polynomial_count,
            "sharedResponsePolynomialCount": first_proof_generation.shared_response_polynomial_count,
            "sharedScoreResponseScalarCount": first_proof_generation.shared_response_scalar_count,
            "responseSharing": "one binary response vector is checked against all 17 RNS limb equations, score-linear constraints, and support constraints; response bytes are not duplicated per limb",
            "provingTimeMilliseconds": total_proving_time_milliseconds.to_string(),
            "verificationTimeMilliseconds": total_verification_time_milliseconds.to_string(),
            "proofGate": first_proof_generation.proof_gate,
            "generation": "Generated and verified one internal binary proof for the all-limb BGV encryption relation, score-linear constraints, and support constraints. This is not claim-bearing ballot validity.",
            "fullRnsCoverage": "The proof covers all 17 BGV RNS limbs with one shared randomizer, error, encoding-carry, score, and one-hot response vector.",
            "blocker": "Next missing pieces are zero-knowledge and soundness accounting, practical evaluator replay, and Node/WASM or mobile runtime evidence."
        },
        "aggregation": aggregation_result.report,
        "evaluatorReplay": evaluator_replay,
        "decision": "Direct BGV ballot encryption, all-limb private preflight, one internal shared-response validity proof, and direct ciphertext aggregation work on the prototype path. The direct-pair evaluator route is used only when topCount is supplied and must match the target oracle before runtime evidence counts."
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
    validate_all_limb_encryption_relation(evaluator_key, ballot)
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

fn validate_all_limb_encryption_relation(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    if ballot.ciphertext.components.len() != 2
        || ballot.ciphertext.components[0].len() != DATA_PRIMES.len()
        || ballot.ciphertext.components[1].len() != DATA_PRIMES.len()
        || public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot RNS limb relation requires two full data-prime ciphertext components and a full public key",
        ));
    }
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        validate_limb_encryption_relation(
            ballot,
            public_component_zero,
            public_component_one,
            limb_index,
            modulus,
        )?;
    }

    Ok(())
}

fn validate_limb_encryption_relation(
    ballot: &DirectEncryptedBallot,
    public_component_zero: &[Vec<u64>],
    public_component_one: &[Vec<u64>],
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<()> {
    let randomizer_residues = ballot
        .encryption_witness
        .randomizer_coefficients
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let public_key_product = negacyclic_mul(
        &public_component_zero[limb_index],
        &randomizer_residues,
        modulus,
    )?;
    let public_sample_product = negacyclic_mul(
        &public_component_one[limb_index],
        &randomizer_residues,
        modulus,
    )?;
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
        if expected_component_zero != ballot.ciphertext.components[0][limb_index][coefficient_index]
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("direct encrypted ballot RNS limb {limb_index} c0 relation failed"),
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
        if expected_component_one != ballot.ciphertext.components[1][limb_index][coefficient_index]
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("direct encrypted ballot RNS limb {limb_index} c1 relation failed"),
            ));
        }
    }

    Ok(())
}

fn direct_ballot_shared_short_response_vector_length() -> usize {
    DIRECT_BALLOT_RNS_LIMB_PROOF_COLUMNS * (POLYNOMIAL_DEGREE / DIRECT_BALLOT_PROOF_RING_DEGREE) + 1
}

fn direct_ballot_duplicated_short_response_vector_length() -> usize {
    direct_ballot_shared_short_response_vector_length() * DATA_PRIMES.len()
}

fn verify_direct_ballot_aggregation(
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
        "result": "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and test-decrypted aggregate score slots to the plaintext oracle.",
        "ballotCount": encrypted_ballots.len(),
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_bytes_hex.len() / 2,
        "aggregateScores": aggregate_scores,
        "plaintextOracleScores": expected_scores
    });

    Ok(DirectBallotAggregationResult {
        report,
        aggregate_ciphertext,
        aggregate_scores,
    })
}

fn run_direct_ballot_direct_pair_evaluator(
    evaluator_key: &DevelopmentBgvKey,
    private_setup_seed: &str,
    aggregate_ciphertext: &Ciphertext,
    aggregate_scores: &[u64],
    ballot_count: usize,
    top_count: usize,
) -> CanonicalResult<Value> {
    if top_count != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot evaluator prefix top counts remain blocked by target projection correctness",
        ));
    }
    let score_domain_max = direct_ballot_comparison_domain_max(ballot_count)?;
    let aggregate_ciphertext_root = ciphertext_object_root(aggregate_ciphertext)?;
    let replay_seed = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/direct-pair-evaluator-seed-v1",
        &[
            private_setup_seed.as_bytes(),
            aggregate_ciphertext_root.as_bytes(),
            top_count.to_string().as_bytes(),
        ],
    );
    let working_level = direct_ballot_evaluator_working_level(ballot_count, top_count);
    let context = EvaluatorContext::from_key(evaluator_key.clone(), &replay_seed, working_level)?;
    let working_aggregate = modulus_switch_to(aggregate_ciphertext, context.working_level())?;
    let replay_started = Instant::now();
    let packed_scores = pack_direct_score_slots(
        &context,
        &working_aggregate,
        DIRECT_BALLOT_OPTION_COUNT,
        &replay_seed,
    )?;
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        DIRECT_BALLOT_OPTION_COUNT,
        score_domain_max,
        &replay_seed,
    )?;
    let target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &rank_evaluation,
        DIRECT_BALLOT_OPTION_COUNT,
        top_count,
    )?;
    let replay_time_milliseconds = replay_started.elapsed().as_millis();
    let target_id_slots = evaluator_key.decrypt_to_slots(&target.target_id)?;
    let target_order_slots = evaluator_key.decrypt_to_slots(&target.target_order)?;
    let decoded_target_ids = direct_packed_option_slots(&target_id_slots);
    let decoded_target_orders = direct_packed_option_slots(&target_order_slots);
    let (oracle_target_ids, oracle_target_orders) =
        direct_ballot_plaintext_target_slots(aggregate_scores, top_count)?;
    if decoded_target_ids != oracle_target_ids || decoded_target_orders != oracle_target_orders {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot packed batched-pair evaluator did not match the plaintext target oracle",
        ));
    }

    Ok(json!({
        "result": "Replayed the packed batched-pair encrypted evaluator over the direct aggregate and test-decrypted the sparse target to the plaintext oracle.",
        "topCount": top_count,
        "scoreDomainMax": score_domain_max,
        "workingLevel": context.working_level(),
        "packedScoreRoot": ciphertext_object_root(&packed_scores)?,
        "rankRoot": ciphertext_object_root(&rank_evaluation.packed_ranks)?,
        "targetIdRoot": ciphertext_object_root(&target.target_id)?,
        "targetOrderRoot": ciphertext_object_root(&target.target_order)?,
        "decodedTargetIds": decoded_target_ids,
        "decodedTargetOrders": decoded_target_orders,
        "plaintextOracleTargetIds": oracle_target_ids,
        "plaintextOracleTargetOrders": oracle_target_orders,
        "replayTimeMilliseconds": replay_time_milliseconds.to_string()
    }))
}

fn direct_packed_option_slots(slots: &[u64]) -> Vec<u64> {
    (0..DIRECT_BALLOT_OPTION_COUNT)
        .map(|option| slots[packed_score_slot(option)])
        .collect()
}

fn direct_ballot_evaluator_working_level(ballot_count: usize, top_count: usize) -> usize {
    if ballot_count == 1 && top_count == DIRECT_BALLOT_OPTION_COUNT {
        DIRECT_BALLOT_SINGLE_BALLOT_FULL_TARGET_WORKING_LEVEL
    } else {
        DIRECT_BALLOT_DEFAULT_EVALUATOR_WORKING_LEVEL
    }
}

fn direct_ballot_plaintext_aggregate_scores(
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

fn direct_ballot_comparison_domain_max(ballot_count: usize) -> CanonicalResult<u64> {
    let ballot_count_u64 = usize_to_u64(ballot_count, "ballot count")?;
    let score_span = DIRECT_BALLOT_MAXIMUM_SCORE - DIRECT_BALLOT_MINIMUM_SCORE;

    score_span.checked_mul(ballot_count_u64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot comparison domain overflowed",
        )
    })
}

fn direct_ballot_plaintext_target_slots(
    aggregate_scores: &[u64],
    top_count: usize,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    if aggregate_scores.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot target oracle requires twenty aggregate scores",
        ));
    }
    if top_count == 0 || top_count > DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount must be between one and the direct ballot option count",
        ));
    }

    let mut ranked_options = aggregate_scores
        .iter()
        .enumerate()
        .collect::<Vec<(usize, &u64)>>();
    ranked_options.sort_by(|(left_option, left_score), (right_option, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_option.cmp(right_option))
    });
    let mut ranks_by_option = vec![0_usize; DIRECT_BALLOT_OPTION_COUNT];
    for (rank, (option_index, _)) in ranked_options.iter().enumerate() {
        ranks_by_option[*option_index] = rank;
    }
    let mut target_ids = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
    let mut target_orders = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
    for (option_index, rank) in ranks_by_option.iter().enumerate() {
        if *rank < top_count {
            target_ids[option_index] = usize_to_u64(option_index + 1, "option identifier")?;
            target_orders[option_index] = usize_to_u64(rank + 1, "target order")?;
        }
    }

    Ok((target_ids, target_orders))
}

fn optional_direct_ballot_top_count(request: &Value) -> CanonicalResult<Option<usize>> {
    let Some(value) = request.get("topCount") else {
        return Ok(None);
    };
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
    if top_count == 0 || top_count > DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount must be between one and the direct ballot option count",
        ));
    }

    Ok(Some(top_count))
}

fn usize_to_u64(value: usize, name: &str) -> CanonicalResult<u64> {
    u64::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{name} does not fit u64"),
        )
    })
}

fn direct_ballot_proof_randomness_seed(
    private_setup_seed: &str,
    ballot: &DirectEncryptedBallot,
) -> String {
    hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/proof-randomness-seed-v1",
        &[
            private_setup_seed.as_bytes(),
            ballot.ciphertext_root.as_bytes(),
            ballot.input.voter_identity.as_bytes(),
            ballot.input.action_context_hash.as_bytes(),
        ],
    )
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
    fn direct_encrypted_ballot_command_reports_current_proof_status() {
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
                "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; zero-knowledge and claim-bearing soundness accounting are not included yet"
            )
        );
        assert!(
            result["proofAttempt"]["generation"]
                .as_str()
                .expect("proof generation assessment")
                .starts_with("Generated and verified one internal binary proof")
        );
        assert_eq!(
            result["proofAttempt"]["proofSizeBytes"],
            result["proofAttempt"]["verifiedProofSizeBytes"]
        );
        assert_eq!(
            result["proofAttempt"]["proofSizeBytes"].as_u64(),
            Some(13_374_704)
        );
        assert_eq!(
            result["proofAttempt"]["responseSharing"].as_str(),
            Some(
                "one binary response vector is checked against all 17 RNS limb equations, score-linear constraints, and support constraints; response bytes are not duplicated per limb"
            )
        );
        assert_eq!(
            result["proofAttempt"]["sharedScoreResponseScalarCount"].as_u64(),
            Some(
                u64::try_from(relation_proof::direct_ballot_relation_response_scalar_count())
                    .expect("response scalar count fits u64")
            )
        );
        assert_eq!(
            result["proofAttempt"]["rnsLimbCount"].as_u64(),
            Some(u64::try_from(DATA_PRIMES.len()).expect("limb count fits u64"))
        );
        assert_eq!(
            result["proofAttempt"]["sharedShortResponseVectorLength"].as_u64(),
            Some(
                u64::try_from(direct_ballot_shared_short_response_vector_length())
                    .expect("response length fits u64")
            )
        );
        assert_eq!(
            result["proofAttempt"]["duplicatedShortResponseVectorLength"].as_u64(),
            Some(
                u64::try_from(direct_ballot_duplicated_short_response_vector_length())
                    .expect("duplicated response length fits u64")
            )
        );
        assert_eq!(
            result["ballotPackages"]["ciphertextRoots"]
                .as_array()
                .expect("ciphertext roots")
                .len(),
            1
        );
        assert_eq!(result["aggregation"]["ballotCount"].as_u64(), Some(1));
        assert_eq!(
            result["aggregation"]["aggregateScores"].as_array(),
            result["aggregation"]["plaintextOracleScores"].as_array()
        );
        assert_eq!(
            result["aggregation"]["result"].as_str(),
            Some(
                "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and test-decrypted aggregate score slots to the plaintext oracle."
            )
        );
        assert_eq!(
            result["evaluatorReplay"].as_str(),
            Some(
                "Not run in this command. Supply topCount to attempt the direct-pair evaluator route over the direct aggregate."
            )
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_verifies() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        let proof_verification = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect("proof verification");

        assert_eq!(
            proof_verification.relation_commitment_hash_hex,
            proof_generation.relation_commitment_hash_hex
        );
        assert_eq!(proof_verification.challenge, proof_generation.challenge);
        assert!(proof_generation.proof_size_bytes > 0);
    }

    #[test]
    fn direct_ballot_aggregation_matches_plaintext_oracle_for_multiple_ballots() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let first_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("first encrypted ballot");
        let mut second_input = valid_ballot_input();
        second_input.voter_identity = "voter-aggregation-second".to_string();
        second_input.scores = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10];
        let second_ballot = encrypt_direct_ballot(&setup_package, &evaluator_key, second_input, 1)
            .expect("second encrypted ballot");

        let aggregation_report =
            verify_direct_ballot_aggregation(&evaluator_key, &[first_ballot, second_ballot])
                .expect("aggregation report");

        assert_eq!(aggregation_report.report["ballotCount"].as_u64(), Some(2));
        assert_eq!(
            aggregation_report.report["aggregateScores"],
            json!([
                11, 10, 10, 9, 9, 8, 8, 7, 7, 6, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20
            ])
        );
        assert_eq!(
            aggregation_report.report["aggregateScores"],
            aggregation_report.report["plaintextOracleScores"]
        );
    }

    #[test]
    #[ignore = "heavy direct ballot evaluator replay candidate; run selectively"]
    fn direct_ballot_packed_batched_pair_evaluator_top_count_20_matches_oracle() {
        let setup_package = setup_package();
        let result = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "topCount": DIRECT_BALLOT_OPTION_COUNT,
            "ballots": [
                {
                    "voterIdentity": "voter-validation",
                    "actionContextHash": "a".repeat(128),
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
            result["evaluatorReplay"]["topCount"].as_u64(),
            Some(u64::try_from(DIRECT_BALLOT_OPTION_COUNT).expect("option count fits u64"))
        );
        assert_eq!(
            result["evaluatorReplay"]["decodedTargetIds"],
            result["evaluatorReplay"]["plaintextOracleTargetIds"]
        );
        assert_eq!(
            result["evaluatorReplay"]["decodedTargetOrders"],
            result["evaluatorReplay"]["plaintextOracleTargetOrders"]
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_last_limb_ciphertext_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let last_limb_index = DATA_PRIMES.len() - 1;
        encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
            encrypted_ballot.ciphertext.components[0][last_limb_index][0],
            1,
            DATA_PRIMES[last_limb_index],
        )
        .expect("mutated residue");

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated last limb must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error.message.contains("not bound to this statement")
                || error.message.contains("limb 16 c0 response")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_response_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let response_offset =
            8 + 64 + 8 + relation_proof::direct_ballot_relation_commitment_bytes();
        proof_generation.proof_bytes[response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("randomizer support check failed"));
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_score_response_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let score_response_offset = direct_ballot_score_response_offset();
        proof_generation.proof_bytes[score_response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated score response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("direct ballot score proof option 0"));
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_one_hot_response_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let one_hot_response_offset =
            direct_ballot_score_response_offset() + DIRECT_BALLOT_OPTION_COUNT * 8;
        proof_generation.proof_bytes[one_hot_response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated one-hot response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("direct ballot score proof option 0"));
    }

    #[test]
    fn direct_ballot_relation_proof_rejects_linear_consistent_non_boolean_one_hot_witness() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let mut one_hot_witnesses = one_hot_witnesses_for_scores(&encrypted_ballot.input.scores);
        one_hot_witnesses[0] = vec![0, 0, 0, 0, 0, 0, 0, 65536, 2, 0];
        encrypted_ballot.input.one_hot_witnesses = Some(one_hot_witnesses);
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("non-Boolean one-hot witness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("one-hot Booleanity option 0 support check failed")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_commitment_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let commitment_offset = 8 + 64 + 8;
        proof_generation.proof_bytes[commitment_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated commitment must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("challenge does not match its commitment")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_wrong_public_key() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let wrong_setup_package = setup_package_with_seed("direct-encrypted-ballot-wrong-seed");
        let wrong_evaluator_key = development_evaluator_key_from_passive_setup_package(
            &wrong_setup_package,
            "direct-encrypted-ballot-wrong-seed",
        )
        .expect("wrong evaluator key");

        let error = verify_direct_ballot_relation_proof(
            &wrong_setup_package,
            &wrong_evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("wrong public key must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("not bound to this statement"));
    }

    #[test]
    fn direct_ballot_all_limb_relation_rejects_last_limb_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let last_limb_index = DATA_PRIMES.len() - 1;
        encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
            encrypted_ballot.ciphertext.components[0][last_limb_index][0],
            1,
            DATA_PRIMES[last_limb_index],
        )
        .expect("mutated residue");

        let error = validate_all_limb_encryption_relation(&evaluator_key, &encrypted_ballot)
            .expect_err("last limb mutation must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("RNS limb 16 c0 relation failed"));
    }

    #[test]
    fn direct_ballot_all_limb_relation_rejects_different_plaintext_witness() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        encrypted_ballot.plaintext_coefficients[0] += 1;

        let error = validate_all_limb_encryption_relation(&evaluator_key, &encrypted_ballot)
            .expect_err("different plaintext witness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("RNS limb 0 c0 relation failed"));
    }

    #[test]
    fn direct_ballot_support_rejects_out_of_range_randomizer() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        encrypted_ballot.encryption_witness.randomizer_coefficients[0] = 2;

        let error = validate_encryption_witness_support(&encrypted_ballot.encryption_witness)
            .expect_err("out-of-range randomizer must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains(
            "direct encrypted ballot randomizer has a coefficient outside the expected support"
        ));
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

    fn one_hot_witnesses_for_scores(scores: &[u64]) -> Vec<Vec<u64>> {
        scores
            .iter()
            .map(|score| {
                let mut row = vec![0_u64; 10];
                row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
                row
            })
            .collect()
    }

    fn direct_ballot_score_response_offset() -> usize {
        8 + 64
            + 8
            + relation_proof::direct_ballot_relation_commitment_bytes()
            + 4 * POLYNOMIAL_DEGREE * 8
    }

    fn setup_package() -> Value {
        setup_package_with_seed(DIRECT_BALLOT_TEST_SETUP_SEED)
    }

    fn setup_package_with_seed(setup_seed: &str) -> Value {
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
            "setupSeed": setup_seed
        }))
        .expect("setup package")
    }
}
