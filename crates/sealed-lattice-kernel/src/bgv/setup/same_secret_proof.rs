use num_bigint::BigUint;
use num_bigint::BigInt;
use serde_json::{Value, json};

use crate::{
    bgv::{
        modular_arithmetic::{self, SignedResidueFailure, add_mod, mul_mod, sub_mod},
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        setup_helpers::decimal_i128_value,
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512, hash512_hex, to_hex},
};

use super::commitment::{
    SETUP_COMMITMENT_PROFILE_ID, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentLimb, SetupCommitmentValue,
    compute_setup_big_signed_lifted_commitment, linear_combination_setup_commitments,
    setup_big_signed_coefficient_fits_centered_commitment_modulus_product,
    parse_setup_commitment_full_value, setup_commitment_root,
    verify_setup_big_signed_lifted_commitment_opening,
};
use super::setup_proof::SETUP_PROOF_PROFILE_ID;

const SAME_SECRET_LNP_PROOF_MAGIC: &[u8; 8] = b"SLSSLNP1";
pub(super) const SAME_SECRET_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/same-secret/lnp-scalar-challenge-v1";
const SAME_SECRET_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret/lnp-relation-commitment-v1";
const SAME_SECRET_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret/lnp-proof-bytes-v1";
pub(super) const SAME_SECRET_MESSAGE_MASK_BITS: usize = 80;
pub(super) const SAME_SECRET_RANDOMNESS_MASK_BITS: usize = 80;
pub(super) const SAME_SECRET_SCALAR_CHALLENGE_BITS: usize = 63;
pub(super) const SAME_SECRET_TERNARY_INFINITY_BOUND: i128 = 1;
pub(super) const SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND: i128 = 1;

pub(super) const SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-same-secret-relation-verified-with-accepted-setup-proof-accounting";
pub(super) const SAME_SECRET_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, centered signed 80-bit same-secret masks and responses, same-secret BDLOP commitment relation algebra, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing setup proof acceptance";

#[derive(Debug)]
pub(super) struct SameSecretLnpProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) tbox_commitment_prefix_hash: String,
    pub(super) z34_seed_material_hash: String,
    pub(super) z34_challenge_seed_hash: String,
    pub(super) z34_challenge_tail_hash: String,
    pub(super) z34_challenge_row_domain_hash: String,
    pub(super) z34_challenge_z3_row_set_hash: String,
    pub(super) z34_challenge_z4_row_set_hash: String,
    pub(super) tbox_lower_protocol_challenge_hash: String,
    pub(super) z34_z3_check_window_hash: String,
    pub(super) z34_z4_check_window_hash: String,
    pub(super) z34_z3_l2_squared_decimal: String,
    pub(super) z34_z4_infinity_norm_decimal: String,
    pub(super) challenge: u64,
}

struct ParsedSameSecretLnpProof {
    challenge: u64,
    relation_commitments: Vec<SetupCommitmentValue>,
    support_commitments: Vec<[u64; 4]>,
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    tbox_proof_bytes: Vec<u8>,
    tbox_commitment_prefix_hash: String,
    parameter_profile_hash_hex: String,
}

pub(super) fn same_secret_lnp_relation_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(SAME_SECRET_LNP_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes])
}

pub(crate) fn generate_same_secret_lnp_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "publicMatrixSeedHash",
            "statementRecord",
            "constantCommitments",
            "setupProofBinding",
            "secretCoefficients",
            "openingRandomnessByLimb",
            "proofRandomnessSource",
            "proofRandomnessSeedHex",
        ],
        "generateSameSecretLnpProof",
    )?;

    let public_matrix_seed_hash = string_field(request, "publicMatrixSeedHash")?;
    validate_lowercase_hash(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let statement_record = object_field(request, "statementRecord")?;
    let setup_proof_binding = object_field(request, "setupProofBinding")?;
    let constant_commitments = setup_commitment_values_field(request, "constantCommitments")?;
    let secret_coefficients = i64_vector_field(request, "secretCoefficients")?;
    let opening_randomness_by_limb = i128_matrix3_field(request, "openingRandomnessByLimb")?;
    let proof_randomness_source = proof_randomness_source(request)?;
    let proof_randomness_seed_hex = string_field(request, "proofRandomnessSeedHex")?;
    validate_proof_randomness_seed(proof_randomness_seed_hex, "proofRandomnessSeedHex")?;

    let witness = SameSecretLnpProofWitness {
        secret_coefficients,
        opening_randomness_by_limb,
    };
    let proof_bytes = generate_same_secret_lnp_relation_proof(
        public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        setup_proof_binding,
        &witness,
        proof_randomness_seed_hex,
    )?;
    let verification = verify_same_secret_lnp_relation_proof(
        public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        setup_proof_binding,
        &proof_bytes,
    )?;
    let proof_bytes_hash = same_secret_lnp_relation_proof_bytes_hash(&proof_bytes);

    Ok(json!({
        "ok": true,
        "operation": "generateSameSecretLnpProof",
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "same-secret-consistency",
        "proofVerificationStatus": SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": SAME_SECRET_LNP_PROOF_MODEL_STATUS,
        "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
        "statementHash": verification.statement_hash_hex,
        "relationCommitmentHash": verification.relation_commitment_hash_hex,
        "tboxCommitmentPrefixHash": verification.tbox_commitment_prefix_hash,
        "z34SeedMaterialHash": verification.z34_seed_material_hash,
        "z34ChallengeSeedHash": verification.z34_challenge_seed_hash,
        "z34ChallengeTailHash": verification.z34_challenge_tail_hash,
        "z34ChallengeRowDomainHash": verification.z34_challenge_row_domain_hash,
        "z34ChallengeZ3RowSetHash": verification.z34_challenge_z3_row_set_hash,
        "z34ChallengeZ4RowSetHash": verification.z34_challenge_z4_row_set_hash,
        "tboxLowerProtocolChallengeHash": verification.tbox_lower_protocol_challenge_hash,
        "z34Z3CheckWindowHash": verification.z34_z3_check_window_hash,
        "z34Z4CheckWindowHash": verification.z34_z4_check_window_hash,
        "z34Z3L2SquaredDecimal": verification.z34_z3_l2_squared_decimal,
        "z34Z4InfinityNormDecimal": verification.z34_z4_infinity_norm_decimal,
        "challenge": verification.challenge.to_string(),
        "proofSizeBytes": verification.proof_size_bytes,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "seedBytes": 64,
            "retention": "proof randomness seed material is consumed for proof generation and is not returned"
        }
    }))
}

pub(super) fn verify_same_secret_lnp_relation_proof(
    public_matrix_seed_hash: &str,
    statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    setup_proof_binding: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<SameSecretLnpProofVerification> {
    validate_same_secret_constant_commitments(constant_commitments)?;
    let statement_hash = same_secret_lnp_statement_hash(
        statement_record,
        constant_commitments,
        setup_proof_binding,
    )?;
    let parsed_proof =
        parse_same_secret_lnp_relation_proof(proof_bytes, &statement_hash, constant_commitments)?;
    let expected_parameter_profile_hash =
        super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?;
    if parsed_proof.parameter_profile_hash_hex != expected_parameter_profile_hash {
        return Err(invalid_same_secret_proof(
            "same-secret LNP proof is not bound to the accepted tbox parameter profile",
        ));
    }
    let encoded_commitments = encode_same_secret_relation_commitments(
        &parsed_proof.relation_commitments,
        &parsed_proof.support_commitments,
    )?;
    let statement_hash_hex = to_hex(&statement_hash);
    let layout = super::setup_proof::same_secret_lnp_tbox_layout();
    let expected_tbox_prefix_binding_seed =
        super::setup_proof::setup_proof_lnp_tbox_prefix_binding_seed(
            &layout,
            &statement_hash_hex,
            &expected_parameter_profile_hash,
            &encoded_commitments,
        )?;
    let expected_tbox_prefix =
        encode_same_secret_lnp_tbox_prefix(&layout, &expected_tbox_prefix_binding_seed)?;
    let expected_tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &expected_tbox_prefix,
        )?;
    if parsed_proof.tbox_commitment_prefix_hash != expected_tbox_commitment_prefix_hash {
        return Err(invalid_same_secret_proof(
            "same-secret LNP tbox commitment prefix is not bound to the statement and relation commitments",
        ));
    }
    let relation_commitment_hash_hex = same_secret_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &parsed_proof.parameter_profile_hash_hex,
        &parsed_proof.tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let recomputed_challenge =
        same_secret_lnp_relation_challenge(&statement_hash_hex, &relation_commitment_hash_hex)?;
    if parsed_proof.challenge != recomputed_challenge {
        return Err(invalid_same_secret_proof(
            "same-secret LNP scalar challenge does not match its relation transcript",
        ));
    }
    let tbox_summary = super::setup_proof::verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
        &parsed_proof.tbox_proof_bytes,
    )?;

    verify_same_secret_response_bounds(
        parsed_proof.challenge,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;
    verify_same_secret_support_response(
        parsed_proof.challenge,
        &parsed_proof.support_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
    )?;
    verify_same_secret_commitment_responses(
        public_matrix_seed_hash,
        constant_commitments,
        parsed_proof.challenge,
        &parsed_proof.relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;

    Ok(SameSecretLnpProofVerification {
        proof_size_bytes: proof_bytes.len(),
        statement_hash_hex,
        relation_commitment_hash_hex,
        tbox_commitment_prefix_hash: parsed_proof.tbox_commitment_prefix_hash,
        z34_seed_material_hash: tbox_summary.z34_seed_material_hash,
        z34_challenge_seed_hash: tbox_summary.z34_challenge_seed_hash,
        z34_challenge_tail_hash: tbox_summary.z34_challenge_tail_hash,
        z34_challenge_row_domain_hash: tbox_summary.z34_challenge_row_domain_hash,
        z34_challenge_z3_row_set_hash: tbox_summary.z34_challenge_z3_row_set_hash,
        z34_challenge_z4_row_set_hash: tbox_summary.z34_challenge_z4_row_set_hash,
        tbox_lower_protocol_challenge_hash: tbox_summary.tbox_lower_protocol_challenge_hash,
        z34_z3_check_window_hash: tbox_summary.z34_z3_check_window_hash,
        z34_z4_check_window_hash: tbox_summary.z34_z4_check_window_hash,
        z34_z3_l2_squared_decimal: tbox_summary.z3_l2_squared.to_string(),
        z34_z4_infinity_norm_decimal: tbox_summary.z4_infinity_norm.to_string(),
        challenge: parsed_proof.challenge,
    })
}

fn validate_same_secret_constant_commitments(
    constant_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<()> {
    if constant_commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_same_secret_proof(
            "same-secret proof requires one constant VSS commitment for every Q_share limb",
        ));
    }
    let Some(first_commitment) = constant_commitments.first() else {
        return Err(invalid_same_secret_proof(
            "same-secret proof requires non-empty constant commitments",
        ));
    };
    let ring_degree = first_commitment.ring_degree;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(invalid_same_secret_proof(
            "same-secret proof commitment ring degree is outside the selected profile",
        ));
    }
    for (rns_limb_index, (commitment, rns_prime)) in constant_commitments
        .iter()
        .zip(DATA_PRIMES.iter())
        .enumerate()
    {
        if commitment.source_rns_limb_index != rns_limb_index
            || commitment.source_message_modulus != *rns_prime
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(invalid_same_secret_proof(
                "same-secret proof constant commitments must follow the accepted Q_share constant-coefficient order",
            ));
        }
    }

    Ok(())
}

fn same_secret_lnp_statement_hash(
    statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    setup_proof_binding: &Value,
) -> CanonicalResult<[u8; 64]> {
    let commitment_roots = constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": commitment.source_message_modulus,
                "shamirCoefficientIndex": 0,
                "commitmentRoot": setup_commitment_root(commitment)?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let parameter_profile_hash = super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?;
    let statement_json = canonical_json(&json!({
        "objectType": "SameSecretLnpRelationProofStatement",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofBinding": setup_proof_binding,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "proofVerificationStatus": SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": SAME_SECRET_LNP_PROOF_MODEL_STATUS,
        "sameSecretTboxParameterProfileHash": parameter_profile_hash,
        "sameSecretStatementRoot": statement_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_same_secret_proof("same-secret statement root is required"))?,
        "trusteeSecretCommitmentRoot": statement_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_same_secret_proof("trustee secret commitment root is required"))?,
        "trusteeRosterPosition": statement_record
            .get("trusteeRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_same_secret_proof("trustee roster position is required"))?,
        "ringDegree": constant_commitments
            .first()
            .map(|commitment| commitment.ring_degree)
            .ok_or_else(|| invalid_same_secret_proof("constant commitments are required"))?,
        "rnsLimbCount": constant_commitments.len(),
        "constantCoefficientCommitmentRoots": commitment_roots,
        "relation": "for one shared ternary integer polynomial s_i, every accepted C_i,l,0 opens to s_i mod q_l",
    }))?;

    Ok(hash512(
        "sealed-lattice/setup/same-secret/lnp-relation-statement-v1",
        &[statement_json.as_bytes()],
    ))
}

fn parse_same_secret_lnp_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
    expected_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<ParsedSameSecretLnpProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(proof_bytes, &mut cursor)?;
    if &magic != SAME_SECRET_LNP_PROOF_MAGIC {
        return Err(invalid_same_secret_proof(
            "same-secret LNP proof has the wrong format marker",
        ));
    }
    let statement_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_same_secret_proof(
            "same-secret LNP proof is not bound to this statement",
        ));
    }
    let parameter_profile_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    let parameter_profile_hash_hex = to_hex(&parameter_profile_hash);
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 {
        return Err(invalid_same_secret_proof(
            "same-secret LNP scalar challenge is outside the expected range",
        ));
    }
    if challenge > same_secret_scalar_challenge_maximum()? {
        return Err(invalid_same_secret_proof(
            "same-secret LNP scalar challenge exceeds the accepted scalar challenge space",
        ));
    }
    let tbox_proof_byte_count =
        usize::try_from(read_u64(proof_bytes, &mut cursor)?).map_err(|_| {
            invalid_same_secret_proof("same-secret LNP tbox proof byte count does not fit usize")
        })?;
    if tbox_proof_byte_count == 0 {
        return Err(invalid_same_secret_proof(
            "same-secret LNP proof must include tbox proof bytes",
        ));
    }
    let tbox_proof_bytes = read_bytes(proof_bytes, &mut cursor, tbox_proof_byte_count)?;
    let layout = super::setup_proof::same_secret_lnp_tbox_layout();
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;
    let relation_commitments = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_same_secret_relation_commitment(proof_bytes, &mut cursor, expected_commitment)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let support_commitments = (0..expected_commitments[0].ring_degree)
        .map(|_| {
            Ok([
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
            ])
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secret_response_coefficients = read_i128_vector(
        proof_bytes,
        &mut cursor,
        expected_commitments[0].ring_degree,
    )?;
    let negative_indicator_response_coefficients = read_i128_vector(
        proof_bytes,
        &mut cursor,
        expected_commitments[0].ring_degree,
    )?;
    let randomness_response_by_limb = expected_commitments
        .iter()
        .map(|expected_commitment| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|_| {
                    read_i128_vector(proof_bytes, &mut cursor, expected_commitment.ring_degree)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if cursor != proof_bytes.len() {
        return Err(invalid_same_secret_proof(
            "same-secret LNP proof has trailing bytes",
        ));
    }

    Ok(ParsedSameSecretLnpProof {
        challenge,
        relation_commitments,
        support_commitments,
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        tbox_proof_bytes,
        tbox_commitment_prefix_hash,
        parameter_profile_hash_hex,
    })
}

fn read_same_secret_relation_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
    expected_commitment: &SetupCommitmentValue,
) -> CanonicalResult<SetupCommitmentValue> {
    let mut limbs = Vec::with_capacity(expected_commitment.limbs.len());
    for expected_limb in &expected_commitment.limbs {
        let mut rows = Vec::with_capacity(expected_limb.rows.len());
        for expected_row in &expected_limb.rows {
            let mut row = Vec::with_capacity(expected_row.len());
            for _ in expected_row {
                let coefficient = read_u64(proof_bytes, cursor)?;
                if coefficient >= expected_limb.modulus {
                    return Err(invalid_same_secret_proof(
                        "same-secret relation commitment coefficient is not canonical",
                    ));
                }
                row.push(coefficient);
            }
            rows.push(row);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index: expected_limb.commitment_modulus_index,
            modulus: expected_limb.modulus,
            rows,
        });
    }

    Ok(SetupCommitmentValue {
        source_rns_limb_index: expected_commitment.source_rns_limb_index,
        source_message_modulus: expected_commitment.source_message_modulus,
        shamir_coefficient_index: expected_commitment.shamir_coefficient_index,
        ring_degree: expected_commitment.ring_degree,
        limbs,
    })
}

fn verify_same_secret_commitment_responses(
    public_matrix_seed_hash: &str,
    constant_commitments: &[SetupCommitmentValue],
    challenge: u64,
    relation_commitments: &[SetupCommitmentValue],
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
    randomness_response_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    if relation_commitments.len() != constant_commitments.len()
        || randomness_response_by_limb.len() != constant_commitments.len()
    {
        return Err(invalid_same_secret_proof(
            "same-secret proof response limb count does not match the statement",
        ));
    }
    for (limb_index, ((constant_commitment, relation_commitment), randomness_response)) in
        constant_commitments
            .iter()
            .zip(relation_commitments.iter())
            .zip(randomness_response_by_limb.iter())
            .enumerate()
    {
        let expected_response_commitment = linear_combination_setup_commitments(&[
            (relation_commitment, 1),
            (constant_commitment, u128::from(challenge)),
        ])?;
        let response_message_coefficients = secret_response_coefficients
            .iter()
            .zip(negative_indicator_response_coefficients.iter())
            .map(|(secret_response, negative_indicator_response)| {
                same_secret_lifted_message_response(
                    *secret_response,
                    *negative_indicator_response,
                    constant_commitment.source_message_modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let response_randomness_bound = same_secret_randomness_response_bound(challenge)?;
        verify_setup_big_signed_lifted_commitment_opening(
            public_matrix_seed_hash,
            &expected_response_commitment,
            &response_message_coefficients,
            randomness_response,
            response_randomness_bound,
        )
        .map_err(|_| {
            invalid_same_secret_proof(format!(
                "same-secret proof commitment response failed for Q_share limb {limb_index}"
            ))
        })?;
    }

    Ok(())
}

fn verify_same_secret_response_bounds(
    challenge: u64,
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
    randomness_response_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    let secret_response_bound = same_secret_message_response_bound(
        challenge,
        SAME_SECRET_TERNARY_INFINITY_BOUND,
        "same-secret secret response",
    )?;
    let negative_indicator_response_bound = same_secret_message_response_bound(
        challenge,
        SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND,
        "same-secret negative-indicator response",
    )?;
    verify_i128_vector_bound(
        secret_response_coefficients,
        secret_response_bound,
        "same-secret secret response",
    )?;
    verify_i128_vector_bound(
        negative_indicator_response_coefficients,
        negative_indicator_response_bound,
        "same-secret negative-indicator response",
    )?;
    let randomness_response_bound = same_secret_randomness_response_bound(challenge)?;
    for limb_columns in randomness_response_by_limb {
        for column in limb_columns {
            verify_i128_vector_bound(
                column,
                randomness_response_bound,
                "same-secret opening-randomness response",
            )?;
        }
    }

    Ok(())
}

fn verify_i128_vector_bound(
    values: &[i128],
    inclusive_bound: i128,
    label: &str,
) -> CanonicalResult<()> {
    for value in values {
        let absolute_value = value.checked_abs().ok_or_else(|| {
            invalid_same_secret_proof(format!("{label} absolute value overflowed"))
        })?;
        if absolute_value > inclusive_bound {
            return Err(invalid_same_secret_proof(format!(
                "{label} exceeds the accepted response bound"
            )));
        }
    }

    Ok(())
}

fn verify_same_secret_support_response(
    challenge: u64,
    support_commitments: &[[u64; 4]],
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
) -> CanonicalResult<()> {
    if support_commitments.len() != secret_response_coefficients.len()
        || negative_indicator_response_coefficients.len() != secret_response_coefficients.len()
    {
        return Err(invalid_same_secret_proof(
            "same-secret support commitment count does not match the secret response",
        ));
    }
    let modulus = DATA_PRIMES[0];
    let challenge_residue = challenge % modulus;
    for (coefficient_index, ((support_commitment, secret_response), negative_response)) in
        support_commitments
            .iter()
            .zip(secret_response_coefficients.iter())
            .zip(negative_indicator_response_coefficients.iter())
            .enumerate()
    {
        verify_boolean_support_response(
            "same-secret negative indicator",
            coefficient_index,
            *negative_response,
            support_commitment[0],
            support_commitment[1],
            challenge_residue,
            modulus,
        )?;
        verify_boolean_support_response(
            "same-secret shifted nonnegative indicator",
            coefficient_index,
            secret_response
                .checked_add(*negative_response)
                .ok_or_else(|| {
                    invalid_same_secret_proof("same-secret shifted support response overflowed")
                })?,
            support_commitment[2],
            support_commitment[3],
            challenge_residue,
            modulus,
        )?;
    }

    Ok(())
}

fn verify_boolean_support_response(
    label: &str,
    coefficient_index: usize,
    response: i128,
    commitment_constant: u64,
    commitment_linear: u64,
    challenge_residue: u64,
    modulus: u64,
) -> CanonicalResult<()> {
    let response_residue = signed_i128_residue_u64(response, modulus)?;
    let response_square = mul_mod(response_residue, response_residue, modulus)?;
    let support_value = sub_mod(
        response_square,
        mul_mod(challenge_residue, response_residue, modulus)?,
        modulus,
    )?;
    let expanded_value = add_mod(
        commitment_constant,
        mul_mod(challenge_residue, commitment_linear, modulus)?,
        modulus,
    )?;
    if support_value != expanded_value {
        return Err(invalid_same_secret_proof(format!(
            "{label} support check failed at coefficient {coefficient_index}"
        )));
    }

    Ok(())
}

fn encode_same_secret_relation_commitments(
    relation_commitments: &[SetupCommitmentValue],
    support_commitments: &[[u64; 4]],
) -> CanonicalResult<Vec<u8>> {
    let byte_count = relation_commitments
        .iter()
        .try_fold(0_usize, |accumulator, commitment| {
            accumulator
                .checked_add(setup_commitment_value_byte_count(commitment)?)
                .ok_or_else(|| {
                    invalid_same_secret_proof("same-secret proof commitment size overflowed")
                })
        })?
        .checked_add(
            support_commitments
                .len()
                .checked_mul(4)
                .and_then(|count| count.checked_mul(8))
                .ok_or_else(|| invalid_same_secret_proof("same-secret support size overflowed"))?,
        )
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof commitment size overflowed"))?;
    let mut encoded = Vec::with_capacity(byte_count);
    for commitment in relation_commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    encoded.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
    for support_commitment in support_commitments {
        for value in support_commitment {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }

    Ok(encoded)
}

fn same_secret_lnp_relation_commitment_hash(
    statement_hash_hex: &str,
    parameter_profile_hash_hex: &str,
    tbox_commitment_prefix_hash: &str,
    encoded_commitments: &[u8],
) -> String {
    hash512_hex(
        SAME_SECRET_LNP_COMMITMENT_HASH_DOMAIN,
        &[
            statement_hash_hex.as_bytes(),
            parameter_profile_hash_hex.as_bytes(),
            tbox_commitment_prefix_hash.as_bytes(),
            encoded_commitments,
        ],
    )
}

fn same_secret_lnp_relation_challenge(
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
) -> CanonicalResult<u64> {
    super::setup_proof::derive_setup_proof_scalar_challenge(
        "same-secret-consistency",
        SAME_SECRET_LNP_SCALAR_CHALLENGE_DOMAIN,
        statement_hash_hex,
        relation_commitment_hash_hex,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
    )
}

fn same_secret_scalar_challenge_maximum() -> CanonicalResult<u64> {
    let challenge_bits = u32::try_from(SAME_SECRET_SCALAR_CHALLENGE_BITS).map_err(|_| {
        invalid_same_secret_proof("same-secret challenge bit count does not fit u32")
    })?;
    1_u64
        .checked_shl(challenge_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_same_secret_proof("same-secret challenge bound overflowed"))
}

fn same_secret_message_response_bound(
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    same_secret_response_bound(
        SAME_SECRET_MESSAGE_MASK_BITS,
        challenge,
        witness_infinity_bound,
        label,
    )
}

fn same_secret_randomness_response_bound(challenge: u64) -> CanonicalResult<i128> {
    same_secret_response_bound(
        SAME_SECRET_RANDOMNESS_MASK_BITS,
        challenge,
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        "same-secret opening-randomness response",
    )
}

fn same_secret_response_bound(
    mask_bits: usize,
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    let mask_bound = same_secret_mask_magnitude_bound(mask_bits, label)?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| invalid_same_secret_proof(format!("{label} bound overflowed")))?;
    mask_bound
        .checked_add(challenge_term)
        .ok_or_else(|| invalid_same_secret_proof(format!("{label} bound overflowed")))
}

fn same_secret_mask_magnitude_bound(mask_bits: usize, label: &str) -> CanonicalResult<i128> {
    let mask_bits = u32::try_from(mask_bits)
        .map_err(|_| invalid_same_secret_proof(format!("{label} mask bit count overflowed")))?;
    1_i128
        .checked_shl(mask_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_same_secret_proof(format!("{label} mask bound overflowed")))
}

fn setup_commitment_value_byte_count(commitment: &SetupCommitmentValue) -> CanonicalResult<usize> {
    commitment
        .limbs
        .iter()
        .try_fold(0_usize, |accumulator, limb| {
            let limb_count = limb.rows.iter().try_fold(0_usize, |row_accumulator, row| {
                row_accumulator.checked_add(row.len()).ok_or_else(|| {
                    invalid_same_secret_proof("same-secret commitment row size overflowed")
                })
            })?;
            accumulator
                .checked_add(limb_count.checked_mul(8).ok_or_else(|| {
                    invalid_same_secret_proof("same-secret commitment limb size overflowed")
                })?)
                .ok_or_else(|| invalid_same_secret_proof("same-secret commitment size overflowed"))
        })
}

fn signed_i128_residue_u64(value: i128, modulus: u64) -> CanonicalResult<u64> {
    modular_arithmetic::signed_i128_residue_u64(value, modulus).map_err(|failure| match failure {
        SignedResidueFailure::Overflowed => invalid_same_secret_proof("signed residue overflowed"),
        SignedResidueFailure::DoesNotFitU64 => {
            invalid_same_secret_proof("signed residue does not fit u64")
        }
    })
}

// The lifted committed-message response s_z + q_l * b_z can exceed the signed
// 128-bit range at the top of the centered mask distribution (the mask bound
// times the largest Q_share prime sits at the 2^127 boundary), so the lift is
// computed as a big integer; the commitment opening validates the centered
// no-wrap window against the commitment modulus product.
fn same_secret_lifted_message_response(
    secret_response: i128,
    negative_indicator_response: i128,
    source_message_modulus: u64,
) -> CanonicalResult<BigInt> {
    let lifted = BigInt::from(secret_response)
        + (BigInt::from(source_message_modulus) * BigInt::from(negative_indicator_response));
    if !setup_big_signed_coefficient_fits_centered_commitment_modulus_product(&lifted) {
        return Err(invalid_same_secret_proof(
            "same-secret lifted response wraps in the centered setup commitment modulus product",
        ));
    }

    Ok(lifted)
}

fn read_i128_vector(
    proof_bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> CanonicalResult<Vec<i128>> {
    (0..count)
        .map(|_| {
            let bytes = read_fixed::<16>(proof_bytes, cursor)?;
            Ok(i128::from_le_bytes(bytes))
        })
        .collect()
}

fn read_u64(proof_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed::<8>(proof_bytes, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_fixed<const LENGTH: usize>(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor
        .checked_add(LENGTH)
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof ended early"))?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn read_bytes(proof_bytes: &[u8], cursor: &mut usize, length: usize) -> CanonicalResult<Vec<u8>> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof ended early"))?;
    *cursor = end;

    Ok(bytes.to_vec())
}

fn invalid_same_secret_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_same_secret_proof(format!("{field_name} must be a non-empty string"))
        })
}

fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| invalid_same_secret_proof(format!("{field_name} must be an object")))
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_same_secret_proof(format!("{field_name} must be an array")))
}

fn setup_commitment_values_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<SetupCommitmentValue>> {
    array_field(value, field_name)?
        .iter()
        .map(parse_setup_commitment_full_value)
        .collect()
}

fn i64_vector_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<i64>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(item_index, item)| {
            decimal_i128_value(item)
                .and_then(|item| i64::try_from(item).ok())
                .ok_or_else(|| {
                    invalid_same_secret_proof(format!(
                        "{field_name}.{item_index} must be a signed 64-bit integer"
                    ))
                })
        })
        .collect()
}

fn i128_matrix3_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(outer_index, middle_value)| {
            middle_value
                .as_array()
                .ok_or_else(|| {
                    invalid_same_secret_proof(format!("{field_name}.{outer_index} must be an array"))
                })?
                .iter()
                .enumerate()
                .map(|(middle_index, inner_value)| {
                    inner_value
                        .as_array()
                        .ok_or_else(|| {
                            invalid_same_secret_proof(format!(
                                "{field_name}.{outer_index}.{middle_index} must be an array"
                            ))
                        })?
                        .iter()
                        .enumerate()
                        .map(|(inner_index, item)| {
                            decimal_i128_value(item).ok_or_else(|| {
                                invalid_same_secret_proof(format!(
                                    "{field_name}.{outer_index}.{middle_index}.{inner_index} must be a signed integer or decimal string"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn proof_randomness_source(value: &Value) -> CanonicalResult<&'static str> {
    match value
        .get("proofRandomnessSource")
        .and_then(Value::as_str)
        .unwrap_or("fresh-csprng")
    {
        "fresh-csprng" => Ok("fresh-csprng"),
        "development-deterministic-fixture" => Ok("development-deterministic-fixture"),
        _ => Err(invalid_same_secret_proof(
            "proofRandomnessSource must be fresh-csprng or development-deterministic-fixture",
        )),
    }
}

fn validate_lowercase_hash(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_same_secret_proof(format!(
        "{field_name} must be lowercase 512-bit hex"
    )))
}

fn validate_proof_randomness_seed(seed_hex: &str, field_name: &str) -> CanonicalResult<()> {
    validate_lowercase_hash(seed_hex, field_name)
}

pub(super) struct SameSecretLnpProofWitness {
    pub(super) secret_coefficients: Vec<i64>,
    pub(super) opening_randomness_by_limb: Vec<Vec<Vec<i128>>>,
}

pub(super) fn generate_same_secret_lnp_relation_proof(
    public_matrix_seed_hash: &str,
    statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    setup_proof_binding: &Value,
    witness: &SameSecretLnpProofWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    validate_same_secret_constant_commitments(constant_commitments)?;
    if witness.secret_coefficients.len() != constant_commitments[0].ring_degree
        || witness.opening_randomness_by_limb.len() != constant_commitments.len()
    {
        return Err(invalid_same_secret_proof(
            "same-secret proof witness shape does not match constant commitments",
        ));
    }
    let statement_hash = same_secret_lnp_statement_hash(
        statement_record,
        constant_commitments,
        setup_proof_binding,
    )?;
    let statement_hash_hex = to_hex(&statement_hash);
    let parameter_profile_hash = super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?;
    let parameter_profile_hash_bytes = hash_hex_to_fixed_bytes(&parameter_profile_hash)?;
    let layout = super::setup_proof::same_secret_lnp_tbox_layout();

    let secret_masks = (0..constant_commitments[0].ring_degree)
        .map(|coefficient_index| {
            sample_same_secret_message_mask_i128(
                &statement_hash,
                proof_randomness_seed_hex,
                0,
                coefficient_index,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_coefficients = witness
        .secret_coefficients
        .iter()
        .map(|coefficient| match *coefficient {
            -1 => Ok(1_i64),
            0 | 1 => Ok(0_i64),
            _ => Err(invalid_same_secret_proof(
                "same-secret witness coefficient must be ternary",
            )),
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_masks = (0..constant_commitments[0].ring_degree)
        .map(|coefficient_index| {
            sample_same_secret_message_mask_i128(
                &statement_hash,
                proof_randomness_seed_hex,
                1,
                coefficient_index,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_masks_by_limb = constant_commitments
        .iter()
        .enumerate()
        .map(|(limb_index, commitment)| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..commitment.ring_degree)
                        .map(|coefficient_index| {
                            sample_same_secret_mask_i128(
                                &statement_hash,
                                proof_randomness_seed_hex,
                                limb_index + 2,
                                randomness_column_index,
                                coefficient_index,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let relation_commitments = constant_commitments
        .iter()
        .zip(randomness_masks_by_limb.iter())
        .map(|(commitment, randomness_masks)| {
            let mask_message_coefficients = secret_masks
                .iter()
                .zip(negative_indicator_masks.iter())
                .map(|(secret_mask, negative_mask)| {
                    same_secret_lifted_message_response(
                        *secret_mask,
                        *negative_mask,
                        commitment.source_message_modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            compute_setup_big_signed_lifted_commitment(
                public_matrix_seed_hash,
                commitment.source_rns_limb_index,
                commitment.source_message_modulus,
                0,
                &mask_message_coefficients,
                randomness_masks,
                commitment.ring_degree,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let support_commitments = secret_masks
        .iter()
        .zip(negative_indicator_masks.iter())
        .zip(witness.secret_coefficients.iter())
        .zip(negative_indicator_coefficients.iter())
        .map(
            |(((secret_mask, negative_mask), secret), negative_indicator)| {
                same_secret_support_expansion(
                    *secret_mask,
                    *negative_mask,
                    *secret,
                    *negative_indicator,
                    DATA_PRIMES[0],
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    let encoded_commitments =
        encode_same_secret_relation_commitments(&relation_commitments, &support_commitments)?;
    let tbox_prefix_binding_seed = super::setup_proof::setup_proof_lnp_tbox_prefix_binding_seed(
        &layout,
        &statement_hash_hex,
        &parameter_profile_hash,
        &encoded_commitments,
    )?;
    let tbox_prefix = encode_same_secret_lnp_tbox_prefix(&layout, &tbox_prefix_binding_seed)?;
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(&layout, &tbox_prefix)?;
    let relation_commitment_hash = same_secret_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &parameter_profile_hash,
        &tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let challenge =
        same_secret_lnp_relation_challenge(&statement_hash_hex, &relation_commitment_hash)?;
    let mut tbox_proof_bytes = tbox_prefix;
    super::setup_proof::append_setup_proof_lnp_tbox_generated_suffix(
        &mut tbox_proof_bytes,
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash,
    )?;

    let challenge_wide = i128::from(challenge);
    let secret_response_coefficients =
        secret_masks
            .iter()
            .zip(witness.secret_coefficients.iter())
            .map(|(mask, secret)| {
                mask.checked_add(challenge_wide.checked_mul(i128::from(*secret)).ok_or_else(
                    || {
                        invalid_same_secret_proof(
                            "same-secret secret response multiplication overflowed",
                        )
                    },
                )?)
                .ok_or_else(|| invalid_same_secret_proof("same-secret secret response overflowed"))
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_response_coefficients = negative_indicator_masks
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(mask, indicator)| {
            mask.checked_add(
                challenge_wide
                    .checked_mul(i128::from(*indicator))
                    .ok_or_else(|| {
                        invalid_same_secret_proof(
                            "same-secret negative response multiplication overflowed",
                        )
                    })?,
            )
            .ok_or_else(|| invalid_same_secret_proof("same-secret negative response overflowed"))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_response_by_limb = randomness_masks_by_limb
        .iter()
        .zip(witness.opening_randomness_by_limb.iter())
        .map(|(mask_columns, witness_columns)| {
            if mask_columns.len() != witness_columns.len() {
                return Err(invalid_same_secret_proof(
                    "same-secret randomness witness column count mismatch",
                ));
            }
            mask_columns
                .iter()
                .zip(witness_columns.iter())
                .map(|(mask_column, witness_column)| {
                    if mask_column.len() != witness_column.len() {
                        return Err(invalid_same_secret_proof(
                            "same-secret randomness witness coefficient count mismatch",
                        ));
                    }
                    mask_column
                        .iter()
                        .zip(witness_column.iter())
                        .map(|(mask, opening)| {
                            mask.checked_add(challenge_wide.checked_mul(*opening).ok_or_else(
                                || {
                                    invalid_same_secret_proof(
                                        "same-secret randomness response multiplication overflowed",
                                    )
                                },
                            )?)
                            .ok_or_else(|| {
                                invalid_same_secret_proof(
                                    "same-secret randomness response overflowed",
                                )
                            })
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(SAME_SECRET_LNP_PROOF_MAGIC);
    proof_bytes.extend_from_slice(&statement_hash);
    proof_bytes.extend_from_slice(&parameter_profile_hash_bytes);
    proof_bytes.extend_from_slice(&challenge.to_le_bytes());
    let tbox_proof_size = u64::try_from(tbox_proof_bytes.len()).map_err(|_| {
        invalid_same_secret_proof("same-secret LNP tbox proof size does not fit u64")
    })?;
    proof_bytes.extend_from_slice(&tbox_proof_size.to_le_bytes());
    proof_bytes.extend_from_slice(&tbox_proof_bytes);
    proof_bytes.extend_from_slice(&encoded_commitments);
    for coefficient in &secret_response_coefficients {
        proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
    }
    for coefficient in &negative_indicator_response_coefficients {
        proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
    }
    for limb_columns in &randomness_response_by_limb {
        for column in limb_columns {
            for coefficient in column {
                proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    Ok(proof_bytes)
}

fn hash_hex_to_fixed_bytes(hash_hex: &str) -> CanonicalResult<[u8; 64]> {
    if hash_hex.len() != 128 {
        return Err(invalid_same_secret_proof(
            "same-secret hash must be 64 bytes",
        ));
    }
    let mut output = [0_u8; 64];
    for (byte_index, chunk) in hash_hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[byte_index] = (high << 4) | low;
    }

    Ok(output)
}

fn hex_nibble(value: u8) -> CanonicalResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_same_secret_proof(
            "same-secret hash contains a non-hex character",
        )),
    }
}

fn encode_same_secret_lnp_tbox_prefix(
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = SameSecretLnpBitWriter::new();
    encode_same_secret_lnp_uniform_polyvec(
        &mut writer,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        Some(&layout.proof_modulus),
        proof_randomness_seed_hex,
        0,
    )?;
    encode_same_secret_lnp_uniform_polyvec(
        &mut writer,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        Some(&layout.proof_modulus),
        proof_randomness_seed_hex,
        1,
    )?;
    encode_same_secret_lnp_uniform_polyvec(
        &mut writer,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        layout
            .proof_modulus_bit_count
            .checked_sub(layout.compression_dropped_bits)
            .ok_or_else(|| invalid_same_secret_proof("same-secret LNP compression underflowed"))?,
        None,
        proof_randomness_seed_hex,
        2,
    )?;

    Ok(writer.into_bytes())
}

fn encode_same_secret_lnp_uniform_polyvec(
    writer: &mut SameSecretLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    bit_count: usize,
    modulus: Option<&BigUint>,
    proof_randomness_seed_hex: &str,
    field_index: u64,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            invalid_same_secret_proof("same-secret LNP tbox coefficient count overflowed")
        })?;
    for coefficient_index in 0..coefficient_count {
        if field_index == 1
            && super::setup_proof::setup_proof_lnp_tbox_h_coefficient_must_be_zero(
                coefficient_index,
                proof_ring_degree,
            )
        {
            let zero_residue_bytes = vec![
                0_u8;
                bit_count.checked_add(7).ok_or_else(|| {
                    invalid_same_secret_proof("same-secret LNP tbox bit count overflowed")
                })? / 8
            ];
            writer.write_little_endian_bytes_bits(&zero_residue_bytes, bit_count)?;
            continue;
        }
        let residue_bytes = super::setup_proof::sample_setup_proof_lnp_tbox_uniform_residue_bytes(
            "sealed-lattice/setup/same-secret/lnp-tbox-uniform-v1",
            proof_randomness_seed_hex,
            field_index,
            coefficient_index,
            bit_count,
            modulus,
        )?;
        writer.write_little_endian_bytes_bits(&residue_bytes, bit_count)?;
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "borrowed mode is retained for local LNP bit-writer parity"
)]
enum SameSecretLnpBitWriterStorage<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut Vec<u8>),
}

struct SameSecretLnpBitWriter<'a> {
    storage: SameSecretLnpBitWriterStorage<'a>,
    bit_offset: usize,
}

impl<'a> SameSecretLnpBitWriter<'a> {
    fn new() -> Self {
        Self {
            storage: SameSecretLnpBitWriterStorage::Owned(Vec::new()),
            bit_offset: 0,
        }
    }

    #[allow(
        dead_code,
        reason = "borrowed mode is retained for local LNP bit-writer parity"
    )]
    fn from_bytes(bytes: &'a mut Vec<u8>) -> Self {
        let bit_offset = bytes.len() * 8;
        Self {
            storage: SameSecretLnpBitWriterStorage::Borrowed(bytes),
            bit_offset,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            SameSecretLnpBitWriterStorage::Owned(bytes) => bytes,
            SameSecretLnpBitWriterStorage::Borrowed(_) => {
                unreachable!("borrowed same-secret LNP bit writer is not consumed by value")
            }
        }
    }

    #[allow(
        dead_code,
        reason = "suffix encoding moved to setup_proof shared writer"
    )]
    fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) -> CanonicalResult<()> {
        for bit_index in 0..bit_count {
            let bit = if bit_index < u64::BITS as usize {
                ((value >> bit_index) & 1) == 1
            } else {
                false
            };
            self.write_bit(bit);
        }

        Ok(())
    }

    fn write_little_endian_bytes_bits(
        &mut self,
        bytes: &[u8],
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if bytes
            .len()
            .checked_mul(8)
            .is_none_or(|available_bits| available_bits < bit_count)
        {
            return Err(invalid_same_secret_proof(
                "same-secret LNP byte residue is shorter than its declared bit count",
            ));
        }
        for bit_index in 0..bit_count {
            let byte = bytes[bit_index / 8];
            self.write_bit(((byte >> (bit_index % 8)) & 1) == 1);
        }

        Ok(())
    }

    fn write_bit(&mut self, bit: bool) {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let bytes = self.bytes_mut();
        if byte_index == bytes.len() {
            bytes.push(0);
        }
        if bit {
            bytes[byte_index] |= 1_u8 << bit_index;
        }
        self.bit_offset += 1;
    }

    #[allow(
        dead_code,
        reason = "suffix encoding moved to setup_proof shared writer"
    )]
    fn finish_with_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        match &mut self.storage {
            SameSecretLnpBitWriterStorage::Owned(bytes) => bytes,
            SameSecretLnpBitWriterStorage::Borrowed(bytes) => bytes,
        }
    }
}

fn sample_same_secret_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    vector_index: usize,
    column_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let vector_index_bytes = u64::try_from(vector_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask vector index overflowed"))?
        .to_le_bytes();
    let column_index_bytes = u64::try_from(column_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask column index overflowed"))?
        .to_le_bytes();
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask coefficient index overflowed"))?
        .to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/same-secret/lnp-relation-mask-v1",
        &[
            statement_hash,
            proof_randomness_seed_hex.as_bytes(),
            &vector_index_bytes,
            &column_index_bytes,
            &coefficient_index_bytes,
        ],
    );
    let magnitude_byte_count = SAME_SECRET_RANDOMNESS_MASK_BITS.div_ceil(8);
    let mut magnitude_bytes = block[..magnitude_byte_count].to_vec();
    let excess_bits = magnitude_byte_count * 8 - SAME_SECRET_RANDOMNESS_MASK_BITS;
    if excess_bits > 0 {
        let kept_bits = 8 - excess_bits;
        let mask = (1_u16 << kept_bits) - 1;
        if let Some(last_byte) = magnitude_bytes.last_mut() {
            *last_byte &= u8::try_from(mask).expect("mask fits u8");
        }
    }
    let mut full_bytes = [0_u8; 16];
    full_bytes[..magnitude_bytes.len()].copy_from_slice(&magnitude_bytes);
    let magnitude = i128::from_le_bytes(full_bytes);
    if block[magnitude_byte_count] & 1 == 1 {
        Ok(-magnitude)
    } else {
        Ok(magnitude)
    }
}

fn sample_same_secret_message_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    vector_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let vector_index_bytes = u64::try_from(vector_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask vector index overflowed"))?
        .to_le_bytes();
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask coefficient index overflowed"))?
        .to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/same-secret/lnp-message-mask-v1",
        &[
            statement_hash,
            proof_randomness_seed_hex.as_bytes(),
            &vector_index_bytes,
            &coefficient_index_bytes,
        ],
    );
    let magnitude_byte_count = SAME_SECRET_MESSAGE_MASK_BITS.div_ceil(8);
    let mut bytes = [0_u8; 16];
    bytes[..magnitude_byte_count].copy_from_slice(&block[..magnitude_byte_count]);
    let excess_bits = magnitude_byte_count * 8 - SAME_SECRET_MESSAGE_MASK_BITS;
    if excess_bits > 0 {
        let kept_bits = 8 - excess_bits;
        let mask = (1_u16 << kept_bits) - 1;
        bytes[magnitude_byte_count - 1] &= u8::try_from(mask).expect("mask fits u8");
    }
    let magnitude = i128::from_le_bytes(bytes);
    if block[magnitude_byte_count] & 1 == 1 {
        Ok(-magnitude)
    } else {
        Ok(magnitude)
    }
}

fn same_secret_support_expansion(
    secret_mask: i128,
    negative_indicator_mask: i128,
    secret: i64,
    negative_indicator: i64,
    modulus: u64,
) -> CanonicalResult<[u64; 4]> {
    if !matches!(secret, -1..=1) || !matches!(negative_indicator, 0..=1) {
        return Err(invalid_same_secret_proof(
            "same-secret witness support values are outside the expected set",
        ));
    }
    let shifted_value = secret
        .checked_add(negative_indicator)
        .ok_or_else(|| invalid_same_secret_proof("same-secret shifted witness overflowed"))?;
    if !matches!(shifted_value, 0..=1) {
        return Err(invalid_same_secret_proof(
            "same-secret shifted witness must be Boolean",
        ));
    }
    let negative_expansion =
        boolean_support_expansion(negative_indicator_mask, negative_indicator, modulus)?;
    let shifted_expansion = boolean_support_expansion(
        secret_mask
            .checked_add(negative_indicator_mask)
            .ok_or_else(|| invalid_same_secret_proof("same-secret shifted mask overflowed"))?,
        shifted_value,
        modulus,
    )?;
    Ok([
        negative_expansion[0],
        negative_expansion[1],
        shifted_expansion[0],
        shifted_expansion[1],
    ])
}

fn boolean_support_expansion(mask: i128, witness: i64, modulus: u64) -> CanonicalResult<[u64; 2]> {
    if !matches!(witness, 0..=1) {
        return Err(invalid_same_secret_proof(
            "same-secret Boolean support witness must be zero or one",
        ));
    }
    let mask_residue = signed_i128_residue_u64(mask, modulus)?;
    let witness_residue = signed_i128_residue_u64(i128::from(witness), modulus)?;
    let mask_square = mul_mod(mask_residue, mask_residue, modulus)?;
    Ok([
        mask_square,
        sub_mod(
            mul_mod(
                2 % modulus,
                mul_mod(mask_residue, witness_residue, modulus)?,
                modulus,
            )?,
            mask_residue,
            modulus,
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_secret_lnp_relation_proof_refuses_unbounded_response_residue() {
        let challenge = same_secret_scalar_challenge_maximum().expect("challenge maximum");
        let accepted_bound = same_secret_message_response_bound(
            challenge,
            SAME_SECRET_TERNARY_INFINITY_BOUND,
            "test same-secret response",
        )
        .expect("same-secret response bound");
        let oversized_same_residue_response = accepted_bound
            .checked_add(i128::from(DATA_PRIMES[0]))
            .expect("oversized response");

        let error = verify_same_secret_response_bounds(
            challenge,
            &[oversized_same_residue_response],
            &[0],
            &[],
        )
        .expect_err("oversized response should fail before modular support checks");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("response bound"));
    }
}
