use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;
use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::{coefficient_vector_hash512, write_i128_vector},
        modular_arithmetic::{self, SignedResidueFailure, add_mod, inverse_mod, mul_mod, sub_mod},
        profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        setup_helpers::decimal_i128_value,
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512, hash512_hex, to_hex},
};

use super::{
    commitment::{
        SETUP_COMMITMENT_PROFILE_ID, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentLimb, SetupCommitmentValue,
        compute_setup_signed_lifted_commitment, linear_combination_setup_commitments,
        parse_setup_commitment_full_value, setup_commitment_root,
        setup_signed_coefficient_fits_centered_commitment_modulus_product,
        verify_setup_signed_lifted_commitment_opening,
    },
    sampling::{dense_public_residues, negacyclic_product_mod},
    setup_proof::SETUP_PROOF_PROFILE_ID,
};

pub(super) const PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1";
const PUBLIC_KEY_SHARE_LNP_PROOF_MAGIC: &[u8; 8] = b"SLPKLNP1";
pub(super) const PUBLIC_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/public-key-share/lnp-scalar-challenge-v1";
const PUBLIC_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-key-share/lnp-relation-commitment-v1";
const PUBLIC_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-key-share/lnp-proof-bytes-v1";
const PUBLIC_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT: usize = 32;
const PUBLIC_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT: usize = 4;
pub(super) const PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS: usize = 80;
pub(super) const PUBLIC_KEY_SHARE_ERROR_MASK_BITS: usize = 80;
pub(super) const PUBLIC_KEY_SHARE_CARRY_MASK_BITS: usize = 64;
pub(super) const PUBLIC_KEY_SHARE_RANDOMNESS_MASK_BITS: usize = 80;
pub(super) const PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS: usize = 63;
pub(super) const PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND: i128 = 1;
pub(super) const PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND: i128 = 1;
pub(super) const PUBLIC_KEY_SHARE_ERROR_INFINITY_BOUND: i128 = 2;

pub(super) const PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-public-key-share-relation-verified-with-accepted-setup-proof-accounting";
pub(super) const PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, VSS-bound secret opening with centered signed 80-bit committed-secret masks and responses, fixed-width signed big-integer public-key relation commitments, centered-binomial error support, lifted no-wrap carry witnesses, public-key algebra, fixed response bounds, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing public-key proof acceptance";

pub(super) struct PublicKeyShareLnpProofVerification {
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

pub(super) struct PublicKeyShareLnpProofVerificationInput<'a> {
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) public_key_share_record: &'a Value,
    pub(super) public_key_share_proof_record: &'a Value,
    pub(super) same_secret_statement_record: &'a Value,
    pub(super) constant_commitments: &'a [SetupCommitmentValue],
    pub(super) public_share_coefficients_by_limb: &'a [Vec<u64>],
    pub(super) setup_proof_binding: &'a Value,
    pub(super) proof_bytes: &'a [u8],
}

struct ParsedPublicKeyShareLnpProof {
    challenge: u64,
    public_key_relation_commitments_by_limb: Vec<Vec<BigInt>>,
    error_support_commitments_by_limb: Vec<Vec<[u64; 5]>>,
    secret_commitment_relation_commitments: Vec<SetupCommitmentValue>,
    secret_support_commitments: Vec<[u64; 4]>,
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    error_response_by_limb: Vec<Vec<i128>>,
    carry_response_by_limb: Vec<Vec<i128>>,
    tbox_proof_bytes: Vec<u8>,
    tbox_commitment_prefix_hash: String,
    parameter_profile_hash_hex: String,
}

pub(super) fn public_key_share_lnp_relation_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(PUBLIC_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes])
}

pub(super) fn public_key_share_coefficient_vector_hash(coefficients: &[u64]) -> String {
    coefficient_vector_hash512(
        coefficients,
        PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN,
    )
}

pub(crate) fn generate_public_key_share_lnp_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "publicMatrixSeedHash",
            "publicKeyShareRecord",
            "publicKeyShareProofRecord",
            "sameSecretStatementRecord",
            "constantCommitments",
            "publicShareCoefficientsByLimb",
            "setupProofBinding",
            "secretCoefficients",
            "openingRandomnessByLimb",
            "errorCoefficientsByLimb",
            "proofRandomnessSource",
            "proofRandomnessSeedHex",
        ],
        "generatePublicKeyShareLnpProof",
    )?;

    let public_matrix_seed_hash = string_field(request, "publicMatrixSeedHash")?;
    validate_lowercase_hash(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let public_key_share_record = object_field(request, "publicKeyShareRecord")?;
    let public_key_share_proof_record = object_field(request, "publicKeyShareProofRecord")?;
    let same_secret_statement_record = object_field(request, "sameSecretStatementRecord")?;
    let setup_proof_binding = object_field(request, "setupProofBinding")?;
    let constant_commitments = setup_commitment_values_field(request, "constantCommitments")?;
    let public_share_coefficients_by_limb =
        u64_matrix_field(request, "publicShareCoefficientsByLimb")?;
    let secret_coefficients = i64_vector_field(request, "secretCoefficients")?;
    let opening_randomness_by_limb = i128_matrix3_field(request, "openingRandomnessByLimb")?;
    let error_coefficients_by_limb = i64_matrix_field(request, "errorCoefficientsByLimb")?;
    let proof_randomness_source = proof_randomness_source(request)?;
    let proof_randomness_seed_hex = string_field(request, "proofRandomnessSeedHex")?;
    validate_proof_randomness_seed(proof_randomness_seed_hex, "proofRandomnessSeedHex")?;

    let witness = PublicKeyShareLnpProofWitness {
        secret_coefficients,
        opening_randomness_by_limb,
        error_coefficients_by_limb,
    };
    let generation_input = PublicKeyShareLnpProofGenerationInput {
        public_matrix_seed_hash,
        public_key_share_record,
        public_key_share_proof_record,
        same_secret_statement_record,
        constant_commitments: &constant_commitments,
        public_share_coefficients_by_limb: &public_share_coefficients_by_limb,
        setup_proof_binding,
        witness: &witness,
        proof_randomness_seed_hex,
    };
    let proof_bytes = generate_public_key_share_lnp_relation_proof(generation_input)?;
    let verification =
        verify_public_key_share_lnp_relation_proof(PublicKeyShareLnpProofVerificationInput {
            public_matrix_seed_hash,
            public_key_share_record,
            public_key_share_proof_record,
            same_secret_statement_record,
            constant_commitments: &constant_commitments,
            public_share_coefficients_by_limb: &public_share_coefficients_by_limb,
            setup_proof_binding,
            proof_bytes: &proof_bytes,
        })?;
    let proof_bytes_hash = public_key_share_lnp_relation_proof_bytes_hash(&proof_bytes);

    Ok(json!({
        "ok": true,
        "operation": "generatePublicKeyShareLnpProof",
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "public-key-share",
        "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
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

pub(super) fn verify_public_key_share_lnp_relation_proof(
    input: PublicKeyShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<PublicKeyShareLnpProofVerification> {
    let PublicKeyShareLnpProofVerificationInput {
        public_matrix_seed_hash,
        public_key_share_record,
        public_key_share_proof_record,
        same_secret_statement_record,
        constant_commitments,
        public_share_coefficients_by_limb,
        setup_proof_binding,
        proof_bytes,
    } = input;

    validate_public_key_share_statement_material(
        constant_commitments,
        public_share_coefficients_by_limb,
    )?;
    let statement_hash = public_key_share_lnp_statement_hash(
        public_key_share_record,
        public_key_share_proof_record,
        same_secret_statement_record,
        constant_commitments,
        public_share_coefficients_by_limb,
        setup_proof_binding,
    )?;
    let parsed_proof = parse_public_key_share_lnp_relation_proof(
        proof_bytes,
        &statement_hash,
        constant_commitments,
    )?;
    let expected_parameter_profile_hash =
        super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?;
    if parsed_proof.parameter_profile_hash_hex != expected_parameter_profile_hash {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP proof is not bound to the accepted tbox parameter profile",
        ));
    }
    let encoded_commitments = encode_public_key_share_relation_commitments(
        &parsed_proof.public_key_relation_commitments_by_limb,
        &parsed_proof.error_support_commitments_by_limb,
        &parsed_proof.secret_commitment_relation_commitments,
        &parsed_proof.secret_support_commitments,
    )?;
    let statement_hash_hex = to_hex(&statement_hash);
    let layout = super::setup_proof::public_key_share_lnp_tbox_layout();
    let expected_tbox_prefix_binding_seed =
        super::setup_proof::setup_proof_lnp_tbox_prefix_binding_seed(
            &layout,
            &statement_hash_hex,
            &expected_parameter_profile_hash,
            &encoded_commitments,
        )?;
    let expected_tbox_prefix =
        encode_public_key_share_lnp_tbox_prefix(&layout, &expected_tbox_prefix_binding_seed)?;
    let expected_tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &expected_tbox_prefix,
        )?;
    if parsed_proof.tbox_commitment_prefix_hash != expected_tbox_commitment_prefix_hash {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP tbox commitment prefix is not bound to the statement and relation commitments",
        ));
    }
    let relation_commitment_hash_hex = public_key_share_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &expected_parameter_profile_hash,
        &parsed_proof.tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let recomputed_challenge = public_key_share_lnp_relation_challenge(
        &statement_hash_hex,
        &relation_commitment_hash_hex,
    )?;
    if parsed_proof.challenge != recomputed_challenge {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP proof scalar challenge does not match its setup-proof transcript",
        ));
    }
    let tbox_summary = super::setup_proof::verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
        &parsed_proof.tbox_proof_bytes,
    )?;
    verify_public_key_share_response_bounds(
        parsed_proof.challenge,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
        &parsed_proof.error_response_by_limb,
    )?;
    verify_secret_support_response(
        parsed_proof.challenge,
        &parsed_proof.secret_support_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
    )?;
    verify_error_support_responses(
        parsed_proof.challenge,
        &parsed_proof.error_support_commitments_by_limb,
        &parsed_proof.error_response_by_limb,
    )?;
    verify_secret_commitment_responses(
        public_matrix_seed_hash,
        constant_commitments,
        parsed_proof.challenge,
        &parsed_proof.secret_commitment_relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;
    verify_public_key_lifted_relation_responses(
        public_matrix_seed_hash,
        public_share_coefficients_by_limb,
        parsed_proof.challenge,
        &parsed_proof.public_key_relation_commitments_by_limb,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.error_response_by_limb,
        &parsed_proof.carry_response_by_limb,
    )?;

    Ok(PublicKeyShareLnpProofVerification {
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

fn validate_public_key_share_statement_material(
    constant_commitments: &[SetupCommitmentValue],
    public_share_coefficients_by_limb: &[Vec<u64>],
) -> CanonicalResult<()> {
    if constant_commitments.len() != DATA_PRIMES.len()
        || public_share_coefficients_by_limb.len() != DATA_PRIMES.len()
    {
        return Err(invalid_public_key_share_proof(
            "public-key share proof requires one VSS constant commitment and one public share vector for every Q_share limb",
        ));
    }
    let Some(first_commitment) = constant_commitments.first() else {
        return Err(invalid_public_key_share_proof(
            "public-key share proof requires non-empty VSS constant commitments",
        ));
    };
    let ring_degree = first_commitment.ring_degree;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(invalid_public_key_share_proof(
            "public-key share proof ring degree is outside the selected profile",
        ));
    }
    for (rns_limb_index, ((commitment, coefficients), rns_prime)) in constant_commitments
        .iter()
        .zip(public_share_coefficients_by_limb.iter())
        .zip(DATA_PRIMES.iter())
        .enumerate()
    {
        if commitment.source_rns_limb_index != rns_limb_index
            || commitment.source_message_modulus != *rns_prime
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(invalid_public_key_share_proof(
                "public-key share proof VSS constant commitments must follow accepted Q_share order",
            ));
        }
        if coefficients.len() != ring_degree
            || coefficients.iter().any(|value| *value >= *rns_prime)
        {
            return Err(invalid_public_key_share_proof(
                "public-key share coefficient vectors must be canonical residues with the proof ring degree",
            ));
        }
    }

    Ok(())
}

fn public_key_share_lnp_statement_hash(
    public_key_share_record: &Value,
    public_key_share_proof_record: &Value,
    same_secret_statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    public_share_coefficients_by_limb: &[Vec<u64>],
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
    let share_coefficient_hashes = public_share_coefficients_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, coefficients)| {
            json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b_i",
                "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
            })
        })
        .collect::<Vec<_>>();
    let parameter_profile_hash =
        super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?;
    let statement_json = canonical_json(&json!({
        "objectType": "PublicKeyShareLnpRelationProofStatement",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofBinding": setup_proof_binding,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "publicKeyShareTboxParameterProfileHash": parameter_profile_hash,
        "publicKeyShareRoot": public_key_share_record
            .get("publicKeyShareRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("public-key share root is required"))?,
        "publicKeyShareProofRoot": public_key_share_proof_record
            .get("publicKeyShareProofRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("public-key share proof root is required"))?,
        "sameSecretStatementRoot": same_secret_statement_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("same-secret statement root is required"))?,
        "trusteeSecretCommitmentRoot": same_secret_statement_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("trustee secret commitment root is required"))?,
        "trusteeRosterPosition": same_secret_statement_record
            .get("trusteeRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_public_key_share_proof("trustee roster position is required"))?,
        "publicMatrixSeedHash": public_key_share_proof_record
            .get("publicMatrixSeedHash")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("public matrix seed hash is required"))?,
        "publicKeyCrpRoot": public_key_share_proof_record
            .get("publicKeyCrpRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("public-key CRP root is required"))?,
        "publicAPolynomialRoot": public_key_share_proof_record
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_public_key_share_proof("public a polynomial root is required"))?,
        "ringDegree": constant_commitments
            .first()
            .map(|commitment| commitment.ring_degree)
            .ok_or_else(|| invalid_public_key_share_proof("constant commitments are required"))?,
        "rnsLimbCount": constant_commitments.len(),
        "publicKeyShareCoefficientHashes": share_coefficient_hashes,
        "constantCoefficientCommitmentRoots": commitment_roots,
        "relation": "for each Q_share limb, public-key share coefficients satisfy b_i - p*e_i + a*s_i + q_l*v_i = 0 over lifted integers while s_i opens the accepted VSS constant commitments",
        "carryBound": public_key_lifted_carry_bound(constant_commitments[0].ring_degree)?,
        "claimClosure": "repo-owned setup proof soundness, zero-knowledge, and QROM accounting is accepted by the setup proof accounting certificate",
    }))?;

    Ok(hash512(
        "sealed-lattice/setup/public-key-share/lnp-relation-statement-v1",
        &[statement_json.as_bytes()],
    ))
}

fn parse_public_key_share_lnp_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
    expected_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<ParsedPublicKeyShareLnpProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(proof_bytes, &mut cursor)?;
    if &magic != PUBLIC_KEY_SHARE_LNP_PROOF_MAGIC {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP proof has the wrong format marker",
        ));
    }
    let statement_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP proof is not bound to this statement",
        ));
    }
    let parameter_profile_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    let parameter_profile_hash_hex = to_hex(&parameter_profile_hash);
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP scalar challenge is outside the expected range",
        ));
    }
    if challenge > public_key_share_scalar_challenge_maximum()? {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP scalar challenge exceeds the accepted scalar challenge space",
        ));
    }
    let tbox_proof_byte_count =
        usize::try_from(read_u64(proof_bytes, &mut cursor)?).map_err(|_| {
            invalid_public_key_share_proof(
                "public-key share LNP tbox proof byte count does not fit usize",
            )
        })?;
    if tbox_proof_byte_count == 0 {
        return Err(invalid_public_key_share_proof(
            "public-key share LNP proof must include tbox proof bytes",
        ));
    }
    let tbox_proof_bytes = read_bytes(proof_bytes, &mut cursor, tbox_proof_byte_count)?;
    let layout = super::setup_proof::public_key_share_lnp_tbox_layout();
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;
    let ring_degree = expected_commitments[0].ring_degree;
    let public_key_relation_commitments_by_limb = expected_commitments
        .iter()
        .map(|_| {
            let mut relation_commitments = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                relation_commitments.push(read_signed_big_int_le_fixed(
                    proof_bytes,
                    &mut cursor,
                    PUBLIC_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT,
                )?);
            }
            Ok(relation_commitments)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_support_commitments_by_limb = expected_commitments
        .iter()
        .map(|_| {
            (0..ring_degree)
                .map(|_| {
                    Ok([
                        read_u64(proof_bytes, &mut cursor)?,
                        read_u64(proof_bytes, &mut cursor)?,
                        read_u64(proof_bytes, &mut cursor)?,
                        read_u64(proof_bytes, &mut cursor)?,
                        read_u64(proof_bytes, &mut cursor)?,
                    ])
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    validate_error_support_commitments(&error_support_commitments_by_limb)?;
    let secret_commitment_relation_commitments = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_secret_relation_commitment(proof_bytes, &mut cursor, expected_commitment)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secret_support_commitments = (0..ring_degree)
        .map(|_| {
            Ok([
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
            ])
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secret_response_coefficients = read_i128_vector(proof_bytes, &mut cursor, ring_degree)?;
    let negative_indicator_response_coefficients =
        read_i128_vector(proof_bytes, &mut cursor, ring_degree)?;
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
    let error_response_by_limb = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_i128_vector(proof_bytes, &mut cursor, expected_commitment.ring_degree)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let carry_response_by_limb = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_i128_vector(proof_bytes, &mut cursor, expected_commitment.ring_degree)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if cursor != proof_bytes.len() {
        return Err(invalid_public_key_share_proof(
            "public-key share proof has trailing bytes",
        ));
    }
    Ok(ParsedPublicKeyShareLnpProof {
        challenge,
        public_key_relation_commitments_by_limb,
        error_support_commitments_by_limb,
        secret_commitment_relation_commitments,
        secret_support_commitments,
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        error_response_by_limb,
        carry_response_by_limb,
        tbox_proof_bytes,
        tbox_commitment_prefix_hash,
        parameter_profile_hash_hex,
    })
}

fn validate_error_support_commitments(
    commitments_by_limb: &[Vec<[u64; 5]>],
) -> CanonicalResult<()> {
    let modulus = DATA_PRIMES[0];
    for support_commitments in commitments_by_limb {
        for support_commitment in support_commitments {
            if support_commitment.iter().any(|value| *value >= modulus) {
                return Err(invalid_public_key_share_proof(
                    "public-key error support commitment is not canonical",
                ));
            }
        }
    }

    Ok(())
}

fn read_secret_relation_commitment(
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
                    return Err(invalid_public_key_share_proof(
                        "public-key secret relation commitment coefficient is not canonical",
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

fn verify_secret_commitment_responses(
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
        return Err(invalid_public_key_share_proof(
            "public-key share proof commitment response limb count does not match the statement",
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
                lifted_secret_message_response(
                    *secret_response,
                    *negative_indicator_response,
                    constant_commitment.source_message_modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let response_randomness_bound = public_key_share_randomness_response_bound(challenge)?;
        verify_setup_signed_lifted_commitment_opening(
            public_matrix_seed_hash,
            &expected_response_commitment,
            &response_message_coefficients,
            randomness_response,
            response_randomness_bound,
        )
        .map_err(|_| {
            invalid_public_key_share_proof(format!(
                "public-key share proof VSS commitment response failed for Q_share limb {limb_index}"
            ))
        })?;
    }

    Ok(())
}

fn verify_public_key_share_response_bounds(
    challenge: u64,
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
    randomness_response_by_limb: &[Vec<Vec<i128>>],
    error_response_by_limb: &[Vec<i128>],
) -> CanonicalResult<()> {
    let secret_response_bound = public_key_share_message_response_bound(
        challenge,
        PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND,
        "public-key secret response",
    )?;
    verify_i128_vector_bound(
        secret_response_coefficients,
        secret_response_bound,
        "public-key secret response",
    )?;
    let negative_indicator_response_bound = public_key_share_message_response_bound(
        challenge,
        PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND,
        "public-key negative-indicator response",
    )?;
    verify_i128_vector_bound(
        negative_indicator_response_coefficients,
        negative_indicator_response_bound,
        "public-key negative-indicator response",
    )?;
    let randomness_response_bound = public_key_share_randomness_response_bound(challenge)?;
    for limb_columns in randomness_response_by_limb {
        for column in limb_columns {
            verify_i128_vector_bound(
                column,
                randomness_response_bound,
                "public-key opening-randomness response",
            )?;
        }
    }
    let error_response_bound = public_key_share_response_bound(
        PUBLIC_KEY_SHARE_ERROR_MASK_BITS,
        challenge,
        PUBLIC_KEY_SHARE_ERROR_INFINITY_BOUND,
        "public-key error response",
    )?;
    for limb_responses in error_response_by_limb {
        verify_i128_vector_bound(
            limb_responses,
            error_response_bound,
            "public-key error response",
        )?;
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
            invalid_public_key_share_proof(format!("{label} absolute value overflowed"))
        })?;
        if absolute_value > inclusive_bound {
            return Err(invalid_public_key_share_proof(format!(
                "{label} exceeds the accepted response bound"
            )));
        }
    }

    Ok(())
}

fn verify_public_key_lifted_relation_responses(
    public_matrix_seed_hash: &str,
    public_share_coefficients_by_limb: &[Vec<u64>],
    challenge: u64,
    relation_commitments_by_limb: &[Vec<BigInt>],
    secret_response_coefficients: &[i128],
    error_response_by_limb: &[Vec<i128>],
    carry_response_by_limb: &[Vec<i128>],
) -> CanonicalResult<()> {
    if relation_commitments_by_limb.len() != DATA_PRIMES.len()
        || error_response_by_limb.len() != DATA_PRIMES.len()
        || carry_response_by_limb.len() != DATA_PRIMES.len()
        || public_share_coefficients_by_limb.len() != DATA_PRIMES.len()
    {
        return Err(invalid_public_key_share_proof(
            "public-key share proof relation limb count does not match Q_share",
        ));
    }
    let ring_degree = secret_response_coefficients.len();
    for (rns_limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let public_a_coefficients =
            public_a_coefficients_for_relation(public_matrix_seed_hash, modulus, ring_degree);
        let public_a_secret_product = negacyclic_product_lifted_big_int(
            &public_a_coefficients,
            secret_response_coefficients,
        )?;
        let public_share_coefficients = &public_share_coefficients_by_limb[rns_limb_index];
        let relation_commitments = &relation_commitments_by_limb[rns_limb_index];
        let error_responses = &error_response_by_limb[rns_limb_index];
        let carry_responses = &carry_response_by_limb[rns_limb_index];
        if public_share_coefficients.len() != ring_degree
            || relation_commitments.len() != ring_degree
            || error_responses.len() != ring_degree
            || carry_responses.len() != ring_degree
        {
            return Err(invalid_public_key_share_proof(
                "public-key share proof relation vector width does not match the proof ring degree",
            ));
        }
        let carry_response_bound = public_key_lifted_carry_response_bound(challenge, ring_degree)?;
        for coefficient_index in 0..ring_degree {
            let carry_response = carry_responses[coefficient_index];
            if carry_response.checked_abs().ok_or_else(|| {
                invalid_public_key_share_proof(
                    "public-key carry response absolute value overflowed",
                )
            })? > carry_response_bound
            {
                return Err(invalid_public_key_share_proof(format!(
                    "public-key lifted carry response is outside the no-wrap bound at Q_share limb {rns_limb_index}, coefficient {coefficient_index}"
                )));
            }
            let mut checked_relation = BigInt::from(challenge)
                * BigInt::from(public_share_coefficients[coefficient_index]);
            checked_relation -=
                BigInt::from(PLAINTEXT_MODULUS) * BigInt::from(error_responses[coefficient_index]);
            checked_relation += public_a_secret_product[coefficient_index].clone();
            checked_relation += BigInt::from(modulus) * BigInt::from(carry_response);
            if checked_relation != relation_commitments[coefficient_index] {
                return Err(invalid_public_key_share_proof(format!(
                    "public-key lifted no-wrap relation failed at Q_share limb {rns_limb_index}, coefficient {coefficient_index}"
                )));
            }
        }
    }

    Ok(())
}

fn public_a_coefficients_for_relation(
    public_matrix_seed_hash: &str,
    modulus: u64,
    ring_degree: usize,
) -> Vec<u64> {
    dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
        .into_iter()
        .take(ring_degree)
        .collect()
}

fn negacyclic_product_lifted_i128(left: &[u64], right: &[i128]) -> CanonicalResult<Vec<i128>> {
    negacyclic_product_lifted_big_int(left, right)?
        .into_iter()
        .map(|coefficient| {
            coefficient.to_i128().ok_or_else(|| {
                invalid_public_key_share_proof(
                    "public-key lifted relation coefficient does not fit i128",
                )
            })
        })
        .collect()
}

fn negacyclic_product_lifted_big_int(left: &[u64], right: &[i128]) -> CanonicalResult<Vec<BigInt>> {
    if left.len() != right.len() {
        return Err(invalid_public_key_share_proof(
            "public-key lifted big-integer product inputs must have the same width",
        ));
    }
    let ring_degree = left.len();
    if DATA_PRIMES.len() < PUBLIC_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT {
        return Err(invalid_public_key_share_proof(
            "public-key lifted relation CRT basis is too small",
        ));
    }
    let crt_moduli = &DATA_PRIMES[..PUBLIC_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT];
    let product_residues_by_modulus = crt_moduli
        .iter()
        .map(|modulus| {
            let left_residues = left
                .iter()
                .map(|coefficient| coefficient % modulus)
                .collect::<Vec<_>>();
            let right_residues = right
                .iter()
                .map(|coefficient| signed_i128_residue_u64(*coefficient, *modulus))
                .collect::<CanonicalResult<Vec<_>>>()?;
            negacyclic_product_mod(&left_residues, &right_residues, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut output = Vec::with_capacity(ring_degree);
    for coefficient_index in 0..ring_degree {
        let residues = product_residues_by_modulus
            .iter()
            .map(|residues| residues[coefficient_index])
            .collect::<Vec<_>>();
        output.push(reconstruct_centered_big_int_from_crt_residues(
            &residues, crt_moduli,
        )?);
    }

    Ok(output)
}

fn reconstruct_centered_big_int_from_crt_residues(
    residues: &[u64],
    moduli: &[u64],
) -> CanonicalResult<BigInt> {
    if residues.len() != moduli.len() || residues.is_empty() {
        return Err(invalid_public_key_share_proof(
            "public-key lifted relation CRT inputs must have matching non-empty length",
        ));
    }
    let mut value = BigInt::from(residues[0]);
    let mut modulus_product = BigInt::from(moduli[0]);
    for (residue, modulus) in residues.iter().copied().zip(moduli.iter().copied()).skip(1) {
        let current_residue = nonnegative_big_int_mod_u64(&value, modulus)?;
        let delta = if residue >= current_residue {
            residue - current_residue
        } else {
            residue
                .checked_add(modulus)
                .and_then(|sum| sum.checked_sub(current_residue))
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key lifted CRT residue delta overflowed")
                })?
        };
        let product_residue = nonnegative_big_int_mod_u64(&modulus_product, modulus)?;
        let product_inverse = inverse_mod(product_residue, modulus)?;
        let correction = mul_mod(delta, product_inverse, modulus)?;
        value += &modulus_product * BigInt::from(correction);
        modulus_product *= BigInt::from(modulus);
    }

    if value > (&modulus_product >> 1_usize) {
        value -= modulus_product;
    }

    Ok(value)
}

fn nonnegative_big_int_mod_u64(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_big = BigInt::from(modulus);
    let residue = ((value % &modulus_big) + &modulus_big) % &modulus_big;
    residue.to_u64().ok_or_else(|| {
        invalid_public_key_share_proof("public-key lifted CRT residue does not fit u64")
    })
}

fn verify_secret_support_response(
    challenge: u64,
    support_commitments: &[[u64; 4]],
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
) -> CanonicalResult<()> {
    if support_commitments.len() != secret_response_coefficients.len()
        || negative_indicator_response_coefficients.len() != secret_response_coefficients.len()
    {
        return Err(invalid_public_key_share_proof(
            "public-key secret support commitment count does not match the secret response",
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
            "public-key secret negative indicator",
            coefficient_index,
            *negative_response,
            support_commitment[0],
            support_commitment[1],
            challenge_residue,
            modulus,
        )?;
        verify_boolean_support_response(
            "public-key secret shifted nonnegative indicator",
            coefficient_index,
            secret_response
                .checked_add(*negative_response)
                .ok_or_else(|| {
                    invalid_public_key_share_proof(
                        "public-key shifted secret support response overflowed",
                    )
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
        return Err(invalid_public_key_share_proof(format!(
            "{label} support check failed at coefficient {coefficient_index}"
        )));
    }

    Ok(())
}

fn verify_error_support_responses(
    challenge: u64,
    error_support_commitments_by_limb: &[Vec<[u64; 5]>],
    error_response_by_limb: &[Vec<i128>],
) -> CanonicalResult<()> {
    if error_support_commitments_by_limb.len() != error_response_by_limb.len() {
        return Err(invalid_public_key_share_proof(
            "public-key error support limb count does not match the response",
        ));
    }
    let modulus = DATA_PRIMES[0];
    let challenge_residue = challenge % modulus;
    for (rns_limb_index, (support_commitments, responses)) in error_support_commitments_by_limb
        .iter()
        .zip(error_response_by_limb.iter())
        .enumerate()
    {
        if support_commitments.len() != responses.len() {
            return Err(invalid_public_key_share_proof(
                "public-key error support width does not match the response",
            ));
        }
        for (coefficient_index, (support_commitment, response)) in
            support_commitments.iter().zip(responses.iter()).enumerate()
        {
            let response_residue = signed_i128_residue_u64(*response, modulus)?;
            let support_value =
                error_support_polynomial_value(response_residue, challenge_residue, modulus)?;
            let mut expanded_value = 0_u64;
            let mut challenge_power = 1_u64;
            for commitment in support_commitment {
                expanded_value = add_mod(
                    expanded_value,
                    mul_mod(*commitment, challenge_power, modulus)?,
                    modulus,
                )?;
                challenge_power = mul_mod(challenge_power, challenge_residue, modulus)?;
            }
            if support_value != expanded_value {
                return Err(invalid_public_key_share_proof(format!(
                    "public-key error support check failed at Q_share limb {rns_limb_index}, coefficient {coefficient_index}"
                )));
            }
        }
    }

    Ok(())
}

fn error_support_expansion_coefficients(
    mask: u64,
    witness: u64,
    modulus: u64,
) -> CanonicalResult<[u64; 5]> {
    let mask_power = powers(mask, 5, modulus)?;
    let witness_power = powers(witness, 5, modulus)?;
    Ok([
        mask_power[5],
        mul_mod(
            5 % modulus,
            mul_mod(mask_power[4], witness, modulus)?,
            modulus,
        )?,
        sub_mod(
            mul_mod(
                10 % modulus,
                mul_mod(mask_power[3], witness_power[2], modulus)?,
                modulus,
            )?,
            mul_mod(5 % modulus, mask_power[3], modulus)?,
            modulus,
        )?,
        sub_mod(
            mul_mod(
                10 % modulus,
                mul_mod(mask_power[2], witness_power[3], modulus)?,
                modulus,
            )?,
            mul_mod(
                15 % modulus,
                mul_mod(mask_power[2], witness, modulus)?,
                modulus,
            )?,
            modulus,
        )?,
        add_mod(
            sub_mod(
                mul_mod(
                    5 % modulus,
                    mul_mod(mask, witness_power[4], modulus)?,
                    modulus,
                )?,
                mul_mod(
                    15 % modulus,
                    mul_mod(mask, witness_power[2], modulus)?,
                    modulus,
                )?,
                modulus,
            )?,
            mul_mod(4 % modulus, mask, modulus)?,
            modulus,
        )?,
    ])
}

fn error_support_polynomial_value(
    value: u64,
    homogenizing_value: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let value_power = powers(value, 5, modulus)?;
    let homogenizing_power = powers(homogenizing_value, 5, modulus)?;
    add_mod(
        sub_mod(
            value_power[5],
            mul_mod(
                mul_mod(5 % modulus, value_power[3], modulus)?,
                homogenizing_power[2],
                modulus,
            )?,
            modulus,
        )?,
        mul_mod(
            mul_mod(4 % modulus, value, modulus)?,
            homogenizing_power[4],
            modulus,
        )?,
        modulus,
    )
}

fn powers(value: u64, highest_power: usize, modulus: u64) -> CanonicalResult<Vec<u64>> {
    let mut powers = vec![1_u64; highest_power + 1];
    for power_index in 1..=highest_power {
        powers[power_index] = mul_mod(powers[power_index - 1], value, modulus)?;
    }

    Ok(powers)
}

fn encode_public_key_share_relation_commitments(
    public_key_relation_commitments_by_limb: &[Vec<BigInt>],
    error_support_commitments_by_limb: &[Vec<[u64; 5]>],
    secret_commitment_relation_commitments: &[SetupCommitmentValue],
    secret_support_commitments: &[[u64; 4]],
) -> CanonicalResult<Vec<u8>> {
    let byte_count = public_key_relation_commitments_by_limb
        .iter()
        .try_fold(0_usize, |accumulator, coefficients| {
            accumulator
                .checked_add(
                    coefficients
                        .len()
                        .checked_mul(PUBLIC_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT)
                        .ok_or_else(|| {
                            invalid_public_key_share_proof(
                                "public-key relation commitment size overflowed",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key relation commitment size overflowed")
                })
        })?
        .checked_add(error_support_commitments_by_limb.iter().try_fold(
            0_usize,
            |accumulator, commitments| {
                accumulator
                    .checked_add(
                        commitments
                            .len()
                            .checked_mul(5)
                            .and_then(|count| count.checked_mul(8))
                            .ok_or_else(|| {
                                invalid_public_key_share_proof(
                                    "public-key error support size overflowed",
                                )
                            })?,
                    )
                    .ok_or_else(|| {
                        invalid_public_key_share_proof("public-key error support size overflowed")
                    })
            },
        )?)
        .ok_or_else(|| {
            invalid_public_key_share_proof("public-key proof commitment size overflowed")
        })?
        .checked_add(secret_commitment_relation_commitments.iter().try_fold(
            0_usize,
            |accumulator, commitment| {
                accumulator
                    .checked_add(setup_commitment_value_byte_count(commitment)?)
                    .ok_or_else(|| {
                        invalid_public_key_share_proof(
                            "public-key secret commitment size overflowed",
                        )
                    })
            },
        )?)
        .ok_or_else(|| {
            invalid_public_key_share_proof("public-key proof commitment size overflowed")
        })?
        .checked_add(
            secret_support_commitments
                .len()
                .checked_mul(4)
                .and_then(|count| count.checked_mul(8))
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key secret support size overflowed")
                })?,
        )
        .ok_or_else(|| {
            invalid_public_key_share_proof("public-key proof commitment size overflowed")
        })?;
    let mut encoded = Vec::with_capacity(byte_count);
    for relation_commitments in public_key_relation_commitments_by_limb {
        for coefficient in relation_commitments {
            write_signed_big_int_le_fixed(
                &mut encoded,
                coefficient,
                PUBLIC_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT,
            )?;
        }
    }
    for support_commitments in error_support_commitments_by_limb {
        for support_commitment in support_commitments {
            for coefficient in support_commitment {
                encoded.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }
    for commitment in secret_commitment_relation_commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    encoded.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
    for support_commitment in secret_support_commitments {
        for value in support_commitment {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }

    Ok(encoded)
}

fn public_key_share_lnp_relation_commitment_hash(
    statement_hash_hex: &str,
    parameter_profile_hash_hex: &str,
    tbox_commitment_prefix_hash: &str,
    encoded_commitments: &[u8],
) -> String {
    hash512_hex(
        PUBLIC_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN,
        &[
            statement_hash_hex.as_bytes(),
            parameter_profile_hash_hex.as_bytes(),
            tbox_commitment_prefix_hash.as_bytes(),
            encoded_commitments,
        ],
    )
}

fn public_key_share_lnp_relation_challenge(
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
) -> CanonicalResult<u64> {
    super::setup_proof::derive_setup_proof_scalar_challenge(
        "public-key-share",
        PUBLIC_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
        statement_hash_hex,
        relation_commitment_hash_hex,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
    )
}

fn public_key_share_scalar_challenge_maximum() -> CanonicalResult<u64> {
    let challenge_bits = u32::try_from(PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS).map_err(|_| {
        invalid_public_key_share_proof("public-key challenge bit count does not fit u32")
    })?;
    1_u64
        .checked_shl(challenge_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_public_key_share_proof("public-key challenge bound overflowed"))
}

fn public_key_share_message_response_bound(
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    public_key_share_response_bound(
        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
        challenge,
        witness_infinity_bound,
        label,
    )
}

fn public_key_share_randomness_response_bound(challenge: u64) -> CanonicalResult<i128> {
    public_key_share_response_bound(
        PUBLIC_KEY_SHARE_RANDOMNESS_MASK_BITS,
        challenge,
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        "public-key opening-randomness response",
    )
}

fn public_key_share_response_bound(
    mask_bits: usize,
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    let mask_bound = public_key_share_mask_magnitude_bound(mask_bits, label)?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| invalid_public_key_share_proof(format!("{label} bound overflowed")))?;
    mask_bound
        .checked_add(challenge_term)
        .ok_or_else(|| invalid_public_key_share_proof(format!("{label} bound overflowed")))
}

fn public_key_share_mask_magnitude_bound(mask_bits: usize, label: &str) -> CanonicalResult<i128> {
    let mask_bits = u32::try_from(mask_bits).map_err(|_| {
        invalid_public_key_share_proof(format!("{label} mask bit count overflowed"))
    })?;
    1_i128
        .checked_shl(mask_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_public_key_share_proof(format!("{label} mask bound overflowed")))
}

fn setup_commitment_value_byte_count(commitment: &SetupCommitmentValue) -> CanonicalResult<usize> {
    commitment
        .limbs
        .iter()
        .try_fold(0_usize, |accumulator, limb| {
            let limb_count = limb.rows.iter().try_fold(0_usize, |row_accumulator, row| {
                row_accumulator.checked_add(row.len()).ok_or_else(|| {
                    invalid_public_key_share_proof("public-key commitment row size overflowed")
                })
            })?;
            accumulator
                .checked_add(limb_count.checked_mul(8).ok_or_else(|| {
                    invalid_public_key_share_proof("public-key commitment limb size overflowed")
                })?)
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key commitment size overflowed")
                })
        })
}

fn signed_i128_residue_u64(value: i128, modulus: u64) -> CanonicalResult<u64> {
    modular_arithmetic::signed_i128_residue_u64(value, modulus).map_err(|failure| match failure {
        SignedResidueFailure::Overflowed => {
            invalid_public_key_share_proof("public-key signed residue overflowed")
        }
        SignedResidueFailure::DoesNotFitU64 => {
            invalid_public_key_share_proof("public-key signed residue does not fit u64")
        }
    })
}

fn public_key_lifted_carry_bound(ring_degree: usize) -> CanonicalResult<i128> {
    i128::try_from(ring_degree)
        .map_err(|_| invalid_public_key_share_proof("public-key ring degree does not fit i128"))?
        .checked_add(3)
        .ok_or_else(|| invalid_public_key_share_proof("public-key carry bound overflowed"))
}

fn public_key_lifted_carry_response_bound(
    challenge: u64,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    let mask_bound = 1_i128
        .checked_shl(PUBLIC_KEY_SHARE_CARRY_MASK_BITS as u32)
        .ok_or_else(|| invalid_public_key_share_proof("public-key carry mask bound overflowed"))?;
    let witness_bound = public_key_lifted_carry_bound(ring_degree)?;
    mask_bound
        .checked_add(
            i128::from(challenge)
                .checked_mul(witness_bound)
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key carry response bound overflowed")
                })?,
        )
        .ok_or_else(|| invalid_public_key_share_proof("public-key carry response bound overflowed"))
}

fn checked_i128_sum(values: &[i128]) -> CanonicalResult<i128> {
    values.iter().try_fold(0_i128, |accumulator, value| {
        accumulator.checked_add(*value).ok_or_else(|| {
            invalid_public_key_share_proof("public-key lifted relation sum overflowed")
        })
    })
}

fn lifted_secret_message_response(
    secret_response: i128,
    negative_indicator_response: i128,
    source_message_modulus: u64,
) -> CanonicalResult<i128> {
    let lifted = secret_response
        .checked_add(
            i128::from(source_message_modulus)
                .checked_mul(negative_indicator_response)
                .ok_or_else(|| {
                    invalid_public_key_share_proof(
                        "public-key lifted secret response multiplication overflowed",
                    )
                })?,
        )
        .ok_or_else(|| {
            invalid_public_key_share_proof("public-key lifted secret response overflowed")
        })?;
    if !setup_signed_coefficient_fits_centered_commitment_modulus_product(lifted) {
        return Err(invalid_public_key_share_proof(
            "public-key lifted secret response wraps in the centered setup commitment modulus product",
        ));
    }

    Ok(lifted)
}

fn read_signed_big_int_le_fixed(
    proof_bytes: &[u8],
    cursor: &mut usize,
    byte_count: usize,
) -> CanonicalResult<BigInt> {
    let end = cursor.checked_add(byte_count).ok_or_else(|| {
        invalid_public_key_share_proof("public-key signed big-integer read offset overflowed")
    })?;
    let slice = proof_bytes.get(*cursor..end).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key proof ended before a signed big-integer relation commitment",
        )
    })?;
    *cursor = end;

    Ok(BigInt::from_signed_bytes_le(slice))
}

fn write_signed_big_int_le_fixed(
    output: &mut Vec<u8>,
    value: &BigInt,
    byte_count: usize,
) -> CanonicalResult<()> {
    let bit_count = byte_count
        .checked_mul(8)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| {
            invalid_public_key_share_proof("public-key signed big-integer width is invalid")
        })?;
    let range_limit = BigInt::from(1_u8) << bit_count;
    if value < &(-&range_limit) || value >= &range_limit {
        return Err(invalid_public_key_share_proof(
            "public-key relation commitment exceeds the fixed signed big-integer encoding width",
        ));
    }
    let extension_byte = if value.sign() == Sign::Minus {
        0xff
    } else {
        0x00
    };
    let encoded = value.to_signed_bytes_le();
    if encoded.len() > byte_count {
        return Err(invalid_public_key_share_proof(
            "public-key relation commitment is not canonical for the fixed-width signed encoding",
        ));
    }
    let mut fixed = vec![extension_byte; byte_count];
    fixed[..encoded.len()].copy_from_slice(&encoded);
    output.extend_from_slice(&fixed);

    Ok(())
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
        .ok_or_else(|| invalid_public_key_share_proof("public-key proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_public_key_share_proof("public-key proof ended early"))?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn read_bytes(proof_bytes: &[u8], cursor: &mut usize, length: usize) -> CanonicalResult<Vec<u8>> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_public_key_share_proof("public-key proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_public_key_share_proof("public-key proof ended early"))?;
    *cursor = end;

    Ok(bytes.to_vec())
}

fn invalid_public_key_share_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_public_key_share_proof(format!("{field_name} must be a non-empty string"))
        })
}

fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| invalid_public_key_share_proof(format!("{field_name} must be an object")))
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_public_key_share_proof(format!("{field_name} must be an array")))
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

fn u64_matrix_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<u64>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_public_key_share_proof(format!(
                        "{field_name}.{row_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    item.as_u64().ok_or_else(|| {
                        invalid_public_key_share_proof(format!(
                            "{field_name}.{row_index}.{column_index} must be an unsigned integer"
                        ))
                    })
                })
                .collect()
        })
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
                    invalid_public_key_share_proof(format!(
                        "{field_name}.{item_index} must be a signed 64-bit integer"
                    ))
                })
        })
        .collect()
}

fn i64_matrix_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i64>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_public_key_share_proof(format!("{field_name}.{row_index} must be an array"))
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    decimal_i128_value(item)
                        .and_then(|item| i64::try_from(item).ok())
                        .ok_or_else(|| {
                            invalid_public_key_share_proof(format!(
                                "{field_name}.{row_index}.{column_index} must be a signed 64-bit integer"
                            ))
                        })
                })
                .collect()
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
                    invalid_public_key_share_proof(format!(
                        "{field_name}.{outer_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(middle_index, inner_value)| {
                    inner_value
                        .as_array()
                        .ok_or_else(|| {
                            invalid_public_key_share_proof(format!(
                                "{field_name}.{outer_index}.{middle_index} must be an array"
                            ))
                        })?
                        .iter()
                        .enumerate()
                        .map(|(inner_index, item)| {
                            decimal_i128_value(item).ok_or_else(|| {
                                invalid_public_key_share_proof(format!(
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
        _ => Err(invalid_public_key_share_proof(
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

    Err(invalid_public_key_share_proof(format!(
        "{field_name} must be lowercase 512-bit hex"
    )))
}

fn validate_proof_randomness_seed(seed_hex: &str, field_name: &str) -> CanonicalResult<()> {
    validate_lowercase_hash(seed_hex, field_name)
}

pub(super) struct PublicKeyShareLnpProofWitness {
    pub(super) secret_coefficients: Vec<i64>,
    pub(super) opening_randomness_by_limb: Vec<Vec<Vec<i128>>>,
    pub(super) error_coefficients_by_limb: Vec<Vec<i64>>,
}

pub(super) struct PublicKeyShareLnpProofGenerationInput<'a> {
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) public_key_share_record: &'a Value,
    pub(super) public_key_share_proof_record: &'a Value,
    pub(super) same_secret_statement_record: &'a Value,
    pub(super) constant_commitments: &'a [SetupCommitmentValue],
    pub(super) public_share_coefficients_by_limb: &'a [Vec<u64>],
    pub(super) setup_proof_binding: &'a Value,
    pub(super) witness: &'a PublicKeyShareLnpProofWitness,
    pub(super) proof_randomness_seed_hex: &'a str,
}

pub(super) fn generate_public_key_share_lnp_relation_proof(
    input: PublicKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    let PublicKeyShareLnpProofGenerationInput {
        public_matrix_seed_hash,
        public_key_share_record,
        public_key_share_proof_record,
        same_secret_statement_record,
        constant_commitments,
        public_share_coefficients_by_limb,
        setup_proof_binding,
        witness,
        proof_randomness_seed_hex,
    } = input;

    validate_public_key_share_statement_material(
        constant_commitments,
        public_share_coefficients_by_limb,
    )?;
    if witness.secret_coefficients.len() != constant_commitments[0].ring_degree
        || witness.opening_randomness_by_limb.len() != constant_commitments.len()
        || witness.error_coefficients_by_limb.len() != constant_commitments.len()
    {
        return Err(invalid_public_key_share_proof(
            "public-key share proof witness shape does not match statement material",
        ));
    }
    for error_coefficients in &witness.error_coefficients_by_limb {
        if error_coefficients.len() != constant_commitments[0].ring_degree
            || error_coefficients
                .iter()
                .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(invalid_public_key_share_proof(
                "public-key share proof error witness must be centered-binomial support",
            ));
        }
    }
    let statement_hash = public_key_share_lnp_statement_hash(
        public_key_share_record,
        public_key_share_proof_record,
        same_secret_statement_record,
        constant_commitments,
        public_share_coefficients_by_limb,
        setup_proof_binding,
    )?;
    let statement_hash_hex = to_hex(&statement_hash);
    let parameter_profile_hash =
        super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?;
    let parameter_profile_hash_bytes = hash_hex_to_fixed_bytes(&parameter_profile_hash)?;
    let layout = super::setup_proof::public_key_share_lnp_tbox_layout();
    let ring_degree = constant_commitments[0].ring_degree;
    let secret_masks = (0..ring_degree)
        .map(|coefficient_index| {
            sample_public_key_share_message_mask_i128(
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
            _ => Err(invalid_public_key_share_proof(
                "public-key share proof secret witness must be ternary",
            )),
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_masks = (0..ring_degree)
        .map(|coefficient_index| {
            sample_public_key_share_message_mask_i128(
                &statement_hash,
                proof_randomness_seed_hex,
                1,
                coefficient_index,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_masks_by_limb = constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, _)| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    sample_public_key_share_error_mask_i128(
                        &statement_hash,
                        proof_randomness_seed_hex,
                        rns_limb_index,
                        coefficient_index,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
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
                            sample_public_key_share_mask_i128(
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
    let carry_masks_by_limb = constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            (0..commitment.ring_degree)
                .map(|coefficient_index| {
                    sample_public_key_share_carry_mask_i128(
                        &statement_hash,
                        proof_randomness_seed_hex,
                        rns_limb_index,
                        coefficient_index,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let carry_witnesses_by_limb = constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            let modulus = commitment.source_message_modulus;
            let public_a_coefficients =
                public_a_coefficients_for_relation(public_matrix_seed_hash, modulus, ring_degree);
            public_key_lifted_carry_witnesses(
                &public_a_coefficients,
                &witness.secret_coefficients,
                &witness.error_coefficients_by_limb[rns_limb_index],
                &public_share_coefficients_by_limb[rns_limb_index],
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let public_key_relation_commitments_by_limb = constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            let modulus = commitment.source_message_modulus;
            let public_a_coefficients =
                public_a_coefficients_for_relation(public_matrix_seed_hash, modulus, ring_degree);
            let public_a_secret_mask_product =
                negacyclic_product_lifted_big_int(&public_a_coefficients, &secret_masks)?;
            error_masks_by_limb[rns_limb_index]
                .iter()
                .zip(public_a_secret_mask_product.iter())
                .zip(carry_masks_by_limb[rns_limb_index].iter())
                .map(|((error_mask, product_coefficient), carry_mask)| {
                    let mut relation_commitment = product_coefficient.clone();
                    relation_commitment -=
                        BigInt::from(PLAINTEXT_MODULUS) * BigInt::from(*error_mask);
                    relation_commitment += BigInt::from(modulus) * BigInt::from(*carry_mask);
                    Ok(relation_commitment)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_support_commitments_by_limb = witness
        .error_coefficients_by_limb
        .iter()
        .zip(error_masks_by_limb.iter())
        .map(|(error_coefficients, error_masks)| {
            error_coefficients
                .iter()
                .zip(error_masks.iter())
                .map(|(error_coefficient, error_mask)| {
                    error_support_expansion_coefficients(
                        signed_i128_residue_u64(*error_mask, DATA_PRIMES[0])?,
                        signed_i128_residue_u64(i128::from(*error_coefficient), DATA_PRIMES[0])?,
                        DATA_PRIMES[0],
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secret_commitment_relation_commitments = constant_commitments
        .iter()
        .zip(randomness_masks_by_limb.iter())
        .map(|(commitment, randomness_masks)| {
            let mask_message_coefficients = secret_masks
                .iter()
                .zip(negative_indicator_masks.iter())
                .map(|(secret_mask, negative_mask)| {
                    lifted_secret_message_response(
                        *secret_mask,
                        *negative_mask,
                        commitment.source_message_modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            compute_setup_signed_lifted_commitment(
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
    let secret_support_commitments = secret_masks
        .iter()
        .zip(witness.secret_coefficients.iter())
        .zip(
            negative_indicator_masks
                .iter()
                .zip(negative_indicator_coefficients.iter()),
        )
        .map(
            |((secret_mask, secret_coefficient), (negative_mask, negative_indicator))| {
                secret_support_commitment(
                    *secret_mask,
                    i128::from(*secret_coefficient),
                    *negative_mask,
                    i128::from(*negative_indicator),
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    let encoded_commitments = encode_public_key_share_relation_commitments(
        &public_key_relation_commitments_by_limb,
        &error_support_commitments_by_limb,
        &secret_commitment_relation_commitments,
        &secret_support_commitments,
    )?;
    let tbox_prefix_binding_seed = super::setup_proof::setup_proof_lnp_tbox_prefix_binding_seed(
        &layout,
        &statement_hash_hex,
        &parameter_profile_hash,
        &encoded_commitments,
    )?;
    let tbox_prefix = encode_public_key_share_lnp_tbox_prefix(&layout, &tbox_prefix_binding_seed)?;
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(&layout, &tbox_prefix)?;
    let relation_commitment_hash = public_key_share_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &parameter_profile_hash,
        &tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let challenge =
        public_key_share_lnp_relation_challenge(&statement_hash_hex, &relation_commitment_hash)?;
    let mut tbox_proof_bytes = tbox_prefix;
    super::setup_proof::append_setup_proof_lnp_tbox_generated_suffix(
        &mut tbox_proof_bytes,
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash,
    )?;
    let secret_response_coefficients = secret_masks
        .iter()
        .zip(witness.secret_coefficients.iter())
        .map(|(secret_mask, secret_coefficient)| {
            secret_mask
                .checked_add(
                    i128::from(challenge)
                        .checked_mul(i128::from(*secret_coefficient))
                        .ok_or_else(|| {
                            invalid_public_key_share_proof("public-key secret response overflowed")
                        })?,
                )
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key secret response overflowed")
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_response_coefficients = negative_indicator_masks
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(negative_mask, negative_indicator)| {
            negative_mask
                .checked_add(
                    i128::from(challenge)
                        .checked_mul(i128::from(*negative_indicator))
                        .ok_or_else(|| {
                            invalid_public_key_share_proof(
                                "public-key negative response overflowed",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    invalid_public_key_share_proof("public-key negative response overflowed")
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_response_by_limb = randomness_masks_by_limb
        .iter()
        .zip(witness.opening_randomness_by_limb.iter())
        .map(|(randomness_masks, opening_randomness)| {
            randomness_masks
                .iter()
                .zip(opening_randomness.iter())
                .map(|(mask_column, witness_column)| {
                    mask_column
                        .iter()
                        .zip(witness_column.iter())
                        .map(|(mask, witness_value)| {
                            mask.checked_add(
                                i128::from(challenge)
                                    .checked_mul(*witness_value)
                                    .ok_or_else(|| {
                                        invalid_public_key_share_proof(
                                            "public-key randomness response overflowed",
                                        )
                                    })?,
                            )
                            .ok_or_else(|| {
                                invalid_public_key_share_proof(
                                    "public-key randomness response overflowed",
                                )
                            })
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_response_by_limb = error_masks_by_limb
        .iter()
        .zip(witness.error_coefficients_by_limb.iter())
        .map(|(error_masks, error_coefficients)| {
            error_masks
                .iter()
                .zip(error_coefficients.iter())
                .map(|(error_mask, error_coefficient)| {
                    error_mask
                        .checked_add(
                            i128::from(challenge)
                                .checked_mul(i128::from(*error_coefficient))
                                .ok_or_else(|| {
                                    invalid_public_key_share_proof(
                                        "public-key error response overflowed",
                                    )
                                })?,
                        )
                        .ok_or_else(|| {
                            invalid_public_key_share_proof("public-key error response overflowed")
                        })
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let carry_response_by_limb = carry_masks_by_limb
        .iter()
        .zip(carry_witnesses_by_limb.iter())
        .map(|(carry_masks, carry_witnesses)| {
            carry_masks
                .iter()
                .zip(carry_witnesses.iter())
                .map(|(carry_mask, carry_witness)| {
                    carry_mask
                        .checked_add(
                            i128::from(challenge)
                                .checked_mul(*carry_witness)
                                .ok_or_else(|| {
                                    invalid_public_key_share_proof(
                                        "public-key carry response overflowed",
                                    )
                                })?,
                        )
                        .ok_or_else(|| {
                            invalid_public_key_share_proof("public-key carry response overflowed")
                        })
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(PUBLIC_KEY_SHARE_LNP_PROOF_MAGIC);
    proof_bytes.extend_from_slice(&statement_hash);
    proof_bytes.extend_from_slice(&parameter_profile_hash_bytes);
    proof_bytes.extend_from_slice(&challenge.to_le_bytes());
    proof_bytes.extend_from_slice(
        &u64::try_from(tbox_proof_bytes.len())
            .map_err(|_| {
                invalid_public_key_share_proof(
                    "public-key LNP tbox proof byte count does not fit u64",
                )
            })?
            .to_le_bytes(),
    );
    proof_bytes.extend_from_slice(&tbox_proof_bytes);
    for relation_commitments in &public_key_relation_commitments_by_limb {
        for coefficient in relation_commitments {
            write_signed_big_int_le_fixed(
                &mut proof_bytes,
                coefficient,
                PUBLIC_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT,
            )?;
        }
    }
    for support_commitments in &error_support_commitments_by_limb {
        for support_commitment in support_commitments {
            for coefficient in support_commitment {
                proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }
    for commitment in &secret_commitment_relation_commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
    for support_commitment in &secret_support_commitments {
        for coefficient in support_commitment {
            proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
        }
    }
    write_i128_vector(&mut proof_bytes, &secret_response_coefficients);
    write_i128_vector(&mut proof_bytes, &negative_indicator_response_coefficients);
    for randomness_response in &randomness_response_by_limb {
        for column in randomness_response {
            write_i128_vector(&mut proof_bytes, column);
        }
    }
    for error_response in &error_response_by_limb {
        write_i128_vector(&mut proof_bytes, error_response);
    }
    for carry_response in &carry_response_by_limb {
        write_i128_vector(&mut proof_bytes, carry_response);
    }

    Ok(proof_bytes)
}

fn hash_hex_to_fixed_bytes(hash_hex: &str) -> CanonicalResult<[u8; 64]> {
    if hash_hex.len() != 128 {
        return Err(invalid_public_key_share_proof(
            "public-key hash must be 64 bytes",
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
        _ => Err(invalid_public_key_share_proof(
            "public-key hash contains a non-hex character",
        )),
    }
}

fn encode_public_key_share_lnp_tbox_prefix(
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = PublicKeyShareLnpBitWriter::new();
    encode_public_key_share_lnp_uniform_polyvec(
        &mut writer,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        Some(&layout.proof_modulus),
        proof_randomness_seed_hex,
        0,
    )?;
    encode_public_key_share_lnp_uniform_polyvec(
        &mut writer,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        Some(&layout.proof_modulus),
        proof_randomness_seed_hex,
        1,
    )?;
    encode_public_key_share_lnp_uniform_polyvec(
        &mut writer,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        layout
            .proof_modulus_bit_count
            .checked_sub(layout.compression_dropped_bits)
            .ok_or_else(|| {
                invalid_public_key_share_proof("public-key LNP compression underflowed")
            })?,
        None,
        proof_randomness_seed_hex,
        2,
    )?;

    Ok(writer.into_bytes())
}

fn encode_public_key_share_lnp_uniform_polyvec(
    writer: &mut PublicKeyShareLnpBitWriter<'_>,
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
            invalid_public_key_share_proof("public-key LNP tbox coefficient count overflowed")
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
                    invalid_public_key_share_proof("public-key LNP tbox bit count overflowed")
                })? / 8
            ];
            writer.write_little_endian_bytes_bits(&zero_residue_bytes, bit_count)?;
            continue;
        }
        let residue_bytes = super::setup_proof::sample_setup_proof_lnp_tbox_uniform_residue_bytes(
            "sealed-lattice/setup/public-key-share/lnp-tbox-uniform-v1",
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
enum PublicKeyShareLnpBitWriterStorage<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut Vec<u8>),
}

struct PublicKeyShareLnpBitWriter<'a> {
    storage: PublicKeyShareLnpBitWriterStorage<'a>,
    bit_offset: usize,
}

impl<'a> PublicKeyShareLnpBitWriter<'a> {
    fn new() -> Self {
        Self {
            storage: PublicKeyShareLnpBitWriterStorage::Owned(Vec::new()),
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
            storage: PublicKeyShareLnpBitWriterStorage::Borrowed(bytes),
            bit_offset,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            PublicKeyShareLnpBitWriterStorage::Owned(bytes) => bytes,
            PublicKeyShareLnpBitWriterStorage::Borrowed(_) => {
                unreachable!("borrowed public-key LNP bit writer is not consumed by value")
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
            return Err(invalid_public_key_share_proof(
                "public-key LNP byte residue is shorter than its declared bit count",
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
            PublicKeyShareLnpBitWriterStorage::Owned(bytes) => bytes,
            PublicKeyShareLnpBitWriterStorage::Borrowed(bytes) => bytes,
        }
    }
}

fn secret_support_commitment(
    secret_mask: i128,
    secret_coefficient: i128,
    negative_indicator_mask: i128,
    negative_indicator: i128,
) -> CanonicalResult<[u64; 4]> {
    let modulus = DATA_PRIMES[0];
    let negative_mask_residue = signed_i128_residue_u64(negative_indicator_mask, modulus)?;
    let negative_witness_residue = signed_i128_residue_u64(negative_indicator, modulus)?;
    let shifted_mask_residue =
        signed_i128_residue_u64(secret_mask + negative_indicator_mask, modulus)?;
    let shifted_witness_residue =
        signed_i128_residue_u64(secret_coefficient + negative_indicator, modulus)?;
    Ok([
        mul_mod(negative_mask_residue, negative_mask_residue, modulus)?,
        sub_mod(
            mul_mod(
                2 % modulus,
                mul_mod(negative_mask_residue, negative_witness_residue, modulus)?,
                modulus,
            )?,
            negative_mask_residue,
            modulus,
        )?,
        mul_mod(shifted_mask_residue, shifted_mask_residue, modulus)?,
        sub_mod(
            mul_mod(
                2 % modulus,
                mul_mod(shifted_mask_residue, shifted_witness_residue, modulus)?,
                modulus,
            )?,
            shifted_mask_residue,
            modulus,
        )?,
    ])
}

fn public_key_lifted_carry_witnesses(
    public_a_coefficients: &[u64],
    secret_coefficients: &[i64],
    error_coefficients: &[i64],
    public_share_coefficients: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<i128>> {
    let secret_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let product_coefficients =
        negacyclic_product_lifted_i128(public_a_coefficients, &secret_coefficients)?;
    if error_coefficients.len() != product_coefficients.len()
        || public_share_coefficients.len() != product_coefficients.len()
    {
        return Err(invalid_public_key_share_proof(
            "public-key carry witness inputs must have the proof ring degree",
        ));
    }
    let carry_bound = public_key_lifted_carry_bound(product_coefficients.len())?;
    error_coefficients
        .iter()
        .zip(public_share_coefficients.iter())
        .zip(product_coefficients.iter())
        .enumerate()
        .map(
            |(coefficient_index, ((error_coefficient, public_share), product_coefficient))| {
                let numerator = checked_i128_sum(&[
                    i128::from(PLAINTEXT_MODULUS)
                        .checked_mul(i128::from(*error_coefficient))
                        .ok_or_else(|| {
                            invalid_public_key_share_proof(
                                "public-key carry witness error term overflowed",
                            )
                        })?,
                    product_coefficient.checked_neg().ok_or_else(|| {
                        invalid_public_key_share_proof(
                            "public-key carry witness product term overflowed",
                        )
                    })?,
                    i128::from(*public_share).checked_neg().ok_or_else(|| {
                        invalid_public_key_share_proof(
                            "public-key carry witness public share term overflowed",
                        )
                    })?,
                ])?;
                let modulus_wide = i128::from(modulus);
                if numerator % modulus_wide != 0 {
                    return Err(invalid_public_key_share_proof(format!(
                        "public-key lifted relation is not divisible by q_l at coefficient {coefficient_index}"
                    )));
                }
                let carry = numerator / modulus_wide;
                if carry.checked_abs().ok_or_else(|| {
                    invalid_public_key_share_proof(
                        "public-key carry witness absolute value overflowed",
                    )
                })? > carry_bound
                {
                    return Err(invalid_public_key_share_proof(format!(
                        "public-key carry witness exceeds the no-wrap bound at coefficient {coefficient_index}"
                    )));
                }
                Ok(carry)
            },
        )
        .collect()
}

fn sample_public_key_share_message_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    column_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let mask = sample_public_key_share_mask_i128(
        statement_hash,
        proof_randomness_seed_hex,
        0,
        column_index,
        coefficient_index,
    )?;
    let bound = 1_i128
        .checked_shl(PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS as u32)
        .ok_or_else(|| {
            invalid_public_key_share_proof("public-key message mask bound overflowed")
        })?;
    Ok(mask % bound)
}

fn sample_public_key_share_carry_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    limb_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let mask = sample_public_key_share_mask_i128(
        statement_hash,
        proof_randomness_seed_hex,
        DATA_PRIMES.len() + 2,
        limb_index,
        coefficient_index,
    )?;
    let bound = 1_i128
        .checked_shl(PUBLIC_KEY_SHARE_CARRY_MASK_BITS as u32)
        .ok_or_else(|| invalid_public_key_share_proof("public-key carry mask bound overflowed"))?;
    Ok(mask % bound)
}

fn sample_public_key_share_error_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    limb_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let mask = sample_public_key_share_mask_i128(
        statement_hash,
        proof_randomness_seed_hex,
        1,
        limb_index,
        coefficient_index,
    )?;
    let bound = 1_i128
        .checked_shl(PUBLIC_KEY_SHARE_ERROR_MASK_BITS as u32)
        .ok_or_else(|| invalid_public_key_share_proof("public-key error mask bound overflowed"))?;
    Ok(mask % bound)
}

fn sample_public_key_share_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    domain_index: usize,
    column_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let domain_bytes = (domain_index as u64).to_le_bytes();
    let column_bytes = (column_index as u64).to_le_bytes();
    let coefficient_bytes = (coefficient_index as u64).to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/public-key-share/lnp-proof-mask-v1",
        &[
            statement_hash,
            proof_randomness_seed_hex.as_bytes(),
            &domain_bytes,
            &column_bytes,
            &coefficient_bytes,
        ],
    );
    let mut mask_bytes = [0_u8; 16];
    mask_bytes[..10].copy_from_slice(&block[..10]);
    let value = i128::from_le_bytes(mask_bytes);
    let sign = if block[10] & 1 == 0 { 1_i128 } else { -1_i128 };
    let bound = 1_i128
        .checked_shl(PUBLIC_KEY_SHARE_RANDOMNESS_MASK_BITS as u32)
        .ok_or_else(|| invalid_public_key_share_proof("public-key proof mask bound overflowed"))?;
    Ok(sign * (value % bound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_share_lnp_relation_proof_refuses_unbounded_response_residue() {
        let challenge = public_key_share_scalar_challenge_maximum().expect("challenge maximum");
        let accepted_bound = public_key_share_response_bound(
            PUBLIC_KEY_SHARE_ERROR_MASK_BITS,
            challenge,
            PUBLIC_KEY_SHARE_ERROR_INFINITY_BOUND,
            "test public-key error response",
        )
        .expect("public-key error response bound");
        let oversized_same_residue_response = accepted_bound
            .checked_add(i128::from(DATA_PRIMES[0]))
            .expect("oversized response");

        let error = verify_public_key_share_response_bounds(
            challenge,
            &[0],
            &[0],
            &[],
            &[vec![oversized_same_residue_response]],
        )
        .expect_err("oversized response should fail before modular support checks");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("response bound"));
    }
}
