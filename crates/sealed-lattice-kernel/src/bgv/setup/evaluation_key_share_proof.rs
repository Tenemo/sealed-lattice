use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::{
            coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
        },
        evaluator::{
            key_switch::{KEY_SWITCH_SAMPLE_DOMAIN, PLAINTEXT_MODULUS_I64},
            prg::DeterministicSampler,
        },
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_varuint},
    hashing::{canonical_json, derive_protocol_hash, hash512, hash512_hex, to_hex},
};

use super::{
    accepted_setup::{COLLECTIVE_BGV_SETUP_PROFILE_ID, setup_proof_profile_hash},
    commitment::{
        SETUP_COMMITMENT_PROFILE_ID, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentLimb, SetupCommitmentValue,
        compute_setup_commitment, linear_combination_setup_commitments,
        parse_setup_commitment_full_value, setup_commitment_modulus_product, setup_commitment_root,
        verify_setup_lifted_commitment_opening,
    },
    setup_proof::{SETUP_PROOF_PROFILE_ID, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES},
};

pub(super) const RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-relinearization-key-share-relation-verified-review-gated";
pub(super) const RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes, setup-proof challenge domain, binary proof-material schema, same-secret-bound secret opening response, deterministic key-switch sampler, public component-vector material, lifted key-switch algebra, round-one same-secret source response, generator-side round-two aggregate-source product validation, centered-binomial error support, carried no-wrap responses, fixed response bounds, and root-bound relinearization source binding records verified; verifier-side round-two aggregate-square source proof closure plus external AB-DLOP/LNP soundness and zero-knowledge review remain required before claim-bearing relinearization acceptance";
pub(super) const GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-galois-key-share-relation-verified-review-gated";
pub(super) const GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes, setup-proof challenge domain, binary proof-material schema, same-secret-bound secret opening response, deterministic key-switch sampler, public component-vector material, Galois automorphism source response, lifted key-switch algebra, centered-binomial error support, carried no-wrap responses, and fixed response bounds verified; external AB-DLOP/LNP soundness and zero-knowledge review remain required before claim-bearing Galois-key acceptance";

pub(super) const EVALUATION_KEY_SHARE_COMPONENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/evaluation-key-share-component-vector-v1";
pub(super) const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING: &str =
    "binary-chunked-key-switch-component-vectors";
pub(super) const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareComponentMaterialSet";
pub(super) const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareComponentMaterial";

const RELINEARIZATION_KEY_SHARE_LNP_PROOF_MAGIC: &[u8; 8] = b"SLRKLNP1";
const GALOIS_KEY_SHARE_LNP_PROOF_MAGIC: &[u8; 8] = b"SLGKLNP1";
const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV1";
const RELINEARIZATION_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-scalar-challenge-v1";
const GALOIS_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-scalar-challenge-v1";
const RELINEARIZATION_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-relation-commitment-v1";
const GALOIS_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-relation-commitment-v1";
const RELINEARIZATION_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-proof-bytes-v1";
const GALOIS_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-proof-bytes-v1";
const RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundOne";
const RELINEARIZATION_KEY_SHARE_TBOX_UNIFORM_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-tbox-uniform-v1";
const GALOIS_KEY_SHARE_TBOX_UNIFORM_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-tbox-uniform-v1";
const EVALUATION_KEY_SHARE_SECRET_MASK_DOMAIN: &str =
    "sealed-lattice/setup/evaluation-key-share/lnp-secret-mask-v1";
const EVALUATION_KEY_SHARE_NEGATIVE_INDICATOR_MASK_DOMAIN: &str =
    "sealed-lattice/setup/evaluation-key-share/lnp-negative-indicator-mask-v1";
const EVALUATION_KEY_SHARE_RANDOMNESS_MASK_DOMAIN: &str =
    "sealed-lattice/setup/evaluation-key-share/lnp-opening-randomness-mask-v1";
const EVALUATION_KEY_SHARE_ERROR_MASK_DOMAIN: &str =
    "sealed-lattice/setup/evaluation-key-share/lnp-error-mask-v1";
const EVALUATION_KEY_SHARE_SOURCE_MASK_DOMAIN: &str =
    "sealed-lattice/setup/evaluation-key-share/lnp-source-mask-v1";
const EVALUATION_KEY_SHARE_CARRY_MASK_DOMAIN: &str =
    "sealed-lattice/setup/evaluation-key-share/lnp-carry-mask-v1";

const EVALUATION_KEY_SHARE_SECRET_MASK_BITS: usize = 32;
const EVALUATION_KEY_SHARE_ERROR_MASK_BITS: usize = 32;
const EVALUATION_KEY_SHARE_SOURCE_MASK_BITS: usize = 48;
const EVALUATION_KEY_SHARE_CARRY_MASK_BITS: usize = 64;
const EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS: usize = 80;
const EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS: usize = 32;
const EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND: i128 = 1;
const EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND: i128 = 2;
const EVALUATION_KEY_SHARE_ROUND_TWO_AGGREGATE_SOURCE_PARTICIPANT_BOUND: i128 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvaluationKeyShareProofFamily {
    Relinearization,
    Galois,
}

impl EvaluationKeyShareProofFamily {
    pub(super) fn proof_family(self) -> &'static str {
        match self {
            Self::Relinearization => "relinearization-key-share",
            Self::Galois => "galois-key-share",
        }
    }

    fn relation_statement_object_type(self) -> &'static str {
        match self {
            Self::Relinearization => "RelinearizationKeyShareLnpRelationProofStatement",
            Self::Galois => "GaloisKeyShareLnpRelationProofStatement",
        }
    }

    fn proof_profile_id(self) -> &'static str {
        match self {
            Self::Relinearization => "sealed-lattice-relinearization-key-share-proof-lnp-v1",
            Self::Galois => "sealed-lattice-galois-key-share-proof-lnp-v1",
        }
    }

    fn proof_verification_status(self) -> &'static str {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
            Self::Galois => GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        }
    }

    fn proof_model_status(self) -> &'static str {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
            Self::Galois => GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        }
    }

    fn tbox_parameter_profile_hash(self) -> CanonicalResult<String> {
        match self {
            Self::Relinearization => {
                super::setup_proof::relinearization_key_share_lnp_tbox_parameter_profile_hash()
            }
            Self::Galois => super::setup_proof::galois_key_share_lnp_tbox_parameter_profile_hash(),
        }
    }

    fn tbox_layout(self) -> super::setup_proof::SetupProofLnpTboxLayout {
        match self {
            Self::Relinearization => {
                super::setup_proof::relinearization_key_share_lnp_tbox_layout()
            }
            Self::Galois => super::setup_proof::galois_key_share_lnp_tbox_layout(),
        }
    }

    fn scalar_challenge_domain(self) -> &'static str {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
            Self::Galois => GALOIS_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
        }
    }

    fn commitment_hash_domain(self) -> &'static str {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN,
            Self::Galois => GALOIS_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN,
        }
    }

    fn proof_bytes_hash_domain(self) -> &'static str {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN,
            Self::Galois => GALOIS_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN,
        }
    }

    fn proof_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_LNP_PROOF_MAGIC,
            Self::Galois => GALOIS_KEY_SHARE_LNP_PROOF_MAGIC,
        }
    }

    fn tbox_uniform_domain(self) -> &'static str {
        match self {
            Self::Relinearization => RELINEARIZATION_KEY_SHARE_TBOX_UNIFORM_DOMAIN,
            Self::Galois => GALOIS_KEY_SHARE_TBOX_UNIFORM_DOMAIN,
        }
    }

    fn tbox_parameter_profile_hash_field(self) -> &'static str {
        match self {
            Self::Relinearization => "relinearizationKeyShareTboxParameterProfileHash",
            Self::Galois => "galoisKeyShareTboxParameterProfileHash",
        }
    }
}

pub(super) struct EvaluationKeyShareLnpProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) tbox_commitment_prefix_hash: String,
    pub(super) challenge: u64,
}

pub(super) struct EvaluationKeyShareLnpProofVerificationInput<'a> {
    pub(super) proof_family: EvaluationKeyShareProofFamily,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) proof_record: &'a Value,
    pub(super) same_secret_statement_record: &'a Value,
    pub(super) constant_commitments: &'a [SetupCommitmentValue],
    pub(super) setup_proof_binding: &'a Value,
    pub(super) transported_key_switch_component_material: Option<&'a Value>,
    pub(super) proof_bytes: &'a [u8],
}

pub(super) struct EvaluationKeyShareLnpProofWitness {
    pub(super) secret_coefficients: Vec<i64>,
    pub(super) opening_randomness_by_limb: Vec<Vec<Vec<i128>>>,
    pub(super) error_coefficients_by_digit: Vec<Vec<i64>>,
    pub(super) relinearization_source_coefficients_by_digit: Vec<Vec<i128>>,
    pub(super) round_one_aggregate_source_coefficients_by_digit: Vec<Vec<i128>>,
}

pub(super) struct EvaluationKeyShareLnpProofGenerationInput<'a> {
    pub(super) proof_family: EvaluationKeyShareProofFamily,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) proof_record: &'a Value,
    pub(super) same_secret_statement_record: &'a Value,
    pub(super) constant_commitments: &'a [SetupCommitmentValue],
    pub(super) component_b_by_digit: &'a [Vec<Vec<u64>>],
    pub(super) setup_proof_binding: &'a Value,
    pub(super) transported_key_switch_component_material: Option<&'a Value>,
    pub(super) witness: &'a EvaluationKeyShareLnpProofWitness,
    pub(super) proof_randomness_seed_hex: &'a str,
}

#[derive(Debug, Clone)]
pub(super) struct EvaluationKeyShareComponentMaterialTransportHashes {
    pub(super) full_object_hash: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) chunk_root: String,
    pub(super) total_byte_length: u64,
}

struct ParsedEvaluationKeyShareLnpProof {
    challenge: u64,
    key_switch_relation_commitments: Vec<Vec<Vec<i128>>>,
    secret_commitment_relation_commitments: Vec<SetupCommitmentValue>,
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    error_response_by_digit: Vec<Vec<i128>>,
    relinearization_source_response_by_digit: Vec<Vec<i128>>,
    carry_response_by_digit_by_limb: Vec<Vec<Vec<i128>>>,
    tbox_proof_bytes: Vec<u8>,
    tbox_commitment_prefix_hash: String,
    parameter_profile_hash_hex: String,
}

pub(super) fn evaluation_key_share_lnp_relation_proof_bytes_hash(
    proof_family: EvaluationKeyShareProofFamily,
    proof_bytes: &[u8],
) -> String {
    hash512_hex(proof_family.proof_bytes_hash_domain(), &[proof_bytes])
}

pub(crate) fn generate_evaluation_key_share_lnp_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "proofFamily",
            "publicMatrixSeedHash",
            "proofRecord",
            "sameSecretStatementRecord",
            "constantCommitments",
            "setupProofBinding",
            "transportedKeySwitchComponentMaterial",
            "secretCoefficients",
            "openingRandomnessByLimb",
            "errorCoefficientsByDigit",
            "relinearizationSourceCoefficientsByDigit",
            "roundOneAggregateSourceCoefficientsByDigit",
            "proofRandomnessSource",
            "proofRandomnessSeedHex",
        ],
        "generateEvaluationKeyShareLnpProof",
    )?;

    let proof_family = evaluation_key_share_proof_family_from_request(request)?;
    let public_matrix_seed_hash = string_field(request, "publicMatrixSeedHash")?;
    validate_lowercase_hash(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let proof_record = object_field(request, "proofRecord")?;
    let same_secret_statement_record = object_field(request, "sameSecretStatementRecord")?;
    let setup_proof_binding = object_field(request, "setupProofBinding")?;
    let constant_commitments = setup_commitment_values_field(request, "constantCommitments")?;
    let transported_key_switch_component_material = request
        .get("transportedKeySwitchComponentMaterial")
        .map(|material| {
            if material.is_object() {
                Ok(material)
            } else {
                Err(invalid_evaluation_key_share_proof(
                    "transportedKeySwitchComponentMaterial must be an object",
                ))
            }
        })
        .transpose()?;
    let component_b_by_digit = component_b_vectors_from_record(
        proof_family,
        proof_record,
        transported_key_switch_component_material,
    )?;
    let secret_coefficients = i64_vector_field(request, "secretCoefficients")?;
    let opening_randomness_by_limb = i128_matrix3_field(request, "openingRandomnessByLimb")?;
    let error_coefficients_by_digit = i64_matrix_field(request, "errorCoefficientsByDigit")?;
    let relinearization_source_coefficients_by_digit = match (
        proof_family,
        request.get("relinearizationSourceCoefficientsByDigit"),
    ) {
        (EvaluationKeyShareProofFamily::Relinearization, Some(_)) => {
            i128_matrix_field(request, "relinearizationSourceCoefficientsByDigit")?
        }
        (EvaluationKeyShareProofFamily::Relinearization, None) => {
            return Err(invalid_evaluation_key_share_proof(
                "relinearizationSourceCoefficientsByDigit is required for relinearization proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Galois, Some(_)) => {
            return Err(invalid_evaluation_key_share_proof(
                "relinearizationSourceCoefficientsByDigit must not be provided for Galois proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Galois, None) => Vec::new(),
    };
    let round_one_aggregate_source_coefficients_by_digit = match (
        proof_family,
        relinearization_record_uses_same_secret_source(proof_record),
        request.get("roundOneAggregateSourceCoefficientsByDigit"),
    ) {
        (EvaluationKeyShareProofFamily::Relinearization, false, Some(_)) => {
            i128_matrix_field(request, "roundOneAggregateSourceCoefficientsByDigit")?
        }
        (EvaluationKeyShareProofFamily::Relinearization, false, None) => {
            return Err(invalid_evaluation_key_share_proof(
                "roundOneAggregateSourceCoefficientsByDigit is required for relinearization round-two proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Relinearization, true, Some(_)) => {
            return Err(invalid_evaluation_key_share_proof(
                "roundOneAggregateSourceCoefficientsByDigit must not be provided for relinearization round-one proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Relinearization, true, None)
        | (EvaluationKeyShareProofFamily::Galois, _, None) => Vec::new(),
        (EvaluationKeyShareProofFamily::Galois, _, Some(_)) => {
            return Err(invalid_evaluation_key_share_proof(
                "roundOneAggregateSourceCoefficientsByDigit must not be provided for Galois proof generation",
            ));
        }
    };
    let proof_randomness_source = proof_randomness_source(request)?;
    let proof_randomness_seed_hex = string_field(request, "proofRandomnessSeedHex")?;
    validate_proof_randomness_seed(proof_randomness_seed_hex, "proofRandomnessSeedHex")?;

    let witness = EvaluationKeyShareLnpProofWitness {
        secret_coefficients,
        opening_randomness_by_limb,
        error_coefficients_by_digit,
        relinearization_source_coefficients_by_digit,
        round_one_aggregate_source_coefficients_by_digit,
    };
    let generation_input = EvaluationKeyShareLnpProofGenerationInput {
        proof_family,
        public_matrix_seed_hash,
        proof_record,
        same_secret_statement_record,
        constant_commitments: &constant_commitments,
        component_b_by_digit: &component_b_by_digit,
        setup_proof_binding,
        transported_key_switch_component_material,
        witness: &witness,
        proof_randomness_seed_hex,
    };
    let proof_bytes = generate_evaluation_key_share_lnp_relation_proof(generation_input)?;
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family,
            public_matrix_seed_hash,
            proof_record,
            same_secret_statement_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )?;
    let proof_bytes_hash =
        evaluation_key_share_lnp_relation_proof_bytes_hash(proof_family, &proof_bytes);

    let mut response = json!({
        "ok": true,
        "operation": "generateEvaluationKeyShareLnpProof",
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": proof_family.proof_family(),
        "proofVerificationStatus": proof_family.proof_verification_status(),
        "proofModelStatus": proof_family.proof_model_status(),
        "statementHash": verification.statement_hash_hex,
        "relationCommitmentHash": verification.relation_commitment_hash_hex,
        "tboxCommitmentPrefixHash": verification.tbox_commitment_prefix_hash,
        "challenge": verification.challenge,
        "proofSizeBytes": verification.proof_size_bytes,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "seedBytes": 64,
            "retention": "proof randomness seed material is consumed for proof generation and is not returned"
        }
    });
    response[proof_family.tbox_parameter_profile_hash_field()] =
        json!(proof_family.tbox_parameter_profile_hash()?);

    Ok(response)
}

pub(super) fn evaluation_key_share_component_vector_hash(coefficients: &[u64]) -> String {
    coefficient_vector_hash512(
        coefficients,
        EVALUATION_KEY_SHARE_COMPONENT_VECTOR_HASH_DOMAIN,
    )
}

pub(super) fn evaluation_key_share_component_vector_root(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_vector_entries: &[Value],
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluationKeyShareComponentVectorRoot",
        &json!({
            "objectType": "EvaluationKeyShareComponentVectorSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": proof_family.proof_family(),
            "keySwitchDomain": key_switch_domain,
            "keySwitchSeedHex": key_switch_seed_hex,
            "level": level,
            "ringDegree": ring_degree,
            "digitCount": level + 1,
            "rnsLimbCount": level + 1,
            "componentVectors": component_vector_entries,
        }),
    )
}

pub(super) fn encode_evaluation_key_share_component_vectors(
    level: usize,
    ring_degree: usize,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<Vec<u8>> {
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key level digit count overflowed")
    })?;
    if component_b_by_digit.len() != digit_count {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component material digit count does not match the proof level",
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC);
    write_u64(
        &mut output,
        u64::try_from(level).map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key level does not fit u64")
        })?,
    );
    write_u64(
        &mut output,
        u64::try_from(ring_degree).map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key ringDegree does not fit u64")
        })?,
    );
    write_u64(
        &mut output,
        u64::try_from(digit_count).map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key digit count does not fit u64")
        })?,
    );
    write_u64(
        &mut output,
        u64::try_from(digit_count).map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key limb count does not fit u64")
        })?,
    );
    for (digit_index, component_b_by_limb) in component_b_by_digit.iter().enumerate() {
        if component_b_by_limb.len() != digit_count {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key component material limb count does not match the proof level",
            ));
        }
        for (rns_limb_index, coefficients) in component_b_by_limb.iter().enumerate() {
            if coefficients.len() != ring_degree {
                return Err(invalid_evaluation_key_share_proof(
                    "evaluation-key component material coefficient count does not match ringDegree",
                ));
            }
            if coefficients
                .iter()
                .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
            {
                return Err(invalid_evaluation_key_share_proof(
                    "evaluation-key component material contains non-canonical Q_share residues",
                ));
            }
            write_u64(
                &mut output,
                u64::try_from(digit_index).map_err(|_| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key digit index does not fit u64",
                    )
                })?,
            );
            write_u64(
                &mut output,
                u64::try_from(rns_limb_index).map_err(|_| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key RNS limb index does not fit u64",
                    )
                })?,
            );
            write_u64(&mut output, DATA_PRIMES[rns_limb_index]);
            write_u64(
                &mut output,
                u64::try_from(coefficients.len()).map_err(|_| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key coefficient count does not fit u64",
                    )
                })?,
            );
            for coefficient in coefficients {
                write_u64(&mut output, *coefficient);
            }
        }
    }

    Ok(output)
}

pub(super) fn evaluation_key_share_component_material_transport_hashes(
    proof_family: EvaluationKeyShareProofFamily,
    chunks: &[Vec<u8>],
    chunk_size_bytes: u64,
) -> CanonicalResult<EvaluationKeyShareComponentMaterialTransportHashes> {
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material chunk size must be positive",
        ));
    }
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material transport requires at least one chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |byte_count, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material contains a short non-final chunk",
                    ));
                }
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material chunk length does not fit u64",
                    )
                })?;
                byte_count.checked_add(chunk_length).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material byte length overflowed",
                    )
                })
            })?;

    let full_object_hash = evaluation_key_share_component_material_full_object_hash(
        proof_family,
        total_byte_length,
        chunks,
    )?;
    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        chunk_hashes.push(evaluation_key_share_component_material_chunk_hash(
            proof_family,
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_count = u64::try_from(chunks.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material chunk count does not fit u64",
        )
    })?;
    let chunk_root = derive_protocol_hash(
        "EvaluationKeyShareComponentMaterialChunkRoot",
        &json!({
            "objectType": "EvaluationKeyShareComponentMaterialChunkManifest",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": proof_family.proof_family(),
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )?;

    Ok(EvaluationKeyShareComponentMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

pub(super) fn evaluation_key_share_component_material_reference_root(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    transport_hashes: &EvaluationKeyShareComponentMaterialTransportHashes,
) -> CanonicalResult<String> {
    let level = value_u64(proof_record, "level")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key digit count overflowed")
    })?;
    derive_protocol_hash(
        "EvaluationKeyShareComponentMaterialRoot",
        &json!({
            "objectType": "EvaluationKeyShareComponentMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": proof_family.proof_family(),
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "trusteeIdentity": string_field(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "keySwitchDomain": string_field(proof_record, "keySwitchDomain")?,
            "keySwitchSeedHex": string_field(proof_record, "keySwitchSeedHex")?,
            "level": level,
            "ringDegree": value_u64(proof_record, "ringDegree")?,
            "digitCount": digit_count,
            "rnsLimbCount": digit_count,
            "keySwitchComponentVectorRoot": string_field(
                proof_record,
                "keySwitchComponentVectorRoot",
            )?,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        }),
    )
}

fn evaluation_key_share_component_material_full_object_hash(
    proof_family: EvaluationKeyShareProofFamily,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut total_length_bytes = Vec::new();
    append_varuint(&mut total_length_bytes, total_byte_length);
    let mut parts = Vec::with_capacity(chunks.len() + 2);
    parts.push(proof_family.proof_family().as_bytes());
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    Ok(hash512_hex(
        "sealed-lattice/setup/evaluation-key-share/component-material/full-object-v1",
        &parts,
    ))
}

fn evaluation_key_share_component_material_chunk_hash(
    proof_family: EvaluationKeyShareProofFamily,
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "evaluation-key component material chunk index does not fit u64",
            )
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/evaluation-key-share/component-material/chunk-v1",
        &[
            proof_family.proof_family().as_bytes(),
            full_object_hash.as_bytes(),
            &chunk_index_bytes,
            chunk,
        ],
    ))
}

pub(super) fn verify_evaluation_key_share_lnp_relation_proof(
    input: EvaluationKeyShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<EvaluationKeyShareLnpProofVerification> {
    validate_evaluation_key_share_statement_material(&input)?;
    let component_b_by_digit = component_b_vectors_from_record(
        input.proof_family,
        input.proof_record,
        input.transported_key_switch_component_material,
    )?;
    let statement_value = evaluation_key_share_lnp_statement_value(&input, &component_b_by_digit)?;
    let statement_hash =
        evaluation_key_share_lnp_statement_hash(input.proof_family, &statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
    let parsed_proof = parse_evaluation_key_share_lnp_relation_proof(
        input.proof_family,
        input.proof_bytes,
        &statement_hash,
        input.constant_commitments,
        &component_b_by_digit,
    )?;
    let expected_parameter_profile_hash = input.proof_family.tbox_parameter_profile_hash()?;
    if parsed_proof.parameter_profile_hash_hex != expected_parameter_profile_hash {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof is not bound to the accepted tbox parameter profile",
        ));
    }
    let encoded_commitments = encode_evaluation_key_share_relation_commitments(
        &parsed_proof.key_switch_relation_commitments,
        &parsed_proof.secret_commitment_relation_commitments,
    )?;
    let relation_commitment_hash_hex = evaluation_key_share_lnp_relation_commitment_hash(
        input.proof_family,
        &statement_hash_hex,
        &expected_parameter_profile_hash,
        &parsed_proof.tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let recomputed_challenge = evaluation_key_share_lnp_relation_challenge(
        input.proof_family,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
    )?;
    if parsed_proof.challenge != recomputed_challenge {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP scalar challenge does not match its relation transcript",
        ));
    }
    let layout = input.proof_family.tbox_layout();
    super::setup_proof::verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
        &parsed_proof.tbox_proof_bytes,
    )?;
    verify_evaluation_key_share_response_bounds(
        input.proof_family,
        input.proof_record,
        parsed_proof.challenge,
        &component_b_by_digit,
        &parsed_proof,
    )?;
    verify_evaluation_key_secret_commitment_responses(
        input.public_matrix_seed_hash,
        input.constant_commitments,
        parsed_proof.challenge,
        &parsed_proof.secret_commitment_relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;
    verify_evaluation_key_share_key_switch_responses(
        input.proof_family,
        input.proof_record,
        &component_b_by_digit,
        parsed_proof.challenge,
        &parsed_proof.key_switch_relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.error_response_by_digit,
        &parsed_proof.relinearization_source_response_by_digit,
        &parsed_proof.carry_response_by_digit_by_limb,
    )?;

    Ok(EvaluationKeyShareLnpProofVerification {
        proof_size_bytes: input.proof_bytes.len(),
        statement_hash_hex,
        relation_commitment_hash_hex,
        tbox_commitment_prefix_hash: parsed_proof.tbox_commitment_prefix_hash,
        challenge: parsed_proof.challenge,
    })
}

pub(super) fn generate_evaluation_key_share_lnp_relation_proof(
    input: EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    validate_evaluation_key_share_generation_material(&input)?;
    let statement_input = EvaluationKeyShareLnpProofVerificationInput {
        proof_family: input.proof_family,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        proof_record: input.proof_record,
        same_secret_statement_record: input.same_secret_statement_record,
        constant_commitments: input.constant_commitments,
        setup_proof_binding: input.setup_proof_binding,
        transported_key_switch_component_material: input.transported_key_switch_component_material,
        proof_bytes: &[],
    };
    let statement_value =
        evaluation_key_share_lnp_statement_value(&statement_input, input.component_b_by_digit)?;
    let statement_hash =
        evaluation_key_share_lnp_statement_hash(input.proof_family, &statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
    let layout = input.proof_family.tbox_layout();
    let parameter_profile_hash = input.proof_family.tbox_parameter_profile_hash()?;
    let mut tbox_proof_bytes = encode_evaluation_key_share_lnp_tbox_prefix(
        input.proof_family,
        &layout,
        input.proof_randomness_seed_hex,
    )?;
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;

    let masks = sample_evaluation_key_share_masks(&input)?;
    let key_switch_relation_commitments =
        key_switch_relation_commitments_from_masks(&input, &masks)?;
    let secret_commitment_relation_commitments =
        secret_commitment_relation_commitments_from_masks(&input, &masks)?;
    let encoded_commitments = encode_evaluation_key_share_relation_commitments(
        &key_switch_relation_commitments,
        &secret_commitment_relation_commitments,
    )?;
    let relation_commitment_hash_hex = evaluation_key_share_lnp_relation_commitment_hash(
        input.proof_family,
        &statement_hash_hex,
        &parameter_profile_hash,
        &tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let challenge = evaluation_key_share_lnp_relation_challenge(
        input.proof_family,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
    )?;
    let challenge_coefficients = super::setup_proof::derive_setup_proof_challenge_coefficients(
        input.proof_family.proof_family(),
        &statement_hash_hex,
        &relation_commitment_hash_hex,
        super::setup_proof::SETUP_PROOF_LNP_PROOF_RING_DEGREE,
    )?;
    encode_evaluation_key_share_lnp_tbox_suffix(
        &mut tbox_proof_bytes,
        &layout,
        &challenge_coefficients,
    )?;

    let responses = evaluation_key_share_responses(&input, &masks, challenge)?;
    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(input.proof_family.proof_magic());
    proof_bytes.extend_from_slice(&statement_hash);
    proof_bytes.extend_from_slice(&hash_hex_to_fixed_bytes(&parameter_profile_hash)?);
    proof_bytes.extend_from_slice(&challenge.to_le_bytes());
    let tbox_proof_size = u64::try_from(tbox_proof_bytes.len()).map_err(|_| {
        invalid_evaluation_key_share_proof("evaluation-key LNP tbox proof size does not fit u64")
    })?;
    proof_bytes.extend_from_slice(&tbox_proof_size.to_le_bytes());
    proof_bytes.extend_from_slice(&tbox_proof_bytes);
    write_i128_matrix3(&mut proof_bytes, &key_switch_relation_commitments);
    write_setup_commitments(&mut proof_bytes, &secret_commitment_relation_commitments);
    write_i128_vector(&mut proof_bytes, &responses.secret_response_coefficients);
    write_i128_vector(
        &mut proof_bytes,
        &responses.negative_indicator_response_coefficients,
    );
    write_i128_matrix3(&mut proof_bytes, &responses.randomness_response_by_limb);
    write_i128_matrix(&mut proof_bytes, &responses.error_response_by_digit);
    if input.proof_family == EvaluationKeyShareProofFamily::Relinearization {
        write_i128_matrix(
            &mut proof_bytes,
            &responses.relinearization_source_response_by_digit,
        );
    }
    write_i128_matrix3(&mut proof_bytes, &responses.carry_response_by_digit_by_limb);

    Ok(proof_bytes)
}

fn validate_evaluation_key_share_statement_material(
    input: &EvaluationKeyShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<()> {
    if input.constant_commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof requires one same-secret constant commitment per Q_share limb",
        ));
    }
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof ringDegree is outside the selected profile",
        ));
    }
    for (rns_limb_index, commitment) in input.constant_commitments.iter().enumerate() {
        if commitment.source_rns_limb_index != rns_limb_index
            || commitment.source_message_modulus != DATA_PRIMES[rns_limb_index]
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key proof same-secret commitments must follow Q_share order and proof ringDegree",
            ));
        }
    }
    if input.proof_record.get("setupProofBinding") != Some(input.setup_proof_binding) {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof setupProofBinding must match the accepted setup-proof profile",
        ));
    }
    let expected_tbox_parameter_profile_hash = input.proof_family.tbox_parameter_profile_hash()?;
    if input
        .proof_record
        .get(input.proof_family.tbox_parameter_profile_hash_field())
        .and_then(Value::as_str)
        != Some(expected_tbox_parameter_profile_hash.as_str())
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof tbox parameter profile hash does not match the accepted profile",
        ));
    }
    if input.proof_record.get("sameSecretStatementRoot")
        != input
            .same_secret_statement_record
            .get("sameSecretStatementRoot")
        || input.proof_record.get("trusteeSecretCommitmentRoot")
            != input
                .same_secret_statement_record
                .get("trusteeSecretCommitmentRoot")
        || input.proof_record.get("trusteeIdentity")
            != input.same_secret_statement_record.get("trusteeIdentity")
        || input.proof_record.get("trusteeRosterPosition")
            != input
                .same_secret_statement_record
                .get("trusteeRosterPosition")
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof record must bind the accepted same-secret statement",
        ));
    }
    super::setup_proof::verify_setup_proof_record_binding(
        input.setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;

    Ok(())
}

fn validate_evaluation_key_share_generation_material(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<()> {
    let verification_input = EvaluationKeyShareLnpProofVerificationInput {
        proof_family: input.proof_family,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        proof_record: input.proof_record,
        same_secret_statement_record: input.same_secret_statement_record,
        constant_commitments: input.constant_commitments,
        setup_proof_binding: input.setup_proof_binding,
        transported_key_switch_component_material: input.transported_key_switch_component_material,
        proof_bytes: &[],
    };
    validate_evaluation_key_share_statement_material(&verification_input)?;
    let parsed_component_b = component_b_vectors_from_record(
        input.proof_family,
        input.proof_record,
        input.transported_key_switch_component_material,
    )?;
    if parsed_component_b != input.component_b_by_digit {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key generation component vectors must match the proof record",
        ));
    }
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    if input.witness.secret_coefficients.len() != ring_degree
        || input.witness.opening_randomness_by_limb.len() != DATA_PRIMES.len()
        || input.witness.error_coefficients_by_digit.len() != input.component_b_by_digit.len()
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key witness shape does not match proof statement",
        ));
    }
    if input
        .witness
        .secret_coefficients
        .iter()
        .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key secret witness must be ternary",
        ));
    }
    for limb_randomness in &input.witness.opening_randomness_by_limb {
        if limb_randomness.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || limb_randomness
                .iter()
                .any(|column| column.len() != ring_degree)
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key opening-randomness witness shape does not match proof statement",
            ));
        }
    }
    for error in &input.witness.error_coefficients_by_digit {
        if error.len() != ring_degree
            || error
                .iter()
                .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key error witness must be centered-binomial support with the proof ringDegree",
            ));
        }
    }
    if input.proof_family == EvaluationKeyShareProofFamily::Relinearization
        && (input
            .witness
            .relinearization_source_coefficients_by_digit
            .len()
            != input.component_b_by_digit.len()
            || input
                .witness
                .relinearization_source_coefficients_by_digit
                .iter()
                .any(|source| source.len() != ring_degree))
    {
        return Err(invalid_evaluation_key_share_proof(
            "relinearization source witness shape does not match proof statement",
        ));
    }
    if input.proof_family == EvaluationKeyShareProofFamily::Relinearization {
        let is_round_one = relinearization_record_uses_same_secret_source(input.proof_record);
        if is_round_one {
            if !input
                .witness
                .round_one_aggregate_source_coefficients_by_digit
                .is_empty()
            {
                return Err(invalid_evaluation_key_share_proof(
                    "round-one relinearization proof generation must not include round-one aggregate source witness material",
                ));
            }
        } else if input
            .witness
            .round_one_aggregate_source_coefficients_by_digit
            .len()
            != input.component_b_by_digit.len()
            || input
                .witness
                .round_one_aggregate_source_coefficients_by_digit
                .iter()
                .any(|source| source.len() != ring_degree)
        {
            return Err(invalid_evaluation_key_share_proof(
                "round-one aggregate source witness shape does not match proof statement",
            ));
        }
        let source_bound = relinearization_source_witness_bound(input.proof_record, ring_degree)?;
        let secret_coefficients = input
            .witness
            .secret_coefficients
            .iter()
            .map(|coefficient| i128::from(*coefficient))
            .collect::<Vec<_>>();
        for (digit_index, source_coefficients) in input
            .witness
            .relinearization_source_coefficients_by_digit
            .iter()
            .enumerate()
        {
            if is_round_one {
                if source_coefficients != &secret_coefficients {
                    return Err(invalid_evaluation_key_share_proof(format!(
                        "round-one relinearization source witness must equal the same-secret witness at digit {digit_index}"
                    )));
                }
            } else {
                let expected_source = negacyclic_i128_product_lifted(
                    &secret_coefficients,
                    &input
                        .witness
                        .round_one_aggregate_source_coefficients_by_digit[digit_index],
                )?;
                if source_coefficients != &expected_source {
                    return Err(invalid_evaluation_key_share_proof(format!(
                        "round-two relinearization source witness must equal the trustee secret times the accepted round-one aggregate source at digit {digit_index}"
                    )));
                }
            }
            if source_coefficients
                .iter()
                .any(|coefficient| match coefficient.checked_abs() {
                    Some(magnitude) => magnitude > source_bound,
                    None => true,
                })
            {
                return Err(invalid_evaluation_key_share_proof(
                    "relinearization source witness exceeds the accepted no-wrap source bound",
                ));
            }
        }
    } else if !input
        .witness
        .relinearization_source_coefficients_by_digit
        .is_empty()
    {
        return Err(invalid_evaluation_key_share_proof(
            "Galois proof generation must not include relinearization source witness material",
        ));
    } else if !input
        .witness
        .round_one_aggregate_source_coefficients_by_digit
        .is_empty()
    {
        return Err(invalid_evaluation_key_share_proof(
            "Galois proof generation must not include round-one aggregate source witness material",
        ));
    }

    Ok(())
}

fn evaluation_key_share_lnp_statement_value(
    input: &EvaluationKeyShareLnpProofVerificationInput<'_>,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<Value> {
    let level = value_usize(input.proof_record, "level")?;
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let key_switch_domain = string_field(input.proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(input.proof_record, "keySwitchSeedHex")?;
    let constant_commitment_roots = input
        .constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "shamirCoefficientIndex": 0,
                "commitmentRoot": setup_commitment_root(commitment)?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let source_relation = match input.proof_family {
        EvaluationKeyShareProofFamily::Relinearization
            if relinearization_record_uses_same_secret_source(input.proof_record) =>
        {
            "round-one source response is the same response vector as the committed trustee secret"
        }
        EvaluationKeyShareProofFamily::Relinearization => {
            "round-two source response is bound as a hidden contribution to the aggregate squared secret; aggregate-square proof closure remains review-gated"
        }
        EvaluationKeyShareProofFamily::Galois => {
            "source response is the public Galois automorphism applied to the same-secret response"
        }
    };

    let mut statement = json!({
        "objectType": input.proof_family.relation_statement_object_type(),
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofBinding": input.setup_proof_binding,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "proofProfileId": input.proof_family.proof_profile_id(),
        "proofFamily": input.proof_family.proof_family(),
        "proofVerificationStatus": input.proof_family.proof_verification_status(),
        "proofModelStatus": input.proof_family.proof_model_status(),
        "recordStatement": proof_record_statement_projection(input.proof_record),
        "sameSecretStatementRoot": input.proof_record["sameSecretStatementRoot"],
        "trusteeSecretCommitmentRoot": input.proof_record["trusteeSecretCommitmentRoot"],
        "sameSecretProofRoot": input.proof_record["sameSecretProofRoot"],
        "sameSecretProofFamilyBindingRoot": input.proof_record["sameSecretProofFamilyBindingRoot"],
        "constantCoefficientCommitmentRoots": constant_commitment_roots,
        "keySwitchDomain": key_switch_domain,
        "keySwitchSeedHex": key_switch_seed_hex,
        "level": level,
        "ringDegree": ring_degree,
        "digitCount": component_b_by_digit.len(),
        "rnsLimbCount": component_b_by_digit.first().map(Vec::len).unwrap_or_default(),
        "relation": "for every digit j and limb l, b_j,l + a_j,l*s - p*e_j - source_j,l - q_l*v_j,l = 0 over lifted integers",
        "sourceRelation": source_relation,
        "nonClosure": match input.proof_family {
            EvaluationKeyShareProofFamily::Relinearization => "linear key-switch relation, same-secret binding, round-one same-secret source response, public component material, tbox byte layout, response bounds, and relinearization source record binding are verified; round-two aggregate-square source proof closure plus external AB-DLOP/LNP soundness and zero-knowledge review remain pending",
            EvaluationKeyShareProofFamily::Galois => "linear key-switch relation, same-secret binding, Galois automorphism source response, public component material, tbox byte layout, and response bounds are verified; external AB-DLOP/LNP soundness and zero-knowledge review remain pending",
        },
    });
    statement[input.proof_family.tbox_parameter_profile_hash_field()] =
        json!(input.proof_family.tbox_parameter_profile_hash()?);

    Ok(statement)
}

fn relinearization_record_uses_same_secret_source(proof_record: &Value) -> bool {
    proof_record.get("objectType").and_then(Value::as_str)
        == Some(RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE)
}

fn proof_record_statement_projection(record: &Value) -> Value {
    let mut projection = record.clone();
    let Some(object) = projection.as_object_mut() else {
        return projection;
    };
    for field_name in [
        "roundOneRecordRoot",
        "roundTwoRecordRoot",
        "galoisKeyShareProofRoot",
        "roundOneProofRoot",
        "roundTwoProofRoot",
        "sourceSquareBindingRoot",
        "roundOneSourceSquareBindingRoot",
        "roundOneSourceSquareAggregateRoot",
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
        "statementHash",
        "relationCommitmentHash",
        "tboxCommitmentPrefixHash",
        "challenge",
        "proofSizeBytes",
        "proofBytesHash",
        "proofBytesHex",
    ] {
        object.remove(field_name);
    }

    projection
}

fn evaluation_key_share_lnp_statement_hash(
    proof_family: EvaluationKeyShareProofFamily,
    statement_value: &Value,
) -> CanonicalResult<[u8; 64]> {
    let statement_json = canonical_json(statement_value)?;
    Ok(hash512(
        match proof_family {
            EvaluationKeyShareProofFamily::Relinearization => {
                "sealed-lattice/setup/relinearization-key-share/lnp-relation-statement-v1"
            }
            EvaluationKeyShareProofFamily::Galois => {
                "sealed-lattice/setup/galois-key-share/lnp-relation-statement-v1"
            }
        },
        &[statement_json.as_bytes()],
    ))
}

pub(super) fn component_b_vectors_from_record(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    transported_key_switch_component_material: Option<&Value>,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    match string_field(record, "keySwitchMaterialEncoding")? {
        "embedded-full-key-switch-component-vectors" => {
            if record.get("keySwitchComponentMaterialRoot").is_some()
                || record.get("keySwitchComponentChunkSizeBytes").is_some()
                || record.get("keySwitchComponentChunkCount").is_some()
                || record.get("keySwitchComponentTotalByteLength").is_some()
                || record.get("keySwitchComponentFullObjectHash").is_some()
                || record.get("keySwitchComponentChunkRoot").is_some()
                || record.get("keySwitchComponentChunkHashes").is_some()
            {
                return Err(invalid_evaluation_key_share_proof(
                    "embedded evaluation-key component material must not include transported component references",
                ));
            }
            component_b_vectors_from_embedded_record(proof_family, record)
        }
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING => {
            if record.get("keySwitchComponentVectors").is_some() {
                return Err(invalid_evaluation_key_share_proof(
                    "binary evaluation-key component material must not embed keySwitchComponentVectors",
                ));
            }
            let transported_material_set =
                transported_key_switch_component_material.ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "transported evaluation-key component material is required by binary keySwitchMaterialEncoding",
                    )
                })?;
            component_b_vectors_from_transported_material(
                proof_family,
                record,
                transported_material_set,
            )
        }
        _ => Err(invalid_evaluation_key_share_proof(
            "evaluation-key keySwitchMaterialEncoding is not accepted",
        )),
    }
}

fn component_b_vectors_from_embedded_record(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let level = value_usize(record, "level")?;
    let ring_degree = value_usize(record, "ringDegree")?;
    let key_switch_domain = string_field(record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(record, "keySwitchSeedHex")?;
    validate_hex_string(key_switch_seed_hex, "keySwitchSeedHex")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key level digit count overflowed")
    })?;
    let limb_count = digit_count;
    let entries = array_field(record, "keySwitchComponentVectors")?;
    if entries.len()
        != digit_count.checked_mul(limb_count).ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key component vector count overflowed")
        })?
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component vectors must contain one vector for every digit and active limb",
        ));
    }
    let mut component_b_by_digit = vec![vec![Vec::<u64>::new(); limb_count]; digit_count];
    for entry in entries {
        let digit_index = value_usize(entry, "digitIndex")?;
        let rns_limb_index = value_usize(entry, "rnsLimbIndex")?;
        if digit_index >= digit_count || rns_limb_index >= limb_count {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key component vector index is outside the proof level",
            ));
        }
        if entry.get("rnsPrime").and_then(Value::as_u64) != Some(DATA_PRIMES[rns_limb_index])
            || entry.get("component").and_then(Value::as_str) != Some("b")
            || entry.get("coefficientByteLength").and_then(Value::as_u64)
                != Some(
                    u64::try_from(ring_degree.checked_mul(8).ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key coefficient byte length overflowed",
                        )
                    })?)
                    .map_err(|_| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key coefficient byte length does not fit u64",
                        )
                    })?,
                )
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key component vector metadata does not match the proof level",
            ));
        }
        if !component_b_by_digit[digit_index][rns_limb_index].is_empty() {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key component vectors contain a duplicate digit and limb",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            string_field(entry, "coefficientsLeHex")?,
            ring_degree,
            "evaluation-key component vector width",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key component vector contains non-canonical Q_share residues",
            ));
        }
        let expected_coefficient_vector_hash =
            evaluation_key_share_component_vector_hash(&coefficients);
        if entry
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(expected_coefficient_vector_hash.as_str())
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key component vector hash does not match coefficientsLeHex",
            ));
        }
        component_b_by_digit[digit_index][rns_limb_index] = coefficients;
    }
    let expected_root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        entries,
    )?;
    if record
        .get("keySwitchComponentVectorRoot")
        .and_then(Value::as_str)
        != Some(expected_root.as_str())
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component vector root does not match embedded public material",
        ));
    }

    Ok(component_b_by_digit)
}

fn component_b_vectors_from_transported_material(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    material_set: &Value,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
        || material_set.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || material_set.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
    {
        return Err(invalid_evaluation_key_share_proof(
            "transported evaluation-key component material set header is invalid",
        ));
    }
    let expected_material_root = string_field(record, "keySwitchComponentMaterialRoot")?;
    let component_materials = array_field(material_set, "componentMaterials")?;
    let mut matching_component_material = None;
    for component_material in component_materials {
        if string_field(component_material, "keySwitchComponentMaterialRoot")?
            != expected_material_root
        {
            continue;
        }
        if matching_component_material.is_some() {
            return Err(invalid_evaluation_key_share_proof(
                "transported evaluation-key component material contains duplicate keySwitchComponentMaterialRoot entries",
            ));
        }
        matching_component_material = Some(component_material);
    }
    let component_material = matching_component_material.ok_or_else(|| {
        invalid_evaluation_key_share_proof(
            "transported evaluation-key component material is missing the requested keySwitchComponentMaterialRoot",
        )
    })?;
    verify_evaluation_key_share_component_material_header(
        proof_family,
        record,
        component_material,
    )?;
    let chunks = evaluation_key_share_component_material_chunks(component_material)?;
    let transport_hashes = evaluation_key_share_component_material_transport_hashes(
        proof_family,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_evaluation_key_share_component_material_hash_fields(
        component_material,
        &transport_hashes,
        "transported evaluation-key component material",
    )?;
    verify_evaluation_key_share_component_material_hash_fields(
        record,
        &transport_hashes,
        "evaluation-key component material reference",
    )?;
    let canonical_material_root = evaluation_key_share_component_material_reference_root(
        proof_family,
        record,
        &transport_hashes,
    )?;
    if expected_material_root != canonical_material_root {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component material root must match the canonical transported material reference",
        ));
    }
    let total_byte_length = usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key transported component material length does not fit usize",
        )
    })?;
    let mut material_bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        material_bytes.extend_from_slice(&chunk);
    }

    decode_evaluation_key_share_component_vectors(proof_family, record, &material_bytes)
}

fn verify_evaluation_key_share_component_material_header(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    component_material: &Value,
) -> CanonicalResult<()> {
    if component_material.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE)
        || component_material
            .get("objectVersion")
            .and_then(Value::as_u64)
            != Some(1)
        || component_material
            .get("setupProfileId")
            .and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || component_material
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || component_material
            .get("proofFamily")
            .and_then(Value::as_str)
            != Some(proof_family.proof_family())
        || component_material
            .get("keySwitchMaterialEncoding")
            .and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
    {
        return Err(invalid_evaluation_key_share_proof(
            "transported evaluation-key component material header is invalid",
        ));
    }
    for field_name in [
        "trusteeIdentity",
        "trusteeRosterPosition",
        "keySwitchDomain",
        "keySwitchSeedHex",
        "level",
        "ringDegree",
        "keySwitchComponentVectorRoot",
    ] {
        if component_material.get(field_name) != record.get(field_name) {
            return Err(invalid_evaluation_key_share_proof(format!(
                "transported evaluation-key component material {field_name} must match the proof record"
            )));
        }
    }
    let level = value_u64(record, "level")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key digit count overflowed")
    })?;
    if component_material.get("digitCount").and_then(Value::as_u64) != Some(digit_count)
        || component_material
            .get("rnsLimbCount")
            .and_then(Value::as_u64)
            != Some(digit_count)
    {
        return Err(invalid_evaluation_key_share_proof(
            "transported evaluation-key component material digit and limb counts must match the proof level",
        ));
    }

    Ok(())
}

fn evaluation_key_share_component_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_evaluation_key_share_proof(
            "transported evaluation-key component material chunkSizeBytes must match the setup transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        invalid_evaluation_key_share_proof(
            "transported evaluation-key component material chunkCount does not fit usize",
        )
    })?;
    let chunk_values = array_field(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
        return Err(invalid_evaluation_key_share_proof(
            "transported evaluation-key component material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        let observed_chunk_index = value_usize(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index {
            return Err(invalid_evaluation_key_share_proof(
                "transported evaluation-key component material chunks must be in ascending chunk-index order",
            ));
        }
        let bytes_hex = string_field(chunk_value, "bytesHex")?;
        chunks.push(crate::transcript_core::decode_hex(bytes_hex)?);
    }

    Ok(chunks)
}

fn verify_evaluation_key_share_component_material_hash_fields(
    value: &Value,
    transport_hashes: &EvaluationKeyShareComponentMaterialTransportHashes,
    value_name: &str,
) -> CanonicalResult<()> {
    if value_u64(value, "chunkSizeBytes")
        .or_else(|_| value_u64(value, "keySwitchComponentChunkSizeBytes"))?
        != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
        || value_u64(value, "chunkCount")
            .or_else(|_| value_u64(value, "keySwitchComponentChunkCount"))?
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "evaluation-key component material chunk count does not fit u64",
                )
            })?
        || value_u64(value, "totalByteLength")
            .or_else(|_| value_u64(value, "keySwitchComponentTotalByteLength"))?
            != transport_hashes.total_byte_length
        || string_field(value, "fullObjectHash")
            .or_else(|_| string_field(value, "keySwitchComponentFullObjectHash"))?
            != transport_hashes.full_object_hash
        || string_field(value, "chunkRoot")
            .or_else(|_| string_field(value, "keySwitchComponentChunkRoot"))?
            != transport_hashes.chunk_root
    {
        return Err(invalid_evaluation_key_share_proof(format!(
            "{value_name} hash metadata does not match supplied chunks"
        )));
    }
    let chunk_hash_values = value
        .get("chunkHashes")
        .or_else(|| value.get("keySwitchComponentChunkHashes"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!(
                "{value_name} must list every component material chunk hash"
            ))
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(invalid_evaluation_key_share_proof(format!(
            "{value_name} chunk hash count must match supplied chunks"
        )));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(invalid_evaluation_key_share_proof(format!(
                "{value_name} chunk hashes must match supplied chunks"
            )));
        }
    }

    Ok(())
}

fn decode_evaluation_key_share_component_vectors(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    material_bytes: &[u8],
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(material_bytes, &mut cursor)?;
    if &magic != EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component material has the wrong format marker",
        ));
    }
    let level = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_proof(
            "evaluation-key component material level does not fit usize",
        )
    })?;
    let ring_degree = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_proof(
            "evaluation-key component material ringDegree does not fit usize",
        )
    })?;
    let digit_count = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_proof(
            "evaluation-key component material digit count does not fit usize",
        )
    })?;
    let limb_count = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_proof(
            "evaluation-key component material limb count does not fit usize",
        )
    })?;
    if level != value_usize(record, "level")?
        || ring_degree != value_usize(record, "ringDegree")?
        || ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE
        || digit_count
            != level.checked_add(1).ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key digit count overflowed")
            })?
        || limb_count != digit_count
        || limb_count == 0
        || limb_count > DATA_PRIMES.len()
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component material shape does not match the proof record",
        ));
    }
    let key_switch_domain = string_field(record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(record, "keySwitchSeedHex")?;
    validate_hex_string(key_switch_seed_hex, "keySwitchSeedHex")?;
    let mut component_b_by_digit = vec![vec![Vec::<u64>::new(); limb_count]; digit_count];
    let mut entries = Vec::with_capacity(digit_count * limb_count);
    for expected_digit_index in 0..digit_count {
        for expected_rns_limb_index in 0..limb_count {
            let digit_index =
                usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key component material digit index does not fit usize",
                    )
                })?;
            let rns_limb_index =
                usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key component material RNS limb index does not fit usize",
                    )
                })?;
            let rns_prime = read_u64(material_bytes, &mut cursor)?;
            let coefficient_count = usize::try_from(read_u64(material_bytes, &mut cursor)?)
                .map_err(|_| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key component material coefficient count does not fit usize",
                    )
                })?;
            if digit_index != expected_digit_index
                || rns_limb_index != expected_rns_limb_index
                || rns_limb_index >= DATA_PRIMES.len()
                || rns_prime != DATA_PRIMES[rns_limb_index]
                || coefficient_count != ring_degree
            {
                return Err(invalid_evaluation_key_share_proof(
                    "evaluation-key component material record order or metadata is invalid",
                ));
            }
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let coefficient = read_u64(material_bytes, &mut cursor)?;
                if coefficient >= DATA_PRIMES[rns_limb_index] {
                    return Err(invalid_evaluation_key_share_proof(
                        "evaluation-key component material contains non-canonical Q_share residues",
                    ));
                }
                coefficients.push(coefficient);
            }
            entries.push(json!({
                "digitIndex": digit_index,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b",
                "coefficientByteLength": ring_degree.checked_mul(8).ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key coefficient byte length overflowed",
                    )
                })?,
                "coefficientVectorHash512": evaluation_key_share_component_vector_hash(&coefficients),
                "coefficientsLeHex": coefficient_vector_le_hex(&coefficients),
            }));
            component_b_by_digit[digit_index][rns_limb_index] = coefficients;
        }
    }
    if cursor != material_bytes.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component material has trailing bytes",
        ));
    }
    let expected_root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )?;
    if string_field(record, "keySwitchComponentVectorRoot")? != expected_root {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key component vector root does not match transported public material",
        ));
    }

    Ok(component_b_by_digit)
}

fn parse_evaluation_key_share_lnp_relation_proof(
    proof_family: EvaluationKeyShareProofFamily,
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
    expected_commitments: &[SetupCommitmentValue],
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<ParsedEvaluationKeyShareLnpProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(proof_bytes, &mut cursor)?;
    if &magic != proof_family.proof_magic() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof has the wrong format marker",
        ));
    }
    let statement_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof is not bound to this statement",
        ));
    }
    let parameter_profile_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    let parameter_profile_hash_hex = to_hex(&parameter_profile_hash);
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 || challenge > evaluation_key_share_scalar_challenge_maximum()? {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP scalar challenge is outside the expected range",
        ));
    }
    let tbox_proof_byte_count =
        usize::try_from(read_u64(proof_bytes, &mut cursor)?).map_err(|_| {
            invalid_evaluation_key_share_proof(
                "evaluation-key LNP tbox proof byte count does not fit usize",
            )
        })?;
    if tbox_proof_byte_count == 0 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof must include tbox proof bytes",
        ));
    }
    let tbox_proof_bytes = read_bytes(proof_bytes, &mut cursor, tbox_proof_byte_count)?;
    let layout = proof_family.tbox_layout();
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;
    let digit_count = component_b_by_digit.len();
    let limb_count = component_b_by_digit
        .first()
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no digits"))?;
    let ring_degree = component_b_by_digit
        .first()
        .and_then(|digit| digit.first())
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no limbs"))?;
    let key_switch_relation_commitments = read_i128_matrix3(
        proof_bytes,
        &mut cursor,
        digit_count,
        limb_count,
        ring_degree,
    )?;
    let secret_commitment_relation_commitments = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_evaluation_key_share_relation_commitment(
                proof_bytes,
                &mut cursor,
                expected_commitment,
            )
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
    let error_response_by_digit =
        read_i128_matrix(proof_bytes, &mut cursor, digit_count, ring_degree)?;
    let relinearization_source_response_by_digit =
        if proof_family == EvaluationKeyShareProofFamily::Relinearization {
            read_i128_matrix(proof_bytes, &mut cursor, digit_count, ring_degree)?
        } else {
            Vec::new()
        };
    let carry_response_by_digit_by_limb = read_i128_matrix3(
        proof_bytes,
        &mut cursor,
        digit_count,
        limb_count,
        ring_degree,
    )?;
    if cursor != proof_bytes.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof has trailing bytes",
        ));
    }

    Ok(ParsedEvaluationKeyShareLnpProof {
        challenge,
        key_switch_relation_commitments,
        secret_commitment_relation_commitments,
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        error_response_by_digit,
        relinearization_source_response_by_digit,
        carry_response_by_digit_by_limb,
        tbox_proof_bytes,
        tbox_commitment_prefix_hash,
        parameter_profile_hash_hex,
    })
}

fn read_evaluation_key_share_relation_commitment(
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
                    return Err(invalid_evaluation_key_share_proof(
                        "evaluation-key relation commitment coefficient is not canonical",
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

fn verify_evaluation_key_share_response_bounds(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    challenge: u64,
    component_b_by_digit: &[Vec<Vec<u64>>],
    parsed_proof: &ParsedEvaluationKeyShareLnpProof,
) -> CanonicalResult<()> {
    let ring_degree = component_b_by_digit
        .first()
        .and_then(|digit| digit.first())
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no limbs"))?;
    let secret_response_bound = evaluation_key_share_secret_response_bound(challenge)?;
    verify_i128_vector_bound(
        &parsed_proof.secret_response_coefficients,
        secret_response_bound,
        "evaluation-key secret response",
    )?;
    verify_i128_vector_bound(
        &parsed_proof.negative_indicator_response_coefficients,
        secret_response_bound,
        "evaluation-key negative-indicator response",
    )?;
    let randomness_response_bound = evaluation_key_share_randomness_response_bound(challenge)?;
    for randomness_responses in &parsed_proof.randomness_response_by_limb {
        for column in randomness_responses {
            verify_i128_vector_bound(
                column,
                randomness_response_bound,
                "evaluation-key opening-randomness response",
            )?;
        }
    }
    let error_response_bound = evaluation_key_share_error_response_bound(challenge)?;
    for error_response in &parsed_proof.error_response_by_digit {
        verify_i128_vector_bound(
            error_response,
            error_response_bound,
            "evaluation-key error response",
        )?;
    }
    if proof_family == EvaluationKeyShareProofFamily::Relinearization {
        let source_response_bound = evaluation_key_share_relinearization_source_response_bound(
            challenge,
            proof_record,
            ring_degree,
        )?;
        for source_response in &parsed_proof.relinearization_source_response_by_digit {
            verify_i128_vector_bound(
                source_response,
                source_response_bound,
                "relinearization source response",
            )?;
        }
    }
    let carry_response_bound = evaluation_key_share_carry_response_bound(challenge, ring_degree)?;
    for carry_by_limb in &parsed_proof.carry_response_by_digit_by_limb {
        for carry_response in carry_by_limb {
            verify_i128_vector_bound(
                carry_response,
                carry_response_bound,
                "evaluation-key carry response",
            )?;
        }
    }

    Ok(())
}

fn verify_evaluation_key_secret_commitment_responses(
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
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key commitment response limb count does not match the statement",
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
        let response_randomness_bound = evaluation_key_share_randomness_response_bound(challenge)?;
        verify_setup_lifted_commitment_opening(
            public_matrix_seed_hash,
            &expected_response_commitment,
            &response_message_coefficients,
            randomness_response,
            response_randomness_bound,
        )
        .map_err(|_| {
            invalid_evaluation_key_share_proof(format!(
                "evaluation-key proof VSS commitment response failed for Q_share limb {limb_index}"
            ))
        })?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_evaluation_key_share_key_switch_responses(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    component_b_by_digit: &[Vec<Vec<u64>>],
    challenge: u64,
    relation_commitments: &[Vec<Vec<i128>>],
    secret_response_coefficients: &[i128],
    error_response_by_digit: &[Vec<i128>],
    relinearization_source_response_by_digit: &[Vec<i128>],
    carry_response_by_digit_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    let level = value_usize(proof_record, "level")?;
    let ring_degree = value_usize(proof_record, "ringDegree")?;
    let key_switch_domain = string_field(proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(proof_record, "keySwitchSeedHex")?;
    if proof_family == EvaluationKeyShareProofFamily::Relinearization
        && relinearization_record_uses_same_secret_source(proof_record)
    {
        for (digit_index, source_response) in
            relinearization_source_response_by_digit.iter().enumerate()
        {
            if source_response != secret_response_coefficients {
                return Err(invalid_evaluation_key_share_proof(format!(
                    "relinearization round-one source response must match the same-secret response at digit {digit_index}"
                )));
            }
        }
    }
    let galois_element = proof_record
        .get("rotation")
        .and_then(Value::as_u64)
        .map(|rotation| {
            usize::try_from(rotation).map_err(|_| {
                invalid_evaluation_key_share_proof("Galois rotation does not fit usize")
            })
        })
        .transpose()?;
    for (digit_index, component_b_by_limb) in component_b_by_digit.iter().enumerate() {
        let error_response = error_response_by_digit.get(digit_index).ok_or_else(|| {
            invalid_evaluation_key_share_proof(
                "evaluation-key error response digit count does not match component vectors",
            )
        })?;
        let source_response = match proof_family {
            EvaluationKeyShareProofFamily::Relinearization => relinearization_source_response_by_digit
                .get(digit_index)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "relinearization source response digit count does not match component vectors",
                    )
                })?
                .clone(),
            EvaluationKeyShareProofFamily::Galois => automorphism_i128(
                secret_response_coefficients,
                galois_element.ok_or_else(|| {
                    invalid_evaluation_key_share_proof("Galois proof must include rotation")
                })?,
            )?,
        };
        for (rns_limb_index, component_b) in component_b_by_limb.iter().enumerate() {
            let modulus = DATA_PRIMES[rns_limb_index];
            let public_sample = deterministic_key_switch_public_sample(
                key_switch_domain,
                key_switch_seed_hex,
                digit_index,
                modulus,
                ring_degree,
            );
            let public_sample_secret_product = negacyclic_public_sample_secret_product_lifted(
                &public_sample,
                secret_response_coefficients,
            )?;
            let carry_response = carry_response_by_digit_by_limb
                .get(digit_index)
                .and_then(|limbs| limbs.get(rns_limb_index))
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key carry response shape does not match component vectors",
                    )
                })?;
            let relation_commitment = relation_commitments
                .get(digit_index)
                .and_then(|limbs| limbs.get(rns_limb_index))
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key relation commitment shape does not match component vectors",
                    )
                })?;
            if component_b.len() != ring_degree
                || public_sample_secret_product.len() != ring_degree
                || error_response.len() != ring_degree
                || source_response.len() != ring_degree
                || carry_response.len() != ring_degree
                || relation_commitment.len() != ring_degree
            {
                return Err(invalid_evaluation_key_share_proof(
                    "evaluation-key key-switch response width does not match ringDegree",
                ));
            }
            for coefficient_index in 0..ring_degree {
                let mut left_side = i128::from(challenge)
                    .checked_mul(i128::from(component_b[coefficient_index]))
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key public component challenge product overflowed",
                        )
                    })?;
                left_side = left_side
                    .checked_add(public_sample_secret_product[coefficient_index])
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key key-switch relation overflowed",
                        )
                    })?;
                left_side = left_side
                    .checked_sub(
                        i128::from(PLAINTEXT_MODULUS_I64)
                            .checked_mul(error_response[coefficient_index])
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key error response scaling overflowed",
                                )
                            })?,
                    )
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key key-switch relation overflowed",
                        )
                    })?;
                let source_term = if rns_limb_index == digit_index {
                    source_response[coefficient_index]
                } else {
                    0
                };
                left_side = left_side.checked_sub(source_term).ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key source response subtraction overflowed",
                    )
                })?;
                left_side = left_side
                    .checked_sub(
                        i128::from(modulus)
                            .checked_mul(carry_response[coefficient_index])
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key carry response scaling overflowed",
                                )
                            })?,
                    )
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key key-switch relation overflowed",
                        )
                    })?;
                if left_side != relation_commitment[coefficient_index] {
                    return Err(invalid_evaluation_key_share_proof(format!(
                        "evaluation-key key-switch relation failed at level {level}, digit {digit_index}, limb {rns_limb_index}, coefficient {coefficient_index}"
                    )));
                }
            }
        }
    }

    Ok(())
}

struct EvaluationKeyShareMasks {
    secret_masks: Vec<i128>,
    negative_indicator_masks: Vec<i128>,
    randomness_masks_by_limb: Vec<Vec<Vec<i128>>>,
    error_masks_by_digit: Vec<Vec<i128>>,
    relinearization_source_masks_by_digit: Vec<Vec<i128>>,
    carry_masks_by_digit_by_limb: Vec<Vec<Vec<i128>>>,
}

struct EvaluationKeyShareResponses {
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    error_response_by_digit: Vec<Vec<i128>>,
    relinearization_source_response_by_digit: Vec<Vec<i128>>,
    carry_response_by_digit_by_limb: Vec<Vec<Vec<i128>>>,
}

fn sample_evaluation_key_share_masks(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<EvaluationKeyShareMasks> {
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let digit_count = input.component_b_by_digit.len();
    let limb_count = input
        .component_b_by_digit
        .first()
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no digits"))?;
    let secret_masks = (0..ring_degree)
        .map(|coefficient_index| {
            sample_nonnegative_mask_i128(
                EVALUATION_KEY_SHARE_SECRET_MASK_DOMAIN,
                input.proof_randomness_seed_hex,
                &[0, coefficient_index as u64],
                EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_masks = (0..ring_degree)
        .map(|coefficient_index| {
            sample_nonnegative_mask_i128(
                EVALUATION_KEY_SHARE_NEGATIVE_INDICATOR_MASK_DOMAIN,
                input.proof_randomness_seed_hex,
                &[0, coefficient_index as u64],
                EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_masks_by_limb = (0..DATA_PRIMES.len())
        .map(|rns_limb_index| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            sample_signed_mask_i128(
                                EVALUATION_KEY_SHARE_RANDOMNESS_MASK_DOMAIN,
                                input.proof_randomness_seed_hex,
                                &[
                                    rns_limb_index as u64,
                                    randomness_column_index as u64,
                                    coefficient_index as u64,
                                ],
                                EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_masks_by_digit = (0..digit_count)
        .map(|digit_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    sample_signed_mask_i128(
                        EVALUATION_KEY_SHARE_ERROR_MASK_DOMAIN,
                        input.proof_randomness_seed_hex,
                        &[digit_index as u64, coefficient_index as u64],
                        EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let relinearization_source_masks_by_digit =
        if input.proof_family == EvaluationKeyShareProofFamily::Relinearization {
            if relinearization_record_uses_same_secret_source(input.proof_record) {
                vec![secret_masks.clone(); digit_count]
            } else {
                (0..digit_count)
                    .map(|digit_index| {
                        (0..ring_degree)
                            .map(|coefficient_index| {
                                sample_signed_mask_i128(
                                    EVALUATION_KEY_SHARE_SOURCE_MASK_DOMAIN,
                                    input.proof_randomness_seed_hex,
                                    &[digit_index as u64, coefficient_index as u64],
                                    EVALUATION_KEY_SHARE_SOURCE_MASK_BITS,
                                )
                            })
                            .collect::<CanonicalResult<Vec<_>>>()
                    })
                    .collect::<CanonicalResult<Vec<_>>>()?
            }
        } else {
            Vec::new()
        };
    let carry_masks_by_digit_by_limb = (0..digit_count)
        .map(|digit_index| {
            (0..limb_count)
                .map(|rns_limb_index| {
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            sample_signed_mask_i128(
                                EVALUATION_KEY_SHARE_CARRY_MASK_DOMAIN,
                                input.proof_randomness_seed_hex,
                                &[
                                    digit_index as u64,
                                    rns_limb_index as u64,
                                    coefficient_index as u64,
                                ],
                                EVALUATION_KEY_SHARE_CARRY_MASK_BITS,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(EvaluationKeyShareMasks {
        secret_masks,
        negative_indicator_masks,
        randomness_masks_by_limb,
        error_masks_by_digit,
        relinearization_source_masks_by_digit,
        carry_masks_by_digit_by_limb,
    })
}

fn key_switch_relation_commitments_from_masks(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
    masks: &EvaluationKeyShareMasks,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let key_switch_domain = string_field(input.proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(input.proof_record, "keySwitchSeedHex")?;
    let galois_element = input
        .proof_record
        .get("rotation")
        .and_then(Value::as_u64)
        .map(|rotation| {
            usize::try_from(rotation).map_err(|_| {
                invalid_evaluation_key_share_proof("Galois rotation does not fit usize")
            })
        })
        .transpose()?;
    let galois_source_masks = if input.proof_family == EvaluationKeyShareProofFamily::Galois {
        automorphism_i128(
            &masks.secret_masks,
            galois_element.ok_or_else(|| {
                invalid_evaluation_key_share_proof("Galois proof must include rotation")
            })?,
        )?
    } else {
        Vec::new()
    };
    input
        .component_b_by_digit
        .iter()
        .enumerate()
        .map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(|(rns_limb_index, _component_b)| {
                    let modulus = DATA_PRIMES[rns_limb_index];
                    let public_sample = deterministic_key_switch_public_sample(
                        key_switch_domain,
                        key_switch_seed_hex,
                        digit_index,
                        modulus,
                        ring_degree,
                    );
                    let public_sample_secret_product =
                        negacyclic_public_sample_secret_product_lifted(
                            &public_sample,
                            &masks.secret_masks,
                        )?;
                    let source_masks = match input.proof_family {
                        EvaluationKeyShareProofFamily::Relinearization => {
                            masks.relinearization_source_masks_by_digit[digit_index].clone()
                        }
                        EvaluationKeyShareProofFamily::Galois => galois_source_masks.clone(),
                    };
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            let mut value = public_sample_secret_product[coefficient_index];
                            value = value
                                .checked_sub(
                                    i128::from(PLAINTEXT_MODULUS_I64)
                                        .checked_mul(
                                            masks.error_masks_by_digit[digit_index]
                                                [coefficient_index],
                                        )
                                        .ok_or_else(|| {
                                            invalid_evaluation_key_share_proof(
                                                "evaluation-key error mask scaling overflowed",
                                            )
                                        })?,
                                )
                                .ok_or_else(|| {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key relation commitment overflowed",
                                    )
                                })?;
                            if rns_limb_index == digit_index {
                                value = value
                                    .checked_sub(source_masks[coefficient_index])
                                    .ok_or_else(|| {
                                        invalid_evaluation_key_share_proof(
                                            "evaluation-key source mask subtraction overflowed",
                                        )
                                    })?;
                            }
                            value = value
                                .checked_sub(
                                    i128::from(modulus)
                                        .checked_mul(
                                            masks.carry_masks_by_digit_by_limb[digit_index]
                                                [rns_limb_index][coefficient_index],
                                        )
                                        .ok_or_else(|| {
                                            invalid_evaluation_key_share_proof(
                                                "evaluation-key carry mask scaling overflowed",
                                            )
                                        })?,
                                )
                                .ok_or_else(|| {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key relation commitment overflowed",
                                    )
                                })?;
                            Ok(value)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn secret_commitment_relation_commitments_from_masks(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
    masks: &EvaluationKeyShareMasks,
) -> CanonicalResult<Vec<SetupCommitmentValue>> {
    input
        .constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            let message_coefficients = masks
                .secret_masks
                .iter()
                .zip(masks.negative_indicator_masks.iter())
                .map(|(secret_mask, negative_indicator_mask)| {
                    lifted_secret_message_response(
                        *secret_mask,
                        *negative_indicator_mask,
                        commitment.source_message_modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            compute_setup_commitment(
                input.public_matrix_seed_hash,
                rns_limb_index,
                commitment.source_message_modulus,
                0,
                &message_coefficients,
                &masks.randomness_masks_by_limb[rns_limb_index],
                commitment.ring_degree,
            )
        })
        .collect()
}

fn evaluation_key_share_responses(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
    masks: &EvaluationKeyShareMasks,
    challenge: u64,
) -> CanonicalResult<EvaluationKeyShareResponses> {
    let challenge_i128 = i128::from(challenge);
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let secret_response_coefficients = masks
        .secret_masks
        .iter()
        .zip(input.witness.secret_coefficients.iter())
        .map(|(mask, witness)| {
            mask.checked_add(
                challenge_i128
                    .checked_mul(i128::from(*witness))
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key secret response overflowed",
                        )
                    })?,
            )
            .ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key secret response overflowed")
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_response_coefficients =
        masks
            .negative_indicator_masks
            .iter()
            .zip(input.witness.secret_coefficients.iter())
            .map(|(mask, secret)| {
                let negative_indicator = if *secret < 0 { 1_i128 } else { 0_i128 };
                mask.checked_add(challenge_i128.checked_mul(negative_indicator).ok_or_else(
                    || {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key negative-indicator response overflowed",
                        )
                    },
                )?)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key negative-indicator response overflowed",
                    )
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_response_by_limb = masks
        .randomness_masks_by_limb
        .iter()
        .zip(input.witness.opening_randomness_by_limb.iter())
        .map(|(mask_columns, witness_columns)| {
            mask_columns
                .iter()
                .zip(witness_columns.iter())
                .map(|(mask_column, witness_column)| {
                    mask_column
                        .iter()
                        .zip(witness_column.iter())
                        .map(|(mask, witness)| {
                            mask.checked_add(challenge_i128.checked_mul(*witness).ok_or_else(
                                || {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key randomness response overflowed",
                                    )
                                },
                            )?)
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key randomness response overflowed",
                                )
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<Vec<Vec<i128>>>>>()?;
    let error_response_by_digit = masks
        .error_masks_by_digit
        .iter()
        .zip(input.witness.error_coefficients_by_digit.iter())
        .map(|(mask_error, witness_error)| {
            mask_error
                .iter()
                .zip(witness_error.iter())
                .map(|(mask, witness)| {
                    mask.checked_add(
                        challenge_i128
                            .checked_mul(i128::from(*witness))
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key error response overflowed",
                                )
                            })?,
                    )
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key error response overflowed",
                        )
                    })
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<Vec<i128>>>>()?;
    let relinearization_source_response_by_digit = if input.proof_family
        == EvaluationKeyShareProofFamily::Relinearization
    {
        masks
            .relinearization_source_masks_by_digit
            .iter()
            .zip(
                input
                    .witness
                    .relinearization_source_coefficients_by_digit
                    .iter(),
            )
            .map(|(mask_source, witness_source)| {
                mask_source
                    .iter()
                    .zip(witness_source.iter())
                    .map(|(mask, witness)| {
                        mask.checked_add(challenge_i128.checked_mul(*witness).ok_or_else(|| {
                            invalid_evaluation_key_share_proof(
                                "relinearization source response overflowed",
                            )
                        })?)
                        .ok_or_else(|| {
                            invalid_evaluation_key_share_proof(
                                "relinearization source response overflowed",
                            )
                        })
                    })
                    .collect()
            })
            .collect::<CanonicalResult<Vec<Vec<i128>>>>()?
    } else {
        Vec::new()
    };
    let carry_witnesses = key_switch_carry_witnesses(input)?;
    let carry_response_by_digit_by_limb = masks
        .carry_masks_by_digit_by_limb
        .iter()
        .zip(carry_witnesses.iter())
        .map(|(mask_by_limb, witness_by_limb)| {
            mask_by_limb
                .iter()
                .zip(witness_by_limb.iter())
                .map(|(mask_carry, witness_carry)| {
                    mask_carry
                        .iter()
                        .zip(witness_carry.iter())
                        .map(|(mask, witness)| {
                            mask.checked_add(challenge_i128.checked_mul(*witness).ok_or_else(
                                || {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key carry response overflowed",
                                    )
                                },
                            )?)
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key carry response overflowed",
                                )
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<Vec<Vec<i128>>>>>()?;
    if secret_response_coefficients.len() != ring_degree {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key response width does not match ringDegree",
        ));
    }

    Ok(EvaluationKeyShareResponses {
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        error_response_by_digit,
        relinearization_source_response_by_digit,
        carry_response_by_digit_by_limb,
    })
}

fn key_switch_carry_witnesses(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let key_switch_domain = string_field(input.proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(input.proof_record, "keySwitchSeedHex")?;
    let galois_element = input
        .proof_record
        .get("rotation")
        .and_then(Value::as_u64)
        .map(|rotation| {
            usize::try_from(rotation).map_err(|_| {
                invalid_evaluation_key_share_proof("Galois rotation does not fit usize")
            })
        })
        .transpose()?;
    let secret_witness = input
        .witness
        .secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let galois_source = if input.proof_family == EvaluationKeyShareProofFamily::Galois {
        automorphism_i128(
            &secret_witness,
            galois_element.ok_or_else(|| {
                invalid_evaluation_key_share_proof("Galois proof must include rotation")
            })?,
        )?
    } else {
        Vec::new()
    };
    input
        .component_b_by_digit
        .iter()
        .enumerate()
        .map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(|(rns_limb_index, component_b)| {
                    let modulus = DATA_PRIMES[rns_limb_index];
                    let public_sample = deterministic_key_switch_public_sample(
                        key_switch_domain,
                        key_switch_seed_hex,
                        digit_index,
                        modulus,
                        ring_degree,
                    );
                    let public_sample_secret_product =
                        negacyclic_public_sample_secret_product_lifted(
                            &public_sample,
                            &secret_witness,
                        )?;
                    let source = match input.proof_family {
                        EvaluationKeyShareProofFamily::Relinearization => input
                            .witness
                            .relinearization_source_coefficients_by_digit[digit_index]
                            .clone(),
                        EvaluationKeyShareProofFamily::Galois => galois_source.clone(),
                    };
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            let mut numerator = i128::from(component_b[coefficient_index]);
                            numerator = numerator
                                .checked_add(public_sample_secret_product[coefficient_index])
                                .ok_or_else(|| {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key carry numerator overflowed",
                                    )
                                })?;
                            numerator = numerator
                                .checked_sub(
                                    i128::from(PLAINTEXT_MODULUS_I64)
                                        .checked_mul(i128::from(
                                            input.witness.error_coefficients_by_digit[digit_index]
                                                [coefficient_index],
                                        ))
                                        .ok_or_else(|| {
                                            invalid_evaluation_key_share_proof(
                                                "evaluation-key carry error scaling overflowed",
                                            )
                                        })?,
                                )
                                .ok_or_else(|| {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key carry numerator overflowed",
                                    )
                                })?;
                            if rns_limb_index == digit_index {
                                numerator = numerator
                                    .checked_sub(source[coefficient_index])
                                    .ok_or_else(|| {
                                        invalid_evaluation_key_share_proof(
                                            "evaluation-key carry source subtraction overflowed",
                                        )
                                    })?;
                            }
                            let modulus_i128 = i128::from(modulus);
                            if numerator % modulus_i128 != 0 {
                                return Err(invalid_evaluation_key_share_proof(
                                    "evaluation-key witness does not satisfy the lifted key-switch relation",
                                ));
                            }
                            Ok(numerator / modulus_i128)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn encode_evaluation_key_share_relation_commitments(
    key_switch_relation_commitments: &[Vec<Vec<i128>>],
    secret_commitment_relation_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<Vec<u8>> {
    let mut encoded = Vec::new();
    for relation_commitments_by_limb in key_switch_relation_commitments {
        for relation_commitments in relation_commitments_by_limb {
            for coefficient in relation_commitments {
                encoded.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }
    write_setup_commitments(&mut encoded, secret_commitment_relation_commitments);

    Ok(encoded)
}

fn evaluation_key_share_lnp_relation_commitment_hash(
    proof_family: EvaluationKeyShareProofFamily,
    statement_hash_hex: &str,
    parameter_profile_hash_hex: &str,
    tbox_commitment_prefix_hash: &str,
    encoded_commitments: &[u8],
) -> String {
    hash512_hex(
        proof_family.commitment_hash_domain(),
        &[
            statement_hash_hex.as_bytes(),
            parameter_profile_hash_hex.as_bytes(),
            tbox_commitment_prefix_hash.as_bytes(),
            encoded_commitments,
        ],
    )
}

fn evaluation_key_share_lnp_relation_challenge(
    proof_family: EvaluationKeyShareProofFamily,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
) -> CanonicalResult<u64> {
    let challenge_coefficients = super::setup_proof::derive_setup_proof_challenge_coefficients(
        proof_family.proof_family(),
        statement_hash_hex,
        relation_commitment_hash_hex,
        super::setup_proof::SETUP_PROOF_LNP_PROOF_RING_DEGREE,
    )?;
    let mut encoded_challenge = Vec::with_capacity(challenge_coefficients.len() * 8);
    for coefficient in challenge_coefficients {
        encoded_challenge.extend_from_slice(&coefficient.to_le_bytes());
    }
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            proof_family.scalar_challenge_domain(),
            &[
                statement_hash_hex.as_bytes(),
                relation_commitment_hash_hex.as_bytes(),
                &encoded_challenge,
                &block_index_bytes,
            ],
        );
        let mut challenge_bytes = [0_u8; 8];
        challenge_bytes[..4].copy_from_slice(&block[..4]);
        let challenge = u64::from_le_bytes(challenge_bytes);
        if challenge != 0 {
            return Ok(challenge);
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_evaluation_key_share_proof(
                "evaluation-key LNP challenge block index overflowed",
            )
        })?;
    }
}

fn evaluation_key_share_scalar_challenge_maximum() -> CanonicalResult<u64> {
    let challenge_bits =
        u32::try_from(EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS).map_err(|_| {
            invalid_evaluation_key_share_proof(
                "evaluation-key challenge bit count does not fit u32",
            )
        })?;
    1_u64
        .checked_shl(challenge_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key challenge bound overflowed")
        })
}

fn evaluation_key_share_secret_response_bound(challenge: u64) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_SECRET_MASK_BITS + 1,
        challenge,
        EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND,
        "evaluation-key secret response",
    )
}

fn evaluation_key_share_error_response_bound(challenge: u64) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
        challenge,
        EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND,
        "evaluation-key error response",
    )
}

fn evaluation_key_share_randomness_response_bound(challenge: u64) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
        challenge,
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        "evaluation-key opening-randomness response",
    )
}

fn evaluation_key_share_relinearization_source_response_bound(
    challenge: u64,
    proof_record: &Value,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_SOURCE_MASK_BITS,
        challenge,
        relinearization_source_witness_bound(proof_record, ring_degree)?,
        "relinearization source response",
    )
}

fn relinearization_source_witness_bound(
    proof_record: &Value,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    let ring_degree = i128::try_from(ring_degree).map_err(|_| {
        invalid_evaluation_key_share_proof("evaluation-key ringDegree does not fit i128")
    })?;
    if relinearization_record_uses_same_secret_source(proof_record) {
        return Ok(ring_degree);
    }

    ring_degree
        .checked_mul(EVALUATION_KEY_SHARE_ROUND_TWO_AGGREGATE_SOURCE_PARTICIPANT_BOUND)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("round-two relinearization source bound overflowed")
        })
}

fn evaluation_key_share_carry_response_bound(
    challenge: u64,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    let witness_bound = i128::try_from(ring_degree)
        .map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key ringDegree does not fit i128")
        })?
        .checked_mul(2)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key carry bound overflowed")
        })?;
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_CARRY_MASK_BITS,
        challenge,
        witness_bound,
        "evaluation-key carry response",
    )
}

fn evaluation_key_share_response_bound(
    mask_bits: usize,
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    let mask_bound = mask_magnitude_bound(mask_bits, label)?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} bound overflowed")))?;
    mask_bound
        .checked_add(challenge_term)
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} bound overflowed")))
}

fn mask_magnitude_bound(mask_bits: usize, label: &str) -> CanonicalResult<i128> {
    let mask_bits = u32::try_from(mask_bits).map_err(|_| {
        invalid_evaluation_key_share_proof(format!("{label} mask bit count overflowed"))
    })?;
    1_i128
        .checked_shl(mask_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} mask bound overflowed")))
}

fn verify_i128_vector_bound(values: &[i128], bound: i128, label: &str) -> CanonicalResult<()> {
    for value in values {
        let magnitude = value
            .checked_abs()
            .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} overflowed")))?;
        if magnitude > bound {
            return Err(invalid_evaluation_key_share_proof(format!(
                "{label} exceeds the accepted no-wrap bound"
            )));
        }
    }

    Ok(())
}

fn lifted_secret_message_response(
    secret_response: i128,
    negative_indicator_response: i128,
    source_message_modulus: u64,
) -> CanonicalResult<u128> {
    let lifted = secret_response
        .checked_add(
            i128::from(source_message_modulus)
                .checked_mul(negative_indicator_response)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key lifted secret response multiplication overflowed",
                    )
                })?,
        )
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key lifted secret response overflowed")
        })?;
    if lifted < 0 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key lifted secret response became negative",
        ));
    }
    let lifted = u128::try_from(lifted).map_err(|_| {
        invalid_evaluation_key_share_proof(
            "evaluation-key lifted secret response does not fit u128",
        )
    })?;
    if lifted >= setup_commitment_modulus_product() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key lifted secret response wraps in the setup commitment modulus product",
        ));
    }

    Ok(lifted)
}

fn deterministic_key_switch_public_sample(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    digit_index: usize,
    modulus: u64,
    ring_degree: usize,
) -> Vec<u64> {
    let digit_bytes = (digit_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    DeterministicSampler::new(
        KEY_SWITCH_SAMPLE_DOMAIN,
        &[
            key_switch_domain.as_bytes(),
            key_switch_seed_hex.as_bytes(),
            &digit_bytes,
            &modulus_bytes,
        ],
    )
    .uniform_residues(modulus, ring_degree)
}

fn negacyclic_public_sample_secret_product_lifted(
    public_sample: &[u64],
    secret_coefficients: &[i128],
) -> CanonicalResult<Vec<i128>> {
    if public_sample.len() != secret_coefficients.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key lifted product inputs must have equal width",
        ));
    }
    let ring_degree = public_sample.len();
    let mut output = vec![0_i128; ring_degree];
    for (left_index, left_value) in public_sample.iter().enumerate() {
        for (right_index, right_value) in secret_coefficients.iter().enumerate() {
            let product = i128::from(*left_value)
                .checked_mul(*right_value)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key lifted product multiplication overflowed",
                    )
                })?;
            let raw_index = left_index.checked_add(right_index).ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key product index overflowed")
            })?;
            if raw_index < ring_degree {
                output[raw_index] = output[raw_index].checked_add(product).ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key lifted product accumulation overflowed",
                    )
                })?;
            } else {
                output[raw_index - ring_degree] = output[raw_index - ring_degree]
                    .checked_sub(product)
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key lifted product accumulation overflowed",
                        )
                    })?;
            }
        }
    }

    Ok(output)
}

fn negacyclic_i128_product_lifted(left: &[i128], right: &[i128]) -> CanonicalResult<Vec<i128>> {
    if left.len() != right.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key source product inputs must have equal width",
        ));
    }
    let ring_degree = left.len();
    let mut output = vec![0_i128; ring_degree];
    for (left_index, left_value) in left.iter().enumerate() {
        for (right_index, right_value) in right.iter().enumerate() {
            let product = left_value.checked_mul(*right_value).ok_or_else(|| {
                invalid_evaluation_key_share_proof(
                    "evaluation-key source product multiplication overflowed",
                )
            })?;
            let raw_index = left_index.checked_add(right_index).ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key source product index overflowed")
            })?;
            if raw_index < ring_degree {
                output[raw_index] = output[raw_index].checked_add(product).ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key source product accumulation overflowed",
                    )
                })?;
            } else {
                output[raw_index - ring_degree] = output[raw_index - ring_degree]
                    .checked_sub(product)
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key source product accumulation overflowed",
                        )
                    })?;
            }
        }
    }

    Ok(output)
}

#[cfg(test)]
pub(super) fn negacyclic_i128_product_for_evaluation_key_fixture(
    left: &[i128],
    right: &[i128],
) -> CanonicalResult<Vec<i128>> {
    negacyclic_i128_product_lifted(left, right)
}

#[cfg(test)]
pub(super) fn automorphism_i128_for_evaluation_key_fixture(
    input: &[i128],
    galois_element: usize,
) -> CanonicalResult<Vec<i128>> {
    automorphism_i128(input, galois_element)
}

fn automorphism_i128(input: &[i128], galois_element: usize) -> CanonicalResult<Vec<i128>> {
    let ring_degree = input.len();
    if ring_degree == 0 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key automorphism input must be non-empty",
        ));
    }
    let two_n = ring_degree.checked_mul(2).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key automorphism ring size overflowed")
    })?;
    let mut output = vec![0_i128; ring_degree];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = coefficient_index
            .checked_mul(galois_element)
            .map(|raw| raw % two_n)
            .ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key automorphism index overflowed")
            })?;
        if exponent < ring_degree {
            output[exponent] = output[exponent].checked_add(*value).ok_or_else(|| {
                invalid_evaluation_key_share_proof(
                    "evaluation-key automorphism accumulation overflowed",
                )
            })?;
        } else {
            output[exponent - ring_degree] = output[exponent - ring_degree]
                .checked_sub(*value)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key automorphism accumulation overflowed",
                    )
                })?;
        }
    }

    Ok(output)
}

#[cfg(test)]
pub(super) struct KeySwitchComponentBFixtureInput<'a> {
    pub(super) key_switch_domain: &'a str,
    pub(super) key_switch_seed_hex: &'a str,
    pub(super) digit_index: usize,
    pub(super) source_coefficients: &'a [i128],
    pub(super) secret_coefficients: &'a [i64],
    pub(super) error_coefficients: &'a [i64],
    pub(super) modulus: u64,
    pub(super) ring_degree: usize,
}

#[cfg(test)]
pub(super) fn key_switch_component_b_for_evaluation_key_fixture(
    input: KeySwitchComponentBFixtureInput<'_>,
) -> CanonicalResult<Vec<u64>> {
    let secret_i128 = input
        .secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let public_sample = deterministic_key_switch_public_sample(
        input.key_switch_domain,
        input.key_switch_seed_hex,
        input.digit_index,
        input.modulus,
        input.ring_degree,
    );
    let public_sample_secret_product =
        negacyclic_public_sample_secret_product_lifted(&public_sample, &secret_i128)?;
    (0..input.ring_degree)
        .map(|coefficient_index| {
            let mut lifted_value = i128::from(PLAINTEXT_MODULUS_I64)
                .checked_mul(i128::from(input.error_coefficients[coefficient_index]))
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key fixture error scaling overflowed",
                    )
                })?;
            lifted_value = lifted_value
                .checked_sub(public_sample_secret_product[coefficient_index])
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key fixture public-sample subtraction overflowed",
                    )
                })?;
            lifted_value = lifted_value
                .checked_add(input.source_coefficients[coefficient_index])
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key fixture source addition overflowed",
                    )
                })?;
            signed_i128_residue_u64(lifted_value, input.modulus)
        })
        .collect()
}

#[cfg(test)]
fn signed_i128_residue_u64(value: i128, modulus: u64) -> CanonicalResult<u64> {
    let modulus_wide = i128::from(modulus);
    let mut residue = value % modulus_wide;
    if residue < 0 {
        residue = residue.checked_add(modulus_wide).ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key signed residue overflowed")
        })?;
    }
    u64::try_from(residue).map_err(|_| {
        invalid_evaluation_key_share_proof("evaluation-key signed residue does not fit u64")
    })
}

fn encode_evaluation_key_share_lnp_tbox_prefix(
    proof_family: EvaluationKeyShareProofFamily,
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = EvaluationKeyShareLnpBitWriter::new();
    encode_evaluation_key_share_lnp_uniform_polyvec(
        proof_family,
        &mut writer,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        proof_randomness_seed_hex,
        0,
    )?;
    encode_evaluation_key_share_lnp_uniform_polyvec(
        proof_family,
        &mut writer,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        proof_randomness_seed_hex,
        1,
    )?;
    encode_evaluation_key_share_lnp_uniform_polyvec(
        proof_family,
        &mut writer,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        layout
            .proof_modulus_bit_count
            .checked_sub(layout.compression_dropped_bits)
            .ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key LNP compression underflowed")
            })?,
        proof_randomness_seed_hex,
        2,
    )?;

    Ok(writer.into_bytes())
}

fn encode_evaluation_key_share_lnp_tbox_suffix(
    prefix_bytes: &mut Vec<u8>,
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    challenge_coefficients: &[i64],
) -> CanonicalResult<()> {
    let mut writer = EvaluationKeyShareLnpBitWriter::from_bytes(prefix_bytes);
    for coefficient in challenge_coefficients {
        let shifted = coefficient
            .checked_add(
                i64::try_from(super::setup_proof::SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                    .expect("fixed challenge coefficient bound fits i64"),
            )
            .ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key LNP challenge shift overflowed")
            })?;
        let shifted = u64::try_from(shifted).map_err(|_| {
            invalid_evaluation_key_share_proof(
                "evaluation-key LNP challenge coefficient is negative",
            )
        })?;
        writer.write_u64_le_bits(
            shifted,
            super::setup_proof::SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        )?;
    }
    encode_evaluation_key_share_lnp_zero_hint_polyvec(
        &mut writer,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    encode_evaluation_key_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z1_polynomial_count,
        layout.proof_ring_degree,
        layout.z1_log2_standard_deviation,
    )?;
    encode_evaluation_key_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z21_polynomial_count,
        layout.proof_ring_degree,
        layout.z21_log2_standard_deviation,
    )?;
    encode_evaluation_key_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z3_polynomial_count,
        layout.proof_ring_degree,
        layout.z3_log2_standard_deviation,
    )?;
    encode_evaluation_key_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z4_polynomial_count,
        layout.proof_ring_degree,
        layout.z4_log2_standard_deviation,
    )?;
    writer.finish_with_lazer_padding();

    Ok(())
}

fn encode_evaluation_key_share_lnp_uniform_polyvec(
    proof_family: EvaluationKeyShareProofFamily,
    writer: &mut EvaluationKeyShareLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    bit_count: usize,
    proof_randomness_seed_hex: &str,
    field_index: u64,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(
                "evaluation-key LNP tbox coefficient count overflowed",
            )
        })?;
    for coefficient_index in 0..coefficient_count {
        let coefficient_index_bytes = u64::try_from(coefficient_index)
            .map_err(|_| {
                invalid_evaluation_key_share_proof(
                    "evaluation-key LNP coefficient index overflowed",
                )
            })?
            .to_le_bytes();
        let field_index_bytes = field_index.to_le_bytes();
        let block = hash512(
            proof_family.tbox_uniform_domain(),
            &[
                proof_randomness_seed_hex.as_bytes(),
                &field_index_bytes,
                &coefficient_index_bytes,
            ],
        );
        let mut word = [0_u8; 8];
        word.copy_from_slice(&block[..8]);
        let value = u64::from_le_bytes(word) & ((1_u64 << bit_count.min(32)) - 1);
        writer.write_u64_le_bits(value, bit_count)?;
    }

    Ok(())
}

fn encode_evaluation_key_share_lnp_zero_hint_polyvec(
    writer: &mut EvaluationKeyShareLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key LNP hint count overflowed")
        })?;
    for _ in 0..coefficient_count {
        writer.write_bit(false);
        writer.write_bit(false);
    }

    Ok(())
}

fn encode_evaluation_key_share_lnp_zero_gaussian_polyvec(
    writer: &mut EvaluationKeyShareLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key LNP Gaussian count overflowed")
        })?;
    let low_bit_count = log2_standard_deviation.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key LNP Gaussian low-bit count overflowed")
    })?;
    for _ in 0..coefficient_count {
        writer.write_bit(false);
        writer.write_u64_le_bits(0, low_bit_count)?;
    }

    Ok(())
}

enum EvaluationKeyShareLnpBitWriterStorage<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut Vec<u8>),
}

struct EvaluationKeyShareLnpBitWriter<'a> {
    storage: EvaluationKeyShareLnpBitWriterStorage<'a>,
    bit_offset: usize,
}

impl<'a> EvaluationKeyShareLnpBitWriter<'a> {
    fn new() -> Self {
        Self {
            storage: EvaluationKeyShareLnpBitWriterStorage::Owned(Vec::new()),
            bit_offset: 0,
        }
    }

    fn from_bytes(bytes: &'a mut Vec<u8>) -> Self {
        let bit_offset = bytes.len() * 8;
        Self {
            storage: EvaluationKeyShareLnpBitWriterStorage::Borrowed(bytes),
            bit_offset,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            EvaluationKeyShareLnpBitWriterStorage::Owned(bytes) => bytes,
            EvaluationKeyShareLnpBitWriterStorage::Borrowed(_) => {
                unreachable!("borrowed evaluation-key LNP bit writer is not consumed by value")
            }
        }
    }

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

    fn write_bit(&mut self, bit: bool) {
        let bytes = match &mut self.storage {
            EvaluationKeyShareLnpBitWriterStorage::Owned(bytes) => bytes,
            EvaluationKeyShareLnpBitWriterStorage::Borrowed(bytes) => bytes,
        };
        if self.bit_offset / 8 == bytes.len() {
            bytes.push(0);
        }
        if bit {
            bytes[self.bit_offset / 8] |= 1_u8 << (self.bit_offset % 8);
        }
        self.bit_offset += 1;
    }

    fn finish_with_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }
}

fn sample_nonnegative_mask_i128(
    domain: &str,
    proof_randomness_seed_hex: &str,
    coordinates: &[u64],
    bit_count: usize,
) -> CanonicalResult<i128> {
    let low = sample_unsigned_i128(domain, proof_randomness_seed_hex, coordinates, bit_count)?;
    let offset = 1_i128
        .checked_shl(u32::try_from(bit_count).map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key mask bit count overflowed")
        })?)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key mask offset overflowed")
        })?;
    offset
        .checked_add(low)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key mask overflowed"))
}

fn sample_signed_mask_i128(
    domain: &str,
    proof_randomness_seed_hex: &str,
    coordinates: &[u64],
    bit_count: usize,
) -> CanonicalResult<i128> {
    let magnitude =
        sample_unsigned_i128(domain, proof_randomness_seed_hex, coordinates, bit_count)?;
    let sign_block = hash512(
        domain,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"sign",
            &coordinates
                .iter()
                .flat_map(|coordinate| coordinate.to_le_bytes())
                .collect::<Vec<_>>(),
        ],
    );
    if sign_block[0] & 1 == 0 {
        Ok(magnitude)
    } else {
        magnitude
            .checked_neg()
            .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key mask overflowed"))
    }
}

fn sample_unsigned_i128(
    domain: &str,
    proof_randomness_seed_hex: &str,
    coordinates: &[u64],
    bit_count: usize,
) -> CanonicalResult<i128> {
    if bit_count > 120 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key mask sampler supports at most 120 bits",
        ));
    }
    let coordinate_bytes = coordinates
        .iter()
        .flat_map(|coordinate| coordinate.to_le_bytes())
        .collect::<Vec<_>>();
    let block = hash512(
        domain,
        &[proof_randomness_seed_hex.as_bytes(), &coordinate_bytes],
    );
    let mut value = 0_i128;
    let byte_count = bit_count.div_ceil(8);
    for (byte_index, byte) in block[..byte_count].iter().enumerate() {
        value |= i128::from(*byte) << (byte_index * 8);
    }
    if !bit_count.is_multiple_of(8) {
        let mask = (1_i128 << bit_count) - 1;
        value &= mask;
    }

    Ok(value)
}

fn hash_hex_to_fixed_bytes(hash_hex: &str) -> CanonicalResult<[u8; 64]> {
    if hash_hex.len() != 128 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key hash must be 64 bytes",
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

fn validate_hex_string(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.is_empty()
        || value
            .as_bytes()
            .iter()
            .any(|byte| hex_nibble(*byte).is_err())
    {
        return Err(invalid_evaluation_key_share_proof(format!(
            "{field_name} must be non-empty hexadecimal"
        )));
    }

    Ok(())
}

fn hex_nibble(value: u8) -> CanonicalResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_evaluation_key_share_proof(
            "evaluation-key hash contains a non-hex character",
        )),
    }
}

fn read_i128_matrix3(
    proof_bytes: &[u8],
    cursor: &mut usize,
    outer_count: usize,
    middle_count: usize,
    inner_count: usize,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    (0..outer_count)
        .map(|_| read_i128_matrix(proof_bytes, cursor, middle_count, inner_count))
        .collect()
}

fn read_i128_matrix(
    proof_bytes: &[u8],
    cursor: &mut usize,
    outer_count: usize,
    inner_count: usize,
) -> CanonicalResult<Vec<Vec<i128>>> {
    (0..outer_count)
        .map(|_| read_i128_vector(proof_bytes, cursor, inner_count))
        .collect()
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
    let end = cursor.checked_add(LENGTH).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key proof cursor overflowed")
    })?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof ended early"))?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn read_bytes(proof_bytes: &[u8], cursor: &mut usize, length: usize) -> CanonicalResult<Vec<u8>> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key proof cursor overflowed")
    })?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof ended early"))?;
    *cursor = end;

    Ok(bytes.to_vec())
}

fn write_i128_matrix3(output: &mut Vec<u8>, values: &[Vec<Vec<i128>>]) {
    for matrix in values {
        write_i128_matrix(output, matrix);
    }
}

fn write_i128_matrix(output: &mut Vec<u8>, values: &[Vec<i128>]) {
    for vector in values {
        write_i128_vector(output, vector);
    }
}

fn write_i128_vector(output: &mut Vec<u8>, values: &[i128]) {
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
}

fn write_setup_commitments(output: &mut Vec<u8>, commitments: &[SetupCommitmentValue]) {
    for commitment in commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    output.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
}

fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn value_usize(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let unsigned = value_u64(value, field_name)?;
    usize::try_from(unsigned)
        .map_err(|_| invalid_evaluation_key_share_proof(format!("{field_name} does not fit usize")))
}

fn value_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!("{field_name} must be an unsigned integer"))
        })
}

fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!("{field_name} must be a non-empty string"))
        })
}

fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!("{field_name} must be an object"))
        })
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{field_name} must be an array")))
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
                    invalid_evaluation_key_share_proof(format!(
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
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{row_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    decimal_i128_value(item)
                        .and_then(|item| i64::try_from(item).ok())
                        .ok_or_else(|| {
                            invalid_evaluation_key_share_proof(format!(
                                "{field_name}.{row_index}.{column_index} must be a signed 64-bit integer"
                            ))
                        })
                })
                .collect()
        })
        .collect()
}

fn i128_matrix_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i128>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{row_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    decimal_i128_value(item).ok_or_else(|| {
                        invalid_evaluation_key_share_proof(format!(
                            "{field_name}.{row_index}.{column_index} must be a signed integer or decimal string"
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
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{outer_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(middle_index, inner_value)| {
                    inner_value
                        .as_array()
                        .ok_or_else(|| {
                            invalid_evaluation_key_share_proof(format!(
                                "{field_name}.{outer_index}.{middle_index} must be an array"
                            ))
                        })?
                        .iter()
                        .enumerate()
                        .map(|(inner_index, item)| {
                            decimal_i128_value(item).ok_or_else(|| {
                                invalid_evaluation_key_share_proof(format!(
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

fn decimal_i128_value(value: &Value) -> Option<i128> {
    if let Some(value) = value.as_i64() {
        return Some(i128::from(value));
    }
    if let Some(value) = value.as_u64() {
        return Some(i128::from(value));
    }
    value.as_str()?.parse::<i128>().ok()
}

fn evaluation_key_share_proof_family_from_request(
    value: &Value,
) -> CanonicalResult<EvaluationKeyShareProofFamily> {
    match string_field(value, "proofFamily")? {
        "relinearization-key-share" => Ok(EvaluationKeyShareProofFamily::Relinearization),
        "galois-key-share" => Ok(EvaluationKeyShareProofFamily::Galois),
        _ => Err(invalid_evaluation_key_share_proof(
            "proofFamily must be relinearization-key-share or galois-key-share",
        )),
    }
}

fn proof_randomness_source(value: &Value) -> CanonicalResult<&'static str> {
    match value
        .get("proofRandomnessSource")
        .and_then(Value::as_str)
        .unwrap_or("fresh-csprng")
    {
        "fresh-csprng" => Ok("fresh-csprng"),
        "development-deterministic-fixture" => Ok("development-deterministic-fixture"),
        _ => Err(invalid_evaluation_key_share_proof(
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

    Err(invalid_evaluation_key_share_proof(format!(
        "{field_name} must be lowercase 512-bit hex"
    )))
}

fn validate_proof_randomness_seed(seed_hex: &str, field_name: &str) -> CanonicalResult<()> {
    validate_lowercase_hash(seed_hex, field_name)
}

fn invalid_evaluation_key_share_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
