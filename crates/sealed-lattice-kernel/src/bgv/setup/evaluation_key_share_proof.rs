mod challenge;
mod codec;
mod component_material;
mod generation;
mod masks;
mod ring_algebra;
mod statement;
mod verification;

pub(super) use self::codec::evaluation_key_share_lnp_relation_proof_bytes_hash;
pub(super) use self::component_material::component_b_vectors_from_record;
#[cfg(test)]
pub(super) use self::component_material::{
    KeySwitchComponentBFixtureInput, encode_evaluation_key_share_component_vectors,
    evaluation_key_share_component_material_reference_root,
    evaluation_key_share_component_material_transport_hashes,
    evaluation_key_share_component_vector_hash, evaluation_key_share_component_vector_root,
    key_switch_component_b_for_evaluation_key_fixture,
    register_verified_evaluation_key_share_component_material_chunks,
};
pub(crate) use self::generation::generate_evaluation_key_share_lnp_proof_from_request;
#[cfg(test)]
pub(super) use self::generation::{
    generate_evaluation_key_share_lnp_relation_proof,
    generate_evaluation_key_share_lnp_relation_proof_with_metadata,
};
#[cfg(test)]
pub(super) use self::ring_algebra::{
    automorphism_i128_for_evaluation_key_fixture,
    negacyclic_i128_product_for_evaluation_key_fixture,
};
pub(super) use self::verification::verify_evaluation_key_share_lnp_relation_proof;

use self::challenge::{
    encode_evaluation_key_share_relation_commitments, evaluation_key_share_lnp_relation_challenge,
    evaluation_key_share_lnp_relation_commitment_hash,
};
#[cfg(test)]
use self::codec::write_u64;
use self::codec::{
    array_field, encode_evaluation_key_share_lnp_tbox_prefix,
    evaluation_key_share_proof_family_from_request, hash_hex_to_fixed_bytes, i64_matrix_field,
    i64_vector_field, i128_matrix_field, i128_matrix3_field, object_field, proof_randomness_source,
    read_bytes, read_fixed, read_i128_matrix, read_i128_matrix3, read_i128_vector,
    read_signed_big_int_matrix3, read_u64, setup_commitment_values_field, string_field,
    validate_hex_string, validate_lowercase_hash, validate_proof_randomness_seed, value_u64,
    value_usize, write_i128_matrix, write_i128_matrix3, write_setup_commitments,
    write_signed_big_int_le_fixed, write_signed_big_int_matrix3,
};
use self::masks::{EvaluationKeyShareMasks, sample_evaluation_key_share_masks};
#[cfg(test)]
use self::ring_algebra::signed_i128_residue_u64;
use self::ring_algebra::{
    automorphism_i128, deterministic_key_switch_public_sample,
    lifted_secret_message_response_big_int, negacyclic_i128_product_lifted,
    negacyclic_public_sample_secret_product_big_int,
    negacyclic_public_sample_secret_product_lifted,
};
use self::statement::{
    evaluation_key_share_lnp_statement_hash, evaluation_key_share_lnp_statement_value,
    relinearization_record_uses_same_secret_source,
};
use self::verification::{
    relinearization_source_witness_bound, validate_evaluation_key_share_statement_material,
};
use super::{commitment, setup_proof};

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
#[cfg(test)]
use std::{fs, io::Write};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;
use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::{
            coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
            write_i128_vector,
        },
        evaluator::{
            key_switch::{KEY_SWITCH_SAMPLE_DOMAIN, PLAINTEXT_MODULUS_I64},
            prg::DeterministicSampler,
        },
        modular_arithmetic::{inverse_mod, mul_mod},
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
        compute_setup_big_signed_lifted_commitment, linear_combination_setup_commitments,
        parse_setup_commitment_full_value, setup_commitment_root,
        verify_setup_big_signed_lifted_commitment_opening,
    },
    sampling::negacyclic_product_mod,
    setup_proof::{SETUP_PROOF_PROFILE_ID, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES},
};

pub(super) const RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-relinearization-key-share-relation-verified-with-accepted-setup-proof-accounting";
pub(super) const RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, same-secret-bound secret opening response with centered signed 80-bit committed-secret masks and responses, fixed-width signed big-integer key-switch relation commitments, deterministic key-switch sampler, public component-vector material, lifted key-switch algebra, round-one same-secret source response, generator-side round-two aggregate-source product validation, centered-binomial error support, carried no-wrap responses, fixed response bounds, root-bound relinearization source binding records, verifier-side round-two source-square aggregate roots, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing relinearization proof acceptance";
pub(super) const GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-galois-key-share-relation-verified-with-accepted-setup-proof-accounting";
pub(super) const GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, same-secret-bound secret opening response with centered signed 80-bit committed-secret masks and responses, fixed-width signed big-integer key-switch relation commitments, deterministic key-switch sampler, public component-vector material, Galois automorphism source response, lifted key-switch algebra, centered-binomial error support, carried no-wrap responses, fixed response bounds, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing Galois-key proof acceptance";

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
const EVALUATION_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT: usize = 4;
pub(super) const RELINEARIZATION_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-scalar-challenge-v1";
pub(super) const GALOIS_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-scalar-challenge-v1";
const RELINEARIZATION_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-relation-commitment-v1";
const GALOIS_KEY_SHARE_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-relation-commitment-v1";
const RELINEARIZATION_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-key-share/lnp-proof-bytes-v1";
const GALOIS_KEY_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/galois-key-share/lnp-proof-bytes-v1";
const EVALUATION_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT: usize = 32;
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

pub(super) const EVALUATION_KEY_SHARE_SECRET_MASK_BITS: usize = 80;
pub(super) const EVALUATION_KEY_SHARE_ERROR_MASK_BITS: usize = 80;
pub(super) const EVALUATION_KEY_SHARE_SOURCE_MASK_BITS: usize = 80;
pub(super) const EVALUATION_KEY_SHARE_CARRY_MASK_BITS: usize = 64;
pub(super) const EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS: usize = 80;
pub(super) const EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS: usize = 63;
pub(super) const EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND: i128 = 1;
pub(super) const EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND: i128 = 2;
pub(super) const EVALUATION_KEY_SHARE_ROUND_TWO_AGGREGATE_SOURCE_PARTICIPANT_BOUND: i128 = 10;

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

fn invalid_evaluation_key_share_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
