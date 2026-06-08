use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde_json::{Value, json};
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint},
    hashing::{HASH512_PREIMAGE_PREFIX, derive_protocol_hash, hash512, hash512_hex, to_hex},
};

use super::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
    SETUP_COMMITMENT_ROW_COUNT,
};

pub(super) const SETUP_PROOF_PROFILE_ID: &str = "SealedLattice-LNP-SetupProof-v1";
pub(super) const SETUP_PROOF_CHALLENGE_BITS: u64 = 128;
pub(super) const SETUP_PROOF_CHALLENGE_COUNT: u64 = 1;
pub(super) const SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND: u64 = 2;
pub(super) const SETUP_PROOF_LNP_PROOF_RING_DEGREE: usize = 128;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE: usize = 3;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS: u64 =
    SETUP_PROOF_LNP_PROOF_RING_DEGREE as u64 * SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE as u64;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS: u64 = 147;
pub(super) const SETUP_PROOF_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-v1";
pub(super) const SETUP_PROOF_CHALLENGE_DOMAIN_PURPOSE: &str = "setup-proof-challenge-domain-v1";
pub(super) const SETUP_PROOF_CHALLENGE_SPACE: &str =
    "fixed-lnp-small-coefficient-polynomial-challenge-set";
pub(super) const SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS: &str =
    "repo-owned-lnp22-small-coefficient-challenge-differences-invertible";
pub(super) const SETUP_PROOF_CHALLENGE_SAMPLER: &str =
    "sealed-lattice-shake256-lazer-autostable-rejection-v1";
const SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS: usize = 256;
const SETUP_PROOF_LNP_TBOX_Z34_SECURITY_PARAMETER: u64 = 128;
const SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_NUMERATOR: u64 = 164;
const SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_DENOMINATOR: u64 = 100;
const SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR: u64 = 155;
const SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR: u64 = 100;
const SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT: usize = 32;
const SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K: u64 = 1;
const SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START: u64 = 0;
const SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START: u64 = 256;
pub(super) const SETUP_PROOF_CHALLENGE_SEED_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1";
pub(super) const SETUP_PROOF_CHALLENGE_STREAM_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1";
const SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/lnp-tbox-lower-protocol-challenge-v1";
const SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_SEED_DOMAIN: &str =
    "sealed-lattice/setup/lnp-tbox-lower-protocol-challenge-seed-v1";
pub(super) const SETUP_PROOF_BYTES_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-proof-bytes-v1";
pub(super) const SETUP_PROOF_SERIALIZATION: &str = "binary";
pub(crate) const SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
pub(crate) const SETUP_PROOF_MATERIAL_ENCODING: &str = "binary-chunked-proof-bytes";
const SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupProofMaterialChunkManifest";
const SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER: &str =
    "sealed-lattice-lnp-tbox-proof-byte-decoder-v1";
pub(crate) const SAME_SECRET_LNP_TBOX_PARAMETER_PROFILE_ID: &str =
    "SealedLattice-LNP-SameSecretConsistency-Tbox-v1";
pub(crate) const PUBLIC_KEY_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID: &str =
    "SealedLattice-LNP-PublicKeyShare-Tbox-v1";
pub(crate) const PRIVATE_VSS_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID: &str =
    "SealedLattice-LNP-PrivateVssShare-Tbox-v1";
pub(crate) const RELINEARIZATION_KEY_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID: &str =
    "SealedLattice-LNP-RelinearizationKeyShare-Tbox-v1";
pub(crate) const GALOIS_KEY_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID: &str =
    "SealedLattice-LNP-GaloisKeyShare-Tbox-v1";
pub(super) const SETUP_PROOF_FAMILIES: &[&str] = &[
    "vss-opening-carry",
    "same-secret-consistency",
    "public-key-share",
    "relinearization-key-share",
    "galois-key-share",
];

#[derive(Debug, Clone)]
pub(crate) struct SetupProofMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

pub(crate) struct SetupProofMaterialReferenceInput<'a> {
    pub(crate) setup_profile_id: &'a str,
    pub(crate) proof_family: &'a str,
    pub(crate) trustee_identity: &'a str,
    pub(crate) trustee_roster_position: u64,
    pub(crate) statement_hash_hex: &'a str,
    pub(crate) relation_commitment_hash_hex: &'a str,
    pub(crate) tbox_commitment_prefix_hash: &'a str,
    pub(crate) proof_size_bytes: u64,
    pub(crate) proof_bytes_hash: &'a str,
    pub(crate) transport_hashes: &'a SetupProofMaterialTransportHashes,
}

#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "used by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct SetupProofLnpTboxLayout {
    pub(crate) proof_family: &'static str,
    pub(crate) tbox_parameter_profile_id: &'static str,
    pub(crate) tbox_commitment_prefix_hash_domain: &'static str,
    pub(crate) proof_ring_degree: usize,
    pub(crate) proof_modulus: BigUint,
    pub(crate) proof_modulus_bit_count: usize,
    pub(crate) compression_dropped_bits: usize,
    pub(crate) t_b_polynomial_count: usize,
    pub(crate) h_polynomial_count: usize,
    pub(crate) t_a1_polynomial_count: usize,
    pub(crate) hint_polynomial_count: usize,
    pub(crate) z1_polynomial_count: usize,
    pub(crate) z21_polynomial_count: usize,
    pub(crate) z3_polynomial_count: usize,
    pub(crate) z4_polynomial_count: usize,
    pub(crate) z1_log2_standard_deviation: usize,
    pub(crate) z21_log2_standard_deviation: usize,
    pub(crate) z3_log2_standard_deviation: usize,
    pub(crate) z4_log2_standard_deviation: usize,
}

pub(crate) fn same_secret_lnp_tbox_layout() -> SetupProofLnpTboxLayout {
    SetupProofLnpTboxLayout {
        proof_family: "same-secret-consistency",
        tbox_parameter_profile_id: SAME_SECRET_LNP_TBOX_PARAMETER_PROFILE_ID,
        tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/same-secret/lnp-tbox-commitment-prefix-v1",
        proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        proof_modulus: setup_proof_lnp_tbox_proof_modulus(),
        proof_modulus_bit_count: 255,
        compression_dropped_bits: 23,
        t_b_polynomial_count: 11,
        h_polynomial_count: 4,
        t_a1_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + 2,
        hint_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + 2,
        z1_polynomial_count: 4,
        z21_polynomial_count: 16,
        z3_polynomial_count: 2,
        z4_polynomial_count: 2,
        z1_log2_standard_deviation: 24,
        z21_log2_standard_deviation: 40,
        z3_log2_standard_deviation: 16,
        z4_log2_standard_deviation: 16,
    }
}

pub(crate) fn public_key_share_lnp_tbox_layout() -> SetupProofLnpTboxLayout {
    SetupProofLnpTboxLayout {
        proof_family: "public-key-share",
        tbox_parameter_profile_id: PUBLIC_KEY_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID,
        tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/public-key-share/lnp-tbox-commitment-prefix-v1",
        proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        proof_modulus: setup_proof_lnp_tbox_proof_modulus(),
        proof_modulus_bit_count: 255,
        compression_dropped_bits: 23,
        t_b_polynomial_count: DATA_PRIMES.len() * 8 + 3,
        h_polynomial_count: 4,
        t_a1_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + DATA_PRIMES.len() * 2 + 2,
        hint_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + DATA_PRIMES.len() * 2 + 2,
        z1_polynomial_count: 4 + DATA_PRIMES.len() * 2,
        z21_polynomial_count: 16 + DATA_PRIMES.len() * 8,
        z3_polynomial_count: 2,
        z4_polynomial_count: 2,
        z1_log2_standard_deviation: 24,
        z21_log2_standard_deviation: 40,
        z3_log2_standard_deviation: 16,
        z4_log2_standard_deviation: 16,
    }
}

pub(crate) fn private_vss_share_lnp_tbox_layout() -> SetupProofLnpTboxLayout {
    SetupProofLnpTboxLayout {
        proof_family: "vss-opening-carry",
        tbox_parameter_profile_id: PRIVATE_VSS_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID,
        tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/private-vss-share/lnp-tbox-commitment-prefix-v1",
        proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        proof_modulus: setup_proof_lnp_tbox_proof_modulus(),
        proof_modulus_bit_count: 255,
        compression_dropped_bits: 23,
        t_b_polynomial_count: 19,
        h_polynomial_count: 4,
        t_a1_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH * 4 + 6,
        hint_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH * 4 + 6,
        z1_polynomial_count: 8,
        z21_polynomial_count: 32,
        z3_polynomial_count: 2,
        z4_polynomial_count: 2,
        z1_log2_standard_deviation: 24,
        z21_log2_standard_deviation: 40,
        z3_log2_standard_deviation: 16,
        z4_log2_standard_deviation: 16,
    }
}

pub(crate) fn relinearization_key_share_lnp_tbox_layout() -> SetupProofLnpTboxLayout {
    SetupProofLnpTboxLayout {
        proof_family: "relinearization-key-share",
        tbox_parameter_profile_id: RELINEARIZATION_KEY_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID,
        tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/relinearization-key-share/lnp-tbox-commitment-prefix-v1",
        proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        proof_modulus: setup_proof_lnp_tbox_proof_modulus(),
        proof_modulus_bit_count: 255,
        compression_dropped_bits: 23,
        t_b_polynomial_count: 11,
        h_polynomial_count: 4,
        t_a1_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + 8,
        hint_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + 8,
        z1_polynomial_count: 8,
        z21_polynomial_count: 24,
        z3_polynomial_count: 2,
        z4_polynomial_count: 2,
        z1_log2_standard_deviation: 24,
        z21_log2_standard_deviation: 40,
        z3_log2_standard_deviation: 16,
        z4_log2_standard_deviation: 16,
    }
}

pub(crate) fn galois_key_share_lnp_tbox_layout() -> SetupProofLnpTboxLayout {
    SetupProofLnpTboxLayout {
        proof_family: "galois-key-share",
        tbox_parameter_profile_id: GALOIS_KEY_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID,
        tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/galois-key-share/lnp-tbox-commitment-prefix-v1",
        proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        proof_modulus: setup_proof_lnp_tbox_proof_modulus(),
        proof_modulus_bit_count: 255,
        compression_dropped_bits: 23,
        t_b_polynomial_count: 11,
        h_polynomial_count: 4,
        t_a1_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + 8,
        hint_polynomial_count: SETUP_COMMITMENT_RANDOMNESS_WIDTH + 8,
        z1_polynomial_count: 8,
        z21_polynomial_count: 24,
        z3_polynomial_count: 2,
        z4_polynomial_count: 2,
        z1_log2_standard_deviation: 24,
        z21_log2_standard_deviation: 40,
        z3_log2_standard_deviation: 16,
        z4_log2_standard_deviation: 16,
    }
}

pub(crate) fn same_secret_lnp_tbox_parameter_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupProofLnpTboxParameterProfileHash",
        &same_secret_lnp_tbox_parameter_profile_value()?,
    )
}

pub(crate) fn public_key_share_lnp_tbox_parameter_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupProofLnpTboxParameterProfileHash",
        &public_key_share_lnp_tbox_parameter_profile_value()?,
    )
}

pub(crate) fn private_vss_share_lnp_tbox_parameter_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupProofLnpTboxParameterProfileHash",
        &private_vss_share_lnp_tbox_parameter_profile_value()?,
    )
}

pub(crate) fn relinearization_key_share_lnp_tbox_parameter_profile_hash() -> CanonicalResult<String>
{
    derive_protocol_hash(
        "SetupProofLnpTboxParameterProfileHash",
        &relinearization_key_share_lnp_tbox_parameter_profile_value()?,
    )
}

pub(crate) fn galois_key_share_lnp_tbox_parameter_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupProofLnpTboxParameterProfileHash",
        &galois_key_share_lnp_tbox_parameter_profile_value()?,
    )
}

pub(crate) fn same_secret_lnp_tbox_parameter_profile_value() -> CanonicalResult<Value> {
    let layout = same_secret_lnp_tbox_layout();
    setup_proof_lnp_tbox_parameter_profile_value(
        &layout,
        "pinned sealed-lattice first-profile same-secret relation dimensions",
        json!({
            "rnsLimbCount": DATA_PRIMES.len(),
            "commitmentModulusLimbCount": SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "openingRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "sharedSecretPolynomialCount": 1,
            "negativeIndicatorPolynomialCount": 1,
            "constantCommitmentCount": DATA_PRIMES.len(),
            "supportRelationCountPerCoefficient": 2
        }),
        "SLSSLNP1",
        "same-secret verifier pins and checks this profile; repo-owned setup proof soundness, zero-knowledge, and QROM accounting is accepted by the setup proof accounting certificate",
    )
}

pub(crate) fn private_vss_share_lnp_tbox_parameter_profile_value() -> CanonicalResult<Value> {
    let layout = private_vss_share_lnp_tbox_layout();
    setup_proof_lnp_tbox_parameter_profile_value(
        &layout,
        "pinned sealed-lattice first-profile recipient-local private VSS share relation dimensions",
        json!({
            "rnsLimbCountPerProof": 1,
            "commitmentModulusLimbCount": SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "openingRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "shamirCoefficientCommitmentCount": 4,
            "recipientSharePolynomialCount": 1,
            "carryPolynomialCount": 1,
            "coefficientOpeningRelationCount": 4,
            "carryAwareLiftedRelationCount": 1
        }),
        "SLVSLNP1",
        "private VSS share verifier pins and checks this profile; repo-owned setup proof soundness, zero-knowledge, and QROM accounting is accepted by the setup proof accounting certificate",
    )
}

pub(crate) fn public_key_share_lnp_tbox_parameter_profile_value() -> CanonicalResult<Value> {
    let layout = public_key_share_lnp_tbox_layout();
    setup_proof_lnp_tbox_parameter_profile_value(
        &layout,
        "pinned sealed-lattice first-profile lifted public-key share relation dimensions",
        json!({
            "rnsLimbCount": DATA_PRIMES.len(),
            "commitmentModulusLimbCount": SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "openingRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "sharedSecretPolynomialCount": 1,
            "negativeIndicatorPolynomialCount": 1,
            "publicKeySharePolynomialCountPerLimb": 1,
            "publicKeyErrorPolynomialCountPerLimb": 1,
            "publicKeyCarryPolynomialCountPerLimb": 1,
            "constantCommitmentCount": DATA_PRIMES.len(),
            "publicKeyLiftedRelationCountPerCoefficientPerLimb": 1,
            "errorSupportRelationCountPerCoefficientPerLimb": 1,
            "secretSupportRelationCountPerCoefficient": 2
        }),
        "SLPKLNP1",
        "public-key share verifier pins and checks this profile; repo-owned setup proof soundness, zero-knowledge, and QROM accounting is accepted by the setup proof accounting certificate",
    )
}

pub(crate) fn relinearization_key_share_lnp_tbox_parameter_profile_value() -> CanonicalResult<Value>
{
    let layout = relinearization_key_share_lnp_tbox_layout();
    setup_proof_lnp_tbox_parameter_profile_value(
        &layout,
        "pinned sealed-lattice first-profile lifted relinearization key-share relation dimensions",
        json!({
            "rnsLimbCount": DATA_PRIMES.len(),
            "activeDigitCountMaximum": DATA_PRIMES.len(),
            "activeLimbPairCountMaximum": DATA_PRIMES.len() * DATA_PRIMES.len(),
            "commitmentModulusLimbCount": SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "openingRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "sharedSecretPolynomialCount": 1,
            "negativeIndicatorPolynomialCount": 1,
            "sourceResponsePolynomialCountPerDigit": 1,
            "errorPolynomialCountPerDigit": 1,
            "carryPolynomialCountPerDigitAndLimb": 1,
            "componentBPolynomialCountPerDigitAndLimb": 1,
            "constantCommitmentCount": DATA_PRIMES.len(),
            "keySwitchLiftedRelationCountPerCoefficientPerDigitAndLimb": 1,
            "roundTwoAggregateSourceParticipantBound": 10,
            "sourceSquareClosureStatus": "verifier-checked-round-two-source-square-aggregate-binding",
        }),
        "SLRKLNP1",
        "relinearization key-share verifier pins and checks this linear key-switch profile with round-one same-secret source responses, generator-side round-two aggregate-source product validation, verifier-side round-two source-square aggregate-root binding, and accepted setup proof soundness, zero-knowledge, and QROM accounting",
    )
}

pub(crate) fn galois_key_share_lnp_tbox_parameter_profile_value() -> CanonicalResult<Value> {
    let layout = galois_key_share_lnp_tbox_layout();
    setup_proof_lnp_tbox_parameter_profile_value(
        &layout,
        "pinned sealed-lattice first-profile lifted Galois key-share relation dimensions",
        json!({
            "rnsLimbCount": DATA_PRIMES.len(),
            "activeDigitCountMaximum": DATA_PRIMES.len(),
            "activeLimbPairCountMaximum": DATA_PRIMES.len() * DATA_PRIMES.len(),
            "commitmentModulusLimbCount": SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "openingRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "sharedSecretPolynomialCount": 1,
            "negativeIndicatorPolynomialCount": 1,
            "automorphismSourcePolynomialCountPerDigit": 1,
            "errorPolynomialCountPerDigit": 1,
            "carryPolynomialCountPerDigitAndLimb": 1,
            "componentBPolynomialCountPerDigitAndLimb": 1,
            "constantCommitmentCount": DATA_PRIMES.len(),
            "keySwitchLiftedRelationCountPerCoefficientPerDigitAndLimb": 1,
        }),
        "SLGKLNP1",
        "Galois key-share verifier pins and checks this profile; repo-owned setup proof soundness, zero-knowledge, and QROM accounting is accepted by the setup proof accounting certificate",
    )
}

fn setup_proof_lnp_tbox_parameter_profile_value(
    layout: &SetupProofLnpTboxLayout,
    parameter_source: &str,
    relation_dimensions: Value,
    envelope_magic: &str,
    review_status: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofLnpTboxParameterProfile",
        "objectVersion": 1,
        "profileId": layout.tbox_parameter_profile_id,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": layout.proof_family,
        "referenceImplementation": "LaZer LNP tbox parameter model with sealed-lattice fixed relation dimensions",
        "parameterSource": parameter_source,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "proofRingDegree": layout.proof_ring_degree,
        "proofModulusDecimal": layout.proof_modulus.to_string(),
        "proofModulusBitCount": layout.proof_modulus_bit_count,
        "compressionDroppedBits": layout.compression_dropped_bits,
        "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
        "proofByteDecoder": SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER,
        "tboxLayout": {
            "tBPolynomialCount": layout.t_b_polynomial_count,
            "hPolynomialCount": layout.h_polynomial_count,
            "tA1PolynomialCount": layout.t_a1_polynomial_count,
            "hintPolynomialCount": layout.hint_polynomial_count,
            "z1PolynomialCount": layout.z1_polynomial_count,
            "z21PolynomialCount": layout.z21_polynomial_count,
            "z3PolynomialCount": layout.z3_polynomial_count,
            "z4PolynomialCount": layout.z4_polynomial_count,
            "z1Log2StandardDeviation": layout.z1_log2_standard_deviation,
            "z21Log2StandardDeviation": layout.z21_log2_standard_deviation,
            "z3Log2StandardDeviation": layout.z3_log2_standard_deviation,
            "z4Log2StandardDeviation": layout.z4_log2_standard_deviation
        },
        "z34SeedMaterialProfile": setup_proof_lnp_tbox_z34_seed_profile_value(layout)?,
        "relationDimensions": relation_dimensions,
        "proofMaterialSchema": {
            "encoding": "binary",
            "envelopeMagic": envelope_magic,
            "metadataTransport": "canonical-json-roots-only",
            "largeProofTransport": SETUP_PROOF_MATERIAL_ENCODING,
            "streaming": "root-bound binary chunks with canonical full-object and chunk hashes",
            "tboxCommitmentPrefixHash": layout.tbox_commitment_prefix_hash_domain
        },
        "reviewStatus": review_status,
    }))
}

pub(crate) fn setup_proof_lnp_tbox_commitment_prefix_byte_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    validate_lnp_tbox_layout(layout)?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let prefix_bit_count = layout
        .t_b_polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .and_then(|count| count.checked_mul(layout.proof_modulus_bit_count))
        .and_then(|count| {
            layout
                .h_polynomial_count
                .checked_mul(layout.proof_ring_degree)
                .and_then(|h_count| h_count.checked_mul(layout.proof_modulus_bit_count))
                .and_then(|h_bits| count.checked_add(h_bits))
        })
        .and_then(|count| {
            layout
                .t_a1_polynomial_count
                .checked_mul(layout.proof_ring_degree)
                .and_then(|t_a1_count| t_a1_count.checked_mul(compressed_bit_count))
                .and_then(|t_a1_bits| count.checked_add(t_a1_bits))
        })
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox commitment prefix size overflowed")
        })?;
    if prefix_bit_count % 8 != 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox commitment prefix must end on a byte boundary",
        ));
    }

    Ok(prefix_bit_count / 8)
}

pub(crate) fn setup_proof_lnp_tbox_commitment_prefix_hash(
    layout: &SetupProofLnpTboxLayout,
    proof_bytes: &[u8],
) -> CanonicalResult<String> {
    let prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(layout)?;
    let Some(prefix_bytes) = proof_bytes.get(..prefix_byte_count) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox proof ended before the commitment prefix",
        ));
    };

    Ok(hash512_hex(
        layout.tbox_commitment_prefix_hash_domain,
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            prefix_bytes,
        ],
    ))
}

pub(super) fn setup_proof_lnp_tbox_prefix_binding_seed(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    tbox_parameter_profile_hash: &str,
    encoded_relation_commitments: &[u8],
) -> CanonicalResult<String> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(statement_hash_hex, "setupProofLnpTboxPrefix.statementHash")?;
    validate_hash_string(
        tbox_parameter_profile_hash,
        "setupProofLnpTboxPrefix.parameterProfileHash",
    )?;
    if encoded_relation_commitments.is_empty() {
        return Err(setup_proof_error(
            "setup proof LNP tbox prefix binding requires relation commitments",
        ));
    }

    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-prefix-binding-seed-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            tbox_parameter_profile_hash.as_bytes(),
            encoded_relation_commitments,
        ],
    ))
}

pub(super) fn sample_setup_proof_lnp_tbox_uniform_residue_bytes(
    domain: &str,
    proof_randomness_seed_hex: &str,
    field_index: u64,
    coefficient_index: usize,
    bit_count: usize,
    modulus: Option<&BigUint>,
) -> CanonicalResult<Vec<u8>> {
    if bit_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox uniform residue bit count must be positive",
        ));
    }
    if let Some(modulus) = modulus {
        if modulus.is_zero() {
            return Err(setup_proof_error(
                "setup proof LNP tbox uniform residue modulus must be positive",
            ));
        }
        if modulus.bits() > bit_count as u64 {
            return Err(setup_proof_error(
                "setup proof LNP tbox uniform residue modulus does not fit the declared bit count",
            ));
        }
    }

    let byte_count = bit_count
        .checked_add(7)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox bit count overflowed"))?
        / 8;
    let field_index_bytes = field_index.to_le_bytes();
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| setup_proof_error("setup proof LNP tbox coefficient index overflowed"))?
        .to_le_bytes();
    let kept_high_bits = bit_count % 8;
    let mut rejection_counter = 0_u64;

    loop {
        let rejection_counter_bytes = rejection_counter.to_le_bytes();
        let mut candidate_bytes = Vec::with_capacity(byte_count);
        let mut block_index = 0_u64;
        while candidate_bytes.len() < byte_count {
            let block_index_bytes = block_index.to_le_bytes();
            let block = hash512(
                domain,
                &[
                    proof_randomness_seed_hex.as_bytes(),
                    &field_index_bytes,
                    &coefficient_index_bytes,
                    &rejection_counter_bytes,
                    &block_index_bytes,
                ],
            );
            candidate_bytes.extend_from_slice(&block);
            block_index = block_index.checked_add(1).ok_or_else(|| {
                setup_proof_error("setup proof LNP tbox sampler block index overflowed")
            })?;
        }
        candidate_bytes.truncate(byte_count);
        if kept_high_bits != 0 {
            let high_byte_mask = (1_u8 << kept_high_bits) - 1;
            let last_byte = candidate_bytes
                .last_mut()
                .expect("positive bit count produces at least one byte");
            *last_byte &= high_byte_mask;
        }

        if modulus.is_none_or(|modulus| BigUint::from_bytes_le(&candidate_bytes) < *modulus) {
            return Ok(candidate_bytes);
        }

        rejection_counter = rejection_counter.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox sampler rejection counter overflowed")
        })?;
    }
}

pub(super) fn setup_proof_lnp_tbox_h_coefficient_must_be_zero(
    coefficient_index: usize,
    proof_ring_degree: usize,
) -> bool {
    if proof_ring_degree == 0 {
        return false;
    }
    let coefficient_position = coefficient_index % proof_ring_degree;
    coefficient_position == 0 || coefficient_position == proof_ring_degree / 2
}

fn setup_proof_lnp_tbox_z34_seed_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    if !SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS.is_multiple_of(layout.proof_ring_degree) {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 seed coefficient count must divide the proof ring degree",
        ));
    }

    Ok(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS / layout.proof_ring_degree)
}

fn setup_proof_lnp_tbox_message_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    let extension_polynomial_count = setup_proof_lnp_tbox_extension_polynomial_count(layout)?;

    layout
        .t_b_polynomial_count
        .checked_sub(extension_polynomial_count)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox tB layout is too small for z3/z4 seed material")
        })
}

fn setup_proof_lnp_tbox_extension_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    let seed_polynomial_count = setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?;
    seed_polynomial_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(layout.h_polynomial_count))
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox extension count overflowed"))
}

fn setup_proof_lnp_tbox_challenge_tail_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    layout
        .h_polynomial_count
        .checked_add(1)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox challenge-tail count overflowed"))
}

fn setup_proof_lnp_tbox_z34_seed_profile_value(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<Value> {
    Ok(json!({
        "source": "LaZer lnp_tbox_check_z34 tB seed-material split",
        "seedCoefficientCount": SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
        "seedPolynomialCountPerVector": setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?,
        "messagePolynomialCount": setup_proof_lnp_tbox_message_polynomial_count(layout)?,
        "ty3PolynomialCount": setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?,
        "ty4PolynomialCount": setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?,
        "tbetaPolynomialCount": 1,
        "tgPolynomialCount": layout.h_polynomial_count,
        "lowerQuadraticTailPolynomialCount": 1,
        "challengeTailPolynomialCount": setup_proof_lnp_tbox_challenge_tail_polynomial_count(layout)?,
        "seedMaterialEncoding": "canonical LaZer-style urandom3 ty3 || ty4 || tbeta residues with final one-bit padding",
        "challengeTailBinding": "canonical fixed-width tB tg || lower-quadratic-tail residues after tbeta are hash-bound into the lower-protocol challenge",
        "challengeProfile": setup_proof_lnp_tbox_z34_challenge_profile_value(layout)?,
        "normBoundProfile": setup_proof_lnp_tbox_z34_norm_bound_profile_value(layout)?,
    }))
}

fn setup_proof_lnp_tbox_z34_challenge_profile_value(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<Value> {
    Ok(json!({
        "source": "LaZer lnp_tbox_check_z34 challenge seed and brandom row-domain split",
        "challengeSeedByteCount": SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT,
        "challengeSeedDerivation": "SHAKE-derived seed over statement hash, relation commitment hash, proof family, tbox profile, and canonical ty3 || ty4 || tbeta seed material",
        "lowerProtocolChallengeDerivation": "setup LNP challenge coefficients are sampled from the lower-protocol challenge hash over statement hash, relation commitment hash, z34 seed-material hash, z34 challenge-seed hash, challenge-tail hash, and row-domain/hash material",
        "rowExpansion": {
            "sampler": "LaZer _brandom",
            "brandomK": SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K,
            "coefficientSet": [-1, 0, 1],
            "z3RowDomainStart": SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START,
            "z3RowDomainCount": SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
            "z3RowColumnCount": setup_proof_lnp_tbox_z34_row_column_count(
                layout,
                layout.z3_polynomial_count,
                "z3",
            )?,
            "z4RowDomainStart": SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START,
            "z4RowDomainCount": SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
            "z4RowColumnCount": setup_proof_lnp_tbox_z34_row_column_count(
                layout,
                layout.z4_polynomial_count,
                "z4",
            )?,
        },
        "status": "verifier-derived-row-expansion, hash binding, generated suffix challenge equations, and z3/z4 bounds are enforced",
    }))
}

fn setup_proof_lnp_tbox_z34_norm_bound_profile_value(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<Value> {
    Ok(json!({
        "source": "LaZer lnp-tbox-codegen.sage generated Bz3sqr and Bz4 formulas",
        "securityParameter": SETUP_PROOF_LNP_TBOX_Z34_SECURITY_PARAMETER,
        "tailBoundTDecimal": "1.64",
        "gaussianBaseStandardDeviationDecimal": "1.55",
        "measuredCoefficientCount": SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
        "z3Log2StandardDeviation": layout.z3_log2_standard_deviation,
        "z4Log2StandardDeviation": layout.z4_log2_standard_deviation,
        "z3L2SquaredBoundDecimal": setup_proof_lnp_tbox_z3_l2_squared_bound(layout)?.to_string(),
        "z4InfinityNormBoundDecimal": setup_proof_lnp_tbox_z4_infinity_norm_bound(layout)?.to_string(),
        "status": "verifier-enforced-for-lnp-check-z34-256-coefficient-window",
    }))
}

fn setup_proof_lnp_tbox_z3_l2_squared_bound(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<BigUint> {
    generated_lnp_tbox_z3_l2_squared_bound(layout.z3_log2_standard_deviation)
}

fn setup_proof_lnp_tbox_z4_infinity_norm_bound(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<BigUint> {
    generated_lnp_tbox_z4_infinity_norm_bound(layout.z4_log2_standard_deviation)
}

fn generated_lnp_tbox_z3_l2_squared_bound(
    log2_standard_deviation: usize,
) -> CanonicalResult<BigUint> {
    let doubled_exponent = log2_standard_deviation
        .checked_mul(2)
        .ok_or_else(|| setup_proof_error("setup proof LNP z3 bound exponent overflowed"))?;
    let seed_coefficient_count = u64::try_from(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS)
        .map_err(|_| setup_proof_error("setup proof LNP z3 seed coefficient count overflowed"))?;
    let numerator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * seed_coefficient_count,
    ) << doubled_exponent;
    let denominator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR,
    );

    Ok(numerator / denominator)
}

fn generated_lnp_tbox_z4_infinity_norm_bound(
    log2_standard_deviation: usize,
) -> CanonicalResult<BigUint> {
    let sqrt_two_kappa = integer_square_root(
        SETUP_PROOF_LNP_TBOX_Z34_SECURITY_PARAMETER
            .checked_mul(2)
            .ok_or_else(|| setup_proof_error("setup proof LNP z4 security parameter overflowed"))?,
    )?;
    let numerator = (BigUint::from(
        sqrt_two_kappa
            .checked_mul(SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR)
            .ok_or_else(|| setup_proof_error("setup proof LNP z4 bound numerator overflowed"))?,
    )) << log2_standard_deviation;
    let denominator = BigUint::from(SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR);

    Ok(numerator / denominator)
}

fn integer_square_root(value: u64) -> CanonicalResult<u64> {
    let mut root = 0_u64;
    while root
        .checked_add(1)
        .and_then(|candidate| candidate.checked_mul(candidate))
        .is_some_and(|square| square <= value)
    {
        root += 1;
    }
    if root.checked_mul(root) != Some(value) {
        return Err(setup_proof_error(
            "setup proof LNP tbox generated bound requires an exact integer square root",
        ));
    }

    Ok(root)
}

pub(super) fn derive_setup_proof_scalar_challenge(
    proof_family: &str,
    scalar_challenge_domain: &str,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    challenge_bits: usize,
) -> CanonicalResult<u64> {
    validate_hash_string(
        statement_hash_hex,
        "setupProofScalarChallenge.statementHash",
    )?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofScalarChallenge.relationCommitmentHash",
    )?;
    if challenge_bits == 0 || challenge_bits > u64::BITS as usize {
        return Err(setup_proof_error(
            "setup proof scalar challenge bit count must be in 1..=64",
        ));
    }

    let challenge_coefficients = derive_setup_proof_challenge_coefficients(
        proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
        SETUP_PROOF_LNP_PROOF_RING_DEGREE,
    )?;
    let mut encoded_challenge = Vec::with_capacity(challenge_coefficients.len() * 8);
    for coefficient in challenge_coefficients {
        encoded_challenge.extend_from_slice(&coefficient.to_le_bytes());
    }

    let byte_count = challenge_bits.div_ceil(8);
    let unused_high_bits = byte_count * 8 - challenge_bits;
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            scalar_challenge_domain,
            &[
                statement_hash_hex.as_bytes(),
                relation_commitment_hash_hex.as_bytes(),
                &encoded_challenge,
                &block_index_bytes,
            ],
        );
        let mut challenge_bytes = [0_u8; 8];
        challenge_bytes[..byte_count].copy_from_slice(&block[..byte_count]);
        if unused_high_bits > 0 {
            let kept_high_mask = 0xff_u8 >> unused_high_bits;
            challenge_bytes[byte_count - 1] &= kept_high_mask;
        }
        let challenge = u64::from_le_bytes(challenge_bytes);
        if challenge != 0 {
            return Ok(challenge);
        }

        block_index = block_index.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof scalar challenge block index overflowed")
        })?;
    }
}

fn setup_proof_lnp_tbox_proof_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10,
    )
    .expect("setup proof LNP tbox proof modulus is a fixed decimal integer")
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct SetupProofLnpTboxDecodedSummary {
    pub(crate) decoded_size_bytes: usize,
    pub(crate) t_b_coefficients: Vec<BigUint>,
    pub(crate) h_coefficients: Vec<BigUint>,
    pub(crate) t_a1_compressed_coefficients: Vec<BigUint>,
    pub(crate) challenge_coefficients: Vec<i64>,
    pub(crate) hint_coefficients: Vec<LnpTboxHintCoefficient>,
    pub(crate) z1_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z21_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z3_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z4_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z3_l2_squared: BigUint,
    pub(crate) z4_infinity_norm: BigUint,
    pub(crate) z34_seed_material_hash: String,
    pub(crate) z34_challenge_seed_hex: String,
    pub(crate) z34_challenge_seed_hash: String,
    pub(crate) z34_challenge_tail_hash: String,
    pub(crate) z34_challenge_row_domain_hash: String,
    pub(crate) z34_challenge_z3_row_set_hash: String,
    pub(crate) z34_challenge_z4_row_set_hash: String,
    pub(crate) tbox_lower_protocol_challenge_hash: String,
    pub(crate) z34_z3_check_window_hash: String,
    pub(crate) z34_z4_check_window_hash: String,
}

pub(crate) struct SetupProofLnpTboxChallengeMaterial {
    pub(crate) challenge_coefficients: Vec<i64>,
    pub(crate) lower_protocol_challenge_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct LnpTboxHintCoefficient {
    pub(crate) first_bit: bool,
    pub(crate) second_bit: bool,
    pub(crate) extension_zero_count: usize,
    pub(crate) value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct LnpTboxGaussianCoefficient {
    pub(crate) unary_ones: usize,
    pub(crate) low_bits: u64,
    pub(crate) low_bit_count: usize,
    pub(crate) value: i128,
}

pub(super) fn setup_proof_challenge_domain_hash(setup_profile_id: &str) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &setup_proof_challenge_domain_value(setup_profile_id),
    )
}

pub(super) fn setup_proof_challenge_domain_value(setup_profile_id: &str) -> Value {
    json!({
        "objectType": "SetupProofChallengeDomain",
        "objectVersion": 1,
        "purpose": SETUP_PROOF_CHALLENGE_DOMAIN_PURPOSE,
        "setupProfileId": setup_profile_id,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
        "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
        "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        "challengeDifferenceInvertibilityAccounting": challenge_difference_invertibility_accounting_value().expect("fixed setup proof challenge accounting is valid"),
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "randomOracleModel": "repo-owned Fiat-Shamir/QROM accounting is accepted by the setup proof accounting certificate",
    })
}

pub(super) fn setup_proof_record_binding_value(
    setup_profile_id: &str,
    setup_proof_profile_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofRecordBinding",
        "objectVersion": 1,
        "setupProfileId": setup_profile_id,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofProfileHash": setup_proof_profile_hash,
        "proofSystem": "fixed-lnp-linear-relation-subset",
        "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
        "challengeDomainHash": setup_proof_challenge_domain_hash(setup_profile_id)?,
        "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
        "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        "challengeDifferenceInvertibilityAccounting": challenge_difference_invertibility_accounting_value()?,
        "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
        "proofSerialization": SETUP_PROOF_SERIALIZATION,
        "proofByteDecoder": SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER,
        "privateVssShareTboxParameterProfileHash": private_vss_share_lnp_tbox_parameter_profile_hash()?,
        "sameSecretTboxParameterProfileHash": same_secret_lnp_tbox_parameter_profile_hash()?,
        "publicKeyShareTboxParameterProfileHash": public_key_share_lnp_tbox_parameter_profile_hash()?,
        "relinearizationKeyShareTboxParameterProfileHash": relinearization_key_share_lnp_tbox_parameter_profile_hash()?,
        "galoisKeyShareTboxParameterProfileHash": galois_key_share_lnp_tbox_parameter_profile_hash()?,
        "proofBytesAcceptedStatus": "private-vss-same-secret-public-key-share-relinearization-and-galois-proof-bytes-accepted-for-setup-proof-accounting",
    }))
}

pub(super) fn verify_setup_proof_record_binding(
    value: &Value,
    setup_profile_id: &str,
    setup_proof_profile_hash: &str,
) -> CanonicalResult<()> {
    let expected = setup_proof_record_binding_value(setup_profile_id, setup_proof_profile_hash)?;
    if value != &expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof record binding must match the fixed setup-proof profile and challenge domain",
        ));
    }

    Ok(())
}

pub(crate) fn setup_proof_material_transport_hashes(
    proof_family: &str,
    chunks: &[Vec<u8>],
    chunk_size_bytes: u64,
) -> CanonicalResult<SetupProofMaterialTransportHashes> {
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
        return Err(setup_proof_error(
            "setup proof material proof family is not in the fixed setup-proof profile",
        ));
    }
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size must be positive",
        ));
    }
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material transport requires at least one chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |accumulator, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material contains a short non-final chunk",
                    ));
                }
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunk length does not fit u64",
                    )
                })?;
                accumulator.checked_add(chunk_length).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material byte length overflowed",
                    )
                })
            })?;

    let full_object_hash =
        setup_proof_material_full_object_hash(proof_family, total_byte_length, chunks)?;
    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        chunk_hashes.push(setup_proof_material_chunk_hash(
            proof_family,
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_root = setup_proof_material_chunk_manifest_root(
        proof_family,
        chunk_size_bytes,
        u64::try_from(chunks.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk count does not fit u64",
            )
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(SetupProofMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

pub(crate) fn setup_proof_material_reference_root(
    input: SetupProofMaterialReferenceInput<'_>,
) -> CanonicalResult<String> {
    validate_hash_string(input.statement_hash_hex, "setupProofMaterial.statementHash")?;
    validate_hash_string(
        input.relation_commitment_hash_hex,
        "setupProofMaterial.relationCommitmentHash",
    )?;
    validate_hash_string(
        input.tbox_commitment_prefix_hash,
        "setupProofMaterial.tboxCommitmentPrefixHash",
    )?;
    validate_hash_string(input.proof_bytes_hash, "setupProofMaterial.proofBytesHash")?;
    validate_hash_string(
        &input.transport_hashes.full_object_hash,
        "setupProofMaterial.fullObjectHash",
    )?;
    validate_hash_string(
        &input.transport_hashes.chunk_root,
        "setupProofMaterial.chunkRoot",
    )?;
    for (chunk_index, chunk_hash) in input.transport_hashes.chunk_hashes.iter().enumerate() {
        validate_hash_string(
            chunk_hash,
            &format!("setupProofMaterial.chunkHashes[{chunk_index}]"),
        )?;
    }

    derive_protocol_hash(
        "SetupProofMaterialRoot",
        &json!({
            "objectType": "SetupProofMaterialReference",
            "objectVersion": 1,
            "setupProfileId": input.setup_profile_id,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": input.proof_family,
            "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
            "trusteeIdentity": input.trustee_identity,
            "trusteeRosterPosition": input.trustee_roster_position,
            "statementHash": input.statement_hash_hex,
            "relationCommitmentHash": input.relation_commitment_hash_hex,
            "tboxCommitmentPrefixHash": input.tbox_commitment_prefix_hash,
            "proofSizeBytes": input.proof_size_bytes,
            "proofBytesHash": input.proof_bytes_hash,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": input.transport_hashes.chunk_hashes.len(),
            "totalByteLength": input.transport_hashes.total_byte_length,
            "fullObjectHash": input.transport_hashes.full_object_hash,
            "chunkRoot": input.transport_hashes.chunk_root,
            "chunkHashes": input.transport_hashes.chunk_hashes,
        }),
    )
}

fn setup_proof_material_full_object_hash(
    proof_family: &str,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    append_bytes_to_hasher(
        &mut hasher,
        b"sealed-lattice/setup/proof-material/full-object-v1",
    )?;
    append_bytes_to_hasher(&mut hasher, proof_family.as_bytes())?;
    let mut length = Vec::new();
    append_varuint(&mut length, total_byte_length);
    hasher.update(&length);
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut output = [0_u8; 64];
    hasher.finalize_xof().read(&mut output);

    Ok(to_hex(&output))
}

fn setup_proof_material_chunk_hash(
    proof_family: &str,
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    validate_hash_string(full_object_hash, "setupProofMaterial.fullObjectHash")?;
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk index does not fit u64",
            )
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/proof-material/chunk-v1",
        &[
            proof_family.as_bytes(),
            full_object_hash.as_bytes(),
            &chunk_index_bytes,
            chunk,
        ],
    ))
}

fn setup_proof_material_chunk_manifest_root(
    proof_family: &str,
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupProofChunkManifestRoot",
        &json!({
            "objectType": SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": proof_family,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
}

fn append_bytes_to_hasher(hasher: &mut Shake256, value: &[u8]) -> CanonicalResult<()> {
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, value);
    hasher.update(&encoded);

    Ok(())
}

pub(super) fn challenge_difference_invertibility_accounting_value() -> CanonicalResult<Value> {
    let proof_modulus = setup_proof_lnp_tbox_proof_modulus();
    let challenge_coefficient_bound = BigUint::from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND);
    let difference_coefficient_bound = &challenge_coefficient_bound * BigUint::from(2_u32);
    let lnp_bound_left =
        BigUint::from(4_u32) * &challenge_coefficient_bound * &challenge_coefficient_bound;
    if lnp_bound_left >= proof_modulus {
        return Err(setup_proof_error(
            "setup proof challenge coefficient bound does not satisfy the LNP22 invertibility condition",
        ));
    }

    Ok(json!({
        "objectType": "SetupProofChallengeDifferenceInvertibilityAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofRing": "Z_qproof[X]/(X^d+1)",
        "proofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "proofModulusDecimal": proof_modulus.to_string(),
        "proofModulusBitCount": proof_modulus.bits(),
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "challengeDifferenceCoefficientBound": difference_coefficient_bound.to_string(),
        "condition": "4 * challengeCoefficientBound^2 < proofModulus",
        "conditionLeftDecimal": lnp_bound_left.to_string(),
        "conditionRightDecimal": proof_modulus.to_string(),
        "conditionSatisfied": true,
        "referenceRows": [
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "Section 2.7 Challenge Space",
                    "Appendix A, Theorem A.2 knowledge soundness"
                ],
            }
        ],
        "status": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
    }))
}

fn challenge_audit_statement_hash(proof_family: &str) -> String {
    hash512_hex(
        "sealed-lattice/collective-bgv-setup/challenge-audit-statement-v1",
        &[proof_family.as_bytes()],
    )
}

fn challenge_audit_relation_commitment_hash(proof_family: &str) -> String {
    hash512_hex(
        "sealed-lattice/collective-bgv-setup/challenge-audit-relation-commitment-v1",
        &[proof_family.as_bytes()],
    )
}

fn sampled_challenge_coefficients(coefficients: &[i64], sample_positions: &[usize]) -> Vec<Value> {
    sample_positions
        .iter()
        .map(|coefficient_position| {
            json!({
                "coefficientPosition": coefficient_position,
                "coefficientValue": coefficients[*coefficient_position],
            })
        })
        .collect()
}

fn subtract_centered_coefficients(left: &[i64], right: &[i64]) -> CanonicalResult<Vec<i64>> {
    if left.len() != right.len() {
        return Err(setup_proof_error(
            "setup proof challenge difference requires equal-length coefficient vectors",
        ));
    }

    left.iter()
        .zip(right)
        .map(|(left_coefficient, right_coefficient)| {
            left_coefficient
                .checked_sub(*right_coefficient)
                .ok_or_else(|| setup_proof_error("setup proof challenge difference overflowed"))
        })
        .collect()
}

fn centered_coefficient_infinity_norm(coefficients: &[i64]) -> u64 {
    coefficients
        .iter()
        .map(|coefficient| coefficient.unsigned_abs())
        .max()
        .unwrap_or(0)
}

fn centered_polynomial_is_invertible_mod_negacyclic(
    coefficients: &[i64],
    ring_degree: usize,
    modulus: &BigUint,
) -> CanonicalResult<bool> {
    if coefficients.len() != ring_degree {
        return Err(setup_proof_error(
            "setup proof challenge polynomial length does not match the proof ring degree",
        ));
    }
    let polynomial = centered_coefficients_to_modular_polynomial(coefficients, modulus);
    if polynomial.is_empty() {
        return Ok(false);
    }

    let ring_polynomial = negacyclic_modulus_polynomial(ring_degree);
    let greatest_common_divisor =
        modular_polynomial_greatest_common_divisor(polynomial, ring_polynomial, modulus)?;
    Ok(greatest_common_divisor.len() == 1 && greatest_common_divisor[0].is_one())
}

fn centered_coefficients_to_modular_polynomial(
    coefficients: &[i64],
    modulus: &BigUint,
) -> Vec<BigUint> {
    let mut polynomial = coefficients
        .iter()
        .map(|coefficient| {
            if *coefficient >= 0 {
                BigUint::from(*coefficient as u64) % modulus
            } else {
                let magnitude = BigUint::from(coefficient.unsigned_abs()) % modulus;
                if magnitude.is_zero() {
                    BigUint::zero()
                } else {
                    modulus.clone() - magnitude
                }
            }
        })
        .collect::<Vec<_>>();
    trim_modular_polynomial(&mut polynomial);

    polynomial
}

fn negacyclic_modulus_polynomial(ring_degree: usize) -> Vec<BigUint> {
    let mut polynomial = vec![BigUint::zero(); ring_degree + 1];
    polynomial[0] = BigUint::one();
    polynomial[ring_degree] = BigUint::one();
    polynomial
}

fn modular_polynomial_greatest_common_divisor(
    mut left: Vec<BigUint>,
    mut right: Vec<BigUint>,
    modulus: &BigUint,
) -> CanonicalResult<Vec<BigUint>> {
    trim_modular_polynomial(&mut left);
    trim_modular_polynomial(&mut right);

    while !right.is_empty() {
        let remainder = modular_polynomial_remainder(left, &right, modulus)?;
        left = right;
        right = remainder;
    }

    if left.is_empty() {
        return Ok(left);
    }
    let leading_inverse = modular_inverse(
        left.last()
            .expect("non-empty modular polynomial has a leading coefficient"),
        modulus,
    )?;
    for coefficient in &mut left {
        *coefficient = (coefficient.clone() * &leading_inverse) % modulus;
    }
    trim_modular_polynomial(&mut left);

    Ok(left)
}

fn modular_polynomial_remainder(
    mut numerator: Vec<BigUint>,
    denominator: &[BigUint],
    modulus: &BigUint,
) -> CanonicalResult<Vec<BigUint>> {
    let mut denominator = denominator.to_vec();
    trim_modular_polynomial(&mut denominator);
    if denominator.is_empty() {
        return Err(setup_proof_error(
            "setup proof modular polynomial division by zero",
        ));
    }

    let denominator_degree = denominator.len() - 1;
    let denominator_leading_inverse = modular_inverse(
        denominator
            .last()
            .expect("non-empty denominator has a leading coefficient"),
        modulus,
    )?;

    trim_modular_polynomial(&mut numerator);
    while !numerator.is_empty() && numerator.len() >= denominator.len() {
        let numerator_degree = numerator.len() - 1;
        let shift = numerator_degree - denominator_degree;
        let scale = (numerator[numerator_degree].clone() * &denominator_leading_inverse) % modulus;
        if !scale.is_zero() {
            for (denominator_index, denominator_coefficient) in denominator.iter().enumerate() {
                let target_index = shift + denominator_index;
                let product = (&scale * denominator_coefficient) % modulus;
                let current = numerator[target_index].clone();
                numerator[target_index] = if current >= product {
                    current - product
                } else {
                    (current + modulus.clone()) - product
                };
                numerator[target_index] = numerator[target_index].clone() % modulus;
            }
        }
        trim_modular_polynomial(&mut numerator);
    }

    Ok(numerator)
}

fn modular_inverse(value: &BigUint, modulus: &BigUint) -> CanonicalResult<BigUint> {
    if value.is_zero() {
        return Err(setup_proof_error(
            "setup proof modular inverse of zero is undefined",
        ));
    }
    let exponent = modulus - BigUint::from(2_u32);

    Ok(value.modpow(&exponent, modulus))
}

fn trim_modular_polynomial(polynomial: &mut Vec<BigUint>) {
    while polynomial.last().is_some_and(BigUint::is_zero) {
        polynomial.pop();
    }
}

pub(super) fn setup_proof_challenge_space_audit_value(
    ring_degree: usize,
) -> CanonicalResult<Value> {
    let sample_positions = challenge_sample_positions(ring_degree)?;
    let proof_modulus = setup_proof_lnp_tbox_proof_modulus();
    let mut family_challenges = Vec::new();
    for proof_family in SETUP_PROOF_FAMILIES {
        let statement_hash = challenge_audit_statement_hash(proof_family);
        let relation_commitment_hash = challenge_audit_relation_commitment_hash(proof_family);
        let challenge_coefficients = derive_setup_proof_challenge_coefficients(
            proof_family,
            &statement_hash,
            &relation_commitment_hash,
            ring_degree,
        )?;
        let samples = sampled_challenge_coefficients(&challenge_coefficients, &sample_positions);
        family_challenges.push((
            *proof_family,
            statement_hash,
            relation_commitment_hash,
            challenge_coefficients,
            samples,
        ));
    }

    let mut sampled_difference_checks = Vec::new();
    for left_index in 0..family_challenges.len() {
        for right_index in (left_index + 1)..family_challenges.len() {
            let left = &family_challenges[left_index];
            let right = &family_challenges[right_index];
            let difference_coefficients = subtract_centered_coefficients(&left.3, &right.3)?;
            let coefficient_infinity_norm =
                centered_coefficient_infinity_norm(&difference_coefficients);
            let difference_samples =
                sampled_challenge_coefficients(&difference_coefficients, &sample_positions);
            sampled_difference_checks.push(json!({
                "leftProofFamily": left.0,
                "rightProofFamily": right.0,
                "coefficientInfinityNorm": coefficient_infinity_norm,
                "differenceCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND * 2,
                "sampledDifferenceCoefficients": difference_samples,
                "invertibleOverProofRing": centered_polynomial_is_invertible_mod_negacyclic(
                    &difference_coefficients,
                    ring_degree,
                    &proof_modulus,
                )?,
            }));
        }
    }

    let family_samples = family_challenges
        .iter()
        .map(
            |(
                proof_family,
                statement_hash,
                relation_commitment_hash,
                _challenge_coefficients,
                samples,
            )| {
                json!({
                    "proofFamily": proof_family,
                    "statementHash": statement_hash,
                    "relationCommitmentHash": relation_commitment_hash,
                    "sampledCoefficients": samples,
                })
            },
        )
        .collect::<Vec<_>>();

    Ok(json!({
        "objectType": "SetupProofChallengeSpaceAudit",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": ring_degree,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": u64::try_from(ring_degree)
            .map_err(|_| setup_proof_error("setup proof challenge audit ring degree does not fit u64"))?
            .checked_mul(SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE as u64)
            .ok_or_else(|| setup_proof_error("setup proof challenge encoded bit count overflowed"))?,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        "challengeDifferenceInvertibilityAccounting": challenge_difference_invertibility_accounting_value()?,
        "familySamples": family_samples,
        "sampledDifferenceChecks": sampled_difference_checks,
    }))
}

pub(super) fn setup_proof_challenge_space_audit_hash(
    namespace: &str,
    ring_degree: usize,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        namespace,
        &setup_proof_challenge_space_audit_value(ring_degree)?,
    )
}

pub(super) fn derive_setup_proof_challenge_coefficients(
    proof_family: &str,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    ring_degree: usize,
) -> CanonicalResult<Vec<i64>> {
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge proof family is not in the fixed setup-proof profile",
        ));
    }
    validate_hash_string(statement_hash_hex, "setupProofChallenge.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofChallenge.relationCommitmentHash",
    )?;
    let sampler = SetupProofChallengeSampler::new(
        proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
    );
    derive_setup_proof_challenge_coefficients_from_sampler(proof_family, ring_degree, sampler)
}

pub(crate) fn derive_setup_proof_lnp_tbox_challenge_from_prefix(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
) -> CanonicalResult<SetupProofLnpTboxChallengeMaterial> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(
        statement_hash_hex,
        "setupProofLnpTboxChallenge.statementHash",
    )?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTboxChallenge.relationCommitmentHash",
    )?;
    let mut reader = LnpBitReader::new(prefix_bytes);
    let t_b_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "tB",
    )?;
    let z34_seed_material = setup_proof_lnp_tbox_z34_seed_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &t_b_coefficients,
    )?;
    let h_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "h",
    )?;
    verify_lnp_tbox_h_forced_zero_coefficients(&h_coefficients, layout.proof_ring_degree)?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let compressed_modulus = BigUint::one() << compressed_bit_count;
    decode_uniform_polyvec(
        &mut reader,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        &compressed_modulus,
        compressed_bit_count,
        "tA1",
    )?;
    reader.finish_exact_end("setup proof LNP tbox prefix")?;

    setup_proof_lnp_tbox_challenge_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &z34_seed_material,
    )
}

fn setup_proof_lnp_tbox_challenge_material(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    z34_seed_material: &SetupProofLnpTboxZ34SeedMaterial,
) -> CanonicalResult<SetupProofLnpTboxChallengeMaterial> {
    let lower_protocol_challenge_hash = hash512_hex(
        SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_DOMAIN,
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            z34_seed_material.seed_material_hash.as_bytes(),
            z34_seed_material.challenge_seed_hash.as_bytes(),
            z34_seed_material.challenge_tail_hash.as_bytes(),
            z34_seed_material.challenge_row_domain_hash.as_bytes(),
            z34_seed_material.challenge_z3_row_set_hash.as_bytes(),
            z34_seed_material.challenge_z4_row_set_hash.as_bytes(),
        ],
    );
    let sampler = SetupProofChallengeSampler::new_lnp_tbox_lower_protocol(
        layout.proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &lower_protocol_challenge_hash,
    );
    let challenge_coefficients = derive_setup_proof_challenge_coefficients_from_sampler(
        layout.proof_family,
        layout.proof_ring_degree,
        sampler,
    )?;

    Ok(SetupProofLnpTboxChallengeMaterial {
        challenge_coefficients,
        lower_protocol_challenge_hash,
    })
}

fn derive_setup_proof_challenge_coefficients_from_sampler(
    proof_family: &str,
    ring_degree: usize,
    mut sampler: SetupProofChallengeSampler,
) -> CanonicalResult<Vec<i64>> {
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge proof family is not in the fixed setup-proof profile",
        ));
    }
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge ring degree must be even and at least two",
        ));
    }

    let half_degree = ring_degree / 2;
    let mut coefficients = vec![0_i64; ring_degree];
    for coefficient in coefficients.iter_mut().take(half_degree) {
        let sample = sampler.next_bounded_sample(
            SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .expect("fixed challenge modulus fits u64"),
            3,
        )?;
        *coefficient = i64::try_from(sample).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge sample does not fit i64",
            )
        })? - i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
            .expect("fixed challenge coefficient bound fits i64");
    }
    coefficients[half_degree] = 0;
    for coefficient_position in (half_degree + 1)..ring_degree {
        coefficients[coefficient_position] = -coefficients[ring_degree - coefficient_position];
    }

    Ok(coefficients)
}

pub(super) fn setup_proof_lnp_tbox_byte_layout_profile_value() -> Value {
    json!({
        "objectType": "SetupProofLnpTboxByteLayoutProfile",
        "objectVersion": 1,
        "decoder": SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "challengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "challengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "fieldOrder": [
            "tB full-sized polynomial vector",
            "h full-sized polynomial vector",
            "tA1 compressed polynomial vector",
            "c autostable challenge polynomial",
            "hint decompression hint polynomial vector",
            "z1 Gaussian response polynomial vector",
            "z21 Gaussian response polynomial vector",
            "z3 Gaussian response polynomial vector",
            "z4 Gaussian response polynomial vector",
            "final one bit and zero padding"
        ],
        "uniformResidueEncoding": "little-endian fixed-bit coder_enc_urandom with strict residue range",
        "currentPrefixBinding": "deterministic statement-and-relation binding seed over proof family, tbox profile hash, statement hash, and encoded relation commitments",
        "currentZ34SeedMaterial": "verifier extracts LaZer lnp_tbox_check_z34 ty3, ty4, and tbeta seed material from tB using the fixed tB message-prefix count and canonical urandom3 encoding",
        "currentZ34ChallengeBinding": "verifier derives the 32-byte check_z34 challenge seed from the statement hash, relation commitment hash, proof family, tbox profile, and canonical ty3 || ty4 || tbeta encoding, hashes the current tB challenge-tail residues after tbeta, expands LaZer brandom k=1 ternary R/Rprime rows with R domains 0..255 and Rprime domains 256..511 over the declared z3/z4 row widths, hashes the row-domain schedule plus concrete row sets, and samples the proof-byte challenge polynomial from the resulting lower-protocol challenge hash",
        "hintEncoding": "LaZer coder_enc_ghint coefficient code with signed verifier-side value decoding",
        "gaussianEncoding": "LaZer coder_enc_grandom signed unary quotient plus two's-complement low bits with verifier-side signed value decoding",
        "currentSuffixAccounting": "verifier hashes the signed z3/z4 check-window values, computes z3 L2 squared and z4 infinity norm over the LaZer check_z34 256-coefficient window, rejects values above generated Bz3sqr/Bz4 bounds, checks generated z1/z21 Gaussian L2 bounds, checks generated hint ranges, and enforces the generated lower-protocol tbox suffix against the statement-and-relation-bound prefix",
        "parameterStatus": "family-specific generated tbox dimensions and proof modulus are verifier-pinned for the setup proof-byte profile",
    })
}

#[allow(
    dead_code,
    reason = "entry point for the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) fn verify_setup_proof_lnp_tbox_proof_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<SetupProofLnpTboxDecodedSummary> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(statement_hash_hex, "setupProofLnpTbox.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTbox.relationCommitmentHash",
    )?;

    let mut reader = LnpBitReader::new(proof_bytes);
    let t_b_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "tB",
    )?;
    let z34_seed_material = setup_proof_lnp_tbox_z34_seed_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &t_b_coefficients,
    )?;
    let challenge_material = setup_proof_lnp_tbox_challenge_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &z34_seed_material,
    )?;
    let h_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "h",
    )?;
    verify_lnp_tbox_h_forced_zero_coefficients(&h_coefficients, layout.proof_ring_degree)?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let compressed_modulus = BigUint::one() << compressed_bit_count;
    let t_a1_compressed_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        &compressed_modulus,
        compressed_bit_count,
        "tA1",
    )?;
    let decoded_challenge = decode_centered_challenge_polynomial(&mut reader, layout)?;
    if decoded_challenge != challenge_material.challenge_coefficients {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox challenge does not match the z34-bound lower-protocol transcript sampler",
        ));
    }
    let hint_coefficients = decode_hint_polyvec(
        &mut reader,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    verify_lnp_tbox_hint_coefficients(&hint_coefficients)?;
    let z1_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z1_polynomial_count,
        layout.proof_ring_degree,
        layout.z1_log2_standard_deviation,
        "z1",
    )?;
    verify_lnp_tbox_gaussian_l2_bound(
        layout,
        &z1_coefficients,
        layout.z1_log2_standard_deviation,
        "z1",
    )?;
    let z21_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z21_polynomial_count,
        layout.proof_ring_degree,
        layout.z21_log2_standard_deviation,
        "z21",
    )?;
    verify_lnp_tbox_gaussian_l2_bound(
        layout,
        &z21_coefficients,
        layout.z21_log2_standard_deviation,
        "z21",
    )?;
    let z3_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z3_polynomial_count,
        layout.proof_ring_degree,
        layout.z3_log2_standard_deviation,
        "z3",
    )?;
    let z34_check_coefficient_count = setup_proof_lnp_tbox_z34_check_coefficient_count(layout)?;
    let z3_l2_squared = gaussian_l2_squared(gaussian_coefficient_prefix(
        &z3_coefficients,
        z34_check_coefficient_count,
        "z3",
    )?);
    let z34_z3_check_window_hash = setup_proof_lnp_tbox_z34_check_window_hash(
        layout,
        "z3",
        gaussian_coefficient_prefix(&z3_coefficients, z34_check_coefficient_count, "z3")?,
    )?;
    let z4_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z4_polynomial_count,
        layout.proof_ring_degree,
        layout.z4_log2_standard_deviation,
        "z4",
    )?;
    let z4_infinity_norm = gaussian_infinity_norm(gaussian_coefficient_prefix(
        &z4_coefficients,
        z34_check_coefficient_count,
        "z4",
    )?);
    let z34_z4_check_window_hash = setup_proof_lnp_tbox_z34_check_window_hash(
        layout,
        "z4",
        gaussian_coefficient_prefix(&z4_coefficients, z34_check_coefficient_count, "z4")?,
    )?;
    verify_lnp_tbox_z34_norm_bounds(layout, &z3_l2_squared, &z4_infinity_norm)?;
    reader.finish_with_lazer_padding()?;
    verify_generated_lnp_tbox_suffix_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        proof_bytes,
    )?;

    Ok(SetupProofLnpTboxDecodedSummary {
        decoded_size_bytes: proof_bytes.len(),
        t_b_coefficients,
        h_coefficients,
        t_a1_compressed_coefficients,
        challenge_coefficients: decoded_challenge,
        hint_coefficients,
        z1_coefficients,
        z21_coefficients,
        z3_coefficients,
        z4_coefficients,
        z3_l2_squared,
        z4_infinity_norm,
        z34_seed_material_hash: z34_seed_material.seed_material_hash,
        z34_challenge_seed_hex: z34_seed_material.challenge_seed_hex,
        z34_challenge_seed_hash: z34_seed_material.challenge_seed_hash,
        z34_challenge_tail_hash: z34_seed_material.challenge_tail_hash,
        z34_challenge_row_domain_hash: z34_seed_material.challenge_row_domain_hash,
        z34_challenge_z3_row_set_hash: z34_seed_material.challenge_z3_row_set_hash,
        z34_challenge_z4_row_set_hash: z34_seed_material.challenge_z4_row_set_hash,
        tbox_lower_protocol_challenge_hash: challenge_material.lower_protocol_challenge_hash,
        z34_z3_check_window_hash,
        z34_z4_check_window_hash,
    })
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn validate_lnp_tbox_layout(layout: &SetupProofLnpTboxLayout) -> CanonicalResult<()> {
    if !SETUP_PROOF_FAMILIES.contains(&layout.proof_family) {
        return Err(setup_proof_error(
            "setup proof LNP tbox layout proof family is not in the fixed profile",
        ));
    }
    if !matches!(layout.proof_ring_degree, 64 | 128) {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree must be 64 or 128",
        ));
    }
    if layout.proof_ring_degree != SETUP_PROOF_LNP_PROOF_RING_DEGREE {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree does not match the fixed first-profile challenge shape",
        ));
    }
    let seed_polynomial_count = setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?;
    setup_proof_lnp_tbox_message_polynomial_count(layout)?;
    let challenge_modulus = setup_proof_challenge_modulus();
    if layout.proof_modulus <= challenge_modulus {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof modulus must be larger than the challenge modulus",
        ));
    }
    if layout.proof_modulus.bits() > layout.proof_modulus_bit_count as u64 {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof modulus does not fit its declared bit count",
        ));
    }
    if layout.proof_modulus_bit_count == 0
        || layout.compression_dropped_bits >= layout.proof_modulus_bit_count
    {
        return Err(setup_proof_error(
            "setup proof LNP tbox compression parameters are invalid",
        ));
    }
    if layout.h_polynomial_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox h polynomial count must be non-zero",
        ));
    }
    if layout.z3_polynomial_count != seed_polynomial_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3 polynomial count must equal the LaZer 256-coefficient check vector width",
        ));
    }
    if layout.z4_polynomial_count != seed_polynomial_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox z4 polynomial count must equal the LaZer 256-coefficient check vector width",
        ));
    }
    if layout.t_a1_polynomial_count != layout.hint_polynomial_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox tA1 and hint polynomial counts must match the AB-DLOP commitment row count",
        ));
    }
    for (name, count) in [
        ("tB", layout.t_b_polynomial_count),
        ("h", layout.h_polynomial_count),
        ("tA1", layout.t_a1_polynomial_count),
        ("hint", layout.hint_polynomial_count),
        ("z1", layout.z1_polynomial_count),
        ("z21", layout.z21_polynomial_count),
        ("z3", layout.z3_polynomial_count),
        ("z4", layout.z4_polynomial_count),
    ] {
        if count == 0 {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} polynomial count must be non-zero",
            )));
        }
    }
    let z34_check_coefficient_count = setup_proof_lnp_tbox_z34_check_coefficient_count(layout)?;
    for (name, count) in [
        ("z3", layout.z3_polynomial_count),
        ("z4", layout.z4_polynomial_count),
    ] {
        let coefficient_count = count.checked_mul(layout.proof_ring_degree).ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP tbox {name} coefficient count overflowed"
            ))
        })?;
        if coefficient_count < z34_check_coefficient_count {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} vector is too small for the z3/z4 check window",
            )));
        }
    }
    for (name, bit_count) in [
        ("z1", layout.z1_log2_standard_deviation),
        ("z21", layout.z21_log2_standard_deviation),
        ("z3", layout.z3_log2_standard_deviation),
        ("z4", layout.z4_log2_standard_deviation),
    ] {
        if bit_count > 61 {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} standard-deviation bit count is outside the supported range",
            )));
        }
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_uniform_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    modulus: &BigUint,
    bit_count: usize,
    field_name: &str,
) -> CanonicalResult<Vec<BigUint>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox coefficient count overflowed"))?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let value = reader.read_big_uint_le_bits(bit_count)?;
        if &value >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("setup proof LNP tbox {field_name} residue is not canonical"),
            ));
        }
        coefficients.push(value);
    }

    Ok(coefficients)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupProofLnpTboxZ34SeedMaterial {
    seed_material_hash: String,
    challenge_seed_hex: String,
    challenge_seed_hash: String,
    challenge_tail_hash: String,
    challenge_row_domain_hash: String,
    challenge_z3_row_set_hash: String,
    challenge_z4_row_set_hash: String,
}

fn setup_proof_lnp_tbox_z34_seed_material(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    t_b_coefficients: &[BigUint],
) -> CanonicalResult<SetupProofLnpTboxZ34SeedMaterial> {
    validate_hash_string(statement_hash_hex, "setupProofLnpTboxZ34.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTboxZ34.relationCommitmentHash",
    )?;
    let message_polynomial_count = setup_proof_lnp_tbox_message_polynomial_count(layout)?;
    let seed_polynomial_count = setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?;
    let expected_coefficient_count = layout
        .t_b_polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox tB coefficient count overflowed"))?;
    if t_b_coefficients.len() != expected_coefficient_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox tB coefficient count does not match the layout",
        ));
    }

    let ty3_start = message_polynomial_count;
    let ty4_start = ty3_start
        .checked_add(seed_polynomial_count)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox ty4 offset overflowed"))?;
    let tbeta_start = ty4_start
        .checked_add(seed_polynomial_count)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox beta offset overflowed"))?;
    let challenge_tail_start = tbeta_start.checked_add(1).ok_or_else(|| {
        setup_proof_error("setup proof LNP tbox challenge-tail offset overflowed")
    })?;
    let challenge_tail_polynomial_count =
        setup_proof_lnp_tbox_challenge_tail_polynomial_count(layout)?;
    let ty3_coefficients = t_b_polynomial_slice(
        t_b_coefficients,
        layout.proof_ring_degree,
        ty3_start,
        seed_polynomial_count,
    )?;
    let ty4_coefficients = t_b_polynomial_slice(
        t_b_coefficients,
        layout.proof_ring_degree,
        ty4_start,
        seed_polynomial_count,
    )?;
    let tbeta_coefficients =
        t_b_polynomial_slice(t_b_coefficients, layout.proof_ring_degree, tbeta_start, 1)?;
    let challenge_tail_coefficients = t_b_polynomial_slice(
        t_b_coefficients,
        layout.proof_ring_degree,
        challenge_tail_start,
        challenge_tail_polynomial_count,
    )?;

    let seed_material_bytes = encode_setup_proof_lnp_tbox_z34_seed_material(
        layout,
        &[ty3_coefficients, ty4_coefficients, tbeta_coefficients],
    )?;
    let seed_material_hash = hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-seed-material-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            &seed_material_bytes,
        ],
    );
    let challenge_seed_bytes = setup_proof_lnp_tbox_z34_challenge_seed_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &seed_material_bytes,
    );
    let challenge_seed_hex = to_hex(&challenge_seed_bytes);
    let challenge_seed_hash = hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-challenge-seed-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            seed_material_hash.as_bytes(),
            &challenge_seed_bytes,
        ],
    );
    let challenge_tail_bytes =
        encode_setup_proof_lnp_tbox_z34_seed_material(layout, &[challenge_tail_coefficients])?;
    let challenge_tail_hash = hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-challenge-tail-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            seed_material_hash.as_bytes(),
            &challenge_tail_bytes,
        ],
    );
    let challenge_row_domain_hash =
        setup_proof_lnp_tbox_z34_challenge_row_domain_hash(layout, &challenge_seed_bytes)?;
    let challenge_z3_row_set_hash = setup_proof_lnp_tbox_z34_challenge_row_set_hash(
        layout,
        "z3",
        &challenge_seed_bytes,
        SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
        setup_proof_lnp_tbox_z34_row_column_count(layout, layout.z3_polynomial_count, "z3")?,
    )?;
    let challenge_z4_row_set_hash = setup_proof_lnp_tbox_z34_challenge_row_set_hash(
        layout,
        "z4",
        &challenge_seed_bytes,
        SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
        setup_proof_lnp_tbox_z34_row_column_count(layout, layout.z4_polynomial_count, "z4")?,
    )?;

    Ok(SetupProofLnpTboxZ34SeedMaterial {
        seed_material_hash,
        challenge_seed_hex,
        challenge_seed_hash,
        challenge_tail_hash,
        challenge_row_domain_hash,
        challenge_z3_row_set_hash,
        challenge_z4_row_set_hash,
    })
}

fn setup_proof_lnp_tbox_z34_challenge_seed_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    seed_material_bytes: &[u8],
) -> [u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT] {
    let seed = hash512(
        "sealed-lattice/setup/lnp-tbox-z34-challenge-seed-bytes-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            seed_material_bytes,
        ],
    );
    let mut challenge_seed_bytes = [0_u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT];
    challenge_seed_bytes
        .copy_from_slice(&seed[..SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT]);

    challenge_seed_bytes
}

fn setup_proof_lnp_tbox_z34_challenge_row_domain_hash(
    layout: &SetupProofLnpTboxLayout,
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
) -> CanonicalResult<String> {
    let row_domain_schedule = setup_proof_lnp_tbox_z34_row_domain_schedule_bytes()?;
    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-row-domain-schedule-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            challenge_seed_bytes,
            &row_domain_schedule,
        ],
    ))
}

fn setup_proof_lnp_tbox_z34_row_domain_schedule_bytes() -> CanonicalResult<Vec<u8>> {
    let mut encoded = Vec::new();
    for value in [
        SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K,
        SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64,
        SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64,
    ] {
        append_varuint(&mut encoded, value);
    }

    Ok(encoded)
}

fn setup_proof_lnp_tbox_z34_challenge_row_set_hash(
    layout: &SetupProofLnpTboxLayout,
    row_set_label: &str,
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
    row_domain_start: u64,
    row_domain_count: usize,
    row_column_count: usize,
) -> CanonicalResult<String> {
    let row_set_bytes = setup_proof_lnp_tbox_z34_challenge_row_set_bytes(
        challenge_seed_bytes,
        row_domain_start,
        row_domain_count,
        row_column_count,
    )?;
    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-row-set-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            row_set_label.as_bytes(),
            challenge_seed_bytes,
            &row_set_bytes,
        ],
    ))
}

fn setup_proof_lnp_tbox_z34_challenge_row_set_bytes(
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
    row_domain_start: u64,
    row_domain_count: usize,
    row_column_count: usize,
) -> CanonicalResult<Vec<u8>> {
    if row_domain_count == 0 || row_column_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 challenge row set dimensions must be positive",
        ));
    }
    let row_domain_count_u64 = u64::try_from(row_domain_count)
        .map_err(|_| setup_proof_error("setup proof LNP tbox z3/z4 row-domain count overflowed"))?;
    let row_column_count_u64 = u64::try_from(row_column_count)
        .map_err(|_| setup_proof_error("setup proof LNP tbox z3/z4 row-column count overflowed"))?;
    let row_byte_count = row_domain_count
        .checked_mul(row_column_count)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox z3/z4 row-set byte count overflowed")
        })?;
    let mut encoded = Vec::with_capacity(row_byte_count.saturating_add(40));
    append_varuint(&mut encoded, SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K);
    append_varuint(&mut encoded, row_domain_start);
    append_varuint(&mut encoded, row_domain_count_u64);
    append_varuint(&mut encoded, row_column_count_u64);
    for row_offset in 0..row_domain_count {
        let row_domain = row_domain_start
            .checked_add(u64::try_from(row_offset).map_err(|_| {
                setup_proof_error("setup proof LNP tbox z3/z4 row offset overflowed")
            })?)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox z3/z4 row domain overflowed"))?;
        let row = setup_proof_lnp_tbox_z34_brandom_row(
            challenge_seed_bytes,
            row_domain,
            row_column_count,
        )?;
        for coefficient in row {
            encoded.push(match coefficient {
                -1 => 0xff,
                0 => 0,
                1 => 1,
                _ => {
                    return Err(setup_proof_error(
                        "setup proof LNP tbox z3/z4 brandom coefficient is outside {-1,0,1}",
                    ));
                }
            });
        }
    }

    Ok(encoded)
}

fn setup_proof_lnp_tbox_z34_brandom_row(
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
    row_domain: u64,
    row_column_count: usize,
) -> CanonicalResult<Vec<i8>> {
    if row_column_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 brandom row width must be positive",
        ));
    }
    let brandom_k = usize::try_from(SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K).map_err(|_| {
        setup_proof_error("setup proof LNP tbox z3/z4 brandom k does not fit usize")
    })?;
    if brandom_k == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 brandom k must be positive",
        ));
    }
    let one_plane_bit_count = row_column_count.checked_mul(brandom_k).ok_or_else(|| {
        setup_proof_error("setup proof LNP tbox z3/z4 brandom bit count overflowed")
    })?;
    let total_bit_count = one_plane_bit_count.checked_mul(2).ok_or_else(|| {
        setup_proof_error("setup proof LNP tbox z3/z4 brandom total bit count overflowed")
    })?;
    let random_byte_count = total_bit_count.div_ceil(8);
    let mut shake = Shake128::default();
    shake.update(challenge_seed_bytes);
    shake.update(&row_domain.to_le_bytes());
    let mut random_bytes = vec![0_u8; random_byte_count];
    shake.finalize_xof().read(&mut random_bytes);

    let mut row = Vec::with_capacity(row_column_count);
    for column_index in 0..row_column_count {
        let mut coefficient = 0_i8;
        for bit_index in 0..brandom_k {
            let add_bit_index = column_index
                .checked_mul(brandom_k)
                .and_then(|start| start.checked_add(bit_index))
                .ok_or_else(|| {
                    setup_proof_error("setup proof LNP tbox z3/z4 add bit index overflowed")
                })?;
            if setup_proof_lnp_tbox_z34_brandom_bit(&random_bytes, add_bit_index) {
                coefficient = coefficient.checked_add(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP tbox z3/z4 brandom coefficient overflowed")
                })?;
            }
            let subtract_bit_index =
                one_plane_bit_count
                    .checked_add(add_bit_index)
                    .ok_or_else(|| {
                        setup_proof_error(
                            "setup proof LNP tbox z3/z4 subtract bit index overflowed",
                        )
                    })?;
            if setup_proof_lnp_tbox_z34_brandom_bit(&random_bytes, subtract_bit_index) {
                coefficient = coefficient.checked_sub(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP tbox z3/z4 brandom coefficient underflowed")
                })?;
            }
        }
        row.push(coefficient);
    }

    Ok(row)
}

fn setup_proof_lnp_tbox_z34_brandom_bit(random_bytes: &[u8], bit_index: usize) -> bool {
    let byte = random_bytes[bit_index / 8];
    ((byte >> (bit_index % 8)) & 1) == 1
}

fn setup_proof_lnp_tbox_z34_row_column_count(
    layout: &SetupProofLnpTboxLayout,
    polynomial_count: usize,
    field_name: &str,
) -> CanonicalResult<usize> {
    let row_column_count = polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP tbox {field_name} row-column count overflowed"
            ))
        })?;
    if row_column_count == 0 {
        return Err(setup_proof_error(format!(
            "setup proof LNP tbox {field_name} row-column count must be positive"
        )));
    }

    Ok(row_column_count)
}

fn t_b_polynomial_slice<'a>(
    coefficients: &'a [BigUint],
    proof_ring_degree: usize,
    polynomial_start: usize,
    polynomial_count: usize,
) -> CanonicalResult<&'a [BigUint]> {
    let coefficient_start = polynomial_start
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tB slice start overflowed"))?;
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tB slice length overflowed"))?;
    let coefficient_end = coefficient_start
        .checked_add(coefficient_count)
        .ok_or_else(|| setup_proof_error("setup proof LNP tB slice end overflowed"))?;
    coefficients
        .get(coefficient_start..coefficient_end)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tB seed-material slice is outside the tB vector")
        })
}

fn encode_setup_proof_lnp_tbox_z34_seed_material(
    layout: &SetupProofLnpTboxLayout,
    coefficient_slices: &[&[BigUint]],
) -> CanonicalResult<Vec<u8>> {
    let mut writer = LnpBitWriter::new();
    for coefficients in coefficient_slices {
        for coefficient in *coefficients {
            writer.write_big_uint_le_bits(coefficient, layout.proof_modulus_bit_count)?;
        }
    }
    writer.finish_with_lazer_padding();

    Ok(writer.into_bytes())
}

pub(super) fn append_setup_proof_lnp_tbox_generated_suffix(
    proof_bytes: &mut Vec<u8>,
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
) -> CanonicalResult<()> {
    let suffix_bytes = setup_proof_lnp_tbox_generated_suffix_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        proof_bytes,
    )?;
    proof_bytes.extend_from_slice(&suffix_bytes);

    Ok(())
}

fn setup_proof_lnp_tbox_generated_suffix_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
) -> CanonicalResult<Vec<u8>> {
    let expected_prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(layout)?;
    if prefix_bytes.len() != expected_prefix_byte_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox generated suffix requires exactly the commitment prefix bytes",
        ));
    }
    let challenge_material = derive_setup_proof_lnp_tbox_challenge_from_prefix(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
    )?;
    let suffix_seed = setup_proof_lnp_tbox_generated_suffix_seed(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
        &challenge_material.lower_protocol_challenge_hash,
    )?;
    let mut writer = LnpBitWriter::new();
    encode_lnp_tbox_challenge_coefficients(
        &mut writer,
        &challenge_material.challenge_coefficients,
    )?;
    encode_lnp_tbox_generated_hint_polyvec(
        &mut writer,
        &suffix_seed,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        "z1",
        layout.z1_polynomial_count,
        layout.proof_ring_degree,
        layout.z1_log2_standard_deviation,
        3,
    )?;
    encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        "z21",
        layout.z21_polynomial_count,
        layout.proof_ring_degree,
        layout.z21_log2_standard_deviation,
        3,
    )?;
    encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        "z3",
        layout.z3_polynomial_count,
        layout.proof_ring_degree,
        layout.z3_log2_standard_deviation,
        1,
    )?;
    encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        "z4",
        layout.z4_polynomial_count,
        layout.proof_ring_degree,
        layout.z4_log2_standard_deviation,
        1,
    )?;
    writer.finish_with_lazer_padding();

    Ok(writer.into_bytes())
}

fn setup_proof_lnp_tbox_generated_suffix_seed(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
    lower_protocol_challenge_hash: &str,
) -> CanonicalResult<[u8; 64]> {
    validate_hash_string(statement_hash_hex, "setupProofLnpTboxSuffix.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTboxSuffix.relationCommitmentHash",
    )?;
    validate_hash_string(
        lower_protocol_challenge_hash,
        "setupProofLnpTboxSuffix.lowerProtocolChallengeHash",
    )?;
    Ok(hash512(
        "sealed-lattice/setup/lnp-tbox-generated-suffix-seed-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            lower_protocol_challenge_hash.as_bytes(),
            prefix_bytes,
        ],
    ))
}

fn encode_lnp_tbox_challenge_coefficients(
    writer: &mut LnpBitWriter,
    challenge_coefficients: &[i64],
) -> CanonicalResult<()> {
    for coefficient in challenge_coefficients {
        let shifted = coefficient
            .checked_add(
                i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                    .expect("fixed challenge coefficient bound fits i64"),
            )
            .ok_or_else(|| setup_proof_error("setup proof LNP challenge shift overflowed"))?;
        let shifted = u64::try_from(shifted)
            .map_err(|_| setup_proof_error("setup proof LNP challenge coefficient is negative"))?;
        writer.write_u64_le_bits(shifted, SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE)?;
    }

    Ok(())
}

fn encode_lnp_tbox_generated_hint_polyvec(
    writer: &mut LnpBitWriter,
    suffix_seed: &[u8; 64],
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP hint count overflowed"))?;
    for coefficient_index in 0..coefficient_count {
        let value = generated_lnp_tbox_small_signed_value(
            suffix_seed,
            "hint",
            coefficient_index,
            1,
            Some(1),
        )?;
        let value = i64::try_from(value)
            .map_err(|_| setup_proof_error("setup proof LNP generated hint does not fit i64"))?;
        encode_lnp_tbox_hint_coefficient(writer, value)?;
    }

    Ok(())
}

fn encode_lnp_tbox_hint_coefficient(writer: &mut LnpBitWriter, value: i64) -> CanonicalResult<()> {
    match value {
        0 => {
            writer.write_bit(false);
            writer.write_bit(false);
        }
        1 => {
            writer.write_bit(false);
            writer.write_bit(true);
        }
        -1 => {
            writer.write_bit(true);
            writer.write_bit(false);
        }
        value if value >= 2 => {
            writer.write_bit(true);
            writer.write_bit(true);
            let extension_zero_count = usize::try_from(
                value
                    .checked_mul(2)
                    .and_then(|doubled| doubled.checked_sub(4))
                    .ok_or_else(|| {
                        setup_proof_error("setup proof LNP hint extension overflowed")
                    })?,
            )
            .map_err(|_| setup_proof_error("setup proof LNP hint extension is negative"))?;
            for _ in 0..extension_zero_count {
                writer.write_bit(false);
            }
            writer.write_bit(true);
        }
        value => {
            writer.write_bit(true);
            writer.write_bit(true);
            let extension_zero_count = usize::try_from(
                value
                    .checked_neg()
                    .and_then(|magnitude| magnitude.checked_mul(2))
                    .and_then(|doubled| doubled.checked_sub(3))
                    .ok_or_else(|| {
                        setup_proof_error("setup proof LNP hint extension overflowed")
                    })?,
            )
            .map_err(|_| setup_proof_error("setup proof LNP hint extension is negative"))?;
            for _ in 0..extension_zero_count {
                writer.write_bit(false);
            }
            writer.write_bit(true);
        }
    }

    Ok(())
}

fn encode_lnp_tbox_generated_gaussian_polyvec(
    writer: &mut LnpBitWriter,
    suffix_seed: &[u8; 64],
    field_name: &str,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
    coefficient_bound: i128,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP {field_name} coefficient count overflowed"
            ))
        })?;
    for coefficient_index in 0..coefficient_count {
        let value = generated_lnp_tbox_small_signed_value(
            suffix_seed,
            field_name,
            coefficient_index,
            coefficient_bound,
            Some(match field_name {
                "z21" | "z4" => -1,
                _ => 1,
            }),
        )?;
        encode_lnp_tbox_gaussian_coefficient(writer, value, log2_standard_deviation)?;
    }

    Ok(())
}

fn generated_lnp_tbox_small_signed_value(
    suffix_seed: &[u8; 64],
    field_name: &str,
    coefficient_index: usize,
    inclusive_bound: i128,
    first_coefficient_value: Option<i128>,
) -> CanonicalResult<i128> {
    if inclusive_bound < 0 {
        return Err(setup_proof_error(
            "setup proof LNP generated suffix bound must be nonnegative",
        ));
    }
    if coefficient_index == 0
        && let Some(value) = first_coefficient_value
    {
        return Ok(value.clamp(-inclusive_bound, inclusive_bound));
    }
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| setup_proof_error("setup proof LNP suffix coefficient index overflowed"))?
        .to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/lnp-tbox-generated-suffix-coefficient-v1",
        &[suffix_seed, field_name.as_bytes(), &coefficient_index_bytes],
    );
    let modulus = u128::try_from(
        inclusive_bound
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| setup_proof_error("setup proof LNP suffix bound overflowed"))?,
    )
    .map_err(|_| setup_proof_error("setup proof LNP suffix modulus does not fit u128"))?;
    let mut random_bytes = [0_u8; 16];
    random_bytes.copy_from_slice(&block[..16]);
    let sample = u128::from_le_bytes(random_bytes) % modulus;
    i128::try_from(sample)
        .map(|value| value - inclusive_bound)
        .map_err(|_| setup_proof_error("setup proof LNP suffix sample does not fit i128"))
}

fn encode_lnp_tbox_gaussian_coefficient(
    writer: &mut LnpBitWriter,
    value: i128,
    log2_standard_deviation: usize,
) -> CanonicalResult<()> {
    let low_bit_count = log2_standard_deviation
        .checked_add(1)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian low-bit count overflowed"))?;
    if low_bit_count == 0 || low_bit_count > u64::BITS as usize {
        return Err(setup_proof_error(
            "setup proof LNP Gaussian low-bit count is outside the supported encoding range",
        ));
    }
    let range = 1_i128
        .checked_shl(u32::try_from(low_bit_count).map_err(|_| {
            setup_proof_error("setup proof LNP Gaussian low-bit count does not fit u32")
        })?)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian range overflowed"))?;
    let half_range = range / 2;
    let mut low_value = value % range;
    if low_value >= half_range {
        low_value -= range;
    }
    if low_value < -half_range {
        low_value += range;
    }
    let quotient = value
        .checked_sub(low_value)
        .and_then(|high_value| high_value.checked_div(range))
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian quotient overflowed"))?;
    let unary_ones = if quotient <= 0 {
        usize::try_from(
            quotient
                .checked_neg()
                .and_then(|value| value.checked_mul(2))
                .ok_or_else(|| {
                    setup_proof_error("setup proof LNP Gaussian unary quotient overflowed")
                })?,
        )
        .map_err(|_| setup_proof_error("setup proof LNP Gaussian unary quotient overflowed"))?
    } else {
        usize::try_from(
            quotient
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| {
                    setup_proof_error("setup proof LNP Gaussian unary quotient overflowed")
                })?,
        )
        .map_err(|_| setup_proof_error("setup proof LNP Gaussian unary quotient overflowed"))?
    };
    for _ in 0..unary_ones {
        writer.write_bit(true);
    }
    writer.write_bit(false);
    let low_bits_mask = (1_u128 << low_bit_count) - 1;
    let low_bits = u64::try_from((low_value as u128) & low_bits_mask)
        .map_err(|_| setup_proof_error("setup proof LNP Gaussian low bits do not fit u64"))?;
    writer.write_u64_le_bits(low_bits, low_bit_count)?;

    Ok(())
}

fn verify_lnp_tbox_hint_coefficients(
    coefficients: &[LnpTboxHintCoefficient],
) -> CanonicalResult<()> {
    for coefficient in coefficients {
        if coefficient.value.unsigned_abs() > 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox hint coefficient exceeds the generated first-profile range",
            ));
        }
    }

    Ok(())
}

fn verify_lnp_tbox_h_forced_zero_coefficients(
    coefficients: &[BigUint],
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        if setup_proof_lnp_tbox_h_coefficient_must_be_zero(coefficient_index, proof_ring_degree)
            && !coefficient.is_zero()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox h coefficients at positions 0 and d/2 must be zero",
            ));
        }
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_centered_challenge_polynomial(
    reader: &mut LnpBitReader<'_>,
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<Vec<i64>> {
    let modulus = setup_proof_challenge_modulus();
    let mut coefficients = Vec::with_capacity(layout.proof_ring_degree);
    for _ in 0..layout.proof_ring_degree {
        let value = reader.read_big_uint_le_bits(SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE)?;
        if value >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox challenge coefficient is not canonical",
            ));
        }
        let residue = big_uint_to_u64(&value, "setup proof LNP challenge residue")?;
        let coefficient = i64::try_from(residue)
            .map_err(|_| setup_proof_error("setup proof LNP challenge residue does not fit i64"))?
            - i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                .expect("fixed challenge coefficient bound fits i64");
        coefficients.push(coefficient);
    }

    Ok(coefficients)
}

fn verify_lnp_tbox_gaussian_l2_bound(
    layout: &SetupProofLnpTboxLayout,
    coefficients: &[LnpTboxGaussianCoefficient],
    log2_standard_deviation: usize,
    field_name: &str,
) -> CanonicalResult<()> {
    let l2_squared = gaussian_l2_squared(coefficients);
    let coefficient_count = u64::try_from(coefficients.len()).map_err(|_| {
        setup_proof_error(format!(
            "setup proof LNP tbox {field_name} coefficient count overflowed"
        ))
    })?;
    let bound =
        generated_lnp_tbox_gaussian_l2_squared_bound(coefficient_count, log2_standard_deviation)?;
    if l2_squared > bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof LNP tbox {field_name} L2-squared exceeds the generated bound"),
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| coefficient.low_bit_count != log2_standard_deviation + 1)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof LNP tbox {field_name} Gaussian coding width is not canonical"),
        ));
    }
    if layout.proof_ring_degree == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree must be positive",
        ));
    }

    Ok(())
}

fn generated_lnp_tbox_gaussian_l2_squared_bound(
    coefficient_count: u64,
    log2_standard_deviation: usize,
) -> CanonicalResult<BigUint> {
    let doubled_exponent = log2_standard_deviation
        .checked_mul(2)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian bound exponent overflowed"))?;
    let numerator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * 2
            * coefficient_count,
    ) << doubled_exponent;
    let denominator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR,
    );

    Ok(numerator / denominator)
}

fn verify_generated_lnp_tbox_suffix_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    let prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(layout)?;
    let Some(prefix_bytes) = proof_bytes.get(..prefix_byte_count) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox proof ended before the commitment prefix",
        ));
    };
    let actual_suffix_bytes = proof_bytes.get(prefix_byte_count..).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox proof ended before the generated suffix",
        )
    })?;
    let expected_suffix_bytes = setup_proof_lnp_tbox_generated_suffix_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
    )?;
    if actual_suffix_bytes != expected_suffix_bytes.as_slice() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox generated suffix does not match the lower-protocol transcript",
        ));
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_hint_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<Vec<LnpTboxHintCoefficient>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP hint coefficient count overflowed"))?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let first_bit = reader.read_bit()?;
        let second_bit = reader.read_bit()?;
        let mut extension_zero_count = 0_usize;
        if first_bit && second_bit {
            while !reader.read_bit()? {
                extension_zero_count = extension_zero_count.checked_add(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP hint unary extension overflowed")
                })?;
            }
        }
        let value = decode_lnp_tbox_hint_value(first_bit, second_bit, extension_zero_count)?;
        coefficients.push(LnpTboxHintCoefficient {
            first_bit,
            second_bit,
            extension_zero_count,
            value,
        });
    }

    Ok(coefficients)
}

fn decode_lnp_tbox_hint_value(
    first_bit: bool,
    second_bit: bool,
    extension_zero_count: usize,
) -> CanonicalResult<i64> {
    match (first_bit, second_bit) {
        (false, false) => Ok(0),
        (false, true) => Ok(1),
        (true, false) => Ok(-1),
        (true, true) => {
            let extension = i64::try_from(extension_zero_count).map_err(|_| {
                setup_proof_error("setup proof LNP hint extension does not fit i64")
            })?;
            if extension_zero_count.is_multiple_of(2) {
                extension
                    .checked_add(4)
                    .and_then(|value| value.checked_div(2))
                    .ok_or_else(|| setup_proof_error("setup proof LNP hint value overflowed"))
            } else {
                extension
                    .checked_add(3)
                    .and_then(|value| value.checked_div(2))
                    .and_then(i64::checked_neg)
                    .ok_or_else(|| setup_proof_error("setup proof LNP hint value overflowed"))
            }
        }
    }
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_gaussian_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
    field_name: &str,
) -> CanonicalResult<Vec<LnpTboxGaussianCoefficient>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP {field_name} coefficient count overflowed",
            ))
        })?;
    let low_bit_count = log2_standard_deviation.checked_add(1).ok_or_else(|| {
        setup_proof_error(format!(
            "setup proof LNP {field_name} low-bit count overflowed",
        ))
    })?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let mut unary_ones = 0_usize;
        while reader.read_bit()? {
            unary_ones = unary_ones.checked_add(1).ok_or_else(|| {
                setup_proof_error(format!(
                    "setup proof LNP {field_name} unary coefficient overflowed"
                ))
            })?;
        }
        let low_bits = reader.read_u64_le_bits(low_bit_count)?;
        let value = decode_lnp_tbox_gaussian_value(unary_ones, low_bits, low_bit_count)?;
        coefficients.push(LnpTboxGaussianCoefficient {
            unary_ones,
            low_bits,
            low_bit_count,
            value,
        });
    }

    Ok(coefficients)
}

fn decode_lnp_tbox_gaussian_value(
    unary_ones: usize,
    low_bits: u64,
    low_bit_count: usize,
) -> CanonicalResult<i128> {
    if low_bit_count == 0 || low_bit_count > 127 {
        return Err(setup_proof_error(
            "setup proof LNP Gaussian low-bit count is outside the supported range",
        ));
    }
    let quotient_magnitude = i128::try_from(unary_ones / 2).map_err(|_| {
        setup_proof_error("setup proof LNP Gaussian unary quotient does not fit i128")
    })?;
    let quotient = if unary_ones.is_multiple_of(2) {
        quotient_magnitude.checked_neg().ok_or_else(|| {
            setup_proof_error("setup proof LNP Gaussian quotient negation overflowed")
        })?
    } else {
        quotient_magnitude
            .checked_add(1)
            .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian quotient overflowed"))?
    };
    let range = 1_i128
        .checked_shl(u32::try_from(low_bit_count).map_err(|_| {
            setup_proof_error("setup proof LNP Gaussian low-bit count does not fit u32")
        })?)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian range overflowed"))?;
    let low_value = decode_twos_complement_bits(low_bits, low_bit_count)?;

    quotient
        .checked_mul(range)
        .and_then(|high_value| high_value.checked_add(low_value))
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian value overflowed"))
}

fn decode_twos_complement_bits(value: u64, bit_count: usize) -> CanonicalResult<i128> {
    if bit_count == 0 || bit_count > u64::BITS as usize {
        return Err(setup_proof_error(
            "setup proof LNP two's-complement bit count is outside the supported range",
        ));
    }
    let unsigned_value = i128::from(value);
    let sign_bit = 1_u64
        .checked_shl(
            u32::try_from(bit_count - 1)
                .map_err(|_| setup_proof_error("setup proof LNP sign-bit index overflowed"))?,
        )
        .ok_or_else(|| setup_proof_error("setup proof LNP sign bit overflowed"))?;
    if value & sign_bit == 0 {
        return Ok(unsigned_value);
    }

    let range = 1_i128
        .checked_shl(u32::try_from(bit_count).map_err(|_| {
            setup_proof_error("setup proof LNP two's-complement range bit count overflowed")
        })?)
        .ok_or_else(|| setup_proof_error("setup proof LNP two's-complement range overflowed"))?;
    unsigned_value
        .checked_sub(range)
        .ok_or_else(|| setup_proof_error("setup proof LNP two's-complement value overflowed"))
}

fn gaussian_coefficient_prefix<'a>(
    coefficients: &'a [LnpTboxGaussianCoefficient],
    prefix_count: usize,
    field_name: &str,
) -> CanonicalResult<&'a [LnpTboxGaussianCoefficient]> {
    coefficients.get(..prefix_count).ok_or_else(|| {
        setup_proof_error(format!(
            "setup proof LNP tbox {field_name} vector is too short for the z3/z4 check window",
        ))
    })
}

fn setup_proof_lnp_tbox_z34_check_window_hash(
    layout: &SetupProofLnpTboxLayout,
    field_name: &str,
    coefficients: &[LnpTboxGaussianCoefficient],
) -> CanonicalResult<String> {
    if field_name != "z3" && field_name != "z4" {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 check-window field name is not accepted",
        ));
    }
    let mut encoded = Vec::new();
    append_varuint(
        &mut encoded,
        u64::try_from(coefficients.len()).map_err(|_| {
            setup_proof_error("setup proof LNP tbox z3/z4 check-window length overflowed")
        })?,
    );
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        append_varuint(
            &mut encoded,
            u64::try_from(coefficient_index).map_err(|_| {
                setup_proof_error(
                    "setup proof LNP tbox z3/z4 check-window coefficient index overflowed",
                )
            })?,
        );
        append_bytes(&mut encoded, coefficient.value.to_string().as_bytes());
    }

    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-check-window-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            field_name.as_bytes(),
            &encoded,
        ],
    ))
}

fn gaussian_l2_squared(coefficients: &[LnpTboxGaussianCoefficient]) -> BigUint {
    coefficients
        .iter()
        .fold(BigUint::zero(), |sum, coefficient| {
            let magnitude = BigUint::from(coefficient.value.unsigned_abs());
            sum + (&magnitude * &magnitude)
        })
}

fn gaussian_infinity_norm(coefficients: &[LnpTboxGaussianCoefficient]) -> BigUint {
    coefficients
        .iter()
        .map(|coefficient| BigUint::from(coefficient.value.unsigned_abs()))
        .max()
        .unwrap_or_else(BigUint::zero)
}

fn setup_proof_lnp_tbox_z34_check_coefficient_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP z3/z4 check coefficient count overflowed")
        })
}

fn verify_lnp_tbox_z34_norm_bounds(
    layout: &SetupProofLnpTboxLayout,
    z3_l2_squared: &BigUint,
    z4_infinity_norm: &BigUint,
) -> CanonicalResult<()> {
    let z3_l2_squared_bound = setup_proof_lnp_tbox_z3_l2_squared_bound(layout)?;
    if z3_l2_squared > &z3_l2_squared_bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox z3 L2-squared exceeds the generated check_z34 bound",
        ));
    }

    let z4_infinity_norm_bound = setup_proof_lnp_tbox_z4_infinity_norm_bound(layout)?;
    if z4_infinity_norm > &z4_infinity_norm_bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox z4 infinity norm exceeds the generated check_z34 bound",
        ));
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn setup_proof_challenge_modulus() -> BigUint {
    BigUint::from(
        SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .expect("fixed challenge modulus fits u64"),
    )
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn big_uint_to_u64(value: &BigUint, label: &str) -> CanonicalResult<u64> {
    let digits = value.to_u64_digits();
    match digits.as_slice() {
        [] => Ok(0),
        [digit] => Ok(*digit),
        _ => Err(setup_proof_error(format!("{label} does not fit u64"))),
    }
}

struct LnpBitWriter {
    bytes: Vec<u8>,
    bit_offset: usize,
}

impl LnpBitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_big_uint_le_bits(&mut self, value: &BigUint, bit_count: usize) -> CanonicalResult<()> {
        if value.bits() > bit_count as u64 {
            return Err(setup_proof_error(
                "setup proof LNP bit writer value exceeds the declared bit width",
            ));
        }
        for bit_index in 0..bit_count {
            let bit = ((value >> bit_index) & BigUint::one()).is_one();
            self.write_bit(bit);
        }

        Ok(())
    }

    fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) -> CanonicalResult<()> {
        if bit_count > u64::BITS as usize && value != 0 {
            return Err(setup_proof_error(
                "setup proof LNP bit writer u64 value exceeds the declared bit width",
            ));
        }
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
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        if byte_index == self.bytes.len() {
            self.bytes.push(0);
        }
        if bit {
            self.bytes[byte_index] |= 1_u8 << bit_index;
        }
        self.bit_offset += 1;
    }

    fn finish_with_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
struct LnpBitReader<'a> {
    bytes: &'a [u8],
    bit_offset: usize,
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
impl<'a> LnpBitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bit_offset: 0,
        }
    }

    fn read_big_uint_le_bits(&mut self, bit_count: usize) -> CanonicalResult<BigUint> {
        let mut value = BigUint::zero();
        for bit_index in 0..bit_count {
            if self.read_bit()? {
                value |= BigUint::one() << bit_index;
            }
        }

        Ok(value)
    }

    fn read_u64_le_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count > u64::BITS as usize {
            return Err(setup_proof_error(
                "setup proof LNP tbox u64 bit read exceeds u64 width",
            ));
        }
        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            if self.read_bit()? {
                value |= 1_u64 << bit_index;
            }
        }

        Ok(value)
    }

    fn read_bit(&mut self) -> CanonicalResult<bool> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let Some(byte) = self.bytes.get(byte_index) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof LNP tbox proof ended before the declared field layout",
            ));
        };
        let bit = ((*byte >> bit_index) & 1) == 1;
        self.bit_offset = self
            .bit_offset
            .checked_add(1)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox bit offset overflowed"))?;

        Ok(bit)
    }

    fn skip_bits(&mut self, bit_count: usize) -> CanonicalResult<()> {
        for _ in 0..bit_count {
            self.read_bit()?;
        }

        Ok(())
    }

    fn finish_exact_end(&mut self, label: &str) -> CanonicalResult<()> {
        let consumed_bits = self
            .bytes
            .len()
            .checked_mul(8)
            .ok_or_else(|| setup_proof_error(format!("{label} bit length overflowed")))?;
        if self.bit_offset != consumed_bits {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} ended before the declared prefix layout"),
            ));
        }

        Ok(())
    }

    fn finish_with_lazer_padding(&mut self) -> CanonicalResult<()> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let Some(byte) = self.bytes.get(byte_index) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof LNP tbox proof is missing its final padding byte",
            ));
        };
        let high_bits = *byte & (!0_u8 << bit_index);
        if high_bits != (1_u8 << bit_index) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox final padding is not canonical",
            ));
        }
        let consumed_bytes = byte_index.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox consumed byte count overflowed")
        })?;
        if consumed_bytes != self.bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::TrailingBytes,
                "setup proof LNP tbox proof has trailing bytes after final padding",
            ));
        }
        self.bit_offset = consumed_bytes
            .checked_mul(8)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox final bit offset overflowed"))?;

        Ok(())
    }
}

struct SetupProofChallengeSampler {
    seed: [u8; 64],
    block_index: u64,
    block: [u8; 64],
    bit_offset: usize,
}

impl SetupProofChallengeSampler {
    fn new(
        proof_family: &str,
        statement_hash_hex: &str,
        relation_commitment_hash_hex: &str,
    ) -> Self {
        Self {
            seed: hash512(
                SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
                &[
                    proof_family.as_bytes(),
                    statement_hash_hex.as_bytes(),
                    relation_commitment_hash_hex.as_bytes(),
                ],
            ),
            block_index: 0,
            block: [0_u8; 64],
            bit_offset: 512,
        }
    }

    fn new_lnp_tbox_lower_protocol(
        proof_family: &str,
        statement_hash_hex: &str,
        relation_commitment_hash_hex: &str,
        lower_protocol_challenge_hash: &str,
    ) -> Self {
        Self {
            seed: hash512(
                SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_SEED_DOMAIN,
                &[
                    proof_family.as_bytes(),
                    statement_hash_hex.as_bytes(),
                    relation_commitment_hash_hex.as_bytes(),
                    lower_protocol_challenge_hash.as_bytes(),
                ],
            ),
            block_index: 0,
            block: [0_u8; 64],
            bit_offset: 512,
        }
    }

    fn next_bounded_sample(&mut self, modulus: u64, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count == 0 || bit_count > 63 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge sample bit count is outside the supported range",
            ));
        }
        if modulus < (1_u64 << (bit_count - 1)) || modulus >= (1_u64 << bit_count) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge modulus does not match the rejection bit count",
            ));
        }

        loop {
            let candidate = self.next_bits(bit_count)?;
            if candidate < modulus {
                return Ok(candidate);
            }
        }
    }

    fn next_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if self.bit_offset + bit_count > 512 {
            let block_index_bytes = self.block_index.to_le_bytes();
            self.block = hash512(
                SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
                &[&self.seed, &block_index_bytes],
            );
            self.block_index = self.block_index.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "setup proof challenge stream block index overflowed",
                )
            })?;
            self.bit_offset = 0;
        }

        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            let absolute_bit_index = self.bit_offset + bit_index;
            let byte = self.block[absolute_bit_index / 8];
            let bit = (byte >> (absolute_bit_index % 8)) & 1;
            value |= u64::from(bit) << bit_index;
        }
        self.bit_offset += bit_count;

        Ok(value)
    }
}

fn challenge_sample_positions(ring_degree: usize) -> CanonicalResult<Vec<usize>> {
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge sample positions require an even ring degree",
        ));
    }

    let half_degree = ring_degree / 2;
    let last_position = ring_degree - 1;
    let mut positions = vec![0, 1.min(last_position), half_degree - 1, half_degree];
    if half_degree + 1 < ring_degree {
        positions.push(half_degree + 1);
    }
    positions.push(last_position);
    positions.sort_unstable();
    positions.dedup();

    Ok(positions)
}

fn setup_proof_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ProfileComponentMismatch, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash512_hex;

    #[test]
    fn setup_proof_challenge_sampler_derives_autostable_bounded_coefficients() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

        let coefficients = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &statement_hash,
            &relation_commitment_hash,
            16,
        )
        .expect("challenge coefficients");

        assert_eq!(coefficients.len(), 16);
        assert!(
            coefficients[..8]
                .iter()
                .any(|coefficient| *coefficient != 0)
        );
        assert_eq!(coefficients[8], 0);
        for coefficient in &coefficients {
            assert!((-2..=2).contains(coefficient));
        }
        for coefficient_position in 9..16 {
            assert_eq!(
                coefficients[coefficient_position],
                -coefficients[16 - coefficient_position]
            );
        }
    }

    #[test]
    fn setup_proof_challenge_sampler_binds_statement_and_relation() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let other_statement_hash = hash512_hex("test-statement", &[b"same-secret-drift"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

        let first = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &statement_hash,
            &relation_commitment_hash,
            32,
        )
        .expect("challenge coefficients");
        let second = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &other_statement_hash,
            &relation_commitment_hash,
            32,
        )
        .expect("challenge coefficients");

        assert_ne!(first, second);
    }

    #[test]
    fn setup_proof_challenge_sampler_rejects_wrong_profile_shape() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

        let odd_ring_error = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &statement_hash,
            &relation_commitment_hash,
            15,
        )
        .expect_err("odd ring degree should fail");
        let wrong_family_error = derive_setup_proof_challenge_coefficients(
            "unknown-proof-family",
            &statement_hash,
            &relation_commitment_hash,
            16,
        )
        .expect_err("unknown proof family should fail");

        assert_eq!(
            odd_ring_error.code,
            CanonicalErrorCode::ProfileComponentMismatch
        );
        assert_eq!(
            wrong_family_error.code,
            CanonicalErrorCode::ProfileComponentMismatch
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_uniform_sampler_uses_full_declared_width() {
        let bit_count = 130;
        let modulus = (BigUint::one() << bit_count) - BigUint::from(159_u64);
        let mut observed_high_bits = false;

        for coefficient_index in 0..64 {
            let residue_bytes = sample_setup_proof_lnp_tbox_uniform_residue_bytes(
                "sealed-lattice/setup/test/lnp-tbox-uniform-v1",
                "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                2,
                coefficient_index,
                bit_count,
                Some(&modulus),
            )
            .expect("uniform residue");
            assert_eq!(residue_bytes.len(), bit_count.div_ceil(8));
            assert_eq!(residue_bytes[16] & !0b0000_0011, 0);

            let residue = BigUint::from_bytes_le(&residue_bytes);
            assert!(residue < modulus);
            if residue.bits() > 64 {
                observed_high_bits = true;
            }
        }

        assert!(
            observed_high_bits,
            "tbox uniform sampler must not truncate residues to the low machine word"
        );
    }

    #[test]
    fn setup_proof_scalar_challenge_sampler_uses_declared_width() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let mut observed_above_old_word = false;
        let challenge_maximum = (1_u64 << 45) - 1;

        for relation_index in 0..64_u64 {
            let relation_index_bytes = relation_index.to_le_bytes();
            let relation_commitment_hash =
                hash512_hex("test-relation", &[b"same-secret", &relation_index_bytes]);
            let challenge = derive_setup_proof_scalar_challenge(
                "same-secret-consistency",
                "sealed-lattice/setup/test/scalar-challenge-v1",
                &statement_hash,
                &relation_commitment_hash,
                45,
            )
            .expect("scalar challenge");

            assert!((1..=challenge_maximum).contains(&challenge));
            if challenge > u64::from(u32::MAX) {
                observed_above_old_word = true;
            }
        }

        assert!(
            observed_above_old_word,
            "scalar challenge sampler must not truncate to the old 32-bit challenge space"
        );
    }

    #[test]
    fn setup_proof_challenge_space_audit_covers_all_families_and_invertible_differences() {
        let accounting = challenge_difference_invertibility_accounting_value()
            .expect("challenge difference accounting");
        assert_eq!(
            accounting["status"],
            SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS
        );
        assert_eq!(accounting["conditionSatisfied"], true);

        let audit = setup_proof_challenge_space_audit_value(SETUP_PROOF_LNP_PROOF_RING_DEGREE)
            .expect("challenge audit");
        let family_samples = audit["familySamples"].as_array().expect("family samples");
        assert_eq!(family_samples.len(), SETUP_PROOF_FAMILIES.len());
        for proof_family in SETUP_PROOF_FAMILIES {
            assert!(
                family_samples.iter().any(|sample| {
                    sample["proofFamily"].as_str() == Some(proof_family)
                        && sample["sampledCoefficients"]
                            .as_array()
                            .is_some_and(|coefficients| {
                                coefficients.len()
                                    == challenge_sample_positions(SETUP_PROOF_LNP_PROOF_RING_DEGREE)
                                        .expect("sample positions")
                                        .len()
                            })
                }),
                "missing challenge audit family {proof_family}"
            );
        }

        let sampled_difference_checks = audit["sampledDifferenceChecks"]
            .as_array()
            .expect("sampled difference checks");
        assert_eq!(sampled_difference_checks.len(), 10);
        assert!(sampled_difference_checks.iter().all(|check| {
            check["invertibleOverProofRing"].as_bool() == Some(true)
                && check["coefficientInfinityNorm"]
                    .as_u64()
                    .is_some_and(|norm| norm <= SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND * 2)
        }));
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_accepts_generated_canonical_proof_byte_layout() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");

        let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect("proof byte layout");

        assert_eq!(decoded.decoded_size_bytes, proof_bytes.len());
        let derived_challenge = derive_setup_proof_lnp_tbox_challenge_from_prefix(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes[..setup_proof_lnp_tbox_commitment_prefix_byte_count(&layout)
                .expect("prefix byte count")],
        )
        .expect("derived tbox challenge");
        assert_eq!(
            decoded.challenge_coefficients,
            derived_challenge.challenge_coefficients
        );
        assert_eq!(
            decoded.t_b_coefficients.len(),
            layout.t_b_polynomial_count * layout.proof_ring_degree
        );
        assert_eq!(
            decoded.h_coefficients.len(),
            layout.h_polynomial_count * layout.proof_ring_degree
        );
        assert_eq!(
            decoded.t_a1_compressed_coefficients.len(),
            layout.t_a1_polynomial_count * layout.proof_ring_degree
        );
        assert_eq!(decoded.t_b_coefficients[1], BigUint::from(1_u64));
        assert_eq!(decoded.h_coefficients[2], BigUint::from(2_u64));
        assert_eq!(
            decoded.t_a1_compressed_coefficients[3],
            BigUint::from(3_u64)
        );
        assert!(
            decoded
                .hint_coefficients
                .iter()
                .any(|coefficient| coefficient.value != 0)
        );
        for coefficients in [
            &decoded.z1_coefficients,
            &decoded.z21_coefficients,
            &decoded.z3_coefficients,
            &decoded.z4_coefficients,
        ] {
            assert!(
                coefficients
                    .iter()
                    .any(|coefficient| coefficient.value != 0)
            );
        }
        assert!(!decoded.z3_l2_squared.is_zero());
        assert!(!decoded.z4_infinity_norm.is_zero());
        assert_eq!(decoded.z34_seed_material_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_seed_hex.len(), 64);
        assert_eq!(decoded.z34_challenge_seed_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_tail_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_row_domain_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_z3_row_set_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_z4_row_set_hash.len(), 128);
        assert_eq!(decoded.tbox_lower_protocol_challenge_hash.len(), 128);
        assert_eq!(decoded.z34_z3_check_window_hash.len(), 128);
        assert_eq!(decoded.z34_z4_check_window_hash.len(), 128);
        assert_ne!(
            decoded.z34_challenge_z3_row_set_hash,
            decoded.z34_challenge_z4_row_set_hash
        );
        assert_ne!(
            decoded.z34_z3_check_window_hash,
            decoded.z34_z4_check_window_hash
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_accepts_generated_suffix_for_all_setup_families() {
        for layout in [
            private_vss_share_lnp_tbox_layout(),
            same_secret_lnp_tbox_layout(),
            public_key_share_lnp_tbox_layout(),
            relinearization_key_share_lnp_tbox_layout(),
            galois_key_share_lnp_tbox_layout(),
        ] {
            let statement_hash = hash512_hex(
                "test-statement",
                &[
                    layout.proof_family.as_bytes(),
                    layout.tbox_parameter_profile_id.as_bytes(),
                ],
            );
            let relation_commitment_hash = hash512_hex(
                "test-relation",
                &[
                    layout.proof_family.as_bytes(),
                    layout.tbox_parameter_profile_id.as_bytes(),
                ],
            );
            let proof_bytes = encode_lnp_tbox_proof_for_test(
                &layout,
                &statement_hash,
                &relation_commitment_hash,
                None,
                None,
                TboxSuffixProfileForTest::Generated,
            )
            .expect("proof bytes");
            let prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(&layout)
                .expect("prefix byte count");
            assert!(
                proof_bytes[prefix_byte_count..]
                    .iter()
                    .any(|byte| *byte != 0),
                "generated suffix for {} must not collapse to a zero placeholder",
                layout.proof_family
            );

            let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
                &layout,
                &statement_hash,
                &relation_commitment_hash,
                &proof_bytes,
            )
            .expect("generated suffix verifies");

            assert_eq!(decoded.decoded_size_bytes, proof_bytes.len());
            assert_eq!(decoded.z34_seed_material_hash.len(), 128);
            assert_eq!(decoded.z34_challenge_seed_hash.len(), 128);
            assert_eq!(decoded.z34_challenge_tail_hash.len(), 128);
            assert_eq!(decoded.z34_challenge_row_domain_hash.len(), 128);
            assert_eq!(decoded.z34_challenge_z3_row_set_hash.len(), 128);
            assert_eq!(decoded.z34_challenge_z4_row_set_hash.len(), 128);
            assert_eq!(decoded.tbox_lower_protocol_challenge_hash.len(), 128);
            assert_eq!(decoded.z34_z3_check_window_hash.len(), 128);
            assert_eq!(decoded.z34_z4_check_window_hash.len(), 128);
            assert!(!decoded.z3_l2_squared.is_zero());
            assert!(!decoded.z4_infinity_norm.is_zero());
        }
    }

    #[test]
    fn setup_proof_lnp_tbox_generated_norm_bounds_match_lazer_codegen_formula() {
        let layout = small_lnp_tbox_layout_for_test();

        assert_eq!(
            setup_proof_lnp_tbox_z3_l2_squared_bound(&layout).expect("z3 L2-squared bound"),
            BigUint::from(26_467_u64)
        );
        assert_eq!(
            setup_proof_lnp_tbox_z4_infinity_norm_bound(&layout).expect("z4 infinity bound"),
            BigUint::from(99_u64)
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_z34_challenge_profile_pins_row_domains() {
        let layout = small_lnp_tbox_layout_for_test();
        let profile =
            setup_proof_lnp_tbox_z34_challenge_profile_value(&layout).expect("z34 profile");
        assert_eq!(
            profile["challengeSeedByteCount"].as_u64(),
            Some(SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT as u64)
        );
        assert_eq!(
            profile["rowExpansion"]["brandomK"].as_u64(),
            Some(SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K)
        );
        assert_eq!(
            profile["rowExpansion"]["z3RowDomainStart"].as_u64(),
            Some(SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START)
        );
        assert_eq!(
            profile["rowExpansion"]["z4RowDomainStart"].as_u64(),
            Some(SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START)
        );
        assert_eq!(
            profile["rowExpansion"]["z3RowDomainCount"].as_u64(),
            Some(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64)
        );
        assert_eq!(
            profile["rowExpansion"]["z4RowDomainCount"].as_u64(),
            Some(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64)
        );
        assert_eq!(
            profile["rowExpansion"]["z3RowColumnCount"].as_u64(),
            Some((layout.z3_polynomial_count * layout.proof_ring_degree) as u64)
        );
        assert_eq!(
            profile["rowExpansion"]["z4RowColumnCount"].as_u64(),
            Some((layout.z4_polynomial_count * layout.proof_ring_degree) as u64)
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_z34_brandom_row_matches_lazer_bit_planes() {
        let mut challenge_seed_bytes = [0_u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT];
        for (byte_index, byte) in challenge_seed_bytes.iter_mut().enumerate() {
            *byte = u8::try_from(byte_index).expect("test seed byte fits u8");
        }

        let row = setup_proof_lnp_tbox_z34_brandom_row(&challenge_seed_bytes, 7, 17)
            .expect("brandom row");

        assert_eq!(
            row,
            vec![1, -1, 0, 1, 0, 0, 0, -1, -1, 0, 0, -1, 0, -1, 0, 0, 1]
        );
        assert!(
            row.iter()
                .all(|coefficient| [-1, 0, 1].contains(coefficient))
        );
        assert_ne!(
            setup_proof_lnp_tbox_z34_brandom_row(&challenge_seed_bytes, 7, 17).expect("same row"),
            setup_proof_lnp_tbox_z34_brandom_row(&challenge_seed_bytes, 263, 17)
                .expect("domain-separated row")
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_z34_check_window_hash_binds_signed_values() {
        let layout = small_lnp_tbox_layout_for_test();
        let mut zero_window = (0..SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS)
            .map(|_| LnpTboxGaussianCoefficient {
                unary_ones: 0,
                low_bits: 0,
                low_bit_count: 3,
                value: 0,
            })
            .collect::<Vec<_>>();
        let zero_hash = setup_proof_lnp_tbox_z34_check_window_hash(&layout, "z3", &zero_window)
            .expect("zero check-window hash");

        zero_window[17].value = -3;
        let changed_hash = setup_proof_lnp_tbox_z34_check_window_hash(&layout, "z3", &zero_window)
            .expect("changed check-window hash");
        let z4_domain_hash =
            setup_proof_lnp_tbox_z34_check_window_hash(&layout, "z4", &zero_window)
                .expect("z4 check-window hash");

        assert_eq!(zero_hash.len(), 128);
        assert_ne!(zero_hash, changed_hash);
        assert_ne!(changed_hash, z4_domain_hash);
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_z34_norm_bound_overflow() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();

        let high_z3_proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::NonzeroZ3AboveBound,
        )
        .expect("z3 proof bytes");
        let z3_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &high_z3_proof_bytes,
        )
        .expect_err("oversized z3 should fail the generated bound");
        assert_eq!(z3_error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(z3_error.message.contains("z3 L2-squared"));

        let high_z4_proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::NonzeroZ4AboveBound,
        )
        .expect("z4 proof bytes");
        let z4_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &high_z4_proof_bytes,
        )
        .expect_err("oversized z4 should fail the generated bound");
        assert_eq!(z4_error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(z4_error.message.contains("z4 infinity norm"));
    }

    #[test]
    fn setup_proof_lnp_tbox_z34_seed_material_tracks_t_b_seed_components() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");
        let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect("decoded proof");

        let seed_polynomial_count =
            setup_proof_lnp_tbox_z34_seed_polynomial_count(&layout).expect("seed polynomial count");
        let message_polynomial_count = setup_proof_lnp_tbox_message_polynomial_count(&layout)
            .expect("message polynomial count");
        assert_eq!(seed_polynomial_count, 2);
        assert_eq!(message_polynomial_count, 1);
        let mut changed_t_b = decoded.t_b_coefficients.clone();
        let ty3_first_coefficient = message_polynomial_count * layout.proof_ring_degree;
        changed_t_b[ty3_first_coefficient] += BigUint::one();
        if changed_t_b[ty3_first_coefficient] >= layout.proof_modulus {
            changed_t_b[ty3_first_coefficient] = BigUint::zero();
        }
        let changed_seed = setup_proof_lnp_tbox_z34_seed_material(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &changed_t_b,
        )
        .expect("changed seed material");

        assert_ne!(
            changed_seed.seed_material_hash,
            decoded.z34_seed_material_hash
        );
        assert_ne!(
            changed_seed.challenge_seed_hex,
            decoded.z34_challenge_seed_hex
        );
        assert_ne!(
            changed_seed.challenge_seed_hash,
            decoded.z34_challenge_seed_hash
        );
        assert_ne!(
            changed_seed.challenge_tail_hash,
            decoded.z34_challenge_tail_hash
        );
        assert_ne!(
            changed_seed.challenge_row_domain_hash,
            decoded.z34_challenge_row_domain_hash
        );
        assert_ne!(
            changed_seed.challenge_z3_row_set_hash,
            decoded.z34_challenge_z3_row_set_hash
        );
        assert_ne!(
            changed_seed.challenge_z4_row_set_hash,
            decoded.z34_challenge_z4_row_set_hash
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_z34_tail_hash_tracks_t_b_tail_components() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");
        let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect("decoded proof");

        let seed_polynomial_count =
            setup_proof_lnp_tbox_z34_seed_polynomial_count(&layout).expect("seed polynomial count");
        let message_polynomial_count = setup_proof_lnp_tbox_message_polynomial_count(&layout)
            .expect("message polynomial count");
        let challenge_tail_start = message_polynomial_count
            .checked_add(seed_polynomial_count * 2)
            .and_then(|start| start.checked_add(1))
            .expect("challenge-tail start");
        let challenge_tail_first_coefficient = challenge_tail_start * layout.proof_ring_degree;
        let mut changed_t_b = decoded.t_b_coefficients.clone();
        changed_t_b[challenge_tail_first_coefficient] += BigUint::one();
        if changed_t_b[challenge_tail_first_coefficient] >= layout.proof_modulus {
            changed_t_b[challenge_tail_first_coefficient] = BigUint::zero();
        }
        let changed_seed = setup_proof_lnp_tbox_z34_seed_material(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &changed_t_b,
        )
        .expect("changed seed material");

        assert_eq!(
            changed_seed.seed_material_hash,
            decoded.z34_seed_material_hash
        );
        assert_ne!(
            changed_seed.challenge_tail_hash,
            decoded.z34_challenge_tail_hash
        );
        let changed_challenge_material = setup_proof_lnp_tbox_challenge_material(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &changed_seed,
        )
        .expect("changed lower-protocol challenge");
        assert_ne!(
            changed_challenge_material.lower_protocol_challenge_hash,
            decoded.tbox_lower_protocol_challenge_hash
        );
        assert_ne!(
            changed_challenge_material.challenge_coefficients,
            decoded.challenge_coefficients
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_layout_rejects_missing_z34_seed_material() {
        let mut layout = small_lnp_tbox_layout_for_test();
        layout.t_b_polynomial_count = 6;

        let error = validate_lnp_tbox_layout(&layout)
            .expect_err("layout without ty3, ty4, beta, and tail space must fail");

        assert!(error.message.contains("too small for z3/z4 seed material"));
    }

    #[test]
    fn setup_proof_lnp_hint_decoder_matches_lazer_signed_values() {
        assert_eq!(
            decode_lnp_tbox_hint_value(false, false, 0).expect("zero hint"),
            0
        );
        assert_eq!(
            decode_lnp_tbox_hint_value(false, true, 0).expect("one hint"),
            1
        );
        assert_eq!(
            decode_lnp_tbox_hint_value(true, false, 0).expect("minus one hint"),
            -1
        );
        assert_eq!(
            decode_lnp_tbox_hint_value(true, true, 0).expect("positive extended hint"),
            2
        );
        assert_eq!(
            decode_lnp_tbox_hint_value(true, true, 1).expect("negative extended hint"),
            -2
        );
        assert_eq!(
            decode_lnp_tbox_hint_value(true, true, 4).expect("larger positive extended hint"),
            4
        );
        assert_eq!(
            decode_lnp_tbox_hint_value(true, true, 5).expect("larger negative extended hint"),
            -4
        );
    }

    #[test]
    fn setup_proof_lnp_gaussian_decoder_matches_lazer_signed_values() {
        assert_eq!(
            decode_lnp_tbox_gaussian_value(0, 0, 3).expect("zero Gaussian"),
            0
        );
        assert_eq!(
            decode_lnp_tbox_gaussian_value(0, 7, 3).expect("negative low bits"),
            -1
        );
        assert_eq!(
            decode_lnp_tbox_gaussian_value(1, 0, 3).expect("positive quotient"),
            8
        );
        assert_eq!(
            decode_lnp_tbox_gaussian_value(1, 7, 3).expect("positive quotient negative low bits"),
            7
        );
        assert_eq!(
            decode_lnp_tbox_gaussian_value(2, 0, 3).expect("negative quotient"),
            -8
        );
        assert_eq!(
            decode_lnp_tbox_gaussian_value(3, 3, 3).expect("larger positive quotient"),
            19
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_noncanonical_uniform_residue() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let dummy_challenge = vec![0_i64; layout.proof_ring_degree];
        let proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            Some(&dummy_challenge),
            Some(layout.proof_modulus.clone()),
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");

        let error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect_err("noncanonical residue should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("tB"));
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_nonzero_h_forced_zero_position() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let mut proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");
        let h_bit_offset =
            layout.t_b_polynomial_count * layout.proof_ring_degree * layout.proof_modulus_bit_count;
        proof_bytes[h_bit_offset / 8] |= 1 << (h_bit_offset % 8);

        let error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect_err("nonzero forced h coefficient should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("h coefficients"));
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_challenge_drift_and_trailing_bytes() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let valid_proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("valid proof bytes");
        let mut challenge = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &valid_proof_bytes,
        )
        .expect("valid proof bytes should decode")
        .challenge_coefficients;
        challenge[0] = if challenge[0] == 2 {
            1
        } else {
            challenge[0] + 1
        };
        let proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            Some(&challenge),
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");

        let challenge_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect_err("challenge drift should fail");

        assert_eq!(
            challenge_error.code,
            CanonicalErrorCode::InvalidProtocolObject
        );
        assert!(challenge_error.message.contains("challenge"));

        let mut trailing_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");
        trailing_bytes.push(0);
        let trailing_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &trailing_bytes,
        )
        .expect_err("trailing byte should fail");

        assert_eq!(trailing_error.code, CanonicalErrorCode::TrailingBytes);
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_noncanonical_generated_suffix() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();

        let nonzero_hint_proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::NonzeroHint,
        )
        .expect("proof bytes");
        let hint_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &nonzero_hint_proof_bytes,
        )
        .expect_err("noncanonical generated hint should fail");
        assert_eq!(hint_error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(hint_error.message.contains("generated suffix"));

        let nonzero_gaussian_proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::NonzeroGaussian,
        )
        .expect("proof bytes");
        let gaussian_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &nonzero_gaussian_proof_bytes,
        )
        .expect_err("noncanonical generated Gaussian should fail");
        assert_eq!(
            gaussian_error.code,
            CanonicalErrorCode::InvalidProtocolObject
        );
        assert!(gaussian_error.message.contains("generated suffix"));
    }

    fn small_lnp_tbox_layout_for_test() -> SetupProofLnpTboxLayout {
        SetupProofLnpTboxLayout {
            proof_family: "same-secret-consistency",
            tbox_parameter_profile_id: SAME_SECRET_LNP_TBOX_PARAMETER_PROFILE_ID,
            tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/same-secret/lnp-tbox-commitment-prefix-v1",
            proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
            proof_modulus: BigUint::from(12_289_u64),
            proof_modulus_bit_count: 14,
            compression_dropped_bits: 3,
            t_b_polynomial_count: 11,
            h_polynomial_count: 4,
            t_a1_polynomial_count: 1,
            hint_polynomial_count: 1,
            z1_polynomial_count: 1,
            z21_polynomial_count: 1,
            z3_polynomial_count: 2,
            z4_polynomial_count: 2,
            z1_log2_standard_deviation: 2,
            z21_log2_standard_deviation: 2,
            z3_log2_standard_deviation: 2,
            z4_log2_standard_deviation: 2,
        }
    }

    fn encode_lnp_tbox_proof_for_test(
        layout: &SetupProofLnpTboxLayout,
        statement_hash_hex: &str,
        relation_commitment_hash_hex: &str,
        challenge_override: Option<&[i64]>,
        first_t_b_residue_override: Option<BigUint>,
        suffix_profile: TboxSuffixProfileForTest,
    ) -> CanonicalResult<Vec<u8>> {
        let has_first_t_b_residue_override = first_t_b_residue_override.is_some();
        let mut writer = LnpBitWriterForTest::new();
        encode_uniform_polyvec_for_test(
            &mut writer,
            layout.t_b_polynomial_count,
            layout.proof_ring_degree,
            layout.proof_modulus_bit_count,
            first_t_b_residue_override,
            false,
        )?;
        encode_uniform_polyvec_for_test(
            &mut writer,
            layout.h_polynomial_count,
            layout.proof_ring_degree,
            layout.proof_modulus_bit_count,
            None,
            true,
        )?;
        encode_uniform_polyvec_for_test(
            &mut writer,
            layout.t_a1_polynomial_count,
            layout.proof_ring_degree,
            layout.proof_modulus_bit_count - layout.compression_dropped_bits,
            None,
            false,
        )?;
        if suffix_profile == TboxSuffixProfileForTest::Generated
            && challenge_override.is_none()
            && !has_first_t_b_residue_override
        {
            let prefix_bytes = writer.into_bytes();
            let suffix_bytes = setup_proof_lnp_tbox_generated_suffix_bytes(
                layout,
                statement_hash_hex,
                relation_commitment_hash_hex,
                &prefix_bytes,
            )?;
            let mut proof_bytes = prefix_bytes;
            proof_bytes.extend_from_slice(&suffix_bytes);
            return Ok(proof_bytes);
        }
        let derived_challenge;
        let challenge_coefficients = if let Some(challenge_override) = challenge_override {
            challenge_override
        } else {
            derived_challenge = derive_setup_proof_lnp_tbox_challenge_from_prefix(
                layout,
                statement_hash_hex,
                relation_commitment_hash_hex,
                writer.bytes(),
            )?;
            &derived_challenge.challenge_coefficients
        };
        for coefficient in challenge_coefficients {
            let shifted = coefficient
                .checked_add(i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND).unwrap())
                .ok_or_else(|| setup_proof_error("test challenge coefficient overflowed"))?;
            writer.write_u64_le_bits(
                u64::try_from(shifted)
                    .map_err(|_| setup_proof_error("test challenge coefficient was negative"))?,
                SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
            );
        }
        let hint_count = layout
            .hint_polynomial_count
            .checked_mul(layout.proof_ring_degree)
            .ok_or_else(|| setup_proof_error("test hint count overflowed"))?;
        for coefficient_index in 0..hint_count {
            match (suffix_profile, coefficient_index) {
                (TboxSuffixProfileForTest::NonzeroHint, 0) => {
                    writer.write_bit(true);
                    writer.write_bit(false);
                }
                _ => {
                    writer.write_bit(false);
                    writer.write_bit(false);
                }
            }
        }
        for (field, polynomial_count, log2_standard_deviation) in [
            (
                TboxGaussianFieldForTest::Z1,
                layout.z1_polynomial_count,
                layout.z1_log2_standard_deviation,
            ),
            (
                TboxGaussianFieldForTest::Z21,
                layout.z21_polynomial_count,
                layout.z21_log2_standard_deviation,
            ),
            (
                TboxGaussianFieldForTest::Z3,
                layout.z3_polynomial_count,
                layout.z3_log2_standard_deviation,
            ),
            (
                TboxGaussianFieldForTest::Z4,
                layout.z4_polynomial_count,
                layout.z4_log2_standard_deviation,
            ),
        ] {
            let coefficient_count = polynomial_count
                .checked_mul(layout.proof_ring_degree)
                .ok_or_else(|| setup_proof_error("test gaussian count overflowed"))?;
            for coefficient_index in 0..coefficient_count {
                if suffix_profile == TboxSuffixProfileForTest::NonzeroGaussian
                    && coefficient_index == 0
                {
                    write_gaussian_coefficient_for_test(&mut writer, log2_standard_deviation, 2, 3);
                } else if suffix_profile == TboxSuffixProfileForTest::NonzeroZ3AboveBound
                    && field == TboxGaussianFieldForTest::Z3
                    && coefficient_index == 0
                {
                    write_gaussian_coefficient_for_test(
                        &mut writer,
                        log2_standard_deviation,
                        41,
                        0,
                    );
                } else if suffix_profile == TboxSuffixProfileForTest::NonzeroZ4AboveBound
                    && field == TboxGaussianFieldForTest::Z4
                    && coefficient_index == 0
                {
                    write_gaussian_coefficient_for_test(
                        &mut writer,
                        log2_standard_deviation,
                        25,
                        0,
                    );
                } else {
                    write_gaussian_coefficient_for_test(&mut writer, log2_standard_deviation, 0, 0);
                }
            }
        }
        writer.finish_lazer_padding();

        Ok(writer.into_bytes())
    }

    fn write_gaussian_coefficient_for_test(
        writer: &mut LnpBitWriterForTest,
        log2_standard_deviation: usize,
        unary_ones: usize,
        low_bits: u64,
    ) {
        for _ in 0..unary_ones {
            writer.write_bit(true);
        }
        writer.write_bit(false);
        writer.write_u64_le_bits(low_bits, log2_standard_deviation + 1);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TboxSuffixProfileForTest {
        Generated,
        NonzeroHint,
        NonzeroGaussian,
        NonzeroZ3AboveBound,
        NonzeroZ4AboveBound,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TboxGaussianFieldForTest {
        Z1,
        Z21,
        Z3,
        Z4,
    }

    fn encode_uniform_polyvec_for_test(
        writer: &mut LnpBitWriterForTest,
        polynomial_count: usize,
        proof_ring_degree: usize,
        bit_count: usize,
        first_residue_override: Option<BigUint>,
        force_lnp_tbox_h_zero_positions: bool,
    ) -> CanonicalResult<()> {
        let coefficient_count = polynomial_count
            .checked_mul(proof_ring_degree)
            .ok_or_else(|| setup_proof_error("test uniform count overflowed"))?;
        for coefficient_index in 0..coefficient_count {
            if force_lnp_tbox_h_zero_positions
                && setup_proof_lnp_tbox_h_coefficient_must_be_zero(
                    coefficient_index,
                    proof_ring_degree,
                )
            {
                writer.write_u64_le_bits(0, bit_count);
                continue;
            }
            if coefficient_index == 0
                && let Some(value) = first_residue_override.as_ref()
            {
                writer.write_big_uint_le_bits(value, bit_count);
                continue;
            }
            writer.write_u64_le_bits(
                u64::try_from(coefficient_index)
                    .map_err(|_| setup_proof_error("test coefficient index overflowed"))?,
                bit_count,
            );
        }

        Ok(())
    }

    struct LnpBitWriterForTest {
        bytes: Vec<u8>,
        bit_offset: usize,
    }

    impl LnpBitWriterForTest {
        fn new() -> Self {
            Self {
                bytes: vec![0],
                bit_offset: 0,
            }
        }

        fn write_bit(&mut self, bit: bool) {
            let byte_index = self.bit_offset / 8;
            let bit_index = self.bit_offset % 8;
            if byte_index == self.bytes.len() {
                self.bytes.push(0);
            }
            if bit {
                self.bytes[byte_index] |= 1 << bit_index;
            }
            self.bit_offset += 1;
        }

        fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) {
            for bit_index in 0..bit_count {
                let bit = if bit_index < u64::BITS as usize {
                    ((value >> bit_index) & 1) == 1
                } else {
                    false
                };
                self.write_bit(bit);
            }
        }

        fn write_big_uint_le_bits(&mut self, value: &BigUint, bit_count: usize) {
            let digits = value.to_u64_digits();
            for bit_index in 0..bit_count {
                let digit_index = bit_index / 64;
                let digit_bit_index = bit_index % 64;
                let bit = digits
                    .get(digit_index)
                    .map(|digit| ((digit >> digit_bit_index) & 1) == 1)
                    .unwrap_or(false);
                self.write_bit(bit);
            }
        }

        fn finish_lazer_padding(&mut self) {
            self.write_bit(true);
            while !self.bit_offset.is_multiple_of(8) {
                self.write_bit(false);
            }
        }

        fn bytes(&self) -> &[u8] {
            &self.bytes[..self.bit_offset.div_ceil(8)]
        }

        fn into_bytes(mut self) -> Vec<u8> {
            let used_bytes = self.bit_offset.div_ceil(8);
            self.bytes.truncate(used_bytes);
            self.bytes
        }
    }
}
