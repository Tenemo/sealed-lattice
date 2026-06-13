use super::*;

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

pub(super) fn setup_proof_lnp_tbox_z34_challenge_profile_value(
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

pub(in crate::bgv::setup) fn setup_proof_lnp_tbox_byte_layout_profile_value() -> Value {
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
