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

#[cfg(test)]
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
