use super::super::extension_field::{ChallengeExtensionElement, ChallengeExtensionTower};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::relation::{
    CompactVssShareLinkagePublicVectorInput, LimbColumnLayout, SumcheckErrorWeights,
    TrusteeEvaluationKeyStatement, build_compact_vss_share_linkage_public_vectors,
    build_linkage_public_vectors, build_private_vss_public_vectors,
};
use super::super::*;
use super::polynomial::{extension_powers, negacyclic_transpose_product_extension_matrix};
use crate::bgv::modular_arithmetic::pow_mod;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT,
};

// Public per-limb sumcheck vectors, shared by prover and verifier: per
// repetition the combined secret factor and power vector, the consistency
// vectors, the mask selector combinations, the per-repetition error weights,
// and the combined lincheck sum.
pub(in super::super) struct LimbPublicVectors {
    pub(in super::super) secret_factor: Vec<Vec<ChallengeExtensionElement>>,
    pub(in super::super) u_powers: Vec<Vec<ChallengeExtensionElement>>,
    pub(in super::super) mask_selectors: Vec<Vec<ChallengeExtensionElement>>,
    // Linkage pair vectors in SumcheckPublicEvaluations order, empty outside
    // the commitment fields.
    pub(in super::super) linkage_vectors: Vec<Vec<ChallengeExtensionElement>>,
    pub(in super::super) error_weights: SumcheckErrorWeights,
    pub(in super::super) lincheck_claim: ChallengeExtensionElement,
}

pub(in super::super) struct LimbChallenges {
    pub(in super::super) gamma_by_key: Vec<ChallengeExtensionElement>,
    pub(in super::super) lincheck_challenges: Vec<ChallengeExtensionElement>,
    pub(in super::super) lincheck_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) linkage_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) consistency_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) beta: Vec<ChallengeExtensionElement>,
}

pub(in super::super) fn draw_limb_challenges(
    transcript: &mut FiatShamirTranscript,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> LimbChallenges {
    let mut gamma_by_key = Vec::with_capacity(layout.active_keys.len());
    for _ in 0..layout.active_keys.len() {
        gamma_by_key.push(transcript.challenge_nonzero_extension_element("gamma", modulus));
    }
    let mut lincheck_challenges = Vec::with_capacity(LINCHECK_REPETITIONS);
    for _ in 0..LINCHECK_REPETITIONS {
        lincheck_challenges
            .push(transcript.challenge_nonzero_extension_element("lincheck-u", modulus));
    }
    let lincheck_alpha = transcript.challenge_extension_elements(
        "lincheck-alpha",
        modulus,
        layout.active_keys.len() * LINCHECK_REPETITIONS,
    );
    let linkage_alpha = if layout.private_vss_active() {
        transcript.challenge_extension_elements(
            "private-vss-relation-alpha",
            modulus,
            layout.private_vss_relation_count() * LINCHECK_REPETITIONS,
        )
    } else if layout.compact_vss_active() {
        transcript.challenge_extension_elements(
            "compact-vss-share-linkage-alpha",
            modulus,
            layout.compact_vss_relation_count(),
        )
    } else if layout.linkage_active() {
        let commitment_count =
            layout.linkage_randomness_columns / SETUP_COMMITMENT_RANDOMNESS_WIDTH;
        transcript.challenge_extension_elements(
            "linkage-alpha",
            modulus,
            commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS,
        )
    } else {
        Vec::new()
    };
    let consistency_alpha =
        transcript.challenge_extension_elements("consistency-alpha", modulus, layout.claim_count());
    let beta = transcript.challenge_extension_elements(
        "beta",
        modulus,
        layout.row_check_constraint_count(),
    );

    LimbChallenges {
        gamma_by_key,
        lincheck_challenges,
        lincheck_alpha,
        linkage_alpha,
        consistency_alpha,
        beta,
    }
}

pub(in super::super) fn build_limb_public_vectors(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    limb_index: usize,
    modulus: u64,
    challenges: &LimbChallenges,
    masked_claims: &[u64],
) -> CanonicalResult<LimbPublicVectors> {
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let ring_degree = statement.ring_degree;
    let u_powers = challenges
        .lincheck_challenges
        .iter()
        .map(|challenge| extension_powers(&tower, challenge, ring_degree))
        .collect::<Vec<_>>();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    if layout.private_vss_active() {
        let private_vss_share = statement.private_vss_share.as_ref().ok_or_else(|| {
            invalid_succinct_setup_proof("private VSS layout requires a private VSS statement")
        })?;
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..CLAIM_MASK_DIGIT_COUNT {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight =
                    tower.scale_base(alpha_value, pow_mod(2, digit_index as u64, modulus)?);
                mask_selectors[column][position] =
                    tower.add(&mask_selectors[column][position], &digit_weight);
            }
        }
        let (private_vss_claim, relation_vectors) = build_private_vss_public_vectors(
            private_vss_share,
            limb_index,
            &tower,
            &u_powers,
            &challenges.linkage_alpha,
        )?;
        combined_claim = tower.add(&combined_claim, &private_vss_claim);

        return Ok(LimbPublicVectors {
            secret_factor: Vec::new(),
            u_powers,
            mask_selectors,
            linkage_vectors: relation_vectors,
            error_weights: SumcheckErrorWeights {
                weights: vec![Vec::new(); LINCHECK_REPETITIONS],
            },
            lincheck_claim: combined_claim,
        });
    }
    if layout.compact_vss_active() {
        let compact_vss_share_linkage =
            statement
                .compact_vss_share_linkage
                .as_ref()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "compact VSS layout requires a compact share-linkage statement",
                    )
                })?;
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..CLAIM_MASK_DIGIT_COUNT {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight =
                    tower.scale_base(alpha_value, pow_mod(2, digit_index as u64, modulus)?);
                mask_selectors[column][position] =
                    tower.add(&mask_selectors[column][position], &digit_weight);
            }
        }
        let (compact_vss_claim, relation_vectors) = build_compact_vss_share_linkage_public_vectors(
            CompactVssShareLinkagePublicVectorInput {
                public_matrix_seed_hash: &compact_vss_share_linkage.public_matrix_seed_hash,
                rns_limb_index: compact_vss_share_linkage.source_rns_limb_index,
                commitment_modulus_index: limb_index,
                modulus,
                source_message_modulus: compact_vss_share_linkage.source_message_modulus,
                recipient_roster_position: compact_vss_share_linkage.recipient_roster_position,
                ring_degree,
                coefficient_commitments: &compact_vss_share_linkage.coefficient_commitments,
                recipient_share_commitment: &compact_vss_share_linkage.recipient_share_commitment,
                relation_alpha: &challenges.linkage_alpha,
            },
            &tower,
        )?;
        combined_claim = tower.add(&combined_claim, &compact_vss_claim);

        return Ok(LimbPublicVectors {
            secret_factor: Vec::new(),
            u_powers,
            mask_selectors,
            linkage_vectors: relation_vectors,
            error_weights: SumcheckErrorWeights {
                weights: vec![Vec::new(); LINCHECK_REPETITIONS],
            },
            lincheck_claim: combined_claim,
        });
    }
    let mut secret_factor = vec![extension_zero_vector(); LINCHECK_REPETITIONS];
    let mut error_weights = vec![
        vec![ChallengeExtensionTower::zero(); layout.total_error_columns];
        LINCHECK_REPETITIONS
    ];
    let mut lincheck_claim = ChallengeExtensionTower::zero();
    let mut error_cursor = 0_usize;
    for (key_position, (key_index, digit_count)) in layout.active_keys.iter().enumerate() {
        let key = &statement.keys[*key_index];
        let gamma = &challenges.gamma_by_key[key_position];
        let gamma_powers = extension_powers(&tower, gamma, *digit_count);
        // Combined public sample and component vector for this key at this
        // limb, gamma-weighted into the challenge extension.
        let mut combined_public_sample = extension_zero_vector();
        let mut combined_component = extension_zero_vector();
        for (digit_index, gamma_power) in gamma_powers.iter().enumerate() {
            let public_sample = key.public_sample(digit_index, modulus, ring_degree);
            let component = &key.component_b_by_digit[digit_index][limb_index];
            for coefficient_index in 0..ring_degree {
                combined_public_sample[coefficient_index] = tower.add(
                    &combined_public_sample[coefficient_index],
                    &tower.scale_base(gamma_power, public_sample[coefficient_index]),
                );
                combined_component[coefficient_index] = tower.add(
                    &combined_component[coefficient_index],
                    &tower.scale_base(gamma_power, component[coefficient_index]),
                );
            }
        }
        for (repetition, u_power_vector) in u_powers.iter().enumerate() {
            let alpha_value =
                &challenges.lincheck_alpha[key_position * LINCHECK_REPETITIONS + repetition];
            let v_vector = negacyclic_transpose_product_extension_matrix(
                &tower,
                &combined_public_sample,
                u_power_vector,
                modulus,
            )?;
            if key.kind.has_diagonal_source() {
                let diagonal_vector =
                    key.diagonal_source_vector_extension(limb_index, u_power_vector, modulus)?;
                let gamma_limb_power = &gamma_powers[limb_index];
                for coefficient_index in 0..ring_degree {
                    let factor = tower.sub(
                        &v_vector[coefficient_index],
                        &tower.mul(gamma_limb_power, &diagonal_vector[coefficient_index]),
                    );
                    secret_factor[repetition][coefficient_index] = tower.add(
                        &secret_factor[repetition][coefficient_index],
                        &tower.mul(alpha_value, &factor),
                    );
                }
            } else {
                for (secret_factor_value, v_value) in
                    secret_factor[repetition].iter_mut().zip(v_vector.iter())
                {
                    *secret_factor_value =
                        tower.add(secret_factor_value, &tower.mul(alpha_value, v_value));
                }
            }
            let mut component_dot = ChallengeExtensionTower::zero();
            for (u_value, component_value) in u_power_vector.iter().zip(combined_component.iter()) {
                component_dot = tower.add(&component_dot, &tower.mul(u_value, component_value));
            }
            let lincheck_sum = tower.sub(&ChallengeExtensionTower::zero(), &component_dot);
            lincheck_claim = tower.add(&lincheck_claim, &tower.mul(alpha_value, &lincheck_sum));
            for (digit_index, gamma_power) in gamma_powers.iter().enumerate() {
                error_weights[repetition][error_cursor + digit_index] =
                    tower.mul(alpha_value, gamma_power);
            }
        }
        error_cursor += digit_count;
    }
    // Mask selector combinations: each claim contributes alpha' * 2^digit at
    // its mask slots, and alpha' * masked claim to the combined sum.
    let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
    let mut combined_claim = lincheck_claim;
    for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
        combined_claim = tower.add(
            &combined_claim,
            &tower.scale_base(alpha_value, masked_claims[local_claim]),
        );
        for digit_index in 0..CLAIM_MASK_DIGIT_COUNT {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            let position = half * layout.trace_size + half_position;
            let digit_weight =
                tower.scale_base(alpha_value, pow_mod(2, digit_index as u64, modulus)?);
            mask_selectors[column][position] =
                tower.add(&mask_selectors[column][position], &digit_weight);
        }
    }

    let mut linkage_vectors = Vec::new();
    if layout.linkage_active() {
        let linkage = statement.same_secret_linkage.as_ref().ok_or_else(|| {
            invalid_succinct_setup_proof(
                "limb layout expects a same-secret linkage on the statement",
            )
        })?;
        let (linkage_claim, vectors) = build_linkage_public_vectors(
            linkage,
            limb_index,
            &tower,
            &u_powers,
            &challenges.linkage_alpha,
        )?;
        combined_claim = tower.add(&combined_claim, &linkage_claim);
        linkage_vectors = vectors;
    }

    Ok(LimbPublicVectors {
        secret_factor,
        u_powers,
        mask_selectors,
        linkage_vectors,
        error_weights: SumcheckErrorWeights {
            weights: error_weights,
        },
        lincheck_claim: combined_claim,
    })
}
