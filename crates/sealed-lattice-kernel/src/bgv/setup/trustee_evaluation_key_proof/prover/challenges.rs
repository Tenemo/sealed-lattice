use super::super::extension_field::{ChallengeExtensionElement, ChallengeExtensionTower};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::relation::{
    LimbColumnLayout, SameSecretBridgePublicVectorInput, SumcheckErrorWeights,
    TargetDecryptionSharePublicVectorInput, TrusteeEvaluationKeyStatement,
    build_linkage_public_vectors, build_private_vss_public_vectors,
    build_same_secret_bridge_public_vectors, build_target_decryption_share_public_vectors,
    build_vss_share_linkage_batch_public_vectors,
};
use super::super::{CLAIM_MASK_RADIX, LINCHECK_REPETITIONS, invalid_succinct_setup_proof};
use super::polynomial::{extension_powers, negacyclic_transpose_product_extension_matrix};
use crate::bgv::modular_arithmetic::pow_mod;
use crate::encoding::CanonicalResult;

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
    pub(in super::super) same_secret_bridge_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) consistency_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) beta: Vec<ChallengeExtensionElement>,
}

fn build_combined_same_secret_bridge_public_vectors(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    limb_index: usize,
    modulus: u64,
    challenges: &LimbChallenges,
    u_power_vectors: &[Vec<ChallengeExtensionElement>],
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    let same_secret_bridge = statement.same_secret_bridge().ok_or_else(|| {
        invalid_succinct_setup_proof("limb layout expects a same-secret bridge statement")
    })?;
    let (bridge_claim, mut combined_vectors) = build_same_secret_bridge_public_vectors(
        SameSecretBridgePublicVectorInput {
            modulus,
            ring_degree: layout.ring_degree,
            bridge_rns_primes: &same_secret_bridge.bridge_rns_primes,
            target_constant_commitments: &same_secret_bridge.target_constant_commitments,
            relation_alpha: &challenges.same_secret_bridge_alpha,
            u_power_vectors,
        },
        tower,
    )?;
    if !layout.linkage_active() {
        return Ok((bridge_claim, combined_vectors));
    }

    let linkage = statement.same_secret_linkage().ok_or_else(|| {
        invalid_succinct_setup_proof(
            "same-secret bridge layout expects the source commitment linkage",
        )
    })?;
    let (linkage_claim, linkage_vectors) = build_linkage_public_vectors(
        linkage,
        limb_index,
        tower,
        u_power_vectors,
        &challenges.linkage_alpha,
    )?;
    if combined_vectors.len() < 2 || linkage_vectors.len() < 2 {
        return Err(invalid_succinct_setup_proof(
            "same-secret bridge public vectors are missing their shared secret columns",
        ));
    }
    for shared_vector_index in 0..2 {
        for (combined_value, linkage_value) in combined_vectors[shared_vector_index]
            .iter_mut()
            .zip(linkage_vectors[shared_vector_index].iter())
        {
            *combined_value = tower.add(combined_value, linkage_value);
        }
    }
    combined_vectors.extend(linkage_vectors.into_iter().skip(2));

    Ok((tower.add(&bridge_claim, &linkage_claim), combined_vectors))
}

fn mask_digit_weight(
    tower: &ChallengeExtensionTower,
    alpha_value: &ChallengeExtensionElement,
    digit_index: usize,
) -> CanonicalResult<ChallengeExtensionElement> {
    Ok(tower.scale_base(
        alpha_value,
        pow_mod(CLAIM_MASK_RADIX, digit_index as u64, tower.modulus)?,
    ))
}

pub(in super::super) fn draw_limb_challenges(
    transcript: &mut FiatShamirTranscript,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> CanonicalResult<LimbChallenges> {
    let mut gamma_by_key = Vec::with_capacity(layout.active_keys.len());
    for _ in 0..layout.active_keys.len() {
        gamma_by_key.push(transcript.challenge_nonzero_extension_element("gamma", modulus)?);
    }
    let mut lincheck_challenges = Vec::with_capacity(LINCHECK_REPETITIONS);
    for _ in 0..LINCHECK_REPETITIONS {
        lincheck_challenges
            .push(transcript.challenge_nonzero_extension_element("lincheck-u", modulus)?);
    }
    let lincheck_alpha = transcript.challenge_extension_elements(
        "lincheck-alpha",
        modulus,
        layout.active_keys.len() * LINCHECK_REPETITIONS,
    )?;
    let same_secret_bridge_alpha = if layout.same_secret_bridge_material_active() {
        transcript.challenge_extension_elements(
            "same-secret-bridge-alpha",
            modulus,
            layout.same_secret_bridge_relation_count(),
        )?
    } else {
        Vec::new()
    };
    let linkage_alpha = if layout.private_vss_active() {
        transcript.challenge_extension_elements(
            "private-vss-relation-alpha",
            modulus,
            layout.private_vss_relation_count() * LINCHECK_REPETITIONS,
        )?
    } else if layout.vss_public_active() {
        transcript.challenge_extension_elements(
            "vss-share-linkage-alpha",
            modulus,
            layout.vss_public_relation_count(),
        )?
    } else if layout.target_decryption_active() {
        transcript.challenge_extension_elements(
            "target-decryption-share-alpha",
            modulus,
            layout.target_decryption_relation_count,
        )?
    } else if layout.linkage_active() {
        let challenge_label = if layout.same_secret_bridge_material_active() {
            "same-secret-source-linkage-alpha"
        } else {
            "linkage-alpha"
        };
        transcript.challenge_extension_elements(
            challenge_label,
            modulus,
            layout.linkage_relation_count(),
        )?
    } else {
        Vec::new()
    };
    let consistency_alpha = transcript.challenge_extension_elements(
        "consistency-alpha",
        modulus,
        layout.claim_count(),
    )?;
    let beta = transcript.challenge_extension_elements(
        "beta",
        modulus,
        layout.row_check_constraint_count(),
    )?;

    Ok(LimbChallenges {
        gamma_by_key,
        lincheck_challenges,
        lincheck_alpha,
        linkage_alpha,
        same_secret_bridge_alpha,
        consistency_alpha,
        beta,
    })
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
    let ring_degree = layout.ring_degree;
    let u_powers = challenges
        .lincheck_challenges
        .iter()
        .map(|challenge| extension_powers(&tower, challenge, ring_degree))
        .collect::<Vec<_>>();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    if layout.private_vss_active() {
        let private_vss_share = statement.private_vss_share().ok_or_else(|| {
            invalid_succinct_setup_proof("private VSS layout requires a private VSS statement")
        })?;
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..layout.claim_mask_digit_count(local_claim) {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight = mask_digit_weight(&tower, alpha_value, digit_index)?;
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
    if layout.vss_public_active() {
        let vss_share_linkage = statement.vss_share_linkage().ok_or_else(|| {
            invalid_succinct_setup_proof("VSS layout requires a share-linkage statement")
        })?;
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..layout.claim_mask_digit_count(local_claim) {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight = mask_digit_weight(&tower, alpha_value, digit_index)?;
                mask_selectors[column][position] =
                    tower.add(&mask_selectors[column][position], &digit_weight);
            }
        }
        let (vss_public_claim, relation_vectors) = build_vss_share_linkage_batch_public_vectors(
            vss_share_linkage,
            modulus,
            layout.base_ring_degree,
            &challenges.linkage_alpha,
            &u_powers,
            &tower,
        )?;
        combined_claim = tower.add(&combined_claim, &vss_public_claim);

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
    if layout.same_secret_bridge_active() {
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..layout.claim_mask_digit_count(local_claim) {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight = mask_digit_weight(&tower, alpha_value, digit_index)?;
                mask_selectors[column][position] =
                    tower.add(&mask_selectors[column][position], &digit_weight);
            }
        }
        let (bridge_claim, relation_vectors) = build_combined_same_secret_bridge_public_vectors(
            statement, layout, limb_index, modulus, challenges, &u_powers, &tower,
        )?;
        combined_claim = tower.add(&combined_claim, &bridge_claim);

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
    if layout.target_decryption_active() {
        let target_decryption_share =
            statement.target_decryption_share().ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "target-decryption layout requires a target share statement",
                )
            })?;
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..layout.claim_mask_digit_count(local_claim) {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight = mask_digit_weight(&tower, alpha_value, digit_index)?;
                mask_selectors[column][position] =
                    tower.add(&mask_selectors[column][position], &digit_weight);
            }
        }
        let (target_claim, relation_vectors) = build_target_decryption_share_public_vectors(
            TargetDecryptionSharePublicVectorInput {
                proof_statement: statement,
                statement: target_decryption_share,
                limb_index,
                modulus,
                ring_degree,
                relation_alpha: &challenges.linkage_alpha,
                u_power_vectors: &u_powers,
            },
            &tower,
        )?;
        combined_claim = tower.add(&combined_claim, &target_claim);

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
        let key = &statement.keys()[*key_index];
        let gamma = &challenges.gamma_by_key[key_position];
        let gamma_powers = extension_powers(&tower, gamma, *digit_count);
        // Combined public sample and component vector for this key at this
        // limb, gamma-weighted into the challenge extension.
        let mut combined_public_sample = extension_zero_vector();
        let mut combined_component = extension_zero_vector();
        for (digit_index, gamma_power) in gamma_powers.iter().enumerate() {
            let public_sample = key.public_sample(digit_index, modulus, ring_degree)?;
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
            // Diagonal-source kinds are proven by the key-switch atom
            // schedule; the engine's key claims cover the no-diagonal
            // public-key share relation only.
            for (secret_factor_value, v_value) in
                secret_factor[repetition].iter_mut().zip(v_vector.iter())
            {
                *secret_factor_value =
                    tower.add(secret_factor_value, &tower.mul(alpha_value, v_value));
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
    // Mask selector combinations: each claim contributes alpha' * radix^digit at
    // its mask slots, and alpha' * masked claim to the combined sum.
    let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
    let mut combined_claim = lincheck_claim;
    for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
        combined_claim = tower.add(
            &combined_claim,
            &tower.scale_base(alpha_value, masked_claims[local_claim]),
        );
        for digit_index in 0..layout.claim_mask_digit_count(local_claim) {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            let position = half * layout.trace_size + half_position;
            let digit_weight = mask_digit_weight(&tower, alpha_value, digit_index)?;
            mask_selectors[column][position] =
                tower.add(&mask_selectors[column][position], &digit_weight);
        }
    }

    let mut linkage_vectors = Vec::new();
    if layout.same_secret_bridge_material_active() {
        let (bridge_claim, vectors) = build_combined_same_secret_bridge_public_vectors(
            statement, layout, limb_index, modulus, challenges, &u_powers, &tower,
        )?;
        combined_claim = tower.add(&combined_claim, &bridge_claim);
        linkage_vectors = vectors;
    } else if layout.linkage_active() {
        let linkage = statement.same_secret_linkage().ok_or_else(|| {
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
