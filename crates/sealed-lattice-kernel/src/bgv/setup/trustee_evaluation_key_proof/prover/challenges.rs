use super::super::extension_field::{ChallengeExtensionElement, ChallengeExtensionTower};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::relation::{
    LimbColumnLayout, TrusteeEvaluationKeyStatement, build_private_vss_public_vectors,
};
use super::super::{CLAIM_MASK_RADIX, LINCHECK_REPETITIONS, invalid_succinct_setup_proof};
use super::polynomial::extension_powers;
use crate::bgv::modular_arithmetic::pow_mod;
use crate::encoding::CanonicalResult;

pub(in super::super) struct LimbPublicVectors {
    pub(in super::super) mask_selectors: Vec<Vec<ChallengeExtensionElement>>,
    pub(in super::super) private_vss_relation_vectors: Vec<Vec<ChallengeExtensionElement>>,
    pub(in super::super) lincheck_claim: ChallengeExtensionElement,
}

pub(in super::super) struct LimbChallenges {
    pub(in super::super) lincheck_challenges: Vec<ChallengeExtensionElement>,
    pub(in super::super) private_vss_relation_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) consistency_alpha: Vec<ChallengeExtensionElement>,
    pub(in super::super) beta: Vec<ChallengeExtensionElement>,
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
    let mut lincheck_challenges = Vec::with_capacity(LINCHECK_REPETITIONS);
    for _ in 0..LINCHECK_REPETITIONS {
        lincheck_challenges
            .push(transcript.challenge_nonzero_extension_element("lincheck-u", modulus)?);
    }
    let private_vss_relation_alpha = transcript.challenge_extension_elements(
        "private-vss-relation-alpha",
        modulus,
        layout.private_vss_relation_count() * LINCHECK_REPETITIONS,
    )?;
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
        lincheck_challenges,
        private_vss_relation_alpha,
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
    let private_vss_share = statement.private_vss_share().ok_or_else(|| {
        invalid_succinct_setup_proof("private VSS layout requires a private VSS statement")
    })?;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let u_powers = challenges
        .lincheck_challenges
        .iter()
        .map(|challenge| extension_powers(&tower, challenge, layout.ring_degree))
        .collect::<Vec<_>>();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); layout.ring_degree];
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
        &challenges.private_vss_relation_alpha,
    )?;
    combined_claim = tower.add(&combined_claim, &private_vss_claim);

    Ok(LimbPublicVectors {
        mask_selectors,
        private_vss_relation_vectors: relation_vectors,
        lincheck_claim: combined_claim,
    })
}
