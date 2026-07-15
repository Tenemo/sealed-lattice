use super::super::invalid_succinct_setup_proof;
use super::family_shape_and_validation::validate_context_token;
use super::key_relation_algebra::public_key_switch_sample;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentValue,
};
use crate::encoding::CanonicalResult;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EvaluationKeyShareKind {
    RelinearizationRoundOne,
    RelinearizationRoundTwo,
    GaloisRotation { galois_element: usize },
}

impl EvaluationKeyShareKind {
    pub(crate) fn tag_bytes(self) -> [u8; 9] {
        let mut bytes = [0_u8; 9];
        match self {
            Self::RelinearizationRoundOne => bytes[0] = 1,
            Self::RelinearizationRoundTwo => bytes[0] = 2,
            Self::GaloisRotation { galois_element } => {
                bytes[0] = 3;
                bytes[1..].copy_from_slice(&(galois_element as u64).to_le_bytes());
            }
        }
        bytes
    }

    pub(crate) fn has_diagonal_source(self) -> bool {
        true
    }
}

pub(crate) struct EvaluationKeyShareDescriptor {
    pub(crate) kind: EvaluationKeyShareKind,
    pub(crate) level: usize,
    pub(crate) key_switch_domain: String,
    pub(crate) key_switch_seed_hex: String,
    pub(crate) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(crate) round_one_aggregate_diagonal: Vec<Vec<u64>>,
}

#[derive(Clone)]
pub(crate) struct SameSecretLinkageStatement {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) commitments: Vec<SetupCommitmentValue>,
}

pub(crate) struct PrivateVssShareStatement {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) private_envelope_aad_hash: String,
    pub(crate) source_trustee_identity: String,
    pub(crate) source_trustee_roster_position: u64,
    pub(crate) recipient_identity: String,
    pub(crate) recipient_roster_position: u64,
    pub(crate) source_trustee_commitment_root: String,
    pub(crate) source_rns_limb_index: usize,
    pub(crate) share_values: Vec<u64>,
    pub(crate) coefficient_commitment_roots: Vec<String>,
    pub(crate) coefficient_commitments: Vec<SetupCommitmentValue>,
}

#[derive(Clone)]
pub(crate) struct VssShareLinkageCommitment {
    pub(crate) commitment_context_hash: String,
    pub(crate) material_root: super::super::merkle_commitment::MerkleDigest,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SuccinctSetupProofContext {
    pub(crate) setup_context_hash: String,
    pub(crate) trustee_identity: String,
    pub(crate) trustee_roster_position: u64,
    pub(crate) binding_roots: Vec<String>,
}

pub(crate) enum SetupProofStatement {
    PrivateVssShare(PrivateVssShareStatement),
    TrusteeEvaluationKey {
        keys: Vec<EvaluationKeyShareDescriptor>,
        same_secret_linkage: SameSecretLinkageStatement,
    },
}

pub(crate) struct TrusteeEvaluationKeyStatement {
    pub(crate) context: SuccinctSetupProofContext,
    pub(crate) ring_degree: usize,
    pub(crate) proof: SetupProofStatement,
}

impl TrusteeEvaluationKeyStatement {
    pub(crate) fn application_statement_schema_identifier(&self) -> u16 {
        match &self.proof {
            SetupProofStatement::PrivateVssShare(_) => 0x2110,
            SetupProofStatement::TrusteeEvaluationKey { .. } => 0x1216,
        }
    }
}

pub(crate) struct KeyBearingWitness {
    pub(crate) secret_coefficients: Vec<i64>,
    pub(crate) error_coefficients_by_key: Vec<Vec<Vec<i64>>>,
}

pub(crate) struct SameSecretLinkageWitness {
    pub(crate) negative_indicator_coefficients: Vec<i64>,
    pub(crate) opening_randomness_by_limb: Vec<Vec<Vec<i64>>>,
}

pub(crate) enum TrusteeEvaluationKeyWitness {
    PrivateVssShare {
        coefficient_messages_by_shamir_index: Vec<Vec<i64>>,
        opening_randomness_by_shamir_index: Vec<Vec<Vec<i64>>>,
        carry_witnesses: Vec<i64>,
    },
    TrusteeEvaluationKey {
        key: KeyBearingWitness,
        linkage: SameSecretLinkageWitness,
    },
}

impl TrusteeEvaluationKeyStatement {
    pub(crate) fn keys(&self) -> &[EvaluationKeyShareDescriptor] {
        match &self.proof {
            SetupProofStatement::PrivateVssShare(_) => &[],
            SetupProofStatement::TrusteeEvaluationKey { keys, .. } => keys,
        }
    }

    #[cfg(test)]
    pub(crate) fn keys_mut(&mut self) -> &mut [EvaluationKeyShareDescriptor] {
        match &mut self.proof {
            SetupProofStatement::PrivateVssShare(_) => &mut [],
            SetupProofStatement::TrusteeEvaluationKey { keys, .. } => keys,
        }
    }

    pub(crate) fn same_secret_linkage(&self) -> Option<&SameSecretLinkageStatement> {
        match &self.proof {
            SetupProofStatement::TrusteeEvaluationKey {
                same_secret_linkage,
                ..
            } => Some(same_secret_linkage),
            SetupProofStatement::PrivateVssShare(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn same_secret_linkage_mut(&mut self) -> Option<&mut SameSecretLinkageStatement> {
        match &mut self.proof {
            SetupProofStatement::TrusteeEvaluationKey {
                same_secret_linkage,
                ..
            } => Some(same_secret_linkage),
            SetupProofStatement::PrivateVssShare(_) => None,
        }
    }

    pub(crate) fn private_vss_share(&self) -> Option<&PrivateVssShareStatement> {
        match &self.proof {
            SetupProofStatement::PrivateVssShare(statement) => Some(statement),
            SetupProofStatement::TrusteeEvaluationKey { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn private_vss_share_mut(&mut self) -> Option<&mut PrivateVssShareStatement> {
        match &mut self.proof {
            SetupProofStatement::PrivateVssShare(statement) => Some(statement),
            SetupProofStatement::TrusteeEvaluationKey { .. } => None,
        }
    }
}

impl TrusteeEvaluationKeyWitness {
    pub(crate) fn secret_coefficients(&self) -> &[i64] {
        match self {
            Self::PrivateVssShare { .. } => &[],
            Self::TrusteeEvaluationKey { key, .. } => &key.secret_coefficients,
        }
    }

    #[cfg(test)]
    pub(crate) fn secret_coefficients_mut(&mut self) -> &mut [i64] {
        match self {
            Self::PrivateVssShare { .. } => &mut [],
            Self::TrusteeEvaluationKey { key, .. } => &mut key.secret_coefficients,
        }
    }

    pub(crate) fn error_coefficients_by_key(&self) -> &[Vec<Vec<i64>>] {
        match self {
            Self::PrivateVssShare { .. } => &[],
            Self::TrusteeEvaluationKey { key, .. } => &key.error_coefficients_by_key,
        }
    }

    pub(crate) fn negative_indicator_coefficients(&self) -> &[i64] {
        match self {
            Self::PrivateVssShare { .. } => &[],
            Self::TrusteeEvaluationKey { linkage, .. } => {
                &linkage.negative_indicator_coefficients
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn negative_indicator_coefficients_mut(&mut self) -> &mut [i64] {
        match self {
            Self::PrivateVssShare { .. } => &mut [],
            Self::TrusteeEvaluationKey { linkage, .. } => {
                &mut linkage.negative_indicator_coefficients
            }
        }
    }

    pub(crate) fn opening_randomness_by_limb(&self) -> &[Vec<Vec<i64>>] {
        match self {
            Self::PrivateVssShare { .. } => &[],
            Self::TrusteeEvaluationKey { linkage, .. } => &linkage.opening_randomness_by_limb,
        }
    }

    #[cfg(test)]
    pub(crate) fn opening_randomness_by_limb_mut(&mut self) -> &mut [Vec<Vec<i64>>] {
        match self {
            Self::PrivateVssShare { .. } => &mut [],
            Self::TrusteeEvaluationKey { linkage, .. } => {
                &mut linkage.opening_randomness_by_limb
            }
        }
    }

    pub(crate) fn private_vss_coefficient_messages_by_shamir_index(&self) -> &[Vec<i64>] {
        match self {
            Self::PrivateVssShare {
                coefficient_messages_by_shamir_index,
                ..
            } => coefficient_messages_by_shamir_index,
            Self::TrusteeEvaluationKey { .. } => &[],
        }
    }

    pub(crate) fn private_vss_opening_randomness_by_shamir_index(&self) -> &[Vec<Vec<i64>>] {
        match self {
            Self::PrivateVssShare {
                opening_randomness_by_shamir_index,
                ..
            } => opening_randomness_by_shamir_index,
            Self::TrusteeEvaluationKey { .. } => &[],
        }
    }

    pub(crate) fn private_vss_carry_witnesses(&self) -> &[i64] {
        match self {
            Self::PrivateVssShare {
                carry_witnesses, ..
            } => carry_witnesses,
            Self::TrusteeEvaluationKey { .. } => &[],
        }
    }
}

impl EvaluationKeyShareDescriptor {
    pub(crate) fn digit_count(&self) -> usize {
        self.level + 1
    }

    fn limb_width(&self) -> usize {
        self.level + 1
    }

    pub(crate) fn validate_shape(&self, ring_degree: usize) -> CanonicalResult<()> {
        validate_context_token("keySwitchDomain", &self.key_switch_domain)?;
        validate_context_token("keySwitchSeedHex", &self.key_switch_seed_hex)?;
        if self.level + 1 > DATA_PRIMES.len() {
            return Err(invalid_succinct_setup_proof(
                "key level is outside the selected data basis",
            ));
        }
        if self.component_b_by_digit.len() != self.digit_count()
            || self.component_b_by_digit.iter().any(|by_limb| {
                by_limb.len() != self.limb_width()
                    || by_limb
                        .iter()
                        .any(|component| component.len() != ring_degree)
            })
        {
            return Err(invalid_succinct_setup_proof(
                "key component material shape does not match its level and ring degree",
            ));
        }
        for component_b_by_limb in &self.component_b_by_digit {
            for (rns_limb_index, component_b) in component_b_by_limb.iter().enumerate() {
                let modulus = DATA_PRIMES[rns_limb_index];
                if component_b.iter().any(|coefficient| *coefficient >= modulus) {
                    return Err(invalid_succinct_setup_proof(
                        "key component material contains noncanonical Q_share residues",
                    ));
                }
            }
        }
        match self.kind {
            EvaluationKeyShareKind::RelinearizationRoundOne => {
                if !self.round_one_aggregate_diagonal.is_empty() {
                    return Err(invalid_succinct_setup_proof(
                        "round-one key must not carry a round-one aggregate diagonal",
                    ));
                }
            }
            EvaluationKeyShareKind::RelinearizationRoundTwo => {
                if self.round_one_aggregate_diagonal.len() != self.digit_count() {
                    return Err(invalid_succinct_setup_proof(
                        "round-two key requires one aggregate diagonal per digit",
                    ));
                }
                for (digit_index, aggregate) in self.round_one_aggregate_diagonal.iter().enumerate()
                {
                    if aggregate.len() != ring_degree
                        || aggregate
                            .iter()
                            .any(|value| *value >= DATA_PRIMES[digit_index])
                    {
                        return Err(invalid_succinct_setup_proof(
                            "round-two aggregate diagonal shape or residue is out of range",
                        ));
                    }
                }
            }
            EvaluationKeyShareKind::GaloisRotation { galois_element } => {
                if !self.round_one_aggregate_diagonal.is_empty() {
                    return Err(invalid_succinct_setup_proof(
                        "Galois key must not carry a round-one aggregate diagonal",
                    ));
                }
                if galois_element.is_multiple_of(2) || galois_element <= 1 {
                    return Err(invalid_succinct_setup_proof(
                        "Galois element must be a nontrivial odd element",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn public_sample(
        &self,
        digit_index: usize,
        modulus: u64,
        ring_degree: usize,
    ) -> CanonicalResult<Vec<u64>> {
        Ok(public_key_switch_sample(
            &self.key_switch_domain,
            &self.key_switch_seed_hex,
            digit_index,
            modulus,
            ring_degree,
        ))
    }
}

impl TrusteeEvaluationKeyStatement {
    pub(crate) fn limb_count(&self) -> usize {
        if self.private_vss_share().is_some() {
            return SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
        }
        self.keys()
            .iter()
            .map(|key| key.level + 1)
            .chain(
                self.same_secret_linkage()
                    .map(|_| SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()),
            )
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn proof_limb_indices(&self) -> Vec<usize> {
        (0..self.limb_count()).collect()
    }

    #[cfg(test)]
    pub(crate) fn limb_moduli(&self) -> Vec<u64> {
        self.proof_limb_indices()
            .into_iter()
            .map(|limb_index| DATA_PRIMES[limb_index])
            .collect()
    }

    pub(crate) fn proof_limb_count(&self) -> usize {
        self.limb_count()
    }

    pub(crate) fn active_key_indices(&self, limb_index: usize) -> Vec<usize> {
        self.keys()
            .iter()
            .enumerate()
            .filter(|(_, key)| key.level >= limb_index)
            .map(|(key_index, _)| key_index)
            .collect()
    }

    pub(crate) fn linkage_randomness_count(&self, limb_index: usize) -> usize {
        if limb_index >= SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
            return 0;
        }
        self.same_secret_linkage()
            .map(|linkage| linkage.commitments.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .unwrap_or(0)
    }

    pub(crate) fn private_vss_randomness_count(&self, limb_index: usize) -> usize {
        match self.private_vss_share() {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.coefficient_commitments.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH
            }
            _ => 0,
        }
    }
}
