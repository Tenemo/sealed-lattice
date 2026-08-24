//! Canonical artifacts owned by the fixed sealed-lattice suite.

#[cfg(test)]
use super::CanonicalDecodeLimits;
#[cfg(test)]
use super::CanonicalItemType;
#[cfg(test)]
use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::SchemaResult;
#[cfg(test)]
use super::schemas::{read_item, read_u16, read_u32, read_u64, require_header};
#[cfg(test)]
use super::suite::{read_unsigned16_list, read_unsigned64_list};
use super::suite::{unsigned16_list, unsigned64_list};
use super::{
    CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, FoundationSchemaError, RefusalReason,
};
use crate::bgv::{
    direct_ballots::{
        PAIR_CHARACTER_AUXILIARY_COUNT, PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT,
        PAIR_CHARACTER_LANE_DEGREE, pair_character_lane_assignments, pair_character_lane_value,
        pair_character_plaintexts,
    },
    evaluator::program::selected_evaluator_program_set,
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    parameters::{
        DATA_PRIMES, PLAINTEXT_EXTENSION_DEGREE, PLAINTEXT_EXTENSION_LANE_COUNT,
        PLAINTEXT_LANE_ORBIT_GENERATOR, PLAINTEXT_LANE_ROOT_GENERATOR, PLAINTEXT_MODULUS,
        POLYNOMIAL_DEGREE, plaintext_extension_lane_root, validate_supported_algebraic_parameters,
    },
    proof_suite::{
        ProofProfileError, ValidatedRelationPlanArtifact, selected_committed_material_profile,
        selected_proof_profile_set, selected_proof_profile_set_from_relation_plans,
        selected_same_secret_relation_plan_input, selected_target_decryption_flooding_bound,
    },
    setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
};
use num_bigint::BigUint;

pub(crate) const ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x1300;
pub(crate) const VERIFIABLE_SECRET_SHARING_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2120;
pub(crate) const COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2121;
pub(crate) const LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2122;
pub(crate) const TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1630;

const SCHEMA_VERSION: u16 = 1;
const ENCODER_AND_BALLOT_LAYOUT_VERSION: u16 = 4;
const LATTICE_COMMITMENT_PROFILE_VERSION: u16 = 3;
const COMMITTED_MATERIAL_PROOF_FIELD_INDEX: u16 = 0;
const LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncoderAndBallotLayout {
    polynomial_degree: u32,
    lane_root_generator: u64,
    lane_orbit_generator: u16,
    extension_degree: u16,
    lane_count: u16,
    ciphertext_count: u16,
    auxiliary_count: u16,
    option_count: u16,
    minimum_score: u16,
    maximum_score: u16,
    pair_difference_rule: u16,
    ordered_pair_character_assignments: Vec<u16>,
}

impl EncoderAndBallotLayout {
    pub(crate) fn selected() -> SchemaResult<Self> {
        Self::for_option_count(FOUNDATION_PROFILE.option_count)
    }

    pub(crate) fn for_option_count(option_count: u16) -> SchemaResult<Self> {
        validate_supported_algebraic_parameters().map_err(|_| invalid_selected_artifact())?;
        let artifact = Self {
            polynomial_degree: u32::try_from(POLYNOMIAL_DEGREE)
                .map_err(|_| invalid_selected_artifact())?,
            lane_root_generator: PLAINTEXT_LANE_ROOT_GENERATOR,
            lane_orbit_generator: u16::try_from(PLAINTEXT_LANE_ORBIT_GENERATOR)
                .map_err(|_| invalid_selected_artifact())?,
            extension_degree: u16::try_from(PLAINTEXT_EXTENSION_DEGREE)
                .map_err(|_| invalid_selected_artifact())?,
            lane_count: u16::try_from(PLAINTEXT_EXTENSION_LANE_COUNT)
                .map_err(|_| invalid_selected_artifact())?,
            ciphertext_count: u16::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT)
                .map_err(|_| invalid_selected_artifact())?,
            auxiliary_count: u16::try_from(PAIR_CHARACTER_AUXILIARY_COUNT)
                .map_err(|_| invalid_selected_artifact())?,
            option_count,
            minimum_score: FOUNDATION_PROFILE.minimum_score,
            maximum_score: FOUNDATION_PROFILE.maximum_score,
            pair_difference_rule: LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE,
            ordered_pair_character_assignments: pair_character_assignment_catalog(option_count)?,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header_with_version(
            &tuple,
            ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER,
            ENCODER_AND_BALLOT_LAYOUT_VERSION,
            12,
        )?;
        let artifact = Self {
            polynomial_degree: read_u32(&tuple.items[0])?,
            lane_root_generator: read_u64(&tuple.items[1])?,
            lane_orbit_generator: read_u16(&tuple.items[2])?,
            extension_degree: read_u16(&tuple.items[3])?,
            lane_count: read_u16(&tuple.items[4])?,
            ciphertext_count: read_u16(&tuple.items[5])?,
            auxiliary_count: read_u16(&tuple.items[6])?,
            option_count: read_u16(&tuple.items[7])?,
            minimum_score: read_u16(&tuple.items[8])?,
            maximum_score: read_u16(&tuple.items[9])?,
            pair_difference_rule: read_u16(&tuple.items[10])?,
            ordered_pair_character_assignments: read_unsigned16_list(&tuple.items[11])?,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub(crate) fn encode(self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER,
            ENCODER_AND_BALLOT_LAYOUT_VERSION,
            vec![
                CanonicalItem::unsigned32(self.polynomial_degree),
                CanonicalItem::unsigned64(self.lane_root_generator),
                CanonicalItem::unsigned16(self.lane_orbit_generator),
                CanonicalItem::unsigned16(self.extension_degree),
                CanonicalItem::unsigned16(self.lane_count),
                CanonicalItem::unsigned16(self.ciphertext_count),
                CanonicalItem::unsigned16(self.auxiliary_count),
                CanonicalItem::unsigned16(self.option_count),
                CanonicalItem::unsigned16(self.minimum_score),
                CanonicalItem::unsigned16(self.maximum_score),
                CanonicalItem::unsigned16(self.pair_difference_rule),
                unsigned16_list(&self.ordered_pair_character_assignments)?,
            ],
        )
        .encode()?)
    }

    fn validate(&self) -> SchemaResult<()> {
        validate_supported_algebraic_parameters().map_err(|_| invalid_selected_artifact())?;
        if usize::try_from(self.polynomial_degree).ok() != Some(POLYNOMIAL_DEGREE)
            || self.lane_root_generator != PLAINTEXT_LANE_ROOT_GENERATOR
            || usize::from(self.lane_orbit_generator) != PLAINTEXT_LANE_ORBIT_GENERATOR
            || usize::from(self.extension_degree) != PLAINTEXT_EXTENSION_DEGREE
            || usize::from(self.extension_degree) != PAIR_CHARACTER_LANE_DEGREE
            || usize::from(self.lane_count) != PLAINTEXT_EXTENSION_LANE_COUNT
            || usize::from(self.lane_count) != PAIR_CHARACTER_LANE_COUNT
            || usize::from(self.ciphertext_count) != PAIR_CHARACTER_CIPHERTEXT_COUNT
            || usize::from(self.auxiliary_count) != PAIR_CHARACTER_AUXILIARY_COUNT
            || !(super::MINIMUM_CONFIGURABLE_OPTION_COUNT
                ..=super::MAXIMUM_CONFIGURABLE_OPTION_COUNT)
                .contains(&self.option_count)
            || self.minimum_score != FOUNDATION_PROFILE.minimum_score
            || self.maximum_score != FOUNDATION_PROFILE.maximum_score
            || self.minimum_score > self.maximum_score
            || self.pair_difference_rule != LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE
            || self.ordered_pair_character_assignments
                != pair_character_assignment_catalog(self.option_count)?
        {
            return Err(invalid_selected_artifact());
        }
        if self.option_count == FOUNDATION_PROFILE.option_count {
            require_pair_character_ballot_codec_layout(self.option_count)?;
        }
        Ok(())
    }
}

fn pair_character_assignment_catalog(option_count: u16) -> SchemaResult<Vec<u16>> {
    Ok(pair_character_lane_assignments(usize::from(option_count))
        .map_err(|_| invalid_selected_artifact())?
        .into_iter()
        .flat_map(|assignment| {
            [
                assignment.ciphertext_ordinal(),
                assignment.lane_ordinal(),
                assignment.lower_option_ordinal(),
                assignment.higher_option_ordinal(),
            ]
        })
        .collect::<Vec<_>>())
}

fn require_pair_character_ballot_codec_layout(option_count: u16) -> SchemaResult<()> {
    let option_count = usize::from(option_count);
    let score_bucket_count = u64::from(
        FOUNDATION_PROFILE
            .maximum_score
            .checked_sub(FOUNDATION_PROFILE.minimum_score)
            .and_then(|score_span| score_span.checked_add(1))
            .ok_or_else(invalid_selected_artifact)?,
    );
    if score_bucket_count < 2 {
        return Err(invalid_selected_artifact());
    }
    let discriminating_scores = (0..option_count)
        .map(|option_ordinal| {
            u64::try_from(option_ordinal)
                .ok()
                .and_then(|ordinal| ordinal.checked_mul(score_bucket_count - 1))
                .map(|offset| offset % score_bucket_count)
                .and_then(|offset| offset.checked_add(u64::from(FOUNDATION_PROFILE.minimum_score)))
                .ok_or_else(invalid_selected_artifact)
        })
        .collect::<SchemaResult<Vec<_>>>()?;
    let plaintexts =
        pair_character_plaintexts(&discriminating_scores, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
            .map_err(|_| invalid_selected_artifact())?;
    let assignments =
        pair_character_lane_assignments(option_count).map_err(|_| invalid_selected_artifact())?;
    for (ciphertext_ordinal, plaintext) in plaintexts
        .iter()
        .enumerate()
        .take(PAIR_CHARACTER_CIPHERTEXT_COUNT)
    {
        for lane_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
            let assignment = assignments.iter().find(|assignment| {
                usize::from(assignment.ciphertext_ordinal()) == ciphertext_ordinal
                    && usize::from(assignment.lane_ordinal()) == lane_ordinal
            });
            let mut expected_message = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
            let mut expected_auxiliary_left = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
            if let Some(assignment) = assignment {
                let lower_score =
                    discriminating_scores[usize::from(assignment.lower_option_ordinal())];
                let higher_score =
                    discriminating_scores[usize::from(assignment.higher_option_ordinal())];
                let score_span =
                    u64::from(FOUNDATION_PROFILE.maximum_score - FOUNDATION_PROFILE.minimum_score);
                expected_message[usize::try_from(lower_score + score_span - higher_score)
                    .map_err(|_| invalid_selected_artifact())?] = 1;
                expected_auxiliary_left[usize::try_from(lower_score + score_span)
                    .map_err(|_| invalid_selected_artifact())?] = 1;
            }
            let observed_message =
                pair_character_lane_value(plaintext.message_coefficients(), lane_ordinal)
                    .map_err(|_| invalid_selected_artifact())?;
            let observed_auxiliary_left =
                pair_character_lane_value(plaintext.auxiliary_left_coefficients(), lane_ordinal)
                    .map_err(|_| invalid_selected_artifact())?;
            let observed_auxiliary_right =
                pair_character_lane_value(plaintext.auxiliary_right_coefficients(), lane_ordinal)
                    .map_err(|_| invalid_selected_artifact())?;
            if observed_message != expected_message
                || observed_auxiliary_left != expected_auxiliary_left
            {
                return Err(invalid_selected_artifact());
            }
            let Some(assignment) = assignment else {
                if observed_auxiliary_right
                    .iter()
                    .any(|coefficient| *coefficient != 0)
                {
                    return Err(invalid_selected_artifact());
                }
                continue;
            };
            let higher_score =
                discriminating_scores[usize::from(assignment.higher_option_ordinal())];
            let right_exponent = PAIR_CHARACTER_LANE_DEGREE
                .checked_sub(
                    usize::try_from(higher_score).map_err(|_| invalid_selected_artifact())?,
                )
                .ok_or_else(invalid_selected_artifact)?;
            let lane_root = plaintext_extension_lane_root(lane_ordinal)
                .ok_or_else(invalid_selected_artifact)?;
            if observed_auxiliary_right.iter().enumerate().any(
                |(coefficient_ordinal, coefficient)| {
                    if coefficient_ordinal == right_exponent {
                        (u128::from(*coefficient) * u128::from(lane_root))
                            % u128::from(PLAINTEXT_MODULUS)
                            != 1
                    } else {
                        *coefficient != 0
                    }
                },
            ) {
                return Err(invalid_selected_artifact());
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialFieldProfile {
    proof_field_index: u16,
    evaluation_coset_offset: u64,
    masking_polynomial_maximum_degree: u32,
    committed_polynomial_degree_bound_exclusive: u32,
}

impl CommittedMaterialFieldProfile {
    fn selected() -> SchemaResult<Self> {
        let profile = selected_committed_material_profile().map_err(proof_profile_error)?;
        let selected = Self {
            proof_field_index: COMMITTED_MATERIAL_PROOF_FIELD_INDEX,
            evaluation_coset_offset: profile.evaluation_coset_offset(),
            masking_polynomial_maximum_degree: u32::try_from(
                profile.masking_polynomial_maximum_degree(),
            )
            .map_err(|_| invalid_selected_artifact())?,
            committed_polynomial_degree_bound_exclusive: u32::try_from(
                profile.committed_polynomial_degree_bound_exclusive(),
            )
            .map_err(|_| invalid_selected_artifact())?,
        };
        selected.validate()?;
        Ok(selected)
    }

    #[cfg(test)]
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER, 4)?;
        let profile = Self {
            proof_field_index: read_u16(&tuple.items[0])?,
            evaluation_coset_offset: read_u64(&tuple.items[1])?,
            masking_polynomial_maximum_degree: read_u32(&tuple.items[2])?,
            committed_polynomial_degree_bound_exclusive: read_u32(&tuple.items[3])?,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.proof_field_index),
                CanonicalItem::unsigned64(self.evaluation_coset_offset),
                CanonicalItem::unsigned32(self.masking_polynomial_maximum_degree),
                CanonicalItem::unsigned32(self.committed_polynomial_degree_bound_exclusive),
            ],
        ))
    }

    fn validate(self) -> SchemaResult<()> {
        if self != Self::selected_unchecked()? {
            return Err(invalid_selected_artifact());
        }
        Ok(())
    }

    fn selected_unchecked() -> SchemaResult<Self> {
        let profile = selected_committed_material_profile().map_err(proof_profile_error)?;
        Ok(Self {
            proof_field_index: COMMITTED_MATERIAL_PROOF_FIELD_INDEX,
            evaluation_coset_offset: profile.evaluation_coset_offset(),
            masking_polynomial_maximum_degree: u32::try_from(
                profile.masking_polynomial_maximum_degree(),
            )
            .map_err(|_| invalid_selected_artifact())?,
            committed_polynomial_degree_bound_exclusive: u32::try_from(
                profile.committed_polynomial_degree_bound_exclusive(),
            )
            .map_err(|_| invalid_selected_artifact())?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiableSecretSharingProfile {
    committed_material_field: CommittedMaterialFieldProfile,
}

impl VerifiableSecretSharingProfile {
    pub(crate) fn selected() -> SchemaResult<Self> {
        Ok(Self {
            committed_material_field: CommittedMaterialFieldProfile::selected()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(
            &tuple,
            VERIFIABLE_SECRET_SHARING_PROFILE_SCHEMA_IDENTIFIER,
            1,
        )?;
        let nested_bytes = read_item(&tuple.items[0], CanonicalItemType::NestedTuple)?;
        let (committed_material_tuple, consumed_byte_length) =
            CanonicalTuple::decode_prefix(nested_bytes, limits, &mut budget, 1)?;
        if consumed_byte_length != nested_bytes.len() {
            return Err(malformed_nested_artifact());
        }
        Ok(Self {
            committed_material_field: CommittedMaterialFieldProfile::from_tuple(
                &committed_material_tuple,
            )?,
        })
    }

    pub(crate) fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            VERIFIABLE_SECRET_SHARING_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![CanonicalItem::nested_tuple(
                &self.committed_material_field.canonical_tuple()?,
            )?],
        )
        .encode()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LatticeCommitmentProfile {
    commitment_module_rank: u16,
    ordered_commitment_data_prime_indexes: Vec<u16>,
}

impl LatticeCommitmentProfile {
    pub(crate) fn selected() -> SchemaResult<Self> {
        let profile = Self {
            commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
                .map_err(|_| invalid_selected_artifact())?,
            ordered_commitment_data_prime_indexes: SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                .iter()
                .copied()
                .map(|index| u16::try_from(index).map_err(|_| invalid_selected_artifact()))
                .collect::<SchemaResult<Vec<_>>>()?,
        };
        profile.validate()?;
        Ok(profile)
    }

    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header_with_version(
            &tuple,
            LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER,
            LATTICE_COMMITMENT_PROFILE_VERSION,
            2,
        )?;
        let profile = Self {
            commitment_module_rank: read_u16(&tuple.items[0])?,
            ordered_commitment_data_prime_indexes: read_unsigned16_list(&tuple.items[1])?,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub(crate) fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER,
            LATTICE_COMMITMENT_PROFILE_VERSION,
            vec![
                CanonicalItem::unsigned16(self.commitment_module_rank),
                unsigned16_list(&self.ordered_commitment_data_prime_indexes)?,
            ],
        )
        .encode()?)
    }

    fn validate(&self) -> SchemaResult<()> {
        let selected = Self::selected_unchecked()?;
        if self != &selected
            || self
                .ordered_commitment_data_prime_indexes
                .iter()
                .any(|index| usize::from(*index) >= DATA_PRIMES.len())
        {
            return Err(invalid_selected_artifact());
        }
        Ok(())
    }

    fn selected_unchecked() -> SchemaResult<Self> {
        Ok(Self {
            commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
                .map_err(|_| invalid_selected_artifact())?,
            ordered_commitment_data_prime_indexes: SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                .iter()
                .copied()
                .map(|index| u16::try_from(index).map_err(|_| invalid_selected_artifact()))
                .collect::<SchemaResult<Vec<_>>>()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetDecryptionProfile {
    flooding_coefficient_bound_words_little_endian: Vec<u64>,
}

impl TargetDecryptionProfile {
    pub(crate) fn selected() -> SchemaResult<Self> {
        let flooding_bound =
            selected_target_decryption_flooding_bound().map_err(proof_profile_error)?;
        let target_modulus = selected_target_modulus()?;
        let word_count = usize::try_from(target_modulus.bits().div_ceil(u64::from(u64::BITS)))
            .map_err(|_| invalid_selected_artifact())?;
        let mut words = flooding_bound.to_u64_digits();
        if words.len() > word_count {
            return Err(invalid_selected_artifact());
        }
        words.resize(word_count, 0);
        let profile = Self {
            flooding_coefficient_bound_words_little_endian: words,
        };
        profile.validate()?;
        Ok(profile)
    }

    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER, 1)?;
        let profile = Self {
            flooding_coefficient_bound_words_little_endian: read_unsigned64_list(&tuple.items[0])?,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub(crate) fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![unsigned64_list(
                &self.flooding_coefficient_bound_words_little_endian,
            )?],
        )
        .encode()?)
    }

    fn validate(&self) -> SchemaResult<()> {
        if self != &Self::selected_unchecked()? {
            return Err(invalid_selected_artifact());
        }
        Ok(())
    }

    fn selected_unchecked() -> SchemaResult<Self> {
        let flooding_bound =
            selected_target_decryption_flooding_bound().map_err(proof_profile_error)?;
        let target_modulus = selected_target_modulus()?;
        if flooding_bound == BigUint::from(0_u8) || flooding_bound >= target_modulus {
            return Err(invalid_selected_artifact());
        }
        let word_count = usize::try_from(target_modulus.bits().div_ceil(u64::from(u64::BITS)))
            .map_err(|_| invalid_selected_artifact())?;
        let mut words = flooding_bound.to_u64_digits();
        if words.len() > word_count {
            return Err(invalid_selected_artifact());
        }
        words.resize(word_count, 0);
        Ok(Self {
            flooding_coefficient_bound_words_little_endian: words,
        })
    }
}

pub(crate) fn selected_proof_profile_artifact_bytes(
    maximum_ballot_attempts_per_participant: u16,
) -> SchemaResult<Vec<u8>> {
    selected_proof_profile_set(maximum_ballot_attempts_per_participant)
        .and_then(|profile| profile.canonical_bytes())
        .map_err(proof_profile_error)
}

#[cfg(test)]
pub(crate) fn selected_proof_profile_artifact_bytes_from_relation_plans(
    relation_plans: Vec<ValidatedRelationPlanArtifact>,
    maximum_ballot_attempts_per_participant: u16,
) -> SchemaResult<Vec<u8>> {
    selected_proof_profile_set_from_relation_plans(
        relation_plans,
        maximum_ballot_attempts_per_participant,
    )
    .and_then(|profile| profile.canonical_bytes())
    .map_err(proof_profile_error)
}

pub(crate) fn selected_evaluator_program_artifact_bytes() -> SchemaResult<Vec<u8>> {
    selected_evaluator_program_set()
        .and_then(|program| program.encode())
        .map_err(|_| invalid_selected_artifact())
}

pub(crate) fn selected_encoder_and_ballot_layout_artifact_bytes() -> SchemaResult<Vec<u8>> {
    EncoderAndBallotLayout::selected()?.encode()
}

pub(crate) fn selected_verifiable_secret_sharing_profile_artifact_bytes() -> SchemaResult<Vec<u8>> {
    VerifiableSecretSharingProfile::selected()?.encode()
}

pub(crate) fn selected_lattice_commitment_profile_artifact_bytes() -> SchemaResult<Vec<u8>> {
    LatticeCommitmentProfile::selected()?.encode()
}

pub(crate) fn selected_target_decryption_profile_artifact_bytes() -> SchemaResult<Vec<u8>> {
    TargetDecryptionProfile::selected()?.encode()
}

fn selected_target_modulus() -> SchemaResult<BigUint> {
    Ok(DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
        .iter()
        .map(|modulus| BigUint::from(*modulus))
        .product())
}

#[cfg(test)]
fn require_header_with_version(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    schema_version: u16,
    item_count: usize,
) -> SchemaResult<()> {
    if tuple.schema_identifier != schema_identifier
        || tuple.schema_version != schema_version
        || tuple.items.len() != item_count
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "suite artifact uses an unsupported schema or version",
        ));
    }
    Ok(())
}

fn invalid_selected_artifact() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::UnsupportedVersionOrSuite,
        "suite artifact does not match the fixed sealed-lattice profile",
    )
}

#[cfg(test)]
fn malformed_nested_artifact() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::MalformedEncoding,
        "nested suite artifact contains trailing bytes",
    )
}

fn proof_profile_error(_: ProofProfileError) -> FoundationSchemaError {
    invalid_selected_artifact()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_encoder_layout_tuple_refuses(tuple: CanonicalTuple, description: &str) {
        let bytes = tuple.encode().expect("mutated encoder artifact encodes");
        assert_eq!(
            EncoderAndBallotLayout::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect_err(description)
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn current_suite_artifacts_round_trip() {
        let limits = CanonicalDecodeLimits::default();

        let encoder = EncoderAndBallotLayout::selected().expect("selected encoder artifact");
        let encoder_bytes = encoder.clone().encode().expect("encode encoder artifact");
        assert_eq!(
            EncoderAndBallotLayout::decode(&encoder_bytes, &limits)
                .expect("decode encoder artifact"),
            encoder
        );

        let vss_bytes = VerifiableSecretSharingProfile::selected()
            .and_then(VerifiableSecretSharingProfile::encode)
            .expect("selected VSS artifact");
        assert_eq!(
            VerifiableSecretSharingProfile::decode(&vss_bytes, &limits)
                .expect("decode VSS artifact"),
            VerifiableSecretSharingProfile::selected().expect("selected VSS artifact")
        );

        let commitment = LatticeCommitmentProfile::selected().expect("selected commitment");
        let commitment_bytes = commitment.encode().expect("encode commitment artifact");
        assert_eq!(
            LatticeCommitmentProfile::decode(&commitment_bytes, &limits)
                .expect("decode commitment artifact"),
            commitment
        );

        match TargetDecryptionProfile::selected() {
            Ok(target) => {
                let target_bytes = target.encode().expect("encode target artifact");
                assert_eq!(
                    TargetDecryptionProfile::decode(&target_bytes, &limits)
                        .expect("decode target artifact"),
                    target
                );
            }
            Err(error) => {
                assert_eq!(
                    error.refusal_reason,
                    RefusalReason::UnsupportedVersionOrSuite
                );
            }
        }
    }

    #[test]
    fn encoder_layout_derives_every_configurable_option_count() {
        let limits = CanonicalDecodeLimits::default();
        for option_count in super::super::MINIMUM_CONFIGURABLE_OPTION_COUNT
            ..=super::super::MAXIMUM_CONFIGURABLE_OPTION_COUNT
        {
            let artifact = EncoderAndBallotLayout::for_option_count(option_count)
                .expect("bounded encoder layout derives");
            let expected_pair_count = usize::from(option_count) * usize::from(option_count - 1) / 2;
            assert_eq!(
                artifact.ordered_pair_character_assignments.len(),
                expected_pair_count * 4
            );
            let encoded = artifact.clone().encode().expect("encoder layout encodes");
            assert_eq!(
                EncoderAndBallotLayout::decode(&encoded, &limits).expect("encoder layout decodes"),
                artifact
            );
        }
    }

    #[test]
    fn encoder_layout_refuses_generator_geometry_and_catalog_mutations() {
        let selected_bytes = EncoderAndBallotLayout::selected()
            .and_then(EncoderAndBallotLayout::encode)
            .expect("selected encoder artifact");
        let selected_tuple =
            CanonicalTuple::decode(&selected_bytes, &CanonicalDecodeLimits::default())
                .expect("selected encoder tuple decodes");

        let mut obsolete_scalar_layout_version = selected_tuple.clone();
        obsolete_scalar_layout_version.schema_version = 3;
        assert_encoder_layout_tuple_refuses(
            obsolete_scalar_layout_version,
            "obsolete scalar-layout schema version must refuse",
        );

        for (description, item_ordinal, replacement) in [
            (
                "wrong polynomial degree must refuse",
                0,
                CanonicalItem::unsigned32(
                    u32::try_from(POLYNOMIAL_DEGREE / 2).expect("half degree fits u32"),
                ),
            ),
            (
                "wrong lane-root generator must refuse",
                1,
                CanonicalItem::unsigned64(PLAINTEXT_LANE_ROOT_GENERATOR + 1),
            ),
            (
                "wrong lane-orbit generator must refuse",
                2,
                CanonicalItem::unsigned16(
                    u16::try_from(PLAINTEXT_LANE_ORBIT_GENERATOR + 2)
                        .expect("mutated orbit generator fits u16"),
                ),
            ),
            (
                "wrong extension degree must refuse",
                3,
                CanonicalItem::unsigned16(
                    u16::try_from(PLAINTEXT_EXTENSION_DEGREE / 2)
                        .expect("half extension degree fits u16"),
                ),
            ),
            (
                "wrong lane count must refuse",
                4,
                CanonicalItem::unsigned16(
                    u16::try_from(PLAINTEXT_EXTENSION_LANE_COUNT - 1)
                        .expect("mutated lane count fits u16"),
                ),
            ),
            (
                "wrong ciphertext count must refuse",
                5,
                CanonicalItem::unsigned16(
                    u16::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT + 1)
                        .expect("mutated ciphertext count fits u16"),
                ),
            ),
            (
                "wrong auxiliary count must refuse",
                6,
                CanonicalItem::unsigned16(
                    u16::try_from(PAIR_CHARACTER_AUXILIARY_COUNT + 1)
                        .expect("mutated auxiliary count fits u16"),
                ),
            ),
            (
                "wrong option count must refuse",
                7,
                CanonicalItem::unsigned16(
                    FOUNDATION_PROFILE
                        .option_count
                        .checked_sub(1)
                        .expect("selected option count is positive"),
                ),
            ),
            (
                "wrong minimum score must refuse",
                8,
                CanonicalItem::unsigned16(
                    FOUNDATION_PROFILE
                        .minimum_score
                        .checked_add(1)
                        .expect("mutated minimum score fits u16"),
                ),
            ),
            (
                "wrong maximum score must refuse",
                9,
                CanonicalItem::unsigned16(
                    FOUNDATION_PROFILE
                        .maximum_score
                        .checked_sub(1)
                        .expect("selected maximum score is positive"),
                ),
            ),
            (
                "wrong pair-difference rule must refuse",
                10,
                CanonicalItem::unsigned16(
                    LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE
                        .checked_add(1)
                        .expect("mutated pair-difference rule fits u16"),
                ),
            ),
        ] {
            let mut mutated = selected_tuple.clone();
            mutated.items[item_ordinal] = replacement;
            assert_encoder_layout_tuple_refuses(mutated, description);
        }

        let selected_catalog = read_unsigned16_list(&selected_tuple.items[11])
            .expect("selected pair-character catalog decodes");
        let mut shortened_catalog = selected_catalog.clone();
        shortened_catalog.truncate(shortened_catalog.len() - 4);
        let mut missing_assignment = selected_tuple.clone();
        missing_assignment.items[11] =
            unsigned16_list(&shortened_catalog).expect("shortened catalog encodes");
        assert_encoder_layout_tuple_refuses(
            missing_assignment,
            "missing catalog assignment must refuse",
        );

        let mut reversed_orientation_catalog = selected_catalog.clone();
        reversed_orientation_catalog.swap(2, 3);
        let mut reversed_orientation = selected_tuple.clone();
        reversed_orientation.items[11] = unsigned16_list(&reversed_orientation_catalog)
            .expect("reversed orientation catalog encodes");
        assert_encoder_layout_tuple_refuses(
            reversed_orientation,
            "reversed pair orientation must refuse",
        );

        let mut wrong_ciphertext_catalog = selected_catalog.clone();
        wrong_ciphertext_catalog[0] = (wrong_ciphertext_catalog[0] + 1)
            % u16::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT).expect("ciphertext count fits u16");
        let mut wrong_ciphertext = selected_tuple.clone();
        wrong_ciphertext.items[11] =
            unsigned16_list(&wrong_ciphertext_catalog).expect("wrong ciphertext catalog encodes");
        assert_encoder_layout_tuple_refuses(
            wrong_ciphertext,
            "wrong assignment ciphertext must refuse",
        );

        let mut wrong_lane_catalog = selected_catalog;
        wrong_lane_catalog[1] = (wrong_lane_catalog[1] + 1)
            % u16::try_from(PAIR_CHARACTER_LANE_COUNT).expect("lane count fits u16");
        let mut wrong_lane = selected_tuple;
        wrong_lane.items[11] =
            unsigned16_list(&wrong_lane_catalog).expect("wrong lane catalog encodes");
        assert_encoder_layout_tuple_refuses(wrong_lane, "wrong assignment lane must refuse");
    }

    #[test]
    fn target_flooding_bound_uses_the_complete_target_modulus_width() {
        let Ok(profile) = TargetDecryptionProfile::selected() else {
            return;
        };
        let target_modulus = selected_target_modulus().expect("target modulus derives");
        let expected_word_count =
            usize::try_from(target_modulus.bits().div_ceil(u64::from(u64::BITS)))
                .expect("target word count fits usize");
        assert_eq!(
            profile.flooding_coefficient_bound_words_little_endian.len(),
            expected_word_count
        );
        assert_eq!(
            BigUint::new(
                profile
                    .flooding_coefficient_bound_words_little_endian
                    .iter()
                    .flat_map(|word| {
                        let bytes = word.to_le_bytes();
                        [
                            u32::from_le_bytes(bytes[..4].try_into().expect("low word")),
                            u32::from_le_bytes(bytes[4..].try_into().expect("high word")),
                        ]
                    })
                    .collect(),
            ),
            selected_target_decryption_flooding_bound().expect("selected flooding bound derives")
        );

        let truncated_words =
            &profile.flooding_coefficient_bound_words_little_endian[..expected_word_count - 1];
        let truncated = CanonicalTuple::new(
            TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![unsigned64_list(truncated_words).expect("truncated word list")],
        )
        .encode()
        .expect("encode truncated target profile");
        assert_eq!(
            TargetDecryptionProfile::decode(&truncated, &CanonicalDecodeLimits::default())
                .expect_err("truncated target width must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn committed_material_profile_matches_the_selected_common_proof_domain() {
        let profile = CommittedMaterialFieldProfile::selected().expect("selected material profile");
        let same_secret_plan =
            selected_same_secret_relation_plan_input().expect("selected same-secret plan derives");
        let plan_opening_degree_bound =
            u32::try_from(same_secret_plan.opening_degree_bound_exclusive)
                .expect("selected same-secret opening bound fits u32");
        assert_eq!(profile.proof_field_index, 0);
        assert_eq!(profile.evaluation_coset_offset, 7);
        assert_eq!(profile.masking_polynomial_maximum_degree, 2_047);
        assert_eq!(
            profile.committed_polynomial_degree_bound_exclusive,
            plan_opening_degree_bound,
        );
        assert_eq!(plan_opening_degree_bound, 2_097_152);
        assert_eq!(
            usize::try_from(plan_opening_degree_bound).expect("selected opening bound fits usize")
                / crate::bgv::parameters::POLYNOMIAL_DEGREE,
            64,
        );
        assert_eq!(
            usize::try_from(plan_opening_degree_bound).expect("selected opening bound fits usize")
                % crate::bgv::parameters::POLYNOMIAL_DEGREE,
            0,
        );
        assert_eq!(crate::bgv::parameters::POLYNOMIAL_DEGREE, 32_768);
    }
}
