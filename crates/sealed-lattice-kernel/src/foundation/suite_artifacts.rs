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
    direct_ballots::direct_ballot_slots,
    evaluator::program::selected_evaluator_program_set,
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    parameters::{
        DATA_PRIMES, LOGICAL_SLOT_GENERATOR, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE,
        root_parameters_for_modulus, validate_supported_algebraic_parameters,
    },
    proof_suite::{
        PROOF_EVALUATION_BLOWUP_FACTOR, ProofProfileError, selected_committed_material_profile,
        selected_proof_profile_set, selected_target_decryption_flooding_bound,
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
const ENCODER_AND_BALLOT_LAYOUT_VERSION: u16 = 2;
const LATTICE_COMMITMENT_PROFILE_VERSION: u16 = 3;
const COMMITTED_MATERIAL_PROOF_FIELD_INDEX: u16 = 0;
const RESERVED_BALLOT_SLOT_RULE: u16 = 1;
const LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncoderAndBallotLayout {
    polynomial_degree: u32,
    primitive_two_n_root: u64,
    slot_generator: u16,
    reserved_slot_rule: u16,
    option_count: u16,
    minimum_score: u16,
    maximum_score: u16,
    pair_difference_rule: u16,
    ordered_pair_ordinals: Vec<u16>,
}

impl EncoderAndBallotLayout {
    pub(crate) fn selected() -> SchemaResult<Self> {
        validate_supported_algebraic_parameters().map_err(|_| invalid_selected_artifact())?;
        let primitive_two_n_root = root_parameters_for_modulus(PLAINTEXT_MODULUS)
            .ok_or_else(invalid_selected_artifact)?
            .negacyclic_root;
        let slot_generator =
            u16::try_from(LOGICAL_SLOT_GENERATOR).map_err(|_| invalid_selected_artifact())?;
        let artifact = Self {
            polynomial_degree: u32::try_from(POLYNOMIAL_DEGREE)
                .map_err(|_| invalid_selected_artifact())?,
            primitive_two_n_root,
            slot_generator,
            reserved_slot_rule: RESERVED_BALLOT_SLOT_RULE,
            option_count: FOUNDATION_PROFILE.option_count,
            minimum_score: FOUNDATION_PROFILE.minimum_score,
            maximum_score: FOUNDATION_PROFILE.maximum_score,
            pair_difference_rule: LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE,
            ordered_pair_ordinals: selected_ordered_pair_ordinals()?,
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
            9,
        )?;
        let artifact = Self {
            polynomial_degree: read_u32(&tuple.items[0])?,
            primitive_two_n_root: read_u64(&tuple.items[1])?,
            slot_generator: read_u16(&tuple.items[2])?,
            reserved_slot_rule: read_u16(&tuple.items[3])?,
            option_count: read_u16(&tuple.items[4])?,
            minimum_score: read_u16(&tuple.items[5])?,
            maximum_score: read_u16(&tuple.items[6])?,
            pair_difference_rule: read_u16(&tuple.items[7])?,
            ordered_pair_ordinals: read_unsigned16_list(&tuple.items[8])?,
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
                CanonicalItem::unsigned64(self.primitive_two_n_root),
                CanonicalItem::unsigned16(self.slot_generator),
                CanonicalItem::unsigned16(self.reserved_slot_rule),
                CanonicalItem::unsigned16(self.option_count),
                CanonicalItem::unsigned16(self.minimum_score),
                CanonicalItem::unsigned16(self.maximum_score),
                CanonicalItem::unsigned16(self.pair_difference_rule),
                unsigned16_list(&self.ordered_pair_ordinals)?,
            ],
        )
        .encode()?)
    }

    fn validate(&self) -> SchemaResult<()> {
        let selected_root = root_parameters_for_modulus(PLAINTEXT_MODULUS)
            .ok_or_else(invalid_selected_artifact)?
            .negacyclic_root;
        if usize::try_from(self.polynomial_degree).ok() != Some(POLYNOMIAL_DEGREE)
            || self.primitive_two_n_root != selected_root
            || usize::from(self.slot_generator) != LOGICAL_SLOT_GENERATOR
            || self.reserved_slot_rule != RESERVED_BALLOT_SLOT_RULE
            || self.option_count != FOUNDATION_PROFILE.option_count
            || self.minimum_score != FOUNDATION_PROFILE.minimum_score
            || self.maximum_score != FOUNDATION_PROFILE.maximum_score
            || self.minimum_score > self.maximum_score
            || self.pair_difference_rule != LOWER_MINUS_HIGHER_PAIR_DIFFERENCE_RULE
            || self.ordered_pair_ordinals != selected_ordered_pair_ordinals()?
        {
            return Err(invalid_selected_artifact());
        }
        require_pairwise_ballot_codec_layout(&self.ordered_pair_ordinals)?;
        Ok(())
    }
}

fn selected_ordered_pair_ordinals() -> SchemaResult<Vec<u16>> {
    let option_count = usize::from(FOUNDATION_PROFILE.option_count);
    let pair_count = option_count
        .checked_mul(
            option_count
                .checked_sub(1)
                .ok_or_else(invalid_selected_artifact)?,
        )
        .and_then(|product| product.checked_div(2))
        .ok_or_else(invalid_selected_artifact)?;
    let flattened_ordinal_count = pair_count
        .checked_mul(2)
        .ok_or_else(invalid_selected_artifact)?;
    let mut ordered_pair_ordinals = Vec::new();
    ordered_pair_ordinals
        .try_reserve_exact(flattened_ordinal_count)
        .map_err(|_| invalid_selected_artifact())?;
    for shift in 1..option_count {
        for lower_option_ordinal in 0..option_count - shift {
            let higher_option_ordinal = lower_option_ordinal
                .checked_add(shift)
                .ok_or_else(invalid_selected_artifact)?;
            ordered_pair_ordinals.push(
                u16::try_from(lower_option_ordinal).map_err(|_| invalid_selected_artifact())?,
            );
            ordered_pair_ordinals.push(
                u16::try_from(higher_option_ordinal).map_err(|_| invalid_selected_artifact())?,
            );
        }
    }
    if ordered_pair_ordinals.len() != flattened_ordinal_count {
        return Err(invalid_selected_artifact());
    }
    Ok(ordered_pair_ordinals)
}

fn require_pairwise_ballot_codec_layout(ordered_pair_ordinals: &[u16]) -> SchemaResult<()> {
    let option_count = usize::from(FOUNDATION_PROFILE.option_count);
    let ordinal_scores = (0..option_count)
        .map(|option_ordinal| {
            u64::try_from(option_ordinal)
                .ok()
                .and_then(|ordinal| ordinal.checked_add(1))
                .ok_or_else(invalid_selected_artifact)
        })
        .collect::<SchemaResult<Vec<_>>>()?;
    let actual_slots = direct_ballot_slots(&ordinal_scores, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
        .map_err(|_| invalid_selected_artifact())?;
    let pair_count = ordered_pair_ordinals.len() / 2;
    if ordered_pair_ordinals.len() % 2 != 0
        || pair_count > actual_slots.len()
        || actual_slots[pair_count..].iter().any(|slot| *slot != 0)
    {
        return Err(invalid_selected_artifact());
    }
    for (pair_ordinal, pair) in ordered_pair_ordinals.chunks_exact(2).enumerate() {
        let lower_option_ordinal = usize::from(pair[0]);
        let higher_option_ordinal = usize::from(pair[1]);
        let lower_score = *ordinal_scores
            .get(lower_option_ordinal)
            .ok_or_else(invalid_selected_artifact)?;
        let higher_score = *ordinal_scores
            .get(higher_option_ordinal)
            .ok_or_else(invalid_selected_artifact)?;
        let expected_difference = if lower_score >= higher_score {
            lower_score - higher_score
        } else {
            PLAINTEXT_MODULUS - (higher_score - lower_score)
        };
        if actual_slots[pair_ordinal] != expected_difference {
            return Err(invalid_selected_artifact());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialFieldProfile {
    proof_field_index: u16,
    evaluation_blowup_factor: u32,
    evaluation_coset_offset: u64,
    masking_polynomial_maximum_degree: u32,
    committed_polynomial_degree_bound_exclusive: u32,
}

impl CommittedMaterialFieldProfile {
    fn selected() -> SchemaResult<Self> {
        let profile = selected_committed_material_profile().map_err(proof_profile_error)?;
        let selected = Self {
            proof_field_index: COMMITTED_MATERIAL_PROOF_FIELD_INDEX,
            evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
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
        require_header(tuple, COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER, 5)?;
        let profile = Self {
            proof_field_index: read_u16(&tuple.items[0])?,
            evaluation_blowup_factor: read_u32(&tuple.items[1])?,
            evaluation_coset_offset: read_u64(&tuple.items[2])?,
            masking_polynomial_maximum_degree: read_u32(&tuple.items[3])?,
            committed_polynomial_degree_bound_exclusive: read_u32(&tuple.items[4])?,
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
                CanonicalItem::unsigned32(self.evaluation_blowup_factor),
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
            evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
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

    #[test]
    fn fixed_suite_artifacts_round_trip_and_reject_profile_drift() {
        let limits = CanonicalDecodeLimits::default();

        let encoder_bytes = EncoderAndBallotLayout::selected()
            .and_then(EncoderAndBallotLayout::encode)
            .expect("selected encoder artifact");
        assert_eq!(
            EncoderAndBallotLayout::decode(&encoder_bytes, &limits)
                .expect("decode encoder artifact"),
            EncoderAndBallotLayout::selected().expect("selected encoder artifact")
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
                eprintln!("selected target profile unavailable: {error:?}");
            }
        }

        let mut drifted_encoder_tuple = CanonicalTuple::decode(&encoder_bytes, &limits)
            .expect("selected encoder tuple decodes");
        drifted_encoder_tuple.items[5] =
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.maximum_score);
        let drifted_encoder = drifted_encoder_tuple
            .encode()
            .expect("encode drifted artifact");
        assert_eq!(
            EncoderAndBallotLayout::decode(&drifted_encoder, &limits)
                .expect_err("drifted encoder must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
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
    fn retired_lattice_commitment_versions_refuse() {
        let selected = LatticeCommitmentProfile::selected().expect("selected commitment profile");
        for retired_version in [1_u16, 2] {
            let bytes = CanonicalTuple::new(
                LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER,
                retired_version,
                vec![
                    CanonicalItem::unsigned16(selected.commitment_module_rank),
                    unsigned16_list(&selected.ordered_commitment_data_prime_indexes)
                        .expect("commitment index list"),
                ],
            )
            .encode()
            .expect("retired commitment artifact");
            assert_eq!(
                LatticeCommitmentProfile::decode(&bytes, &CanonicalDecodeLimits::default())
                    .expect_err("retired version must refuse")
                    .refusal_reason,
                RefusalReason::UnsupportedVersionOrSuite
            );
        }
    }

    #[test]
    fn committed_material_profile_matches_the_selected_common_proof_domain() {
        let profile = CommittedMaterialFieldProfile::selected().expect("selected material profile");
        assert_eq!(profile.proof_field_index, 0);
        assert_eq!(profile.evaluation_blowup_factor, 8);
        assert_eq!(profile.evaluation_coset_offset, 7);
        assert_eq!(profile.masking_polynomial_maximum_degree, 2_047);
        assert_eq!(profile.committed_polynomial_degree_bound_exclusive, 262_144);
        assert_eq!(crate::bgv::parameters::POLYNOMIAL_DEGREE, 65_536);
    }
}
