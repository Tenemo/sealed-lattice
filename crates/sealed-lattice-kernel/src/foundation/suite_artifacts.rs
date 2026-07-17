//! Canonical artifacts owned by the fixed sealed-lattice suite.

#[cfg(test)]
use super::CanonicalDecodeLimits;
#[cfg(test)]
use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::SchemaResult;
#[cfg(test)]
use super::schemas::{read_item, read_list_header, read_u16, read_u32, read_u64, require_header};
use super::{
    CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError, RefusalReason,
};
use crate::bgv::{
    evaluator::program::selected_evaluator_program_set_bytes,
    parameters::{
        DATA_PRIMES, LOGICAL_SLOT_GENERATOR, PLAINTEXT_MODULUS, root_parameters_for_modulus,
        validate_supported_algebraic_parameters,
    },
    proof_suite::{
        PROOF_EVALUATION_BLOWUP_FACTOR, ProofProfileError, selected_committed_material_profile,
        selected_proof_profile_set, selected_target_decryption_flooding_bound,
    },
    setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
};

pub(crate) const ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x1300;
pub(crate) const VERIFIABLE_SECRET_SHARING_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2120;
pub(crate) const COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2121;
pub(crate) const LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2122;
pub(crate) const TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1630;

const SCHEMA_VERSION: u16 = 1;
const LATTICE_COMMITMENT_PROFILE_VERSION: u16 = 3;
const COMMITTED_MATERIAL_PROOF_FIELD_INDEX: u16 = 0;
const RESERVED_BALLOT_SLOT_RULE: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EncoderAndBallotLayout {
    primitive_two_n_root: u64,
    slot_generator: u16,
    reserved_slot_rule: u16,
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
            primitive_two_n_root,
            slot_generator,
            reserved_slot_rule: RESERVED_BALLOT_SLOT_RULE,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER, 3)?;
        let artifact = Self {
            primitive_two_n_root: read_u64(&tuple.items[0])?,
            slot_generator: read_u16(&tuple.items[1])?,
            reserved_slot_rule: read_u16(&tuple.items[2])?,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub(crate) fn encode(self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.primitive_two_n_root),
                CanonicalItem::unsigned16(self.slot_generator),
                CanonicalItem::unsigned16(self.reserved_slot_rule),
            ],
        )
        .encode()?)
    }

    fn validate(self) -> SchemaResult<()> {
        let selected_root = root_parameters_for_modulus(PLAINTEXT_MODULUS)
            .ok_or_else(invalid_selected_artifact)?
            .negacyclic_root;
        if self.primitive_two_n_root != selected_root
            || usize::from(self.slot_generator) != LOGICAL_SLOT_GENERATOR
            || self.reserved_slot_rule != RESERVED_BALLOT_SLOT_RULE
        {
            return Err(invalid_selected_artifact());
        }
        Ok(())
    }
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
            u128::from(selected_target_decryption_flooding_bound().map_err(proof_profile_error)?);
        let target_modulus = selected_target_modulus()?;
        let word_count =
            usize::try_from((u128::BITS - target_modulus.leading_zeros()).div_ceil(u64::BITS))
                .map_err(|_| invalid_selected_artifact())?;
        let mut words = vec![0_u64; word_count];
        words[0] = flooding_bound as u64;
        if word_count > 1 {
            words[1] = (flooding_bound >> u64::BITS) as u64;
        }
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
            u128::from(selected_target_decryption_flooding_bound().map_err(proof_profile_error)?);
        let target_modulus = selected_target_modulus()?;
        if flooding_bound == 0 || flooding_bound >= target_modulus {
            return Err(invalid_selected_artifact());
        }
        let word_count =
            usize::try_from((u128::BITS - target_modulus.leading_zeros()).div_ceil(u64::BITS))
                .map_err(|_| invalid_selected_artifact())?;
        let mut words = vec![0_u64; word_count];
        words[0] = flooding_bound as u64;
        if word_count > 1 {
            words[1] = (flooding_bound >> u64::BITS) as u64;
        }
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
    selected_evaluator_program_set_bytes().map_err(|_| invalid_selected_artifact())
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

fn selected_target_modulus() -> SchemaResult<u128> {
    DATA_PRIMES[..2]
        .iter()
        .try_fold(1_u128, |product, modulus| {
            product.checked_mul(u128::from(*modulus))
        })
        .ok_or_else(invalid_selected_artifact)
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

fn unsigned16_list(values: &[u16]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned16)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned16,
        &items,
    )?)
}

fn unsigned64_list(values: &[u64]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned64,
        &items,
    )?)
}

#[cfg(test)]
fn read_unsigned16_list(item: &CanonicalItem) -> SchemaResult<Vec<u16>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned16)?;
    if bytes.len() != count.checked_mul(2).ok_or_else(malformed_list)? {
        return Err(malformed_list());
    }
    bytes
        .chunks_exact(2)
        .map(|bytes| {
            Ok(u16::from_le_bytes(
                bytes.try_into().map_err(|_| malformed_list())?,
            ))
        })
        .collect()
}

#[cfg(test)]
fn read_unsigned64_list(item: &CanonicalItem) -> SchemaResult<Vec<u64>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned64)?;
    if bytes.len() != count.checked_mul(8).ok_or_else(malformed_list)? {
        return Err(malformed_list());
    }
    bytes
        .chunks_exact(8)
        .map(|bytes| {
            Ok(u64::from_le_bytes(
                bytes.try_into().map_err(|_| malformed_list())?,
            ))
        })
        .collect()
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

#[cfg(test)]
fn malformed_list() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::MalformedEncoding,
        "suite artifact list length is malformed",
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

        let target = TargetDecryptionProfile::selected().expect("selected target profile");
        let target_bytes = target.encode().expect("encode target artifact");
        assert_eq!(
            TargetDecryptionProfile::decode(&target_bytes, &limits)
                .expect("decode target artifact"),
            target
        );

        let drifted_encoder = CanonicalTuple::new(
            ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(1),
                CanonicalItem::unsigned16(LOGICAL_SLOT_GENERATOR as u16),
                CanonicalItem::unsigned16(RESERVED_BALLOT_SLOT_RULE),
            ],
        )
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
        let profile = TargetDecryptionProfile::selected().expect("selected target profile");
        assert_eq!(
            profile.flooding_coefficient_bound_words_little_endian,
            vec![16, 0]
        );

        let truncated = CanonicalTuple::new(
            TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![unsigned64_list(&[16]).expect("truncated word list")],
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
        assert_eq!(crate::bgv::parameters::POLYNOMIAL_DEGREE, 32_768);
    }
}
