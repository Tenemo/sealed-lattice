use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;

use crate::{
    bgv::{
        evaluator::{engine::EVALUATOR_FULL_LEVEL, top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL},
        parameters::{
            DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, root_parameters_for_modulus,
        },
        proof_suite::{
            COMMON_PROOF_PROFILE,
            profile::{is_prime_u64, modular_power},
            profile_artifact::ProofProfileSetArtifact,
        },
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
            TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
            VSS_COMMITTED_MATERIAL_COLUMN_MASK_DEGREE_CAP,
        },
    },
    foundation::{
        CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
        CanonicalTuple,
    },
    hashing::hash_framed_parts_512,
};

const SCHEMA_VERSION: u16 = 1;
const ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x1300;
const VSS_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2120;
const COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2121;
const LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2122;
const EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER: u16 = 0x1500;
const EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x1501;
const EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER: u16 = 0x1503;
const EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER: u16 = 0x1504;
const TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1630;

const LOGICAL_SLOT_GENERATOR: u16 = 3;
const RESERVED_SLOT_RULE: u16 = 1;
const FIRST_PROFILE_FIELD_INDEX: u16 = 0;
const COMMITTED_MATERIAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE: u32 = POLYNOMIAL_DEGREE as u32;
const EVALUATOR_CONSTANT_HASH_DOMAIN: &str = "sealed-lattice/evaluator/constant/v1";
const MAXIMUM_EVALUATOR_CONSTANT_COUNT: usize = 4_096;
const MAXIMUM_EVALUATOR_INSTRUCTION_COUNT: usize = 4_096;
const MAXIMUM_EVALUATOR_INPUT_REGISTER_COUNT: usize = 2;
const FIRST_PROFILE_OPTION_COUNT: usize = 20;
const COMMITTED_MATERIAL_CONSUMING_FAMILIES: [u16; 4] = [0x1211, 0x1621, 0x2110, 0x2111];

fn logical_slot_exponents(slot_generator: u64) -> DeterministicArtifactResult<Vec<u64>> {
    let automorphism_modulus = u64::try_from(POLYNOMIAL_DEGREE)
        .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?
        .checked_mul(2)
        .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
    if slot_generator == 0
        || slot_generator >= automorphism_modulus
        || slot_generator.is_multiple_of(2)
    {
        return Err(DeterministicArtifactError::InvalidValue);
    }

    let generator_order = u64::try_from(POLYNOMIAL_DEGREE / 2)
        .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
    let mut subgroup_exponent = 1_u64;
    let mut slot_exponents = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for _ in 0..generator_order {
        if subgroup_exponent == automorphism_modulus - 1 {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        slot_exponents.push(subgroup_exponent);
        slot_exponents.push(automorphism_modulus - subgroup_exponent);
        subgroup_exponent = subgroup_exponent
            .checked_mul(slot_generator)
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?
            % automorphism_modulus;
    }
    if modular_power(slot_generator, generator_order, automorphism_modulus) != 1
        || modular_power(slot_generator, generator_order / 2, automorphism_modulus) == 1
    {
        return Err(DeterministicArtifactError::InvalidValue);
    }
    validate_complete_odd_exponent_coverage(&slot_exponents, automorphism_modulus)?;
    Ok(slot_exponents)
}

fn validate_complete_odd_exponent_coverage(
    slot_exponents: &[u64],
    automorphism_modulus: u64,
) -> DeterministicArtifactResult<()> {
    if slot_exponents.len() != POLYNOMIAL_DEGREE {
        return Err(DeterministicArtifactError::InvalidValue);
    }
    let mut distinct_exponents = BTreeSet::new();
    for exponent in slot_exponents {
        if *exponent == 0 || *exponent >= automorphism_modulus || exponent.is_multiple_of(2) {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        if !distinct_exponents.insert(*exponent) {
            return Err(DeterministicArtifactError::DuplicateValue);
        }
    }
    if distinct_exponents.len() != POLYNOMIAL_DEGREE {
        return Err(DeterministicArtifactError::InvalidValue);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeterministicArtifactError {
    Canonical(CanonicalCodecError),
    WrongSchema,
    WrongVersion,
    WrongItemCount,
    WrongItemType,
    LimitExceeded,
    ArithmeticOverflow,
    InvalidValue,
    InvalidOrdering,
    DuplicateValue,
    UnresolvedReference,
    IncompatiblePersistentMaterialDomain,
    IncompleteEvaluatorProgram,
}

impl From<CanonicalCodecError> for DeterministicArtifactError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

pub(crate) type DeterministicArtifactResult<T> = Result<T, DeterministicArtifactError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SuiteArtifactSemanticBlocker {
    ProofRelationProgramsNotLowered,
    PersistentMaterialMaskImageEvidenceMissing,
    LatticeCommitmentConcreteSecurityEvidenceMissing,
    EvaluatorProgramNotMaterialized,
    EvaluatorCorrectnessAndErrorEvidenceMissing,
    TargetDecryptionTheoremEvidenceMissing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncoderAndBallotLayoutArtifact {
    pub(crate) primitive_two_n_root: u64,
    pub(crate) slot_generator: u16,
    pub(crate) reserved_slot_rule: u16,
}

impl EncoderAndBallotLayoutArtifact {
    pub(crate) fn from_operative_parameters() -> DeterministicArtifactResult<Self> {
        let root_parameters = root_parameters_for_modulus(PLAINTEXT_MODULUS)
            .ok_or(DeterministicArtifactError::InvalidValue)?;
        let artifact = Self {
            primitive_two_n_root: root_parameters.negacyclic_root,
            slot_generator: LOGICAL_SLOT_GENERATOR,
            reserved_slot_rule: RESERVED_SLOT_RULE,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub(crate) fn validate(&self) -> DeterministicArtifactResult<()> {
        if !is_prime_u64(PLAINTEXT_MODULUS)
            || self.slot_generator != LOGICAL_SLOT_GENERATOR
            || self.reserved_slot_rule != RESERVED_SLOT_RULE
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let twice_degree = u64::try_from(POLYNOMIAL_DEGREE)
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?
            .checked_mul(2)
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        if modular_power(self.primitive_two_n_root, twice_degree, PLAINTEXT_MODULUS) != 1
            || modular_power(
                self.primitive_two_n_root,
                POLYNOMIAL_DEGREE as u64,
                PLAINTEXT_MODULUS,
            ) != PLAINTEXT_MODULUS - 1
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }

        logical_slot_exponents(u64::from(self.slot_generator))?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> DeterministicArtifactResult<Vec<u8>> {
        self.validate()?;
        Ok(self.to_tuple().encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> DeterministicArtifactResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_tuple(&tuple, ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER, 3)?;
        let artifact = Self {
            primitive_two_n_root: read_u64(&tuple.items[0])?,
            slot_generator: read_u16(&tuple.items[1])?,
            reserved_slot_rule: read_u16(&tuple.items[2])?,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    fn to_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            ENCODER_AND_BALLOT_LAYOUT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.primitive_two_n_root),
                CanonicalItem::unsigned16(self.slot_generator),
                CanonicalItem::unsigned16(self.reserved_slot_rule),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialFieldProfileArtifact {
    pub(crate) proof_field_index: u16,
    pub(crate) evaluation_blowup_factor: u32,
    pub(crate) evaluation_coset_offset: u64,
    pub(crate) masking_polynomial_maximum_degree: u32,
    pub(crate) committed_polynomial_degree_bound_exclusive: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VssProfileArtifact {
    pub(crate) committed_material_field: CommittedMaterialFieldProfileArtifact,
}

impl VssProfileArtifact {
    pub(crate) fn from_operative_parameters() -> DeterministicArtifactResult<Self> {
        let masking_polynomial_maximum_degree =
            u32::try_from(VSS_COMMITTED_MATERIAL_COLUMN_MASK_DEGREE_CAP)
                .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        Ok(Self {
            committed_material_field: CommittedMaterialFieldProfileArtifact {
                proof_field_index: FIRST_PROFILE_FIELD_INDEX,
                evaluation_blowup_factor: COMMON_PROOF_PROFILE.evaluation_blowup_factor,
                evaluation_coset_offset: COMMON_PROOF_PROFILE.evaluation_coset_offset,
                masking_polynomial_maximum_degree,
                committed_polynomial_degree_bound_exclusive:
                    COMMITTED_MATERIAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
            },
        })
    }

    pub(crate) fn validate(
        &self,
        proof_profile: &ProofProfileSetArtifact,
    ) -> DeterministicArtifactResult<()> {
        let evaluation_domain_size = self.validate_field_and_consuming_schedules(proof_profile)?;
        for family_schema_identifier in COMMITTED_MATERIAL_CONSUMING_FAMILIES {
            let relation_plan = proof_profile
                .relation_plans
                .iter()
                .find(|plan| {
                    plan.application_statement_schema_identifier == family_schema_identifier
                })
                .ok_or(DeterministicArtifactError::UnresolvedReference)?;
            if relation_plan.variants.is_empty()
                || relation_plan
                    .variants
                    .iter()
                    .any(|variant| variant.evaluation_domain_size != evaluation_domain_size)
            {
                return Err(DeterministicArtifactError::IncompatiblePersistentMaterialDomain);
            }
        }
        Ok(())
    }

    fn validate_field_and_consuming_schedules(
        &self,
        proof_profile: &ProofProfileSetArtifact,
    ) -> DeterministicArtifactResult<u64> {
        let field_profile = &self.committed_material_field;
        let operative_masking_degree = u32::try_from(VSS_COMMITTED_MATERIAL_COLUMN_MASK_DEGREE_CAP)
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        if proof_profile.proof_fields.len() != 1
            || field_profile.proof_field_index != FIRST_PROFILE_FIELD_INDEX
            || field_profile.evaluation_blowup_factor == 0
            || !field_profile.evaluation_blowup_factor.is_power_of_two()
            || field_profile.masking_polynomial_maximum_degree != operative_masking_degree
            || field_profile.committed_polynomial_degree_bound_exclusive
                != COMMITTED_MATERIAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let proof_field = proof_profile
            .proof_fields
            .get(usize::from(field_profile.proof_field_index))
            .ok_or(DeterministicArtifactError::UnresolvedReference)?;
        if proof_field.base_field_modulus < 3
            || !is_prime_u64(proof_field.base_field_modulus)
            || field_profile.evaluation_coset_offset == 0
            || field_profile.evaluation_coset_offset >= proof_field.base_field_modulus
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let half_ring_degree = u32::try_from(POLYNOMIAL_DEGREE / 2)
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        if half_ring_degree
            .checked_add(field_profile.masking_polynomial_maximum_degree)
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?
            >= field_profile.committed_polynomial_degree_bound_exclusive
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let committed_degree_capacity = field_profile
            .committed_polynomial_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        let evaluation_domain_size = u64::from(field_profile.evaluation_blowup_factor)
            .checked_mul(u64::from(committed_degree_capacity))
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        let maximum_two_adic_order = 1_u64
            .checked_shl((proof_field.base_field_modulus - 1).trailing_zeros())
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        let half_ring_degree_u64 = u64::from(half_ring_degree);
        if modular_power(
            proof_field.maximum_two_adic_subgroup_generator,
            maximum_two_adic_order,
            proof_field.base_field_modulus,
        ) != 1
            || modular_power(
                proof_field.maximum_two_adic_subgroup_generator,
                maximum_two_adic_order / 2,
                proof_field.base_field_modulus,
            ) == 1
            || !maximum_two_adic_order.is_multiple_of(evaluation_domain_size)
            || !evaluation_domain_size.is_multiple_of(half_ring_degree_u64)
            || !(proof_field.base_field_modulus - 1).is_multiple_of(evaluation_domain_size)
            || modular_power(
                field_profile.evaluation_coset_offset,
                evaluation_domain_size,
                proof_field.base_field_modulus,
            ) == 1
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let evaluation_root = modular_power(
            proof_field.maximum_two_adic_subgroup_generator,
            maximum_two_adic_order / evaluation_domain_size,
            proof_field.base_field_modulus,
        );
        if modular_power(
            evaluation_root,
            evaluation_domain_size,
            proof_field.base_field_modulus,
        ) != 1
            || modular_power(
                evaluation_root,
                evaluation_domain_size / 2,
                proof_field.base_field_modulus,
            ) == 1
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let trace_root = modular_power(
            evaluation_root,
            evaluation_domain_size / half_ring_degree_u64,
            proof_field.base_field_modulus,
        );
        if modular_power(
            trace_root,
            half_ring_degree_u64,
            proof_field.base_field_modulus,
        ) != 1
            || modular_power(
                trace_root,
                half_ring_degree_u64 / 2,
                proof_field.base_field_modulus,
            ) == 1
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }

        let consuming_schedules = proof_profile
            .proof_families
            .iter()
            .filter(|family| {
                COMMITTED_MATERIAL_CONSUMING_FAMILIES
                    .contains(&family.application_statement_schema_identifier)
            })
            .collect::<Vec<_>>();
        if consuming_schedules.len() != COMMITTED_MATERIAL_CONSUMING_FAMILIES.len() {
            return Err(DeterministicArtifactError::UnresolvedReference);
        }
        for family_schema_identifier in COMMITTED_MATERIAL_CONSUMING_FAMILIES {
            let schedule = consuming_schedules
                .iter()
                .find(|family| {
                    family.application_statement_schema_identifier == family_schema_identifier
                })
                .ok_or(DeterministicArtifactError::UnresolvedReference)?
                .field_schedule
                .clone();
            if schedule.proof_field_index != field_profile.proof_field_index
                || schedule.evaluation_blowup_factor != field_profile.evaluation_blowup_factor
                || schedule.evaluation_coset_offset != field_profile.evaluation_coset_offset
            {
                return Err(DeterministicArtifactError::InvalidValue);
            }
            let schedule_domain_size = u64::from(schedule.evaluation_blowup_factor)
                .checked_mul(u64::from(committed_degree_capacity))
                .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
            if schedule_domain_size != evaluation_domain_size {
                return Err(DeterministicArtifactError::InvalidValue);
            }
        }
        Ok(evaluation_domain_size)
    }

    pub(crate) fn encode(&self) -> DeterministicArtifactResult<Vec<u8>> {
        let field = &self.committed_material_field;
        let field_tuple = CanonicalTuple::new(
            COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(field.proof_field_index),
                CanonicalItem::unsigned32(field.evaluation_blowup_factor),
                CanonicalItem::unsigned64(field.evaluation_coset_offset),
                CanonicalItem::unsigned32(field.masking_polynomial_maximum_degree),
                CanonicalItem::unsigned32(field.committed_polynomial_degree_bound_exclusive),
            ],
        );
        Ok(CanonicalTuple::new(
            VSS_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![CanonicalItem::nested_tuple(&field_tuple)?],
        )
        .encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> DeterministicArtifactResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_tuple(&tuple, VSS_PROFILE_SCHEMA_IDENTIFIER, 1)?;
        let field_tuple = read_nested_tuple(&tuple.items[0], limits)?;
        require_tuple(
            &field_tuple,
            COMMITTED_MATERIAL_FIELD_PROFILE_SCHEMA_IDENTIFIER,
            5,
        )?;
        Ok(Self {
            committed_material_field: CommittedMaterialFieldProfileArtifact {
                proof_field_index: read_u16(&field_tuple.items[0])?,
                evaluation_blowup_factor: read_u32(&field_tuple.items[1])?,
                evaluation_coset_offset: read_u64(&field_tuple.items[2])?,
                masking_polynomial_maximum_degree: read_u32(&field_tuple.items[3])?,
                committed_polynomial_degree_bound_exclusive: read_u32(&field_tuple.items[4])?,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LatticeCommitmentProfileArtifact {
    pub(crate) commitment_module_rank: u16,
    pub(crate) ordered_commitment_data_prime_indexes: Vec<u16>,
}

impl LatticeCommitmentProfileArtifact {
    pub(crate) fn from_operative_parameters() -> DeterministicArtifactResult<Self> {
        let commitment_module_rank = u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        let ordered_commitment_data_prime_indexes = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .copied()
            .map(|index| {
                u16::try_from(index).map_err(|_| DeterministicArtifactError::ArithmeticOverflow)
            })
            .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        let artifact = Self {
            commitment_module_rank,
            ordered_commitment_data_prime_indexes,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub(crate) fn validate(&self) -> DeterministicArtifactResult<()> {
        let operative_rank = u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        let operative_indexes = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .copied()
            .map(|index| {
                u16::try_from(index).map_err(|_| DeterministicArtifactError::ArithmeticOverflow)
            })
            .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        if self.commitment_module_rank == 0
            || self.commitment_module_rank != operative_rank
            || self.ordered_commitment_data_prime_indexes != operative_indexes
            || self.ordered_commitment_data_prime_indexes.is_empty()
            || self
                .ordered_commitment_data_prime_indexes
                .windows(2)
                .any(|window| window[0] >= window[1])
            || self
                .ordered_commitment_data_prime_indexes
                .iter()
                .any(|index| usize::from(*index) >= DATA_PRIMES.len())
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> DeterministicArtifactResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.commitment_module_rank),
                u16_list(&self.ordered_commitment_data_prime_indexes)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> DeterministicArtifactResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_tuple(&tuple, LATTICE_COMMITMENT_PROFILE_SCHEMA_IDENTIFIER, 2)?;
        let artifact = Self {
            commitment_module_rank: read_u16(&tuple.items[0])?,
            ordered_commitment_data_prime_indexes: read_u16_list(
                &tuple.items[1],
                DATA_PRIMES.len(),
            )?,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum EvaluatorConstantKind {
    CoefficientVector = 1,
    SlotVector = 2,
}

impl EvaluatorConstantKind {
    fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::CoefficientVector),
            2 => Some(Self::SlotVector),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorConstantArtifact {
    pub(crate) constant_kind: EvaluatorConstantKind,
    pub(crate) values: Vec<u64>,
}

impl EvaluatorConstantArtifact {
    fn validate(&self) -> DeterministicArtifactResult<()> {
        let expected_length = match self.constant_kind {
            EvaluatorConstantKind::CoefficientVector => {
                if self.values.is_empty() || self.values.len() > POLYNOMIAL_DEGREE {
                    return Err(DeterministicArtifactError::InvalidValue);
                }
                None
            }
            EvaluatorConstantKind::SlotVector => Some(POLYNOMIAL_DEGREE),
        };
        if expected_length.is_some_and(|length| self.values.len() != length)
            || self.values.iter().any(|value| *value >= PLAINTEXT_MODULUS)
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        Ok(())
    }

    fn constant_hash(&self) -> DeterministicArtifactResult<[u8; 64]> {
        let canonical_bytes = self.to_tuple()?.encode()?;
        Ok(hash_framed_parts_512(
            EVALUATOR_CONSTANT_HASH_DOMAIN,
            &[&canonical_bytes],
        ))
    }

    fn to_tuple(&self) -> DeterministicArtifactResult<CanonicalTuple> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.constant_kind as u16),
                field_element_list(&self.values)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> DeterministicArtifactResult<Self> {
        require_tuple(tuple, EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER, 2)?;
        let constant_kind = EvaluatorConstantKind::from_canonical_code(read_u16(&tuple.items[0])?)
            .ok_or(DeterministicArtifactError::InvalidValue)?;
        let maximum_count = match constant_kind {
            EvaluatorConstantKind::CoefficientVector => POLYNOMIAL_DEGREE,
            EvaluatorConstantKind::SlotVector => POLYNOMIAL_DEGREE,
        };
        let constant = Self {
            constant_kind,
            values: read_field_element_list(&tuple.items[1], maximum_count)?,
        };
        constant.validate()?;
        Ok(constant)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum EvaluatorOpcode {
    ModulusSwitchToLevel = 1,
    NormalizeDecryptionMultiplier = 2,
    CiphertextAdd = 3,
    CiphertextSubtract = 4,
    CiphertextNegate = 5,
    PlaintextAdd = 6,
    PlaintextMultiply = 7,
    CiphertextMultiplyRelinearizeAndDrop = 8,
    CiphertextMultiplyAndRelinearize = 9,
    GaloisRotate = 10,
    DropRegister = 11,
    DeclareOutput = 12,
}

impl EvaluatorOpcode {
    fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::ModulusSwitchToLevel),
            2 => Some(Self::NormalizeDecryptionMultiplier),
            3 => Some(Self::CiphertextAdd),
            4 => Some(Self::CiphertextSubtract),
            5 => Some(Self::CiphertextNegate),
            6 => Some(Self::PlaintextAdd),
            7 => Some(Self::PlaintextMultiply),
            8 => Some(Self::CiphertextMultiplyRelinearizeAndDrop),
            9 => Some(Self::CiphertextMultiplyAndRelinearize),
            10 => Some(Self::GaloisRotate),
            11 => Some(Self::DropRegister),
            12 => Some(Self::DeclareOutput),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorInstructionArtifact {
    pub(crate) opcode: EvaluatorOpcode,
    pub(crate) output_register: Option<u32>,
    pub(crate) input_registers: Vec<u32>,
    pub(crate) immediate0: u64,
    pub(crate) immediate1: u64,
    pub(crate) constant_hash: Option<[u8; 64]>,
}

impl EvaluatorInstructionArtifact {
    fn validate_field_use(&self) -> DeterministicArtifactResult<()> {
        if self.immediate1 != 0
            || self.input_registers.len() > MAXIMUM_EVALUATOR_INPUT_REGISTER_COUNT
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let (input_count, output_required, expected_immediate0, constant_rule) = match self.opcode {
            EvaluatorOpcode::ModulusSwitchToLevel => (1, true, None, ConstantRule::Absent),
            EvaluatorOpcode::NormalizeDecryptionMultiplier => (1, true, None, ConstantRule::Absent),
            EvaluatorOpcode::CiphertextAdd | EvaluatorOpcode::CiphertextSubtract => {
                (2, true, Some(0), ConstantRule::Absent)
            }
            EvaluatorOpcode::CiphertextNegate => (1, true, Some(0), ConstantRule::Absent),
            EvaluatorOpcode::PlaintextAdd | EvaluatorOpcode::PlaintextMultiply => {
                (1, true, Some(0), ConstantRule::Required)
            }
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                (2, true, Some(0), ConstantRule::Absent)
            }
            EvaluatorOpcode::GaloisRotate => (1, true, None, ConstantRule::Absent),
            EvaluatorOpcode::DropRegister => (1, false, Some(0), ConstantRule::Absent),
            EvaluatorOpcode::DeclareOutput => (1, false, None, ConstantRule::Absent),
        };
        if self.input_registers.len() != input_count
            || self.output_register.is_some() != output_required
            || expected_immediate0.is_some_and(|value| self.immediate0 != value)
            || matches!(constant_rule, ConstantRule::Required) != self.constant_hash.is_some()
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        match self.opcode {
            EvaluatorOpcode::ModulusSwitchToLevel
                if self.immediate0 > EVALUATOR_FULL_LEVEL as u64 =>
            {
                Err(DeterministicArtifactError::InvalidValue)
            }
            EvaluatorOpcode::NormalizeDecryptionMultiplier
                if self.immediate0 == 0 || self.immediate0 >= PLAINTEXT_MODULUS =>
            {
                Err(DeterministicArtifactError::InvalidValue)
            }
            EvaluatorOpcode::GaloisRotate
                if self.immediate0 == 1
                    || self.immediate0.is_multiple_of(2)
                    || self.immediate0 >= (2 * POLYNOMIAL_DEGREE) as u64 =>
            {
                Err(DeterministicArtifactError::InvalidValue)
            }
            EvaluatorOpcode::DeclareOutput if !matches!(self.immediate0, 1 | 2) => {
                Err(DeterministicArtifactError::InvalidValue)
            }
            _ => Ok(()),
        }
    }

    fn to_tuple(&self) -> DeterministicArtifactResult<CanonicalTuple> {
        self.validate_field_use()?;
        Ok(CanonicalTuple::new(
            EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.opcode as u16),
                optional_u32(self.output_register)?,
                u32_list(&self.input_registers)?,
                CanonicalItem::unsigned64(self.immediate0),
                CanonicalItem::unsigned64(self.immediate1),
                optional_hash512(self.constant_hash)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> DeterministicArtifactResult<Self> {
        require_tuple(tuple, EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER, 6)?;
        let instruction = Self {
            opcode: EvaluatorOpcode::from_canonical_code(read_u16(&tuple.items[0])?)
                .ok_or(DeterministicArtifactError::InvalidValue)?,
            output_register: read_optional_u32(&tuple.items[1])?,
            input_registers: read_u32_list(
                &tuple.items[2],
                MAXIMUM_EVALUATOR_INPUT_REGISTER_COUNT,
            )?,
            immediate0: read_u64(&tuple.items[3])?,
            immediate1: read_u64(&tuple.items[4])?,
            constant_hash: read_optional_hash512(&tuple.items[5])?,
        };
        instruction.validate_field_use()?;
        Ok(instruction)
    }
}

#[derive(Clone, Copy)]
enum ConstantRule {
    Absent,
    Required,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorInstructionStreamArtifact {
    pub(crate) top_count: u16,
    pub(crate) instructions: Vec<EvaluatorInstructionArtifact>,
}

impl EvaluatorInstructionStreamArtifact {
    fn to_tuple(&self) -> DeterministicArtifactResult<CanonicalTuple> {
        let instruction_tuples = self
            .instructions
            .iter()
            .map(EvaluatorInstructionArtifact::to_tuple)
            .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.top_count),
                nested_tuple_list(&instruction_tuples)?,
            ],
        ))
    }

    fn from_tuple(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
    ) -> DeterministicArtifactResult<Self> {
        require_tuple(tuple, EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER, 2)?;
        let instructions =
            read_nested_tuple_list(&tuple.items[1], limits, MAXIMUM_EVALUATOR_INSTRUCTION_COUNT)?
                .iter()
                .map(EvaluatorInstructionArtifact::from_tuple)
                .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        Ok(Self {
            top_count: read_u16(&tuple.items[0])?,
            instructions,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorProgramSetArtifact {
    pub(crate) constants: Vec<EvaluatorConstantArtifact>,
    pub(crate) streams: Vec<EvaluatorInstructionStreamArtifact>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EvaluatorRegisterState {
    level: usize,
    decryption_multiplier: u64,
}

impl EvaluatorProgramSetArtifact {
    pub(crate) fn from_unmaterialized_operative_evaluator() -> Self {
        Self {
            constants: Vec::new(),
            streams: (1..=FIRST_PROFILE_OPTION_COUNT)
                .map(|top_count| EvaluatorInstructionStreamArtifact {
                    top_count: top_count as u16,
                    instructions: Vec::new(),
                })
                .collect(),
        }
    }

    pub(crate) fn validate_catalog_shape(&self) -> DeterministicArtifactResult<()> {
        if self.constants.len() > MAXIMUM_EVALUATOR_CONSTANT_COUNT
            || self.streams.len() != FIRST_PROFILE_OPTION_COUNT
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let mut previous_hash = None;
        for constant in &self.constants {
            constant.validate()?;
            let constant_hash = constant.constant_hash()?;
            if previous_hash.is_some_and(|previous| previous >= constant_hash) {
                return Err(DeterministicArtifactError::InvalidOrdering);
            }
            previous_hash = Some(constant_hash);
        }
        for (stream_index, stream) in self.streams.iter().enumerate() {
            if usize::from(stream.top_count) != stream_index + 1
                || stream.instructions.len() > MAXIMUM_EVALUATOR_INSTRUCTION_COUNT
            {
                return Err(DeterministicArtifactError::InvalidOrdering);
            }
            for instruction in &stream.instructions {
                instruction.validate_field_use()?;
            }
        }
        Ok(())
    }

    pub(crate) fn validate_materialized_structure(
        &self,
        ordered_galois_elements: &[usize],
    ) -> DeterministicArtifactResult<()> {
        self.validate_catalog_shape()?;
        if self.constants.is_empty()
            || self
                .streams
                .iter()
                .any(|stream| stream.instructions.is_empty())
        {
            return Err(DeterministicArtifactError::IncompleteEvaluatorProgram);
        }
        let constants = self
            .constants
            .iter()
            .map(|constant| Ok((constant.constant_hash()?, constant.constant_kind)))
            .collect::<DeterministicArtifactResult<BTreeMap<_, _>>>()?;
        let galois_elements = ordered_galois_elements
            .iter()
            .copied()
            .map(|element| {
                u64::try_from(element).map_err(|_| DeterministicArtifactError::ArithmeticOverflow)
            })
            .collect::<DeterministicArtifactResult<BTreeSet<_>>>()?;
        if galois_elements.len() != ordered_galois_elements.len() {
            return Err(DeterministicArtifactError::DuplicateValue);
        }
        for stream in &self.streams {
            self.validate_stream(stream, &constants, &galois_elements)?;
        }
        Ok(())
    }

    fn validate_stream(
        &self,
        stream: &EvaluatorInstructionStreamArtifact,
        constants: &BTreeMap<[u8; 64], EvaluatorConstantKind>,
        galois_elements: &BTreeSet<u64>,
    ) -> DeterministicArtifactResult<()> {
        let mut register_states = BTreeMap::from([(
            0_u32,
            EvaluatorRegisterState {
                level: EVALUATOR_FULL_LEVEL,
                decryption_multiplier: 1,
            },
        )]);
        let mut dropped_registers = BTreeSet::new();
        let mut next_output_register = 1_u32;
        let mut declared_outputs = BTreeMap::new();
        let last_use = stream
            .instructions
            .iter()
            .enumerate()
            .flat_map(|(instruction_index, instruction)| {
                instruction
                    .input_registers
                    .iter()
                    .copied()
                    .map(move |register| (register, instruction_index))
            })
            .fold(BTreeMap::new(), |mut positions, (register, position)| {
                positions.insert(register, position);
                positions
            });

        for (instruction_index, instruction) in stream.instructions.iter().enumerate() {
            instruction.validate_field_use()?;
            let input_states = instruction
                .input_registers
                .iter()
                .map(|register| {
                    if dropped_registers.contains(register) {
                        return Err(DeterministicArtifactError::UnresolvedReference);
                    }
                    register_states
                        .get(register)
                        .copied()
                        .ok_or(DeterministicArtifactError::UnresolvedReference)
                })
                .collect::<DeterministicArtifactResult<Vec<_>>>()?;
            if instruction.opcode == EvaluatorOpcode::DropRegister
                && last_use.get(&instruction.input_registers[0]).copied() != Some(instruction_index)
            {
                return Err(DeterministicArtifactError::InvalidValue);
            }
            let output_state = match instruction.opcode {
                EvaluatorOpcode::ModulusSwitchToLevel => {
                    let target_level = usize::try_from(instruction.immediate0)
                        .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
                    let input = input_states[0];
                    if target_level >= input.level {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    let mut multiplier = input.decryption_multiplier;
                    for dropped_prime in DATA_PRIMES[(target_level + 1)..=input.level].iter().rev()
                    {
                        multiplier = multiply_mod_plaintext(multiplier, *dropped_prime)?;
                    }
                    Some(EvaluatorRegisterState {
                        level: target_level,
                        decryption_multiplier: multiplier,
                    })
                }
                EvaluatorOpcode::NormalizeDecryptionMultiplier => {
                    let input = input_states[0];
                    if instruction.immediate0 == input.decryption_multiplier {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    Some(EvaluatorRegisterState {
                        level: input.level,
                        decryption_multiplier: instruction.immediate0,
                    })
                }
                EvaluatorOpcode::CiphertextAdd | EvaluatorOpcode::CiphertextSubtract => {
                    if input_states[0] != input_states[1] {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    Some(input_states[0])
                }
                EvaluatorOpcode::CiphertextNegate => Some(input_states[0]),
                EvaluatorOpcode::PlaintextAdd | EvaluatorOpcode::PlaintextMultiply => {
                    let constant_hash = instruction
                        .constant_hash
                        .ok_or(DeterministicArtifactError::UnresolvedReference)?;
                    let constant_kind = constants
                        .get(&constant_hash)
                        .ok_or(DeterministicArtifactError::UnresolvedReference)?;
                    if instruction.opcode == EvaluatorOpcode::PlaintextAdd
                        && *constant_kind != EvaluatorConstantKind::SlotVector
                    {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    Some(input_states[0])
                }
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => {
                    if input_states[0].level != input_states[1].level || input_states[0].level == 0
                    {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    let product_multiplier = multiply_mod_plaintext(
                        input_states[0].decryption_multiplier,
                        input_states[1].decryption_multiplier,
                    )?;
                    Some(EvaluatorRegisterState {
                        level: input_states[0].level - 1,
                        decryption_multiplier: multiply_mod_plaintext(
                            product_multiplier,
                            DATA_PRIMES[input_states[0].level],
                        )?,
                    })
                }
                EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                    if input_states[0].level != input_states[1].level {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    Some(EvaluatorRegisterState {
                        level: input_states[0].level,
                        decryption_multiplier: multiply_mod_plaintext(
                            input_states[0].decryption_multiplier,
                            input_states[1].decryption_multiplier,
                        )?,
                    })
                }
                EvaluatorOpcode::GaloisRotate => {
                    if !galois_elements.contains(&instruction.immediate0) {
                        return Err(DeterministicArtifactError::UnresolvedReference);
                    }
                    Some(input_states[0])
                }
                EvaluatorOpcode::DropRegister => {
                    let register = instruction.input_registers[0];
                    if declared_outputs.values().any(|output| *output == register)
                        || !dropped_registers.insert(register)
                    {
                        return Err(DeterministicArtifactError::InvalidValue);
                    }
                    None
                }
                EvaluatorOpcode::DeclareOutput => {
                    let role = instruction.immediate0;
                    let register = instruction.input_registers[0];
                    if declared_outputs.insert(role, register).is_some() {
                        return Err(DeterministicArtifactError::DuplicateValue);
                    }
                    None
                }
            };
            if let Some(output_register) = instruction.output_register {
                if output_register != next_output_register
                    || register_states.contains_key(&output_register)
                {
                    return Err(DeterministicArtifactError::InvalidOrdering);
                }
                register_states.insert(
                    output_register,
                    output_state.ok_or(DeterministicArtifactError::InvalidValue)?,
                );
                next_output_register = next_output_register
                    .checked_add(1)
                    .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
            } else if output_state.is_some() {
                return Err(DeterministicArtifactError::InvalidValue);
            }
        }

        let instruction_count = stream.instructions.len();
        if instruction_count < 2
            || stream.instructions[instruction_count - 2].opcode != EvaluatorOpcode::DeclareOutput
            || stream.instructions[instruction_count - 2].immediate0 != 1
            || stream.instructions[instruction_count - 1].opcode != EvaluatorOpcode::DeclareOutput
            || stream.instructions[instruction_count - 1].immediate0 != 2
            || declared_outputs.len() != 2
        {
            return Err(DeterministicArtifactError::InvalidOrdering);
        }
        let identifier_register = *declared_outputs
            .get(&1)
            .ok_or(DeterministicArtifactError::UnresolvedReference)?;
        let order_register = *declared_outputs
            .get(&2)
            .ok_or(DeterministicArtifactError::UnresolvedReference)?;
        if identifier_register == order_register {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let identifier_state = register_states
            .get(&identifier_register)
            .ok_or(DeterministicArtifactError::UnresolvedReference)?;
        let order_state = register_states
            .get(&order_register)
            .ok_or(DeterministicArtifactError::UnresolvedReference)?;
        if identifier_state.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
            || order_state.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        for register in register_states.keys().copied() {
            if register != identifier_register
                && register != order_register
                && !dropped_registers.contains(&register)
            {
                return Err(DeterministicArtifactError::InvalidValue);
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> DeterministicArtifactResult<Vec<u8>> {
        self.validate_catalog_shape()?;
        let constant_tuples = self
            .constants
            .iter()
            .map(EvaluatorConstantArtifact::to_tuple)
            .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        let stream_tuples = self
            .streams
            .iter()
            .map(EvaluatorInstructionStreamArtifact::to_tuple)
            .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                nested_tuple_list(&constant_tuples)?,
                nested_tuple_list(&stream_tuples)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> DeterministicArtifactResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_tuple(&tuple, EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER, 2)?;
        let constants =
            read_nested_tuple_list(&tuple.items[0], limits, MAXIMUM_EVALUATOR_CONSTANT_COUNT)?
                .iter()
                .map(EvaluatorConstantArtifact::from_tuple)
                .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        let streams = read_nested_tuple_list(&tuple.items[1], limits, FIRST_PROFILE_OPTION_COUNT)?
            .iter()
            .map(|stream| EvaluatorInstructionStreamArtifact::from_tuple(stream, limits))
            .collect::<DeterministicArtifactResult<Vec<_>>>()?;
        let artifact = Self { constants, streams };
        artifact.validate_catalog_shape()?;
        Ok(artifact)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetDecryptionProfileArtifact {
    pub(crate) flooding_coefficient_bound_words_little_endian: Vec<u64>,
}

impl TargetDecryptionProfileArtifact {
    pub(crate) fn from_operative_parameters() -> DeterministicArtifactResult<Self> {
        let target_modulus = target_modulus();
        let word_count = usize::try_from(target_modulus.bits().div_ceil(64))
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        let coefficient_bound = u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND)
            .map_err(|_| DeterministicArtifactError::InvalidValue)?;
        let mut words = vec![0_u64; word_count];
        *words
            .first_mut()
            .ok_or(DeterministicArtifactError::InvalidValue)? = coefficient_bound;
        let artifact = Self {
            flooding_coefficient_bound_words_little_endian: words,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub(crate) fn validate(&self) -> DeterministicArtifactResult<()> {
        let modulus = target_modulus();
        let expected_word_count = usize::try_from(modulus.bits().div_ceil(64))
            .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)?;
        if self.flooding_coefficient_bound_words_little_endian.len() != expected_word_count {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let bound =
            big_uint_from_little_endian_words(&self.flooding_coefficient_bound_words_little_endian);
        if bound == BigUint::from(0_u8) || bound >= modulus {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let modulus_bit_length = target_modulus().bits();
        let high_word_bits = modulus_bit_length % 64;
        if high_word_bits != 0 {
            let high_word = *self
                .flooding_coefficient_bound_words_little_endian
                .last()
                .ok_or(DeterministicArtifactError::InvalidValue)?;
            if high_word >> high_word_bits != 0 {
                return Err(DeterministicArtifactError::InvalidValue);
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> DeterministicArtifactResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![u64_list(
                &self.flooding_coefficient_bound_words_little_endian,
            )?],
        )
        .encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> DeterministicArtifactResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_tuple(&tuple, TARGET_DECRYPTION_PROFILE_SCHEMA_IDENTIFIER, 1)?;
        let artifact = Self {
            flooding_coefficient_bound_words_little_endian: read_u64_list(
                &tuple.items[0],
                DATA_PRIMES.len(),
            )?,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeterministicSuiteArtifactSet {
    pub(crate) encoder_and_ballot_layout: EncoderAndBallotLayoutArtifact,
    pub(crate) vss_profile: VssProfileArtifact,
    pub(crate) lattice_commitment_profile: LatticeCommitmentProfileArtifact,
    pub(crate) evaluator_program_set: EvaluatorProgramSetArtifact,
    pub(crate) target_decryption_profile: TargetDecryptionProfileArtifact,
}

impl DeterministicSuiteArtifactSet {
    pub(crate) fn from_operative_parameters() -> DeterministicArtifactResult<Self> {
        Ok(Self {
            encoder_and_ballot_layout: EncoderAndBallotLayoutArtifact::from_operative_parameters()?,
            vss_profile: VssProfileArtifact::from_operative_parameters()?,
            lattice_commitment_profile:
                LatticeCommitmentProfileArtifact::from_operative_parameters()?,
            evaluator_program_set:
                EvaluatorProgramSetArtifact::from_unmaterialized_operative_evaluator(),
            target_decryption_profile: TargetDecryptionProfileArtifact::from_operative_parameters(
            )?,
        })
    }

    pub(crate) fn validate_available_structure(
        &self,
        proof_profile: &ProofProfileSetArtifact,
        ordered_galois_elements: &[usize],
    ) -> DeterministicArtifactResult<()> {
        self.encoder_and_ballot_layout.validate()?;
        // The fixed VSS field and every consuming family schedule already
        // align. Their relation-program domains cannot align until those
        // programs are lowered: the current scaffolding derives 524288 while
        // the persistent-material domain is 262144. Final validation keeps
        // enforcing exact equality through `VssProfileArtifact::validate`;
        // this development-only structural pass deliberately stops short of
        // manufacturing that missing relation-program result.
        self.vss_profile
            .validate_field_and_consuming_schedules(proof_profile)?;
        self.lattice_commitment_profile.validate()?;
        self.evaluator_program_set.validate_catalog_shape()?;
        self.target_decryption_profile.validate()?;

        let limits = CanonicalDecodeLimits::default();
        let layout_bytes = self.encoder_and_ballot_layout.encode()?;
        if EncoderAndBallotLayoutArtifact::decode(&layout_bytes, &limits)?
            != self.encoder_and_ballot_layout
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let vss_bytes = self.vss_profile.encode()?;
        let decoded_vss = VssProfileArtifact::decode(&vss_bytes, &limits)?;
        decoded_vss.validate_field_and_consuming_schedules(proof_profile)?;
        if decoded_vss != self.vss_profile {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let commitment_bytes = self.lattice_commitment_profile.encode()?;
        if LatticeCommitmentProfileArtifact::decode(&commitment_bytes, &limits)?
            != self.lattice_commitment_profile
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        let evaluator_bytes = self.evaluator_program_set.encode()?;
        if EvaluatorProgramSetArtifact::decode(&evaluator_bytes, &limits)?
            != self.evaluator_program_set
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        match self
            .evaluator_program_set
            .validate_materialized_structure(ordered_galois_elements)
        {
            Err(DeterministicArtifactError::IncompleteEvaluatorProgram) => {}
            Ok(()) => return Err(DeterministicArtifactError::InvalidValue),
            Err(error) => return Err(error),
        }
        let target_bytes = self.target_decryption_profile.encode()?;
        if TargetDecryptionProfileArtifact::decode(&target_bytes, &limits)?
            != self.target_decryption_profile
        {
            return Err(DeterministicArtifactError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn semantic_blockers(
        &self,
        proof_profile: &ProofProfileSetArtifact,
    ) -> DeterministicArtifactResult<Vec<SuiteArtifactSemanticBlocker>> {
        match self.vss_profile.validate(proof_profile) {
            Ok(()) | Err(DeterministicArtifactError::IncompatiblePersistentMaterialDomain) => {}
            Err(error) => return Err(error),
        }
        Ok(vec![
            SuiteArtifactSemanticBlocker::ProofRelationProgramsNotLowered,
            SuiteArtifactSemanticBlocker::PersistentMaterialMaskImageEvidenceMissing,
            SuiteArtifactSemanticBlocker::LatticeCommitmentConcreteSecurityEvidenceMissing,
            SuiteArtifactSemanticBlocker::EvaluatorProgramNotMaterialized,
            SuiteArtifactSemanticBlocker::EvaluatorCorrectnessAndErrorEvidenceMissing,
            SuiteArtifactSemanticBlocker::TargetDecryptionTheoremEvidenceMissing,
        ])
    }

    /// Preserves the pre-existing development transcript domain while final
    /// suite construction remains closed. These bytes are not accepted suite
    /// artifacts and must never be returned by a public generation command.
    pub(crate) fn encode_incomplete_development_bodies(
        &self,
        proof_profile_bytes: Vec<u8>,
    ) -> DeterministicArtifactResult<Vec<Vec<u8>>> {
        Ok(vec![
            self.encoder_and_ballot_layout.encode()?,
            self.vss_profile.encode()?,
            self.lattice_commitment_profile.encode()?,
            proof_profile_bytes,
            self.evaluator_program_set.encode()?,
            self.target_decryption_profile.encode()?,
        ])
    }
}

fn target_modulus() -> BigUint {
    DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
        .iter()
        .fold(BigUint::from(1_u8), |product, prime| product * prime)
}

fn big_uint_from_little_endian_words(words: &[u64]) -> BigUint {
    words.iter().rev().fold(BigUint::from(0_u8), |value, word| {
        (value << 64) + BigUint::from(*word)
    })
}

fn multiply_mod_plaintext(left: u64, right: u64) -> DeterministicArtifactResult<u64> {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(PLAINTEXT_MODULUS))
        .map_err(|_| DeterministicArtifactError::ArithmeticOverflow)
}

fn require_tuple(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> DeterministicArtifactResult<()> {
    if tuple.schema_identifier != schema_identifier {
        return Err(DeterministicArtifactError::WrongSchema);
    }
    if tuple.schema_version != SCHEMA_VERSION {
        return Err(DeterministicArtifactError::WrongVersion);
    }
    if tuple.items.len() != item_count {
        return Err(DeterministicArtifactError::WrongItemCount);
    }
    Ok(())
}

fn read_fixed<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> DeterministicArtifactResult<[u8; BYTE_LENGTH]> {
    if item.item_type() != expected_type || item.canonical_bytes().len() != BYTE_LENGTH {
        return Err(DeterministicArtifactError::WrongItemType);
    }
    let mut bytes = [0_u8; BYTE_LENGTH];
    bytes.copy_from_slice(item.canonical_bytes());
    Ok(bytes)
}

fn read_u16(item: &CanonicalItem) -> DeterministicArtifactResult<u16> {
    Ok(u16::from_le_bytes(read_fixed::<2>(
        item,
        CanonicalItemType::Unsigned16,
    )?))
}

fn read_u32(item: &CanonicalItem) -> DeterministicArtifactResult<u32> {
    Ok(u32::from_le_bytes(read_fixed::<4>(
        item,
        CanonicalItemType::Unsigned32,
    )?))
}

fn read_u64(item: &CanonicalItem) -> DeterministicArtifactResult<u64> {
    Ok(u64::from_le_bytes(read_fixed::<8>(
        item,
        CanonicalItemType::Unsigned64,
    )?))
}

fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> DeterministicArtifactResult<CanonicalTuple> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(DeterministicArtifactError::WrongItemType);
    }
    Ok(CanonicalTuple::decode(item.canonical_bytes(), limits)?)
}

fn read_optional_fixed<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    contained_type: CanonicalItemType,
) -> DeterministicArtifactResult<Option<[u8; BYTE_LENGTH]>> {
    if item.item_type() != CanonicalItemType::Optional {
        return Err(DeterministicArtifactError::WrongItemType);
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]]) != contained_type.canonical_code()
    {
        return Err(DeterministicArtifactError::WrongItemType);
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == BYTE_LENGTH + 3 => {
            let mut value = [0_u8; BYTE_LENGTH];
            value.copy_from_slice(&bytes[3..]);
            Ok(Some(value))
        }
        _ => Err(DeterministicArtifactError::InvalidValue),
    }
}

fn read_optional_u32(item: &CanonicalItem) -> DeterministicArtifactResult<Option<u32>> {
    Ok(read_optional_fixed::<4>(item, CanonicalItemType::Unsigned32)?.map(u32::from_le_bytes))
}

fn read_optional_hash512(item: &CanonicalItem) -> DeterministicArtifactResult<Option<[u8; 64]>> {
    read_optional_fixed::<64>(item, CanonicalItemType::Hash512)
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
    maximum_count: usize,
) -> DeterministicArtifactResult<(usize, &[u8])> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(DeterministicArtifactError::WrongItemType);
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(DeterministicArtifactError::WrongItemType);
    }
    let count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if count > maximum_count {
        return Err(DeterministicArtifactError::LimitExceeded);
    }
    Ok((count, &bytes[6..]))
}

fn read_fixed_list<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    element_type: CanonicalItemType,
    maximum_count: usize,
) -> DeterministicArtifactResult<Vec<[u8; BYTE_LENGTH]>> {
    let (count, payload) = read_list_header(item, element_type, maximum_count)?;
    let expected_length = count
        .checked_mul(BYTE_LENGTH)
        .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
    if payload.len() != expected_length {
        return Err(DeterministicArtifactError::InvalidValue);
    }
    payload
        .chunks_exact(BYTE_LENGTH)
        .map(|chunk| {
            let mut value = [0_u8; BYTE_LENGTH];
            value.copy_from_slice(chunk);
            Ok(value)
        })
        .collect()
}

fn read_u16_list(
    item: &CanonicalItem,
    maximum_count: usize,
) -> DeterministicArtifactResult<Vec<u16>> {
    read_fixed_list::<2>(item, CanonicalItemType::Unsigned16, maximum_count)?
        .into_iter()
        .map(|value| Ok(u16::from_le_bytes(value)))
        .collect()
}

fn read_u32_list(
    item: &CanonicalItem,
    maximum_count: usize,
) -> DeterministicArtifactResult<Vec<u32>> {
    read_fixed_list::<4>(item, CanonicalItemType::Unsigned32, maximum_count)?
        .into_iter()
        .map(|value| Ok(u32::from_le_bytes(value)))
        .collect()
}

fn read_u64_list(
    item: &CanonicalItem,
    maximum_count: usize,
) -> DeterministicArtifactResult<Vec<u64>> {
    read_fixed_list::<8>(item, CanonicalItemType::Unsigned64, maximum_count)?
        .into_iter()
        .map(|value| Ok(u64::from_le_bytes(value)))
        .collect()
}

fn read_field_element_list(
    item: &CanonicalItem,
    maximum_count: usize,
) -> DeterministicArtifactResult<Vec<u64>> {
    read_fixed_list::<8>(item, CanonicalItemType::FieldElement, maximum_count)?
        .into_iter()
        .map(|value| Ok(u64::from_le_bytes(value)))
        .collect()
}

fn read_nested_tuple_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    maximum_count: usize,
) -> DeterministicArtifactResult<Vec<CanonicalTuple>> {
    let (count, payload) = read_list_header(item, CanonicalItemType::NestedTuple, maximum_count)?;
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0_usize;
    for _ in 0..count {
        let tuple_length = canonical_tuple_prefix_length(
            payload
                .get(offset..)
                .ok_or(DeterministicArtifactError::InvalidValue)?,
        )?;
        let end = offset
            .checked_add(tuple_length)
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        tuples.push(CanonicalTuple::decode(
            payload
                .get(offset..end)
                .ok_or(DeterministicArtifactError::InvalidValue)?,
            limits,
        )?);
        offset = end;
    }
    if offset != payload.len() {
        return Err(DeterministicArtifactError::InvalidValue);
    }
    Ok(tuples)
}

fn canonical_tuple_prefix_length(bytes: &[u8]) -> DeterministicArtifactResult<usize> {
    if bytes.len() < 8 {
        return Err(DeterministicArtifactError::InvalidValue);
    }
    let item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header_end = offset
            .checked_add(6)
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        let header = bytes
            .get(offset..header_end)
            .ok_or(DeterministicArtifactError::InvalidValue)?;
        let item_length = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        offset = header_end
            .checked_add(item_length)
            .ok_or(DeterministicArtifactError::ArithmeticOverflow)?;
        if offset > bytes.len() {
            return Err(DeterministicArtifactError::InvalidValue);
        }
    }
    Ok(offset)
}

fn nested_tuple_list(tuples: &[CanonicalTuple]) -> DeterministicArtifactResult<CanonicalItem> {
    let items = tuples
        .iter()
        .map(CanonicalItem::nested_tuple)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::NestedTuple,
        &items,
    )?)
}

fn u16_list(values: &[u16]) -> DeterministicArtifactResult<CanonicalItem> {
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

fn u32_list(values: &[u32]) -> DeterministicArtifactResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned32)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned32,
        &items,
    )?)
}

fn u64_list(values: &[u64]) -> DeterministicArtifactResult<CanonicalItem> {
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

fn field_element_list(values: &[u64]) -> DeterministicArtifactResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(|value| {
            CanonicalItem::from_canonical_bytes(
                CanonicalItemType::FieldElement,
                value.to_le_bytes().to_vec(),
                &CanonicalDecodeLimits::default(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::FieldElement,
        &items,
    )?)
}

fn optional_u32(value: Option<u32>) -> DeterministicArtifactResult<CanonicalItem> {
    let item = value.map(CanonicalItem::unsigned32);
    Ok(CanonicalItem::optional(
        CanonicalItemType::Unsigned32,
        item.as_ref(),
    )?)
}

fn optional_hash512(value: Option<[u8; 64]>) -> DeterministicArtifactResult<CanonicalItem> {
    let item = value.map(CanonicalItem::hash512);
    Ok(CanonicalItem::optional(
        CanonicalItemType::Hash512,
        item.as_ref(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        build_relation_plan_catalog, profile_artifact::ProofProfileSetArtifact,
    };

    fn proof_profile() -> ProofProfileSetArtifact {
        let relation_plans =
            build_relation_plan_catalog(1, 16).expect("first-profile relation plans");
        ProofProfileSetArtifact::from_unlowered_relation_plan_catalog(&relation_plans)
            .expect("typed proof profile")
    }

    fn materialized_program() -> EvaluatorProgramSetArtifact {
        let constant = EvaluatorConstantArtifact {
            constant_kind: EvaluatorConstantKind::CoefficientVector,
            values: vec![1],
        };
        let constant_hash = constant.constant_hash().expect("constant hash");
        let streams = (1..=FIRST_PROFILE_OPTION_COUNT)
            .map(|top_count| EvaluatorInstructionStreamArtifact {
                top_count: top_count as u16,
                instructions: vec![
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::ModulusSwitchToLevel,
                        output_register: Some(1),
                        input_registers: vec![0],
                        immediate0: CANONICAL_TARGET_CIPHERTEXT_LEVEL as u64,
                        immediate1: 0,
                        constant_hash: None,
                    },
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::DropRegister,
                        output_register: None,
                        input_registers: vec![0],
                        immediate0: 0,
                        immediate1: 0,
                        constant_hash: None,
                    },
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::CiphertextNegate,
                        output_register: Some(2),
                        input_registers: vec![1],
                        immediate0: 0,
                        immediate1: 0,
                        constant_hash: None,
                    },
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::DropRegister,
                        output_register: None,
                        input_registers: vec![1],
                        immediate0: 0,
                        immediate1: 0,
                        constant_hash: None,
                    },
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::PlaintextMultiply,
                        output_register: Some(3),
                        input_registers: vec![2],
                        immediate0: 0,
                        immediate1: 0,
                        constant_hash: Some(constant_hash),
                    },
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::DeclareOutput,
                        output_register: None,
                        input_registers: vec![2],
                        immediate0: 1,
                        immediate1: 0,
                        constant_hash: None,
                    },
                    EvaluatorInstructionArtifact {
                        opcode: EvaluatorOpcode::DeclareOutput,
                        output_register: None,
                        input_registers: vec![3],
                        immediate0: 2,
                        immediate1: 0,
                        constant_hash: None,
                    },
                ],
            })
            .collect();
        EvaluatorProgramSetArtifact {
            constants: vec![constant],
            streams,
        }
    }

    #[test]
    fn encoder_layout_round_trips_and_proves_the_complete_slot_partition() {
        let artifact =
            EncoderAndBallotLayoutArtifact::from_operative_parameters().expect("operative layout");
        let bytes = artifact.encode().expect("layout bytes");
        assert_eq!(
            EncoderAndBallotLayoutArtifact::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("decoded layout"),
            artifact
        );

        let mut wrong_root = artifact.clone();
        wrong_root.primitive_two_n_root = 1;
        assert_eq!(
            wrong_root.validate(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut wrong_generator = artifact.clone();
        wrong_generator.slot_generator = 5;
        assert_eq!(
            wrong_generator.validate(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut wrong_reserved_rule = artifact.clone();
        wrong_reserved_rule.reserved_slot_rule = 0;
        assert_eq!(
            wrong_reserved_rule.validate(),
            Err(DeterministicArtifactError::InvalidValue)
        );

        let mut wrong_version = bytes.clone();
        wrong_version[2..4].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            EncoderAndBallotLayoutArtifact::decode(
                &wrong_version,
                &CanonicalDecodeLimits::default()
            ),
            Err(DeterministicArtifactError::WrongVersion)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            EncoderAndBallotLayoutArtifact::decode(&trailing, &CanonicalDecodeLimits::default()),
            Err(DeterministicArtifactError::Canonical(_))
        ));
    }

    #[test]
    fn encoder_layout_rejects_a_short_order_slot_generator() {
        assert_eq!(
            logical_slot_exponents(9),
            Err(DeterministicArtifactError::InvalidValue)
        );
    }

    #[test]
    fn encoder_layout_rejects_a_generator_whose_subgroup_contains_negation() {
        let automorphism_modulus = (2 * POLYNOMIAL_DEGREE) as u64;
        let generator_containing_negation = automorphism_modulus - 1;

        assert_eq!(
            logical_slot_exponents(generator_containing_negation),
            Err(DeterministicArtifactError::InvalidValue)
        );
    }

    #[test]
    fn encoder_layout_rejects_duplicate_or_missing_odd_exponent_coverage() {
        let automorphism_modulus = (2 * POLYNOMIAL_DEGREE) as u64;
        let complete_coverage = logical_slot_exponents(u64::from(LOGICAL_SLOT_GENERATOR))
            .expect("operative slot generator coverage");

        let mut duplicate_coverage = complete_coverage.clone();
        let first_exponent = duplicate_coverage[0];
        *duplicate_coverage
            .last_mut()
            .expect("operative coverage is non-empty") = first_exponent;
        assert_eq!(
            validate_complete_odd_exponent_coverage(&duplicate_coverage, automorphism_modulus),
            Err(DeterministicArtifactError::DuplicateValue)
        );

        let mut missing_coverage = complete_coverage;
        missing_coverage.pop();
        assert_eq!(
            validate_complete_odd_exponent_coverage(&missing_coverage, automorphism_modulus),
            Err(DeterministicArtifactError::InvalidValue)
        );
    }

    #[test]
    fn vss_profile_round_trips_and_exposes_the_unlowered_domain_mismatch() {
        let proof_profile_artifact = proof_profile();
        let artifact =
            VssProfileArtifact::from_operative_parameters().expect("operative VSS profile");
        assert_eq!(
            artifact.validate(&proof_profile_artifact),
            Err(DeterministicArtifactError::IncompatiblePersistentMaterialDomain)
        );
        artifact
            .validate_field_and_consuming_schedules(&proof_profile_artifact)
            .expect("VSS field schedules align before relation lowering");
        let bytes = artifact.encode().expect("VSS profile bytes");
        let decoded = VssProfileArtifact::decode(&bytes, &CanonicalDecodeLimits::default())
            .expect("decoded VSS profile");
        assert_eq!(decoded, artifact);
        assert_eq!(
            decoded.validate(&proof_profile_artifact),
            Err(DeterministicArtifactError::IncompatiblePersistentMaterialDomain)
        );

        let mut wrong_blowup = artifact.clone();
        wrong_blowup
            .committed_material_field
            .evaluation_blowup_factor = 4;
        assert_eq!(
            wrong_blowup.validate(&proof_profile_artifact),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut subgroup_coset = artifact.clone();
        subgroup_coset
            .committed_material_field
            .evaluation_coset_offset = 1;
        assert_eq!(
            subgroup_coset.validate(&proof_profile_artifact),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut overlapping_degree = artifact.clone();
        overlapping_degree
            .committed_material_field
            .committed_polynomial_degree_bound_exclusive = 16_384;
        assert_eq!(
            overlapping_degree.validate(&proof_profile_artifact),
            Err(DeterministicArtifactError::InvalidValue)
        );

        let mut mismatched_profile = proof_profile_artifact;
        let material_family = mismatched_profile
            .proof_families
            .iter_mut()
            .find(|family| family.application_statement_schema_identifier == 0x2110)
            .expect("material family");
        material_family.field_schedule.evaluation_coset_offset += 1;
        assert_eq!(
            artifact.validate(&mismatched_profile),
            Err(DeterministicArtifactError::InvalidValue)
        );

        let mut wrong_field_root = proof_profile();
        wrong_field_root.proof_fields[0].maximum_two_adic_subgroup_generator = 1;
        assert_eq!(
            artifact.validate_field_and_consuming_schedules(&wrong_field_root),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut invalid_field_modulus = proof_profile();
        invalid_field_modulus.proof_fields[0].base_field_modulus = 0;
        assert_eq!(
            artifact.validate_field_and_consuming_schedules(&invalid_field_modulus),
            Err(DeterministicArtifactError::InvalidValue)
        );
    }

    #[test]
    fn lattice_commitment_profile_is_derived_from_the_operative_setup_constants() {
        let artifact = LatticeCommitmentProfileArtifact::from_operative_parameters()
            .expect("operative commitment profile");
        assert_eq!(
            usize::from(artifact.commitment_module_rank),
            SETUP_COMMITMENT_MODULE_RANK
        );
        assert_eq!(
            artifact
                .ordered_commitment_data_prime_indexes
                .iter()
                .map(|index| usize::from(*index))
                .collect::<Vec<_>>(),
            SETUP_COMMITMENT_MODULUS_LIMB_INDICES.to_vec()
        );
        let bytes = artifact.encode().expect("commitment profile bytes");
        assert_eq!(
            LatticeCommitmentProfileArtifact::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("decoded commitment profile"),
            artifact
        );

        for changed in [
            LatticeCommitmentProfileArtifact {
                commitment_module_rank: 0,
                ..artifact.clone()
            },
            LatticeCommitmentProfileArtifact {
                ordered_commitment_data_prime_indexes: vec![0, 2, 1],
                ..artifact.clone()
            },
            LatticeCommitmentProfileArtifact {
                ordered_commitment_data_prime_indexes: vec![0, 1, 1],
                ..artifact.clone()
            },
            LatticeCommitmentProfileArtifact {
                ordered_commitment_data_prime_indexes: vec![0, 1, u16::MAX],
                ..artifact.clone()
            },
        ] {
            assert_eq!(
                changed.validate(),
                Err(DeterministicArtifactError::InvalidValue)
            );
        }
    }

    #[test]
    fn evaluator_codec_preserves_twenty_streams_but_refuses_empty_programs() {
        let artifact = EvaluatorProgramSetArtifact::from_unmaterialized_operative_evaluator();
        artifact
            .validate_catalog_shape()
            .expect("twenty ordered stream shells");
        assert_eq!(artifact.streams.len(), FIRST_PROFILE_OPTION_COUNT);
        let bytes = artifact.encode().expect("unmaterialized development bytes");
        assert_eq!(
            EvaluatorProgramSetArtifact::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("decoded program shells"),
            artifact
        );
        assert_eq!(
            artifact.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::IncompleteEvaluatorProgram)
        );

        let mut missing_stream = artifact.clone();
        missing_stream.streams.pop();
        assert_eq!(
            missing_stream.validate_catalog_shape(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut reordered = artifact;
        reordered.streams.swap(0, 1);
        assert_eq!(
            reordered.validate_catalog_shape(),
            Err(DeterministicArtifactError::InvalidOrdering)
        );
    }

    #[test]
    fn evaluator_validator_checks_register_liveness_and_terminal_basis() {
        let artifact = materialized_program();
        artifact
            .validate_materialized_structure(&[3])
            .expect("structurally materialized program");
        let bytes = artifact.encode().expect("program bytes");
        let decoded =
            EvaluatorProgramSetArtifact::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("decoded program");
        decoded
            .validate_materialized_structure(&[3])
            .expect("decoded materialized program");
        assert_eq!(decoded.encode().expect("round trip"), bytes);

        let mut use_before_definition = artifact.clone();
        use_before_definition.streams[0].instructions[0].input_registers[0] = 99;
        assert_eq!(
            use_before_definition.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::UnresolvedReference)
        );
        let mut nonconsecutive_register = artifact.clone();
        nonconsecutive_register.streams[0].instructions[0].output_register = Some(2);
        assert_eq!(
            nonconsecutive_register.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::InvalidOrdering)
        );
        let mut wrong_terminal_level = artifact.clone();
        wrong_terminal_level.streams[0].instructions[0].immediate0 =
            (CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1) as u64;
        assert_eq!(
            wrong_terminal_level.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut unknown_constant = artifact;
        unknown_constant.streams[0].instructions[4].constant_hash = Some([0xff; 64]);
        assert_eq!(
            unknown_constant.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::UnresolvedReference)
        );

        let mut use_after_drop = materialized_program();
        use_after_drop.streams[0].instructions[2].input_registers[0] = 0;
        assert_eq!(
            use_after_drop.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut missing_drop = materialized_program();
        missing_drop.streams[0].instructions.remove(1);
        assert_eq!(
            missing_drop.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut unsupported_galois_element = materialized_program();
        unsupported_galois_element.streams[0].instructions[2].opcode =
            EvaluatorOpcode::GaloisRotate;
        unsupported_galois_element.streams[0].instructions[2].immediate0 = 5;
        assert_eq!(
            unsupported_galois_element.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::UnresolvedReference)
        );
        let mut duplicate_output_role = materialized_program();
        duplicate_output_role.streams[0]
            .instructions
            .last_mut()
            .expect("order output declaration")
            .immediate0 = 1;
        assert_eq!(
            duplicate_output_role.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::DuplicateValue)
        );
        let mut wrong_output_order = materialized_program();
        let instruction_count = wrong_output_order.streams[0].instructions.len();
        wrong_output_order.streams[0]
            .instructions
            .swap(instruction_count - 2, instruction_count - 1);
        assert_eq!(
            wrong_output_order.validate_materialized_structure(&[3]),
            Err(DeterministicArtifactError::InvalidOrdering)
        );
    }

    #[test]
    fn evaluator_instruction_fields_and_constant_catalog_are_closed() {
        let artifact = materialized_program();
        let mut nonzero_reserved_immediate = artifact.clone();
        nonzero_reserved_immediate.streams[0].instructions[2].immediate1 = 1;
        assert_eq!(
            nonzero_reserved_immediate.validate_catalog_shape(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut constant_on_ciphertext_opcode = artifact.clone();
        constant_on_ciphertext_opcode.streams[0].instructions[2].constant_hash = Some([1; 64]);
        assert_eq!(
            constant_on_ciphertext_opcode.validate_catalog_shape(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut duplicate_constant = artifact;
        duplicate_constant
            .constants
            .push(duplicate_constant.constants[0].clone());
        assert_eq!(
            duplicate_constant.validate_catalog_shape(),
            Err(DeterministicArtifactError::InvalidOrdering)
        );
    }

    #[test]
    fn target_profile_round_trips_and_rejects_wrong_width_or_high_bits() {
        let artifact = TargetDecryptionProfileArtifact::from_operative_parameters()
            .expect("operative target profile");
        let bytes = artifact.encode().expect("target profile bytes");
        assert_eq!(
            TargetDecryptionProfileArtifact::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("decoded target profile"),
            artifact
        );

        let mut zero = artifact.clone();
        zero.flooding_coefficient_bound_words_little_endian.fill(0);
        assert_eq!(
            zero.validate(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut wrong_width = artifact.clone();
        wrong_width
            .flooding_coefficient_bound_words_little_endian
            .pop();
        assert_eq!(
            wrong_width.validate(),
            Err(DeterministicArtifactError::InvalidValue)
        );
        let mut high_bits = artifact;
        *high_bits
            .flooding_coefficient_bound_words_little_endian
            .last_mut()
            .expect("high word") = u64::MAX;
        assert_eq!(
            high_bits.validate(),
            Err(DeterministicArtifactError::InvalidValue)
        );
    }

    #[test]
    fn suite_artifact_set_reports_every_independent_semantic_blocker() {
        let proof_profile = proof_profile();
        let artifacts = DeterministicSuiteArtifactSet::from_operative_parameters()
            .expect("typed deterministic artifacts");
        artifacts
            .validate_available_structure(&proof_profile, &[3])
            .expect("available structural checks");
        assert_eq!(
            artifacts
                .semantic_blockers(&proof_profile)
                .expect("semantic blocker inventory"),
            vec![
                SuiteArtifactSemanticBlocker::ProofRelationProgramsNotLowered,
                SuiteArtifactSemanticBlocker::PersistentMaterialMaskImageEvidenceMissing,
                SuiteArtifactSemanticBlocker::LatticeCommitmentConcreteSecurityEvidenceMissing,
                SuiteArtifactSemanticBlocker::EvaluatorProgramNotMaterialized,
                SuiteArtifactSemanticBlocker::EvaluatorCorrectnessAndErrorEvidenceMissing,
                SuiteArtifactSemanticBlocker::TargetDecryptionTheoremEvidenceMissing,
            ]
        );
    }
}
