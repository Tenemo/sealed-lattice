use std::collections::{BTreeSet, HashSet};

use super::super::schemas::{
    SchemaResult, optional_u16, optional_u32, optional_u64, read_ascii, read_item,
    read_list_header, read_nested_tuple, read_nested_tuple_list, read_optional_u16,
    read_optional_u32, read_optional_u64, read_u16, read_u32, read_u64, read_variable_item,
    require_header,
};
use super::super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, ProofFamily,
    ProofFieldProfile, ProofFieldSchedule, ProofPrivateCoinClassification, ProofProfileSet,
    RefusalReason, SuiteRecord,
};
use super::{
    BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER, PROOF_CREATED_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_ADDITION_SCHEMA_IDENTIFIER,
    RELATION_APPLICATION_SLOT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER,
    RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
    RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER, RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER,
    RELATION_CONSTRAINT_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER,
    RELATION_FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER, RELATION_MASK_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER, RELATION_NEGATION_SCHEMA_IDENTIFIER,
    RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER,
    RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_OPENING_POINT_DESCRIPTOR_SCHEMA_IDENTIFIER, RELATION_PLAN_MAXIMUM_BYTE_LENGTH,
    RELATION_PLAN_SCHEMA_IDENTIFIER, RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER,
    RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
    RELATION_PUBLIC_SAMPLER_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER,
    RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER,
    RELATION_SAMPLER_OUTPUT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER, RELATION_SCHEMA_VERSION,
    RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
    RELATION_SUITE_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RELATION_TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER,
    RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER,
    RELATION_VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
    SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER, modular_power, schema_error,
};

const EVALUATOR_KEY_AGGREGATE_VARIANT_COUNT: usize = 20;
const RESERVED_MASK_PURPOSE_START: u16 = 0xff00;
const PROOF_LEAF_SALT_MASK_PURPOSE: u16 = 0xfffe;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum ProofPrivacyMode {
    PublicOnlyDeterministic = 1,
    SecretBearingMasked = 2,
}

impl ProofPrivacyMode {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            1 => Ok(Self::PublicOnlyDeterministic),
            2 => Ok(Self::SecretBearingMasked),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation proof-privacy mode is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }

    fn for_family(proof_family: ProofFamily) -> Self {
        match proof_family.private_coin_classification() {
            ProofPrivateCoinClassification::PublicOnly => Self::PublicOnlyDeterministic,
            ProofPrivateCoinClassification::ResetSafeSecretBearing
            | ProofPrivateCoinClassification::OrdinarySecretBearing => Self::SecretBearingMasked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
enum SuiteModulusCatalog {
    Data = 1,
    Special = 2,
    Plaintext = 3,
    ProofField = 4,
    TargetBasis = 5,
}

impl SuiteModulusCatalog {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Special),
            3 => Ok(Self::Plaintext),
            4 => Ok(Self::ProofField),
            5 => Ok(Self::TargetBasis),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "suite modulus catalog is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SuiteModulusReference {
    catalog: SuiteModulusCatalog,
    modulus_index: u16,
}

impl SuiteModulusReference {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER, 2)?;
        let reference = Self {
            catalog: SuiteModulusCatalog::decode(read_u16(&tuple.items[0])?)?,
            modulus_index: read_u16(&tuple.items[1])?,
        };
        if matches!(
            reference.catalog,
            SuiteModulusCatalog::Plaintext | SuiteModulusCatalog::ProofField
        ) && reference.modulus_index != 0
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "scalar suite modulus catalogs require index zero",
            ));
        }
        Ok(reference)
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.catalog.canonical_code()),
                CanonicalItem::unsigned16(self.modulus_index),
            ],
        )
    }

    fn resolve(self, suite_record: &SuiteRecord, proof_field: &ProofFieldProfile) -> SchemaResult<u64> {
        match self.catalog {
            SuiteModulusCatalog::Data => suite_record
                .ordered_data_primes
                .get(usize::from(self.modulus_index))
                .copied(),
            SuiteModulusCatalog::Special => suite_record
                .ordered_special_primes
                .get(usize::from(self.modulus_index))
                .copied(),
            SuiteModulusCatalog::Plaintext => Some(suite_record.plaintext_modulus),
            SuiteModulusCatalog::ProofField => Some(proof_field.base_field_modulus),
            SuiteModulusCatalog::TargetBasis => suite_record
                .ordered_target_data_prime_indexes
                .get(usize::from(self.modulus_index))
                .and_then(|data_prime_index| {
                    suite_record
                        .ordered_data_primes
                        .get(usize::from(*data_prime_index))
                })
                .copied(),
        }
        .ok_or_else(|| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "suite modulus reference is outside its catalog",
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum RelationElementKind {
    Hash512 = 1,
    ProofBaseField = 2,
    ProofChallengeExtension = 3,
    SuiteResidue = 4,
}

impl RelationElementKind {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            1 => Ok(Self::Hash512),
            2 => Ok(Self::ProofBaseField),
            3 => Ok(Self::ProofChallengeExtension),
            4 => Ok(Self::SuiteResidue),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation value element kind is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum RelationEmbeddingKind {
    None = 0,
    Identity = 1,
    LeastNonnegative = 2,
    Centered = 3,
}

impl RelationEmbeddingKind {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Identity),
            2 => Ok(Self::LeastNonnegative),
            3 => Ok(Self::Centered),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation value embedding kind is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelationValueLayout {
    element_kind: RelationElementKind,
    residue_modulus: Option<SuiteModulusReference>,
    shape: Vec<u64>,
    embedding_kind: RelationEmbeddingKind,
    logical_element_count: u64,
}

impl RelationValueLayout {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(tuple, RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER, 4)?;
        let element_kind = RelationElementKind::decode(read_u16(&tuple.items[0])?)?;
        let residue_modulus = read_optional_nested_tuple(&tuple.items[1], limits)?
            .as_ref()
            .map(SuiteModulusReference::from_tuple)
            .transpose()?;
        let shape = read_u64_list(&tuple.items[2])?;
        let embedding_kind = RelationEmbeddingKind::decode(read_u16(&tuple.items[3])?)?;
        let logical_element_count = shape.iter().try_fold(1u64, |count, dimension| {
            if *dimension == 0 {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation value-layout dimensions must be positive",
                ));
            }
            count.checked_mul(*dimension).ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "relation value-layout element count overflows",
                )
            })
        })?;
        let layout = Self {
            element_kind,
            residue_modulus,
            shape,
            embedding_kind,
            logical_element_count,
        };
        layout.validate_intrinsic()?;
        Ok(layout)
    }

    fn validate_intrinsic(&self) -> SchemaResult<()> {
        let valid = match self.element_kind {
            RelationElementKind::Hash512 => {
                self.residue_modulus.is_none()
                    && self.shape.is_empty()
                    && self.embedding_kind == RelationEmbeddingKind::None
            }
            RelationElementKind::ProofBaseField
            | RelationElementKind::ProofChallengeExtension => {
                self.residue_modulus.is_none()
                    && self.embedding_kind == RelationEmbeddingKind::Identity
            }
            RelationElementKind::SuiteResidue => {
                self.residue_modulus.is_some_and(|reference| {
                    reference.catalog != SuiteModulusCatalog::ProofField
                }) && matches!(
                    self.embedding_kind,
                    RelationEmbeddingKind::LeastNonnegative | RelationEmbeddingKind::Centered
                )
            }
        };
        if !valid {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation value layout has an invalid type, modulus, shape, or embedding combination",
            ));
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        let modulus_tuple = self.residue_modulus.map(|reference| reference.canonical_tuple());
        Ok(CanonicalTuple::new(
            RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.element_kind.canonical_code()),
                encode_optional_nested_tuple(modulus_tuple.as_ref())?,
                encode_u64_list(&self.shape)?,
                CanonicalItem::unsigned16(self.embedding_kind.canonical_code()),
            ],
        ))
    }

    fn validate_for_suite(
        &self,
        suite_record: &SuiteRecord,
        proof_field: &ProofFieldProfile,
    ) -> SchemaResult<()> {
        if let Some(reference) = self.residue_modulus {
            let modulus = reference.resolve(suite_record, proof_field)?;
            if modulus >= proof_field.base_field_modulus {
                return Err(schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "relation residue modulus must be smaller than the proof base field",
                ));
            }
        }
        Ok(())
    }

    fn is_scalar_hash(&self) -> bool {
        self.element_kind == RelationElementKind::Hash512 && self.shape.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum SelectorStepKind {
    TupleField = 1,
    LiteralListIndex = 2,
    VariantSchedulePosition = 3,
    ApplicationRosterPosition = 4,
    ApplicationSchedulePosition = 5,
    ApplicationProducerSequence = 6,
    StreamLogicalElement = 7,
    SuiteArtifact = 8,
}

impl SelectorStepKind {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            1 => Ok(Self::TupleField),
            2 => Ok(Self::LiteralListIndex),
            3 => Ok(Self::VariantSchedulePosition),
            4 => Ok(Self::ApplicationRosterPosition),
            5 => Ok(Self::ApplicationSchedulePosition),
            6 => Ok(Self::ApplicationProducerSequence),
            7 => Ok(Self::StreamLogicalElement),
            8 => Ok(Self::SuiteArtifact),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation selector step kind is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelationSelectorPathStep {
    step_kind: SelectorStepKind,
    argument: u64,
}

impl RelationSelectorPathStep {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER, 2)?;
        let step = Self {
            step_kind: SelectorStepKind::decode(read_u16(&tuple.items[0])?)?,
            argument: read_u64(&tuple.items[1])?,
        };
        if matches!(
            step.step_kind,
            SelectorStepKind::VariantSchedulePosition
                | SelectorStepKind::ApplicationRosterPosition
                | SelectorStepKind::ApplicationSchedulePosition
                | SelectorStepKind::ApplicationProducerSequence
        ) && step.argument != 0
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "dynamic relation selector steps require a zero argument",
            ));
        }
        if step.step_kind == SelectorStepKind::SuiteArtifact && !(1..=6).contains(&step.argument) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation suite-artifact selector names an unassigned artifact kind",
            ));
        }
        Ok(step)
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.step_kind.canonical_code()),
                CanonicalItem::unsigned64(self.argument),
            ],
        )
    }
}

fn decode_selector_path(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<RelationSelectorPathStep>> {
    let path = read_nested_tuple_list(item, limits)?
        .iter()
        .map(RelationSelectorPathStep::from_tuple)
        .collect::<SchemaResult<Vec<_>>>()?;
    if path.is_empty() {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "relation selector path must be nonempty",
        ));
    }
    Ok(path)
}

fn encode_selector_path(path: &[RelationSelectorPathStep]) -> SchemaResult<CanonicalItem> {
    encode_nested_tuple_list(path.iter().copied().map(RelationSelectorPathStep::canonical_tuple))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum ProtocolSourceKind {
    EvaluatorSetupComponent = 1,
    BallotCiphertextComponent = 2,
    FinalizedTargetCiphertextComponent = 3,
    TargetReleasePartialDecryption = 4,
    CommitmentMatrixEntry = 5,
    CollectivePublicKeyCommonPolynomial = 6,
    RelinearizationCommonPolynomial = 7,
    GaloisCommonPolynomial = 8,
    PublicSetupSeed = 9,
}

impl ProtocolSourceKind {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            1 => Ok(Self::EvaluatorSetupComponent),
            2 => Ok(Self::BallotCiphertextComponent),
            3 => Ok(Self::FinalizedTargetCiphertextComponent),
            4 => Ok(Self::TargetReleasePartialDecryption),
            5 => Ok(Self::CommitmentMatrixEntry),
            6 => Ok(Self::CollectivePublicKeyCommonPolynomial),
            7 => Ok(Self::RelinearizationCommonPolynomial),
            8 => Ok(Self::GaloisCommonPolynomial),
            9 => Ok(Self::PublicSetupSeed),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation protocol-source kind is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }

    const fn coordinate_count(self) -> usize {
        match self {
            Self::EvaluatorSetupComponent | Self::BallotCiphertextComponent => 2,
            Self::FinalizedTargetCiphertextComponent => 3,
            Self::TargetReleasePartialDecryption => 2,
            Self::CommitmentMatrixEntry => 4,
            Self::CollectivePublicKeyCommonPolynomial => 1,
            Self::RelinearizationCommonPolynomial | Self::GaloisCommonPolynomial => 4,
            Self::PublicSetupSeed => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationVerifierSource {
    ApplicationStatement {
        value_path: Vec<RelationSelectorPathStep>,
        value_layout: RelationValueLayout,
    },
    Protocol {
        protocol_source_kind: ProtocolSourceKind,
        source_coordinates: Vec<u64>,
        statement_binding_path: Vec<RelationSelectorPathStep>,
        value_layout: RelationValueLayout,
    },
    Suite {
        value_path: Vec<RelationSelectorPathStep>,
        value_layout: RelationValueLayout,
    },
    ApplicationSlot {
        value_path: Vec<RelationSelectorPathStep>,
        value_layout: RelationValueLayout,
    },
    SamplerOutput {
        public_sampler_ordinal: u32,
    },
}

impl RelationVerifierSource {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        match tuple.schema_identifier {
            RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(
                    tuple,
                    RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                    2,
                )?;
                let source = Self::ApplicationStatement {
                    value_path: decode_selector_path(&tuple.items[0], limits)?,
                    value_layout: RelationValueLayout::from_tuple(
                        &read_nested_tuple(&tuple.items[1], limits)?,
                        limits,
                    )?,
                };
                source.validate_path_grammar()?;
                Ok(source)
            }
            RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER, 4)?;
                let source = Self::Protocol {
                    protocol_source_kind: ProtocolSourceKind::decode(read_u16(&tuple.items[0])?)?,
                    source_coordinates: read_u64_list(&tuple.items[1])?,
                    statement_binding_path: decode_selector_path(&tuple.items[2], limits)?,
                    value_layout: RelationValueLayout::from_tuple(
                        &read_nested_tuple(&tuple.items[3], limits)?,
                        limits,
                    )?,
                };
                source.validate_path_grammar()?;
                Ok(source)
            }
            RELATION_SUITE_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_SUITE_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER, 2)?;
                let source = Self::Suite {
                    value_path: decode_selector_path(&tuple.items[0], limits)?,
                    value_layout: RelationValueLayout::from_tuple(
                        &read_nested_tuple(&tuple.items[1], limits)?,
                        limits,
                    )?,
                };
                source.validate_path_grammar()?;
                Ok(source)
            }
            RELATION_APPLICATION_SLOT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(
                    tuple,
                    RELATION_APPLICATION_SLOT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                    2,
                )?;
                let source = Self::ApplicationSlot {
                    value_path: decode_selector_path(&tuple.items[0], limits)?,
                    value_layout: RelationValueLayout::from_tuple(
                        &read_nested_tuple(&tuple.items[1], limits)?,
                        limits,
                    )?,
                };
                source.validate_path_grammar()?;
                Ok(source)
            }
            RELATION_SAMPLER_OUTPUT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(
                    tuple,
                    RELATION_SAMPLER_OUTPUT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                    1,
                )?;
                Ok(Self::SamplerOutput {
                    public_sampler_ordinal: read_u32(&tuple.items[0])?,
                })
            }
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation verifier source uses an unassigned nested schema",
            )),
        }
    }

    fn validate_path_grammar(&self) -> SchemaResult<()> {
        let path = match self {
            Self::ApplicationStatement { value_path, .. }
            | Self::Suite { value_path, .. }
            | Self::ApplicationSlot { value_path, .. } => value_path,
            Self::Protocol {
                statement_binding_path,
                ..
            } => statement_binding_path,
            Self::SamplerOutput { .. } => return Ok(()),
        };
        if path.first().is_none_or(|step| step.step_kind != SelectorStepKind::TupleField) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation selector path must begin with a canonical tuple field",
            ));
        }
        for step in path {
            let allowed = match self {
                Self::ApplicationStatement { .. } => {
                    step.step_kind != SelectorStepKind::SuiteArtifact
                }
                Self::Protocol { .. } => step.step_kind == SelectorStepKind::TupleField,
                Self::Suite { .. } => matches!(
                    step.step_kind,
                    SelectorStepKind::TupleField
                        | SelectorStepKind::LiteralListIndex
                        | SelectorStepKind::SuiteArtifact
                ),
                Self::ApplicationSlot { .. } => {
                    matches!(step.step_kind, SelectorStepKind::TupleField)
                }
                Self::SamplerOutput { .. } => true,
            };
            if !allowed {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation selector step is not legal for its source root",
                ));
            }
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        match self {
            Self::ApplicationStatement {
                value_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    encode_selector_path(value_path)?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)?,
                ],
            )),
            Self::Protocol {
                protocol_source_kind,
                source_coordinates,
                statement_binding_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(protocol_source_kind.canonical_code()),
                    encode_u64_list(source_coordinates)?,
                    encode_selector_path(statement_binding_path)?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)?,
                ],
            )),
            Self::Suite {
                value_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                RELATION_SUITE_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    encode_selector_path(value_path)?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)?,
                ],
            )),
            Self::ApplicationSlot {
                value_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                RELATION_APPLICATION_SLOT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    encode_selector_path(value_path)?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)?,
                ],
            )),
            Self::SamplerOutput {
                public_sampler_ordinal,
            } => Ok(CanonicalTuple::new(
                RELATION_SAMPLER_OUTPUT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*public_sampler_ordinal)],
            )),
        }
    }

    fn value_layout(&self) -> Option<&RelationValueLayout> {
        match self {
            Self::ApplicationStatement { value_layout, .. }
            | Self::Protocol { value_layout, .. }
            | Self::Suite { value_layout, .. }
            | Self::ApplicationSlot { value_layout, .. } => Some(value_layout),
            Self::SamplerOutput { .. } => None,
        }
    }

    fn validate_for_family(
        &self,
        proof_family: ProofFamily,
        suite_record: &SuiteRecord,
        proof_field: &ProofFieldProfile,
    ) -> SchemaResult<()> {
        if let Some(layout) = self.value_layout() {
            layout.validate_for_suite(suite_record, proof_field)?;
        }
        let Self::Protocol {
            protocol_source_kind,
            source_coordinates,
            statement_binding_path,
            value_layout,
        } = self
        else {
            return Ok(());
        };
        if source_coordinates.len() != protocol_source_kind.coordinate_count() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation protocol source has the wrong coordinate arity",
            ));
        }
        let expected_field_index = expected_protocol_binding_field(
            *protocol_source_kind,
            proof_family,
            source_coordinates,
        )?;
        if statement_binding_path
            != &[RelationSelectorPathStep {
                step_kind: SelectorStepKind::TupleField,
                argument: expected_field_index,
            }]
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation protocol source has the wrong statement binding path",
            ));
        }
        validate_protocol_source_layout(
            *protocol_source_kind,
            source_coordinates,
            value_layout,
            suite_record,
        )
    }
}

fn expected_protocol_binding_field(
    source_kind: ProtocolSourceKind,
    proof_family: ProofFamily,
    source_coordinates: &[u64],
) -> SchemaResult<u64> {
    let statement = proof_family.statement_schema_identifier();
    let expected = match source_kind {
        ProtocolSourceKind::EvaluatorSetupComponent if statement == 0x1302 => 7,
        ProtocolSourceKind::BallotCiphertextComponent if statement == 0x1302 => 8,
        ProtocolSourceKind::FinalizedTargetCiphertextComponent if statement == 0x1621 => 6,
        ProtocolSourceKind::TargetReleasePartialDecryption if statement == 0x1621 => {
            let target_role = source_coordinates.first().copied().ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "target release source omits its role coordinate",
                )
            })?;
            if target_role > 1 {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "target release source role is unassigned",
                ));
            }
            13 + target_role
        }
        ProtocolSourceKind::CommitmentMatrixEntry
            if matches!(statement, 0x1211 | 0x1212 | 0x1214 | 0x1216 | 0x1217) =>
        {
            0
        }
        ProtocolSourceKind::CollectivePublicKeyCommonPolynomial if statement == 0x1212 => 0,
        ProtocolSourceKind::RelinearizationCommonPolynomial
            if matches!(statement, 0x1214 | 0x1215 | 0x1216) =>
        {
            0
        }
        ProtocolSourceKind::GaloisCommonPolynomial if statement == 0x1217 => 0,
        ProtocolSourceKind::PublicSetupSeed if statement == 0x2111 => 7,
        ProtocolSourceKind::PublicSetupSeed if (0x1211..=0x1218).contains(&statement) => 0,
        ProtocolSourceKind::PublicSetupSeed if statement == 0x1302 => 7,
        ProtocolSourceKind::PublicSetupSeed if statement == 0x1621 => 5,
        _ => {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation protocol-source kind is not assigned to this proof family",
            ));
        }
    };
    Ok(expected)
}

fn validate_protocol_source_layout(
    source_kind: ProtocolSourceKind,
    coordinates: &[u64],
    layout: &RelationValueLayout,
    suite_record: &SuiteRecord,
) -> SchemaResult<()> {
    if source_kind == ProtocolSourceKind::PublicSetupSeed {
        if !layout.is_scalar_hash() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "public setup seed source requires a scalar hash layout",
            ));
        }
        return Ok(());
    }
    if layout.element_kind != RelationElementKind::SuiteResidue
        || layout.embedding_kind != RelationEmbeddingKind::LeastNonnegative
        || layout.shape != [u64::from(suite_record.polynomial_degree)]
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "polynomial protocol source requires the suite residue polynomial layout",
        ));
    }
    if matches!(
        source_kind,
        ProtocolSourceKind::EvaluatorSetupComponent
            | ProtocolSourceKind::BallotCiphertextComponent
            | ProtocolSourceKind::FinalizedTargetCiphertextComponent
    ) && coordinates.first().is_some_and(|coordinate| *coordinate > 1)
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "relation ciphertext component ordinal is unassigned",
        ));
    }
    let expected_modulus = match source_kind {
        ProtocolSourceKind::EvaluatorSetupComponent | ProtocolSourceKind::BallotCiphertextComponent => {
            SuiteModulusReference {
                catalog: SuiteModulusCatalog::Data,
                modulus_index: coordinate_as_u16(coordinates[1])?,
            }
        }
        ProtocolSourceKind::FinalizedTargetCiphertextComponent => {
            if coordinates[0] > 1 || coordinates[1] > 1 {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "target ciphertext source has an unassigned role or component",
                ));
            }
            SuiteModulusReference {
                catalog: SuiteModulusCatalog::TargetBasis,
                modulus_index: coordinate_as_u16(coordinates[2])?,
            }
        }
        ProtocolSourceKind::TargetReleasePartialDecryption => SuiteModulusReference {
            catalog: SuiteModulusCatalog::TargetBasis,
            modulus_index: coordinate_as_u16(coordinates[1])?,
        },
        ProtocolSourceKind::CommitmentMatrixEntry
        | ProtocolSourceKind::CollectivePublicKeyCommonPolynomial => SuiteModulusReference {
            catalog: SuiteModulusCatalog::Data,
            modulus_index: coordinate_as_u16(coordinates[0])?,
        },
        ProtocolSourceKind::RelinearizationCommonPolynomial
        | ProtocolSourceKind::GaloisCommonPolynomial => {
            let catalog = SuiteModulusCatalog::decode(coordinate_as_u16(coordinates[2])?)?;
            if !matches!(catalog, SuiteModulusCatalog::Data | SuiteModulusCatalog::Special) {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "evaluation-key source modulus catalog must be data or special",
                ));
            }
            SuiteModulusReference {
                catalog,
                modulus_index: coordinate_as_u16(coordinates[3])?,
            }
        }
        ProtocolSourceKind::PublicSetupSeed => unreachable!("handled above"),
    };
    if layout.residue_modulus != Some(expected_modulus) {
        return Err(schema_error(
            RefusalReason::WrongContext,
            "relation protocol source layout names the wrong suite modulus",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelationPublicSamplerDescriptor {
    seed_verifier_source_ordinal: u32,
    role_domain: String,
    canonical_role_coordinate_bytes: Vec<u8>,
    output_modulus: SuiteModulusReference,
    output_count: u64,
    output_verifier_source_ordinal: u32,
}

impl RelationPublicSamplerDescriptor {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(
            tuple,
            RELATION_PUBLIC_SAMPLER_DESCRIPTOR_SCHEMA_IDENTIFIER,
            6,
        )?;
        let role_domain = read_ascii(&tuple.items[1])?.to_owned();
        if role_domain.is_empty() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation public-sampler role domain must be nonempty",
            ));
        }
        let canonical_role_coordinate_bytes = read_variable_item(
            &tuple.items[2],
            CanonicalItemType::RawBytes,
        )?
        .to_vec();
        if canonical_role_coordinate_bytes.is_empty()
            || CanonicalTuple::decode(&canonical_role_coordinate_bytes, limits).is_err()
        {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "relation public-sampler coordinates must be one complete canonical tuple",
            ));
        }
        let descriptor = Self {
            seed_verifier_source_ordinal: read_u32(&tuple.items[0])?,
            role_domain,
            canonical_role_coordinate_bytes,
            output_modulus: SuiteModulusReference::from_tuple(&read_nested_tuple(
                &tuple.items[3],
                limits,
            )?)?,
            output_count: read_u64(&tuple.items[4])?,
            output_verifier_source_ordinal: read_u32(&tuple.items[5])?,
        };
        if descriptor.output_count == 0
            || descriptor.output_modulus.catalog == SuiteModulusCatalog::ProofField
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation public sampler requires a positive non-proof-field output",
            ));
        }
        Ok(descriptor)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_PUBLIC_SAMPLER_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.seed_verifier_source_ordinal),
                CanonicalItem::nonempty_ascii(&self.role_domain)?,
                CanonicalItem::variable_bytes(&self.canonical_role_coordinate_bytes)?,
                CanonicalItem::nested_tuple(&self.output_modulus.canonical_tuple())?,
                CanonicalItem::unsigned64(self.output_count),
                CanonicalItem::unsigned32(self.output_verifier_source_ordinal),
            ],
        ))
    }

    fn validate_role_domain(&self, proof_family: ProofFamily) -> SchemaResult<()> {
        let expected_prefix = format!(
            "sealed-lattice/proof/{:04x}/public-sampler/",
            proof_family.statement_schema_identifier()
        );
        let Some(role) = self
            .role_domain
            .strip_prefix(&expected_prefix)
            .and_then(|remaining| remaining.strip_suffix("/v1"))
        else {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation public-sampler role domain does not match its proof family",
            ));
        };
        if role.is_empty()
            || role
                .bytes()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation public-sampler role is not canonical lowercase ASCII",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum RelationColumnValueType {
    BaseField = 1,
    ChallengeExtension = 2,
}

impl RelationColumnValueType {
    fn decode(value: u16) -> SchemaResult<Self> {
        match value {
            1 => Ok(Self::BaseField),
            2 => Ok(Self::ChallengeExtension),
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation column value type is unassigned",
            )),
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationColumnOrigin {
    VerifierSequence {
        verifier_source_ordinal: u32,
        first_logical_element_index: u64,
        logical_element_stride: u64,
    },
    BoundTree {
        expected_root_source_ordinal: u32,
    },
    Prover,
}

impl RelationColumnOrigin {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        match tuple.schema_identifier {
            RELATION_VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER => {
                require_header(
                    tuple,
                    RELATION_VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                    3,
                )?;
                Ok(Self::VerifierSequence {
                    verifier_source_ordinal: read_u32(&tuple.items[0])?,
                    first_logical_element_index: read_u64(&tuple.items[1])?,
                    logical_element_stride: read_u64(&tuple.items[2])?,
                })
            }
            RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER => {
                require_header(
                    tuple,
                    RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                    1,
                )?;
                Ok(Self::BoundTree {
                    expected_root_source_ordinal: read_u32(&tuple.items[0])?,
                })
            }
            RELATION_PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Prover)
            }
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation column origin uses an unassigned nested schema",
            )),
        }
    }

    fn canonical_tuple(&self) -> CanonicalTuple {
        match self {
            Self::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } => CanonicalTuple::new(
                RELATION_VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*verifier_source_ordinal),
                    CanonicalItem::unsigned64(*first_logical_element_index),
                    CanonicalItem::unsigned64(*logical_element_stride),
                ],
            ),
            Self::BoundTree {
                expected_root_source_ordinal,
            } => CanonicalTuple::new(
                RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*expected_root_source_ordinal)],
            ),
            Self::Prover => CanonicalTuple::new(
                RELATION_PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                Vec::new(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelationColumnDescriptor {
    origin: RelationColumnOrigin,
    value_type: RelationColumnValueType,
    source_degree_bound_exclusive: u64,
}

impl RelationColumnDescriptor {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(tuple, RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER, 3)?;
        let descriptor = Self {
            origin: RelationColumnOrigin::from_tuple(&read_nested_tuple(
                &tuple.items[0],
                limits,
            )?)?,
            value_type: RelationColumnValueType::decode(read_u16(&tuple.items[1])?)?,
            source_degree_bound_exclusive: read_u64(&tuple.items[2])?,
        };
        if descriptor.source_degree_bound_exclusive == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation column degree bound must be positive",
            ));
        }
        Ok(descriptor)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.origin.canonical_tuple())?,
                CanonicalItem::unsigned16(self.value_type.canonical_code()),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
            ],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationTreeDescriptor {
    ProofCreated {
        proof_tree_role: u16,
        ordered_column_ordinals: Vec<u32>,
    },
    BoundPublic {
        construction_kind: u16,
        expected_root_source_ordinal: u32,
        root_use: u16,
        ordered_column_ordinals: Vec<u32>,
    },
}

impl RelationTreeDescriptor {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        match tuple.schema_identifier {
            PROOF_CREATED_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(tuple, PROOF_CREATED_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER, 2)?;
                let proof_tree_role = read_u16(&tuple.items[0])?;
                let ordered_column_ordinals = read_u32_list(&tuple.items[1])?;
                if !matches!(proof_tree_role, 1 | 2) || ordered_column_ordinals.is_empty() {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "proof-created tree requires role one or two and at least one column",
                    ));
                }
                Ok(Self::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                })
            }
            BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER => {
                require_header(tuple, BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER, 4)?;
                let construction_kind = read_u16(&tuple.items[0])?;
                let root_use = read_u16(&tuple.items[2])?;
                let ordered_column_ordinals = read_u32_list(&tuple.items[3])?;
                if !matches!(construction_kind, 1 | 2)
                    || !matches!(root_use, 1 | 2)
                    || ordered_column_ordinals.is_empty()
                {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "bound public tree has an invalid construction, root use, or column list",
                    ));
                }
                Ok(Self::BoundPublic {
                    construction_kind,
                    expected_root_source_ordinal: read_u32(&tuple.items[1])?,
                    root_use,
                    ordered_column_ordinals,
                })
            }
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation tree uses an unassigned nested schema",
            )),
        }
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        match self {
            Self::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => Ok(CanonicalTuple::new(
                PROOF_CREATED_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*proof_tree_role),
                    encode_u32_list(ordered_column_ordinals)?,
                ],
            )),
            Self::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                root_use,
                ordered_column_ordinals,
            } => Ok(CanonicalTuple::new(
                BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*construction_kind),
                    CanonicalItem::unsigned32(*expected_root_source_ordinal),
                    CanonicalItem::unsigned16(*root_use),
                    encode_u32_list(ordered_column_ordinals)?,
                ],
            )),
        }
    }

    fn ordered_column_ordinals(&self) -> &[u32] {
        match self {
            Self::ProofCreated {
                ordered_column_ordinals,
                ..
            }
            | Self::BoundPublic {
                ordered_column_ordinals,
                ..
            } => ordered_column_ordinals,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationExpressionInstruction {
    BaseFieldConstant(Vec<u8>),
    EvaluationVariable,
    ColumnValue {
        column_ordinal: u32,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
    },
    TranscriptChallenge {
        challenge_role: u16,
        role_coordinates: Vec<u64>,
    },
    Addition,
    Multiplication,
    Negation,
    NonnegativePower(u64),
    FrobeniusConjugate(u16),
}

impl RelationExpressionInstruction {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        match tuple.schema_identifier {
            RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::BaseFieldConstant(
                    read_item(&tuple.items[0], CanonicalItemType::FieldElement)?.to_vec(),
                ))
            }
            RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::EvaluationVariable)
            }
            RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER, 3)?;
                let sign = read_u8(&tuple.items[1])?;
                let rotation_magnitude = read_u64(&tuple.items[2])?;
                if sign > 1 || (sign == 1 && rotation_magnitude == 0) {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation column rotation sign is noncanonical",
                    ));
                }
                Ok(Self::ColumnValue {
                    column_ordinal: read_u32(&tuple.items[0])?,
                    rotation_is_negative: sign == 1,
                    rotation_magnitude,
                })
            }
            RELATION_TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER, 2)?;
                let challenge_role = read_u16(&tuple.items[0])?;
                let role_coordinates = read_u64_list(&tuple.items[1])?;
                let expected_coordinate_count = match challenge_role {
                    1 => 2,
                    2 => 3,
                    _ => {
                        return Err(schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation transcript challenge role is unassigned",
                        ));
                    }
                };
                if role_coordinates.len() != expected_coordinate_count {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation transcript challenge has the wrong coordinate arity",
                    ));
                }
                Ok(Self::TranscriptChallenge {
                    challenge_role,
                    role_coordinates,
                })
            }
            RELATION_ADDITION_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_ADDITION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Addition)
            }
            RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Multiplication)
            }
            RELATION_NEGATION_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_NEGATION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Negation)
            }
            RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::NonnegativePower(read_u64(&tuple.items[0])?))
            }
            RELATION_FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER => {
                require_header(tuple, RELATION_FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::FrobeniusConjugate(read_u16(&tuple.items[0])?))
            }
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation expression contains an unassigned instruction schema",
            )),
        }
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        let tuple = match self {
            Self::BaseFieldConstant(bytes) => CanonicalTuple::new(
                RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::from_canonical_bytes(
                    CanonicalItemType::FieldElement,
                    bytes.clone(),
                    &CanonicalDecodeLimits::default(),
                )?],
            ),
            Self::EvaluationVariable => CanonicalTuple::new(
                RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                Vec::new(),
            ),
            Self::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => CanonicalTuple::new(
                RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*column_ordinal),
                    CanonicalItem::unsigned8(u8::from(*rotation_is_negative)),
                    CanonicalItem::unsigned64(*rotation_magnitude),
                ],
            ),
            Self::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => CanonicalTuple::new(
                RELATION_TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*challenge_role),
                    encode_u64_list(role_coordinates)?,
                ],
            ),
            Self::Addition => empty_tuple(RELATION_ADDITION_SCHEMA_IDENTIFIER),
            Self::Multiplication => empty_tuple(RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER),
            Self::Negation => empty_tuple(RELATION_NEGATION_SCHEMA_IDENTIFIER),
            Self::NonnegativePower(exponent) => CanonicalTuple::new(
                RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::unsigned64(*exponent)],
            ),
            Self::FrobeniusConjugate(conjugate_index) => CanonicalTuple::new(
                RELATION_FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::unsigned16(*conjugate_index)],
            ),
        };
        Ok(tuple)
    }
}

fn decode_expression(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<RelationExpressionInstruction>> {
    let expression = read_nested_tuple_list(item, limits)?
        .iter()
        .map(RelationExpressionInstruction::from_tuple)
        .collect::<SchemaResult<Vec<_>>>()?;
    if expression.is_empty() {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "relation expression must be nonempty",
        ));
    }
    Ok(expression)
}

fn encode_expression(expression: &[RelationExpressionInstruction]) -> SchemaResult<CanonicalItem> {
    encode_nested_tuple_list(
        expression
            .iter()
            .map(RelationExpressionInstruction::canonical_tuple)
            .collect::<SchemaResult<Vec<_>>>()?,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelationConstraintDescriptor {
    constraint_role: u16,
    role_coordinates: Vec<u64>,
    numerator_postfix_expression: Vec<RelationExpressionInstruction>,
    zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
}

impl RelationConstraintDescriptor {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(tuple, RELATION_CONSTRAINT_DESCRIPTOR_SCHEMA_IDENTIFIER, 4)?;
        let constraint_role = read_u16(&tuple.items[0])?;
        if constraint_role == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation constraint role must be assigned",
            ));
        }
        Ok(Self {
            constraint_role,
            role_coordinates: read_u64_list(&tuple.items[1])?,
            numerator_postfix_expression: decode_expression(&tuple.items[2], limits)?,
            zeroifier_postfix_expression: decode_expression(&tuple.items[3], limits)?,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_CONSTRAINT_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.constraint_role),
                encode_u64_list(&self.role_coordinates)?,
                encode_expression(&self.numerator_postfix_expression)?,
                encode_expression(&self.zeroifier_postfix_expression)?,
            ],
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RelationOpeningPointDescriptor {
    deep_point_ordinal: u16,
    trace_rotation_is_negative: bool,
    trace_rotation_magnitude: u64,
    conjugate_index: u16,
}

impl RelationOpeningPointDescriptor {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RELATION_OPENING_POINT_DESCRIPTOR_SCHEMA_IDENTIFIER, 4)?;
        let sign = read_u8(&tuple.items[1])?;
        let trace_rotation_magnitude = read_u64(&tuple.items[2])?;
        if sign > 1 || (sign == 1 && trace_rotation_magnitude == 0) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation opening-point rotation sign is noncanonical",
            ));
        }
        Ok(Self {
            deep_point_ordinal: read_u16(&tuple.items[0])?,
            trace_rotation_is_negative: sign == 1,
            trace_rotation_magnitude,
            conjugate_index: read_u16(&tuple.items[3])?,
        })
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_OPENING_POINT_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.deep_point_ordinal),
                CanonicalItem::unsigned8(u8::from(self.trace_rotation_is_negative)),
                CanonicalItem::unsigned64(self.trace_rotation_magnitude),
                CanonicalItem::unsigned16(self.conjugate_index),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RelationOpeningClaimDescriptor {
    source_class: u16,
    source_ordinal: u32,
    column_ordinal: Option<u32>,
    opening_point_ordinal: u32,
    source_degree_bound_exclusive: u64,
}

impl RelationOpeningClaimDescriptor {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER, 5)?;
        let claim = Self {
            source_class: read_u16(&tuple.items[0])?,
            source_ordinal: read_u32(&tuple.items[1])?,
            column_ordinal: read_optional_u32(&tuple.items[2])?,
            opening_point_ordinal: read_u32(&tuple.items[3])?,
            source_degree_bound_exclusive: read_u64(&tuple.items[4])?,
        };
        let valid_presence = match claim.source_class {
            1 => claim.column_ordinal.is_some(),
            2 | 3 => claim.column_ordinal.is_none(),
            _ => false,
        };
        if !valid_presence || claim.source_degree_bound_exclusive == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation opening claim has an invalid source class, column presence, or degree",
            ));
        }
        Ok(claim)
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.source_class),
                CanonicalItem::unsigned32(self.source_ordinal),
                optional_u32(self.column_ordinal)?,
                CanonicalItem::unsigned32(self.opening_point_ordinal),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
            ],
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelationMaskDescriptor {
    mask_purpose: u16,
    mask_kind: u16,
    target_class: u16,
    target_ordinal: u32,
    mask_degree_bound_exclusive: u64,
}

impl RelationMaskDescriptor {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RELATION_MASK_DESCRIPTOR_SCHEMA_IDENTIFIER, 5)?;
        let descriptor = Self {
            mask_purpose: read_u16(&tuple.items[0])?,
            mask_kind: read_u16(&tuple.items[1])?,
            target_class: read_u16(&tuple.items[2])?,
            target_ordinal: read_u32(&tuple.items[3])?,
            mask_degree_bound_exclusive: read_u64(&tuple.items[4])?,
        };
        if descriptor.mask_purpose >= RESERVED_MASK_PURPOSE_START
            || descriptor.mask_purpose == PROOF_LEAF_SALT_MASK_PURPOSE
            || !matches!(
                (descriptor.mask_kind, descriptor.target_class),
                (1, 1) | (2, 2) | (3, 3)
            )
            || descriptor.mask_degree_bound_exclusive == 0
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation mask descriptor has an invalid purpose, kind, target, or degree",
            ));
        }
        Ok(descriptor)
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_MASK_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.mask_purpose),
                CanonicalItem::unsigned16(self.mask_kind),
                CanonicalItem::unsigned16(self.target_class),
                CanonicalItem::unsigned32(self.target_ordinal),
                CanonicalItem::unsigned64(self.mask_degree_bound_exclusive),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelationPlanVariant {
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_privacy_mode: ProofPrivacyMode,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    ordered_non_native_moduli: Vec<SuiteModulusReference>,
    ordered_verifier_sources: Vec<RelationVerifierSource>,
    ordered_public_samplers: Vec<RelationPublicSamplerDescriptor>,
    ordered_columns: Vec<RelationColumnDescriptor>,
    ordered_trees: Vec<RelationTreeDescriptor>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
    ordered_opening_points: Vec<RelationOpeningPointDescriptor>,
    ordered_opening_claims: Vec<RelationOpeningClaimDescriptor>,
    ordered_masks: Vec<RelationMaskDescriptor>,
}

impl RelationPlanVariant {
    fn from_tuple(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        proof_family: ProofFamily,
    ) -> SchemaResult<Self> {
        require_header(tuple, RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER, 15)?;
        let variant = Self {
            schedule_position: read_optional_u32(&tuple.items[0])?,
            top_count: read_optional_u16(&tuple.items[1])?,
            proof_privacy_mode: ProofPrivacyMode::decode(read_u16(&tuple.items[2])?)?,
            trace_domain_size: read_u64(&tuple.items[3])?,
            evaluation_domain_size: read_u64(&tuple.items[4])?,
            opening_degree_bound_exclusive: read_u64(&tuple.items[5])?,
            ordered_non_native_moduli: read_nested_tuple_list(&tuple.items[6], limits)?
                .iter()
                .map(SuiteModulusReference::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_verifier_sources: read_nested_tuple_list(&tuple.items[7], limits)?
                .iter()
                .map(|source| RelationVerifierSource::from_tuple(source, limits))
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_public_samplers: read_nested_tuple_list(&tuple.items[8], limits)?
                .iter()
                .map(|sampler| RelationPublicSamplerDescriptor::from_tuple(sampler, limits))
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_columns: read_nested_tuple_list(&tuple.items[9], limits)?
                .iter()
                .map(|column| RelationColumnDescriptor::from_tuple(column, limits))
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_trees: read_nested_tuple_list(&tuple.items[10], limits)?
                .iter()
                .map(RelationTreeDescriptor::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_constraints: read_nested_tuple_list(&tuple.items[11], limits)?
                .iter()
                .map(|constraint| RelationConstraintDescriptor::from_tuple(constraint, limits))
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_opening_points: read_nested_tuple_list(&tuple.items[12], limits)?
                .iter()
                .map(RelationOpeningPointDescriptor::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_opening_claims: read_nested_tuple_list(&tuple.items[13], limits)?
                .iter()
                .map(RelationOpeningClaimDescriptor::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?,
            ordered_masks: read_nested_tuple_list(&tuple.items[14], limits)?
                .iter()
                .map(RelationMaskDescriptor::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?,
        };
        variant.validate_intrinsic(proof_family)?;
        Ok(variant)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                optional_u32(self.schedule_position)?,
                optional_u16(self.top_count)?,
                CanonicalItem::unsigned16(self.proof_privacy_mode.canonical_code()),
                CanonicalItem::unsigned64(self.trace_domain_size),
                CanonicalItem::unsigned64(self.evaluation_domain_size),
                CanonicalItem::unsigned64(self.opening_degree_bound_exclusive),
                encode_nested_tuple_list(
                    self.ordered_non_native_moduli
                        .iter()
                        .copied()
                        .map(SuiteModulusReference::canonical_tuple),
                )?,
                encode_nested_tuple_list(
                    self.ordered_verifier_sources
                        .iter()
                        .map(RelationVerifierSource::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                encode_nested_tuple_list(
                    self.ordered_public_samplers
                        .iter()
                        .map(RelationPublicSamplerDescriptor::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                encode_nested_tuple_list(
                    self.ordered_columns
                        .iter()
                        .map(RelationColumnDescriptor::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                encode_nested_tuple_list(
                    self.ordered_trees
                        .iter()
                        .map(RelationTreeDescriptor::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                encode_nested_tuple_list(
                    self.ordered_constraints
                        .iter()
                        .map(RelationConstraintDescriptor::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                encode_nested_tuple_list(
                    self.ordered_opening_points
                        .iter()
                        .copied()
                        .map(RelationOpeningPointDescriptor::canonical_tuple),
                )?,
                encode_nested_tuple_list(
                    self.ordered_opening_claims
                        .iter()
                        .copied()
                        .map(RelationOpeningClaimDescriptor::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                encode_nested_tuple_list(
                    self.ordered_masks
                        .iter()
                        .copied()
                        .map(RelationMaskDescriptor::canonical_tuple),
                )?,
            ],
        ))
    }

    fn validate_intrinsic(&self, proof_family: ProofFamily) -> SchemaResult<()> {
        if self.proof_privacy_mode != ProofPrivacyMode::for_family(proof_family) {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation proof-privacy mode does not match its proof family",
            ));
        }
        if self.trace_domain_size < 2
            || !self.trace_domain_size.is_power_of_two()
            || self.evaluation_domain_size < self.trace_domain_size
            || !self.evaluation_domain_size.is_power_of_two()
            || !self.evaluation_domain_size.is_multiple_of(self.trace_domain_size)
            || self.opening_degree_bound_exclusive <= 1
            || self.opening_degree_bound_exclusive > self.evaluation_domain_size
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "relation variant has invalid trace, evaluation, or opening domains",
            ));
        }
        if self.ordered_verifier_sources.is_empty()
            || self.ordered_columns.is_empty()
            || self.ordered_trees.is_empty()
            || self.ordered_constraints.is_empty()
            || self.ordered_opening_points.is_empty()
            || self.ordered_opening_claims.is_empty()
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "relation variant omits a required source, column, tree, constraint, or opening",
            ));
        }
        require_strictly_increasing(
            &self.ordered_non_native_moduli,
            "relation non-native modulus references must be unique and increasing",
        )?;
        if self
            .ordered_non_native_moduli
            .iter()
            .any(|reference| reference.catalog == SuiteModulusCatalog::ProofField)
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation non-native modulus list cannot contain the proof field",
            ));
        }
        self.validate_source_ordering()?;
        self.validate_sampler_links(proof_family)?;
        self.validate_column_and_tree_layout()?;
        self.validate_constraint_programs(None)?;
        self.validate_openings(None)?;
        self.validate_masks()?;
        Ok(())
    }

    fn validate_source_ordering(&self) -> SchemaResult<()> {
        let source_bytes = self
            .ordered_verifier_sources
            .iter()
            .map(|source| source.canonical_tuple()?.encode().map_err(Into::into))
            .collect::<SchemaResult<Vec<Vec<u8>>>>()?;
        for pair in source_bytes.windows(2) {
            if pair[0] >= pair[1] {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation verifier sources must be unique and canonically ordered",
                ));
            }
        }
        Ok(())
    }

    fn validate_sampler_links(&self, proof_family: ProofFamily) -> SchemaResult<()> {
        let mut previous_key: Option<(&str, &[u8])> = None;
        let mut output_source_ordinals = HashSet::new();
        for (sampler_ordinal, sampler) in self.ordered_public_samplers.iter().enumerate() {
            sampler.validate_role_domain(proof_family)?;
            let key = (
                sampler.role_domain.as_str(),
                sampler.canonical_role_coordinate_bytes.as_slice(),
            );
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation public samplers must be unique and canonically ordered",
                ));
            }
            previous_key = Some(key);
            let seed_source = source_at(
                &self.ordered_verifier_sources,
                sampler.seed_verifier_source_ordinal,
            )?;
            if !seed_source.value_layout().is_some_and(RelationValueLayout::is_scalar_hash) {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation public-sampler seed must resolve to one scalar hash",
                ));
            }
            let output_source = source_at(
                &self.ordered_verifier_sources,
                sampler.output_verifier_source_ordinal,
            )?;
            if output_source
                != &(RelationVerifierSource::SamplerOutput {
                    public_sampler_ordinal: u32::try_from(sampler_ordinal).map_err(|_| {
                        schema_error(
                            RefusalReason::OutsideSupportedProfile,
                            "relation public-sampler ordinal does not fit u32",
                        )
                    })?,
                })
            {
                return Err(schema_error(
                    RefusalReason::WrongContext,
                    "relation public sampler has the wrong output-source back-reference",
                ));
            }
            if !output_source_ordinals.insert(sampler.output_verifier_source_ordinal) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation public samplers share an output verifier source",
                ));
            }
        }
        for source in &self.ordered_verifier_sources {
            if let RelationVerifierSource::SamplerOutput {
                public_sampler_ordinal,
            } = source
                && usize::try_from(*public_sampler_ordinal)
                    .ok()
                    .is_none_or(|ordinal| ordinal >= self.ordered_public_samplers.len())
            {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation sampler-output source names an absent sampler",
                ));
            }
        }
        Ok(())
    }

    fn validate_column_and_tree_layout(&self) -> SchemaResult<()> {
        if self.ordered_columns.iter().any(|column| {
            column.source_degree_bound_exclusive > self.opening_degree_bound_exclusive
        }) {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "relation column degree exceeds the opening-degree bound",
            ));
        }
        if self.proof_privacy_mode == ProofPrivacyMode::PublicOnlyDeterministic
            && self
                .ordered_columns
                .iter()
                .any(|column| column.origin == RelationColumnOrigin::Prover)
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "public-only relation cannot contain a prover column",
            ));
        }

        let mut column_tree_membership = vec![None; self.ordered_columns.len()];
        let mut consumed_sources = vec![false; self.ordered_verifier_sources.len()];
        for sampler in &self.ordered_public_samplers {
            mark_source_consumed(&mut consumed_sources, sampler.seed_verifier_source_ordinal)?;
        }
        for (tree_ordinal, tree) in self.ordered_trees.iter().enumerate() {
            for column_ordinal in tree.ordered_column_ordinals() {
                let column_index = usize::try_from(*column_ordinal).map_err(|_| {
                    schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation tree column ordinal does not fit the runtime",
                    )
                })?;
                let membership = column_tree_membership.get_mut(column_index).ok_or_else(|| {
                    schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation tree names a column outside the column catalog",
                    )
                })?;
                if membership.replace(tree_ordinal).is_some() {
                    return Err(schema_error(
                        RefusalReason::DuplicateIdentity,
                        "relation column occurs in more than one tree",
                    ));
                }
                let column = &self.ordered_columns[column_index];
                match (tree, &column.origin) {
                    (
                        RelationTreeDescriptor::BoundPublic {
                            expected_root_source_ordinal,
                            ..
                        },
                        RelationColumnOrigin::BoundTree {
                            expected_root_source_ordinal: column_root_source,
                        },
                    ) if expected_root_source_ordinal == column_root_source => {}
                    (RelationTreeDescriptor::ProofCreated { .. }, RelationColumnOrigin::BoundTree { .. })
                    | (RelationTreeDescriptor::BoundPublic { .. }, _)
                    | (RelationTreeDescriptor::ProofCreated { .. }, _) => {
                        if matches!(tree, RelationTreeDescriptor::BoundPublic { .. })
                            || matches!(column.origin, RelationColumnOrigin::BoundTree { .. })
                        {
                            return Err(schema_error(
                                RefusalReason::WrongContext,
                                "relation tree and column origin disagree on bound-root ownership",
                            ));
                        }
                    }
                }
            }
            if let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ..
            } = tree
            {
                let root_source = source_at(
                    &self.ordered_verifier_sources,
                    *expected_root_source_ordinal,
                )?;
                if !root_source
                    .value_layout()
                    .is_some_and(RelationValueLayout::is_scalar_hash)
                {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "bound public tree root source must be one scalar hash",
                    ));
                }
                mark_source_consumed(&mut consumed_sources, *expected_root_source_ordinal)?;
            }
        }
        if column_tree_membership.iter().any(Option::is_none) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "every relation column must occur in exactly one tree",
            ));
        }

        for column in &self.ordered_columns {
            let RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } = column.origin
            else {
                continue;
            };
            let source = source_at(
                &self.ordered_verifier_sources,
                verifier_source_ordinal,
            )?;
            let (element_kind, logical_element_count) =
                self.source_element_kind_and_count(source)?;
            let expected_column_value_type = match element_kind {
                RelationElementKind::ProofChallengeExtension => {
                    RelationColumnValueType::ChallengeExtension
                }
                RelationElementKind::ProofBaseField | RelationElementKind::SuiteResidue => {
                    RelationColumnValueType::BaseField
                }
                RelationElementKind::Hash512 => {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "hash source cannot supply a relation column",
                    ));
                }
            };
            if column.value_type != expected_column_value_type {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation verifier source and column value types disagree",
                ));
            }
            if logical_element_stride == 0 && logical_element_count != 1 {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "zero-stride relation column requires a scalar source",
                ));
            }
            let final_source_index = first_logical_element_index
                .checked_add(
                    self.trace_domain_size
                        .checked_sub(1)
                        .and_then(|last_row| last_row.checked_mul(logical_element_stride))
                        .ok_or_else(|| {
                            schema_error(
                                RefusalReason::OutsideSupportedProfile,
                                "relation verifier-sequence range overflows",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "relation verifier-sequence final index overflows",
                    )
                })?;
            if final_source_index >= logical_element_count {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation verifier-sequence range exceeds its source layout",
                ));
            }
            mark_source_consumed(&mut consumed_sources, verifier_source_ordinal)?;
        }
        if consumed_sources.iter().any(|consumed| !consumed) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation contains an unconsumed verifier source",
            ));
        }
        Ok(())
    }

    fn source_element_kind_and_count(
        &self,
        source: &RelationVerifierSource,
    ) -> SchemaResult<(RelationElementKind, u64)> {
        if let Some(layout) = source.value_layout() {
            return Ok((layout.element_kind, layout.logical_element_count));
        }
        let RelationVerifierSource::SamplerOutput {
            public_sampler_ordinal,
        } = source
        else {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation verifier source has no value layout",
            ));
        };
        let sampler = self
            .ordered_public_samplers
            .get(usize::try_from(*public_sampler_ordinal).map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation sampler ordinal does not fit the runtime",
                )
            })?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation sampler-output source names an absent sampler",
                )
            })?;
        Ok((RelationElementKind::SuiteResidue, sampler.output_count))
    }

    fn validate_constraint_programs(
        &self,
        context: Option<ExpressionValidationContext<'_>>,
    ) -> SchemaResult<()> {
        let mut identities = HashSet::new();
        for constraint in &self.ordered_constraints {
            if !identities.insert((
                constraint.constraint_role,
                constraint.role_coordinates.clone(),
            )) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation constraint role and coordinates must be unique",
                ));
            }
            validate_expression_program(
                &constraint.numerator_postfix_expression,
                false,
                self,
                context,
            )?;
            validate_expression_program(
                &constraint.zeroifier_postfix_expression,
                true,
                self,
                context,
            )?;
        }
        Ok(())
    }

    fn validate_openings(
        &self,
        context: Option<ExpressionValidationContext<'_>>,
    ) -> SchemaResult<()> {
        let mut opening_points = HashSet::new();
        for point in &self.ordered_opening_points {
            if point.trace_rotation_magnitude >= self.trace_domain_size {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation opening rotation is not reduced by the trace domain",
                ));
            }
            if let Some(context) = context
                && (point.deep_point_ordinal >= context.schedule.deep_point_count
                    || usize::from(point.conjugate_index)
                        >= context.proof_field.challenge_extension_degree())
            {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation opening point is outside its DEEP or conjugate catalog",
                ));
            }
            if !opening_points.insert(*point) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation opening points must be unique",
                ));
            }
        }

        let mut claim_identities = HashSet::new();
        let mut quotient_ordinals = BTreeSet::new();
        for claim in &self.ordered_opening_claims {
            if usize::try_from(claim.opening_point_ordinal)
                .ok()
                .is_none_or(|ordinal| ordinal >= self.ordered_opening_points.len())
                || claim.source_degree_bound_exclusive > self.opening_degree_bound_exclusive
            {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation opening claim has an out-of-range point or degree",
                ));
            }
            if !claim_identities.insert((
                claim.source_class,
                claim.source_ordinal,
                claim.column_ordinal,
                claim.opening_point_ordinal,
            )) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation opening claim identity must be unique",
                ));
            }
            match claim.source_class {
                1 => {
                    let tree = self
                        .ordered_trees
                        .get(usize::try_from(claim.source_ordinal).map_err(|_| {
                            schema_error(
                                RefusalReason::WrongTypeOrLength,
                                "relation opening tree ordinal does not fit the runtime",
                            )
                        })?)
                        .ok_or_else(|| {
                            schema_error(
                                RefusalReason::WrongTypeOrLength,
                                "relation opening names an absent tree",
                            )
                        })?;
                    let column_ordinal = claim.column_ordinal.ok_or_else(|| {
                        schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "tree-column opening omits its column",
                        )
                    })?;
                    if !tree.ordered_column_ordinals().contains(&column_ordinal) {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "relation tree-column opening names a column outside its tree",
                        ));
                    }
                    let column = self
                        .ordered_columns
                        .get(usize::try_from(column_ordinal).map_err(|_| {
                            schema_error(
                                RefusalReason::WrongTypeOrLength,
                                "relation opening column ordinal does not fit the runtime",
                            )
                        })?)
                        .ok_or_else(|| {
                            schema_error(
                                RefusalReason::WrongTypeOrLength,
                                "relation opening names an absent column",
                            )
                        })?;
                    if claim.source_degree_bound_exclusive
                        != column.source_degree_bound_exclusive
                    {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "relation tree-column opening has the wrong degree bound",
                        ));
                    }
                }
                2 => {
                    quotient_ordinals.insert(claim.source_ordinal);
                }
                3 => {
                    if self.proof_privacy_mode != ProofPrivacyMode::SecretBearingMasked
                        || claim.source_ordinal != 0
                        || claim.source_degree_bound_exclusive
                            != self.opening_degree_bound_exclusive - 1
                    {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "opening-batch mask claim does not match the secret-bearing grammar",
                        ));
                    }
                }
                _ => unreachable!("opening source class was checked while decoding"),
            }
        }
        if quotient_ordinals.len() < 2
            || quotient_ordinals
                .iter()
                .copied()
                .ne(0..u32::try_from(quotient_ordinals.len()).map_err(|_| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "relation quotient-component count does not fit u32",
                    )
                })?)
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation quotient opening ordinals must be contiguous from zero",
            ));
        }
        Ok(())
    }

    fn validate_masks(&self) -> SchemaResult<()> {
        if self.proof_privacy_mode == ProofPrivacyMode::PublicOnlyDeterministic {
            if !self.ordered_masks.is_empty() {
                return Err(schema_error(
                    RefusalReason::WrongContext,
                    "public-only relation cannot contain mask descriptors",
                ));
            }
            return Ok(());
        }
        let prover_column_ordinals = self
            .ordered_columns
            .iter()
            .enumerate()
            .filter_map(|(ordinal, column)| {
                (column.origin == RelationColumnOrigin::Prover)
                    .then(|| u32::try_from(ordinal).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if prover_column_ordinals.is_empty() || self.ordered_masks.is_empty() {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "secret-bearing relation requires prover columns and complete masks",
            ));
        }
        let mut purposes = HashSet::new();
        let mut targets = HashSet::new();
        let mut trace_targets = BTreeSet::new();
        let mut common_trace_bound = None;
        let mut quotient_targets = BTreeSet::new();
        let mut opening_batch_count = 0usize;
        for mask in &self.ordered_masks {
            if !purposes.insert(mask.mask_purpose)
                || !targets.insert((mask.target_class, mask.target_ordinal))
            {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "relation mask purposes and targets must be unique",
                ));
            }
            match mask.mask_kind {
                1 => {
                    if mask.mask_degree_bound_exclusive > self.trace_domain_size {
                        return Err(schema_error(
                            RefusalReason::OutsideSupportedProfile,
                            "relation trace-mask degree exceeds the trace domain",
                        ));
                    }
                    if common_trace_bound
                        .replace(mask.mask_degree_bound_exclusive)
                        .is_some_and(|bound| bound != mask.mask_degree_bound_exclusive)
                    {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "relation trace masks must share one degree bound",
                        ));
                    }
                    trace_targets.insert(mask.target_ordinal);
                }
                2 => {
                    quotient_targets.insert(mask.target_ordinal);
                }
                3 => {
                    if mask.target_ordinal != 0
                        || mask.mask_degree_bound_exclusive
                            != self.opening_degree_bound_exclusive - 1
                    {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "relation opening-batch mask has the wrong target or degree",
                        ));
                    }
                    opening_batch_count += 1;
                }
                _ => unreachable!("mask kind was checked while decoding"),
            }
        }
        if trace_targets != prover_column_ordinals || opening_batch_count != 1 {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation mask catalog does not cover exactly the private columns and opening batch",
            ));
        }
        let quotient_component_count = self
            .ordered_opening_claims
            .iter()
            .filter(|claim| claim.source_class == 2)
            .map(|claim| claim.source_ordinal)
            .max()
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "secret-bearing relation omits quotient openings",
                )
            })?;
        if quotient_targets
            .iter()
            .copied()
            .ne(0..quotient_component_count.saturating_sub(1))
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation quotient-mask targets do not cover the telescoping chain",
            ));
        }
        Ok(())
    }

    fn validate_for_suite(
        &self,
        proof_family: ProofFamily,
        suite_record: &SuiteRecord,
        proof_field: &ProofFieldProfile,
        schedule: &ProofFieldSchedule,
    ) -> SchemaResult<()> {
        let expected_evaluation_domain_size = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .and_then(|domain| domain.checked_mul(u64::from(schedule.evaluation_blowup_factor)))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "relation evaluation-domain derivation overflows",
                )
            })?;
        if self.evaluation_domain_size != expected_evaluation_domain_size
            || self.evaluation_domain_size > proof_field.maximum_two_adic_subgroup_order()
            || !(proof_field.base_field_modulus - 1).is_multiple_of(self.evaluation_domain_size)
            || modular_power(
                schedule.evaluation_coset_offset,
                self.evaluation_domain_size,
                proof_field.base_field_modulus,
            ) == 1
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "relation evaluation domain does not match its proof-field schedule",
            ));
        }
        for reference in &self.ordered_non_native_moduli {
            if reference.resolve(suite_record, proof_field)? >= proof_field.base_field_modulus {
                return Err(schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "relation non-native modulus is not injective in the proof base field",
                ));
            }
        }
        for source in &self.ordered_verifier_sources {
            source.validate_for_family(proof_family, suite_record, proof_field)?;
        }
        for sampler in &self.ordered_public_samplers {
            if sampler.output_modulus.resolve(suite_record, proof_field)?
                >= proof_field.base_field_modulus
            {
                return Err(schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "relation public-sampler modulus is not injective in the proof base field",
                ));
            }
        }
        let context = ExpressionValidationContext {
            proof_field,
            schedule,
            non_native_modulus_count: self.ordered_non_native_moduli.len(),
            constraint_count: self.ordered_constraints.len(),
        };
        self.validate_constraint_programs(Some(context))?;
        self.validate_openings(Some(context))?;
        self.validate_referenced_moduli(proof_family)?;
        Ok(())
    }

    fn validate_referenced_moduli(&self, proof_family: ProofFamily) -> SchemaResult<()> {
        let mut referenced = BTreeSet::new();
        for source in &self.ordered_verifier_sources {
            if let Some(reference) = source
                .value_layout()
                .and_then(|layout| layout.residue_modulus)
            {
                referenced.insert(reference);
            }
        }
        for sampler in &self.ordered_public_samplers {
            referenced.insert(sampler.output_modulus);
        }
        for constraint in &self.ordered_constraints {
            if proof_family == ProofFamily::CollectivePublicKeyAggregate
                && constraint.constraint_role == 1
                && let Some(modulus_ordinal) = constraint.role_coordinates.first().copied()
            {
                let modulus_index = usize::try_from(modulus_ordinal).map_err(|_| {
                    schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation constraint modulus ordinal does not fit the runtime",
                    )
                })?;
                if let Some(reference) = self.ordered_non_native_moduli.get(modulus_index) {
                    referenced.insert(*reference);
                }
            }
            for instruction in &constraint.numerator_postfix_expression {
                if let RelationExpressionInstruction::TranscriptChallenge {
                    role_coordinates,
                    ..
                } = instruction
                {
                    let modulus_index = usize::try_from(role_coordinates[0]).map_err(|_| {
                        schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation challenge modulus ordinal does not fit the runtime",
                        )
                    })?;
                    if let Some(reference) = self.ordered_non_native_moduli.get(modulus_index) {
                        referenced.insert(*reference);
                    }
                }
            }
        }
        if referenced
            != self
                .ordered_non_native_moduli
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation non-native modulus catalog is incomplete or contains an unused entry",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ExpressionValidationContext<'a> {
    proof_field: &'a ProofFieldProfile,
    schedule: &'a ProofFieldSchedule,
    non_native_modulus_count: usize,
    constraint_count: usize,
}

fn validate_expression_program(
    program: &[RelationExpressionInstruction],
    is_zeroifier: bool,
    variant: &RelationPlanVariant,
    context: Option<ExpressionValidationContext<'_>>,
) -> SchemaResult<u64> {
    let mut degree_stack = Vec::with_capacity(program.len().min(64));
    for instruction in program {
        let result_degree = match instruction {
            RelationExpressionInstruction::BaseFieldConstant(bytes) => {
                if let Some(context) = context {
                    validate_base_field_element(bytes, context.proof_field.base_field_modulus)?;
                }
                Some(0)
            }
            RelationExpressionInstruction::EvaluationVariable => Some(1),
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_magnitude,
                ..
            } => {
                if is_zeroifier {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation zeroifier cannot read a witness or verifier column",
                    ));
                }
                let column = variant
                    .ordered_columns
                    .get(usize::try_from(*column_ordinal).map_err(|_| {
                        schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation expression column ordinal does not fit the runtime",
                        )
                    })?)
                    .ok_or_else(|| {
                        schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation expression names an absent column",
                        )
                    })?;
                if *rotation_magnitude >= variant.trace_domain_size {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation column rotation is not reduced by the trace domain",
                    ));
                }
                Some(column.source_degree_bound_exclusive.saturating_sub(1))
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => {
                if is_zeroifier {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation zeroifier cannot read transcript challenges",
                    ));
                }
                if let Some(context) = context {
                    let modulus_ordinal = usize::try_from(role_coordinates[0]).map_err(|_| {
                        schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation challenge modulus ordinal does not fit the runtime",
                        )
                    })?;
                    let challenge_ordinal = usize::try_from(role_coordinates[1]).map_err(|_| {
                        schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation challenge ordinal does not fit the runtime",
                        )
                    })?;
                    if modulus_ordinal >= context.non_native_modulus_count
                        || challenge_ordinal
                            >= usize::from(
                                context
                                    .schedule
                                    .non_native_modular_identity_challenge_count,
                            )
                        || (*challenge_role == 2
                            && usize::try_from(role_coordinates[2])
                                .ok()
                                .is_none_or(|unit| unit >= context.constraint_count))
                    {
                        return Err(schema_error(
                            RefusalReason::WrongTypeOrLength,
                            "relation transcript challenge coordinates are out of range",
                        ));
                    }
                }
                Some(0)
            }
            RelationExpressionInstruction::Addition => {
                let right = pop_expression_degree(&mut degree_stack)?;
                let left = pop_expression_degree(&mut degree_stack)?;
                Some(left.max(right))
            }
            RelationExpressionInstruction::Multiplication => {
                let right = pop_expression_degree(&mut degree_stack)?;
                let left = pop_expression_degree(&mut degree_stack)?;
                Some(left.checked_add(right).ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "relation expression symbolic degree overflows",
                    )
                })?)
            }
            RelationExpressionInstruction::Negation => {
                Some(pop_expression_degree(&mut degree_stack)?)
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let input_degree = pop_expression_degree(&mut degree_stack)?;
                Some(input_degree.checked_mul(*exponent).ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "relation power instruction symbolic degree overflows",
                    )
                })?)
            }
            RelationExpressionInstruction::FrobeniusConjugate(conjugate_index) => {
                if is_zeroifier {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation zeroifier cannot use a Frobenius instruction",
                    ));
                }
                if let Some(context) = context
                    && usize::from(*conjugate_index)
                        >= context.proof_field.challenge_extension_degree()
                {
                    return Err(schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "relation Frobenius conjugate index is outside the extension degree",
                    ));
                }
                Some(pop_expression_degree(&mut degree_stack)?)
            }
        };
        if let Some(degree) = result_degree {
            degree_stack.push(degree);
        }
    }
    if degree_stack.len() != 1 {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "relation postfix expression does not finish with exactly one stack value",
        ));
    }
    Ok(degree_stack[0])
}

fn pop_expression_degree(stack: &mut Vec<u64>) -> SchemaResult<u64> {
    stack.pop().ok_or_else(|| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "relation postfix expression underflows its value stack",
        )
    })
}

fn validate_base_field_element(bytes: &[u8], modulus: u64) -> SchemaResult<()> {
    let expected_byte_length = usize::try_from((u64::BITS - (modulus - 1).leading_zeros()).div_ceil(8))
        .map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof base-field width does not fit the runtime",
            )
        })?;
    if bytes.len() != expected_byte_length || bytes.len() > u64::BITS as usize / 8 {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "relation base-field constant has the wrong fixed width",
        ));
    }
    let mut value_bytes = [0u8; 8];
    value_bytes[..bytes.len()].copy_from_slice(bytes);
    if u64::from_le_bytes(value_bytes) >= modulus {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "relation base-field constant is not a canonical residue",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalRelationPlan {
    proof_family: ProofFamily,
    variants: Vec<RelationPlanVariant>,
}

impl CanonicalRelationPlan {
    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        if bytes.len() > RELATION_PLAN_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "relation plan exceeds its bounded canonical length",
            ));
        }
        let mut bounded_limits = *limits;
        bounded_limits.maximum_tuple_byte_length = bounded_limits
            .maximum_tuple_byte_length
            .min(RELATION_PLAN_MAXIMUM_BYTE_LENGTH);
        bounded_limits.maximum_item_byte_length = bounded_limits
            .maximum_item_byte_length
            .min(RELATION_PLAN_MAXIMUM_BYTE_LENGTH);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, RELATION_PLAN_SCHEMA_IDENTIFIER, 2)?;
        let statement_schema_identifier = read_u16(&tuple.items[0])?;
        let proof_family = ProofFamily::from_statement_schema_identifier(
            statement_schema_identifier,
        )
        .ok_or_else(|| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation plan names an unassigned application-statement family",
            )
        })?;
        let variants = read_nested_tuple_list(&tuple.items[1], &bounded_limits)?
            .iter()
            .map(|variant| RelationPlanVariant::from_tuple(variant, &bounded_limits, proof_family))
            .collect::<SchemaResult<Vec<_>>>()?;
        let plan = Self {
            proof_family,
            variants,
        };
        plan.validate_variant_catalog()?;
        if plan.encode()? != bytes {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "typed relation plan does not re-encode byte-identically",
            ));
        }
        Ok(plan)
    }

    pub(crate) fn encode(&self) -> SchemaResult<Vec<u8>> {
        let bytes = CanonicalTuple::new(
            RELATION_PLAN_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.proof_family.statement_schema_identifier()),
                encode_nested_tuple_list(
                    self.variants
                        .iter()
                        .map(RelationPlanVariant::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
            ],
        )
        .encode()?;
        if bytes.len() > RELATION_PLAN_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "relation plan exceeds its bounded canonical length",
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn validate_for_suite(
        &self,
        suite_record: &SuiteRecord,
        proof_profile_set: &ProofProfileSet,
    ) -> SchemaResult<()> {
        suite_record.validate_intrinsic()?;
        let (proof_field, schedule) =
            proof_profile_set.field_and_schedule_for_family(self.proof_family)?;
        for variant in &self.variants {
            variant.validate_for_suite(
                self.proof_family,
                suite_record,
                proof_field,
                schedule,
            )?;
        }
        Ok(())
    }

    fn validate_variant_catalog(&self) -> SchemaResult<()> {
        match self.proof_family {
            ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundOneAggregate
            | ProofFamily::RelinearizationRoundTwo
            | ProofFamily::GaloisKeyShare => {
                if self.variants.is_empty() {
                    return Err(schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "scheduled relation plan must contain at least one variant",
                    ));
                }
                for (expected_position, variant) in self.variants.iter().enumerate() {
                    if variant.top_count.is_some()
                        || variant.schedule_position
                            != Some(u32::try_from(expected_position).map_err(|_| {
                                schema_error(
                                    RefusalReason::OutsideSupportedProfile,
                                    "relation schedule position does not fit u32",
                                )
                            })?)
                    {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "scheduled relation variants must be contiguous from position zero",
                        ));
                    }
                }
            }
            ProofFamily::EvaluatorKeyAggregate => {
                if self.variants.len() != EVALUATOR_KEY_AGGREGATE_VARIANT_COUNT {
                    return Err(schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "evaluator-key aggregate relation must contain twenty variants",
                    ));
                }
                for (variant_index, variant) in self.variants.iter().enumerate() {
                    if variant.schedule_position.is_some()
                        || variant.top_count
                            != Some(u16::try_from(variant_index + 1).map_err(|_| {
                                schema_error(
                                    RefusalReason::OutsideSupportedProfile,
                                    "relation top count does not fit u16",
                                )
                            })?)
                    {
                        return Err(schema_error(
                            RefusalReason::WrongContext,
                            "evaluator-key aggregate variants must cover top counts one through twenty",
                        ));
                    }
                }
            }
            _ => {
                if self.variants.len() != 1
                    || self.variants[0].schedule_position.is_some()
                    || self.variants[0].top_count.is_some()
                {
                    return Err(schema_error(
                        RefusalReason::WrongContext,
                        "unscheduled relation plan must contain one selector-free variant",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationRootEndpoint {
    proof_family: ProofFamily,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    producer_sequence: Option<u64>,
    verifier_source_ordinal: u32,
}

impl RelationRootEndpoint {
    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER, 6)?;
        let statement_schema_identifier = read_u16(&tuple.items[0])?;
        let endpoint = Self {
            proof_family: ProofFamily::from_statement_schema_identifier(
                statement_schema_identifier,
            )
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "relation root endpoint names an unassigned proof family",
                )
            })?,
            roster_position: read_optional_u16(&tuple.items[1])?,
            schedule_position: read_optional_u32(&tuple.items[2])?,
            top_count: read_optional_u16(&tuple.items[3])?,
            producer_sequence: read_optional_u64(&tuple.items[4])?,
            verifier_source_ordinal: read_u32(&tuple.items[5])?,
        };
        endpoint.validate_coordinate_grammar()?;
        Ok(endpoint)
    }

    fn validate_coordinate_grammar(&self) -> SchemaResult<()> {
        let valid = match self.proof_family {
            ProofFamily::SourceBatchedVerifiableSecretSharingLinkage
            | ProofFamily::AggregateThresholdShare
            | ProofFamily::SameSecretLinkage
            | ProofFamily::PublicKeyShare
            | ProofFamily::PairedTargetShare => {
                self.roster_position.is_some()
                    && self.schedule_position.is_none()
                    && self.top_count.is_none()
                    && self.producer_sequence.is_none()
            }
            ProofFamily::CollectivePublicKeyAggregate => {
                self.roster_position.is_none()
                    && self.schedule_position.is_none()
                    && self.top_count.is_none()
                    && self.producer_sequence.is_none()
            }
            ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundTwo
            | ProofFamily::GaloisKeyShare => {
                self.roster_position.is_some()
                    && self.schedule_position.is_some()
                    && self.top_count.is_none()
                    && self.producer_sequence.is_none()
            }
            ProofFamily::RelinearizationRoundOneAggregate => {
                self.roster_position.is_none()
                    && self.schedule_position.is_some()
                    && self.top_count.is_none()
                    && self.producer_sequence.is_none()
            }
            ProofFamily::EvaluatorKeyAggregate => {
                self.roster_position.is_none()
                    && self.schedule_position.is_none()
                    && self.top_count.is_some_and(|top_count| (1..=20).contains(&top_count))
                    && self.producer_sequence.is_none()
            }
            ProofFamily::BallotValidity => {
                self.roster_position.is_some()
                    && self.schedule_position.is_none()
                    && self.top_count.is_none()
                    && self.producer_sequence.is_some()
            }
        };
        if !valid {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation root endpoint coordinates do not match the proof family",
            ));
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate_coordinate_grammar()?;
        Ok(CanonicalTuple::new(
            RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.proof_family.statement_schema_identifier()),
                optional_u16(self.roster_position)?,
                optional_u32(self.schedule_position)?,
                optional_u16(self.top_count)?,
                optional_u64(self.producer_sequence)?,
                CanonicalItem::unsigned32(self.verifier_source_ordinal),
            ],
        ))
    }

    pub(crate) fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        let endpoint = Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)?;
        if endpoint.encode()? != bytes {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "relation root endpoint does not re-encode byte-identically",
            ));
        }
        Ok(endpoint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationRootCompatibilityEdge {
    producer_endpoint: RelationRootEndpoint,
    consumer_endpoint: RelationRootEndpoint,
    construction_kind: u16,
}

impl RelationRootCompatibilityEdge {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(tuple, RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER, 3)?;
        let construction_kind = read_u16(&tuple.items[2])?;
        if !matches!(construction_kind, 1 | 2) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation root edge construction kind is unassigned",
            ));
        }
        let edge = Self {
            producer_endpoint: RelationRootEndpoint::from_tuple(&read_nested_tuple(
                &tuple.items[0],
                limits,
            )?)?,
            consumer_endpoint: RelationRootEndpoint::from_tuple(&read_nested_tuple(
                &tuple.items[1],
                limits,
            )?)?,
            construction_kind,
        };
        if edge.producer_endpoint == edge.consumer_endpoint {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "relation root edge cannot connect an endpoint to itself",
            ));
        }
        Ok(edge)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.producer_endpoint.canonical_tuple()?)?,
                CanonicalItem::nested_tuple(&self.consumer_endpoint.canonical_tuple()?)?,
                CanonicalItem::unsigned16(self.construction_kind),
            ],
        ))
    }

    pub(crate) fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        let edge = Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?, limits)?;
        if edge.encode()? != bytes {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "relation root edge does not re-encode byte-identically",
            ));
        }
        Ok(edge)
    }
}

fn source_at(
    sources: &[RelationVerifierSource],
    source_ordinal: u32,
) -> SchemaResult<&RelationVerifierSource> {
    sources
        .get(usize::try_from(source_ordinal).map_err(|_| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation verifier-source ordinal does not fit the runtime",
            )
        })?)
        .ok_or_else(|| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation verifier-source ordinal is outside the source catalog",
            )
        })
}

fn mark_source_consumed(consumed_sources: &mut [bool], source_ordinal: u32) -> SchemaResult<()> {
    let source = consumed_sources
        .get_mut(usize::try_from(source_ordinal).map_err(|_| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation verifier-source ordinal does not fit the runtime",
            )
        })?)
        .ok_or_else(|| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "relation verifier-source ordinal is outside the source catalog",
            )
        })?;
    *source = true;
    Ok(())
}

fn coordinate_as_u16(coordinate: u64) -> SchemaResult<u16> {
    u16::try_from(coordinate).map_err(|_| {
        schema_error(
            RefusalReason::WrongTypeOrLength,
            "relation source coordinate does not fit u16",
        )
    })
}

fn read_u8(item: &CanonicalItem) -> SchemaResult<u8> {
    let bytes = read_item(item, CanonicalItemType::Unsigned8)?;
    if bytes.len() != 1 {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "relation u8 item has the wrong length",
        ));
    }
    Ok(bytes[0])
}

fn read_u32_list(item: &CanonicalItem) -> SchemaResult<Vec<u32>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned32)?;
    if bytes.len()
        != count.checked_mul(4).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "relation u32-list length overflows",
            )
        })?
    {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "relation u32-list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let value: [u8; 4] = chunk.try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "relation u32-list element length is malformed",
                )
            })?;
            Ok(u32::from_le_bytes(value))
        })
        .collect()
}

fn read_u64_list(item: &CanonicalItem) -> SchemaResult<Vec<u64>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned64)?;
    if bytes.len()
        != count.checked_mul(8).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "relation u64-list length overflows",
            )
        })?
    {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "relation u64-list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let value: [u8; 8] = chunk.try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "relation u64-list element length is malformed",
                )
            })?;
            Ok(u64::from_le_bytes(value))
        })
        .collect()
}

fn read_optional_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Option<CanonicalTuple>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]])
            != CanonicalItemType::NestedTuple.canonical_code()
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "optional relation tuple has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 => Ok(Some(CanonicalTuple::decode(&bytes[3..], limits)?)),
        _ => Err(schema_error(
            RefusalReason::MalformedEncoding,
            "optional relation tuple encoding is malformed",
        )),
    }
}

fn encode_optional_nested_tuple(tuple: Option<&CanonicalTuple>) -> SchemaResult<CanonicalItem> {
    let item = tuple.map(CanonicalItem::nested_tuple).transpose()?;
    Ok(CanonicalItem::optional(
        CanonicalItemType::NestedTuple,
        item.as_ref(),
    )?)
}

fn encode_nested_tuple_list(
    tuples: impl IntoIterator<Item = CanonicalTuple>,
) -> SchemaResult<CanonicalItem> {
    let items = tuples
        .into_iter()
        .map(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
        .collect::<SchemaResult<Vec<_>>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::NestedTuple,
        &items,
    )?)
}

fn encode_u32_list(values: &[u32]) -> SchemaResult<CanonicalItem> {
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

fn encode_u64_list(values: &[u64]) -> SchemaResult<CanonicalItem> {
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

fn require_strictly_increasing<Value: Ord>(
    values: &[Value],
    message: &'static str,
) -> SchemaResult<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(schema_error(RefusalReason::DuplicateIdentity, message));
    }
    Ok(())
}

fn empty_tuple(schema_identifier: u16) -> CanonicalTuple {
    CanonicalTuple::new(schema_identifier, RELATION_SCHEMA_VERSION, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_layout() -> RelationValueLayout {
        RelationValueLayout {
            element_kind: RelationElementKind::Hash512,
            residue_modulus: None,
            shape: Vec::new(),
            embedding_kind: RelationEmbeddingKind::None,
            logical_element_count: 1,
        }
    }

    fn statement_hash_source(field_index: u64) -> RelationVerifierSource {
        RelationVerifierSource::ApplicationStatement {
            value_path: vec![RelationSelectorPathStep {
                step_kind: SelectorStepKind::TupleField,
                argument: field_index,
            }],
            value_layout: hash_layout(),
        }
    }

    fn zeroifier_expression() -> Vec<RelationExpressionInstruction> {
        vec![
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::NonnegativePower(2),
            RelationExpressionInstruction::BaseFieldConstant(vec![1, 0]),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ]
    }

    fn valid_public_variant() -> RelationPlanVariant {
        RelationPlanVariant {
            schedule_position: None,
            top_count: None,
            proof_privacy_mode: ProofPrivacyMode::PublicOnlyDeterministic,
            trace_domain_size: 2,
            evaluation_domain_size: 8,
            opening_degree_bound_exclusive: 2,
            ordered_non_native_moduli: Vec::new(),
            ordered_verifier_sources: vec![statement_hash_source(0)],
            ordered_public_samplers: Vec::new(),
            ordered_columns: vec![RelationColumnDescriptor {
                origin: RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: 0,
                },
                value_type: RelationColumnValueType::BaseField,
                source_degree_bound_exclusive: 2,
            }],
            ordered_trees: vec![RelationTreeDescriptor::BoundPublic {
                construction_kind: 2,
                expected_root_source_ordinal: 0,
                root_use: 1,
                ordered_column_ordinals: vec![0],
            }],
            ordered_constraints: vec![RelationConstraintDescriptor {
                constraint_role: 1,
                role_coordinates: Vec::new(),
                numerator_postfix_expression: vec![
                    RelationExpressionInstruction::ColumnValue {
                        column_ordinal: 0,
                        rotation_is_negative: false,
                        rotation_magnitude: 0,
                    },
                ],
                zeroifier_postfix_expression: zeroifier_expression(),
            }],
            ordered_opening_points: vec![RelationOpeningPointDescriptor {
                deep_point_ordinal: 0,
                trace_rotation_is_negative: false,
                trace_rotation_magnitude: 0,
                conjugate_index: 0,
            }],
            ordered_opening_claims: vec![
                RelationOpeningClaimDescriptor {
                    source_class: 1,
                    source_ordinal: 0,
                    column_ordinal: Some(0),
                    opening_point_ordinal: 0,
                    source_degree_bound_exclusive: 2,
                },
                RelationOpeningClaimDescriptor {
                    source_class: 2,
                    source_ordinal: 0,
                    column_ordinal: None,
                    opening_point_ordinal: 0,
                    source_degree_bound_exclusive: 2,
                },
                RelationOpeningClaimDescriptor {
                    source_class: 2,
                    source_ordinal: 1,
                    column_ordinal: None,
                    opening_point_ordinal: 0,
                    source_degree_bound_exclusive: 2,
                },
            ],
            ordered_masks: Vec::new(),
        }
    }

    fn valid_public_plan() -> CanonicalRelationPlan {
        CanonicalRelationPlan {
            proof_family: ProofFamily::CollectivePublicKeyAggregate,
            variants: vec![valid_public_variant()],
        }
    }

    #[test]
    fn typed_relation_plan_round_trips_without_implying_proof_acceptance() {
        let plan = valid_public_plan();
        let bytes = plan.encode().expect("typed relation plan encodes");
        assert_eq!(
            CanonicalRelationPlan::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("typed relation plan decodes"),
            plan
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            CanonicalRelationPlan::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );

        let mut wrong_family_tuple =
            CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).expect("plan tuple");
        wrong_family_tuple.items[0] = CanonicalItem::unsigned16(0xffff);
        assert!(
            CanonicalRelationPlan::decode(
                &wrong_family_tuple.encode().expect("wrong-family bytes"),
                &CanonicalDecodeLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn expression_validator_rejects_stack_and_opcode_misuse() {
        let variant = valid_public_variant();
        for program in [
            vec![RelationExpressionInstruction::Addition],
            vec![
                RelationExpressionInstruction::EvaluationVariable,
                RelationExpressionInstruction::EvaluationVariable,
            ],
            vec![RelationExpressionInstruction::ColumnValue {
                column_ordinal: 9,
                rotation_is_negative: false,
                rotation_magnitude: 0,
            }],
        ] {
            assert!(validate_expression_program(&program, false, &variant, None).is_err());
        }
        assert!(
            validate_expression_program(
                &[RelationExpressionInstruction::ColumnValue {
                    column_ordinal: 0,
                    rotation_is_negative: false,
                    rotation_magnitude: 0,
                }],
                true,
                &variant,
                None,
            )
            .is_err()
        );

        let negative_zero = CanonicalTuple::new(
            RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(0),
                CanonicalItem::unsigned8(1),
                CanonicalItem::unsigned64(0),
            ],
        );
        assert!(RelationExpressionInstruction::from_tuple(&negative_zero).is_err());
        let unknown_opcode = CanonicalTuple::new(0x2219, RELATION_SCHEMA_VERSION, Vec::new());
        assert!(RelationExpressionInstruction::from_tuple(&unknown_opcode).is_err());
    }

    #[test]
    fn selector_source_and_layout_grammars_reject_ambiguous_inputs() {
        let dynamic_nonzero = CanonicalTuple::new(
            RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned16(3), CanonicalItem::unsigned64(1)],
        );
        assert!(RelationSelectorPathStep::from_tuple(&dynamic_nonzero).is_err());

        let invalid_hash_layout = CanonicalTuple::new(
            RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(1),
                CanonicalItem::optional(CanonicalItemType::NestedTuple, None)
                    .expect("empty optional"),
                encode_u64_list(&[1]).expect("shape"),
                CanonicalItem::unsigned16(0),
            ],
        );
        assert!(
            RelationValueLayout::from_tuple(
                &invalid_hash_layout,
                &CanonicalDecodeLimits::default(),
            )
            .is_err()
        );

        let empty_path_source = CanonicalTuple::new(
            RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                encode_nested_tuple_list(Vec::<CanonicalTuple>::new()).expect("empty path"),
                CanonicalItem::nested_tuple(
                    &hash_layout().canonical_tuple().expect("hash layout tuple"),
                )
                .expect("nested layout"),
            ],
        );
        assert!(
            RelationVerifierSource::from_tuple(
                &empty_path_source,
                &CanonicalDecodeLimits::default(),
            )
            .is_err()
        );

        let mut duplicate_source_variant = valid_public_variant();
        duplicate_source_variant
            .ordered_verifier_sources
            .push(statement_hash_source(0));
        assert!(
            duplicate_source_variant
                .validate_intrinsic(ProofFamily::CollectivePublicKeyAggregate)
                .is_err()
        );
    }

    #[test]
    fn tree_opening_and_mask_cross_references_fail_closed() {
        let mut duplicate_column_variant = valid_public_variant();
        duplicate_column_variant
            .ordered_trees
            .push(RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 1,
                ordered_column_ordinals: vec![0],
            });
        assert!(
            duplicate_column_variant
                .validate_intrinsic(ProofFamily::CollectivePublicKeyAggregate)
                .is_err()
        );

        let mut wrong_tree_opening = valid_public_variant();
        wrong_tree_opening.ordered_opening_claims[0].source_ordinal = 3;
        assert!(
            wrong_tree_opening
                .validate_intrinsic(ProofFamily::CollectivePublicKeyAggregate)
                .is_err()
        );

        let mut public_mask = valid_public_variant();
        public_mask.ordered_masks.push(RelationMaskDescriptor {
            mask_purpose: 1,
            mask_kind: 1,
            target_class: 1,
            target_ordinal: 0,
            mask_degree_bound_exclusive: 1,
        });
        assert!(
            public_mask
                .validate_intrinsic(ProofFamily::CollectivePublicKeyAggregate)
                .is_err()
        );
    }

    fn endpoint_for_family(proof_family: ProofFamily, source_ordinal: u32) -> RelationRootEndpoint {
        let (roster_position, schedule_position, top_count, producer_sequence) = match proof_family {
            ProofFamily::SourceBatchedVerifiableSecretSharingLinkage
            | ProofFamily::AggregateThresholdShare
            | ProofFamily::SameSecretLinkage
            | ProofFamily::PublicKeyShare
            | ProofFamily::PairedTargetShare => (Some(1), None, None, None),
            ProofFamily::CollectivePublicKeyAggregate => (None, None, None, None),
            ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundTwo
            | ProofFamily::GaloisKeyShare => (Some(1), Some(2), None, None),
            ProofFamily::RelinearizationRoundOneAggregate => (None, Some(2), None, None),
            ProofFamily::EvaluatorKeyAggregate => (None, None, Some(3), None),
            ProofFamily::BallotValidity => (Some(1), None, None, Some(4)),
        };
        RelationRootEndpoint {
            proof_family,
            roster_position,
            schedule_position,
            top_count,
            producer_sequence,
            verifier_source_ordinal: source_ordinal,
        }
    }

    #[test]
    fn root_endpoints_and_edges_round_trip_the_closed_coordinate_grammar() {
        for proof_family in ProofFamily::assigned_families() {
            let endpoint = endpoint_for_family(proof_family, 0);
            let bytes = endpoint.encode().expect("root endpoint encodes");
            assert_eq!(
                RelationRootEndpoint::decode(&bytes, &CanonicalDecodeLimits::default())
                    .expect("root endpoint decodes"),
                endpoint
            );
        }

        let edge = RelationRootCompatibilityEdge {
            producer_endpoint: endpoint_for_family(ProofFamily::SameSecretLinkage, 2),
            consumer_endpoint: endpoint_for_family(ProofFamily::PublicKeyShare, 4),
            construction_kind: 1,
        };
        let bytes = edge.encode().expect("root edge encodes");
        assert_eq!(
            RelationRootCompatibilityEdge::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("root edge decodes"),
            edge
        );

        let mut wrong_coordinates = endpoint_for_family(ProofFamily::CollectivePublicKeyAggregate, 0);
        wrong_coordinates.roster_position = Some(0);
        assert!(wrong_coordinates.encode().is_err());
        let self_edge = RelationRootCompatibilityEdge {
            producer_endpoint: endpoint_for_family(ProofFamily::SameSecretLinkage, 0),
            consumer_endpoint: endpoint_for_family(ProofFamily::SameSecretLinkage, 0),
            construction_kind: 1,
        };
        assert!(
            RelationRootCompatibilityEdge::decode(
                &self_edge.encode().expect("structural self-edge bytes"),
                &CanonicalDecodeLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn every_nested_union_member_has_a_typed_byte_exact_codec() {
        let selector = RelationSelectorPathStep {
            step_kind: SelectorStepKind::TupleField,
            argument: 0,
        };
        assert_eq!(
            RelationSelectorPathStep::from_tuple(&selector.canonical_tuple())
                .expect("selector decodes"),
            selector
        );

        for source in [
            statement_hash_source(0),
            RelationVerifierSource::Protocol {
                protocol_source_kind: ProtocolSourceKind::PublicSetupSeed,
                source_coordinates: Vec::new(),
                statement_binding_path: vec![selector],
                value_layout: hash_layout(),
            },
            RelationVerifierSource::Suite {
                value_path: vec![selector],
                value_layout: hash_layout(),
            },
            RelationVerifierSource::ApplicationSlot {
                value_path: vec![selector],
                value_layout: hash_layout(),
            },
            RelationVerifierSource::SamplerOutput {
                public_sampler_ordinal: 0,
            },
        ] {
            let tuple = source.canonical_tuple().expect("source tuple");
            assert_eq!(
                RelationVerifierSource::from_tuple(&tuple, &CanonicalDecodeLimits::default())
                    .expect("source decodes"),
                source
            );
        }

        for origin in [
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal: 0,
                first_logical_element_index: 0,
                logical_element_stride: 1,
            },
            RelationColumnOrigin::BoundTree {
                expected_root_source_ordinal: 0,
            },
            RelationColumnOrigin::Prover,
        ] {
            assert_eq!(
                RelationColumnOrigin::from_tuple(&origin.canonical_tuple())
                    .expect("column origin decodes"),
                origin
            );
        }

        let coordinate_bytes = CanonicalTuple::new(
            0x1209,
            RELATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned16(0)],
        )
        .encode()
        .expect("coordinate bytes");
        let sampler = RelationPublicSamplerDescriptor {
            seed_verifier_source_ordinal: 0,
            role_domain:
                "sealed-lattice/proof/1212/public-sampler/public-key-common-polynomial/v1"
                    .to_owned(),
            canonical_role_coordinate_bytes: coordinate_bytes,
            output_modulus: SuiteModulusReference {
                catalog: SuiteModulusCatalog::Data,
                modulus_index: 0,
            },
            output_count: 2,
            output_verifier_source_ordinal: 1,
        };
        assert_eq!(
            RelationPublicSamplerDescriptor::from_tuple(
                &sampler.canonical_tuple().expect("sampler tuple"),
                &CanonicalDecodeLimits::default(),
            )
            .expect("sampler decodes"),
            sampler
        );

        for instruction in [
            RelationExpressionInstruction::BaseFieldConstant(vec![1, 0]),
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::ColumnValue {
                column_ordinal: 0,
                rotation_is_negative: false,
                rotation_magnitude: 0,
            },
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role: 1,
                role_coordinates: vec![0, 0],
            },
            RelationExpressionInstruction::Addition,
            RelationExpressionInstruction::Multiplication,
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::NonnegativePower(3),
            RelationExpressionInstruction::FrobeniusConjugate(0),
        ] {
            assert_eq!(
                RelationExpressionInstruction::from_tuple(
                    &instruction.canonical_tuple().expect("instruction tuple"),
                )
                .expect("instruction decodes"),
                instruction
            );
        }
    }
}
