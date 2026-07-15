//! Canonical generated relation plans.
//!
//! The semantic relation owner lowers one typed definition into this module's
//! closed plan grammar. Proof bytes never choose a source, column, tree,
//! challenge, opening, or privacy mode. `CompiledRelationPlan::check` is a
//! second pass over the generated value and does not trust compiler-side
//! counters or ordering decisions.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    StreamingFoundationTupleHash512,
};

use super::transcript::{
    CommonProofApplicationChallengeGroup, CommonProofChallenge, CommonProofPrivacyMode,
    CommonProofTranscriptSchedule,
};

const RELATION_PLAN_SCHEMA_IDENTIFIER: u16 = 0x2204;
const RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER: u16 = 0x2205;
const RELATION_COLUMN_SCHEMA_IDENTIFIER: u16 = 0x2206;
const PROOF_CREATED_TREE_SCHEMA_IDENTIFIER: u16 = 0x2207;
const BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER: u16 = 0x2208;
const RELATION_CONSTRAINT_SCHEMA_IDENTIFIER: u16 = 0x2209;
const RELATION_OPENING_POINT_SCHEMA_IDENTIFIER: u16 = 0x220a;
const RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER: u16 = 0x220b;
const RELATION_MASK_SCHEMA_IDENTIFIER: u16 = 0x220c;
const SIGNED_INTEGER_SCHEMA_IDENTIFIER: u16 = 0x220d;
const SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x220e;
const RELATION_PUBLIC_SAMPLER_SCHEMA_IDENTIFIER: u16 = 0x220f;
const BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER: u16 = 0x2210;
const EVALUATION_VARIABLE_SCHEMA_IDENTIFIER: u16 = 0x2211;
const COLUMN_VALUE_SCHEMA_IDENTIFIER: u16 = 0x2212;
const TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER: u16 = 0x2213;
const ADDITION_SCHEMA_IDENTIFIER: u16 = 0x2214;
const MULTIPLICATION_SCHEMA_IDENTIFIER: u16 = 0x2215;
const NEGATION_SCHEMA_IDENTIFIER: u16 = 0x2216;
const NONNEGATIVE_POWER_SCHEMA_IDENTIFIER: u16 = 0x2217;
const FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER: u16 = 0x2218;
const RADIX_CONVOLUTION_COEFFICIENT_SCHEMA_IDENTIFIER: u16 = 0x2219;
const TRACE_DOMAIN_EXCEPT_ROOTS_SCHEMA_IDENTIFIER: u16 = 0x221a;
const NON_NATIVE_MODULUS_CONSTANT_SCHEMA_IDENTIFIER: u16 = 0x221b;
const APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2220;
const PROTOCOL_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2221;
const SUITE_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2222;
const APPLICATION_SLOT_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2223;
const SAMPLER_OUTPUT_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2224;
const SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER: u16 = 0x2225;
const VALUE_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x2226;
const VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2227;
const BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2228;
const PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2229;
const RELATION_CHALLENGE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2230;
const PROOF_APPLICATION_SLOT_TEMPLATE_SCHEMA_IDENTIFIER: u16 = 0x2231;
const RELATION_CHALLENGE_MODULUS_SELECTOR_SCHEMA_IDENTIFIER: u16 = 0x2232;
const RELATION_CHALLENGE_EPOCH_CATALOG_SCHEMA_IDENTIFIER: u16 = 0x2233;
const SEMANTIC_CELL_SCHEMA_IDENTIFIER: u16 = 0x2234;
const TRINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x2235;
const BINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x2236;
const UNSIGNED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x2237;
const SHIFTED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x2238;
const RADIX_COLUMN_DIGITS_SCHEMA_IDENTIFIER: u16 = 0x2239;
const RADIX_CONSTANT_DIGITS_SCHEMA_IDENTIFIER: u16 = 0x223a;
const RADIX_SCALAR_COLUMN_SCHEMA_IDENTIFIER: u16 = 0x223b;
const RADIX_PRODUCT_TERM_SCHEMA_IDENTIFIER: u16 = 0x223c;
const RADIX_CONVOLUTION_SCHEMA_IDENTIFIER: u16 = 0x223d;
const RADIX_TRANSCRIPT_CHALLENGE_DIGITS_SCHEMA_IDENTIFIER: u16 = 0x223e;
const RADIX_NON_NATIVE_MODULUS_DIGITS_SCHEMA_IDENTIFIER: u16 = 0x223f;
const CANONICAL_MODULUS_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x2240;
const INJECTIVE_INTEGER_FACTOR_PROGRAM_SCHEMA_IDENTIFIER: u16 = 0x2241;
const FINITE_INTEGER_SET_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x2242;
const INTEGER_LIFT_LINEAR_TERM_SCHEMA_IDENTIFIER: u16 = 0x2243;
const INTEGER_LIFT_CONVOLUTION_PRODUCT_SCHEMA_IDENTIFIER: u16 = 0x2244;
const INTEGER_LIFT_COMPONENT_SCHEMA_IDENTIFIER: u16 = 0x2245;
const INTEGER_LIFT_BATCH_SCHEMA_IDENTIFIER: u16 = 0x2246;
const INTEGER_LIFT_CONSTANT_COEFFICIENT_SCHEMA_IDENTIFIER: u16 = 0x2247;
const INTEGER_LIFT_MODULUS_COEFFICIENT_SCHEMA_IDENTIFIER: u16 = 0x2248;
const INTEGER_LIFT_FULL_RING_NEGACYCLIC_PRODUCT_SCHEMA_IDENTIFIER: u16 = 0x2249;
const INTEGER_LIFT_REVERSED_COLUMN_BINDING_SCHEMA_IDENTIFIER: u16 = 0x224a;
const COEFFICIENT_LOCAL_RESIDUAL_SCHEMA_IDENTIFIER: u16 = 0x224b;
const COEFFICIENT_LOCAL_IDENTITY_BATCH_SCHEMA_IDENTIFIER: u16 = 0x224c;
const NEGACYCLIC_AUTOMORPHISM_MAPPING_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x224d;
const INTEGER_LIFT_NEGACYCLIC_AUTOMORPHISM_PERMUTATION_SCHEMA_IDENTIFIER: u16 = 0x224e;
const RADIX_DECOMPOSED_VERIFIER_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x224f;
const SCHEMA_VERSION: u16 = 1;
const RELATION_PLAN_HASH_DOMAIN: &str = "sealed-lattice/proof/relation-plan/v1";
const RELATION_PLAN_VARIANT_HASH_DOMAIN: &str = "sealed-lattice/proof/relation-plan-variant/v1";

const PUBLIC_ONLY_FAMILIES: [u16; 3] = [0x1213, 0x1215, 0x1218];
const SECRET_BEARING_FAMILIES: [u16; 9] = [
    0x1211, 0x1212, 0x1214, 0x1216, 0x1217, 0x1302, 0x1621, 0x2110, 0x2111,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationPlanError {
    CanonicalEncoding,
    UnsupportedApplicationFamily,
    InvalidVariantSelector,
    DuplicateVariant,
    InvalidDomain,
    InvalidModulus,
    MissingModulus,
    UnusedModulus,
    NonCanonicalOrder,
    DuplicateItem,
    InvalidSource,
    SourceCycle,
    UnusedSource,
    InvalidSampler,
    InvalidSemanticCell,
    InvalidSignedMagnitude,
    InvalidBoundCertificate,
    InvalidColumn,
    InvalidRoot,
    MissingRoot,
    InvalidConstraint,
    InvalidZeroifier,
    ZeroifierVanishesOnEvaluationCoset,
    DegreeBoundExceeded,
    IntegerBoundOverflow,
    NoWrapBoundViolated,
    InvalidOpening,
    InvalidChallengeCatalog,
    InvalidMaskGrammar,
    InvalidApplicationSlot,
    MissingExactNegacyclicLowering,
    CountOverflow,
}

fn canonical_encoding_error<T>(_: T) -> RelationPlanError {
    RelationPlanError::CanonicalEncoding
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub(crate) enum ModulusCatalog {
    Data = 1,
    Special = 2,
    Plaintext = 3,
    ProofField = 4,
    Target = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SuiteModulusReference {
    catalog: ModulusCatalog,
    modulus_index: u16,
}

impl SuiteModulusReference {
    pub(crate) const fn data(modulus_index: u16) -> Self {
        Self {
            catalog: ModulusCatalog::Data,
            modulus_index,
        }
    }

    pub(crate) const fn special(modulus_index: u16) -> Self {
        Self {
            catalog: ModulusCatalog::Special,
            modulus_index,
        }
    }

    pub(crate) const fn plaintext() -> Self {
        Self {
            catalog: ModulusCatalog::Plaintext,
            modulus_index: 0,
        }
    }

    pub(crate) const fn target(modulus_index: u16) -> Self {
        Self {
            catalog: ModulusCatalog::Target,
            modulus_index,
        }
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.catalog as u16),
                CanonicalItem::unsigned16(self.modulus_index),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ProofPrivacyMode {
    PublicOnly = 1,
    SecretBearing = 2,
}

impl ProofPrivacyMode {
    fn for_family(application_statement_schema_identifier: u16) -> Option<Self> {
        if PUBLIC_ONLY_FAMILIES.contains(&application_statement_schema_identifier) {
            Some(Self::PublicOnly)
        } else if SECRET_BEARING_FAMILIES.contains(&application_statement_schema_identifier) {
            Some(Self::SecretBearing)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationElementKind {
    Hash512 = 1,
    BaseField = 2,
    ChallengeExtension = 3,
    Residue = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationEmbeddingKind {
    None = 0,
    Identity = 1,
    LeastNonnegative = 2,
    Centered = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationValueLayout {
    element_kind: RelationElementKind,
    residue_modulus: Option<SuiteModulusReference>,
    shape: Vec<u64>,
    embedding_kind: RelationEmbeddingKind,
}

impl RelationValueLayout {
    fn scalar_hash() -> Self {
        Self {
            element_kind: RelationElementKind::Hash512,
            residue_modulus: None,
            shape: Vec::new(),
            embedding_kind: RelationEmbeddingKind::None,
        }
    }

    fn residue_vector(modulus: SuiteModulusReference, element_count: u64) -> Self {
        Self {
            element_kind: RelationElementKind::Residue,
            residue_modulus: Some(modulus),
            shape: vec![element_count],
            embedding_kind: RelationEmbeddingKind::LeastNonnegative,
        }
    }

    fn logical_element_count(&self) -> Result<u64, RelationPlanError> {
        self.shape.iter().try_fold(1_u64, |product, dimension| {
            if *dimension == 0 {
                return Err(RelationPlanError::InvalidSource);
            }
            product
                .checked_mul(*dimension)
                .ok_or(RelationPlanError::CountOverflow)
        })
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        let modulus_item = self
            .residue_modulus
            .map(|modulus| CanonicalItem::nested_tuple(&modulus.canonical_tuple()))
            .transpose()
            .map_err(canonical_encoding_error)?;
        Ok(CanonicalTuple::new(
            VALUE_LAYOUT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.element_kind as u16),
                CanonicalItem::optional(CanonicalItemType::NestedTuple, modulus_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                canonical_u64_list(&self.shape)?,
                CanonicalItem::unsigned16(self.embedding_kind as u16),
            ],
        ))
    }

    fn validate(&self) -> Result<(), RelationPlanError> {
        let _ = self.logical_element_count()?;
        match (
            self.element_kind,
            self.residue_modulus,
            self.embedding_kind,
            self.shape.is_empty(),
        ) {
            (RelationElementKind::Hash512, None, RelationEmbeddingKind::None, true)
            | (
                RelationElementKind::BaseField | RelationElementKind::ChallengeExtension,
                None,
                RelationEmbeddingKind::Identity,
                _,
            )
            | (
                RelationElementKind::Residue,
                Some(_),
                RelationEmbeddingKind::LeastNonnegative | RelationEmbeddingKind::Centered,
                _,
            ) => Ok(()),
            _ => Err(RelationPlanError::InvalidSource),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum SelectorPathStepKind {
    TupleField = 1,
    LiteralListIndex = 2,
    VariantSchedulePosition = 3,
    RosterPosition = 4,
    ApplicationSchedulePosition = 5,
    ProducerSequence = 6,
    StreamElement = 7,
    SuiteArtifact = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationSelectorPathStep {
    step_kind: SelectorPathStepKind,
    argument: u64,
}

impl RelationSelectorPathStep {
    const fn tuple_field(argument: u64) -> Self {
        Self {
            step_kind: SelectorPathStepKind::TupleField,
            argument,
        }
    }

    pub(crate) const fn step_kind(self) -> SelectorPathStepKind {
        self.step_kind
    }

    pub(crate) const fn argument(self) -> u64 {
        self.argument
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.step_kind as u16),
                CanonicalItem::unsigned64(self.argument),
            ],
        )
    }

    fn validate(self) -> Result<(), RelationPlanError> {
        if matches!(
            self.step_kind,
            SelectorPathStepKind::VariantSchedulePosition
                | SelectorPathStepKind::RosterPosition
                | SelectorPathStepKind::ApplicationSchedulePosition
                | SelectorPathStepKind::ProducerSequence
        ) && self.argument != 0
        {
            return Err(RelationPlanError::InvalidSource);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationVerifierSource {
    ApplicationStatement {
        value_path: Vec<RelationSelectorPathStep>,
        value_layout: RelationValueLayout,
    },
    Protocol {
        protocol_source_kind: u16,
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
    NegacyclicAutomorphismMapping {
        ring_degree: u64,
        galois_element: u64,
    },
    /// A plan-owned, deterministic view of a canonical residue source.  It
    /// emits one fixed radix digit of `scale * residue` for every source
    /// element.  The wrapped source remains the sole protocol-facing source;
    /// callers cannot supply an independently interpreted limb stream.
    RadixDecomposition {
        source: Box<RelationVerifierSource>,
        modulus_reference: SuiteModulusReference,
        scale: u64,
        radix: u64,
        digit_ordinal: u16,
        digit_count: u16,
    },
}

impl RelationVerifierSource {
    pub(crate) fn application_statement_scalar_hash_path(
        &self,
    ) -> Option<&[RelationSelectorPathStep]> {
        match self {
            Self::ApplicationStatement {
                value_path,
                value_layout,
            } if value_layout.element_kind == RelationElementKind::Hash512
                && value_layout.residue_modulus.is_none()
                && value_layout.shape.is_empty()
                && value_layout.embedding_kind == RelationEmbeddingKind::None =>
            {
                Some(value_path)
            }
            _ => None,
        }
    }

    fn value_layout<'source>(
        &'source self,
        samplers: &'source [RelationPublicSamplerDescriptor],
        sources: &'source [Self],
    ) -> Result<RelationValueLayout, RelationPlanError> {
        match self {
            Self::ApplicationStatement { value_layout, .. }
            | Self::Protocol { value_layout, .. }
            | Self::Suite { value_layout, .. }
            | Self::ApplicationSlot { value_layout, .. } => Ok(value_layout.clone()),
            Self::SamplerOutput {
                public_sampler_ordinal,
            } => {
                let sampler = samplers
                    .get(*public_sampler_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidSource)?;
                let output_source = sources
                    .get(sampler.output_verifier_source_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidSampler)?;
                if !matches!(
                    output_source,
                    Self::SamplerOutput {
                        public_sampler_ordinal: ordinal
                    } if ordinal == public_sampler_ordinal
                ) {
                    return Err(RelationPlanError::InvalidSampler);
                }
                Ok(RelationValueLayout::residue_vector(
                    sampler.output_modulus,
                    sampler.output_count,
                ))
            }
            Self::NegacyclicAutomorphismMapping { ring_degree, .. } => Ok(RelationValueLayout {
                element_kind: RelationElementKind::BaseField,
                residue_modulus: None,
                shape: vec![
                    ring_degree
                        .checked_mul(3)
                        .ok_or(RelationPlanError::CountOverflow)?,
                ],
                embedding_kind: RelationEmbeddingKind::Identity,
            }),
            Self::RadixDecomposition { source, .. } => {
                let source_layout = source.value_layout(samplers, sources)?;
                Ok(RelationValueLayout {
                    element_kind: RelationElementKind::BaseField,
                    residue_modulus: None,
                    shape: source_layout.shape,
                    embedding_kind: RelationEmbeddingKind::Identity,
                })
            }
        }
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        let (schema_identifier, items) = match self {
            Self::ApplicationStatement {
                value_path,
                value_layout,
            } => (
                APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    canonical_nested_list(value_path.iter().map(|step| step.canonical_tuple()))?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)
                        .map_err(canonical_encoding_error)?,
                ],
            ),
            Self::Protocol {
                protocol_source_kind,
                source_coordinates,
                statement_binding_path,
                value_layout,
            } => (
                PROTOCOL_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::unsigned16(*protocol_source_kind),
                    canonical_u64_list(source_coordinates)?,
                    canonical_nested_list(
                        statement_binding_path
                            .iter()
                            .map(|step| step.canonical_tuple()),
                    )?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)
                        .map_err(canonical_encoding_error)?,
                ],
            ),
            Self::Suite {
                value_path,
                value_layout,
            } => (
                SUITE_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    canonical_nested_list(value_path.iter().map(|step| step.canonical_tuple()))?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)
                        .map_err(canonical_encoding_error)?,
                ],
            ),
            Self::ApplicationSlot {
                value_path,
                value_layout,
            } => (
                APPLICATION_SLOT_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    canonical_nested_list(value_path.iter().map(|step| step.canonical_tuple()))?,
                    CanonicalItem::nested_tuple(&value_layout.canonical_tuple()?)
                        .map_err(canonical_encoding_error)?,
                ],
            ),
            Self::SamplerOutput {
                public_sampler_ordinal,
            } => (
                SAMPLER_OUTPUT_SOURCE_SCHEMA_IDENTIFIER,
                vec![CanonicalItem::unsigned32(*public_sampler_ordinal)],
            ),
            Self::NegacyclicAutomorphismMapping {
                ring_degree,
                galois_element,
            } => (
                NEGACYCLIC_AUTOMORPHISM_MAPPING_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::unsigned64(*ring_degree),
                    CanonicalItem::unsigned64(*galois_element),
                ],
            ),
            Self::RadixDecomposition {
                source,
                modulus_reference,
                scale,
                radix,
                digit_ordinal,
                digit_count,
            } => (
                RADIX_DECOMPOSED_VERIFIER_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::nested_tuple(&source.canonical_tuple()?)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned64(*scale),
                    CanonicalItem::unsigned64(*radix),
                    CanonicalItem::unsigned16(*digit_ordinal),
                    CanonicalItem::unsigned16(*digit_count),
                ],
            ),
        };
        Ok(CanonicalTuple::new(
            schema_identifier,
            SCHEMA_VERSION,
            items,
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }

    fn validate_path(path: &[RelationSelectorPathStep]) -> Result<(), RelationPlanError> {
        if path.is_empty() {
            return Err(RelationPlanError::InvalidSource);
        }
        for step in path {
            step.validate()?;
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), RelationPlanError> {
        match self {
            Self::ApplicationStatement {
                value_path,
                value_layout,
            }
            | Self::Suite {
                value_path,
                value_layout,
            }
            | Self::ApplicationSlot {
                value_path,
                value_layout,
            } => {
                Self::validate_path(value_path)?;
                value_layout.validate()
            }
            Self::Protocol {
                protocol_source_kind,
                source_coordinates,
                statement_binding_path,
                value_layout,
            } => {
                if !(1..=9).contains(protocol_source_kind) {
                    return Err(RelationPlanError::InvalidSource);
                }
                Self::validate_path(statement_binding_path)?;
                let expected_coordinate_count = match protocol_source_kind {
                    1 | 2 => 2,
                    3 => 3,
                    4 => 2,
                    5 => 4,
                    6 => 1,
                    7 | 8 => 4,
                    9 => 0,
                    _ => unreachable!(),
                };
                if source_coordinates.len() != expected_coordinate_count {
                    return Err(RelationPlanError::InvalidSource);
                }
                value_layout.validate()
            }
            Self::SamplerOutput { .. } => Ok(()),
            Self::NegacyclicAutomorphismMapping {
                ring_degree,
                galois_element,
            } => validate_negacyclic_automorphism(*ring_degree, *galois_element),
            Self::RadixDecomposition {
                source,
                modulus_reference,
                scale,
                radix,
                digit_ordinal,
                digit_count,
            } => {
                source.validate_shape()?;
                let layout = source.value_layout(&[], &[])?;
                if *scale == 0
                    || *radix < 2
                    || *digit_count == 0
                    || *digit_ordinal >= *digit_count
                    || layout.element_kind != RelationElementKind::Residue
                    || layout.residue_modulus != Some(*modulus_reference)
                    || layout.embedding_kind != RelationEmbeddingKind::LeastNonnegative
                {
                    return Err(RelationPlanError::InvalidSource);
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn radix_decompose_scaled_residues(
    residues: &[u64],
    modulus: u64,
    scale: u64,
    radix: u64,
    digit_ordinal: u16,
    digit_count: u16,
) -> Result<Vec<u64>, RelationPlanError> {
    if modulus < 3 || scale == 0 || radix < 2 || digit_count == 0 || digit_ordinal >= digit_count {
        return Err(RelationPlanError::InvalidSource);
    }
    let maximum_scaled = u128::from(modulus - 1)
        .checked_mul(u128::from(scale))
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    let capacity = (0..digit_count).try_fold(1_u128, |capacity, _| {
        capacity
            .checked_mul(u128::from(radix))
            .ok_or(RelationPlanError::IntegerBoundOverflow)
    })?;
    if maximum_scaled >= capacity {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    let divisor = (0..digit_ordinal).try_fold(1_u128, |divisor, _| {
        divisor
            .checked_mul(u128::from(radix))
            .ok_or(RelationPlanError::IntegerBoundOverflow)
    })?;
    residues
        .iter()
        .copied()
        .map(|residue| {
            if residue >= modulus {
                return Err(RelationPlanError::InvalidSource);
            }
            Ok(u64::try_from(
                (u128::from(residue) * u128::from(scale) / divisor) % u128::from(radix),
            )
            .map_err(|_| RelationPlanError::IntegerBoundOverflow)?)
        })
        .collect()
}

fn validate_negacyclic_automorphism(
    ring_degree: u64,
    galois_element: u64,
) -> Result<(), RelationPlanError> {
    let automorphism_modulus = ring_degree
        .checked_mul(2)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    if ring_degree < 4
        || !ring_degree.is_power_of_two()
        || galois_element <= 1
        || galois_element >= automorphism_modulus
        || galois_element.is_multiple_of(2)
    {
        Err(RelationPlanError::InvalidDomain)
    } else {
        Ok(())
    }
}

/// Returns the six row-major half-ring sequences used by the exact compact
/// automorphism permutation check. The verifier recomputes these values from
/// the suite-bound ring degree and Galois element; they are never witness data.
pub(crate) fn negacyclic_automorphism_mapping_values(
    ring_degree: u64,
    galois_element: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    validate_negacyclic_automorphism(ring_degree, galois_element)?;
    let half_ring_degree = ring_degree / 2;
    let automorphism_modulus = u128::from(ring_degree) * 2;
    let capacity = usize::try_from(
        ring_degree
            .checked_mul(3)
            .ok_or(RelationPlanError::CountOverflow)?,
    )
    .map_err(|_| RelationPlanError::CountOverflow)?;
    let mut mapped_low_positions = Vec::with_capacity(
        usize::try_from(half_ring_degree).map_err(|_| RelationPlanError::CountOverflow)?,
    );
    let mut low_negation_bits = Vec::with_capacity(mapped_low_positions.capacity());
    let mut mapped_high_positions = Vec::with_capacity(mapped_low_positions.capacity());
    let mut high_negation_bits = Vec::with_capacity(mapped_low_positions.capacity());
    let mut target_low_positions = Vec::with_capacity(mapped_low_positions.capacity());
    let mut target_high_positions = Vec::with_capacity(mapped_low_positions.capacity());
    for row_ordinal in 0..half_ring_degree {
        for (source_position, mapped_positions, negation_bits) in [
            (
                row_ordinal,
                &mut mapped_low_positions,
                &mut low_negation_bits,
            ),
            (
                half_ring_degree
                    .checked_add(row_ordinal)
                    .ok_or(RelationPlanError::CountOverflow)?,
                &mut mapped_high_positions,
                &mut high_negation_bits,
            ),
        ] {
            let mapped_exponent =
                (u128::from(galois_element) * u128::from(source_position)) % automorphism_modulus;
            let negated = mapped_exponent >= u128::from(ring_degree);
            let mapped_position = mapped_exponent % u128::from(ring_degree);
            mapped_positions.push(
                u64::try_from(mapped_position).map_err(|_| RelationPlanError::CountOverflow)?,
            );
            negation_bits.push(u64::from(negated));
        }
        target_low_positions.push(row_ordinal);
        target_high_positions.push(
            half_ring_degree
                .checked_add(row_ordinal)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    }
    let mut values = Vec::with_capacity(capacity);
    values.extend(mapped_low_positions);
    values.extend(low_negation_bits);
    values.extend(mapped_high_positions);
    values.extend(high_negation_bits);
    values.extend(target_low_positions);
    values.extend(target_high_positions);
    Ok(values)
}

/// Independently evaluates `X -> X^g` in `Z[X]/(X^N + 1)` for semantic
/// equivalence tests and witness construction. This does not use the compiled
/// constraint programs or their accumulator implementation.
pub(crate) fn apply_negacyclic_automorphism(
    coefficients: &[i64],
    galois_element: u64,
) -> Result<Vec<i64>, RelationPlanError> {
    let ring_degree =
        u64::try_from(coefficients.len()).map_err(|_| RelationPlanError::CountOverflow)?;
    validate_negacyclic_automorphism(ring_degree, galois_element)?;
    let automorphism_modulus = u128::from(ring_degree) * 2;
    let mut output = vec![0_i64; coefficients.len()];
    for (source_position, coefficient) in coefficients.iter().copied().enumerate() {
        let mapped_exponent = (u128::from(galois_element)
            * u128::try_from(source_position).map_err(|_| RelationPlanError::CountOverflow)?)
            % automorphism_modulus;
        let mapped_position = usize::try_from(mapped_exponent % u128::from(ring_degree))
            .map_err(|_| RelationPlanError::CountOverflow)?;
        output[mapped_position] = if mapped_exponent >= u128::from(ring_degree) {
            coefficient
                .checked_neg()
                .ok_or(RelationPlanError::IntegerBoundOverflow)?
        } else {
            coefficient
        };
    }
    Ok(output)
}

pub(crate) fn negacyclic_automorphism_semantics_match(
    source_coefficients: &[i64],
    target_coefficients: &[i64],
    galois_element: u64,
) -> Result<bool, RelationPlanError> {
    if source_coefficients.len() != target_coefficients.len() {
        return Ok(false);
    }
    apply_negacyclic_automorphism(source_coefficients, galois_element)
        .map(|expected| expected == target_coefficients)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPublicSamplerDescriptor {
    seed_verifier_source_ordinal: u32,
    role_domain: String,
    canonical_role_coordinate_bytes: Vec<u8>,
    output_modulus: SuiteModulusReference,
    output_count: u64,
    output_verifier_source_ordinal: u32,
}

impl RelationPublicSamplerDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_PUBLIC_SAMPLER_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.seed_verifier_source_ordinal),
                CanonicalItem::ascii(&self.role_domain).map_err(canonical_encoding_error)?,
                CanonicalItem::variable_bytes(&self.canonical_role_coordinate_bytes)
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::nested_tuple(&self.output_modulus.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned64(self.output_count),
                CanonicalItem::unsigned32(self.output_verifier_source_ordinal),
            ],
        ))
    }

    fn canonical_order_key(&self) -> (&str, &[u8]) {
        (&self.role_domain, &self.canonical_role_coordinate_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationColumnValueType {
    BaseField = 1,
    ChallengeExtension = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationColumnOrigin {
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
    fn canonical_tuple(&self) -> CanonicalTuple {
        match self {
            Self::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } => CanonicalTuple::new(
                VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*verifier_source_ordinal),
                    CanonicalItem::unsigned64(*first_logical_element_index),
                    CanonicalItem::unsigned64(*logical_element_stride),
                ],
            ),
            Self::BoundTree {
                expected_root_source_ordinal,
            } => CanonicalTuple::new(
                BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*expected_root_source_ordinal)],
            ),
            Self::Prover => CanonicalTuple::new(
                PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                Vec::new(),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationColumnDescriptor {
    origin: RelationColumnOrigin,
    value_type: RelationColumnValueType,
    source_degree_bound_exclusive: u64,
    canonical_residue_modulus: Option<SuiteModulusReference>,
}

impl RelationColumnDescriptor {
    pub(crate) const fn origin(&self) -> &RelationColumnOrigin {
        &self.origin
    }

    pub(crate) const fn value_type(&self) -> RelationColumnValueType {
        self.value_type
    }

    pub(crate) const fn source_degree_bound_exclusive(&self) -> u64 {
        self.source_degree_bound_exclusive
    }

    pub(crate) const fn canonical_residue_modulus(&self) -> Option<SuiteModulusReference> {
        self.canonical_residue_modulus
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_COLUMN_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.origin.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.value_type as u16),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
                canonical_nested_list(
                    self.canonical_residue_modulus
                        .map(SuiteModulusReference::canonical_tuple),
                )?,
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum BoundTreeConstructionKind {
    CommittedMaterial = 1,
    SetupPolynomial = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum BoundTreeRootUse {
    Input = 1,
    Output = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationTreeDescriptor {
    ProofCreated {
        proof_tree_role: u16,
        ordered_column_ordinals: Vec<u32>,
    },
    BoundPublic {
        construction_kind: BoundTreeConstructionKind,
        expected_root_source_ordinal: u32,
        root_use: BoundTreeRootUse,
        ordered_column_ordinals: Vec<u32>,
    },
}

impl RelationTreeDescriptor {
    pub(crate) fn ordered_column_ordinals(&self) -> &[u32] {
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

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => CanonicalTuple::new(
                PROOF_CREATED_TREE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*proof_tree_role),
                    canonical_u32_list(ordered_column_ordinals)?,
                ],
            ),
            Self::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                root_use,
                ordered_column_ordinals,
            } => CanonicalTuple::new(
                BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*construction_kind as u16),
                    CanonicalItem::unsigned32(*expected_root_source_ordinal),
                    CanonicalItem::unsigned16(*root_use as u16),
                    canonical_u32_list(ordered_column_ordinals)?,
                ],
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum RelationChallengeRole {
    NonNativeTheta = 1,
    NonNativeAlpha = 2,
    ConstraintComposition = 3,
    DeepPoint = 4,
    OpeningBatch = 5,
    FriFold = 6,
    QueryPosition = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationChallengeModulusSelector {
    BaseField,
    NonNativeModulusOrdinal(u16),
    QueryOrbitCount,
}

impl RelationChallengeModulusSelector {
    fn canonical_tuple(self) -> CanonicalTuple {
        let (selector_kind, selector_ordinal) = match self {
            Self::BaseField => (1, 0),
            Self::NonNativeModulusOrdinal(modulus_ordinal) => (2, modulus_ordinal),
            Self::QueryOrbitCount => (3, 0),
        };
        CanonicalTuple::new(
            RELATION_CHALLENGE_MODULUS_SELECTOR_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(selector_kind),
                CanonicalItem::unsigned16(selector_ordinal),
            ],
        )
    }

    fn resolve(
        self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<u64, RelationPlanError> {
        match self {
            Self::BaseField => Ok(context.base_field_modulus),
            Self::NonNativeModulusOrdinal(modulus_ordinal) => variant
                .ordered_non_native_moduli
                .get(usize::from(modulus_ordinal))
                .copied()
                .ok_or(RelationPlanError::InvalidChallengeCatalog)
                .and_then(|reference| context.resolved_modulus(reference)),
            Self::QueryOrbitCount => variant
                .evaluation_domain_size
                .checked_div(2)
                .filter(|count| *count > 0)
                .ok_or(RelationPlanError::InvalidChallengeCatalog),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationChallengeSampling {
    IndependentResidues {
        modulus_selector: RelationChallengeModulusSelector,
        coordinate_count: u16,
        maximum_candidate_draws_per_output: u32,
    },
    ProductResidueVectorCoordinate {
        modulus_selector: RelationChallengeModulusSelector,
        coordinate_count: u16,
        maximum_candidate_draws_per_output: u32,
    },
    PowerOfProductResidueVectorCoordinate {
        modulus_selector: RelationChallengeModulusSelector,
        coordinate_count: u16,
        maximum_candidate_draws_per_output: u32,
    },
    NonzeroExtensionVectors {
        base_modulus_selector: RelationChallengeModulusSelector,
        coordinate_count: u16,
        maximum_candidate_draws_per_output: u32,
    },
    DistinctPositions {
        position_count_selector: RelationChallengeModulusSelector,
        maximum_candidate_draws_per_output: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedRelationChallengeSampling {
    pub(crate) coordinate_modulus: u64,
    pub(crate) coordinate_count: u16,
    pub(crate) output_count: u32,
    pub(crate) maximum_candidate_draws_per_output: u32,
    pub(crate) reject_zero_vector: bool,
    pub(crate) require_distinct_outputs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationChallengeDescriptor {
    pub(crate) epoch: u16,
    pub(crate) role: RelationChallengeRole,
    pub(crate) role_coordinates: Vec<u64>,
    pub(crate) value_count: u32,
    pub(crate) sampling: RelationChallengeSampling,
}

impl RelationChallengeDescriptor {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_CHALLENGE_DESCRIPTOR_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.epoch),
                CanonicalItem::unsigned16(self.role as u16),
                canonical_u64_list(&self.role_coordinates)?,
                CanonicalItem::unsigned32(self.value_count),
                CanonicalItem::unsigned16(self.sampling_kind()),
                CanonicalItem::nested_tuple(&self.modulus_selector().canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.coordinate_count()),
                CanonicalItem::unsigned32(self.maximum_candidate_draws_per_output()),
            ],
        ))
    }

    pub(crate) fn resolved_sampling(
        &self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<ResolvedRelationChallengeSampling, RelationPlanError> {
        self.validate(variant, context)?;
        Ok(ResolvedRelationChallengeSampling {
            coordinate_modulus: self.modulus_selector().resolve(variant, context)?,
            coordinate_count: self.coordinate_count(),
            output_count: self.value_count,
            maximum_candidate_draws_per_output: self.maximum_candidate_draws_per_output(),
            reject_zero_vector: matches!(
                self.sampling,
                RelationChallengeSampling::NonzeroExtensionVectors { .. }
            ),
            require_distinct_outputs: matches!(
                self.sampling,
                RelationChallengeSampling::DistinctPositions { .. }
            ),
        })
    }

    fn sampling_kind(&self) -> u16 {
        match self.sampling {
            RelationChallengeSampling::IndependentResidues { .. } => 1,
            RelationChallengeSampling::NonzeroExtensionVectors { .. } => 2,
            RelationChallengeSampling::DistinctPositions { .. } => 3,
            RelationChallengeSampling::ProductResidueVectorCoordinate { .. } => 4,
            RelationChallengeSampling::PowerOfProductResidueVectorCoordinate { .. } => 5,
        }
    }

    fn modulus_selector(&self) -> RelationChallengeModulusSelector {
        match self.sampling {
            RelationChallengeSampling::IndependentResidues {
                modulus_selector, ..
            }
            | RelationChallengeSampling::ProductResidueVectorCoordinate {
                modulus_selector, ..
            }
            | RelationChallengeSampling::PowerOfProductResidueVectorCoordinate {
                modulus_selector,
                ..
            } => modulus_selector,
            RelationChallengeSampling::NonzeroExtensionVectors {
                base_modulus_selector,
                ..
            } => base_modulus_selector,
            RelationChallengeSampling::DistinctPositions {
                position_count_selector,
                ..
            } => position_count_selector,
        }
    }

    fn coordinate_count(&self) -> u16 {
        match self.sampling {
            RelationChallengeSampling::IndependentResidues {
                coordinate_count, ..
            }
            | RelationChallengeSampling::ProductResidueVectorCoordinate {
                coordinate_count, ..
            }
            | RelationChallengeSampling::PowerOfProductResidueVectorCoordinate {
                coordinate_count,
                ..
            }
            | RelationChallengeSampling::NonzeroExtensionVectors {
                coordinate_count, ..
            } => coordinate_count,
            RelationChallengeSampling::DistinctPositions { .. } => 1,
        }
    }

    fn maximum_candidate_draws_per_output(&self) -> u32 {
        match self.sampling {
            RelationChallengeSampling::IndependentResidues {
                maximum_candidate_draws_per_output,
                ..
            }
            | RelationChallengeSampling::ProductResidueVectorCoordinate {
                maximum_candidate_draws_per_output,
                ..
            }
            | RelationChallengeSampling::PowerOfProductResidueVectorCoordinate {
                maximum_candidate_draws_per_output,
                ..
            }
            | RelationChallengeSampling::NonzeroExtensionVectors {
                maximum_candidate_draws_per_output,
                ..
            }
            | RelationChallengeSampling::DistinctPositions {
                maximum_candidate_draws_per_output,
                ..
            } => maximum_candidate_draws_per_output,
        }
    }

    fn validate(
        &self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        let expected_coordinate_count = match self.role {
            RelationChallengeRole::NonNativeTheta => 2,
            RelationChallengeRole::NonNativeAlpha => 3,
            RelationChallengeRole::ConstraintComposition
            | RelationChallengeRole::DeepPoint
            | RelationChallengeRole::OpeningBatch
            | RelationChallengeRole::FriFold
            | RelationChallengeRole::QueryPosition => 1,
        };
        if self.value_count == 0
            || self.role_coordinates.len() != expected_coordinate_count
            || self.coordinate_count() == 0
            || self.maximum_candidate_draws_per_output()
                != context.maximum_fiat_shamir_candidate_draws_per_output
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let resolved_modulus = self.modulus_selector().resolve(variant, context)?;
        if resolved_modulus < 2
            || matches!(
                self.role,
                RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha
            ) && BigUint::from(resolved_modulus).pow(u32::from(
                context.non_native_modular_identity_challenge_count,
            )) >= (BigUint::one() << 512_usize)
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let expected_epoch = match self.role {
            RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha => 1,
            RelationChallengeRole::ConstraintComposition => 2,
            RelationChallengeRole::DeepPoint => 3,
            RelationChallengeRole::OpeningBatch => 4,
            RelationChallengeRole::FriFold => 4_u16
                .checked_add(
                    self.role_coordinates
                        .first()
                        .copied()
                        .and_then(|ordinal| u16::try_from(ordinal).ok())
                        .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
                )
                .ok_or(RelationPlanError::CountOverflow)?,
            RelationChallengeRole::QueryPosition => 4_u16
                .checked_add(context.fri_fold_count)
                .ok_or(RelationPlanError::CountOverflow)?,
        };
        let expected_sampling = match self.role {
            RelationChallengeRole::NonNativeTheta => {
                let modulus_ordinal = self
                    .role_coordinates
                    .first()
                    .copied()
                    .and_then(|ordinal| u16::try_from(ordinal).ok())
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                RelationChallengeSampling::ProductResidueVectorCoordinate {
                    modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(
                        modulus_ordinal,
                    ),
                    coordinate_count: context.non_native_modular_identity_challenge_count,
                    maximum_candidate_draws_per_output: context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                }
            }
            RelationChallengeRole::NonNativeAlpha => {
                let modulus_ordinal = self
                    .role_coordinates
                    .first()
                    .copied()
                    .and_then(|ordinal| u16::try_from(ordinal).ok())
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                RelationChallengeSampling::PowerOfProductResidueVectorCoordinate {
                    modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(
                        modulus_ordinal,
                    ),
                    coordinate_count: context.non_native_modular_identity_challenge_count,
                    maximum_candidate_draws_per_output: context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                }
            }
            RelationChallengeRole::ConstraintComposition
            | RelationChallengeRole::OpeningBatch
            | RelationChallengeRole::FriFold => RelationChallengeSampling::IndependentResidues {
                modulus_selector: RelationChallengeModulusSelector::BaseField,
                coordinate_count: context.challenge_extension_degree,
                maximum_candidate_draws_per_output: context
                    .maximum_fiat_shamir_candidate_draws_per_output,
            },
            RelationChallengeRole::DeepPoint => {
                RelationChallengeSampling::NonzeroExtensionVectors {
                    base_modulus_selector: RelationChallengeModulusSelector::BaseField,
                    coordinate_count: context.challenge_extension_degree,
                    maximum_candidate_draws_per_output: context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                }
            }
            RelationChallengeRole::QueryPosition => RelationChallengeSampling::DistinctPositions {
                position_count_selector: RelationChallengeModulusSelector::QueryOrbitCount,
                maximum_candidate_draws_per_output: context
                    .maximum_fiat_shamir_candidate_draws_per_output,
            },
        };
        let coordinates_and_count_are_valid = match self.role {
            RelationChallengeRole::NonNativeTheta => {
                self.role_coordinates[1]
                    < u64::from(context.non_native_modular_identity_challenge_count)
                    && self.value_count == 1
            }
            RelationChallengeRole::NonNativeAlpha => {
                self.role_coordinates[1]
                    < u64::from(context.non_native_modular_identity_challenge_count)
                    && self.value_count == 1
            }
            RelationChallengeRole::ConstraintComposition => {
                self.role_coordinates[0] < variant.ordered_constraints.len() as u64
                    && self.value_count == 1
            }
            RelationChallengeRole::DeepPoint => {
                self.role_coordinates[0] < u64::from(context.deep_point_count)
                    && self.value_count == 1
            }
            RelationChallengeRole::OpeningBatch => {
                self.role_coordinates[0] == 0
                    && self.value_count as usize == variant.ordered_opening_claims.len()
            }
            RelationChallengeRole::FriFold => {
                self.role_coordinates[0] < u64::from(context.fri_fold_count)
                    && self.value_count == 1
            }
            RelationChallengeRole::QueryPosition => {
                self.role_coordinates[0] == 0 && self.value_count == context.unique_query_count
            }
        };
        if self.epoch != expected_epoch
            || self.sampling != expected_sampling
            || !coordinates_and_count_are_valid
            || matches!(self.role, RelationChallengeRole::QueryPosition)
                && u64::from(self.value_count) > resolved_modulus
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationChallengeEpochPrecedingMessage {
    BaseRoots,
    AuxiliaryRoots,
    QuotientRoots,
    DeepValuesAndOpeningBatchMask,
    FriLayerRoot(u16),
    FriTerminal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationChallengeEpochCatalog {
    pub(crate) epoch: u16,
    pub(crate) preceding_message: RelationChallengeEpochPrecedingMessage,
    pub(crate) ordered_descriptors: Vec<RelationChallengeDescriptor>,
}

impl RelationChallengeEpochCatalog {
    pub(crate) fn canonical_descriptor_bytes(&self) -> Result<Vec<Vec<u8>>, RelationPlanError> {
        self.ordered_descriptors
            .iter()
            .map(RelationChallengeDescriptor::canonical_bytes)
            .collect()
    }

    pub(crate) fn canonical_catalog_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        let tuple = CanonicalTuple::new(
            RELATION_CHALLENGE_EPOCH_CATALOG_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.epoch),
                canonical_nested_list(
                    self.ordered_descriptors
                        .iter()
                        .map(RelationChallengeDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        );
        encode_generated_tuple(&tuple)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationRadixFactorDescriptor {
    ColumnDigits {
        ordered_column_ordinals: Vec<u32>,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
    },
    ConstantDigits {
        ordered_digits: Vec<u64>,
    },
    TranscriptChallengeDigits {
        challenge_role: RelationChallengeRole,
        role_coordinates: Vec<u64>,
        digit_count: u16,
    },
    NonNativeModulusDigits {
        modulus_reference: SuiteModulusReference,
        multiplier: u16,
        digit_count: u16,
    },
    ScalarColumn {
        column_ordinal: u32,
        complement_binary_value: bool,
    },
}

impl RelationRadixFactorDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::ColumnDigits {
                ordered_column_ordinals,
                rotation_is_negative,
                rotation_magnitude,
            } => CanonicalTuple::new(
                RADIX_COLUMN_DIGITS_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    canonical_u32_list(ordered_column_ordinals)?,
                    CanonicalItem::unsigned8(u8::from(*rotation_is_negative)),
                    CanonicalItem::unsigned64(*rotation_magnitude),
                ],
            ),
            Self::ConstantDigits { ordered_digits } => CanonicalTuple::new(
                RADIX_CONSTANT_DIGITS_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![canonical_u64_list(ordered_digits)?],
            ),
            Self::TranscriptChallengeDigits {
                challenge_role,
                role_coordinates,
                digit_count,
            } => CanonicalTuple::new(
                RADIX_TRANSCRIPT_CHALLENGE_DIGITS_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*challenge_role as u16),
                    canonical_u64_list(role_coordinates)?,
                    CanonicalItem::unsigned16(*digit_count),
                ],
            ),
            Self::NonNativeModulusDigits {
                modulus_reference,
                multiplier,
                digit_count,
            } => CanonicalTuple::new(
                RADIX_NON_NATIVE_MODULUS_DIGITS_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(*multiplier),
                    CanonicalItem::unsigned16(*digit_count),
                ],
            ),
            Self::ScalarColumn {
                column_ordinal,
                complement_binary_value,
            } => CanonicalTuple::new(
                RADIX_SCALAR_COLUMN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*column_ordinal),
                    CanonicalItem::boolean(*complement_binary_value),
                ],
            ),
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationRadixProductTermDescriptor {
    negative: bool,
    ordered_factors: Vec<RelationRadixFactorDescriptor>,
}

impl RelationRadixProductTermDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RADIX_PRODUCT_TERM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                canonical_nested_list(
                    self.ordered_factors
                        .iter()
                        .map(RelationRadixFactorDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationRadixConvolutionDescriptor {
    radix: u64,
    ordered_terms: Vec<RelationRadixProductTermDescriptor>,
}

impl RelationRadixConvolutionDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RADIX_CONVOLUTION_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.radix),
                canonical_nested_list(
                    self.ordered_terms
                        .iter()
                        .map(RelationRadixProductTermDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationExpressionInstruction {
    BaseFieldConstant(u64),
    NonNativeModulusConstant {
        modulus_reference: SuiteModulusReference,
        multiplier: u16,
    },
    EvaluationVariable,
    ColumnValue {
        column_ordinal: u32,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
    },
    TranscriptChallenge {
        challenge_role: RelationChallengeRole,
        role_coordinates: Vec<u64>,
    },
    Addition,
    Multiplication,
    Negation,
    NonnegativePower(u64),
    FrobeniusConjugate(u16),
    RadixConvolutionCoefficient {
        convolution_ordinal: u32,
        coefficient_ordinal: u32,
    },
    TraceDomainExceptRoots {
        trace_domain_size: u64,
        ordered_excluded_roots: Vec<u64>,
    },
}

impl RelationExpressionInstruction {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::BaseFieldConstant(value) => CanonicalTuple::new(
                BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::from_canonical_bytes(
                        CanonicalItemType::FieldElement,
                        value.to_le_bytes().to_vec(),
                        &CanonicalDecodeLimits::default(),
                    )
                    .map_err(canonical_encoding_error)?,
                ],
            ),
            Self::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } => CanonicalTuple::new(
                NON_NATIVE_MODULUS_CONSTANT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(*multiplier),
                ],
            ),
            Self::EvaluationVariable => CanonicalTuple::new(
                EVALUATION_VARIABLE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                Vec::new(),
            ),
            Self::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => CanonicalTuple::new(
                COLUMN_VALUE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
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
                TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*challenge_role as u16),
                    canonical_u64_list(role_coordinates)?,
                ],
            ),
            Self::Addition => {
                CanonicalTuple::new(ADDITION_SCHEMA_IDENTIFIER, SCHEMA_VERSION, Vec::new())
            }
            Self::Multiplication => {
                CanonicalTuple::new(MULTIPLICATION_SCHEMA_IDENTIFIER, SCHEMA_VERSION, Vec::new())
            }
            Self::Negation => {
                CanonicalTuple::new(NEGATION_SCHEMA_IDENTIFIER, SCHEMA_VERSION, Vec::new())
            }
            Self::NonnegativePower(exponent) => CanonicalTuple::new(
                NONNEGATIVE_POWER_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned64(*exponent)],
            ),
            Self::FrobeniusConjugate(conjugate_index) => CanonicalTuple::new(
                FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned16(*conjugate_index)],
            ),
            Self::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } => CanonicalTuple::new(
                RADIX_CONVOLUTION_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*convolution_ordinal),
                    CanonicalItem::unsigned32(*coefficient_ordinal),
                ],
            ),
            Self::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } => CanonicalTuple::new(
                TRACE_DOMAIN_EXCEPT_ROOTS_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned64(*trace_domain_size),
                    canonical_u64_list(ordered_excluded_roots)?,
                ],
            ),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SignedIntegerInterval {
    minimum: BigInt,
    maximum: BigInt,
}

impl SignedIntegerInterval {
    fn new(minimum: i128, maximum: i128) -> Self {
        Self {
            minimum: BigInt::from(minimum),
            maximum: BigInt::from(maximum),
        }
    }

    fn from_bigints(minimum: BigInt, maximum: BigInt) -> Result<Self, RelationPlanError> {
        if minimum > maximum {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
        Ok(Self { minimum, maximum })
    }

    fn canonical_items(&self) -> Result<[CanonicalItem; 2], RelationPlanError> {
        Ok([
            CanonicalItem::nested_tuple(&canonical_signed_integer_tuple(&self.minimum)?)
                .map_err(canonical_encoding_error)?,
            CanonicalItem::nested_tuple(&canonical_signed_integer_tuple(&self.maximum)?)
                .map_err(canonical_encoding_error)?,
        ])
    }

    fn add(self, other: Self) -> Result<Self, RelationPlanError> {
        Self::from_bigints(self.minimum + other.minimum, self.maximum + other.maximum)
    }

    fn multiply(self, other: Self) -> Result<Self, RelationPlanError> {
        let products = [
            &self.minimum * &other.minimum,
            &self.minimum * &other.maximum,
            &self.maximum * &other.minimum,
            &self.maximum * &other.maximum,
        ];
        Self::from_bigints(
            products
                .iter()
                .min()
                .cloned()
                .ok_or(RelationPlanError::InvalidConstraint)?,
            products
                .iter()
                .max()
                .cloned()
                .ok_or(RelationPlanError::InvalidConstraint)?,
        )
    }

    fn negate(self) -> Result<Self, RelationPlanError> {
        Self::from_bigints(-self.maximum, -self.minimum)
    }

    fn power(self, exponent: u64) -> Result<Self, RelationPlanError> {
        if exponent == 0 {
            return Ok(Self::new(1, 1));
        }
        let mut result = Self::new(1, 1);
        let mut base = self;
        let mut remaining = exponent;
        while remaining > 0 {
            if remaining & 1 == 1 {
                result = result.multiply(base.clone())?;
            }
            remaining >>= 1;
            if remaining > 0 {
                base = base.clone().multiply(base)?;
            }
        }
        Ok(result)
    }

    fn is_injective_modulo(&self, modulus: &BigInt) -> bool {
        self.minimum > -modulus.clone() && self.maximum < modulus.clone()
    }
}

fn canonical_signed_integer_tuple(value: &BigInt) -> Result<CanonicalTuple, RelationPlanError> {
    let (sign, mut magnitude) = value.to_bytes_be();
    if value.is_zero() {
        magnitude.clear();
    }
    let sign_code = match sign {
        Sign::Minus => 1,
        Sign::NoSign | Sign::Plus => 0,
    };
    validate_signed_magnitude(sign_code, &magnitude)?;
    Ok(CanonicalTuple::new(
        SIGNED_INTEGER_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned8(sign_code),
            CanonicalItem::variable_bytes(magnitude).map_err(canonical_encoding_error)?,
        ],
    ))
}

#[cfg(test)]
fn signed_integer_from_magnitude(
    sign_code: u8,
    magnitude: &[u8],
) -> Result<BigInt, RelationPlanError> {
    validate_signed_magnitude(sign_code, magnitude)?;
    Ok(if magnitude.is_empty() {
        BigInt::zero()
    } else if sign_code == 1 {
        -BigInt::from_bytes_be(Sign::Plus, magnitude)
    } else {
        BigInt::from_bytes_be(Sign::Plus, magnitude)
    })
}

fn validate_signed_magnitude(sign_code: u8, magnitude: &[u8]) -> Result<(), RelationPlanError> {
    if sign_code > 1
        || (!magnitude.is_empty() && magnitude[0] == 0)
        || (sign_code == 1 && magnitude.is_empty())
    {
        return Err(RelationPlanError::InvalidSignedMagnitude);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationBoundCertificate {
    Trinary {
        constraint_ordinal: u32,
    },
    Binary {
        constraint_ordinal: u32,
    },
    UnsignedRadixRecomposition {
        constraint_ordinal: u32,
        radix: u64,
        ordered_digit_column_ordinals: Vec<u32>,
    },
    ShiftedRadixRecomposition {
        constraint_ordinal: u32,
        radix: u64,
        offset: BigUint,
        ordered_digit_column_ordinals: Vec<u32>,
    },
    CanonicalModulusRecomposition {
        recomposition_constraint_ordinal: u32,
        modulus_reference: SuiteModulusReference,
        radix: u64,
        ordered_digit_column_ordinals: Vec<u32>,
        ordered_comparator_constraint_ordinals: Vec<u32>,
        ordered_difference_digit_column_ordinals: Vec<u32>,
        ordered_borrow_column_ordinals: Vec<u32>,
    },
    FiniteIntegerSet {
        constraint_ordinal: u32,
        ordered_values: Vec<BigInt>,
    },
}

impl RelationBoundCertificate {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::Trinary { constraint_ordinal } => CanonicalTuple::new(
                TRINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*constraint_ordinal)],
            ),
            Self::Binary { constraint_ordinal } => CanonicalTuple::new(
                BINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*constraint_ordinal)],
            ),
            Self::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix,
                ordered_digit_column_ordinals,
            } => CanonicalTuple::new(
                UNSIGNED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*constraint_ordinal),
                    CanonicalItem::unsigned64(*radix),
                    canonical_u32_list(ordered_digit_column_ordinals)?,
                ],
            ),
            Self::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix,
                offset,
                ordered_digit_column_ordinals,
            } => CanonicalTuple::new(
                SHIFTED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*constraint_ordinal),
                    CanonicalItem::unsigned64(*radix),
                    canonical_unsigned_magnitude_item(offset)?,
                    canonical_u32_list(ordered_digit_column_ordinals)?,
                ],
            ),
            Self::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                modulus_reference,
                radix,
                ordered_digit_column_ordinals,
                ordered_comparator_constraint_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
            } => CanonicalTuple::new(
                CANONICAL_MODULUS_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*recomposition_constraint_ordinal),
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned64(*radix),
                    canonical_u32_list(ordered_digit_column_ordinals)?,
                    canonical_u32_list(ordered_comparator_constraint_ordinals)?,
                    canonical_u32_list(ordered_difference_digit_column_ordinals)?,
                    canonical_u32_list(ordered_borrow_column_ordinals)?,
                ],
            ),
            Self::FiniteIntegerSet {
                constraint_ordinal,
                ordered_values,
            } => CanonicalTuple::new(
                FINITE_INTEGER_SET_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*constraint_ordinal),
                    canonical_nested_list(
                        ordered_values
                            .iter()
                            .map(canonical_signed_integer_tuple)
                            .collect::<Result<Vec<_>, _>>()?,
                    )?,
                ],
            ),
        })
    }

    fn constraint_ordinal(&self) -> u32 {
        match self {
            Self::Trinary { constraint_ordinal }
            | Self::Binary { constraint_ordinal }
            | Self::UnsignedRadixRecomposition {
                constraint_ordinal, ..
            }
            | Self::ShiftedRadixRecomposition {
                constraint_ordinal, ..
            } => *constraint_ordinal,
            Self::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                ..
            } => *recomposition_constraint_ordinal,
            Self::FiniteIntegerSet {
                constraint_ordinal, ..
            } => *constraint_ordinal,
        }
    }
}

fn canonical_unsigned_magnitude_item(value: &BigUint) -> Result<CanonicalItem, RelationPlanError> {
    let mut magnitude = value.to_bytes_be();
    if value.is_zero() {
        magnitude.clear();
    }
    if !magnitude.is_empty() && magnitude[0] == 0 {
        return Err(RelationPlanError::InvalidSignedMagnitude);
    }
    CanonicalItem::variable_bytes(magnitude).map_err(canonical_encoding_error)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SemanticCellDescriptor {
    semantic_cell_ordinal: u32,
    column_ordinal: u32,
    claimed_interval: SignedIntegerInterval,
    bound_certificate: RelationBoundCertificate,
}

impl SemanticCellDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        let [minimum, maximum] = self.claimed_interval.canonical_items()?;
        Ok(CanonicalTuple::new(
            SEMANTIC_CELL_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.semantic_cell_ordinal),
                CanonicalItem::unsigned32(self.column_ordinal),
                minimum,
                maximum,
                CanonicalItem::nested_tuple(&self.bound_certificate.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationConstraintDescriptor {
    constraint_role: u16,
    role_coordinates: Vec<u64>,
    numerator_postfix_expression: Vec<RelationExpressionInstruction>,
    zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
    enforce_proof_base_field_no_wrap: bool,
    ordered_injective_integer_factor_expressions: Vec<Vec<RelationExpressionInstruction>>,
}

impl RelationConstraintDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_CONSTRAINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.constraint_role),
                canonical_u64_list(&self.role_coordinates)?,
                canonical_nested_list(
                    self.numerator_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.zeroifier_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                CanonicalItem::boolean(self.enforce_proof_base_field_no_wrap),
                canonical_nested_list(
                    self.ordered_injective_integer_factor_expressions
                        .iter()
                        .map(|factor_expression| {
                            Ok(CanonicalTuple::new(
                                INJECTIVE_INTEGER_FACTOR_PROGRAM_SCHEMA_IDENTIFIER,
                                SCHEMA_VERSION,
                                vec![canonical_nested_list(
                                    factor_expression
                                        .iter()
                                        .map(RelationExpressionInstruction::canonical_tuple)
                                        .collect::<Result<Vec<_>, _>>()?,
                                )?],
                            ))
                        })
                        .collect::<Result<Vec<_>, RelationPlanError>>()?,
                )?,
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationIntegerLiftCoefficient {
    Constant(u64),
    Modulus {
        modulus_reference: SuiteModulusReference,
        multiplier: u16,
    },
}

impl RelationIntegerLiftCoefficient {
    fn canonical_tuple(self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::Constant(value) => CanonicalTuple::new(
                INTEGER_LIFT_CONSTANT_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned64(value)],
            ),
            Self::Modulus {
                modulus_reference,
                multiplier,
            } => CanonicalTuple::new(
                INTEGER_LIFT_MODULUS_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(multiplier),
                ],
            ),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftLinearTermDescriptor {
    pub(crate) negative: bool,
    pub(crate) column_ordinal: u32,
    pub(crate) column_offset: u64,
    pub(crate) coefficient: RelationIntegerLiftCoefficient,
}

impl RelationIntegerLiftLinearTermDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            INTEGER_LIFT_LINEAR_TERM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                CanonicalItem::unsigned32(self.column_ordinal),
                CanonicalItem::unsigned64(self.column_offset),
                CanonicalItem::nested_tuple(&self.coefficient.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
            ],
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationIntegerLiftConvolutionKind {
    Negacyclic = 1,
    OrdinaryLowHalf = 2,
    OrdinaryHighHalf = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftConvolutionProductDescriptor {
    pub(crate) negative: bool,
    pub(crate) convolution_kind: RelationIntegerLiftConvolutionKind,
    pub(crate) multiplicand_column_ordinal: u32,
    pub(crate) reversed_multiplier_column_ordinal: u32,
    pub(crate) multiplier_offset: u64,
    pub(crate) suffix_evaluation_column_ordinal: u32,
    pub(crate) reversed_transpose_column_ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationIntegerLiftFullRingHalf {
    Low = 1,
    High = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftFullRingNegacyclicProductDescriptor {
    pub(crate) negative: bool,
    pub(crate) selected_half: RelationIntegerLiftFullRingHalf,
    pub(crate) multiplicand_low_column_ordinal: u32,
    pub(crate) multiplicand_high_column_ordinal: u32,
    pub(crate) multiplier_low_column_ordinal: u32,
    pub(crate) multiplier_high_column_ordinal: u32,
    pub(crate) reversed_multiplier_low_column_ordinal: u32,
    pub(crate) reversed_multiplier_high_column_ordinal: u32,
    pub(crate) multiplier_low_offset: u64,
    pub(crate) multiplier_high_offset: u64,
    pub(crate) multiplicand_low_suffix_evaluation_column_ordinal: u32,
    pub(crate) multiplicand_high_suffix_evaluation_column_ordinal: u32,
    pub(crate) reversed_multiplier_low_transpose_column_ordinal: u32,
    pub(crate) reversed_multiplier_high_transpose_column_ordinal: u32,
}

impl RelationIntegerLiftFullRingNegacyclicProductDescriptor {
    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_FULL_RING_NEGACYCLIC_PRODUCT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                CanonicalItem::unsigned16(self.selected_half as u16),
                CanonicalItem::unsigned32(self.multiplicand_low_column_ordinal),
                CanonicalItem::unsigned32(self.multiplicand_high_column_ordinal),
                CanonicalItem::unsigned32(self.multiplier_low_column_ordinal),
                CanonicalItem::unsigned32(self.multiplier_high_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_low_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_high_column_ordinal),
                CanonicalItem::unsigned64(self.multiplier_low_offset),
                CanonicalItem::unsigned64(self.multiplier_high_offset),
                CanonicalItem::unsigned32(self.multiplicand_low_suffix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.multiplicand_high_suffix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_low_transpose_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_high_transpose_column_ordinal),
            ],
        )
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftReversedColumnBindingDescriptor {
    pub(crate) source_column_ordinal: u32,
    pub(crate) reversed_column_ordinal: u32,
    pub(crate) source_prefix_evaluation_column_ordinal: u32,
    pub(crate) reversed_suffix_evaluation_column_ordinal: u32,
}

impl RelationIntegerLiftReversedColumnBindingDescriptor {
    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_REVERSED_COLUMN_BINDING_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.source_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_column_ordinal),
                CanonicalItem::unsigned32(self.source_prefix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_suffix_evaluation_column_ordinal),
            ],
        )
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor {
    pub(crate) galois_element: u64,
    pub(crate) mapping_verifier_source_ordinal: u32,
    pub(crate) source_low_column_ordinal: u32,
    pub(crate) source_high_column_ordinal: u32,
    pub(crate) target_low_column_ordinal: u32,
    pub(crate) target_high_column_ordinal: u32,
    pub(crate) mapped_low_position_column_ordinal: u32,
    pub(crate) low_negation_bit_column_ordinal: u32,
    pub(crate) mapped_high_position_column_ordinal: u32,
    pub(crate) high_negation_bit_column_ordinal: u32,
    pub(crate) target_low_position_column_ordinal: u32,
    pub(crate) target_high_position_column_ordinal: u32,
    pub(crate) source_product_before_column_ordinal: u32,
    pub(crate) source_low_product_column_ordinal: u32,
    pub(crate) target_product_before_column_ordinal: u32,
    pub(crate) target_low_product_column_ordinal: u32,
}

impl RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor {
    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_NEGACYCLIC_AUTOMORPHISM_PERMUTATION_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.galois_element),
                CanonicalItem::unsigned32(self.mapping_verifier_source_ordinal),
                CanonicalItem::unsigned32(self.source_low_column_ordinal),
                CanonicalItem::unsigned32(self.source_high_column_ordinal),
                CanonicalItem::unsigned32(self.target_low_column_ordinal),
                CanonicalItem::unsigned32(self.target_high_column_ordinal),
                CanonicalItem::unsigned32(self.mapped_low_position_column_ordinal),
                CanonicalItem::unsigned32(self.low_negation_bit_column_ordinal),
                CanonicalItem::unsigned32(self.mapped_high_position_column_ordinal),
                CanonicalItem::unsigned32(self.high_negation_bit_column_ordinal),
                CanonicalItem::unsigned32(self.target_low_position_column_ordinal),
                CanonicalItem::unsigned32(self.target_high_position_column_ordinal),
                CanonicalItem::unsigned32(self.source_product_before_column_ordinal),
                CanonicalItem::unsigned32(self.source_low_product_column_ordinal),
                CanonicalItem::unsigned32(self.target_product_before_column_ordinal),
                CanonicalItem::unsigned32(self.target_low_product_column_ordinal),
            ],
        )
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

impl RelationIntegerLiftConvolutionProductDescriptor {
    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_CONVOLUTION_PRODUCT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                CanonicalItem::unsigned16(self.convolution_kind as u16),
                CanonicalItem::unsigned32(self.multiplicand_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_column_ordinal),
                CanonicalItem::unsigned64(self.multiplier_offset),
                CanonicalItem::unsigned32(self.suffix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_transpose_column_ordinal),
            ],
        )
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftComponentDescriptor {
    pub(crate) quotient_is_negative: bool,
    pub(crate) quotient_column_ordinal: u32,
    pub(crate) ordered_linear_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
    pub(crate) ordered_convolution_products: Vec<RelationIntegerLiftConvolutionProductDescriptor>,
    pub(crate) ordered_full_ring_negacyclic_products:
        Vec<RelationIntegerLiftFullRingNegacyclicProductDescriptor>,
    pub(crate) linear_evaluation_column_ordinal: u32,
    pub(crate) product_accumulator_column_ordinal: u32,
}

impl RelationIntegerLiftComponentDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            INTEGER_LIFT_COMPONENT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.quotient_is_negative),
                CanonicalItem::unsigned32(self.quotient_column_ordinal),
                canonical_nested_list(
                    self.ordered_linear_terms
                        .iter()
                        .map(RelationIntegerLiftLinearTermDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_convolution_products
                        .iter()
                        .map(RelationIntegerLiftConvolutionProductDescriptor::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_full_ring_negacyclic_products.iter().map(
                        RelationIntegerLiftFullRingNegacyclicProductDescriptor::canonical_tuple,
                    ),
                )?,
                CanonicalItem::unsigned32(self.linear_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.product_accumulator_column_ordinal),
            ],
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftBatchDescriptor {
    pub(crate) modulus_reference: SuiteModulusReference,
    pub(crate) challenge_ordinal: u16,
    pub(crate) ordered_reversed_column_bindings:
        Vec<RelationIntegerLiftReversedColumnBindingDescriptor>,
    pub(crate) ordered_negacyclic_automorphism_permutations:
        Vec<RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor>,
    pub(crate) ordered_components: Vec<RelationIntegerLiftComponentDescriptor>,
}

impl RelationIntegerLiftBatchDescriptor {
    pub(crate) const fn modulus_reference(&self) -> SuiteModulusReference {
        self.modulus_reference
    }

    pub(crate) const fn challenge_ordinal(&self) -> u16 {
        self.challenge_ordinal
    }

    pub(crate) fn negacyclic_automorphism_permutations(
        &self,
    ) -> &[RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor] {
        &self.ordered_negacyclic_automorphism_permutations
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            INTEGER_LIFT_BATCH_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.modulus_reference.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.challenge_ordinal),
                canonical_nested_list(
                    self.ordered_reversed_column_bindings
                        .iter()
                        .map(RelationIntegerLiftReversedColumnBindingDescriptor::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_negacyclic_automorphism_permutations
                        .iter()
                        .map(
                            RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor::canonical_tuple,
                        ),
                )?,
                canonical_nested_list(
                    self.ordered_components
                        .iter()
                        .map(RelationIntegerLiftComponentDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationCoefficientLocalResidualDescriptor {
    pub(crate) unit_ordinal: u32,
    pub(crate) residual_postfix_expression: Vec<RelationExpressionInstruction>,
}

impl RelationCoefficientLocalResidualDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            COEFFICIENT_LOCAL_RESIDUAL_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.unit_ordinal),
                canonical_nested_list(
                    self.residual_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationCoefficientLocalIdentityBatchDescriptor {
    pub(crate) modulus_reference: SuiteModulusReference,
    pub(crate) challenge_ordinal: u16,
    pub(crate) batch_ordinal: u16,
    pub(crate) constraint_ordinal: u32,
    pub(crate) ordered_residuals: Vec<RelationCoefficientLocalResidualDescriptor>,
}

impl RelationCoefficientLocalIdentityBatchDescriptor {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            COEFFICIENT_LOCAL_IDENTITY_BATCH_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.modulus_reference.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.challenge_ordinal),
                CanonicalItem::unsigned16(self.batch_ordinal),
                CanonicalItem::unsigned32(self.constraint_ordinal),
                canonical_nested_list(
                    self.ordered_residuals
                        .iter()
                        .map(RelationCoefficientLocalResidualDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }

    fn numerator_postfix_expression(
        &self,
        modulus_ordinal: u16,
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        let mut expression = Vec::new();
        for (residual_index, residual) in self.ordered_residuals.iter().enumerate() {
            if residual.unit_ordinal
                != u32::try_from(residual_index).map_err(|_| RelationPlanError::CountOverflow)?
                || residual.residual_postfix_expression.is_empty()
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            expression.push(RelationExpressionInstruction::TranscriptChallenge {
                challenge_role: RelationChallengeRole::NonNativeAlpha,
                role_coordinates: vec![
                    u64::from(modulus_ordinal),
                    u64::from(self.challenge_ordinal),
                    u64::from(residual.unit_ordinal),
                ],
            });
            expression.extend_from_slice(&residual.residual_postfix_expression);
            expression.push(RelationExpressionInstruction::Multiplication);
            if residual_index > 0 {
                expression.push(RelationExpressionInstruction::Addition);
            }
        }
        if expression.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(expression)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftConstraintProgram {
    pub(crate) numerator_postfix_expression: Vec<RelationExpressionInstruction>,
    pub(crate) zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
}

impl RelationIntegerLiftBatchDescriptor {
    pub(crate) fn constraint_programs(
        &self,
        modulus_ordinal: u16,
        trace_domain_size: u64,
        evaluation_domain_size: u64,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
        let theta_expression =
            integer_lift_theta_expression(modulus_ordinal, self.challenge_ordinal);
        let last_row = trace_domain_size
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidDomain)?;
        let point_last = integer_lift_point_zeroifier(
            last_row,
            trace_domain_size,
            evaluation_domain_size,
            context,
        )?;
        let point_zero =
            integer_lift_point_zeroifier(0, trace_domain_size, evaluation_domain_size, context)?;
        let except_zero = integer_lift_trace_except_rows_zeroifier(
            &[0],
            trace_domain_size,
            evaluation_domain_size,
            context,
        )?;
        let except_last = integer_lift_trace_except_rows_zeroifier(
            &[last_row],
            trace_domain_size,
            evaluation_domain_size,
            context,
        )?;

        let mut programs = Vec::new();
        for permutation in &self.ordered_negacyclic_automorphism_permutations {
            programs.extend(
                integer_lift_negacyclic_automorphism_permutation_constraint_programs(
                    permutation,
                    &theta_expression,
                    point_zero.clone(),
                    point_last.clone(),
                    except_last.clone(),
                    trace_domain_size,
                )?,
            );
        }
        for binding in &self.ordered_reversed_column_bindings {
            programs.extend(integer_lift_reversed_column_binding_constraint_programs(
                binding,
                &theta_expression,
                point_zero.clone(),
                point_last.clone(),
                except_zero.clone(),
                except_last.clone(),
            ));
        }
        for component in &self.ordered_components {
            for product in &component.ordered_convolution_products {
                programs.extend(integer_lift_product_constraint_programs(
                    product,
                    &theta_expression,
                    trace_domain_size,
                    point_last.clone(),
                    except_zero.clone(),
                    except_last.clone(),
                )?);
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                programs.extend(integer_lift_full_ring_product_constraint_programs(
                    product,
                    &theta_expression,
                    trace_domain_size,
                    point_last.clone(),
                    except_last.clone(),
                )?);
            }
            programs.extend(integer_lift_component_constraint_programs(
                component,
                self.modulus_reference,
                &theta_expression,
                point_last.clone(),
                except_last.clone(),
            )?);
        }
        Ok(programs)
    }
}

fn negacyclic_automorphism_encoded_source_expression(
    position_column_ordinal: u32,
    negation_bit_column_ordinal: u32,
    value_column_ordinal: u32,
) -> Vec<RelationExpressionInstruction> {
    let tagged_position = multiply_integer_lift_expressions(
        integer_lift_column_expression(position_column_ordinal, false, 0),
        vec![RelationExpressionInstruction::BaseFieldConstant(3)],
    );
    let signed_value = subtract_integer_lift_expressions(
        integer_lift_column_expression(value_column_ordinal, false, 0),
        multiply_integer_lift_expressions(
            multiply_integer_lift_expressions(
                integer_lift_column_expression(negation_bit_column_ordinal, false, 0),
                vec![RelationExpressionInstruction::BaseFieldConstant(2)],
            ),
            integer_lift_column_expression(value_column_ordinal, false, 0),
        ),
    );
    add_integer_lift_expressions(
        add_integer_lift_expressions(
            tagged_position,
            vec![RelationExpressionInstruction::BaseFieldConstant(1)],
        ),
        signed_value,
    )
}

fn negacyclic_automorphism_encoded_target_expression(
    position_column_ordinal: u32,
    value_column_ordinal: u32,
) -> Vec<RelationExpressionInstruction> {
    add_integer_lift_expressions(
        add_integer_lift_expressions(
            multiply_integer_lift_expressions(
                integer_lift_column_expression(position_column_ordinal, false, 0),
                vec![RelationExpressionInstruction::BaseFieldConstant(3)],
            ),
            vec![RelationExpressionInstruction::BaseFieldConstant(1)],
        ),
        integer_lift_column_expression(value_column_ordinal, false, 0),
    )
}

fn negacyclic_automorphism_product_factor_expression(
    theta_expression: &[RelationExpressionInstruction],
    encoded_value_expression: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    subtract_integer_lift_expressions(theta_expression.to_vec(), encoded_value_expression)
}

fn integer_lift_negacyclic_automorphism_permutation_constraint_programs(
    descriptor: &RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    point_zero: Vec<RelationExpressionInstruction>,
    point_last: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
    trace_domain_size: u64,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    if trace_domain_size == 0 {
        return Err(RelationPlanError::InvalidDomain);
    }
    let source_low_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_source_expression(
            descriptor.mapped_low_position_column_ordinal,
            descriptor.low_negation_bit_column_ordinal,
            descriptor.source_low_column_ordinal,
        ),
    );
    let source_high_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_source_expression(
            descriptor.mapped_high_position_column_ordinal,
            descriptor.high_negation_bit_column_ordinal,
            descriptor.source_high_column_ordinal,
        ),
    );
    let target_low_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_target_expression(
            descriptor.target_low_position_column_ordinal,
            descriptor.target_low_column_ordinal,
        ),
    );
    let target_high_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_target_expression(
            descriptor.target_high_position_column_ordinal,
            descriptor.target_high_column_ordinal,
        ),
    );
    let source_before = descriptor.source_product_before_column_ordinal;
    let source_low_product = descriptor.source_low_product_column_ordinal;
    let target_before = descriptor.target_product_before_column_ordinal;
    let target_low_product = descriptor.target_low_product_column_ordinal;
    let one = vec![RelationExpressionInstruction::BaseFieldConstant(1)];
    Ok(vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(source_before, false, 0),
                one.clone(),
            ),
            zeroifier_postfix_expression: point_zero.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(target_before, false, 0),
                one,
            ),
            zeroifier_postfix_expression: point_zero,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(source_low_product, false, 0),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(source_before, false, 0),
                    source_low_factor,
                ),
            ),
            zeroifier_postfix_expression: full_trace_zeroifier_expression(trace_domain_size),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(target_low_product, false, 0),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(target_before, false, 0),
                    target_low_factor,
                ),
            ),
            zeroifier_postfix_expression: full_trace_zeroifier_expression(trace_domain_size),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(source_before, false, 1),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(source_low_product, false, 0),
                    source_high_factor.clone(),
                ),
            ),
            zeroifier_postfix_expression: except_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(target_before, false, 1),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(target_low_product, false, 0),
                    target_high_factor.clone(),
                ),
            ),
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(source_low_product, false, 0),
                    source_high_factor,
                ),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(target_low_product, false, 0),
                    target_high_factor,
                ),
            ),
            zeroifier_postfix_expression: point_last,
        },
    ])
}

fn integer_lift_reversed_column_binding_constraint_programs(
    binding: &RelationIntegerLiftReversedColumnBindingDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    point_zero: Vec<RelationExpressionInstruction>,
    point_last: Vec<RelationExpressionInstruction>,
    except_zero: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Vec<RelationIntegerLiftConstraintProgram> {
    let source = binding.source_column_ordinal;
    let reversed = binding.reversed_column_ordinal;
    let prefix = binding.source_prefix_evaluation_column_ordinal;
    let suffix = binding.reversed_suffix_evaluation_column_ordinal;
    vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(prefix, false, 0),
                integer_lift_column_expression(source, false, 0),
            ),
            zeroifier_postfix_expression: point_zero.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    integer_lift_column_expression(prefix, false, 0),
                    integer_lift_column_expression(source, false, 0),
                ),
                multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(prefix, true, 1),
                ),
            ),
            zeroifier_postfix_expression: except_zero,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(suffix, false, 0),
                integer_lift_column_expression(reversed, false, 0),
            ),
            zeroifier_postfix_expression: point_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    integer_lift_column_expression(suffix, false, 0),
                    integer_lift_column_expression(reversed, false, 0),
                ),
                multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(suffix, false, 1),
                ),
            ),
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(prefix, true, 1),
                integer_lift_column_expression(suffix, false, 0),
            ),
            zeroifier_postfix_expression: point_zero,
        },
    ]
}

fn integer_lift_full_ring_product_constraint_programs(
    product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    half_ring_degree: u64,
    point_last: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    let mut programs = Vec::with_capacity(8);
    for (multiplicand, suffix) in [
        (
            product.multiplicand_low_column_ordinal,
            product.multiplicand_low_suffix_evaluation_column_ordinal,
        ),
        (
            product.multiplicand_high_column_ordinal,
            product.multiplicand_high_suffix_evaluation_column_ordinal,
        ),
    ] {
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(suffix, false, 0),
                integer_lift_column_expression(multiplicand, false, 0),
            ),
            zeroifier_postfix_expression: point_last.clone(),
        });
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    integer_lift_column_expression(suffix, false, 0),
                    integer_lift_column_expression(multiplicand, false, 0),
                ),
                multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(suffix, false, 1),
                ),
            ),
            zeroifier_postfix_expression: except_last.clone(),
        });
    }

    let mut theta_to_half_ring_degree = theta_expression.to_vec();
    theta_to_half_ring_degree.push(RelationExpressionInstruction::NonnegativePower(
        half_ring_degree,
    ));
    let low_multiplicand_next =
        integer_lift_column_expression(product.multiplicand_low_column_ordinal, false, 1);
    let high_multiplicand_next =
        integer_lift_column_expression(product.multiplicand_high_column_ordinal, false, 1);
    let theta_to_half_times_low = multiply_integer_lift_expressions(
        theta_to_half_ring_degree.clone(),
        low_multiplicand_next.clone(),
    );
    let theta_to_half_times_high = multiply_integer_lift_expressions(
        theta_to_half_ring_degree,
        high_multiplicand_next.clone(),
    );

    for (is_low_multiplier, transpose) in [
        (
            true,
            product.reversed_multiplier_low_transpose_column_ordinal,
        ),
        (
            false,
            product.reversed_multiplier_high_transpose_column_ordinal,
        ),
    ] {
        let boundary = match (product.selected_half, is_low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => subtract_integer_lift_expressions(
                integer_lift_column_expression(transpose, false, 0),
                integer_lift_column_expression(
                    product.multiplicand_low_suffix_evaluation_column_ordinal,
                    false,
                    1,
                ),
            ),
            (RelationIntegerLiftFullRingHalf::Low, false) => add_integer_lift_expressions(
                integer_lift_column_expression(transpose, false, 0),
                integer_lift_column_expression(
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    false,
                    1,
                ),
            ),
            (RelationIntegerLiftFullRingHalf::High, true) => subtract_integer_lift_expressions(
                integer_lift_column_expression(transpose, false, 0),
                integer_lift_column_expression(
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    false,
                    1,
                ),
            ),
        };
        let transpose_minus_theta_next = subtract_integer_lift_expressions(
            integer_lift_column_expression(transpose, false, 0),
            multiply_integer_lift_expressions(
                theta_expression.to_vec(),
                integer_lift_column_expression(transpose, false, 1),
            ),
        );
        let recurrence = match (product.selected_half, is_low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => add_integer_lift_expressions(
                add_integer_lift_expressions(
                    transpose_minus_theta_next,
                    theta_to_half_times_low.clone(),
                ),
                high_multiplicand_next.clone(),
            ),
            (RelationIntegerLiftFullRingHalf::Low, false) => subtract_integer_lift_expressions(
                add_integer_lift_expressions(
                    transpose_minus_theta_next,
                    low_multiplicand_next.clone(),
                ),
                theta_to_half_times_high.clone(),
            ),
            (RelationIntegerLiftFullRingHalf::High, true) => add_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    transpose_minus_theta_next,
                    low_multiplicand_next.clone(),
                ),
                theta_to_half_times_high.clone(),
            ),
        };
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: boundary,
            zeroifier_postfix_expression: point_last.clone(),
        });
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: recurrence,
            zeroifier_postfix_expression: except_last.clone(),
        });
    }
    Ok(programs)
}

fn integer_lift_product_constraint_programs(
    product: &RelationIntegerLiftConvolutionProductDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    trace_domain_size: u64,
    point_last: Vec<RelationExpressionInstruction>,
    except_zero: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    let suffix = product.suffix_evaluation_column_ordinal;
    let multiplicand = product.multiplicand_column_ordinal;
    let transpose = product.reversed_transpose_column_ordinal;
    let suffix_last = subtract_integer_lift_expressions(
        integer_lift_column_expression(suffix, false, 0),
        integer_lift_column_expression(multiplicand, false, 0),
    );

    let theta_times_next_suffix = multiply_integer_lift_expressions(
        theta_expression.to_vec(),
        integer_lift_column_expression(suffix, false, 1),
    );
    let suffix_recurrence = subtract_integer_lift_expressions(
        subtract_integer_lift_expressions(
            integer_lift_column_expression(suffix, false, 0),
            integer_lift_column_expression(multiplicand, false, 0),
        ),
        theta_times_next_suffix,
    );

    let mut theta_to_ring_degree_plus_one = theta_expression.to_vec();
    theta_to_ring_degree_plus_one.push(RelationExpressionInstruction::NonnegativePower(
        trace_domain_size,
    ));
    theta_to_ring_degree_plus_one.extend([
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Addition,
    ]);
    let (transpose_boundary, transpose_recurrence, transpose_zeroifier) =
        match product.convolution_kind {
            RelationIntegerLiftConvolutionKind::Negacyclic => {
                let boundary = subtract_integer_lift_expressions(
                    integer_lift_column_expression(transpose, false, 0),
                    integer_lift_column_expression(suffix, false, 1),
                );
                let theta_times_transpose = multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(transpose, false, 0),
                );
                let wrap_correction = multiply_integer_lift_expressions(
                    theta_to_ring_degree_plus_one,
                    integer_lift_column_expression(multiplicand, false, 0),
                );
                let recurrence = add_integer_lift_expressions(
                    subtract_integer_lift_expressions(
                        integer_lift_column_expression(transpose, true, 1),
                        theta_times_transpose,
                    ),
                    wrap_correction,
                );
                (boundary, recurrence, except_zero)
            }
            RelationIntegerLiftConvolutionKind::OrdinaryLowHalf => {
                let boundary = subtract_integer_lift_expressions(
                    integer_lift_column_expression(transpose, false, 0),
                    integer_lift_column_expression(suffix, false, 1),
                );
                let mut theta_to_ring_degree = theta_expression.to_vec();
                theta_to_ring_degree.push(RelationExpressionInstruction::NonnegativePower(
                    trace_domain_size,
                ));
                let recurrence = add_integer_lift_expressions(
                    subtract_integer_lift_expressions(
                        integer_lift_column_expression(transpose, false, 0),
                        multiply_integer_lift_expressions(
                            theta_expression.to_vec(),
                            integer_lift_column_expression(transpose, false, 1),
                        ),
                    ),
                    multiply_integer_lift_expressions(
                        theta_to_ring_degree,
                        integer_lift_column_expression(multiplicand, false, 1),
                    ),
                );
                (boundary, recurrence, except_last.clone())
            }
            RelationIntegerLiftConvolutionKind::OrdinaryHighHalf => {
                let boundary = integer_lift_column_expression(transpose, false, 0);
                let recurrence = subtract_integer_lift_expressions(
                    subtract_integer_lift_expressions(
                        integer_lift_column_expression(transpose, false, 0),
                        integer_lift_column_expression(multiplicand, false, 1),
                    ),
                    multiply_integer_lift_expressions(
                        theta_expression.to_vec(),
                        integer_lift_column_expression(transpose, false, 1),
                    ),
                );
                (boundary, recurrence, except_last.clone())
            }
        };

    Ok(vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: suffix_last,
            zeroifier_postfix_expression: point_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: suffix_recurrence,
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: transpose_boundary,
            zeroifier_postfix_expression: point_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: transpose_recurrence,
            zeroifier_postfix_expression: transpose_zeroifier,
        },
    ])
}

fn integer_lift_component_constraint_programs(
    component: &RelationIntegerLiftComponentDescriptor,
    modulus_reference: SuiteModulusReference,
    theta_expression: &[RelationExpressionInstruction],
    point_last: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    let coefficient_expression =
        integer_lift_component_coefficient_expression(component, modulus_reference)?;
    let linear_evaluation = component.linear_evaluation_column_ordinal;
    let linear_last = subtract_integer_lift_expressions(
        integer_lift_column_expression(linear_evaluation, false, 0),
        coefficient_expression.clone(),
    );
    let linear_recurrence = subtract_integer_lift_expressions(
        subtract_integer_lift_expressions(
            integer_lift_column_expression(linear_evaluation, false, 0),
            coefficient_expression,
        ),
        multiply_integer_lift_expressions(
            theta_expression.to_vec(),
            integer_lift_column_expression(linear_evaluation, false, 1),
        ),
    );

    let product_expression = integer_lift_component_product_expression(component)?;
    let accumulator = component.product_accumulator_column_ordinal;
    let accumulator_step = subtract_integer_lift_expressions(
        subtract_integer_lift_expressions(
            integer_lift_column_expression(accumulator, false, 1),
            integer_lift_column_expression(accumulator, false, 0),
        ),
        product_expression.clone(),
    );
    let accumulator_terminal = subtract_integer_lift_expressions(
        accumulator_step.clone(),
        integer_lift_column_expression(linear_evaluation, false, 1),
    );

    Ok(vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: linear_last,
            zeroifier_postfix_expression: point_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: linear_recurrence,
            zeroifier_postfix_expression: except_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: accumulator_step,
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: accumulator_terminal,
            zeroifier_postfix_expression: point_last,
        },
    ])
}

fn integer_lift_component_coefficient_expression(
    component: &RelationIntegerLiftComponentDescriptor,
    modulus_reference: SuiteModulusReference,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut terms = component
        .ordered_linear_terms
        .iter()
        .map(integer_lift_linear_term_expression)
        .collect::<Result<Vec<_>, _>>()?;
    let quotient = multiply_integer_lift_expressions(
        vec![RelationExpressionInstruction::NonNativeModulusConstant {
            modulus_reference,
            multiplier: 1,
        }],
        integer_lift_column_expression(component.quotient_column_ordinal, false, 0),
    );
    terms.push(if component.quotient_is_negative {
        negate_integer_lift_expression(quotient)
    } else {
        quotient
    });
    sum_integer_lift_expressions(terms)
}

fn integer_lift_component_product_expression(
    component: &RelationIntegerLiftComponentDescriptor,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut terms = component
        .ordered_convolution_products
        .iter()
        .map(|product| {
            let shifted_multiplier = subtract_integer_lift_expressions(
                integer_lift_column_expression(
                    product.reversed_multiplier_column_ordinal,
                    false,
                    0,
                ),
                vec![RelationExpressionInstruction::BaseFieldConstant(
                    product.multiplier_offset,
                )],
            );
            let expression = multiply_integer_lift_expressions(
                integer_lift_column_expression(product.reversed_transpose_column_ordinal, false, 0),
                shifted_multiplier,
            );
            if product.negative {
                negate_integer_lift_expression(expression)
            } else {
                expression
            }
        })
        .collect::<Vec<_>>();
    terms.extend(
        component
            .ordered_full_ring_negacyclic_products
            .iter()
            .map(|product| {
                let low_multiplier = subtract_integer_lift_expressions(
                    integer_lift_column_expression(
                        product.reversed_multiplier_low_column_ordinal,
                        false,
                        0,
                    ),
                    vec![RelationExpressionInstruction::BaseFieldConstant(
                        product.multiplier_low_offset,
                    )],
                );
                let high_multiplier = subtract_integer_lift_expressions(
                    integer_lift_column_expression(
                        product.reversed_multiplier_high_column_ordinal,
                        false,
                        0,
                    ),
                    vec![RelationExpressionInstruction::BaseFieldConstant(
                        product.multiplier_high_offset,
                    )],
                );
                let expression = add_integer_lift_expressions(
                    multiply_integer_lift_expressions(
                        integer_lift_column_expression(
                            product.reversed_multiplier_low_transpose_column_ordinal,
                            false,
                            0,
                        ),
                        low_multiplier,
                    ),
                    multiply_integer_lift_expressions(
                        integer_lift_column_expression(
                            product.reversed_multiplier_high_transpose_column_ordinal,
                            false,
                            0,
                        ),
                        high_multiplier,
                    ),
                );
                if product.negative {
                    negate_integer_lift_expression(expression)
                } else {
                    expression
                }
            }),
    );
    sum_integer_lift_expressions(terms)
}

fn integer_lift_linear_term_expression(
    term: &RelationIntegerLiftLinearTermDescriptor,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let shifted_column = subtract_integer_lift_expressions(
        integer_lift_column_expression(term.column_ordinal, false, 0),
        vec![RelationExpressionInstruction::BaseFieldConstant(
            term.column_offset,
        )],
    );
    let coefficient = match term.coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => {
            RelationExpressionInstruction::BaseFieldConstant(value)
        }
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => RelationExpressionInstruction::NonNativeModulusConstant {
            modulus_reference,
            multiplier,
        },
    };
    let expression = multiply_integer_lift_expressions(vec![coefficient], shifted_column);
    Ok(if term.negative {
        negate_integer_lift_expression(expression)
    } else {
        expression
    })
}

fn integer_lift_theta_expression(
    modulus_ordinal: u16,
    challenge_ordinal: u16,
) -> Vec<RelationExpressionInstruction> {
    vec![RelationExpressionInstruction::TranscriptChallenge {
        challenge_role: RelationChallengeRole::NonNativeTheta,
        role_coordinates: vec![u64::from(modulus_ordinal), u64::from(challenge_ordinal)],
    }]
}

fn integer_lift_column_expression(
    column_ordinal: u32,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Vec<RelationExpressionInstruction> {
    vec![RelationExpressionInstruction::ColumnValue {
        column_ordinal,
        rotation_is_negative,
        rotation_magnitude,
    }]
}

fn add_integer_lift_expressions(
    mut left: Vec<RelationExpressionInstruction>,
    right: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    left.extend(right);
    left.push(RelationExpressionInstruction::Addition);
    left
}

fn subtract_integer_lift_expressions(
    left: Vec<RelationExpressionInstruction>,
    right: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    add_integer_lift_expressions(left, negate_integer_lift_expression(right))
}

fn multiply_integer_lift_expressions(
    mut left: Vec<RelationExpressionInstruction>,
    right: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    left.extend(right);
    left.push(RelationExpressionInstruction::Multiplication);
    left
}

fn negate_integer_lift_expression(
    mut expression: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    expression.push(RelationExpressionInstruction::Negation);
    expression
}

fn sum_integer_lift_expressions(
    expressions: Vec<Vec<RelationExpressionInstruction>>,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut expressions = expressions.into_iter();
    let mut sum = expressions
        .next()
        .ok_or(RelationPlanError::InvalidConstraint)?;
    for expression in expressions {
        sum = add_integer_lift_expressions(sum, expression);
    }
    Ok(sum)
}

fn integer_lift_point_zeroifier(
    row_ordinal: u64,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let root = integer_lift_trace_root(
        row_ordinal,
        trace_domain_size,
        evaluation_domain_size,
        context,
    )?;
    Ok(vec![
        RelationExpressionInstruction::EvaluationVariable,
        RelationExpressionInstruction::BaseFieldConstant(root),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ])
}

fn integer_lift_trace_except_rows_zeroifier(
    excluded_rows: &[u64],
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    if excluded_rows.is_empty() {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let mut ordered_excluded_roots = excluded_rows
        .iter()
        .map(|row_ordinal| {
            integer_lift_trace_root(
                *row_ordinal,
                trace_domain_size,
                evaluation_domain_size,
                context,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ordered_excluded_roots.sort_unstable();
    if !strictly_sorted_unique(&ordered_excluded_roots) {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    Ok(vec![
        RelationExpressionInstruction::TraceDomainExceptRoots {
            trace_domain_size,
            ordered_excluded_roots,
        },
    ])
}

fn integer_lift_trace_root(
    row_ordinal: u64,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    if row_ordinal >= trace_domain_size || !evaluation_domain_size.is_multiple_of(trace_domain_size)
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    let trace_generator = modular_power(
        context.evaluation_domain_generator,
        evaluation_domain_size / trace_domain_size,
        context.base_field_modulus,
    );
    Ok(modular_power(
        trace_generator,
        row_ordinal,
        context.base_field_modulus,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationOpeningPointDescriptor {
    deep_point_ordinal: u16,
    trace_rotation_is_negative: bool,
    trace_rotation_magnitude: u64,
    conjugate_index: u16,
}

impl RelationOpeningPointDescriptor {
    pub(crate) const fn deep_point_ordinal(self) -> u16 {
        self.deep_point_ordinal
    }

    pub(crate) const fn trace_rotation(self) -> (bool, u64) {
        (
            self.trace_rotation_is_negative,
            self.trace_rotation_magnitude,
        )
    }

    pub(crate) const fn conjugate_index(self) -> u16 {
        self.conjugate_index
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_OPENING_POINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.deep_point_ordinal),
                CanonicalItem::unsigned8(u8::from(self.trace_rotation_is_negative)),
                CanonicalItem::unsigned64(self.trace_rotation_magnitude),
                CanonicalItem::unsigned16(self.conjugate_index),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationOpeningSourceClass {
    TreeColumn = 1,
    Quotient = 2,
    BatchMask = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationOpeningClaimDescriptor {
    source_class: RelationOpeningSourceClass,
    source_ordinal: u32,
    column_ordinal: Option<u32>,
    opening_point_ordinal: u32,
    source_degree_bound_exclusive: u64,
}

impl RelationOpeningClaimDescriptor {
    pub(crate) const fn source_class(self) -> RelationOpeningSourceClass {
        self.source_class
    }

    pub(crate) const fn source_ordinal(self) -> u32 {
        self.source_ordinal
    }

    pub(crate) const fn column_ordinal(self) -> Option<u32> {
        self.column_ordinal
    }

    pub(crate) const fn opening_point_ordinal(self) -> u32 {
        self.opening_point_ordinal
    }

    pub(crate) const fn source_degree_bound_exclusive(self) -> u64 {
        self.source_degree_bound_exclusive
    }

    fn canonical_tuple(self) -> Result<CanonicalTuple, RelationPlanError> {
        let column_item = self.column_ordinal.map(CanonicalItem::unsigned32);
        Ok(CanonicalTuple::new(
            RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.source_class as u16),
                CanonicalItem::unsigned32(self.source_ordinal),
                CanonicalItem::optional(CanonicalItemType::Unsigned32, column_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned32(self.opening_point_ordinal),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationMaskKind {
    Trace = 1,
    Telescoping = 2,
    OpeningBatch = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationMaskTargetClass {
    Column = 1,
    QuotientComponent = 2,
    Batch = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationMaskDescriptor {
    mask_purpose: u16,
    mask_kind: RelationMaskKind,
    target_class: RelationMaskTargetClass,
    target_ordinal: u32,
    mask_degree_bound_exclusive: u64,
}

impl RelationMaskDescriptor {
    pub(crate) const fn mask_purpose(self) -> u16 {
        self.mask_purpose
    }

    pub(crate) const fn mask_kind(self) -> RelationMaskKind {
        self.mask_kind
    }

    pub(crate) const fn target_class(self) -> RelationMaskTargetClass {
        self.target_class
    }

    pub(crate) const fn target_ordinal(self) -> u32 {
        self.target_ordinal
    }

    pub(crate) const fn mask_degree_bound_exclusive(self) -> u64 {
        self.mask_degree_bound_exclusive
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_MASK_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.mask_purpose),
                CanonicalItem::unsigned16(self.mask_kind as u16),
                CanonicalItem::unsigned16(self.target_class as u16),
                CanonicalItem::unsigned32(self.target_ordinal),
                CanonicalItem::unsigned64(self.mask_degree_bound_exclusive),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanVariant {
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
    ordered_semantic_cells: Vec<SemanticCellDescriptor>,
    ordered_radix_convolutions: Vec<RelationRadixConvolutionDescriptor>,
    ordered_integer_lift_batches: Vec<RelationIntegerLiftBatchDescriptor>,
    ordered_coefficient_local_identity_batches:
        Vec<RelationCoefficientLocalIdentityBatchDescriptor>,
    ordered_trees: Vec<RelationTreeDescriptor>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
    ordered_opening_points: Vec<RelationOpeningPointDescriptor>,
    ordered_opening_claims: Vec<RelationOpeningClaimDescriptor>,
    ordered_masks: Vec<RelationMaskDescriptor>,
}

impl RelationPlanVariant {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        encode_generated_tuple(&self.canonical_tuple()?)
    }

    pub(crate) fn canonical_hash(&self) -> Result<[u8; 64], RelationPlanError> {
        hash_generated_variable_bytes(RELATION_PLAN_VARIANT_HASH_DOMAIN, &self.canonical_bytes()?)
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn proof_privacy_mode(&self) -> ProofPrivacyMode {
        self.proof_privacy_mode
    }

    pub(crate) const fn trace_domain_size(&self) -> u64 {
        self.trace_domain_size
    }

    pub(crate) const fn evaluation_domain_size(&self) -> u64 {
        self.evaluation_domain_size
    }

    pub(crate) const fn opening_degree_bound_exclusive(&self) -> u64 {
        self.opening_degree_bound_exclusive
    }

    pub(crate) fn non_native_modulus_ordinal(
        &self,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u16, RelationPlanError> {
        u16::try_from(
            self.ordered_non_native_moduli
                .binary_search(&modulus_reference)
                .map_err(|_| RelationPlanError::MissingModulus)?,
        )
        .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(crate) fn ordered_columns(&self) -> &[RelationColumnDescriptor] {
        &self.ordered_columns
    }

    pub(crate) fn verifier_source(&self, ordinal: u32) -> Option<&RelationVerifierSource> {
        self.ordered_verifier_sources.get(ordinal as usize)
    }

    pub(crate) fn ordered_trees(&self) -> &[RelationTreeDescriptor] {
        &self.ordered_trees
    }

    pub(crate) fn ordered_integer_lift_batches(&self) -> &[RelationIntegerLiftBatchDescriptor] {
        &self.ordered_integer_lift_batches
    }

    pub(crate) fn ordered_coefficient_local_identity_batches(
        &self,
    ) -> &[RelationCoefficientLocalIdentityBatchDescriptor] {
        &self.ordered_coefficient_local_identity_batches
    }

    pub(crate) fn ordered_opening_points(&self) -> &[RelationOpeningPointDescriptor] {
        &self.ordered_opening_points
    }

    pub(crate) fn ordered_opening_claims(&self) -> &[RelationOpeningClaimDescriptor] {
        &self.ordered_opening_claims
    }

    pub(crate) fn ordered_masks(&self) -> &[RelationMaskDescriptor] {
        &self.ordered_masks
    }

    /// Degree of the cross-multiplied DEEP identity used after the quotient
    /// roots are fixed. The bound is derived from the checked expression
    /// programs and canonical quotient decomposition; it is an input to the
    /// round-by-round application theorem, not a proof-body assertion.
    pub(crate) fn application_deep_identity_degree_bound(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<u64, RelationPlanError> {
        let mut distinct_zeroifier_degrees = BTreeMap::<Vec<u8>, u64>::new();
        let mut numerator_and_zeroifier_degrees = Vec::new();
        for constraint in &self.ordered_constraints {
            let numerator = check_expression(
                &constraint.numerator_postfix_expression,
                self,
                context,
                false,
            )?;
            let zeroifier = check_expression(
                &constraint.zeroifier_postfix_expression,
                self,
                context,
                true,
            )?;
            let zeroifier_key = canonical_nested_list(
                constraint
                    .zeroifier_postfix_expression
                    .iter()
                    .map(RelationExpressionInstruction::canonical_tuple)
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .canonical_bytes()
            .to_vec();
            distinct_zeroifier_degrees
                .entry(zeroifier_key)
                .or_insert(zeroifier.degree);
            numerator_and_zeroifier_degrees.push((numerator.degree, zeroifier.degree));
        }
        let total_zeroifier_degree = distinct_zeroifier_degrees
            .values()
            .try_fold(0_u64, |total, degree| total.checked_add(*degree))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let quotient_component_degree = u64::from(
            context
                .quotient_component_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        );
        let quotient_degree = u64::from(
            context
                .quotient_component_count
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        )
        .checked_mul(self.quotient_decomposition_stride(context)?)
        .and_then(|degree| degree.checked_add(quotient_component_degree))
        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let quotient_term_degree = quotient_degree
            .checked_add(total_zeroifier_degree)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        numerator_and_zeroifier_degrees.into_iter().try_fold(
            quotient_term_degree,
            |maximum_degree, (numerator_degree, zeroifier_degree)| {
                let term_degree = numerator_degree
                    .checked_add(total_zeroifier_degree)
                    .and_then(|degree| degree.checked_sub(zeroifier_degree))
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                Ok(maximum_degree.max(term_degree))
            },
        )
    }

    /// Conservative cardinality of the values rejected while sampling the
    /// last DEEP center. Rotations and Frobenius maps are bijections, so a
    /// union bound over their inverse images covers trace roots, the evaluation
    /// coset, every checked zeroifier root, and collisions with earlier centers.
    pub(crate) fn application_deep_forbidden_candidate_count_bound(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<BigUint, RelationPlanError> {
        let mut distinct_zeroifier_degrees = BTreeMap::<Vec<u8>, u64>::new();
        for constraint in &self.ordered_constraints {
            let zeroifier = check_expression(
                &constraint.zeroifier_postfix_expression,
                self,
                context,
                true,
            )?;
            let zeroifier_key = canonical_nested_list(
                constraint
                    .zeroifier_postfix_expression
                    .iter()
                    .map(RelationExpressionInstruction::canonical_tuple)
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .canonical_bytes()
            .to_vec();
            distinct_zeroifier_degrees
                .entry(zeroifier_key)
                .or_insert(zeroifier.degree);
        }
        let total_zeroifier_degree = distinct_zeroifier_degrees
            .values()
            .try_fold(0_u64, |total, degree| total.checked_add(*degree))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let opening_point_count_per_center = u64::try_from(
            self.ordered_opening_points
                .iter()
                .filter(|point| point.deep_point_ordinal == 0)
                .count(),
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        if opening_point_count_per_center == 0 {
            return Err(RelationPlanError::InvalidOpening);
        }
        let excluded_per_translated_point = self
            .trace_domain_size
            .checked_add(self.evaluation_domain_size)
            .and_then(|count| count.checked_add(total_zeroifier_degree))
            .ok_or(RelationPlanError::CountOverflow)?;
        let prior_center_count = u64::from(
            context
                .deep_point_count
                .checked_sub(1)
                .ok_or(RelationPlanError::InvalidOpening)?,
        );
        let mut non_full_degree_element_bound = BigUint::zero();
        for proper_subfield_degree in 1..context.challenge_extension_degree {
            if context
                .challenge_extension_degree
                .is_multiple_of(proper_subfield_degree)
            {
                non_full_degree_element_bound += BigUint::from(context.base_field_modulus)
                    .pow(u32::from(proper_subfield_degree));
            }
        }
        let opening_point_count = BigUint::from(opening_point_count_per_center);
        let extension_degree = BigUint::from(context.challenge_extension_degree);
        let prior_orbit_collision_bound = &opening_point_count
            * &opening_point_count
            * BigUint::from(prior_center_count)
            * &extension_degree;
        let current_orbit_collision_pair_count = opening_point_count_per_center
            .checked_mul(opening_point_count_per_center.saturating_sub(1))
            .and_then(|count| count.checked_div(2))
            .ok_or(RelationPlanError::CountOverflow)?;
        let current_orbit_collision_bound =
            BigUint::from(current_orbit_collision_pair_count) * &extension_degree;
        Ok(BigUint::one()
            + &opening_point_count * BigUint::from(excluded_per_translated_point)
            + &opening_point_count * non_full_degree_element_bound
            + prior_orbit_collision_bound
            + current_orbit_collision_bound)
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        let schedule_item = self.schedule_position.map(CanonicalItem::unsigned32);
        let top_count_item = self.top_count.map(CanonicalItem::unsigned16);
        Ok(CanonicalTuple::new(
            RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::optional(CanonicalItemType::Unsigned32, schedule_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(CanonicalItemType::Unsigned16, top_count_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.proof_privacy_mode as u16),
                CanonicalItem::unsigned64(self.trace_domain_size),
                CanonicalItem::unsigned64(self.evaluation_domain_size),
                CanonicalItem::unsigned64(self.opening_degree_bound_exclusive),
                canonical_nested_list(
                    self.ordered_non_native_moduli
                        .iter()
                        .copied()
                        .map(SuiteModulusReference::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_verifier_sources
                        .iter()
                        .map(RelationVerifierSource::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_public_samplers
                        .iter()
                        .map(RelationPublicSamplerDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_columns
                        .iter()
                        .map(RelationColumnDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_semantic_cells
                        .iter()
                        .map(SemanticCellDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_radix_convolutions
                        .iter()
                        .map(RelationRadixConvolutionDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_integer_lift_batches
                        .iter()
                        .map(RelationIntegerLiftBatchDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_coefficient_local_identity_batches
                        .iter()
                        .map(RelationCoefficientLocalIdentityBatchDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_trees
                        .iter()
                        .map(RelationTreeDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_constraints
                        .iter()
                        .map(RelationConstraintDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_opening_points
                        .iter()
                        .copied()
                        .map(RelationOpeningPointDescriptor::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_opening_claims
                        .iter()
                        .copied()
                        .map(RelationOpeningClaimDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_masks
                        .iter()
                        .copied()
                        .map(RelationMaskDescriptor::canonical_tuple),
                )?,
            ],
        ))
    }

    pub(crate) fn derived_challenge_catalog(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationChallengeDescriptor>, RelationPlanError> {
        let mut catalog = BTreeSet::new();
        for constraint in &self.ordered_constraints {
            for instruction in &constraint.numerator_postfix_expression {
                if let RelationExpressionInstruction::TranscriptChallenge {
                    challenge_role,
                    role_coordinates,
                } = instruction
                {
                    catalog.insert(challenge_descriptor(
                        *challenge_role,
                        role_coordinates.clone(),
                        1,
                        self,
                        context,
                    )?);
                }
            }
        }
        for factor in self
            .ordered_radix_convolutions
            .iter()
            .flat_map(|convolution| &convolution.ordered_terms)
            .flat_map(|term| &term.ordered_factors)
        {
            if let RelationRadixFactorDescriptor::TranscriptChallengeDigits {
                challenge_role,
                role_coordinates,
                ..
            } = factor
            {
                catalog.insert(challenge_descriptor(
                    *challenge_role,
                    role_coordinates.clone(),
                    1,
                    self,
                    context,
                )?);
            }
        }
        for constraint_ordinal in 0..self.ordered_constraints.len() {
            catalog.insert(challenge_descriptor(
                RelationChallengeRole::ConstraintComposition,
                vec![constraint_ordinal as u64],
                1,
                self,
                context,
            )?);
        }
        for deep_point_ordinal in 0..context.deep_point_count {
            catalog.insert(challenge_descriptor(
                RelationChallengeRole::DeepPoint,
                vec![u64::from(deep_point_ordinal)],
                1,
                self,
                context,
            )?);
        }
        catalog.insert(challenge_descriptor(
            RelationChallengeRole::OpeningBatch,
            vec![0],
            u32::try_from(self.ordered_opening_claims.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            self,
            context,
        )?);
        for fold_ordinal in 0..context.fri_fold_count {
            catalog.insert(challenge_descriptor(
                RelationChallengeRole::FriFold,
                vec![u64::from(fold_ordinal)],
                1,
                self,
                context,
            )?);
        }
        catalog.insert(challenge_descriptor(
            RelationChallengeRole::QueryPosition,
            vec![0],
            context.unique_query_count,
            self,
            context,
        )?);
        let catalog = catalog.into_iter().collect::<Vec<_>>();
        validate_challenge_catalog(&catalog, self, context)?;
        Ok(catalog)
    }

    pub(crate) fn derived_challenge_epoch_catalogs(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationChallengeEpochCatalog>, RelationPlanError> {
        let mut descriptors_by_epoch = BTreeMap::<u16, Vec<_>>::new();
        for descriptor in self.derived_challenge_catalog(context)? {
            descriptors_by_epoch
                .entry(descriptor.epoch)
                .or_default()
                .push(descriptor);
        }
        let query_epoch = 4_u16
            .checked_add(context.fri_fold_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        descriptors_by_epoch
            .into_iter()
            .map(|(epoch, ordered_descriptors)| {
                let preceding_message = match epoch {
                    1 => RelationChallengeEpochPrecedingMessage::BaseRoots,
                    2 => RelationChallengeEpochPrecedingMessage::AuxiliaryRoots,
                    3 => RelationChallengeEpochPrecedingMessage::QuotientRoots,
                    4 => RelationChallengeEpochPrecedingMessage::DeepValuesAndOpeningBatchMask,
                    value if value == query_epoch => {
                        RelationChallengeEpochPrecedingMessage::FriTerminal
                    }
                    value if value > 4 && value < query_epoch => {
                        RelationChallengeEpochPrecedingMessage::FriLayerRoot(value - 5)
                    }
                    _ => return Err(RelationPlanError::InvalidChallengeCatalog),
                };
                Ok(RelationChallengeEpochCatalog {
                    epoch,
                    preceding_message,
                    ordered_descriptors,
                })
            })
            .collect()
    }

    pub(crate) fn common_proof_transcript_schedule(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<CommonProofTranscriptSchedule, RelationPlanError> {
        let mut next_base_tree_ordinal = 0_u16;
        let mut next_auxiliary_tree_ordinal = 0_u16;
        let mut ordered_base_tree_ordinals = Vec::new();
        let mut ordered_auxiliary_tree_ordinals = Vec::new();
        for tree in &self.ordered_trees {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role, ..
            } = tree
            else {
                continue;
            };
            match *proof_tree_role {
                1 => {
                    ordered_base_tree_ordinals.push(next_base_tree_ordinal);
                    next_base_tree_ordinal = next_base_tree_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                }
                2 => {
                    ordered_auxiliary_tree_ordinals.push(next_auxiliary_tree_ordinal);
                    next_auxiliary_tree_ordinal = next_auxiliary_tree_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                }
                _ => return Err(RelationPlanError::InvalidRoot),
            }
        }

        let mut application_group_inputs =
            BTreeMap::<CommonProofChallenge, (u64, BTreeSet<u16>)>::new();
        for descriptor in
            self.derived_challenge_catalog(context)?
                .into_iter()
                .filter(|descriptor| {
                    matches!(
                        descriptor.role,
                        RelationChallengeRole::NonNativeTheta
                            | RelationChallengeRole::NonNativeAlpha
                    )
                })
        {
            let modulus_ordinal = u16::try_from(descriptor.role_coordinates[0])
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let repetition_ordinal = u16::try_from(descriptor.role_coordinates[1])
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let challenge = match descriptor.role {
                RelationChallengeRole::NonNativeTheta => {
                    CommonProofChallenge::Theta { modulus_ordinal }
                }
                RelationChallengeRole::NonNativeAlpha => {
                    CommonProofChallenge::Alpha { modulus_ordinal }
                }
                _ => return Err(RelationPlanError::InvalidChallengeCatalog),
            };
            let sampling = descriptor.resolved_sampling(self, context)?;
            if sampling.coordinate_count != context.non_native_modular_identity_challenge_count {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            let (group_modulus, repetition_ordinals) = application_group_inputs
                .entry(challenge)
                .or_insert_with(|| (sampling.coordinate_modulus, BTreeSet::new()));
            if *group_modulus != sampling.coordinate_modulus {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            repetition_ordinals.insert(repetition_ordinal);
        }
        let expected_repetition_ordinals =
            (0..context.non_native_modular_identity_challenge_count).collect::<BTreeSet<_>>();
        let ordered_application_challenge_groups = application_group_inputs
            .into_iter()
            .map(|(challenge, (modulus, repetition_ordinals))| {
                if repetition_ordinals != expected_repetition_ordinals {
                    return Err(RelationPlanError::InvalidChallengeCatalog);
                }
                CommonProofApplicationChallengeGroup::new(
                    challenge,
                    modulus,
                    context.non_native_modular_identity_challenge_count,
                )
                .map_err(|_| RelationPlanError::InvalidChallengeCatalog)
            })
            .collect::<Result<Vec<_>, _>>()?;

        CommonProofTranscriptSchedule::new(
            ordered_base_tree_ordinals,
            ordered_application_challenge_groups,
            ordered_auxiliary_tree_ordinals,
            u16::try_from(self.ordered_constraints.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            u16::try_from(context.quotient_component_count)
                .map_err(|_| RelationPlanError::CountOverflow)?,
            context.deep_point_count,
            u16::try_from(self.ordered_opening_claims.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            context.fri_fold_count,
            context.final_polynomial_degree_bound_exclusive,
            context.unique_query_count,
            self.evaluation_domain_size
                .checked_div(2)
                .filter(|count| *count > 0)
                .ok_or(RelationPlanError::InvalidDomain)?,
            context.maximum_fiat_shamir_candidate_draws_per_output,
            match self.proof_privacy_mode {
                ProofPrivacyMode::PublicOnly => CommonProofPrivacyMode::PublicOnly,
                ProofPrivacyMode::SecretBearing => CommonProofPrivacyMode::SecretBearing,
            },
        )
        .map_err(|_| RelationPlanError::InvalidChallengeCatalog)
    }
}

fn challenge_descriptor(
    role: RelationChallengeRole,
    role_coordinates: Vec<u64>,
    value_count: u32,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<RelationChallengeDescriptor, RelationPlanError> {
    let epoch = match role {
        RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha => 1,
        RelationChallengeRole::ConstraintComposition => 2,
        RelationChallengeRole::DeepPoint => 3,
        RelationChallengeRole::OpeningBatch => 4,
        RelationChallengeRole::FriFold => 4_u16
            .checked_add(
                role_coordinates
                    .first()
                    .copied()
                    .and_then(|ordinal| u16::try_from(ordinal).ok())
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?,
        RelationChallengeRole::QueryPosition => 4_u16
            .checked_add(context.fri_fold_count)
            .ok_or(RelationPlanError::CountOverflow)?,
    };
    let sampling = match role {
        RelationChallengeRole::NonNativeTheta => {
            let modulus_ordinal = role_coordinates
                .first()
                .copied()
                .and_then(|ordinal| u16::try_from(ordinal).ok())
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            RelationChallengeSampling::ProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(
                    modulus_ordinal,
                ),
                coordinate_count: context.non_native_modular_identity_challenge_count,
                maximum_candidate_draws_per_output: context
                    .maximum_fiat_shamir_candidate_draws_per_output,
            }
        }
        RelationChallengeRole::NonNativeAlpha => {
            let modulus_ordinal = role_coordinates
                .first()
                .copied()
                .and_then(|ordinal| u16::try_from(ordinal).ok())
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            RelationChallengeSampling::PowerOfProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(
                    modulus_ordinal,
                ),
                coordinate_count: context.non_native_modular_identity_challenge_count,
                maximum_candidate_draws_per_output: context
                    .maximum_fiat_shamir_candidate_draws_per_output,
            }
        }
        RelationChallengeRole::ConstraintComposition
        | RelationChallengeRole::OpeningBatch
        | RelationChallengeRole::FriFold => RelationChallengeSampling::IndependentResidues {
            modulus_selector: RelationChallengeModulusSelector::BaseField,
            coordinate_count: context.challenge_extension_degree,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        },
        RelationChallengeRole::DeepPoint => RelationChallengeSampling::NonzeroExtensionVectors {
            base_modulus_selector: RelationChallengeModulusSelector::BaseField,
            coordinate_count: context.challenge_extension_degree,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        },
        RelationChallengeRole::QueryPosition => RelationChallengeSampling::DistinctPositions {
            position_count_selector: RelationChallengeModulusSelector::QueryOrbitCount,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        },
    };
    let descriptor = RelationChallengeDescriptor {
        epoch,
        role,
        role_coordinates,
        value_count,
        sampling,
    };
    descriptor.validate(variant, context)?;
    Ok(descriptor)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofApplicationSlotTemplate {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

impl ProofApplicationSlotTemplate {
    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        let schedule_item = self.schedule_position.map(CanonicalItem::unsigned32);
        let top_count_item = self.top_count.map(CanonicalItem::unsigned16);
        CanonicalTuple::new(
            PROOF_APPLICATION_SLOT_TEMPLATE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::optional(CanonicalItemType::Unsigned32, schedule_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(CanonicalItemType::Unsigned16, top_count_item.as_ref())
                    .map_err(canonical_encoding_error)?,
            ],
        )
        .encode()
        .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RelationPlan {
    application_statement_schema_identifier: u16,
    variants: Vec<RelationPlanVariant>,
}

impl RelationPlan {
    fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_PLAN_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                canonical_nested_list(
                    self.variants
                        .iter()
                        .map(RelationPlanVariant::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        encode_generated_tuple(&self.canonical_tuple()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompiledRelationPlan {
    plan: RelationPlan,
}

impl CompiledRelationPlan {
    pub(crate) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        self.plan.canonical_tuple()
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.plan.canonical_bytes()
    }

    pub(crate) fn encode_canonical_tuple(
        &self,
        canonical_tuple: &CanonicalTuple,
    ) -> Result<Vec<u8>, RelationPlanError> {
        encode_generated_tuple(canonical_tuple)
    }

    pub(crate) fn canonical_hash(&self) -> Result<[u8; 64], RelationPlanError> {
        hash_generated_variable_bytes(RELATION_PLAN_HASH_DOMAIN, &self.canonical_bytes()?)
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.plan.application_statement_schema_identifier
    }

    pub(crate) fn variants(&self) -> &[RelationPlanVariant] {
        &self.plan.variants
    }

    pub(crate) fn select_variant(
        &self,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<&RelationPlanVariant, RelationPlanError> {
        let mut matches = self.plan.variants.iter().filter(|variant| {
            variant.schedule_position == schedule_position && variant.top_count == top_count
        });
        let selected = matches
            .next()
            .ok_or(RelationPlanError::InvalidVariantSelector)?;
        if matches.next().is_some() {
            return Err(RelationPlanError::DuplicateVariant);
        }
        Ok(selected)
    }

    pub(crate) fn application_slot_templates(&self) -> Result<Vec<Vec<u8>>, RelationPlanError> {
        self.plan
            .variants
            .iter()
            .map(|variant| {
                ProofApplicationSlotTemplate {
                    application_statement_schema_identifier: self
                        .plan
                        .application_statement_schema_identifier,
                    schedule_position: variant.schedule_position,
                    top_count: variant.top_count,
                }
                .canonical_bytes()
            })
            .collect()
    }

    pub(crate) fn check(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        RelationPlanChecker::new(context).check(self)
    }
}

pub(crate) fn merge_checked_relation_plan_variants(
    application_statement_schema_identifier: u16,
    plans: Vec<CompiledRelationPlan>,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    if plans.is_empty()
        || plans.iter().any(|plan| {
            plan.application_statement_schema_identifier()
                != application_statement_schema_identifier
        })
    {
        return Err(RelationPlanError::UnsupportedApplicationFamily);
    }

    let variants = plans
        .into_iter()
        .flat_map(|plan| plan.plan.variants)
        .collect::<Vec<_>>();
    let merged = CompiledRelationPlan {
        plan: RelationPlan {
            application_statement_schema_identifier,
            variants,
        },
    };
    merged.check(context)?;
    Ok(merged)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedSuiteModulus {
    reference: SuiteModulusReference,
    modulus: u64,
}

impl ResolvedSuiteModulus {
    pub(crate) const fn new(reference: SuiteModulusReference, modulus: u64) -> Self {
        Self { reference, modulus }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanCheckContext {
    pub(crate) base_field_modulus: u64,
    pub(crate) challenge_extension_degree: u16,
    pub(crate) evaluation_blowup_factor: u32,
    pub(crate) evaluation_domain_generator: u64,
    pub(crate) evaluation_coset_offset: u64,
    pub(crate) deep_point_count: u16,
    pub(crate) quotient_component_count: u32,
    pub(crate) quotient_component_degree_bound_exclusive: u64,
    pub(crate) fri_fold_count: u16,
    pub(crate) final_polynomial_degree_bound_exclusive: u32,
    pub(crate) unique_query_count: u32,
    pub(crate) non_native_modular_identity_challenge_count: u16,
    pub(crate) maximum_fiat_shamir_candidate_draws_per_output: u32,
    pub(crate) resolved_moduli: Vec<ResolvedSuiteModulus>,
}

impl RelationPlanCheckContext {
    pub(crate) fn resolved_modulus(
        &self,
        reference: SuiteModulusReference,
    ) -> Result<u64, RelationPlanError> {
        self.resolved_moduli
            .binary_search_by_key(&reference, |entry| entry.reference)
            .ok()
            .map(|index| self.resolved_moduli[index].modulus)
            .ok_or(RelationPlanError::MissingModulus)
    }
}

#[derive(Default)]
struct ApplicationExtractorPhaseColumns {
    derived_base_columns: BTreeSet<u32>,
    derived_auxiliary_columns: BTreeSet<u32>,
}

struct RelationPlanChecker<'context> {
    context: &'context RelationPlanCheckContext,
}

impl<'context> RelationPlanChecker<'context> {
    fn new(context: &'context RelationPlanCheckContext) -> Self {
        Self { context }
    }

    fn check(&self, compiled: &CompiledRelationPlan) -> Result<(), RelationPlanError> {
        self.check_context()?;
        let plan = &compiled.plan;
        let expected_privacy_mode =
            ProofPrivacyMode::for_family(plan.application_statement_schema_identifier)
                .ok_or(RelationPlanError::UnsupportedApplicationFamily)?;
        if plan.variants.is_empty() {
            return Err(RelationPlanError::InvalidVariantSelector);
        }
        let mut selectors = BTreeSet::new();
        for variant in &plan.variants {
            self.check_variant_selector(plan.application_statement_schema_identifier, variant)?;
            if !selectors.insert((variant.schedule_position, variant.top_count)) {
                return Err(RelationPlanError::DuplicateVariant);
            }
            if variant.proof_privacy_mode != expected_privacy_mode {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            self.check_variant(plan.application_statement_schema_identifier, variant)?;
        }
        Ok(())
    }

    fn check_context(&self) -> Result<(), RelationPlanError> {
        if self.context.base_field_modulus < 3
            || self.context.base_field_modulus.is_multiple_of(2)
            || self.context.challenge_extension_degree == 0
            || self.context.evaluation_blowup_factor == 0
            || !self.context.evaluation_blowup_factor.is_power_of_two()
            || self.context.evaluation_domain_generator == 0
            || self.context.evaluation_domain_generator >= self.context.base_field_modulus
            || self.context.evaluation_coset_offset == 0
            || self.context.evaluation_coset_offset >= self.context.base_field_modulus
            || self.context.deep_point_count == 0
            || self.context.quotient_component_count < 2
            || self.context.quotient_component_degree_bound_exclusive == 0
            || self.context.fri_fold_count == 0
            || self.context.final_polynomial_degree_bound_exclusive == 0
            || self.context.unique_query_count == 0
            || self.context.non_native_modular_identity_challenge_count == 0
            || self.context.maximum_fiat_shamir_candidate_draws_per_output == 0
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        if !strictly_sorted_unique_by_key(&self.context.resolved_moduli, |entry| entry.reference) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for resolved in &self.context.resolved_moduli {
            if resolved.reference.catalog == ModulusCatalog::ProofField
                || resolved.modulus < 3
                || resolved.modulus >= self.context.base_field_modulus
            {
                return Err(RelationPlanError::InvalidModulus);
            }
        }
        Ok(())
    }

    fn check_variant_selector(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        let valid = match application_statement_schema_identifier {
            0x1214..=0x1217 => variant.schedule_position.is_some() && variant.top_count.is_none(),
            0x1218 => {
                variant.schedule_position.is_none() && matches!(variant.top_count, Some(1..=20))
            }
            _ => variant.schedule_position.is_none() && variant.top_count.is_none(),
        };
        if !valid {
            return Err(RelationPlanError::InvalidVariantSelector);
        }
        Ok(())
    }

    fn check_variant(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        self.check_domains(variant)?;
        self.check_moduli(variant)?;
        self.check_sources_and_samplers(variant)?;
        let semantic_bounds = self.check_columns_and_semantic_cells(variant)?;
        self.check_radix_convolutions(variant, &semantic_bounds)?;
        self.check_trees(variant)?;
        self.check_constraints(variant, &semantic_bounds)?;
        self.check_coefficient_local_identity_batches(
            application_statement_schema_identifier,
            variant,
            &semantic_bounds,
        )?;
        let extractor_phase_columns = self.check_integer_lift_batches(
            application_statement_schema_identifier,
            variant,
            &semantic_bounds,
        )?;
        self.check_application_extractor_phase_ownership(variant, &extractor_phase_columns)?;
        self.check_openings(variant)?;
        self.check_masks(variant)?;
        super::validate_zero_knowledge_mask_image(variant, self.context)?;
        let challenge_catalog = variant.derived_challenge_catalog(self.context)?;
        validate_challenge_catalog(&challenge_catalog, variant, self.context)?;
        let epoch_catalogs = variant.derived_challenge_epoch_catalogs(self.context)?;
        if epoch_catalogs.is_empty() {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        for epoch_catalog in epoch_catalogs {
            let _ = epoch_catalog.canonical_catalog_bytes()?;
        }
        let _ = variant.common_proof_transcript_schedule(self.context)?;
        Ok(())
    }

    fn check_domains(&self, variant: &RelationPlanVariant) -> Result<(), RelationPlanError> {
        if variant.trace_domain_size == 0
            || !variant.trace_domain_size.is_power_of_two()
            || variant.evaluation_domain_size == 0
            || !variant.evaluation_domain_size.is_power_of_two()
            || !variant
                .evaluation_domain_size
                .is_multiple_of(variant.trace_domain_size)
            || variant.opening_degree_bound_exclusive <= 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let next_degree_domain = variant
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        let expected_evaluation_domain = next_degree_domain
            .checked_mul(u64::from(self.context.evaluation_blowup_factor))
            .ok_or(RelationPlanError::CountOverflow)?;
        if expected_evaluation_domain != variant.evaluation_domain_size
            || !(self.context.base_field_modulus - 1).is_multiple_of(variant.evaluation_domain_size)
            || modular_power(
                self.context.evaluation_domain_generator,
                variant.evaluation_domain_size,
                self.context.base_field_modulus,
            ) != 1
            || modular_power(
                self.context.evaluation_domain_generator,
                variant.evaluation_domain_size / 2,
                self.context.base_field_modulus,
            ) == 1
            || modular_power(
                self.context.evaluation_coset_offset,
                variant.trace_domain_size,
                self.context.base_field_modulus,
            ) == 1
            || modular_power(
                self.context.evaluation_coset_offset,
                variant.evaluation_domain_size,
                self.context.base_field_modulus,
            ) == 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let initial_fri_degree_bound_exclusive = variant
            .opening_degree_bound_exclusive
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidDomain)?;
        let final_degree_bound = u64::from(self.context.final_polynomial_degree_bound_exclusive);
        if final_degree_bound >= initial_fri_degree_bound_exclusive {
            return Err(RelationPlanError::InvalidDomain);
        }
        let mut folded_degree_bound = initial_fri_degree_bound_exclusive;
        let mut expected_fold_count = 0_u16;
        while folded_degree_bound > final_degree_bound {
            folded_degree_bound = folded_degree_bound
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?
                / 2;
            expected_fold_count = expected_fold_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        if expected_fold_count != self.context.fri_fold_count {
            return Err(RelationPlanError::InvalidDomain);
        }
        Ok(())
    }

    fn check_moduli(&self, variant: &RelationPlanVariant) -> Result<(), RelationPlanError> {
        if !strictly_sorted_unique(&variant.ordered_non_native_moduli)
            || variant
                .ordered_non_native_moduli
                .iter()
                .any(|reference| reference.catalog == ModulusCatalog::ProofField)
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for reference in &variant.ordered_non_native_moduli {
            let modulus = self.context.resolved_modulus(*reference)?;
            if modulus >= self.context.base_field_modulus {
                return Err(RelationPlanError::InvalidModulus);
            }
        }
        let used = self.used_moduli(variant)?;
        let declared = variant
            .ordered_non_native_moduli
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if used != declared {
            return Err(if used.is_subset(&declared) {
                RelationPlanError::UnusedModulus
            } else {
                RelationPlanError::MissingModulus
            });
        }
        Ok(())
    }

    fn used_moduli(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<BTreeSet<SuiteModulusReference>, RelationPlanError> {
        let mut used = BTreeSet::new();
        for source in &variant.ordered_verifier_sources {
            if let RelationVerifierSource::ApplicationStatement { value_layout, .. }
            | RelationVerifierSource::Protocol { value_layout, .. }
            | RelationVerifierSource::Suite { value_layout, .. }
            | RelationVerifierSource::ApplicationSlot { value_layout, .. } = source
                && let Some(modulus) = value_layout.residue_modulus
            {
                used.insert(modulus);
            }
            if let RelationVerifierSource::RadixDecomposition {
                modulus_reference, ..
            } = source
            {
                used.insert(*modulus_reference);
            }
        }
        for sampler in &variant.ordered_public_samplers {
            used.insert(sampler.output_modulus);
        }
        for column in &variant.ordered_columns {
            if let Some(modulus_reference) = column.canonical_residue_modulus {
                used.insert(modulus_reference);
            }
        }
        for semantic_cell in &variant.ordered_semantic_cells {
            if let RelationBoundCertificate::CanonicalModulusRecomposition {
                modulus_reference,
                ..
            } = &semantic_cell.bound_certificate
            {
                used.insert(*modulus_reference);
            }
        }
        for constraint in &variant.ordered_constraints {
            for instruction in &constraint.numerator_postfix_expression {
                match instruction {
                    RelationExpressionInstruction::TranscriptChallenge {
                        challenge_role:
                            RelationChallengeRole::NonNativeTheta
                            | RelationChallengeRole::NonNativeAlpha,
                        role_coordinates,
                    } => {
                        let modulus_ordinal = role_coordinates
                            .first()
                            .copied()
                            .and_then(|ordinal| usize::try_from(ordinal).ok())
                            .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                        used.insert(
                            variant
                                .ordered_non_native_moduli
                                .get(modulus_ordinal)
                                .copied()
                                .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
                        );
                    }
                    RelationExpressionInstruction::NonNativeModulusConstant {
                        modulus_reference,
                        ..
                    } => {
                        used.insert(*modulus_reference);
                    }
                    _ => {}
                }
            }
        }
        for factor in variant
            .ordered_radix_convolutions
            .iter()
            .flat_map(|convolution| &convolution.ordered_terms)
            .flat_map(|term| &term.ordered_factors)
        {
            match factor {
                RelationRadixFactorDescriptor::TranscriptChallengeDigits {
                    challenge_role:
                        RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha,
                    role_coordinates,
                    ..
                } => {
                    let modulus_ordinal = role_coordinates
                        .first()
                        .copied()
                        .and_then(|ordinal| usize::try_from(ordinal).ok())
                        .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                    used.insert(
                        variant
                            .ordered_non_native_moduli
                            .get(modulus_ordinal)
                            .copied()
                            .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
                    );
                }
                RelationRadixFactorDescriptor::NonNativeModulusDigits {
                    modulus_reference, ..
                } => {
                    used.insert(*modulus_reference);
                }
                _ => {}
            }
        }
        Ok(used)
    }

    fn check_sources_and_samplers(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        let source_bytes = variant
            .ordered_verifier_sources
            .iter()
            .map(RelationVerifierSource::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted_unique(&source_bytes) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for source in &variant.ordered_verifier_sources {
            source.validate_shape()?;
            if let RelationVerifierSource::RadixDecomposition {
                modulus_reference,
                scale,
                radix,
                digit_count,
                ..
            } = source
            {
                let modulus = self.context.resolved_modulus(*modulus_reference)?;
                let maximum_scaled = u128::from(modulus - 1)
                    .checked_mul(u128::from(*scale))
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?;
                let capacity = (0..*digit_count).try_fold(1_u128, |capacity, _| {
                    capacity
                        .checked_mul(u128::from(*radix))
                        .ok_or(RelationPlanError::IntegerBoundOverflow)
                })?;
                if maximum_scaled >= capacity
                    || (*digit_count > 1
                        && maximum_scaled
                            < (0..(*digit_count - 1)).try_fold(1_u128, |capacity, _| {
                                capacity
                                    .checked_mul(u128::from(*radix))
                                    .ok_or(RelationPlanError::IntegerBoundOverflow)
                            })?)
                {
                    return Err(RelationPlanError::InvalidSource);
                }
            }
        }
        if !variant
            .ordered_public_samplers
            .windows(2)
            .all(|window| window[0].canonical_order_key() < window[1].canonical_order_key())
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let mut consumed_sources = BTreeSet::new();
        for sampler in &variant.ordered_public_samplers {
            if sampler.output_count == 0
                || !sampler.role_domain.starts_with("sealed-lattice/proof/")
                || !sampler.role_domain.ends_with("/v1")
            {
                return Err(RelationPlanError::InvalidSampler);
            }
            let seed = variant
                .ordered_verifier_sources
                .get(sampler.seed_verifier_source_ordinal as usize)
                .ok_or(RelationPlanError::InvalidSampler)?;
            if matches!(seed, RelationVerifierSource::SamplerOutput { .. })
                || seed.value_layout(
                    &variant.ordered_public_samplers,
                    &variant.ordered_verifier_sources,
                )? != RelationValueLayout::scalar_hash()
            {
                return Err(RelationPlanError::SourceCycle);
            }
            let output = variant
                .ordered_verifier_sources
                .get(sampler.output_verifier_source_ordinal as usize)
                .ok_or(RelationPlanError::InvalidSampler)?;
            if !matches!(
                output,
                RelationVerifierSource::SamplerOutput {
                    public_sampler_ordinal
                } if *public_sampler_ordinal as usize
                    == variant
                        .ordered_public_samplers
                        .iter()
                        .position(|candidate| candidate == sampler)
                        .ok_or(RelationPlanError::InvalidSampler)?
            ) {
                return Err(RelationPlanError::InvalidSampler);
            }
            consumed_sources.insert(sampler.seed_verifier_source_ordinal);
        }
        for column in &variant.ordered_columns {
            match column.origin {
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal,
                    ..
                } => {
                    consumed_sources.insert(verifier_source_ordinal);
                }
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                } => {
                    consumed_sources.insert(expected_root_source_ordinal);
                }
                RelationColumnOrigin::Prover => {}
            }
        }
        if consumed_sources.len() != variant.ordered_verifier_sources.len() {
            return Err(RelationPlanError::UnusedSource);
        }
        Ok(())
    }

    fn check_columns_and_semantic_cells(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<BTreeMap<u32, SignedIntegerInterval>, RelationPlanError> {
        if variant.ordered_columns.is_empty() {
            return Err(RelationPlanError::InvalidColumn);
        }
        let mut verifier_columns_by_source = BTreeMap::<u32, Vec<(u64, u64)>>::new();
        let mut expected_semantic_ordinal = 0_u32;
        let mut semantic_columns = BTreeSet::new();
        for cell in &variant.ordered_semantic_cells {
            if cell.semantic_cell_ordinal != expected_semantic_ordinal
                || cell.claimed_interval.minimum > cell.claimed_interval.maximum
                || !semantic_columns.insert(cell.column_ordinal)
            {
                return Err(RelationPlanError::InvalidSemanticCell);
            }
            let column = variant
                .ordered_columns
                .get(cell.column_ordinal as usize)
                .ok_or(RelationPlanError::InvalidSemanticCell)?;
            if column.value_type != RelationColumnValueType::BaseField {
                return Err(RelationPlanError::InvalidSemanticCell);
            }
            expected_semantic_ordinal = expected_semantic_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        for column in &variant.ordered_columns {
            if column.source_degree_bound_exclusive == 0
                || column.source_degree_bound_exclusive > variant.opening_degree_bound_exclusive
                || (column.canonical_residue_modulus.is_some()
                    && (column.value_type != RelationColumnValueType::BaseField
                        || matches!(column.origin, RelationColumnOrigin::Prover)))
            {
                return Err(
                    if column.source_degree_bound_exclusive == 0
                        || column.source_degree_bound_exclusive
                            > variant.opening_degree_bound_exclusive
                    {
                        RelationPlanError::DegreeBoundExceeded
                    } else {
                        RelationPlanError::InvalidColumn
                    },
                );
            }
            match column.origin {
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal,
                    first_logical_element_index,
                    logical_element_stride,
                } => {
                    let layout = variant
                        .ordered_verifier_sources
                        .get(verifier_source_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidColumn)?
                        .value_layout(
                            &variant.ordered_public_samplers,
                            &variant.ordered_verifier_sources,
                        )?;
                    let last_trace_row = variant.trace_domain_size - 1;
                    let last_index = first_logical_element_index
                        .checked_add(
                            last_trace_row
                                .checked_mul(logical_element_stride)
                                .ok_or(RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::CountOverflow)?;
                    if last_index >= layout.logical_element_count()?
                        || matches!(layout.element_kind, RelationElementKind::Hash512)
                    {
                        return Err(RelationPlanError::InvalidColumn);
                    }
                    verifier_columns_by_source
                        .entry(verifier_source_ordinal)
                        .or_default()
                        .push((first_logical_element_index, logical_element_stride));
                }
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                } => {
                    let layout = variant
                        .ordered_verifier_sources
                        .get(expected_root_source_ordinal as usize)
                        .ok_or(RelationPlanError::MissingRoot)?
                        .value_layout(
                            &variant.ordered_public_samplers,
                            &variant.ordered_verifier_sources,
                        )?;
                    if layout != RelationValueLayout::scalar_hash() {
                        return Err(RelationPlanError::InvalidRoot);
                    }
                }
                RelationColumnOrigin::Prover => {}
            }
        }
        for (source_ordinal, source) in variant.ordered_verifier_sources.iter().enumerate() {
            let source_ordinal =
                u32::try_from(source_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            let layout = source.value_layout(
                &variant.ordered_public_samplers,
                &variant.ordered_verifier_sources,
            )?;
            if matches!(layout.element_kind, RelationElementKind::Hash512) {
                if verifier_columns_by_source.contains_key(&source_ordinal) {
                    return Err(RelationPlanError::InvalidColumn);
                }
                continue;
            }
            let logical_element_count = layout.logical_element_count()?;
            let mappings = verifier_columns_by_source
                .get_mut(&source_ordinal)
                .ok_or(RelationPlanError::InvalidColumn)?;
            mappings.sort_unstable();
            if logical_element_count == 1 {
                if mappings.as_slice() != [(0, 0)] {
                    return Err(RelationPlanError::InvalidColumn);
                }
                continue;
            }
            if !logical_element_count.is_multiple_of(variant.trace_domain_size) {
                return Err(RelationPlanError::InvalidColumn);
            }
            let expected_mapping_count = logical_element_count / variant.trace_domain_size;
            if u64::try_from(mappings.len()).map_err(|_| RelationPlanError::CountOverflow)?
                != expected_mapping_count
            {
                return Err(RelationPlanError::InvalidColumn);
            }
            for (mapping_ordinal, (first_logical_element_index, logical_element_stride)) in
                mappings.iter().copied().enumerate()
            {
                let expected_first = u64::try_from(mapping_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?
                    .checked_mul(variant.trace_domain_size)
                    .ok_or(RelationPlanError::CountOverflow)?;
                if first_logical_element_index != expected_first || logical_element_stride != 1 {
                    return Err(RelationPlanError::InvalidColumn);
                }
            }
        }
        self.derive_semantic_bounds(variant)
    }

    fn derive_semantic_bounds(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<BTreeMap<u32, SignedIntegerInterval>, RelationPlanError> {
        let semantic_cells_by_column = variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| (cell.column_ordinal, cell))
            .collect::<BTreeMap<_, _>>();
        if semantic_cells_by_column.len() != variant.ordered_semantic_cells.len() {
            return Err(RelationPlanError::InvalidSemanticCell);
        }

        let mut derived_intervals = BTreeMap::new();
        let mut active_columns = BTreeSet::new();
        for column_ordinal in semantic_cells_by_column.keys().copied() {
            derive_semantic_cell_interval(
                column_ordinal,
                &semantic_cells_by_column,
                &variant.ordered_constraints,
                variant.trace_domain_size,
                self.context,
                &mut derived_intervals,
                &mut active_columns,
            )?;
        }
        for (column_ordinal, column) in variant.ordered_columns.iter().enumerate() {
            if let Some(modulus_reference) = column.canonical_residue_modulus {
                let column_ordinal =
                    u32::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
                let modulus = self.context.resolved_modulus(modulus_reference)?;
                let canonical_interval = match column.origin {
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal,
                        ..
                    } => {
                        let layout = variant
                            .ordered_verifier_sources
                            .get(verifier_source_ordinal as usize)
                            .ok_or(RelationPlanError::InvalidSource)?
                            .value_layout(
                                &variant.ordered_public_samplers,
                                &variant.ordered_verifier_sources,
                            )?;
                        if layout.element_kind != RelationElementKind::Residue
                            || layout.residue_modulus != Some(modulus_reference)
                        {
                            return Err(RelationPlanError::InvalidColumn);
                        }
                        match layout.embedding_kind {
                            RelationEmbeddingKind::LeastNonnegative => {
                                SignedIntegerInterval::from_bigints(
                                    BigInt::zero(),
                                    BigInt::from(modulus - 1),
                                )?
                            }
                            RelationEmbeddingKind::Centered => {
                                let absolute_bound = (modulus - 1) / 2;
                                SignedIntegerInterval::from_bigints(
                                    -BigInt::from(absolute_bound),
                                    BigInt::from(absolute_bound),
                                )?
                            }
                            _ => return Err(RelationPlanError::InvalidColumn),
                        }
                    }
                    RelationColumnOrigin::BoundTree { .. }
                        if integer_lift_bound_tree_has_canonical_residue_capability(
                            column_ordinal,
                            variant,
                        ) =>
                    {
                        SignedIntegerInterval::from_bigints(
                            BigInt::zero(),
                            BigInt::from(modulus - 1),
                        )?
                    }
                    RelationColumnOrigin::BoundTree { .. } => continue,
                    RelationColumnOrigin::Prover => {
                        return Err(RelationPlanError::InvalidColumn);
                    }
                };
                if let Some(derived_interval) = derived_intervals.get(&column_ordinal) {
                    if derived_interval != &canonical_interval {
                        return Err(RelationPlanError::InvalidSemanticCell);
                    }
                } else {
                    derived_intervals.insert(column_ordinal, canonical_interval);
                }
            }
        }
        Ok(derived_intervals)
    }

    fn check_radix_convolutions(
        &self,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        let mut referenced_convolutions = BTreeSet::new();
        for constraint in &variant.ordered_constraints {
            for instruction in &constraint.numerator_postfix_expression {
                if let RelationExpressionInstruction::RadixConvolutionCoefficient {
                    convolution_ordinal,
                    ..
                } = instruction
                {
                    referenced_convolutions.insert(*convolution_ordinal);
                }
            }
        }
        if referenced_convolutions
            != (0..variant.ordered_radix_convolutions.len())
                .map(|ordinal| u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow))
                .collect::<Result<BTreeSet<_>, _>>()?
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let mut convolution_bytes = BTreeSet::new();
        for convolution in &variant.ordered_radix_convolutions {
            if !(2..self.context.base_field_modulus).contains(&convolution.radix)
                || convolution.ordered_terms.is_empty()
                || !convolution_bytes.insert(
                    convolution
                        .canonical_tuple()?
                        .encode()
                        .map_err(canonical_encoding_error)?,
                )
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let binary_interval = SignedIntegerInterval::new(0, 1);
            let term_bytes = convolution
                .ordered_terms
                .iter()
                .map(RelationRadixProductTermDescriptor::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            if !strictly_sorted_unique(&term_bytes) {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
            for term in &convolution.ordered_terms {
                if term.ordered_factors.is_empty() {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let factor_bytes = term
                    .ordered_factors
                    .iter()
                    .map(RelationRadixFactorDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                if !strictly_sorted_unique(&factor_bytes) {
                    return Err(RelationPlanError::NonCanonicalOrder);
                }
                for factor in &term.ordered_factors {
                    match factor {
                        RelationRadixFactorDescriptor::ColumnDigits {
                            ordered_column_ordinals,
                            rotation_is_negative,
                            rotation_magnitude,
                        } => {
                            if ordered_column_ordinals.is_empty()
                                || !strictly_sorted_unique(ordered_column_ordinals)
                                || (*rotation_is_negative && *rotation_magnitude == 0)
                                || *rotation_magnitude >= variant.trace_domain_size
                                || ordered_column_ordinals.iter().any(|column_ordinal| {
                                    semantic_bounds.get(column_ordinal).is_none_or(|interval| {
                                        interval.minimum < BigInt::zero()
                                            || interval.maximum
                                                > BigInt::from(convolution.radix - 1)
                                    })
                                })
                            {
                                return Err(RelationPlanError::InvalidBoundCertificate);
                            }
                        }
                        RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => {
                            if ordered_digits.is_empty()
                                || ordered_digits.last() == Some(&0)
                                || ordered_digits
                                    .iter()
                                    .any(|digit| *digit >= convolution.radix)
                            {
                                return Err(RelationPlanError::InvalidConstraint);
                            }
                        }
                        RelationRadixFactorDescriptor::TranscriptChallengeDigits {
                            challenge_role,
                            role_coordinates,
                            digit_count,
                        } => {
                            if !matches!(
                                challenge_role,
                                RelationChallengeRole::NonNativeTheta
                                    | RelationChallengeRole::NonNativeAlpha
                            ) {
                                return Err(RelationPlanError::InvalidChallengeCatalog);
                            }
                            let descriptor = challenge_descriptor(
                                *challenge_role,
                                role_coordinates.clone(),
                                1,
                                variant,
                                self.context,
                            )?;
                            let modulus = descriptor
                                .resolved_sampling(variant, self.context)?
                                .coordinate_modulus;
                            if *digit_count
                                != minimum_radix_digit_count(modulus - 1, convolution.radix)?
                            {
                                return Err(RelationPlanError::InvalidConstraint);
                            }
                        }
                        RelationRadixFactorDescriptor::NonNativeModulusDigits {
                            modulus_reference,
                            multiplier,
                            digit_count,
                        } => {
                            let value = resolved_modulus_multiple(
                                *modulus_reference,
                                *multiplier,
                                self.context,
                            )?;
                            if *digit_count != minimum_radix_digit_count(value, convolution.radix)?
                            {
                                return Err(RelationPlanError::InvalidConstraint);
                            }
                        }
                        RelationRadixFactorDescriptor::ScalarColumn { column_ordinal, .. } => {
                            if semantic_bounds.get(column_ordinal) != Some(&binary_interval) {
                                return Err(RelationPlanError::InvalidBoundCertificate);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn check_trees(&self, variant: &RelationPlanVariant) -> Result<(), RelationPlanError> {
        if variant.ordered_trees.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        let mut owned_columns = BTreeSet::new();
        for tree in &variant.ordered_trees {
            if tree.ordered_column_ordinals().is_empty()
                || !strictly_sorted_unique(tree.ordered_column_ordinals())
            {
                return Err(RelationPlanError::InvalidRoot);
            }
            match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                } if !matches!(proof_tree_role, 1 | 2) => {
                    return Err(RelationPlanError::InvalidRoot);
                }
                RelationTreeDescriptor::BoundPublic {
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                } => {
                    for ordinal in ordered_column_ordinals {
                        let column = variant
                            .ordered_columns
                            .get(*ordinal as usize)
                            .ok_or(RelationPlanError::InvalidRoot)?;
                        if !matches!(
                            column.origin,
                            RelationColumnOrigin::BoundTree {
                                expected_root_source_ordinal: source
                            } if source == *expected_root_source_ordinal
                        ) {
                            return Err(RelationPlanError::InvalidRoot);
                        }
                    }
                }
                _ => {}
            }
            for ordinal in tree.ordered_column_ordinals() {
                if *ordinal as usize >= variant.ordered_columns.len()
                    || !owned_columns.insert(*ordinal)
                {
                    return Err(RelationPlanError::InvalidRoot);
                }
            }
        }
        if owned_columns.len() != variant.ordered_columns.len() {
            return Err(RelationPlanError::MissingRoot);
        }
        Ok(())
    }

    fn check_constraints(
        &self,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if variant.ordered_constraints.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut roles = BTreeSet::new();
        let mut checked_zeroifiers = BTreeSet::new();
        for constraint in &variant.ordered_constraints {
            if !roles.insert((
                constraint.constraint_role,
                constraint.role_coordinates.clone(),
            )) {
                return Err(RelationPlanError::DuplicateItem);
            }
            let numerator = check_expression(
                &constraint.numerator_postfix_expression,
                variant,
                self.context,
                false,
            )?;
            if numerator.degree >= variant.opening_degree_bound_exclusive {
                return Err(RelationPlanError::DegreeBoundExceeded);
            }
            let zeroifier = check_expression(
                &constraint.zeroifier_postfix_expression,
                variant,
                self.context,
                true,
            )?;
            if zeroifier.degree == 0 && zeroifier.constant_value == Some(0) {
                return Err(RelationPlanError::InvalidZeroifier);
            }
            let zeroifier_bytes = canonical_nested_list(
                constraint
                    .zeroifier_postfix_expression
                    .iter()
                    .map(RelationExpressionInstruction::canonical_tuple)
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .canonical_bytes()
            .to_vec();
            if checked_zeroifiers.insert(zeroifier_bytes) {
                self.check_zeroifier_on_coset(
                    &constraint.zeroifier_postfix_expression,
                    variant.evaluation_domain_size,
                )?;
            }

            if constraint.enforce_proof_base_field_no_wrap {
                let referenced_columns =
                    expression_column_ordinals(&constraint.numerator_postfix_expression, variant)?;
                let declared_bounds = referenced_columns
                    .iter()
                    .map(|column_ordinal| {
                        semantic_bounds
                            .get(column_ordinal)
                            .cloned()
                            .map(|interval| (*column_ordinal, interval))
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let interval = evaluate_integer_interval(
                    &constraint.numerator_postfix_expression,
                    &declared_bounds,
                    variant,
                    self.context,
                )?;
                if !interval.is_injective_modulo(&BigInt::from(self.context.base_field_modulus)) {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
            }
            if !constraint
                .ordered_injective_integer_factor_expressions
                .is_empty()
            {
                if constraint.enforce_proof_base_field_no_wrap
                    || constraint
                        .ordered_injective_integer_factor_expressions
                        .len()
                        < 2
                    || constraint.numerator_postfix_expression
                        != ordered_injective_integer_factor_product_expression(
                            &constraint.ordered_injective_integer_factor_expressions,
                        )?
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                for factor_expression in &constraint.ordered_injective_integer_factor_expressions {
                    check_expression(factor_expression, variant, self.context, false)?;
                    let referenced_columns =
                        expression_column_ordinals(factor_expression, variant)?;
                    let declared_bounds = referenced_columns
                        .iter()
                        .map(|column_ordinal| {
                            semantic_bounds
                                .get(column_ordinal)
                                .cloned()
                                .map(|interval| (*column_ordinal, interval))
                                .ok_or(RelationPlanError::InvalidSemanticCell)
                        })
                        .collect::<Result<BTreeMap<_, _>, _>>()?;
                    let interval = evaluate_integer_interval(
                        factor_expression,
                        &declared_bounds,
                        variant,
                        self.context,
                    )?;
                    if !interval.is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
                    {
                        return Err(RelationPlanError::NoWrapBoundViolated);
                    }
                }
            }
        }
        Ok(())
    }

    fn check_zeroifier_on_coset(
        &self,
        expression: &[RelationExpressionInstruction],
        evaluation_domain_size: u64,
    ) -> Result<(), RelationPlanError> {
        let polynomial = compile_base_field_polynomial(
            expression,
            self.context.base_field_modulus,
            usize::try_from(evaluation_domain_size)
                .map_err(|_| RelationPlanError::CountOverflow)?,
        )?;
        if polynomial.iter().all(|coefficient| *coefficient == 0) {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        let mut point = self.context.evaluation_coset_offset;
        for _ in 0..evaluation_domain_size {
            if evaluate_polynomial(&polynomial, point, self.context.base_field_modulus) == 0 {
                return Err(RelationPlanError::ZeroifierVanishesOnEvaluationCoset);
            }
            point = modular_product(
                point,
                self.context.evaluation_domain_generator,
                self.context.base_field_modulus,
            );
        }
        Ok(())
    }

    fn check_coefficient_local_identity_batches(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if application_statement_schema_identifier == 0x2111 {
            return self.check_deterministic_coefficient_local_identities(variant, semantic_bounds);
        }
        let is_coefficient_local_family = application_statement_schema_identifier == 0x2110;
        if !is_coefficient_local_family {
            return if variant
                .ordered_coefficient_local_identity_batches
                .is_empty()
            {
                Ok(())
            } else {
                Err(RelationPlanError::InvalidConstraint)
            };
        }
        if variant
            .ordered_coefficient_local_identity_batches
            .is_empty()
            || !variant.ordered_integer_lift_batches.is_empty()
            || !variant.ordered_radix_convolutions.is_empty()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let canonical_batch_bytes = variant
            .ordered_coefficient_local_identity_batches
            .iter()
            .map(RelationCoefficientLocalIdentityBatchDescriptor::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted_unique(&canonical_batch_bytes) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let expected_batch_coordinates = variant
            .ordered_non_native_moduli
            .iter()
            .copied()
            .flat_map(|modulus_reference| {
                (0..self.context.non_native_modular_identity_challenge_count).flat_map(
                    move |challenge_ordinal| {
                        (0_u16..2).map(move |batch_ordinal| {
                            (modulus_reference, challenge_ordinal, batch_ordinal)
                        })
                    },
                )
            })
            .collect::<BTreeSet<_>>();
        let mut seen_batch_coordinates = BTreeSet::new();
        let mut matched_constraint_ordinals = BTreeSet::new();

        for batch in &variant.ordered_coefficient_local_identity_batches {
            let modulus_ordinal = u16::try_from(
                variant
                    .ordered_non_native_moduli
                    .binary_search(&batch.modulus_reference)
                    .map_err(|_| RelationPlanError::MissingModulus)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;
            if batch.challenge_ordinal >= self.context.non_native_modular_identity_challenge_count
                || batch.batch_ordinal >= 2
                || batch.ordered_residuals.is_empty()
                || !seen_batch_coordinates.insert((
                    batch.modulus_reference,
                    batch.challenge_ordinal,
                    batch.batch_ordinal,
                ))
            {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }

            let mut residual_bytes = BTreeSet::new();
            for (residual_index, residual) in batch.ordered_residuals.iter().enumerate() {
                if residual.unit_ordinal
                    != u32::try_from(residual_index)
                        .map_err(|_| RelationPlanError::CountOverflow)?
                    || residual.residual_postfix_expression.is_empty()
                    || residual
                        .residual_postfix_expression
                        .iter()
                        .any(|instruction| {
                            !matches!(
                                instruction,
                                RelationExpressionInstruction::BaseFieldConstant(_)
                                    | RelationExpressionInstruction::NonNativeModulusConstant { .. }
                                    | RelationExpressionInstruction::ColumnValue { .. }
                                    | RelationExpressionInstruction::Addition
                                    | RelationExpressionInstruction::Multiplication
                                    | RelationExpressionInstruction::Negation
                            )
                        })
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let residual_canonical_bytes = canonical_nested_list(
                    residual
                        .residual_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?
                .canonical_bytes()
                .to_vec();
                if !residual_bytes.insert(residual_canonical_bytes) {
                    return Err(RelationPlanError::DuplicateItem);
                }

                let referenced_moduli = residual
                    .residual_postfix_expression
                    .iter()
                    .filter_map(|instruction| match instruction {
                        RelationExpressionInstruction::NonNativeModulusConstant {
                            modulus_reference,
                            ..
                        } => Some(*modulus_reference),
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                if referenced_moduli != BTreeSet::from([batch.modulus_reference]) {
                    return Err(RelationPlanError::InvalidModulus);
                }
                check_expression(
                    &residual.residual_postfix_expression,
                    variant,
                    self.context,
                    false,
                )?;
                let referenced_columns =
                    expression_column_ordinals(&residual.residual_postfix_expression, variant)?;
                if referenced_columns.is_empty() {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let declared_bounds = referenced_columns
                    .iter()
                    .map(|column_ordinal| {
                        integer_lift_require_pre_challenge_column(
                            *column_ordinal,
                            variant,
                            &tree_roles_by_column,
                        )?;
                        semantic_bounds
                            .get(column_ordinal)
                            .cloned()
                            .map(|interval| (*column_ordinal, interval))
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let residual_interval = evaluate_integer_interval(
                    &residual.residual_postfix_expression,
                    &declared_bounds,
                    variant,
                    self.context,
                )?;
                if !residual_interval
                    .is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
                {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
            }

            let constraint = variant
                .ordered_constraints
                .get(batch.constraint_ordinal as usize)
                .ok_or(RelationPlanError::InvalidConstraint)?;
            if !matched_constraint_ordinals.insert(batch.constraint_ordinal)
                || constraint.enforce_proof_base_field_no_wrap
                || !constraint
                    .ordered_injective_integer_factor_expressions
                    .is_empty()
                || constraint.zeroifier_postfix_expression
                    != full_trace_zeroifier_expression(variant.trace_domain_size)
                || constraint.numerator_postfix_expression
                    != batch.numerator_postfix_expression(modulus_ordinal)?
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }

        let alpha_constraint_ordinals = variant
            .ordered_constraints
            .iter()
            .enumerate()
            .filter_map(|(constraint_ordinal, constraint)| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        matches!(
                            instruction,
                            RelationExpressionInstruction::TranscriptChallenge {
                                challenge_role: RelationChallengeRole::NonNativeAlpha,
                                ..
                            }
                        )
                    })
                    .then(|| u32::try_from(constraint_ordinal).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if variant.ordered_constraints.iter().any(|constraint| {
            constraint
                .numerator_postfix_expression
                .iter()
                .any(|instruction| {
                    matches!(
                        instruction,
                        RelationExpressionInstruction::TranscriptChallenge {
                            challenge_role: RelationChallengeRole::NonNativeTheta,
                            ..
                        }
                    )
                })
        }) || seen_batch_coordinates != expected_batch_coordinates
            || matched_constraint_ordinals != alpha_constraint_ordinals
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(())
    }

    fn check_deterministic_coefficient_local_identities(
        &self,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if !variant
            .ordered_coefficient_local_identity_batches
            .is_empty()
            || !variant.ordered_integer_lift_batches.is_empty()
            || !variant.ordered_radix_convolutions.is_empty()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let deterministic_constraints = variant
            .ordered_constraints
            .iter()
            .enumerate()
            .filter(|(_, constraint)| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        matches!(
                            instruction,
                            RelationExpressionInstruction::NonNativeModulusConstant { .. }
                        )
                    })
            })
            .collect::<Vec<_>>();
        let expected_constraint_count = variant
            .ordered_non_native_moduli
            .len()
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        if deterministic_constraints.len() != expected_constraint_count {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let mut residuals_by_modulus = BTreeMap::<SuiteModulusReference, BTreeSet<Vec<u8>>>::new();
        for (deterministic_ordinal, (_, constraint)) in
            deterministic_constraints.into_iter().enumerate()
        {
            let expected_modulus = variant.ordered_non_native_moduli[deterministic_ordinal / 2];
            if constraint.enforce_proof_base_field_no_wrap
                || !constraint
                    .ordered_injective_integer_factor_expressions
                    .is_empty()
                || constraint.zeroifier_postfix_expression
                    != full_trace_zeroifier_expression(variant.trace_domain_size)
                || constraint.numerator_postfix_expression.is_empty()
                || constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        !matches!(
                            instruction,
                            RelationExpressionInstruction::BaseFieldConstant(_)
                                | RelationExpressionInstruction::NonNativeModulusConstant { .. }
                                | RelationExpressionInstruction::ColumnValue { .. }
                                | RelationExpressionInstruction::Addition
                                | RelationExpressionInstruction::Multiplication
                                | RelationExpressionInstruction::Negation
                        )
                    })
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let referenced_moduli = constraint
                .numerator_postfix_expression
                .iter()
                .filter_map(|instruction| match instruction {
                    RelationExpressionInstruction::NonNativeModulusConstant {
                        modulus_reference,
                        ..
                    } => Some(*modulus_reference),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if referenced_moduli != BTreeSet::from([expected_modulus]) {
                return Err(RelationPlanError::InvalidModulus);
            }
            check_expression(
                &constraint.numerator_postfix_expression,
                variant,
                self.context,
                false,
            )?;
            let referenced_columns =
                expression_column_ordinals(&constraint.numerator_postfix_expression, variant)?;
            if referenced_columns.is_empty() {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let declared_bounds = referenced_columns
                .iter()
                .map(|column_ordinal| {
                    integer_lift_require_pre_challenge_column(
                        *column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    semantic_bounds
                        .get(column_ordinal)
                        .cloned()
                        .map(|interval| (*column_ordinal, interval))
                        .ok_or(RelationPlanError::InvalidSemanticCell)
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            let residual_interval = evaluate_integer_interval(
                &constraint.numerator_postfix_expression,
                &declared_bounds,
                variant,
                self.context,
            )?;
            if !residual_interval
                .is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
            {
                return Err(RelationPlanError::NoWrapBoundViolated);
            }
            let residual_bytes = canonical_nested_list(
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .map(RelationExpressionInstruction::canonical_tuple)
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .canonical_bytes()
            .to_vec();
            if !residuals_by_modulus
                .entry(expected_modulus)
                .or_default()
                .insert(residual_bytes)
            {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
        if residuals_by_modulus
            .values()
            .any(|residuals| residuals.len() != 2)
            || variant.ordered_constraints.iter().any(|constraint| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        matches!(
                            instruction,
                            RelationExpressionInstruction::TranscriptChallenge {
                                challenge_role: RelationChallengeRole::NonNativeAlpha
                                    | RelationChallengeRole::NonNativeTheta,
                                ..
                            }
                        )
                    })
            })
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(())
    }

    fn check_integer_lift_batches(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<ApplicationExtractorPhaseColumns, RelationPlanError> {
        if variant.ordered_integer_lift_batches.is_empty() {
            return Ok(ApplicationExtractorPhaseColumns::default());
        }
        let canonical_batch_bytes = variant
            .ordered_integer_lift_batches
            .iter()
            .map(RelationIntegerLiftBatchDescriptor::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted_unique(&canonical_batch_bytes) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }

        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let explicitly_certified_columns = variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| cell.column_ordinal)
            .collect::<BTreeSet<_>>();
        let expected_challenge_ordinals =
            (0..self.context.non_native_modular_identity_challenge_count).collect::<BTreeSet<_>>();
        let mut challenge_ordinals_by_modulus =
            BTreeMap::<SuiteModulusReference, BTreeSet<u16>>::new();
        let mut descriptor_auxiliary_columns = BTreeSet::new();
        let mut derived_base_columns = BTreeSet::new();
        let mut matched_constraint_ordinals = BTreeSet::new();
        let mut automorphism_permutation_coordinates = BTreeSet::new();
        let mut automorphism_semantics = None;

        for batch in &variant.ordered_integer_lift_batches {
            let modulus_ordinal = u16::try_from(
                variant
                    .ordered_non_native_moduli
                    .binary_search(&batch.modulus_reference)
                    .map_err(|_| RelationPlanError::MissingModulus)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;
            let modulus = self.context.resolved_modulus(batch.modulus_reference)?;
            if modulus <= variant.trace_domain_size
                || batch.challenge_ordinal
                    >= self.context.non_native_modular_identity_challenge_count
                || batch.ordered_components.is_empty()
                || !challenge_ordinals_by_modulus
                    .entry(batch.modulus_reference)
                    .or_default()
                    .insert(batch.challenge_ordinal)
            {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }

            let reversed_binding_bytes = batch
                .ordered_reversed_column_bindings
                .iter()
                .map(RelationIntegerLiftReversedColumnBindingDescriptor::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            if !reversed_binding_bytes.is_empty()
                && !strictly_sorted_unique(&reversed_binding_bytes)
            {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
            let mut reversed_bindings_by_columns = BTreeMap::new();
            for binding in &batch.ordered_reversed_column_bindings {
                if binding.source_column_ordinal == binding.reversed_column_ordinal {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                integer_lift_require_pre_challenge_column(
                    binding.source_column_ordinal,
                    variant,
                    &tree_roles_by_column,
                )?;
                integer_lift_require_unbounded_reversed_base_column(
                    binding.reversed_column_ordinal,
                    variant,
                    &tree_roles_by_column,
                    &explicitly_certified_columns,
                )?;
                derived_base_columns.insert(binding.reversed_column_ordinal);
                integer_lift_column_interval(
                    binding.source_column_ordinal,
                    variant,
                    semantic_bounds,
                    &explicitly_certified_columns,
                    self.context,
                )?;
                if reversed_bindings_by_columns
                    .insert(
                        (
                            binding.source_column_ordinal,
                            binding.reversed_column_ordinal,
                        ),
                        binding,
                    )
                    .is_some()
                {
                    return Err(RelationPlanError::DuplicateItem);
                }
                for auxiliary_column in [
                    binding.source_prefix_evaluation_column_ordinal,
                    binding.reversed_suffix_evaluation_column_ordinal,
                ] {
                    integer_lift_require_auxiliary_column(
                        auxiliary_column,
                        variant,
                        &tree_roles_by_column,
                        &explicitly_certified_columns,
                    )?;
                    if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                        return Err(RelationPlanError::DuplicateItem);
                    }
                }
            }

            let automorphism_permutation_bytes = batch
                .ordered_negacyclic_automorphism_permutations
                .iter()
                .map(
                    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor::canonical_bytes,
                )
                .collect::<Result<Vec<_>, _>>()?;
            if automorphism_permutation_bytes.len() > 1
                || (!automorphism_permutation_bytes.is_empty()
                    && !strictly_sorted_unique(&automorphism_permutation_bytes))
            {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
            for permutation in &batch.ordered_negacyclic_automorphism_permutations {
                if application_statement_schema_identifier != 0x1217
                    || variant.ordered_non_native_moduli.first().copied()
                        != Some(batch.modulus_reference)
                    || !automorphism_permutation_coordinates
                        .insert((batch.modulus_reference, batch.challenge_ordinal))
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let ring_degree = variant
                    .trace_domain_size
                    .checked_mul(2)
                    .ok_or(RelationPlanError::CountOverflow)?;
                validate_negacyclic_automorphism(ring_degree, permutation.galois_element)?;
                match variant
                    .ordered_verifier_sources
                    .get(permutation.mapping_verifier_source_ordinal as usize)
                {
                    Some(RelationVerifierSource::NegacyclicAutomorphismMapping {
                        ring_degree: source_ring_degree,
                        galois_element,
                    }) if *source_ring_degree == ring_degree
                        && *galois_element == permutation.galois_element => {}
                    _ => return Err(RelationPlanError::InvalidSource),
                }

                let semantic_columns = [
                    permutation.source_low_column_ordinal,
                    permutation.source_high_column_ordinal,
                    permutation.target_low_column_ordinal,
                    permutation.target_high_column_ordinal,
                ];
                for column_ordinal in semantic_columns {
                    integer_lift_require_pre_challenge_column(
                        column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    let column = variant
                        .ordered_columns
                        .get(column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidColumn)?;
                    if !matches!(column.origin, RelationColumnOrigin::Prover)
                        || integer_lift_column_interval(
                            column_ordinal,
                            variant,
                            semantic_bounds,
                            &explicitly_certified_columns,
                            self.context,
                        )? != SignedIntegerInterval::new(-1, 1)
                    {
                        return Err(RelationPlanError::InvalidSemanticCell);
                    }
                }

                let mapping_columns = [
                    permutation.mapped_low_position_column_ordinal,
                    permutation.low_negation_bit_column_ordinal,
                    permutation.mapped_high_position_column_ordinal,
                    permutation.high_negation_bit_column_ordinal,
                    permutation.target_low_position_column_ordinal,
                    permutation.target_high_position_column_ordinal,
                ];
                for (sequence_ordinal, column_ordinal) in
                    mapping_columns.iter().copied().enumerate()
                {
                    integer_lift_require_pre_challenge_column(
                        column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    let expected_first_element_index = u64::try_from(sequence_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?
                        .checked_mul(variant.trace_domain_size)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    let column = variant
                        .ordered_columns
                        .get(column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidColumn)?;
                    if !matches!(
                        column.origin,
                        RelationColumnOrigin::VerifierSequence {
                            verifier_source_ordinal,
                            first_logical_element_index,
                            logical_element_stride: 1,
                        } if verifier_source_ordinal
                            == permutation.mapping_verifier_source_ordinal
                            && first_logical_element_index == expected_first_element_index
                    ) || column.value_type != RelationColumnValueType::BaseField
                        || column.source_degree_bound_exclusive != variant.trace_domain_size
                        || column.canonical_residue_modulus.is_some()
                    {
                        return Err(RelationPlanError::InvalidColumn);
                    }
                }

                let accumulator_columns = [
                    permutation.source_product_before_column_ordinal,
                    permutation.source_low_product_column_ordinal,
                    permutation.target_product_before_column_ordinal,
                    permutation.target_low_product_column_ordinal,
                ];
                for column_ordinal in accumulator_columns {
                    integer_lift_require_auxiliary_column(
                        column_ordinal,
                        variant,
                        &tree_roles_by_column,
                        &explicitly_certified_columns,
                    )?;
                    if !descriptor_auxiliary_columns.insert(column_ordinal) {
                        return Err(RelationPlanError::DuplicateItem);
                    }
                }
                let all_columns = semantic_columns
                    .into_iter()
                    .chain(mapping_columns)
                    .chain(accumulator_columns)
                    .collect::<BTreeSet<_>>();
                if all_columns.len() != 14 {
                    return Err(RelationPlanError::DuplicateItem);
                }
                let current_semantics = (
                    permutation.galois_element,
                    permutation.mapping_verifier_source_ordinal,
                    semantic_columns,
                    mapping_columns,
                );
                match automorphism_semantics {
                    Some(existing) if existing != current_semantics => {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                    None => automorphism_semantics = Some(current_semantics),
                    _ => {}
                }
            }
            let mut used_reversed_bindings = BTreeSet::new();

            let component_bytes = batch
                .ordered_components
                .iter()
                .map(RelationIntegerLiftComponentDescriptor::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            if !strictly_sorted_unique(&component_bytes) {
                return Err(RelationPlanError::NonCanonicalOrder);
            }

            for component in &batch.ordered_components {
                let linear_term_bytes = component
                    .ordered_linear_terms
                    .iter()
                    .map(RelationIntegerLiftLinearTermDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                let product_bytes = component
                    .ordered_convolution_products
                    .iter()
                    .map(RelationIntegerLiftConvolutionProductDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                let full_ring_product_bytes = component
                    .ordered_full_ring_negacyclic_products
                    .iter()
                    .map(RelationIntegerLiftFullRingNegacyclicProductDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                if linear_term_bytes.is_empty()
                    || (product_bytes.is_empty() && full_ring_product_bytes.is_empty())
                    || !strictly_sorted_unique(&linear_term_bytes)
                    || (!product_bytes.is_empty() && !strictly_sorted_unique(&product_bytes))
                    || (!full_ring_product_bytes.is_empty()
                        && !strictly_sorted_unique(&full_ring_product_bytes))
                {
                    return Err(RelationPlanError::NonCanonicalOrder);
                }

                integer_lift_require_pre_challenge_column(
                    component.quotient_column_ordinal,
                    variant,
                    &tree_roles_by_column,
                )?;
                let quotient_interval = integer_lift_column_interval(
                    component.quotient_column_ordinal,
                    variant,
                    semantic_bounds,
                    &explicitly_certified_columns,
                    self.context,
                )?;
                let mut residual_interval =
                    quotient_interval.multiply(SignedIntegerInterval::from_bigints(
                        BigInt::from(modulus),
                        BigInt::from(modulus),
                    )?)?;
                if component.quotient_is_negative {
                    residual_interval = residual_interval.negate()?;
                }

                for term in &component.ordered_linear_terms {
                    integer_lift_require_pre_challenge_column(
                        term.column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    if term.column_offset >= self.context.base_field_modulus {
                        return Err(RelationPlanError::NoWrapBoundViolated);
                    }
                    let interval = integer_lift_column_interval(
                        term.column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let shifted = SignedIntegerInterval::from_bigints(
                        interval.minimum - BigInt::from(term.column_offset),
                        interval.maximum - BigInt::from(term.column_offset),
                    )?;
                    let coefficient =
                        integer_lift_coefficient_value(term.coefficient, self.context)?;
                    let mut term_interval =
                        shifted.multiply(SignedIntegerInterval::from_bigints(
                            BigInt::from(coefficient),
                            BigInt::from(coefficient),
                        )?)?;
                    if term.negative {
                        term_interval = term_interval.negate()?;
                    }
                    residual_interval = residual_interval.add(term_interval)?;
                }

                for product in &component.ordered_convolution_products {
                    integer_lift_require_pre_challenge_column(
                        product.multiplicand_column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    integer_lift_require_pre_challenge_column(
                        product.reversed_multiplier_column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    if product.multiplier_offset >= self.context.base_field_modulus {
                        return Err(RelationPlanError::NoWrapBoundViolated);
                    }
                    let multiplicand_interval = integer_lift_column_interval(
                        product.multiplicand_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplier_interval = integer_lift_column_interval(
                        product.reversed_multiplier_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let shifted_multiplier = SignedIntegerInterval::from_bigints(
                        multiplier_interval.minimum - BigInt::from(product.multiplier_offset),
                        multiplier_interval.maximum - BigInt::from(product.multiplier_offset),
                    )?;
                    let coefficient_product = multiplicand_interval.multiply(shifted_multiplier)?;
                    let maximum_absolute_product = coefficient_product
                        .minimum
                        .magnitude()
                        .max(coefficient_product.maximum.magnitude())
                        .clone();
                    let convolution_bound = BigInt::from(maximum_absolute_product)
                        * BigInt::from(variant.trace_domain_size);
                    let mut product_interval = SignedIntegerInterval::from_bigints(
                        -convolution_bound.clone(),
                        convolution_bound,
                    )?;
                    if product.negative {
                        product_interval = product_interval.negate()?;
                    }
                    residual_interval = residual_interval.add(product_interval)?;

                    for auxiliary_column in [
                        product.suffix_evaluation_column_ordinal,
                        product.reversed_transpose_column_ordinal,
                    ] {
                        integer_lift_require_auxiliary_column(
                            auxiliary_column,
                            variant,
                            &tree_roles_by_column,
                            &explicitly_certified_columns,
                        )?;
                        if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                            return Err(RelationPlanError::DuplicateItem);
                        }
                    }
                }

                for product in &component.ordered_full_ring_negacyclic_products {
                    if product.multiplicand_low_column_ordinal
                        == product.multiplicand_high_column_ordinal
                        || product.multiplier_low_column_ordinal
                            == product.multiplier_high_column_ordinal
                        || product.reversed_multiplier_low_column_ordinal
                            == product.reversed_multiplier_high_column_ordinal
                        || product.multiplier_low_offset >= self.context.base_field_modulus
                        || product.multiplier_high_offset >= self.context.base_field_modulus
                    {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                    for column_ordinal in [
                        product.multiplicand_low_column_ordinal,
                        product.multiplicand_high_column_ordinal,
                        product.multiplier_low_column_ordinal,
                        product.multiplier_high_column_ordinal,
                        product.reversed_multiplier_low_column_ordinal,
                        product.reversed_multiplier_high_column_ordinal,
                    ] {
                        integer_lift_require_pre_challenge_column(
                            column_ordinal,
                            variant,
                            &tree_roles_by_column,
                        )?;
                    }
                    for binding_key in [
                        (
                            product.multiplier_low_column_ordinal,
                            product.reversed_multiplier_low_column_ordinal,
                        ),
                        (
                            product.multiplier_high_column_ordinal,
                            product.reversed_multiplier_high_column_ordinal,
                        ),
                    ] {
                        if !reversed_bindings_by_columns.contains_key(&binding_key) {
                            return Err(RelationPlanError::InvalidConstraint);
                        }
                        used_reversed_bindings.insert(binding_key);
                    }
                    let multiplicand_low_interval = integer_lift_column_interval(
                        product.multiplicand_low_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplicand_high_interval = integer_lift_column_interval(
                        product.multiplicand_high_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplier_low_interval = integer_lift_column_interval(
                        product.multiplier_low_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplier_high_interval = integer_lift_column_interval(
                        product.multiplier_high_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let shifted_multiplier_low = SignedIntegerInterval::from_bigints(
                        multiplier_low_interval.minimum
                            - BigInt::from(product.multiplier_low_offset),
                        multiplier_low_interval.maximum
                            - BigInt::from(product.multiplier_low_offset),
                    )?;
                    let shifted_multiplier_high = SignedIntegerInterval::from_bigints(
                        multiplier_high_interval.minimum
                            - BigInt::from(product.multiplier_high_offset),
                        multiplier_high_interval.maximum
                            - BigInt::from(product.multiplier_high_offset),
                    )?;
                    let low_low = integer_lift_maximum_absolute_product(
                        &multiplicand_low_interval,
                        &shifted_multiplier_low,
                    )?;
                    let high_low = integer_lift_maximum_absolute_product(
                        &multiplicand_high_interval,
                        &shifted_multiplier_low,
                    )?;
                    let low_high = integer_lift_maximum_absolute_product(
                        &multiplicand_low_interval,
                        &shifted_multiplier_high,
                    )?;
                    let high_high = integer_lift_maximum_absolute_product(
                        &multiplicand_high_interval,
                        &shifted_multiplier_high,
                    )?;
                    let diagonal_bound = low_low + high_high;
                    let cross_bound = high_low + low_high;
                    let convolution_bound = BigInt::from(diagonal_bound.max(cross_bound))
                        * BigInt::from(variant.trace_domain_size);
                    let mut product_interval = SignedIntegerInterval::from_bigints(
                        -convolution_bound.clone(),
                        convolution_bound,
                    )?;
                    if product.negative {
                        product_interval = product_interval.negate()?;
                    }
                    residual_interval = residual_interval.add(product_interval)?;

                    for auxiliary_column in [
                        product.multiplicand_low_suffix_evaluation_column_ordinal,
                        product.multiplicand_high_suffix_evaluation_column_ordinal,
                        product.reversed_multiplier_low_transpose_column_ordinal,
                        product.reversed_multiplier_high_transpose_column_ordinal,
                    ] {
                        integer_lift_require_auxiliary_column(
                            auxiliary_column,
                            variant,
                            &tree_roles_by_column,
                            &explicitly_certified_columns,
                        )?;
                        if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                            return Err(RelationPlanError::DuplicateItem);
                        }
                    }
                }

                for auxiliary_column in [
                    component.linear_evaluation_column_ordinal,
                    component.product_accumulator_column_ordinal,
                ] {
                    integer_lift_require_auxiliary_column(
                        auxiliary_column,
                        variant,
                        &tree_roles_by_column,
                        &explicitly_certified_columns,
                    )?;
                    if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                        return Err(RelationPlanError::DuplicateItem);
                    }
                }

                if !residual_interval
                    .is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
                {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
            }

            if used_reversed_bindings != reversed_bindings_by_columns.keys().copied().collect() {
                return Err(RelationPlanError::InvalidConstraint);
            }

            for program in batch.constraint_programs(
                modulus_ordinal,
                variant.trace_domain_size,
                variant.evaluation_domain_size,
                self.context,
            )? {
                let matching_ordinals = variant
                    .ordered_constraints
                    .iter()
                    .enumerate()
                    .filter_map(|(constraint_ordinal, constraint)| {
                        (!constraint.enforce_proof_base_field_no_wrap
                            && constraint
                                .ordered_injective_integer_factor_expressions
                                .is_empty()
                            && constraint.numerator_postfix_expression
                                == program.numerator_postfix_expression
                            && constraint.zeroifier_postfix_expression
                                == program.zeroifier_postfix_expression)
                            .then_some(constraint_ordinal)
                    })
                    .collect::<Vec<_>>();
                if matching_ordinals.len() != 1
                    || !matched_constraint_ordinals.insert(
                        u32::try_from(matching_ordinals[0])
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
            }
        }

        if challenge_ordinals_by_modulus
            .values()
            .any(|ordinals| ordinals != &expected_challenge_ordinals)
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let expected_automorphism_permutation_coordinates =
            if application_statement_schema_identifier == 0x1217 {
                let modulus_reference = variant
                    .ordered_non_native_moduli
                    .first()
                    .copied()
                    .ok_or(RelationPlanError::MissingModulus)?;
                expected_challenge_ordinals
                    .iter()
                    .copied()
                    .map(|challenge_ordinal| (modulus_reference, challenge_ordinal))
                    .collect()
            } else {
                BTreeSet::new()
            };
        if automorphism_permutation_coordinates != expected_automorphism_permutation_coordinates
            || (application_statement_schema_identifier == 0x1217)
                != automorphism_semantics.is_some()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(ApplicationExtractorPhaseColumns {
            derived_base_columns,
            derived_auxiliary_columns: descriptor_auxiliary_columns,
        })
    }

    /// Ensures the first application oracle contains every essential witness
    /// value. Later application oracles may contain only columns whose values
    /// are determined by the checked integer-lift grammar and the preceding
    /// public challenge. This is the phase boundary used by the application
    /// knowledge extractor: it never relies on a witness first supplied after
    /// a verifier challenge.
    fn check_application_extractor_phase_ownership(
        &self,
        variant: &RelationPlanVariant,
        phase_columns: &ApplicationExtractorPhaseColumns,
    ) -> Result<(), RelationPlanError> {
        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let semantic_prover_columns = variant
            .ordered_semantic_cells
            .iter()
            .filter_map(|cell| {
                variant
                    .ordered_columns
                    .get(cell.column_ordinal as usize)
                    .is_some_and(|column| matches!(column.origin, RelationColumnOrigin::Prover))
                    .then_some(cell.column_ordinal)
            })
            .collect::<BTreeSet<_>>();

        for semantic_column in &semantic_prover_columns {
            if tree_roles_by_column.get(semantic_column) != Some(&Some(1)) {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }

        let mut observed_auxiliary_columns = BTreeSet::new();
        for (column_index, column) in variant.ordered_columns.iter().enumerate() {
            let column_ordinal =
                u32::try_from(column_index).map_err(|_| RelationPlanError::CountOverflow)?;
            let tree_role = tree_roles_by_column
                .get(&column_ordinal)
                .copied()
                .ok_or(RelationPlanError::MissingRoot)?;
            match (tree_role, &column.origin) {
                (Some(1), RelationColumnOrigin::Prover)
                    if !semantic_prover_columns.contains(&column_ordinal)
                        && !phase_columns.derived_base_columns.contains(&column_ordinal) =>
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                (Some(2), RelationColumnOrigin::Prover) => {
                    observed_auxiliary_columns.insert(column_ordinal);
                }
                (Some(2), _) => return Err(RelationPlanError::InvalidConstraint),
                _ => {}
            }
        }
        if observed_auxiliary_columns != phase_columns.derived_auxiliary_columns {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(())
    }

    fn check_openings(&self, variant: &RelationPlanVariant) -> Result<(), RelationPlanError> {
        if variant.ordered_opening_points.is_empty() || variant.ordered_opening_claims.is_empty() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let required_rotations_by_column = required_column_rotations(
            &variant.ordered_constraints,
            &variant.ordered_radix_convolutions,
        )?;
        if required_rotations_by_column.len() != variant.ordered_columns.len() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let required_rotations = required_rotations_by_column
            .values()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<BTreeSet<_>>();
        let expected_points = (0..self.context.deep_point_count)
            .flat_map(|deep_point_ordinal| {
                required_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        deep_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    })
            })
            .collect::<BTreeSet<_>>();
        let mut points = BTreeSet::new();
        for point in &variant.ordered_opening_points {
            if point.deep_point_ordinal >= self.context.deep_point_count
                || point.conjugate_index >= self.context.challenge_extension_degree
                || !points.insert(*point)
            {
                return Err(RelationPlanError::InvalidOpening);
            }
        }
        if points != expected_points {
            return Err(RelationPlanError::InvalidOpening);
        }
        let mut claims = BTreeSet::new();
        for claim in &variant.ordered_opening_claims {
            if claim.opening_point_ordinal as usize >= variant.ordered_opening_points.len()
                || claim.source_degree_bound_exclusive == 0
                || claim.source_degree_bound_exclusive > variant.opening_degree_bound_exclusive
                || !claims.insert((
                    claim.source_class as u16,
                    claim.source_ordinal,
                    claim.column_ordinal,
                    claim.opening_point_ordinal,
                ))
            {
                return Err(RelationPlanError::InvalidOpening);
            }
            match claim.source_class {
                RelationOpeningSourceClass::TreeColumn => {
                    let column_ordinal = claim
                        .column_ordinal
                        .ok_or(RelationPlanError::InvalidOpening)?;
                    let tree = variant
                        .ordered_trees
                        .get(claim.source_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidOpening)?;
                    let column = variant
                        .ordered_columns
                        .get(column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidOpening)?;
                    if !tree.ordered_column_ordinals().contains(&column_ordinal)
                        || column.source_degree_bound_exclusive
                            != claim.source_degree_bound_exclusive
                    {
                        return Err(RelationPlanError::InvalidOpening);
                    }
                }
                RelationOpeningSourceClass::Quotient => {
                    if claim.column_ordinal.is_some()
                        || claim.source_ordinal >= self.context.quotient_component_count
                        || claim.source_degree_bound_exclusive
                            != self.context.quotient_component_degree_bound_exclusive
                    {
                        return Err(RelationPlanError::InvalidOpening);
                    }
                }
                RelationOpeningSourceClass::BatchMask => {
                    if variant.proof_privacy_mode != ProofPrivacyMode::SecretBearing
                        || claim.source_ordinal != 0
                        || claim.column_ordinal.is_some()
                        || claim.source_degree_bound_exclusive
                            != variant.opening_degree_bound_exclusive - 1
                    {
                        return Err(RelationPlanError::InvalidOpening);
                    }
                }
            }
        }
        let mut expected_claims = BTreeSet::new();
        let point_ordinals = variant
            .ordered_opening_points
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, point)| {
                Ok((
                    point,
                    u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, RelationPlanError>>()?;
        for (tree_ordinal, tree) in variant.ordered_trees.iter().enumerate() {
            let tree_ordinal =
                u32::try_from(tree_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            for column_ordinal in tree.ordered_column_ordinals() {
                let rotations = required_rotations_by_column
                    .get(column_ordinal)
                    .ok_or(RelationPlanError::InvalidOpening)?;
                for deep_point_ordinal in 0..self.context.deep_point_count {
                    for rotation in rotations {
                        let opening_point_ordinal = point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                deep_point_ordinal,
                                trace_rotation_is_negative: rotation.0,
                                trace_rotation_magnitude: rotation.1,
                                conjugate_index: 0,
                            })
                            .copied()
                            .ok_or(RelationPlanError::InvalidOpening)?;
                        expected_claims.insert((
                            RelationOpeningSourceClass::TreeColumn as u16,
                            tree_ordinal,
                            Some(*column_ordinal),
                            opening_point_ordinal,
                        ));
                    }
                }
            }
        }
        for quotient_ordinal in 0..self.context.quotient_component_count {
            for deep_point_ordinal in 0..self.context.deep_point_count {
                let opening_point_ordinal = point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        deep_point_ordinal,
                        trace_rotation_is_negative: false,
                        trace_rotation_magnitude: 0,
                        conjugate_index: 0,
                    })
                    .copied()
                    .ok_or(RelationPlanError::InvalidOpening)?;
                expected_claims.insert((
                    RelationOpeningSourceClass::Quotient as u16,
                    quotient_ordinal,
                    None,
                    opening_point_ordinal,
                ));
            }
        }
        if variant.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
            expected_claims.insert((RelationOpeningSourceClass::BatchMask as u16, 0, None, 0));
        }
        if claims != expected_claims {
            return Err(RelationPlanError::InvalidOpening);
        }
        Ok(())
    }

    fn check_masks(&self, variant: &RelationPlanVariant) -> Result<(), RelationPlanError> {
        let prover_columns = variant
            .ordered_columns
            .iter()
            .enumerate()
            .filter_map(|(ordinal, column)| {
                matches!(column.origin, RelationColumnOrigin::Prover)
                    .then_some(u32::try_from(ordinal).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if variant.proof_privacy_mode == ProofPrivacyMode::PublicOnly {
            if !prover_columns.is_empty() || !variant.ordered_masks.is_empty() {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            return Ok(());
        }
        if prover_columns.is_empty() || variant.ordered_masks.is_empty() {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let mut purposes = BTreeSet::new();
        let mut trace_targets = BTreeSet::new();
        let mut telescoping_targets = BTreeSet::new();
        let mut batch_count = 0_usize;
        let mut trace_degree = None;
        let mut telescoping_degree = None;
        for mask in &variant.ordered_masks {
            if mask.mask_purpose == 0
                || mask.mask_purpose >= 0xff00
                || mask.mask_degree_bound_exclusive == 0
                || !purposes.insert(mask.mask_purpose)
            {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            match (mask.mask_kind, mask.target_class) {
                (RelationMaskKind::Trace, RelationMaskTargetClass::Column) => {
                    if !prover_columns.contains(&mask.target_ordinal)
                        || mask.mask_degree_bound_exclusive > variant.trace_domain_size
                        || trace_degree
                            .is_some_and(|degree| degree != mask.mask_degree_bound_exclusive)
                        || !trace_targets.insert(mask.target_ordinal)
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                    trace_degree = Some(mask.mask_degree_bound_exclusive);
                }
                (RelationMaskKind::Telescoping, RelationMaskTargetClass::QuotientComponent) => {
                    if mask.target_ordinal + 1 >= self.context.quotient_component_count
                        || telescoping_degree
                            .is_some_and(|degree| degree != mask.mask_degree_bound_exclusive)
                        || !telescoping_targets.insert(mask.target_ordinal)
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                    telescoping_degree = Some(mask.mask_degree_bound_exclusive);
                }
                (RelationMaskKind::OpeningBatch, RelationMaskTargetClass::Batch) => {
                    if mask.target_ordinal != 0
                        || mask.mask_degree_bound_exclusive
                            != variant.opening_degree_bound_exclusive - 1
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                    batch_count += 1;
                }
                _ => return Err(RelationPlanError::InvalidMaskGrammar),
            }
        }
        if trace_targets != prover_columns
            || telescoping_targets.len() != (self.context.quotient_component_count - 1) as usize
            || batch_count != 1
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let decomposition_stride = variant.quotient_decomposition_stride(self.context)?;
        let expected_telescoping_degree = self
            .context
            .quotient_component_degree_bound_exclusive
            .checked_sub(decomposition_stride)
            .filter(|degree| *degree != 0)
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        if telescoping_degree != Some(expected_telescoping_degree) {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        Ok(())
    }
}

fn integer_lift_tree_roles_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, Option<u16>>, RelationPlanError> {
    let mut roles = BTreeMap::new();
    for tree in &variant.ordered_trees {
        let role = match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role, ..
            } => Some(*proof_tree_role),
            RelationTreeDescriptor::BoundPublic { .. } => None,
        };
        for column_ordinal in tree.ordered_column_ordinals() {
            if roles.insert(*column_ordinal, role).is_some() {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
    }
    Ok(roles)
}

fn integer_lift_require_pre_challenge_column(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    tree_roles_by_column: &BTreeMap<u32, Option<u16>>,
) -> Result<(), RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    let role = tree_roles_by_column
        .get(&column_ordinal)
        .copied()
        .ok_or(RelationPlanError::MissingRoot)?;
    match column.origin {
        RelationColumnOrigin::Prover | RelationColumnOrigin::VerifierSequence { .. }
            if role == Some(1) =>
        {
            Ok(())
        }
        RelationColumnOrigin::BoundTree { .. } if role.is_none() => Ok(()),
        _ => Err(RelationPlanError::InvalidConstraint),
    }
}

fn integer_lift_require_auxiliary_column(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    tree_roles_by_column: &BTreeMap<u32, Option<u16>>,
    explicitly_certified_columns: &BTreeSet<u32>,
) -> Result<(), RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    if !matches!(column.origin, RelationColumnOrigin::Prover)
        || tree_roles_by_column.get(&column_ordinal) != Some(&Some(2))
        || explicitly_certified_columns.contains(&column_ordinal)
        || column.canonical_residue_modulus.is_some()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(())
}

fn integer_lift_require_unbounded_reversed_base_column(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    tree_roles_by_column: &BTreeMap<u32, Option<u16>>,
    explicitly_certified_columns: &BTreeSet<u32>,
) -> Result<(), RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    if !matches!(column.origin, RelationColumnOrigin::Prover)
        || tree_roles_by_column.get(&column_ordinal) != Some(&Some(1))
        || explicitly_certified_columns.contains(&column_ordinal)
        || column.canonical_residue_modulus.is_some()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(())
}

fn integer_lift_maximum_absolute_product(
    left: &SignedIntegerInterval,
    right: &SignedIntegerInterval,
) -> Result<BigUint, RelationPlanError> {
    let product = left.clone().multiply(right.clone())?;
    Ok(product
        .minimum
        .magnitude()
        .max(product.maximum.magnitude())
        .clone())
}

fn integer_lift_column_interval(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    explicitly_certified_columns: &BTreeSet<u32>,
    context: &RelationPlanCheckContext,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    match column.origin {
        RelationColumnOrigin::VerifierSequence {
            verifier_source_ordinal,
            ..
        } => {
            let source = variant
                .ordered_verifier_sources
                .get(verifier_source_ordinal as usize)
                .ok_or(RelationPlanError::InvalidSource)?;
            if let RelationVerifierSource::RadixDecomposition { radix, .. } = source {
                if column.canonical_residue_modulus.is_some() {
                    return Err(RelationPlanError::InvalidSemanticCell);
                }
                return SignedIntegerInterval::from_bigints(
                    BigInt::zero(),
                    BigInt::from(radix - 1),
                );
            }
            let modulus_reference = column
                .canonical_residue_modulus
                .ok_or(RelationPlanError::InvalidSemanticCell)?;
            let layout = source.value_layout(
                &variant.ordered_public_samplers,
                &variant.ordered_verifier_sources,
            )?;
            if layout.element_kind != RelationElementKind::Residue
                || layout.residue_modulus != Some(modulus_reference)
            {
                return Err(RelationPlanError::InvalidSemanticCell);
            }
            let modulus = context.resolved_modulus(modulus_reference)?;
            match layout.embedding_kind {
                RelationEmbeddingKind::LeastNonnegative => {
                    SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(modulus - 1))
                }
                RelationEmbeddingKind::Centered => {
                    let absolute_bound = (modulus - 1) / 2;
                    SignedIntegerInterval::from_bigints(
                        -BigInt::from(absolute_bound),
                        BigInt::from(absolute_bound),
                    )
                }
                _ => Err(RelationPlanError::InvalidSemanticCell),
            }
        }
        RelationColumnOrigin::BoundTree { .. } => {
            if explicitly_certified_columns.contains(&column_ordinal) {
                return semantic_bounds
                    .get(&column_ordinal)
                    .cloned()
                    .ok_or(RelationPlanError::InvalidSemanticCell);
            }
            let modulus_reference = column
                .canonical_residue_modulus
                .filter(|_| {
                    integer_lift_bound_tree_has_canonical_residue_capability(
                        column_ordinal,
                        variant,
                    )
                })
                .ok_or(RelationPlanError::InvalidBoundCertificate)?;
            let modulus = context.resolved_modulus(modulus_reference)?;
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(modulus - 1))
        }
        RelationColumnOrigin::Prover => semantic_bounds
            .get(&column_ordinal)
            .cloned()
            .ok_or(RelationPlanError::InvalidSemanticCell),
    }
}

fn integer_lift_bound_tree_has_canonical_residue_capability(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
) -> bool {
    variant.ordered_trees.iter().any(|tree| {
        matches!(
            tree,
            RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } if ordered_column_ordinals.binary_search(&column_ordinal).is_ok()
        )
    })
}

fn integer_lift_coefficient_value(
    coefficient: RelationIntegerLiftCoefficient,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => {
            if !(1..context.base_field_modulus).contains(&value) {
                return Err(RelationPlanError::NoWrapBoundViolated);
            }
            Ok(value)
        }
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => resolved_modulus_multiple(modulus_reference, multiplier, context),
    }
}

fn derive_semantic_cell_interval<'cell>(
    column_ordinal: u32,
    semantic_cells_by_column: &BTreeMap<u32, &'cell SemanticCellDescriptor>,
    constraints: &[RelationConstraintDescriptor],
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
    derived_intervals: &mut BTreeMap<u32, SignedIntegerInterval>,
    active_columns: &mut BTreeSet<u32>,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let proof_base_field_modulus = context.base_field_modulus;
    if let Some(interval) = derived_intervals.get(&column_ordinal) {
        return Ok(interval.clone());
    }
    if !active_columns.insert(column_ordinal) {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let semantic_cell = semantic_cells_by_column
        .get(&column_ordinal)
        .copied()
        .ok_or(RelationPlanError::InvalidSemanticCell)?;
    let constraint = constraints
        .get(semantic_cell.bound_certificate.constraint_ordinal() as usize)
        .ok_or(RelationPlanError::InvalidBoundCertificate)?;
    if constraint.enforce_proof_base_field_no_wrap
        || constraint.zeroifier_postfix_expression
            != full_trace_zeroifier_expression(trace_domain_size)
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let derived_interval = match &semantic_cell.bound_certificate {
        RelationBoundCertificate::Trinary { .. } => {
            if constraint.numerator_postfix_expression
                != trinary_constraint_expression(column_ordinal)
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::new(0, 2)
        }
        RelationBoundCertificate::Binary { .. } => {
            if constraint.numerator_postfix_expression
                != binary_constraint_expression(column_ordinal)
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::new(0, 1)
        }
        RelationBoundCertificate::UnsignedRadixRecomposition {
            radix,
            ordered_digit_column_ordinals,
            ..
        } => {
            let maximum = validate_radix_digit_bounds(
                column_ordinal,
                *radix,
                ordered_digit_column_ordinals,
                semantic_cells_by_column,
                constraints,
                trace_domain_size,
                context,
                derived_intervals,
                active_columns,
            )?;
            let expected_expression = radix_recomposition_expression(
                column_ordinal,
                *radix,
                None,
                ordered_digit_column_ordinals,
                proof_base_field_modulus,
            )?;
            if constraint.numerator_postfix_expression != expected_expression {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?
        }
        RelationBoundCertificate::ShiftedRadixRecomposition {
            radix,
            offset,
            ordered_digit_column_ordinals,
            ..
        } => {
            if offset.is_zero() || offset >= &BigUint::from(proof_base_field_modulus) {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            let maximum = validate_radix_digit_bounds(
                column_ordinal,
                *radix,
                ordered_digit_column_ordinals,
                semantic_cells_by_column,
                constraints,
                trace_domain_size,
                context,
                derived_intervals,
                active_columns,
            )?;
            let expected_expression = radix_recomposition_expression(
                column_ordinal,
                *radix,
                Some(offset),
                ordered_digit_column_ordinals,
                proof_base_field_modulus,
            )?;
            if constraint.numerator_postfix_expression != expected_expression {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            let offset = BigInt::from(offset.clone());
            SignedIntegerInterval::from_bigints(-offset.clone(), BigInt::from(maximum) - offset)?
        }
        RelationBoundCertificate::CanonicalModulusRecomposition {
            modulus_reference,
            radix,
            ordered_digit_column_ordinals,
            ordered_comparator_constraint_ordinals,
            ordered_difference_digit_column_ordinals,
            ordered_borrow_column_ordinals,
            ..
        } => validate_canonical_modulus_recomposition_bound(
            column_ordinal,
            *modulus_reference,
            *radix,
            ordered_digit_column_ordinals,
            ordered_comparator_constraint_ordinals,
            ordered_difference_digit_column_ordinals,
            ordered_borrow_column_ordinals,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )?,
        RelationBoundCertificate::FiniteIntegerSet { ordered_values, .. } => {
            if ordered_values.len() < 2 || !strictly_sorted_unique(ordered_values) {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            let ordered_factor_expressions = ordered_values
                .iter()
                .map(|value| {
                    finite_integer_set_factor_expression(
                        column_ordinal,
                        value,
                        proof_base_field_modulus,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            if constraint.ordered_injective_integer_factor_expressions != ordered_factor_expressions
                || constraint.numerator_postfix_expression
                    != ordered_injective_integer_factor_product_expression(
                        &ordered_factor_expressions,
                    )?
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::from_bigints(
                ordered_values
                    .first()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
                ordered_values
                    .last()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
            )?
        }
    };

    if semantic_cell.claimed_interval != derived_interval {
        return Err(RelationPlanError::InvalidSemanticCell);
    }
    active_columns.remove(&column_ordinal);
    derived_intervals.insert(column_ordinal, derived_interval.clone());
    Ok(derived_interval)
}

#[allow(clippy::too_many_arguments)]
fn validate_radix_digit_bounds<'cell>(
    target_column_ordinal: u32,
    radix: u64,
    ordered_digit_column_ordinals: &[u32],
    semantic_cells_by_column: &BTreeMap<u32, &'cell SemanticCellDescriptor>,
    constraints: &[RelationConstraintDescriptor],
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
    derived_intervals: &mut BTreeMap<u32, SignedIntegerInterval>,
    active_columns: &mut BTreeSet<u32>,
) -> Result<BigUint, RelationPlanError> {
    let proof_base_field_modulus = context.base_field_modulus;
    if !(2..proof_base_field_modulus).contains(&radix)
        || ordered_digit_column_ordinals.is_empty()
        || !strictly_sorted_unique(ordered_digit_column_ordinals)
        || ordered_digit_column_ordinals.contains(&target_column_ordinal)
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let expected_digit_interval =
        SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(radix - 1))?;
    for digit_column_ordinal in ordered_digit_column_ordinals {
        let interval = derive_semantic_cell_interval(
            *digit_column_ordinal,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )?;
        if interval != expected_digit_interval {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }

    let mut radix_power = BigUint::one();
    let radix = BigUint::from(radix);
    for _ in ordered_digit_column_ordinals {
        radix_power *= &radix;
    }
    let maximum = radix_power - BigUint::one();
    if maximum >= BigUint::from(proof_base_field_modulus) {
        return Err(RelationPlanError::NoWrapBoundViolated);
    }
    Ok(maximum)
}

#[allow(clippy::too_many_arguments)]
fn validate_canonical_modulus_recomposition_bound<'cell>(
    target_column_ordinal: u32,
    modulus_reference: SuiteModulusReference,
    radix: u64,
    ordered_digit_column_ordinals: &[u32],
    ordered_comparator_constraint_ordinals: &[u32],
    ordered_difference_digit_column_ordinals: &[u32],
    ordered_borrow_column_ordinals: &[u32],
    semantic_cells_by_column: &BTreeMap<u32, &'cell SemanticCellDescriptor>,
    constraints: &[RelationConstraintDescriptor],
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
    derived_intervals: &mut BTreeMap<u32, SignedIntegerInterval>,
    active_columns: &mut BTreeSet<u32>,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let digit_count = ordered_digit_column_ordinals.len();
    if digit_count == 0
        || ordered_comparator_constraint_ordinals.len() != digit_count
        || ordered_difference_digit_column_ordinals.len() != digit_count
        || ordered_borrow_column_ordinals.len() != digit_count.saturating_sub(1)
        || !strictly_sorted_unique(ordered_comparator_constraint_ordinals)
        || !strictly_sorted_unique(ordered_difference_digit_column_ordinals)
        || (!ordered_borrow_column_ordinals.is_empty()
            && !strictly_sorted_unique(ordered_borrow_column_ordinals))
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let auxiliary_columns = ordered_digit_column_ordinals
        .iter()
        .chain(ordered_difference_digit_column_ordinals)
        .chain(ordered_borrow_column_ordinals)
        .copied()
        .collect::<BTreeSet<_>>();
    if auxiliary_columns.len()
        != ordered_digit_column_ordinals.len()
            + ordered_difference_digit_column_ordinals.len()
            + ordered_borrow_column_ordinals.len()
        || auxiliary_columns.contains(&target_column_ordinal)
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let broad_maximum = validate_radix_digit_bounds(
        target_column_ordinal,
        radix,
        ordered_digit_column_ordinals,
        semantic_cells_by_column,
        constraints,
        trace_domain_size,
        context,
        derived_intervals,
        active_columns,
    )?;
    let recomposition_constraint = constraints
        .get(
            semantic_cells_by_column
                .get(&target_column_ordinal)
                .ok_or(RelationPlanError::InvalidSemanticCell)?
                .bound_certificate
                .constraint_ordinal() as usize,
        )
        .ok_or(RelationPlanError::InvalidBoundCertificate)?;
    if recomposition_constraint.numerator_postfix_expression
        != radix_recomposition_expression(
            target_column_ordinal,
            radix,
            None,
            ordered_digit_column_ordinals,
            context.base_field_modulus,
        )?
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let maximum = context
        .resolved_modulus(modulus_reference)?
        .checked_sub(1)
        .ok_or(RelationPlanError::InvalidModulus)?;
    if usize::from(minimum_radix_digit_count(maximum, radix)?) != digit_count
        || BigUint::from(maximum) > broad_maximum
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let maximum_digits = fixed_radix_u64_digits(maximum, digit_count, radix)?;
    let expected_digit_interval =
        SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(radix - 1))?;
    for difference_column_ordinal in ordered_difference_digit_column_ordinals {
        if derive_semantic_cell_interval(
            *difference_column_ordinal,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )? != expected_digit_interval
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }
    for borrow_column_ordinal in ordered_borrow_column_ordinals {
        if derive_semantic_cell_interval(
            *borrow_column_ordinal,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )? != SignedIntegerInterval::new(0, 1)
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }
    for digit_ordinal in 0..digit_count {
        let comparator_constraint = constraints
            .get(ordered_comparator_constraint_ordinals[digit_ordinal] as usize)
            .ok_or(RelationPlanError::InvalidBoundCertificate)?;
        let incoming_borrow = digit_ordinal
            .checked_sub(1)
            .map(|ordinal| ordered_borrow_column_ordinals[ordinal]);
        let outgoing_borrow = (digit_ordinal + 1 < digit_count)
            .then(|| ordered_borrow_column_ordinals[digit_ordinal]);
        if !comparator_constraint.enforce_proof_base_field_no_wrap
            || comparator_constraint.zeroifier_postfix_expression
                != full_trace_zeroifier_expression(trace_domain_size)
            || comparator_constraint.numerator_postfix_expression
                != unsigned_radix_comparator_digit_expression(
                    maximum_digits[digit_ordinal],
                    ordered_digit_column_ordinals[digit_ordinal],
                    ordered_difference_digit_column_ordinals[digit_ordinal],
                    incoming_borrow,
                    outgoing_borrow,
                    radix,
                )
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }
    SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))
}

fn full_trace_zeroifier_expression(trace_domain_size: u64) -> Vec<RelationExpressionInstruction> {
    vec![
        RelationExpressionInstruction::EvaluationVariable,
        RelationExpressionInstruction::NonnegativePower(trace_domain_size),
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]
}

pub(crate) fn unsigned_radix_comparator_digit_expression(
    maximum_digit: u64,
    value_digit_column_ordinal: u32,
    difference_digit_column_ordinal: u32,
    incoming_borrow_column_ordinal: Option<u32>,
    outgoing_borrow_column_ordinal: Option<u32>,
    radix: u64,
) -> Vec<RelationExpressionInstruction> {
    let mut expression = vec![
        RelationExpressionInstruction::BaseFieldConstant(maximum_digit),
        unrotated_column_expression(value_digit_column_ordinal),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ];
    if let Some(incoming_borrow_column_ordinal) = incoming_borrow_column_ordinal {
        expression.extend([
            unrotated_column_expression(incoming_borrow_column_ordinal),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ]);
    }
    if let Some(outgoing_borrow_column_ordinal) = outgoing_borrow_column_ordinal {
        expression.extend([
            unrotated_column_expression(outgoing_borrow_column_ordinal),
            RelationExpressionInstruction::BaseFieldConstant(radix),
            RelationExpressionInstruction::Multiplication,
            RelationExpressionInstruction::Addition,
        ]);
    }
    expression.extend([
        unrotated_column_expression(difference_digit_column_ordinal),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]);
    expression
}

fn unrotated_column_expression(column_ordinal: u32) -> RelationExpressionInstruction {
    RelationExpressionInstruction::ColumnValue {
        column_ordinal,
        rotation_is_negative: false,
        rotation_magnitude: 0,
    }
}

fn binary_constraint_expression(column_ordinal: u32) -> Vec<RelationExpressionInstruction> {
    let column = unrotated_column_expression(column_ordinal);
    vec![
        column.clone(),
        column,
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
        RelationExpressionInstruction::Multiplication,
    ]
}

fn trinary_constraint_expression(column_ordinal: u32) -> Vec<RelationExpressionInstruction> {
    let column = unrotated_column_expression(column_ordinal);
    vec![
        column.clone(),
        column.clone(),
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
        RelationExpressionInstruction::Multiplication,
        column,
        RelationExpressionInstruction::BaseFieldConstant(2),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
        RelationExpressionInstruction::Multiplication,
    ]
}

fn radix_recomposition_expression(
    target_column_ordinal: u32,
    radix: u64,
    offset: Option<&BigUint>,
    ordered_digit_column_ordinals: &[u32],
    proof_base_field_modulus: u64,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut expression = vec![unrotated_column_expression(target_column_ordinal)];
    if let Some(offset) = offset {
        expression.push(RelationExpressionInstruction::BaseFieldConstant(
            bounded_biguint_as_u64(offset, proof_base_field_modulus)?,
        ));
        expression.push(RelationExpressionInstruction::Addition);
    }

    let mut weight = BigUint::one();
    let radix = BigUint::from(radix);
    for (digit_ordinal, digit_column_ordinal) in
        ordered_digit_column_ordinals.iter().copied().enumerate()
    {
        expression.push(unrotated_column_expression(digit_column_ordinal));
        expression.push(RelationExpressionInstruction::BaseFieldConstant(
            bounded_biguint_as_u64(&weight, proof_base_field_modulus)?,
        ));
        expression.push(RelationExpressionInstruction::Multiplication);
        if digit_ordinal > 0 {
            expression.push(RelationExpressionInstruction::Addition);
        }
        weight *= &radix;
    }
    expression.push(RelationExpressionInstruction::Negation);
    expression.push(RelationExpressionInstruction::Addition);
    Ok(expression)
}

fn bounded_biguint_as_u64(
    value: &BigUint,
    exclusive_upper_bound: u64,
) -> Result<u64, RelationPlanError> {
    let digits = value.to_u64_digits();
    if digits.len() > 1 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    let value = digits.first().copied().unwrap_or(0);
    if value >= exclusive_upper_bound {
        return Err(RelationPlanError::NoWrapBoundViolated);
    }
    Ok(value)
}

pub(crate) fn finite_integer_set_constraint_expressions(
    column_ordinal: u32,
    ordered_values: &[BigInt],
    proof_base_field_modulus: u64,
) -> Result<
    (
        Vec<RelationExpressionInstruction>,
        Vec<Vec<RelationExpressionInstruction>>,
    ),
    RelationPlanError,
> {
    if ordered_values.len() < 2 || !strictly_sorted_unique(ordered_values) {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let ordered_factor_expressions = ordered_values
        .iter()
        .map(|value| {
            finite_integer_set_factor_expression(column_ordinal, value, proof_base_field_modulus)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let product_expression =
        ordered_injective_integer_factor_product_expression(&ordered_factor_expressions)?;
    Ok((product_expression, ordered_factor_expressions))
}

fn finite_integer_set_factor_expression(
    column_ordinal: u32,
    value: &BigInt,
    proof_base_field_modulus: u64,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let (sign, magnitude_bytes) = value.to_bytes_be();
    let magnitude = BigUint::from_bytes_be(&magnitude_bytes);
    let magnitude = bounded_biguint_as_u64(&magnitude, proof_base_field_modulus)?;
    let encoded_value = match sign {
        Sign::Minus if magnitude != 0 => proof_base_field_modulus - magnitude,
        Sign::NoSign if magnitude == 0 => 0,
        Sign::Plus => magnitude,
        _ => return Err(RelationPlanError::InvalidSignedMagnitude),
    };
    Ok(vec![
        unrotated_column_expression(column_ordinal),
        RelationExpressionInstruction::BaseFieldConstant(modular_negation(
            encoded_value,
            proof_base_field_modulus,
        )),
        RelationExpressionInstruction::Addition,
    ])
}

pub(crate) fn ordered_injective_integer_factor_product_expression(
    ordered_factor_expressions: &[Vec<RelationExpressionInstruction>],
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    if ordered_factor_expressions.len() < 2
        || ordered_factor_expressions
            .iter()
            .any(|factor_expression| factor_expression.is_empty())
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let instruction_count = ordered_factor_expressions.iter().try_fold(
        ordered_factor_expressions.len() - 1,
        |count, factor_expression| {
            count
                .checked_add(factor_expression.len())
                .ok_or(RelationPlanError::CountOverflow)
        },
    )?;
    let mut product_expression = Vec::with_capacity(instruction_count);
    for (factor_ordinal, factor_expression) in ordered_factor_expressions.iter().enumerate() {
        product_expression.extend_from_slice(factor_expression);
        if factor_ordinal > 0 {
            product_expression.push(RelationExpressionInstruction::Multiplication);
        }
    }
    Ok(product_expression)
}

fn expression_column_ordinals(
    expression: &[RelationExpressionInstruction],
    variant: &RelationPlanVariant,
) -> Result<BTreeSet<u32>, RelationPlanError> {
    let mut column_ordinals = BTreeSet::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::ColumnValue { column_ordinal, .. } => {
                column_ordinals.insert(*column_ordinal);
            }
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                ..
            } => {
                let convolution = variant
                    .ordered_radix_convolutions
                    .get(*convolution_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                for term in &convolution.ordered_terms {
                    for factor in &term.ordered_factors {
                        match factor {
                            RelationRadixFactorDescriptor::ColumnDigits {
                                ordered_column_ordinals,
                                ..
                            } => {
                                column_ordinals.extend(ordered_column_ordinals.iter().copied());
                            }
                            RelationRadixFactorDescriptor::ScalarColumn {
                                column_ordinal, ..
                            } => {
                                column_ordinals.insert(*column_ordinal);
                            }
                            RelationRadixFactorDescriptor::ConstantDigits { .. }
                            | RelationRadixFactorDescriptor::TranscriptChallengeDigits { .. }
                            | RelationRadixFactorDescriptor::NonNativeModulusDigits { .. } => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if column_ordinals.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(column_ordinals)
}

fn required_column_rotations(
    constraints: &[RelationConstraintDescriptor],
    radix_convolutions: &[RelationRadixConvolutionDescriptor],
) -> Result<BTreeMap<u32, BTreeSet<(bool, u64)>>, RelationPlanError> {
    let mut rotations_by_column = BTreeMap::<u32, BTreeSet<_>>::new();
    for constraint in constraints {
        for instruction in &constraint.numerator_postfix_expression {
            match instruction {
                RelationExpressionInstruction::ColumnValue {
                    column_ordinal,
                    rotation_is_negative,
                    rotation_magnitude,
                } => {
                    rotations_by_column
                        .entry(*column_ordinal)
                        .or_default()
                        .insert((*rotation_is_negative, *rotation_magnitude));
                }
                RelationExpressionInstruction::RadixConvolutionCoefficient {
                    convolution_ordinal,
                    ..
                } => {
                    let convolution = radix_convolutions
                        .get(*convolution_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidOpening)?;
                    for factor in convolution
                        .ordered_terms
                        .iter()
                        .flat_map(|term| &term.ordered_factors)
                    {
                        match factor {
                            RelationRadixFactorDescriptor::ColumnDigits {
                                ordered_column_ordinals,
                                rotation_is_negative,
                                rotation_magnitude,
                            } => {
                                for column_ordinal in ordered_column_ordinals {
                                    rotations_by_column
                                        .entry(*column_ordinal)
                                        .or_default()
                                        .insert((*rotation_is_negative, *rotation_magnitude));
                                }
                            }
                            RelationRadixFactorDescriptor::ScalarColumn {
                                column_ordinal, ..
                            } => {
                                rotations_by_column
                                    .entry(*column_ordinal)
                                    .or_default()
                                    .insert((false, 0));
                            }
                            RelationRadixFactorDescriptor::ConstantDigits { .. }
                            | RelationRadixFactorDescriptor::TranscriptChallengeDigits { .. }
                            | RelationRadixFactorDescriptor::NonNativeModulusDigits { .. } => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(rotations_by_column)
}

#[derive(Clone, Copy)]
struct ExpressionShape {
    value_type: RelationColumnValueType,
    degree: u64,
    constant_value: Option<u64>,
}

fn check_expression(
    expression: &[RelationExpressionInstruction],
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    zeroifier: bool,
) -> Result<ExpressionShape, RelationPlanError> {
    if expression.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut stack = Vec::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                if *value >= context.base_field_modulus {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: 0,
                    constant_value: Some(*value),
                });
            }
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } => {
                if zeroifier {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                let value = resolved_modulus_multiple(*modulus_reference, *multiplier, context)?;
                if value >= context.base_field_modulus {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: 0,
                    constant_value: Some(value),
                });
            }
            RelationExpressionInstruction::EvaluationVariable => stack.push(ExpressionShape {
                value_type: RelationColumnValueType::BaseField,
                degree: 1,
                constant_value: None,
            }),
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => {
                if zeroifier
                    || (*rotation_magnitude == 0 && *rotation_is_negative)
                    || *rotation_magnitude >= variant.trace_domain_size
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let column = variant
                    .ordered_columns
                    .get(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(ExpressionShape {
                    value_type: column.value_type,
                    degree: column.source_degree_bound_exclusive - 1,
                    constant_value: None,
                });
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => {
                if zeroifier {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                challenge_descriptor(
                    *challenge_role,
                    role_coordinates.clone(),
                    1,
                    variant,
                    context,
                )?;
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::ChallengeExtension,
                    degree: 0,
                    constant_value: None,
                });
            }
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } => {
                if zeroifier {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                stack.push(radix_convolution_expression_shape(
                    variant,
                    *convolution_ordinal,
                    *coefficient_ordinal,
                )?);
            }
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } => {
                if !zeroifier
                    || *trace_domain_size != variant.trace_domain_size
                    || ordered_excluded_roots.is_empty()
                    || !strictly_sorted_unique(ordered_excluded_roots)
                    || ordered_excluded_roots.len() as u64 >= *trace_domain_size
                    || ordered_excluded_roots.iter().any(|root| {
                        *root == 0
                            || *root >= context.base_field_modulus
                            || modular_power(*root, *trace_domain_size, context.base_field_modulus)
                                != 1
                    })
                {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: trace_domain_size
                        .checked_sub(ordered_excluded_roots.len() as u64)
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?,
                    constant_value: None,
                });
            }
            RelationExpressionInstruction::Addition
            | RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let value_type = if left.value_type == RelationColumnValueType::ChallengeExtension
                    || right.value_type == RelationColumnValueType::ChallengeExtension
                {
                    RelationColumnValueType::ChallengeExtension
                } else {
                    RelationColumnValueType::BaseField
                };
                let (degree, constant_value) =
                    if matches!(instruction, RelationExpressionInstruction::Addition) {
                        (
                            left.degree.max(right.degree),
                            left.constant_value
                                .zip(right.constant_value)
                                .map(|(left, right)| {
                                    modular_sum(left, right, context.base_field_modulus)
                                }),
                        )
                    } else {
                        (
                            left.degree
                                .checked_add(right.degree)
                                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
                            left.constant_value
                                .zip(right.constant_value)
                                .map(|(left, right)| {
                                    modular_product(left, right, context.base_field_modulus)
                                }),
                        )
                    };
                stack.push(ExpressionShape {
                    value_type,
                    degree,
                    constant_value,
                });
            }
            RelationExpressionInstruction::Negation => {
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                value.constant_value = value
                    .constant_value
                    .map(|constant| modular_negation(constant, context.base_field_modulus));
                stack.push(value);
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                value.degree = value
                    .degree
                    .checked_mul(*exponent)
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                value.constant_value = value
                    .constant_value
                    .map(|constant| modular_power(constant, *exponent, context.base_field_modulus));
                stack.push(value);
            }
            RelationExpressionInstruction::FrobeniusConjugate(conjugate_index) => {
                if zeroifier || *conjugate_index >= context.challenge_extension_degree {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                value.value_type = RelationColumnValueType::ChallengeExtension;
                value.constant_value = None;
                stack.push(value);
            }
        }
    }
    if stack.len() != 1 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    stack.pop().ok_or(RelationPlanError::InvalidConstraint)
}

fn radix_convolution_expression_shape(
    variant: &RelationPlanVariant,
    convolution_ordinal: u32,
    coefficient_ordinal: u32,
) -> Result<ExpressionShape, RelationPlanError> {
    let convolution = variant
        .ordered_radix_convolutions
        .get(convolution_ordinal as usize)
        .ok_or(RelationPlanError::InvalidConstraint)?;
    let coefficient_ordinal = u64::from(coefficient_ordinal);
    let mut maximum_degree = None;
    for term in &convolution.ordered_terms {
        let mut maximum_coefficient_ordinal = 0_u64;
        let mut term_degree = 0_u64;
        let mut has_column_factor = false;
        for factor in &term.ordered_factors {
            match factor {
                RelationRadixFactorDescriptor::ColumnDigits {
                    ordered_column_ordinals,
                    ..
                } => {
                    maximum_coefficient_ordinal = maximum_coefficient_ordinal
                        .checked_add(
                            u64::try_from(ordered_column_ordinals.len() - 1)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    let factor_degree = ordered_column_ordinals
                        .iter()
                        .map(|column_ordinal| {
                            variant
                                .ordered_columns
                                .get(*column_ordinal as usize)
                                .map(|column| column.source_degree_bound_exclusive - 1)
                                .ok_or(RelationPlanError::InvalidConstraint)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .max()
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    term_degree = term_degree
                        .checked_add(factor_degree)
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    has_column_factor = true;
                }
                RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => {
                    maximum_coefficient_ordinal = maximum_coefficient_ordinal
                        .checked_add(
                            u64::try_from(ordered_digits.len() - 1)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                }
                RelationRadixFactorDescriptor::TranscriptChallengeDigits {
                    digit_count, ..
                } => {
                    maximum_coefficient_ordinal = maximum_coefficient_ordinal
                        .checked_add(u64::from(
                            digit_count
                                .checked_sub(1)
                                .ok_or(RelationPlanError::InvalidConstraint)?,
                        ))
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                }
                RelationRadixFactorDescriptor::NonNativeModulusDigits { digit_count, .. } => {
                    maximum_coefficient_ordinal = maximum_coefficient_ordinal
                        .checked_add(u64::from(
                            digit_count
                                .checked_sub(1)
                                .ok_or(RelationPlanError::InvalidConstraint)?,
                        ))
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                }
                RelationRadixFactorDescriptor::ScalarColumn { column_ordinal, .. } => {
                    term_degree = term_degree
                        .checked_add(
                            variant
                                .ordered_columns
                                .get(*column_ordinal as usize)
                                .map(|column| column.source_degree_bound_exclusive - 1)
                                .ok_or(RelationPlanError::InvalidConstraint)?,
                        )
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    has_column_factor = true;
                }
            }
        }
        if !has_column_factor {
            return Err(RelationPlanError::InvalidConstraint);
        }
        if coefficient_ordinal <= maximum_coefficient_ordinal {
            maximum_degree = Some(maximum_degree.unwrap_or(0_u64).max(term_degree));
        }
    }
    Ok(ExpressionShape {
        value_type: RelationColumnValueType::BaseField,
        degree: maximum_degree.ok_or(RelationPlanError::InvalidConstraint)?,
        constant_value: None,
    })
}

fn evaluate_integer_interval(
    expression: &[RelationExpressionInstruction],
    column_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let mut stack = Vec::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                let centered = if *value > context.base_field_modulus / 2 {
                    BigInt::from(*value) - BigInt::from(context.base_field_modulus)
                } else {
                    BigInt::from(*value)
                };
                stack.push(SignedIntegerInterval::from_bigints(
                    centered.clone(),
                    centered,
                )?);
            }
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } => {
                let value = resolved_modulus_multiple(*modulus_reference, *multiplier, context)?;
                if value >= context.base_field_modulus {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
                stack.push(SignedIntegerInterval::from_bigints(
                    BigInt::from(value),
                    BigInt::from(value),
                )?);
            }
            RelationExpressionInstruction::ColumnValue { column_ordinal, .. } => {
                stack.push(
                    column_bounds
                        .get(column_ordinal)
                        .cloned()
                        .ok_or(RelationPlanError::InvalidSemanticCell)?,
                );
            }
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } => {
                let convolution = variant
                    .ordered_radix_convolutions
                    .get(*convolution_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(evaluate_radix_convolution_interval(
                    convolution,
                    *coefficient_ordinal,
                    column_bounds,
                    variant,
                    context,
                )?);
            }
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(left.add(right)?);
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(left.multiply(right)?);
            }
            RelationExpressionInstruction::Negation => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(value.negate()?);
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(value.power(*exponent)?);
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role:
                    challenge_role @ (RelationChallengeRole::NonNativeTheta
                    | RelationChallengeRole::NonNativeAlpha),
                role_coordinates,
            } => {
                challenge_descriptor(
                    *challenge_role,
                    role_coordinates.clone(),
                    1,
                    variant,
                    context,
                )?;
                let modulus_ordinal = role_coordinates
                    .first()
                    .copied()
                    .and_then(|ordinal| usize::try_from(ordinal).ok())
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                let modulus_reference = variant
                    .ordered_non_native_moduli
                    .get(modulus_ordinal)
                    .copied()
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                let modulus = context.resolved_modulus(modulus_reference)?;
                stack.push(SignedIntegerInterval::from_bigints(
                    BigInt::zero(),
                    BigInt::from(modulus - 1),
                )?);
            }
            RelationExpressionInstruction::EvaluationVariable
            | RelationExpressionInstruction::TranscriptChallenge { .. }
            | RelationExpressionInstruction::FrobeniusConjugate(_)
            | RelationExpressionInstruction::TraceDomainExceptRoots { .. } => {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }
    }
    if stack.len() != 1 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    stack.pop().ok_or(RelationPlanError::InvalidConstraint)
}

fn evaluate_radix_convolution_interval(
    convolution: &RelationRadixConvolutionDescriptor,
    coefficient_ordinal: u32,
    column_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let coefficient_ordinal =
        usize::try_from(coefficient_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
    let mut sum = SignedIntegerInterval::new(0, 0);
    for term in &convolution.ordered_terms {
        let mut coefficients = vec![SignedIntegerInterval::new(1, 1)];
        for factor in &term.ordered_factors {
            let factor_coefficients = match factor {
                RelationRadixFactorDescriptor::ColumnDigits {
                    ordered_column_ordinals,
                    ..
                } => ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        column_bounds
                            .get(column_ordinal)
                            .cloned()
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => ordered_digits
                    .iter()
                    .map(|digit| {
                        SignedIntegerInterval::from_bigints(
                            BigInt::from(*digit),
                            BigInt::from(*digit),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                RelationRadixFactorDescriptor::TranscriptChallengeDigits {
                    challenge_role,
                    role_coordinates,
                    digit_count,
                } => {
                    let descriptor = challenge_descriptor(
                        *challenge_role,
                        role_coordinates.clone(),
                        1,
                        variant,
                        context,
                    )?;
                    let modulus = descriptor
                        .resolved_sampling(variant, context)?
                        .coordinate_modulus;
                    radix_digit_intervals(modulus - 1, convolution.radix, *digit_count)?
                }
                RelationRadixFactorDescriptor::NonNativeModulusDigits {
                    modulus_reference,
                    multiplier,
                    digit_count,
                } => {
                    let value =
                        resolved_modulus_multiple(*modulus_reference, *multiplier, context)?;
                    exact_radix_digit_intervals(value, convolution.radix, *digit_count)?
                }
                RelationRadixFactorDescriptor::ScalarColumn {
                    column_ordinal,
                    complement_binary_value,
                } => {
                    let interval = column_bounds
                        .get(column_ordinal)
                        .cloned()
                        .ok_or(RelationPlanError::InvalidSemanticCell)?;
                    vec![if *complement_binary_value {
                        SignedIntegerInterval::from_bigints(
                            BigInt::one() - interval.maximum,
                            BigInt::one() - interval.minimum,
                        )?
                    } else {
                        interval
                    }]
                }
            };
            coefficients = convolve_interval_vectors(
                &coefficients,
                &factor_coefficients,
                coefficient_ordinal,
            )?;
        }
        let mut coefficient = coefficients
            .get(coefficient_ordinal)
            .cloned()
            .unwrap_or_else(|| SignedIntegerInterval::new(0, 0));
        if term.negative {
            coefficient = coefficient.negate()?;
        }
        sum = sum.add(coefficient)?;
    }
    Ok(sum)
}

fn minimum_radix_digit_count(maximum_value: u64, radix: u64) -> Result<u16, RelationPlanError> {
    if radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut remaining = maximum_value;
    let mut digit_count = 1_u16;
    while remaining >= radix {
        remaining /= radix;
        digit_count = digit_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(digit_count)
}

fn resolved_modulus_multiple(
    modulus_reference: SuiteModulusReference,
    multiplier: u16,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    if multiplier == 0 {
        return Err(RelationPlanError::InvalidModulus);
    }
    context
        .resolved_modulus(modulus_reference)?
        .checked_mul(u64::from(multiplier))
        .ok_or(RelationPlanError::IntegerBoundOverflow)
}

fn fixed_radix_u64_digits(
    mut value: u64,
    digit_count: usize,
    radix: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if digit_count == 0 || radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut digits = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        digits.push(value % radix);
        value /= radix;
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

fn exact_radix_digit_intervals(
    mut value: u64,
    radix: u64,
    digit_count: u16,
) -> Result<Vec<SignedIntegerInterval>, RelationPlanError> {
    if digit_count != minimum_radix_digit_count(value, radix)? {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut intervals = Vec::with_capacity(usize::from(digit_count));
    for _ in 0..digit_count {
        let digit = value % radix;
        value /= radix;
        intervals.push(SignedIntegerInterval::from_bigints(
            BigInt::from(digit),
            BigInt::from(digit),
        )?);
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(intervals)
}

fn radix_digit_intervals(
    maximum_value: u64,
    radix: u64,
    digit_count: u16,
) -> Result<Vec<SignedIntegerInterval>, RelationPlanError> {
    if digit_count != minimum_radix_digit_count(maximum_value, radix)? {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let most_significant_ordinal = usize::from(digit_count - 1);
    let mut most_significant_place_value = 1_u64;
    for _ in 0..most_significant_ordinal {
        most_significant_place_value = most_significant_place_value
            .checked_mul(radix)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    let most_significant_maximum = maximum_value / most_significant_place_value;
    Ok((0..usize::from(digit_count))
        .map(|digit_ordinal| {
            let maximum = if digit_ordinal == most_significant_ordinal {
                most_significant_maximum
            } else {
                radix - 1
            };
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))
        })
        .collect::<Result<Vec<_>, _>>()?)
}

fn convolve_interval_vectors(
    left: &[SignedIntegerInterval],
    right: &[SignedIntegerInterval],
    maximum_coefficient_ordinal: usize,
) -> Result<Vec<SignedIntegerInterval>, RelationPlanError> {
    let output_length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?
        .min(
            maximum_coefficient_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    let mut output = vec![SignedIntegerInterval::new(0, 0); output_length];
    for (left_ordinal, left_interval) in left.iter().enumerate() {
        for (right_ordinal, right_interval) in right.iter().enumerate() {
            let output_ordinal = left_ordinal
                .checked_add(right_ordinal)
                .ok_or(RelationPlanError::CountOverflow)?;
            if output_ordinal >= output_length {
                break;
            }
            output[output_ordinal] = output[output_ordinal]
                .clone()
                .add(left_interval.clone().multiply(right_interval.clone())?)?;
        }
    }
    Ok(output)
}

fn compile_base_field_polynomial(
    expression: &[RelationExpressionInstruction],
    modulus: u64,
    maximum_coefficient_count: usize,
) -> Result<Vec<u64>, RelationPlanError> {
    let mut stack: Vec<Vec<u64>> = Vec::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                stack.push(vec![*value]);
            }
            RelationExpressionInstruction::EvaluationVariable => stack.push(vec![0, 1]),
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                stack.push(polynomial_add(&left, &right, modulus)?);
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let product = polynomial_multiply(&left, &right, modulus)?;
                if product.len() > maximum_coefficient_count {
                    return Err(RelationPlanError::DegreeBoundExceeded);
                }
                stack.push(product);
            }
            RelationExpressionInstruction::Negation => {
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                for coefficient in &mut value {
                    *coefficient = modular_negation(*coefficient, modulus);
                }
                stack.push(value);
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let mut result = vec![1];
                let mut base = value;
                let mut remaining = *exponent;
                while remaining > 0 {
                    if remaining & 1 == 1 {
                        result = polynomial_multiply(&result, &base, modulus)?;
                        if result.len() > maximum_coefficient_count {
                            return Err(RelationPlanError::DegreeBoundExceeded);
                        }
                    }
                    remaining >>= 1;
                    if remaining > 0 {
                        base = polynomial_multiply(&base, &base, modulus)?;
                        if base.len() > maximum_coefficient_count {
                            return Err(RelationPlanError::DegreeBoundExceeded);
                        }
                    }
                }
                stack.push(result);
            }
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } => {
                let coefficient_count = usize::try_from(
                    trace_domain_size
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?,
                )
                .map_err(|_| RelationPlanError::CountOverflow)?;
                if coefficient_count > maximum_coefficient_count
                    || ordered_excluded_roots.is_empty()
                    || !strictly_sorted_unique(ordered_excluded_roots)
                {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                let mut polynomial = vec![0; coefficient_count];
                polynomial[0] = modulus - 1;
                polynomial[coefficient_count - 1] = 1;
                for root in ordered_excluded_roots {
                    polynomial = divide_polynomial_by_root(&polynomial, *root, modulus)?;
                }
                stack.push(polynomial);
            }
            _ => return Err(RelationPlanError::InvalidZeroifier),
        }
    }
    if stack.len() != 1 {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let mut polynomial = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
    while polynomial.len() > 1 && polynomial.last() == Some(&0) {
        polynomial.pop();
    }
    Ok(polynomial)
}

fn divide_polynomial_by_root(
    polynomial: &[u64],
    root: u64,
    modulus: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if polynomial.len() < 2 || root == 0 || root >= modulus {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let mut quotient = vec![0; polynomial.len() - 1];
    quotient[polynomial.len() - 2] = polynomial[polynomial.len() - 1];
    for coefficient_ordinal in (1..polynomial.len() - 1).rev() {
        quotient[coefficient_ordinal - 1] = modular_sum(
            polynomial[coefficient_ordinal],
            modular_product(root, quotient[coefficient_ordinal], modulus),
            modulus,
        );
    }
    if modular_sum(
        polynomial[0],
        modular_product(root, quotient[0], modulus),
        modulus,
    ) != 0
    {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    Ok(quotient)
}

fn polynomial_add(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    let mut result = vec![0; left.len().max(right.len())];
    for (index, value) in left.iter().enumerate() {
        result[index] = *value;
    }
    for (index, value) in right.iter().enumerate() {
        result[index] = modular_sum(result[index], *value, modulus);
    }
    Ok(result)
}

fn polynomial_multiply(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    let length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut result = vec![0; length];
    for (left_index, left_value) in left.iter().enumerate() {
        for (right_index, right_value) in right.iter().enumerate() {
            let position = left_index + right_index;
            result[position] = modular_sum(
                result[position],
                modular_product(*left_value, *right_value, modulus),
                modulus,
            );
        }
    }
    Ok(result)
}

fn evaluate_polynomial(polynomial: &[u64], point: u64, modulus: u64) -> u64 {
    polynomial.iter().rev().fold(0, |value, coefficient| {
        modular_sum(
            modular_product(value, point, modulus),
            *coefficient,
            modulus,
        )
    })
}

fn modular_sum(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}

fn modular_negation(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = modular_product(result, base, modulus);
        }
        exponent >>= 1;
        if exponent > 0 {
            base = modular_product(base, base, modulus);
        }
    }
    result
}

fn validate_challenge_catalog(
    catalog: &[RelationChallengeDescriptor],
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    if catalog.is_empty() || !strictly_sorted_unique(catalog) {
        return Err(RelationPlanError::InvalidChallengeCatalog);
    }
    for descriptor in catalog {
        descriptor.validate(variant, context)?;
    }
    Ok(())
}

fn strictly_sorted_unique<Value: Ord>(values: &[Value]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn strictly_sorted_unique_by_key<Value, Key: Ord + Copy>(
    values: &[Value],
    key: impl Fn(&Value) -> Key,
) -> bool {
    values
        .windows(2)
        .all(|window| key(&window[0]) < key(&window[1]))
}

fn canonical_u32_list(values: &[u32]) -> Result<CanonicalItem, RelationPlanError> {
    let values = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned32)
        .collect::<Vec<_>>();
    canonical_generated_list(CanonicalItemType::Unsigned32, &values)
}

fn canonical_u8_list(values: &[u8]) -> Result<CanonicalItem, RelationPlanError> {
    let values = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned8)
        .collect::<Vec<_>>();
    canonical_generated_list(CanonicalItemType::Unsigned8, &values)
}

fn canonical_u64_list(values: &[u64]) -> Result<CanonicalItem, RelationPlanError> {
    let values = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    canonical_generated_list(CanonicalItemType::Unsigned64, &values)
}

fn canonical_nested_list(
    tuples: impl IntoIterator<Item = CanonicalTuple>,
) -> Result<CanonicalItem, RelationPlanError> {
    let values = tuples
        .into_iter()
        .map(|tuple| {
            let limits = generated_tuple_encoding_limits(&tuple, true)?;
            CanonicalItem::nested_tuple_with_limits(&tuple, &limits)
                .map_err(canonical_encoding_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical_generated_list(CanonicalItemType::NestedTuple, &values)
}

fn canonical_generated_list(
    element_type: CanonicalItemType,
    values: &[CanonicalItem],
) -> Result<CanonicalItem, RelationPlanError> {
    let canonical_byte_length = values.iter().try_fold(6_usize, |length, value| {
        length
            .checked_add(value.canonical_bytes().len())
            .ok_or(RelationPlanError::CountOverflow)
    })?;
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: canonical_byte_length,
        maximum_item_count: values.len(),
        maximum_item_byte_length: canonical_byte_length,
        ..CanonicalDecodeLimits::default()
    };
    CanonicalItem::homogeneous_list_with_limits(element_type, values, &limits)
        .map_err(canonical_encoding_error)
}

fn generated_tuple_encoding_limits(
    tuple: &CanonicalTuple,
    nested_item: bool,
) -> Result<CanonicalDecodeLimits, RelationPlanError> {
    let tuple_byte_length = tuple.items.iter().try_fold(8_usize, |length, item| {
        u32::try_from(item.canonical_bytes().len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        length
            .checked_add(6)
            .and_then(|value| value.checked_add(item.canonical_bytes().len()))
            .ok_or(RelationPlanError::CountOverflow)
    })?;
    let maximum_contained_item_byte_length = tuple
        .items
        .iter()
        .map(|item| item.canonical_bytes().len())
        .max()
        .unwrap_or(0);
    Ok(CanonicalDecodeLimits {
        maximum_tuple_byte_length: tuple_byte_length,
        maximum_item_count: tuple.items.len(),
        maximum_item_byte_length: if nested_item {
            maximum_contained_item_byte_length.max(tuple_byte_length)
        } else {
            maximum_contained_item_byte_length
        },
        ..CanonicalDecodeLimits::default()
    })
}

fn encode_generated_tuple(tuple: &CanonicalTuple) -> Result<Vec<u8>, RelationPlanError> {
    tuple
        .encode_with_limits(&generated_tuple_encoding_limits(tuple, false)?)
        .map_err(canonical_encoding_error)
}

fn hash_generated_variable_bytes(
    domain: &str,
    canonical_bytes: &[u8],
) -> Result<[u8; 64], RelationPlanError> {
    let mut hasher =
        StreamingFoundationTupleHash512::new_variable_bytes(domain, &[], canonical_bytes.len())
            .map_err(|_| RelationPlanError::CanonicalEncoding)?;
    hasher
        .absorb(canonical_bytes)
        .map_err(|_| RelationPlanError::CanonicalEncoding)?;
    Ok(hasher
        .finalize()
        .map_err(|_| RelationPlanError::CanonicalEncoding)?
        .into_bytes())
}

mod aggregate_threshold_share;
mod ballot_validity;
mod committed_material;
mod interpreter;
mod key_relation;
mod public_aggregate;
mod public_key_share;
mod same_secret_anchor;
mod target_release;
mod trustee_evaluation_key;
mod vss_share_linkage;

pub(crate) use aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan;
pub(crate) use ballot_validity::{
    BallotValidityRelationPlanInput, compile_ballot_validity_relation_plan,
};
pub(crate) use committed_material::CommittedMaterialRelationPlanInput;
pub(crate) use interpreter::{
    RelationApplicationChallengeAssignment, RelationConstraintEvaluation,
};
pub(crate) use key_relation::{PublicKeyShareRelationPlanInput, SameSecretRelationPlanInput};
pub(crate) use public_aggregate::{
    CollectivePublicKeyAggregatePlanInput, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput,
    PublicAggregateRelationGeometry, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
};
pub(crate) use public_key_share::compile_public_key_share_relation_plan;
pub(crate) use same_secret_anchor::compile_same_secret_relation_plan;
pub(crate) use target_release::{
    CompiledTargetReleaseRelation, TargetReleaseCapabilityError, TargetReleaseModulusWitness,
    TargetReleaseRelationPlanInput, TargetReleaseRoleWitness, TargetReleaseVerifiedColumnEvaluator,
    TargetReleaseWitness, TargetReleaseWitnessError, VerifiedTargetReleaseModulusInput,
    VerifiedTargetReleaseProof, compile_target_release_relation,
    compile_target_release_relation_plan, target_release_radix_semantics_match,
};
pub(crate) use trustee_evaluation_key::{
    GaloisKeyShareRelationPlanInput, RelinearizationRoundOneRelationPlanInput,
    RelinearizationRoundTwoRelationPlanInput, TrusteeEvaluationKeyDecompositionBlock,
    TrusteeEvaluationKeyRelationGeometry, compile_galois_key_share_relation_plan,
    compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan,
};
pub(crate) use vss_share_linkage::compile_vss_share_linkage_relation_plan;
#[cfg(test)]
mod tests;
