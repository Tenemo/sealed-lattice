use num_bigint::BigUint;
use num_traits::One;

use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple};

use super::{
    compiled_plan::RelationPlanCheckContext,
    expressions::{
        canonical_nested_list, canonical_u32_list, canonical_u64_list,
        checked_resident_payload_add, encode_generated_tuple, resident_string_payload_byte_length,
        resident_vec_storage_byte_length,
    },
    layout::RelationPlanVariant,
    schema::{
        APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER, BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER,
        BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
        DIRECT_BALLOT_PAIR_CHARACTER_ENCODER_PROFILE_SOURCE_SCHEMA_IDENTIFIER,
        NEGACYCLIC_AUTOMORPHISM_MAPPING_SOURCE_SCHEMA_IDENTIFIER,
        PROOF_CREATED_TREE_SCHEMA_IDENTIFIER, PROTOCOL_SOURCE_SCHEMA_IDENTIFIER,
        PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER, PUBLIC_ONLY_FAMILIES,
        RADIX_DECOMPOSED_VERIFIER_SOURCE_SCHEMA_IDENTIFIER,
        RELATION_CHALLENGE_DESCRIPTOR_SCHEMA_IDENTIFIER,
        RELATION_CHALLENGE_EPOCH_CATALOG_SCHEMA_IDENTIFIER,
        RELATION_CHALLENGE_MODULUS_SELECTOR_SCHEMA_IDENTIFIER, RELATION_COLUMN_SCHEMA_IDENTIFIER,
        RELATION_PUBLIC_SAMPLER_SCHEMA_IDENTIFIER, SCHEMA_VERSION, SECRET_BEARING_FAMILIES,
        SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER, SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER,
        VALUE_LAYOUT_SCHEMA_IDENTIFIER, VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
    },
};

#[cfg(test)]
use super::schema::{
    RADIX_COLUMN_DIGITS_SCHEMA_IDENTIFIER, RADIX_CONSTANT_DIGITS_SCHEMA_IDENTIFIER,
    RADIX_CONVOLUTION_SCHEMA_IDENTIFIER, RADIX_PRODUCT_TERM_SCHEMA_IDENTIFIER,
    RADIX_SCALAR_COLUMN_SCHEMA_IDENTIFIER,
};

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
    CountOverflow,
}

pub(super) fn canonical_encoding_error<T>(_: T) -> RelationPlanError {
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
    pub(super) catalog: ModulusCatalog,
    pub(super) modulus_index: u16,
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

    pub(super) fn canonical_tuple(self) -> CanonicalTuple {
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
    pub(super) fn for_family(application_statement_schema_identifier: u16) -> Option<Self> {
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
    pub(super) element_kind: RelationElementKind,
    pub(super) residue_modulus: Option<SuiteModulusReference>,
    pub(super) shape: Vec<u64>,
    pub(super) embedding_kind: RelationEmbeddingKind,
}

impl RelationValueLayout {
    fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        resident_vec_storage_byte_length(&self.shape)
    }

    pub(super) fn scalar_hash() -> Self {
        Self {
            element_kind: RelationElementKind::Hash512,
            residue_modulus: None,
            shape: Vec::new(),
            embedding_kind: RelationEmbeddingKind::None,
        }
    }

    pub(super) fn residue_vector(modulus: SuiteModulusReference, element_count: u64) -> Self {
        Self {
            element_kind: RelationElementKind::Residue,
            residue_modulus: Some(modulus),
            shape: vec![element_count],
            embedding_kind: RelationEmbeddingKind::LeastNonnegative,
        }
    }

    pub(super) fn logical_element_count(&self) -> Result<u64, RelationPlanError> {
        self.shape.iter().try_fold(1_u64, |product, dimension| {
            if *dimension == 0 {
                return Err(RelationPlanError::InvalidSource);
            }
            product
                .checked_mul(*dimension)
                .ok_or(RelationPlanError::CountOverflow)
        })
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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

    pub(super) fn validate(&self) -> Result<(), RelationPlanError> {
        let _ = self.logical_element_count()?;
        match (
            self.element_kind,
            self.residue_modulus,
            self.embedding_kind,
            self.shape.is_empty(),
        ) {
            (RelationElementKind::Hash512, None, RelationEmbeddingKind::None, true)
            | (RelationElementKind::BaseField, None, RelationEmbeddingKind::Identity, _)
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationSelectorPathStep {
    pub(super) step_kind: SelectorPathStepKind,
    pub(super) argument: u64,
}

impl RelationSelectorPathStep {
    pub(super) const fn tuple_field(argument: u64) -> Self {
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

    pub(super) fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.step_kind as u16),
                CanonicalItem::unsigned64(self.argument),
            ],
        )
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
    NegacyclicAutomorphismMapping {
        ring_degree: u64,
        galois_element: u64,
    },
    /// One verifier-derived sparse coefficient profile in the suite-fixed
    /// pair-character encoder. Its ten fixed rotations linearly map one
    /// option's shared score indicators into one ciphertext's U/V auxiliary.
    DirectBallotPairCharacterEncoderProfile {
        ring_degree: u64,
        plaintext_modulus: u64,
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        option_count: u16,
        option_ordinal: u16,
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
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        match self {
            Self::ApplicationStatement {
                value_path,
                value_layout,
            } => checked_resident_payload_add(
                resident_vec_storage_byte_length(value_path)?,
                value_layout.resident_owned_payload_byte_length()?,
            ),
            Self::Protocol {
                source_coordinates,
                statement_binding_path,
                value_layout,
                ..
            } => [
                resident_vec_storage_byte_length(source_coordinates)?,
                resident_vec_storage_byte_length(statement_binding_path)?,
                value_layout.resident_owned_payload_byte_length()?,
            ]
            .into_iter()
            .try_fold(0_u64, checked_resident_payload_add),
            Self::RadixDecomposition { source, .. } => checked_resident_payload_add(
                u64::try_from(std::mem::size_of::<RelationVerifierSource>())
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                source.resident_owned_payload_byte_length()?,
            ),
            Self::NegacyclicAutomorphismMapping { .. }
            | Self::DirectBallotPairCharacterEncoderProfile { .. } => Ok(0),
        }
    }

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

    pub(super) fn value_layout(&self) -> Result<RelationValueLayout, RelationPlanError> {
        match self {
            Self::ApplicationStatement { value_layout, .. }
            | Self::Protocol { value_layout, .. } => Ok(value_layout.clone()),
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
            Self::DirectBallotPairCharacterEncoderProfile { ring_degree, .. } => {
                Ok(RelationValueLayout::residue_vector(
                    SuiteModulusReference::plaintext(),
                    *ring_degree,
                ))
            }
            Self::RadixDecomposition { source, .. } => {
                let source_layout = source.value_layout()?;
                Ok(RelationValueLayout {
                    element_kind: RelationElementKind::BaseField,
                    residue_modulus: None,
                    shape: source_layout.shape,
                    embedding_kind: RelationEmbeddingKind::Identity,
                })
            }
        }
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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
            Self::DirectBallotPairCharacterEncoderProfile {
                ring_degree,
                plaintext_modulus,
                ciphertext_ordinal,
                auxiliary_ordinal,
                option_count,
                option_ordinal,
            } => (
                DIRECT_BALLOT_PAIR_CHARACTER_ENCODER_PROFILE_SOURCE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::unsigned64(*ring_degree),
                    CanonicalItem::unsigned64(*plaintext_modulus),
                    CanonicalItem::unsigned16(*ciphertext_ordinal),
                    CanonicalItem::unsigned16(*auxiliary_ordinal),
                    CanonicalItem::unsigned16(*option_count),
                    CanonicalItem::unsigned16(*option_ordinal),
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

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }

    pub(super) fn validate_path(
        path: &[RelationSelectorPathStep],
    ) -> Result<(), RelationPlanError> {
        if path.is_empty() {
            return Err(RelationPlanError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn validate_shape(&self) -> Result<(), RelationPlanError> {
        match self {
            Self::ApplicationStatement {
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
            Self::NegacyclicAutomorphismMapping {
                ring_degree,
                galois_element,
            } => validate_negacyclic_automorphism(*ring_degree, *galois_element),
            Self::DirectBallotPairCharacterEncoderProfile {
                ring_degree,
                plaintext_modulus,
                ciphertext_ordinal,
                auxiliary_ordinal,
                option_count,
                option_ordinal,
            } => {
                let option_count = u64::from(*option_count);
                let pair_count = option_count
                    .checked_mul(option_count.saturating_sub(1))
                    .ok_or(RelationPlanError::CountOverflow)?
                    / 2;
                if *ring_degree < 2
                    || !ring_degree.is_power_of_two()
                    || option_count < 2
                    || pair_count > 256
                    || u64::from(*option_ordinal) >= option_count
                    || *ring_degree != 32_768
                    || *plaintext_modulus != 257
                    || *ciphertext_ordinal >= 2
                    || *auxiliary_ordinal >= 2
                {
                    return Err(RelationPlanError::InvalidSource);
                }
                Ok(())
            }
            Self::RadixDecomposition {
                source,
                modulus_reference,
                scale,
                radix,
                digit_ordinal,
                digit_count,
            } => {
                source.validate_shape()?;
                let layout = source.value_layout()?;
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
            u64::try_from((u128::from(residue) * u128::from(scale) / divisor) % u128::from(radix))
                .map_err(|_| RelationPlanError::IntegerBoundOverflow)
        })
        .collect()
}

pub(super) fn validate_negacyclic_automorphism(
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

#[cfg(test)]
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
    pub(super) seed_verifier_source_ordinal: u32,
    pub(super) role_domain: String,
    pub(super) canonical_role_coordinate_bytes: Vec<u8>,
    pub(super) output_modulus: SuiteModulusReference,
    pub(super) output_count: u64,
    pub(super) output_verifier_source_ordinal: u32,
}

impl RelationPublicSamplerDescriptor {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_resident_payload_add(
            resident_string_payload_byte_length(&self.role_domain)?,
            resident_vec_storage_byte_length(&self.canonical_role_coordinate_bytes)?,
        )
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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
    pub(super) fn canonical_tuple(&self) -> CanonicalTuple {
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
    pub(super) origin: RelationColumnOrigin,
    pub(super) value_type: RelationColumnValueType,
    pub(super) source_degree_bound_exclusive: u64,
    pub(super) canonical_residue_modulus: Option<SuiteModulusReference>,
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

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        match self {
            Self::ProofCreated {
                ordered_column_ordinals,
                ..
            }
            | Self::BoundPublic {
                ordered_column_ordinals,
                ..
            } => resident_vec_storage_byte_length(ordered_column_ordinals),
        }
    }

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

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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
    pub(super) fn canonical_tuple(self) -> CanonicalTuple {
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

    pub(super) fn resolve(
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
    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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

    pub(super) fn sampling_kind(&self) -> u16 {
        match self.sampling {
            RelationChallengeSampling::IndependentResidues { .. } => 1,
            RelationChallengeSampling::NonzeroExtensionVectors { .. } => 2,
            RelationChallengeSampling::DistinctPositions { .. } => 3,
            RelationChallengeSampling::ProductResidueVectorCoordinate { .. } => 4,
            RelationChallengeSampling::PowerOfProductResidueVectorCoordinate { .. } => 5,
        }
    }

    pub(super) fn modulus_selector(&self) -> RelationChallengeModulusSelector {
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

    pub(super) fn coordinate_count(&self) -> u16 {
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

    pub(super) fn maximum_candidate_draws_per_output(&self) -> u32 {
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

    pub(super) fn validate(
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
#[cfg(test)]
pub(crate) enum RelationRadixFactorDescriptor {
    ColumnDigits {
        ordered_column_ordinals: Vec<u32>,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
    },
    ConstantDigits {
        ordered_digits: Vec<u64>,
    },
    ScalarColumn {
        column_ordinal: u32,
        complement_binary_value: bool,
    },
}

#[cfg(test)]
impl RelationRadixFactorDescriptor {
    fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        match self {
            Self::ColumnDigits {
                ordered_column_ordinals,
                ..
            } => resident_vec_storage_byte_length(ordered_column_ordinals),
            Self::ConstantDigits { ordered_digits } => {
                resident_vec_storage_byte_length(ordered_digits)
            }
            Self::ScalarColumn { .. } => Ok(0),
        }
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct RelationRadixProductTermDescriptor {
    pub(super) negative: bool,
    pub(super) ordered_factors: Vec<RelationRadixFactorDescriptor>,
}

#[cfg(test)]
impl RelationRadixProductTermDescriptor {
    fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        self.ordered_factors.iter().try_fold(
            resident_vec_storage_byte_length(&self.ordered_factors)?,
            |total, factor| {
                checked_resident_payload_add(total, factor.resident_owned_payload_byte_length()?)
            },
        )
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationRadixConvolutionDescriptor {
    #[cfg(test)]
    pub(super) radix: u64,
    #[cfg(test)]
    pub(super) ordered_terms: Vec<RelationRadixProductTermDescriptor>,
}

impl RelationRadixConvolutionDescriptor {
    #[cfg(not(test))]
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        Err(RelationPlanError::InvalidConstraint)
    }

    #[cfg(test)]
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        self.ordered_terms.iter().try_fold(
            resident_vec_storage_byte_length(&self.ordered_terms)?,
            |total, term| {
                checked_resident_payload_add(total, term.resident_owned_payload_byte_length()?)
            },
        )
    }

    #[cfg(not(test))]
    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Err(RelationPlanError::InvalidConstraint)
    }

    #[cfg(test)]
    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
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
