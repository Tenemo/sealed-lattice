use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

use std::rc::Rc;

use num_traits::ToPrimitive;
use zeroize::Zeroizing;

use crate::bgv::setup::{
    SetupGenerationCompactPublicKeyDevelopmentAuthority,
    setup_generation_compact_public_key_development_retained_payload_byte_length,
    with_setup_generation_compact_public_key_development_relation_reentry,
};
use crate::{
    bgv::{
        parameters::PLAINTEXT_MODULUS,
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, SetupGenerationAuthorityHandle,
            SetupGenerationKeyRelationApplication, SetupGenerationKeyRelationSource,
            SetupKeyRelationProofFamily, sample_collective_public_key_common_reference_limb,
            setup_commitment_matrix_polynomial, setup_generation_retained_memory_accounting,
            with_setup_generation_key_relation,
        },
    },
    foundation::{
        Hash512, PreparedActionProofAttemptSource, ProofApplicationSlotCeilings, RefusalReason,
    },
    hashing::hash_framed_parts_512,
    transcript_core::encode_hex,
};

use super::super::prover::requested_pre_challenge_source_column_ordinals;
use super::super::{
    CommonProofBoundTreeLeafSaltRequest, CommonProofProverError, CommonProofRelationPlanCapability,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequest, CommonProofSourcePolynomialRequestContext,
    CommonProofSourceProviderMemoryAccounting, ProofBaseFieldElement, ProofEvaluationDomain,
    ProofLeafVisibility, ProofTreeRole, ProvidedCommonProofSourcePolynomial,
    RelationProofTreeInput, StatementOwnedProofTreeInput,
};
#[cfg(test)]
use super::key_relation::PublicKeyShareRelationPlanInput;
use super::{
    BoundTreeConstructionKind, CompactAuthenticatedAssignmentCatalog,
    CompactPublicKeyRelationCatalog, PublicKeyShareSourceLayout, RelationBoundCertificate,
    RelationColumnOrigin, RelationIntegerLiftCoefficient, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanCheckContext,
    RelationPlanError, RelationPlanVariant, RelationTreeDescriptor, RelationVerifierSource,
    SameSecretSourceLayout, SuiteModulusReference,
    galois_key_share_adapter::{
        canonical_comparator_column_rows, exact_modular_quotient, exact_negacyclic_product_radix,
        exact_negacyclic_product_small, half_position, resolve_integer_lift_coefficient,
        signed_integer_to_base_field, split_rows_match, split_signed_i8_polynomial,
        split_signed_polynomial,
    },
    key_relation::{
        EXACT_INTEGER_LIFT_RADIX, ExactRadixDigitColumnCatalog, MATERIAL_DIGIT_RADIX,
        SplitIntegerVector, TRIT_RADIX, UpperBoundComparatorWitnessLayout,
    },
    public_key_share::compact_public_key_assignment_source_column_ordinals,
};
#[cfg(test)]
use super::{CompiledRelationPlan, RelationColumnValueType};

const SAME_SECRET_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/same-secret/source-replay-identity/v1";
const PUBLIC_KEY_SHARE_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/public-key-share/source-replay-identity/v1";

enum SetupKeyRelationSourceLayout {
    SameSecret(SameSecretSourceLayout),
    PublicKeyShare(PublicKeyShareSourceLayout),
}

enum SetupKeyRelationAuthorityAccess {
    RetainedRegistry(u32),
    CompactPublicKeyDevelopment(Rc<SetupGenerationCompactPublicKeyDevelopmentAuthority>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupKeyRelationSourceRequestProfile {
    CompleteRelation,
    CompactPublicKeyAssignment,
}

const COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_SCHEMA_VERSION: u16 = 1;
const COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_DIGEST_DOMAIN: &str =
    "sealed-lattice/compact-public-key-assignment-source-catalog/v1";
const MAXIMUM_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTE_LENGTH: usize = 256 * 1024;
const GENERATED_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTES: &[u8] =
    include_bytes!("compact_public_key_assignment_source.generated.json");

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompactPublicKeyAssignmentSourceCatalog {
    schema_version: u16,
    #[serde(
        serialize_with = "serialize_compact_assignment_source_hash",
        deserialize_with = "deserialize_compact_assignment_source_hash"
    )]
    complete_relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    relation_column_count: u32,
    assignment_catalog: CompactAuthenticatedAssignmentCatalog,
    ordered_sources: Vec<CompactPublicKeyAssignmentSource>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactPublicKeyAssignmentSource {
    column_ordinal: u32,
    derivation: CompactPublicKeySourceDerivation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum CompactPublicKeySourceDerivation {
    CommonSecret {
        half_ordinal: u8,
        centered_offset: u64,
    },
    PublicKeyError {
        half_ordinal: u8,
        centered_offset: u64,
    },
    PublicKeyShare {
        limb_ordinal: u16,
        half_ordinal: u8,
    },
    PublicKeyCommonReference {
        data_modulus_index: u16,
        first_logical_element_index: u64,
        logical_element_stride: u64,
    },
    PublicKeyQuotient {
        limb_ordinal: u16,
        data_modulus_index: u16,
        half_ordinal: u8,
    },
    AnchorHidingSecret {
        anchor_ordinal: u16,
        polynomial_ordinal: u16,
        half_ordinal: u8,
        centered_offset: u64,
    },
    AnchorHidingError {
        anchor_ordinal: u16,
        polynomial_ordinal: u16,
        half_ordinal: u8,
        centered_offset: u64,
    },
    AnchorCommitment {
        anchor_ordinal: u16,
        row_ordinal: u16,
        half_ordinal: u8,
    },
    SetupCommitmentMatrix {
        data_modulus_index: u16,
        matrix_row: u16,
        matrix_column: u16,
        first_logical_element_index: u64,
        logical_element_stride: u64,
    },
    AnchorQuotient {
        anchor_ordinal: u16,
        row_ordinal: u16,
        data_modulus_index: u16,
        half_ordinal: u8,
    },
}

impl CompactPublicKeySourceDerivation {
    fn matches_descriptor(
        &self,
        descriptor: &super::RelationColumnDescriptor,
        trace_domain_size: u64,
        ring_degree: u64,
    ) -> bool {
        let valid_half_ordinal = |half_ordinal: u8| half_ordinal < 2;
        let valid_verifier_range =
            |first_logical_element_index: u64, logical_element_stride: u64| {
                logical_element_stride != 0
                    && trace_domain_size
                        .checked_sub(1)
                        .and_then(|last_offset| last_offset.checked_mul(logical_element_stride))
                        .and_then(|last_offset| {
                            first_logical_element_index.checked_add(last_offset)
                        })
                        .is_some_and(|last_index| last_index < ring_degree)
            };
        match (self, descriptor.origin()) {
            (
                Self::PublicKeyCommonReference {
                    first_logical_element_index,
                    logical_element_stride,
                    ..
                }
                | Self::SetupCommitmentMatrix {
                    first_logical_element_index,
                    logical_element_stride,
                    ..
                },
                RelationColumnOrigin::VerifierSequence {
                    first_logical_element_index: descriptor_first_index,
                    logical_element_stride: descriptor_stride,
                    ..
                },
            ) => {
                first_logical_element_index == descriptor_first_index
                    && logical_element_stride == descriptor_stride
                    && valid_verifier_range(*first_logical_element_index, *logical_element_stride)
            }
            (
                Self::PublicKeyShare { half_ordinal, .. }
                | Self::AnchorCommitment { half_ordinal, .. },
                RelationColumnOrigin::BoundTree { .. },
            ) => valid_half_ordinal(*half_ordinal),
            (
                Self::CommonSecret { half_ordinal, .. }
                | Self::PublicKeyError { half_ordinal, .. }
                | Self::PublicKeyQuotient { half_ordinal, .. }
                | Self::AnchorHidingSecret { half_ordinal, .. }
                | Self::AnchorHidingError { half_ordinal, .. }
                | Self::AnchorQuotient { half_ordinal, .. },
                RelationColumnOrigin::Prover,
            ) => valid_half_ordinal(*half_ordinal),
            _ => false,
        }
    }
}

impl CompactPublicKeyAssignmentSourceCatalog {
    fn canonical_digest(&self) -> Result<[u8; Hash512::BYTE_LENGTH], RelationPlanError> {
        let canonical_bytes =
            serde_json::to_vec(self).map_err(|_| RelationPlanError::CanonicalEncoding)?;
        Ok(hash_framed_parts_512(
            COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_DIGEST_DOMAIN,
            &[canonical_bytes.as_slice()],
        ))
    }

    fn validate_generated(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), RelationPlanError> {
        self.assignment_catalog.validate_generated(relation)?;
        let source_column_ordinals = self.assignment_catalog.source_column_ordinals();
        let ring_degree = relation.ring_degree();
        let trace_domain_size = self.assignment_catalog.trace_domain_size();
        if self.schema_version != COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_SCHEMA_VERSION
            || self.relation_column_count == 0
            || self.ordered_sources.is_empty()
            || self.ordered_sources.len() != source_column_ordinals.len()
            || self.assignment_catalog.requested_source_column_count()
                != self
                    .assignment_catalog
                    .ignored_source_column_count()
                    .checked_add(
                        u64::try_from(self.ordered_sources.len())
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?
            || trace_domain_size.checked_mul(2) != Some(ring_degree)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        for (source_index, (source, expected_column_ordinal)) in self
            .ordered_sources
            .iter()
            .zip(source_column_ordinals)
            .enumerate()
        {
            let descriptor = self
                .assignment_catalog
                .source_descriptor(source_index)
                .ok_or(RelationPlanError::InvalidColumn)?;
            if source.column_ordinal != expected_column_ordinal
                || source.column_ordinal >= self.relation_column_count
                || !source
                    .derivation
                    .matches_descriptor(descriptor, trace_domain_size, ring_degree)
            {
                return Err(RelationPlanError::InvalidColumn);
            }
        }
        if self.complete_relation_plan_hash != relation.complete_relation_plan_hash()
            || self.canonical_digest()? != relation.assignment_source_catalog_digest()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(())
    }
}

pub(crate) fn selected_compact_public_key_assignment_source_catalog(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactPublicKeyAssignmentSourceCatalog, RelationPlanError> {
    if GENERATED_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTES.len()
        > MAXIMUM_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTE_LENGTH
    {
        return Err(RelationPlanError::CanonicalEncoding);
    }
    let canonical_bytes = GENERATED_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTES
        .strip_suffix(b"\n")
        .ok_or(RelationPlanError::CanonicalEncoding)?;
    let catalog: CompactPublicKeyAssignmentSourceCatalog = serde_json::from_slice(canonical_bytes)
        .map_err(|_| RelationPlanError::CanonicalEncoding)?;
    if serde_json::to_vec(&catalog).map_err(|_| RelationPlanError::CanonicalEncoding)?
        != canonical_bytes
    {
        return Err(RelationPlanError::CanonicalEncoding);
    }
    catalog.validate_generated(relation)?;
    Ok(catalog)
}

fn serialize_compact_assignment_source_hash<Serializer>(
    hash: &[u8; Hash512::BYTE_LENGTH],
    serializer: Serializer,
) -> Result<Serializer::Ok, Serializer::Error>
where
    Serializer: serde::Serializer,
{
    serde::Serialize::serialize(hash.as_slice(), serializer)
}

fn deserialize_compact_assignment_source_hash<'de, Deserializer>(
    deserializer: Deserializer,
) -> Result<[u8; Hash512::BYTE_LENGTH], Deserializer::Error>
where
    Deserializer: serde::Deserializer<'de>,
{
    let bytes = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        serde::de::Error::invalid_length(bytes.len(), &"exactly 64 hash bytes")
    })
}

#[cfg(test)]
fn record_unique_compact_public_key_derivation(
    selected: &mut Option<CompactPublicKeySourceDerivation>,
    candidate: CompactPublicKeySourceDerivation,
) -> Result<(), RelationPlanError> {
    if selected.replace(candidate).is_some() {
        Err(RelationPlanError::DuplicateItem)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn source_half_ordinal(vector: SplitIntegerVector, column_ordinal: u32) -> Option<u8> {
    vector
        .halves
        .iter()
        .position(|candidate| *candidate == column_ordinal)
        .and_then(|half_ordinal| u8::try_from(half_ordinal).ok())
}

#[cfg(test)]
fn derive_compact_public_key_source_derivation(
    column_ordinal: u32,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<CompactPublicKeySourceDerivation, RelationPlanError> {
    let descriptor = relation_plan_variant
        .ordered_columns()
        .get(usize::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
        .ok_or(RelationPlanError::InvalidColumn)?;
    if descriptor.value_type() != RelationColumnValueType::BaseField {
        return Err(RelationPlanError::InvalidColumn);
    }
    let mut selected = None;
    if let Some(half_ordinal) = source_half_ordinal(
        source_layout.common_secret.source.coefficients,
        column_ordinal,
    ) {
        record_unique_compact_public_key_derivation(
            &mut selected,
            CompactPublicKeySourceDerivation::CommonSecret {
                half_ordinal,
                centered_offset: source_layout.common_secret.source.offset,
            },
        )?;
    }
    if let Some(half_ordinal) =
        source_half_ordinal(source_layout.public_key_error.coefficients, column_ordinal)
    {
        record_unique_compact_public_key_derivation(
            &mut selected,
            CompactPublicKeySourceDerivation::PublicKeyError {
                half_ordinal,
                centered_offset: source_layout.public_key_error.offset,
            },
        )?;
    }
    for (limb_ordinal, vector) in source_layout
        .public_key_share_limbs
        .iter()
        .copied()
        .enumerate()
    {
        if let Some(half_ordinal) = source_half_ordinal(vector, column_ordinal) {
            record_unique_compact_public_key_derivation(
                &mut selected,
                CompactPublicKeySourceDerivation::PublicKeyShare {
                    limb_ordinal: u16::try_from(limb_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    half_ordinal,
                },
            )?;
        }
    }
    for (limb_ordinal, limb) in source_layout.ordered_limbs.iter().enumerate() {
        if let Some(half_ordinal) = limb
            .quotient_columns
            .iter()
            .position(|candidate| *candidate == column_ordinal)
            .and_then(|half_ordinal| u8::try_from(half_ordinal).ok())
        {
            record_unique_compact_public_key_derivation(
                &mut selected,
                CompactPublicKeySourceDerivation::PublicKeyQuotient {
                    limb_ordinal: u16::try_from(limb_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    data_modulus_index: limb.data_modulus_index,
                    half_ordinal,
                },
            )?;
        }
    }
    for (anchor_ordinal, anchor) in source_layout.ordered_anchors.iter().enumerate() {
        let anchor_ordinal =
            u16::try_from(anchor_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        for (polynomial_ordinal, hiding_secret) in
            anchor.opening.hiding_secrets().iter().enumerate()
        {
            if let Some(half_ordinal) =
                source_half_ordinal(hiding_secret.source.coefficients, column_ordinal)
            {
                record_unique_compact_public_key_derivation(
                    &mut selected,
                    CompactPublicKeySourceDerivation::AnchorHidingSecret {
                        anchor_ordinal,
                        polynomial_ordinal: u16::try_from(polynomial_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        half_ordinal,
                        centered_offset: hiding_secret.source.offset,
                    },
                )?;
            }
        }
        for (polynomial_ordinal, hiding_error) in anchor.opening.hiding_errors().iter().enumerate()
        {
            if let Some(half_ordinal) =
                source_half_ordinal(hiding_error.coefficients, column_ordinal)
            {
                record_unique_compact_public_key_derivation(
                    &mut selected,
                    CompactPublicKeySourceDerivation::AnchorHidingError {
                        anchor_ordinal,
                        polynomial_ordinal: u16::try_from(polynomial_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        half_ordinal,
                        centered_offset: hiding_error.offset,
                    },
                )?;
            }
        }
        for (row_ordinal, commitment) in anchor.commitments.iter().copied().enumerate() {
            if let Some(half_ordinal) = source_half_ordinal(commitment, column_ordinal) {
                record_unique_compact_public_key_derivation(
                    &mut selected,
                    CompactPublicKeySourceDerivation::AnchorCommitment {
                        anchor_ordinal,
                        row_ordinal: u16::try_from(row_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        half_ordinal,
                    },
                )?;
            }
        }
        for (row_ordinal, quotient_columns) in anchor.quotients.rows().iter().enumerate() {
            if let Some(half_ordinal) = quotient_columns
                .iter()
                .position(|candidate| *candidate == column_ordinal)
                .and_then(|half_ordinal| u8::try_from(half_ordinal).ok())
            {
                record_unique_compact_public_key_derivation(
                    &mut selected,
                    CompactPublicKeySourceDerivation::AnchorQuotient {
                        anchor_ordinal,
                        row_ordinal: u16::try_from(row_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        data_modulus_index: anchor.data_modulus_index,
                        half_ordinal,
                    },
                )?;
            }
        }
    }
    if let RelationColumnOrigin::VerifierSequence {
        verifier_source_ordinal,
        first_logical_element_index,
        logical_element_stride,
    } = descriptor.origin()
    {
        let verifier_source = relation_plan_variant
            .verifier_source(*verifier_source_ordinal)
            .ok_or(RelationPlanError::InvalidSource)?;
        let verifier_derivation = match verifier_source {
            RelationVerifierSource::Protocol {
                protocol_source_kind: 5,
                source_coordinates,
                ..
            } => {
                let [data_modulus_index, matrix_part, row, column] = source_coordinates.as_slice()
                else {
                    return Err(RelationPlanError::InvalidSource);
                };
                let matrix_row = match *matrix_part {
                    1 => *row,
                    2 if *row == 0 => u64::try_from(SETUP_COMMITMENT_MODULE_RANK)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    _ => return Err(RelationPlanError::InvalidSource),
                };
                CompactPublicKeySourceDerivation::SetupCommitmentMatrix {
                    data_modulus_index: u16::try_from(*data_modulus_index)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    matrix_row: u16::try_from(matrix_row)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    matrix_column: u16::try_from(*column)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    first_logical_element_index: *first_logical_element_index,
                    logical_element_stride: *logical_element_stride,
                }
            }
            RelationVerifierSource::Protocol {
                protocol_source_kind: 6,
                source_coordinates,
                ..
            } => {
                let [data_modulus_index] = source_coordinates.as_slice() else {
                    return Err(RelationPlanError::InvalidSource);
                };
                CompactPublicKeySourceDerivation::PublicKeyCommonReference {
                    data_modulus_index: u16::try_from(*data_modulus_index)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    first_logical_element_index: *first_logical_element_index,
                    logical_element_stride: *logical_element_stride,
                }
            }
            _ => return Err(RelationPlanError::InvalidSource),
        };
        record_unique_compact_public_key_derivation(&mut selected, verifier_derivation)?;
    }
    let selected = selected.ok_or(RelationPlanError::InvalidColumn)?;
    let origin_matches = matches!(
        (&selected, descriptor.origin()),
        (
            CompactPublicKeySourceDerivation::PublicKeyCommonReference { .. }
                | CompactPublicKeySourceDerivation::SetupCommitmentMatrix { .. },
            RelationColumnOrigin::VerifierSequence { .. }
        ) | (
            CompactPublicKeySourceDerivation::PublicKeyShare { .. }
                | CompactPublicKeySourceDerivation::AnchorCommitment { .. },
            RelationColumnOrigin::BoundTree { .. }
        ) | (
            CompactPublicKeySourceDerivation::CommonSecret { .. }
                | CompactPublicKeySourceDerivation::PublicKeyError { .. }
                | CompactPublicKeySourceDerivation::PublicKeyQuotient { .. }
                | CompactPublicKeySourceDerivation::AnchorHidingSecret { .. }
                | CompactPublicKeySourceDerivation::AnchorHidingError { .. }
                | CompactPublicKeySourceDerivation::AnchorQuotient { .. },
            RelationColumnOrigin::Prover
        )
    );
    if !origin_matches {
        return Err(RelationPlanError::InvalidColumn);
    }
    Ok(selected)
}

#[cfg(test)]
pub(crate) fn derive_compact_public_key_assignment_source_catalog(
    relation_plan: &CompiledRelationPlan,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactPublicKeyAssignmentSourceCatalog, RelationPlanError> {
    let assignment_catalog =
        CompactAuthenticatedAssignmentCatalog::derive(relation, relation_plan_variant)?;
    let ordered_sources = assignment_catalog
        .source_column_ordinals()
        .into_iter()
        .map(|column_ordinal| {
            Ok(CompactPublicKeyAssignmentSource {
                column_ordinal,
                derivation: derive_compact_public_key_source_derivation(
                    column_ordinal,
                    relation_plan_variant,
                    source_layout,
                )?,
            })
        })
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    Ok(CompactPublicKeyAssignmentSourceCatalog {
        schema_version: COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_SCHEMA_VERSION,
        complete_relation_plan_hash: relation_plan.canonical_hash()?,
        relation_column_count: u32::try_from(relation_plan_variant.ordered_columns().len())
            .map_err(|_| RelationPlanError::CountOverflow)?,
        assignment_catalog,
        ordered_sources,
    })
}

#[cfg(test)]
pub(crate) fn derive_bound_compact_public_key_catalogs(
    input: &PublicKeyShareRelationPlanInput,
    relation_plan: &CompiledRelationPlan,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<
    (
        CompactPublicKeyRelationCatalog,
        CompactPublicKeyAssignmentSourceCatalog,
    ),
    RelationPlanError,
> {
    let mut relation = super::compact_ring_vector::derive_compact_public_key_relation_catalog(
        input,
        relation_plan_variant,
        source_layout,
    )?;
    let source_catalog = derive_compact_public_key_assignment_source_catalog(
        relation_plan,
        relation_plan_variant,
        source_layout,
        &relation,
    )?;
    relation.bind_generated_authorities(
        relation_plan.canonical_hash()?,
        source_catalog.canonical_digest()?,
    )?;
    source_catalog.validate_generated(&relation)?;
    Ok((relation, source_catalog))
}

fn classify_setup_key_relation_source_request_profile(
    public_key_source_layout: Option<&PublicKeyShareSourceLayout>,
    relation_plan_variant: &RelationPlanVariant,
    requested_column_ordinals: &[u32],
) -> Result<SetupKeyRelationSourceRequestProfile, CommonProofProverError> {
    let complete_requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_plan_variant)?;
    if requested_column_ordinals == complete_requested_column_ordinals {
        return Ok(SetupKeyRelationSourceRequestProfile::CompleteRelation);
    }
    let Some(public_key_source_layout) = public_key_source_layout else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    let compact_requested_column_ordinals = compact_public_key_assignment_source_column_ordinals(
        relation_plan_variant,
        public_key_source_layout,
    )?;
    if requested_column_ordinals == compact_requested_column_ordinals {
        Ok(SetupKeyRelationSourceRequestProfile::CompactPublicKeyAssignment)
    } else {
        Err(CommonProofProverError::InvalidColumn)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CachedQuotientKey {
    Anchor {
        family: SetupKeyRelationProofFamily,
        anchor_ordinal: usize,
        row_ordinal: usize,
    },
    PublicKeyShare {
        limb_ordinal: usize,
    },
}

struct CachedQuotient {
    key: CachedQuotientKey,
    coefficients: Zeroizing<Vec<i128>>,
}

trait SetupKeyRelationAnchorCoefficientSource {
    fn source_family(&self) -> SetupKeyRelationProofFamily;
    fn public_setup_seed_bytes(&self) -> [u8; Hash512::BYTE_LENGTH];
    fn common_secret_coefficient_slice(&self) -> &[i8];
    fn anchor_count(&self) -> usize;
    fn anchor_hiding_secret_polynomial(
        &self,
        anchor_ordinal: usize,
        polynomial_ordinal: usize,
    ) -> Result<&[i8], RefusalReason>;
    fn anchor_hiding_error_polynomial(
        &self,
        anchor_ordinal: usize,
        polynomial_ordinal: usize,
    ) -> Result<&[i8], RefusalReason>;
    fn anchor_commitment_trace_row_half(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
        half_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason>;
    fn anchor_commitment_row(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<Vec<i128>, RefusalReason>;
    fn public_key_common_reference_limb(
        &self,
        data_modulus_index: u16,
        ring_degree: usize,
    ) -> Result<Vec<u64>, RefusalReason>;
}

trait PublicKeyShareCoefficientSource: SetupKeyRelationAnchorCoefficientSource {
    fn public_key_error_coefficient_slice(&self) -> Result<&[i8], RefusalReason>;
    fn public_key_limb_coefficient_slice(
        &self,
        limb_ordinal: usize,
    ) -> Result<&[u64], RefusalReason>;
    fn public_key_limb_count(&self) -> Result<usize, RefusalReason>;
}

impl SetupKeyRelationAnchorCoefficientSource for SetupGenerationKeyRelationSource<'_, '_> {
    fn source_family(&self) -> SetupKeyRelationProofFamily {
        self.family()
    }

    fn public_setup_seed_bytes(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed()
    }

    fn common_secret_coefficient_slice(&self) -> &[i8] {
        self.common_secret_coefficients()
    }

    fn anchor_count(&self) -> usize {
        self.anchor_openings().len()
    }

    fn anchor_hiding_secret_polynomial(
        &self,
        anchor_ordinal: usize,
        polynomial_ordinal: usize,
    ) -> Result<&[i8], RefusalReason> {
        self.anchor_openings()
            .get(anchor_ordinal)
            .and_then(|anchor| anchor.hiding_secret_polynomials().get(polynomial_ordinal))
            .map(|polynomial| polynomial.as_slice())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn anchor_hiding_error_polynomial(
        &self,
        anchor_ordinal: usize,
        polynomial_ordinal: usize,
    ) -> Result<&[i8], RefusalReason> {
        self.anchor_openings()
            .get(anchor_ordinal)
            .and_then(|anchor| anchor.hiding_error_polynomials().get(polynomial_ordinal))
            .map(|polynomial| polynomial.as_slice())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn anchor_commitment_trace_row_half(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
        half_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        self.anchor_openings()
            .get(anchor_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .commitment_trace_row_half(row_ordinal, half_ordinal)
    }

    fn anchor_commitment_row(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<Vec<i128>, RefusalReason> {
        self.anchor_openings()
            .get(anchor_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .commitment_row(row_ordinal)
    }

    fn public_key_common_reference_limb(
        &self,
        data_modulus_index: u16,
        ring_degree: usize,
    ) -> Result<Vec<u64>, RefusalReason> {
        if self.family() != SetupKeyRelationProofFamily::PublicKeyShare {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        sample_collective_public_key_common_reference_limb(
            &self.public_setup_seed(),
            data_modulus_index,
            ring_degree,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)
    }
}

impl PublicKeyShareCoefficientSource for SetupGenerationKeyRelationSource<'_, '_> {
    fn public_key_error_coefficient_slice(&self) -> Result<&[i8], RefusalReason> {
        Ok(self.public_key_share()?.centered_error_coefficients())
    }

    fn public_key_limb_coefficient_slice(
        &self,
        limb_ordinal: usize,
    ) -> Result<&[u64], RefusalReason> {
        self.public_key_share()?
            .ordered_limb_coefficients()
            .get(limb_ordinal)
            .map(|coefficients| coefficients.as_slice())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn public_key_limb_count(&self) -> Result<usize, RefusalReason> {
        Ok(self.public_key_share()?.ordered_limb_coefficients().len())
    }
}

#[cfg(test)]
pub(crate) struct CompactPublicKeyDevelopmentAnchorCoefficientSource {
    commitment_data_modulus_index: u16,
    commitment_rows: Box<[Vec<u64>]>,
    hiding_secret_polynomials: Box<[Zeroizing<Vec<i8>>]>,
    hiding_error_polynomials: Box<[Zeroizing<Vec<i8>>]>,
}

#[cfg(test)]
impl CompactPublicKeyDevelopmentAnchorCoefficientSource {
    pub(crate) fn new(
        commitment_data_modulus_index: u16,
        commitment_rows: Vec<Vec<u64>>,
        hiding_secret_polynomials: Vec<Zeroizing<Vec<i8>>>,
        hiding_error_polynomials: Vec<Zeroizing<Vec<i8>>>,
        ring_degree: usize,
    ) -> Result<Self, RefusalReason> {
        if ring_degree == 0
            || commitment_rows.len() != SETUP_COMMITMENT_MODULE_RANK + 1
            || commitment_rows.iter().any(|row| row.len() != ring_degree)
            || hiding_secret_polynomials.len()
                != crate::bgv::setup::SETUP_COMMITMENT_HIDING_SECRET_WIDTH
            || hiding_error_polynomials.len()
                != crate::bgv::setup::SETUP_COMMITMENT_HIDING_ERROR_WIDTH
            || hiding_secret_polynomials.iter().any(|polynomial| {
                polynomial.len() != ring_degree
                    || polynomial
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
            })
            || hiding_error_polynomials.iter().any(|polynomial| {
                polynomial.len() != ring_degree
                    || polynomial
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
            })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            commitment_data_modulus_index,
            commitment_rows: commitment_rows.into_boxed_slice(),
            hiding_secret_polynomials: hiding_secret_polynomials.into_boxed_slice(),
            hiding_error_polynomials: hiding_error_polynomials.into_boxed_slice(),
        })
    }
}

#[cfg(test)]
pub(crate) struct CompactPublicKeyDevelopmentCoefficientSource {
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    common_secret_coefficients: Zeroizing<Vec<i8>>,
    public_key_error_coefficients: Zeroizing<Vec<i8>>,
    ordered_public_key_limb_coefficients: Box<[Zeroizing<Vec<u64>>]>,
    ordered_anchor_sources: Box<[CompactPublicKeyDevelopmentAnchorCoefficientSource]>,
}

#[cfg(test)]
impl CompactPublicKeyDevelopmentCoefficientSource {
    pub(crate) fn new(
        public_setup_seed: [u8; Hash512::BYTE_LENGTH],
        common_secret_coefficients: Zeroizing<Vec<i8>>,
        public_key_error_coefficients: Zeroizing<Vec<i8>>,
        ordered_public_key_limb_coefficients: Vec<Zeroizing<Vec<u64>>>,
        ordered_anchor_sources: Vec<CompactPublicKeyDevelopmentAnchorCoefficientSource>,
    ) -> Result<Self, RefusalReason> {
        let ring_degree = common_secret_coefficients.len();
        if ring_degree == 0
            || !ring_degree.is_power_of_two()
            || common_secret_coefficients
                .iter()
                .any(|coefficient| !(-1..=1).contains(coefficient))
            || public_key_error_coefficients.len() != ring_degree
            || public_key_error_coefficients
                .iter()
                .any(|coefficient| !(-2..=2).contains(coefficient))
            || ordered_public_key_limb_coefficients.is_empty()
            || ordered_public_key_limb_coefficients
                .iter()
                .any(|coefficients| coefficients.len() != ring_degree)
            || ordered_anchor_sources.is_empty()
            || ordered_anchor_sources.iter().any(|anchor| {
                anchor
                    .commitment_rows
                    .iter()
                    .any(|row| row.len() != ring_degree)
                    || anchor
                        .hiding_secret_polynomials
                        .iter()
                        .chain(anchor.hiding_error_polynomials.iter())
                        .any(|polynomial| polynomial.len() != ring_degree)
            })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            public_setup_seed,
            common_secret_coefficients,
            public_key_error_coefficients,
            ordered_public_key_limb_coefficients: ordered_public_key_limb_coefficients
                .into_boxed_slice(),
            ordered_anchor_sources: ordered_anchor_sources.into_boxed_slice(),
        })
    }

    fn ring_degree(&self) -> usize {
        self.common_secret_coefficients.len()
    }
}

#[cfg(test)]
impl SetupKeyRelationAnchorCoefficientSource for CompactPublicKeyDevelopmentCoefficientSource {
    fn source_family(&self) -> SetupKeyRelationProofFamily {
        SetupKeyRelationProofFamily::PublicKeyShare
    }

    fn public_setup_seed_bytes(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    fn common_secret_coefficient_slice(&self) -> &[i8] {
        &self.common_secret_coefficients
    }

    fn anchor_count(&self) -> usize {
        self.ordered_anchor_sources.len()
    }

    fn anchor_hiding_secret_polynomial(
        &self,
        anchor_ordinal: usize,
        polynomial_ordinal: usize,
    ) -> Result<&[i8], RefusalReason> {
        self.ordered_anchor_sources
            .get(anchor_ordinal)
            .and_then(|anchor| anchor.hiding_secret_polynomials.get(polynomial_ordinal))
            .map(|polynomial| polynomial.as_slice())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn anchor_hiding_error_polynomial(
        &self,
        anchor_ordinal: usize,
        polynomial_ordinal: usize,
    ) -> Result<&[i8], RefusalReason> {
        self.ordered_anchor_sources
            .get(anchor_ordinal)
            .and_then(|anchor| anchor.hiding_error_polynomials.get(polynomial_ordinal))
            .map(|polynomial| polynomial.as_slice())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn anchor_commitment_trace_row_half(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
        half_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let row = self
            .ordered_anchor_sources
            .get(anchor_ordinal)
            .and_then(|anchor| anchor.commitment_rows.get(row_ordinal))
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let half_size = self.ring_degree() / 2;
        let start = half_ordinal
            .checked_mul(half_size)
            .filter(|_| half_ordinal < 2)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let end = start
            .checked_add(half_size)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(Zeroizing::new(
            row.get(start..end)
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .iter()
                .copied()
                .map(i128::from)
                .collect(),
        ))
    }

    fn anchor_commitment_row(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<Vec<i128>, RefusalReason> {
        self.ordered_anchor_sources
            .get(anchor_ordinal)
            .and_then(|anchor| anchor.commitment_rows.get(row_ordinal))
            .map(|row| row.iter().copied().map(i128::from).collect())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn public_key_common_reference_limb(
        &self,
        data_modulus_index: u16,
        ring_degree: usize,
    ) -> Result<Vec<u64>, RefusalReason> {
        crate::bgv::setup::sample_collective_public_key_common_reference_limb_for_development_degree(
            &self.public_setup_seed,
            data_modulus_index,
            ring_degree,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)
    }
}

#[cfg(test)]
impl PublicKeyShareCoefficientSource for CompactPublicKeyDevelopmentCoefficientSource {
    fn public_key_error_coefficient_slice(&self) -> Result<&[i8], RefusalReason> {
        Ok(&self.public_key_error_coefficients)
    }

    fn public_key_limb_coefficient_slice(
        &self,
        limb_ordinal: usize,
    ) -> Result<&[u64], RefusalReason> {
        self.ordered_public_key_limb_coefficients
            .get(limb_ordinal)
            .map(|coefficients| coefficients.as_slice())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn public_key_limb_count(&self) -> Result<usize, RefusalReason> {
        Ok(self.ordered_public_key_limb_coefficients.len())
    }
}

#[derive(Clone, Copy)]
struct BoundMaterialTreeSource {
    tree_catalog_index: u16,
    material_ordinal: usize,
}

pub(super) fn checked_setup_provider_add(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

pub(super) fn checked_setup_provider_multiply(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

pub(super) fn setup_provider_payload_for_count<Value>(
    count: usize,
) -> Result<u64, CommonProofProverError> {
    checked_setup_provider_multiply(
        u64::try_from(count).map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<Value>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )
}

fn setup_anchor_heap_byte_length(
    opening: &super::key_relation::AnchorOpeningWitness,
    commitments: &[super::key_relation::SplitIntegerVector],
    first_matrix: &[Box<[super::key_relation::SplitIntegerVector]>],
    second_matrix: &[super::key_relation::SplitIntegerVector],
    quotient_heap_byte_length: u64,
) -> Result<u64, CommonProofProverError> {
    let first_matrix_rows = first_matrix.iter().try_fold(0_u64, |total, row| {
        checked_setup_provider_add(
            total,
            setup_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(row.len())?,
        )
    })?;
    [
        opening
            .retained_heap_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        setup_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            commitments.len(),
        )?,
        setup_provider_payload_for_count::<Box<[super::key_relation::SplitIntegerVector]>>(
            first_matrix.len(),
        )?,
        first_matrix_rows,
        setup_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            second_matrix.len(),
        )?,
        quotient_heap_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)
}

pub(super) fn exact_radix_catalog_heap_byte_length(
    catalog: &ExactRadixDigitColumnCatalog,
) -> Result<u64, CommonProofProverError> {
    let digit_payload_byte_length = catalog.values().try_fold(0_u64, |total, digits| {
        checked_setup_provider_add(
            total,
            setup_provider_payload_for_count::<u32>(digits.len())?,
        )
    })?;
    checked_setup_provider_add(
        setup_provider_payload_for_count::<(u32, Box<[u32]>)>(catalog.len())?,
        digit_payload_byte_length,
    )
}

fn same_secret_source_layout_heap_byte_length(
    source_layout: &SameSecretSourceLayout,
) -> Result<u64, CommonProofProverError> {
    let material_nested_payload_byte_length = source_layout
        .ordered_materials
        .iter()
        .flat_map(|material| material.upper_bound_comparators.iter())
        .try_fold(0_u64, |total, comparator| {
            checked_setup_provider_add(
                total,
                comparator
                    .retained_heap_byte_length()
                    .map_err(CommonProofProverError::Relation)?,
            )
        })?;
    let anchor_nested_payload_byte_length =
        source_layout
            .ordered_anchors
            .iter()
            .try_fold(0_u64, |total, anchor| {
                checked_setup_provider_add(
                    total,
                    setup_anchor_heap_byte_length(
                        &anchor.opening,
                        &anchor.commitments,
                        &anchor.first_matrix,
                        &anchor.second_matrix,
                        anchor
                            .quotients
                            .retained_heap_byte_length()
                            .map_err(CommonProofProverError::Relation)?,
                    )?,
                )
            })?;
    [
        setup_provider_payload_for_count::<
            super::same_secret_anchor::SameSecretMaterialSourceLayout,
        >(source_layout.ordered_materials.len())?,
        material_nested_payload_byte_length,
        setup_provider_payload_for_count::<super::same_secret_anchor::SameSecretAnchorSourceLayout>(
            source_layout.ordered_anchors.len(),
        )?,
        anchor_nested_payload_byte_length,
        exact_radix_catalog_heap_byte_length(&source_layout.exact_radix_digits_by_column)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)
}

fn public_key_share_source_layout_heap_byte_length(
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<u64, CommonProofProverError> {
    let anchor_nested_payload_byte_length =
        source_layout
            .ordered_anchors
            .iter()
            .try_fold(0_u64, |total, anchor| {
                checked_setup_provider_add(
                    total,
                    setup_anchor_heap_byte_length(
                        &anchor.opening,
                        &anchor.commitments,
                        &anchor.first_matrix,
                        &anchor.second_matrix,
                        anchor
                            .quotients
                            .retained_heap_byte_length()
                            .map_err(CommonProofProverError::Relation)?,
                    )?,
                )
            })?;
    [
        setup_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.public_key_share_limbs.len(),
        )?,
        setup_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.public_key_common_reference_limbs.len(),
        )?,
        setup_provider_payload_for_count::<super::public_key_share::PublicKeyShareLimbSourceLayout>(
            source_layout.ordered_limbs.len(),
        )?,
        setup_provider_payload_for_count::<
            super::public_key_share::PublicKeyShareAnchorSourceLayout,
        >(source_layout.ordered_anchors.len())?,
        anchor_nested_payload_byte_length,
        exact_radix_catalog_heap_byte_length(&source_layout.exact_radix_digits_by_column)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)
}

fn insert_setup_column_dependency(
    dependencies: &mut BTreeMap<u32, BTreeSet<u32>>,
    target_column_ordinal: u32,
    source_column_ordinal: u32,
) {
    if target_column_ordinal != source_column_ordinal {
        dependencies
            .entry(target_column_ordinal)
            .or_default()
            .insert(source_column_ordinal);
    }
}

fn same_secret_comparator_dependencies(source_layout: &SameSecretSourceLayout) -> Vec<(u32, u32)> {
    let mut dependencies = Vec::new();
    for material in &source_layout.ordered_materials {
        for half_ordinal in 0..2 {
            let value_columns = material.material[half_ordinal].ordered_digit_column_ordinals();
            let comparator = &material.upper_bound_comparators[half_ordinal];
            for dependent_column in comparator
                .difference_digits
                .iter()
                .flat_map(|difference| {
                    std::iter::once(difference.target_column_ordinal)
                        .chain(difference.trit_column_ordinals.iter().copied())
                })
                .chain(comparator.borrow_column_ordinals.iter().copied())
            {
                dependencies.extend(
                    value_columns
                        .iter()
                        .copied()
                        .map(|source_column| (dependent_column, source_column)),
                );
            }
        }
    }
    dependencies
}

fn setup_key_relation_column_dependencies(
    relation_plan_variant: &RelationPlanVariant,
    exact_radix_digits_by_column: &ExactRadixDigitColumnCatalog,
) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut dependencies = BTreeMap::<u32, BTreeSet<u32>>::new();
    for (source_column_ordinal, digit_column_ordinals) in exact_radix_digits_by_column {
        for digit_column_ordinal in digit_column_ordinals.iter().copied() {
            insert_setup_column_dependency(
                &mut dependencies,
                digit_column_ordinal,
                *source_column_ordinal,
            );
        }
    }
    for semantic_cell in &relation_plan_variant.ordered_semantic_cells {
        let dependent_columns: &[u32] = match &semantic_cell.bound_certificate {
            RelationBoundCertificate::UnsignedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            }
            | RelationBoundCertificate::ShiftedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            } => ordered_digit_column_ordinals,
            RelationBoundCertificate::CanonicalModulusRecomposition {
                ordered_digit_column_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
                ..
            } => {
                for dependent_column in ordered_difference_digit_column_ordinals
                    .iter()
                    .chain(ordered_borrow_column_ordinals)
                    .copied()
                {
                    insert_setup_column_dependency(
                        &mut dependencies,
                        dependent_column,
                        semantic_cell.column_ordinal,
                    );
                }
                ordered_digit_column_ordinals
            }
            RelationBoundCertificate::Trinary { .. }
            | RelationBoundCertificate::Binary { .. }
            | RelationBoundCertificate::FiniteIntegerSet { .. } => &[],
        };
        for dependent_column in dependent_columns.iter().copied() {
            insert_setup_column_dependency(
                &mut dependencies,
                dependent_column,
                semantic_cell.column_ordinal,
            );
        }
    }
    for component in relation_plan_variant
        .ordered_integer_lift_batches()
        .iter()
        .flat_map(|batch| batch.ordered_components.iter())
    {
        let carry_columns = component
            .ordered_linear_terms
            .iter()
            .filter(|term| {
                term.negative
                    && term.column_offset == 0
                    && term.coefficient
                        == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
            })
            .map(|term| term.column_ordinal)
            .collect::<BTreeSet<_>>();
        for carry_column in carry_columns {
            for term in &component.ordered_linear_terms {
                if term.column_ordinal != carry_column {
                    insert_setup_column_dependency(
                        &mut dependencies,
                        carry_column,
                        term.column_ordinal,
                    );
                }
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                for source_column in [
                    product.multiplicand_low_column_ordinal,
                    product.multiplicand_high_column_ordinal,
                    product.multiplier_low_column_ordinal,
                    product.multiplier_high_column_ordinal,
                ] {
                    insert_setup_column_dependency(&mut dependencies, carry_column, source_column);
                }
            }
        }
    }
    dependencies
}

fn setup_key_relation_recursive_column_closures(
    relation_plan_variant: &RelationPlanVariant,
    exact_radix_digits_by_column: &ExactRadixDigitColumnCatalog,
    additional_dependencies: &[(u32, u32)],
    requested_column_ordinals: &[u32],
) -> Result<Vec<BTreeSet<u32>>, CommonProofProverError> {
    let mut dependencies =
        setup_key_relation_column_dependencies(relation_plan_variant, exact_radix_digits_by_column);
    for (target_column_ordinal, source_column_ordinal) in additional_dependencies {
        insert_setup_column_dependency(
            &mut dependencies,
            *target_column_ordinal,
            *source_column_ordinal,
        );
    }
    requested_column_ordinals
        .iter()
        .copied()
        .map(|requested_column| {
            let mut pending = vec![requested_column];
            let mut visited = BTreeSet::new();
            while let Some(column) = pending.pop() {
                if visited.insert(column) {
                    pending.extend(
                        dependencies
                            .get(&column)
                            .into_iter()
                            .flat_map(|sources| sources.iter().copied()),
                    );
                }
            }
            if visited.is_empty() {
                return Err(CommonProofProverError::InvalidColumn);
            }
            Ok(visited)
        })
        .collect()
}

fn full_ring_carry_columns(relation_plan_variant: &RelationPlanVariant) -> BTreeSet<u32> {
    relation_plan_variant
        .ordered_integer_lift_batches()
        .iter()
        .flat_map(|batch| batch.ordered_components.iter())
        .filter(|component| !component.ordered_full_ring_negacyclic_products.is_empty())
        .flat_map(|component| component.ordered_linear_terms.iter())
        .filter(|term| {
            term.negative
                && term.column_offset == 0
                && term.coefficient
                    == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
        })
        .map(|term| term.column_ordinal)
        .collect()
}

pub(super) fn setup_key_relation_derivation_transient_byte_length_with_dependencies(
    relation_plan_variant: &RelationPlanVariant,
    exact_radix_digits_by_column: &ExactRadixDigitColumnCatalog,
    public_key_quotient_columns: &BTreeSet<u32>,
    anchor_quotient_columns: &BTreeSet<u32>,
    ring_degree: u64,
    additional_dependencies: &[(u32, u32)],
) -> Result<u64, CommonProofProverError> {
    let requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_plan_variant)?;
    setup_key_relation_derivation_transient_byte_length_for_requested_columns(
        relation_plan_variant,
        exact_radix_digits_by_column,
        public_key_quotient_columns,
        anchor_quotient_columns,
        ring_degree,
        additional_dependencies,
        &requested_column_ordinals,
    )
}

#[allow(clippy::too_many_arguments)]
fn setup_key_relation_derivation_transient_byte_length_for_requested_columns(
    relation_plan_variant: &RelationPlanVariant,
    exact_radix_digits_by_column: &ExactRadixDigitColumnCatalog,
    public_key_quotient_columns: &BTreeSet<u32>,
    anchor_quotient_columns: &BTreeSet<u32>,
    ring_degree: u64,
    additional_dependencies: &[(u32, u32)],
    requested_column_ordinals: &[u32],
) -> Result<u64, CommonProofProverError> {
    let trace_domain_size = relation_plan_variant.trace_domain_size();
    let complete_requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_plan_variant)?;
    if trace_domain_size.checked_mul(2) != Some(ring_degree) {
        return Err(CommonProofProverError::InvalidColumn);
    }
    if requested_column_ordinals.is_empty()
        || requested_column_ordinals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || requested_column_ordinals.iter().any(|column_ordinal| {
            complete_requested_column_ordinals
                .binary_search(column_ordinal)
                .is_err()
        })
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let i128_byte_length =
        u64::try_from(size_of::<i128>()).map_err(|_| CommonProofProverError::CountOverflow)?;
    let base_field_byte_length = u64::try_from(size_of::<ProofBaseFieldElement>())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_row_byte_length =
        checked_setup_provider_multiply(trace_domain_size, i128_byte_length)?;
    // Direct full-ring decoding retains at most one ring-sized i128 input and
    // one returned half-row alongside the provider's current output row.
    let direct_derivation_workspace_byte_length =
        checked_setup_provider_multiply(trace_row_byte_length, 3)?;
    // The full-ring carry path retains the accumulated half-row, four returned
    // halves, two operands, the product result and the two in-place 2N field
    // transforms. These are the exact simultaneously live payload vectors.
    let full_ring_derivation_workspace_byte_length = [
        checked_setup_provider_multiply(
            trace_domain_size,
            checked_setup_provider_multiply(11, i128_byte_length)?,
        )?,
        checked_setup_provider_multiply(
            trace_domain_size,
            checked_setup_provider_multiply(8, base_field_byte_length)?,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)?;
    // Public-key quotient derivation retains two ring inputs, the outer radix
    // result and digit, two 2N field transforms, and the inner ring result.
    let public_key_quotient_workspace_byte_length = checked_setup_provider_multiply(
        ring_degree,
        u64::try_from(size_of::<i128>() * 5 + size_of::<ProofBaseFieldElement>() * 4)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let anchor_product_column_count = u64::try_from(
        SETUP_COMMITMENT_MODULE_RANK
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?,
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    // At the final anchor product, the commitment, prior products, centered
    // matrix, hiding secret, radix result and digit, inner result, and two 2N
    // field transforms coexist. The product-vector catalog and 128-byte seed
    // string are separately owned allocations at that same point.
    let anchor_quotient_workspace_byte_length = [
        checked_setup_provider_multiply(
            anchor_product_column_count
                .checked_add(7)
                .ok_or(CommonProofProverError::CountOverflow)?,
            checked_setup_provider_multiply(ring_degree, i128_byte_length)?,
        )?,
        checked_setup_provider_multiply(
            anchor_product_column_count,
            u64::try_from(size_of::<Zeroizing<Vec<i128>>>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?,
        u64::try_from(Hash512::BYTE_LENGTH * 2)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)?;
    let carry_columns = full_ring_carry_columns(relation_plan_variant);
    let recursive_column_closures = setup_key_relation_recursive_column_closures(
        relation_plan_variant,
        exact_radix_digits_by_column,
        additional_dependencies,
        requested_column_ordinals,
    )?;
    let mut maximum_cache_and_derivation_byte_length = 0_u64;
    for closure in &recursive_column_closures {
        let mut operation_workspace_byte_length = direct_derivation_workspace_byte_length;
        if closure.iter().any(|column| carry_columns.contains(column)) {
            operation_workspace_byte_length =
                operation_workspace_byte_length.max(full_ring_derivation_workspace_byte_length);
        }
        if closure
            .iter()
            .any(|column| public_key_quotient_columns.contains(column))
        {
            operation_workspace_byte_length =
                operation_workspace_byte_length.max(public_key_quotient_workspace_byte_length);
        }
        if closure
            .iter()
            .any(|column| anchor_quotient_columns.contains(column))
        {
            operation_workspace_byte_length =
                operation_workspace_byte_length.max(anchor_quotient_workspace_byte_length);
        }
        let closure_count =
            u64::try_from(closure.len()).map_err(|_| CommonProofProverError::CountOverflow)?;
        let cache_before_operation_byte_length = checked_setup_provider_multiply(
            closure_count.saturating_sub(1),
            trace_row_byte_length,
        )?;
        let operation_peak_byte_length = checked_setup_provider_add(
            cache_before_operation_byte_length,
            operation_workspace_byte_length,
        )?;
        let completed_derivation_peak_byte_length = checked_setup_provider_multiply(
            closure_count
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?,
            trace_row_byte_length,
        )?;
        maximum_cache_and_derivation_byte_length = maximum_cache_and_derivation_byte_length
            .max(operation_peak_byte_length)
            .max(completed_derivation_peak_byte_length);
    }
    if maximum_cache_and_derivation_byte_length == 0 {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let column_count = relation_plan_variant.ordered_columns().len();
    [
        setup_provider_payload_for_count::<Option<Zeroizing<Box<[i128]>>>>(column_count)?,
        setup_provider_payload_for_count::<bool>(column_count)?,
        maximum_cache_and_derivation_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)
}

struct SetupKeyRelationSourceProviderMemoryAccountingInput<'input> {
    relation_plan_variant: &'input RelationPlanVariant,
    relation_context: &'input RelationPlanCheckContext,
    requested_column_ordinals: &'input [u32],
    ring_degree: u64,
    canonical_application_statement_byte_length: usize,
    source_layout_heap_byte_length: u64,
    exact_radix_digits_by_column: &'input ExactRadixDigitColumnCatalog,
    public_key_quotient_columns: BTreeSet<u32>,
    anchor_quotient_columns: BTreeSet<u32>,
    additional_dependencies: Vec<(u32, u32)>,
}

fn finish_setup_key_relation_source_provider_memory_accounting(
    input: SetupKeyRelationSourceProviderMemoryAccountingInput<'_>,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let SetupKeyRelationSourceProviderMemoryAccountingInput {
        relation_plan_variant,
        relation_context,
        requested_column_ordinals,
        ring_degree,
        canonical_application_statement_byte_length,
        source_layout_heap_byte_length,
        exact_radix_digits_by_column,
        public_key_quotient_columns,
        anchor_quotient_columns,
        additional_dependencies,
    } = input;
    let complete_requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_plan_variant)?;
    let requested_column_count = requested_column_ordinals.len();
    if canonical_application_statement_byte_length == 0
        || requested_column_count == 0
        || requested_column_count > relation_plan_variant.ordered_columns().len()
        || requested_column_ordinals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || requested_column_ordinals.iter().any(|column_ordinal| {
            complete_requested_column_ordinals
                .binary_search(column_ordinal)
                .is_err()
        })
        || relation_plan_variant.trace_domain_size().checked_mul(2) != Some(ring_degree)
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let bound_material_tree_count = relation_plan_variant
        .ordered_trees()
        .iter()
        .filter(|tree| {
            matches!(
                tree,
                RelationTreeDescriptor::BoundPublic {
                    construction_kind: BoundTreeConstructionKind::CommittedMaterial,
                    ..
                }
            )
        })
        .count();
    let adapter_retained_byte_length = [
        u64::try_from(size_of::<SetupKeyRelationSourcePolynomialAdapter>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(canonical_application_statement_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        relation_plan_variant
            .resident_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        relation_context
            .resident_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        source_layout_heap_byte_length,
        setup_provider_payload_for_count::<u32>(requested_column_count)?,
        setup_provider_payload_for_count::<BoundMaterialTreeSource>(bound_material_tree_count)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)?;
    let cached_quotient_byte_length = checked_setup_provider_multiply(
        ring_degree,
        u64::try_from(size_of::<i128>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let additional_loading_transient_byte_length =
        setup_key_relation_derivation_transient_byte_length_for_requested_columns(
            relation_plan_variant,
            exact_radix_digits_by_column,
            &public_key_quotient_columns,
            &anchor_quotient_columns,
            ring_degree,
            &additional_dependencies,
            requested_column_ordinals,
        )?;
    let maximum_returned_source_polynomial_byte_length = checked_setup_provider_multiply(
        relation_plan_variant.trace_domain_size(),
        u64::try_from(size_of::<ProofBaseFieldElement>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    Ok(CommonProofSourceProviderMemoryAccounting::new(
        checked_setup_provider_add(adapter_retained_byte_length, cached_quotient_byte_length)?,
        adapter_retained_byte_length,
        additional_loading_transient_byte_length,
        maximum_returned_source_polynomial_byte_length,
    ))
}

pub(crate) fn same_secret_source_provider_memory_accounting(
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: u64,
    source_layout: &SameSecretSourceLayout,
    canonical_application_statement_byte_length: usize,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_plan_variant)?;
    let anchor_quotient_columns = source_layout
        .ordered_anchors
        .iter()
        .flat_map(|anchor| anchor.quotients.rows().iter().flatten().copied())
        .collect();
    finish_setup_key_relation_source_provider_memory_accounting(
        SetupKeyRelationSourceProviderMemoryAccountingInput {
            relation_plan_variant,
            relation_context,
            requested_column_ordinals: &requested_column_ordinals,
            ring_degree,
            canonical_application_statement_byte_length,
            source_layout_heap_byte_length: same_secret_source_layout_heap_byte_length(
                source_layout,
            )?,
            exact_radix_digits_by_column: &source_layout.exact_radix_digits_by_column,
            public_key_quotient_columns: BTreeSet::new(),
            anchor_quotient_columns,
            additional_dependencies: same_secret_comparator_dependencies(source_layout),
        },
    )
}

pub(crate) fn public_key_share_source_provider_memory_accounting(
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: u64,
    source_layout: &PublicKeyShareSourceLayout,
    canonical_application_statement_byte_length: usize,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_plan_variant)?;
    public_key_share_source_provider_memory_accounting_for_requested_columns(
        relation_plan_variant,
        relation_context,
        ring_degree,
        source_layout,
        canonical_application_statement_byte_length,
        &requested_column_ordinals,
    )
}

fn public_key_share_source_provider_memory_accounting_for_requested_columns(
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: u64,
    source_layout: &PublicKeyShareSourceLayout,
    canonical_application_statement_byte_length: usize,
    requested_column_ordinals: &[u32],
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let public_key_quotient_columns = source_layout
        .ordered_limbs
        .iter()
        .flat_map(|limb| limb.quotient_columns)
        .collect();
    let anchor_quotient_columns = source_layout
        .ordered_anchors
        .iter()
        .flat_map(|anchor| anchor.quotients.rows().iter().flatten().copied())
        .collect();
    finish_setup_key_relation_source_provider_memory_accounting(
        SetupKeyRelationSourceProviderMemoryAccountingInput {
            relation_plan_variant,
            relation_context,
            requested_column_ordinals,
            ring_degree,
            canonical_application_statement_byte_length,
            source_layout_heap_byte_length: public_key_share_source_layout_heap_byte_length(
                source_layout,
            )?,
            exact_radix_digits_by_column: &source_layout.exact_radix_digits_by_column,
            public_key_quotient_columns,
            anchor_quotient_columns,
            additional_dependencies: Vec::new(),
        },
    )
}

fn add_setup_authority_memory_accounting(
    provider: CommonProofSourceProviderMemoryAccounting,
    authority_identifier: u32,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let authority = setup_generation_retained_memory_accounting(
        &SetupGenerationAuthorityHandle::from_identifier(authority_identifier),
    )
    .map_err(|_| CommonProofProverError::InvalidInput)?;
    add_setup_authority_payload_memory_accounting(provider, authority.active_payload_byte_length())
}

fn add_setup_authority_payload_memory_accounting(
    provider: CommonProofSourceProviderMemoryAccounting,
    authority_byte_length: u64,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    Ok(CommonProofSourceProviderMemoryAccounting::new(
        checked_setup_provider_add(
            provider.loading_persistent_resident_byte_length(),
            authority_byte_length,
        )?,
        checked_setup_provider_add(
            provider.post_source_polynomial_finish_persistent_resident_byte_length(),
            authority_byte_length,
        )?,
        provider.additional_loading_transient_byte_length(),
        provider.maximum_returned_source_polynomial_byte_length(),
    ))
}

/// Ordered generation-only source provider for the selected same-secret and
/// public-key-share relations. It retains reset-stable binding facts and
/// relation layout only; every secret or authenticated material read reenters
/// the browser-owned setup authority.
pub(crate) struct SetupKeyRelationSourcePolynomialAdapter {
    authority_access: SetupKeyRelationAuthorityAccess,
    family: SetupKeyRelationProofFamily,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: Vec<u8>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    setup_attempt_identifier: [u8; 32],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    request_context: CommonProofSourcePolynomialRequestContext,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: SetupKeyRelationSourceLayout,
    request_profile: SetupKeyRelationSourceRequestProfile,
    requested_column_ordinals: Box<[u32]>,
    bound_material_tree_sources: Box<[BoundMaterialTreeSource]>,
    next_source_index: usize,
    next_leaf_salt_source_ordinal: usize,
    next_leaf_salt_index: usize,
    cached_quotient: Option<CachedQuotient>,
    source_polynomials_finished: bool,
    leaf_salts_finished: bool,
}

/// Compact public-key source provider backed by the immutable selected source
/// catalog. Unlike the general relation adapter, this owner does not retain or
/// reconstruct the multi-megabyte production relation plan at runtime.
pub(crate) struct CompactPublicKeySourcePolynomialAdapter {
    authority_access: SetupKeyRelationAuthorityAccess,
    expected_compact_public_key_authority_owner_count: Option<usize>,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: Vec<u8>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    setup_attempt_identifier: [u8; 32],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    request_context: CommonProofSourcePolynomialRequestContext,
    relation_context: RelationPlanCheckContext,
    ring_degree: usize,
    ordered_sources: Box<[CompactPublicKeyAssignmentSource]>,
    ordered_source_descriptors: Box<[super::RelationColumnDescriptor]>,
    next_source_index: usize,
    cached_quotient: Option<CachedQuotient>,
    source_polynomials_finished: bool,
}

impl CompactPublicKeySourcePolynomialAdapter {
    pub(crate) fn new(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation: &CompactPublicKeyRelationCatalog,
        relation_context: RelationPlanCheckContext,
        source_catalog: CompactPublicKeyAssignmentSourceCatalog,
    ) -> Result<(Self, CompactAuthenticatedAssignmentCatalog), CommonProofProverError> {
        source_catalog.validate_generated(relation)?;
        let ring_degree = usize::try_from(relation.ring_degree())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_domain_size =
            usize::try_from(source_catalog.assignment_catalog.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let expected_public_key_limb_count = source_catalog
            .ordered_sources
            .iter()
            .filter_map(|entry| match entry.derivation {
                CompactPublicKeySourceDerivation::PublicKeyShare { limb_ordinal, .. }
                | CompactPublicKeySourceDerivation::PublicKeyQuotient { limb_ordinal, .. } => {
                    Some(usize::from(limb_ordinal))
                }
                _ => None,
            })
            .max()
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let expected_anchor_count = source_catalog
            .ordered_sources
            .iter()
            .filter_map(|entry| match entry.derivation {
                CompactPublicKeySourceDerivation::AnchorHidingSecret { anchor_ordinal, .. }
                | CompactPublicKeySourceDerivation::AnchorHidingError { anchor_ordinal, .. }
                | CompactPublicKeySourceDerivation::AnchorCommitment { anchor_ordinal, .. }
                | CompactPublicKeySourceDerivation::AnchorQuotient { anchor_ordinal, .. } => {
                    Some(usize::from(anchor_ordinal))
                }
                _ => None,
            })
            .max()
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if source.family() != SetupKeyRelationProofFamily::PublicKeyShare
            || source.family().statement_schema_identifier()
                != ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || source.ring_degree() != ring_degree
            || trace_domain_size.checked_mul(2) != Some(ring_degree)
            || source
                .public_key_limb_count()
                .map_err(|_| CommonProofProverError::InvalidColumn)?
                != expected_public_key_limb_count
            || source.anchor_count() != expected_anchor_count
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        for entry in source_catalog.ordered_sources.iter() {
            let data_modulus_index = match entry.derivation {
                CompactPublicKeySourceDerivation::PublicKeyCommonReference {
                    data_modulus_index,
                    ..
                }
                | CompactPublicKeySourceDerivation::PublicKeyQuotient {
                    data_modulus_index, ..
                }
                | CompactPublicKeySourceDerivation::SetupCommitmentMatrix {
                    data_modulus_index,
                    ..
                }
                | CompactPublicKeySourceDerivation::AnchorQuotient {
                    data_modulus_index, ..
                } => Some(data_modulus_index),
                _ => None,
            };
            if data_modulus_index.is_some_and(|index| {
                relation_context
                    .resolved_modulus(SuiteModulusReference::data(index))
                    .is_err()
            }) {
                return Err(CommonProofProverError::InvalidColumn);
            }
        }
        let ordered_source_descriptors = (0..source_catalog.ordered_sources.len())
            .map(|source_index| {
                source_catalog
                    .assignment_catalog
                    .source_descriptor(source_index)
                    .cloned()
                    .ok_or(CommonProofProverError::InvalidColumn)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            source.protocol_version(),
            source.suite_identifier(),
            source.family().statement_schema_identifier(),
            source
                .prepared_attempt()
                .application_statement_hash()
                .into_bytes(),
            source_catalog.complete_relation_plan_hash,
            source_catalog.assignment_catalog.relation_plan_hash(),
            None,
            None,
        );
        let authority_access = source
            .compact_public_key_development_authority()
            .map(SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment)
            .unwrap_or_else(|| {
                SetupKeyRelationAuthorityAccess::RetainedRegistry(source.authority_identifier())
            });
        let expected_compact_public_key_authority_owner_count = matches!(
            &authority_access,
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(_)
        )
        .then_some(1);
        let assignment_catalog = source_catalog.assignment_catalog;
        let adapter = Self {
            authority_access,
            expected_compact_public_key_authority_owner_count,
            prepared_attempt: *source.prepared_attempt(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes()
                .to_vec(),
            setup_proof_context_hash: source.setup_proof_context_hash(),
            roster_hash: source.roster_hash(),
            participant_identity: source.participant_identity(),
            roster_position: source.roster_position(),
            setup_attempt_identifier: source.setup_attempt_identifier(),
            source_setup_intent_object_hash: source.source_setup_intent_object_hash(),
            action_randomness_authorization_hash: source.action_randomness_authorization_hash(),
            request_context,
            relation_context,
            ring_degree,
            ordered_sources: source_catalog.ordered_sources.into_boxed_slice(),
            ordered_source_descriptors,
            next_source_index: 0,
            cached_quotient: None,
            source_polynomials_finished: false,
        };
        Ok((adapter, assignment_catalog))
    }

    pub(crate) const fn request_context(&self) -> CommonProofSourcePolynomialRequestContext {
        self.request_context
    }

    pub(crate) fn retain_deferred_authority(
        &mut self,
    ) -> Result<Rc<SetupGenerationCompactPublicKeyDevelopmentAuthority>, CommonProofProverError>
    {
        let Some(expected_owner_count) = self
            .expected_compact_public_key_authority_owner_count
            .as_mut()
        else {
            return Err(CommonProofProverError::InvalidInput);
        };
        let SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(authority) =
            &self.authority_access
        else {
            return Err(CommonProofProverError::InvalidInput);
        };
        if *expected_owner_count != 1 || Rc::strong_count(authority) != *expected_owner_count {
            return Err(CommonProofProverError::InvalidInput);
        }
        let deferred_authority = Rc::clone(authority);
        *expected_owner_count = 2;
        Ok(deferred_authority)
    }

    pub(crate) fn finish_compact_sources(self) -> Result<(), CommonProofProverError> {
        let authority_access_is_valid = match &self.authority_access {
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(authority) => self
                .expected_compact_public_key_authority_owner_count
                .is_some_and(|expected_owner_count| {
                    Rc::strong_count(authority) == expected_owner_count
                }),
            SetupKeyRelationAuthorityAccess::RetainedRegistry(_) => self
                .expected_compact_public_key_authority_owner_count
                .is_none(),
        };
        if self.next_source_index != self.ordered_sources.len()
            || self.ordered_sources.len() != self.ordered_source_descriptors.len()
            || !self.source_polynomials_finished
            || self.cached_quotient.is_some()
            || !authority_access_is_valid
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(())
    }

    fn replay_identity(
        &self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomialReplayIdentity, CommonProofProverError> {
        CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(hash_framed_parts_512(
            PUBLIC_KEY_SHARE_SOURCE_REPLAY_IDENTITY_DOMAIN,
            &[
                &self.request_context.stable_generation_binding_hash(),
                &column_ordinal.to_le_bytes(),
                &self.setup_attempt_identifier,
                &self.source_setup_intent_object_hash,
                &self.action_randomness_authorization_hash,
                &self.setup_proof_context_hash,
                &self.roster_hash,
                &self.participant_identity,
                &self.roster_position.to_le_bytes(),
            ],
        ))
    }

    fn derive_source_polynomial(
        &mut self,
        source_index: usize,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let derivation = self
            .ordered_sources
            .get(source_index)
            .map(|entry| entry.derivation.clone())
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
            SetupKeyRelationProofFamily::PublicKeyShare,
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.roster_hash,
            self.participant_identity,
            self.roster_position,
        );
        let relation_context = &self.relation_context;
        let ring_degree = self.ring_degree;
        let cached_quotient = &mut self.cached_quotient;
        let derive_polynomial = |source: SetupGenerationKeyRelationSource<'_, '_>| {
            derive_compact_public_key_source_polynomial(
                &source,
                relation_context,
                ring_degree,
                &derivation,
                cached_quotient,
            )
        };
        match &self.authority_access {
            SetupKeyRelationAuthorityAccess::RetainedRegistry(authority_identifier) => {
                with_setup_generation_key_relation::<_, RefusalReason>(
                    &SetupGenerationAuthorityHandle::from_identifier(*authority_identifier),
                    &application,
                    derive_polynomial,
                )
            }
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(authority) => {
                with_setup_generation_compact_public_key_development_relation_reentry::<
                    _,
                    RefusalReason,
                >(authority, &application, derive_polynomial)
            }
        }
        .map_err(|_| CommonProofProverError::InvalidColumn)
    }

    fn base_memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        let ring_degree =
            u64::try_from(self.ring_degree).map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_domain_size = ring_degree / 2;
        let adapter_retained_byte_length = [
            u64::try_from(size_of::<Self>()).map_err(|_| CommonProofProverError::CountOverflow)?,
            u64::try_from(self.canonical_application_statement_bytes.capacity())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            self.relation_context
                .resident_owned_payload_byte_length()
                .map_err(CommonProofProverError::Relation)?,
            setup_provider_payload_for_count::<CompactPublicKeyAssignmentSource>(
                self.ordered_sources.len(),
            )?,
            setup_provider_payload_for_count::<super::RelationColumnDescriptor>(
                self.ordered_source_descriptors.len(),
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_setup_provider_add)?;
        let cached_quotient_byte_length = checked_setup_provider_multiply(
            ring_degree,
            u64::try_from(size_of::<i128>()).map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
        let per_ring_coefficient_transient_byte_length = u64::try_from(
            4 * size_of::<u64>() + 12 * size_of::<i128>() + 6 * size_of::<ProofBaseFieldElement>(),
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let additional_loading_transient_byte_length = checked_setup_provider_multiply(
            ring_degree,
            per_ring_coefficient_transient_byte_length,
        )?;
        let maximum_returned_source_polynomial_byte_length = checked_setup_provider_multiply(
            trace_domain_size,
            u64::try_from(size_of::<ProofBaseFieldElement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
        Ok(CommonProofSourceProviderMemoryAccounting::new(
            checked_setup_provider_add(adapter_retained_byte_length, cached_quotient_byte_length)?,
            adapter_retained_byte_length,
            additional_loading_transient_byte_length,
            maximum_returned_source_polynomial_byte_length,
        ))
    }
}

impl CommonProofSourcePolynomialProvider for CompactPublicKeySourcePolynomialAdapter {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        let base = self.base_memory_accounting()?;
        match &self.authority_access {
            SetupKeyRelationAuthorityAccess::RetainedRegistry(authority_identifier) => {
                add_setup_authority_memory_accounting(base, *authority_identifier)
            }
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(authority) => {
                add_setup_authority_payload_memory_accounting(
                    base,
                    setup_generation_compact_public_key_development_retained_payload_byte_length(
                        authority,
                    )
                    .map_err(|_| CommonProofProverError::InvalidInput)?,
                )
            }
        }
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let expected_source = self
            .ordered_sources
            .get(self.next_source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.source_polynomials_finished
            || request.request_context() != self.request_context
            || request.column_ordinal() != expected_source.column_ordinal
            || self.ordered_source_descriptors.get(self.next_source_index)
                != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_index = self.next_source_index;
        let column_ordinal = request.column_ordinal();
        let replay_identity = self.replay_identity(column_ordinal)?;
        let polynomial = self.derive_source_polynomial(source_index)?;
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
        ))
    }

    fn poll_replayed_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let source_index = self
            .ordered_sources
            .binary_search_by_key(&request.column_ordinal(), |entry| entry.column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        if !self.source_polynomials_finished
            || request.request_context() != self.request_context
            || self.ordered_source_descriptors.get(source_index) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_quotient = None;
        let polynomial = self.derive_source_polynomial(source_index)?;
        self.cached_quotient = None;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(
                polynomial,
                self.replay_identity(request.column_ordinal())?,
            ),
        ))
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished || self.next_source_index != self.ordered_sources.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_quotient = None;
        self.source_polynomials_finished = true;
        Ok(())
    }
}

#[cfg(test)]
fn derive_compact_public_key_relation_plan_binding(
    relation_plan: &CompiledRelationPlan,
    relation_plan_variant: &RelationPlanVariant,
    expected_statement_schema_identifier: u16,
) -> Result<([u8; Hash512::BYTE_LENGTH], [u8; Hash512::BYTE_LENGTH]), CommonProofProverError> {
    if relation_plan.application_statement_schema_identifier()
        != expected_statement_schema_identifier
        || relation_plan.select_variant(None, None)? != relation_plan_variant
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    Ok((
        relation_plan.canonical_hash()?,
        relation_plan_variant.canonical_hash()?,
    ))
}

impl SetupKeyRelationSourcePolynomialAdapter {
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) const fn exact_same_secret_evidence_request_context(
        &self,
    ) -> CommonProofSourcePolynomialRequestContext {
        self.request_context
    }

    /// Reconstructs one plan-owned verifier sequence through the accepted
    /// setup authority. The caller cannot supply polynomial bytes, and every
    /// prover-owned or statement-tree column is refused.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn exact_same_secret_evidence_verifier_sequence_polynomial(
        &mut self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let descriptor = self
            .relation_plan_variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if !matches!(
            descriptor.origin(),
            RelationColumnOrigin::VerifierSequence { .. }
        ) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.derive_source_polynomial(column_ordinal)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_same_secret(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: SameSecretSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        let requested_column_ordinals =
            requested_pre_challenge_source_column_ordinals(&relation_plan_variant)?
                .into_boxed_slice();
        Self::new(
            source,
            relation_plan,
            relation_plan_variant,
            relation_context,
            ring_degree,
            SetupKeyRelationSourceLayout::SameSecret(source_layout),
            requested_column_ordinals,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_public_key_share(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: PublicKeyShareSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        let requested_column_ordinals =
            requested_pre_challenge_source_column_ordinals(&relation_plan_variant)?
                .into_boxed_slice();
        Self::new_public_key_share_for_requested_columns(
            source,
            relation_plan,
            relation_plan_variant,
            relation_context,
            ring_degree,
            source_layout,
            requested_column_ordinals,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_public_key_share_for_requested_columns(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: PublicKeyShareSourceLayout,
        requested_column_ordinals: Box<[u32]>,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            source,
            relation_plan,
            relation_plan_variant,
            relation_context,
            ring_degree,
            SetupKeyRelationSourceLayout::PublicKeyShare(source_layout),
            requested_column_ordinals,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: SetupKeyRelationSourceLayout,
        requested_column_ordinals: Box<[u32]>,
    ) -> Result<Self, CommonProofProverError> {
        Self::new_with_relation_hashes(
            source,
            relation_plan.relation_plan_hash(),
            relation_plan.relation_plan_variant_hash(),
            relation_plan_variant,
            relation_context,
            ring_degree,
            source_layout,
            requested_column_ordinals,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_relation_hashes(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: SetupKeyRelationSourceLayout,
        requested_column_ordinals: Box<[u32]>,
    ) -> Result<Self, CommonProofProverError> {
        if relation_plan_variant.schedule_position().is_some()
            || relation_plan_variant.top_count().is_some()
            || ring_degree == 0
            || ring_degree != source.ring_degree()
            || source.family()
                != match &source_layout {
                    SetupKeyRelationSourceLayout::SameSecret(_) => {
                        SetupKeyRelationProofFamily::SameSecret
                    }
                    SetupKeyRelationSourceLayout::PublicKeyShare(_) => {
                        SetupKeyRelationProofFamily::PublicKeyShare
                    }
                }
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            source.protocol_version(),
            source.suite_identifier(),
            source.family().statement_schema_identifier(),
            source
                .prepared_attempt()
                .application_statement_hash()
                .into_bytes(),
            relation_plan_hash,
            relation_plan_variant_hash,
            None,
            None,
        );
        let request_profile = classify_setup_key_relation_source_request_profile(
            match &source_layout {
                SetupKeyRelationSourceLayout::SameSecret(_) => None,
                SetupKeyRelationSourceLayout::PublicKeyShare(source_layout) => Some(source_layout),
            },
            &relation_plan_variant,
            &requested_column_ordinals,
        )?;
        let bound_material_tree_sources = match &source_layout {
            SetupKeyRelationSourceLayout::SameSecret(layout) => relation_plan_variant
                .ordered_trees()
                .iter()
                .enumerate()
                .filter_map(|(tree_catalog_index, tree)| {
                    let RelationTreeDescriptor::BoundPublic {
                        construction_kind: BoundTreeConstructionKind::CommittedMaterial,
                        ordered_column_ordinals,
                        ..
                    } = tree
                    else {
                        return None;
                    };
                    let material_ordinal = layout.ordered_materials.iter().position(|material| {
                        material_columns_match(material, ordered_column_ordinals)
                    });
                    Some((tree_catalog_index, material_ordinal))
                })
                .map(|(tree_catalog_index, material_ordinal)| {
                    Ok::<BoundMaterialTreeSource, CommonProofProverError>(BoundMaterialTreeSource {
                        tree_catalog_index: u16::try_from(tree_catalog_index)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        material_ordinal: material_ordinal
                            .ok_or(CommonProofProverError::InvalidTree)?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice(),
            SetupKeyRelationSourceLayout::PublicKeyShare(_) => Box::new([]),
        };
        let authority_access = source
            .compact_public_key_development_authority()
            .map(SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment)
            .unwrap_or_else(|| {
                SetupKeyRelationAuthorityAccess::RetainedRegistry(source.authority_identifier())
            });
        Ok(Self {
            authority_access,
            family: source.family(),
            prepared_attempt: *source.prepared_attempt(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes()
                .to_vec(),
            setup_proof_context_hash: source.setup_proof_context_hash(),
            roster_hash: source.roster_hash(),
            participant_identity: source.participant_identity(),
            roster_position: source.roster_position(),
            setup_attempt_identifier: source.setup_attempt_identifier(),
            source_setup_intent_object_hash: source.source_setup_intent_object_hash(),
            action_randomness_authorization_hash: source.action_randomness_authorization_hash(),
            request_context,
            relation_plan_variant,
            relation_context,
            ring_degree,
            source_layout,
            request_profile,
            requested_column_ordinals,
            bound_material_tree_sources,
            next_source_index: 0,
            next_leaf_salt_source_ordinal: 0,
            next_leaf_salt_index: 0,
            cached_quotient: None,
            source_polynomials_finished: false,
            leaf_salts_finished: false,
        })
    }

    fn application(&self) -> SetupGenerationKeyRelationApplication<'_> {
        SetupGenerationKeyRelationApplication::from_runtime_binding(
            self.family,
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.roster_hash,
            self.participant_identity,
            self.roster_position,
        )
    }

    fn replay_identity(
        &self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomialReplayIdentity, CommonProofProverError> {
        let domain = match self.family {
            SetupKeyRelationProofFamily::SameSecret => SAME_SECRET_SOURCE_REPLAY_IDENTITY_DOMAIN,
            SetupKeyRelationProofFamily::PublicKeyShare => {
                PUBLIC_KEY_SHARE_SOURCE_REPLAY_IDENTITY_DOMAIN
            }
        };
        CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(hash_framed_parts_512(
            domain,
            &[
                &self.request_context.stable_generation_binding_hash(),
                &column_ordinal.to_le_bytes(),
                &self.setup_attempt_identifier,
                &self.source_setup_intent_object_hash,
                &self.action_randomness_authorization_hash,
                &self.setup_proof_context_hash,
                &self.roster_hash,
                &self.participant_identity,
                &self.roster_position.to_le_bytes(),
            ],
        ))
    }

    fn independently_expected_requested_column_ordinals(
        &self,
    ) -> Result<Vec<u32>, CommonProofProverError> {
        match (&self.source_layout, self.request_profile) {
            (_, SetupKeyRelationSourceRequestProfile::CompleteRelation) => {
                requested_pre_challenge_source_column_ordinals(&self.relation_plan_variant)
            }
            (
                SetupKeyRelationSourceLayout::PublicKeyShare(source_layout),
                SetupKeyRelationSourceRequestProfile::CompactPublicKeyAssignment,
            ) => compact_public_key_assignment_source_column_ordinals(
                &self.relation_plan_variant,
                source_layout,
            )
            .map_err(CommonProofProverError::Relation),
            (
                SetupKeyRelationSourceLayout::SameSecret(_),
                SetupKeyRelationSourceRequestProfile::CompactPublicKeyAssignment,
            ) => Err(CommonProofProverError::InvalidInput),
        }
    }

    fn derive_source_polynomial(
        &mut self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
            self.family,
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.roster_hash,
            self.participant_identity,
            self.roster_position,
        );
        let relation_plan_variant = &self.relation_plan_variant;
        let relation_context = &self.relation_context;
        let ring_degree = self.ring_degree;
        let source_layout = &self.source_layout;
        let cached_quotient = &mut self.cached_quotient;
        let derive_polynomial = |source: SetupGenerationKeyRelationSource<'_, '_>| {
            if let SetupKeyRelationSourceLayout::SameSecret(layout) = source_layout
                && let Some((material_ordinal, physical_column_ordinal)) =
                    bound_material_column(layout, column_ordinal)
            {
                let coefficients = source
                    .degree_zero_material(material_ordinal)?
                    .owned_authenticated_source()
                    .regenerate_masked_coefficients(physical_column_ordinal)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                return Ok(
                    CommonProofSourcePolynomial::from_protected_base_coefficients(coefficients),
                );
            }
            if let SetupKeyRelationSourceLayout::PublicKeyShare(layout) = source_layout {
                return derive_public_key_share_source_polynomial(
                    &source,
                    relation_plan_variant,
                    relation_context,
                    ring_degree,
                    layout,
                    column_ordinal,
                    cached_quotient,
                );
            }
            let SetupKeyRelationSourceLayout::SameSecret(layout) = source_layout else {
                return Err(RefusalReason::WrongTypeOrLength);
            };
            let mut derivation = SameSecretColumnDerivation {
                source: &source,
                relation_plan_variant,
                relation_context,
                ring_degree,
                source_layout: layout,
                cached_rows: ExactKeyRelationDerivedRowCache::new(
                    relation_plan_variant.ordered_columns().len(),
                ),
                active_columns: ExactKeyRelationActiveColumnSet::new(
                    relation_plan_variant.ordered_columns().len(),
                ),
                cached_quotient,
            };
            let signed_rows = derivation.derive_rows(column_ordinal)?;
            let mut field_values = Zeroizing::new(
                signed_rows
                    .iter()
                    .copied()
                    .map(signed_integer_to_base_field)
                    .collect::<Result<Vec<_>, _>>()?,
            );
            relation_plan_variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            ProofEvaluationDomain::new_subgroup(
                usize::try_from(relation_plan_variant.trace_domain_size())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
            .interpolate_base_polynomial_in_place(&mut field_values)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
        };
        let polynomial = match &self.authority_access {
            SetupKeyRelationAuthorityAccess::RetainedRegistry(authority_identifier) => {
                let authority_handle =
                    SetupGenerationAuthorityHandle::from_identifier(*authority_identifier);
                with_setup_generation_key_relation::<_, RefusalReason>(
                    &authority_handle,
                    &application,
                    derive_polynomial,
                )
            }
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(authority) => {
                with_setup_generation_compact_public_key_development_relation_reentry::<
                    _,
                    RefusalReason,
                >(authority, &application, derive_polynomial)
            }
        }
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        Ok(polynomial)
    }
}

impl CommonProofSourcePolynomialProvider for SetupKeyRelationSourcePolynomialAdapter {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        let base = match &self.source_layout {
            SetupKeyRelationSourceLayout::SameSecret(source_layout) => {
                same_secret_source_provider_memory_accounting(
                    &self.relation_plan_variant,
                    &self.relation_context,
                    u64::try_from(self.ring_degree)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    source_layout,
                    self.canonical_application_statement_bytes.len(),
                )?
            }
            SetupKeyRelationSourceLayout::PublicKeyShare(source_layout) => {
                let ring_degree = u64::try_from(self.ring_degree)
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                match self.request_profile {
                    SetupKeyRelationSourceRequestProfile::CompleteRelation => {
                        public_key_share_source_provider_memory_accounting(
                            &self.relation_plan_variant,
                            &self.relation_context,
                            ring_degree,
                            source_layout,
                            self.canonical_application_statement_bytes.len(),
                        )?
                    }
                    SetupKeyRelationSourceRequestProfile::CompactPublicKeyAssignment => {
                        public_key_share_source_provider_memory_accounting_for_requested_columns(
                            &self.relation_plan_variant,
                            &self.relation_context,
                            ring_degree,
                            source_layout,
                            self.canonical_application_statement_bytes.len(),
                            &self.requested_column_ordinals,
                        )?
                    }
                }
            }
        };
        if self.requested_column_ordinals.as_ref()
            != self
                .independently_expected_requested_column_ordinals()?
                .as_slice()
            || setup_provider_payload_for_count::<BoundMaterialTreeSource>(
                self.bound_material_tree_sources.len(),
            )? != setup_provider_payload_for_count::<BoundMaterialTreeSource>(
                self.relation_plan_variant
                    .ordered_trees()
                    .iter()
                    .filter(|tree| {
                        matches!(
                            tree,
                            RelationTreeDescriptor::BoundPublic {
                                construction_kind: BoundTreeConstructionKind::CommittedMaterial,
                                ..
                            }
                        )
                    })
                    .count(),
            )?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        match &self.authority_access {
            SetupKeyRelationAuthorityAccess::RetainedRegistry(authority_identifier) => {
                add_setup_authority_memory_accounting(base, *authority_identifier)
            }
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(authority) => {
                add_setup_authority_payload_memory_accounting(
                    base,
                    setup_generation_compact_public_key_development_retained_payload_byte_length(
                        authority,
                    )
                    .map_err(|_| CommonProofProverError::InvalidInput)?,
                )
            }
        }
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.source_polynomials_finished
            || request.request_context() != self.request_context
            || self
                .requested_column_ordinals
                .get(self.next_source_index)
                .copied()
                != Some(request.column_ordinal())
            || self.relation_plan_variant.ordered_columns().get(
                usize::try_from(request.column_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let column_ordinal = request.column_ordinal();
        let replay_identity = self.replay_identity(column_ordinal)?;
        let polynomial = self.derive_source_polynomial(column_ordinal)?;
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
        ))
    }

    fn poll_replayed_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if !self.source_polynomials_finished
            || request.request_context() != self.request_context
            || self
                .requested_column_ordinals
                .binary_search(&request.column_ordinal())
                .is_err()
            || self.relation_plan_variant.ordered_columns().get(
                usize::try_from(request.column_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let column_ordinal = request.column_ordinal();
        self.cached_quotient = None;
        let polynomial = self.derive_source_polynomial(column_ordinal)?;
        self.cached_quotient = None;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(
                polynomial,
                self.replay_identity(column_ordinal)?,
            ),
        ))
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            || self.next_source_index != self.requested_column_ordinals.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_quotient = None;
        self.source_polynomials_finished = true;
        Ok(())
    }

    fn provide_bound_tree_leaf_salt(
        &mut self,
        request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<
        Option<[u8; super::super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        CommonProofProverError,
    > {
        if !self.source_polynomials_finished || self.leaf_salts_finished {
            return Err(CommonProofProverError::InvalidTree);
        }
        let bound_source = self
            .bound_material_tree_sources
            .get(self.next_leaf_salt_source_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let authority_identifier = match &self.authority_access {
            SetupKeyRelationAuthorityAccess::RetainedRegistry(authority_identifier) => {
                *authority_identifier
            }
            SetupKeyRelationAuthorityAccess::CompactPublicKeyDevelopment(_) => {
                return Err(CommonProofProverError::InvalidTree);
            }
        };
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(authority_identifier);
        let application = self.application();
        let leaf_index = self.next_leaf_salt_index;
        let salt_and_leaf_count = with_setup_generation_key_relation::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                let material = source.degree_zero_material(bound_source.material_ordinal)?;
                let compact_source = material.compact_source();
                let leaf_count = compact_source.profile().evaluation_domain_size() / 2;
                if request.request_context() != self.request_context
                    || request.tree_catalog_index() != bound_source.tree_catalog_index
                    || request.expected_root() != compact_source.root()
                    || usize::try_from(request.leaf_index()).ok() != Some(leaf_index)
                    || leaf_index >= leaf_count
                {
                    return Err(RefusalReason::WrongContext);
                }
                Ok((
                    compact_source
                        .persistent_leaf_salt(leaf_index)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                    leaf_count,
                ))
            },
        )
        .map_err(|_| CommonProofProverError::InvalidTree)?;
        self.next_leaf_salt_index = self
            .next_leaf_salt_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_leaf_salt_index == salt_and_leaf_count.1 {
            self.next_leaf_salt_source_ordinal = self
                .next_leaf_salt_source_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.next_leaf_salt_index = 0;
        }
        Ok(Some(salt_and_leaf_count.0))
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            && !self.leaf_salts_finished
            && self.next_leaf_salt_source_ordinal == self.bound_material_tree_sources.len()
            && self.next_leaf_salt_index == 0
        {
            self.leaf_salts_finished = true;
            Ok(())
        } else {
            Err(CommonProofProverError::InvalidTree)
        }
    }
}

pub(crate) fn same_secret_relation_tree_inputs(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &SameSecretSourceLayout,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    relation_tree_inputs(source, relation_plan_variant, |tree, tree_catalog_index| {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            return Ok(None);
        };
        match construction_kind {
            BoundTreeConstructionKind::CommittedMaterial => {
                let material_ordinal = source_layout
                    .ordered_materials
                    .iter()
                    .position(|material| material_columns_match(material, ordered_column_ordinals))
                    .ok_or(CommonProofProverError::InvalidTree)?;
                let material = source
                    .degree_zero_material(material_ordinal)
                    .map_err(|_| CommonProofProverError::InvalidTree)?;
                let _ = u16::try_from(tree_catalog_index)
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                Ok(Some(RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: material.compact_source().material_context_hash(),
                        expected_root: material.compact_source().root(),
                    },
                )))
            }
            BoundTreeConstructionKind::SetupPolynomial => {
                let anchor_ordinal = source_layout
                    .ordered_anchors
                    .iter()
                    .position(|anchor| {
                        split_rows_match(&anchor.commitments, ordered_column_ordinals)
                    })
                    .ok_or(CommonProofProverError::InvalidTree)?;
                let anchor = source
                    .anchor_openings()
                    .get(anchor_ordinal)
                    .ok_or(CommonProofProverError::InvalidTree)?;
                Ok(Some(RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
                        row_width: u32::try_from(ordered_column_ordinals.len())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        expected_root: anchor.root(),
                    },
                )))
            }
        }
    })
}

pub(crate) fn public_key_share_relation_tree_inputs(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    relation_tree_inputs(source, relation_plan_variant, |tree, _| {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            return Err(CommonProofProverError::InvalidTree);
        };
        if source_layout
            .public_key_share_limbs
            .iter()
            .flat_map(|limb| limb.halves)
            .eq(ordered_column_ordinals.iter().copied())
        {
            return Ok(Some(RelationProofTreeInput::BoundPublic(
                StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash: source
                        .public_key_share()
                        .map_err(|_| CommonProofProverError::InvalidTree)?
                        .public_polynomial_context_hash(),
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    expected_root: source
                        .public_key_share()
                        .map_err(|_| CommonProofProverError::InvalidTree)?
                        .root(),
                },
            )));
        }
        let anchor_ordinal = source_layout
            .ordered_anchors
            .iter()
            .position(|anchor| split_rows_match(&anchor.commitments, ordered_column_ordinals))
            .ok_or(CommonProofProverError::InvalidTree)?;
        let anchor = source
            .anchor_openings()
            .get(anchor_ordinal)
            .ok_or(CommonProofProverError::InvalidTree)?;
        Ok(Some(RelationProofTreeInput::BoundPublic(
            StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
                row_width: u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                expected_root: anchor.root(),
            },
        )))
    })
}

fn relation_tree_inputs(
    _source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    mut bound_tree: impl FnMut(
        &RelationTreeDescriptor,
        usize,
    ) -> Result<Option<RelationProofTreeInput>, CommonProofProverError>,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    let mut relation_trees = Vec::with_capacity(relation_plan_variant.ordered_trees().len());
    for (tree_catalog_index, tree) in relation_plan_variant.ordered_trees().iter().enumerate() {
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match *proof_tree_role {
                    value if value == ProofTreeRole::BaseOracle as u16 => ProofTreeRole::BaseOracle,
                    value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                        ProofTreeRole::AuxiliaryOracle
                    }
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let leaf_visibility = ordered_column_ordinals.iter().try_fold(
                    ProofLeafVisibility::Public,
                    |visibility, column_ordinal| {
                        let descriptor = relation_plan_variant
                            .ordered_columns()
                            .get(
                                usize::try_from(*column_ordinal)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::InvalidColumn)?;
                        Ok::<_, CommonProofProverError>(
                            if matches!(descriptor.origin(), RelationColumnOrigin::Prover) {
                                ProofLeafVisibility::SecretBearing
                            } else {
                                visibility
                            },
                        )
                    },
                )?;
                relation_trees.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic { .. } => relation_trees.push(
                bound_tree(tree, tree_catalog_index)?.ok_or(CommonProofProverError::InvalidTree)?,
            ),
        }
    }
    Ok(relation_trees)
}

fn material_columns_match(
    material: &super::same_secret_anchor::SameSecretMaterialSourceLayout,
    ordered_column_ordinals: &[u32],
) -> bool {
    let first = material.material[0].ordered_digit_column_ordinals();
    let second = material.material[1].ordered_digit_column_ordinals();
    first.len() == 2
        && second.len() == 2
        && ordered_column_ordinals == [first[0], second[0], first[1], second[1]]
}

fn bound_material_column(
    source_layout: &SameSecretSourceLayout,
    column_ordinal: u32,
) -> Option<(usize, usize)> {
    source_layout
        .ordered_materials
        .iter()
        .enumerate()
        .find_map(|(material_ordinal, material)| {
            let first = material.material[0].ordered_digit_column_ordinals();
            let second = material.material[1].ordered_digit_column_ordinals();
            [first[0], second[0], first[1], second[1]]
                .iter()
                .position(|candidate| *candidate == column_ordinal)
                .map(|physical_column_ordinal| (material_ordinal, physical_column_ordinal))
        })
}

fn public_key_bound_half(
    source_layout: &PublicKeyShareSourceLayout,
    column_ordinal: u32,
) -> Option<(usize, usize)> {
    source_layout
        .public_key_share_limbs
        .iter()
        .enumerate()
        .find_map(|(limb_ordinal, limb)| {
            limb.halves
                .iter()
                .position(|candidate| *candidate == column_ordinal)
                .map(|half_ordinal| (limb_ordinal, half_ordinal))
        })
}

fn derive_public_key_share_source_polynomial<Source>(
    source: &Source,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: &PublicKeyShareSourceLayout,
    column_ordinal: u32,
    cached_quotient: &mut Option<CachedQuotient>,
) -> Result<CommonProofSourcePolynomial, RefusalReason>
where
    Source: PublicKeyShareCoefficientSource + ?Sized,
{
    if let Some((limb_ordinal, half_ordinal)) = public_key_bound_half(source_layout, column_ordinal)
    {
        let coefficients = source.public_key_limb_coefficient_slice(limb_ordinal)?;
        if coefficients.len() != ring_degree || coefficients.len() % 2 != 0 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let half_size = coefficients.len() / 2;
        let start = half_ordinal
            .checked_mul(half_size)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let end = start
            .checked_add(half_size)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let half = coefficients
            .get(start..end)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let mut field_values = half
            .iter()
            .copied()
            .map(ProofBaseFieldElement::from_canonical)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        ProofEvaluationDomain::new_subgroup(half_size)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
            .interpolate_base_polynomial_in_place(&mut field_values)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        return Ok(
            CommonProofSourcePolynomial::from_protected_base_coefficients(Zeroizing::new(
                field_values,
            )),
        );
    }

    let mut derivation = PublicKeyShareColumnDerivation {
        source,
        relation_plan_variant,
        relation_context,
        ring_degree,
        source_layout,
        cached_rows: ExactKeyRelationDerivedRowCache::new(
            relation_plan_variant.ordered_columns().len(),
        ),
        active_columns: ExactKeyRelationActiveColumnSet::new(
            relation_plan_variant.ordered_columns().len(),
        ),
        cached_quotient,
    };
    let signed_rows = derivation.derive_rows(column_ordinal)?;
    let mut field_values = Zeroizing::new(
        signed_rows
            .iter()
            .copied()
            .map(signed_integer_to_base_field)
            .collect::<Result<Vec<_>, _>>()?,
    );
    relation_plan_variant
        .ordered_columns()
        .get(usize::try_from(column_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    ProofEvaluationDomain::new_subgroup(
        usize::try_from(relation_plan_variant.trace_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
    )
    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
    .interpolate_base_polynomial_in_place(&mut field_values)
    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
}

#[cfg(test)]
pub(crate) fn derive_compact_public_key_development_source_polynomials(
    source: &CompactPublicKeyDevelopmentCoefficientSource,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    source_layout: &PublicKeyShareSourceLayout,
    requested_column_ordinals: &[u32],
) -> Result<Vec<(u32, CommonProofSourcePolynomial)>, CommonProofProverError> {
    let expected_column_ordinals =
        compact_public_key_assignment_source_column_ordinals(relation_plan_variant, source_layout)?;
    let trace_domain_size = usize::try_from(relation_plan_variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let ring_degree = source.ring_degree();
    if requested_column_ordinals != expected_column_ordinals
        || trace_domain_size
            .checked_mul(2)
            .filter(|derived_ring_degree| *derived_ring_degree == ring_degree)
            .is_none()
        || source
            .public_key_limb_count()
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            != source_layout.ordered_limbs.len()
        || source.anchor_count() != source_layout.ordered_anchors.len()
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    for (limb_ordinal, limb_layout) in source_layout.ordered_limbs.iter().enumerate() {
        let modulus = relation_context
            .resolved_modulus(SuiteModulusReference::data(limb_layout.data_modulus_index))
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        if source
            .public_key_limb_coefficient_slice(limb_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    for (anchor_source, anchor_layout) in source
        .ordered_anchor_sources
        .iter()
        .zip(source_layout.ordered_anchors.iter())
    {
        let modulus = relation_context
            .resolved_modulus(SuiteModulusReference::data(
                anchor_layout.data_modulus_index,
            ))
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        if anchor_source.commitment_data_modulus_index != anchor_layout.data_modulus_index
            || anchor_source
                .commitment_rows
                .iter()
                .flatten()
                .any(|coefficient| *coefficient >= modulus)
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }

    let mut cached_quotient = None;
    requested_column_ordinals
        .iter()
        .copied()
        .map(|column_ordinal| {
            derive_public_key_share_source_polynomial(
                source,
                relation_plan_variant,
                relation_context,
                ring_degree,
                source_layout,
                column_ordinal,
                &mut cached_quotient,
            )
            .map(|polynomial| (column_ordinal, polynomial))
            .map_err(|_| CommonProofProverError::InvalidColumn)
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn derive_generated_compact_public_key_development_source_polynomials(
    source: &CompactPublicKeyDevelopmentCoefficientSource,
    relation_context: &RelationPlanCheckContext,
    source_catalog: &CompactPublicKeyAssignmentSourceCatalog,
) -> Result<Vec<(u32, CommonProofSourcePolynomial)>, CommonProofProverError> {
    let ring_degree = source.ring_degree();
    if source.source_family() != SetupKeyRelationProofFamily::PublicKeyShare
        || source_catalog.ordered_sources.is_empty()
        || source_catalog.ordered_sources.len()
            != source_catalog
                .assignment_catalog
                .ordered_source_halves()
                .len()
        || source_catalog
            .assignment_catalog
            .trace_domain_size()
            .checked_mul(2)
            != u64::try_from(ring_degree).ok()
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let mut cached_quotient = None;
    source_catalog
        .ordered_sources
        .iter()
        .map(|entry| {
            derive_compact_public_key_source_polynomial(
                source,
                relation_context,
                ring_degree,
                &entry.derivation,
                &mut cached_quotient,
            )
            .map(|polynomial| (entry.column_ordinal, polynomial))
            .map_err(|_| CommonProofProverError::InvalidColumn)
        })
        .collect()
}

type CachedExactKeyRelationRows = Box<[Option<Zeroizing<Box<[i128]>>>]>;

pub(super) struct ExactKeyRelationDerivedRowCache {
    ordered_rows: CachedExactKeyRelationRows,
}

impl ExactKeyRelationDerivedRowCache {
    pub(super) fn new(column_count: usize) -> Self {
        Self {
            ordered_rows: (0..column_count)
                .map(|_| None)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    pub(super) fn get(&self, column_ordinal: u32) -> Option<&[i128]> {
        self.ordered_rows
            .get(usize::try_from(column_ordinal).ok()?)
            .and_then(Option::as_ref)
            .map(|rows| &rows[..])
    }

    #[cfg(test)]
    pub(super) fn descriptor_slot_count(&self) -> usize {
        self.ordered_rows.len()
    }

    fn insert(
        &mut self,
        column_ordinal: u32,
        rows: Zeroizing<Box<[i128]>>,
    ) -> Result<(), RefusalReason> {
        let slot = self
            .ordered_rows
            .get_mut(
                usize::try_from(column_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if slot.is_some() {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        *slot = Some(rows);
        Ok(())
    }
}

pub(super) struct ExactKeyRelationActiveColumnSet {
    active_columns: Box<[bool]>,
}

impl ExactKeyRelationActiveColumnSet {
    pub(super) fn new(column_count: usize) -> Self {
        Self {
            active_columns: vec![false; column_count].into_boxed_slice(),
        }
    }

    #[cfg(test)]
    pub(super) fn flag_count(&self) -> usize {
        self.active_columns.len()
    }

    pub(super) fn insert(&mut self, column_ordinal: u32) -> Result<bool, RefusalReason> {
        let active = self
            .active_columns
            .get_mut(
                usize::try_from(column_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let was_active = *active;
        *active = true;
        Ok(!was_active)
    }

    pub(super) fn remove(&mut self, column_ordinal: u32) -> Result<(), RefusalReason> {
        let active = self
            .active_columns
            .get_mut(
                usize::try_from(column_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if !*active {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        *active = false;
        Ok(())
    }
}

fn derive_upper_bound_comparator_rows_from_values(
    value_digit_rows: &[Zeroizing<Vec<i128>>],
    maximum_digits: &[u64],
    comparator: &UpperBoundComparatorWitnessLayout,
    requested_column_ordinal: u32,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
    if value_digit_rows.is_empty()
        || value_digit_rows.len() != maximum_digits.len()
        || comparator.difference_digits.len() != value_digit_rows.len()
        || comparator.borrow_column_ordinals.len() + 1 != value_digit_rows.len()
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let row_count = value_digit_rows
        .first()
        .map(|rows| rows.len())
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    if value_digit_rows.iter().any(|rows| rows.len() != row_count) {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let mut previous_borrow = vec![0_i128; row_count];
    let mut requested_rows = None;
    for digit_ordinal in 0..value_digit_rows.len() {
        let mut difference_rows = Vec::with_capacity(row_count);
        let mut next_borrow = vec![0_i128; row_count];
        for row_ordinal in 0..row_count {
            let value = value_digit_rows[digit_ordinal][row_ordinal];
            if !(0..i128::from(MATERIAL_DIGIT_RADIX)).contains(&value) {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            let raw_difference = i128::from(maximum_digits[digit_ordinal])
                .checked_sub(value)
                .and_then(|difference| difference.checked_sub(previous_borrow[row_ordinal]))
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            let borrow = i128::from(raw_difference < 0);
            if digit_ordinal + 1 == value_digit_rows.len() && borrow != 0 {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            let difference = raw_difference
                .checked_add(i128::from(MATERIAL_DIGIT_RADIX) * borrow)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            difference_rows.push(difference);
            next_borrow[row_ordinal] = borrow;
        }
        let difference_layout = &comparator.difference_digits[digit_ordinal];
        let candidate_rows = if difference_layout.target_column_ordinal == requested_column_ordinal
        {
            Some(difference_rows.clone())
        } else if let Some(trit_ordinal) = difference_layout
            .trit_column_ordinals
            .iter()
            .position(|column| *column == requested_column_ordinal)
        {
            let divisor = i128::from(TRIT_RADIX)
                .checked_pow(
                    u32::try_from(trit_ordinal)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            Some(
                difference_rows
                    .iter()
                    .map(|difference| (difference / divisor) % i128::from(TRIT_RADIX))
                    .collect(),
            )
        } else if comparator
            .borrow_column_ordinals
            .get(digit_ordinal)
            .is_some_and(|column| *column == requested_column_ordinal)
        {
            Some(next_borrow.clone())
        } else {
            None
        };
        if let Some(candidate_rows) = candidate_rows
            && requested_rows.replace(candidate_rows).is_some()
        {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        previous_borrow = next_borrow;
    }
    requested_rows
        .map(Zeroizing::new)
        .map(Some)
        .ok_or(RefusalReason::InvalidArithmeticRelation)
}

pub(super) trait KeyRelationColumnDerivation {
    fn relation_plan_variant(&self) -> &RelationPlanVariant;
    fn relation_context(&self) -> &RelationPlanCheckContext;
    fn exact_radix_digits_by_column(&self) -> &ExactRadixDigitColumnCatalog;
    fn cached_rows(&self) -> &ExactKeyRelationDerivedRowCache;
    fn cached_rows_mut(&mut self) -> &mut ExactKeyRelationDerivedRowCache;
    fn active_columns_mut(&mut self) -> &mut ExactKeyRelationActiveColumnSet;
    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason>;
    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason>;

    fn upper_bound_comparator_rows(
        &mut self,
        value_digit_column_ordinals: &[u32],
        maximum_digits: &[u64],
        comparator: &UpperBoundComparatorWitnessLayout,
        requested_column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let requested_by_comparator = comparator.difference_digits.iter().any(|difference| {
            difference.target_column_ordinal == requested_column_ordinal
                || difference
                    .trit_column_ordinals
                    .contains(&requested_column_ordinal)
        }) || comparator
            .borrow_column_ordinals
            .contains(&requested_column_ordinal);
        if !requested_by_comparator {
            return Ok(None);
        }
        let mut value_digit_rows = Vec::with_capacity(value_digit_column_ordinals.len());
        for column_ordinal in value_digit_column_ordinals {
            value_digit_rows.push(self.derive_rows(*column_ordinal)?);
        }
        derive_upper_bound_comparator_rows_from_values(
            &value_digit_rows,
            maximum_digits,
            comparator,
            requested_column_ordinal,
        )
    }

    fn derive_rows(&mut self, column_ordinal: u32) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        if let Some(rows) = self.cached_rows().get(column_ordinal) {
            return Ok(Zeroizing::new(rows.to_vec()));
        }
        if !self.active_columns_mut().insert(column_ordinal)? {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        let rows = if let Some(rows) = self.direct_witness_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.exact_radix_digit_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.verifier_sequence_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.semantic_auxiliary_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.exact_integer_lift_carry_rows(column_ordinal)? {
            rows
        } else {
            return Err(RefusalReason::InvalidArithmeticRelation);
        };
        self.active_columns_mut().remove(column_ordinal)?;
        if rows.len()
            != usize::try_from(self.relation_plan_variant().trace_domain_size())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.cached_rows_mut().insert(
            column_ordinal,
            Zeroizing::new(rows.to_vec().into_boxed_slice()),
        )?;
        Ok(rows)
    }

    fn exact_radix_digit_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let source_and_digit = self.exact_radix_digits_by_column().iter().find_map(
            |(source_column_ordinal, digit_column_ordinals)| {
                digit_column_ordinals
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                    .map(|digit_ordinal| (*source_column_ordinal, digit_ordinal))
            },
        );
        let Some((source_column_ordinal, digit_ordinal)) = source_and_digit else {
            return Ok(None);
        };
        let source_rows = self.derive_rows(source_column_ordinal)?;
        let divisor = i128::from(EXACT_INTEGER_LIFT_RADIX)
            .checked_pow(
                u32::try_from(digit_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        source_rows
            .iter()
            .map(|value| {
                if *value < 0 {
                    Err(RefusalReason::InvalidArithmeticRelation)
                } else {
                    Ok((*value / divisor) % i128::from(EXACT_INTEGER_LIFT_RADIX))
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
            .map(Some)
    }

    fn verifier_sequence_rows(
        &self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let descriptor = self
            .relation_plan_variant()
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let RelationColumnOrigin::VerifierSequence {
            verifier_source_ordinal,
            first_logical_element_index,
            logical_element_stride,
        } = descriptor.origin()
        else {
            return Ok(None);
        };
        let source = self
            .relation_plan_variant()
            .verifier_source(*verifier_source_ordinal)
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        let sequence = self.full_verifier_sequence(source)?;
        let trace_size = usize::try_from(self.relation_plan_variant().trace_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let first_index = usize::try_from(*first_logical_element_index)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let stride = usize::try_from(*logical_element_stride)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        (0..trace_size)
            .map(|row_ordinal| {
                first_index
                    .checked_add(
                        row_ordinal
                            .checked_mul(stride)
                            .ok_or(RefusalReason::OutsideSupportedProfile)?,
                    )
                    .and_then(|index| sequence.get(index).copied())
                    .map(i128::from)
                    .ok_or(RefusalReason::WrongTypeOrLength)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
            .map(Some)
    }

    fn semantic_auxiliary_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let certificate = self
            .relation_plan_variant()
            .ordered_semantic_cells
            .iter()
            .find_map(|semantic_cell| match &semantic_cell.bound_certificate {
                RelationBoundCertificate::UnsignedRadixRecomposition {
                    radix,
                    ordered_digit_column_ordinals,
                    ..
                } if ordered_digit_column_ordinals.contains(&column_ordinal) => Some((
                    semantic_cell.column_ordinal,
                    SemanticAuxiliaryRecipe::Radix {
                        radix: *radix,
                        offset: 0,
                        digit_ordinal: ordered_digit_column_ordinals
                            .iter()
                            .position(|candidate| *candidate == column_ordinal)?,
                    },
                )),
                RelationBoundCertificate::ShiftedRadixRecomposition {
                    radix,
                    offset,
                    ordered_digit_column_ordinals,
                    ..
                } if ordered_digit_column_ordinals.contains(&column_ordinal) => Some((
                    semantic_cell.column_ordinal,
                    SemanticAuxiliaryRecipe::Radix {
                        radix: *radix,
                        offset: offset.to_i128()?,
                        digit_ordinal: ordered_digit_column_ordinals
                            .iter()
                            .position(|candidate| *candidate == column_ordinal)?,
                    },
                )),
                RelationBoundCertificate::CanonicalModulusRecomposition {
                    modulus_reference,
                    radix,
                    ordered_digit_column_ordinals,
                    ordered_difference_digit_column_ordinals,
                    ordered_borrow_column_ordinals,
                    ..
                } if ordered_digit_column_ordinals.contains(&column_ordinal)
                    || ordered_difference_digit_column_ordinals.contains(&column_ordinal)
                    || ordered_borrow_column_ordinals.contains(&column_ordinal) =>
                {
                    Some((
                        semantic_cell.column_ordinal,
                        SemanticAuxiliaryRecipe::CanonicalComparator {
                            modulus_reference: *modulus_reference,
                            radix: *radix,
                            digit_columns: ordered_digit_column_ordinals.clone(),
                            difference_columns: ordered_difference_digit_column_ordinals.clone(),
                            borrow_columns: ordered_borrow_column_ordinals.clone(),
                        },
                    ))
                }
                _ => None,
            });
        let Some((target_column_ordinal, recipe)) = certificate else {
            return Ok(None);
        };
        let target = self.derive_rows(target_column_ordinal)?;
        match recipe {
            SemanticAuxiliaryRecipe::Radix {
                radix,
                offset,
                digit_ordinal,
            } => {
                let divisor = i128::from(radix)
                    .checked_pow(
                        u32::try_from(digit_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                target
                    .iter()
                    .map(|value| {
                        value
                            .checked_add(offset)
                            .filter(|shifted| *shifted >= 0)
                            .map(|shifted| (shifted / divisor) % i128::from(radix))
                            .ok_or(RefusalReason::InvalidArithmeticRelation)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Zeroizing::new)
                    .map(Some)
            }
            SemanticAuxiliaryRecipe::CanonicalComparator {
                modulus_reference,
                radix,
                digit_columns,
                difference_columns,
                borrow_columns,
            } => canonical_comparator_column_rows(
                &target,
                self.relation_context()
                    .resolved_modulus(modulus_reference)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                radix,
                &digit_columns,
                &difference_columns,
                &borrow_columns,
                column_ordinal,
            )
            .map(Some),
        }
    }

    fn exact_integer_lift_carry_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let component = self
            .relation_plan_variant()
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| batch.ordered_components.iter())
            .find(|component| {
                component.ordered_linear_terms.iter().any(|term| {
                    term.negative
                        && term.column_ordinal == column_ordinal
                        && term.column_offset == 0
                        && term.coefficient
                            == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
                })
            })
            .cloned();
        let Some(component) = component else {
            return Ok(None);
        };
        let trace_size = usize::try_from(self.relation_plan_variant().trace_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut accumulated = Zeroizing::new(vec![0_i128; trace_size]);
        for term in &component.ordered_linear_terms {
            if term.negative
                && term.column_ordinal == column_ordinal
                && term.column_offset == 0
                && term.coefficient
                    == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
            {
                continue;
            }
            let rows = self.derive_rows(term.column_ordinal)?;
            let coefficient = i128::from(resolve_integer_lift_coefficient(
                term.coefficient,
                self.relation_context(),
            )?);
            for (accumulated, value) in accumulated.iter_mut().zip(rows.iter()) {
                let shifted = value
                    .checked_sub(i128::from(term.column_offset))
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                let contribution = shifted
                    .checked_mul(coefficient)
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                *accumulated = if term.negative {
                    accumulated.checked_sub(contribution)
                } else {
                    accumulated.checked_add(contribution)
                }
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            }
        }
        for product in &component.ordered_full_ring_negacyclic_products {
            let product_rows = self.full_ring_product_rows(product)?;
            for (accumulated, value) in accumulated.iter_mut().zip(product_rows.iter()) {
                *accumulated = accumulated
                    .checked_add(*value)
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            }
        }
        let radix = i128::from(EXACT_INTEGER_LIFT_RADIX);
        accumulated
            .iter()
            .copied()
            .map(|value| {
                if value % radix == 0 {
                    Ok(value / radix)
                } else {
                    Err(RefusalReason::InvalidArithmeticRelation)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
            .map(Some)
    }

    fn full_ring_product_rows(
        &mut self,
        product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let multiplicand_low = self.derive_rows(product.multiplicand_low_column_ordinal)?;
        let multiplicand_high = self.derive_rows(product.multiplicand_high_column_ordinal)?;
        let multiplier_low = self.derive_rows(product.multiplier_low_column_ordinal)?;
        let multiplier_high = self.derive_rows(product.multiplier_high_column_ordinal)?;
        let multiplicand = multiplicand_low
            .iter()
            .chain(multiplicand_high.iter())
            .copied()
            .collect::<Vec<_>>();
        let multiplier = multiplier_low
            .iter()
            .map(|value| value - i128::from(product.multiplier_low_offset))
            .chain(
                multiplier_high
                    .iter()
                    .map(|value| value - i128::from(product.multiplier_high_offset)),
            )
            .collect::<Vec<_>>();
        let product_coefficients = exact_negacyclic_product_small(&multiplicand, &multiplier)?;
        let half_size = multiplicand_low.len();
        let selected = match product.selected_half {
            RelationIntegerLiftFullRingHalf::Low => &product_coefficients[..half_size],
            RelationIntegerLiftFullRingHalf::High => &product_coefficients[half_size..],
        };
        Ok(Zeroizing::new(
            selected
                .iter()
                .map(|value| if product.negative { -*value } else { *value })
                .collect(),
        ))
    }
}

enum SemanticAuxiliaryRecipe {
    Radix {
        radix: u64,
        offset: i128,
        digit_ordinal: usize,
    },
    CanonicalComparator {
        modulus_reference: SuiteModulusReference,
        radix: u64,
        digit_columns: Vec<u32>,
        difference_columns: Vec<u32>,
        borrow_columns: Vec<u32>,
    },
}

struct SameSecretColumnDerivation<'source, 'authority, 'statement, 'plan> {
    source: &'source SetupGenerationKeyRelationSource<'authority, 'statement>,
    relation_plan_variant: &'plan RelationPlanVariant,
    relation_context: &'plan RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: &'plan SameSecretSourceLayout,
    cached_rows: ExactKeyRelationDerivedRowCache,
    active_columns: ExactKeyRelationActiveColumnSet,
    cached_quotient: &'plan mut Option<CachedQuotient>,
}

impl KeyRelationColumnDerivation for SameSecretColumnDerivation<'_, '_, '_, '_> {
    fn relation_plan_variant(&self) -> &RelationPlanVariant {
        self.relation_plan_variant
    }

    fn relation_context(&self) -> &RelationPlanCheckContext {
        self.relation_context
    }

    fn exact_radix_digits_by_column(&self) -> &ExactRadixDigitColumnCatalog {
        &self.source_layout.exact_radix_digits_by_column
    }

    fn cached_rows(&self) -> &ExactKeyRelationDerivedRowCache {
        &self.cached_rows
    }

    fn cached_rows_mut(&mut self) -> &mut ExactKeyRelationDerivedRowCache {
        &mut self.cached_rows
    }

    fn active_columns_mut(&mut self) -> &mut ExactKeyRelationActiveColumnSet {
        &mut self.active_columns
    }

    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        if let Some(half_ordinal) = half_position(
            self.source_layout.common_secret.coefficients,
            column_ordinal,
        ) {
            return split_i8_polynomial_with_relation_offset(
                self.source.common_secret_coefficients(),
                half_ordinal,
                self.source_layout.common_secret.offset,
            )
            .map(Some);
        }
        if let Some(half_ordinal) = self
            .source_layout
            .negative_indicator
            .iter()
            .position(|candidate| *candidate == column_ordinal)
        {
            let indicator = self
                .source
                .common_secret_coefficients()
                .iter()
                .map(|coefficient| if *coefficient == -1 { 1 } else { 0 })
                .collect::<Vec<_>>();
            return split_signed_polynomial(&indicator, half_ordinal).map(Some);
        }
        for (material_ordinal, material_layout) in
            self.source_layout.ordered_materials.iter().enumerate()
        {
            for half_ordinal in 0..2 {
                if let Some(material_digit_ordinal) = material_layout.material[half_ordinal]
                    .ordered_digit_column_ordinals()
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                {
                    let authenticated_source = self
                        .source
                        .degree_zero_material(material_ordinal)?
                        .owned_authenticated_source();
                    let trace_size =
                        usize::try_from(self.relation_plan_variant.trace_domain_size())
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                    return (0..trace_size)
                        .map(|row_ordinal| {
                            authenticated_source
                                .material_digit(half_ordinal, material_digit_ordinal, row_ordinal)
                                .map(i128::from)
                                .map_err(|_| RefusalReason::InvalidArithmeticRelation)
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(Zeroizing::new)
                        .map(Some);
                }
            }
        }
        let mut comparator_request = None;
        for material_layout in &self.source_layout.ordered_materials {
            for half_ordinal in 0..2 {
                let comparator = &material_layout.upper_bound_comparators[half_ordinal];
                let contains_column =
                    comparator.difference_digits.iter().any(|difference| {
                        difference.target_column_ordinal == column_ordinal
                            || difference.trit_column_ordinals.contains(&column_ordinal)
                    }) || comparator.borrow_column_ordinals.contains(&column_ordinal);
                if contains_column {
                    if comparator_request.is_some() {
                        return Err(RefusalReason::InvalidArithmeticRelation);
                    }
                    comparator_request = Some((
                        material_layout.data_modulus_index,
                        material_layout.material[half_ordinal]
                            .ordered_digit_column_ordinals()
                            .to_vec(),
                        comparator.clone(),
                    ));
                }
            }
        }
        if let Some((data_modulus_index, value_digit_columns, comparator)) = comparator_request {
            let mut maximum = self
                .relation_context
                .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
                .checked_sub(1)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            let mut maximum_digits = Vec::with_capacity(value_digit_columns.len());
            for _ in &value_digit_columns {
                maximum_digits.push(maximum % MATERIAL_DIGIT_RADIX);
                maximum /= MATERIAL_DIGIT_RADIX;
            }
            if maximum != 0 {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            return self.upper_bound_comparator_rows(
                &value_digit_columns,
                &maximum_digits,
                &comparator,
                column_ordinal,
            );
        }
        anchor_direct_witness_rows(
            self.source,
            self.relation_plan_variant,
            self.relation_context,
            self.ring_degree,
            SetupKeyRelationProofFamily::SameSecret,
            &self.source_layout.ordered_anchors,
            column_ordinal,
            self.cached_quotient,
        )
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        setup_verifier_sequence(source, self.source, self.relation_context, self.ring_degree)
    }
}

struct PublicKeyShareColumnDerivation<'source, 'plan, Source>
where
    Source: PublicKeyShareCoefficientSource + ?Sized,
{
    source: &'source Source,
    relation_plan_variant: &'plan RelationPlanVariant,
    relation_context: &'plan RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: &'plan PublicKeyShareSourceLayout,
    cached_rows: ExactKeyRelationDerivedRowCache,
    active_columns: ExactKeyRelationActiveColumnSet,
    cached_quotient: &'plan mut Option<CachedQuotient>,
}

impl<Source> KeyRelationColumnDerivation for PublicKeyShareColumnDerivation<'_, '_, Source>
where
    Source: PublicKeyShareCoefficientSource + ?Sized,
{
    fn relation_plan_variant(&self) -> &RelationPlanVariant {
        self.relation_plan_variant
    }

    fn relation_context(&self) -> &RelationPlanCheckContext {
        self.relation_context
    }

    fn exact_radix_digits_by_column(&self) -> &ExactRadixDigitColumnCatalog {
        &self.source_layout.exact_radix_digits_by_column
    }

    fn cached_rows(&self) -> &ExactKeyRelationDerivedRowCache {
        &self.cached_rows
    }

    fn cached_rows_mut(&mut self) -> &mut ExactKeyRelationDerivedRowCache {
        &mut self.cached_rows
    }

    fn active_columns_mut(&mut self) -> &mut ExactKeyRelationActiveColumnSet {
        &mut self.active_columns
    }

    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        if let Some(half_ordinal) = half_position(
            self.source_layout.common_secret.source.coefficients,
            column_ordinal,
        ) {
            return split_i8_polynomial_with_relation_offset(
                self.source.common_secret_coefficient_slice(),
                half_ordinal,
                self.source_layout.common_secret.source.offset,
            )
            .map(Some);
        }
        if let Some(half_ordinal) = half_position(
            self.source_layout.public_key_error.coefficients,
            column_ordinal,
        ) {
            return split_i8_polynomial_with_relation_offset(
                self.source.public_key_error_coefficient_slice()?,
                half_ordinal,
                self.source_layout.public_key_error.offset,
            )
            .map(Some);
        }
        for (limb_ordinal, limb_layout) in self
            .source_layout
            .public_key_share_limbs
            .iter()
            .copied()
            .enumerate()
        {
            let coefficients = self
                .source
                .public_key_limb_coefficient_slice(limb_ordinal)?;
            if let Some(half_ordinal) = half_position(limb_layout, column_ordinal) {
                let signed = coefficients
                    .iter()
                    .copied()
                    .map(i128::from)
                    .collect::<Vec<_>>();
                return split_signed_polynomial(&signed, half_ordinal).map(Some);
            }
        }
        for (limb_ordinal, limb_layout) in self.source_layout.ordered_limbs.iter().enumerate() {
            if let Some(half_ordinal) = limb_layout
                .quotient_columns
                .iter()
                .position(|candidate| *candidate == column_ordinal)
            {
                let quotient = self.cached_public_key_quotient(limb_ordinal)?;
                return split_signed_polynomial(quotient, half_ordinal).map(Some);
            }
        }
        anchor_direct_witness_rows(
            self.source,
            self.relation_plan_variant,
            self.relation_context,
            self.ring_degree,
            SetupKeyRelationProofFamily::PublicKeyShare,
            &self.source_layout.ordered_anchors,
            column_ordinal,
            self.cached_quotient,
        )
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        setup_verifier_sequence(source, self.source, self.relation_context, self.ring_degree)
    }
}

impl<Source> PublicKeyShareColumnDerivation<'_, '_, Source>
where
    Source: PublicKeyShareCoefficientSource + ?Sized,
{
    fn cached_public_key_quotient(
        &mut self,
        limb_ordinal: usize,
    ) -> Result<&[i128], RefusalReason> {
        let key = CachedQuotientKey::PublicKeyShare { limb_ordinal };
        if self.cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
            let coefficients = self.derive_public_key_quotient(limb_ordinal)?;
            *self.cached_quotient = Some(CachedQuotient { key, coefficients });
        }
        self.cached_quotient
            .as_ref()
            .map(|cache| cache.coefficients.as_slice())
            .ok_or(RefusalReason::ConsumedState)
    }

    fn derive_public_key_quotient(
        &self,
        limb_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let limb_layout = self
            .source_layout
            .ordered_limbs
            .get(limb_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        derive_public_key_quotient(
            self.source,
            self.relation_context,
            self.ring_degree,
            limb_ordinal,
            limb_layout.data_modulus_index,
        )
    }
}

fn derive_public_key_quotient<Source>(
    source: &Source,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    limb_ordinal: usize,
    data_modulus_index: u16,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason>
where
    Source: PublicKeyShareCoefficientSource + ?Sized,
{
    let modulus = relation_context
        .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let public_key_share = source.public_key_limb_coefficient_slice(limb_ordinal)?;
    let common_reference =
        source.public_key_common_reference_limb(data_modulus_index, ring_degree)?;
    let secret = source
        .common_secret_coefficient_slice()
        .iter()
        .copied()
        .map(i128::from)
        .collect::<Vec<_>>();
    let product = exact_negacyclic_product_radix(
        &common_reference
            .into_iter()
            .map(i128::from)
            .collect::<Vec<_>>(),
        &secret,
    )?;
    let error = source.public_key_error_coefficient_slice()?;
    exact_modular_quotient(
        public_key_share
            .iter()
            .copied()
            .zip(product.iter().copied())
            .zip(error.iter().copied()),
        modulus,
        |((public_key_share, product), error)| {
            i128::from(public_key_share)
                .checked_add(product)
                .and_then(|value| {
                    value.checked_sub(i128::from(PLAINTEXT_MODULUS) * i128::from(error))
                })
        },
    )
}

trait AnchorSourceLayout {
    fn data_modulus_index(&self) -> u16;
    fn opening(&self) -> &super::key_relation::AnchorOpeningWitness;
    fn commitments(&self) -> &[super::key_relation::SplitIntegerVector];
    fn first_matrix(&self) -> &[Box<[super::key_relation::SplitIntegerVector]>];
    fn second_matrix(&self) -> &[super::key_relation::SplitIntegerVector];
    fn quotient_rows(&self) -> &[[u32; 2]];
}

impl AnchorSourceLayout for super::same_secret_anchor::SameSecretAnchorSourceLayout {
    fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }
    fn opening(&self) -> &super::key_relation::AnchorOpeningWitness {
        &self.opening
    }
    fn commitments(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.commitments
    }
    fn first_matrix(&self) -> &[Box<[super::key_relation::SplitIntegerVector]>] {
        &self.first_matrix
    }
    fn second_matrix(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.second_matrix
    }
    fn quotient_rows(&self) -> &[[u32; 2]] {
        self.quotients.rows()
    }
}

impl AnchorSourceLayout for super::public_key_share::PublicKeyShareAnchorSourceLayout {
    fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }
    fn opening(&self) -> &super::key_relation::AnchorOpeningWitness {
        &self.opening
    }
    fn commitments(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.commitments
    }
    fn first_matrix(&self) -> &[Box<[super::key_relation::SplitIntegerVector]>] {
        &self.first_matrix
    }
    fn second_matrix(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.second_matrix
    }
    fn quotient_rows(&self) -> &[[u32; 2]] {
        self.quotients.rows()
    }
}

#[allow(clippy::too_many_arguments)]
fn anchor_direct_witness_rows<Layout, Source>(
    source: &Source,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    family: SetupKeyRelationProofFamily,
    layouts: &[Layout],
    column_ordinal: u32,
    cached_quotient: &mut Option<CachedQuotient>,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason>
where
    Layout: AnchorSourceLayout,
    Source: SetupKeyRelationAnchorCoefficientSource + ?Sized,
{
    if layouts.len() != source.anchor_count() || source.source_family() != family {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    for (anchor_ordinal, layout) in layouts.iter().enumerate() {
        for (polynomial_ordinal, hiding_secret) in
            layout.opening().hiding_secrets().iter().enumerate()
        {
            if let Some(half_ordinal) =
                half_position(hiding_secret.source.coefficients, column_ordinal)
            {
                return split_i8_polynomial_with_relation_offset(
                    source.anchor_hiding_secret_polynomial(anchor_ordinal, polynomial_ordinal)?,
                    half_ordinal,
                    hiding_secret.source.offset,
                )
                .map(Some);
            }
        }
        for (polynomial_ordinal, hiding_error) in
            layout.opening().hiding_errors().iter().enumerate()
        {
            if let Some(half_ordinal) = half_position(hiding_error.coefficients, column_ordinal) {
                return split_i8_polynomial_with_relation_offset(
                    source.anchor_hiding_error_polynomial(anchor_ordinal, polynomial_ordinal)?,
                    half_ordinal,
                    hiding_error.offset,
                )
                .map(Some);
            }
        }
        for (row_ordinal, commitment) in layout.commitments().iter().copied().enumerate() {
            if let Some(half_ordinal) = half_position(commitment, column_ordinal) {
                return source
                    .anchor_commitment_trace_row_half(anchor_ordinal, row_ordinal, half_ordinal)
                    .map(Some);
            }
        }
        for matrix_row in layout.first_matrix() {
            for matrix in matrix_row.iter() {
                if let Some(rows) = recentered_matrix_rows(
                    matrix,
                    column_ordinal,
                    source,
                    relation_plan_variant,
                    relation_context,
                    ring_degree,
                )? {
                    return Ok(Some(rows));
                }
            }
        }
        for matrix in layout.second_matrix() {
            if let Some(rows) = recentered_matrix_rows(
                matrix,
                column_ordinal,
                source,
                relation_plan_variant,
                relation_context,
                ring_degree,
            )? {
                return Ok(Some(rows));
            }
        }
        for (row_ordinal, quotient_columns) in layout.quotient_rows().iter().enumerate() {
            if let Some(half_ordinal) = quotient_columns
                .iter()
                .position(|candidate| *candidate == column_ordinal)
            {
                let key = CachedQuotientKey::Anchor {
                    family,
                    anchor_ordinal,
                    row_ordinal,
                };
                if cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
                    let coefficients = derive_anchor_quotient(
                        source,
                        relation_context,
                        ring_degree,
                        layout.data_modulus_index(),
                        anchor_ordinal,
                        row_ordinal,
                    )?;
                    *cached_quotient = Some(CachedQuotient { key, coefficients });
                }
                let quotient = cached_quotient
                    .as_ref()
                    .map(|cache| cache.coefficients.as_slice())
                    .ok_or(RefusalReason::ConsumedState)?;
                return split_signed_polynomial(quotient, half_ordinal).map(Some);
            }
        }
    }
    Ok(None)
}

fn split_i8_polynomial_with_relation_offset(
    coefficients: &[i8],
    half_ordinal: usize,
    relation_offset: u64,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    let mut rows = split_signed_i8_polynomial(coefficients, half_ordinal)?;
    for row in rows.iter_mut() {
        *row = row
            .checked_add(i128::from(relation_offset))
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
    }
    Ok(rows)
}

fn select_compact_verifier_trace_rows(
    sequence: &[u64],
    first_logical_element_index: u64,
    logical_element_stride: u64,
    trace_domain_size: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    let first_index = usize::try_from(first_logical_element_index)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let stride = usize::try_from(logical_element_stride)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if stride == 0 {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    (0..trace_domain_size)
        .map(|row_ordinal| {
            first_index
                .checked_add(
                    row_ordinal
                        .checked_mul(stride)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?,
                )
                .and_then(|index| sequence.get(index).copied())
                .map(i128::from)
                .ok_or(RefusalReason::WrongTypeOrLength)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Zeroizing::new)
}

fn derive_compact_public_key_source_polynomial<Source>(
    source: &Source,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    derivation: &CompactPublicKeySourceDerivation,
    cached_quotient: &mut Option<CachedQuotient>,
) -> Result<CommonProofSourcePolynomial, RefusalReason>
where
    Source: PublicKeyShareCoefficientSource + ?Sized,
{
    if source.source_family() != SetupKeyRelationProofFamily::PublicKeyShare
        || ring_degree == 0
        || !ring_degree.is_multiple_of(2)
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let trace_domain_size = ring_degree / 2;
    let half_ordinal = |half_ordinal: u8| {
        usize::from(half_ordinal)
            .checked_add(1)
            .filter(|exclusive| *exclusive <= 2)
            .map(|exclusive| exclusive - 1)
            .ok_or(RefusalReason::WrongTypeOrLength)
    };
    let signed_rows = match *derivation {
        CompactPublicKeySourceDerivation::CommonSecret {
            half_ordinal: selected_half,
            centered_offset,
        } => split_i8_polynomial_with_relation_offset(
            source.common_secret_coefficient_slice(),
            half_ordinal(selected_half)?,
            centered_offset,
        )?,
        CompactPublicKeySourceDerivation::PublicKeyError {
            half_ordinal: selected_half,
            centered_offset,
        } => split_i8_polynomial_with_relation_offset(
            source.public_key_error_coefficient_slice()?,
            half_ordinal(selected_half)?,
            centered_offset,
        )?,
        CompactPublicKeySourceDerivation::PublicKeyShare {
            limb_ordinal,
            half_ordinal: selected_half,
        } => {
            let coefficients =
                source.public_key_limb_coefficient_slice(usize::from(limb_ordinal))?;
            if coefficients.len() != ring_degree {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            let selected_half = half_ordinal(selected_half)?;
            let first = selected_half
                .checked_mul(trace_domain_size)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let end = first
                .checked_add(trace_domain_size)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            Zeroizing::new(
                coefficients
                    .get(first..end)
                    .ok_or(RefusalReason::WrongTypeOrLength)?
                    .iter()
                    .copied()
                    .map(i128::from)
                    .collect(),
            )
        }
        CompactPublicKeySourceDerivation::PublicKeyCommonReference {
            data_modulus_index,
            first_logical_element_index,
            logical_element_stride,
        } => {
            let sequence =
                source.public_key_common_reference_limb(data_modulus_index, ring_degree)?;
            select_compact_verifier_trace_rows(
                &sequence,
                first_logical_element_index,
                logical_element_stride,
                trace_domain_size,
            )?
        }
        CompactPublicKeySourceDerivation::PublicKeyQuotient {
            limb_ordinal,
            data_modulus_index,
            half_ordinal: selected_half,
        } => {
            let limb_ordinal = usize::from(limb_ordinal);
            let key = CachedQuotientKey::PublicKeyShare { limb_ordinal };
            if cached_quotient.as_ref().map(|cached| cached.key) != Some(key) {
                *cached_quotient = Some(CachedQuotient {
                    key,
                    coefficients: derive_public_key_quotient(
                        source,
                        relation_context,
                        ring_degree,
                        limb_ordinal,
                        data_modulus_index,
                    )?,
                });
            }
            split_signed_polynomial(
                cached_quotient
                    .as_ref()
                    .ok_or(RefusalReason::ConsumedState)?
                    .coefficients
                    .as_slice(),
                half_ordinal(selected_half)?,
            )?
        }
        CompactPublicKeySourceDerivation::AnchorHidingSecret {
            anchor_ordinal,
            polynomial_ordinal,
            half_ordinal: selected_half,
            centered_offset,
        } => split_i8_polynomial_with_relation_offset(
            source.anchor_hiding_secret_polynomial(
                usize::from(anchor_ordinal),
                usize::from(polynomial_ordinal),
            )?,
            half_ordinal(selected_half)?,
            centered_offset,
        )?,
        CompactPublicKeySourceDerivation::AnchorHidingError {
            anchor_ordinal,
            polynomial_ordinal,
            half_ordinal: selected_half,
            centered_offset,
        } => split_i8_polynomial_with_relation_offset(
            source.anchor_hiding_error_polynomial(
                usize::from(anchor_ordinal),
                usize::from(polynomial_ordinal),
            )?,
            half_ordinal(selected_half)?,
            centered_offset,
        )?,
        CompactPublicKeySourceDerivation::AnchorCommitment {
            anchor_ordinal,
            row_ordinal,
            half_ordinal: selected_half,
        } => source.anchor_commitment_trace_row_half(
            usize::from(anchor_ordinal),
            usize::from(row_ordinal),
            half_ordinal(selected_half)?,
        )?,
        CompactPublicKeySourceDerivation::SetupCommitmentMatrix {
            data_modulus_index,
            matrix_row,
            matrix_column,
            first_logical_element_index,
            logical_element_stride,
        } => {
            let modulus = relation_context
                .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            let sequence = setup_commitment_matrix_polynomial(
                &encode_hex(&source.public_setup_seed_bytes()),
                usize::from(data_modulus_index),
                usize::from(matrix_row),
                usize::from(matrix_column),
                ring_degree,
                modulus,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            select_compact_verifier_trace_rows(
                &sequence,
                first_logical_element_index,
                logical_element_stride,
                trace_domain_size,
            )?
        }
        CompactPublicKeySourceDerivation::AnchorQuotient {
            anchor_ordinal,
            row_ordinal,
            data_modulus_index,
            half_ordinal: selected_half,
        } => {
            let anchor_ordinal = usize::from(anchor_ordinal);
            let row_ordinal = usize::from(row_ordinal);
            let key = CachedQuotientKey::Anchor {
                family: SetupKeyRelationProofFamily::PublicKeyShare,
                anchor_ordinal,
                row_ordinal,
            };
            if cached_quotient.as_ref().map(|cached| cached.key) != Some(key) {
                *cached_quotient = Some(CachedQuotient {
                    key,
                    coefficients: derive_anchor_quotient(
                        source,
                        relation_context,
                        ring_degree,
                        data_modulus_index,
                        anchor_ordinal,
                        row_ordinal,
                    )?,
                });
            }
            split_signed_polynomial(
                cached_quotient
                    .as_ref()
                    .ok_or(RefusalReason::ConsumedState)?
                    .coefficients
                    .as_slice(),
                half_ordinal(selected_half)?,
            )?
        }
    };
    if signed_rows.len() != trace_domain_size {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let mut field_values = Zeroizing::new(
        signed_rows
            .iter()
            .copied()
            .map(signed_integer_to_base_field)
            .collect::<Result<Vec<_>, _>>()?,
    );
    drop(signed_rows);
    ProofEvaluationDomain::new_subgroup(trace_domain_size)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
        .interpolate_base_polynomial_in_place(&mut field_values)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
}

fn recentered_matrix_rows<Source>(
    matrix: &SplitIntegerVector,
    column_ordinal: u32,
    source: &Source,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason>
where
    Source: SetupKeyRelationAnchorCoefficientSource + ?Sized,
{
    for half_ordinal in 0..2 {
        if matrix.halves[half_ordinal] == column_ordinal {
            let canonical_column = matrix.halves[half_ordinal];
            let descriptor = relation_plan_variant
                .ordered_columns()
                .get(
                    usize::try_from(canonical_column)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } = descriptor.origin()
            else {
                return Err(RefusalReason::InvalidArithmeticRelation);
            };
            let verifier_source = relation_plan_variant
                .verifier_source(*verifier_source_ordinal)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            let sequence =
                setup_verifier_sequence(verifier_source, source, relation_context, ring_degree)?;
            let trace_size = usize::try_from(relation_plan_variant.trace_domain_size())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let first_index = usize::try_from(*first_logical_element_index)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let stride = usize::try_from(*logical_element_stride)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let canonical = (0..trace_size)
                .map(|row_ordinal| {
                    first_index
                        .checked_add(row_ordinal.checked_mul(stride)?)
                        .and_then(|index| sequence.get(index).copied())
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            return Ok(Some(Zeroizing::new(
                canonical.into_iter().map(i128::from).collect(),
            )));
        }
    }
    Ok(None)
}

fn derive_anchor_quotient<Source>(
    source: &Source,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    data_modulus_index: u16,
    anchor_ordinal: usize,
    row_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason>
where
    Source: SetupKeyRelationAnchorCoefficientSource + ?Sized,
{
    if anchor_ordinal >= source.anchor_count() {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    if row_ordinal > SETUP_COMMITMENT_MODULE_RANK {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let modulus = relation_context
        .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let commitment = source.anchor_commitment_row(anchor_ordinal, row_ordinal)?;
    let seed = encode_hex(&source.public_setup_seed_bytes());
    let mut products = Vec::new();
    let product_columns = if row_ordinal < SETUP_COMMITMENT_MODULE_RANK {
        SETUP_COMMITMENT_MODULE_RANK + 1
    } else {
        SETUP_COMMITMENT_MODULE_RANK
    };
    for column_ordinal in 0..product_columns {
        let matrix_row = if row_ordinal < SETUP_COMMITMENT_MODULE_RANK {
            row_ordinal
        } else {
            SETUP_COMMITMENT_MODULE_RANK
        };
        let matrix = setup_commitment_matrix_polynomial(
            &seed,
            usize::from(data_modulus_index),
            matrix_row,
            column_ordinal,
            ring_degree,
            modulus,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let hiding_secret =
            source.anchor_hiding_secret_polynomial(anchor_ordinal, column_ordinal)?;
        products.push(exact_anchor_matrix_product(matrix, hiding_secret)?);
    }
    let last_hiding_secret =
        source.anchor_hiding_secret_polynomial(anchor_ordinal, SETUP_COMMITMENT_MODULE_RANK)?;
    let hiding_error = (row_ordinal < SETUP_COMMITMENT_MODULE_RANK)
        .then(|| source.anchor_hiding_error_polynomial(anchor_ordinal, row_ordinal))
        .transpose()?;
    exact_modular_quotient(0..ring_degree, modulus, |coefficient_ordinal| {
        let product_sum = products.iter().try_fold(0_i128, |sum, product| {
            sum.checked_add(product[coefficient_ordinal])
        })?;
        let value = commitment[coefficient_ordinal].checked_sub(product_sum)?;
        if let Some(error) = hiding_error {
            value.checked_sub(i128::from(error[coefficient_ordinal]))
        } else {
            value
                .checked_sub(i128::from(last_hiding_secret[coefficient_ordinal]))
                .and_then(|value| {
                    value.checked_sub(i128::from(
                        source.common_secret_coefficient_slice()[coefficient_ordinal],
                    ))
                })
        }
    })
}

fn exact_anchor_matrix_product(
    canonical_matrix: Vec<u64>,
    hiding_secret: &[i8],
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    exact_negacyclic_product_radix(
        &canonical_matrix
            .into_iter()
            .map(i128::from)
            .collect::<Vec<_>>(),
        &hiding_secret
            .iter()
            .copied()
            .map(i128::from)
            .collect::<Vec<_>>(),
    )
}

fn setup_verifier_sequence<Source>(
    source: &RelationVerifierSource,
    coefficient_source: &Source,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
) -> Result<Vec<u64>, RefusalReason>
where
    Source: SetupKeyRelationAnchorCoefficientSource + ?Sized,
{
    match source {
        RelationVerifierSource::Protocol {
            protocol_source_kind: 5,
            source_coordinates,
            ..
        } => {
            let [data_modulus_index, matrix_part, row, column] = source_coordinates.as_slice()
            else {
                return Err(RefusalReason::WrongTypeOrLength);
            };
            let data_modulus_index =
                u16::try_from(*data_modulus_index).map_err(|_| RefusalReason::WrongTypeOrLength)?;
            let matrix_part =
                u16::try_from(*matrix_part).map_err(|_| RefusalReason::WrongTypeOrLength)?;
            let matrix_row = match matrix_part {
                1 => usize::try_from(*row).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                2 if *row == 0 => SETUP_COMMITMENT_MODULE_RANK,
                _ => return Err(RefusalReason::WrongTypeOrLength),
            };
            let modulus = relation_context
                .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            setup_commitment_matrix_polynomial(
                &encode_hex(&coefficient_source.public_setup_seed_bytes()),
                usize::from(data_modulus_index),
                matrix_row,
                usize::try_from(*column).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                ring_degree,
                modulus,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)
        }
        RelationVerifierSource::Protocol {
            protocol_source_kind: 6,
            source_coordinates,
            ..
        } if coefficient_source.source_family() == SetupKeyRelationProofFamily::PublicKeyShare => {
            let [data_modulus_index] = source_coordinates.as_slice() else {
                return Err(RefusalReason::WrongTypeOrLength);
            };
            coefficient_source.public_key_common_reference_limb(
                u16::try_from(*data_modulus_index).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                ring_degree,
            )
        }
        _ => Err(RefusalReason::WrongTypeOrLength),
    }
}

#[cfg(test)]
mod compact_source_request_profile_tests {
    use super::*;
    use crate::{
        bgv::{
            parameters::POLYNOMIAL_DEGREE,
            proof_suite::{
                relation_plan::compile_public_key_share_relation_with_source_layout,
                selected_public_key_share_relation_plan_input,
                selected_relation_plan_check_context,
            },
        },
        foundation::ProofApplicationSlotCeilings,
    };

    fn selected_compact_request_fixture() -> (
        CompiledRelationPlan,
        RelationPlanVariant,
        RelationPlanCheckContext,
        PublicKeyShareSourceLayout,
        Vec<u32>,
    ) {
        let input = selected_public_key_share_relation_plan_input()
            .expect("selected public-key relation input");
        let relation_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected public-key relation context");
        let compiled =
            compile_public_key_share_relation_with_source_layout(&input, &relation_context)
                .expect("selected public-key relation compiles");
        let relation_plan_variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("selected public-key variant")
            .clone();
        let requested_column_ordinals = compact_public_key_assignment_source_column_ordinals(
            &relation_plan_variant,
            &compiled.source_layout,
        )
        .expect("compact authenticated source sequence derives");
        let independently_cataloged_column_ordinals =
            super::super::compact_ring_vector::compact_public_key_authenticated_source_column_ordinals(
                &input,
                &relation_plan_variant,
                &compiled.source_layout,
            )
            .expect("compact assignment catalog source sequence derives");
        assert_eq!(
            requested_column_ordinals,
            independently_cataloged_column_ordinals,
        );
        (
            compiled.relation_plan,
            relation_plan_variant,
            relation_context,
            compiled.source_layout,
            requested_column_ordinals,
        )
    }

    #[test]
    fn compact_public_key_provider_profile_accounts_only_the_exact_source_sequence() {
        let (_, relation_plan_variant, relation_context, source_layout, requested_column_ordinals) =
            selected_compact_request_fixture();
        let complete_requested_column_ordinals =
            requested_pre_challenge_source_column_ordinals(&relation_plan_variant)
                .expect("complete source sequence derives");
        assert_eq!(complete_requested_column_ordinals.len(), 3_302);
        assert_eq!(requested_column_ordinals.len(), 202);
        assert!(
            requested_column_ordinals
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(requested_column_ordinals.iter().all(|column_ordinal| {
            complete_requested_column_ordinals
                .binary_search(column_ordinal)
                .is_ok()
        }));
        assert_eq!(
            classify_setup_key_relation_source_request_profile(
                Some(&source_layout),
                &relation_plan_variant,
                &complete_requested_column_ordinals,
            )
            .expect("complete request profile classifies"),
            SetupKeyRelationSourceRequestProfile::CompleteRelation,
        );
        assert_eq!(
            classify_setup_key_relation_source_request_profile(
                Some(&source_layout),
                &relation_plan_variant,
                &requested_column_ordinals,
            )
            .expect("compact request profile classifies"),
            SetupKeyRelationSourceRequestProfile::CompactPublicKeyAssignment,
        );

        let complete_accounting = public_key_share_source_provider_memory_accounting(
            &relation_plan_variant,
            &relation_context,
            u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64"),
            &source_layout,
            128,
        )
        .expect("complete provider accounting derives");
        let compact_accounting =
            public_key_share_source_provider_memory_accounting_for_requested_columns(
                &relation_plan_variant,
                &relation_context,
                u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64"),
                &source_layout,
                128,
                &requested_column_ordinals,
            )
            .expect("compact provider accounting derives");
        let request_vector_payload_reduction = u64::try_from(
            (complete_requested_column_ordinals.len() - requested_column_ordinals.len())
                * core::mem::size_of::<u32>(),
        )
        .expect("request payload reduction fits u64");
        assert_eq!(
            complete_accounting.loading_persistent_resident_byte_length()
                - compact_accounting.loading_persistent_resident_byte_length(),
            request_vector_payload_reduction,
        );
        assert_eq!(
            complete_accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                - compact_accounting
                    .post_source_polynomial_finish_persistent_resident_byte_length(),
            request_vector_payload_reduction,
        );
        assert!(
            compact_accounting.additional_loading_transient_byte_length()
                <= complete_accounting.additional_loading_transient_byte_length()
        );
        assert_eq!(
            compact_accounting.maximum_returned_source_polynomial_byte_length(),
            complete_accounting.maximum_returned_source_polynomial_byte_length(),
        );
    }

    #[test]
    fn compact_public_key_provider_profile_refuses_noncanonical_source_sequences() {
        let (_, relation_plan_variant, relation_context, source_layout, requested_column_ordinals) =
            selected_compact_request_fixture();
        let ring_degree = u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64");
        let mut reversed = requested_column_ordinals.clone();
        reversed.swap(0, 1);
        let mut duplicated = requested_column_ordinals.clone();
        duplicated[1] = duplicated[0];
        let mut extraneous = requested_column_ordinals;
        extraneous[0] = u32::MAX;
        for malformed in [reversed, duplicated, extraneous, Vec::new()] {
            assert_eq!(
                classify_setup_key_relation_source_request_profile(
                    Some(&source_layout),
                    &relation_plan_variant,
                    &malformed,
                ),
                Err(CommonProofProverError::InvalidColumn),
            );
            assert_eq!(
                public_key_share_source_provider_memory_accounting_for_requested_columns(
                    &relation_plan_variant,
                    &relation_context,
                    ring_degree,
                    &source_layout,
                    128,
                    &malformed,
                ),
                Err(CommonProofProverError::InvalidColumn),
            );
        }
    }

    #[test]
    fn compact_public_key_plan_binding_refuses_a_substituted_variant_or_schema() {
        let (relation_plan, relation_plan_variant, _, _, _) = selected_compact_request_fixture();
        let expected_binding = derive_compact_public_key_relation_plan_binding(
            &relation_plan,
            &relation_plan_variant,
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the checked plan and its selected variant bind");
        assert_eq!(
            expected_binding,
            (
                relation_plan.canonical_hash().expect("plan hash derives"),
                relation_plan_variant
                    .canonical_hash()
                    .expect("variant hash derives"),
            ),
        );

        let mut substituted_variant = relation_plan_variant;
        substituted_variant.trace_domain_size = substituted_variant
            .trace_domain_size
            .checked_mul(2)
            .expect("selected trace domain doubles");
        assert_eq!(
            derive_compact_public_key_relation_plan_binding(
                &relation_plan,
                &substituted_variant,
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            Err(CommonProofProverError::InvalidInput),
        );
        assert_eq!(
            derive_compact_public_key_relation_plan_binding(
                &relation_plan,
                relation_plan
                    .select_variant(None, None)
                    .expect("selected variant remains available"),
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            Err(CommonProofProverError::InvalidInput),
        );
    }

    #[test]
    fn generated_compact_assignment_source_catalog_is_the_checked_production_output() {
        let (relation_plan, relation_plan_variant, relation_context, source_layout, _) =
            selected_compact_request_fixture();
        let input = selected_public_key_share_relation_plan_input()
            .expect("selected public-key relation input");
        let (relation, independently_derived) = derive_bound_compact_public_key_catalogs(
            &input,
            &relation_plan,
            &relation_plan_variant,
            &source_layout,
        )
        .expect("bound compact public-key catalogs derive");
        relation
            .check(&input, &relation_context, &relation_plan_variant)
            .expect("compact public-key relation checks");
        independently_derived
            .validate_generated(&relation)
            .expect("independently derived compact assignment source catalog checks");
        let selected = selected_compact_public_key_assignment_source_catalog(&relation)
            .expect("generated compact assignment source catalog decodes");
        assert_eq!(selected, independently_derived);
        assert_eq!(selected.ordered_sources.len(), 202);
        assert_eq!(selected.relation_column_count, 6_976);
        assert_eq!(
            serde_json::to_vec(&independently_derived)
                .expect("independently derived compact assignment source catalog serializes"),
            GENERATED_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTES
                .strip_suffix(b"\n")
                .expect("generated compact assignment source catalog has one source-file newline"),
        );
    }

    #[cfg(feature = "compact-public-key-catalog-regeneration")]
    #[test]
    fn generated_compact_public_key_catalog_regeneration_writes_canonical_compiler_output() {
        let (relation_plan, relation_plan_variant, relation_context, source_layout, _) =
            selected_compact_request_fixture();
        let input = selected_public_key_share_relation_plan_input()
            .expect("selected public-key relation input");
        let (relation, source_catalog) = derive_bound_compact_public_key_catalogs(
            &input,
            &relation_plan,
            &relation_plan_variant,
            &source_layout,
        )
        .expect("bound compact public-key catalogs derive");
        relation
            .check(&input, &relation_context, &relation_plan_variant)
            .expect("regenerated compact public-key relation checks");
        source_catalog
            .validate_generated(&relation)
            .expect("regenerated compact assignment-source catalog checks");

        let canonical_relation_bytes = serde_json::to_vec(&relation)
            .expect("regenerated compact public-key relation serializes");
        let canonical_source_catalog_bytes = serde_json::to_vec(&source_catalog)
            .expect("regenerated compact assignment-source catalog serializes");
        if let Some(output_directory) =
            std::env::var_os("SEALED_LATTICE_COMPACT_PUBLIC_KEY_CATALOG_OUTPUT_DIRECTORY")
                .map(std::path::PathBuf::from)
        {
            std::fs::write(
                output_directory.join("compact_public_key_relation.generated.json"),
                [canonical_relation_bytes.as_slice(), b"\n"].concat(),
            )
            .expect("regenerated compact public-key relation writes");
            std::fs::write(
                output_directory.join("compact_public_key_assignment_source.generated.json"),
                [canonical_source_catalog_bytes.as_slice(), b"\n"].concat(),
            )
            .expect("regenerated compact assignment-source catalog writes");
        } else {
            assert_eq!(
                super::super::compact_ring_vector::selected_compact_public_key_relation_catalog()
                    .expect("checked-in compact public-key relation decodes"),
                relation,
            );
            assert_eq!(
                [canonical_source_catalog_bytes.as_slice(), b"\n"].concat(),
                GENERATED_COMPACT_PUBLIC_KEY_ASSIGNMENT_SOURCE_CATALOG_BYTES,
            );
        }
    }

    #[test]
    fn generated_compact_assignment_source_catalog_refuses_substituted_bindings_and_derivations() {
        let (relation_plan, relation_plan_variant, relation_context, source_layout, _) =
            selected_compact_request_fixture();
        let input = selected_public_key_share_relation_plan_input()
            .expect("selected public-key relation input");
        let (relation, catalog) = derive_bound_compact_public_key_catalogs(
            &input,
            &relation_plan,
            &relation_plan_variant,
            &source_layout,
        )
        .expect("bound compact public-key catalogs derive");
        relation
            .check(&input, &relation_context, &relation_plan_variant)
            .expect("compact public-key relation checks");

        let mut wrong_schema = catalog.clone();
        wrong_schema.schema_version += 1;
        assert_eq!(
            wrong_schema.validate_generated(&relation),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut substituted_complete_plan_hash = catalog.clone();
        substituted_complete_plan_hash.complete_relation_plan_hash[0] ^= 1;
        assert_eq!(
            substituted_complete_plan_hash.validate_generated(&relation),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut substituted_variant_hash_value =
            serde_json::to_value(&catalog).expect("source catalog converts to JSON value");
        let substituted_variant_hash_byte = substituted_variant_hash_value
            .pointer_mut("/assignment_catalog/relation_plan_hash/0")
            .expect("assignment variant hash byte exists");
        *substituted_variant_hash_byte =
            serde_json::json!(substituted_variant_hash_byte.as_u64().expect("hash byte") ^ 1);
        let substituted_variant_hash: CompactPublicKeyAssignmentSourceCatalog =
            serde_json::from_value(substituted_variant_hash_value)
                .expect("substituted variant-hash catalog decodes");
        assert_eq!(
            substituted_variant_hash.validate_generated(&relation),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut missing_relation_columns = catalog.clone();
        missing_relation_columns.relation_column_count = 0;
        assert_eq!(
            missing_relation_columns.validate_generated(&relation),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut reordered_sources = catalog.clone();
        reordered_sources.ordered_sources.swap(0, 1);
        assert_eq!(
            reordered_sources.validate_generated(&relation),
            Err(RelationPlanError::InvalidColumn)
        );

        let mut wrong_origin_value =
            serde_json::to_value(&catalog).expect("source catalog converts to JSON value");
        *wrong_origin_value
            .pointer_mut("/assignment_catalog/ordered_source_halves/0/source_origin")
            .expect("first source origin exists") = serde_json::json!("BoundTree");
        let wrong_origin: CompactPublicKeyAssignmentSourceCatalog =
            serde_json::from_value(wrong_origin_value)
                .expect("wrong-origin source catalog decodes");
        assert_eq!(
            wrong_origin.validate_generated(&relation),
            Err(RelationPlanError::InvalidColumn)
        );

        let mut wrong_destination_value =
            serde_json::to_value(&catalog).expect("source catalog converts to JSON value");
        let wrong_destination = wrong_destination_value
            .pointer_mut("/assignment_catalog/ordered_source_halves/0/destination_first_element")
            .expect("first destination exists");
        *wrong_destination = serde_json::json!(
            wrong_destination
                .as_u64()
                .expect("destination is an integer")
                + 1
        );
        let wrong_destination: CompactPublicKeyAssignmentSourceCatalog =
            serde_json::from_value(wrong_destination_value)
                .expect("wrong-destination source catalog decodes");
        assert!(wrong_destination.validate_generated(&relation).is_err());

        let mut invalid_half = catalog.clone();
        let CompactPublicKeySourceDerivation::CommonSecret { half_ordinal, .. } =
            &mut invalid_half.ordered_sources[0].derivation
        else {
            panic!("the first generated source is the first common-secret half")
        };
        *half_ordinal = 2;
        assert_eq!(
            invalid_half.validate_generated(&relation),
            Err(RelationPlanError::InvalidColumn)
        );

        let mut wrong_modulus = catalog.clone();
        let CompactPublicKeySourceDerivation::PublicKeyQuotient {
            data_modulus_index, ..
        } = &mut wrong_modulus
            .ordered_sources
            .iter_mut()
            .find(|source| {
                matches!(
                    &source.derivation,
                    CompactPublicKeySourceDerivation::PublicKeyQuotient { .. }
                )
            })
            .expect("a public-key quotient source exists")
            .derivation
        else {
            unreachable!("the selected source is a public-key quotient")
        };
        *data_modulus_index += 1;
        assert_eq!(
            wrong_modulus.validate_generated(&relation),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut wrong_source_derivation = catalog;
        let CompactPublicKeySourceDerivation::CommonSecret {
            centered_offset, ..
        } = &mut wrong_source_derivation.ordered_sources[0].derivation
        else {
            panic!("the first generated source is the first common-secret half")
        };
        *centered_offset += 1;
        assert_eq!(
            wrong_source_derivation.validate_generated(&relation),
            Err(RelationPlanError::InvalidConstraint)
        );
    }
}

#[cfg(test)]
mod upper_bound_comparator_tests {
    use super::super::key_relation::BoundedMaterialDigitWitnessLayout;
    use super::*;

    fn two_digit_comparator() -> UpperBoundComparatorWitnessLayout {
        UpperBoundComparatorWitnessLayout {
            difference_digits: vec![
                BoundedMaterialDigitWitnessLayout {
                    target_column_ordinal: 10,
                    trit_column_ordinals: (100..117).collect(),
                },
                BoundedMaterialDigitWitnessLayout {
                    target_column_ordinal: 20,
                    trit_column_ordinals: vec![200],
                },
            ],
            borrow_column_ordinals: vec![30],
        }
    }

    fn valid_value_rows() -> Vec<Zeroizing<Vec<i128>>> {
        vec![
            Zeroizing::new(vec![0, 5, 6, i128::from(MATERIAL_DIGIT_RADIX - 1), 0]),
            Zeroizing::new(vec![0, 1, 0, 0, 1]),
        ]
    }

    fn requested_rows(
        value_rows: &[Zeroizing<Vec<i128>>],
        requested_column_ordinal: u32,
    ) -> Result<Vec<i128>, RefusalReason> {
        derive_upper_bound_comparator_rows_from_values(
            value_rows,
            &[5, 1],
            &two_digit_comparator(),
            requested_column_ordinal,
        )
        .map(|rows| {
            rows.expect("the requested comparator column must be owned")
                .to_vec()
        })
    }

    #[test]
    fn upper_bound_comparator_derives_difference_trits_and_borrows_at_boundaries() {
        let values = valid_value_rows();
        assert_eq!(
            requested_rows(&values, 10),
            Ok(vec![5, 0, i128::from(MATERIAL_DIGIT_RADIX - 1), 6, 5])
        );
        assert_eq!(requested_rows(&values, 20), Ok(vec![1, 0, 0, 0, 0]));
        assert_eq!(requested_rows(&values, 30), Ok(vec![0, 0, 1, 1, 0]));
        assert_eq!(requested_rows(&values, 100), Ok(vec![2, 0, 2, 0, 2]));
        assert_eq!(requested_rows(&values, 116), Ok(vec![0, 0, 2, 0, 0]));
        assert_eq!(requested_rows(&values, 200), Ok(vec![1, 0, 0, 0, 0]));
    }

    #[test]
    fn upper_bound_comparator_rejects_out_of_range_values_and_final_borrow() {
        let negative_value = vec![Zeroizing::new(vec![-1]), Zeroizing::new(vec![0])];
        assert_eq!(
            requested_rows(&negative_value, 10),
            Err(RefusalReason::InvalidArithmeticRelation)
        );

        let radix_value = vec![
            Zeroizing::new(vec![i128::from(MATERIAL_DIGIT_RADIX)]),
            Zeroizing::new(vec![0]),
        ];
        assert_eq!(
            requested_rows(&radix_value, 10),
            Err(RefusalReason::InvalidArithmeticRelation)
        );

        let above_maximum = vec![Zeroizing::new(vec![6]), Zeroizing::new(vec![1])];
        assert_eq!(
            requested_rows(&above_maximum, 10),
            Err(RefusalReason::InvalidArithmeticRelation)
        );
    }

    #[test]
    fn upper_bound_comparator_rejects_malformed_geometry() {
        let values = valid_value_rows();
        assert_eq!(
            derive_upper_bound_comparator_rows_from_values(
                &values[..1],
                &[5, 1],
                &two_digit_comparator(),
                10,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        );

        let mismatched_rows = vec![Zeroizing::new(vec![0, 1]), Zeroizing::new(vec![0])];
        assert_eq!(
            requested_rows(&mismatched_rows, 10),
            Err(RefusalReason::WrongTypeOrLength)
        );

        let mut duplicate_column = two_digit_comparator();
        duplicate_column.difference_digits[1].target_column_ordinal = 10;
        assert_eq!(
            derive_upper_bound_comparator_rows_from_values(&values, &[5, 1], &duplicate_column, 10),
            Err(RefusalReason::InvalidArithmeticRelation)
        );
    }
}

#[cfg(test)]
mod anchor_quotient_representative_tests {
    use super::*;

    #[test]
    fn shifted_small_witness_rows_use_the_relation_encoding() {
        let coefficients = [-1_i8, 0, 1, 1, -1, 0, 1, -1];
        assert_eq!(
            &split_i8_polynomial_with_relation_offset(&coefficients, 0, 1)
                .expect("shifted low half")[..],
            &[0, 1, 2, 2],
        );
        assert_eq!(
            &split_i8_polynomial_with_relation_offset(&coefficients, 1, 1)
                .expect("shifted high half")[..],
            &[0, 1, 2, 0],
        );
        assert_eq!(
            &split_i8_polynomial_with_relation_offset(&coefficients, 0, 0)
                .expect("unshifted low half")[..],
            &[-1, 0, 1, 1],
        );
        assert_eq!(
            split_i8_polynomial_with_relation_offset(&coefficients, 2, 1),
            Err(RefusalReason::WrongTypeOrLength),
        );
    }

    #[test]
    fn anchor_quotient_uses_the_canonical_matrix_representative_proved_by_the_relation() {
        let modulus = 17_u64;
        let commitment = [16_u64, 0];
        let canonical_product =
            exact_anchor_matrix_product(vec![16, 0], &[1, 0]).expect("canonical matrix product");
        let canonical_quotient = exact_modular_quotient(
            commitment
                .iter()
                .copied()
                .zip(canonical_product.iter().copied()),
            modulus,
            |(commitment, product)| i128::from(commitment).checked_sub(product),
        )
        .expect("canonical quotient");
        assert_eq!(&canonical_product[..], &[16, 0]);
        assert_eq!(&canonical_quotient[..], &[0, 0]);

        let centered_product =
            exact_negacyclic_product_radix(&[-1, 0], &[1, 0]).expect("centered matrix product");
        let centered_quotient = exact_modular_quotient(
            commitment
                .iter()
                .copied()
                .zip(centered_product.iter().copied()),
            modulus,
            |(commitment, product)| i128::from(commitment).checked_sub(product),
        )
        .expect("centered quotient");
        assert_eq!(&centered_quotient[..], &[1, 0]);
        assert_eq!(
            i128::from(commitment[0])
                - canonical_product[0]
                - i128::from(modulus) * centered_quotient[0],
            -17,
        );

        let negative_secret_product = exact_anchor_matrix_product(vec![16, 0], &[-1, 0])
            .expect("negative-secret matrix product");
        let negative_secret_quotient = exact_modular_quotient(
            [1_u64, 0]
                .into_iter()
                .zip(negative_secret_product.iter().copied()),
            modulus,
            |(commitment, product)| i128::from(commitment).checked_sub(product),
        )
        .expect("negative-secret quotient");
        assert_eq!(&negative_secret_product[..], &[-16, 0]);
        assert_eq!(&negative_secret_quotient[..], &[1, 0]);
    }

    #[test]
    fn public_key_quotient_uses_the_same_least_nonnegative_representative_as_the_relation() {
        let modulus = 17_u64;
        let public_key_share = [1_u64, 0];
        let least_nonnegative_product = exact_negacyclic_product_radix(&[16_i128, 0], &[1_i128, 0])
            .expect("least-nonnegative public product");
        let quotient = exact_modular_quotient(
            public_key_share
                .iter()
                .copied()
                .zip(least_nonnegative_product.iter().copied()),
            modulus,
            |(public_key_share, product)| i128::from(public_key_share).checked_add(product),
        )
        .expect("least-nonnegative public-key quotient");
        assert_eq!(&least_nonnegative_product[..], &[16, 0]);
        assert_eq!(&quotient[..], &[1, 0]);

        let centered_product = exact_negacyclic_product_radix(&[-1_i128, 0], &[1_i128, 0])
            .expect("centered public product");
        let centered_quotient = exact_modular_quotient(
            public_key_share
                .iter()
                .copied()
                .zip(centered_product.iter().copied()),
            modulus,
            |(public_key_share, product)| i128::from(public_key_share).checked_add(product),
        )
        .expect("centered public-key quotient");
        assert_eq!(&centered_quotient[..], &[0, 0]);
        assert_ne!(quotient, centered_quotient);
    }
}
