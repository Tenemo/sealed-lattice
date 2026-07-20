use std::{
    mem::size_of,
    sync::{Arc, atomic::AtomicUsize},
};

use zeroize::Zeroizing;

use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    foundation::{
        CanonicalStreamDomain, CanonicalStreamReadbackVerifier, FOUNDATION_PROFILE, Hash512,
        ProofApplicationSlotCeilings, StreamDescriptor, VerifiedCanonicalStreamSummary,
    },
    hashing::hash_framed_parts_512,
};

use super::{
    BoundTreeConstructionKind, CompiledRelationPlan, RelationColumnDescriptor,
    RelationColumnOrigin, RelationColumnValueType, RelationPlanVariant, RelationTreeDescriptor,
    SuiteModulusReference,
};
use crate::bgv::proof_suite::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofProverError, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    ProofBaseFieldElement, ProofEvaluationDomain, ProvidedCommonProofSourcePolynomial,
    RelationProofTreeInput, StatementOwnedProofTreeInput,
};

const COLLECTIVE_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/collective-public-key/source-replay-identity/v3";
const COLLECTIVE_SOURCE_DESCRIPTOR_BINDING_DOMAIN: &str =
    "sealed-lattice/collective-public-key/source-descriptor-binding/v1";
const TRACE_HALVES_PER_POLYNOMIAL: usize = 2;
const TRACE_HALF_DEGREE: usize = POLYNOMIAL_DEGREE / TRACE_HALVES_PER_POLYNOMIAL;
const TRACE_HALF_BYTE_LENGTH: usize = TRACE_HALF_DEGREE * size_of::<u64>();
const PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH: u64 =
    DATA_PRIMES.len() as u64 * POLYNOMIAL_DEGREE as u64 * size_of::<u64>() as u64;

enum CollectivePublicKeySetupPolynomialMaterial {
    Authenticated {
        carrier_binding: [u8; Hash512::BYTE_LENGTH],
        verified_summary: Box<VerifiedCanonicalStreamSummary>,
    },
    Resident {
        ordered_limb_polynomials: Box<[Arc<[u64]>]>,
    },
}

pub(crate) struct CollectivePublicKeySetupPolynomialSource {
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_root: [u8; Hash512::BYTE_LENGTH],
    material: CollectivePublicKeySetupPolynomialMaterial,
}

impl CollectivePublicKeySetupPolynomialSource {
    pub(crate) fn from_authenticated_stream(
        public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
        expected_root: [u8; Hash512::BYTE_LENGTH],
        carrier_binding: [u8; Hash512::BYTE_LENGTH],
        verified_summary: VerifiedCanonicalStreamSummary,
    ) -> Result<Self, CommonProofProverError> {
        if public_polynomial_context_hash == [0_u8; Hash512::BYTE_LENGTH]
            || expected_root == [0_u8; Hash512::BYTE_LENGTH]
            || carrier_binding == [0_u8; Hash512::BYTE_LENGTH]
            || verified_summary.stream_domain() != CanonicalStreamDomain::PublicKeyShareMaterial
            || verified_summary.total_byte_length() != PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(Self {
            public_polynomial_context_hash,
            expected_root,
            material: CollectivePublicKeySetupPolynomialMaterial::Authenticated {
                carrier_binding,
                verified_summary: Box::new(verified_summary),
            },
        })
    }

    pub(crate) fn from_resident_polynomials(
        public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
        expected_root: [u8; Hash512::BYTE_LENGTH],
        ordered_limb_polynomials: Box<[Arc<[u64]>]>,
    ) -> Result<Self, CommonProofProverError> {
        if public_polynomial_context_hash == [0_u8; Hash512::BYTE_LENGTH]
            || expected_root == [0_u8; Hash512::BYTE_LENGTH]
            || !resident_polynomials_are_canonical(&ordered_limb_polynomials)
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(Self {
            public_polynomial_context_hash,
            expected_root,
            material: CollectivePublicKeySetupPolynomialMaterial::Resident {
                ordered_limb_polynomials,
            },
        })
    }
}

struct PreparedAuthenticatedCollectiveSourceMaterial {
    carrier_binding: [u8; Hash512::BYTE_LENGTH],
    descriptor_binding: [u8; Hash512::BYTE_LENGTH],
    stream_descriptor: StreamDescriptor,
    readback: Option<CanonicalStreamReadbackVerifier>,
}

enum PreparedCollectiveSourceMaterial {
    Authenticated(Box<PreparedAuthenticatedCollectiveSourceMaterial>),
    Resident {
        ordered_limb_polynomials: Box<[Arc<[u64]>]>,
    },
}

struct PreparedCollectiveSource {
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_root: [u8; Hash512::BYTE_LENGTH],
    material: PreparedCollectiveSourceMaterial,
}

#[derive(Clone)]
struct CollectiveSourceColumn {
    column_ordinal: u32,
    source_ordinal: usize,
    limb_ordinal: usize,
    half_ordinal: usize,
    descriptor: RelationColumnDescriptor,
}

struct PendingCollectiveSourceColumn {
    source_column: CollectiveSourceColumn,
    coefficients_bytes: Zeroizing<Box<[u8]>>,
    filled_byte_length: usize,
}

struct CachedCollectiveSourceChunk {
    source_ordinal: usize,
    stream_byte_offset: u64,
    bytes: Zeroizing<Box<[u8]>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CollectivePublicKeySourceProviderMemoryAccounting {
    provider_fixed_byte_length: u64,
    input_source_catalog_byte_length: u64,
    input_authenticated_summary_payload_byte_length: u64,
    prepared_source_catalog_byte_length: u64,
    prepared_authenticated_material_payload_byte_length: u64,
    ordered_column_catalog_byte_length: u64,
    relation_tree_input_catalog_byte_length: u64,
    authenticated_descriptor_digest_payload_byte_length: u64,
    authenticated_descriptor_digest_allocation_header_byte_length: u64,
    authenticated_chunk_flag_payload_byte_length: u64,
    resident_polynomial_payload_byte_length: u64,
    resident_polynomial_allocation_header_byte_length: u64,
    resident_polynomial_reference_catalog_byte_length: u64,
    preparation_peak_resident_byte_length: u64,
    loading_persistent_resident_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_byte_length: u64,
    additional_loading_source_polynomials_transient_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
    authenticated_source_read_count: u64,
    authenticated_source_read_byte_length: u64,
}

impl CollectivePublicKeySourceProviderMemoryAccounting {
    #[cfg(test)]
    pub(crate) const fn provider_fixed_byte_length(self) -> u64 {
        self.provider_fixed_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn input_source_catalog_byte_length(self) -> u64 {
        self.input_source_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn input_authenticated_summary_payload_byte_length(self) -> u64 {
        self.input_authenticated_summary_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn prepared_source_catalog_byte_length(self) -> u64 {
        self.prepared_source_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn prepared_authenticated_material_payload_byte_length(self) -> u64 {
        self.prepared_authenticated_material_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn ordered_column_catalog_byte_length(self) -> u64 {
        self.ordered_column_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn relation_tree_input_catalog_byte_length(self) -> u64 {
        self.relation_tree_input_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn authenticated_descriptor_digest_payload_byte_length(self) -> u64 {
        self.authenticated_descriptor_digest_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn authenticated_descriptor_digest_allocation_header_byte_length(self) -> u64 {
        self.authenticated_descriptor_digest_allocation_header_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn authenticated_chunk_flag_payload_byte_length(self) -> u64 {
        self.authenticated_chunk_flag_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn resident_polynomial_payload_byte_length(self) -> u64 {
        self.resident_polynomial_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn resident_polynomial_allocation_header_byte_length(self) -> u64 {
        self.resident_polynomial_allocation_header_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn resident_polynomial_reference_catalog_byte_length(self) -> u64 {
        self.resident_polynomial_reference_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn preparation_peak_resident_byte_length(self) -> u64 {
        self.preparation_peak_resident_byte_length
    }

    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        self.post_source_polynomial_finish_persistent_resident_byte_length
    }

    pub(crate) const fn additional_loading_source_polynomials_transient_byte_length(self) -> u64 {
        self.additional_loading_source_polynomials_transient_byte_length
    }

    pub(crate) const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
        self.maximum_returned_source_polynomial_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn authenticated_source_read_count(self) -> u64 {
        self.authenticated_source_read_count
    }

    #[cfg(test)]
    pub(crate) const fn authenticated_source_read_byte_length(self) -> u64 {
        self.authenticated_source_read_byte_length
    }
}

pub(crate) fn collective_public_key_source_provider_memory_accounting(
    variant: &RelationPlanVariant,
) -> Result<CollectivePublicKeySourceProviderMemoryAccounting, CommonProofProverError> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let source_count = participant_count
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let column_count_per_source = DATA_PRIMES
        .len()
        .checked_mul(TRACE_HALVES_PER_POLYNOMIAL)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let expected_ordered_column_count = source_count
        .checked_mul(column_count_per_source)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if variant.ordered_trees().len() != source_count
        || variant.ordered_columns().len() != expected_ordered_column_count
        || variant.ordered_trees().iter().any(|tree| {
            !matches!(
                tree,
                RelationTreeDescriptor::BoundPublic {
                    construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                    ordered_column_ordinals,
                    ..
                } if ordered_column_ordinals.len() == column_count_per_source
            )
        })
    {
        return Err(CommonProofProverError::InvalidTree);
    }

    let count_bytes = |count: usize, item_byte_length: usize| {
        u64::try_from(count)
            .ok()
            .and_then(|count| {
                u64::try_from(item_byte_length)
                    .ok()
                    .and_then(|item_byte_length| count.checked_mul(item_byte_length))
            })
            .ok_or(CommonProofProverError::CountOverflow)
    };
    let add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or(CommonProofProverError::CountOverflow)
    };
    let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
    let authenticated_chunk_count_per_source = usize::try_from(PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH)
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .div_ceil(chunk_byte_length);
    let authenticated_source_read_count = participant_count
        .checked_mul(authenticated_chunk_count_per_source)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(CommonProofProverError::CountOverflow)?;
    let authenticated_source_read_byte_length = u64::try_from(participant_count)
        .ok()
        .and_then(|count| count.checked_mul(PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let provider_fixed_byte_length =
        count_bytes(1, size_of::<CollectivePublicKeySourcePolynomialProvider>())?;
    let input_source_catalog_byte_length = count_bytes(
        source_count,
        size_of::<CollectivePublicKeySetupPolynomialSource>(),
    )?;
    let input_authenticated_summary_payload_byte_length = count_bytes(
        participant_count,
        size_of::<VerifiedCanonicalStreamSummary>(),
    )?;
    let prepared_source_catalog_byte_length =
        count_bytes(source_count, size_of::<PreparedCollectiveSource>())?;
    let prepared_authenticated_material_payload_byte_length = count_bytes(
        participant_count,
        size_of::<PreparedAuthenticatedCollectiveSourceMaterial>(),
    )?;
    let ordered_column_catalog_byte_length = count_bytes(
        expected_ordered_column_count,
        size_of::<CollectiveSourceColumn>(),
    )?;
    let relation_tree_input_catalog_byte_length =
        count_bytes(source_count, size_of::<RelationProofTreeInput>())?;
    let authenticated_descriptor_digest_payload_byte_length = count_bytes(
        participant_count
            .checked_mul(authenticated_chunk_count_per_source)
            .ok_or(CommonProofProverError::CountOverflow)?,
        size_of::<Hash512>(),
    )?;
    let arc_allocation_header_byte_length = size_of::<AtomicUsize>()
        .checked_mul(2)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let authenticated_descriptor_digest_allocation_header_byte_length =
        count_bytes(participant_count, arc_allocation_header_byte_length)?;
    let authenticated_chunk_flag_payload_byte_length = count_bytes(
        participant_count
            .checked_mul(authenticated_chunk_count_per_source)
            .ok_or(CommonProofProverError::CountOverflow)?,
        size_of::<bool>(),
    )?;
    let resident_polynomial_payload_byte_length = PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH;
    let resident_polynomial_allocation_header_byte_length =
        count_bytes(DATA_PRIMES.len(), arc_allocation_header_byte_length)?;
    let resident_polynomial_reference_catalog_byte_length =
        count_bytes(DATA_PRIMES.len(), size_of::<Arc<[u64]>>())?;

    let loading_persistent_resident_byte_length = [
        provider_fixed_byte_length,
        prepared_source_catalog_byte_length,
        prepared_authenticated_material_payload_byte_length,
        ordered_column_catalog_byte_length,
        authenticated_descriptor_digest_payload_byte_length,
        authenticated_descriptor_digest_allocation_header_byte_length,
        authenticated_chunk_flag_payload_byte_length,
        resident_polynomial_payload_byte_length,
        resident_polynomial_allocation_header_byte_length,
        resident_polynomial_reference_catalog_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, add)?;
    let post_source_polynomial_finish_persistent_resident_byte_length = provider_fixed_byte_length;
    let preparation_input_source_byte_length = add(
        input_source_catalog_byte_length,
        input_authenticated_summary_payload_byte_length,
    )?;
    let preparation_peak_resident_byte_length = loading_persistent_resident_byte_length
        .checked_sub(provider_fixed_byte_length)
        .and_then(|length| length.checked_add(relation_tree_input_catalog_byte_length))
        .and_then(|length| {
            length.checked_add(provider_fixed_byte_length.max(preparation_input_source_byte_length))
        })
        .ok_or(CommonProofProverError::CountOverflow)?;
    let additional_loading_source_polynomials_transient_byte_length =
        count_bytes(1, TRACE_HALF_BYTE_LENGTH)?
            .checked_add(
                u64::try_from(chunk_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
    let maximum_returned_source_polynomial_byte_length =
        count_bytes(TRACE_HALF_DEGREE, size_of::<ProofBaseFieldElement>())?;

    Ok(CollectivePublicKeySourceProviderMemoryAccounting {
        provider_fixed_byte_length,
        input_source_catalog_byte_length,
        input_authenticated_summary_payload_byte_length,
        prepared_source_catalog_byte_length,
        prepared_authenticated_material_payload_byte_length,
        ordered_column_catalog_byte_length,
        relation_tree_input_catalog_byte_length,
        authenticated_descriptor_digest_payload_byte_length,
        authenticated_descriptor_digest_allocation_header_byte_length,
        authenticated_chunk_flag_payload_byte_length,
        resident_polynomial_payload_byte_length,
        resident_polynomial_allocation_header_byte_length,
        resident_polynomial_reference_catalog_byte_length,
        preparation_peak_resident_byte_length,
        loading_persistent_resident_byte_length,
        post_source_polynomial_finish_persistent_resident_byte_length,
        additional_loading_source_polynomials_transient_byte_length,
        maximum_returned_source_polynomial_byte_length,
        authenticated_source_read_count,
        authenticated_source_read_byte_length,
    })
}

/// Exact ordered provider for the selected collective-public-key relation.
/// Participant bodies remain in authenticated browser storage; the provider
/// retains the aggregate plus one trace half and one authenticated chunk.
pub(crate) struct CollectivePublicKeySourcePolynomialProvider {
    expected_request_context: CommonProofSourcePolynomialRequestContext,
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    sources: Option<Box<[PreparedCollectiveSource]>>,
    ordered_columns: Option<Box<[CollectiveSourceColumn]>>,
    next_column_position: usize,
    pending_column: Option<PendingCollectiveSourceColumn>,
    cached_chunk: Option<CachedCollectiveSourceChunk>,
    loading_persistent_resident_memory_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_memory_byte_length: u64,
    loading_transient_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
    finished: bool,
}

impl CollectivePublicKeySourcePolynomialProvider {
    pub(crate) fn prepare(
        relation_plan: &CompiledRelationPlan,
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        application_statement_hash: [u8; Hash512::BYTE_LENGTH],
        source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
        sources: Vec<CollectivePublicKeySetupPolynomialSource>,
    ) -> Result<(Vec<RelationProofTreeInput>, Self), CommonProofProverError> {
        let schema_identifier = ProofApplicationSlotCeilings::
            COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
        let variant = relation_plan.select_variant(None, None)?.clone();
        let participant_count =
            usize::from(crate::foundation::FOUNDATION_PROFILE.participant_count);
        if relation_plan.application_statement_schema_identifier() != schema_identifier
            || variant.schedule_position().is_some()
            || variant.top_count().is_some()
            || source_catalog_binding == [0_u8; Hash512::BYTE_LENGTH]
            || sources.len() != variant.ordered_trees().len()
            || sources.len() != participant_count + 1
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let memory_accounting = collective_public_key_source_provider_memory_accounting(&variant)?;
        let expected_request_context = CommonProofSourcePolynomialRequestContext::new(
            protocol_version,
            suite_identifier,
            schema_identifier,
            application_statement_hash,
            relation_plan.canonical_hash()?,
            variant.canonical_hash()?,
            None,
            None,
        );
        let mut relation_trees = Vec::new();
        relation_trees
            .try_reserve_exact(sources.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut ordered_columns = Vec::new();
        ordered_columns
            .try_reserve_exact(variant.ordered_columns().len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut prepared_sources = Vec::new();
        prepared_sources
            .try_reserve_exact(sources.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let expected_column_count = DATA_PRIMES
            .len()
            .checked_mul(TRACE_HALVES_PER_POLYNOMIAL)
            .ok_or(CommonProofProverError::CountOverflow)?;
        for (source_ordinal, (tree, source)) in
            variant.ordered_trees().iter().zip(sources).enumerate()
        {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } = tree
            else {
                return Err(CommonProofProverError::InvalidTree);
            };
            if ordered_column_ordinals.len() != expected_column_count {
                return Err(CommonProofProverError::InvalidColumn);
            }
            let prepared_material = match source.material {
                CollectivePublicKeySetupPolynomialMaterial::Authenticated {
                    carrier_binding,
                    verified_summary,
                } if source_ordinal < participant_count => {
                    let stream_descriptor = verified_summary.stream_descriptor().clone();
                    let descriptor_binding = hash_framed_parts_512(
                        COLLECTIVE_SOURCE_DESCRIPTOR_BINDING_DOMAIN,
                        &[
                            &source.public_polynomial_context_hash,
                            &source.expected_root,
                            &carrier_binding,
                            &stream_descriptor.total_byte_length.to_le_bytes(),
                            stream_descriptor.full_object_digest.as_bytes(),
                        ],
                    );
                    PreparedCollectiveSourceMaterial::Authenticated(Box::new(
                        PreparedAuthenticatedCollectiveSourceMaterial {
                            carrier_binding,
                            descriptor_binding,
                            stream_descriptor,
                            readback: Some(
                                CanonicalStreamReadbackVerifier::new(
                                    CanonicalStreamDomain::PublicKeyShareMaterial,
                                    *verified_summary,
                                )
                                .map_err(|_| CommonProofProverError::InvalidInput)?,
                            ),
                        },
                    ))
                }
                CollectivePublicKeySetupPolynomialMaterial::Resident {
                    ordered_limb_polynomials,
                } if source_ordinal == participant_count
                    && resident_polynomials_are_canonical(&ordered_limb_polynomials) =>
                {
                    PreparedCollectiveSourceMaterial::Resident {
                        ordered_limb_polynomials,
                    }
                }
                _ => return Err(CommonProofProverError::InvalidInput),
            };
            relation_trees.push(RelationProofTreeInput::BoundPublic(
                StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash: source.public_polynomial_context_hash,
                    row_width: u32::try_from(expected_column_count)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    expected_root: source.expected_root,
                },
            ));
            for (physical_column_ordinal, column_ordinal) in
                ordered_column_ordinals.iter().copied().enumerate()
            {
                let limb_ordinal = physical_column_ordinal / TRACE_HALVES_PER_POLYNOMIAL;
                let half_ordinal = physical_column_ordinal % TRACE_HALVES_PER_POLYNOMIAL;
                let descriptor = variant
                    .ordered_columns()
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .cloned()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let expected_modulus_reference = SuiteModulusReference::data(
                    u16::try_from(limb_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                );
                if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. })
                    || descriptor.value_type() != RelationColumnValueType::BaseField
                    || descriptor.source_degree_bound_exclusive()
                        != u64::try_from(TRACE_HALF_DEGREE)
                            .map_err(|_| CommonProofProverError::CountOverflow)?
                    || descriptor.canonical_residue_modulus() != Some(expected_modulus_reference)
                    || ordered_columns
                        .last()
                        .is_some_and(|prior: &CollectiveSourceColumn| {
                            prior.column_ordinal >= column_ordinal
                        })
                {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                ordered_columns.push(CollectiveSourceColumn {
                    column_ordinal,
                    source_ordinal,
                    limb_ordinal,
                    half_ordinal,
                    descriptor,
                });
            }
            prepared_sources.push(PreparedCollectiveSource {
                public_polynomial_context_hash: source.public_polynomial_context_hash,
                expected_root: source.expected_root,
                material: prepared_material,
            });
        }
        if ordered_columns.len() != variant.ordered_columns().len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok((
            relation_trees,
            Self {
                expected_request_context,
                source_catalog_binding,
                sources: Some(prepared_sources.into_boxed_slice()),
                ordered_columns: Some(ordered_columns.into_boxed_slice()),
                next_column_position: 0,
                pending_column: None,
                cached_chunk: None,
                loading_persistent_resident_memory_byte_length: memory_accounting
                    .loading_persistent_resident_byte_length(),
                post_source_polynomial_finish_persistent_resident_memory_byte_length:
                    memory_accounting
                        .post_source_polynomial_finish_persistent_resident_byte_length(),
                loading_transient_byte_length: memory_accounting
                    .additional_loading_source_polynomials_transient_byte_length(),
                maximum_returned_source_polynomial_byte_length: memory_accounting
                    .maximum_returned_source_polynomial_byte_length(),
                finished: false,
            },
        ))
    }

    fn expected_column(&self) -> Result<CollectiveSourceColumn, CommonProofProverError> {
        self.ordered_columns
            .as_ref()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .get(self.next_column_position)
            .cloned()
            .ok_or(CommonProofProverError::InvalidColumn)
    }

    fn next_read_request(
        &self,
    ) -> Result<CommonProofAuthenticatedSourceReadRequest, CommonProofProverError> {
        let pending = self
            .pending_column
            .as_ref()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let source = self
            .sources
            .as_ref()
            .and_then(|sources| sources.get(pending.source_column.source_ordinal))
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let PreparedCollectiveSourceMaterial::Authenticated(authenticated_material) =
            &source.material
        else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        let column_byte_offset = source_column_byte_offset(&pending.source_column)?;
        let next_column_byte_offset = column_byte_offset
            .checked_add(
                u64::try_from(pending.filled_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let chunk_index = next_column_byte_offset / chunk_byte_length;
        let stream_byte_offset = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let requested_byte_length = authenticated_material
            .stream_descriptor
            .total_byte_length
            .checked_sub(stream_byte_offset)
            .map(|remaining| remaining.min(chunk_byte_length))
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(CommonProofProverError::CountOverflow)?;
        CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
            self.expected_request_context.request(
                pending.source_column.column_ordinal,
                &pending.source_column.descriptor,
            ),
            self.source_catalog_binding,
            authenticated_material.descriptor_binding,
            authenticated_material.carrier_binding,
            authenticated_material
                .stream_descriptor
                .full_object_digest
                .into_bytes(),
            authenticated_material.stream_descriptor.total_byte_length,
            stream_byte_offset,
            stream_byte_offset,
            requested_byte_length,
            u32::try_from(chunk_index).map_err(|_| CommonProofProverError::CountOverflow)?,
        )
    }

    fn absorb_cached_chunk(&mut self) -> Result<(), CommonProofProverError> {
        let Some(cache) = self.cached_chunk.as_ref() else {
            return Ok(());
        };
        let pending = self
            .pending_column
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if cache.source_ordinal != pending.source_column.source_ordinal {
            return Ok(());
        }
        let column_byte_offset = source_column_byte_offset(&pending.source_column)?;
        let next_byte_offset = column_byte_offset
            .checked_add(
                u64::try_from(pending.filled_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let cache_end = cache
            .stream_byte_offset
            .checked_add(
                u64::try_from(cache.bytes.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if next_byte_offset < cache.stream_byte_offset || next_byte_offset >= cache_end {
            return Ok(());
        }
        let column_end = column_byte_offset
            .checked_add(
                u64::try_from(TRACE_HALF_BYTE_LENGTH)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let copy_end = column_end.min(cache_end);
        let cache_start = usize::try_from(next_byte_offset - cache.stream_byte_offset)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let cache_copy_end = usize::try_from(copy_end - cache.stream_byte_offset)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let copied_byte_length = cache_copy_end
            .checked_sub(cache_start)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let filled_end = pending
            .filled_byte_length
            .checked_add(copied_byte_length)
            .filter(|end| *end <= pending.coefficients_bytes.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        pending.coefficients_bytes[pending.filled_byte_length..filled_end]
            .copy_from_slice(&cache.bytes[cache_start..cache_copy_end]);
        pending.filled_byte_length = filled_end;
        Ok(())
    }

    fn finish_pending_column(
        &mut self,
    ) -> Result<ProvidedCommonProofSourcePolynomial, CommonProofProverError> {
        let pending = self
            .pending_column
            .take()
            .filter(|pending| pending.filled_byte_length == TRACE_HALF_BYTE_LENGTH)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let source = self
            .sources
            .as_ref()
            .and_then(|sources| sources.get(pending.source_column.source_ordinal))
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let modulus = *DATA_PRIMES
            .get(pending.source_column.limb_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let mut trace_values = Vec::new();
        trace_values
            .try_reserve_exact(TRACE_HALF_DEGREE)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        for coefficient_bytes in pending.coefficients_bytes.chunks_exact(size_of::<u64>()) {
            let coefficient = u64::from_le_bytes(
                coefficient_bytes
                    .try_into()
                    .map_err(|_| CommonProofProverError::InvalidColumn)?,
            );
            if coefficient >= modulus {
                return Err(CommonProofProverError::InvalidColumn);
            }
            trace_values.push(ProofBaseFieldElement::from_canonical(coefficient)?);
        }
        ProofEvaluationDomain::new_subgroup(TRACE_HALF_DEGREE)?
            .interpolate_base_polynomial_in_place(&mut trace_values)?;
        let replay_identity = self.replay_identity(&pending.source_column, source)?;
        self.next_column_position = self
            .next_column_position
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(ProvidedCommonProofSourcePolynomial::new(
            CommonProofSourcePolynomial::from_base_coefficients(trace_values),
            replay_identity,
        ))
    }

    fn resident_column(
        &mut self,
        column: &CollectiveSourceColumn,
    ) -> Result<ProvidedCommonProofSourcePolynomial, CommonProofProverError> {
        let source = self
            .sources
            .as_ref()
            .and_then(|sources| sources.get(column.source_ordinal))
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let PreparedCollectiveSourceMaterial::Resident {
            ordered_limb_polynomials,
        } = &source.material
        else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        let start = column
            .half_ordinal
            .checked_mul(TRACE_HALF_DEGREE)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let end = start
            .checked_add(TRACE_HALF_DEGREE)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let mut trace_values = ordered_limb_polynomials
            .get(column.limb_ordinal)
            .and_then(|polynomial| polynomial.get(start..end))
            .ok_or(CommonProofProverError::InvalidColumn)?
            .iter()
            .copied()
            .map(ProofBaseFieldElement::from_canonical)
            .collect::<Result<Vec<_>, _>>()?;
        ProofEvaluationDomain::new_subgroup(TRACE_HALF_DEGREE)?
            .interpolate_base_polynomial_in_place(&mut trace_values)?;
        let replay_identity = self.replay_identity(column, source)?;
        self.next_column_position = self
            .next_column_position
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(ProvidedCommonProofSourcePolynomial::new(
            CommonProofSourcePolynomial::from_base_coefficients(trace_values),
            replay_identity,
        ))
    }

    fn replay_identity(
        &self,
        column: &CollectiveSourceColumn,
        source: &PreparedCollectiveSource,
    ) -> Result<CommonProofSourcePolynomialReplayIdentity, CommonProofProverError> {
        let material_binding = match &source.material {
            PreparedCollectiveSourceMaterial::Authenticated(authenticated_material) => {
                authenticated_material.descriptor_binding
            }
            PreparedCollectiveSourceMaterial::Resident { .. } => hash_framed_parts_512(
                COLLECTIVE_SOURCE_DESCRIPTOR_BINDING_DOMAIN,
                &[
                    &source.public_polynomial_context_hash,
                    &source.expected_root,
                    b"resident-collective-aggregate",
                ],
            ),
        };
        CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(hash_framed_parts_512(
            COLLECTIVE_SOURCE_REPLAY_IDENTITY_DOMAIN,
            &[
                &self
                    .expected_request_context
                    .stable_generation_binding_hash(),
                &self.source_catalog_binding,
                &column.column_ordinal.to_le_bytes(),
                &u64::try_from(column.source_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
                &u64::try_from(column.limb_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
                &u64::try_from(column.half_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
                &source.public_polynomial_context_hash,
                &source.expected_root,
                &material_binding,
            ],
        ))
    }
}

impl CommonProofSourcePolynomialProvider for CollectivePublicKeySourcePolynomialProvider {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        Ok(CommonProofSourceProviderMemoryAccounting::new(
            self.loading_persistent_resident_memory_byte_length,
            self.post_source_polynomial_finish_persistent_resident_memory_byte_length,
            self.loading_transient_byte_length,
            self.maximum_returned_source_polynomial_byte_length,
        ))
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.finished {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let expected = self.expected_column()?;
        if request.request_context() != self.expected_request_context
            || request.column_ordinal() != expected.column_ordinal
            || request.descriptor() != &expected.descriptor
            || self.pending_column.as_ref().is_some_and(|pending| {
                pending.source_column.column_ordinal != expected.column_ordinal
            })
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_is_resident = matches!(
            self.sources
                .as_ref()
                .and_then(|sources| sources.get(expected.source_ordinal))
                .map(|source| &source.material),
            Some(PreparedCollectiveSourceMaterial::Resident { .. })
        );
        if source_is_resident {
            return self
                .resident_column(&expected)
                .map(CommonProofSourcePolynomialProviderPoll::Ready);
        }
        if self.pending_column.is_none() {
            self.pending_column = Some(PendingCollectiveSourceColumn {
                source_column: expected,
                coefficients_bytes: Zeroizing::new(
                    vec![0_u8; TRACE_HALF_BYTE_LENGTH].into_boxed_slice(),
                ),
                filled_byte_length: 0,
            });
        }
        self.absorb_cached_chunk()?;
        if self
            .pending_column
            .as_ref()
            .is_some_and(|pending| pending.filled_byte_length == TRACE_HALF_BYTE_LENGTH)
        {
            return self
                .finish_pending_column()
                .map(CommonProofSourcePolynomialProviderPoll::Ready);
        }
        self.next_read_request()?;
        self.cached_chunk = None;
        Ok(CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired)
    }

    fn pending_authenticated_source_read_request(
        &self,
    ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError> {
        self.next_read_request().map(Some)
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        if request != self.next_read_request()?
            || authenticated_bytes.len()
                != usize::try_from(request.source_byte_length())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_ordinal = self
            .pending_column
            .as_ref()
            .map(|pending| pending.source_column.source_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let source = self
            .sources
            .as_mut()
            .and_then(|sources| sources.get_mut(source_ordinal))
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let PreparedCollectiveSourceMaterial::Authenticated(authenticated_material) =
            &mut source.material
        else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        authenticated_material
            .readback
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .authenticate_chunk(
                usize::try_from(request.authentication_chunk_index())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                &authenticated_bytes,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        self.cached_chunk = Some(CachedCollectiveSourceChunk {
            source_ordinal,
            stream_byte_offset: request.source_stream_byte_offset(),
            bytes: authenticated_bytes,
        });
        Ok(())
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.pending_column = None;
        self.cached_chunk = None;
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        let ordered_column_count = self
            .ordered_columns
            .as_ref()
            .map(|columns| columns.len())
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.finished
            || self.next_column_position != ordered_column_count
            || self.pending_column.is_some()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.ordered_columns = None;
        let sources = self
            .sources
            .take()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        self.cached_chunk = None;
        for source in sources {
            if let PreparedCollectiveSourceMaterial::Authenticated(authenticated_material) =
                source.material
            {
                authenticated_material
                    .readback
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .finish()
                    .into_result()
                    .map_err(|_| CommonProofProverError::InvalidColumn)?;
            }
        }
        self.finished = true;
        Ok(())
    }
}

fn resident_polynomials_are_canonical(polynomials: &[Arc<[u64]>]) -> bool {
    polynomials.len() == DATA_PRIMES.len()
        && polynomials
            .iter()
            .zip(DATA_PRIMES)
            .all(|(polynomial, modulus)| {
                polynomial.len() == POLYNOMIAL_DEGREE
                    && polynomial.iter().all(|coefficient| *coefficient < modulus)
            })
}

fn source_column_byte_offset(
    column: &CollectiveSourceColumn,
) -> Result<u64, CommonProofProverError> {
    let coefficient_offset = column
        .limb_ordinal
        .checked_mul(POLYNOMIAL_DEGREE)
        .and_then(|offset| {
            column
                .half_ordinal
                .checked_mul(TRACE_HALF_DEGREE)
                .and_then(|half_offset| offset.checked_add(half_offset))
        })
        .ok_or(CommonProofProverError::CountOverflow)?;
    u64::try_from(coefficient_offset)
        .ok()
        .and_then(|offset| offset.checked_mul(size_of::<u64>() as u64))
        .ok_or(CommonProofProverError::CountOverflow)
}
