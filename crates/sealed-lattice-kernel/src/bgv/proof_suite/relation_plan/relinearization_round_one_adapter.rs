use std::{collections::BTreeSet, mem::size_of};

use zeroize::Zeroizing;

use crate::{
    bgv::{
        parameters::PLAINTEXT_MODULUS,
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, SetupGeneratedKeySwitchComponent,
            SetupGenerationAnchorOpening, SetupGenerationAuthorityHandle,
            SetupGenerationRelinearizationRoundOneApplication,
            SetupGenerationRelinearizationRoundOneSource,
            SetupGenerationRelinearizationRoundTwoSource,
            sample_relinearization_common_reference_limb, setup_commitment_matrix_polynomial,
            setup_generation_retained_memory_accounting,
            with_setup_generation_relinearization_round_one,
        },
    },
    foundation::{
        Hash512, PreparedActionProofAttemptSource, ProofApplicationSlotCeilings, RefusalReason,
    },
    hashing::hash_framed_parts_512,
    transcript_core::encode_hex,
};

use super::super::{
    CommonProofProverError, CommonProofRelationPlanCapability, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    ProofBaseFieldElement, ProofEvaluationDomain, ProofLeafVisibility, ProofTreeRole,
    ProvidedCommonProofSourcePolynomial, RelationProofTreeInput, StatementOwnedProofTreeInput,
};
use super::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor, RelationVerifierSource, SuiteModulusReference,
    galois_key_share_adapter::{
        anchor_full_row, centered_residue, exact_modular_quotient, exact_negacyclic_product_radix,
        half_position, requested_source_column_ordinals, signed_integer_to_base_field,
        split_balanced_quotient, split_rows_match, split_signed_i8_polynomial,
    },
    key_relation::{
        ExactRadixDigitColumnCatalog, RecenteredVerifierVectorWitness,
        ReversibleShiftedSmallVector, SplitIntegerVector,
    },
    setup_key_relation_adapter::{
        ExactKeyRelationActiveColumnSet, ExactKeyRelationDerivedRowCache,
        KeyRelationColumnDerivation, checked_setup_provider_add, checked_setup_provider_multiply,
        exact_radix_catalog_heap_byte_length,
        setup_key_relation_derivation_transient_byte_length_with_dependencies,
        setup_provider_payload_for_count,
    },
    trustee_evaluation_key::{
        GaloisKeyShareAnchorSourceLayout, RelinearizationRoundOneErrorSourceLayout,
        RelinearizationRoundOneQuotientSourceLayout, RelinearizationRoundOneSourceLayout,
        RelinearizationRoundTwoSourceLayout, TrusteeEvaluationKeyDecompositionBlock,
        TrusteeEvaluationKeyRelationGeometry,
    },
};

const RELINEARIZATION_ROUND_ONE_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/relinearization-round-one/source-replay-identity/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CachedQuotientKey {
    RoundOneLeft {
        row_ordinal: usize,
    },
    RoundOneRight {
        row_ordinal: usize,
    },
    RoundTwo {
        row_ordinal: usize,
    },
    Anchor {
        anchor_ordinal: usize,
        row_ordinal: usize,
    },
}

pub(super) struct CachedQuotient {
    pub(super) key: CachedQuotientKey,
    pub(super) coefficients: Zeroizing<Vec<i128>>,
}

pub(super) trait RelinearizationRoundOneWitnessSource {
    fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn schedule_position(&self) -> u32;

    fn common_secret_coefficients(&self) -> &[i8];

    fn ephemeral_secret_coefficients(&self) -> &[i8];

    fn round_one_left_component(&self) -> &SetupGeneratedKeySwitchComponent;

    fn round_one_right_component(&self) -> &SetupGeneratedKeySwitchComponent;

    fn round_one_left_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>];

    fn round_one_right_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>];

    fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening];
}

impl RelinearizationRoundOneWitnessSource for SetupGenerationRelinearizationRoundOneSource<'_, '_> {
    fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed()
    }

    fn schedule_position(&self) -> u32 {
        self.schedule_position()
    }

    fn common_secret_coefficients(&self) -> &[i8] {
        self.common_secret_coefficients()
    }

    fn ephemeral_secret_coefficients(&self) -> &[i8] {
        self.ephemeral_secret_coefficients()
    }

    fn round_one_left_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.round_one_left_component()
    }

    fn round_one_right_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.round_one_right_component()
    }

    fn round_one_left_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.round_one_left_errors_by_block()
    }

    fn round_one_right_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.round_one_right_errors_by_block()
    }

    fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening] {
        self.anchor_openings()
    }
}

impl RelinearizationRoundOneWitnessSource for SetupGenerationRelinearizationRoundTwoSource<'_, '_> {
    fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed()
    }

    fn schedule_position(&self) -> u32 {
        self.schedule_position()
    }

    fn common_secret_coefficients(&self) -> &[i8] {
        self.common_secret_coefficients()
    }

    fn ephemeral_secret_coefficients(&self) -> &[i8] {
        self.ephemeral_secret_coefficients()
    }

    fn round_one_left_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.round_one_left_component()
    }

    fn round_one_right_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.round_one_right_component()
    }

    fn round_one_left_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.round_one_left_errors_by_block()
    }

    fn round_one_right_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.round_one_right_errors_by_block()
    }

    fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening] {
        self.anchor_openings()
    }
}

#[derive(Clone, Copy)]
pub(super) struct RelinearizationRoundOneSourceLayoutView<'layout> {
    pub(super) common_secret: &'layout ReversibleShiftedSmallVector,
    pub(super) ephemeral_secret: &'layout ReversibleShiftedSmallVector,
    pub(super) round_one_left_rows: &'layout [SplitIntegerVector],
    pub(super) round_one_right_rows: &'layout [SplitIntegerVector],
    pub(super) errors_by_block: &'layout [RelinearizationRoundOneErrorSourceLayout],
    pub(super) quotients_by_row: &'layout [RelinearizationRoundOneQuotientSourceLayout],
    pub(super) ordered_anchors: &'layout [GaloisKeyShareAnchorSourceLayout],
    pub(super) exact_radix_digits_by_column: &'layout ExactRadixDigitColumnCatalog,
}

impl<'layout> RelinearizationRoundOneSourceLayoutView<'layout> {
    pub(super) fn from_round_one(
        source_layout: &'layout RelinearizationRoundOneSourceLayout,
    ) -> Self {
        Self {
            common_secret: &source_layout.common_secret,
            ephemeral_secret: &source_layout.ephemeral_secret,
            round_one_left_rows: &source_layout.round_one_left_rows,
            round_one_right_rows: &source_layout.round_one_right_rows,
            errors_by_block: &source_layout.errors_by_block,
            quotients_by_row: &source_layout.quotients_by_row,
            ordered_anchors: &source_layout.ordered_anchors,
            exact_radix_digits_by_column: &source_layout.exact_radix_digits_by_column,
        }
    }

    pub(super) fn from_round_two(
        source_layout: &'layout RelinearizationRoundTwoSourceLayout,
    ) -> Self {
        Self {
            common_secret: &source_layout.common_secret,
            ephemeral_secret: &source_layout.ephemeral_secret,
            round_one_left_rows: &source_layout.round_one_left_rows,
            round_one_right_rows: &source_layout.round_one_right_rows,
            errors_by_block: &source_layout.round_one_errors_by_block,
            quotients_by_row: &source_layout.round_one_quotients_by_row,
            ordered_anchors: &source_layout.ordered_anchors,
            exact_radix_digits_by_column: &source_layout.exact_radix_digits_by_column,
        }
    }
}

fn retained_vector_capacity_byte_length<Value>(
    values: &Vec<Value>,
) -> Result<u64, CommonProofProverError> {
    checked_setup_provider_multiply(
        u64::try_from(values.capacity()).map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<Value>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )
}

fn relinearization_geometry_heap_byte_length(
    geometry: &TrusteeEvaluationKeyRelationGeometry,
) -> Result<u64, CommonProofProverError> {
    let decomposition_index_payload_byte_length =
        geometry
            .decomposition_blocks
            .iter()
            .try_fold(0_u64, |total, block| {
                checked_setup_provider_add(
                    total,
                    retained_vector_capacity_byte_length(&block.data_modulus_indices)?,
                )
            })?;
    [
        retained_vector_capacity_byte_length(&geometry.data_moduli)?,
        retained_vector_capacity_byte_length(&geometry.special_moduli)?,
        retained_vector_capacity_byte_length::<TrusteeEvaluationKeyDecompositionBlock>(
            &geometry.decomposition_blocks,
        )?,
        decomposition_index_payload_byte_length,
        retained_vector_capacity_byte_length(&geometry.commitment_data_modulus_indices)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)
}

fn relinearization_round_one_source_layout_heap_byte_length(
    source_layout: RelinearizationRoundOneSourceLayoutView<'_>,
) -> Result<u64, CommonProofProverError> {
    let anchor_nested_payload_byte_length =
        source_layout
            .ordered_anchors
            .iter()
            .try_fold(0_u64, |total, anchor| {
                let first_matrix_rows =
                    anchor
                        .first_matrix
                        .iter()
                        .try_fold(0_u64, |row_total, row| {
                            checked_setup_provider_add(
                                row_total,
                                setup_provider_payload_for_count::<RecenteredVerifierVectorWitness>(
                                    row.len(),
                                )?,
                            )
                        })?;
                let anchor_payload_byte_length = [
                    retained_vector_capacity_byte_length(&anchor.opening.hiding_secrets)?,
                    retained_vector_capacity_byte_length(&anchor.opening.hiding_errors)?,
                    setup_provider_payload_for_count::<SplitIntegerVector>(
                        anchor.commitments.len(),
                    )?,
                    setup_provider_payload_for_count::<Box<[RecenteredVerifierVectorWitness]>>(
                        anchor.first_matrix.len(),
                    )?,
                    first_matrix_rows,
                    setup_provider_payload_for_count::<RecenteredVerifierVectorWitness>(
                        anchor.second_matrix.len(),
                    )?,
                    setup_provider_payload_for_count::<
                        super::key_relation::TrusteeRadixThreeQuotientWitness,
                    >(anchor.quotients.len())?,
                ]
                .into_iter()
                .try_fold(0_u64, checked_setup_provider_add)?;
                checked_setup_provider_add(total, anchor_payload_byte_length)
            })?;
    [
        setup_provider_payload_for_count::<SplitIntegerVector>(
            source_layout.round_one_left_rows.len(),
        )?,
        setup_provider_payload_for_count::<SplitIntegerVector>(
            source_layout.round_one_right_rows.len(),
        )?,
        setup_provider_payload_for_count::<RelinearizationRoundOneErrorSourceLayout>(
            source_layout.errors_by_block.len(),
        )?,
        setup_provider_payload_for_count::<RelinearizationRoundOneQuotientSourceLayout>(
            source_layout.quotients_by_row.len(),
        )?,
        setup_provider_payload_for_count::<GaloisKeyShareAnchorSourceLayout>(
            source_layout.ordered_anchors.len(),
        )?,
        anchor_nested_payload_byte_length,
        exact_radix_catalog_heap_byte_length(source_layout.exact_radix_digits_by_column)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)
}

fn relinearization_round_one_additional_dependencies(
    source_layout: RelinearizationRoundOneSourceLayoutView<'_>,
) -> Vec<(u32, u32)> {
    source_layout
        .ordered_anchors
        .iter()
        .flat_map(|anchor| {
            anchor
                .first_matrix
                .iter()
                .flat_map(|row| row.iter())
                .chain(anchor.second_matrix.iter())
        })
        .flat_map(|matrix| {
            (0..2).flat_map(|half_ordinal| {
                [
                    (
                        matrix.centered.source.coefficients.halves[half_ordinal],
                        matrix.canonical.halves[half_ordinal],
                    ),
                    (
                        matrix.carry_columns[half_ordinal],
                        matrix.canonical.halves[half_ordinal],
                    ),
                ]
            })
        })
        .collect()
}

pub(crate) fn relinearization_round_one_source_provider_memory_accounting(
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    source_layout: &RelinearizationRoundOneSourceLayout,
    canonical_application_statement_byte_length: usize,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    if canonical_application_statement_byte_length == 0
        || relation_plan_variant.trace_domain_size().checked_mul(2) != Some(geometry.ring_degree)
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let source_layout_view = RelinearizationRoundOneSourceLayoutView::from_round_one(source_layout);
    let round_one_quotient_columns = source_layout_view
        .quotients_by_row
        .iter()
        .flat_map(|quotient| {
            quotient
                .left
                .low_quotients
                .into_iter()
                .chain(quotient.left.high_carries)
                .chain(quotient.right.low_quotients)
                .chain(quotient.right.high_carries)
        })
        .collect::<BTreeSet<_>>();
    let anchor_quotient_columns = source_layout_view
        .ordered_anchors
        .iter()
        .flat_map(|anchor| {
            anchor.quotients.iter().flat_map(|quotient| {
                quotient
                    .low_quotients
                    .into_iter()
                    .chain(quotient.high_carries)
            })
        })
        .collect::<BTreeSet<_>>();
    let additional_dependencies =
        relinearization_round_one_additional_dependencies(source_layout_view);
    let requested_column_count = requested_source_column_ordinals(relation_plan_variant)?.len();
    let adapter_retained_byte_length = [
        u64::try_from(size_of::<RelinearizationRoundOneSourcePolynomialAdapter>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(canonical_application_statement_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        relation_plan_variant
            .resident_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        relation_context
            .resident_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        relinearization_geometry_heap_byte_length(geometry)?,
        relinearization_round_one_source_layout_heap_byte_length(source_layout_view)?,
        setup_provider_payload_for_count::<u32>(requested_column_count)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_setup_provider_add)?;
    let cached_quotient_byte_length = checked_setup_provider_multiply(
        geometry.ring_degree,
        u64::try_from(size_of::<i128>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let derivation_workspace_byte_length =
        setup_key_relation_derivation_transient_byte_length_with_dependencies(
            relation_plan_variant,
            source_layout_view.exact_radix_digits_by_column,
            &round_one_quotient_columns,
            &anchor_quotient_columns,
            geometry.ring_degree,
            &additional_dependencies,
        )?;
    let maximum_returned_source_polynomial_byte_length = checked_setup_provider_multiply(
        relation_plan_variant.trace_domain_size(),
        u64::try_from(size_of::<ProofBaseFieldElement>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    Ok(CommonProofSourceProviderMemoryAccounting::new(
        checked_setup_provider_add(adapter_retained_byte_length, cached_quotient_byte_length)?,
        adapter_retained_byte_length,
        derivation_workspace_byte_length,
        maximum_returned_source_polynomial_byte_length,
    ))
}

fn add_setup_authority_memory_accounting(
    provider: CommonProofSourceProviderMemoryAccounting,
    authority_identifier: u32,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let authority = setup_generation_retained_memory_accounting(
        &SetupGenerationAuthorityHandle::from_identifier(authority_identifier),
    )
    .map_err(|_| CommonProofProverError::InvalidInput)?;
    let authority_byte_length = authority.active_payload_byte_length();
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

/// Ordered generation-only source provider for one participant's exact
/// suite-fixed relinearization round-one relation. The adapter retains only
/// reset-stable binding facts and one quotient frontier; every witness read
/// reenters the browser-owned setup authority.
pub(crate) struct RelinearizationRoundOneSourcePolynomialAdapter {
    authority_identifier: u32,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: Vec<u8>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    setup_attempt_identifier: [u8; 32],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    request_context: CommonProofSourcePolynomialRequestContext,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    geometry: TrusteeEvaluationKeyRelationGeometry,
    source_layout: RelinearizationRoundOneSourceLayout,
    requested_column_ordinals: Box<[u32]>,
    next_source_index: usize,
    cached_quotient: Option<CachedQuotient>,
    source_polynomials_finished: bool,
}

impl RelinearizationRoundOneSourcePolynomialAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source: &SetupGenerationRelinearizationRoundOneSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        geometry: TrusteeEvaluationKeyRelationGeometry,
        source_layout: RelinearizationRoundOneSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        if relation_plan_variant.schedule_position() != Some(source.schedule_position())
            || relation_plan_variant.top_count().is_some()
            || usize::try_from(relation_plan_variant.trace_domain_size())
                .ok()
                .and_then(|trace_size| trace_size.checked_mul(2))
                != usize::try_from(geometry.ring_degree).ok()
            || source.round_one_left_component().topology()
                != source.round_one_right_component().topology()
            || source
                .round_one_left_component()
                .topology()
                .polynomial_degree()
                != usize::try_from(geometry.ring_degree)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            source.protocol_version(),
            source.suite_identifier(),
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            source
                .prepared_attempt()
                .application_statement_hash()
                .into_bytes(),
            relation_plan.relation_plan_hash(),
            relation_plan.relation_plan_variant_hash(),
            relation_plan_variant.schedule_position(),
            relation_plan_variant.top_count(),
        );
        let requested_column_ordinals =
            requested_source_column_ordinals(&relation_plan_variant)?.into_boxed_slice();
        Ok(Self {
            authority_identifier: source.authority_identifier(),
            prepared_attempt: *source.prepared_attempt(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes()
                .to_vec(),
            setup_proof_context_hash: source.setup_proof_context_hash(),
            roster_hash: source.roster_hash(),
            participant_identity: source.participant_identity(),
            roster_position: source.roster_position(),
            schedule_position: source.schedule_position(),
            setup_attempt_identifier: source.setup_attempt_identifier(),
            source_setup_intent_object_hash: source.source_setup_intent_object_hash(),
            action_randomness_authorization_hash: source.action_randomness_authorization_hash(),
            request_context,
            relation_plan_variant,
            relation_context,
            geometry,
            source_layout,
            requested_column_ordinals,
            next_source_index: 0,
            cached_quotient: None,
            source_polynomials_finished: false,
        })
    }

    fn replay_identity(
        &self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomialReplayIdentity, CommonProofProverError> {
        CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(hash_framed_parts_512(
            RELINEARIZATION_ROUND_ONE_SOURCE_REPLAY_IDENTITY_DOMAIN,
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
                &self.schedule_position.to_le_bytes(),
            ],
        ))
    }

    fn derive_source_polynomial(
        &mut self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = SetupGenerationRelinearizationRoundOneApplication::from_decoded_statement(
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.participant_identity,
            self.roster_position,
            self.schedule_position,
        );
        let relation_plan_variant = &self.relation_plan_variant;
        let relation_context = &self.relation_context;
        let geometry = &self.geometry;
        let source_layout = &self.source_layout;
        let cached_quotient = &mut self.cached_quotient;
        let mut field_values = with_setup_generation_relinearization_round_one::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                let mut derivation = RelinearizationRoundOneColumnDerivation {
                    source: &source,
                    relation_plan_variant,
                    relation_context,
                    geometry,
                    source_layout: RelinearizationRoundOneSourceLayoutView::from_round_one(
                        source_layout,
                    ),
                    cached_rows: ExactKeyRelationDerivedRowCache::new(
                        relation_plan_variant.ordered_columns().len(),
                    ),
                    active_columns: ExactKeyRelationActiveColumnSet::new(
                        relation_plan_variant.ordered_columns().len(),
                    ),
                    cached_quotient,
                };
                let signed_rows = derivation.derive_rows(column_ordinal)?;
                signed_rows
                    .iter()
                    .copied()
                    .map(signed_integer_to_base_field)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Zeroizing::new)
            },
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        ProofEvaluationDomain::new_subgroup(
            usize::try_from(self.relation_plan_variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?
        .interpolate_base_polynomial_in_place(&mut field_values)?;
        Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
    }
}

impl CommonProofSourcePolynomialProvider for RelinearizationRoundOneSourcePolynomialAdapter {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        let requested_column_count =
            requested_source_column_ordinals(&self.relation_plan_variant)?.len();
        if requested_column_count != self.requested_column_ordinals.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let provider = relinearization_round_one_source_provider_memory_accounting(
            &self.relation_plan_variant,
            &self.relation_context,
            &self.geometry,
            &self.source_layout,
            self.canonical_application_statement_bytes.len(),
        )?;
        add_setup_authority_memory_accounting(provider, self.authority_identifier)
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

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        if !self.source_polynomials_finished {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(())
    }
}

pub(crate) fn relinearization_round_one_relation_tree_inputs(
    source: &SetupGenerationRelinearizationRoundOneSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &RelinearizationRoundOneSourceLayout,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    let generated_source = source
        .generated_source_authority()
        .map_err(|_| CommonProofProverError::InvalidTree)?;
    let component_sources = generated_source.components();
    let mut relation_trees = Vec::with_capacity(relation_plan_variant.ordered_trees().len());
    for tree in relation_plan_variant.ordered_trees() {
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
                        let column = relation_plan_variant
                            .ordered_columns()
                            .get(
                                usize::try_from(*column_ordinal)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::InvalidColumn)?;
                        Ok::<_, CommonProofProverError>(
                            if matches!(column.origin(), RelationColumnOrigin::Prover) {
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
            RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } => {
                let row_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let component_source = if split_rows_match(
                    &source_layout.round_one_left_rows,
                    ordered_column_ordinals,
                ) {
                    component_sources.first()
                } else if split_rows_match(
                    &source_layout.round_one_right_rows,
                    ordered_column_ordinals,
                ) {
                    component_sources.get(1)
                } else {
                    None
                };
                if let Some(component_source) = component_source {
                    relation_trees.push(RelationProofTreeInput::BoundPublic(
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: component_source
                                .public_polynomial_context_hash(),
                            row_width,
                            expected_root: component_source.contribution_root(),
                        },
                    ));
                } else if let Some(anchor_ordinal) =
                    source_layout.ordered_anchors.iter().position(|anchor| {
                        split_rows_match(&anchor.commitments, ordered_column_ordinals)
                    })
                {
                    let anchor = source
                        .anchor_openings()
                        .get(anchor_ordinal)
                        .ok_or(CommonProofProverError::InvalidTree)?;
                    relation_trees.push(RelationProofTreeInput::BoundPublic(
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
                            row_width,
                            expected_root: anchor.root(),
                        },
                    ));
                } else {
                    return Err(CommonProofProverError::InvalidTree);
                }
            }
            RelationTreeDescriptor::BoundPublic { .. } => {
                return Err(CommonProofProverError::InvalidTree);
            }
        }
    }
    Ok(relation_trees)
}

pub(super) struct RelinearizationRoundOneColumnDerivation<'source, 'plan> {
    pub(super) source: &'source dyn RelinearizationRoundOneWitnessSource,
    pub(super) relation_plan_variant: &'plan RelationPlanVariant,
    pub(super) relation_context: &'plan RelationPlanCheckContext,
    pub(super) geometry: &'plan TrusteeEvaluationKeyRelationGeometry,
    pub(super) source_layout: RelinearizationRoundOneSourceLayoutView<'plan>,
    pub(super) cached_rows: ExactKeyRelationDerivedRowCache,
    pub(super) active_columns: ExactKeyRelationActiveColumnSet,
    pub(super) cached_quotient: &'plan mut Option<CachedQuotient>,
}

impl KeyRelationColumnDerivation for RelinearizationRoundOneColumnDerivation<'_, '_> {
    fn relation_plan_variant(&self) -> &RelationPlanVariant {
        self.relation_plan_variant
    }

    fn relation_context(&self) -> &RelationPlanCheckContext {
        self.relation_context
    }

    fn exact_radix_digits_by_column(&self) -> &ExactRadixDigitColumnCatalog {
        self.source_layout.exact_radix_digits_by_column
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
            return split_signed_i8_polynomial(
                self.source.common_secret_coefficients(),
                half_ordinal,
            )
            .map(Some);
        }
        if let Some(half_ordinal) = half_position(
            self.source_layout.ephemeral_secret.source.coefficients,
            column_ordinal,
        ) {
            return split_signed_i8_polynomial(
                self.source.ephemeral_secret_coefficients(),
                half_ordinal,
            )
            .map(Some);
        }
        for (component, rows) in [
            (
                self.source.round_one_left_component(),
                self.source_layout.round_one_left_rows.as_ref(),
            ),
            (
                self.source.round_one_right_component(),
                self.source_layout.round_one_right_rows.as_ref(),
            ),
        ] {
            if let Some(result) = component_direct_witness_rows(component, rows, column_ordinal)? {
                return Ok(Some(result));
            }
        }
        for (block_ordinal, error_layout) in self.source_layout.errors_by_block.iter().enumerate() {
            if let Some(half_ordinal) =
                half_position(error_layout.left.coefficients, column_ordinal)
            {
                let error = self
                    .source
                    .round_one_left_errors_by_block()
                    .get(block_ordinal)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                return split_signed_i8_polynomial(error, half_ordinal).map(Some);
            }
            if let Some(half_ordinal) =
                half_position(error_layout.right.coefficients, column_ordinal)
            {
                let error = self
                    .source
                    .round_one_right_errors_by_block()
                    .get(block_ordinal)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                return split_signed_i8_polynomial(error, half_ordinal).map(Some);
            }
        }
        for (row_ordinal, quotient_layout) in self
            .source_layout
            .quotients_by_row
            .iter()
            .copied()
            .enumerate()
        {
            for half_ordinal in 0..2 {
                if quotient_layout.left.low_quotients[half_ordinal] == column_ordinal {
                    let quotient = self.cached_round_one_quotient(row_ordinal, true)?;
                    return split_balanced_quotient(quotient, half_ordinal, false).map(Some);
                }
                if quotient_layout.left.high_carries[half_ordinal] == column_ordinal {
                    let quotient = self.cached_round_one_quotient(row_ordinal, true)?;
                    return split_balanced_quotient(quotient, half_ordinal, true).map(Some);
                }
                if quotient_layout.right.low_quotients[half_ordinal] == column_ordinal {
                    let quotient = self.cached_round_one_quotient(row_ordinal, false)?;
                    return split_balanced_quotient(quotient, half_ordinal, false).map(Some);
                }
                if quotient_layout.right.high_carries[half_ordinal] == column_ordinal {
                    let quotient = self.cached_round_one_quotient(row_ordinal, false)?;
                    return split_balanced_quotient(quotient, half_ordinal, true).map(Some);
                }
            }
        }
        self.anchor_direct_witness_rows(column_ordinal)
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
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
                let data_modulus_index = u16::try_from(*data_modulus_index)
                    .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                let matrix_row = match u16::try_from(*matrix_part)
                    .map_err(|_| RefusalReason::WrongTypeOrLength)?
                {
                    1 => usize::try_from(*row).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    2 if *row == 0 => SETUP_COMMITMENT_MODULE_RANK,
                    _ => return Err(RefusalReason::WrongTypeOrLength),
                };
                let modulus = self
                    .relation_context
                    .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                setup_commitment_matrix_polynomial(
                    &encode_hex(&self.source.public_setup_seed()),
                    usize::from(data_modulus_index),
                    matrix_row,
                    usize::try_from(*column).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    usize::try_from(self.geometry.ring_degree)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    modulus,
                )
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)
            }
            RelationVerifierSource::Protocol {
                protocol_source_kind: 7,
                source_coordinates,
                ..
            } => {
                let [
                    schedule_position,
                    block_ordinal,
                    modulus_catalog,
                    modulus_index,
                ] = source_coordinates.as_slice()
                else {
                    return Err(RefusalReason::WrongTypeOrLength);
                };
                sample_relinearization_common_reference_limb(
                    &self.source.public_setup_seed(),
                    u32::try_from(*schedule_position)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    u16::try_from(*block_ordinal).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    u16::try_from(*modulus_catalog)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    u16::try_from(*modulus_index).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    usize::try_from(self.geometry.ring_degree)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)
            }
            _ => Err(RefusalReason::WrongTypeOrLength),
        }
    }
}

impl RelinearizationRoundOneColumnDerivation<'_, '_> {
    pub(super) fn common_direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        <Self as KeyRelationColumnDerivation>::direct_witness_rows(self, column_ordinal)
    }

    pub(super) fn common_full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        <Self as KeyRelationColumnDerivation>::full_verifier_sequence(self, source)
    }

    fn anchor_direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        for (anchor_ordinal, (layout, anchor)) in self
            .source_layout
            .ordered_anchors
            .iter()
            .zip(self.source.anchor_openings())
            .enumerate()
        {
            for (polynomial_ordinal, hiding_secret) in
                layout.opening.hiding_secrets.iter().enumerate()
            {
                if let Some(half_ordinal) = half_position(*hiding_secret, column_ordinal) {
                    return split_signed_i8_polynomial(
                        anchor
                            .hiding_secret_polynomials()
                            .get(polynomial_ordinal)
                            .ok_or(RefusalReason::WrongTypeOrLength)?,
                        half_ordinal,
                    )
                    .map(Some);
                }
            }
            for (polynomial_ordinal, hiding_error) in
                layout.opening.hiding_errors.iter().enumerate()
            {
                if let Some(half_ordinal) = half_position(hiding_error.coefficients, column_ordinal)
                {
                    return split_signed_i8_polynomial(
                        anchor
                            .hiding_error_polynomials()
                            .get(polynomial_ordinal)
                            .ok_or(RefusalReason::WrongTypeOrLength)?,
                        half_ordinal,
                    )
                    .map(Some);
                }
            }
            for (row_ordinal, commitment_layout) in layout.commitments.iter().copied().enumerate() {
                if let Some(half_ordinal) = half_position(commitment_layout, column_ordinal) {
                    return anchor
                        .commitment_trace_row_half(row_ordinal, half_ordinal)
                        .map(Some);
                }
            }
            for matrix_row in layout.first_matrix.iter() {
                for matrix in matrix_row.iter() {
                    if let Some(rows) = self.recentered_matrix_rows(matrix, column_ordinal)? {
                        return Ok(Some(rows));
                    }
                }
            }
            for matrix in layout.second_matrix.iter() {
                if let Some(rows) = self.recentered_matrix_rows(matrix, column_ordinal)? {
                    return Ok(Some(rows));
                }
            }
            for (row_ordinal, quotient_layout) in layout.quotients.iter().enumerate() {
                for half_ordinal in 0..2 {
                    if quotient_layout.low_quotients[half_ordinal] == column_ordinal {
                        let quotient = self.cached_anchor_quotient(anchor_ordinal, row_ordinal)?;
                        return split_balanced_quotient(quotient, half_ordinal, false).map(Some);
                    }
                    if quotient_layout.high_carries[half_ordinal] == column_ordinal {
                        let quotient = self.cached_anchor_quotient(anchor_ordinal, row_ordinal)?;
                        return split_balanced_quotient(quotient, half_ordinal, true).map(Some);
                    }
                }
            }
        }
        Ok(None)
    }

    fn recentered_matrix_rows(
        &mut self,
        matrix: &RecenteredVerifierVectorWitness,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        for half_ordinal in 0..2 {
            if matrix.centered.source.coefficients.halves[half_ordinal] == column_ordinal
                || matrix.carry_columns[half_ordinal] == column_ordinal
            {
                let canonical = self.derive_rows(matrix.canonical.halves[half_ordinal])?;
                let modulus_reference = self
                    .relation_plan_variant
                    .ordered_columns()
                    .get(
                        usize::try_from(matrix.canonical.halves[half_ordinal])
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .and_then(|column| column.canonical_residue_modulus())
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                let modulus = i128::from(
                    self.relation_context
                        .resolved_modulus(modulus_reference)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                );
                let offset = (modulus - 1) / 2;
                return Ok(Some(Zeroizing::new(
                    canonical
                        .iter()
                        .map(|value| {
                            if *value <= offset {
                                if matrix.carry_columns[half_ordinal] == column_ordinal {
                                    0
                                } else {
                                    *value + offset
                                }
                            } else if matrix.carry_columns[half_ordinal] == column_ordinal {
                                1
                            } else {
                                *value + offset - modulus
                            }
                        })
                        .collect(),
                )));
            }
        }
        Ok(None)
    }

    fn cached_round_one_quotient(
        &mut self,
        row_ordinal: usize,
        left: bool,
    ) -> Result<&[i128], RefusalReason> {
        let key = if left {
            CachedQuotientKey::RoundOneLeft { row_ordinal }
        } else {
            CachedQuotientKey::RoundOneRight { row_ordinal }
        };
        if self.cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
            let coefficients = self.derive_round_one_quotient(row_ordinal, left)?;
            *self.cached_quotient = Some(CachedQuotient { key, coefficients });
        }
        self.cached_quotient
            .as_ref()
            .map(|cache| cache.coefficients.as_slice())
            .ok_or(RefusalReason::ConsumedState)
    }

    fn derive_round_one_quotient(
        &self,
        row_ordinal: usize,
        left: bool,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let modulus_references = self.ordered_modulus_references()?;
        let modulus_reference = modulus_references
            .get(row_ordinal % modulus_references.len())
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let decomposition_block_index = row_ordinal / modulus_references.len();
        if decomposition_block_index >= self.geometry.decomposition_blocks.len() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let modulus = self
            .relation_context
            .resolved_modulus(modulus_reference)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let component = if left {
            self.source.round_one_left_component()
        } else {
            self.source.round_one_right_component()
        };
        let bound = decode_component_full_row(component, row_ordinal)?;
        let common_reference = sample_relinearization_common_reference_limb(
            &self.source.public_setup_seed(),
            self.source.schedule_position(),
            u16::try_from(decomposition_block_index)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            modulus_reference.catalog as u16,
            modulus_reference.modulus_index,
            usize::try_from(self.geometry.ring_degree)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let multiplier = if left {
            self.source.ephemeral_secret_coefficients()
        } else {
            self.source.common_secret_coefficients()
        }
        .iter()
        .copied()
        .map(i128::from)
        .collect::<Vec<_>>();
        let product = exact_negacyclic_product_radix(
            &common_reference
                .into_iter()
                .map(i128::from)
                .collect::<Vec<_>>(),
            &multiplier,
        )?;
        let error = if left {
            self.source.round_one_left_errors_by_block()
        } else {
            self.source.round_one_right_errors_by_block()
        }
        .get(decomposition_block_index)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
        let common_secret = self.source.common_secret_coefficients();
        let gadget_coefficient = self
            .geometry
            .gadget_coefficient(decomposition_block_index, modulus_reference)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        exact_modular_quotient(
            bound
                .iter()
                .copied()
                .zip(product.iter().copied())
                .zip(error.iter().copied().zip(common_secret.iter().copied())),
            modulus,
            |((bound, product), (error, common_secret))| {
                if left {
                    bound
                        .checked_add(product)
                        .and_then(|value| {
                            value.checked_sub(i128::from(PLAINTEXT_MODULUS) * i128::from(error))
                        })
                        .and_then(|value| {
                            value.checked_sub(
                                i128::from(gadget_coefficient) * i128::from(common_secret),
                            )
                        })
                } else {
                    bound.checked_sub(product).and_then(|value| {
                        value.checked_sub(i128::from(PLAINTEXT_MODULUS) * i128::from(error))
                    })
                }
            },
        )
    }

    fn cached_anchor_quotient(
        &mut self,
        anchor_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<&[i128], RefusalReason> {
        let key = CachedQuotientKey::Anchor {
            anchor_ordinal,
            row_ordinal,
        };
        if self.cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
            let coefficients = self.derive_anchor_quotient(anchor_ordinal, row_ordinal)?;
            *self.cached_quotient = Some(CachedQuotient { key, coefficients });
        }
        self.cached_quotient
            .as_ref()
            .map(|cache| cache.coefficients.as_slice())
            .ok_or(RefusalReason::ConsumedState)
    }

    fn derive_anchor_quotient(
        &self,
        anchor_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let layout = self
            .source_layout
            .ordered_anchors
            .get(anchor_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let anchor = self
            .source
            .anchor_openings()
            .get(anchor_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if row_ordinal > SETUP_COMMITMENT_MODULE_RANK {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let modulus = self
            .relation_context
            .resolved_modulus(SuiteModulusReference::data(layout.data_modulus_index))
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let commitment = anchor_full_row(anchor, row_ordinal)?;
        let ring_degree = usize::try_from(self.geometry.ring_degree)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let seed = encode_hex(&self.source.public_setup_seed());
        let product_column_count = if row_ordinal < SETUP_COMMITMENT_MODULE_RANK {
            SETUP_COMMITMENT_MODULE_RANK + 1
        } else {
            SETUP_COMMITMENT_MODULE_RANK
        };
        let mut products = Vec::with_capacity(product_column_count);
        for column_ordinal in 0..product_column_count {
            let matrix_row = if row_ordinal < SETUP_COMMITMENT_MODULE_RANK {
                row_ordinal
            } else {
                SETUP_COMMITMENT_MODULE_RANK
            };
            let matrix = setup_commitment_matrix_polynomial(
                &seed,
                usize::from(layout.data_modulus_index),
                matrix_row,
                column_ordinal,
                ring_degree,
                modulus,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            let centered_matrix = matrix
                .into_iter()
                .map(|value| centered_residue(value, modulus))
                .collect::<Vec<_>>();
            let hiding_secret = anchor
                .hiding_secret_polynomials()
                .get(column_ordinal)
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .iter()
                .copied()
                .map(i128::from)
                .collect::<Vec<_>>();
            products.push(exact_negacyclic_product_radix(
                &centered_matrix,
                &hiding_secret,
            )?);
        }
        let last_hiding_secret = anchor
            .hiding_secret_polynomials()
            .get(SETUP_COMMITMENT_MODULE_RANK)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let hiding_error = (row_ordinal < SETUP_COMMITMENT_MODULE_RANK)
            .then(|| anchor.hiding_error_polynomials().get(row_ordinal))
            .flatten();
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
                            self.source.common_secret_coefficients()[coefficient_ordinal],
                        ))
                    })
            }
        })
    }

    fn ordered_modulus_references(&self) -> Result<Vec<SuiteModulusReference>, RefusalReason> {
        let mut references = Vec::with_capacity(
            self.geometry
                .data_moduli
                .len()
                .checked_add(self.geometry.special_moduli.len())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        );
        for modulus_index in 0..self.geometry.data_moduli.len() {
            references.push(SuiteModulusReference::data(
                u16::try_from(modulus_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            ));
        }
        for modulus_index in 0..self.geometry.special_moduli.len() {
            references.push(SuiteModulusReference::special(
                u16::try_from(modulus_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            ));
        }
        if references.is_empty() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(references)
    }
}

pub(super) fn component_direct_witness_rows(
    component: &SetupGeneratedKeySwitchComponent,
    rows: &[super::key_relation::SplitIntegerVector],
    column_ordinal: u32,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
    component_bytes_direct_witness_rows(
        component.topology(),
        component.canonical_bytes(),
        rows,
        column_ordinal,
    )
}

pub(super) fn component_bytes_direct_witness_rows(
    topology: &crate::bgv::proof_suite::KeySwitchComponentMaterialTopology,
    canonical_bytes: &[u8],
    rows: &[super::key_relation::SplitIntegerVector],
    column_ordinal: u32,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
    for (row_ordinal, row) in rows.iter().copied().enumerate() {
        if let Some(half_ordinal) = half_position(row, column_ordinal) {
            let trace_column = topology.trace_column(
                row_ordinal
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(half_ordinal))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
            let byte_start = usize::try_from(trace_column.byte_offset())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let byte_end = usize::try_from(
                trace_column
                    .byte_offset()
                    .checked_add(trace_column.byte_length())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let values = trace_column.decode_authenticated_bytes(
                canonical_bytes
                    .get(byte_start..byte_end)
                    .ok_or(RefusalReason::WrongTypeOrLength)?,
            )?;
            return Ok(Some(Zeroizing::new(
                values
                    .into_iter()
                    .map(|value| i128::from(value.canonical()))
                    .collect(),
            )));
        }
    }
    Ok(None)
}

pub(super) fn decode_component_full_row(
    component: &SetupGeneratedKeySwitchComponent,
    row_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    decode_component_full_row_from_bytes(
        component.topology(),
        component.canonical_bytes(),
        row_ordinal,
    )
}

pub(super) fn decode_component_full_row_from_bytes(
    topology: &crate::bgv::proof_suite::KeySwitchComponentMaterialTopology,
    canonical_bytes: &[u8],
    row_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    let half_count = 2_usize;
    let mut coefficients = Zeroizing::new(Vec::with_capacity(topology.polynomial_degree()));
    for half_ordinal in 0..half_count {
        let trace_column = topology.trace_column(
            row_ordinal
                .checked_mul(half_count)
                .and_then(|value| value.checked_add(half_ordinal))
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        let byte_start = usize::try_from(trace_column.byte_offset())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let byte_end = usize::try_from(
            trace_column
                .byte_offset()
                .checked_add(trace_column.byte_length())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        coefficients.extend(
            trace_column
                .decode_authenticated_bytes(
                    canonical_bytes
                        .get(byte_start..byte_end)
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                )?
                .into_iter()
                .map(|value| i128::from(value.canonical())),
        );
    }
    if coefficients.len() != topology.polynomial_degree() {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(coefficients)
}
