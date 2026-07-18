use std::collections::{BTreeMap, BTreeSet};

use num_traits::ToPrimitive;
use zeroize::Zeroizing;

use crate::{
    bgv::{
        parameters::PLAINTEXT_MODULUS,
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, sample_galois_common_reference_limb,
            setup_commitment_matrix_polynomial,
        },
    },
    foundation::{
        Hash512, PreparedActionProofAttemptSource, ProofApplicationSlotCeilings, RefusalReason,
    },
    hashing::hash_framed_parts_512,
    transcript_core::encode_hex,
};

use super::super::prover::{integer_lift_derived_columns, proof_created_tree_roles_by_column};
use super::super::{
    CommonProofProverError, CommonProofRelationPlanCapability, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, PROOF_BASE_FIELD_MODULUS, ProofBaseFieldElement,
    ProofEvaluationDomain, ProofLeafVisibility, ProofTreeRole, ProvidedCommonProofSourcePolynomial,
    RelationProofTreeInput, SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    StatementOwnedProofTreeInput,
};
use super::{
    BoundTreeConstructionKind, RelationBoundCertificate, RelationColumnOrigin,
    RelationIntegerLiftCoefficient, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanCheckContext,
    RelationPlanVariant, RelationTreeDescriptor, RelationVerifierSource, SuiteModulusReference,
    apply_negacyclic_automorphism, negacyclic_automorphism_mapping_values,
    resolved_modulus_radix_digit,
};
use super::{
    key_relation::{EXACT_INTEGER_LIFT_RADIX, SplitIntegerVector},
    trustee_evaluation_key::{GaloisKeyShareSourceLayout, TrusteeEvaluationKeyRelationGeometry},
};
use crate::bgv::setup::{
    SetupGenerationAuthorityHandle, SetupGenerationGaloisApplication,
    SetupGenerationGaloisBatchSource, with_setup_generation_galois_batch,
};

const GALOIS_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/galois-key-share/source-replay-identity/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CachedQuotientKey {
    Galois {
        entry_ordinal: usize,
        row_ordinal: usize,
    },
    Anchor {
        anchor_ordinal: usize,
        row_ordinal: usize,
    },
}

struct CachedQuotient {
    key: CachedQuotientKey,
    coefficients: Zeroizing<Vec<i128>>,
}

/// Ordered, authority-backed source provider for the exact suite-fixed Galois
/// common proof. Secret material remains in the setup-generation authority;
/// this adapter retains only reset-stable binding facts and one quotient
/// frontier at a time.
pub(crate) struct GaloisKeyShareSourcePolynomialAdapter {
    authority_identifier: u32,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: Vec<u8>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
    setup_attempt_identifier: [u8; 32],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    request_context: CommonProofSourcePolynomialRequestContext,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    geometry: TrusteeEvaluationKeyRelationGeometry,
    source_layout: GaloisKeyShareSourceLayout,
    requested_column_ordinals: Box<[u32]>,
    next_source_index: usize,
    cached_quotient: Option<CachedQuotient>,
    source_polynomials_finished: bool,
}

impl GaloisKeyShareSourcePolynomialAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source: &SetupGenerationGaloisBatchSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        geometry: TrusteeEvaluationKeyRelationGeometry,
        source_layout: GaloisKeyShareSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        if relation_plan_variant.schedule_position() != Some(source.batch_schedule_position())
            || relation_plan_variant.top_count().is_some()
            || usize::try_from(relation_plan_variant.trace_domain_size())
                .ok()
                .and_then(|trace_size| trace_size.checked_mul(2))
                != usize::try_from(geometry.ring_degree).ok()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            source.protocol_version(),
            source.suite_identifier(),
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
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
            batch_schedule_position: source.batch_schedule_position(),
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
            GALOIS_SOURCE_REPLAY_IDENTITY_DOMAIN,
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
                &self.batch_schedule_position.to_le_bytes(),
            ],
        ))
    }

    fn derive_source_polynomial(
        &mut self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = SetupGenerationGaloisApplication::from_decoded_statement(
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.roster_hash,
            self.participant_identity,
            self.roster_position,
            self.batch_schedule_position,
        );
        let relation_plan_variant = &self.relation_plan_variant;
        let relation_context = &self.relation_context;
        let geometry = &self.geometry;
        let source_layout = &self.source_layout;
        let cached_quotient = &mut self.cached_quotient;
        let mut field_values = with_setup_generation_galois_batch::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                let mut derivation = GaloisColumnDerivation {
                    source: &source,
                    relation_plan_variant,
                    relation_context,
                    geometry,
                    source_layout,
                    cached_rows: BTreeMap::new(),
                    active_columns: BTreeSet::new(),
                    cached_quotient,
                };
                let signed_rows = derivation.derive_rows(column_ordinal)?;
                let field_values = signed_rows
                    .iter()
                    .copied()
                    .map(signed_integer_to_base_field)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Zeroizing::new(field_values))
            },
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let descriptor = self
            .relation_plan_variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. }) {
            ProofEvaluationDomain::new_subgroup(
                usize::try_from(self.relation_plan_variant.trace_domain_size())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?
            .interpolate_base_polynomial_in_place(&mut field_values)?;
        }
        Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
    }
}

impl CommonProofSourcePolynomialProvider for GaloisKeyShareSourcePolynomialAdapter {
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

fn requested_source_column_ordinals(
    relation_plan_variant: &RelationPlanVariant,
) -> Result<Vec<u32>, CommonProofProverError> {
    let proof_tree_roles = proof_created_tree_roles_by_column(relation_plan_variant)?;
    let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(relation_plan_variant)?;
    let reversed_columns = reversed_columns_by_source
        .into_values()
        .collect::<BTreeSet<_>>();
    let mut requested_column_ordinals =
        Vec::with_capacity(relation_plan_variant.ordered_columns().len());
    for (column_index, _) in relation_plan_variant.ordered_columns().iter().enumerate() {
        let column_ordinal =
            u32::try_from(column_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        if !reversed_columns.contains(&column_ordinal)
            && !integer_lift_auxiliary_columns.contains(&column_ordinal)
            && proof_tree_roles.get(&column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
        {
            requested_column_ordinals.push(column_ordinal);
        }
    }
    Ok(requested_column_ordinals)
}

pub(crate) fn galois_relation_tree_inputs(
    source: &SetupGenerationGaloisBatchSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &GaloisKeyShareSourceLayout,
    ordered_contribution_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
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
                if let Some(entry_ordinal) = source_layout
                    .ordered_entries
                    .iter()
                    .position(|entry| split_rows_match(&entry.bound_rows, ordered_column_ordinals))
                {
                    let root = ordered_contribution_roots
                        .get(entry_ordinal)
                        .copied()
                        .ok_or(CommonProofProverError::InvalidTree)?;
                    let logical_schedule_position = u32::try_from(entry_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                    let context = SetupPublicPolynomialContext::new(
                        source.setup_proof_context_hash(),
                        SetupPublicPolynomialRootRole::GaloisKeyShare,
                        Some(source.participant_identity()),
                        Some(source.roster_position()),
                        Some(logical_schedule_position),
                        None,
                    )
                    .map_err(|_| CommonProofProverError::InvalidTree)?;
                    relation_trees.push(RelationProofTreeInput::BoundPublic(
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: context
                                .context_hash()
                                .map_err(|_| CommonProofProverError::InvalidTree)?,
                            row_width,
                            expected_root: root,
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

fn split_rows_match(rows: &[SplitIntegerVector], ordered_column_ordinals: &[u32]) -> bool {
    rows.iter()
        .flat_map(|row| row.halves)
        .eq(ordered_column_ordinals.iter().copied())
}

struct GaloisColumnDerivation<'source, 'authority, 'statement, 'plan> {
    source: &'source SetupGenerationGaloisBatchSource<'authority, 'statement>,
    relation_plan_variant: &'plan RelationPlanVariant,
    relation_context: &'plan RelationPlanCheckContext,
    geometry: &'plan TrusteeEvaluationKeyRelationGeometry,
    source_layout: &'plan GaloisKeyShareSourceLayout,
    cached_rows: BTreeMap<u32, Zeroizing<Vec<i128>>>,
    active_columns: BTreeSet<u32>,
    cached_quotient: &'plan mut Option<CachedQuotient>,
}

impl GaloisColumnDerivation<'_, '_, '_, '_> {
    fn derive_rows(&mut self, column_ordinal: u32) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        if let Some(rows) = self.cached_rows.get(&column_ordinal) {
            return Ok(Zeroizing::new(rows.to_vec()));
        }
        if !self.active_columns.insert(column_ordinal) {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        let rows = self.derive_rows_uncached(column_ordinal)?;
        self.active_columns.remove(&column_ordinal);
        if rows.len()
            != usize::try_from(self.relation_plan_variant.trace_domain_size())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.cached_rows
            .insert(column_ordinal, Zeroizing::new(rows.to_vec()));
        Ok(rows)
    }

    fn derive_rows_uncached(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        if let Some(rows) = self.direct_witness_rows(column_ordinal)? {
            return Ok(rows);
        }
        if let Some(rows) = self.exact_radix_digit_rows(column_ordinal)? {
            return Ok(rows);
        }
        if let Some(rows) = self.verifier_sequence_rows(column_ordinal)? {
            return Ok(rows);
        }
        if let Some(rows) = self.semantic_auxiliary_rows(column_ordinal)? {
            return Ok(rows);
        }
        if let Some(rows) = self.exact_integer_lift_carry_rows(column_ordinal)? {
            return Ok(rows);
        }
        Err(RefusalReason::InvalidArithmeticRelation)
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
        for (entry_ordinal, (layout, entry)) in self
            .source_layout
            .ordered_entries
            .iter()
            .zip(self.source.ordered_entries())
            .enumerate()
        {
            if let Some(half_ordinal) =
                half_position(layout.automorphed_secret.coefficients, column_ordinal)
            {
                let source_secret = self
                    .source
                    .common_secret_coefficients()
                    .iter()
                    .copied()
                    .map(i64::from)
                    .collect::<Vec<_>>();
                let automorphed =
                    apply_negacyclic_automorphism(&source_secret, layout.galois_element)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                return split_signed_i64_polynomial(&automorphed, half_ordinal).map(Some);
            }
            for (row_ordinal, row) in layout.bound_rows.iter().copied().enumerate() {
                if let Some(half_ordinal) = half_position(row, column_ordinal) {
                    let trace_column = entry.component().topology().trace_column(
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
                        entry
                            .component()
                            .canonical_bytes()
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
            for (block_ordinal, error_layout) in layout.errors_by_block.iter().enumerate() {
                if let Some(half_ordinal) = half_position(error_layout.coefficients, column_ordinal)
                {
                    let error = entry
                        .centered_error_polynomials_by_block()
                        .get(block_ordinal)
                        .ok_or(RefusalReason::WrongTypeOrLength)?;
                    return split_signed_i8_polynomial(error, half_ordinal).map(Some);
                }
            }
            for (row_ordinal, quotient_layout) in
                layout.quotients_by_row.iter().copied().enumerate()
            {
                for half_ordinal in 0..2 {
                    if quotient_layout.low_quotients[half_ordinal] == column_ordinal {
                        let quotient = self.cached_galois_quotient(entry_ordinal, row_ordinal)?;
                        return split_balanced_quotient(quotient, half_ordinal, false).map(Some);
                    }
                    if quotient_layout.high_carries[half_ordinal] == column_ordinal {
                        let quotient = self.cached_galois_quotient(entry_ordinal, row_ordinal)?;
                        return split_balanced_quotient(quotient, half_ordinal, true).map(Some);
                    }
                }
            }
        }
        for (anchor_ordinal, (layout, anchor)) in self
            .source_layout
            .ordered_anchors
            .iter()
            .zip(self.source.anchor_openings())
            .enumerate()
        {
            for (polynomial_ordinal, hiding_secret) in
                layout.opening.hiding_secrets.iter().copied().enumerate()
            {
                if let Some(half_ordinal) = half_position(hiding_secret, column_ordinal) {
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
                        .ordered_coefficient_columns()
                        .get(
                            row_ordinal
                                .checked_mul(2)
                                .and_then(|value| value.checked_add(half_ordinal))
                                .ok_or(RefusalReason::OutsideSupportedProfile)?,
                        )
                        .map(|column| {
                            Zeroizing::new(
                                column
                                    .iter()
                                    .map(|value| i128::from(value.canonical()))
                                    .collect(),
                            )
                        })
                        .ok_or(RefusalReason::WrongTypeOrLength)
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
            for (row_ordinal, quotient_layout) in layout.quotients.iter().copied().enumerate() {
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
        matrix: &super::key_relation::RecenteredVerifierVectorWitness,
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

    fn cached_galois_quotient(
        &mut self,
        entry_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<&[i128], RefusalReason> {
        let key = CachedQuotientKey::Galois {
            entry_ordinal,
            row_ordinal,
        };
        if self.cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
            let coefficients = self.derive_galois_quotient(entry_ordinal, row_ordinal)?;
            *self.cached_quotient = Some(CachedQuotient { key, coefficients });
        }
        self.cached_quotient
            .as_ref()
            .map(|cache| cache.coefficients.as_slice())
            .ok_or(RefusalReason::ConsumedState)
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

    fn derive_galois_quotient(
        &self,
        entry_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let layout = self
            .source_layout
            .ordered_entries
            .get(entry_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let entry = self
            .source
            .ordered_entries()
            .get(entry_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let ordered_modulus_references = self
            .geometry
            .ordered_modulus_references()
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let modulus_reference = ordered_modulus_references
            .get(row_ordinal % ordered_modulus_references.len())
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let decomposition_block_index = row_ordinal / ordered_modulus_references.len();
        let modulus = self
            .relation_context
            .resolved_modulus(modulus_reference)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let bound = decode_component_full_row(entry, row_ordinal)?;
        let common_reference = sample_galois_common_reference_limb(
            &self.source.public_setup_seed(),
            layout.schedule_position,
            u16::try_from(decomposition_block_index)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            modulus_reference.catalog as u16,
            modulus_reference.modulus_index,
            usize::try_from(self.geometry.ring_degree)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let secret = self
            .source
            .common_secret_coefficients()
            .iter()
            .copied()
            .map(i128::from)
            .collect::<Vec<_>>();
        let common_reference_times_secret = exact_negacyclic_product_radix(
            &common_reference
                .into_iter()
                .map(i128::from)
                .collect::<Vec<_>>(),
            &secret,
        )?;
        let automorphed_secret = apply_negacyclic_automorphism(
            &secret
                .iter()
                .copied()
                .map(|value| i64::try_from(value).map_err(|_| RefusalReason::WrongTypeOrLength))
                .collect::<Result<Vec<_>, _>>()?,
            layout.galois_element,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let error = entry
            .centered_error_polynomials_by_block()
            .get(decomposition_block_index)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let gadget_coefficient = self
            .geometry
            .gadget_coefficient(decomposition_block_index, modulus_reference)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        exact_modular_quotient(
            bound
                .iter()
                .copied()
                .zip(common_reference_times_secret.iter().copied())
                .zip(
                    error
                        .iter()
                        .copied()
                        .zip(automorphed_secret.iter().copied()),
                ),
            modulus,
            |((bound, product), (error, automorphed_secret))| {
                bound
                    .checked_add(product)
                    .and_then(|value| {
                        value.checked_sub(i128::from(PLAINTEXT_MODULUS) * i128::from(error))
                    })
                    .and_then(|value| {
                        value.checked_sub(
                            i128::from(gadget_coefficient) * i128::from(automorphed_secret),
                        )
                    })
            },
        )
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
        let rank = SETUP_COMMITMENT_MODULE_RANK;
        if row_ordinal > rank {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let modulus_reference = SuiteModulusReference::data(layout.data_modulus_index);
        let modulus = self
            .relation_context
            .resolved_modulus(modulus_reference)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let commitment = anchor_full_row(anchor, row_ordinal)?;
        let seed = encode_hex(&self.source.public_setup_seed());
        let ring_degree = usize::try_from(self.geometry.ring_degree)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut products = Vec::new();
        let product_columns = if row_ordinal < rank { rank + 1 } else { rank };
        for column_ordinal in 0..product_columns {
            let matrix_row = if row_ordinal < rank {
                row_ordinal
            } else {
                rank
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
        let common_secret = self.source.common_secret_coefficients();
        let last_hiding_secret = anchor
            .hiding_secret_polynomials()
            .get(rank)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let hiding_error = (row_ordinal < rank)
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
                        value.checked_sub(i128::from(common_secret[coefficient_ordinal]))
                    })
            }
        })
    }

    fn exact_radix_digit_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        for (source_column_ordinal, digit_column_ordinals) in
            &self.source_layout.exact_radix_digits_by_column
        {
            if let Some(digit_ordinal) = digit_column_ordinals
                .iter()
                .position(|candidate| *candidate == column_ordinal)
            {
                let source_rows = self.derive_rows(*source_column_ordinal)?;
                let divisor = i128::from(EXACT_INTEGER_LIFT_RADIX)
                    .checked_pow(
                        u32::try_from(digit_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                let digit_rows = source_rows
                    .iter()
                    .map(|value| {
                        if *value < 0 {
                            return Err(RefusalReason::InvalidArithmeticRelation);
                        }
                        Ok((*value / divisor) % i128::from(EXACT_INTEGER_LIFT_RADIX))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(Some(Zeroizing::new(digit_rows)));
            }
        }
        Ok(None)
    }

    fn verifier_sequence_rows(
        &self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let descriptor = self
            .relation_plan_variant
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
        let verifier_source = self
            .relation_plan_variant
            .verifier_source(*verifier_source_ordinal)
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        let sequence = self.full_verifier_sequence(verifier_source)?;
        let trace_size = usize::try_from(self.relation_plan_variant.trace_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let first_index = usize::try_from(*first_logical_element_index)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let stride = usize::try_from(*logical_element_stride)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let selected_sequence = (0..trace_size)
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
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Zeroizing::new(selected_sequence)))
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
                let matrix_part =
                    u16::try_from(*matrix_part).map_err(|_| RefusalReason::WrongTypeOrLength)?;
                let matrix_row = match matrix_part {
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
                protocol_source_kind: 8,
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
                sample_galois_common_reference_limb(
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
            RelationVerifierSource::NegacyclicAutomorphismMapping {
                ring_degree,
                galois_element,
            } => negacyclic_automorphism_mapping_values(*ring_degree, *galois_element)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation),
            _ => Err(RefusalReason::WrongTypeOrLength),
        }
    }

    fn semantic_auxiliary_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        for semantic_cell in &self.relation_plan_variant.ordered_semantic_cells {
            match &semantic_cell.bound_certificate {
                RelationBoundCertificate::UnsignedRadixRecomposition {
                    radix,
                    ordered_digit_column_ordinals,
                    ..
                } => {
                    if let Some(digit_ordinal) = ordered_digit_column_ordinals
                        .iter()
                        .position(|candidate| *candidate == column_ordinal)
                    {
                        return self
                            .radix_digit_rows(
                                semantic_cell.column_ordinal,
                                *radix,
                                digit_ordinal,
                                0,
                            )
                            .map(Some);
                    }
                }
                RelationBoundCertificate::ShiftedRadixRecomposition {
                    radix,
                    offset,
                    ordered_digit_column_ordinals,
                    ..
                } => {
                    if let Some(digit_ordinal) = ordered_digit_column_ordinals
                        .iter()
                        .position(|candidate| *candidate == column_ordinal)
                    {
                        let offset = offset
                            .to_i128()
                            .ok_or(RefusalReason::OutsideSupportedProfile)?;
                        return self
                            .radix_digit_rows(
                                semantic_cell.column_ordinal,
                                *radix,
                                digit_ordinal,
                                offset,
                            )
                            .map(Some);
                    }
                }
                RelationBoundCertificate::CanonicalModulusRecomposition {
                    modulus_reference,
                    radix,
                    ordered_digit_column_ordinals,
                    ordered_difference_digit_column_ordinals,
                    ordered_borrow_column_ordinals,
                    ..
                } => {
                    if ordered_digit_column_ordinals.contains(&column_ordinal)
                        || ordered_difference_digit_column_ordinals.contains(&column_ordinal)
                        || ordered_borrow_column_ordinals.contains(&column_ordinal)
                    {
                        let target = self.derive_rows(semantic_cell.column_ordinal)?;
                        return canonical_comparator_column_rows(
                            &target,
                            self.relation_context
                                .resolved_modulus(*modulus_reference)
                                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                            *radix,
                            ordered_digit_column_ordinals,
                            ordered_difference_digit_column_ordinals,
                            ordered_borrow_column_ordinals,
                            column_ordinal,
                        )
                        .map(Some);
                    }
                }
                RelationBoundCertificate::Trinary { .. }
                | RelationBoundCertificate::Binary { .. }
                | RelationBoundCertificate::FiniteIntegerSet { .. } => {}
            }
        }
        Ok(None)
    }

    fn radix_digit_rows(
        &mut self,
        target_column_ordinal: u32,
        radix: u64,
        digit_ordinal: usize,
        offset: i128,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let divisor = i128::from(radix)
            .checked_pow(
                u32::try_from(digit_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let digit_rows = self
            .derive_rows(target_column_ordinal)?
            .iter()
            .map(|value| {
                value
                    .checked_add(offset)
                    .filter(|shifted| *shifted >= 0)
                    .map(|shifted| (shifted / divisor) % i128::from(radix))
                    .ok_or(RefusalReason::InvalidArithmeticRelation)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Zeroizing::new(digit_rows))
    }

    fn exact_integer_lift_carry_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let component = self
            .relation_plan_variant
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
        let trace_size = usize::try_from(self.relation_plan_variant.trace_domain_size())
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
                self.relation_context,
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
        let carry_rows = accumulated
            .iter()
            .copied()
            .map(|value| {
                if value % radix != 0 {
                    Err(RefusalReason::InvalidArithmeticRelation)
                } else {
                    Ok(value / radix)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Zeroizing::new(carry_rows)))
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

fn half_position(vector: SplitIntegerVector, column_ordinal: u32) -> Option<usize> {
    vector
        .halves
        .iter()
        .position(|candidate| *candidate == column_ordinal)
}

fn split_signed_i8_polynomial(
    coefficients: &[i8],
    half_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    split_signed_polynomial(
        &coefficients
            .iter()
            .copied()
            .map(i128::from)
            .collect::<Vec<_>>(),
        half_ordinal,
    )
}

fn split_signed_i64_polynomial(
    coefficients: &[i64],
    half_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    split_signed_polynomial(
        &coefficients
            .iter()
            .copied()
            .map(i128::from)
            .collect::<Vec<_>>(),
        half_ordinal,
    )
}

fn split_signed_polynomial(
    coefficients: &[i128],
    half_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    if coefficients.is_empty() || !coefficients.len().is_multiple_of(2) || half_ordinal > 1 {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let half_size = coefficients.len() / 2;
    let start = half_ordinal
        .checked_mul(half_size)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    Ok(Zeroizing::new(
        coefficients[start..start + half_size].to_vec(),
    ))
}

fn split_balanced_quotient(
    quotient: &[i128],
    half_ordinal: usize,
    select_high: bool,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    let coefficients = split_signed_polynomial(quotient, half_ordinal)?;
    let radix = i128::from(EXACT_INTEGER_LIFT_RADIX);
    let offset = (radix - 1) / 2;
    let split_coefficients = coefficients
        .iter()
        .map(|value| {
            let low = value.rem_euclid(radix);
            let low = if low > offset { low - radix } else { low };
            let high = (value - low) / radix;
            if !(-2..=2).contains(&high) {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            Ok(if select_high { high } else { low })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Zeroizing::new(split_coefficients))
}

fn decode_component_full_row(
    entry: &crate::bgv::setup::SetupGeneratedGaloisEntry,
    row_ordinal: usize,
) -> Result<Vec<i128>, RefusalReason> {
    let topology = entry.component().topology();
    let mut coefficients = Vec::with_capacity(topology.polynomial_degree());
    for half_ordinal in 0..2 {
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
        coefficients.extend(
            trace_column
                .decode_authenticated_bytes(
                    entry
                        .component()
                        .canonical_bytes()
                        .get(byte_start..byte_end)
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                )?
                .into_iter()
                .map(|value| i128::from(value.canonical())),
        );
    }
    Ok(coefficients)
}

fn anchor_full_row(
    anchor: &crate::bgv::setup::SetupGenerationAnchorOpening,
    row_ordinal: usize,
) -> Result<Vec<i128>, RefusalReason> {
    let mut coefficients = Vec::new();
    for half_ordinal in 0..2 {
        coefficients.extend(
            anchor
                .ordered_coefficient_columns()
                .get(
                    row_ordinal
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(half_ordinal))
                        .ok_or(RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .iter()
                .map(|value| i128::from(value.canonical())),
        );
    }
    Ok(coefficients)
}

fn exact_modular_quotient<Coordinate>(
    coordinates: impl IntoIterator<Item = Coordinate>,
    modulus: u64,
    mut numerator: impl FnMut(Coordinate) -> Option<i128>,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    let modulus = i128::from(modulus);
    let quotient = coordinates
        .into_iter()
        .map(|coordinate| {
            let numerator =
                numerator(coordinate).ok_or(RefusalReason::InvalidArithmeticRelation)?;
            if numerator % modulus != 0 {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            Ok(numerator / modulus)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Zeroizing::new(quotient))
}

fn centered_residue(value: u64, modulus: u64) -> i128 {
    if value <= (modulus - 1) / 2 {
        i128::from(value)
    } else {
        i128::from(value) - i128::from(modulus)
    }
}

fn exact_negacyclic_product_radix(
    left: &[i128],
    right: &[i128],
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    if left.is_empty() || left.len() != right.len() || !left.len().is_power_of_two() {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let radix = i128::from(EXACT_INTEGER_LIFT_RADIX);
    let maximum_magnitude = left
        .iter()
        .map(|value| value.unsigned_abs())
        .max()
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    let mut digit_count = 1_usize;
    let radix_unsigned = u128::from(EXACT_INTEGER_LIFT_RADIX);
    let mut capacity = radix_unsigned;
    while capacity <= maximum_magnitude {
        capacity = capacity
            .checked_mul(radix_unsigned)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        digit_count = digit_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
    }
    let mut result = Zeroizing::new(vec![0_i128; left.len()]);
    let mut radix_power = 1_i128;
    for digit_ordinal in 0..digit_count {
        let radix_power_unsigned =
            u128::try_from(radix_power).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let digit_values = left
            .iter()
            .map(|value| {
                let magnitude_digit =
                    i128::try_from((value.unsigned_abs() / radix_power_unsigned) % radix_unsigned)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                Ok(if *value < 0 {
                    -magnitude_digit
                } else {
                    magnitude_digit
                })
            })
            .collect::<Result<Vec<_>, RefusalReason>>()?;
        let digit_product = exact_negacyclic_product_small(&digit_values, right)?;
        for (result, digit_product) in result.iter_mut().zip(digit_product.iter()) {
            *result = result
                .checked_add(
                    digit_product
                        .checked_mul(radix_power)
                        .ok_or(RefusalReason::InvalidArithmeticRelation)?,
                )
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        }
        if digit_ordinal + 1 < digit_count {
            radix_power = radix_power
                .checked_mul(radix)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
    }
    Ok(result)
}

fn exact_negacyclic_product_small(
    left: &[i128],
    right: &[i128],
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    if left.is_empty() || left.len() != right.len() || !left.len().is_power_of_two() {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let maximum_left = left
        .iter()
        .map(|value| value.unsigned_abs())
        .max()
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    let right_l1_norm = right.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(value.unsigned_abs())
            .ok_or(RefusalReason::InvalidArithmeticRelation)
    })?;
    if maximum_left
        .checked_mul(right_l1_norm)
        .is_none_or(|bound| bound >= u128::from(PROOF_BASE_FIELD_MODULUS / 2))
    {
        return Err(RefusalReason::InvalidArithmeticRelation);
    }
    let transform_size = left
        .len()
        .checked_mul(2)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let domain = ProofEvaluationDomain::new_subgroup(transform_size)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let mut left_evaluations = Zeroizing::new(
        left.iter()
            .copied()
            .map(signed_integer_to_base_field)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut right_evaluations = Zeroizing::new(
        right
            .iter()
            .copied()
            .map(signed_integer_to_base_field)
            .collect::<Result<Vec<_>, _>>()?,
    );
    domain
        .evaluate_base_polynomial_in_place(&mut left_evaluations)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    domain
        .evaluate_base_polynomial_in_place(&mut right_evaluations)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    for (left, right) in left_evaluations.iter_mut().zip(right_evaluations.iter()) {
        *left = left.multiply(*right);
    }
    domain
        .interpolate_base_polynomial_in_place(&mut left_evaluations)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    left_evaluations.resize(transform_size, ProofBaseFieldElement::ZERO);
    let coefficient_count = left.len();
    let result = (0..coefficient_count)
        .map(|coefficient_ordinal| {
            centered_base_field_value(
                left_evaluations[coefficient_ordinal]
                    .subtract(left_evaluations[coefficient_ordinal + coefficient_count]),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Zeroizing::new(result))
}

fn signed_integer_to_base_field(value: i128) -> Result<ProofBaseFieldElement, RefusalReason> {
    if value >= 0 {
        ProofBaseFieldElement::from_canonical(
            u64::try_from(value).map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)
    } else {
        let magnitude = u64::try_from(value.unsigned_abs())
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        if magnitude >= PROOF_BASE_FIELD_MODULUS {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MODULUS - magnitude)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)
    }
}

fn centered_base_field_value(value: ProofBaseFieldElement) -> Result<i128, RefusalReason> {
    let canonical = value.canonical();
    if canonical <= PROOF_BASE_FIELD_MODULUS / 2 {
        Ok(i128::from(canonical))
    } else {
        Ok(i128::from(canonical) - i128::from(PROOF_BASE_FIELD_MODULUS))
    }
}

fn resolve_integer_lift_coefficient(
    coefficient: RelationIntegerLiftCoefficient,
    context: &RelationPlanCheckContext,
) -> Result<u64, RefusalReason> {
    match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => Ok(value),
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => context
            .resolved_modulus(modulus_reference)
            .ok()
            .and_then(|modulus| modulus.checked_mul(u64::from(multiplier)))
            .ok_or(RefusalReason::InvalidArithmeticRelation),
        RelationIntegerLiftCoefficient::ModulusRadixDigit {
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
        } => resolved_modulus_radix_digit(
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
            context,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation),
    }
}

#[allow(clippy::too_many_arguments)]
fn canonical_comparator_column_rows(
    target: &[i128],
    modulus: u64,
    radix: u64,
    digit_columns: &[u32],
    difference_columns: &[u32],
    borrow_columns: &[u32],
    requested_column_ordinal: u32,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    if digit_columns.is_empty()
        || digit_columns.len() != difference_columns.len()
        || borrow_columns.len() + 1 != digit_columns.len()
    {
        return Err(RefusalReason::InvalidArithmeticRelation);
    }
    let maximum = modulus
        .checked_sub(1)
        .ok_or(RefusalReason::InvalidArithmeticRelation)?;
    let maximum_digits = fixed_radix_digits(i128::from(maximum), digit_columns.len(), radix)?;
    let mut requested_rows = Zeroizing::new(Vec::with_capacity(target.len()));
    for value in target {
        if *value < 0 || *value >= i128::from(modulus) {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        let value_digits = fixed_radix_digits(*value, digit_columns.len(), radix)?;
        let mut incoming_borrow = 0_i128;
        let mut selected_value = None;
        for digit_ordinal in 0..digit_columns.len() {
            let raw_difference = i128::from(maximum_digits[digit_ordinal])
                - i128::from(value_digits[digit_ordinal])
                - incoming_borrow;
            let outgoing_borrow = i128::from(raw_difference < 0);
            let difference = raw_difference + outgoing_borrow * i128::from(radix);
            if digit_columns[digit_ordinal] == requested_column_ordinal {
                selected_value = Some(i128::from(value_digits[digit_ordinal]));
            }
            if difference_columns[digit_ordinal] == requested_column_ordinal {
                selected_value = Some(difference);
            }
            if digit_ordinal < borrow_columns.len()
                && borrow_columns[digit_ordinal] == requested_column_ordinal
            {
                selected_value = Some(outgoing_borrow);
            }
            incoming_borrow = outgoing_borrow;
        }
        if incoming_borrow != 0 {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        requested_rows.push(selected_value.ok_or(RefusalReason::WrongTypeOrLength)?);
    }
    Ok(requested_rows)
}

fn fixed_radix_digits(
    mut value: i128,
    digit_count: usize,
    radix: u64,
) -> Result<Vec<u64>, RefusalReason> {
    if value < 0 || digit_count == 0 || radix < 2 {
        return Err(RefusalReason::InvalidArithmeticRelation);
    }
    let radix = i128::from(radix);
    let mut digits = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        digits.push(
            u64::try_from(value % radix).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        );
        value /= radix;
    }
    if value != 0 {
        return Err(RefusalReason::InvalidArithmeticRelation);
    }
    Ok(digits)
}
