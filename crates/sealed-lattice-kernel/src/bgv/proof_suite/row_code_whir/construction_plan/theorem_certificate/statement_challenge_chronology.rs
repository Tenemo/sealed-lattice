use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionInitialTranscriptBinding {
    ProtocolSuiteConstructionSchemaAndCanonicalProofHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionChallengeChronologyRow {
    operation_ordinal: u32,
    immediate_predecessor_operation_ordinal: u32,
    verifier_message_round_ordinal: u64,
    output_byte_length: u64,
    fixed_hash_query_count: u64,
    failure_event_owner: SelectedPlanFailureEventOwner,
}

/// Finite production-plan proof that the statement-bearing canonical header is
/// absorbed before every verifier message owned by this physical proof.
///
/// This is derived from the same oracle-equation catalog and semantic state
/// transition rows consumed by the mapped CMS transform. It is not a caller-
/// supplied chronology flag.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionStatementChallengeChronologyCertificate {
    construction_plan_identity_hash: [u8; 64],
    initial_binding: ProductionInitialTranscriptBinding,
    initial_operation_ordinal: u32,
    canonical_header_root_equation_slot_ordinal: u64,
    initial_absorption_equation_slot_ordinal: u64,
    challenge_rows: Vec<ProductionChallengeChronologyRow>,
}

impl ProductionStatementChallengeChronologyCertificate {
    fn derive_from_geometry(
        plan: &RowCodeWhirConstructionPlan,
        geometry: &RowCodeWhirProductionGeometryCertificate,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if !geometry.is_complete()
            || geometry.construction_plan_identity_hash
                != plan
                    .canonical_identity_hash()
                    .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        Self::derive_from_parts(
            plan,
            &geometry.selected_plan_state_predicate,
            &geometry.cms19_whole_state_transitions,
            geometry.logical_verifier_message_count,
        )
    }

    fn derive_from_parts(
        plan: &RowCodeWhirConstructionPlan,
        selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
        whole_state_transitions: &Cms19WholeStateTransitionCertificate,
        logical_verifier_message_count: u64,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let catalog = plan
            .oracle_equation_catalog()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        if !whole_state_transitions.is_complete_for(plan, &catalog, selected_plan_state_predicate) {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let initial_operation = catalog
            .operations
            .first()
            .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        let initial_state_row = whole_state_transitions
            .rows
            .first()
            .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        let [header_root_range, initial_absorption_range] = initial_operation.ranges.as_slice()
        else {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        };
        if initial_operation.operation_ordinal != 0
            || initial_operation.predecessor_operation_ordinal.is_some()
            || initial_operation.first_equation_slot_ordinal != 0
            || initial_operation.kind != RowCodeWhirOracleEquationOperationKind::InitialTranscript
            || initial_operation.oracle_tag.is_some()
            || header_root_range.kind != RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot
            || header_root_range.predecessor != RowCodeWhirOracleEquationPredecessor::Independent
            || initial_absorption_range.kind
                != RowCodeWhirOracleEquationRangeKind::InitialAbsorption
            || initial_absorption_range.predecessor
                != RowCodeWhirOracleEquationPredecessor::FixedZeroState
            || initial_state_row.operation_ordinal != 0
            || initial_state_row.predecessor_operation_ordinal.is_some()
            || initial_state_row.transition != Cms19SemanticStateTransition::InitialCanonicalPrefix
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }

        let mut challenge_rows = Vec::new();
        for (operation, state_row) in catalog.operations.iter().zip(&whole_state_transitions.rows) {
            let Cms19SemanticStateTransition::VerifierMessageFill {
                round_ordinal,
                output_byte_length,
                failure_event_owner,
                ..
            } = state_row.transition
            else {
                continue;
            };
            let immediate_predecessor_operation_ordinal = operation
                .operation_ordinal
                .checked_sub(1)
                .filter(|predecessor| operation.predecessor_operation_ordinal == Some(*predecessor))
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
            let mut atomic_challenge_ranges =
                operation
                    .ranges
                    .iter()
                    .filter_map(|range| match range.kind {
                        RowCodeWhirOracleEquationRangeKind::AtomicChallengeSeededHashStream {
                            output_byte_length,
                            fixed_hash_query_count,
                        } => Some((output_byte_length, fixed_hash_query_count)),
                        _ => None,
                    });
            if !oracle_equation_operation_leaves_pending_challenge(&operation.kind)
                || atomic_challenge_ranges.next()
                    != Some((
                        output_byte_length,
                        atomic_challenge_fixed_hash_query_count(output_byte_length).map_err(
                            |_| WhirTheoremCertificateError::IncompleteTranscriptMapping,
                        )?,
                    ))
                || atomic_challenge_ranges.next().is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            challenge_rows.push(ProductionChallengeChronologyRow {
                operation_ordinal: operation.operation_ordinal,
                immediate_predecessor_operation_ordinal,
                verifier_message_round_ordinal: round_ordinal,
                output_byte_length,
                fixed_hash_query_count: atomic_challenge_fixed_hash_query_count(output_byte_length)
                    .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
                failure_event_owner,
            });
        }
        let certificate = Self {
            construction_plan_identity_hash: plan
                .canonical_identity_hash()
                .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
            initial_binding:
                ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader,
            initial_operation_ordinal: initial_operation.operation_ordinal,
            canonical_header_root_equation_slot_ordinal: initial_operation
                .first_equation_slot_ordinal
                .checked_add(header_root_range.first_equation_offset)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            initial_absorption_equation_slot_ordinal: initial_operation
                .first_equation_slot_ordinal
                .checked_add(initial_absorption_range.first_equation_offset)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            challenge_rows,
        };
        if !certificate.is_self_consistent(logical_verifier_message_count)
            || !plan
                .canonical_identity_hash()
                .is_ok_and(|identity| identity == certificate.construction_plan_identity_hash)
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        Ok(certificate)
    }

    fn is_self_consistent(&self, logical_verifier_message_count: u64) -> bool {
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.initial_binding
                == ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader
            && self.initial_operation_ordinal == 0
            && self.canonical_header_root_equation_slot_ordinal == 0
            && self.initial_absorption_equation_slot_ordinal == 1
            && u64::try_from(self.challenge_rows.len()).ok()
                == Some(logical_verifier_message_count)
            && !self.challenge_rows.is_empty()
            && self.challenge_rows.iter().all(|row| {
                row.operation_ordinal > self.initial_operation_ordinal
                    && row.immediate_predecessor_operation_ordinal
                        == row.operation_ordinal - 1
                    && row.verifier_message_round_ordinal > 0
                    && row.output_byte_length > 0
                    && atomic_challenge_fixed_hash_query_count(row.output_byte_length).ok()
                        == Some(row.fixed_hash_query_count)
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProductionStatementChallengeChronologySummary {
    pub(super) construction_plan_identity_hash: [u8; 64],
    pub(super) logical_challenge_count: u64,
    pub(super) first_challenge_operation_ordinal: u32,
    pub(super) last_challenge_operation_ordinal: u32,
    pub(super) canonical_statement_and_header_are_absorbed_first: bool,
    pub(super) every_challenge_has_immediate_predecessor: bool,
}

pub(super) fn checked_production_statement_challenge_chronology_summary(
    plan: &RowCodeWhirConstructionPlan,
    geometry: &RowCodeWhirProductionGeometryCertificate,
) -> Result<ProductionStatementChallengeChronologySummary, WhirTheoremCertificateError> {
    let certificate =
        ProductionStatementChallengeChronologyCertificate::derive_from_geometry(plan, geometry)?;
    let first_challenge_operation_ordinal = certificate
        .challenge_rows
        .first()
        .map(|row| row.operation_ordinal)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let last_challenge_operation_ordinal = certificate
        .challenge_rows
        .last()
        .map(|row| row.operation_ordinal)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    Ok(ProductionStatementChallengeChronologySummary {
        construction_plan_identity_hash: certificate.construction_plan_identity_hash,
        logical_challenge_count: u64::try_from(certificate.challenge_rows.len())
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        first_challenge_operation_ordinal,
        last_challenge_operation_ordinal,
        canonical_statement_and_header_are_absorbed_first: certificate.initial_operation_ordinal
            == 0
            && certificate.canonical_header_root_equation_slot_ordinal == 0
            && certificate.initial_absorption_equation_slot_ordinal == 1
            && first_challenge_operation_ordinal > certificate.initial_operation_ordinal,
        every_challenge_has_immediate_predecessor: certificate.challenge_rows.iter().all(|row| {
            row.immediate_predecessor_operation_ordinal.checked_add(1)
                == Some(row.operation_ordinal)
        }),
    })
}
