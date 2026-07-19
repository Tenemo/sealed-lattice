use super::super::canonical_common_proof_byte_length_ceiling;
use super::{
    CanonicalItem, CanonicalTuple, CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
    CommonProofTranscript, CommonProofVerifierError, CompiledRelationPlan, DecodedProofBodyPrefix,
    PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER, PROOF_OBJECT_HEADER_SCHEMA_VERSION, ProofBodyError,
    ProofBodyLayout, ProofByteSource, ProofDecodeError, ProofEvaluationDomain,
    ProofFriQueryVerifier, ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeRole,
    ProofTreeValue, QueryVerificationWorkspace, RelationApplicationChallengeAssignment,
    RelationPlanCheckContext, RelationPlanVariant, SELECTED_PROOF_FIELD_INDEX,
    ValidatedRelationPlanArtifact, VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree, absorb_relation_roots,
    build_complete_proof_tree_catalog, build_runtime_claim_groups, catalog_root,
    decode_application_statement, decode_proof_body_prefix_owned,
    decode_proof_query_section_header_at, decode_proof_query_tree_at, derive_relation_tree_inputs,
    proof_body_prefix_byte_length, proof_query_tree_byte_length,
    validate_evaluator_auxiliary_root_linkage, verified_application_statement_hash,
    verified_proof_header_hash, verify_statement_derived_deep_values,
};

/// Inputs that have already crossed their family-specific trust boundaries.
/// The application wrapper owns statement/source resolution; proof bytes never
/// supply any value in this structure.
pub(crate) struct CommonProofVerificationInput<'input, Source: ProofByteSource + ?Sized> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; 64],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) statement_owned_trees: &'input [VerifiedStatementOwnedTree],
    pub(crate) evaluator_auxiliary_roots: &'input [VerifiedEvaluatorAuxiliaryRoot],
    pub(crate) proof_source: &'input Source,
    pub(crate) declared_proof_byte_length: usize,
    pub(crate) proof_byte_ceiling: usize,
}

pub(crate) struct PollableCommonProofVerificationInput<'input> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; 64],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) statement_owned_trees: &'input [VerifiedStatementOwnedTree],
    pub(crate) evaluator_auxiliary_roots: &'input [VerifiedEvaluatorAuxiliaryRoot],
    pub(crate) declared_proof_byte_length: usize,
    pub(crate) proof_byte_ceiling: usize,
    pub(crate) maximum_resident_window_byte_length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofRequiredByteRange {
    offset: usize,
    byte_length: usize,
}

impl CommonProofRequiredByteRange {
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }

    pub(crate) const fn byte_length(self) -> usize {
        self.byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerificationPoll {
    PrefixAccepted,
    QueryHeaderAccepted,
    QueryTreeAccepted { catalog_index: u16 },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofVerificationPhase {
    AwaitingPrefix,
    AwaitingQueryHeader,
    AwaitingQueryTree { catalog_index: usize },
    Complete,
    Cancelled,
}

/// Persistent bounded verifier.  The proof prefix is decoded once, each
/// authenticated opening advances the transcript and algebra workspace once,
/// and no verified token exists before the terminal query and trailing-byte
/// checks complete.
pub(crate) struct CommonProofVerificationStateMachine {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    canonical_application_statement_bytes: Vec<u8>,
    application_statement_schema_identifier: u16,
    relation_context: RelationPlanCheckContext,
    variant: RelationPlanVariant,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    declared_proof_byte_length: usize,
    proof_byte_ceiling: usize,
    maximum_resident_window_byte_length: usize,
    canonical_proof_object_header_bytes: Vec<u8>,
    proof_body_byte_length: usize,
    prefix_end_absolute_offset: usize,
    transcript_schedule: super::super::CommonProofTranscriptSchedule,
    evaluation_domain: ProofEvaluationDomain,
    layout: ProofBodyLayout,
    phase: CommonProofVerificationPhase,
    current_body_offset: usize,
    query_tree_byte_lengths: Vec<usize>,
    tree_roots: Vec<[u8; 64]>,
    sorted_query_representatives: Vec<u64>,
    transcript: Option<CommonProofTranscript>,
    query_opening_absorber: Option<CommonProofQueryOpeningAbsorber>,
    workspace: Option<QueryVerificationWorkspace>,
    verified_common_proof: Option<VerifiedCommonProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofVerificationResidentMemoryAccounting {
    fixed_and_plan_resident_byte_length: u64,
    maximum_post_prefix_resident_byte_length: u64,
    maximum_decoding_transient_byte_length: u64,
    maximum_resident_byte_length: u64,
}

impl CommonProofVerificationResidentMemoryAccounting {
    pub(crate) const fn fixed_and_plan_resident_byte_length(self) -> u64 {
        self.fixed_and_plan_resident_byte_length
    }

    pub(crate) const fn maximum_post_prefix_resident_byte_length(self) -> u64 {
        self.maximum_post_prefix_resident_byte_length
    }

    pub(crate) const fn maximum_decoding_transient_byte_length(self) -> u64 {
        self.maximum_decoding_transient_byte_length
    }

    pub(crate) const fn maximum_resident_byte_length(self) -> u64 {
        self.maximum_resident_byte_length
    }
}

pub(super) struct ProofBodyByteSource<'source, Source: ProofByteSource + ?Sized> {
    source: &'source Source,
    body_offset: usize,
    body_byte_length: usize,
}

impl<Source: ProofByteSource + ?Sized> ProofByteSource for ProofBodyByteSource<'_, Source> {
    fn byte_length(&self) -> usize {
        self.body_byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(relative_end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if relative_end > self.body_byte_length {
            return false;
        }
        let Some(absolute_offset) = self.body_offset.checked_add(offset) else {
            return false;
        };
        self.source.copy_bytes(absolute_offset, destination)
    }
}

impl CommonProofVerificationStateMachine {
    pub(crate) fn new(
        input: PollableCommonProofVerificationInput<'_>,
    ) -> Result<Self, CommonProofVerifierError> {
        let _validated_artifact = ValidatedRelationPlanArtifact::from_compiled_plan(
            input.relation_plan,
            input.relation_context,
        )?;
        let application_statement = decode_application_statement(
            input.canonical_application_statement_bytes,
            input
                .relation_plan
                .application_statement_schema_identifier(),
            input.protocol_version,
            input.suite_identifier,
            input.schedule_position,
            input.top_count,
            input.relation_context,
        )?;
        validate_evaluator_auxiliary_root_linkage(
            &application_statement,
            input
                .relation_plan
                .application_statement_schema_identifier(),
            input.schedule_position,
            input.top_count,
            input.evaluator_auxiliary_roots,
            input.relation_context,
        )?;
        let canonical_proof_object_header_bytes = CanonicalTuple::new(
            PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
            PROOF_OBJECT_HEADER_SCHEMA_VERSION,
            vec![
                CanonicalItem::variable_bytes(input.canonical_application_statement_bytes)
                    .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?,
            ],
        )
        .encode()
        .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?;
        if input.declared_proof_byte_length == 0 {
            return Err(ProofBodyError::Decode(ProofDecodeError::EmptyProof).into());
        }
        if input.declared_proof_byte_length > input.proof_byte_ceiling {
            return Err(ProofBodyError::Decode(ProofDecodeError::ProofByteCeilingExceeded).into());
        }
        let proof_body_byte_length = input
            .declared_proof_byte_length
            .checked_sub(canonical_proof_object_header_bytes.len())
            .filter(|length| *length > 0)
            .ok_or(CommonProofVerifierError::InvalidProofHeader)?;
        let variant = input
            .relation_plan
            .select_variant(input.schedule_position, input.top_count)?;
        let transcript_schedule =
            variant.common_proof_transcript_schedule(input.relation_context)?;
        let evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(variant.evaluation_domain_size())
                .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            input.relation_context.evaluation_coset_offset,
        )?;
        if evaluation_domain.generator().canonical()
            != input.relation_context.evaluation_domain_generator
        {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        let relation_trees = derive_relation_tree_inputs(
            variant,
            &application_statement,
            input.statement_owned_trees,
        )?;
        let catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: input.suite_identifier,
                canonical_proof_object_header_bytes: canonical_proof_object_header_bytes.clone(),
                application_statement_schema_identifier: input
                    .relation_plan
                    .application_statement_schema_identifier(),
                proof_field_index: SELECTED_PROOF_FIELD_INDEX,
                evaluation_domain_size: variant.evaluation_domain_size(),
                relation_trees,
            },
            &transcript_schedule,
        )?;
        let layout = ProofBodyLayout::new(
            catalog,
            &transcript_schedule,
            transcript_schedule.terminal_coefficient_count(),
        )?;
        let prefix_end_absolute_offset = canonical_proof_object_header_bytes
            .len()
            .checked_add(proof_body_prefix_byte_length(&layout)?)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        if input.maximum_resident_window_byte_length == 0
            || prefix_end_absolute_offset > input.maximum_resident_window_byte_length
            || prefix_end_absolute_offset >= input.declared_proof_byte_length
        {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }

        Ok(Self {
            protocol_version: input.protocol_version,
            suite_identifier: input.suite_identifier,
            canonical_application_statement_bytes: input
                .canonical_application_statement_bytes
                .to_vec(),
            application_statement_schema_identifier: input
                .relation_plan
                .application_statement_schema_identifier(),
            relation_context: input.relation_context.clone(),
            variant: variant.clone(),
            schedule_position: input.schedule_position,
            top_count: input.top_count,
            declared_proof_byte_length: input.declared_proof_byte_length,
            proof_byte_ceiling: input.proof_byte_ceiling,
            maximum_resident_window_byte_length: input.maximum_resident_window_byte_length,
            canonical_proof_object_header_bytes,
            proof_body_byte_length,
            prefix_end_absolute_offset,
            transcript_schedule,
            evaluation_domain,
            layout,
            phase: CommonProofVerificationPhase::AwaitingPrefix,
            current_body_offset: 0,
            query_tree_byte_lengths: Vec::new(),
            tree_roots: Vec::new(),
            sorted_query_representatives: Vec::new(),
            transcript: None,
            query_opening_absorber: None,
            workspace: None,
            verified_common_proof: None,
        })
    }

    pub(crate) fn required_byte_range(&self) -> Option<CommonProofRequiredByteRange> {
        match self.phase {
            CommonProofVerificationPhase::AwaitingPrefix => Some(CommonProofRequiredByteRange {
                offset: 0,
                byte_length: self.prefix_end_absolute_offset,
            }),
            CommonProofVerificationPhase::AwaitingQueryHeader => {
                let absolute_offset = self
                    .canonical_proof_object_header_bytes
                    .len()
                    .checked_add(self.current_body_offset)?;
                Some(CommonProofRequiredByteRange {
                    offset: absolute_offset,
                    byte_length: 4,
                })
            }
            CommonProofVerificationPhase::AwaitingQueryTree { catalog_index } => {
                let absolute_offset = self
                    .canonical_proof_object_header_bytes
                    .len()
                    .checked_add(self.current_body_offset)?;
                Some(CommonProofRequiredByteRange {
                    offset: absolute_offset,
                    byte_length: *self.query_tree_byte_lengths.get(catalog_index)?,
                })
            }
            CommonProofVerificationPhase::Complete | CommonProofVerificationPhase::Cancelled => {
                None
            }
        }
    }

    pub(crate) fn poll<Source, ColumnEvaluator>(
        &mut self,
        source: &Source,
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<CommonProofVerificationPoll, CommonProofVerifierError>
    where
        Source: ProofByteSource + ?Sized,
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let result = self.poll_once(source, evaluate_verified_column);
        if result.is_err() {
            self.cancel();
        }
        result
    }

    fn poll_once<Source, ColumnEvaluator>(
        &mut self,
        source: &Source,
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<CommonProofVerificationPoll, CommonProofVerifierError>
    where
        Source: ProofByteSource + ?Sized,
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        match self.phase {
            CommonProofVerificationPhase::Cancelled => {
                return Err(CommonProofVerifierError::Cancelled);
            }
            CommonProofVerificationPhase::Complete => {
                return Ok(CommonProofVerificationPoll::Complete);
            }
            _ => {}
        }
        if source.byte_length() != self.declared_proof_byte_length {
            return Err(ProofBodyError::Decode(ProofDecodeError::DeclaredLengthMismatch).into());
        }
        let required_range = self
            .required_byte_range()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        ensure_required_range_is_resident(source, required_range)?;
        let proof_body_source = if self.phase == CommonProofVerificationPhase::AwaitingPrefix {
            verify_and_slice_proof_header(
                source,
                self.declared_proof_byte_length,
                self.proof_byte_ceiling,
                &self.canonical_proof_object_header_bytes,
            )?
        } else {
            ProofBodyByteSource {
                source,
                body_offset: self.canonical_proof_object_header_bytes.len(),
                body_byte_length: self.proof_body_byte_length,
            }
        };

        match self.phase {
            CommonProofVerificationPhase::AwaitingPrefix => {
                let proof_body_byte_ceiling = self
                    .proof_byte_ceiling
                    .checked_sub(self.canonical_proof_object_header_bytes.len())
                    .ok_or(CommonProofVerifierError::InvalidProofHeader)?;
                let prefix = decode_proof_body_prefix_owned(
                    &proof_body_source,
                    self.proof_body_byte_length,
                    proof_body_byte_ceiling,
                    &self.layout,
                )?;
                let expected_query_section_offset = self
                    .prefix_end_absolute_offset
                    .checked_sub(self.canonical_proof_object_header_bytes.len())
                    .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
                if prefix.query_section_offset() != expected_query_section_offset {
                    return Err(CommonProofVerifierError::InvalidTreeLayout);
                }
                self.prepare_query_verification(prefix, evaluate_verified_column)?;
                self.current_body_offset = expected_query_section_offset;
                self.phase = CommonProofVerificationPhase::AwaitingQueryHeader;
                Ok(CommonProofVerificationPoll::PrefixAccepted)
            }
            CommonProofVerificationPhase::AwaitingQueryHeader => {
                let next_body_offset = decode_proof_query_section_header_at(
                    &proof_body_source,
                    self.current_body_offset,
                    self.layout.catalog().entries().len(),
                )?;
                if next_body_offset
                    != self
                        .current_body_offset
                        .checked_add(4)
                        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?
                {
                    return Err(CommonProofVerifierError::InvalidTreeLayout);
                }
                self.absorb_body_range(
                    &proof_body_source,
                    self.current_body_offset,
                    next_body_offset,
                )?;
                self.current_body_offset = next_body_offset;
                self.phase = CommonProofVerificationPhase::AwaitingQueryTree { catalog_index: 0 };
                Ok(CommonProofVerificationPoll::QueryHeaderAccepted)
            }
            CommonProofVerificationPhase::AwaitingQueryTree { catalog_index } => {
                let expected_tree_byte_length = *self
                    .query_tree_byte_lengths
                    .get(catalog_index)
                    .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
                let expected_root = *self
                    .tree_roots
                    .get(catalog_index)
                    .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
                let (next_body_offset, decoded_opening) = decode_proof_query_tree_at(
                    &proof_body_source,
                    self.current_body_offset,
                    &self.layout,
                    catalog_index,
                    expected_root,
                    &self.sorted_query_representatives,
                )?;
                if next_body_offset
                    != self
                        .current_body_offset
                        .checked_add(expected_tree_byte_length)
                        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?
                {
                    return Err(CommonProofVerifierError::InvalidTreeLayout);
                }
                {
                    let catalog_entry = self
                        .layout
                        .catalog()
                        .entries()
                        .get(catalog_index)
                        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
                    self.workspace
                        .as_mut()
                        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?
                        .consume_opening(
                            decoded_opening.as_opening(catalog_entry),
                            &self.variant,
                            self.layout.catalog(),
                            &self.sorted_query_representatives,
                            evaluate_verified_column,
                        )?;
                }
                self.absorb_body_range(
                    &proof_body_source,
                    self.current_body_offset,
                    next_body_offset,
                )?;
                self.current_body_offset = next_body_offset;
                let next_catalog_index = catalog_index + 1;
                if next_catalog_index < self.layout.catalog().entries().len() {
                    self.phase = CommonProofVerificationPhase::AwaitingQueryTree {
                        catalog_index: next_catalog_index,
                    };
                    Ok(CommonProofVerificationPoll::QueryTreeAccepted {
                        catalog_index: u16::try_from(catalog_index)
                            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
                    })
                } else {
                    self.finish_verification()?;
                    Ok(CommonProofVerificationPoll::Complete)
                }
            }
            CommonProofVerificationPhase::Complete | CommonProofVerificationPhase::Cancelled => {
                unreachable!()
            }
        }
    }

    fn prepare_query_verification<ColumnEvaluator>(
        &mut self,
        prefix: DecodedProofBodyPrefix,
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<(), CommonProofVerifierError>
    where
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let mut transcript = CommonProofTranscript::new(
            self.protocol_version,
            self.suite_identifier,
            self.application_statement_schema_identifier,
            &self.canonical_proof_object_header_bytes,
            self.transcript_schedule.clone(),
        )?;
        absorb_relation_roots(
            &mut transcript,
            self.layout.catalog(),
            prefix.tree_roots(),
            ProofTreeRole::BaseOracle,
            self.transcript_schedule.ordered_base_tree_ordinals(),
        )?;

        let mut application_challenges = Vec::new();
        application_challenges
            .try_reserve_exact(
                self.transcript_schedule
                    .ordered_application_challenge_groups()
                    .iter()
                    .try_fold(0_usize, |count, group| {
                        count.checked_add(usize::from(group.coordinate_count()))
                    })
                    .ok_or(CommonProofVerifierError::InvalidTreeLayout)?,
            )
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        for scheduled_group in self
            .transcript_schedule
            .ordered_application_challenge_groups()
        {
            let challenge = scheduled_group.challenge();
            let values = transcript.sample_application_challenge_group(challenge)?;
            if values.len() != usize::from(scheduled_group.coordinate_count()) {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            for (repetition_ordinal, value) in values.into_iter().enumerate() {
                application_challenges.push(RelationApplicationChallengeAssignment::new(
                    challenge,
                    u16::try_from(repetition_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
                    value,
                )?);
            }
        }
        absorb_relation_roots(
            &mut transcript,
            self.layout.catalog(),
            prefix.tree_roots(),
            ProofTreeRole::AuxiliaryOracle,
            self.transcript_schedule.ordered_auxiliary_tree_ordinals(),
        )?;

        let mut composition_challenges = Vec::new();
        composition_challenges
            .try_reserve_exact(usize::from(
                self.transcript_schedule.composition_challenge_count(),
            ))
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        for constraint_ordinal in 0..self.transcript_schedule.composition_challenge_count() {
            composition_challenges
                .push(transcript.sample_composition_challenge(constraint_ordinal)?);
        }
        for component_ordinal in 0..self.transcript_schedule.quotient_component_count() {
            transcript.absorb_quotient_root(
                component_ordinal,
                catalog_root(self.layout.catalog(), prefix.tree_roots(), |source| {
                    source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                })?,
            )?;
        }

        let mut deep_points = Vec::new();
        deep_points
            .try_reserve_exact(usize::from(self.transcript_schedule.deep_point_count()))
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        for point_ordinal in 0..self.transcript_schedule.deep_point_count() {
            let mut relation_error = None;
            let sampled = transcript.sample_deep_point(point_ordinal, |candidate| {
                match self.variant.deep_point_candidate_is_forbidden(
                    &self.relation_context,
                    point_ordinal,
                    candidate,
                    &deep_points,
                ) {
                    Ok(is_forbidden) => is_forbidden,
                    Err(error) => {
                        relation_error = Some(error);
                        true
                    }
                }
            });
            if let Some(error) = relation_error {
                return Err(error.into());
            }
            deep_points.push(sampled?);
        }
        let opening_points = self
            .variant
            .derive_opening_points(&self.relation_context, &deep_points)?;
        verify_statement_derived_deep_values(
            &self.variant,
            &opening_points,
            prefix.deep_evaluations(),
            evaluate_verified_column,
        )?;
        self.variant.verify_deep_composition(
            &self.relation_context,
            &application_challenges,
            &composition_challenges,
            &deep_points,
            prefix.deep_evaluations(),
        )?;
        transcript.absorb_deep_evaluations(prefix.deep_evaluations())?;

        if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing {
            transcript.absorb_opening_batch_mask_root(catalog_root(
                self.layout.catalog(),
                prefix.tree_roots(),
                |source| source == ProofTreeCatalogSource::OpeningBatchMask,
            )?)?;
        }
        let mut opening_batch_coefficients = Vec::new();
        let opening_claim_count = usize::try_from(self.transcript_schedule.opening_claim_count())
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        opening_batch_coefficients
            .try_reserve_exact(opening_claim_count)
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        for claim_ordinal in 0..self.transcript_schedule.opening_claim_count() {
            opening_batch_coefficients
                .push(transcript.sample_opening_batch_challenge(claim_ordinal)?);
        }

        let mut fri_fold_challenges = Vec::new();
        fri_fold_challenges
            .try_reserve_exact(usize::from(self.transcript_schedule.fri_fold_count()))
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        for fold_ordinal in 0..self.transcript_schedule.fri_fold_count() {
            fri_fold_challenges.push(transcript.sample_fri_fold_challenge(fold_ordinal)?);
            if fold_ordinal + 1 < self.transcript_schedule.fri_fold_count() {
                transcript.absorb_fri_layer_root(
                    fold_ordinal,
                    catalog_root(self.layout.catalog(), prefix.tree_roots(), |source| {
                        source == ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal }
                    })?,
                )?;
            }
        }
        transcript.absorb_fri_terminal_coefficients(prefix.terminal_coefficients())?;
        let mut sampled_query_representatives = transcript.sample_query_representatives()?;
        let sorted_query_representatives = transcript.sorted_query_representatives()?;
        sampled_query_representatives.sort_unstable();
        if sampled_query_representatives != sorted_query_representatives {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }

        let claim_groups = build_runtime_claim_groups(
            &self.variant,
            self.layout.catalog(),
            &opening_points,
            prefix.deep_evaluations(),
            &opening_batch_coefficients,
        )?;
        let fri_verifier = ProofFriQueryVerifier::new(
            self.evaluation_domain,
            fri_fold_challenges,
            prefix.terminal_coefficients().to_vec(),
            usize::try_from(
                self.relation_context
                    .final_polynomial_degree_bound_exclusive,
            )
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
        )?;
        let workspace = QueryVerificationWorkspace::new(
            self.layout.catalog().entries().len(),
            self.evaluation_domain,
            sorted_query_representatives.len(),
            claim_groups,
            fri_verifier,
        )?;
        let query_section_byte_length = self
            .proof_body_byte_length
            .checked_sub(prefix.query_section_offset())
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let mut query_tree_byte_lengths = Vec::new();
        query_tree_byte_lengths
            .try_reserve_exact(self.layout.catalog().entries().len())
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        let mut expected_query_section_byte_length = 4_usize;
        for catalog_index in 0..self.layout.catalog().entries().len() {
            let tree_byte_length = proof_query_tree_byte_length(
                &self.layout,
                catalog_index,
                &sorted_query_representatives,
            )?;
            if tree_byte_length > self.maximum_resident_window_byte_length {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            expected_query_section_byte_length = expected_query_section_byte_length
                .checked_add(tree_byte_length)
                .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
            query_tree_byte_lengths.push(tree_byte_length);
        }
        if expected_query_section_byte_length > query_section_byte_length {
            return Err(ProofBodyError::Decode(ProofDecodeError::Truncated).into());
        }
        let query_opening_absorber = transcript.begin_query_openings(query_section_byte_length)?;

        self.tree_roots = prefix.tree_roots().to_vec();
        self.sorted_query_representatives = sorted_query_representatives;
        self.query_tree_byte_lengths = query_tree_byte_lengths;
        self.transcript = Some(transcript);
        self.query_opening_absorber = Some(query_opening_absorber);
        self.workspace = Some(workspace);
        Ok(())
    }

    fn absorb_body_range<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        start_offset: usize,
        end_offset: usize,
    ) -> Result<(), CommonProofVerifierError> {
        if end_offset <= start_offset || end_offset > self.proof_body_byte_length {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        let absorber = self
            .query_opening_absorber
            .as_mut()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let mut offset = start_offset;
        let mut scratch = [0_u8; 256];
        while offset < end_offset {
            let chunk_byte_length = scratch.len().min(end_offset - offset);
            let chunk = &mut scratch[..chunk_byte_length];
            if !source.copy_bytes(offset, chunk) {
                return Err(ProofBodyError::Decode(ProofDecodeError::Truncated).into());
            }
            absorber.absorb(chunk)?;
            offset += chunk_byte_length;
        }
        Ok(())
    }

    fn finish_verification(&mut self) -> Result<(), CommonProofVerifierError> {
        if self.current_body_offset != self.proof_body_byte_length {
            return Err(ProofBodyError::Decode(ProofDecodeError::TrailingBytes).into());
        }
        self.workspace
            .as_mut()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?
            .finish(
                self.layout.catalog().entries().len(),
                &self.sorted_query_representatives,
            )?;
        let query_opening_absorber = self
            .query_opening_absorber
            .take()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let mut transcript = self
            .transcript
            .take()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        transcript.finish_query_openings(query_opening_absorber)?;
        transcript.finish()?;

        self.verified_common_proof = Some(VerifiedCommonProof {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            application_statement_schema_identifier: self.application_statement_schema_identifier,
            application_statement_hash: verified_application_statement_hash(
                self.protocol_version,
                self.suite_identifier,
                self.application_statement_schema_identifier,
                &self.canonical_application_statement_bytes,
            ),
            proof_header_hash: verified_proof_header_hash(
                &self.canonical_proof_object_header_bytes,
            )?,
            proof_byte_length: u64::try_from(self.declared_proof_byte_length)
                .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            verified_query_count: self.transcript_schedule.unique_query_count(),
            relation_plan_variant_hash: self.variant.canonical_hash()?,
            schedule_position: self.schedule_position,
            top_count: self.top_count,
        });
        self.phase = CommonProofVerificationPhase::Complete;
        Ok(())
    }

    pub(crate) fn take_verified_common_proof(&mut self) -> Option<VerifiedCommonProof> {
        if self.phase != CommonProofVerificationPhase::Complete {
            return None;
        }
        self.verified_common_proof.take()
    }

    pub(crate) fn cancel(&mut self) {
        self.phase = CommonProofVerificationPhase::Cancelled;
        self.tree_roots.clear();
        self.sorted_query_representatives.clear();
        self.transcript = None;
        self.query_opening_absorber = None;
        self.workspace = None;
        self.verified_common_proof = None;
    }
}

fn ensure_required_range_is_resident<Source: ProofByteSource + ?Sized>(
    source: &Source,
    required_range: CommonProofRequiredByteRange,
) -> Result<(), CommonProofVerifierError> {
    if required_range.byte_length == 0 {
        return Err(ProofBodyError::Decode(ProofDecodeError::Truncated).into());
    }
    let final_offset = required_range
        .offset
        .checked_add(required_range.byte_length - 1)
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    let mut byte = [0_u8; 1];
    if !source.copy_bytes(required_range.offset, &mut byte)
        || !source.copy_bytes(final_offset, &mut byte)
    {
        return Err(ProofBodyError::Decode(ProofDecodeError::Truncated).into());
    }
    Ok(())
}

pub(super) fn verify_and_slice_proof_header<'source, Source: ProofByteSource + ?Sized>(
    source: &'source Source,
    declared_proof_byte_length: usize,
    proof_byte_ceiling: usize,
    expected_header: &[u8],
) -> Result<ProofBodyByteSource<'source, Source>, CommonProofVerifierError> {
    if declared_proof_byte_length == 0 {
        return Err(ProofBodyError::Decode(super::super::ProofDecodeError::EmptyProof).into());
    }
    if declared_proof_byte_length > proof_byte_ceiling {
        return Err(ProofBodyError::Decode(
            super::super::ProofDecodeError::ProofByteCeilingExceeded,
        )
        .into());
    }
    if source.byte_length() != declared_proof_byte_length {
        return Err(
            ProofBodyError::Decode(super::super::ProofDecodeError::DeclaredLengthMismatch).into(),
        );
    }
    let body_byte_length = declared_proof_byte_length
        .checked_sub(expected_header.len())
        .filter(|length| *length > 0)
        .ok_or(CommonProofVerifierError::InvalidProofHeader)?;
    let mut compared_byte_length = 0_usize;
    let mut scratch = [0_u8; 256];
    while compared_byte_length < expected_header.len() {
        let chunk_byte_length = scratch
            .len()
            .min(expected_header.len() - compared_byte_length);
        let chunk = &mut scratch[..chunk_byte_length];
        if !source.copy_bytes(compared_byte_length, chunk) {
            return Err(ProofBodyError::Decode(super::super::ProofDecodeError::Truncated).into());
        }
        if chunk
            != expected_header
                .get(compared_byte_length..compared_byte_length + chunk_byte_length)
                .ok_or(CommonProofVerifierError::InvalidProofHeader)?
        {
            return Err(CommonProofVerifierError::InvalidProofHeader);
        }
        compared_byte_length += chunk_byte_length;
    }
    Ok(ProofBodyByteSource {
        source,
        body_offset: expected_header.len(),
        body_byte_length,
    })
}
