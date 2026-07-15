//! Bounded verifier for the suite-bound common transparent proof.
//!
//! The verifier derives every proof role, count, opening, and transcript round
//! from a checked relation plan.  It retains only the proof prefix, one
//! authenticated tree opening, and one small state per sampled query.  The
//! canonical query section is hashed while the same first read is decoded and
//! algebraically checked.

use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple};
use crate::hashing::hash_framed_parts_512;

use super::field::ProofChallengeExtensionElement;
use super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationColumnValueType,
    RelationOpeningSourceClass, RelationPlanVariant, RelationSelectorPathStep,
    RelationTreeDescriptor, SelectorPathStepKind, SuiteModulusReference,
};
use super::{
    CommittedMaterialTree, CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
    CommonProofTranscript, CompiledRelationPlan, CompleteProofTreeCatalog, DecodedProofBodyPrefix,
    OpenedFriLayerPair, ProofBodyError, ProofBodyLayout, ProofByteSource, ProofDecodeError,
    ProofEvaluationDomain, ProofFriError, ProofFriQueryState, ProofFriQueryVerifier,
    ProofLeafVisibility, ProofOpeningClaimEvaluation, ProofOpeningError, ProofPolynomialError,
    ProofProfileError, ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeOpening,
    ProofTreeRole, ProofTreeValue, RelationApplicationChallengeAssignment,
    RelationPlanCheckContext, RelationPlanError, RelationProofTreeInput, SetupPublicPolynomialTree,
    StatementOwnedProofTreeInput, TranscriptError, ValidatedRelationPlanArtifact,
    build_complete_proof_tree_catalog, decode_proof_body_prefix, decode_proof_body_prefix_owned,
    decode_proof_query_section_header_at, decode_proof_query_tree_at,
    evaluate_normalized_opening_claim_pair, proof_body_prefix_byte_length,
};

const PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER: u16 = 0x0102;
const PROOF_OBJECT_HEADER_SCHEMA_VERSION: u16 = 1;
const SELECTED_PROOF_FIELD_INDEX: u16 = 0;
const VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/verified-application-statement/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerifierError {
    CanonicalEncoding,
    Cancelled,
    InvalidApplicationStatement,
    InvalidProofHeader,
    InvalidBoundTree,
    InvalidTreeLayout,
    InvalidOpeningClaim,
    MissingVerifiedColumnValue,
    VerifiedColumnMismatch,
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    Polynomial(ProofPolynomialError),
    Opening(ProofOpeningError),
    Fri(ProofFriError),
}

impl From<ProofProfileError> for CommonProofVerifierError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for CommonProofVerifierError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<ProofBodyError> for CommonProofVerifierError {
    fn from(error: ProofBodyError) -> Self {
        Self::Body(error)
    }
}

impl From<TranscriptError> for CommonProofVerifierError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<ProofPolynomialError> for CommonProofVerifierError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<ProofOpeningError> for CommonProofVerifierError {
    fn from(error: ProofOpeningError) -> Self {
        Self::Opening(error)
    }
}

impl From<ProofFriError> for CommonProofVerifierError {
    fn from(error: ProofFriError) -> Self {
        Self::Fri(error)
    }
}

/// Opaque evidence minted only after the complete generated verifier accepts.
/// It binds the exact suite, protocol version, application statement, and
/// selected relation-plan variant. Family code consumes this capability
/// instead of accepting a proof byte string or a caller-supplied verdict.
pub(crate) struct VerifiedCommonProof {
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

impl VerifiedCommonProof {
    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }
}

/// One statement-owned tree already resolved from the verified application
/// inputs.  The source ordinal and relation-tree ordinal prevent a caller from
/// substituting another otherwise well-formed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedStatementOwnedTree {
    ordered_tree_ordinal: u32,
    expected_root_source_ordinal: u32,
    tree: StatementOwnedProofTreeInput,
    ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
}

impl VerifiedStatementOwnedTree {
    pub(crate) fn from_committed_material_tree(
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        tree: &CommittedMaterialTree,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
    ) -> Self {
        Self {
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            tree: StatementOwnedProofTreeInput::CommittedMaterial {
                material_context_hash: tree.material_context_hash(),
                expected_root: tree.root(),
            },
            ordered_canonical_residue_moduli,
        }
    }

    /// Constructs the verifier-owned tree input only from canonical source
    /// coefficients that the public-polynomial tree implementation already
    /// evaluated and hashed. There is deliberately no constructor accepting a
    /// separately claimed setup-polynomial root.
    pub(crate) fn from_setup_public_polynomial_tree(
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        tree: &SetupPublicPolynomialTree,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
    ) -> Self {
        Self {
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            tree: StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: tree.public_polynomial_context_hash(),
                row_width: tree.row_width(),
                expected_root: tree.root(),
            },
            ordered_canonical_residue_moduli,
        }
    }
}

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
pub(crate) struct CommonProofVerificationStateMachine<'input> {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    canonical_application_statement_bytes: &'input [u8],
    application_statement_schema_identifier: u16,
    relation_context: &'input RelationPlanCheckContext,
    variant: &'input RelationPlanVariant,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    declared_proof_byte_length: usize,
    proof_byte_ceiling: usize,
    maximum_resident_window_byte_length: usize,
    canonical_proof_object_header_bytes: Vec<u8>,
    proof_body_byte_length: usize,
    prefix_end_absolute_offset: usize,
    transcript_schedule: super::CommonProofTranscriptSchedule,
    evaluation_domain: ProofEvaluationDomain,
    layout: ProofBodyLayout,
    phase: CommonProofVerificationPhase,
    current_body_offset: usize,
    tree_roots: Vec<[u8; 64]>,
    sorted_query_representatives: Vec<u64>,
    transcript: Option<CommonProofTranscript>,
    query_opening_absorber: Option<CommonProofQueryOpeningAbsorber>,
    workspace: Option<QueryVerificationWorkspace>,
    verified_common_proof: Option<VerifiedCommonProof>,
}

struct ProofBodyByteSource<'source, Source: ProofByteSource + ?Sized> {
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

impl<'input> CommonProofVerificationStateMachine<'input> {
    pub(crate) fn new(
        input: PollableCommonProofVerificationInput<'input>,
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
            return Err(
                ProofBodyError::Decode(ProofDecodeError::ProofByteCeilingExceeded).into(),
            );
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
            canonical_application_statement_bytes: input.canonical_application_statement_bytes,
            application_statement_schema_identifier: input
                .relation_plan
                .application_statement_schema_identifier(),
            relation_context: input.relation_context,
            variant,
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
            CommonProofVerificationPhase::AwaitingQueryHeader
            | CommonProofVerificationPhase::AwaitingQueryTree { .. } => {
                let absolute_offset = self
                    .canonical_proof_object_header_bytes
                    .len()
                    .checked_add(self.current_body_offset)?;
                let remaining_byte_length = self
                    .declared_proof_byte_length
                    .checked_sub(absolute_offset)?;
                Some(CommonProofRequiredByteRange {
                    offset: absolute_offset,
                    byte_length: remaining_byte_length
                        .min(self.maximum_resident_window_byte_length),
                })
            }
            CommonProofVerificationPhase::Complete
            | CommonProofVerificationPhase::Cancelled => None,
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
        let proof_body_source = verify_and_slice_proof_header(
            source,
            self.declared_proof_byte_length,
            self.proof_byte_ceiling,
            &self.canonical_proof_object_header_bytes,
        )?;

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
                self.absorb_body_range(
                    &proof_body_source,
                    self.current_body_offset,
                    next_body_offset,
                )?;
                self.current_body_offset = next_body_offset;
                self.phase = CommonProofVerificationPhase::AwaitingQueryTree {
                    catalog_index: 0,
                };
                Ok(CommonProofVerificationPoll::QueryHeaderAccepted)
            }
            CommonProofVerificationPhase::AwaitingQueryTree { catalog_index } => {
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
                            self.variant,
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
            CommonProofVerificationPhase::Complete
            | CommonProofVerificationPhase::Cancelled => unreachable!(),
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
            self.transcript_schedule
                .ordered_auxiliary_tree_ordinals(),
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
                    self.relation_context,
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
            .derive_opening_points(self.relation_context, &deep_points)?;
        verify_statement_derived_deep_values(
            self.variant,
            &opening_points,
            prefix.deep_evaluations(),
            evaluate_verified_column,
        )?;
        self.variant.verify_deep_composition(
            self.relation_context,
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
        opening_batch_coefficients
            .try_reserve_exact(usize::from(
                self.transcript_schedule.opening_claim_count(),
            ))
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
            self.variant,
            self.layout.catalog(),
            &opening_points,
            prefix.deep_evaluations(),
            &opening_batch_coefficients,
        )?;
        let fri_verifier = ProofFriQueryVerifier::new(
            self.evaluation_domain,
            fri_fold_challenges,
            prefix.terminal_coefficients().to_vec(),
            usize::try_from(self.relation_context.final_polynomial_degree_bound_exclusive)
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
        let query_opening_absorber = transcript.begin_query_openings(query_section_byte_length)?;

        self.tree_roots = prefix.tree_roots().to_vec();
        self.sorted_query_representatives = sorted_query_representatives;
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

        let protocol_version_bytes = self.protocol_version.to_le_bytes();
        let application_statement_schema_identifier_bytes =
            self.application_statement_schema_identifier.to_le_bytes();
        self.verified_common_proof = Some(VerifiedCommonProof {
            application_statement_schema_identifier: self.application_statement_schema_identifier,
            application_statement_hash: hash_framed_parts_512(
                VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN,
                &[
                    &protocol_version_bytes,
                    &self.suite_identifier,
                    &application_statement_schema_identifier_bytes,
                    self.canonical_application_statement_bytes,
                ],
            ),
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

fn verify_and_slice_proof_header<'source, Source: ProofByteSource + ?Sized>(
    source: &'source Source,
    declared_proof_byte_length: usize,
    proof_byte_ceiling: usize,
    expected_header: &[u8],
) -> Result<ProofBodyByteSource<'source, Source>, CommonProofVerifierError> {
    if declared_proof_byte_length == 0 {
        return Err(ProofBodyError::Decode(super::ProofDecodeError::EmptyProof).into());
    }
    if declared_proof_byte_length > proof_byte_ceiling {
        return Err(
            ProofBodyError::Decode(super::ProofDecodeError::ProofByteCeilingExceeded).into(),
        );
    }
    if source.byte_length() != declared_proof_byte_length {
        return Err(ProofBodyError::Decode(super::ProofDecodeError::DeclaredLengthMismatch).into());
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
            return Err(ProofBodyError::Decode(super::ProofDecodeError::Truncated).into());
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

/// Resolves plan-addressed verifier-sequence columns from verified statement,
/// suite, slot, sampler, or protocol sources. Proof bytes never supply these
/// values. Implementations retaining a verifier column over the evaluation
/// domain should override the pair method to avoid per-query interpolation.
pub(crate) trait VerifiedRelationColumnEvaluator {
    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement>;

    fn evaluate_at_evaluation_domain_pair(
        &mut self,
        column_ordinal: u32,
        evaluation_domain: ProofEvaluationDomain,
        query_representative: u64,
    ) -> Option<OpenedFriLayerPair> {
        let evaluation_point = evaluation_domain
            .point(usize::try_from(query_representative).ok()?)
            .ok()?;
        let first = self.evaluate_at_extension_point(
            column_ordinal,
            ProofChallengeExtensionElement::from_base(evaluation_point),
        )?;
        let opposite = self.evaluate_at_extension_point(
            column_ordinal,
            ProofChallengeExtensionElement::from_base(evaluation_point.negate()),
        )?;
        Some(OpenedFriLayerPair::new(first, opposite))
    }
}

/// Verifies one complete common proof. Returning `None` from a verified-column
/// evaluator fails closed; prover and bound-tree columns never call it.
pub(crate) fn verify_common_proof<Source, ColumnEvaluator>(
    input: CommonProofVerificationInput<'_, Source>,
    evaluate_verified_column: &mut ColumnEvaluator,
) -> Result<VerifiedCommonProof, CommonProofVerifierError>
where
    Source: ProofByteSource + ?Sized,
    ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
{
    let _validated_artifact = ValidatedRelationPlanArtifact::from_compiled_plan(
        input.relation_plan,
        input.relation_context,
    )?;
    let application_statement = decode_application_statement(
        input.canonical_application_statement_bytes,
        input
            .relation_plan
            .application_statement_schema_identifier(),
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
    let proof_body_source = verify_and_slice_proof_header(
        input.proof_source,
        input.declared_proof_byte_length,
        input.proof_byte_ceiling,
        &canonical_proof_object_header_bytes,
    )?;
    let proof_body_byte_ceiling = input
        .proof_byte_ceiling
        .checked_sub(canonical_proof_object_header_bytes.len())
        .ok_or(CommonProofVerifierError::InvalidProofHeader)?;

    let variant = input
        .relation_plan
        .select_variant(input.schedule_position, input.top_count)?;
    let transcript_schedule = variant.common_proof_transcript_schedule(input.relation_context)?;
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

    let relation_trees =
        derive_relation_tree_inputs(variant, &application_statement, input.statement_owned_trees)?;
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
    let pending = decode_proof_body_prefix(
        &proof_body_source,
        proof_body_source.byte_length(),
        proof_body_byte_ceiling,
        &layout,
    )?;

    let mut transcript = CommonProofTranscript::new(
        input.protocol_version,
        input.suite_identifier,
        input
            .relation_plan
            .application_statement_schema_identifier(),
        &canonical_proof_object_header_bytes,
        transcript_schedule.clone(),
    )?;
    absorb_relation_roots(
        &mut transcript,
        layout.catalog(),
        pending.tree_roots(),
        ProofTreeRole::BaseOracle,
        transcript_schedule.ordered_base_tree_ordinals(),
    )?;

    let mut application_challenges = Vec::new();
    application_challenges
        .try_reserve_exact(
            transcript_schedule
                .ordered_application_challenge_groups()
                .iter()
                .try_fold(0_usize, |count, group| {
                    count.checked_add(usize::from(group.coordinate_count()))
                })
                .ok_or(CommonProofVerifierError::InvalidTreeLayout)?,
        )
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for scheduled_group in transcript_schedule.ordered_application_challenge_groups() {
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
        layout.catalog(),
        pending.tree_roots(),
        ProofTreeRole::AuxiliaryOracle,
        transcript_schedule.ordered_auxiliary_tree_ordinals(),
    )?;

    let mut composition_challenges = Vec::new();
    composition_challenges
        .try_reserve_exact(usize::from(
            transcript_schedule.composition_challenge_count(),
        ))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for constraint_ordinal in 0..transcript_schedule.composition_challenge_count() {
        composition_challenges.push(transcript.sample_composition_challenge(constraint_ordinal)?);
    }

    for component_ordinal in 0..transcript_schedule.quotient_component_count() {
        transcript.absorb_quotient_root(
            component_ordinal,
            catalog_root(layout.catalog(), pending.tree_roots(), |source| {
                source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
            })?,
        )?;
    }

    let mut deep_points = Vec::new();
    deep_points
        .try_reserve_exact(usize::from(transcript_schedule.deep_point_count()))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for point_ordinal in 0..transcript_schedule.deep_point_count() {
        let mut relation_error = None;
        let sampled = transcript.sample_deep_point(point_ordinal, |candidate| {
            match variant.deep_point_candidate_is_forbidden(
                input.relation_context,
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
    let opening_points = variant.derive_opening_points(input.relation_context, &deep_points)?;
    verify_statement_derived_deep_values(
        variant,
        &opening_points,
        pending.deep_evaluations(),
        evaluate_verified_column,
    )?;
    variant.verify_deep_composition(
        input.relation_context,
        &application_challenges,
        &composition_challenges,
        &deep_points,
        pending.deep_evaluations(),
    )?;
    transcript.absorb_deep_evaluations(pending.deep_evaluations())?;

    if transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing {
        transcript.absorb_opening_batch_mask_root(catalog_root(
            layout.catalog(),
            pending.tree_roots(),
            |source| source == ProofTreeCatalogSource::OpeningBatchMask,
        )?)?;
    }

    let mut opening_batch_coefficients = Vec::new();
    opening_batch_coefficients
        .try_reserve_exact(usize::from(transcript_schedule.opening_claim_count()))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for claim_ordinal in 0..transcript_schedule.opening_claim_count() {
        opening_batch_coefficients.push(transcript.sample_opening_batch_challenge(claim_ordinal)?);
    }

    let mut fri_fold_challenges = Vec::new();
    fri_fold_challenges
        .try_reserve_exact(usize::from(transcript_schedule.fri_fold_count()))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for fold_ordinal in 0..transcript_schedule.fri_fold_count() {
        fri_fold_challenges.push(transcript.sample_fri_fold_challenge(fold_ordinal)?);
        if fold_ordinal + 1 < transcript_schedule.fri_fold_count() {
            transcript.absorb_fri_layer_root(
                fold_ordinal,
                catalog_root(layout.catalog(), pending.tree_roots(), |source| {
                    source == ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal }
                })?,
            )?;
        }
    }
    transcript.absorb_fri_terminal_coefficients(pending.terminal_coefficients())?;

    let mut sampled_query_representatives = transcript.sample_query_representatives()?;
    let sorted_query_representatives = transcript.sorted_query_representatives()?;
    sampled_query_representatives.sort_unstable();
    if sampled_query_representatives != sorted_query_representatives {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }

    let claim_groups = build_runtime_claim_groups(
        variant,
        layout.catalog(),
        &opening_points,
        pending.deep_evaluations(),
        &opening_batch_coefficients,
    )?;
    let fri_verifier = ProofFriQueryVerifier::new(
        evaluation_domain,
        fri_fold_challenges,
        pending.terminal_coefficients().to_vec(),
        usize::try_from(
            input
                .relation_context
                .final_polynomial_degree_bound_exclusive,
        )
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
    )?;
    let mut workspace = QueryVerificationWorkspace::new(
        layout.catalog().entries().len(),
        evaluation_domain,
        sorted_query_representatives.len(),
        claim_groups,
        fri_verifier,
    )?;
    let mut query_opening_absorber =
        transcript.begin_query_openings(pending.query_section_byte_length()?)?;
    let mut query_verification_error = None;
    let decode_result = pending.decode_query_section(
        &sorted_query_representatives,
        &mut query_opening_absorber,
        |opening| {
            if let Err(error) = workspace.consume_opening(
                opening,
                variant,
                layout.catalog(),
                &sorted_query_representatives,
                evaluate_verified_column,
            ) {
                query_verification_error = Some(error);
                return Err(ProofBodyError::InvalidLeaf);
            }
            Ok(())
        },
    );
    if let Some(error) = query_verification_error {
        return Err(error);
    }
    let _decoded_body = decode_result?;
    workspace.finish(
        layout.catalog().entries().len(),
        &sorted_query_representatives,
    )?;
    transcript.finish_query_openings(query_opening_absorber)?;
    transcript.finish()?;
    let application_statement_schema_identifier = input
        .relation_plan
        .application_statement_schema_identifier();
    let protocol_version_bytes = input.protocol_version.to_le_bytes();
    let application_statement_schema_identifier_bytes =
        application_statement_schema_identifier.to_le_bytes();
    Ok(VerifiedCommonProof {
        application_statement_schema_identifier,
        application_statement_hash: hash_framed_parts_512(
            VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN,
            &[
                &protocol_version_bytes,
                &input.suite_identifier,
                &application_statement_schema_identifier_bytes,
                input.canonical_application_statement_bytes,
            ],
        ),
        relation_plan_variant_hash: variant.canonical_hash()?,
        schedule_position: input.schedule_position,
        top_count: input.top_count,
    })
}

fn decode_application_statement(
    canonical_bytes: &[u8],
    expected_schema_identifier: u16,
) -> Result<CanonicalTuple, CommonProofVerifierError> {
    let statement = CanonicalTuple::decode(canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if statement.schema_identifier != expected_schema_identifier
        || statement.schema_version != PROOF_OBJECT_HEADER_SCHEMA_VERSION
        || statement
            .encode()
            .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?
            != canonical_bytes
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(statement)
}

fn derive_relation_tree_inputs(
    variant: &RelationPlanVariant,
    application_statement: &CanonicalTuple,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<Vec<RelationProofTreeInput>, CommonProofVerifierError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(variant.ordered_trees().len())
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    let mut consumed_statement_trees = vec![false; statement_owned_trees.len()];

    for (tree_index, tree) in variant.ordered_trees().iter().enumerate() {
        let ordered_tree_ordinal =
            u32::try_from(tree_index).map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofVerifierError::InvalidTreeLayout),
                };
                let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                validate_tree_columns(variant, ordered_column_ordinals, None)?;
                inputs.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } => {
                validate_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let mut matches = statement_owned_trees
                    .iter()
                    .enumerate()
                    .filter(|(_, input)| {
                        input.ordered_tree_ordinal == ordered_tree_ordinal
                            && input.expected_root_source_ordinal == *expected_root_source_ordinal
                    });
                let (input_index, input) = matches
                    .next()
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                if matches.next().is_some() || consumed_statement_trees[input_index] {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                let expected_row_width = ordered_column_ordinals.len();
                let expected_canonical_residue_moduli = ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        variant
                            .ordered_columns()
                            .get(*column_ordinal as usize)
                            .map(|column| column.canonical_residue_modulus())
                            .ok_or(CommonProofVerifierError::InvalidTreeLayout)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let construction_matches = match (&input.tree, construction_kind) {
                    (
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                        BoundTreeConstructionKind::CommittedMaterial,
                    ) => expected_row_width == 4,
                    (
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                        BoundTreeConstructionKind::SetupPolynomial,
                    ) => usize::try_from(*row_width).is_ok_and(|width| width == expected_row_width),
                    _ => false,
                };
                if !construction_matches
                    || input.ordered_canonical_residue_moduli != expected_canonical_residue_moduli
                {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                let value_path = variant
                    .verifier_source(*expected_root_source_ordinal)
                    .and_then(|source| source.application_statement_scalar_hash_path())
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                let expected_statement_root =
                    select_application_statement_hash(application_statement, value_path)?;
                let supplied_root = match &input.tree {
                    StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
                    | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. } => {
                        *expected_root
                    }
                };
                if supplied_root != expected_statement_root {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                consumed_statement_trees[input_index] = true;
                inputs.push(RelationProofTreeInput::BoundPublic(input.tree.clone()));
            }
        }
    }
    if consumed_statement_trees.iter().any(|consumed| !consumed) {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    Ok(inputs)
}

enum SelectedApplicationStatementValue {
    Tuple(CanonicalTuple),
    Item(CanonicalItem),
}

fn select_application_statement_hash(
    application_statement: &CanonicalTuple,
    value_path: &[RelationSelectorPathStep],
) -> Result<[u8; 64], CommonProofVerifierError> {
    if value_path.is_empty() {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let mut selected = SelectedApplicationStatementValue::Tuple(application_statement.clone());
    for step in value_path {
        selected = match step.step_kind() {
            SelectorPathStepKind::TupleField => {
                let tuple = match selected {
                    SelectedApplicationStatementValue::Tuple(tuple) => tuple,
                    SelectedApplicationStatementValue::Item(item)
                        if item.item_type() == CanonicalItemType::NestedTuple =>
                    {
                        CanonicalTuple::decode(
                            item.canonical_bytes(),
                            &CanonicalDecodeLimits::default(),
                        )
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
                    }
                    SelectedApplicationStatementValue::Item(_) => {
                        return Err(CommonProofVerifierError::InvalidBoundTree);
                    }
                };
                SelectedApplicationStatementValue::Item(
                    tuple
                        .items
                        .get(
                            usize::try_from(step.argument())
                                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                        )
                        .cloned()
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
                )
            }
            SelectorPathStepKind::LiteralListIndex => {
                let SelectedApplicationStatementValue::Item(item) = selected else {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                };
                SelectedApplicationStatementValue::Item(select_homogeneous_list_item(
                    &item,
                    usize::try_from(step.argument())
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                )?)
            }
            _ => return Err(CommonProofVerifierError::InvalidBoundTree),
        };
    }
    let SelectedApplicationStatementValue::Item(item) = selected else {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    };
    if item.item_type() != CanonicalItemType::Hash512 || item.canonical_bytes().len() != 64 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn select_homogeneous_list_item(
    list: &CanonicalItem,
    selected_index: usize,
) -> Result<CanonicalItem, CommonProofVerifierError> {
    if list.item_type() != CanonicalItemType::HomogeneousList {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let bytes = list.canonical_bytes();
    if bytes.len() < 6 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let element_type =
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    let element_count =
        usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    if selected_index >= element_count {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let payload = &bytes[6..];
    let selected_bytes = match element_type {
        CanonicalItemType::Hash512 => {
            let expected_byte_length = element_count
                .checked_mul(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            if payload.len() != expected_byte_length {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let start = selected_index
                .checked_mul(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            let end = start
                .checked_add(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            payload
                .get(start..end)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?
        }
        CanonicalItemType::NestedTuple => {
            let mut offset = 0_usize;
            let mut selected_range = None;
            for element_index in 0..element_count {
                let tuple_byte_length = encoded_tuple_byte_length(
                    payload
                        .get(offset..)
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
                )?;
                let next_offset = offset
                    .checked_add(tuple_byte_length)
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                if element_index == selected_index {
                    selected_range = Some((offset, next_offset));
                }
                offset = next_offset;
            }
            if offset != payload.len() {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let (start, end) = selected_range.ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            payload
                .get(start..end)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?
        }
        _ => return Err(CommonProofVerifierError::InvalidBoundTree),
    };
    CanonicalItem::from_canonical_bytes(
        element_type,
        selected_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn encoded_tuple_byte_length(bytes: &[u8]) -> Result<usize, CommonProofVerifierError> {
    if bytes.len() < 8 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let item_count = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header = bytes
            .get(offset..offset + 6)
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([header[0], header[1]]))
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        let value_byte_length = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        offset = offset
            .checked_add(6)
            .and_then(|value| value.checked_add(value_byte_length))
            .filter(|value| *value <= bytes.len())
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    }
    Ok(offset)
}

fn validate_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofVerifierError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    for column_ordinal in ordered_column_ordinals {
        let column_index = usize::try_from(*column_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            (_, None) => {}
        }
    }
    Ok(())
}

fn absorb_relation_roots(
    transcript: &mut CommonProofTranscript,
    catalog: &CompleteProofTreeCatalog,
    roots: &[[u8; 64]],
    target_role: ProofTreeRole,
    ordered_role_ordinals: &[u16],
) -> Result<(), CommonProofVerifierError> {
    for role_ordinal in ordered_role_ordinals {
        let root = catalog_root(catalog, roots, |source| {
            source
                == ProofTreeCatalogSource::RelationProofCreated {
                    tree_role: target_role,
                    tree_ordinal: *role_ordinal,
                }
        })?;
        match target_role {
            ProofTreeRole::BaseOracle => {
                transcript.absorb_base_root(*role_ordinal, root)?;
            }
            ProofTreeRole::AuxiliaryOracle => {
                transcript.absorb_auxiliary_root(*role_ordinal, root)?;
            }
            _ => return Err(CommonProofVerifierError::InvalidTreeLayout),
        }
    }
    Ok(())
}

fn catalog_root(
    catalog: &CompleteProofTreeCatalog,
    roots: &[[u8; 64]],
    mut matches_source: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<[u8; 64], CommonProofVerifierError> {
    if roots.len() != catalog.entries().len() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    let mut matches = catalog
        .entries()
        .iter()
        .zip(roots)
        .filter(|(entry, _)| matches_source(entry.source()));
    let root = matches
        .next()
        .map(|(_, root)| *root)
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    if matches.next().is_some() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    Ok(root)
}

fn verify_statement_derived_deep_values<ColumnEvaluator>(
    variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    deep_evaluations: &[ProofChallengeExtensionElement],
    evaluate_verified_column: &mut ColumnEvaluator,
) -> Result<(), CommonProofVerifierError>
where
    ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
{
    if deep_evaluations.len() != variant.ordered_opening_claims().len() {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    for (claim_ordinal, claim) in variant.ordered_opening_claims().iter().copied().enumerate() {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_ordinal = claim
            .column_ordinal()
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        if !matches!(
            column.origin(),
            RelationColumnOrigin::VerifierSequence { .. }
        ) {
            continue;
        }
        let opening_point_index = usize::try_from(claim.opening_point_ordinal())
            .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
        let point = opening_points
            .get(opening_point_index)
            .copied()
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        let expected = evaluate_verified_column
            .evaluate_at_extension_point(column_ordinal, point)
            .ok_or(CommonProofVerifierError::MissingVerifiedColumnValue)?;
        if deep_evaluations[claim_ordinal] != expected {
            return Err(CommonProofVerifierError::VerifiedColumnMismatch);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RuntimeOpeningClaim {
    column_position: Option<usize>,
    source_degree_bound_exclusive: u64,
    opening_point: ProofChallengeExtensionElement,
    opened_value: ProofChallengeExtensionElement,
    batching_coefficient: ProofChallengeExtensionElement,
}

fn build_runtime_claim_groups(
    variant: &RelationPlanVariant,
    catalog: &CompleteProofTreeCatalog,
    opening_points: &[ProofChallengeExtensionElement],
    deep_evaluations: &[ProofChallengeExtensionElement],
    batching_coefficients: &[ProofChallengeExtensionElement],
) -> Result<Vec<Vec<RuntimeOpeningClaim>>, CommonProofVerifierError> {
    if deep_evaluations.len() != variant.ordered_opening_claims().len()
        || batching_coefficients.len() != variant.ordered_opening_claims().len()
    {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    let mut groups = vec![Vec::new(); catalog.entries().len()];
    for (claim_ordinal, claim) in variant.ordered_opening_claims().iter().copied().enumerate() {
        let (catalog_index, column_position) = match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let tree_index = usize::try_from(claim.source_ordinal())
                    .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
                if !matches!(
                    catalog
                        .entries()
                        .get(tree_index)
                        .map(|entry| entry.source()),
                    Some(
                        ProofTreeCatalogSource::RelationProofCreated { .. }
                            | ProofTreeCatalogSource::RelationBoundPublic
                    )
                ) {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                let tree = variant
                    .ordered_trees()
                    .get(tree_index)
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let column_ordinal = claim
                    .column_ordinal()
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let mut positions = tree
                    .ordered_column_ordinals()
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| **candidate == column_ordinal)
                    .map(|(position, _)| position);
                let position = positions
                    .next()
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                if positions.next().is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                (tree_index, Some(position))
            }
            RelationOpeningSourceClass::Quotient => {
                if claim.column_ordinal().is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                let component_ordinal = u16::try_from(claim.source_ordinal())
                    .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
                (
                    catalog_index_for_source(catalog, |source| {
                        source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                    })?,
                    None,
                )
            }
            RelationOpeningSourceClass::BatchMask => {
                if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                (
                    catalog_index_for_source(catalog, |source| {
                        source == ProofTreeCatalogSource::OpeningBatchMask
                    })?,
                    None,
                )
            }
        };
        let opening_point_index = usize::try_from(claim.opening_point_ordinal())
            .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
        let opening_point = opening_points
            .get(opening_point_index)
            .copied()
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        groups
            .get_mut(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?
            .push(RuntimeOpeningClaim {
                column_position,
                source_degree_bound_exclusive: claim.source_degree_bound_exclusive(),
                opening_point,
                opened_value: deep_evaluations[claim_ordinal],
                batching_coefficient: batching_coefficients[claim_ordinal],
            });
    }
    Ok(groups)
}

fn catalog_index_for_source(
    catalog: &CompleteProofTreeCatalog,
    mut matches_source: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<usize, CommonProofVerifierError> {
    let mut matches = catalog
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches_source(entry.source()));
    let index = matches
        .next()
        .map(|(index, _)| index)
        .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
    if matches.next().is_some() {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    Ok(index)
}

struct QueryVerificationWorkspace {
    evaluation_domain: ProofEvaluationDomain,
    claim_groups: Vec<Vec<RuntimeOpeningClaim>>,
    accumulated_initial_pairs: Vec<OpenedFriLayerPair>,
    fri_verifier: ProofFriQueryVerifier,
    fri_states: Option<Vec<ProofFriQueryState>>,
    next_catalog_index: usize,
}

impl QueryVerificationWorkspace {
    fn new(
        catalog_entry_count: usize,
        evaluation_domain: ProofEvaluationDomain,
        query_representative_count: usize,
        claim_groups: Vec<Vec<RuntimeOpeningClaim>>,
        fri_verifier: ProofFriQueryVerifier,
    ) -> Result<Self, CommonProofVerifierError> {
        if query_representative_count == 0 || claim_groups.len() != catalog_entry_count {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        Ok(QueryVerificationWorkspace {
            evaluation_domain,
            claim_groups,
            accumulated_initial_pairs: vec![
                OpenedFriLayerPair::new(
                    ProofChallengeExtensionElement::ZERO,
                    ProofChallengeExtensionElement::ZERO,
                );
                query_representative_count
            ],
            fri_verifier,
            fri_states: None,
            next_catalog_index: 0,
        })
    }

    fn consume_opening<ColumnEvaluator>(
        &mut self,
        opening: ProofTreeOpening<'_>,
        variant: &RelationPlanVariant,
        catalog: &CompleteProofTreeCatalog,
        query_representatives: &[u64],
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<(), CommonProofVerifierError>
    where
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let catalog_index = usize::from(opening.catalog_entry().tree_catalog_index());
        if catalog_index != self.next_catalog_index
            || catalog.entries().get(catalog_index) != Some(opening.catalog_entry())
        {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        match opening.catalog_entry().source() {
            ProofTreeCatalogSource::RelationProofCreated { .. }
            | ProofTreeCatalogSource::RelationBoundPublic => {
                self.consume_relation_tree(
                    catalog_index,
                    opening.leaves(),
                    variant,
                    query_representatives,
                    evaluate_verified_column,
                )?;
            }
            ProofTreeCatalogSource::QuotientComponent { .. } => {
                self.consume_single_extension_tree(
                    catalog_index,
                    opening.leaves(),
                    false,
                    variant,
                    query_representatives,
                )?;
            }
            ProofTreeCatalogSource::OpeningBatchMask => {
                self.consume_single_extension_tree(
                    catalog_index,
                    opening.leaves(),
                    true,
                    variant,
                    query_representatives,
                )?;
            }
            ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal } => {
                self.consume_fri_tree(
                    usize::from(fold_ordinal),
                    opening.leaves(),
                    query_representatives,
                )?;
            }
        }
        self.next_catalog_index += 1;
        Ok(())
    }

    fn consume_relation_tree<ColumnEvaluator>(
        &mut self,
        catalog_index: usize,
        leaves: &[super::DecodedProofPhasePairLeaf],
        variant: &RelationPlanVariant,
        query_representatives: &[u64],
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<(), CommonProofVerifierError>
    where
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let tree = variant
            .ordered_trees()
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let columns = tree.ordered_column_ordinals();
        let claims = self
            .claim_groups
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;

        for (query_index, representative) in query_representatives.iter().copied().enumerate() {
            let leaf = leaf_for_index(leaves, representative)?;
            if leaf.first_point_values().len() != columns.len()
                || leaf.opposite_point_values().len() != columns.len()
            {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            let evaluation_point = self.evaluation_domain.point(
                usize::try_from(representative)
                    .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            )?;
            for (column_position, column_ordinal) in columns.iter().copied().enumerate() {
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
                let column = variant
                    .ordered_columns()
                    .get(column_index)
                    .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
                let pair = opened_pair(leaf, column_position, column.value_type())?;
                if matches!(
                    column.origin(),
                    RelationColumnOrigin::VerifierSequence { .. }
                ) {
                    let expected_pair = evaluate_verified_column
                        .evaluate_at_evaluation_domain_pair(
                            column_ordinal,
                            self.evaluation_domain,
                            representative,
                        )
                        .ok_or(CommonProofVerifierError::MissingVerifiedColumnValue)?;
                    if pair != expected_pair {
                        return Err(CommonProofVerifierError::VerifiedColumnMismatch);
                    }
                }
            }
            for claim in claims {
                let column_position = claim
                    .column_position
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let column_ordinal = *columns
                    .get(column_position)
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
                let column = variant
                    .ordered_columns()
                    .get(column_index)
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let source_pair = opened_pair(leaf, column_position, column.value_type())?;
                add_opening_claim(
                    variant.opening_degree_bound_exclusive(),
                    evaluation_point,
                    *claim,
                    source_pair,
                    &mut self.accumulated_initial_pairs[query_index],
                )?;
            }
        }
        Ok(())
    }

    fn consume_single_extension_tree(
        &mut self,
        catalog_index: usize,
        leaves: &[super::DecodedProofPhasePairLeaf],
        add_direct_pair: bool,
        variant: &RelationPlanVariant,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        let claims = self
            .claim_groups
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        for (query_index, representative) in query_representatives.iter().copied().enumerate() {
            let leaf = leaf_for_index(leaves, representative)?;
            let source_pair = opened_pair(leaf, 0, RelationColumnValueType::ChallengeExtension)?;
            if add_direct_pair {
                self.accumulated_initial_pairs[query_index] =
                    add_pairs(self.accumulated_initial_pairs[query_index], source_pair);
            }
            let evaluation_point = self.evaluation_domain.point(
                usize::try_from(representative)
                    .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            )?;
            for claim in claims {
                if claim.column_position.is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                add_opening_claim(
                    variant.opening_degree_bound_exclusive(),
                    evaluation_point,
                    *claim,
                    source_pair,
                    &mut self.accumulated_initial_pairs[query_index],
                )?;
            }
        }
        Ok(())
    }

    fn consume_fri_tree(
        &mut self,
        fold_ordinal: usize,
        leaves: &[super::DecodedProofPhasePairLeaf],
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        if self
            .claim_groups
            .get(self.next_catalog_index)
            .is_none_or(|claims| !claims.is_empty())
        {
            return Err(CommonProofVerifierError::InvalidOpeningClaim);
        }
        self.ensure_fri_states(query_representatives)?;
        let states = self
            .fri_states
            .as_mut()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let shift = u32::try_from(fold_ordinal)
            .ok()
            .and_then(|ordinal| ordinal.checked_add(2))
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let leaf_count = u64::try_from(self.evaluation_domain.size())
            .ok()
            .and_then(|domain_size| domain_size.checked_shr(shift))
            .filter(|leaf_count| *leaf_count != 0)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        for (state, representative) in states.iter_mut().zip(query_representatives.iter().copied())
        {
            let leaf = leaf_for_index(leaves, representative % leaf_count)?;
            let next_pair = opened_pair(leaf, 0, RelationColumnValueType::ChallengeExtension)?;
            self.fri_verifier
                .verify_nonterminal_layer(state, fold_ordinal, next_pair)?;
        }
        Ok(())
    }

    fn ensure_fri_states(
        &mut self,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        if self.fri_states.is_some() {
            return Ok(());
        }
        let states = query_representatives
            .iter()
            .copied()
            .zip(self.accumulated_initial_pairs.iter().copied())
            .map(|(representative, initial_pair)| {
                self.fri_verifier
                    .begin_query(representative, initial_pair)
                    .map_err(CommonProofVerifierError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.fri_states = Some(states);
        Ok(())
    }

    fn finish(
        &mut self,
        catalog_entry_count: usize,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        if self.next_catalog_index != catalog_entry_count {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        self.ensure_fri_states(query_representatives)?;
        for state in self
            .fri_states
            .take()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?
        {
            self.fri_verifier.finish_query(state)?;
        }
        Ok(())
    }
}

fn leaf_for_index(
    leaves: &[super::DecodedProofPhasePairLeaf],
    expected_index: u64,
) -> Result<&super::DecodedProofPhasePairLeaf, CommonProofVerifierError> {
    leaves
        .binary_search_by_key(&expected_index, |leaf| leaf.leaf_index())
        .ok()
        .and_then(|index| leaves.get(index))
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)
}

fn opened_pair(
    leaf: &super::DecodedProofPhasePairLeaf,
    column_position: usize,
    expected_value_type: RelationColumnValueType,
) -> Result<OpenedFriLayerPair, CommonProofVerifierError> {
    let first = leaf
        .first_point_values()
        .get(column_position)
        .copied()
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    let opposite = leaf
        .opposite_point_values()
        .get(column_position)
        .copied()
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    let convert = |value| match (value, expected_value_type) {
        (ProofTreeValue::Base(value), RelationColumnValueType::BaseField) => {
            Ok(ProofChallengeExtensionElement::from_base(value))
        }
        (ProofTreeValue::Extension(value), RelationColumnValueType::ChallengeExtension) => {
            Ok(value)
        }
        _ => Err(CommonProofVerifierError::InvalidTreeLayout),
    };
    Ok(OpenedFriLayerPair::new(convert(first)?, convert(opposite)?))
}

fn add_opening_claim(
    opening_degree_bound_exclusive: u64,
    evaluation_point: super::ProofBaseFieldElement,
    claim: RuntimeOpeningClaim,
    source_pair: OpenedFriLayerPair,
    accumulator: &mut OpenedFriLayerPair,
) -> Result<(), CommonProofVerifierError> {
    let term = evaluate_normalized_opening_claim_pair(
        opening_degree_bound_exclusive,
        evaluation_point,
        ProofOpeningClaimEvaluation::new(
            claim.source_degree_bound_exclusive,
            claim.opening_point,
            claim.opened_value,
            source_pair,
            claim.batching_coefficient,
        ),
    )?;
    *accumulator = add_pairs(*accumulator, term);
    Ok(())
}

fn add_pairs(left: OpenedFriLayerPair, right: OpenedFriLayerPair) -> OpenedFriLayerPair {
    OpenedFriLayerPair::new(
        left.first().add(right.first()),
        left.opposite().add(right.opposite()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_header_is_consumed_before_the_body_source_is_exposed() {
        let mut complete_proof = b"canonical-proof-header".to_vec();
        complete_proof.extend_from_slice(b"streamed-proof-body");
        let body = verify_and_slice_proof_header(
            &complete_proof,
            complete_proof.len(),
            complete_proof.len(),
            b"canonical-proof-header",
        )
        .expect("the exact header must be accepted");

        assert_eq!(body.byte_length(), b"streamed-proof-body".len());
        let mut copied_body = vec![0_u8; body.byte_length()];
        assert!(body.copy_bytes(0, &mut copied_body));
        assert_eq!(copied_body, b"streamed-proof-body");
        assert!(!body.copy_bytes(body.byte_length(), &mut [0_u8; 1]));
    }

    #[test]
    fn proof_header_mismatch_and_header_only_stream_fail_closed() {
        let proof = b"canonical-proof-headerstreamed-proof-body".to_vec();
        assert_eq!(
            verify_and_slice_proof_header(
                &proof,
                proof.len(),
                proof.len(),
                b"canonical-proof-headeR",
            )
            .err(),
            Some(CommonProofVerifierError::InvalidProofHeader),
        );

        let header_only = b"canonical-proof-header".to_vec();
        assert_eq!(
            verify_and_slice_proof_header(
                &header_only,
                header_only.len(),
                header_only.len(),
                &header_only,
            )
            .err(),
            Some(CommonProofVerifierError::InvalidProofHeader),
        );
    }

    #[test]
    fn proof_header_preflight_enforces_declared_and_profile_lengths() {
        let proof = b"headerbody".to_vec();
        assert_eq!(
            verify_and_slice_proof_header(&proof, proof.len() - 1, proof.len(), b"header").err(),
            Some(CommonProofVerifierError::Body(ProofBodyError::Decode(
                super::super::ProofDecodeError::DeclaredLengthMismatch,
            ))),
        );
        assert_eq!(
            verify_and_slice_proof_header(&proof, proof.len(), proof.len() - 1, b"header").err(),
            Some(CommonProofVerifierError::Body(ProofBodyError::Decode(
                super::super::ProofDecodeError::ProofByteCeilingExceeded,
            ))),
        );
    }
}
