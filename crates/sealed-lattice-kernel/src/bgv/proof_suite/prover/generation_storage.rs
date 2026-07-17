use super::{
    BTreeMap, BoundTreeConstructionKind, BoundedCommonProofByteSinkError,
    COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH, CommonProofEncodingError,
    CommonProofGenerationPoll, CommonProofMerkleStoragePlan, CommonProofOpeningArtifact,
    CommonProofOpeningGeometry, CommonProofPrivacyMode, CommonProofPrivateCoinError,
    CommonProofProverError, CommonProofSourcePolynomial, CommonProofTranscriptSchedule,
    CompiledRelationPlan, CompleteProofTreeCatalog, ExternalPolynomialVector,
    ExternalStockhamTransformDirection, ExternalStockhamTransformPlan, HASH_BYTE_LENGTH,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofBodyError,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofExternalMemory,
    ProofExternalMemoryError, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
    ProofExternalMemoryProtection, ProofLeafVisibility, ProofPrivacyMode, ProofProfileError,
    ProofTreeCatalogEntry, ProofTreeCatalogSource, ProofTreeRole, RelationColumnOrigin,
    RelationColumnValueType, RelationMaskKind, RelationMaskTargetClass, RelationPlanCheckContext,
    RelationPlanError, RelationPlanVariant, RelationProofTreeInput, RelationTreeDescriptor,
    StatementOwnedProofTreeInput, StoredCommonProofMerkleTree, TranscriptError, Zeroize, Zeroizing,
    canonical_common_proof_leaf_byte_length, common_proof_merkle_storage_plan,
    common_proof_tree_value_type, map_external_polynomial_plan_error,
    required_relation_rotations_by_column, trim_extension_polynomial,
};
#[cfg(test)]
use super::{CommonProofByteSink, CommonProofPrivateCoinSource};

/// Family-owned access to the statement trees already authenticated while
/// constructing the application statement.  The common prover owns every
/// proof-created tree; this boundary exists only because committed-material
/// and setup-polynomial trees retain their canonical bytes in their owning
/// family stores.
pub(crate) trait CommonProofBoundOpeningProvider {
    type Error;

    fn opening_geometry(
        &self,
        catalog_entry: &ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, Self::Error>;

    fn encode_bound_opening_fragment(
        &mut self,
        catalog: &CompleteProofTreeCatalog,
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
        sorted_query_representatives: &[u64],
        maximum_fragment_byte_length: usize,
    ) -> Result<Vec<u8>, CommonProofEncodingError<BoundedCommonProofByteSinkError, Self::Error>>;
}

/// Complete application-owned inputs for one production common-proof
/// attempt.  Only genuine pre-challenge source columns are accepted:
/// integer-lift reversed and auxiliary columns are always synthesized by the
/// common prover.
pub(crate) struct CommonProofGenerationInput<'input> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
    pub(crate) provided_pre_challenge_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
    pub(crate) maximum_external_memory_chunk_byte_length: u32,
    pub(crate) maximum_proof_transport_chunk_byte_length: usize,
    pub(crate) maximum_prefetched_query_byte_length: u64,
}

#[derive(Debug)]
pub(crate) enum CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    CoinSource(CoinError),
    Sink(SinkError),
    BoundOpening(BoundOpeningError),
    Cleanup {
        original:
            Box<CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError>>,
        cleanup: ProofExternalMemoryExecutorError<StorageError>,
    },
}

pub(super) type CommonProofGenerationPollResult<
    StorageError,
    CoinError,
    SinkError,
    BoundOpeningError,
> = Result<
    CommonProofGenerationPoll,
    CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError>,
>;

#[cfg(test)]
pub(super) type CompletedCommonProofGenerationResult<Storage, Coins, Sink, BoundOpenings> = Result<
    (),
    CommonProofGenerationError<
        <Storage as ProofExternalMemory>::Error,
        <Coins as CommonProofPrivateCoinSource>::Error,
        <Sink as CommonProofByteSink>::Error,
        <BoundOpenings as CommonProofBoundOpeningProvider>::Error,
    >,
>;

pub(super) struct GeneratedCommonProofStoragePlan {
    pub(super) external_memory_plan: ProofExternalMemoryPlan,
    pub(super) tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    pub(super) replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    pub(super) relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CommonProofReplayPolynomialKey {
    RelationColumn(u32),
    QuotientComponent(u16),
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CommonProofReplayPolynomialPlan {
    pub(super) object: ProofExternalMemoryObject,
    pub(super) value_type: RelationColumnValueType,
    pub(super) coefficient_count: usize,
    pub(super) exact_byte_length: u64,
}

pub(super) enum CommonProofReplayPolynomialRef<'polynomial> {
    Source(&'polynomial CommonProofSourcePolynomial),
    Extension(&'polynomial [ProofChallengeExtensionElement]),
}

impl CommonProofReplayPolynomialRef<'_> {
    fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Source(polynomial) => polynomial.value_type(),
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    fn coefficient_count(&self) -> usize {
        match self {
            Self::Source(polynomial) => polynomial.coefficient_count(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    fn append_coefficient_bytes(
        &self,
        coefficient_index: usize,
        destination: &mut Vec<u8>,
    ) -> Result<(), CommonProofProverError> {
        match self {
            Self::Source(CommonProofSourcePolynomial::Base(coefficients)) => {
                destination.extend_from_slice(
                    &coefficients
                        .get(coefficient_index)
                        .copied()
                        .unwrap_or(ProofBaseFieldElement::ZERO)
                        .canonical()
                        .to_le_bytes(),
                );
            }
            Self::Source(CommonProofSourcePolynomial::Extension(coefficients)) => {
                for coordinate in coefficients
                    .get(coefficient_index)
                    .copied()
                    .unwrap_or(ProofChallengeExtensionElement::ZERO)
                    .canonical_coordinates()
                {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
            Self::Extension(coefficients) => {
                for coordinate in coefficients
                    .get(coefficient_index)
                    .copied()
                    .unwrap_or(ProofChallengeExtensionElement::ZERO)
                    .canonical_coordinates()
                {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayPolynomialWriterPhase {
    Begin,
    Append,
    Seal,
    Complete,
}

pub(super) struct CommonProofReplayPolynomialWriter {
    plan: CommonProofReplayPolynomialPlan,
    phase: CommonProofReplayPolynomialWriterPhase,
    next_coefficient_index: usize,
    pending_coefficient_bytes: Zeroizing<Vec<u8>>,
    pending_coefficient_byte_offset: usize,
    write_chunk: Zeroizing<Vec<u8>>,
}

impl CommonProofReplayPolynomialWriter {
    pub(super) fn new(
        plan: CommonProofReplayPolynomialPlan,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = u64::try_from(plan.coefficient_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(resident_value_byte_length(plan.value_type))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if polynomial.value_type() != plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > plan.coefficient_count
            || expected_byte_length != plan.exact_byte_length
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            plan,
            phase: CommonProofReplayPolynomialWriterPhase::Begin,
            next_coefficient_index: 0,
            pending_coefficient_bytes: Zeroizing::new(Vec::new()),
            pending_coefficient_byte_offset: 0,
            write_chunk: Zeroizing::new(Vec::new()),
        })
    }

    pub(super) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if polynomial.value_type() != self.plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > self.plan.coefficient_count
        {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        match self.phase {
            CommonProofReplayPolynomialWriterPhase::Begin => {
                executor.begin_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Append;
                Ok(false)
            }
            CommonProofReplayPolynomialWriterPhase::Append => {
                let value_byte_length =
                    usize::try_from(resident_value_byte_length(self.plan.value_type))
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                let maximum_chunk_byte_length =
                    usize::try_from(executor.maximum_chunk_byte_length())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                if maximum_chunk_byte_length == 0 {
                    return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
                }
                loop {
                    if self.write_chunk.len() == maximum_chunk_byte_length {
                        executor.append_object_bytes(
                            storage,
                            self.plan.object,
                            &self.write_chunk,
                        )?;
                        self.write_chunk.zeroize();
                        if !self.pending_coefficient_bytes.is_empty()
                            && self.pending_coefficient_byte_offset
                                == self.pending_coefficient_bytes.len()
                        {
                            self.pending_coefficient_bytes.zeroize();
                            self.pending_coefficient_byte_offset = 0;
                            self.next_coefficient_index = self
                                .next_coefficient_index
                                .checked_add(1)
                                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                        }
                        return Ok(false);
                    }
                    if self.pending_coefficient_bytes.is_empty() {
                        if self.next_coefficient_index == self.plan.coefficient_count {
                            if self.write_chunk.is_empty() {
                                executor.seal_object(storage, self.plan.object)?;
                                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                                return Ok(true);
                            }
                            executor.append_object_bytes(
                                storage,
                                self.plan.object,
                                &self.write_chunk,
                            )?;
                            self.write_chunk.zeroize();
                            self.phase = CommonProofReplayPolynomialWriterPhase::Seal;
                            return Ok(false);
                        }
                        self.pending_coefficient_bytes
                            .try_reserve_exact(value_byte_length)
                            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                        polynomial
                            .append_coefficient_bytes(
                                self.next_coefficient_index,
                                &mut self.pending_coefficient_bytes,
                            )
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
                        if self.pending_coefficient_bytes.len() != value_byte_length {
                            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                        }
                        self.pending_coefficient_byte_offset = 0;
                    }
                    if self.pending_coefficient_byte_offset >= self.pending_coefficient_bytes.len()
                        || self.write_chunk.len() > maximum_chunk_byte_length
                    {
                        return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                    }
                    let remaining_chunk_capacity =
                        maximum_chunk_byte_length - self.write_chunk.len();
                    self.write_chunk
                        .try_reserve_exact(remaining_chunk_capacity)
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                    let copied_byte_length = remaining_chunk_capacity.min(
                        self.pending_coefficient_bytes.len() - self.pending_coefficient_byte_offset,
                    );
                    let pending_coefficient_end = self
                        .pending_coefficient_byte_offset
                        .checked_add(copied_byte_length)
                        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    self.write_chunk.extend_from_slice(
                        &self.pending_coefficient_bytes
                            [self.pending_coefficient_byte_offset..pending_coefficient_end],
                    );
                    self.pending_coefficient_byte_offset = pending_coefficient_end;
                    if self.write_chunk.len() < maximum_chunk_byte_length
                        && self.pending_coefficient_byte_offset
                            == self.pending_coefficient_bytes.len()
                    {
                        self.pending_coefficient_bytes.zeroize();
                        self.pending_coefficient_byte_offset = 0;
                        self.next_coefficient_index = self
                            .next_coefficient_index
                            .checked_add(1)
                            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    }
                }
            }
            CommonProofReplayPolynomialWriterPhase::Seal => {
                executor.seal_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                Ok(true)
            }
            CommonProofReplayPolynomialWriterPhase::Complete => Ok(true),
        }
    }
}

enum CommonProofReplayPolynomialCoefficients {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

pub(super) struct CommonProofReplayPolynomialReader {
    plan: CommonProofReplayPolynomialPlan,
    next_coefficient_index: usize,
    coefficients: CommonProofReplayPolynomialCoefficients,
}

impl CommonProofReplayPolynomialReader {
    pub(super) fn new(
        plan: CommonProofReplayPolynomialPlan,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = u64::try_from(plan.coefficient_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(resident_value_byte_length(plan.value_type))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if plan.coefficient_count == 0 || expected_byte_length != plan.exact_byte_length {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let coefficients = match plan.value_type {
            RelationColumnValueType::BaseField => {
                CommonProofReplayPolynomialCoefficients::Base(Vec::new())
            }
            RelationColumnValueType::ChallengeExtension => {
                CommonProofReplayPolynomialCoefficients::Extension(Vec::new())
            }
        };
        Ok(Self {
            plan,
            next_coefficient_index: 0,
            coefficients,
        })
    }

    pub(super) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.next_coefficient_index >= self.plan.coefficient_count {
            return Ok(true);
        }
        let value_byte_length = usize::try_from(resident_value_byte_length(self.plan.value_type))
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let maximum_coefficient_count = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let coefficient_count = maximum_coefficient_count
            .min(self.plan.coefficient_count - self.next_coefficient_index);
        let byte_length = coefficient_count
            .checked_mul(value_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        bytes.resize(byte_length, 0);
        let offset = self
            .next_coefficient_index
            .checked_mul(value_byte_length)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        executor.read_object_bytes(storage, self.plan.object, offset, &mut bytes)?;
        match &mut self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(coefficients) => {
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for encoded in bytes.chunks_exact(8) {
                    let mut value = [0_u8; 8];
                    value.copy_from_slice(encoded);
                    coefficients.push(
                        ProofBaseFieldElement::from_canonical(u64::from_le_bytes(value))
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                    );
                }
            }
            CommonProofReplayPolynomialCoefficients::Extension(coefficients) => {
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for encoded in bytes.chunks_exact(value_byte_length) {
                    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                    for (coordinate, coordinate_bytes) in
                        coordinates.iter_mut().zip(encoded.chunks_exact(8))
                    {
                        let mut value = [0_u8; 8];
                        value.copy_from_slice(coordinate_bytes);
                        *coordinate = u64::from_le_bytes(value);
                    }
                    coefficients.push(
                        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                    );
                }
            }
        }
        self.next_coefficient_index += coefficient_count;
        Ok(self.next_coefficient_index == self.plan.coefficient_count)
    }

    pub(super) fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        if self.next_coefficient_index != self.plan.coefficient_count {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(match self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(mut coefficients) => {
                while coefficients.len() > 1
                    && coefficients.last() == Some(&ProofBaseFieldElement::ZERO)
                {
                    coefficients.pop();
                }
                CommonProofSourcePolynomial::Base(coefficients)
            }
            CommonProofReplayPolynomialCoefficients::Extension(mut coefficients) => {
                trim_extension_polynomial(&mut coefficients);
                CommonProofSourcePolynomial::Extension(coefficients)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeneratedCommonProofStoragePlanError {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryError),
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_add(right)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))
}

fn checked_multiply_u64(
    left: u64,
    right: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_mul(right)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))
}

fn ceiling_division_u64(
    numerator: u64,
    denominator: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    if numerator == 0 || denominator == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    Ok(numerator.checked_add(denominator - 1).ok_or(
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
    )? / denominator)
}

fn exact_peak_stored_byte_length(
    object_plans: &[ProofExternalMemoryObjectPlan],
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    let event_count =
        object_plans
            .len()
            .checked_mul(2)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    let mut liveness_events = Vec::new();
    liveness_events
        .try_reserve_exact(event_count)
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::AllocationLimitExceeded,
            )
        })?;
    for object_plan in object_plans {
        liveness_events.push((
            object_plan.issued_step(),
            true,
            object_plan.exact_byte_length(),
        ));
        liveness_events.push((
            object_plan.last_use_step().checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?,
            false,
            object_plan.exact_byte_length(),
        ));
    }
    liveness_events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
    let mut live_byte_length = 0_u64;
    let mut peak_stored_byte_length = 0_u64;
    for (_, is_issuance, byte_length) in liveness_events {
        if is_issuance {
            live_byte_length = checked_add_u64(live_byte_length, byte_length)?;
            peak_stored_byte_length = peak_stored_byte_length.max(live_byte_length);
        } else {
            live_byte_length = live_byte_length.checked_sub(byte_length).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidInput),
            )?;
        }
    }
    if live_byte_length != 0 || peak_stored_byte_length == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    Ok(peak_stored_byte_length)
}

pub(super) fn common_tree_materialization_write_transaction_count(
    leaf_count: u64,
    canonical_leaf_byte_length: u64,
    chunk_byte_length: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    if !leaf_count.is_power_of_two() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let leaf_object_byte_length = checked_multiply_u64(leaf_count, canonical_leaf_byte_length)?;
    let mut transaction_count = ceiling_division_u64(leaf_object_byte_length, chunk_byte_length)?;
    let mut level_node_count = leaf_count;
    loop {
        let level_byte_length = checked_multiply_u64(level_node_count, HASH_BYTE_LENGTH as u64)?;
        transaction_count = checked_add_u64(
            transaction_count,
            ceiling_division_u64(level_byte_length, chunk_byte_length)?,
        )?;
        if level_node_count == 1 {
            break;
        }
        level_node_count /= 2;
    }
    Ok(transaction_count)
}

fn common_tree_materialization_phase(source: ProofTreeCatalogSource) -> Option<u8> {
    match source {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle,
            ..
        } => Some(0),
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::AuxiliaryOracle,
            ..
        } => Some(1),
        ProofTreeCatalogSource::QuotientComponent { .. } => Some(2),
        ProofTreeCatalogSource::OpeningBatchMask => Some(3),
        ProofTreeCatalogSource::NonterminalFriLayer { .. } => Some(4),
        ProofTreeCatalogSource::RelationProofCreated { .. }
        | ProofTreeCatalogSource::RelationBoundPublic => None,
    }
}

/// Generates the exact object liveness graph for every common tree.  Read and
/// transaction ceilings include worst-case query collisions and frontiers;
/// they are operational limits, never proof fields.
pub(super) fn generated_common_proof_storage_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    catalog: &CompleteProofTreeCatalog,
    transcript_schedule: &CommonProofTranscriptSchedule,
    maximum_chunk_byte_length: u32,
    include_replay_polynomials: bool,
) -> Result<GeneratedCommonProofStoragePlan, GeneratedCommonProofStoragePlanError> {
    if maximum_chunk_byte_length == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let mut common_entries = catalog
        .entries()
        .iter()
        .filter_map(|entry| {
            common_tree_materialization_phase(entry.source())
                .map(|phase| (phase, entry.tree_catalog_index(), entry))
        })
        .collect::<Vec<_>>();
    common_entries.sort_unstable_by_key(|(phase, catalog_index, _)| (*phase, *catalog_index));
    if common_entries.is_empty() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }

    let base_tree_count = common_entries
        .iter()
        .take_while(|(phase, _, _)| *phase == 0)
        .count();
    let relation_replay_step = u32::try_from(base_tree_count).map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let transform_pass_count = if include_replay_polynomials {
        u32::try_from(variant.ordered_columns().len())
            .ok()
            .and_then(|column_count| {
                column_count.checked_mul(variant.evaluation_domain_size().trailing_zeros())
            })
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?
    } else {
        0
    };
    let first_relation_transform_step = relation_replay_step
        .checked_add(if include_replay_polynomials { 1 } else { 0 })
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let first_post_challenge_tree_step = first_relation_transform_step
        .checked_add(transform_pass_count)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let mut materialization_steps = BTreeMap::new();
    let mut next_post_challenge_tree_step = first_post_challenge_tree_step;
    for (materialization_index, (phase, catalog_index, _)) in common_entries.iter().enumerate() {
        let materialization_step = if *phase == 0 {
            u32::try_from(materialization_index).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?
        } else {
            let step = next_post_challenge_tree_step;
            next_post_challenge_tree_step = next_post_challenge_tree_step.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            step
        };
        if materialization_steps
            .insert(*catalog_index, materialization_step)
            .is_some()
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
    }
    let mut last_relation_evaluation_use_steps = BTreeMap::new();
    for (tree_index, descriptor) in variant.ordered_trees().iter().enumerate() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 2,
            ordered_column_ordinals,
        } = descriptor
        else {
            continue;
        };
        let tree_catalog_index = u16::try_from(tree_index).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let materialization_step = *materialization_steps.get(&tree_catalog_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        for column_ordinal in ordered_column_ordinals {
            last_relation_evaluation_use_steps
                .entry(*column_ordinal)
                .and_modify(|last_use_step: &mut u32| {
                    *last_use_step = (*last_use_step).max(materialization_step);
                })
                .or_insert(materialization_step);
        }
    }
    let query_step = next_post_challenge_tree_step;
    let step_count =
        query_step
            .checked_add(1)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    let chunk_byte_length = u64::from(maximum_chunk_byte_length);
    let hash_read_transaction_count =
        ceiling_division_u64(HASH_BYTE_LENGTH as u64, chunk_byte_length)?;
    let maximum_opened_leaf_count = u64::from(transcript_schedule.unique_query_count());

    let mut next_object_ordinal = 0_u32;
    let mut object_plans = Vec::new();
    let mut tree_plans = BTreeMap::new();
    let mut replay_polynomial_plans = BTreeMap::new();
    let mut relation_evaluation_transform_plans = BTreeMap::new();
    let mut maximum_total_written_byte_length = 0_u64;
    let mut maximum_total_read_byte_length = 0_u64;
    let mut maximum_transaction_count = 0_u64;

    for (_, catalog_index, entry) in &common_entries {
        let materialization_step = *materialization_steps.get(catalog_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        let tree_plan = common_proof_merkle_storage_plan(
            entry,
            next_object_ordinal,
            materialization_step,
            query_step,
        )
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        next_object_ordinal = tree_plan.next_object_ordinal();
        let context =
            entry
                .common_context()
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
        let leaf_count = u64::try_from(
            context
                .leaf_count()
                .map_err(CommonProofProverError::from)
                .map_err(GeneratedCommonProofStoragePlanError::Prover)?,
        )
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let opened_leaf_count = maximum_opened_leaf_count.min(leaf_count);
        let tree_height = u64::from(leaf_count.trailing_zeros());
        let frontier_node_bound = checked_multiply_u64(opened_leaf_count, tree_height)?;
        let construction_digest_read_count = leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let construction_read_byte_length =
            checked_multiply_u64(construction_digest_read_count, HASH_BYTE_LENGTH as u64)?;
        let query_leaf_read_byte_length = checked_multiply_u64(
            opened_leaf_count,
            u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
        )?;
        let query_frontier_read_byte_length =
            checked_multiply_u64(frontier_node_bound, HASH_BYTE_LENGTH as u64)?;
        maximum_total_read_byte_length = checked_add_u64(
            maximum_total_read_byte_length,
            checked_add_u64(
                construction_read_byte_length,
                checked_add_u64(query_leaf_read_byte_length, query_frontier_read_byte_length)?,
            )?,
        )?;
        if matches!(
            entry.source(),
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                ..
            }
        ) {
            let descriptor = variant
                .ordered_trees()
                .get(usize::from(*catalog_index))
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 2,
                ordered_column_ordinals,
            } = descriptor
            else {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            };
            let mut row_byte_length = 0_u64;
            for column_ordinal in ordered_column_ordinals {
                let column = variant
                    .ordered_columns()
                    .get(usize::try_from(*column_ordinal).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                row_byte_length = checked_add_u64(
                    row_byte_length,
                    resident_value_byte_length(column.value_type()),
                )?;
            }
            let paired_leaf_value_count =
                leaf_count
                    .checked_mul(2)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(paired_leaf_value_count, row_byte_length)?,
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_multiply_u64(
                    paired_leaf_value_count,
                    u64::try_from(ordered_column_ordinals.len()).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?,
                )?,
            )?;
        }

        let object_count = u64::try_from(tree_plan.object_plans().len()).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(object_count, 2)?,
        )?;
        for object_plan in tree_plan.object_plans() {
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                object_plan.exact_byte_length(),
            )?;
        }
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            common_tree_materialization_write_transaction_count(
                leaf_count,
                u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                chunk_byte_length,
            )?,
        )?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(construction_digest_read_count, hash_read_transaction_count)?,
        )?;
        let query_leaf_read_transaction_count = checked_multiply_u64(
            opened_leaf_count,
            ceiling_division_u64(
                u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                chunk_byte_length,
            )?,
        )?;
        let query_frontier_read_transaction_count =
            checked_multiply_u64(frontier_node_bound, hash_read_transaction_count)?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_add_u64(
                query_leaf_read_transaction_count,
                query_frontier_read_transaction_count,
            )?,
        )?;

        object_plans.extend_from_slice(tree_plan.object_plans());
        if tree_plans.insert(*catalog_index, tree_plan).is_some() {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
    }
    if include_replay_polynomials {
        if relation_replay_step >= query_step {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let replay_protection = match variant.proof_privacy_mode() {
            ProofPrivacyMode::PublicOnly => ProofExternalMemoryProtection::PublicIntegrity,
            ProofPrivacyMode::SecretBearing => {
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption
            }
        };
        let mut replay_specifications = Vec::new();
        replay_specifications
            .try_reserve_exact(
                variant
                    .ordered_columns()
                    .len()
                    .checked_add(usize::from(transcript_schedule.quotient_component_count()))
                    .and_then(|count| {
                        count.checked_add(
                            if transcript_schedule.privacy_mode()
                                == CommonProofPrivacyMode::SecretBearing
                            {
                                1
                            } else {
                                0
                            },
                        )
                    })
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?,
            )
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        for (column_index, column) in variant.ordered_columns().iter().enumerate() {
            replay_specifications.push((
                CommonProofReplayPolynomialKey::RelationColumn(
                    u32::try_from(column_index).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?,
                ),
                column.value_type(),
                usize::try_from(column.source_degree_bound_exclusive()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                relation_replay_step,
            ));
        }
        for (_, catalog_index, entry) in &common_entries {
            match entry.source() {
                ProofTreeCatalogSource::QuotientComponent { component_ordinal } => {
                    replay_specifications.push((
                        CommonProofReplayPolynomialKey::QuotientComponent(component_ordinal),
                        RelationColumnValueType::ChallengeExtension,
                        usize::try_from(relation_context.quotient_component_degree_bound_exclusive)
                            .map_err(|_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                        *materialization_steps.get(catalog_index).ok_or(
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidTree,
                            ),
                        )?,
                    ));
                }
                ProofTreeCatalogSource::OpeningBatchMask => {
                    let mut descriptors = variant.ordered_masks().iter().copied().filter(|mask| {
                        mask.mask_kind() == RelationMaskKind::OpeningBatch
                            && mask.target_class() == RelationMaskTargetClass::Batch
                            && mask.target_ordinal() == 0
                    });
                    let descriptor =
                        descriptors
                            .next()
                            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidMask,
                            ))?;
                    if descriptors.next().is_some() {
                        return Err(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    replay_specifications.push((
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        RelationColumnValueType::ChallengeExtension,
                        usize::try_from(descriptor.mask_degree_bound_exclusive()).map_err(
                            |_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            },
                        )?,
                        *materialization_steps.get(catalog_index).ok_or(
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidTree,
                            ),
                        )?,
                    ));
                }
                ProofTreeCatalogSource::RelationProofCreated { .. }
                | ProofTreeCatalogSource::NonterminalFriLayer { .. }
                | ProofTreeCatalogSource::RelationBoundPublic => {}
            }
        }
        let maximum_replay_count = u64::from(transcript_schedule.opening_claim_count())
            .checked_mul(2)
            .and_then(|count| {
                u64::try_from(catalog.entries().len())
                    .ok()
                    .and_then(|catalog_entry_count| count.checked_add(catalog_entry_count))
            })
            .and_then(|count| count.checked_add(u64::from(transcript_schedule.fri_fold_count())))
            .and_then(|count| count.checked_add(4))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        for (key, value_type, coefficient_count, issued_step) in replay_specifications {
            if coefficient_count == 0 || issued_step >= query_step {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
            let exact_byte_length = checked_multiply_u64(
                u64::try_from(coefficient_count).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                resident_value_byte_length(value_type),
            )?;
            let object = ProofExternalMemoryObject::new(next_object_ordinal);
            next_object_ordinal = next_object_ordinal.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                replay_protection,
                exact_byte_length,
                issued_step,
                issued_step,
                query_step,
            ));
            maximum_total_written_byte_length =
                checked_add_u64(maximum_total_written_byte_length, exact_byte_length)?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(exact_byte_length, maximum_replay_count)?,
            )?;
            let object_chunk_count = ceiling_division_u64(exact_byte_length, chunk_byte_length)?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_add_u64(
                    2,
                    checked_add_u64(
                        object_chunk_count,
                        checked_multiply_u64(object_chunk_count, maximum_replay_count)?,
                    )?,
                )?,
            )?;
            if replay_polynomial_plans
                .insert(
                    key,
                    CommonProofReplayPolynomialPlan {
                        object,
                        value_type,
                        coefficient_count,
                        exact_byte_length,
                    },
                )
                .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
        }

        let evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(variant.evaluation_domain_size()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
            relation_context.evaluation_coset_offset,
        )
        .map_err(CommonProofProverError::from)
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        for (column_index, _) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let source_plan = replay_polynomial_plans
                .get(&CommonProofReplayPolynomialKey::RelationColumn(
                    column_ordinal,
                ))
                .copied()
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let source = ExternalPolynomialVector::new(
                source_plan.object,
                source_plan.value_type,
                source_plan.coefficient_count,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            let first_executor_step = first_relation_transform_step
                .checked_add(
                    column_ordinal
                        .checked_mul(evaluation_domain.size().trailing_zeros())
                        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?,
                )
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let transform_plan = ExternalStockhamTransformPlan::new(
                evaluation_domain,
                ExternalStockhamTransformDirection::Forward,
                source,
                next_object_ordinal,
                first_executor_step,
                last_relation_evaluation_use_steps
                    .get(&column_ordinal)
                    .copied()
                    .unwrap_or(first_post_challenge_tree_step),
                maximum_chunk_byte_length,
                replay_protection,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            if transform_plan.next_executor_step()
                != first_executor_step
                    .checked_add(evaluation_domain.size().trailing_zeros())
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            next_object_ordinal = transform_plan.next_object_ordinal();
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                transform_plan.total_written_byte_length(),
            )?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                transform_plan.total_read_byte_length(),
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                transform_plan.maximum_transaction_count(),
            )?;
            object_plans.extend_from_slice(transform_plan.object_plans());
            if relation_evaluation_transform_plans
                .insert(column_ordinal, transform_plan)
                .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
        }
    }
    // One deletion transaction for each materialized root and one final
    // transaction for all query-live leaf/frontier objects.
    maximum_transaction_count = checked_add_u64(
        maximum_transaction_count,
        u64::try_from(common_entries.len())
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?
            .checked_add(1 + u64::from(include_replay_polynomials))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?,
    )?;
    let maximum_transaction_operation_count = u32::try_from(object_plans.len()).map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let maximum_stored_byte_length = exact_peak_stored_byte_length(&object_plans)?;
    let external_memory_plan = ProofExternalMemoryPlan::new(
        step_count,
        maximum_chunk_byte_length,
        chunk_byte_length,
        maximum_transaction_operation_count,
        maximum_stored_byte_length,
        maximum_total_written_byte_length,
        maximum_total_read_byte_length,
        maximum_transaction_count,
        object_plans,
    )
    .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
    Ok(GeneratedCommonProofStoragePlan {
        external_memory_plan,
        tree_plans,
        replay_polynomial_plans,
        relation_evaluation_transform_plans,
    })
}

pub(super) fn validate_generation_relation_trees(
    variant: &RelationPlanVariant,
    relation_trees: &[RelationProofTreeInput],
) -> Result<(), CommonProofProverError> {
    if relation_trees.len() != variant.ordered_trees().len() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for (descriptor, input) in variant.ordered_trees().iter().zip(relation_trees) {
        match (descriptor, input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width,
                    leaf_visibility,
                },
            ) => {
                let expected_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let expected_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let expected_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|index| variant.ordered_columns().get(index))
                        .is_some_and(|column| column.origin() == &RelationColumnOrigin::Prover)
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                if *tree_role != expected_role
                    || *row_width != expected_width
                    || *leaf_visibility != expected_visibility
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                validate_generation_tree_columns(variant, ordered_column_ordinals, None)?;
            }
            (
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                validate_generation_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let construction_matches = match (construction_kind, statement_tree) {
                    (
                        BoundTreeConstructionKind::CommittedMaterial,
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                    ) => ordered_column_ordinals.len() == 4,
                    (
                        BoundTreeConstructionKind::SetupPolynomial,
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                    ) => usize::try_from(*row_width)
                        .is_ok_and(|width| width == ordered_column_ordinals.len()),
                    _ => false,
                };
                if !construction_matches {
                    return Err(CommonProofProverError::InvalidTree);
                }
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        }
    }
    Ok(())
}

fn validate_generation_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for column_ordinal in ordered_column_ordinals {
        let column = variant
            .ordered_columns()
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofProverError::InvalidTree);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofProverError::InvalidTree);
            }
            (_, None) => {}
        }
    }
    Ok(())
}

pub(super) fn statement_owned_tree_root(
    input: &RelationProofTreeInput,
) -> Option<[u8; HASH_BYTE_LENGTH]> {
    match input {
        RelationProofTreeInput::BoundPublic(
            StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
            | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. },
        ) => Some(*expected_root),
        RelationProofTreeInput::ProofCreated { .. } => None,
    }
}

pub(super) fn unique_catalog_entry(
    catalog: &CompleteProofTreeCatalog,
    mut predicate: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<&ProofTreeCatalogEntry, CommonProofProverError> {
    let mut matches = catalog
        .entries()
        .iter()
        .filter(|entry| predicate(entry.source()));
    let entry = matches.next().ok_or(CommonProofProverError::InvalidTree)?;
    if matches.next().is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(entry)
}

pub(super) fn map_private_coin_generation_error<
    StorageError,
    CoinError,
    SinkError,
    BoundOpeningError,
>(
    error: CommonProofPrivateCoinError<CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        CommonProofPrivateCoinError::Prover(error) => CommonProofGenerationError::Prover(error),
        CommonProofPrivateCoinError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

pub(super) fn insert_materialized_tree(
    tree: StoredCommonProofMerkleTree,
    tree_roots: &mut [[u8; HASH_BYTE_LENGTH]],
    root_present: &mut [bool],
    stored_trees: &mut BTreeMap<u16, StoredCommonProofMerkleTree>,
) -> Result<(), CommonProofProverError> {
    let catalog_index = tree.tree_catalog_index();
    let tree_index = usize::from(catalog_index);
    let root = tree.root();
    let destination = tree_roots
        .get_mut(tree_index)
        .ok_or(CommonProofProverError::InvalidTree)?;
    let presence = root_present
        .get_mut(tree_index)
        .ok_or(CommonProofProverError::InvalidTree)?;
    if *presence || stored_trees.insert(catalog_index, tree).is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    *destination = root;
    *presence = true;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationInitializationError {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
}

/// Absolute WASM-memory safety bound, distinct from phone qualification targets.
pub(crate) const MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH: u64 = 671_088_640;
const COMMON_PROOF_EXECUTOR_RESIDENT_RESERVE_BYTE_LENGTH: u64 = 33_554_432;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CommonProofResidentMemoryPhase {
    PreparingInputs = 1,
    MaterializingRelationTree = 2,
    DerivingApplicationColumns = 3,
    PersistingRelationColumns = 4,
    ConstructingQuotient = 5,
    MaterializingQuotientTree = 6,
    DerivingOpenings = 7,
    ConstructingInitialFri = 8,
    FoldingFri = 9,
    EmittingQueries = 10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryPhasePlan {
    phase: CommonProofResidentMemoryPhase,
    executor_reserve_byte_length: u64,
    relation_column_catalog_byte_length: u64,
    trace_row_cache_byte_length: u64,
    trace_synthesis_scratch_byte_length: u64,
    replay_source_byte_length: u64,
    primary_vector_byte_length: u64,
    secondary_vector_byte_length: u64,
    claim_and_query_metadata_byte_length: u64,
    relation_rotation_block_byte_length: u64,
    external_working_set_byte_length: u64,
    query_prefetch_byte_length: u64,
    stream_window_byte_length: u64,
    total_byte_length: u64,
}

impl CommonProofResidentMemoryPhasePlan {
    pub(crate) const fn phase(&self) -> CommonProofResidentMemoryPhase {
        self.phase
    }

    pub(crate) const fn executor_reserve_byte_length(&self) -> u64 {
        self.executor_reserve_byte_length
    }

    pub(crate) const fn relation_column_catalog_byte_length(&self) -> u64 {
        self.relation_column_catalog_byte_length
    }

    pub(crate) const fn trace_row_cache_byte_length(&self) -> u64 {
        self.trace_row_cache_byte_length
    }

    pub(crate) const fn trace_synthesis_scratch_byte_length(&self) -> u64 {
        self.trace_synthesis_scratch_byte_length
    }

    pub(crate) const fn replay_source_byte_length(&self) -> u64 {
        self.replay_source_byte_length
    }

    pub(crate) const fn primary_vector_byte_length(&self) -> u64 {
        self.primary_vector_byte_length
    }

    pub(crate) const fn secondary_vector_byte_length(&self) -> u64 {
        self.secondary_vector_byte_length
    }

    pub(crate) const fn claim_and_query_metadata_byte_length(&self) -> u64 {
        self.claim_and_query_metadata_byte_length
    }

    pub(crate) const fn relation_rotation_block_byte_length(&self) -> u64 {
        self.relation_rotation_block_byte_length
    }

    pub(crate) const fn external_working_set_byte_length(&self) -> u64 {
        self.external_working_set_byte_length
    }

    pub(crate) const fn query_prefetch_byte_length(&self) -> u64 {
        self.query_prefetch_byte_length
    }

    pub(crate) const fn stream_window_byte_length(&self) -> u64 {
        self.stream_window_byte_length
    }

    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.total_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryPlan {
    phases: Vec<CommonProofResidentMemoryPhasePlan>,
    peak_byte_length: u64,
}

impl CommonProofResidentMemoryPlan {
    pub(crate) fn phases(&self) -> &[CommonProofResidentMemoryPhasePlan] {
        &self.phases
    }

    pub(crate) const fn peak_byte_length(&self) -> u64 {
        self.peak_byte_length
    }
}

fn checked_resident_add(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn checked_resident_multiply(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn resident_value_byte_length(value_type: RelationColumnValueType) -> u64 {
    match value_type {
        RelationColumnValueType::BaseField => 8,
        RelationColumnValueType::ChallengeExtension => {
            u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE).expect("extension degree fits u64") * 8
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resident_phase_plan(
    phase: CommonProofResidentMemoryPhase,
    relation_column_catalog_byte_length: u64,
    trace_row_cache_byte_length: u64,
    trace_synthesis_scratch_byte_length: u64,
    replay_source_byte_length: u64,
    primary_vector_byte_length: u64,
    secondary_vector_byte_length: u64,
    claim_and_query_metadata_byte_length: u64,
    relation_rotation_block_byte_length: u64,
    external_working_set_byte_length: u64,
    query_prefetch_byte_length: u64,
    stream_window_byte_length: u64,
) -> Result<CommonProofResidentMemoryPhasePlan, CommonProofProverError> {
    let total_byte_length = [
        COMMON_PROOF_EXECUTOR_RESIDENT_RESERVE_BYTE_LENGTH,
        relation_column_catalog_byte_length,
        trace_row_cache_byte_length,
        trace_synthesis_scratch_byte_length,
        replay_source_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        relation_rotation_block_byte_length,
        external_working_set_byte_length,
        query_prefetch_byte_length,
        stream_window_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_resident_add)?;
    if total_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
    }
    Ok(CommonProofResidentMemoryPhasePlan {
        phase,
        executor_reserve_byte_length: COMMON_PROOF_EXECUTOR_RESIDENT_RESERVE_BYTE_LENGTH,
        relation_column_catalog_byte_length,
        trace_row_cache_byte_length,
        trace_synthesis_scratch_byte_length,
        replay_source_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        relation_rotation_block_byte_length,
        external_working_set_byte_length,
        query_prefetch_byte_length,
        stream_window_byte_length,
        total_byte_length,
    })
}

/// Derives the hard resident live-set for the implemented external-memory
/// schedule. Every potentially domain-sized state-machine field is assigned to
/// a phase: the complete relation-column catalog and integer-lift row cache,
/// one replay source, quotient and FRI vectors, DEEP/opening metadata, terminal
/// and query vectors, the bounded external materialization, transform, and
/// write working sets, query prefetch, and the acknowledged stream window.
/// Complete Merkle levels and polynomial vectors are external.
pub(crate) fn common_proof_resident_memory_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    maximum_prefetched_query_byte_length: u64,
    external_memory_write_chunk_byte_length: u64,
    maximum_stream_window_byte_length: u64,
) -> Result<CommonProofResidentMemoryPlan, CommonProofProverError> {
    if maximum_prefetched_query_byte_length == 0
        || external_memory_write_chunk_byte_length == 0
        || maximum_stream_window_byte_length == 0
        || variant.evaluation_domain_size() != catalog.evaluation_domain_size()
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let evaluation_domain_size = variant.evaluation_domain_size();
    let trace_domain_size = variant.trace_domain_size();
    let extension_value_byte_length =
        resident_value_byte_length(RelationColumnValueType::ChallengeExtension);
    let base_value_byte_length = resident_value_byte_length(RelationColumnValueType::BaseField);
    let mut relation_column_catalog_byte_length = 0_u64;
    let mut base_column_count = 0_u64;
    let mut maximum_replay_source_byte_length = 0_u64;
    let mut maximum_scalar_lde_byte_length = 0_u64;
    let mut maximum_relation_persistence_external_working_set_byte_length = 0_u64;
    for column in variant.ordered_columns() {
        let value_byte_length = resident_value_byte_length(column.value_type());
        let source_byte_length =
            checked_resident_multiply(column.source_degree_bound_exclusive(), value_byte_length)?;
        relation_column_catalog_byte_length =
            checked_resident_add(relation_column_catalog_byte_length, source_byte_length)?;
        maximum_replay_source_byte_length =
            maximum_replay_source_byte_length.max(source_byte_length);
        maximum_scalar_lde_byte_length = maximum_scalar_lde_byte_length.max(
            checked_resident_multiply(evaluation_domain_size, value_byte_length)?,
        );
        let maximum_scan_element_count = external_memory_write_chunk_byte_length
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidInput)?;
        let stockham_scan_byte_length =
            checked_resident_multiply(maximum_scan_element_count, value_byte_length)?;
        let stockham_working_set_byte_length = checked_resident_add(
            checked_resident_multiply(stockham_scan_byte_length, 3)?,
            external_memory_write_chunk_byte_length,
        )?;
        let replay_writer_working_set_byte_length =
            checked_resident_add(external_memory_write_chunk_byte_length, value_byte_length)?;
        maximum_relation_persistence_external_working_set_byte_length =
            maximum_relation_persistence_external_working_set_byte_length
                .max(stockham_working_set_byte_length)
                .max(replay_writer_working_set_byte_length);
        if column.value_type() == RelationColumnValueType::BaseField {
            base_column_count = checked_resident_add(base_column_count, 1)?;
        }
    }
    if maximum_replay_source_byte_length == 0 || maximum_scalar_lde_byte_length == 0 {
        return Err(CommonProofProverError::InvalidColumn);
    }

    let trace_row_cache_byte_length = checked_resident_multiply(
        checked_resident_multiply(base_column_count, trace_domain_size)?,
        base_value_byte_length,
    )?;
    // The largest integer-lift helper simultaneously owns the product
    // accumulator, two suffix vectors, two transpose vectors, one contribution
    // vector, and the reduced/evaluated scratch pair used while populating the
    // cache. These eight trace vectors are dropped before transcript progress.
    let trace_synthesis_scratch_byte_length = checked_resident_multiply(
        checked_resident_multiply(trace_domain_size, base_value_byte_length)?,
        8,
    )?;

    let mut maximum_relation_merkle_working_set_byte_length = 0_u64;
    let mut maximum_extension_merkle_working_set_byte_length = 0_u64;
    for entry in catalog.entries() {
        let Some(context) = entry.common_context() else {
            continue;
        };
        let leaf_count = u64::try_from(context.leaf_count()?)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if leaf_count == 0 || !leaf_count.is_power_of_two() {
            return Err(CommonProofProverError::InvalidTree);
        }
        let canonical_leaf_byte_length = u64::try_from(canonical_common_proof_leaf_byte_length(
            context,
            common_proof_tree_value_type(entry)?,
        )?)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        // The materializer owns one canonical leaf, both typed phase values,
        // the two child plus one parent digests, and two external-memory write
        // chunks that gather exact object-wide records. All complete levels
        // live in external memory.
        let working_set_byte_length = checked_resident_add(
            checked_resident_add(
                checked_resident_multiply(canonical_leaf_byte_length, 2)?,
                checked_resident_multiply(3, HASH_BYTE_LENGTH as u64)?,
            )?,
            checked_resident_multiply(external_memory_write_chunk_byte_length, 2)?,
        )?;
        match entry.source() {
            ProofTreeCatalogSource::RelationProofCreated { .. } => {
                maximum_relation_merkle_working_set_byte_length =
                    maximum_relation_merkle_working_set_byte_length.max(working_set_byte_length);
            }
            ProofTreeCatalogSource::QuotientComponent { .. }
            | ProofTreeCatalogSource::OpeningBatchMask
            | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                maximum_extension_merkle_working_set_byte_length =
                    maximum_extension_merkle_working_set_byte_length.max(working_set_byte_length);
            }
            ProofTreeCatalogSource::RelationBoundPublic => {}
        }
    }
    // Relation-column persistence serially writes replay polynomials, runs one
    // Stockham transform, or materializes one relation tree. The state machine
    // never owns these working sets concurrently, so the phase owns their
    // maximum rather than their sum.
    maximum_relation_persistence_external_working_set_byte_length =
        maximum_relation_persistence_external_working_set_byte_length
            .max(maximum_relation_merkle_working_set_byte_length);

    let evaluation_extension_vector_byte_length =
        checked_resident_multiply(evaluation_domain_size, extension_value_byte_length)?;
    let relation_rotation_count = required_relation_rotations_by_column(variant)?
        .into_iter()
        .try_fold(0_u64, |count, rotations| {
            checked_resident_add(
                count,
                u64::try_from(rotations.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
        })?;
    let relation_rotation_block_byte_length = checked_resident_multiply(
        checked_resident_multiply(
            evaluation_domain_size.min(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH as u64),
            relation_rotation_count,
        )?,
        extension_value_byte_length,
    )?;
    let quotient_component_byte_length = checked_resident_multiply(
        relation_context.quotient_component_degree_bound_exclusive,
        extension_value_byte_length,
    )?;
    let opening_accumulator_byte_length = checked_resident_multiply(
        variant
            .opening_degree_bound_exclusive()
            .checked_sub(1)
            .ok_or(CommonProofProverError::InvalidOpening)?,
        extension_value_byte_length,
    )?;
    let quotient_cursor_byte_length = checked_resident_add(
        evaluation_extension_vector_byte_length,
        checked_resident_multiply(quotient_component_byte_length, 2)?,
    )?;
    let opening_claim_count = u64::try_from(variant.ordered_opening_claims().len())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let opening_point_count = variant
        .ordered_opening_claims()
        .iter()
        .map(|claim| u64::from(claim.opening_point_ordinal()) + 1)
        .max()
        .unwrap_or(0);
    let opening_metadata_byte_length = checked_resident_multiply(
        checked_resident_add(
            checked_resident_multiply(opening_claim_count, 2)?,
            opening_point_count,
        )?,
        extension_value_byte_length,
    )?;
    let terminal_coefficient_byte_length = checked_resident_multiply(
        u64::from(relation_context.final_polynomial_degree_bound_exclusive),
        extension_value_byte_length,
    )?;
    let query_representative_byte_length = checked_resident_multiply(
        checked_resident_multiply(u64::from(transcript_schedule.unique_query_count()), 2)?,
        u64::try_from(core::mem::size_of::<u64>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let query_metadata_byte_length = checked_resident_add(
        terminal_coefficient_byte_length,
        query_representative_byte_length,
    )?;

    let phases = vec![
        resident_phase_plan(
            CommonProofResidentMemoryPhase::PreparingInputs,
            relation_column_catalog_byte_length,
            trace_row_cache_byte_length,
            trace_synthesis_scratch_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingRelationTree,
            relation_column_catalog_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_relation_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::DerivingApplicationColumns,
            relation_column_catalog_byte_length,
            trace_row_cache_byte_length,
            trace_synthesis_scratch_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::PersistingRelationColumns,
            relation_column_catalog_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_relation_persistence_external_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingQuotient,
            0,
            0,
            0,
            maximum_replay_source_byte_length,
            evaluation_extension_vector_byte_length,
            maximum_scalar_lde_byte_length,
            0,
            relation_rotation_block_byte_length,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingQuotientTree,
            0,
            0,
            0,
            0,
            quotient_cursor_byte_length,
            0,
            0,
            0,
            maximum_extension_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::DerivingOpenings,
            0,
            0,
            0,
            maximum_replay_source_byte_length.max(quotient_component_byte_length),
            quotient_component_byte_length,
            0,
            opening_metadata_byte_length,
            0,
            maximum_extension_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingInitialFri,
            0,
            0,
            0,
            maximum_replay_source_byte_length.max(quotient_component_byte_length),
            opening_accumulator_byte_length,
            0,
            opening_metadata_byte_length,
            0,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::FoldingFri,
            0,
            0,
            0,
            0,
            evaluation_extension_vector_byte_length,
            0,
            opening_metadata_byte_length,
            0,
            maximum_extension_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::EmittingQueries,
            0,
            0,
            0,
            0,
            0,
            0,
            query_metadata_byte_length,
            0,
            0,
            maximum_prefetched_query_byte_length,
            maximum_stream_window_byte_length,
        )?,
    ];
    let peak_byte_length = phases
        .iter()
        .map(CommonProofResidentMemoryPhasePlan::total_byte_length)
        .max()
        .ok_or(CommonProofProverError::InvalidInput)?;
    Ok(CommonProofResidentMemoryPlan {
        phases,
        peak_byte_length,
    })
}
