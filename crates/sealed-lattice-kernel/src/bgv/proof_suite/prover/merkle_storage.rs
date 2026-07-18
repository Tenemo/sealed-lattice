use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinSource, CommonProofProverError, HASH_BYTE_LENGTH, ProofBaseFieldElement,
    ProofBodyError, ProofChallengeExtensionElement, ProofExternalMemory,
    ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError, ProofExternalMemoryObject,
    ProofExternalMemoryObjectPlan, ProofExternalMemoryProtection, ProofLeafVisibility,
    ProofMerkleTreeContext, ProofOraclePhasePairLeaf, ProofTreeCatalogEntry,
    ProofTreeCatalogSource, ProofTreeRole, ProofTreeValue, RelationColumnValueType, Zeroize,
    Zeroizing, canonical_leaf_byte_length, entry_leaf_count, minimal_frontier_coordinates,
    opened_leaf_indexes,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofTreeStorageError<StorageError, CoinError> {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    CoinSource(CoinError),
}

/// External-memory location of one common proof-created Merkle tree.  Canonical
/// leaves and every digest level remain random-accessible until the generated
/// liveness plan reaches the proof-query step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredCommonProofMerkleTree {
    tree_catalog_index: u16,
    catalog_entry: ProofTreeCatalogEntry,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    root: [u8; HASH_BYTE_LENGTH],
}

impl StoredCommonProofMerkleTree {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn root(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.root
    }

    pub(crate) const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub(crate) const fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }
}

/// Exact external-memory allocation for one common proof-created Merkle tree.
/// The object identifiers are plan-local and deliberately contain no secret
/// material.  The returned liveness entries can be concatenated with the
/// entries for the other common trees before constructing the executor plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofMerkleStoragePlan {
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    object_plans: Vec<ProofExternalMemoryObjectPlan>,
    canonical_leaf_byte_length: usize,
    next_object_ordinal: u32,
}

impl CommonProofMerkleStoragePlan {
    pub(crate) fn object_plans(&self) -> &[ProofExternalMemoryObjectPlan] {
        &self.object_plans
    }

    pub(crate) const fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }

    pub(crate) const fn next_object_ordinal(&self) -> u32 {
        self.next_object_ordinal
    }
}

/// Generates the exact object lengths and last-use deletion schedule for one
/// common tree.  Canonical leaf length is derived through the same encoder used
/// by the committed leaf, avoiding a second hand-maintained wire-size formula.
/// Checked relation trees contain base-field rows; quotient, batch-mask, and
/// FRI trees contain extension-field rows.
pub(crate) fn common_proof_merkle_storage_plan(
    catalog_entry: &ProofTreeCatalogEntry,
    evaluation_domain_size: u64,
    first_object_ordinal: u32,
    materialization_step: u32,
    query_step: u32,
) -> Result<CommonProofMerkleStoragePlan, CommonProofProverError> {
    if query_step < materialization_step {
        return Err(CommonProofProverError::InvalidTree);
    }
    let leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
        .map_err(map_proof_body_tree_error)?;
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let canonical_leaf_byte_length =
        canonical_leaf_byte_length(catalog_entry).map_err(map_proof_body_tree_error)?;
    let stored_leaf_byte_length = u64::try_from(canonical_leaf_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_mul(u64::try_from(leaf_count).map_err(|_| CommonProofProverError::CountOverflow)?)
        .ok_or(CommonProofProverError::CountOverflow)?;

    let leaf_bytes_object = ProofExternalMemoryObject::new(first_object_ordinal);
    let leaf_protection = match catalog_entry.materialized_leaf_visibility() {
        ProofLeafVisibility::Public => ProofExternalMemoryProtection::PublicIntegrity,
        ProofLeafVisibility::SecretBearing => {
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption
        }
    };
    let mut object_plans = vec![ProofExternalMemoryObjectPlan::new(
        leaf_bytes_object,
        leaf_protection,
        stored_leaf_byte_length,
        materialization_step,
        materialization_step,
        query_step,
    )];
    let level_count = usize::try_from(leaf_count.trailing_zeros())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    object_plans
        .try_reserve_exact(level_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut digest_level_objects = Vec::new();
    digest_level_objects
        .try_reserve_exact(level_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut node_count = leaf_count;
    let mut next_object_ordinal = first_object_ordinal
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    for level_ordinal in 0..level_count {
        let object = ProofExternalMemoryObject::new(next_object_ordinal);
        next_object_ordinal = next_object_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let exact_byte_length = u64::try_from(node_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(HASH_BYTE_LENGTH as u64)
            .ok_or(CommonProofProverError::CountOverflow)?;
        // The root is cached in `StoredCommonProofMerkleTree`; unlike every
        // lower level it is never needed to construct an authentication
        // frontier and can be removed when materialization completes.
        let last_use_step = if level_ordinal + 1 == level_count {
            materialization_step
        } else {
            query_step
        };
        digest_level_objects.push(object);
        object_plans.push(ProofExternalMemoryObjectPlan::new(
            object,
            ProofExternalMemoryProtection::PublicIntegrity,
            exact_byte_length,
            materialization_step,
            materialization_step,
            last_use_step,
        ));
        node_count /= 2;
    }
    Ok(CommonProofMerkleStoragePlan {
        leaf_bytes_object,
        digest_level_objects,
        object_plans,
        canonical_leaf_byte_length,
        next_object_ordinal,
    })
}

pub(super) fn common_proof_tree_value_type(
    catalog_entry: &ProofTreeCatalogEntry,
) -> Result<RelationColumnValueType, CommonProofProverError> {
    match catalog_entry.source() {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle | ProofTreeRole::AuxiliaryOracle,
            ..
        } => Ok(RelationColumnValueType::BaseField),
        ProofTreeCatalogSource::QuotientComponent { .. }
        | ProofTreeCatalogSource::OpeningBatchMask
        | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
            Ok(RelationColumnValueType::ChallengeExtension)
        }
        ProofTreeCatalogSource::RelationBoundPublic => Ok(RelationColumnValueType::BaseField),
        ProofTreeCatalogSource::RelationProofCreated { .. } => {
            Err(CommonProofProverError::InvalidTree)
        }
    }
}

pub(super) fn canonical_common_proof_leaf_byte_length(
    context: &ProofMerkleTreeContext,
    value_type: RelationColumnValueType,
) -> Result<usize, CommonProofProverError> {
    let row_width =
        usize::try_from(context.row_width()).map_err(|_| CommonProofProverError::CountOverflow)?;
    let empty_value = match value_type {
        RelationColumnValueType::BaseField => ProofTreeValue::Base(ProofBaseFieldElement::ZERO),
        RelationColumnValueType::ChallengeExtension => {
            ProofTreeValue::Extension(ProofChallengeExtensionElement::ZERO)
        }
    };
    let row = vec![empty_value; row_width];
    let secret_salt = (context.leaf_visibility() == ProofLeafVisibility::SecretBearing)
        .then_some([0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]);
    Ok(
        ProofOraclePhasePairLeaf::new(context, 0, secret_salt, row.clone(), row)?
            .canonical_bytes()?
            .len(),
    )
}

fn common_proof_tree_value_has_type(
    value: &ProofTreeValue,
    expected_type: RelationColumnValueType,
) -> bool {
    matches!(
        (value, expected_type),
        (ProofTreeValue::Base(_), RelationColumnValueType::BaseField)
            | (
                ProofTreeValue::Extension(_),
                RelationColumnValueType::ChallengeExtension
            )
    )
}

fn common_proof_merkle_storage_plan_matches(
    catalog_entry: &ProofTreeCatalogEntry,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    storage_plan: &CommonProofMerkleStoragePlan,
) -> Result<bool, CommonProofProverError> {
    let expected_object_plan_count = storage_plan
        .digest_level_objects
        .len()
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if storage_plan.object_plans.len() != expected_object_plan_count {
        return Ok(false);
    }
    let leaf_plan = storage_plan
        .object_plans
        .first()
        .copied()
        .ok_or(CommonProofProverError::InvalidTree)?;
    let expected_leaf_protection = match catalog_entry.materialized_leaf_visibility() {
        ProofLeafVisibility::Public => ProofExternalMemoryProtection::PublicIntegrity,
        ProofLeafVisibility::SecretBearing => {
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption
        }
    };
    let expected_leaf_storage_byte_length = u64::try_from(canonical_leaf_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_mul(u64::try_from(leaf_count).map_err(|_| CommonProofProverError::CountOverflow)?)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let materialization_step = leaf_plan.issued_step();
    let query_step = leaf_plan.last_use_step();
    if leaf_plan.object() != storage_plan.leaf_bytes_object
        || leaf_plan.protection() != expected_leaf_protection
        || leaf_plan.exact_byte_length() != expected_leaf_storage_byte_length
        || leaf_plan.seal_step() != materialization_step
        || query_step < materialization_step
    {
        return Ok(false);
    }

    let first_object_ordinal = storage_plan.leaf_bytes_object.ordinal();
    let expected_next_object_ordinal = first_object_ordinal
        .checked_add(
            u32::try_from(expected_object_plan_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
    if storage_plan.next_object_ordinal != expected_next_object_ordinal {
        return Ok(false);
    }

    let mut level_node_count = leaf_count;
    for (level_ordinal, object) in storage_plan.digest_level_objects.iter().enumerate() {
        let plan = storage_plan.object_plans[level_ordinal + 1];
        let expected_object_ordinal = first_object_ordinal
            .checked_add(
                u32::try_from(level_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let expected_byte_length = u64::try_from(level_node_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(HASH_BYTE_LENGTH as u64)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let is_root_level = level_ordinal + 1 == storage_plan.digest_level_objects.len();
        let expected_last_use_step = if is_root_level {
            materialization_step
        } else {
            query_step
        };
        if object.ordinal() != expected_object_ordinal
            || plan.object() != *object
            || plan.protection() != ProofExternalMemoryProtection::PublicIntegrity
            || plan.exact_byte_length() != expected_byte_length
            || plan.issued_step() != materialization_step
            || plan.seal_step() != materialization_step
            || plan.last_use_step() != expected_last_use_step
        {
            return Ok(false);
        }
        level_node_count /= 2;
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofMerkleMaterializerPhase {
    BeginLeafBytes,
    BeginLeafDigests,
    NeedLeafValues,
    WriteLeafBytes,
    WriteLeafDigest,
    FlushLeafBytes,
    FlushLeafDigests,
    SealLeafBytes,
    SealLeafDigests,
    BeginParentLevel,
    ReadLeftChild,
    ReadRightChild,
    WriteParentDigest,
    FlushParentLevel,
    SealParentLevel,
    ReadRoot,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofMerkleMaterializerProgress {
    StorageTransactionCompleted,
    NeedsLeafValues { leaf_index: u64 },
    Complete,
}

/// Resumable common-tree materialization for the browser worker.  Every call
/// to `advance_storage` performs at most one bounded storage transaction.  If
/// the recorder yields, operation-specific offsets and executor state do not
/// advance; replaying the exact operation is therefore safe.  Zero-work phase
/// transitions may occur before that operation is issued.  A secret leaf is
/// sampled and encoded once by `supply_next_leaf` and retained in zeroizing
/// memory across all of its bounded append transactions.
pub(crate) struct CommonProofMerkleMaterializer {
    tree_catalog_index: u16,
    catalog_entry: ProofTreeCatalogEntry,
    value_type: RelationColumnValueType,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    phase: CommonProofMerkleMaterializerPhase,
    next_leaf_index: usize,
    current_leaf_bytes: Zeroizing<Vec<u8>>,
    current_leaf_digest: [u8; HASH_BYTE_LENGTH],
    leaf_bytes_write_chunk: Zeroizing<Vec<u8>>,
    digest_write_chunk: Zeroizing<Vec<u8>>,
    current_byte_offset: usize,
    current_level_ordinal: usize,
    current_parent_index: usize,
    left_child_digest: [u8; HASH_BYTE_LENGTH],
    right_child_digest: [u8; HASH_BYTE_LENGTH],
    root: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofMerkleMaterializer {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) fn new(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        storage_plan: CommonProofMerkleStoragePlan,
    ) -> Result<Self, CommonProofProverError> {
        let leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
            .map_err(map_proof_body_tree_error)?;
        let value_type = common_proof_tree_value_type(catalog_entry)?;
        let expected_leaf_byte_length =
            canonical_leaf_byte_length(catalog_entry).map_err(map_proof_body_tree_error)?;
        let expected_level_count = usize::try_from(leaf_count.trailing_zeros())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || storage_plan.digest_level_objects.len() != expected_level_count
            || storage_plan.canonical_leaf_byte_length != expected_leaf_byte_length
            || !common_proof_merkle_storage_plan_matches(
                catalog_entry,
                leaf_count,
                expected_leaf_byte_length,
                &storage_plan,
            )?
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(Self {
            tree_catalog_index: catalog_entry.tree_catalog_index(),
            catalog_entry: catalog_entry.clone(),
            value_type,
            leaf_count,
            canonical_leaf_byte_length: storage_plan.canonical_leaf_byte_length,
            leaf_bytes_object: storage_plan.leaf_bytes_object,
            digest_level_objects: storage_plan.digest_level_objects,
            phase: CommonProofMerkleMaterializerPhase::BeginLeafBytes,
            next_leaf_index: 0,
            current_leaf_bytes: Zeroizing::new(Vec::new()),
            current_leaf_digest: [0; HASH_BYTE_LENGTH],
            leaf_bytes_write_chunk: Zeroizing::new(Vec::new()),
            digest_write_chunk: Zeroizing::new(Vec::new()),
            current_byte_offset: 0,
            current_level_ordinal: 0,
            current_parent_index: 0,
            left_child_digest: [0; HASH_BYTE_LENGTH],
            right_child_digest: [0; HASH_BYTE_LENGTH],
            root: [0; HASH_BYTE_LENGTH],
        })
    }

    fn fill_write_chunk(
        write_chunk: &mut Vec<u8>,
        source: &[u8],
        source_offset: &mut usize,
        maximum_chunk_byte_length: usize,
    ) -> Result<(), CommonProofProverError> {
        if maximum_chunk_byte_length == 0
            || write_chunk.len() > maximum_chunk_byte_length
            || *source_offset > source.len()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        if write_chunk.len() == maximum_chunk_byte_length || *source_offset == source.len() {
            return Ok(());
        }
        write_chunk
            .try_reserve_exact(maximum_chunk_byte_length - write_chunk.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let copied_byte_length =
            (maximum_chunk_byte_length - write_chunk.len()).min(source.len() - *source_offset);
        let source_end = source_offset
            .checked_add(copied_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        write_chunk.extend_from_slice(&source[*source_offset..source_end]);
        *source_offset = source_end;
        Ok(())
    }

    fn finish_current_leaf(&mut self) -> Result<(), CommonProofProverError> {
        if self.current_byte_offset != HASH_BYTE_LENGTH || self.next_leaf_index >= self.leaf_count {
            return Err(CommonProofProverError::InvalidTree);
        }
        self.current_leaf_bytes.zeroize();
        self.current_leaf_digest = [0; HASH_BYTE_LENGTH];
        self.current_byte_offset = 0;
        self.next_leaf_index = self
            .next_leaf_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.phase = if self.next_leaf_index == self.leaf_count {
            CommonProofMerkleMaterializerPhase::FlushLeafBytes
        } else {
            CommonProofMerkleMaterializerPhase::NeedLeafValues
        };
        Ok(())
    }

    fn finish_current_parent_digest(&mut self) -> Result<(), CommonProofProverError> {
        if self.current_byte_offset != HASH_BYTE_LENGTH
            || self.current_level_ordinal == 0
            || self.current_level_ordinal >= self.digest_level_objects.len()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        self.current_leaf_digest = [0; HASH_BYTE_LENGTH];
        self.current_byte_offset = 0;
        self.current_parent_index = self
            .current_parent_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let parent_count = self.leaf_count >> self.current_level_ordinal;
        if self.current_parent_index > parent_count {
            return Err(CommonProofProverError::InvalidTree);
        }
        self.phase = if self.current_parent_index == parent_count {
            CommonProofMerkleMaterializerPhase::FlushParentLevel
        } else {
            CommonProofMerkleMaterializerPhase::ReadLeftChild
        };
        Ok(())
    }

    pub(crate) fn supply_next_leaf<Coins>(
        &mut self,
        first_point_values: Zeroizing<Vec<ProofTreeValue>>,
        opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
        persistent_leaf_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        coins: &mut Coins,
    ) -> Result<(), CommonProofTreeStorageError<core::convert::Infallible, Coins::Error>>
    where
        Coins: CommonProofPrivateCoinSource,
    {
        let expected_row_width = self
            .catalog_entry
            .materialized_row_width()
            .map_err(map_proof_body_tree_error)
            .map_err(CommonProofTreeStorageError::Prover)?;
        if self.phase != CommonProofMerkleMaterializerPhase::NeedLeafValues
            || self.next_leaf_index >= self.leaf_count
            || first_point_values.len() != expected_row_width
            || opposite_point_values.len() != expected_row_width
            || first_point_values
                .iter()
                .chain(opposite_point_values.iter())
                .any(|value| !common_proof_tree_value_has_type(value, self.value_type))
        {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let secret_salt = if self.catalog_entry.requires_persistent_leaf_salt() {
            Some(
                persistent_leaf_salt.ok_or(CommonProofTreeStorageError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?,
            )
        } else if persistent_leaf_salt.is_some() {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        } else if self.catalog_entry.materialized_leaf_visibility()
            == ProofLeafVisibility::SecretBearing
        {
            let mut salt = [0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
            coins
                .fill_raw_bytes(CommonProofPrivateCoinCoordinate::proof_salt(), &mut salt)
                .map_err(CommonProofTreeStorageError::CoinSource)?;
            Some(salt)
        } else {
            None
        };
        let (canonical_bytes, leaf_digest) = self
            .catalog_entry
            .encode_materialized_leaf(
                u64::try_from(self.next_leaf_index).map_err(|_| {
                    CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
                })?,
                secret_salt,
                first_point_values,
                opposite_point_values,
            )
            .map_err(map_proof_body_tree_error)
            .map_err(CommonProofTreeStorageError::Prover)?;
        if canonical_bytes.len() != self.canonical_leaf_byte_length {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        self.current_leaf_digest = leaf_digest;
        self.current_leaf_bytes = Zeroizing::new(canonical_bytes);
        self.current_byte_offset = 0;
        self.phase = CommonProofMerkleMaterializerPhase::WriteLeafBytes;
        Ok(())
    }

    pub(crate) fn advance_storage<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        CommonProofMerkleMaterializerProgress,
        CommonProofTreeStorageError<Storage::Error, core::convert::Infallible>,
    > {
        let maximum_chunk_byte_length = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
            })?;
        if maximum_chunk_byte_length == 0 {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }

        loop {
            match self.phase {
                CommonProofMerkleMaterializerPhase::BeginLeafBytes => {
                    executor
                        .begin_object(storage, self.leaf_bytes_object)
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.phase = CommonProofMerkleMaterializerPhase::BeginLeafDigests;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::BeginLeafDigests => {
                    executor
                        .begin_object(storage, self.digest_level_objects[0])
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.phase = CommonProofMerkleMaterializerPhase::NeedLeafValues;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::NeedLeafValues => {
                    return Ok(CommonProofMerkleMaterializerProgress::NeedsLeafValues {
                        leaf_index: u64::try_from(self.next_leaf_index).map_err(|_| {
                            CommonProofTreeStorageError::Prover(
                                CommonProofProverError::CountOverflow,
                            )
                        })?,
                    });
                }
                CommonProofMerkleMaterializerPhase::WriteLeafBytes => {
                    Self::fill_write_chunk(
                        &mut self.leaf_bytes_write_chunk,
                        &self.current_leaf_bytes,
                        &mut self.current_byte_offset,
                        maximum_chunk_byte_length,
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    let leaf_is_buffered =
                        self.current_byte_offset == self.current_leaf_bytes.len();
                    if self.leaf_bytes_write_chunk.len() == maximum_chunk_byte_length {
                        executor
                            .append_object_bytes(
                                storage,
                                self.leaf_bytes_object,
                                &self.leaf_bytes_write_chunk,
                            )
                            .map_err(CommonProofTreeStorageError::Storage)?;
                        self.leaf_bytes_write_chunk.zeroize();
                        if leaf_is_buffered {
                            self.current_byte_offset = 0;
                            self.phase = CommonProofMerkleMaterializerPhase::WriteLeafDigest;
                        }
                        return Ok(
                            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted,
                        );
                    }
                    if !leaf_is_buffered {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.current_byte_offset = 0;
                    self.phase = CommonProofMerkleMaterializerPhase::WriteLeafDigest;
                }
                CommonProofMerkleMaterializerPhase::WriteLeafDigest => {
                    Self::fill_write_chunk(
                        &mut self.digest_write_chunk,
                        &self.current_leaf_digest,
                        &mut self.current_byte_offset,
                        maximum_chunk_byte_length,
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    let digest_is_buffered = self.current_byte_offset == HASH_BYTE_LENGTH;
                    if self.digest_write_chunk.len() == maximum_chunk_byte_length {
                        executor
                            .append_object_bytes(
                                storage,
                                self.digest_level_objects[0],
                                &self.digest_write_chunk,
                            )
                            .map_err(CommonProofTreeStorageError::Storage)?;
                        self.digest_write_chunk.zeroize();
                        if digest_is_buffered {
                            self.finish_current_leaf()
                                .map_err(CommonProofTreeStorageError::Prover)?;
                        }
                        return Ok(
                            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted,
                        );
                    }
                    if !digest_is_buffered {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.finish_current_leaf()
                        .map_err(CommonProofTreeStorageError::Prover)?;
                }
                CommonProofMerkleMaterializerPhase::FlushLeafBytes => {
                    if self.leaf_bytes_write_chunk.is_empty() {
                        self.phase = CommonProofMerkleMaterializerPhase::FlushLeafDigests;
                        continue;
                    }
                    executor
                        .append_object_bytes(
                            storage,
                            self.leaf_bytes_object,
                            &self.leaf_bytes_write_chunk,
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.leaf_bytes_write_chunk.zeroize();
                    self.phase = CommonProofMerkleMaterializerPhase::FlushLeafDigests;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::FlushLeafDigests => {
                    if self.digest_write_chunk.is_empty() {
                        self.phase = CommonProofMerkleMaterializerPhase::SealLeafBytes;
                        continue;
                    }
                    executor
                        .append_object_bytes(
                            storage,
                            self.digest_level_objects[0],
                            &self.digest_write_chunk,
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.digest_write_chunk.zeroize();
                    self.phase = CommonProofMerkleMaterializerPhase::SealLeafBytes;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealLeafBytes => {
                    executor
                        .seal_object(storage, self.leaf_bytes_object)
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.phase = CommonProofMerkleMaterializerPhase::SealLeafDigests;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealLeafDigests => {
                    executor
                        .seal_object(storage, self.digest_level_objects[0])
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_level_ordinal = 1;
                    self.phase = if self.digest_level_objects.len() == 1 {
                        CommonProofMerkleMaterializerPhase::ReadRoot
                    } else {
                        CommonProofMerkleMaterializerPhase::BeginParentLevel
                    };
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::BeginParentLevel => {
                    if !self.digest_write_chunk.is_empty() {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    let object = *self
                        .digest_level_objects
                        .get(self.current_level_ordinal)
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ))?;
                    executor
                        .begin_object(storage, object)
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_parent_index = 0;
                    self.current_byte_offset = 0;
                    self.phase = CommonProofMerkleMaterializerPhase::ReadLeftChild;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::ReadLeftChild => {
                    let child_object = self.digest_level_objects[self.current_level_ordinal - 1];
                    let child_index = self.current_parent_index.checked_mul(2).ok_or(
                        CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow),
                    )?;
                    let storage_offset =
                        stored_hash_chunk_offset(child_index, self.current_byte_offset)
                            .map_err(CommonProofTreeStorageError::Prover)?;
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .read_object_bytes(
                            storage,
                            child_object,
                            storage_offset,
                            &mut self.left_child_digest[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.current_byte_offset = 0;
                        self.phase = CommonProofMerkleMaterializerPhase::ReadRightChild;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::ReadRightChild => {
                    let child_object = self.digest_level_objects[self.current_level_ordinal - 1];
                    let child_index = self
                        .current_parent_index
                        .checked_mul(2)
                        .and_then(|index| index.checked_add(1))
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    let storage_offset =
                        stored_hash_chunk_offset(child_index, self.current_byte_offset)
                            .map_err(CommonProofTreeStorageError::Prover)?;
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .read_object_bytes(
                            storage,
                            child_object,
                            storage_offset,
                            &mut self.right_child_digest[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.current_leaf_digest = self
                            .catalog_entry
                            .materialized_parent_digest(
                                u32::try_from(self.current_level_ordinal).map_err(|_| {
                                    CommonProofTreeStorageError::Prover(
                                        CommonProofProverError::CountOverflow,
                                    )
                                })?,
                                u64::try_from(self.current_parent_index).map_err(|_| {
                                    CommonProofTreeStorageError::Prover(
                                        CommonProofProverError::CountOverflow,
                                    )
                                })?,
                                self.left_child_digest,
                                self.right_child_digest,
                            )
                            .map_err(map_proof_body_tree_error)
                            .map_err(CommonProofTreeStorageError::Prover)?;
                        self.left_child_digest = [0; HASH_BYTE_LENGTH];
                        self.right_child_digest = [0; HASH_BYTE_LENGTH];
                        self.current_byte_offset = 0;
                        self.phase = CommonProofMerkleMaterializerPhase::WriteParentDigest;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::WriteParentDigest => {
                    Self::fill_write_chunk(
                        &mut self.digest_write_chunk,
                        &self.current_leaf_digest,
                        &mut self.current_byte_offset,
                        maximum_chunk_byte_length,
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    let digest_is_buffered = self.current_byte_offset == HASH_BYTE_LENGTH;
                    if self.digest_write_chunk.len() == maximum_chunk_byte_length {
                        executor
                            .append_object_bytes(
                                storage,
                                self.digest_level_objects[self.current_level_ordinal],
                                &self.digest_write_chunk,
                            )
                            .map_err(CommonProofTreeStorageError::Storage)?;
                        self.digest_write_chunk.zeroize();
                        if digest_is_buffered {
                            self.finish_current_parent_digest()
                                .map_err(CommonProofTreeStorageError::Prover)?;
                        }
                        return Ok(
                            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted,
                        );
                    }
                    if !digest_is_buffered {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.finish_current_parent_digest()
                        .map_err(CommonProofTreeStorageError::Prover)?;
                }
                CommonProofMerkleMaterializerPhase::FlushParentLevel => {
                    if self.digest_write_chunk.is_empty() {
                        self.phase = CommonProofMerkleMaterializerPhase::SealParentLevel;
                        continue;
                    }
                    executor
                        .append_object_bytes(
                            storage,
                            self.digest_level_objects[self.current_level_ordinal],
                            &self.digest_write_chunk,
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.digest_write_chunk.zeroize();
                    self.phase = CommonProofMerkleMaterializerPhase::SealParentLevel;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealParentLevel => {
                    executor
                        .seal_object(
                            storage,
                            self.digest_level_objects[self.current_level_ordinal],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_level_ordinal = self.current_level_ordinal.checked_add(1).ok_or(
                        CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow),
                    )?;
                    self.phase = if self.current_level_ordinal == self.digest_level_objects.len() {
                        self.current_byte_offset = 0;
                        CommonProofMerkleMaterializerPhase::ReadRoot
                    } else {
                        CommonProofMerkleMaterializerPhase::BeginParentLevel
                    };
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::ReadRoot => {
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .read_object_bytes(
                            storage,
                            *self.digest_level_objects.last().ok_or(
                                CommonProofTreeStorageError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ),
                            )?,
                            u64::try_from(self.current_byte_offset).map_err(|_| {
                                CommonProofTreeStorageError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                            &mut self.root[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.phase = CommonProofMerkleMaterializerPhase::Complete;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::Complete => {
                    return Ok(CommonProofMerkleMaterializerProgress::Complete);
                }
            }
        }
    }

    pub(crate) fn finish(self) -> Result<StoredCommonProofMerkleTree, CommonProofProverError> {
        if self.phase != CommonProofMerkleMaterializerPhase::Complete
            || self.next_leaf_index != self.leaf_count
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(StoredCommonProofMerkleTree {
            tree_catalog_index: self.tree_catalog_index,
            catalog_entry: self.catalog_entry,
            leaf_count: self.leaf_count,
            canonical_leaf_byte_length: self.canonical_leaf_byte_length,
            leaf_bytes_object: self.leaf_bytes_object,
            digest_level_objects: self.digest_level_objects,
            root: self.root,
        })
    }
}

fn next_bounded_offset(
    current_offset: usize,
    exact_byte_length: usize,
    maximum_chunk_byte_length: u32,
) -> Result<usize, CommonProofProverError> {
    if current_offset >= exact_byte_length || maximum_chunk_byte_length == 0 {
        return Err(CommonProofProverError::InvalidTree);
    }
    current_offset
        .checked_add(
            (exact_byte_length - current_offset).min(
                usize::try_from(maximum_chunk_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ),
        )
        .ok_or(CommonProofProverError::CountOverflow)
}

fn stored_hash_chunk_offset(
    hash_index: usize,
    within_hash_offset: usize,
) -> Result<u64, CommonProofProverError> {
    hash_index
        .checked_mul(HASH_BYTE_LENGTH)
        .and_then(|offset| offset.checked_add(within_hash_offset))
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(CommonProofProverError::CountOverflow)
}

fn append_bounded<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    object: ProofExternalMemoryObject,
    bytes: &[u8],
) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
    let maximum_chunk = usize::try_from(executor.maximum_chunk_byte_length()).map_err(|_| {
        ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        )
    })?;
    if maximum_chunk == 0 {
        return Err(ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        ));
    }
    for chunk in bytes.chunks(maximum_chunk) {
        executor.append_object_bytes(storage, object, chunk)?;
    }
    Ok(())
}

fn map_proof_body_tree_error(error: ProofBodyError) -> CommonProofProverError {
    match error {
        ProofBodyError::CanonicalEncoding => CommonProofProverError::CanonicalEncoding,
        ProofBodyError::CountOverflow => CommonProofProverError::CountOverflow,
        ProofBodyError::AllocationLimitExceeded => CommonProofProverError::AllocationLimitExceeded,
        ProofBodyError::Merkle(error) => CommonProofProverError::Merkle(error),
        ProofBodyError::Decode(_)
        | ProofBodyError::Transcript(_)
        | ProofBodyError::InvalidCatalog
        | ProofBodyError::CatalogTooLarge
        | ProofBodyError::InvalidQueryRepresentatives
        | ProofBodyError::InvalidSchema
        | ProofBodyError::InvalidSchemaVersion
        | ProofBodyError::InvalidItemCount
        | ProofBodyError::InvalidItemType
        | ProofBodyError::InvalidItemLength
        | ProofBodyError::InvalidListCount
        | ProofBodyError::InvalidTreeCatalogIndex
        | ProofBodyError::InvalidLeaf => CommonProofProverError::InvalidTree,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofOpeningPrefetchPhase {
    ReadLeaves,
    ReadFrontier,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofOpeningPrefetchProgress {
    StorageTransactionCompleted,
    Complete,
}

/// One tree's query material, prefetched through resumable IndexedDB reads.
/// This is the largest browser-side query working set: it is capped explicitly,
/// emitted immediately, and then dropped before the next catalog entry.
pub(crate) struct CommonProofOpeningPrefetcher {
    tree_catalog_index: u16,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_bytes: Zeroizing<Vec<u8>>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    phase: CommonProofOpeningPrefetchPhase,
    next_item_index: usize,
    current_byte_offset: usize,
}

impl CommonProofOpeningPrefetcher {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tree: &StoredCommonProofMerkleTree,
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
    ) -> Result<Self, CommonProofProverError> {
        let expected_leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
            .map_err(map_proof_body_tree_error)?;
        let expected_leaf_byte_length =
            canonical_leaf_byte_length(catalog_entry).map_err(map_proof_body_tree_error)?;
        let expected_digest_level_count = usize::try_from(expected_leaf_count.trailing_zeros())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if tree.tree_catalog_index != catalog_entry.tree_catalog_index()
            || &tree.catalog_entry != catalog_entry
            || tree.leaf_count != expected_leaf_count
            || tree.canonical_leaf_byte_length != expected_leaf_byte_length
            || tree.digest_level_objects.len() != expected_digest_level_count
            || maximum_prefetched_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let opened_leaf_indexes = opened_leaf_indexes(
            catalog_entry.source(),
            evaluation_domain_size,
            sorted_query_representatives,
        )?;
        let frontier_coordinates =
            minimal_frontier_coordinates(&opened_leaf_indexes, tree.leaf_count)?;
        let opened_leaf_byte_length = opened_leaf_indexes
            .len()
            .checked_mul(tree.canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let frontier_byte_length = frontier_coordinates
            .len()
            .checked_mul(HASH_BYTE_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let prefetched_byte_length = opened_leaf_byte_length
            .checked_add(frontier_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if u64::try_from(prefetched_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            > maximum_prefetched_byte_length
        {
            return Err(CommonProofProverError::AllocationLimitExceeded);
        }
        let mut opened_leaf_bytes = Vec::new();
        opened_leaf_bytes
            .try_reserve_exact(opened_leaf_byte_length)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        opened_leaf_bytes.resize(opened_leaf_byte_length, 0);
        let mut frontier_digests = Vec::new();
        frontier_digests
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        frontier_digests.resize(frontier_coordinates.len(), [0; HASH_BYTE_LENGTH]);
        Ok(Self {
            tree_catalog_index: tree.tree_catalog_index,
            leaf_count: tree.leaf_count,
            canonical_leaf_byte_length: tree.canonical_leaf_byte_length,
            leaf_bytes_object: tree.leaf_bytes_object,
            digest_level_objects: tree.digest_level_objects.clone(),
            opened_leaf_indexes,
            opened_leaf_bytes: Zeroizing::new(opened_leaf_bytes),
            frontier_coordinates,
            frontier_digests,
            phase: CommonProofOpeningPrefetchPhase::ReadLeaves,
            next_item_index: 0,
            current_byte_offset: 0,
        })
    }

    pub(crate) fn advance_storage<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<CommonProofOpeningPrefetchProgress, ProofExternalMemoryExecutorError<Storage::Error>>
    {
        match self.phase {
            CommonProofOpeningPrefetchPhase::ReadLeaves => {
                if self.next_item_index == self.opened_leaf_indexes.len() {
                    self.next_item_index = 0;
                    self.current_byte_offset = 0;
                    self.phase = if self.frontier_coordinates.is_empty() {
                        CommonProofOpeningPrefetchPhase::Complete
                    } else {
                        CommonProofOpeningPrefetchPhase::ReadFrontier
                    };
                    return self.advance_storage(executor, storage);
                }
                let leaf_index = self.opened_leaf_indexes[self.next_item_index];
                let leaf_storage_offset = usize::try_from(leaf_index)
                    .ok()
                    .and_then(|index| index.checked_mul(self.canonical_leaf_byte_length))
                    .and_then(|offset| offset.checked_add(self.current_byte_offset))
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                let end_within_leaf = next_bounded_offset(
                    self.current_byte_offset,
                    self.canonical_leaf_byte_length,
                    executor.maximum_chunk_byte_length(),
                )
                .map_err(|_| {
                    ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?;
                let destination_start = self
                    .next_item_index
                    .checked_mul(self.canonical_leaf_byte_length)
                    .and_then(|offset| offset.checked_add(self.current_byte_offset))
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                let destination_end = destination_start
                    .checked_add(end_within_leaf - self.current_byte_offset)
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                executor.read_object_bytes(
                    storage,
                    self.leaf_bytes_object,
                    leaf_storage_offset,
                    &mut self.opened_leaf_bytes[destination_start..destination_end],
                )?;
                self.current_byte_offset = end_within_leaf;
                if end_within_leaf == self.canonical_leaf_byte_length {
                    self.next_item_index += 1;
                    self.current_byte_offset = 0;
                }
                Ok(CommonProofOpeningPrefetchProgress::StorageTransactionCompleted)
            }
            CommonProofOpeningPrefetchPhase::ReadFrontier => {
                if self.next_item_index == self.frontier_coordinates.len() {
                    self.phase = CommonProofOpeningPrefetchPhase::Complete;
                    return Ok(CommonProofOpeningPrefetchProgress::Complete);
                }
                let (level, node_index) = self.frontier_coordinates[self.next_item_index];
                let object = *self
                    .digest_level_objects
                    .get(usize::try_from(level).map_err(|_| {
                        ProofExternalMemoryExecutorError::Execution(
                            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                        )
                    })?)
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::WrongOffsetOrLength,
                    ))?;
                let storage_offset = usize::try_from(node_index)
                    .ok()
                    .and_then(|index| index.checked_mul(HASH_BYTE_LENGTH))
                    .and_then(|offset| offset.checked_add(self.current_byte_offset))
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                let end = next_bounded_offset(
                    self.current_byte_offset,
                    HASH_BYTE_LENGTH,
                    executor.maximum_chunk_byte_length(),
                )
                .map_err(|_| {
                    ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?;
                executor.read_object_bytes(
                    storage,
                    object,
                    storage_offset,
                    &mut self.frontier_digests[self.next_item_index][self.current_byte_offset..end],
                )?;
                self.current_byte_offset = end;
                if end == HASH_BYTE_LENGTH {
                    self.next_item_index += 1;
                    self.current_byte_offset = 0;
                }
                Ok(CommonProofOpeningPrefetchProgress::StorageTransactionCompleted)
            }
            CommonProofOpeningPrefetchPhase::Complete => {
                Ok(CommonProofOpeningPrefetchProgress::Complete)
            }
        }
    }

    pub(crate) fn finish(
        self,
    ) -> Result<PrefetchedCommonProofOpeningArtifact, CommonProofProverError> {
        if self.phase != CommonProofOpeningPrefetchPhase::Complete {
            return Err(CommonProofProverError::InvalidOpening);
        }
        Ok(PrefetchedCommonProofOpeningArtifact {
            tree_catalog_index: self.tree_catalog_index,
            leaf_count: self.leaf_count,
            canonical_leaf_byte_length: self.canonical_leaf_byte_length,
            opened_leaf_indexes: self.opened_leaf_indexes,
            opened_leaf_bytes: self.opened_leaf_bytes,
            frontier_coordinates: self.frontier_coordinates,
            frontier_digests: self.frontier_digests,
        })
    }
}

pub(crate) struct PrefetchedCommonProofOpeningArtifact {
    tree_catalog_index: u16,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_bytes: Zeroizing<Vec<u8>>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
}

impl PrefetchedCommonProofOpeningArtifact {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub(crate) const fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }

    pub(crate) fn opened_leaf_indexes(&self) -> &[u64] {
        &self.opened_leaf_indexes
    }

    pub(crate) fn canonical_leaf_bytes_by_position(
        &self,
        position: usize,
    ) -> Result<&[u8], CommonProofProverError> {
        let start = position
            .checked_mul(self.canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let end = start
            .checked_add(self.canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.opened_leaf_bytes
            .get(start..end)
            .ok_or(CommonProofProverError::InvalidOpening)
    }

    pub(crate) fn frontier_coordinates(&self) -> &[(u32, u64)] {
        &self.frontier_coordinates
    }

    pub(crate) fn frontier_digest_by_position(
        &self,
        position: usize,
    ) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofProverError> {
        self.frontier_digests
            .get(position)
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)
    }
}
