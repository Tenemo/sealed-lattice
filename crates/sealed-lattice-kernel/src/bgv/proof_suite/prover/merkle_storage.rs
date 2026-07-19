use crate::bgv::proof_suite::merkle::{
    ProofOraclePhasePairLeafByteBuilder, ProofOraclePhasePairLeafDigestBuilder,
};

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinReplayCursor, CommonProofPrivateCoinSource, CommonProofProverError,
    HASH_BYTE_LENGTH, ProofBaseFieldElement, ProofBodyError, ProofChallengeExtensionElement,
    ProofExternalMemory, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryProtection,
    ProofLeafVisibility, ProofMerkleTreeContext, ProofOraclePhasePairLeaf, ProofTreeCatalogEntry,
    ProofTreeCatalogSource, ProofTreeRole, ProofTreeValue, RelationColumnValueType,
    ReplayableCommonProofPrivateCoinSource, StreamingHash512, Zeroize, Zeroizing,
    canonical_leaf_byte_length, entry_leaf_count, external_value_byte_length,
    minimal_frontier_coordinates, opened_leaf_indexes,
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
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, CommonProofProverError> {
        let digest_catalog_byte_length = u64::try_from(self.digest_level_objects.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(std::mem::size_of::<ProofExternalMemoryObject>()).ok()?,
                )
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        let object_plan_catalog_byte_length = u64::try_from(self.object_plans.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(std::mem::size_of::<ProofExternalMemoryObjectPlan>()).ok()?,
                )
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        digest_catalog_byte_length
            .checked_add(object_plan_catalog_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)
    }

    pub(crate) fn stored_tree_resident_owned_payload_byte_length(
        &self,
    ) -> Result<u64, CommonProofProverError> {
        u64::try_from(self.digest_level_objects.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(std::mem::size_of::<ProofExternalMemoryObject>()).ok()?,
                )
            })
            .ok_or(CommonProofProverError::CountOverflow)
    }

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
    if catalog_entry.uses_setup_polynomial_construction() || query_step < materialization_step {
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
        if catalog_entry.uses_setup_polynomial_construction() {
            return Err(CommonProofProverError::InvalidTree);
        }
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
        if catalog_entry.uses_setup_polynomial_construction() {
            return Err(CommonProofProverError::InvalidTree);
        }
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
            opened_leaf_bytes: PrefetchedCommonProofLeafBytes::Flat(self.opened_leaf_bytes),
            frontier_coordinates: self.frontier_coordinates,
            frontier_digests: self.frontier_digests,
        })
    }
}

enum PrefetchedCommonProofLeafBytes {
    Flat(Zeroizing<Vec<u8>>),
    Segmented(Vec<Zeroizing<Vec<u8>>>),
}

pub(crate) struct PrefetchedCommonProofOpeningArtifact {
    tree_catalog_index: u16,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_bytes: PrefetchedCommonProofLeafBytes,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
}

impl PrefetchedCommonProofOpeningArtifact {
    fn from_recomputed_statement_owned_tree(
        tree_catalog_index: u16,
        leaf_count: usize,
        canonical_leaf_byte_length: usize,
        opened_leaf_indexes: Vec<u64>,
        opened_leaf_bytes: Zeroizing<Vec<u8>>,
        frontier_coordinates: Vec<(u32, u64)>,
        frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    ) -> Result<Self, CommonProofProverError> {
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || canonical_leaf_byte_length == 0
            || opened_leaf_indexes.is_empty()
            || !opened_leaf_indexes.windows(2).all(|pair| pair[0] < pair[1])
            || opened_leaf_indexes.last().is_some_and(|index| {
                usize::try_from(*index).map_or(true, |index| index >= leaf_count)
            })
            || opened_leaf_bytes.len()
                != opened_leaf_indexes
                    .len()
                    .checked_mul(canonical_leaf_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || frontier_coordinates.len() != frontier_digests.len()
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        Ok(Self {
            tree_catalog_index,
            leaf_count,
            canonical_leaf_byte_length,
            opened_leaf_indexes,
            opened_leaf_bytes: PrefetchedCommonProofLeafBytes::Flat(opened_leaf_bytes),
            frontier_coordinates,
            frontier_digests,
        })
    }

    fn from_recomputed_common_tree(
        tree_catalog_index: u16,
        leaf_count: usize,
        canonical_leaf_byte_length: usize,
        opened_leaf_indexes: Vec<u64>,
        opened_leaf_bytes: Vec<Zeroizing<Vec<u8>>>,
        frontier_coordinates: Vec<(u32, u64)>,
        frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    ) -> Result<Self, CommonProofProverError> {
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || canonical_leaf_byte_length == 0
            || opened_leaf_indexes.is_empty()
            || !opened_leaf_indexes.windows(2).all(|pair| pair[0] < pair[1])
            || opened_leaf_indexes.last().is_some_and(|index| {
                usize::try_from(*index).map_or(true, |index| index >= leaf_count)
            })
            || opened_leaf_bytes.len() != opened_leaf_indexes.len()
            || opened_leaf_bytes
                .iter()
                .any(|bytes| bytes.len() != canonical_leaf_byte_length)
            || frontier_coordinates.len() != frontier_digests.len()
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        Ok(Self {
            tree_catalog_index,
            leaf_count,
            canonical_leaf_byte_length,
            opened_leaf_indexes,
            opened_leaf_bytes: PrefetchedCommonProofLeafBytes::Segmented(opened_leaf_bytes),
            frontier_coordinates,
            frontier_digests,
        })
    }

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
        match &self.opened_leaf_bytes {
            PrefetchedCommonProofLeafBytes::Flat(opened_leaf_bytes) => {
                let start = position
                    .checked_mul(self.canonical_leaf_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let end = start
                    .checked_add(self.canonical_leaf_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                opened_leaf_bytes
                    .get(start..end)
                    .ok_or(CommonProofProverError::InvalidOpening)
            }
            PrefetchedCommonProofLeafBytes::Segmented(opened_leaf_bytes) => opened_leaf_bytes
                .get(position)
                .map(AsRef::as_ref)
                .ok_or(CommonProofProverError::InvalidOpening),
        }
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

const COMMON_PROOF_COLUMN_REPLAY_CATALOG_DOMAIN: &str =
    "sealed-lattice/common-proof/column-replay-catalog/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofColumnMajorMerkleReplayMode {
    RootPass,
    OpeningPass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofColumnMajorMerkleReplayPhase {
    FirstPointValues,
    OppositePointValues,
}

/// Root-pass result retained across the Fiat-Shamir rounds. The context hash
/// binds the suite, canonical proof header, application schema, tree role,
/// tree ordinal, domain, width, and visibility. The caller-provided replay
/// binding additionally binds the proof attempt, checkpoint, private-coin
/// authority, and authenticated source identity.
#[derive(Clone, Debug)]
pub(crate) struct CommonProofColumnMajorMerkleRootPass {
    tree_catalog_index: u16,
    tree_context_hash: [u8; HASH_BYTE_LENGTH],
    ordered_column_catalog_digest: [u8; HASH_BYTE_LENGTH],
    replay_binding: [u8; HASH_BYTE_LENGTH],
    root: [u8; HASH_BYTE_LENGTH],
    source_stream_byte_length: u64,
    proof_salt_replay_span: Option<CommonProofPrivateCoinReplaySpan>,
}

impl CommonProofColumnMajorMerkleRootPass {
    pub(crate) const fn root(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.root
    }

    pub(crate) const fn source_stream_byte_length(&self) -> u64 {
        self.source_stream_byte_length
    }
}

#[derive(Clone, Debug)]
struct CommonProofPrivateCoinReplaySpan {
    start: CommonProofPrivateCoinReplayCursor,
    end: CommonProofPrivateCoinReplayCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofColumnMajorMerkleReplayMemoryAccounting {
    digest_builder_arena_byte_length: u64,
    ordered_column_catalog_byte_length: u64,
    opened_leaf_index_catalog_byte_length: u64,
    opened_leaf_builder_catalog_byte_length: u64,
    opened_leaf_byte_length: u64,
    frontier_coordinate_catalog_byte_length: u64,
    frontier_digest_byte_length: u64,
    frontier_presence_byte_length: u64,
    digest_stack_byte_length: u64,
    total_resident_owned_byte_length: u64,
    maximum_copied_buffer_byte_length: u64,
}

impl CommonProofColumnMajorMerkleReplayMemoryAccounting {
    pub(crate) const fn digest_builder_arena_byte_length(self) -> u64 {
        self.digest_builder_arena_byte_length
    }

    pub(crate) const fn opened_leaf_byte_length(self) -> u64 {
        self.opened_leaf_byte_length
    }

    pub(crate) const fn frontier_digest_byte_length(self) -> u64 {
        self.frontier_digest_byte_length
    }

    pub(crate) const fn total_resident_owned_byte_length(self) -> u64 {
        self.total_resident_owned_byte_length
    }

    pub(crate) const fn maximum_copied_buffer_byte_length(self) -> u64 {
        self.maximum_copied_buffer_byte_length
    }
}

/// Column-major common-tree materialization. The producer supplies all first
/// point columns in catalog order, switches phases once, and then replays the
/// same catalog for opposite-point columns. The root pass owns one incremental
/// leaf hash state and one digest per tree level; the opening pass additionally
/// owns only queried canonical leaves and the exact minimal frontier.
pub(crate) struct CommonProofColumnMajorMerkleReplay {
    catalog_entry: ProofTreeCatalogEntry,
    value_type: RelationColumnValueType,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    ordered_column_ordinals: Vec<u32>,
    ordered_column_catalog_digest: [u8; HASH_BYTE_LENGTH],
    replay_binding: [u8; HASH_BYTE_LENGTH],
    expected_root: Option<[u8; HASH_BYTE_LENGTH]>,
    mode: CommonProofColumnMajorMerkleReplayMode,
    phase: CommonProofColumnMajorMerkleReplayPhase,
    next_column_position: usize,
    next_leaf_index: usize,
    source_stream_byte_length: u64,
    digest_builders: Vec<ProofOraclePhasePairLeafDigestBuilder>,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_byte_builders: Vec<ProofOraclePhasePairLeafByteBuilder>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    frontier_digest_present: Vec<u8>,
    pending_left_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    proof_salt_replay_span: Option<CommonProofPrivateCoinReplaySpan>,
}

fn ordered_column_catalog_digest(
    ordered_column_ordinals: &[u32],
) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofProverError> {
    let byte_length = ordered_column_ordinals
        .len()
        .checked_mul(core::mem::size_of::<u32>())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(CommonProofProverError::CountOverflow)?;
    let mut hasher = StreamingHash512::new(COMMON_PROOF_COLUMN_REPLAY_CATALOG_DOMAIN, 1);
    hasher.begin_part(byte_length);
    for ordinal in ordered_column_ordinals {
        hasher.absorb_raw(&ordinal.to_le_bytes());
    }
    Ok(hasher.finalize())
}

impl CommonProofColumnMajorMerkleReplay {
    pub(crate) fn new_root_pass<Coins>(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
        replay_binding: [u8; HASH_BYTE_LENGTH],
        coins: &mut Coins,
    ) -> Result<Self, CommonProofTreeStorageError<core::convert::Infallible, Coins::Error>>
    where
        Coins: ReplayableCommonProofPrivateCoinSource,
    {
        Self::new(
            catalog_entry,
            evaluation_domain_size,
            ordered_column_ordinals,
            replay_binding,
            None,
            &[],
            u64::MAX,
            CommonProofColumnMajorMerkleReplayMode::RootPass,
            coins,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_opening_pass<Coins>(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
        replay_binding: [u8; HASH_BYTE_LENGTH],
        root_pass: &CommonProofColumnMajorMerkleRootPass,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
        coins: &mut Coins,
    ) -> Result<Self, CommonProofTreeStorageError<core::convert::Infallible, Coins::Error>>
    where
        Coins: ReplayableCommonProofPrivateCoinSource,
    {
        Self::new(
            catalog_entry,
            evaluation_domain_size,
            ordered_column_ordinals,
            replay_binding,
            Some(root_pass),
            sorted_query_representatives,
            maximum_prefetched_byte_length,
            CommonProofColumnMajorMerkleReplayMode::OpeningPass,
            coins,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new<Coins>(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
        replay_binding: [u8; HASH_BYTE_LENGTH],
        root_pass: Option<&CommonProofColumnMajorMerkleRootPass>,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
        mode: CommonProofColumnMajorMerkleReplayMode,
        coins: &mut Coins,
    ) -> Result<Self, CommonProofTreeStorageError<core::convert::Infallible, Coins::Error>>
    where
        Coins: ReplayableCommonProofPrivateCoinSource,
    {
        let context = catalog_entry
            .common_context()
            .ok_or(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ))?;
        let leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
            .map_err(map_proof_body_tree_error)
            .map_err(CommonProofTreeStorageError::Prover)?;
        let row_width = catalog_entry
            .materialized_row_width()
            .map_err(map_proof_body_tree_error)
            .map_err(CommonProofTreeStorageError::Prover)?;
        let value_type = common_proof_tree_value_type(catalog_entry)
            .map_err(CommonProofTreeStorageError::Prover)?;
        let canonical_leaf_byte_length = canonical_leaf_byte_length(catalog_entry)
            .map_err(map_proof_body_tree_error)
            .map_err(CommonProofTreeStorageError::Prover)?;
        let tree_context_hash = context
            .context_hash()
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofTreeStorageError::Prover)?;
        let ordered_column_catalog_digest = ordered_column_catalog_digest(ordered_column_ordinals)
            .map_err(CommonProofTreeStorageError::Prover)?;
        if catalog_entry.bound_root().is_some()
            || leaf_count == 0
            || !leaf_count.is_power_of_two()
            || row_width == 0
            || row_width != ordered_column_ordinals.len()
            || leaf_count.trailing_zeros() >= u64::BITS
        {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }

        let expected_root = match (mode, root_pass) {
            (CommonProofColumnMajorMerkleReplayMode::RootPass, None) => None,
            (CommonProofColumnMajorMerkleReplayMode::OpeningPass, Some(root_pass))
                if root_pass.tree_catalog_index == catalog_entry.tree_catalog_index()
                    && root_pass.tree_context_hash == tree_context_hash
                    && root_pass.ordered_column_catalog_digest == ordered_column_catalog_digest
                    && root_pass.replay_binding == replay_binding =>
            {
                Some(root_pass.root)
            }
            _ => {
                return Err(CommonProofTreeStorageError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
        };
        let opened_leaf_indexes = match mode {
            CommonProofColumnMajorMerkleReplayMode::RootPass => Vec::new(),
            CommonProofColumnMajorMerkleReplayMode::OpeningPass => opened_leaf_indexes(
                catalog_entry.source(),
                evaluation_domain_size,
                sorted_query_representatives,
            )
            .map_err(CommonProofTreeStorageError::Prover)?,
        };
        let frontier_coordinates = if opened_leaf_indexes.is_empty() {
            Vec::new()
        } else {
            setup_polynomial_frontier_coordinates(&opened_leaf_indexes, leaf_count)
                .map_err(CommonProofTreeStorageError::Prover)?
        };
        let opened_leaf_payload_byte_length = opened_leaf_indexes
            .len()
            .checked_mul(canonical_leaf_byte_length)
            .ok_or(CommonProofTreeStorageError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let frontier_payload_byte_length = frontier_coordinates
            .len()
            .checked_mul(HASH_BYTE_LENGTH)
            .ok_or(CommonProofTreeStorageError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let prefetched_payload_byte_length = opened_leaf_payload_byte_length
            .checked_add(frontier_payload_byte_length)
            .ok_or(CommonProofTreeStorageError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        if matches!(mode, CommonProofColumnMajorMerkleReplayMode::OpeningPass)
            && (opened_leaf_indexes.is_empty()
                || maximum_prefetched_byte_length == 0
                || u64::try_from(prefetched_payload_byte_length).map_err(|_| {
                    CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
                })? > maximum_prefetched_byte_length)
        {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::AllocationLimitExceeded,
            ));
        }

        let expected_proof_salt_replay_span =
            root_pass.and_then(|root_pass| root_pass.proof_salt_replay_span.as_ref());
        let proof_salt_replay_start = if context.leaf_visibility()
            == ProofLeafVisibility::SecretBearing
        {
            match mode {
                CommonProofColumnMajorMerkleReplayMode::RootPass => Some(
                    coins
                        .capture_proof_salt_replay_cursor()
                        .map_err(CommonProofTreeStorageError::CoinSource)?,
                ),
                CommonProofColumnMajorMerkleReplayMode::OpeningPass => {
                    let expected_span = expected_proof_salt_replay_span.ok_or(
                        CommonProofTreeStorageError::Prover(CommonProofProverError::InvalidTree),
                    )?;
                    coins
                        .restore_proof_salt_replay_cursor(&expected_span.start)
                        .map_err(CommonProofTreeStorageError::CoinSource)?;
                    Some(expected_span.start.clone())
                }
            }
        } else {
            if expected_proof_salt_replay_span.is_some() {
                return Err(CommonProofTreeStorageError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
            None
        };

        let value_example = match value_type {
            RelationColumnValueType::BaseField => ProofTreeValue::Base(ProofBaseFieldElement::ZERO),
            RelationColumnValueType::ChallengeExtension => {
                ProofTreeValue::Extension(ProofChallengeExtensionElement::ZERO)
            }
        };
        let mut digest_builders = Vec::new();
        digest_builders.try_reserve_exact(leaf_count).map_err(|_| {
            CommonProofTreeStorageError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
        let mut opened_leaf_byte_builders = Vec::new();
        opened_leaf_byte_builders
            .try_reserve_exact(opened_leaf_indexes.len())
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::AllocationLimitExceeded)
            })?;
        let mut next_opened_leaf_position = 0_usize;
        for leaf_index in 0..leaf_count {
            let secret_salt = if context.leaf_visibility() == ProofLeafVisibility::SecretBearing {
                let mut salt = [0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
                coins
                    .fill_raw_bytes(CommonProofPrivateCoinCoordinate::proof_salt(), &mut salt)
                    .map_err(CommonProofTreeStorageError::CoinSource)?;
                Some(salt)
            } else {
                None
            };
            let leaf_index_u64 = u64::try_from(leaf_index).map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
            })?;
            digest_builders.push(
                ProofOraclePhasePairLeafDigestBuilder::new_from_context(
                    context,
                    leaf_index_u64,
                    secret_salt,
                    value_example,
                    row_width,
                )
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofTreeStorageError::Prover)?,
            );
            if opened_leaf_indexes.get(next_opened_leaf_position).copied() == Some(leaf_index_u64) {
                opened_leaf_byte_builders.push(
                    ProofOraclePhasePairLeafByteBuilder::new_from_context(
                        context,
                        leaf_index_u64,
                        secret_salt,
                        value_example,
                        row_width,
                    )
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofTreeStorageError::Prover)?,
                );
                next_opened_leaf_position = next_opened_leaf_position.checked_add(1).ok_or(
                    CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow),
                )?;
            }
        }
        if next_opened_leaf_position != opened_leaf_indexes.len() {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidOpening,
            ));
        }
        let proof_salt_replay_span = if let Some(start) = proof_salt_replay_start {
            let end = coins
                .capture_proof_salt_replay_cursor()
                .map_err(CommonProofTreeStorageError::CoinSource)?;
            if let Some(expected_span) = expected_proof_salt_replay_span {
                if !coins
                    .proof_salt_replay_cursor_matches(&expected_span.end)
                    .map_err(CommonProofTreeStorageError::CoinSource)?
                {
                    return Err(CommonProofTreeStorageError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                Some(expected_span.clone())
            } else {
                Some(CommonProofPrivateCoinReplaySpan { start, end })
            }
        } else {
            None
        };

        let mut frontier_digests = Vec::new();
        frontier_digests
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::AllocationLimitExceeded)
            })?;
        frontier_digests.resize(frontier_coordinates.len(), [0; HASH_BYTE_LENGTH]);
        let mut frontier_digest_present = Vec::new();
        frontier_digest_present
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::AllocationLimitExceeded)
            })?;
        frontier_digest_present.resize(frontier_coordinates.len(), 0);
        let tree_height = usize::try_from(leaf_count.trailing_zeros()).map_err(|_| {
            CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let mut pending_left_digests = Vec::new();
        pending_left_digests
            .try_reserve_exact(tree_height)
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::AllocationLimitExceeded)
            })?;
        pending_left_digests.resize(tree_height, [0; HASH_BYTE_LENGTH]);

        let mut retained_ordered_column_ordinals = Vec::new();
        retained_ordered_column_ordinals
            .try_reserve_exact(ordered_column_ordinals.len())
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::AllocationLimitExceeded)
            })?;
        retained_ordered_column_ordinals.extend_from_slice(ordered_column_ordinals);

        Ok(Self {
            catalog_entry: catalog_entry.clone(),
            value_type,
            leaf_count,
            canonical_leaf_byte_length,
            ordered_column_ordinals: retained_ordered_column_ordinals,
            ordered_column_catalog_digest,
            replay_binding,
            expected_root,
            mode,
            phase: CommonProofColumnMajorMerkleReplayPhase::FirstPointValues,
            next_column_position: 0,
            next_leaf_index: 0,
            source_stream_byte_length: 0,
            digest_builders,
            opened_leaf_indexes,
            opened_leaf_byte_builders,
            frontier_coordinates,
            frontier_digests,
            frontier_digest_present,
            pending_left_digests,
            proof_salt_replay_span,
        })
    }

    pub(crate) const fn mode(&self) -> CommonProofColumnMajorMerkleReplayMode {
        self.mode
    }

    pub(crate) fn next_column_ordinal(&self) -> Option<u32> {
        self.ordered_column_ordinals
            .get(self.next_column_position)
            .copied()
    }

    pub(crate) const fn next_leaf_index(&self) -> usize {
        self.next_leaf_index
    }

    pub(crate) fn supply_next_column_chunk(
        &mut self,
        column_ordinal: u32,
        first_leaf_index: usize,
        values: &[ProofTreeValue],
    ) -> Result<(), CommonProofProverError> {
        let expected_column_ordinal = self
            .next_column_ordinal()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let end_leaf_index = first_leaf_index
            .checked_add(values.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if column_ordinal != expected_column_ordinal
            || values.is_empty()
            || first_leaf_index != self.next_leaf_index
            || end_leaf_index > self.leaf_count
            || values
                .iter()
                .any(|value| !common_proof_tree_value_has_type(value, self.value_type))
        {
            return Err(CommonProofProverError::InvalidColumn);
        }

        let digest_builders = self
            .digest_builders
            .get_mut(first_leaf_index..end_leaf_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        match self.phase {
            CommonProofColumnMajorMerkleReplayPhase::FirstPointValues => {
                for (builder, value) in digest_builders.iter_mut().zip(values.iter().copied()) {
                    builder.absorb_first_value(value)?;
                }
            }
            CommonProofColumnMajorMerkleReplayPhase::OppositePointValues => {
                for (builder, value) in digest_builders.iter_mut().zip(values.iter().copied()) {
                    builder.absorb_opposite_value(value)?;
                }
            }
        }

        let first_leaf_index_u64 =
            u64::try_from(first_leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        let end_leaf_index_u64 =
            u64::try_from(end_leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut opened_position = self
            .opened_leaf_indexes
            .partition_point(|index| *index < first_leaf_index_u64);
        while let Some(opened_leaf_index) = self.opened_leaf_indexes.get(opened_position).copied() {
            if opened_leaf_index >= end_leaf_index_u64 {
                break;
            }
            let value_position = usize::try_from(opened_leaf_index - first_leaf_index_u64)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
            let value = *values
                .get(value_position)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let builder = self
                .opened_leaf_byte_builders
                .get_mut(opened_position)
                .ok_or(CommonProofProverError::InvalidOpening)?;
            match self.phase {
                CommonProofColumnMajorMerkleReplayPhase::FirstPointValues => {
                    builder.absorb_first_value(value)?;
                }
                CommonProofColumnMajorMerkleReplayPhase::OppositePointValues => {
                    builder.absorb_opposite_value(value)?;
                }
            }
            opened_position = opened_position
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }

        let value_byte_length = external_value_byte_length(self.value_type);
        self.source_stream_byte_length = self
            .source_stream_byte_length
            .checked_add(
                u64::try_from(values.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .checked_mul(value_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.next_leaf_index = end_leaf_index;
        if self.next_leaf_index == self.leaf_count {
            self.next_leaf_index = 0;
            self.next_column_position = self
                .next_column_position
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
        Ok(())
    }

    pub(crate) fn begin_opposite_point_values(&mut self) -> Result<(), CommonProofProverError> {
        if self.phase != CommonProofColumnMajorMerkleReplayPhase::FirstPointValues
            || self.next_column_position != self.ordered_column_ordinals.len()
            || self.next_leaf_index != 0
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        for builder in &mut self.digest_builders {
            builder.begin_opposite_values()?;
        }
        for builder in &mut self.opened_leaf_byte_builders {
            builder.begin_opposite_values()?;
        }
        self.phase = CommonProofColumnMajorMerkleReplayPhase::OppositePointValues;
        self.next_column_position = 0;
        Ok(())
    }

    pub(crate) fn memory_accounting(
        &self,
    ) -> Result<CommonProofColumnMajorMerkleReplayMemoryAccounting, CommonProofProverError> {
        let vector_payload_byte_length = |capacity: usize, element_byte_length: usize| {
            u64::try_from(capacity)
                .ok()
                .and_then(|capacity| {
                    u64::try_from(element_byte_length)
                        .ok()
                        .and_then(|element_byte_length| capacity.checked_mul(element_byte_length))
                })
                .ok_or(CommonProofProverError::CountOverflow)
        };
        let digest_builder_arena_byte_length = vector_payload_byte_length(
            self.digest_builders.capacity(),
            core::mem::size_of::<ProofOraclePhasePairLeafDigestBuilder>(),
        )?;
        let ordered_column_catalog_byte_length = vector_payload_byte_length(
            self.ordered_column_ordinals.capacity(),
            core::mem::size_of::<u32>(),
        )?;
        let opened_leaf_index_catalog_byte_length = vector_payload_byte_length(
            self.opened_leaf_indexes.capacity(),
            core::mem::size_of::<u64>(),
        )?;
        let opened_leaf_builder_catalog_byte_length = vector_payload_byte_length(
            self.opened_leaf_byte_builders.capacity(),
            core::mem::size_of::<ProofOraclePhasePairLeafByteBuilder>(),
        )?;
        let opened_leaf_byte_length =
            self.opened_leaf_byte_builders
                .iter()
                .try_fold(0_u64, |total, builder| {
                    total
                        .checked_add(
                            builder
                                .resident_owned_payload_byte_length()
                                .map_err(CommonProofProverError::from)?,
                        )
                        .ok_or(CommonProofProverError::CountOverflow)
                })?;
        let frontier_coordinate_catalog_byte_length = vector_payload_byte_length(
            self.frontier_coordinates.capacity(),
            core::mem::size_of::<(u32, u64)>(),
        )?;
        let frontier_digest_byte_length = vector_payload_byte_length(
            self.frontier_digests.capacity(),
            core::mem::size_of::<[u8; HASH_BYTE_LENGTH]>(),
        )?;
        let frontier_presence_byte_length = u64::try_from(self.frontier_digest_present.capacity())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let digest_stack_byte_length = vector_payload_byte_length(
            self.pending_left_digests.capacity(),
            core::mem::size_of::<[u8; HASH_BYTE_LENGTH]>(),
        )?;
        let total_resident_owned_byte_length = [
            digest_builder_arena_byte_length,
            ordered_column_catalog_byte_length,
            opened_leaf_index_catalog_byte_length,
            opened_leaf_builder_catalog_byte_length,
            opened_leaf_byte_length,
            frontier_coordinate_catalog_byte_length,
            frontier_digest_byte_length,
            frontier_presence_byte_length,
            digest_stack_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, |total, length| {
            total
                .checked_add(length)
                .ok_or(CommonProofProverError::CountOverflow)
        })?;
        Ok(CommonProofColumnMajorMerkleReplayMemoryAccounting {
            digest_builder_arena_byte_length,
            ordered_column_catalog_byte_length,
            opened_leaf_index_catalog_byte_length,
            opened_leaf_builder_catalog_byte_length,
            opened_leaf_byte_length,
            frontier_coordinate_catalog_byte_length,
            frontier_digest_byte_length,
            frontier_presence_byte_length,
            digest_stack_byte_length,
            total_resident_owned_byte_length,
            maximum_copied_buffer_byte_length: 0,
        })
    }

    fn capture_frontier_digest(
        &mut self,
        level: u32,
        node_index: u64,
        digest: [u8; HASH_BYTE_LENGTH],
    ) -> Result<(), CommonProofProverError> {
        let Ok(position) = self
            .frontier_coordinates
            .binary_search(&(level, node_index))
        else {
            return Ok(());
        };
        if self.frontier_digest_present[position] != 0 {
            return Err(CommonProofProverError::InvalidOpening);
        }
        self.frontier_digests[position] = digest;
        self.frontier_digest_present[position] = 1;
        Ok(())
    }

    fn finish_replay(
        mut self,
    ) -> Result<
        (
            [u8; HASH_BYTE_LENGTH],
            Vec<Zeroizing<Vec<u8>>>,
            Vec<u64>,
            Vec<(u32, u64)>,
            Vec<[u8; HASH_BYTE_LENGTH]>,
        ),
        CommonProofProverError,
    > {
        if self.phase != CommonProofColumnMajorMerkleReplayPhase::OppositePointValues
            || self.next_column_position != self.ordered_column_ordinals.len()
            || self.next_leaf_index != 0
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let expected_source_stream_byte_length = u64::try_from(self.leaf_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(
                u64::try_from(self.ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .and_then(|length| length.checked_mul(2))
            .and_then(|length| length.checked_mul(external_value_byte_length(self.value_type)))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.source_stream_byte_length != expected_source_stream_byte_length {
            return Err(CommonProofProverError::InvalidTree);
        }

        let digest_builders = core::mem::take(&mut self.digest_builders);
        let mut occupied_level_mask = 0_u64;
        let mut recomputed_root = None;
        for (leaf_index, builder) in digest_builders.into_iter().enumerate() {
            let leaf_index =
                u64::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
            let mut current_digest = builder.finish()?;
            let mut current_node_index = leaf_index;
            self.capture_frontier_digest(0, current_node_index, current_digest)?;
            let mut level = 0_usize;
            while level < self.pending_left_digests.len()
                && occupied_level_mask & (1_u64 << level) != 0
            {
                current_digest = self
                    .catalog_entry
                    .materialized_parent_digest(
                        u32::try_from(level + 1)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        current_node_index / 2,
                        self.pending_left_digests[level],
                        current_digest,
                    )
                    .map_err(map_proof_body_tree_error)?;
                occupied_level_mask &= !(1_u64 << level);
                current_node_index /= 2;
                level += 1;
                self.capture_frontier_digest(
                    u32::try_from(level).map_err(|_| CommonProofProverError::CountOverflow)?,
                    current_node_index,
                    current_digest,
                )?;
            }
            if level == self.pending_left_digests.len() {
                if leaf_index
                    != u64::try_from(self.leaf_count - 1)
                        .map_err(|_| CommonProofProverError::CountOverflow)?
                    || occupied_level_mask != 0
                    || recomputed_root.is_some()
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                recomputed_root = Some(current_digest);
            } else {
                self.pending_left_digests[level] = current_digest;
                occupied_level_mask |= 1_u64 << level;
            }
        }
        let root = recomputed_root.ok_or(CommonProofProverError::InvalidTree)?;
        if self
            .frontier_digest_present
            .iter()
            .any(|present| *present != 1)
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let opened_leaf_bytes = core::mem::take(&mut self.opened_leaf_byte_builders)
            .into_iter()
            .map(ProofOraclePhasePairLeafByteBuilder::finish)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            root,
            opened_leaf_bytes,
            self.opened_leaf_indexes,
            self.frontier_coordinates,
            self.frontier_digests,
        ))
    }

    pub(crate) fn finish_root_pass(
        self,
    ) -> Result<CommonProofColumnMajorMerkleRootPass, CommonProofProverError> {
        if self.mode != CommonProofColumnMajorMerkleReplayMode::RootPass
            || self.expected_root.is_some()
            || !self.opened_leaf_indexes.is_empty()
            || !self.frontier_coordinates.is_empty()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let tree_catalog_index = self.catalog_entry.tree_catalog_index();
        let tree_context_hash = self
            .catalog_entry
            .common_context()
            .ok_or(CommonProofProverError::InvalidTree)?
            .context_hash()?;
        let ordered_column_catalog_digest = self.ordered_column_catalog_digest;
        let replay_binding = self.replay_binding;
        let source_stream_byte_length = self.source_stream_byte_length;
        let proof_salt_replay_span = self.proof_salt_replay_span.clone();
        let (root, opened_leaf_bytes, opened_leaf_indexes, frontier_coordinates, frontier_digests) =
            self.finish_replay()?;
        if !opened_leaf_bytes.is_empty()
            || !opened_leaf_indexes.is_empty()
            || !frontier_coordinates.is_empty()
            || !frontier_digests.is_empty()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(CommonProofColumnMajorMerkleRootPass {
            tree_catalog_index,
            tree_context_hash,
            ordered_column_catalog_digest,
            replay_binding,
            root,
            source_stream_byte_length,
            proof_salt_replay_span,
        })
    }

    pub(crate) fn finish_opening_pass(
        self,
        root_pass: &CommonProofColumnMajorMerkleRootPass,
    ) -> Result<PrefetchedCommonProofOpeningArtifact, CommonProofProverError> {
        if self.mode != CommonProofColumnMajorMerkleReplayMode::OpeningPass
            || self.expected_root != Some(root_pass.root)
            || self.catalog_entry.tree_catalog_index() != root_pass.tree_catalog_index
            || self
                .catalog_entry
                .common_context()
                .ok_or(CommonProofProverError::InvalidTree)?
                .context_hash()?
                != root_pass.tree_context_hash
            || self.ordered_column_catalog_digest != root_pass.ordered_column_catalog_digest
            || self.replay_binding != root_pass.replay_binding
            || self.source_stream_byte_length != root_pass.source_stream_byte_length
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let tree_catalog_index = self.catalog_entry.tree_catalog_index();
        let leaf_count = self.leaf_count;
        let canonical_leaf_byte_length = self.canonical_leaf_byte_length;
        let expected_frontier_coordinates = self.frontier_coordinates.clone();
        let (root, opened_leaf_bytes, opened_leaf_indexes, frontier_coordinates, frontier_digests) =
            self.finish_replay()?;
        if root != root_pass.root
            || frontier_coordinates != expected_frontier_coordinates
            || frontier_digests.len() != frontier_coordinates.len()
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        PrefetchedCommonProofOpeningArtifact::from_recomputed_common_tree(
            tree_catalog_index,
            leaf_count,
            canonical_leaf_byte_length,
            opened_leaf_indexes,
            opened_leaf_bytes,
            frontier_coordinates,
            frontier_digests,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatementOwnedMerkleReplayMode {
    RootPass,
    OpeningPass,
}

/// Deterministic statement-owned Merkle replay used by the common prover.
///
/// The root pass retains only one digest per tree level. After the transcript
/// fixes the query representatives, the opening pass replays the same leaf
/// stream and retains only the queried canonical leaves and their canonical
/// minimal authentication frontier. No complete leaf or Merkle level is ever
/// materialized. Setup-polynomial leaves are public and unsalted; committed-
/// material leaves consume their provider-authenticated persistent salts.
pub(crate) struct StatementOwnedMerkleReplay {
    catalog_entry: ProofTreeCatalogEntry,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    expected_root: [u8; HASH_BYTE_LENGTH],
    mode: StatementOwnedMerkleReplayMode,
    opened_leaf_indexes: Vec<u64>,
    next_opened_leaf_position: usize,
    opened_leaf_bytes: Zeroizing<Vec<u8>>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    frontier_digest_present: Vec<u8>,
    pending_left_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    occupied_level_mask: u64,
    absorbed_leaf_count: u64,
    recomputed_root: Option<[u8; HASH_BYTE_LENGTH]>,
}

fn scan_setup_polynomial_frontier_coordinates(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
    mut output: Option<&mut [(u32, u64)]>,
) -> Result<usize, CommonProofProverError> {
    let leaf_count_u64 =
        u64::try_from(leaf_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || sorted_unique_leaf_indexes.is_empty()
        || !sorted_unique_leaf_indexes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_unique_leaf_indexes
            .last()
            .is_some_and(|index| *index >= leaf_count_u64)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let expected_output_length = output.as_ref().map(|coordinates| coordinates.len());
    let mut coordinate_count = 0_usize;
    for level in 0..leaf_count.trailing_zeros() {
        let mut leaf_position = 0_usize;
        while leaf_position < sorted_unique_leaf_indexes.len() {
            let node_index = sorted_unique_leaf_indexes[leaf_position] >> level;
            leaf_position += 1;
            while leaf_position < sorted_unique_leaf_indexes.len()
                && sorted_unique_leaf_indexes[leaf_position] >> level == node_index
            {
                leaf_position += 1;
            }
            if node_index & 1 == 0
                && leaf_position < sorted_unique_leaf_indexes.len()
                && sorted_unique_leaf_indexes[leaf_position] >> level == node_index + 1
            {
                let sibling_index = node_index + 1;
                leaf_position += 1;
                while leaf_position < sorted_unique_leaf_indexes.len()
                    && sorted_unique_leaf_indexes[leaf_position] >> level == sibling_index
                {
                    leaf_position += 1;
                }
                continue;
            }
            if let Some(coordinates) = output.as_deref_mut() {
                *coordinates
                    .get_mut(coordinate_count)
                    .ok_or(CommonProofProverError::InvalidOpening)? = (level, node_index ^ 1);
            }
            coordinate_count = coordinate_count
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
    }
    if expected_output_length.is_some_and(|length| length != coordinate_count) {
        return Err(CommonProofProverError::InvalidOpening);
    }
    Ok(coordinate_count)
}

/// Derives the canonical minimal frontier with scalar counters only. The first
/// scan obtains the exact output length; the second fills that sole allocation.
fn setup_polynomial_frontier_coordinates(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<Vec<(u32, u64)>, CommonProofProverError> {
    let coordinate_count =
        scan_setup_polynomial_frontier_coordinates(sorted_unique_leaf_indexes, leaf_count, None)?;
    let mut coordinates = Vec::new();
    coordinates
        .try_reserve_exact(coordinate_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    coordinates.resize(coordinate_count, (0, 0));
    scan_setup_polynomial_frontier_coordinates(
        sorted_unique_leaf_indexes,
        leaf_count,
        Some(coordinates.as_mut_slice()),
    )?;
    coordinates.shrink_to_fit();
    Ok(coordinates)
}

impl StatementOwnedMerkleReplay {
    pub(crate) fn new_root_pass(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            catalog_entry,
            evaluation_domain_size,
            &[],
            u64::MAX,
            StatementOwnedMerkleReplayMode::RootPass,
        )
    }

    pub(crate) fn new_opening_pass(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            catalog_entry,
            evaluation_domain_size,
            sorted_query_representatives,
            maximum_prefetched_byte_length,
            StatementOwnedMerkleReplayMode::OpeningPass,
        )
    }

    fn new(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
        mode: StatementOwnedMerkleReplayMode,
    ) -> Result<Self, CommonProofProverError> {
        if catalog_entry.bound_root().is_none() || catalog_entry.uses_common_merkle_context() {
            return Err(CommonProofProverError::InvalidTree);
        }
        let leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
            .map_err(map_proof_body_tree_error)?;
        let canonical_leaf_byte_length =
            canonical_leaf_byte_length(catalog_entry).map_err(map_proof_body_tree_error)?;
        let expected_root = catalog_entry
            .bound_root()
            .ok_or(CommonProofProverError::InvalidTree)?;
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || leaf_count.trailing_zeros() >= u64::BITS
            || canonical_leaf_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidTree);
        }

        let opened_leaf_indexes = match mode {
            StatementOwnedMerkleReplayMode::RootPass => Vec::new(),
            StatementOwnedMerkleReplayMode::OpeningPass => opened_leaf_indexes(
                catalog_entry.source(),
                evaluation_domain_size,
                sorted_query_representatives,
            )?,
        };
        let frontier_coordinates = if opened_leaf_indexes.is_empty() {
            Vec::new()
        } else {
            setup_polynomial_frontier_coordinates(&opened_leaf_indexes, leaf_count)?
        };
        let opened_leaf_payload_byte_length = opened_leaf_indexes
            .len()
            .checked_mul(canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let frontier_payload_byte_length = frontier_coordinates
            .len()
            .checked_mul(HASH_BYTE_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let prefetched_payload_byte_length = opened_leaf_payload_byte_length
            .checked_add(frontier_payload_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if matches!(mode, StatementOwnedMerkleReplayMode::OpeningPass)
            && (opened_leaf_indexes.is_empty()
                || maximum_prefetched_byte_length == 0
                || u64::try_from(prefetched_payload_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    > maximum_prefetched_byte_length)
        {
            return Err(CommonProofProverError::AllocationLimitExceeded);
        }

        let mut opened_leaf_bytes = Vec::new();
        opened_leaf_bytes
            .try_reserve_exact(opened_leaf_payload_byte_length)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let mut frontier_digests = Vec::new();
        frontier_digests
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        frontier_digests.resize(frontier_coordinates.len(), [0; HASH_BYTE_LENGTH]);
        let mut frontier_digest_present = Vec::new();
        frontier_digest_present
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        frontier_digest_present.resize(frontier_coordinates.len(), 0);
        let tree_height = usize::try_from(leaf_count.trailing_zeros())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut pending_left_digests = Vec::new();
        pending_left_digests
            .try_reserve_exact(tree_height)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        pending_left_digests.resize(tree_height, [0; HASH_BYTE_LENGTH]);

        Ok(Self {
            catalog_entry: catalog_entry.clone(),
            leaf_count,
            canonical_leaf_byte_length,
            expected_root,
            mode,
            opened_leaf_indexes,
            next_opened_leaf_position: 0,
            opened_leaf_bytes: Zeroizing::new(opened_leaf_bytes),
            frontier_coordinates,
            frontier_digests,
            frontier_digest_present,
            pending_left_digests,
            occupied_level_mask: 0,
            absorbed_leaf_count: 0,
            recomputed_root: None,
        })
    }

    pub(crate) const fn mode(&self) -> StatementOwnedMerkleReplayMode {
        self.mode
    }

    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.catalog_entry.tree_catalog_index()
    }

    pub(crate) const fn requires_persistent_leaf_salt(&self) -> bool {
        self.catalog_entry.requires_persistent_leaf_salt()
    }

    pub(crate) fn next_leaf_index(&self) -> Option<u64> {
        (self.absorbed_leaf_count
            < u64::try_from(self.leaf_count).expect("validated leaf count fits u64"))
        .then_some(self.absorbed_leaf_count)
    }

    #[cfg(test)]
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, CommonProofProverError> {
        let vector_payload = |capacity: usize, element_byte_length: usize| {
            u64::try_from(capacity)
                .ok()
                .and_then(|capacity| {
                    u64::try_from(element_byte_length)
                        .ok()
                        .and_then(|element_byte_length| capacity.checked_mul(element_byte_length))
                })
                .ok_or(CommonProofProverError::CountOverflow)
        };
        [
            vector_payload(
                self.opened_leaf_indexes.capacity(),
                core::mem::size_of::<u64>(),
            )?,
            u64::try_from(self.opened_leaf_bytes.capacity())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            vector_payload(
                self.frontier_coordinates.capacity(),
                core::mem::size_of::<(u32, u64)>(),
            )?,
            vector_payload(
                self.frontier_digests.capacity(),
                core::mem::size_of::<[u8; HASH_BYTE_LENGTH]>(),
            )?,
            u64::try_from(self.frontier_digest_present.capacity())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            vector_payload(
                self.pending_left_digests.capacity(),
                core::mem::size_of::<[u8; HASH_BYTE_LENGTH]>(),
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, |total, length| {
            total
                .checked_add(length)
                .ok_or(CommonProofProverError::CountOverflow)
        })
    }

    pub(crate) fn supply_next_leaf(
        &mut self,
        first_point_values: Zeroizing<Vec<ProofTreeValue>>,
        opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
    ) -> Result<(), CommonProofProverError> {
        self.supply_next_leaf_with_persistent_salt(None, first_point_values, opposite_point_values)
    }

    pub(crate) fn supply_next_leaf_with_persistent_salt(
        &mut self,
        persistent_leaf_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Zeroizing<Vec<ProofTreeValue>>,
        opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
    ) -> Result<(), CommonProofProverError> {
        let leaf_index = self
            .next_leaf_index()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let (canonical_leaf_bytes, leaf_digest) = self
            .catalog_entry
            .encode_materialized_leaf(
                leaf_index,
                persistent_leaf_salt,
                first_point_values,
                opposite_point_values,
            )
            .map_err(map_proof_body_tree_error)?;
        if canonical_leaf_bytes.len() != self.canonical_leaf_byte_length {
            return Err(CommonProofProverError::InvalidTree);
        }
        if self
            .opened_leaf_indexes
            .get(self.next_opened_leaf_position)
            .copied()
            == Some(leaf_index)
        {
            self.opened_leaf_bytes
                .extend_from_slice(&canonical_leaf_bytes);
            self.next_opened_leaf_position = self
                .next_opened_leaf_position
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
        self.capture_frontier_digest(0, leaf_index, leaf_digest)?;

        let mut current_digest = leaf_digest;
        let mut current_node_index = leaf_index;
        let mut level = 0_usize;
        while level < self.pending_left_digests.len()
            && self.occupied_level_mask & (1_u64 << level) != 0
        {
            current_digest = self
                .catalog_entry
                .materialized_parent_digest(
                    u32::try_from(level + 1).map_err(|_| CommonProofProverError::CountOverflow)?,
                    current_node_index / 2,
                    self.pending_left_digests[level],
                    current_digest,
                )
                .map_err(map_proof_body_tree_error)?;
            self.occupied_level_mask &= !(1_u64 << level);
            current_node_index /= 2;
            level += 1;
            self.capture_frontier_digest(
                u32::try_from(level).map_err(|_| CommonProofProverError::CountOverflow)?,
                current_node_index,
                current_digest,
            )?;
        }
        self.absorbed_leaf_count = self
            .absorbed_leaf_count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if level == self.pending_left_digests.len() {
            if self.absorbed_leaf_count
                != u64::try_from(self.leaf_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                || self.occupied_level_mask != 0
            {
                return Err(CommonProofProverError::InvalidTree);
            }
            self.recomputed_root = Some(current_digest);
        } else {
            self.pending_left_digests[level] = current_digest;
            self.occupied_level_mask |= 1_u64 << level;
        }
        Ok(())
    }

    fn capture_frontier_digest(
        &mut self,
        level: u32,
        node_index: u64,
        digest: [u8; HASH_BYTE_LENGTH],
    ) -> Result<(), CommonProofProverError> {
        let Ok(position) = self
            .frontier_coordinates
            .binary_search(&(level, node_index))
        else {
            return Ok(());
        };
        if self.frontier_digest_present[position] != 0 {
            return Err(CommonProofProverError::InvalidOpening);
        }
        self.frontier_digests[position] = digest;
        self.frontier_digest_present[position] = 1;
        Ok(())
    }

    pub(crate) fn finish_root_pass(self) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofProverError> {
        if self.mode != StatementOwnedMerkleReplayMode::RootPass
            || self.absorbed_leaf_count
                != u64::try_from(self.leaf_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
            || self.occupied_level_mask != 0
            || self.recomputed_root != Some(self.expected_root)
            || !self.opened_leaf_bytes.is_empty()
            || !self.frontier_digests.is_empty()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(self.expected_root)
    }

    pub(crate) fn finish_opening_pass(
        self,
        pass_one_root: [u8; HASH_BYTE_LENGTH],
    ) -> Result<PrefetchedCommonProofOpeningArtifact, CommonProofProverError> {
        if self.mode != StatementOwnedMerkleReplayMode::OpeningPass
            || self.absorbed_leaf_count
                != u64::try_from(self.leaf_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
            || self.occupied_level_mask != 0
            || self.recomputed_root != Some(pass_one_root)
            || pass_one_root != self.expected_root
            || self.next_opened_leaf_position != self.opened_leaf_indexes.len()
            || self
                .frontier_digest_present
                .iter()
                .any(|present| *present != 1)
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        PrefetchedCommonProofOpeningArtifact::from_recomputed_statement_owned_tree(
            self.catalog_entry.tree_catalog_index(),
            self.leaf_count,
            self.canonical_leaf_byte_length,
            self.opened_leaf_indexes,
            self.opened_leaf_bytes,
            self.frontier_coordinates,
            self.frontier_digests,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofPrivacyMode, CommonProofTranscriptSchedule, ProofTreeCatalogInput,
        RelationProofTreeInput, StatementOwnedProofTreeInput, build_complete_proof_tree_catalog,
    };
    use crate::foundation::{Hash512, PRIVATE_PROOF_SALT_PURPOSE, PrivateRandomCursor};

    #[derive(Clone)]
    struct TestCoinSource {
        seed: u8,
        next_salt_ordinal: u64,
        replay_instance_binding: Rc<()>,
    }

    impl TestCoinSource {
        fn new(seed: u8) -> Self {
            Self {
                seed,
                next_salt_ordinal: 0,
                replay_instance_binding: Rc::new(()),
            }
        }

        fn salt(seed: u8, salt_ordinal: u64) -> [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
            let mut salt = [0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
            for (byte_index, byte) in salt.iter_mut().enumerate() {
                *byte = seed
                    .wrapping_add((salt_ordinal as u8).wrapping_mul(17))
                    .wrapping_add(byte_index as u8);
            }
            salt
        }
    }

    impl CommonProofPrivateCoinSource for TestCoinSource {
        type Error = &'static str;

        fn sample_modulo(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            _modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            Err("the Merkle replay test does not sample field coins")
        }

        fn fill_raw_bytes(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            if coordinate != CommonProofPrivateCoinCoordinate::proof_salt()
                || destination.len() != COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
            {
                return Err("unexpected test coin request");
            }
            destination.copy_from_slice(&Self::salt(self.seed, self.next_salt_ordinal));
            self.next_salt_ordinal = self
                .next_salt_ordinal
                .checked_add(1)
                .ok_or("test salt cursor overflow")?;
            Ok(())
        }
    }

    impl TestCoinSource {
        fn replay_cursor(&self) -> PrivateRandomCursor {
            PrivateRandomCursor::new(
                0x1218,
                PRIVATE_PROOF_SALT_PURPOSE,
                Hash512::from_bytes([0x64; 64]),
                [0x91; 32],
                self.next_salt_ordinal,
                None,
            )
            .expect("the deterministic test replay cursor is valid")
        }
    }

    impl ReplayableCommonProofPrivateCoinSource for TestCoinSource {
        fn capture_proof_salt_replay_cursor(
            &self,
        ) -> Result<CommonProofPrivateCoinReplayCursor, Self::Error> {
            Ok(CommonProofPrivateCoinReplayCursor::new(
                &self.replay_instance_binding,
                self.replay_cursor(),
            ))
        }

        fn restore_proof_salt_replay_cursor(
            &mut self,
            replay_cursor: &CommonProofPrivateCoinReplayCursor,
        ) -> Result<(), Self::Error> {
            if !replay_cursor.belongs_to(&self.replay_instance_binding) {
                return Err("the replay cursor belongs to a different test source");
            }
            let cursor = replay_cursor.cursor();
            if cursor.family() != 0x1218
                || cursor.purpose() != PRIVATE_PROOF_SALT_PURPOSE
                || cursor.derivation_context_hash() != Hash512::from_bytes([0x64; 64])
                || cursor.stream_attempt_identifier() != [0x91; 32]
                || cursor.next_unread_bit_offset_in_buffered_block().is_some()
            {
                return Err("the replay cursor has the wrong test identity");
            }
            self.next_salt_ordinal = cursor.next_counter();
            Ok(())
        }

        fn proof_salt_replay_cursor_matches(
            &self,
            replay_cursor: &CommonProofPrivateCoinReplayCursor,
        ) -> Result<bool, Self::Error> {
            if !replay_cursor.belongs_to(&self.replay_instance_binding) {
                return Err("the replay cursor belongs to a different test source");
            }
            Ok(replay_cursor.cursor() == self.replay_cursor())
        }
    }

    fn test_base_value(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("the test value is canonical")
    }

    fn test_extension_value(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([
            value,
            value + 1,
            value + 2,
            value + 3,
            value + 4,
        ])
        .expect("the test extension value is canonical")
    }

    fn column_replay_catalog_entry(
        privacy_mode: CommonProofPrivacyMode,
        value_type: RelationColumnValueType,
    ) -> ProofTreeCatalogEntry {
        let leaf_visibility = match privacy_mode {
            CommonProofPrivacyMode::PublicOnly => ProofLeafVisibility::Public,
            CommonProofPrivacyMode::SecretBearing => ProofLeafVisibility::SecretBearing,
        };
        let schedule = CommonProofTranscriptSchedule::new(
            vec![0],
            Vec::new(),
            Vec::new(),
            1,
            1,
            1,
            1,
            1,
            1,
            3,
            8,
            64,
            privacy_mode,
        )
        .expect("the column replay schedule is valid");
        let catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: [0x31; 64],
                canonical_proof_object_header_bytes: vec![0x42; 96],
                application_statement_schema_identifier: 0x1218,
                proof_field_index: 0,
                evaluation_domain_size: 16,
                relation_trees: vec![RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    row_width: 3,
                    leaf_visibility,
                }],
            },
            &schedule,
        )
        .expect("the column replay catalog is valid");
        catalog
            .entries()
            .iter()
            .find(|entry| common_proof_tree_value_type(entry) == Ok(value_type))
            .expect("the requested test tree exists")
            .clone()
    }

    fn replay_tree_value(
        value_type: RelationColumnValueType,
        column_position: usize,
        leaf_index: usize,
        is_opposite: bool,
        mutation: u64,
    ) -> ProofTreeValue {
        let value = 100_u64
            + u64::try_from(column_position).expect("the column position fits u64") * 1_000
            + u64::try_from(leaf_index).expect("the leaf index fits u64") * 11
            + if is_opposite { 50_000 } else { 0 }
            + mutation;
        match value_type {
            RelationColumnValueType::BaseField => ProofTreeValue::Base(test_base_value(value)),
            RelationColumnValueType::ChallengeExtension => {
                ProofTreeValue::Extension(test_extension_value(value))
            }
        }
    }

    fn drive_column_replay(
        replay: &mut CommonProofColumnMajorMerkleReplay,
        ordered_column_ordinals: &[u32],
        value_type: RelationColumnValueType,
        opening_mutation: Option<(bool, usize, usize)>,
    ) -> Result<(), CommonProofProverError> {
        for is_opposite in [false, true] {
            if is_opposite {
                replay.begin_opposite_point_values()?;
            }
            for (column_position, column_ordinal) in
                ordered_column_ordinals.iter().copied().enumerate()
            {
                let values = (0..8)
                    .map(|leaf_index| {
                        let mutation = u64::from(
                            opening_mutation == Some((is_opposite, column_position, leaf_index)),
                        );
                        replay_tree_value(
                            value_type,
                            column_position,
                            leaf_index,
                            is_opposite,
                            mutation,
                        )
                    })
                    .collect::<Vec<_>>();
                let mut first_leaf_index = 0_usize;
                for chunk_length in [1_usize, 3, 4] {
                    let end_leaf_index = first_leaf_index + chunk_length;
                    replay.supply_next_column_chunk(
                        column_ordinal,
                        first_leaf_index,
                        &values[first_leaf_index..end_leaf_index],
                    )?;
                    first_leaf_index = end_leaf_index;
                }
            }
        }
        Ok(())
    }

    fn expected_materialized_tree(
        entry: &ProofTreeCatalogEntry,
        ordered_column_ordinals: &[u32],
        value_type: RelationColumnValueType,
        secret_salt_seed: u8,
    ) -> (Vec<Vec<u8>>, Vec<Vec<[u8; HASH_BYTE_LENGTH]>>) {
        let leaf_count = 8_usize;
        let mut canonical_leaf_bytes = Vec::with_capacity(leaf_count);
        let mut leaf_digests = Vec::with_capacity(leaf_count);
        for leaf_index in 0..leaf_count {
            let first_point_values = Zeroizing::new(
                (0..ordered_column_ordinals.len())
                    .map(|column_position| {
                        replay_tree_value(value_type, column_position, leaf_index, false, 0)
                    })
                    .collect(),
            );
            let opposite_point_values = Zeroizing::new(
                (0..ordered_column_ordinals.len())
                    .map(|column_position| {
                        replay_tree_value(value_type, column_position, leaf_index, true, 0)
                    })
                    .collect(),
            );
            let salt = (entry.materialized_leaf_visibility() == ProofLeafVisibility::SecretBearing)
                .then(|| {
                    TestCoinSource::salt(
                        secret_salt_seed,
                        u64::try_from(leaf_index).expect("the leaf index fits u64"),
                    )
                });
            let (bytes, digest) = entry
                .encode_materialized_leaf(
                    u64::try_from(leaf_index).expect("the leaf index fits u64"),
                    salt,
                    first_point_values,
                    opposite_point_values,
                )
                .expect("the materialized leaf is valid");
            canonical_leaf_bytes.push(bytes);
            leaf_digests.push(digest);
        }
        let mut levels = vec![leaf_digests];
        while levels.last().expect("the leaf level exists").len() > 1 {
            let child_level = levels.last().expect("the child level exists");
            let parent_level_ordinal =
                u32::try_from(levels.len()).expect("the test level fits u32");
            let parent_level = child_level
                .chunks_exact(2)
                .enumerate()
                .map(|(parent_index, children)| {
                    entry
                        .materialized_parent_digest(
                            parent_level_ordinal,
                            u64::try_from(parent_index).expect("the parent index fits u64"),
                            children[0],
                            children[1],
                        )
                        .expect("the materialized parent hashes")
                })
                .collect();
            levels.push(parent_level);
        }
        (canonical_leaf_bytes, levels)
    }

    fn assert_column_replay_case(
        privacy_mode: CommonProofPrivacyMode,
        value_type: RelationColumnValueType,
    ) {
        let entry = column_replay_catalog_entry(privacy_mode, value_type);
        let ordered_column_ordinals = match value_type {
            RelationColumnValueType::BaseField => vec![701, 9, 4_000],
            RelationColumnValueType::ChallengeExtension => vec![701],
        };
        let replay_binding = [0x5a; HASH_BYTE_LENGTH];
        let secret_salt_seed = 0x73;
        let (expected_leaf_bytes, expected_levels) = expected_materialized_tree(
            &entry,
            &ordered_column_ordinals,
            value_type,
            secret_salt_seed,
        );
        let expected_root = expected_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("the expected root exists");

        let mut replay_coins = TestCoinSource::new(secret_salt_seed);
        let mut root_pass = CommonProofColumnMajorMerkleReplay::new_root_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
            &mut replay_coins,
        )
        .expect("the root replay initializes");
        assert_eq!(
            root_pass.mode(),
            CommonProofColumnMajorMerkleReplayMode::RootPass
        );
        let root_memory = root_pass
            .memory_accounting()
            .expect("root replay memory is measurable");
        assert_eq!(
            root_memory.digest_builder_arena_byte_length(),
            8 * u64::try_from(core::mem::size_of::<ProofOraclePhasePairLeafDigestBuilder>())
                .expect("the digest builder size fits u64")
        );
        assert_eq!(root_memory.opened_leaf_byte_length(), 0);
        assert_eq!(root_memory.frontier_digest_byte_length(), 0);
        assert_eq!(root_memory.maximum_copied_buffer_byte_length(), 0);
        assert!(root_memory.total_resident_owned_byte_length() > 0);
        drive_column_replay(&mut root_pass, &ordered_column_ordinals, value_type, None)
            .expect("the root columns replay");
        let root_pass = root_pass
            .finish_root_pass()
            .expect("the root pass finishes");
        assert_eq!(root_pass.root(), expected_root);
        assert_eq!(
            root_pass.source_stream_byte_length(),
            8 * u64::try_from(ordered_column_ordinals.len()).expect("the row width fits u64")
                * 2
                * external_value_byte_length(value_type),
        );

        let sorted_query_representatives = [0_u64, 3, 7];
        let expected_opened_leaf_indexes =
            opened_leaf_indexes(entry.source(), 16, &sorted_query_representatives)
                .expect("the opened indexes derive");
        let expected_frontier_coordinates =
            minimal_frontier_coordinates(&expected_opened_leaf_indexes, expected_levels[0].len())
                .expect("the expected frontier derives");
        let mut opening_pass = CommonProofColumnMajorMerkleReplay::new_opening_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
            &root_pass,
            &sorted_query_representatives,
            u64::MAX,
            &mut replay_coins,
        )
        .expect("the opening replay initializes");
        let opening_memory = opening_pass
            .memory_accounting()
            .expect("opening replay memory is measurable");
        assert!(opening_memory.opened_leaf_byte_length() > 0);
        assert_eq!(opening_memory.maximum_copied_buffer_byte_length(), 0);
        drive_column_replay(
            &mut opening_pass,
            &ordered_column_ordinals,
            value_type,
            None,
        )
        .expect("the opening columns replay");
        let artifact = opening_pass
            .finish_opening_pass(&root_pass)
            .expect("the opening replay finishes");
        assert_eq!(artifact.opened_leaf_indexes(), expected_opened_leaf_indexes);
        for (position, leaf_index) in expected_opened_leaf_indexes.iter().copied().enumerate() {
            assert_eq!(
                artifact
                    .canonical_leaf_bytes_by_position(position)
                    .expect("the retained leaf exists"),
                expected_leaf_bytes
                    .get(usize::try_from(leaf_index).expect("the leaf index fits usize"))
                    .expect("the expected leaf exists")
            );
        }
        assert_eq!(
            artifact.frontier_coordinates(),
            expected_frontier_coordinates
        );
        for (position, (level, node_index)) in
            expected_frontier_coordinates.iter().copied().enumerate()
        {
            assert_eq!(
                artifact
                    .frontier_digest_by_position(position)
                    .expect("the retained frontier digest exists"),
                expected_levels[usize::try_from(level).expect("the level fits usize")]
                    [usize::try_from(node_index).expect("the node index fits usize")]
            );
        }

        assert!(matches!(
            CommonProofColumnMajorMerkleReplay::new_opening_pass(
                &entry,
                16,
                &ordered_column_ordinals,
                [0x5b; HASH_BYTE_LENGTH],
                &root_pass,
                &sorted_query_representatives,
                u64::MAX,
                &mut replay_coins,
            ),
            Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree
            ))
        ));

        if privacy_mode == CommonProofPrivacyMode::SecretBearing {
            let mut stale_replay_source = TestCoinSource::new(secret_salt_seed);
            assert!(matches!(
                CommonProofColumnMajorMerkleReplay::new_opening_pass(
                    &entry,
                    16,
                    &ordered_column_ordinals,
                    replay_binding,
                    &root_pass,
                    &sorted_query_representatives,
                    u64::MAX,
                    &mut stale_replay_source,
                ),
                Err(CommonProofTreeStorageError::CoinSource(
                    "the replay cursor belongs to a different test source"
                ))
            ));
        }

        let mut changed_value_pass = CommonProofColumnMajorMerkleReplay::new_opening_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
            &root_pass,
            &sorted_query_representatives,
            u64::MAX,
            &mut replay_coins,
        )
        .expect("the changed-value replay initializes");
        drive_column_replay(
            &mut changed_value_pass,
            &ordered_column_ordinals,
            value_type,
            Some((true, 0, 7)),
        )
        .expect("the changed-value columns replay");
        assert!(matches!(
            changed_value_pass.finish_opening_pass(&root_pass),
            Err(CommonProofProverError::InvalidOpening)
        ));

        let mut wrong_order_coins = TestCoinSource::new(secret_salt_seed);
        let mut wrong_order_pass = CommonProofColumnMajorMerkleReplay::new_root_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
            &mut wrong_order_coins,
        )
        .expect("the wrong-order replay initializes");
        assert_eq!(
            wrong_order_pass.supply_next_column_chunk(
                ordered_column_ordinals[ordered_column_ordinals.len() - 1],
                0,
                &[replay_tree_value(value_type, 0, 0, false, 0)],
            ),
            Err(CommonProofProverError::InvalidColumn)
        );
    }

    #[test]
    fn common_tree_column_replay_is_byte_identical_and_rejects_context_drift() {
        for privacy_mode in [
            CommonProofPrivacyMode::PublicOnly,
            CommonProofPrivacyMode::SecretBearing,
        ] {
            for value_type in [
                RelationColumnValueType::BaseField,
                RelationColumnValueType::ChallengeExtension,
            ] {
                assert_column_replay_case(privacy_mode, value_type);
            }
        }
    }

    fn setup_polynomial_catalog_entry() -> ProofTreeCatalogEntry {
        let schedule = CommonProofTranscriptSchedule::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            2,
            1,
            CommonProofPrivacyMode::PublicOnly,
        )
        .expect("the focused transcript schedule is valid");
        let catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: [0x11; 64],
                canonical_proof_object_header_bytes: vec![0x22],
                application_statement_schema_identifier: 0x1216,
                proof_field_index: 0,
                evaluation_domain_size: 4,
                relation_trees: vec![RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash: [0x33; 64],
                        row_width: 1,
                        expected_root: [0x44; 64],
                    },
                )],
            },
            &schedule,
        )
        .expect("the focused catalog is valid");
        catalog.entries()[0].clone()
    }

    #[test]
    fn setup_polynomial_streaming_frontier_matches_canonical_with_exact_allocation() {
        for leaf_count in [1_usize, 2, 4, 8] {
            for selected_mask in 1_u64..(1_u64 << leaf_count) {
                let opened_leaf_indexes = (0..leaf_count)
                    .filter(|leaf_index| selected_mask & (1_u64 << *leaf_index) != 0)
                    .map(|leaf_index| u64::try_from(leaf_index).expect("the leaf index fits u64"))
                    .collect::<Vec<_>>();
                let expected = minimal_frontier_coordinates(&opened_leaf_indexes, leaf_count)
                    .expect("the canonical frontier derives");
                let coordinate_count = scan_setup_polynomial_frontier_coordinates(
                    &opened_leaf_indexes,
                    leaf_count,
                    None,
                )
                .expect("the scalar count scan succeeds");
                let observed =
                    setup_polynomial_frontier_coordinates(&opened_leaf_indexes, leaf_count)
                        .expect("the scalar fill scan succeeds");
                assert_eq!(observed, expected);
                assert_eq!(observed.len(), coordinate_count);
                assert_eq!(
                    observed.capacity(),
                    coordinate_count,
                    "the final coordinate vector is the only frontier heap payload",
                );
                assert!(observed.windows(2).all(|pair| pair[0] < pair[1]));
            }
        }

        for opened_leaf_indexes in [
            vec![0],
            vec![15],
            (0_u64..16).step_by(2).collect(),
            (1_u64..16).step_by(2).collect(),
            vec![0, 1, 7, 8, 14, 15],
            (0_u64..16).collect(),
        ] {
            assert_eq!(
                setup_polynomial_frontier_coordinates(&opened_leaf_indexes, 16)
                    .expect("the selected frontier derives"),
                minimal_frontier_coordinates(&opened_leaf_indexes, 16)
                    .expect("the canonical selected frontier derives"),
            );
        }

        for (opened_leaf_indexes, leaf_count) in [
            (vec![], 4),
            (vec![0, 0], 4),
            (vec![1, 0], 4),
            (vec![4], 4),
            (vec![0], 3),
        ] {
            assert_eq!(
                setup_polynomial_frontier_coordinates(&opened_leaf_indexes, leaf_count),
                Err(CommonProofProverError::InvalidOpening),
            );
        }
    }

    #[test]
    fn setup_polynomial_generic_storage_constructors_reject_materialized_fallback() {
        let entry = setup_polynomial_catalog_entry();
        assert!(matches!(
            common_proof_merkle_storage_plan(&entry, 4, 0, 0, 1),
            Err(CommonProofProverError::InvalidTree),
        ));

        let leaf_bytes_object = ProofExternalMemoryObject::new(0);
        let forged_plan = CommonProofMerkleStoragePlan {
            leaf_bytes_object,
            digest_level_objects: Vec::new(),
            object_plans: Vec::new(),
            canonical_leaf_byte_length: 1,
            next_object_ordinal: 1,
        };
        assert!(matches!(
            CommonProofMerkleMaterializer::new(&entry, 4, forged_plan),
            Err(CommonProofProverError::InvalidTree),
        ));

        let forged_tree = StoredCommonProofMerkleTree {
            tree_catalog_index: entry.tree_catalog_index(),
            catalog_entry: entry.clone(),
            leaf_count: 2,
            canonical_leaf_byte_length: 1,
            leaf_bytes_object,
            digest_level_objects: Vec::new(),
            root: entry.bound_root().expect("the setup root is bound"),
        };
        assert!(matches!(
            CommonProofOpeningPrefetcher::new(&forged_tree, &entry, 4, &[0], 1_048_576),
            Err(CommonProofProverError::InvalidTree),
        ));
    }
}
