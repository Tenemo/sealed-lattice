use crate::bgv::proof_suite::{
    SetupPublicPolynomialError, SetupPublicPolynomialLeafByteBuilder,
    SetupPublicPolynomialLeafHashArena, WASM_SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_STATE_BYTE_LENGTH,
};

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinSource, CommonProofProverError, HASH_BYTE_LENGTH, ProofBaseFieldElement,
    ProofBodyError, ProofChallengeExtensionElement, ProofExternalMemory,
    ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError, ProofExternalMemoryObject,
    ProofExternalMemoryObjectPlan, ProofExternalMemoryProtection, ProofLeafVisibility,
    ProofMerkleTreeContext, ProofOraclePhasePairLeaf, ProofTreeCatalogEntry,
    ProofTreeCatalogSource, ProofTreeRole, ProofTreeValue, RelationColumnValueType,
    StreamingHash512, Zeroize, Zeroizing, canonical_leaf_byte_length, entry_leaf_count,
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

type RecomputedMerkleReplayOutput = (
    [u8; HASH_BYTE_LENGTH],
    Vec<Zeroizing<Vec<u8>>>,
    Vec<u64>,
    Vec<(u32, u64)>,
    Vec<[u8; HASH_BYTE_LENGTH]>,
);

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

fn map_setup_public_polynomial_replay_error(
    error: SetupPublicPolynomialError,
) -> CommonProofProverError {
    match error {
        SetupPublicPolynomialError::InvalidContext
        | SetupPublicPolynomialError::InvalidInput
        | SetupPublicPolynomialError::InvalidLatticeAnchor => CommonProofProverError::InvalidTree,
        SetupPublicPolynomialError::CountOverflow => CommonProofProverError::CountOverflow,
        SetupPublicPolynomialError::AllocationLimitExceeded => {
            CommonProofProverError::AllocationLimitExceeded
        }
        SetupPublicPolynomialError::CanonicalEncoding => CommonProofProverError::CanonicalEncoding,
        SetupPublicPolynomialError::Field(error) => CommonProofProverError::Field(error),
        SetupPublicPolynomialError::Polynomial(error) => CommonProofProverError::Polynomial(error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupPolynomialColumnMajorMerkleReplayMode {
    RootPass,
    OpeningPass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SetupPolynomialColumnMajorMerkleRootPass {
    tree_catalog_index: u16,
    public_polynomial_context_hash: [u8; HASH_BYTE_LENGTH],
    ordered_column_catalog_digest: [u8; HASH_BYTE_LENGTH],
    replay_binding: [u8; HASH_BYTE_LENGTH],
    root: [u8; HASH_BYTE_LENGTH],
    source_stream_byte_length: u64,
}

impl SetupPolynomialColumnMajorMerkleRootPass {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn root(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.root
    }

    #[cfg(test)]
    pub(crate) const fn source_stream_byte_length(&self) -> u64 {
        self.source_stream_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupPolynomialColumnMajorMerkleReplayMemoryAccounting {
    native_leaf_hash_arena_byte_length: u64,
    wasm_leaf_hash_arena_byte_length: u64,
    ordered_column_catalog_byte_length: u64,
    opened_leaf_index_catalog_byte_length: u64,
    native_opened_leaf_builder_catalog_byte_length: u64,
    wasm_opened_leaf_builder_catalog_byte_length: u64,
    opened_leaf_byte_length: u64,
    frontier_coordinate_catalog_byte_length: u64,
    frontier_digest_byte_length: u64,
    frontier_presence_byte_length: u64,
    digest_stack_byte_length: u64,
    native_total_resident_owned_byte_length: u64,
    wasm_total_resident_owned_byte_length: u64,
}

impl SetupPolynomialColumnMajorMerkleReplayMemoryAccounting {
    #[cfg(test)]
    pub(crate) const fn native_leaf_hash_arena_byte_length(self) -> u64 {
        self.native_leaf_hash_arena_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn wasm_leaf_hash_arena_byte_length(self) -> u64 {
        self.wasm_leaf_hash_arena_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn opened_leaf_byte_length(self) -> u64 {
        self.opened_leaf_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn frontier_digest_byte_length(self) -> u64 {
        self.frontier_digest_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn native_total_resident_owned_byte_length(self) -> u64 {
        self.native_total_resident_owned_byte_length
    }

    pub(crate) const fn wasm_total_resident_owned_byte_length(self) -> u64 {
        self.wasm_total_resident_owned_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupPolynomialColumnMajorMerkleReplayWasmMemoryBound {
    replay_resident_owned_byte_length: u64,
    retained_opening_artifact_owned_byte_length: u64,
}

impl SetupPolynomialColumnMajorMerkleReplayWasmMemoryBound {
    pub(crate) const fn replay_resident_owned_byte_length(self) -> u64 {
        self.replay_resident_owned_byte_length
    }

    pub(crate) const fn retained_opening_artifact_owned_byte_length(self) -> u64 {
        self.retained_opening_artifact_owned_byte_length
    }
}

/// Derives the allocation-free WebAssembly live-set bound for one setup
/// polynomial replay directly from its authenticated tree geometry. The
/// replay bound includes the leaf-hash arena and every owned replay catalog;
/// the retained artifact bound contains only allocations that move into the
/// catalogued query artifact after the arena and replay-only catalogs drop.
pub(crate) fn setup_polynomial_column_major_merkle_replay_wasm_memory_bound(
    leaf_count: usize,
    ordered_column_count: usize,
    canonical_leaf_byte_length: usize,
    opened_leaf_count: usize,
    frontier_node_count: usize,
) -> Result<SetupPolynomialColumnMajorMerkleReplayWasmMemoryBound, CommonProofProverError> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || ordered_column_count == 0
        || canonical_leaf_byte_length == 0
        || opened_leaf_count > leaf_count
        || (opened_leaf_count == 0 && frontier_node_count != 0)
    {
        return Err(CommonProofProverError::InvalidTree);
    }
    let multiply = |count: usize, element_byte_length: usize| {
        u64::try_from(count)
            .ok()
            .and_then(|count| {
                u64::try_from(element_byte_length)
                    .ok()
                    .and_then(|element_byte_length| count.checked_mul(element_byte_length))
            })
            .ok_or(CommonProofProverError::CountOverflow)
    };
    let leaf_hash_arena_byte_length = multiply(
        leaf_count,
        WASM_SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_STATE_BYTE_LENGTH,
    )?;
    let ordered_column_catalog_byte_length = multiply(ordered_column_count, 4)?;
    let opened_leaf_index_catalog_byte_length = multiply(opened_leaf_count, 8)?;
    let opened_leaf_builder_catalog_byte_length = multiply(opened_leaf_count, 24)?;
    let opened_leaf_byte_length = multiply(opened_leaf_count, canonical_leaf_byte_length)?;
    // `(u32, u64)` retains eight-byte alignment under wasm32 and therefore
    // occupies sixteen bytes, matching the deployed replay layout.
    let frontier_coordinate_catalog_byte_length = multiply(frontier_node_count, 16)?;
    let frontier_digest_byte_length = multiply(frontier_node_count, HASH_BYTE_LENGTH)?;
    let frontier_presence_byte_length = multiply(frontier_node_count, 1)?;
    let digest_stack_byte_length = multiply(
        usize::try_from(leaf_count.trailing_zeros())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        HASH_BYTE_LENGTH,
    )?;
    let replay_resident_owned_byte_length = [
        leaf_hash_arena_byte_length,
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
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(CommonProofProverError::CountOverflow)
    })?;
    let retained_opening_artifact_owned_byte_length = [
        opened_leaf_index_catalog_byte_length,
        // The completed segmented artifact retains one wasm32 `Vec<u8>`
        // descriptor per opened leaf after the larger replay-builder catalog
        // drops.
        multiply(opened_leaf_count, 12)?,
        opened_leaf_byte_length,
        frontier_coordinate_catalog_byte_length,
        frontier_digest_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(CommonProofProverError::CountOverflow)
    })?;
    Ok(SetupPolynomialColumnMajorMerkleReplayWasmMemoryBound {
        replay_resident_owned_byte_length,
        retained_opening_artifact_owned_byte_length,
    })
}

/// Column-at-a-time replay for statement-owned setup-polynomial trees.
///
/// The deployed leaf bytes interleave each column's first and opposite
/// evaluation. One SHAKE state per leaf therefore accepts a complete column
/// without retaining any other evaluation column. The root pass retains only
/// its source identity; the opening pass replays the same verified columns and
/// retains only queried leaves plus their exact minimal frontier.
pub(crate) struct SetupPolynomialColumnMajorMerkleReplay {
    catalog_entry: ProofTreeCatalogEntry,
    public_polynomial_context_hash: [u8; HASH_BYTE_LENGTH],
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    ordered_column_ordinals: Vec<u32>,
    ordered_column_catalog_digest: [u8; HASH_BYTE_LENGTH],
    replay_binding: [u8; HASH_BYTE_LENGTH],
    expected_root: [u8; HASH_BYTE_LENGTH],
    mode: SetupPolynomialColumnMajorMerkleReplayMode,
    next_column_position: usize,
    next_leaf_index: usize,
    source_stream_byte_length: u64,
    leaf_hash_arena: Option<SetupPublicPolynomialLeafHashArena>,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_byte_builders: Vec<SetupPublicPolynomialLeafByteBuilder>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    frontier_digest_present: Vec<u8>,
    pending_left_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
}

impl SetupPolynomialColumnMajorMerkleReplay {
    pub(crate) fn new_root_pass(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
        replay_binding: [u8; HASH_BYTE_LENGTH],
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            catalog_entry,
            evaluation_domain_size,
            ordered_column_ordinals,
            replay_binding,
            None,
            &[],
            u64::MAX,
            SetupPolynomialColumnMajorMerkleReplayMode::RootPass,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_opening_pass(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
        replay_binding: [u8; HASH_BYTE_LENGTH],
        root_pass: &SetupPolynomialColumnMajorMerkleRootPass,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            catalog_entry,
            evaluation_domain_size,
            ordered_column_ordinals,
            replay_binding,
            Some(root_pass),
            sorted_query_representatives,
            maximum_prefetched_byte_length,
            SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
        replay_binding: [u8; HASH_BYTE_LENGTH],
        root_pass: Option<&SetupPolynomialColumnMajorMerkleRootPass>,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
        mode: SetupPolynomialColumnMajorMerkleReplayMode,
    ) -> Result<Self, CommonProofProverError> {
        let (public_polynomial_context_hash, row_width) = catalog_entry
            .setup_polynomial_construction()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let expected_root = catalog_entry
            .bound_root()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
            .map_err(map_proof_body_tree_error)?;
        let canonical_leaf_byte_length =
            canonical_leaf_byte_length(catalog_entry).map_err(map_proof_body_tree_error)?;
        let ordered_column_catalog_digest = ordered_column_catalog_digest(ordered_column_ordinals)?;
        if replay_binding == [0_u8; HASH_BYTE_LENGTH]
            || leaf_count == 0
            || !leaf_count.is_power_of_two()
            || leaf_count.trailing_zeros() >= u64::BITS
            || usize::try_from(row_width).map_or(true, |width| {
                width == 0 || width != ordered_column_ordinals.len()
            })
            || common_proof_tree_value_type(catalog_entry)? != RelationColumnValueType::BaseField
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        match (mode, root_pass) {
            (SetupPolynomialColumnMajorMerkleReplayMode::RootPass, None) => {}
            (SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass, Some(root_pass))
                if root_pass.tree_catalog_index == catalog_entry.tree_catalog_index()
                    && root_pass.public_polynomial_context_hash
                        == public_polynomial_context_hash
                    && root_pass.ordered_column_catalog_digest == ordered_column_catalog_digest
                    && root_pass.replay_binding == replay_binding
                    && root_pass.root == expected_root => {}
            _ => return Err(CommonProofProverError::InvalidTree),
        }

        let opened_leaf_indexes = match mode {
            SetupPolynomialColumnMajorMerkleReplayMode::RootPass => Vec::new(),
            SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass => opened_leaf_indexes(
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
        if matches!(
            mode,
            SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass
        ) && (opened_leaf_indexes.is_empty()
            || maximum_prefetched_byte_length == 0
            || u64::try_from(prefetched_payload_byte_length)
                .map_err(|_| CommonProofProverError::CountOverflow)?
                > maximum_prefetched_byte_length)
        {
            return Err(CommonProofProverError::AllocationLimitExceeded);
        }

        let mut opened_leaf_byte_builders = Vec::new();
        opened_leaf_byte_builders
            .try_reserve_exact(opened_leaf_indexes.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for leaf_index in &opened_leaf_indexes {
            opened_leaf_byte_builders.push(
                SetupPublicPolynomialLeafByteBuilder::new(
                    public_polynomial_context_hash,
                    *leaf_index,
                    row_width,
                )
                .map_err(map_setup_public_polynomial_replay_error)?,
            );
        }
        let leaf_hash_arena = SetupPublicPolynomialLeafHashArena::new(
            public_polynomial_context_hash,
            leaf_count,
            row_width,
        )
        .map_err(map_setup_public_polynomial_replay_error)?;
        let mut frontier_digests = Vec::new();
        frontier_digests
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        frontier_digests.resize(frontier_coordinates.len(), [0_u8; HASH_BYTE_LENGTH]);
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
        pending_left_digests.resize(tree_height, [0_u8; HASH_BYTE_LENGTH]);
        let mut retained_ordered_column_ordinals = Vec::new();
        retained_ordered_column_ordinals
            .try_reserve_exact(ordered_column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        retained_ordered_column_ordinals.extend_from_slice(ordered_column_ordinals);

        Ok(Self {
            catalog_entry: catalog_entry.clone(),
            public_polynomial_context_hash,
            leaf_count,
            canonical_leaf_byte_length,
            ordered_column_ordinals: retained_ordered_column_ordinals,
            ordered_column_catalog_digest,
            replay_binding,
            expected_root,
            mode,
            next_column_position: 0,
            next_leaf_index: 0,
            source_stream_byte_length: 0,
            leaf_hash_arena: Some(leaf_hash_arena),
            opened_leaf_indexes,
            opened_leaf_byte_builders,
            frontier_coordinates,
            frontier_digests,
            frontier_digest_present,
            pending_left_digests,
        })
    }

    pub(crate) const fn mode(&self) -> SetupPolynomialColumnMajorMerkleReplayMode {
        self.mode
    }

    pub(crate) fn ordered_column_ordinals(&self) -> &[u32] {
        &self.ordered_column_ordinals
    }

    pub(crate) fn next_column_ordinal(&self) -> Option<u32> {
        self.ordered_column_ordinals
            .get(self.next_column_position)
            .copied()
    }

    pub(crate) fn memory_accounting(
        &self,
    ) -> Result<SetupPolynomialColumnMajorMerkleReplayMemoryAccounting, CommonProofProverError>
    {
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
        let arena = self
            .leaf_hash_arena
            .as_ref()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let native_leaf_hash_arena_byte_length = arena
            .native_resident_owned_payload_byte_length()
            .map_err(map_setup_public_polynomial_replay_error)?;
        let wasm_leaf_hash_arena_byte_length = arena
            .wasm_resident_owned_payload_byte_length()
            .map_err(map_setup_public_polynomial_replay_error)?;
        let ordered_column_catalog_byte_length = vector_payload_byte_length(
            self.ordered_column_ordinals.capacity(),
            core::mem::size_of::<u32>(),
        )?;
        let opened_leaf_index_catalog_byte_length = vector_payload_byte_length(
            self.opened_leaf_indexes.capacity(),
            core::mem::size_of::<u64>(),
        )?;
        let native_opened_leaf_builder_catalog_byte_length = vector_payload_byte_length(
            self.opened_leaf_byte_builders.capacity(),
            core::mem::size_of::<SetupPublicPolynomialLeafByteBuilder>(),
        )?;
        // wasm32 stores Vec as three u32 words and each of the builder's
        // three scalar counters as one usize word: 12 + 12 exact bytes.
        let wasm_opened_leaf_builder_catalog_byte_length =
            vector_payload_byte_length(self.opened_leaf_byte_builders.capacity(), 24)?;
        let opened_leaf_byte_length =
            self.opened_leaf_byte_builders
                .iter()
                .try_fold(0_u64, |total, builder| {
                    total
                        .checked_add(
                            builder
                                .resident_owned_payload_byte_length()
                                .map_err(map_setup_public_polynomial_replay_error)?,
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
        let native_total_resident_owned_byte_length = [
            native_leaf_hash_arena_byte_length,
            ordered_column_catalog_byte_length,
            opened_leaf_index_catalog_byte_length,
            native_opened_leaf_builder_catalog_byte_length,
            opened_leaf_byte_length,
            frontier_coordinate_catalog_byte_length,
            frontier_digest_byte_length,
            frontier_presence_byte_length,
            digest_stack_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(byte_length)
                .ok_or(CommonProofProverError::CountOverflow)
        })?;
        let wasm_total_resident_owned_byte_length = [
            wasm_leaf_hash_arena_byte_length,
            ordered_column_catalog_byte_length,
            opened_leaf_index_catalog_byte_length,
            wasm_opened_leaf_builder_catalog_byte_length,
            opened_leaf_byte_length,
            frontier_coordinate_catalog_byte_length,
            frontier_digest_byte_length,
            frontier_presence_byte_length,
            digest_stack_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(byte_length)
                .ok_or(CommonProofProverError::CountOverflow)
        })?;
        Ok(SetupPolynomialColumnMajorMerkleReplayMemoryAccounting {
            native_leaf_hash_arena_byte_length,
            wasm_leaf_hash_arena_byte_length,
            ordered_column_catalog_byte_length,
            opened_leaf_index_catalog_byte_length,
            native_opened_leaf_builder_catalog_byte_length,
            wasm_opened_leaf_builder_catalog_byte_length,
            opened_leaf_byte_length,
            frontier_coordinate_catalog_byte_length,
            frontier_digest_byte_length,
            frontier_presence_byte_length,
            digest_stack_byte_length,
            native_total_resident_owned_byte_length,
            wasm_total_resident_owned_byte_length,
        })
    }

    pub(crate) fn supply_next_column_chunk(
        &mut self,
        column_ordinal: u32,
        first_leaf_index: usize,
        first_point_values: &[ProofBaseFieldElement],
        opposite_point_values: &[ProofBaseFieldElement],
    ) -> Result<(), CommonProofProverError> {
        let expected_column_ordinal = self
            .next_column_ordinal()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let end_leaf_index = first_leaf_index
            .checked_add(first_point_values.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if column_ordinal != expected_column_ordinal
            || first_point_values.is_empty()
            || first_point_values.len() != opposite_point_values.len()
            || first_leaf_index != self.next_leaf_index
            || end_leaf_index > self.leaf_count
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.leaf_hash_arena
            .as_mut()
            .ok_or(CommonProofProverError::InvalidTree)?
            .absorb_extension_column_chunk(
                first_leaf_index,
                first_point_values,
                opposite_point_values,
            )
            .map_err(map_setup_public_polynomial_replay_error)?;

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
            self.opened_leaf_byte_builders
                .get_mut(opened_position)
                .ok_or(CommonProofProverError::InvalidOpening)?
                .absorb_column_pair(
                    *first_point_values
                        .get(value_position)
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                    *opposite_point_values
                        .get(value_position)
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                )
                .map_err(map_setup_public_polynomial_replay_error)?;
            opened_position = opened_position
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }

        self.source_stream_byte_length = self
            .source_stream_byte_length
            .checked_add(
                u64::try_from(first_point_values.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .checked_mul(16)
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

    fn finish_replay(mut self) -> Result<RecomputedMerkleReplayOutput, CommonProofProverError> {
        if self.next_column_position != self.ordered_column_ordinals.len()
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
            .and_then(|length| length.checked_mul(16))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.source_stream_byte_length != expected_source_stream_byte_length {
            return Err(CommonProofProverError::InvalidTree);
        }

        let leaf_hash_arena = self
            .leaf_hash_arena
            .take()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let leaf_digests = leaf_hash_arena
            .finish_leaf_digests()
            .map_err(map_setup_public_polynomial_replay_error)?;
        let mut occupied_level_mask = 0_u64;
        let mut recomputed_root = None;
        for (leaf_index, leaf_digest) in leaf_digests.enumerate() {
            let leaf_index =
                u64::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
            let mut current_digest = leaf_digest;
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
        if root != self.expected_root
            || self
                .frontier_digest_present
                .iter()
                .any(|present| *present != 1)
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let opened_leaf_bytes = core::mem::take(&mut self.opened_leaf_byte_builders)
            .into_iter()
            .map(|builder| {
                builder
                    .finish()
                    .map(Zeroizing::new)
                    .map_err(map_setup_public_polynomial_replay_error)
            })
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
    ) -> Result<SetupPolynomialColumnMajorMerkleRootPass, CommonProofProverError> {
        if self.mode != SetupPolynomialColumnMajorMerkleReplayMode::RootPass
            || !self.opened_leaf_indexes.is_empty()
            || !self.frontier_coordinates.is_empty()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let tree_catalog_index = self.catalog_entry.tree_catalog_index();
        let public_polynomial_context_hash = self.public_polynomial_context_hash;
        let ordered_column_catalog_digest = self.ordered_column_catalog_digest;
        let replay_binding = self.replay_binding;
        let source_stream_byte_length = self.source_stream_byte_length;
        let (root, opened_leaf_bytes, opened_leaf_indexes, frontier_coordinates, frontier_digests) =
            self.finish_replay()?;
        if !opened_leaf_bytes.is_empty()
            || !opened_leaf_indexes.is_empty()
            || !frontier_coordinates.is_empty()
            || !frontier_digests.is_empty()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(SetupPolynomialColumnMajorMerkleRootPass {
            tree_catalog_index,
            public_polynomial_context_hash,
            ordered_column_catalog_digest,
            replay_binding,
            root,
            source_stream_byte_length,
        })
    }

    pub(crate) fn finish_opening_pass(
        self,
        root_pass: &SetupPolynomialColumnMajorMerkleRootPass,
    ) -> Result<PrefetchedCommonProofOpeningArtifact, CommonProofProverError> {
        if self.mode != SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass
            || self.catalog_entry.tree_catalog_index() != root_pass.tree_catalog_index
            || self.public_polynomial_context_hash != root_pass.public_polynomial_context_hash
            || self.ordered_column_catalog_digest != root_pass.ordered_column_catalog_digest
            || self.replay_binding != root_pass.replay_binding
            || self.expected_root != root_pass.root
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let tree_catalog_index = self.catalog_entry.tree_catalog_index();
        let leaf_count = self.leaf_count;
        let canonical_leaf_byte_length = self.canonical_leaf_byte_length;
        let (root, opened_leaf_bytes, opened_leaf_indexes, frontier_coordinates, frontier_digests) =
            self.finish_replay()?;
        if root != root_pass.root {
            return Err(CommonProofProverError::InvalidTree);
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
/// materialized. This path is confined to committed-material leaves and their
/// provider-authenticated persistent salts. Setup-polynomial trees use the
/// bounded column-major replay above.
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
        if catalog_entry.bound_root().is_none()
            || catalog_entry.uses_common_merkle_context()
            || catalog_entry.uses_setup_polynomial_construction()
        {
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

    #[cfg(test)]
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
    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofPrivacyMode, CommonProofTranscriptSchedule, ProofTreeCatalogInput,
        RelationProofTreeInput, StatementOwnedProofTreeInput, build_complete_proof_tree_catalog,
    };
    fn test_base_value(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("the test value is canonical")
    }

    fn replay_base_field_value(
        column_position: usize,
        leaf_index: usize,
        is_opposite_point: bool,
        mutation: u64,
    ) -> ProofBaseFieldElement {
        let value = u64::try_from(column_position)
            .expect("the column position fits u64")
            .checked_mul(64)
            .and_then(|value| {
                value.checked_add(u64::try_from(leaf_index).expect("the leaf index fits u64"))
            })
            .and_then(|value| value.checked_add(if is_opposite_point { 32 } else { 1 }))
            .and_then(|value| value.checked_add(mutation))
            .expect("the focused test value fits u64");
        test_base_value(value)
    }

    fn expected_setup_materialized_tree(
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        ordered_column_ordinals: &[u32],
    ) -> (Vec<Vec<u8>>, Vec<Vec<[u8; HASH_BYTE_LENGTH]>>) {
        let leaf_count = entry_leaf_count(catalog_entry, evaluation_domain_size)
            .expect("the focused setup leaf count derives");
        let mut canonical_leaf_bytes = Vec::with_capacity(leaf_count);
        let mut leaf_digests = Vec::with_capacity(leaf_count);
        for leaf_index in 0..leaf_count {
            let first_point_values = (0..ordered_column_ordinals.len())
                .map(|column_position| {
                    ProofTreeValue::Base(replay_base_field_value(
                        column_position,
                        leaf_index,
                        false,
                        0,
                    ))
                })
                .collect();
            let opposite_point_values = (0..ordered_column_ordinals.len())
                .map(|column_position| {
                    ProofTreeValue::Base(replay_base_field_value(
                        column_position,
                        leaf_index,
                        true,
                        0,
                    ))
                })
                .collect();
            let (leaf_bytes, leaf_digest) = catalog_entry
                .encode_materialized_leaf(
                    u64::try_from(leaf_index).expect("the leaf index fits u64"),
                    None,
                    Zeroizing::new(first_point_values),
                    Zeroizing::new(opposite_point_values),
                )
                .expect("the focused setup leaf encodes");
            canonical_leaf_bytes.push(leaf_bytes);
            leaf_digests.push(leaf_digest);
        }

        let mut digest_levels = vec![leaf_digests];
        let mut level = 1_u32;
        while digest_levels
            .last()
            .expect("the leaf digest level exists")
            .len()
            > 1
        {
            let previous_level = digest_levels
                .last()
                .expect("the previous digest level exists");
            assert_eq!(previous_level.len() % 2, 0);
            let parent_level = previous_level
                .chunks_exact(2)
                .enumerate()
                .map(|(parent_index, children)| {
                    catalog_entry
                        .materialized_parent_digest(
                            level,
                            u64::try_from(parent_index).expect("the parent index fits u64"),
                            children[0],
                            children[1],
                        )
                        .expect("the focused setup parent digest derives")
                })
                .collect();
            digest_levels.push(parent_level);
            level = level.checked_add(1).expect("the digest level fits u32");
        }
        (canonical_leaf_bytes, digest_levels)
    }

    fn setup_polynomial_catalog_entry_with_geometry(
        evaluation_domain_size: u64,
        row_width: u32,
        expected_root: [u8; HASH_BYTE_LENGTH],
    ) -> ProofTreeCatalogEntry {
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
            evaluation_domain_size / 2,
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
                evaluation_domain_size,
                relation_trees: vec![RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash: [0x33; 64],
                        row_width,
                        expected_root,
                    },
                )],
            },
            &schedule,
        )
        .expect("the focused catalog is valid");
        catalog.entries()[0].clone()
    }

    fn setup_polynomial_catalog_entry() -> ProofTreeCatalogEntry {
        setup_polynomial_catalog_entry_with_geometry(4, 1, [0x44; HASH_BYTE_LENGTH])
    }

    fn drive_setup_polynomial_column_replay(
        replay: &mut SetupPolynomialColumnMajorMerkleReplay,
        ordered_column_ordinals: &[u32],
        opening_mutation: Option<(usize, usize)>,
    ) -> Result<(), CommonProofProverError> {
        for (column_position, column_ordinal) in ordered_column_ordinals.iter().copied().enumerate()
        {
            let first_point_values = (0..8)
                .map(|leaf_index| {
                    let mutation =
                        u64::from(opening_mutation == Some((column_position, leaf_index)));
                    replay_base_field_value(column_position, leaf_index, false, mutation)
                })
                .collect::<Vec<_>>();
            let opposite_point_values = (0..8)
                .map(|leaf_index| replay_base_field_value(column_position, leaf_index, true, 0))
                .collect::<Vec<_>>();
            let mut first_leaf_index = 0_usize;
            for chunk_length in [2_usize, 1, 5] {
                let end_leaf_index = first_leaf_index + chunk_length;
                replay.supply_next_column_chunk(
                    column_ordinal,
                    first_leaf_index,
                    &first_point_values[first_leaf_index..end_leaf_index],
                    &opposite_point_values[first_leaf_index..end_leaf_index],
                )?;
                first_leaf_index = end_leaf_index;
            }
        }
        Ok(())
    }

    #[test]
    fn setup_polynomial_column_replay_is_byte_identical_and_rejects_drift() {
        assert_eq!(
            core::mem::size_of::<SetupPolynomialColumnMajorMerkleRootPass>(),
            272,
        );
        assert_eq!(
            core::mem::size_of::<(u16, SetupPolynomialColumnMajorMerkleRootPass)>(),
            280,
        );
        let ordered_column_ordinals = [93_u32, 7, 4_001];
        let placeholder_entry = setup_polynomial_catalog_entry_with_geometry(
            16,
            u32::try_from(ordered_column_ordinals.len()).expect("the row width fits u32"),
            [0x44; HASH_BYTE_LENGTH],
        );
        let (expected_leaf_bytes, expected_levels) =
            expected_setup_materialized_tree(&placeholder_entry, 16, &ordered_column_ordinals);
        let expected_root = expected_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("the expected setup root exists");
        let entry = setup_polynomial_catalog_entry_with_geometry(
            16,
            u32::try_from(ordered_column_ordinals.len()).expect("the row width fits u32"),
            expected_root,
        );
        let replay_binding = [0x81; HASH_BYTE_LENGTH];
        let mut root_replay = SetupPolynomialColumnMajorMerkleReplay::new_root_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
        )
        .expect("the setup root replay initializes");
        assert_eq!(
            root_replay.mode(),
            SetupPolynomialColumnMajorMerkleReplayMode::RootPass,
        );
        let root_memory = root_replay
            .memory_accounting()
            .expect("the setup root replay memory is measurable");
        let canonical_setup_leaf_byte_length =
            canonical_leaf_byte_length(&entry).expect("the setup leaf length derives");
        let root_memory_bound = setup_polynomial_column_major_merkle_replay_wasm_memory_bound(
            8,
            ordered_column_ordinals.len(),
            canonical_setup_leaf_byte_length,
            0,
            0,
        )
        .expect("the setup root replay bound derives without allocating the replay");
        assert_eq!(root_memory.wasm_leaf_hash_arena_byte_length(), 8 * 216);
        assert_eq!(
            root_memory_bound.replay_resident_owned_byte_length(),
            root_memory.wasm_total_resident_owned_byte_length(),
        );
        assert_eq!(
            root_memory.native_leaf_hash_arena_byte_length(),
            8 * u64::try_from(core::mem::size_of::<tiny_keccak::Shake>())
                .expect("the native SHAKE state size fits u64"),
        );
        assert_eq!(root_memory.opened_leaf_byte_length(), 0);
        assert_eq!(root_memory.frontier_digest_byte_length(), 0);
        assert!(
            root_memory.native_total_resident_owned_byte_length()
                >= root_memory.native_leaf_hash_arena_byte_length()
        );
        assert_eq!(
            root_memory.wasm_total_resident_owned_byte_length()
                - root_memory.wasm_leaf_hash_arena_byte_length(),
            root_memory.native_total_resident_owned_byte_length()
                - root_memory.native_leaf_hash_arena_byte_length(),
        );
        drive_setup_polynomial_column_replay(&mut root_replay, &ordered_column_ordinals, None)
            .expect("the setup columns replay");
        let root_pass = root_replay
            .finish_root_pass()
            .expect("the setup root replay finishes");
        assert_eq!(root_pass.root(), expected_root);
        assert_eq!(
            root_pass.source_stream_byte_length(),
            8 * u64::try_from(ordered_column_ordinals.len()).expect("the row width fits u64") * 16,
        );

        let sorted_query_representatives = [0_u64, 3, 7];
        let expected_opened_leaf_indexes =
            opened_leaf_indexes(entry.source(), 16, &sorted_query_representatives)
                .expect("the setup opened leaf indexes derive");
        let expected_frontier_coordinates =
            minimal_frontier_coordinates(&expected_opened_leaf_indexes, 8)
                .expect("the setup frontier derives");
        let mut opening_replay = SetupPolynomialColumnMajorMerkleReplay::new_opening_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
            &root_pass,
            &sorted_query_representatives,
            u64::MAX,
        )
        .expect("the setup opening replay initializes");
        let opening_memory = opening_replay
            .memory_accounting()
            .expect("the setup opening replay memory is measurable");
        let opening_memory_bound = setup_polynomial_column_major_merkle_replay_wasm_memory_bound(
            8,
            ordered_column_ordinals.len(),
            canonical_setup_leaf_byte_length,
            expected_opened_leaf_indexes.len(),
            expected_frontier_coordinates.len(),
        )
        .expect("the setup opening replay bound derives without allocating the replay");
        assert_eq!(opening_memory.wasm_leaf_hash_arena_byte_length(), 8 * 216);
        assert_eq!(
            opening_memory_bound.replay_resident_owned_byte_length(),
            opening_memory.wasm_total_resident_owned_byte_length(),
        );
        assert!(
            opening_memory_bound.retained_opening_artifact_owned_byte_length()
                < opening_memory_bound.replay_resident_owned_byte_length(),
        );
        assert!(
            opening_memory.opened_leaf_byte_length()
                >= u64::try_from(expected_opened_leaf_indexes.len())
                    .expect("the opening count fits u64")
                    * u64::try_from(
                        canonical_leaf_byte_length(&entry).expect("leaf length derives"),
                    )
                    .expect("the leaf length fits u64"),
        );
        drive_setup_polynomial_column_replay(&mut opening_replay, &ordered_column_ordinals, None)
            .expect("the setup opening columns replay");
        let artifact = opening_replay
            .finish_opening_pass(&root_pass)
            .expect("the setup opening replay finishes");
        assert_eq!(artifact.opened_leaf_indexes(), expected_opened_leaf_indexes);
        for (position, leaf_index) in expected_opened_leaf_indexes.iter().copied().enumerate() {
            assert_eq!(
                artifact
                    .canonical_leaf_bytes_by_position(position)
                    .expect("the queried setup leaf exists"),
                expected_leaf_bytes
                    .get(usize::try_from(leaf_index).expect("the leaf index fits usize"))
                    .expect("the expected setup leaf exists"),
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
                    .expect("the setup frontier digest exists"),
                expected_levels[usize::try_from(level).expect("the level fits usize")]
                    [usize::try_from(node_index).expect("the node index fits usize")],
            );
        }

        assert!(matches!(
            SetupPolynomialColumnMajorMerkleReplay::new_opening_pass(
                &entry,
                16,
                &ordered_column_ordinals,
                [0x82; HASH_BYTE_LENGTH],
                &root_pass,
                &sorted_query_representatives,
                u64::MAX,
            ),
            Err(CommonProofProverError::InvalidTree),
        ));
        let changed_root_entry = setup_polynomial_catalog_entry_with_geometry(
            16,
            u32::try_from(ordered_column_ordinals.len()).expect("the row width fits u32"),
            [0x55; HASH_BYTE_LENGTH],
        );
        assert!(matches!(
            SetupPolynomialColumnMajorMerkleReplay::new_opening_pass(
                &changed_root_entry,
                16,
                &ordered_column_ordinals,
                replay_binding,
                &root_pass,
                &sorted_query_representatives,
                u64::MAX,
            ),
            Err(CommonProofProverError::InvalidTree),
        ));

        let mut changed_value_replay = SetupPolynomialColumnMajorMerkleReplay::new_opening_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
            &root_pass,
            &sorted_query_representatives,
            u64::MAX,
        )
        .expect("the changed setup replay initializes");
        drive_setup_polynomial_column_replay(
            &mut changed_value_replay,
            &ordered_column_ordinals,
            Some((1, 6)),
        )
        .expect("the changed setup columns replay");
        assert!(matches!(
            changed_value_replay.finish_opening_pass(&root_pass),
            Err(CommonProofProverError::InvalidTree),
        ));

        let mut wrong_order_replay = SetupPolynomialColumnMajorMerkleReplay::new_root_pass(
            &entry,
            16,
            &ordered_column_ordinals,
            replay_binding,
        )
        .expect("the wrong-order setup replay initializes");
        assert_eq!(
            wrong_order_replay.supply_next_column_chunk(
                ordered_column_ordinals[1],
                0,
                &[test_base_value(1)],
                &[test_base_value(2)],
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
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
        assert!(matches!(
            StatementOwnedMerkleReplay::new_root_pass(&entry, 4),
            Err(CommonProofProverError::InvalidTree),
        ));
        assert!(matches!(
            StatementOwnedMerkleReplay::new_opening_pass(&entry, 4, &[0], 1_048_576),
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
