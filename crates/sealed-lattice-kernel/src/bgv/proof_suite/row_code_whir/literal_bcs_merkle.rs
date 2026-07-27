//! Standard binary Merkle commitment used by the literal BCS compiler.
//!
//! Context symbols occupy the left half and payload symbols occupy the right
//! half of one ordinary complete binary tree. Every internal node is exactly
//! `SHAKE256(left || right)`. Each payload opening therefore carries the
//! context root as its final sibling, which the verifier recomputes from the
//! role, payload geometry, construction identity, and application binding.
//! Uniform context padding lets that recomputation use logarithmic work.

#[cfg(test)]
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[cfg(test)]
const LITERAL_BCS_MERKLE_ENCODING_VERSION: u16 = 1;
#[cfg(test)]
const LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH: usize = 64;
const LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH_U64: u64 = 64;
const LITERAL_BCS_CONTEXT_REQUIRED_LEAF_COUNT: usize = 3;

#[cfg(test)]
pub(super) type LiteralBcsMerkleNode = [u8; LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH];

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LiteralBcsTreeRole {
    RelationBase,
    OpeningBatchMask,
    Aggregate,
    WhirRound { round_ordinal: u32 },
    CanonicalProverMessage { source_operation_ordinal: u32 },
}

#[cfg(test)]
impl LiteralBcsTreeRole {
    const fn encoding(self) -> (u16, u32) {
        match self {
            Self::RelationBase => (1, 0),
            Self::OpeningBatchMask => (4, 0),
            Self::Aggregate => (5, 0),
            Self::WhirRound { round_ordinal } => (7, round_ordinal),
            Self::CanonicalProverMessage {
                source_operation_ordinal,
            } => (8, source_operation_ordinal),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LiteralBcsTreeContext {
    pub(super) role: LiteralBcsTreeRole,
    pub(super) message_byte_length: u64,
    pub(super) construction_identity: LiteralBcsMerkleNode,
    /// Recomputed canonical binding of the suite, action, and statement.
    pub(super) application_binding: LiteralBcsMerkleNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LiteralBcsMerkleError {
    EmptyPayload,
    InvalidMessageByteLength,
    InvalidLeafCount,
    NonCanonicalPayloadPadding,
    InvalidPayloadLeafOrdinal,
    InvalidAuthenticationPathLength,
    WrongContextSubtree,
    WrongRoot,
    CountOverflow,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LiteralBcsMerkleOpening {
    pub(super) payload_leaf_ordinal: usize,
    pub(super) authentication_path: Vec<LiteralBcsMerkleNode>,
}

/// Full-tree reference used only to establish parity with the bounded
/// frontier and opening verifier. The production prover must retain or
/// regenerate authenticated paths through its bounded storage schedule.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LiteralBcsMerkleTree {
    context: LiteralBcsTreeContext,
    payload_leaf_count: usize,
    subtree_leaf_count: usize,
    levels: Vec<Vec<LiteralBcsMerkleNode>>,
    root: LiteralBcsMerkleNode,
}

#[cfg(test)]
impl LiteralBcsMerkleTree {
    pub(super) fn new(
        context: LiteralBcsTreeContext,
        payload_leaves: &[LiteralBcsMerkleNode],
    ) -> Result<Self, LiteralBcsMerkleError> {
        let subtree_leaf_count = checked_subtree_leaf_count(context, payload_leaves)?;
        let leaves = canonical_tree_leaves(context, payload_leaves, subtree_leaf_count)?;
        let mut levels = vec![leaves];
        while levels
            .last()
            .ok_or(LiteralBcsMerkleError::InvalidLeafCount)?
            .len()
            > 1
        {
            let previous_level = levels
                .last()
                .ok_or(LiteralBcsMerkleError::InvalidLeafCount)?;
            let mut next_level = Vec::with_capacity(previous_level.len() / 2);
            for pair in previous_level.chunks_exact(2) {
                next_level.push(literal_bcs_hash_pair(&pair[0], &pair[1]));
            }
            levels.push(next_level);
        }
        let root = levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .ok_or(LiteralBcsMerkleError::InvalidLeafCount)?;
        Ok(Self {
            context,
            payload_leaf_count: payload_leaves.len(),
            subtree_leaf_count,
            levels,
            root,
        })
    }

    pub(super) const fn root(&self) -> LiteralBcsMerkleNode {
        self.root
    }

    pub(super) fn open(
        &self,
        payload_leaf_ordinal: usize,
    ) -> Result<LiteralBcsMerkleOpening, LiteralBcsMerkleError> {
        if payload_leaf_ordinal >= self.payload_leaf_count {
            return Err(LiteralBcsMerkleError::InvalidPayloadLeafOrdinal);
        }
        let mut node_ordinal = self
            .subtree_leaf_count
            .checked_add(payload_leaf_ordinal)
            .ok_or(LiteralBcsMerkleError::CountOverflow)?;
        let mut authentication_path = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            authentication_path.push(level[node_ordinal ^ 1]);
            node_ordinal /= 2;
        }
        Ok(LiteralBcsMerkleOpening {
            payload_leaf_ordinal,
            authentication_path,
        })
    }

    pub(super) const fn context(&self) -> LiteralBcsTreeContext {
        self.context
    }

    pub(super) const fn subtree_leaf_count(&self) -> usize {
        self.subtree_leaf_count
    }
}

#[cfg(test)]
pub(super) fn literal_bcs_hash_pair(
    left: &LiteralBcsMerkleNode,
    right: &LiteralBcsMerkleNode,
) -> LiteralBcsMerkleNode {
    let mut state = Shake256::default();
    state.update(left);
    state.update(right);
    let mut output = [0_u8; LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH];
    state.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
pub(super) fn literal_bcs_payload_symbols(
    canonical_message: &[u8],
) -> Result<Vec<LiteralBcsMerkleNode>, LiteralBcsMerkleError> {
    if canonical_message.is_empty() {
        return Err(LiteralBcsMerkleError::EmptyPayload);
    }
    let payload_leaf_count = canonical_message
        .len()
        .div_ceil(LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH);
    let mut payload_leaves = Vec::with_capacity(payload_leaf_count);
    for chunk in canonical_message.chunks(LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH) {
        let mut leaf = [0_u8; LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH];
        leaf[..chunk.len()].copy_from_slice(chunk);
        payload_leaves.push(leaf);
    }
    Ok(payload_leaves)
}

pub(super) fn literal_bcs_subtree_leaf_count(
    payload_leaf_count: usize,
) -> Result<usize, LiteralBcsMerkleError> {
    if payload_leaf_count == 0 {
        return Err(LiteralBcsMerkleError::EmptyPayload);
    }
    payload_leaf_count
        .max(LITERAL_BCS_CONTEXT_REQUIRED_LEAF_COUNT)
        .checked_next_power_of_two()
        .ok_or(LiteralBcsMerkleError::CountOverflow)
}

pub(super) fn literal_bcs_committed_tree_leaf_count(
    payload_leaf_count: usize,
) -> Result<usize, LiteralBcsMerkleError> {
    literal_bcs_subtree_leaf_count(payload_leaf_count)?
        .checked_mul(2)
        .ok_or(LiteralBcsMerkleError::CountOverflow)
}

/// Counts only the commitment's binary-hash evaluations. The caller owns
/// accounting for the already-recomputed construction and application
/// bindings.
pub(super) fn literal_bcs_commitment_hash_query_count(
    payload_leaf_count: usize,
) -> Result<u64, LiteralBcsMerkleError> {
    let subtree_leaf_count = literal_bcs_subtree_leaf_count(payload_leaf_count)?;
    let payload_subtree_hash_query_count = u64::try_from(
        subtree_leaf_count
            .checked_sub(1)
            .ok_or(LiteralBcsMerkleError::CountOverflow)?,
    )
    .map_err(|_| LiteralBcsMerkleError::CountOverflow)?;
    let context_subtree_hash_query_count = context_subtree_hash_query_count(subtree_leaf_count)?;
    payload_subtree_hash_query_count
        .checked_add(context_subtree_hash_query_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(LiteralBcsMerkleError::CountOverflow)
}

pub(super) fn literal_bcs_standard_tree_internal_node_count(
    payload_leaf_count: usize,
) -> Result<u64, LiteralBcsMerkleError> {
    let committed_tree_leaf_count = literal_bcs_committed_tree_leaf_count(payload_leaf_count)?;
    u64::try_from(
        committed_tree_leaf_count
            .checked_sub(1)
            .ok_or(LiteralBcsMerkleError::CountOverflow)?,
    )
    .map_err(|_| LiteralBcsMerkleError::CountOverflow)
}

/// Counts the binary-hash evaluations needed to verify one opening, excluding
/// derivation of the already-recomputed context bindings.
pub(super) fn literal_bcs_opening_hash_query_count(
    payload_leaf_count: usize,
) -> Result<u64, LiteralBcsMerkleError> {
    let subtree_leaf_count = literal_bcs_subtree_leaf_count(payload_leaf_count)?;
    context_subtree_hash_query_count(subtree_leaf_count)?
        .checked_add(u64::from(subtree_leaf_count.ilog2()))
        .and_then(|count| count.checked_add(1))
        .ok_or(LiteralBcsMerkleError::CountOverflow)
}

#[cfg(test)]
pub(super) fn literal_bcs_merkle_root_with_frontier(
    context: LiteralBcsTreeContext,
    payload_leaves: &[LiteralBcsMerkleNode],
) -> Result<LiteralBcsMerkleNode, LiteralBcsMerkleError> {
    let subtree_leaf_count = checked_subtree_leaf_count(context, payload_leaves)?;
    let context_root = context_subtree_root(context, payload_leaves.len(), subtree_leaf_count)?;
    let payload_root = complete_binary_tree_root(
        payload_leaves
            .iter()
            .copied()
            .chain((payload_leaves.len()..subtree_leaf_count).map(|_| payload_padding_leaf())),
        subtree_leaf_count,
    )?;
    Ok(literal_bcs_hash_pair(&context_root, &payload_root))
}

#[cfg(test)]
pub(super) fn verify_literal_bcs_merkle_opening(
    context: LiteralBcsTreeContext,
    payload_leaf_count: usize,
    payload_leaf: LiteralBcsMerkleNode,
    opening: &LiteralBcsMerkleOpening,
    expected_root: LiteralBcsMerkleNode,
) -> Result<(), LiteralBcsMerkleError> {
    let subtree_leaf_count = checked_message_geometry(context, payload_leaf_count)?.0;
    if opening.payload_leaf_ordinal >= payload_leaf_count {
        return Err(LiteralBcsMerkleError::InvalidPayloadLeafOrdinal);
    }
    validate_payload_leaf_padding(
        context,
        payload_leaf_count,
        opening.payload_leaf_ordinal,
        &payload_leaf,
    )?;
    let expected_path_length = subtree_leaf_count
        .ilog2()
        .checked_add(1)
        .ok_or(LiteralBcsMerkleError::CountOverflow)? as usize;
    if opening.authentication_path.len() != expected_path_length {
        return Err(LiteralBcsMerkleError::InvalidAuthenticationPathLength);
    }
    let expected_context_root =
        context_subtree_root(context, payload_leaf_count, subtree_leaf_count)?;
    if opening.authentication_path[expected_path_length - 1] != expected_context_root {
        return Err(LiteralBcsMerkleError::WrongContextSubtree);
    }

    let mut root = payload_leaf;
    let mut node_ordinal = subtree_leaf_count
        .checked_add(opening.payload_leaf_ordinal)
        .ok_or(LiteralBcsMerkleError::CountOverflow)?;
    for sibling in &opening.authentication_path {
        root = if node_ordinal.is_multiple_of(2) {
            literal_bcs_hash_pair(&root, sibling)
        } else {
            literal_bcs_hash_pair(sibling, &root)
        };
        node_ordinal /= 2;
    }
    if root != expected_root {
        return Err(LiteralBcsMerkleError::WrongRoot);
    }
    Ok(())
}

#[cfg(test)]
fn checked_subtree_leaf_count(
    context: LiteralBcsTreeContext,
    payload_leaves: &[LiteralBcsMerkleNode],
) -> Result<usize, LiteralBcsMerkleError> {
    let (subtree_leaf_count, _) = checked_message_geometry(context, payload_leaves.len())?;
    validate_payload_leaf_padding(
        context,
        payload_leaves.len(),
        payload_leaves
            .len()
            .checked_sub(1)
            .ok_or(LiteralBcsMerkleError::EmptyPayload)?,
        payload_leaves
            .last()
            .ok_or(LiteralBcsMerkleError::EmptyPayload)?,
    )?;
    Ok(subtree_leaf_count)
}

#[cfg(test)]
fn checked_message_geometry(
    context: LiteralBcsTreeContext,
    payload_leaf_count: usize,
) -> Result<(usize, usize), LiteralBcsMerkleError> {
    if payload_leaf_count == 0 {
        return Err(LiteralBcsMerkleError::EmptyPayload);
    }
    let payload_leaf_count_u64 =
        u64::try_from(payload_leaf_count).map_err(|_| LiteralBcsMerkleError::CountOverflow)?;
    let maximum_message_byte_length = payload_leaf_count_u64
        .checked_mul(LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH_U64)
        .ok_or(LiteralBcsMerkleError::CountOverflow)?;
    let complete_prefix_byte_length = payload_leaf_count_u64
        .checked_sub(1)
        .and_then(|count| count.checked_mul(LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH_U64))
        .ok_or(LiteralBcsMerkleError::CountOverflow)?;
    if context.message_byte_length <= complete_prefix_byte_length
        || context.message_byte_length > maximum_message_byte_length
    {
        return Err(LiteralBcsMerkleError::InvalidMessageByteLength);
    }
    let final_payload_byte_length = usize::try_from(
        context
            .message_byte_length
            .checked_sub(complete_prefix_byte_length)
            .ok_or(LiteralBcsMerkleError::CountOverflow)?,
    )
    .map_err(|_| LiteralBcsMerkleError::CountOverflow)?;
    Ok((
        literal_bcs_subtree_leaf_count(payload_leaf_count)?,
        final_payload_byte_length,
    ))
}

#[cfg(test)]
fn validate_payload_leaf_padding(
    context: LiteralBcsTreeContext,
    payload_leaf_count: usize,
    payload_leaf_ordinal: usize,
    payload_leaf: &LiteralBcsMerkleNode,
) -> Result<(), LiteralBcsMerkleError> {
    if payload_leaf_ordinal >= payload_leaf_count {
        return Err(LiteralBcsMerkleError::InvalidPayloadLeafOrdinal);
    }
    if payload_leaf_ordinal
        != payload_leaf_count
            .checked_sub(1)
            .ok_or(LiteralBcsMerkleError::EmptyPayload)?
    {
        return Ok(());
    }
    let (_, final_payload_byte_length) = checked_message_geometry(context, payload_leaf_count)?;
    if payload_leaf[final_payload_byte_length..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(LiteralBcsMerkleError::NonCanonicalPayloadPadding);
    }
    Ok(())
}

#[cfg(test)]
fn canonical_tree_leaves(
    context: LiteralBcsTreeContext,
    payload_leaves: &[LiteralBcsMerkleNode],
    subtree_leaf_count: usize,
) -> Result<Vec<LiteralBcsMerkleNode>, LiteralBcsMerkleError> {
    if payload_leaves.is_empty()
        || subtree_leaf_count < payload_leaves.len()
        || subtree_leaf_count < LITERAL_BCS_CONTEXT_REQUIRED_LEAF_COUNT
        || !subtree_leaf_count.is_power_of_two()
    {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    let total_leaf_count = subtree_leaf_count
        .checked_mul(2)
        .ok_or(LiteralBcsMerkleError::CountOverflow)?;
    let mut leaves = Vec::with_capacity(total_leaf_count);
    leaves.push(context_descriptor(
        context,
        payload_leaves.len(),
        subtree_leaf_count,
    )?);
    leaves.push(context.construction_identity);
    leaves.push(context.application_binding);
    leaves.extend(
        (LITERAL_BCS_CONTEXT_REQUIRED_LEAF_COUNT..subtree_leaf_count)
            .map(|_| context_padding_leaf()),
    );
    leaves.extend_from_slice(payload_leaves);
    leaves.extend((payload_leaves.len()..subtree_leaf_count).map(|_| payload_padding_leaf()));
    if leaves.len() != total_leaf_count {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    Ok(leaves)
}

#[cfg(test)]
fn context_subtree_root(
    context: LiteralBcsTreeContext,
    payload_leaf_count: usize,
    subtree_leaf_count: usize,
) -> Result<LiteralBcsMerkleNode, LiteralBcsMerkleError> {
    let expected_subtree_leaf_count = checked_message_geometry(context, payload_leaf_count)?.0;
    if subtree_leaf_count != expected_subtree_leaf_count {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    let descriptor = context_descriptor(context, payload_leaf_count, subtree_leaf_count)?;
    let descriptor_and_construction =
        literal_bcs_hash_pair(&descriptor, &context.construction_identity);
    let application_and_padding =
        literal_bcs_hash_pair(&context.application_binding, &context_padding_leaf());
    let mut context_root =
        literal_bcs_hash_pair(&descriptor_and_construction, &application_and_padding);
    if subtree_leaf_count == 4 {
        return Ok(context_root);
    }

    let mut uniform_padding_root = context_padding_leaf();
    for _ in 0..2 {
        uniform_padding_root = literal_bcs_hash_pair(&uniform_padding_root, &uniform_padding_root);
    }
    let mut represented_leaf_count = 4_usize;
    while represented_leaf_count < subtree_leaf_count {
        context_root = literal_bcs_hash_pair(&context_root, &uniform_padding_root);
        represented_leaf_count = represented_leaf_count
            .checked_mul(2)
            .ok_or(LiteralBcsMerkleError::CountOverflow)?;
        if represented_leaf_count < subtree_leaf_count {
            uniform_padding_root =
                literal_bcs_hash_pair(&uniform_padding_root, &uniform_padding_root);
        }
    }
    Ok(context_root)
}

fn context_subtree_hash_query_count(
    subtree_leaf_count: usize,
) -> Result<u64, LiteralBcsMerkleError> {
    if subtree_leaf_count < 4 || !subtree_leaf_count.is_power_of_two() {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    if subtree_leaf_count == 4 {
        return Ok(3);
    }
    u64::from(subtree_leaf_count.ilog2())
        .checked_mul(2)
        .ok_or(LiteralBcsMerkleError::CountOverflow)
}

#[cfg(test)]
fn context_descriptor(
    context: LiteralBcsTreeContext,
    payload_leaf_count: usize,
    subtree_leaf_count: usize,
) -> Result<LiteralBcsMerkleNode, LiteralBcsMerkleError> {
    let payload_leaf_count_u64 =
        u64::try_from(payload_leaf_count).map_err(|_| LiteralBcsMerkleError::CountOverflow)?;
    let subtree_leaf_count_u64 =
        u64::try_from(subtree_leaf_count).map_err(|_| LiteralBcsMerkleError::CountOverflow)?;
    let (tree_role, role_ordinal) = context.role.encoding();
    let mut descriptor = [0_u8; LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH];
    descriptor[..8].copy_from_slice(b"SLXBCSM1");
    descriptor[8..10].copy_from_slice(&LITERAL_BCS_MERKLE_ENCODING_VERSION.to_le_bytes());
    descriptor[10..12].copy_from_slice(&tree_role.to_le_bytes());
    descriptor[12..16].copy_from_slice(&role_ordinal.to_le_bytes());
    descriptor[16..24].copy_from_slice(&context.message_byte_length.to_le_bytes());
    descriptor[24..32].copy_from_slice(&payload_leaf_count_u64.to_le_bytes());
    descriptor[32..40].copy_from_slice(&subtree_leaf_count_u64.to_le_bytes());
    Ok(descriptor)
}

#[cfg(test)]
fn context_padding_leaf() -> LiteralBcsMerkleNode {
    let mut leaf = [0_u8; LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH];
    leaf[..8].copy_from_slice(b"SLXBCSM1");
    leaf[8] = 1;
    leaf
}

#[cfg(test)]
fn payload_padding_leaf() -> LiteralBcsMerkleNode {
    let mut leaf = [0_u8; LITERAL_BCS_MERKLE_SYMBOL_BYTE_LENGTH];
    leaf[..8].copy_from_slice(b"SLXBCSM1");
    leaf[8] = 2;
    leaf
}

#[cfg(test)]
fn complete_binary_tree_root(
    leaves: impl Iterator<Item = LiteralBcsMerkleNode>,
    expected_leaf_count: usize,
) -> Result<LiteralBcsMerkleNode, LiteralBcsMerkleError> {
    if expected_leaf_count == 0 || !expected_leaf_count.is_power_of_two() {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    let mut frontier = vec![None; expected_leaf_count.ilog2() as usize + 1];
    let mut observed_leaf_count = 0_usize;
    for leaf in leaves {
        observed_leaf_count = observed_leaf_count
            .checked_add(1)
            .ok_or(LiteralBcsMerkleError::CountOverflow)?;
        if observed_leaf_count > expected_leaf_count {
            return Err(LiteralBcsMerkleError::InvalidLeafCount);
        }
        let mut node = leaf;
        let mut level_ordinal = 0_usize;
        loop {
            let slot = frontier
                .get_mut(level_ordinal)
                .ok_or(LiteralBcsMerkleError::InvalidLeafCount)?;
            if let Some(left) = slot.take() {
                node = literal_bcs_hash_pair(&left, &node);
                level_ordinal = level_ordinal
                    .checked_add(1)
                    .ok_or(LiteralBcsMerkleError::CountOverflow)?;
            } else {
                *slot = Some(node);
                break;
            }
        }
    }
    if observed_leaf_count != expected_leaf_count {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    let root_level = expected_leaf_count.ilog2() as usize;
    if frontier
        .iter()
        .enumerate()
        .any(|(level_ordinal, node)| level_ordinal != root_level && node.is_some())
    {
        return Err(LiteralBcsMerkleError::InvalidLeafCount);
    }
    frontier[root_level]
        .take()
        .ok_or(LiteralBcsMerkleError::InvalidLeafCount)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(role: LiteralBcsTreeRole, message_byte_length: u64) -> LiteralBcsTreeContext {
        LiteralBcsTreeContext {
            role,
            message_byte_length,
            construction_identity: [0x41; 64],
            application_binding: [0x52; 64],
        }
    }

    fn canonical_message(byte_length: usize) -> Vec<u8> {
        (0..byte_length)
            .map(|byte_ordinal| (byte_ordinal as u8).wrapping_mul(29).wrapping_add(7))
            .collect()
    }

    #[test]
    fn pair_hash_is_exactly_one_scalar_shake256_query() {
        let left = [0x31; 64];
        let right = [0xa7; 64];
        let mut scalar_state = Shake256::default();
        scalar_state.update(&left);
        scalar_state.update(&right);
        let mut expected = [0_u8; 64];
        scalar_state.finalize_xof().read(&mut expected);
        assert_eq!(literal_bcs_hash_pair(&left, &right), expected);
    }

    #[test]
    fn one_symbol_commitment_matches_the_fixed_context_binding_golden() {
        let message = canonical_message(47);
        let payload =
            literal_bcs_payload_symbols(&message).expect("the canonical message has one symbol");
        let context = context(
            LiteralBcsTreeRole::CanonicalProverMessage {
                source_operation_ordinal: 37,
            },
            47,
        );
        let tree = LiteralBcsMerkleTree::new(context, &payload)
            .expect("the one-symbol commitment derives");
        assert_eq!(
            tree.root(),
            [
                0xed, 0x87, 0x97, 0x9c, 0xd9, 0xba, 0x01, 0x23, 0x8a, 0xba, 0x72, 0x47, 0x38, 0xff,
                0xac, 0xc8, 0xf8, 0x8a, 0x43, 0x52, 0xc9, 0x1b, 0xe7, 0x37, 0xb1, 0x70, 0x28, 0x7a,
                0xb1, 0x02, 0x0b, 0x0f, 0x1f, 0xaa, 0xdf, 0x9d, 0x4f, 0xa6, 0x97, 0x08, 0x5c, 0x5c,
                0xc8, 0x63, 0x12, 0x3d, 0x89, 0x91, 0x3c, 0x63, 0x04, 0xb0, 0xd0, 0xb5, 0xf4, 0x94,
                0xfb, 0x10, 0x0a, 0x8d, 0xe1, 0x33, 0x08, 0x01,
            ],
        );
        assert_eq!(
            literal_bcs_commitment_hash_query_count(payload.len())
                .expect("the one-symbol hash count derives"),
            7,
        );
        let opening = tree.open(0).expect("the sole symbol opens");
        assert_eq!(opening.authentication_path.len(), 3);
        verify_literal_bcs_merkle_opening(
            context,
            payload.len(),
            payload[0],
            &opening,
            tree.root(),
        )
        .expect("the one-symbol commitment verifies");
    }

    #[test]
    fn canonical_symbolization_has_one_zero_padded_final_symbol() {
        for message_byte_length in [1, 63, 64, 65, 127, 128, 129] {
            let message = canonical_message(message_byte_length);
            let symbols = literal_bcs_payload_symbols(&message)
                .expect("every nonempty canonical message has symbols");
            assert_eq!(symbols.len(), message_byte_length.div_ceil(64));
            let reconstructed = symbols
                .iter()
                .flat_map(|symbol| symbol.iter().copied())
                .take(message_byte_length)
                .collect::<Vec<_>>();
            assert_eq!(reconstructed, message);
            let final_payload_byte_length = (message_byte_length - 1) % 64 + 1;
            assert!(
                symbols.last().expect("the symbol list is nonempty")[final_payload_byte_length..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        assert_eq!(
            literal_bcs_payload_symbols(&[]),
            Err(LiteralBcsMerkleError::EmptyPayload),
        );
    }

    #[test]
    fn full_tree_frontier_and_all_payload_openings_are_identical() {
        for (
            payload_leaf_count,
            expected_subtree_leaf_count,
            expected_commitment_hash_query_count,
            expected_opening_hash_query_count,
        ) in [
            (1, 4, 7, 6),
            (2, 4, 7, 6),
            (3, 4, 7, 6),
            (4, 4, 7, 6),
            (5, 8, 14, 10),
            (8, 8, 14, 10),
            (9, 16, 24, 13),
            (17, 32, 42, 16),
        ] {
            let message_byte_length = payload_leaf_count * 64 - 17;
            let payload = literal_bcs_payload_symbols(&canonical_message(message_byte_length))
                .expect("the canonical message has symbols");
            assert_eq!(payload.len(), payload_leaf_count);
            let context = context(
                LiteralBcsTreeRole::CanonicalProverMessage {
                    source_operation_ordinal: 37,
                },
                u64::try_from(message_byte_length).expect("test length fits u64"),
            );
            let tree = LiteralBcsMerkleTree::new(context, &payload)
                .expect("the fixed geometry tree derives");
            assert_eq!(
                literal_bcs_merkle_root_with_frontier(context, &payload)
                    .expect("the bounded frontier derives the same root"),
                tree.root(),
            );
            assert_eq!(tree.context(), context);
            assert_eq!(tree.subtree_leaf_count(), expected_subtree_leaf_count);
            assert_eq!(
                literal_bcs_commitment_hash_query_count(payload_leaf_count)
                    .expect("the commitment hash count derives"),
                expected_commitment_hash_query_count,
            );
            assert_eq!(
                literal_bcs_opening_hash_query_count(payload_leaf_count)
                    .expect("the opening hash count derives"),
                expected_opening_hash_query_count,
            );
            assert_eq!(
                literal_bcs_standard_tree_internal_node_count(payload_leaf_count)
                    .expect("the standard-tree node count derives"),
                u64::try_from(expected_subtree_leaf_count * 2 - 1).expect("test geometry fits u64"),
            );
            for (payload_leaf_ordinal, payload_leaf) in payload.iter().copied().enumerate() {
                let opening = tree
                    .open(payload_leaf_ordinal)
                    .expect("every payload leaf opens");
                assert_eq!(
                    opening.authentication_path.len(),
                    (tree.subtree_leaf_count() * 2).ilog2() as usize,
                );
                verify_literal_bcs_merkle_opening(
                    context,
                    payload_leaf_count,
                    payload_leaf,
                    &opening,
                    tree.root(),
                )
                .expect("every authentic payload opening verifies");
            }
        }
    }

    #[test]
    fn every_context_payload_path_index_and_root_mutation_is_rejected() {
        let message_byte_length = 5 * 64 - 9;
        let payload = literal_bcs_payload_symbols(&canonical_message(message_byte_length))
            .expect("the canonical message has symbols");
        let context = context(
            LiteralBcsTreeRole::Aggregate,
            u64::try_from(message_byte_length).expect("test length fits u64"),
        );
        let tree = LiteralBcsMerkleTree::new(context, &payload).expect("the tree derives");
        let opening = tree.open(3).expect("the selected leaf opens");

        let mut changed_role = context;
        changed_role.role = LiteralBcsTreeRole::WhirRound { round_ordinal: 0 };
        assert!(
            verify_literal_bcs_merkle_opening(
                changed_role,
                payload.len(),
                payload[3],
                &opening,
                tree.root(),
            )
            .is_err(),
        );
        let mut changed_length = context;
        changed_length.message_byte_length += 1;
        assert!(
            verify_literal_bcs_merkle_opening(
                changed_length,
                payload.len(),
                payload[3],
                &opening,
                tree.root(),
            )
            .is_err(),
        );
        let mut changed_construction = context;
        changed_construction.construction_identity[0] ^= 1;
        assert!(
            verify_literal_bcs_merkle_opening(
                changed_construction,
                payload.len(),
                payload[3],
                &opening,
                tree.root(),
            )
            .is_err(),
        );
        let mut changed_application = context;
        changed_application.application_binding[0] ^= 1;
        assert!(
            verify_literal_bcs_merkle_opening(
                changed_application,
                payload.len(),
                payload[3],
                &opening,
                tree.root(),
            )
            .is_err(),
        );
        let mut changed_payload_leaf = payload[3];
        changed_payload_leaf[0] ^= 1;
        assert!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                changed_payload_leaf,
                &opening,
                tree.root(),
            )
            .is_err(),
        );
        let mut changed_path = opening.clone();
        changed_path.authentication_path[0][0] ^= 1;
        assert!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                payload[3],
                &changed_path,
                tree.root(),
            )
            .is_err(),
        );
        let mut changed_context_sibling = opening.clone();
        changed_context_sibling
            .authentication_path
            .last_mut()
            .expect("every payload path carries the context root")[0] ^= 1;
        assert_eq!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                payload[3],
                &changed_context_sibling,
                tree.root(),
            ),
            Err(LiteralBcsMerkleError::WrongContextSubtree),
        );
        let mut wrong_ordinal = opening.clone();
        wrong_ordinal.payload_leaf_ordinal = 4;
        assert!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                payload[3],
                &wrong_ordinal,
                tree.root(),
            )
            .is_err(),
        );
        let mut wrong_root = tree.root();
        wrong_root[0] ^= 1;
        assert_eq!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                payload[3],
                &opening,
                wrong_root,
            ),
            Err(LiteralBcsMerkleError::WrongRoot),
        );
    }

    #[test]
    fn malformed_geometry_padding_paths_and_indices_refuse() {
        let one_leaf = literal_bcs_payload_symbols(&canonical_message(64))
            .expect("the canonical message has one symbol");
        assert_eq!(
            LiteralBcsMerkleTree::new(context(LiteralBcsTreeRole::RelationBase, 0), &one_leaf),
            Err(LiteralBcsMerkleError::InvalidMessageByteLength),
        );
        assert_eq!(
            LiteralBcsMerkleTree::new(context(LiteralBcsTreeRole::RelationBase, 65), &one_leaf),
            Err(LiteralBcsMerkleError::InvalidMessageByteLength),
        );
        assert_eq!(
            LiteralBcsMerkleTree::new(context(LiteralBcsTreeRole::RelationBase, 1), &[]),
            Err(LiteralBcsMerkleError::EmptyPayload),
        );
        let tree =
            LiteralBcsMerkleTree::new(context(LiteralBcsTreeRole::RelationBase, 64), &one_leaf)
                .expect("one payload symbol is valid");
        assert_eq!(
            tree.open(1),
            Err(LiteralBcsMerkleError::InvalidPayloadLeafOrdinal),
        );

        let message = canonical_message(79);
        let mut payload =
            literal_bcs_payload_symbols(&message).expect("the partial final symbol is canonical");
        let context = context(
            LiteralBcsTreeRole::OpeningBatchMask,
            u64::try_from(message.len()).expect("test length fits u64"),
        );
        let tree = LiteralBcsMerkleTree::new(context, &payload).expect("the tree derives");
        let opening = tree.open(1).expect("the final symbol opens");
        payload[1][63] = 1;
        assert_eq!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                payload[1],
                &opening,
                tree.root(),
            ),
            Err(LiteralBcsMerkleError::NonCanonicalPayloadPadding),
        );
        assert_eq!(
            LiteralBcsMerkleTree::new(context, &payload),
            Err(LiteralBcsMerkleError::NonCanonicalPayloadPadding),
        );

        let mut short_path = opening;
        short_path.authentication_path.pop();
        assert_eq!(
            verify_literal_bcs_merkle_opening(
                context,
                payload.len(),
                literal_bcs_payload_symbols(&message).expect("the canonical message has symbols")
                    [1],
                &short_path,
                tree.root(),
            ),
            Err(LiteralBcsMerkleError::InvalidAuthenticationPathLength),
        );
        let canonical_payload =
            literal_bcs_payload_symbols(&message).expect("the canonical message has symbols");
        let mut long_path = tree.open(1).expect("the final symbol opens");
        long_path.authentication_path.push([0_u8; 64]);
        assert_eq!(
            verify_literal_bcs_merkle_opening(
                context,
                canonical_payload.len(),
                canonical_payload[1],
                &long_path,
                tree.root(),
            ),
            Err(LiteralBcsMerkleError::InvalidAuthenticationPathLength),
        );
        assert_eq!(
            literal_bcs_subtree_leaf_count(usize::MAX),
            Err(LiteralBcsMerkleError::CountOverflow),
        );
    }
}
