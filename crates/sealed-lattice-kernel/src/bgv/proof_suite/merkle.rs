use std::collections::{BTreeMap, BTreeSet};

use crate::{
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    hashing::hash_framed_parts_512 as hash512,
};

use super::{
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofChallengeExtensionElement,
};

const MERKLE_LEAF_DOMAIN: &str = "sealed-lattice/proof/merkle/leaf/v1";
const MERKLE_NODE_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";
const PROOF_TREE_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/tree-context/v1";
const PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/phase-pair-leaf/v1";

const PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x0103;
const PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x0104;
const PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER: u16 = 0x0105;
const PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER: u16 = 0x0106;
const SCHEMA_VERSION: u16 = 1;
const SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;

pub(crate) fn leaf_hash(
    application_statement_schema_identifier: u16,
    tree_ordinal: u16,
    leaf_index: usize,
    canonical_leaf_row: &[u8],
) -> [u8; 64] {
    hash512(
        MERKLE_LEAF_DOMAIN,
        &[
            &application_statement_schema_identifier.to_le_bytes(),
            &tree_ordinal.to_le_bytes(),
            &u64::try_from(leaf_index)
                .expect("a usize leaf index fits the canonical u64 field")
                .to_le_bytes(),
            canonical_leaf_row,
        ],
    )
}

pub(crate) fn node_hash(
    application_statement_schema_identifier: u16,
    tree_ordinal: u16,
    level_ordinal: u32,
    node_index: usize,
    left: [u8; 64],
    right: [u8; 64],
) -> [u8; 64] {
    hash512(
        MERKLE_NODE_DOMAIN,
        &[
            &application_statement_schema_identifier.to_le_bytes(),
            &tree_ordinal.to_le_bytes(),
            &level_ordinal.to_le_bytes(),
            &u64::try_from(node_index)
                .expect("a usize node index fits the canonical u64 field")
                .to_le_bytes(),
            &left,
            &right,
        ],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofMerkleError {
    CanonicalEncoding,
    InvalidContext,
    InvalidLeaf,
    InvalidNode,
    InvalidOpening,
    DuplicateIndex,
    NonCanonicalOrder,
    CountOverflow,
    RootMismatch,
}

fn canonical_encoding_error<T>(_: T) -> ProofMerkleError {
    ProofMerkleError::CanonicalEncoding
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ProofTreeRole {
    BaseOracle = 1,
    AuxiliaryOracle = 2,
    QuotientComponent = 3,
    OpeningBatchMask = 4,
    NonterminalFriLayer = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ProofLeafVisibility {
    Public = 1,
    SecretBearing = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofMerkleTreeContext {
    suite_id: [u8; 64],
    proof_header_hash: [u8; 64],
    application_statement_schema_identifier: u16,
    proof_field_index: u16,
    tree_role: ProofTreeRole,
    tree_ordinal: u16,
    domain_size: u64,
    row_width: u32,
    leaf_visibility: ProofLeafVisibility,
}

impl ProofMerkleTreeContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        suite_id: [u8; 64],
        proof_header_hash: [u8; 64],
        application_statement_schema_identifier: u16,
        proof_field_index: u16,
        tree_role: ProofTreeRole,
        tree_ordinal: u16,
        domain_size: u64,
        row_width: u32,
        leaf_visibility: ProofLeafVisibility,
    ) -> Result<Self, ProofMerkleError> {
        if domain_size < 2 || !domain_size.is_power_of_two() || row_width == 0 {
            return Err(ProofMerkleError::InvalidContext);
        }
        if matches!(
            tree_role,
            ProofTreeRole::QuotientComponent
                | ProofTreeRole::OpeningBatchMask
                | ProofTreeRole::NonterminalFriLayer
        ) && row_width != 1
        {
            return Err(ProofMerkleError::InvalidContext);
        }
        if tree_role == ProofTreeRole::OpeningBatchMask
            && (tree_ordinal != 0 || leaf_visibility != ProofLeafVisibility::SecretBearing)
        {
            return Err(ProofMerkleError::InvalidContext);
        }
        let context = Self {
            suite_id,
            proof_header_hash,
            application_statement_schema_identifier,
            proof_field_index,
            tree_role,
            tree_ordinal,
            domain_size,
            row_width,
            leaf_visibility,
        };
        context.leaf_count()?;
        Ok(context)
    }

    pub(crate) fn leaf_count(&self) -> Result<usize, ProofMerkleError> {
        usize::try_from(self.domain_size / 2).map_err(|_| ProofMerkleError::CountOverflow)
    }

    pub(crate) const fn row_width(&self) -> u32 {
        self.row_width
    }

    pub(crate) const fn leaf_visibility(&self) -> ProofLeafVisibility {
        self.leaf_visibility
    }

    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.suite_id),
                CanonicalItem::hash512(self.proof_header_hash),
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::unsigned16(self.proof_field_index),
                CanonicalItem::unsigned16(self.tree_role as u16),
                CanonicalItem::unsigned16(self.tree_ordinal),
                CanonicalItem::unsigned64(self.domain_size),
                CanonicalItem::unsigned32(self.row_width),
                CanonicalItem::unsigned16(self.leaf_visibility as u16),
            ],
        )
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, ProofMerkleError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }

    pub(crate) fn context_hash(&self) -> Result<[u8; 64], ProofMerkleError> {
        Ok(hash_foundation_tuple_512(
            PROOF_TREE_CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)
                .map_err(canonical_encoding_error)?],
        )
        .map_err(canonical_encoding_error)?
        .into_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofTreeValue {
    Base(ProofBaseFieldElement),
    Extension(ProofChallengeExtensionElement),
}

impl ProofTreeValue {
    fn item_type(self) -> CanonicalItemType {
        match self {
            Self::Base(_) => CanonicalItemType::FieldElement,
            Self::Extension(_) => CanonicalItemType::ChallengeExtensionElement,
        }
    }

    fn canonical_item(self) -> Result<CanonicalItem, ProofMerkleError> {
        match self {
            Self::Base(value) => CanonicalItem::from_canonical_bytes(
                CanonicalItemType::FieldElement,
                value.canonical().to_le_bytes().to_vec(),
                &CanonicalDecodeLimits::default(),
            )
            .map_err(canonical_encoding_error),
            Self::Extension(value) => {
                let mut bytes = Vec::with_capacity(PROOF_CHALLENGE_EXTENSION_DEGREE * 8);
                for coordinate in value.canonical_coordinates() {
                    bytes.extend_from_slice(&coordinate.to_le_bytes());
                }
                CanonicalItem::from_canonical_bytes(
                    CanonicalItemType::ChallengeExtensionElement,
                    bytes,
                    &CanonicalDecodeLimits::default(),
                )
                .map_err(canonical_encoding_error)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofOraclePhasePairLeaf {
    proof_tree_context_hash: [u8; 64],
    leaf_index: u64,
    leaf_visibility: ProofLeafVisibility,
    secret_salt: Option<[u8; SECRET_LEAF_SALT_BYTE_LENGTH]>,
    first_point_values: Vec<ProofTreeValue>,
    opposite_point_values: Vec<ProofTreeValue>,
}

impl ProofOraclePhasePairLeaf {
    pub(crate) fn new(
        context: &ProofMerkleTreeContext,
        leaf_index: u64,
        secret_salt: Option<[u8; SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Vec<ProofTreeValue>,
        opposite_point_values: Vec<ProofTreeValue>,
    ) -> Result<Self, ProofMerkleError> {
        if leaf_index >= context.domain_size / 2
            || first_point_values.len()
                != usize::try_from(context.row_width)
                    .map_err(|_| ProofMerkleError::CountOverflow)?
            || opposite_point_values.len() != first_point_values.len()
            || first_point_values.is_empty()
            || secret_salt.is_some()
                != (context.leaf_visibility == ProofLeafVisibility::SecretBearing)
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        let expected_type = first_point_values[0].item_type();
        if first_point_values
            .iter()
            .chain(&opposite_point_values)
            .any(|value| value.item_type() != expected_type)
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        if matches!(
            context.tree_role,
            ProofTreeRole::QuotientComponent
                | ProofTreeRole::OpeningBatchMask
                | ProofTreeRole::NonterminalFriLayer
        ) && expected_type != CanonicalItemType::ChallengeExtensionElement
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        Ok(Self {
            proof_tree_context_hash: context.context_hash()?,
            leaf_index,
            leaf_visibility: context.leaf_visibility,
            secret_salt,
            first_point_values,
            opposite_point_values,
        })
    }

    pub(crate) const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, ProofMerkleError> {
        let first_values = canonical_tree_value_list(&self.first_point_values)?;
        let opposite_values = canonical_tree_value_list(&self.opposite_point_values)?;
        let mut items = Vec::with_capacity(if self.secret_salt.is_some() { 6 } else { 5 });
        items.push(CanonicalItem::hash512(self.proof_tree_context_hash));
        items.push(CanonicalItem::unsigned64(self.leaf_index));
        items.push(CanonicalItem::unsigned16(self.leaf_visibility as u16));
        if let Some(salt) = self.secret_salt {
            items.push(CanonicalItem::fixed_bytes(salt).map_err(canonical_encoding_error)?);
        }
        items.push(first_values);
        items.push(opposite_values);
        Ok(CanonicalTuple::new(
            PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            items,
        ))
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, ProofMerkleError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }

    pub(crate) fn digest(&self) -> Result<[u8; 64], ProofMerkleError> {
        Ok(hash_foundation_tuple_512(
            PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)
                .map_err(canonical_encoding_error)?],
        )
        .map_err(canonical_encoding_error)?
        .into_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProofAuthenticationNode {
    level: u32,
    node_index: u64,
    node_digest: [u8; 64],
}

impl ProofAuthenticationNode {
    pub(crate) const fn new(level: u32, node_index: u64, node_digest: [u8; 64]) -> Self {
        Self {
            level,
            node_index,
            node_digest,
        }
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.level),
                CanonicalItem::unsigned64(self.node_index),
                CanonicalItem::hash512(self.node_digest),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalProofMerkleTree {
    context: ProofMerkleTreeContext,
    levels: Vec<Vec<[u8; 64]>>,
}

impl CanonicalProofMerkleTree {
    pub(crate) fn from_phase_pair_leaves(
        context: ProofMerkleTreeContext,
        leaves: &[ProofOraclePhasePairLeaf],
    ) -> Result<Self, ProofMerkleError> {
        if leaves.len() != context.leaf_count()? {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        let context_hash = context.context_hash()?;
        let mut leaf_digests = Vec::new();
        leaf_digests
            .try_reserve_exact(leaves.len())
            .map_err(|_| ProofMerkleError::CountOverflow)?;
        for (expected_index, leaf) in leaves.iter().enumerate() {
            if leaf.proof_tree_context_hash != context_hash
                || leaf.leaf_index
                    != u64::try_from(expected_index).map_err(|_| ProofMerkleError::CountOverflow)?
                || leaf.leaf_visibility != context.leaf_visibility
            {
                return Err(ProofMerkleError::InvalidLeaf);
            }
            leaf_digests.push(leaf.digest()?);
        }
        let levels = build_merkle_levels(&context_hash, leaf_digests)?;
        Ok(Self { context, levels })
    }

    pub(crate) fn root(&self) -> [u8; 64] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("a validated Merkle tree has one root")
    }

    pub(crate) fn authentication_frontier(
        &self,
        sorted_unique_leaf_indexes: &[u64],
    ) -> Result<Vec<ProofAuthenticationNode>, ProofMerkleError> {
        validate_sorted_unique_leaf_indexes(
            sorted_unique_leaf_indexes,
            self.context.leaf_count()?,
        )?;
        let mut required = sorted_unique_leaf_indexes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut frontier = Vec::new();
        for level in 0..self.levels.len() - 1 {
            let mut next = BTreeSet::new();
            let mut processed = BTreeSet::new();
            for index in required.iter().copied() {
                if !processed.insert(index) {
                    continue;
                }
                let sibling = index ^ 1;
                if required.contains(&sibling) {
                    processed.insert(sibling);
                } else {
                    let sibling_index =
                        usize::try_from(sibling).map_err(|_| ProofMerkleError::CountOverflow)?;
                    frontier.push(ProofAuthenticationNode::new(
                        u32::try_from(level).map_err(|_| ProofMerkleError::CountOverflow)?,
                        sibling,
                        *self.levels[level]
                            .get(sibling_index)
                            .ok_or(ProofMerkleError::InvalidOpening)?,
                    ));
                }
                next.insert(index / 2);
            }
            required = next;
        }
        frontier.sort();
        Ok(frontier)
    }
}

pub(crate) fn verify_authentication_frontier(
    context: &ProofMerkleTreeContext,
    sorted_unique_opened_leaves: &[(u64, [u8; 64])],
    frontier: &[ProofAuthenticationNode],
    expected_root: [u8; 64],
) -> Result<(), ProofMerkleError> {
    let leaf_indexes = sorted_unique_opened_leaves
        .iter()
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    validate_sorted_unique_leaf_indexes(&leaf_indexes, context.leaf_count()?)?;
    if !frontier.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ProofMerkleError::NonCanonicalOrder);
    }
    let context_hash = context.context_hash()?;
    let mut current = sorted_unique_opened_leaves
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    let mut frontier_offset = 0_usize;
    let tree_height = context.leaf_count()?.trailing_zeros();
    for level in 0..tree_height {
        let mut next = BTreeMap::new();
        let mut processed = BTreeSet::new();
        let indexes = current.keys().copied().collect::<Vec<_>>();
        for index in indexes {
            if !processed.insert(index) {
                continue;
            }
            let sibling_index = index ^ 1;
            let sibling_digest = if let Some(digest) = current.get(&sibling_index).copied() {
                processed.insert(sibling_index);
                digest
            } else {
                let expected = ProofAuthenticationNode {
                    level,
                    node_index: sibling_index,
                    node_digest: [0_u8; 64],
                };
                let supplied = frontier
                    .get(frontier_offset)
                    .ok_or(ProofMerkleError::InvalidOpening)?;
                if supplied.level != expected.level || supplied.node_index != expected.node_index {
                    return Err(ProofMerkleError::InvalidOpening);
                }
                frontier_offset += 1;
                supplied.node_digest
            };
            let own_digest = *current
                .get(&index)
                .ok_or(ProofMerkleError::InvalidOpening)?;
            let (left, right) = if index & 1 == 0 {
                (own_digest, sibling_digest)
            } else {
                (sibling_digest, own_digest)
            };
            let parent_index = index / 2;
            let parent_digest =
                proof_merkle_node_digest(context_hash, level + 1, parent_index, left, right)?;
            if next.insert(parent_index, parent_digest).is_some() {
                return Err(ProofMerkleError::InvalidOpening);
            }
        }
        current = next;
    }
    if frontier_offset != frontier.len()
        || current.len() != 1
        || current.get(&0).copied() != Some(expected_root)
    {
        return Err(ProofMerkleError::RootMismatch);
    }
    Ok(())
}

fn canonical_tree_value_list(values: &[ProofTreeValue]) -> Result<CanonicalItem, ProofMerkleError> {
    let first = values.first().ok_or(ProofMerkleError::InvalidLeaf)?;
    let item_type = first.item_type();
    if values.iter().any(|value| value.item_type() != item_type) {
        return Err(ProofMerkleError::InvalidLeaf);
    }
    let items = values
        .iter()
        .copied()
        .map(ProofTreeValue::canonical_item)
        .collect::<Result<Vec<_>, _>>()?;
    CanonicalItem::homogeneous_list(item_type, &items).map_err(canonical_encoding_error)
}

fn build_merkle_levels(
    context_hash: &[u8; 64],
    leaf_digests: Vec<[u8; 64]>,
) -> Result<Vec<Vec<[u8; 64]>>, ProofMerkleError> {
    if leaf_digests.is_empty() || !leaf_digests.len().is_power_of_two() {
        return Err(ProofMerkleError::InvalidLeaf);
    }
    let mut levels = vec![leaf_digests];
    while levels.last().map_or(0, Vec::len) > 1 {
        let current = levels.last().ok_or(ProofMerkleError::InvalidNode)?;
        let level = u32::try_from(levels.len()).map_err(|_| ProofMerkleError::CountOverflow)?;
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(current.len() / 2)
            .map_err(|_| ProofMerkleError::CountOverflow)?;
        for (parent_index, pair) in current.chunks_exact(2).enumerate() {
            parents.push(proof_merkle_node_digest(
                *context_hash,
                level,
                u64::try_from(parent_index).map_err(|_| ProofMerkleError::CountOverflow)?,
                pair[0],
                pair[1],
            )?);
        }
        levels.push(parents);
    }
    Ok(levels)
}

fn proof_merkle_node_digest(
    context_hash: [u8; 64],
    level: u32,
    node_index: u64,
    left_child_digest: [u8; 64],
    right_child_digest: [u8; 64],
) -> Result<[u8; 64], ProofMerkleError> {
    if level == 0 {
        return Err(ProofMerkleError::InvalidNode);
    }
    let canonical_bytes = CanonicalTuple::new(
        PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(context_hash),
            CanonicalItem::unsigned32(level),
            CanonicalItem::unsigned64(node_index),
            CanonicalItem::hash512(left_child_digest),
            CanonicalItem::hash512(right_child_digest),
        ],
    )
    .encode()
    .map_err(canonical_encoding_error)?;
    Ok(hash_foundation_tuple_512(
        MERKLE_NODE_DOMAIN,
        &[CanonicalItem::variable_bytes(canonical_bytes).map_err(canonical_encoding_error)?],
    )
    .map_err(canonical_encoding_error)?
    .into_bytes())
}

fn validate_sorted_unique_leaf_indexes(
    indexes: &[u64],
    leaf_count: usize,
) -> Result<(), ProofMerkleError> {
    if indexes.is_empty()
        || !indexes.windows(2).all(|pair| pair[0] < pair[1])
        || indexes.last().copied().unwrap_or(0)
            >= u64::try_from(leaf_count).map_err(|_| ProofMerkleError::CountOverflow)?
    {
        return Err(ProofMerkleError::InvalidOpening);
    }
    Ok(())
}

#[cfg(test)]
mod canonical_tree_tests {
    use super::*;
    use crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS;

    fn context(visibility: ProofLeafVisibility) -> ProofMerkleTreeContext {
        ProofMerkleTreeContext::new(
            [1_u8; 64],
            [2_u8; 64],
            0x1216,
            0,
            ProofTreeRole::QuotientComponent,
            0,
            16,
            1,
            visibility,
        )
        .expect("test context")
    }

    fn extension_value(index: u64) -> ProofTreeValue {
        ProofTreeValue::Extension(
            ProofChallengeExtensionElement::from_canonical_coordinates([
                index,
                index + 1,
                index + 2,
                index + 3,
                index + 4,
            ])
            .expect("small extension coordinates"),
        )
    }

    fn leaves(
        context: &ProofMerkleTreeContext,
        visibility: ProofLeafVisibility,
    ) -> Vec<ProofOraclePhasePairLeaf> {
        (0..context.leaf_count().expect("leaf count"))
            .map(|index| {
                ProofOraclePhasePairLeaf::new(
                    context,
                    index as u64,
                    (visibility == ProofLeafVisibility::SecretBearing)
                        .then_some([index as u8; SECRET_LEAF_SALT_BYTE_LENGTH]),
                    vec![extension_value(index as u64)],
                    vec![extension_value(index as u64 + 100)],
                )
                .expect("test leaf")
            })
            .collect()
    }

    #[test]
    fn canonical_frontier_verifies_sparse_and_collision_heavy_openings() {
        for visibility in [
            ProofLeafVisibility::Public,
            ProofLeafVisibility::SecretBearing,
        ] {
            let context = context(visibility);
            let leaves = leaves(&context, visibility);
            let tree = CanonicalProofMerkleTree::from_phase_pair_leaves(context.clone(), &leaves)
                .expect("test tree");
            for indexes in [&[0_u64][..], &[0, 1, 6][..], &[1, 2, 3, 4, 5, 7][..]] {
                let opened = indexes
                    .iter()
                    .map(|index| {
                        (
                            *index,
                            leaves[*index as usize].digest().expect("leaf digest"),
                        )
                    })
                    .collect::<Vec<_>>();
                let frontier = tree
                    .authentication_frontier(indexes)
                    .expect("canonical frontier");
                verify_authentication_frontier(&context, &opened, &frontier, tree.root())
                    .expect("valid frontier");

                if !frontier.is_empty() {
                    let mut changed = frontier.clone();
                    changed[0].node_digest[0] ^= 1;
                    assert_eq!(
                        verify_authentication_frontier(&context, &opened, &changed, tree.root(),),
                        Err(ProofMerkleError::RootMismatch),
                    );
                }
            }
        }
    }

    #[test]
    fn phase_pair_leaf_rejects_wrong_visibility_width_and_value_type() {
        let public_context = context(ProofLeafVisibility::Public);
        assert_eq!(
            ProofOraclePhasePairLeaf::new(
                &public_context,
                0,
                Some([0_u8; SECRET_LEAF_SALT_BYTE_LENGTH]),
                vec![extension_value(0)],
                vec![extension_value(1)],
            ),
            Err(ProofMerkleError::InvalidLeaf),
        );
        assert_eq!(
            ProofOraclePhasePairLeaf::new(
                &public_context,
                0,
                None,
                vec![ProofTreeValue::Base(
                    ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MODULUS - 1)
                        .expect("canonical base value"),
                )],
                vec![ProofTreeValue::Base(ProofBaseFieldElement::ZERO)],
            ),
            Err(ProofMerkleError::InvalidLeaf),
        );
    }

    #[test]
    fn frontier_rejects_duplicates_reordering_and_extras() {
        let context = context(ProofLeafVisibility::Public);
        let leaves = leaves(&context, ProofLeafVisibility::Public);
        let tree = CanonicalProofMerkleTree::from_phase_pair_leaves(context.clone(), &leaves)
            .expect("test tree");
        assert_eq!(
            tree.authentication_frontier(&[1, 1]),
            Err(ProofMerkleError::InvalidOpening),
        );
        let opened = vec![(1, leaves[1].digest().expect("leaf digest"))];
        let mut frontier = tree
            .authentication_frontier(&[1])
            .expect("canonical frontier");
        frontier.push(ProofAuthenticationNode::new(99, 99, [9_u8; 64]));
        assert!(verify_authentication_frontier(&context, &opened, &frontier, tree.root()).is_err());
    }
}
