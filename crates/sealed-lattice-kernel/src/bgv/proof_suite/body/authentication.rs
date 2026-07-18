use std::collections::{BTreeMap, BTreeSet};

use crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
use crate::foundation::{CanonicalItem, CanonicalItemType, hash_foundation_tuple_512};

use super::super::{
    PROOF_CHALLENGE_EXTENSION_DEGREE,
    decoder::{BoundedProofDecoder, ProofByteSource},
    merkle::{
        ProofLeafVisibility, ProofMerkleError, ProofMerkleTreeContext, ProofOraclePhasePairLeaf,
        ProofTreeRole, ProofTreeValue, minimal_frontier_coordinates,
        verify_authentication_frontier,
    },
};
use super::decoding::{
    DecodedProofPhasePairLeaf, read_hash_item, read_item_header, read_list_header,
    read_tuple_header, read_u16_item, read_u64_item,
};
use super::{
    AUTHENTICATION_DIGEST_BYTE_LENGTH, COMMITTED_MATERIAL_LEAF_HASH_DOMAIN,
    COMMITTED_MATERIAL_NODE_HASH_DOMAIN, COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
    COMMITTED_MATERIAL_ROW_WIDTH, PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
    PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER, ProofBodyError, ProofTreeCatalogEntry,
    ProofTreeCatalogSource, ProofTreeConstruction, SCHEMA_VERSION,
    SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN, SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN,
    SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
};

pub(super) fn decode_phase_pair_leaf(
    entry: &ProofTreeCatalogEntry,
    expected_leaf_index: u64,
    expected_leaf_count: usize,
    canonical_bytes: &[u8],
) -> Result<(DecodedProofPhasePairLeaf, [u8; 64]), ProofBodyError> {
    if expected_leaf_index
        >= u64::try_from(expected_leaf_count).map_err(|_| ProofBodyError::CountOverflow)?
    {
        return Err(ProofBodyError::InvalidLeaf);
    }
    match &entry.construction {
        ProofTreeConstruction::Common(context) => {
            decode_common_phase_pair_leaf(entry, context, expected_leaf_index, canonical_bytes)
        }
        ProofTreeConstruction::CommittedMaterial {
            material_context_hash,
        } => decode_statement_owned_phase_pair_leaf(
            StatementLeafLayout {
                schema_identifier: COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
                context_hash: *material_context_hash,
                row_width: COMMITTED_MATERIAL_ROW_WIDTH,
                secret_salt: true,
                leaf_hash_domain: COMMITTED_MATERIAL_LEAF_HASH_DOMAIN,
            },
            expected_leaf_index,
            canonical_bytes,
        ),
        ProofTreeConstruction::SetupPolynomial {
            public_polynomial_context_hash,
            row_width,
        } => decode_statement_owned_phase_pair_leaf(
            StatementLeafLayout {
                schema_identifier: SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
                context_hash: *public_polynomial_context_hash,
                row_width: *row_width,
                secret_salt: false,
                leaf_hash_domain: SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
            },
            expected_leaf_index,
            canonical_bytes,
        ),
    }
}

fn decode_common_phase_pair_leaf(
    entry: &ProofTreeCatalogEntry,
    context: &ProofMerkleTreeContext,
    expected_leaf_index: u64,
    canonical_bytes: &[u8],
) -> Result<(DecodedProofPhasePairLeaf, [u8; 64]), ProofBodyError> {
    let secret_bearing = context.leaf_visibility() == ProofLeafVisibility::SecretBearing;
    let expected_item_count = if secret_bearing { 6 } else { 5 };
    let mut decoder = BoundedProofDecoder::new(
        canonical_bytes,
        canonical_bytes.len(),
        canonical_bytes.len(),
    )?;
    read_tuple_header(
        &mut decoder,
        PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        expected_item_count,
    )?;
    if read_hash_item(&mut decoder)? != context.context_hash()? {
        return Err(ProofBodyError::InvalidLeaf);
    }
    if read_u64_item(&mut decoder)? != expected_leaf_index {
        return Err(ProofBodyError::InvalidLeaf);
    }
    read_u16_item(
        &mut decoder,
        context.leaf_visibility() as u16,
        ProofBodyError::InvalidLeaf,
    )?;
    let secret_salt = if secret_bearing {
        read_item_header(
            &mut decoder,
            CanonicalItemType::RawBytes,
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
        )?;
        Some(decoder.read_array::<COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH>()?)
    } else {
        None
    };
    let row_width =
        usize::try_from(context.row_width()).map_err(|_| ProofBodyError::CountOverflow)?;
    let value_kind = match entry.source {
        ProofTreeCatalogSource::RelationProofCreated { .. } => TreeValueKind::Base,
        ProofTreeCatalogSource::QuotientComponent { .. }
        | ProofTreeCatalogSource::OpeningBatchMask
        | ProofTreeCatalogSource::NonterminalFriLayer { .. } => TreeValueKind::Extension,
        ProofTreeCatalogSource::RelationBoundPublic => {
            return Err(ProofBodyError::InvalidCatalog);
        }
    };
    let first_point_values = read_tree_value_list_item(&mut decoder, value_kind, row_width)?;
    let opposite_point_values = read_tree_value_list_item(&mut decoder, value_kind, row_width)?;
    decoder.finish()?;

    let canonical_leaf = ProofOraclePhasePairLeaf::new(
        context,
        expected_leaf_index,
        secret_salt,
        first_point_values.clone(),
        opposite_point_values.clone(),
    )?;
    if canonical_leaf.canonical_bytes()?.as_slice() != canonical_bytes {
        return Err(ProofBodyError::InvalidLeaf);
    }
    let digest = canonical_leaf.digest()?;
    Ok((
        DecodedProofPhasePairLeaf {
            leaf_index: expected_leaf_index,
            first_point_values,
            opposite_point_values,
        },
        digest,
    ))
}

#[derive(Clone, Copy)]
struct StatementLeafLayout {
    schema_identifier: u16,
    context_hash: [u8; 64],
    row_width: u32,
    secret_salt: bool,
    leaf_hash_domain: &'static str,
}

fn decode_statement_owned_phase_pair_leaf(
    layout: StatementLeafLayout,
    expected_leaf_index: u64,
    canonical_bytes: &[u8],
) -> Result<(DecodedProofPhasePairLeaf, [u8; 64]), ProofBodyError> {
    let expected_item_count = if layout.secret_salt { 5 } else { 4 };
    let mut decoder = BoundedProofDecoder::new(
        canonical_bytes,
        canonical_bytes.len(),
        canonical_bytes.len(),
    )?;
    read_tuple_header(&mut decoder, layout.schema_identifier, expected_item_count)?;
    if read_hash_item(&mut decoder)? != layout.context_hash
        || read_u64_item(&mut decoder)? != expected_leaf_index
    {
        return Err(ProofBodyError::InvalidLeaf);
    }
    if layout.secret_salt {
        read_item_header(
            &mut decoder,
            CanonicalItemType::RawBytes,
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
        )?;
        let _ = decoder.read_array::<COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH>()?;
    }
    let row_width = usize::try_from(layout.row_width).map_err(|_| ProofBodyError::CountOverflow)?;
    let first_point_values =
        read_tree_value_list_item(&mut decoder, TreeValueKind::Base, row_width)?;
    let opposite_point_values =
        read_tree_value_list_item(&mut decoder, TreeValueKind::Base, row_width)?;
    decoder.finish()?;
    let digest = hash_canonical_leaf(layout.leaf_hash_domain, canonical_bytes)?;
    Ok((
        DecodedProofPhasePairLeaf {
            leaf_index: expected_leaf_index,
            first_point_values,
            opposite_point_values,
        },
        digest,
    ))
}

#[derive(Clone, Copy)]
pub(super) enum TreeValueKind {
    Base,
    Extension,
}

impl TreeValueKind {
    const fn item_type(self) -> CanonicalItemType {
        match self {
            Self::Base => CanonicalItemType::FieldElement,
            Self::Extension => CanonicalItemType::ChallengeExtensionElement,
        }
    }

    const fn canonical_byte_length(self) -> usize {
        match self {
            Self::Base => 8,
            Self::Extension => PROOF_CHALLENGE_EXTENSION_DEGREE * 8,
        }
    }
}

fn read_tree_value_list_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    value_kind: TreeValueKind,
    expected_count: usize,
) -> Result<Vec<ProofTreeValue>, ProofBodyError> {
    let item_byte_length = expected_count
        .checked_mul(value_kind.canonical_byte_length())
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    read_item_header(
        decoder,
        CanonicalItemType::HomogeneousList,
        item_byte_length,
    )?;
    read_list_header(decoder, value_kind.item_type(), expected_count)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(expected_count)
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    for _ in 0..expected_count {
        values.push(match value_kind {
            TreeValueKind::Base => ProofTreeValue::Base(decoder.read_base_field_element()?),
            TreeValueKind::Extension => {
                ProofTreeValue::Extension(decoder.read_challenge_extension_element()?)
            }
        });
    }
    Ok(values)
}

pub(super) fn hash_canonical_leaf(
    domain: &str,
    canonical_bytes: &[u8],
) -> Result<[u8; 64], ProofBodyError> {
    Ok(hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(canonical_bytes)
            .map_err(|_| ProofBodyError::CanonicalEncoding)?],
    )
    .map_err(|_| ProofBodyError::CanonicalEncoding)?
    .into_bytes())
}

pub(super) fn read_authentication_frontier<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_tree_catalog_index: u16,
    expected_node_count: usize,
) -> Result<Vec<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>, ProofBodyError> {
    read_tuple_header(decoder, PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER, 2)?;
    read_u16_item(
        decoder,
        expected_tree_catalog_index,
        ProofBodyError::InvalidTreeCatalogIndex,
    )?;
    let list_byte_length = expected_node_count
        .checked_mul(AUTHENTICATION_DIGEST_BYTE_LENGTH)
        .and_then(|length| length.checked_add(6))
        .filter(|length| u32::try_from(*length).is_ok())
        .ok_or(ProofBodyError::CountOverflow)?;
    read_item_header(
        decoder,
        CanonicalItemType::HomogeneousList,
        list_byte_length,
    )?;
    read_list_header(decoder, CanonicalItemType::Hash512, expected_node_count)?;
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(expected_node_count)
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    for _ in 0..expected_node_count {
        digests.push(decoder.read_hash512()?);
    }
    Ok(digests)
}

pub(in crate::bgv::proof_suite) fn minimal_frontier_node_count(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<usize, ProofBodyError> {
    minimal_frontier_coordinates(sorted_unique_leaf_indexes, leaf_count)
        .map(|coordinates| coordinates.len())
        .map_err(|error| match error {
            ProofMerkleError::CountOverflow => ProofBodyError::CountOverflow,
            _ => ProofBodyError::InvalidQueryRepresentatives,
        })
}

pub(super) fn authenticate_opening(
    entry: &ProofTreeCatalogEntry,
    sorted_unique_opened_leaves: &[(u64, [u8; 64])],
    frontier: &[[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]],
    expected_root: [u8; 64],
    leaf_count: usize,
) -> Result<(), ProofBodyError> {
    match &entry.construction {
        ProofTreeConstruction::Common(context) => Ok(verify_authentication_frontier(
            context,
            sorted_unique_opened_leaves,
            frontier,
            expected_root,
        )?),
        ProofTreeConstruction::CommittedMaterial { .. }
        | ProofTreeConstruction::SetupPolynomial { .. } => verify_statement_owned_frontier(
            &entry.construction,
            sorted_unique_opened_leaves,
            frontier,
            expected_root,
            leaf_count,
        ),
    }
}

fn verify_statement_owned_frontier(
    construction: &ProofTreeConstruction,
    sorted_unique_opened_leaves: &[(u64, [u8; 64])],
    frontier: &[[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]],
    expected_root: [u8; 64],
    leaf_count: usize,
) -> Result<(), ProofBodyError> {
    if !sorted_unique_opened_leaves
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
    {
        return Err(ProofMerkleError::NonCanonicalOrder.into());
    }
    let mut current = sorted_unique_opened_leaves
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    let mut frontier_offset = 0_usize;
    for level in 0..leaf_count.trailing_zeros() {
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
                let supplied_digest = frontier
                    .get(frontier_offset)
                    .copied()
                    .ok_or(ProofMerkleError::InvalidOpening)?;
                frontier_offset += 1;
                supplied_digest
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
            let parent_digest = statement_owned_node_digest(
                construction,
                level.checked_add(1).ok_or(ProofBodyError::CountOverflow)?,
                parent_index,
                left,
                right,
            )?;
            if next.insert(parent_index, parent_digest).is_some() {
                return Err(ProofMerkleError::InvalidOpening.into());
            }
        }
        current = next;
    }
    if frontier_offset != frontier.len()
        || current.len() != 1
        || current.get(&0).copied() != Some(expected_root)
    {
        return Err(ProofMerkleError::RootMismatch.into());
    }
    Ok(())
}

pub(super) fn statement_owned_node_digest(
    construction: &ProofTreeConstruction,
    level: u32,
    parent_index: u64,
    left_child_digest: [u8; 64],
    right_child_digest: [u8; 64],
) -> Result<[u8; 64], ProofBodyError> {
    let left_child_index = parent_index
        .checked_mul(2)
        .ok_or(ProofBodyError::CountOverflow)?;
    let (domain, items) = match construction {
        ProofTreeConstruction::CommittedMaterial { .. } => (
            COMMITTED_MATERIAL_NODE_HASH_DOMAIN,
            vec![
                CanonicalItem::unsigned32(level),
                CanonicalItem::unsigned64(left_child_index),
                CanonicalItem::hash512(left_child_digest),
                CanonicalItem::hash512(right_child_digest),
            ],
        ),
        ProofTreeConstruction::SetupPolynomial {
            public_polynomial_context_hash,
            ..
        } => (
            SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN,
            vec![
                CanonicalItem::hash512(*public_polynomial_context_hash),
                CanonicalItem::unsigned32(level),
                CanonicalItem::unsigned64(left_child_index),
                CanonicalItem::hash512(left_child_digest),
                CanonicalItem::hash512(right_child_digest),
            ],
        ),
        ProofTreeConstruction::Common(_) => return Err(ProofBodyError::InvalidCatalog),
    };
    Ok(hash_foundation_tuple_512(domain, &items)
        .map_err(|_| ProofBodyError::CanonicalEncoding)?
        .into_bytes())
}
