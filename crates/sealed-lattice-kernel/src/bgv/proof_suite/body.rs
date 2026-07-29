//! Verifier-owned tree descriptions shared by row-code proof generation and verification.

use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    hash_foundation_tuple_512,
};

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, ProofBaseFieldElement,
    committed_material::COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
    decoder::ProofDecodeError,
    merkle::{ProofLeafVisibility, ProofMerkleError, ProofTreeRole, ProofTreeValue},
    setup_public_polynomial::{
        SetupPublicPolynomialError,
        canonical_setup_public_polynomial_phase_pair_leaf_bytes_from_iterators,
        setup_public_polynomial_leaf_digest, setup_public_polynomial_merkle_node_digest,
    },
};

const SCHEMA_VERSION: u16 = 1;
const COMMITTED_MATERIAL_ROW_WIDTH: u32 = 4;
const MAXIMUM_TREE_CATALOG_ENTRY_COUNT: usize = u16::MAX as usize + 1;
const COMMITTED_MATERIAL_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/phase-pair-leaf/v1";
const COMMITTED_MATERIAL_NODE_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/merkle-node/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofBodyError {
    Decode(ProofDecodeError),
    Merkle(ProofMerkleError),
    CanonicalEncoding,
    InvalidCatalog,
    CatalogTooLarge,
    CountOverflow,
    AllocationLimitExceeded,
    InvalidLeaf,
}

impl From<ProofDecodeError> for ProofBodyError {
    fn from(error: ProofDecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<ProofMerkleError> for ProofBodyError {
    fn from(error: ProofMerkleError) -> Self {
        Self::Merkle(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StatementOwnedProofTreeInput {
    CommittedMaterial {
        material_context_hash: [u8; 64],
        expected_root: [u8; 64],
    },
    SetupPolynomial {
        public_polynomial_context_hash: [u8; 64],
        row_width: u32,
        expected_root: [u8; 64],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationProofTreeInput {
    ProofCreated {
        tree_role: ProofTreeRole,
        row_width: u32,
        leaf_visibility: ProofLeafVisibility,
    },
    BoundPublic(StatementOwnedProofTreeInput),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProofTreeConstruction {
    CommittedMaterial {
        material_context_hash: [u8; 64],
        row_width: u32,
    },
    SetupPolynomial {
        public_polynomial_context_hash: [u8; 64],
        row_width: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofTreeCatalogEntry {
    tree_catalog_index: u16,
    construction: ProofTreeConstruction,
    bound_root: [u8; 64],
}

impl ProofTreeCatalogEntry {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) fn uses_setup_polynomial_construction(&self) -> bool {
        matches!(
            &self.construction,
            ProofTreeConstruction::SetupPolynomial { .. }
        )
    }

    pub(crate) const fn bound_root(&self) -> Option<[u8; 64]> {
        Some(self.bound_root)
    }

    pub(crate) fn materialized_row_width(&self) -> Result<usize, ProofBodyError> {
        let row_width = match &self.construction {
            ProofTreeConstruction::CommittedMaterial { row_width, .. }
            | ProofTreeConstruction::SetupPolynomial { row_width, .. } => *row_width,
        };
        usize::try_from(row_width).map_err(|_| ProofBodyError::CountOverflow)
    }

    pub(crate) const fn requires_persistent_leaf_salt(&self) -> bool {
        matches!(
            &self.construction,
            ProofTreeConstruction::CommittedMaterial { .. }
        )
    }

    pub(crate) fn encode_materialized_leaf(
        &self,
        leaf_index: u64,
        salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Zeroizing<Vec<ProofTreeValue>>,
        opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
    ) -> Result<(Vec<u8>, [u8; 64]), ProofBodyError> {
        let expected_row_width = self.materialized_row_width()?;
        if first_point_values.len() != expected_row_width
            || opposite_point_values.len() != expected_row_width
        {
            return Err(ProofBodyError::InvalidLeaf);
        }
        match &self.construction {
            ProofTreeConstruction::CommittedMaterial {
                material_context_hash,
                ..
            } => {
                let salt = salt.ok_or(ProofBodyError::InvalidLeaf)?;
                let canonical_bytes = canonical_committed_material_phase_pair_leaf_bytes(
                    *material_context_hash,
                    leaf_index,
                    salt,
                    first_point_values.as_slice(),
                    opposite_point_values.as_slice(),
                )?;
                let digest =
                    hash_canonical_leaf(COMMITTED_MATERIAL_LEAF_HASH_DOMAIN, &canonical_bytes)?;
                Ok((canonical_bytes, digest))
            }
            ProofTreeConstruction::SetupPolynomial {
                public_polynomial_context_hash,
                ..
            } => {
                if salt.is_some() {
                    return Err(ProofBodyError::InvalidLeaf);
                }
                validate_base_field_values(first_point_values.as_slice())?;
                validate_base_field_values(opposite_point_values.as_slice())?;
                let canonical_bytes =
                    canonical_setup_public_polynomial_phase_pair_leaf_bytes_from_iterators(
                        *public_polynomial_context_hash,
                        leaf_index,
                        first_point_values.iter().map(base_field_value),
                        opposite_point_values.iter().map(base_field_value),
                    )
                    .map_err(map_setup_public_polynomial_error)?;
                let digest = setup_public_polynomial_leaf_digest(&canonical_bytes)
                    .map_err(map_setup_public_polynomial_error)?;
                Ok((canonical_bytes, digest))
            }
        }
    }

    pub(crate) fn materialized_parent_digest(
        &self,
        level: u32,
        parent_index: u64,
        left_child_digest: [u8; 64],
        right_child_digest: [u8; 64],
    ) -> Result<[u8; 64], ProofBodyError> {
        match &self.construction {
            ProofTreeConstruction::CommittedMaterial { .. } => {
                let left_child_index = parent_index
                    .checked_mul(2)
                    .ok_or(ProofBodyError::CountOverflow)?;
                hash_foundation_tuple_512(
                    COMMITTED_MATERIAL_NODE_HASH_DOMAIN,
                    &[
                        CanonicalItem::unsigned32(level),
                        CanonicalItem::unsigned64(left_child_index),
                        CanonicalItem::hash512(left_child_digest),
                        CanonicalItem::hash512(right_child_digest),
                    ],
                )
                .map(|digest| digest.into_bytes())
                .map_err(|_| ProofBodyError::CanonicalEncoding)
            }
            ProofTreeConstruction::SetupPolynomial {
                public_polynomial_context_hash,
                ..
            } => setup_public_polynomial_merkle_node_digest(
                *public_polynomial_context_hash,
                level,
                parent_index,
                left_child_digest,
                right_child_digest,
            )
            .map_err(map_setup_public_polynomial_error),
        }
    }
}

pub(crate) fn build_relation_bound_public_tree_catalog_entries(
    relation_trees: &[RelationProofTreeInput],
) -> Result<Vec<ProofTreeCatalogEntry>, ProofBodyError> {
    if relation_trees.len() > MAXIMUM_TREE_CATALOG_ENTRY_COUNT {
        return Err(ProofBodyError::CatalogTooLarge);
    }
    let bound_tree_count = relation_trees
        .iter()
        .filter(|tree| matches!(tree, RelationProofTreeInput::BoundPublic(_)))
        .count();
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(bound_tree_count)
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    for (tree_catalog_index, relation_tree) in relation_trees.iter().enumerate() {
        let RelationProofTreeInput::BoundPublic(statement_tree) = relation_tree else {
            continue;
        };
        let (construction, bound_root) = match statement_tree {
            StatementOwnedProofTreeInput::CommittedMaterial {
                material_context_hash,
                expected_root,
            } => (
                ProofTreeConstruction::CommittedMaterial {
                    material_context_hash: *material_context_hash,
                    row_width: COMMITTED_MATERIAL_ROW_WIDTH,
                },
                *expected_root,
            ),
            StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash,
                row_width,
                expected_root,
            } => {
                if *row_width == 0 {
                    return Err(ProofBodyError::InvalidCatalog);
                }
                (
                    ProofTreeConstruction::SetupPolynomial {
                        public_polynomial_context_hash: *public_polynomial_context_hash,
                        row_width: *row_width,
                    },
                    *expected_root,
                )
            }
        };
        entries.push(ProofTreeCatalogEntry {
            tree_catalog_index: u16::try_from(tree_catalog_index)
                .map_err(|_| ProofBodyError::CatalogTooLarge)?,
            construction,
            bound_root,
        });
    }
    Ok(entries)
}

fn canonical_committed_material_phase_pair_leaf_bytes(
    context_hash: [u8; 64],
    leaf_index: u64,
    salt: [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    first_point_values: &[ProofTreeValue],
    opposite_point_values: &[ProofTreeValue],
) -> Result<Vec<u8>, ProofBodyError> {
    let first_values = canonical_base_field_list(first_point_values)?;
    let opposite_values = canonical_base_field_list(opposite_point_values)?;
    CanonicalTuple::new(
        COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(context_hash),
            CanonicalItem::unsigned64(leaf_index),
            CanonicalItem::fixed_bytes(salt).map_err(|_| ProofBodyError::CanonicalEncoding)?,
            first_values,
            opposite_values,
        ],
    )
    .encode()
    .map_err(|_| ProofBodyError::CanonicalEncoding)
}

fn canonical_base_field_list(values: &[ProofTreeValue]) -> Result<CanonicalItem, ProofBodyError> {
    if values.is_empty() {
        return Err(ProofBodyError::InvalidLeaf);
    }
    let mut items = Vec::new();
    items
        .try_reserve_exact(values.len())
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    for value in values {
        let value = match value {
            ProofTreeValue::Base(value) => value,
        };
        items.push(
            CanonicalItem::from_canonical_bytes(
                CanonicalItemType::FieldElement,
                value.canonical().to_le_bytes().to_vec(),
                &CanonicalDecodeLimits::default(),
            )
            .map_err(|_| ProofBodyError::CanonicalEncoding)?,
        );
    }
    CanonicalItem::homogeneous_list(CanonicalItemType::FieldElement, &items)
        .map_err(|_| ProofBodyError::CanonicalEncoding)
}

fn validate_base_field_values(values: &[ProofTreeValue]) -> Result<(), ProofBodyError> {
    if values.is_empty() {
        return Err(ProofBodyError::InvalidLeaf);
    }
    Ok(())
}

fn base_field_value(value: &ProofTreeValue) -> ProofBaseFieldElement {
    match value {
        ProofTreeValue::Base(value) => *value,
    }
}

fn hash_canonical_leaf(domain: &str, canonical_bytes: &[u8]) -> Result<[u8; 64], ProofBodyError> {
    hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(canonical_bytes)
            .map_err(|_| ProofBodyError::CanonicalEncoding)?],
    )
    .map(|digest| digest.into_bytes())
    .map_err(|_| ProofBodyError::CanonicalEncoding)
}

fn map_setup_public_polynomial_error(error: SetupPublicPolynomialError) -> ProofBodyError {
    match error {
        SetupPublicPolynomialError::CountOverflow => ProofBodyError::CountOverflow,
        SetupPublicPolynomialError::AllocationLimitExceeded => {
            ProofBodyError::AllocationLimitExceeded
        }
        SetupPublicPolynomialError::InvalidContext
        | SetupPublicPolynomialError::InvalidInput
        | SetupPublicPolynomialError::InvalidLatticeAnchor
        | SetupPublicPolynomialError::CanonicalEncoding
        | SetupPublicPolynomialError::Field(_)
        | SetupPublicPolynomialError::Polynomial(_) => ProofBodyError::CanonicalEncoding,
    }
}
