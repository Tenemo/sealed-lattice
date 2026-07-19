use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        StreamingFoundationTupleHash512, canonical_foundation_tuple_hash_preimage,
        canonical_foundation_variable_bytes_hash_preimage, hash_foundation_tuple_512,
    },
    hashing::hash_framed_parts_512 as hash512,
};

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_CHALLENGE_EXTENSION_DEGREE,
    ProofBaseFieldElement, ProofChallengeExtensionElement,
};

const MERKLE_LEAF_DOMAIN: &str = "sealed-lattice/proof/merkle/leaf/v1";
const MERKLE_NODE_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";
const PROOF_TREE_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/tree-context/v1";
const PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/phase-pair-leaf/v1";

const PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x0103;
pub(super) const PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x0104;
pub(super) const PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER: u16 = 0x0105;
const SCHEMA_VERSION: u16 = 1;

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

impl Zeroize for ProofTreeValue {
    fn zeroize(&mut self) {
        match self {
            Self::Base(value) => value.zeroize(),
            Self::Extension(value) => value.zeroize(),
        }
    }
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

    fn absorb_canonical_bytes(
        self,
        digest_builder: &mut StreamingFoundationTupleHash512,
    ) -> Result<(), ProofMerkleError> {
        match self {
            Self::Base(value) => digest_builder
                .absorb(&value.canonical().to_le_bytes())
                .map_err(canonical_encoding_error),
            Self::Extension(value) => {
                for coordinate in value.canonical_coordinates() {
                    digest_builder
                        .absorb(&coordinate.to_le_bytes())
                        .map_err(canonical_encoding_error)?;
                }
                Ok(())
            }
        }
    }

    fn append_canonical_bytes(self, destination: &mut Vec<u8>) {
        match self {
            Self::Base(value) => destination.extend_from_slice(&value.canonical().to_le_bytes()),
            Self::Extension(value) => {
                for coordinate in value.canonical_coordinates() {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
        }
    }
}

fn append_canonical_item(
    destination: &mut Vec<u8>,
    item: &CanonicalItem,
) -> Result<(), ProofMerkleError> {
    destination.extend_from_slice(&item.item_type().canonical_code().to_le_bytes());
    destination.extend_from_slice(
        &u32::try_from(item.canonical_bytes().len())
            .map_err(|_| ProofMerkleError::CountOverflow)?
            .to_le_bytes(),
    );
    destination.extend_from_slice(item.canonical_bytes());
    Ok(())
}

fn append_phase_pair_value_list_header(
    destination: &mut Vec<u8>,
    value_type: CanonicalItemType,
    value_count: usize,
) -> Result<(), ProofMerkleError> {
    let value_byte_length = match value_type {
        CanonicalItemType::FieldElement => 8_usize,
        CanonicalItemType::ChallengeExtensionElement => PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(8)
            .ok_or(ProofMerkleError::CountOverflow)?,
        _ => return Err(ProofMerkleError::InvalidLeaf),
    };
    let list_payload_byte_length = value_count
        .checked_mul(value_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofMerkleError::CountOverflow)?;
    destination.extend_from_slice(
        &CanonicalItemType::HomogeneousList
            .canonical_code()
            .to_le_bytes(),
    );
    destination.extend_from_slice(
        &u32::try_from(list_payload_byte_length)
            .map_err(|_| ProofMerkleError::CountOverflow)?
            .to_le_bytes(),
    );
    destination.extend_from_slice(&value_type.canonical_code().to_le_bytes());
    destination.extend_from_slice(
        &u32::try_from(value_count)
            .map_err(|_| ProofMerkleError::CountOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn phase_pair_leaf_canonical_byte_length(
    secret_salt_is_present: bool,
    value_type: CanonicalItemType,
    value_count: usize,
) -> Result<usize, ProofMerkleError> {
    let value_byte_length = match value_type {
        CanonicalItemType::FieldElement => 8_usize,
        CanonicalItemType::ChallengeExtensionElement => PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(8)
            .ok_or(ProofMerkleError::CountOverflow)?,
        _ => return Err(ProofMerkleError::InvalidLeaf),
    };
    let item_count = if secret_salt_is_present {
        6_usize
    } else {
        5_usize
    };
    let fixed_item_payload_byte_length = 64_usize
        .checked_add(8)
        .and_then(|length| length.checked_add(2))
        .and_then(|length| {
            length.checked_add(if secret_salt_is_present {
                COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
            } else {
                0
            })
        })
        .ok_or(ProofMerkleError::CountOverflow)?;
    let row_payload_byte_length = value_count
        .checked_mul(value_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofMerkleError::CountOverflow)?;
    8_usize
        .checked_add(
            item_count
                .checked_mul(6)
                .ok_or(ProofMerkleError::CountOverflow)?,
        )
        .and_then(|length| length.checked_add(fixed_item_payload_byte_length))
        .and_then(|length| length.checked_add(row_payload_byte_length.checked_mul(2)?))
        .ok_or(ProofMerkleError::CountOverflow)
}

fn phase_pair_leaf_canonical_prefix(
    proof_tree_context_hash: [u8; 64],
    leaf_index: u64,
    leaf_visibility: ProofLeafVisibility,
    secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    value_type: CanonicalItemType,
    value_count: usize,
) -> Result<Vec<u8>, ProofMerkleError> {
    let item_count = if secret_salt.is_some() { 6_u32 } else { 5_u32 };
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER.to_le_bytes());
    prefix.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    prefix.extend_from_slice(&item_count.to_le_bytes());
    append_canonical_item(
        &mut prefix,
        &CanonicalItem::hash512(proof_tree_context_hash),
    )?;
    append_canonical_item(&mut prefix, &CanonicalItem::unsigned64(leaf_index))?;
    append_canonical_item(
        &mut prefix,
        &CanonicalItem::unsigned16(leaf_visibility as u16),
    )?;
    if let Some(secret_salt) = secret_salt {
        append_canonical_item(
            &mut prefix,
            &CanonicalItem::fixed_bytes(secret_salt).map_err(canonical_encoding_error)?,
        )?;
    }
    append_phase_pair_value_list_header(&mut prefix, value_type, value_count)?;
    Ok(prefix)
}

/// Incremental canonical digest for one phase-pair leaf. The row widths and
/// item lengths are committed before values are accepted, so a column-major
/// producer can retain only this hash state while preserving the exact leaf
/// bytes and Merkle root accepted by the verifier.
pub(crate) struct ProofOraclePhasePairLeafDigestBuilder {
    digest_builder: StreamingFoundationTupleHash512,
    value_type: CanonicalItemType,
    expected_value_count: usize,
    absorbed_first_value_count: usize,
    absorbed_opposite_value_count: usize,
    opposite_header_absorbed: bool,
}

impl ProofOraclePhasePairLeafDigestBuilder {
    pub(in crate::bgv::proof_suite) fn new(
        leaf: &ProofOraclePhasePairLeaf,
    ) -> Result<Self, ProofMerkleError> {
        let first_value = leaf
            .first_point_values
            .first()
            .copied()
            .ok_or(ProofMerkleError::InvalidLeaf)?;
        let value_type = first_value.item_type();
        let expected_value_count = leaf.first_point_values.len();
        if leaf.opposite_point_values.len() != expected_value_count
            || leaf
                .first_point_values
                .iter()
                .chain(leaf.opposite_point_values.iter())
                .any(|value| value.item_type() != value_type)
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }

        Self::new_from_parts(
            leaf.proof_tree_context_hash,
            leaf.leaf_index,
            leaf.leaf_visibility,
            leaf.secret_salt,
            value_type,
            expected_value_count,
        )
    }

    pub(in crate::bgv::proof_suite) fn new_from_context(
        context: &ProofMerkleTreeContext,
        leaf_index: u64,
        secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        value_example: ProofTreeValue,
        expected_value_count: usize,
    ) -> Result<Self, ProofMerkleError> {
        let expected_context_value_count =
            usize::try_from(context.row_width).map_err(|_| ProofMerkleError::CountOverflow)?;
        let value_type = value_example.item_type();
        if leaf_index >= context.domain_size / 2
            || expected_value_count == 0
            || expected_value_count != expected_context_value_count
            || secret_salt.is_some()
                != (context.leaf_visibility == ProofLeafVisibility::SecretBearing)
            || (matches!(
                context.tree_role,
                ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer
            ) && value_type != CanonicalItemType::ChallengeExtensionElement)
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        Self::new_from_parts(
            context.context_hash()?,
            leaf_index,
            context.leaf_visibility,
            secret_salt,
            value_type,
            expected_value_count,
        )
    }

    fn new_from_parts(
        proof_tree_context_hash: [u8; 64],
        leaf_index: u64,
        leaf_visibility: ProofLeafVisibility,
        secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        value_type: CanonicalItemType,
        expected_value_count: usize,
    ) -> Result<Self, ProofMerkleError> {
        let prefix = phase_pair_leaf_canonical_prefix(
            proof_tree_context_hash,
            leaf_index,
            leaf_visibility,
            secret_salt,
            value_type,
            expected_value_count,
        )?;
        let canonical_leaf_byte_length = phase_pair_leaf_canonical_byte_length(
            secret_salt.is_some(),
            value_type,
            expected_value_count,
        )?;
        let mut digest_builder = StreamingFoundationTupleHash512::new_variable_bytes(
            PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN,
            &[],
            canonical_leaf_byte_length,
        )
        .map_err(canonical_encoding_error)?;
        digest_builder
            .absorb(&prefix)
            .map_err(canonical_encoding_error)?;
        Ok(Self {
            digest_builder,
            value_type,
            expected_value_count,
            absorbed_first_value_count: 0,
            absorbed_opposite_value_count: 0,
            opposite_header_absorbed: false,
        })
    }

    pub(crate) fn absorb_first_value(
        &mut self,
        value: ProofTreeValue,
    ) -> Result<(), ProofMerkleError> {
        if self.opposite_header_absorbed
            || self.absorbed_first_value_count >= self.expected_value_count
            || value.item_type() != self.value_type
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        value.absorb_canonical_bytes(&mut self.digest_builder)?;
        self.absorbed_first_value_count += 1;
        Ok(())
    }

    pub(crate) fn begin_opposite_values(&mut self) -> Result<(), ProofMerkleError> {
        if self.opposite_header_absorbed
            || self.absorbed_first_value_count != self.expected_value_count
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        let mut header = Vec::new();
        append_phase_pair_value_list_header(
            &mut header,
            self.value_type,
            self.expected_value_count,
        )?;
        self.digest_builder
            .absorb(&header)
            .map_err(canonical_encoding_error)?;
        self.opposite_header_absorbed = true;
        Ok(())
    }

    pub(crate) fn absorb_opposite_value(
        &mut self,
        value: ProofTreeValue,
    ) -> Result<(), ProofMerkleError> {
        if !self.opposite_header_absorbed
            || self.absorbed_opposite_value_count >= self.expected_value_count
            || value.item_type() != self.value_type
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        value.absorb_canonical_bytes(&mut self.digest_builder)?;
        self.absorbed_opposite_value_count += 1;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<[u8; 64], ProofMerkleError> {
        if !self.opposite_header_absorbed
            || self.absorbed_first_value_count != self.expected_value_count
            || self.absorbed_opposite_value_count != self.expected_value_count
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        Ok(self
            .digest_builder
            .finalize()
            .map_err(canonical_encoding_error)?
            .into_bytes())
    }
}

/// Incremental canonical byte encoder for the small set of queried leaves.
/// It follows the same state transitions as the digest builder while owning
/// only one exact-size final leaf buffer per retained query.
pub(in crate::bgv::proof_suite) struct ProofOraclePhasePairLeafByteBuilder {
    canonical_bytes: Zeroizing<Vec<u8>>,
    canonical_leaf_byte_length: usize,
    value_type: CanonicalItemType,
    expected_value_count: usize,
    absorbed_first_value_count: usize,
    absorbed_opposite_value_count: usize,
    opposite_header_absorbed: bool,
}

impl ProofOraclePhasePairLeafByteBuilder {
    pub(in crate::bgv::proof_suite) fn new_from_context(
        context: &ProofMerkleTreeContext,
        leaf_index: u64,
        secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        value_example: ProofTreeValue,
        expected_value_count: usize,
    ) -> Result<Self, ProofMerkleError> {
        let expected_context_value_count =
            usize::try_from(context.row_width).map_err(|_| ProofMerkleError::CountOverflow)?;
        let value_type = value_example.item_type();
        if leaf_index >= context.domain_size / 2
            || expected_value_count == 0
            || expected_value_count != expected_context_value_count
            || secret_salt.is_some()
                != (context.leaf_visibility == ProofLeafVisibility::SecretBearing)
            || (matches!(
                context.tree_role,
                ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer
            ) && value_type != CanonicalItemType::ChallengeExtensionElement)
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        let mut canonical_bytes = Vec::new();
        let canonical_leaf_byte_length = phase_pair_leaf_canonical_byte_length(
            secret_salt.is_some(),
            value_type,
            expected_value_count,
        )?;
        canonical_bytes
            .try_reserve_exact(canonical_leaf_byte_length)
            .map_err(|_| ProofMerkleError::CountOverflow)?;
        canonical_bytes.extend_from_slice(&phase_pair_leaf_canonical_prefix(
            context.context_hash()?,
            leaf_index,
            context.leaf_visibility,
            secret_salt,
            value_type,
            expected_value_count,
        )?);
        Ok(Self {
            canonical_bytes: Zeroizing::new(canonical_bytes),
            canonical_leaf_byte_length,
            value_type,
            expected_value_count,
            absorbed_first_value_count: 0,
            absorbed_opposite_value_count: 0,
            opposite_header_absorbed: false,
        })
    }

    pub(in crate::bgv::proof_suite) fn absorb_first_value(
        &mut self,
        value: ProofTreeValue,
    ) -> Result<(), ProofMerkleError> {
        if self.opposite_header_absorbed
            || self.absorbed_first_value_count >= self.expected_value_count
            || value.item_type() != self.value_type
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        value.append_canonical_bytes(&mut self.canonical_bytes);
        self.absorbed_first_value_count += 1;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn begin_opposite_values(
        &mut self,
    ) -> Result<(), ProofMerkleError> {
        if self.opposite_header_absorbed
            || self.absorbed_first_value_count != self.expected_value_count
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        append_phase_pair_value_list_header(
            &mut self.canonical_bytes,
            self.value_type,
            self.expected_value_count,
        )?;
        self.opposite_header_absorbed = true;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn absorb_opposite_value(
        &mut self,
        value: ProofTreeValue,
    ) -> Result<(), ProofMerkleError> {
        if !self.opposite_header_absorbed
            || self.absorbed_opposite_value_count >= self.expected_value_count
            || value.item_type() != self.value_type
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        value.append_canonical_bytes(&mut self.canonical_bytes);
        self.absorbed_opposite_value_count += 1;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn finish(
        self,
    ) -> Result<Zeroizing<Vec<u8>>, ProofMerkleError> {
        if !self.opposite_header_absorbed
            || self.absorbed_first_value_count != self.expected_value_count
            || self.absorbed_opposite_value_count != self.expected_value_count
            || self.canonical_bytes.len() != self.canonical_leaf_byte_length
        {
            return Err(ProofMerkleError::InvalidLeaf);
        }
        Ok(self.canonical_bytes)
    }

    pub(in crate::bgv::proof_suite) fn resident_owned_payload_byte_length(
        &self,
    ) -> Result<u64, ProofMerkleError> {
        u64::try_from(self.canonical_bytes.capacity()).map_err(|_| ProofMerkleError::CountOverflow)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProofOraclePhasePairLeaf {
    proof_tree_context_hash: [u8; 64],
    leaf_index: u64,
    leaf_visibility: ProofLeafVisibility,
    secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    first_point_values: Zeroizing<Vec<ProofTreeValue>>,
    opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
}

impl fmt::Debug for ProofOraclePhasePairLeaf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofOraclePhasePairLeaf")
            .field("leaf_index", &self.leaf_index)
            .field("leaf_visibility", &self.leaf_visibility)
            .field("has_secret_salt", &self.secret_salt.is_some())
            .field("row_width", &self.first_point_values.len())
            .finish_non_exhaustive()
    }
}

impl Drop for ProofOraclePhasePairLeaf {
    fn drop(&mut self) {
        self.secret_salt.zeroize();
    }
}

impl ProofOraclePhasePairLeaf {
    pub(crate) fn new(
        context: &ProofMerkleTreeContext,
        leaf_index: u64,
        secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Vec<ProofTreeValue>,
        opposite_point_values: Vec<ProofTreeValue>,
    ) -> Result<Self, ProofMerkleError> {
        Self::new_protected(
            context,
            leaf_index,
            secret_salt,
            Zeroizing::new(first_point_values),
            Zeroizing::new(opposite_point_values),
        )
    }

    pub(crate) fn new_protected(
        context: &ProofMerkleTreeContext,
        leaf_index: u64,
        secret_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Zeroizing<Vec<ProofTreeValue>>,
        opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
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
            .chain(opposite_point_values.iter())
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
        let first_values = canonical_tree_value_list(self.first_point_values.as_slice())?;
        let opposite_values = canonical_tree_value_list(self.opposite_point_values.as_slice())?;
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

    pub(crate) fn hash_preimage(&self) -> Result<Zeroizing<Vec<u8>>, ProofMerkleError> {
        let canonical_bytes = Zeroizing::new(self.canonical_bytes()?);
        canonical_foundation_variable_bytes_hash_preimage(
            PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN,
            canonical_bytes.as_slice(),
        )
        .map_err(canonical_encoding_error)
    }

    fn canonical_leaf_byte_length(
        &self,
        value_type: CanonicalItemType,
    ) -> Result<usize, ProofMerkleError> {
        phase_pair_leaf_canonical_byte_length(
            self.secret_salt.is_some(),
            value_type,
            self.first_point_values.len(),
        )
    }

    pub(crate) fn digest(&self) -> Result<[u8; 64], ProofMerkleError> {
        let mut digest_builder = ProofOraclePhasePairLeafDigestBuilder::new(self)?;
        for value in self.first_point_values.iter().copied() {
            digest_builder.absorb_first_value(value)?;
        }
        digest_builder.begin_opposite_values()?;
        for value in self.opposite_point_values.iter().copied() {
            digest_builder.absorb_opposite_value(value)?;
        }
        digest_builder.finish()
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
    ) -> Result<Vec<[u8; 64]>, ProofMerkleError> {
        let coordinates =
            minimal_frontier_coordinates(sorted_unique_leaf_indexes, self.context.leaf_count()?)?;
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(coordinates.len())
            .map_err(|_| ProofMerkleError::CountOverflow)?;
        for (level, node_index) in coordinates {
            let level = usize::try_from(level).map_err(|_| ProofMerkleError::CountOverflow)?;
            let node_index =
                usize::try_from(node_index).map_err(|_| ProofMerkleError::CountOverflow)?;
            frontier.push(
                *self
                    .levels
                    .get(level)
                    .and_then(|nodes| nodes.get(node_index))
                    .ok_or(ProofMerkleError::InvalidOpening)?,
            );
        }
        Ok(frontier)
    }
}

pub(crate) fn verify_authentication_frontier(
    context: &ProofMerkleTreeContext,
    sorted_unique_opened_leaves: &[(u64, [u8; 64])],
    frontier: &[[u8; 64]],
    expected_root: [u8; 64],
) -> Result<(), ProofMerkleError> {
    let leaf_indexes = sorted_unique_opened_leaves
        .iter()
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    validate_sorted_unique_leaf_indexes(&leaf_indexes, context.leaf_count()?)?;
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

pub(in crate::bgv::proof_suite) fn proof_merkle_node_digest(
    context_hash: [u8; 64],
    level: u32,
    node_index: u64,
    left_child_digest: [u8; 64],
    right_child_digest: [u8; 64],
) -> Result<[u8; 64], ProofMerkleError> {
    let items = proof_merkle_node_hash_items(
        context_hash,
        level,
        node_index,
        left_child_digest,
        right_child_digest,
    )?;
    Ok(hash_foundation_tuple_512(MERKLE_NODE_DOMAIN, &items)
        .map_err(canonical_encoding_error)?
        .into_bytes())
}

pub(in crate::bgv::proof_suite) fn proof_merkle_node_hash_preimage(
    context_hash: [u8; 64],
    level: u32,
    node_index: u64,
    left_child_digest: [u8; 64],
    right_child_digest: [u8; 64],
) -> Result<Zeroizing<Vec<u8>>, ProofMerkleError> {
    let items = proof_merkle_node_hash_items(
        context_hash,
        level,
        node_index,
        left_child_digest,
        right_child_digest,
    )?;
    canonical_foundation_tuple_hash_preimage(MERKLE_NODE_DOMAIN, &items)
        .map_err(canonical_encoding_error)
}

fn proof_merkle_node_hash_items(
    context_hash: [u8; 64],
    level: u32,
    node_index: u64,
    left_child_digest: [u8; 64],
    right_child_digest: [u8; 64],
) -> Result<[CanonicalItem; 1], ProofMerkleError> {
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
    Ok([CanonicalItem::variable_bytes(canonical_bytes).map_err(canonical_encoding_error)?])
}

pub(in crate::bgv::proof_suite) fn minimal_frontier_coordinates(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<Vec<(u32, u64)>, ProofMerkleError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(ProofMerkleError::InvalidOpening);
    }
    validate_sorted_unique_leaf_indexes(sorted_unique_leaf_indexes, leaf_count)?;

    let mut required = sorted_unique_leaf_indexes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut coordinates = Vec::new();
    for level in 0..leaf_count.trailing_zeros() {
        let mut next = BTreeSet::new();
        let mut processed = BTreeSet::new();
        for index in required.iter().copied() {
            if !processed.insert(index) {
                continue;
            }
            let sibling_index = index ^ 1;
            if required.contains(&sibling_index) {
                processed.insert(sibling_index);
            } else {
                coordinates
                    .try_reserve(1)
                    .map_err(|_| ProofMerkleError::CountOverflow)?;
                coordinates.push((level, sibling_index));
            }
            next.insert(index / 2);
        }
        required = next;
    }
    Ok(coordinates)
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
                        .then_some([index as u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
                    vec![extension_value(index as u64)],
                    vec![extension_value(index as u64 + 100)],
                )
                .expect("test leaf")
            })
            .collect()
    }

    fn one_shot_phase_pair_leaf_digest(
        leaf: &ProofOraclePhasePairLeaf,
    ) -> Result<[u8; 64], ProofMerkleError> {
        Ok(hash_foundation_tuple_512(
            PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(leaf.canonical_bytes()?)
                .map_err(canonical_encoding_error)?],
        )
        .map_err(canonical_encoding_error)?
        .into_bytes())
    }

    #[test]
    fn streamed_phase_pair_leaf_digest_matches_canonical_one_shot_encoding() {
        for visibility in [
            ProofLeafVisibility::Public,
            ProofLeafVisibility::SecretBearing,
        ] {
            let context = context(visibility);
            for leaf in leaves(&context, visibility) {
                assert_eq!(
                    leaf.digest().expect("streamed leaf digest"),
                    one_shot_phase_pair_leaf_digest(&leaf).expect("one-shot leaf digest"),
                );
            }
        }

        let base_context = ProofMerkleTreeContext::new(
            [0x31_u8; 64],
            [0x42_u8; 64],
            0x1216,
            3,
            ProofTreeRole::BaseOracle,
            5,
            32,
            4,
            ProofLeafVisibility::SecretBearing,
        )
        .expect("base-tree context");
        let base_value = |value| {
            ProofTreeValue::Base(
                ProofBaseFieldElement::from_canonical(value).expect("small base-field value"),
            )
        };
        let base_leaf = ProofOraclePhasePairLeaf::new(
            &base_context,
            11,
            Some([0x5a_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
            vec![base_value(0), base_value(1), base_value(2), base_value(3)],
            vec![
                base_value(PROOF_BASE_FIELD_MODULUS - 1),
                base_value(5),
                base_value(8),
                base_value(13),
            ],
        )
        .expect("base-tree leaf");
        assert_eq!(
            base_leaf.digest().expect("streamed base leaf digest"),
            one_shot_phase_pair_leaf_digest(&base_leaf).expect("one-shot base leaf digest"),
        );
    }

    #[test]
    fn streamed_phase_pair_leaf_digest_rejects_incomplete_reordered_and_surplus_values() {
        let context = context(ProofLeafVisibility::Public);
        let leaf = ProofOraclePhasePairLeaf::new(
            &context,
            0,
            None,
            vec![extension_value(0)],
            vec![extension_value(1)],
        )
        .expect("test leaf");

        let mut missing_first_value =
            ProofOraclePhasePairLeafDigestBuilder::new(&leaf).expect("digest builder initializes");
        assert_eq!(
            missing_first_value.begin_opposite_values(),
            Err(ProofMerkleError::InvalidLeaf),
        );

        let mut missing_opposite_value =
            ProofOraclePhasePairLeafDigestBuilder::new(&leaf).expect("digest builder initializes");
        missing_opposite_value
            .absorb_first_value(extension_value(0))
            .expect("declared first value");
        missing_opposite_value
            .begin_opposite_values()
            .expect("opposite row starts after the complete first row");
        assert_eq!(
            missing_opposite_value.finish(),
            Err(ProofMerkleError::InvalidLeaf),
        );

        let mut surplus_first_value =
            ProofOraclePhasePairLeafDigestBuilder::new(&leaf).expect("digest builder initializes");
        surplus_first_value
            .absorb_first_value(extension_value(0))
            .expect("declared first value");
        assert_eq!(
            surplus_first_value.absorb_first_value(extension_value(2)),
            Err(ProofMerkleError::InvalidLeaf),
        );

        let mut wrong_value_type =
            ProofOraclePhasePairLeafDigestBuilder::new(&leaf).expect("digest builder initializes");
        assert_eq!(
            wrong_value_type.absorb_first_value(ProofTreeValue::Base(ProofBaseFieldElement::ZERO,)),
            Err(ProofMerkleError::InvalidLeaf),
        );
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
                    changed[0][0] ^= 1;
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
                Some([0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
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
    fn frontier_accepts_equal_digests_at_distinct_derived_coordinates() {
        let context = context(ProofLeafVisibility::Public);
        let leaves = leaves(&context, ProofLeafVisibility::Public);
        let opened_leaf_digest = leaves[0].digest().expect("leaf digest");
        let repeated_frontier_digest = [0x5a_u8; 64];
        let context_hash = context.context_hash().expect("context hash");
        let mut reconstructed_root = opened_leaf_digest;
        for level in 1..=3 {
            reconstructed_root = proof_merkle_node_digest(
                context_hash,
                level,
                0,
                reconstructed_root,
                repeated_frontier_digest,
            )
            .expect("derived node digest");
        }

        verify_authentication_frontier(
            &context,
            &[(0, opened_leaf_digest)],
            &[repeated_frontier_digest; 3],
            reconstructed_root,
        )
        .expect("equal digest values have distinct verifier-derived coordinates");
    }

    #[test]
    fn frontier_rejects_reordered_distinct_digests() {
        let context = context(ProofLeafVisibility::Public);
        let leaves = leaves(&context, ProofLeafVisibility::Public);
        let opened_leaf_digest = leaves[0].digest().expect("leaf digest");
        let ordered_frontier = [[0x31_u8; 64], [0x42_u8; 64], [0x53_u8; 64]];
        let context_hash = context.context_hash().expect("context hash");
        let mut expected_root = opened_leaf_digest;
        for (level, frontier_digest) in (1..=3).zip(ordered_frontier) {
            expected_root =
                proof_merkle_node_digest(context_hash, level, 0, expected_root, frontier_digest)
                    .expect("derived node digest");
        }
        verify_authentication_frontier(
            &context,
            &[(0, opened_leaf_digest)],
            &ordered_frontier,
            expected_root,
        )
        .expect("ordered frontier verifies");

        let mut reordered_frontier = ordered_frontier;
        reordered_frontier.swap(0, 1);
        assert_eq!(
            verify_authentication_frontier(
                &context,
                &[(0, opened_leaf_digest)],
                &reordered_frontier,
                expected_root,
            ),
            Err(ProofMerkleError::RootMismatch),
        );
    }

    #[test]
    fn frontier_rejects_duplicate_openings_and_surplus_digests() {
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
        frontier.push([9_u8; 64]);
        assert!(verify_authentication_frontier(&context, &opened, &frontier, tree.root()).is_err());
    }
}
