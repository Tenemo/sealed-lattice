use std::collections::{BTreeMap, BTreeSet};

use super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_list_header, read_nested_tuple_list, read_u16,
    read_u32, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    FoundationSchemaError, Hash512, RefusalReason, hash512,
};

pub const PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x0103;
pub const PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x0104;
pub const PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER: u16 = 0x0105;
pub const PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER: u16 = 0x0106;
pub const PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0107;
pub const PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER: u16 = 0x0108;

const PROOF_COMMITMENT_SCHEMA_VERSION: u16 = 1;
const SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;
const PROOF_HEADER_HASH_DOMAIN: &str = "sealed-lattice/proof/header/v1";
const PROOF_TREE_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/tree-context/v1";
const PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/proof/merkle/phase-pair-leaf/v1";
const PROOF_MERKLE_NODE_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ProofMerkleTreeRole {
    NewBaseOracle = 1,
    AuxiliaryOracle = 2,
    RandomizedQuotientComponent = 3,
    OpeningBatchMask = 4,
    NonterminalFriLayer = 5,
}

impl ProofMerkleTreeRole {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::NewBaseOracle),
            2 => Some(Self::AuxiliaryOracle),
            3 => Some(Self::RandomizedQuotientComponent),
            4 => Some(Self::OpeningBatchMask),
            5 => Some(Self::NonterminalFriLayer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ProofLeafVisibility {
    Public = 1,
    SecretBearing = 2,
}

impl ProofLeafVisibility {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Public),
            2 => Some(Self::SecretBearing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofTreeValueKind {
    BaseField,
    ChallengeExtension,
}

impl ProofTreeValueKind {
    const fn canonical_item_type(self) -> CanonicalItemType {
        match self {
            Self::BaseField => CanonicalItemType::FieldElement,
            Self::ChallengeExtension => CanonicalItemType::ChallengeExtensionElement,
        }
    }
}

/// Verifier-derived framing for one relation plan's proof-tree values.
///
/// This profile is process-local and never serialized into a proof object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofTreeValueProfile {
    pub kind: ProofTreeValueKind,
    pub canonical_byte_length: usize,
}

impl ProofTreeValueProfile {
    pub fn new(
        kind: ProofTreeValueKind,
        canonical_byte_length: usize,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        if canonical_byte_length == 0 || canonical_byte_length > limits.maximum_item_byte_length {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof-tree value width is outside the configured profile",
            ));
        }
        Ok(Self {
            kind,
            canonical_byte_length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofTreeValue {
    kind: ProofTreeValueKind,
    canonical_bytes: Vec<u8>,
}

impl ProofTreeValue {
    pub fn new(
        profile: ProofTreeValueProfile,
        canonical_bytes: Vec<u8>,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        ProofTreeValueProfile::new(profile.kind, profile.canonical_byte_length, limits)?;
        if canonical_bytes.len() != profile.canonical_byte_length {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof-tree value has the wrong canonical width",
            ));
        }
        CanonicalItem::from_canonical_bytes(
            profile.kind.canonical_item_type(),
            canonical_bytes.clone(),
            limits,
        )?;
        Ok(Self {
            kind: profile.kind,
            canonical_bytes,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn canonical_item(&self) -> SchemaResult<CanonicalItem> {
        Ok(CanonicalItem::from_canonical_bytes(
            self.kind.canonical_item_type(),
            self.canonical_bytes.clone(),
            &CanonicalDecodeLimits::default(),
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofMerkleTreeContext {
    pub suite_id: Hash512,
    pub proof_header_hash: Hash512,
    pub application_statement_schema_identifier: u16,
    pub proof_field_index: u16,
    pub tree_role: ProofMerkleTreeRole,
    pub tree_ordinal: u16,
    pub domain_size: u64,
    pub row_width: u32,
    pub leaf_visibility: ProofLeafVisibility,
}

impl ProofMerkleTreeContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        suite_id: Hash512,
        proof_header_hash: Hash512,
        application_statement_schema_identifier: u16,
        proof_field_index: u16,
        tree_role: ProofMerkleTreeRole,
        tree_ordinal: u16,
        domain_size: u64,
        row_width: u32,
        leaf_visibility: ProofLeafVisibility,
    ) -> SchemaResult<Self> {
        if application_statement_schema_identifier == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof application-statement schema identifier is unassigned",
            ));
        }
        if domain_size < 2 || !domain_size.is_power_of_two() || row_width == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof tree domain and row width are invalid",
            ));
        }
        Ok(Self {
            suite_id,
            proof_header_hash,
            application_statement_schema_identifier,
            proof_field_index,
            tree_role,
            tree_ordinal,
            domain_size,
            row_width,
            leaf_visibility,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.suite_id,
            self.proof_header_hash,
            self.application_statement_schema_identifier,
            self.proof_field_index,
            self.tree_role,
            self.tree_ordinal,
            self.domain_size,
            self.row_width,
            self.leaf_visibility,
        )?;
        Ok(CanonicalTuple::new(
            PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER,
            PROOF_COMMITMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.proof_header_hash.into_bytes()),
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::unsigned16(self.proof_field_index),
                CanonicalItem::unsigned16(self.tree_role.canonical_code()),
                CanonicalItem::unsigned16(self.tree_ordinal),
                CanonicalItem::unsigned64(self.domain_size),
                CanonicalItem::unsigned32(self.row_width),
                CanonicalItem::unsigned16(self.leaf_visibility.canonical_code()),
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER, 9)?;
        let tree_role = ProofMerkleTreeRole::from_canonical_code(read_u16(&tuple.items[4])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof Merkle tree role is unassigned",
                )
            })?;
        let leaf_visibility =
            ProofLeafVisibility::from_canonical_code(read_u16(&tuple.items[8])?).ok_or_else(
                || {
                    schema_error(
                        RefusalReason::WrongTypeOrLength,
                        "proof leaf visibility is unassigned",
                    )
                },
            )?;
        Self::new(
            read_hash(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
            read_u16(&tuple.items[2])?,
            read_u16(&tuple.items[3])?,
            tree_role,
            read_u16(&tuple.items[5])?,
            read_u64(&tuple.items[6])?,
            read_u32(&tuple.items[7])?,
            leaf_visibility,
        )
    }

    pub fn context_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            PROOF_TREE_CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    pub const fn leaf_count(&self) -> u64 {
        self.domain_size / 2
    }

    pub const fn tree_height(&self) -> u32 {
        self.leaf_count().trailing_zeros()
    }
}

pub fn derive_proof_header_hash(
    canonical_proof_object_header_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        PROOF_HEADER_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(
            canonical_proof_object_header_bytes,
        )?],
    )?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOraclePhasePairLeaf {
    proof_tree_context_hash: Hash512,
    leaf_index: u64,
    leaf_visibility: ProofLeafVisibility,
    secret_salt: Option<[u8; SECRET_LEAF_SALT_BYTE_LENGTH]>,
    first_point_values: Vec<ProofTreeValue>,
    opposite_point_values: Vec<ProofTreeValue>,
}

impl ProofOraclePhasePairLeaf {
    pub fn new(
        context: &ProofMerkleTreeContext,
        leaf_index: u64,
        secret_salt: Option<[u8; SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Vec<ProofTreeValue>,
        opposite_point_values: Vec<ProofTreeValue>,
    ) -> SchemaResult<Self> {
        if leaf_index >= context.leaf_count() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf index is outside its tree domain",
            ));
        }
        validate_leaf_salt(context.leaf_visibility, secret_salt.as_ref())?;
        validate_leaf_value_shape(
            &first_point_values,
            &opposite_point_values,
            usize::try_from(context.row_width).map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "proof tree row width does not fit the runtime",
                )
            })?,
        )?;
        Ok(Self {
            proof_tree_context_hash: context.context_hash()?,
            leaf_index,
            leaf_visibility: context.leaf_visibility,
            secret_salt,
            first_point_values,
            opposite_point_values,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        validate_leaf_salt(self.leaf_visibility, self.secret_salt.as_ref())?;
        validate_leaf_value_shape(
            &self.first_point_values,
            &self.opposite_point_values,
            self.first_point_values.len(),
        )?;
        let value_kind = self.first_point_values[0].kind;
        let first_items = self
            .first_point_values
            .iter()
            .map(ProofTreeValue::canonical_item)
            .collect::<SchemaResult<Vec<_>>>()?;
        let opposite_items = self
            .opposite_point_values
            .iter()
            .map(ProofTreeValue::canonical_item)
            .collect::<SchemaResult<Vec<_>>>()?;
        let mut items = vec![
            CanonicalItem::hash512(self.proof_tree_context_hash.into_bytes()),
            CanonicalItem::unsigned64(self.leaf_index),
            CanonicalItem::unsigned16(self.leaf_visibility.canonical_code()),
        ];
        if let Some(secret_salt) = self.secret_salt {
            items.push(CanonicalItem::fixed_bytes(secret_salt)?);
        }
        items.push(CanonicalItem::homogeneous_list(
            value_kind.canonical_item_type(),
            &first_items,
        )?);
        items.push(CanonicalItem::homogeneous_list(
            value_kind.canonical_item_type(),
            &opposite_items,
        )?);
        Ok(CanonicalTuple::new(
            PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
            PROOF_COMMITMENT_SCHEMA_VERSION,
            items,
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        context: &ProofMerkleTreeContext,
        value_profile: ProofTreeValueProfile,
    ) -> SchemaResult<Self> {
        ProofTreeValueProfile::new(
            value_profile.kind,
            value_profile.canonical_byte_length,
            limits,
        )?;
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        let (visibility, first_value_list_index) = parse_leaf_header_and_visibility(&tuple)?;
        if read_hash(&tuple.items[0])? != context.context_hash()?
            || visibility != context.leaf_visibility
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "proof leaf does not match its verifier-derived tree context",
            ));
        }
        let secret_salt = match visibility {
            ProofLeafVisibility::Public => None,
            ProofLeafVisibility::SecretBearing => Some(read_fixed_bytes(&tuple.items[3])?),
        };
        let first_point_values = decode_value_list(
            &tuple.items[first_value_list_index],
            value_profile,
            context.row_width,
            limits,
        )?;
        let opposite_point_values = decode_value_list(
            &tuple.items[first_value_list_index + 1],
            value_profile,
            context.row_width,
            limits,
        )?;
        Self::new(
            context,
            read_u64(&tuple.items[1])?,
            secret_salt,
            first_point_values,
            opposite_point_values,
        )
    }

    fn from_canonical_tuple_without_relation_context(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        let (visibility, first_value_list_index) = parse_leaf_header_and_visibility(tuple)?;
        let secret_salt = match visibility {
            ProofLeafVisibility::Public => None,
            ProofLeafVisibility::SecretBearing => Some(read_fixed_bytes(&tuple.items[3])?),
        };
        let first_value_list = &tuple.items[first_value_list_index];
        let opposite_value_list = &tuple.items[first_value_list_index + 1];
        let (value_profile, value_count) =
            derive_unbound_value_list_profile(first_value_list, opposite_value_list, limits)?;
        let expected_count = u32::try_from(value_count).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof-tree value count does not fit u32",
            )
        })?;
        Ok(Self {
            proof_tree_context_hash: read_hash(&tuple.items[0])?,
            leaf_index: read_u64(&tuple.items[1])?,
            leaf_visibility: visibility,
            secret_salt,
            first_point_values: decode_value_list(
                first_value_list,
                value_profile,
                expected_count,
                limits,
            )?,
            opposite_point_values: decode_value_list(
                opposite_value_list,
                value_profile,
                expected_count,
                limits,
            )?,
        })
    }

    pub fn leaf_digest(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            PROOF_PHASE_PAIR_LEAF_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}
