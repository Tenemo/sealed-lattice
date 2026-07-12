use std::collections::{BTreeMap, BTreeSet};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    FoundationSchemaError, SchemaResult, read_fixed_bytes, read_hash, read_list_header,
    read_nested_tuple_list_with_budget, read_u16, read_u32, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    RefusalReason, hash512,
};

pub const PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x0103;
pub const PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x0104;
pub const PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER: u16 = 0x0105;
pub const PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER: u16 = 0x0106;
pub const PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0107;
pub const PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER: u16 = 0x0108;

const PROOF_COMMITMENT_SCHEMA_VERSION: u16 = 1;
const SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;

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

/// Verifier-derived framing for one relation plan's proof-tree values. It is
/// not serialized in the proof and therefore cannot select an algorithm.
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

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER, 9)?;
        let tree_role = ProofMerkleTreeRole::from_canonical_code(read_u16(&tuple.items[4])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof Merkle-tree role is unassigned",
                )
            })?;
        let leaf_visibility = ProofLeafVisibility::from_canonical_code(read_u16(&tuple.items[8])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof leaf visibility is unassigned",
                )
            })?;
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

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }

    pub fn context_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/proof/merkle/tree-context/v1",
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
        "sealed-lattice/proof/header/v1",
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
                "proof leaf index is outside the tree",
            ));
        }
        match (context.leaf_visibility, secret_salt) {
            (ProofLeafVisibility::Public, None) | (ProofLeafVisibility::SecretBearing, Some(_)) => {
            }
            _ => {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof leaf salt does not match its visibility",
                ));
            }
        }
        let expected_row_width = usize::try_from(context.row_width).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof row width does not fit the runtime",
            )
        })?;
        if first_point_values.len() != expected_row_width
            || opposite_point_values.len() != expected_row_width
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf value count does not match the tree row width",
            ));
        }
        let Some(first_value) = first_point_values.first() else {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf row is empty",
            ));
        };
        let value_kind = first_value.kind;
        let value_byte_length = first_value.canonical_bytes.len();
        if first_point_values
            .iter()
            .chain(opposite_point_values.iter())
            .any(|value| {
                value.kind != value_kind || value.canonical_bytes.len() != value_byte_length
            })
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf values do not share one relation-derived encoding",
            ));
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

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        let value_kind = self
            .first_point_values
            .first()
            .ok_or_else(|| {
                schema_error(RefusalReason::WrongTypeOrLength, "proof leaf row is empty")
            })?
            .kind;
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
        if tuple.schema_identifier != PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER
            || !matches!(tuple.items.len(), 5 | 6)
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf has the wrong schema or item count",
            ));
        }
        if tuple.schema_version != PROOF_COMMITMENT_SCHEMA_VERSION {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "proof leaf schema version is unsupported",
            ));
        }
        let visibility = ProofLeafVisibility::from_canonical_code(read_u16(&tuple.items[2])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof leaf visibility is unassigned",
                )
            })?;
        let expected_item_count = match visibility {
            ProofLeafVisibility::Public => 5,
            ProofLeafVisibility::SecretBearing => 6,
        };
        require_header(
            &tuple,
            PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
            expected_item_count,
        )?;
        if read_hash(&tuple.items[0])? != context.context_hash()?
            || visibility != context.leaf_visibility
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "proof leaf does not match its verifier-derived tree context",
            ));
        }
        let leaf_index = read_u64(&tuple.items[1])?;
        let (secret_salt, first_index) = match visibility {
            ProofLeafVisibility::Public => (None, 3),
            ProofLeafVisibility::SecretBearing => (Some(read_fixed_bytes(&tuple.items[3])?), 4),
        };
        let first_point_values = decode_value_list(
            &tuple.items[first_index],
            value_profile,
            context.row_width,
            limits,
        )?;
        let opposite_point_values = decode_value_list(
            &tuple.items[first_index + 1],
            value_profile,
            context.row_width,
            limits,
        )?;
        Self::new(
            context,
            leaf_index,
            secret_salt,
            first_point_values,
            opposite_point_values,
        )
    }

    fn from_canonical_tuple_without_relation_context(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        if tuple.schema_identifier != PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER
            || !matches!(tuple.items.len(), 5 | 6)
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf has the wrong schema or item count",
            ));
        }
        let visibility = ProofLeafVisibility::from_canonical_code(read_u16(&tuple.items[2])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof leaf visibility is unassigned",
                )
            })?;
        let expected_item_count = match visibility {
            ProofLeafVisibility::Public => 5,
            ProofLeafVisibility::SecretBearing => 6,
        };
        require_header(
            tuple,
            PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
            expected_item_count,
        )?;
        let (secret_salt, first_value_list_index) = match visibility {
            ProofLeafVisibility::Public => (None, 3),
            ProofLeafVisibility::SecretBearing => (Some(read_fixed_bytes(&tuple.items[3])?), 4),
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
            "sealed-lattice/proof/merkle/phase-pair-leaf/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofMerkleNode {
    proof_tree_context_hash: Hash512,
    level: u32,
    node_index: u64,
    left_child_digest: Hash512,
    right_child_digest: Hash512,
}

impl ProofMerkleNode {
    pub fn new(
        context: &ProofMerkleTreeContext,
        level: u32,
        node_index: u64,
        left_child_digest: Hash512,
        right_child_digest: Hash512,
    ) -> SchemaResult<Self> {
        if level == 0 || level > context.tree_height() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof Merkle-node level is outside the tree",
            ));
        }
        let node_count = context.leaf_count() >> level;
        if node_index >= node_count {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof Merkle-node index is outside its level",
            ));
        }
        Ok(Self {
            proof_tree_context_hash: context.context_hash()?,
            level,
            node_index,
            left_child_digest,
            right_child_digest,
        })
    }

    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER,
            PROOF_COMMITMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.proof_tree_context_hash.into_bytes()),
                CanonicalItem::unsigned32(self.level),
                CanonicalItem::unsigned64(self.node_index),
                CanonicalItem::hash512(self.left_child_digest.into_bytes()),
                CanonicalItem::hash512(self.right_child_digest.into_bytes()),
            ],
        )
    }

    fn from_tuple(tuple: &CanonicalTuple, context: &ProofMerkleTreeContext) -> SchemaResult<Self> {
        require_header(tuple, PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER, 5)?;
        if read_hash(&tuple.items[0])? != context.context_hash()? {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "proof Merkle node has the wrong tree context",
            ));
        }
        Self::new(
            context,
            read_u32(&tuple.items[1])?,
            read_u64(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_hash(&tuple.items[4])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple().encode()?)
    }

    pub fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        context: &ProofMerkleTreeContext,
    ) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?, context)
    }

    fn from_canonical_tuple_without_tree_context(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER, 5)?;
        Ok(Self {
            proof_tree_context_hash: read_hash(&tuple.items[0])?,
            level: read_u32(&tuple.items[1])?,
            node_index: read_u64(&tuple.items[2])?,
            left_child_digest: read_hash(&tuple.items[3])?,
            right_child_digest: read_hash(&tuple.items[4])?,
        })
    }

    pub fn node_digest(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/proof/merkle/node/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofAuthenticationNode {
    pub level: u32,
    pub node_index: u64,
    pub node_digest: Hash512,
}

impl ProofAuthenticationNode {
    pub const fn new(level: u32, node_index: u64, node_digest: Hash512) -> Self {
        Self {
            level,
            node_index,
            node_digest,
        }
    }

    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER,
            PROOF_COMMITMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.level),
                CanonicalItem::unsigned64(self.node_index),
                CanonicalItem::hash512(self.node_digest.into_bytes()),
            ],
        )
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER, 3)?;
        Ok(Self::new(
            read_u32(&tuple.items[0])?,
            read_u64(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple().encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofQueryOpeningRecord {
    pub tree_catalog_index: u16,
    pub canonical_opened_leaves: Vec<Vec<u8>>,
}

impl ProofQueryOpeningRecord {
    pub fn new(
        tree_catalog_index: u16,
        canonical_opened_leaves: Vec<Vec<u8>>,
    ) -> SchemaResult<Self> {
        if canonical_opened_leaves.is_empty() || canonical_opened_leaves.iter().any(Vec::is_empty) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof opening must contain nonempty canonical leaves",
            ));
        }
        Ok(Self {
            tree_catalog_index,
            canonical_opened_leaves,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.tree_catalog_index,
            self.canonical_opened_leaves.clone(),
        )?;
        let leaves = self
            .canonical_opened_leaves
            .iter()
            .map(CanonicalItem::variable_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CanonicalTuple::new(
            PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER,
            PROOF_COMMITMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.tree_catalog_index),
                CanonicalItem::homogeneous_list(CanonicalItemType::RawBytes, &leaves)?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER, 2)?;
        Self::new(
            read_u16(&tuple.items[0])?,
            decode_variable_byte_list(&tuple.items[1], limits)?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofAuthenticationFrontier {
    pub tree_catalog_index: u16,
    pub authentication_nodes: Vec<ProofAuthenticationNode>,
}

impl ProofAuthenticationFrontier {
    pub fn new(
        tree_catalog_index: u16,
        authentication_nodes: Vec<ProofAuthenticationNode>,
    ) -> SchemaResult<Self> {
        if authentication_nodes
            .windows(2)
            .any(|pair| (pair[0].level, pair[0].node_index) >= (pair[1].level, pair[1].node_index))
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof authentication nodes must be strictly ordered and duplicate-free",
            ));
        }
        Ok(Self {
            tree_catalog_index,
            authentication_nodes,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.tree_catalog_index, self.authentication_nodes.clone())?;
        let nodes = self
            .authentication_nodes
            .iter()
            .map(|node| CanonicalItem::nested_tuple(&node.canonical_tuple()).map_err(Into::into))
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
            PROOF_COMMITMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.tree_catalog_index),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &nodes)?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(super) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER, 2)?;
        let nodes = read_nested_tuple_list_with_budget(&tuple.items[1], limits, budget)?
            .iter()
            .map(ProofAuthenticationNode::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(read_u16(&tuple.items[0])?, nodes)
    }
}

/// Verifies one common proof-created tree opening using only the expected leaf
/// indexes, the canonical opened leaves, and the minimal authentication
/// frontier. Statement-owned trees use their relation-specific leaf and node
/// equations instead.
pub struct CommonProofTreeOpeningVerification<'input> {
    pub context: &'input ProofMerkleTreeContext,
    pub expected_tree_catalog_index: u16,
    pub expected_root: Hash512,
    pub expected_leaf_indexes: &'input [u64],
    pub opening: &'input ProofQueryOpeningRecord,
    pub frontier: &'input ProofAuthenticationFrontier,
    pub value_profile: ProofTreeValueProfile,
    pub limits: &'input CanonicalDecodeLimits,
}

pub fn verify_common_proof_tree_opening(
    input: CommonProofTreeOpeningVerification<'_>,
) -> SchemaResult<()> {
    let CommonProofTreeOpeningVerification {
        context,
        expected_tree_catalog_index,
        expected_root,
        expected_leaf_indexes,
        opening,
        frontier,
        value_profile,
        limits,
    } = input;
    if opening.tree_catalog_index != expected_tree_catalog_index
        || frontier.tree_catalog_index != expected_tree_catalog_index
    {
        return Err(schema_error(
            RefusalReason::WrongContext,
            "proof opening and authentication frontier target the wrong tree catalog entry",
        ));
    }
    if expected_leaf_indexes.is_empty()
        || expected_leaf_indexes.len() != opening.canonical_opened_leaves.len()
        || expected_leaf_indexes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || expected_leaf_indexes
            .iter()
            .any(|leaf_index| *leaf_index >= context.leaf_count())
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof opening leaf indexes do not match the derived query closure",
        ));
    }

    let mut known_nodes = BTreeMap::new();
    for (expected_leaf_index, canonical_leaf) in expected_leaf_indexes
        .iter()
        .copied()
        .zip(opening.canonical_opened_leaves.iter())
    {
        let leaf =
            ProofOraclePhasePairLeaf::decode(canonical_leaf, limits, context, value_profile)?;
        if leaf.leaf_index() != expected_leaf_index {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof opened leaves are not in the derived index order",
            ));
        }
        known_nodes.insert(expected_leaf_index, leaf.leaf_digest()?);
    }

    let mut frontier_nodes = BTreeMap::new();
    for node in &frontier.authentication_nodes {
        if node.level > context.tree_height()
            || node.node_index >= (context.leaf_count() >> node.level)
            || frontier_nodes
                .insert((node.level, node.node_index), node.node_digest)
                .is_some()
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof authentication frontier contains an invalid node coordinate",
            ));
        }
    }

    for level in 0..context.tree_height() {
        let parent_indexes = known_nodes
            .keys()
            .map(|node_index| node_index / 2)
            .collect::<BTreeSet<_>>();
        let mut parent_nodes = BTreeMap::new();
        for parent_index in parent_indexes {
            let left_index = parent_index.checked_mul(2).ok_or_else(|| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "proof Merkle child index overflows",
                )
            })?;
            let right_index = left_index + 1;
            let left_digest = known_nodes
                .get(&left_index)
                .copied()
                .or_else(|| frontier_nodes.remove(&(level, left_index)));
            let right_digest = known_nodes
                .get(&right_index)
                .copied()
                .or_else(|| frontier_nodes.remove(&(level, right_index)));
            let (Some(left_digest), Some(right_digest)) = (left_digest, right_digest) else {
                return Err(schema_error(
                    RefusalReason::WrongHashOrRoot,
                    "proof authentication frontier is missing a required sibling",
                ));
            };
            let parent =
                ProofMerkleNode::new(context, level + 1, parent_index, left_digest, right_digest)?;
            parent_nodes.insert(parent_index, parent.node_digest()?);
        }
        known_nodes = parent_nodes;
    }

    if !frontier_nodes.is_empty()
        || known_nodes.len() != 1
        || known_nodes.get(&0).copied() != Some(expected_root)
    {
        return Err(schema_error(
            RefusalReason::WrongHashOrRoot,
            "proof authentication frontier does not yield the expected sole root",
        ));
    }
    Ok(())
}

pub(crate) fn reencode_canonical_proof_commitment_object(
    schema_identifier: u16,
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<u8>> {
    match schema_identifier {
        PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER => {
            ProofMerkleTreeContext::decode(bytes, limits)?.encode()
        }
        PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER => {
            let tuple = CanonicalTuple::decode(bytes, limits)?;
            ProofOraclePhasePairLeaf::from_canonical_tuple_without_relation_context(&tuple, limits)?
                .encode()
        }
        PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER => {
            let tuple = CanonicalTuple::decode(bytes, limits)?;
            ProofMerkleNode::from_canonical_tuple_without_tree_context(&tuple)?.encode()
        }
        PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER => {
            let tuple = CanonicalTuple::decode(bytes, limits)?;
            ProofAuthenticationNode::from_tuple(&tuple)?.encode()
        }
        PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER => {
            ProofQueryOpeningRecord::decode(bytes, limits)?.encode()
        }
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER => {
            ProofAuthenticationFrontier::decode(bytes, limits)?.encode()
        }
        _ => Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "canonical object is not a proof commitment schema",
        )),
    }
}

fn derive_unbound_value_list_profile(
    first_value_list: &CanonicalItem,
    opposite_value_list: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<(ProofTreeValueProfile, usize)> {
    if first_value_list.item_type() != CanonicalItemType::HomogeneousList
        || opposite_value_list.item_type() != CanonicalItemType::HomogeneousList
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof leaf values must use homogeneous lists",
        ));
    }
    let element_type = first_value_list
        .canonical_bytes()
        .get(..2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .and_then(CanonicalItemType::from_canonical_code)
        .ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "proof leaf value-list element type is malformed",
            )
        })?;
    let value_kind = match element_type {
        CanonicalItemType::FieldElement => ProofTreeValueKind::BaseField,
        CanonicalItemType::ChallengeExtensionElement => ProofTreeValueKind::ChallengeExtension,
        _ => {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof leaf value-list element type is unsupported",
            ));
        }
    };
    let (first_count, first_bytes) = read_list_header(first_value_list, element_type)?;
    let (opposite_count, opposite_bytes) = read_list_header(opposite_value_list, element_type)?;
    if first_count == 0
        || first_count != opposite_count
        || first_bytes.len() != opposite_bytes.len()
        || first_bytes.len() % first_count != 0
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof leaf value lists must have one shared nonempty shape",
        ));
    }
    let value_byte_length = first_bytes.len() / first_count;
    let value_profile = ProofTreeValueProfile::new(value_kind, value_byte_length, limits)?;
    Ok((value_profile, first_count))
}

fn decode_value_list(
    item: &CanonicalItem,
    profile: ProofTreeValueProfile,
    expected_count: u32,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<ProofTreeValue>> {
    let (count, bytes) = read_list_header(item, profile.kind.canonical_item_type())?;
    let expected_count = usize::try_from(expected_count).map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof-tree row count does not fit the runtime",
        )
    })?;
    if count != expected_count || count > limits.maximum_item_count {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof-tree value count does not match the relation plan",
        ));
    }
    let expected_byte_length = count
        .checked_mul(profile.canonical_byte_length)
        .ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "proof-tree value list length overflows",
            )
        })?;
    if bytes.len() != expected_byte_length {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof-tree value-list payload has the wrong length",
        ));
    }
    bytes
        .chunks_exact(profile.canonical_byte_length)
        .map(|value| ProofTreeValue::new(profile, value.to_vec(), limits))
        .collect()
}

fn decode_variable_byte_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<Vec<u8>>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::RawBytes)?;
    if count > limits.maximum_item_count {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof opening leaf count exceeds the configured limit",
        ));
    }
    let mut values = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let length_end = offset.checked_add(4).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "proof opening leaf length offset overflows",
            )
        })?;
        let length_bytes: [u8; 4] = bytes
            .get(offset..length_end)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "proof opening leaf length is truncated",
                )
            })?;
        let byte_length = u32::from_le_bytes(length_bytes) as usize;
        if byte_length == 0 || byte_length > limits.maximum_item_byte_length {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof opening leaf length is outside the configured limit",
            ));
        }
        let value_end = length_end.checked_add(byte_length).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "proof opening leaf end offset overflows",
            )
        })?;
        let value = bytes.get(length_end..value_end).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "proof opening leaf is truncated",
            )
        })?;
        values.push(value.to_vec());
        offset = value_end;
    }
    if offset != bytes.len() {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "proof opening leaf list contains trailing bytes",
        ));
    }
    Ok(values)
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; 64])
    }

    fn context(visibility: ProofLeafVisibility) -> ProofMerkleTreeContext {
        ProofMerkleTreeContext::new(
            hash(1),
            hash(2),
            0x1302,
            0,
            ProofMerkleTreeRole::NewBaseOracle,
            0,
            8,
            1,
            visibility,
        )
        .expect("test context is valid")
    }

    fn value_profile() -> ProofTreeValueProfile {
        ProofTreeValueProfile::new(
            ProofTreeValueKind::BaseField,
            8,
            &CanonicalDecodeLimits::default(),
        )
        .expect("test value profile is valid")
    }

    fn leaf(context: &ProofMerkleTreeContext, leaf_index: u64) -> ProofOraclePhasePairLeaf {
        let profile = value_profile();
        let first = ProofTreeValue::new(
            profile,
            (leaf_index + 1).to_le_bytes().to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .expect("first value is canonical");
        let opposite = ProofTreeValue::new(
            profile,
            (leaf_index + 101).to_le_bytes().to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .expect("opposite value is canonical");
        ProofOraclePhasePairLeaf::new(
            context,
            leaf_index,
            match context.leaf_visibility {
                ProofLeafVisibility::Public => None,
                ProofLeafVisibility::SecretBearing => Some([leaf_index as u8; 48]),
            },
            vec![first],
            vec![opposite],
        )
        .expect("test leaf is valid")
    }

    #[test]
    fn context_and_both_leaf_visibilities_round_trip_canonically() {
        for visibility in [
            ProofLeafVisibility::Public,
            ProofLeafVisibility::SecretBearing,
        ] {
            let context = context(visibility);
            let context_bytes = context.encode().expect("context encodes");
            assert_eq!(
                ProofMerkleTreeContext::decode(&context_bytes, &CanonicalDecodeLimits::default())
                    .expect("context decodes"),
                context
            );

            let leaf = leaf(&context, 3);
            let leaf_bytes = leaf.encode().expect("leaf encodes");
            assert_eq!(
                ProofOraclePhasePairLeaf::decode(
                    &leaf_bytes,
                    &CanonicalDecodeLimits::default(),
                    &context,
                    value_profile(),
                )
                .expect("leaf decodes"),
                leaf
            );
        }
    }

    #[test]
    fn leaf_context_salt_width_and_value_profile_mismatches_refuse() {
        let public_context = context(ProofLeafVisibility::Public);
        let secret_context = context(ProofLeafVisibility::SecretBearing);
        let public_leaf_bytes = leaf(&public_context, 0).encode().expect("leaf encodes");
        assert_eq!(
            ProofOraclePhasePairLeaf::decode(
                &public_leaf_bytes,
                &CanonicalDecodeLimits::default(),
                &secret_context,
                value_profile(),
            )
            .expect_err("cross-context leaf must refuse")
            .refusal_reason,
            RefusalReason::WrongContext
        );
        let wrong_width = ProofTreeValueProfile::new(
            ProofTreeValueKind::BaseField,
            7,
            &CanonicalDecodeLimits::default(),
        )
        .expect("alternate width is structurally valid");
        assert_eq!(
            ProofOraclePhasePairLeaf::decode(
                &public_leaf_bytes,
                &CanonicalDecodeLimits::default(),
                &public_context,
                wrong_width,
            )
            .expect_err("wrong relation width must refuse")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
        assert!(
            ProofOraclePhasePairLeaf::new(
                &public_context,
                0,
                Some([7; 48]),
                vec![
                    ProofTreeValue::new(
                        value_profile(),
                        vec![1; 8],
                        &CanonicalDecodeLimits::default()
                    )
                    .expect("value")
                ],
                vec![
                    ProofTreeValue::new(
                        value_profile(),
                        vec![2; 8],
                        &CanonicalDecodeLimits::default()
                    )
                    .expect("value")
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn minimal_frontier_authenticates_exactly_the_opened_leaf_set() {
        let context = context(ProofLeafVisibility::Public);
        let leaves = (0..4)
            .map(|leaf_index| leaf(&context, leaf_index))
            .collect::<Vec<_>>();
        let leaf_digests = leaves
            .iter()
            .map(ProofOraclePhasePairLeaf::leaf_digest)
            .collect::<SchemaResult<Vec<_>>>()
            .expect("leaf digests derive");
        let left_parent = ProofMerkleNode::new(&context, 1, 0, leaf_digests[0], leaf_digests[1])
            .expect("left parent")
            .node_digest()
            .expect("left digest");
        let right_parent = ProofMerkleNode::new(&context, 1, 1, leaf_digests[2], leaf_digests[3])
            .expect("right parent")
            .node_digest()
            .expect("right digest");
        let root = ProofMerkleNode::new(&context, 2, 0, left_parent, right_parent)
            .expect("root node")
            .node_digest()
            .expect("root digest");

        let opening = ProofQueryOpeningRecord::new(
            4,
            vec![
                leaves[0].encode().expect("leaf zero encodes"),
                leaves[3].encode().expect("leaf three encodes"),
            ],
        )
        .expect("opening is valid");
        let frontier = ProofAuthenticationFrontier::new(
            4,
            vec![
                ProofAuthenticationNode::new(0, 1, leaf_digests[1]),
                ProofAuthenticationNode::new(0, 2, leaf_digests[2]),
            ],
        )
        .expect("frontier is ordered");
        verify_common_proof_tree_opening(CommonProofTreeOpeningVerification {
            context: &context,
            expected_tree_catalog_index: 4,
            expected_root: root,
            expected_leaf_indexes: &[0, 3],
            opening: &opening,
            frontier: &frontier,
            value_profile: value_profile(),
            limits: &CanonicalDecodeLimits::default(),
        })
        .expect("minimal frontier authenticates");

        let relabelled_opening =
            ProofQueryOpeningRecord::new(5, opening.canonical_opened_leaves.clone())
                .expect("relabelled opening is structurally valid");
        let relabelled_frontier =
            ProofAuthenticationFrontier::new(5, frontier.authentication_nodes.clone())
                .expect("relabelled frontier is structurally valid");
        assert_eq!(
            verify_common_proof_tree_opening(CommonProofTreeOpeningVerification {
                context: &context,
                expected_tree_catalog_index: 4,
                expected_root: root,
                expected_leaf_indexes: &[0, 3],
                opening: &relabelled_opening,
                frontier: &relabelled_frontier,
                value_profile: value_profile(),
                limits: &CanonicalDecodeLimits::default(),
            })
            .expect_err("verifier-derived tree catalog index must bind the pair")
            .refusal_reason,
            RefusalReason::WrongContext
        );

        for invalid_frontier in [
            ProofAuthenticationFrontier::new(
                4,
                vec![ProofAuthenticationNode::new(0, 1, leaf_digests[1])],
            )
            .expect("missing frontier is structurally valid"),
            ProofAuthenticationFrontier::new(
                4,
                vec![
                    ProofAuthenticationNode::new(0, 1, leaf_digests[1]),
                    ProofAuthenticationNode::new(0, 2, leaf_digests[2]),
                    ProofAuthenticationNode::new(1, 0, left_parent),
                ],
            )
            .expect("extra frontier is structurally valid"),
        ] {
            assert_eq!(
                verify_common_proof_tree_opening(CommonProofTreeOpeningVerification {
                    context: &context,
                    expected_tree_catalog_index: 4,
                    expected_root: root,
                    expected_leaf_indexes: &[0, 3],
                    opening: &opening,
                    frontier: &invalid_frontier,
                    value_profile: value_profile(),
                    limits: &CanonicalDecodeLimits::default(),
                })
                .expect_err("non-minimal frontier must refuse")
                .refusal_reason,
                RefusalReason::WrongHashOrRoot
            );
        }
    }

    #[test]
    fn opening_and_frontier_round_trip_and_reject_disorder_or_trailing_bytes() {
        let context = context(ProofLeafVisibility::Public);
        let opening = ProofQueryOpeningRecord::new(
            2,
            vec![leaf(&context, 1).encode().expect("leaf encodes")],
        )
        .expect("opening");
        assert_eq!(
            ProofQueryOpeningRecord::decode(
                &opening.encode().expect("opening encodes"),
                &CanonicalDecodeLimits::default()
            )
            .expect("opening decodes"),
            opening
        );

        let frontier = ProofAuthenticationFrontier::new(
            2,
            vec![
                ProofAuthenticationNode::new(0, 0, hash(8)),
                ProofAuthenticationNode::new(1, 1, hash(9)),
            ],
        )
        .expect("frontier");
        assert_eq!(
            ProofAuthenticationFrontier::decode(
                &frontier.encode().expect("frontier encodes"),
                &CanonicalDecodeLimits::default()
            )
            .expect("frontier decodes"),
            frontier
        );
        assert!(
            ProofAuthenticationFrontier::new(
                2,
                vec![
                    ProofAuthenticationNode::new(1, 1, hash(9)),
                    ProofAuthenticationNode::new(0, 0, hash(8)),
                ],
            )
            .is_err()
        );

        let mut trailing = opening.encode().expect("opening encodes");
        trailing.push(0);
        assert!(
            ProofQueryOpeningRecord::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );
    }
}
