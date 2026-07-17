use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
};

use crate::foundation::{CanonicalItem, CanonicalItemType, hash_foundation_tuple_512};

use super::{
    decoder::{BoundedProofDecoder, ProofByteSource, ProofDecodeError},
    field::ProofChallengeExtensionElement,
    merkle::{
        ProofAuthenticationNode, ProofLeafVisibility, ProofMerkleError, ProofMerkleTreeContext,
        ProofOraclePhasePairLeaf, ProofTreeRole, ProofTreeValue, verify_authentication_frontier,
    },
    transcript::{
        CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber, CommonProofTranscriptSchedule,
        TranscriptError,
    },
};

const PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0107;
const PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER: u16 = 0x0108;
const PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER: u16 = 0x0106;
const PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x0104;
const COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x2102;
const SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x121c;
const SCHEMA_VERSION: u16 = 1;
const SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;
const COMMITTED_MATERIAL_ROW_WIDTH: u32 = 4;
const AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH: usize = 102;
const MAXIMUM_TREE_CATALOG_ENTRY_COUNT: usize = u16::MAX as usize + 1;

const COMMITTED_MATERIAL_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/phase-pair-leaf/v1";
const COMMITTED_MATERIAL_NODE_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/merkle-node/v1";
const SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-polynomial/phase-pair-leaf/v1";
const SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-polynomial/merkle-node/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofBodyError {
    Decode(ProofDecodeError),
    Merkle(ProofMerkleError),
    Transcript(TranscriptError),
    CanonicalEncoding,
    InvalidCatalog,
    CatalogTooLarge,
    CountOverflow,
    AllocationLimitExceeded,
    InvalidQueryRepresentatives,
    InvalidSchema,
    InvalidSchemaVersion,
    InvalidItemCount,
    InvalidItemType,
    InvalidItemLength,
    InvalidListCount,
    InvalidTreeCatalogIndex,
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

impl From<TranscriptError> for ProofBodyError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
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
pub(crate) struct ProofTreeCatalogInput {
    pub(crate) suite_identifier: [u8; 64],
    pub(crate) canonical_proof_object_header_bytes: Vec<u8>,
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) proof_field_index: u16,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofTreeCatalogSource {
    RelationProofCreated {
        tree_role: ProofTreeRole,
        tree_ordinal: u16,
    },
    RelationBoundPublic,
    QuotientComponent {
        component_ordinal: u16,
    },
    OpeningBatchMask,
    NonterminalFriLayer {
        fold_ordinal: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProofTreeConstruction {
    Common(ProofMerkleTreeContext),
    CommittedMaterial {
        material_context_hash: [u8; 64],
    },
    SetupPolynomial {
        public_polynomial_context_hash: [u8; 64],
        row_width: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofTreeCatalogEntry {
    tree_catalog_index: u16,
    source: ProofTreeCatalogSource,
    construction: ProofTreeConstruction,
    bound_root: Option<[u8; 64]>,
}

impl ProofTreeCatalogEntry {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn source(&self) -> ProofTreeCatalogSource {
        self.source
    }

    pub(crate) fn common_context(&self) -> Option<&ProofMerkleTreeContext> {
        match &self.construction {
            ProofTreeConstruction::Common(context) => Some(context),
            ProofTreeConstruction::CommittedMaterial { .. }
            | ProofTreeConstruction::SetupPolynomial { .. } => None,
        }
    }

    fn leaf_count(&self) -> Result<usize, ProofBodyError> {
        match &self.construction {
            ProofTreeConstruction::Common(context) => Ok(context.leaf_count()?),
            ProofTreeConstruction::CommittedMaterial { .. }
            | ProofTreeConstruction::SetupPolynomial { .. } => Err(ProofBodyError::InvalidCatalog),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompleteProofTreeCatalog {
    evaluation_domain_size: u64,
    entries: Vec<ProofTreeCatalogEntry>,
}

impl CompleteProofTreeCatalog {
    pub(crate) fn entries(&self) -> &[ProofTreeCatalogEntry] {
        &self.entries
    }

    pub(crate) const fn evaluation_domain_size(&self) -> u64 {
        self.evaluation_domain_size
    }
}

pub(crate) fn build_complete_proof_tree_catalog(
    input: ProofTreeCatalogInput,
    transcript_schedule: &CommonProofTranscriptSchedule,
) -> Result<CompleteProofTreeCatalog, ProofBodyError> {
    if input.canonical_proof_object_header_bytes.is_empty()
        || input.relation_trees.is_empty()
        || input.evaluation_domain_size < 2
        || !input.evaluation_domain_size.is_power_of_two()
        || transcript_schedule.query_orbit_count() != input.evaluation_domain_size / 2
    {
        return Err(ProofBodyError::InvalidCatalog);
    }

    let proof_header_hash = hash_foundation_tuple_512(
        "sealed-lattice/proof/header/v1",
        &[
            CanonicalItem::variable_bytes(&input.canonical_proof_object_header_bytes)
                .map_err(|_| ProofBodyError::CanonicalEncoding)?,
        ],
    )
    .map_err(|_| ProofBodyError::CanonicalEncoding)?
    .into_bytes();

    let quotient_component_count = usize::from(transcript_schedule.quotient_component_count());
    let nonterminal_fri_tree_count = usize::from(transcript_schedule.fri_fold_count() - 1);
    let opening_batch_tree_count =
        if transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing {
            1
        } else {
            0
        };
    let total_tree_count = input
        .relation_trees
        .len()
        .checked_add(quotient_component_count)
        .and_then(|count| count.checked_add(opening_batch_tree_count))
        .and_then(|count| count.checked_add(nonterminal_fri_tree_count))
        .ok_or(ProofBodyError::CountOverflow)?;
    if total_tree_count > MAXIMUM_TREE_CATALOG_ENTRY_COUNT {
        return Err(ProofBodyError::CatalogTooLarge);
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(total_tree_count)
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    let mut base_tree_count = 0_usize;
    let mut auxiliary_tree_count = 0_usize;
    let mut ordered_base_tree_ordinals = Vec::new();
    let mut ordered_auxiliary_tree_ordinals = Vec::new();

    for relation_tree in &input.relation_trees {
        match relation_tree {
            RelationProofTreeInput::ProofCreated {
                tree_role,
                row_width,
                leaf_visibility,
            } => {
                if *row_width == 0
                    || !matches!(
                        tree_role,
                        ProofTreeRole::BaseOracle | ProofTreeRole::AuxiliaryOracle
                    )
                    || (transcript_schedule.privacy_mode() == CommonProofPrivacyMode::PublicOnly
                        && *leaf_visibility != ProofLeafVisibility::Public)
                {
                    return Err(ProofBodyError::InvalidCatalog);
                }
                let role_count = match tree_role {
                    ProofTreeRole::BaseOracle => &mut base_tree_count,
                    ProofTreeRole::AuxiliaryOracle => &mut auxiliary_tree_count,
                    ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer => {
                        return Err(ProofBodyError::InvalidCatalog);
                    }
                };
                let tree_ordinal =
                    u16::try_from(*role_count).map_err(|_| ProofBodyError::CatalogTooLarge)?;
                *role_count = (*role_count)
                    .checked_add(1)
                    .ok_or(ProofBodyError::CountOverflow)?;
                match tree_role {
                    ProofTreeRole::BaseOracle => ordered_base_tree_ordinals.push(tree_ordinal),
                    ProofTreeRole::AuxiliaryOracle => {
                        ordered_auxiliary_tree_ordinals.push(tree_ordinal)
                    }
                    ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer => {
                        return Err(ProofBodyError::InvalidCatalog);
                    }
                }
                let context = common_tree_context(
                    &input,
                    proof_header_hash,
                    *tree_role,
                    tree_ordinal,
                    input.evaluation_domain_size,
                    *row_width,
                    *leaf_visibility,
                )?;
                push_catalog_entry(
                    &mut entries,
                    ProofTreeCatalogSource::RelationProofCreated {
                        tree_role: *tree_role,
                        tree_ordinal,
                    },
                    ProofTreeConstruction::Common(context),
                    None,
                )?;
            }
            RelationProofTreeInput::BoundPublic(statement_tree) => match statement_tree {
                StatementOwnedProofTreeInput::CommittedMaterial {
                    material_context_hash,
                    expected_root,
                } => push_catalog_entry(
                    &mut entries,
                    ProofTreeCatalogSource::RelationBoundPublic,
                    ProofTreeConstruction::CommittedMaterial {
                        material_context_hash: *material_context_hash,
                    },
                    Some(*expected_root),
                )?,
                StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash,
                    row_width,
                    expected_root,
                } => {
                    if *row_width == 0 {
                        return Err(ProofBodyError::InvalidCatalog);
                    }
                    push_catalog_entry(
                        &mut entries,
                        ProofTreeCatalogSource::RelationBoundPublic,
                        ProofTreeConstruction::SetupPolynomial {
                            public_polynomial_context_hash: *public_polynomial_context_hash,
                            row_width: *row_width,
                        },
                        Some(*expected_root),
                    )?;
                }
            },
        }
    }

    if ordered_base_tree_ordinals.as_slice() != transcript_schedule.ordered_base_tree_ordinals()
        || ordered_auxiliary_tree_ordinals.as_slice()
            != transcript_schedule.ordered_auxiliary_tree_ordinals()
    {
        return Err(ProofBodyError::InvalidCatalog);
    }

    let derived_visibility = match transcript_schedule.privacy_mode() {
        CommonProofPrivacyMode::PublicOnly => ProofLeafVisibility::Public,
        CommonProofPrivacyMode::SecretBearing => ProofLeafVisibility::SecretBearing,
    };
    for component_index in 0..quotient_component_count {
        let component_ordinal =
            u16::try_from(component_index).map_err(|_| ProofBodyError::CatalogTooLarge)?;
        let context = common_tree_context(
            &input,
            proof_header_hash,
            ProofTreeRole::QuotientComponent,
            component_ordinal,
            input.evaluation_domain_size,
            1,
            derived_visibility,
        )?;
        push_catalog_entry(
            &mut entries,
            ProofTreeCatalogSource::QuotientComponent { component_ordinal },
            ProofTreeConstruction::Common(context),
            None,
        )?;
    }

    if transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing {
        let context = common_tree_context(
            &input,
            proof_header_hash,
            ProofTreeRole::OpeningBatchMask,
            0,
            input.evaluation_domain_size,
            1,
            ProofLeafVisibility::SecretBearing,
        )?;
        push_catalog_entry(
            &mut entries,
            ProofTreeCatalogSource::OpeningBatchMask,
            ProofTreeConstruction::Common(context),
            None,
        )?;
    }

    for fold_index in 0..nonterminal_fri_tree_count {
        let fold_ordinal =
            u16::try_from(fold_index).map_err(|_| ProofBodyError::CatalogTooLarge)?;
        let shift = u32::from(fold_ordinal)
            .checked_add(1)
            .ok_or(ProofBodyError::CountOverflow)?;
        let domain_size = input
            .evaluation_domain_size
            .checked_shr(shift)
            .ok_or(ProofBodyError::InvalidCatalog)?;
        if domain_size < 2 {
            return Err(ProofBodyError::InvalidCatalog);
        }
        let context = common_tree_context(
            &input,
            proof_header_hash,
            ProofTreeRole::NonterminalFriLayer,
            fold_ordinal,
            domain_size,
            1,
            derived_visibility,
        )?;
        push_catalog_entry(
            &mut entries,
            ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal },
            ProofTreeConstruction::Common(context),
            None,
        )?;
    }

    if entries.len() != total_tree_count {
        return Err(ProofBodyError::InvalidCatalog);
    }
    Ok(CompleteProofTreeCatalog {
        evaluation_domain_size: input.evaluation_domain_size,
        entries,
    })
}

fn common_tree_context(
    input: &ProofTreeCatalogInput,
    proof_header_hash: [u8; 64],
    tree_role: ProofTreeRole,
    tree_ordinal: u16,
    domain_size: u64,
    row_width: u32,
    leaf_visibility: ProofLeafVisibility,
) -> Result<ProofMerkleTreeContext, ProofBodyError> {
    Ok(ProofMerkleTreeContext::new(
        input.suite_identifier,
        proof_header_hash,
        input.application_statement_schema_identifier,
        input.proof_field_index,
        tree_role,
        tree_ordinal,
        domain_size,
        row_width,
        leaf_visibility,
    )?)
}

fn push_catalog_entry(
    entries: &mut Vec<ProofTreeCatalogEntry>,
    source: ProofTreeCatalogSource,
    construction: ProofTreeConstruction,
    bound_root: Option<[u8; 64]>,
) -> Result<(), ProofBodyError> {
    let tree_catalog_index =
        u16::try_from(entries.len()).map_err(|_| ProofBodyError::CatalogTooLarge)?;
    entries.push(ProofTreeCatalogEntry {
        tree_catalog_index,
        source,
        construction,
        bound_root,
    });
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofBodyLayout {
    catalog: CompleteProofTreeCatalog,
    deep_evaluation_count: u32,
    terminal_coefficient_count: u32,
    unique_query_count: u32,
    query_orbit_count: u64,
}

impl ProofBodyLayout {
    pub(crate) fn new(
        catalog: CompleteProofTreeCatalog,
        transcript_schedule: &CommonProofTranscriptSchedule,
        terminal_coefficient_count: u32,
    ) -> Result<Self, ProofBodyError> {
        if terminal_coefficient_count == 0
            || transcript_schedule.query_orbit_count() != catalog.evaluation_domain_size / 2
        {
            return Err(ProofBodyError::InvalidCatalog);
        }
        Ok(Self {
            catalog,
            deep_evaluation_count: transcript_schedule.opening_claim_count(),
            terminal_coefficient_count,
            unique_query_count: transcript_schedule.unique_query_count(),
            query_orbit_count: transcript_schedule.query_orbit_count(),
        })
    }

    pub(crate) const fn catalog(&self) -> &CompleteProofTreeCatalog {
        &self.catalog
    }

    fn opened_leaf_indexes(
        &self,
        entry: &ProofTreeCatalogEntry,
        sorted_query_representatives: &[u64],
    ) -> Result<Vec<u64>, ProofBodyError> {
        if let ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal } = entry.source {
            let shift = u32::from(fold_ordinal)
                .checked_add(2)
                .ok_or(ProofBodyError::CountOverflow)?;
            let leaf_count = self
                .catalog
                .evaluation_domain_size
                .checked_shr(shift)
                .filter(|count| *count != 0)
                .ok_or(ProofBodyError::InvalidCatalog)?;
            Ok(sorted_query_representatives
                .iter()
                .map(|representative| representative % leaf_count)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect())
        } else {
            Ok(sorted_query_representatives.to_vec())
        }
    }

    fn validate_query_representatives(
        &self,
        sorted_query_representatives: &[u64],
    ) -> Result<(), ProofBodyError> {
        if sorted_query_representatives.len()
            != usize::try_from(self.unique_query_count)
                .map_err(|_| ProofBodyError::CountOverflow)?
            || !sorted_query_representatives
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || sorted_query_representatives
                .last()
                .is_some_and(|representative| *representative >= self.query_orbit_count)
        {
            return Err(ProofBodyError::InvalidQueryRepresentatives);
        }
        Ok(())
    }
}

mod authentication;
mod decoding;
mod sizing;

pub(super) use authentication::minimal_frontier_node_count;
#[cfg(test)]
use authentication::{
    ParsedAuthenticationNode, TreeValueKind, hash_canonical_leaf, statement_owned_node_digest,
};
pub(crate) use decoding::{
    DecodedProofBody, DecodedProofBodyPrefix, DecodedProofPhasePairLeaf, DecodedProofTreeOpening,
    PendingProofBodyQueries, ProofTreeOpening, decode_proof_body_prefix,
    decode_proof_body_prefix_owned, decode_proof_query_section_header_at,
    decode_proof_query_tree_at,
};
#[cfg(test)]
use sizing::maximum_minimal_frontier_node_count;
pub(crate) use sizing::{
    CommonProofByteLengthCeiling, ProofQueryTreeByteLengthCeiling,
    canonical_common_proof_byte_length_ceiling, proof_body_prefix_byte_length,
    proof_query_tree_byte_length,
};

#[cfg(test)]
#[path = "body/common-proof-engine-tests.rs"]
mod common_proof_engine_tests;

#[cfg(test)]
#[path = "body/tests.rs"]
mod tests;
