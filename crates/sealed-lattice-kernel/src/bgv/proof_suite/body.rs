use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
};

use crate::foundation::{
    CanonicalItem, CanonicalItemType, hash_foundation_tuple_512,
};

use super::{
    decoder::{BoundedProofDecoder, ProofByteSource, ProofDecodeError},
    field::ProofChallengeExtensionElement,
    merkle::{
        ProofAuthenticationNode, ProofLeafVisibility, ProofMerkleError,
        ProofMerkleTreeContext, ProofOraclePhasePairLeaf, ProofTreeRole, ProofTreeValue,
        verify_authentication_frontier,
    },
    transcript::{
        CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
        CommonProofTranscriptSchedule, TranscriptError,
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
            | ProofTreeConstruction::SetupPolynomial { .. } => {
                Err(ProofBodyError::InvalidCatalog)
            }
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

/// Derives the maximum number of distinct Merkle and tree-context hash
/// equations needed by one accepted verification. Statement-owned trees are
/// counted both for their mandatory complete canonical-source reconstruction
/// and for the proof opening authenticated against that rebuilt root. The
/// opening term is the exact maximum over every admissible set of distinct
/// query representatives, including collisions introduced by FRI folding.
pub(crate) fn maximum_verifier_tree_hash_equation_count(
    catalog: &CompleteProofTreeCatalog,
    unique_query_count: u32,
) -> Result<u64, ProofBodyError> {
    if unique_query_count == 0
        || u64::from(unique_query_count) > catalog.evaluation_domain_size / 2
    {
        return Err(ProofBodyError::InvalidQueryRepresentatives);
    }

    // `build_complete_proof_tree_catalog` derives the proof-header hash once.
    let mut equation_count = 1_u64;
    for entry in &catalog.entries {
        let leaf_count = entry_leaf_count(entry, catalog.evaluation_domain_size)?;
        let maximum_opened_leaf_count = usize::try_from(unique_query_count)
            .map_err(|_| ProofBodyError::CountOverflow)?
            .min(leaf_count);
        let opening_equations = maximum_merkle_opening_hash_equation_count(
            leaf_count,
            maximum_opened_leaf_count,
        )?;
        equation_count = equation_count
            .checked_add(opening_equations)
            .ok_or(ProofBodyError::CountOverflow)?;

        match &entry.construction {
            ProofTreeConstruction::Common(_) => {
                // One context digest is shared by all opened leaves and node
                // equations for this tree.
                equation_count = equation_count
                    .checked_add(1)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            ProofTreeConstruction::CommittedMaterial { .. }
            | ProofTreeConstruction::SetupPolynomial { .. } => {
                let full_tree_equations = u64::try_from(leaf_count)
                    .map_err(|_| ProofBodyError::CountOverflow)?
                    .checked_mul(2)
                    .and_then(|count| count.checked_sub(1))
                    .ok_or(ProofBodyError::CountOverflow)?;
                equation_count = equation_count
                    .checked_add(full_tree_equations)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
        }
    }
    Ok(equation_count)
}

fn maximum_merkle_opening_hash_equation_count(
    leaf_count: usize,
    maximum_opened_leaf_count: usize,
) -> Result<u64, ProofBodyError> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || maximum_opened_leaf_count == 0
        || maximum_opened_leaf_count > leaf_count
    {
        return Err(ProofBodyError::InvalidCatalog);
    }
    let opened_leaf_count = u64::try_from(maximum_opened_leaf_count)
        .map_err(|_| ProofBodyError::CountOverflow)?;
    let mut equation_count = opened_leaf_count;
    let mut node_count = leaf_count / 2;
    while node_count != 0 {
        equation_count = equation_count
            .checked_add(
                opened_leaf_count.min(
                    u64::try_from(node_count)
                        .map_err(|_| ProofBodyError::CountOverflow)?,
                ),
            )
            .ok_or(ProofBodyError::CountOverflow)?;
        node_count /= 2;
    }
    Ok(equation_count)
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
        &[CanonicalItem::variable_bytes(&input.canonical_proof_object_header_bytes)
            .map_err(|_| ProofBodyError::CanonicalEncoding)?],
    )
    .map_err(|_| ProofBodyError::CanonicalEncoding)?
    .into_bytes();

    let quotient_component_count = usize::from(transcript_schedule.quotient_component_count());
    let nonterminal_fri_tree_count = usize::from(transcript_schedule.fri_fold_count() - 1);
    let opening_batch_tree_count = if transcript_schedule.privacy_mode()
        == CommonProofPrivacyMode::SecretBearing
    {
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

    if ordered_base_tree_ordinals.as_slice()
        != transcript_schedule.ordered_base_tree_ordinals()
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
            deep_evaluation_count: u32::from(transcript_schedule.opening_claim_count()),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedProofPhasePairLeaf {
    leaf_index: u64,
    first_point_values: Vec<ProofTreeValue>,
    opposite_point_values: Vec<ProofTreeValue>,
}

impl DecodedProofPhasePairLeaf {
    pub(crate) const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    pub(crate) fn first_point_values(&self) -> &[ProofTreeValue] {
        &self.first_point_values
    }

    pub(crate) fn opposite_point_values(&self) -> &[ProofTreeValue] {
        &self.opposite_point_values
    }
}

pub(crate) struct ProofTreeOpening<'opening> {
    catalog_entry: &'opening ProofTreeCatalogEntry,
    leaves: &'opening [DecodedProofPhasePairLeaf],
}

impl<'opening> ProofTreeOpening<'opening> {
    pub(crate) const fn catalog_entry(&self) -> &'opening ProofTreeCatalogEntry {
        self.catalog_entry
    }

    pub(crate) const fn leaves(&self) -> &'opening [DecodedProofPhasePairLeaf] {
        self.leaves
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedProofBody {
    tree_roots: Vec<[u8; 64]>,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
}

impl DecodedProofBody {
    pub(crate) fn tree_roots(&self) -> &[[u8; 64]] {
        &self.tree_roots
    }

    pub(crate) fn deep_evaluations(&self) -> &[ProofChallengeExtensionElement] {
        &self.deep_evaluations
    }

    pub(crate) fn terminal_coefficients(&self) -> &[ProofChallengeExtensionElement] {
        &self.terminal_coefficients
    }
}

pub(crate) struct PendingProofBodyQueries<
    'source,
    'layout,
    Source: ProofByteSource + ?Sized,
> {
    source: &'source Source,
    layout: &'layout ProofBodyLayout,
    declared_byte_length: usize,
    query_section_offset: usize,
    tree_roots: Vec<[u8; 64]>,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
}

struct AbsorbingQuerySource<'source, 'absorber, Source: ProofByteSource + ?Sized> {
    source: &'source Source,
    source_offset: usize,
    byte_length: usize,
    next_offset: Cell<usize>,
    absorber: RefCell<&'absorber mut CommonProofQueryOpeningAbsorber>,
    transcript_error: RefCell<Option<TranscriptError>>,
}

impl<Source: ProofByteSource + ?Sized> AbsorbingQuerySource<'_, '_, Source> {
    fn take_transcript_error(&self) -> Option<TranscriptError> {
        self.transcript_error.borrow_mut().take()
    }
}

impl<Source: ProofByteSource + ?Sized> ProofByteSource
    for AbsorbingQuerySource<'_, '_, Source>
{
    fn byte_length(&self) -> usize {
        self.byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        if offset != self.next_offset.get() {
            return false;
        }
        let Some(relative_end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if relative_end > self.byte_length {
            return false;
        }
        let Some(absolute_offset) = self.source_offset.checked_add(offset) else {
            return false;
        };
        if !self.source.copy_bytes(absolute_offset, destination) {
            return false;
        }
        self.next_offset.set(relative_end);
        let should_absorb = self.transcript_error.borrow().is_none();
        if should_absorb {
            let absorb_result = self.absorber.borrow_mut().absorb(destination);
            if let Err(error) = absorb_result {
                *self.transcript_error.borrow_mut() = Some(error);
            }
        }
        true
    }
}

impl<Source: ProofByteSource + ?Sized> PendingProofBodyQueries<'_, '_, Source> {
    pub(crate) fn tree_roots(&self) -> &[[u8; 64]] {
        &self.tree_roots
    }

    pub(crate) fn deep_evaluations(&self) -> &[ProofChallengeExtensionElement] {
        &self.deep_evaluations
    }

    pub(crate) fn terminal_coefficients(&self) -> &[ProofChallengeExtensionElement] {
        &self.terminal_coefficients
    }

    pub(crate) fn query_section_byte_length(&self) -> Result<usize, ProofBodyError> {
        self.declared_byte_length
            .checked_sub(self.query_section_offset)
            .ok_or(ProofBodyError::CountOverflow)
    }
}

pub(crate) fn decode_proof_body_prefix<'source, 'layout, Source>(
    source: &'source Source,
    declared_byte_length: usize,
    proof_byte_ceiling: usize,
    layout: &'layout ProofBodyLayout,
) -> Result<PendingProofBodyQueries<'source, 'layout, Source>, ProofBodyError>
where
    Source: ProofByteSource + ?Sized,
    Source: 'source,
{
    let mut decoder = BoundedProofDecoder::new(
        source,
        declared_byte_length,
        proof_byte_ceiling,
    )?;
    let mut tree_roots = Vec::new();
    tree_roots
        .try_reserve_exact(layout.catalog.entries.len())
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    tree_roots.extend(layout.catalog.entries.iter().map(|entry| entry.bound_root));

    read_serialized_roots(
        &mut decoder,
        &layout.catalog.entries,
        &mut tree_roots,
        |source| {
            matches!(
                source,
                ProofTreeCatalogSource::RelationProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    ..
                }
            )
        },
    )?;
    read_serialized_roots(
        &mut decoder,
        &layout.catalog.entries,
        &mut tree_roots,
        |source| {
            matches!(
                source,
                ProofTreeCatalogSource::RelationProofCreated {
                    tree_role: ProofTreeRole::AuxiliaryOracle,
                    ..
                }
            )
        },
    )?;
    read_serialized_roots(
        &mut decoder,
        &layout.catalog.entries,
        &mut tree_roots,
        |source| matches!(source, ProofTreeCatalogSource::QuotientComponent { .. }),
    )?;

    let deep_evaluations = read_extension_value_list(
        &mut decoder,
        usize::try_from(layout.deep_evaluation_count)
            .map_err(|_| ProofBodyError::CountOverflow)?,
    )?;

    read_serialized_roots(
        &mut decoder,
        &layout.catalog.entries,
        &mut tree_roots,
        |source| matches!(source, ProofTreeCatalogSource::OpeningBatchMask),
    )?;
    read_serialized_roots(
        &mut decoder,
        &layout.catalog.entries,
        &mut tree_roots,
        |source| matches!(source, ProofTreeCatalogSource::NonterminalFriLayer { .. }),
    )?;

    let terminal_coefficients = read_extension_value_list(
        &mut decoder,
        usize::try_from(layout.terminal_coefficient_count)
            .map_err(|_| ProofBodyError::CountOverflow)?,
    )?;

    let tree_roots = tree_roots
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(ProofBodyError::InvalidCatalog)?;
    let query_section_offset = proof_body_prefix_byte_length(layout)?;
    if decoder.offset() != query_section_offset {
        return Err(ProofBodyError::InvalidItemLength);
    }
    if query_section_offset >= declared_byte_length {
        return Err(ProofDecodeError::Truncated.into());
    }
    drop(decoder);

    Ok(PendingProofBodyQueries {
        source,
        layout,
        declared_byte_length,
        query_section_offset,
        tree_roots,
        deep_evaluations,
        terminal_coefficients,
    })
}

impl<'source, 'layout, Source: ProofByteSource + ?Sized>
    PendingProofBodyQueries<'source, 'layout, Source>
{
    pub(crate) fn decode_query_section<OpeningConsumer>(
        self,
        sorted_query_representatives: &[u64],
        query_opening_absorber: &mut CommonProofQueryOpeningAbsorber,
        mut consume_opening: OpeningConsumer,
    ) -> Result<DecodedProofBody, ProofBodyError>
    where
        OpeningConsumer: FnMut(ProofTreeOpening<'_>) -> Result<(), ProofBodyError>,
    {
        self.layout
            .validate_query_representatives(sorted_query_representatives)?;
        let PendingProofBodyQueries {
            source,
            layout,
            declared_byte_length,
            query_section_offset,
            tree_roots,
            deep_evaluations,
            terminal_coefficients,
        } = self;

        let query_section_byte_length = declared_byte_length
            .checked_sub(query_section_offset)
            .ok_or(ProofBodyError::CountOverflow)?;
        let query_source = AbsorbingQuerySource {
            source,
            source_offset: query_section_offset,
            byte_length: query_section_byte_length,
            next_offset: Cell::new(0),
            absorber: RefCell::new(query_opening_absorber),
            transcript_error: RefCell::new(None),
        };
        let mut decoder = BoundedProofDecoder::new(
            &query_source,
            query_section_byte_length,
            query_section_byte_length,
        )?;

        let expected_record_pair_count = u32::try_from(layout.catalog.entries.len())
            .map_err(|_| ProofBodyError::CountOverflow)?;
        if decoder.read_u32()? != expected_record_pair_count {
            return Err(ProofBodyError::InvalidListCount);
        }

        for (entry, expected_root) in layout.catalog.entries.iter().zip(&tree_roots) {
            let opened_leaf_indexes =
                layout.opened_leaf_indexes(entry, sorted_query_representatives)?;
            let expected_leaf_count =
                entry_leaf_count(entry, layout.catalog.evaluation_domain_size)?;
            let expected_leaf_byte_length = canonical_leaf_byte_length(entry)?;
            if expected_leaf_byte_length > declared_byte_length {
                return Err(ProofBodyError::InvalidItemLength);
            }
            let mut opened_leaves = Vec::new();
            opened_leaves
                .try_reserve_exact(opened_leaf_indexes.len())
                .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
            let mut opened_leaf_digests = Vec::new();
            opened_leaf_digests
                .try_reserve_exact(opened_leaf_indexes.len())
                .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;

            read_tuple_header(
                &mut decoder,
                PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER,
                2,
            )?;
            read_u16_item(
                &mut decoder,
                entry.tree_catalog_index,
                ProofBodyError::InvalidTreeCatalogIndex,
            )?;
            let opening_list_byte_length = raw_byte_list_byte_length(
                opened_leaf_indexes.len(),
                expected_leaf_byte_length,
            )?;
            read_item_header(
                &mut decoder,
                CanonicalItemType::HomogeneousList,
                opening_list_byte_length,
            )?;
            read_list_header(
                &mut decoder,
                CanonicalItemType::RawBytes,
                opened_leaf_indexes.len(),
            )?;
            for expected_leaf_index in opened_leaf_indexes.iter().copied() {
                if usize::try_from(decoder.read_u32()?)
                    .map_err(|_| ProofBodyError::CountOverflow)?
                    != expected_leaf_byte_length
                {
                    return Err(ProofBodyError::InvalidItemLength);
                }
                let canonical_leaf_bytes = decoder.read_bytes(expected_leaf_byte_length)?;
                let (leaf, digest) = decode_phase_pair_leaf(
                    entry,
                    expected_leaf_index,
                    expected_leaf_count,
                    &canonical_leaf_bytes,
                )?;
                opened_leaves.push(leaf);
                opened_leaf_digests.push((expected_leaf_index, digest));
            }

            let expected_frontier_count =
                minimal_frontier_node_count(&opened_leaf_indexes, expected_leaf_count)?;
            let frontier = read_authentication_frontier(
                &mut decoder,
                entry.tree_catalog_index,
                expected_frontier_count,
            )?;
            authenticate_opening(
                entry,
                &opened_leaf_digests,
                &frontier,
                *expected_root,
                expected_leaf_count,
            )?;
            consume_opening(ProofTreeOpening {
                catalog_entry: entry,
                leaves: &opened_leaves,
            })?;
        }

        decoder.finish()?;
        if let Some(error) = query_source.take_transcript_error() {
            return Err(error.into());
        }
        Ok(DecodedProofBody {
            tree_roots,
            deep_evaluations,
            terminal_coefficients,
        })
    }
}

fn proof_body_prefix_byte_length(layout: &ProofBodyLayout) -> Result<usize, ProofBodyError> {
    let serialized_root_count = layout
        .catalog
        .entries
        .iter()
        .filter(|entry| entry.bound_root.is_none())
        .count();
    let root_byte_length = serialized_root_count
        .checked_mul(64)
        .ok_or(ProofBodyError::CountOverflow)?;
    let extension_element_byte_length = super::PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(8)
        .ok_or(ProofBodyError::CountOverflow)?;
    let deep_byte_length = usize::try_from(layout.deep_evaluation_count)
        .map_err(|_| ProofBodyError::CountOverflow)?
        .checked_mul(extension_element_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    let terminal_byte_length = usize::try_from(layout.terminal_coefficient_count)
        .map_err(|_| ProofBodyError::CountOverflow)?
        .checked_mul(extension_element_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    root_byte_length
        .checked_add(deep_byte_length)
        .and_then(|length| length.checked_add(terminal_byte_length))
        .ok_or(ProofBodyError::CountOverflow)
}

fn read_serialized_roots<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    entries: &[ProofTreeCatalogEntry],
    roots: &mut [Option<[u8; 64]>],
    mut belongs_to_phase: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<(), ProofBodyError> {
    for (entry, root) in entries.iter().zip(roots) {
        if belongs_to_phase(entry.source) {
            if entry.bound_root.is_some() || root.is_some() {
                return Err(ProofBodyError::InvalidCatalog);
            }
            *root = Some(decoder.read_hash512()?);
        }
    }
    Ok(())
}

fn read_extension_value_list<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_count: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, ProofBodyError> {
    read_list_header(
        decoder,
        CanonicalItemType::ChallengeExtensionElement,
        expected_count,
    )?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(expected_count)
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    for _ in 0..expected_count {
        values.push(decoder.read_challenge_extension_element()?);
    }
    Ok(values)
}

fn read_tuple_header<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_schema_identifier: u16,
    expected_item_count: u32,
) -> Result<(), ProofBodyError> {
    if decoder.read_u16()? != expected_schema_identifier {
        return Err(ProofBodyError::InvalidSchema);
    }
    if decoder.read_u16()? != SCHEMA_VERSION {
        return Err(ProofBodyError::InvalidSchemaVersion);
    }
    if decoder.read_u32()? != expected_item_count {
        return Err(ProofBodyError::InvalidItemCount);
    }
    Ok(())
}

fn read_item_header<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_item_type: CanonicalItemType,
    expected_byte_length: usize,
) -> Result<(), ProofBodyError> {
    if decoder.read_u16()? != expected_item_type.canonical_code() {
        return Err(ProofBodyError::InvalidItemType);
    }
    let byte_length = usize::try_from(decoder.read_u32()?)
        .map_err(|_| ProofBodyError::CountOverflow)?;
    if byte_length != expected_byte_length {
        return Err(ProofBodyError::InvalidItemLength);
    }
    Ok(())
}

fn read_list_header<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_element_type: CanonicalItemType,
    expected_count: usize,
) -> Result<(), ProofBodyError> {
    if decoder.read_u16()? != expected_element_type.canonical_code() {
        return Err(ProofBodyError::InvalidItemType);
    }
    let count = usize::try_from(decoder.read_u32()?)
        .map_err(|_| ProofBodyError::CountOverflow)?;
    if count != expected_count {
        return Err(ProofBodyError::InvalidListCount);
    }
    Ok(())
}

fn read_u16_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_value: u16,
    mismatch_error: ProofBodyError,
) -> Result<(), ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Unsigned16, 2)?;
    if decoder.read_u16()? != expected_value {
        return Err(mismatch_error);
    }
    Ok(())
}

fn read_u32_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
) -> Result<u32, ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Unsigned32, 4)?;
    Ok(decoder.read_u32()?)
}

fn read_u64_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
) -> Result<u64, ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Unsigned64, 8)?;
    Ok(decoder.read_u64()?)
}

fn read_hash_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
) -> Result<[u8; 64], ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Hash512, 64)?;
    Ok(decoder.read_hash512()?)
}

fn raw_byte_list_byte_length(
    element_count: usize,
    element_byte_length: usize,
) -> Result<usize, ProofBodyError> {
    let framed_element_length = element_byte_length
        .checked_add(4)
        .ok_or(ProofBodyError::CountOverflow)?;
    let byte_length = element_count
        .checked_mul(framed_element_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    ensure_u32_length(byte_length)
}

fn nested_tuple_list_byte_length(
    element_count: usize,
    element_byte_length: usize,
) -> Result<usize, ProofBodyError> {
    let byte_length = element_count
        .checked_mul(element_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    ensure_u32_length(byte_length)
}

fn ensure_u32_length(byte_length: usize) -> Result<usize, ProofBodyError> {
    u32::try_from(byte_length).map_err(|_| ProofBodyError::CountOverflow)?;
    Ok(byte_length)
}

fn entry_leaf_count(
    entry: &ProofTreeCatalogEntry,
    evaluation_domain_size: u64,
) -> Result<usize, ProofBodyError> {
    match &entry.construction {
        ProofTreeConstruction::Common(_) => entry.leaf_count(),
        ProofTreeConstruction::CommittedMaterial { .. }
        | ProofTreeConstruction::SetupPolynomial { .. } => {
            usize::try_from(evaluation_domain_size / 2)
                .map_err(|_| ProofBodyError::CountOverflow)
        }
    }
}

fn canonical_leaf_byte_length(
    entry: &ProofTreeCatalogEntry,
) -> Result<usize, ProofBodyError> {
    match &entry.construction {
        ProofTreeConstruction::Common(context) => {
            let value_byte_length = match entry.source {
                ProofTreeCatalogSource::RelationProofCreated { .. } => 8_usize,
                ProofTreeCatalogSource::QuotientComponent { .. }
                | ProofTreeCatalogSource::OpeningBatchMask
                | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                    super::PROOF_CHALLENGE_EXTENSION_DEGREE
                        .checked_mul(8)
                        .ok_or(ProofBodyError::CountOverflow)?
                }
                ProofTreeCatalogSource::RelationBoundPublic => {
                    return Err(ProofBodyError::InvalidCatalog);
                }
            };
            let row_width = usize::try_from(context.row_width())
                .map_err(|_| ProofBodyError::CountOverflow)?;
            let list_values_byte_length = row_width
                .checked_mul(value_byte_length)
                .and_then(|length| length.checked_mul(2))
                .ok_or(ProofBodyError::CountOverflow)?;
            let salt_item_byte_length = if context.leaf_visibility()
                == ProofLeafVisibility::SecretBearing
            {
                6 + SECRET_LEAF_SALT_BYTE_LENGTH
            } else {
                0
            };
            124_usize
                .checked_add(list_values_byte_length)
                .and_then(|length| length.checked_add(salt_item_byte_length))
                .ok_or(ProofBodyError::CountOverflow)
        }
        ProofTreeConstruction::CommittedMaterial { .. } => Ok(234),
        ProofTreeConstruction::SetupPolynomial { row_width, .. } => {
            let row_width =
                usize::try_from(*row_width).map_err(|_| ProofBodyError::CountOverflow)?;
            116_usize
                .checked_add(
                    row_width
                        .checked_mul(16)
                        .ok_or(ProofBodyError::CountOverflow)?,
                )
                .ok_or(ProofBodyError::CountOverflow)
        }
    }
}

fn decode_phase_pair_leaf(
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
            SECRET_LEAF_SALT_BYTE_LENGTH,
        )?;
        Some(decoder.read_array::<SECRET_LEAF_SALT_BYTE_LENGTH>()?)
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
            SECRET_LEAF_SALT_BYTE_LENGTH,
        )?;
        let _ = decoder.read_array::<SECRET_LEAF_SALT_BYTE_LENGTH>()?;
    }
    let row_width =
        usize::try_from(layout.row_width).map_err(|_| ProofBodyError::CountOverflow)?;
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
enum TreeValueKind {
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
            Self::Extension => super::PROOF_CHALLENGE_EXTENSION_DEGREE * 8,
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

fn hash_canonical_leaf(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedAuthenticationNode {
    level: u32,
    node_index: u64,
    node_digest: [u8; 64],
}

fn read_authentication_frontier<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_tree_catalog_index: u16,
    expected_node_count: usize,
) -> Result<Vec<ParsedAuthenticationNode>, ProofBodyError> {
    read_tuple_header(
        decoder,
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
        2,
    )?;
    read_u16_item(
        decoder,
        expected_tree_catalog_index,
        ProofBodyError::InvalidTreeCatalogIndex,
    )?;
    let list_byte_length = nested_tuple_list_byte_length(
        expected_node_count,
        AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH,
    )?;
    read_item_header(
        decoder,
        CanonicalItemType::HomogeneousList,
        list_byte_length,
    )?;
    read_list_header(
        decoder,
        CanonicalItemType::NestedTuple,
        expected_node_count,
    )?;
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(expected_node_count)
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    for _ in 0..expected_node_count {
        read_tuple_header(
            decoder,
            PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER,
            3,
        )?;
        let node = ParsedAuthenticationNode {
            level: read_u32_item(decoder)?,
            node_index: read_u64_item(decoder)?,
            node_digest: read_hash_item(decoder)?,
        };
        if nodes.last().is_some_and(|previous| previous >= &node) {
            return Err(ProofMerkleError::NonCanonicalOrder.into());
        }
        nodes.push(node);
    }
    Ok(nodes)
}

fn minimal_frontier_node_count(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<usize, ProofBodyError> {
    if sorted_unique_leaf_indexes.is_empty()
        || leaf_count == 0
        || !leaf_count.is_power_of_two()
        || !sorted_unique_leaf_indexes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_unique_leaf_indexes.last().is_some_and(|index| {
            usize::try_from(*index).map_or(true, |index| index >= leaf_count)
        })
    {
        return Err(ProofBodyError::InvalidQueryRepresentatives);
    }
    let mut required = sorted_unique_leaf_indexes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut frontier_count = 0_usize;
    for _ in 0..leaf_count.trailing_zeros() {
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
                frontier_count = frontier_count
                    .checked_add(1)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            next.insert(index / 2);
        }
        required = next;
    }
    Ok(frontier_count)
}

fn authenticate_opening(
    entry: &ProofTreeCatalogEntry,
    sorted_unique_opened_leaves: &[(u64, [u8; 64])],
    frontier: &[ParsedAuthenticationNode],
    expected_root: [u8; 64],
    leaf_count: usize,
) -> Result<(), ProofBodyError> {
    match &entry.construction {
        ProofTreeConstruction::Common(context) => {
            let common_frontier = frontier
                .iter()
                .map(|node| {
                    ProofAuthenticationNode::new(node.level, node.node_index, node.node_digest)
                })
                .collect::<Vec<_>>();
            Ok(verify_authentication_frontier(
                context,
                sorted_unique_opened_leaves,
                &common_frontier,
                expected_root,
            )?)
        }
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
    frontier: &[ParsedAuthenticationNode],
    expected_root: [u8; 64],
    leaf_count: usize,
) -> Result<(), ProofBodyError> {
    if !sorted_unique_opened_leaves
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
        || frontier.windows(2).any(|pair| pair[0] >= pair[1])
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
                let supplied = frontier
                    .get(frontier_offset)
                    .ok_or(ProofMerkleError::InvalidOpening)?;
                if supplied.level != level || supplied.node_index != sibling_index {
                    return Err(ProofMerkleError::InvalidOpening.into());
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
            let parent_digest = statement_owned_node_digest(
                construction,
                level
                    .checked_add(1)
                    .ok_or(ProofBodyError::CountOverflow)?,
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

fn statement_owned_node_digest(
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

#[cfg(test)]
#[path = "body/tests.rs"]
mod tests;
