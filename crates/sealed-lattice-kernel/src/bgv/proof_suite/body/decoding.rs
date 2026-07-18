use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};

use crate::foundation::CanonicalItemType;

use super::super::{
    decoder::{BoundedProofDecoder, ProofByteSource, ProofDecodeError},
    field::ProofChallengeExtensionElement,
    merkle::{ProofTreeRole, ProofTreeValue},
    transcript::{
        CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber, CommonProofTranscriptSchedule,
        TranscriptError,
    },
};
use super::authentication::{
    authenticate_opening, decode_phase_pair_leaf, minimal_frontier_node_count,
    read_authentication_frontier,
};
use super::sizing::{
    canonical_leaf_byte_length, entry_leaf_count, proof_body_prefix_byte_length,
    raw_byte_list_byte_length,
};
use super::{
    CompleteProofTreeCatalog, PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER, ProofBodyError,
    ProofBodyLayout, ProofTreeCatalogEntry, ProofTreeCatalogSource, SCHEMA_VERSION,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedProofPhasePairLeaf {
    pub(super) leaf_index: u64,
    pub(super) first_point_values: Vec<ProofTreeValue>,
    pub(super) opposite_point_values: Vec<ProofTreeValue>,
}

impl DecodedProofPhasePairLeaf {
    #[cfg(test)]
    pub(crate) fn from_test_values(
        leaf_index: u64,
        first_point_values: Vec<ProofTreeValue>,
        opposite_point_values: Vec<ProofTreeValue>,
    ) -> Self {
        Self {
            leaf_index,
            first_point_values,
            opposite_point_values,
        }
    }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedProofBodyPrefix {
    query_section_offset: usize,
    tree_roots: Vec<[u8; 64]>,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
}

impl DecodedProofBodyPrefix {
    pub(crate) const fn query_section_offset(&self) -> usize {
        self.query_section_offset
    }

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

pub(crate) struct DecodedProofTreeOpening {
    leaves: Vec<DecodedProofPhasePairLeaf>,
}

impl DecodedProofTreeOpening {
    pub(crate) fn as_opening<'opening>(
        &'opening self,
        catalog_entry: &'opening ProofTreeCatalogEntry,
    ) -> ProofTreeOpening<'opening> {
        ProofTreeOpening {
            catalog_entry,
            leaves: &self.leaves,
        }
    }
}

pub(crate) struct PendingProofBodyQueries<'source, 'layout, Source: ProofByteSource + ?Sized> {
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

impl<Source: ProofByteSource + ?Sized> ProofByteSource for AbsorbingQuerySource<'_, '_, Source> {
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

pub(crate) fn decode_proof_body_prefix_owned<Source>(
    source: &Source,
    declared_byte_length: usize,
    proof_byte_ceiling: usize,
    layout: &ProofBodyLayout,
) -> Result<DecodedProofBodyPrefix, ProofBodyError>
where
    Source: ProofByteSource + ?Sized,
{
    let mut decoder = BoundedProofDecoder::new(source, declared_byte_length, proof_byte_ceiling)?;
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
        usize::try_from(layout.deep_evaluation_count).map_err(|_| ProofBodyError::CountOverflow)?,
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
    Ok(DecodedProofBodyPrefix {
        query_section_offset,
        tree_roots,
        deep_evaluations,
        terminal_coefficients,
    })
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
    let prefix =
        decode_proof_body_prefix_owned(source, declared_byte_length, proof_byte_ceiling, layout)?;
    Ok(PendingProofBodyQueries {
        source,
        layout,
        declared_byte_length,
        query_section_offset: prefix.query_section_offset,
        tree_roots: prefix.tree_roots,
        deep_evaluations: prefix.deep_evaluations,
        terminal_coefficients: prefix.terminal_coefficients,
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
            let opening_list_byte_length =
                raw_byte_list_byte_length(opened_leaf_indexes.len(), expected_leaf_byte_length)?;
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

struct ProofRangeByteSource<'source, Source: ProofByteSource + ?Sized> {
    source: &'source Source,
    source_offset: usize,
    byte_length: usize,
}

impl<Source: ProofByteSource + ?Sized> ProofByteSource for ProofRangeByteSource<'_, Source> {
    fn byte_length(&self) -> usize {
        self.byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if end > self.byte_length {
            return false;
        }
        let Some(source_offset) = self.source_offset.checked_add(offset) else {
            return false;
        };
        self.source.copy_bytes(source_offset, destination)
    }
}

pub(crate) fn decode_proof_query_section_header_at<Source: ProofByteSource + ?Sized>(
    source: &Source,
    query_section_offset: usize,
    expected_record_pair_count: usize,
) -> Result<usize, ProofBodyError> {
    let byte_length = source
        .byte_length()
        .checked_sub(query_section_offset)
        .filter(|byte_length| *byte_length > 0)
        .ok_or(ProofDecodeError::Truncated)?;
    let range = ProofRangeByteSource {
        source,
        source_offset: query_section_offset,
        byte_length,
    };
    let mut decoder = BoundedProofDecoder::new(&range, byte_length, byte_length)?;
    if decoder.read_u32()?
        != u32::try_from(expected_record_pair_count).map_err(|_| ProofBodyError::CountOverflow)?
    {
        return Err(ProofBodyError::InvalidListCount);
    }
    query_section_offset
        .checked_add(decoder.offset())
        .ok_or(ProofBodyError::CountOverflow)
}

pub(crate) fn decode_proof_query_tree_at<Source: ProofByteSource + ?Sized>(
    source: &Source,
    tree_fragment_offset: usize,
    layout: &ProofBodyLayout,
    catalog_index: usize,
    expected_root: [u8; 64],
    sorted_query_representatives: &[u64],
) -> Result<(usize, DecodedProofTreeOpening), ProofBodyError> {
    layout.validate_query_representatives(sorted_query_representatives)?;
    let entry = layout
        .catalog
        .entries
        .get(catalog_index)
        .ok_or(ProofBodyError::InvalidTreeCatalogIndex)?;
    let byte_length = source
        .byte_length()
        .checked_sub(tree_fragment_offset)
        .filter(|byte_length| *byte_length > 0)
        .ok_or(ProofDecodeError::Truncated)?;
    let range = ProofRangeByteSource {
        source,
        source_offset: tree_fragment_offset,
        byte_length,
    };
    let mut decoder = BoundedProofDecoder::new(&range, byte_length, byte_length)?;
    let opened_leaf_indexes = layout.opened_leaf_indexes(entry, sorted_query_representatives)?;
    let expected_leaf_count = entry_leaf_count(entry, layout.catalog.evaluation_domain_size)?;
    let expected_leaf_byte_length = canonical_leaf_byte_length(entry)?;
    if expected_leaf_byte_length > source.byte_length() {
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
    let opening_list_byte_length =
        raw_byte_list_byte_length(opened_leaf_indexes.len(), expected_leaf_byte_length)?;
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
        if usize::try_from(decoder.read_u32()?).map_err(|_| ProofBodyError::CountOverflow)?
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
        expected_root,
        expected_leaf_count,
    )?;
    let next_offset = tree_fragment_offset
        .checked_add(decoder.offset())
        .ok_or(ProofBodyError::CountOverflow)?;
    Ok((
        next_offset,
        DecodedProofTreeOpening {
            leaves: opened_leaves,
        },
    ))
}

pub(super) fn read_serialized_roots<Source: ProofByteSource + ?Sized>(
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

pub(super) fn read_extension_value_list<Source: ProofByteSource + ?Sized>(
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

pub(super) fn read_tuple_header<Source: ProofByteSource + ?Sized>(
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

pub(super) fn read_item_header<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_item_type: CanonicalItemType,
    expected_byte_length: usize,
) -> Result<(), ProofBodyError> {
    if decoder.read_u16()? != expected_item_type.canonical_code() {
        return Err(ProofBodyError::InvalidItemType);
    }
    let byte_length =
        usize::try_from(decoder.read_u32()?).map_err(|_| ProofBodyError::CountOverflow)?;
    if byte_length != expected_byte_length {
        return Err(ProofBodyError::InvalidItemLength);
    }
    Ok(())
}

pub(super) fn read_list_header<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
    expected_element_type: CanonicalItemType,
    expected_count: usize,
) -> Result<(), ProofBodyError> {
    if decoder.read_u16()? != expected_element_type.canonical_code() {
        return Err(ProofBodyError::InvalidItemType);
    }
    let count = usize::try_from(decoder.read_u32()?).map_err(|_| ProofBodyError::CountOverflow)?;
    if count != expected_count {
        return Err(ProofBodyError::InvalidListCount);
    }
    Ok(())
}

pub(super) fn read_u16_item<Source: ProofByteSource + ?Sized>(
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

pub(super) fn read_u32_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
) -> Result<u32, ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Unsigned32, 4)?;
    Ok(decoder.read_u32()?)
}

pub(super) fn read_u64_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
) -> Result<u64, ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Unsigned64, 8)?;
    Ok(decoder.read_u64()?)
}

pub(super) fn read_hash_item<Source: ProofByteSource + ?Sized>(
    decoder: &mut BoundedProofDecoder<'_, Source>,
) -> Result<[u8; 64], ProofBodyError> {
    read_item_header(decoder, CanonicalItemType::Hash512, 64)?;
    Ok(decoder.read_hash512()?)
}
