use super::{
    AUTHENTICATION_DIGEST_BYTE_LENGTH, BTreeSet, CanonicalDecodeLimits, CanonicalItemType,
    CommonProofProverError, CommonProofQueryOpeningAbsorber, CommonProofTranscriptSchedule,
    CompleteProofTreeCatalog, HASH_BYTE_LENGTH, PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
    PROOF_AUTHENTICATION_FRONTIER_SCHEMA_VERSION, PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER,
    PrefetchedCommonProofOpeningArtifact, ProofChallengeExtensionElement, ProofObjectHeader,
    ProofTreeCatalogEntry, ProofTreeCatalogSource, ProofTreeRole, SCHEMA_VERSION, TranscriptError,
    canonical_common_proof_leaf_byte_length, common_proof_tree_value_type,
    minimal_frontier_coordinates,
};

/// Streaming destination for the canonical header and proof body.  Production
/// implementations bind the final length and digest in the owning stream
/// descriptor; this interface never asks for the accumulated bytes.
pub(crate) trait CommonProofByteSink {
    type Error;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedCommonProofByteSinkError {
    ByteLengthExceeded,
    AllocationLimitExceeded,
}

/// Bounded worker-owned output for one independently appendable proof fragment
/// (the query count or one tree's opening/frontier pair).  The browser appends
/// the fragment durably, absorbs those identical bytes, drops it, and then
/// moves to the next catalog entry.
pub(crate) struct BoundedCommonProofByteSink {
    maximum_byte_length: usize,
    bytes: Vec<u8>,
}

impl BoundedCommonProofByteSink {
    pub(crate) fn new(maximum_byte_length: usize) -> Result<Self, BoundedCommonProofByteSinkError> {
        if maximum_byte_length == 0 {
            return Err(BoundedCommonProofByteSinkError::ByteLengthExceeded);
        }
        Ok(Self {
            maximum_byte_length,
            bytes: Vec::new(),
        })
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl CommonProofByteSink for BoundedCommonProofByteSink {
    type Error = BoundedCommonProofByteSinkError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let next_byte_length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(BoundedCommonProofByteSinkError::ByteLengthExceeded)?;
        if next_byte_length > self.maximum_byte_length {
            return Err(BoundedCommonProofByteSinkError::ByteLengthExceeded);
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| BoundedCommonProofByteSinkError::AllocationLimitExceeded)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

pub(crate) fn canonical_common_proof_query_section_header(
    catalog: &CompleteProofTreeCatalog,
) -> Result<[u8; 4], CommonProofProverError> {
    Ok(u32::try_from(catalog.entries().len())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .to_le_bytes())
}

/// Encodes one catalog entry's opening/frontier pair as an independently
/// bounded fragment.  Concatenating the query-count header and these fragments
/// in catalog order is exactly the body grammar consumed by `body.rs`.
pub(crate) fn encode_common_proof_query_tree_fragment(
    catalog: &CompleteProofTreeCatalog,
    catalog_index: usize,
    geometry: CommonProofOpeningGeometry,
    sorted_query_representatives: &[u64],
    artifact: &PrefetchedCommonProofOpeningArtifact,
    maximum_fragment_byte_length: usize,
) -> Result<
    Vec<u8>,
    CommonProofEncodingError<BoundedCommonProofByteSinkError, CommonProofProverError>,
> {
    let entry = catalog
        .entries()
        .get(catalog_index)
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidTree,
        ))?;
    if geometry.tree_catalog_index != entry.tree_catalog_index()
        || geometry.leaf_count == 0
        || !geometry.leaf_count.is_power_of_two()
        || geometry.canonical_leaf_byte_length == 0
        || sorted_query_representatives.is_empty()
        || !sorted_query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_query_representatives
            .last()
            .is_some_and(|representative| *representative >= catalog.evaluation_domain_size() / 2)
    {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidOpening,
        ));
    }
    validate_common_proof_opening_geometry(entry, geometry)
        .map_err(CommonProofEncodingError::Prover)?;
    if artifact.tree_catalog_index() != entry.tree_catalog_index()
        || artifact.leaf_count() != geometry.leaf_count
        || artifact.canonical_leaf_byte_length() != geometry.canonical_leaf_byte_length
    {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }
    if !artifact_matches_query_representatives(
        entry.source(),
        catalog.evaluation_domain_size(),
        sorted_query_representatives,
        artifact.opened_leaf_indexes(),
    )? {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidOpening,
        ));
    }
    let mut sink = BoundedCommonProofByteSink::new(maximum_fragment_byte_length)
        .map_err(CommonProofEncodingError::Sink)?;
    write_opening_record(
        &mut sink,
        entry.tree_catalog_index(),
        geometry.canonical_leaf_byte_length,
        artifact,
    )?;
    write_authentication_frontier(&mut sink, entry.tree_catalog_index(), artifact)?;
    Ok(sink.finish())
}

/// Couples the streamed query-section bytes to the transcript without ever
/// buffering the section.  A fragment reaches the transcript only after the
/// output sink accepts the identical bytes, so a sink failure cannot advance
/// the Fiat-Shamir state past the durable proof stream.
pub(crate) struct CommonProofTranscriptQuerySink<'borrow, Sink> {
    sink: &'borrow mut Sink,
    absorber: &'borrow mut CommonProofQueryOpeningAbsorber,
}

impl<'borrow, Sink> CommonProofTranscriptQuerySink<'borrow, Sink> {
    pub(crate) const fn new(
        sink: &'borrow mut Sink,
        absorber: &'borrow mut CommonProofQueryOpeningAbsorber,
    ) -> Self {
        Self { sink, absorber }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofTranscriptQuerySinkError<SinkError> {
    Sink(SinkError),
    Transcript(TranscriptError),
}

impl<Sink: CommonProofByteSink> CommonProofByteSink for CommonProofTranscriptQuerySink<'_, Sink> {
    type Error = CommonProofTranscriptQuerySinkError<Sink::Error>;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.sink
            .write_bytes(bytes)
            .map_err(CommonProofTranscriptQuerySinkError::Sink)?;
        self.absorber
            .absorb(bytes)
            .map_err(CommonProofTranscriptQuerySinkError::Transcript)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofEncodingError<SinkError, ArtifactError> {
    Prover(CommonProofProverError),
    Sink(SinkError),
    Artifact(ArtifactError),
}

pub(crate) fn canonical_proof_object_header_bytes(
    canonical_application_statement_bytes: &[u8],
) -> Result<Vec<u8>, CommonProofProverError> {
    if canonical_application_statement_bytes.is_empty() {
        return Err(CommonProofProverError::InvalidInput);
    }
    ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.encode())
    .map_err(|_| CommonProofProverError::CanonicalEncoding)
}

/// Writes the canonical proof header followed by the complete pre-query body
/// prefix in the exact order consumed by `body.rs`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_common_proof_prefix<Sink>(
    sink: &mut Sink,
    canonical_header_bytes: &[u8],
    catalog: &CompleteProofTreeCatalog,
    tree_roots: &[[u8; HASH_BYTE_LENGTH]],
    deep_evaluations: &[ProofChallengeExtensionElement],
    terminal_coefficients: &[ProofChallengeExtensionElement],
    transcript_schedule: &CommonProofTranscriptSchedule,
) -> Result<(), CommonProofEncodingError<Sink::Error, core::convert::Infallible>>
where
    Sink: CommonProofByteSink,
{
    let expected_opening_claim_count =
        usize::try_from(transcript_schedule.opening_claim_count())
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?;
    if canonical_header_bytes.is_empty()
        || tree_roots.len() != catalog.entries().len()
        || deep_evaluations.len() != expected_opening_claim_count
        || terminal_coefficients.len()
            != usize::try_from(transcript_schedule.terminal_coefficient_count()).map_err(|_| {
                CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
            })?
    {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    sink.write_bytes(canonical_header_bytes)
        .map_err(CommonProofEncodingError::Sink)?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(
            source,
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                ..
            }
        )
    })?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(
            source,
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                ..
            }
        )
    })?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(source, ProofTreeCatalogSource::QuotientComponent { .. })
    })?;
    write_extension_list(sink, deep_evaluations)?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        source == ProofTreeCatalogSource::OpeningBatchMask
    })?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(source, ProofTreeCatalogSource::NonterminalFriLayer { .. })
    })?;
    write_extension_list(sink, terminal_coefficients)?;
    Ok(())
}

fn write_roots_for_phase<Sink>(
    sink: &mut Sink,
    catalog: &CompleteProofTreeCatalog,
    tree_roots: &[[u8; HASH_BYTE_LENGTH]],
    mut belongs_to_phase: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<(), CommonProofEncodingError<Sink::Error, core::convert::Infallible>>
where
    Sink: CommonProofByteSink,
{
    for (entry, root) in catalog.entries().iter().zip(tree_roots) {
        if belongs_to_phase(entry.source()) {
            sink.write_bytes(root)
                .map_err(CommonProofEncodingError::Sink)?;
        }
    }
    Ok(())
}

fn write_extension_list<Sink>(
    sink: &mut Sink,
    values: &[ProofChallengeExtensionElement],
) -> Result<(), CommonProofEncodingError<Sink::Error, core::convert::Infallible>>
where
    Sink: CommonProofByteSink,
{
    write_u16(
        sink,
        CanonicalItemType::ChallengeExtensionElement.canonical_code(),
    )?;
    write_u32(
        sink,
        u32::try_from(values.len())
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )?;
    for value in values {
        for coordinate in value.canonical_coordinates() {
            sink.write_bytes(&coordinate.to_le_bytes())
                .map_err(CommonProofEncodingError::Sink)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofOpeningGeometry {
    pub(crate) tree_catalog_index: u16,
    pub(crate) leaf_count: usize,
    pub(crate) canonical_leaf_byte_length: usize,
}

/// Computes the exact query-section length before the transcript starts its
/// streamed query-opening round.
pub(crate) fn common_proof_query_section_byte_length(
    catalog: &CompleteProofTreeCatalog,
    geometries: &[CommonProofOpeningGeometry],
    sorted_query_representatives: &[u64],
) -> Result<usize, CommonProofProverError> {
    validate_query_geometry(catalog, geometries, sorted_query_representatives)?;
    let mut byte_length = 4_usize;
    for (entry, geometry) in catalog.entries().iter().zip(geometries) {
        let opened_indexes = opened_leaf_indexes(
            entry.source(),
            catalog.evaluation_domain_size(),
            sorted_query_representatives,
        )?;
        let frontier_count = minimal_frontier_node_count(&opened_indexes, geometry.leaf_count)?;
        let leaf_payload = opened_indexes
            .len()
            .checked_mul(
                geometry
                    .canonical_leaf_byte_length
                    .checked_add(4)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        byte_length = byte_length
            .checked_add(56)
            .and_then(|length| length.checked_add(leaf_payload))
            .and_then(|length| {
                length.checked_add(frontier_count.checked_mul(AUTHENTICATION_DIGEST_BYTE_LENGTH)?)
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    if byte_length > u32::MAX as usize {
        return Err(CommonProofProverError::CountOverflow);
    }
    Ok(byte_length)
}

fn validate_query_geometry(
    catalog: &CompleteProofTreeCatalog,
    geometries: &[CommonProofOpeningGeometry],
    sorted_query_representatives: &[u64],
) -> Result<(), CommonProofProverError> {
    if geometries.len() != catalog.entries().len()
        || sorted_query_representatives.is_empty()
        || !sorted_query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_query_representatives
            .last()
            .is_some_and(|representative| *representative >= catalog.evaluation_domain_size() / 2)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    for (entry, geometry) in catalog.entries().iter().zip(geometries) {
        if geometry.tree_catalog_index != entry.tree_catalog_index()
            || geometry.leaf_count == 0
            || !geometry.leaf_count.is_power_of_two()
            || geometry.canonical_leaf_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        validate_common_proof_opening_geometry(entry, *geometry)?;
    }
    Ok(())
}

fn validate_common_proof_opening_geometry(
    catalog_entry: &ProofTreeCatalogEntry,
    geometry: CommonProofOpeningGeometry,
) -> Result<(), CommonProofProverError> {
    let Some(context) = catalog_entry.common_context() else {
        return Ok(());
    };
    let expected_leaf_count = context.leaf_count()?;
    let expected_leaf_byte_length = canonical_common_proof_leaf_byte_length(
        context,
        common_proof_tree_value_type(catalog_entry)?,
    )?;
    if geometry.leaf_count != expected_leaf_count
        || geometry.canonical_leaf_byte_length != expected_leaf_byte_length
    {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(())
}

fn write_opening_record<Sink>(
    sink: &mut Sink,
    tree_catalog_index: u16,
    canonical_leaf_byte_length: usize,
    artifact: &PrefetchedCommonProofOpeningArtifact,
) -> Result<(), CommonProofEncodingError<Sink::Error, CommonProofProverError>>
where
    Sink: CommonProofByteSink,
{
    let opened_indexes = artifact.opened_leaf_indexes();
    write_tuple_header(
        sink,
        PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        2,
    )?;
    write_u16_item(sink, tree_catalog_index)?;
    let list_payload_length = opened_indexes
        .len()
        .checked_mul(canonical_leaf_byte_length.checked_add(4).ok_or(
            CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .and_then(|length| length.checked_add(6))
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    write_item_header(
        sink,
        CanonicalItemType::HomogeneousList,
        list_payload_length,
    )?;
    write_u16(sink, CanonicalItemType::RawBytes.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(opened_indexes.len())
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )?;
    for position in 0..opened_indexes.len() {
        write_u32(
            sink,
            u32::try_from(canonical_leaf_byte_length).map_err(|_| {
                CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
            })?,
        )?;
        let leaf_bytes = artifact
            .canonical_leaf_bytes_by_position(position)
            .map_err(CommonProofEncodingError::Artifact)?;
        sink.write_bytes(leaf_bytes)
            .map_err(CommonProofEncodingError::Sink)?;
    }
    Ok(())
}

fn write_authentication_frontier<Sink>(
    sink: &mut Sink,
    tree_catalog_index: u16,
    artifact: &PrefetchedCommonProofOpeningArtifact,
) -> Result<(), CommonProofEncodingError<Sink::Error, CommonProofProverError>>
where
    Sink: CommonProofByteSink,
{
    let frontier_coordinates = artifact.frontier_coordinates();
    let frontier_count = frontier_coordinates.len();
    write_tuple_header(
        sink,
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_VERSION,
        2,
    )?;
    write_u16_item(sink, tree_catalog_index)?;
    let list_payload_length = frontier_count
        .checked_mul(AUTHENTICATION_DIGEST_BYTE_LENGTH)
        .and_then(|length| length.checked_add(6))
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    write_item_header(
        sink,
        CanonicalItemType::HomogeneousList,
        list_payload_length,
    )?;
    write_u16(sink, CanonicalItemType::Hash512.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(frontier_count)
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )?;
    for position in 0..frontier_coordinates.len() {
        let digest = artifact
            .frontier_digest_by_position(position)
            .map_err(CommonProofEncodingError::Artifact)?;
        sink.write_bytes(&digest)
            .map_err(CommonProofEncodingError::Sink)?;
    }
    Ok(())
}

fn artifact_matches_query_representatives(
    source: ProofTreeCatalogSource,
    evaluation_domain_size: u64,
    sorted_query_representatives: &[u64],
    opened_leaf_indexes: &[u64],
) -> Result<bool, CommonProofEncodingError<BoundedCommonProofByteSinkError, CommonProofProverError>>
{
    if !opened_leaf_indexes.windows(2).all(|pair| pair[0] < pair[1]) {
        return Ok(false);
    }
    let ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal } = source else {
        return Ok(opened_leaf_indexes == sorted_query_representatives);
    };
    let shift = u32::from(fold_ordinal)
        .checked_add(2)
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let leaf_count = evaluation_domain_size
        .checked_shr(shift)
        .filter(|count| *count != 0)
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidTree,
        ))?;
    if opened_leaf_indexes
        .last()
        .is_some_and(|leaf_index| *leaf_index >= leaf_count)
    {
        return Ok(false);
    }
    let every_query_is_opened = sorted_query_representatives.iter().all(|representative| {
        opened_leaf_indexes
            .binary_search(&(representative % leaf_count))
            .is_ok()
    });
    let every_opened_leaf_is_queried = opened_leaf_indexes.iter().all(|leaf_index| {
        sorted_query_representatives
            .iter()
            .any(|representative| representative % leaf_count == *leaf_index)
    });
    Ok(every_query_is_opened && every_opened_leaf_is_queried)
}

pub(super) fn opened_leaf_indexes(
    source: ProofTreeCatalogSource,
    evaluation_domain_size: u64,
    sorted_query_representatives: &[u64],
) -> Result<Vec<u64>, CommonProofProverError> {
    if let ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal } = source {
        let shift = u32::from(fold_ordinal)
            .checked_add(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let leaf_count = evaluation_domain_size
            .checked_shr(shift)
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidTree)?;
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

fn minimal_frontier_node_count(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<usize, CommonProofProverError> {
    Ok(minimal_frontier_coordinates(sorted_unique_leaf_indexes, leaf_count)?.len())
}

fn write_tuple_header<Sink, ArtifactError>(
    sink: &mut Sink,
    schema_identifier: u16,
    schema_version: u16,
    item_count: u32,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    sink.write_bytes(&schema_identifier.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)?;
    sink.write_bytes(&schema_version.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)?;
    sink.write_bytes(&item_count.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}

fn write_item_header<Sink, ArtifactError>(
    sink: &mut Sink,
    item_type: CanonicalItemType,
    byte_length: usize,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_u16(sink, item_type.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(byte_length)
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )
}

fn write_u16_item<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u16,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_item_header(sink, CanonicalItemType::Unsigned16, 2)?;
    write_u16(sink, value)
}

fn write_u16<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u16,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    sink.write_bytes(&value.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}

fn write_u32<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u32,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    sink.write_bytes(&value.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}
