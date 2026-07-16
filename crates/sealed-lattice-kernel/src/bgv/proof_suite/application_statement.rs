//! Canonical application-statement schemas for the selected proof suite.

use crate::{
    bgv::{
        evaluator::program::selected_evaluator_program_set, parameters::DATA_PRIMES,
        target_decryption::selected_target_partial_decryption_stream_byte_length,
    },
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings, StreamDescriptor,
    },
};

const ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER: u16 = 0x1219;
const EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x121a;
const APPLICATION_STATEMENT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedApplicationStatementError {
    CanonicalEncoding,
    WrongSchema,
    WrongTypeOrLength,
    WrongValue,
    InvalidProfile,
    CountOverflow,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SelectedApplicationStatementContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

impl SelectedApplicationStatementContext {
    pub(crate) const fn new(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Self {
        Self {
            protocol_version,
            suite_identifier,
            schedule_position,
            top_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatementFieldShape {
    ExactUnsigned16(u16),
    RosterPosition,
    ExactUnsigned32(u32),
    Unsigned64,
    Hash,
    ExactHash([u8; Hash512::BYTE_LENGTH]),
    ParticipantIdentity,
    HashList(usize),
    RoundOneSourceRootPairs(usize),
    EvaluatorKeyAggregateEntries(Vec<SelectedEvaluatorEntryPosition>),
    StreamDescriptor { exact_total_byte_length: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedEvaluatorEntryKind {
    Relinearization {
        catalog_level: usize,
    },
    Galois {
        galois_element: usize,
        catalog_level: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorEntryPosition {
    key_kind: SelectedEvaluatorEntryKind,
    schedule_position: u32,
}

impl SelectedEvaluatorEntryPosition {
    pub(crate) const fn key_kind(self) -> SelectedEvaluatorEntryKind {
        self.key_kind
    }

    pub(crate) const fn schedule_position(self) -> u32 {
        self.schedule_position
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorAggregateEntryRoots {
    entry_ordinal: u32,
    position: SelectedEvaluatorEntryPosition,
    runtime_component_root: [u8; Hash512::BYTE_LENGTH],
    auxiliary_component_root: [u8; Hash512::BYTE_LENGTH],
}

pub(crate) struct SelectedEvaluatorAggregateEntryInput<'input> {
    source_component_roots: &'input [[u8; Hash512::BYTE_LENGTH]],
    runtime_component_root: [u8; Hash512::BYTE_LENGTH],
    auxiliary_component_root: [u8; Hash512::BYTE_LENGTH],
}

impl<'input> SelectedEvaluatorAggregateEntryInput<'input> {
    pub(crate) const fn new(
        source_component_roots: &'input [[u8; Hash512::BYTE_LENGTH]],
        runtime_component_root: [u8; Hash512::BYTE_LENGTH],
        auxiliary_component_root: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            source_component_roots,
            runtime_component_root,
            auxiliary_component_root,
        }
    }
}

impl SelectedEvaluatorAggregateEntryRoots {
    pub(crate) const fn entry_ordinal(self) -> u32 {
        self.entry_ordinal
    }

    pub(crate) const fn position(self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) const fn runtime_component_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.runtime_component_root
    }

    pub(crate) const fn auxiliary_component_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.auxiliary_component_root
    }
}

pub(crate) fn decode_selected_application_statement(
    canonical_bytes: &[u8],
    expected_schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<CanonicalTuple, SelectedApplicationStatementError> {
    let statement = CanonicalTuple::decode(canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    validate_selected_application_statement(&statement, expected_schema_identifier, context)?;
    if statement
        .encode()
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?
        != canonical_bytes
    {
        return Err(SelectedApplicationStatementError::CanonicalEncoding);
    }
    Ok(statement)
}

pub(crate) fn canonical_selected_application_statement_for_ceiling(
    schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    let fields = selected_statement_field_shapes(schema_identifier, context)?;
    let items = fields
        .iter()
        .map(canonical_item_for_statement_field)
        .collect::<Result<Vec<_>, _>>()?;
    let canonical_bytes = CanonicalTuple::new(
        schema_identifier,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        items,
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_application_statement(&canonical_bytes, schema_identifier, context)?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_evaluator_aggregate_statement(
    evaluator_context_hash: [u8; Hash512::BYTE_LENGTH],
    top_count: u16,
    entry_ordinal: u32,
    entry: &SelectedEvaluatorAggregateEntryInput<'_>,
    evaluator_key_store_digest: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    let position = selected_evaluator_entry_position(top_count, entry_ordinal)?;
    if entry.source_component_roots.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let source_roots = entry
        .source_component_roots
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    let aggregate_roots = [
        CanonicalItem::hash512(entry.runtime_component_root),
        CanonicalItem::hash512(entry.auxiliary_component_root),
    ];
    let entry_items = [CanonicalItem::nested_tuple(&CanonicalTuple::new(
        EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned32(position.schedule_position),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &source_roots)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &aggregate_roots)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
        ],
    ))
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?];
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(evaluator_context_hash),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entry_items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
            CanonicalItem::hash512(evaluator_key_store_digest),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_application_statement(
        &canonical_bytes,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(entry_ordinal),
            Some(top_count),
        ),
    )?;
    Ok(canonical_bytes)
}

fn validate_selected_application_statement(
    statement: &CanonicalTuple,
    expected_schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<(), SelectedApplicationStatementError> {
    if statement.schema_identifier != expected_schema_identifier
        || statement.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
    {
        return Err(SelectedApplicationStatementError::WrongSchema);
    }
    let fields = selected_statement_field_shapes(expected_schema_identifier, context)?;
    if statement.items.len() != fields.len() {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    for (item, field) in statement.items.iter().zip(fields.iter()) {
        validate_statement_field(item, field)?;
    }
    Ok(())
}

fn selected_statement_field_shapes(
    schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<Vec<StatementFieldShape>, SelectedApplicationStatementError> {
    let hash = StatementFieldShape::Hash;
    let exact_suite = StatementFieldShape::ExactHash(context.suite_identifier);
    let participant = StatementFieldShape::ParticipantIdentity;
    let roster_position = StatementFieldShape::RosterPosition;
    let protocol_version = StatementFieldShape::ExactUnsigned16(context.protocol_version);
    let schedule_position = || {
        context
            .schedule_position
            .map(StatementFieldShape::ExactUnsigned32)
            .ok_or(SelectedApplicationStatementError::InvalidProfile)
    };
    let require_no_schedule = || {
        if context.schedule_position.is_some() {
            Err(SelectedApplicationStatementError::InvalidProfile)
        } else {
            Ok(())
        }
    };
    let require_no_top_count = || {
        if context.top_count.is_some() {
            Err(SelectedApplicationStatementError::InvalidProfile)
        } else {
            Ok(())
        }
    };

    let fields = match schema_identifier {
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(vss_coefficient_material_root_count()?),
                StatementFieldShape::HashList(vss_recipient_share_material_root_count()?),
            ]
        }
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                roster_position,
                hash.clone(),
                StatementFieldShape::HashList(vss_recipient_share_material_root_count()?),
                StatementFieldShape::HashList(DATA_PRIMES.len()),
            ]
        }
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(DATA_PRIMES.len()),
                StatementFieldShape::HashList(3),
            ]
        }
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(3),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                hash.clone(),
                StatementFieldShape::HashList(usize::from(
                    FOUNDATION_PROFILE.participant_count,
                )),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                schedule_position()?,
                StatementFieldShape::HashList(3),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                schedule_position()?,
                StatementFieldShape::RoundOneSourceRootPairs(usize::from(
                    FOUNDATION_PROFILE.participant_count,
                )),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                schedule_position()?,
                StatementFieldShape::HashList(3),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                schedule_position()?,
                StatementFieldShape::HashList(3),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            let entry_ordinal = context
                .schedule_position
                .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
            let top_count = context
                .top_count
                .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
            vec![
                hash.clone(),
                StatementFieldShape::EvaluatorKeyAggregateEntries(vec![
                    selected_evaluator_entry_position(top_count, entry_ordinal)?,
                ]),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                StatementFieldShape::Unsigned64,
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            let target_stream_byte_length = u64::try_from(
                selected_target_partial_decryption_stream_byte_length()
                    .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?,
            )
            .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(DATA_PRIMES.len()),
                StatementFieldShape::StreamDescriptor {
                    exact_total_byte_length: target_stream_byte_length,
                },
                StatementFieldShape::StreamDescriptor {
                    exact_total_byte_length: target_stream_byte_length,
                },
            ]
        }
        _ => return Err(SelectedApplicationStatementError::WrongSchema),
    };
    Ok(fields)
}

pub(crate) fn selected_evaluator_entry_positions(
    top_count: u16,
) -> Result<Vec<SelectedEvaluatorEntryPosition>, SelectedApplicationStatementError> {
    let key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
    let stream = key_positions
        .streams()
        .get(
            usize::from(top_count)
                .checked_sub(1)
                .ok_or(SelectedApplicationStatementError::InvalidProfile)?,
        )
        .filter(|stream| stream.top_count() == top_count)
        .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
    let mut positions = Vec::new();
    positions
        .try_reserve_exact(
            stream
                .relinearization_catalog_levels()
                .len()
                .checked_add(stream.galois_catalog_positions().len())
                .ok_or(SelectedApplicationStatementError::CountOverflow)?,
        )
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    for level in stream.relinearization_catalog_levels() {
        let catalog_position = key_positions
            .relinearization_catalog_levels()
            .binary_search(level)
            .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
        positions.push(SelectedEvaluatorEntryPosition {
            key_kind: SelectedEvaluatorEntryKind::Relinearization {
                catalog_level: *level,
            },
            schedule_position: u32::try_from(catalog_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        });
    }
    for position in stream.galois_catalog_positions() {
        let catalog_position = key_positions
            .galois_catalog_positions()
            .binary_search(position)
            .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
        positions.push(SelectedEvaluatorEntryPosition {
            key_kind: SelectedEvaluatorEntryKind::Galois {
                galois_element: position.galois_element(),
                catalog_level: position.catalog_level(),
            },
            schedule_position: u32::try_from(catalog_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        });
    }
    Ok(positions)
}

pub(crate) fn selected_evaluator_entry_position(
    top_count: u16,
    entry_ordinal: u32,
) -> Result<SelectedEvaluatorEntryPosition, SelectedApplicationStatementError> {
    selected_evaluator_entry_positions(top_count)?
        .get(
            usize::try_from(entry_ordinal)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        )
        .copied()
        .ok_or(SelectedApplicationStatementError::InvalidProfile)
}

pub(crate) fn selected_evaluator_aggregate_entry_roots(
    statement: &CanonicalTuple,
    top_count: u16,
    entry_ordinal: u32,
) -> Result<SelectedEvaluatorAggregateEntryRoots, SelectedApplicationStatementError> {
    if statement.schema_identifier
        != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        || statement.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
        || statement.items.len() != 3
    {
        return Err(SelectedApplicationStatementError::WrongSchema);
    }
    let position = selected_evaluator_entry_position(top_count, entry_ordinal)?;
    let entries = decode_nested_tuple_list(&statement.items[1], 1)?;
    let entry = &entries[0];
    if entry.schema_identifier != EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER
        || entry.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
        || entry.items.len() != 3
        || read_unsigned32(&entry.items[0])? != position.schedule_position
    {
        return Err(SelectedApplicationStatementError::WrongSchema);
    }
    validate_hash_list(
        &entry.items[1],
        usize::from(FOUNDATION_PROFILE.participant_count),
    )?;
    let aggregate_roots = read_hash_list_values(&entry.items[2], 2)?;
    Ok(SelectedEvaluatorAggregateEntryRoots {
        entry_ordinal,
        position,
        runtime_component_root: aggregate_roots[0],
        auxiliary_component_root: aggregate_roots[1],
    })
}

fn vss_coefficient_material_root_count() -> Result<usize, SelectedApplicationStatementError> {
    DATA_PRIMES
        .len()
        .checked_mul(usize::from(FOUNDATION_PROFILE.reconstruction_threshold))
        .ok_or(SelectedApplicationStatementError::CountOverflow)
}

fn vss_recipient_share_material_root_count() -> Result<usize, SelectedApplicationStatementError> {
    DATA_PRIMES
        .len()
        .checked_mul(usize::from(FOUNDATION_PROFILE.participant_count))
        .ok_or(SelectedApplicationStatementError::CountOverflow)
}

fn canonical_item_for_statement_field(
    field: &StatementFieldShape,
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    match field {
        StatementFieldShape::ExactUnsigned16(value) => Ok(CanonicalItem::unsigned16(*value)),
        StatementFieldShape::RosterPosition => Ok(CanonicalItem::unsigned16(0)),
        StatementFieldShape::ExactUnsigned32(value) => Ok(CanonicalItem::unsigned32(*value)),
        StatementFieldShape::Unsigned64 => Ok(CanonicalItem::unsigned64(0)),
        StatementFieldShape::Hash => Ok(CanonicalItem::hash512([0; Hash512::BYTE_LENGTH])),
        StatementFieldShape::ExactHash(value) => Ok(CanonicalItem::hash512(*value)),
        StatementFieldShape::ParticipantIdentity => Ok(CanonicalItem::participant_identity(
            [0; Hash512::BYTE_LENGTH],
        )),
        StatementFieldShape::HashList(count) => canonical_hash_list(*count),
        StatementFieldShape::RoundOneSourceRootPairs(count) => {
            let items = (0..*count)
                .map(|_| {
                    CanonicalItem::nested_tuple(&CanonicalTuple::new(
                        ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER,
                        APPLICATION_STATEMENT_SCHEMA_VERSION,
                        vec![
                            CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
                            CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
                        ],
                    ))
                    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
                })
                .collect::<Result<Vec<_>, _>>()?;
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        }
        StatementFieldShape::EvaluatorKeyAggregateEntries(positions) => {
            let items = positions
                .iter()
                .map(|position| {
                    let tuple = CanonicalTuple::new(
                        EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER,
                        APPLICATION_STATEMENT_SCHEMA_VERSION,
                        vec![
                            CanonicalItem::unsigned32(position.schedule_position),
                            canonical_hash_list(usize::from(FOUNDATION_PROFILE.participant_count))?,
                            canonical_hash_list(2)?,
                        ],
                    );
                    CanonicalItem::nested_tuple(&tuple)
                        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
                })
                .collect::<Result<Vec<_>, _>>()?;
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        }
        StatementFieldShape::StreamDescriptor {
            exact_total_byte_length,
        } => canonical_stream_descriptor_item(*exact_total_byte_length),
    }
}

fn validate_statement_field(
    item: &CanonicalItem,
    field: &StatementFieldShape,
) -> Result<(), SelectedApplicationStatementError> {
    match field {
        StatementFieldShape::ExactUnsigned16(expected) => {
            if read_unsigned16(item)? != *expected {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::RosterPosition => {
            if read_unsigned16(item)? >= FOUNDATION_PROFILE.participant_count {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::ExactUnsigned32(expected) => {
            if read_unsigned32(item)? != *expected {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::Unsigned64 => {
            require_fixed_item(item, CanonicalItemType::Unsigned64, 8)?;
        }
        StatementFieldShape::Hash => {
            require_fixed_item(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
        }
        StatementFieldShape::ExactHash(expected) => {
            require_fixed_item(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
            if item.canonical_bytes() != expected {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::ParticipantIdentity => {
            require_fixed_item(
                item,
                CanonicalItemType::ParticipantIdentity,
                Hash512::BYTE_LENGTH,
            )?;
        }
        StatementFieldShape::HashList(expected_count) => {
            validate_hash_list(item, *expected_count)?;
        }
        StatementFieldShape::RoundOneSourceRootPairs(expected_count) => {
            let tuples = decode_nested_tuple_list(item, *expected_count)?;
            for tuple in tuples {
                if tuple.schema_identifier != ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER
                    || tuple.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
                    || tuple.items.len() != 2
                {
                    return Err(SelectedApplicationStatementError::WrongSchema);
                }
                for root in &tuple.items {
                    require_fixed_item(root, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
                }
            }
        }
        StatementFieldShape::EvaluatorKeyAggregateEntries(positions) => {
            let tuples = decode_nested_tuple_list(item, positions.len())?;
            for (tuple, position) in tuples.iter().zip(positions.iter()) {
                if tuple.schema_identifier != EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER
                    || tuple.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
                    || tuple.items.len() != 3
                {
                    return Err(SelectedApplicationStatementError::WrongSchema);
                }
                if read_unsigned32(&tuple.items[0])? != position.schedule_position {
                    return Err(SelectedApplicationStatementError::WrongValue);
                }
                validate_hash_list(
                    &tuple.items[1],
                    usize::from(FOUNDATION_PROFILE.participant_count),
                )?;
                // Runtime B is the only aggregated/proved component. The
                // second root is the linked RKG A or verifier-derived Galois A.
                validate_hash_list(&tuple.items[2], 2)?;
            }
        }
        StatementFieldShape::StreamDescriptor {
            exact_total_byte_length,
        } => {
            require_item_type(item, CanonicalItemType::NestedTuple)?;
            let descriptor =
                StreamDescriptor::decode(item.canonical_bytes(), &CanonicalDecodeLimits::default())
                    .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
            if descriptor.total_byte_length != *exact_total_byte_length {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
    }
    Ok(())
}

fn canonical_hash_list(count: usize) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let items = vec![CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]); count];
    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &items)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn canonical_stream_descriptor_item(
    total_byte_length: u64,
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    let chunk_count = total_byte_length
        .checked_sub(1)
        .and_then(|length| length.checked_div(chunk_byte_length))
        .and_then(|count| count.checked_add(1))
        .ok_or(SelectedApplicationStatementError::CountOverflow)?;
    let descriptor = StreamDescriptor::new(
        total_byte_length,
        vec![
            Hash512::from_bytes([0; Hash512::BYTE_LENGTH]);
            usize::try_from(chunk_count)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?
        ],
        Hash512::from_bytes([0; Hash512::BYTE_LENGTH]),
    )
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    let descriptor_tuple = CanonicalTuple::decode(
        &descriptor
            .encode()
            .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    CanonicalItem::nested_tuple(&descriptor_tuple)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn require_item_type(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> Result<(), SelectedApplicationStatementError> {
    if item.item_type() != expected_type {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(())
}

fn require_fixed_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> Result<(), SelectedApplicationStatementError> {
    require_item_type(item, expected_type)?;
    if item.canonical_bytes().len() != expected_byte_length {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(())
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, SelectedApplicationStatementError> {
    require_fixed_item(item, CanonicalItemType::Unsigned16, 2)?;
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?,
    ))
}

fn read_unsigned32(item: &CanonicalItem) -> Result<u32, SelectedApplicationStatementError> {
    require_fixed_item(item, CanonicalItemType::Unsigned32, 4)?;
    Ok(u32::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?,
    ))
}

fn validate_hash_list(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<(), SelectedApplicationStatementError> {
    let (count, payload) = read_list_header(item, CanonicalItemType::Hash512)?;
    if count != expected_count
        || payload.len()
            != count
                .checked_mul(Hash512::BYTE_LENGTH)
                .ok_or(SelectedApplicationStatementError::CountOverflow)?
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(())
}

fn read_hash_list_values(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<Vec<[u8; Hash512::BYTE_LENGTH]>, SelectedApplicationStatementError> {
    validate_hash_list(item, expected_count)?;
    let (_, payload) = read_list_header(item, CanonicalItemType::Hash512)?;
    payload
        .chunks_exact(Hash512::BYTE_LENGTH)
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)
        })
        .collect()
}

fn decode_nested_tuple_list(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<Vec<CanonicalTuple>, SelectedApplicationStatementError> {
    let (count, payload) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count != expected_count {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let mut tuples = Vec::new();
    tuples
        .try_reserve_exact(count)
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    let mut offset = 0_usize;
    for _ in 0..count {
        let tuple_byte_length = encoded_tuple_byte_length(
            payload
                .get(offset..)
                .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?,
        )?;
        let next_offset = offset
            .checked_add(tuple_byte_length)
            .ok_or(SelectedApplicationStatementError::CountOverflow)?;
        let tuple = CanonicalTuple::decode(
            payload
                .get(offset..next_offset)
                .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?,
            &CanonicalDecodeLimits::default(),
        )
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
        tuples.push(tuple);
        offset = next_offset;
    }
    if offset != payload.len() {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(tuples)
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> Result<(usize, &[u8]), SelectedApplicationStatementError> {
    require_item_type(item, CanonicalItemType::HomogeneousList)?;
    let bytes = item.canonical_bytes();
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let count = usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    Ok((count, &bytes[6..]))
}

fn encoded_tuple_byte_length(bytes: &[u8]) -> Result<usize, SelectedApplicationStatementError> {
    if bytes.len() < 8 {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let item_count = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header = bytes
            .get(offset..offset + 6)
            .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?;
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([header[0], header[1]]))
            .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?;
        let item_byte_length = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
        offset = offset
            .checked_add(6)
            .and_then(|value| value.checked_add(item_byte_length))
            .filter(|value| *value <= bytes.len())
            .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?;
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_statement_schema_uses_the_single_statement_owner() {
        let cases = [
            (
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                Some(1),
            ),
            (
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
        ];
        for (schema_identifier, schedule_position, top_count) in cases {
            let context = SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0x5a; Hash512::BYTE_LENGTH],
                schedule_position,
                top_count,
            );
            let bytes =
                canonical_selected_application_statement_for_ceiling(schema_identifier, context)
                    .expect("statement encodes");
            let decoded = decode_selected_application_statement(&bytes, schema_identifier, context)
                .expect("statement decodes");
            assert_eq!(decoded.encode().expect("statement re-encodes"), bytes);
        }
    }

    #[test]
    fn selected_statement_decoder_rejects_truncation_and_wrong_context() {
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x31; Hash512::BYTE_LENGTH],
            None,
            None,
        );
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("ballot statement");
        for truncated_length in [0, 1, 7, bytes.len() - 1] {
            assert!(
                decode_selected_application_statement(
                    &bytes[..truncated_length],
                    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                    context,
                )
                .is_err()
            );
        }
        assert!(
            decode_selected_application_statement(
                &bytes,
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0x32; Hash512::BYTE_LENGTH],
                    None,
                    None,
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn evaluator_statement_uses_segment_local_catalog_positions() {
        for (entry_ordinal, expected_schedule_position) in [(0, 0), (1, 0), (16, 15)] {
            let context = SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                Some(entry_ordinal),
                Some(20),
            );
            let bytes = canonical_selected_application_statement_for_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .expect("evaluator entry statement");
            let tuple = decode_selected_application_statement(
                &bytes,
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .expect("evaluator entry statement decodes");
            let entries = decode_nested_tuple_list(&tuple.items[1], 1).expect("one entry");
            assert_eq!(entries[0].items.len(), 3);
            assert_eq!(
                read_unsigned32(&entries[0].items[0]),
                Ok(expected_schedule_position)
            );
        }
        assert!(
            canonical_selected_application_statement_for_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    Some(17),
                    Some(20),
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn evaluator_statement_decoder_rejects_multiple_entries_and_wrong_catalog_position() {
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(1),
            Some(20),
        );
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("evaluator statement");
        let tuple = CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default())
            .expect("canonical statement");
        let entries = decode_nested_tuple_list(&tuple.items[1], 1).expect("entry");

        let duplicate =
            replace_evaluator_entries(&tuple, &[entries[0].clone(), entries[0].clone()]);
        assert_eq!(
            decode_selected_application_statement(
                &duplicate,
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .err(),
            Some(SelectedApplicationStatementError::WrongTypeOrLength),
        );

        let mut wrong_position_entries = entries;
        wrong_position_entries[0].items[0] = CanonicalItem::unsigned32(1);
        let wrong_position = replace_evaluator_entries(&tuple, &wrong_position_entries);
        assert_eq!(
            decode_selected_application_statement(
                &wrong_position,
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .err(),
            Some(SelectedApplicationStatementError::WrongValue),
        );
    }

    #[test]
    fn typed_evaluator_statement_constructor_owns_the_selected_entry_order() {
        let source_roots = (0..FOUNDATION_PROFILE.participant_count)
            .map(|participant_index| [participant_index as u8; Hash512::BYTE_LENGTH])
            .collect::<Vec<_>>();
        let entry = SelectedEvaluatorAggregateEntryInput::new(
            &source_roots,
            [0x40; Hash512::BYTE_LENGTH],
            [0x80; Hash512::BYTE_LENGTH],
        );
        let bytes = canonical_selected_evaluator_aggregate_statement(
            [0x21; Hash512::BYTE_LENGTH],
            20,
            16,
            &entry,
            [0x22; Hash512::BYTE_LENGTH],
        )
        .expect("typed evaluator statement");
        let decoded = decode_selected_application_statement(
            &bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                Some(16),
                Some(20),
            ),
        )
        .expect("typed statement decodes");
        let decoded_entry =
            selected_evaluator_aggregate_entry_roots(&decoded, 20, 16).expect("typed roots");
        assert_eq!(decoded_entry.entry_ordinal(), 16);
        assert_eq!(decoded_entry.position().schedule_position(), 15);
        assert_eq!(decoded_entry.runtime_component_root(), [0x40; 64]);
        assert_eq!(decoded_entry.auxiliary_component_root(), [0x80; 64]);

        assert!(
            canonical_selected_evaluator_aggregate_statement(
                [0x21; Hash512::BYTE_LENGTH],
                20,
                17,
                &entry,
                [0x22; Hash512::BYTE_LENGTH],
            )
            .is_err()
        );
    }

    fn replace_evaluator_entries(
        statement: &CanonicalTuple,
        entries: &[CanonicalTuple],
    ) -> Vec<u8> {
        let entry_items = entries
            .iter()
            .map(|entry| CanonicalItem::nested_tuple(entry).expect("entry encodes"))
            .collect::<Vec<_>>();
        let mut mutated = statement.clone();
        mutated.items[1] =
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entry_items)
                .expect("entry list encodes");
        mutated.encode().expect("statement encodes")
    }
}
