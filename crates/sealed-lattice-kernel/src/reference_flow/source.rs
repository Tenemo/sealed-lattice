use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_fixed_byte_slice, read_hash, read_hash_array, read_u16, require_tuple},
    challenge::{ChallengeDealerCoordinates, verify_and_aggregate_challenge},
    direct_check::verify_vertical_source_response_batch,
    field::{
        DIRECT_CHECK_REPETITION_COUNT, FieldElement, PARTICIPANT_COUNT, pack_field_elements,
        unpack_field_elements,
    },
    flow_context::{
        FLOW_CONTEXT_ITEM_COUNT, ReferenceFlowContext, hash_item, require_participant_position,
    },
    inventory::{
        InventoryKind, PROTECTED_SOURCE_POSITION, SourceDeclaration, complete_inventory_identity,
        declaration_inventory_identity, selected_source_identity,
        verify_vertical_source_declarations,
    },
    protocol_oracle::protocol_oracle_512,
    signed_message::VerifiedSignedMessage,
};

const SOURCE_SUBMIT_CONTRIBUTION_SCHEMA_IDENTIFIER: u16 = 0x0270;
const SOURCE_ABSTAIN_CONTRIBUTION_SCHEMA_IDENTIFIER: u16 = 0x0271;
const SOURCE_NOT_OWNED_CONTRIBUTION_SCHEMA_IDENTIFIER: u16 = 0x0272;
const SOURCE_CHALLENGE_OPENING_SCHEMA_IDENTIFIER: u16 = 0x0273;
const SOURCE_RESPONSE_SCHEMA_IDENTIFIER: u16 = 0x0274;
const SOURCE_TERMINAL_SCHEMA_IDENTIFIER: u16 = 0x0275;
const SOURCE_SCHEMA_VERSION: u16 = 1;
const SOURCE_CONTRIBUTION_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 2 + PARTICIPANT_COUNT;
const SOURCE_OPENING_FIELD_ELEMENT_COUNT: usize = PARTICIPANT_COUNT * DIRECT_CHECK_REPETITION_COUNT;
const SOURCE_OPENING_PACKED_BYTE_LENGTH: usize = SOURCE_OPENING_FIELD_ELEMENT_COUNT.div_ceil(2);
const SOURCE_OPENING_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 4 + PARTICIPANT_COUNT;
const SOURCE_RESPONSE_PACKED_BYTE_LENGTH: usize = DIRECT_CHECK_REPETITION_COUNT.div_ceil(2);
const SOURCE_RESPONSE_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 5;
const SOURCE_TERMINAL_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 6;

#[derive(Debug)]
pub(crate) struct VerifiedSourceContribution {
    context: ReferenceFlowContext,
    sender_position: u16,
    preparation_terminal_identity: Hash512,
    declaration: SourceDeclaration,
    mailbox_body_identities: [Hash512; PARTICIPANT_COUNT],
    body_identity: Hash512,
}

#[derive(Debug)]
pub(crate) struct VerifiedSourceChallengeOpening {
    context: ReferenceFlowContext,
    sender_position: u16,
    preparation_terminal_identity: Hash512,
    source_inventory_identity: Hash512,
    mailbox_body_identities: [Hash512; PARTICIPANT_COUNT],
    dealer_challenge_coordinates: Vec<FieldElement>,
    body_identity: Hash512,
}

impl VerifiedSourceChallengeOpening {
    fn dealer_challenge_block(&self, dealer_position: usize) -> &[FieldElement] {
        let start = dealer_position * DIRECT_CHECK_REPETITION_COUNT;
        &self.dealer_challenge_coordinates[start..start + DIRECT_CHECK_REPETITION_COUNT]
    }
}

#[derive(Debug)]
pub(crate) struct VerifiedSourceResponse {
    context: ReferenceFlowContext,
    sender_position: u16,
    preparation_terminal_identity: Hash512,
    source_inventory_identity: Hash512,
    challenge_inventory_identity: Hash512,
    response_coordinates: Vec<FieldElement>,
    body_identity: Hash512,
}

#[derive(Debug)]
pub(crate) struct SourceTerminal {
    context: ReferenceFlowContext,
    preparation_terminal_identity: Hash512,
    declaration_inventory_identity: Hash512,
    source_inventory_identity: Hash512,
    challenge_inventory_identity: Hash512,
    response_inventory_identity: Hash512,
    selected_source_identity: Hash512,
    source_is_present: bool,
}

impl SourceTerminal {
    pub(crate) fn identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/source-terminal/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )
    }

    pub(crate) fn encode(&self) -> ProtocolResult<Vec<u8>> {
        let mut items = Vec::with_capacity(SOURCE_TERMINAL_ITEM_COUNT);
        items.extend(self.context.canonical_items());
        items.extend([
            hash_item(self.preparation_terminal_identity),
            hash_item(self.declaration_inventory_identity),
            hash_item(self.source_inventory_identity),
            hash_item(self.challenge_inventory_identity),
            hash_item(self.response_inventory_identity),
            hash_item(self.selected_source_identity),
        ]);
        Ok(CanonicalTuple::new(
            SOURCE_TERMINAL_SCHEMA_IDENTIFIER,
            SOURCE_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn declaration_inventory_identity(&self) -> Hash512 {
        self.declaration_inventory_identity
    }

    pub(crate) fn source_inventory_identity(&self) -> Hash512 {
        self.source_inventory_identity
    }

    pub(crate) fn context(&self) -> ReferenceFlowContext {
        self.context
    }

    pub(crate) fn preparation_terminal_identity(&self) -> Hash512 {
        self.preparation_terminal_identity
    }

    pub(crate) fn selected_source_identity(&self) -> Hash512 {
        self.selected_source_identity
    }

    pub(crate) fn source_is_present(&self) -> bool {
        self.source_is_present
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(
        context: ReferenceFlowContext,
        preparation_terminal_identity: Hash512,
        source_is_present: bool,
    ) -> Self {
        let marker = if source_is_present { 0x91 } else { 0x92 };
        Self {
            context,
            preparation_terminal_identity,
            declaration_inventory_identity: Hash512::from_bytes([marker; 64]),
            source_inventory_identity: Hash512::from_bytes([marker.wrapping_add(1); 64]),
            challenge_inventory_identity: Hash512::from_bytes([marker.wrapping_add(2); 64]),
            response_inventory_identity: Hash512::from_bytes([marker.wrapping_add(3); 64]),
            selected_source_identity: Hash512::from_bytes([marker.wrapping_add(4); 64]),
            source_is_present,
        }
    }
}

pub(crate) fn encode_source_contribution_body(
    context: ReferenceFlowContext,
    sender_position: usize,
    preparation_terminal_identity: Hash512,
    declaration: SourceDeclaration,
    mailbox_body_identities: &[Hash512],
) -> ProtocolResult<Vec<u8>> {
    require_source_declaration_for_position(sender_position, declaration)?;
    if mailbox_body_identities.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source contribution is missing a mailbox body identity",
        ));
    }
    let schema_identifier = contribution_schema_identifier(declaration);
    let mut items = Vec::with_capacity(SOURCE_CONTRIBUTION_ITEM_COUNT);
    items.extend(context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(sender_position as u16),
        hash_item(preparation_terminal_identity),
    ]);
    items.extend(mailbox_body_identities.iter().copied().map(hash_item));
    Ok(CanonicalTuple::new(schema_identifier, SOURCE_SCHEMA_VERSION, items).encode()?)
}

pub(crate) fn decode_source_contribution(
    message: &VerifiedSignedMessage,
    expected_context: ReferenceFlowContext,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedSourceContribution> {
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    let declaration = declaration_from_schema_identifier(tuple.schema_identifier)?;
    require_tuple(
        &tuple,
        contribution_schema_identifier(declaration),
        SOURCE_SCHEMA_VERSION,
        SOURCE_CONTRIBUTION_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(expected_context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    require_expected_sender(sender_position, expected_sender_position)?;
    require_source_declaration_for_position(expected_sender_position, declaration)?;
    Ok(VerifiedSourceContribution {
        context,
        sender_position,
        preparation_terminal_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1])?,
        declaration,
        mailbox_body_identities: read_hash_array(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 2..])?,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn encode_source_challenge_opening_body(
    context: ReferenceFlowContext,
    sender_position: usize,
    preparation_terminal_identity: Hash512,
    source_inventory_identity: Hash512,
    verified_mailbox_body_identities: &[Hash512],
    dealer_challenge_coordinates: &[FieldElement],
) -> ProtocolResult<Vec<u8>> {
    require_participant_position_from_usize(sender_position)?;
    if verified_mailbox_body_identities.len() != PARTICIPANT_COUNT
        || dealer_challenge_coordinates.len() != SOURCE_OPENING_FIELD_ELEMENT_COUNT
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source opening has an incomplete mailbox or challenge inventory",
        ));
    }
    let packed_challenges = pack_field_elements(dealer_challenge_coordinates);
    let mut items = Vec::with_capacity(SOURCE_OPENING_ITEM_COUNT);
    items.extend(context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(sender_position as u16),
        hash_item(preparation_terminal_identity),
        hash_item(source_inventory_identity),
    ]);
    items.extend(
        verified_mailbox_body_identities
            .iter()
            .copied()
            .map(hash_item),
    );
    items.push(CanonicalItem::fixed_bytes(packed_challenges)?);
    Ok(CanonicalTuple::new(
        SOURCE_CHALLENGE_OPENING_SCHEMA_IDENTIFIER,
        SOURCE_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

pub(crate) fn decode_source_challenge_opening(
    message: &VerifiedSignedMessage,
    expected_context: ReferenceFlowContext,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedSourceChallengeOpening> {
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    require_tuple(
        &tuple,
        SOURCE_CHALLENGE_OPENING_SCHEMA_IDENTIFIER,
        SOURCE_SCHEMA_VERSION,
        SOURCE_OPENING_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(expected_context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    require_expected_sender(sender_position, expected_sender_position)?;
    let mailbox_start = FLOW_CONTEXT_ITEM_COUNT + 3;
    let challenge_index = mailbox_start + PARTICIPANT_COUNT;
    Ok(VerifiedSourceChallengeOpening {
        context,
        sender_position,
        preparation_terminal_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1])?,
        source_inventory_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 2])?,
        mailbox_body_identities: read_hash_array(&tuple.items[mailbox_start..challenge_index])?,
        dealer_challenge_coordinates: unpack_field_elements(
            read_fixed_byte_slice(
                &tuple.items[challenge_index],
                SOURCE_OPENING_PACKED_BYTE_LENGTH,
            )?,
            SOURCE_OPENING_FIELD_ELEMENT_COUNT,
        )?,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn encode_source_response_body(
    context: ReferenceFlowContext,
    sender_position: usize,
    preparation_terminal_identity: Hash512,
    source_inventory_identity: Hash512,
    challenge_inventory_identity: Hash512,
    response_coordinates: &[FieldElement],
) -> ProtocolResult<Vec<u8>> {
    require_participant_position_from_usize(sender_position)?;
    if response_coordinates.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source response has the wrong repetition count",
        ));
    }
    let packed_responses = pack_field_elements(response_coordinates);
    let mut items = Vec::with_capacity(SOURCE_RESPONSE_ITEM_COUNT);
    items.extend(context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(sender_position as u16),
        hash_item(preparation_terminal_identity),
        hash_item(source_inventory_identity),
        hash_item(challenge_inventory_identity),
        CanonicalItem::fixed_bytes(packed_responses)?,
    ]);
    Ok(CanonicalTuple::new(
        SOURCE_RESPONSE_SCHEMA_IDENTIFIER,
        SOURCE_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

pub(crate) fn decode_source_response(
    message: &VerifiedSignedMessage,
    expected_context: ReferenceFlowContext,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedSourceResponse> {
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    require_tuple(
        &tuple,
        SOURCE_RESPONSE_SCHEMA_IDENTIFIER,
        SOURCE_SCHEMA_VERSION,
        SOURCE_RESPONSE_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(expected_context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    require_expected_sender(sender_position, expected_sender_position)?;
    let response_index = FLOW_CONTEXT_ITEM_COUNT + 4;
    Ok(VerifiedSourceResponse {
        context,
        sender_position,
        preparation_terminal_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1])?,
        source_inventory_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 2])?,
        challenge_inventory_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 3])?,
        response_coordinates: unpack_field_elements(
            read_fixed_byte_slice(
                &tuple.items[response_index],
                SOURCE_RESPONSE_PACKED_BYTE_LENGTH,
            )?,
            DIRECT_CHECK_REPETITION_COUNT,
        )?,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn verify_source_transcript(
    expected_context: ReferenceFlowContext,
    expected_preparation_terminal_identity: Hash512,
    contributions: &[VerifiedSourceContribution],
    openings: &[VerifiedSourceChallengeOpening],
    responses: &[VerifiedSourceResponse],
) -> ProtocolResult<SourceTerminal> {
    require_complete_phase_inventory(contributions.len(), openings.len(), responses.len())?;
    for position in 0..PARTICIPANT_COUNT {
        require_phase_sender(
            contributions[position].context,
            contributions[position].sender_position,
            expected_context,
            position,
        )?;
        require_phase_sender(
            openings[position].context,
            openings[position].sender_position,
            expected_context,
            position,
        )?;
        require_phase_sender(
            responses[position].context,
            responses[position].sender_position,
            expected_context,
            position,
        )?;
        if contributions[position].preparation_terminal_identity
            != expected_preparation_terminal_identity
            || openings[position].preparation_terminal_identity
                != expected_preparation_terminal_identity
            || responses[position].preparation_terminal_identity
                != expected_preparation_terminal_identity
        {
            return Err(wrong_source_predecessor());
        }
    }

    let declarations = contributions
        .iter()
        .map(|message| message.declaration)
        .collect::<Vec<_>>();
    let source_is_present = verify_vertical_source_declarations(&declarations)?;
    let declaration_inventory_identity =
        declaration_inventory_identity(expected_context, &declarations)?;
    let contribution_identities = contributions
        .iter()
        .map(|message| message.body_identity)
        .collect::<Vec<_>>();
    let source_inventory_identity =
        complete_inventory_identity(InventoryKind::SourceContribution, &contribution_identities)?;

    for (recipient_position, opening) in openings.iter().enumerate() {
        if opening.source_inventory_identity != source_inventory_identity {
            return Err(wrong_source_predecessor());
        }
        for (sender_position, contribution) in contributions.iter().enumerate() {
            if opening.mailbox_body_identities[sender_position]
                != contribution.mailbox_body_identities[recipient_position]
            {
                return Err(ProtocolRefusal::new(
                    RefusalReason::WrongContext,
                    "source opening does not match the committed mailbox matrix",
                ));
            }
        }
    }

    let challenge_dealers = (0..PARTICIPANT_COUNT)
        .map(|dealer_position| {
            let recipient_blocks = core::array::from_fn(|recipient_position| {
                openings[recipient_position]
                    .dealer_challenge_block(dealer_position)
                    .to_vec()
            });
            ChallengeDealerCoordinates::from_recipient_blocks(recipient_blocks)
        })
        .collect::<ProtocolResult<Vec<_>>>()?;
    verify_and_aggregate_challenge(&challenge_dealers)?;

    let opening_identities = openings
        .iter()
        .map(|message| message.body_identity)
        .collect::<Vec<_>>();
    let challenge_inventory_identity =
        complete_inventory_identity(InventoryKind::SourceChallengeOpening, &opening_identities)?;
    for response in responses {
        if response.source_inventory_identity != source_inventory_identity
            || response.challenge_inventory_identity != challenge_inventory_identity
        {
            return Err(wrong_source_predecessor());
        }
    }
    let response_batch = (0..DIRECT_CHECK_REPETITION_COUNT)
        .map(|repetition| {
            core::array::from_fn(|position| responses[position].response_coordinates[repetition])
        })
        .collect::<Vec<[FieldElement; PARTICIPANT_COUNT]>>();
    verify_vertical_source_response_batch(&response_batch)?;

    let response_identities = responses
        .iter()
        .map(|message| message.body_identity)
        .collect::<Vec<_>>();
    let response_inventory_identity =
        complete_inventory_identity(InventoryKind::SourceResponse, &response_identities)?;
    let selected_source_identity = selected_source_identity(
        expected_context,
        contributions[PROTECTED_SOURCE_POSITION].body_identity,
        contributions[PROTECTED_SOURCE_POSITION].declaration,
    )?;
    Ok(SourceTerminal {
        context: expected_context,
        preparation_terminal_identity: expected_preparation_terminal_identity,
        declaration_inventory_identity,
        source_inventory_identity,
        challenge_inventory_identity,
        response_inventory_identity,
        selected_source_identity,
        source_is_present,
    })
}

fn contribution_schema_identifier(declaration: SourceDeclaration) -> u16 {
    match declaration {
        SourceDeclaration::Submit => SOURCE_SUBMIT_CONTRIBUTION_SCHEMA_IDENTIFIER,
        SourceDeclaration::Abstain => SOURCE_ABSTAIN_CONTRIBUTION_SCHEMA_IDENTIFIER,
        SourceDeclaration::NoSource => SOURCE_NOT_OWNED_CONTRIBUTION_SCHEMA_IDENTIFIER,
    }
}

fn declaration_from_schema_identifier(schema_identifier: u16) -> ProtocolResult<SourceDeclaration> {
    match schema_identifier {
        SOURCE_SUBMIT_CONTRIBUTION_SCHEMA_IDENTIFIER => Ok(SourceDeclaration::Submit),
        SOURCE_ABSTAIN_CONTRIBUTION_SCHEMA_IDENTIFIER => Ok(SourceDeclaration::Abstain),
        SOURCE_NOT_OWNED_CONTRIBUTION_SCHEMA_IDENTIFIER => Ok(SourceDeclaration::NoSource),
        _ => Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source contribution has the wrong declaration schema",
        )),
    }
}

fn require_source_declaration_for_position(
    sender_position: usize,
    declaration: SourceDeclaration,
) -> ProtocolResult<()> {
    require_participant_position_from_usize(sender_position)?;
    let permitted = if sender_position == PROTECTED_SOURCE_POSITION {
        matches!(
            declaration,
            SourceDeclaration::Submit | SourceDeclaration::Abstain
        )
    } else {
        declaration == SourceDeclaration::NoSource
    };
    if !permitted {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "source declaration does not match the participant's vertical role",
        ));
    }
    Ok(())
}

fn require_expected_sender(actual: u16, expected: usize) -> ProtocolResult<()> {
    require_participant_position(actual)?;
    if usize::from(actual) != expected {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "source message is in the wrong roster slot",
        ));
    }
    Ok(())
}

fn require_participant_position_from_usize(position: usize) -> ProtocolResult<()> {
    let position = u16::try_from(position).map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "source participant does not fit a roster position",
        )
    })?;
    require_participant_position(position)?;
    Ok(())
}

fn require_phase_sender(
    actual_context: ReferenceFlowContext,
    actual_sender: u16,
    expected_context: ReferenceFlowContext,
    expected_sender: usize,
) -> ProtocolResult<()> {
    actual_context.require(expected_context)?;
    require_expected_sender(actual_sender, expected_sender)
}

fn require_complete_phase_inventory(
    contribution_count: usize,
    opening_count: usize,
    response_count: usize,
) -> ProtocolResult<()> {
    if contribution_count != PARTICIPANT_COUNT
        || opening_count != PARTICIPANT_COUNT
        || response_count != PARTICIPANT_COUNT
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source transcript is missing a roster message",
        ));
    }
    Ok(())
}

fn wrong_source_predecessor() -> ProtocolRefusal {
    ProtocolRefusal::new(
        RefusalReason::WrongContext,
        "source message does not bind the exact preceding terminal or inventory",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        challenge::{CHALLENGE_DEALER_RANDOM_BYTE_LENGTH, create_challenge_dealer_coordinates},
        direct_check::create_vertical_source_response_batch,
        roster_signature::{
            ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
            RosterSigningKey, RosterVerificationKey, generate_roster_signature_keypair,
        },
        sharing::{
            SOURCE_CODEWORD_RANDOM_BYTE_LENGTH, SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
            create_source_codeword, create_source_response_pads,
        },
        signed_message::{sign_public_message, verify_public_message},
    };

    fn context() -> ReferenceFlowContext {
        ReferenceFlowContext {
            suite_identity: Hash512::from_bytes([1; 64]),
            build_identity: Hash512::from_bytes([2; 64]),
            action_identity: Hash512::from_bytes([3; 64]),
            roster_identity: Hash512::from_bytes([4; 64]),
            circuit_identity: Hash512::from_bytes([5; 64]),
            action_predecessor_identity: Hash512::from_bytes([6; 64]),
            attempt_ordinal: 1,
            output_ordinal: 0,
        }
    }

    fn keys() -> Vec<(RosterVerificationKey, RosterSigningKey)> {
        (0_u8..PARTICIPANT_COUNT as u8)
            .map(|position| {
                generate_roster_signature_keypair(
                    [position.wrapping_add(1); ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH],
                )
            })
            .collect()
    }

    fn sign_and_verify(
        body: &[u8],
        position: usize,
        keys: &[(RosterVerificationKey, RosterSigningKey)],
        seed_marker: u8,
    ) -> VerifiedSignedMessage {
        let carrier = sign_public_message(
            body,
            &keys[position].1,
            &keys[position].0,
            [seed_marker.wrapping_add(position as u8); ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();
        verify_public_message(&carrier, &keys[position].0).unwrap()
    }

    fn verify_case(source_is_present: bool) -> SourceTerminal {
        let keys = keys();
        let preparation_terminal_identity = Hash512::from_bytes([0x19; 64]);
        let mailbox_matrix: [[Hash512; PARTICIPANT_COUNT]; PARTICIPANT_COUNT] =
            core::array::from_fn(|sender| {
                core::array::from_fn(|recipient| {
                    Hash512::from_bytes([(sender * PARTICIPANT_COUNT + recipient + 1) as u8; 64])
                })
            });
        let contribution_messages = (0..PARTICIPANT_COUNT)
            .map(|position| {
                let declaration = if position == PROTECTED_SOURCE_POSITION {
                    if source_is_present {
                        SourceDeclaration::Submit
                    } else {
                        SourceDeclaration::Abstain
                    }
                } else {
                    SourceDeclaration::NoSource
                };
                let body = encode_source_contribution_body(
                    context(),
                    position,
                    preparation_terminal_identity,
                    declaration,
                    &mailbox_matrix[position],
                )
                .unwrap();
                sign_and_verify(&body, position, &keys, 0x20)
            })
            .collect::<Vec<_>>();
        let contributions = contribution_messages
            .iter()
            .enumerate()
            .map(|(position, message)| decode_source_contribution(message, context(), position))
            .collect::<ProtocolResult<Vec<_>>>()
            .unwrap();
        let source_inventory_identity = complete_inventory_identity(
            InventoryKind::SourceContribution,
            &contributions
                .iter()
                .map(|message| message.body_identity)
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let challenge_dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_challenge_dealer_coordinates(&vec![
                    dealer.wrapping_add(0x31);
                    CHALLENGE_DEALER_RANDOM_BYTE_LENGTH
                ])
                .unwrap()
            })
            .collect::<Vec<_>>();
        let opening_messages = (0..PARTICIPANT_COUNT)
            .map(|recipient| {
                let delivery_identities = (0..PARTICIPANT_COUNT)
                    .map(|sender| mailbox_matrix[sender][recipient])
                    .collect::<Vec<_>>();
                let challenge_coordinates = challenge_dealers
                    .iter()
                    .flat_map(|dealer| dealer.recipient_block(recipient).iter().copied())
                    .collect::<Vec<_>>();
                let body = encode_source_challenge_opening_body(
                    context(),
                    recipient,
                    preparation_terminal_identity,
                    source_inventory_identity,
                    &delivery_identities,
                    &challenge_coordinates,
                )
                .unwrap();
                sign_and_verify(&body, recipient, &keys, 0x40)
            })
            .collect::<Vec<_>>();
        let openings = opening_messages
            .iter()
            .enumerate()
            .map(|(position, message)| {
                decode_source_challenge_opening(message, context(), position)
            })
            .collect::<ProtocolResult<Vec<_>>>()
            .unwrap();
        let challenge_inventory_identity = complete_inventory_identity(
            InventoryKind::SourceChallengeOpening,
            &openings
                .iter()
                .map(|message| message.body_identity)
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let source =
            create_source_codeword(true, &[0x51; SOURCE_CODEWORD_RANDOM_BYTE_LENGTH]).unwrap();
        let challenge = verify_and_aggregate_challenge(&challenge_dealers).unwrap();
        let response_pads = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_source_response_pads(&vec![
                    dealer.wrapping_add(0x71);
                    SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH
                ])
                .unwrap()
            })
            .collect::<Vec<_>>();
        let response_batch = create_vertical_source_response_batch(
            source_is_present.then_some(&source),
            &challenge,
            &response_pads,
        )
        .unwrap();
        let response_messages = (0..PARTICIPANT_COUNT)
            .map(|position| {
                let coordinates = response_batch
                    .iter()
                    .map(|response| response[position])
                    .collect::<Vec<_>>();
                let body = encode_source_response_body(
                    context(),
                    position,
                    preparation_terminal_identity,
                    source_inventory_identity,
                    challenge_inventory_identity,
                    &coordinates,
                )
                .unwrap();
                sign_and_verify(&body, position, &keys, 0x60)
            })
            .collect::<Vec<_>>();
        let responses = response_messages
            .iter()
            .enumerate()
            .map(|(position, message)| decode_source_response(message, context(), position))
            .collect::<ProtocolResult<Vec<_>>>()
            .unwrap();
        verify_source_transcript(
            context(),
            preparation_terminal_identity,
            &contributions,
            &openings,
            &responses,
        )
        .unwrap()
    }

    #[test]
    fn submit_and_abstain_transcripts_create_distinct_exact_terminals() {
        let submit = verify_case(true);
        let abstain = verify_case(false);
        assert!(submit.source_is_present());
        assert!(!abstain.source_is_present());
        assert_ne!(submit.identity().unwrap(), abstain.identity().unwrap());
        assert_ne!(
            submit.selected_source_identity(),
            abstain.selected_source_identity()
        );
        assert_ne!(
            submit.declaration_inventory_identity(),
            abstain.declaration_inventory_identity()
        );
    }

    #[test]
    fn source_role_and_shape_mismatches_refuse() {
        let identities = [Hash512::from_bytes([0x28; 64]); PARTICIPANT_COUNT];
        assert!(
            encode_source_contribution_body(
                context(),
                1,
                Hash512::from_bytes([0x29; 64]),
                SourceDeclaration::Submit,
                &identities,
            )
            .is_err()
        );
        assert!(
            encode_source_challenge_opening_body(
                context(),
                0,
                Hash512::from_bytes([0x29; 64]),
                Hash512::from_bytes([0x30; 64]),
                &identities,
                &[FieldElement::ZERO; SOURCE_OPENING_FIELD_ELEMENT_COUNT - 1],
            )
            .is_err()
        );
    }
}
