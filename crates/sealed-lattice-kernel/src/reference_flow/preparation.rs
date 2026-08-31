use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_fixed_byte_slice, read_hash, read_hash_array, read_u16, require_tuple},
    challenge::{ChallengeDealerCoordinates, verify_and_aggregate_challenge},
    direct_check::verify_vertical_preparation_response_batch,
    field::{
        DIRECT_CHECK_REPETITION_COUNT, FieldElement, PARTICIPANT_COUNT, PreparationResponse,
        pack_field_elements, unpack_field_elements,
    },
    flow_context::{
        FLOW_CONTEXT_ITEM_COUNT, ReferenceFlowContext, hash_item, require_participant_position,
    },
    inventory::{InventoryKind, complete_inventory_identity},
    private_payload::PreparationRecipientCoordinate,
    protocol_oracle::protocol_oracle_512,
    signed_message::VerifiedSignedMessage,
};

const PREPARATION_CONTRIBUTION_SCHEMA_IDENTIFIER: u16 = 0x0260;
const PREPARATION_CHALLENGE_OPENING_SCHEMA_IDENTIFIER: u16 = 0x0261;
const PREPARATION_RESPONSE_SCHEMA_IDENTIFIER: u16 = 0x0262;
const PREPARATION_TERMINAL_SCHEMA_IDENTIFIER: u16 = 0x0263;
const PREPARATION_SCHEMA_VERSION: u16 = 1;
const PREPARATION_CONTRIBUTION_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 1 + PARTICIPANT_COUNT;
const PREPARATION_OPENING_FIELD_ELEMENT_COUNT: usize =
    PARTICIPANT_COUNT * DIRECT_CHECK_REPETITION_COUNT;
const PREPARATION_OPENING_PACKED_BYTE_LENGTH: usize =
    PREPARATION_OPENING_FIELD_ELEMENT_COUNT.div_ceil(2);
const PREPARATION_OPENING_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 3 + PARTICIPANT_COUNT;
const PREPARATION_RESPONSE_FIELD_ELEMENT_COUNT: usize = DIRECT_CHECK_REPETITION_COUNT * 3;
const PREPARATION_RESPONSE_PACKED_BYTE_LENGTH: usize =
    PREPARATION_RESPONSE_FIELD_ELEMENT_COUNT.div_ceil(2);
const PREPARATION_RESPONSE_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 4;
const PREPARATION_TERMINAL_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 3;

#[derive(Debug)]
pub(crate) struct VerifiedPreparationContribution {
    context: ReferenceFlowContext,
    sender_position: u16,
    mailbox_body_identities: [Hash512; PARTICIPANT_COUNT],
    body_identity: Hash512,
}

#[derive(Debug)]
pub(crate) struct VerifiedPreparationChallengeOpening {
    context: ReferenceFlowContext,
    sender_position: u16,
    candidate_inventory_identity: Hash512,
    mailbox_body_identities: [Hash512; PARTICIPANT_COUNT],
    dealer_challenge_coordinates: Vec<FieldElement>,
    body_identity: Hash512,
}

impl VerifiedPreparationChallengeOpening {
    fn dealer_challenge_block(&self, dealer_position: usize) -> &[FieldElement] {
        let start = dealer_position * DIRECT_CHECK_REPETITION_COUNT;
        &self.dealer_challenge_coordinates[start..start + DIRECT_CHECK_REPETITION_COUNT]
    }
}

#[derive(Debug)]
pub(crate) struct VerifiedPreparationResponse {
    context: ReferenceFlowContext,
    sender_position: u16,
    candidate_inventory_identity: Hash512,
    challenge_inventory_identity: Hash512,
    response_coordinates: Vec<PreparationRecipientCoordinate>,
    body_identity: Hash512,
}

#[derive(Debug)]
pub(crate) struct PreparationTerminal {
    context: ReferenceFlowContext,
    candidate_inventory_identity: Hash512,
    challenge_inventory_identity: Hash512,
    response_inventory_identity: Hash512,
}

impl PreparationTerminal {
    pub(crate) fn identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/preparation-terminal/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )
    }

    pub(crate) fn encode(&self) -> ProtocolResult<Vec<u8>> {
        let mut items = Vec::with_capacity(PREPARATION_TERMINAL_ITEM_COUNT);
        items.extend(self.context.canonical_items());
        items.extend([
            hash_item(self.candidate_inventory_identity),
            hash_item(self.challenge_inventory_identity),
            hash_item(self.response_inventory_identity),
        ]);
        Ok(CanonicalTuple::new(
            PREPARATION_TERMINAL_SCHEMA_IDENTIFIER,
            PREPARATION_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }
}

pub(crate) fn encode_preparation_contribution_body(
    context: ReferenceFlowContext,
    sender_position: usize,
    mailbox_body_identities: &[Hash512],
) -> ProtocolResult<Vec<u8>> {
    require_complete_body_identity_inventory(sender_position, mailbox_body_identities)?;
    let mut items = Vec::with_capacity(PREPARATION_CONTRIBUTION_ITEM_COUNT);
    items.extend(context.canonical_items());
    items.push(CanonicalItem::unsigned16(sender_position as u16));
    items.extend(mailbox_body_identities.iter().copied().map(hash_item));
    Ok(CanonicalTuple::new(
        PREPARATION_CONTRIBUTION_SCHEMA_IDENTIFIER,
        PREPARATION_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

pub(crate) fn decode_preparation_contribution(
    message: &VerifiedSignedMessage,
    expected_context: ReferenceFlowContext,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedPreparationContribution> {
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    require_tuple(
        &tuple,
        PREPARATION_CONTRIBUTION_SCHEMA_IDENTIFIER,
        PREPARATION_SCHEMA_VERSION,
        PREPARATION_CONTRIBUTION_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(expected_context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    require_expected_sender(sender_position, expected_sender_position)?;
    Ok(VerifiedPreparationContribution {
        context,
        sender_position,
        mailbox_body_identities: read_hash_array(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1..])?,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn encode_preparation_challenge_opening_body(
    context: ReferenceFlowContext,
    sender_position: usize,
    candidate_inventory_identity: Hash512,
    verified_mailbox_body_identities: &[Hash512],
    dealer_challenge_coordinates: &[FieldElement],
) -> ProtocolResult<Vec<u8>> {
    require_complete_body_identity_inventory(sender_position, verified_mailbox_body_identities)?;
    if dealer_challenge_coordinates.len() != PREPARATION_OPENING_FIELD_ELEMENT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "preparation opening has the wrong challenge-coordinate count",
        ));
    }
    let packed_challenges = pack_field_elements(dealer_challenge_coordinates);
    let mut items = Vec::with_capacity(PREPARATION_OPENING_ITEM_COUNT);
    items.extend(context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(sender_position as u16),
        hash_item(candidate_inventory_identity),
    ]);
    items.extend(
        verified_mailbox_body_identities
            .iter()
            .copied()
            .map(hash_item),
    );
    items.push(CanonicalItem::fixed_bytes(packed_challenges)?);
    Ok(CanonicalTuple::new(
        PREPARATION_CHALLENGE_OPENING_SCHEMA_IDENTIFIER,
        PREPARATION_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

pub(crate) fn decode_preparation_challenge_opening(
    message: &VerifiedSignedMessage,
    expected_context: ReferenceFlowContext,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedPreparationChallengeOpening> {
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    require_tuple(
        &tuple,
        PREPARATION_CHALLENGE_OPENING_SCHEMA_IDENTIFIER,
        PREPARATION_SCHEMA_VERSION,
        PREPARATION_OPENING_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(expected_context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    require_expected_sender(sender_position, expected_sender_position)?;
    let mailbox_start = FLOW_CONTEXT_ITEM_COUNT + 2;
    let challenge_index = mailbox_start + PARTICIPANT_COUNT;
    Ok(VerifiedPreparationChallengeOpening {
        context,
        sender_position,
        candidate_inventory_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1])?,
        mailbox_body_identities: read_hash_array(&tuple.items[mailbox_start..challenge_index])?,
        dealer_challenge_coordinates: unpack_field_elements(
            read_fixed_byte_slice(
                &tuple.items[challenge_index],
                PREPARATION_OPENING_PACKED_BYTE_LENGTH,
            )?,
            PREPARATION_OPENING_FIELD_ELEMENT_COUNT,
        )?,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn encode_preparation_response_body(
    context: ReferenceFlowContext,
    sender_position: usize,
    candidate_inventory_identity: Hash512,
    challenge_inventory_identity: Hash512,
    response_coordinates: &[PreparationRecipientCoordinate],
) -> ProtocolResult<Vec<u8>> {
    require_participant_position(u16::try_from(sender_position).map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "preparation response sender does not fit its roster position",
        )
    })?)?;
    if response_coordinates.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "preparation response has the wrong repetition count",
        ));
    }
    let mut field_elements = Vec::with_capacity(PREPARATION_RESPONSE_FIELD_ELEMENT_COUNT);
    for response in response_coordinates {
        field_elements.extend([response.low, response.high, response.output_zero]);
    }
    let packed_responses = pack_field_elements(&field_elements);
    let mut items = Vec::with_capacity(PREPARATION_RESPONSE_ITEM_COUNT);
    items.extend(context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(sender_position as u16),
        hash_item(candidate_inventory_identity),
        hash_item(challenge_inventory_identity),
        CanonicalItem::fixed_bytes(packed_responses)?,
    ]);
    Ok(CanonicalTuple::new(
        PREPARATION_RESPONSE_SCHEMA_IDENTIFIER,
        PREPARATION_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

pub(crate) fn decode_preparation_response(
    message: &VerifiedSignedMessage,
    expected_context: ReferenceFlowContext,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedPreparationResponse> {
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    require_tuple(
        &tuple,
        PREPARATION_RESPONSE_SCHEMA_IDENTIFIER,
        PREPARATION_SCHEMA_VERSION,
        PREPARATION_RESPONSE_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(expected_context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    require_expected_sender(sender_position, expected_sender_position)?;
    let response_index = FLOW_CONTEXT_ITEM_COUNT + 3;
    let field_elements = unpack_field_elements(
        read_fixed_byte_slice(
            &tuple.items[response_index],
            PREPARATION_RESPONSE_PACKED_BYTE_LENGTH,
        )?,
        PREPARATION_RESPONSE_FIELD_ELEMENT_COUNT,
    )?;
    let response_coordinates = field_elements
        .chunks_exact(3)
        .map(|coordinates| PreparationRecipientCoordinate {
            low: coordinates[0],
            high: coordinates[1],
            output_zero: coordinates[2],
        })
        .collect();
    Ok(VerifiedPreparationResponse {
        context,
        sender_position,
        candidate_inventory_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1])?,
        challenge_inventory_identity: read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 2])?,
        response_coordinates,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn verify_preparation_transcript(
    expected_context: ReferenceFlowContext,
    contributions: &[VerifiedPreparationContribution],
    openings: &[VerifiedPreparationChallengeOpening],
    responses: &[VerifiedPreparationResponse],
) -> ProtocolResult<PreparationTerminal> {
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
    }

    let contribution_identities = contributions
        .iter()
        .map(|message| message.body_identity)
        .collect::<Vec<_>>();
    let candidate_inventory_identity = complete_inventory_identity(
        InventoryKind::PreparationContribution,
        &contribution_identities,
    )?;
    for (recipient_position, opening) in openings.iter().enumerate() {
        if opening.candidate_inventory_identity != candidate_inventory_identity {
            return Err(wrong_preparation_predecessor());
        }
        for (sender_position, contribution) in contributions.iter().enumerate() {
            if opening.mailbox_body_identities[sender_position]
                != contribution.mailbox_body_identities[recipient_position]
            {
                return Err(ProtocolRefusal::new(
                    RefusalReason::WrongContext,
                    "preparation opening does not match the committed mailbox matrix",
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
    let challenge_inventory_identity = complete_inventory_identity(
        InventoryKind::PreparationChallengeOpening,
        &opening_identities,
    )?;
    for response in responses {
        if response.candidate_inventory_identity != candidate_inventory_identity
            || response.challenge_inventory_identity != challenge_inventory_identity
        {
            return Err(wrong_preparation_predecessor());
        }
    }

    let response_batch = (0..DIRECT_CHECK_REPETITION_COUNT)
        .map(|repetition| PreparationResponse {
            low: core::array::from_fn(|position| {
                responses[position].response_coordinates[repetition].low
            }),
            high: core::array::from_fn(|position| {
                responses[position].response_coordinates[repetition].high
            }),
            output_zero: core::array::from_fn(|position| {
                responses[position].response_coordinates[repetition].output_zero
            }),
        })
        .collect::<Vec<_>>();
    verify_vertical_preparation_response_batch(&response_batch)?;

    let response_identities = responses
        .iter()
        .map(|message| message.body_identity)
        .collect::<Vec<_>>();
    let response_inventory_identity =
        complete_inventory_identity(InventoryKind::PreparationResponse, &response_identities)?;
    Ok(PreparationTerminal {
        context: expected_context,
        candidate_inventory_identity,
        challenge_inventory_identity,
        response_inventory_identity,
    })
}

fn require_complete_body_identity_inventory(
    sender_position: usize,
    identities: &[Hash512],
) -> ProtocolResult<()> {
    require_participant_position(u16::try_from(sender_position).map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "preparation sender does not fit its roster position",
        )
    })?)?;
    if identities.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "preparation message is missing a mailbox body identity",
        ));
    }
    Ok(())
}

fn require_expected_sender(actual: u16, expected: usize) -> ProtocolResult<()> {
    require_participant_position(actual)?;
    if usize::from(actual) != expected {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "preparation message is in the wrong roster slot",
        ));
    }
    Ok(())
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
            "preparation transcript is missing a roster message",
        ));
    }
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

fn wrong_preparation_predecessor() -> ProtocolRefusal {
    ProtocolRefusal::new(
        RefusalReason::WrongContext,
        "preparation message does not bind the exact preceding inventory",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        challenge::{CHALLENGE_DEALER_RANDOM_BYTE_LENGTH, create_challenge_dealer_coordinates},
        direct_check::create_vertical_preparation_response_batch,
        roster_signature::{
            ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
            RosterSigningKey, RosterVerificationKey, generate_roster_signature_keypair,
        },
        sharing::{
            PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH, PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
            aggregate_preparation_coordinates, create_preparation_candidate,
            create_preparation_response_pads,
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

    #[test]
    fn complete_signed_preparation_transcript_creates_one_terminal() {
        let keys = keys();
        let mailbox_matrix: [[Hash512; PARTICIPANT_COUNT]; PARTICIPANT_COUNT] =
            core::array::from_fn(|sender| {
                core::array::from_fn(|recipient| {
                    Hash512::from_bytes([(sender * PARTICIPANT_COUNT + recipient) as u8; 64])
                })
            });
        let contribution_messages = (0..PARTICIPANT_COUNT)
            .map(|position| {
                let body = encode_preparation_contribution_body(
                    context(),
                    position,
                    &mailbox_matrix[position],
                )
                .unwrap();
                sign_and_verify(&body, position, &keys, 0x20)
            })
            .collect::<Vec<_>>();
        let contributions = contribution_messages
            .iter()
            .enumerate()
            .map(|(position, message)| {
                decode_preparation_contribution(message, context(), position)
            })
            .collect::<ProtocolResult<Vec<_>>>()
            .unwrap();
        let candidate_inventory_identity = complete_inventory_identity(
            InventoryKind::PreparationContribution,
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
                let body = encode_preparation_challenge_opening_body(
                    context(),
                    recipient,
                    candidate_inventory_identity,
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
                decode_preparation_challenge_opening(message, context(), position)
            })
            .collect::<ProtocolResult<Vec<_>>>()
            .unwrap();
        let challenge_inventory_identity = complete_inventory_identity(
            InventoryKind::PreparationChallengeOpening,
            &openings
                .iter()
                .map(|message| message.body_identity)
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let candidate_dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_preparation_candidate(
                    &[dealer.wrapping_add(0x51); PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let candidate =
            aggregate_preparation_coordinates(&candidate_dealers.iter().collect::<Vec<_>>())
                .unwrap();
        let challenge = verify_and_aggregate_challenge(&challenge_dealers).unwrap();
        let response_pads = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_preparation_response_pads(&vec![
                    dealer.wrapping_add(0x71);
                    PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH
                ])
                .unwrap()
            })
            .collect::<Vec<_>>();
        let response_batch =
            create_vertical_preparation_response_batch(&candidate, &challenge, &response_pads)
                .unwrap();
        let response_messages = (0..PARTICIPANT_COUNT)
            .map(|position| {
                let coordinates = response_batch
                    .iter()
                    .map(|response| PreparationRecipientCoordinate {
                        low: response.low[position],
                        high: response.high[position],
                        output_zero: response.output_zero[position],
                    })
                    .collect::<Vec<_>>();
                let body = encode_preparation_response_body(
                    context(),
                    position,
                    candidate_inventory_identity,
                    challenge_inventory_identity,
                    &coordinates,
                )
                .unwrap();
                sign_and_verify(&body, position, &keys, 0x60)
            })
            .collect::<Vec<_>>();
        let mut responses = response_messages
            .iter()
            .enumerate()
            .map(|(position, message)| decode_preparation_response(message, context(), position))
            .collect::<ProtocolResult<Vec<_>>>()
            .unwrap();

        let terminal =
            verify_preparation_transcript(context(), &contributions, &openings, &responses)
                .expect("complete signed preparation transcript verifies");
        assert_ne!(terminal.identity().unwrap(), Hash512::from_bytes([0; 64]));

        responses[6].response_coordinates[93].high = responses[6].response_coordinates[93]
            .high
            .add(FieldElement::ONE);
        assert!(
            verify_preparation_transcript(context(), &contributions, &openings, &responses)
                .is_err()
        );
    }

    #[test]
    fn opening_refuses_wrong_mailbox_matrix_and_incomplete_inventory() {
        let identities = [Hash512::from_bytes([0x19; 64]); PARTICIPANT_COUNT];
        assert!(encode_preparation_contribution_body(context(), 0, &identities[..9]).is_err());
        assert!(
            encode_preparation_challenge_opening_body(
                context(),
                0,
                Hash512::from_bytes([0x21; 64]),
                &identities,
                &[FieldElement::ZERO; PREPARATION_OPENING_FIELD_ELEMENT_COUNT - 1],
            )
            .is_err()
        );
    }
}
