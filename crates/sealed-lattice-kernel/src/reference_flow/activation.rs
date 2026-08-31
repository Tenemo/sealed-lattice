use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_hash, read_u16, read_variable_bytes, require_tuple},
    field::{CORRUPTION_BOUND, PARTICIPANT_COUNT},
    finality::{ComputationTarget, FinalityPolicy, VerifiedFinalityCertificate},
    flow_context::{FLOW_CONTEXT_ITEM_COUNT, ReferenceFlowContext, hash_item},
    garbling::{
        GarblingContext, VERTICAL_ACTIVATION_ENCODING_VERSION, VerticalActivation,
        evaluate_vertical_activations,
    },
    inventory::{InventoryKind, complete_inventory_identity},
    protocol_oracle::protocol_oracle_512,
    signed_message::VerifiedSignedMessage,
    source::SourceTerminal,
};

const ACTIVATION_BODY_SCHEMA_IDENTIFIER: u16 = 0x0290;
const RESULT_TERMINAL_SCHEMA_IDENTIFIER: u16 = 0x0291;
const NO_RESULT_TERMINAL_SCHEMA_IDENTIFIER: u16 = 0x0292;
const ACTIVATION_SCHEMA_VERSION: u16 = 1;
const ACTIVATION_BODY_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 5;
const RESULT_TERMINAL_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 3;
const NO_RESULT_TERMINAL_ITEM_COUNT: usize = FLOW_CONTEXT_ITEM_COUNT + 2;

#[derive(Clone, Copy)]
pub(crate) struct VerticalCapabilities<'a> {
    context: ReferenceFlowContext,
    preparation_terminal_identity: Hash512,
    source_terminal: &'a SourceTerminal,
    target: &'a ComputationTarget,
    finality: &'a VerifiedFinalityCertificate,
    public_control: bool,
    action_ordinal: u64,
}

pub(crate) struct VerifiedActivation {
    context: ReferenceFlowContext,
    sender_position: u16,
    preparation_terminal_identity: Hash512,
    source_terminal_identity: Hash512,
    target_identity: Hash512,
    activation: VerticalActivation,
    body_identity: Hash512,
}

impl core::fmt::Debug for VerifiedActivation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedActivation")
            .field("sender_position", &self.sender_position)
            .field("target_identity", &self.target_identity)
            .field("body_identity", &self.body_identity)
            .finish_non_exhaustive()
    }
}

pub(crate) struct VerifiedResultTerminal {
    context: ReferenceFlowContext,
    target_identity: Hash512,
    activation_inventory_identity: Hash512,
    result_bit: bool,
}

impl core::fmt::Debug for VerifiedResultTerminal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedResultTerminal")
            .field("target_identity", &self.target_identity)
            .field(
                "activation_inventory_identity",
                &self.activation_inventory_identity,
            )
            .field("result_bit", &self.result_bit)
            .finish()
    }
}

impl VerifiedResultTerminal {
    pub(crate) fn result_bit(&self) -> bool {
        self.result_bit
    }

    pub(crate) fn activation_inventory_identity(&self) -> Hash512 {
        self.activation_inventory_identity
    }

    pub(crate) fn encode(&self) -> ProtocolResult<Vec<u8>> {
        let mut items = Vec::with_capacity(RESULT_TERMINAL_ITEM_COUNT);
        items.extend(self.context.canonical_items());
        items.extend([
            hash_item(self.target_identity),
            hash_item(self.activation_inventory_identity),
            CanonicalItem::unsigned16(u16::from(self.result_bit)),
        ]);
        Ok(CanonicalTuple::new(
            RESULT_TERMINAL_SCHEMA_IDENTIFIER,
            ACTIVATION_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn semantic_identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/result/v1",
            &[
                hash_item(self.target_identity),
                CanonicalItem::unsigned16(u16::from(self.result_bit)),
            ],
        )
    }

    pub(crate) fn carrier_identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/result-terminal-carrier/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )
    }
}

pub(crate) struct VerifiedNoResultTerminal {
    context: ReferenceFlowContext,
    target_identity: Hash512,
    source_terminal_identity: Hash512,
}

impl core::fmt::Debug for VerifiedNoResultTerminal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedNoResultTerminal")
            .field("target_identity", &self.target_identity)
            .field("source_terminal_identity", &self.source_terminal_identity)
            .finish()
    }
}

impl VerifiedNoResultTerminal {
    pub(crate) fn encode(&self) -> ProtocolResult<Vec<u8>> {
        let mut items = Vec::with_capacity(NO_RESULT_TERMINAL_ITEM_COUNT);
        items.extend(self.context.canonical_items());
        items.extend([
            hash_item(self.target_identity),
            hash_item(self.source_terminal_identity),
        ]);
        Ok(CanonicalTuple::new(
            NO_RESULT_TERMINAL_SCHEMA_IDENTIFIER,
            ACTIVATION_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn semantic_identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/no-result/v1",
            &[hash_item(self.target_identity)],
        )
    }
}

pub(crate) fn derive_vertical_computation_target(
    context: ReferenceFlowContext,
    preparation_terminal_identity: Hash512,
    source_terminal: &SourceTerminal,
    public_control: bool,
    action_ordinal: u64,
) -> ProtocolResult<ComputationTarget> {
    source_terminal.context().require(context)?;
    if source_terminal.preparation_terminal_identity() != preparation_terminal_identity {
        return Err(wrong_activation_predecessor());
    }
    Ok(ComputationTarget {
        suite_identity: context.suite_identity,
        build_identity: context.build_identity,
        action_identity: context.action_identity,
        predecessor_identity: context.action_predecessor_identity,
        roster_identity: context.roster_identity,
        circuit_identity: context.circuit_identity,
        compiler_identity: vertical_compiler_identity()?,
        output_schema_identity: vertical_output_schema_identity()?,
        preparation_terminal_identity,
        declaration_inventory_identity: source_terminal.declaration_inventory_identity(),
        source_inventory_identity: source_terminal.source_inventory_identity(),
        selected_source_identity: source_terminal.selected_source_identity(),
        public_input_identity: vertical_public_input_identity(context, public_control)?,
        activation_policy_identity: vertical_activation_policy_identity()?,
        finality_policy: FinalityPolicy::completion_profile(),
        output_bit_count: 1,
        action_ordinal,
        output_ordinal: context.output_ordinal,
    })
}

pub(crate) fn encode_activation_body(
    capabilities: VerticalCapabilities<'_>,
    activation: &VerticalActivation,
) -> ProtocolResult<Vec<u8>> {
    let (source_terminal_identity, target_identity) = require_vertical_capabilities(capabilities)?;
    if !capabilities.source_terminal.source_is_present() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "an empty source cannot publish an activation",
        ));
    }
    let sender_position = activation.garbler_position();
    if sender_position >= PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "activation sender is outside the roster",
        ));
    }
    let mut items = Vec::with_capacity(ACTIVATION_BODY_ITEM_COUNT);
    items.extend(capabilities.context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(sender_position as u16),
        hash_item(capabilities.preparation_terminal_identity),
        hash_item(source_terminal_identity),
        hash_item(target_identity),
        CanonicalItem::variable_bytes(activation.encode_payload()?)?,
    ]);
    Ok(CanonicalTuple::new(
        ACTIVATION_BODY_SCHEMA_IDENTIFIER,
        ACTIVATION_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

pub(crate) fn decode_activation(
    message: &VerifiedSignedMessage,
    capabilities: VerticalCapabilities<'_>,
    expected_sender_position: usize,
) -> ProtocolResult<VerifiedActivation> {
    let (expected_source_terminal_identity, expected_target_identity) =
        require_vertical_capabilities(capabilities)?;
    if !capabilities.source_terminal.source_is_present() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "an empty source cannot accept an activation",
        ));
    }
    if expected_sender_position >= PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "expected activation sender is outside the roster",
        ));
    }
    let tuple = CanonicalTuple::decode(message.body_bytes(), &CanonicalDecodeLimits::default())?;
    require_tuple(
        &tuple,
        ACTIVATION_BODY_SCHEMA_IDENTIFIER,
        ACTIVATION_SCHEMA_VERSION,
        ACTIVATION_BODY_ITEM_COUNT,
    )?;
    let context = ReferenceFlowContext::read_from_items(&tuple.items)?;
    context.require(capabilities.context)?;
    let sender_position = read_u16(&tuple.items[FLOW_CONTEXT_ITEM_COUNT])?;
    if usize::from(sender_position) != expected_sender_position {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "activation message is in the wrong roster slot",
        ));
    }
    let preparation_terminal_identity = read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 1])?;
    let source_terminal_identity = read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 2])?;
    let target_identity = read_hash(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 3])?;
    if preparation_terminal_identity != capabilities.preparation_terminal_identity
        || source_terminal_identity != expected_source_terminal_identity
        || target_identity != expected_target_identity
    {
        return Err(wrong_activation_predecessor());
    }
    let activation = VerticalActivation::decode_payload(
        expected_sender_position,
        read_variable_bytes(&tuple.items[FLOW_CONTEXT_ITEM_COUNT + 4])?,
    )?;
    Ok(VerifiedActivation {
        context,
        sender_position,
        preparation_terminal_identity,
        source_terminal_identity,
        target_identity,
        activation,
        body_identity: message.body_identity(),
    })
}

pub(crate) fn verify_activation_transcript(
    capabilities: VerticalCapabilities<'_>,
    activations: Vec<VerifiedActivation>,
) -> ProtocolResult<Option<VerifiedResultTerminal>> {
    let (expected_source_terminal_identity, expected_target_identity) =
        require_vertical_capabilities(capabilities)?;
    if !capabilities.source_terminal.source_is_present() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "an empty source has no activation transcript",
        ));
    }

    let mut ordered = (0..PARTICIPANT_COUNT)
        .map(|_| None)
        .collect::<Vec<Option<VerifiedActivation>>>();
    for activation in activations {
        activation.context.require(capabilities.context)?;
        let position = usize::from(activation.sender_position);
        if position >= PARTICIPANT_COUNT
            || activation.preparation_terminal_identity
                != capabilities.preparation_terminal_identity
            || activation.source_terminal_identity != expected_source_terminal_identity
            || activation.target_identity != expected_target_identity
            || activation.activation.garbler_position() != position
        {
            return Err(wrong_activation_predecessor());
        }
        if ordered[position].replace(activation).is_some() {
            return Err(ProtocolRefusal::new(
                RefusalReason::DuplicateIdentity,
                "activation inventory repeats a roster position",
            ));
        }
    }
    if ordered.iter().any(Option::is_none) {
        return Ok(None);
    }
    let ordered = ordered
        .into_iter()
        .map(|entry| entry.expect("the complete activation inventory was checked"))
        .collect::<Vec<_>>();
    let body_identities = ordered
        .iter()
        .map(|activation| activation.body_identity)
        .collect::<Vec<_>>();
    let activation_inventory_identity =
        complete_inventory_identity(InventoryKind::Activation, &body_identities)?;
    let activation_payloads = ordered
        .into_iter()
        .map(|activation| activation.activation)
        .collect::<Vec<_>>();
    let result_bit = evaluate_vertical_activations(
        vertical_garbling_context(
            capabilities.context,
            capabilities.preparation_terminal_identity,
            expected_source_terminal_identity,
            expected_target_identity,
        ),
        &activation_payloads,
    )?;
    Ok(Some(VerifiedResultTerminal {
        context: capabilities.context,
        target_identity: expected_target_identity,
        activation_inventory_identity,
        result_bit,
    }))
}

pub(crate) fn finalize_empty_source(
    expected_context: ReferenceFlowContext,
    expected_preparation_terminal_identity: Hash512,
    source_terminal: &SourceTerminal,
    target: &ComputationTarget,
    finality: &VerifiedFinalityCertificate,
    public_control: bool,
    action_ordinal: u64,
) -> ProtocolResult<VerifiedNoResultTerminal> {
    let (source_terminal_identity, target_identity) =
        require_vertical_capabilities(VerticalCapabilities {
            context: expected_context,
            preparation_terminal_identity: expected_preparation_terminal_identity,
            source_terminal,
            target,
            finality,
            public_control,
            action_ordinal,
        })?;
    if source_terminal.source_is_present() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "a nonempty source cannot produce the empty-source terminal",
        ));
    }
    Ok(VerifiedNoResultTerminal {
        context: expected_context,
        target_identity,
        source_terminal_identity,
    })
}

pub(crate) fn vertical_garbling_context(
    context: ReferenceFlowContext,
    preparation_terminal_identity: Hash512,
    source_terminal_identity: Hash512,
    target_identity: Hash512,
) -> GarblingContext {
    GarblingContext {
        suite_identity: context.suite_identity,
        build_identity: context.build_identity,
        action_identity: context.action_identity,
        roster_identity: context.roster_identity,
        circuit_identity: context.circuit_identity,
        preparation_terminal_identity,
        source_terminal_identity,
        target_identity,
        activation_encoding_version: VERTICAL_ACTIVATION_ENCODING_VERSION,
        output_ordinal: context.output_ordinal,
    }
}

fn require_vertical_capabilities(
    capabilities: VerticalCapabilities<'_>,
) -> ProtocolResult<(Hash512, Hash512)> {
    let expected_target = derive_vertical_computation_target(
        capabilities.context,
        capabilities.preparation_terminal_identity,
        capabilities.source_terminal,
        capabilities.public_control,
        capabilities.action_ordinal,
    )?;
    if capabilities.target != &expected_target {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "computation target does not match the verified vertical transcript",
        ));
    }
    let target_identity = capabilities.target.identity()?;
    if capabilities.finality.target_identity() != target_identity {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "activation does not follow finality for its exact target",
        ));
    }
    Ok((capabilities.source_terminal.identity()?, target_identity))
}

fn vertical_compiler_identity() -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/one-input-one-and-compiler/v1",
        &[
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(1),
        ],
    )
}

fn vertical_output_schema_identity() -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/one-bit-output-schema/v1",
        &[CanonicalItem::unsigned16(1)],
    )
}

fn vertical_activation_policy_identity() -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/all-participant-activation-policy/v1",
        &[
            CanonicalItem::unsigned16(PARTICIPANT_COUNT as u16),
            CanonicalItem::unsigned16(PARTICIPANT_COUNT as u16),
            CanonicalItem::unsigned16(CORRUPTION_BOUND as u16),
            CanonicalItem::unsigned16(VERTICAL_ACTIVATION_ENCODING_VERSION),
            CanonicalItem::unsigned16(1),
        ],
    )
}

fn vertical_public_input_identity(
    context: ReferenceFlowContext,
    public_control: bool,
) -> ProtocolResult<Hash512> {
    let mut items = Vec::with_capacity(FLOW_CONTEXT_ITEM_COUNT + 1);
    items.extend(context.canonical_items());
    items.push(CanonicalItem::unsigned16(u16::from(public_control)));
    protocol_oracle_512("sealed-lattice/protocol/vertical-public-input/v1", &items)
}

fn wrong_activation_predecessor() -> ProtocolRefusal {
    ProtocolRefusal::new(
        RefusalReason::WrongContext,
        "activation does not bind the exact verified predecessor",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        finality::{
            FinalitySignature, create_finality_certificate, create_finality_signature,
            verify_finality_certificate,
        },
        garbling::{
            GarblerContext, VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH, create_vertical_activation,
        },
        roster_signature::{
            ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
            RosterSigningKey, RosterVerificationKey, generate_roster_signature_keypair,
        },
        sharing::{
            PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH, SOURCE_CODEWORD_RANDOM_BYTE_LENGTH,
            aggregate_preparation_coordinates, create_preparation_candidate,
            create_source_codeword,
        },
        signed_message::{sign_public_message, verify_public_message},
        token::{
            RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH, TOKEN_BYTE_LENGTH, create_receiver_token_setup,
        },
    };

    const ACTION_ORDINAL: u64 = 4;

    fn hash(marker: u8) -> Hash512 {
        Hash512::from_bytes([marker; 64])
    }

    fn context() -> ReferenceFlowContext {
        ReferenceFlowContext {
            suite_identity: hash(1),
            build_identity: hash(2),
            action_identity: hash(3),
            roster_identity: hash(4),
            circuit_identity: hash(5),
            action_predecessor_identity: hash(6),
            attempt_ordinal: 1,
            output_ordinal: 0,
        }
    }

    fn deterministic_bytes(mut state: u64, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            output.push(state as u8);
        }
        output
    }

    fn roster_keys() -> Vec<(RosterVerificationKey, RosterSigningKey)> {
        (0_u8..PARTICIPANT_COUNT as u8)
            .map(|position| {
                generate_roster_signature_keypair(
                    [position.wrapping_add(1); ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH],
                )
            })
            .collect()
    }

    fn verified_finality(
        target: &ComputationTarget,
        keys: &[(RosterVerificationKey, RosterSigningKey)],
    ) -> (Vec<FinalitySignature>, VerifiedFinalityCertificate) {
        let signatures = (0..usize::from(target.finality_policy.quorum))
            .map(|position| {
                create_finality_signature(
                    target,
                    position,
                    &keys[position].1,
                    &keys[position].0,
                    [0x30_u8.wrapping_add(position as u8); ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let verification_keys = keys.iter().map(|entry| entry.0).collect::<Vec<_>>();
        let certificate = create_finality_certificate(target, &signatures, &verification_keys)
            .unwrap()
            .unwrap();
        let verified =
            verify_finality_certificate(target, &certificate, &signatures, &verification_keys)
                .unwrap()
                .unwrap();
        (signatures, verified)
    }

    fn vertical_capabilities<'a>(
        source_terminal: &'a SourceTerminal,
        target: &'a ComputationTarget,
        finality: &'a VerifiedFinalityCertificate,
        public_control: bool,
    ) -> VerticalCapabilities<'a> {
        VerticalCapabilities {
            context: context(),
            preparation_terminal_identity: source_terminal.preparation_terminal_identity(),
            source_terminal,
            target,
            finality,
            public_control,
            action_ordinal: ACTION_ORDINAL,
        }
    }

    fn real_activations(
        source_terminal: &SourceTerminal,
        target: &ComputationTarget,
        source_bit: bool,
        public_control: bool,
        random_offset: u64,
    ) -> Vec<VerticalActivation> {
        let source = create_source_codeword(
            source_bit,
            &deterministic_bytes(0x3000, SOURCE_CODEWORD_RANDOM_BYTE_LENGTH),
        )
        .unwrap();
        let preparation_dealers = (0..PARTICIPANT_COUNT)
            .map(|position| {
                create_preparation_candidate(&deterministic_bytes(
                    0x1000 + position as u64,
                    PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH,
                ))
                .unwrap()
            })
            .collect::<Vec<_>>();
        let preparation =
            aggregate_preparation_coordinates(&preparation_dealers.iter().collect::<Vec<_>>())
                .unwrap();
        let token_setups = (0..PARTICIPANT_COUNT)
            .map(|position| {
                let mut bytes = deterministic_bytes(
                    0x2000 + position as u64,
                    RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH,
                );
                bytes[PARTICIPANT_COUNT * TOKEN_BYTE_LENGTH] |= 1;
                create_receiver_token_setup(&bytes).unwrap()
            })
            .collect::<Vec<_>>();
        let garbling_context = vertical_garbling_context(
            context(),
            source_terminal.preparation_terminal_identity(),
            source_terminal.identity().unwrap(),
            target.identity().unwrap(),
        );
        (0..PARTICIPANT_COUNT)
            .map(|garbler_position| {
                let evaluations = token_setups
                    .iter()
                    .map(|setup| setup.clone_evaluation_for_garbler(garbler_position))
                    .collect::<Vec<_>>();
                let continuation_keys = token_setups[garbler_position].clone_continuation_keys();
                create_vertical_activation(
                    GarblerContext {
                        context: garbling_context,
                        position: garbler_position,
                    },
                    &source,
                    public_control,
                    &preparation,
                    &evaluations,
                    &continuation_keys,
                    &deterministic_bytes(
                        0x4000 + random_offset + garbler_position as u64,
                        VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH,
                    ),
                )
                .unwrap()
            })
            .collect()
    }

    fn signed_and_decoded_activations(
        source_terminal: &SourceTerminal,
        target: &ComputationTarget,
        finality: &VerifiedFinalityCertificate,
        keys: &[(RosterVerificationKey, RosterSigningKey)],
        source_bit: bool,
        public_control: bool,
        random_offset: u64,
    ) -> Vec<VerifiedActivation> {
        real_activations(
            source_terminal,
            target,
            source_bit,
            public_control,
            random_offset,
        )
        .iter()
        .enumerate()
        .map(|(position, activation)| {
            let body = encode_activation_body(
                vertical_capabilities(source_terminal, target, finality, public_control),
                activation,
            )
            .unwrap();
            let carrier = sign_public_message(
                &body,
                &keys[position].1,
                &keys[position].0,
                [0x70_u8.wrapping_add(position as u8); ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            )
            .unwrap();
            let message = verify_public_message(&carrier, &keys[position].0).unwrap();
            decode_activation(
                &message,
                vertical_capabilities(source_terminal, target, finality, public_control),
                position,
            )
            .unwrap()
        })
        .collect()
    }

    #[test]
    fn finality_gates_signed_all_participant_activation_and_result() {
        let preparation_terminal_identity = hash(0x21);
        let source_terminal =
            SourceTerminal::test_fixture(context(), preparation_terminal_identity, true);
        let target = derive_vertical_computation_target(
            context(),
            preparation_terminal_identity,
            &source_terminal,
            true,
            ACTION_ORDINAL,
        )
        .unwrap();
        let keys = roster_keys();
        let (_, finality) = verified_finality(&target, &keys);
        let activations = signed_and_decoded_activations(
            &source_terminal,
            &target,
            &finality,
            &keys,
            true,
            true,
            0,
        );
        let result = verify_activation_transcript(
            vertical_capabilities(&source_terminal, &target, &finality, true),
            activations,
        )
        .unwrap()
        .unwrap();
        assert!(result.result_bit());
        assert_ne!(
            result.semantic_identity().unwrap(),
            result.carrier_identity().unwrap()
        );
        let encoded = result.encode().unwrap();
        let tuple = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).unwrap();
        assert_eq!(tuple.schema_identifier, RESULT_TERMINAL_SCHEMA_IDENTIFIER);
    }

    #[test]
    fn missing_wrong_target_and_duplicate_activation_remain_unaccepted() {
        let preparation_terminal_identity = hash(0x41);
        let source_terminal =
            SourceTerminal::test_fixture(context(), preparation_terminal_identity, true);
        let target = derive_vertical_computation_target(
            context(),
            preparation_terminal_identity,
            &source_terminal,
            true,
            ACTION_ORDINAL,
        )
        .unwrap();
        let keys = roster_keys();
        let (_, finality) = verified_finality(&target, &keys);
        let mut activations = signed_and_decoded_activations(
            &source_terminal,
            &target,
            &finality,
            &keys,
            true,
            true,
            0,
        );
        activations.pop();
        assert!(
            verify_activation_transcript(
                vertical_capabilities(&source_terminal, &target, &finality, true),
                activations,
            )
            .unwrap()
            .is_none()
        );

        let wrong_target = derive_vertical_computation_target(
            context(),
            preparation_terminal_identity,
            &source_terminal,
            false,
            ACTION_ORDINAL,
        )
        .unwrap();
        let activation = real_activations(&source_terminal, &target, true, true, 0).remove(0);
        assert!(
            encode_activation_body(
                vertical_capabilities(&source_terminal, &wrong_target, &finality, false),
                &activation,
            )
            .is_err()
        );

        let mut duplicates = signed_and_decoded_activations(
            &source_terminal,
            &target,
            &finality,
            &keys,
            true,
            true,
            0,
        );
        duplicates.pop();
        let duplicate = signed_and_decoded_activations(
            &source_terminal,
            &target,
            &finality,
            &keys,
            true,
            true,
            1,
        )
        .remove(0);
        duplicates.push(duplicate);
        assert!(
            verify_activation_transcript(
                vertical_capabilities(&source_terminal, &target, &finality, true),
                duplicates,
            )
            .is_err()
        );
    }

    #[test]
    fn valid_activation_variants_have_one_semantic_result() {
        let preparation_terminal_identity = hash(0x51);
        let source_terminal =
            SourceTerminal::test_fixture(context(), preparation_terminal_identity, true);
        let target = derive_vertical_computation_target(
            context(),
            preparation_terminal_identity,
            &source_terminal,
            true,
            ACTION_ORDINAL,
        )
        .unwrap();
        let keys = roster_keys();
        let (_, finality) = verified_finality(&target, &keys);
        let first = verify_activation_transcript(
            vertical_capabilities(&source_terminal, &target, &finality, true),
            signed_and_decoded_activations(
                &source_terminal,
                &target,
                &finality,
                &keys,
                true,
                true,
                0,
            ),
        )
        .unwrap()
        .unwrap();
        let second = verify_activation_transcript(
            vertical_capabilities(&source_terminal, &target, &finality, true),
            signed_and_decoded_activations(
                &source_terminal,
                &target,
                &finality,
                &keys,
                true,
                true,
                0x100,
            ),
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.result_bit(), second.result_bit());
        assert_eq!(
            first.semantic_identity().unwrap(),
            second.semantic_identity().unwrap()
        );
        assert_ne!(
            first.activation_inventory_identity(),
            second.activation_inventory_identity()
        );
    }

    #[test]
    fn empty_source_finalizes_no_result_and_never_activates() {
        let preparation_terminal_identity = hash(0x61);
        let source_terminal =
            SourceTerminal::test_fixture(context(), preparation_terminal_identity, false);
        let target = derive_vertical_computation_target(
            context(),
            preparation_terminal_identity,
            &source_terminal,
            true,
            ACTION_ORDINAL,
        )
        .unwrap();
        let keys = roster_keys();
        let (_, finality) = verified_finality(&target, &keys);
        let terminal = finalize_empty_source(
            context(),
            preparation_terminal_identity,
            &source_terminal,
            &target,
            &finality,
            true,
            ACTION_ORDINAL,
        )
        .unwrap();
        assert!(!terminal.encode().unwrap().is_empty());
        assert_ne!(
            terminal.semantic_identity().unwrap(),
            target.identity().unwrap()
        );

        let present_source =
            SourceTerminal::test_fixture(context(), preparation_terminal_identity, true);
        let present_target = derive_vertical_computation_target(
            context(),
            preparation_terminal_identity,
            &present_source,
            true,
            ACTION_ORDINAL,
        )
        .unwrap();
        let (_, present_finality) = verified_finality(&present_target, &keys);
        assert!(
            finalize_empty_source(
                context(),
                preparation_terminal_identity,
                &present_source,
                &present_target,
                &present_finality,
                true,
                ACTION_ORDINAL,
            )
            .is_err()
        );
    }
}
