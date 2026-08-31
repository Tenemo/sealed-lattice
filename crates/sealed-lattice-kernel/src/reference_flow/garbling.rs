use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_fixed_byte_slice, read_u16, require_tuple},
    field::{
        BitCodeword, FieldElement, MaskPairCodeword, PARTICIPANT_COUNT,
        PreparationCandidateCoordinates, ProductCodeword, ZeroCodeword,
    },
    protocol_oracle::protocol_oracle_output,
    sharing::SourceCodewordCoordinates,
    token::{SecretToken, TOKEN_BYTE_LENGTH, reconstruct_selected_token},
};

pub(crate) const LABEL_BYTE_LENGTH: usize = 48;
const FIELD_BIT_COUNT: usize = 4;
const SEGMENT_ZERO_GATE_COUNT: usize = FIELD_BIT_COUNT * 2;
const SEGMENT_ONE_GATE_COUNT: usize = FIELD_BIT_COUNT;
const LABEL_PAIR_RANDOM_BYTE_LENGTH: usize = LABEL_BYTE_LENGTH * 2;
const LABEL_PAIR_COUNT: usize = FIELD_BIT_COUNT
    + 1
    + FIELD_BIT_COUNT
    + SEGMENT_ZERO_GATE_COUNT
    + FIELD_BIT_COUNT
    + FIELD_BIT_COUNT
    + SEGMENT_ONE_GATE_COUNT;
const TRANSITION_RANDOM_PIECE_COUNT: usize = PARTICIPANT_COUNT * (FIELD_BIT_COUNT - 1);
pub(crate) const VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH: usize = LABEL_PAIR_COUNT
    * LABEL_PAIR_RANDOM_BYTE_LENGTH
    + TRANSITION_RANDOM_PIECE_COUNT * TOKEN_BYTE_LENGTH;
const CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH: usize = LABEL_BYTE_LENGTH * 2;
const VERTICAL_ACTIVATION_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0280;
const VERTICAL_ACTIVATION_PAYLOAD_SCHEMA_VERSION: u16 = 1;
pub(crate) const VERTICAL_ACTIVATION_ENCODING_VERSION: u16 = 1;
const VERTICAL_ACTIVATION_PAYLOAD_ITEM_COUNT: usize = 11;
const GARBLED_TABLE_BYTE_LENGTH: usize = 4 * LABEL_BYTE_LENGTH;
const SEGMENT_ZERO_TABLE_BYTE_LENGTH: usize = SEGMENT_ZERO_GATE_COUNT * GARBLED_TABLE_BYTE_LENGTH;
const FIELD_LABEL_BLOCK_BYTE_LENGTH: usize = FIELD_BIT_COUNT * LABEL_BYTE_LENGTH;
const TRANSITION_TABLE_BYTE_LENGTH: usize = 2 * TOKEN_BYTE_LENGTH;
const TRANSITION_TABLE_BLOCK_BYTE_LENGTH: usize =
    PARTICIPANT_COUNT * FIELD_BIT_COUNT * TRANSITION_TABLE_BYTE_LENGTH;
const CONTINUATION_BUNDLE_BLOCK_BYTE_LENGTH: usize = 2 * CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH;
const DIRECT_REFRESHED_LABEL_BLOCK_BYTE_LENGTH: usize = (FIELD_BIT_COUNT - 1) * LABEL_BYTE_LENGTH;
const SEGMENT_ONE_TABLE_BYTE_LENGTH: usize = SEGMENT_ONE_GATE_COUNT * GARBLED_TABLE_BYTE_LENGTH;
const OUTPUT_DECODER_BLOCK_BYTE_LENGTH: usize = FIELD_BIT_COUNT * 2 * LABEL_BYTE_LENGTH;

const GATE_ROW_DOMAIN: &str = "sealed-lattice/field-collapsed/garbled-gate-row/v1";
const TRANSITION_ROW_DOMAIN: &str = "sealed-lattice/field-collapsed/transition-row/v1";
const CONTINUATION_BUNDLE_DOMAIN: &str = "sealed-lattice/field-collapsed/continuation-bundle/v1";
const CONTINUATION_TAG_DOMAIN: &str = "sealed-lattice/field-collapsed/continuation-tag/v1";
const OUTPUT_DIGEST_DOMAIN: &str = "sealed-lattice/field-collapsed/output-label-digest/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GarblingContext {
    pub(crate) suite_identity: Hash512,
    pub(crate) build_identity: Hash512,
    pub(crate) action_identity: Hash512,
    pub(crate) roster_identity: Hash512,
    pub(crate) circuit_identity: Hash512,
    pub(crate) preparation_terminal_identity: Hash512,
    pub(crate) source_terminal_identity: Hash512,
    pub(crate) target_identity: Hash512,
    pub(crate) activation_encoding_version: u16,
    pub(crate) output_ordinal: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct GarblerContext {
    pub(crate) context: GarblingContext,
    pub(crate) position: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WireLabel(Zeroizing<[u8; LABEL_BYTE_LENGTH]>);

impl core::fmt::Debug for WireLabel {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WireLabel([redacted])")
    }
}

impl WireLabel {
    fn from_bytes(bytes: [u8; LABEL_BYTE_LENGTH]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; LABEL_BYTE_LENGTH] {
        &self.0
    }

    fn permutation_bit(&self) -> bool {
        self.0[0] & 1 != 0
    }
}

struct LabelPair {
    zero: WireLabel,
    one: WireLabel,
}

impl LabelPair {
    fn from_random_tape(tape: &mut RandomByteTape<'_>) -> ProtocolResult<Self> {
        let zero = tape.read_array::<LABEL_BYTE_LENGTH>()?;
        let mut one = tape.read_array::<LABEL_BYTE_LENGTH>()?;
        one[0] = (one[0] & !1) | u8::from(zero[0] & 1 == 0);
        Ok(Self {
            zero: WireLabel::from_bytes(zero),
            one: WireLabel::from_bytes(one),
        })
    }

    fn label(&self, bit: bool) -> &WireLabel {
        if bit { &self.one } else { &self.zero }
    }

    fn selected(&self, bit: bool) -> WireLabel {
        self.label(bit).clone()
    }
}

#[derive(Clone, Copy)]
enum GateKind {
    And,
    Xor,
}

#[derive(Clone, Copy)]
struct GateAddress {
    garbler: GarblerContext,
    segment_index: usize,
    gate_index: usize,
    kind: GateKind,
}

impl GateKind {
    const fn name(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Xor => "xor",
        }
    }

    const fn evaluate(self, left: bool, right: bool) -> bool {
        match self {
            Self::And => left & right,
            Self::Xor => left ^ right,
        }
    }
}

struct GarbledTable {
    rows: [[u8; LABEL_BYTE_LENGTH]; 4],
}

struct TransitionTable {
    rows: [[u8; TOKEN_BYTE_LENGTH]; 2],
}

struct ContinuationBundle {
    ciphertext: [u8; CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH],
}

struct OutputDecoder {
    digests: [[u8; LABEL_BYTE_LENGTH]; 2],
}

pub(crate) struct VerticalActivation {
    garbler_position: usize,
    segment_zero_tables: Vec<GarbledTable>,
    source_labels: [WireLabel; FIELD_BIT_COUNT],
    public_control_label: WireLabel,
    high_mask_labels: [WireLabel; FIELD_BIT_COUNT],
    masked_output_zero_permutation_bits: [bool; FIELD_BIT_COUNT],
    transition_tables: Vec<[TransitionTable; FIELD_BIT_COUNT]>,
    continuation_bundles: [ContinuationBundle; 2],
    direct_refreshed_labels: [WireLabel; FIELD_BIT_COUNT - 1],
    segment_one_tables: Vec<GarbledTable>,
    output_mask_labels: [WireLabel; FIELD_BIT_COUNT],
    output_decoders: [OutputDecoder; FIELD_BIT_COUNT],
}

impl VerticalActivation {
    pub(crate) fn garbler_position(&self) -> usize {
        self.garbler_position
    }

    pub(crate) fn encode_payload(&self) -> ProtocolResult<Vec<u8>> {
        require_activation_shape(self)?;
        let segment_zero_tables = encode_garbled_tables(&self.segment_zero_tables);
        let source_labels = encode_wire_labels(&self.source_labels);
        let high_mask_labels = encode_wire_labels(&self.high_mask_labels);
        let transition_tables = encode_transition_tables(&self.transition_tables);
        let continuation_bundles = self
            .continuation_bundles
            .iter()
            .flat_map(|bundle| bundle.ciphertext)
            .collect::<Vec<_>>();
        let direct_refreshed_labels = encode_wire_labels(&self.direct_refreshed_labels);
        let segment_one_tables = encode_garbled_tables(&self.segment_one_tables);
        let output_mask_labels = encode_wire_labels(&self.output_mask_labels);
        let output_decoders = self
            .output_decoders
            .iter()
            .flat_map(|decoder| decoder.digests.into_iter().flatten())
            .collect::<Vec<_>>();
        let permutation_bits = self
            .masked_output_zero_permutation_bits
            .iter()
            .enumerate()
            .fold(0_u16, |bits, (index, bit)| {
                bits | (u16::from(*bit) << index)
            });
        Ok(CanonicalTuple::new(
            VERTICAL_ACTIVATION_PAYLOAD_SCHEMA_IDENTIFIER,
            VERTICAL_ACTIVATION_PAYLOAD_SCHEMA_VERSION,
            vec![
                CanonicalItem::fixed_bytes(segment_zero_tables)?,
                CanonicalItem::fixed_bytes(source_labels)?,
                CanonicalItem::fixed_bytes(self.public_control_label.as_bytes())?,
                CanonicalItem::fixed_bytes(high_mask_labels)?,
                CanonicalItem::unsigned16(permutation_bits),
                CanonicalItem::fixed_bytes(transition_tables)?,
                CanonicalItem::fixed_bytes(continuation_bundles)?,
                CanonicalItem::fixed_bytes(direct_refreshed_labels)?,
                CanonicalItem::fixed_bytes(segment_one_tables)?,
                CanonicalItem::fixed_bytes(output_mask_labels)?,
                CanonicalItem::fixed_bytes(output_decoders)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn decode_payload(garbler_position: usize, bytes: &[u8]) -> ProtocolResult<Self> {
        if garbler_position >= PARTICIPANT_COUNT {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "activation payload garbler is outside the roster",
            ));
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())?;
        require_tuple(
            &tuple,
            VERTICAL_ACTIVATION_PAYLOAD_SCHEMA_IDENTIFIER,
            VERTICAL_ACTIVATION_PAYLOAD_SCHEMA_VERSION,
            VERTICAL_ACTIVATION_PAYLOAD_ITEM_COUNT,
        )?;
        let permutation_bits = read_u16(&tuple.items[4])?;
        if permutation_bits & !0x0f != 0 {
            return Err(ProtocolRefusal::new(
                RefusalReason::MalformedEncoding,
                "activation payload has noncanonical permutation bits",
            ));
        }
        let transition_tables = decode_transition_tables(read_fixed_byte_slice(
            &tuple.items[5],
            TRANSITION_TABLE_BLOCK_BYTE_LENGTH,
        )?)?;
        let continuation_bundles =
            read_fixed_byte_slice(&tuple.items[6], CONTINUATION_BUNDLE_BLOCK_BYTE_LENGTH)?
                .chunks_exact(CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH)
                .map(|bytes| {
                    Ok(ContinuationBundle {
                        ciphertext: bytes
                            .try_into()
                            .map_err(|_| activation_payload_length_refusal())?,
                    })
                })
                .collect::<ProtocolResult<Vec<_>>>()?
                .try_into()
                .map_err(|_| activation_payload_length_refusal())?;
        let output_decoders =
            read_fixed_byte_slice(&tuple.items[10], OUTPUT_DECODER_BLOCK_BYTE_LENGTH)?
                .chunks_exact(2 * LABEL_BYTE_LENGTH)
                .map(|bytes| {
                    let mut rows = bytes.chunks_exact(LABEL_BYTE_LENGTH);
                    let zero = rows
                        .next()
                        .ok_or_else(activation_payload_length_refusal)?
                        .try_into()
                        .map_err(|_| activation_payload_length_refusal())?;
                    let one = rows
                        .next()
                        .ok_or_else(activation_payload_length_refusal)?
                        .try_into()
                        .map_err(|_| activation_payload_length_refusal())?;
                    Ok(OutputDecoder {
                        digests: [zero, one],
                    })
                })
                .collect::<ProtocolResult<Vec<_>>>()?
                .try_into()
                .map_err(|_| activation_payload_length_refusal())?;
        let activation = Self {
            garbler_position,
            segment_zero_tables: decode_garbled_tables(
                read_fixed_byte_slice(&tuple.items[0], SEGMENT_ZERO_TABLE_BYTE_LENGTH)?,
                SEGMENT_ZERO_GATE_COUNT,
            )?,
            source_labels: decode_wire_labels(read_fixed_byte_slice(
                &tuple.items[1],
                FIELD_LABEL_BLOCK_BYTE_LENGTH,
            )?)?,
            public_control_label: WireLabel::from_bytes(
                read_fixed_byte_slice(&tuple.items[2], LABEL_BYTE_LENGTH)?
                    .try_into()
                    .map_err(|_| activation_payload_length_refusal())?,
            ),
            high_mask_labels: decode_wire_labels(read_fixed_byte_slice(
                &tuple.items[3],
                FIELD_LABEL_BLOCK_BYTE_LENGTH,
            )?)?,
            masked_output_zero_permutation_bits: core::array::from_fn(|index| {
                permutation_bits & (1 << index) != 0
            }),
            transition_tables,
            continuation_bundles,
            direct_refreshed_labels: decode_wire_labels(read_fixed_byte_slice(
                &tuple.items[7],
                DIRECT_REFRESHED_LABEL_BLOCK_BYTE_LENGTH,
            )?)?,
            segment_one_tables: decode_garbled_tables(
                read_fixed_byte_slice(&tuple.items[8], SEGMENT_ONE_TABLE_BYTE_LENGTH)?,
                SEGMENT_ONE_GATE_COUNT,
            )?,
            output_mask_labels: decode_wire_labels(read_fixed_byte_slice(
                &tuple.items[9],
                FIELD_LABEL_BLOCK_BYTE_LENGTH,
            )?)?,
            output_decoders,
        };
        require_activation_shape(&activation)?;
        Ok(activation)
    }
}

pub(crate) fn create_vertical_activation(
    garbler: GarblerContext,
    source: &SourceCodewordCoordinates,
    public_control: bool,
    preparation: &PreparationCandidateCoordinates,
    token_evaluations: &[(SecretToken, SecretToken)],
    continuation_keys: &[SecretToken; 2],
    random_bytes: &[u8],
) -> ProtocolResult<VerticalActivation> {
    let context = garbler.context;
    let garbler_position = garbler.position;
    if garbler_position >= PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "activation garbler position is outside the roster",
        ));
    }
    if token_evaluations.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "activation token setup is missing a receiver",
        ));
    }
    MaskPairCodeword::verify(preparation.low, preparation.high)?;
    ZeroCodeword::verify(preparation.output_zero)?;

    let mut tape = RandomByteTape::new(random_bytes, VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH)?;
    let source_pairs = create_label_pairs::<FIELD_BIT_COUNT>(&mut tape)?;
    let public_control_pair = LabelPair::from_random_tape(&mut tape)?;
    let high_mask_pairs = create_label_pairs::<FIELD_BIT_COUNT>(&mut tape)?;

    let source_bits = field_bits(source.coordinates()[garbler_position]);
    let high_mask_bits = field_bits(preparation.high[garbler_position]);
    let source_labels = core::array::from_fn(|bit| source_pairs[bit].selected(source_bits[bit]));
    let public_control_label = public_control_pair.selected(public_control);
    let high_mask_labels =
        core::array::from_fn(|bit| high_mask_pairs[bit].selected(high_mask_bits[bit]));

    let mut segment_zero_tables = Vec::with_capacity(SEGMENT_ZERO_GATE_COUNT);
    let mut masked_output_pairs = Vec::with_capacity(FIELD_BIT_COUNT);
    for bit in 0..FIELD_BIT_COUNT {
        let (and_table, product_pair) = garble_gate(
            GateAddress {
                garbler,
                segment_index: 0,
                gate_index: segment_zero_tables.len(),
                kind: GateKind::And,
            },
            &source_pairs[bit],
            &public_control_pair,
            &mut tape,
        )?;
        segment_zero_tables.push(and_table);
        let (xor_table, masked_pair) = garble_gate(
            GateAddress {
                garbler,
                segment_index: 0,
                gate_index: segment_zero_tables.len(),
                kind: GateKind::Xor,
            },
            &product_pair,
            &high_mask_pairs[bit],
            &mut tape,
        )?;
        segment_zero_tables.push(xor_table);
        masked_output_pairs.push(masked_pair);
    }
    let masked_output_pairs: [LabelPair; FIELD_BIT_COUNT] = masked_output_pairs
        .try_into()
        .map_err(|_| internal_length_refusal("masked output pair count is wrong"))?;
    let masked_output_zero_permutation_bits =
        core::array::from_fn(|bit| masked_output_pairs[bit].zero.permutation_bit());

    let mut transition_tables = Vec::with_capacity(PARTICIPANT_COUNT);
    for (receiver_position, (a_evaluation, b_evaluation)) in token_evaluations.iter().enumerate() {
        let random_pieces = [
            SecretToken::from_bytes(tape.read_array::<TOKEN_BYTE_LENGTH>()?),
            SecretToken::from_bytes(tape.read_array::<TOKEN_BYTE_LENGTH>()?),
            SecretToken::from_bytes(tape.read_array::<TOKEN_BYTE_LENGTH>()?),
        ];
        let final_piece = a_evaluation
            .add(&random_pieces[0])
            .add(&random_pieces[1])
            .add(&random_pieces[2]);
        let pieces = [
            random_pieces[0].clone(),
            random_pieces[1].clone(),
            random_pieces[2].clone(),
            final_piece,
        ];
        let mut receiver_tables = Vec::with_capacity(FIELD_BIT_COUNT);
        for bit in 0..FIELD_BIT_COUNT {
            let one_message = pieces[bit].add(
                &b_evaluation.multiply(
                    FieldElement::new(1_u8 << bit)
                        .expect("the four polynomial-basis elements are canonical"),
                ),
            );
            receiver_tables.push(garble_transition(
                context,
                garbler_position,
                receiver_position,
                bit,
                &masked_output_pairs[bit],
                &pieces[bit],
                &one_message,
            )?);
        }
        transition_tables.push(
            receiver_tables
                .try_into()
                .map_err(|_| internal_length_refusal("receiver transition count is wrong"))?,
        );
    }

    let refreshed_pairs = create_label_pairs::<FIELD_BIT_COUNT>(&mut tape)?;
    let output_mask_pairs = create_label_pairs::<FIELD_BIT_COUNT>(&mut tape)?;
    let low_mask_bits = field_bits(preparation.low[garbler_position]);
    let output_mask_bits = field_bits(preparation.output_zero[garbler_position]);
    let continuation_bundles = [
        create_continuation_bundle(
            context,
            garbler_position,
            false,
            &continuation_keys[0],
            refreshed_pairs[0].label(low_mask_bits[0]),
        )?,
        create_continuation_bundle(
            context,
            garbler_position,
            true,
            &continuation_keys[1],
            refreshed_pairs[0].label(!low_mask_bits[0]),
        )?,
    ];
    let direct_refreshed_labels = core::array::from_fn(|index| {
        let bit = index + 1;
        refreshed_pairs[bit].selected(low_mask_bits[bit])
    });
    let output_mask_labels =
        core::array::from_fn(|bit| output_mask_pairs[bit].selected(output_mask_bits[bit]));

    let mut segment_one_tables = Vec::with_capacity(SEGMENT_ONE_GATE_COUNT);
    let mut output_pairs = Vec::with_capacity(FIELD_BIT_COUNT);
    for bit in 0..FIELD_BIT_COUNT {
        let (table, output_pair) = garble_gate(
            GateAddress {
                garbler,
                segment_index: 1,
                gate_index: bit,
                kind: GateKind::Xor,
            },
            &refreshed_pairs[bit],
            &output_mask_pairs[bit],
            &mut tape,
        )?;
        segment_one_tables.push(table);
        output_pairs.push(output_pair);
    }
    let output_pairs: [LabelPair; FIELD_BIT_COUNT] = output_pairs
        .try_into()
        .map_err(|_| internal_length_refusal("output pair count is wrong"))?;
    let output_decoders = create_output_decoders(context, garbler_position, &output_pairs)?;
    tape.finish()?;

    Ok(VerticalActivation {
        garbler_position,
        segment_zero_tables,
        source_labels,
        public_control_label,
        high_mask_labels,
        masked_output_zero_permutation_bits,
        transition_tables,
        continuation_bundles,
        direct_refreshed_labels,
        segment_one_tables,
        output_mask_labels,
        output_decoders,
    })
}

pub(crate) fn evaluate_vertical_activations(
    context: GarblingContext,
    activations: &[VerticalActivation],
) -> ProtocolResult<bool> {
    let ordered = order_activations(activations)?;
    let mut masked_labels = Vec::with_capacity(PARTICIPANT_COUNT);
    let mut masked_coordinates = [FieldElement::ZERO; PARTICIPANT_COUNT];
    for (position, activation) in ordered.iter().enumerate() {
        require_activation_shape(activation)?;
        let mut selected = Vec::with_capacity(FIELD_BIT_COUNT);
        let mut table_index = 0;
        for bit in 0..FIELD_BIT_COUNT {
            let product = evaluate_gate(
                GateAddress {
                    garbler: GarblerContext { context, position },
                    segment_index: 0,
                    gate_index: table_index,
                    kind: GateKind::And,
                },
                &activation.segment_zero_tables[table_index],
                &activation.source_labels[bit],
                &activation.public_control_label,
            )?;
            table_index += 1;
            let masked = evaluate_gate(
                GateAddress {
                    garbler: GarblerContext { context, position },
                    segment_index: 0,
                    gate_index: table_index,
                    kind: GateKind::Xor,
                },
                &activation.segment_zero_tables[table_index],
                &product,
                &activation.high_mask_labels[bit],
            )?;
            table_index += 1;
            selected.push(masked);
        }
        let selected: [WireLabel; FIELD_BIT_COUNT] = selected
            .try_into()
            .map_err(|_| internal_length_refusal("masked label count is wrong"))?;
        let bits = core::array::from_fn(|bit| {
            selected[bit].permutation_bit() ^ activation.masked_output_zero_permutation_bits[bit]
        });
        masked_coordinates[position] = field_from_bits(bits);
        masked_labels.push(selected);
    }
    let masked_word = ProductCodeword::verify(masked_coordinates)?;
    let masked_bit = masked_word.constant() == FieldElement::ONE;

    let mut output_coordinates = [FieldElement::ZERO; PARTICIPANT_COUNT];
    for receiver_position in 0..PARTICIPANT_COUNT {
        let mut contributions = Vec::with_capacity(PARTICIPANT_COUNT);
        for garbler_position in 0..PARTICIPANT_COUNT {
            let mut contribution = SecretToken::zero();
            for bit in 0..FIELD_BIT_COUNT {
                contribution = contribution.add(&evaluate_transition(
                    context,
                    garbler_position,
                    receiver_position,
                    bit,
                    &ordered[garbler_position].transition_tables[receiver_position][bit],
                    &masked_labels[garbler_position][bit],
                )?);
            }
            contributions.push(contribution);
        }
        let selected_token = reconstruct_selected_token(&contributions)?;
        let receiver_activation = ordered[receiver_position];
        let first_refreshed_label = open_continuation_bundle(
            context,
            receiver_position,
            masked_bit,
            &selected_token,
            &receiver_activation.continuation_bundles[usize::from(masked_bit)],
        )?;
        let refreshed_labels = [
            first_refreshed_label,
            receiver_activation.direct_refreshed_labels[0].clone(),
            receiver_activation.direct_refreshed_labels[1].clone(),
            receiver_activation.direct_refreshed_labels[2].clone(),
        ];
        let mut output_bits = [false; FIELD_BIT_COUNT];
        for bit in 0..FIELD_BIT_COUNT {
            let output_label = evaluate_gate(
                GateAddress {
                    garbler: GarblerContext {
                        context,
                        position: receiver_position,
                    },
                    segment_index: 1,
                    gate_index: bit,
                    kind: GateKind::Xor,
                },
                &receiver_activation.segment_one_tables[bit],
                &refreshed_labels[bit],
                &receiver_activation.output_mask_labels[bit],
            )?;
            output_bits[bit] = decode_output_label(
                context,
                receiver_position,
                bit,
                &output_label,
                &receiver_activation.output_decoders[bit],
            )?;
        }
        output_coordinates[receiver_position] = field_from_bits(output_bits);
    }
    let output_word = BitCodeword::verify(output_coordinates)?;
    Ok(output_word.constant() == FieldElement::ONE)
}

fn garble_gate(
    address: GateAddress,
    left: &LabelPair,
    right: &LabelPair,
    tape: &mut RandomByteTape<'_>,
) -> ProtocolResult<(GarbledTable, LabelPair)> {
    let output = LabelPair::from_random_tape(tape)?;
    let mut rows = [[0_u8; LABEL_BYTE_LENGTH]; 4];
    for left_bit in [false, true] {
        for right_bit in [false, true] {
            let left_label = left.label(left_bit);
            let right_label = right.label(right_bit);
            let slot = gate_slot(left_label, right_label);
            let pad = gate_pad(address, slot, left_label, right_label)?;
            rows[slot] = xor_fixed(
                &pad,
                output
                    .label(address.kind.evaluate(left_bit, right_bit))
                    .as_bytes(),
            );
        }
    }
    Ok((GarbledTable { rows }, output))
}

fn evaluate_gate(
    address: GateAddress,
    table: &GarbledTable,
    left: &WireLabel,
    right: &WireLabel,
) -> ProtocolResult<WireLabel> {
    let slot = gate_slot(left, right);
    let pad = gate_pad(address, slot, left, right)?;
    Ok(WireLabel::from_bytes(xor_fixed(&pad, &table.rows[slot])))
}

fn gate_pad(
    address: GateAddress,
    row_slot: usize,
    left: &WireLabel,
    right: &WireLabel,
) -> ProtocolResult<[u8; LABEL_BYTE_LENGTH]> {
    let mut items = common_context_items(address.garbler.context);
    items.extend([
        CanonicalItem::unsigned16(address.garbler.position as u16),
        CanonicalItem::unsigned64(address.segment_index as u64),
        CanonicalItem::unsigned64(address.gate_index as u64),
        CanonicalItem::nonempty_ascii(address.kind.name())?,
        CanonicalItem::unsigned16(row_slot as u16),
        CanonicalItem::fixed_bytes(left.as_bytes())?,
        CanonicalItem::fixed_bytes(right.as_bytes())?,
        CanonicalItem::unsigned64(LABEL_BYTE_LENGTH as u64),
    ]);
    protocol_oracle_output(GATE_ROW_DOMAIN, &items)
}

fn garble_transition(
    context: GarblingContext,
    garbler_position: usize,
    receiver_position: usize,
    field_bit: usize,
    selected_pair: &LabelPair,
    zero_message: &SecretToken,
    one_message: &SecretToken,
) -> ProtocolResult<TransitionTable> {
    let mut rows = [[0_u8; TOKEN_BYTE_LENGTH]; 2];
    for semantic_bit in [false, true] {
        let label = selected_pair.label(semantic_bit);
        let slot = usize::from(label.permutation_bit());
        let pad = transition_pad(
            context,
            garbler_position,
            receiver_position,
            field_bit,
            slot,
            label,
        )?;
        let message = if semantic_bit {
            one_message
        } else {
            zero_message
        };
        rows[slot] = xor_fixed(&pad, message.as_bytes());
    }
    Ok(TransitionTable { rows })
}

fn evaluate_transition(
    context: GarblingContext,
    garbler_position: usize,
    receiver_position: usize,
    field_bit: usize,
    table: &TransitionTable,
    selected_label: &WireLabel,
) -> ProtocolResult<SecretToken> {
    let slot = usize::from(selected_label.permutation_bit());
    let pad = transition_pad(
        context,
        garbler_position,
        receiver_position,
        field_bit,
        slot,
        selected_label,
    )?;
    Ok(SecretToken::from_bytes(xor_fixed(&pad, &table.rows[slot])))
}

fn transition_pad(
    context: GarblingContext,
    garbler_position: usize,
    receiver_position: usize,
    field_bit: usize,
    row_slot: usize,
    label: &WireLabel,
) -> ProtocolResult<[u8; TOKEN_BYTE_LENGTH]> {
    let mut items = common_context_items(context);
    items.extend([
        CanonicalItem::unsigned16(garbler_position as u16),
        CanonicalItem::unsigned16(receiver_position as u16),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned16(field_bit as u16),
        CanonicalItem::unsigned16(row_slot as u16),
        CanonicalItem::fixed_bytes(label.as_bytes())?,
        CanonicalItem::unsigned64(TOKEN_BYTE_LENGTH as u64),
    ]);
    protocol_oracle_output(TRANSITION_ROW_DOMAIN, &items)
}

fn create_continuation_bundle(
    context: GarblingContext,
    receiver_position: usize,
    candidate: bool,
    key: &SecretToken,
    refreshed_label: &WireLabel,
) -> ProtocolResult<ContinuationBundle> {
    let tag = continuation_tag(context, receiver_position, candidate)?;
    let mut plaintext = Zeroizing::new([0_u8; CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH]);
    plaintext[..LABEL_BYTE_LENGTH].copy_from_slice(refreshed_label.as_bytes());
    plaintext[LABEL_BYTE_LENGTH..].copy_from_slice(&tag);
    let pad = continuation_bundle_pad(context, receiver_position, candidate, key)?;
    Ok(ContinuationBundle {
        ciphertext: xor_fixed(&plaintext, &pad),
    })
}

fn open_continuation_bundle(
    context: GarblingContext,
    receiver_position: usize,
    candidate: bool,
    key: &SecretToken,
    bundle: &ContinuationBundle,
) -> ProtocolResult<WireLabel> {
    let pad = continuation_bundle_pad(context, receiver_position, candidate, key)?;
    let plaintext = Zeroizing::new(xor_fixed(&bundle.ciphertext, &pad));
    let expected_tag = continuation_tag(context, receiver_position, candidate)?;
    if !bool::from(plaintext[LABEL_BYTE_LENGTH..].ct_eq(&expected_tag)) {
        return Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "continuation bundle tag verification failed",
        ));
    }
    let mut label = [0_u8; LABEL_BYTE_LENGTH];
    label.copy_from_slice(&plaintext[..LABEL_BYTE_LENGTH]);
    Ok(WireLabel::from_bytes(label))
}

fn continuation_bundle_pad(
    context: GarblingContext,
    receiver_position: usize,
    candidate: bool,
    key: &SecretToken,
) -> ProtocolResult<[u8; CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH]> {
    let mut items = common_context_items(context);
    items.extend([
        CanonicalItem::unsigned16(receiver_position as u16),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned16(u16::from(candidate)),
        CanonicalItem::fixed_bytes(key.as_bytes())?,
        CanonicalItem::unsigned64(CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH as u64),
    ]);
    protocol_oracle_output(CONTINUATION_BUNDLE_DOMAIN, &items)
}

fn continuation_tag(
    context: GarblingContext,
    receiver_position: usize,
    candidate: bool,
) -> ProtocolResult<[u8; LABEL_BYTE_LENGTH]> {
    let mut items = common_context_items(context);
    items.extend([
        CanonicalItem::unsigned16(receiver_position as u16),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned16(u16::from(candidate)),
        CanonicalItem::unsigned64(CONTINUATION_BUNDLE_PLAINTEXT_BYTE_LENGTH as u64),
        CanonicalItem::unsigned64(LABEL_BYTE_LENGTH as u64),
    ]);
    protocol_oracle_output(CONTINUATION_TAG_DOMAIN, &items)
}

fn create_output_decoders(
    context: GarblingContext,
    garbler_position: usize,
    output_pairs: &[LabelPair; FIELD_BIT_COUNT],
) -> ProtocolResult<[OutputDecoder; FIELD_BIT_COUNT]> {
    let mut decoders = Vec::with_capacity(FIELD_BIT_COUNT);
    for (field_bit, pair) in output_pairs.iter().enumerate() {
        decoders.push(OutputDecoder {
            digests: [
                output_digest(context, garbler_position, field_bit, false, &pair.zero)?,
                output_digest(context, garbler_position, field_bit, true, &pair.one)?,
            ],
        });
    }
    decoders
        .try_into()
        .map_err(|_| internal_length_refusal("output decoder count is wrong"))
}

fn decode_output_label(
    context: GarblingContext,
    garbler_position: usize,
    field_bit: usize,
    label: &WireLabel,
    decoder: &OutputDecoder,
) -> ProtocolResult<bool> {
    let zero = output_digest(context, garbler_position, field_bit, false, label)?;
    let one = output_digest(context, garbler_position, field_bit, true, label)?;
    let zero_matches = bool::from(zero.ct_eq(&decoder.digests[0]));
    let one_matches = bool::from(one.ct_eq(&decoder.digests[1]));
    match (zero_matches, one_matches) {
        (true, false) => Ok(false),
        (false, true) => Ok(true),
        _ => Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "output label does not have one unique semantic decoding",
        )),
    }
}

fn output_digest(
    context: GarblingContext,
    garbler_position: usize,
    field_bit: usize,
    semantic_bit: bool,
    label: &WireLabel,
) -> ProtocolResult<[u8; LABEL_BYTE_LENGTH]> {
    let mut items = common_context_items(context);
    items.extend([
        CanonicalItem::unsigned16(garbler_position as u16),
        CanonicalItem::unsigned64(context.output_ordinal),
        CanonicalItem::unsigned16(field_bit as u16),
        CanonicalItem::unsigned16(u16::from(semantic_bit)),
        CanonicalItem::fixed_bytes(label.as_bytes())?,
        CanonicalItem::unsigned64(LABEL_BYTE_LENGTH as u64),
    ]);
    protocol_oracle_output(OUTPUT_DIGEST_DOMAIN, &items)
}

fn common_context_items(context: GarblingContext) -> Vec<CanonicalItem> {
    vec![
        CanonicalItem::hash512(context.suite_identity.into_bytes()),
        CanonicalItem::hash512(context.build_identity.into_bytes()),
        CanonicalItem::hash512(context.action_identity.into_bytes()),
        CanonicalItem::hash512(context.roster_identity.into_bytes()),
        CanonicalItem::hash512(context.circuit_identity.into_bytes()),
        CanonicalItem::hash512(context.preparation_terminal_identity.into_bytes()),
        CanonicalItem::hash512(context.source_terminal_identity.into_bytes()),
        CanonicalItem::hash512(context.target_identity.into_bytes()),
        CanonicalItem::unsigned16(context.activation_encoding_version),
    ]
}

fn order_activations(
    activations: &[VerticalActivation],
) -> ProtocolResult<[&VerticalActivation; PARTICIPANT_COUNT]> {
    if activations.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "activation inventory is missing a roster position",
        ));
    }
    let mut ordered = [None; PARTICIPANT_COUNT];
    for activation in activations {
        if activation.garbler_position >= PARTICIPANT_COUNT {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "activation position is outside the roster",
            ));
        }
        if ordered[activation.garbler_position]
            .replace(activation)
            .is_some()
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::DuplicateIdentity,
                "activation inventory repeats a roster position",
            ));
        }
    }
    ordered
        .map(|entry| {
            entry.ok_or_else(|| {
                ProtocolRefusal::new(
                    RefusalReason::WrongTypeOrLength,
                    "activation inventory is incomplete",
                )
            })
        })
        .into_iter()
        .collect::<ProtocolResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| internal_length_refusal("ordered activation count is wrong"))
}

fn encode_wire_labels<const COUNT: usize>(labels: &[WireLabel; COUNT]) -> Vec<u8> {
    labels
        .iter()
        .flat_map(|label| label.as_bytes().iter().copied())
        .collect()
}

fn decode_wire_labels<const COUNT: usize>(bytes: &[u8]) -> ProtocolResult<[WireLabel; COUNT]> {
    if bytes.len() != COUNT * LABEL_BYTE_LENGTH {
        return Err(activation_payload_length_refusal());
    }
    bytes
        .chunks_exact(LABEL_BYTE_LENGTH)
        .map(|label| {
            Ok(WireLabel::from_bytes(
                label
                    .try_into()
                    .map_err(|_| activation_payload_length_refusal())?,
            ))
        })
        .collect::<ProtocolResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| activation_payload_length_refusal())
}

fn encode_garbled_tables(tables: &[GarbledTable]) -> Vec<u8> {
    tables
        .iter()
        .flat_map(|table| table.rows.into_iter().flatten())
        .collect()
}

fn decode_garbled_tables(bytes: &[u8], table_count: usize) -> ProtocolResult<Vec<GarbledTable>> {
    if bytes.len() != table_count * GARBLED_TABLE_BYTE_LENGTH {
        return Err(activation_payload_length_refusal());
    }
    bytes
        .chunks_exact(GARBLED_TABLE_BYTE_LENGTH)
        .map(|table_bytes| {
            let rows = table_bytes
                .chunks_exact(LABEL_BYTE_LENGTH)
                .map(|row| {
                    row.try_into()
                        .map_err(|_| activation_payload_length_refusal())
                })
                .collect::<ProtocolResult<Vec<_>>>()?
                .try_into()
                .map_err(|_| activation_payload_length_refusal())?;
            Ok(GarbledTable { rows })
        })
        .collect()
}

fn encode_transition_tables(tables: &[[TransitionTable; FIELD_BIT_COUNT]]) -> Vec<u8> {
    tables
        .iter()
        .flat_map(|receiver| receiver.iter())
        .flat_map(|table| table.rows.into_iter().flatten())
        .collect()
}

fn decode_transition_tables(
    bytes: &[u8],
) -> ProtocolResult<Vec<[TransitionTable; FIELD_BIT_COUNT]>> {
    if bytes.len() != TRANSITION_TABLE_BLOCK_BYTE_LENGTH {
        return Err(activation_payload_length_refusal());
    }
    bytes
        .chunks_exact(FIELD_BIT_COUNT * TRANSITION_TABLE_BYTE_LENGTH)
        .map(|receiver_bytes| {
            receiver_bytes
                .chunks_exact(TRANSITION_TABLE_BYTE_LENGTH)
                .map(|table_bytes| {
                    let rows = table_bytes
                        .chunks_exact(TOKEN_BYTE_LENGTH)
                        .map(|row| {
                            row.try_into()
                                .map_err(|_| activation_payload_length_refusal())
                        })
                        .collect::<ProtocolResult<Vec<_>>>()?
                        .try_into()
                        .map_err(|_| activation_payload_length_refusal())?;
                    Ok(TransitionTable { rows })
                })
                .collect::<ProtocolResult<Vec<_>>>()?
                .try_into()
                .map_err(|_| activation_payload_length_refusal())
        })
        .collect()
}

fn activation_payload_length_refusal() -> ProtocolRefusal {
    ProtocolRefusal::new(
        RefusalReason::WrongTypeOrLength,
        "activation payload has the wrong fixed section length",
    )
}

fn require_activation_shape(activation: &VerticalActivation) -> ProtocolResult<()> {
    if activation.segment_zero_tables.len() != SEGMENT_ZERO_GATE_COUNT
        || activation.transition_tables.len() != PARTICIPANT_COUNT
        || activation.segment_one_tables.len() != SEGMENT_ONE_GATE_COUNT
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "activation package has the wrong circuit shape",
        ));
    }
    Ok(())
}

fn create_label_pairs<const COUNT: usize>(
    tape: &mut RandomByteTape<'_>,
) -> ProtocolResult<[LabelPair; COUNT]> {
    (0..COUNT)
        .map(|_| LabelPair::from_random_tape(tape))
        .collect::<ProtocolResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| internal_length_refusal("label pair count is wrong"))
}

fn field_bits(value: FieldElement) -> [bool; FIELD_BIT_COUNT] {
    core::array::from_fn(|bit| value.value() & (1 << bit) != 0)
}

fn field_from_bits(bits: [bool; FIELD_BIT_COUNT]) -> FieldElement {
    let value = bits
        .into_iter()
        .enumerate()
        .fold(0_u8, |value, (bit, selected)| {
            value | (u8::from(selected) << bit)
        });
    FieldElement::new(value).expect("four bits are one canonical field element")
}

fn gate_slot(left: &WireLabel, right: &WireLabel) -> usize {
    (usize::from(left.permutation_bit()) << 1) | usize::from(right.permutation_bit())
}

fn xor_fixed<const LENGTH: usize>(left: &[u8; LENGTH], right: &[u8; LENGTH]) -> [u8; LENGTH] {
    core::array::from_fn(|index| left[index] ^ right[index])
}

fn internal_length_refusal(message: &'static str) -> ProtocolRefusal {
    ProtocolRefusal::new(RefusalReason::OutsideSupportedProfile, message)
}

struct RandomByteTape<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RandomByteTape<'a> {
    fn new(bytes: &'a [u8], expected_byte_length: usize) -> ProtocolResult<Self> {
        if bytes.len() != expected_byte_length {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "activation random tape has the wrong byte length",
            ));
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn read_array<const LENGTH: usize>(&mut self) -> ProtocolResult<[u8; LENGTH]> {
        let end = self.offset.checked_add(LENGTH).ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "activation random-tape cursor overflows",
            )
        })?;
        let bytes = self.bytes.get(self.offset..end).ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "activation random tape is exhausted",
            )
        })?;
        self.offset = end;
        bytes.try_into().map_err(|_| {
            ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "activation random-tape item has the wrong length",
            )
        })
    }

    fn finish(self) -> ProtocolResult<()> {
        if self.offset != self.bytes.len() {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "activation random tape was not consumed exactly once",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        sharing::{
            PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH, SOURCE_CODEWORD_RANDOM_BYTE_LENGTH,
            aggregate_preparation_coordinates, create_preparation_candidate,
            create_source_codeword,
        },
        token::{RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH, create_receiver_token_setup},
    };

    fn context() -> GarblingContext {
        GarblingContext {
            suite_identity: Hash512::from_bytes([0x11; 64]),
            build_identity: Hash512::from_bytes([0x12; 64]),
            action_identity: Hash512::from_bytes([0x22; 64]),
            roster_identity: Hash512::from_bytes([0x33; 64]),
            circuit_identity: Hash512::from_bytes([0x44; 64]),
            preparation_terminal_identity: Hash512::from_bytes([0x55; 64]),
            source_terminal_identity: Hash512::from_bytes([0x66; 64]),
            target_identity: Hash512::from_bytes([0x77; 64]),
            activation_encoding_version: 1,
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

    fn preparation() -> PreparationCandidateCoordinates {
        let dealers = (0..PARTICIPANT_COUNT)
            .map(|position| {
                create_preparation_candidate(&deterministic_bytes(
                    0x1000 + position as u64,
                    PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH,
                ))
                .expect("preparation randomness has the exact length")
            })
            .collect::<Vec<_>>();
        let dealer_references = dealers.iter().collect::<Vec<_>>();
        aggregate_preparation_coordinates(&dealer_references)
            .expect("all preparation dealers are present")
    }

    fn token_setups() -> Vec<super::super::token::ReceiverTokenSetup> {
        (0..PARTICIPANT_COUNT)
            .map(|position| {
                let mut bytes = deterministic_bytes(
                    0x2000 + position as u64,
                    RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH,
                );
                bytes[10 * TOKEN_BYTE_LENGTH] |= 1;
                create_receiver_token_setup(&bytes)
                    .expect("receiver token setup has a nonzero difference")
            })
            .collect()
    }

    fn activations_for(source_bit: bool, public_control: bool) -> Vec<VerticalActivation> {
        let context = context();
        let source = create_source_codeword(
            source_bit,
            &deterministic_bytes(0x3000, SOURCE_CODEWORD_RANDOM_BYTE_LENGTH),
        )
        .expect("source randomness has the exact length");
        let preparation = preparation();
        let setups = token_setups();
        (0..PARTICIPANT_COUNT)
            .map(|garbler_position| {
                let evaluations = setups
                    .iter()
                    .map(|setup| setup.clone_evaluation_for_garbler(garbler_position))
                    .collect::<Vec<_>>();
                let keys = setups[garbler_position].clone_continuation_keys();
                create_vertical_activation(
                    GarblerContext {
                        context,
                        position: garbler_position,
                    },
                    &source,
                    public_control,
                    &preparation,
                    &evaluations,
                    &keys,
                    &deterministic_bytes(
                        0x4000 + garbler_position as u64,
                        VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH,
                    ),
                )
                .expect("activation inputs are complete")
            })
            .collect()
    }

    #[test]
    fn real_one_input_one_and_one_output_flow_matches_boolean_semantics() {
        for source_bit in [false, true] {
            for public_control in [false, true] {
                let activations = activations_for(source_bit, public_control);
                let encoded = activations
                    .iter()
                    .map(VerticalActivation::encode_payload)
                    .collect::<ProtocolResult<Vec<_>>>()
                    .expect("activation payloads encode");
                let decoded = encoded
                    .iter()
                    .enumerate()
                    .map(|(position, bytes)| VerticalActivation::decode_payload(position, bytes))
                    .collect::<ProtocolResult<Vec<_>>>()
                    .expect("activation payloads decode");
                assert_eq!(
                    evaluate_vertical_activations(context(), &decoded)
                        .expect("complete honest activations evaluate"),
                    source_bit & public_control
                );
                assert_eq!(
                    decoded
                        .iter()
                        .map(VerticalActivation::encode_payload)
                        .collect::<ProtocolResult<Vec<_>>>()
                        .unwrap(),
                    encoded
                );
            }
        }
    }

    #[test]
    fn missing_duplicate_wrong_context_and_selected_bundle_mutation_refuse() {
        let mut activations = activations_for(true, true);
        assert!(evaluate_vertical_activations(context(), &activations[..9]).is_err());

        activations[9].garbler_position = 8;
        assert!(evaluate_vertical_activations(context(), &activations).is_err());
        activations[9].garbler_position = 9;

        let wrong_context = GarblingContext {
            target_identity: Hash512::from_bytes([0xa7; 64]),
            ..context()
        };
        assert!(evaluate_vertical_activations(wrong_context, &activations).is_err());

        activations[3].continuation_bundles[0].ciphertext[0] ^= 1;
        activations[3].continuation_bundles[1].ciphertext[0] ^= 1;
        assert!(evaluate_vertical_activations(context(), &activations).is_err());
    }

    #[test]
    fn transition_and_output_mutations_refuse_before_result_acceptance() {
        let mut transition_mutation = activations_for(true, true);
        for row in &mut transition_mutation[2].transition_tables[4][0].rows {
            row[7] ^= 1;
        }
        assert!(evaluate_vertical_activations(context(), &transition_mutation).is_err());

        let mut output_mutation = activations_for(true, true);
        output_mutation[7].output_decoders[2].digests[0][0] ^= 1;
        output_mutation[7].output_decoders[2].digests[1][0] ^= 1;
        assert!(evaluate_vertical_activations(context(), &output_mutation).is_err());
    }

    #[test]
    fn activation_randomness_and_token_inventory_have_exact_lengths() {
        let source = create_source_codeword(
            false,
            &deterministic_bytes(0x5000, SOURCE_CODEWORD_RANDOM_BYTE_LENGTH),
        )
        .expect("source randomness has the exact length");
        let preparation = preparation();
        let setups = token_setups();
        let evaluations = setups
            .iter()
            .map(|setup| setup.clone_evaluation_for_garbler(0))
            .collect::<Vec<_>>();
        let keys = setups[0].clone_continuation_keys();
        assert!(
            create_vertical_activation(
                GarblerContext {
                    context: context(),
                    position: 0,
                },
                &source,
                false,
                &preparation,
                &evaluations,
                &keys,
                &vec![0; VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH - 1],
            )
            .is_err()
        );
        assert!(
            create_vertical_activation(
                GarblerContext {
                    context: context(),
                    position: 0,
                },
                &source,
                false,
                &preparation,
                &evaluations[..9],
                &keys,
                &vec![0; VERTICAL_ACTIVATION_RANDOM_BYTE_LENGTH],
            )
            .is_err()
        );

        let activation = activations_for(true, true).remove(0);
        let encoded = activation.encode_payload().unwrap();
        let mut tuple =
            CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).unwrap();
        tuple.items[4] = CanonicalItem::unsigned16(0x10);
        assert!(VerticalActivation::decode_payload(0, &tuple.encode().unwrap()).is_err());
    }
}
