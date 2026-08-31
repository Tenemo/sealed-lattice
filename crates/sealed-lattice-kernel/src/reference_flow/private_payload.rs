use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, RefusalReason};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_fixed_byte_slice, read_fixed_bytes, require_tuple},
    challenge::ChallengeDealerCoordinates,
    field::{
        DIRECT_CHECK_REPETITION_COUNT, FieldElement, PARTICIPANT_COUNT,
        PreparationCandidateCoordinates, pack_field_elements, unpack_field_elements,
    },
    sharing::SourceCodewordCoordinates,
    token::{ReceiverTokenSetup, SecretToken},
};

const PREPARATION_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0240;
const SOURCE_SUBMIT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0241;
const SOURCE_ABSENT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0242;
const PRIVATE_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const PREPARATION_CANDIDATE_FIELD_ELEMENT_COUNT: usize = 3;
const PREPARATION_RESPONSE_PAD_FIELD_ELEMENT_COUNT: usize =
    DIRECT_CHECK_REPETITION_COUNT * PREPARATION_CANDIDATE_FIELD_ELEMENT_COUNT;
const PACKED_PREPARATION_CANDIDATE_BYTE_LENGTH: usize =
    PREPARATION_CANDIDATE_FIELD_ELEMENT_COUNT.div_ceil(2);
const PACKED_CHALLENGE_BYTE_LENGTH: usize = DIRECT_CHECK_REPETITION_COUNT.div_ceil(2);
const PACKED_PREPARATION_RESPONSE_PAD_BYTE_LENGTH: usize =
    PREPARATION_RESPONSE_PAD_FIELD_ELEMENT_COUNT.div_ceil(2);
const PACKED_SOURCE_COORDINATE_BYTE_LENGTH: usize = 1;
const PACKED_SOURCE_RESPONSE_PAD_BYTE_LENGTH: usize = DIRECT_CHECK_REPETITION_COUNT.div_ceil(2);

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PreparationRecipientCoordinate {
    pub(crate) low: FieldElement,
    pub(crate) high: FieldElement,
    pub(crate) output_zero: FieldElement,
}

impl core::fmt::Debug for PreparationRecipientCoordinate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparationRecipientCoordinate([redacted])")
    }
}

impl Zeroize for PreparationRecipientCoordinate {
    fn zeroize(&mut self) {
        self.low.zeroize();
        self.high.zeroize();
        self.output_zero.zeroize();
    }
}

pub(crate) struct PreparationMailboxPayload {
    recipient_candidate: PreparationRecipientCoordinate,
    challenge_coordinates: Vec<FieldElement>,
    response_pad_coordinates: Vec<PreparationRecipientCoordinate>,
    token_a_evaluation: SecretToken,
    token_b_evaluation: SecretToken,
}

impl core::fmt::Debug for PreparationMailboxPayload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparationMailboxPayload([redacted])")
    }
}

impl Drop for PreparationMailboxPayload {
    fn drop(&mut self) {
        self.recipient_candidate.zeroize();
        self.challenge_coordinates.zeroize();
        self.response_pad_coordinates.zeroize();
    }
}

impl PreparationMailboxPayload {
    pub(crate) fn recipient_candidate(&self) -> &PreparationRecipientCoordinate {
        &self.recipient_candidate
    }

    pub(crate) fn challenge_coordinates(&self) -> &[FieldElement] {
        &self.challenge_coordinates
    }

    pub(crate) fn response_pad_coordinates(&self) -> &[PreparationRecipientCoordinate] {
        &self.response_pad_coordinates
    }

    pub(crate) fn token_evaluations(&self) -> (&SecretToken, &SecretToken) {
        (&self.token_a_evaluation, &self.token_b_evaluation)
    }
}

pub(crate) struct SourceMailboxPayload {
    source_coordinate: Option<FieldElement>,
    challenge_coordinates: Vec<FieldElement>,
    response_pad_coordinates: Vec<FieldElement>,
}

impl core::fmt::Debug for SourceMailboxPayload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SourceMailboxPayload([redacted])")
    }
}

impl Drop for SourceMailboxPayload {
    fn drop(&mut self) {
        self.source_coordinate.zeroize();
        self.challenge_coordinates.zeroize();
        self.response_pad_coordinates.zeroize();
    }
}

impl SourceMailboxPayload {
    pub(crate) fn source_coordinate(&self) -> Option<FieldElement> {
        self.source_coordinate
    }

    pub(crate) fn challenge_coordinates(&self) -> &[FieldElement] {
        &self.challenge_coordinates
    }

    pub(crate) fn response_pad_coordinates(&self) -> &[FieldElement] {
        &self.response_pad_coordinates
    }
}

pub(crate) fn encode_preparation_mailbox_payload(
    recipient_position: usize,
    candidate: &PreparationCandidateCoordinates,
    challenge: &ChallengeDealerCoordinates,
    response_pads: &[PreparationCandidateCoordinates],
    receiver_token_setup: &ReceiverTokenSetup,
) -> ProtocolResult<Zeroizing<Vec<u8>>> {
    require_recipient_position(recipient_position)?;
    if response_pads.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "preparation mailbox has the wrong response-pad count",
        ));
    }

    let candidate_elements = [
        candidate.low[recipient_position],
        candidate.high[recipient_position],
        candidate.output_zero[recipient_position],
    ];
    let packed_candidate = Zeroizing::new(pack_field_elements(&candidate_elements));
    let packed_challenge = Zeroizing::new(pack_field_elements(
        challenge.recipient_block(recipient_position),
    ));
    let mut response_pad_elements = Zeroizing::new(Vec::with_capacity(
        PREPARATION_RESPONSE_PAD_FIELD_ELEMENT_COUNT,
    ));
    for pad in response_pads {
        response_pad_elements.extend([
            pad.low[recipient_position],
            pad.high[recipient_position],
            pad.output_zero[recipient_position],
        ]);
    }
    let packed_response_pads = Zeroizing::new(pack_field_elements(&response_pad_elements));
    let (token_a_evaluation, token_b_evaluation) =
        receiver_token_setup.evaluation_for_garbler(recipient_position);

    let mut tuple = CanonicalTuple::new(
        PREPARATION_PAYLOAD_SCHEMA_IDENTIFIER,
        PRIVATE_PAYLOAD_SCHEMA_VERSION,
        vec![
            CanonicalItem::fixed_bytes(&*packed_candidate)?,
            CanonicalItem::fixed_bytes(&*packed_challenge)?,
            CanonicalItem::fixed_bytes(&*packed_response_pads)?,
            CanonicalItem::fixed_bytes(token_a_evaluation.as_bytes())?,
            CanonicalItem::fixed_bytes(token_b_evaluation.as_bytes())?,
        ],
    );
    let encoded = tuple.encode();
    tuple.zeroize();
    Ok(Zeroizing::new(encoded?))
}

pub(crate) fn decode_preparation_mailbox_payload(
    bytes: &[u8],
) -> ProtocolResult<PreparationMailboxPayload> {
    let mut tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())?;
    let decoded = decode_preparation_tuple(&tuple);
    tuple.zeroize();
    decoded
}

fn decode_preparation_tuple(tuple: &CanonicalTuple) -> ProtocolResult<PreparationMailboxPayload> {
    require_tuple(
        tuple,
        PREPARATION_PAYLOAD_SCHEMA_IDENTIFIER,
        PRIVATE_PAYLOAD_SCHEMA_VERSION,
        5,
    )?;
    let mut candidate_elements = unpack_field_elements(
        read_fixed_byte_slice(&tuple.items[0], PACKED_PREPARATION_CANDIDATE_BYTE_LENGTH)?,
        PREPARATION_CANDIDATE_FIELD_ELEMENT_COUNT,
    )?;
    let recipient_candidate = PreparationRecipientCoordinate {
        low: candidate_elements[0],
        high: candidate_elements[1],
        output_zero: candidate_elements[2],
    };
    candidate_elements.zeroize();

    let challenge_coordinates = unpack_field_elements(
        read_fixed_byte_slice(&tuple.items[1], PACKED_CHALLENGE_BYTE_LENGTH)?,
        DIRECT_CHECK_REPETITION_COUNT,
    )?;
    let mut response_pad_elements = unpack_field_elements(
        read_fixed_byte_slice(&tuple.items[2], PACKED_PREPARATION_RESPONSE_PAD_BYTE_LENGTH)?,
        PREPARATION_RESPONSE_PAD_FIELD_ELEMENT_COUNT,
    )?;
    let response_pad_coordinates = response_pad_elements
        .chunks_exact(PREPARATION_CANDIDATE_FIELD_ELEMENT_COUNT)
        .map(|coordinates| PreparationRecipientCoordinate {
            low: coordinates[0],
            high: coordinates[1],
            output_zero: coordinates[2],
        })
        .collect();
    response_pad_elements.zeroize();

    Ok(PreparationMailboxPayload {
        recipient_candidate,
        challenge_coordinates,
        response_pad_coordinates,
        token_a_evaluation: SecretToken::from_bytes(read_fixed_bytes(&tuple.items[3])?),
        token_b_evaluation: SecretToken::from_bytes(read_fixed_bytes(&tuple.items[4])?),
    })
}

pub(crate) fn encode_source_mailbox_payload(
    recipient_position: usize,
    source: Option<&SourceCodewordCoordinates>,
    challenge: &ChallengeDealerCoordinates,
    response_pads: &[SourceCodewordCoordinates],
) -> ProtocolResult<Zeroizing<Vec<u8>>> {
    require_recipient_position(recipient_position)?;
    if response_pads.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source mailbox has the wrong response-pad count",
        ));
    }

    let packed_challenge = Zeroizing::new(pack_field_elements(
        challenge.recipient_block(recipient_position),
    ));
    let response_pad_elements = response_pads
        .iter()
        .map(|pad| pad.coordinates()[recipient_position])
        .collect::<Vec<_>>();
    let response_pad_elements = Zeroizing::new(response_pad_elements);
    let packed_response_pads = Zeroizing::new(pack_field_elements(&response_pad_elements));

    let (schema_identifier, items) = match source {
        Some(source) => {
            let packed_source = Zeroizing::new(pack_field_elements(&[
                source.coordinates()[recipient_position]
            ]));
            (
                SOURCE_SUBMIT_PAYLOAD_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::fixed_bytes(&*packed_source)?,
                    CanonicalItem::fixed_bytes(&*packed_challenge)?,
                    CanonicalItem::fixed_bytes(&*packed_response_pads)?,
                ],
            )
        }
        None => (
            SOURCE_ABSENT_PAYLOAD_SCHEMA_IDENTIFIER,
            vec![
                CanonicalItem::fixed_bytes(&*packed_challenge)?,
                CanonicalItem::fixed_bytes(&*packed_response_pads)?,
            ],
        ),
    };
    let mut tuple = CanonicalTuple::new(schema_identifier, PRIVATE_PAYLOAD_SCHEMA_VERSION, items);
    let encoded = tuple.encode();
    tuple.zeroize();
    Ok(Zeroizing::new(encoded?))
}

pub(crate) fn decode_source_mailbox_payload(bytes: &[u8]) -> ProtocolResult<SourceMailboxPayload> {
    let mut tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())?;
    let decoded = decode_source_tuple(&tuple);
    tuple.zeroize();
    decoded
}

fn decode_source_tuple(tuple: &CanonicalTuple) -> ProtocolResult<SourceMailboxPayload> {
    let (source_coordinate, challenge_index, response_pad_index) = match tuple.schema_identifier {
        SOURCE_SUBMIT_PAYLOAD_SCHEMA_IDENTIFIER => {
            require_tuple(
                tuple,
                SOURCE_SUBMIT_PAYLOAD_SCHEMA_IDENTIFIER,
                PRIVATE_PAYLOAD_SCHEMA_VERSION,
                3,
            )?;
            let mut source_elements = unpack_field_elements(
                read_fixed_byte_slice(&tuple.items[0], PACKED_SOURCE_COORDINATE_BYTE_LENGTH)?,
                1,
            )?;
            let source_coordinate = source_elements[0];
            source_elements.zeroize();
            (Some(source_coordinate), 1, 2)
        }
        SOURCE_ABSENT_PAYLOAD_SCHEMA_IDENTIFIER => {
            require_tuple(
                tuple,
                SOURCE_ABSENT_PAYLOAD_SCHEMA_IDENTIFIER,
                PRIVATE_PAYLOAD_SCHEMA_VERSION,
                2,
            )?;
            (None, 0, 1)
        }
        _ => {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "source mailbox payload has the wrong schema",
            ));
        }
    };
    let challenge_coordinates = unpack_field_elements(
        read_fixed_byte_slice(&tuple.items[challenge_index], PACKED_CHALLENGE_BYTE_LENGTH)?,
        DIRECT_CHECK_REPETITION_COUNT,
    )?;
    let response_pad_coordinates = unpack_field_elements(
        read_fixed_byte_slice(
            &tuple.items[response_pad_index],
            PACKED_SOURCE_RESPONSE_PAD_BYTE_LENGTH,
        )?,
        DIRECT_CHECK_REPETITION_COUNT,
    )?;
    Ok(SourceMailboxPayload {
        source_coordinate,
        challenge_coordinates,
        response_pad_coordinates,
    })
}

fn require_recipient_position(recipient_position: usize) -> ProtocolResult<()> {
    if recipient_position >= PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "private payload recipient is outside the roster",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        challenge::{CHALLENGE_DEALER_RANDOM_BYTE_LENGTH, create_challenge_dealer_coordinates},
        sharing::{
            PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH, PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
            SOURCE_CODEWORD_RANDOM_BYTE_LENGTH, SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
            create_preparation_candidate, create_preparation_response_pads, create_source_codeword,
            create_source_response_pads,
        },
        token::{
            RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH, TOKEN_BYTE_LENGTH, create_receiver_token_setup,
        },
    };

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

    fn token_setup() -> ReceiverTokenSetup {
        let mut bytes = deterministic_bytes(0x4c21_a057, RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH);
        bytes[10 * TOKEN_BYTE_LENGTH] |= 1;
        create_receiver_token_setup(&bytes).expect("token setup has a nonzero difference")
    }

    #[test]
    fn preparation_payload_round_trips_the_exact_recipient_projection() {
        let recipient_position = 7;
        let candidate = create_preparation_candidate(&deterministic_bytes(
            0x1112,
            PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH,
        ))
        .unwrap();
        let challenge = create_challenge_dealer_coordinates(&deterministic_bytes(
            0x2223,
            CHALLENGE_DEALER_RANDOM_BYTE_LENGTH,
        ))
        .unwrap();
        let response_pads = create_preparation_response_pads(&deterministic_bytes(
            0x3334,
            PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
        ))
        .unwrap();
        let setup = token_setup();

        let encoded = encode_preparation_mailbox_payload(
            recipient_position,
            &candidate,
            &challenge,
            &response_pads,
            &setup,
        )
        .unwrap();
        let decoded = decode_preparation_mailbox_payload(&encoded).unwrap();
        assert_eq!(
            decoded.recipient_candidate().low,
            candidate.low[recipient_position]
        );
        assert_eq!(
            decoded.recipient_candidate().high,
            candidate.high[recipient_position]
        );
        assert_eq!(
            decoded.recipient_candidate().output_zero,
            candidate.output_zero[recipient_position]
        );
        assert_eq!(
            decoded.challenge_coordinates(),
            challenge.recipient_block(recipient_position)
        );
        assert_eq!(
            decoded.response_pad_coordinates().len(),
            DIRECT_CHECK_REPETITION_COUNT
        );
        for (decoded_pad, source_pad) in decoded
            .response_pad_coordinates()
            .iter()
            .zip(&response_pads)
        {
            assert_eq!(decoded_pad.low, source_pad.low[recipient_position]);
            assert_eq!(decoded_pad.high, source_pad.high[recipient_position]);
            assert_eq!(
                decoded_pad.output_zero,
                source_pad.output_zero[recipient_position]
            );
        }
        let (expected_a, expected_b) = setup.evaluation_for_garbler(recipient_position);
        let (decoded_a, decoded_b) = decoded.token_evaluations();
        assert_eq!(decoded_a, expected_a);
        assert_eq!(decoded_b, expected_b);
    }

    #[test]
    fn source_submit_and_absent_payloads_are_distinct_and_exact() {
        let recipient_position = 4;
        let source = create_source_codeword(
            true,
            &deterministic_bytes(0x5152, SOURCE_CODEWORD_RANDOM_BYTE_LENGTH),
        )
        .unwrap();
        let challenge = create_challenge_dealer_coordinates(&deterministic_bytes(
            0x6162,
            CHALLENGE_DEALER_RANDOM_BYTE_LENGTH,
        ))
        .unwrap();
        let response_pads = create_source_response_pads(&deterministic_bytes(
            0x7172,
            SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
        ))
        .unwrap();

        let submitted = encode_source_mailbox_payload(
            recipient_position,
            Some(&source),
            &challenge,
            &response_pads,
        )
        .unwrap();
        let absent =
            encode_source_mailbox_payload(recipient_position, None, &challenge, &response_pads)
                .unwrap();
        assert_ne!(&*submitted, &*absent);

        let decoded_submit = decode_source_mailbox_payload(&submitted).unwrap();
        assert_eq!(
            decoded_submit.source_coordinate(),
            Some(source.coordinates()[recipient_position])
        );
        assert_eq!(
            decoded_submit.challenge_coordinates(),
            challenge.recipient_block(recipient_position)
        );
        assert_eq!(
            decoded_submit.response_pad_coordinates().len(),
            DIRECT_CHECK_REPETITION_COUNT
        );

        let decoded_absent = decode_source_mailbox_payload(&absent).unwrap();
        assert_eq!(decoded_absent.source_coordinate(), None);
        assert_eq!(
            decoded_absent.response_pad_coordinates(),
            response_pads
                .iter()
                .map(|pad| pad.coordinates()[recipient_position])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn payload_decoders_refuse_wrong_lengths_noncanonical_nibbles_and_schema_confusion() {
        let challenge =
            create_challenge_dealer_coordinates(&vec![0x31; CHALLENGE_DEALER_RANDOM_BYTE_LENGTH])
                .unwrap();
        let response_pads =
            create_source_response_pads(&vec![0x42; SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH])
                .unwrap();
        assert!(encode_source_mailbox_payload(10, None, &challenge, &response_pads).is_err());
        assert!(encode_source_mailbox_payload(0, None, &challenge, &response_pads[..383]).is_err());

        let absent = encode_source_mailbox_payload(0, None, &challenge, &response_pads).unwrap();
        assert!(decode_preparation_mailbox_payload(&absent).is_err());

        let source =
            create_source_codeword(true, &[0x53; SOURCE_CODEWORD_RANDOM_BYTE_LENGTH]).unwrap();
        let encoded =
            encode_source_mailbox_payload(0, Some(&source), &challenge, &response_pads).unwrap();

        let mut tuple =
            CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).unwrap();
        let mut malformed_source = tuple.items[0].canonical_bytes().to_vec();
        malformed_source[0] ^= 0xf0;
        tuple.items[0] = CanonicalItem::fixed_bytes(malformed_source).unwrap();
        let malformed = tuple.encode().unwrap();
        tuple.zeroize();
        assert_eq!(
            decode_source_mailbox_payload(&malformed)
                .expect_err("noncanonical packed field nibble refuses")
                .reason,
            RefusalReason::MalformedEncoding
        );
    }
}
