use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogInclusionProof320,
        PseudorandomZeroSharingSeedCatalogLayout320,
    },
    pseudorandom_zero_sharing_seed_catalog_source_kernel_320::run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320,
    pseudorandom_zero_sharing_seed_delivery_320::PseudorandomZeroSharingSeedDeliveryLayout320,
    pseudorandom_zero_sharing_subset_seed_320::PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
};

const REQUEST_MAGIC: &[u8; 4] = b"SLSK";
const RESPONSE_MAGIC: &[u8; 4] = b"SLSR";
const CODEC_VERSION: u16 = 1;
const PRODUCE_CATALOG_OPERATION: u8 = 1;
const VALIDATE_CATALOG_OPERATION: u8 = 2;
const PRODUCE_DELIVERY_OPERATION: u8 = 3;
const VALIDATE_DELIVERY_OPERATION: u8 = 4;
const CATALOG_STATUS: u8 = 1;
const DELIVERY_STATUS: u8 = 2;
const VALIDATION_STATUS: u8 = 3;
const FAILURE_STATUS: u8 = 0;
const COMPLETION_ROOT_BODY_BYTE_LENGTH: usize = 522;
const COMPLETION_SOURCE_CONTRIBUTION_BYTE_LENGTH: usize = 40;
const COMPLETION_COMMITMENT_SALT_BYTE_LENGTH: usize = 64;
const RESPONSE_HEADER_BYTE_LENGTH: usize = 7;

#[test]
fn exact_completion_source_catalog_and_delivery_round_trip() {
    let context = completion_context(0x51);
    let parameter_identity = Hash512::from_bytes([0x61; Hash512::BYTE_LENGTH]);
    let contributor_position = 3;
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        context,
        contributor_position,
    )
    .unwrap();
    let produce_catalog_request = request_prefix(
        PRODUCE_CATALOG_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    assert_eq!(produce_catalog_request.len(), 10_949);

    let catalog_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&produce_catalog_request);
    require_status(&catalog_response, CATALOG_STATUS);
    assert_eq!(catalog_response.len(), 103_829);
    let catalog_payload = &catalog_response[RESPONSE_HEADER_BYTE_LENGTH..];
    assert_eq!(catalog_payload.len(), 103_822);
    assert_eq!(
        &catalog_payload[..Hash512::BYTE_LENGTH],
        layout.identity().as_bytes()
    );

    let mut validate_catalog_request = request_prefix(
        VALIDATE_CATALOG_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    validate_catalog_request.extend_from_slice(catalog_payload);
    let validation_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&validate_catalog_request);
    require_status(&validation_response, VALIDATION_STATUS);
    assert_eq!(validation_response.len(), RESPONSE_HEADER_BYTE_LENGTH);

    let recipient_position = 7_u16;
    let mut produce_delivery_request = request_prefix(
        PRODUCE_DELIVERY_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    produce_delivery_request.extend_from_slice(catalog_payload);
    produce_delivery_request.extend_from_slice(&recipient_position.to_le_bytes());
    assert_eq!(produce_delivery_request.len(), 114_773);
    let delivery_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&produce_delivery_request);
    require_status(&delivery_response, DELIVERY_STATUS);
    assert_eq!(delivery_response.len(), 62_599);
    assert_eq!(
        &delivery_response[RESPONSE_HEADER_BYTE_LENGTH..RESPONSE_HEADER_BYTE_LENGTH + 2],
        &recipient_position.to_le_bytes()
    );
    let delivery_payload = &delivery_response[RESPONSE_HEADER_BYTE_LENGTH + 2..];
    assert_eq!(delivery_payload.len(), 62_590);

    let mut validate_delivery_request = request_prefix(
        VALIDATE_DELIVERY_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    validate_delivery_request.extend_from_slice(catalog_payload);
    validate_delivery_request.extend_from_slice(&recipient_position.to_le_bytes());
    validate_delivery_request.extend_from_slice(delivery_payload);
    assert_eq!(validate_delivery_request.len(), 177_363);
    let validation_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&validate_delivery_request);
    require_status(&validation_response, VALIDATION_STATUS);
}

#[test]
fn source_kernel_refuses_context_geometry_catalog_delivery_and_carrier_mutations() {
    let context = completion_context(0x73);
    let parameter_identity = Hash512::from_bytes([0x81; Hash512::BYTE_LENGTH]);
    let contributor_position = 3;
    let catalog_request = request_prefix(
        PRODUCE_CATALOG_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    let catalog_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&catalog_request);
    require_status(&catalog_response, CATALOG_STATUS);
    let catalog_payload = &catalog_response[RESPONSE_HEADER_BYTE_LENGTH..];

    let preparation_context_identity_offset = REQUEST_MAGIC.len()
        + 2
        + 1
        + 4
        + context.canonical_bytes().len()
        + 3 * Hash512::BYTE_LENGTH;
    let leaf_count_offset = REQUEST_MAGIC.len()
        + 2
        + 1
        + 4
        + context.canonical_bytes().len()
        + 6 * Hash512::BYTE_LENGTH
        + 3 * 2;
    for mutation_offset in [0, preparation_context_identity_offset, leaf_count_offset] {
        let mut mutated = catalog_request.clone();
        mutated[mutation_offset] ^= 0x01;
        require_status(
            &run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&mutated),
            FAILURE_STATUS,
        );
    }
    let mut alternate_source = catalog_request.clone();
    let last_position = alternate_source.len() - 1;
    alternate_source[last_position] ^= 0x01;
    let alternate_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&alternate_source);
    require_status(&alternate_response, CATALOG_STATUS);
    assert_ne!(alternate_response.as_slice(), catalog_response.as_slice());
    let mut truncated = catalog_request.clone();
    truncated.pop();
    require_status(
        &run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&truncated),
        FAILURE_STATUS,
    );
    let mut extra = catalog_request.clone();
    extra.push(0);
    require_status(
        &run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&extra),
        FAILURE_STATUS,
    );

    let mut validate_catalog_request = request_prefix(
        VALIDATE_CATALOG_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    validate_catalog_request.extend_from_slice(catalog_payload);
    for catalog_mutation_offset in [
        validate_catalog_request.len() - catalog_payload.len(),
        validate_catalog_request.len() - 1,
    ] {
        let mut mutated = validate_catalog_request.clone();
        mutated[catalog_mutation_offset] ^= 0x80;
        require_status(
            &run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&mutated),
            FAILURE_STATUS,
        );
    }

    let recipient_position = 7_u16;
    let mut produce_delivery_request = request_prefix(
        PRODUCE_DELIVERY_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    produce_delivery_request.extend_from_slice(catalog_payload);
    produce_delivery_request.extend_from_slice(&recipient_position.to_le_bytes());
    let delivery_response =
        run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&produce_delivery_request);
    require_status(&delivery_response, DELIVERY_STATUS);
    let delivery_payload = &delivery_response[RESPONSE_HEADER_BYTE_LENGTH + 2..];

    let mut wrong_recipient_request = produce_delivery_request.clone();
    let recipient_offset = wrong_recipient_request.len() - 2;
    wrong_recipient_request[recipient_offset..]
        .copy_from_slice(&contributor_position.to_le_bytes());
    require_status(
        &run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&wrong_recipient_request),
        FAILURE_STATUS,
    );

    let mut validate_delivery_request = request_prefix(
        VALIDATE_DELIVERY_OPERATION,
        parameter_identity,
        context,
        contributor_position,
    );
    validate_delivery_request.extend_from_slice(catalog_payload);
    validate_delivery_request.extend_from_slice(&recipient_position.to_le_bytes());
    validate_delivery_request.extend_from_slice(delivery_payload);
    let last_position = validate_delivery_request.len() - 1;
    validate_delivery_request[last_position] ^= 0x01;
    require_status(
        &run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(&validate_delivery_request),
        FAILURE_STATUS,
    );
}

fn request_prefix(
    operation: u8,
    parameter_identity: Hash512,
    context: TallyPreparationContext,
    contributor_position: u16,
) -> Vec<u8> {
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        context,
        contributor_position,
    )
    .unwrap();
    let context_bytes = context.canonical_bytes();
    let coordinates = layout.coordinates().unwrap().collect::<Vec<_>>();
    let recipient_positions = (0..context.participant_count())
        .filter(|position| *position != contributor_position)
        .collect::<Vec<_>>();
    let proof_byte_length =
        PseudorandomZeroSharingSeedCatalogInclusionProof320::canonical_byte_length_for_layout(
            layout,
        )
        .unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(REQUEST_MAGIC);
    request.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    request.push(operation);
    request.extend_from_slice(&u32::try_from(context_bytes.len()).unwrap().to_le_bytes());
    request.extend_from_slice(&context_bytes);
    request.extend_from_slice(parameter_identity.as_bytes());
    request.extend_from_slice(context.roster_hash().as_bytes());
    request.extend_from_slice(context.action_context_hash().as_bytes());
    request.extend_from_slice(context.identity().as_bytes());
    request.extend_from_slice(layout.compiler_identity().as_bytes());
    request.extend_from_slice(&[0xa5; Hash512::BYTE_LENGTH]);
    request.extend_from_slice(&0_u16.to_le_bytes());
    request.extend_from_slice(&context.participant_count().to_le_bytes());
    request.extend_from_slice(&contributor_position.to_le_bytes());
    request.extend_from_slice(&u32::try_from(coordinates.len()).unwrap().to_le_bytes());
    request.extend_from_slice(
        &u32::try_from(COMPLETION_SOURCE_CONTRIBUTION_BYTE_LENGTH)
            .unwrap()
            .to_le_bytes(),
    );
    request.extend_from_slice(
        &u32::try_from(COMPLETION_COMMITMENT_SALT_BYTE_LENGTH)
            .unwrap()
            .to_le_bytes(),
    );
    request.extend_from_slice(
        &u32::try_from(COMPLETION_ROOT_BODY_BYTE_LENGTH)
            .unwrap()
            .to_le_bytes(),
    );
    request.extend_from_slice(&u32::try_from(proof_byte_length).unwrap().to_le_bytes());
    request.extend_from_slice(
        &u16::try_from(recipient_positions.len())
            .unwrap()
            .to_le_bytes(),
    );
    for coordinate in &coordinates {
        let byte_length = match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(_) => {
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair { .. } => {
                PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
                COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH
            }
        };
        request.extend_from_slice(&u32::try_from(byte_length).unwrap().to_le_bytes());
    }
    for recipient_position in recipient_positions {
        let byte_length =
            PseudorandomZeroSharingSeedDeliveryLayout320::derive(layout, recipient_position)
                .unwrap()
                .payload_byte_length();
        request.extend_from_slice(&u32::try_from(byte_length).unwrap().to_le_bytes());
    }
    for leaf_ordinal in 0..coordinates.len() {
        request.extend(
            (0..COMPLETION_SOURCE_CONTRIBUTION_BYTE_LENGTH).map(|byte_position| {
                (leaf_ordinal as u8)
                    .wrapping_mul(17)
                    .wrapping_add(byte_position as u8)
            }),
        );
        request.extend(
            (0..COMPLETION_COMMITMENT_SALT_BYTE_LENGTH).map(|byte_position| {
                (leaf_ordinal as u8)
                    .wrapping_mul(29)
                    .wrapping_add(byte_position as u8)
                    .wrapping_add(1)
            }),
        );
    }
    request
}

fn require_status(response: &[u8], expected_status: u8) {
    assert!(response.len() >= RESPONSE_HEADER_BYTE_LENGTH);
    assert_eq!(&response[..RESPONSE_MAGIC.len()], RESPONSE_MAGIC);
    assert_eq!(
        u16::from_le_bytes(response[4..6].try_into().unwrap()),
        CODEC_VERSION
    );
    assert_eq!(response[6], expected_status);
}

fn completion_context(attempt_byte: u8) -> TallyPreparationContext {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([0x91; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x93; Hash512::BYTE_LENGTH]),
        [attempt_byte; 32],
        &circuit,
    )
    .unwrap()
}
