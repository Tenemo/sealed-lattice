use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector::{
        AuthenticatedKeyShareVectorDescriptor, AuthenticatedKeyShareVectorDescriptorBuilder,
    },
    authenticated_key_share_vector_local_check::{
        AuthenticatedKeyShareVectorLocalCheck,
        create_authenticated_key_share_vector_acknowledgement_body,
    },
    authenticated_key_share_vector_manifest::{
        AuthenticatedKeyShareVectorAcknowledgementBody, AuthenticatedKeyShareVectorManifest,
    },
};

const HONEST_FIELD_MARKER: u8 = 0x35;
const INCONSISTENT_FIELD_MARKER: u8 = 0x46;

#[test]
fn streamed_local_check_requires_every_bound_chunk_before_acknowledgement() {
    let circuit = circuit(9, 2, 1);
    let context = preparation_context(0x21, &circuit);
    let holder_commitment_root = hash(0x32);
    let published_basis_descriptors = (0..4)
        .map(|sender_position| {
            descriptor(
                context,
                &circuit,
                holder_commitment_root,
                sender_position,
                HONEST_FIELD_MARKER,
                None,
            )
        })
        .collect::<Vec<_>>();
    let manifest = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &published_basis_descriptors,
    )
    .unwrap();
    let local_descriptor = descriptor(
        context,
        &circuit,
        holder_commitment_root,
        8,
        HONEST_FIELD_MARKER,
        None,
    );

    let incomplete_check = AuthenticatedKeyShareVectorLocalCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &published_basis_descriptors,
        &local_descriptor,
        8,
    )
    .unwrap();
    assert!(matches!(
        incomplete_check.finish(),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckIncomplete {
                checked_chunk_count: 0,
                checked_field_count: 0,
                ..
            }
        )
    ));

    let mut payload_mutation_check = AuthenticatedKeyShareVectorLocalCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &published_basis_descriptors,
        &local_descriptor,
        8,
    )
    .unwrap();
    let honest_first_payload = payload_for_descriptor(
        &published_basis_descriptors[0],
        0,
        HONEST_FIELD_MARKER,
        None,
    );
    let mut mutated_first_payload = honest_first_payload.clone();
    mutated_first_payload[0] ^= 1;
    assert!(matches!(
        payload_mutation_check.verify_next_payload_chunks(
            &[
                mutated_first_payload.as_slice(),
                honest_first_payload.as_slice(),
                honest_first_payload.as_slice(),
                honest_first_payload.as_slice(),
            ],
            &honest_first_payload,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorPayloadDigestMismatch)
    ));

    let inconsistent_local_descriptor = descriptor(
        context,
        &circuit,
        holder_commitment_root,
        8,
        HONEST_FIELD_MARKER,
        Some(INCONSISTENT_FIELD_MARKER),
    );
    let mut inconsistent_local_check = AuthenticatedKeyShareVectorLocalCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &published_basis_descriptors,
        &inconsistent_local_descriptor,
        8,
    )
    .unwrap();
    let inconsistent_local_payload = payload_for_descriptor(
        &inconsistent_local_descriptor,
        0,
        HONEST_FIELD_MARKER,
        Some(INCONSISTENT_FIELD_MARKER),
    );
    assert!(matches!(
        inconsistent_local_check.verify_next_payload_chunks(
            &[
                honest_first_payload.as_slice(),
                honest_first_payload.as_slice(),
                honest_first_payload.as_slice(),
                honest_first_payload.as_slice(),
            ],
            &inconsistent_local_payload,
        ),
        Err(TallyPreparationError::InconsistentShare { roster_position: 8 })
    ));

    let wrong_sender_descriptor = descriptor(
        context,
        &circuit,
        holder_commitment_root,
        7,
        HONEST_FIELD_MARKER,
        None,
    );
    assert!(matches!(
        AuthenticatedKeyShareVectorLocalCheck::begin(
            context,
            &circuit,
            holder_commitment_root,
            &manifest,
            &published_basis_descriptors,
            &wrong_sender_descriptor,
            8,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorLocalDescriptorMismatch)
    ));

    let mut local_check = AuthenticatedKeyShareVectorLocalCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &published_basis_descriptors,
        &local_descriptor,
        8,
    )
    .unwrap();
    let expected_reconstructed_field = BinaryFieldElement256::from_canonical_bytes(
        &[HONEST_FIELD_MARKER; BinaryFieldElement256::CANONICAL_BYTE_LENGTH],
    )
    .unwrap();
    let mut expected_first_field_index = 0_u64;
    for chunk_index in 0..local_descriptor.chunk_count() {
        let payload =
            payload_for_descriptor(&local_descriptor, chunk_index, HONEST_FIELD_MARKER, None);
        let checked_chunk = local_check
            .verify_next_payload_chunks(
                &[
                    payload.as_slice(),
                    payload.as_slice(),
                    payload.as_slice(),
                    payload.as_slice(),
                ],
                &payload,
            )
            .unwrap();
        assert_eq!(
            checked_chunk.first_field_index(),
            expected_first_field_index
        );
        assert!(
            checked_chunk
                .reconstructed_fields()
                .iter()
                .all(|field| *field == expected_reconstructed_field)
        );
        expected_first_field_index += checked_chunk.reconstructed_fields().len() as u64;
    }
    assert_eq!(expected_first_field_index, manifest.total_field_count());
    let final_payload = payload_for_descriptor(
        &local_descriptor,
        local_descriptor.chunk_count() - 1,
        HONEST_FIELD_MARKER,
        None,
    );
    assert!(matches!(
        local_check.verify_next_payload_chunks(
            &[
                final_payload.as_slice(),
                final_payload.as_slice(),
                final_payload.as_slice(),
                final_payload.as_slice(),
            ],
            &final_payload,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckAlreadyComplete)
    ));
    let checked_share_vector = local_check.finish().unwrap();
    let acknowledgement_body =
        create_authenticated_key_share_vector_acknowledgement_body(checked_share_vector, &manifest)
            .unwrap();
    assert_eq!(
        AuthenticatedKeyShareVectorAcknowledgementBody::from_canonical_bytes(
            &acknowledgement_body.canonical_bytes(),
        )
        .unwrap(),
        acknowledgement_body
    );
}

#[test]
fn local_check_refuses_profiles_whose_derived_threshold_is_not_four() {
    let circuit = circuit(12, 2, 1);
    let context = preparation_context(0x22, &circuit);
    let holder_commitment_root = hash(0x33);
    let published_basis_descriptors = (0..5)
        .map(|sender_position| {
            descriptor(
                context,
                &circuit,
                holder_commitment_root,
                sender_position,
                HONEST_FIELD_MARKER,
                None,
            )
        })
        .collect::<Vec<_>>();
    let manifest = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &published_basis_descriptors,
    )
    .unwrap();
    let local_descriptor = descriptor(
        context,
        &circuit,
        holder_commitment_root,
        11,
        HONEST_FIELD_MARKER,
        None,
    );

    assert!(matches!(
        AuthenticatedKeyShareVectorLocalCheck::begin(
            context,
            &circuit,
            holder_commitment_root,
            &manifest,
            &published_basis_descriptors,
            &local_descriptor,
            11,
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyReleaseProfileMismatch {
                participant_count: 12,
                derived_reconstruction_threshold: 5,
                supported_reconstruction_threshold: 4,
            }
        )
    ));
}

fn descriptor(
    context: TallyPreparationContext,
    circuit: &CompiledTallyCircuit,
    holder_commitment_root: Hash512,
    sender_position: u16,
    field_marker: u8,
    first_field_override: Option<u8>,
) -> AuthenticatedKeyShareVectorDescriptor {
    let mut builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
        context,
        circuit,
        holder_commitment_root,
        sender_position,
    )
    .unwrap();
    for chunk_index in 0..builder.chunk_count() {
        let payload_byte_length =
            usize::try_from(builder.expected_next_payload_byte_length().unwrap()).unwrap();
        let mut payload = vec![field_marker; payload_byte_length];
        if chunk_index == 0
            && let Some(first_field_override) = first_field_override
        {
            payload[..BinaryFieldElement256::CANONICAL_BYTE_LENGTH].fill(first_field_override);
        }
        builder.absorb_next_payload_chunk(&payload).unwrap();
    }
    builder.finish().unwrap()
}

fn payload_for_descriptor(
    descriptor: &AuthenticatedKeyShareVectorDescriptor,
    chunk_index: u64,
    field_marker: u8,
    first_field_override: Option<u8>,
) -> Vec<u8> {
    let payload_byte_length = if chunk_index + 1 == descriptor.chunk_count() {
        descriptor.final_chunk_payload_byte_length()
    } else {
        FOUNDATION_PROFILE.stream_chunk_byte_length as u64
    };
    let mut payload = vec![field_marker; usize::try_from(payload_byte_length).unwrap()];
    if chunk_index == 0
        && let Some(first_field_override) = first_field_override
    {
        payload[..BinaryFieldElement256::CANONICAL_BYTE_LENGTH].fill(first_field_override);
    }
    payload
}

fn preparation_context(marker: u8, circuit: &CompiledTallyCircuit) -> TallyPreparationContext {
    TallyPreparationContext::new(
        hash(marker),
        hash(marker.wrapping_add(1)),
        [marker.wrapping_add(2); 32],
        circuit,
    )
    .unwrap()
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
}

fn circuit(participant_count: u16, option_count: u16, top_count: u16) -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
    )
    .unwrap()
}
