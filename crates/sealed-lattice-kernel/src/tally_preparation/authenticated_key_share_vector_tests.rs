use crate::{
    encoding::encode_varuint,
    foundation::{FOUNDATION_PROFILE, Hash512},
    hashing::{framed_hash512_preimage, to_hex},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector::{
        AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION,
        AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC, AuthenticatedKeyFieldRole,
        AuthenticatedKeyShareVectorDescriptor, AuthenticatedKeyShareVectorDescriptorBuilder,
        authenticated_key_field_coordinates, authenticated_key_share_vector_compiler_identity,
        authenticated_key_share_vector_descriptor_canonical_byte_length,
        authenticated_key_share_vector_payload_chunk_preimage_byte_length,
        compiler_identity_from_source_for_test,
    },
    preparation_holder_record_catalog::{
        PreparationHolderRecordCatalog, PreparationHolderRecordClass,
        PreparationHolderRecordInventory,
    },
};

const COMPLETION_VERIFICATION_KEY_FIELD_COUNT: u64 = 1_443_180;
const COMPLETION_SHARE_VECTOR_PAYLOAD_BYTE_LENGTH: u64 = 46_181_760;
const COMPLETION_SHARE_VECTOR_CHUNK_COUNT: u64 = 45;
const COMPLETION_FINAL_CHUNK_PAYLOAD_BYTE_LENGTH: u64 = 44_416;
const COMPLETION_DESCRIPTOR_BYTE_LENGTH: u64 = 3_261;

#[test]
fn completion_descriptor_streams_exact_payload_geometry_and_hash_matched_fields() {
    let circuit = completion_profile_circuit();
    let context = preparation_context(0x31, &circuit);
    let holder_commitment_root = hash(0x42);
    let mut builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
        context,
        &circuit,
        holder_commitment_root,
        2,
    )
    .unwrap();

    assert_eq!(builder.chunk_count(), COMPLETION_SHARE_VECTOR_CHUNK_COUNT);
    let complete_payload = vec![0x53; FOUNDATION_PROFILE.stream_chunk_byte_length];
    for _ in 0..(COMPLETION_SHARE_VECTOR_CHUNK_COUNT - 1) {
        assert_eq!(
            builder.expected_next_payload_byte_length().unwrap(),
            FOUNDATION_PROFILE.stream_chunk_byte_length as u64
        );
        builder
            .absorb_next_payload_chunk(&complete_payload)
            .unwrap();
    }
    let final_payload =
        vec![0x64; usize::try_from(COMPLETION_FINAL_CHUNK_PAYLOAD_BYTE_LENGTH).unwrap()];
    assert_eq!(
        builder.expected_next_payload_byte_length().unwrap(),
        COMPLETION_FINAL_CHUNK_PAYLOAD_BYTE_LENGTH
    );
    builder.absorb_next_payload_chunk(&final_payload).unwrap();
    assert_eq!(
        builder.expected_next_payload_byte_length(),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorChunkOutOfRange {
                chunk_index: COMPLETION_SHARE_VECTOR_CHUNK_COUNT,
                chunk_count: COMPLETION_SHARE_VECTOR_CHUNK_COUNT,
            }
        )
    );

    let descriptor = builder.finish().unwrap();
    assert_eq!(descriptor.participant_count(), 10);
    assert_eq!(descriptor.sender_position(), 2);
    assert_eq!(
        descriptor.total_field_count(),
        COMPLETION_VERIFICATION_KEY_FIELD_COUNT
    );
    assert_eq!(
        descriptor.total_payload_byte_length(),
        COMPLETION_SHARE_VECTOR_PAYLOAD_BYTE_LENGTH
    );
    assert_eq!(
        descriptor.final_chunk_payload_byte_length(),
        COMPLETION_FINAL_CHUNK_PAYLOAD_BYTE_LENGTH
    );
    assert_eq!(
        descriptor.canonical_bytes().len() as u64,
        COMPLETION_DESCRIPTOR_BYTE_LENGTH
    );
    assert_eq!(
        authenticated_key_share_vector_descriptor_canonical_byte_length(
            10,
            2,
            COMPLETION_VERIFICATION_KEY_FIELD_COUNT,
        )
        .unwrap(),
        COMPLETION_DESCRIPTOR_BYTE_LENGTH
    );
    assert_eq!(
        authenticated_key_share_vector_payload_chunk_preimage_byte_length(
            COMPLETION_VERIFICATION_KEY_FIELD_COUNT,
            0,
        )
        .unwrap(),
        1_048_982
    );
    assert_eq!(
        authenticated_key_share_vector_payload_chunk_preimage_byte_length(
            COMPLETION_VERIFICATION_KEY_FIELD_COUNT,
            COMPLETION_SHARE_VECTOR_CHUNK_COUNT - 1,
        )
        .unwrap(),
        44_822
    );
    let four_hashes = [[0_u8; 64]; 4];
    let two_unsigned16_values = [[0_u8; 2]; 2];
    let six_unsigned64_values = [[0_u8; 8]; 6];
    let independent_full_chunk_preimage = framed_hash512_preimage(
        "sealed-lattice/authenticated-key-share-vector-payload-chunk/v1",
        &[
            &four_hashes[0],
            &four_hashes[1],
            &four_hashes[2],
            &four_hashes[3],
            &two_unsigned16_values[0],
            &two_unsigned16_values[1],
            &six_unsigned64_values[0],
            &six_unsigned64_values[1],
            &six_unsigned64_values[2],
            &six_unsigned64_values[3],
            &six_unsigned64_values[4],
            &six_unsigned64_values[5],
            &complete_payload,
        ],
    );
    assert_eq!(independent_full_chunk_preimage.len(), 1_048_982);

    descriptor
        .verify_source(context, &circuit, holder_commitment_root)
        .unwrap();
    let first_chunk = descriptor
        .verify_payload_chunk(0, &complete_payload)
        .unwrap();
    assert_eq!(first_chunk.first_field_index(), 0);
    assert_eq!(first_chunk.field_count(), 32_768);
    assert_eq!(
        first_chunk.field_value(0).unwrap(),
        BinaryFieldElement256::from_canonical_bytes(&[0x53; 32]).unwrap()
    );
    let final_chunk = descriptor
        .verify_payload_chunk(COMPLETION_SHARE_VECTOR_CHUNK_COUNT - 1, &final_payload)
        .unwrap();
    assert_eq!(final_chunk.first_field_index(), 1_441_792);
    assert_eq!(final_chunk.field_count(), 1_388);
    assert_eq!(
        final_chunk.field_value(1_387).unwrap(),
        BinaryFieldElement256::from_canonical_bytes(&[0x64; 32]).unwrap()
    );
    assert_eq!(
        final_chunk.field_value(1_388),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorFieldPositionOutOfRange {
                position_within_chunk: 1_388,
                field_count: 1_388,
            }
        )
    );
}

#[test]
fn descriptor_round_trip_preserves_identity_and_rejects_malformed_framing() {
    let circuit = small_circuit();
    let context = preparation_context(0x32, &circuit);
    let holder_commitment_root = hash(0x43);
    let (descriptor, _payloads) =
        descriptor_and_payloads(context, &circuit, holder_commitment_root, 1, 0x54);
    let canonical_bytes = descriptor.canonical_bytes();
    let decoded =
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&canonical_bytes).unwrap();
    assert_eq!(decoded, descriptor);
    assert_eq!(decoded.identity(), descriptor.identity());

    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&[]),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorDescriptorByteLengthOutOfRange {
                actual: 0,
                maximum: FOUNDATION_PROFILE.stream_chunk_byte_length,
            }
        )
    );
    let oversized_descriptor = vec![0; FOUNDATION_PROFILE.stream_chunk_byte_length + 1];
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&oversized_descriptor),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorDescriptorByteLengthOutOfRange {
                actual: FOUNDATION_PROFILE.stream_chunk_byte_length + 1,
                maximum: FOUNDATION_PROFILE.stream_chunk_byte_length,
            }
        )
    );

    let version_offset = encode_varuint(
        u64::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC.len()).unwrap(),
    )
    .len()
        + AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC.len();
    let mut wrong_magic = canonical_bytes.clone();
    wrong_magic[1] ^= 1;
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&wrong_magic),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorArtifactMagicMismatch)
    );
    let mut wrong_version = canonical_bytes.clone();
    wrong_version[version_offset] =
        u8::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION + 1).unwrap();
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&wrong_version),
        Err(
            TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorArtifactVersion {
                version: 2,
            }
        )
    );
    let first_hash_length_offset = version_offset + 1;
    let mut wrong_hash_length = canonical_bytes.clone();
    wrong_hash_length[first_hash_length_offset] = 63;
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&wrong_hash_length),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorHashByteLength {
                field: "context identity",
                expected: 64,
                actual: 63,
            }
        )
    );
    let compiler_hash_payload_offset = first_hash_length_offset + (2 * 65) + 1;
    let mut wrong_compiler_identity = canonical_bytes.clone();
    wrong_compiler_identity[compiler_hash_payload_offset] ^= 1;
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&wrong_compiler_identity),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch)
    );

    let total_field_count_offset = first_hash_length_offset + (4 * 65) + 2;
    let field_byte_length_offset =
        total_field_count_offset + encode_varuint(descriptor.total_field_count()).len();
    let mut wrong_field_byte_length = canonical_bytes.clone();
    wrong_field_byte_length[field_byte_length_offset] = 31;
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&wrong_field_byte_length),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)
    );
    let mut trailing_bytes = canonical_bytes;
    trailing_bytes.push(0);
    assert_eq!(
        AuthenticatedKeyShareVectorDescriptor::from_canonical_bytes(&trailing_bytes),
        Err(TallyPreparationError::TrailingAuthenticatedKeyShareVectorArtifactBytes)
    );
}

#[test]
fn payload_verification_rejects_length_digest_index_and_source_mutations() {
    let circuit = small_circuit();
    let context = preparation_context(0x33, &circuit);
    let holder_commitment_root = hash(0x44);
    let (descriptor, payloads) =
        descriptor_and_payloads(context, &circuit, holder_commitment_root, 0, 0x55);
    let first_payload = &payloads[0];

    assert_eq!(
        descriptor.verify_payload_chunk(0, &first_payload[..first_payload.len() - 1]),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorPayloadByteLengthMismatch {
                expected: first_payload.len() as u64,
                actual: first_payload.len() as u64 - 1,
            }
        )
    );
    let mut changed_payload = first_payload.clone();
    let changed_payload_position = changed_payload.len() / 2;
    changed_payload[changed_payload_position] ^= 1;
    assert_eq!(
        descriptor.verify_payload_chunk(0, &changed_payload),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorPayloadDigestMismatch)
    );
    assert_eq!(
        descriptor.verify_payload_chunk(descriptor.chunk_count(), first_payload),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorChunkOutOfRange {
                chunk_index: descriptor.chunk_count(),
                chunk_count: descriptor.chunk_count(),
            }
        )
    );
    assert_eq!(
        descriptor.verify_source(context, &circuit, hash(0x45)),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch)
    );
    let changed_context = preparation_context(0x34, &circuit);
    assert_eq!(
        descriptor.verify_source(changed_context, &circuit, holder_commitment_root),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch)
    );

    let (changed_sender, _) =
        descriptor_and_payloads(context, &circuit, holder_commitment_root, 1, 0x55);
    let (changed_payload_descriptor, _) =
        descriptor_and_payloads(context, &circuit, holder_commitment_root, 0, 0x56);
    let (changed_root, _) = descriptor_and_payloads(context, &circuit, hash(0x46), 0, 0x55);
    assert_ne!(descriptor.identity(), changed_sender.identity());
    assert_ne!(descriptor.identity(), changed_payload_descriptor.identity());
    assert_ne!(descriptor.identity(), changed_root.identity());
}

#[test]
fn builder_refuses_incomplete_oversized_and_extra_payload_sequences() {
    let circuit = small_circuit();
    let context = preparation_context(0x35, &circuit);
    let holder_commitment_root = hash(0x47);
    let builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
        context,
        &circuit,
        holder_commitment_root,
        0,
    )
    .unwrap();
    assert_eq!(
        builder.finish(),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorIncomplete {
                expected_chunk_count: 1,
                actual_chunk_count: 0,
            }
        )
    );

    let mut builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
        context,
        &circuit,
        holder_commitment_root,
        0,
    )
    .unwrap();
    let expected_payload_byte_length =
        usize::try_from(builder.expected_next_payload_byte_length().unwrap()).unwrap();
    assert_eq!(
        builder.absorb_next_payload_chunk(&vec![0; expected_payload_byte_length + 1]),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorPayloadByteLengthMismatch {
                expected: expected_payload_byte_length as u64,
                actual: expected_payload_byte_length as u64 + 1,
            }
        )
    );
    let payload = vec![0; expected_payload_byte_length];
    builder.absorb_next_payload_chunk(&payload).unwrap();
    assert_eq!(
        builder.absorb_next_payload_chunk(&[]),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorChunkOutOfRange {
                chunk_index: 1,
                chunk_count: 1,
            }
        )
    );
    builder.finish().unwrap();

    assert_eq!(
        AuthenticatedKeyShareVectorDescriptorBuilder::new(
            context,
            &circuit,
            holder_commitment_root,
            context.participant_count(),
        )
        .unwrap_err(),
        TallyPreparationError::AuthenticatedKeyShareVectorSenderPositionOutOfRange {
            sender_position: context.participant_count(),
            participant_count: context.participant_count(),
        }
    );
}

#[test]
fn flattened_key_coordinates_bind_coefficients_then_offset_for_every_record() {
    let circuit = small_circuit();
    let context = preparation_context(0x36, &circuit);
    let catalog = PreparationHolderRecordCatalog::derive(context, &circuit).unwrap();
    let coordinates = authenticated_key_field_coordinates(&catalog)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        coordinates.len() as u64,
        catalog.verification_key_field_element_count()
    );

    let mut field_index = 0_usize;
    let mut saw_scalar_record = false;
    let mut saw_label_record = false;
    for record in catalog.records() {
        let record = record.unwrap();
        for value_limb_position in 0..record.value_field_element_count() {
            assert_eq!(
                coordinates[field_index],
                super::authenticated_key_share_vector::AuthenticatedKeyFieldCoordinate {
                    field_index: field_index as u64,
                    record,
                    role: AuthenticatedKeyFieldRole::Coefficient {
                        value_limb_position,
                    },
                }
            );
            field_index += 1;
        }
        assert_eq!(
            coordinates[field_index],
            super::authenticated_key_share_vector::AuthenticatedKeyFieldCoordinate {
                field_index: field_index as u64,
                record,
                role: AuthenticatedKeyFieldRole::Offset,
            }
        );
        field_index += 1;
        saw_scalar_record |= record.value_field_element_count() == 1;
        saw_label_record |= matches!(record.class(), PreparationHolderRecordClass::InputLabelBody)
            && record.value_field_element_count() == 3;
    }
    assert_eq!(field_index, coordinates.len());
    assert!(saw_scalar_record);
    assert!(saw_label_record);
}

#[test]
fn compiler_identity_requires_canonical_lf_source_and_is_exact() {
    let identity = authenticated_key_share_vector_compiler_identity().unwrap();
    assert_eq!(
        to_hex(identity.as_bytes()),
        "73972000df4f1a4e560a2bfc8757ca6510529c6d33d587bb8a0aaaf8d1259f7073f29b2dd1c44044783f04610fc4e566423502a95c00c4530052d81b9fdc6f9c"
    );
    assert_eq!(
        compiler_identity_from_source_for_test(b"valid source\n").unwrap(),
        compiler_identity_from_source_for_test(b"valid source\n").unwrap()
    );
    for invalid_source in [
        b"missing final line feed".as_slice(),
        b"contains\r\ncarriage return\n".as_slice(),
        b"\xef\xbb\xbfbyte order mark\n".as_slice(),
        b"invalid utf8 \xff\n".as_slice(),
    ] {
        assert_eq!(
            compiler_identity_from_source_for_test(invalid_source),
            Err(TallyPreparationError::NonCanonicalPreparationSourceEncoding)
        );
    }
}

#[test]
fn descriptor_length_formula_covers_every_admitted_shape_and_sender() {
    for participant_count in 4..=10 {
        for option_count in 2..=20 {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let context = preparation_context(u8::try_from(top_count).unwrap(), &circuit);
                let inventory =
                    PreparationHolderRecordInventory::derive(context, &circuit).unwrap();
                let first_sender_length =
                    authenticated_key_share_vector_descriptor_canonical_byte_length(
                        participant_count,
                        0,
                        inventory.verification_key_field_element_count(),
                    )
                    .unwrap();
                let final_sender_length =
                    authenticated_key_share_vector_descriptor_canonical_byte_length(
                        participant_count,
                        participant_count - 1,
                        inventory.verification_key_field_element_count(),
                    )
                    .unwrap();
                assert_eq!(first_sender_length, final_sender_length);
                assert!(first_sender_length < FOUNDATION_PROFILE.stream_chunk_byte_length as u64);
            }
        }
    }
}

fn descriptor_and_payloads(
    context: TallyPreparationContext,
    circuit: &CompiledTallyCircuit,
    holder_commitment_root: Hash512,
    sender_position: u16,
    payload_marker: u8,
) -> (AuthenticatedKeyShareVectorDescriptor, Vec<Vec<u8>>) {
    let mut builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
        context,
        circuit,
        holder_commitment_root,
        sender_position,
    )
    .unwrap();
    let mut payloads = Vec::new();
    while payloads.len() < usize::try_from(builder.chunk_count()).unwrap() {
        let payload = vec![
            payload_marker;
            usize::try_from(builder.expected_next_payload_byte_length().unwrap())
                .unwrap()
        ];
        builder.absorb_next_payload_chunk(&payload).unwrap();
        payloads.push(payload);
    }
    (builder.finish().unwrap(), payloads)
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

fn small_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(TallyCircuitProfile::new(4, 2, 1).unwrap()).unwrap()
}

fn completion_profile_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}
