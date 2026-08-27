use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    hashing::to_hex,
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector::{
        AuthenticatedKeyShareVectorDescriptor, AuthenticatedKeyShareVectorDescriptorBuilder,
    },
    authenticated_key_share_vector_codeword_manifest::{
        AUTHENTICATED_KEY_SHARE_VECTOR_CODEWORD_MANIFEST_MAGIC,
        AUTHENTICATED_KEY_SHARE_VECTOR_CODEWORD_MANIFEST_VERSION,
        AuthenticatedKeyShareVectorCodewordManifest,
        authenticated_key_share_vector_codeword_manifest_canonical_byte_length,
        authenticated_key_share_vector_codeword_manifest_compiler_identity,
        compiler_identity_from_source_for_test,
    },
};

const COMPLETION_VERIFICATION_KEY_FIELD_COUNT: u64 = 573_980;

#[test]
fn all_roster_manifest_binds_ordered_descriptors_and_round_trips() {
    let circuit = circuit(9, 2, 1);
    let context = preparation_context(0x21, &circuit);
    let holder_commitment_root = hash(0x32);
    let descriptors = descriptors(
        context,
        &circuit,
        holder_commitment_root,
        circuit.profile().participant_count(),
    );
    let manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &descriptors,
    )
    .unwrap();
    assert_eq!(manifest.participant_count(), 9);
    assert_eq!(manifest.reconstruction_threshold(), 4);
    assert_eq!(
        manifest.canonical_bytes().len() as u64,
        authenticated_key_share_vector_codeword_manifest_canonical_byte_length(
            9,
            manifest.total_field_count(),
        )
        .unwrap()
    );
    let decoded = AuthenticatedKeyShareVectorCodewordManifest::from_canonical_bytes(
        &manifest.canonical_bytes(),
    )
    .unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.identity(), manifest.identity());
    decoded
        .verify_source_and_descriptors(context, &circuit, holder_commitment_root, &descriptors)
        .unwrap();

    let mut reordered_descriptors = descriptors.clone();
    reordered_descriptors.swap(0, 1);
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::derive(
            context,
            &circuit,
            holder_commitment_root,
            &reordered_descriptors,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorCodewordManifestMismatch)
    );
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::derive(
            context,
            &circuit,
            holder_commitment_root,
            &descriptors[..descriptors.len() - 1],
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorCodewordManifestDescriptorCountMismatch {
                expected: 9,
                actual: 8,
            }
        )
    );
}

#[test]
fn all_roster_manifest_refuses_mixed_sources_and_changed_payload_identity() {
    let circuit = circuit(4, 2, 1);
    let context = preparation_context(0x22, &circuit);
    let holder_commitment_root = hash(0x33);
    let baseline_descriptors = descriptors(context, &circuit, holder_commitment_root, 4);
    let baseline = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &baseline_descriptors,
    )
    .unwrap();

    let mut changed_payload_descriptors = baseline_descriptors.clone();
    changed_payload_descriptors[2] = descriptor(context, &circuit, holder_commitment_root, 2, 0x75);
    let changed_payload = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &changed_payload_descriptors,
    )
    .unwrap();
    assert_ne!(baseline.identity(), changed_payload.identity());

    let mut mixed_root_descriptors = baseline_descriptors.clone();
    mixed_root_descriptors[1] = descriptor(context, &circuit, hash(0x34), 1, 0x54);
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::derive(
            context,
            &circuit,
            holder_commitment_root,
            &mixed_root_descriptors,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch)
    );
    assert_eq!(
        baseline.verify_source_and_descriptors(
            preparation_context(0x23, &circuit),
            &circuit,
            holder_commitment_root,
            &baseline_descriptors,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch)
    );
}

#[test]
fn codeword_manifest_decoder_refuses_malformed_framing() {
    let circuit = circuit(4, 2, 1);
    let context = preparation_context(0x24, &circuit);
    let holder_commitment_root = hash(0x35);
    let descriptors = descriptors(context, &circuit, holder_commitment_root, 4);
    let manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &descriptors,
    )
    .unwrap();

    let mut wrong_magic = manifest.canonical_bytes();
    wrong_magic[1] ^= 1;
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::from_canonical_bytes(&wrong_magic),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorCodewordManifestMagicMismatch)
    );
    let version_offset = 1 + AUTHENTICATED_KEY_SHARE_VECTOR_CODEWORD_MANIFEST_MAGIC.len();
    let mut wrong_version = manifest.canonical_bytes();
    wrong_version[version_offset] =
        u8::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_CODEWORD_MANIFEST_VERSION + 1).unwrap();
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::from_canonical_bytes(&wrong_version),
        Err(
            TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorCodewordManifestVersion {
                version: 2,
            }
        )
    );
    let mut trailing_bytes = manifest.canonical_bytes();
    trailing_bytes.push(0);
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::from_canonical_bytes(&trailing_bytes),
        Err(TallyPreparationError::TrailingAuthenticatedKeyShareVectorCodewordManifestBytes)
    );
    assert_eq!(
        AuthenticatedKeyShareVectorCodewordManifest::from_canonical_bytes(&[]),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorControlByteLengthOutOfRange {
                actual: 0,
                maximum: FOUNDATION_PROFILE.stream_chunk_byte_length,
            }
        )
    );
}

#[test]
fn completion_codeword_manifest_length_is_exact_and_bounded() {
    assert_eq!(
        authenticated_key_share_vector_codeword_manifest_canonical_byte_length(
            FOUNDATION_PROFILE.participant_count,
            COMPLETION_VERIFICATION_KEY_FIELD_COUNT,
        )
        .unwrap(),
        1_056
    );
}

#[test]
fn codeword_manifest_compiler_identity_requires_canonical_lf_source_and_is_exact() {
    assert_eq!(
        to_hex(
            authenticated_key_share_vector_codeword_manifest_compiler_identity()
                .unwrap()
                .as_bytes(),
        ),
        "4053daf8c6ad1d11a5c0cf4851275145f6bbc57587d19174a055e8bb0b9fd8462e6eb679cfa8f4227b236638eb88db81d5af6913a8aa44271f2a0d55c170c5f5"
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

fn descriptors(
    context: TallyPreparationContext,
    circuit: &CompiledTallyCircuit,
    holder_commitment_root: Hash512,
    participant_count: u16,
) -> Vec<AuthenticatedKeyShareVectorDescriptor> {
    (0..participant_count)
        .map(|sender_position| {
            descriptor(
                context,
                circuit,
                holder_commitment_root,
                sender_position,
                u8::try_from(0x43 + sender_position).unwrap(),
            )
        })
        .collect()
}

fn descriptor(
    context: TallyPreparationContext,
    circuit: &CompiledTallyCircuit,
    holder_commitment_root: Hash512,
    sender_position: u16,
    payload_marker: u8,
) -> AuthenticatedKeyShareVectorDescriptor {
    let mut builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
        context,
        circuit,
        holder_commitment_root,
        sender_position,
    )
    .unwrap();
    for _chunk_index in 0..builder.chunk_count() {
        let payload = vec![
            payload_marker;
            usize::try_from(builder.expected_next_payload_byte_length().unwrap())
                .unwrap()
        ];
        builder.absorb_next_payload_chunk(&payload).unwrap();
    }
    builder.finish().unwrap()
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
