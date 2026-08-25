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
    authenticated_key_share_vector_manifest::{
        AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_MAGIC,
        AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION,
        AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_MAGIC,
        AuthenticatedKeyShareVectorAcknowledgementBody, AuthenticatedKeyShareVectorManifest,
        authenticated_key_share_vector_acknowledgement_canonical_byte_length,
        authenticated_key_share_vector_manifest_canonical_byte_length,
        authenticated_key_share_vector_manifest_compiler_identity,
        compiler_identity_from_source_for_test,
        derive_authenticated_key_share_vector_acknowledgement_root,
    },
};

const COMPLETION_VERIFICATION_KEY_FIELD_COUNT: u64 = 1_443_180;

#[test]
fn threshold_four_manifest_binds_ordered_descriptors_and_round_trips() {
    let circuit = circuit(9, 2, 1);
    let context = preparation_context(0x21, &circuit);
    let holder_commitment_root = hash(0x32);
    let descriptors = (0..4)
        .map(|sender_position| {
            descriptor(
                context,
                &circuit,
                holder_commitment_root,
                sender_position,
                u8::try_from(0x43 + sender_position).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let manifest = AuthenticatedKeyShareVectorManifest::derive(
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
        authenticated_key_share_vector_manifest_canonical_byte_length(
            9,
            manifest.total_field_count(),
        )
        .unwrap()
    );
    let decoded =
        AuthenticatedKeyShareVectorManifest::from_canonical_bytes(&manifest.canonical_bytes())
            .unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.identity(), manifest.identity());
    decoded
        .verify_source_and_descriptors(context, &circuit, holder_commitment_root, &descriptors)
        .unwrap();

    let mut reordered_descriptors = descriptors.clone();
    reordered_descriptors.swap(0, 1);
    assert_eq!(
        AuthenticatedKeyShareVectorManifest::derive(
            context,
            &circuit,
            holder_commitment_root,
            &reordered_descriptors,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch)
    );
    assert_eq!(
        AuthenticatedKeyShareVectorManifest::derive(
            context,
            &circuit,
            holder_commitment_root,
            &descriptors[..3],
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorManifestDescriptorCountMismatch {
                expected: 4,
                actual: 3,
            }
        )
    );
}

#[test]
fn manifest_refuses_mixed_sources_and_detects_payload_identity_changes() {
    let circuit = circuit(4, 2, 1);
    let context = preparation_context(0x22, &circuit);
    let holder_commitment_root = hash(0x33);
    let baseline_descriptors = vec![
        descriptor(context, &circuit, holder_commitment_root, 0, 0x44),
        descriptor(context, &circuit, holder_commitment_root, 1, 0x45),
    ];
    let baseline = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &baseline_descriptors,
    )
    .unwrap();

    let changed_payload_descriptors = vec![
        descriptor(context, &circuit, holder_commitment_root, 0, 0x46),
        baseline_descriptors[1].clone(),
    ];
    let changed_payload = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &changed_payload_descriptors,
    )
    .unwrap();
    assert_ne!(baseline.identity(), changed_payload.identity());

    let mixed_root_descriptors = vec![
        descriptor(context, &circuit, hash(0x34), 0, 0x44),
        baseline_descriptors[1].clone(),
    ];
    assert_eq!(
        AuthenticatedKeyShareVectorManifest::derive(
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
fn all_roster_acknowledgement_root_requires_exact_order_and_manifest() {
    let circuit = circuit(4, 2, 1);
    let context = preparation_context(0x24, &circuit);
    let holder_commitment_root = hash(0x35);
    let descriptors = vec![
        descriptor(context, &circuit, holder_commitment_root, 0, 0x47),
        descriptor(context, &circuit, holder_commitment_root, 1, 0x48),
    ];
    let manifest = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &descriptors,
    )
    .unwrap();
    let acknowledgements = (0..manifest.participant_count())
        .map(|participant_position| {
            AuthenticatedKeyShareVectorAcknowledgementBody::unsigned_body_for_participant(
                &manifest,
                participant_position,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let root =
        derive_authenticated_key_share_vector_acknowledgement_root(&manifest, &acknowledgements)
            .unwrap();
    assert_ne!(root, hash(0));
    for acknowledgement in &acknowledgements {
        let canonical_bytes = acknowledgement.canonical_bytes();
        assert_eq!(
            canonical_bytes.len() as u64,
            authenticated_key_share_vector_acknowledgement_canonical_byte_length(
                manifest.participant_count(),
                acknowledgement.participant_position(),
            )
            .unwrap()
        );
        assert_eq!(
            AuthenticatedKeyShareVectorAcknowledgementBody::from_canonical_bytes(&canonical_bytes)
                .unwrap(),
            *acknowledgement
        );
    }

    assert_eq!(
        derive_authenticated_key_share_vector_acknowledgement_root(
            &manifest,
            &acknowledgements[..3],
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementCountMismatch {
                expected: 4,
                actual: 3,
            }
        )
    );
    let mut reordered_acknowledgements = acknowledgements.clone();
    reordered_acknowledgements.swap(1, 2);
    assert_eq!(
        derive_authenticated_key_share_vector_acknowledgement_root(
            &manifest,
            &reordered_acknowledgements,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch)
    );

    let changed_descriptors = vec![
        descriptor(context, &circuit, holder_commitment_root, 0, 0x49),
        descriptors[1].clone(),
    ];
    let changed_manifest = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &changed_descriptors,
    )
    .unwrap();
    assert_eq!(
        derive_authenticated_key_share_vector_acknowledgement_root(
            &changed_manifest,
            &acknowledgements,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch)
    );
}

#[test]
fn manifest_and_acknowledgement_decoders_refuse_malformed_bytes() {
    let circuit = circuit(4, 2, 1);
    let context = preparation_context(0x25, &circuit);
    let holder_commitment_root = hash(0x36);
    let descriptors = vec![
        descriptor(context, &circuit, holder_commitment_root, 0, 0x4a),
        descriptor(context, &circuit, holder_commitment_root, 1, 0x4b),
    ];
    let manifest = AuthenticatedKeyShareVectorManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &descriptors,
    )
    .unwrap();
    let mut wrong_manifest_magic = manifest.canonical_bytes();
    wrong_manifest_magic[1] ^= 1;
    assert_eq!(
        AuthenticatedKeyShareVectorManifest::from_canonical_bytes(&wrong_manifest_magic),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMagicMismatch)
    );
    let manifest_version_offset = 1 + AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_MAGIC.len();
    let mut wrong_manifest_version = manifest.canonical_bytes();
    wrong_manifest_version[manifest_version_offset] =
        u8::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION + 1).unwrap();
    assert_eq!(
        AuthenticatedKeyShareVectorManifest::from_canonical_bytes(&wrong_manifest_version),
        Err(
            TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorManifestVersion {
                version: 2,
            }
        )
    );
    let mut trailing_manifest = manifest.canonical_bytes();
    trailing_manifest.push(0);
    assert_eq!(
        AuthenticatedKeyShareVectorManifest::from_canonical_bytes(&trailing_manifest),
        Err(TallyPreparationError::TrailingAuthenticatedKeyShareVectorManifestBytes)
    );

    let acknowledgement =
        AuthenticatedKeyShareVectorAcknowledgementBody::unsigned_body_for_participant(&manifest, 0)
            .unwrap();
    let mut wrong_acknowledgement_magic = acknowledgement.canonical_bytes();
    wrong_acknowledgement_magic[1] ^= 1;
    assert_eq!(
        AuthenticatedKeyShareVectorAcknowledgementBody::from_canonical_bytes(
            &wrong_acknowledgement_magic,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMagicMismatch)
    );
    let acknowledgement_version_offset =
        1 + AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_MAGIC.len();
    let mut wrong_acknowledgement_version = acknowledgement.canonical_bytes();
    wrong_acknowledgement_version[acknowledgement_version_offset] =
        u8::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION + 1).unwrap();
    assert_eq!(
        AuthenticatedKeyShareVectorAcknowledgementBody::from_canonical_bytes(
            &wrong_acknowledgement_version,
        ),
        Err(
            TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorAcknowledgementVersion {
                version: 2,
            }
        )
    );
    let mut trailing_acknowledgement = acknowledgement.canonical_bytes();
    trailing_acknowledgement.push(0);
    assert_eq!(
        AuthenticatedKeyShareVectorAcknowledgementBody::from_canonical_bytes(
            &trailing_acknowledgement,
        ),
        Err(TallyPreparationError::TrailingAuthenticatedKeyShareVectorAcknowledgementBytes)
    );
}

#[test]
fn completion_control_body_lengths_are_exact_and_bounded() {
    assert_eq!(
        authenticated_key_share_vector_manifest_canonical_byte_length(
            FOUNDATION_PROFILE.participant_count,
            COMPLETION_VERIFICATION_KEY_FIELD_COUNT,
        )
        .unwrap(),
        651
    );
    for participant_position in 0..FOUNDATION_PROFILE.participant_count {
        assert_eq!(
            authenticated_key_share_vector_acknowledgement_canonical_byte_length(
                FOUNDATION_PROFILE.participant_count,
                participant_position,
            )
            .unwrap(),
            130
        );
    }
}

#[test]
fn manifest_compiler_identity_requires_canonical_lf_source_and_is_exact() {
    assert_eq!(
        to_hex(
            authenticated_key_share_vector_manifest_compiler_identity()
                .unwrap()
                .as_bytes(),
        ),
        "fd0cbf403246d98c5c4a5b263bd526420301f89c2dd24e0b11e5d5e64ca3afd5acabbc17acb7c12966b8b9e72212c224af99ed6c69686f07b198da73780a0303"
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
    for _ in 0..builder.chunk_count() {
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
