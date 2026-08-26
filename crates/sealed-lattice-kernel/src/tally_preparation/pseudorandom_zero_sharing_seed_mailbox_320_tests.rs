use fips204::traits::Signer;
use zeroize::Zeroizing;

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedMailboxTestFixture320, seed_mailbox_test_fixture_320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320,
    pseudorandom_zero_sharing_seed_mailbox_320::{
        AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320,
        ML_KEM_768_CIPHERTEXT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_DIGEST_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_RECIPIENT_KEY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN,
        PseudorandomZeroSharingSeedMailboxError320,
        PseudorandomZeroSharingSeedMailboxHeaderBody320,
        PseudorandomZeroSharingSeedMailboxManifestBody320,
        PseudorandomZeroSharingSeedMailboxSealer320,
        PseudorandomZeroSharingSeedMailboxSignatureBody320,
        PseudorandomZeroSharingSeedMailboxVerifier320,
        PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320,
        derive_mailbox_stream_geometry, hash_mailbox_chunk,
        pseudorandom_zero_sharing_seed_mailbox_control_and_tag_byte_length,
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length,
    },
};

struct SealedMailboxTestStream320 {
    header: PseudorandomZeroSharingSeedMailboxHeaderBody320,
    header_bytes: Vec<u8>,
    manifest: PseudorandomZeroSharingSeedMailboxManifestBody320,
    manifest_bytes: Vec<u8>,
    signature_body: PseudorandomZeroSharingSeedMailboxSignatureBody320,
    signature_envelope_bytes: Vec<u8>,
    encrypted_chunks: Vec<Zeroizing<Vec<u8>>>,
}

#[test]
fn signed_mailbox_stream_round_trips_through_kem_aead_and_root_verification() {
    let fixture = seed_mailbox_test_fixture_320(2, 7);
    let sealed = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        [0x81; 32],
        0x83,
    );

    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER,
        "ml-kem-768+kmac256+aes-256-gcm-siv"
    );
    assert_eq!(ML_KEM_768_CIPHERTEXT_BYTE_LENGTH, 1_088);
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH,
        1_048_560
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH,
        16
    );
    assert_eq!(sealed.header.delivery_descriptor().sender_position(), 2);
    assert_eq!(sealed.header.delivery_descriptor().recipient_position(), 7);
    assert_eq!(
        sealed.header.delivery_descriptor().payload_byte_length(),
        62_590
    );
    assert_eq!(sealed.header.chunk_count(), 1);
    assert_eq!(sealed.header.total_carrier_byte_length(), 62_606);
    assert_eq!(
        sealed.header.maximum_plaintext_chunk_byte_length(),
        1_048_560
    );
    assert_eq!(sealed.header.encapsulation_ciphertext().len(), 1_088);
    let _ = sealed.header.recipient_encapsulation_key_identity();
    assert_eq!(sealed.manifest.ordered_chunk_digests().len(), 1);
    assert_eq!(
        sealed.manifest.header_identity(),
        sealed.header.identity().unwrap()
    );
    assert_eq!(sealed.signature_body.sender_position(), 2);
    assert_eq!(
        sealed.signature_body.header_identity(),
        sealed.header.identity().unwrap()
    );
    assert_eq!(
        sealed.signature_body.manifest_identity(),
        sealed.manifest.identity().unwrap()
    );
    assert_eq!(sealed.encrypted_chunks.len(), 1);
    assert_eq!(sealed.encrypted_chunks[0].len(), 62_606);

    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        1_655
    );
    assert_eq!(
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length(1).unwrap(),
        215
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH,
        309
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        3_713
    );
    assert_eq!(sealed.header_bytes.len(), 1_655);
    assert_eq!(sealed.manifest_bytes.len(), 215);
    assert_eq!(sealed.signature_body.canonical_bytes().unwrap().len(), 309);
    assert_eq!(sealed.signature_envelope_bytes.len(), 3_713);
    assert_eq!(
        pseudorandom_zero_sharing_seed_mailbox_control_and_tag_byte_length(1).unwrap(),
        5_599
    );

    let mut verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &sealed.header_bytes,
        &sealed.manifest_bytes,
        &sealed.signature_envelope_bytes,
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
    )
    .unwrap();
    for encrypted_chunk in &sealed.encrypted_chunks {
        verifier
            .absorb_next_encrypted_chunk(encrypted_chunk)
            .unwrap();
    }
    let authenticated_delivery = verifier.finish().unwrap();
    assert_eq!(
        authenticated_delivery.header_identity(),
        sealed.header.identity().unwrap()
    );
    assert_eq!(
        authenticated_delivery.manifest_identity(),
        sealed.manifest.identity().unwrap()
    );
    assert_eq!(
        authenticated_delivery
            .delivery()
            .descriptor()
            .canonical_bytes()
            .unwrap(),
        fixture.descriptor_bytes
    );
    assert_eq!(authenticated_delivery.delivery().subset_entries().len(), 56);
    let _ = authenticated_delivery.into_delivery();
    assert!(format!("{:?}", sealed.header).contains("[redacted]"));
}

#[test]
fn mailbox_stream_is_replay_stable_but_fresh_encapsulation_changes_every_carrier_identity() {
    let fixture = seed_mailbox_test_fixture_320(3, 8);
    let first = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        [0x91; 32],
        0x93,
    );
    let replay = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        [0x91; 32],
        0x93,
    );
    assert_eq!(first.header_bytes, replay.header_bytes);
    assert_eq!(first.manifest_bytes, replay.manifest_bytes);
    assert_eq!(
        first.signature_envelope_bytes,
        replay.signature_envelope_bytes
    );
    assert_eq!(first.encrypted_chunks, replay.encrypted_chunks);

    let fresh = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        [0x95; 32],
        0x97,
    );
    assert_ne!(first.header_bytes, fresh.header_bytes);
    assert_ne!(first.manifest_bytes, fresh.manifest_bytes);
    assert_ne!(first.encrypted_chunks, fresh.encrypted_chunks);
}

#[test]
fn mailbox_verifier_separates_unsigned_replacement_from_signed_malformed_carriers() {
    let fixture = seed_mailbox_test_fixture_320(1, 6);
    let sealed = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        [0xa1; 32],
        0xa3,
    );

    let mut changed_signature = sealed.signature_envelope_bytes.clone();
    *changed_signature.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        PseudorandomZeroSharingSeedMailboxVerifier320::new(
            &fixture.root_terminal,
            &fixture.roster,
            fixture.sender_position,
            fixture.recipient_position,
            &sealed.header_bytes,
            &sealed.manifest_bytes,
            &changed_signature,
            &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
        ),
        Err(PseudorandomZeroSharingSeedMailboxError320::InvalidSenderSignature)
    ));

    let mut replacement_chunk = sealed.encrypted_chunks[0].to_vec();
    replacement_chunk[11] ^= 0x20;
    let mut replacement_verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &sealed.header_bytes,
        &sealed.manifest_bytes,
        &sealed.signature_envelope_bytes,
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
    )
    .unwrap();
    assert!(matches!(
        replacement_verifier.absorb_next_encrypted_chunk(&replacement_chunk),
        Err(PseudorandomZeroSharingSeedMailboxError320::ChunkDigestMismatch { chunk_index: 0 })
    ));

    let mut signed_invalid_tag_chunk = sealed.encrypted_chunks[0].to_vec();
    *signed_invalid_tag_chunk.last_mut().unwrap() ^= 0x40;
    let signed_invalid_tag_manifest = PseudorandomZeroSharingSeedMailboxManifestBody320::new(
        &sealed.header,
        vec![
            hash_mailbox_chunk(
                sealed.header.identity().unwrap(),
                0,
                &signed_invalid_tag_chunk,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let signed_invalid_tag_envelope =
        sign_manifest(&fixture, &sealed.header, &signed_invalid_tag_manifest, 0xa5);
    let mut signed_invalid_tag_verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &sealed.header_bytes,
        &signed_invalid_tag_manifest.canonical_bytes().unwrap(),
        &signed_invalid_tag_envelope,
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
    )
    .unwrap();
    assert!(matches!(
        signed_invalid_tag_verifier.absorb_next_encrypted_chunk(&signed_invalid_tag_chunk),
        Err(PseudorandomZeroSharingSeedMailboxError320::AuthenticatedDecryptionFailed)
    ));

    assert!(matches!(
        PseudorandomZeroSharingSeedMailboxVerifier320::new(
            &fixture.root_terminal,
            &fixture.roster,
            fixture.sender_position,
            fixture.recipient_position,
            &sealed.header_bytes,
            &sealed.manifest_bytes,
            &sealed.signature_envelope_bytes,
            &fixture.mailbox_decapsulation_keys[usize::from((fixture.recipient_position + 1) % 10)],
        ),
        Err(PseudorandomZeroSharingSeedMailboxError320::DecapsulationKeyMismatch)
    ));
}

#[test]
fn mailbox_verifier_rejects_every_truncated_control_record_and_incomplete_chunk_sequences() {
    let fixture = seed_mailbox_test_fixture_320(5, 0);
    let sealed = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        [0xa7; 32],
        0xa9,
    );
    let recipient_decapsulation_key =
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)];

    for truncated_byte_length in 0..sealed.header_bytes.len() {
        assert!(
            PseudorandomZeroSharingSeedMailboxVerifier320::new(
                &fixture.root_terminal,
                &fixture.roster,
                fixture.sender_position,
                fixture.recipient_position,
                &sealed.header_bytes[..truncated_byte_length],
                &sealed.manifest_bytes,
                &sealed.signature_envelope_bytes,
                recipient_decapsulation_key,
            )
            .is_err(),
            "accepted truncated header at byte length {truncated_byte_length}"
        );
    }
    for truncated_byte_length in 0..sealed.manifest_bytes.len() {
        assert!(
            PseudorandomZeroSharingSeedMailboxVerifier320::new(
                &fixture.root_terminal,
                &fixture.roster,
                fixture.sender_position,
                fixture.recipient_position,
                &sealed.header_bytes,
                &sealed.manifest_bytes[..truncated_byte_length],
                &sealed.signature_envelope_bytes,
                recipient_decapsulation_key,
            )
            .is_err(),
            "accepted truncated manifest at byte length {truncated_byte_length}"
        );
    }
    for truncated_byte_length in 0..sealed.signature_envelope_bytes.len() {
        assert!(
            PseudorandomZeroSharingSeedMailboxVerifier320::new(
                &fixture.root_terminal,
                &fixture.roster,
                fixture.sender_position,
                fixture.recipient_position,
                &sealed.header_bytes,
                &sealed.manifest_bytes,
                &sealed.signature_envelope_bytes[..truncated_byte_length],
                recipient_decapsulation_key,
            )
            .is_err(),
            "accepted truncated signature envelope at byte length {truncated_byte_length}"
        );
    }

    for (field, complete_bytes) in [
        ("header", sealed.header_bytes.as_slice()),
        ("manifest", sealed.manifest_bytes.as_slice()),
        (
            "signature envelope",
            sealed.signature_envelope_bytes.as_slice(),
        ),
    ] {
        let mut bytes_with_trailing_data = complete_bytes.to_vec();
        bytes_with_trailing_data.push(0);
        let (header_bytes, manifest_bytes, signature_envelope_bytes) = match field {
            "header" => (
                bytes_with_trailing_data.as_slice(),
                sealed.manifest_bytes.as_slice(),
                sealed.signature_envelope_bytes.as_slice(),
            ),
            "manifest" => (
                sealed.header_bytes.as_slice(),
                bytes_with_trailing_data.as_slice(),
                sealed.signature_envelope_bytes.as_slice(),
            ),
            _ => (
                sealed.header_bytes.as_slice(),
                sealed.manifest_bytes.as_slice(),
                bytes_with_trailing_data.as_slice(),
            ),
        };
        assert!(
            PseudorandomZeroSharingSeedMailboxVerifier320::new(
                &fixture.root_terminal,
                &fixture.roster,
                fixture.sender_position,
                fixture.recipient_position,
                header_bytes,
                manifest_bytes,
                signature_envelope_bytes,
                recipient_decapsulation_key,
            )
            .is_err(),
            "accepted trailing data in {field}"
        );
    }

    let unfinished_verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &sealed.header_bytes,
        &sealed.manifest_bytes,
        &sealed.signature_envelope_bytes,
        recipient_decapsulation_key,
    )
    .unwrap();
    assert!(matches!(
        unfinished_verifier.finish(),
        Err(PseudorandomZeroSharingSeedMailboxError320::ChunkCount {
            expected: 1,
            actual: 0
        })
    ));

    let mut extra_chunk_verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &sealed.header_bytes,
        &sealed.manifest_bytes,
        &sealed.signature_envelope_bytes,
        recipient_decapsulation_key,
    )
    .unwrap();
    extra_chunk_verifier
        .absorb_next_encrypted_chunk(&sealed.encrypted_chunks[0])
        .unwrap();
    assert!(matches!(
        extra_chunk_verifier.absorb_next_encrypted_chunk(&sealed.encrypted_chunks[0]),
        Err(PseudorandomZeroSharingSeedMailboxError320::ChunkOrder {
            expected: 1,
            actual: 1
        })
    ));
}

#[test]
fn signed_root_inconsistent_plaintext_and_wrong_endpoint_headers_refuse() {
    let fixture = seed_mailbox_test_fixture_320(4, 9);
    let mut changed_payload = fixture.payload_bytes.to_vec();
    changed_payload[0] ^= 0x80;
    let changed = seal_mailbox_stream(
        &fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &changed_payload,
        [0xb1; 32],
        0xb3,
    );
    let mut changed_verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &changed.header_bytes,
        &changed.manifest_bytes,
        &changed.signature_envelope_bytes,
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
    )
    .unwrap();
    assert!(matches!(
        changed_verifier.absorb_next_encrypted_chunk(&changed.encrypted_chunks[0]),
        Err(PseudorandomZeroSharingSeedMailboxError320::Delivery(_))
    ));

    let other_recipient_position = 8;
    let other_descriptor = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        &fixture.root_terminal,
        fixture.sender_position,
        other_recipient_position,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    let wrong_endpoint = seal_mailbox_stream(
        &fixture,
        other_recipient_position,
        &other_descriptor,
        &fixture.payload_bytes,
        [0xb5; 32],
        0xb7,
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedMailboxVerifier320::new(
            &fixture.root_terminal,
            &fixture.roster,
            fixture.sender_position,
            fixture.recipient_position,
            &wrong_endpoint.header_bytes,
            &wrong_endpoint.manifest_bytes,
            &wrong_endpoint.signature_envelope_bytes,
            &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
        ),
        Err(PseudorandomZeroSharingSeedMailboxError320::ObjectMismatch {
            field: "delivery descriptor"
        })
    ));
}

#[test]
fn mailbox_geometry_preserves_one_mebibyte_carrier_chunks_and_has_a_hard_count_bound() {
    let maximum_plaintext =
        u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH)
            .unwrap();
    assert_eq!(derive_mailbox_stream_geometry(1).unwrap(), (1, 17));
    assert_eq!(
        derive_mailbox_stream_geometry(maximum_plaintext).unwrap(),
        (1, 1_048_576)
    );
    assert_eq!(
        derive_mailbox_stream_geometry(maximum_plaintext + 1).unwrap(),
        (2, maximum_plaintext + 33)
    );
    assert_eq!(
        derive_mailbox_stream_geometry(maximum_plaintext * 4_096).unwrap(),
        (4_096, 4_096 * 1_048_576)
    );
    assert!(derive_mailbox_stream_geometry(maximum_plaintext * 4_096 + 1).is_err());
    assert!(derive_mailbox_stream_geometry(0).is_err());
}

#[test]
fn mailbox_domains_and_kdf_labels_are_exact_and_pairwise_distinct() {
    let domains = [
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_RECIPIENT_KEY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_DIGEST_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN,
    ];
    for (domain_index, domain) in domains.iter().enumerate() {
        assert!(domain.is_ascii());
        for other_domain in &domains[domain_index + 1..] {
            assert_ne!(domain, other_domain);
        }
    }
    assert_ne!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL
    );
    assert_ne!(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL
    );
}

fn seal_mailbox_stream(
    fixture: &SeedMailboxTestFixture320,
    recipient_position: u16,
    descriptor_bytes: &[u8],
    payload_bytes: &[u8],
    encapsulation_randomness: [u8; 32],
    signature_seed_marker: u8,
) -> SealedMailboxTestStream320 {
    let mut sealer = PseudorandomZeroSharingSeedMailboxSealer320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        recipient_position,
        descriptor_bytes,
        &encapsulation_randomness,
    )
    .unwrap();
    let header = sealer.header().clone();
    let header_bytes = header.canonical_bytes().unwrap();
    let encrypted_chunks = payload_bytes
        .chunks(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH)
        .map(|plaintext_chunk| sealer.seal_next_plaintext_chunk(plaintext_chunk).unwrap())
        .collect::<Vec<_>>();
    let manifest = sealer.finish().unwrap();
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let signature_body =
        PseudorandomZeroSharingSeedMailboxSignatureBody320::new(&header, &manifest).unwrap();
    let signature_envelope_bytes =
        sign_manifest(fixture, &header, &manifest, signature_seed_marker);
    SealedMailboxTestStream320 {
        header,
        header_bytes,
        manifest,
        manifest_bytes,
        signature_body,
        signature_envelope_bytes,
        encrypted_chunks,
    }
}

pub(super) fn authenticated_mailbox_delivery_320(
    fixture: &SeedMailboxTestFixture320,
    encapsulation_randomness: [u8; 32],
    signature_seed_marker: u8,
) -> AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320 {
    let sealed = seal_mailbox_stream(
        fixture,
        fixture.recipient_position,
        &fixture.descriptor_bytes,
        &fixture.payload_bytes,
        encapsulation_randomness,
        signature_seed_marker,
    );
    let mut verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &sealed.header_bytes,
        &sealed.manifest_bytes,
        &sealed.signature_envelope_bytes,
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
    )
    .unwrap();
    for encrypted_chunk in &sealed.encrypted_chunks {
        verifier
            .absorb_next_encrypted_chunk(encrypted_chunk)
            .unwrap();
    }
    verifier.finish().unwrap()
}

fn sign_manifest(
    fixture: &SeedMailboxTestFixture320,
    header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
    manifest: &PseudorandomZeroSharingSeedMailboxManifestBody320,
    signature_seed_marker: u8,
) -> Vec<u8> {
    let signature_body =
        PseudorandomZeroSharingSeedMailboxSignatureBody320::new(header, manifest).unwrap();
    let signature = fixture.signing_keys[usize::from(fixture.sender_position)]
        .try_sign_with_seed(
            &[signature_seed_marker; 32],
            &signature_body.canonical_bytes().unwrap(),
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT,
        )
        .unwrap();
    PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320::new(signature_body, signature)
        .canonical_bytes()
        .unwrap()
}
