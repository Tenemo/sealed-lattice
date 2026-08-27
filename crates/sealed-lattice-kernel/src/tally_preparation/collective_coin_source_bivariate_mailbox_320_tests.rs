use std::collections::HashSet;

use fips204::{ml_dsa_65, traits::Signer};

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
    hash_foundation_tuple_512,
};

use super::{
    collective_coin_source_bivariate_commitment_320_tests::{
        CompletionFixture, authenticate_root, synthetic_completion_fixture,
    },
    collective_coin_source_bivariate_mailbox_320::{
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        CollectiveCoinSourceBivariateMailboxError320,
        CollectiveCoinSourceBivariateMailboxSignatureEnvelope320,
        SealedCollectiveCoinSourceBivariateMailboxPackage320,
        collective_coin_source_bivariate_mailbox_manifest_body_byte_length,
        complete_collective_coin_source_bivariate_mailbox_delivery_320,
        hash_collective_coin_source_bivariate_mailbox_carrier_for_test,
        seal_collective_coin_source_bivariate_mailbox_package_320,
        verify_collective_coin_source_bivariate_mailbox_manifest_signature_320,
        verify_collective_coin_source_bivariate_mailbox_public_carrier_320,
    },
    masked_ballot_bivariate_mailbox_320::{
        MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
    },
    pseudorandom_zero_sharing_seed_mailbox_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
    },
};

#[test]
fn every_completion_holder_authenticates_one_signed_fixed_shape_carrier() {
    let fixture = synthetic_completion_fixture(0x11);
    let authenticated_root = authenticate_root(&fixture, 0x31);
    let sealed_package = seal_fixture_package(&fixture, 0x41);
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let manifest_signature_envelope_bytes = sign_manifest(
        &manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        0x51,
    );
    let authenticated_manifest =
        verify_collective_coin_source_bivariate_mailbox_manifest_signature_320(
            &authenticated_root,
            &fixture.roster,
            &manifest_bytes,
            &manifest_signature_envelope_bytes,
        )
        .unwrap();

    assert_eq!(
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        1_500
    );
    assert_eq!(
        collective_coin_source_bivariate_mailbox_manifest_body_byte_length(
            FOUNDATION_PROFILE.participant_count,
        )
        .unwrap(),
        1_674
    );
    assert_eq!(
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        3_497
    );
    assert_eq!(sealed_package.headers().len(), 10);
    assert_eq!(sealed_package.encrypted_row_carriers().len(), 10);
    assert_eq!(manifest_bytes.len(), 1_674);
    assert_eq!(manifest_signature_envelope_bytes.len(), 3_497);
    assert_eq!(
        authenticated_manifest.layout_identity(),
        fixture.layout.identity()
    );
    assert_eq!(
        authenticated_manifest.root_body_identity(),
        authenticated_root.root_body_identity()
    );
    assert_eq!(
        authenticated_manifest.participant_count(),
        FOUNDATION_PROFILE.participant_count
    );
    assert_eq!(
        authenticated_manifest.contributor_position(),
        fixture.layout.contributor_position()
    );

    for holder_position in 0..FOUNDATION_PROFILE.participant_count {
        let holder_index = usize::from(holder_position);
        let header_bytes = sealed_package.headers()[holder_index]
            .canonical_bytes()
            .unwrap();
        assert_eq!(header_bytes.len(), 1_500);
        assert_eq!(
            sealed_package.encrypted_row_carriers()[holder_index].len(),
            3_404
        );
        let public_carrier = verify_collective_coin_source_bivariate_mailbox_public_carrier_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            holder_position,
            &header_bytes,
            &sealed_package.encrypted_row_carriers()[holder_index],
        )
        .unwrap();
        let delivery = complete_collective_coin_source_bivariate_mailbox_delivery_320(
            &authenticated_root,
            &fixture.roster,
            public_carrier,
            &fixture.mailbox_decapsulation_keys[holder_index],
        )
        .unwrap();
        assert_eq!(delivery.layout_identity(), fixture.layout.identity());
        assert_eq!(
            delivery.root_body_identity(),
            authenticated_root.root_body_identity()
        );
        assert_eq!(
            delivery.manifest_identity(),
            authenticated_manifest.manifest_identity()
        );
        assert_eq!(
            delivery.contributor_position(),
            fixture.layout.contributor_position()
        );
        assert_eq!(delivery.holder_position(), holder_position);
        assert_eq!(
            delivery.authenticated_private_row().row(),
            &fixture.polynomial.row(holder_position).unwrap()
        );
        assert_eq!(
            delivery.retained_private_row_body_bytes(),
            fixture
                .inventory
                .private_row_body(holder_position)
                .unwrap()
                .canonical_bytes()
                .unwrap()
                .as_slice()
        );
        assert_ne!(
            delivery.carrier_header_identity(),
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
        );
        assert_ne!(
            delivery.carrier_digest(),
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
        );
    }

    let public_mailbox_control_total = sealed_package
        .headers()
        .iter()
        .map(|header| header.canonical_bytes().unwrap().len())
        .sum::<usize>()
        + manifest_bytes.len()
        + manifest_signature_envelope_bytes.len();
    let private_carrier_total = sealed_package
        .encrypted_row_carriers()
        .iter()
        .map(|carrier| carrier.len())
        .sum::<usize>();
    assert_eq!(public_mailbox_control_total, 20_171);
    assert_eq!(private_carrier_total, 34_040);
}

#[test]
fn unsigned_replacements_and_wrong_recipient_keys_refuse_before_custody() {
    let fixture = synthetic_completion_fixture(0x12);
    let authenticated_root = authenticate_root(&fixture, 0x32);
    let sealed_package = seal_fixture_package(&fixture, 0x42);
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_manifest(
        &manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        0x52,
    );
    let authenticated_manifest =
        verify_collective_coin_source_bivariate_mailbox_manifest_signature_320(
            &authenticated_root,
            &fixture.roster,
            &manifest_bytes,
            &signature_envelope_bytes,
        )
        .unwrap();

    let mut changed_signature = signature_envelope_bytes.clone();
    *changed_signature.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_collective_coin_source_bivariate_mailbox_manifest_signature_320(
            &authenticated_root,
            &fixture.roster,
            &manifest_bytes,
            &changed_signature,
        ),
        Err(CollectiveCoinSourceBivariateMailboxError320::InvalidContributorSignature)
    ));

    let holder_zero_header_bytes = sealed_package.headers()[0].canonical_bytes().unwrap();
    let mut changed_carrier = sealed_package.encrypted_row_carriers()[0].to_vec();
    changed_carrier[17] ^= 0x40;
    assert!(matches!(
        verify_collective_coin_source_bivariate_mailbox_public_carrier_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            0,
            &holder_zero_header_bytes,
            &changed_carrier,
        ),
        Err(
            CollectiveCoinSourceBivariateMailboxError320::CarrierDigestMismatch {
                holder_position: 0
            }
        )
    ));

    let holder_one_header_bytes = sealed_package.headers()[1].canonical_bytes().unwrap();
    assert!(
        verify_collective_coin_source_bivariate_mailbox_public_carrier_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            0,
            &holder_one_header_bytes,
            &sealed_package.encrypted_row_carriers()[1],
        )
        .is_err()
    );

    let public_carrier = verify_collective_coin_source_bivariate_mailbox_public_carrier_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        &holder_zero_header_bytes,
        &sealed_package.encrypted_row_carriers()[0],
    )
    .unwrap();
    assert!(matches!(
        complete_collective_coin_source_bivariate_mailbox_delivery_320(
            &authenticated_root,
            &fixture.roster,
            public_carrier,
            &fixture.mailbox_decapsulation_keys[1],
        ),
        Err(CollectiveCoinSourceBivariateMailboxError320::DecapsulationKeyMismatch)
    ));
}

#[test]
fn contributor_signed_bad_tag_is_an_authenticated_post_manifest_inconsistency() {
    let fixture = synthetic_completion_fixture(0x13);
    let authenticated_root = authenticate_root(&fixture, 0x33);
    let sealed_package = seal_fixture_package(&fixture, 0x43);
    let mut changed_carrier = sealed_package.encrypted_row_carriers()[0].to_vec();
    *changed_carrier.last_mut().unwrap() ^= 0x01;
    let changed_carrier_digest = hash_collective_coin_source_bivariate_mailbox_carrier_for_test(
        &sealed_package.headers()[0],
        &changed_carrier,
    )
    .unwrap();
    let mut changed_manifest = decode_tuple(&sealed_package.manifest().canonical_bytes().unwrap());
    let changed_digest_item_index = 7 + usize::from(FOUNDATION_PROFILE.participant_count);
    changed_manifest.items[changed_digest_item_index] =
        CanonicalItem::hash512(changed_carrier_digest.into_bytes());
    let changed_manifest_bytes = changed_manifest.encode().unwrap();
    let changed_manifest_signature = sign_manifest(
        &changed_manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        0x53,
    );
    let authenticated_manifest =
        verify_collective_coin_source_bivariate_mailbox_manifest_signature_320(
            &authenticated_root,
            &fixture.roster,
            &changed_manifest_bytes,
            &changed_manifest_signature,
        )
        .unwrap();
    let public_carrier = verify_collective_coin_source_bivariate_mailbox_public_carrier_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        &sealed_package.headers()[0].canonical_bytes().unwrap(),
        &changed_carrier,
    )
    .unwrap();
    assert!(matches!(
        complete_collective_coin_source_bivariate_mailbox_delivery_320(
            &authenticated_root,
            &fixture.roster,
            public_carrier,
            &fixture.mailbox_decapsulation_keys[0],
        ),
        Err(CollectiveCoinSourceBivariateMailboxError320::AuthenticatedDecryptionFailed)
    ));
}

#[test]
fn deterministic_replay_is_exact_and_fresh_encapsulation_changes_every_carrier() {
    let fixture = synthetic_completion_fixture(0x14);
    let first = seal_fixture_package(&fixture, 0x44);
    let replay = seal_fixture_package(&fixture, 0x44);
    let fresh = seal_fixture_package(&fixture, 0x45);
    assert_eq!(
        first.manifest().canonical_bytes().unwrap(),
        replay.manifest().canonical_bytes().unwrap()
    );
    assert_ne!(
        first.manifest().canonical_bytes().unwrap(),
        fresh.manifest().canonical_bytes().unwrap()
    );
    for holder_index in 0..usize::from(FOUNDATION_PROFILE.participant_count) {
        assert_eq!(
            first.headers()[holder_index].canonical_bytes().unwrap(),
            replay.headers()[holder_index].canonical_bytes().unwrap()
        );
        assert_eq!(
            first.encrypted_row_carriers()[holder_index],
            replay.encrypted_row_carriers()[holder_index]
        );
        assert_ne!(
            first.headers()[holder_index].canonical_bytes().unwrap(),
            fresh.headers()[holder_index].canonical_bytes().unwrap()
        );
        assert_ne!(
            first.encrypted_row_carriers()[holder_index],
            fresh.encrypted_row_carriers()[holder_index]
        );
    }
}

#[test]
fn collective_coin_mailbox_domains_are_distinct_and_secret_debug_output_is_redacted() {
    let labels = [
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
        MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
    ];
    assert_eq!(labels.iter().copied().collect::<HashSet<_>>().len(), 6);

    let fixture = synthetic_completion_fixture(0x15);
    let authenticated_root = authenticate_root(&fixture, 0x35);
    let sealed_package = seal_fixture_package(&fixture, 0x45);
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let signature_bytes = sign_manifest(
        &manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        0x55,
    );
    let authenticated_manifest =
        verify_collective_coin_source_bivariate_mailbox_manifest_signature_320(
            &authenticated_root,
            &fixture.roster,
            &manifest_bytes,
            &signature_bytes,
        )
        .unwrap();
    let public_carrier = verify_collective_coin_source_bivariate_mailbox_public_carrier_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        &sealed_package.headers()[0].canonical_bytes().unwrap(),
        &sealed_package.encrypted_row_carriers()[0],
    )
    .unwrap();
    let delivery = complete_collective_coin_source_bivariate_mailbox_delivery_320(
        &authenticated_root,
        &fixture.roster,
        public_carrier,
        &fixture.mailbox_decapsulation_keys[0],
    )
    .unwrap();
    let output = format!("{sealed_package:?} {delivery:?}");
    assert!(output.contains("[redacted]"));
    assert!(!output.contains(&hex_prefix(&fixture.expected_source)));
    assert!(!output.contains(&hex_prefix(&fixture.expected_commitment_salt)));
}

fn seal_fixture_package(
    fixture: &CompletionFixture,
    marker: u8,
) -> SealedCollectiveCoinSourceBivariateMailboxPackage320 {
    seal_collective_coin_source_bivariate_mailbox_package_320(
        &fixture.inventory,
        &fixture.roster,
        &deterministic_encapsulation_randomness(FOUNDATION_PROFILE.participant_count, marker),
    )
    .unwrap()
}

fn sign_manifest(
    manifest_bytes: &[u8],
    signing_key: &ml_dsa_65::PrivateKey,
    signature_marker: u8,
) -> Vec<u8> {
    let manifest_identity = hash_foundation_tuple_512(
        COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(manifest_bytes).unwrap()],
    )
    .unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[signature_marker; 32],
            manifest_bytes,
            COLLECTIVE_COIN_SOURCE_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
        )
        .unwrap();
    CollectiveCoinSourceBivariateMailboxSignatureEnvelope320::new(manifest_identity, signature)
        .canonical_bytes()
        .unwrap()
}

fn deterministic_encapsulation_randomness(participant_count: u16, marker: u8) -> Vec<[u8; 32]> {
    (0..participant_count)
        .map(|holder_position| {
            let mut randomness = [marker; 32];
            randomness[0] ^= u8::try_from(holder_position).unwrap();
            randomness[31] = marker.wrapping_add(u8::try_from(holder_position).unwrap());
            randomness
        })
        .collect()
}

fn decode_tuple(bytes: &[u8]) -> CanonicalTuple {
    CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).unwrap()
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
