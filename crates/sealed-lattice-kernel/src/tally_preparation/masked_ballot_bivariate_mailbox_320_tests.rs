use std::collections::HashSet;

use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use crate::{
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512, Roster,
        RosterEntry, hash_foundation_tuple_512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bivariate_commitment_320::{
        AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        MaskedBallotBivariateCommitmentInventory320, MaskedBallotBivariateCommitmentLayout320,
        MaskedBallotBivariateCommitmentRootBody320,
        MaskedBallotBivariateCommitmentSignatureEnvelope320,
        verify_masked_ballot_bivariate_commitment_root_signature_320,
    },
    masked_ballot_bivariate_mailbox_320::{
        MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
        MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        MaskedBallotBivariateMailboxError320, MaskedBallotBivariateMailboxSignatureEnvelope320,
        SealedMaskedBallotBivariateMailboxPackage320,
        complete_masked_ballot_bivariate_mailbox_delivery_320,
        hash_masked_ballot_bivariate_mailbox_carrier_for_test,
        masked_ballot_bivariate_mailbox_manifest_body_byte_length,
        seal_masked_ballot_bivariate_mailbox_package_320,
        verify_masked_ballot_bivariate_mailbox_manifest_signature_320,
        verify_masked_ballot_bivariate_mailbox_public_carrier_320,
    },
    masked_ballot_bivariate_sharing_320::MaskedBallotSymmetricBivariatePolynomial320,
    masked_ballot_bundle_320::{MaskedBallotBundle320, masked_ballot_bundle_input_bit_count},
    pseudorandom_zero_sharing_seed_mailbox_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
    },
};

#[test]
fn every_completion_holder_authenticates_one_signed_fixed_shape_carrier() {
    let fixture = completion_fixture(0x11, 0x21);
    let authenticated_root = authenticate_root(&fixture, 0x31);
    let encapsulation_randomness =
        deterministic_encapsulation_randomness(FOUNDATION_PROFILE.participant_count, 0x41);
    let sealed_package = seal_masked_ballot_bivariate_mailbox_package_320(
        &fixture.inventory,
        &fixture.roster,
        &encapsulation_randomness,
    )
    .unwrap();
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let manifest_signature_envelope_bytes = sign_manifest(
        &manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x51,
    );
    let authenticated_manifest = verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
        &authenticated_root,
        &fixture.roster,
        &manifest_bytes,
        &manifest_signature_envelope_bytes,
    )
    .unwrap();

    for holder_roster_position in 0..FOUNDATION_PROFILE.participant_count {
        let holder_index = usize::from(holder_roster_position);
        let header_bytes = sealed_package.headers()[holder_index]
            .canonical_bytes()
            .unwrap();
        let public_carrier = verify_masked_ballot_bivariate_mailbox_public_carrier_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            holder_roster_position,
            &header_bytes,
            &sealed_package.encrypted_row_carriers()[holder_index],
        )
        .unwrap();
        let delivery = complete_masked_ballot_bivariate_mailbox_delivery_320(
            &authenticated_root,
            &fixture.roster,
            public_carrier,
            &fixture.decapsulation_keys[holder_index],
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
            delivery.author_roster_position(),
            fixture.layout.author_roster_position()
        );
        assert_eq!(delivery.holder_roster_position(), holder_roster_position);
        assert_eq!(
            delivery.authenticated_private_row().row(),
            &fixture.polynomial.row(holder_roster_position).unwrap()
        );
        assert_eq!(
            delivery.retained_private_row_body_bytes(),
            fixture
                .inventory
                .private_row_body(holder_roster_position)
                .unwrap()
                .canonical_bytes()
                .unwrap()
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
}

#[test]
fn absent_and_present_bundles_have_identical_complete_mailbox_shapes() {
    let (roster, signing_keys, _) = roster_and_keys(FOUNDATION_PROFILE.participant_count, 0x61);
    let circuit = completion_circuit();
    let layout = MaskedBallotBivariateCommitmentLayout320::derive(
        deterministic_hash(0x71, 0),
        completion_context(&roster, &circuit, 0x72),
        deterministic_hash(0x73, 0),
        4,
    )
    .unwrap();
    let absent_bundle = MaskedBallotBundle320::from_canonical_bytes(
        &circuit,
        &vec![0_u8; canonical_bundle_byte_length(&circuit)],
    )
    .unwrap();
    let present_bundle = patterned_bundle(&circuit, 0x81);
    let absent_inventory = inventory_for_bundle(layout, &absent_bundle, 0x91);
    let present_inventory = inventory_for_bundle(layout, &present_bundle, 0xa1);
    let encapsulation_randomness =
        deterministic_encapsulation_randomness(FOUNDATION_PROFILE.participant_count, 0xb1);
    let absent_package = seal_masked_ballot_bivariate_mailbox_package_320(
        &absent_inventory,
        &roster,
        &encapsulation_randomness,
    )
    .unwrap();
    let present_package = seal_masked_ballot_bivariate_mailbox_package_320(
        &present_inventory,
        &roster,
        &encapsulation_randomness,
    )
    .unwrap();

    assert_eq!(
        MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        1_479
    );
    assert_eq!(
        masked_ballot_bivariate_mailbox_manifest_body_byte_length(
            FOUNDATION_PROFILE.participant_count
        )
        .unwrap(),
        1_653
    );
    assert_eq!(
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        3_476
    );
    assert_eq!(absent_package.headers().len(), 10);
    assert_eq!(absent_package.encrypted_row_carriers().len(), 10);
    for holder_index in 0..usize::from(FOUNDATION_PROFILE.participant_count) {
        let absent_header_bytes = absent_package.headers()[holder_index]
            .canonical_bytes()
            .unwrap();
        let present_header_bytes = present_package.headers()[holder_index]
            .canonical_bytes()
            .unwrap();
        assert_eq!(absent_header_bytes.len(), 1_479);
        assert_eq!(present_header_bytes.len(), 1_479);
        assert_ne!(absent_header_bytes, present_header_bytes);
        assert_eq!(
            absent_package.encrypted_row_carriers()[holder_index].len(),
            1_303
        );
        assert_eq!(
            present_package.encrypted_row_carriers()[holder_index].len(),
            1_303
        );
        assert_ne!(
            absent_package.encrypted_row_carriers()[holder_index],
            present_package.encrypted_row_carriers()[holder_index]
        );
    }
    let absent_manifest_bytes = absent_package.manifest().canonical_bytes().unwrap();
    let present_manifest_bytes = present_package.manifest().canonical_bytes().unwrap();
    assert_eq!(absent_manifest_bytes.len(), 1_653);
    assert_eq!(present_manifest_bytes.len(), 1_653);
    assert_ne!(absent_manifest_bytes, present_manifest_bytes);
    let absent_manifest_signature = sign_manifest(&absent_manifest_bytes, &signing_keys[4], 0xc1);
    let present_manifest_signature = sign_manifest(&present_manifest_bytes, &signing_keys[4], 0xd1);
    assert_eq!(absent_manifest_signature.len(), 3_476);
    assert_eq!(present_manifest_signature.len(), 3_476);

    let public_control_total = absent_inventory
        .root_body()
        .canonical_bytes()
        .unwrap()
        .len()
        + sign_root(absent_inventory.root_body(), &signing_keys[4], 0xe1).len()
        + absent_package
            .headers()
            .iter()
            .map(|header| header.canonical_bytes().unwrap().len())
            .sum::<usize>()
        + absent_manifest_bytes.len()
        + absent_manifest_signature.len();
    let private_carrier_total = absent_package
        .encrypted_row_carriers()
        .iter()
        .map(|carrier| carrier.len())
        .sum::<usize>();
    assert_eq!(public_control_total, 27_663);
    assert_eq!(private_carrier_total, 13_030);
}

#[test]
fn unsigned_replacements_refuse_before_recipient_decapsulation() {
    let fixture = completion_fixture(0x12, 0x22);
    let authenticated_root = authenticate_root(&fixture, 0x32);
    let sealed_package = seal_fixture_package(&fixture, 0x42);
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_manifest(
        &manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x52,
    );
    let authenticated_manifest = verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
        &authenticated_root,
        &fixture.roster,
        &manifest_bytes,
        &signature_envelope_bytes,
    )
    .unwrap();

    let mut changed_signature = signature_envelope_bytes.clone();
    *changed_signature.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
            &authenticated_root,
            &fixture.roster,
            &manifest_bytes,
            &changed_signature,
        ),
        Err(MaskedBallotBivariateMailboxError320::InvalidAuthorSignature)
    ));

    let header_bytes = sealed_package.headers()[0].canonical_bytes().unwrap();
    let mut changed_carrier = sealed_package.encrypted_row_carriers()[0].to_vec();
    changed_carrier[17] ^= 0x40;
    assert!(matches!(
        verify_masked_ballot_bivariate_mailbox_public_carrier_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            0,
            &header_bytes,
            &changed_carrier,
        ),
        Err(
            MaskedBallotBivariateMailboxError320::CarrierDigestMismatch {
                holder_roster_position: 0
            }
        )
    ));

    let holder_one_header_bytes = sealed_package.headers()[1].canonical_bytes().unwrap();
    assert!(
        verify_masked_ballot_bivariate_mailbox_public_carrier_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            0,
            &holder_one_header_bytes,
            &sealed_package.encrypted_row_carriers()[1],
        )
        .is_err()
    );

    let public_carrier = verify_masked_ballot_bivariate_mailbox_public_carrier_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        &header_bytes,
        &sealed_package.encrypted_row_carriers()[0],
    )
    .unwrap();
    assert!(matches!(
        complete_masked_ballot_bivariate_mailbox_delivery_320(
            &authenticated_root,
            &fixture.roster,
            public_carrier,
            &fixture.decapsulation_keys[1],
        ),
        Err(MaskedBallotBivariateMailboxError320::DecapsulationKeyMismatch)
    ));
}

#[test]
fn author_signed_bad_tag_is_an_authenticated_post_manifest_inconsistency() {
    let fixture = completion_fixture(0x13, 0x23);
    let authenticated_root = authenticate_root(&fixture, 0x33);
    let sealed_package = seal_fixture_package(&fixture, 0x43);
    let mut changed_carrier = sealed_package.encrypted_row_carriers()[0].to_vec();
    *changed_carrier.last_mut().unwrap() ^= 0x01;
    let changed_carrier_digest = hash_masked_ballot_bivariate_mailbox_carrier_for_test(
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
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x53,
    );
    let authenticated_manifest = verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
        &authenticated_root,
        &fixture.roster,
        &changed_manifest_bytes,
        &changed_manifest_signature,
    )
    .unwrap();
    let public_carrier = verify_masked_ballot_bivariate_mailbox_public_carrier_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        &sealed_package.headers()[0].canonical_bytes().unwrap(),
        &changed_carrier,
    )
    .unwrap();
    assert!(matches!(
        complete_masked_ballot_bivariate_mailbox_delivery_320(
            &authenticated_root,
            &fixture.roster,
            public_carrier,
            &fixture.decapsulation_keys[0],
        ),
        Err(MaskedBallotBivariateMailboxError320::AuthenticatedDecryptionFailed)
    ));
}

#[test]
fn deterministic_replay_is_exact_and_fresh_encapsulation_changes_every_carrier() {
    let fixture = completion_fixture(0x14, 0x24);
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
fn ballot_mailbox_domains_are_distinct_and_secret_debug_output_is_redacted() {
    let labels = [
        MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
    ];
    assert_eq!(labels.iter().copied().collect::<HashSet<_>>().len(), 4);

    let fixture = completion_fixture(0x15, 0x25);
    let authenticated_root = authenticate_root(&fixture, 0x35);
    let sealed_package = seal_fixture_package(&fixture, 0x45);
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let signature_bytes = sign_manifest(
        &manifest_bytes,
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x55,
    );
    let authenticated_manifest = verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
        &authenticated_root,
        &fixture.roster,
        &manifest_bytes,
        &signature_bytes,
    )
    .unwrap();
    let public_carrier = verify_masked_ballot_bivariate_mailbox_public_carrier_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        &sealed_package.headers()[0].canonical_bytes().unwrap(),
        &sealed_package.encrypted_row_carriers()[0],
    )
    .unwrap();
    let output = format!("{sealed_package:?} {public_carrier:?}");
    assert!(output.contains("[redacted]"));
    assert!(!output.contains(&"45".repeat(32)));
}

struct CompletionFixture {
    roster: Roster,
    signing_keys: Vec<ml_dsa_65::PrivateKey>,
    decapsulation_keys: Vec<ml_kem_768::DecapsKey>,
    layout: MaskedBallotBivariateCommitmentLayout320,
    polynomial: MaskedBallotSymmetricBivariatePolynomial320,
    inventory: MaskedBallotBivariateCommitmentInventory320,
}

fn completion_fixture(roster_marker: u8, bundle_marker: u8) -> CompletionFixture {
    let (roster, signing_keys, decapsulation_keys) =
        roster_and_keys(FOUNDATION_PROFILE.participant_count, roster_marker);
    let circuit = completion_circuit();
    let layout = MaskedBallotBivariateCommitmentLayout320::derive(
        deterministic_hash(roster_marker.wrapping_add(1), 0),
        completion_context(&roster, &circuit, roster_marker.wrapping_add(2)),
        deterministic_hash(roster_marker.wrapping_add(3), 0),
        4,
    )
    .unwrap();
    let bundle = patterned_bundle(&circuit, bundle_marker);
    let polynomial = polynomial_for_bundle(layout, &bundle, bundle_marker.wrapping_add(1));
    let inventory = MaskedBallotBivariateCommitmentInventory320::create(
        layout,
        &polynomial,
        deterministic_salts(layout.leaf_count(), bundle_marker.wrapping_add(2)),
    )
    .unwrap();
    CompletionFixture {
        roster,
        signing_keys,
        decapsulation_keys,
        layout,
        polynomial,
        inventory,
    }
}

fn seal_fixture_package(
    fixture: &CompletionFixture,
    marker: u8,
) -> SealedMaskedBallotBivariateMailboxPackage320 {
    seal_masked_ballot_bivariate_mailbox_package_320(
        &fixture.inventory,
        &fixture.roster,
        &deterministic_encapsulation_randomness(FOUNDATION_PROFILE.participant_count, marker),
    )
    .unwrap()
}

fn authenticate_root(
    fixture: &CompletionFixture,
    signature_marker: u8,
) -> AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320 {
    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        signature_marker,
    );
    verify_masked_ballot_bivariate_commitment_root_signature_320(
        fixture.layout,
        &root_body_bytes,
        &fixture.roster,
        &signature_envelope_bytes,
    )
    .unwrap()
}

fn sign_root(
    root_body: &MaskedBallotBivariateCommitmentRootBody320,
    signing_key: &ml_dsa_65::PrivateKey,
    signature_marker: u8,
) -> Vec<u8> {
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[signature_marker; 32],
            &root_body_bytes,
            MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    MaskedBallotBivariateCommitmentSignatureEnvelope320::new(
        root_body.identity().unwrap(),
        signature,
    )
    .canonical_bytes()
    .unwrap()
}

fn sign_manifest(
    manifest_bytes: &[u8],
    signing_key: &ml_dsa_65::PrivateKey,
    signature_marker: u8,
) -> Vec<u8> {
    let manifest_identity = hash_foundation_tuple_512(
        MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(manifest_bytes).unwrap()],
    )
    .unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[signature_marker; 32],
            manifest_bytes,
            MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
        )
        .unwrap();
    MaskedBallotBivariateMailboxSignatureEnvelope320::new(manifest_identity, signature)
        .canonical_bytes()
        .unwrap()
}

fn inventory_for_bundle(
    layout: MaskedBallotBivariateCommitmentLayout320,
    bundle: &MaskedBallotBundle320,
    marker: u8,
) -> MaskedBallotBivariateCommitmentInventory320 {
    let polynomial = polynomial_for_bundle(layout, bundle, marker);
    MaskedBallotBivariateCommitmentInventory320::create(
        layout,
        &polynomial,
        deterministic_salts(layout.leaf_count(), marker.wrapping_add(1)),
    )
    .unwrap()
}

fn polynomial_for_bundle(
    layout: MaskedBallotBivariateCommitmentLayout320,
    bundle: &MaskedBallotBundle320,
    marker: u8,
) -> MaskedBallotSymmetricBivariatePolynomial320 {
    let reconstruction_threshold = usize::from(layout.reconstruction_threshold());
    let random_coefficient_count =
        reconstruction_threshold * (reconstruction_threshold + 1) / 2 - 1;
    let random_coefficients = (0..random_coefficient_count)
        .map(|coefficient_position| {
            BinaryFieldElement320::from_low_polynomial_u16(
                u16::from(marker)
                    .wrapping_mul(257)
                    .wrapping_add(u16::try_from(coefficient_position + 1).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    MaskedBallotSymmetricBivariatePolynomial320::from_bundle_and_random_coefficients(
        layout.participant_count(),
        bundle,
        &random_coefficients,
    )
    .unwrap()
}

fn patterned_bundle(circuit: &CompiledTallyCircuit, marker: u8) -> MaskedBallotBundle320 {
    let mut bytes = vec![0_u8; canonical_bundle_byte_length(circuit)];
    for (byte_position, byte) in bytes.iter_mut().enumerate() {
        *byte = marker.wrapping_add(u8::try_from(byte_position).unwrap().wrapping_mul(29));
    }
    let input_bit_count = masked_ballot_bundle_input_bit_count(circuit).unwrap();
    let used_bit_count_in_last_byte = input_bit_count % 8;
    if used_bit_count_in_last_byte != 0 {
        let used_bit_mask = (1_u8 << used_bit_count_in_last_byte) - 1;
        *bytes.last_mut().unwrap() &= used_bit_mask;
    }
    MaskedBallotBundle320::from_canonical_bytes(circuit, &bytes).unwrap()
}

fn canonical_bundle_byte_length(circuit: &CompiledTallyCircuit) -> usize {
    masked_ballot_bundle_input_bit_count(circuit)
        .unwrap()
        .div_ceil(8)
}

fn deterministic_salts(
    leaf_count: u64,
    marker: u8,
) -> Vec<[u8; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]> {
    (0..leaf_count)
        .map(|leaf_ordinal| {
            let mut salt = [marker; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH];
            salt[..8].copy_from_slice(&leaf_ordinal.to_le_bytes());
            salt[63] ^= u8::try_from(leaf_ordinal % 251).unwrap();
            salt
        })
        .collect()
}

fn deterministic_encapsulation_randomness(participant_count: u16, marker: u8) -> Vec<[u8; 32]> {
    (0..participant_count)
        .map(|holder_roster_position| {
            let mut randomness = [marker; 32];
            randomness[0] ^= u8::try_from(holder_roster_position).unwrap();
            randomness[31] = marker.wrapping_add(u8::try_from(holder_roster_position).unwrap());
            randomness
        })
        .collect()
}

fn roster_and_keys(
    participant_count: u16,
    marker: u8,
) -> (
    Roster,
    Vec<ml_dsa_65::PrivateKey>,
    Vec<ml_kem_768::DecapsKey>,
) {
    let mut signing_keys = Vec::with_capacity(usize::from(participant_count));
    let mut decapsulation_keys = Vec::with_capacity(usize::from(participant_count));
    let entries = (0..participant_count)
        .map(|roster_position| {
            let mut signing_seed = [marker; 32];
            signing_seed[0] = marker.wrapping_add(u8::try_from(roster_position).unwrap());
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);

            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= u8::try_from(roster_position).unwrap();
            let mut mailbox_fallback_seed = [marker.wrapping_add(0x53); 32];
            mailbox_fallback_seed[31] ^= u8::try_from(roster_position).unwrap();
            let (mailbox_encapsulation_key, mailbox_decapsulation_key) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            decapsulation_keys.push(mailbox_decapsulation_key);
            RosterEntry::new(
                roster_position,
                signing_verification_key.into_bytes(),
                mailbox_encapsulation_key.into_bytes(),
            )
            .unwrap()
        })
        .collect();
    (
        Roster::new(entries).unwrap(),
        signing_keys,
        decapsulation_keys,
    )
}

fn completion_circuit() -> CompiledTallyCircuit {
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

fn completion_context(
    roster: &Roster,
    circuit: &CompiledTallyCircuit,
    marker: u8,
) -> TallyPreparationContext {
    TallyPreparationContext::new(
        deterministic_hash(0xd1, 0),
        roster.roster_hash().unwrap(),
        [marker; 32],
        circuit,
    )
    .unwrap()
}

fn deterministic_hash(marker: u8, ordinal: u64) -> Hash512 {
    let mut bytes = [marker; Hash512::BYTE_LENGTH];
    bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
    Hash512::from_bytes(bytes)
}

fn decode_tuple(bytes: &[u8]) -> CanonicalTuple {
    CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).unwrap()
}
