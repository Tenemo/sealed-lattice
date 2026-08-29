use fips204::traits::Signer;

use crate::foundation::{FOUNDATION_PROFILE, Hash512};

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedMailboxTestFixture320, seed_mailbox_test_fixture_320,
        seed_mailbox_test_fixture_with_parameter_identity_320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::PseudorandomZeroSharingSeedDeliveryError320,
    pseudorandom_zero_sharing_seed_mailbox_320::AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320,
    pseudorandom_zero_sharing_seed_mailbox_320_tests::authenticated_mailbox_delivery_320,
    pseudorandom_zero_sharing_seed_receipt_320::{
        PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedReceiptError320,
        PseudorandomZeroSharingSeedRecipientReceiptBody320,
        PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320,
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_320,
        pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length,
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320,
    },
};

#[test]
fn complete_authenticated_inventory_receives_exactly_one_recipient_signature() {
    let recipient_position = 6;
    let (fixture, authenticated_deliveries) = authenticated_delivery_set(recipient_position, 0x11);
    let inventory = verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
        &fixture.root_terminal,
        recipient_position,
        authenticated_deliveries,
    )
    .unwrap();

    assert_eq!(
        inventory.body().ordered_header_identities().len(),
        usize::from(FOUNDATION_PROFILE.participant_count - 1)
    );
    assert_eq!(
        inventory.body().ordered_manifest_identities().len(),
        usize::from(FOUNDATION_PROFILE.participant_count - 1)
    );
    assert_eq!(
        inventory.body().canonical_bytes().unwrap().len(),
        pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length(
            FOUNDATION_PROFILE.participant_count,
        )
        .unwrap()
    );
    assert_eq!(
        inventory.root_matched_inventory().deliveries().len(),
        usize::from(FOUNDATION_PROFILE.participant_count - 1)
    );
    let receipt_body = PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&inventory).unwrap();
    let receipt_envelope_bytes = sign_receipt(
        &fixture,
        receipt_body,
        recipient_position,
        0x31,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );

    assert_eq!(
        receipt_body.canonical_bytes().unwrap().len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH
    );
    assert_eq!(
        receipt_envelope_bytes.len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH
    );
    assert_eq!(receipt_body.recipient_position(), recipient_position);
    assert_eq!(
        receipt_body.parameter_identity(),
        inventory.body().parameter_identity()
    );
    assert_eq!(
        receipt_body.preparation_context_identity(),
        inventory.body().preparation_context_identity()
    );
    assert_eq!(
        receipt_body.root_terminal_identity(),
        inventory.body().root_terminal_identity()
    );
    assert_eq!(
        receipt_body.participant_count(),
        inventory.body().participant_count()
    );
    assert_eq!(
        receipt_body.authenticated_recipient_inventory_identity(),
        inventory.body().identity().unwrap()
    );
    assert!(format!("{inventory:?}").contains("[redacted]"));

    let produced_receipt = produce_pseudorandom_zero_sharing_seed_recipient_receipt_320(
        &fixture.root_terminal,
        &fixture.roster,
        inventory,
        &fixture.signing_keys[usize::from(recipient_position)],
        [0x31; 32],
    )
    .unwrap();
    assert_eq!(
        produced_receipt.receipt_envelope_bytes(),
        receipt_envelope_bytes
    );
    assert!(format!("{produced_receipt:?}").contains("receipt_envelope_byte_length: 3778"));
    let authenticated_receipt = produced_receipt.roster_authenticated_receipt();
    assert_eq!(authenticated_receipt.receipt_body(), receipt_body);
    assert_eq!(
        authenticated_receipt
            .recipient_inventory()
            .body()
            .recipient_position(),
        recipient_position
    );
    let _ = authenticated_receipt.receipt_envelope_identity();
    assert!(format!("{authenticated_receipt:?}").contains("[redacted]"));
    let (authenticated_receipt, receipt_envelope_bytes) = produced_receipt.into_parts();
    assert_eq!(
        receipt_envelope_bytes.len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH
    );
    let inventory = authenticated_receipt.into_recipient_inventory();
    let _ = inventory.into_root_matched_inventory();
}

#[test]
fn production_refuses_zero_randomness_and_a_nonrecipient_signing_key() {
    let recipient_position = 6;
    let (zero_randomness_fixture, zero_randomness_deliveries) =
        authenticated_delivery_set(recipient_position, 0x35);
    let zero_randomness_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &zero_randomness_fixture.root_terminal,
            recipient_position,
            zero_randomness_deliveries,
        )
        .unwrap();
    assert!(matches!(
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &zero_randomness_fixture.root_terminal,
            &zero_randomness_fixture.roster,
            zero_randomness_inventory,
            &zero_randomness_fixture.signing_keys[usize::from(recipient_position)],
            [0; 32],
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::InvalidSignatureRandomness)
    ));

    let (wrong_key_fixture, wrong_key_deliveries) =
        authenticated_delivery_set(recipient_position, 0x45);
    let wrong_key_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &wrong_key_fixture.root_terminal,
            recipient_position,
            wrong_key_deliveries,
        )
        .unwrap();
    assert!(matches!(
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &wrong_key_fixture.root_terminal,
            &wrong_key_fixture.roster,
            wrong_key_inventory,
            &wrong_key_fixture.signing_keys[usize::from(recipient_position + 1)],
            [0x47; 32],
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::RecipientSigningKeyMismatch)
    ));
}

#[test]
fn fresh_signature_randomness_changes_only_the_receipt_carrier_identity() {
    let recipient_position = 7;
    let (first_fixture, first_deliveries) = authenticated_delivery_set(recipient_position, 0x51);
    let first_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &first_fixture.root_terminal,
            recipient_position,
            first_deliveries,
        )
        .unwrap();
    let first_receipt = produce_pseudorandom_zero_sharing_seed_recipient_receipt_320(
        &first_fixture.root_terminal,
        &first_fixture.roster,
        first_inventory,
        &first_fixture.signing_keys[usize::from(recipient_position)],
        [0x53; 32],
    )
    .unwrap();

    let (alternate_fixture, alternate_deliveries) =
        authenticated_delivery_set(recipient_position, 0x51);
    let alternate_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &alternate_fixture.root_terminal,
            recipient_position,
            alternate_deliveries,
        )
        .unwrap();
    let alternate_receipt = produce_pseudorandom_zero_sharing_seed_recipient_receipt_320(
        &alternate_fixture.root_terminal,
        &alternate_fixture.roster,
        alternate_inventory,
        &alternate_fixture.signing_keys[usize::from(recipient_position)],
        [0x55; 32],
    )
    .unwrap();

    assert_eq!(
        first_receipt.roster_authenticated_receipt().receipt_body(),
        alternate_receipt
            .roster_authenticated_receipt()
            .receipt_body()
    );
    assert_ne!(
        first_receipt
            .roster_authenticated_receipt()
            .receipt_envelope_identity(),
        alternate_receipt
            .roster_authenticated_receipt()
            .receipt_envelope_identity()
    );
    assert_ne!(
        first_receipt.receipt_envelope_bytes(),
        alternate_receipt.receipt_envelope_bytes()
    );
}

#[test]
fn fresh_encryption_changes_receipt_identity_without_changing_semantic_seed_inventory() {
    let recipient_position = 8;
    let (first_fixture, first_deliveries) = authenticated_delivery_set(recipient_position, 0x41);
    let first_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &first_fixture.root_terminal,
            recipient_position,
            first_deliveries,
        )
        .unwrap();
    let (fresh_fixture, fresh_deliveries) = authenticated_delivery_set(recipient_position, 0x61);
    let fresh_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &fresh_fixture.root_terminal,
            recipient_position,
            fresh_deliveries,
        )
        .unwrap();

    assert_eq!(
        first_inventory
            .body()
            .semantic_recipient_inventory_identity(),
        fresh_inventory
            .body()
            .semantic_recipient_inventory_identity()
    );
    assert_ne!(
        first_inventory.body().ordered_header_identities(),
        fresh_inventory.body().ordered_header_identities()
    );
    assert_ne!(
        first_inventory.body().ordered_manifest_identities(),
        fresh_inventory.body().ordered_manifest_identities()
    );
    let first_receipt_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&first_inventory).unwrap();
    let fresh_receipt_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&fresh_inventory).unwrap();
    assert_ne!(
        first_receipt_body.authenticated_recipient_inventory_identity(),
        fresh_receipt_body.authenticated_recipient_inventory_identity()
    );
    assert_ne!(
        first_receipt_body.identity().unwrap(),
        fresh_receipt_body.identity().unwrap()
    );
}

#[test]
fn incomplete_reordered_and_duplicate_delivery_inventories_refuse() {
    let recipient_position = 9;

    let (missing_fixture, mut missing_deliveries) =
        authenticated_delivery_set(recipient_position, 0x71);
    missing_deliveries.remove(3);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &missing_fixture.root_terminal,
            recipient_position,
            missing_deliveries,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::Delivery(
            PseudorandomZeroSharingSeedDeliveryError320::DeliveryCount {
                expected: 9,
                actual: 8
            }
        ))
    ));

    let (reordered_fixture, mut reordered_deliveries) =
        authenticated_delivery_set(recipient_position, 0x81);
    reordered_deliveries.swap(2, 5);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &reordered_fixture.root_terminal,
            recipient_position,
            reordered_deliveries,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::Delivery(
            PseudorandomZeroSharingSeedDeliveryError320::DeliveryOrder { .. }
        ))
    ));

    let (duplicate_fixture, mut duplicate_deliveries) =
        authenticated_delivery_set(recipient_position, 0x91);
    let duplicate_sender_fixture = seed_mailbox_test_fixture_320(0, recipient_position);
    duplicate_deliveries[1] =
        authenticated_mailbox_delivery_320(&duplicate_sender_fixture, [0xa1; 32], 0xa3);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &duplicate_fixture.root_terminal,
            recipient_position,
            duplicate_deliveries,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::Delivery(
            PseudorandomZeroSharingSeedDeliveryError320::DeliveryOrder {
                expected_sender_position: 1,
                actual_sender_position: 0,
                ..
            }
        ))
    ));
}

#[test]
fn only_the_bound_recipient_key_and_context_authorize_a_receipt() {
    let recipient_position = 4;

    let (wrong_signer_fixture, wrong_signer_deliveries) =
        authenticated_delivery_set(recipient_position, 0xb1);
    let wrong_signer_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &wrong_signer_fixture.root_terminal,
            recipient_position,
            wrong_signer_deliveries,
        )
        .unwrap();
    let wrong_signer_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&wrong_signer_inventory).unwrap();
    let wrong_signer_bytes = sign_receipt(
        &wrong_signer_fixture,
        wrong_signer_body,
        5,
        0xb3,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &wrong_signer_fixture.root_terminal,
            &wrong_signer_fixture.roster,
            wrong_signer_inventory,
            &wrong_signer_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature)
    ));

    let (wrong_context_fixture, wrong_context_deliveries) =
        authenticated_delivery_set(recipient_position, 0xc1);
    let wrong_context_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &wrong_context_fixture.root_terminal,
            recipient_position,
            wrong_context_deliveries,
        )
        .unwrap();
    let wrong_context_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&wrong_context_inventory).unwrap();
    let wrong_context_bytes = sign_receipt(
        &wrong_context_fixture,
        wrong_context_body,
        recipient_position,
        0xc3,
        b"sealed-lattice/v1/preparation/wrong-seed-recipient-receipt",
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &wrong_context_fixture.root_terminal,
            &wrong_context_fixture.roster,
            wrong_context_inventory,
            &wrong_context_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature)
    ));

    let (tampered_fixture, tampered_deliveries) =
        authenticated_delivery_set(recipient_position, 0xd1);
    let tampered_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &tampered_fixture.root_terminal,
            recipient_position,
            tampered_deliveries,
        )
        .unwrap();
    let tampered_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&tampered_inventory).unwrap();
    let mut tampered_bytes = sign_receipt(
        &tampered_fixture,
        tampered_body,
        recipient_position,
        0xd3,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    *tampered_bytes.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &tampered_fixture.root_terminal,
            &tampered_fixture.roster,
            tampered_inventory,
            &tampered_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature)
    ));
}

#[test]
fn mismatched_roster_and_receipt_inventory_are_not_interchangeable() {
    let recipient_position = 3;
    let (fixture, deliveries) = authenticated_delivery_set(recipient_position, 0xe1);
    let inventory = verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
        &fixture.root_terminal,
        recipient_position,
        deliveries,
    )
    .unwrap();
    let receipt_body = PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&inventory).unwrap();
    let receipt_bytes = sign_receipt(
        &fixture,
        receipt_body,
        recipient_position,
        0xe3,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    let mut wrong_roster = fixture.roster.clone();
    wrong_roster.entries[0].mailbox_encapsulation_key[0] ^= 0x01;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &fixture.root_terminal,
            &wrong_roster,
            inventory,
            &receipt_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::RosterMismatch)
    ));

    let (other_fixture, other_deliveries) = authenticated_delivery_set(5, 0xf1);
    let other_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &other_fixture.root_terminal,
            5,
            other_deliveries,
        )
        .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
            &other_fixture.root_terminal,
            &other_fixture.roster,
            other_inventory,
            &receipt_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::ObjectMismatch { .. })
    ));
}

#[test]
fn receipt_envelope_decoder_rejects_every_truncated_prefix_and_trailing_data() {
    let recipient_position = 2;
    let (fixture, deliveries) = authenticated_delivery_set(recipient_position, 0x21);
    let inventory = verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
        &fixture.root_terminal,
        recipient_position,
        deliveries,
    )
    .unwrap();
    let receipt_body = PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&inventory).unwrap();
    let receipt_bytes = sign_receipt(
        &fixture,
        receipt_body,
        recipient_position,
        0x23,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );

    let decoded_envelope =
        PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320::from_canonical_bytes(
            receipt_body,
            &receipt_bytes,
        )
        .unwrap();
    assert_eq!(decoded_envelope.receipt_body(), receipt_body);

    for prefix_byte_length in 0..receipt_bytes.len() {
        assert!(
            PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320::from_canonical_bytes(
                receipt_body,
                &receipt_bytes[..prefix_byte_length],
            )
            .is_err(),
            "accepted truncated prefix with {prefix_byte_length} bytes"
        );
    }
    let mut trailing_bytes = receipt_bytes;
    trailing_bytes.push(0);
    assert!(matches!(
        PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320::from_canonical_bytes(
            receipt_body,
            &trailing_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptError320::Canonical(_))
    ));
}

#[test]
fn receipt_domains_are_ascii_pairwise_distinct_and_signature_context_names_the_signed_body() {
    let domains = [
        PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_IDENTITY_DOMAIN,
    ];
    for (domain_index, domain) in domains.iter().enumerate() {
        assert!(domain.is_ascii());
        for other_domain in &domains[domain_index + 1..] {
            assert_ne!(domain, other_domain);
        }
    }
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN.as_bytes(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT
    );
}

#[test]
fn authenticated_inventory_length_refuses_unsupported_roster_sizes() {
    assert!(matches!(
        pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length(2),
        Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch)
    ));
    assert!(matches!(
        pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length(21),
        Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch)
    ));
}

pub(super) fn authenticated_delivery_set(
    recipient_position: u16,
    encapsulation_marker: u8,
) -> (
    SeedMailboxTestFixture320,
    Vec<AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320>,
) {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let first_sender_position = if recipient_position == 0 { 1 } else { 0 };
    let owner_fixture = seed_mailbox_test_fixture_320(first_sender_position, recipient_position);
    let authenticated_deliveries = (0..participant_count)
        .filter(|sender_position| *sender_position != recipient_position)
        .map(|sender_position| {
            let randomness_marker = encapsulation_marker.wrapping_add(sender_position as u8);
            if sender_position == first_sender_position {
                authenticated_mailbox_delivery_320(
                    &owner_fixture,
                    [randomness_marker; 32],
                    randomness_marker.wrapping_add(0x20),
                )
            } else {
                let sender_fixture =
                    seed_mailbox_test_fixture_320(sender_position, recipient_position);
                assert_eq!(
                    sender_fixture.root_terminal.identity().unwrap(),
                    owner_fixture.root_terminal.identity().unwrap()
                );
                authenticated_mailbox_delivery_320(
                    &sender_fixture,
                    [randomness_marker; 32],
                    randomness_marker.wrapping_add(0x20),
                )
            }
        })
        .collect();
    (owner_fixture, authenticated_deliveries)
}

pub(super) fn authenticated_delivery_set_with_parameter_identity(
    parameter_identity: Hash512,
    recipient_position: u16,
    encapsulation_marker: u8,
) -> (
    SeedMailboxTestFixture320,
    Vec<AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320>,
) {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let first_sender_position = if recipient_position == 0 { 1 } else { 0 };
    let owner_fixture = seed_mailbox_test_fixture_with_parameter_identity_320(
        first_sender_position,
        recipient_position,
        parameter_identity,
    );
    let authenticated_deliveries = (0..participant_count)
        .filter(|sender_position| *sender_position != recipient_position)
        .map(|sender_position| {
            let randomness_marker = encapsulation_marker.wrapping_add(sender_position as u8);
            if sender_position == first_sender_position {
                authenticated_mailbox_delivery_320(
                    &owner_fixture,
                    [randomness_marker; 32],
                    randomness_marker.wrapping_add(0x20),
                )
            } else {
                let sender_fixture = seed_mailbox_test_fixture_with_parameter_identity_320(
                    sender_position,
                    recipient_position,
                    parameter_identity,
                );
                assert_eq!(
                    sender_fixture.root_terminal.identity().unwrap(),
                    owner_fixture.root_terminal.identity().unwrap()
                );
                authenticated_mailbox_delivery_320(
                    &sender_fixture,
                    [randomness_marker; 32],
                    randomness_marker.wrapping_add(0x20),
                )
            }
        })
        .collect();
    (owner_fixture, authenticated_deliveries)
}

pub(super) fn sign_receipt(
    fixture: &SeedMailboxTestFixture320,
    receipt_body: PseudorandomZeroSharingSeedRecipientReceiptBody320,
    signer_position: u16,
    signature_seed_marker: u8,
    signature_context: &[u8],
) -> Vec<u8> {
    let signature = fixture.signing_keys[usize::from(signer_position)]
        .try_sign_with_seed(
            &[signature_seed_marker; 32],
            &receipt_body.canonical_bytes().unwrap(),
            signature_context,
        )
        .unwrap();
    PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320::new(receipt_body, signature)
        .canonical_bytes()
        .unwrap()
}
