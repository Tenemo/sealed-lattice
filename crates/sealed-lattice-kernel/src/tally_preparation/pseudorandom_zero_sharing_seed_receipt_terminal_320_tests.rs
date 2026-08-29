use fips204::{ml_dsa_65, traits::Signer};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    FOUNDATION_PROFILE, Hash512,
};

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedMailboxTestFixture320, seed_mailbox_test_fixture_320,
    },
    pseudorandom_zero_sharing_seed_receipt_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedReceiptError320,
        PseudorandomZeroSharingSeedRecipientReceiptBody320,
        RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_320,
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedReceiptTerminalError320,
        PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320,
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320,
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320,
        VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320,
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320,
        pseudorandom_zero_sharing_seed_recipient_receipt_inventory_body_byte_length,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320,
    },
};

const COMPLETION_RECEIPT_INVENTORY_BODY_BYTE_LENGTH: usize = 850;
const COMPLETION_RECEIPT_TERMINAL_CERTIFICATE_BYTE_LENGTH: usize = 36_340;

#[test]
fn all_roster_terminal_binds_one_semantic_receipt_inventory() {
    let fixture = seed_mailbox_test_fixture_320(0, 1);
    let (first_receipt_envelopes, alternate_receipt_envelopes, retained_first_recipient_receipt) =
        signed_receipt_envelopes_from_authenticated_deliveries(0x31, 0x41, 0x51);
    let first_inventory = verified_receipt_inventory(&fixture, &first_receipt_envelopes);
    let alternate_inventory = verified_receipt_inventory(&fixture, &alternate_receipt_envelopes);

    assert_eq!(
        first_inventory.body().participant_count(),
        FOUNDATION_PROFILE.participant_count
    );
    assert_eq!(
        first_inventory.body().root_terminal_identity(),
        fixture.root_terminal.identity().unwrap()
    );
    assert_eq!(first_inventory.body().receipt_body_identities().len(), 10);
    assert_eq!(first_inventory.receipts().len(), 10);
    assert_eq!(
        first_inventory.body().canonical_bytes().unwrap().len(),
        COMPLETION_RECEIPT_INVENTORY_BODY_BYTE_LENGTH
    );
    assert_eq!(
        first_inventory.identity().unwrap(),
        alternate_inventory.identity().unwrap(),
        "fresh receipt-signature randomness must not fork the semantic inventory"
    );
    assert_ne!(
        first_inventory.receipts()[0].receipt_envelope_identity(),
        alternate_inventory.receipts()[0].receipt_envelope_identity(),
        "the exact receipt carriers must still bind their signature randomness"
    );

    let terminal_body =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(&first_inventory).unwrap();
    let different_receipt_envelopes = signed_receipt_envelopes(
        &fixture,
        0x91,
        0xa1,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    let different_receipt_inventory =
        verified_receipt_inventory(&fixture, &different_receipt_envelopes);
    assert!(matches!(
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            fixture.root_terminal.clone(),
            different_receipt_inventory,
            &fixture.roster,
            &retained_first_recipient_receipt,
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::RetainedLocalReceiptMismatch {
                field: "body"
            }
        )
    ));
    assert!(matches!(
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            fixture.root_terminal.clone(),
            alternate_inventory.clone(),
            &fixture.roster,
            &retained_first_recipient_receipt,
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::RetainedLocalReceiptMismatch {
                field: "envelope identity"
            }
        )
    ));

    let zero_randomness_preparation =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            fixture.root_terminal.clone(),
            first_inventory.clone(),
            &fixture.roster,
            &retained_first_recipient_receipt,
        )
        .unwrap();
    assert!(matches!(
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            zero_randomness_preparation,
            &fixture.roster,
            &fixture.signing_keys[0],
            [0; 32],
        ),
        Err(PseudorandomZeroSharingSeedReceiptTerminalError320::InvalidSignatureRandomness)
    ));

    let wrong_key_preparation =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            fixture.root_terminal.clone(),
            first_inventory.clone(),
            &fixture.roster,
            &retained_first_recipient_receipt,
        )
        .unwrap();
    assert!(matches!(
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            wrong_key_preparation,
            &fixture.roster,
            &fixture.signing_keys[1],
            [0x61; 32],
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorserSigningKeyMismatch {
                endorser_position: 0
            }
        )
    ));

    let prepared_endorsement =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            fixture.root_terminal.clone(),
            first_inventory.clone(),
            &fixture.roster,
            &retained_first_recipient_receipt,
        )
        .unwrap();
    assert_eq!(prepared_endorsement.endorser_position(), 0);
    assert_eq!(prepared_endorsement.terminal_body(), terminal_body);
    assert_eq!(
        prepared_endorsement.root_terminal().identity().unwrap(),
        fixture.root_terminal.identity().unwrap()
    );
    assert_eq!(
        prepared_endorsement.receipt_inventory().identity().unwrap(),
        first_inventory.identity().unwrap()
    );
    let produced_endorsement =
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            prepared_endorsement,
            &fixture.roster,
            &fixture.signing_keys[0],
            [0x61; 32],
        )
        .unwrap();
    assert_eq!(
        produced_endorsement.endorsement_envelope_bytes().len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH
    );
    assert_eq!(
        produced_endorsement.endorsement_envelope_bytes(),
        produced_endorsement
            .endorsement_envelope()
            .canonical_bytes()
            .unwrap()
    );
    assert!(format!("{produced_endorsement:?}").contains("[redacted]"));

    let alternate_randomness_preparation =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            fixture.root_terminal.clone(),
            first_inventory.clone(),
            &fixture.roster,
            &retained_first_recipient_receipt,
        )
        .unwrap();
    let alternate_randomness_endorsement =
        produce_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            alternate_randomness_preparation,
            &fixture.roster,
            &fixture.signing_keys[0],
            [0x62; 32],
        )
        .unwrap();
    assert_eq!(
        produced_endorsement.prepared_endorsement().terminal_body(),
        alternate_randomness_endorsement
            .prepared_endorsement()
            .terminal_body()
    );
    assert_ne!(
        produced_endorsement.endorsement_envelope_bytes(),
        alternate_randomness_endorsement.endorsement_envelope_bytes()
    );

    let mut first_endorsement_envelopes = signed_terminal_endorsement_envelopes(
        terminal_body,
        &fixture.signing_keys,
        0x61,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    );
    let (produced_preparation, produced_envelope, produced_envelope_bytes) =
        produced_endorsement.into_parts();
    assert_eq!(produced_preparation.terminal_body(), terminal_body);
    assert_eq!(
        produced_envelope_bytes,
        produced_envelope.canonical_bytes().unwrap()
    );
    first_endorsement_envelopes[0] = produced_envelope;
    let first_certificate = PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
        terminal_body,
        first_endorsement_envelopes,
    )
    .unwrap();
    let alternate_certificate = signed_terminal_certificate(
        &alternate_inventory,
        &fixture.signing_keys,
        0x71,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    );

    assert_eq!(
        terminal_body.receipt_inventory_identity(),
        first_inventory.identity().unwrap()
    );
    assert_eq!(
        terminal_body.participant_count(),
        FOUNDATION_PROFILE.participant_count
    );
    assert_eq!(
        terminal_body.canonical_bytes().unwrap().len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_BYTE_LENGTH
    );
    assert_eq!(
        first_certificate.canonical_bytes().unwrap().len(),
        COMPLETION_RECEIPT_TERMINAL_CERTIFICATE_BYTE_LENGTH
    );
    assert_eq!(first_certificate.endorsement_envelopes().len(), 10);
    assert_eq!(
        first_certificate.endorsement_envelopes()[0]
            .authorization_body()
            .canonical_bytes()
            .unwrap()
            .len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH
    );
    assert_eq!(
        first_certificate.endorsement_envelopes()[0]
            .canonical_bytes()
            .unwrap()
            .len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH
    );
    assert!(format!("{first_certificate:?}").contains("[redacted]"));
    assert!(format!("{:?}", first_certificate.endorsement_envelopes()[0]).contains("[redacted]"));

    let first_terminal = verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
        fixture.root_terminal.clone(),
        first_inventory,
        &fixture.roster,
        &first_certificate.canonical_bytes().unwrap(),
    )
    .unwrap();
    let alternate_terminal = verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
        fixture.root_terminal.clone(),
        alternate_inventory,
        &fixture.roster,
        &alternate_certificate.canonical_bytes().unwrap(),
    )
    .unwrap();

    assert_eq!(first_terminal.terminal_body(), terminal_body);
    assert_eq!(
        first_terminal.identity().unwrap(),
        terminal_body.identity().unwrap()
    );
    assert_eq!(
        first_terminal.identity().unwrap(),
        alternate_terminal.identity().unwrap(),
        "receipt and terminal signature randomness must not fork the semantic terminal"
    );
    assert_ne!(
        first_terminal.certificate_identity(),
        alternate_terminal.certificate_identity(),
        "terminal certificate identities must bind exact signature carriers"
    );
    assert_eq!(
        first_terminal.root_terminal().identity().unwrap(),
        fixture.root_terminal.identity().unwrap()
    );
    assert_eq!(
        first_terminal.receipt_inventory().identity().unwrap(),
        terminal_body.receipt_inventory_identity()
    );
}

#[test]
fn receipt_inventory_refuses_missing_reordered_duplicate_forged_and_wrong_scope_receipts() {
    let fixture = seed_mailbox_test_fixture_320(0, 1);
    let receipt_envelopes = signed_receipt_envelopes(
        &fixture,
        0x81,
        0x91,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );

    assert!(matches!(
        verify_receipt_inventory(&fixture, &receipt_envelopes[..9]),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::ReceiptCount {
                expected: 10,
                actual: 9,
            }
        )
    ));
    let mut extra_receipts = receipt_envelopes.clone();
    extra_receipts.push(receipt_envelopes[0].clone());
    assert!(matches!(
        verify_receipt_inventory(&fixture, &extra_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::ReceiptCount {
                expected: 10,
                actual: 11,
            }
        )
    ));

    let mut reordered_receipts = receipt_envelopes.clone();
    reordered_receipts.swap(2, 3);
    assert!(matches!(
        verify_receipt_inventory(&fixture, &reordered_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                recipient_position: 2,
                error: PseudorandomZeroSharingSeedReceiptError320::ObjectMismatch {
                    field: "recipient position",
                },
            }
        )
    ));
    let mut duplicate_receipts = receipt_envelopes.clone();
    duplicate_receipts[4] = receipt_envelopes[3].clone();
    assert!(matches!(
        verify_receipt_inventory(&fixture, &duplicate_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                recipient_position: 4,
                error: PseudorandomZeroSharingSeedReceiptError320::ObjectMismatch {
                    field: "recipient position",
                },
            }
        )
    ));

    let mut forged_receipts = receipt_envelopes.clone();
    *forged_receipts[7].last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        verify_receipt_inventory(&fixture, &forged_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                recipient_position: 7,
                error: PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature,
            }
        )
    ));

    let mut wrong_signer_receipts = receipt_envelopes.clone();
    wrong_signer_receipts[5] = signed_receipt_envelope(
        &fixture,
        5,
        6,
        Hash512::from_bytes([0xa5; Hash512::BYTE_LENGTH]),
        fixture.root_terminal.identity().unwrap(),
        0xa7,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    assert!(matches!(
        verify_receipt_inventory(&fixture, &wrong_signer_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                recipient_position: 5,
                error: PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature,
            }
        )
    ));

    let mut wrong_context_receipts = receipt_envelopes.clone();
    wrong_context_receipts[1] = signed_receipt_envelope(
        &fixture,
        1,
        1,
        Hash512::from_bytes([0xa1; Hash512::BYTE_LENGTH]),
        fixture.root_terminal.identity().unwrap(),
        0xa3,
        b"sealed-lattice/v1/preparation/wrong-seed-recipient-receipt",
    );
    assert!(matches!(
        verify_receipt_inventory(&fixture, &wrong_context_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                recipient_position: 1,
                error: PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature,
            }
        )
    ));

    let mut wrong_scope_receipts = receipt_envelopes.clone();
    wrong_scope_receipts[8] = signed_receipt_envelope(
        &fixture,
        8,
        8,
        Hash512::from_bytes([0xb1; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0xb3; Hash512::BYTE_LENGTH]),
        0xb5,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    assert!(matches!(
        verify_receipt_inventory(&fixture, &wrong_scope_receipts),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                recipient_position: 8,
                error: PseudorandomZeroSharingSeedReceiptError320::ObjectMismatch {
                    field: "root-terminal identity",
                },
            }
        )
    ));

    let mut wrong_roster = fixture.roster.clone();
    wrong_roster.entries[0].mailbox_encapsulation_key[0] ^= 0x01;
    let receipt_references = receipt_envelopes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320(
            &fixture.root_terminal,
            &wrong_roster,
            &receipt_references,
        ),
        Err(PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch)
    );
}

#[test]
fn terminal_refuses_incomplete_reordered_forged_mismatched_and_noncanonical_certificates() {
    let fixture = seed_mailbox_test_fixture_320(0, 1);
    let receipt_envelopes = signed_receipt_envelopes(
        &fixture,
        0xc1,
        0xd1,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    let receipt_inventory = verified_receipt_inventory(&fixture, &receipt_envelopes);
    let terminal_body =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(&receipt_inventory)
            .unwrap();
    let endorsement_envelopes = signed_terminal_endorsement_envelopes(
        terminal_body,
        &fixture.signing_keys,
        0xe1,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    );

    assert!(matches!(
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
            terminal_body,
            endorsement_envelopes[..9].to_vec(),
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementCount {
                expected: 10,
                actual: 9,
            }
        )
    ));
    let mut extra_endorsements = endorsement_envelopes.clone();
    extra_endorsements.push(endorsement_envelopes[0].clone());
    assert!(matches!(
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
            terminal_body,
            extra_endorsements,
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementCount {
                expected: 10,
                actual: 11,
            }
        )
    ));
    let mut reordered_endorsements = endorsement_envelopes.clone();
    reordered_endorsements.swap(3, 4);
    assert_eq!(
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
            terminal_body,
            reordered_endorsements,
        ),
        Err(PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementOrder)
    );
    let mut duplicate_endorsements = endorsement_envelopes.clone();
    duplicate_endorsements[6] = endorsement_envelopes[5].clone();
    assert_eq!(
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
            terminal_body,
            duplicate_endorsements,
        ),
        Err(PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementOrder)
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320::new(
            terminal_body,
            FOUNDATION_PROFILE.participant_count,
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorserPositionOutOfRange {
                endorser_position: 10,
                participant_count: 10,
            }
        )
    ));

    let certificate = PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
        terminal_body,
        endorsement_envelopes,
    )
    .unwrap();
    let certificate_bytes = certificate.canonical_bytes().unwrap();
    let mut forged_certificate_bytes = certificate_bytes.clone();
    *forged_certificate_bytes.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
            fixture.root_terminal.clone(),
            receipt_inventory.clone(),
            &fixture.roster,
            &forged_certificate_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::InvalidEndorsementSignature {
                endorser_position: 9,
            }
        )
    ));

    let wrong_context_certificate = signed_terminal_certificate(
        &receipt_inventory,
        &fixture.signing_keys,
        0xf1,
        b"sealed-lattice/v1/preparation/wrong-seed-receipt-terminal",
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
            fixture.root_terminal.clone(),
            receipt_inventory.clone(),
            &fixture.roster,
            &wrong_context_certificate.canonical_bytes().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::InvalidEndorsementSignature {
                endorser_position: 0,
            }
        )
    ));

    let mut wrong_roster = fixture.roster.clone();
    wrong_roster.entries[0].mailbox_encapsulation_key[0] ^= 0x01;
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
            fixture.root_terminal.clone(),
            receipt_inventory.clone(),
            &wrong_roster,
            &certificate_bytes,
        ),
        Err(PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch)
    );

    let changed_receipt_envelopes = signed_receipt_envelopes(
        &fixture,
        0x13,
        0x15,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    );
    let changed_inventory = verified_receipt_inventory(&fixture, &changed_receipt_envelopes);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
            fixture.root_terminal.clone(),
            changed_inventory,
            &fixture.roster,
            &certificate_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::ObjectMismatch {
                field: "receipt-inventory identity",
            }
        )
    ));

    for truncated_byte_length in [0, 1, 7, 8, 149, 1_024, certificate_bytes.len() - 1] {
        assert!(
            verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
                fixture.root_terminal.clone(),
                receipt_inventory.clone(),
                &fixture.roster,
                &certificate_bytes[..truncated_byte_length],
            )
            .is_err(),
            "accepted a {truncated_byte_length}-byte terminal certificate prefix"
        );
    }
    let mut trailing_certificate_bytes = certificate_bytes;
    trailing_certificate_bytes.push(0);
    assert!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
            fixture.root_terminal.clone(),
            receipt_inventory.clone(),
            &fixture.roster,
            &trailing_certificate_bytes,
        )
        .is_err()
    );
    assert!(
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
            fixture.root_terminal,
            receipt_inventory,
            &fixture.roster,
            &vec![0_u8; 131_073],
        )
        .is_err()
    );
}

#[test]
fn receipt_terminal_domains_and_lengths_are_exact_and_profile_derived() {
    let domains = [
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN,
    ];
    for (domain_index, domain) in domains.iter().enumerate() {
        assert!(domain.is_ascii());
        for other_domain in &domains[domain_index + 1..] {
            assert_ne!(domain, other_domain);
        }
    }
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN.as_bytes(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT
    );
    assert_eq!(
        pseudorandom_zero_sharing_seed_recipient_receipt_inventory_body_byte_length(
            FOUNDATION_PROFILE.participant_count,
        )
        .unwrap(),
        COMPLETION_RECEIPT_INVENTORY_BODY_BYTE_LENGTH
    );
    assert_eq!(
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::canonical_byte_length_for_participant_count(
            FOUNDATION_PROFILE.participant_count,
        )
        .unwrap(),
        COMPLETION_RECEIPT_TERMINAL_CERTIFICATE_BYTE_LENGTH
    );
    for unsupported_participant_count in [2, 21] {
        assert!(matches!(
            pseudorandom_zero_sharing_seed_recipient_receipt_inventory_body_byte_length(
                unsupported_participant_count,
            ),
            Err(PseudorandomZeroSharingSeedReceiptTerminalError320::GeometryMismatch)
        ));
        assert!(matches!(
            PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::canonical_byte_length_for_participant_count(
                unsupported_participant_count,
            ),
            Err(PseudorandomZeroSharingSeedReceiptTerminalError320::GeometryMismatch)
        ));
    }
}

pub(super) fn verified_receipt_inventory(
    fixture: &SeedMailboxTestFixture320,
    receipt_envelopes: &[Vec<u8>],
) -> VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320 {
    verify_receipt_inventory(fixture, receipt_envelopes).unwrap()
}

fn verify_receipt_inventory(
    fixture: &SeedMailboxTestFixture320,
    receipt_envelopes: &[Vec<u8>],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    let receipt_references = receipt_envelopes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320(
        &fixture.root_terminal,
        &fixture.roster,
        &receipt_references,
    )
}

fn signed_receipt_envelopes(
    fixture: &SeedMailboxTestFixture320,
    inventory_identity_marker: u8,
    signature_seed_marker: u8,
    signature_context: &[u8],
) -> Vec<Vec<u8>> {
    (0..FOUNDATION_PROFILE.participant_count)
        .map(|recipient_position| {
            signed_receipt_envelope(
                fixture,
                recipient_position,
                recipient_position,
                Hash512::from_bytes(
                    [inventory_identity_marker.wrapping_add(recipient_position as u8);
                        Hash512::BYTE_LENGTH],
                ),
                fixture.root_terminal.identity().unwrap(),
                signature_seed_marker.wrapping_add(recipient_position as u8),
                signature_context,
            )
        })
        .collect()
}

pub(super) fn signed_receipt_envelopes_with_inventory_marker_for_test(
    fixture: &SeedMailboxTestFixture320,
    inventory_identity_marker: u8,
    signature_seed_marker: u8,
) -> Vec<Vec<u8>> {
    signed_receipt_envelopes(
        fixture,
        inventory_identity_marker,
        signature_seed_marker,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    )
}

pub(super) fn signed_receipt_envelopes_from_authenticated_deliveries(
    encapsulation_marker: u8,
    first_signature_seed_marker: u8,
    alternate_signature_seed_marker: u8,
) -> (
    Vec<Vec<u8>>,
    Vec<Vec<u8>>,
    RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
) {
    let mut first_receipt_envelopes = Vec::new();
    let mut alternate_receipt_envelopes = Vec::new();
    let mut retained_first_recipient_receipt = None;
    for recipient_position in 0..FOUNDATION_PROFILE.participant_count {
        let (fixture, authenticated_deliveries) =
            super::pseudorandom_zero_sharing_seed_receipt_320_tests::authenticated_delivery_set(
                recipient_position,
                encapsulation_marker.wrapping_add((recipient_position as u8).wrapping_mul(0x10)),
            );
        let authenticated_inventory =
            verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
                &fixture.root_terminal,
                recipient_position,
                authenticated_deliveries,
            )
            .unwrap();
        let receipt_body =
            PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&authenticated_inventory)
                .unwrap();
        let alternate_receipt_envelope =
            super::pseudorandom_zero_sharing_seed_receipt_320_tests::sign_receipt(
                &fixture,
                receipt_body,
                recipient_position,
                alternate_signature_seed_marker.wrapping_add(recipient_position as u8),
                PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
            );
        let first_signature_seed_marker =
            first_signature_seed_marker.wrapping_add(recipient_position as u8);
        let first_receipt_envelope = if recipient_position == 0 {
            let produced_receipt = produce_pseudorandom_zero_sharing_seed_recipient_receipt_320(
                &fixture.root_terminal,
                &fixture.roster,
                authenticated_inventory,
                &fixture.signing_keys[usize::from(recipient_position)],
                [first_signature_seed_marker; 32],
            )
            .unwrap();
            assert_eq!(
                produced_receipt
                    .roster_authenticated_receipt()
                    .receipt_body(),
                receipt_body
            );
            let (verified_receipt, receipt_envelope_bytes) = produced_receipt.into_parts();
            retained_first_recipient_receipt = Some(verified_receipt);
            receipt_envelope_bytes
        } else {
            let receipt_envelope_bytes =
                super::pseudorandom_zero_sharing_seed_receipt_320_tests::sign_receipt(
                    &fixture,
                    receipt_body,
                    recipient_position,
                    first_signature_seed_marker,
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
                );
            let verified_receipt = verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
                &fixture.root_terminal,
                &fixture.roster,
                authenticated_inventory,
                &receipt_envelope_bytes,
            )
            .unwrap();
            assert_eq!(verified_receipt.receipt_body(), receipt_body);
            receipt_envelope_bytes
        };
        first_receipt_envelopes.push(first_receipt_envelope);
        alternate_receipt_envelopes.push(alternate_receipt_envelope);
    }
    (
        first_receipt_envelopes,
        alternate_receipt_envelopes,
        retained_first_recipient_receipt.unwrap(),
    )
}

pub(super) fn signed_receipt_envelopes_from_authenticated_deliveries_with_parameter_identity(
    parameter_identity: Hash512,
    encapsulation_marker: u8,
    signature_seed_marker: u8,
) -> Vec<Vec<u8>> {
    (0..FOUNDATION_PROFILE.participant_count)
        .map(|recipient_position| {
            let (fixture, authenticated_deliveries) =
                super::pseudorandom_zero_sharing_seed_receipt_320_tests::authenticated_delivery_set_with_parameter_identity(
                    parameter_identity,
                    recipient_position,
                    encapsulation_marker
                        .wrapping_add((recipient_position as u8).wrapping_mul(0x10)),
                );
            let authenticated_inventory =
                verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
                    &fixture.root_terminal,
                    recipient_position,
                    authenticated_deliveries,
                )
                .unwrap();
            let receipt_body =
                PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&authenticated_inventory)
                    .unwrap();
            let receipt_envelope_bytes =
                super::pseudorandom_zero_sharing_seed_receipt_320_tests::sign_receipt(
                    &fixture,
                    receipt_body,
                    recipient_position,
                    signature_seed_marker.wrapping_add(recipient_position as u8),
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
                );
            verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
                &fixture.root_terminal,
                &fixture.roster,
                authenticated_inventory,
                &receipt_envelope_bytes,
            )
            .unwrap();
            receipt_envelope_bytes
        })
        .collect()
}

fn signed_receipt_envelope(
    fixture: &SeedMailboxTestFixture320,
    recipient_position: u16,
    signer_position: u16,
    authenticated_inventory_identity: Hash512,
    root_terminal_identity: Hash512,
    signature_seed_marker: u8,
    signature_context: &[u8],
) -> Vec<u8> {
    let root_inventory_body = fixture.root_terminal.root_inventory().body();
    let receipt_body_bytes = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::nonempty_ascii(
                PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
            )
            .unwrap(),
            CanonicalItem::hash512(root_inventory_body.parameter_identity().into_bytes()),
            CanonicalItem::hash512(
                root_inventory_body
                    .preparation_context_identity()
                    .into_bytes(),
            ),
            CanonicalItem::unsigned16(0),
            CanonicalItem::hash512(root_terminal_identity.into_bytes()),
            CanonicalItem::unsigned16(root_inventory_body.participant_count()),
            CanonicalItem::unsigned16(recipient_position),
            CanonicalItem::hash512(authenticated_inventory_identity.into_bytes()),
        ],
    )
    .encode()
    .unwrap();
    let signature = fixture.signing_keys[usize::from(signer_position)]
        .try_sign_with_seed(
            &[signature_seed_marker; 32],
            &receipt_body_bytes,
            signature_context,
        )
        .unwrap();
    CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::nonempty_ascii(
                PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
            )
            .unwrap(),
            CanonicalItem::variable_bytes(receipt_body_bytes).unwrap(),
            CanonicalItem::fixed_bytes(signature).unwrap(),
        ],
    )
    .encode()
    .unwrap()
}

pub(super) fn signed_terminal_certificate(
    receipt_inventory: &VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    signature_seed_marker: u8,
    signature_context: &[u8],
) -> PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320 {
    let terminal_body =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(receipt_inventory).unwrap();
    PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::new(
        terminal_body,
        signed_terminal_endorsement_envelopes(
            terminal_body,
            signing_keys,
            signature_seed_marker,
            signature_context,
        ),
    )
    .unwrap()
}

fn signed_terminal_endorsement_envelopes(
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    signature_seed_marker: u8,
    signature_context: &[u8],
) -> Vec<PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320> {
    (0..terminal_body.participant_count())
        .map(|endorser_position| {
            let authorization_body =
                PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320::new(
                    terminal_body,
                    endorser_position,
                )
                .unwrap();
            let signature = signing_keys[usize::from(endorser_position)]
                .try_sign_with_seed(
                    &[signature_seed_marker.wrapping_add(endorser_position as u8); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    signature_context,
                )
                .unwrap();
            PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect()
}
