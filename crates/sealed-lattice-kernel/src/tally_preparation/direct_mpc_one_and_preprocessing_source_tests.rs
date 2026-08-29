use crate::foundation::{FOUNDATION_PROFILE, Hash512};

use super::{
    direct_mpc_one_and_preprocessing_source::{
        DirectMpcOneAndPreprocessingSourceError,
        direct_mpc_one_and_preprocessing_source_parameter_identity,
        verify_direct_mpc_one_and_preprocessing_source,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        build_action_context, seed_mailbox_test_fixture_with_parameter_identity_320,
    },
    pseudorandom_zero_sharing_seed_master_join_320_tests::verified_one_and_source_and_joined_custody,
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320_tests::{
        signed_receipt_envelopes_from_authenticated_deliveries_with_parameter_identity,
        signed_terminal_certificate, verified_receipt_inventory,
    },
};

#[test]
fn actual_seed_mailboxes_and_roster_terminals_mint_the_exact_one_and_source() {
    let parameter_identity = direct_mpc_one_and_preprocessing_source_parameter_identity().unwrap();
    let (fixture, receipt_terminal, joined_seed_masters) =
        verified_one_and_source_and_joined_custody(parameter_identity);
    let source =
        verify_direct_mpc_one_and_preprocessing_source(&fixture.roster, &receipt_terminal).unwrap();

    assert_eq!(source.parameter_identity(), parameter_identity);
    assert_eq!(source.preparation_context(), fixture.preparation_context);
    source
        .verify_action_roster_and_local_custody(
            &fixture.action_context,
            &fixture.roster,
            &joined_seed_masters,
        )
        .unwrap();
    let wrong_action_context = build_action_context(&fixture.roster, 0x2b);
    assert_eq!(
        source.verify_action_roster_and_local_custody(
            &wrong_action_context,
            &fixture.roster,
            &joined_seed_masters,
        ),
        Err(DirectMpcOneAndPreprocessingSourceError::WrongContext)
    );
    let mut wrong_roster = fixture.roster.clone();
    wrong_roster.entries[0].mailbox_encapsulation_key[0] ^= 1;
    assert_eq!(
        verify_direct_mpc_one_and_preprocessing_source(&wrong_roster, &receipt_terminal),
        Err(DirectMpcOneAndPreprocessingSourceError::WrongContext)
    );
    assert_ne!(
        source.identity(),
        Hash512::from_bytes([0; Hash512::BYTE_LENGTH])
    );
    assert_eq!(
        receipt_terminal.receipt_inventory().receipts().len(),
        usize::from(FOUNDATION_PROFILE.participant_count)
    );
}

#[test]
fn source_verifier_refuses_an_otherwise_valid_terminal_for_another_parameter() {
    let wrong_parameter_identity = Hash512::from_bytes([0xa7; Hash512::BYTE_LENGTH]);
    let fixture =
        seed_mailbox_test_fixture_with_parameter_identity_320(0, 1, wrong_parameter_identity);
    let receipt_envelopes =
        signed_receipt_envelopes_from_authenticated_deliveries_with_parameter_identity(
            wrong_parameter_identity,
            0x81,
            0xa1,
        );
    let receipt_inventory = verified_receipt_inventory(&fixture, &receipt_envelopes);
    let terminal_certificate = signed_terminal_certificate(
        &receipt_inventory,
        &fixture.signing_keys,
        0xc1,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    );
    let receipt_terminal = verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
        fixture.root_terminal.clone(),
        receipt_inventory,
        &fixture.roster,
        &terminal_certificate.canonical_bytes().unwrap(),
    )
    .unwrap();

    assert_eq!(
        verify_direct_mpc_one_and_preprocessing_source(&fixture.roster, &receipt_terminal),
        Err(DirectMpcOneAndPreprocessingSourceError::WrongSourceParameter)
    );
}
