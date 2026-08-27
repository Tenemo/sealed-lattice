use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512, Roster, RosterEntry},
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
        AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
        MaskedBallotBivariateMailboxSignatureEnvelope320,
        SealedMaskedBallotBivariateMailboxPackage320,
        complete_masked_ballot_bivariate_mailbox_delivery_320,
        seal_masked_ballot_bivariate_mailbox_package_320,
        verify_masked_ballot_bivariate_mailbox_manifest_signature_320,
        verify_masked_ballot_bivariate_mailbox_public_carrier_320,
    },
    masked_ballot_bivariate_receipt_320::{
        AllRosterMaskedBallotBivariateReceiptTerminal320,
        MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT,
        MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_BYTE_LENGTH,
        MaskedBallotBivariateReceiptAuthorizationBody320,
        MaskedBallotBivariateReceiptAuthorizationPackage320,
        MaskedBallotBivariateReceiptEnvelope320, MaskedBallotBivariateReceiptError320,
        ProducedMaskedBallotBivariateReceipt320,
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320,
        join_masked_ballot_bivariate_custody_320,
        masked_ballot_bivariate_receipt_terminal_certificate_byte_length,
        produce_masked_ballot_bivariate_receipt_320,
        verify_masked_ballot_bivariate_receipt_announcement_320,
        verify_masked_ballot_bivariate_receipt_terminal_320,
    },
    masked_ballot_bivariate_receipt_state_320::{
        MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
        MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_SIGNATURE_CONTEXT,
        MaskedBallotBivariateReceiptStateError320, MaskedBallotBivariateReceiptStateKey320,
        MaskedBallotBivariateReceiptStateOutputCertificate320,
        MaskedBallotBivariateReceiptStateOutputIntent320,
        MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320,
        MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320,
        MaskedBallotBivariateReceiptStateReservationCertificate320,
        MaskedBallotBivariateReceiptStateReservationIntent320,
        MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320,
        MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320,
        VerifiedMaskedBallotBivariateReceiptStateOutput320,
        VerifiedMaskedBallotBivariateReceiptStateReservation320,
        verify_masked_ballot_bivariate_receipt_state_output_320,
        verify_masked_ballot_bivariate_receipt_state_reservation_320,
    },
    masked_ballot_bivariate_sharing_320::MaskedBallotSymmetricBivariatePolynomial320,
    masked_ballot_bundle_320::{MaskedBallotBundle320, masked_ballot_bundle_input_bit_count},
};

#[test]
fn all_ten_local_receipts_form_one_positive_terminal() {
    let fixture = completion_fixture(0x31, 0x41);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x51);
    let produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x61,
    );
    let receipt_packages = authorization_packages(&produced_receipts);
    let state_outputs = verified_state_outputs(&produced_receipts);
    let terminal_certificate_bytes =
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &receipt_packages,
        )
        .unwrap();
    let terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &state_outputs,
        &terminal_certificate_bytes,
    )
    .unwrap();
    assert_terminal_is_not_continuation_authority(&terminal);
    assert_eq!(terminal.receipt_body_identities().len(), 10);
    assert_eq!(terminal.state_key_identities().len(), 10);
    assert_eq!(terminal.reservation_certificate_identities().len(), 10);
    assert_eq!(terminal.exact_output_certificate_identities().len(), 10);
    assert_eq!(terminal.receipt_envelope_identities().len(), 10);
    assert_ne!(
        terminal.terminal_body_identity(),
        Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
    );
    assert_ne!(
        terminal.certificate_identity(),
        Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
    );
    for (holder_index, produced_receipt) in produced_receipts.iter().enumerate() {
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .delivery()
                .holder_roster_position(),
            u16::try_from(holder_index).unwrap()
        );
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .receipt_envelope_identity(),
            terminal.receipt_envelope_identities()[holder_index]
        );
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .state_key_identity(),
            terminal.state_key_identities()[holder_index]
        );
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .reservation_certificate_identity(),
            terminal.reservation_certificate_identities()[holder_index]
        );
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .exact_output_certificate_identity(),
            terminal.exact_output_certificate_identities()[holder_index]
        );
    }
}

#[test]
fn completion_receipts_and_terminal_have_exact_fixed_lengths() {
    let fixture = completion_fixture(0x32, 0x42);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x52);
    let produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x62,
    );
    assert_eq!(MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH, 311);
    assert_eq!(
        MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_BYTE_LENGTH,
        231
    );
    assert_eq!(MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_BYTE_LENGTH, 3_637);
    assert_eq!(
        MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_BYTE_LENGTH,
        312
    );
    assert_eq!(
        masked_ballot_bivariate_receipt_terminal_certificate_byte_length(
            FOUNDATION_PROFILE.participant_count
        )
        .unwrap(),
        36_885
    );
    for produced_receipt in &produced_receipts {
        assert_eq!(produced_receipt.receipt_envelope_bytes().len(), 3_637);
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .receipt_body()
                .canonical_bytes()
                .unwrap()
                .len(),
            311
        );
    }
    let receipt_packages = authorization_packages(&produced_receipts);
    let state_outputs = verified_state_outputs(&produced_receipts);
    let certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &receipt_packages,
    )
    .unwrap();
    assert_eq!(certificate.len(), 36_885);
    let terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &state_outputs,
        &certificate,
    )
    .unwrap();
    assert_eq!(
        terminal.terminal_body().canonical_bytes().unwrap().len(),
        312
    );
}

#[test]
fn missing_reordered_duplicate_and_forged_receipts_never_form_a_terminal() {
    let fixture = completion_fixture(0x33, 0x43);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x53);
    let produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x63,
    );
    let mut receipt_envelope_bytes = produced_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes().to_vec())
        .collect::<Vec<_>>();

    let missing = authorization_packages_with_envelopes(
        &produced_receipts[..9],
        &receipt_envelope_bytes[..9],
    );
    assert!(matches!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &missing,
        ),
        Err(MaskedBallotBivariateReceiptError320::ReceiptCount {
            expected: 10,
            actual: 9
        })
    ));

    receipt_envelope_bytes.swap(0, 1);
    let reordered =
        authorization_packages_with_envelopes(&produced_receipts, &receipt_envelope_bytes);
    assert!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &reordered,
        )
        .is_err()
    );
    receipt_envelope_bytes.swap(0, 1);

    receipt_envelope_bytes[1] = receipt_envelope_bytes[0].clone();
    let duplicate =
        authorization_packages_with_envelopes(&produced_receipts, &receipt_envelope_bytes);
    assert!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &duplicate,
        )
        .is_err()
    );

    receipt_envelope_bytes[1] = produced_receipts[1].receipt_envelope_bytes().to_vec();
    *receipt_envelope_bytes[7].last_mut().unwrap() ^= 0x80;
    let forged = authorization_packages_with_envelopes(&produced_receipts, &receipt_envelope_bytes);
    assert!(matches!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &forged,
        ),
        Err(
            MaskedBallotBivariateReceiptError320::InvalidReceiptSignature {
                holder_roster_position: 7
            }
        )
    ));
}

#[test]
fn receipt_carrier_randomness_cannot_fork_the_semantic_terminal() {
    let fixture = completion_fixture(0x34, 0x44);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x54);
    let first_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x64,
    );
    let alternate_receipt_envelopes = first_receipts
        .iter()
        .enumerate()
        .map(|(holder_index, produced_receipt)| {
            let authorization_body = MaskedBallotBivariateReceiptAuthorizationBody320::new(
                produced_receipt.state_output,
            )
            .unwrap();
            let signature = fixture.signing_keys[holder_index]
                .try_sign_with_seed(
                    &[0x74_u8.wrapping_add(u8::try_from(holder_index).unwrap()); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT,
                )
                .unwrap();
            MaskedBallotBivariateReceiptEnvelope320::new(authorization_body, signature)
                .canonical_bytes()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let first_packages = authorization_packages(&first_receipts);
    let alternate_packages =
        authorization_packages_with_envelopes(&first_receipts, &alternate_receipt_envelopes);
    let state_outputs = verified_state_outputs(&first_receipts);
    let first_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &first_packages,
    )
    .unwrap();
    let alternate_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &alternate_packages,
    )
    .unwrap();
    let first_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &state_outputs,
        &first_certificate,
    )
    .unwrap();
    let alternate_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &state_outputs,
        &alternate_certificate,
    )
    .unwrap();
    assert_eq!(
        first_terminal.terminal_body_identity(),
        alternate_terminal.terminal_body_identity()
    );
    assert_eq!(
        first_terminal.receipt_body_identities(),
        alternate_terminal.receipt_body_identities()
    );
    assert_ne!(
        first_terminal.receipt_envelope_identities(),
        alternate_terminal.receipt_envelope_identities()
    );
    assert_ne!(
        first_terminal.certificate_identity(),
        alternate_terminal.certificate_identity()
    );
}

#[test]
fn receipt_production_requires_the_bound_holder_key_and_nonzero_randomness() {
    let fixture = completion_fixture(0x35, 0x45);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x55);
    let state_output = authorize_receipt_state(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        0,
        0x64,
    );
    let delivery = complete_delivery(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0,
    );
    assert!(matches!(
        produce_masked_ballot_bivariate_receipt_320(
            state_output,
            &fixture.roster,
            delivery,
            &fixture.signing_keys[1],
            [0x65; 32],
        ),
        Err(
            MaskedBallotBivariateReceiptError320::HolderSigningKeyMismatch {
                holder_roster_position: 0
            }
        )
    ));

    let delivery = complete_delivery(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0,
    );
    assert!(matches!(
        produce_masked_ballot_bivariate_receipt_320(
            state_output,
            &fixture.roster,
            delivery,
            &fixture.signing_keys[0],
            [0_u8; 32],
        ),
        Err(MaskedBallotBivariateReceiptError320::InvalidSignatureRandomness)
    ));
}

#[test]
fn receipt_announcement_is_scoped_to_one_root_manifest_and_holder() {
    let fixture = completion_fixture(0x36, 0x46);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x56);
    let produced_receipt = produce_receipt(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0,
        0x66,
    );
    let announcement = verify_masked_ballot_bivariate_receipt_announcement_320(
        produced_receipt.state_output,
        &fixture.roster,
        produced_receipt.receipt_envelope_bytes(),
    )
    .unwrap();
    assert_eq!(announcement.receipt_body().holder_roster_position(), 0);
    assert_eq!(
        announcement.state_key_identity(),
        produced_receipt.state_output.state_key_identity()
    );
    assert_eq!(
        announcement.reservation_certificate_identity(),
        produced_receipt
            .state_output
            .reservation_certificate_identity()
    );
    assert_eq!(
        announcement.exact_output_certificate_identity(),
        MaskedBallotBivariateReceiptAuthorizationBody320::new(produced_receipt.state_output)
            .unwrap()
            .exact_output_certificate_identity()
    );
    assert_eq!(
        announcement.receipt_envelope_identity(),
        produced_receipt
            .authenticated_receipt()
            .receipt_envelope_identity()
    );
    assert!(
        verify_masked_ballot_bivariate_receipt_announcement_320(
            authorize_receipt_state(
                &fixture,
                &authenticated_root,
                &authenticated_manifest,
                1,
                0x67,
            ),
            &fixture.roster,
            produced_receipt.receipt_envelope_bytes(),
        )
        .is_err()
    );

    let other_fixture = completion_fixture(0x37, 0x47);
    let (other_root, other_manifest, _) = authenticate_package(&other_fixture, 0x57);
    let other_state_output =
        authorize_receipt_state(&other_fixture, &other_root, &other_manifest, 0, 0x68);
    assert!(
        verify_masked_ballot_bivariate_receipt_announcement_320(
            other_state_output,
            &other_fixture.roster,
            produced_receipt.receipt_envelope_bytes(),
        )
        .is_err()
    );
}

#[test]
fn local_receipt_joins_only_its_exact_all_roster_terminal() {
    let fixture = completion_fixture(0x38, 0x48);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x58);
    let mut produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x68,
    );
    let receipt_packages = authorization_packages(&produced_receipts);
    let state_outputs = verified_state_outputs(&produced_receipts);
    let terminal_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &receipt_packages,
    )
    .unwrap();
    let terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &state_outputs,
        &terminal_certificate,
    )
    .unwrap();
    let local_receipt = produced_receipts.remove(6).into_authenticated_receipt();
    let joined = join_masked_ballot_bivariate_custody_320(local_receipt, &terminal).unwrap();
    assert_eq!(joined.delivery().holder_roster_position(), 6);
    assert_eq!(
        joined.receipt_body_identity(),
        terminal.receipt_body_identities()[6]
    );
    assert_eq!(
        joined.receipt_envelope_identity(),
        terminal.receipt_envelope_identities()[6]
    );
    assert_eq!(
        joined.state_key_identity(),
        terminal.state_key_identities()[6]
    );
    assert_eq!(
        joined.reservation_certificate_identity(),
        terminal.reservation_certificate_identities()[6]
    );
    assert_eq!(
        joined.exact_output_certificate_identity(),
        terminal.exact_output_certificate_identities()[6]
    );
    assert_eq!(
        joined.terminal_body_identity(),
        terminal.terminal_body_identity()
    );
    assert_eq!(
        joined.terminal_certificate_identity(),
        terminal.certificate_identity()
    );

    let other_fixture = completion_fixture(0x39, 0x49);
    let (other_root, other_manifest, other_package) = authenticate_package(&other_fixture, 0x59);
    let other_receipts = produce_all_receipts(
        &other_fixture,
        &other_root,
        &other_manifest,
        &other_package,
        0x69,
    );
    let other_receipt_packages = authorization_packages(&other_receipts);
    let other_state_outputs = verified_state_outputs(&other_receipts);
    let other_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &other_root,
        &other_manifest,
        &other_fixture.roster,
        &other_receipt_packages,
    )
    .unwrap();
    let other_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &other_root,
        &other_manifest,
        &other_fixture.roster,
        &other_state_outputs,
        &other_certificate,
    )
    .unwrap();
    let remaining_local_receipt = produced_receipts.remove(0).into_authenticated_receipt();
    assert!(matches!(
        join_masked_ballot_bivariate_custody_320(remaining_local_receipt, &other_terminal),
        Err(MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch { .. })
    ));
}

#[test]
fn receipt_state_key_excludes_alternatives_and_binds_every_conflict_coordinate() {
    let fixture = completion_fixture(0x3a, 0x4a);
    let holder_roster_position = 6;
    let state_key =
        MaskedBallotBivariateReceiptStateKey320::derive(fixture.layout, holder_roster_position)
            .unwrap();
    let alternate_preparation_record_layout = MaskedBallotBivariateCommitmentLayout320::derive(
        fixture.layout.parameter_identity(),
        fixture.layout.preparation_context(),
        deterministic_hash(0xf1, 0),
        fixture.layout.author_roster_position(),
    )
    .unwrap();
    assert_eq!(
        state_key.identity(),
        MaskedBallotBivariateReceiptStateKey320::derive(
            alternate_preparation_record_layout,
            holder_roster_position,
        )
        .unwrap()
        .identity()
    );
    assert_ne!(
        state_key.identity(),
        MaskedBallotBivariateReceiptStateKey320::derive(fixture.layout, 5)
            .unwrap()
            .identity()
    );
    let alternate_author_layout = MaskedBallotBivariateCommitmentLayout320::derive(
        fixture.layout.parameter_identity(),
        fixture.layout.preparation_context(),
        fixture.layout.preparation_record_identity(),
        5,
    )
    .unwrap();
    assert_ne!(
        state_key.identity(),
        MaskedBallotBivariateReceiptStateKey320::derive(
            alternate_author_layout,
            holder_roster_position,
        )
        .unwrap()
        .identity()
    );
    let alternate_parameter_layout = MaskedBallotBivariateCommitmentLayout320::derive(
        deterministic_hash(0xf2, 0),
        fixture.layout.preparation_context(),
        fixture.layout.preparation_record_identity(),
        fixture.layout.author_roster_position(),
    )
    .unwrap();
    assert_ne!(
        state_key.identity(),
        MaskedBallotBivariateReceiptStateKey320::derive(
            alternate_parameter_layout,
            holder_roster_position,
        )
        .unwrap()
        .identity()
    );
    let circuit = completion_circuit();
    let alternate_action_layout = MaskedBallotBivariateCommitmentLayout320::derive(
        fixture.layout.parameter_identity(),
        completion_context(&fixture.roster, &circuit, 0xf3),
        fixture.layout.preparation_record_identity(),
        fixture.layout.author_roster_position(),
    )
    .unwrap();
    assert_ne!(
        state_key.identity(),
        MaskedBallotBivariateReceiptStateKey320::derive(
            alternate_action_layout,
            holder_roster_position,
        )
        .unwrap()
        .identity()
    );
}

#[test]
fn receipt_state_requires_both_exact_non_subject_quorums() {
    let fixture = completion_fixture(0x3b, 0x4b);
    let (authenticated_root, authenticated_manifest, _) = authenticate_package(&fixture, 0x5b);
    let holder_roster_position = 4;
    let artifacts = receipt_state_artifacts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        holder_roster_position,
        0x6b,
    );
    assert_eq!(
        artifacts
            .reservation_intent
            .canonical_bytes()
            .unwrap()
            .len(),
        353
    );
    assert_eq!(
        artifacts.reservation_witness_envelopes[0]
            .authorization_body()
            .canonical_bytes()
            .unwrap()
            .len(),
        181
    );
    assert_eq!(
        artifacts.reservation_witness_envelopes[0]
            .canonical_bytes()
            .unwrap()
            .len(),
        3_613
    );
    assert_eq!(artifacts.reservation_certificate_bytes.len(), 25_826);
    assert_eq!(
        artifacts
            .exact_output_intent
            .canonical_bytes()
            .unwrap()
            .len(),
        368
    );
    assert_eq!(
        artifacts.exact_output_witness_envelopes[0]
            .authorization_body()
            .canonical_bytes()
            .unwrap()
            .len(),
        182
    );
    assert_eq!(
        artifacts.exact_output_witness_envelopes[0]
            .canonical_bytes()
            .unwrap()
            .len(),
        3_615
    );
    assert_eq!(artifacts.exact_output_certificate_bytes.len(), 25_856);
    assert_eq!(
        artifacts.reservation_intent.predecessor_identity(),
        fixture.layout.preparation_record_identity()
    );
    assert_eq!(
        artifacts.reservation_intent.receipt_body_identity(),
        artifacts.verified_output.receipt_body().identity().unwrap()
    );
    assert_eq!(
        artifacts.verified_reservation.reservation_intent_identity(),
        artifacts.reservation_intent.identity().unwrap()
    );
    assert_eq!(
        artifacts.exact_output_intent.operation_body_byte_length(),
        311
    );
    assert_eq!(
        artifacts.exact_output_intent.operation_body_identity(),
        artifacts.verified_output.receipt_body().identity().unwrap()
    );
    assert_eq!(
        artifacts.verified_output.exact_output_intent_identity(),
        artifacts.exact_output_intent.identity().unwrap()
    );
    assert!(matches!(
        MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320::new(
            artifacts.reservation_intent,
            holder_roster_position,
        ),
        Err(MaskedBallotBivariateReceiptStateError320::SubjectCannotWitness)
    ));
    assert!(matches!(
        MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320::new(
            artifacts.exact_output_intent,
            holder_roster_position,
        ),
        Err(MaskedBallotBivariateReceiptStateError320::SubjectCannotWitness)
    ));
    assert!(matches!(
        MaskedBallotBivariateReceiptStateReservationCertificate320::new(
            artifacts.reservation_intent,
            artifacts.reservation_witness_envelopes[..6].to_vec(),
        ),
        Err(MaskedBallotBivariateReceiptStateError320::WitnessCount {
            expected: 7,
            actual: 6,
        })
    ));
    assert!(matches!(
        MaskedBallotBivariateReceiptStateOutputCertificate320::new(
            artifacts.exact_output_intent,
            artifacts.exact_output_witness_envelopes[..6].to_vec(),
        ),
        Err(MaskedBallotBivariateReceiptStateError320::WitnessCount {
            expected: 7,
            actual: 6,
        })
    ));
}

#[test]
fn receipt_state_verifiers_refuse_wrong_scope_and_corrupted_witnesses() {
    let fixture = completion_fixture(0x3c, 0x4c);
    let (authenticated_root, authenticated_manifest, _) = authenticate_package(&fixture, 0x5c);
    let artifacts = receipt_state_artifacts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        2,
        0x6c,
    );
    assert!(
        verify_masked_ballot_bivariate_receipt_state_reservation_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            3,
            &artifacts.reservation_certificate_bytes,
        )
        .is_err()
    );
    let mut corrupted_reservation_certificate = artifacts.reservation_certificate_bytes.clone();
    *corrupted_reservation_certificate.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_masked_ballot_bivariate_receipt_state_reservation_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            2,
            &corrupted_reservation_certificate,
        ),
        Err(MaskedBallotBivariateReceiptStateError320::InvalidWitnessSignature { .. })
    ));
    let mut corrupted_output_certificate = artifacts.exact_output_certificate_bytes.clone();
    *corrupted_output_certificate.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_masked_ballot_bivariate_receipt_state_output_320(
            artifacts.verified_reservation,
            &fixture.roster,
            &corrupted_output_certificate,
        ),
        Err(MaskedBallotBivariateReceiptStateError320::InvalidWitnessSignature { .. })
    ));
    let other_fixture = completion_fixture(0x3d, 0x4d);
    assert!(matches!(
        verify_masked_ballot_bivariate_receipt_state_output_320(
            artifacts.verified_reservation,
            &other_fixture.roster,
            &artifacts.exact_output_certificate_bytes,
        ),
        Err(MaskedBallotBivariateReceiptStateError320::RosterMismatch)
    ));
}

#[test]
fn alternate_state_and_signature_carriers_preserve_one_semantic_terminal() {
    let fixture = completion_fixture(0x3e, 0x4e);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x5e);
    let first_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x6e,
    );
    let alternate_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x7e,
    );
    let first_packages = authorization_packages(&first_receipts);
    let alternate_packages = authorization_packages(&alternate_receipts);
    let first_outputs = verified_state_outputs(&first_receipts);
    let alternate_outputs = verified_state_outputs(&alternate_receipts);
    let first_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &first_packages,
    )
    .unwrap();
    let alternate_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &alternate_packages,
    )
    .unwrap();
    let first_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &first_outputs,
        &first_certificate,
    )
    .unwrap();
    let alternate_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &alternate_outputs,
        &alternate_certificate,
    )
    .unwrap();
    assert_eq!(
        first_terminal.terminal_body_identity(),
        alternate_terminal.terminal_body_identity()
    );
    assert_eq!(
        first_terminal.receipt_body_identities(),
        alternate_terminal.receipt_body_identities()
    );
    assert_eq!(
        first_terminal.state_key_identities(),
        alternate_terminal.state_key_identities()
    );
    assert_ne!(
        first_terminal.reservation_certificate_identities(),
        alternate_terminal.reservation_certificate_identities()
    );
    assert_ne!(
        first_terminal.exact_output_certificate_identities(),
        alternate_terminal.exact_output_certificate_identities()
    );
    assert_ne!(
        first_terminal.receipt_envelope_identities(),
        alternate_terminal.receipt_envelope_identities()
    );
    assert_ne!(
        first_terminal.certificate_identity(),
        alternate_terminal.certificate_identity()
    );
}

struct CompletionFixture {
    roster: Roster,
    signing_keys: Vec<ml_dsa_65::PrivateKey>,
    decapsulation_keys: Vec<ml_kem_768::DecapsKey>,
    layout: MaskedBallotBivariateCommitmentLayout320,
    inventory: MaskedBallotBivariateCommitmentInventory320,
}

struct StateAuthorizedProducedReceipt {
    state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    produced_receipt: ProducedMaskedBallotBivariateReceipt320,
}

struct ReceiptStateArtifacts {
    reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
    reservation_witness_envelopes:
        Vec<MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320>,
    reservation_certificate_bytes: Vec<u8>,
    verified_reservation: VerifiedMaskedBallotBivariateReceiptStateReservation320,
    exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
    exact_output_witness_envelopes: Vec<MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320>,
    exact_output_certificate_bytes: Vec<u8>,
    verified_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
}

impl StateAuthorizedProducedReceipt {
    fn receipt_envelope_bytes(&self) -> &[u8] {
        self.produced_receipt.receipt_envelope_bytes()
    }

    fn authenticated_receipt(
        &self,
    ) -> &super::masked_ballot_bivariate_receipt_320::AuthenticatedMaskedBallotBivariateReceipt320
    {
        self.produced_receipt.authenticated_receipt()
    }

    fn into_authenticated_receipt(
        self,
    ) -> super::masked_ballot_bivariate_receipt_320::AuthenticatedMaskedBallotBivariateReceipt320
    {
        self.produced_receipt.into_authenticated_receipt()
    }
}

fn authorization_packages(
    receipts: &[StateAuthorizedProducedReceipt],
) -> Vec<MaskedBallotBivariateReceiptAuthorizationPackage320<'_>> {
    receipts
        .iter()
        .map(|receipt| {
            MaskedBallotBivariateReceiptAuthorizationPackage320::new(
                receipt.state_output,
                receipt.receipt_envelope_bytes(),
            )
        })
        .collect()
}

fn authorization_packages_with_envelopes<'a>(
    receipts: &[StateAuthorizedProducedReceipt],
    receipt_envelope_bytes: &'a [Vec<u8>],
) -> Vec<MaskedBallotBivariateReceiptAuthorizationPackage320<'a>> {
    receipts
        .iter()
        .zip(receipt_envelope_bytes)
        .map(|(receipt, envelope_bytes)| {
            MaskedBallotBivariateReceiptAuthorizationPackage320::new(
                receipt.state_output,
                envelope_bytes,
            )
        })
        .collect()
}

fn verified_state_outputs(
    receipts: &[StateAuthorizedProducedReceipt],
) -> Vec<VerifiedMaskedBallotBivariateReceiptStateOutput320> {
    receipts
        .iter()
        .map(|receipt| receipt.state_output)
        .collect()
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
        inventory,
    }
}

fn authenticate_package(
    fixture: &CompletionFixture,
    marker: u8,
) -> (
    AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    SealedMaskedBallotBivariateMailboxPackage320,
) {
    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let root_signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        marker,
    );
    let authenticated_root = verify_masked_ballot_bivariate_commitment_root_signature_320(
        fixture.layout,
        &root_body_bytes,
        &fixture.roster,
        &root_signature_envelope_bytes,
    )
    .unwrap();
    let sealed_package = seal_masked_ballot_bivariate_mailbox_package_320(
        &fixture.inventory,
        &fixture.roster,
        &deterministic_encapsulation_randomness(
            FOUNDATION_PROFILE.participant_count,
            marker.wrapping_add(1),
        ),
    )
    .unwrap();
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let manifest_signature = fixture.signing_keys
        [usize::from(fixture.layout.author_roster_position())]
    .try_sign_with_seed(
        &[marker.wrapping_add(2); 32],
        &manifest_bytes,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
    )
    .unwrap();
    let manifest_signature_envelope_bytes = MaskedBallotBivariateMailboxSignatureEnvelope320::new(
        sealed_package.manifest().identity().unwrap(),
        manifest_signature,
    )
    .canonical_bytes()
    .unwrap();
    let authenticated_manifest = verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
        &authenticated_root,
        &fixture.roster,
        &manifest_bytes,
        &manifest_signature_envelope_bytes,
    )
    .unwrap();
    (authenticated_root, authenticated_manifest, sealed_package)
}

fn produce_all_receipts(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    sealed_package: &SealedMaskedBallotBivariateMailboxPackage320,
    marker: u8,
) -> Vec<StateAuthorizedProducedReceipt> {
    (0..FOUNDATION_PROFILE.participant_count)
        .map(|holder_roster_position| {
            produce_receipt(
                fixture,
                authenticated_root,
                authenticated_manifest,
                sealed_package,
                holder_roster_position,
                marker.wrapping_add(u8::try_from(holder_roster_position).unwrap()),
            )
        })
        .collect()
}

fn produce_receipt(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    sealed_package: &SealedMaskedBallotBivariateMailboxPackage320,
    holder_roster_position: u16,
    signature_marker: u8,
) -> StateAuthorizedProducedReceipt {
    let state_output = authorize_receipt_state(
        fixture,
        authenticated_root,
        authenticated_manifest,
        holder_roster_position,
        signature_marker.wrapping_add(0x40),
    );
    let delivery = complete_delivery(
        fixture,
        authenticated_root,
        authenticated_manifest,
        sealed_package,
        holder_roster_position,
    );
    let produced_receipt = produce_masked_ballot_bivariate_receipt_320(
        state_output,
        &fixture.roster,
        delivery,
        &fixture.signing_keys[usize::from(holder_roster_position)],
        [signature_marker; 32],
    )
    .unwrap();
    StateAuthorizedProducedReceipt {
        state_output,
        produced_receipt,
    }
}

fn authorize_receipt_state(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    holder_roster_position: u16,
    marker: u8,
) -> VerifiedMaskedBallotBivariateReceiptStateOutput320 {
    receipt_state_artifacts(
        fixture,
        authenticated_root,
        authenticated_manifest,
        holder_roster_position,
        marker,
    )
    .verified_output
}

fn receipt_state_artifacts(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    holder_roster_position: u16,
    marker: u8,
) -> ReceiptStateArtifacts {
    let receipt_body =
        super::masked_ballot_bivariate_receipt_320::MaskedBallotBivariateReceiptBody320::new(
            authenticated_root,
            authenticated_manifest,
            holder_roster_position,
        )
        .unwrap();
    let reservation_intent =
        MaskedBallotBivariateReceiptStateReservationIntent320::new(fixture.layout, receipt_body)
            .unwrap();
    let witness_positions = state_witness_positions(holder_roster_position);
    let reservation_witness_envelopes = witness_positions
        .iter()
        .map(|witness_roster_position| {
            let authorization_body =
                MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320::new(
                    reservation_intent,
                    *witness_roster_position,
                )
                .unwrap();
            let signature = fixture.signing_keys[usize::from(*witness_roster_position)]
                .try_sign_with_seed(
                    &[marker.wrapping_add(u8::try_from(*witness_roster_position).unwrap()); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_SIGNATURE_CONTEXT,
                )
                .unwrap();
            MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect::<Vec<_>>();
    let reservation_certificate = MaskedBallotBivariateReceiptStateReservationCertificate320::new(
        reservation_intent,
        reservation_witness_envelopes.clone(),
    )
    .unwrap();
    let reservation_certificate_bytes = reservation_certificate.canonical_bytes().unwrap();
    let verified_reservation = verify_masked_ballot_bivariate_receipt_state_reservation_320(
        authenticated_root,
        authenticated_manifest,
        &fixture.roster,
        holder_roster_position,
        &reservation_certificate_bytes,
    )
    .unwrap();
    let exact_output_intent =
        MaskedBallotBivariateReceiptStateOutputIntent320::new(verified_reservation).unwrap();
    let exact_output_witness_envelopes = witness_positions
        .iter()
        .map(|witness_roster_position| {
            let authorization_body =
                MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320::new(
                    exact_output_intent,
                    *witness_roster_position,
                )
                .unwrap();
            let signature = fixture.signing_keys[usize::from(*witness_roster_position)]
                .try_sign_with_seed(
                    &[marker
                        .wrapping_add(0x20)
                        .wrapping_add(u8::try_from(*witness_roster_position).unwrap());
                        32],
                    &authorization_body.canonical_bytes().unwrap(),
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
                )
                .unwrap();
            MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect::<Vec<_>>();
    let exact_output_certificate = MaskedBallotBivariateReceiptStateOutputCertificate320::new(
        exact_output_intent,
        exact_output_witness_envelopes.clone(),
    )
    .unwrap();
    let exact_output_certificate_bytes = exact_output_certificate.canonical_bytes().unwrap();
    let verified_output = verify_masked_ballot_bivariate_receipt_state_output_320(
        verified_reservation,
        &fixture.roster,
        &exact_output_certificate_bytes,
    )
    .unwrap();
    ReceiptStateArtifacts {
        reservation_intent,
        reservation_witness_envelopes,
        reservation_certificate_bytes,
        verified_reservation,
        exact_output_intent,
        exact_output_witness_envelopes,
        exact_output_certificate_bytes,
        verified_output,
    }
}

fn state_witness_positions(subject_roster_position: u16) -> Vec<u16> {
    (0..FOUNDATION_PROFILE.participant_count)
        .filter(|position| *position != subject_roster_position)
        .take(usize::from(FOUNDATION_PROFILE.state_witness_quorum))
        .collect()
}

fn complete_delivery(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    sealed_package: &SealedMaskedBallotBivariateMailboxPackage320,
    holder_roster_position: u16,
) -> super::masked_ballot_bivariate_mailbox_320::AuthenticatedMaskedBallotBivariateMailboxDelivery320
{
    let holder_index = usize::from(holder_roster_position);
    let public_carrier = verify_masked_ballot_bivariate_mailbox_public_carrier_320(
        authenticated_root,
        authenticated_manifest,
        &fixture.roster,
        holder_roster_position,
        &sealed_package.headers()[holder_index]
            .canonical_bytes()
            .unwrap(),
        &sealed_package.encrypted_row_carriers()[holder_index],
    )
    .unwrap();
    complete_masked_ballot_bivariate_mailbox_delivery_320(
        authenticated_root,
        &fixture.roster,
        public_carrier,
        &fixture.decapsulation_keys[holder_index],
    )
    .unwrap()
}

fn sign_root(
    root_body: &MaskedBallotBivariateCommitmentRootBody320,
    signing_key: &ml_dsa_65::PrivateKey,
    marker: u8,
) -> Vec<u8> {
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[marker; 32],
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

fn assert_terminal_is_not_continuation_authority(
    _terminal: &AllRosterMaskedBallotBivariateReceiptTerminal320,
) {
    // The type intentionally exposes only identities and receipt inventories.
}
