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
        RosterEntry,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
        PseudorandomZeroSharingSeedCatalogTree320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootSignatureBody320,
        PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320,
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_output_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320,
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320,
        PseudorandomZeroSharingSeedCatalogStateOutputError,
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320,
        verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320,
    },
};

const COMPLETION_ROOT_BODY_BYTE_LENGTH: usize = 522;
const COMPLETION_RESERVATION_CERTIFICATE_BYTE_LENGTH: usize = 25_515;
const COMPLETION_EXACT_OUTPUT_INTENT_BYTE_LENGTH: usize = 342;
const COMPLETION_EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_BYTE_LENGTH: usize = 163;
const COMPLETION_EXACT_OUTPUT_WITNESS_ENVELOPE_BYTE_LENGTH: usize = 3_577;
const COMPLETION_EXACT_OUTPUT_CERTIFICATE_BYTE_LENGTH: usize = 25_545;
const COMPLETION_CONTRIBUTOR_SIGNATURE_ENVELOPE_BYTE_LENGTH: usize = 3_723;
const COMPLETION_INDIVIDUALLY_AUTHORIZED_ROOT_BYTE_LENGTH: usize = 55_305;

#[test]
fn every_completion_root_requires_both_state_slots_and_its_contributor_signature() {
    let (roster, signing_keys) = completion_roster_and_signing_keys(0x21);
    let context = completion_context(&roster, 0x31);
    let mut all_root_package_byte_length = 0_usize;

    for contributor_position in 0..FOUNDATION_PROFILE.participant_count {
        let layout = catalog_layout(context, contributor_position);
        let root_body = catalog_root(layout, 0x41_u8.wrapping_add(contributor_position as u8));
        let root_body_bytes = root_body.canonical_bytes().unwrap();
        let reservation_intent =
            PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body)
                .unwrap();
        let witness_positions = canonical_witness_positions(contributor_position, false);
        let reservation_certificate = signed_reservation_certificate(
            reservation_intent,
            &signing_keys,
            &witness_positions,
            0x51_u8.wrapping_add(contributor_position as u8),
        );
        let reservation_certificate_bytes = reservation_certificate.canonical_bytes().unwrap();
        let verified_reservation =
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
                layout,
                &root_body_bytes,
                &roster,
                &reservation_certificate_bytes,
            )
            .unwrap();
        let exact_output_intent =
            PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(verified_reservation)
                .unwrap();
        let exact_output_certificate = signed_exact_output_certificate(
            exact_output_intent,
            &signing_keys,
            &witness_positions,
            0x61_u8.wrapping_add(contributor_position as u8),
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
        );
        let exact_output_certificate_bytes = exact_output_certificate.canonical_bytes().unwrap();
        let verified_state_output =
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
                verified_reservation,
                &roster,
                &exact_output_certificate_bytes,
            )
            .unwrap();
        let contributor_signature_envelope = signed_root_envelope(
            root_body,
            exact_output_certificate.identity().unwrap(),
            &signing_keys[usize::from(contributor_position)],
            0x71_u8.wrapping_add(contributor_position as u8),
        );
        let contributor_signature_envelope_bytes =
            contributor_signature_envelope.canonical_bytes().unwrap();

        let authorized_root =
            verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
                layout,
                &root_body_bytes,
                &roster,
                &reservation_certificate_bytes,
                &exact_output_certificate_bytes,
                &contributor_signature_envelope_bytes,
            )
            .unwrap();

        assert_eq!(authorized_root.root_body(), root_body);
        assert_eq!(
            authorized_root.state_key_identity(),
            verified_reservation.state_key_identity()
        );
        assert_eq!(
            authorized_root.reservation_certificate_identity(),
            reservation_certificate.identity().unwrap()
        );
        assert_eq!(
            authorized_root.exact_output_certificate_identity(),
            exact_output_certificate.identity().unwrap()
        );
        assert_eq!(verified_state_output.root_body(), root_body);
        assert_eq!(
            verified_state_output.exact_output_intent_identity(),
            exact_output_intent.identity().unwrap()
        );
        assert_eq!(
            exact_output_intent.operation_body_byte_length(),
            COMPLETION_ROOT_BODY_BYTE_LENGTH as u64
        );
        assert_eq!(
            exact_output_intent.operation_body_identity(),
            root_body.identity().unwrap()
        );

        assert_eq!(root_body_bytes.len(), COMPLETION_ROOT_BODY_BYTE_LENGTH);
        assert_eq!(
            reservation_certificate_bytes.len(),
            COMPLETION_RESERVATION_CERTIFICATE_BYTE_LENGTH
        );
        assert_eq!(
            exact_output_intent.canonical_bytes().unwrap().len(),
            COMPLETION_EXACT_OUTPUT_INTENT_BYTE_LENGTH
        );
        assert_eq!(
            exact_output_certificate.witness_envelopes()[0]
                .authorization_body()
                .canonical_bytes()
                .unwrap()
                .len(),
            COMPLETION_EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_BYTE_LENGTH
        );
        assert_eq!(
            exact_output_certificate.witness_envelopes()[0]
                .canonical_bytes()
                .unwrap()
                .len(),
            COMPLETION_EXACT_OUTPUT_WITNESS_ENVELOPE_BYTE_LENGTH
        );
        assert_eq!(
            exact_output_certificate_bytes.len(),
            COMPLETION_EXACT_OUTPUT_CERTIFICATE_BYTE_LENGTH
        );
        assert_eq!(
            contributor_signature_envelope_bytes.len(),
            COMPLETION_CONTRIBUTOR_SIGNATURE_ENVELOPE_BYTE_LENGTH
        );
        let root_package_byte_length = root_body_bytes.len()
            + reservation_certificate_bytes.len()
            + exact_output_certificate_bytes.len()
            + contributor_signature_envelope_bytes.len();
        assert_eq!(
            root_package_byte_length,
            COMPLETION_INDIVIDUALLY_AUTHORIZED_ROOT_BYTE_LENGTH
        );
        all_root_package_byte_length += root_package_byte_length;
    }

    assert_eq!(
        all_root_package_byte_length,
        FOUNDATION_PROFILE.participant_count as usize
            * COMPLETION_INDIVIDUALLY_AUTHORIZED_ROOT_BYTE_LENGTH
    );
}

#[test]
fn exact_output_predecessors_bind_certificates_without_changing_semantic_root_identity() {
    let (roster, signing_keys) = completion_roster_and_signing_keys(0x81);
    let context = completion_context(&roster, 0x83);
    let contributor_position = 4;
    let layout = catalog_layout(context, contributor_position);
    let root_body = catalog_root(layout, 0x85);
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body).unwrap();
    let first_witness_positions = canonical_witness_positions(contributor_position, false);
    let second_witness_positions = canonical_witness_positions(contributor_position, true);
    let first_reservation_certificate = signed_reservation_certificate(
        reservation_intent,
        &signing_keys,
        &first_witness_positions,
        0x87,
    );
    let second_reservation_certificate = signed_reservation_certificate(
        reservation_intent,
        &signing_keys,
        &second_witness_positions,
        0x89,
    );
    let first_verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &first_reservation_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    let second_verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &second_reservation_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    let first_output_intent =
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(first_verified_reservation)
            .unwrap();
    let second_output_intent = PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(
        second_verified_reservation,
    )
    .unwrap();

    assert_eq!(
        first_output_intent.state_key_identity(),
        second_output_intent.state_key_identity()
    );
    assert_eq!(
        first_output_intent.operation_body_identity(),
        second_output_intent.operation_body_identity()
    );
    assert_eq!(
        first_output_intent.operation_body_byte_length(),
        second_output_intent.operation_body_byte_length()
    );
    assert_ne!(
        first_output_intent.reservation_certificate_identity(),
        second_output_intent.reservation_certificate_identity()
    );
    assert_ne!(
        first_output_intent.identity().unwrap(),
        second_output_intent.identity().unwrap()
    );

    let first_output_certificate = signed_exact_output_certificate(
        first_output_intent,
        &signing_keys,
        &first_witness_positions,
        0x8b,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    let alternate_output_certificate = signed_exact_output_certificate(
        first_output_intent,
        &signing_keys,
        &second_witness_positions,
        0x8d,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    assert_ne!(
        first_output_certificate.identity().unwrap(),
        alternate_output_certificate.identity().unwrap()
    );
    let first_verified_output =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            first_verified_reservation,
            &roster,
            &first_output_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    let alternate_verified_output =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            first_verified_reservation,
            &roster,
            &alternate_output_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    assert_eq!(first_verified_output.root_body(), root_body);
    assert_eq!(alternate_verified_output.root_body(), root_body);
    assert_eq!(
        first_verified_output.exact_output_intent_identity(),
        alternate_verified_output.exact_output_intent_identity()
    );

    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            second_verified_reservation,
            &roster,
            &first_output_certificate.canonical_bytes().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::ObjectMismatch {
                field: "reservation-certificate identity"
            }
        )
    ));

    let changed_root_body = catalog_root(layout, 0x8f);
    let changed_reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(changed_root_body)
            .unwrap();
    let changed_reservation_certificate = signed_reservation_certificate(
        changed_reservation_intent,
        &signing_keys,
        &first_witness_positions,
        0x91,
    );
    let changed_verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &changed_root_body.canonical_bytes().unwrap(),
            &roster,
            &changed_reservation_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    let changed_output_intent = PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(
        changed_verified_reservation,
    )
    .unwrap();
    assert_eq!(
        first_output_intent.state_key_identity(),
        changed_output_intent.state_key_identity(),
        "changed alternatives must still compete for one stable state key"
    );
    assert_ne!(
        first_output_intent.operation_body_identity(),
        changed_output_intent.operation_body_identity()
    );
}

#[test]
fn exact_output_verifier_refuses_wrong_signatures_inventories_and_authorization_chains() {
    let (roster, signing_keys) = completion_roster_and_signing_keys(0xa1);
    let context = completion_context(&roster, 0xa3);
    let contributor_position = 4;
    let layout = catalog_layout(context, contributor_position);
    let root_body = catalog_root(layout, 0xa5);
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body).unwrap();
    let witness_positions = canonical_witness_positions(contributor_position, false);
    let reservation_certificate =
        signed_reservation_certificate(reservation_intent, &signing_keys, &witness_positions, 0xa7);
    let reservation_certificate_bytes = reservation_certificate.canonical_bytes().unwrap();
    let verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &reservation_certificate_bytes,
        )
        .unwrap();
    let exact_output_intent =
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(verified_reservation)
            .unwrap();
    let exact_output_certificate = signed_exact_output_certificate(
        exact_output_intent,
        &signing_keys,
        &witness_positions,
        0xa9,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    let exact_output_certificate_bytes = exact_output_certificate.canonical_bytes().unwrap();

    let (wrong_roster, _) = completion_roster_and_signing_keys(0xab);
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &wrong_roster,
            &exact_output_certificate_bytes,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch)
    );

    let first_witness_position = witness_positions[0];
    let mut wrong_signer_witnesses = exact_output_certificate.witness_envelopes().to_vec();
    wrong_signer_witnesses[0] = signed_exact_output_witness_envelope(
        exact_output_intent,
        first_witness_position,
        &signing_keys[usize::from(witness_positions[1])],
        0xad,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    let wrong_signer_certificate =
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::new(
            exact_output_intent,
            wrong_signer_witnesses,
        )
        .unwrap();
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &wrong_signer_certificate.canonical_bytes().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::InvalidWitnessSignature {
                witness_position: first_witness_position,
            }
        )
    );

    let wrong_context_certificate = signed_exact_output_certificate(
        exact_output_intent,
        &signing_keys,
        &witness_positions,
        0xaf,
        b"sealed-lattice/v1/state/wrong-exact-output-purpose",
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &wrong_context_certificate.canonical_bytes().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::InvalidWitnessSignature { .. })
    ));

    let mut changed_certificate_tuple = decode_tuple(&exact_output_certificate_bytes);
    let mut changed_witness_envelope_bytes = changed_certificate_tuple.items[2]
        .variable_value_bytes()
        .unwrap()
        .to_vec();
    *changed_witness_envelope_bytes.last_mut().unwrap() ^= 0x80;
    changed_certificate_tuple.items[2] =
        CanonicalItem::variable_bytes(changed_witness_envelope_bytes).unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &changed_certificate_tuple.encode().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::InvalidWitnessSignature { .. })
    ));

    let mut reordered_witnesses = exact_output_certificate.witness_envelopes().to_vec();
    reordered_witnesses.swap(0, 1);
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::new(
            exact_output_intent,
            reordered_witnesses,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessOrder)
    );
    let mut duplicate_witnesses = exact_output_certificate.witness_envelopes().to_vec();
    duplicate_witnesses[1] = duplicate_witnesses[0].clone();
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::new(
            exact_output_intent,
            duplicate_witnesses,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessOrder)
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::new(
            exact_output_intent,
            exact_output_certificate.witness_envelopes()
                [..exact_output_certificate.witness_envelopes().len() - 1]
                .to_vec(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessCount { .. })
    ));
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320::new(
            exact_output_intent,
            contributor_position,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::SubjectCannotWitness)
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320::new(
            exact_output_intent,
            FOUNDATION_PROFILE.participant_count,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessPositionOutOfRange { .. })
    ));

    let valid_contributor_signature = signed_root_envelope(
        root_body,
        exact_output_certificate.identity().unwrap(),
        &signing_keys[usize::from(contributor_position)],
        0xb1,
    );
    assert!(
        verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
            layout,
            &root_body_bytes,
            &roster,
            &reservation_certificate_bytes,
            &exact_output_certificate_bytes,
            &valid_contributor_signature.canonical_bytes().unwrap(),
        )
        .is_ok()
    );

    let reservation_only_signature = signed_root_envelope(
        root_body,
        reservation_certificate.identity().unwrap(),
        &signing_keys[usize::from(contributor_position)],
        0xb3,
    );
    assert!(matches!(
        verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
            layout,
            &root_body_bytes,
            &roster,
            &reservation_certificate_bytes,
            &exact_output_certificate_bytes,
            &reservation_only_signature.canonical_bytes().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::RootSignature(_))
    ));

    let alternate_output_certificate = signed_exact_output_certificate(
        exact_output_intent,
        &signing_keys,
        &canonical_witness_positions(contributor_position, true),
        0xb5,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    let alternate_certificate_signature = signed_root_envelope(
        root_body,
        alternate_output_certificate.identity().unwrap(),
        &signing_keys[usize::from(contributor_position)],
        0xb7,
    );
    assert!(matches!(
        verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
            layout,
            &root_body_bytes,
            &roster,
            &reservation_certificate_bytes,
            &exact_output_certificate_bytes,
            &alternate_certificate_signature.canonical_bytes().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::RootSignature(_))
    ));

    let wrong_contributor_signature = signed_root_envelope(
        root_body,
        exact_output_certificate.identity().unwrap(),
        &signing_keys[usize::from(contributor_position + 1)],
        0xb9,
    );
    assert!(matches!(
        verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
            layout,
            &root_body_bytes,
            &roster,
            &reservation_certificate_bytes,
            &exact_output_certificate_bytes,
            &wrong_contributor_signature.canonical_bytes().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateOutputError::RootSignature(_))
    ));
}

#[test]
fn exact_output_objects_bind_every_field_and_refuse_malformed_certificate_shapes() {
    let (roster, signing_keys) = completion_roster_and_signing_keys(0xc1);
    let context = completion_context(&roster, 0xc3);
    let contributor_position = 2;
    let layout = catalog_layout(context, contributor_position);
    let root_body = catalog_root(layout, 0xc5);
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body).unwrap();
    let witness_positions = canonical_witness_positions(contributor_position, false);
    let reservation_certificate =
        signed_reservation_certificate(reservation_intent, &signing_keys, &witness_positions, 0xc7);
    let verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &reservation_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    let exact_output_intent =
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(verified_reservation)
            .unwrap();
    let exact_output_certificate = signed_exact_output_certificate(
        exact_output_intent,
        &signing_keys,
        &witness_positions,
        0xc9,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    let exact_output_certificate_bytes = exact_output_certificate.canonical_bytes().unwrap();
    let certificate_tuple = decode_tuple(&exact_output_certificate_bytes);
    let exact_output_intent_tuple =
        decode_tuple(certificate_tuple.items[1].variable_value_bytes().unwrap());

    for field_position in 1..exact_output_intent_tuple.items.len() {
        let mut changed_intent_tuple = exact_output_intent_tuple.clone();
        changed_intent_tuple.items[field_position] = match field_position {
            1 => CanonicalItem::nonempty_ascii("wrong-operation-kind").unwrap(),
            2 | 3 | 5 => CanonicalItem::hash512([field_position as u8; 64]),
            4 => CanonicalItem::unsigned64(COMPLETION_ROOT_BODY_BYTE_LENGTH as u64 + 1),
            _ => unreachable!(),
        };
        let mut changed_certificate_tuple = certificate_tuple.clone();
        changed_certificate_tuple.items[1] =
            CanonicalItem::variable_bytes(changed_intent_tuple.encode().unwrap()).unwrap();
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
                verified_reservation,
                &roster,
                &changed_certificate_tuple.encode().unwrap(),
            )
            .is_err(),
            "exact-output intent field {field_position} must bind"
        );
    }

    let mut wrong_intent_domain = exact_output_intent_tuple.clone();
    wrong_intent_domain.items[0] = CanonicalItem::nonempty_ascii(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_DOMAIN,
    )
    .unwrap();
    let mut wrong_intent_domain_certificate = certificate_tuple.clone();
    wrong_intent_domain_certificate.items[1] =
        CanonicalItem::variable_bytes(wrong_intent_domain.encode().unwrap()).unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &wrong_intent_domain_certificate.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::ObjectMismatch {
                field: "object domain"
            }
        )
    ));

    let mut wrong_certificate_domain = certificate_tuple.clone();
    wrong_certificate_domain.items[0] = CanonicalItem::nonempty_ascii(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_DOMAIN,
    )
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &wrong_certificate_domain.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::ObjectMismatch {
                field: "object domain"
            }
        )
    ));

    let mut missing_witness = certificate_tuple.clone();
    missing_witness.items.pop();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &missing_witness.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessCount {
                expected: 7,
                actual: 6
            }
        )
    ));

    let additional_witness_position = (0..FOUNDATION_PROFILE.participant_count)
        .find(|position| *position != contributor_position && !witness_positions.contains(position))
        .unwrap();
    let additional_witness = signed_exact_output_witness_envelope(
        exact_output_intent,
        additional_witness_position,
        &signing_keys[usize::from(additional_witness_position)],
        0xcb,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
    );
    let mut extra_witness = certificate_tuple.clone();
    extra_witness.items.push(
        CanonicalItem::variable_bytes(additional_witness.canonical_bytes().unwrap()).unwrap(),
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &extra_witness.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessCount {
                expected: 7,
                actual: 8
            }
        )
    ));

    for truncated_length in [
        0,
        1,
        7,
        exact_output_certificate_bytes.len() / 2,
        exact_output_certificate_bytes.len() - 1,
    ] {
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
                verified_reservation,
                &roster,
                &exact_output_certificate_bytes[..truncated_length],
            )
            .is_err()
        );
    }
    assert!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            &roster,
            &[0_u8; 131_073],
        )
        .is_err()
    );
    let debug_output = format!("{exact_output_certificate:?}");
    assert!(debug_output.contains("[redacted]"));
}

fn signed_reservation_certificate(
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    witness_positions: &[u16],
    seed_marker: u8,
) -> PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320 {
    let witness_envelopes = witness_positions
        .iter()
        .map(|witness_position| {
            let authorization_body =
                PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320::new(
                    reservation_intent,
                    *witness_position,
                )
                .unwrap();
            let signature = signing_keys[usize::from(*witness_position)]
                .try_sign_with_seed(
                    &[seed_marker.wrapping_add(*witness_position as u8); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
                )
                .unwrap();
            PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect();
    PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
        reservation_intent,
        witness_envelopes,
    )
    .unwrap()
}

fn signed_exact_output_certificate(
    exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    witness_positions: &[u16],
    seed_marker: u8,
    signature_context: &[u8],
) -> PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320 {
    let witness_envelopes = witness_positions
        .iter()
        .map(|witness_position| {
            signed_exact_output_witness_envelope(
                exact_output_intent,
                *witness_position,
                &signing_keys[usize::from(*witness_position)],
                seed_marker.wrapping_add(*witness_position as u8),
                signature_context,
            )
        })
        .collect();
    PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::new(
        exact_output_intent,
        witness_envelopes,
    )
    .unwrap()
}

fn signed_exact_output_witness_envelope(
    exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
    witness_position: u16,
    signing_key: &ml_dsa_65::PrivateKey,
    seed_marker: u8,
    signature_context: &[u8],
) -> PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320 {
    let authorization_body =
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320::new(
            exact_output_intent,
            witness_position,
        )
        .unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[seed_marker; 32],
            &authorization_body.canonical_bytes().unwrap(),
            signature_context,
        )
        .unwrap();
    PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320::new(
        authorization_body,
        signature,
    )
}

fn signed_root_envelope(
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    authorization_certificate_identity: Hash512,
    signing_key: &ml_dsa_65::PrivateKey,
    seed_marker: u8,
) -> PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320 {
    let signature_body = PseudorandomZeroSharingSeedCatalogRootSignatureBody320::new(
        root_body,
        authorization_certificate_identity,
    )
    .unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[seed_marker; 32],
            &signature_body.canonical_bytes().unwrap(),
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(signature_body, signature)
}

fn canonical_witness_positions(contributor_position: u16, take_from_end: bool) -> Vec<u16> {
    let positions = (0..FOUNDATION_PROFILE.participant_count)
        .filter(|position| *position != contributor_position)
        .collect::<Vec<_>>();
    let witness_count = usize::from(FOUNDATION_PROFILE.state_witness_quorum);
    if take_from_end {
        positions[positions.len() - witness_count..].to_vec()
    } else {
        positions[..witness_count].to_vec()
    }
}

fn catalog_layout(
    context: TallyPreparationContext,
    contributor_position: u16,
) -> PseudorandomZeroSharingSeedCatalogLayout320 {
    PseudorandomZeroSharingSeedCatalogLayout320::derive(
        Hash512::from_bytes([0xd1; 64]),
        context,
        contributor_position,
    )
    .unwrap()
}

fn catalog_root(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    marker: u8,
) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
    PseudorandomZeroSharingSeedCatalogTree320::create(
        layout,
        (0..layout.leaf_count())
            .map(|leaf_ordinal| deterministic_hash(marker, leaf_ordinal))
            .collect(),
    )
    .unwrap()
    .root_body()
}

fn completion_roster_and_signing_keys(marker: u8) -> (Roster, Vec<ml_dsa_65::PrivateKey>) {
    let mut signing_keys = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    let entries = (0..FOUNDATION_PROFILE.participant_count)
        .map(|roster_position| {
            let mut signing_seed = [marker; 32];
            signing_seed[0] = marker.wrapping_add(roster_position as u8);
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);

            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= roster_position as u8;
            let mut mailbox_fallback_seed = [marker.wrapping_add(0x53); 32];
            mailbox_fallback_seed[31] ^= roster_position as u8;
            let (mailbox_encapsulation_key, _) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            RosterEntry::new(
                roster_position,
                signing_verification_key.into_bytes(),
                mailbox_encapsulation_key.into_bytes(),
            )
            .unwrap()
        })
        .collect();
    (Roster::new(entries).unwrap(), signing_keys)
}

fn completion_context(roster: &Roster, attempt_marker: u8) -> TallyPreparationContext {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            u16::try_from(roster.entries.len()).unwrap(),
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([0xe1; 64]),
        roster.roster_hash().unwrap(),
        [attempt_marker; 32],
        &circuit,
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
