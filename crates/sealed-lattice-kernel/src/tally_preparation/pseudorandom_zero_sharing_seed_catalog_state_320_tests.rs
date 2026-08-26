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
        CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, Roster,
        RosterEntry, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
        PseudorandomZeroSharingSeedCatalogTree320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootStateKey320,
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320,
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320,
        PseudorandomZeroSharingSeedCatalogStateError,
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320,
    },
};

const COMPLETION_RESERVATION_INTENT_BYTE_LENGTH: usize = 327;
const COMPLETION_WITNESS_AUTHORIZATION_BODY_BYTE_LENGTH: usize = 162;
const COMPLETION_WITNESS_ENVELOPE_BYTE_LENGTH: usize = 3_575;
const COMPLETION_STATE_CERTIFICATE_BYTE_LENGTH: usize = 25_515;
const COMPLETION_ROOT_BODY_BYTE_LENGTH: usize = 522;

#[test]
fn every_completion_contributor_requires_an_exact_non_subject_reservation_quorum() {
    let (roster, signing_keys) =
        roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, 0x21);
    let context = preparation_context(&roster, 0x31);
    let roster_parameters =
        derive_foundation_roster_parameters(FOUNDATION_PROFILE.participant_count).unwrap();

    for subject_position in 0..FOUNDATION_PROFILE.participant_count {
        let layout = catalog_layout(context, subject_position);
        let root_body = catalog_root(layout, 0x41_u8.wrapping_add(subject_position as u8));
        let root_body_bytes = root_body.canonical_bytes().unwrap();
        let reservation_intent =
            PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body)
                .unwrap();
        let witness_positions = canonical_witness_positions(
            FOUNDATION_PROFILE.participant_count,
            subject_position,
            roster_parameters.state_witness_quorum,
            false,
        );
        let certificate = signed_state_certificate(
            reservation_intent,
            &signing_keys,
            &witness_positions,
            0x51_u8.wrapping_add(subject_position as u8),
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
        );
        let certificate_bytes = certificate.canonical_bytes().unwrap();
        let certificate_identity = certificate.identity().unwrap();

        let verified_reservation =
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
                layout,
                &root_body_bytes,
                &roster,
                &certificate_bytes,
            )
            .unwrap();
        assert_eq!(verified_reservation.root_body(), root_body);
        assert_eq!(
            verified_reservation.state_key_identity(),
            reservation_intent.state_key_identity()
        );
        assert_eq!(
            verified_reservation.reservation_intent_identity(),
            reservation_intent.identity().unwrap()
        );
        assert_eq!(
            verified_reservation.state_certificate_identity(),
            certificate_identity
        );

        assert_eq!(
            reservation_intent.canonical_bytes().unwrap().len(),
            COMPLETION_RESERVATION_INTENT_BYTE_LENGTH
        );
        assert_eq!(
            certificate.witness_envelopes()[0]
                .authorization_body()
                .canonical_bytes()
                .unwrap()
                .len(),
            COMPLETION_WITNESS_AUTHORIZATION_BODY_BYTE_LENGTH
        );
        assert_eq!(
            certificate.witness_envelopes()[0]
                .canonical_bytes()
                .unwrap()
                .len(),
            COMPLETION_WITNESS_ENVELOPE_BYTE_LENGTH
        );
        assert_eq!(
            certificate_bytes.len(),
            COMPLETION_STATE_CERTIFICATE_BYTE_LENGTH
        );
        assert_eq!(root_body_bytes.len(), COMPLETION_ROOT_BODY_BYTE_LENGTH);
    }
}

#[test]
fn stable_keys_exclude_alternatives_and_quorum_intersections_retain_an_honest_witness() {
    let (roster, _) = roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, 0x71);
    let context = preparation_context(&roster, 0x73);
    let layout = catalog_layout(context, 4);
    let first_root = catalog_root(layout, 0x75);
    let second_root = catalog_root(layout, 0x77);
    let first_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(first_root).unwrap();
    let second_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(second_root).unwrap();

    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateKey320::derive(layout)
            .unwrap()
            .identity(),
        first_intent.state_key_identity()
    );
    assert_eq!(
        first_intent.state_key_identity(),
        second_intent.state_key_identity(),
        "a changed root must compete for the same stable slot"
    );
    assert_ne!(
        first_intent.identity().unwrap(),
        second_intent.identity().unwrap(),
        "the reserved alternative must still change the intent"
    );
    assert_ne!(
        first_intent.root_body_identity(),
        second_intent.root_body_identity()
    );
    assert_eq!(first_intent.predecessor_identity(), context.identity());

    let other_subject_layout = catalog_layout(context, 5);
    assert_ne!(
        PseudorandomZeroSharingSeedCatalogRootStateKey320::derive(layout)
            .unwrap()
            .identity(),
        PseudorandomZeroSharingSeedCatalogRootStateKey320::derive(other_subject_layout)
            .unwrap()
            .identity()
    );
    let other_context = preparation_context(&roster, 0x79);
    assert_ne!(
        PseudorandomZeroSharingSeedCatalogRootStateKey320::derive(layout)
            .unwrap()
            .identity(),
        PseudorandomZeroSharingSeedCatalogRootStateKey320::derive(catalog_layout(other_context, 4))
            .unwrap()
            .identity()
    );

    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        assert!(parameters.state_witness_quorum < participant_count);
        let minimum_intersection = 2 * parameters.state_witness_quorum - (participant_count - 1);
        assert!(minimum_intersection >= parameters.active_fault_bound + 2);
    }

    let parameters =
        derive_foundation_roster_parameters(FOUNDATION_PROFILE.participant_count).unwrap();
    for subject_position in 0..FOUNDATION_PROFILE.participant_count {
        let quorum_masks = completion_quorum_masks(subject_position);
        let minimum_observed_intersection = quorum_masks
            .iter()
            .flat_map(|first| {
                quorum_masks
                    .iter()
                    .map(move |second| (first & second).count_ones() as u16)
            })
            .min()
            .unwrap();
        assert_eq!(
            minimum_observed_intersection,
            parameters.active_fault_bound + 2
        );
    }
}

#[test]
fn reservation_verifier_refuses_wrong_rosters_signatures_inventories_and_bindings() {
    let (roster, signing_keys) =
        roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, 0x91);
    let context = preparation_context(&roster, 0x93);
    let subject_position = 4;
    let layout = catalog_layout(context, subject_position);
    let root_body = catalog_root(layout, 0x95);
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body).unwrap();
    let witness_positions = canonical_witness_positions(
        FOUNDATION_PROFILE.participant_count,
        subject_position,
        FOUNDATION_PROFILE.state_witness_quorum,
        false,
    );
    let certificate = signed_state_certificate(
        reservation_intent,
        &signing_keys,
        &witness_positions,
        0x97,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
    );
    let certificate_bytes = certificate.canonical_bytes().unwrap();

    let (wrong_roster, _) = roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, 0x99);
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &wrong_roster,
            &certificate_bytes,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch)
    );

    let mut changed_certificate_tuple = decode_tuple(&certificate_bytes);
    let mut changed_witness_envelope_bytes = changed_certificate_tuple.items[2]
        .variable_value_bytes()
        .unwrap()
        .to_vec();
    *changed_witness_envelope_bytes.last_mut().unwrap() ^= 0x80;
    changed_certificate_tuple.items[2] =
        CanonicalItem::variable_bytes(changed_witness_envelope_bytes).unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &changed_certificate_tuple.encode().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::InvalidWitnessSignature { .. })
    ));

    let first_witness_position = witness_positions[0];
    let mut wrong_signer_witnesses = certificate.witness_envelopes().to_vec();
    wrong_signer_witnesses[0] = signed_witness_envelope(
        reservation_intent,
        first_witness_position,
        &signing_keys[usize::from(witness_positions[1])],
        0x9c,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
    );
    let wrong_signer_certificate =
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
            reservation_intent,
            wrong_signer_witnesses,
        )
        .unwrap();
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &wrong_signer_certificate.canonical_bytes().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateError::InvalidWitnessSignature {
                witness_position: first_witness_position,
            }
        )
    );

    let wrong_context_certificate = signed_state_certificate(
        reservation_intent,
        &signing_keys,
        &witness_positions,
        0x9b,
        b"sealed-lattice/v1/state/wrong-purpose",
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &wrong_context_certificate.canonical_bytes().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::InvalidWitnessSignature { .. })
    ));

    let mut reordered_witnesses = certificate.witness_envelopes().to_vec();
    reordered_witnesses.swap(0, 1);
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
            reservation_intent,
            reordered_witnesses,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessOrder)
    );
    let mut duplicate_witnesses = certificate.witness_envelopes().to_vec();
    duplicate_witnesses[1] = duplicate_witnesses[0].clone();
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
            reservation_intent,
            duplicate_witnesses,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessOrder)
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
            reservation_intent,
            certificate.witness_envelopes()[..certificate.witness_envelopes().len() - 1].to_vec(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessCount { .. })
    ));

    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320::new(
            reservation_intent,
            subject_position,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::SubjectCannotWitness)
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320::new(
            reservation_intent,
            FOUNDATION_PROFILE.participant_count,
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessPositionOutOfRange { .. })
    ));

    let other_root = catalog_root(layout, 0x9d);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &other_root.canonical_bytes().unwrap(),
            &roster,
            &certificate_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateError::ObjectMismatch {
                field: "root-body identity"
            }
        )
    ));

    let alternate_witness_positions = canonical_witness_positions(
        FOUNDATION_PROFILE.participant_count,
        subject_position,
        FOUNDATION_PROFILE.state_witness_quorum,
        true,
    );
    let alternate_certificate = signed_state_certificate(
        reservation_intent,
        &signing_keys,
        &alternate_witness_positions,
        0xa1,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
    );
    assert_ne!(
        certificate.identity().unwrap(),
        alternate_certificate.identity().unwrap()
    );
}

#[test]
fn state_objects_bind_every_field_and_refuse_malformed_certificate_shapes() {
    let (roster, signing_keys) =
        roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, 0xb1);
    let context = preparation_context(&roster, 0xb3);
    let layout = catalog_layout(context, 2);
    let root_body = catalog_root(layout, 0xb5);
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body).unwrap();
    let witness_positions = canonical_witness_positions(
        FOUNDATION_PROFILE.participant_count,
        2,
        FOUNDATION_PROFILE.state_witness_quorum,
        false,
    );
    let certificate = signed_state_certificate(
        reservation_intent,
        &signing_keys,
        &witness_positions,
        0xb7,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
    );
    let certificate_bytes = certificate.canonical_bytes().unwrap();
    let certificate_tuple = decode_tuple(&certificate_bytes);
    let reservation_intent_tuple =
        decode_tuple(certificate_tuple.items[1].variable_value_bytes().unwrap());

    for field_position in 1..reservation_intent_tuple.items.len() {
        let mut changed_intent_tuple = reservation_intent_tuple.clone();
        changed_intent_tuple.items[field_position] = match field_position {
            1 => CanonicalItem::nonempty_ascii("wrong-operation-kind").unwrap(),
            2..=4 => CanonicalItem::hash512([field_position as u8; 64]),
            _ => unreachable!(),
        };
        let mut changed_certificate_tuple = certificate_tuple.clone();
        changed_certificate_tuple.items[1] =
            CanonicalItem::variable_bytes(changed_intent_tuple.encode().unwrap()).unwrap();
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
                layout,
                &root_body_bytes,
                &roster,
                &changed_certificate_tuple.encode().unwrap(),
            )
            .is_err(),
            "reservation intent field {field_position} must bind"
        );
    }

    let mut wrong_intent_domain = reservation_intent_tuple.clone();
    wrong_intent_domain.items[0] = CanonicalItem::nonempty_ascii(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_DOMAIN,
    )
    .unwrap();
    let mut wrong_intent_domain_certificate = certificate_tuple.clone();
    wrong_intent_domain_certificate.items[1] =
        CanonicalItem::variable_bytes(wrong_intent_domain.encode().unwrap()).unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &wrong_intent_domain_certificate.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateError::ObjectMismatch {
                field: "object domain"
            }
        )
    ));

    let mut wrong_certificate_domain = certificate_tuple.clone();
    wrong_certificate_domain.items[0] = CanonicalItem::nonempty_ascii(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_DOMAIN,
    )
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &wrong_certificate_domain.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogStateError::ObjectMismatch {
                field: "object domain"
            }
        )
    ));

    let mut missing_witness = certificate_tuple.clone();
    missing_witness.items.pop();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &missing_witness.encode().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessCount {
            expected: 7,
            actual: 6
        })
    ));

    let additional_witness_position = (0..FOUNDATION_PROFILE.participant_count)
        .find(|position| {
            *position != reservation_intent.subject_position()
                && !witness_positions.contains(position)
        })
        .unwrap();
    let additional_envelope = signed_witness_envelope(
        reservation_intent,
        additional_witness_position,
        &signing_keys[usize::from(additional_witness_position)],
        0xb9,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
    );
    let mut extra_witness = certificate_tuple.clone();
    extra_witness.items.push(
        CanonicalItem::variable_bytes(additional_envelope.canonical_bytes().unwrap()).unwrap(),
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &extra_witness.encode().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessCount {
            expected: 7,
            actual: 8
        })
    ));

    for truncated_length in [
        0,
        1,
        7,
        certificate_bytes.len() / 2,
        certificate_bytes.len() - 1,
    ] {
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
                layout,
                &root_body_bytes,
                &roster,
                &certificate_bytes[..truncated_length],
            )
            .is_err()
        );
    }
    assert!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            &roster,
            &[0_u8; 131_073],
        )
        .is_err()
    );
    let debug_output = format!("{certificate:?}");
    assert!(debug_output.contains("[redacted]"));
    assert!(!debug_output.contains(&"b7".repeat(32)));
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
        "preparation-seed-catalog-root"
    );
}

fn signed_state_certificate(
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    witness_positions: &[u16],
    seed_marker: u8,
    signature_context: &[u8],
) -> PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320 {
    let witness_envelopes = witness_positions
        .iter()
        .map(|witness_position| {
            signed_witness_envelope(
                reservation_intent,
                *witness_position,
                &signing_keys[usize::from(*witness_position)],
                seed_marker.wrapping_add(*witness_position as u8),
                signature_context,
            )
        })
        .collect();
    PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
        reservation_intent,
        witness_envelopes,
    )
    .unwrap()
}

fn signed_witness_envelope(
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    witness_position: u16,
    signing_key: &ml_dsa_65::PrivateKey,
    seed_marker: u8,
    signature_context: &[u8],
) -> PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320 {
    let authorization_body =
        PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320::new(
            reservation_intent,
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
    PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320::new(
        authorization_body,
        signature,
    )
}

fn canonical_witness_positions(
    participant_count: u16,
    subject_position: u16,
    witness_count: u16,
    take_from_end: bool,
) -> Vec<u16> {
    let positions = (0..participant_count)
        .filter(|position| *position != subject_position)
        .collect::<Vec<_>>();
    if take_from_end {
        positions[positions.len() - usize::from(witness_count)..].to_vec()
    } else {
        positions[..usize::from(witness_count)].to_vec()
    }
}

fn completion_quorum_masks(subject_position: u16) -> Vec<u32> {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let witness_quorum = FOUNDATION_PROFILE.state_witness_quorum;
    (0_u32..(1_u32 << participant_count))
        .filter(|mask| mask & (1_u32 << subject_position) == 0)
        .filter(|mask| mask.count_ones() == u32::from(witness_quorum))
        .collect()
}

fn catalog_layout(
    context: TallyPreparationContext,
    subject_position: u16,
) -> PseudorandomZeroSharingSeedCatalogLayout320 {
    PseudorandomZeroSharingSeedCatalogLayout320::derive(
        Hash512::from_bytes([0xc1; 64]),
        context,
        subject_position,
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

fn roster_and_signing_keys(
    participant_count: u16,
    marker: u8,
) -> (Roster, Vec<ml_dsa_65::PrivateKey>) {
    let mut signing_keys = Vec::with_capacity(usize::from(participant_count));
    let entries = (0..participant_count)
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

fn preparation_context(roster: &Roster, attempt_marker: u8) -> TallyPreparationContext {
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
        Hash512::from_bytes([0xd1; 64]),
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
