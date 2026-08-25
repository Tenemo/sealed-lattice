use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use crate::{
    encoding::CanonicalErrorCode,
    foundation::{Hash512, Roster, RosterEntry},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext,
    output_sharing::canonical_evaluation_point,
    replicated_beaver_opening::{
        TripleReductionOpeningBurnReason, TripleReductionOpeningError,
        TripleReductionOpeningProgress,
    },
    replicated_beaver_opening_record::{
        ML_DSA_65_SIGNATURE_BYTE_LENGTH, SignedTripleReductionOpeningCollector,
        SignedTripleReductionOpeningError, SignedTripleReductionOpeningRecord,
        TRIPLE_REDUCTION_OPENING_SIGNATURE_CONTEXT, TripleReductionOpeningRecordBody,
    },
    replicated_random_sharing::BinaryFieldPolynomial,
};

const PARTICIPANT_COUNT: u16 = 10;

#[test]
fn canonical_signed_records_round_trip_and_complete_in_any_sender_order() {
    assert_eq!(ML_DSA_65_SIGNATURE_BYTE_LENGTH, ml_dsa_65::SIG_LEN);
    let (roster, signing_keys) = roster_and_signing_keys(0x11);
    let circuit = circuit();
    let context = preparation_context(0x21, &circuit, &roster);
    let coordinate = super::replicated_beaver_opening::TripleReductionOpeningCoordinate::derive(
        context,
        &circuit,
        hash(0x31),
        0,
    )
    .unwrap();
    let polynomial = opening_polynomial();
    let signed_records = (0..PARTICIPANT_COUNT)
        .map(|roster_position| {
            let body = body(coordinate, roster_position, &polynomial);
            let record_bytes = signed_record_bytes(
                body,
                &signing_keys[usize::from(roster_position)],
                u8::try_from(0x40 + roster_position).unwrap(),
            );
            let parsed =
                SignedTripleReductionOpeningRecord::from_canonical_bytes(&record_bytes).unwrap();
            assert_eq!(parsed.body(), body);
            assert_eq!(parsed.canonical_bytes(), record_bytes);
            assert_eq!(
                TripleReductionOpeningRecordBody::from_canonical_bytes(&body.canonical_bytes())
                    .unwrap(),
                body
            );
            record_bytes
        })
        .collect::<Vec<_>>();
    assert!(
        signed_records
            .windows(2)
            .all(|records| records[0].len() == records[1].len())
    );

    let mut collector =
        SignedTripleReductionOpeningCollector::new(context, coordinate, &roster).unwrap();
    let first_record = &signed_records[9];
    assert_eq!(
        collector.absorb_canonical_record(first_record).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            required_sender_count: 10,
        }
    );
    assert_eq!(
        collector.absorb_canonical_record(first_record).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            required_sender_count: 10,
        }
    );

    let mut final_progress = None;
    for roster_position in (0..9).rev() {
        final_progress = Some(
            collector
                .absorb_canonical_record(&signed_records[roster_position])
                .unwrap(),
        );
    }
    let TripleReductionOpeningProgress::AlgebraicallyConsistent(result) = final_progress.unwrap()
    else {
        panic!("a complete signed exact codeword must pass the algebra-only check");
    };
    assert_eq!(result.coordinate_identity(), coordinate.identity());
    assert_eq!(result.polynomial(), &polynomial);
    assert_eq!(
        collector.absorb_canonical_record(first_record),
        Err(SignedTripleReductionOpeningError::Opening(
            TripleReductionOpeningError::AlreadyTerminal,
        ))
    );
}

#[test]
fn malformed_or_invalidly_signed_bytes_never_create_a_sender_slot() {
    let (roster, signing_keys) = roster_and_signing_keys(0x12);
    let circuit = circuit();
    let context = preparation_context(0x22, &circuit, &roster);
    let coordinate = super::replicated_beaver_opening::TripleReductionOpeningCoordinate::derive(
        context,
        &circuit,
        hash(0x32),
        0,
    )
    .unwrap();
    let polynomial = opening_polynomial();
    let record_body = body(coordinate, 0, &polynomial);
    let valid_record = signed_record_bytes(record_body, &signing_keys[0], 0x51);

    let mut invalid_signature_record = valid_record.clone();
    *invalid_signature_record.last_mut().unwrap() ^= 0x80;
    let mut collector =
        SignedTripleReductionOpeningCollector::new(context, coordinate, &roster).unwrap();
    assert_eq!(
        collector.absorb_canonical_record(&invalid_signature_record),
        Err(SignedTripleReductionOpeningError::InvalidSignature)
    );

    let wrong_key_record = signed_record_bytes(record_body, &signing_keys[1], 0x52);
    assert_eq!(
        collector.absorb_canonical_record(&wrong_key_record),
        Err(SignedTripleReductionOpeningError::InvalidSignature)
    );

    let truncated_record = &valid_record[..valid_record.len() - 1];
    assert!(matches!(
        collector.absorb_canonical_record(truncated_record),
        Err(SignedTripleReductionOpeningError::Canonical(_))
            | Err(SignedTripleReductionOpeningError::SignatureByteLength { .. })
    ));

    let mut trailing_record = valid_record.clone();
    trailing_record.push(0);
    assert!(matches!(
        collector.absorb_canonical_record(&trailing_record),
        Err(SignedTripleReductionOpeningError::Canonical(ref error))
            if error.code == CanonicalErrorCode::TrailingBytes
    ));

    let mut noncanonical_version_record = valid_record.clone();
    let version_offset = 1 + b"sealed-lattice/signed-triple-reduction-opening".len();
    assert_eq!(noncanonical_version_record[version_offset], 1);
    noncanonical_version_record[version_offset] = 0x81;
    noncanonical_version_record.insert(version_offset + 1, 0);
    assert!(matches!(
        collector.absorb_canonical_record(&noncanonical_version_record),
        Err(SignedTripleReductionOpeningError::Canonical(ref error))
            if error.code == CanonicalErrorCode::NonCanonicalVarUint
    ));

    assert_eq!(
        collector.absorb_canonical_record(&valid_record).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            required_sender_count: 10,
        }
    );
}

#[test]
fn a_second_valid_signature_for_the_same_slot_is_equivocation() {
    let (roster, signing_keys) = roster_and_signing_keys(0x13);
    let circuit = circuit();
    let context = preparation_context(0x23, &circuit, &roster);
    let coordinate = super::replicated_beaver_opening::TripleReductionOpeningCoordinate::derive(
        context,
        &circuit,
        hash(0x33),
        0,
    )
    .unwrap();
    let record_body = body(coordinate, 0, &opening_polynomial());
    let first_record = signed_record_bytes(record_body, &signing_keys[0], 0x61);
    let second_record = signed_record_bytes(record_body, &signing_keys[0], 0x62);
    assert_ne!(first_record, second_record);

    let mut collector =
        SignedTripleReductionOpeningCollector::new(context, coordinate, &roster).unwrap();
    assert!(matches!(
        collector.absorb_canonical_record(&first_record).unwrap(),
        TripleReductionOpeningProgress::Pending { .. }
    ));
    assert_eq!(
        collector.absorb_canonical_record(&second_record).unwrap(),
        TripleReductionOpeningProgress::BurnRequired(
            TripleReductionOpeningBurnReason::Equivocation,
        )
    );
    assert_eq!(
        collector.absorb_canonical_record(&first_record),
        Err(SignedTripleReductionOpeningError::Opening(
            TripleReductionOpeningError::AlreadyTerminal,
        ))
    );
}

#[test]
fn a_validly_signed_wrong_value_burns_only_after_the_complete_roster_arrives() {
    let (roster, signing_keys) = roster_and_signing_keys(0x16);
    let circuit = circuit();
    let context = preparation_context(0x26, &circuit, &roster);
    let coordinate = super::replicated_beaver_opening::TripleReductionOpeningCoordinate::derive(
        context,
        &circuit,
        hash(0x36),
        0,
    )
    .unwrap();
    let polynomial = opening_polynomial();
    let corrupt_position = PARTICIPANT_COUNT - 1;
    let corrupt_body = TripleReductionOpeningRecordBody::new(
        coordinate,
        corrupt_position,
        value(&polynomial, corrupt_position).add(BinaryFieldElement256::ONE),
    )
    .unwrap();
    let corrupt_record = signed_record_bytes(
        corrupt_body,
        &signing_keys[usize::from(corrupt_position)],
        0x7b,
    );
    let mut collector =
        SignedTripleReductionOpeningCollector::new(context, coordinate, &roster).unwrap();
    assert_eq!(
        collector.absorb_canonical_record(&corrupt_record).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            required_sender_count: 10,
        }
    );

    let mut final_progress = None;
    for roster_position in 0..corrupt_position {
        let honest_record = signed_record_bytes(
            body(coordinate, roster_position, &polynomial),
            &signing_keys[usize::from(roster_position)],
            u8::try_from(0x80 + roster_position).unwrap(),
        );
        final_progress = Some(collector.absorb_canonical_record(&honest_record).unwrap());
    }
    assert_eq!(
        final_progress.unwrap(),
        TripleReductionOpeningProgress::BurnRequired(TripleReductionOpeningBurnReason::NonCodeword,)
    );
}

#[test]
fn validly_signed_wrong_context_point_count_and_predecessor_records_burn() {
    let (roster, signing_keys) = roster_and_signing_keys(0x14);
    let circuit = circuit();
    let context = preparation_context(0x24, &circuit, &roster);
    let coordinate = super::replicated_beaver_opening::TripleReductionOpeningCoordinate::derive(
        context,
        &circuit,
        hash(0x34),
        0,
    )
    .unwrap();
    let changed_predecessor_coordinate =
        super::replicated_beaver_opening::TripleReductionOpeningCoordinate::derive(
            context,
            &circuit,
            hash(0x35),
            0,
        )
        .unwrap();
    let polynomial = opening_polynomial();
    let expected_value = value(&polynomial, 0);

    let hostile_cases = [
        (
            TripleReductionOpeningRecordBody::from_untrusted_fields(
                changed_predecessor_coordinate.identity(),
                PARTICIPANT_COUNT,
                0,
                canonical_evaluation_point(PARTICIPANT_COUNT, 0).unwrap(),
                expected_value,
            ),
            TripleReductionOpeningBurnReason::CoordinateMismatch,
        ),
        (
            TripleReductionOpeningRecordBody::from_untrusted_fields(
                coordinate.identity(),
                PARTICIPANT_COUNT,
                0,
                canonical_evaluation_point(PARTICIPANT_COUNT, 1).unwrap(),
                expected_value,
            ),
            TripleReductionOpeningBurnReason::EvaluationPointMismatch,
        ),
        (
            TripleReductionOpeningRecordBody::from_untrusted_fields(
                coordinate.identity(),
                PARTICIPANT_COUNT - 1,
                0,
                canonical_evaluation_point(PARTICIPANT_COUNT, 0).unwrap(),
                expected_value,
            ),
            TripleReductionOpeningBurnReason::ParticipantCountMismatch,
        ),
    ];
    for (case_ordinal, (record_body, expected_burn_reason)) in hostile_cases.into_iter().enumerate()
    {
        let record = signed_record_bytes(
            record_body,
            &signing_keys[0],
            u8::try_from(0x70 + case_ordinal).unwrap(),
        );
        let mut collector =
            SignedTripleReductionOpeningCollector::new(context, coordinate, &roster).unwrap();
        assert_eq!(
            collector.absorb_canonical_record(&record).unwrap(),
            TripleReductionOpeningProgress::BurnRequired(expected_burn_reason)
        );
    }

    let changed_context = preparation_context(0x25, &circuit, &roster);
    assert!(matches!(
        SignedTripleReductionOpeningCollector::new(changed_context, coordinate, &roster),
        Err(SignedTripleReductionOpeningError::ContextMismatch)
    ));

    let (different_roster, _) = roster_and_signing_keys(0x15);
    assert!(matches!(
        SignedTripleReductionOpeningCollector::new(context, coordinate, &different_roster),
        Err(SignedTripleReductionOpeningError::RosterMismatch)
    ));

    let out_of_range_body = TripleReductionOpeningRecordBody::from_untrusted_fields(
        coordinate.identity(),
        PARTICIPANT_COUNT,
        PARTICIPANT_COUNT,
        BinaryFieldElement256::ONE,
        expected_value,
    );
    let out_of_range_record = signed_record_bytes(out_of_range_body, &signing_keys[0], 0x79);
    let mut collector =
        SignedTripleReductionOpeningCollector::new(context, coordinate, &roster).unwrap();
    assert_eq!(
        collector.absorb_canonical_record(&out_of_range_record),
        Err(
            SignedTripleReductionOpeningError::SenderPositionOutOfRange {
                roster_position: PARTICIPANT_COUNT,
                participant_count: PARTICIPANT_COUNT,
            }
        )
    );
    let valid_record =
        signed_record_bytes(body(coordinate, 0, &polynomial), &signing_keys[0], 0x7a);
    assert!(matches!(
        collector.absorb_canonical_record(&valid_record).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            ..
        }
    ));
}

fn signed_record_bytes(
    body: TripleReductionOpeningRecordBody,
    signing_key: &ml_dsa_65::PrivateKey,
    signature_seed_marker: u8,
) -> Vec<u8> {
    let signature = signing_key
        .try_sign_with_seed(
            &[signature_seed_marker; 32],
            &body.canonical_bytes(),
            TRIPLE_REDUCTION_OPENING_SIGNATURE_CONTEXT,
        )
        .unwrap();
    SignedTripleReductionOpeningRecord::new(body, signature).canonical_bytes()
}

fn roster_and_signing_keys(marker: u8) -> (Roster, Vec<ml_dsa_65::PrivateKey>) {
    let mut signing_keys = Vec::with_capacity(usize::from(PARTICIPANT_COUNT));
    let entries = (0..PARTICIPANT_COUNT)
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
            let (mailbox_encapsulation_key, _) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            RosterEntry::new(
                roster_position,
                signing_verification_key.into_bytes(),
                mailbox_encapsulation_key.into_bytes(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    (Roster::new(entries).unwrap(), signing_keys)
}

fn body(
    coordinate: super::replicated_beaver_opening::TripleReductionOpeningCoordinate,
    roster_position: u16,
    polynomial: &BinaryFieldPolynomial,
) -> TripleReductionOpeningRecordBody {
    TripleReductionOpeningRecordBody::new(
        coordinate,
        roster_position,
        value(polynomial, roster_position),
    )
    .unwrap()
}

fn value(polynomial: &BinaryFieldPolynomial, roster_position: u16) -> BinaryFieldElement256 {
    polynomial.evaluate(canonical_evaluation_point(PARTICIPANT_COUNT, roster_position).unwrap())
}

fn opening_polynomial() -> BinaryFieldPolynomial {
    BinaryFieldPolynomial::new(
        (0..=6)
            .map(|coefficient_position| {
                BinaryFieldElement256::from_low_polynomial_u16(0x181 + coefficient_position)
            })
            .collect(),
    )
}

fn preparation_context(
    marker: u8,
    circuit: &CompiledTallyCircuit,
    roster: &Roster,
) -> TallyPreparationContext {
    TallyPreparationContext::new(
        hash(marker),
        roster.roster_hash().unwrap(),
        [marker.wrapping_add(1); 32],
        circuit,
    )
    .unwrap()
}

fn circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(TallyCircuitProfile::new(PARTICIPANT_COUNT, 2, 1).unwrap())
        .unwrap()
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
}
