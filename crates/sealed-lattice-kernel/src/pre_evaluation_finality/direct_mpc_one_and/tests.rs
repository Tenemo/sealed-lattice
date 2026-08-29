use std::collections::HashMap;

use super::*;
use crate::{
    foundation::FOUNDATION_PROFILE,
    pre_evaluation_finality::tests::{
        TestEnvironment, canonical_witness_positions, no_result_terminal_bytes, sign_test_message,
        signed_state_output_certificate, target_finality_terminal, test_environment,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
    tally_preparation::{
        ReplicatedRandomSharingSubset, TallyPreparationContext,
        locally_joined_seed_masters_for_direct_mpc_test,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestStateError {
    Conflict,
    Retired,
}

#[derive(Default)]
struct TestOneShotState {
    retained_outputs: HashMap<Hash512, (Hash512, Vec<u8>)>,
    retired: bool,
}

impl TestOneShotState {
    fn authorize(
        &mut self,
        intent: StateOutputIntent,
        carrier: Vec<u8>,
    ) -> Result<Vec<u8>, TestStateError> {
        if self.retired {
            return Err(TestStateError::Retired);
        }
        match self.retained_outputs.get(&intent.state_key_identity) {
            Some((retained_identity, retained_carrier))
                if *retained_identity == intent.semantic_body_identity =>
            {
                Ok(retained_carrier.clone())
            }
            Some(_) => Err(TestStateError::Conflict),
            None => {
                self.retained_outputs.insert(
                    intent.state_key_identity,
                    (intent.semantic_body_identity, carrier.clone()),
                );
                Ok(carrier)
            }
        }
    }

    fn retire_after_rollback(&mut self) {
        self.retired = true;
    }
}

struct OneAndFixture {
    environment: TestEnvironment,
    context: DirectMpcOneAndContext,
    preparation: VerifiedDirectMpcOneAndPreparation,
    preparation_terminal: Vec<u8>,
    input_source_terminal: Vec<u8>,
    selected_set: VerifiedDirectMpcOneAndSelectedSet,
    selected_set_terminal: Vec<u8>,
    target: DirectMpcOneAndTarget,
    finality: VerifiedTargetFinality,
    activation: VerifiedDirectMpcOneAndActivation,
    events: Vec<Vec<u8>>,
    activation_bodies: Vec<DirectMpcActivationShareBody>,
    output_bodies: Vec<DirectMpcOutputShareBody>,
}

#[test]
fn direct_mpc_one_and_producer_and_positive_verifier_return_both_clear_results() {
    for (protected_input, marker) in [(false, 0x31), (true, 0x71)] {
        let fixture = one_and_fixture(protected_input, marker);
        let result_identity = match verify_output_terminal(
            fixture.context,
            fixture.activation,
            &fixture.environment.roster,
            &fixture.events[3],
        )
        .unwrap()
        {
            DirectMpcOutputVerification::ClearResult {
                result_identity, ..
            } => result_identity,
            DirectMpcOutputVerification::Burn { .. } => panic!("valid output burned"),
        };
        assert_eq!(
            verify_direct_mpc_one_and_ceremony(
                &fixture.environment.action_context,
                &fixture.environment.roster,
                &fixture.preparation,
                &fixture.selected_set,
                &fixture.events,
            ),
            DirectMpcOneAndVerification::Complete {
                terminal: VerifiedDirectMpcOneAndTerminal::ClearResult {
                    target_identity: fixture.target.identity,
                    result_identity,
                    result: protected_input,
                },
            }
        );
    }
}

#[test]
fn canonical_bundle_matches_the_positive_verifier_and_typed_refusal() {
    let fixture = one_and_fixture(true, 0xa1);
    let request = verification_bundle_bytes(&fixture, Some(&fixture.input_source_terminal));
    let expected_response = run_direct_mpc_one_and_verification_bundle(&request);
    assert_verification_response(
        &expected_response,
        VERIFICATION_STATUS_CLEAR_RESULT,
        0,
        NEXT_EVENT_NONE,
        true,
    );

    let pending_input_source_request = verification_bundle_bytes(&fixture, None);
    assert_verification_response(
        &run_direct_mpc_one_and_verification_bundle(&pending_input_source_request),
        VERIFICATION_STATUS_PENDING,
        0,
        NEXT_EVENT_INPUT_SOURCE_TERMINAL,
        false,
    );

    let mut hostile_request = request.clone();
    let final_byte = hostile_request
        .last_mut()
        .expect("verification bundle is not empty");
    *final_byte ^= 0x01;
    let hostile_response = run_direct_mpc_one_and_verification_bundle(&hostile_request);
    assert_verification_response(
        &hostile_response,
        VERIFICATION_STATUS_REFUSED,
        RefusalReason::InvalidSignature.canonical_code(),
        NEXT_EVENT_NONE,
        false,
    );

    if let Some(output_directory) =
        std::env::var_os("SEALED_LATTICE_DIRECT_MPC_ONE_AND_FIXTURE_DIRECTORY")
    {
        let output_directory = std::path::PathBuf::from(output_directory);
        std::fs::create_dir_all(&output_directory).unwrap();
        for (file_name, bytes) in [
            ("request.bin", request.as_slice()),
            ("response.bin", expected_response.as_slice()),
            ("hostile-request.bin", hostile_request.as_slice()),
            ("hostile-response.bin", hostile_response.as_slice()),
        ] {
            std::fs::write(output_directory.join(file_name), bytes).unwrap();
        }
    }
}

#[test]
fn bounded_preparation_checkpoint_restores_identical_share_and_refuses_mutation() {
    let environment = test_environment(0x22);
    let context = DirectMpcOneAndContext::for_test(
        &environment.action_context,
        &environment.roster,
        hash(0x41),
        hash(0x42),
    )
    .unwrap();
    let checkpoint_key = [0x53; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH];
    let mut interrupted = DirectMpcOneAndPreparationCursor::from_test_subset_masters(
        context,
        0,
        test_subset_masters(context, 0),
        checkpoint_key,
    )
    .unwrap();
    for _ in 0..37 {
        assert!(!interrupted.step().unwrap());
    }
    let checkpoint = interrupted.checkpoint_bytes().unwrap();
    let mut restored = DirectMpcOneAndPreparationCursor::restore_from_test_checkpoint(
        context,
        0,
        test_subset_masters(context, 0),
        checkpoint_key,
        &checkpoint,
    )
    .unwrap();
    while !restored.step().unwrap() {}
    let restored_body = restored.finish().unwrap().preparation_share_body();

    let mut uninterrupted = DirectMpcOneAndPreparationCursor::from_test_subset_masters(
        context,
        0,
        test_subset_masters(context, 0),
        checkpoint_key,
    )
    .unwrap();
    while !uninterrupted.step().unwrap() {}
    assert_eq!(
        restored_body,
        uninterrupted.finish().unwrap().preparation_share_body()
    );

    let mut changed_checkpoint = checkpoint.to_vec();
    let changed_position = changed_checkpoint.len() / 2;
    changed_checkpoint[changed_position] ^= 1;
    assert!(matches!(
        DirectMpcOneAndPreparationCursor::restore_from_test_checkpoint(
            context,
            0,
            test_subset_masters(context, 0),
            checkpoint_key,
            &changed_checkpoint,
        ),
        Err(DirectMpcOneAndError::Cursor(
            DirectMpcCursorError::CheckpointAuthenticationFailed
                | DirectMpcCursorError::CheckpointEncoding
        ))
    ));
}

#[test]
fn preparation_cursor_consumes_only_typed_joined_seed_custody() {
    let environment = test_environment(0x27);
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    let preparation_context = TallyPreparationContext::new(
        environment.action_context.context_hash(),
        environment.roster.roster_hash().unwrap(),
        [0x43; 32],
        &circuit,
    )
    .unwrap();
    let parameter_identity = hash(0x44);
    let participant_position = 0;
    let subset_masters = ReplicatedRandomSharingSubset::iter(FOUNDATION_PROFILE.participant_count)
        .unwrap()
        .filter(|subset| subset.contains(participant_position).unwrap())
        .map(|subset| {
            let mut bytes = [0x45; 40];
            bytes[..4].copy_from_slice(&subset.excluded_position_mask().to_le_bytes());
            (subset, bytes)
        })
        .collect();
    let joined_seed_masters = locally_joined_seed_masters_for_direct_mpc_test(
        parameter_identity,
        preparation_context,
        participant_position,
        subset_masters,
    );
    let context = DirectMpcOneAndContext::from_verified_seed_custody(
        &environment.action_context,
        &environment.roster,
        &joined_seed_masters,
    )
    .unwrap();
    let checkpoint_key = [0x46; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH];
    let mut cursor = DirectMpcOneAndPreparationCursor::from_verified_seed_custody(
        context,
        &joined_seed_masters,
        checkpoint_key,
    )
    .unwrap();
    for _ in 0..23 {
        assert!(!cursor.step().unwrap());
    }
    let checkpoint = cursor.checkpoint_bytes().unwrap();
    let mut restored =
        DirectMpcOneAndPreparationCursor::restore_from_checkpoint_with_verified_seed_custody(
            context,
            &joined_seed_masters,
            checkpoint_key,
            &checkpoint,
        )
        .unwrap();
    while !restored.step().unwrap() {}
    assert_eq!(
        restored
            .finish()
            .unwrap()
            .preparation_share_body()
            .participant_position,
        participant_position
    );
}

#[test]
fn missing_and_premature_online_events_never_mint_continuation() {
    let fixture = one_and_fixture(true, 0x39);
    let expected = [
        DirectMpcOneAndRequiredEvent::ComputationTarget,
        DirectMpcOneAndRequiredEvent::TargetFinality,
        DirectMpcOneAndRequiredEvent::ActivationTerminal,
        DirectMpcOneAndRequiredEvent::OutputTerminal,
    ];
    for (event_count, next_required) in expected.into_iter().enumerate() {
        assert_eq!(
            verify_direct_mpc_one_and_ceremony(
                &fixture.environment.action_context,
                &fixture.environment.roster,
                &fixture.preparation,
                &fixture.selected_set,
                &fixture.events[..event_count],
            ),
            DirectMpcOneAndVerification::Pending { next_required }
        );
    }

    for events in [
        vec![fixture.events[2].clone()],
        vec![fixture.events[3].clone()],
        vec![fixture.events[0].clone(), fixture.events[2].clone()],
    ] {
        assert_eq!(
            verify_direct_mpc_one_and_ceremony(
                &fixture.environment.action_context,
                &fixture.environment.roster,
                &fixture.preparation,
                &fixture.selected_set,
                &events,
            ),
            DirectMpcOneAndVerification::Refused {
                refusal_reason: RefusalReason::MissingPrerequisite,
            }
        );
    }
}

#[test]
fn authenticated_opening_inconsistency_burns_and_cannot_be_retried() {
    let fixture = one_and_fixture(true, 0x4b);
    let mut activation_bodies = fixture.activation_bodies.clone();
    activation_bodies[8].opened_input_difference = activation_bodies[8]
        .opened_input_difference
        .add(DirectMpcPrimeFieldElement::ONE);
    let activation_terminal = activation_terminal_from_bodies(&fixture, &activation_bodies, 0x91);
    let mut events = vec![
        fixture.events[0].clone(),
        fixture.events[1].clone(),
        activation_terminal,
    ];
    let verification = verify_direct_mpc_one_and_ceremony(
        &fixture.environment.action_context,
        &fixture.environment.roster,
        &fixture.preparation,
        &fixture.selected_set,
        &events,
    );
    assert!(matches!(
        verification,
        DirectMpcOneAndVerification::Complete {
            terminal: VerifiedDirectMpcOneAndTerminal::Abort {
                target_identity,
                reason: DirectMpcOneAndAbortReason::AuthenticatedActivationInconsistency,
                ..
            }
        } if target_identity == fixture.target.identity
    ));
    events.push(fixture.events[3].clone());
    assert_eq!(
        verify_direct_mpc_one_and_ceremony(
            &fixture.environment.action_context,
            &fixture.environment.roster,
            &fixture.preparation,
            &fixture.selected_set,
            &events,
        ),
        verification
    );

    let mut output_bodies = fixture.output_bodies.clone();
    output_bodies[9].output_share = output_bodies[9]
        .output_share
        .add(DirectMpcPrimeFieldElement::ONE);
    let output_terminal = output_terminal_from_bodies(&fixture, &output_bodies, 0xa1);
    let output_events = vec![
        fixture.events[0].clone(),
        fixture.events[1].clone(),
        fixture.events[2].clone(),
        output_terminal,
    ];
    assert!(matches!(
        verify_direct_mpc_one_and_ceremony(
            &fixture.environment.action_context,
            &fixture.environment.roster,
            &fixture.preparation,
            &fixture.selected_set,
            &output_events,
        ),
        DirectMpcOneAndVerification::Complete {
            terminal: VerifiedDirectMpcOneAndTerminal::Abort {
                reason: DirectMpcOneAndAbortReason::AuthenticatedOutputInconsistency,
                ..
            }
        }
    ));
}

#[test]
fn phase_state_replays_exact_bytes_and_retires_after_rollback() {
    let fixture = one_and_fixture(false, 0x5d);
    let semantic_body = authorized_phase_semantic_body(&fixture.events[2]).unwrap();
    let transcript = decode_domain_tuple(&semantic_body, ACTIVATION_TRANSCRIPT_DOMAIN).unwrap();
    let normalized_items = transcript.items[1..]
        .iter()
        .map(|item| {
            let carrier = decode_domain_tuple(
                read_variable_bytes(item).unwrap(),
                ACTIVATION_SHARE_CARRIER_DOMAIN,
            )
            .unwrap();
            CanonicalItem::variable_bytes(read_variable_bytes(&carrier.items[1]).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    let semantic_identity =
        hash_foundation_tuple_512(ACTIVATION_TRANSCRIPT_IDENTITY_DOMAIN, &normalized_items)
            .unwrap();
    let endorsement = PhaseEndorsementBody {
        operation_kind: ACTIVATION_TERMINAL_OPERATION_KIND,
        predecessor_identity: fixture.finality.finality_identity,
        semantic_body_identity: semantic_identity,
        subject_position: 0,
    };
    let intent = StateOutputIntent::new_with_namespace(
        fixture.context.suite_identity,
        fixture.context.action_context_identity,
        fixture.preparation.identity,
        fixture.context.participant_count,
        ACTIVATION_TERMINAL_OPERATION_KIND,
        0,
        fixture.finality.finality_identity,
        endorsement.identity().unwrap(),
    )
    .unwrap();
    let mut state = TestOneShotState::default();
    let retained = state.authorize(intent, fixture.events[2].clone()).unwrap();
    assert_eq!(state.authorize(intent, vec![0x11]).unwrap(), retained);

    let conflicting_endorsement = PhaseEndorsementBody {
        semantic_body_identity: hash(0xe1),
        ..endorsement
    };
    let conflicting_intent = StateOutputIntent::new_with_namespace(
        fixture.context.suite_identity,
        fixture.context.action_context_identity,
        fixture.preparation.identity,
        fixture.context.participant_count,
        ACTIVATION_TERMINAL_OPERATION_KIND,
        0,
        fixture.finality.finality_identity,
        conflicting_endorsement.identity().unwrap(),
    )
    .unwrap();
    assert_eq!(
        state.authorize(conflicting_intent, vec![0x22]),
        Err(TestStateError::Conflict)
    );
    state.retire_after_rollback();
    assert_eq!(
        state.authorize(intent, fixture.events[2].clone()),
        Err(TestStateError::Retired)
    );
}

#[test]
fn all_abstention_has_one_no_result_terminal_and_no_target() {
    let environment = test_environment(0x63);
    let context = DirectMpcOneAndContext::for_test(
        &environment.action_context,
        &environment.roster,
        hash(0x31),
        hash(0x32),
    )
    .unwrap();
    let (preparation, _online, _terminal) = preparation_fixture(context, &environment, 0x41);
    let declarations = (0..context.participant_count)
        .map(|participant_position| {
            DirectMpcOneAndDeclarationBody::abstain(context, participant_position).unwrap()
        })
        .collect::<Vec<_>>();
    let selected_terminal =
        selected_set_terminal_from_bodies(context, &preparation, &environment, &declarations, 0x51);
    let selected_set = verify_selected_set_terminal(
        context,
        &preparation,
        None,
        &environment.roster,
        Some(&selected_terminal),
    )
    .unwrap()
    .unwrap();
    assert!(
        derive_direct_mpc_one_and_target(
            &environment.action_context,
            &environment.roster,
            &preparation,
            &selected_set,
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        verify_direct_mpc_one_and_ceremony(
            &environment.action_context,
            &environment.roster,
            &preparation,
            &selected_set,
            &[],
        ),
        DirectMpcOneAndVerification::Pending {
            next_required: DirectMpcOneAndRequiredEvent::NoResultTerminal,
        }
    );
    let scope = PreEvaluationFinalityScope::all_abstained(
        &environment.action_context,
        &environment.roster,
        preparation.identity,
        selected_set.root,
    )
    .unwrap();
    let no_result = no_result_terminal_bytes(scope);
    assert_eq!(
        verify_direct_mpc_one_and_ceremony(
            &environment.action_context,
            &environment.roster,
            &preparation,
            &selected_set,
            &[no_result],
        ),
        DirectMpcOneAndVerification::Complete {
            terminal: VerifiedDirectMpcOneAndTerminal::NoResult {
                selected_set_root: selected_set.root,
            }
        }
    );
}

#[test]
fn every_three_recipient_view_has_an_exact_zero_and_one_completion() {
    let shared_corrupt_values = [
        DirectMpcPrimeFieldElement::from_u16(101),
        DirectMpcPrimeFieldElement::from_u16(211),
        DirectMpcPrimeFieldElement::from_u16(307),
    ];
    for first in 0_u16..8 {
        for second in first + 1..9 {
            for third in second + 1..10 {
                let points = [first + 1, second + 1, third + 1];
                let zero_coefficients = interpolate_four_points(
                    DirectMpcPrimeFieldElement::ZERO,
                    points,
                    shared_corrupt_values,
                );
                let one_coefficients = interpolate_four_points(
                    DirectMpcPrimeFieldElement::ONE,
                    points,
                    shared_corrupt_values,
                );
                assert_eq!(zero_coefficients[0], DirectMpcPrimeFieldElement::ZERO);
                assert_eq!(one_coefficients[0], DirectMpcPrimeFieldElement::ONE);
                for (point, expected) in points.into_iter().zip(shared_corrupt_values) {
                    assert_eq!(
                        evaluate_prime_field_polynomial(
                            &zero_coefficients,
                            DirectMpcPrimeFieldElement::from_u16(point),
                        ),
                        expected
                    );
                    assert_eq!(
                        evaluate_prime_field_polynomial(
                            &one_coefficients,
                            DirectMpcPrimeFieldElement::from_u16(point),
                        ),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn exact_codeword_check_recovers_the_constant_and_rejects_one_changed_coordinate() {
    let coefficients = [
        DirectMpcPrimeFieldElement::from_u16(1),
        DirectMpcPrimeFieldElement::from_u16(17),
        DirectMpcPrimeFieldElement::from_u16(29),
        DirectMpcPrimeFieldElement::from_u16(43),
    ];
    let mut values = (1_u16..=10)
        .map(|point| {
            evaluate_prime_field_polynomial(
                &coefficients,
                DirectMpcPrimeFieldElement::from_u16(point),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        exact_codeword_constant(&values, 3).unwrap(),
        Some(DirectMpcPrimeFieldElement::ONE)
    );
    values[8] = values[8].add(DirectMpcPrimeFieldElement::ONE);
    assert_eq!(exact_codeword_constant(&values, 3).unwrap(), None);
}

fn verification_bundle_bytes(
    fixture: &OneAndFixture,
    input_source_terminal: Option<&[u8]>,
) -> Vec<u8> {
    let mut items = vec![
        CanonicalItem::hash512(fixture.environment.action_context.suite_id().into_bytes()),
        CanonicalItem::hash512(
            fixture
                .environment
                .action_context
                .context_hash()
                .into_bytes(),
        ),
        CanonicalItem::variable_bytes(fixture.environment.roster.encode().unwrap()).unwrap(),
        CanonicalItem::hash512(fixture.context.preparation_context_identity.into_bytes()),
        CanonicalItem::hash512(fixture.context.seed_terminal_identity.into_bytes()),
        CanonicalItem::variable_bytes(&fixture.preparation_terminal).unwrap(),
        CanonicalItem::variable_bytes(input_source_terminal.unwrap_or(&[])).unwrap(),
        CanonicalItem::variable_bytes(&fixture.selected_set_terminal).unwrap(),
        CanonicalItem::unsigned16(u16::try_from(fixture.events.len()).unwrap()),
    ];
    items.extend(
        fixture
            .events
            .iter()
            .map(|event| CanonicalItem::variable_bytes(event).unwrap()),
    );
    encode_domain_tuple(VERIFICATION_BUNDLE_DOMAIN, items).unwrap()
}

fn assert_verification_response(
    response: &[u8],
    expected_status: u16,
    expected_refusal_reason: u16,
    expected_next_event: u16,
    expected_result: bool,
) {
    let tuple = decode_domain_tuple(response, VERIFICATION_RESPONSE_DOMAIN).unwrap();
    assert_eq!(tuple.items.len(), 12);
    assert_eq!(read_u16(&tuple.items[1]).unwrap(), expected_status);
    assert_eq!(read_u16(&tuple.items[2]).unwrap(), expected_refusal_reason);
    assert_eq!(read_u16(&tuple.items[3]).unwrap(), expected_next_event);
    assert_eq!(read_boolean(&tuple.items[10]).unwrap(), expected_result);
    assert_eq!(read_boolean(&tuple.items[11]).unwrap(), expected_result);
}

fn one_and_fixture(protected_input: bool, marker: u8) -> OneAndFixture {
    let environment = test_environment(marker);
    let context = DirectMpcOneAndContext::for_test(
        &environment.action_context,
        &environment.roster,
        hash(marker.wrapping_add(1)),
        hash(marker.wrapping_add(2)),
    )
    .unwrap();
    let (preparation, online_participants, preparation_terminal) =
        preparation_fixture(context, &environment, marker.wrapping_add(3));
    let source_position = 0;
    let commitment_salts = (0..context.participant_count)
        .map(|recipient_position| {
            [marker
                .wrapping_add(0x21)
                .wrapping_add(recipient_position as u8);
                INPUT_SHARE_COMMITMENT_SALT_BYTE_LENGTH]
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let source_material = DirectMpcOneAndInputSourceMaterial::new(
        context,
        source_position,
        protected_input,
        [
            DirectMpcPrimeFieldElement::from_u16(109),
            DirectMpcPrimeFieldElement::from_u16(223),
            DirectMpcPrimeFieldElement::from_u16(397),
        ],
        commitment_salts,
    )
    .unwrap();
    assert_eq!(source_material.context, context);
    assert_eq!(source_material.source_position, source_position);
    let manifest_body_bytes = source_material.manifest_body_bytes().unwrap();
    let manifest_carrier = signed_carrier(
        INPUT_SOURCE_MANIFEST_CARRIER_DOMAIN,
        &manifest_body_bytes,
        source_position,
        INPUT_SOURCE_MANIFEST_SIGNATURE_CONTEXT,
        &environment,
        marker.wrapping_add(4),
    );
    let mut input_shares = Vec::with_capacity(usize::from(context.participant_count));
    let mut acknowledgement_carriers = Vec::with_capacity(usize::from(context.participant_count));
    let mut acknowledgement_body_bytes = Vec::with_capacity(usize::from(context.participant_count));
    for recipient_position in 0..context.participant_count {
        let delivery_body_bytes = source_material
            .delivery_body_bytes(recipient_position)
            .unwrap();
        let delivery_carrier = signed_carrier(
            INPUT_SHARE_DELIVERY_CARRIER_DOMAIN,
            &delivery_body_bytes,
            source_position,
            INPUT_SHARE_DELIVERY_SIGNATURE_CONTEXT,
            &environment,
            marker.wrapping_add(5),
        );
        let input_share = verify_input_share_delivery(
            context,
            &environment.roster,
            &manifest_carrier,
            recipient_position,
            &delivery_carrier,
        )
        .unwrap();
        let body_bytes = input_share
            .acknowledgement_body()
            .canonical_bytes()
            .unwrap();
        acknowledgement_carriers.push(signed_carrier(
            INPUT_SHARE_ACKNOWLEDGEMENT_CARRIER_DOMAIN,
            &body_bytes,
            recipient_position,
            INPUT_SHARE_ACKNOWLEDGEMENT_SIGNATURE_CONTEXT,
            &environment,
            marker.wrapping_add(6),
        ));
        acknowledgement_body_bytes.push(body_bytes);
        input_shares.push(input_share);
    }
    let mut source_transcript_items = Vec::with_capacity(1 + acknowledgement_carriers.len());
    source_transcript_items.push(CanonicalItem::variable_bytes(&manifest_carrier).unwrap());
    source_transcript_items.extend(
        acknowledgement_carriers
            .iter()
            .map(|carrier| CanonicalItem::variable_bytes(carrier).unwrap()),
    );
    let source_transcript =
        encode_domain_tuple(INPUT_SOURCE_TRANSCRIPT_DOMAIN, source_transcript_items).unwrap();
    let mut source_identity_items = vec![
        CanonicalItem::variable_bytes(source_material.manifest_body.canonical_bytes().unwrap())
            .unwrap(),
    ];
    source_identity_items.extend(
        acknowledgement_body_bytes
            .iter()
            .map(|body| CanonicalItem::variable_bytes(body).unwrap()),
    );
    let source_transcript_identity = hash_foundation_tuple_512(
        INPUT_SOURCE_TRANSCRIPT_IDENTITY_DOMAIN,
        &source_identity_items,
    )
    .unwrap();
    let source_terminal = authorized_phase_terminal(
        context,
        &environment,
        INPUT_SOURCE_TERMINAL_OPERATION_KIND,
        context.seed_terminal_identity,
        preparation.identity,
        source_transcript_identity,
        &source_transcript,
        marker.wrapping_add(7),
    );
    let input_source = verify_input_source_terminal(
        context,
        &preparation,
        &environment.roster,
        Some(&source_terminal),
    )
    .unwrap()
    .unwrap();

    let declarations = (0..context.participant_count)
        .map(|participant_position| {
            if participant_position == source_position {
                DirectMpcOneAndDeclarationBody::submit(
                    context,
                    participant_position,
                    input_source.root,
                )
                .unwrap()
            } else {
                DirectMpcOneAndDeclarationBody::abstain(context, participant_position).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let selected_terminal = selected_set_terminal_from_bodies(
        context,
        &preparation,
        &environment,
        &declarations,
        marker.wrapping_add(8),
    );
    let selected_set = verify_selected_set_terminal(
        context,
        &preparation,
        Some(&input_source),
        &environment.roster,
        Some(&selected_terminal),
    )
    .unwrap()
    .unwrap();
    let target = derive_direct_mpc_one_and_target(
        &environment.action_context,
        &environment.roster,
        &preparation,
        &selected_set,
    )
    .unwrap()
    .unwrap();
    let target_bytes = target.body.canonical_bytes().unwrap();
    let finality_bytes = target_finality_terminal(
        target.scope,
        target.body,
        &environment,
        &(0..FOUNDATION_PROFILE.finality_quorum).collect::<Vec<_>>(),
        false,
        marker.wrapping_add(9),
    );
    let finality = verify_target_finality_terminal(
        target.scope,
        target.body,
        &environment.roster,
        &finality_bytes,
    )
    .unwrap();
    let activation_bodies = online_participants
        .iter()
        .zip(&input_shares)
        .map(|(participant, share)| {
            participant
                .activation_share_body(share, &input_source, target, finality)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let activation_terminal = activation_terminal_from_parts(
        context,
        &environment,
        preparation.identity,
        finality,
        &activation_bodies,
        marker.wrapping_add(10),
    );
    let activation = match verify_activation_terminal(
        context,
        &preparation,
        &selected_set,
        target,
        finality,
        &environment.roster,
        &activation_terminal,
    )
    .unwrap()
    {
        DirectMpcActivationVerification::Verified(activation) => *activation,
        DirectMpcActivationVerification::Burn { .. } => panic!("valid activation burned"),
    };
    let output_bodies = online_participants
        .iter()
        .map(|participant| participant.output_share_body(activation).unwrap())
        .collect::<Vec<_>>();
    let output_terminal = output_terminal_from_parts(
        context,
        &environment,
        preparation.identity,
        activation,
        &output_bodies,
        marker.wrapping_add(11),
    );
    assert!(matches!(
        verify_output_terminal(context, activation, &environment.roster, &output_terminal).unwrap(),
        DirectMpcOutputVerification::ClearResult { result, .. } if result == protected_input
    ));
    OneAndFixture {
        environment,
        context,
        preparation,
        preparation_terminal,
        input_source_terminal: source_terminal,
        selected_set,
        selected_set_terminal: selected_terminal,
        target,
        finality,
        activation,
        events: vec![
            target_bytes,
            finality_bytes,
            activation_terminal,
            output_terminal,
        ],
        activation_bodies,
        output_bodies,
    }
}

fn preparation_fixture(
    context: DirectMpcOneAndContext,
    environment: &TestEnvironment,
    marker: u8,
) -> (
    VerifiedDirectMpcOneAndPreparation,
    Vec<DirectMpcOneAndOnlineParticipant>,
    Vec<u8>,
) {
    let prepared = (0..context.participant_count)
        .map(|participant_position| {
            let mut cursor = DirectMpcOneAndPreparationCursor::from_test_subset_masters(
                context,
                participant_position,
                test_subset_masters(context, participant_position),
                [marker.wrapping_add(participant_position as u8);
                    DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
            )
            .unwrap();
            while !cursor.step().unwrap() {}
            cursor.finish().unwrap()
        })
        .collect::<Vec<_>>();
    let bodies = prepared
        .iter()
        .map(DirectMpcOneAndPreparedParticipant::preparation_share_body)
        .collect::<Vec<_>>();
    let mut carriers = Vec::with_capacity(bodies.len());
    let mut identity_items = vec![
        CanonicalItem::hash512(context.candidate_identity.into_bytes()),
        CanonicalItem::hash512(context.seed_terminal_identity.into_bytes()),
    ];
    for body in &bodies {
        let body_bytes = body.canonical_bytes().unwrap();
        carriers.push(signed_carrier(
            PREPARATION_SHARE_CARRIER_DOMAIN,
            &body_bytes,
            body.participant_position,
            PREPARATION_SHARE_SIGNATURE_CONTEXT,
            environment,
            marker,
        ));
        identity_items.push(CanonicalItem::variable_bytes(body_bytes).unwrap());
    }
    let mut transcript_items = vec![
        CanonicalItem::hash512(context.candidate_identity.into_bytes()),
        CanonicalItem::hash512(context.seed_terminal_identity.into_bytes()),
    ];
    transcript_items.extend(
        carriers
            .iter()
            .map(|carrier| CanonicalItem::variable_bytes(carrier).unwrap()),
    );
    let transcript = encode_domain_tuple(PREPARATION_TRANSCRIPT_DOMAIN, transcript_items).unwrap();
    let transcript_identity =
        hash_foundation_tuple_512(PREPARATION_TRANSCRIPT_IDENTITY_DOMAIN, &identity_items).unwrap();
    let terminal = authorized_phase_terminal(
        context,
        environment,
        PREPARATION_TERMINAL_OPERATION_KIND,
        context.seed_terminal_identity,
        context.seed_terminal_identity,
        transcript_identity,
        &transcript,
        marker.wrapping_add(1),
    );
    let (verification, preparation) =
        verify_preparation_terminal(context, &environment.roster, Some(&terminal)).unwrap();
    assert_eq!(verification, DirectMpcPreparationVerification::Verified);
    let preparation = preparation.unwrap();
    let online = prepared
        .into_iter()
        .map(|participant| participant.accept_preparation(preparation.clone()).unwrap())
        .collect();
    (preparation, online, terminal)
}

fn activation_terminal_from_bodies(
    fixture: &OneAndFixture,
    bodies: &[DirectMpcActivationShareBody],
    marker: u8,
) -> Vec<u8> {
    activation_terminal_from_parts(
        fixture.context,
        &fixture.environment,
        fixture.preparation.identity,
        fixture.finality,
        bodies,
        marker,
    )
}

fn activation_terminal_from_parts(
    context: DirectMpcOneAndContext,
    environment: &TestEnvironment,
    preparation_identity: Hash512,
    finality: VerifiedTargetFinality,
    bodies: &[DirectMpcActivationShareBody],
    marker: u8,
) -> Vec<u8> {
    let (transcript, transcript_identity) = signed_body_transcript(
        ACTIVATION_TRANSCRIPT_DOMAIN,
        ACTIVATION_TRANSCRIPT_IDENTITY_DOMAIN,
        ACTIVATION_SHARE_CARRIER_DOMAIN,
        ACTIVATION_SHARE_SIGNATURE_CONTEXT,
        bodies
            .iter()
            .map(|body| (body.participant_position, body.canonical_bytes().unwrap()))
            .collect(),
        environment,
        marker,
    );
    authorized_phase_terminal(
        context,
        environment,
        ACTIVATION_TERMINAL_OPERATION_KIND,
        preparation_identity,
        finality.finality_identity,
        transcript_identity,
        &transcript,
        marker.wrapping_add(1),
    )
}

fn output_terminal_from_bodies(
    fixture: &OneAndFixture,
    bodies: &[DirectMpcOutputShareBody],
    marker: u8,
) -> Vec<u8> {
    output_terminal_from_parts(
        fixture.context,
        &fixture.environment,
        fixture.preparation.identity,
        fixture.activation,
        bodies,
        marker,
    )
}

fn output_terminal_from_parts(
    context: DirectMpcOneAndContext,
    environment: &TestEnvironment,
    preparation_identity: Hash512,
    activation: VerifiedDirectMpcOneAndActivation,
    bodies: &[DirectMpcOutputShareBody],
    marker: u8,
) -> Vec<u8> {
    let (transcript, transcript_identity) = signed_body_transcript(
        OUTPUT_TRANSCRIPT_DOMAIN,
        OUTPUT_TRANSCRIPT_IDENTITY_DOMAIN,
        OUTPUT_SHARE_CARRIER_DOMAIN,
        OUTPUT_SHARE_SIGNATURE_CONTEXT,
        bodies
            .iter()
            .map(|body| (body.participant_position, body.canonical_bytes().unwrap()))
            .collect(),
        environment,
        marker,
    );
    authorized_phase_terminal(
        context,
        environment,
        OUTPUT_TERMINAL_OPERATION_KIND,
        preparation_identity,
        activation.identity,
        transcript_identity,
        &transcript,
        marker.wrapping_add(1),
    )
}

fn selected_set_terminal_from_bodies(
    context: DirectMpcOneAndContext,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    environment: &TestEnvironment,
    bodies: &[DirectMpcOneAndDeclarationBody],
    marker: u8,
) -> Vec<u8> {
    let (transcript, transcript_identity) = signed_body_transcript(
        SELECTED_SET_TRANSCRIPT_DOMAIN,
        SELECTED_SET_TRANSCRIPT_IDENTITY_DOMAIN,
        DECLARATION_CARRIER_DOMAIN,
        DECLARATION_SIGNATURE_CONTEXT,
        bodies
            .iter()
            .map(|body| (body.participant_position, body.canonical_bytes().unwrap()))
            .collect(),
        environment,
        marker,
    );
    authorized_phase_terminal(
        context,
        environment,
        SELECTED_SET_TERMINAL_OPERATION_KIND,
        context.action_context_identity,
        preparation.identity,
        transcript_identity,
        &transcript,
        marker.wrapping_add(1),
    )
}

fn signed_body_transcript(
    transcript_domain: &str,
    identity_domain: &str,
    carrier_domain: &str,
    signature_context: &[u8],
    bodies: Vec<(u16, Vec<u8>)>,
    environment: &TestEnvironment,
    marker: u8,
) -> (Vec<u8>, Hash512) {
    let carriers = bodies
        .iter()
        .map(|(participant_position, body_bytes)| {
            signed_carrier(
                carrier_domain,
                body_bytes,
                *participant_position,
                signature_context,
                environment,
                marker,
            )
        })
        .collect::<Vec<_>>();
    let transcript = encode_domain_tuple(
        transcript_domain,
        carriers
            .iter()
            .map(|carrier| CanonicalItem::variable_bytes(carrier).unwrap())
            .collect(),
    )
    .unwrap();
    let identity = hash_foundation_tuple_512(
        identity_domain,
        &bodies
            .iter()
            .map(|(_, body)| CanonicalItem::variable_bytes(body).unwrap())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    (transcript, identity)
}

fn signed_carrier(
    domain: &str,
    body_bytes: &[u8],
    signer_position: u16,
    signature_context: &[u8],
    environment: &TestEnvironment,
    marker: u8,
) -> Vec<u8> {
    let signature = sign_test_message(
        &environment.signing_keys[usize::from(signer_position)],
        signer_position,
        body_bytes,
        signature_context,
        marker,
    );
    encode_domain_tuple(
        domain,
        vec![
            CanonicalItem::variable_bytes(body_bytes).unwrap(),
            CanonicalItem::fixed_bytes(signature).unwrap(),
        ],
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn authorized_phase_terminal(
    context: DirectMpcOneAndContext,
    environment: &TestEnvironment,
    operation_kind: &'static str,
    state_namespace_identity: Hash512,
    predecessor_identity: Hash512,
    semantic_body_identity: Hash512,
    semantic_body: &[u8],
    marker: u8,
) -> Vec<u8> {
    let mut items = vec![CanonicalItem::variable_bytes(semantic_body).unwrap()];
    for subject_position in 0..FOUNDATION_PROFILE.finality_quorum {
        let endorsement = PhaseEndorsementBody {
            operation_kind,
            predecessor_identity,
            semantic_body_identity,
            subject_position,
        };
        let intent = StateOutputIntent::new_with_namespace(
            context.suite_identity,
            context.action_context_identity,
            state_namespace_identity,
            context.participant_count,
            operation_kind,
            subject_position,
            predecessor_identity,
            endorsement.identity().unwrap(),
        )
        .unwrap();
        let certificate = signed_state_output_certificate(
            intent,
            environment,
            &canonical_witness_positions(subject_position, false),
            marker,
        );
        let carrier = encode_domain_tuple(
            PHASE_ENDORSEMENT_CARRIER_DOMAIN,
            vec![
                CanonicalItem::unsigned16(subject_position),
                CanonicalItem::variable_bytes(certificate).unwrap(),
            ],
        )
        .unwrap();
        items.push(CanonicalItem::variable_bytes(carrier).unwrap());
    }
    encode_domain_tuple(AUTHORIZED_PHASE_TERMINAL_DOMAIN, items).unwrap()
}

fn test_subset_masters(
    context: DirectMpcOneAndContext,
    participant_position: u16,
) -> Box<[DirectMpcJoinedSubsetMaster]> {
    ReplicatedRandomSharingSubset::iter(context.participant_count)
        .unwrap()
        .filter(|subset| subset.contains(participant_position).unwrap())
        .map(|subset| {
            let identity = hash_foundation_tuple_512(
                "sealed-lattice/test/direct-mpc-one-and/subset-master",
                &[
                    CanonicalItem::hash512(context.candidate_identity.into_bytes()),
                    CanonicalItem::unsigned32(subset.excluded_position_mask()),
                ],
            )
            .unwrap();
            let bytes: [u8; 40] = identity.as_bytes()[..40].try_into().unwrap();
            DirectMpcJoinedSubsetMaster::new(subset, bytes)
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn interpolate_four_points(
    constant: DirectMpcPrimeFieldElement,
    nonzero_points: [u16; 3],
    nonzero_values: [DirectMpcPrimeFieldElement; 3],
) -> [DirectMpcPrimeFieldElement; 4] {
    let points = [
        DirectMpcPrimeFieldElement::ZERO,
        DirectMpcPrimeFieldElement::from_u16(nonzero_points[0]),
        DirectMpcPrimeFieldElement::from_u16(nonzero_points[1]),
        DirectMpcPrimeFieldElement::from_u16(nonzero_points[2]),
    ];
    let values = [
        constant,
        nonzero_values[0],
        nonzero_values[1],
        nonzero_values[2],
    ];
    let mut coefficients = [DirectMpcPrimeFieldElement::ZERO; 4];
    for basis_position in 0..4 {
        let mut basis = vec![DirectMpcPrimeFieldElement::ONE];
        let mut denominator = DirectMpcPrimeFieldElement::ONE;
        for other_position in 0..4 {
            if other_position == basis_position {
                continue;
            }
            basis = multiply_by_linear_factor(&basis, points[other_position]);
            denominator =
                denominator.multiply(points[basis_position].subtract(points[other_position]));
        }
        let scale = values[basis_position].multiply(denominator.multiplicative_inverse().unwrap());
        for (coefficient_position, coefficient) in basis.into_iter().enumerate() {
            coefficients[coefficient_position] =
                coefficients[coefficient_position].add(coefficient.multiply(scale));
        }
    }
    coefficients
}

fn multiply_by_linear_factor(
    coefficients: &[DirectMpcPrimeFieldElement],
    root: DirectMpcPrimeFieldElement,
) -> Vec<DirectMpcPrimeFieldElement> {
    let mut product = vec![DirectMpcPrimeFieldElement::ZERO; coefficients.len() + 1];
    for (position, coefficient) in coefficients.iter().copied().enumerate() {
        product[position] = product[position].subtract(coefficient.multiply(root));
        product[position + 1] = product[position + 1].add(coefficient);
    }
    product
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
}
