use std::collections::HashMap;

use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use super::*;
use crate::{
    foundation::{
        ActionDefinition, BoardPolicy, CeremonyContext, Manifest, OptionDefinition, RosterEntry,
        StabilizedDisplayText,
    },
    tally_preparation::BinaryFieldElement256,
};

const TEST_SIGNATURE_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice/test/pre-evaluation-finality/signature-randomness";
const TEST_CORRUPT_VIEW_DOMAIN: &str = "sealed-lattice/test/pre-evaluation-finality/corrupt-view";

pub(super) struct TestEnvironment {
    pub(super) roster: Roster,
    pub(super) action_context: ActionContext,
    pub(super) signing_keys: Vec<ml_dsa_65::PrivateKey>,
}

struct NonemptyFixture {
    scope: PreEvaluationFinalityScope,
    events: Vec<Vec<u8>>,
    target: ComputationTargetBody,
    finality: VerifiedTargetFinality,
    activation_body: InputActivationBody,
    garbling_body: GarblingReleaseBody,
}

#[test]
fn positive_fragment_derives_both_clear_and_outputs_after_finality() {
    let environment = test_environment(0x21);
    for (protected_input, marker) in [(false, 0x31), (true, 0x51)] {
        let fixture = nonempty_fixture(&environment, protected_input, marker);
        assert_eq!(
            verify_pre_evaluation_finality_fragment(
                fixture.scope,
                &environment.roster,
                &fixture.events,
            ),
            FragmentVerification::Complete {
                terminal: VerifiedFragmentTerminal::ClearResult {
                    target_identity: fixture.target.identity().unwrap(),
                    result: protected_input,
                },
            },
        );
        assert_eq!(
            fixture.finality.target_identity,
            fixture.target.identity().unwrap()
        );
        assert_eq!(
            fixture.garbling_body.input_activation_identity,
            fixture.activation_body.identity().unwrap()
        );
    }
}

#[test]
fn alternate_valid_finality_carriers_mint_one_semantic_finality() {
    let environment = test_environment(0x28);
    let fixture = nonempty_fixture(&environment, true, 0x41);
    let alternate_terminal = target_finality_terminal(
        fixture.scope,
        fixture.target,
        &environment,
        &(3..FOUNDATION_PROFILE.participant_count).collect::<Vec<_>>(),
        true,
        0x42,
    );
    assert_ne!(alternate_terminal, fixture.events[1]);
    let alternate_finality = verify_target_finality_terminal(
        fixture.scope,
        fixture.target,
        &environment.roster,
        &alternate_terminal,
    )
    .unwrap();
    assert_eq!(alternate_finality, fixture.finality);
}

#[test]
fn every_missing_event_remains_pending_and_releases_refuse_before_finality() {
    let environment = test_environment(0x22);
    let fixture = nonempty_fixture(&environment, true, 0x61);
    let expected_next = [
        RequiredEvent::ComputationTarget,
        RequiredEvent::TargetFinality,
        RequiredEvent::InputActivation,
        RequiredEvent::GarblingRelease,
    ];
    for (event_count, next_required) in expected_next.into_iter().enumerate() {
        assert_eq!(
            verify_pre_evaluation_finality_fragment(
                fixture.scope,
                &environment.roster,
                &fixture.events[..event_count],
            ),
            FragmentVerification::Pending { next_required },
        );
    }

    for premature_events in [
        vec![fixture.events[2].clone()],
        vec![fixture.events[3].clone()],
        vec![fixture.events[0].clone(), fixture.events[2].clone()],
        vec![fixture.events[0].clone(), fixture.events[3].clone()],
    ] {
        assert_refused(
            verify_pre_evaluation_finality_fragment(
                fixture.scope,
                &environment.roster,
                &premature_events,
            ),
            RefusalReason::MissingPrerequisite,
        );
    }
}

#[test]
fn all_abstention_has_one_no_result_terminal_and_no_target() {
    let environment = test_environment(0x23);
    let circuit_identity = one_and_circuit_identity().unwrap();
    let preparation_terminal_identity = derive_preparation_terminal_identity(
        environment.action_context.context_hash(),
        circuit_identity,
        9,
        true,
        [0x71; OPENING_NONCE_BYTE_LENGTH],
    )
    .unwrap();
    let selected_set_root = Hash512::from_bytes([0x72; Hash512::BYTE_LENGTH]);
    let scope = PreEvaluationFinalityScope::all_abstained(
        &environment.action_context,
        &environment.roster,
        preparation_terminal_identity,
        selected_set_root,
    )
    .unwrap();
    assert_eq!(
        verify_pre_evaluation_finality_fragment(scope, &environment.roster, &[]),
        FragmentVerification::Pending {
            next_required: RequiredEvent::NoResultTerminal,
        },
    );
    let no_result_terminal = no_result_terminal_bytes(scope);
    assert_eq!(
        verify_pre_evaluation_finality_fragment(
            scope,
            &environment.roster,
            std::slice::from_ref(&no_result_terminal),
        ),
        FragmentVerification::Complete {
            terminal: VerifiedFragmentTerminal::NoResult { selected_set_root },
        },
    );

    let nonempty_fixture = nonempty_fixture(&environment, true, 0x73);
    assert_refused(
        verify_pre_evaluation_finality_fragment(
            scope,
            &environment.roster,
            std::slice::from_ref(&nonempty_fixture.events[0]),
        ),
        RefusalReason::MissingPrerequisite,
    );
    assert_refused(
        verify_pre_evaluation_finality_fragment(
            scope,
            &environment.roster,
            &[no_result_terminal.clone(), no_result_terminal],
        ),
        RefusalReason::ConsumedState,
    );
}

#[test]
fn finality_refuses_mixed_duplicate_reordered_and_invalid_carriers() {
    let environment = test_environment(0x24);
    let fixture = nonempty_fixture(&environment, true, 0x81);

    let mut invalid_signature_events = fixture.events.clone();
    *invalid_signature_events[1]
        .last_mut()
        .expect("finality terminal is nonempty") ^= 0x80;
    assert_refused(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &invalid_signature_events,
        ),
        RefusalReason::InvalidSignature,
    );

    let finality_tuple =
        decode_domain_tuple(&fixture.events[1], TARGET_FINALITY_TERMINAL_DOMAIN).unwrap();
    let mut duplicate_items = finality_tuple.items.clone();
    duplicate_items[3] = duplicate_items[2].clone();
    let duplicate_terminal = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        duplicate_items,
    )
    .encode()
    .unwrap();
    let mut duplicate_events = fixture.events.clone();
    duplicate_events[1] = duplicate_terminal;
    assert_refused(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &duplicate_events,
        ),
        RefusalReason::DuplicateIdentity,
    );

    let mut reordered_items = finality_tuple.items.clone();
    reordered_items.swap(2, 3);
    let reordered_terminal = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        reordered_items,
    )
    .encode()
    .unwrap();
    let mut reordered_events = fixture.events.clone();
    reordered_events[1] = reordered_terminal;
    assert_refused(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &reordered_events,
        ),
        RefusalReason::WrongTypeOrLength,
    );

    let alternate_input_source_root = Hash512::from_bytes([0x97; Hash512::BYTE_LENGTH]);
    let alternate_scope = PreEvaluationFinalityScope::nonempty(
        &environment.action_context,
        &environment.roster,
        fixture.scope.preparation_terminal_identity,
        fixture.scope.selected_set_root,
        alternate_input_source_root,
        8,
        9,
    )
    .unwrap();
    let alternate_target = ComputationTargetBody::new(alternate_scope).unwrap();
    let mixed_carrier = target_finality_carrier(
        alternate_scope,
        alternate_target,
        &environment,
        0,
        false,
        0x92,
    );
    let mut mixed_items = finality_tuple.items;
    mixed_items[2] = CanonicalItem::variable_bytes(mixed_carrier).unwrap();
    let mixed_terminal = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        mixed_items,
    )
    .encode()
    .unwrap();
    let mut mixed_events = fixture.events.clone();
    mixed_events[1] = mixed_terminal;
    assert_refused(
        verify_pre_evaluation_finality_fragment(fixture.scope, &environment.roster, &mixed_events),
        RefusalReason::WrongHashOrRoot,
    );
}

#[test]
fn state_certified_source_and_garbling_inconsistency_burn_without_retry() {
    let environment = test_environment(0x25);
    let fixture = nonempty_fixture(&environment, true, 0xa1);

    let mut inconsistent_activation_body = fixture.activation_body;
    inconsistent_activation_body.source_opening_nonce[0] ^= 0x01;
    let inconsistent_activation_carrier = input_activation_carrier(
        fixture.scope,
        fixture.finality,
        inconsistent_activation_body,
        &environment,
        false,
        0xa2,
    );
    let inconsistent_activation_events = vec![
        fixture.events[0].clone(),
        fixture.events[1].clone(),
        inconsistent_activation_carrier.clone(),
    ];
    assert_eq!(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &inconsistent_activation_events,
        ),
        FragmentVerification::Complete {
            terminal: VerifiedFragmentTerminal::Abort {
                target_identity: fixture.target.identity().unwrap(),
                reason: AuthenticatedAbortReason::InputSourceOpeningMismatch,
            },
        },
    );
    let mut retry_after_abort = inconsistent_activation_events;
    retry_after_abort.push(fixture.events[3].clone());
    assert_eq!(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &retry_after_abort,
        ),
        FragmentVerification::Complete {
            terminal: VerifiedFragmentTerminal::Abort {
                target_identity: fixture.target.identity().unwrap(),
                reason: AuthenticatedAbortReason::InputSourceOpeningMismatch,
            },
        },
    );

    let mut inconsistent_garbling_body = fixture.garbling_body;
    inconsistent_garbling_body.preparation_opening_nonce[0] ^= 0x01;
    let inconsistent_garbling_carrier = garbling_release_carrier(
        fixture.scope,
        fixture.finality,
        fixture.activation_body,
        inconsistent_garbling_body,
        &environment,
        false,
        0xa3,
    );
    let inconsistent_garbling_events = vec![
        fixture.events[0].clone(),
        fixture.events[1].clone(),
        fixture.events[2].clone(),
        inconsistent_garbling_carrier,
    ];
    assert_eq!(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &inconsistent_garbling_events,
        ),
        FragmentVerification::Complete {
            terminal: VerifiedFragmentTerminal::Abort {
                target_identity: fixture.target.identity().unwrap(),
                reason: AuthenticatedAbortReason::GarblingOpeningMismatch,
            },
        },
    );

    let activation_intent = StateOutputIntent::new(
        fixture.scope,
        INPUT_ACTIVATION_OPERATION_KIND,
        fixture.activation_body.holder_position,
        fixture.finality.finality_identity,
        fixture.activation_body.identity().unwrap(),
    )
    .unwrap();
    let conflicting_activation_intent = StateOutputIntent::new(
        fixture.scope,
        INPUT_ACTIVATION_OPERATION_KIND,
        inconsistent_activation_body.holder_position,
        fixture.finality.finality_identity,
        inconsistent_activation_body.identity().unwrap(),
    )
    .unwrap();
    assert_eq!(
        activation_intent.state_key_identity,
        conflicting_activation_intent.state_key_identity
    );
    assert_ne!(
        activation_intent.semantic_body_identity,
        conflicting_activation_intent.semantic_body_identity
    );
}

#[test]
fn quorum_intersections_exclude_two_targets_after_three_corruptions_and_one_state_loss() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let parameters = derive_foundation_roster_parameters(participant_count).unwrap();
    let finality_quorums = masks_with_weight(participant_count, parameters.finality_quorum);
    let corruption_sets = masks_with_weight(participant_count, parameters.active_fault_bound);
    for first_quorum in &finality_quorums {
        for second_quorum in &finality_quorums {
            let intersection = first_quorum & second_quorum;
            assert!(intersection.count_ones() >= 4);
            for corruption_set in &corruption_sets {
                assert_ne!(intersection & !corruption_set, 0);
            }
        }
    }

    for subject_position in 0..participant_count {
        let subject_bit = 1_u32 << subject_position;
        let witness_quorums = masks_with_weight(participant_count, parameters.state_witness_quorum)
            .into_iter()
            .filter(|mask| mask & subject_bit == 0)
            .collect::<Vec<_>>();
        for first_quorum in &witness_quorums {
            for second_quorum in &witness_quorums {
                let intersection = first_quorum & second_quorum;
                assert!(intersection.count_ones() >= 5);
                for corruption_set in &corruption_sets {
                    let honest_intersection = intersection & !corruption_set;
                    for unavailable_position in 0..participant_count {
                        let unavailable_bit = 1_u32 << unavailable_position;
                        if honest_intersection & unavailable_bit != 0 {
                            assert_ne!(honest_intersection & !unavailable_bit, 0);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn ideal_pre_finality_views_couple_every_three_holder_corruption_set() {
    let environment = test_environment(0x26);
    let fixture = nonempty_fixture(&environment, false, 0xb1);
    let corruption_sets = masks_with_weight(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.active_fault_bound,
    );
    for corruption_set in corruption_sets {
        let corrupt_positions = (0..FOUNDATION_PROFILE.participant_count)
            .filter(|position| corruption_set & (1_u32 << position) != 0)
            .collect::<Vec<_>>();
        let difference_denominator =
            corrupt_positions
                .iter()
                .fold(BinaryFieldElement256::ONE, |product, position| {
                    product.multiply(BinaryFieldElement256::from_low_polynomial_u16(position + 1))
                });
        let inverse_denominator = difference_denominator.multiplicative_inverse().unwrap();
        let base_coefficients = [
            BinaryFieldElement256::ZERO,
            BinaryFieldElement256::from_low_polynomial_u16(0x31),
            BinaryFieldElement256::from_low_polynomial_u16(0x53),
            BinaryFieldElement256::from_low_polynomial_u16(0x79),
        ];
        let mut zero_world_shares = Vec::new();
        let mut one_world_shares = Vec::new();
        for corrupt_position in &corrupt_positions {
            let point = BinaryFieldElement256::from_low_polynomial_u16(corrupt_position + 1);
            let zero_world_share = evaluate_degree_three(base_coefficients, point);
            let difference = corrupt_positions
                .iter()
                .map(|position| {
                    point.add(BinaryFieldElement256::from_low_polynomial_u16(position + 1))
                })
                .fold(BinaryFieldElement256::ONE, |product, factor| {
                    product.multiply(factor)
                })
                .multiply(inverse_denominator);
            let one_world_share = zero_world_share.add(difference);
            assert_eq!(difference, BinaryFieldElement256::ZERO);
            assert_eq!(zero_world_share, one_world_share);
            zero_world_shares.push(zero_world_share);
            one_world_shares.push(one_world_share);
        }
        let zero_view =
            corrupt_view_bytes(&fixture.events[..2], &corrupt_positions, &zero_world_shares);
        let one_view =
            corrupt_view_bytes(&fixture.events[..2], &corrupt_positions, &one_world_shares);
        assert_eq!(zero_view, one_view);
    }
}

#[test]
fn one_shot_state_replays_exact_bytes_and_retires_after_rollback_or_loss() {
    let first_key = Hash512::from_bytes([0xc1; Hash512::BYTE_LENGTH]);
    let first_body = Hash512::from_bytes([0xc2; Hash512::BYTE_LENGTH]);
    let second_body = Hash512::from_bytes([0xc3; Hash512::BYTE_LENGTH]);
    let first_carrier = vec![0x11, 0x22, 0x33];
    let mut state = TestOneShotState::default();
    assert_eq!(
        state
            .authorize(first_key, first_body, first_carrier.clone())
            .unwrap(),
        first_carrier,
    );
    assert_eq!(
        state.authorize(first_key, first_body, vec![0xff]).unwrap(),
        vec![0x11, 0x22, 0x33],
    );
    assert_eq!(
        state.authorize(first_key, second_body, vec![0x44]),
        Err(TestStateError::Conflict),
    );

    state.observe_rollback();
    assert_eq!(
        state.authorize(first_key, first_body, vec![0x55]),
        Err(TestStateError::Retired),
    );

    let mut lost_state = TestOneShotState::default();
    lost_state.observe_state_loss();
    assert_eq!(
        lost_state.authorize(first_key, first_body, vec![0x66]),
        Err(TestStateError::Retired),
    );
}

#[test]
fn malformed_events_never_mint_a_terminal_or_accept_replay() {
    let environment = test_environment(0x27);
    let fixture = nonempty_fixture(&environment, true, 0xd1);
    for event_position in 0..fixture.events.len() {
        for retained_byte_length in sampled_prefix_lengths(fixture.events[event_position].len()) {
            let mut events = fixture.events[..=event_position].to_vec();
            events[event_position].truncate(retained_byte_length);
            assert!(matches!(
                verify_pre_evaluation_finality_fragment(
                    fixture.scope,
                    &environment.roster,
                    &events,
                ),
                FragmentVerification::Refused { .. }
            ));
        }
    }
    let mut replayed_events = fixture.events.clone();
    replayed_events.push(fixture.events[2].clone());
    assert_refused(
        verify_pre_evaluation_finality_fragment(
            fixture.scope,
            &environment.roster,
            &replayed_events,
        ),
        RefusalReason::ConsumedState,
    );
}

fn nonempty_fixture(
    environment: &TestEnvironment,
    protected_input: bool,
    marker: u8,
) -> NonemptyFixture {
    let circuit_identity = one_and_circuit_identity().unwrap();
    let activation_holder_position = FOUNDATION_PROFILE.participant_count - 2;
    let garbling_contributor_position = FOUNDATION_PROFILE.participant_count - 1;
    let preparation_opening_nonce = [marker; OPENING_NONCE_BYTE_LENGTH];
    let preparation_terminal_identity = derive_preparation_terminal_identity(
        environment.action_context.context_hash(),
        circuit_identity,
        garbling_contributor_position,
        true,
        preparation_opening_nonce,
    )
    .unwrap();
    let selected_set_root = Hash512::from_bytes([marker.wrapping_add(1); Hash512::BYTE_LENGTH]);
    let source_opening_nonce = [marker.wrapping_add(2); OPENING_NONCE_BYTE_LENGTH];
    let input_source_root = derive_input_source_root(
        environment.action_context.context_hash(),
        preparation_terminal_identity,
        selected_set_root,
        activation_holder_position,
        protected_input,
        source_opening_nonce,
    )
    .unwrap();
    let scope = PreEvaluationFinalityScope::nonempty(
        &environment.action_context,
        &environment.roster,
        preparation_terminal_identity,
        selected_set_root,
        input_source_root,
        activation_holder_position,
        garbling_contributor_position,
    )
    .unwrap();
    let target = ComputationTargetBody::new(scope).unwrap();
    let target_bytes = target.canonical_bytes().unwrap();
    let finality_bytes = target_finality_terminal(
        scope,
        target,
        environment,
        &(0..FOUNDATION_PROFILE.finality_quorum).collect::<Vec<_>>(),
        false,
        marker.wrapping_add(3),
    );
    let finality = VerifiedTargetFinality {
        target_identity: target.identity().unwrap(),
        finality_identity: hash_foundation_tuple_512(
            TARGET_FINALITY_IDENTITY_DOMAIN,
            &[CanonicalItem::hash512(
                target.identity().unwrap().into_bytes(),
            )],
        )
        .unwrap(),
    };
    let activation_body = InputActivationBody {
        action_context_identity: scope.action_context_identity,
        preparation_terminal_identity,
        selected_set_root,
        input_source_root,
        holder_position: activation_holder_position,
        protected_input,
        source_opening_nonce,
    };
    let activation_bytes = input_activation_carrier(
        scope,
        finality,
        activation_body,
        environment,
        false,
        marker.wrapping_add(4),
    );
    let garbling_body = GarblingReleaseBody {
        action_context_identity: scope.action_context_identity,
        circuit_identity,
        preparation_terminal_identity,
        input_activation_identity: activation_body.identity().unwrap(),
        contributor_position: garbling_contributor_position,
        public_input: true,
        preparation_opening_nonce,
    };
    let garbling_bytes = garbling_release_carrier(
        scope,
        finality,
        activation_body,
        garbling_body,
        environment,
        false,
        marker.wrapping_add(5),
    );
    NonemptyFixture {
        scope,
        events: vec![
            target_bytes,
            finality_bytes,
            activation_bytes,
            garbling_bytes,
        ],
        target,
        finality,
        activation_body,
        garbling_body,
    }
}

pub(super) fn target_finality_terminal(
    scope: PreEvaluationFinalityScope,
    target: ComputationTargetBody,
    environment: &TestEnvironment,
    subject_positions: &[u16],
    witnesses_from_end: bool,
    carrier_variant: u8,
) -> Vec<u8> {
    let mut items = Vec::with_capacity(subject_positions.len() + 1);
    items.push(CanonicalItem::hash512(
        target.identity().unwrap().into_bytes(),
    ));
    for subject_position in subject_positions {
        items.push(
            CanonicalItem::variable_bytes(target_finality_carrier(
                scope,
                target,
                environment,
                *subject_position,
                witnesses_from_end,
                carrier_variant,
            ))
            .unwrap(),
        );
    }
    encode_domain_tuple(TARGET_FINALITY_TERMINAL_DOMAIN, items).unwrap()
}

fn target_finality_carrier(
    scope: PreEvaluationFinalityScope,
    target: ComputationTargetBody,
    environment: &TestEnvironment,
    subject_position: u16,
    witnesses_from_end: bool,
    carrier_variant: u8,
) -> Vec<u8> {
    let endorsement_body =
        TargetFinalityEndorsementBody::new(target.identity().unwrap(), subject_position);
    let intent = StateOutputIntent::new(
        scope,
        TARGET_FINALITY_OPERATION_KIND,
        subject_position,
        target.identity().unwrap(),
        endorsement_body.identity().unwrap(),
    )
    .unwrap();
    let certificate = signed_state_output_certificate(
        intent,
        environment,
        &canonical_witness_positions(subject_position, witnesses_from_end),
        carrier_variant,
    );
    encode_domain_tuple(
        TARGET_FINALITY_CARRIER_DOMAIN,
        vec![
            CanonicalItem::unsigned16(subject_position),
            CanonicalItem::variable_bytes(certificate).unwrap(),
        ],
    )
    .unwrap()
}

fn input_activation_carrier(
    scope: PreEvaluationFinalityScope,
    finality: VerifiedTargetFinality,
    body: InputActivationBody,
    environment: &TestEnvironment,
    witnesses_from_end: bool,
    carrier_variant: u8,
) -> Vec<u8> {
    let intent = StateOutputIntent::new(
        scope,
        INPUT_ACTIVATION_OPERATION_KIND,
        body.holder_position,
        finality.finality_identity,
        body.identity().unwrap(),
    )
    .unwrap();
    let certificate = signed_state_output_certificate(
        intent,
        environment,
        &canonical_witness_positions(body.holder_position, witnesses_from_end),
        carrier_variant,
    );
    encode_domain_tuple(
        INPUT_ACTIVATION_CARRIER_DOMAIN,
        vec![
            CanonicalItem::variable_bytes(body.canonical_bytes().unwrap()).unwrap(),
            CanonicalItem::variable_bytes(certificate).unwrap(),
        ],
    )
    .unwrap()
}

fn garbling_release_carrier(
    scope: PreEvaluationFinalityScope,
    finality: VerifiedTargetFinality,
    activation_body: InputActivationBody,
    body: GarblingReleaseBody,
    environment: &TestEnvironment,
    witnesses_from_end: bool,
    carrier_variant: u8,
) -> Vec<u8> {
    let predecessor_identity = hash_foundation_tuple_512(
        GARBLING_RELEASE_PREDECESSOR_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(finality.finality_identity.into_bytes()),
            CanonicalItem::hash512(activation_body.identity().unwrap().into_bytes()),
        ],
    )
    .unwrap();
    let intent = StateOutputIntent::new(
        scope,
        GARBLING_RELEASE_OPERATION_KIND,
        body.contributor_position,
        predecessor_identity,
        body.identity().unwrap(),
    )
    .unwrap();
    let certificate = signed_state_output_certificate(
        intent,
        environment,
        &canonical_witness_positions(body.contributor_position, witnesses_from_end),
        carrier_variant,
    );
    encode_domain_tuple(
        GARBLING_RELEASE_CARRIER_DOMAIN,
        vec![
            CanonicalItem::variable_bytes(body.canonical_bytes().unwrap()).unwrap(),
            CanonicalItem::variable_bytes(certificate).unwrap(),
        ],
    )
    .unwrap()
}

pub(super) fn signed_state_output_certificate(
    intent: StateOutputIntent,
    environment: &TestEnvironment,
    witness_positions: &[u16],
    carrier_variant: u8,
) -> Vec<u8> {
    let witness_envelopes = witness_positions
        .iter()
        .map(|witness_position| {
            let authorization_body =
                StateWitnessAuthorizationBody::new(intent, *witness_position).unwrap();
            let authorization_body_bytes = authorization_body.canonical_bytes().unwrap();
            let signature = sign_test_message(
                &environment.signing_keys[usize::from(*witness_position)],
                *witness_position,
                &authorization_body_bytes,
                STATE_WITNESS_SIGNATURE_CONTEXT,
                carrier_variant,
            );
            encode_domain_tuple(
                STATE_WITNESS_ENVELOPE_DOMAIN,
                vec![
                    CanonicalItem::variable_bytes(authorization_body_bytes).unwrap(),
                    CanonicalItem::fixed_bytes(signature).unwrap(),
                ],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let witness_envelope_references = witness_envelopes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let witness_certificate_identity =
        state_witness_certificate_identity(intent, &witness_envelope_references).unwrap();
    let subject_authorization_body =
        StateSubjectAuthorizationBody::new(intent, witness_certificate_identity).unwrap();
    let subject_authorization_body_bytes = subject_authorization_body.canonical_bytes().unwrap();
    let subject_signature = sign_test_message(
        &environment.signing_keys[usize::from(intent.subject_position)],
        intent.subject_position,
        &subject_authorization_body_bytes,
        STATE_SUBJECT_SIGNATURE_CONTEXT,
        carrier_variant,
    );
    let mut items = Vec::with_capacity(witness_envelopes.len() + 3);
    items.push(CanonicalItem::variable_bytes(intent.canonical_bytes().unwrap()).unwrap());
    for witness_envelope in witness_envelopes {
        items.push(CanonicalItem::variable_bytes(witness_envelope).unwrap());
    }
    items.push(CanonicalItem::variable_bytes(subject_authorization_body_bytes).unwrap());
    items.push(CanonicalItem::fixed_bytes(subject_signature).unwrap());
    encode_domain_tuple(STATE_OUTPUT_CERTIFICATE_DOMAIN, items).unwrap()
}

pub(super) fn sign_test_message(
    signing_key: &ml_dsa_65::PrivateKey,
    signer_position: u16,
    message: &[u8],
    signature_context: &[u8],
    carrier_variant: u8,
) -> [u8; ml_dsa_65::SIG_LEN] {
    let randomness = hash_foundation_tuple_512(
        TEST_SIGNATURE_RANDOMNESS_DOMAIN,
        &[
            CanonicalItem::unsigned16(signer_position),
            CanonicalItem::unsigned16(u16::from(carrier_variant)),
            CanonicalItem::variable_bytes(signature_context).unwrap(),
            CanonicalItem::variable_bytes(message).unwrap(),
        ],
    )
    .unwrap();
    let seed: [u8; 32] = randomness.as_bytes()[..32].try_into().unwrap();
    signing_key
        .try_sign_with_seed(&seed, message, signature_context)
        .unwrap()
}

pub(super) fn canonical_witness_positions(subject_position: u16, from_end: bool) -> Vec<u16> {
    let positions = (0..FOUNDATION_PROFILE.participant_count)
        .filter(|position| *position != subject_position)
        .collect::<Vec<_>>();
    let witness_count = usize::from(FOUNDATION_PROFILE.state_witness_quorum);
    if from_end {
        positions[positions.len() - witness_count..].to_vec()
    } else {
        positions[..witness_count].to_vec()
    }
}

pub(super) fn no_result_terminal_bytes(scope: PreEvaluationFinalityScope) -> Vec<u8> {
    encode_domain_tuple(
        NO_RESULT_TERMINAL_DOMAIN,
        vec![
            CanonicalItem::hash512(scope.action_context_identity.into_bytes()),
            CanonicalItem::hash512(scope.preparation_terminal_identity.into_bytes()),
            CanonicalItem::hash512(scope.selected_set_root.into_bytes()),
        ],
    )
    .unwrap()
}

pub(super) fn test_environment(marker: u8) -> TestEnvironment {
    let mut signing_keys = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    let roster_entries = (0..FOUNDATION_PROFILE.participant_count)
        .map(|roster_position| {
            let mut signing_seed = [marker; 32];
            signing_seed[0] ^= roster_position as u8;
            let (verification_key, signing_key) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);
            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= roster_position as u8;
            let mut fallback_seed = [marker.wrapping_add(0x53); 32];
            fallback_seed[31] ^= roster_position as u8;
            let (mailbox_key, _) = ml_kem_768::KG::keygen_from_seed(mailbox_seed, fallback_seed);
            RosterEntry::new(
                roster_position,
                verification_key.into_bytes(),
                mailbox_key.into_bytes(),
            )
            .unwrap()
        })
        .collect();
    let roster = Roster::new(roster_entries).unwrap();
    let manifest = Manifest::new(
        stabilized_text("Target-finality fragment"),
        (0..FOUNDATION_PROFILE.option_count)
            .map(|option_position| {
                OptionDefinition::new(
                    option_position,
                    format!("option-{option_position}"),
                    stabilized_text(&format!("Option {option_position}")),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let ceremony_context = CeremonyContext::new(
        Hash512::from_bytes([marker.wrapping_add(0x75); Hash512::BYTE_LENGTH]),
        &manifest,
        &roster,
        format!("target-finality-fragment-{marker}"),
    )
    .unwrap();
    let board_policy = BoardPolicy::new("board.example".to_owned()).unwrap();
    let action_context = ActionContext::new(
        &ceremony_context,
        format!("one-and-action-{marker}"),
        ActionDefinition::new(1, 1_800_000_000_000).unwrap(),
        &board_policy,
    )
    .unwrap();
    TestEnvironment {
        roster,
        action_context,
        signing_keys,
    }
}

fn stabilized_text(value: &str) -> StabilizedDisplayText {
    StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap()
}

fn masks_with_weight(participant_count: u16, selected_count: u16) -> Vec<u32> {
    (0..(1_u32 << participant_count))
        .filter(|mask| mask.count_ones() == u32::from(selected_count))
        .collect()
}

fn evaluate_degree_three(
    coefficients: [BinaryFieldElement256; 4],
    point: BinaryFieldElement256,
) -> BinaryFieldElement256 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(BinaryFieldElement256::ZERO, |value, coefficient| {
            value.multiply(point).add(coefficient)
        })
}

fn corrupt_view_bytes(
    public_events: &[Vec<u8>],
    corrupt_positions: &[u16],
    corrupt_shares: &[BinaryFieldElement256],
) -> Vec<u8> {
    let mut items = Vec::with_capacity(public_events.len() + corrupt_positions.len() * 2);
    for public_event in public_events {
        items.push(CanonicalItem::variable_bytes(public_event).unwrap());
    }
    for (corrupt_position, corrupt_share) in corrupt_positions.iter().zip(corrupt_shares) {
        items.push(CanonicalItem::unsigned16(*corrupt_position));
        items.push(CanonicalItem::fixed_bytes(corrupt_share.canonical_bytes()).unwrap());
    }
    encode_domain_tuple(TEST_CORRUPT_VIEW_DOMAIN, items).unwrap()
}

fn sampled_prefix_lengths(byte_length: usize) -> Vec<usize> {
    let mut lengths = vec![0, 1, byte_length / 3, byte_length / 2, byte_length - 1];
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

fn assert_refused(verification: FragmentVerification, refusal_reason: RefusalReason) {
    assert_eq!(
        verification,
        FragmentVerification::Refused { refusal_reason },
    );
}

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
        state_key_identity: Hash512,
        semantic_body_identity: Hash512,
        carrier: Vec<u8>,
    ) -> Result<Vec<u8>, TestStateError> {
        if self.retired {
            return Err(TestStateError::Retired);
        }
        match self.retained_outputs.get(&state_key_identity) {
            Some((retained_body_identity, retained_carrier))
                if *retained_body_identity == semantic_body_identity =>
            {
                Ok(retained_carrier.clone())
            }
            Some(_) => Err(TestStateError::Conflict),
            None => {
                self.retained_outputs.insert(
                    state_key_identity,
                    (semantic_body_identity, carrier.clone()),
                );
                Ok(carrier)
            }
        }
    }

    fn observe_rollback(&mut self) {
        self.retired = true;
    }

    fn observe_state_loss(&mut self) {
        self.retired = true;
        self.retained_outputs.clear();
    }
}
