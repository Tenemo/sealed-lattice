use num_bigint::BigUint;

use crate::{
    foundation::{FOUNDATION_PROFILE, derive_foundation_roster_parameters},
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile},
};

use super::lpsy15_candidate_compiler::{
    LPSY15_PRIME_MODULUS_DECIMAL, LPSY15_PRIME_MODULUS_LITTLE_ENDIAN, Lpsy15CandidateCompilation,
    Lpsy15CandidatePathKind, Lpsy15CandidatePathTerminal, Lpsy15CandidateStreamKind,
    Lpsy15CheckpointStateKind, Lpsy15GateKind, Lpsy15InputWireSide, Lpsy15MultiplicationKind,
    Lpsy15PhysicalWireSource, Lpsy15RoundKind, Lpsy15RoundParticipation,
    Lpsy15SourcePolynomialKind, Lpsy15StateIntentKind, Lpsy15StatePredecessorKind,
};

#[test]
fn completion_profile_reconciles_paper_counts_without_collapsing_per_participant_prf_inputs() {
    let circuit = completion_profile_circuit();
    let compilation = Lpsy15CandidateCompilation::compile(&circuit).unwrap();
    let ledger = compilation.resource_ledger();

    assert_eq!(compilation.profile(), circuit.profile());
    assert_eq!(ledger.logical_wire_count, 7_933);
    assert_eq!(ledger.physical_wire_count, 7_176);
    assert_eq!(ledger.ballot_input_wire_count, 410);
    assert_eq!(ledger.fixed_false_source_count, 1);
    assert_eq!(ledger.conjunction_gate_count, 2_962);
    assert_eq!(ledger.exclusive_or_gate_count, 3_803);
    assert_eq!(ledger.eliminated_negation_count, 756);
    assert_eq!(ledger.binary_gate_count, 6_765);
    assert_eq!(ledger.logical_output_bit_count, 41);
    assert_eq!(ledger.unique_output_physical_wire_count, 41);
    assert_eq!(ledger.mask_random_bit_count_per_participant, 7_176);
    assert_eq!(
        ledger.independent_field_sample_count_per_participant,
        2_455_796
    );
    assert_eq!(ledger.complete_independent_field_sample_count, 24_557_960);
    assert_eq!(ledger.field_sampling_statistical_numerator, 663_064_920);
    assert_eq!(ledger.randomness_xof_message_byte_length, 500);
    assert_eq!(
        ledger.randomness_xof_output_byte_length_per_participant,
        98_232_737
    );
    assert_eq!(
        ledger.randomness_xof_rate_block_count_per_participant,
        722_300
    );
    assert_eq!(
        ledger.randomness_xof_permutation_count_per_participant,
        722_303
    );
    assert_eq!(
        ledger.degree_three_polynomial_count_per_participant,
        688_271
    );
    assert_eq!(ledger.degree_six_polynomial_count_per_participant, 41_848);
    assert_eq!(
        ledger.polynomial_evaluation_multiplication_count_per_participant,
        23_159_010
    );
    assert_eq!(
        ledger.polynomial_evaluation_addition_count_per_participant,
        23_159_010
    );
    assert_eq!(
        ledger.source_extraction_multiplication_count_per_participant,
        11_717_160
    );
    assert_eq!(
        ledger.source_extraction_addition_count_per_participant,
        10_545_444
    );
    assert_eq!(
        ledger.sharing_check_multiplication_count_per_participant,
        7_947_551
    );
    assert_eq!(
        ledger.sharing_check_addition_count_per_participant,
        7_301_160
    );
    assert_eq!(
        ledger.degree_three_codeword_check_count_per_participant,
        868_216
    );
    assert_eq!(
        ledger.degree_six_codeword_check_count_per_participant,
        292_939
    );
    assert_eq!(
        ledger.codeword_check_multiplication_count_per_participant,
        32_512_340
    );
    assert_eq!(
        ledger.codeword_check_addition_count_per_participant,
        25_263_072
    );
    assert_eq!(
        ledger.triple_generation_multiplication_count_per_participant,
        292_929
    );
    assert_eq!(
        ledger.triple_generation_addition_count_per_participant,
        585_858
    );
    assert_eq!(
        ledger.beaver_evaluation_multiplication_count_per_participant,
        878_787
    );
    assert_eq!(
        ledger.beaver_evaluation_addition_count_per_participant,
        1_464_645
    );
    assert_eq!(
        ledger.garbling_affine_addition_count_per_participant,
        5_862_731
    );
    assert_eq!(
        ledger.mask_conversion_constant_multiplication_count_per_participant,
        7_176
    );
    assert_eq!(
        ledger.online_evaluation_addition_count_per_participant,
        1_353_000
    );
    assert_eq!(
        ledger.complete_field_multiplication_count_per_participant,
        76_515_363
    );
    assert_eq!(
        ledger.complete_field_addition_count_per_participant,
        75_550_092
    );
    assert_eq!(ledger.paper_gate_multiplication_count, 220_759);
    assert_eq!(ledger.mask_generation_multiplication_count, 71_760);
    assert_eq!(ledger.preparation_multiplication_count, 292_519);
    assert_eq!(ledger.source_bound_activation_multiplication_count, 410);
    assert_eq!(
        ledger.source_bound_activation_constant_multiplication_count_per_participant,
        410
    );
    assert_eq!(
        ledger.source_bound_activation_addition_count_per_participant,
        820
    );
    assert_eq!(ledger.total_multiplication_count, 292_929);
    assert_eq!(
        ledger.multiplication_count_by_layer,
        [35_880, 14_352, 7_176, 7_176, 13_941, 19_454, 194_540, 410]
    );
    assert_eq!(ledger.prf_output_input_count_per_participant, 541_200);
    assert_eq!(ledger.complete_prf_output_input_count, 5_412_000);
    assert_eq!(ledger.online_prf_call_count_per_participant, 1_353_000);
    assert_eq!(ledger.complete_online_prf_call_count, 13_530_000);
    assert_eq!(ledger.prf_message_byte_length, 452);
    assert_eq!(ledger.prf_kmac_permutation_count_per_call, 6);
    assert_eq!(ledger.complete_prf_call_count_per_participant, 1_894_200);
    assert_eq!(
        ledger.complete_prf_kmac_permutation_count_per_participant,
        11_365_200
    );
    assert_eq!(ledger.table_field_element_count, 270_600);
    assert_eq!(ledger.paper_style_raw_table_byte_length, 10_824_000);
    assert_eq!(ledger.canonical_table_byte_length, 11_094_600);
    assert_eq!(ledger.private_mpc_input_count, 5_627_280);
    assert_eq!(
        ledger.random_source_polynomial_count_per_participant,
        83_694
    );
    assert_eq!(ledger.double_source_pair_count_per_participant, 41_847);
    assert_eq!(ledger.sharing_check_mask_polynomial_count, 30);
    assert_eq!(ledger.source_polynomial_count, 1_673_910);
    assert_eq!(ledger.total_polynomial_count, 7_301_190);
    assert_eq!(ledger.remote_private_share_field_element_count, 65_710_710);
    assert_eq!(
        ledger.remote_private_share_payload_byte_length,
        2_694_139_110
    );
    assert_eq!(ledger.public_opening_field_element_count, 11_611_550);
    assert_eq!(ledger.public_opening_payload_byte_length, 476_073_550);
    assert_eq!(ledger.active_key_opening_field_element_count, 41_100);
    assert_eq!(ledger.raw_upload_payload_byte_length, 3_170_212_660);
    assert_eq!(ledger.private_stream_count, 90);
    assert_eq!(ledger.public_stream_count, 191);
    assert_eq!(ledger.network_signature_count, 281);
    assert_eq!(ledger.encapsulation_count, 90);
    assert_eq!(ledger.authenticated_encryption_count, 2_610);
    assert_eq!(ledger.stream_identity_hash_count, 3_752);
    assert_eq!(ledger.private_stream_carrier_byte_length, 2_694_864_420);
    assert_eq!(ledger.public_stream_carrier_byte_length, 476_998_345);
    assert_eq!(ledger.complete_upload_carrier_byte_length, 3_171_862_765);
    assert_eq!(ledger.maximum_canonical_stream_byte_length, 29_942_938);
    assert_eq!(
        ledger.maximum_participant_upload_carrier_byte_length,
        317_190_376
    );
    assert_eq!(
        ledger.clean_state_participant_download_carrier_byte_length,
        746_484_787
    );
    assert_eq!(ledger.evaluation_success_claim_byte_length, 169);
    assert_eq!(ledger.authenticated_failure_claim_byte_length, 170);
    assert_eq!(ledger.round_root_derivation_count, 20);
    assert_eq!(ledger.burn_terminal_stream_count, 8);
    assert_eq!(ledger.paper_round_reconciliation_count, 12);
    assert_eq!(ledger.preparation_complete_roster_round_count, 13);
    assert_eq!(ledger.online_complete_roster_round_count, 4);
    assert_eq!(ledger.minimum_dependency_separated_visit_count, 173);
    assert_eq!(ledger.maximum_dependency_separated_visit_count, 191);
    assert_eq!(ledger.maximum_live_active_wire_count, 416);
    assert_eq!(ledger.maximum_live_active_key_byte_length, 199_680);
    assert_eq!(ledger.field_work_batch_element_count, 4_096);
    assert_eq!(ledger.maximum_field_work_batch_byte_length, 1_376_256);
    assert_eq!(ledger.participant_share_state_byte_length, 299_348_790);
    assert_eq!(ledger.participant_source_staging_byte_length, 122_877_733);
    assert_eq!(
        ledger.participant_share_checkpoint_storage_byte_length,
        600_233_012
    );
    assert_eq!(
        ledger.participant_source_checkpoint_storage_byte_length,
        246_392_434
    );
    assert_eq!(
        ledger.retained_transcript_with_cleanup_lag_byte_length,
        1_015_971_229
    );
    assert_eq!(
        ledger.persistent_storage_with_repair_and_cleanup_lag_byte_length,
        1_864_381_467
    );
    assert_eq!(ledger.maximum_contiguous_allocation_byte_length, 1_376_256);
    assert_eq!(ledger.maximum_wasm_data_live_set_byte_length, 3_673_088);
    assert_eq!(
        ledger.maximum_javascript_data_live_set_byte_length,
        2_260_822
    );
    assert_eq!(
        ledger.maximum_browser_process_data_live_set_byte_length,
        5_933_910
    );

    assert_eq!(
        compilation.checkpoint_storage_intents(),
        &[
            super::lpsy15_candidate_compiler::Lpsy15CheckpointStorageIntent {
                kind: Lpsy15CheckpointStateKind::SourceStaging,
                state_byte_length: 122_877_733,
                state_chunk_count: 118,
                cursor_byte_length: 226,
                stream_descriptor_byte_length: 7_656,
                canonical_manifest_byte_length: 8_774,
                maximum_journal_byte_length: 67_574,
                configured_manifest_limit_byte_length: 67_574,
                copy_on_write_stored_value_byte_length: 246_102_562,
                repair_head_overlap_byte_length: 289_872,
                complete_storage_byte_length: 246_392_434,
            },
            super::lpsy15_candidate_compiler::Lpsy15CheckpointStorageIntent {
                kind: Lpsy15CheckpointStateKind::ParticipantShareState,
                state_byte_length: 299_348_790,
                state_chunk_count: 286,
                cursor_byte_length: 226,
                stream_descriptor_byte_length: 18_408,
                canonical_manifest_byte_length: 19_526,
                maximum_journal_byte_length: 163_670,
                configured_manifest_limit_byte_length: 163_670,
                copy_on_write_stored_value_byte_length: 599_534_564,
                repair_head_overlap_byte_length: 698_448,
                complete_storage_byte_length: 600_233_012,
            },
        ]
    );

    assert_eq!(compilation.logical_wire_roles().len(), 7_933);
    assert_eq!(compilation.physical_wire_roles().len(), 7_176);
    assert_eq!(compilation.gate_roles().len(), 6_765);
    assert_eq!(compilation.output_roles().len(), 41);
    assert_eq!(compilation.rounds().len(), 20);
    assert_eq!(compilation.streams().len(), 281);
    assert!(matches!(
        compilation.rounds()[4].kind,
        Lpsy15RoundKind::TripleProductOpening
    ));
    assert!(matches!(
        compilation.rounds()[19].kind,
        Lpsy15RoundKind::ResultTerminalWitness
    ));
}

#[test]
fn state_intents_and_terminal_paths_bind_finality_before_clear_output_material() {
    let compilation = Lpsy15CandidateCompilation::compile(&completion_profile_circuit()).unwrap();
    let ledger = compilation.resource_ledger();
    let state_intents = compilation.state_intents();
    let candidate_paths = compilation.candidate_paths();

    assert_eq!(state_intents.len(), compilation.rounds().len());
    assert_eq!(state_intents.len(), 20);
    for (round, state_intent) in compilation.rounds().iter().zip(state_intents) {
        assert_eq!(state_intent.round_index, round.round_index);
        assert_eq!(state_intent.round_kind, round.kind);
        assert!(state_intent.sender_stream_identity_count > 0);
        assert!(state_intent.round_root_body_byte_length > 0);
    }
    assert_eq!(
        state_intents[0].predecessor_kind,
        Lpsy15StatePredecessorKind::PreparationAttempt
    );
    assert_eq!(state_intents[0].predecessor_count, 1);
    let target_finality_position = state_intents
        .iter()
        .position(|state_intent| state_intent.kind == Lpsy15StateIntentKind::TargetFinality)
        .unwrap();
    let target_finality_intent = state_intents[target_finality_position];
    assert_eq!(
        target_finality_intent.predecessor_kind,
        Lpsy15StatePredecessorKind::PreparationAndSelectedSet
    );
    assert_eq!(target_finality_intent.predecessor_count, 3);
    assert!(!target_finality_intent.permits_clear_output_material);
    assert!(
        state_intents[..=target_finality_position]
            .iter()
            .all(|state_intent| !state_intent.permits_clear_output_material)
    );
    assert!(matches!(
        state_intents[target_finality_position + 1].round_kind,
        Lpsy15RoundKind::SourceBoundInputActivation
    ));
    assert!(
        state_intents[target_finality_position + 1..]
            .iter()
            .all(|state_intent| state_intent.permits_clear_output_material)
    );

    assert_eq!(candidate_paths.len(), 62);
    assert_eq!(candidate_paths[0].kind, Lpsy15CandidatePathKind::Success);
    assert_eq!(
        candidate_paths[0].terminal,
        Lpsy15CandidatePathTerminal::Result
    );
    assert_eq!(candidate_paths[0].verified_prefix_stream_count, 281);
    assert_eq!(
        candidate_paths[0].downloaded_carrier_byte_length,
        ledger.complete_upload_carrier_byte_length
    );
    assert_eq!(
        candidate_paths[1].kind,
        Lpsy15CandidatePathKind::AllAbstention
    );
    assert_eq!(
        candidate_paths[1].terminal,
        Lpsy15CandidatePathTerminal::NoResult
    );
    assert_eq!(candidate_paths[1].verified_prefix_stream_count, 227);
    assert_eq!(
        candidate_paths[1].downloaded_carrier_byte_length,
        3_058_470_335
    );

    for path in &candidate_paths[2..] {
        match path.kind {
            Lpsy15CandidatePathKind::Withholding { .. }
            | Lpsy15CandidatePathKind::UnauthenticatedMalformed { .. } => {
                assert_eq!(path.terminal, Lpsy15CandidatePathTerminal::Pending);
                assert_eq!(path.additional_terminal_stream_count, 0);
                assert_eq!(path.additional_terminal_carrier_byte_length, 0);
            }
            Lpsy15CandidatePathKind::AuthenticatedInconsistency { .. } => {
                assert_eq!(path.terminal, Lpsy15CandidatePathTerminal::Burn);
                assert_eq!(
                    path.additional_terminal_stream_count,
                    ledger.burn_terminal_stream_count
                );
                assert_eq!(
                    path.additional_terminal_carrier_byte_length,
                    ledger.burn_terminal_carrier_byte_length
                );
            }
            Lpsy15CandidatePathKind::Success | Lpsy15CandidatePathKind::AllAbstention => {
                panic!("terminal path kind repeated")
            }
        }
        assert!(path.downloaded_carrier_byte_length >= path.verified_prefix_carrier_byte_length);
    }
    assert_eq!(ledger.burn_terminal_carrier_byte_length, 36_674);
    assert_eq!(
        ledger.maximum_authenticated_failure_path_carrier_byte_length,
        3_171_899_439
    );
}

#[test]
fn canonical_stream_graph_covers_every_sender_recipient_and_round_slot() {
    let compilation = Lpsy15CandidateCompilation::compile(&completion_profile_circuit()).unwrap();
    let private_streams = compilation
        .streams()
        .iter()
        .filter(|stream| {
            matches!(
                stream.kind,
                Lpsy15CandidateStreamKind::PrivateSourceDelivery
            )
        })
        .collect::<Vec<_>>();
    let public_streams = compilation
        .streams()
        .iter()
        .filter(|stream| matches!(stream.kind, Lpsy15CandidateStreamKind::PublicRound(_)))
        .collect::<Vec<_>>();

    assert_eq!(private_streams.len(), 90);
    for sender_position in 0..10_u16 {
        for recipient_position in 0..10_u16 {
            let matching_stream_count = private_streams
                .iter()
                .filter(|stream| {
                    stream.sender_position == sender_position
                        && stream.recipient_position == Some(recipient_position)
                })
                .count();
            assert_eq!(
                matching_stream_count,
                usize::from(sender_position != recipient_position),
                "wrong private-stream cardinality for {sender_position}->{recipient_position}"
            );
        }
    }
    assert!(private_streams.iter().all(|stream| {
        stream.field_element_count == 730_119
            && stream.payload_byte_length == 29_934_879
            && stream.maximum_payload_chunk_byte_length == 1_048_534
            && stream.chunk_count == 29
            && stream.header_byte_length == 1_620
            && stream.manifest_byte_length == 2_022
            && stream.signature_envelope_byte_length == 3_953
            && stream.authentication_tag_byte_length == 464
            && stream.carrier_byte_length == 29_942_938
    }));

    for round in compilation.rounds() {
        let expected_sender_count = match round.participation {
            Lpsy15RoundParticipation::CompleteRoster => 10,
            Lpsy15RoundParticipation::StateWitnessQuorum
            | Lpsy15RoundParticipation::FinalityQuorum => 7,
        };
        assert_eq!(
            public_streams
                .iter()
                .filter(|stream| stream.round_index == round.round_index)
                .count(),
            expected_sender_count
        );
    }
    assert!(compilation.streams().iter().all(|stream| {
        stream.carrier_byte_length <= 4_294_967_291
            && stream.maximum_payload_chunk_byte_length <= 1_048_576
    }));
}

#[test]
fn deterministic_role_cursors_cover_every_random_key_prf_polynomial_and_multiplication_object() {
    let compilation = Lpsy15CandidateCompilation::compile(&completion_profile_circuit()).unwrap();
    let ledger = compilation.resource_ledger();
    let first_gate = compilation.gate_roles()[0];
    let last_gate = compilation.gate_roles()[6_764];

    let first_mask = compilation.mask_random_bit_role(0).unwrap();
    assert_eq!(first_mask.contributor_position, 0);
    assert_eq!(first_mask.physical_wire_index, 0);
    let complete_mask_count = ledger.mask_random_bit_count_per_participant * 10;
    let last_mask = compilation
        .mask_random_bit_role(complete_mask_count - 1)
        .unwrap();
    assert_eq!(last_mask.contributor_position, 9);
    assert_eq!(last_mask.physical_wire_index, 7_175);
    assert!(
        compilation
            .mask_random_bit_role(complete_mask_count)
            .is_none()
    );

    let first_key = compilation.field_key_role(0).unwrap();
    assert_eq!(first_key.owner_position, 0);
    assert_eq!(first_key.physical_wire_index, 0);
    assert!(!first_key.alternative);
    assert!(compilation.field_key_role(1).unwrap().alternative);
    let complete_key_count = ledger.physical_wire_count * ledger.participant_count * 2;
    let last_key = compilation.field_key_role(complete_key_count - 1).unwrap();
    assert_eq!(last_key.owner_position, 9);
    assert_eq!(last_key.physical_wire_index, 7_175);
    assert!(last_key.alternative);
    assert!(compilation.field_key_role(complete_key_count).is_none());

    let first_offline_prf = compilation.offline_prf_output_input_role(0).unwrap();
    assert_eq!(first_offline_prf.key_owner_position, 0);
    assert_eq!(first_offline_prf.gate_index, first_gate.gate_index);
    assert_eq!(first_offline_prf.input_side, Lpsy15InputWireSide::Left);
    assert_eq!(
        first_offline_prf.input_physical_wire_index,
        first_gate.left_physical_wire_index
    );
    assert!(!first_offline_prf.key_alternative);
    assert!(!first_offline_prf.branch);
    assert_eq!(first_offline_prf.output_component_position, 0);
    let last_offline_prf = compilation
        .offline_prf_output_input_role(ledger.complete_prf_output_input_count - 1)
        .unwrap();
    assert_eq!(last_offline_prf.key_owner_position, 9);
    assert_eq!(last_offline_prf.gate_index, last_gate.gate_index);
    assert_eq!(last_offline_prf.input_side, Lpsy15InputWireSide::Right);
    assert_eq!(
        last_offline_prf.input_physical_wire_index,
        last_gate.right_physical_wire_index
    );
    assert!(last_offline_prf.key_alternative);
    assert!(last_offline_prf.branch);
    assert_eq!(last_offline_prf.output_component_position, 9);
    assert!(
        compilation
            .offline_prf_output_input_role(ledger.complete_prf_output_input_count)
            .is_none()
    );

    let first_online_prf = compilation.online_prf_call_role(0).unwrap();
    assert_eq!(first_online_prf.evaluator_position, 0);
    assert_eq!(first_online_prf.gate_index, first_gate.gate_index);
    assert_eq!(first_online_prf.input_side, Lpsy15InputWireSide::Left);
    assert_eq!(first_online_prf.key_owner_position, 0);
    assert_eq!(first_online_prf.output_component_position, 0);
    let last_online_prf = compilation
        .online_prf_call_role(ledger.complete_online_prf_call_count - 1)
        .unwrap();
    assert_eq!(last_online_prf.evaluator_position, 9);
    assert_eq!(last_online_prf.gate_index, last_gate.gate_index);
    assert_eq!(last_online_prf.input_side, Lpsy15InputWireSide::Right);
    assert_eq!(
        last_online_prf.input_physical_wire_index,
        last_gate.right_physical_wire_index
    );
    assert_eq!(last_online_prf.key_owner_position, 9);
    assert_eq!(last_online_prf.output_component_position, 9);
    assert!(
        compilation
            .online_prf_call_role(ledger.complete_online_prf_call_count)
            .is_none()
    );

    let first_polynomial = compilation.source_polynomial_role(0).unwrap();
    assert_eq!(first_polynomial.dealer_position, 0);
    assert_eq!(
        first_polynomial.kind,
        Lpsy15SourcePolynomialKind::PrivateInput
    );
    assert_eq!(first_polynomial.ordinal_within_kind, 0);
    let last_polynomial = compilation
        .source_polynomial_role(ledger.total_polynomial_count - 1)
        .unwrap();
    assert_eq!(last_polynomial.dealer_position, 9);
    assert_eq!(
        last_polynomial.kind,
        Lpsy15SourcePolynomialKind::PairedCheckDegreeSix
    );
    assert_eq!(last_polynomial.ordinal_within_kind, 0);
    assert!(
        compilation
            .source_polynomial_role(ledger.total_polynomial_count)
            .is_none()
    );

    let first_multiplication = compilation.multiplication_role(0).unwrap();
    assert_eq!(first_multiplication.multiplication_ordinal, 0);
    assert_eq!(first_multiplication.layer_index, 1);
    assert_eq!(first_multiplication.ordinal_within_layer, 0);
    assert_eq!(
        first_multiplication.kind,
        Lpsy15MultiplicationKind::MaskProduct
    );
    let second_layer_start = ledger.multiplication_count_by_layer[0];
    let second_layer = compilation.multiplication_role(second_layer_start).unwrap();
    assert_eq!(second_layer.layer_index, 2);
    assert_eq!(second_layer.ordinal_within_layer, 0);
    let last_multiplication = compilation
        .multiplication_role(ledger.total_multiplication_count - 1)
        .unwrap();
    assert_eq!(last_multiplication.layer_index, 8);
    assert_eq!(last_multiplication.ordinal_within_layer, 409);
    assert_eq!(
        last_multiplication.kind,
        Lpsy15MultiplicationKind::SourceBoundInputActivation
    );
    assert!(
        compilation
            .multiplication_role(ledger.total_multiplication_count)
            .is_none()
    );
}

#[test]
fn polarity_normalization_preserves_every_logical_wire_on_hostile_inputs() {
    let circuit = completion_profile_circuit();
    let compilation = Lpsy15CandidateCompilation::compile(&circuit).unwrap();
    let input_bit_count = circuit.geometry().input_bit_count;
    let mut cases = vec![vec![false; input_bit_count], vec![true; input_bit_count]];
    let mut generator_state = 0x5a17_39c4_d208_6ef1_u64;
    for _ in 0..64 {
        let mut input_bits = Vec::with_capacity(input_bit_count);
        for _ in 0..input_bit_count {
            generator_state ^= generator_state << 13;
            generator_state ^= generator_state >> 7;
            generator_state ^= generator_state << 17;
            input_bits.push((generator_state & 1) == 1);
        }
        cases.push(input_bits);
    }

    for input_bits in cases {
        let logical_values = independently_evaluate_logical_circuit(&circuit, &input_bits);
        let physical_values = independently_evaluate_normalized_circuit(&compilation, &input_bits);
        for (logical_role, logical_value) in
            compilation.logical_wire_roles().iter().zip(logical_values)
        {
            let physical_value =
                physical_values[usize::try_from(logical_role.physical_wire_index).unwrap()];
            assert_eq!(
                logical_value,
                physical_value ^ logical_role.is_inverted,
                "logical wire {} disagrees with its normalized physical role",
                logical_role.logical_wire_index
            );
        }
    }
}

#[test]
fn every_profile_derives_roles_counts_and_visits_from_its_compiled_circuit() {
    for top_count in 1..=FOUNDATION_PROFILE.option_count {
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(
                FOUNDATION_PROFILE.participant_count,
                FOUNDATION_PROFILE.option_count,
                top_count,
            )
            .unwrap(),
        )
        .unwrap();
        let compilation = Lpsy15CandidateCompilation::compile(&circuit).unwrap();
        let ledger = compilation.resource_ledger();
        let roster_parameters =
            derive_foundation_roster_parameters(circuit.profile().participant_count()).unwrap();
        let independently_counted_binary_gates = circuit
            .operations()
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    BooleanOperation::ExclusiveOr { .. } | BooleanOperation::Conjunction { .. }
                )
            })
            .count();
        let independently_counted_physical_wires =
            circuit.geometry().input_bit_count + 1 + independently_counted_binary_gates;
        let independently_counted_negations = circuit
            .operations()
            .iter()
            .filter(|operation| matches!(operation, BooleanOperation::Negation { .. }))
            .count();

        assert_eq!(
            compilation.logical_wire_roles().len(),
            circuit.geometry().total_wire_count
        );
        assert_eq!(
            compilation.physical_wire_roles().len(),
            independently_counted_physical_wires
        );
        assert_eq!(
            compilation.gate_roles().len(),
            independently_counted_binary_gates
        );
        assert_eq!(
            ledger.eliminated_negation_count,
            u64::try_from(independently_counted_negations).unwrap()
        );
        assert_eq!(ledger.participant_count, 10);
        assert_eq!(
            ledger.corruption_bound,
            u64::from(roster_parameters.active_fault_bound)
        );
        assert_eq!(
            ledger.complete_prf_output_input_count,
            ledger.prf_output_input_count_per_participant * ledger.participant_count
        );
        assert_eq!(
            ledger.canonical_table_byte_length,
            ledger.table_field_element_count * ledger.prime_field_element_byte_length
        );
        assert_eq!(
            ledger.raw_upload_payload_byte_length,
            ledger.remote_private_share_payload_byte_length
                + ledger.public_opening_payload_byte_length
        );
        assert!(ledger.minimum_dependency_separated_visit_count > 0);
        assert!(
            ledger.maximum_dependency_separated_visit_count
                >= ledger.minimum_dependency_separated_visit_count
        );
    }
}

#[test]
fn prime_representation_has_the_required_canonical_width_and_offset() {
    let modulus = BigUint::from_bytes_le(&LPSY15_PRIME_MODULUS_LITTLE_ENDIAN);
    let two_to_320 = BigUint::from(1_u8) << 320;
    assert_eq!(modulus, &two_to_320 + BigUint::from(27_u8));
    assert_eq!(modulus.to_str_radix(10), LPSY15_PRIME_MODULUS_DECIMAL);
    assert_eq!(modulus.bits(), 321);
    assert_eq!(modulus.to_bytes_le().len(), 41);

    for even_offset in (2_u8..27).step_by(2) {
        assert_eq!(
            (&two_to_320 + BigUint::from(even_offset)) % BigUint::from(2_u8),
            BigUint::from(0_u8)
        );
    }
}

fn completion_profile_circuit() -> CompiledTallyCircuit {
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

fn independently_evaluate_logical_circuit(
    circuit: &CompiledTallyCircuit,
    input_bits: &[bool],
) -> Vec<bool> {
    let mut values = input_bits.to_vec();
    for operation in circuit.operations() {
        let value = match operation {
            BooleanOperation::Constant(value) => *value,
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            } => {
                values[usize::try_from(*left_wire).unwrap()]
                    ^ values[usize::try_from(*right_wire).unwrap()]
            }
            BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => {
                values[usize::try_from(*left_wire).unwrap()]
                    & values[usize::try_from(*right_wire).unwrap()]
            }
            BooleanOperation::Negation { input_wire } => {
                !values[usize::try_from(*input_wire).unwrap()]
            }
        };
        values.push(value);
    }
    values
}

fn independently_evaluate_normalized_circuit(
    compilation: &Lpsy15CandidateCompilation,
    input_bits: &[bool],
) -> Vec<bool> {
    let mut values = Vec::with_capacity(compilation.physical_wire_roles().len());
    for wire in compilation.physical_wire_roles() {
        match wire.source {
            Lpsy15PhysicalWireSource::BallotInput(_) => {
                values.push(input_bits[usize::try_from(wire.wire_index).unwrap()]);
            }
            Lpsy15PhysicalWireSource::FixedFalse => values.push(false),
            Lpsy15PhysicalWireSource::GateOutput { gate_index } => {
                let gate = compilation.gate_roles()[usize::try_from(gate_index).unwrap()];
                let left = values[usize::try_from(gate.left_physical_wire_index).unwrap()];
                let right = values[usize::try_from(gate.right_physical_wire_index).unwrap()];
                let output = match gate.kind {
                    Lpsy15GateKind::ExclusiveOr => left ^ right,
                    Lpsy15GateKind::Nonlinear { truth_table } => {
                        let bit_position = usize::from(left) * 2 + usize::from(right);
                        ((truth_table >> bit_position) & 1) == 1
                    }
                };
                values.push(output);
            }
        }
    }
    values
}
