use crate::{
    foundation::Hash512,
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile},
};
use tiny_keccak::{Hasher, Kmac};

use super::{
    ExplicitJointRandomTape, SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH, SeededJointRandomTape,
    TallyPreparationContext, TallyPreparationError, TallyPreparationGeometry,
    TallyPreparationRandomTapeSource, parse_tally_preparation_random_state,
};

#[test]
fn completion_geometry_is_derived_from_the_emitted_full_ranking_circuit() {
    let circuit = completion_circuit(10);
    let geometry = TallyPreparationGeometry::derive(&circuit).unwrap();

    assert_eq!(geometry.participant_count, 10);
    assert_eq!(geometry.wire_count, 7_933);
    assert_eq!(geometry.packed_wire_mask_byte_length, 992);
    assert_eq!(geometry.label_key_count, 158_660);
    assert_eq!(geometry.label_key_byte_length, 5_077_120);
    assert_eq!(geometry.score_input_wire_count, 400);
    assert_eq!(geometry.result_output_wire_count, 40);
    assert_eq!(geometry.shared_mask_count, 440);
    assert_eq!(geometry.sharing_random_coefficient_count, 1_320);
    assert_eq!(geometry.sharing_random_coefficient_byte_length, 42_240);
    assert_eq!(geometry.label_opening_leaf_count, 158_660);
    assert_eq!(geometry.present_owner_mask_bundle_leaf_count, 10);
    assert_eq!(geometry.absence_share_bundle_leaf_count, 100);
    assert_eq!(geometry.result_share_bundle_leaf_count, 10);
    assert_eq!(geometry.private_wire_mask_bundle_leaf_count, 1);
    assert_eq!(geometry.secret_leaf_salt_count, 158_781);
    assert_eq!(geometry.secret_leaf_salt_byte_length, 7_621_488);
    assert_eq!(geometry.direct_joint_random_tape_byte_length, 12_741_840);
    assert_eq!(
        geometry.all_party_explicit_tape_input_byte_length,
        127_418_400
    );
    assert_eq!(geometry.seeded_expansion_kmac_call_count, 195);
    assert_eq!(geometry.binary_gate_row_count, 27_060);
    assert_eq!(geometry.unary_gate_row_count, 1_512);
    assert_eq!(geometry.garbled_gate_row_count, 28_572);
    assert_eq!(geometry.constant_activation_count, 2);
    assert_eq!(geometry.correlation_key_contribution_count, 2_857_200);
    assert_eq!(geometry.correlation_selector_contribution_count, 285_720);
    assert_eq!(geometry.correlation_contribution_byte_length, 91_716_120);
    assert_eq!(geometry.garbling_kmac_call_count, 2_857_200);
    assert_eq!(geometry.public_garbled_table_byte_length, 9_172_254);
}

#[test]
fn geometry_matches_an_independent_operation_and_schema_counter_for_every_top_count() {
    for top_count in 1..=10 {
        let circuit = completion_circuit(top_count);
        let geometry = TallyPreparationGeometry::derive(&circuit).unwrap();
        let participant_count = u64::from(circuit.profile().participant_count());
        let independently_counted_wire_count = u64::try_from(circuit.geometry().input_bit_count)
            .unwrap()
            + u64::try_from(circuit.operations().len()).unwrap();
        let independently_counted_rows = circuit
            .operations()
            .iter()
            .map(|operation| match operation {
                BooleanOperation::Constant(_) => 0_u64,
                BooleanOperation::ExclusiveOr { .. } | BooleanOperation::Conjunction { .. } => {
                    4_u64
                }
                BooleanOperation::Negation { .. } => 2_u64,
            })
            .sum::<u64>();
        let independently_counted_constants = circuit
            .operations()
            .iter()
            .filter(|operation| matches!(operation, BooleanOperation::Constant(_)))
            .count() as u64;
        let active_label_vector_bytes = participant_count * 32 + 1;

        assert_eq!(geometry.wire_count, independently_counted_wire_count);
        assert_eq!(geometry.garbled_gate_row_count, independently_counted_rows);
        assert_eq!(
            geometry.constant_activation_count,
            independently_counted_constants
        );
        assert_eq!(
            geometry.public_garbled_table_byte_length,
            (independently_counted_rows + independently_counted_constants)
                * active_label_vector_bytes
        );
        assert_eq!(
            geometry.correlation_contribution_byte_length,
            independently_counted_rows * participant_count * active_label_vector_bytes
        );
    }
}

#[test]
fn explicit_joint_tape_xors_all_participants_and_refuses_shape_errors() {
    let circuit = small_circuit();
    let geometry = TallyPreparationGeometry::derive(&circuit).unwrap();
    let tape_byte_length = geometry
        .direct_joint_random_tape_byte_length_usize()
        .unwrap();
    let tapes = (0..4_u8)
        .map(|participant_position| {
            (0..tape_byte_length)
                .map(|byte_position| {
                    participant_position.wrapping_mul(0x31)
                        ^ u8::try_from(byte_position % 251).unwrap()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let tape_views = tapes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let mut source = ExplicitJointRandomTape::new(&tape_views, 4, geometry).unwrap();
    let mut expected_joint_tape = vec![0_u8; tape_byte_length];
    for tape in &tapes {
        for (joint_byte, tape_byte) in expected_joint_tape.iter_mut().zip(tape) {
            *joint_byte ^= *tape_byte;
        }
    }
    let state = parse_tally_preparation_random_state(&circuit, &mut source).unwrap();
    assert_eq!(state.wire_masks()[0], expected_joint_tape[0] & 1);
    let mask_byte_length = usize::try_from(geometry.packed_wire_mask_byte_length).unwrap();
    assert_eq!(
        state.label_keys()[0].canonical_bytes(),
        &expected_joint_tape[mask_byte_length..mask_byte_length + 32]
    );
    assert_eq!(
        state
            .label_key(geometry, 0, false, 0)
            .unwrap()
            .canonical_bytes(),
        state.label_keys()[0].canonical_bytes()
    );
    assert!(state.label_key(geometry, usize::MAX, false, 0).is_none());
    assert_eq!(
        state.label_keys().len(),
        usize::try_from(geometry.label_key_count).unwrap()
    );
    assert_eq!(
        state.score_input_mask_polynomials().len(),
        usize::try_from(geometry.score_input_wire_count).unwrap()
    );
    assert_eq!(
        state.result_mask_polynomials().len(),
        usize::try_from(geometry.result_output_wire_count).unwrap()
    );
    assert_eq!(
        state.secret_leaf_salts().len(),
        usize::try_from(geometry.secret_leaf_salt_count).unwrap()
    );
    assert_eq!(state.secret_leaf_salts()[0].canonical_bytes().len(), 48);

    assert!(matches!(
        ExplicitJointRandomTape::new(&tape_views[..3], 4, geometry),
        Err(TallyPreparationError::RandomTapeParticipantCountMismatch {
            expected: 4,
            actual: 3
        })
    ));
    let mut short_tapes = tape_views.clone();
    short_tapes[2] = &short_tapes[2][..tape_byte_length - 1];
    assert!(matches!(
        ExplicitJointRandomTape::new(&short_tapes, 4, geometry),
        Err(TallyPreparationError::RandomTapeByteLengthMismatch {
            participant_position: 2,
            ..
        })
    ));
}

#[test]
fn seeded_model_replays_the_exact_explicit_tape_and_binds_every_context_field() {
    let circuit = small_circuit();
    let geometry = TallyPreparationGeometry::derive(&circuit).unwrap();
    let context = sample_context(&circuit, 0x44, 0x71, 0x9b);
    let participant_seeds = [[0x11_u8; 32], [0x37_u8; 32], [0x8c_u8; 32], [0xe2_u8; 32]];
    let tape_byte_length = geometry
        .direct_joint_random_tape_byte_length_usize()
        .unwrap();
    let mut seeded_source =
        SeededJointRandomTape::new(&participant_seeds, context, geometry).unwrap();
    let mut expanded_tape = vec![0_u8; tape_byte_length];
    for chunk in expanded_tape.chunks_mut(7_919) {
        seeded_source.fill_exact(chunk).unwrap();
    }
    seeded_source.ensure_finished().unwrap();

    let zero_tape = vec![0_u8; tape_byte_length];
    let explicit_tapes = [
        expanded_tape.as_slice(),
        zero_tape.as_slice(),
        zero_tape.as_slice(),
        zero_tape.as_slice(),
    ];
    let mut explicit_source = ExplicitJointRandomTape::new(&explicit_tapes, 4, geometry).unwrap();
    let explicit_state =
        parse_tally_preparation_random_state(&circuit, &mut explicit_source).unwrap();
    let mut seeded_source =
        SeededJointRandomTape::new(&participant_seeds, context, geometry).unwrap();
    let seeded_state = parse_tally_preparation_random_state(&circuit, &mut seeded_source).unwrap();
    assert_eq!(seeded_state, explicit_state);

    for changed_context in [
        sample_context(&circuit, 0x45, 0x71, 0x9b),
        sample_context(&circuit, 0x44, 0x72, 0x9b),
        sample_context(&circuit, 0x44, 0x71, 0x9c),
    ] {
        let mut changed_source =
            SeededJointRandomTape::new(&participant_seeds, changed_context, geometry).unwrap();
        let mut changed_prefix = [0_u8; 96];
        changed_source.fill_exact(&mut changed_prefix).unwrap();
        assert_ne!(changed_prefix.as_slice(), &expanded_tape[..96]);
    }
    let mut changed_seeds = participant_seeds;
    changed_seeds[3][17] ^= 1;
    let mut changed_source = SeededJointRandomTape::new(&changed_seeds, context, geometry).unwrap();
    let mut changed_prefix = [0_u8; 96];
    changed_source.fill_exact(&mut changed_prefix).unwrap();
    assert_ne!(changed_prefix.as_slice(), &expanded_tape[..96]);
}

#[test]
fn seeded_model_block_matches_independent_kmac256_bytes() {
    let circuit = small_circuit();
    let geometry = TallyPreparationGeometry::derive(&circuit).unwrap();
    let context = sample_context(&circuit, 0x2b, 0x63, 0xa1);
    let participant_seeds = [[0x19_u8; 32], [0x35_u8; 32], [0x78_u8; 32], [0xc4_u8; 32]];
    let mut source = SeededJointRandomTape::new(&participant_seeds, context, geometry).unwrap();
    let mut actual_prefix = [0_u8; 257];
    source.fill_exact(&mut actual_prefix).unwrap();

    let mut joint_seed = [0_u8; 32];
    for participant_seed in participant_seeds {
        for (joint_byte, participant_byte) in joint_seed.iter_mut().zip(participant_seed) {
            *joint_byte ^= participant_byte;
        }
    }
    let total_byte_length = geometry
        .direct_joint_random_tape_byte_length_usize()
        .unwrap();
    let mut independent_kmac = Kmac::v256(
        &joint_seed,
        b"sealed-lattice/tally-preparation-seeded-random-tape/v1",
    );
    independently_update_framed(&mut independent_kmac, context.identity().as_bytes());
    independently_update_framed(
        &mut independent_kmac,
        &u64::try_from(total_byte_length).unwrap().to_le_bytes(),
    );
    independently_update_framed(&mut independent_kmac, &0_u64.to_le_bytes());
    let mut expected_block = vec![0_u8; SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH];
    independent_kmac.finalize(&mut expected_block);

    assert_eq!(
        actual_prefix.as_slice(),
        &expected_block[..actual_prefix.len()]
    );
}

#[test]
fn tape_sources_enforce_exact_consumption_and_exhaustion() {
    let circuit = small_circuit();
    let geometry = TallyPreparationGeometry::derive(&circuit).unwrap();
    let tape_byte_length = geometry
        .direct_joint_random_tape_byte_length_usize()
        .unwrap();
    let tape = vec![0_u8; tape_byte_length];
    let tape_views = [tape.as_slice(); 4];
    let mut source = ExplicitJointRandomTape::new(&tape_views, 4, geometry).unwrap();
    source.fill_exact(&mut [0_u8; 17]).unwrap();
    assert_eq!(
        source.ensure_finished(),
        Err(TallyPreparationError::RandomTapeNotFullyConsumed {
            expected: tape_byte_length,
            consumed: 17,
        })
    );
    let mut remaining = vec![0_u8; tape_byte_length - 17];
    source.fill_exact(&mut remaining).unwrap();
    source.ensure_finished().unwrap();
    assert_eq!(
        source.fill_exact(&mut [0_u8; 1]),
        Err(TallyPreparationError::RandomTapeExhausted)
    );

    assert_eq!(
        geometry.seeded_expansion_kmac_call_count,
        geometry
            .direct_joint_random_tape_byte_length
            .div_ceil(u64::try_from(SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH).unwrap())
    );
}

fn completion_circuit(top_count: u16) -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(TallyCircuitProfile::new(10, 10, top_count).unwrap()).unwrap()
}

fn small_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(TallyCircuitProfile::new(4, 2, 1).unwrap()).unwrap()
}

fn sample_context(
    circuit: &CompiledTallyCircuit,
    action_byte: u8,
    roster_byte: u8,
    attempt_byte: u8,
) -> TallyPreparationContext {
    TallyPreparationContext::new(
        Hash512::from_bytes([action_byte; 64]),
        Hash512::from_bytes([roster_byte; 64]),
        [attempt_byte; 32],
        circuit,
    )
    .unwrap()
}

fn independently_update_framed(kmac: &mut Kmac, part: &[u8]) {
    kmac.update(&u64::try_from(part.len()).unwrap().to_le_bytes());
    kmac.update(part);
}
