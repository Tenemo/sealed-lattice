use super::lpsy15_scalar_measurement::{
    FIELD_MEASUREMENT_KIND, Lpsy15ScalarMeasurementCounts, Lpsy15ScalarMeasurementCursor,
    Lpsy15ScalarMeasurementError, Lpsy15ScalarMeasurementKind, PRF_MEASUREMENT_KIND,
};

#[test]
fn completion_counts_come_from_the_candidate_compiler() {
    let counts = Lpsy15ScalarMeasurementCounts::derive().unwrap();
    assert_eq!(counts.field_multiplication_count, 76_515_363);
    assert_eq!(counts.field_addition_count, 75_550_092);
    assert_eq!(counts.prf_call_count, 1_894_200);
    assert_eq!(counts.prf_message_byte_length, 452);
    assert_eq!(counts.prf_permutation_count_per_call, 6);
    assert_eq!(counts.work_batch_operation_count, 4_096);
    assert_eq!(counts.field_scratch_byte_length, 1_376_256);
}

#[test]
fn field_and_prf_cursors_advance_one_bounded_batch() {
    for (kind, code) in [
        (
            Lpsy15ScalarMeasurementKind::PrimeField,
            FIELD_MEASUREMENT_KIND,
        ),
        (Lpsy15ScalarMeasurementKind::BmrPrf, PRF_MEASUREMENT_KIND),
    ] {
        assert_eq!(kind.code(), code);
        let mut cursor = Lpsy15ScalarMeasurementCursor::new(kind).unwrap();
        let initial_snapshot = cursor.snapshot_bytes();
        assert!(!cursor.step().unwrap());
        assert_eq!(
            cursor.completed_operation_count,
            cursor.counts.work_batch_operation_count
        );
        assert_ne!(
            cursor.snapshot_bytes().as_slice(),
            initial_snapshot.as_slice()
        );
    }
}

#[test]
fn authenticated_checkpoint_restores_exactly_and_refuses_mutation() {
    for kind in [
        Lpsy15ScalarMeasurementKind::PrimeField,
        Lpsy15ScalarMeasurementKind::BmrPrf,
    ] {
        let mut uninterrupted = Lpsy15ScalarMeasurementCursor::new(kind).unwrap();
        uninterrupted.step().unwrap();
        uninterrupted.step().unwrap();
        let checkpoint = uninterrupted.checkpoint_bytes();
        uninterrupted.step().unwrap();
        let expected = uninterrupted.snapshot_bytes();

        let mut restored = Lpsy15ScalarMeasurementCursor::restore(kind, &checkpoint).unwrap();
        restored.step().unwrap();
        assert_eq!(restored.snapshot_bytes().as_slice(), expected.as_slice());

        for mutation_position in [0, checkpoint.len() / 2, checkpoint.len() - 1] {
            let mut mutated = checkpoint.to_vec();
            mutated[mutation_position] ^= 1;
            assert!(matches!(
                Lpsy15ScalarMeasurementCursor::restore(kind, &mutated),
                Err(Lpsy15ScalarMeasurementError::AuthenticationFailed)
            ));
        }
    }
}

#[test]
fn checkpoint_kind_cannot_be_replayed_across_kernels() {
    let mut field_cursor =
        Lpsy15ScalarMeasurementCursor::new(Lpsy15ScalarMeasurementKind::PrimeField).unwrap();
    field_cursor.step().unwrap();
    let checkpoint = field_cursor.checkpoint_bytes();
    assert!(matches!(
        Lpsy15ScalarMeasurementCursor::restore(Lpsy15ScalarMeasurementKind::BmrPrf, &checkpoint,),
        Err(Lpsy15ScalarMeasurementError::AuthenticationFailed)
    ));
}
