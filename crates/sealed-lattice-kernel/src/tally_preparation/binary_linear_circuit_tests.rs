use super::binary_linear_circuit::CompiledBinaryLinearCircuit;

#[test]
fn windowed_linear_circuit_matches_direct_parities_for_every_small_input() {
    let targets = vec![
        vec![false, false, false, false, false, false],
        vec![true, false, false, false, false, false],
        vec![true, true, true, true, true, true],
        vec![true, false, true, false, true, false],
        vec![false, true, true, false, false, true],
    ];
    let circuit = CompiledBinaryLinearCircuit::compile_smallest_windowed(&targets, 6).unwrap();

    for encoded_input in 0_u8..64_u8 {
        let input_values = (0..6)
            .map(|bit_position| (encoded_input >> bit_position) & 1_u8 == 1_u8)
            .collect::<Vec<_>>();
        let expected_outputs = targets
            .iter()
            .map(|target| {
                target
                    .iter()
                    .copied()
                    .zip(input_values.iter().copied())
                    .fold(false, |parity, (selected, value)| {
                        parity ^ (selected && value)
                    })
            })
            .collect::<Vec<_>>();

        assert_eq!(circuit.evaluate(&input_values).unwrap(), expected_outputs);
    }
}

#[test]
fn windowed_linear_circuit_refuses_inconsistent_geometry() {
    assert!(CompiledBinaryLinearCircuit::compile_smallest_windowed(&[], 0).is_err());
    assert!(
        CompiledBinaryLinearCircuit::compile_smallest_windowed(
            &[vec![true, false], vec![true]],
            2,
        )
        .is_err()
    );

    let circuit =
        CompiledBinaryLinearCircuit::compile_smallest_windowed(&[vec![true, false]], 2).unwrap();
    assert!(circuit.evaluate(&[true]).is_err());
    assert_eq!(circuit.evaluate(&[false, true]).unwrap(), vec![false]);
    assert_eq!(circuit.evaluate(&[true, false]).unwrap(), vec![true]);
}
