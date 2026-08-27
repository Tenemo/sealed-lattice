use super::{
    CompiledTallyCircuit, TallyCircuitError, TallyCircuitProfile, TallyEvaluationInput, WireIndex,
    compiler::compile_tally_circuit_with_authorship_sources,
    direct_evaluator::evaluate_tally_directly,
    foundation_score_bounds,
    interpreter::{encode_tally_input_bits, interpret_boolean_operations, read_wire},
};

/// An identity boundary that assigns a fresh independent label pair to output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutputRekeyOperation {
    input_wire: WireIndex,
    output_wire: WireIndex,
}

impl OutputRekeyOperation {
    pub(crate) const fn input_wire(self) -> WireIndex {
        self.input_wire
    }

    pub(crate) const fn output_wire(self) -> WireIndex {
        self.output_wire
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutputRekeyedTallyCircuitGeometry {
    pub(crate) input_bit_count: usize,
    pub(crate) conjunction_gate_count: usize,
    pub(crate) exclusive_or_gate_count: usize,
    pub(crate) negation_gate_count: usize,
    pub(crate) output_rekey_operation_count: usize,
    pub(crate) active_gate_count: usize,
    pub(crate) public_output_bit_count: usize,
    pub(crate) private_result_bit_count: usize,
    pub(crate) total_wire_count: usize,
}

/// Output-rekey extension of the deterministic tally circuit.
///
/// This extension adds accepted-ballot authorship outputs and one fresh
/// independent-label boundary for every public and private output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputRekeyedTallyCircuit {
    core_circuit: CompiledTallyCircuit,
    geometry: OutputRekeyedTallyCircuitGeometry,
    output_rekey_operations: Vec<OutputRekeyOperation>,
    accepted_ballot_authorship_output_wires: Vec<WireIndex>,
    nonempty_output_wire: WireIndex,
    ordered_option_position_wires: Vec<Vec<WireIndex>>,
}

impl OutputRekeyedTallyCircuit {
    pub(crate) fn compile(profile: TallyCircuitProfile) -> Result<Self, TallyCircuitError> {
        let (core_circuit, accepted_ballot_authorship_source_wires) =
            compile_tally_circuit_with_authorship_sources(profile)?;
        let mut next_wire_position = core_circuit.geometry().total_wire_count;
        let mut output_rekey_operations = Vec::new();

        let accepted_ballot_authorship_output_wires = accepted_ballot_authorship_source_wires
            .into_iter()
            .map(|source_wire| {
                append_output_rekey(
                    source_wire,
                    &mut next_wire_position,
                    &mut output_rekey_operations,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let nonempty_output_wire = append_output_rekey(
            core_circuit.nonempty_output_wire(),
            &mut next_wire_position,
            &mut output_rekey_operations,
        )?;
        let ordered_option_position_wires = core_circuit
            .ordered_option_position_wires()
            .iter()
            .map(|position_source_wires| {
                position_source_wires
                    .iter()
                    .copied()
                    .map(|source_wire| {
                        append_output_rekey(
                            source_wire,
                            &mut next_wire_position,
                            &mut output_rekey_operations,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let core_geometry = core_circuit.geometry();
        let public_output_bit_count = accepted_ballot_authorship_output_wires
            .len()
            .checked_add(1)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        let private_result_bit_count = ordered_option_position_wires
            .iter()
            .try_fold(0_usize, |count, position_wires| {
                count.checked_add(position_wires.len())
            })
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        let output_rekey_operation_count = output_rekey_operations.len();
        if output_rekey_operation_count
            != public_output_bit_count
                .checked_add(private_result_bit_count)
                .ok_or(TallyCircuitError::ArithmeticOverflow)?
        {
            return Err(TallyCircuitError::CircuitMismatch);
        }
        let active_gate_count = core_geometry
            .conjunction_gate_count
            .checked_add(core_geometry.exclusive_or_gate_count)
            .and_then(|count| count.checked_add(core_geometry.negation_gate_count))
            .and_then(|count| count.checked_add(output_rekey_operation_count))
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;

        Ok(Self {
            core_circuit,
            geometry: OutputRekeyedTallyCircuitGeometry {
                input_bit_count: core_geometry.input_bit_count,
                conjunction_gate_count: core_geometry.conjunction_gate_count,
                exclusive_or_gate_count: core_geometry.exclusive_or_gate_count,
                negation_gate_count: core_geometry.negation_gate_count,
                output_rekey_operation_count,
                active_gate_count,
                public_output_bit_count,
                private_result_bit_count,
                total_wire_count: next_wire_position,
            },
            output_rekey_operations,
            accepted_ballot_authorship_output_wires,
            nonempty_output_wire,
            ordered_option_position_wires,
        })
    }

    pub(crate) const fn profile(&self) -> TallyCircuitProfile {
        self.core_circuit.profile()
    }

    pub(crate) const fn geometry(&self) -> OutputRekeyedTallyCircuitGeometry {
        self.geometry
    }

    pub(crate) const fn core_circuit(&self) -> &CompiledTallyCircuit {
        &self.core_circuit
    }

    pub(crate) fn output_rekey_operations(&self) -> &[OutputRekeyOperation] {
        &self.output_rekey_operations
    }

    pub(crate) fn accepted_ballot_authorship_output_wires(&self) -> &[WireIndex] {
        &self.accepted_ballot_authorship_output_wires
    }

    pub(crate) const fn nonempty_output_wire(&self) -> WireIndex {
        self.nonempty_output_wire
    }

    pub(crate) fn ordered_option_position_wires(&self) -> &[Vec<WireIndex>] {
        &self.ordered_option_position_wires
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputRekeyedTallyEvaluationOutcome {
    accepted_ballot_authorship: Vec<bool>,
    ordered_option_positions: Vec<u16>,
    has_selected_ballot: bool,
}

impl OutputRekeyedTallyEvaluationOutcome {
    pub(crate) fn accepted_ballot_authorship(&self) -> &[bool] {
        &self.accepted_ballot_authorship
    }

    pub(crate) fn ordered_option_positions(&self) -> &[u16] {
        &self.ordered_option_positions
    }

    pub(crate) const fn has_selected_ballot(&self) -> bool {
        self.has_selected_ballot
    }

    pub(crate) fn accepted_ordered_option_positions(&self) -> Option<&[u16]> {
        self.has_selected_ballot
            .then_some(self.ordered_option_positions.as_slice())
    }
}

pub(crate) fn evaluate_output_rekeyed_tally_circuit(
    circuit: &OutputRekeyedTallyCircuit,
    input: &TallyEvaluationInput,
) -> Result<OutputRekeyedTallyEvaluationOutcome, TallyCircuitError> {
    let input_bits = encode_tally_input_bits(circuit.core_circuit(), input)?;
    let mut wire_values = interpret_boolean_operations(circuit.core_circuit(), &input_bits)?;

    for operation in circuit.output_rekey_operations() {
        let expected_output_wire = WireIndex::try_from(wire_values.len())
            .map_err(|_| TallyCircuitError::WireIndexOverflow)?;
        if operation.output_wire() != expected_output_wire {
            return Err(TallyCircuitError::CircuitMismatch);
        }
        let output_value = read_wire(&wire_values, operation.input_wire())?;
        wire_values.push(output_value);
    }
    if wire_values.len() != circuit.geometry().total_wire_count {
        return Err(TallyCircuitError::CircuitMismatch);
    }

    let accepted_ballot_authorship = circuit
        .accepted_ballot_authorship_output_wires()
        .iter()
        .copied()
        .map(|wire| read_wire(&wire_values, wire))
        .collect::<Result<Vec<_>, _>>()?;
    let ordered_option_positions =
        decode_ordered_option_positions(&wire_values, circuit.ordered_option_position_wires())?;
    let has_selected_ballot = read_wire(&wire_values, circuit.nonempty_output_wire())?;

    Ok(OutputRekeyedTallyEvaluationOutcome {
        accepted_ballot_authorship,
        ordered_option_positions,
        has_selected_ballot,
    })
}

/// Evaluates the extended public-output semantics without using circuit wires.
pub(crate) fn evaluate_output_rekeyed_tally_directly(
    profile: TallyCircuitProfile,
    input: &TallyEvaluationInput,
) -> Result<OutputRekeyedTallyEvaluationOutcome, TallyCircuitError> {
    let core_outcome = evaluate_tally_directly(profile, input)?;
    let (minimum_score, maximum_score) = foundation_score_bounds()?;
    let accepted_ballot_authorship = input
        .participant_ballots()
        .iter()
        .map(|ballot| {
            ballot.is_present()
                && ballot
                    .score_encodings()
                    .iter()
                    .copied()
                    .all(|score_encoding| {
                        (minimum_score..=maximum_score).contains(&u16::from(score_encoding))
                    })
        })
        .collect::<Vec<_>>();
    let has_selected_ballot = accepted_ballot_authorship
        .iter()
        .copied()
        .any(|value| value);
    if has_selected_ballot != core_outcome.has_selected_ballot() {
        return Err(TallyCircuitError::CircuitMismatch);
    }

    Ok(OutputRekeyedTallyEvaluationOutcome {
        accepted_ballot_authorship,
        ordered_option_positions: core_outcome.ordered_option_positions().to_vec(),
        has_selected_ballot,
    })
}

fn append_output_rekey(
    input_wire: WireIndex,
    next_wire_position: &mut usize,
    operations: &mut Vec<OutputRekeyOperation>,
) -> Result<WireIndex, TallyCircuitError> {
    if usize::try_from(input_wire).map_or(true, |wire| wire >= *next_wire_position) {
        return Err(TallyCircuitError::InvalidWireReference {
            wire: input_wire,
            available_wire_count: *next_wire_position,
        });
    }
    let output_wire = WireIndex::try_from(*next_wire_position)
        .map_err(|_| TallyCircuitError::WireIndexOverflow)?;
    *next_wire_position = next_wire_position
        .checked_add(1)
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    operations.push(OutputRekeyOperation {
        input_wire,
        output_wire,
    });
    Ok(output_wire)
}

fn decode_ordered_option_positions(
    wire_values: &[bool],
    ordered_option_position_wires: &[Vec<WireIndex>],
) -> Result<Vec<u16>, TallyCircuitError> {
    ordered_option_position_wires
        .iter()
        .map(|position_wires| {
            position_wires.iter().copied().enumerate().try_fold(
                0_u16,
                |position, (bit_position, wire)| {
                    if read_wire(wire_values, wire)? {
                        let bit_value = 1_u16
                            .checked_shl(
                                u32::try_from(bit_position)
                                    .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
                            )
                            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
                        position
                            .checked_add(bit_value)
                            .ok_or(TallyCircuitError::ArithmeticOverflow)
                    } else {
                        Ok(position)
                    }
                },
            )
        })
        .collect()
}
