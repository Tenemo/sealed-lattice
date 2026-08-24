use crate::hashing::hash_framed_parts_512;

use super::{
    BooleanOperation, CompiledTallyCircuit, TALLY_CIRCUIT_COMPILER_DEFINITION,
    TALLY_CIRCUIT_COMPILER_IDENTITY_DOMAIN, TallyCircuitError, TallyCircuitGeometry,
    TallyCircuitProfile, WireIndex, bit_width_for_maximum_value, foundation_score_bounds,
};

pub(crate) fn tally_circuit_compiler_identity() -> Result<[u8; 64], TallyCircuitError> {
    let (minimum_score, maximum_score) = foundation_score_bounds()?;
    Ok(hash_framed_parts_512(
        TALLY_CIRCUIT_COMPILER_IDENTITY_DOMAIN,
        &[
            TALLY_CIRCUIT_COMPILER_DEFINITION,
            &minimum_score.to_le_bytes(),
            &maximum_score.to_le_bytes(),
        ],
    ))
}

pub(crate) fn compile_tally_circuit(
    profile: TallyCircuitProfile,
) -> Result<CompiledTallyCircuit, TallyCircuitError> {
    let (_, maximum_score) = foundation_score_bounds()?;
    let participant_count = usize::from(profile.participant_count());
    let option_count = usize::from(profile.option_count());
    let top_count = usize::from(profile.top_count());
    let score_bit_width = bit_width_for_maximum_value(usize::from(maximum_score));
    let input_bit_count = participant_count
        .checked_mul(option_count)
        .and_then(|score_count| score_count.checked_mul(score_bit_width))
        .and_then(|score_bit_count| score_bit_count.checked_add(participant_count))
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    let maximum_aggregate_score = participant_count
        .checked_mul(usize::from(maximum_score))
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    let aggregate_score_bit_width = bit_width_for_maximum_value(maximum_aggregate_score);
    let option_position_bit_width = bit_width_for_maximum_value(option_count - 1).max(1);

    let mut builder = BooleanCircuitBuilder::new(input_bit_count)?;
    let participant_presence_wires = (0..participant_count)
        .map(wire_index_from_usize)
        .collect::<Result<Vec<_>, _>>()?;
    let participant_score_wires =
        derive_score_input_wires(participant_count, option_count, score_bit_width)?;

    let mut participant_validity_wires = Vec::with_capacity(participant_count);
    let mut presence_gated_score_wires = vec![vec![Vec::new(); option_count]; participant_count];

    for participant_position in 0..participant_count {
        let mut all_scores_valid_wire = builder.append_constant(true)?;
        let mut flattened_score_wires = Vec::with_capacity(
            option_count
                .checked_mul(score_bit_width)
                .ok_or(TallyCircuitError::ArithmeticOverflow)?,
        );

        for option_position in 0..option_count {
            let score_wires = &participant_score_wires[participant_position][option_position];
            let valid_score_wire = score_is_valid(&mut builder, score_wires)?;
            all_scores_valid_wire =
                builder.append_conjunction(all_scores_valid_wire, valid_score_wire)?;
            flattened_score_wires.extend_from_slice(score_wires);

            let mut gated_wires = Vec::with_capacity(score_bit_width);
            for score_wire in score_wires {
                gated_wires.push(builder.append_conjunction(
                    participant_presence_wires[participant_position],
                    *score_wire,
                )?);
            }
            presence_gated_score_wires[participant_position][option_position] = gated_wires;
        }

        let absent_scores_are_zero_wire = all_zero(&mut builder, &flattened_score_wires)?;
        let valid_present_wire = builder.append_conjunction(
            participant_presence_wires[participant_position],
            all_scores_valid_wire,
        )?;
        let absent_presence_wire =
            builder.append_negation(participant_presence_wires[participant_position])?;
        let valid_absent_wire =
            builder.append_conjunction(absent_presence_wire, absent_scores_are_zero_wire)?;
        participant_validity_wires
            .push(builder.append_exclusive_or(valid_present_wire, valid_absent_wire)?);
    }

    let mut aggregate_score_wires = Vec::with_capacity(option_count);
    for option_position in 0..option_count {
        let participant_numbers = (0..participant_count)
            .map(|participant_position| {
                presence_gated_score_wires[participant_position][option_position].as_slice()
            })
            .collect::<Vec<_>>();
        aggregate_score_wires.push(carry_save_sum(
            &mut builder,
            &participant_numbers,
            aggregate_score_bit_width,
        )?);
    }

    let mut ordered_items = Vec::with_capacity(option_count);
    for (option_position, aggregate_wires) in aggregate_score_wires.into_iter().enumerate() {
        let mut item_wires = aggregate_wires;
        for bit_position in 0..option_position_bit_width {
            let bit_is_set = ((option_position >> bit_position) & 1) == 1;
            item_wires.push(builder.append_constant(bit_is_set)?);
        }
        ordered_items.push(item_wires);
    }

    // This stable partial bubble network uses a strict comparison. Equal
    // totals therefore retain the canonical lower option position first.
    for output_position in 0..top_count {
        for right_position in (output_position + 1..option_count).rev() {
            let left_item = &ordered_items[right_position - 1];
            let right_item = &ordered_items[right_position];
            let swap_selector = greater_than_unsigned(
                &mut builder,
                &right_item[..aggregate_score_bit_width],
                &left_item[..aggregate_score_bit_width],
            )?;
            let (swapped_left_item, swapped_right_item) =
                conditional_swap(&mut builder, swap_selector, left_item, right_item)?;
            ordered_items[right_position - 1] = swapped_left_item;
            ordered_items[right_position] = swapped_right_item;
        }
    }

    let ordered_option_position_wires = ordered_items
        .into_iter()
        .take(top_count)
        .map(|item_wires| item_wires[aggregate_score_bit_width..].to_vec())
        .collect::<Vec<_>>();
    let geometry = builder.geometry(
        score_bit_width,
        aggregate_score_bit_width,
        option_position_bit_width,
        participant_validity_wires.len(),
        top_count
            .checked_mul(option_position_bit_width)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?,
    )?;

    Ok(CompiledTallyCircuit {
        profile,
        geometry,
        operations: builder.operations,
        participant_validity_wires,
        ordered_option_position_wires,
    })
}

fn derive_score_input_wires(
    participant_count: usize,
    option_count: usize,
    score_bit_width: usize,
) -> Result<Vec<Vec<Vec<WireIndex>>>, TallyCircuitError> {
    let mut next_wire = participant_count;
    let mut participant_score_wires = Vec::with_capacity(participant_count);
    for _participant_position in 0..participant_count {
        let mut option_score_wires = Vec::with_capacity(option_count);
        for _option_position in 0..option_count {
            let end_wire = next_wire
                .checked_add(score_bit_width)
                .ok_or(TallyCircuitError::ArithmeticOverflow)?;
            option_score_wires.push(
                (next_wire..end_wire)
                    .map(wire_index_from_usize)
                    .collect::<Result<Vec<_>, _>>()?,
            );
            next_wire = end_wire;
        }
        participant_score_wires.push(option_score_wires);
    }
    Ok(participant_score_wires)
}

fn score_is_valid(
    builder: &mut BooleanCircuitBuilder,
    score_wires: &[WireIndex],
) -> Result<WireIndex, TallyCircuitError> {
    if score_wires.len() != 4 {
        return Err(TallyCircuitError::UnsupportedFoundationScoreRange {
            minimum_score: crate::foundation::FOUNDATION_PROFILE.minimum_score,
            maximum_score: crate::foundation::FOUNDATION_PROFILE.maximum_score,
        });
    }

    let least_significant_bit = score_wires[0];
    let second_bit = score_wires[1];
    let third_bit = score_wires[2];
    let most_significant_bit = score_wires[3];

    let low_bits_nonzero = builder.append_disjunction(least_significant_bit, second_bit)?;
    let high_bits_nonzero = builder.append_disjunction(third_bit, most_significant_bit)?;
    let score_is_nonzero = builder.append_disjunction(low_bits_nonzero, high_bits_nonzero)?;
    let two_low_bits_set = builder.append_conjunction(second_bit, least_significant_bit)?;
    let value_above_ten_tail = builder.append_disjunction(third_bit, two_low_bits_set)?;
    let value_is_above_ten =
        builder.append_conjunction(most_significant_bit, value_above_ten_tail)?;
    let value_is_at_most_ten = builder.append_negation(value_is_above_ten)?;
    builder.append_conjunction(score_is_nonzero, value_is_at_most_ten)
}

fn all_zero(
    builder: &mut BooleanCircuitBuilder,
    wires: &[WireIndex],
) -> Result<WireIndex, TallyCircuitError> {
    let mut all_zero_wire = builder.append_constant(true)?;
    for wire in wires {
        let negated_wire = builder.append_negation(*wire)?;
        all_zero_wire = builder.append_conjunction(all_zero_wire, negated_wire)?;
    }
    Ok(all_zero_wire)
}

fn full_adder(
    builder: &mut BooleanCircuitBuilder,
    left_wire: WireIndex,
    right_wire: WireIndex,
    carry_input_wire: WireIndex,
) -> Result<(WireIndex, WireIndex), TallyCircuitError> {
    let left_exclusive_or_right = builder.append_exclusive_or(left_wire, right_wire)?;
    let sum_wire = builder.append_exclusive_or(left_exclusive_or_right, carry_input_wire)?;
    let first_carry_wire = builder.append_conjunction(left_wire, right_wire)?;
    let second_carry_wire =
        builder.append_conjunction(left_exclusive_or_right, carry_input_wire)?;
    let carry_output_wire = builder.append_exclusive_or(first_carry_wire, second_carry_wire)?;
    Ok((sum_wire, carry_output_wire))
}

fn add_fixed_width(
    builder: &mut BooleanCircuitBuilder,
    left_wires: &[WireIndex],
    right_wires: &[WireIndex],
    width: usize,
) -> Result<Vec<WireIndex>, TallyCircuitError> {
    let zero_wire = builder.append_constant(false)?;
    let mut carry_wire = zero_wire;
    let mut output_wires = Vec::with_capacity(width);
    for bit_position in 0..width {
        let left_wire = left_wires.get(bit_position).copied().unwrap_or(zero_wire);
        let right_wire = right_wires.get(bit_position).copied().unwrap_or(zero_wire);
        let (sum_wire, next_carry_wire) = full_adder(builder, left_wire, right_wire, carry_wire)?;
        output_wires.push(sum_wire);
        carry_wire = next_carry_wire;
    }
    Ok(output_wires)
}

fn carry_save_sum(
    builder: &mut BooleanCircuitBuilder,
    numbers: &[&[WireIndex]],
    width: usize,
) -> Result<Vec<WireIndex>, TallyCircuitError> {
    let column_count = width
        .checked_add(3)
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    let mut columns = vec![Vec::new(); column_count];
    let zero_wire = builder.append_constant(false)?;

    for number_wires in numbers {
        for (bit_position, wire) in number_wires.iter().copied().enumerate() {
            if bit_position < width {
                columns[bit_position].push(wire);
            }
        }
    }

    for bit_position in 0..width {
        while columns[bit_position].len() > 2 {
            let first_wire = columns[bit_position]
                .pop()
                .ok_or(TallyCircuitError::ArithmeticOverflow)?;
            let second_wire = columns[bit_position]
                .pop()
                .ok_or(TallyCircuitError::ArithmeticOverflow)?;
            let third_wire = columns[bit_position]
                .pop()
                .ok_or(TallyCircuitError::ArithmeticOverflow)?;
            let (sum_wire, carry_wire) = full_adder(builder, first_wire, second_wire, third_wire)?;
            columns[bit_position].push(sum_wire);
            columns[bit_position + 1].push(carry_wire);
        }
    }

    let first_row = (0..width)
        .map(|bit_position| columns[bit_position].first().copied().unwrap_or(zero_wire))
        .collect::<Vec<_>>();
    let second_row = (0..width)
        .map(|bit_position| columns[bit_position].get(1).copied().unwrap_or(zero_wire))
        .collect::<Vec<_>>();
    add_fixed_width(builder, &first_row, &second_row, width)
}

fn greater_than_unsigned(
    builder: &mut BooleanCircuitBuilder,
    left_wires: &[WireIndex],
    right_wires: &[WireIndex],
) -> Result<WireIndex, TallyCircuitError> {
    let zero_wire = builder.append_constant(false)?;
    let mut borrow_wire = zero_wire;
    let width = left_wires.len().max(right_wires.len());

    for bit_position in 0..width {
        let left_wire = left_wires.get(bit_position).copied().unwrap_or(zero_wire);
        let right_wire = right_wires.get(bit_position).copied().unwrap_or(zero_wire);
        let negated_right_wire = builder.append_negation(right_wire)?;
        let first_term_wire = builder.append_conjunction(negated_right_wire, left_wire)?;
        let difference_wire = builder.append_exclusive_or(right_wire, left_wire)?;
        let equal_at_this_bit_wire = builder.append_negation(difference_wire)?;
        let second_term_wire = builder.append_conjunction(borrow_wire, equal_at_this_bit_wire)?;
        borrow_wire = builder.append_exclusive_or(first_term_wire, second_term_wire)?;
    }
    Ok(borrow_wire)
}

fn conditional_swap(
    builder: &mut BooleanCircuitBuilder,
    selector_wire: WireIndex,
    left_wires: &[WireIndex],
    right_wires: &[WireIndex],
) -> Result<(Vec<WireIndex>, Vec<WireIndex>), TallyCircuitError> {
    if left_wires.len() != right_wires.len() {
        return Err(TallyCircuitError::ArithmeticOverflow);
    }

    let mut swapped_left_wires = Vec::with_capacity(left_wires.len());
    let mut swapped_right_wires = Vec::with_capacity(right_wires.len());
    for (left_wire, right_wire) in left_wires.iter().copied().zip(right_wires.iter().copied()) {
        let difference_wire = builder.append_exclusive_or(left_wire, right_wire)?;
        let selected_difference_wire =
            builder.append_conjunction(selector_wire, difference_wire)?;
        swapped_left_wires.push(builder.append_exclusive_or(left_wire, selected_difference_wire)?);
        swapped_right_wires
            .push(builder.append_exclusive_or(right_wire, selected_difference_wire)?);
    }
    Ok((swapped_left_wires, swapped_right_wires))
}

fn wire_index_from_usize(value: usize) -> Result<WireIndex, TallyCircuitError> {
    WireIndex::try_from(value).map_err(|_| TallyCircuitError::WireIndexOverflow)
}

struct BooleanCircuitBuilder {
    input_bit_count: usize,
    operations: Vec<BooleanOperation>,
    false_constant_wire: Option<WireIndex>,
    true_constant_wire: Option<WireIndex>,
    constant_operation_count: usize,
    conjunction_gate_count: usize,
    exclusive_or_gate_count: usize,
    negation_gate_count: usize,
}

impl BooleanCircuitBuilder {
    fn new(input_bit_count: usize) -> Result<Self, TallyCircuitError> {
        wire_index_from_usize(input_bit_count)?;
        Ok(Self {
            input_bit_count,
            operations: Vec::new(),
            false_constant_wire: None,
            true_constant_wire: None,
            constant_operation_count: 0,
            conjunction_gate_count: 0,
            exclusive_or_gate_count: 0,
            negation_gate_count: 0,
        })
    }

    fn append_constant(&mut self, value: bool) -> Result<WireIndex, TallyCircuitError> {
        let existing_wire = if value {
            self.true_constant_wire
        } else {
            self.false_constant_wire
        };
        if let Some(existing_wire) = existing_wire {
            return Ok(existing_wire);
        }
        self.constant_operation_count = self
            .constant_operation_count
            .checked_add(1)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        let wire = self.append_operation(BooleanOperation::Constant(value))?;
        if value {
            self.true_constant_wire = Some(wire);
        } else {
            self.false_constant_wire = Some(wire);
        }
        Ok(wire)
    }

    fn append_exclusive_or(
        &mut self,
        left_wire: WireIndex,
        right_wire: WireIndex,
    ) -> Result<WireIndex, TallyCircuitError> {
        self.validate_input_wire(left_wire)?;
        self.validate_input_wire(right_wire)?;
        self.exclusive_or_gate_count = self
            .exclusive_or_gate_count
            .checked_add(1)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        self.append_operation(BooleanOperation::ExclusiveOr {
            left_wire,
            right_wire,
        })
    }

    fn append_conjunction(
        &mut self,
        left_wire: WireIndex,
        right_wire: WireIndex,
    ) -> Result<WireIndex, TallyCircuitError> {
        self.validate_input_wire(left_wire)?;
        self.validate_input_wire(right_wire)?;
        self.conjunction_gate_count = self
            .conjunction_gate_count
            .checked_add(1)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        self.append_operation(BooleanOperation::Conjunction {
            left_wire,
            right_wire,
        })
    }

    fn append_negation(&mut self, input_wire: WireIndex) -> Result<WireIndex, TallyCircuitError> {
        self.validate_input_wire(input_wire)?;
        self.negation_gate_count = self
            .negation_gate_count
            .checked_add(1)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        self.append_operation(BooleanOperation::Negation { input_wire })
    }

    fn append_disjunction(
        &mut self,
        left_wire: WireIndex,
        right_wire: WireIndex,
    ) -> Result<WireIndex, TallyCircuitError> {
        let exclusive_or_wire = self.append_exclusive_or(left_wire, right_wire)?;
        let conjunction_wire = self.append_conjunction(left_wire, right_wire)?;
        self.append_exclusive_or(exclusive_or_wire, conjunction_wire)
    }

    fn append_operation(
        &mut self,
        operation: BooleanOperation,
    ) -> Result<WireIndex, TallyCircuitError> {
        let output_wire = self.available_wire_count()?;
        let output_wire = wire_index_from_usize(output_wire)?;
        self.operations.push(operation);
        Ok(output_wire)
    }

    fn validate_input_wire(&self, wire: WireIndex) -> Result<(), TallyCircuitError> {
        let available_wire_count = self.available_wire_count()?;
        if usize::try_from(wire).map_or(true, |wire| wire >= available_wire_count) {
            return Err(TallyCircuitError::InvalidWireReference {
                wire,
                available_wire_count,
            });
        }
        Ok(())
    }

    fn available_wire_count(&self) -> Result<usize, TallyCircuitError> {
        self.input_bit_count
            .checked_add(self.operations.len())
            .ok_or(TallyCircuitError::ArithmeticOverflow)
    }

    fn geometry(
        &self,
        score_bit_width: usize,
        aggregate_score_bit_width: usize,
        option_position_bit_width: usize,
        participant_validity_bit_count: usize,
        result_bit_count: usize,
    ) -> Result<TallyCircuitGeometry, TallyCircuitError> {
        Ok(TallyCircuitGeometry {
            input_bit_count: self.input_bit_count,
            score_bit_width,
            aggregate_score_bit_width,
            option_position_bit_width,
            constant_operation_count: self.constant_operation_count,
            conjunction_gate_count: self.conjunction_gate_count,
            exclusive_or_gate_count: self.exclusive_or_gate_count,
            negation_gate_count: self.negation_gate_count,
            total_wire_count: self.available_wire_count()?,
            participant_validity_bit_count,
            result_bit_count,
        })
    }
}
