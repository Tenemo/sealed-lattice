use super::TallyPreparationError;

const MAXIMUM_WINDOW_WIDTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryLinearCircuitOperation {
    left_signal: usize,
    right_signal: usize,
}

/// Deterministic windowed circuit for a binary linear map.
///
/// Each window computes only the subset parities used by at least one target,
/// sharing those parities across all outputs. The compiler checks every window
/// width up to sixteen and retains the smallest exact circuit. This research
/// helper has no protocol authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CompiledBinaryLinearCircuit {
    input_count: usize,
    window_width: usize,
    operations: Vec<BinaryLinearCircuitOperation>,
    output_signals: Vec<Option<usize>>,
}

impl CompiledBinaryLinearCircuit {
    pub(super) fn compile_smallest_windowed(
        targets: &[Vec<bool>],
        input_count: usize,
    ) -> Result<Self, TallyPreparationError> {
        if input_count == 0 || targets.iter().any(|target| target.len() != input_count) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let maximum_window_width = MAXIMUM_WINDOW_WIDTH.min(input_count);
        let mut smallest_circuit = None::<Self>;
        for window_width in 1..=maximum_window_width {
            let candidate = Self::compile_with_window_width(targets, input_count, window_width)?;
            let should_replace = smallest_circuit.as_ref().is_none_or(|smallest| {
                candidate.operations.len() < smallest.operations.len()
                    || (candidate.operations.len() == smallest.operations.len()
                        && candidate.window_width < smallest.window_width)
            });
            if should_replace {
                smallest_circuit = Some(candidate);
            }
        }
        smallest_circuit.ok_or(TallyPreparationError::GeometryMismatch)
    }

    pub(super) fn operation_count(&self) -> u64 {
        self.operations.len() as u64
    }

    pub(super) fn window_width(&self) -> u64 {
        self.window_width as u64
    }

    pub(super) fn evaluate(
        &self,
        input_values: &[bool],
    ) -> Result<Vec<bool>, TallyPreparationError> {
        if input_values.len() != self.input_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let mut signal_values = Vec::with_capacity(self.input_count + self.operations.len());
        signal_values.extend_from_slice(input_values);
        for operation in &self.operations {
            let left = signal_values
                .get(operation.left_signal)
                .copied()
                .ok_or(TallyPreparationError::GeometryMismatch)?;
            let right = signal_values
                .get(operation.right_signal)
                .copied()
                .ok_or(TallyPreparationError::GeometryMismatch)?;
            signal_values.push(left ^ right);
        }
        self.output_signals
            .iter()
            .map(|output_signal| {
                output_signal.map_or(Ok(false), |signal| {
                    signal_values
                        .get(signal)
                        .copied()
                        .ok_or(TallyPreparationError::GeometryMismatch)
                })
            })
            .collect()
    }

    fn compile_with_window_width(
        targets: &[Vec<bool>],
        input_count: usize,
        window_width: usize,
    ) -> Result<Self, TallyPreparationError> {
        if window_width == 0 || window_width > MAXIMUM_WINDOW_WIDTH {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let mut operations = Vec::new();
        let mut output_terms = vec![Vec::<usize>::new(); targets.len()];
        for window_start in (0..input_count).step_by(window_width) {
            let current_window_width = window_width.min(input_count - window_start);
            let subset_count = 1_usize
                .checked_shl(
                    u32::try_from(current_window_width)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                )
                .ok_or(TallyPreparationError::ArithmeticOverflow)?;
            let target_subsets = targets
                .iter()
                .map(|target| target_subset(target, window_start, current_window_width))
                .collect::<Vec<_>>();
            let mut required_subsets = vec![false; subset_count];
            for mut subset in target_subsets.iter().copied() {
                while subset.count_ones() > 1 {
                    required_subsets[subset] = true;
                    subset &= subset - 1;
                }
            }
            let mut subset_signals = vec![None::<usize>; subset_count];
            for local_input_position in 0..current_window_width {
                subset_signals[1_usize << local_input_position] =
                    Some(window_start + local_input_position);
            }
            for subset in 1..subset_count {
                if !required_subsets[subset] || subset.count_ones() <= 1 {
                    continue;
                }
                let lowest_bit_position = subset.trailing_zeros() as usize;
                let remainder = subset & (subset - 1);
                let right_signal =
                    subset_signals[remainder].ok_or(TallyPreparationError::GeometryMismatch)?;
                let output_signal = input_count
                    .checked_add(operations.len())
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?;
                operations.push(BinaryLinearCircuitOperation {
                    left_signal: window_start + lowest_bit_position,
                    right_signal,
                });
                subset_signals[subset] = Some(output_signal);
            }
            for (output_position, subset) in target_subsets.iter().copied().enumerate() {
                if subset == 0 {
                    continue;
                }
                output_terms[output_position]
                    .push(subset_signals[subset].ok_or(TallyPreparationError::GeometryMismatch)?);
            }
        }

        let mut output_signals = Vec::with_capacity(targets.len());
        for terms in output_terms {
            let mut terms = terms.into_iter();
            let Some(mut accumulated_signal) = terms.next() else {
                output_signals.push(None);
                continue;
            };
            for term_signal in terms {
                let output_signal = input_count
                    .checked_add(operations.len())
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?;
                operations.push(BinaryLinearCircuitOperation {
                    left_signal: accumulated_signal,
                    right_signal: term_signal,
                });
                accumulated_signal = output_signal;
            }
            output_signals.push(Some(accumulated_signal));
        }

        Ok(Self {
            input_count,
            window_width,
            operations,
            output_signals,
        })
    }
}

fn target_subset(target: &[bool], window_start: usize, window_width: usize) -> usize {
    target[window_start..window_start + window_width]
        .iter()
        .copied()
        .enumerate()
        .fold(0_usize, |subset, (local_position, selected)| {
            subset | (usize::from(selected) << local_position)
        })
}
