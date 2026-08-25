use super::{BinaryFieldElement256, TallyPreparationError};

const FIELD_BIT_LENGTH: usize = BinaryFieldElement256::CANONICAL_BYTE_LENGTH * u8::BITS as usize;
const INPUT_WIRE_COUNT: usize = FIELD_BIT_LENGTH * 2;
const REDUCTION_EXPONENTS: [usize; 4] = [0, 2, 5, 10];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryFieldMultiplicationOperation {
    ExclusiveOr { left_wire: usize, right_wire: usize },
    Conjunction { left_wire: usize, right_wire: usize },
}

/// Executable binary circuit for the kernel's canonical `GF(2^256)` product.
///
/// Polynomial multiplication uses an eight-level Karatsuba recursion. Reduction
/// by `X^256 + X^10 + X^5 + X^2 + 1` is linear and therefore adds no
/// conjunctions. This is a research comparison owner, not the selected runtime
/// field implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledBinaryFieldMultiplicationCircuit {
    constant_zero_wire: usize,
    operations: Vec<BinaryFieldMultiplicationOperation>,
    output_wires: [usize; FIELD_BIT_LENGTH],
    conjunction_count: u64,
    exclusive_or_count: u64,
}

impl CompiledBinaryFieldMultiplicationCircuit {
    pub(crate) fn compile() -> Result<Self, TallyPreparationError> {
        let constant_zero_wire = INPUT_WIRE_COUNT;
        let mut compiler = BinaryFieldMultiplicationCompiler {
            constant_zero_wire,
            next_wire: constant_zero_wire + 1,
            operations: Vec::new(),
            conjunction_count: 0,
            exclusive_or_count: 0,
        };
        let left_input_wires = (0..FIELD_BIT_LENGTH).collect::<Vec<_>>();
        let right_input_wires = (FIELD_BIT_LENGTH..INPUT_WIRE_COUNT).collect::<Vec<_>>();
        let mut product_wires =
            compile_karatsuba_product(&mut compiler, &left_input_wires, &right_input_wires)?;
        if product_wires.len() != FIELD_BIT_LENGTH * 2 - 1 {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        for product_exponent in (FIELD_BIT_LENGTH..product_wires.len()).rev() {
            let coefficient_wire = product_wires[product_exponent];
            let reduction_base_exponent = product_exponent - FIELD_BIT_LENGTH;
            for reduction_exponent in REDUCTION_EXPONENTS {
                let output_exponent = reduction_base_exponent + reduction_exponent;
                product_wires[output_exponent] =
                    compiler.exclusive_or(product_wires[output_exponent], coefficient_wire)?;
            }
        }

        let output_wires = product_wires[..FIELD_BIT_LENGTH]
            .try_into()
            .map_err(|_| TallyPreparationError::GeometryMismatch)?;
        let expected_conjunction_count = karatsuba_conjunction_count()?;
        if compiler.conjunction_count != expected_conjunction_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        Ok(Self {
            constant_zero_wire,
            operations: compiler.operations,
            output_wires,
            conjunction_count: compiler.conjunction_count,
            exclusive_or_count: compiler.exclusive_or_count,
        })
    }

    pub(crate) fn conjunction_count(&self) -> u64 {
        self.conjunction_count
    }

    pub(crate) fn exclusive_or_count(&self) -> u64 {
        self.exclusive_or_count
    }

    pub(crate) fn multiply(
        &self,
        left: BinaryFieldElement256,
        right: BinaryFieldElement256,
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        let mut wire_values =
            Vec::with_capacity(self.constant_zero_wire + 1 + self.operations.len());
        append_canonical_bits(&mut wire_values, left.canonical_bytes());
        append_canonical_bits(&mut wire_values, right.canonical_bytes());
        if wire_values.len() != self.constant_zero_wire {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        wire_values.push(false);

        for operation in &self.operations {
            let output = match *operation {
                BinaryFieldMultiplicationOperation::ExclusiveOr {
                    left_wire,
                    right_wire,
                } => wire_value(&wire_values, left_wire)? ^ wire_value(&wire_values, right_wire)?,
                BinaryFieldMultiplicationOperation::Conjunction {
                    left_wire,
                    right_wire,
                } => wire_value(&wire_values, left_wire)? & wire_value(&wire_values, right_wire)?,
            };
            wire_values.push(output);
        }

        let mut output_bytes = [0_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
        for (output_bit_position, output_wire) in self.output_wires.iter().copied().enumerate() {
            if wire_value(&wire_values, output_wire)? {
                output_bytes[output_bit_position / u8::BITS as usize] |=
                    1_u8 << (output_bit_position % u8::BITS as usize);
            }
        }
        BinaryFieldElement256::from_canonical_bytes(&output_bytes)
    }
}

pub(crate) fn karatsuba_conjunction_count() -> Result<u64, TallyPreparationError> {
    karatsuba_conjunction_count_for_bit_length(FIELD_BIT_LENGTH)
}

fn compile_karatsuba_product(
    compiler: &mut BinaryFieldMultiplicationCompiler,
    left_wires: &[usize],
    right_wires: &[usize],
) -> Result<Vec<usize>, TallyPreparationError> {
    if left_wires.len() != right_wires.len()
        || left_wires.is_empty()
        || !left_wires.len().is_power_of_two()
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    if left_wires.len() == 1 {
        return Ok(vec![compiler.conjunction(left_wires[0], right_wires[0])?]);
    }

    let half_length = left_wires.len() / 2;
    let left_low_wires = &left_wires[..half_length];
    let left_high_wires = &left_wires[half_length..];
    let right_low_wires = &right_wires[..half_length];
    let right_high_wires = &right_wires[half_length..];

    let low_product = compile_karatsuba_product(compiler, left_low_wires, right_low_wires)?;
    let high_product = compile_karatsuba_product(compiler, left_high_wires, right_high_wires)?;
    let left_sum = compile_polynomial_sum(compiler, left_low_wires, left_high_wires)?;
    let right_sum = compile_polynomial_sum(compiler, right_low_wires, right_high_wires)?;
    let mixed_product = compile_karatsuba_product(compiler, &left_sum, &right_sum)?;

    let mut product = vec![compiler.constant_zero_wire; left_wires.len() * 2 - 1];
    product[..low_product.len()].copy_from_slice(&low_product);
    let high_product_offset = half_length * 2;
    product[high_product_offset..high_product_offset + high_product.len()]
        .copy_from_slice(&high_product);

    for (mixed_position, mixed_wire) in mixed_product.iter().copied().enumerate() {
        let low_component = low_product
            .get(mixed_position)
            .copied()
            .unwrap_or(compiler.constant_zero_wire);
        let high_component = high_product
            .get(mixed_position)
            .copied()
            .unwrap_or(compiler.constant_zero_wire);
        let middle_without_low = compiler.exclusive_or(mixed_wire, low_component)?;
        let middle_component = compiler.exclusive_or(middle_without_low, high_component)?;
        let output_position = half_length + mixed_position;
        product[output_position] =
            compiler.exclusive_or(product[output_position], middle_component)?;
    }

    Ok(product)
}

fn compile_polynomial_sum(
    compiler: &mut BinaryFieldMultiplicationCompiler,
    left_wires: &[usize],
    right_wires: &[usize],
) -> Result<Vec<usize>, TallyPreparationError> {
    if left_wires.len() != right_wires.len() {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    left_wires
        .iter()
        .copied()
        .zip(right_wires.iter().copied())
        .map(|(left_wire, right_wire)| compiler.exclusive_or(left_wire, right_wire))
        .collect()
}

struct BinaryFieldMultiplicationCompiler {
    constant_zero_wire: usize,
    next_wire: usize,
    operations: Vec<BinaryFieldMultiplicationOperation>,
    conjunction_count: u64,
    exclusive_or_count: u64,
}

impl BinaryFieldMultiplicationCompiler {
    fn conjunction(
        &mut self,
        left_wire: usize,
        right_wire: usize,
    ) -> Result<usize, TallyPreparationError> {
        let output_wire = self.append(BinaryFieldMultiplicationOperation::Conjunction {
            left_wire,
            right_wire,
        })?;
        self.conjunction_count = checked_add(self.conjunction_count, 1)?;
        Ok(output_wire)
    }

    fn exclusive_or(
        &mut self,
        left_wire: usize,
        right_wire: usize,
    ) -> Result<usize, TallyPreparationError> {
        if left_wire == self.constant_zero_wire {
            return Ok(right_wire);
        }
        if right_wire == self.constant_zero_wire {
            return Ok(left_wire);
        }
        if left_wire == right_wire {
            return Ok(self.constant_zero_wire);
        }
        let output_wire = self.append(BinaryFieldMultiplicationOperation::ExclusiveOr {
            left_wire,
            right_wire,
        })?;
        self.exclusive_or_count = checked_add(self.exclusive_or_count, 1)?;
        Ok(output_wire)
    }

    fn append(
        &mut self,
        operation: BinaryFieldMultiplicationOperation,
    ) -> Result<usize, TallyPreparationError> {
        let output_wire = self.next_wire;
        self.next_wire = self
            .next_wire
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        self.operations.push(operation);
        Ok(output_wire)
    }
}

fn karatsuba_conjunction_count_for_bit_length(
    bit_length: usize,
) -> Result<u64, TallyPreparationError> {
    if bit_length == 0 || !bit_length.is_power_of_two() {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    if bit_length == 1 {
        return Ok(1);
    }
    checked_multiply(
        karatsuba_conjunction_count_for_bit_length(bit_length / 2)?,
        3,
    )
}

fn append_canonical_bits(wire_values: &mut Vec<bool>, canonical_bytes: [u8; 32]) {
    for bit_position in 0..FIELD_BIT_LENGTH {
        wire_values.push(
            (canonical_bytes[bit_position / u8::BITS as usize]
                >> (bit_position % u8::BITS as usize))
                & 1
                == 1,
        );
    }
}

fn wire_value(wire_values: &[bool], wire: usize) -> Result<bool, TallyPreparationError> {
    wire_values
        .get(wire)
        .copied()
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
