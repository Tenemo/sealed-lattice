use super::*;
use crate::bgv::{
    modular_arithmetic::{inverse_mod, pow_mod},
    profile::{POLYNOMIAL_DEGREE, root_parameters_for_modulus},
};

// Cyclic NTT plan for one power-of-two transform length over one profile
// prime. Stage s (block length 2^(s+1)) stores the powers of the stage root
// root^(length / 2^(s+1)) up to half the block length, in natural order.
struct CyclicTransformPlan {
    modulus: u64,
    length: usize,
    forward_stage_twiddles: Vec<Vec<u64>>,
    inverse_stage_twiddles: Vec<Vec<u64>>,
    inverse_length: u64,
}

// Domain plan for one limb field: the order-m trace subgroup H = <trace_root>
// and the rate-1/2 extension coset offset * <extension_root> of size 2m.
pub(super) struct EvaluationDomainPlan {
    pub(super) modulus: u64,
    pub(super) trace_size: usize,
    pub(super) extension_size: usize,
    pub(super) trace_root: u64,
    pub(super) extension_root: u64,
    pub(super) coset_offset: u64,
    trace_plan: CyclicTransformPlan,
    extension_plan: CyclicTransformPlan,
}

fn bit_reverse(value: usize, bit_count: u32) -> usize {
    let mut reversed = 0_usize;
    let mut remaining = value;
    for _ in 0..bit_count {
        reversed = (reversed << 1) | (remaining & 1);
        remaining >>= 1;
    }

    reversed
}

fn build_cyclic_transform_plan(
    length: usize,
    root: u64,
    modulus: u64,
) -> CanonicalResult<CyclicTransformPlan> {
    if !length.is_power_of_two() || length < 2 {
        return Err(invalid_succinct_setup_proof(
            "cyclic transform length must be a power of two of at least two",
        ));
    }
    if pow_mod(root, length as u64, modulus)? != 1
        || pow_mod(root, (length / 2) as u64, modulus)? == 1
    {
        return Err(invalid_succinct_setup_proof(
            "cyclic transform root does not have the requested order",
        ));
    }

    Ok(CyclicTransformPlan {
        modulus,
        length,
        forward_stage_twiddles: stage_twiddle_tables(length, root, modulus)?,
        inverse_stage_twiddles: stage_twiddle_tables(length, inverse_mod(root, modulus)?, modulus)?,
        inverse_length: inverse_mod(length as u64, modulus)?,
    })
}

fn stage_twiddle_tables(length: usize, root: u64, modulus: u64) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut tables = Vec::new();
    let mut block_length = 2_usize;
    while block_length <= length {
        let stage_root = pow_mod(root, (length / block_length) as u64, modulus)?;
        let mut table = Vec::with_capacity(block_length / 2);
        let mut power = 1_u64;
        for _ in 0..block_length / 2 {
            table.push(power);
            power = mul_mod_fast(power, stage_root, modulus);
        }
        tables.push(table);
        block_length <<= 1;
    }

    Ok(tables)
}

// In-place decimation-in-time cyclic NTT: bit-reverse the input, then run
// per-stage butterflies with the precomputed natural-order twiddle tables.
fn cyclic_transform_in_place(values: &mut [u64], plan: &CyclicTransformPlan, inverse: bool) {
    let length = plan.length;
    debug_assert_eq!(values.len(), length);
    let bit_count = length.trailing_zeros();
    for index in 0..length {
        let swapped = bit_reverse(index, bit_count);
        if swapped > index {
            values.swap(index, swapped);
        }
    }
    let stage_tables = if inverse {
        &plan.inverse_stage_twiddles
    } else {
        &plan.forward_stage_twiddles
    };
    let modulus = plan.modulus;
    for (stage, table) in stage_tables.iter().enumerate() {
        let block_length = 2_usize << stage;
        let half = block_length / 2;
        let mut block_start = 0_usize;
        while block_start < length {
            for (offset, twiddle) in table.iter().enumerate() {
                let position = block_start + offset;
                let upper = values[position];
                let lower = mul_mod_fast(values[position + half], *twiddle, modulus);
                values[position] = add_mod_fast(upper, lower, modulus);
                values[position + half] = sub_mod_fast(upper, lower, modulus);
            }
            block_start += block_length;
        }
    }
    if inverse {
        for value in values.iter_mut() {
            *value = mul_mod_fast(*value, plan.inverse_length, modulus);
        }
    }
}

impl EvaluationDomainPlan {
    pub(super) fn new(modulus: u64, trace_size: usize) -> CanonicalResult<Self> {
        if !trace_size.is_power_of_two()
            || !(MINIMUM_TRACE_SIZE..=POLYNOMIAL_DEGREE).contains(&trace_size)
        {
            return Err(invalid_succinct_setup_proof(
                "trace size must be a power of two between the minimum and the ring degree",
            ));
        }
        let root_parameters = root_parameters_for_modulus(modulus).ok_or_else(|| {
            invalid_succinct_setup_proof("modulus is not part of the selected BGV-RNS profile")
        })?;
        let extension_size = trace_size * DOMAIN_BLOWUP;
        let full_order = 2 * POLYNOMIAL_DEGREE;
        if !full_order.is_multiple_of(extension_size) {
            return Err(invalid_succinct_setup_proof(
                "extension size exceeds the guaranteed two-adicity of the profile primes",
            ));
        }
        // The negacyclic root has exact order 2 * POLYNOMIAL_DEGREE = 2^16, so
        // raising it to full_order / size yields a root of exact order size.
        let extension_root = pow_mod(
            root_parameters.negacyclic_root,
            (full_order / extension_size) as u64,
            modulus,
        )?;
        let trace_root = pow_mod(extension_root, DOMAIN_BLOWUP as u64, modulus)?;
        let coset_offset = root_parameters.primitive_generator;

        Ok(Self {
            modulus,
            trace_size,
            extension_size,
            trace_root,
            extension_root,
            coset_offset,
            trace_plan: build_cyclic_transform_plan(trace_size, trace_root, modulus)?,
            extension_plan: build_cyclic_transform_plan(extension_size, extension_root, modulus)?,
        })
    }

    // Interpolate trace values indexed by H into coefficient form.
    pub(super) fn coefficients_from_trace_values(&self, trace_values: &[u64]) -> Vec<u64> {
        debug_assert_eq!(trace_values.len(), self.trace_size);
        let mut coefficients = trace_values.to_vec();
        cyclic_transform_in_place(&mut coefficients, &self.trace_plan, true);

        coefficients
    }

    // Evaluate a coefficient vector of length at most the extension size over
    // the extension coset offset * <extension_root>.
    pub(super) fn extension_evaluations_from_coefficients(&self, coefficients: &[u64]) -> Vec<u64> {
        debug_assert!(coefficients.len() <= self.extension_size);
        let mut padded = vec![0_u64; self.extension_size];
        let mut offset_power = 1_u64;
        for (index, coefficient) in coefficients.iter().enumerate() {
            padded[index] = mul_mod_fast(*coefficient, offset_power, self.modulus);
            offset_power = mul_mod_fast(offset_power, self.coset_offset, self.modulus);
        }
        cyclic_transform_in_place(&mut padded, &self.extension_plan, false);

        padded
    }

    // Interpolate extension-coset evaluations back into coefficient form.
    pub(super) fn coefficients_from_extension_evaluations(
        &self,
        evaluations: &[u64],
    ) -> CanonicalResult<Vec<u64>> {
        debug_assert_eq!(evaluations.len(), self.extension_size);
        let mut coefficients = evaluations.to_vec();
        cyclic_transform_in_place(&mut coefficients, &self.extension_plan, true);
        let offset_inverse = inverse_mod(self.coset_offset, self.modulus)?;
        let mut offset_power = 1_u64;
        for coefficient in coefficients.iter_mut() {
            *coefficient = mul_mod_fast(*coefficient, offset_power, self.modulus);
            offset_power = mul_mod_fast(offset_power, offset_inverse, self.modulus);
        }

        Ok(coefficients)
    }

    // The extension-coset point at one position.
    pub(super) fn extension_point(&self, position: usize) -> u64 {
        mul_mod_fast(
            self.coset_offset,
            pow_mod(self.extension_root, position as u64, self.modulus)
                .expect("extension root power is a canonical residue"),
            self.modulus,
        )
    }

    // Barycentric evaluation of the interpolant of trace values at one point
    // outside H: F(z) = (z^m - 1) / m * sum_i values_i * omega^i / (z - omega^i).
}

// Montgomery batch inversion; fails on a zero element.
pub(super) fn batch_inverse(values: &[u64], modulus: u64) -> CanonicalResult<Vec<u64>> {
    let mut prefix_products = Vec::with_capacity(values.len());
    let mut running = 1_u64;
    for value in values {
        if *value == 0 {
            return Err(invalid_succinct_setup_proof(
                "batch inversion input contains zero",
            ));
        }
        running = mul_mod_fast(running, *value, modulus);
        prefix_products.push(running);
    }
    let mut inverted = vec![0_u64; values.len()];
    let mut suffix_inverse = inverse_mod(running, modulus)?;
    for index in (0..values.len()).rev() {
        let prefix = if index == 0 {
            1
        } else {
            prefix_products[index - 1]
        };
        inverted[index] = mul_mod_fast(suffix_inverse, prefix, modulus);
        suffix_inverse = mul_mod_fast(suffix_inverse, values[index], modulus);
    }

    Ok(inverted)
}

// Negacyclic product in Z_q[Y] / (Y^d + 1) via the psi-weighted cyclic NTT.
// The degree d must be a power of two with 2d dividing 2 * POLYNOMIAL_DEGREE.
pub(super) fn negacyclic_ring_product(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let degree = left.len();
    if right.len() != degree || !degree.is_power_of_two() || degree < 2 {
        return Err(invalid_succinct_setup_proof(
            "negacyclic product requires equal power-of-two lengths",
        ));
    }
    let root_parameters = root_parameters_for_modulus(modulus).ok_or_else(|| {
        invalid_succinct_setup_proof("modulus is not part of the selected BGV-RNS profile")
    })?;
    let full_order = 2 * POLYNOMIAL_DEGREE;
    if !full_order.is_multiple_of(2 * degree) {
        return Err(invalid_succinct_setup_proof(
            "negacyclic product degree exceeds the profile two-adicity",
        ));
    }
    let psi = pow_mod(
        root_parameters.negacyclic_root,
        (full_order / (2 * degree)) as u64,
        modulus,
    )?;
    let omega = mul_mod_fast(psi, psi, modulus);
    let plan = build_cyclic_transform_plan(degree, omega, modulus)?;
    let weight = |values: &[u64]| -> Vec<u64> {
        let mut weighted = Vec::with_capacity(degree);
        let mut psi_power = 1_u64;
        for value in values {
            weighted.push(mul_mod_fast(*value, psi_power, modulus));
            psi_power = mul_mod_fast(psi_power, psi, modulus);
        }
        weighted
    };
    let mut left_weighted = weight(left);
    let mut right_weighted = weight(right);
    cyclic_transform_in_place(&mut left_weighted, &plan, false);
    cyclic_transform_in_place(&mut right_weighted, &plan, false);
    for (left_value, right_value) in left_weighted.iter_mut().zip(right_weighted.iter()) {
        *left_value = mul_mod_fast(*left_value, *right_value, modulus);
    }
    cyclic_transform_in_place(&mut left_weighted, &plan, true);
    let psi_inverse = inverse_mod(psi, modulus)?;
    let mut psi_inverse_power = 1_u64;
    for value in left_weighted.iter_mut() {
        *value = mul_mod_fast(*value, psi_inverse_power, modulus);
        psi_inverse_power = mul_mod_fast(psi_inverse_power, psi_inverse, modulus);
    }

    Ok(left_weighted)
}

// Transpose negacyclic-matrix action: Neg(a)^T u = 2 a_0 u - rev(a) (*) u in
// the negacyclic ring, where rev(a)_0 = a_0 and rev(a)_k = a_{d-k}.
pub(super) fn negacyclic_transpose_product(
    coefficients: &[u64],
    vector: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let degree = coefficients.len();
    if vector.len() != degree {
        return Err(invalid_succinct_setup_proof(
            "transpose product requires equal lengths",
        ));
    }
    let mut reversed = vec![0_u64; degree];
    reversed[0] = coefficients[0];
    for index in 1..degree {
        reversed[index] = coefficients[degree - index];
    }
    let product = negacyclic_ring_product(&reversed, vector, modulus)?;
    let double_constant = add_mod_fast(coefficients[0], coefficients[0], modulus);
    let mut transposed = Vec::with_capacity(degree);
    for (vector_value, product_value) in vector.iter().zip(product.iter()) {
        let doubled = mul_mod_fast(double_constant, *vector_value, modulus);
        transposed.push(sub_mod_fast(doubled, *product_value, modulus));
    }

    Ok(transposed)
}
