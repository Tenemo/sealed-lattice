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

// Domain plan for one limb field: trace values over H and the extension coset
// offset * <extension_root>.
pub(in crate::bgv) struct EvaluationDomainPlan {
    pub(in crate::bgv) modulus: u64,
    pub(in crate::bgv) trace_size: usize,
    pub(in crate::bgv) extension_size: usize,
    pub(in crate::bgv) extension_root: u64,
    pub(in crate::bgv) coset_offset: u64,
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
        return Err(invalid_polynomial_iop(
            "cyclic transform length must be a power of two of at least two",
        ));
    }
    if pow_mod(root, length as u64, modulus)? != 1
        || pow_mod(root, (length / 2) as u64, modulus)? == 1
    {
        return Err(invalid_polynomial_iop(
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
    pub(in crate::bgv) fn new(modulus: u64, trace_size: usize) -> CanonicalResult<Self> {
        if !trace_size.is_power_of_two()
            || !(MINIMUM_TRACE_SIZE..=POLYNOMIAL_DEGREE).contains(&trace_size)
        {
            return Err(invalid_polynomial_iop(
                "trace size must be a power of two between the minimum and the ring degree",
            ));
        }
        let root_parameters = root_parameters_for_modulus(modulus).ok_or_else(|| {
            invalid_polynomial_iop("modulus is not part of the selected BGV-RNS profile")
        })?;
        let extension_size = trace_size * DOMAIN_BLOWUP;
        let full_order = 2 * POLYNOMIAL_DEGREE;
        if !full_order.is_multiple_of(extension_size) {
            return Err(invalid_polynomial_iop(
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
        // Coset disjointness from H requires the offset to generate all of
        // F_p^* (order p-1), not just any unit; the profile's
        // primitive_generator is a full generator, so the coset stays outside
        // every 2-power subgroup and thus off H.
        let coset_offset = root_parameters.primitive_generator;

        Ok(Self {
            modulus,
            trace_size,
            extension_size,
            extension_root,
            coset_offset,
            trace_plan: build_cyclic_transform_plan(trace_size, trace_root, modulus)?,
            extension_plan: build_cyclic_transform_plan(extension_size, extension_root, modulus)?,
        })
    }

    // Interpolate trace values indexed by H into coefficient form.
    pub(in crate::bgv) fn coefficients_from_trace_values(&self, trace_values: &[u64]) -> Vec<u64> {
        debug_assert_eq!(trace_values.len(), self.trace_size);
        let mut coefficients = trace_values.to_vec();
        cyclic_transform_in_place(&mut coefficients, &self.trace_plan, true);

        coefficients
    }

    // Evaluate a coefficient vector of length at most the extension size over
    // the extension coset offset * <extension_root>.
    pub(in crate::bgv) fn extension_evaluations_from_coefficients(
        &self,
        coefficients: &[u64],
    ) -> Vec<u64> {
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
    pub(in crate::bgv) fn coefficients_from_extension_evaluations(
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
    pub(in crate::bgv) fn extension_point(&self, position: usize) -> u64 {
        mul_mod_fast(
            self.coset_offset,
            pow_mod(self.extension_root, position as u64, self.modulus)
                .expect("extension root power is a canonical residue"),
            self.modulus,
        )
    }
}

// Montgomery batch inversion; fails on a zero element.
pub(in crate::bgv) fn batch_inverse(values: &[u64], modulus: u64) -> CanonicalResult<Vec<u64>> {
    let mut prefix_products = Vec::with_capacity(values.len());
    let mut running = 1_u64;
    for value in values {
        if *value == 0 {
            return Err(invalid_polynomial_iop(
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
