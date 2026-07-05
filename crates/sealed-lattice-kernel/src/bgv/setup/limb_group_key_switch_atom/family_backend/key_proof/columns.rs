use super::*;

pub(super) fn vanishing_polynomial<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_size: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut vanishing = vec![parameters.zero(); trace_size + 1];
    vanishing[0] = parameters.negate(&parameters.one());
    vanishing[trace_size] = parameters.one();
    vanishing
}

pub(super) fn masked_coefficients<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    trace_size: usize,
    mask_degree: usize,
    salt_seed: &mut u64,
) -> Vec<[u64; LIMB_COUNT]> {
    if mask_degree == 0 {
        return coefficients.to_vec();
    }
    let mut mask = Vec::with_capacity(mask_degree + 1);
    for _ in 0..=mask_degree {
        *salt_seed = salt_seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        mask.push(parameters.unsigned_word_to_element(*salt_seed));
    }
    let mask_multiple = polynomial::multiply_via_ntt(
        parameters,
        &mask,
        &vanishing_polynomial(parameters, trace_size),
    );
    polynomial::add(parameters, coefficients, &mask_multiple)
}

// Build the round-1 base column coefficient vectors: the shared secret block,
// the per-digit witness blocks, then one carry-range multiplicity column per
// table chunk. The multiplicity of each table value is the number of shifted
// carries equal to it; an out-of-range carry is simply not counted, which makes
// the logUp balance fail (the sound outcome, exercised by a tamper test).
pub(super) fn build_base_columns<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    secret: &[i64],
    digits: &[DigitWitness],
    mask_degree: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<Vec<Vec<[u64; LIMB_COUNT]>>> {
    let mut columns = Vec::with_capacity(base_column_count(ring_degree, digits.len()));

    // Shared: S, S^2.
    let secret_values: Vec<[u64; LIMB_COUNT]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let secret_square_values: Vec<[u64; LIMB_COUNT]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(v * v))
        .collect();
    for values in [&secret_values, &secret_square_values] {
        let coefficients = trace_domain.interpolate(values);
        columns.push(masked_coefficients(
            parameters,
            &coefficients,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    // Per digit: E_j, C_j, E_j^2, Pcol_j.
    for digit in digits {
        if digit.error.len() != ring_degree || digit.carry.len() != ring_degree {
            return Err(invalid_key(
                "digit witness length does not match ring degree",
            ));
        }
        let error_values: Vec<[u64; LIMB_COUNT]> = digit
            .error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_values: Vec<[u64; LIMB_COUNT]> = digit
            .carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let error_square_values: Vec<[u64; LIMB_COUNT]> = digit
            .error
            .iter()
            .map(|v| parameters.signed_word_to_element(v * v))
            .collect();
        let error_support_values: Vec<[u64; LIMB_COUNT]> = digit
            .error
            .iter()
            .map(|v| {
                let square = v * v;
                parameters.signed_word_to_element((square - 1) * (square - 4))
            })
            .collect();
        for values in [
            &error_values,
            &carry_values,
            &error_square_values,
            &error_support_values,
        ] {
            let coefficients = trace_domain.interpolate(values);
            columns.push(masked_coefficients(
                parameters,
                &coefficients,
                ring_degree,
                mask_degree,
                salt_seed,
            ));
        }
    }

    // Carry-range multiplicity columns (one per table chunk).
    let multiplicity_columns = carry_multiplicity_values(parameters, ring_degree, digits);
    for multiplicity in &multiplicity_columns {
        let coefficients = trace_domain.interpolate(multiplicity);
        columns.push(masked_coefficients(
            parameters,
            &coefficients,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    Ok(columns)
}

// The carry-range multiplicity value columns (one per table chunk), counting how
// many shifted carries across all digits equal each table value. Out-of-range
// carries are not counted, which makes the logUp balance fail. Deterministic
// from the witness, so both the round-1 base builder and the round-2 aux builder
// derive the same columns.
pub(super) fn carry_multiplicity_values<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digits: &[DigitWitness],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let shift = carry_range_lookup::carry_shift(ring_degree);
    let max_shifted = carry_range_lookup::max_shifted_value(ring_degree);
    let mut shifted_in_range = Vec::with_capacity(digits.len() * ring_degree);
    for digit in digits {
        for &carry in &digit.carry {
            let shifted = carry + shift;
            if shifted >= 0 && (shifted as usize) <= max_shifted {
                shifted_in_range.push(shifted as usize);
            }
        }
    }
    carry_range_lookup::multiplicities(parameters, &shifted_in_range, ring_degree)
}

// Build the round-2 auxiliary column coefficient vectors (committed after the
// logUp challenge `mu` is drawn): one lookup fraction column per digit
// `f_d[x] = 1/(mu - (c_d(x) + shift))`, then one table fraction column per chunk
// `f_T_k[x] = m_k(x)/(mu - T_k(x))`. Returns the columns together with the logUp
// terminals (`lookup_terminal = sum_x sum_d f_d`, `table_terminals[k] = sum_x
// f_T_k`), computed from the on-domain values so masking does not affect them.
pub(super) struct AuxColumns<const LIMB_COUNT: usize> {
    pub(super) coefficients: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) lookup_terminal: [u64; LIMB_COUNT],
    pub(super) table_terminals: Vec<[u64; LIMB_COUNT]>,
}

pub(super) fn build_aux_columns<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    digits: &[DigitWitness],
    multiplicity_values: &[Vec<[u64; LIMB_COUNT]>],
    challenge: &[u64; LIMB_COUNT],
    mask_degree: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<AuxColumns<LIMB_COUNT>> {
    let shift = carry_range_lookup::carry_shift(ring_degree);
    let mut coefficients = Vec::with_capacity(aux_column_count(ring_degree, digits.len()));
    let mut lookup_terminal = parameters.zero();

    // Per-digit lookup fractions.
    for digit in digits {
        let shifted_values: Vec<[u64; LIMB_COUNT]> = digit
            .carry
            .iter()
            .map(|carry| parameters.signed_word_to_element(carry + shift))
            .collect();
        let fraction = carry_range_lookup::lookup_fraction_column(parameters, challenge, &shifted_values)
            .ok_or_else(|| invalid_key("logUp challenge collided with a shifted carry"))?;
        lookup_terminal =
            parameters.add(&lookup_terminal, &carry_range_lookup::column_sum(parameters, &fraction));
        let column = trace_domain.interpolate(&fraction);
        coefficients.push(masked_coefficients(
            parameters,
            &column,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    // Table fractions, one per chunk.
    let mut table_terminals = Vec::with_capacity(multiplicity_values.len());
    for (table_index, multiplicity) in multiplicity_values.iter().enumerate() {
        let table_values = carry_range_lookup::table_values(parameters, ring_degree, table_index);
        let fraction =
            carry_range_lookup::table_fraction_column(parameters, challenge, &table_values, multiplicity)
                .ok_or_else(|| invalid_key("logUp challenge collided with a table value"))?;
        table_terminals.push(carry_range_lookup::column_sum(parameters, &fraction));
        let column = trace_domain.interpolate(&fraction);
        coefficients.push(masked_coefficients(
            parameters,
            &column,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    Ok(AuxColumns {
        coefficients,
        lookup_terminal,
        table_terminals,
    })
}

