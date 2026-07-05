use super::*;

// Support constraint count: ternary (2) + per digit [eta-2 (3) + lookup
// fraction pin (1)] + one table fraction pin per chunk.
pub(super) fn support_constraint_count(ring_degree: usize, digit_count: usize) -> usize {
    2 + digit_count * 4 + carry_range_lookup::table_count(ring_degree)
}

// The public table value polynomials (coefficient form), one per chunk, shared
// by prover and verifier. `T_k` interpolates the chunk's public value column
// over the trace domain; both sides evaluate it at query points like the
// sumcheck linear forms, so no table column is committed and no out-of-range
// value can enter the table.
pub(super) fn table_value_polynomials<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    (0..carry_range_lookup::table_count(ring_degree))
        .map(|table_index| {
            let values = carry_range_lookup::table_values(parameters, ring_degree, table_index);
            trace_domain.interpolate(&values)
        })
        .collect()
}

// Build the support constraint polynomials in a fixed order shared by prover and
// verifier: ternary, then per digit [eta-2 x3, lookup fraction pin], then the
// table fraction pins. The fraction pins are the logUp relation
// `(mu - value) * fraction - multiplicity = 0` (multiplicity is the implicit 1
// for a looked-up carry).
pub(super) fn support_constraints<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    base_columns: &[Vec<[u64; LIMB_COUNT]>],
    aux_columns: &[Vec<[u64; LIMB_COUNT]>],
    table_polynomials: &[Vec<[u64; LIMB_COUNT]>],
    challenge: &[u64; LIMB_COUNT],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let one = vec![parameters.one()];
    let four = vec![parameters.unsigned_word_to_element(4)];
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = vec![parameters.subtract(challenge, &shift)];
    let challenge_constant = vec![*challenge];
    let secret = &base_columns[COLUMN_SECRET];
    let secret_square = &base_columns[COLUMN_SECRET_SQUARE];

    let mut constraints = Vec::new();
    // Ternary: Ssq - S*S, S*(Ssq-1).
    constraints.push(polynomial::subtract(
        parameters,
        secret_square,
        &polynomial::multiply_via_ntt(parameters, secret, secret),
    ));
    constraints.push(polynomial::multiply_via_ntt(
        parameters,
        secret,
        &polynomial::subtract(parameters, secret_square, &one),
    ));
    for digit in 0..digit_count {
        let error = &base_columns[digit_column(digit, DIGIT_ERROR)];
        let carry = &base_columns[digit_column(digit, DIGIT_CARRY)];
        let error_square = &base_columns[digit_column(digit, DIGIT_ERROR_SQUARE)];
        let error_support = &base_columns[digit_column(digit, DIGIT_ERROR_SUPPORT)];
        // eta-2: Wsq - E*E, Pcol - (Wsq-1)(Wsq-4), E*Pcol.
        constraints.push(polynomial::subtract(
            parameters,
            error_square,
            &polynomial::multiply_via_ntt(parameters, error, error),
        ));
        constraints.push(polynomial::subtract(
            parameters,
            error_support,
            &polynomial::multiply_via_ntt(
                parameters,
                &polynomial::subtract(parameters, error_square, &one),
                &polynomial::subtract(parameters, error_square, &four),
            ),
        ));
        constraints.push(polynomial::multiply_via_ntt(
            parameters,
            error,
            error_support,
        ));
        // lookup fraction pin: (mu - shift - C) * f - 1 = 0.
        let fraction = &aux_columns[aux_lookup_column(digit)];
        let denominator = polynomial::subtract(parameters, &challenge_minus_shift, carry);
        constraints.push(polynomial::subtract(
            parameters,
            &polynomial::multiply_via_ntt(parameters, &denominator, fraction),
            &one,
        ));
    }
    // Table fraction pins: (mu - T_k) * f_T_k - m_k = 0.
    for (table_index, table_polynomial) in table_polynomials.iter().enumerate() {
        let fraction = &aux_columns[aux_table_fraction_column(digit_count, table_index)];
        let multiplicity = &base_columns[base_multiplicity_column(digit_count, table_index)];
        let denominator = polynomial::subtract(parameters, &challenge_constant, table_polynomial);
        constraints.push(polynomial::subtract(
            parameters,
            &polynomial::multiply_via_ntt(parameters, &denominator, fraction),
            multiplicity,
        ));
    }
    constraints
}

// The support constraint value at one coset point, from opened base and aux
// values, the public table values evaluated at the point, and the logUp
// challenge. The constraint order matches `support_constraints`.
#[allow(clippy::too_many_arguments)]
pub(super) fn support_value_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    base_values: &[[u64; LIMB_COUNT]],
    aux_values: &[[u64; LIMB_COUNT]],
    table_values_at_point: &[[u64; LIMB_COUNT]],
    challenge: &[u64; LIMB_COUNT],
    alpha: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let one = parameters.one();
    let four = parameters.unsigned_word_to_element(4);
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = parameters.subtract(challenge, &shift);
    let secret = base_values[COLUMN_SECRET];
    let secret_square = base_values[COLUMN_SECRET_SQUARE];

    let mut constraints = Vec::with_capacity(support_constraint_count(ring_degree, digit_count));
    constraints.push(parameters.subtract(&secret_square, &parameters.multiply(&secret, &secret)));
    constraints.push(parameters.multiply(&secret, &parameters.subtract(&secret_square, &one)));
    for digit in 0..digit_count {
        let error = base_values[digit_column(digit, DIGIT_ERROR)];
        let carry = base_values[digit_column(digit, DIGIT_CARRY)];
        let error_square = base_values[digit_column(digit, DIGIT_ERROR_SQUARE)];
        let error_support = base_values[digit_column(digit, DIGIT_ERROR_SUPPORT)];
        constraints.push(parameters.subtract(&error_square, &parameters.multiply(&error, &error)));
        let support_product = parameters.multiply(
            &parameters.subtract(&error_square, &one),
            &parameters.subtract(&error_square, &four),
        );
        constraints.push(parameters.subtract(&error_support, &support_product));
        constraints.push(parameters.multiply(&error, &error_support));
        // lookup fraction pin: (mu - shift - C) * f - 1.
        let fraction = aux_values[aux_lookup_column(digit)];
        let denominator = parameters.subtract(&challenge_minus_shift, &carry);
        constraints.push(parameters.subtract(&parameters.multiply(&denominator, &fraction), &one));
    }
    for (table_index, table_value) in table_values_at_point.iter().enumerate() {
        let fraction = aux_values[aux_table_fraction_column(digit_count, table_index)];
        let multiplicity = base_values[base_multiplicity_column(digit_count, table_index)];
        let denominator = parameters.subtract(challenge, table_value);
        constraints.push(parameters.subtract(
            &parameters.multiply(&denominator, &fraction),
            &multiplicity,
        ));
    }

    let mut value = parameters.zero();
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        value = parameters.add(&value, &parameters.multiply(weight, constraint));
    }
    value
}

// The combined per-digit linear forms, computed by both sides from public data
// and the challenges: the shared secret form Ls (sum_j delta_j L_j.secret),
// per-digit Le_j, Lc_j (delta_j scaled), and the summed target.
pub(super) struct CombinedForms<const LIMB_COUNT: usize> {
    pub(super) secret: Vec<[u64; LIMB_COUNT]>,
    pub(super) error_by_digit: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) carry_by_digit: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) target: [u64; LIMB_COUNT],
}

pub(super) fn combined_forms<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    negacyclic: &NegacyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    delta: &[[u64; LIMB_COUNT]],
) -> CombinedForms<LIMB_COUNT> {
    let mut secret = vec![parameters.zero(); ring_degree];
    let mut error_by_digit = Vec::with_capacity(public.digits.len());
    let mut carry_by_digit = Vec::with_capacity(public.digits.len());
    let mut target = parameters.zero();
    for (digit_index, digit) in public.digits.iter().enumerate() {
        let atom_public = AtomPublicInputs {
            recombined_sample: &digit.recombined_sample,
            recombined_component_b: &digit.recombined_component_b,
            gadget_idempotent: digit.gadget_idempotent,
            group_modulus: public.group_modulus,
            plaintext_modulus: public.plaintext_modulus,
        };
        let form = reduce_atom(
            parameters,
            negacyclic,
            &atom_public,
            &source.atom_source(digit_index),
            gamma,
        );
        let weight = delta[digit_index];
        for (accumulator, coefficient) in secret.iter_mut().zip(form.secret_coefficients.iter()) {
            *accumulator = parameters.add(accumulator, &parameters.multiply(&weight, coefficient));
        }
        error_by_digit.push(
            form.error_coefficients
                .iter()
                .map(|c| parameters.multiply(&weight, c))
                .collect(),
        );
        carry_by_digit.push(
            form.carry_coefficients
                .iter()
                .map(|c| parameters.multiply(&weight, c))
                .collect(),
        );
        target = parameters.add(&target, &parameters.multiply(&weight, &form.target));
    }
    CombinedForms {
        secret,
        error_by_digit,
        carry_by_digit,
        target,
    }
}

pub(super) fn combination_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    base_values: &[[u64; LIMB_COUNT]],
    aux_values: &[[u64; LIMB_COUNT]],
    quotient_values: &[[u64; LIMB_COUNT]],
    weights: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut value = parameters.zero();
    for (weight, column_value) in weights.iter().zip(
        base_values
            .iter()
            .chain(aux_values.iter())
            .chain(quotient_values.iter()),
    ) {
        value = parameters.add(&value, &parameters.multiply(weight, column_value));
    }
    value
}

pub(super) fn absorb_public<const LIMB_COUNT: usize>(
    transcript: &mut Transcript,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
) {
    transcript.absorb_u64("ring-degree", ring_degree as u64);
    transcript.absorb_u64("digit-count", public.digits.len() as u64);
    transcript.absorb_field_elements("group-modulus", &[public.group_modulus]);
    transcript.absorb_field_elements("plaintext-modulus", &[public.plaintext_modulus]);
    for digit in &public.digits {
        transcript.absorb_field_elements("digit-sample", &digit.recombined_sample);
        transcript.absorb_field_elements("digit-component-b", &digit.recombined_component_b);
        transcript.absorb_field_elements("digit-gadget", &[digit.gadget_idempotent]);
    }
    source.absorb(transcript);
}

