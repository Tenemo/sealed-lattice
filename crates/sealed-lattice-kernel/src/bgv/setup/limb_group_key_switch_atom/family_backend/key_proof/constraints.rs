use super::*;

// Support constraint count: ternary (2) + per digit [eta-2 (3) + lookup
// fraction pin (1)] + one table fraction pin per chunk + the linkage block's
// constraints when present. The recombined component material `B_j` carries no
// support constraint of its own: it is bound only by the relation, through the
// sumcheck's material forms.
pub(super) fn support_constraint_count(
    ring_degree: usize,
    digit_count: usize,
    linkage_layout: Option<&linkage::LinkageLayout>,
) -> usize {
    2 + digit_count * 4
        + carry_range_lookup::table_count(ring_degree)
        + linkage_layout
            .map(linkage::linkage_support_constraint_count)
            .unwrap_or(0)
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

// The support constraint value at one coset point, from opened base and aux
// values, the public table values evaluated at the point, and the logUp
// challenge. The constraint order matches the prover's streamed folds: ternary,
// per digit [eta-2 x3, lookup pin], then table pins.
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
    linkage_context: Option<&linkage::LinkageConstraintContext>,
) -> [u64; LIMB_COUNT] {
    let one = parameters.one();
    let four = parameters.unsigned_word_to_element(4);
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = parameters.subtract(challenge, &shift);
    let secret = base_values[COLUMN_SECRET];
    let secret_square = base_values[COLUMN_SECRET_SQUARE];

    let mut constraints = Vec::with_capacity(support_constraint_count(
        ring_degree,
        digit_count,
        linkage_context.map(|context| context.layout()),
    ));
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
        constraints.push(
            parameters.subtract(&parameters.multiply(&denominator, &fraction), &multiplicity),
        );
    }
    if let Some(context) = linkage_context {
        linkage::push_linkage_support_values(
            parameters,
            context,
            base_values,
            aux_values,
            base_linkage_start(ring_degree, digit_count),
            aux_linkage_start(ring_degree, digit_count),
            challenge,
            &mut constraints,
        );
    }
    let mut value = parameters.zero();
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        value = parameters.add(&value, &parameters.multiply(weight, constraint));
    }
    value
}

// One digit's delta-weighted linear forms, handed to the caller and dropped
// immediately: neither the prover nor the verifier ever holds every digit's
// forms at once (at the full profile that set alone is hundreds of megabytes).
// `material_form` is the linear form paired with the committed material column
// `B_col_j`: it is `delta_j * gamma`, so `<material_form_j, B_col_j> =
// delta_j <gamma, B_col_j>`, which is exactly the term the sumcheck target used
// to carry as `-delta_j <gamma, B_public_j>`, moved to the left-hand side with
// the material committed instead of hashed as a public target scalar.
pub(super) struct WeightedDigitForms<const LIMB_COUNT: usize> {
    pub(super) error_form: Vec<[u64; LIMB_COUNT]>,
    pub(super) carry_form: Vec<[u64; LIMB_COUNT]>,
    pub(super) material_form: Vec<[u64; LIMB_COUNT]>,
}

// Stream the per-digit reduced atom forms: `consume` receives each digit's
// delta-weighted error/carry/material forms in digit order, while the
// delta-weighted shared secret form accumulates across the sweep and is
// returned with a zero atom target contribution. The transported component is
// carried on the sumcheck's left-hand side by the material form against the
// committed `B_col_j`: `LHS_forms + sum delta_j <gamma, B_col_j> = 0`. A
// committed material that does not equal the correct component breaks this
// equality and the sumcheck rejects.
pub(super) fn accumulate_forms<const LIMB_COUNT: usize, Consume>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    negacyclic: &NegacyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    delta: &[[u64; LIMB_COUNT]],
    mut consume: Consume,
) -> CanonicalResult<(Vec<[u64; LIMB_COUNT]>, [u64; LIMB_COUNT])>
where
    Consume: FnMut(usize, WeightedDigitForms<LIMB_COUNT>) -> CanonicalResult<()>,
{
    let mut secret_form = vec![parameters.zero(); ring_degree];
    for (digit_index, digit) in public.digits.iter().enumerate() {
        let atom_public = AtomPublicInputs {
            recombined_sample: &digit.recombined_sample,
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
        for (accumulator, coefficient) in
            secret_form.iter_mut().zip(form.secret_coefficients.iter())
        {
            *accumulator = parameters.add(accumulator, &parameters.multiply(&weight, coefficient));
        }
        consume(
            digit_index,
            WeightedDigitForms {
                error_form: form
                    .error_coefficients
                    .iter()
                    .map(|c| parameters.multiply(&weight, c))
                    .collect(),
                carry_form: form
                    .carry_coefficients
                    .iter()
                    .map(|c| parameters.multiply(&weight, c))
                    .collect(),
                // The material form `delta_j * gamma`: the atom's component term
                // moved to the left-hand side against the committed column.
                material_form: gamma
                    .iter()
                    .map(|value| parameters.multiply(&weight, value))
                    .collect(),
            },
        )?;
    }
    // The atom target contribution is zero: the component term now rides the
    // material forms on the left-hand side, not the target scalar.
    Ok((secret_form, parameters.zero()))
}

// The random-combination value at one opened point. The weights zip against the
// committed columns in the fixed order base + material + aux + quotient (the
// same order the prover accumulates the codewords), so the material columns take
// the weight block immediately after the base columns.
pub(super) fn combination_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    base_values: &[[u64; LIMB_COUNT]],
    material_values: &[[u64; LIMB_COUNT]],
    aux_values: &[[u64; LIMB_COUNT]],
    quotient_values: &[[u64; LIMB_COUNT]],
    weights: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut value = parameters.zero();
    for (weight, column_value) in weights.iter().zip(
        base_values
            .iter()
            .chain(material_values.iter())
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
        transcript.absorb_field_elements("digit-gadget", &[digit.gadget_idempotent]);
    }
    source.absorb(transcript);
}
