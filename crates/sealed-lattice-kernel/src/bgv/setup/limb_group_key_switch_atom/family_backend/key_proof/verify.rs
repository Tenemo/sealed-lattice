use super::*;
use super::constraints::*;

pub(in super::super) fn verify_round_one_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    proof: &KeyFriProof<LIMB_COUNT>,
    proof_parameters: &KeyFriProofParameters,
) -> CanonicalResult<bool> {
    verify_key_fri(
        parameters,
        ring_degree,
        public,
        &KeySource::RoundOne,
        proof,
        proof_parameters,
    )
}

pub(in super::super) fn verify_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    proof: &KeyFriProof<LIMB_COUNT>,
    proof_parameters: &KeyFriProofParameters,
) -> CanonicalResult<bool> {
    let layout = layout(ring_degree)?;
    let digit_count = public.digits.len();
    if digit_count == 0 {
        return Ok(false);
    }
    let trace_domain = CyclicDomain::new(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let negacyclic = NegacyclicDomain::new(parameters, ring_degree)?;
    let table_count = carry_range_lookup::table_count(ring_degree);
    let base_count = base_column_count(ring_degree, digit_count);
    let aux_count = aux_column_count(ring_degree, digit_count);

    // The logUp terminals in the proof must be shaped for this key, and the
    // cross-check `lookup = sum_k table_k` must hold before any query work.
    if proof.table_terminals.len() != table_count {
        return Ok(false);
    }
    let table_terminal_sum = proof
        .table_terminals
        .iter()
        .fold(parameters.zero(), |sum, terminal| {
            parameters.add(&sum, terminal)
        });
    if table_terminal_sum != proof.lookup_terminal {
        return Ok(false);
    }

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_digest("key-base-root", &proof.base_root);
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];

    transcript.absorb_digest("key-aux-root", &proof.aux_root);
    transcript.absorb_field_elements("key-lookup-terminal", &[proof.lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &proof.table_terminals);
    let sum_batch =
        transcript.challenge_field_elements(parameters, "key-sum-batch", 1 + table_count);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count),
    );

    let forms = combined_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
    );

    transcript.absorb_digest("key-quotient-root", &proof.quotient_root);
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + aux_count + QUOTIENT_COLUMN_COUNT,
    );

    let fri_parameters = FriParameters {
        blowup: FRI_RATE_BLOWUP,
        query_count: proof_parameters.query_count,
    };
    let Some(verification) = fri_verify_structure(
        parameters,
        &mut transcript,
        &proof.fri,
        layout.coset_size,
        &offset,
        &fri_parameters,
    )?
    else {
        return Ok(false);
    };
    let query_positions = transcript.challenge_positions(
        "key-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    if !fri_verify_queries(parameters, &verification, &proof.fri, &query_positions) {
        return Ok(false);
    }

    let Some(base_rows) = verify_column_opening(
        &proof.base_root,
        layout.coset_size,
        base_count,
        &proof.base_opening,
    ) else {
        return Ok(false);
    };
    let Some(aux_rows) = verify_column_opening(
        &proof.aux_root,
        layout.coset_size,
        aux_count,
        &proof.aux_opening,
    ) else {
        return Ok(false);
    };
    let Some(quotient_rows) = verify_column_opening(
        &proof.quotient_root,
        layout.coset_size,
        QUOTIENT_COLUMN_COUNT,
        &proof.quotient_opening,
    ) else {
        return Ok(false);
    };

    // Public linear-form polynomials over H, plus the public table value
    // polynomials for the fraction-pin support constraints.
    let ls = trace_domain.interpolate(&forms.secret);
    let le_by_digit: Vec<Vec<[u64; LIMB_COUNT]>> = forms
        .error_by_digit
        .iter()
        .map(|form| trace_domain.interpolate(form))
        .collect();
    let lc_by_digit: Vec<Vec<[u64; LIMB_COUNT]>> = forms
        .carry_by_digit
        .iter()
        .map(|form| trace_domain.interpolate(form))
        .collect();
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    // Combined sumcheck target: the atom target plus the batched logUp terminals.
    let mut target = parameters.add(
        &forms.target,
        &parameters.multiply(&sum_batch[0], &proof.lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(&sum_batch[1 + table_index], &proof.table_terminals[table_index]),
        );
    }
    let target_over_size = parameters.multiply(&target, &size_inverse);

    let half = layout.coset_size / 2;
    for (query_index, &position) in query_positions.iter().enumerate() {
        let folded = position % half;
        let sibling = folded + half;
        let layers = &proof.fri.query_answers[query_index].layers;
        if layers.is_empty() {
            return Ok(false);
        }
        let layer_zero = &layers[0];
        for (index, expected) in [
            (folded, layer_zero.value),
            (sibling, layer_zero.sibling_value),
        ] {
            let Some(base_values) = base_rows.get(&index) else {
                return Ok(false);
            };
            let Some(aux_values) = aux_rows.get(&index) else {
                return Ok(false);
            };
            let Some(quotient_values) = quotient_rows.get(&index) else {
                return Ok(false);
            };
            if combination_at(parameters, base_values, aux_values, quotient_values, &weights)
                != expected
            {
                return Ok(false);
            }
            let x = parameters.multiply(&offset, &coset_domain.point(index));
            let vanishing_x = polynomial::vanishing_at(parameters, &x, layout.trace_size);

            // Sumcheck: f(x) = target/m + x g(x) + Z_H(x) q_sc(x), where f folds
            // in the batched logUp fraction columns.
            let mut f_x = parameters.multiply(
                &polynomial::evaluate(parameters, &ls, &x),
                &base_values[COLUMN_SECRET],
            );
            for digit in 0..digit_count {
                let le_x = polynomial::evaluate(parameters, &le_by_digit[digit], &x);
                let lc_x = polynomial::evaluate(parameters, &lc_by_digit[digit], &x);
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&le_x, &base_values[digit_column(digit, DIGIT_ERROR)]),
                );
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&lc_x, &base_values[digit_column(digit, DIGIT_CARRY)]),
                );
            }
            for digit in 0..digit_count {
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&sum_batch[0], &aux_values[aux_lookup_column(digit)]),
                );
            }
            for table_index in 0..table_count {
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(
                        &sum_batch[1 + table_index],
                        &aux_values[aux_table_fraction_column(digit_count, table_index)],
                    ),
                );
            }
            let sumcheck_rhs = parameters.add(
                &parameters.add(
                    &target_over_size,
                    &parameters.multiply(&x, &quotient_values[QUOTIENT_G]),
                ),
                &parameters.multiply(&vanishing_x, &quotient_values[QUOTIENT_SUMCHECK]),
            );
            if f_x != sumcheck_rhs {
                return Ok(false);
            }

            // Support: V(x) = Z_H(x) q_support(x), with the table value
            // polynomials evaluated at x for the fraction pins.
            let table_values_at_point: Vec<[u64; LIMB_COUNT]> = table_polynomials
                .iter()
                .map(|table_polynomial| polynomial::evaluate(parameters, table_polynomial, &x))
                .collect();
            let v_x = support_value_at(
                parameters,
                ring_degree,
                digit_count,
                base_values,
                aux_values,
                &table_values_at_point,
                &mu,
                &alpha,
            );
            if v_x != parameters.multiply(&vanishing_x, &quotient_values[QUOTIENT_SUPPORT]) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

