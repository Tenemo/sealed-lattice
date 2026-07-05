use super::columns::*;
use super::constraints::*;
use super::*;

pub(in super::super) fn prove_round_one_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    proof_parameters: &KeyFriProofParameters,
    salt_seed: &mut u64,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    prove_key_fri(
        parameters,
        ring_degree,
        public,
        &KeySource::RoundOne,
        secret,
        digits,
        proof_parameters,
        salt_seed,
    )
}

// The streamed prover: commit, sumcheck/support, combination, and opening
// passes each regenerate exactly the columns they consume from the
// deterministic `KeyColumnPlan`, so peak memory is bounded by one coset
// codeword plus one incremental leaf-hash state per coset position - never the
// full column set (at the full profile the retained column set alone is
// gigabytes). The regeneration trades roughly two extra coset LDEs per column
// for that bound; the transcript, challenge order, and deterministic salt/mask
// stream are unchanged from the one-shot shape.
pub(in super::super) fn prove_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    proof_parameters: &KeyFriProofParameters,
    salt_seed: &mut u64,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    if public.digits.len() != digits.len() || digits.is_empty() {
        return Err(invalid_key("digit public and witness counts must match"));
    }
    let layout = layout(ring_degree)?;
    let digit_count = digits.len();
    let trace_domain = CyclicDomain::new(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let negacyclic = NegacyclicDomain::new(parameters, ring_degree)?;
    let table_count = carry_range_lookup::table_count(ring_degree);

    let mut plan = KeyColumnPlan::new(
        parameters,
        ring_degree,
        proof_parameters.mask_degree,
        secret,
        digits,
        salt_seed,
    )?;
    let base_count = plan.base_column_count();

    // Round 1 (streamed): witness columns plus the carry-range multiplicity
    // columns, committed one codeword at a time.
    let mut base_builder =
        StreamedColumnCommitmentBuilder::begin(layout.coset_size, base_count, salt_seed)?;
    for column in 0..base_count {
        let coefficients = plan.base_column_coefficients(parameters, &trace_domain, column);
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &coefficients);
        base_builder.absorb_column(&codeword)?;
    }
    let base_commitment = base_builder.finalize()?;

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_digest("key-base-root", &base_commitment.root());
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];

    // Round 2 (streamed): the logUp fraction columns, which depend on `mu`. The
    // lookup and table terminals are computed from the on-domain values and
    // bound into the transcript.
    plan.set_lookup_challenge(mu, salt_seed);
    let aux_count = plan.aux_column_count();
    let (lookup_terminal, table_terminals) = plan.lookup_terminals(parameters)?;
    let mut aux_builder =
        StreamedColumnCommitmentBuilder::begin(layout.coset_size, aux_count, salt_seed)?;
    for column in 0..aux_count {
        let coefficients = plan.aux_column_coefficients(parameters, &trace_domain, column)?;
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &coefficients);
        aux_builder.absorb_column(&codeword)?;
    }
    let aux_commitment = aux_builder.finalize()?;
    transcript.absorb_digest("key-aux-root", &aux_commitment.root());
    transcript.absorb_field_elements("key-lookup-terminal", &[lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &table_terminals);

    // Batching challenges: one for the lookup terminal, one per table terminal,
    // folded into the single sumcheck; and the support-constraint weights.
    let sum_batch =
        transcript.challenge_field_elements(parameters, "key-sum-batch", 1 + table_count);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count),
    );

    // Sumcheck: f = Ls*S + sum_j (Le_j*E_j + Lc_j*C_j) plus the batched logUp
    // fraction sums, whose target folds in the committed terminals. The
    // per-digit forms stream through `accumulate_forms` and are dropped after
    // their products; witness columns regenerate from the plan.
    let mut f = vec![parameters.zero()];
    let (secret_form, atom_target) = accumulate_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
        |digit, forms| {
            let error_linear = trace_domain.interpolate(&forms.error_form);
            let error_column = plan.base_column_coefficients(
                parameters,
                &trace_domain,
                digit_column(digit, DIGIT_ERROR),
            );
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &error_linear, &error_column),
            );
            let carry_linear = trace_domain.interpolate(&forms.carry_form);
            let carry_column = plan.base_column_coefficients(
                parameters,
                &trace_domain,
                digit_column(digit, DIGIT_CARRY),
            );
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &carry_linear, &carry_column),
            );
            Ok(())
        },
    )?;
    let ls = trace_domain.interpolate(&secret_form);
    let secret_column = plan.base_column_coefficients(parameters, &trace_domain, COLUMN_SECRET);
    f = polynomial::add(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &ls, &secret_column),
    );
    let lookup_weight = sum_batch[0];
    for digit in 0..digit_count {
        let column =
            plan.aux_column_coefficients(parameters, &trace_domain, aux_lookup_column(digit))?;
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(parameters, &column, &lookup_weight),
        );
    }
    for table_index in 0..table_count {
        let column = plan.aux_column_coefficients(
            parameters,
            &trace_domain,
            aux_table_fraction_column(digit_count, table_index),
        )?;
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(parameters, &column, &sum_batch[1 + table_index]),
        );
    }
    let mut target = parameters.add(
        &atom_target,
        &parameters.multiply(&lookup_weight, &lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(&sum_batch[1 + table_index], &table_terminals[table_index]),
        );
    }

    let vanishing = vanishing_polynomial(parameters, layout.trace_size);
    let q_sc = polynomial::divide_by_vanishing(parameters, &f, layout.trace_size);
    let mut remainder = polynomial::subtract(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &q_sc, &vanishing),
    );
    drop(f);
    polynomial::trim(&mut remainder);
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    let target_over_size = parameters.multiply(&target, &size_inverse);
    let remainder_constant = remainder
        .first()
        .copied()
        .unwrap_or_else(|| parameters.zero());
    if remainder_constant != target_over_size {
        return Err(invalid_key("sumcheck remainder constant mismatch"));
    }
    let mut shifted = remainder;
    if shifted.is_empty() {
        shifted.push(parameters.zero());
    }
    shifted[0] = parameters.subtract(&shifted[0], &target_over_size);
    let g = if shifted.len() > 1 {
        shifted[1..].to_vec()
    } else {
        vec![parameters.zero()]
    };

    // Support: V = sum alpha_i constraint_i, vanishing on H, streamed in the
    // same fixed constraint order the verifier's `support_value_at` walks:
    // ternary, then per digit [eta-2 x3, lookup fraction pin], then the table
    // fraction pins. Each constraint polynomial is weighted into V and dropped.
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let one = vec![parameters.one()];
    let four = vec![parameters.unsigned_word_to_element(4)];
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = vec![parameters.subtract(&mu, &shift)];
    let challenge_constant = vec![mu];
    let mut v = vec![parameters.zero()];
    let mut alpha_index = 0;
    let fold_constraint = |v: &mut Vec<[u64; LIMB_COUNT]>,
                           alpha_index: &mut usize,
                           constraint: Vec<[u64; LIMB_COUNT]>| {
        *v = polynomial::add(
            parameters,
            v,
            &polynomial::scale(parameters, &constraint, &alpha[*alpha_index]),
        );
        *alpha_index += 1;
    };
    {
        let secret_column = plan.base_column_coefficients(parameters, &trace_domain, COLUMN_SECRET);
        let secret_square_column =
            plan.base_column_coefficients(parameters, &trace_domain, COLUMN_SECRET_SQUARE);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &secret_square_column,
                &polynomial::multiply_via_ntt(parameters, &secret_column, &secret_column),
            ),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::multiply_via_ntt(
                parameters,
                &secret_column,
                &polynomial::subtract(parameters, &secret_square_column, &one),
            ),
        );
    }
    for digit in 0..digit_count {
        let error_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_ERROR),
        );
        let error_square_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_ERROR_SQUARE),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &error_square_column,
                &polynomial::multiply_via_ntt(parameters, &error_column, &error_column),
            ),
        );
        let error_support_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_ERROR_SUPPORT),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &error_support_column,
                &polynomial::multiply_via_ntt(
                    parameters,
                    &polynomial::subtract(parameters, &error_square_column, &one),
                    &polynomial::subtract(parameters, &error_square_column, &four),
                ),
            ),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::multiply_via_ntt(parameters, &error_column, &error_support_column),
        );
        // lookup fraction pin: (mu - shift - C) * f - 1 = 0.
        let carry_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_CARRY),
        );
        let fraction_column =
            plan.aux_column_coefficients(parameters, &trace_domain, aux_lookup_column(digit))?;
        let denominator = polynomial::subtract(parameters, &challenge_minus_shift, &carry_column);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &polynomial::multiply_via_ntt(parameters, &denominator, &fraction_column),
                &one,
            ),
        );
    }
    // Table fraction pins: (mu - T_k) * f_T_k - m_k = 0.
    for (table_index, table_polynomial) in table_polynomials.iter().enumerate() {
        let fraction_column = plan.aux_column_coefficients(
            parameters,
            &trace_domain,
            aux_table_fraction_column(digit_count, table_index),
        )?;
        let multiplicity_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            base_multiplicity_column(digit_count, table_index),
        );
        let denominator = polynomial::subtract(parameters, &challenge_constant, table_polynomial);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &polynomial::multiply_via_ntt(parameters, &denominator, &fraction_column),
                &multiplicity_column,
            ),
        );
    }
    let q_support = polynomial::divide_by_vanishing(parameters, &v, layout.trace_size);
    let mut support_remainder = polynomial::subtract(
        parameters,
        &v,
        &polynomial::multiply_via_ntt(parameters, &q_support, &vanishing),
    );
    drop(v);
    polynomial::trim(&mut support_remainder);
    if support_remainder
        .iter()
        .any(|c| c.iter().any(|limb| *limb != 0))
    {
        return Err(invalid_key("support constraints do not vanish on H"));
    }

    // Round 3 (streamed): quotients. Their coefficient vectors stay resident
    // (three short vectors) so the combination and opening passes can
    // regenerate their codewords.
    let quotient_coefficients = [q_sc, g, q_support];
    let mut quotient_builder = StreamedColumnCommitmentBuilder::begin(
        layout.coset_size,
        QUOTIENT_COLUMN_COUNT,
        salt_seed,
    )?;
    for coefficients in &quotient_coefficients {
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
        quotient_builder.absorb_column(&codeword)?;
    }
    let quotient_commitment = quotient_builder.finalize()?;
    transcript.absorb_digest("key-quotient-root", &quotient_commitment.root());

    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + aux_count + QUOTIENT_COLUMN_COUNT,
    );

    // Combination pass: the weighted sum of every committed column's codeword,
    // regenerating one codeword at a time.
    let mut combination = vec![parameters.zero(); layout.coset_size];
    let accumulate = |combination: &mut Vec<[u64; LIMB_COUNT]>,
                      weight: &[u64; LIMB_COUNT],
                      codeword: &[[u64; LIMB_COUNT]]| {
        for (slot, value) in combination.iter_mut().zip(codeword.iter()) {
            *slot = parameters.add(slot, &parameters.multiply(weight, value));
        }
    };
    let mut weight_index = 0;
    for column in 0..base_count {
        let coefficients = plan.base_column_coefficients(parameters, &trace_domain, column);
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &coefficients);
        accumulate(&mut combination, &weights[weight_index], &codeword);
        weight_index += 1;
    }
    for column in 0..aux_count {
        let coefficients = plan.aux_column_coefficients(parameters, &trace_domain, column)?;
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &coefficients);
        accumulate(&mut combination, &weights[weight_index], &codeword);
        weight_index += 1;
    }
    for coefficients in &quotient_coefficients {
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
        accumulate(&mut combination, &weights[weight_index], &codeword);
        weight_index += 1;
    }

    let fri_commitment = fri_commit(
        parameters,
        &mut transcript,
        &combination,
        &offset,
        salt_seed,
    )?;
    drop(combination);
    let query_positions = transcript.challenge_positions(
        "key-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    let fri = fri_answer(&fri_commitment, &query_positions);

    // Opening pass: regenerate each column's codeword once more and collect the
    // values at the sorted unique opened positions.
    let half = layout.coset_size / 2;
    let mut open_indices = Vec::with_capacity(query_positions.len() * 2);
    for &position in &query_positions {
        let folded = position % half;
        open_indices.push(folded);
        open_indices.push(folded + half);
    }
    let sorted = sorted_unique_indices(open_indices.iter().copied());
    let mut base_rows_values = vec![Vec::with_capacity(base_count); sorted.len()];
    for column in 0..base_count {
        let coefficients = plan.base_column_coefficients(parameters, &trace_domain, column);
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &coefficients);
        for (row, &index) in base_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let mut aux_rows_values = vec![Vec::with_capacity(aux_count); sorted.len()];
    for column in 0..aux_count {
        let coefficients = plan.aux_column_coefficients(parameters, &trace_domain, column)?;
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &coefficients);
        for (row, &index) in aux_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let mut quotient_rows_values = vec![Vec::with_capacity(QUOTIENT_COLUMN_COUNT); sorted.len()];
    for coefficients in &quotient_coefficients {
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
        for (row, &index) in quotient_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let base_opening = base_commitment.open_rows(&sorted, base_rows_values)?;
    let aux_opening = aux_commitment.open_rows(&sorted, aux_rows_values)?;
    let quotient_opening = quotient_commitment.open_rows(&sorted, quotient_rows_values)?;

    Ok(KeyFriProof {
        base_root: base_commitment.root(),
        aux_root: aux_commitment.root(),
        quotient_root: quotient_commitment.root(),
        fri,
        base_opening,
        aux_opening,
        quotient_opening,
        lookup_terminal,
        table_terminals,
    })
}
